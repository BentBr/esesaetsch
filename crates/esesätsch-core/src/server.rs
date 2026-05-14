//! SSH server glue.
//!
//! `russh::server::Server` and `russh::server::Handler` implementations
//! that dispatch incoming auth requests to our trait objects, and apply
//! information-disclosure hygiene to every wire-level response.
//!
//! Channel/session methods run a [`crate::session::run`] task per opened
//! channel that bridges the spawned `PtyChild` to the russh wire protocol.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use russh::keys::{PublicKey, PublicKeyBase64};
use russh::server::{Auth, Config as RusshConfig, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, SshId};
use tokio::sync::mpsc;

use crate::auth::{PasswordAuthenticator, PubkeyAuthenticator};
use crate::cert::{CertAuthenticator, CertGrants};
use crate::config::Config;
use crate::crypto;
use crate::pty::{Command, PtySpawner, SpawnSpec, TerminalSize};
use crate::session::{self, ControlMsg};

// =====================================================================
// Server state + factory
// =====================================================================

/// Server-wide state shared across all connections.
struct ServerState {
    config: Config,
    pubkey_auth: Arc<dyn PubkeyAuthenticator>,
    password_auth: Arc<dyn PasswordAuthenticator>,
    cert_auth: Option<Arc<dyn CertAuthenticator>>,
    spawner: Arc<dyn PtySpawner>,
}

/// SSH server, implements [`russh::server::Server`].
pub struct EsesätschServer {
    state: Arc<ServerState>,
}

impl EsesätschServer {
    /// Construct the server.
    #[must_use]
    pub fn new(
        config: Config,
        pubkey_auth: Arc<dyn PubkeyAuthenticator>,
        password_auth: Arc<dyn PasswordAuthenticator>,
        cert_auth: Option<Arc<dyn CertAuthenticator>>,
        spawner: Arc<dyn PtySpawner>,
        host_key: russh::keys::PrivateKey,
    ) -> (Self, Arc<RusshConfig>) {
        let methods = advertised_methods(&config);

        let russh_config = RusshConfig {
            // Server identification string reveals no minor/patch, no OS,
            // no hostname — defence against fingerprinting.
            server_id: SshId::Standard("SSH-2.0-esesaetsch_0".into()),
            methods,
            keys: vec![host_key],
            preferred: crypto::preferences(),
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            max_auth_attempts: config.max_auth_attempts as usize,
            ..RusshConfig::default()
        };

        let state = Arc::new(ServerState {
            config,
            pubkey_auth,
            password_auth,
            cert_auth,
            spawner,
        });

        (Self { state }, Arc::new(russh_config))
    }
}

fn advertised_methods(config: &Config) -> MethodSet {
    let mut methods = Vec::new();
    if config.pubkey_enabled || config.cert_enabled {
        methods.push(MethodKind::PublicKey);
    }
    if config.password_enabled {
        methods.push(MethodKind::Password);
    }
    MethodSet::from(methods.as_slice())
}

impl Server for EsesätschServer {
    type Handler = ConnectionHandler;

    fn new_client(&mut self, peer: Option<SocketAddr>) -> Self::Handler {
        ConnectionHandler {
            state: Arc::clone(&self.state),
            peer,
            authenticated_user: None,
            cert_grants: None,
            channels: HashMap::new(),
        }
    }
}

// =====================================================================
// Per-connection state
// =====================================================================

/// Per-channel state tracked by the connection handler.
struct ChannelEntry {
    pty_request: Option<PtyRequestInfo>,
    control_tx: Option<mpsc::Sender<ControlMsg>>,
}

#[derive(Debug, Clone)]
struct PtyRequestInfo {
    term: String,
    size: TerminalSize,
}

/// Per-connection state. Implements [`russh::server::Handler`].
pub struct ConnectionHandler {
    state: Arc<ServerState>,
    peer: Option<SocketAddr>,
    authenticated_user: Option<String>,
    cert_grants: Option<CertGrants>,
    channels: HashMap<ChannelId, ChannelEntry>,
}

impl ConnectionHandler {
    /// Build the uniform reject response. The `proceed_with_methods` list
    /// is computed from server config only — never from per-user state —
    /// so it can't be used to probe which methods are configured for a
    /// given username.
    fn uniform_reject(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(advertised_methods(&self.state.config)),
            partial_success: false,
        }
    }

    fn channel_entry_mut(&mut self, channel_id: ChannelId) -> &mut ChannelEntry {
        self.channels.entry(channel_id).or_insert(ChannelEntry {
            pty_request: None,
            control_tx: None,
        })
    }

    /// Run cert validation synchronously, mutating `self` on success so
    /// the authenticated user and grants are visible to subsequent
    /// handler calls.
    fn run_cert_auth(&mut self, user: &str, certificate: &russh::keys::Certificate) -> Auth {
        if !self.state.config.cert_enabled {
            tracing::warn!(
                target: "esesaetsch_core::server",
                user,
                method = "openssh-cert",
                reason = "method_disabled",
                "auth rejected",
            );
            return self.uniform_reject();
        }
        let Some(cert_auth) = self.state.cert_auth.clone() else {
            tracing::warn!(
                target: "esesaetsch_core::server",
                user,
                reason = "no_cert_authenticator_configured",
                "auth rejected",
            );
            return self.uniform_reject();
        };
        let Ok(bytes) = certificate.to_bytes() else {
            tracing::warn!(
                target: "esesaetsch_core::server",
                user,
                reason = "cert_serialisation_failed",
                "auth rejected",
            );
            return self.uniform_reject();
        };
        let parsed = match crate::cert::ParsedCert::parse(&bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    target: "esesaetsch_core::server",
                    user,
                    error = %e,
                    "cert parse failed",
                );
                return self.uniform_reject();
            }
        };
        match cert_auth.verify(user, &parsed) {
            Ok(grants) => {
                self.authenticated_user = Some(user.to_owned());
                self.cert_grants = Some(grants.clone());
                tracing::info!(
                    target: "esesaetsch_core::server",
                    user,
                    method = "openssh-cert",
                    force_command = grants.force_command.is_some(),
                    "auth succeeded",
                );
                Auth::Accept
            }
            Err(e) => {
                tracing::warn!(
                    target: "esesaetsch_core::server",
                    user,
                    method = "openssh-cert",
                    reason = %e,
                    "auth rejected",
                );
                self.uniform_reject()
            }
        }
    }

    /// Build a `SpawnSpec`, call the spawner, and launch a session task.
    /// On spawn-failure: client sees `exit-status = 1` and a closed
    /// channel, with no diagnostic bytes — the operator-side reason is
    /// only in the server log.
    fn launch_session(
        &mut self,
        channel_id: ChannelId,
        command: Command,
        interactive: bool,
        session: &mut Session,
    ) {
        let Some(user) = self.authenticated_user.clone() else {
            tracing::warn!(
                target: "esesaetsch_core::server",
                "shell/exec request without prior auth — refusing",
            );
            let _ = session.exit_status_request(channel_id, 1);
            let _ = session.close(channel_id);
            return;
        };

        let pty_info = self
            .channels
            .get(&channel_id)
            .and_then(|c| c.pty_request.clone());
        let (term, size) = pty_info.map_or_else(
            || ("dumb".to_owned(), TerminalSize::default()),
            |p| (p.term, p.size),
        );

        let grants = self.cert_grants.clone().unwrap_or_default();
        let spawn_result = self.state.spawner.spawn(SpawnSpec {
            user: &user,
            term: &term,
            size,
            env: &[],
            command,
            interactive,
            grants,
        });

        let child = match spawn_result {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    target: "esesaetsch_core::server",
                    user,
                    error = %e,
                    "spawn failed; client sees exit-status=1 with no detail",
                );
                let _ = session.exit_status_request(channel_id, 1);
                let _ = session.close(channel_id);
                return;
            }
        };

        let (control_tx, control_rx) = mpsc::channel::<ControlMsg>(32);
        let handle = session.handle();
        tokio::spawn(session::run(
            child,
            control_rx,
            handle,
            channel_id,
            interactive,
        ));

        self.channel_entry_mut(channel_id).control_tx = Some(control_tx);
    }
}

// =====================================================================
// russh::server::Handler implementation (russh 0.60 — native impl Future)
// =====================================================================

// `clippy::manual_async_fn` triggers on every method below because russh
// 0.60 declares Handler methods as `fn ... -> impl Future + Send` rather
// than `async fn`. The trait shape is fixed by upstream; we match it.
#[allow(clippy::manual_async_fn)]
impl Handler for ConnectionHandler {
    type Error = russh::Error;

    // -------- Auth --------

    fn auth_none(&mut self, _user: &str) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        let reject = self.uniform_reject();
        async move { Ok(reject) }
    }

    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        // Auth has no awaits — compute the verdict synchronously so we
        // can mutate `self.authenticated_user` on success; the returned
        // future is trivial.
        let result = if self.state.config.password_enabled {
            match self.state.password_auth.verify(user, password) {
                Ok(()) => {
                    self.authenticated_user = Some(user.to_owned());
                    tracing::info!(
                        target: "esesaetsch_core::server",
                        user,
                        method = "password",
                        peer = ?self.peer,
                        "auth succeeded",
                    );
                    Auth::Accept
                }
                Err(e) => {
                    tracing::warn!(
                        target: "esesaetsch_core::server",
                        user,
                        method = "password",
                        reason = %e,
                        "auth rejected",
                    );
                    self.uniform_reject()
                }
            }
        } else {
            tracing::warn!(
                target: "esesaetsch_core::server",
                user,
                method = "password",
                reason = "method_disabled",
                "auth rejected",
            );
            self.uniform_reject()
        };
        async move { Ok(result) }
    }

    fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        let alg = public_key.algorithm().as_str().to_owned();
        let blob = public_key.public_key_bytes();
        let result = if self.state.config.pubkey_enabled {
            match self.state.pubkey_auth.verify(user, &blob) {
                Ok(()) => {
                    self.authenticated_user = Some(user.to_owned());
                    tracing::info!(
                        target: "esesaetsch_core::server",
                        user,
                        method = "publickey",
                        key_type = %alg,
                        peer = ?self.peer,
                        "auth succeeded",
                    );
                    Auth::Accept
                }
                Err(e) => {
                    tracing::warn!(
                        target: "esesaetsch_core::server",
                        user,
                        method = "publickey",
                        key_type = %alg,
                        reason = %e,
                        "auth rejected",
                    );
                    self.uniform_reject()
                }
            }
        } else {
            tracing::warn!(
                target: "esesaetsch_core::server",
                user,
                method = "publickey",
                reason = "method_disabled",
                "auth rejected",
            );
            self.uniform_reject()
        };
        async move { Ok(result) }
    }

    fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &russh::keys::Certificate,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        let result = self.run_cert_auth(user, certificate);
        async move { Ok(result) }
    }

    // -------- Channels --------

    fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        self.channel_entry_mut(channel.id());
        async { Ok(true) }
    }

    fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let info = PtyRequestInfo {
            term: term.to_owned(),
            size: TerminalSize {
                cols: u16::try_from(col_width).unwrap_or(80),
                rows: u16::try_from(row_height).unwrap_or(24),
                pixel_w: u16::try_from(pix_width).unwrap_or(0),
                pixel_h: u16::try_from(pix_height).unwrap_or(0),
            },
        };
        self.channel_entry_mut(channel).pty_request = Some(info);
        async { Ok(()) }
    }

    fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let interactive = self
            .channels
            .get(&channel)
            .is_some_and(|c| c.pty_request.is_some());
        self.launch_session(channel, Command::Shell, interactive, session);
        async { Ok(()) }
    }

    fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let cmd = String::from_utf8_lossy(data).into_owned();
        let interactive = self
            .channels
            .get(&channel)
            .is_some_and(|c| c.pty_request.is_some());
        self.launch_session(channel, Command::Exec(cmd), interactive, session);
        async { Ok(()) }
    }

    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let tx = self
            .channels
            .get(&channel)
            .and_then(|c| c.control_tx.clone());
        let bytes = data.to_vec();
        async move {
            if let Some(tx) = tx {
                let _ = tx.send(ControlMsg::Stdin(bytes)).await;
            }
            Ok(())
        }
    }

    fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let tx = self
            .channels
            .get(&channel)
            .and_then(|c| c.control_tx.clone());
        let cols = u16::try_from(col_width).unwrap_or(80);
        let rows = u16::try_from(row_height).unwrap_or(24);
        async move {
            if let Some(tx) = tx {
                let _ = tx.send(ControlMsg::Resize { cols, rows }).await;
            }
            Ok(())
        }
    }
}

// =====================================================================
// Inline unit tests for pure helpers.
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_methods_reflects_only_server_config() {
        let mut cfg = Config::defaults();
        cfg.pubkey_enabled = true;
        cfg.password_enabled = false;
        cfg.cert_enabled = false;
        assert_eq!(
            advertised_methods(&cfg),
            MethodSet::from(&[MethodKind::PublicKey][..])
        );

        cfg.pubkey_enabled = false;
        cfg.password_enabled = true;
        assert_eq!(
            advertised_methods(&cfg),
            MethodSet::from(&[MethodKind::Password][..])
        );

        cfg.pubkey_enabled = false;
        cfg.password_enabled = false;
        cfg.cert_enabled = true;
        assert_eq!(
            advertised_methods(&cfg),
            MethodSet::from(&[MethodKind::PublicKey][..])
        );

        cfg.pubkey_enabled = true;
        cfg.password_enabled = true;
        cfg.cert_enabled = true;
        assert_eq!(
            advertised_methods(&cfg),
            MethodSet::from(&[MethodKind::PublicKey, MethodKind::Password][..]),
        );
    }
}
