//! SSH server glue.
//!
//! `russh::server::Server` and `russh::server::Handler` implementations
//! that dispatch incoming auth requests to our trait objects, and apply
//! spec §6.4 information-disclosure hygiene to every wire-level response.
//!
//! Channel/session methods run a [`crate::session::run`] task per opened
//! channel that bridges the spawned `PtyChild` to the russh wire protocol.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use russh::server::{Auth, Config as RusshConfig, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, SshId};
use russh_keys::PublicKeyBase64;
use russh_keys::key::PublicKey;
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
    /// Optional: only used when `config.cert_enabled` is true.
    /// Held now so cert-via-russh wiring is a localised change later.
    #[allow(dead_code)]
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
        host_key: russh_keys::key::KeyPair,
    ) -> (Self, Arc<RusshConfig>) {
        let methods = advertised_methods(&config);

        let russh_config = RusshConfig {
            // Spec §6.4 rule 4: server-id reveals no minor/patch/OS/hostname.
            server_id: SshId::Standard("SSH-2.0-esesaetsch_0".to_owned()),
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

fn advertised_methods(config: &Config) -> russh::MethodSet {
    let mut m = russh::MethodSet::empty();
    if config.pubkey_enabled || config.cert_enabled {
        m |= russh::MethodSet::PUBLICKEY;
    }
    if config.password_enabled {
        m |= russh::MethodSet::PASSWORD;
    }
    m
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
    /// PTY allocation recorded on `pty_request`, consumed by
    /// `shell_request`/`exec_request`.
    pty_request: Option<PtyRequestInfo>,
    /// Sender into the running session task. `None` until shell/exec has
    /// been requested.
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
    /// Cert grants captured during a successful cert auth (force-command).
    cert_grants: Option<CertGrants>,
    channels: HashMap<ChannelId, ChannelEntry>,
}

impl ConnectionHandler {
    /// Build the uniform reject response. Spec §6.4 rule 1 + rule 2.
    fn uniform_reject(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(advertised_methods(&self.state.config)),
        }
    }

    fn channel_entry_mut(&mut self, channel_id: ChannelId) -> &mut ChannelEntry {
        self.channels.entry(channel_id).or_insert(ChannelEntry {
            pty_request: None,
            control_tx: None,
        })
    }

    /// Build a `SpawnSpec`, call the spawner, and launch a session task.
    /// On spawn-failure: spec §6.4 rule 6 (exit-status=1, no stderr to wire).
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
            session.exit_status_request(channel_id, 1);
            session.close(channel_id);
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
                session.exit_status_request(channel_id, 1);
                session.close(channel_id);
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
// russh::server::Handler implementation
// =====================================================================

#[async_trait]
impl Handler for ConnectionHandler {
    type Error = russh::Error;

    // -------- Auth --------

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(self.uniform_reject())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if !self.state.config.password_enabled {
            tracing::warn!(
                target: "esesaetsch_core::server",
                user,
                method = "password",
                reason = "method_disabled",
                "auth rejected",
            );
            return Ok(self.uniform_reject());
        }
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
                Ok(Auth::Accept)
            }
            Err(e) => {
                tracing::warn!(
                    target: "esesaetsch_core::server",
                    user,
                    method = "password",
                    reason = %e,
                    "auth rejected",
                );
                Ok(self.uniform_reject())
            }
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let key_type = public_key.name();
        let is_cert = key_type.contains("-cert-v01@openssh.com");

        if is_cert {
            // v1 cert-via-russh wiring is deferred (russh's Handler trait
            // does not surface the raw cert blob alongside the typed key).
            tracing::warn!(
                target: "esesaetsch_core::server",
                user,
                key_type,
                reason = "cert_auth_via_russh_not_yet_wired",
                "auth rejected",
            );
            return Ok(self.uniform_reject());
        }

        if !self.state.config.pubkey_enabled {
            tracing::warn!(
                target: "esesaetsch_core::server",
                user,
                method = "publickey",
                reason = "method_disabled",
                "auth rejected",
            );
            return Ok(self.uniform_reject());
        }

        let blob = public_key.public_key_bytes();
        match self.state.pubkey_auth.verify(user, &blob) {
            Ok(()) => {
                self.authenticated_user = Some(user.to_owned());
                tracing::info!(
                    target: "esesaetsch_core::server",
                    user,
                    method = "publickey",
                    key_type,
                    peer = ?self.peer,
                    "auth succeeded",
                );
                Ok(Auth::Accept)
            }
            Err(e) => {
                tracing::warn!(
                    target: "esesaetsch_core::server",
                    user,
                    method = "publickey",
                    key_type,
                    reason = %e,
                    "auth rejected",
                );
                Ok(self.uniform_reject())
            }
        }
    }

    // -------- Channels --------

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channel_entry_mut(channel.id());
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
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
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Interactive iff a pty_request preceded.
        let interactive = self
            .channels
            .get(&channel)
            .is_some_and(|c| c.pty_request.is_some());
        self.launch_session(channel, Command::Shell, interactive, session);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).into_owned();
        let interactive = self
            .channels
            .get(&channel)
            .is_some_and(|c| c.pty_request.is_some());
        self.launch_session(channel, Command::Exec(cmd), interactive, session);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(entry) = self.channels.get(&channel) {
            if let Some(tx) = &entry.control_tx {
                let _ = tx.send(ControlMsg::Stdin(data.to_vec())).await;
            }
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(entry) = self.channels.get(&channel) {
            if let Some(tx) = &entry.control_tx {
                let _ = tx
                    .send(ControlMsg::Resize {
                        cols: u16::try_from(col_width).unwrap_or(80),
                        rows: u16::try_from(row_height).unwrap_or(24),
                    })
                    .await;
            }
        }
        Ok(())
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
        assert_eq!(advertised_methods(&cfg), russh::MethodSet::PUBLICKEY);

        cfg.pubkey_enabled = false;
        cfg.password_enabled = true;
        assert_eq!(advertised_methods(&cfg), russh::MethodSet::PASSWORD);

        cfg.pubkey_enabled = false;
        cfg.password_enabled = false;
        cfg.cert_enabled = true;
        // cert_enabled also advertises PUBLICKEY (cert auth rides on it).
        assert_eq!(advertised_methods(&cfg), russh::MethodSet::PUBLICKEY);

        cfg.pubkey_enabled = true;
        cfg.password_enabled = true;
        cfg.cert_enabled = true;
        assert_eq!(
            advertised_methods(&cfg),
            russh::MethodSet::PUBLICKEY | russh::MethodSet::PASSWORD,
        );
    }
}
