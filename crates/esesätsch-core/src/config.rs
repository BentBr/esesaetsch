//! Configuration data model.
//!
//! This module defines three layers:
//! 1. `Cli`        — derived from `clap`, populated by the binary.
//! 2. `TomlConfig` — derived from `serde`, populated by `toml::from_str`.
//! 3. `Config`     — the merged, validated, ready-to-use config.
//!
//! `Config::from_sources` is a pure function: it performs no I/O.
//! `Config::validate` enforces every invariant after merge.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use serde::Deserialize;

use crate::error::ConfigError;

/// Parsed TOML config — every field is optional so the merge layer can
/// apply CLI overrides and built-in defaults.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TomlConfig {
    /// `[server]` section.
    #[serde(default)]
    pub server: ServerConfig,
    /// `[auth]` section.
    #[serde(default)]
    pub auth: AuthConfig,
    /// `[logging]` section (optional).
    pub logging: Option<LoggingConfig>,
}

/// `[server]` section of the TOML config.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Bind address; defaults to `0.0.0.0` when omitted.
    pub bind: Option<String>,
    /// Listen port; defaults to `2222` when omitted.
    pub port: Option<u16>,
    /// Path to host key file.
    pub host_key: Option<PathBuf>,
}

/// `[auth]` section of the TOML config.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // independent enable-flags, not state machine
pub struct AuthConfig {
    /// Whether password auth (verified against the OS) is enabled.
    pub password_enabled: Option<bool>,
    /// Whether plain-pubkey auth is enabled.
    pub pubkey_enabled: Option<bool>,
    /// Whether OpenSSH certificate auth is enabled.
    pub cert_enabled: Option<bool>,
    /// Maximum auth attempts before dropping the connection.
    pub max_auth_attempts: Option<u32>,

    /// `username → [openssh-format key, …]` allowlist.
    #[serde(default)]
    pub authorized_keys: BTreeMap<String, Vec<String>>,

    /// `[auth.ca]` sub-section.
    pub ca: Option<CaConfig>,
}

/// `[auth.ca]` sub-section — only consulted when `cert_enabled = true`.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    /// Trusted CA public keys in OpenSSH format.
    #[serde(default)]
    pub trusted: Vec<String>,
    /// Revoked certificate serial numbers.
    #[serde(default)]
    pub revoked_serials: Vec<u64>,
}

/// `[logging]` section.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// `off|error|warn|info|debug|trace`.
    pub level: Option<String>,
    /// Enable wire-level packet trace.
    pub packet_trace: Option<bool>,
}

/// CLI-provided values. Filled in by the binary using `clap`.
#[derive(Debug, Default, Clone)]
#[allow(clippy::struct_excessive_bools)] // independent CLI flags
pub struct Cli {
    /// Optional path to the TOML config.
    pub config_path: Option<PathBuf>,
    /// Listen port override.
    pub port: Option<u16>,
    /// Bind address override.
    pub bind: Option<String>,
    /// Host key path override.
    pub host_key: Option<PathBuf>,
    /// Verbose tracing flag.
    pub debug: bool,
    /// Wire-level packet trace flag (implies debug).
    pub trace: bool,
}

impl Config {
    /// Validate the merged configuration. Returns `Ok(())` on success or the
    /// first violation encountered.
    ///
    /// # Errors
    ///
    /// See `ConfigError` for the catalogue of failures.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.pubkey_enabled && !self.password_enabled && !self.cert_enabled {
            return Err(ConfigError::NoAuthMethodEnabled);
        }

        for (user, keys) in &self.authorized_keys {
            for k in keys {
                parse_pubkey_blob(k).map_err(|detail| ConfigError::InvalidAuthorizedKey {
                    user: user.clone(),
                    detail,
                })?;
            }
        }

        if self.cert_enabled && self.ca_trusted.is_empty() {
            return Err(ConfigError::CertEnabledWithoutTrustedCa);
        }

        for ca in &self.ca_trusted {
            parse_pubkey_blob(ca).map_err(|detail| ConfigError::InvalidAuthorizedKey {
                user: "<ca>".to_owned(),
                detail,
            })?;
        }

        if self
            .host_key
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(ConfigError::InvalidHostKeyPath(
                self.host_key.to_string_lossy().into_owned(),
            ));
        }

        Ok(())
    }

    /// Merge CLI overrides on top of an optional TOML config, falling back
    /// to the built-in defaults from §5.5. Pure function — no I/O.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::InvalidBindAddress` if the bind string cannot
    /// be parsed.
    pub fn from_sources(cli: &Cli, toml: Option<TomlConfig>) -> Result<Self, ConfigError> {
        let mut out = Self::defaults();
        if let Some(t) = toml {
            apply_toml(&mut out, t)?;
        }
        apply_cli(&mut out, cli)?;
        Ok(out)
    }

    /// Built-in defaults. Returned by the merge layer when no TOML file
    /// is supplied and no CLI flag overrides a given field.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], 2222)),
            host_key: PathBuf::from("./host_key"),
            password_enabled: false,
            pubkey_enabled: true,
            cert_enabled: false,
            max_auth_attempts: 3,
            authorized_keys: BTreeMap::new(),
            ca_trusted: Vec::new(),
            ca_revoked_serials: Vec::new(),
            logging_level: "info".to_owned(),
            packet_trace: false,
        }
    }
}

/// The merged, validated configuration handed to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent enable-flags
pub struct Config {
    /// Address the server will bind to.
    pub bind: SocketAddr,
    /// Path to the host key file.
    pub host_key: PathBuf,
    /// Whether password auth is enabled.
    pub password_enabled: bool,
    /// Whether plain-pubkey auth is enabled.
    pub pubkey_enabled: bool,
    /// Whether cert auth is enabled.
    pub cert_enabled: bool,
    /// Max auth attempts before disconnect.
    pub max_auth_attempts: u32,
    /// Pubkey allowlist.
    pub authorized_keys: BTreeMap<String, Vec<String>>,
    /// Trusted CA pubkeys (cert auth).
    pub ca_trusted: Vec<String>,
    /// Revoked cert serials (cert auth).
    pub ca_revoked_serials: Vec<u64>,
    /// Effective logging level.
    pub logging_level: String,
    /// Whether packet-trace mode is on.
    pub packet_trace: bool,
}

/// Parse an OpenSSH `type base64 [comment]` public key string. Returns
/// `Ok(())` if the base64 blob decodes via `russh-keys`; otherwise an
/// error string describing the failure (for context in `ConfigError`).
fn parse_pubkey_blob(line: &str) -> Result<(), String> {
    let blob = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "missing base64 blob (expected `type base64 [comment]`)".to_owned())?;
    russh::keys::parse_public_key_base64(blob).map_err(|e| format!("{e}"))?;
    Ok(())
}

fn apply_toml(out: &mut Config, t: TomlConfig) -> Result<(), ConfigError> {
    if let Some(p) = t.server.port {
        out.bind = SocketAddr::new(out.bind.ip(), p);
    }
    if let Some(b) = t.server.bind {
        let ip = IpAddr::from_str(&b).map_err(|_| ConfigError::InvalidBindAddress(b.clone()))?;
        out.bind = SocketAddr::new(ip, out.bind.port());
    }
    if let Some(hk) = t.server.host_key {
        out.host_key = hk;
    }
    if let Some(v) = t.auth.password_enabled {
        out.password_enabled = v;
    }
    if let Some(v) = t.auth.pubkey_enabled {
        out.pubkey_enabled = v;
    }
    if let Some(v) = t.auth.cert_enabled {
        out.cert_enabled = v;
    }
    if let Some(v) = t.auth.max_auth_attempts {
        out.max_auth_attempts = v;
    }
    if !t.auth.authorized_keys.is_empty() {
        out.authorized_keys = t.auth.authorized_keys;
    }
    if let Some(ca) = t.auth.ca {
        out.ca_trusted = ca.trusted;
        out.ca_revoked_serials = ca.revoked_serials;
    }
    if let Some(l) = t.logging {
        if let Some(level) = l.level {
            out.logging_level = level;
        }
        if let Some(pt) = l.packet_trace {
            out.packet_trace = pt;
        }
    }
    Ok(())
}

fn apply_cli(out: &mut Config, cli: &Cli) -> Result<(), ConfigError> {
    if let Some(p) = cli.port {
        out.bind = SocketAddr::new(out.bind.ip(), p);
    }
    if let Some(b) = &cli.bind {
        let ip = IpAddr::from_str(b).map_err(|_| ConfigError::InvalidBindAddress(b.clone()))?;
        out.bind = SocketAddr::new(ip, out.bind.port());
    }
    if let Some(hk) = &cli.host_key {
        out.host_key.clone_from(hk);
    }
    if cli.trace {
        "trace".clone_into(&mut out.logging_level);
        out.packet_trace = true;
    } else if cli.debug {
        "debug".clone_into(&mut out.logging_level);
    }
    Ok(())
}
