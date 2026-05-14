//! Top-level error types for the core library.
//!
//! Every fallible operation returns a domain-specific `*Error` enum.
//! `Error` is the top-level wrapper used at the `lib.rs` surface.
//! `Display` output is intended for operator logs only — it must never
//! be returned to an SSH client (see spec §6.4).

use thiserror::Error;

/// Errors arising from configuration parsing, merging, or validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// TOML deserialisation failed.
    #[error("config file is not valid TOML: {0}")]
    Toml(#[from] toml::de::Error),

    /// Port out of the valid range.
    #[error("invalid port `{0}` (must be 1..=65535)")]
    InvalidPort(u32),

    /// `bind` did not parse as a host string.
    #[error("invalid bind address `{0}`")]
    InvalidBindAddress(String),

    /// No authentication method enabled.
    #[error("at least one of pubkey_enabled / cert_enabled / password_enabled must be true")]
    NoAuthMethodEnabled,

    /// An entry in `auth.authorized_keys` failed to parse.
    #[error("invalid authorized key for user `{user}`: {detail}")]
    InvalidAuthorizedKey { user: String, detail: String },

    /// `host_key` path contained `..` traversal.
    #[error("host_key path `{0}` may not contain parent-directory traversal")]
    InvalidHostKeyPath(String),

    /// `cert_enabled` is true but `auth.ca.trusted` is empty.
    #[error("cert_enabled is true but auth.ca.trusted is empty")]
    CertEnabledWithoutTrustedCa,
}

/// Errors arising from host-key load / generate operations.
#[derive(Debug, Error)]
pub enum HostKeyError {
    /// Filesystem I/O failed.
    #[error("host-key I/O failed for `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The host-key file exists but could not be parsed.
    #[error("host-key file at `{path}` is malformed: {detail}")]
    Malformed { path: String, detail: String },

    /// Key generation failed (extremely rare; treated as fatal).
    #[error("host-key generation failed: {0}")]
    Generation(String),
}

/// Errors arising from certificate parsing or validation.
///
/// **Operator-only.** Never reaches the wire — every cert-validation
/// failure produces a uniform `AuthError::CredentialMismatch` (or
/// `UnknownUser`) over the SSH channel.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum CertError {
    /// Cert blob did not parse as an OpenSSH user certificate.
    #[error("certificate blob is malformed: {0}")]
    Malformed(String),
    /// Cert was signed by a CA we do not trust.
    #[error("certificate signed by untrusted CA")]
    UntrustedCa,
    /// CA signature verification failed.
    #[error("certificate signature is invalid")]
    BadSignature,
    /// Current time is outside the cert's validity window.
    #[error("certificate is expired or not yet valid")]
    OutsideValidityWindow,
    /// SSH username is not in the cert's `valid_principals` list.
    #[error("ssh username is not in certificate principals")]
    PrincipalMismatch,
    /// Cert serial is in the configured revocation list.
    #[error("certificate serial is revoked")]
    Revoked,
    /// Cert advertises a critical option we do not support; per RFC 4252 /
    /// the OpenSSH cert spec, unknown critical options MUST cause rejection.
    #[error("certificate uses unsupported critical option `{0}`")]
    UnsupportedCriticalOption(String),
    /// Cert is a host certificate, not a user certificate.
    #[error("certificate is not a user certificate")]
    WrongCertType,
}

/// Errors arising from authentication attempts.
///
/// **Operator-only.** This is for server-side logs. Per spec §6.4 it must
/// never reach the SSH client wire — the wire response is always a uniform
/// `Auth::Reject` with no detail.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AuthError {
    /// User is not present in the allowlist (pubkey) / not known to the OS (password).
    #[error("unknown user")]
    UnknownUser,
    /// User exists but the offered credential did not match.
    #[error("credential mismatch")]
    CredentialMismatch,
    /// The auth method is disabled by config.
    #[error("auth method disabled by configuration")]
    MethodDisabled,
    /// An internal backend error (e.g., PAM service file missing). Treated
    /// as a credential mismatch over the wire; logged at warn server-side.
    #[error("auth backend error: {0}")]
    Backend(String),
}

/// Errors arising from the crypto allowlist module.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// A required algorithm name is not known to the linked `russh` version.
    #[error("crypto preference `{0}` is not supported by the linked russh; rebuild allowlist")]
    UnknownAlgorithm(&'static str),
}

/// Top-level core-library error.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration-related error.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// Host-key-related error.
    #[error(transparent)]
    HostKey(#[from] HostKeyError),

    /// Crypto-allowlist-related error.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
