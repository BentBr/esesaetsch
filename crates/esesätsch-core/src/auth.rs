//! Authentication trait surfaces.
//!
//! Three orthogonal authentication methods are supported, each enabled
//! independently via the server config:
//!
//! - [`PasswordAuthenticator`] — verifies a `(username, password)` pair against
//!   an OS-native backend (PAM on Unix, `LogonUserW` on Windows). The library
//!   defines only the trait; real backends live in the `esesätsch` binary
//!   crate behind `#[cfg(target_os = ...)]`.
//!
//! - [`PubkeyAuthenticator`] — verifies an offered public-key blob against the
//!   server's central TOML allowlist. Implemented in this crate by
//!   [`AllowlistPubkeyAuthenticator`].
//!
//! - `CertAuthenticator` (see [`crate::cert`]) — verifies an OpenSSH certificate.
//!
//! ## Information-disclosure hygiene
//!
//! Every implementation performs the same amount of cryptographic work
//! whether the user exists or not, so timing or branch-shape attacks can't
//! distinguish unknown-user from bad-credential outcomes:
//!
//! - The pubkey allowlist impl performs a constant-time compare against a
//!   fixed sentinel key when the user is missing, keeping the auth code
//!   path structurally identical between the two failure cases.
//! - A counter hook exposed via [`AllowlistPubkeyAuthenticator::sentinel_compares`]
//!   lets tests assert that the sentinel-compare path actually ran in the
//!   unknown-user case (testing the *structure* of the work, not its
//!   wall-clock duration).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use russh::keys::PublicKeyBase64;
use subtle::ConstantTimeEq;

use crate::error::AuthError;

/// A `PasswordAuthenticator` that rejects every credential.
///
/// Useful as a stand-in when password auth is disabled in config: the
/// server never calls `verify` (it short-circuits on
/// `password_enabled = false`), but the type system still wants a value.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllPasswordAuthenticator;

impl PasswordAuthenticator for DenyAllPasswordAuthenticator {
    fn verify(&self, _user: &str, _password: &str) -> Result<(), AuthError> {
        Err(AuthError::MethodDisabled)
    }
}

/// Authenticate a `(username, password)` pair.
pub trait PasswordAuthenticator: Send + Sync {
    /// Verify the credentials. Returns `Ok(())` on success or an `AuthError`
    /// describing the **operator-side** reason for failure.
    ///
    /// # Errors
    ///
    /// See [`AuthError`] for the catalogue.
    fn verify(&self, user: &str, password: &str) -> Result<(), AuthError>;
}

/// Authenticate a `(username, public-key-blob)` pair.
pub trait PubkeyAuthenticator: Send + Sync {
    /// Verify the offered key. `key_blob` is the SSH wire-format public-key
    /// blob (the bytes that `russh::keys::PublicKey::public_key_bytes` returns).
    ///
    /// # Errors
    ///
    /// See [`AuthError`] for the catalogue.
    fn verify(&self, user: &str, key_blob: &[u8]) -> Result<(), AuthError>;
}

/// Central-allowlist pubkey authenticator backed by the server config.
///
/// The compare is constant-time, and unknown-user lookups still run a
/// sentinel comparison so the code path's shape is identical regardless
/// of whether the user exists in the allowlist.
#[derive(Debug)]
pub struct AllowlistPubkeyAuthenticator {
    /// `username → [pre-parsed wire blob, …]`. Blobs are decoded once at
    /// construction so the hot path is a pure byte compare.
    keys: BTreeMap<String, Vec<Vec<u8>>>,
    /// Sentinel blob compared against when the username is unknown.
    sentinel: Vec<u8>,
    /// Counter for hygiene tests: number of times the sentinel branch ran.
    sentinel_compares: Arc<AtomicU64>,
}

impl AllowlistPubkeyAuthenticator {
    /// Build an authenticator from the config-shaped allowlist.
    ///
    /// `allowlist` maps usernames to OpenSSH-format public-key strings
    /// (`type base64 [comment]`). Each entry's base64 blob is decoded once
    /// at construction so the hot path is a pure byte compare.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::Backend` if any allowlist entry fails to parse.
    /// (Config-time validation in `Config::validate` already catches this,
    /// but we re-check defensively here.)
    pub fn from_allowlist(allowlist: &BTreeMap<String, Vec<String>>) -> Result<Self, AuthError> {
        let mut keys: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
        for (user, lines) in allowlist {
            let mut decoded = Vec::with_capacity(lines.len());
            for line in lines {
                let b64 = line.split_whitespace().nth(1).ok_or_else(|| {
                    AuthError::Backend(format!("allowlist entry for {user} missing base64 blob"))
                })?;
                let parsed = russh::keys::parse_public_key_base64(b64)
                    .map_err(|e| AuthError::Backend(format!("decoding key for {user}: {e}")))?;
                decoded.push(parsed.public_key_bytes());
            }
            keys.insert(user.clone(), decoded);
        }
        Ok(Self {
            keys,
            sentinel: vec![0_u8; 32],
            sentinel_compares: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Test/observability hook: how many times the sentinel branch was
    /// reached (i.e., an unknown user attempted pubkey auth).
    #[must_use]
    pub fn sentinel_compares(&self) -> u64 {
        self.sentinel_compares.load(Ordering::Relaxed)
    }
}

impl PubkeyAuthenticator for AllowlistPubkeyAuthenticator {
    // The explicit `if let / else` keeps the two security-critical branches
    // visually parallel and easier to audit than a `map_or_else` chain.
    #[allow(clippy::option_if_let_else)]
    fn verify(&self, user: &str, key_blob: &[u8]) -> Result<(), AuthError> {
        if let Some(blobs) = self.keys.get(user) {
            // Walk the full list with constant-time compares on each entry.
            // Don't short-circuit: that would leak which slot matched via
            // timing.
            let mut matched = subtle::Choice::from(0_u8);
            for b in blobs {
                matched |= b.as_slice().ct_eq(key_blob);
            }
            if bool::from(matched) {
                Ok(())
            } else {
                Err(AuthError::CredentialMismatch)
            }
        } else {
            // Unknown user: still do work — sentinel compare — so the auth
            // path's shape is identical to the known-user-bad-key path.
            let _ = self.sentinel.as_slice().ct_eq(key_blob);
            self.sentinel_compares.fetch_add(1, Ordering::Relaxed);
            Err(AuthError::UnknownUser)
        }
    }
}
