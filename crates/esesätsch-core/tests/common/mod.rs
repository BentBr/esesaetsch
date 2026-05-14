//! Shared test helpers — mock implementations of the core's traits, plus
//! small fixtures. Included by integration tests via `mod common;`.
//!
//! The `#![allow]` at the top of each integration test file covers the
//! `unwrap_used`/`expect_used` lints; this module relies on that.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use esesaetsch_core::auth::{PasswordAuthenticator, PubkeyAuthenticator};
use esesaetsch_core::error::AuthError;

/// A scriptable `PasswordAuthenticator` for integration tests.
///
/// Verdicts are looked up by `(user, password)`. Any `(user, _)` for a user
/// not present in the map produces `AuthError::UnknownUser` (after the
/// dummy-cost work has been recorded — see `dummy_work_count`).
pub struct MockPasswordAuthenticator {
    /// Map from `user → password → outcome`.
    pub verdicts: BTreeMap<String, BTreeMap<String, Result<(), AuthError>>>,
    /// Count of unknown-user calls that triggered dummy work.
    dummy_work_count: Arc<AtomicU64>,
}

impl MockPasswordAuthenticator {
    /// Empty mock — every call returns `AuthError::UnknownUser`.
    #[must_use]
    pub fn new() -> Self {  // not const: BTreeMap::new is const but Arc::new is not
        Self {
            verdicts: BTreeMap::new(),
            dummy_work_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Builder: insert one verdict.
    #[must_use]
    pub fn with_verdict(
        mut self,
        user: &str,
        password: &str,
        outcome: Result<(), AuthError>,
    ) -> Self {
        self.verdicts
            .entry(user.to_owned())
            .or_default()
            .insert(password.to_owned(), outcome);
        self
    }

    /// Test hook: how many times we entered the unknown-user / dummy-work branch.
    #[must_use]
    pub fn dummy_work_count(&self) -> u64 {
        self.dummy_work_count.load(Ordering::Relaxed)
    }
}

impl Default for MockPasswordAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordAuthenticator for MockPasswordAuthenticator {
    fn verify(&self, user: &str, password: &str) -> Result<(), AuthError> {
        self.verdicts.get(user).map_or_else(
            || {
                // Simulate the bcrypt-cost dummy work that a real backend
                // would perform to equalise timing between unknown-user and
                // bad-password (spec §6.4 rule 3). Tests assert on this
                // counter to verify the structural-hygiene property.
                self.dummy_work_count.fetch_add(1, Ordering::Relaxed);
                Err(AuthError::UnknownUser)
            },
            |passwords| {
                passwords
                    .get(password)
                    .cloned()
                    .unwrap_or(Err(AuthError::CredentialMismatch))
            },
        )
    }
}

/// A scriptable `PubkeyAuthenticator` for integration tests that don't want
/// to construct an OpenSSH allowlist. Use the real
/// `AllowlistPubkeyAuthenticator` for hygiene tests that need to exercise
/// the constant-time / sentinel-compare paths.
pub struct MockPubkeyAuthenticator {
    /// Pre-recorded outcomes by `(user, key_blob)`.
    pub verdicts: BTreeMap<String, BTreeMap<Vec<u8>, Result<(), AuthError>>>,
}

impl MockPubkeyAuthenticator {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            verdicts: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_verdict(
        mut self,
        user: &str,
        key_blob: &[u8],
        outcome: Result<(), AuthError>,
    ) -> Self {
        self.verdicts
            .entry(user.to_owned())
            .or_default()
            .insert(key_blob.to_vec(), outcome);
        self
    }
}

impl Default for MockPubkeyAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl PubkeyAuthenticator for MockPubkeyAuthenticator {
    fn verify(&self, user: &str, key_blob: &[u8]) -> Result<(), AuthError> {
        self.verdicts.get(user).map_or(Err(AuthError::UnknownUser), |blobs| {
            blobs
                .get(key_blob)
                .cloned()
                .unwrap_or(Err(AuthError::CredentialMismatch))
        })
    }
}

/// A valid Ed25519 public key string in OpenSSH text form. Useful for
/// integration tests that need a parseable key without generating one.
pub const ED25519_FIXTURE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDuiUkU0+nukC7q+TI0gMA0+jl3wQuRZ2u5GFOdjT2Cn alice@laptop";

/// Decode the base64 portion of an OpenSSH-format pubkey line into the
/// wire-blob bytes used by `PubkeyAuthenticator`. Convenience for tests.
#[must_use]
pub fn pubkey_blob(openssh_line: &str) -> Vec<u8> {
    use russh_keys::PublicKeyBase64;
    let b64 = openssh_line.split_whitespace().nth(1).expect("openssh line has b64 token");
    russh_keys::parse_public_key_base64(b64)
        .expect("test fixture parses")
        .public_key_bytes()
}
