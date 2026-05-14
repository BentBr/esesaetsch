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

// =====================================================================
// Certificate test helpers
// =====================================================================

use rand::rngs::OsRng;
use ssh_key::certificate::CertType;
use ssh_key::{Algorithm, PrivateKey};

/// Generate a random Ed25519 private key for use as a test CA or user key.
#[must_use]
pub fn random_ed25519_key() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("random ed25519 key")
}

/// Render a `PrivateKey`'s public side as an OpenSSH `authorized_keys` style
/// line: `type base64 comment`. Used to wire test CAs into the
/// `trusted_cas` parameter of `CaTrustCertAuthenticator::new`.
#[must_use]
pub fn pubkey_openssh_line(key: &PrivateKey, comment: &str) -> String {
    let pub_text = key
        .public_key()
        .to_openssh()
        .expect("public to_openssh succeeds");
    // `to_openssh` produces "type base64 [comment]"; strip the trailing
    // comment (which may be empty) and append ours so callers get a
    // predictable shape.
    let mut parts = pub_text.split_whitespace();
    let alg = parts.next().expect("alg");
    let b64 = parts.next().expect("b64");
    format!("{alg} {b64} {comment}")
}

/// Parameters for building a test certificate. Sensible defaults are
/// provided; tests override one field at a time.
pub struct CertSpec<'a> {
    pub user_key: &'a PrivateKey,
    pub ca_key: &'a PrivateKey,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    pub serial: u64,
    pub cert_type: CertType,
    pub key_id: String,
    pub critical_options: Vec<(String, String)>,
}

impl<'a> CertSpec<'a> {
    /// A spec that should always validate cleanly: principal "alice",
    /// window 1970-01-01 .. 9999-01-01, serial 1, user cert, no options.
    #[must_use]
    pub fn happy_path(user_key: &'a PrivateKey, ca_key: &'a PrivateKey) -> Self {
        Self {
            user_key,
            ca_key,
            principals: vec!["alice".to_owned()],
            valid_after: 0,
            valid_before: 253_402_300_799, // year 9999
            serial: 1,
            cert_type: CertType::User,
            key_id: "test-key-id".to_owned(),
            critical_options: Vec::new(),
        }
    }
}

/// Build a signed OpenSSH user certificate from `spec` and return its
/// SSH wire-blob bytes (suitable for `ParsedCert::parse`).
pub fn build_cert_bytes(spec: &CertSpec<'_>) -> Vec<u8> {
    let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        spec.user_key.public_key().clone(),
        spec.valid_after,
        spec.valid_before,
    )
    .expect("new builder");
    builder.serial(spec.serial).expect("serial");
    builder.cert_type(spec.cert_type).expect("cert_type");
    builder.key_id(spec.key_id.clone()).expect("key_id");
    for p in &spec.principals {
        builder.valid_principal(p.clone()).expect("principal");
    }
    for (name, value) in &spec.critical_options {
        builder
            .critical_option(name.clone(), value.clone())
            .expect("critical_option");
    }
    let cert = builder.sign(spec.ca_key).expect("sign");
    cert.to_bytes().expect("cert to_bytes")
}
