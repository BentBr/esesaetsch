//! OpenSSH certificate authentication (spec §6.1 cert path, §6.4 cert hygiene).
//!
//! This module parses and validates OpenSSH user certificates. Validation is
//! performed in this order:
//!
//! 1. **Parse** the wire blob into an `ssh_key::Certificate`.
//! 2. **Cert type** must be `User` (host certs are rejected).
//! 3. **CA trust** — the cert's signature key must match one of the configured
//!    trusted CA public keys (constant-time compare).
//! 4. **Signature verify** — the cert's payload must be correctly signed by
//!    the CA whose key we matched.
//! 5. **Validity window** — the current time must be in `[valid_after,
//!    valid_before)`.
//! 6. **Principal** — the SSH username must appear in the cert's
//!    `valid_principals` list.
//! 7. **Revocation** — the cert's serial must not be in the configured
//!    revocation list.
//! 8. **Critical options** — any critical option name we don't recognise
//!    causes rejection (OpenSSH cert spec: unknown critical options MUST be
//!    fail-closed). Supported: `force-command`. Anything else rejected.
//!
//! Information-disclosure hygiene (spec §6.4 rule 3): when validation fails
//! at any step, the implementation still completes structurally equivalent
//! work — parse + constant-time CA-compare on a sentinel input. A counter
//! exposed via [`CaTrustCertAuthenticator::dummy_work_count`] lets tests
//! assert on this without relying on wall-clock timing.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use ssh_key::Certificate;
use ssh_key::certificate::CertType;
use subtle::ConstantTimeEq;

use crate::error::{AuthError, CertError};

/// A parsed OpenSSH certificate ready for validation.
#[derive(Debug, Clone)]
pub struct ParsedCert {
    inner: Certificate,
}

impl ParsedCert {
    /// Parse a cert from its SSH wire-blob bytes (the bytes that follow the
    /// `ssh-ed25519-cert-v01@openssh.com ` algorithm tag in a `userauth`
    /// request, or the base64-decoded payload of an OpenSSH text file).
    ///
    /// # Errors
    ///
    /// `CertError::Malformed` if the blob fails to parse.
    pub fn parse(blob: &[u8]) -> Result<Self, CertError> {
        let inner = Certificate::from_bytes(blob)
            .map_err(|e| CertError::Malformed(format!("{e}")))?;
        Ok(Self { inner })
    }

    /// Borrow the underlying `ssh_key::Certificate`.
    #[must_use]
    pub const fn inner(&self) -> &Certificate {
        &self.inner
    }

    /// The cert's `key_id` field (an opaque label).
    #[must_use]
    pub fn key_id(&self) -> &str {
        self.inner.key_id()
    }

    /// The cert's serial number.
    #[must_use]
    pub fn serial(&self) -> u64 {
        self.inner.serial()
    }

    /// User or host certificate?
    #[must_use]
    pub fn cert_type(&self) -> CertType {
        self.inner.cert_type()
    }

    /// `valid_principals` slice.
    #[must_use]
    pub fn valid_principals(&self) -> &[String] {
        self.inner.valid_principals()
    }

    /// `valid_after` as a unix timestamp.
    #[must_use]
    pub fn valid_after(&self) -> u64 {
        self.inner.valid_after()
    }

    /// `valid_before` as a unix timestamp.
    #[must_use]
    pub fn valid_before(&self) -> u64 {
        self.inner.valid_before()
    }
}

/// Grants conferred by a validated certificate.
///
/// Populated by [`CertAuthenticator::verify`] when a cert successfully
/// validates. The handler honors these when launching the session.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CertGrants {
    /// `force-command` critical option: if set, replaces any client-requested
    /// exec/shell command.
    pub force_command: Option<String>,
}

/// Validates an OpenSSH user certificate against a configured CA trust set.
pub trait CertAuthenticator: Send + Sync {
    /// Verify the certificate for the given SSH username.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::CredentialMismatch` on any validation failure.
    /// The operator-side reason is logged separately, never sent over the
    /// wire — spec §6.4.
    fn verify(&self, user: &str, cert: &ParsedCert) -> Result<CertGrants, AuthError>;
}

/// Real implementation: validates against a configured CA trust set, a
/// revocation list, and the current wall-clock time.
pub struct CaTrustCertAuthenticator {
    /// Pre-decoded wire blobs of trusted CA public keys.
    trusted_ca_blobs: Vec<Vec<u8>>,
    /// Revoked cert serial numbers.
    revoked_serials: BTreeSet<u64>,
    /// Source of "now" — pluggable for tests so we can simulate expired /
    /// not-yet-valid certs deterministically.
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    /// Sentinel blob compared against on hygiene paths.
    sentinel_ca: Vec<u8>,
    /// Test/observability hook: number of times the hygiene branch ran.
    dummy_work_count: Arc<AtomicU64>,
}

impl CaTrustCertAuthenticator {
    /// Build the authenticator.
    ///
    /// `trusted_cas` are OpenSSH-format public-key strings (`type base64
    /// [comment]`); `revoked_serials` may be empty.
    ///
    /// # Errors
    ///
    /// `AuthError::Backend` if any CA entry fails to parse.
    pub fn new(trusted_cas: &[String], revoked_serials: &[u64]) -> Result<Self, AuthError> {
        use russh_keys::PublicKeyBase64;
        let mut blobs = Vec::with_capacity(trusted_cas.len());
        for line in trusted_cas {
            let b64 = line.split_whitespace().nth(1).ok_or_else(|| {
                AuthError::Backend(format!(
                    "CA entry missing base64 blob: {}",
                    line.chars().take(40).collect::<String>(),
                ))
            })?;
            let parsed = russh_keys::parse_public_key_base64(b64)
                .map_err(|e| AuthError::Backend(format!("decoding CA: {e}")))?;
            blobs.push(parsed.public_key_bytes());
        }
        Ok(Self {
            trusted_ca_blobs: blobs,
            revoked_serials: revoked_serials.iter().copied().collect(),
            now: Arc::new(SystemTime::now),
            sentinel_ca: vec![0_u8; 32],
            dummy_work_count: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Override the clock source (test hook).
    #[must_use]
    pub fn with_clock(mut self, now: Arc<dyn Fn() -> SystemTime + Send + Sync>) -> Self {
        self.now = now;
        self
    }

    /// Test/observability hook: how many times the hygiene branch ran.
    #[must_use]
    pub fn dummy_work_count(&self) -> u64 {
        self.dummy_work_count.load(Ordering::Relaxed)
    }

    /// Always-run hygiene work on a failure path: constant-time compare
    /// against the sentinel CA, then increment the counter.
    fn run_hygiene_work(&self, payload: &[u8]) {
        let _ = self.sentinel_ca.as_slice().ct_eq(payload);
        self.dummy_work_count.fetch_add(1, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for CaTrustCertAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaTrustCertAuthenticator")
            .field("trusted_cas", &self.trusted_ca_blobs.len())
            .field("revoked_serials", &self.revoked_serials.len())
            .field("dummy_work_count", &self.dummy_work_count())
            .finish_non_exhaustive()
    }
}

/// Serialize the cert's signature key (a `KeyData`) to SSH wire-blob bytes
/// by wrapping it in a `PublicKey` and asking for its wire form.
fn signature_key_bytes(cert: &Certificate) -> Result<Vec<u8>, AuthError> {
    let pub_key: ssh_key::PublicKey = cert.signature_key().clone().into();
    pub_key
        .to_bytes()
        .map_err(|e| AuthError::Backend(format!("re-encoding cert signature key: {e}")))
}

impl CertAuthenticator for CaTrustCertAuthenticator {
    fn verify(&self, user: &str, cert: &ParsedCert) -> Result<CertGrants, AuthError> {
        // 1. Cert type must be User.
        if cert.cert_type() != CertType::User {
            self.run_hygiene_work(b"wrong-cert-type-sentinel");
            tracing::warn!(
                target: "esesaetsch_core::cert",
                user,
                "cert rejected: {}",
                CertError::WrongCertType,
            );
            return Err(AuthError::CredentialMismatch);
        }

        // 2. CA trust — constant-time scan across all trusted CA blobs.
        let sig_key_blob = signature_key_bytes(cert.inner())?;
        let mut trusted = subtle::Choice::from(0_u8);
        for ca in &self.trusted_ca_blobs {
            trusted |= ca.as_slice().ct_eq(&sig_key_blob);
        }
        if !bool::from(trusted) {
            self.run_hygiene_work(&sig_key_blob);
            tracing::warn!(
                target: "esesaetsch_core::cert",
                user,
                "cert rejected: {}",
                CertError::UntrustedCa,
            );
            return Err(AuthError::CredentialMismatch);
        }

        // 3. Signature verify.
        if cert.inner().verify_signature().is_err() {
            self.run_hygiene_work(b"bad-signature-sentinel");
            tracing::warn!(
                target: "esesaetsch_core::cert",
                user,
                "cert rejected: {}",
                CertError::BadSignature,
            );
            return Err(AuthError::CredentialMismatch);
        }

        // 4. Validity window.
        let now_unix = (self.now)()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if now_unix < cert.valid_after() || now_unix >= cert.valid_before() {
            self.run_hygiene_work(b"validity-window-sentinel");
            tracing::warn!(
                target: "esesaetsch_core::cert",
                user,
                "cert rejected: {}",
                CertError::OutsideValidityWindow,
            );
            return Err(AuthError::CredentialMismatch);
        }

        // 5. Principal check.
        if !cert.valid_principals().iter().any(|p| p == user) {
            self.run_hygiene_work(b"principal-sentinel");
            tracing::warn!(
                target: "esesaetsch_core::cert",
                user,
                "cert rejected: {}",
                CertError::PrincipalMismatch,
            );
            return Err(AuthError::CredentialMismatch);
        }

        // 6. Revocation.
        if self.revoked_serials.contains(&cert.serial()) {
            self.run_hygiene_work(b"revoked-sentinel");
            tracing::warn!(
                target: "esesaetsch_core::cert",
                user,
                serial = cert.serial(),
                "cert rejected: {}",
                CertError::Revoked,
            );
            return Err(AuthError::CredentialMismatch);
        }

        // 7. Critical options: parse supported ones; reject any unknown.
        let mut grants = CertGrants::default();
        for (name, value) in cert.inner().critical_options().iter() {
            match name.as_str() {
                "force-command" => {
                    grants.force_command = Some(value.clone());
                }
                other => {
                    self.run_hygiene_work(b"unsupported-option-sentinel");
                    tracing::warn!(
                        target: "esesaetsch_core::cert",
                        user,
                        option = other,
                        "cert rejected: {}",
                        CertError::UnsupportedCriticalOption(other.to_owned()),
                    );
                    return Err(AuthError::CredentialMismatch);
                }
            }
        }

        Ok(grants)
    }
}
