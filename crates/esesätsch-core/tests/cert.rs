//! Integration tests for OpenSSH cert authentication (spec §6.1 cert path,
//! §6.4 cert hygiene, §11.1 cert scenarios).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use esesaetsch_core::cert::{CaTrustCertAuthenticator, CertAuthenticator, ParsedCert};
use esesaetsch_core::error::AuthError;
use ssh_key::certificate::CertType;

use common::{
    CertSpec, build_cert_bytes, pubkey_openssh_line, random_ed25519_key,
};

/// Build a `CaTrustCertAuthenticator` that trusts `ca_key` and has the given
/// revocation list. Uses real wall-clock time.
fn auth_trusting(
    ca_key: &ssh_key::PrivateKey,
    revoked: &[u64],
) -> CaTrustCertAuthenticator {
    let ca_line = pubkey_openssh_line(ca_key, "test-ca");
    CaTrustCertAuthenticator::new(&[ca_line], revoked).expect("constructs")
}

/// `auth_trusting` but with a fixed clock so we can simulate expired /
/// not-yet-valid certs deterministically.
fn auth_trusting_at(
    ca_key: &ssh_key::PrivateKey,
    revoked: &[u64],
    now_unix: u64,
) -> CaTrustCertAuthenticator {
    let now = UNIX_EPOCH + Duration::from_secs(now_unix);
    auth_trusting(ca_key, revoked).with_clock(Arc::new(move || now))
}

#[test]
fn happy_path_cert_validates() {
    let ca = random_ed25519_key();
    let user = random_ed25519_key();
    let bytes = build_cert_bytes(&CertSpec::happy_path(&user, &ca));
    let cert = ParsedCert::parse(&bytes).expect("parse");
    let grants = auth_trusting(&ca, &[]).verify("alice", &cert).expect("validates");
    assert!(grants.force_command.is_none());
}

#[test]
fn cert_signed_by_untrusted_ca_rejects_and_runs_dummy_work() {
    let real_ca = random_ed25519_key();
    let imposter_ca = random_ed25519_key();
    let user = random_ed25519_key();

    // Issue the cert with the imposter CA, but trust only the real CA.
    let bytes = build_cert_bytes(&CertSpec::happy_path(&user, &imposter_ca));
    let cert = ParsedCert::parse(&bytes).expect("parse");
    let auth = auth_trusting(&real_ca, &[]);
    assert_eq!(auth.verify("alice", &cert), Err(AuthError::CredentialMismatch));
    assert_eq!(auth.dummy_work_count(), 1);
}

#[test]
fn malformed_cert_blob_fails_to_parse() {
    assert!(ParsedCert::parse(b"not-a-cert-blob").is_err());
}

#[test]
fn expired_cert_rejects_and_runs_dummy_work() {
    let ca = random_ed25519_key();
    let user = random_ed25519_key();
    let mut spec = CertSpec::happy_path(&user, &ca);
    spec.valid_before = 1_000; // expired in 1970
    let bytes = build_cert_bytes(&spec);
    let cert = ParsedCert::parse(&bytes).expect("parse");
    let auth = auth_trusting_at(&ca, &[], 10_000); // "now" past valid_before
    assert_eq!(auth.verify("alice", &cert), Err(AuthError::CredentialMismatch));
    assert_eq!(auth.dummy_work_count(), 1);
}

#[test]
fn not_yet_valid_cert_rejects() {
    let ca = random_ed25519_key();
    let user = random_ed25519_key();
    let mut spec = CertSpec::happy_path(&user, &ca);
    // Window entirely in the far future relative to our simulated "now".
    spec.valid_after = 200_000_000_000;
    spec.valid_before = 200_000_001_000;
    let bytes = build_cert_bytes(&spec);
    let cert = ParsedCert::parse(&bytes).expect("parse");
    let auth = auth_trusting_at(&ca, &[], 1_000);
    assert_eq!(auth.verify("alice", &cert), Err(AuthError::CredentialMismatch));
    assert_eq!(auth.dummy_work_count(), 1);
}

#[test]
fn wrong_principal_rejects() {
    let ca = random_ed25519_key();
    let user = random_ed25519_key();
    let mut spec = CertSpec::happy_path(&user, &ca);
    spec.principals = vec!["alice".to_owned()];
    let bytes = build_cert_bytes(&spec);
    let cert = ParsedCert::parse(&bytes).expect("parse");
    let auth = auth_trusting(&ca, &[]);
    assert_eq!(auth.verify("mallory", &cert), Err(AuthError::CredentialMismatch));
    assert_eq!(auth.dummy_work_count(), 1);
}

#[test]
fn revoked_serial_rejects() {
    let ca = random_ed25519_key();
    let user = random_ed25519_key();
    let mut spec = CertSpec::happy_path(&user, &ca);
    spec.serial = 42;
    let bytes = build_cert_bytes(&spec);
    let cert = ParsedCert::parse(&bytes).expect("parse");
    let auth = auth_trusting(&ca, &[42]);
    assert_eq!(auth.verify("alice", &cert), Err(AuthError::CredentialMismatch));
    assert_eq!(auth.dummy_work_count(), 1);
}

#[test]
fn host_cert_rejects() {
    let ca = random_ed25519_key();
    let user = random_ed25519_key();
    let mut spec = CertSpec::happy_path(&user, &ca);
    spec.cert_type = CertType::Host;
    // Host certs have hostnames, not user names; use a hostname.
    spec.principals = vec!["host.example.com".to_owned()];
    let bytes = build_cert_bytes(&spec);
    let cert = ParsedCert::parse(&bytes).expect("parse");
    let auth = auth_trusting(&ca, &[]);
    assert_eq!(auth.verify("alice", &cert), Err(AuthError::CredentialMismatch));
    assert_eq!(auth.dummy_work_count(), 1);
}

#[test]
fn unknown_critical_option_rejects() {
    let ca = random_ed25519_key();
    let user = random_ed25519_key();
    let mut spec = CertSpec::happy_path(&user, &ca);
    spec.critical_options = vec![("source-address".to_owned(), "10.0.0.0/8".to_owned())];
    let bytes = build_cert_bytes(&spec);
    let cert = ParsedCert::parse(&bytes).expect("parse");
    let auth = auth_trusting(&ca, &[]);
    assert_eq!(auth.verify("alice", &cert), Err(AuthError::CredentialMismatch));
    assert_eq!(auth.dummy_work_count(), 1);
}

#[test]
fn force_command_critical_option_populates_grants() {
    let ca = random_ed25519_key();
    let user = random_ed25519_key();
    let mut spec = CertSpec::happy_path(&user, &ca);
    spec.critical_options = vec![("force-command".to_owned(), "/usr/bin/echo locked".to_owned())];
    let bytes = build_cert_bytes(&spec);
    let cert = ParsedCert::parse(&bytes).expect("parse");
    let auth = auth_trusting(&ca, &[]);
    let grants = auth.verify("alice", &cert).expect("validates");
    assert_eq!(grants.force_command.as_deref(), Some("/usr/bin/echo locked"));
}

#[test]
fn malformed_ca_entry_in_trust_list_fails_construction() {
    let err = CaTrustCertAuthenticator::new(&["not-a-ca".to_owned()], &[]).expect_err("rejects");
    assert!(matches!(err, AuthError::Backend(_)));
}

#[test]
fn dummy_work_counter_increments_per_failure() {
    let real_ca = random_ed25519_key();
    let imposter_ca = random_ed25519_key();
    let user = random_ed25519_key();

    let bytes = build_cert_bytes(&CertSpec::happy_path(&user, &imposter_ca));
    let cert = ParsedCert::parse(&bytes).expect("parse");
    let auth = auth_trusting(&real_ca, &[]);

    let _ = auth.verify("alice", &cert);
    let _ = auth.verify("bob", &cert);
    let _ = auth.verify("carol", &cert);
    assert_eq!(auth.dummy_work_count(), 3);
}

#[test]
fn happy_path_does_not_increment_dummy_work() {
    let ca = random_ed25519_key();
    let user = random_ed25519_key();
    let bytes = build_cert_bytes(&CertSpec::happy_path(&user, &ca));
    let cert = ParsedCert::parse(&bytes).expect("parse");
    let auth = auth_trusting(&ca, &[]);
    auth.verify("alice", &cert).expect("ok");
    assert_eq!(auth.dummy_work_count(), 0);
}

#[test]
fn parsed_cert_exposes_metadata() {
    let ca = random_ed25519_key();
    let user = random_ed25519_key();
    let mut spec = CertSpec::happy_path(&user, &ca);
    spec.serial = 99;
    spec.key_id = "auditable-label".to_owned();
    let bytes = build_cert_bytes(&spec);
    let cert = ParsedCert::parse(&bytes).expect("parse");
    assert_eq!(cert.serial(), 99);
    assert_eq!(cert.key_id(), "auditable-label");
    assert_eq!(cert.cert_type(), CertType::User);
    assert_eq!(cert.valid_principals(), &["alice".to_owned()]);
}
