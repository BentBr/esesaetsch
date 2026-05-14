//! Integration tests for the auth trait surfaces (spec §6.3, §6.4).

mod common;

use std::collections::BTreeMap;

use esesaetsch_core::auth::{
    AllowlistPubkeyAuthenticator, PasswordAuthenticator, PubkeyAuthenticator,
};
use esesaetsch_core::error::AuthError;
use russh_keys::PublicKeyBase64;

use common::{ED25519_FIXTURE, MockPasswordAuthenticator, pubkey_blob};

#[allow(clippy::expect_used)] // test helper: panic on setup failure is fine
fn allowlist_with_alice() -> AllowlistPubkeyAuthenticator {
    let mut map = BTreeMap::new();
    map.insert("alice".to_owned(), vec![ED25519_FIXTURE.to_owned()]);
    AllowlistPubkeyAuthenticator::from_allowlist(&map).expect("constructs")
}

#[test]
fn pubkey_accept_for_listed_user_and_matching_key() {
    let auth = allowlist_with_alice();
    let blob = pubkey_blob(ED25519_FIXTURE);
    auth.verify("alice", &blob).expect("matches");
}

#[test]
fn pubkey_reject_for_listed_user_and_wrong_key() {
    let auth = allowlist_with_alice();
    // 32 zero bytes — definitely not alice's actual ed25519 wire blob.
    let bogus = vec![0_u8; 32];
    let outcome = auth.verify("alice", &bogus);
    assert_eq!(outcome, Err(AuthError::CredentialMismatch));
    // Sentinel branch must NOT have run — known user, just wrong key.
    assert_eq!(auth.sentinel_compares(), 0);
}

#[test]
fn pubkey_reject_for_unknown_user_runs_sentinel_compare() {
    let auth = allowlist_with_alice();
    let blob = pubkey_blob(ED25519_FIXTURE);
    let outcome = auth.verify("mallory", &blob);
    assert_eq!(outcome, Err(AuthError::UnknownUser));
    // Sentinel branch ran exactly once.
    assert_eq!(auth.sentinel_compares(), 1);
}

#[test]
fn pubkey_sentinel_increments_per_unknown_user_call() {
    let auth = allowlist_with_alice();
    let blob = pubkey_blob(ED25519_FIXTURE);
    let _ = auth.verify("alpha", &blob);
    let _ = auth.verify("beta", &blob);
    let _ = auth.verify("gamma", &blob);
    assert_eq!(auth.sentinel_compares(), 3);
}

#[test]
fn pubkey_allowlist_rejects_malformed_entry_at_construction() {
    let mut map = BTreeMap::new();
    map.insert("alice".to_owned(), vec!["NOT-A-KEY".to_owned()]);
    let err = AllowlistPubkeyAuthenticator::from_allowlist(&map).expect_err("rejects");
    assert!(matches!(err, AuthError::Backend(_)));
}

#[test]
fn pubkey_allowlist_supports_multiple_keys_per_user() {
    // Generate a second valid key so we can list two keys for one user and
    // verify either matches.
    let key2 = russh_keys::key::KeyPair::generate_ed25519().unwrap();
    let key2_pub = key2.clone_public_key().unwrap();
    let key2_line = format!(
        "{} {} test-key-2",
        key2_pub.name(),
        key2_pub.public_key_base64()
    );

    let mut map = BTreeMap::new();
    map.insert(
        "bob".to_owned(),
        vec![ED25519_FIXTURE.to_owned(), key2_line.clone()],
    );
    let auth = AllowlistPubkeyAuthenticator::from_allowlist(&map).expect("constructs");

    let blob1 = pubkey_blob(ED25519_FIXTURE);
    let blob2 = pubkey_blob(&key2_line);
    auth.verify("bob", &blob1).expect("first key matches");
    auth.verify("bob", &blob2).expect("second key matches");
}

// ----- MockPasswordAuthenticator hygiene tests -----

#[test]
fn password_mock_accepts_when_scripted() {
    let auth = MockPasswordAuthenticator::new().with_verdict("alice", "secret", Ok(()));
    auth.verify("alice", "secret").expect("scripted ok");
}

#[test]
fn password_mock_rejects_wrong_password_without_dummy_work() {
    let auth = MockPasswordAuthenticator::new().with_verdict("alice", "secret", Ok(()));
    let outcome = auth.verify("alice", "wrong");
    assert_eq!(outcome, Err(AuthError::CredentialMismatch));
    assert_eq!(
        auth.dummy_work_count(),
        0,
        "known-user path must not run dummy work"
    );
}

#[test]
fn password_mock_unknown_user_runs_dummy_work() {
    let auth = MockPasswordAuthenticator::new().with_verdict("alice", "secret", Ok(()));
    let outcome = auth.verify("mallory", "anything");
    assert_eq!(outcome, Err(AuthError::UnknownUser));
    assert_eq!(
        auth.dummy_work_count(),
        1,
        "unknown-user path must run dummy work once"
    );
}
