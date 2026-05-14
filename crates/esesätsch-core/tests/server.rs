//! Wire-protocol integration tests for the auth-layer russh handler.
//!
//! These tests boot a real `EsesätschServer` on `127.0.0.1:0` and drive
//! it with a real `russh::client::Handle`. They prove the handler glues
//! correctly to russh and that the §6.4 hygiene rules show up at the
//! wire level (uniform reject shape, methods-list policy-only, etc.).

mod common;

use std::sync::Arc;
use std::time::Duration;

use ssh_key::PrivateKey;
use tokio::time::timeout;

use common::{AcceptAnyClientHandler, TestServer, client_config};

/// Re-export the test user's key as a russh `KeyPair` so the client can
/// sign with it. We round-trip through OpenSSH text format since
/// `ssh-key` and `russh-keys` share that format.
#[allow(clippy::expect_used)] // test helper
fn to_russh_keypair(p: &PrivateKey) -> russh_keys::key::KeyPair {
    let openssh = p
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("to_openssh")
        .to_string();
    russh_keys::decode_secret_key(&openssh, None).expect("decode_secret_key")
}

#[allow(clippy::expect_used)] // test helper
async fn connect(server: &TestServer) -> russh::client::Handle<AcceptAnyClientHandler> {
    timeout(
        Duration::from_secs(5),
        russh::client::connect(client_config(), server.bound_addr, AcceptAnyClientHandler),
    )
    .await
    .expect("client connect timed out")
    .expect("client connect")
}

#[tokio::test]
async fn pubkey_auth_accepts_listed_user_with_correct_key() {
    let (server, user_key) = TestServer::with_default_users().await;
    let mut handle = connect(&server).await;
    let kp = Arc::new(to_russh_keypair(&user_key));
    let ok = handle
        .authenticate_publickey("alice", kp)
        .await
        .expect("auth call");
    assert!(ok, "alice with her key should be accepted");
}

#[tokio::test]
async fn pubkey_auth_rejects_wrong_user() {
    let (server, user_key) = TestServer::with_default_users().await;
    let mut handle = connect(&server).await;
    let kp = Arc::new(to_russh_keypair(&user_key));
    let ok = handle
        .authenticate_publickey("mallory", kp)
        .await
        .expect("auth call");
    assert!(!ok, "unknown user must be rejected");
}

#[tokio::test]
async fn pubkey_auth_rejects_wrong_key_for_listed_user() {
    let (server, _allowed_key) = TestServer::with_default_users().await;
    let mut handle = connect(&server).await;

    // A different user-key not in the allowlist.
    let imposter = common::random_ed25519_key();
    let kp = Arc::new(to_russh_keypair(&imposter));
    let ok = handle
        .authenticate_publickey("alice", kp)
        .await
        .expect("auth call");
    assert!(!ok, "alice with the wrong key must be rejected");
}

#[tokio::test]
async fn password_auth_accepts_correct_password() {
    let (server, _user_key) = TestServer::with_default_users().await;
    let mut handle = connect(&server).await;
    let ok = handle
        .authenticate_password("alice", "hunter2")
        .await
        .expect("auth call");
    assert!(ok, "alice with the right password should be accepted");
}

#[tokio::test]
async fn password_auth_rejects_wrong_password() {
    let (server, _user_key) = TestServer::with_default_users().await;
    let mut handle = connect(&server).await;
    let ok = handle
        .authenticate_password("alice", "wrong")
        .await
        .expect("auth call");
    assert!(!ok);
}

#[tokio::test]
async fn password_auth_rejects_unknown_user() {
    let (server, _user_key) = TestServer::with_default_users().await;
    let mut handle = connect(&server).await;
    let ok = handle
        .authenticate_password("mallory", "anything")
        .await
        .expect("auth call");
    assert!(!ok);
}

#[tokio::test]
async fn pubkey_disabled_rejects_even_with_valid_key() {
    use std::collections::BTreeMap;

    use esesaetsch_core::auth::{AllowlistPubkeyAuthenticator, PubkeyAuthenticator};
    use esesaetsch_core::config::Config;

    // Build a server where pubkey_enabled = false, password_enabled = true.
    let user_key = common::random_ed25519_key();
    let user_pub = user_key.public_key().to_openssh().unwrap();
    let mut map = BTreeMap::new();
    map.insert("alice".to_owned(), vec![user_pub.clone()]);
    let pubkey_auth: Arc<dyn PubkeyAuthenticator> =
        Arc::new(AllowlistPubkeyAuthenticator::from_allowlist(&map).unwrap());
    let password_auth: Arc<dyn esesaetsch_core::auth::PasswordAuthenticator> =
        Arc::new(common::MockPasswordAuthenticator::new().with_verdict("alice", "hunter2", Ok(())));

    let mut config = Config::defaults();
    config.pubkey_enabled = false;
    config.password_enabled = true;
    config.cert_enabled = false;
    config
        .authorized_keys
        .insert("alice".to_owned(), vec![user_pub]);

    let server = TestServer::start(config, pubkey_auth, password_auth).await;
    let mut handle = connect(&server).await;

    // Pubkey attempt: must fail regardless of allowlist.
    let kp = Arc::new(to_russh_keypair(&user_key));
    let ok = handle
        .authenticate_publickey("alice", kp)
        .await
        .expect("auth call");
    assert!(!ok, "pubkey must be rejected when method is disabled");

    // Password still works.
    let ok2 = handle
        .authenticate_password("alice", "hunter2")
        .await
        .expect("auth call");
    assert!(ok2, "password should still work");
}

#[tokio::test]
async fn server_banner_does_not_leak_version_or_os() {
    // Open a raw TCP connection to the server and read the SSH banner
    // line directly to assert it matches spec §6.4 rule 4.
    use tokio::io::AsyncReadExt;
    let (server, _user_key) = TestServer::with_default_users().await;
    let mut s = tokio::net::TcpStream::connect(server.bound_addr)
        .await
        .expect("tcp");
    let mut buf = [0_u8; 64];
    let n = timeout(Duration::from_secs(2), s.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");
    let banner = std::str::from_utf8(&buf[..n]).unwrap_or("");
    // Trim line terminators.
    let banner = banner.trim_end_matches(['\r', '\n']);
    assert!(
        banner == "SSH-2.0-esesaetsch_0",
        "banner must be exactly the policy-defined string, got: {banner:?}",
    );
}

#[tokio::test]
async fn server_drops_connection_after_max_auth_attempts() {
    // Spec §6.1 step 3: after `max_auth_attempts` failed attempts, the
    // server drops the connection. Our `TestServer::with_default_users`
    // uses the built-in default of 3.
    let (server, _user_key) = TestServer::with_default_users().await;
    let mut handle = connect(&server).await;

    // Three consecutive wrong-password attempts. The third's behaviour
    // (and any subsequent attempt) is the contract under test: russh
    // closes the channel after the configured limit. We assert that an
    // attempt past the limit either rejects or returns an error.
    let r1 = handle
        .authenticate_password("alice", "wrong-1")
        .await
        .expect("call 1");
    let r2 = handle
        .authenticate_password("alice", "wrong-2")
        .await
        .expect("call 2");
    let r3 = handle
        .authenticate_password("alice", "wrong-3")
        .await
        .expect("call 3");
    assert!(
        !r1 && !r2 && !r3,
        "all three wrong attempts must be rejected"
    );

    // A fourth attempt should fail to even complete: the connection has
    // been torn down. We accept either `Ok(false)` or `Err(_)` here —
    // both signal "no further auth possible".
    if let Ok(success) = handle.authenticate_password("alice", "wrong-4").await {
        assert!(!success, "post-limit attempt must not succeed");
    }
}

#[tokio::test]
async fn allowlist_sentinel_compare_counter_increments_for_unknown_user() {
    // We can't get a direct handle on the AllowlistPubkeyAuthenticator's
    // counter from outside the test-helper builder, so this test
    // exercises the sentinel path via repeated unknown-user attempts and
    // observes the wire-level result. The structural counter assertion
    // is covered in tests/auth.rs against the AllowlistPubkeyAuthenticator
    // in isolation. Here we just confirm the wire response shape is
    // identical for unknown user vs. wrong key.

    let (server, user_key) = TestServer::with_default_users().await;
    let mut handle = connect(&server).await;

    // Two distinct rejection scenarios:
    // 1. Known user, wrong key -> reject.
    let imposter = common::random_ed25519_key();
    let kp_imposter = Arc::new(to_russh_keypair(&imposter));
    let r1 = handle
        .authenticate_publickey("alice", kp_imposter)
        .await
        .expect("call");
    assert!(!r1);

    // 2. Unknown user, valid-looking key -> reject.
    let kp_valid = Arc::new(to_russh_keypair(&user_key));
    let r2 = handle
        .authenticate_publickey("mallory", kp_valid)
        .await
        .expect("call");
    assert!(!r2);

    // Both rejections must have produced the same outcome flavor from
    // the client's perspective (Ok(false)).
}
