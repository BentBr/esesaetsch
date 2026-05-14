//! Wire-level negotiation tests for the compiled-in crypto allowlist.
//!
//! For each allowed algorithm slot (KEX, cipher, MAC, compression) we
//! constrain the russh **client** to a single algorithm and verify the
//! handshake succeeds. For each rejected/legacy algorithm we constrain
//! the client to only that legacy value and verify the handshake fails.
//!
//! These tests exercise russh's real negotiator against our real
//! `EsesätschServer` configured with `crypto::preferences()`.

mod common;

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use russh::client::Config as ClientConfig;
use tokio::time::timeout;

use common::{AcceptAnyClientHandler, TestServer};

/// Build a client `Config` that only proposes the given KEX algorithm,
/// leaving the other slots at russh defaults.
fn client_with_only_kex(kex: russh::kex::Name) -> Arc<ClientConfig> {
    let mut cfg = ClientConfig::default();
    cfg.preferred.kex = Cow::Owned(vec![kex]);
    Arc::new(cfg)
}

/// Build a client `Config` that only proposes the given cipher.
fn client_with_only_cipher(cipher: russh::cipher::Name) -> Arc<ClientConfig> {
    let mut cfg = ClientConfig::default();
    cfg.preferred.cipher = Cow::Owned(vec![cipher]);
    Arc::new(cfg)
}

/// Build a client `Config` that only proposes the given MAC.
fn client_with_only_mac(mac: russh::mac::Name) -> Arc<ClientConfig> {
    let mut cfg = ClientConfig::default();
    cfg.preferred.mac = Cow::Owned(vec![mac]);
    Arc::new(cfg)
}

/// Try to complete the SSH handshake against the given server using the
/// given client config. Returns `Ok` on a successful handshake; `Err` if
/// connect/handshake fails for any reason (including no shared algorithm).
async fn try_handshake(server: &TestServer, client_cfg: Arc<ClientConfig>) -> Result<(), String> {
    let outcome = timeout(
        Duration::from_secs(5),
        russh::client::connect(client_cfg, server.bound_addr, AcceptAnyClientHandler),
    )
    .await
    .map_err(|_| "connect timed out".to_owned())?;

    match outcome {
        Ok(_handle) => Ok(()),
        Err(e) => Err(format!("{e:?}")),
    }
}

// =====================================================================
// Negotiation succeeds for each allowlisted algorithm
// =====================================================================

#[tokio::test]
async fn kex_curve25519_sha256_negotiates() {
    let (server, _user_key) = TestServer::with_default_users().await;
    try_handshake(&server, client_with_only_kex(russh::kex::CURVE25519))
        .await
        .expect("curve25519-sha256 must negotiate");
}

#[tokio::test]
async fn kex_curve25519_sha256_libssh_org_negotiates() {
    let (server, _user_key) = TestServer::with_default_users().await;
    try_handshake(
        &server,
        client_with_only_kex(russh::kex::CURVE25519_PRE_RFC_8731),
    )
    .await
    .expect("curve25519-sha256@libssh.org must negotiate");
}

#[tokio::test]
async fn cipher_chacha20_poly1305_negotiates() {
    let (server, _user_key) = TestServer::with_default_users().await;
    try_handshake(
        &server,
        client_with_only_cipher(russh::cipher::CHACHA20_POLY1305),
    )
    .await
    .expect("chacha20-poly1305@openssh.com must negotiate");
}

#[tokio::test]
async fn cipher_aes256_gcm_negotiates() {
    let (server, _user_key) = TestServer::with_default_users().await;
    try_handshake(&server, client_with_only_cipher(russh::cipher::AES_256_GCM))
        .await
        .expect("aes256-gcm@openssh.com must negotiate");
}

#[tokio::test]
async fn mac_hmac_sha512_etm_negotiates() {
    let (server, _user_key) = TestServer::with_default_users().await;
    try_handshake(&server, client_with_only_mac(russh::mac::HMAC_SHA512_ETM))
        .await
        .expect("hmac-sha2-512-etm@openssh.com must negotiate");
}

#[tokio::test]
async fn mac_hmac_sha256_etm_negotiates() {
    let (server, _user_key) = TestServer::with_default_users().await;
    try_handshake(&server, client_with_only_mac(russh::mac::HMAC_SHA256_ETM))
        .await
        .expect("hmac-sha2-256-etm@openssh.com must negotiate");
}

// =====================================================================
// Legacy algorithms are rejected at handshake
// =====================================================================

#[tokio::test]
async fn legacy_cipher_aes128_cbc_is_rejected() {
    let (server, _user_key) = TestServer::with_default_users().await;
    let outcome = try_handshake(&server, client_with_only_cipher(russh::cipher::AES_128_CBC)).await;
    assert!(
        outcome.is_err(),
        "client offering only aes128-cbc must fail to negotiate, got {outcome:?}",
    );
}

#[tokio::test]
async fn legacy_cipher_aes256_cbc_is_rejected() {
    let (server, _user_key) = TestServer::with_default_users().await;
    let outcome = try_handshake(&server, client_with_only_cipher(russh::cipher::AES_256_CBC)).await;
    assert!(
        outcome.is_err(),
        "client offering only aes256-cbc must fail to negotiate, got {outcome:?}",
    );
}

#[tokio::test]
async fn legacy_cipher_3des_cbc_is_rejected() {
    let (server, _user_key) = TestServer::with_default_users().await;
    let outcome = try_handshake(
        &server,
        client_with_only_cipher(russh::cipher::TRIPLE_DES_CBC),
    )
    .await;
    assert!(
        outcome.is_err(),
        "client offering only 3des-cbc must fail to negotiate, got {outcome:?}",
    );
}

// Legacy-MAC tests are intentionally omitted: our cipher allowlist is
// AEAD-only (chacha20-poly1305 and aes256-gcm). SSH treats the MAC
// negotiation as moot when the chosen cipher provides built-in
// authentication. Constraining a client to only `hmac-sha1` therefore
// still succeeds — the negotiator settles on an AEAD cipher and the
// MAC list is ignored by both sides. The MAC entry of our `Preferred`
// only matters if a future change ever adds a non-AEAD cipher.
