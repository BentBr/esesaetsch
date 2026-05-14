//! Tests that the compiled-in crypto allowlist matches spec §7 exactly.
//! Any change to the policy is a code change in `crypto.rs` and must
//! flow through these tests.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use esesaetsch_core::crypto::{CIPHERS, COMPRESSION, HOST_KEY_ALGORITHMS, KEX_ALGORITHMS, MACS};

#[test]
fn kex_algorithms_match_spec() {
    assert_eq!(
        KEX_ALGORITHMS,
        &[
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "sntrup761x25519-sha512@openssh.com",
        ]
    );
}

#[test]
fn host_key_algorithms_match_spec() {
    assert_eq!(HOST_KEY_ALGORITHMS, &["ssh-ed25519", "rsa-sha2-512"]);
}

#[test]
fn ciphers_match_spec() {
    assert_eq!(
        CIPHERS,
        &[
            "chacha20-poly1305@openssh.com",
            "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com",
        ]
    );
}

#[test]
fn macs_match_spec() {
    assert_eq!(
        MACS,
        &[
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
        ]
    );
}

#[test]
fn compression_match_spec() {
    assert_eq!(COMPRESSION, &["none", "zlib@openssh.com"]);
}

#[test]
fn no_legacy_algorithms_present() {
    let forbidden = [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "ssh-rsa",
        "ssh-dss",
        "aes128-cbc",
        "aes256-cbc",
        "3des-cbc",
        "hmac-sha1",
        "hmac-md5",
    ];
    for legacy in forbidden {
        assert!(
            !KEX_ALGORITHMS.contains(&legacy),
            "kex must not list {legacy}"
        );
        assert!(
            !HOST_KEY_ALGORITHMS.contains(&legacy),
            "host-key must not list {legacy}"
        );
        assert!(!CIPHERS.contains(&legacy), "ciphers must not list {legacy}");
        assert!(!MACS.contains(&legacy), "macs must not list {legacy}");
    }
}
