//! Tests that the compiled-in crypto allowlist matches spec §7 exactly.
//! Any change to the policy is a code change in `crypto.rs` and must
//! flow through these tests.

use esesaetsch_core::crypto::{CIPHERS, COMPRESSION, HOST_KEY_ALGORITHMS, KEX_ALGORITHMS, MACS};

#[test]
fn kex_algorithms_match_spec() {
    // sntrup761x25519-sha512@openssh.com is in the spec but absent from
    // russh 0.45; tracked via TODO in crypto.rs.
    assert_eq!(
        KEX_ALGORITHMS,
        &["curve25519-sha256", "curve25519-sha256@libssh.org"]
    );
}

#[test]
fn host_key_algorithms_match_spec() {
    assert_eq!(HOST_KEY_ALGORITHMS, &["ssh-ed25519", "rsa-sha2-512"]);
}

#[test]
fn ciphers_match_spec() {
    // aes128-gcm@openssh.com is in the spec but absent from russh 0.45.
    assert_eq!(
        CIPHERS,
        &["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"]
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

fn as_strs<T: AsRef<str>>(v: &[T]) -> Vec<&str> {
    v.iter().map(AsRef::as_ref).collect()
}

#[test]
fn preferences_lists_match_constants() {
    // The russh::Preferred we hand to the negotiator must reflect exactly
    // what KEX_ALGORITHMS, HOST_KEY_ALGORITHMS, CIPHERS, MACS, COMPRESSION
    // declare. This guards against a future edit drifting the two apart.
    let prefs = esesaetsch_core::crypto::preferences();
    assert_eq!(as_strs(&prefs.kex), KEX_ALGORITHMS);
    assert_eq!(as_strs(&prefs.key), HOST_KEY_ALGORITHMS);
    assert_eq!(as_strs(&prefs.cipher), CIPHERS);
    assert_eq!(as_strs(&prefs.mac), MACS);
    assert_eq!(as_strs(&prefs.compression), COMPRESSION);
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
