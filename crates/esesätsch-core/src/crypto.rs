//! Compiled-in SSH algorithm allowlist.
//!
//! This module is the **single source of truth** for esesätsch's crypto
//! policy. There is no runtime configuration knob, no env var,
//! no TOML override. Changing the policy means editing this file, which
//! flows through code review, lint, tests, and CI.
//!
//! Algorithms are listed in **preference order** (most preferred first).
//! Legacy algorithms are absent by design.

/// Allowed key-exchange algorithms.
///
/// Includes `mlkem768x25519-sha256` — the IETF-standardised ML-KEM/X25519
/// hybrid that OpenSSH 9.9+ negotiates by default and that protects the
/// session against future quantum-capable attackers ("store now, decrypt
/// later").
pub const KEX_ALGORITHMS: &[&str] = &[
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
];

/// Allowed host-key algorithms.
pub const HOST_KEY_ALGORITHMS: &[&str] = &["ssh-ed25519", "rsa-sha2-512"];

/// Allowed symmetric ciphers.
///
/// TODO(russh): re-add `aes128-gcm@openssh.com` when russh exposes it.
pub const CIPHERS: &[&str] = &["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"];

/// Allowed MAC algorithms.
pub const MACS: &[&str] = &[
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
];

/// Allowed compression algorithms.
pub const COMPRESSION: &[&str] = &["none", "zlib@openssh.com"];

/// Build the `russh::Preferred` algorithm-preference set from the compiled-in
/// allowlist constants. This is the single point at which the policy is
/// handed off to russh's negotiator.
#[must_use]
pub fn preferences() -> russh::Preferred {
    use russh::keys::ssh_key::{Algorithm, HashAlg};
    use std::borrow::Cow;

    russh::Preferred {
        kex: Cow::Borrowed(&[
            russh::kex::MLKEM768X25519_SHA256,
            russh::kex::CURVE25519,
            russh::kex::CURVE25519_PRE_RFC_8731,
        ]),
        key: Cow::Owned(vec![
            Algorithm::Ed25519,
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        ]),
        cipher: Cow::Borrowed(&[russh::cipher::CHACHA20_POLY1305, russh::cipher::AES_256_GCM]),
        mac: Cow::Borrowed(&[russh::mac::HMAC_SHA512_ETM, russh::mac::HMAC_SHA256_ETM]),
        compression: Cow::Borrowed(&[russh::compression::NONE, russh::compression::ZLIB_LEGACY]),
    }
}
