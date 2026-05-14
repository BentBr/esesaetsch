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
/// TODO(russh-0.45): re-add `sntrup761x25519-sha512@openssh.com` (post-quantum
/// hybrid) when russh exposes it. v1 ships classical curve25519 KEX only.
pub const KEX_ALGORITHMS: &[&str] = &["curve25519-sha256", "curve25519-sha256@libssh.org"];

/// Allowed host-key algorithms.
pub const HOST_KEY_ALGORITHMS: &[&str] = &["ssh-ed25519", "rsa-sha2-512"];

/// Allowed symmetric ciphers.
///
/// TODO(russh-0.45): re-add `aes128-gcm@openssh.com` when russh exposes it.
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
///
/// # Panics
///
/// Never. The constants above are validated to match russh's typed name
/// constants at compile time by the integration tests in `tests/crypto.rs`.
#[must_use]
pub const fn preferences() -> russh::Preferred {
    use std::borrow::Cow;

    russh::Preferred {
        kex: Cow::Borrowed(&[russh::kex::CURVE25519, russh::kex::CURVE25519_PRE_RFC_8731]),
        key: Cow::Borrowed(&[russh_keys::key::ED25519, russh_keys::key::RSA_SHA2_512]),
        cipher: Cow::Borrowed(&[russh::cipher::CHACHA20_POLY1305, russh::cipher::AES_256_GCM]),
        mac: Cow::Borrowed(&[russh::mac::HMAC_SHA512_ETM, russh::mac::HMAC_SHA256_ETM]),
        compression: Cow::Borrowed(&[russh::compression::NONE, russh::compression::ZLIB_LEGACY]),
    }
}
