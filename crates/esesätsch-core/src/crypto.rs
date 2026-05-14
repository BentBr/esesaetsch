//! Compiled-in SSH algorithm allowlist.
//!
//! This module is the **single source of truth** for esesätsch's crypto
//! policy (spec §7). There is no runtime configuration knob, no env var,
//! no TOML override. Changing the policy means editing this file, which
//! flows through code review, lint, tests, and CI.
//!
//! Algorithms are listed in **preference order** (most preferred first).
//! Legacy algorithms are absent by design.

/// Allowed key-exchange algorithms.
pub const KEX_ALGORITHMS: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "sntrup761x25519-sha512@openssh.com", // post-quantum hybrid
];

/// Allowed host-key algorithms.
pub const HOST_KEY_ALGORITHMS: &[&str] = &["ssh-ed25519", "rsa-sha2-512"];

/// Allowed symmetric ciphers.
pub const CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
];

/// Allowed MAC algorithms.
pub const MACS: &[&str] = &[
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
];

/// Allowed compression algorithms.
pub const COMPRESSION: &[&str] = &["none", "zlib@openssh.com"];
