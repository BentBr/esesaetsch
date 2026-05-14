//! Tests for the built-in default config (spec §5.5).
//!
//! When no config file and no CLI overrides are provided, `Config::defaults()`
//! returns the documented default values.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use esesaetsch_core::config::Config;
use std::net::SocketAddr;
use std::path::PathBuf;

#[test]
fn defaults_match_spec_5_5() {
    let cfg = Config::defaults();
    assert_eq!(cfg.bind, "0.0.0.0:2222".parse::<SocketAddr>().unwrap());
    assert_eq!(cfg.host_key, PathBuf::from("./host_key"));
    assert!(!cfg.password_enabled);
    assert!(cfg.pubkey_enabled);
    assert!(!cfg.cert_enabled);
    assert_eq!(cfg.max_auth_attempts, 3);
    assert!(cfg.authorized_keys.is_empty());
    assert!(cfg.ca_trusted.is_empty());
    assert!(cfg.ca_revoked_serials.is_empty());
    assert_eq!(cfg.logging_level, "info");
    assert!(!cfg.packet_trace);
}
