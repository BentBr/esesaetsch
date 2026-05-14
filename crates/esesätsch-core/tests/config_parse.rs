//! Top-level surface tests: the public types exist with the expected fields
//! and the TOML examples from spec §5.3 parse without error.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use esesaetsch_core::config::{AuthConfig, CaConfig, LoggingConfig, ServerConfig, TomlConfig};

#[test]
fn parses_minimal_toml() {
    let raw = r#"
        [server]
        bind = "0.0.0.0"
        port = 2222
        host_key = "./host_key"

        [auth]
        password_enabled = false
        pubkey_enabled = true
        cert_enabled = false
        max_auth_attempts = 3

        [auth.authorized_keys]
        alice = ["ssh-ed25519 AAAA alice@laptop"]
    "#;
    let cfg: TomlConfig = toml::from_str(raw).expect("parses");
    assert_eq!(cfg.server.port, Some(2222));
    assert_eq!(cfg.auth.pubkey_enabled, Some(true));
    assert!(cfg.auth.authorized_keys.contains_key("alice"));
}

#[test]
fn parses_full_toml_with_ca() {
    let raw = r#"
        [server]
        bind = "127.0.0.1"
        port = 22000
        host_key = "/etc/esesätsch/host_key"

        [auth]
        password_enabled = true
        pubkey_enabled = true
        cert_enabled = true
        max_auth_attempts = 5

        [auth.authorized_keys]
        bob = ["ssh-ed25519 AAAA bob@desktop"]

        [auth.ca]
        trusted = ["ssh-ed25519 AAAA primary-ca"]
        revoked_serials = [1, 2, 17]

        [logging]
        level = "debug"
        packet_trace = false
    "#;
    let cfg: TomlConfig = toml::from_str(raw).expect("parses");
    let ca: &CaConfig = cfg.auth.ca.as_ref().expect("ca present");
    assert_eq!(ca.trusted.len(), 1);
    assert_eq!(ca.revoked_serials, vec![1, 2, 17]);
    assert_eq!(
        cfg.logging.as_ref().and_then(|l| l.level.as_deref()),
        Some("debug"),
    );
}

#[test]
fn empty_toml_yields_defaults() {
    let cfg: TomlConfig = toml::from_str("").expect("parses empty");
    assert_eq!(cfg.server, ServerConfig::default());
    assert_eq!(cfg.auth, AuthConfig::default());
    assert!(cfg.logging.is_none());
}

#[test]
fn unknown_field_rejected() {
    // Misspelled `port` -> rejected by serde(deny_unknown_fields).
    let raw = r"
        [server]
        prot = 2222
    ";
    assert!(toml::from_str::<TomlConfig>(raw).is_err());
}

#[test]
fn logging_struct_round_trips_via_default() {
    let _ = LoggingConfig::default();
}
