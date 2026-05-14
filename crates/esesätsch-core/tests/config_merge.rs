//! Precedence: CLI > TOML > defaults (spec §5.1).
//!
//! Each test covers one merge precedence rule.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use esesaetsch_core::config::{Cli, Config, TomlConfig};
use std::path::PathBuf;

fn parse(raw: &str) -> TomlConfig {
    toml::from_str(raw).expect("test toml parses")
}

#[test]
fn no_toml_no_cli_returns_defaults() {
    let cli = Cli::default();
    let cfg = Config::from_sources(&cli, None).expect("merges");
    assert_eq!(cfg, Config::defaults());
}

#[test]
fn toml_overrides_defaults() {
    let toml_cfg = parse(
        r#"
        [server]
        port = 5000
        host_key = "/srv/host_key"
    "#,
    );
    let cfg = Config::from_sources(&Cli::default(), Some(toml_cfg)).unwrap();
    assert_eq!(cfg.bind.port(), 5000);
    assert_eq!(cfg.host_key, PathBuf::from("/srv/host_key"));
}

#[test]
fn cli_overrides_toml() {
    let toml_cfg = parse(
        r#"
        [server]
        port = 5000
        host_key = "/srv/host_key"
    "#,
    );
    let cli = Cli {
        port: Some(7000),
        host_key: Some(PathBuf::from("/override/host_key")),
        ..Cli::default()
    };
    let cfg = Config::from_sources(&cli, Some(toml_cfg)).unwrap();
    assert_eq!(cfg.bind.port(), 7000);
    assert_eq!(cfg.host_key, PathBuf::from("/override/host_key"));
}

#[test]
fn cli_bind_replaces_only_address_not_port() {
    let toml_cfg = parse(
        r"
        [server]
        port = 9000
    ",
    );
    let cli = Cli {
        bind: Some("127.0.0.1".to_owned()),
        ..Cli::default()
    };
    let cfg = Config::from_sources(&cli, Some(toml_cfg)).unwrap();
    assert_eq!(cfg.bind.port(), 9000);
    assert_eq!(cfg.bind.ip().to_string(), "127.0.0.1");
}

#[test]
fn debug_flag_sets_logging_level() {
    let cli = Cli {
        debug: true,
        ..Cli::default()
    };
    let cfg = Config::from_sources(&cli, None).unwrap();
    assert_eq!(cfg.logging_level, "debug");
}

#[test]
fn trace_flag_implies_debug_and_packet_trace() {
    let cli = Cli {
        trace: true,
        ..Cli::default()
    };
    let cfg = Config::from_sources(&cli, None).unwrap();
    assert_eq!(cfg.logging_level, "trace");
    assert!(cfg.packet_trace);
}

#[test]
fn invalid_bind_in_toml_returns_error() {
    let toml_cfg = parse(
        r#"
        [server]
        bind = "not-an-address"
    "#,
    );
    assert!(Config::from_sources(&Cli::default(), Some(toml_cfg)).is_err());
}

#[test]
fn invalid_bind_in_cli_returns_error() {
    let cli = Cli {
        bind: Some("garbage".to_owned()),
        ..Cli::default()
    };
    assert!(Config::from_sources(&cli, None).is_err());
}
