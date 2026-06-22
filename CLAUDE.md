# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`esesätsch` is a strict, cross-platform SSH server in Rust — a drop-in `sshd` alternative with a modern-crypto-only wire policy compiled into the binary (no runtime knob to weaken it). Pre-1.0; not yet on crates.io.

## Toolchain gotcha: name vs. directory

The on-disk crate directories use the `ä` spelling (`crates/esesätsch-core`, `crates/esesätsch`), but the **Cargo package names are ASCII**: `esesaetsch-core` (library) and `esesaetsch` (binary, also the `[[bin]]` name). Always use the ASCII names with `cargo -p` / `cargo test -p`. Imports are `use esesaetsch_core::...`.

## Common commands

These are exactly what CI runs (see `docs/development.md`). Rust **nightly** is pinned via `rust-toolchain.toml` and auto-installed by rustup on first `cargo` call.

```sh
cargo fmt --all -- --check                       # format check
cargo +nightly clippy --workspace --all-targets -- \
    -D clippy::all -D warnings -D clippy::pedantic -D clippy::nursery
cargo test --workspace                           # all tests
cargo test -p esesaetsch-core --test server      # one integration test file
cargo test -p esesaetsch-core auth::             # filter by test name
cargo build --release --workspace                # release sanity
cargo machete                                    # unused-dep check (needs cargo-machete)
cargo llvm-cov --workspace --fail-under-lines 100 -p esesaetsch-core   # coverage gate
```

**libclang is a build-time requirement on Unix** — `pam-sys` runs `bindgen`. If a build fails with `libclang` not found: Debian/Ubuntu `apt-get install -y libpam0g-dev libclang-dev clang`; macOS `brew install llvm` then export `LIBCLANG_PATH`/`DYLD_FALLBACK_LIBRARY_PATH` (see `docs/development.md`). Windows needs nothing (PAM is `cfg(unix)`).

Run locally:

```sh
cargo run -- gen-key --host-key ./host_key
cp examples/minimal.toml ./config.toml   # add your pubkey under [auth.authorized_keys]
cargo run -- serve --config ./config.toml --port 2222
```

## Architecture

Two-crate workspace with a hard split:

- **`crates/esesätsch-core`** (lib, `esesaetsch-core`) — OS-agnostic. Protocol, auth logic, session, config, crypto policy. Does **not** spawn shells or touch the OS auth system. **100% line coverage is gated in CI.**
- **`crates/esesätsch`** (binary, `esesaetsch`) — intentionally thin. CLI parsing + the OS-specific implementations. Excluded from the coverage gate because its native paths only run on real hosts.

### Dependency injection via traits — the central pattern

The core defines behavior as traits and the binary injects real implementations. To understand the runtime wiring, read `main.rs::cmd_serve` (constructs the impls) alongside `core/src/server.rs::EsesätschServer::new` (receives them).

| Trait (in `core`) | Core-provided impls | Real impl (in binary) |
|---|---|---|
| `auth::PubkeyAuthenticator` | `AllowlistPubkeyAuthenticator` (central TOML allowlist) | — |
| `auth::PasswordAuthenticator` | `DenyAllPasswordAuthenticator` (stub) | `real_auth.rs`: PAM (Unix) / `LogonUserW` (Windows) |
| `cert::CertAuthenticator` | cert validation lives in `cert.rs` | — (**not yet wired through russh — `None` is passed in `cmd_serve`**) |
| `pty::PtySpawner` / `PtyChild` | `MockPtySpawner` (tests) | `real_pty.rs`: `portable-pty` (Unix PTY / Windows ConPTY) |

This is what makes the core testable to 100%: integration tests inject mocks and exercise real `russh` client↔server wire flows without touching PAM or spawning shells.

### Key modules in `core/src`

- `server.rs` — `EsesätschServer` (impl `russh::server::Server`) builds the `russh::Config` and holds shared `ServerState`; `ConnectionHandler` (impl `russh::server::Handler`) is per-connection and tracks auth state, cert grants, and channels.
- `crypto.rs` — **single source of truth for the crypto allowlist.** KEX/cipher/MAC/host-key/compression consts in preference order, plus `preferences()` which hands them to russh. No env var, no TOML override — changing policy means editing this file. Includes `mlkem768x25519-sha256` PQ hybrid KEX first.
- `config.rs` — `TomlConfig` (file shape) + `Cli` merge into `Config` via `Config::from_sources(...)`, then `.validate()`. CLI flags override file values.
- `auth.rs`, `cert.rs` — auth methods. Security-critical: uniform reject shape, constant-time compares (`subtle`), sentinel-work on unknown-user path to prevent account enumeration. Preserve these invariants when editing.
- `session.rs`, `pty.rs` — interactive session control (`ControlMsg`) and PTY abstraction.
- `logging.rs` — `tracing` setup with a **stderr-wrapping redaction layer** that strips `password=…` and raw key bytes even at trace level. Don't log secrets directly; rely on / extend this layer.

## Lint policy (workspace `Cargo.toml`)

`clippy::all + pedantic + nursery` all **denied**, plus `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented` denied, and `unsafe_code = "deny"`. Tests are exempt from unwrap/expect/panic via `clippy.toml`. `unsafe` may be opted into per-module with `#![allow(unsafe_code)]` + a justifying comment (used only for OS FFI like `LogonUserW`). New code must pass the strict clippy line above with zero warnings.

## Commits, branches, releases

- **Conventional Commits enforced in CI**: `feat`/`fix`/`docs`/`style`/`refactor`/`perf`/`test`/`build`/`ci`/`chore`/`revert`, `!` for breaking.
- **Branch names** must match `<type>/<lowercase-kebab>` (e.g. `feat/cert-auth-wiring`). Exempt: `main`, `develop`, `release-please--*`, `dependabot/*`, `renovate/*`.
- **Releases are fully automated by release-please.** Never hand-edit a crate `version` or `CHANGELOG.md` — release-please bumps both Cargo.toml versions in lock-step (they are intentionally not workspace-inherited) and writes the changelog on merge of its release PR.