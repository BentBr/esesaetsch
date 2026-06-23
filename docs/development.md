# Developing esesätsch

A focused, no-bullshit guide to building, testing, and contributing.

## Prerequisites

- **Rust nightly** (pinned via `rust-toolchain.toml`). Installed automatically by `rustup` on first `cargo` invocation in the repo.
- **A C toolchain** plus **libclang** — required by the `pam-sys` build step (PAM is a hard Unix dependency).

### macOS

```sh
brew install llvm
```

Then for every `cargo` invocation in this repo, export the libclang location:

```sh
export LIBCLANG_PATH=/opt/homebrew/opt/llvm/lib
export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/opt/llvm/lib
```

Or run the cargo command inline:

```sh
DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/opt/llvm/lib \
LIBCLANG_PATH=/opt/homebrew/opt/llvm/lib \
cargo run
```

If you forget, you'll see `dyld: Library not loaded: @rpath/libclang.dylib` during the `pam-sys` build script.

### Linux (Debian/Ubuntu)

```sh
sudo apt-get update
sudo apt-get install -y libpam0g-dev libclang-dev clang
```

For cross-builds to `aarch64-unknown-linux-gnu` (used in CI release builds):

```sh
sudo dpkg --add-architecture arm64
sudo apt-get update
sudo apt-get install -y gcc-aarch64-linux-gnu libpam0g-dev:arm64
```

### Windows

No special prerequisites — PAM is gated to `cfg(unix)`, and `LogonUserW` is part of the OS.

## The build-and-check commands

These are the exact commands CI runs. Run them locally before pushing.

```sh
# 1. Format check
cargo fmt --all -- --check

# 2. Strict clippy (nightly, pedantic + nursery)
cargo +nightly clippy --workspace --all-targets -- \
    -D clippy::all \
    -D warnings \
    -D clippy::pedantic \
    -D clippy::nursery

# 3. Tests
cargo test --workspace

# 4. Release-profile build (sanity)
cargo build --release --workspace

# 5. Unused-dependency check (optional but recommended)
cargo install cargo-machete --locked
cargo machete
```

## Running the server

```sh
# Generate a host key once
cargo run -- gen-key --host-key ./host_key

# Edit a config (start from examples/)
cp examples/minimal.toml ./config.toml
# … add your public key under [auth.authorized_keys]

# Serve
cargo run -- serve --config ./config.toml
```

Then connect from a client:

```sh
ssh -p 2222 alice@127.0.0.1
```

If your client warns about non-post-quantum KEX, your client is older than OpenSSH 9.9. The server offers `mlkem768x25519-sha256` first; OpenSSH 9.9+ uses it automatically.

## Project layout

```
Cargo.toml                 # workspace root + shared deps
clippy.toml                # strict lint config + allow-{unwrap,expect,panic}-in-tests
rust-toolchain.toml        # pinned nightly channel
crates/
├── esesätsch-core/        # library: protocol, auth, session, config — OS-agnostic
│   ├── src/{auth,cert,config,crypto,error,hostkey,logging,pty,server,session}.rs
│   └── tests/             # integration tests, including wire-level russh client↔server
└── esesätsch/             # binary: thin CLI wrapper + OS-specific impls
    ├── src/main.rs
    ├── src/real_pty.rs    # portable-pty PtySpawner
    ├── src/real_auth.rs   # PAM (Unix) + LogonUserW (Windows)
    └── src/service.rs     # install-service: systemd / launchd / Windows service
examples/                  # runnable example configs
docs/                      # this guide + user/operator/security/development sub-guides
.github/workflows/
├── ci.yml                 # fmt + clippy + tests + cross-builds + ci-gate
├── release-please.yml     # release PR + CI gating + release publication
└── release-assets.yml     # build + upload binaries when a release is published
```

## Commit and branch conventions

CI enforces **Conventional Commits** on every PR. Format:

```
<type>[optional scope][!]: <description>
```

Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`. Append `!` for breaking changes. Examples:

- `feat(cert): accept openssh certs through russh wire protocol`
- `fix(server): never leak password field in trace logs`
- `chore(deps): bump russh 0.45 to 0.60`

Branch names must match `<type>/<lowercase-kebab-description>`, e.g. `feat/cert-auth-wiring`. Exempt branches: `main`, `develop`, `release-please--*`, `dependabot/*`, `renovate/*`.

## Releases

Releases are fully automated by [release-please](https://github.com/googleapis/release-please).

1. Land conventional-commit PRs on `main`.
2. release-please opens a PR titled `chore(main): release X.Y.Z` bumping both `Cargo.toml` versions and updating `CHANGELOG.md`.
3. CI runs against that PR.
4. Merge the release PR. release-please publishes a tagged GitHub Release.
5. `release-assets.yml` builds and attaches binaries for all 5 targets.

Native packages (deb/rpm/Arch/apk/macOS pkg/Windows msi) are built and
attached by `release-packages.yml` in the same release flow. See
[`packaging/README.md`](../packaging/README.md) to build one locally.

You don't manually edit `Cargo.toml`'s version or write `CHANGELOG.md` entries — release-please does both.

## Test coverage

Run with `cargo-llvm-cov`:

```sh
cargo install cargo-llvm-cov --locked
cargo llvm-cov --workspace --fail-under-lines 100 -p esesaetsch-core
```

CI enforces 100% line coverage on `esesaetsch-core`. The binary crate is excluded because its OS-native paths (`real_auth`, `real_pty`, `service`) only run on real hosts with real PAM / real users / real systemd / real Windows services — out of scope for headless CI.
