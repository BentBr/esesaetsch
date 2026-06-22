# Packaging

Native installation packages for esesätsch. Built and attached to every
GitHub Release by `.github/workflows/release-packages.yml`.

## Artifacts

| Platform | Arch | Artifact |
|---|---|---|
| Debian/Ubuntu | amd64, arm64 | `esesaetsch_<ver>_<arch>.deb` |
| Fedora/RHEL/SUSE | x86_64, aarch64 | `esesaetsch-<ver>.<arch>.rpm` |
| Arch | x86_64, aarch64 | `esesaetsch-<ver>-<arch>.pkg.tar.zst` |
| Alpine | x86_64, aarch64 | `esesaetsch_<ver>_<arch>.apk` |
| Static musl | x86_64, aarch64 | `esesätsch-<ver>-<target>-musl.tar.gz` |
| macOS (universal) | arm64+x86_64 | `esesätsch-<ver>-universal-apple-darwin.pkg` |
| Windows | x86_64, aarch64 | `esesaetsch-<ver>-<x64\|arm64>.msi` |

Each release also ships `SHA256SUMS`.

## What a package installs (Linux)

- `/usr/bin/esesaetsch`
- `/usr/lib/systemd/system/esesaetsch.service`
- `/etc/esesaetsch/config.toml` (conffile — your edits survive upgrades)
- man page + bash/zsh/fish completions
- `LICENSE`, `NOTICE`, `README.md` under `/usr/share/doc/esesaetsch/`

The postinstall hook generates `/etc/esesaetsch/host_key` if absent. It does
**not** enable or start the service — add your keys to the config, then:

```sh
sudo systemctl enable --now esesaetsch.service
```

Each package declares the libpam runtime dependency (`libpam0g`/`pam`/`linux-pam`).

## Signing

Phase 1 artifacts are **unsigned**; verify integrity with `SHA256SUMS`.
macOS Gatekeeper and Windows SmartScreen will warn on unsigned installers —
this is expected until signing lands (Phase 2: GPG-signed repos, Apple
notarization, Windows Authenticode).

## Building a package locally

```sh
# Build the binary and stage the assets nfpm expects:
cargo build -p esesaetsch
mkdir -p dist/completions
cp target/debug/esesaetsch dist/esesaetsch
target/debug/esesaetsch man | gzip -9 > dist/esesaetsch.1.gz
target/debug/esesaetsch completions bash > dist/completions/esesaetsch.bash
target/debug/esesaetsch completions zsh  > dist/completions/_esesaetsch
target/debug/esesaetsch completions fish > dist/completions/esesaetsch.fish

# Build any format (needs nfpm: `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.0`):
VERSION=0.0.0-dev PKG_ARCH=amd64 nfpm package -f packaging/nfpm.yaml -p deb -t dist/
dpkg-deb -c dist/esesaetsch_0.0.0-dev_amd64.deb   # inspect
```

## Known caveat: PAM on musl

The Alpine `.apk` and static musl tarballs link libpam against musl. Pubkey
and certificate auth are unaffected; the password (PAM) path is less
battle-tested under musl. Smoke tests confirm install + run; verify password
auth manually before relying on it in an Alpine/musl deployment.
