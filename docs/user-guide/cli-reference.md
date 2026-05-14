# CLI reference

Every subcommand and flag the `esesätsch` binary accepts, with at least one runnable example.

## Subcommands

| | |
|---|---|
| [`serve`](#serve-default) | Run the SSH server (default subcommand). |
| [`gen-key`](#gen-key) | Generate a fresh Ed25519 host key and exit. |
| [`install-service`](#install-service) | Register a platform-native service unit so the host OS supervises the binary. |
| [`uninstall-service`](#uninstall-service) | Remove the service unit installed above. |

## Global flags

These work on every subcommand.

| Flag | Long | Type | Description |
|---|---|---|---|
| `-c` | `--config <PATH>` | path | Path to the TOML config. Optional; defaults apply when omitted. |
| `-p` | `--port <PORT>` | u16 | Listen port. Overrides `[server].port` from the config. |
| | `--bind <ADDR>` | string | Bind address (host portion only). Overrides `[server].bind`. |
| | `--host-key <PATH>` | path | Path to the host key file. Overrides `[server].host_key`. |
| `-d` | `--debug` | flag | Verbose tracing (DEBUG level) for esesätsch crates. |
| `-t` | `--trace` | flag | Wire-level packet trace (TRACE level). Implies `--debug`. Passwords and key blobs are redacted before logging. |
| `-h` | `--help` | flag | Print help (works on every subcommand). |
| `-V` | `--version` | flag | Print version and exit. |

---

## `serve` (default)

Runs the SSH server. The most common invocation:

```sh
esesätsch serve --config /etc/esesätsch/config.toml
```

You can omit the subcommand entirely; it defaults to `serve`:

```sh
esesätsch --config /etc/esesätsch/config.toml
```

Override a specific config value from the CLI:

```sh
# Use the config, but listen on a different port for this run
esesätsch serve --config /etc/esesätsch/config.toml --port 22

# Bind only to loopback for local testing
esesätsch serve --config ./config.toml --bind 127.0.0.1

# Use a one-off host key path
esesätsch serve --config ./config.toml --host-key /tmp/test_host_key
```

Verbose logging while debugging an auth failure:

```sh
esesätsch serve --config ./config.toml --debug
```

Maximum verbosity (also dumps redacted SSH packets):

```sh
esesätsch serve --config ./config.toml --trace
```

Run without a config at all (uses defaults — port 2222, pubkey-only, empty allowlist — useful only as a smoke test):

```sh
esesätsch serve
```

---

## `gen-key`

Generate a fresh Ed25519 host key and write it to the given path. The file is created with `0600` permissions on Unix. Refuses to overwrite an existing file.

```sh
esesätsch gen-key --host-key ./host_key
esesätsch gen-key --host-key /etc/esesätsch/host_key
```

Output:

```
wrote new host key to /etc/esesätsch/host_key
```

You normally don't need to run this — `serve` auto-generates if the file is missing. Use `gen-key` when you want to provision the key under a different user/owner before starting the server.

---

## `install-service`

Register a platform-native service unit so the host OS supervises the binary. Requires root (Unix) or Administrator (Windows).

```sh
sudo esesätsch install-service --config /etc/esesätsch/config.toml
```

Without `--config`, the service is registered to run `serve` with built-in defaults — usually not what you want.

**What gets written:**

- **Linux**: `/etc/systemd/system/esesaetsch.service`. After install, activate with:
  ```sh
  sudo systemctl daemon-reload
  sudo systemctl enable --now esesaetsch.service
  ```
- **macOS**: `/Library/LaunchDaemons/com.esesaetsch.server.plist`. After install:
  ```sh
  sudo launchctl load -w /Library/LaunchDaemons/com.esesaetsch.server.plist
  ```
- **Windows**: prints the `sc.exe create` invocation for you to run as Administrator. Native registration via the `windows-service` crate is a planned follow-up.

---

## `uninstall-service`

Inverse of `install-service`. Removes the unit file (Linux/macOS) or prints the `sc.exe` cleanup command (Windows). Requires root / Administrator.

```sh
sudo esesätsch uninstall-service
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Any error. The cause is printed on stderr. |

The binary is intentionally simple about this — operators usually want stdout/stderr for `journalctl`/`launchd`/`Event Log` rather than parsing exit codes.
