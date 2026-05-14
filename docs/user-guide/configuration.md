# Configuration reference

esesätsch is configured by a single TOML file (`--config <PATH>`) plus a small number of CLI flags. Every field is optional — defaults apply when omitted.

**Precedence**: CLI flag > TOML value > built-in default.

Running configs:

- See [`examples/`](../../examples/) for ready-to-edit starting points.
- See [`examples/full.toml`](../../examples/full.toml) for a single file showing every field with inline comments.

---

## `[server]`

### `bind`

The address to listen on. Accepts any IPv4 or IPv6 host string that parses as a `SocketAddr`-compatible value.

| | |
|---|---|
| Type | string |
| Default | `"0.0.0.0"` |
| Examples | `"0.0.0.0"`, `"127.0.0.1"`, `"::"`, `"::1"` |
| CLI override | `--bind <ADDR>` |
| Security | Listening on `0.0.0.0` exposes the server to every interface. Use `127.0.0.1` if you only want local clients. |

### `port`

TCP port. Must be in `1..=65535`.

| | |
|---|---|
| Type | integer |
| Default | `2222` |
| CLI override | `-p / --port <PORT>` |
| Note | Ports < 1024 are privileged on Unix. To listen on `22`, run as root or grant `CAP_NET_BIND_SERVICE` (Linux). |

### `host_key`

Path to the server's host private key in OpenSSH format.

| | |
|---|---|
| Type | path |
| Default | `"./host_key"` |
| CLI override | `--host-key <PATH>` |
| Behavior | If the file exists, it's loaded. If it doesn't, the server auto-generates an Ed25519 key with `0600` permissions on Unix and writes it there. |
| Constraint | Must not contain `..` path components (validation refuses parent-directory traversal). |
| Related | `esesätsch gen-key --host-key <PATH>` writes a fresh key without starting the server. |

---

## `[auth]`

### `password_enabled`

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Behavior | When `true`, the server accepts `userauth-request method=password`. The credentials are verified against the host OS account database — PAM (`/etc/pam.d/sshd` by default) on Linux/macOS, `LogonUserW` with `LOGON32_LOGON_NETWORK` on Windows. |
| Operational | The user **must exist** on the host OS. Linux servers typically need root to read `/etc/shadow` via PAM. |

### `pubkey_enabled`

| | |
|---|---|
| Type | bool |
| Default | `true` |
| Behavior | When `true`, the server accepts `userauth-request method=publickey` and checks the offered key against [`auth.authorized_keys`](#authauthorized_keys). The compare is constant-time; unknown users still run a sentinel compare so timing leaks don't reveal which users are listed. |

### `cert_enabled`

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Behavior | When `true`, the server accepts OpenSSH user certificates. Certs are validated end-to-end: trusted CA → signature → validity window → principal match → not revoked → no unknown critical options. |
| Requires | [`auth.ca.trusted`](#authcatrusted) must be non-empty when this is `true`. |

### `max_auth_attempts`

| | |
|---|---|
| Type | integer |
| Default | `3` |
| Behavior | The server drops a connection after this many failed auth attempts. Enforced by russh's negotiator. |

### `[auth.authorized_keys]`

Per-user public-key allowlist. Only consulted when `pubkey_enabled = true`.

| | |
|---|---|
| Type | table of string → array of string |
| Default | `{}` (empty — no one can authenticate by pubkey) |
| Format | Each value is an array of OpenSSH-format key lines: `"type base64 [comment]"`. |
| Multi-key | A single user can list multiple keys; any one matches. |

```toml
[auth.authorized_keys]
alice = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAEXAMPLE alice@laptop",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAEXAMPLE2 alice@home",
]
bob = [
    "rsa-sha2-512 AAAAB3NzaC1yc2EAAAADAQABEXAMPLE bob@workstation",
]
```

⚠️ If `pubkey_enabled = true` and this table is empty, the server prints a startup warning — no client can authenticate.

### `[auth.ca]`

Certificate authority configuration. Only consulted when `cert_enabled = true`.

#### `auth.ca.trusted`

| | |
|---|---|
| Type | array of string |
| Default | `[]` |
| Format | OpenSSH-format CA public-key lines (the contents of your `ca.pub`). |

Multiple CAs are supported — any matching CA validates the cert.

```toml
[auth.ca]
trusted = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAPRIMARY primary-ca",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAABACKUP  backup-ca",
]
```

#### `auth.ca.revoked_serials`

| | |
|---|---|
| Type | array of integer (u64) |
| Default | `[]` |
| Behavior | Cert serials in this list are refused regardless of validity. The CA assigns a serial via `ssh-keygen -s ca_key -z <N>` when signing. |

---

## `[logging]`

### `level`

Default tracing level. `--debug` and `--trace` on the CLI override this.

| | |
|---|---|
| Type | string |
| Default | `"info"` |
| Allowed | `"off"`, `"error"`, `"warn"`, `"info"`, `"debug"`, `"trace"` |

### `packet_trace`

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Behavior | Enable wire-level packet dumps in the trace output. Passwords and raw key blobs are redacted before write. Same effect as passing `--trace`. |

---

## Validation rules

Enforced by `Config::validate` at server startup. Each rule produces a clear, line-bearing error before the listener binds.

1. `1 ≤ port ≤ 65535` (type-enforced by `u16`; explicit check below).
2. `bind` parses as a `SocketAddr` host.
3. **At least one** of `pubkey_enabled` / `cert_enabled` / `password_enabled` is `true`.
4. Every key in `auth.authorized_keys` parses as a valid SSH public key.
5. If `cert_enabled = true`, `auth.ca.trusted` must be non-empty.
6. Every entry in `auth.ca.trusted` parses as a valid SSH public key.
7. `host_key` path contains no `..` parent-directory traversal.
