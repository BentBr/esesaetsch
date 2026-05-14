# Example configurations

Pick the file that matches what you want, copy it as `config.toml`, edit the
keys/users, and run:

```sh
esesätsch serve --config ./config.toml
```

| File | Use case |
|---|---|
| [`minimal.toml`](minimal.toml) | Single user, pubkey only — smallest working config |
| [`pubkey-only.toml`](pubkey-only.toml) | Multiple users, central pubkey allowlist (no passwords, no certs) |
| [`password.toml`](password.toml) | OS-native password auth via PAM (Linux/macOS) or LogonUserW (Windows) |
| [`cert-auth.toml`](cert-auth.toml) | OpenSSH certificate authentication with a CA |
| [`full.toml`](full.toml) | **Reference** — every field, with explanatory comments |

See [`docs/user-guide/configuration.md`](../docs/user-guide/configuration.md)
for the field-by-field reference.
