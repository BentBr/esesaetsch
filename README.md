# esesätsch

A strict, cross-platform SSH server written in Rust.

## Status

Pre-release. See `docs/index.md` for documentation.

## Quick start

Documentation hub: [`docs/index.md`](docs/index.md).

Once auth + session land (plan 2):

```sh
cargo run --release -- gen-key --host-key ./host_key
cargo run --release -- serve --config ./config.toml --port 2222
```

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Copyright 2026 Bent Brüggemann.
