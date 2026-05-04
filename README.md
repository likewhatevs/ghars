# ghars

Declaratively manage self-hosted GitHub Actions runners on systemd-based Linux hosts.

[![ci](https://github.com/likewhatevs/ghars/actions/workflows/ci.yml/badge.svg)](https://github.com/likewhatevs/ghars/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/likewhatevs/ghars/branch/main/graph/badge.svg)](https://codecov.io/gh/likewhatevs/ghars)
[![docs](https://img.shields.io/badge/docs-mdbook-blue.svg)](https://likewhatevs.github.io/ghars/)
[![license](https://img.shields.io/badge/license-GPL--2.0--only-blue.svg)](LICENSE)

## What it does

Operators describe the desired runner topology in a single TOML file. `ghars plan`
shows a terraform-style diff against current on-host state; `ghars apply` converges
the host. Adding a runner is appending a `[[runner]]` block. Removing one is deleting
the block. Rolling a version is editing `runner_version`. Every change passes through
the same diff.

## Features

- Config-driven lifecycle: plan → approve → apply with rollback on failure. See [Operations](https://likewhatevs.github.io/ghars/operations.html).
- Count-block expansion (`count = N`) for identical runner fleets. See [Configuration](https://likewhatevs.github.io/ghars/configuration.html).
- DynamicUser isolation with trust-zone UID scoping and per-runner sandboxing profile. See [Security](https://likewhatevs.github.io/ghars/security.html).
- Network namespace isolation with nftables egress rules and DNS forwarding. See [Security](https://likewhatevs.github.io/ghars/security.html).
- Shared ccache/sccache pools scoped by trust zone. See [Configuration](https://likewhatevs.github.io/ghars/configuration.html).
- Integrity-checking `runsvc-wrapper` trampoline (`fexecve` of sha256-verified `runsvc.sh`). See [Security](https://likewhatevs.github.io/ghars/security.html).
- `O_NOFOLLOW` validation, crash-safe writes, zeroize-on-drop for credentials. See [Internals](https://likewhatevs.github.io/ghars/internals.html).
- `ghars status --score` reports per-unit systemd security exposure scores. See [Operations](https://likewhatevs.github.io/ghars/operations.html).

## Documentation

The [ghars book](https://likewhatevs.github.io/ghars/) is the operator manual:

- [Introduction](https://likewhatevs.github.io/ghars/introduction.html)
- [Getting started](https://likewhatevs.github.io/ghars/getting-started.html)
- [Configuration](https://likewhatevs.github.io/ghars/configuration.html)
- [Operations](https://likewhatevs.github.io/ghars/operations.html)
- [Security](https://likewhatevs.github.io/ghars/security.html)
- [Filesystem layout](https://likewhatevs.github.io/ghars/filesystem-layout.html)
- [Architecture](https://likewhatevs.github.io/ghars/architecture.html)
- [Internals](https://likewhatevs.github.io/ghars/internals.html)

## Status

ghars is pre-1.0. The config schema, plan/apply engine, and CLI surface are
subject to change before 1.0.

## Requirements

- Linux with cgroup v2 and systemd 254+.
- Rust 1.91 or newer to build from source.

## Install

```sh
git clone https://github.com/likewhatevs/ghars
cd ghars
cargo build --release
sudo install -m 0755 target/release/ghars /usr/local/bin/ghars
sudo install -Dm755 target/release/runsvc-wrapper /usr/lib/ghars/runsvc-wrapper
```

For the full setup walkthrough (config skeleton, credentials, first runner), see
[Getting started](https://likewhatevs.github.io/ghars/getting-started.html).

## Contributing

Install just (`cargo install just --locked`), run `just setup` once, then
`just lint` / `just test`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GPL-2.0-only. See [LICENSE](LICENSE).
