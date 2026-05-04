# Introduction

ghars manages self-hosted GitHub Actions runners on systemd Linux hosts.
Write a TOML file, run `ghars plan` to see the diff, run `ghars apply`
to converge. That's it.

## The short version

- One TOML file describes all your runners.
- `ghars plan` diffs desired vs actual (terraform-style `+`/`~`/`-`).
- `ghars apply` writes systemd units, registers runners with GitHub,
  starts services.
- Each runner gets its own systemd unit with a hardened sandbox profile.
- Optional network namespace isolation with nftables egress rules.
- Optional shared ccache/sccache pools.

## What ghars is not

- Not a workflow runtime — it provisions runners, GitHub runs workflows.
- Not a multi-host orchestrator — it manages one host. Use your existing
  config management for fleet rollout.

## Reading order

- New operators: [Getting Started](./getting-started.md) →
  [Configuration](./configuration.md) → [Operations](./operations.md).
- Security review: [Security](./security.md).
- Contributors: [Architecture](./architecture.md) →
  [Internals](./internals.md).
