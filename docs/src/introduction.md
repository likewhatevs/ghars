# Introduction

`ghars` declaratively manages self-hosted GitHub Actions runners on
systemd-based Linux hosts. The operator writes a TOML file; `ghars
plan` shows a diff; `ghars apply` converges the host.

## Design philosophy

**Declarative, not imperative.** A single TOML file at
`/etc/ghars/ghars.toml` is the source of truth for every managed
runner. Adding a runner is appending a `[[runner]]` block (or setting
`count = N` on an existing one). Removing a runner is deleting that
block. Rolling a version is editing `runner_version`. Every change
goes through the same diff display before any system mutation.

**Plan / apply.** The lifecycle is config → plan → apply, the same
shape `terraform` uses for cloud infrastructure. `ghars plan` reads
the desired config, discovers the actual host state from systemd +
disk, and emits an ordered list of `Action`s with terraform-style
`+` / `~` / `-` lines. `ghars apply` re-runs the plan inside a
serialized critical section and dispatches each action to its
handler.

**One unit per runner.** Each runner gets its own systemd template
instance (`ghars-runner@NAME.service`) layered with per-runner
drop-ins for memory, hardening, cache pool bindings, network mode,
NUMA pinning, proxy environment, and job hooks. The canonical
runner template is shared; per-runner variation lives in the
`*.d/*.conf` overlay.

**DynamicUser identity.** Runners that share a `trust_zone` share a
transient UID/GID that systemd allocates from its reserved range at
unit start and recycles on stop. Nothing is written to `/etc/passwd`
or `/etc/group`. Cross-trust-zone reach is denied at the UID-DAC
layer.

**Runtime integrity.** A small compiled trampoline at
`/usr/lib/ghars/runsvc-wrapper` (the `runsvc-wrapper` `[[bin]]`
target) opens `runsvc.sh` with `O_NOFOLLOW`, recomputes the SHA-256
digest, compares against the `X-Ghars-Runsvc-Sha256` annotation
recorded in the per-runner `00-ghars.conf` drop-in, and `fexecve()`s
the verified file descriptor on match — closing the
open-then-rename TOCTOU window. On mismatch the trampoline refuses
to exec.

**Network namespace by default-fail-closed.** When a runner sets
`network = "name"` and that network's `mode = "netns"`, the runner
unit gets `NetworkNamespacePath=/var/run/netns/ghars-NAME`, which
fails closed when the namespace is missing — unlike
`PrivateNetwork=yes`, which silently falls back to the host netns
when `CONFIG_NET_NS` or `CAP_NET_ADMIN` is unavailable. nftables
rules generated from `[network.NAME].allowed_egress` enforce the
operator's egress policy at both the host veth and inside the
namespace.

**No surprise async runtime.** `fn main()` is sync; `tokio` is
present only in `rt` mode for `octocrab`'s async surface (no
`macros`, no `time`). zbus runs its own executor in blocking mode.
See [Internals](./internals.md#async-runtime-surface) for the full
rationale.

## What ghars is not

- **Not a workflow runtime.** `ghars` provisions and converges the
  systemd unit + drop-ins; the GitHub Actions runner binary
  (`actions/runner`) executes the workflow.
- **Not a `config.sh` wrapper that walks away.** The legacy approach
  of running `actions/runner`'s `config.sh` directly registers one
  runner and returns no host artifact. `ghars` writes a unit per
  runner, computes a diff every time the config changes, integrity-
  checks `runsvc.sh` through a compiled trampoline that fexecve's
  the verified fd, and (in netns mode) hands the runner its own
  namespace with operator-defined nft rules.
- **Not an imperative install script.** Adding, removing, or
  upgrading a runner happens through the TOML file; `ghars apply`
  reconciles. Side-effects flow through a single critical section
  (`apply.lock`); concurrent applies serialize.
- **Not a multi-host orchestrator.** `ghars` manages the runners
  that live on the host it runs on. Operators that need fleet-wide
  rollout drive `ghars` from their existing config-management tool.

## Project status

Pre-1.0. License: GPL-2.0-only.

The canonical workspace layout has one library crate (`ghars`) plus
two `[[bin]]` targets:

- `ghars` — the CLI binary.
- `runsvc-wrapper` — the integrity-checking trampoline installed at
  `/usr/lib/ghars/runsvc-wrapper` (root:root mode 0755). Compiled
  Rust, not a shell script.

`unsafe_code = "forbid"` is set workspace-wide; the `nix` crate
provides safe wrappers for `fexecve(2)`, `renameat2(2)`, and the
other syscalls the apply path needs.

## Reading order

- New operators: [Getting Started](./getting-started.md) →
  [Configuration](./configuration.md) → [Operations](./operations.md).
- Reviewing the security model:
  [Security](./security.md) → [Internals](./internals.md).
- Contributors and reviewers:
  [Architecture](./architecture.md) → [Internals](./internals.md).
