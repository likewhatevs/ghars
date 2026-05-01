# ghars

[![ci](https://github.com/likewhatevs/ghars/actions/workflows/ci.yml/badge.svg)](https://github.com/likewhatevs/ghars/actions/workflows/ci.yml)

Declaratively manage self-hosted GitHub Actions runners on systemd-based
Linux hosts. Operators describe the desired runner topology in a single
TOML file; `ghars plan` shows the diff against current state and
`ghars apply` converges the host. Pre-1.0. License: GPL-2.0-only.

## How it works

ghars follows a config → plan → apply lifecycle:

1. **Config.** A TOML file (`/etc/ghars/ghars.toml` by default) declares
   runners, auth credentials, cache pools, network namespaces, and
   per-host defaults.
2. **Plan.** `ghars plan` parses the config, discovers actual on-host
   state (systemd units, drop-ins, registered runners, cache pools) and
   prints a terraform-style `+`/`~`/`-` diff. No system mutation occurs.
3. **Apply.** `ghars apply` re-runs the plan, prompts for confirmation
   (skippable with `--auto-approve`), and executes the actions in order:
   write systemd unit files and drop-ins, install runner tarballs,
   register runners with GitHub, start units. Each action records undo
   steps; with `--rollback-on-failure` a failure rewinds that action's
   side effects.

Adding a runner is appending a `[[runner]]` block. Removing one is
deleting the block. Rolling a runner version is editing
`runner_version`. Every change passes through the same diff.

## Installation

Build and install from source (the crate is not yet published to
crates.io):

```sh
git clone https://github.com/likewhatevs/ghars
cd ghars
cargo install --path .
sudo install -Dm755 ~/.cargo/bin/runsvc-wrapper \
    /usr/lib/ghars/runsvc-wrapper
```

Two binaries are produced. `ghars` (the operator CLI) lives on
`PATH` once `cargo install` completes. `runsvc-wrapper` (the
integrity-checking trampoline invoked from generated systemd
units) MUST be copied to `/usr/lib/ghars/runsvc-wrapper`,
root-owned, mode `0755` — the unit template's `ExecStart=` points
at that exact path, and unit start fails if the binary is
missing.

Build requires Rust 1.91+ and edition 2024. Runtime requires systemd
and a Linux kernel with cgroup v2.

## Quick start

Minimal `ghars.toml`:

```toml
[defaults]
runner_version = "2.334.0"
auth = "pat"

[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "build-1"
url = "https://github.com/example/repo"
labels = ["self-hosted", "linux"]
```

Then:

```sh
sudo ghars init --output /etc/ghars/ghars.toml   # scaffold (mode 0640)
sudoedit /etc/ghars/ghars.toml                   # paste the snippet above
export GHARS_PAT=ghp_...
sudo -E ghars validate                           # parse + structural checks
sudo -E ghars plan                               # show diff
sudo -E ghars apply                              # converge (prompts y/N)
sudo -E ghars status                             # SYSTEM HEALTH + RUNNERS table
```

Note the `-E`. Most `sudo` configurations include `env_reset` in
`/etc/sudoers`, which scrubs the caller's environment — `GHARS_PAT`
would not survive into the elevated `ghars` process. `sudo -E`
preserves the environment. For a hands-off workflow that does not
require `-E`, use `kind = "token_file"` or
`kind = "github_app"` and put the credential at a root-readable
path instead of an env var.

## CLI reference

| Command | Purpose |
|---|---|
| `ghars validate [--deep]` | Parse and structurally validate the config. `--deep` round-trips auth tokens against GitHub. |
| `ghars plan [--only N,...] [--json] [--diff] [--detailed-exitcode] [--detailed-exitcode-recreate]` | Compute and print the action diff. |
| `ghars apply [--only N,...] [--auto-approve] [--fail-fast] [--rollback-on-failure] [--dry-run] [--diff] [--detailed-exitcode] [--detailed-exitcode-recreate]` | Execute the plan against the host. |
| `ghars status [--json] [--metrics] [--health-only \| --runners-only] [NAMES...]` | Show preflight checks and managed-unit state. |
| `ghars init [--output PATH]` | Scaffold a starter `ghars.toml`. |
| `ghars add --repo OWNER/REPO [--name N] [--labels CSV] [--auth NAME] [--no-apply]` | Append a `[[runner]]` block, then run apply unless `--no-apply`. |
| `ghars logs [NAMES] [--follow] [-n N] [--since SPEC]` | Tail journal entries for runner units. |
| `ghars metrics [NAMES] [--json] [--no-total]` | Per-runner memory / CPU / IO / tasks via systemd D-Bus. |
| `ghars completions <shell>` | Emit shell completions. |
| `ghars manpages OUTPUT_DIR` | Generate man pages. |

Global flags: `--config <PATH>` (env: `GHARS_CONFIG`), `--no-color`,
`--quiet`, `-v` / `-vv` / `-vvv`.

Exit codes: `0` success; `1` generic error; `2` `--detailed-exitcode`
plan diff non-empty; `3` preflight failure; `4` partial apply failure;
`5` auth failure; `6` config parse or validation failure; `7` interactive
prompt required but unavailable; `8` `--detailed-exitcode-recreate` plan
contains a recreate-class action.

`--diff` on `plan` and `apply` renders full drop-in body content,
including `Environment=HTTP_PROXY=...` lines that may carry
credentials in the userinfo component (`https://USER:PASS@host`).
Treat `--diff` output as a credential-bearing artifact and do not
upload it to shared logs or paste channels. See
[Operations](docs/src/operations.md#diff-and-credential-leakage)
for full discussion.

## Configuration reference

The config schema is defined in `src/config.rs`. Every struct uses
`#[serde(deny_unknown_fields)]` so typos fail at load time.

Top-level tables:

- `[defaults]` — fields inherited by every `[[runner]]` (runner version,
  auth ref, memory caps, labels, network ref, arch, hardening overrides,
  trust zone).
- `[auth.NAME]` — one block per credential. `kind = "pat"` (with
  `token_env` XOR `token_file`) or `kind = "github_app"` (with `app_id`,
  `installation_id`, `private_key_path`).
- `[cache_pools.NAME]` — shared ccache and/or sccache pools, scoped by
  `trust_zone`.
- `[network.NAME]` — network namespace declarations with structured
  egress rules used to generate nftables filters.
- `[proxy]` — singleton outbound proxy config (overridable per runner).
- `[hooks]` — singleton pre/post-job hook scripts.
- `[[runner]]` — one entry per runner, or `count = N` to expand to
  `name-1` .. `name-N`.

Identifier rules: every identifier key (auth names, cache pool names,
network names, runner names) must match `^[a-z]([a-z0-9-]*[a-z0-9])?$`
and be at most 64 chars.

A more complete schema reference (with every field and validation rule)
is generated into the project mdbook under `docs/`.

## Security model

Each runner is isolated through several independent layers:

- **Transient identity via systemd `DynamicUser=yes`.** Each runner unit
  runs under a transient UID/GID allocated on unit start and recycled on
  unit stop. Nothing is written to `/etc/passwd` or `/etc/group`. The
  `User=` is set to `ghars-tz-<TRUST_ZONE>`, so runners that share a
  `trust_zone` share a UID and can reach a shared cache home, while
  cross-trust-zone reach is denied at the UID DAC layer (different UIDs
  produce `EACCES` on shared paths and on the sccache UDS).
- **Sandboxed unit profile.** The generated `[Service]` section applies
  `TemporaryFileSystem=/:ro`, `BindReadOnlyPaths` for system paths,
  `PrivateDevices`, `NoNewPrivileges=yes`, an empty
  `CapabilityBoundingSet`, and a `SystemCallFilter` allowlist. Per-field
  hardening overrides in `[defaults.hardening]` and
  `[[runner]].hardening` let operators tighten further.
- **Network namespace isolation.** When a runner references a
  `[network.NAME]` block with `mode = "netns"`, the runner unit uses
  `NetworkNamespacePath=`, which fails closed: the unit refuses to
  start when the bind-mount path is missing or unjoinable. Egress is
  filtered by nftables rules generated from `allowed_egress`,
  `ip_allow`, and `ip_deny`, with `IPAddressAllow=` / `IPAddressDeny=`
  defense-in-depth at the cgroup-BPF layer.
- **Integrity-checking trampoline.** The `runsvc-wrapper` binary
  (root-owned, mode 0755 at `/usr/lib/ghars/runsvc-wrapper`) is the
  unit's `ExecStart`. It opens `runsvc.sh` with `O_NOFOLLOW`,
  recomputes its sha256, compares against the `X-Ghars-Runsvc-Sha256`
  annotation in the per-runner drop-in (read with `O_NOFOLLOW`), and
  `fexecve()`s the verified file descriptor on match. This closes the
  open-then-rename TOCTOU window. The wrapper does not setuid or setgid;
  identity is established by `DynamicUser=`.
- **`O_NOFOLLOW` validation throughout.** Operator-supplied paths
  (private keys, prefixes, tarballs, hook scripts) are opened with
  `O_NOFOLLOW | O_NONBLOCK` so the kernel rejects symlinks at `open(2)`
  time and refuses to hang on a fifo. This closes the lstat-then-open
  TOCTOU window.
- **Crash-safe writes.** Every config artifact is written via
  `tempfile + rename + parent fsync` so a crash mid-write leaves the
  filesystem in a consistent state.
- **Zeroize on drop.** Runner registration tokens are wrapped in a
  `ZeroizeOnDrop` type; the backing memory is scrubbed on unwind so a
  panic between mint and consume does not leave plaintext on stack or
  heap.

## Documentation

Full design (config schema, plan/apply engine, auth subsystem, systemd
unit and drop-in layout, netns model, hardening envelope) lives in the
project mdbook under `docs/`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Build with `cargo build`. Test
with `cargo nextest run`. Lint with `cargo clippy` and `cargo fmt`.

## License

GPL-2.0-only. See [LICENSE](LICENSE).
