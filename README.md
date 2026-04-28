# ghars

[![ci](https://github.com/likewhatevs/ghars/actions/workflows/ci.yml/badge.svg)](https://github.com/likewhatevs/ghars/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/likewhatevs/ghars/branch/main/graph/badge.svg)](https://codecov.io/gh/likewhatevs/ghars)
[![mutation score](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/likewhatevs/GIST_ID_PLACEHOLDER/raw/ghars-mutation-score.json)](https://github.com/likewhatevs/ghars/actions/workflows/mutants-nightly.yml)

Declaratively manage self-hosted GitHub Actions runners on systemd-based
Linux hosts. ghars is to CI infrastructure what terraform is to cloud
infrastructure: write a TOML file, run `ghars plan`, run `ghars apply`.
Each runner gets a dedicated system user, its own systemd unit with a
strict hardening profile, and (optionally) its own network namespace
with operator-defined egress rules.

Pre-1.0. License: GPL-2.0-only.

## 30-second quickstart

```sh
cargo install ghars
sudo ghars init                       # write /etc/ghars/ghars.toml (per-runner system users are created at apply time)
sudoedit /etc/ghars/ghars.toml        # paste an [auth.pat] block + a GHARS_PAT env reference
sudo ghars add --repo OWNER/REPO      # appends [[runner]] + runs apply
sudo ghars status                     # SYSTEM HEALTH + RUNNERS table
```

`ghars add` prompts only for what's not on the command line; with `--auth pat`
and `GHARS_PAT` set, it is non-interactive end to end.

## Configuration

Default path: `/etc/ghars/ghars.toml` (override with `--config` or `GHARS_CONFIG`).

```toml
[defaults]
prefix = "/var/lib/ghars"
runner_version = "2.334.0"
auth = "pat"
arch = "x86_64"
memory_max = "110G"
labels = ["self-hosted", "linux"]
network = "isolated"

# Stricter than the default profile; field-by-field overrides.
[defaults.hardening]
protect_control_groups = true
restrict_realtime = true
restrict_address_families = ["AF_UNIX", "AF_INET"]
extra_syscalls = ["clone3", "rseq", "close_range", "memfd_create", "membarrier"]

# token_env XOR token_file (validator enforces). PAT can be classic with
# `repo` / `admin:org` scope or fine-grained with the equivalent
# Administration: write permission.
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[auth.gh-app-prod]
kind = "github_app"
app_id = 12345
installation_id = 67890
private_key_path = "/etc/ghars/keys/app.pem"

# Singleton — applies to all runners unless overridden in [[runner]].proxy.
[proxy]
http = "http://proxy.example:3128"
https = "http://proxy.example:3128"
no_proxy = ["proxy.example"]
ca_certs = [
  { env = "NODE_EXTRA_CA_CERTS", path = "/etc/pki/ca-trust/source/anchors/proxy-ca.pem" },
  { env = "REQUESTS_CA_BUNDLE", path = "/etc/pki/tls/certs/ca-bundle.crt" },
  { env = "SSL_CERT_FILE", path = "/etc/pki/tls/certs/ca-bundle.crt" },
]

# Singleton — pre/post-job hooks (ACTIONS_RUNNER_HOOK_JOB_STARTED/COMPLETED).
[hooks]
pre_job = "/opt/gha-hooks/pre-job.sh"
post_job = "/opt/gha-hooks/post-job.sh"

# Unified per-pool cache service (one ghars-cache@POOL.service). ccache
# uses cooperative flock for shared writers; sccache satisfies its
# sole-maintainer contract via single-server ownership.
[cache_pools.build]
kinds = ["ccache", "sccache"]
size = "200G"
mode = "shared"

# Network namespace. Runner sees only its own lo + a single veth peer;
# nft rules on the host veth and inside the namespace control egress.
# The structured fields below drive the rule generator.
[network.isolated]
mode = "netns"
allowed_egress = [
  { addr = "proxy.example", port = 3128, proto = "tcp", comment = "outbound proxy" },
]
ip_allow = ["192.0.2.10/32"]
ip_deny = ["0.0.0.0/0"]
address_families = ["AF_UNIX", "AF_INET"]

# Explicit, hand-named runners.
[[runner]]
name = "build-1"
url = "https://github.com/example/build"
labels = ["x64"]
caches = ["build"]

# Count syntax: expands to ci-1..ci-10. Per-runner overrides come from
# declaring an explicit [[runner]] with the matching name (auto-skip).
[[runner]]
name = "ci"
count = 10
url = "https://github.com/example/repo"
labels = ["ci"]
caches = ["build"]

[[runner]]
name = "ci-7"          # auto-skipped from the count block above
url = "https://github.com/example/repo"
labels = ["ci", "big-mem"]
memory_max = "16G"
caches = ["build"]
```

Schema rules (selected — see the docs site for the full set):
- All identifier keys (`auth.*`, `cache_pools.*`, `network.*`, `[[runner]].name`) match `^[a-z]([a-z0-9-]*[a-z0-9])?$` and are at most 64 chars.
- `count` ranges 1..=1024; the explicit-name auto-skip lets count-blocks coexist with per-runner overrides.
- Every `[[runner]]` resolves an `auth` ref (its own, or `defaults.auth`) — validate-time error otherwise.
- `network.NAME.mode = "netns"` requires non-empty `allowed_egress` or `ip_allow` (a netns runner with no egress is almost certainly a misconfiguration).
- `deny_unknown_fields` everywhere — typos error out.

## CLI reference

| Command | Summary |
|---|---|
| `ghars validate [--deep]` | Parse + structural validation. `--deep` round-trips auth tokens against GitHub. |
| `ghars plan [--only X,Y] [--json] [--refresh-releases] [--output-dir DIR]` | Discover state, compute diff, print terraform-style `+`/`~`/`-` lines. No system changes. |
| `ghars apply [--auto-approve] [--fail-fast] [--rollback-on-failure] [--dry-run] [--detailed-exitcode]` | Run plan, prompt, execute. `--detailed-exitcode` makes 2 mean "changes detected" (terraform convention). |
| `ghars status [--json] [--metrics] [--health-only \| --runners-only]` | SYSTEM HEALTH (preflight checks) + RUNNERS (managed-unit table with drift). |
| `ghars init [--output PATH]` | Scaffold `ghars.toml`. Per-runner system users (`ghars-RUNNERNAME`) are provisioned at apply time, not by `init`. |
| `ghars add --repo OWNER/REPO [--name N] [--labels CSV] [--auth NAME] [--no-apply]` | Append `[[runner]]` block, then run `apply` unless `--no-apply`. |
| `ghars logs [NAMES] [--follow] [-n N] [--since SPEC]` | Wraps `journalctl -u ghars-runner@NAME.service`. Empty NAMES = all managed runners. |
| `ghars metrics [NAMES] [--json] [--no-total]` | Per-runner + total memory / CPU / IO / tasks via systemd D-Bus. |
| `ghars completions <shell>` | Emit completions to stdout. |
| `ghars manpages OUTPUT_DIR` | Generate man pages via `clap_mangen`. |

Exit codes: 0 success, 1 generic error, 2 (with `--detailed-exitcode`) plan diff non-empty, 3 preflight/validation failure, 4 partial apply failure, 5 auth failure.

Three hidden subcommands (`_netns-setup`, `_netns-teardown`, `_netns-veth`) are invoked by `ghars-net@INSTANCE.service` units and are not part of the operator surface.

## Why ghars

**vs running `config.sh` directly.** GitHub's `config.sh` registers one runner and walks away — it does not write a systemd unit, does not own the upgrade path, does not reconcile config drift, does not separate runners into different system users or network namespaces, and does not generate nft rules from policy. ghars writes a unit per runner, computes a diff every time you change `ghars.toml`, integrity-checks `runsvc.sh` against an annotation before exec, drops privileges to a per-runner system user via a compiled trampoline, and (in netns mode) hands the runner its own network namespace with `NetworkNamespacePath=` (which fails closed when the namespace is missing — unlike `PrivateNetwork=yes`, which silently falls back to the host netns when `CONFIG_NET_NS` or `CAP_NET_ADMIN` is unavailable).

**vs an imperative install script.** ghars is plan/apply, not install/uninstall. The TOML file is the source of truth; `ghars apply` converges the host. Adding a runner is appending a `[[runner]]` block (or a `count = N` field). Removing a runner is deleting that block. Rolling a version is editing `runner_version`. Every change goes through the same diff display before any system mutation.

**Architectural guarantees.** `fn main()` is sync — ghars uses `OnceLock<Runtime>` + `block_on(...)` for the small async surface that octocrab requires, and zbus (D-Bus) uses its own executor in blocking mode. There is no `#[tokio::main]`, no async sandwich, and no surprise tokio dependency for code that doesn't need one.

## Documentation

Full design (config schema, plan/apply engine, auth subsystem, systemd
unit + drop-in layout, netns model, security envelope) lives in the
[mdbook docs site](https://likewhatevs.github.io/ghars/) — link will be
populated once the gh-pages workflow lands.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Build with `cargo build`. Test
with `cargo nextest run` (the repository does not use `cargo test`).
Lint with `cargo clippy` and `cargo fmt`.

## License

GPL-2.0-only. See [LICENSE](LICENSE).
