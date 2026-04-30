# Configuration

Default config path: `/etc/ghars/ghars.toml`. Override with the
global `--config PATH` flag or the `GHARS_CONFIG` env var.

The schema is parsed by `serde` from TOML. Every struct uses
`#[serde(deny_unknown_fields)]`, so a typo at the operator's TOML
surface fails at load time rather than silently dropping to default.
Forward-evolving fields are added with `#[serde(default)]`, not by
tolerating unknown keys.

## Top-level shape

```toml
[defaults]                # global defaults, inherited by every [[runner]]
[auth.NAME]               # one auth source per block, keyed by identifier
[cache_pools.NAME]        # ccache and/or sccache pool, keyed by identifier
[network.NAME]            # netns network, keyed by identifier
[proxy]                   # singleton — applies to every runner unless overridden
[hooks]                   # singleton — pre/post-job hook scripts
[[runner]]                # one block per runner (or count = N for prefix expansion)
```

`[network.NAME]` blocks declare explicit netns mode. A runner with
no `network` reference uses the host netns implicitly; there is no
`mode = "open"` block to declare.

## Identifiers

All identifier keys (`auth.NAME`, `cache_pools.NAME`,
`network.NAME`, `[[runner]].name`) match the regex
`^[a-z]([a-z0-9-]*[a-z0-9])?$` and are at most `IDENTIFIER_MAX_LEN
= 64` characters. The constant `IDENTIFIER_REGEX` lives in
`config.rs`.

Tighter caps apply to keys whose value flows into a derived
systemd-strict identifier. `validators.rs` defines:

| key | hard cap | derived from |
|---|---|---|
| `[[runner]].name` (Open mode) | `RUNNER_NAME_MAX_LEN = 25` | `SYSTEMD_GROUP_NAME_MAX (31) - len("ghars-")` |
| `[[runner]].name` (Netns mode) | `NETNS_RUNNER_NAME_MAX_LEN = 7` | `IFNAMSIZ (16) - 1 - len("ghars-") - len("-h")` (veth shape) |
| `[cache_pools.NAME]` | `CACHE_POOL_NAME_MAX_LEN = 19` | `SYSTEMD_GROUP_NAME_MAX (31) - len("ghars-cache-")` |

For runner names with `count > 1`, the suffix `-N` is appended
during expansion, so the BASE name has to leave room for the
largest suffix.

## `[defaults]`

```toml
[defaults]
runner_version = "2.334.0"
runner_sha256  = "abcd...64hex..."
auth           = "pat"
memory_max     = "110G"
labels         = ["self-hosted", "linux"]
network        = "isolated"
arch           = "x86_64"            # x86_64 | aarch64; None ≡ host arch
keep_versions  = 2                   # bin.X.Y.Z retention; default 2
```

Fields in `Defaults`:

- `runner_version` (`Option<String>`) — default GitHub Actions
  runner version (e.g. `"2.334.0"`).
- `runner_sha256` (`Option<String>`) — default tarball SHA-256 (64
  hex). Only meaningful with `runner_version`.
- `auth` (`Option<String>`) — default `[auth.NAME]` reference.
- `memory_max` (`Option<String>`) — default systemd `MemoryMax=`,
  parsed by `bytesize` at validate time.
- `labels` (`Vec<String>`) — concatenated with each runner's labels
  (dedup, preserve order — see merge rules below).
- `network` (`Option<String>`) — default `[network.NAME]`
  reference. None ≡ implicit Open mode.
- `arch` (`Option<Arch>`) — default tarball architecture.
- `hardening` (`Hardening`) — per-field overrides; runners can
  layer on top.
- `keep_versions` (`Option<u32>`) — `bin.X.Y.Z/` retention count
  under each runner home after a tarball install. Pruner keeps the
  N most recent by mtime; default `DEFAULT_KEEP_VERSIONS = 2`
  (current install + one rollback target). Set lower (`1` = no
  rollback retention) or higher (e.g. `5`) per disk pressure.

There is NO `slice` field. Every ghars-managed unit uses
`Slice=system.slice` unconditionally.

## `[auth.NAME]`

Tagged enum, `kind = "..."` discriminator. Four variants:

```toml
[auth.pat]
kind       = "pat"
token_env  = "GHARS_PAT"            # XOR token_file (validator enforces)
# token_file = "/etc/ghars/keys/pat" # mode 0600 owned by root

[auth.gh-app-prod]
kind             = "github_app"
app_id           = 12345
installation_id  = 67890
private_key_path = "/etc/ghars/keys/app.pem"

[auth.shared-token]
kind = "token_file"
path = "/etc/ghars/keys/registration.token"  # pre-minted registration token

[auth.dev]
kind = "interactive"  # apply prompts on TTY
```

Notes:

- `pat`: any GitHub PAT (classic with `repo` / `admin:org`,
  fine-grained with Administration: write, or any future token
  type). Forwarded to `octocrab` as a Bearer credential; GitHub
  validates server-side. Exactly one of `token_env` / `token_file`
  MUST be set (XOR). If `token_file`, the file must be mode 0600
  owned by root.
- `github_app`: octocrab handles JWT minting + installation-token
  caching. The `private_key_path` PEM is opened with `O_NOFOLLOW`
  at apply time (closes the lstat-then-open TOCTOU window).
- `interactive`: prints the registration URL, reads a pre-minted
  REGISTRATION TOKEN (not a PAT) from stdin. The registration
  token is the short-lived value GitHub's "Add new self-hosted
  runner" UI generates; expires in 1 hour. TTY required — apply on
  non-TTY stdin without `--auto-approve` returns exit code 7.
- `token_file`: same registration-token semantics as `interactive`,
  sourced from a file instead of pasted at apply time.

The `RegistrationToken.value` field uses `zeroize` (with the
`derive` feature) so it is scrubbed in `Drop` even on panic
unwind.

## `[cache_pools.NAME]`

```toml
[cache_pools.build]
kinds      = ["ccache", "sccache"]    # one or both
size       = "200G"                   # bytesize-parsed
mode       = "shared"                 # shared | isolated; default shared
trust_zone = "default"                # default "default"
```

Fields:

- `kinds` (`Vec<CacheKind>`) — the kinds the pool hosts. Values
  `ccache` and `sccache`. ccache uses cooperative `flock` on a
  shared dir; sccache satisfies its sole-maintainer contract via
  one server unit per pool.
- `size` (`String`) — pool size, parsed by `bytesize` at validate
  time. Drives `CCACHE_MAXSIZE` and `SCCACHE_CACHE_SIZE` in the
  rendered drop-in.
- `mode` (`CacheMode`) — `Shared` (default) lets multiple runners
  reference the pool; `Isolated` rejects configs where >1 runner
  references the pool. sccache pools are always shared regardless
  of this setting (the validator-enforced
  single-sccache-pool-per-runner rule below applies anyway).
- `trust_zone` (`String`) — default `"default"`. Validator: every
  runner referencing the pool must have the same `trust_zone`.

A runner that references >1 cache pool with `kinds` containing
`sccache` is rejected at config load (`SCCACHE_SERVER_UDS` is
single-valued; multi-pool sccache references would silently shadow
all but the last via systemd's last-writer-wins `Environment=`
semantics).

## `[network.NAME]`

```toml
[network.isolated]
mode             = "netns"
allowed_egress   = [
  { addr = "proxy.example", port = 3128, proto = "tcp", comment = "outbound proxy" },
  { addr = "192.0.2.0/24",  port = { start = 1024, end = 65535 } },
]
ip_allow         = ["192.0.2.10/32"]    # IPAddressAllow (cgroup-BPF)
ip_deny          = ["0.0.0.0/0"]        # IPAddressDeny
address_families = ["AF_UNIX", "AF_INET"]
dns              = "forward"            # default; or { mode = "static", servers = [...] }
ipv6             = "disabled"           # default; "enabled" reserved for v0.2
```

Fields:

- `mode` (`NetworkMode`) — `open` (host netns; rarely declared
  explicitly — operators usually omit `network` to get Open) or
  `netns` (per-runner network namespace via
  `ghars-net@RUNNER.service`).
- `allowed_egress` (`Vec<EgressRule>`) — each entry: `addr`
  (IPv4/IPv6 or CIDR), `port` (single, set, or range), `proto`
  (`tcp`, `udp`, or `both` — `both` emits two nft rules),
  optional `comment` (sanitized at generate time).
- `ip_allow` / `ip_deny` (`Vec<IpNet>`) — feed systemd's
  `IPAddressAllow=` / `IPAddressDeny=` (cgroup-BPF layer);
  emitted alongside the netns nft rules as defense in depth.
- `address_families` (`Vec<String>`) — `AF_*` allowlist for
  systemd `RestrictAddressFamilies=`. Empty Vec ≡ unset.
- `dns` (`DnsMode`) — default `forward` (use the host's
  systemd-resolved via the veth IP). `{ mode = "static", servers
  = [...] }` lists explicit upstream nameservers and bypasses
  systemd-resolved. No no-DNS mode.
- `ipv6` (`Ipv6Mode`) — default `disabled`. v0.2 will allocate a
  /64 from a configurable ULA pool when set to `enabled`; v0.1
  apply errors with that explanation.

A `mode = "netns"` block with empty `allowed_egress` AND empty
`ip_allow` is rejected at validate time — a netns runner with no
egress is almost certainly a misconfiguration.

`PortSpec` is an untagged serde enum:

```toml
port = 53                            # Single
port = [53, 80]                      # Set
port = { start = 1024, end = 65535 } # Range (inclusive)
```

## `[proxy]` (singleton)

```toml
[proxy]
http     = "http://proxy.example:3128"
https    = "http://proxy.example:3128"
no_proxy = ["proxy.example", "10.0.0.0/8"]
ca_certs = [
  { env = "NODE_EXTRA_CA_CERTS", path = "/etc/pki/ca-trust/source/anchors/proxy-ca.pem" },
  { env = "REQUESTS_CA_BUNDLE", path = "/etc/pki/tls/certs/ca-bundle.crt" },
]
```

Fields:

- `http` / `https` (`Option<String>`) — proxy URLs. Each is emitted
  as both upper- and lower-case env entries (`HTTP_PROXY` +
  `http_proxy`; `HTTPS_PROXY` + `https_proxy`) so apps that read
  either find a value. Often the same URL.
- `no_proxy` (`Vec<String>`) — emitted as both `NO_PROXY` and
  `no_proxy` env entries.
- `ca_certs` (`Vec<CaCertBinding>`) — each entry maps an env-var
  name to a host CA file path. Common entries:
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`,
  `CURL_CA_BUNDLE`. Operators can add new pairs without ghars
  schema changes. The path must be readable through the runner's
  mount namespace; ghars adds it to `BindReadOnlyPaths` if needed.

Per-runner overrides via `[[runner]].proxy` replace the singleton
entirely for that runner.

Authenticated proxy URLs embed credentials in the userinfo
component (`https://USER:PASS@host`). The `60-proxy.conf` drop-in
emits `Environment=HTTP_PROXY=...` / `HTTPS_PROXY=...` verbatim,
so `--diff` output can leak those credentials. See
[Operations](./operations.md) for the diff caveat.

## `[hooks]` (singleton)

```toml
[hooks]
pre_job  = "/opt/gha-hooks/pre-job.sh"
post_job = "/opt/gha-hooks/post-job.sh"
```

Maps to `ACTIONS_RUNNER_HOOK_JOB_STARTED` /
`ACTIONS_RUNNER_HOOK_JOB_COMPLETED` env vars on the runner.
`validators::validate_hook_script` enforces every check below at
config load (SEC-12); the order matches the source:

- **Absolute path required** — `path.starts_with('/')`. Relative
  paths resolve against the runner's cwd at exec time, which is
  operator-controllable through workflow YAML and would let a
  workflow swap the hook target.
- **Parent must not be `/`** — a hook at `/foo.sh` would force
  the renderer to emit `BindReadOnlyPaths=/`, exposing the entire
  host filesystem to the runner sandbox. Hooks must live under a
  dedicated subdirectory (e.g. `/usr/local/lib/ghars-hooks/`).
- **`O_NOFOLLOW` open** — kernel `ELOOP`s a final-component
  symlink, so the validator inspects the inode the kernel
  returned; no lstat-then-open race.
- **Regular file** — the `fstat` on the open fd must report
  `S_IFREG`. Fifos, sockets, and devices reject.
- **Owner-execute bit** — `mode & 0o100` must be non-zero.
- **Root-owned** — `meta.uid() == 0`. A non-root-owned hook
  could be rewritten by the owning user under the operator's
  feet.
- **Group/world-writable bits rejected** — `mode & 0o022 == 0`.
  Owner-only mutation is the trust premise; if any non-root
  principal can rewrite the script, the root-owned check above
  is moot. Operator remediation: `chmod go-w <path>`.

Per-runner override via `[[runner]].hooks` replaces the singleton
for that runner.

## `[[runner]]`

```toml
[[runner]]
name           = "build-1"
url            = "https://github.com/example/build"
auth           = "pat"
labels         = ["x64"]
caches         = ["build"]
trust_zone     = "default"
network        = "isolated"
memory_max     = "16G"
runner_version = "2.334.0"
runner_sha256  = "abcd...64hex..."
arch           = "x86_64"
# count        = 10                  # prefix expansion (1..1024)
# proxy        = { ... }             # per-runner override of [proxy]
# hooks        = { ... }             # per-runner override of [hooks]
# hardening    = { ... }             # per-field hardening overrides
# allowed_cpus = "0-15"              # AllowedCPUs= (cgroup v2 cpuset)
# allowed_memory_nodes = "0"
```

Selected fields:

- `name` (`String`) — runner name (or prefix when `count > 1`).
  Matches `IDENTIFIER_REGEX`. Effective cap is `RUNNER_NAME_MAX_LEN
  = 25` for Open-mode runners (so the derived
  `ghars-NAME` system identifier fits systemd's 31-char strict
  cap) and `NETNS_RUNNER_NAME_MAX_LEN = 7` for Netns-mode runners
  (so the derived veth `ghars-NAME-h` fits `IFNAMSIZ - 1 = 15`).
  See [Identifiers](#identifiers).
- `count` (`Option<u32>`) — default None ≡ 1 runner with `name`
  as-is. `Some(n)`: `name` is the prefix and ghars generates
  `name-1` through `name-n`. Range `1..=1024`. The count block
  AUTO-SKIPS any index whose generated name matches an explicit
  `[[runner]] name = "..."` block elsewhere — operators with one
  divergent runner in a counted set declare an explicit block to
  override.
- `url` (`String`) — repo or org URL.
- `auth` (`Option<String>`) — `[auth.NAME]` reference. Required
  via the runner's own field or `defaults.auth`.
- `caches` (`Vec<String>`) — references to `[cache_pools.NAME]`.
  Ordered, dedup-on-validate. A runner can reference at most one
  pool with `kinds` containing `sccache`.
- `trust_zone` (`String`) — default `"default"`. Pool references
  must match (validator enforces).
- `runner_tarball` (`Option<Utf8PathBuf>`) — pre-downloaded local
  tarball, bypasses release-API lookup. The path is opened with
  `O_NOFOLLOW` at apply time; symlinks and non-regular files are
  rejected.
- `hardening` (`Hardening`) — per-field overrides on top of
  `defaults.hardening`.
- `allowed_cpus` / `allowed_memory_nodes` (`Option<String>`) —
  systemd cgroup v2 cpuset values. None ≡ no `50-numa.conf`
  drop-in.

`RunnerGroupSpec` and `RunnerOverride` are NOT part of the schema.
Operators that need divergent config in a counted set declare a
new `[[runner]]` block with the matching auto-skipped name.

## Hardening

`Hardening` is per-field; each field is `Option<bool>` (or
equivalent). `None` ≡ inherit ghars's canonical profile;
`Some(...)` ≡ explicit override. Both `[defaults.hardening]` and
`[[runner]].hardening` are merged field-by-field.

Defaults (per `HardeningProfile::from`):

| field                    | default | controls                         |
|--------------------------|---------|----------------------------------|
| `kvm`                    | `true`  | `DeviceAllow=/dev/kvm rw`        |
| `restrict_realtime`      | `false` | `RestrictRealtime=`              |
| `protect_control_groups` | `false` | `ProtectControlGroups=`          |
| `restrict_suid_sgid`     | `true`  | `RestrictSUIDSGID=`              |
| `private_devices`        | `true`  | `PrivateDevices=`                |
| `private_ipc`            | `true`  | `PrivateIPC=`                    |

List-typed fields:

- `restrict_address_families` (`Vec<String>`) — empty ≡ unset; non-
  empty emits `RestrictAddressFamilies=` with the listed AF_*
  tokens.
- `extra_syscalls` (`Vec<String>`) — APPENDED to the canonical
  syscall allowlist (`SystemCallFilter=@system-service ...`).
- `etc_bind_style` (`EtcBindStyle`) — `curated` (default; narrow
  /etc list) or `broad` (whole /etc).
- `bind_readonly_paths` (`Option<Vec<Utf8PathBuf>>`) — REPLACES
  the template's `BindReadOnlyPaths` set (gated by the
  reset-on-empty validator).
- `extra_bind_paths` (`Vec<Utf8PathBuf>`) — APPENDS to the
  template's set (or to `bind_readonly_paths` if also set). Use
  to keep defaults but add paths (e.g. proxy CA bundles).
- `extra_capabilities` (`Vec<String>`) — additional
  `CapabilityBoundingSet=` entries (rarely needed).

The reset-on-empty validator rejects any drop-in that emits a
list-typed directive with bare `=` (e.g. `SystemCallFilter=`),
because that would silently erase the template's allowlist. See
[Internals](./internals.md#reset-on-empty-validator).

## Defaults merge rules

| field family              | merge rule                                          |
|---------------------------|-----------------------------------------------------|
| scalar                    | runner overrides default; missing runner ⇒ default |
| `labels`                  | `concat(defaults.labels, runner.labels)` then dedup, preserve order |
| `caches`                  | runner-only (defaults has no caches list)           |
| `hardening` (per field)   | runner field wins iff `Some`; otherwise default field |

After merge, an `EffectiveRunnerSpec` carries the resolved bindings
(`auth_name`, `caches`, `network`) inline so downstream code never
re-traverses the parent `Config`.

## Validators

Run by `cli::load_config` in this order; first failure short-
circuits:

1. `validate_networks` — egress rule address + port shape, DNS
   mode, netns-requires-egress-or-ip-allow.
2. `validate_security_overrides` — `Hardening.extra_capabilities` /
   `extra_bind_paths` deny-list; hooks scripts via
   `validate_hook_script` (`O_NOFOLLOW` open with the seven SEC-12
   checks listed under [`[hooks]`](#hooks-singleton)).
3. `validate_identity_fields` — trust_zone control-char rejection.
4. `validate_no_duplicate_caches` — no `caches = ["a", "a"]`
   inside a single `[[runner]]`.
5. `validate_single_sccache_pool_per_runner` — at most one sccache
   pool per runner.
6. `validate_cache_pool_names` — length cap on pool keys + runner
   `caches` refs.
7. `validate_runner_names` — length cap retained as a holdover
   from the pre-DynamicUser era (when `User=ghars-<name>` was
   bounded by systemd's 31-char `valid_user_group_name` check).
   Under DynamicUser the User= is `ghars-tz-<TRUST_ZONE>` and
   does not bound the runner name; the synthesized
   `LogNamespace=ghars-<name>` and path-segment uses face much
   looser limits (LOG_NAMESPACE_MAX = 222, NAME_MAX = 255). The
   31-char cap is kept for path-component conservation and
   backward compatibility with pre-DynamicUser configs.
8. `validate_auth_keys` — every runner's `auth` resolves.
9. `validate_pat_xor` — `AuthSpec::Pat` shape-only XOR check on
   `token_env` / `token_file`.
10. `validate_runner_tarballs` — `O_NOFOLLOW` regular-file gate on
    operator-supplied `runner_tarball` paths.
11. `validate_netns_runner_name_lengths` — IFNAMSIZ (kernel veth
    name) cap on runners whose effective network mode is Netns.

`validate --deep` round-trips auth tokens against GitHub via
`octocrab`.

## Worked example

```toml
[defaults]
runner_version = "2.334.0"
auth           = "pat"
arch           = "x86_64"
memory_max     = "110G"
labels         = ["self-hosted", "linux"]
network        = "isolated"

[defaults.hardening]
protect_control_groups    = true
restrict_realtime         = true
restrict_address_families = ["AF_UNIX", "AF_INET"]
extra_syscalls            = ["clone3", "rseq", "close_range", "memfd_create", "membarrier"]

[auth.pat]
kind      = "pat"
token_env = "GHARS_PAT"

[proxy]
http     = "http://proxy.example:3128"
https    = "http://proxy.example:3128"
no_proxy = ["proxy.example"]

[hooks]
pre_job  = "/opt/gha-hooks/pre-job.sh"
post_job = "/opt/gha-hooks/post-job.sh"

[cache_pools.build]
kinds = ["ccache", "sccache"]
size  = "200G"
mode  = "shared"

[network.isolated]
mode             = "netns"
allowed_egress   = [
  { addr = "proxy.example", port = 3128, proto = "tcp", comment = "outbound proxy" },
]
ip_allow         = ["192.0.2.10/32"]
ip_deny          = ["0.0.0.0/0"]
address_families = ["AF_UNIX", "AF_INET"]

[[runner]]
name   = "build-1"
url    = "https://github.com/example/build"
labels = ["x64"]
caches = ["build"]

[[runner]]
name   = "ci"
count  = 10                                # ci-1..ci-10
url    = "https://github.com/example/repo"
labels = ["ci"]
caches = ["build"]

[[runner]]
name       = "ci-7"                        # auto-skipped from count above
url        = "https://github.com/example/repo"
labels     = ["ci", "big-mem"]
memory_max = "16G"
caches     = ["build"]
```
