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
[cache_pools.NAME]        # ccache, sccache, and/or ktstr pool, keyed by identifier
[network.NAME]            # network policy (netns or open mode), keyed by identifier
[proxy]                   # singleton — applies to every runner unless overridden
[hooks]                   # singleton — pre/post-job hook scripts
[[runner]]                # one block per runner (or count = N for prefix expansion)
```

`[network.NAME]` blocks declare a network policy. `mode` is
required and is one of:

- `mode = "netns"` — allocates a per-runner network namespace via
  `ghars-net@RUNNER.service` (veth pair, nft rules, optional DNS
  forwarding).
- `mode = "open"` — keeps the runner in the host netns but lets
  the operator pin systemd's cgroup-BPF egress filter
  (`IPAddressAllow=` / `IPAddressDeny=`) and the syscall
  address-family allowlist (`RestrictAddressFamilies=`) per
  runner.

A runner with no `network` reference at all uses the host netns
implicitly with no extra cgroup-BPF policy.

## Identifiers

All identifier keys (`auth.NAME`, `cache_pools.NAME`,
`network.NAME`, `[[runner]].name`) match the regex
`^[a-z]([a-z0-9-]*[a-z0-9])?$` and are at most `IDENTIFIER_MAX_LEN
= 64` characters. The constant `IDENTIFIER_REGEX` lives in
`config.rs`.

Netns-mode runners face an additional tighter cap so the rendered
veth interface name fits the kernel's IFNAMSIZ limit:

| key | hard cap | derived from |
|---|---|---|
| `[[runner]].name` (Netns mode) | `NETNS_RUNNER_NAME_MAX_LEN = 7` | `IFNAMSIZ (16) - 1 - len("ghars-") - len("-h")` (veth shape) |

For runner names with `count > 1`, the suffix `-N` is appended
during expansion, so the BASE name has to leave room for the
largest suffix within `IDENTIFIER_MAX_LEN`.

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
  hex). Only meaningful with `runner_version`. Empty string is
  normalized to None at merge time: equivalent to omitting the
  field at `[defaults]`, or — on a `[[runner]]` block — suppressing
  any inherited `[defaults].runner_sha256` value (explicit-reset
  semantic for per-runner opt-out). The collapse keeps `spec_hash`
  matching the omit-the-field shape across both `Some(empty)` and
  `None` representations.
- `auth` (`Option<String>`) — default `[auth.NAME]` reference.
- `memory_max` (`Option<String>`) — default systemd `MemoryMax=`,
  parsed by `bytesize` at validate time. Empty string is normalized
  to None at merge time: equivalent to omitting the field at
  `[defaults]`, or — on a `[[runner]]` block — suppressing any
  inherited `[defaults].memory_max` value (explicit-reset semantic
  for per-runner opt-out). The collapse keeps `spec_hash` matching
  the omit-the-field shape across both `Some(empty)` and `None`
  representations.
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
kinds        = ["ccache", "sccache"]      # one or both
size         = "200G"                     # bytesize-parsed
mode         = "shared"                   # shared | isolated; default shared
trust_zone   = "default"                  # default "default"
sccache_path = "/usr/local/bin/sccache"   # optional override
sleep_path   = "/usr/bin/sleep"           # optional override
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
  of this setting (the validator-enforced no-duplicate-cache-kinds
  rule below applies anyway — at most one sccache pool per runner,
  same for ccache).
- `trust_zone` (`String`) — default `"default"`. Validator: every
  runner referencing the pool must have the same `trust_zone`.
  Must match `IDENTIFIER_REGEX` (lowercase letters, digits, dashes;
  start with a letter; end with a letter or digit) and ≤
  `TRUST_ZONE_MAX_LEN = 22` chars: the rendered DynamicUser identity
  `User=ghars-tz-<TRUST_ZONE>` must fit systemd's strict 31-char
  `valid_user_group_name` ceiling.
- `sccache_path` (`Option<Utf8PathBuf>`) — optional absolute path to
  the sccache binary used as the per-pool unit's `ExecStart=`. When
  omitted (default), plan-time auto-detection probes
  `/usr/local/bin/sccache` then `/usr/bin/sccache` and uses the
  first hit. Required only for pools whose `kinds` contains
  `sccache`; ccache-only pools ignore this field. Validator: the
  path must be absolute when set; the operator's pin overrides
  auto-detection without filesystem existence checks at config
  load (the unit-start gates that as part of normal systemd
  resolution).
- `sleep_path` (`Option<Utf8PathBuf>`) — optional absolute path to the
  sleep binary used as the unit's `ExecStart=` for ccache-only
  pools (keeping the unit active so the CacheDirectory= mount
  stays owned; sccache-serving pools put the sccache server on
  ExecStart and never invoke sleep). When omitted (default),
  plan-time auto-detection probes `/usr/bin/sleep` then `/bin/sleep`
  and uses the first hit. Validator: the path must be absolute
  when set.

A runner that references >1 cache pool sharing any single `kind`
(ccache or sccache) is rejected at config load. For sccache pools,
`SCCACHE_SERVER_UDS` is single-valued and multi-pool references would
silently shadow all but the last via systemd's last-writer-wins
`Environment=` semantics. For ccache pools, ghars wires a trust-zone-
shared `CCACHE_DIR=/var/lib/ghars/<TRUST_ZONE>/.ccache` in the
runner's `.env` plus one `CCACHE_MAXSIZE` per binding — ccache is
single-`CCACHE_DIR`-per-process by upstream design, so multiple
ccache pools cannot deliver distinct cache dirs, and the per-binding
`CCACHE_MAXSIZE` values race in the `.env` load (last wins).
Remediation: drop all but one pool of the offending kind from
`[[runner]].caches`, OR merge the kinds into a single
`[cache_pools.NAME]` entry (one pool with `kinds = ["ccache",
"sccache"]` instead of two pools each contributing the same kind).

## `[network.NAME]`

```toml
[network.isolated]
mode                      = "netns"
allowed_egress            = [
  { addr = "proxy.example", port = 3128, proto = "tcp", comment = "outbound proxy" },
  { addr = "192.0.2.0/24",  port = { start = 1024, end = 65535 } },
]
ip_allow                  = ["192.0.2.10/32"]    # IPAddressAllow (cgroup-BPF)
ip_deny                   = ["0.0.0.0/0"]        # IPAddressDeny
restrict_address_families = ["AF_INET", "AF_UNIX"]
dns                       = "forward"            # default; or { mode = "static", servers = [...] }
ipv6                      = "disabled"           # default; "enabled" reserved for v0.2

# Open mode example — host netns, but with cgroup-BPF egress filter
# and an address-family allowlist applied at the cgroup layer.
[network.host-with-policy]
mode                      = "open"
ip_allow                  = ["10.0.0.0/8"]
ip_deny                   = ["0.0.0.0/0"]
restrict_address_families = ["AF_INET"]
```

Fields:

- `mode` (`NetworkMode`) — `netns` (per-runner network namespace
  via `ghars-net@RUNNER.service`) or `open` (host netns; declared
  explicitly when the operator wants to add cgroup-BPF or
  address-family restrictions on top of the host netns without
  the namespace overhead). Operators who want plain host
  networking with no extra policy omit the `network` field
  entirely.
- `allowed_egress` (`Vec<EgressRule>`) — each entry: `addr`
  (IPv4/IPv6 or CIDR), `port` (single, set, or range), `proto`
  (`tcp`, `udp`, or `both` — `both` emits two nft rules),
  optional `comment` (sanitized at generate time). **Netns mode
  only** — `mode = "open"` REJECTS this field at validate time
  (no namespace, no nft, the rules would be silently dropped).
- `ip_allow` / `ip_deny` (`Vec<IpNet>`) — feed systemd's
  `IPAddressAllow=` / `IPAddressDeny=` (cgroup-BPF layer).
  Honored in BOTH modes: under `netns` they're one of two
  independent egress gates (the other being the nft rules from
  `allowed_egress`); the two use different input fields and
  enforce at different layers (cgroup-BPF socket-level vs nft
  packet-level), so they are complementary rather than
  redundant. Under `open` they are the sole egress gate at the
  systemd layer (no namespace, no nft). Set-semantic at the
  lowering boundary: both fields are sorted+deduped at
  `canonicalize_network_spec` AND alpha-sorted again at the
  renderer in `render_network`, so `["192.168.0.0/16", "10.0.0.0/8"]`
  and `["10.0.0.0/8", "192.168.0.0/16"]` produce identical rendered
  output and identical plan output (a cosmetic TOML reorder is a
  true NoOp at plan time). Operators who want their TOML to match
  the rendered drop-in byte-for-byte should write CIDRs in
  canonical order (by network address, then prefix length).
- `restrict_address_families` (`Vec<String>`) — `AF_*` allowlist
  for systemd `RestrictAddressFamilies=`. Empty Vec ≡ unset.
  Honored in both `netns` and `open` modes — the directive lives
  in the per-runner cgroup, not the namespace, so it applies
  regardless of whether the runner has its own netns. Field name
  mirrors the systemd directive and the parallel
  `Hardening.restrict_address_families` field; both fields are
  canonicalized (sort+dedup) at the lowering boundary AND alpha-
  sorted again at the renderer, so `["AF_UNIX", "AF_INET"]` and
  `["AF_INET", "AF_UNIX"]` produce identical rendered output and
  identical plan output — operators who want their TOML to match
  the rendered drop-in byte-for-byte should write the list in
  alphabetical order.
- `dns` (`DnsMode`) — default `forward` (use the host's
  systemd-resolved via the veth IP). `{ mode = "static", servers
  = [...] }` lists explicit upstream nameservers and bypasses
  systemd-resolved. No no-DNS mode. **Netns mode only** —
  `mode = "open"` REJECTS any non-Forward `dns` setting at
  validate time (the per-runner DNS policy is a netns artifact;
  Open-mode runners inherit the host's `/etc/resolv.conf`).
- `ipv6` (`Ipv6Mode`) — default `disabled`. v0.2 will allocate a
  /64 from a configurable ULA pool when set to `enabled`; v0.1
  apply errors with that explanation. **Netns mode only** —
  `mode = "open"` REJECTS `ipv6 = "enabled"` at validate time
  (Open-mode runners share the host's IPv6 stack).

A `mode = "netns"` block with empty `allowed_egress` AND empty
`ip_allow` is rejected at validate time — a netns runner with no
egress is almost certainly a misconfiguration.

A `mode = "open"` block carrying any netns-only field is rejected
at validate time too, because the silent-partial-enforcement
shape (operator writes the field, the renderer ignores it) is
worse than a structured error pointing at the misconfiguration.
Three rejection rules:

- `mode = "open"` + non-empty `allowed_egress` →
  "allowed_egress requires mode = netns; nft rules are not
  generated for open mode"
- `mode = "open"` + non-Forward `dns` →
  "dns requires mode = netns; open-mode runners inherit the
  host's /etc/resolv.conf"
- `mode = "open"` + `ipv6 = "enabled"` →
  "ipv6 = enabled requires mode = netns; open-mode runners share
  the host's IPv6 stack"

`mode = "open"` blocks have no analogous gate for empty cgroup-BPF
policy: an Open block with all defense-in-depth fields empty is
tolerated AND collapses at plan time to the same shape an operator
gets by omitting `network` entirely — no `40-network.conf`
drop-in, no `spec_hash` flip from the no-op block. So
`[network.foo] mode = "open"` with no policy fields and
`network = "foo"` on a runner is a no-op, exactly as if the
runner had `network` unset.

### Common mistake: cgroup-BPF fields under `[defaults.hardening]`

`ip_deny` and `ip_allow` live ONLY under `[network.NAME]`, never
under `[defaults.hardening]` or `[[runner]].hardening`. Putting
them under `[hardening]` fails at config load with serde's
`unknown field` error:

```toml
# WRONG — fails to parse with `unknown field "ip_deny"`
[defaults.hardening]
ip_deny = ["0.0.0.0/0"]

# RIGHT — declare an [network.NAME] block and reference it
[network.host-policy]
mode    = "open"
ip_deny = ["0.0.0.0/0"]

[[runner]]
name    = "build"
url     = "https://github.com/example/build"
auth    = "pat"
network = "host-policy"
```

`restrict_address_families` is the only field name that exists in
BOTH structs:

- `[defaults.hardening].restrict_address_families` (or
  `[[runner]].hardening.restrict_address_families`) — widens the
  systemd `RestrictAddressFamilies=` allowlist for every runner
  regardless of network mode. Emits to `20-hardening.conf`.
- `[network.NAME].restrict_address_families` — narrows the
  allowlist per-`[network.NAME]` block via the resolved network
  binding. Emits to `40-network.conf` (in either Netns or Open
  mode, since the directive lives at the cgroup layer). Composes
  with the hardening field across drop-ins (systemd unions both
  lines at unit-load time).

The fields are NOT interchangeable. There is NO way to attach
`ip_deny` / `ip_allow` to a runner via `[hardening]` — that's by
design (cgroup-BPF egress policy is per-runner network policy,
while hardening is the systemd sandbox shape applied uniformly
across the runner unit).

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

A `[proxy]` block with every field unset (`http`, `https`,
`no_proxy`, `ca_certs` all absent or empty) is normalized to None
at the lowering boundary (`lower_to_effective`); the `60-proxy.conf`
drop-in is not emitted and `spec_hash` matches the no-`[proxy]`
runner shape. Omitting the entire block is the canonical "no
proxy" form.

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

A `[hooks]` block with both fields unset (`pre_job = None`,
`post_job = None`) is normalized to None at the lowering boundary
(`lower_to_effective`); the `70-hooks.conf` drop-in is not emitted
and `spec_hash` matches the no-`[hooks]` runner shape. Same
precedent as `[proxy]` empty-collapse.

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
  Matches `IDENTIFIER_REGEX` (≤ `IDENTIFIER_MAX_LEN = 64` chars).
  When `count > 1`, the base name must leave room for the `-N`
  suffix within this cap. Netns-mode runners face an additional cap
  `NETNS_RUNNER_NAME_MAX_LEN = 7` so the derived veth
  `ghars-NAME-h` fits `IFNAMSIZ - 1 = 15`. See
  [Identifiers](#identifiers).
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
  pool contributing each kind (at most one ccache pool, at most
  one sccache pool); a single combined-kind pool with
  `kinds = ["ccache", "sccache"]` counts as one of each.
- `trust_zone` (`String`) — default `"default"`. Pool references
  must match (validator enforces). Same `IDENTIFIER_REGEX` shape +
  `TRUST_ZONE_MAX_LEN = 22` cap as `[cache_pools.NAME]` — the
  rendered DynamicUser identity `User=ghars-tz-<TRUST_ZONE>` must
  fit systemd's strict 31-char `valid_user_group_name` ceiling.
- `runner_tarball` (`Option<Utf8PathBuf>`) — pre-downloaded local
  tarball, bypasses release-API lookup. The path is opened with
  `O_NOFOLLOW` at apply time; symlinks and non-regular files are
  rejected. MUST be paired with `runner_version` (on the runner
  or in `[defaults]`) — the apply path needs the version string
  to name the on-disk `bin.X.Y.Z` directory, and ghars cannot
  infer the version from the tarball filename; `ghars plan`
  rejects unpaired `runner_tarball` declarations at validation
  time. Empty string (`runner_tarball = ""`) is rejected at
  config-load with "must be absolute" — to fall back to the
  release-API lookup, OMIT the field rather than setting it to
  empty (unlike `allowed_cpus`/`memory_max`, which silently
  normalize empty to None at merge time).
- `hardening` (`Hardening`) — per-field overrides on top of
  `defaults.hardening`.
- `allowed_cpus` / `allowed_memory_nodes` (`Option<String>`) —
  systemd cgroup v2 cpuset values. None ≡ no `50-numa.conf`
  drop-in. Empty string is normalized to None at merge time
  (equivalent to omitting the field); no separate "explicit reset"
  semantic.
- `environment` (`EnvironmentSpec`) — operator-declared env vars
  and PATH additions; merged with `[defaults.environment]`. See
  the `EnvironmentSpec` section below.

`RunnerGroupSpec` and `RunnerOverride` are NOT part of the schema.
Operators that need divergent config in a counted set declare a
new `[[runner]]` block with the matching auto-skipped name.

## EnvironmentSpec

`EnvironmentSpec` declares per-runner env vars and PATH additions.
Both `[defaults.environment]` and `[[runner]].environment` carry
the same shape; the merge is per-key for `vars` (runner wins on
key collision) and additive for `path_prepend` / `path_append`
(defaults entries first, then runner entries, dedup
defense-in-depth).

```toml
[defaults.environment]
vars = { MY_TEAM_VAR = "production", RUST_BACKTRACE = "1" }
path_prepend = ["/opt/company-tools/bin"]

[[runner]]
name = "buckos"
[runner.environment]
vars = { DEPLOY_TARGET = "buckos-ci" }   # adds to defaults.vars
path_append = ["/opt/buckos-specific/bin"]
```

Fields:

- `vars` (`BTreeMap<String, String>`) — operator-declared env
  vars. Iterated alphabetically when rendered into both `.env`
  (LAYER 2, consumed by `Runner.Listener::LoadAndSetEnv` for
  workflow steps) AND `00-ghars.conf`'s `Environment=`
  directives (LAYER 1, consumed by systemd for the runner unit
  process). Both layers carry the same merged keys. Operator
  TOML key reorders produce identical `.env` bytes (no spurious
  in-place rewrite + restart on cosmetic edits).
- `path_prepend` (`Vec<Utf8PathBuf>`) — paths inserted between
  the framework ccache wrappers (`/usr/lib64/ccache`,
  `/usr/lib/ccache`) and the per-runner `.cargo/bin` segment.
  ccache wrappers stay at position 0 unconditionally — operator
  paths cannot shadow `gcc` / `cc` and break the compile cache.
- `path_append` (`Vec<Utf8PathBuf>`) — paths appended after the
  system tail (`/usr/local/sbin:/usr/local/bin:/usr/sbin:
  /usr/bin:/sbin:/bin`).

### Validation (config-load)

Operator-declared env var names are rejected against a deny-list
with per-tier rationale:

- **Tier 1 (LD\_\* injection)**: `LD_PRELOAD`, `LD_LIBRARY_PATH`,
  `LD_AUDIT`, `LD_DEBUG`, `LD_BIND_NOW`, `LD_PROFILE`,
  `LD_TRACE_LOADED_OBJECTS`, `GLIBC_TUNABLES`, `MALLOC_TRACE` —
  dynamic-loader attack surface.
- **Tier 2 (shell hijack)**: `IFS`, `BASH_ENV`, `ENV`, `BASHOPTS`,
  `SHELLOPTS`, `PS4`, `PROMPT_COMMAND` — shell-execution
  hijacking before workflow steps see env.
- **Tier 3 (ghars-owned)**: `PATH`, `HOME`, `USER`, `LOGNAME`,
  `SHELL`, `TMPDIR`, `LANG`, `CCACHE_*`, `KTSTR_*`, `SCCACHE_*`,
  `HTTP_PROXY` family, `ACTIONS_RUNNER_*`, `RUNNER_ALLOW_RUNASROOT`
  — set by ghars from `trust_zone` / cache bindings / `[proxy]`
  / `[[runner.hooks]]`. Use those config surfaces instead.
- **Tier 4 (POSIX shape)**: env var names must match
  `^[A-Z_][A-Z0-9_]*$`.

Values containing control characters (`\n`, `\r`, `\0`) are
rejected (multi-line values would inject a second
`Environment=` directive into `00-ghars.conf` and a second
`KEY=VALUE` line into `.env`).

PATH entries must be absolute paths; relative paths, embedded
`:` (PATH separator), and control characters are all rejected.

### `%`-character handling

Operator values containing `%` are emitted verbatim in `.env`
(Runner.Listener's `LoadAndSetEnv` does not interpret `%`) and
double-escaped to `%%` in `00-ghars.conf`'s `Environment=`
directives (systemd would otherwise expand `%C`, `%t`, `%i`,
`%h` as its own specifiers). Both consumers see the operator's
literal value end-to-end.

If you need systemd specifier expansion in your env vars, do it
inside a wrapper script your workflow step invokes — the
operator-declared surface treats `%` as data.

### `.env` is ghars-owned

The `.env` file at `bin.X.Y.Z/.env` is overwritten by ghars on
every apply. **Do not edit it directly** — your changes will be
lost on the next `ghars apply` (overwritten unconditionally by
`execute_create_runner` + in-place by `execute_update_runner`).
Use `[[runner]].environment.vars` / `[defaults.environment].vars`
in `ghars.toml` instead; ghars will then maintain the `.env`
file in sync with config.

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
  tokens. Composes with the parallel
  `[network.NAME].restrict_address_families` field — `20-hardening.conf`
  and `40-network.conf` both emit a `RestrictAddressFamilies=` line
  and systemd unions them at unit-load time. The hardening field
  widens the allowlist globally; the network-spec field narrows it
  per-`[network.NAME]` block (and applies in either Netns or Open
  mode, since the directive lives at the cgroup layer).
  Canonicalized (sort+dedup) upstream at `merge_hardening` AND
  alpha-sorted at the renderer in `render_hardening`, so `["AF_UNIX", "AF_INET"]` and
  `["AF_INET", "AF_UNIX"]` produce identical rendered output and
  identical plan output — operators who want their TOML to match
  the rendered drop-in byte-for-byte should write the list in
  alphabetical order.
- `extra_syscalls` (`Vec<String>`) — APPENDED to the canonical
  syscall allowlist (`SystemCallFilter=@system-service ...`).
  Canonicalized (sort+dedup) upstream at `merge_hardening` AND
  alpha-sorted at the renderer in `render_hardening`; cosmetic TOML reorders are a true NoOp.
- `etc_bind_style` (`EtcBindStyle`) — `curated` (default; narrow
  /etc list) or `broad` (whole /etc).
- `bind_readonly_paths` (`Option<Vec<Utf8PathBuf>>`) — REPLACES
  the template's `BindReadOnlyPaths` set (gated by the
  reset-on-empty validator). NOT sorted: operator order is
  preserved across the merge boundary because systemd's PID 1
  user-space resorts mount entries parent-first via
  `mount_path_compare` before any `mount(2)` syscall, so operator-
  declared order is purely cosmetic to systemd but load-bearing
  for `spec_hash` byte-equality: introducing sort would flip
  `spec_hash` for existing deployments (triggering spurious in-
  place `UpdateRunner` cascades) and break the round-trip between
  operator TOML order and rendered drop-in bytes.
- `extra_bind_paths` (`Vec<Utf8PathBuf>`) — APPENDS to the
  template's `BindReadOnlyPaths` set (or to `bind_readonly_paths`
  if also set). Use to keep defaults but add paths (e.g. proxy
  CA bundles). All entries are read-only; no `Hardening` field
  exposes RW bind via `BindPaths=`. NOT sorted — same rationale
  as `bind_readonly_paths`.
- `extra_capabilities` (`Vec<String>`) — additional
  `CapabilityBoundingSet=` entries (rarely needed). Canonicalized
  (sort+dedup) upstream at `merge_hardening` AND alpha-sorted at the
  renderer in `render_hardening`; cosmetic TOML reorders are a true NoOp.

The reset-on-empty validator rejects any drop-in that emits a
list-typed directive with bare `=` (e.g. `SystemCallFilter=`),
because that would silently erase the template's allowlist. See
[Internals](./internals.md#reset-on-empty-validator).

## Defaults merge rules

| field family                  | merge rule                                          |
|-------------------------------|-----------------------------------------------------|
| scalar                        | runner overrides default; missing runner ⇒ default |
| `labels`                      | `concat(defaults.labels, runner.labels)` then dedup, preserve order |
| `caches`                      | runner-only (defaults has no caches list)           |
| `hardening` (per field)       | runner field wins iff `Some`; otherwise default field |
| `network` (reference)         | runner overrides default; missing runner ⇒ `defaults.network`; both unset ⇒ `None` (implicit Open) |
| `network` (resolution)†       | resolved `[network.NAME]` block collapses to `None` at plan time when `mode = "open"` AND every cgroup-BPF policy field (`ip_allow` / `ip_deny` / `restrict_address_families`) is empty — same shape as no `network` reference |

† **Footnote on `network` resolution**: This collapse is NOT a
defaults merge per se — it happens later in
`lower_to_effective` (see `src/plan/compute.rs`), after the
reference has resolved through the merge. The table groups it
here because operators looking up "what does my `network` field
do" find it in one place. The mechanical effect: a no-op
`[network.foo] mode = "open"` block referenced by a runner does
NOT flip the runner's `spec_hash` or emit a `40-network.conf`
drop-in — plan-time-equivalent to the runner having no
`network` field at all.

After merge, an `EffectiveRunnerSpec` carries the resolved bindings
(`auth_name`, `caches`, `network`) inline so downstream code never
re-traverses the parent `Config`.

## Validators

Run by `cli::load_config` in this order; first failure short-
circuits:

1. `validate_networks` — egress rule address + port shape, DNS
   mode, mode-scoped invariants:
   - `mode = "netns"` requires at least one of `allowed_egress` /
     `ip_allow`.
   - `mode = "open"` rejects `allowed_egress`, non-Forward `dns`,
     and `ipv6 = "enabled"` (these are netns-only artifacts that
     would be silently ignored under Open mode).
2. `validate_security_overrides` — `Hardening.extra_capabilities` /
   `extra_bind_paths` deny-list; hooks scripts via
   `validate_hook_script` (`O_NOFOLLOW` open with the seven SEC-12
   checks listed under [`[hooks]`](#hooks-singleton)).
3. `validate_identity_fields` — trust_zone control-char rejection.
4. `validate_trust_zone_lengths` — trust_zone identifier-shape
   gate (lowercase letters, digits, dashes; kebab-case only) +
   length cap (`TRUST_ZONE_MAX_LEN = 22`) so the rendered
   DynamicUser identity `User=ghars-tz-<TRUST_ZONE>` fits systemd's
   strict 31-char `valid_user_group_name` ceiling.
5. `validate_no_duplicate_caches` — no `caches = ["a", "a"]`
   inside a single `[[runner]]`.
6. `validate_no_duplicate_cache_kinds` — at most one pool of each
   `CacheKind` per runner (one ccache, one sccache). Sibling of
   `validate_no_duplicate_caches` at the literal-pool-ref layer;
   this validator works at the resolved-kind layer so two distinct
   pools that each contribute the same kind to one runner trip
   the gate. Rationale: each kind's renderer emits per-pool /
   per-binding env vars that would silently shadow under
   last-writer-wins semantics — ccache via shell `.env` loader
   (`CCACHE_MAXSIZE`), sccache via systemd `Environment=`
   (`SCCACHE_SERVER_UDS`).
7. `validate_cache_pool_names` — identifier-shape gate on pool keys
   and runner `caches` refs.
8. `validate_cache_pool_binary_paths` — absolute-path gate on the
   operator-pinned `sccache_path` / `sleep_path` overrides on each
   `[cache_pools.NAME]` block.
9. `validate_runner_names` — identifier-shape gate on every
   `[[runner]] name`. Netns-mode runners face an additional
   tighter cap enforced by `validate_netns_runner_name_lengths`
   below.
10. `validate_auth_keys` — every runner's `auth` resolves.
11. `validate_pat_xor` — `AuthSpec::Pat` shape-only XOR check on
    `token_env` / `token_file`.
12. `validate_runner_tarballs` — `O_NOFOLLOW` regular-file gate on
    operator-supplied `runner_tarball` paths.
13. `validate_netns_runner_name_lengths` — IFNAMSIZ (kernel veth
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
restrict_address_families = ["AF_INET", "AF_UNIX"]
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
mode                      = "netns"
allowed_egress            = [
  { addr = "proxy.example", port = 3128, proto = "tcp", comment = "outbound proxy" },
]
ip_allow                  = ["192.0.2.10/32"]
ip_deny                   = ["0.0.0.0/0"]
restrict_address_families = ["AF_INET", "AF_UNIX"]

# Open-mode policy block: host netns + cgroup-BPF egress filter.
# Useful when the operator needs IP/family restrictions but cannot
# afford the netns/veth setup (older kernels without
# CONFIG_NET_NS, host-routed connectivity policies, etc.).
[network.host-policy]
mode                      = "open"
ip_allow                  = ["10.0.0.0/8", "192.0.2.10/32"]
ip_deny                   = ["0.0.0.0/0"]
restrict_address_families = ["AF_INET", "AF_INET6"]

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

# Runner using the open-mode policy block — host netns, but with
# cgroup-BPF egress filter and address-family allowlist applied at
# the cgroup layer. No per-runner namespace, no veth, no nft.
[[runner]]
name    = "host-net"
url     = "https://github.com/example/legacy"
labels  = ["legacy"]
network = "host-policy"
```
