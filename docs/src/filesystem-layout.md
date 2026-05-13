# Filesystem Layout

Every path ghars touches flows from a single `Paths` value
(`paths.rs`). The defaults follow FHS conventions; tests redirect
the whole tree under a tempdir without per-call plumbing.

## Default roots

| field             | default                          | role                                                          |
|-------------------|----------------------------------|---------------------------------------------------------------|
| `state_dir`       | `/var/lib/ghars`                 | per-runner state (config.sh output, versioned bin/) |
| `cache_dir`       | `/var/cache/ghars`               | shared cache pool storage                                     |
| `logs_dir`        | `/var/log/ghars`                 | persistent log storage outside journald                       |
| `unit_dir`        | `/etc/systemd/system`            | unit + drop-in installation root                              |
| `credentials_dir` | `/etc/credstore.encrypted/ghars` | auth credential storage                                       |
| `runtime_dir`     | `/run/ghars`                     | runtime data (apply lock, sccache UDS, token drops, netns resolv.conf bind-mount sources) |
| `config_dir`      | `/etc/ghars`                     | config + nft rule directory (`nft.d/` lives here)             |
| `resolved_conf_d` | `/etc/systemd/resolved.conf.d`   | host-wide systemd-resolved drop-in directory                  |

## Per-runner paths

Helpers on `Paths` (every helper here is `#[must_use]`):

| helper                                     | example expansion                                                         | what it is                                                  |
|--------------------------------------------|---------------------------------------------------------------------------|-------------------------------------------------------------|
| `runner_home(zone, name)`                  | `/var/lib/ghars/default/ghars-build-1`                                    | runner state dir                                            |
| `trust_zone_home(zone)`                    | `/var/lib/ghars/default`                                                  | shared HOME root for every runner in the zone               |
| `unit_file(name)`                          | `/etc/systemd/system/ghars-runner@build-1.service`                        | per-instance unit reference                                 |
| `drop_in_dir(name)`                        | `/etc/systemd/system/ghars-runner@build-1.service.d`                      | per-runner drop-in dir                                      |
| `cache_template_unit_file()`               | `/etc/systemd/system/ghars-cache@.service`                                | canonical cache template unit                               |
| `netns_template_unit_file()`               | `/etc/systemd/system/ghars-net@.service`                                  | canonical netns template unit                               |
| `netns_unit_file(name)`                    | `/etc/systemd/system/ghars-net@build-1.service`                           | per-runner netns unit (template instance)                   |
| `cache_unit_file(pool)`                    | `/etc/systemd/system/ghars-cache@build.service`                           | per-pool cache unit (template instance)                     |
| `cache_drop_in_dir(pool)`                  | `/etc/systemd/system/ghars-cache@build.service.d`                         | per-pool cache drop-in dir                                  |
| `cache_pool_dir(pool)`                     | `/var/cache/ghars/pools/build`                                            | per-pool storage dir                                        |
| `cache_pool_root()`                        | `/var/cache/ghars/pools`                                                  | parent of every per-pool dir                                |
| `apply_lock()`                             | `/run/ghars/apply.lock`                                                   | POSIX advisory exclusive lock for `apply`                   |
| `apply_log()`                              | `/var/log/ghars/apply.log`                                                | append-only structured audit log (one JSON object per line) |
| `token_drop(name)`                         | `/run/ghars/build-1.token`                                                | token-drop path consumed by config.sh                       |
| `nft_host_rule(name)`                      | `/etc/ghars/nft.d/build-1-host.nft`                                       | host-side nft rules                                         |
| `nft_ns_rule(name)`                        | `/etc/ghars/nft.d/build-1-ns.nft`                                         | inside-namespace nft rules                                  |
| `resolved_drop_in(name)`                   | `/etc/systemd/resolved.conf.d/ghars-build-1.conf`                         | systemd-resolved drop-in for netns DNS forwarding           |
| `netns_resolv_conf(name)`                  | `/run/ghars/netns-resolv/build-1`                                         | generated `resolv.conf` bind-mount source for the netns     |

## Drop-in catalog

The runner template (`ghars-runner@.service`) is canonical and
shared. Per-runner variation lives in
`<unit_dir>/ghars-runner@NAME.service.d/*.conf`. The renderer
(`render_runner_unit` in `systemd/units.rs`) emits these basenames in
order, each behind a "is the operator using this feature?" gate:

| basename                | always emitted?                          | content                                                              |
|-------------------------|------------------------------------------|----------------------------------------------------------------------|
| `00-ghars.conf`         | yes                                      | identity annotation cascade (see the [`X-Ghars-*` annotation reference](#x-ghars--annotation-reference) section below for every key, value format, source-of-truth field, and emission gate). Sets `User=ghars-tz-<TRUST_ZONE>`, the `ExecStart=` (versioned `runsvc.sh`), the `WorkingDirectory=`, and HOME |
| `10-memory.conf`        | when `memory_max` set                    | `MemoryMax=`                                                         |
| `15-resolv.conf`        | yes                                      | binds `/etc/resolv.conf` from the host's file (Open mode) or the netns-private file at `/run/ghars/netns-resolv/<name>` (Netns mode) |
| `20-hardening.conf`     | when any field overrides default         | per-field `Hardening` → systemd directives                           |
| `30-cache-pool.conf`    | when `caches` non-empty                  | ccache / sccache pool bindings, `BindPaths=` for shared dirs, env vars |
| `40-network.conf`       | Netns mode, OR Open mode with any of `ip_allow` / `ip_deny` / `restrict_address_families` | Netns: `NetworkNamespacePath=/var/run/netns/ghars-<name>` + `Requires=ghars-net@%i.service` + cgroup-BPF directives. Open: cgroup-BPF directives only (`IPAddressAllow=` / `IPAddressDeny=` / `RestrictAddressFamilies=`), no `[Unit]` section |
| `50-numa.conf`          | when `allowed_cpus` or `allowed_memory_nodes` set | `AllowedCPUs=` / `AllowedMemoryNodes=`                       |
| `60-proxy.conf`         | when `[proxy]` resolved                  | dual-case `Environment=HTTP_PROXY=...`/`http_proxy=...`, `HTTPS_PROXY=...`/`https_proxy=...`, `NO_PROXY=...`/`no_proxy=...` + CA-trust env vars |
| `70-hooks.conf`         | when `[hooks]` resolved                  | `Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED=...` + `BindReadOnlyPaths` for hook script |
| `80-lognamespace.conf`  | yes                                      | `LogNamespace=ghars-<name>` (per-runner journal isolation)           |

The `00-ghars.conf` `X-Ghars-*` annotations are the load-bearing
state-discovery mechanism: `state.rs` parses them via
`extract_x_ghars` to reconstruct the discovered runner's pre-update
spec for the plan diff. Every annotation field is checked at
emission via `check_identity_field` for control-character escapes,
defense-in-depth against unit-text injection.

### `X-Ghars-*` annotation reference

Every `X-Ghars-*` key the renderer writes, across the runner unit's
`00-ghars.conf` drop-in (per-runner identity), the cache pool unit's
`00-ghars.conf` drop-in (per-pool identity), and the three managed
template bodies (`RUNNER_TEMPLATE`, `NETNS_TEMPLATE`,
`CACHE_TEMPLATE`). Operator-readable via `systemctl cat` for the
matching unit.

Template markers — same pair emitted by every managed template body
so a future operator inspecting any ghars-managed unit body via
`systemctl cat` can identify the unit as ghars-managed and read off
the schema version:

| key | value format | source | emission gate | location |
|---|---|---|---|---|
| `X-Ghars-Managed` | literal `true` | static template marker | always | `RUNNER_TEMPLATE`, `NETNS_TEMPLATE`, `CACHE_TEMPLATE` `[Unit]` |
| `X-Ghars-Schema-Version` | literal `1` | static template marker | always | `RUNNER_TEMPLATE`, `NETNS_TEMPLATE`, `CACHE_TEMPLATE` `[Unit]` |

Per-runner annotations emitted by `render_identity` (runner unit's
`00-ghars.conf` drop-in `[Unit]` section). The network-related rows
read from `EffectiveRunnerSpec.network` (an
`Option<EffectiveNetworkBinding>`) — the source column shows the
field path inside the `Some(...)` binding without a map-key
placeholder since the field is a single optional value, not
map-keyed.

| key | value format | source | emission gate |
|---|---|---|---|
| `X-Ghars-Spec-Hash` | `sha256:<hex>` — computed by `spec_hash()` from canonical-JSON spec + `RENDERER_SCHEMA` | `EffectiveRunnerSpec.spec_hash` (populated by `compute::with_hash`, NOT operator-supplied — value flips on `RENDERER_SCHEMA` bumps) | always |
| `X-Ghars-Runner-Name` | identifier string | `EffectiveRunnerSpec.name` | always |
| `X-Ghars-Runner-Url` | URL string | `EffectiveRunnerSpec.url` | always |
| `X-Ghars-Auth-Name` | identifier string (`[auth.NAME]` key) | `EffectiveRunnerSpec.auth_name` | always |
| `X-Ghars-Labels` | comma-csv, sorted alphabetically; empty when no labels | `EffectiveRunnerSpec.labels` (sorted at emission) | always (empty when `labels` empty) |
| `X-Ghars-Arch` | enum `x86_64` \| `aarch64` | `EffectiveRunnerSpec.arch` (`config::Arch`) | always |
| `X-Ghars-Caches` | comma-csv of cache binding names, sorted alphabetically; empty when no caches | `EffectiveRunnerSpec.caches[].name` (sorted at emission) | always (empty when `caches` empty) |
| `X-Ghars-Config-Source` | path or identifier string | `EffectiveRunnerSpec.config_source` | always |
| `X-Ghars-Effective-Version` | version string (`2.319.1`) or empty when `runner_version` unset | `EffectiveRunnerSpec.runner_version` | always (empty when `None`) |
| `X-Ghars-Runner-Sha256` | sha256 hex (operator-supplied) | `EffectiveRunnerSpec.runner_sha256` | only when `Some(non-empty)` |
| `X-Ghars-Runner-Tarball-Hash` | `sha256:<hex>` — SHA256 of the tarball PATH string, not the file contents | `EffectiveRunnerSpec.runner_tarball` (path hashed at emission) | only when `runner_tarball.is_some()` |
| `X-Ghars-Trust-Zone` | identifier string | `EffectiveRunnerSpec.trust_zone` | always |
| `X-Ghars-Network-Mode` | enum `netns` \| `open` | `EffectiveRunnerSpec.network.spec.mode` (collapses `None` to `open`) | always |
| `X-Ghars-Netns-Subnet` | CIDR string (e.g. `10.200.0.0/30`) | `EffectiveRunnerSpec.network.subnet` | only when `network.is_some() && net.subnet.is_some()` (Netns mode) |
| `X-Ghars-Dns` | `forward` \| `static:<comma-csv-of-ip-addrs>` (via `config::dns_to_annotation`) | `EffectiveRunnerSpec.network.spec.dns` (`config::DnsMode`) | only when `network.is_some()` (both Netns and Open) |
| `X-Ghars-Ipv6` | enum `disabled` \| `enabled` (via `config::ipv6_to_annotation`) | `EffectiveRunnerSpec.network.spec.ipv6` (`config::Ipv6Mode`) | only when `network.is_some()` (both Netns and Open) |

Per-pool annotations emitted by `render_cache_drop_in` into the
cache pool unit's `00-ghars.conf` drop-in (`ghars-cache@POOL.service.d/`):

| key | value format | source | emission gate |
|---|---|---|---|
| `X-Ghars-Spec-Hash` | `sha256:<hex>` — cache pool's per-pool digest (`cache_pool_hash()` output, same format as runner's spec_hash) | populated by `into_cache_pool_plan` (computes `cache_pool_hash()` over canonical-JSON binding + `RENDERER_SCHEMA`, NOT operator-supplied — value flips on `RENDERER_SCHEMA` bumps) | always |
| `X-Ghars-Pool-Name` | identifier string | `EffectiveCacheBinding.name` | always |
| `X-Ghars-Pool-Kinds` | comma-csv of `ccache` / `sccache` enum names | `EffectiveCacheBinding.kinds` | always |
| `X-Ghars-Config-Source` | path or identifier string | `config_source` argument threaded from `into_cache_pool_plan` to `render_cache_drop_in` (matches per-runner X-Ghars-Config-Source for the same apply) | always |

Notes:

- All values pass `check_identity_field` at emission time as
  defense-in-depth against unit-text injection. The check rejects
  every `char::is_control()` character (covers `\n`, `\r`, `NUL`,
  and the broader Unicode control set per std's classification).
- Labels and caches are sorted alphabetically via `sort_unstable()`
  at the emission site as defense-in-depth on top of the upstream
  source-of-truth sort (`merge_defaults` for labels,
  `lower_to_effective` for caches). The parse boundary
  (`DiscoveredAnnotations::from_drop_in_body` in `plan/classify.rs`)
  re-sorts as a third defensive layer so any direct consumer of
  the parsed annotations gets canonical order.
- `X-Ghars-Network-Mode` is always emitted: the renderer collapses
  the no-binding case to `open` rather than omitting the key, so
  operators auditing `systemctl cat` always see the mode explicitly.
- `X-Ghars-Dns` and `X-Ghars-Ipv6` are emitted for every
  network-bound runner including Open mode, where the values are
  validator-fixed to `forward` / `disabled` per
  `validate_network_spec`. The uniform emission keeps the
  annotation surface consistent across modes for plan-time
  classification and `systemctl cat` audit.
- The runner-side `00-ghars.conf` body opens a single `[Unit]`
  section before the per-runner annotation cascade; no `X-Ghars-*`
  keys are emitted under `[Service]`. The pool-side `00-ghars.conf`
  body emits its four annotations in `[Unit]` then opens a
  `[Service]` for `User=ghars-tz-<TRUST_ZONE>` and the cache-kind
  `Environment=` directives — no further `X-Ghars-*` under
  `[Service]` there either.

The `99-*.conf` range is reserved for operator-supplied drop-ins
(NOT validated by ghars; the operator owns those). The
reset-on-empty validator (`systemd::validate_drop_in`) is invoked
on every body the renderer produces (`render_runner_unit` calls
it once per drop-in inside the emit loop, and
`render_cache_drop_in` calls it for the cache pool's
`00-ghars.conf`), so every managed drop-in across the runner
template (00..80) and the cache template's pool drop-in passes
the gate before bytes hit disk.

## Templates

Three canonical template units, written once and shared across
their instances:

- `ghars-runner@.service` (`runner_template_text`) — the runner
  unit. Per-runner variation in `ghars-runner@NAME.service.d/*.conf`.
- `ghars-cache@.service` (`cache_template_text`) — the cache
  service. Per-pool variation in
  `ghars-cache@POOL.service.d/00-ghars.conf`.
- `ghars-net@.service` (`netns_template_text`) — the netns +
  veth + nft setup. `Type=oneshot` with `RemainAfterExit=yes`;
  `ExecStart=` runs `ghars _netns-setup`, `nft -f` for both rule
  files; `ExecStop=` cleans up. The template is pulled in by
  netns-mode runners' `Requires=`; never enabled standalone.

## Versioned `bin.X.Y.Z/` and rollback

Inside each runner home (`runner_home(zone, name)`), tarball
extracts land in `bin.X.Y.Z/` (one per version installed).
`runsvc.sh` ships in the tarball at `bin.X.Y.Z/bin/runsvc.sh`
(upstream `Misc/layoutbin/` installs into `_layout/bin/`); the
systemd drop-in's `ExecStart=` invokes it from there directly:

```text
/var/lib/ghars/default/ghars-build-1/
├── bin.2.334.0/                 # current version's extracted tree
│   ├── config.sh
│   ├── bin/
│   │   ├── runsvc.sh            # ExecStart target
│   │   └── ...
│   └── ...
├── bin.2.333.1/                 # rollback target retained
└── ...                          # config.sh outputs (.runner, .credentials, etc.)
```

The `bin.X.Y.Z/` directory is published atomically via
`renameat2(RENAME_EXCHANGE)` swapping the freshly-extracted
staging dir with the live `bin.X.Y.Z/` (see
[Internals](./internals.md)). The staging dir lives at
`<state_dir>/.staging/<name>-<version>-<pid>/` and is GC'd by the
next apply if the install crashed past its own cleanup
(`gc_stale_staging_dirs`).

`Defaults.keep_versions` controls retention. The default
`DEFAULT_KEEP_VERSIONS = 2` keeps the just-installed bin tree plus
one rollback target. The pruner walks `bin.*` by mtime, keeps the
N most recent, removes the rest. Setting `keep_versions = 1`
disables rollback retention. `0` is silently clamped to `1` by
`plan::plan_from` (`.max(1)`) — the just-installed bin dir would
be pruned otherwise, so the lower bound is enforced at plan
time rather than at config-load.

## Lock and runtime files

`apply.lock` (`/run/ghars/apply.lock`) is the apply critical
section. POSIX advisory exclusive lock via
`fs2::FileExt::try_lock_exclusive`. Mode 0600 at create time. The
file body is the holding apply's PID; `acquire_lock` reads it on
contention and returns
`GharsError::ApplyLocked { pid, path, stale }` so the operator
sees which apply they're racing. `stale: true` indicates that the
recorded PID is no longer alive — the held lock is NOT
auto-reclaimed and the operator must `rm` the file manually.

Token drops at `<runtime_dir>/<NAME>.token` are short-lived
registration tokens consumed by `config.sh` during runner
registration. Mode 0600. Created and removed within a single
`execute_create_runner` invocation; never persisted across apply
runs. The `RegistrationToken` value is `zeroize`-on-drop so the
plaintext is scrubbed from heap memory after consumption (with
the `zeroize` crate's `derive` feature).

## Audit log

`apply.log` (`/var/log/ghars/apply.log`) is the SEC-36 structured
audit log: one JSON object per line, mode 0600, append-mode. Lock-
order ensures cross-run write ordering (apply.lock serializes
apply runs). Logging failures are best-effort and never fail the
apply. Full schema, the JSON example, and the recommended
logrotate config are documented in
[Operations](./operations.md#audit-log).

## nft rules and netns

Per-runner nft rule files under `<config_dir>/nft.d/`:

- `<name>-host.nft` — loaded into the host netns by
  `ghars-net@NAME.service` (binds to the host-side veth peer).
- `<name>-ns.nft` — loaded inside the per-runner netns by
  `ghars-net@NAME.service` (executed via the `_netns-veth` hidden
  subcommand).

The named netns at `/var/run/netns/ghars-NAME` is bind-mounted by
the netns unit; persistent across unit deactivation. Runner
restarts do NOT recreate the netns — only `RemoveRunner` (or
operator action) tears it down.

`<runtime_dir>/netns-resolv/<name>` is the generated
`resolv.conf` bind-mount source for the runner's netns (per
`DnsMode`). Static-mode lists explicit upstream nameservers;
forward-mode (default) uses the host's systemd-resolved via the
veth IP.

## What lives where

A condensed table of "I'm looking for X — where is it?":

| looking for                           | path                                                              |
|---------------------------------------|-------------------------------------------------------------------|
| the config file                       | `/etc/ghars/ghars.toml`                                           |
| a runner's home dir                   | `/var/lib/ghars/<TRUST_ZONE>/ghars-<NAME>/`                       |
| a runner's installed binary           | `/var/lib/ghars/<TRUST_ZONE>/ghars-<NAME>/bin.<VERSION>/`         |
| a runner's `runsvc.sh`                | `/var/lib/ghars/<TRUST_ZONE>/ghars-<NAME>/bin.<VERSION>/bin/runsvc.sh` |
| a runner's unit file (template)       | `/etc/systemd/system/ghars-runner@.service`                       |
| a runner's drop-ins                   | `/etc/systemd/system/ghars-runner@<NAME>.service.d/*.conf`        |
| a cache pool's storage                | `/var/cache/ghars/pools/<POOL>/`                                  |
| a cache pool's unit                   | `/etc/systemd/system/ghars-cache@<POOL>.service`                  |
| a cache pool's drop-ins               | `/etc/systemd/system/ghars-cache@<POOL>.service.d/*.conf`         |
| the apply lock                        | `/run/ghars/apply.lock`                                           |
| the audit log                         | `/var/log/ghars/apply.log`                                        |
| nft rules for runner X                | `/etc/ghars/nft.d/<NAME>-host.nft`, `/etc/ghars/nft.d/<NAME>-ns.nft` |
| the netns                             | `/var/run/netns/ghars-<NAME>`                                     |
| systemd-resolved drop-in              | `/etc/systemd/resolved.conf.d/ghars-<NAME>.conf`                  |
