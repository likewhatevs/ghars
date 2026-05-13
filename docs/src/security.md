# Security

ghars's security envelope rests on three pillars: **DynamicUser
isolation**, **trust zones**, and **systemd sandbox hardening**.
Each is enforced at multiple layers; failure of one layer does not
collapse the whole envelope.

## DynamicUser isolation

The runner template (`ghars-runner@.service`) sets `DynamicUser=yes`
(`man systemd.exec.5`, since systemd 232). At unit start, systemd
allocates a transient UID/GID from its reserved range and recycles
it on stop. Nothing is written to `/etc/passwd` or `/etc/group`.

The per-runner `00-ghars.conf` drop-in sets `User=ghars-tz-<TRUST_ZONE>`
— NOT a per-runner name. Runners that share a `trust_zone` get the
same DynamicUser-allocated UID. That UID-sharing is what makes the
shared HOME / ccache / sccache reach work without `gpasswd` or
`SupplementaryGroups=`.

Cross-trust-zone reach is denied at the UID-DAC layer:

- Different UIDs return EACCES on shared paths.
- Different UIDs return EACCES at `connect()` to the sccache UDS
  (the socket inode is mode 0600 owned by the cache-server's
  trust-zone UID; AF_UNIX `connect()` checks owner-DAC).

There is no `Group=` line, no `SupplementaryGroups=`, no `gpasswd`
involvement. systemd allocates the matching transient GID alongside
the UID.

## Trust zones

A trust zone is the unit of cross-runner isolation. Runners and
cache pools both carry a `trust_zone` field (default `"default"`,
configurable per-block). The validator enforces:

- Every runner referencing a cache pool must have the same
  `trust_zone` as the pool.
- Cross-zone references reject at config load.

The shared HOME for a trust zone is `/var/lib/ghars/<TRUST_ZONE>/`
(see `Paths::trust_zone_home`). Each runner gets its own subdir
`/var/lib/ghars/<TRUST_ZONE>/ghars-<NAME>/` for its config.sh
output (`.runner`, `.credentials`, etc.) and one or more
versioned `bin.X.Y.Z/` directories. The upstream actions/runner
tarball ships `runsvc.sh` at `bin.X.Y.Z/bin/runsvc.sh`, not in
the runner home itself. Within a zone, runners can read each
other's state via DAC; across zones, the kernel returns EACCES.

Operators who don't care about cross-repo poisoning leave the field
unset — every runner and pool stays in `"default"`. The capability
remains available for deployments that need it (the SEC-03 fix).

## Systemd sandbox hardening

The runner template (`runner_template_text()` in `systemd/units.rs`)
emits these directives unconditionally:

- `NoNewPrivileges=yes`
- `CapabilityBoundingSet=` (empty — `ExecStart` does no
  setuid/setgid step; `DynamicUser=` handles identity)
- `AmbientCapabilities=` (empty — kernel raises nothing into
  permitted at exec)
- `TemporaryFileSystem=/:ro` — root is a tmpfs, read-only.
- `BindReadOnlyPaths=` — narrow allowlist of `/usr`, `/lib`,
  `/lib64`, `/bin`, `/sbin`, plus `/etc/hosts`, `/etc/passwd`,
  `/etc/group`, `/etc/ssl`, `/etc/ca-certificates`, etc.
- `PrivateTmp=yes`
- `UMask=0077` — restrictive default mode for any file the
  runner creates (inherited across exec to the workflow process).
  The same `UMask=0077` on the **cache template**
  (`ghars-cache@.service`) is also the kernel-enforced gate on the
  sccache UDS: AF_UNIX `bind()` masks the socket inode mode by
  `current_umask()` at `vfs_mknod` time
  (Linux `net/unix/af_unix.c:unix_bind_bsd`). With `UMask=0077`
  the resulting UDS lands at mode 0600 with no TOCTOU window
  between `bind()` and a chmod shim. sccache's `UnixListener::bind`
  performs no chmod after bind, so the kernel-applied mode is
  final.
- `PrivateDevices=yes` + `DevicePolicy=closed` +
  `DeviceAllow=/dev/kvm rw` (re-add for KVM-backed workloads;
  override via `hardening.kvm = false` to drop).
- `ProtectProc=invisible`
- `ProtectKernelTunables=yes`
- `ProtectKernelModules=yes`
- `ProtectKernelLogs=yes`
- `ProtectControlGroups=no` (intentional — workflows create
  cpuset/memory cgroups for nested virt and VM test harnesses;
  `yes` would break those flows. Override via
  `hardening.protect_control_groups = true` on hosts that don't
  need it).
- `ProtectClock=yes`
- `ProtectHostname=yes`
- `LockPersonality=yes`
- `RestrictNamespaces=yes`
- `PrivateIPC=yes`
- `ProtectHome=yes`
- `RemoveIPC=yes`
- `RestrictRealtime=no` (intentional — KVM vCPU/watchdog threads
  need `SCHED_FIFO`. `LimitRTPRIO=2` caps the priority they can
  request).
- `RestrictSUIDSGID=yes`
- `LimitMEMLOCK=infinity` — required for KVM/buck2 mlock on
  large guest pages.
- `LimitRTPRIO=2`
- `SystemCallArchitectures=native`
- `SystemCallFilter=@system-service pkey_alloc pkey_mprotect pkey_free perf_event_open`
- `SystemCallErrorNumber=EPERM`
- `SystemCallFilter=~@mount @clock @keyring @module @raw-io @reboot @swap @obsolete`
- `SystemCallLog=~@system-service pkey_alloc pkey_mprotect pkey_free perf_event_open`

The `SystemCallFilter` ordering is load-bearing per
`systemd.exec(5)`:

1. The first line WITHOUT `~` establishes the positive allowlist
   (`@system-service` ∪ `{pkey_alloc, pkey_mprotect, pkey_free,
   perf_event_open}`). The unit enters allowlist mode; only
   listed syscalls execute, everything else returns EPERM.
2. The subsequent line WITH `~` SUBTRACTS those groups from the
   allowlist (per `systemd.exec.xml`: when the filter is already
   in allowlist mode, `~`-prefixed assignments subtract).

Net result: `((@system-service ∪ {pkey_*, perf_event_open}) −
{@mount ∪ @clock ∪ @keyring ∪ @module ∪ @raw-io ∪ @reboot ∪ @swap
∪ @obsolete})` is allowed; everything else returns EPERM. The
denylist line is belt-and-suspenders against systemd version drift
in the `@system-service` composition.

Swapping the two lines would defeat the denylist: a `~`-line
emitted before the positive allowlist would attempt to remove from
a not-yet-established set (no-op), then the positive line would
re-include those groups.

## Network namespace mode (fail-closed)

When a runner sets `network = "name"` and `[network.NAME].mode =
"netns"`, the rendered `40-network.conf` drop-in sets:

```text
NetworkNamespacePath=/var/run/netns/ghars-NAME
```

`NetworkNamespacePath=` fails closed: when the namespace is
missing, the unit fails to start. Distinct from
`PrivateNetwork=yes`, which silently falls back to the host netns
when `CONFIG_NET_NS` or `CAP_NET_ADMIN` is unavailable on the
host.

`apply::verify_runner_netns` does a post-start check: `readlink
/proc/PID/ns/net` must differ from `readlink /proc/1/ns/net` when
the spec configured a netns. If they match, the runner has fallen
back to the host netns and the action aborts with
`GharsError::Apply`.

The companion `ghars-net@.service` template owns the netns
creation:

- `ExecStart=+/usr/bin/ghars _netns-setup %i` (`+` runs as root
  regardless of `User=`).
- `ExecStart=+/usr/sbin/nft -f /etc/ghars/nft.d/%i-host.nft`
- `ExecStart=+/usr/bin/ghars _netns-veth %i /usr/sbin/nft -f /etc/ghars/nft.d/%i-ns.nft`

The netns at `/var/run/netns/ghars-%i` is bind-mounted (persistent
across unit deactivation). `StopWhenUnneeded=no` keeps the
ghars-net unit active to symbolize "netns exists"; only torn down
by explicit `ghars apply` removal.

Egress is enforced at two layers:

- **nftables** rules generated from
  `[network.NAME].allowed_egress` (host-side veth and inside the
  namespace).
- **systemd cgroup-BPF** via `IPAddressAllow=` /
  `IPAddressDeny=` from `[network.NAME].ip_allow` /
  `ip_deny`.

Both layers run independently; defense in depth.

## Open mode with cgroup-BPF policy

`[network.NAME] mode = "open"` keeps the runner in the host
netns (no per-runner namespace, no veth, no nft rules) but still
honors the cgroup-BPF directives from the same `[network.NAME]`
block:

- `ip_allow` / `ip_deny` populate `IPAddressAllow=` /
  `IPAddressDeny=` on the runner unit.
- `restrict_address_families` populates `RestrictAddressFamilies=`.

These run at the cgroup layer regardless of namespace; the
runner's traffic is still subject to the cgroup-BPF egress
filter on the host's netns. Use this when the operator wants
defense-in-depth IP/family restrictions but cannot afford the
netns/veth setup (older kernels without `CONFIG_NET_NS`,
operator policy that requires host-routed connectivity, etc.).
The `40-network.conf` drop-in emitted in this mode carries ONLY
the cgroup-BPF directives — no `NetworkNamespacePath=`, no
`Requires=ghars-net@`, and no nft rule files are generated.

## TOCTOU-safe file ops

Every operator-supplied path that reaches a privileged operation
goes through one of these gates:

- `O_NOFOLLOW` at the open site — kernel rejects symlinks at
  `open(2)` time, no lstat-then-open race. Used for
  `runner_tarball`, hook scripts, and the GitHub App
  `private_key_path` PEM. `O_NONBLOCK` is also set to prevent fifo
  hangs (`open_no_follow_with_meta` in `validators.rs`).
- `renameat2` with `RENAME_EXCHANGE` for atomic publish — see
  [Internals](./internals.md#renameat2-atomicity).
- `fsync` after rename to ensure durability across crash — see
  [Internals](./internals.md#fsync-durability).

## SEC-* model

The codebase tracks security concerns under stable SEC-* labels in
doc comments and commit messages. Every label maps to a specific
attack surface and the gate that closes it. Operators reading the
source for review will see references like SEC-03 (trust zones),
SEC-09 (root-owned runner home), SEC-10 (tar safe-member filter),
SEC-12 (hooks ownership), SEC-19 (apply.lock PID liveness), SEC-25
(token_file mode), SEC-30 (egress comment sanitization), SEC-33
(root-owned staging), SEC-36 (apply audit log).

The labels are stable identifiers: a code reader who finds
SEC-09 in a comment can grep the codebase for every other site
that participates in that gate.

## Audit log

Every action taken by `apply` is appended to
`<logs_dir>/apply.log` as one JSON object per line. The file is
mode 0600 / `O_APPEND`; logging failures are best-effort and never
invert a successful action's outcome. The `outcome` field passes
through `escape_control_chars` before write to keep terminal-
manipulation bytes from `GharsError::to_string()` output out of the
audit consumer's input. Full schema and the recommended logrotate
config are documented in
[Operations](./operations.md#audit-log).

## What ghars does NOT defend against

- **Kernel exploits.** A kernel zero-day that breaks the seccomp /
  cgroup / netns isolation is out of scope.
- **Compromised systemd.** ghars trusts the systemd D-Bus
  endpoint. A compromised PID 1 sees all of the host.
- **Workflow code itself.** Once a runner is registered, the
  GitHub Actions runner binary executes whatever the workflow
  YAML demands. ghars hardens the surface the workflow runs on;
  it does not validate the workflow content.
- **Network adversaries inside `allowed_egress`.** If the
  operator allows egress to a host, and that host turns hostile,
  ghars cannot help. The trust boundary is the configured
  `allowed_egress` set.

The full design intent is in the source comments at the SEC-*
sites. Reviewers should read those rather than infer from this
overview.
