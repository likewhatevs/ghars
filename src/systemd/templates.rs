//! Canonical systemd unit-file template bodies (Part 9). Pure data
//! split off from `units.rs` to keep the renderer file focused on
//! render logic. Each `*_template_text()` function returns the same
//! bytes every time; the templates are verbatim from Part 9 of the
//! design spec.

// --- Runner template body (Part 9) ---------------------------------------

/// Canonical `ghars-runner@.service` template body. Pure function:
/// returns the same bytes every time. The body is verbatim from Part 9.
#[must_use]
pub fn runner_template_text() -> String {
    // The template is intentionally large + comment-heavy per Part 9;
    // we emit it as a raw string so the bytes round-trip exactly.
    RUNNER_TEMPLATE.to_string()
}

const RUNNER_TEMPLATE: &str = r"[Unit]
Description=GitHub Actions Runner (%i)
After=network-online.target
Wants=network-online.target
# ConditionPathExists is set in the per-runner 00-ghars.conf drop-in
# (e.g. `/var/lib/ghars/<TRUST_ZONE>/ghars-<NAME>/runsvc.sh`) because
# the path components depend on the runner's trust_zone, which the
# template-level `%i` specifier cannot express on its own.
StartLimitIntervalSec=300
StartLimitBurst=5
X-Ghars-Managed=true
X-Ghars-Schema-Version=1

[Service]
Type=simple
# DynamicUser=yes (man systemd.exec.5, since v232) allocates the
# runner unit a transient UID/GID from systemd's reserved range on
# unit start and recycles it on unit stop — nothing is written to
# /etc/passwd or /etc/group. The User= name is set by the per-runner
# 00-ghars.conf drop-in to `ghars-tz-<TRUST_ZONE>`, NOT to a per-
# runner name: runners that share a `trust_zone` get the SAME
# DynamicUser-allocated UID, and that UID-sharing is what makes the
# shared HOME / ccache / sccache reach work without gpasswd or
# SupplementaryGroups. Cross-trust-zone reach is denied at the
# UID-DAC layer (different UIDs → EACCES on shared paths and on the
# sccache UDS). No `Group=` line — DynamicUser allocates the matching
# transient GID alongside the UID.
#
# ExecStart= is set in the per-runner 00-ghars.conf drop-in. The
# template cannot express it because the path includes the trust_zone
# and the resolved runner version (bin.X.Y.Z), neither of which the
# template-level `%i` specifier can produce. The drop-in resets the
# (absent) template ExecStart with an empty assignment and then sets
# the absolute path to the tarball's runsvc.sh under the versioned
# bin dir.
DynamicUser=yes
# WorkingDirectory + StateDirectory + HOME and the per-runner cache
# env vars are set in the per-runner 00-ghars.conf drop-in. The
# template-level `%i` specifier expands to the runner-name only, so
# it cannot express the trust_zone-shared layout
# (`/var/lib/ghars/<TRUST_ZONE>/ghars-<NAME>/`) that the apply-side
# binds the runner home to.
# Slice=system.slice unconditional. No operator opt-in.
Slice=system.slice

# CacheDirectory + LogsDirectory + RuntimeDirectory still use the
# per-runner `%i` form because they are NOT trust_zone-shared (per
# Part 3 / Part 9). Each runner gets its own per-runner cache /
# log / runtime subtree under systemd's standard roots.
CacheDirectory=ghars/%i
CacheDirectoryMode=0700
LogsDirectory=ghars/%i
LogsDirectoryMode=0700
RuntimeDirectory=ghars/%i
RuntimeDirectoryMode=0700

# PATH set explicitly. systemd's compile-time DEFAULT_PATH varies and
# may omit sbin. ccache wrapper dirs come first to shadow real
# compilers.
Environment=PATH=/usr/lib64/ccache:/usr/lib/ccache:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=LANG=C.UTF-8

# Per-runner cache env. Shared cache pools override these via
# 30-cache-pool.conf drop-in.
Environment=CCACHE_DIR=%C/ghars/%i/ccache
Environment=SCCACHE_DIR=%C/ghars/%i/sccache
Environment=CCACHE_MAXSIZE=200G
Environment=SCCACHE_CACHE_SIZE=200G
# SCCACHE_SERVER_UDS lives on tmpfs (RuntimeDirectory) — no stale
# sockets after crash.
Environment=SCCACHE_SERVER_UDS=%t/ghars/%i/sccache.sock

KillMode=control-group
KillSignal=SIGTERM
TimeoutStopSec=5min

# Privilege isolation. CapabilityBoundingSet is empty: ExecStart does
# not setuid/setgid (DynamicUser= handles the identity), so no
# CAP_SETUID/CAP_SETGID are needed; runsvc.sh is a script with no file
# capabilities, so per capabilities(7) its post-exec permitted set is
# empty regardless. AmbientCapabilities stays empty so the kernel
# does not raise any cap into permitted at exec time.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=

# Filesystem allowlist. Optional paths use `-` prefix for merged-usr
# compat.
TemporaryFileSystem=/:ro
BindReadOnlyPaths=/usr /bin /sbin -/lib -/lib64
BindReadOnlyPaths=/etc/hosts /etc/nsswitch.conf
BindReadOnlyPaths=/etc/passwd /etc/group
BindReadOnlyPaths=-/etc/ssl -/etc/ca-certificates -/etc/pki
BindReadOnlyPaths=-/etc/locale.conf /etc/localtime
BindReadOnlyPaths=/etc/ld.so.cache -/etc/ld.so.conf.d
BindReadOnlyPaths=-/etc/protocols -/etc/services
BindReadOnlyPaths=-/etc/alternatives
BindReadOnlyPaths=-/etc/os-release
BindReadOnlyPaths=-/etc/gitconfig
PrivateTmp=yes
UMask=0077

# Device access. PrivateDevices=yes constructs a clean /dev;
# DevicePolicy=closed denies everything; DeviceAllow re-adds /dev/kvm
# for KVM-backed workloads.
PrivateDevices=yes
DevicePolicy=closed
DeviceAllow=/dev/kvm rw
BindPaths=/dev/kvm

ProtectProc=invisible

# Kernel hardening.
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
# ProtectControlGroups=no is INTENTIONAL: workflows create
# cpuset/memory cgroups on the host (buck2 nested virt, VM test
# harnesses). yes here would make /sys/fs/cgroup read-only and break
# those flows.
ProtectControlGroups=no
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes

# Syscall filtering. @system-service is the baseline allowlist; pkey_*
# and perf_event_open are extras needed by Node, .NET, and KVM
# workloads.
#
# Ordering invariant per systemd.exec(5):
# - The first SystemCallFilter= line WITHOUT `~` prefix establishes
#   the positive allowlist ((@system-service) ∪ extras). The unit
#   enters allowlist mode; only listed syscalls execute, everything
#   else returns EPERM (per SystemCallErrorNumber= below).
# - The subsequent SystemCallFilter=~... line REMOVES those groups
#   from the running allowlist (per systemd.exec.xml: when the
#   filter is already in allowlist mode, ~-prefixed assignments
#   subtract from the allowlist).
# Net result: ((@system-service ∪ {pkey_alloc, pkey_mprotect,
# pkey_free, perf_event_open}) − {@mount ∪ @clock ∪ @keyring ∪
# @module ∪ @raw-io ∪ @reboot ∪ @swap ∪ @obsolete}) is allowed; all
# other syscalls EPERM. The denylist line is belt-and-suspenders
# (modern @system-service already excludes those groups), guarding
# against systemd version drift in the @system-service composition.
# DO NOT swap the two lines: a `~`-line emitted before the positive
# allowlist line would attempt to remove from a not-yet-established
# set (no-op), and the subsequent positive line would re-include
# those groups, defeating the denylist.
SystemCallArchitectures=native
SystemCallFilter=@system-service pkey_alloc pkey_mprotect pkey_free perf_event_open
SystemCallErrorNumber=EPERM
SystemCallFilter=~@mount @clock @keyring @module @raw-io @reboot @swap @obsolete
SystemCallLog=~@system-service pkey_alloc pkey_mprotect pkey_free perf_event_open

RestrictNamespaces=yes
PrivateIPC=yes

ProtectHome=yes
RemoveIPC=yes
# RestrictRealtime=no is INTENTIONAL: KVM vCPU/watchdog threads need
# SCHED_FIFO for stable guest latency. LimitRTPRIO=2 caps the
# priority they can request.
RestrictRealtime=no
RestrictSUIDSGID=yes

# LimitMEMLOCK=infinity required for KVM/buck2 mlock on large guest
# pages.
LimitMEMLOCK=infinity
LimitRTPRIO=2

LogRateLimitIntervalSec=30s
LogRateLimitBurst=10000

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
";

// --- ghars-net@.service template (Part 9c) -------------------------------

/// Canonical `ghars-net@.service` template body (oneshot, persistent
/// netns, fail-closed via `NetworkNamespacePath=` on the runner side).
#[must_use]
pub fn netns_template_text() -> String {
    NETNS_TEMPLATE.to_string()
}

const NETNS_TEMPLATE: &str = r#"[Unit]
Description=ghars netns + veth + nft for runner %i
X-Ghars-Managed=true
X-Ghars-Schema-Version=1
# StopWhenUnneeded=NO. The named netns at /var/run/netns/ghars-%i
# is bind-mounted (persistent across unit deactivation). ghars-net@
# stays in active state to symbolize "netns exists"; only torn down by
# explicit `ghars apply` removal of the runner. Runner restarts do NOT
# recreate the netns — the bind-mount survives.
StopWhenUnneeded=no
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes

# systemd does NOT consult Environment=PATH= when resolving bare
# ExecStart= names: systemd-executor calls
# `find_executable_full(name, root=NULL, exec_search_path,
# use_path_envvar=false, ...)` from
# systemd/src/core/exec-invoke.c (the `false` is fixed at the call
# site), which falls back to `default_PATH()` (the systemd
# compile-time default — `/usr/local/sbin:/usr/local/bin:/usr/sbin:
# /usr/bin` and split-bin variants per
# systemd/src/basic/path-util.{c,h}). Bare `ghars` and `nft` resolve
# via that compile-time default — `cargo install` lands ghars at
# /usr/local/bin/ghars, distro packaging at /usr/bin/ghars, and nft
# at /usr/sbin/nft (split) or /usr/bin/nft (merged); all are
# covered by every default_PATH() variant.
#
# Environment=PATH= IS load-bearing for the `nft` argv handed to
# `ghars _netns-veth`: `ip netns exec` (invoked internally — see
# src/netns.rs::run_in_netns) execvp's the program inside the
# netns'd child, and execvp DOES consult $PATH. The Environment=
# value here is the systemd unit env that the spawned ghars process
# inherits and forwards to that execvp, so bare `nft` in the argv
# resolves the same way bare ExecStart names do.
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# `+` prefix runs as root regardless of User= (per systemd.exec.xml).
# Required for: ip netns add, ip link, sysctl writes, nft -f.
ExecStart=+ghars _netns-setup %i
ExecStart=+nft -f /etc/ghars/nft.d/%i-host.nft
ExecStart=+ghars _netns-veth %i nft -f /etc/ghars/nft.d/%i-ns.nft

# LOAD-BEARING: ExecStop= MUST be present. systemd destroys runtime
# data on SERVICE_EXITED when no ExecStop=, ExecReload=, or
# ExecStopPost= is defined — even with RemainAfterExit=yes. The named
# netns is its own bind-mount so we don't rely on systemd's runtime
# data, but having ExecStop= ensures cleanup helpers run on unit
# deactivation.
ExecStop=+nft destroy table inet ghars_%i
ExecStop=+ghars _netns-veth %i nft destroy table inet ghars_%i_ns
ExecStop=+ghars _netns-teardown %i

User=root
Slice=system.slice
KillMode=control-group
TimeoutSec=30s

[Install]
# Pulled in by runner units' Requires=; never enabled standalone.
"#;

// --- ghars-cache@.service template (Part 9b) -----------------------------

/// Canonical `ghars-cache@.service` template body. Per-pool drop-ins
/// (rendered separately via `render_cache_drop_in`) provide
/// `ExecStart=` + cache-specific `Environment=` entries.
#[must_use]
pub fn cache_template_text() -> String {
    CACHE_TEMPLATE.to_string()
}

const CACHE_TEMPLATE: &str = r"[Unit]
Description=ghars cache service for pool %i (ccache + sccache)
After=network.target
X-Ghars-Managed=true
X-Ghars-Schema-Version=1
# StopWhenUnneeded keeps the unit alive only when at least one runner
# unit Requires= it (per-runner 30-cache-pool.conf adds Requires=).
StopWhenUnneeded=yes

[Service]
Type=simple
# DynamicUser=yes allocates the cache server a transient UID/GID from
# the systemd-allocated range (man systemd.exec.5, since v232) on unit
# start and recycles it on stop — nothing is written to /etc/passwd or
# /etc/group. The User= name is set by the per-pool 00-ghars.conf
# drop-in to `ghars-tz-<TRUST_ZONE>`, NOT to a per-pool name: the
# cache server must share its UID with the runners in the same
# trust_zone so the UDS at `/run/ghars/cache-<pool>.sock` (mode 0600
# owner=ghars-tz-<TRUST_ZONE>) is reachable from those runners by
# owner-DAC. Runners reach the socket via `BindPaths=` in their own
# drop-in; cross-trust-zone reach is denied at the AF_UNIX connect()
# layer because the connecting UID does not match the socket inode
# owner. No `Group=` line, no SupplementaryGroups, no gpasswd.
DynamicUser=yes
Slice=system.slice

# UMask=0077 is the kernel-enforced sccache UDS permission gate.
# AF_UNIX bind() masks the socket inode mode by current_umask() at
# vfs_mknod time (Linux net/unix/af_unix.c:unix_bind_bsd:1349 —
# `umode_t mode = S_IFSOCK | (SOCK_INODE(sk->sk_socket)->i_mode & ~current_umask())`).
# sccache's UnixListener::bind (sccache server.rs:511 +
# commands.rs:104) performs no chmod after bind, so the kernel-applied
# mode is final. With UMask=0077 the resulting UDS inode mode is 0600
# — owner rw, group/others denied. The cache server runs at the same
# DynamicUser-allocated UID as the runners in its trust_zone (set via
# the 00-ghars.conf drop-in's `User=ghars-tz-<TRUST_ZONE>`), so a
# runner inside the same trust_zone connects by owner-DAC. Runners in
# different trust_zones run at different UIDs and get EACCES at
# connect() — no shared group is involved. UMask= closes the mode at
# bind() time atomically (no TOCTOU window between bind() and a chmod
# shim).
UMask=0077

# CacheDirectory creates /var/cache/ghars/pools/%i with mode 0750.
# Owner is the cache server's DynamicUser-allocated UID
# (ghars-tz-<TRUST_ZONE>). Runners in the same trust_zone share that
# UID, so they traverse via owner-DAC; runners in other trust_zones
# run at a different UID and get EACCES — group bits are unused
# because no shared group exists in this model.
CacheDirectory=ghars/pools/%i
CacheDirectoryMode=0750
# RuntimeDirectory=/run/ghars/ holds the per-pool sccache UDS
# (`cache-<pool>.sock`). Mode 0700 owner=ghars-tz-<TRUST_ZONE>: only
# the trust_zone's UID can resolve the directory at the host layer.
# Runners reach the UDS through `BindPaths=` (systemd as root
# performs the bind into the runner sandbox) — sandbox delivery does
# not require runner-side traversal of the host /run/ghars/ entry.
RuntimeDirectory=ghars
RuntimeDirectoryMode=0700
# HOME is required by sccache (dirs::config_dir() panics without it).
# DynamicUser + ProtectHome=yes leaves HOME unset; point it at the
# cache directory so sccache's config lookup succeeds.
Environment=HOME=%C/ghars/pools/%i

# Per-kinds env + ExecStart land in the per-pool 00-ghars.conf drop-in
# (sccache server launches there when kinds includes sccache;
# ccache-only pools render ExecStart=<sleep_path> infinity to keep
# the unit active so its CacheDirectory stays mounted). Both
# binary paths are resolved at plan time — either pinned via
# [cache_pools.NAME].sccache_path / sleep_path or auto-detected
# from a canonical search list per binary:
#   sccache: /usr/local/bin/sccache then /usr/bin/sccache
#   sleep:   /usr/bin/sleep        then /bin/sleep

KillMode=control-group
KillSignal=SIGTERM
TimeoutStopSec=30s

# Hardening — narrower than runner. No /dev/kvm, no realtime, no exec.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateDevices=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectHome=yes
ProtectSystem=strict
RemoveIPC=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallFilter=~@mount @clock @keyring @module @raw-io @reboot @swap @obsolete

# Restart on crash (sccache server crashes are recoverable; clients
# reconnect).
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
";
