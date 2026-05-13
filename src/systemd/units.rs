//! Unit-text and drop-in generation for systemd unit files.
//!
//! Splits from the (previously monolithic) `systemd.rs` module:
//! - Static template bodies: `runner_template_text`,
//!   `netns_template_text`, `cache_template_text`.
//! - Per-runner drop-in renderer: [`render_runner_unit`] +
//!   [`RenderedUnit`].
//! - Per-pool cache drop-in renderer: [`render_cache_drop_in`].
//! - Defense-in-depth identity field validator:
//!   [`check_identity_field`].
//! - Internal `HardeningProfile` and `render_*` helpers
//!   (memory, hardening, `cache_pool`, `resolv_bind`, network, numa,
//!   proxy, hooks, lognamespace).
//!
//! All renderers are pure functions: no D-Bus, no filesystem.

use std::collections::BTreeMap;
use std::fmt::Write;

use crate::config::{
    CacheKind, EffectiveCacheBinding, EffectiveRunnerSpec, EtcBindStyle, Hardening, NetworkMode,
};
use crate::{GharsError, Result};

use super::dbus::validate_drop_in;

// --- Hardening profile ---------------------------------------------------

/// Hardening defaults — match the Python tool's profile (see Part 9,
/// the doc-comments on `Hardening` in `config.rs`). `None` on a
/// `Hardening` field means "inherit"; the renderer translates each
/// option to a concrete bool / list at render time.
//
// One bool per systemd directive is the natural shape — bitflags would
// obscure the per-directive label. Pedantic clippy suggests refactoring
// >3 bools; here the labels are load-bearing for readability.
#[allow(clippy::struct_excessive_bools)]
struct HardeningProfile {
    kvm: bool,
    restrict_realtime: bool,
    protect_control_groups: bool,
    restrict_suid_sgid: bool,
    private_devices: bool,
    private_ipc: bool,
}

impl HardeningProfile {
    fn from(h: &Hardening) -> Self {
        Self {
            kvm: h.kvm.unwrap_or(true),
            restrict_realtime: h.restrict_realtime.unwrap_or(false),
            protect_control_groups: h.protect_control_groups.unwrap_or(false),
            restrict_suid_sgid: h.restrict_suid_sgid.unwrap_or(true),
            private_devices: h.private_devices.unwrap_or(true),
            private_ipc: h.private_ipc.unwrap_or(true),
        }
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

// --- Rendered output ----------------------------------------------------

/// Result of `render_runner_unit`: the canonical template body plus
/// the per-instance drop-ins keyed by basename (e.g.
/// `00-ghars.conf`), plus any warnings the renderer wants to surface
/// to the operator (rendered into plan output).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenderedUnit {
    /// Canonical template body — installed once at
    /// `/etc/systemd/system/ghars-runner@.service`.
    pub template: String,
    /// Drop-in basename → contents. Installed under the per-instance
    /// drop-in directory (`ghars-runner@NAME.service.d/`).
    pub drop_ins: BTreeMap<String, String>,
    /// Body of the runner's `.env` file (`<bin_dir>/.env`).
    /// `Runner.Listener::LoadAndSetEnv` reads this ONCE at runner-process
    /// start and sets each `KEY=VALUE` via
    /// `Environment.SetEnvironmentVariable`; worker / workflow-step
    /// subprocesses inherit through fork+exec. Distinct from systemd
    /// `Environment=` directives, which bind to the systemd unit
    /// process and are inherited the same way once
    /// Runner.Listener spawns — `.env` keys ride a separate
    /// LoadAndSetEnv pathway.
    pub env_file: String,
    /// Body of the runner's `.path` file (`<bin_dir>/.path`).
    /// `runsvc.sh` runs `export PATH=\`cat .path\`` ONCE at script
    /// start; inherited across exec by every subprocess. Single line,
    /// newline-terminated.
    pub path_file: String,
    /// Render-time advisories surfaced to the plan engine. The plan
    /// engine concatenates these into `Plan.warnings` so apply prints
    /// them before executing. Examples: "kvm=false drops /dev/kvm rw
    /// — workflows that need KVM will fail".
    pub warnings: Vec<String>,
}

/// Monotonic schema number for the renderer output surface. Bumped
/// when any byte of any drop-in, template, env_file, or path_file
/// emitted by `render_*` could change across upgrades for the same
/// `EffectiveRunnerSpec` input — even if the operator's TOML is
/// byte-identical.
///
/// Fed into `spec_hash` and `cache_pool_hash` via dedicated
/// `renderer_schema` fields on `EffectiveRunnerSpec` and
/// `EffectiveCacheBinding` so the on-disk `X-Ghars-Spec-Hash`
/// annotation captures the schema. A ghars binary upgrade that
/// changes renderer behavior MUST bump this number; otherwise plan
/// emits NoOp on every runner and operators must `rm -rf` drop-in
/// dirs to force convergence (the bug this constant exists to
/// prevent).
///
/// Cosmetic refactors (comment edits, internal helper renames,
/// formatting) do NOT bump this number — only behavior changes that
/// would alter the bytes a downstream consumer (systemd, runsvc.sh,
/// Runner.Listener) reads from the rendered files.
///
/// Decision rule for contributors: if your change requires re-
/// accepting any `.snap` under `tests/snapshots/python_parity_unit_*`
/// AND the byte change reflects observable systemd / runner behavior
/// (not pure formatting or comment shuffling), bump this constant.
/// If unsure, bump — false positives (an unnecessary bump) cost one
/// cycle of in-place rewrites per managed runner on the next apply;
/// false negatives (a missed bump) leave operators stranded on stale
/// drop-ins requiring manual `rm -rf` to force convergence (the bug
/// this constant exists to prevent).
pub const RENDERER_SCHEMA: u32 = 3;

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

// --- Runner unit + drop-ins renderer (Part 9 / 9d / 9e) ------------------

/// Render the canonical runner unit template + all applicable
/// drop-ins for an effective runner spec.
///
/// Drop-ins emitted (ranges per Part 9):
/// - `00-ghars.conf` — identity annotations (always)
/// - `10-memory.conf` — `MemoryMax=` (when set)
/// - `15-resolv.conf` — `/etc/resolv.conf` bind source (always; switches
///   between host's resolv.conf and the netns-private file in
///   `/run/ghars/netns-resolv/<name>` based on the runner's network mode)
/// - `20-hardening.conf` — per-field hardening overrides
/// - `30-cache-pool.conf` — ccache/sccache pool bindings (when caches non-empty)
/// - `40-network.conf` — netns binding + cgroup-BPF directives in
///   Netns mode; cgroup-BPF directives only (no `NetworkNamespacePath=`,
///   no `Requires=ghars-net@`) in Open mode when any of
///   `ip_allow` / `ip_deny` / `restrict_address_families` is
///   non-empty; skipped entirely when Open mode has none of those
///   set
/// - `50-numa.conf` — `AllowedCPUs=` / `AllowedMemoryNodes=` (when set)
/// - `60-proxy.conf` — proxy env + CA-trust env (when proxy resolved)
/// - `70-hooks.conf` — pre/post-job hook env + `BindReadOnlyPaths` (when hooks resolved)
/// - `80-lognamespace.conf` — `LogNamespace=ghars-NAME` (always)
///
/// # Errors
///
/// Returns `GharsError::Validation` when:
/// - `render_identity` (via [`check_identity_field`]) finds a `\n`,
///   `\r`, `\0`, or other control character in any interpolated
///   X-Ghars-* field — defense-in-depth against unit-text injection.
///   The error message names the offending field and the
///   character class.
/// - The reset-on-empty validator finds any generated drop-in body
///   about to emit a list-typed directive with a bare `=`. Such an
///   output is a generator bug; the validator is a safety net.
pub fn render_runner_unit(spec: &EffectiveRunnerSpec) -> Result<RenderedUnit> {
    let mut drop_ins: BTreeMap<String, String> = BTreeMap::new();
    let mut warnings: Vec<String> = Vec::new();

    drop_ins.insert("00-ghars.conf".into(), render_identity(spec)?);

    if let Some(body) = render_memory(spec)? {
        drop_ins.insert("10-memory.conf".into(), body);
    }

    // 15-resolv.conf — always present. Binds /etc/resolv.conf into the
    // runner's mount namespace from the right source for the runner's
    // network mode. Open mode binds the host's /etc/resolv.conf; Netns
    // mode binds /run/ghars/netns-resolv/<name> (written by
    // `_netns-setup` from the operator's DnsMode). The template's
    // BindReadOnlyPaths intentionally OMITS /etc/resolv.conf because
    // systemd's mount-list dedup keeps the FIRST same-destination entry
    // (per src/core/namespace.c:drop_duplicates), so a drop-in cannot
    // override the template's source. Splitting it out into its own
    // drop-in is the only correct way to swap sources per runner.
    drop_ins.insert("15-resolv.conf".into(), render_resolv_bind(spec));

    if let Some(body) = render_hardening(spec, &mut warnings)? {
        drop_ins.insert("20-hardening.conf".into(), body);
    }

    if let Some(body) = render_cache_pool(spec)? {
        drop_ins.insert("30-cache-pool.conf".into(), body);
    }

    if let Some(body) = render_network(spec)? {
        drop_ins.insert("40-network.conf".into(), body);
    }

    if let Some(body) = render_numa(spec)? {
        drop_ins.insert("50-numa.conf".into(), body);
    }

    if let Some(body) = render_proxy(spec)? {
        drop_ins.insert("60-proxy.conf".into(), body);
    }

    if let Some(body) = render_hooks(spec)? {
        drop_ins.insert("70-hooks.conf".into(), body);
    }

    drop_ins.insert("80-lognamespace.conf".into(), render_lognamespace(spec));

    // Reset-on-empty validator — applied to EVERY generated drop-in.
    for (name, body) in &drop_ins {
        validate_drop_in(name, body)?;
    }

    let env_file = render_runner_env_file(spec)?;
    let path_file = render_runner_path_file(spec)?;
    Ok(RenderedUnit {
        template: runner_template_text(),
        drop_ins,
        env_file,
        path_file,
        warnings,
    })
}

/// Body of the runner's `.env` file. actions/runner's
/// `Runner.Listener` calls `LoadAndSetEnv` ONCE at process start
/// (`src/Runner.Listener/Program.cs` Main), reads `.env`, and sets each
/// `KEY=VALUE` into the process environment via
/// `Environment.SetEnvironmentVariable`. Worker processes that
/// `Runner.Listener` forks inherit those env vars across exec, so
/// workflow steps see them.
///
/// Distinct from the systemd `Environment=` directives in
/// `00-ghars.conf` / `30-cache-pool.conf`: those bind to the systemd
/// unit's process tree and are present in the runner process's
/// environment when `Runner.Listener` starts. `.env` adds the env vars
/// that need to land specifically in workflow steps via
/// `LoadAndSetEnv`'s explicit propagation path (some keys, like
/// `CCACHE_DIR`, ride both layers for redundancy). The runner unit's
/// next stop+start picks up `.env` changes — see
/// `render_identity` (LAYER 1) and this function (LAYER 2).
///
/// Output is deterministic: framework lines are fixed-order
/// (LANG → trust_zone-derived → per-cache loop). The per-cache loop
/// iterates `spec.caches` in source order; `lower_to_effective` sorts
/// `caches` by name before the spec reaches this renderer, so two
/// runners with the same caches produce byte-identical `.env` content.
#[must_use]
pub(crate) fn render_runner_env_file(spec: &EffectiveRunnerSpec) -> Result<String> {
    let check = |field: &str, value: &str| -> Result<()> {
        check_identity_field(field, value)
            .map_err(|e| crate::error::prepend_validation_scope("render_runner_env_file", e))
    };
    check("trust_zone", &spec.trust_zone)?;
    for binding in &spec.caches {
        check("caches[].name", &binding.name)?;
        check("caches[].size", &binding.size)?;
    }

    let mut s = String::new();
    s.push_str("LANG=C.UTF-8\n");
    // CCACHE_DIR is gated on the runner having at least one ccache-
    // kind binding. The .ccache dir at this path is created in
    // execute_create_runner ONLY when the same binding gate is
    // satisfied (see src/apply/runners.rs has_ccache check). The
    // two must stay symmetric: if the runner has no ccache binding,
    // the dir is not created AND the env var is not emitted. Otherwise
    // the unconditional ccache wrappers in PATH (units.rs PATH file)
    // would intercept `gcc` / `cc` calls and try to write to a non-
    // existent dir whose parent (/var/lib/ghars/<TRUST_ZONE>/) is
    // 0o711 root-owned — the DynamicUser worker cannot mkdir it,
    // ccache falls back to its XDG default (HOME/.ccache) which lands
    // in runner_home (per-runner, owned by the DynamicUser, mode
    // 0o777 at runtime). Per-runner ephemeral cache is correct for
    // no-ccache-binding runners; trust-zone-shared cache is the
    // operator opt-in via [[runner]].caches.
    let has_ccache = spec
        .caches
        .iter()
        .any(|b| b.kinds.contains(&CacheKind::Ccache));
    if has_ccache {
        let _ = writeln!(s, "CCACHE_DIR=/var/lib/ghars/{}/.ccache", spec.trust_zone);
    }
    let _ = writeln!(s, "KTSTR_LOCK_DIR=/var/lib/ghars/{}/.ktstr", spec.trust_zone);
    let _ = writeln!(s, "KTSTR_CACHE_DIR=/var/lib/ghars/{}/.ktstr", spec.trust_zone);
    for binding in &spec.caches {
        if binding.kinds.contains(&CacheKind::Ccache) {
            let _ = writeln!(s, "CCACHE_MAXSIZE={}", binding.size);
        }
        if binding.kinds.contains(&CacheKind::Sccache) {
            let _ = writeln!(
                s,
                "SCCACHE_SERVER_UDS=/run/ghars/cache-{}.sock",
                binding.name
            );
            s.push_str("SCCACHE_NO_DAEMON=1\n");
            let _ = writeln!(s, "SCCACHE_CACHE_SIZE={}", binding.size);
            let _ = writeln!(
                s,
                "SCCACHE_DIR=/var/cache/ghars/pools/{}/sccache",
                binding.name
            );
        }
    }
    // LAYER 3: operator-declared env vars (BTreeMap alphabetical
    // iteration → deterministic .env bytes regardless of operator's
    // TOML key order). Appended AFTER framework keys so existing
    // runners with empty `[runner.environment].vars` produce
    // byte-identical .env (no spurious in-place rewrite on the #7
    // deploy). Operator keys colliding with framework keys are
    // rejected at config-load via the deny-list in
    // crate::validators::validate_environment_spec, so values
    // reaching here are validation-clean.
    //
    // Defense-in-depth re-validation: check the value via
    // check_identity_field at render time too — config-load is the
    // primary gate but direct construct sites (test fixtures) might
    // bypass the load path.
    for (key, value) in &spec.environment.vars {
        check("environment.vars[].key", key)?;
        check("environment.vars[].value", value)?;
        let _ = writeln!(s, "{key}={value}");
    }
    Ok(s)
}

/// Body of the runner's `.path` file. `runsvc.sh` runs at runner-
/// process start (the unit's `ExecStart=`) and executes
/// `export PATH=\`cat .path\`` once per process — `Runner.Listener`
/// and every worker process inherit this PATH. Subsequent runs of
/// upstream `env.sh` (only invoked at runner re-config time, not at
/// every job) would `echo $PATH >.path` and overwrite this file with
/// the runner process's `$PATH`, which would NOT include the ccache
/// wrappers or `.cargo/bin`. ghars writes this file pre-emptively so
/// workflow steps get the correct PATH from the first job onwards.
///
/// The framework prefix `/usr/lib64/ccache:/usr/lib/ccache` must come
/// FIRST so that bare `gcc` / `cc` invocations resolve to the ccache
/// wrappers (otherwise ccache misses 100% of compile calls). The
/// per-runner `.cargo/bin` segment is included so cargo-installed
/// binaries land on PATH for workflow steps. System path tail comes
/// last in the standard sbin-before-bin order.
#[must_use]
pub(crate) fn render_runner_path_file(spec: &EffectiveRunnerSpec) -> Result<String> {
    let check = |field: &str, value: &str| -> Result<()> {
        check_identity_field(field, value)
            .map_err(|e| crate::error::prepend_validation_scope("render_runner_path_file", e))
    };
    check("trust_zone", &spec.trust_zone)?;
    check("name", &spec.name)?;
    for p in &spec.environment.path_prepend {
        check("environment.path_prepend[]", p.as_str())?;
    }
    for p in &spec.environment.path_append {
        check("environment.path_append[]", p.as_str())?;
    }
    Ok(format!(
        "{path}\n",
        path = compose_runner_path(spec)
    ))
}

/// Compose the runner's PATH string from framework segments and
/// operator additions. OPTION C layering:
///   ccache_wrappers → operator path_prepend → .cargo/bin →
///   system_tail → operator path_append
/// ccache wrappers stay at position 0 unconditionally — operator
/// path_prepend cannot shadow `gcc` / `cc` and break the compile
/// cache (which would miss 100% if ccache wrappers were not first
/// in PATH). Shared between `render_runner_path_file` and
/// `render_identity`'s `Environment=PATH=` line so both sites emit
/// the identical PATH string (eliminates the LAYER 1/2 PATH drift
/// class).
pub(crate) fn compose_runner_path(spec: &EffectiveRunnerSpec) -> String {
    let mut segments: Vec<String> = Vec::with_capacity(
        2 + spec.environment.path_prepend.len() + 1 + 6 + spec.environment.path_append.len(),
    );
    // ccache wrappers ALWAYS first.
    segments.push("/usr/lib64/ccache".into());
    segments.push("/usr/lib/ccache".into());
    // Operator path_prepend lands BETWEEN ccache and .cargo/bin so
    // operator paths cannot shadow the ccache wrappers.
    for p in &spec.environment.path_prepend {
        segments.push(p.as_str().into());
    }
    // Per-runner .cargo/bin.
    segments.push(format!(
        "/var/lib/ghars/{tz}/ghars-{name}/.cargo/bin",
        tz = spec.trust_zone,
        name = spec.name
    ));
    // System tail (sbin-before-bin order).
    segments.push("/usr/local/sbin".into());
    segments.push("/usr/local/bin".into());
    segments.push("/usr/sbin".into());
    segments.push("/usr/bin".into());
    segments.push("/sbin".into());
    segments.push("/bin".into());
    // Operator path_append lands AFTER system tail (typical
    // "fallback paths" semantics).
    for p in &spec.environment.path_append {
        segments.push(p.as_str().into());
    }
    segments.join(":")
}

/// Defense-in-depth: reject any value about to be interpolated
/// into a `00-ghars.conf` line that contains characters which would
/// break out of the `Key=Value` boundary or corrupt the systemd unit
/// parser. `\n` / `\r` would inject a new directive line; `\0` is a
/// shell / parser hazard; other control chars produce undefined
/// behavior in the X-Ghars-* annotation parser at
/// `state::extract_x_ghars`.
///
/// Called from many render and validation sites (none privileged):
/// - The `render_*` helpers in this file (memory, hardening, cache,
///   network, numa, proxy, hooks, identity) gate every interpolated
///   field before bytes hit disk.
/// - `cli::validate_identity_fields` — config-load gate so the
///   operator sees the offending block name (`runner "NAME"` /
///   `cache_pool "NAME"`) before the planner runs.
/// - `plan::plan_from` — defense-in-depth on the synthesized
///   `config_source` value.
///
/// The error message itself is bare (no caller-site prefix). The
/// `render_identity` caller (this file, just below) wraps with
/// `"render_identity:"` so plan-time render errors name the
/// rejecting function. The cli.rs caller wraps with the offending
/// block name (`runner "NAME":` / `cache_pool "NAME":`); the
/// plan.rs caller propagates the bare error (`config_source` is
/// composed from `paths.config_dir`, no operator-meaningful scope to
/// prepend). Hardcoding `"render_identity:"` here would mislead
/// operators when the rejection actually fires at config-load time.
pub(crate) fn check_identity_field(field: &str, value: &str) -> Result<()> {
    if let Some(bad) = value
        .chars()
        .find(|c| *c == '\n' || *c == '\r' || *c == '\0' || c.is_control())
    {
        let class = if bad == '\n' {
            "newline"
        } else if bad == '\r' {
            "carriage return"
        } else if bad == '\0' {
            "NUL byte"
        } else {
            "control character"
        };
        return Err(GharsError::Validation(
            format!(
                "field {field:?} contains forbidden {class}; \
                 X-Ghars-* annotations must be single-line, control-free"
            ),
            "fix the offending value upstream (likely a config edit added \
             a stray newline or terminal escape)"
                .into(),
        ));
    }
    Ok(())
}

fn render_identity(spec: &EffectiveRunnerSpec) -> Result<String> {
    // Validate every interpolated field BEFORE writing — fail-fast
    // before the bytes touch the BTreeMap so an upstream caller's
    // re-render yields the same error each time and never produces
    // a partially-written buffer.
    //
    // `check` wraps `check_identity_field` so the resulting Validation
    // error names "render_identity" as the rejecting site.
    // `cli::validate_identity_fields` adds its own block-scoped
    // prepend (`runner "NAME":` / `cache_pool "NAME":`); `plan::plan_from`
    // propagates the bare error. By emitting the bare form from
    // `check_identity_field` itself, stderr only says "render_identity"
    // when the rejection actually fires here at plan-render time.
    let check = |field: &str, value: &str| -> Result<()> {
        check_identity_field(field, value)
            .map_err(|e| crate::error::prepend_validation_scope("render_identity", e))
    };
    check("spec_hash", &spec.spec_hash)?;
    check("name", &spec.name)?;
    check("url", &spec.url)?;
    check("auth_name", &spec.auth_name)?;
    for label in &spec.labels {
        check("labels[]", label)?;
    }
    for binding in &spec.caches {
        check("caches[].name", &binding.name)?;
    }
    check("config_source", &spec.config_source)?;
    if let Some(v) = spec.runner_version.as_deref() {
        check("runner_version", v)?;
    }
    if let Some(sha) = spec.runner_sha256.as_deref() {
        check("runner_sha256", sha)?;
    }
    // runner_tarball is hashed (sha256 of the path string) before
    // emission, so the rendered value cannot contain control chars.
    // The path string itself never appears in the unit. No check
    // needed here.
    check("trust_zone", &spec.trust_zone)?;

    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = writeln!(s, "X-Ghars-Spec-Hash={}", spec.spec_hash);
    let _ = writeln!(s, "X-Ghars-Runner-Name={}", spec.name);
    let _ = writeln!(s, "X-Ghars-Runner-Url={}", spec.url);
    let _ = writeln!(s, "X-Ghars-Auth-Name={}", spec.auth_name);
    // Emit Labels and Arch as annotations so the plan engine can
    // reconstruct the recreate-bound subset of an already-applied
    // EffectiveRunnerSpec from the on-disk unit text. Without these,
    // a labels-only or arch-only edit falls through to the
    // `uncovered` in-place arm in `plan_from` — the apply path
    // would still rewrite the runner unit on the spec_hash diff,
    // but it would do so without the typed recreate reason that
    // GitHub-side registration needs (labels/arch are bound to the
    // registration token), so the runner would land in production
    // with the OLD label/arch metadata still active on GitHub's
    // side. Stage 1 detection on these annotations is what flips
    // the change to a true recreate so the runner re-registers.
    // Comma-joined labels mirrors the existing X-Ghars-Caches format.
    //
    // Labels arrive pre-sorted by `merge_defaults` (set semantics —
    // GitHub matches workflow `runs-on:` against the registered label
    // set order-independently). The defensive sort here mirrors the
    // caches comment below: any future caller that builds an
    // `EffectiveRunnerSpec` directly bypasses `merge_defaults`'s
    // sort, so re-sorting at the emission site keeps the on-disk
    // `X-Ghars-Labels=` annotation canonical regardless. Without
    // this, an unsorted-Vec direct-construct caller would emit a
    // non-canonical annotation and the plan classifier's sorted
    // comparison would silently mask the divergence.
    let mut label_names: Vec<&str> = spec.labels.iter().map(String::as_str).collect();
    label_names.sort_unstable();
    let _ = writeln!(s, "X-Ghars-Labels={}", label_names.join(","));
    let arch_str = match spec.arch {
        crate::config::Arch::X86_64 => "x86_64",
        crate::config::Arch::Aarch64 => "aarch64",
    };
    let _ = writeln!(s, "X-Ghars-Arch={arch_str}");
    // emit X-Ghars-Caches unconditionally (matches the X-Ghars-Labels
    // pattern at render_identity above) so the planner can detect
    // caches-list shrinks. Without an unconditional emit, a runner
    // whose caches list goes from `["a"]` → `[]` would have no
    // on-disk record of the prior membership, so the in-place path
    // could not compute a set diff against `DiscoveredAnnotations`
    // to detect the removed cache. Empty value is parsed as
    // `Some(vec![])` by the classifier (see DiscoveredAnnotations
    // labels handling).
    //
    // caches arrive pre-sorted by lower_to_effective. The defensive
    // sort here mirrors the labels emission above: any future caller
    // that builds an `EffectiveRunnerSpec` directly bypasses
    // `lower_to_effective`'s sort, so re-sorting at the emission site
    // keeps the on-disk `X-Ghars-Caches=` annotation canonical
    // regardless. Without this, an unsorted-Vec direct-construct
    // caller would emit a non-canonical annotation and the plan
    // classifier's sorted comparison would silently mask the
    // divergence.
    let mut cache_names: Vec<&str> = spec.caches.iter().map(|c| c.name.as_str()).collect();
    cache_names.sort_unstable();
    let _ = writeln!(s, "X-Ghars-Caches={}", cache_names.join(","));
    let _ = writeln!(s, "X-Ghars-Config-Source={}", spec.config_source);
    // runner_version is filled by the plan pipeline before APPLY-time
    // re-render (lower_to_effective rejects tarball+no-version; the
    // intersection arm fills in-place candidates from the discovered
    // X-Ghars-Effective-Version annotation; resolve_plan_releases
    // fills CreateRunner + recreate UpdateRunner from the release-API
    // lookup before execute_create_runner re-renders). At PLAN time,
    // however, render_runner_unit is called via into_runner_plan
    // BEFORE resolve_plan_releases runs, so runner_version may still
    // be None for "implicit-latest" CreateRunner previews. Emit an
    // empty rvalue rather than fail — the operator-facing
    // `ghars plan --diff` shows the placeholder, and the apply path
    // re-renders with the resolved version before writing to disk.
    // The discovered annotation can be a Some("") for runners that
    // were originally applied with the implicit-latest pattern; the
    // intersection-arm fill skips empty values, leaving them to
    // re-resolve via the apply-time path.
    let _ = writeln!(
        s,
        "X-Ghars-Effective-Version={}",
        spec.runner_version.as_deref().unwrap_or("")
    );
    // runner_sha256 is operator-supplied SHA256 of the runner
    // tarball — recreate-class. Emitted only when set so a missing
    // line means "operator did not pin a digest" (resolves through
    // the releases API). An empty `=` would conflate "operator
    // explicitly cleared the pin" with "field never set" at parse
    // time. Emit nothing when None; the classifier treats absence as
    // "skip this field" not "differs from empty".
    if let Some(sha) = spec.runner_sha256.as_deref()
        && !sha.is_empty()
    {
        let _ = writeln!(s, "X-Ghars-Runner-Sha256={sha}");
    }
    // runner_tarball is an operator-supplied local path to a
    // pre-downloaded tarball. The PATH itself leaks operator
    // environment (mount points, usernames, kernel-private dirs) so
    // we emit a SHA256 of the path string instead. The hash is
    // sufficient for change detection — a change to the tarball
    // path produces a new hash, even though the operator's path is
    // never persisted in the on-disk artifact. No emission when
    // None (same rationale as runner_sha256 above).
    if let Some(tarball) = spec.runner_tarball.as_deref() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(tarball.as_str().as_bytes());
        let _ = writeln!(
            s,
            "X-Ghars-Runner-Tarball-Hash=sha256:{}",
            hex::encode(h.finalize())
        );
    }
    // trust_zone is in EffectiveRunnerSpec spec_hash but has
    // no runner-unit body dependency once cache-pool cross-references
    // validate. Annotated so the classifier can detect an isolated
    // trust_zone change as in-place (FieldChange but no recreate
    // reason — see plan.rs::classify_recreate_reasons_from_annotations).
    let _ = writeln!(s, "X-Ghars-Trust-Zone={}", spec.trust_zone);
    // network mode (open|netns). Recreate-class — see
    // classifier. Emitted unconditionally; "open" is the canonical
    // string for "no [network] block referenced or NetworkMode::Open".
    let net_mode = match spec.network.as_ref().map(|n| &n.spec.mode) {
        Some(crate::config::NetworkMode::Netns) => "netns",
        Some(crate::config::NetworkMode::Open) | None => "open",
    };
    let _ = writeln!(s, "X-Ghars-Network-Mode={net_mode}");
    // X-Ghars-Netns-Subnet is Netns-only (the documented
    // "filesystem-layout" annotation table flags it that way). The
    // binding's `subnet` field is `Some` exactly when
    // `lower_to_effective` allocated a /30, which it does only for
    // Netns mode — so gating on `subnet.is_some()` is equivalent to
    // gating on `mode == Netns`, expressed as a presence check
    // against the field that actually carries the value.
    if let Some(net) = &spec.network
        && let Some(subnet) = net.subnet
    {
        let _ = writeln!(s, "X-Ghars-Netns-Subnet={subnet}");
    }
    // [Service] is always emitted: User=ghars-tz-<TRUST_ZONE> binds
    // the runner unit to the trust_zone's DynamicUser allocation
    // (template body declares DynamicUser=yes; this drop-in pins the
    // name so runners with the same trust_zone share the transient
    // UID/GID systemd allocates per User= name).
    s.push('\n');
    s.push_str("[Service]\n");
    let _ = writeln!(s, "User=ghars-tz-{}", spec.trust_zone);
    // WorkingDirectory + HOME stamp the per-runner home. ghars creates
    // and manages the runner home during apply. StateDirectory= is NOT
    // used because DynamicUser=yes on systemd < 256 tries to create a
    // private dir + symlink at the runner home path, which conflicts
    // with the regular directory ghars already created. The full
    // sandbox (TemporaryFileSystem, BindReadOnlyPaths, DynamicUser)
    // still applies -- only the auto-chown is lost.
    // BindPaths= makes the runner home writable inside the sandbox.
    let _ = writeln!(
        s,
        "BindPaths=/var/lib/ghars/{}",
        spec.trust_zone
    );
    // WorkingDirectory points at the versioned bin dir so the runner
    // finds ./externals/, ./bin/Runner.Listener, etc. relative to cwd.
    // `version` falls back to "latest" when runner_version is None.
    // The bytes on disk are pinned for the CreateRunner and
    // recreate-class UpdateRunner paths (resolve_plan_releases fills
    // runner_version BEFORE execute_create_runner re-renders).
    // The in-place UpdateRunner arm has a different ordering: the
    // intersection-arm fill at compute.rs tries to inherit
    // runner_version from the discovered X-Ghars-Effective-Version
    // annotation, but if that annotation is absent/empty/invalid,
    // the candidate stays None — plan-time-rendered drop-ins (with
    // literal "latest" in WorkingDirectory) get written to disk via
    // read_then_write_if_changed BEFORE the .env/.path rewrite at
    // runners.rs:646 hard-errors. Task #57 tracks moving that
    // hard-error to plan time so the write-then-error ordering
    // closes; until then, the legacy-edge case lands broken-from-
    // birth bytes before failing the apply.
    let version = spec.runner_version.as_deref().unwrap_or("latest");
    let _ = writeln!(
        s,
        "WorkingDirectory=/var/lib/ghars/{}/ghars-{}/bin.{}",
        spec.trust_zone, spec.name, version
    );
    // ExecStart reset-then-set: the template intentionally omits
    // ExecStart= because the path includes the runner version (only
    // known at apply time after install). The empty assignment clears
    // any inherited ExecStart= (defense in depth — the template
    // currently has none, but operators may add one via 99-*.conf);
    // the second line provides the canonical absolute path to the
    // tarball's runsvc.sh under the versioned bin dir's `bin/`
    // subdir. Upstream layout: actions/runner's `Misc/layoutbin/`
    // files install into `_layout/bin/` per the project's build
    // target (`<Copy SourceFiles="@(LayoutBinFiles)"
    // DestinationFolder=".../_layout/bin/..."/>`), so the published
    // tarball ships runsvc.sh at `bin.X.Y.Z/bin/runsvc.sh`, NOT at
    // `bin.X.Y.Z/runsvc.sh`.
    let _ = writeln!(s, "ExecStart=");
    let _ = writeln!(
        s,
        "ExecStart=/bin/bash /var/lib/ghars/{}/ghars-{}/bin.{}/bin/runsvc.sh",
        spec.trust_zone, spec.name, version
    );
    let _ = writeln!(
        s,
        "Environment=HOME=/var/lib/ghars/{}/ghars-{}",
        spec.trust_zone, spec.name
    );
    // Shared with render_runner_path_file via compose_runner_path so
    // Site B (Environment=PATH= here) and Site A (.path file) emit
    // the identical PATH string — eliminates the LAYER 1/2 PATH-drift
    // class. Operator environment.path_prepend / path_append land in
    // the composed string per OPTION C.
    let _ = writeln!(s, "Environment=PATH={}", compose_runner_path(spec));
    // TMPDIR under the runner home so the sccache server (separate unit
    // with its own PrivateTmp) can hash input files. Without this, cargo
    // builds in /tmp which is private to the runner unit and invisible
    // to ghars-cache@.service.
    let _ = writeln!(
        s,
        "Environment=TMPDIR=/var/lib/ghars/{}/ghars-{}/tmp",
        spec.trust_zone, spec.name
    );
    let _ = writeln!(
        s,
        "Environment=KTSTR_LOCK_DIR=/var/lib/ghars/{}/.ktstr",
        spec.trust_zone
    );
    let _ = writeln!(
        s,
        "Environment=KTSTR_CACHE_DIR=/var/lib/ghars/{}/.ktstr",
        spec.trust_zone
    );
    // LAYER 3 (Site B): operator-declared env vars appended after
    // framework Environment= directives. Same BTreeMap iteration as
    // render_runner_env_file (Site A) — operator's MY_VAR lands in
    // BOTH 00-ghars.conf (here) and .env (Site A) per the api-reviewer
    // HARD REQ: a future renderer refactor that drops one layer would
    // re-create the LAYER 1/2 drift class #24 fixed for built-ins.
    //
    // %-escape: operator values containing `%` must be emitted as
    // `%%` here because systemd parses %-specifiers in Environment=
    // values (per `systemd.exec(5)`). Site A (.env) carries the same
    // operator value VERBATIM because Runner.Listener's LoadAndSetEnv
    // (.NET) does not interpret `%`. Escape-on-Site-B + verbatim-on-
    // Site-A yields IDENTICAL effective values seen by both consumers
    // (operator's literal value preserved end-to-end).
    //
    // Defense-in-depth re-validation: check the value via
    // check_identity_field at render time too — config-load is the
    // primary gate but direct construct sites (test fixtures) might
    // bypass the load path.
    for (key, value) in &spec.environment.vars {
        check_identity_field("environment.vars[].key", key)?;
        check_identity_field("environment.vars[].value", value)?;
        let escaped = value.replace('%', "%%");
        let _ = writeln!(s, "Environment={key}={escaped}");
    }
    // ConditionPathExists is a [Unit]-section directive; emit a
    // separate [Unit] section AFTER [Service] (drop-in sections can
    // appear in any order — systemd merges by section name). The path
    // mirrors the ExecStart= target above — the tarball's runsvc.sh
    // at `bin.X.Y.Z/bin/runsvc.sh` (upstream `Misc/layoutbin/`
    // installs into `_layout/bin/`).
    s.push_str("\n[Unit]\n");
    let _ = writeln!(
        s,
        "ConditionPathExists=/var/lib/ghars/{}/ghars-{}/bin.{}/bin/runsvc.sh",
        spec.trust_zone, spec.name, version
    );
    Ok(s)
}

fn render_memory(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(m) = spec.memory_max.as_deref() else {
        return Ok(None);
    };
    if m.is_empty() {
        return Ok(None);
    }
    // Defense-in-depth: `memory_max` is an operator-supplied free-
    // form String (config.rs `EffectiveRunnerSpec.memory_max:
    // Option<String>`) interpolated directly into `MemoryMax=`. A
    // newline would inject a new directive line; NUL/control chars would
    // corrupt the systemd unit parser the same way the
    // `check_identity_field` gate already prevents in `render_identity`.
    check_identity_field("memory_max", m)?;
    let mut s = String::new();
    s.push_str("[Service]\n");
    let _ = writeln!(s, "MemoryMax={m}");
    Ok(Some(s))
}

fn render_hardening(
    spec: &EffectiveRunnerSpec,
    warnings: &mut Vec<String>,
) -> Result<Option<String>> {
    let h = &spec.hardening;
    let profile = HardeningProfile::from(h);

    // Defense-in-depth: every operator-supplied string about to
    // be interpolated into a 20-hardening.conf body must clear
    // check_identity_field BEFORE any bytes are written. The
    // hardening profile lets the operator append entries to systemd
    // list-typed directives (RestrictAddressFamilies, SystemCallFilter
    // → extra_syscalls, CapabilityBoundingSet → extra_capabilities,
    // BindReadOnlyPaths → bind_readonly_paths + extra_bind_paths); a
    // newline anywhere in those values would inject a new directive
    // line at unit-load time. Validating at the top of the renderer
    // means a malformed entry produces an Err instead of bytes.
    for entry in &h.restrict_address_families {
        check_identity_field("restrict_address_families[]", entry)?;
    }
    for entry in &h.extra_syscalls {
        check_identity_field("extra_syscalls[]", entry)?;
    }
    for entry in &h.extra_capabilities {
        check_identity_field("extra_capabilities[]", entry)?;
    }
    if let Some(paths) = &h.bind_readonly_paths {
        for p in paths {
            check_identity_field("bind_readonly_paths[]", p.as_str())?;
        }
    }
    for p in &h.extra_bind_paths {
        check_identity_field("extra_bind_paths[]", p.as_str())?;
    }

    // Determine if any directive needs to be emitted. The template
    // already contains the canonical defaults; we only emit a drop-in
    // when at least one overridable field is touched OR the operator
    // bumped extra_syscalls / extra_capabilities / extra_bind_paths /
    // bind_readonly_paths / restrict_address_families.
    let touches_scalar = h.kvm.is_some()
        || h.restrict_realtime.is_some()
        || h.protect_control_groups.is_some()
        || h.restrict_suid_sgid.is_some()
        || h.private_devices.is_some()
        || h.private_ipc.is_some();
    let has_lists = !h.restrict_address_families.is_empty()
        || !h.extra_syscalls.is_empty()
        || !h.extra_capabilities.is_empty()
        || !h.extra_bind_paths.is_empty()
        || h.bind_readonly_paths.is_some();
    let has_etc_override = h.etc_bind_style != EtcBindStyle::default();
    if !touches_scalar && !has_lists && !has_etc_override {
        return Ok(None);
    }

    let mut s = String::new();
    s.push_str("[Service]\n");

    if h.kvm.is_some() {
        // The runner template grants `DeviceAllow=/dev/kvm rw`. systemd
        // treats `DeviceAllow` as list-typed and the only way to revoke
        // a template-level grant from a drop-in is the empty-reset
        // pattern (a drop-in cannot subtract a specific entry). When
        // the operator opts out of KVM via `hardening.kvm = false` we
        // emit `DeviceAllow=` and follow it with no further entries —
        // the resulting set is empty, combined with the template's
        // `DevicePolicy=closed` this denies all device access.
        //
        // The reset-on-empty validator treats `DeviceAllow`
        // INTENTIONALLY as not-protected (see RESET_ON_EMPTY_DIRECTIVES
        // doc-comment) precisely so this branch can land. The other
        // directives in that list have multi-entry templates where an
        // empty reset would silently disable hardening; `DeviceAllow`
        // has a single template entry and revoking it is the operator's
        // documented intent.
        if profile.kvm {
            s.push_str("DeviceAllow=/dev/kvm rw\n");
        } else {
            s.push_str("DeviceAllow=\n");
            warnings.push(format!(
                "runner {name}: hardening.kvm=false drops DeviceAllow=/dev/kvm rw; \
                workflows that need KVM access (nested virtualization, KVM-based \
                test harnesses) will fail",
                name = spec.name
            ));
        }
    }
    if h.restrict_realtime.is_some() {
        let _ = writeln!(s, "RestrictRealtime={}", yes_no(profile.restrict_realtime));
    }
    if h.protect_control_groups.is_some() {
        let _ = writeln!(
            s,
            "ProtectControlGroups={}",
            yes_no(profile.protect_control_groups)
        );
    }
    if h.restrict_suid_sgid.is_some() {
        let _ = writeln!(s, "RestrictSUIDSGID={}", yes_no(profile.restrict_suid_sgid));
    }
    if h.private_devices.is_some() {
        let _ = writeln!(s, "PrivateDevices={}", yes_no(profile.private_devices));
    }
    if h.private_ipc.is_some() {
        let _ = writeln!(s, "PrivateIPC={}", yes_no(profile.private_ipc));
    }

    if !h.restrict_address_families.is_empty() {
        let _ = writeln!(
            s,
            "RestrictAddressFamilies={}",
            h.restrict_address_families.join(" ")
        );
    }

    if !h.extra_syscalls.is_empty() {
        // Append-style — systemd treats consecutive SystemCallFilter=
        // lines as union, so adding new tokens through a drop-in
        // grows the allowlist instead of replacing it.
        let _ = writeln!(s, "SystemCallFilter={}", h.extra_syscalls.join(" "));
    }

    if !h.extra_capabilities.is_empty() {
        // Same union semantics for CapabilityBoundingSet=. The runner
        // template (`runner_template_text`) sets the base bounding
        // set to empty (no CAP_SETUID/CAP_SETGID — DynamicUser=
        // handles privilege identity, no setuid syscall); appending
        // caps here UNIONS with that empty base — the operator's
        // tokens become the runner's full bounding set. Operators who
        // want a strictly-empty bounding set leave `extra_capabilities`
        // empty and the template's empty value stands.
        //
        // Canonicalization is upstream: this renderer emits whatever
        // is in `h.extra_capabilities` verbatim, including duplicates
        // and operator-supplied order. `plan::merge_hardening` is
        // responsible for sorting AND deduping the merged Vec before
        // the renderer sees it so a pure reorder or accidental
        // dup in TOML does not perturb the rendered drop-in body or
        // the spec_hash. The same upstream contract applies to
        // `extra_syscalls` (SystemCallFilter= line above) and
        // `restrict_address_families` (RestrictAddressFamilies=).
        let _ = writeln!(
            s,
            "CapabilityBoundingSet={}",
            h.extra_capabilities.join(" ")
        );
    }

    // BindReadOnlyPaths handling. systemd.exec(5)
    // documents BindReadOnlyPaths as a list-typed directive: each
    // assignment APPENDS to the cumulative list, and only the
    // empty-reset form (`BindReadOnlyPaths=`) clears it. Both
    // bind_readonly_paths and extra_bind_paths therefore APPEND to the
    // template's accumulated list — neither replaces it. The
    // reset-on-empty validator (the `RESET_ON_EMPTY_DIRECTIVES`
    // list) forbids a managed drop-in from emitting the bare-`=`
    // reset form, so this generator only ever appends. Operators
    // who want to *narrow* the bind-readonly set must use a
    // 99-*.conf operator drop-in (which the validator does NOT
    // police).
    if let Some(paths) = &h.bind_readonly_paths
        && !paths.is_empty()
    {
        // Emit the operator's chosen entries on one
        // BindReadOnlyPaths= line. Multiple assignments would
        // also append; one line is the deterministic form. The
        // generator's branch above filters out the empty case,
        // so the reset-on-empty rule is never violated here.
        let joined = paths
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(s, "BindReadOnlyPaths={joined}");
    }
    if !h.extra_bind_paths.is_empty() {
        let joined = h
            .extra_bind_paths
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(s, "BindReadOnlyPaths={joined}");
    }

    if h.etc_bind_style == EtcBindStyle::Broad {
        // Broad: bind whole /etc. Append; the template's curated /etc
        // entries remain (BindReadOnlyPaths is list-typed; appending
        // /etc widens coverage without resetting).
        s.push_str("BindReadOnlyPaths=/etc\n");
    }

    Ok(Some(s))
}

fn render_cache_pool(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    if spec.caches.is_empty() {
        return Ok(None);
    }
    // Defense-in-depth: `binding.size` is an operator-supplied
    // free-form String (config.rs `EffectiveCacheBinding.size: String`)
    // interpolated into `Environment=CCACHE_MAXSIZE=` and
    // `Environment=SCCACHE_CACHE_SIZE=` lines. A newline would terminate
    // the env value and inject another directive. `binding.name` is
    // already validated by `validate_cache_pool_name` at config load, so
    // it does not need a separate gate here.
    for c in &spec.caches {
        check_identity_field("caches[].size", &c.size)?;
    }
    let mut s = String::new();
    // Track whether any structurally-meaningful directive landed in the
    // body. ccache-only specs hit no emission site (the Ccache branch
    // is empty per LAYER 1/2 contract); without this gate the renderer
    // would write a `[Service]\n` stub drop-in to disk for every
    // ccache-only runner, polluting `systemctl cat` and the in-place
    // diff path. Returning None when nothing meaningful was emitted
    // lets the apply layer's DropInChangeKind::Removed branch delete
    // any pre-existing stub on first apply post-deploy.
    let mut emitted_anything = false;
    let unit_section_pools: Vec<&EffectiveCacheBinding> = spec
        .caches
        .iter()
        .filter(|c| c.kinds.contains(&CacheKind::Sccache))
        .collect();
    if !unit_section_pools.is_empty() {
        // [Unit] Requires=/After= the per-pool sccache server unit.
        // ccache-only pools do NOT have a server unit (filesystem-only
        // mechanism via shared HOME under trust_zone), so they are
        // omitted from this list.
        s.push_str("[Unit]\n");
        for c in &unit_section_pools {
            let _ = writeln!(s, "Requires=ghars-cache@{}.service", c.name);
            let _ = writeln!(s, "After=ghars-cache@{}.service", c.name);
        }
        s.push('\n');
        emitted_anything = true;
    }
    s.push_str("[Service]\n");
    let mut bind_paths: Vec<String> = Vec::new();
    let mut needs_run_ghars = false;
    for c in &spec.caches {
        let pool_dir = format!("/var/cache/ghars/pools/{}", c.name);
        if c.kinds.contains(&CacheKind::Ccache) {
            // ccache uses filesystem mode: the shared $HOME/.cache/ccache/
            // directory under the trust_zone-shared HOME is the entire
            // mechanism. No daemon, no Requires=, no BindPaths to a
            // pool dir — runners with the same trust_zone share the
            // ccache directory by virtue of the shared DynamicUser UID.
            //
            // CCACHE_DIR + CCACHE_MAXSIZE are emitted ONLY by LAYER 2
            // (`render_runner_env_file` → `bin.X.Y.Z/.env`). No LAYER 1
            // `Environment=` emission here: Runner.Listener's
            // `LoadAndSetEnv` runs AS THE FIRST STATEMENT of `Main` —
            // BEFORE any subprocess spawn, BEFORE HostContext setup,
            // BEFORE any other Runner.Listener code — and (verified
            // in actions/runner at `src/Runner.Listener/Program.cs`)
            // reads `.env` line-by-line, calling
            // `Environment.SetEnvironmentVariable` per line. So a
            // LAYER 1 `Environment=CCACHE_DIR=` here would be
            // overwritten by LAYER 2 before any consumer reads it,
            // making it dead code that misleads operators reading
            // `systemctl cat` (the per-pool path it would show is
            // never the path actually used at runtime).
            //
            // ccache invocation path: workflow step runs `gcc` →
            // PATH wrapper at `/usr/lib64/ccache/gcc` → ccache reads
            // CCACHE_DIR from process env → trust-zone-shared path
            // from LAYER 2.
        }
        if c.kinds.contains(&CacheKind::Sccache) {
            let _ = writeln!(
                s,
                "Environment=SCCACHE_SERVER_UDS=/run/ghars/cache-{}.sock",
                c.name
            );
            // Pool-side server is the sole owner; runners are clients.
            // SCCACHE_NO_DAEMON=1 prevents auto-spawn.
            s.push_str("Environment=SCCACHE_NO_DAEMON=1\n");
            let _ = writeln!(s, "Environment=SCCACHE_CACHE_SIZE={}", c.size);
            needs_run_ghars = true;
            // Pool dir is also bound so sccache disk reads succeed even
            // when the runner needs to inspect cache shape locally.
            if !bind_paths.contains(&pool_dir) {
                bind_paths.push(pool_dir);
            }
            emitted_anything = true;
        }
    }
    if needs_run_ghars {
        bind_paths.push("/run/ghars".into());
    }
    if !bind_paths.is_empty() {
        // BindPaths is list-typed; emitting a non-empty value APPENDS
        // to the template's set (the template has no BindPaths line —
        // it relies on TemporaryFileSystem=/:ro + selective rebinds).
        // The reset-on-empty validator passes because we only get
        // here with at least one entry.
        let _ = writeln!(s, "BindPaths={}", bind_paths.join(" "));
    }
    if !emitted_anything {
        return Ok(None);
    }
    Ok(Some(s))
}

/// `15-resolv.conf` — always emitted. Binds /etc/resolv.conf in the
/// runner's mount namespace from the source appropriate for the
/// runner's network mode:
/// - Open / no-network: host's `/etc/resolv.conf` (same path → same
///   path; runner inherits the host resolver).
/// - Netns: `/run/ghars/netns-resolv/<name>` (written by
///   `ghars _netns-setup` from the operator's `DnsMode`).
///
/// Always-emitted so the template can omit the path entirely; see
/// `render_runner_unit` for why the override-via-drop-in pattern fails
/// (systemd's mount-list dedup keeps the FIRST entry per destination).
fn render_resolv_bind(spec: &EffectiveRunnerSpec) -> String {
    let mut s = String::new();
    s.push_str("[Service]\n");
    let netns_mode = matches!(
        spec.network.as_ref().map(|n| &n.spec.mode),
        Some(NetworkMode::Netns),
    );
    if netns_mode {
        // The netns helper writes the source file at unit start; if
        // the file is missing the bind fails — fail-closed. No `-`
        // prefix.
        let _ = writeln!(
            s,
            "BindReadOnlyPaths=/run/ghars/netns-resolv/{}:/etc/resolv.conf",
            spec.name
        );
    } else {
        s.push_str("BindReadOnlyPaths=/etc/resolv.conf\n");
    }
    s
}

fn render_network(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(net) = spec.network.as_ref() else {
        return Ok(None);
    };
    let netns_mode = matches!(net.spec.mode, NetworkMode::Netns);
    let has_cgroup_bpf_directives = !net.spec.ip_allow.is_empty()
        || !net.spec.ip_deny.is_empty()
        || !net.spec.restrict_address_families.is_empty();
    // Defense in depth against direct-construct callers (test
    // fixtures, future programmatic spec builders) that bypass
    // `lower_to_effective`. The lowering pipeline already collapses
    // Open + all-empty policy to `spec.network = None`, so this
    // branch is unreachable on the production path; an Open binding
    // with no directives reaching `render_network` is therefore a
    // bug-shaped input we'd rather render as "no drop-in" than
    // emit an empty `[Service]` section. Netns mode always emits
    // because the namespace bind itself is the load-bearing
    // contribution regardless of cgroup-BPF policy.
    if !netns_mode && !has_cgroup_bpf_directives {
        return Ok(None);
    }
    // Defense-in-depth: `restrict_address_families[]` is the only
    // operator-supplied free-form String surface in this renderer's
    // body. It is joined with `" "` and emitted on a
    // `RestrictAddressFamilies=` line, so a newline anywhere in an
    // entry would inject a new directive. `ip_allow` / `ip_deny` are
    // typed (`Vec<IpNet>`) so they cannot carry control chars;
    // `spec.name` is gated by `validate_runner_name` upstream.
    for entry in &net.spec.restrict_address_families {
        check_identity_field("network.restrict_address_families[]", entry)?;
    }
    let mut s = String::new();
    if netns_mode {
        // Netns mode: pull in the per-runner `ghars-net@` side-unit so
        // the namespace bind-mount exists before the runner unit's
        // `NetworkNamespacePath=` join. `BindsTo` couples the
        // lifecycle so a failed netns side-unit also stops the runner.
        s.push_str("[Unit]\n");
        let _ = writeln!(s, "Requires=ghars-net@{}.service", spec.name);
        let _ = writeln!(s, "BindsTo=ghars-net@{}.service", spec.name);
        let _ = writeln!(s, "After=ghars-net@{}.service", spec.name);
        s.push('\n');
    }
    s.push_str("[Service]\n");

    if netns_mode {
        // Fail-closed: NetworkNamespacePath= refuses to start when the
        // bind-mount path is missing or unjoinable. systemd's
        // exec_invoke() opens the path via `open_shareable_ns_path`
        // and returns EXIT_NETWORK on failure (see the
        // `network_namespace_path` branch in
        // `src/core/exec-invoke.c::exec_invoke`).
        let _ = writeln!(s, "NetworkNamespacePath=/var/run/netns/ghars-{}", spec.name);
    }

    // Cgroup-BPF defense in depth. Emitted in BOTH modes when the
    // operator populates the corresponding NetworkSpec field — Netns
    // pairs them with the nft layer for belt-and-suspenders, Open
    // mode relies on them as the sole egress / family gate at the
    // systemd layer (no namespace, no nft).
    for cidr in &net.spec.ip_allow {
        let _ = writeln!(s, "IPAddressAllow={cidr}");
    }
    for cidr in &net.spec.ip_deny {
        let _ = writeln!(s, "IPAddressDeny={cidr}");
    }
    if !net.spec.restrict_address_families.is_empty() {
        let _ = writeln!(
            s,
            "RestrictAddressFamilies={}",
            net.spec.restrict_address_families.join(" ")
        );
    }

    Ok(Some(s))
}

fn render_numa(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let cpus = spec.allowed_cpus.as_deref();
    let mems = spec.allowed_memory_nodes.as_deref();
    if cpus.is_none() && mems.is_none() {
        return Ok(None);
    }
    // Defense-in-depth: both fields are operator-supplied
    // strings interpolated into AllowedCPUs= / AllowedMemoryNodes=.
    // A newline anywhere would inject a new directive line.
    if let Some(c) = cpus {
        check_identity_field("allowed_cpus", c)?;
    }
    if let Some(m) = mems {
        check_identity_field("allowed_memory_nodes", m)?;
    }
    let mut s = String::new();
    s.push_str("[Service]\n");
    if let Some(c) = cpus {
        let _ = writeln!(s, "AllowedCPUs={c}");
    }
    if let Some(m) = mems {
        let _ = writeln!(s, "AllowedMemoryNodes={m}");
    }
    Ok(Some(s))
}

fn render_proxy(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(proxy) = spec.proxy.as_ref() else {
        return Ok(None);
    };
    if proxy.http.is_none()
        && proxy.https.is_none()
        && proxy.no_proxy.is_empty()
        && proxy.ca_certs.is_empty()
    {
        return Ok(None);
    }
    // Defense-in-depth: every operator-supplied string about to
    // be interpolated into a 60-proxy.conf body must clear
    // check_identity_field BEFORE bytes are written. The proxy fields
    // appear in `Environment=...` directives — a newline would
    // terminate the env var and inject a new directive (or, for
    // path bindings below, escape into BindReadOnlyPaths).
    if let Some(http) = &proxy.http {
        check_identity_field("proxy.http", http)?;
    }
    if let Some(https) = &proxy.https {
        check_identity_field("proxy.https", https)?;
    }
    for entry in &proxy.no_proxy {
        check_identity_field("proxy.no_proxy[]", entry)?;
    }
    for binding in &proxy.ca_certs {
        check_identity_field("proxy.ca_certs[].env", &binding.env)?;
        check_identity_field("proxy.ca_certs[].path", binding.path.as_str())?;
    }
    let mut s = String::new();
    s.push_str("[Service]\n");
    if let Some(http) = &proxy.http {
        // Both upper- and lower-case env vars so apps that read either
        // find a value.
        let _ = writeln!(s, "Environment=HTTP_PROXY={http}");
        let _ = writeln!(s, "Environment=http_proxy={http}");
    }
    if let Some(https) = &proxy.https {
        let _ = writeln!(s, "Environment=HTTPS_PROXY={https}");
        let _ = writeln!(s, "Environment=https_proxy={https}");
    }
    if !proxy.no_proxy.is_empty() {
        let joined = proxy.no_proxy.join(",");
        let _ = writeln!(s, "Environment=NO_PROXY={joined}");
        let _ = writeln!(s, "Environment=no_proxy={joined}");
    }
    let mut bind_paths: Vec<String> = Vec::new();
    for binding in &proxy.ca_certs {
        let _ = writeln!(s, "Environment={}={}", binding.env, binding.path);
        // No `-` prefix: a missing CA cert must FAIL the unit, not silently
        // tolerate absence. Tolerating absence here lets the runner connect
        // through the proxy with the system trust store as a fallback —
        // that's MITM if the proxy is untrusted (SEC-08).
        bind_paths.push(binding.path.to_string());
    }
    if !bind_paths.is_empty() {
        let _ = writeln!(s, "BindReadOnlyPaths={}", bind_paths.join(" "));
    }
    Ok(Some(s))
}

fn render_hooks(spec: &EffectiveRunnerSpec) -> Result<Option<String>> {
    let Some(h) = spec.hooks.as_ref() else {
        return Ok(None);
    };
    if h.pre_job.is_none() && h.post_job.is_none() {
        return Ok(None);
    }
    // Defense-in-depth: `pre_job` / `post_job` are operator-supplied
    // host paths (config.rs `HooksSpec` fields are `Option<Utf8PathBuf>`)
    // interpolated into `Environment=ACTIONS_RUNNER_HOOK_JOB_*` and
    // `BindReadOnlyPaths=` lines. A newline embedded in the Utf8 path
    // string (Utf8PathBuf is a UTF-8 wrapper, not a control-char filter)
    // would split the env value or escape into a separate
    // BindReadOnlyPaths directive. Validate both bytes-on-disk surfaces
    // before any are written.
    if let Some(p) = &h.pre_job {
        check_identity_field("hooks.pre_job", p.as_str())?;
    }
    if let Some(p) = &h.post_job {
        check_identity_field("hooks.post_job", p.as_str())?;
    }
    let mut s = String::new();
    s.push_str("[Service]\n");
    if let Some(p) = &h.pre_job {
        let _ = writeln!(s, "Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED={p}");
    }
    if let Some(p) = &h.post_job {
        let _ = writeln!(s, "Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED={p}");
    }
    // Bind the parent directory of each hook script (deduped if pre and
    // post share the parent). Hook scripts must be reachable through
    // the runner's mount namespace.
    //
    // SEC-12 defense-in-depth: refuse to emit `BindReadOnlyPaths=/`
    // if any hook's parent resolves to the filesystem root. The
    // validator (`validators::validate_hook_script`) already rejects
    // root-parent paths at config-load time, but the renderer is the
    // last gate before the directive lands on disk; keep the check
    // here so any caller that bypasses the validator (programmatic
    // EffectiveRunnerSpec construction, future test harnesses)
    // cannot regress this surface into a host-exposing bind.
    let mut parents: Vec<String> = Vec::new();
    for p in [&h.pre_job, &h.post_job].into_iter().flatten() {
        if let Some(parent) = p.parent() {
            let parent_str = parent.to_string();
            if parent_str.is_empty() {
                continue;
            }
            if parent_str == "/" {
                return Err(GharsError::Validation(
                    format!(
                        "hook script {p}: parent directory is `/` (SEC-12); \
                         BindReadOnlyPaths=/ would expose the entire host"
                    ),
                    "place the hook under a dedicated subdirectory \
                     (e.g. /usr/local/lib/ghars-hooks/<name>.sh)"
                        .into(),
                ));
            }
            if !parents.contains(&parent_str) {
                parents.push(parent_str);
            }
        }
    }
    if !parents.is_empty() {
        let _ = writeln!(s, "BindReadOnlyPaths={}", parents.join(" "));
    }
    Ok(Some(s))
}

fn render_lognamespace(spec: &EffectiveRunnerSpec) -> String {
    let mut s = String::new();
    s.push_str("[Service]\n");
    // SyslogIdentifier gives every runner a clean per-runner tag in
    // journal output regardless of systemd version.
    let _ = writeln!(s, "SyslogIdentifier=ghars-{}", spec.name);
    // LogNamespace= provides full journal isolation (separate journal
    // files per runner) but requires systemd 254+ with journald
    // namespace support. On older systemd (250-253) the directive is
    // silently ignored -- runners still log to the default journal
    // and ghars logs filters by unit name. No conditional needed:
    // systemd drops unknown/unsupported directives without failing
    // the unit.
    let _ = writeln!(s, "LogNamespace=ghars-{}", spec.name);
    s
}

// --- Cache service drop-in (Part 9b) ------------------------------------

/// Render the per-pool drop-in `00-ghars.conf` for
/// `ghars-cache@NAME.service`. Shape varies by `kinds` (ccache only,
/// sccache only, both).
///
/// # Errors
///
/// Returns `GharsError::Validation` from the reset-on-empty
/// validator.
// Pedantic clippy flags ccache/sccache local bindings as confusable;
// the variant names are load-bearing (they ARE the schema's
// CacheKind values) and renaming would obscure the mapping.
#[allow(clippy::similar_names)]
pub fn render_cache_drop_in(
    binding: &EffectiveCacheBinding,
    config_source: &str,
    spec_hash: &str,
) -> Result<String> {
    // Defense-in-depth: three operator/composer-supplied
    // strings interpolate into this drop-in body —
    //   * `binding.size` (operator-supplied, free-form String) →
    //     `Environment=SCCACHE_CACHE_SIZE=` / `Environment=CCACHE_MAXSIZE=`
    //   * `config_source` (composed at plan time from
    //     `paths.config_dir`; already gated by `plan_from`'s
    //     identity-field check, but a future caller that bypasses
    //     `plan_from` would still skip it without this gate) →
    //     `X-Ghars-Config-Source=`
    //   * `spec_hash` (deterministically derived from canonicalized
    //     config; in production cannot contain control chars but the
    //     gate is cheap defense-in-depth in case a future hash format
    //     adds free-form metadata) → `X-Ghars-Spec-Hash=`
    // `binding.name` is gated upstream by `validate_cache_pool_name`
    // (IDENTIFIER_RE charset + identifier-shape) at config load.
    // `binding.kinds` is a typed enum so it cannot carry control chars.
    check_identity_field("caches[].size", &binding.size)?;
    check_identity_field("config_source", config_source)?;
    check_identity_field("spec_hash", spec_hash)?;
    let serves_ccache = binding.kinds.contains(&CacheKind::Ccache);
    let serves_sccache = binding.kinds.contains(&CacheKind::Sccache);

    let mut s = String::new();
    s.push_str("[Unit]\n");
    let _ = writeln!(s, "X-Ghars-Spec-Hash={spec_hash}");
    let _ = writeln!(s, "X-Ghars-Pool-Name={}", binding.name);
    let kinds_csv = binding
        .kinds
        .iter()
        .map(|k| match k {
            CacheKind::Ccache => "ccache",
            CacheKind::Sccache => "sccache",
        })
        .collect::<Vec<_>>()
        .join(",");
    let _ = writeln!(s, "X-Ghars-Pool-Kinds={kinds_csv}");
    let _ = writeln!(s, "X-Ghars-Config-Source={config_source}");
    s.push('\n');

    s.push_str("[Service]\n");
    // The cache template declares `DynamicUser=yes` without a User=
    // line so the per-pool drop-in can pin the User= name to the
    // pool's trust_zone. systemd allocates the same transient UID for
    // every unit that names `ghars-tz-<TRUST_ZONE>` as User= and
    // recycles it when the last such unit stops. The cache server
    // sharing its UID with the runners in the same trust_zone is what
    // makes owner-DAC reach work for the sccache UDS (mode 0600) and
    // the CacheDirectory (mode 0750). Runners in OTHER trust_zones
    // run at a different UID and are denied at AF_UNIX connect()
    // / path traversal. Validators upstream guarantee every runner
    // referencing `pool` has the same trust_zone as the pool, so this
    // emission is consistent with the runner unit's own User= name
    // (set in the per-runner 00-ghars.conf drop-in).
    let _ = writeln!(s, "User=ghars-tz-{}", binding.trust_zone);
    if serves_sccache {
        let _ = writeln!(
            s,
            "Environment=SCCACHE_DIR=%C/ghars/pools/{}/sccache",
            binding.name
        );
        let _ = writeln!(s, "Environment=SCCACHE_CACHE_SIZE={}", binding.size);
        let _ = writeln!(
            s,
            "Environment=SCCACHE_SERVER_UDS=%t/ghars/cache-{}.sock",
            binding.name
        );
        s.push_str("Environment=SCCACHE_NO_DAEMON=1\n");
        // SCCACHE_IDLE_TIMEOUT=0 prevents the server from exiting
        // mid-shift. Mismatch between server idle timeout and runner
        // restart cycles would force re-init of the on-disk cache.
        s.push_str("Environment=SCCACHE_IDLE_TIMEOUT=0\n");
    }
    if serves_ccache {
        // No CCACHE_DIR / CCACHE_MAXSIZE emission here. This drop-in
        // is on the CACHE POOL unit (`ghars-cache@NAME.service`),
        // not the runner unit. For ccache-only pools, the cache pool
        // unit's ExecStart is `<sleep_path> infinity` (the stub at
        // the `else` branch below) — it never reads CCACHE_*. For
        // combined-kind pools the cache pool unit runs
        // `sccache --start-server` (the `if serves_sccache` ExecStart
        // below); sccache is a separate tool whose documented config
        // surface uses SCCACHE_* exclusively, no CCACHE_* reads.
        //
        // Workflow-step ccache invocations get CCACHE_DIR from the
        // RUNNER unit's LAYER 2 `.env` (trust-zone-shared, gated on
        // has_ccache by `render_runner_env_file`), NOT from this
        // cache-pool-unit drop-in. Prior emission was dead code that
        // misled operators reading `systemctl cat
        // ghars-cache@NAME.service` (the per-pool path it showed was
        // never the path actually consumed at runtime).
    }

    if serves_sccache {
        // sccache_path is the plan-time resolution of either the
        // operator pin (`[cache_pools.NAME].sccache_path = "/..."`)
        // or the canonical-search auto-detect (`/usr/local/bin/sccache`
        // then `/usr/bin/sccache`). The plan layer guarantees `Some`
        // here: `resolve_cache_pool_paths` produces `Some(path)`
        // exactly when `kinds.contains(Sccache)`, which is the
        // `serves_sccache` branch we're in. None at this site is a
        // plan-layer invariant violation, not an operator-facing
        // error, so the renderer treats it as a programmer bug.
        let sccache_path = binding.sccache_path.as_ref().ok_or_else(|| {
            GharsError::Validation(
                format!(
                    "render_cache_drop_in: binding for pool '{}' serves sccache \
                     but sccache_path is None; resolve_cache_pool_paths should have populated it",
                    binding.name
                ),
                "this is a ghars bug — the plan layer must resolve sccache_path \
                 before invoking the renderer for sccache-serving pools"
                    .into(),
            )
        })?;
        // Defense-in-depth: the operator-pinned path arrives via a
        // pre-validated absolute Utf8PathBuf, but a future caller that
        // constructs an EffectiveCacheBinding programmatically could
        // bypass that gate; check the bytes here too so the rendered
        // unit cannot smuggle a newline or NUL into ExecStart=.
        check_identity_field("caches[].sccache_path", sccache_path.as_str())?;
        let _ = writeln!(s, "ExecStart={sccache_path} --start-server");
        // sccache --start-server forks: parent exits, child listens.
        // Override the template's Type=simple for sccache pools.
        s.push_str("Type=forking\n");
        // mode enforcement is in the cache template via UMask=0077,
        // not a per-pool ExecStartPost. Kernel-enforced at vfs_mknod
        // time (Linux net/unix/af_unix.c:unix_bind_bsd:1349) so there
        // is no TOCTOU window between bind() and a chmod shim. See the
        // UMask= comment in cache_template_text() for the full
        // mechanism + citations.
        let _ = writeln!(
            s,
            "ReadWritePaths=%C/ghars/pools/{pool} %t/ghars /var/lib/ghars/{tz}",
            pool = binding.name, tz = binding.trust_zone
        );
    } else {
        // ccache-only pool — the unit exists to own the CacheDirectory
        // and act as a Requires= anchor (StopWhenUnneeded handles
        // lifecycle). sleep infinity is the simplest way to keep
        // Type=simple alive without consuming resources. sleep_path
        // is the plan-time resolution of either the operator pin
        // (`[cache_pools.NAME].sleep_path = "/..."`) or the
        // canonical-search auto-detect (`/usr/bin/sleep` then
        // `/bin/sleep`). The plan layer guarantees `Some` for the
        // ccache-only branch we're in (symmetric with sccache_path
        // above) — None here is a programmer bug, not operator-facing.
        let sleep_path = binding.sleep_path.as_ref().ok_or_else(|| {
            GharsError::Validation(
                format!(
                    "render_cache_drop_in: binding for ccache-only pool '{}' \
                     has sleep_path = None; resolve_cache_pool_paths should have populated it",
                    binding.name
                ),
                "this is a ghars bug — the plan layer must resolve sleep_path \
                 before invoking the renderer for ccache-only pools"
                    .into(),
            )
        })?;
        check_identity_field("caches[].sleep_path", sleep_path.as_str())?;
        let _ = writeln!(s, "ExecStart={sleep_path} infinity");
        let _ = writeln!(s, "ReadWritePaths=%C/ghars/pools/{}", binding.name);
    }

    validate_drop_in(&format!("ghars-cache@{}/00-ghars.conf", binding.name), &s)?;
    Ok(s)
}

// --- Test surface --------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use ipnet::IpNet;

    use crate::config::{
        Arch, CaCertBinding, CacheMode, DnsMode, EffectiveNetworkBinding, EgressRule, HooksSpec,
        Ipv6Mode, NetworkSpec, PortSpec, Proto, ProxySpec,
    };

    fn minimal_spec() -> EffectiveRunnerSpec {
        EffectiveRunnerSpec {
            environment: crate::config::EnvironmentSpec::default(),
            name: "buckos".into(),
            url: "https://github.com/example/buckos".into(),
            arch: Arch::X86_64,
            labels: vec!["self-hosted".into(), "linux".into()],
            memory_max: None,
            runner_version: Some("2.334.0".into()),
            runner_sha256: None,
            runner_tarball: None,
            auth_name: "pat".into(),
            caches: vec![],
            trust_zone: "default".into(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
            spec_hash: "sha256:dead".into(),
            config_source: "/etc/ghars/ghars.toml".into(),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        }
    }

    #[test]
    fn template_starts_with_unit_section() {
        let t = runner_template_text();
        assert!(t.starts_with("[Unit]\n"));
        // ConditionPathExists / WorkingDirectory / StateDirectory /
        // HOME live in the per-runner drop-in (path components depend
        // on trust_zone, which `%i` cannot express).
        assert!(!t.contains("ConditionPathExists=/var/lib/ghars/%i/runsvc.sh"));
        assert!(!t.contains("WorkingDirectory=/var/lib/ghars/%i"));
        assert!(!t.contains("\nStateDirectory=ghars/%i\n"));
        // ExecStart= lives only in the per-runner drop-in because the
        // path includes the resolved runner version (bin.X.Y.Z) which
        // the template-level `%i` specifier cannot express.
        assert!(!t.contains("\nExecStart="));
        // DynamicUser=yes replaces the static `User=ghars-%i` /
        // `Group=ghars-%i` from the prior model; the User= name itself
        // is set by the per-runner 00-ghars.conf drop-in to
        // `ghars-tz-<TRUST_ZONE>` so trust-zone-shared runners receive
        // the same transient UID.
        assert!(t.contains("\nDynamicUser=yes\n"));
        assert!(!t.contains("\nUser=ghars-%i\n"));
        assert!(!t.contains("\nGroup=ghars-%i\n"));
        // Capability bounding set is empty: ExecStart does not
        // setuid/setgid (DynamicUser= handles the identity), so no
        // CAP_SETUID/CAP_SETGID are required.
        assert!(t.contains("\nCapabilityBoundingSet=\n"));
        assert!(!t.contains("CapabilityBoundingSet=CAP_SETUID"));
        assert!(t.contains("Slice=system.slice"));
    }

    #[test]
    fn render_identity_emits_exec_start_with_reset_and_versioned_path() {
        // The drop-in provides ExecStart= because the path depends on
        // trust_zone + resolved runner version. The empty `ExecStart=`
        // resets any inherited value (defense against 99-*.conf
        // ExecStart= overrides) and the second line names the
        // tarball's runsvc.sh under the versioned bin dir.
        let spec = minimal_spec();
        let r = render_runner_unit(&spec).unwrap();
        let id = r.drop_ins.get("00-ghars.conf").unwrap();
        assert!(id.contains("\nExecStart=\n"));
        assert!(id.contains(
            "\nExecStart=/bin/bash /var/lib/ghars/default/ghars-buckos/bin.2.334.0/bin/runsvc.sh\n"
        ));
        // Both lines are inside [Service].
        let service_idx = id.find("[Service]").unwrap();
        let reset_idx = id.find("\nExecStart=\n").unwrap();
        let path_idx = id
            .find("ExecStart=/bin/bash")
            .unwrap();
        assert!(service_idx < reset_idx);
        assert!(reset_idx < path_idx);
    }

    #[test]
    fn render_identity_does_not_emit_x_ghars_runsvc_sha256() {
        // The X-Ghars-Runsvc-Sha256 annotation was the runsvc-wrapper
        // trampoline's integrity-check input — both the wrapper and
        // the annotation have been removed. Pin that no future renderer
        // change resurrects the annotation.
        let spec = minimal_spec();
        let r = render_runner_unit(&spec).unwrap();
        let id = r.drop_ins.get("00-ghars.conf").unwrap();
        assert!(!id.contains("X-Ghars-Runsvc-Sha256"));
    }

    #[test]
    fn render_runner_env_file_emits_unconditional_keys_for_empty_caches() {
        // LANG + KTSTR_LOCK_DIR + KTSTR_CACHE_DIR always emitted.
        // CCACHE_DIR is GATED on having at least one ccache-kind
        // binding (#10 fix — symmetric with apply-layer .ccache dir
        // creation gating). Empty caches = no ccache binding = no
        // CCACHE_DIR emission. Pin byte-exact output so any drift
        // (extra blank line, key reorder, missing newline, or a
        // regression to unconditional CCACHE_DIR emission) is caught.
        let spec = minimal_spec();  // caches = vec![]
        let env = render_runner_env_file(&spec).unwrap();
        assert_eq!(
            env,
            "LANG=C.UTF-8\n\
             KTSTR_LOCK_DIR=/var/lib/ghars/default/.ktstr\n\
             KTSTR_CACHE_DIR=/var/lib/ghars/default/.ktstr\n",
            "byte-exact empty-caches output drift detected",
        );
    }

    /// Pin that `render_runner_env_file` emits `CCACHE_DIR=` ONLY
    /// when the spec has at least one ccache-kind binding. Without a
    /// ccache binding the env var must be absent so the unconditional
    /// ccache wrappers in PATH (units.rs render_runner_path_file)
    /// don't intercept `gcc`/`cc` calls and try to write to the
    /// trust-zone `.ccache` dir that wasn't created by apply.
    ///
    /// Symmetric with `execute_create_runner`'s `.ccache` dir
    /// creation gate (src/apply/runners.rs has_ccache check). The
    /// two are load-bearing for the post-#10 invariant: dir presence
    /// ⇔ env var presence ⇔ at-least-one-ccache-binding.
    #[test]
    fn render_runner_env_file_gates_ccache_dir_on_ccache_binding() {
        // Use line-start match (CCACHE_DIR=... is a full env-file
        // line) so the assertion doesn't falsely match the
        // `SCCACHE_DIR=` line which contains `CCACHE_DIR=` as a
        // substring starting at index 1.
        let has_ccache_dir_line = |env: &str| -> bool {
            env.lines().any(|l| l.starts_with("CCACHE_DIR="))
        };

        // No binding → no CCACHE_DIR.
        let spec = minimal_spec();
        let env = render_runner_env_file(&spec).unwrap();
        assert!(
            !has_ccache_dir_line(&env),
            "no-binding spec must NOT emit CCACHE_DIR line: {env}"
        );

        // Ccache-only binding → CCACHE_DIR present.
        let mut spec_c = minimal_spec();
        spec_c.caches.push(crate::config::EffectiveCacheBinding {
            name: "obj".into(),
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        let env_c = render_runner_env_file(&spec_c).unwrap();
        assert!(
            env_c.contains("CCACHE_DIR=/var/lib/ghars/default/.ccache\n"),
            "ccache-binding spec must emit trust-zone-interpolated CCACHE_DIR: {env_c}"
        );

        // Sccache-only binding → no CCACHE_DIR line (kind-blind
        // regression guard — the gate must check the Ccache kind
        // specifically, not just "any binding").
        let mut spec_s = minimal_spec();
        spec_s.caches.push(crate::config::EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        let env_s = render_runner_env_file(&spec_s).unwrap();
        assert!(
            !has_ccache_dir_line(&env_s),
            "sccache-only-binding spec must NOT emit CCACHE_DIR line (note: \
             SCCACHE_DIR is fine — only the bare CCACHE_DIR= line is gated): {env_s}"
        );

        // Combined-kind binding → CCACHE_DIR present (binding has
        // Ccache + Sccache, so the contains-Ccache predicate fires).
        let mut spec_combined = minimal_spec();
        spec_combined.caches.push(crate::config::EffectiveCacheBinding {
            name: "combined".into(),
            kinds: vec![CacheKind::Ccache, CacheKind::Sccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        let env_combined = render_runner_env_file(&spec_combined).unwrap();
        assert!(
            env_combined.contains("CCACHE_DIR=/var/lib/ghars/default/.ccache\n"),
            "combined-kind-binding spec must emit CCACHE_DIR: {env_combined}"
        );
    }

    #[test]
    fn render_runner_env_file_emits_per_binding_lines_by_kind() {
        // Ccache-only binding: CCACHE_MAXSIZE only, no SCCACHE_*.
        let mut spec = minimal_spec();
        spec.caches.push(crate::config::EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Ccache],
            size: "50G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        let env = render_runner_env_file(&spec).unwrap();
        assert!(env.contains("CCACHE_MAXSIZE=50G\n"), "missing CCACHE_MAXSIZE: {env}");
        assert!(!env.contains("SCCACHE_"), "ccache-only must not emit SCCACHE_*: {env}");

        // Sccache-only binding: SCCACHE_* yes, no CCACHE_MAXSIZE.
        let mut spec2 = minimal_spec();
        spec2.caches.push(crate::config::EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        let env2 = render_runner_env_file(&spec2).unwrap();
        assert!(!env2.contains("CCACHE_MAXSIZE"),
                "sccache-only must not emit CCACHE_MAXSIZE: {env2}");
        assert!(env2.contains("SCCACHE_SERVER_UDS=/run/ghars/cache-build.sock\n"),
                "missing SCCACHE_SERVER_UDS: {env2}");
        assert!(env2.contains("SCCACHE_NO_DAEMON=1\n"),
                "missing SCCACHE_NO_DAEMON: {env2}");
        assert!(env2.contains("SCCACHE_CACHE_SIZE=200G\n"),
                "missing SCCACHE_CACHE_SIZE: {env2}");
        assert!(env2.contains("SCCACHE_DIR=/var/cache/ghars/pools/build/sccache\n"),
                "missing SCCACHE_DIR: {env2}");
    }

    /// Renderer contract test: with two ccache bindings in
    /// `spec.caches`, `render_runner_env_file` emits a per-binding
    /// `CCACHE_MAXSIZE=` line for EACH binding in `spec.caches` source
    /// order. The downstream `.env` loader semantic
    /// (`Runner.Listener::LoadAndSetEnv` calls
    /// `Environment.SetEnvironmentVariable` per line, later call
    /// overwrites earlier) is the CONSEQUENCE that motivated the
    /// `validate_no_duplicate_cache_kinds` gate — but this test does
    /// not exercise that consumer. It pins the upstream renderer
    /// contract: both lines present, deterministic source order.
    ///
    /// The config-load gate
    /// `crate::cli::load::validate_no_duplicate_cache_kinds` REJECTS
    /// multi-ccache configs before render — operators cannot trigger
    /// this path through normal `ghars apply`. This test pins the
    /// renderer's contract for direct-construct code paths (test
    /// fixtures, future programmatic users) so the per-binding
    /// emission stays deterministic if it's ever reachable.
    ///
    /// The `lower_to_effective` pipeline sorts `caches` alphabetically
    /// by `name` (src/plan/compute.rs caches.sort_by) before reaching
    /// this renderer — but that pipeline is upstream; this test
    /// constructs `spec.caches` directly so it pins the renderer
    /// contract, not the full pipeline.
    #[test]
    fn render_runner_env_file_emits_one_ccache_maxsize_per_binding_in_source_order() {
        let mut spec = minimal_spec();
        spec.caches.push(crate::config::EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Ccache],
            size: "50G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        spec.caches.push(crate::config::EffectiveCacheBinding {
            name: "test".into(),
            kinds: vec![CacheKind::Ccache],
            size: "100G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        let env = render_runner_env_file(&spec).unwrap();
        assert!(
            env.contains("CCACHE_MAXSIZE=50G\n"),
            "missing first binding's CCACHE_MAXSIZE: {env}"
        );
        assert!(
            env.contains("CCACHE_MAXSIZE=100G\n"),
            "missing second binding's CCACHE_MAXSIZE: {env}"
        );
        let p50 = env.find("CCACHE_MAXSIZE=50G").unwrap();
        let p100 = env.find("CCACHE_MAXSIZE=100G").unwrap();
        assert!(
            p50 < p100,
            "spec.caches order must drive emission order (50G before 100G): {env}"
        );
        // CCACHE_DIR is trust-zone-fixed, not per-binding. Pin that
        // multi-ccache bindings do NOT introduce per-pool CCACHE_DIR
        // emissions — that property is load-bearing for the
        // singleton-per-kind validator's rationale.
        let ccache_dir_count = env.matches("CCACHE_DIR=").count();
        assert_eq!(
            ccache_dir_count, 1,
            "CCACHE_DIR must be emitted exactly once (trust-zone-fixed, not per-binding): {env}"
        );
        // Pin the trust_zone-interpolated VALUE so a regression that
        // swapped the trust_zone variable for a literal "default"
        // doesn't break operators on non-default trust zones while
        // still passing the count check above.
        assert!(
            env.contains("CCACHE_DIR=/var/lib/ghars/default/.ccache\n"),
            "CCACHE_DIR must include the trust-zone-interpolated path: {env}"
        );
    }

    #[test]
    fn render_runner_path_file_contains_ccache_wrappers_and_cargo_bin() {
        // Single line, newline-terminated. ccache wrappers FIRST so
        // bare `gcc`/`cc` resolve to wrappers (otherwise 100% ccache
        // misses). Per-runner .cargo/bin segment included. System path
        // tail in sbin-before-bin order.
        let spec = minimal_spec();  // trust_zone=default, name=buckos
        let p = render_runner_path_file(&spec).unwrap();
        assert!(p.ends_with('\n'), "path_file must end with newline: {p:?}");
        assert_eq!(p.matches('\n').count(), 1,
                   "path_file must be exactly one line: {p:?}");
        assert!(p.starts_with("/usr/lib64/ccache:/usr/lib/ccache:"),
                "ccache wrappers must come first: {p}");
        assert!(p.contains("/var/lib/ghars/default/ghars-buckos/.cargo/bin"),
                "missing per-runner .cargo/bin: {p}");
        assert!(p.ends_with(":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"),
                "system path tail wrong: {p}");
    }

    // ---- render_identity defense-in-depth rejection tests ------------
    //
    // Each test mutates ONE interpolated field in `minimal_spec()`,
    // calls `render_runner_unit`, and asserts:
    //   - render returns Err(GharsError::Validation),
    //   - the error message names the offending field and the
    //     character class label,
    //   - the offending byte itself never appears in the message
    //     (defense-in-depth: validation errors should not leak the
    //     value being validated).
    //
    // Coverage targets `check_identity_field`'s four labels (newline,
    // carriage return, NUL byte, control character) crossed against
    // multiple interpolated fields (name, url, auth_name, user,
    // labels[], caches[].name).

    /// Helper: assert `render_runner_unit(spec)` errors with the
    /// expected field name + class label, and that the offending
    /// `bad` byte does NOT appear in the message segment of the
    /// rendered Display.
    ///
    /// `GharsError::Validation` Display is
    /// `"validation: <msg>\n  hint: <hint>"` (see error.rs's
    /// `Validation` variant `#[error(...)]` thiserror attribute),
    /// so the message segment is everything before `"\n  hint:"`.
    /// Checking only that segment avoids a false positive when the
    /// bad byte is itself `\n` (which the Display formatter always
    /// embeds between message and hint).
    fn assert_render_identity_rejects(
        spec: &EffectiveRunnerSpec,
        field: &str,
        class: &str,
        bad: char,
    ) {
        let err = render_runner_unit(spec).unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("render_identity"),
            "error must name the rejecting function: {msg}"
        );
        assert!(
            msg.contains(field),
            "error must name the offending field {field:?}: {msg}"
        );
        assert!(
            msg.contains(class),
            "error must name the character class {class:?}: {msg}"
        );
        // Defense-in-depth: the offending byte must not appear in the
        // message segment (everything before the Display formatter's
        // hint delimiter `\n  hint:`).
        let message_segment = msg.split("\n  hint:").next().unwrap_or(&msg);
        assert!(
            !message_segment.contains(bad),
            "error message must not leak the offending byte {bad:?} \
             (segment before hint delimiter): {message_segment:?}"
        );
    }

    #[test]
    fn render_identity_rejects_newline_in_name() {
        let mut spec = minimal_spec();
        spec.name = "buckos\nINJECTED=1".into();
        assert_render_identity_rejects(&spec, "name", "newline", '\n');
    }

    #[test]
    fn render_identity_rejects_carriage_return_in_url() {
        let mut spec = minimal_spec();
        spec.url = "https://github.com/example/buckos\rPOLLUTE=1".into();
        assert_render_identity_rejects(&spec, "url", "carriage return", '\r');
    }

    #[test]
    fn render_identity_rejects_nul_in_auth_name() {
        let mut spec = minimal_spec();
        spec.auth_name = "pat\0attacker".into();
        assert_render_identity_rejects(&spec, "auth_name", "NUL byte", '\0');
    }

    #[test]
    fn render_identity_rejects_newline_in_label() {
        let mut spec = minimal_spec();
        spec.labels = vec!["self-hosted".into(), "linux\nbad".into()];
        assert_render_identity_rejects(&spec, "labels[]", "newline", '\n');
    }

    #[test]
    fn render_identity_rejects_newline_in_cache_name() {
        let mut spec = minimal_spec();
        spec.caches.push(EffectiveCacheBinding {
            name: "build\npool".into(),
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        assert_render_identity_rejects(&spec, "caches[].name", "newline", '\n');
    }

    /// Positive path: a clean `minimal_spec` MUST render without error.
    /// Without this pin, a buggy `check_identity_field` that rejects
    /// every input (e.g. inverted condition) would only show up on
    /// the rejection tests — and they'd all pass, masking the bug.
    #[test]
    fn render_identity_accepts_clean_spec() {
        let spec = minimal_spec();
        let r = render_runner_unit(&spec).expect("clean spec must render");
        // Sanity: the rendered drop-in actually contains a key from
        // every check_identity_field call site (proving we hit the
        // success branch end-to-end, not just a short-circuit).
        let id = r.drop_ins.get("00-ghars.conf").unwrap();
        assert!(id.contains("X-Ghars-Runner-Name=buckos"));
        assert!(id.contains("X-Ghars-Auth-Name=pat"));
        assert!(id.contains("X-Ghars-Trust-Zone=default"));
    }

    /// Empty `caches` MUST emit `X-Ghars-Caches=` with
    /// an empty value, NOT skip the line. The classifier
    /// distinguishes `Some(vec![])` (line present, empty value) from
    /// `None` (line absent) — see `DiscoveredAnnotations` docstring.
    /// Without an unconditional emit, a runner whose caches list
    /// shrinks from `["pool-a"]` → `[]` would have no on-disk record
    /// of the prior membership, so `apply.rs` could not compute a
    /// caches-list diff for the drop-in body rewrite.
    #[test]
    fn render_identity_emits_x_ghars_caches_with_empty_value_when_caches_empty() {
        let spec = minimal_spec();
        // minimal_spec already has caches=vec![] — pin that here
        // explicitly so a future minimal_spec mutation doesn't silently
        // weaken the test.
        assert!(
            spec.caches.is_empty(),
            "test relies on minimal_spec having empty caches"
        );
        let r = render_runner_unit(&spec).expect("clean spec must render");
        let id = r.drop_ins.get("00-ghars.conf").unwrap();
        // Anchor on `\nX-Ghars-Caches=\n` (line break before, line break
        // immediately after the `=`). This catches both "missing line"
        // (substring absent) and "line with non-empty value"
        // (`X-Ghars-Caches=pool-a\n` would not contain `=\n`).
        // `writeln!` emits `\n` after every line, so `=\n` is the
        // unambiguous empty-value signature.
        assert!(
            id.contains("\nX-Ghars-Caches=\n"),
            "00-ghars.conf must contain `X-Ghars-Caches=` with empty value when \
             spec.caches is empty; got drop-in:\n{id}"
        );
    }

    /// `render_identity` sorts `spec.labels` alphabetically before
    /// emitting the `X-Ghars-Labels=` annotation, regardless of the
    /// order they arrive in. `plan::merge_defaults` already sorts
    /// labels via `labels.sort_unstable()`; this test pins the
    /// defense-in-depth re-sort inside `render_identity` (where the
    /// `X-Ghars-Labels=` line is emitted) so a direct
    /// `EffectiveRunnerSpec` constructor that bypasses
    /// `merge_defaults` still produces a canonical on-disk
    /// annotation. A regression dropping the sort
    /// at the emission site would surface here as the line carrying
    /// the unsorted construction order.
    #[test]
    fn render_identity_emits_labels_sorted() {
        // Build the spec DIRECTLY (no merge_defaults) so the test
        // proves the emission-site sort is load-bearing.
        let mut spec = minimal_spec();
        spec.labels = vec!["zebra".into(), "alpha".into(), "middle".into()];
        let r = render_runner_unit(&spec).expect("clean spec must render");
        let id = r.drop_ins.get("00-ghars.conf").unwrap();
        // Exact-line pin: `X-Ghars-Labels=alpha,middle,zebra` followed
        // by `\n`. Any other order (insertion: zebra,alpha,middle;
        // reverse: zebra,middle,alpha) would not contain this exact
        // substring.
        assert!(
            id.contains("\nX-Ghars-Labels=alpha,middle,zebra\n"),
            "X-Ghars-Labels= must emit values in alphabetical order; got drop-in:\n{id}"
        );
    }

    /// Propagation: `render_runner_unit` must surface the
    /// `check_identity_field` error verbatim (it's not swallowed
    /// or wrapped with a layer that obscures the offending field).
    /// The error must still name "`render_identity`" so an operator
    /// reading stderr can pinpoint the rejecting function.
    #[test]
    fn render_runner_unit_propagates_check_identity_field_error() {
        let mut spec = minimal_spec();
        spec.name = "buckos\nbad".into();
        let err = render_runner_unit(&spec).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("render_identity"),
            "render_runner_unit must propagate the check_identity_field \
             error verbatim: {msg}"
        );
    }

    /// Fail-fast ordering: when MULTIPLE fields are bad, the
    /// FIRST validated field surfaces — `render_identity` validates
    /// in order (`spec_hash`, name, url, `auth_name`, ...) and the `?`
    /// short-circuits on the first failure. Pin that order: a bad
    /// `url` AND bad `name` MUST report `url` (validated earlier),
    /// not `name`.
    #[test]
    fn render_identity_validation_runs_before_any_write() {
        let mut spec = minimal_spec();
        spec.url = "https://github.com/example/buckos\nbad".into();
        let err = render_runner_unit(&spec).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("\"url\""),
            "first-validated field (url) must surface, not a later \
             field (prefix): {msg}"
        );
        assert!(
            !msg.contains("\"prefix\""),
            "later-validated field (prefix) must NOT surface — fail-fast \
             on first error: {msg}"
        );
    }

    // ---- defense-in-depth across render_hardening / render_proxy / render_numa
    //
    // Each test mutates ONE operator-controllable string in
    // `minimal_spec()`, calls `render_runner_unit`, and asserts:
    //   - render returns Err(GharsError::Validation),
    //   - the error message names the offending field and the
    //     character class label (newline).
    // The pattern matches the render_identity tests above and pins
    // that the corresponding render_* function gates the value
    // BEFORE any bytes hit the drop-in body.

    #[test]
    fn render_hardening_rejects_newline_in_extra_capabilities_entry() {
        let mut spec = minimal_spec();
        spec.hardening.extra_capabilities = vec!["CAP_NET_BIND_SERVICE\nINJECTED=1".into()];
        let err = render_runner_unit(&spec).unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("extra_capabilities[]"),
            "msg must name field: {msg}"
        );
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    #[test]
    fn render_proxy_rejects_newline_in_https_url() {
        let mut spec = minimal_spec();
        spec.proxy = Some(ProxySpec {
            http: None,
            https: Some("http://192.168.2.84:3128\nINJECTED=1".into()),
            no_proxy: vec![],
            ca_certs: vec![],
        });
        let err = render_runner_unit(&spec).unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("proxy.https"), "msg must name field: {msg}");
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    #[test]
    fn render_numa_rejects_newline_in_allowed_cpus() {
        let mut spec = minimal_spec();
        spec.allowed_cpus = Some("0-31\nINJECTED=1".into());
        let err = render_runner_unit(&spec).unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("allowed_cpus"), "msg must name field: {msg}");
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    // ---- defense-in-depth across the remaining render_*
    // functions that interpolate operator-controllable strings into
    // drop-in bodies. Same pattern as the render_hardening / render_proxy
    // / render_numa tests above: mutate ONE field, call
    // `render_runner_unit` (or `render_cache_drop_in`), assert the error
    // surfaces with the field name + char-class label.

    /// `render_memory`: `memory_max` is an operator-supplied free-form
    /// String interpolated into `MemoryMax=`. A newline would inject a
    /// new directive line. The field is gated by the defense-in-depth
    /// `check_identity_field` call inside `render_memory`.
    #[test]
    fn render_memory_rejects_newline_in_memory_max() {
        let mut spec = minimal_spec();
        spec.memory_max = Some("110G\nINJECTED=1".into());
        let err = render_runner_unit(&spec).unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("memory_max"), "msg must name field: {msg}");
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    /// `render_cache_pool`: `caches[].size` is an operator-supplied
    /// free-form String interpolated into `Environment=CCACHE_MAXSIZE=`
    /// and `Environment=SCCACHE_CACHE_SIZE=` lines. A newline would
    /// terminate the env value and inject another directive.
    #[test]
    fn render_cache_pool_rejects_newline_in_caches_size() {
        let mut spec = minimal_spec();
        spec.caches = vec![EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G\nINJECTED=1".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        }];
        let err = render_runner_unit(&spec).unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("caches[].size"), "msg must name field: {msg}");
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    /// `render_network`: `network.restrict_address_families[]` is an
    /// operator-supplied free-form String entry joined with `" "` and
    /// emitted on a `RestrictAddressFamilies=` line. A newline
    /// anywhere in an entry would inject a new directive line.
    #[test]
    fn render_network_rejects_newline_in_restrict_address_families_entry() {
        let mut spec = minimal_spec();
        spec.network = Some(EffectiveNetworkBinding {
            name: "buck2-isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec!["AF_UNIX\nINJECTED=1".into()],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
        });
        let err = render_runner_unit(&spec).unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("network.restrict_address_families[]"),
            "msg must name field: {msg}"
        );
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    /// Defense-in-depth parity: `restrict_address_families[]` newline
    /// rejection MUST fire under Open mode too. The renderer body
    /// runs the same `check_identity_field` loop in both modes — the
    /// gate is mode-independent because the directive lives at the
    /// cgroup layer regardless of whether a netns is allocated.
    /// Pin Open mode separately so a future regression that scopes
    /// the check to only `if netns_mode { ... }` surfaces here.
    #[test]
    fn render_network_open_rejects_newline_in_restrict_address_families_entry() {
        let mut spec = minimal_spec();
        spec.network = Some(EffectiveNetworkBinding {
            name: "hostnet".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Open,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec!["AF_UNIX\nINJECTED=1".into()],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: None,
        });
        let err = render_runner_unit(&spec).unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("network.restrict_address_families[]"),
            "msg must name field: {msg}"
        );
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    /// `render_hooks`: SEC-12 defense-in-depth. The validator
    /// (`validators::validate_hook_script`) rejects root-parent
    /// hook paths at config load time, but the renderer is the
    /// last gate before `BindReadOnlyPaths=<parent>` lands on
    /// disk. A hook at `/foo.sh` whose parent is `/` would emit
    /// `BindReadOnlyPaths=/`, mounting the entire host into the
    /// runner sandbox. The render-time check refuses to emit such
    /// a directive even if the validator was bypassed
    /// (programmatic spec construction, future test surfaces).
    #[test]
    fn render_hooks_rejects_root_parent_pre_job_path() {
        let mut spec = minimal_spec();
        spec.hooks = Some(crate::config::HooksSpec {
            pre_job: Some(camino::Utf8PathBuf::from("/foo.sh")),
            post_job: None,
        });
        let err = render_runner_unit(&spec).unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("parent directory is `/`"), "msg: {msg}");
        assert!(msg.contains("SEC-12"), "msg must label SEC-12: {msg}");
        // Defense in depth: ensure the hint points operators at the
        // subdirectory remediation, not just "remove the hook".
        assert!(
            msg.contains("subdirectory") || msg.contains("ghars-hooks"),
            "remediation hint must point at subdir layout: {msg}"
        );
    }

    /// `render_hooks`: `hooks.pre_job` is an operator-supplied path
    /// (`Utf8PathBuf` is a UTF-8 wrapper, not a control-char filter)
    /// interpolated into `Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED=`
    /// and `BindReadOnlyPaths=` lines. A newline would split the env
    /// value or escape into a separate `BindReadOnlyPaths` directive.
    #[test]
    fn render_hooks_rejects_newline_in_pre_job_path() {
        let mut spec = minimal_spec();
        spec.hooks = Some(crate::config::HooksSpec {
            pre_job: Some(camino::Utf8PathBuf::from(
                "/etc/ghars/hooks/pre.sh\nINJECTED=1",
            )),
            post_job: None,
        });
        let err = render_runner_unit(&spec).unwrap_err();
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("hooks.pre_job"), "msg must name field: {msg}");
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    /// `render_cache_drop_in`: `binding.size` is an operator-supplied
    /// String emitted via `Environment=SCCACHE_CACHE_SIZE=` /
    /// `Environment=CCACHE_MAXSIZE=`. Direct call (not via
    /// `render_runner_unit`) because cache drop-ins are rendered at a
    /// separate call site (`plan.rs::into_cache_pool_plan`).
    #[test]
    fn render_cache_drop_in_rejects_newline_in_binding_size() {
        let binding = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G\nINJECTED=1".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let err = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd")
            .expect_err("must reject newline");
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("caches[].size"), "msg must name field: {msg}");
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    /// `render_cache_drop_in`: `binding.sccache_path` is interpolated
    /// into the `ExecStart=` line for sccache-serving pools. A newline
    /// in the path would split the `ExecStart=` directive and inject a
    /// follow-up directive at unit-load time. The renderer's
    /// `check_identity_field("caches[].sccache_path", ...)` gate must
    /// reject newline before any bytes hit the drop-in body. Mirrors
    /// `render_cache_drop_in_rejects_newline_in_binding_size`.
    #[test]
    fn render_cache_drop_in_rejects_newline_in_sccache_path() {
        let binding = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache\nINJECTED=1".into()),
            sleep_path: None,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let err = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd")
            .expect_err("must reject newline in sccache_path");
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("caches[].sccache_path"),
            "msg must name field: {msg}"
        );
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    /// `render_cache_drop_in`: `binding.sleep_path` is interpolated
    /// into the `ExecStart=` line for ccache-only pools. A newline in
    /// the path would split the `ExecStart=` directive and inject a
    /// follow-up directive at unit-load time. Mirrors the
    /// `_in_sccache_path` test above; the gate is symmetric.
    #[test]
    fn render_cache_drop_in_rejects_newline_in_sleep_path() {
        let binding = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Ccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep\nINJECTED=1".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let err = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd")
            .expect_err("must reject newline in sleep_path");
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("caches[].sleep_path"),
            "msg must name field: {msg}"
        );
        assert!(msg.contains("newline"), "msg must name class: {msg}");
    }

    /// `render_cache_drop_in`: NUL bytes in `sccache_path` would
    /// truncate the path at the parser's C-string boundary
    /// (systemd's conf-parser treats every value as a C-string at
    /// the libc layer). The renderer's
    /// `check_identity_field("caches[].sccache_path", ...)` gate
    /// must reject NUL bytes alongside newlines / carriage returns.
    /// Mirrors the newline test above; the gate's NUL branch is the
    /// "NUL byte" class label from `check_identity_field` and tests
    /// elsewhere pin the same label
    /// (`render_identity_rejects_nul_in_auth_name`).
    #[test]
    fn render_cache_drop_in_rejects_nul_in_sccache_path() {
        let binding = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache\0attacker".into()),
            sleep_path: None,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let err = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd")
            .expect_err("must reject NUL byte in sccache_path");
        assert!(
            matches!(err, GharsError::Validation(_, _)),
            "expected Validation, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("caches[].sccache_path"),
            "msg must name field: {msg}"
        );
        assert!(msg.contains("NUL"), "msg must name class: {msg}");
    }

    #[test]
    fn netns_template_has_load_bearing_execstop() {
        // ExecStop= is mandatory on RemainAfterExit=yes oneshot
        // units to prevent systemd from destroying runtime data.
        let t = netns_template_text();
        assert!(t.contains("RemainAfterExit=yes"));
        assert!(t.contains("ExecStop=+"));
    }

    #[test]
    fn cache_template_has_protect_system_strict() {
        let t = cache_template_text();
        assert!(t.contains("ProtectSystem=strict"));
        assert!(t.contains("StopWhenUnneeded=yes"));
    }

    #[test]
    fn render_minimal_spec_emits_identity_and_lognamespace() {
        let spec = minimal_spec();
        let r = render_runner_unit(&spec).unwrap();
        assert!(r.template.contains("[Unit]"));
        let id = r.drop_ins.get("00-ghars.conf").unwrap();
        assert!(id.contains("X-Ghars-Spec-Hash=sha256:dead"));
        assert!(id.contains("X-Ghars-Runner-Name=buckos"));
        assert!(id.contains("X-Ghars-Auth-Name=pat"));
        let log = r.drop_ins.get("80-lognamespace.conf").unwrap();
        assert!(log.contains("LogNamespace=ghars-buckos"));
    }

    #[test]
    fn render_skips_optional_drop_ins_when_absent() {
        let spec = minimal_spec();
        let r = render_runner_unit(&spec).unwrap();
        assert!(!r.drop_ins.contains_key("10-memory.conf"));
        assert!(!r.drop_ins.contains_key("20-hardening.conf"));
        assert!(!r.drop_ins.contains_key("30-cache-pool.conf"));
        assert!(!r.drop_ins.contains_key("40-network.conf"));
        assert!(!r.drop_ins.contains_key("50-numa.conf"));
        assert!(!r.drop_ins.contains_key("60-proxy.conf"));
        assert!(!r.drop_ins.contains_key("70-hooks.conf"));
        // 15-resolv.conf IS always present; verified separately.
    }

    #[test]
    fn render_resolv_bind_open_mode_binds_host_resolv_conf() {
        // No spec.network ⇒ Open mode ⇒ runner binds host's
        // /etc/resolv.conf (same source/destination).
        let spec = minimal_spec();
        let r = render_runner_unit(&spec).unwrap();
        let body = r
            .drop_ins
            .get("15-resolv.conf")
            .expect("15-resolv.conf must be present for every runner");
        assert!(body.contains("BindReadOnlyPaths=/etc/resolv.conf"));
        // Source != netns path.
        assert!(!body.contains("/run/ghars/netns-resolv/"));
    }

    #[test]
    fn render_resolv_bind_netns_mode_binds_netns_source() {
        // Netns mode ⇒ runner binds the per-runner file written by
        // `_netns-setup` to /etc/resolv.conf (source:dest form).
        let mut spec = minimal_spec();
        spec.network = Some(EffectiveNetworkBinding {
            name: "buck2-isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![EgressRule {
                    addr: "192.168.2.84".into(),
                    port: PortSpec::Single(3128),
                    proto: Proto::Tcp,
                    comment: None,
                }],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
        });
        let r = render_runner_unit(&spec).unwrap();
        let body = r.drop_ins.get("15-resolv.conf").unwrap();
        assert!(
            body.contains("BindReadOnlyPaths=/run/ghars/netns-resolv/buckos:/etc/resolv.conf",)
        );
        // The bare host path must NOT be present.
        assert!(
            !body
                .lines()
                .any(|l| l.trim() == "BindReadOnlyPaths=/etc/resolv.conf")
        );
    }

    #[test]
    fn template_omits_etc_resolv_conf_to_avoid_dedup_conflict() {
        // systemd's mount-list dedup keeps the FIRST same-destination
        // entry (src/core/namespace.c:drop_duplicates). To swap the
        // /etc/resolv.conf source per-runner the template must not bind
        // it; the 15-resolv.conf drop-in is the sole source.
        let body = runner_template_text();
        // The template's `BindReadOnlyPaths=/etc/hosts /etc/nsswitch.conf`
        // line must NOT include /etc/resolv.conf as a token.
        let resolv_line = body
            .lines()
            .find(|l| l.starts_with("BindReadOnlyPaths=") && l.contains("/etc/hosts"));
        let line = resolv_line.expect("etc/hosts bind line missing");
        assert!(
            !line.split_whitespace().any(|tok| tok == "/etc/resolv.conf"),
            "template line {line:?} must omit /etc/resolv.conf"
        );
    }

    #[test]
    fn render_emits_memory_when_set() {
        let mut spec = minimal_spec();
        spec.memory_max = Some("110G".into());
        let r = render_runner_unit(&spec).unwrap();
        let m = r.drop_ins.get("10-memory.conf").unwrap();
        assert!(m.contains("MemoryMax=110G"));
    }

    #[test]
    fn render_emits_hardening_when_overridden() {
        let mut spec = minimal_spec();
        spec.hardening.protect_control_groups = Some(true);
        spec.hardening.restrict_realtime = Some(true);
        spec.hardening.extra_syscalls = vec!["clone3".into(), "rseq".into()];
        spec.hardening.etc_bind_style = EtcBindStyle::Broad;
        let r = render_runner_unit(&spec).unwrap();
        let h = r.drop_ins.get("20-hardening.conf").unwrap();
        assert!(h.contains("ProtectControlGroups=yes"));
        assert!(h.contains("RestrictRealtime=yes"));
        assert!(h.contains("SystemCallFilter=clone3 rseq"));
        assert!(h.contains("BindReadOnlyPaths=/etc"));
        // Sanity: no kvm-related lines or warnings when kvm wasn't
        // touched in the override.
        assert!(!h.lines().any(|l| l.starts_with("DeviceAllow")));
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn render_hardening_kvm_true_emits_device_allow() {
        // Explicit kvm=true is an override (the template default agrees,
        // but the operator's intent is recorded). The drop-in re-emits
        // `DeviceAllow=/dev/kvm rw` rather than relying on the template
        // alone; this also exercises the reset-on-empty validator
        // pass-through (a non-empty DeviceAllow line never triggers the
        // empty-reset rule).
        let mut spec = minimal_spec();
        spec.hardening.kvm = Some(true);
        let r = render_runner_unit(&spec).unwrap();
        let h = r.drop_ins.get("20-hardening.conf").unwrap();
        assert!(h.contains("DeviceAllow=/dev/kvm rw"));
        // Importantly: no bare `DeviceAllow=` reset present.
        assert!(
            !h.lines()
                .any(|l| l == "DeviceAllow=" || l == "DeviceAllow= ")
        );
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn render_hardening_kvm_false_resets_device_allow_and_warns() {
        // kvm=false must emit `DeviceAllow=` (empty
        // reset) so the template's `DeviceAllow=/dev/kvm rw` is
        // revoked. Combined with the template's `DevicePolicy=closed`,
        // this denies all device access. The renderer surfaces a
        // warning so apply prints "kvm=false drops /dev/kvm rw" to the
        // operator before executing.
        let mut spec = minimal_spec();
        spec.hardening.kvm = Some(false);
        let r = render_runner_unit(&spec).unwrap();
        let h = r.drop_ins.get("20-hardening.conf").unwrap();
        assert!(
            h.lines().any(|l| l == "DeviceAllow="),
            "expected bare `DeviceAllow=` reset line in:\n{h}"
        );
        assert!(!h.contains("/dev/kvm rw"));
        // The warning carries the runner name and explains the
        // consequence to the operator.
        assert_eq!(r.warnings.len(), 1);
        let w = &r.warnings[0];
        assert!(w.contains("buckos"));
        assert!(w.contains("kvm=false"));
        assert!(w.contains("DeviceAllow=/dev/kvm rw"));
    }

    #[test]
    fn render_omits_30_cache_pool_for_ccache_filesystem_only() {
        let mut spec = minimal_spec();
        spec.caches.push(EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Ccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        let r = render_runner_unit(&spec).unwrap();
        // ccache-only pools use the filesystem-mode mechanism — no
        // ghars-cache@ unit dependency, no BindPaths to a pool dir,
        // no sccache server, no LAYER 1 Environment= directives. With
        // nothing structurally meaningful to emit, render_cache_pool
        // returns None and the 30-cache-pool.conf drop-in is absent
        // from RenderedUnit.drop_ins entirely — the apply layer's
        // DropInChangeKind::Removed branch will delete any stub left
        // over on disk from before this gate landed.
        assert!(
            !r.drop_ins.contains_key("30-cache-pool.conf"),
            "ccache-only pools must omit 30-cache-pool.conf (no LAYER 1 \
             directives to carry; CCACHE_DIR/CCACHE_MAXSIZE live in \
             LAYER 2 .env): got drop_ins {:?}",
            r.drop_ins.keys().collect::<Vec<_>>()
        );
    }

    /// Last-line-of-defense regression pin for a multi-ccache spec
    /// reaching the renderer via direct `EffectiveRunnerSpec`
    /// construction (bypassing `validate_no_duplicate_cache_kinds` at
    /// config-load and the parallel `lower_to_effective` gate).
    ///
    /// Multi-ccache bindings produce no structurally-meaningful drop-in
    /// content — the ccache branch in `render_cache_pool` is empty by
    /// design (CCACHE_DIR / CCACHE_MAXSIZE live in LAYER 2 .env, owned
    /// by `render_runner_env_file`; the trust-zone-shared CCACHE_DIR
    /// plus last-writer-wins CCACHE_MAXSIZE in .env is what ccache
    /// actually consumes). With nothing to emit, the renderer returns
    /// None and the 30-cache-pool.conf drop-in is absent from
    /// RenderedUnit.drop_ins entirely.
    ///
    /// Pins the renderer-side absence so a future regression that
    /// re-introduces per-binding LAYER 1 emission (and thereby a
    /// misleading `systemctl cat` view) fails this test immediately.
    #[test]
    fn render_omits_30_cache_pool_for_multi_ccache_only_spec() {
        let mut spec = minimal_spec();
        spec.caches.push(EffectiveCacheBinding {
            name: "obj-a".into(),
            kinds: vec![CacheKind::Ccache],
            size: "50G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        spec.caches.push(EffectiveCacheBinding {
            name: "obj-b".into(),
            kinds: vec![CacheKind::Ccache],
            size: "100G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        let r = render_runner_unit(&spec).unwrap();
        assert!(
            !r.drop_ins.contains_key("30-cache-pool.conf"),
            "multi-ccache spec must omit 30-cache-pool.conf (no LAYER 1 \
             directives produced — all CCACHE_* live in LAYER 2 .env): \
             got drop_ins {:?}",
            r.drop_ins.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn render_emits_cache_pool_for_sccache() {
        let mut spec = minimal_spec();
        spec.caches.push(EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        });
        let r = render_runner_unit(&spec).unwrap();
        let c = r.drop_ins.get("30-cache-pool.conf").unwrap();
        assert!(c.contains("SCCACHE_SERVER_UDS=/run/ghars/cache-build.sock"));
        assert!(c.contains("SCCACHE_NO_DAEMON=1"));
        assert!(c.contains("BindPaths="));
        assert!(c.contains("/run/ghars"));
    }

    #[test]
    fn render_emits_network_for_netns() {
        let mut spec = minimal_spec();
        let net_spec = NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec!["192.168.2.84/32".parse::<IpNet>().unwrap()],
            ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
            restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        };
        spec.network = Some(EffectiveNetworkBinding {
            name: "buck2-isolated".into(),
            spec: net_spec,
            subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
        });
        let r = render_runner_unit(&spec).unwrap();
        let n = r.drop_ins.get("40-network.conf").unwrap();
        assert!(n.contains("Requires=ghars-net@buckos.service"));
        assert!(n.contains("BindsTo=ghars-net@buckos.service"));
        assert!(n.contains("NetworkNamespacePath=/var/run/netns/ghars-buckos"));
        assert!(n.contains("IPAddressAllow=192.168.2.84/32"));
        assert!(n.contains("IPAddressDeny=0.0.0.0/0"));
        assert!(n.contains("RestrictAddressFamilies=AF_UNIX AF_INET"));
        // Identity drop-in must record the netns subnet.
        let id = r.drop_ins.get("00-ghars.conf").unwrap();
        assert!(id.contains("X-Ghars-Netns-Subnet=10.200.0.0/30"));
    }

    /// Defense-in-depth gate: an Open-mode binding with no
    /// cgroup-BPF policy fields reaching `render_network` is a
    /// bug-shape input (the production lowering path collapses such
    /// bindings to `spec.network = None` before the renderer runs).
    /// The renderer returns `Ok(None)` rather than emitting an
    /// empty `[Service]` section, so test fixtures that bypass
    /// `lower_to_effective` (this one) still produce no drop-in.
    #[test]
    fn render_skips_network_for_open_mode_with_empty_cgroup_bpf() {
        let mut spec = minimal_spec();
        let net_spec = NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        };
        spec.network = Some(EffectiveNetworkBinding {
            name: "open".into(),
            spec: net_spec,
            subnet: None,
        });
        let r = render_runner_unit(&spec).unwrap();
        assert!(!r.drop_ins.contains_key("40-network.conf"));
    }

    /// Open-mode binding carrying ALL THREE of `ip_deny` / `ip_allow`
    /// / `restrict_address_families` MUST emit a `40-network.conf`
    /// with the cgroup-BPF directives but WITHOUT the
    /// namespace-bound scaffolding
    /// (`Requires=`/`BindsTo=`/`After=ghars-net@…`,
    /// `NetworkNamespacePath=`). Open mode has no per-runner netns,
    /// so the side-unit dependencies and the bind-mount path do not
    /// apply; emitting them would force the unit to fail-closed
    /// against a non-existent ghars-net@ side-unit.
    #[test]
    fn render_emits_cgroup_bpf_only_for_open_mode_with_all_fields() {
        let mut spec = minimal_spec();
        let net_spec = NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
            ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
            restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        };
        spec.network = Some(EffectiveNetworkBinding {
            name: "hostnet".into(),
            spec: net_spec,
            subnet: None,
        });
        let r = render_runner_unit(&spec).unwrap();
        let n = r
            .drop_ins
            .get("40-network.conf")
            .expect("open mode with cgroup-BPF directives must emit 40-network.conf");
        // Cgroup-BPF directives present.
        assert!(n.contains("IPAddressAllow=10.0.0.0/8"));
        assert!(n.contains("IPAddressDeny=0.0.0.0/0"));
        assert!(n.contains("RestrictAddressFamilies=AF_UNIX AF_INET"));
        // Namespace-scoped scaffolding absent.
        assert!(
            !n.contains("Requires=ghars-net@"),
            "open mode must not Require ghars-net@: {n}"
        );
        assert!(
            !n.contains("BindsTo=ghars-net@"),
            "open mode must not BindsTo ghars-net@: {n}"
        );
        assert!(
            !n.contains("After=ghars-net@"),
            "open mode must not order After= ghars-net@: {n}"
        );
        assert!(
            !n.contains("NetworkNamespacePath="),
            "open mode must not bind a netns path: {n}"
        );
        // No [Unit] section header at all (the netns scaffolding is
        // the only [Unit] contributor in this drop-in).
        assert!(
            !n.contains("[Unit]"),
            "open mode 40-network.conf must not carry a [Unit] section: {n}"
        );
    }

    /// Open-mode runs with ONLY `ip_deny` set MUST still emit the
    /// drop-in. Mirrors the `ip_allow_only` and
    /// `restrict_address_families_only` shape tests: each cgroup-BPF
    /// field on its own must trigger emission. Together with the
    /// other two single-field tests, this pins each field as an
    /// independent emission trigger so a future regression that
    /// gates emission on (e.g.) "`ip_allow` OR
    /// `restrict_address_families`" (omitting `ip_deny`) surfaces
    /// here.
    #[test]
    fn render_emits_cgroup_bpf_for_open_mode_with_ip_deny_only() {
        let mut spec = minimal_spec();
        spec.network = Some(EffectiveNetworkBinding {
            name: "hostnet".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Open,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
                restrict_address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: None,
        });
        let r = render_runner_unit(&spec).unwrap();
        let n = r
            .drop_ins
            .get("40-network.conf")
            .expect("ip_deny alone in open mode must emit 40-network.conf");
        assert!(n.contains("IPAddressDeny=0.0.0.0/0"));
        assert!(!n.contains("IPAddressAllow="));
        assert!(!n.contains("RestrictAddressFamilies="));
        assert!(!n.contains("NetworkNamespacePath="));
    }

    /// Open-mode runs with only one of the cgroup-BPF fields set
    /// MUST still emit the drop-in. Pin every single-field shape so a
    /// future regression that gates emission on (e.g.) `ip_deny`
    /// alone surfaces here.
    #[test]
    fn render_emits_cgroup_bpf_for_open_mode_with_ip_allow_only() {
        let mut spec = minimal_spec();
        spec.network = Some(EffectiveNetworkBinding {
            name: "hostnet".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Open,
                allowed_egress: vec![],
                ip_allow: vec!["192.0.2.0/24".parse::<IpNet>().unwrap()],
                ip_deny: vec![],
                restrict_address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: None,
        });
        let r = render_runner_unit(&spec).unwrap();
        let n = r
            .drop_ins
            .get("40-network.conf")
            .expect("ip_allow alone in open mode must emit 40-network.conf");
        assert!(n.contains("IPAddressAllow=192.0.2.0/24"));
        assert!(!n.contains("IPAddressDeny="));
        assert!(!n.contains("RestrictAddressFamilies="));
        assert!(!n.contains("NetworkNamespacePath="));
    }

    #[test]
    fn render_emits_cgroup_bpf_for_open_mode_with_restrict_address_families_only() {
        let mut spec = minimal_spec();
        spec.network = Some(EffectiveNetworkBinding {
            name: "hostnet".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Open,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec!["AF_INET".into()],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: None,
        });
        let r = render_runner_unit(&spec).unwrap();
        let n = r
            .drop_ins
            .get("40-network.conf")
            .expect("restrict_address_families alone in open mode must emit 40-network.conf");
        assert!(n.contains("RestrictAddressFamilies=AF_INET"));
        assert!(!n.contains("IPAddressAllow="));
        assert!(!n.contains("IPAddressDeny="));
        assert!(!n.contains("NetworkNamespacePath="));
    }

    /// `X-Ghars-Netns-Subnet=` is Netns-scoped per the
    /// `filesystem-layout` annotation table. An Open-mode binding
    /// has `subnet = None` (no /30 allocated), so the renderer's
    /// `if let Some(subnet) = net.subnet` gate suppresses the
    /// annotation; otherwise an operator reading `00-ghars.conf`
    /// would conclude a netns had been allocated.
    #[test]
    fn render_identity_omits_netns_subnet_annotation_for_open_mode() {
        let mut spec = minimal_spec();
        spec.network = Some(EffectiveNetworkBinding {
            name: "hostnet".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Open,
                allowed_egress: vec![],
                ip_allow: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
                ip_deny: vec![],
                restrict_address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: None,
        });
        let r = render_runner_unit(&spec).unwrap();
        let id = r.drop_ins.get("00-ghars.conf").unwrap();
        // Network mode is still annotated as "open" so the plan
        // classifier's Open↔Netns transition detector still works.
        assert!(id.contains("X-Ghars-Network-Mode=open"));
        // No subnet line — Open-mode bindings have subnet = None so
        // the renderer's presence-gate suppresses the annotation.
        assert!(
            !id.contains("X-Ghars-Netns-Subnet="),
            "open-mode binding must not emit X-Ghars-Netns-Subnet, got:\n{id}"
        );
    }

    #[test]
    fn render_emits_proxy() {
        let mut spec = minimal_spec();
        spec.proxy = Some(ProxySpec {
            http: Some("http://192.168.2.84:3128".into()),
            https: Some("http://192.168.2.84:3128".into()),
            no_proxy: vec!["192.168.2.84".into()],
            ca_certs: vec![CaCertBinding {
                env: "REQUESTS_CA_BUNDLE".into(),
                path: Utf8PathBuf::from("/etc/pki/tls/certs/ca-bundle.crt"),
            }],
        });
        let r = render_runner_unit(&spec).unwrap();
        let p = r.drop_ins.get("60-proxy.conf").unwrap();
        assert!(p.contains("Environment=HTTP_PROXY=http://192.168.2.84:3128"));
        assert!(p.contains("Environment=http_proxy=http://192.168.2.84:3128"));
        assert!(p.contains("Environment=NO_PROXY=192.168.2.84"));
        assert!(p.contains("Environment=REQUESTS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt"));
        // SEC-08: no `-` prefix on proxy CA cert paths — missing CA
        // must fail the unit start, not silently fall back to system roots.
        assert!(p.contains("BindReadOnlyPaths=/etc/pki/tls/certs/ca-bundle.crt"));
        assert!(!p.contains("BindReadOnlyPaths=-/etc/pki/tls/certs/ca-bundle.crt"));
    }

    #[test]
    fn render_emits_hooks() {
        let mut spec = minimal_spec();
        spec.hooks = Some(HooksSpec {
            pre_job: Some(Utf8PathBuf::from("/opt/gha/pre-job.sh")),
            post_job: Some(Utf8PathBuf::from("/opt/gha/post-job.sh")),
        });
        let r = render_runner_unit(&spec).unwrap();
        let h = r.drop_ins.get("70-hooks.conf").unwrap();
        assert!(h.contains("Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/gha/pre-job.sh"));
        assert!(h.contains("Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/opt/gha/post-job.sh"));
        // Parent dir deduped.
        assert!(h.contains("BindReadOnlyPaths=/opt/gha"));
    }

    // Drop-in interaction tests. systemd treats list-typed
    // directives (RestrictAddressFamilies, BindReadOnlyPaths,
    // SystemCallFilter, ...) as APPEND across drop-ins — every line
    // contributes to the union, the LAST one does not "win". The
    // tests below pin that contract for the directive pairs that the
    // ghars renderer can emit from MULTIPLE drop-ins simultaneously,
    // so a future edit that accidentally rewrites one of these to
    // "scalar override" semantics fails immediately.
    //
    // What "compose" means here in test terms: render_runner_unit
    // produces text bytes; both contributing drop-ins MUST be present
    // in the output map AND each MUST contain the directive line we
    // expect. systemd's load-time merge then unions them. We do NOT
    // re-implement systemd's parser; we verify the inputs to the
    // parser (the bytes ghars writes) so a regression to "only emit
    // one drop-in" is caught.

    #[test]
    fn restrict_address_families_composes_across_hardening_and_network() {
        // 20-hardening.conf and 40-network.conf both emit
        // `RestrictAddressFamilies=`. The union {AF_UNIX, AF_INET,
        // AF_NETLINK} is the operator's intent — hardening scopes the
        // global policy, network adds netns-specific families.
        let mut spec = minimal_spec();
        spec.hardening.restrict_address_families = vec!["AF_UNIX".into(), "AF_NETLINK".into()];
        spec.network = Some(EffectiveNetworkBinding {
            name: "buck2-isolated".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![EgressRule {
                    addr: "192.168.2.84".into(),
                    port: PortSpec::Single(3128),
                    proto: Proto::Tcp,
                    comment: None,
                }],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
        });
        let r = render_runner_unit(&spec).unwrap();
        let h = r
            .drop_ins
            .get("20-hardening.conf")
            .expect("hardening drop-in present");
        let n = r
            .drop_ins
            .get("40-network.conf")
            .expect("network drop-in present");
        // Each drop-in carries its OWN RestrictAddressFamilies= line —
        // systemd will union them at load time. Pin both lines.
        assert!(
            h.lines()
                .any(|l| l == "RestrictAddressFamilies=AF_UNIX AF_NETLINK"),
            "hardening drop-in missing RestrictAddressFamilies, got:\n{h}"
        );
        assert!(
            n.lines()
                .any(|l| l == "RestrictAddressFamilies=AF_UNIX AF_INET"),
            "network drop-in missing RestrictAddressFamilies, got:\n{n}"
        );
        // Neither drop-in emits a bare `RestrictAddressFamilies=` reset
        // (that would erase the union per systemd.exec(5)
        // RestrictAddressFamilies — bare `=` resets the allowlist).
        for body in [h, n] {
            assert!(
                !body.lines().any(|l| l.trim() == "RestrictAddressFamilies="),
                "drop-in must not reset the allowlist, got:\n{body}"
            );
        }
    }

    /// Same composition contract under Open mode. The Open
    /// `40-network.conf` drop-in carries cgroup-BPF directives
    /// only (no namespace bind), but `RestrictAddressFamilies=` is
    /// one of those directives — it lives at the cgroup layer, not
    /// the namespace layer, so it composes across drop-ins
    /// identically in either mode. Pinning Open-mode composition
    /// here mirrors the existing Netns test so a future regression
    /// that gates `RestrictAddressFamilies=` emission on Netns mode
    /// (instead of on the field being non-empty) surfaces.
    #[test]
    fn restrict_address_families_composes_across_hardening_and_open_network() {
        let mut spec = minimal_spec();
        spec.hardening.restrict_address_families = vec!["AF_UNIX".into(), "AF_NETLINK".into()];
        spec.network = Some(EffectiveNetworkBinding {
            name: "hostnet".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Open,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: None,
        });
        let r = render_runner_unit(&spec).unwrap();
        let h = r
            .drop_ins
            .get("20-hardening.conf")
            .expect("hardening drop-in present");
        let n = r
            .drop_ins
            .get("40-network.conf")
            .expect("open-mode network drop-in present (cgroup-BPF directives non-empty)");
        // Each drop-in carries its OWN RestrictAddressFamilies= line.
        assert!(
            h.lines()
                .any(|l| l == "RestrictAddressFamilies=AF_UNIX AF_NETLINK"),
            "hardening drop-in missing RestrictAddressFamilies, got:\n{h}"
        );
        assert!(
            n.lines()
                .any(|l| l == "RestrictAddressFamilies=AF_UNIX AF_INET"),
            "open network drop-in missing RestrictAddressFamilies, got:\n{n}"
        );
        // Neither drop-in emits a bare reset.
        for body in [h, n] {
            assert!(
                !body.lines().any(|l| l.trim() == "RestrictAddressFamilies="),
                "drop-in must not reset the allowlist, got:\n{body}"
            );
        }
        // Open-mode-specific anti-properties: the network drop-in
        // must NOT carry the namespace scaffolding even though it
        // emits `RestrictAddressFamilies=`.
        assert!(
            !n.contains("[Unit]"),
            "open-mode 40-network.conf must not carry [Unit] section, got:\n{n}"
        );
        assert!(
            !n.contains("NetworkNamespacePath="),
            "open-mode 40-network.conf must not bind a netns path, got:\n{n}"
        );
    }

    #[test]
    fn restrict_address_families_drop_ins_load_in_numeric_order() {
        // BTreeMap iteration is alphabetic by key, which for the
        // numeric-prefix drop-in basenames (`20-hardening.conf` <
        // `40-network.conf`) is the same as systemd's load order
        // (lower numbers load first per Part 9). Pin that the
        // map's keys come out in the right order so plan output and
        // any future "concatenate drop-ins for systemd-analyze
        // verify" code observes the same order systemd will use.
        let mut spec = minimal_spec();
        spec.hardening.restrict_address_families = vec!["AF_UNIX".into()];
        spec.network = Some(EffectiveNetworkBinding {
            name: "ci-net".into(),
            spec: NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![EgressRule {
                    addr: "10.0.0.1".into(),
                    port: PortSpec::Single(443),
                    proto: Proto::Tcp,
                    comment: None,
                }],
                ip_allow: vec![],
                ip_deny: vec![],
                restrict_address_families: vec!["AF_INET".into()],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
            subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
        });
        let r = render_runner_unit(&spec).unwrap();
        let keys: Vec<&str> = r.drop_ins.keys().map(String::as_str).collect();
        let h_idx = keys.iter().position(|k| *k == "20-hardening.conf").unwrap();
        let n_idx = keys.iter().position(|k| *k == "40-network.conf").unwrap();
        assert!(
            h_idx < n_idx,
            "hardening (20) must precede network (40); got keys {keys:?}"
        );
    }

    #[test]
    fn bind_readonly_paths_composes_across_hardening_proxy_hooks() {
        // BindReadOnlyPaths is emitted from up to THREE drop-ins:
        // - 20-hardening (extra_bind_paths + etc_bind_style=Broad)
        // - 60-proxy (CA cert paths)
        // - 70-hooks (parent dirs of pre/post-job scripts)
        // systemd unions all of them. Pin that each drop-in carries
        // its own bytes and that none of them emit a bare reset.
        let mut spec = minimal_spec();
        spec.hardening.extra_bind_paths = vec![Utf8PathBuf::from("/opt/internal-tools")];
        spec.proxy = Some(ProxySpec {
            http: Some("http://10.0.0.1:3128".into()),
            https: Some("http://10.0.0.1:3128".into()),
            no_proxy: vec![],
            ca_certs: vec![CaCertBinding {
                env: "REQUESTS_CA_BUNDLE".into(),
                path: Utf8PathBuf::from("/etc/pki/tls/certs/ca-bundle.crt"),
            }],
        });
        spec.hooks = Some(HooksSpec {
            pre_job: Some(Utf8PathBuf::from("/opt/gha-hooks/pre-job.sh")),
            post_job: Some(Utf8PathBuf::from("/opt/gha-hooks/post-job.sh")),
        });
        let r = render_runner_unit(&spec).unwrap();
        let h = r
            .drop_ins
            .get("20-hardening.conf")
            .expect("hardening present");
        let p = r.drop_ins.get("60-proxy.conf").expect("proxy present");
        let k = r.drop_ins.get("70-hooks.conf").expect("hooks present");

        assert!(
            h.lines()
                .any(|l| l == "BindReadOnlyPaths=/opt/internal-tools"),
            "hardening drop-in missing extra_bind_paths line, got:\n{h}"
        );
        assert!(
            p.lines()
                .any(|l| l == "BindReadOnlyPaths=/etc/pki/tls/certs/ca-bundle.crt"),
            "proxy drop-in missing CA cert bind line, got:\n{p}"
        );
        assert!(
            k.lines().any(|l| l == "BindReadOnlyPaths=/opt/gha-hooks"),
            "hooks drop-in missing parent-dir bind line, got:\n{k}"
        );

        // None of these drop-ins emit a bare BindReadOnlyPaths=
        // reset — that would silently erase the template's curated
        // /etc list and the union of every other contributor.
        for (name, body) in [("hardening", h), ("proxy", p), ("hooks", k)] {
            assert!(
                !body.lines().any(|l| l.trim() == "BindReadOnlyPaths="),
                "{name} drop-in emitted reset BindReadOnlyPaths=, got:\n{body}"
            );
        }
    }

    #[test]
    fn system_call_filter_composes_across_template_and_hardening() {
        // SystemCallFilter is emitted by:
        // - the runner template (baseline `@system-service ...` +
        //   the inverse `~@mount @clock ...` denylist)
        // - 20-hardening when `extra_syscalls` is non-empty
        // The union is what systemd enforces. Pin that the hardening
        // line is present alongside the template's two lines.
        let mut spec = minimal_spec();
        spec.hardening.extra_syscalls = vec!["clone3".into(), "rseq".into()];
        let r = render_runner_unit(&spec).unwrap();
        let template = &r.template;
        let h = r
            .drop_ins
            .get("20-hardening.conf")
            .expect("hardening present");

        // Template baseline (allowlist) + denylist must both be
        // present — same line count regardless of drop-in additions.
        assert!(
            template
                .lines()
                .any(|l| l.starts_with("SystemCallFilter=@system-service")),
            "template missing baseline allowlist"
        );
        assert!(
            template
                .lines()
                .any(|l| l.starts_with("SystemCallFilter=~@mount")),
            "template missing denylist"
        );
        // Hardening drop-in adds union members — operator can grow the
        // allowlist without rewriting the template.
        assert!(
            h.lines().any(|l| l == "SystemCallFilter=clone3 rseq"),
            "hardening drop-in missing extra syscalls, got:\n{h}"
        );

        // Hardening must not emit a bare SystemCallFilter=
        // reset (would erase BOTH template lines).
        assert!(
            !h.lines().any(|l| l.trim() == "SystemCallFilter="),
            "hardening drop-in emitted reset SystemCallFilter=, got:\n{h}"
        );
    }

    #[test]
    fn render_emits_numa_drop_in() {
        let mut spec = minimal_spec();
        spec.allowed_cpus = Some("0-31".into());
        spec.allowed_memory_nodes = Some("0".into());
        let r = render_runner_unit(&spec).unwrap();
        let n = r.drop_ins.get("50-numa.conf").unwrap();
        assert!(n.contains("AllowedCPUs=0-31"));
        assert!(n.contains("AllowedMemoryNodes=0"));
    }

    #[test]
    fn render_cache_drop_in_for_sccache_only() {
        let binding = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            // Pin sccache to /usr/local/bin to verify the renderer
            // emits the binding's path verbatim (not a hardcoded
            // /usr/bin/ prefix). The two-path probe in
            // resolve_cache_pool_paths covers cargo-install layouts;
            // this assertion guards that the renderer respects the
            // resolved value rather than re-hardcoding.
            sccache_path: Some("/usr/local/bin/sccache".into()),
            sleep_path: None,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let body = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
        assert!(body.contains("X-Ghars-Pool-Kinds=sccache"));
        assert!(body.contains("\nExecStart=/usr/local/bin/sccache --start-server\n"));
        // Sanity: the prior hardcoded /usr/bin/sccache path is no
        // longer emitted when the binding pins a different location.
        assert!(!body.contains("/usr/bin/sccache"));
        assert!(body.contains("SCCACHE_NO_DAEMON=1"));
        assert!(body.contains("SCCACHE_IDLE_TIMEOUT=0"));
        // ccache-specific env entries are absent. Anchor at line start
        // so we don't match the `CCACHE_DIR=` substring inside
        // `SCCACHE_DIR=` / `Environment=SCCACHE_DIR=`.
        assert!(
            !body
                .lines()
                .any(|l| l.starts_with("Environment=CCACHE_DIR=")
                    || l.starts_with("Environment=CCACHE_MAXSIZE="))
        );
    }

    #[test]
    fn render_cache_drop_in_for_ccache_only_uses_sleep_infinity() {
        let binding = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Ccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            // ccache-only pool: sccache_path stays None, sleep_path
            // pinned to /bin/sleep (the legacy non-merged-usr fallback)
            // to verify the renderer emits the resolved path verbatim
            // rather than the previous hardcoded /usr/bin/sleep.
            sccache_path: None,
            sleep_path: Some("/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let body = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
        assert!(body.contains("X-Ghars-Pool-Kinds=ccache"));
        assert!(body.contains("\nExecStart=/bin/sleep infinity\n"));
        // Sanity: the prior hardcoded /usr/bin/sleep is no longer
        // emitted when the binding pins a different location.
        assert!(!body.contains("/usr/bin/sleep"));
        // Post-#70: CCACHE_DIR is NO LONGER emitted on the cache
        // pool unit drop-in for ccache-only pools. The cache pool
        // unit's ExecStart is `sleep infinity` (the stub) — it
        // never reads CCACHE_DIR. The prior emission was dead code
        // that misled `systemctl cat` readers.
        assert!(
            !body.lines().any(|l| l.starts_with("Environment=CCACHE_DIR=")),
            "no `Environment=CCACHE_DIR=` expected on ccache-only cache pool unit (#70): {body}"
        );
        assert!(!body.contains("--start-server"));
    }

    #[test]
    fn render_cache_drop_in_for_both_kinds_emits_unified_unit() {
        let binding = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache, CacheKind::Ccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            // Pool serves both kinds — the sccache server takes
            // ExecStart and sleep_path is None (the renderer never
            // reads sleep for sccache-serving pools).
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let body = render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
        // Both env sets emit; the sccache server is the ExecStart.
        assert!(body.contains("CCACHE_DIR"));
        assert!(body.contains("SCCACHE_DIR"));
        assert!(body.contains("\nExecStart=/usr/bin/sccache --start-server\n"));
    }

    #[test]
    fn cache_template_sets_umask_0077_for_uds_mode() {
        // sccache UDS mode is kernel-enforced at vfs_mknod time (Linux
        // net/unix/af_unix.c:unix_bind_bsd:1349 —
        // `umode_t mode = S_IFSOCK | (SOCK_INODE(...)->i_mode & ~current_umask())`).
        // sccache's UnixListener::bind (sccache server.rs:511,
        // commands.rs:104) performs no chmod after bind, so the
        // kernel-applied mode is final. UMask=0077 in the template
        // makes the resulting socket mode 0600 (owner rw, group/others
        // denied) atomically — no TOCTOU window between bind() and a
        // chmod shim. Reach is owner-DAC: the cache server and the
        // runners in its trust_zone share the same DynamicUser-allocated
        // UID (User=ghars-tz-<TRUST_ZONE> in both unit drop-ins);
        // runners in other trust_zones get EACCES at connect(). This
        // test pins the template directive so a future cleanup pass
        // can't drop it without surfacing the regression.
        let body = cache_template_text();
        assert!(
            body.contains("\nUMask=0077\n"),
            "cache template must set UMask=0077 for sccache UDS mode 0600; got body:\n{body}"
        );
    }

    #[test]
    fn render_cache_drop_in_relies_on_template_umask_no_exec_start_post_shim() {
        // sccache UDS mode enforcement lives in the cache template
        // (UMask=0077), not the per-pool drop-in. The drop-in must
        // NOT emit a chmod ExecStartPost — the chmod-after-bind shim
        // is rejected because of the TOCTOU window between bind()
        // returning and chmod() landing during which a non-owner
        // could connect. UMask= closes the window at vfs_mknod time.
        // This test pins both pool kinds (sccache and ccache-only)
        // to confirm neither emits ExecStartPost.
        for kinds in [
            vec![CacheKind::Sccache],
            vec![CacheKind::Ccache],
            vec![CacheKind::Sccache, CacheKind::Ccache],
        ] {
            let serves_sccache = kinds.contains(&CacheKind::Sccache);
            let binding = EffectiveCacheBinding {
                name: "build".into(),
                kinds,
                size: "200G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
                sccache_path: serves_sccache.then(|| "/usr/bin/sccache".into()),
                sleep_path: (!serves_sccache).then(|| "/usr/bin/sleep".into()),
                renderer_schema: crate::systemd::RENDERER_SCHEMA,
            };
            let body =
                render_cache_drop_in(&binding, "/etc/ghars/ghars.toml", "sha256:abcd").unwrap();
            assert!(
                !body.contains("ExecStartPost"),
                "cache drop-in must NOT emit ExecStartPost — \
                 mode enforcement is solved at the template level via UMask=0077. \
                 got body:\n{body}"
            );
        }
    }
}
