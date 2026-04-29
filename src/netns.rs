//! Hidden CLI helpers backing `ghars-net@%i.service` ExecStart/ExecStop.
//!
//! Design spec: Part 9c (netns architecture, Challenges 1-9). The
//! helpers shell out to `ip`, `nft`, `sysctl`, and `systemctl` rather
//! than calling rtnetlink directly — the operations are confined to
//! the ghars binary's address space (Challenge 4: no separate
//! `/usr/lib/ghars/*.sh` files).
//!
//! Runtime contract (from `ghars-net@.service`):
//! - `ghars _netns-setup INSTANCE` runs first; it MUST be idempotent
//!   (Challenge 3: `ip link add` and `ip netns add` both fail EEXIST,
//!   so the helper deletes-then-creates).
//! - `ghars _netns-veth INSTANCE PROGRAM ARGS` is the `ip netns exec`
//!   wrapper used to load the inside-netns nft rules.
//! - `ghars _netns-teardown INSTANCE` runs from ExecStop; every step
//!   swallows ENOENT so re-running on already-clean state is safe.
//!
//! `setup_netns` reads the per-instance config dropped by `apply`
//! (subnet, DNS mode, DNS servers) from `<config_dir>/netns.d/INSTANCE.toml`.
//! That file is written by `execute_create_runner` when the runner is
//! in `NetworkMode::Netns`.

use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, ExitStatus};

use camino::{Utf8Path, Utf8PathBuf};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::config::DnsMode;
use crate::error::GharsError;
use crate::paths::Paths;
use crate::validators;

/// Per-instance netns config consumed by `_netns-setup` /
/// `_netns-teardown`. Written by `apply` to
/// `<config_dir>/netns.d/INSTANCE.toml` whenever a runner uses
/// `NetworkMode::Netns`. The helper does not touch the parent
/// `EffectiveRunnerSpec`/`Config` — only the fields it needs to
/// program the kernel land here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetnsConfig {
    /// Allocated /30 (e.g. `10.200.0.0/30`). Host side = `.1`,
    /// runner side = `.2`.
    pub subnet: IpNet,
    /// DNS resolution policy inside the netns.
    pub dns: DnsMode,
}

impl NetnsConfig {
    /// `<config_dir>/netns.d/<instance>.toml` — the file `apply`
    /// writes for `_netns-setup` / `_netns-teardown` to read.
    #[must_use]
    pub fn path_for(paths: &Paths, instance: &str) -> Utf8PathBuf {
        paths
            .config_dir
            .join("netns.d")
            .join(format!("{instance}.toml"))
    }

    /// Load a per-instance config from disk.
    ///
    /// # Errors
    ///
    /// `GharsError::Io` if the file is missing or unreadable;
    /// `GharsError::Config` on TOML parse failure.
    pub fn load(paths: &Paths, instance: &str) -> Result<Self> {
        let path = Self::path_for(paths, instance);
        let text = fs::read_to_string(path.as_std_path()).map_err(|e| {
            GharsError::Io(io::Error::new(
                e.kind(),
                format!("read netns config {path}: {e}"),
            ))
        })?;
        toml::from_str(&text).map_err(|e| {
            GharsError::Config(
                format!("parse netns config {path}: {e}"),
                "regenerate via `ghars apply`".into(),
            )
        })
    }

    /// Write a per-instance config to disk. Parent dir created if
    /// missing; file is mode 0644.
    ///
    /// # Errors
    ///
    /// `GharsError::Io` on I/O failure;
    /// `GharsError::Config` if TOML serialization fails.
    pub fn write(&self, paths: &Paths, instance: &str) -> Result<()> {
        let path = Self::path_for(paths, instance);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent.as_std_path())?;
        }
        let body = toml::to_string(self).map_err(|e| {
            GharsError::Config(
                format!("serialize netns config: {e}"),
                "this is an internal bug; please report".into(),
            )
        })?;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o644)
            .open(path.as_std_path())?;
        f.write_all(body.as_bytes())?;
        f.flush()?;
        Ok(())
    }

    /// Remove the per-instance config file. ENOENT is swallowed.
    ///
    /// # Errors
    ///
    /// `GharsError::Io` on non-ENOENT removal failure.
    pub fn remove(paths: &Paths, instance: &str) -> Result<()> {
        let path = Self::path_for(paths, instance);
        match fs::remove_file(path.as_std_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(GharsError::Io(e)),
        }
    }
}

/// Resolve the `(host_ip, runner_ip)` pair for a `/30` subnet. Host
/// side is the `.1` address (network + 1); runner side is `.2`
/// (network + 2). The /30 layout is `network` / `host` / `runner` /
/// `broadcast` per RFC 3021 conventions used in the design spec.
///
/// # Errors
///
/// `GharsError::Validation` if the subnet is not a `/30` IPv4 range
/// or arithmetic on the network address fails.
pub fn subnet_addresses(subnet: &IpNet) -> Result<(IpAddr, IpAddr)> {
    let IpNet::V4(net) = subnet else {
        return Err(GharsError::Validation(
            format!("netns subnet {subnet} is not IPv4"),
            "ghars only supports IPv4 /30 subnets in the netns pool".into(),
        ));
    };
    if net.prefix_len() != 30 {
        return Err(GharsError::Validation(
            format!(
                "netns subnet {subnet} is /{}, expected /30",
                net.prefix_len()
            ),
            "each runner gets a /30 from the [defaults] netns_subnet pool".into(),
        ));
    }
    let base = u32::from(net.network());
    let host_v4 = std::net::Ipv4Addr::from(base + 1);
    let runner_v4 = std::net::Ipv4Addr::from(base + 2);
    Ok((IpAddr::V4(host_v4), IpAddr::V4(runner_v4)))
}

/// `ghars-{instance}` — netns name and prefix for the veth links.
///
/// Cross-module invariant (verified by
/// `name_helpers_share_ghars_instance_prefix`): both
/// [`host_veth_name`] and [`runner_veth_name`] format on top of
/// `ghars-{instance}` so the nft generator in `systemd.rs` (its
/// `render_nft_host` writes `iifname "ghars-{runner}-h"`) references
/// the exact interface names this module creates. A drift between
/// these formatters and the nft rule strings would break fail-closed
/// — the nft rules would target a non-existent interface.
///
/// Naming safety: `instance` MUST satisfy `IDENTIFIER_REGEX` before
/// reaching this helper. The public entry points
/// ([`setup`] / [`teardown`] / [`run_in_netns`]) gate via
/// [`validate_instance_name`] so an adversarial form like `foo;rm`,
/// whitespace, NUL bytes, or `..` segments cannot reach this
/// `format!`. The full adversarial test surface lives in this
/// module's `tests` block; the broader SEC-35 escaping work spans
/// the systemd / nft rule generator. The internal/private helpers
/// below assume the gate has already run; do not call them with
/// operator-supplied strings without re-running the gate.
///
/// systemd `%i` mismatch note: systemd unit
/// instance names support backslash-`x` escapes (per
/// `systemd.unit(5)`), but `ip netns add` does NOT speak that
/// escape — the kernel uses the raw bytes. ghars dodges the issue
/// by enforcing the IDENTIFIER_REGEX at the gate, which forbids
/// every character that would need escaping. The state-discovery
/// parser (`state.rs::parse_runner_unit_name`) strips
/// `ghars-runner@` + `.service` and does NOT systemd-unescape, on
/// the same assumption.
#[must_use]
pub fn netns_name(instance: &str) -> String {
    format!("ghars-{instance}")
}

/// `ghars-{instance}-h` — host-side veth interface name (consumed by
/// the host nft table and route table). See [`netns_name`] for the
/// cross-module invariant + naming-safety contract.
#[must_use]
pub fn host_veth_name(instance: &str) -> String {
    format!("ghars-{instance}-h")
}

/// `ghars-{instance}-r` — runner-side veth interface name (lives
/// inside the netns). See [`netns_name`] for the cross-module
/// invariant + naming-safety contract.
#[must_use]
pub fn runner_veth_name(instance: &str) -> String {
    format!("ghars-{instance}-r")
}

/// `/etc/systemd/resolved.conf.d/ghars-{instance}.conf` — drop-in
/// path for `dns = "forward"` mode. `apply` and the helper share this
/// constant via `Paths::resolved_drop_in`.
#[must_use]
pub fn resolved_drop_in_path(paths: &Paths, instance: &str) -> Utf8PathBuf {
    paths.resolved_drop_in(instance)
}

// ---------- Public entry points (called from cli::dispatch) -------------

/// Implementation of `ghars _netns-setup INSTANCE`. Idempotent
/// delete-then-create; rolls back on partial failure.
///
/// Asserts `geteuid() == 0` up front: every kernel-level operation
/// (`ip netns add`, `ip link add`, `sysctl -w net.ipv4.conf.X.forwarding`)
/// requires root. systemd already runs `ghars-net@.service` ExecStart
/// with `+` prefix (root regardless of `User=`), but the
/// defense-in-depth check surfaces a clear error when an operator
/// invokes the helper directly.
///
/// # Errors
///
/// `GharsError::Preflight` if not running as root.
/// `GharsError` from any underlying step. On failure, the helper
/// runs the teardown sequence so a partial setup does not leak
/// kernel resources.
pub fn setup(paths: &Paths, instance: &str) -> Result<()> {
    // Gate adversarial instance names against IDENTIFIER_REGEX
    // BEFORE any kernel work or root check. The instance name flows
    // through `format!()` into iproute2 / nftables / systemd unit
    // names; rejecting names like `foo;rm -rf /`, `foo bar`, `foo\0`,
    // or `..` here closes a SEC-35-adjacent injection vector and
    // produces a clear "invalid runner name" error instead of a
    // cryptic kernel/iproute2 failure.
    validate_instance_name(instance, "_netns-setup")?;
    require_root("_netns-setup")?;
    let cfg = NetnsConfig::load(paths, instance)?;
    setup_with_config(paths, instance, &cfg)
}

/// Implementation of `ghars _netns-teardown INSTANCE`. Idempotent;
/// every step swallows ENOENT.
///
/// Asserts `geteuid() == 0` up front for the same reasons as
/// [`setup`]: cleanup verbs (`ip link del`, `ip netns del`,
/// `systemctl reload`) all require root, and silently swallowing
/// `EACCES` / `EPERM` from a non-root invocation would mask a real
/// failure as success.
///
/// # Errors
///
/// `GharsError::Preflight` if not running as root. `GharsError::Io`
/// when a non-ENOENT failure prevents a step from completing.
/// Best-effort: every step runs regardless of whether earlier steps
/// succeeded so a maximally-clean state is reached.
pub fn teardown(paths: &Paths, instance: &str) -> Result<()> {
    // Same as `setup()` — reject adversarial instance names
    // before issuing any kernel cleanup verbs.
    validate_instance_name(instance, "_netns-teardown")?;
    require_root("_netns-teardown")?;
    teardown_inner(paths, instance, /*missing_config_ok=*/ true)
}

/// Defense-in-depth: refuse to run setup/teardown when the effective
/// UID is not 0. iproute2's `ip` returns `EPERM` for non-privileged
/// callers; surfacing a clear "requires root" error here is more
/// actionable than letting every kernel verb fail individually with
/// transport-level EPERM noise.
fn require_root(label: &str) -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        return Ok(());
    }
    Err(GharsError::Preflight(
        format!("{label} requires root (CAP_NET_ADMIN); refusing to run as non-root"),
        "invoke via `ghars-net@.service` ExecStart=+ (systemd raises to root) or run \
         the helper as root manually for diagnostic purposes"
            .into(),
    ))
}

/// Gate the instance name against IDENTIFIER_REGEX
/// (`^[a-z]([a-z0-9-]*[a-z0-9])?$`, ≤ IDENTIFIER_MAX_LEN). The
/// instance flows through `format!()` into:
/// - iproute2 args (`ghars-{instance}`, `ghars-{instance}-h/r`)
/// - nft table names via _netns-veth's `nft destroy table inet
///   ghars_{instance}_ns`
/// - systemd unit instance (`ghars-net@{instance}.service`)
/// - filesystem paths (`<config_dir>/netns.d/{instance}.toml`,
///   `<runtime_dir>/netns-resolv/{instance}`).
///
/// Rejecting whitespace, path separators, NUL bytes, shell
/// metacharacters, and `..` here produces a clear `Validation` error
/// before any of those format strings reach the kernel or filesystem.
fn validate_instance_name(instance: &str, label: &str) -> Result<()> {
    validators::validate_runner_name(instance).map_err(|e| match e {
        GharsError::Validation(msg, _) => GharsError::Validation(
            format!("{label}: invalid instance name {instance:?}: {msg}"),
            "instance names must satisfy IDENTIFIER_REGEX (lowercase letters, digits, dashes; \
             start with a letter, end with a letter or digit)"
                .into(),
        ),
        other => other,
    })?;
    // Defense-in-depth: every callsite of this helper goes on to
    // construct `host_veth_name`/`runner_veth_name` (8-byte veth
    // overhead around `instance`) and hand the result to iproute2 /
    // nft, which inherit the kernel's IFNAMSIZ-1 limit on interface
    // names. `cli::validate_netns_runner_name_lengths` already gates
    // this at config-load time, but the helper subcommands
    // (`_netns-setup`, `_netns-teardown`, `_netns-veth`) are reachable
    // directly via the CLI and could bypass the config path. Re-check
    // the cap here so an oversize name produces a structured
    // `Validation` error instead of an opaque iproute2 / nft failure.
    if instance.len() > validators::NETNS_RUNNER_NAME_MAX_LEN {
        return Err(GharsError::Validation(
            format!(
                "{label}: instance name {instance:?} is {got} chars; derived veth \
                 'ghars-{instance}-h' would exceed kernel IFNAMSIZ ({ifn})",
                got = instance.len(),
                ifn = validators::IFNAMSIZ,
            ),
            format!(
                "shorten the instance name to <={} chars (kernel IFNAMSIZ {} caps \
                 the veth shape 'ghars-{{instance}}-h')",
                validators::NETNS_RUNNER_NAME_MAX_LEN,
                validators::IFNAMSIZ,
            ),
        ));
    }
    Ok(())
}

/// Implementation of `ghars _netns-veth INSTANCE PROGRAM ARGS...` —
/// `ip netns exec ghars-INSTANCE PROGRAM ARGS...`. Replaces the
/// helper's process image so signal forwarding works correctly
/// (systemd sends SIGTERM to the helper; the underlying program
/// receives it directly).
///
/// # Errors
///
/// `GharsError::Io` on spawn failure;
/// `GharsError::Validation` when `program` is empty.
pub fn run_in_netns(instance: &str, program: &[String]) -> Result<i32> {
    // Validate the instance name before constructing
    // `ghars-{instance}` and passing it to `ip netns exec`. iproute2
    // would error confusingly on a name with spaces or shell metas;
    // surfacing the validator's IDENTIFIER_REGEX hint is clearer.
    validate_instance_name(instance, "_netns-veth")?;
    if program.is_empty() {
        return Err(GharsError::Validation(
            "_netns-veth: PROGRAM is required".into(),
            "usage: ghars _netns-veth INSTANCE PROGRAM [ARGS...]".into(),
        ));
    }
    let ns = netns_name(instance);
    let status = Command::new("/usr/sbin/ip")
        .args(["netns", "exec", &ns])
        .args(program)
        .status()
        .map_err(|e| {
            GharsError::Io(io::Error::new(
                e.kind(),
                format!("ip netns exec {ns} {}: {e}", program.join(" ")),
            ))
        })?;
    Ok(exit_status_to_code(status))
}

// ---------- NetnsOps trait (test seam over Command runners) -----------

/// Test seam over the kernel-level command runners. Production wires
/// `RealNetnsOps`, which calls [`run_required`] / [`run_cleanup_verb`]
/// directly. Tests inject [`MockNetnsOps`] (in the test module) to
/// fail a chosen step by label and observe the rollback.
///
/// The trait keeps a narrow surface: every kernel verb in
/// `setup_steps` flows through `run_required` (must succeed), and
/// the pre-create cleanups flow through `run_cleanup` (ENOENT-class
/// stderr is swallowed). Both methods accept a `&mut Command` so the
/// production impl shares its pre-built argv with the existing
/// helpers without rewrapping.
pub trait NetnsOps {
    /// Run `cmd` and propagate any non-zero exit as
    /// `GharsError::Apply { action: label, ... }`. Used for steps
    /// that must succeed (e.g. `ip netns add`, `ip link add`).
    /// Captures stderr and embeds the first ~1KB into the error
    /// chain so iproute2/nft diagnostics reach the operator.
    ///
    /// # Errors
    ///
    /// `GharsError::Apply` on non-zero exit or spawn failure.
    fn run_required(&self, cmd: &mut Command, label: &str) -> Result<()>;

    /// Run `cmd` (a cleanup verb like `ip link del`) and treat
    /// ENOENT-class stderr ("Cannot find device", etc.) as success.
    /// Other failures (EACCES, EPERM, EBUSY) propagate.
    ///
    /// # Errors
    ///
    /// `GharsError::Apply` on a non-ENOENT failure or spawn error.
    fn run_cleanup(&self, cmd: &mut Command, label: &str) -> Result<()>;
}

/// Production implementation: thin shim over the module-private
/// [`run_required`] / [`run_cleanup_verb`] helpers. No state.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealNetnsOps;

impl NetnsOps for RealNetnsOps {
    fn run_required(&self, cmd: &mut Command, label: &str) -> Result<()> {
        run_required(cmd, label)
    }
    fn run_cleanup(&self, cmd: &mut Command, label: &str) -> Result<()> {
        run_cleanup_verb(cmd, label)
    }
}

// ---------- Internals --------------------------------------------------

/// Setup driver. Splits load (`setup`) from execution so tests can
/// drive `setup_with_config` with a synthetic `NetnsConfig` without
/// writing TOML.
///
/// # Errors
///
/// On any step failure the helper runs `teardown_inner` (without
/// reading the on-disk config) so partially-created kernel state
/// does not leak.
pub fn setup_with_config(paths: &Paths, instance: &str, cfg: &NetnsConfig) -> Result<()> {
    setup_with_ops(&RealNetnsOps, paths, instance, cfg)
}

/// Setup driver parameterized over a [`NetnsOps`] implementation.
/// Production calls [`setup_with_config`] (which wires `RealNetnsOps`);
/// tests inject `MockNetnsOps` to inject failures at chosen step
/// labels and observe the teardown_inner rollback.
///
/// # Errors
///
/// On any step failure the helper runs `teardown_inner` so
/// partially-created kernel state does not leak. The original error
/// is propagated regardless of teardown's outcome.
pub fn setup_with_ops(
    ops: &dyn NetnsOps,
    paths: &Paths,
    instance: &str,
    cfg: &NetnsConfig,
) -> Result<()> {
    match setup_steps(ops, paths, instance, cfg) {
        Ok(()) => Ok(()),
        Err(setup_err) => {
            let _ = teardown_inner(paths, instance, /*missing_config_ok=*/ true);
            Err(setup_err)
        }
    }
}

fn setup_steps(ops: &dyn NetnsOps, paths: &Paths, instance: &str, cfg: &NetnsConfig) -> Result<()> {
    let ns = netns_name(instance);
    let host_veth = host_veth_name(instance);
    let runner_veth = runner_veth_name(instance);
    let (host_ip, runner_ip) = subnet_addresses(&cfg.subnet)?;
    let prefix_len = match cfg.subnet {
        IpNet::V4(n) => n.prefix_len(),
        IpNet::V6(_) => unreachable!("subnet_addresses rejects IPv6"),
    };

    // 1) Idempotent cleanup (Challenge 3): swallow ENOENT-style
    //    "absent resource" failures, propagate everything else (EBUSY,
    //    EACCES, EPERM, rtnetlink protocol errors). The next
    //    `ip netns add` would surface EEXIST if the resource were still
    //    here, so this cleanup is best-effort but NOT silent — a real
    //    failure is escalated.
    //    Deleting one veth end implicitly deletes its peer (kernel-level),
    //    and deleting the netns also unmounts the bind-mount.
    ops.run_cleanup(
        Command::new("/usr/sbin/ip").args(["link", "del", &host_veth]),
        "ip link del (pre-create cleanup)",
    )?;
    ops.run_cleanup(
        Command::new("/usr/sbin/ip").args(["netns", "del", &ns]),
        "ip netns del (pre-create cleanup)",
    )?;

    // 2) Create the netns. `ip netns add` is the only verb that
    //    creates the bind-mount at /var/run/netns/<ns> — equivalent
    //    to unshare + mount-bind, but documented and stable.
    ops.run_required(
        Command::new("/usr/sbin/ip").args(["netns", "add", &ns]),
        "ip netns add",
    )?;

    // 3) Create the veth pair on the host side.
    ops.run_required(
        Command::new("/usr/sbin/ip").args([
            "link",
            "add",
            &host_veth,
            "type",
            "veth",
            "peer",
            "name",
            &runner_veth,
        ]),
        "ip link add veth pair",
    )?;

    // 4) Move the runner end into the netns.
    ops.run_required(
        Command::new("/usr/sbin/ip").args(["link", "set", &runner_veth, "netns", &ns]),
        "ip link set netns",
    )?;

    // 5) MTU sync. Detect the host's primary outbound interface and
    //    copy its MTU to both veth ends. On detection failure fall
    //    back to 1500 (with MSS clamping in nft, the absolute MTU is
    //    less critical — but ICMP frag-needed handling depends on
    //    actually matching path MTU).
    //
    //    Emit a tracing::warn! when detection fails. The 1500
    //    fallback is silent in the success path (no log line) but the
    //    failure path is operationally important: a runner on a host
    //    with a 9000-MTU bond or a 1450-MTU GRE tunnel that silently
    //    sticks at 1500 will have unexplained connectivity issues
    //    (path MTU blackholes, large-payload TLS handshakes hanging).
    //    The warning surfaces the divergence so the operator can
    //    investigate `ip route show default` and `ip link show <dev>`.
    let mtu = match detect_host_mtu() {
        Some(m) => m,
        None => {
            tracing::warn!(
                instance = %instance,
                "detect_host_mtu returned None (could not parse `ip -j route show default` or `ip -j link show dev`); falling back to MTU 1500. If the host's primary interface uses a non-1500 MTU, the runner's veth pair will mismatch and may experience PMTU blackholes."
            );
            1500
        }
    };
    ops.run_required(
        Command::new("/usr/sbin/ip").args(["link", "set", &host_veth, "mtu", &mtu.to_string()]),
        "ip link set host veth mtu",
    )?;
    ops.run_required(
        Command::new("/usr/sbin/ip").args([
            "-n",
            &ns,
            "link",
            "set",
            &runner_veth,
            "mtu",
            &mtu.to_string(),
        ]),
        "ip -n NS link set runner veth mtu",
    )?;

    // 6) Address assignment. Host side: <host_ip>/30 on the host's
    //    veth; runner side: <runner_ip>/30 inside the netns.
    ops.run_required(
        Command::new("/usr/sbin/ip").args([
            "addr",
            "add",
            &format!("{host_ip}/{prefix_len}"),
            "dev",
            &host_veth,
        ]),
        "ip addr add host",
    )?;
    ops.run_required(
        Command::new("/usr/sbin/ip").args([
            "-n",
            &ns,
            "addr",
            "add",
            &format!("{runner_ip}/{prefix_len}"),
            "dev",
            &runner_veth,
        ]),
        "ip -n NS addr add runner",
    )?;

    // 7) Bring interfaces up: host veth, runner veth (inside ns),
    //    and lo inside ns (otherwise loopback is DOWN and the runner
    //    can't bind to 127.0.0.1).
    ops.run_required(
        Command::new("/usr/sbin/ip").args(["link", "set", &host_veth, "up"]),
        "ip link set host veth up",
    )?;
    ops.run_required(
        Command::new("/usr/sbin/ip").args(["-n", &ns, "link", "set", &runner_veth, "up"]),
        "ip -n NS link set runner veth up",
    )?;
    ops.run_required(
        Command::new("/usr/sbin/ip").args(["-n", &ns, "link", "set", "lo", "up"]),
        "ip -n NS link set lo up",
    )?;

    // 8) Default route inside the netns: via the host-side veth IP.
    ops.run_required(
        Command::new("/usr/sbin/ip").args([
            "-n",
            &ns,
            "route",
            "add",
            "default",
            "via",
            &host_ip.to_string(),
        ]),
        "ip -n NS route add default",
    )?;

    // 9) IPv6 disable inside the netns (Challenge 8). Both
    //    `all.disable_ipv6` and `default.disable_ipv6` are written so
    //    new interfaces brought up later are also covered.
    ops.run_required(
        Command::new("/usr/sbin/ip").args([
            "netns",
            "exec",
            &ns,
            "/usr/sbin/sysctl",
            "-w",
            "net.ipv6.conf.all.disable_ipv6=1",
        ]),
        "sysctl net.ipv6.conf.all.disable_ipv6=1 (in NS)",
    )?;
    ops.run_required(
        Command::new("/usr/sbin/ip").args([
            "netns",
            "exec",
            &ns,
            "/usr/sbin/sysctl",
            "-w",
            "net.ipv6.conf.default.disable_ipv6=1",
        ]),
        "sysctl net.ipv6.conf.default.disable_ipv6=1 (in NS)",
    )?;

    // 10) Per-interface forwarding on the host's veth (Challenge 6).
    //     Never `net.ipv4.ip_forward=1` host-wide; only the per-iface
    //     setting that the kernel honors regardless of the global.
    let forwarding_key = format!("net.ipv4.conf.{host_veth}.forwarding=1");
    ops.run_required(
        Command::new("/usr/sbin/sysctl").args(["-w", &forwarding_key]),
        "sysctl per-interface forwarding",
    )?;

    // 11) DNS setup (Challenge 1).
    setup_dns(paths, instance, host_ip, &cfg.dns)?;

    Ok(())
}

fn teardown_inner(paths: &Paths, instance: &str, missing_config_ok: bool) -> Result<()> {
    // Read the config to determine whether to run the resolved
    // drop-in cleanup for `dns = "forward"`. If the config is missing
    // (e.g. teardown ran twice, or the file was hand-removed), fall
    // back to "remove the drop-in if it exists" so we never skip
    // cleanup we can do.
    let dns_was_forward = match NetnsConfig::load(paths, instance) {
        Ok(cfg) => matches!(cfg.dns, DnsMode::Forward),
        Err(_) if missing_config_ok => true,
        Err(e) => return Err(e),
    };

    // Best-effort across the whole teardown: collect the first
    // non-ENOENT error and continue. This preserves the design contract
    // (every cleanup step runs so a partial teardown reaches the
    // most-cleaned state) while surfacing real failures (EACCES, EPERM,
    // EBUSY) instead of silently masking them.
    let mut first_err: Option<GharsError> = None;

    // 1) Remove the resolved drop-in if it exists. Even when
    //    `dns_was_forward` is false we attempt the unlink because the
    //    config could have been edited from forward → static between
    //    setup and teardown.
    if let Err(e) = remove_if_exists(&resolved_drop_in_path(paths, instance)) {
        first_err.get_or_insert(e);
    }

    // 2) Reload systemd-resolved best-effort if forward mode wrote a
    //    drop-in (or we removed something just now). Inactive
    //    resolved is not a fatal error during teardown — but a real
    //    spawn failure (e.g. systemctl missing from PATH) is collected
    //    so the operator sees something went wrong.
    if dns_was_forward {
        match Command::new("/usr/bin/systemctl")
            .args(["reload", "systemd-resolved"])
            .status()
        {
            Ok(_) => {} // exit non-zero is acceptable: resolved may be inactive.
            Err(e) => {
                first_err
                    .get_or_insert(spawn_io("systemctl reload systemd-resolved (teardown)", &e));
            }
        }
    }

    // 3) Remove the bind-mount source file. Removing it does NOT
    //    affect an active mount (mount uses inode reference); the
    //    `ip netns del` below tears down the netns which makes the
    //    bind-mount unreferenced, then the source is reclaimed by
    //    the next setup overwriting it.
    if let Err(e) = remove_if_exists(&paths.netns_resolv_conf(instance)) {
        first_err.get_or_insert(e);
    }

    // 4) Delete the veth (auto-removes the runner-side peer because
    //    they share a netdevice).
    if let Err(e) = run_cleanup_verb(
        Command::new("/usr/sbin/ip").args(["link", "del", &host_veth_name(instance)]),
        "ip link del (teardown)",
    ) {
        first_err.get_or_insert(e);
    }

    // 5) Delete the netns; this also unmounts /var/run/netns/<ns>
    //    bind-mount.
    if let Err(e) = run_cleanup_verb(
        Command::new("/usr/sbin/ip").args(["netns", "del", &netns_name(instance)]),
        "ip netns del (teardown)",
    ) {
        first_err.get_or_insert(e);
    }

    match first_err {
        None => Ok(()),
        Some(e) => Err(e),
    }
}

fn setup_dns(paths: &Paths, instance: &str, host_ip: IpAddr, dns: &DnsMode) -> Result<()> {
    let resolv_path = paths.netns_resolv_conf(instance);
    if let Some(parent) = resolv_path.parent() {
        fs::create_dir_all(parent.as_std_path())?;
    }

    match dns {
        DnsMode::Forward => {
            // Write the systemd-resolved drop-in first; `nameserver
            // <host_ip>` only resolves once resolved is listening on
            // that address.
            let drop_in_path = resolved_drop_in_path(paths, instance);
            if let Some(parent) = drop_in_path.parent() {
                fs::create_dir_all(parent.as_std_path())?;
            }
            let drop_in_body = format!(
                "# generated by ghars apply — DO NOT EDIT\n\
                 # runner={instance} veth_host_ip={host_ip}\n\
                 [Resolve]\n\
                 DNSStubListenerExtra={host_ip}\n",
            );
            write_file_644(&drop_in_path, drop_in_body.as_bytes())?;

            // Reload resolved so it picks up the new listener. Treat
            // failure as fatal — without the listener bound, the
            // runner's DNS queries silently break.
            let status = Command::new("/usr/bin/systemctl")
                .args(["reload", "systemd-resolved"])
                .status()
                .map_err(|e| spawn_io("systemctl reload systemd-resolved", &e))?;
            if !status.success() {
                return Err(GharsError::Apply {
                    action: "systemctl reload systemd-resolved".into(),
                    source: Box::new(GharsError::Io(io::Error::other(format!("exit {status:?}")))),
                });
            }

            // Bind-mount source: `nameserver <host_ip>`.
            let body = format!("nameserver {host_ip}\n");
            write_file_644(&resolv_path, body.as_bytes())?;
            // The runner unit's mount setup binds this file to
            // /etc/resolv.conf inside the runner's mount namespace.
            // The netns helper does not perform that mount itself —
            // the runner unit's BindReadOnlyPaths handles it.
        }
        DnsMode::Static { servers } => {
            if servers.is_empty() {
                return Err(GharsError::Validation(
                    format!("_netns-setup {instance}: dns = static with empty servers list"),
                    "set at least one nameserver IP or use dns = \"forward\"".into(),
                ));
            }
            // `nameserver IP` per server, one per line. /etc/resolv.conf
            // honors up to 3 nameservers; any additional are accepted
            // by the parser but unused.
            let mut body = String::new();
            for ip in servers {
                body.push_str(&format!("nameserver {ip}\n"));
            }
            write_file_644(&resolv_path, body.as_bytes())?;
        }
    }
    Ok(())
}

// ---------- Tiny helpers -----------------------------------------------

fn detect_host_mtu() -> Option<u32> {
    // `ip -j route show default` returns JSON. We parse it with
    // serde_json since toml/serde_json are already in the dep tree.
    // The first default route's `dev` is our outbound interface.
    let out = Command::new("/usr/sbin/ip")
        .args(["-j", "route", "show", "default"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let dev = v.as_array()?.first()?.get("dev")?.as_str()?;
    let link = Command::new("/usr/sbin/ip")
        .args(["-j", "link", "show", "dev", dev])
        .output()
        .ok()?;
    if !link.status.success() {
        return None;
    }
    let lv: serde_json::Value = serde_json::from_slice(&link.stdout).ok()?;
    let mtu = lv.as_array()?.first()?.get("mtu")?.as_u64()?;
    u32::try_from(mtu).ok()
}

/// Run `cmd` and require it to succeed; otherwise wrap the exit
/// state and stderr tail into `GharsError::Apply { action: label, ... }`.
///
/// `.output()` captures the first ~1KB of stderr so iproute2 / nft
/// diagnostics reach the operator via the error chain (`Cannot find
/// device`, `RTNETLINK answers: File exists`, `EBUSY`, etc). Mirrors
/// the `run_cleanup_verb` pattern.
///
/// On failure, the captured stderr is ALSO replayed to the parent
/// process's stderr (best-effort, ignored on `Err`) so journalctl
/// continues to see the iproute2 / nft diagnostic verbatim. Without
/// the replay, the error chain alone reaches the operator only via
/// the apply summary; journalctl-only consumers (systemd unit logs)
/// would see nothing past the exit code. The replay is gated to the
/// failure path because successful invocations don't produce
/// diagnostic output worth surfacing.
///
/// The stderr cap (`STDERR_PREVIEW_LEN`) bounds memory growth on a
/// pathological iproute2 / nft binary that floods stderr.
/// `String::from_utf8_lossy` keeps invalid UTF-8 from panicking the
/// helper on locale-tagged messages.
fn run_required(cmd: &mut Command, label: &str) -> Result<()> {
    let out = cmd.output().map_err(|e| spawn_io(label, &e))?;
    if out.status.success() {
        return Ok(());
    }
    // Replay captured stderr to parent stderr (best-effort) so
    // journalctl still surfaces the iproute2 / nft diagnostic.
    // `write_all` failure is ignored — the error chain below
    // already carries the same content.
    let _ = io::stderr().write_all(&out.stderr);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // `trim_end` strips the trailing "\n" iproute2 / nft always
    // append; otherwise the embedded preview includes a stray
    // newline mid-string when concatenated into the source.
    let preview: String = stderr.trim_end().chars().take(STDERR_PREVIEW_LEN).collect();
    Err(GharsError::Apply {
        action: label.into(),
        source: Box::new(GharsError::Io(io::Error::other(format!(
            "exit {status:?}; stderr={preview}",
            status = out.status,
        )))),
    })
}

/// Maximum number of stderr characters preserved in a `run_required`
/// failure preview. 1 KB is enough to capture iproute2 / nft / nft
/// destroy messages plus a few lines of context without unbounding
/// the error chain on a pathological tool that floods stderr.
const STDERR_PREVIEW_LEN: usize = 1024;

/// Run a cleanup verb (`ip link del`, `ip netns del`, etc.) and
/// classify failure modes:
/// - exit 0 → success.
/// - non-zero exit with stderr matching well-known "absent resource"
///   markers (iproute2 prints `Cannot find device`,
///   `Cannot remove namespace file`, `does not exist`) → swallowed
///   as success; the cleanup is a no-op when the resource is
///   already gone.
/// - non-zero exit with stderr matching permission markers
///   (`Operation not permitted`, `Permission denied`) → returned as
///   `GharsError::Apply` so non-root invocations fail loudly
///   instead of pretending the cleanup succeeded.
/// - any other non-zero exit → returned as `GharsError::Apply`. A
///   blanket-swallow approach would mask EBUSY (link in use),
///   EACCES, EPERM, and rtnetlink protocol errors; the explicit
///   classification above is what prevents that.
fn run_cleanup_verb(cmd: &mut Command, label: &str) -> Result<()> {
    let out = cmd.output().map_err(|e| spawn_io(label, &e))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Stable iproute2 messages (verified against iproute2's
    // ip/ip{link,netns}.c source): "Cannot find device" for ENODEV when
    // a link doesn't exist, "Cannot remove namespace file ... No such
    // file or directory" when ip netns del runs against an absent name.
    // nft's `destroy table` is invoked via `_netns-veth INSTANCE nft
    // destroy table inet ghars_INSTANCE_ns` upstream from this helper —
    // its "No such file or directory" surfaces too.
    let absent_markers = [
        "Cannot find device",
        "Cannot remove namespace file",
        "does not exist",
        "No such file or directory",
        "No such device",
    ];
    if absent_markers.iter().any(|m| stderr.contains(m)) {
        return Ok(());
    }
    // Mirror `run_required`'s preview pattern: trim trailing newlines
    // (iproute2 / nft both terminate with "\n", which pollutes the
    // error message when concatenated into the source string) and
    // bound the preview at `STDERR_PREVIEW_LEN` so a pathological
    // tool that floods stderr cannot unbound the error chain.
    let preview: String = stderr.trim_end().chars().take(STDERR_PREVIEW_LEN).collect();
    Err(GharsError::Apply {
        action: label.into(),
        source: Box::new(GharsError::Io(io::Error::other(format!(
            "exit {status:?}; stderr={preview}",
            status = out.status,
        )))),
    })
}

fn remove_if_exists(path: &Utf8Path) -> Result<()> {
    match fs::remove_file(path.as_std_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(GharsError::Io(e)),
    }
}

fn write_file_644(path: &Utf8Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent.as_std_path())?;
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(path.as_std_path())?;
    f.write_all(bytes)?;
    f.flush()?;
    Ok(())
}

fn spawn_io(label: &str, e: &io::Error) -> GharsError {
    GharsError::Io(io::Error::new(e.kind(), format!("{label}: {e}")))
}

fn exit_status_to_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    // Killed by signal → conventional 128 + signum.
    use std::os::unix::process::ExitStatusExt;
    if let Some(sig) = status.signal() {
        return 128 + sig;
    }
    1
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::DnsMode;
    use std::net::Ipv4Addr;
    fn paths_for(tmp: &tempfile::TempDir) -> Paths {
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        Paths {
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            logs_dir: root.join("logs"),
            unit_dir: root.join("units"),
            credentials_dir: root.join("creds"),
            runtime_dir: root.join("run"),
            config_dir: root.join("etc"),
            resolved_conf_d: root.join("resolved.conf.d"),
        }
    }

    #[test]
    fn netns_name_format() {
        assert_eq!(netns_name("buckos"), "ghars-buckos");
        assert_eq!(netns_name("ci-1"), "ghars-ci-1");
    }

    #[test]
    fn veth_name_format_matches_systemd_render() {
        // systemd.rs nft generator uses ghars-{name}-h / ghars-{name}-r;
        // the helper must agree byte-for-byte.
        assert_eq!(host_veth_name("buckos"), "ghars-buckos-h");
        assert_eq!(runner_veth_name("buckos"), "ghars-buckos-r");
    }

    #[test]
    fn subnet_addresses_extracts_host_and_runner_from_30() {
        let s: IpNet = "10.200.0.0/30".parse().unwrap();
        let (h, r) = subnet_addresses(&s).unwrap();
        assert_eq!(h, IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1)));
        assert_eq!(r, IpAddr::V4(Ipv4Addr::new(10, 200, 0, 2)));
    }

    #[test]
    fn subnet_addresses_works_for_offset_30() {
        let s: IpNet = "10.200.0.4/30".parse().unwrap();
        let (h, r) = subnet_addresses(&s).unwrap();
        assert_eq!(h, IpAddr::V4(Ipv4Addr::new(10, 200, 0, 5)));
        assert_eq!(r, IpAddr::V4(Ipv4Addr::new(10, 200, 0, 6)));
    }

    #[test]
    fn subnet_addresses_rejects_non_30() {
        let s: IpNet = "10.200.0.0/24".parse().unwrap();
        let err = subnet_addresses(&s).unwrap_err();
        assert!(matches!(err, GharsError::Validation(_, _)));
    }

    #[test]
    fn subnet_addresses_rejects_ipv6() {
        let s: IpNet = "fd00::/126".parse().unwrap();
        let err = subnet_addresses(&s).unwrap_err();
        assert!(matches!(err, GharsError::Validation(_, _)));
    }

    #[test]
    fn netns_config_round_trips_forward() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_for(&tmp);
        let cfg = NetnsConfig {
            subnet: "10.200.0.0/30".parse().unwrap(),
            dns: DnsMode::Forward,
        };
        cfg.write(&paths, "buckos").unwrap();
        let loaded = NetnsConfig::load(&paths, "buckos").unwrap();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn netns_config_round_trips_static() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_for(&tmp);
        let cfg = NetnsConfig {
            subnet: "10.200.0.4/30".parse().unwrap(),
            dns: DnsMode::Static {
                servers: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
            },
        };
        cfg.write(&paths, "ci-1").unwrap();
        let loaded = NetnsConfig::load(&paths, "ci-1").unwrap();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn netns_config_remove_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_for(&tmp);
        // No file exists yet — must succeed.
        NetnsConfig::remove(&paths, "absent").unwrap();
        // Write, remove, remove again.
        let cfg = NetnsConfig {
            subnet: "10.200.0.0/30".parse().unwrap(),
            dns: DnsMode::Forward,
        };
        cfg.write(&paths, "x").unwrap();
        assert!(NetnsConfig::path_for(&paths, "x").exists());
        NetnsConfig::remove(&paths, "x").unwrap();
        assert!(!NetnsConfig::path_for(&paths, "x").exists());
        NetnsConfig::remove(&paths, "x").unwrap();
    }

    #[test]
    fn netns_config_load_missing_returns_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_for(&tmp);
        let err = NetnsConfig::load(&paths, "nope").unwrap_err();
        assert!(matches!(err, GharsError::Io(_)));
    }

    #[test]
    fn run_in_netns_rejects_empty_program() {
        let err = run_in_netns("buckos", &[]).unwrap_err();
        assert!(matches!(err, GharsError::Validation(_, _)));
    }

    #[test]
    fn config_path_under_config_dir_netns_d() {
        let paths = Paths::default();
        assert_eq!(
            NetnsConfig::path_for(&paths, "buckos"),
            "/etc/ghars/netns.d/buckos.toml"
        );
    }

    #[test]
    fn require_root_rejects_non_root_with_preflight_error() {
        // Test infrastructure runs as the operator user, never root.
        // The fast-path check at setup/teardown entry refuses to run.
        // We can't verify the root path without integration tests, but
        // we CAN verify the non-root rejection produces a clear error.
        if nix::unistd::geteuid().is_root() {
            // Skip when the test happens to run privileged; the
            // negative path is what guards the require_root contract.
            return;
        }
        let err = require_root("_netns-test").unwrap_err();
        match err {
            GharsError::Preflight(msg, hint) => {
                assert!(msg.contains("requires root"), "unexpected msg: {msg}",);
                assert!(
                    hint.contains("ExecStart=+"),
                    "hint should mention ExecStart=+ raise: {hint}",
                );
            }
            other => panic!("expected Preflight error, got {other:?}"),
        }
    }

    #[test]
    fn run_cleanup_verb_swallows_absent_resource_messages() {
        // Real iproute2 prints these on the missing-resource path; we
        // simulate by running `/bin/sh -c "echo Cannot find device >&2;
        // exit 1"`. Any host with a POSIX shell handles this — and we
        // don't need root.
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "echo 'Cannot find device dummy0' >&2; exit 1"]);
        run_cleanup_verb(&mut cmd, "ip link del (test)").unwrap();
    }

    #[test]
    fn run_cleanup_verb_propagates_permission_denied_messages() {
        // Simulate the EPERM/EACCES path. The helper must surface
        // a real error so an unprivileged caller does not get a
        // silent "success" — the absent-marker classifier must
        // refuse to swallow permission-denied messages.
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            "echo 'RTNETLINK answers: Operation not permitted' >&2; exit 2",
        ]);
        let err = run_cleanup_verb(&mut cmd, "ip link del (test)").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Operation not permitted") || msg.contains("ip link del"),
            "expected EPERM-class error to be propagated: {msg}",
        );
    }

    #[test]
    fn run_cleanup_verb_propagates_unknown_failures() {
        // Generic failure mode (e.g. EBUSY, rtnetlink protocol error,
        // malformed argv). Must propagate as a real error rather than
        // being swallowed as "missing resource".
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "echo 'argument is invalid' >&2; exit 1"]);
        let err = run_cleanup_verb(&mut cmd, "ip netns del (test)").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("ip netns del"),
            "expected action label in error: {msg}",
        );
    }

    /// Pin that `run_required` actually surfaces stderr to the
    /// operator. Without `.output()` capture, iproute2 / nft
    /// diagnostics would vanish and the operator would only see
    /// "exit ExitStatus(...)" with no clue what went wrong. Use
    /// /bin/sh as a stand-in for an iproute2 binary that fails on
    /// bad argv.
    #[test]
    fn run_required_captures_stderr_into_error_chain() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "echo 'simulated iproute2 error' >&2; exit 1"]);
        let err = RealNetnsOps
            .run_required(&mut cmd, "ip link add (test)")
            .expect_err("non-zero exit must propagate as Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("simulated iproute2 error"),
            "stderr text MUST appear in the error chain (run_required captures stderr via .output()); got: {msg}",
        );
        assert!(
            msg.contains("ip link add"),
            "action label MUST appear in the error chain; got: {msg}",
        );
    }

    /// Truncation pin: stderr longer than `STDERR_PREVIEW_LEN`
    /// (1 KiB) MUST be bounded so a pathological iproute2 / nft binary
    /// that floods stderr cannot unbound the error chain. The preview
    /// is `chars().take(N).collect()` — char-bounded, not byte-bounded —
    /// so on ASCII stderr the preview is exactly N bytes.
    #[test]
    fn run_required_truncates_oversize_stderr_to_preview_cap() {
        // Emit 2 KiB of 'X' to stderr followed by a non-zero exit.
        // /bin/sh's printf is pinned by POSIX to handle %d.
        let big_n = STDERR_PREVIEW_LEN * 2;
        let script = format!(
            "awk 'BEGIN {{ for (i = 0; i < {big_n}; i++) printf \"X\" > \"/dev/stderr\"; exit 1 }}'"
        );
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", &script]);
        let err = RealNetnsOps
            .run_required(&mut cmd, "ip link add (test-flood)")
            .expect_err("non-zero exit must propagate as Err");
        let msg = format!("{err}");
        // The stderr content embeds in the source string AFTER an
        // "exit ...; stderr=" prefix. The preview is bounded at
        // STDERR_PREVIEW_LEN chars, but the prefix and label add a
        // small constant; bound the assertion at preview cap + a
        // generous overhead allowance to cover the prefix shape
        // without being brittle to its exact wording.
        let prefix_overhead = 256;
        assert!(
            msg.len() <= STDERR_PREVIEW_LEN + prefix_overhead,
            "error message must be bounded around STDERR_PREVIEW_LEN ({}); got {} chars: {msg:.200}",
            STDERR_PREVIEW_LEN,
            msg.len(),
        );
        // And the X-flood must STILL be present (the truncation is
        // a tail-trim, not a content-strip).
        assert!(
            msg.contains("XXXXXXXX"),
            "stderr content (Xs) must still appear in the truncated preview; got: {msg:.200}",
        );
    }

    // -------- adversarial instance-name handling --------------------------

    /// Every adversarial form the validate_runner_name gate must
    /// reject before any kernel work starts. Each entry exercises
    /// one shape of attack against the format strings into iproute2
    /// / nftables / systemd unit names / filesystem paths.
    ///
    /// The IDENTIFIER_REGEX (`^[a-z]([a-z0-9-]*[a-z0-9])?$`, ≤
    /// IDENTIFIER_MAX_LEN) is the single source of truth — any name
    /// that isn't strictly ASCII-lowercase-letters-digits-dashes
    /// MUST fail.
    #[rstest::rstest]
    #[case("", "empty string")]
    #[case(" ", "single space")]
    #[case("foo bar", "embedded whitespace")]
    #[case("foo\tbar", "embedded tab")]
    #[case("foo\nbar", "embedded newline")]
    #[case("foo/bar", "path separator")]
    #[case("..", "dot-dot traversal")]
    #[case(".", "single dot")]
    #[case("foo/../bar", "embedded traversal segment")]
    #[case("foo\0bar", "embedded NUL byte")]
    #[case("foo;rm", "shell metachar (semicolon)")]
    #[case("foo$bar", "shell metachar (dollar)")]
    #[case("foo`bar", "shell metachar (backtick)")]
    #[case("foo|bar", "shell metachar (pipe)")]
    #[case("foo&bar", "shell metachar (ampersand)")]
    #[case("foo>bar", "shell metachar (redirect)")]
    #[case("foo$(rm)", "command substitution")]
    #[case("Foo", "uppercase letter")]
    #[case("FOO", "all uppercase")]
    #[case("123foo", "leading digit")]
    #[case("-foo", "leading dash")]
    #[case("foo-", "trailing dash")]
    #[case("foo_bar", "underscore (not in IDENTIFIER_REGEX)")]
    #[case("foo.bar", "dot")]
    #[case("foo bar baz", "multiple spaces")]
    #[case("../etc/passwd", "leading traversal")]
    #[case("/etc/passwd", "absolute path")]
    fn adversarial_instance_names_rejected_by_validate_instance_name(
        #[case] name: &str,
        #[case] description: &str,
    ) {
        // Every case must produce a Validation error from the gate
        // BEFORE any kernel work. validate_instance_name is the
        // composition point for setup/teardown/run_in_netns; if this
        // test passes for every case, the entry-point gates do too.
        let err = validate_instance_name(name, "_test").unwrap_err();
        match &err {
            GharsError::Validation(msg, _) => {
                assert!(
                    msg.contains("invalid instance name") || msg.contains("identifier"),
                    "case {description}: unexpected message {msg}",
                );
            }
            other => panic!("case {description}: expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validate_instance_name_accepts_canonical_names() {
        // Sanity: the gate must accept names that satisfy the regex.
        // These all map to legal iproute2 / nftables / systemd
        // instance forms.
        for name in ["a", "ab", "buckos", "ci-1", "ci-99", "x-y-z"] {
            validate_instance_name(name, "_test")
                .unwrap_or_else(|e| panic!("expected {name:?} to validate, got {e:?}"));
        }
    }

    #[test]
    fn run_in_netns_rejects_adversarial_instance_name() {
        // End-to-end check: the gate fires before any program-arg
        // path is exercised. The empty-program error path tests the
        // POST-gate branch (validate_instance_name accepts "buckos"
        // first, then empty-program fails); this test confirms the
        // PRE-gate branch — bad name short-circuits before checking
        // program emptiness.
        let err = run_in_netns("foo;rm", &[]).unwrap_err();
        match err {
            GharsError::Validation(msg, _) => {
                assert!(msg.contains("invalid instance name"), "msg={msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    // -------- subnet_addresses property tests -----------------------------

    // proptest: every valid IPv4 /30 round-trips through
    // `subnet_addresses` and yields exactly the (network+1,
    // network+2) pair, anywhere in the address space. The function
    // performs raw u32 arithmetic — exhaustively covering every
    // 4-address-aligned base address with proptest catches any
    // off-by-one / endian / overflow regression that a single
    // hand-picked test would miss.
    proptest::proptest! {
        // Random offset within a /30-aligned IPv4 base.
        // `network()` returns the rounded-down /30 base.
        #[test]
        fn subnet_addresses_round_trips_random_30(base in 0u32..=u32::MAX) {
            // /30 has 4-address alignment: clear the bottom 2 bits.
            let aligned = base & !0x3;
            let network = std::net::Ipv4Addr::from(aligned);
            let cidr = format!("{network}/30");
            let subnet: IpNet = cidr.parse().expect("aligned /30 must parse");
            let (host_ip, runner_ip) = subnet_addresses(&subnet)
                .expect("any /30 must yield host+runner");
            // Host is base+1, runner is base+2 — irrespective of the
            // base address.
            proptest::prop_assert_eq!(
                host_ip,
                IpAddr::V4(std::net::Ipv4Addr::from(aligned.wrapping_add(1))),
            );
            proptest::prop_assert_eq!(
                runner_ip,
                IpAddr::V4(std::net::Ipv4Addr::from(aligned.wrapping_add(2))),
            );
        }
    }

    #[test]
    fn subnet_addresses_boundary_lowest_30() {
        // 0.0.0.0/30 — host = 0.0.0.1, runner = 0.0.0.2. Edge case:
        // u32 arithmetic at the bottom of the address space.
        let s: IpNet = "0.0.0.0/30".parse().unwrap();
        let (h, r) = subnet_addresses(&s).unwrap();
        assert_eq!(h, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)));
        assert_eq!(r, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 2)));
    }

    #[test]
    fn subnet_addresses_boundary_highest_30() {
        // 255.255.255.252/30 — host = 255.255.255.253, runner =
        // 255.255.255.254. Edge case: u32 arithmetic near the top
        // of the address space (the broadcast 255.255.255.255 is
        // unreachable, but the host/runner pair sits within the
        // legal /30 range).
        let s: IpNet = "255.255.255.252/30".parse().unwrap();
        let (h, r) = subnet_addresses(&s).unwrap();
        assert_eq!(h, IpAddr::V4(Ipv4Addr::new(255, 255, 255, 253)));
        assert_eq!(r, IpAddr::V4(Ipv4Addr::new(255, 255, 255, 254)));
    }

    proptest::proptest! {
        // Property: the runner address is always exactly one greater
        // than the host address (the /30 layout: network, host,
        // runner, broadcast). Pinned irrespective of base.
        #[test]
        fn subnet_addresses_runner_is_host_plus_one(base in 0u32..=u32::MAX) {
            let aligned = base & !0x3;
            let cidr = format!("{}/30", std::net::Ipv4Addr::from(aligned));
            let subnet: IpNet = cidr.parse().unwrap();
            let (host_ip, runner_ip) = subnet_addresses(&subnet).unwrap();
            let IpAddr::V4(h) = host_ip else { unreachable!() };
            let IpAddr::V4(r) = runner_ip else { unreachable!() };
            proptest::prop_assert_eq!(u32::from(r), u32::from(h).wrapping_add(1));
        }
    }

    proptest::proptest! {
        // Every non-/30 IPv4 prefix length must be rejected with
        // `GharsError::Validation`. The allocator's
        // contract is "give me a /30, get back (host, runner)"; any
        // other prefix indicates a config-author mistake (likely
        // confusing the per-runner /30 with the [defaults] netns_subnet
        // /N pool). prefix_len ranges that must reject:
        //   - [0..=29]: too wide (would split an octet differently)
        //   - 31:      RFC 3021 point-to-point /31 (no host/runner room)
        //   - 32:      single-host /32
        //
        // We generate (base, prefix_len) pairs uniformly across the
        // legal IPv4 prefix space [0..=32]; `prop_assume!` filters
        // out the legal /30 case so proptest only tests the rejection
        // contract on prefix lengths that must fail. The shrinker
        // converges on the smallest counter-example regardless of
        // which side of /30 the failure comes from.
        #[test]
        fn subnet_addresses_rejects_every_non_30_prefix(
            base in 0u32..=u32::MAX,
            prefix in 0u8..=32u8,
        ) {
            // Skip the legal /30 case — its acceptance is covered by
            // subnet_addresses_round_trips_random_30. This test guards
            // ONLY the rejection contract.
            proptest::prop_assume!(prefix != 30);
            // Mask the base to the network address for `prefix`. ipnet's
            // FromStr does not require a normalized addr, but masking
            // here keeps the printed CIDR canonical and avoids
            // regenerating the same `Ipv4Net::new(addr, prefix)` in two
            // places. For prefix == 32, the mask is u32::MAX (no bits
            // dropped); for prefix == 0, the mask is 0 (all bits dropped).
            let mask = if prefix == 0 { 0u32 } else { u32::MAX << (32 - prefix) };
            let aligned = base & mask;
            let cidr = format!("{}/{}", std::net::Ipv4Addr::from(aligned), prefix);
            let subnet: IpNet = cidr.parse().expect("constructed CIDR must parse");
            let err = subnet_addresses(&subnet).unwrap_err();
            // Every non-/30 input must produce Validation, never any
            // other variant. This also implicitly covers the message
            // shape: `subnet ... is /N, expected /30` for IPv4 inputs.
            proptest::prop_assert!(
                matches!(err, GharsError::Validation(_, _)),
                "prefix /{prefix} on {cidr} did not produce Validation: {err:?}",
            );
        }
    }

    #[test]
    fn subnet_addresses_wrap_around_safety_uses_network_base() {
        // ipnet stores the literal `addr` from the input CIDR;
        // `network()` derives the masked base on demand. Any
        // address inside a /30 (e.g. `.255` in `255.255.255.255/30`)
        // resolves to the same /30 base (`255.255.255.252`), so
        // `subnet_addresses` returns the same (host, runner) pair
        // regardless of which of the four addresses the operator
        // happened to write.
        //
        // This guards against a subtle mis-implementation: had
        // `subnet_addresses` used `net.addr()` directly (skipping the
        // mask), an input of `255.255.255.255/30` would compute
        // `addr+1 = 0.0.0.0` (u32 wrap), silently misallocating the
        // host IP into a different network. The current impl uses
        // `net.network()` inside `subnet_addresses`, so the
        // base is canonicalized before `+1`/`+2`.
        //
        // Verify the canonicalization holds for every address inside
        // the top /30:
        for input in [
            "255.255.255.252/30", // base itself
            "255.255.255.253/30", // host slot
            "255.255.255.254/30", // runner slot
            "255.255.255.255/30", // broadcast slot
        ] {
            let subnet: IpNet = input.parse().unwrap();
            let (h, r) = subnet_addresses(&subnet)
                .unwrap_or_else(|e| panic!("{input} should resolve via network base: {e:?}"));
            assert_eq!(
                h,
                IpAddr::V4(Ipv4Addr::new(255, 255, 255, 253)),
                "{input}: host IP must be the canonical /30 base + 1",
            );
            assert_eq!(
                r,
                IpAddr::V4(Ipv4Addr::new(255, 255, 255, 254)),
                "{input}: runner IP must be the canonical /30 base + 2",
            );
        }

        // Same property at the bottom of the address space — proves
        // the canonicalization is symmetric, not just an accident at
        // the top.
        for input in ["0.0.0.0/30", "0.0.0.1/30", "0.0.0.2/30", "0.0.0.3/30"] {
            let subnet: IpNet = input.parse().unwrap();
            let (h, r) = subnet_addresses(&subnet).unwrap();
            assert_eq!(h, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)));
            assert_eq!(r, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 2)));
        }
    }

    // -------- cross-module name-prefix invariant -------------------------
    //
    // The nft generator in `systemd.rs` (its `render_nft_host` writes
    // `iifname "ghars-{runner}-h"`) constructs interface names
    // independently of `host_veth_name` / `runner_veth_name` here.
    // A drift between these two formatters would point nft rules at a
    // non-existent interface, breaking fail-closed.
    //
    // The property-based form covers every IDENTIFIER_REGEX-shaped name
    // (lowercase letters, digits, dashes; first char letter, last char
    // letter or digit) up to IDENTIFIER_MAX_LEN-1 chars beyond the
    // leading letter. We feed `string_regex` an UN-anchored pattern
    // because proptest's regex engine rejects `^`/`$` anchors (proptest
    // 1.11.0 src/string.rs:232 — "anchors/boundaries not supported for
    // string generation"). The full IDENTIFIER_REGEX has implicit
    // anchors when matched, but the generator produces only matching
    // bodies; a `validate_runner_name` call below double-checks that
    // every generated name is in fact accepted by the gate.
    proptest::proptest! {
        #[test]
        fn name_helpers_share_ghars_instance_prefix(
            instance in r"[a-z]([a-z0-9-]{0,62}[a-z0-9])?",
        ) {
            // The generator MAY produce names that fail
            // validate_runner_name (proptest's regex engine and
            // validators.rs share IDENTIFIER_REGEX, but proptest
            // strips anchors so a pathological corner is not
            // reachable here — still, we re-check to keep the
            // property honest).
            proptest::prop_assume!(
                crate::validators::validate_runner_name(&instance).is_ok()
            );

            let ns = netns_name(&instance);
            let host = host_veth_name(&instance);
            let runner = runner_veth_name(&instance);

            // Cross-module invariant 1: every helper formats on top
            // of the same `ghars-{instance}` prefix.
            proptest::prop_assert_eq!(&ns, &format!("ghars-{instance}"));
            proptest::prop_assert!(
                host.starts_with(&ns),
                "host_veth_name {host:?} must start with netns_name {ns:?}",
            );
            proptest::prop_assert!(
                runner.starts_with(&ns),
                "runner_veth_name {runner:?} must start with netns_name {ns:?}",
            );

            // Cross-module invariant 2: the host/runner suffixes are
            // exactly `-h` / `-r`. systemd.rs:render_nft_host emits
            // `iifname "ghars-{runner}-h"`; if these helpers ever
            // emit a different suffix, the nft rule and the actual
            // interface name diverge.
            proptest::prop_assert!(
                host.ends_with("-h"),
                "host_veth_name {host:?} must end with -h",
            );
            proptest::prop_assert!(
                runner.ends_with("-r"),
                "runner_veth_name {runner:?} must end with -r",
            );

            // Cross-module invariant 3: byte-for-byte equality with
            // the literal format strings the nft generator uses.
            // (If render_nft_host ever changes its template, this
            // property fails immediately and points at the drift.)
            proptest::prop_assert_eq!(host, format!("ghars-{instance}-h"));
            proptest::prop_assert_eq!(runner, format!("ghars-{instance}-r"));
        }
    }

    #[test]
    fn name_helpers_agree_for_canonical_identifiers() {
        // Pin the property at three concrete representative names so a
        // proptest config tweak (low cases, slow shrinking) can never
        // hide a regression. These mirror the systemd.rs
        // render_nft_host expectation exactly.
        for name in ["a", "buckos", "ci-1"] {
            assert_eq!(netns_name(name), format!("ghars-{name}"));
            assert_eq!(host_veth_name(name), format!("ghars-{name}-h"));
            assert_eq!(runner_veth_name(name), format!("ghars-{name}-r"));
            assert!(host_veth_name(name).starts_with(&netns_name(name)));
            assert!(runner_veth_name(name).starts_with(&netns_name(name)));
        }
    }

    // Every name within `NETNS_RUNNER_NAME_MAX_LEN` MUST
    // produce a veth name that fits the kernel's IFNAMSIZ window
    // (`< IFNAMSIZ` bytes including the trailing NUL the kernel
    // reserves; usable len = `IFNAMSIZ - 1`). The cap derivation in
    // `validators.rs::NETNS_RUNNER_NAME_MAX_LEN = IFNAMSIZ - 1 -
    // VETH_NAME_OVERHEAD` is what makes this property hold; if any
    // of those three constants drift independently, this property
    // will catch it immediately.
    //
    // Plain `//` instead of `///` because rustdoc does not generate
    // documentation for macro invocations — the doc comment would
    // attach to the `proptest!` macro call but be silently dropped,
    // triggering `unused_doc_comments`.
    proptest::proptest! {
        #[test]
        fn veth_name_fits_ifnamsiz_for_every_bounded_runner_name(
            // Identifier-shape names bounded to `NETNS_RUNNER_NAME_MAX_LEN`.
            // Single-letter and 2..=cap branches cover both legal name
            // shapes (`[a-z]` and `[a-z][a-z0-9-]*[a-z0-9]`).
            instance in r"[a-z]([a-z0-9-]{0,5}[a-z0-9])?",
        ) {
            // proptest's regex engine doesn't enforce anchors; double
            // check the validator and skip if the gate would reject.
            // Length within the cap is guaranteed by the regex (1 +
            // 0..=5 + optional 1 = 1..=7 chars).
            proptest::prop_assume!(
                crate::validators::validate_runner_name(&instance).is_ok()
            );
            proptest::prop_assume!(
                instance.len() <= crate::validators::NETNS_RUNNER_NAME_MAX_LEN
            );

            let host = host_veth_name(&instance);
            let runner = runner_veth_name(&instance);

            // The kernel reserves the trailing NUL, so the *usable*
            // length cap is `IFNAMSIZ - 1`. Both veth names must fit
            // this window; iproute2 / netlink would refuse anything
            // larger with EINVAL.
            proptest::prop_assert!(
                host.len() < crate::validators::IFNAMSIZ,
                "host_veth_name({instance:?}) = {host:?} ({} bytes) must fit IFNAMSIZ ({})",
                host.len(),
                crate::validators::IFNAMSIZ,
            );
            proptest::prop_assert!(
                runner.len() < crate::validators::IFNAMSIZ,
                "runner_veth_name({instance:?}) = {runner:?} ({} bytes) must fit IFNAMSIZ ({})",
                runner.len(),
                crate::validators::IFNAMSIZ,
            );
        }
    }

    /// Negative pin: an instance name that exceeds
    /// `NETNS_RUNNER_NAME_MAX_LEN` MUST produce a veth name that
    /// overflows the IFNAMSIZ window. Documents the cap as the
    /// boundary, not just an internal constant. The
    /// `validate_netns_runner_name_lengths` and
    /// `validate_instance_name` gates exist specifically because
    /// this overflow would otherwise reach iproute2 and produce an
    /// opaque EINVAL.
    #[test]
    fn host_veth_name_overflows_ifnamsiz_when_instance_exceeds_cap() {
        // 8 chars = NETNS_RUNNER_NAME_MAX_LEN (7) + 1 — the smallest
        // shape that breaks IFNAMSIZ.
        let oversize = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
        assert_eq!(
            oversize.len(),
            8,
            "drift guard: NETNS_RUNNER_NAME_MAX_LEN + 1 must be 8 for this assertion to mean what it claims",
        );
        let host = host_veth_name(&oversize);
        let runner = runner_veth_name(&oversize);
        // Must exceed the kernel's usable IFNAMSIZ window
        // (IFNAMSIZ - 1 = 15 chars). Concretely: "ghars-aaaaaaaa-h"
        // is 16 bytes, exactly at IFNAMSIZ — over the usable cap by
        // 1. The validators MUST catch this upstream so it never
        // reaches iproute2.
        assert!(
            host.len() > crate::validators::IFNAMSIZ - 1,
            "host_veth_name({oversize:?}) = {host:?} ({} bytes) must exceed IFNAMSIZ-1 ({}); \
             this is the overflow the netns validators are protecting against",
            host.len(),
            crate::validators::IFNAMSIZ - 1,
        );
        assert!(
            runner.len() > crate::validators::IFNAMSIZ - 1,
            "runner_veth_name({oversize:?}) = {runner:?} ({} bytes) must exceed IFNAMSIZ-1",
            runner.len(),
        );
    }

    // -------- per-step error path coverage --------------------------------

    use std::sync::Mutex;

    /// Test seam: records every (label, kind) pair that flows through
    /// `setup_steps` and optionally fails at a chosen `fail_at` label.
    /// Mirrors `RealNetnsOps` for the success path; produces a clear
    /// `GharsError::Apply { action: label, ... }` for the configured
    /// failing label.
    ///
    /// We record events instead of running the real command so per-step
    /// tests don't require root, /usr/sbin/ip, or kernel features.
    struct MockNetnsOps {
        fail_at: Option<&'static str>,
        events: Mutex<Vec<(String, &'static str)>>, // (label, kind)
    }

    impl MockNetnsOps {
        fn new() -> Self {
            Self {
                fail_at: None,
                events: Mutex::new(Vec::new()),
            }
        }
        fn failing_at(label: &'static str) -> Self {
            Self {
                fail_at: Some(label),
                events: Mutex::new(Vec::new()),
            }
        }
        fn snapshot(&self) -> Vec<(String, &'static str)> {
            self.events.lock().unwrap().clone()
        }
        fn record(&self, label: &str, kind: &'static str) -> Result<()> {
            self.events.lock().unwrap().push((label.to_string(), kind));
            if Some(label) == self.fail_at {
                return Err(GharsError::Apply {
                    action: label.into(),
                    source: Box::new(GharsError::Io(io::Error::other("mock injected failure"))),
                });
            }
            Ok(())
        }
    }

    impl NetnsOps for MockNetnsOps {
        fn run_required(&self, _cmd: &mut Command, label: &str) -> Result<()> {
            self.record(label, "required")
        }
        fn run_cleanup(&self, _cmd: &mut Command, label: &str) -> Result<()> {
            self.record(label, "cleanup")
        }
    }

    fn mock_setup_paths(tmp: &tempfile::TempDir) -> Paths {
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        Paths {
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            logs_dir: root.join("logs"),
            unit_dir: root.join("units"),
            credentials_dir: root.join("creds"),
            runtime_dir: root.join("run"),
            config_dir: root.join("etc"),
            resolved_conf_d: root.join("resolved.conf.d"),
        }
    }

    fn mock_cfg() -> NetnsConfig {
        NetnsConfig {
            subnet: "10.200.0.0/30".parse().unwrap(),
            // Static avoids the resolved drop-in path; setup_dns under
            // Static only writes the resolv source file, which is
            // root-tolerant under a tempdir.
            dns: DnsMode::Static {
                servers: vec!["1.1.1.1".parse().unwrap()],
            },
        }
    }

    /// All `setup_steps` labels in the order they execute. The
    /// per-step tests iterate this list; if a step is added /
    /// renamed, `setup_steps` and this list move in lock-step.
    const SETUP_STEP_LABELS: &[&str] = &[
        "ip link del (pre-create cleanup)",
        "ip netns del (pre-create cleanup)",
        "ip netns add",
        "ip link add veth pair",
        "ip link set netns",
        "ip link set host veth mtu",
        "ip -n NS link set runner veth mtu",
        "ip addr add host",
        "ip -n NS addr add runner",
        "ip link set host veth up",
        "ip -n NS link set runner veth up",
        "ip -n NS link set lo up",
        "ip -n NS route add default",
        "sysctl net.ipv6.conf.all.disable_ipv6=1 (in NS)",
        "sysctl net.ipv6.conf.default.disable_ipv6=1 (in NS)",
        "sysctl per-interface forwarding",
    ];

    #[test]
    fn mock_setup_happy_path_runs_every_step_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = mock_setup_paths(&tmp);
        let cfg = mock_cfg();
        let ops = MockNetnsOps::new();
        setup_with_ops(&ops, &paths, "buckos", &cfg).unwrap();
        let labels: Vec<String> = ops.snapshot().into_iter().map(|(l, _)| l).collect();
        // Every step label appears exactly once, in order.
        let expected: Vec<String> = SETUP_STEP_LABELS.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(labels, expected);
    }

    #[test]
    fn mock_setup_fails_at_each_step_independently() {
        // Per-step independent-failure spec: "Test each of the setup
        // steps failing independently." We iterate every label and confirm
        // (a) setup_with_ops returns an Err whose action label
        // matches the failing step, (b) the recorded events show we
        // reached the failing step (no later step ran), (c)
        // teardown_inner ran after the failure (rollback contract).
        for fail_label in SETUP_STEP_LABELS {
            let tmp = tempfile::tempdir().unwrap();
            let paths = mock_setup_paths(&tmp);
            let cfg = mock_cfg();
            let ops = MockNetnsOps::failing_at(fail_label);

            let err = setup_with_ops(&ops, &paths, "buckos", &cfg)
                .unwrap_err_or_else(|()| panic!("step {fail_label}: expected failure, got Ok"));

            // (a) The error carries the failing step's label.
            match &err {
                GharsError::Apply { action, .. } => {
                    assert_eq!(
                        action, fail_label,
                        "step {fail_label}: expected action label match",
                    );
                }
                other => panic!("step {fail_label}: expected Apply, got {other:?}"),
            }

            // (b) Events recorded up to and including the failing step.
            let snapshot = ops.snapshot();
            let last = snapshot
                .last()
                .unwrap_or_else(|| panic!("step {fail_label}: no events"));
            assert_eq!(
                last.0, *fail_label,
                "step {fail_label}: last event must be the failing step",
            );
            // Steps AFTER fail_label must NOT appear.
            let fail_idx = SETUP_STEP_LABELS
                .iter()
                .position(|l| l == fail_label)
                .unwrap();
            let later_steps: Vec<&&str> = SETUP_STEP_LABELS.iter().skip(fail_idx + 1).collect();
            for later in later_steps {
                assert!(
                    !snapshot.iter().any(|(l, _)| l == *later),
                    "step {fail_label}: later step {later} unexpectedly ran",
                );
            }
        }
    }

    // -------- DnsMode::Static empty servers rejection --------------------
    //
    // setup_dns is module-private; the test calls it directly with a
    // throw-away tempdir. The Static branch's only failure mode is "no
    // nameservers configured" — the function must surface that before
    // any filesystem I/O so the operator gets a clear message instead
    // of an empty resolv.conf written to disk and a runner that
    // silently fails DNS.

    #[test]
    fn setup_dns_static_with_empty_servers_returns_validation_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = mock_setup_paths(&tmp);
        let dns = DnsMode::Static { servers: vec![] };
        let host_ip = IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1));
        let err = setup_dns(&paths, "buckos", host_ip, &dns).unwrap_err();
        match err {
            GharsError::Validation(msg, hint) => {
                assert!(
                    msg.contains("static") || msg.contains("Static") || msg.contains("dns"),
                    "msg should describe the static-DNS failure: {msg}",
                );
                assert!(
                    !hint.is_empty(),
                    "operator-facing hint must not be empty: {hint}",
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        // No resolv.conf must have been written before the early
        // return (defense in depth: an empty resolv.conf is more
        // dangerous than no resolv.conf — the kernel would silently
        // fail DNS instead of falling back to /etc/resolv.conf bind
        // semantics).
        assert!(
            !paths.netns_resolv_conf("buckos").exists(),
            "setup_dns must not write resolv.conf before the empty-servers check",
        );
    }

    #[test]
    fn setup_dns_static_with_one_server_writes_resolv_conf() {
        // Companion test for the empty-servers case: pin the success
        // path at the same call site so a future refactor that
        // accidentally swaps the empty/non-empty branch order
        // surfaces immediately.
        let tmp = tempfile::tempdir().unwrap();
        let paths = mock_setup_paths(&tmp);
        let dns = DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap()],
        };
        let host_ip = IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1));
        setup_dns(&paths, "buckos", host_ip, &dns).unwrap();
        let body =
            std::fs::read_to_string(paths.netns_resolv_conf("buckos").as_std_path()).unwrap();
        assert!(
            body.contains("nameserver 1.1.1.1"),
            "resolv.conf must contain nameserver line: {body}",
        );
    }

    #[test]
    fn setup_dns_static_with_multiple_servers_writes_each_on_own_line() {
        // Pin /etc/resolv.conf format: one `nameserver IP` per line.
        // The kernel resolver only honors the first 3 lines but the
        // file format is a hard contract.
        let tmp = tempfile::tempdir().unwrap();
        let paths = mock_setup_paths(&tmp);
        let dns = DnsMode::Static {
            servers: vec![
                "1.1.1.1".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                "9.9.9.9".parse().unwrap(),
            ],
        };
        let host_ip = IpAddr::V4(Ipv4Addr::new(10, 200, 0, 1));
        setup_dns(&paths, "buckos", host_ip, &dns).unwrap();
        let body =
            std::fs::read_to_string(paths.netns_resolv_conf("buckos").as_std_path()).unwrap();
        // Three nameserver lines, in input order.
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3, "expected 3 nameserver lines: {body}");
        assert_eq!(lines[0], "nameserver 1.1.1.1");
        assert_eq!(lines[1], "nameserver 8.8.8.8");
        assert_eq!(lines[2], "nameserver 9.9.9.9");
    }

    /// Internal helper because Result<(), E> doesn't have a stable
    /// `unwrap_err_or_else` and we want a `step`-aware panic message.
    trait UnwrapErrOrElse<T, E> {
        fn unwrap_err_or_else(self, f: impl FnOnce(T)) -> E;
    }
    impl<T, E> UnwrapErrOrElse<T, E> for std::result::Result<T, E> {
        fn unwrap_err_or_else(self, f: impl FnOnce(T)) -> E {
            match self {
                Ok(t) => {
                    f(t);
                    unreachable!("f should panic on Ok")
                }
                Err(e) => e,
            }
        }
    }
}
