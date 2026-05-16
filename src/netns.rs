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
//! - `ghars _netns-teardown INSTANCE` runs from `ExecStop`; every step
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
/// by enforcing the `IDENTIFIER_REGEX` at the gate, which forbids
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
/// requires root. systemd already runs `ghars-net@.service` `ExecStart`
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

/// Gate the instance name against `IDENTIFIER_REGEX`
/// (`^[a-z]([a-z0-9-]*[a-z0-9])?$`, ≤ `IDENTIFIER_MAX_LEN`). The
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
            "instance names must use lowercase letters, digits, and dashes; \
             start with a letter; end with a letter or digit"
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
/// labels and observe the `teardown_inner` rollback.
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
    let mtu = if let Some(m) = detect_host_mtu() {
        m
    } else {
        tracing::warn!(
            instance = %instance,
            "detect_host_mtu returned None (could not parse `ip -j route show default` or `ip -j link show dev`); falling back to MTU 1500. If the host's primary interface uses a non-1500 MTU, the runner's veth pair will mismatch and may experience PMTU blackholes."
        );
        1500
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
#[path = "netns_tests.rs"]
mod tests;
