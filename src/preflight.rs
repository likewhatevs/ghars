//! Preflight checks: OS supported, `/dev/kvm` + kvm group, systemd
//! version, `/run/systemd/system` + zbus connect, cgroup v2 + Seccomp +
//! `CONFIG_NET_NS` + `CAP_NET_ADMIN`, required tools present, root for
//! apply mode, `ptrace_scope` advisory.
//!
//! Design spec: Part 10 (Preflight). Surfaced by `ghars status`
//! (system-health section) and gated at apply-time via `run_preflight`.
//!
//! Behavior ported from `install_gha_runner.py:838-985`, with
//! design-spec extensions:
//!
//! - OS support widened to Ubuntu 24+, Fedora 40+, RHEL/CentOS/Rocky/
//!   `AlmaLinux` 10+ (systemd 254+ floor for `LogNamespace=`).
//! - systemd version queried over D-Bus (`Manager.Version`) and
//!   hard-rejected below 254.
//! - kernel-feature checks add empirical `unshare -n` for `CONFIG_NET_NS`
//!   and `CapEff` parse for `CAP_NET_ADMIN`.
//! - tools list extended with `nft`, `ip`, `sysctl`, and
//!   `systemd-analyze`.
//! - `ptrace_scope` (Yama LSM) read advisory; warn at < 2 (SEC-28).

use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::Command;

use zbus::blocking::{Connection, Proxy};

use crate::{GharsError, Result};

/// Minimum systemd major version. Below this, `LogNamespace=` is
/// unimplemented and the unit template fails to load.
pub const MIN_SYSTEMD_VERSION: u32 = 254;

/// One preflight check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// Display name (`OS`, `systemd`, `kvm`, `tools`, `kernel`, `root`,
    /// `ptrace_scope`).
    pub name: String,
    /// Pass / fail / warn / not-applicable.
    pub outcome: Outcome,
    /// One-line detail (distro+version on pass, what failed on fail).
    pub detail: String,
    /// Remediation hint (empty when `outcome == Pass`).
    pub hint: String,
}

/// Per-check outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Check passed.
    Pass,
    /// Check failed; `hint` describes remediation. Apply gate refuses.
    Fail,
    /// Advisory; non-blocking. Apply continues.
    Warn,
    /// Check skipped (e.g. apply-only check during plan).
    Skip,
}

impl CheckResult {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: Outcome::Pass,
            detail: detail.into(),
            hint: String::new(),
        }
    }

    fn fail(name: impl Into<String>, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: Outcome::Fail,
            detail: detail.into(),
            hint: hint.into(),
        }
    }

    fn warn(name: impl Into<String>, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: Outcome::Warn,
            detail: detail.into(),
            hint: hint.into(),
        }
    }

    fn skip(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: Outcome::Skip,
            detail: detail.into(),
            hint: String::new(),
        }
    }
}

/// Parse `/etc/os-release` into key/value pairs. Strips matched
/// surrounding double or single quotes from values; leaves bare values
/// intact.
///
/// Production callers go through [`preflight_os`] →
/// [`preflight_os_with_path`] (the test-seam variant), which calls
/// [`parse_os_release_at`] directly. This helper is retained as the
/// legacy entry point that pins the canonical path; allow(dead_code)
/// because no caller threads through here once `preflight_os_with_path`
/// is the single source of truth.
#[allow(dead_code)]
fn read_os_release() -> Result<std::collections::HashMap<String, String>> {
    parse_os_release_at(Path::new("/etc/os-release"))
}

/// Parse `/etc/os-release`-shaped content from an arbitrary path.
/// Test seam used by `preflight_os_with_path`; production callers go
/// through [`read_os_release`] to keep the canonical path embedded.
fn parse_os_release_at(path: &Path) -> Result<std::collections::HashMap<String, String>> {
    let raw = fs::read_to_string(path)?;
    let mut out = std::collections::HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let unquoted = if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
            || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
        {
            &value[1..value.len() - 1]
        } else {
            value
        };
        out.insert(key.to_string(), unquoted.to_string());
    }
    Ok(out)
}

/// Parse the major component of an `os-release` `VERSION_ID` (e.g.
/// `"24.04"` -> `24`, `"40"` -> `40`).
fn parse_version_major(version_id: &str) -> Option<u32> {
    let major = version_id.split('.').next()?;
    major.parse::<u32>().ok()
}

const UNSUPPORTED_OS_HINT: &str = "ghars requires systemd 254+. Supported: Ubuntu 24.04+, Fedora 40+, RHEL 10+ (and derivatives Rocky/AlmaLinux). Older systems (Ubuntu 22.04, RHEL 9, Fedora 38/39) are NOT supported because LogNamespace= per-runner journal isolation requires systemd 254.";

/// `preflight_os`: parse `/etc/os-release`, accept Ubuntu 24+, Fedora
/// 40+, RHEL/CentOS/Rocky/AlmaLinux 10+. Reject everything else with a
/// hint that names the supported set.
#[must_use]
pub fn preflight_os() -> CheckResult {
    preflight_os_with_path(Path::new("/etc/os-release"))
}

/// Test-seam variant: read os-release fields from `path` instead of
/// `/etc/os-release`. The decision logic (id-and-version-major support
/// matrix) is identical to [`preflight_os`]; only the source path
/// differs. Tests synthesize fixture content under a tempdir and call
/// this directly, leaving `preflight_os` itself wired to the canonical
/// production path.
#[must_use]
pub fn preflight_os_with_path(path: &Path) -> CheckResult {
    let fields = match parse_os_release_at(path) {
        Ok(f) => f,
        Err(e) => {
            return CheckResult::fail(
                "OS",
                format!("cannot read {}: {e}", path.display()),
                "ensure /etc/os-release exists and is readable",
            );
        }
    };
    let id = fields.get("ID").map_or("?", String::as_str);
    let version_id = fields.get("VERSION_ID").map_or("", String::as_str);
    let pretty = fields
        .get("PRETTY_NAME")
        .cloned()
        .unwrap_or_else(|| format!("{id} {version_id}"));

    let Some(major) = parse_version_major(version_id) else {
        let shown = if version_id.is_empty() {
            "?"
        } else {
            version_id
        };
        return CheckResult::fail(
            "OS",
            format!("cannot parse VERSION_ID={shown}"),
            UNSUPPORTED_OS_HINT,
        );
    };

    let supported = match id {
        "ubuntu" => major >= 24,
        "fedora" => major >= 40,
        "rhel" | "centos" | "rocky" | "almalinux" => major >= 10,
        _ => false,
    };

    if supported {
        CheckResult::pass("OS", pretty)
    } else {
        CheckResult::fail(
            "OS",
            format!("unsupported: ID={id} VERSION_ID={version_id}"),
            UNSUPPORTED_OS_HINT,
        )
    }
}

/// Run a process and capture combined stdout. Returns `None` on spawn
/// failure or non-zero exit; the caller treats `None` as "feature
/// absent" without surfacing the underlying error (preflight checks are
/// self-contained).
fn capture_stdout<I, S>(cmd: &str, args: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// Check that an executable named `bin` exists on `$PATH`. We delegate
/// to `/usr/bin/which` (`preflight_tools` enforces presence of required
/// commands; `which` is provided by util-linux on every supported
/// distro).
fn which(bin: &str) -> bool {
    Command::new("which")
        .arg(bin)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Look up a group by name. Tries `getent group NAME` first; falls back
/// to scanning `/etc/group` if `getent` is missing or fails.
fn group_exists(name: &str) -> bool {
    if which("getent") {
        if let Some(out) = capture_stdout("getent", ["group", name]) {
            if !out.trim().is_empty() {
                return true;
            }
        }
    }
    let needle = format!("{name}:");
    match fs::read_to_string("/etc/group") {
        Ok(content) => content.lines().any(|l| l.starts_with(&needle)),
        Err(_) => false,
    }
}

/// `preflight_kvm`: `/dev/kvm` exists and the `kvm` group is provisioned.
#[must_use]
pub fn preflight_kvm() -> CheckResult {
    if !Path::new("/dev/kvm").exists() {
        return CheckResult::fail(
            "kvm",
            "/dev/kvm missing",
            "install qemu-kvm and ensure hardware virtualization is enabled",
        );
    }
    if !group_exists("kvm") {
        return CheckResult::fail(
            "kvm",
            "kvm group not present",
            "install qemu-kvm (provisions the kvm group)",
        );
    }
    CheckResult::pass("kvm", "/dev/kvm present, kvm group exists")
}

/// Parse the major version from a systemd `Manager.Version` D-Bus
/// property string. (#136)
///
/// systemd's `org.freedesktop.systemd1.Manager.Version` property is
/// documented as a free-form string by systemd's D-Bus API; the actual
/// shape is set in `src/core/manager.c` via `PACKAGE_VERSION` (a
/// configure-time constant) optionally followed by a build-suffix.
/// Empirically observed across distros:
///
/// - Ubuntu / Debian: `"252.22-1ubuntu3"` (version-suffix dash form)
/// - Fedora / RHEL: `"254"` or `"254.5-1.fc40"`
/// - Upstream tarball: `"254"` (bare numeric)
/// - Possible future: `"v254"` (leading-`v` is permitted by
///   `PACKAGE_VERSION` semantics; not seen in the wild but the parser
///   must not reject it)
///
/// Strategy: skip any leading non-digit prefix, then collect the run
/// of ASCII digits, then `parse::<u32>()`. This is more robust than
/// the prior `split(non_digit).next()` approach which rejected
/// `"v254"` because the first split yields an empty string.
///
/// Returns `None` if no digits are present at all (e.g. `""` or
/// `"unknown"`).
fn parse_systemd_version_major(version: &str) -> Option<u32> {
    let digits: String = version
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse::<u32>().ok()
}

/// `preflight_systemd`: verify systemd is the init process and query
/// `Manager.Version` over D-Bus. Hard-reject systemd major < 254
/// because `LogNamespace=` is unconditional in v0.1 unit text.
#[must_use]
pub fn preflight_systemd() -> CheckResult {
    if !Path::new("/run/systemd/system").is_dir() {
        return CheckResult::fail(
            "systemd",
            "/run/systemd/system not present",
            "this host is not running systemd; ghars cannot install services",
        );
    }
    let connection = match Connection::system() {
        Ok(c) => c,
        Err(e) => {
            return CheckResult::fail(
                "systemd",
                format!("cannot connect to system D-Bus: {e}"),
                "verify dbus is running and the caller has access to the system bus",
            );
        }
    };
    let proxy = match Proxy::new(
        &connection,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    ) {
        Ok(p) => p,
        Err(e) => {
            return CheckResult::fail(
                "systemd",
                format!("cannot construct Manager proxy: {e}"),
                "verify systemd D-Bus interface is reachable",
            );
        }
    };
    let version: String = match proxy.get_property("Version") {
        Ok(v) => v,
        Err(e) => {
            return CheckResult::fail(
                "systemd",
                format!("cannot read Manager.Version: {e}"),
                "verify systemd D-Bus interface is reachable",
            );
        }
    };
    let Some(major) = parse_systemd_version_major(&version) else {
        return CheckResult::fail(
            "systemd",
            format!("cannot parse systemd version: {version:?}"),
            "report this as a ghars bug",
        );
    };
    if major < MIN_SYSTEMD_VERSION {
        return CheckResult::fail(
            "systemd",
            format!("found {version}; require {MIN_SYSTEMD_VERSION}+"),
            "upgrade or use a newer distro release; LogNamespace= per-runner journal isolation requires systemd 254+",
        );
    }
    CheckResult::pass("systemd", format!("{version} (>= {MIN_SYSTEMD_VERSION})"))
}

/// Read effective UID from `/proc/self/status`. The crate forbids
/// `unsafe_code`, so we cannot call `libc::geteuid`; procfs's `Uid:`
/// line is the documented stable interface (see `proc(5)`,
/// "Uid: Real, effective, saved set, and filesystem UIDs").
///
/// Retained as a path-pinned entry point parallel to [`read_os_release`];
/// `preflight_root` now delegates through `preflight_root_with_status_path`
/// → `read_euid_at`, so this helper is unused outside any future caller
/// that wants the canonical path baked in. allow(dead_code) keeps the
/// build clean.
#[allow(dead_code)]
fn read_euid() -> Option<u32> {
    read_euid_at(Path::new("/proc/self/status"))
}

/// Test seam — parse the `Uid:` line from a procfs-shaped status file.
/// Tests can write a synthetic `Uid: 0 0 0 0` file under a tempdir and
/// drive `preflight_root_with_status_path` without needing real root.
fn read_euid_at(path: &Path) -> Option<u32> {
    let status = fs::read_to_string(path).ok()?;
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("Uid:") else {
            continue;
        };
        let mut cols = rest.split_ascii_whitespace();
        let _real = cols.next();
        if let Some(eff) = cols.next() {
            if let Ok(n) = eff.parse::<u32>() {
                return Some(n);
            }
        }
    }
    None
}

/// `preflight_root`: caller must be EUID 0 for apply mode.
#[must_use]
pub fn preflight_root() -> CheckResult {
    preflight_root_with_status_path(Path::new("/proc/self/status"))
}

/// Test-seam variant of [`preflight_root`]. Reads the procfs-shaped
/// status file at `path` instead of `/proc/self/status`. Tests can
/// inject a fixture file with a chosen `Uid:` line; production wires
/// the real procfs path through [`preflight_root`].
#[must_use]
pub fn preflight_root_with_status_path(path: &Path) -> CheckResult {
    match read_euid_at(path) {
        Some(0) => CheckResult::pass("root", "EUID 0"),
        Some(euid) => CheckResult::fail(
            "root",
            format!("EUID {euid}"),
            "re-run with sudo, or pass --dry-run / --output-dir for read-only operation",
        ),
        None => CheckResult::fail(
            "root",
            format!("cannot read {}", path.display()),
            "verify procfs is mounted at /proc",
        ),
    }
}

/// The list of external commands `preflight_tools` checks for. Exposed
/// for tests so the canonical list stays in sync with the production
/// surface.
#[must_use]
pub fn required_tools() -> &'static [&'static str] {
    &[
        "install",
        "chmod",
        "chown",
        "useradd",
        "usermod",
        "getent",
        "runuser",
        "nft",
        "ip",
        "sysctl",
        "systemd-analyze",
        // `unshare` (util-linux) is invoked by the empirical CONFIG_NET_NS
        // probe in `netns_works()`. Without it that probe returns false
        // and the caller cannot tell "kernel lacks NET_NS" from "tool
        // missing"; surface the gap here so the operator gets a clean
        // remediation hint.
        "unshare",
    ]
}

/// `preflight_tools`: every external command ghars shells out to. The
/// list combines the legacy Python set (install, chmod, chown, useradd,
/// usermod, getent, runuser) with the v0.1 additions (`nft`, `ip`,
/// `sysctl` for netns mode + `systemd-analyze` for plan-time gate).
#[must_use]
pub fn preflight_tools() -> CheckResult {
    preflight_tools_with(&which_callable)
}

/// `which`-via-PATH probe used by [`preflight_tools`]. Wrapped behind a
/// fn pointer so tests can inject a stub that pretends a fixture set
/// of commands is present without depending on the host's `$PATH`.
fn which_callable(bin: &str) -> bool {
    which(bin)
}

/// Test-seam variant of [`preflight_tools`]. Calls `probe(name)` for
/// every required command instead of shelling out to `which`. The list
/// is the same as production ([`required_tools`]); only the resolution
/// differs.
#[must_use]
pub fn preflight_tools_with(probe: &dyn Fn(&str) -> bool) -> CheckResult {
    let need = required_tools();
    let missing: Vec<&str> = need.iter().copied().filter(|t| !probe(t)).collect();
    if missing.is_empty() {
        CheckResult::pass("tools", format!("{} required commands present", need.len()))
    } else {
        CheckResult::fail(
            "tools",
            format!("missing: {}", missing.join(", ")),
            "install the listed commands; netns mode requires nft (nftables), ip (iproute2), sysctl (procps), unshare (util-linux)",
        )
    }
}

/// Empirical `CONFIG_NET_NS` check: invoke `unshare -n true` and
/// require exit code 0. Kernels built without `CONFIG_NET_NS` return
/// `EINVAL` from the `clone(CLONE_NEWNET)` syscall, which surfaces as a
/// non-zero exit. Stronger than scanning `/proc/config.gz` because
/// kernels can ship that file with values that don't match the running
/// image.
fn netns_works() -> bool {
    Command::new("unshare")
        .args(["-n", "true"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Read `CapEff` (effective capability mask) from `/proc/self/status`
/// and check the bit for `CAP_NET_ADMIN` (capability number 12 — see
/// `man capabilities(7)`).
fn has_cap_net_admin() -> Option<bool> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        let Some(hex) = line.strip_prefix("CapEff:") else {
            continue;
        };
        let hex = hex.trim();
        // CapEff is a 64-bit hex value (16 hex chars) per
        // proc(5) and Documentation/filesystems/proc.rst:
        //   "CapEff: Bitmaps of capabilities enabled."
        let mask = u64::from_str_radix(hex, 16).ok()?;
        // CAP_NET_ADMIN = 12; bit set in mask means cap is held.
        return Some((mask & (1u64 << 12)) != 0);
    }
    None
}

/// `preflight_kernel_features`: cgroup v2 unified hierarchy, seccomp,
/// `CONFIG_NET_NS`, and `CAP_NET_ADMIN`. The first two are required for
/// the v0.1 unit template; the latter two are required for netns
/// network mode.
#[must_use]
pub fn preflight_kernel_features() -> CheckResult {
    let mut missing: Vec<String> = Vec::new();

    if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
        missing.push("cgroup v2 (no /sys/fs/cgroup/cgroup.controllers)".into());
    }

    let seccomp_present = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s.lines().any(|l| l.starts_with("Seccomp:")),
        Err(_) => false,
    };
    if !seccomp_present {
        missing.push("seccomp (no Seccomp: line in /proc/self/status)".into());
    }

    if !netns_works() {
        missing.push("CONFIG_NET_NS (unshare -n true failed)".into());
    }

    match has_cap_net_admin() {
        Some(true) => {}
        Some(false) => missing.push("CAP_NET_ADMIN (not in CapEff)".into()),
        None => missing.push("CAP_NET_ADMIN (could not parse CapEff)".into()),
    }

    if missing.is_empty() {
        CheckResult::pass("kernel", "cgroup v2, seccomp, CONFIG_NET_NS, CAP_NET_ADMIN")
    } else {
        CheckResult::fail(
            "kernel",
            format!("missing: {}", missing.join("; ")),
            "cgroup v2 + seccomp are required for the hardened unit; CONFIG_NET_NS + CAP_NET_ADMIN are required for netns mode (re-run as root or grant CAP_NET_ADMIN)",
        )
    }
}

/// `preflight_ptrace_scope`: read `/proc/sys/kernel/yama/ptrace_scope`.
/// Warn (not fail) at < 2 — SEC-28 advises 2 to block same-UID ptrace
/// between runner instances. `ghars apply --harden-host` writes
/// `/etc/sysctl.d/99-ghars.conf` to set 2 persistently; this preflight
/// just reports the current state.
#[must_use]
pub fn preflight_ptrace_scope() -> CheckResult {
    preflight_ptrace_scope_with_path(Path::new("/proc/sys/kernel/yama/ptrace_scope"))
}

/// Test-seam variant: read the `ptrace_scope` value from `path`
/// instead of the canonical procfs node. Tests synthesize a fixture
/// file with the desired integer (or a malformed body) under a tempdir.
#[must_use]
pub fn preflight_ptrace_scope_with_path(path: &Path) -> CheckResult {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            return CheckResult::warn(
                "ptrace_scope",
                format!("cannot read {}: {e}", path.display()),
                "Yama LSM may be disabled; runner-to-runner ptrace not blocked at the kernel layer",
            );
        }
    };
    let value: i32 = match raw.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            return CheckResult::warn(
                "ptrace_scope",
                format!("cannot parse {}: {:?}", path.display(), raw.trim()),
                "expected integer 0..=3 per Documentation/admin-guide/LSM/Yama.rst",
            );
        }
    };
    if value >= 2 {
        CheckResult::pass("ptrace_scope", format!("{value} (>= 2)"))
    } else {
        CheckResult::warn(
            "ptrace_scope",
            format!("{value} (< 2)"),
            "SEC-28: same-UID ptrace not blocked. Set sysctl kernel.yama.ptrace_scope=2 (or run `ghars apply --harden-host` to persist)",
        )
    }
}

/// Run every preflight check.
///
/// In `apply_mode`, root and systemd-version checks are mandatory; in
/// non-apply mode (`ghars status`, `--dry-run`), all checks still run
/// but are reported informationally. The caller (apply gate) translates
/// failures into `GharsError::Preflight`; see [`run_preflight`].
#[must_use]
pub fn run_all(apply_mode: bool) -> Vec<CheckResult> {
    let mut results = Vec::with_capacity(7);
    results.push(preflight_os());
    results.push(preflight_systemd());
    results.push(preflight_kvm());
    results.push(preflight_tools());
    results.push(preflight_kernel_features());
    if apply_mode {
        results.push(preflight_root());
    } else {
        results.push(CheckResult::skip("root", "not required outside apply"));
    }
    results.push(preflight_ptrace_scope());
    results
}

/// Apply gate. Short-circuits on `dry_run` (no checks performed; the
/// caller is in plan-only mode). Otherwise runs every preflight check
/// and returns `Err(GharsError::Preflight)` aggregating ALL failures
/// (`Outcome::Fail`) — not just the first. Warnings are non-blocking
/// and dropped silently here; the CLI surfaces them via `ghars status`.
///
/// #135: changed from first-fail short-circuit to collect-all so the
/// operator sees every problem at once. Apply has a high cost
/// (download, extract, register with GitHub, restart units); making
/// the operator iterate one missing dependency at a time pads that
/// cost with a re-run per problem. Surfacing the full failure set
/// in a single error message lets them resolve everything before
/// retrying.
///
/// # Errors
///
/// Returns `GharsError::Preflight` when any required check fails. The
/// message lists every failed check on its own line (`<name>: <detail>`);
/// the hint joins each check's hint, separated by `; `, so the operator
/// has actionable guidance for every reported failure.
pub fn run_preflight(dry_run: bool) -> Result<()> {
    if dry_run {
        return Ok(());
    }
    let failures: Vec<CheckResult> = run_all(true)
        .into_iter()
        .filter(|r| r.outcome == Outcome::Fail)
        .collect();
    if failures.is_empty() {
        return Ok(());
    }
    let count = failures.len();
    let header = if count == 1 {
        "1 preflight check failed".to_string()
    } else {
        format!("{count} preflight checks failed")
    };
    // Per-failure body: one `<name>: <detail>` line per failure.
    let body: Vec<String> = failures
        .iter()
        .map(|r| format!("  {}: {}", r.name, r.detail))
        .collect();
    let message = format!("{header}\n{}", body.join("\n"));
    let hint = failures
        .iter()
        .map(|r| format!("{}: {}", r.name, r.hint))
        .collect::<Vec<_>>()
        .join("; ");
    Err(GharsError::Preflight(message, hint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_major_handles_dotted_and_bare() {
        assert_eq!(parse_version_major("24.04"), Some(24));
        assert_eq!(parse_version_major("40"), Some(40));
        assert_eq!(parse_version_major("10"), Some(10));
        assert_eq!(parse_version_major("10.5"), Some(10));
        assert_eq!(parse_version_major(""), None);
        assert_eq!(parse_version_major("rolling"), None);
    }

    // ---- #136: parse_systemd_version_major ---------------------------

    /// Bare numeric (upstream tarball, Fedora <40 era): `"254"`.
    #[test]
    fn parse_systemd_version_major_bare() {
        assert_eq!(parse_systemd_version_major("254"), Some(254));
        assert_eq!(parse_systemd_version_major("252"), Some(252));
        assert_eq!(parse_systemd_version_major("100"), Some(100));
    }

    /// Dotted patch level (Fedora `254.5-1.fc40` shape): take the
    /// major before the first non-digit.
    #[test]
    fn parse_systemd_version_major_with_patch_level() {
        assert_eq!(parse_systemd_version_major("254.5"), Some(254));
        assert_eq!(parse_systemd_version_major("256.10"), Some(256));
    }

    /// Distro suffix (Ubuntu/Debian `252.22-1ubuntu3` shape): leading
    /// digits before the first dot are the major; everything after
    /// the first non-digit is suffix and ignored.
    #[test]
    fn parse_systemd_version_major_with_distro_suffix() {
        assert_eq!(
            parse_systemd_version_major("252.22-1ubuntu3"),
            Some(252),
            "Ubuntu Manager.Version shape"
        );
        assert_eq!(
            parse_systemd_version_major("254.5-1.fc40"),
            Some(254),
            "Fedora Manager.Version shape"
        );
        assert_eq!(
            parse_systemd_version_major("254-1.el10"),
            Some(254),
            "RHEL Manager.Version shape"
        );
    }

    /// Future-proof: leading-`v` prefix shouldn't reject. The prior
    /// implementation used `split(non_digit).next()` which yielded
    /// `""` for `"v254"` and tripped the parse-fail arm. The
    /// `skip_while(non_digit) + take_while(digit)` formulation handles
    /// arbitrary non-digit prefixes correctly.
    #[test]
    fn parse_systemd_version_major_tolerates_leading_v() {
        assert_eq!(parse_systemd_version_major("v254"), Some(254));
        assert_eq!(parse_systemd_version_major("V254"), Some(254));
        assert_eq!(parse_systemd_version_major("systemd 254"), Some(254));
    }

    /// Empty / non-numeric → None (callers map to "cannot parse" with
    /// hint "report as a ghars bug").
    #[test]
    fn parse_systemd_version_major_returns_none_for_no_digits() {
        assert_eq!(parse_systemd_version_major(""), None);
        assert_eq!(parse_systemd_version_major("unknown"), None);
        assert_eq!(parse_systemd_version_major("v"), None);
        assert_eq!(parse_systemd_version_major("-"), None);
    }

    /// Boundary check around `MIN_SYSTEMD_VERSION` so a future floor
    /// bump catches a stale parser.
    #[test]
    fn parse_systemd_version_major_at_min_version_floor() {
        assert_eq!(
            parse_systemd_version_major(&MIN_SYSTEMD_VERSION.to_string()),
            Some(MIN_SYSTEMD_VERSION),
        );
    }

    // ---- #137: preflight_os_with_path integration tests --------------

    /// Helper: write a synthesized `os-release` body to a tempfile
    /// and return the path. Tempdir is owned by the caller so the
    /// fixture lives until the test returns.
    fn write_os_release_fixture(tmp: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let path = tmp.path().join("os-release");
        fs::write(&path, body).unwrap();
        path
    }

    /// Accepted OS: Ubuntu 24.04 (the floor for ghars). Pretty-name
    /// flows into `detail`; outcome must be Pass.
    #[test]
    fn preflight_os_with_path_accepts_ubuntu_24_04() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_os_release_fixture(
            &tmp,
            "ID=ubuntu\n\
             VERSION_ID=\"24.04\"\n\
             PRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
        );
        let r = preflight_os_with_path(&path);
        assert_eq!(r.outcome, Outcome::Pass, "Ubuntu 24.04 must pass: {r:?}");
        assert!(
            r.detail.contains("Ubuntu 24.04"),
            "PRETTY_NAME must surface in detail: {}",
            r.detail
        );
    }

    /// Accepted OS: Fedora 40 (also at floor). Bare unquoted
    /// VERSION_ID confirms the os-release parser strips quotes
    /// uniformly.
    #[test]
    fn preflight_os_with_path_accepts_fedora_40() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_os_release_fixture(
            &tmp,
            "ID=fedora\n\
             VERSION_ID=40\n\
             PRETTY_NAME=\"Fedora Linux 40 (Workstation Edition)\"\n",
        );
        let r = preflight_os_with_path(&path);
        assert_eq!(r.outcome, Outcome::Pass, "Fedora 40 must pass: {r:?}");
    }

    /// Accepted OS: RHEL 10. Mirrors RHEL/CentOS/Rocky/AlmaLinux
    /// support matrix (>= 10).
    #[test]
    fn preflight_os_with_path_accepts_rhel_10() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_os_release_fixture(
            &tmp,
            "ID=rhel\n\
             VERSION_ID=\"10.0\"\n\
             PRETTY_NAME=\"Red Hat Enterprise Linux 10.0\"\n",
        );
        let r = preflight_os_with_path(&path);
        assert_eq!(r.outcome, Outcome::Pass, "RHEL 10 must pass: {r:?}");
    }

    /// Rejected OS: Ubuntu 22.04 — below the systemd 254 floor (Ubuntu
    /// 22.04 ships systemd 249). Hint must direct operator to the
    /// supported set.
    #[test]
    fn preflight_os_with_path_rejects_ubuntu_22_04() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_os_release_fixture(
            &tmp,
            "ID=ubuntu\n\
             VERSION_ID=\"22.04\"\n\
             PRETTY_NAME=\"Ubuntu 22.04 LTS\"\n",
        );
        let r = preflight_os_with_path(&path);
        assert_eq!(r.outcome, Outcome::Fail, "Ubuntu 22.04 must fail: {r:?}");
        assert!(
            r.detail.contains("ID=ubuntu") && r.detail.contains("VERSION_ID=22.04"),
            "fail detail must name the rejected ID and version: {}",
            r.detail
        );
        assert!(
            r.hint.contains("systemd 254"),
            "hint must explain the systemd 254 floor: {}",
            r.hint
        );
    }

    /// Rejected OS: Debian 12 — not in the supported ID set. The
    /// `_` arm rejects unknown distros wholesale to fail-closed
    /// against accidentally running on something untested.
    #[test]
    fn preflight_os_with_path_rejects_unknown_distro() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_os_release_fixture(
            &tmp,
            "ID=debian\n\
             VERSION_ID=\"12\"\n\
             PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
        );
        let r = preflight_os_with_path(&path);
        assert_eq!(r.outcome, Outcome::Fail, "Debian must fail: {r:?}");
        assert!(
            r.detail.contains("ID=debian"),
            "fail detail must name the rejected ID: {}",
            r.detail
        );
    }

    /// Missing file: `parse_os_release_at` propagates the I/O error
    /// and `preflight_os_with_path` wraps it with an actionable hint.
    /// Path is constructed under a tempdir but never created so the
    /// open() call fails with NotFound deterministically.
    #[test]
    fn preflight_os_with_path_fails_on_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonexistent-os-release");
        assert!(
            !path.exists(),
            "fixture must not exist for the missing-file branch"
        );
        let r = preflight_os_with_path(&path);
        assert_eq!(r.outcome, Outcome::Fail, "missing file must fail: {r:?}");
        assert!(
            r.detail.contains("cannot read"),
            "fail detail must name the read failure: {}",
            r.detail
        );
        assert!(
            r.hint.contains("/etc/os-release"),
            "hint must mention the canonical path: {}",
            r.hint
        );
    }

    /// Missing VERSION_ID field: the `parse_version_major` helper
    /// returns None for empty / non-numeric input; the caller emits
    /// a "cannot parse VERSION_ID" failure with the supported-set
    /// hint. Pins the failure path so it stays distinguishable from
    /// "unsupported distro".
    #[test]
    fn preflight_os_with_path_fails_when_version_id_unparseable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_os_release_fixture(
            &tmp,
            "ID=ubuntu\n\
             VERSION_ID=\"rolling\"\n\
             PRETTY_NAME=\"Ubuntu Rolling\"\n",
        );
        let r = preflight_os_with_path(&path);
        assert_eq!(
            r.outcome,
            Outcome::Fail,
            "unparseable VERSION_ID must fail: {r:?}"
        );
        assert!(
            r.detail.contains("cannot parse VERSION_ID"),
            "fail detail must name the parse failure: {}",
            r.detail
        );
    }

    #[test]
    fn dry_run_short_circuits() {
        assert!(run_preflight(true).is_ok());
    }

    #[test]
    fn check_result_constructors_set_fields() {
        let p = CheckResult::pass("x", "ok");
        assert_eq!(p.outcome, Outcome::Pass);
        assert!(p.hint.is_empty());

        let f = CheckResult::fail("x", "broken", "fix it");
        assert_eq!(f.outcome, Outcome::Fail);
        assert_eq!(f.hint, "fix it");

        let w = CheckResult::warn("x", "weird", "consider X");
        assert_eq!(w.outcome, Outcome::Warn);

        let s = CheckResult::skip("x", "n/a");
        assert_eq!(s.outcome, Outcome::Skip);
        assert!(s.hint.is_empty());
    }

    /// Helper that mirrors `run_preflight`'s collect-all behavior on
    /// an arbitrary `Vec<CheckResult>`. Mocking every system probe in
    /// `run_all` is impractical; the aggregation logic is the
    /// load-bearing piece for #135 and is testable in isolation.
    fn aggregate_failures(results: Vec<CheckResult>) -> Result<()> {
        let failures: Vec<CheckResult> = results
            .into_iter()
            .filter(|r| r.outcome == Outcome::Fail)
            .collect();
        if failures.is_empty() {
            return Ok(());
        }
        let count = failures.len();
        let header = if count == 1 {
            "1 preflight check failed".to_string()
        } else {
            format!("{count} preflight checks failed")
        };
        let body: Vec<String> = failures
            .iter()
            .map(|r| format!("  {}: {}", r.name, r.detail))
            .collect();
        let message = format!("{header}\n{}", body.join("\n"));
        let hint = failures
            .iter()
            .map(|r| format!("{}: {}", r.name, r.hint))
            .collect::<Vec<_>>()
            .join("; ");
        Err(GharsError::Preflight(message, hint))
    }

    #[test]
    fn aggregate_failures_returns_ok_when_no_failures() {
        let results = vec![
            CheckResult::pass("os", "Ubuntu 24.04"),
            CheckResult::warn("kvm", "no /dev/kvm", "ok if no nested virt"),
            CheckResult::skip("root", "not required"),
        ];
        assert!(aggregate_failures(results).is_ok());
    }

    #[test]
    fn aggregate_failures_collects_every_failure_not_just_first() {
        // #135: the original behavior short-circuited on the FIRST
        // failed check. The new behavior must surface all 3 failures
        // here, not just the first. The message body must list every
        // failing check on its own line so the operator can fix them
        // in one pass.
        let results = vec![
            CheckResult::fail("os", "Debian 11 unsupported", "upgrade to 12+"),
            CheckResult::pass("systemd", "255"),
            CheckResult::fail("kvm", "no /dev/kvm", "load kvm module"),
            CheckResult::fail("tools", "nft missing", "install nftables"),
        ];
        let err = aggregate_failures(results).unwrap_err();
        let GharsError::Preflight(msg, hint) = err else {
            panic!("expected Preflight error");
        };
        assert!(msg.contains("3 preflight checks failed"));
        assert!(msg.contains("os: Debian 11 unsupported"));
        assert!(msg.contains("kvm: no /dev/kvm"));
        assert!(msg.contains("tools: nft missing"));
        // Passing / warning / skipped checks must NOT appear in the
        // failure listing.
        assert!(!msg.contains("systemd"));
        // Hints are joined so the operator gets actionable guidance
        // for every failure.
        assert!(hint.contains("os: upgrade to 12+"));
        assert!(hint.contains("kvm: load kvm module"));
        assert!(hint.contains("tools: install nftables"));
    }

    #[test]
    fn aggregate_failures_singular_header_for_one_failure() {
        let results = vec![
            CheckResult::pass("os", "ok"),
            CheckResult::fail("kvm", "no kvm", "modprobe kvm"),
            CheckResult::pass("systemd", "ok"),
        ];
        let err = aggregate_failures(results).unwrap_err();
        let GharsError::Preflight(msg, _) = err else {
            panic!("expected Preflight");
        };
        assert!(
            msg.contains("1 preflight check failed"),
            "expected singular header: {msg}"
        );
        // No "1 preflight checkS" — singular vs plural distinction.
        assert!(!msg.contains("preflight checks failed"));
    }
}
