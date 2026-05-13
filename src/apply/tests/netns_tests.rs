//! Tests for `apply::netns` (`provision_netns_artifacts`,
//! `teardown_netns_artifacts`, `verify_runner_netns_at`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::Result;
use crate::auth::TokenSource;
use crate::error::GharsError;
use crate::netns::NetnsConfig;
use crate::plan::RunnerIdentity;
use crate::systemd::{Systemd, UnitListEntry};

use super::super::netns::verify_runner_netns_at;
use super::super::runners::{execute_create_runner, execute_remove_runner};
use super::super::undo::{Deps, UndoLog};
use super::common::{
    MockConfigShell, MockSystemd, MockTarball, MockTokenSource, make_paths, make_runner_plan,
};

/// Helper: build a Netns binding so the spec passes through
/// `provision_netns_artifacts`. Mirrors the systemd-test fixture.
fn make_netns_binding(subnet: &str) -> crate::config::EffectiveNetworkBinding {
    use crate::config::{
        DnsMode, EffectiveNetworkBinding, EgressRule, Ipv6Mode, NetworkMode, NetworkSpec, PortSpec,
        Proto,
    };
    EffectiveNetworkBinding {
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
        subnet: Some(subnet.parse::<ipnet::IpNet>().unwrap()),
    }
}

#[test]
fn create_runner_with_netns_provisions_template_nft_config_and_starts_netns_unit() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let mut plan = make_runner_plan("a", &paths.state_dir);
    plan.spec.network = Some(make_netns_binding("10.200.0.0/30"));
    let systemd = MockSystemd::default();
    // verify_runner_netns reads /proc/MainPID/ns/net and compares it
    // to /proc/1/ns/net. In CI the test process IS in the host netns
    // so the readlinks match — the post-start check fires the
    // netns fail-closed branch and returns an error. We don't care: every
    // pre-start side effect is what this test guards.
    systemd.set_property(
        "ghars-runner@a.service",
        "MainPID",
        &std::process::id().to_string(),
    );
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    // Best-effort call. The post-start verify_runner_netns fails in
    // CI; pre-start artifacts must already be on disk regardless.
    let _ = execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new(), 2);

    // 1) NetnsConfig TOML written to <config_dir>/netns.d/a.toml.
    let cfg_path = NetnsConfig::path_for(&paths, "a");
    assert!(cfg_path.as_std_path().exists(), "netns.d/a.toml missing");
    let cfg_body = std::fs::read_to_string(cfg_path.as_std_path()).unwrap();
    assert!(cfg_body.contains("subnet"));
    assert!(cfg_body.contains("10.200.0.0/30"));

    // 2) nft rule files written.
    let host_nft = paths.nft_host_rule("a");
    let ns_nft = paths.nft_ns_rule("a");
    assert!(host_nft.as_std_path().exists(), "host nft missing");
    assert!(ns_nft.as_std_path().exists(), "ns nft missing");
    let host_body = std::fs::read_to_string(host_nft.as_std_path()).unwrap();
    assert!(host_body.contains("table inet ghars_a"));
    assert!(host_body.contains("ip saddr 10.200.0.0/30"));

    // 3) ghars-net@.service template written (idempotent shared body).
    let template_path = paths.netns_template_unit_file();
    assert!(
        template_path.as_std_path().exists(),
        "netns template missing"
    );
    let template_body = std::fs::read_to_string(template_path.as_std_path()).unwrap();
    assert!(template_body.contains("ghars _netns-setup %i"));
    assert!(template_body.contains("StopWhenUnneeded=no"));

    // 4) ghars-net@a was enabled + started before the runner unit.
    let calls = systemd.calls_snapshot();
    let netns_enable = calls
        .iter()
        .position(|c| c == "enable_unit(ghars-net@a.service)");
    let netns_start = calls
        .iter()
        .position(|c| c == "start_unit(ghars-net@a.service)");
    let runner_start = calls
        .iter()
        .position(|c| c == "start_unit(ghars-runner@a.service)");
    assert!(netns_enable.is_some(), "ghars-net@a not enabled: {calls:?}");
    let netns_start = netns_start.expect("ghars-net@a not started");
    let runner_start = runner_start.expect("runner unit not started");
    assert!(
        netns_start < runner_start,
        "netns must start before runner: {calls:?}",
    );
}

#[test]
fn create_runner_open_mode_writes_no_netns_artifacts() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    // Default make_runner_plan has spec.network = None.
    let plan = make_runner_plan("open", &paths.state_dir);
    let systemd = MockSystemd::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new(), 2).unwrap();

    // No NetnsConfig, no nft rules, no netns template, no ghars-net@
    // calls.
    assert!(!NetnsConfig::path_for(&paths, "open").as_std_path().exists());
    assert!(!paths.nft_host_rule("open").as_std_path().exists());
    assert!(!paths.nft_ns_rule("open").as_std_path().exists());
    assert!(!paths.netns_template_unit_file().as_std_path().exists());
    let calls = systemd.calls_snapshot();
    assert!(
        !calls.iter().any(|c| c.contains("ghars-net@")),
        "Open-mode runner must not touch ghars-net@: {calls:?}"
    );
}

/// Defense-in-depth: a Netns-mode binding reaching
/// `provision_netns_artifacts` with `subnet = None` would mean
/// `lower_to_effective` and the apply path disagreed on the
/// mode⇒subnet contract. Surface as a structured `GharsError::Apply`
/// rather than panicking on the downstream `binding.subnet.unwrap()`
/// call. The fixture builds an `EffectiveNetworkBinding` directly
/// (bypassing `lower_to_effective`) so we can pin the bug-shape
/// detection without going through the lowering pipeline.
#[test]
fn provision_netns_rejects_netns_binding_without_subnet() {
    use super::super::netns::provision_netns_artifacts;
    use crate::config::{
        DnsMode, EffectiveNetworkBinding, EgressRule, Ipv6Mode, NetworkMode, NetworkSpec, PortSpec,
        Proto,
    };

    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let mut plan = make_runner_plan("a", &paths.state_dir);
    // Bug-shape input: Netns mode, but no subnet allocated. The
    // production lowering path always pairs Netns with Some(/30);
    // fixture builds the contradictory shape directly.
    plan.spec.network = Some(EffectiveNetworkBinding {
        name: "isolated".into(),
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
            restrict_address_families: vec![],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
        subnet: None,
    });
    let systemd = MockSystemd::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };

    let err = provision_netns_artifacts(&plan.spec, &deps, &paths, &mut UndoLog::new())
        .expect_err("must reject Netns binding without subnet");
    let msg = format!("{err}");
    assert!(
        msg.contains("netns binding has no subnet despite mode = Netns"),
        "msg must name the contract violation: {msg}"
    );
    assert!(
        msg.contains("ghars bug"),
        "msg must flag it as a bug-shaped input: {msg}"
    );
    // The Apply error wraps the action label so operators see
    // which apply path refused the binding.
    assert!(
        msg.contains("provision_netns_artifacts(a)"),
        "msg must name the calling apply path: {msg}"
    );
    // Defense-in-depth: nothing should have been written to disk
    // because the contract violation fires before any side effect.
    assert!(
        !NetnsConfig::path_for(&paths, "a").as_std_path().exists(),
        "no NetnsConfig should have been written"
    );
    assert!(!paths.nft_host_rule("a").as_std_path().exists());
}

#[test]
fn remove_runner_tears_down_netns_artifacts() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    // Pre-stage runner state + netns artifacts as if a prior apply
    // had created them.
    let runner_home = paths.runner_home("default", "a");
    std::fs::create_dir_all(runner_home.as_std_path()).unwrap();
    std::fs::write(runner_home.join("config.sh").as_std_path(), b"#!/bin/sh\n").unwrap();
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
    std::fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
    // Netns artifacts.
    let cfg = NetnsConfig {
        subnet: "10.200.0.0/30".parse().unwrap(),
        dns: crate::config::DnsMode::default(),
    };
    cfg.write(&paths, "a").unwrap();
    let nft_dir = paths.config_dir.join("nft.d");
    std::fs::create_dir_all(nft_dir.as_std_path()).unwrap();
    std::fs::write(
        paths.nft_host_rule("a").as_std_path(),
        b"table inet ghars_a {}\n",
    )
    .unwrap();
    std::fs::write(
        paths.nft_ns_rule("a").as_std_path(),
        b"table inet ghars_a_ns {}\n",
    )
    .unwrap();

    let identity = RunnerIdentity {
        name: "a".into(),
        url: "https://github.com/example/repo".into(),
        auth_name: "pat".into(),
        trust_zone: "default".into(),
    };
    let systemd = MockSystemd::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    execute_remove_runner(&identity, &deps, &paths, &mut UndoLog::new()).unwrap();

    // ghars-net@a stopped + disabled.
    let calls = systemd.calls_snapshot();
    assert!(
        calls.iter().any(|c| c == "stop_unit(ghars-net@a.service)"),
        "ghars-net@a not stopped: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|c| c == "disable_unit(ghars-net@a.service)"),
        "ghars-net@a not disabled: {calls:?}"
    );

    // Netns artifacts gone.
    assert!(
        !NetnsConfig::path_for(&paths, "a").as_std_path().exists(),
        "netns config TOML still present"
    );
    assert!(
        !paths.nft_host_rule("a").as_std_path().exists(),
        "host nft still present"
    );
    assert!(
        !paths.nft_ns_rule("a").as_std_path().exists(),
        "ns nft still present"
    );
}

// ---- verify_runner_netns_at happy + fail paths --------------------
//
// These tests use `verify_runner_netns_at` with a tempdir-rooted
// proc layout so they can exercise both the happy path (distinct
// ns/net symlink targets) and the fail path (matching targets ⇒
// host-namespace fallback) without root or a real netns'd unit.

/// Build a synthetic proc layout: `<root>/<pid>/ns/net` →
/// `<runner_target>` and `<root>/1/ns/net` → `<host_target>`.
fn synth_proc_netns_layout(
    root: &std::path::Path,
    pid: u32,
    runner_target: &str,
    host_target: &str,
) {
    let pid_dir = root.join(pid.to_string()).join("ns");
    std::fs::create_dir_all(&pid_dir).unwrap();
    // Symlink may already exist when a test calls this twice with
    // overlapping PIDs (e.g. mid-retry tests seed both PID=1 and
    // a runner PID under the same root). symlink(2) returns EEXIST
    // on a pre-existing path; remove first so the second call is
    // idempotent.
    let pid_link = pid_dir.join("net");
    let _ = std::fs::remove_file(&pid_link);
    std::os::unix::fs::symlink(runner_target, &pid_link).unwrap();
    let host_dir = root.join("1").join("ns");
    std::fs::create_dir_all(&host_dir).unwrap();
    let host_link = host_dir.join("net");
    let _ = std::fs::remove_file(&host_link);
    std::os::unix::fs::symlink(host_target, &host_link).unwrap();
}

/// 50ms deadline for `verify_runner_netns_at` unit tests. Short
/// enough that fail-path tests don't slow the suite. Production
/// uses `NETNS_VERIFY_DEADLINE` (5s).
const TEST_NETNS_VERIFY_DEADLINE: std::time::Duration = std::time::Duration::from_millis(50);

/// 5ms backoff for `verify_runner_netns_at` unit tests. Combined
/// with the 50ms deadline, this allows up to ~10 polls per
/// test — enough to exercise `FlippingMockSystemd`'s `flip_after=1`
/// (recovers-on-second-poll) and the persistent-ENOENT fail path.
/// Production uses `NETNS_VERIFY_BACKOFF` (100ms).
const TEST_NETNS_VERIFY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(5);

#[test]
fn verify_runner_netns_at_passes_when_targets_differ() {
    // Happy path: runner is in an isolated netns. The runner's
    // `/proc/<pid>/ns/net` symlink target differs from
    // `/proc/1/ns/net`'s target, so the function returns Ok.
    let tmp = tempfile::tempdir().unwrap();
    synth_proc_netns_layout(
        tmp.path(),
        1234,
        "net:[4026532900]", // isolated namespace inode
        "net:[4026531992]", // host namespace inode
    );
    let systemd = MockSystemd::default();
    systemd.set_property("ghars-runner@buckos.service", "MainPID", "1234");
    verify_runner_netns_at(
        tmp.path(),
        "ghars-runner@buckos.service",
        &systemd,
        TEST_NETNS_VERIFY_DEADLINE,
        TEST_NETNS_VERIFY_BACKOFF,
    )
    .expect("isolated netns must pass verify");
}

/// `MockSystemd` variant whose `MainPID` property changes after the
/// first `flip_after` calls. Used by the retry-recovery test:
/// the first reads return the host-netns'd PID; subsequent reads
/// return the freshly-joined PID, mimicking the kernel-side setns
/// race. `MainPID` flows through `get_unit_property_u64` on the
/// Service interface; the mock stores u64 directly, no String
/// round-trip.
struct FlippingMockSystemd {
    unit: String,
    first_pid: u64,
    second_pid: u64,
    flip_after: u32,
    calls: AtomicU32,
}

impl Systemd for FlippingMockSystemd {
    fn daemon_reload(&self) -> Result<()> {
        Ok(())
    }
    fn start_unit(&self, _: &str) -> Result<()> {
        Ok(())
    }
    fn stop_unit(&self, _: &str) -> Result<()> {
        Ok(())
    }
    fn enable_unit(&self, _: &str) -> Result<()> {
        Ok(())
    }
    fn disable_unit(&self, _: &str) -> Result<()> {
        Ok(())
    }
    fn list_units_filtered(&self, _: &[&str]) -> Result<Vec<UnitListEntry>> {
        Ok(vec![])
    }
    fn get_unit_property(&self, _: &str, _: &str, _: &str) -> Result<String> {
        unreachable!("FlippingMockSystemd only services MainPID via get_unit_property_u64")
    }
    fn get_unit_property_u64(&self, unit: &str, iface: &str, property: &str) -> Result<u64> {
        assert_eq!(unit, self.unit);
        assert_eq!(iface, "org.freedesktop.systemd1.Service");
        assert_eq!(property, "MainPID");
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n < self.flip_after {
            Ok(self.first_pid)
        } else {
            Ok(self.second_pid)
        }
    }
    fn get_unit_property_object_path(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<zbus::zvariant::OwnedObjectPath> {
        unreachable!()
    }
    fn get_service_property_string(&self, _: &str, _: &str) -> Result<String> {
        unreachable!("FlippingMockSystemd only services MainPID via get_service_property_u64")
    }
    fn get_service_property_u64(&self, unit: &str, property: &str) -> Result<u64> {
        self.get_unit_property_u64(unit, "org.freedesktop.systemd1.Service", property)
    }
    fn lookup_dynamic_user_by_name(&self, _: &str) -> Result<Option<u32>> {
        unreachable!("FlippingMockSystemd does not exercise DynamicUser lookup")
    }
}

#[test]
fn verify_runner_netns_at_recovers_when_kernel_join_lands_mid_retry() {
    // The kernel-side setns(NetworkNamespacePath=) call lands
    // during the runner's exec, AFTER systemd's StartUnit returns.
    // A single readlink at StartUnit-return-time can observe the
    // still-host symlink target. The retry loop must recover when
    // the join lands by attempt 2 or 3. Flipping mock returns
    // PID=1 (which has the host symlink) for the first call, then
    // PID=5678 (which has an isolated symlink) for subsequent calls.
    let tmp = tempfile::tempdir().unwrap();
    // Synth /proc/1/ns/net = host_target, /proc/5678/ns/net = isolated.
    let host_target = "net:[4026531992]";
    let isolated_target = "net:[4026535123]";
    // synth_proc_netns_layout writes both `<pid>/ns/net` and
    // `1/ns/net` — calling it with pid==1 collides those two paths
    // with EEXIST. Use host-only synth for the PID=1 leg, then lay
    // down /proc/5678/ns/net pointing at the isolated target.
    synth_host_only_proc_layout(tmp.path(), host_target);
    let pid_dir = tmp.path().join("5678").join("ns");
    std::fs::create_dir_all(&pid_dir).unwrap();
    std::os::unix::fs::symlink(isolated_target, pid_dir.join("net")).unwrap();
    let systemd = FlippingMockSystemd {
        unit: "ghars-runner@buckos.service".into(),
        first_pid: 1,
        second_pid: 5678,
        flip_after: 1,
        calls: AtomicU32::new(0),
    };
    // Must succeed: attempt 1 sees PID=1 (host-netns'd), attempt 2
    // sees PID=5678 (isolated). Without the retry, this would
    // false-positive a netns fail-open and abort.
    verify_runner_netns_at(
        tmp.path(),
        "ghars-runner@buckos.service",
        &systemd,
        TEST_NETNS_VERIFY_DEADLINE,
        TEST_NETNS_VERIFY_BACKOFF,
    )
    .unwrap();
}

#[test]
fn verify_runner_netns_at_treats_enoent_on_proc_pid_as_transient() {
    // ENOENT on /proc/PID/ns/net is a transient race condition
    // (the PID was just exec'd by systemd and recorded via
    // service_set_main_pidref before the kernel made /proc/PID
    // visible, OR the PID was reaped between the get_unit_property
    // call and the readlink). Verify must retry — NOT treat missing
    // /proc/PID as success (which would be a fail-open: a PID that
    // doesn't exist trivially isn't in the host netns either).
    // FlippingMock returns PID=99999 (which has no /proc/99999 in
    // our tempdir) for the first call, then PID=5678 (which has an
    // isolated symlink) for subsequent calls. ENOENT on attempt 1
    // → retry → success on attempt 2.
    let tmp = tempfile::tempdir().unwrap();
    let host_target = "net:[4026531992]";
    let isolated_target = "net:[4026535123]";
    // Lay down /proc/1/ns/net (host) and /proc/5678/ns/net (isolated).
    // Crucially do NOT create /proc/99999 — first readlink hits ENOENT.
    synth_host_only_proc_layout(tmp.path(), host_target);
    let pid_dir = tmp.path().join("5678").join("ns");
    std::fs::create_dir_all(&pid_dir).unwrap();
    std::os::unix::fs::symlink(isolated_target, pid_dir.join("net")).unwrap();
    let systemd = FlippingMockSystemd {
        unit: "ghars-runner@buckos.service".into(),
        first_pid: 99999,
        second_pid: 5678,
        flip_after: 1,
        calls: AtomicU32::new(0),
    };
    verify_runner_netns_at(
        tmp.path(),
        "ghars-runner@buckos.service",
        &systemd,
        TEST_NETNS_VERIFY_DEADLINE,
        TEST_NETNS_VERIFY_BACKOFF,
    )
    .expect("ENOENT on /proc/PID must be transient → retry → succeed");
}

#[test]
fn verify_runner_netns_at_persistent_enoent_on_proc_pid_errors_systemd() {
    // If /proc/PID/ns/net stays missing for the entire
    // deadline (e.g. systemd recorded MainPID but the unit failed
    // to start past fork), surface a Systemd error — not Ok (which
    // would be a fail-open). The error message must mention the
    // poll count and the setup_namespace contract so an operator
    // can correlate with `journalctl -u`.
    let tmp = tempfile::tempdir().unwrap();
    // PID 99999's /proc entry never exists.
    synth_host_only_proc_layout(tmp.path(), "net:[4026531992]");
    let systemd = MockSystemd::default();
    systemd.set_property("ghars-runner@buckos.service", "MainPID", "99999");
    let err = verify_runner_netns_at(
        tmp.path(),
        "ghars-runner@buckos.service",
        &systemd,
        TEST_NETNS_VERIFY_DEADLINE,
        TEST_NETNS_VERIFY_BACKOFF,
    )
    .expect_err("persistent ENOENT must NOT count as success");
    let msg = format!("{err}");
    assert!(
        matches!(err, GharsError::Systemd(_, _)),
        "expected Systemd variant, got: {err:?}"
    );
    assert!(
        msg.contains("never resolved"),
        "expected 'never resolved' in error; got: {msg}"
    );
    assert!(
        msg.contains("setup_namespace"),
        "expected 'setup_namespace' citation in error; got: {msg}"
    );
}

#[test]
fn verify_runner_netns_at_aborts_when_targets_match_host() {
    // Fail path: runner symlink target == host's. The netns
    // fail-closed branch fires — abort with a Validation error
    // wrapped in Apply.
    let tmp = tempfile::tempdir().unwrap();
    synth_proc_netns_layout(tmp.path(), 5678, "net:[4026531992]", "net:[4026531992]");
    let systemd = MockSystemd::default();
    systemd.set_property("ghars-runner@buckos.service", "MainPID", "5678");
    let err = verify_runner_netns_at(
        tmp.path(),
        "ghars-runner@buckos.service",
        &systemd,
        TEST_NETNS_VERIFY_DEADLINE,
        TEST_NETNS_VERIFY_BACKOFF,
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("HOST network namespace"), "{msg}");
    assert!(msg.contains("5678"), "{msg}");
    // Error message must record that we polled before giving
    // up — operator triaging a netns fail-open needs to know the
    // verify ran multiple readlinks against the deadline, not a
    // single shot.
    assert!(
        msg.contains("polls"),
        "error must report poll count; got: {msg}"
    );
    assert!(
        msg.contains(&format!("{}ms", TEST_NETNS_VERIFY_DEADLINE.as_millis())),
        "error must report deadline; got: {msg}"
    );
    // Pin the variant: Apply wraps a Validation. A future change
    // that flattened to plain Validation would silently change
    // the CLI exit-code mapping.
    match err {
        GharsError::Apply { source, .. } => {
            assert!(
                matches!(*source, GharsError::Validation(_, _)),
                "expected Apply{{source: Validation}}, got {source:?}"
            );
        }
        other => panic!("expected GharsError::Apply, got {other:?}"),
    }
}

/// Synthesize only the host `<root>/1/ns/net` symlink, leaving the
/// per-PID layer for tests that fail before reaching the readlink
/// for the runner. The function reads `/proc/1/ns/net` first so
/// the host symlink must always exist before we drive any case.
fn synth_host_only_proc_layout(root: &std::path::Path, host_target: &str) {
    let host_dir = root.join("1").join("ns");
    std::fs::create_dir_all(&host_dir).unwrap();
    std::os::unix::fs::symlink(host_target, host_dir.join("net")).unwrap();
}

#[test]
fn verify_runner_netns_at_errors_on_main_pid_zero() {
    let tmp = tempfile::tempdir().unwrap();
    synth_host_only_proc_layout(tmp.path(), "net:[4026531992]");
    let systemd = MockSystemd::default();
    systemd.set_property("ghars-runner@buckos.service", "MainPID", "0");
    let err = verify_runner_netns_at(
        tmp.path(),
        "ghars-runner@buckos.service",
        &systemd,
        TEST_NETNS_VERIFY_DEADLINE,
        TEST_NETNS_VERIFY_BACKOFF,
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("MainPID is 0"), "{msg}");
}

#[test]
fn verify_runner_netns_at_errors_on_main_pid_nonnumeric() {
    let tmp = tempfile::tempdir().unwrap();
    synth_host_only_proc_layout(tmp.path(), "net:[4026531992]");
    let systemd = MockSystemd::default();
    systemd.set_property("ghars-runner@buckos.service", "MainPID", "not-a-pid");
    let err = verify_runner_netns_at(
        tmp.path(),
        "ghars-runner@buckos.service",
        &systemd,
        TEST_NETNS_VERIFY_DEADLINE,
        TEST_NETNS_VERIFY_BACKOFF,
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("not u64"), "{msg}");
}

#[test]
fn verify_runner_netns_at_propagates_systemd_property_lookup_failure() {
    // MockSystemd returns a Systemd error when the property isn't
    // registered. The function must surface that as Apply{source:
    // Systemd} rather than panicking. (Host symlink present so we
    // get past the first readlink.)
    let tmp = tempfile::tempdir().unwrap();
    synth_host_only_proc_layout(tmp.path(), "net:[4026531992]");
    let systemd = MockSystemd::default();
    let err = verify_runner_netns_at(
        tmp.path(),
        "ghars-runner@buckos.service",
        &systemd,
        TEST_NETNS_VERIFY_DEADLINE,
        TEST_NETNS_VERIFY_BACKOFF,
    )
    .unwrap_err();
    match err {
        GharsError::Apply { source, .. } => {
            assert!(
                matches!(*source, GharsError::Systemd(_, _)),
                "expected Apply{{source: Systemd}}, got {source:?}"
            );
        }
        other => panic!("expected GharsError::Apply, got {other:?}"),
    }
}
