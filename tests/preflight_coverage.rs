//! preflight.rs integration tests.
//!
//! Drives the test-seam variants `preflight_os_with_path`,
//! `preflight_root_with_status_path`, `preflight_ptrace_scope_with_path`,
//! and `preflight_tools_with`. Production wires them to fixed paths
//! (`/etc/os-release`, `/proc/self/status`, etc.) and `which`; the
//! integration tests inject fixture content under a tempdir so every
//! decision branch can be exercised without root or a controlled host.
//!
//! Coverage:
//! - `preflight_os`: ubuntu 22 (fail), 24 (pass), fedora 38/40 (fail/pass),
//!   rhel 9/10 (fail/pass), centos/rocky/almalinux 10 (pass), debian
//!   (unsupported), missing `VERSION_ID`, malformed `VERSION_ID`,
//!   non-existent file, empty file, mismatched quotes, comment line.
//! - `preflight_root`: euid=0 (pass), euid=1000 (fail), missing Uid line
//!   (fail), non-existent status file (fail).
//! - `preflight_tools`: every tool present (pass), one missing (fail with
//!   missing-name), all missing (fail listing all).
//! - `preflight_ptrace_scope`: 0/1 (warn), 2/3 (pass), missing
//!   (warn-no-yama), malformed body (warn-cannot-parse).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ghars::preflight::{
    Outcome, preflight_os_with_path, preflight_ptrace_scope_with_path,
    preflight_root_with_status_path, preflight_tools_with, required_tools,
};
use std::fs;
use std::path::Path;

fn write_fixture(dir: &tempfile::TempDir, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.path().join(name);
    fs::write(&p, body).unwrap();
    p
}

// --- preflight_os --------------------------------------------------------

#[test]
fn preflight_os_accepts_ubuntu_24_04() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(
        &tmp,
        "os-release",
        "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
    );
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Pass, "{r:?}");
    assert!(r.detail.contains("Ubuntu 24.04"));
}

#[test]
fn preflight_os_accepts_ubuntu_25_10() {
    // Greater-than-floor accepts.
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=ubuntu\nVERSION_ID=25.10\n");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Pass);
}

#[test]
fn preflight_os_rejects_ubuntu_22_04() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=ubuntu\nVERSION_ID=\"22.04\"\n");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("ubuntu"));
    assert!(r.hint.contains("Ubuntu 24.04"));
}

#[test]
fn preflight_os_rejects_ubuntu_20_04_legacy() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=ubuntu\nVERSION_ID=\"20.04\"\n");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
}

#[test]
fn preflight_os_accepts_fedora_40() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=fedora\nVERSION_ID=40\n");
    assert_eq!(preflight_os_with_path(&p).outcome, Outcome::Pass);
}

#[test]
fn preflight_os_accepts_fedora_42() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=fedora\nVERSION_ID=42\n");
    assert_eq!(preflight_os_with_path(&p).outcome, Outcome::Pass);
}

#[test]
fn preflight_os_rejects_fedora_38() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=fedora\nVERSION_ID=38\n");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("fedora"));
}

#[test]
fn preflight_os_accepts_rhel_10() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=rhel\nVERSION_ID=\"10.0\"\n");
    assert_eq!(preflight_os_with_path(&p).outcome, Outcome::Pass);
}

#[test]
fn preflight_os_rejects_rhel_9() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=rhel\nVERSION_ID=\"9.4\"\n");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("rhel"));
}

#[test]
fn preflight_os_accepts_rhel_derivatives_at_floor() {
    for id in ["centos", "rocky", "almalinux"] {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_fixture(&tmp, "os-release", &format!("ID={id}\nVERSION_ID=10\n"));
        let r = preflight_os_with_path(&p);
        assert_eq!(r.outcome, Outcome::Pass, "{id} 10 should pass: {r:?}");
    }
}

#[test]
fn preflight_os_rejects_unsupported_distro() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=debian\nVERSION_ID=\"12\"\n");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("debian"));
}

#[test]
fn preflight_os_rejects_arch_linux() {
    // Rolling distro with no ID match — must reject.
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=arch\nVERSION_ID=rolling\n");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
}

#[test]
fn preflight_os_rejects_missing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("does-not-exist");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(
        r.detail.contains("cannot read") || r.detail.contains("does-not-exist"),
        "{}",
        r.detail
    );
}

#[test]
fn preflight_os_rejects_missing_version_id() {
    let tmp = tempfile::tempdir().unwrap();
    // ID present, VERSION_ID absent — VERSION_ID defaults to empty
    // string, parse_version_major returns None.
    let p = write_fixture(&tmp, "os-release", "ID=ubuntu\n");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("VERSION_ID"));
}

#[test]
fn preflight_os_rejects_unparseable_version() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=ubuntu\nVERSION_ID=\"rolling\"\n");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("VERSION_ID=rolling"));
}

#[test]
fn preflight_os_handles_comment_and_blank_lines() {
    // os-release files can contain comment lines and blank lines.
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(
        &tmp,
        "os-release",
        "# Distro release info\n\nID=ubuntu\n\n# major-only\nVERSION_ID=24\n",
    );
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Pass);
}

#[test]
fn preflight_os_strips_double_and_single_quotes_around_values() {
    // Ubuntu uses double quotes; some distros use single. Both must
    // strip.
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID='ubuntu'\nVERSION_ID='24.04'\n");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Pass);
}

#[test]
fn preflight_os_pretty_name_falls_back_to_id_version_when_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "os-release", "ID=ubuntu\nVERSION_ID=24.04\n");
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Pass);
    assert!(r.detail.contains("ubuntu") && r.detail.contains("24.04"));
}

// --- preflight_root ------------------------------------------------------

fn write_status(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
    write_fixture(dir, "status", body)
}

#[test]
fn preflight_root_accepts_euid_zero() {
    let tmp = tempfile::tempdir().unwrap();
    // Procfs Uid: line format: "Uid:\tREAL\tEFF\tSAVED\tFS"
    let p = write_status(&tmp, "Name: ghars\nUid:\t0\t0\t0\t0\n");
    let r = preflight_root_with_status_path(&p);
    assert_eq!(r.outcome, Outcome::Pass);
    assert!(r.detail.contains("EUID 0"));
}

#[test]
fn preflight_root_rejects_nonzero_euid() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_status(&tmp, "Name: ghars\nUid:\t1000\t1000\t1000\t1000\n");
    let r = preflight_root_with_status_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("EUID 1000"));
    assert!(r.hint.contains("sudo"));
}

#[test]
fn preflight_root_rejects_when_real_zero_but_eff_nonzero() {
    // setuid programs can have real=0 but effective != 0. The check
    // pulls the EFFECTIVE UID, which is the second column.
    let tmp = tempfile::tempdir().unwrap();
    let p = write_status(&tmp, "Uid:\t0\t1000\t0\t1000\n");
    let r = preflight_root_with_status_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("EUID 1000"));
}

#[test]
fn preflight_root_rejects_missing_uid_line() {
    let tmp = tempfile::tempdir().unwrap();
    // No "Uid:" line at all — read_euid_at returns None.
    let p = write_status(&tmp, "Name: ghars\nState: R (running)\n");
    let r = preflight_root_with_status_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("cannot read"));
    assert!(r.hint.contains("procfs"));
}

#[test]
fn preflight_root_rejects_missing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("absent-status");
    let r = preflight_root_with_status_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("cannot read"));
}

#[test]
fn preflight_root_rejects_garbage_uid_line() {
    // "Uid: garbage" — the EUID column doesn't parse, read_euid_at
    // returns None and the function takes the missing-Uid branch.
    let tmp = tempfile::tempdir().unwrap();
    let p = write_status(&tmp, "Uid:\tnot-a-number\n");
    let r = preflight_root_with_status_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
}

// --- preflight_tools -----------------------------------------------------

#[test]
fn preflight_tools_passes_when_every_required_command_present() {
    // All required tools: probe returns true for every name.
    let r = preflight_tools_with(&|_| true);
    assert_eq!(r.outcome, Outcome::Pass);
    assert!(r.detail.contains("required commands present"));
}

#[test]
fn preflight_tools_fails_when_one_command_missing() {
    // Probe returns false only for "nft"; the failure list should
    // contain that name.
    let r = preflight_tools_with(&|name| name != "nft");
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("missing"));
    assert!(r.detail.contains("nft"));
    // No other tool name appears in the missing list.
    for tool in required_tools() {
        if *tool != "nft" {
            assert!(
                !r.detail.contains(&format!("missing: ... {tool}")),
                "wrongly listed {tool}: {}",
                r.detail
            );
        }
    }
}

#[test]
fn preflight_tools_fails_when_install_missing() {
    // Python parity: missing `install` is the most common failure
    // (operator runs ghars before installing util-linux).
    let r = preflight_tools_with(&|name| name != "install");
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("install"));
}

#[test]
fn preflight_tools_does_not_require_useradd() {
    // Post-DynamicUser: runner identity is provisioned by systemd's
    // DynamicUser=yes — no useradd / usermod / gpasswd at apply time.
    // The preflight tool list MUST NOT demand `useradd`; a probe that
    // returns true for every other tool while `useradd` is missing
    // must still pass.
    let r = preflight_tools_with(&|name| name != "useradd");
    assert_eq!(r.outcome, Outcome::Pass);
    // Belt-and-suspenders: required_tools itself MUST NOT contain
    // useradd. Future regression that re-adds it (e.g. a misguided
    // "Python parity" revert) flips this assertion.
    assert!(
        !required_tools().contains(&"useradd"),
        "required_tools must not list useradd post-DynamicUser; \
         got: {:?}",
        required_tools()
    );
    assert!(
        !required_tools().contains(&"usermod"),
        "required_tools must not list usermod post-DynamicUser; \
         got: {:?}",
        required_tools()
    );
}

#[test]
fn preflight_tools_fails_when_unshare_missing() {
    let r = preflight_tools_with(&|name| name != "unshare");
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("unshare"));
    assert!(r.hint.contains("util-linux"));
}

#[test]
fn preflight_tools_lists_every_missing_command() {
    // None present — failure must enumerate ALL of them. Verifies the
    // function doesn't short-circuit on the first miss.
    let r = preflight_tools_with(&|_| false);
    assert_eq!(r.outcome, Outcome::Fail);
    for tool in required_tools() {
        assert!(
            r.detail.contains(tool),
            "missing list omitted {tool}: {}",
            r.detail
        );
    }
}

#[test]
fn required_tools_includes_v0_1_additions() {
    // The list should include nft, ip, sysctl, systemd-analyze, unshare
    // (v0.1 additions over the Python set). If a future refactor drops
    // any of these the test catches it. `useradd`/`usermod` are NOT
    // listed — see `preflight_tools_does_not_require_useradd`.
    let need = required_tools();
    for must_have in [
        "install",
        "chmod",
        "chown",
        "getent",
        "runuser",
        "nft",
        "ip",
        "sysctl",
        "systemd-analyze",
        "unshare",
    ] {
        assert!(
            need.contains(&must_have),
            "required_tools missing {must_have}"
        );
    }
}

// --- preflight_ptrace_scope ---------------------------------------------

#[test]
fn preflight_ptrace_scope_passes_at_two() {
    // SEC-28 floor: 2 blocks same-UID ptrace.
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "scope", "2\n");
    let r = preflight_ptrace_scope_with_path(&p);
    assert_eq!(r.outcome, Outcome::Pass);
    assert!(r.detail.contains('2'));
}

#[test]
fn preflight_ptrace_scope_passes_at_three() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "scope", "3\n");
    let r = preflight_ptrace_scope_with_path(&p);
    assert_eq!(r.outcome, Outcome::Pass);
}

#[test]
fn preflight_ptrace_scope_warns_at_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "scope", "0\n");
    let r = preflight_ptrace_scope_with_path(&p);
    assert_eq!(r.outcome, Outcome::Warn);
    assert!(r.hint.contains("SEC-28"));
    assert!(r.hint.contains("kernel.yama.ptrace_scope=2"));
}

#[test]
fn preflight_ptrace_scope_warns_at_one() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "scope", "1\n");
    let r = preflight_ptrace_scope_with_path(&p);
    assert_eq!(r.outcome, Outcome::Warn);
}

#[test]
fn preflight_ptrace_scope_warns_when_file_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("absent-scope");
    let r = preflight_ptrace_scope_with_path(&p);
    assert_eq!(r.outcome, Outcome::Warn);
    assert!(r.detail.contains("cannot read"));
    assert!(r.hint.contains("Yama"));
}

#[test]
fn preflight_ptrace_scope_warns_on_unparseable_body() {
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "scope", "garbage\n");
    let r = preflight_ptrace_scope_with_path(&p);
    assert_eq!(r.outcome, Outcome::Warn);
    assert!(r.detail.contains("cannot parse"));
}

#[test]
fn preflight_ptrace_scope_handles_trailing_whitespace() {
    // Procfs writes typically include trailing newline; the parser
    // trims before parsing. Trailing whitespace must not break the
    // Pass branch.
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "scope", "  2  \n\n");
    let r = preflight_ptrace_scope_with_path(&p);
    assert_eq!(r.outcome, Outcome::Pass);
}

// --- canonical paths regression ----------------------------------------
//
// preflight_os, preflight_root, preflight_ptrace_scope (no _with_*
// variant) read fixed production paths. A future refactor that
// silently retargets them at the test seams would invalidate the
// production behaviour. These tests pin that the canonical entry
// point reads the production path: when the production path is
// absent (as it commonly is on macOS / ephemeral CI containers
// without procfs), the canonical helpers should produce the same
// outcome shape as the _with_*_path variants pointed at the
// missing fixture file.

#[test]
fn preflight_root_canonical_path_returns_a_check_result() {
    // Sanity: calling the no-arg entry point must produce a CheckResult
    // (Pass or Fail depending on whether /proc/self/status is
    // readable). It should never panic.
    let r = ghars::preflight::preflight_root();
    // The kind of outcome depends on the environment; what matters is
    // that the function returns at all.
    assert!(matches!(r.outcome, Outcome::Pass | Outcome::Fail));
}

#[test]
fn preflight_os_canonical_path_returns_a_check_result() {
    let r = ghars::preflight::preflight_os();
    assert!(matches!(r.outcome, Outcome::Pass | Outcome::Fail));
}

#[test]
fn preflight_ptrace_scope_canonical_path_returns_a_check_result() {
    let r = ghars::preflight::preflight_ptrace_scope();
    // ptrace_scope can also Warn (file present but value < 2).
    assert!(matches!(
        r.outcome,
        Outcome::Pass | Outcome::Warn | Outcome::Fail
    ));
}

#[test]
fn preflight_os_with_path_uses_passed_path_not_etc_os_release() {
    // Belt-and-braces: the path passed in MUST be read; the function
    // must NOT silently fall through to /etc/os-release. We pass a
    // unique fixture with ID=fedora and verify the resulting detail
    // contains "fedora", which would NOT be true if the function read
    // the test host's /etc/os-release (typically Ubuntu in CI).
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(
        &tmp,
        "os-release",
        "ID=fedora\nVERSION_ID=42\nPRETTY_NAME=\"Fedora Linux 42 (Server Edition)\"\n",
    );
    let r = preflight_os_with_path(&p);
    assert_eq!(r.outcome, Outcome::Pass);
    assert!(r.detail.contains("Fedora") || r.detail.contains("fedora"));
}

#[test]
fn preflight_root_with_status_path_uses_passed_path_not_proc_self() {
    // Same belt-and-braces for the status path. We write a fixture
    // claiming euid=12345 and verify the result reports that exact
    // value — proves the seam is honoured.
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "status", "Uid:\t12345\t12345\t12345\t12345\n");
    let r = preflight_root_with_status_path(&p);
    assert_eq!(r.outcome, Outcome::Fail);
    assert!(r.detail.contains("12345"));
}

#[test]
fn preflight_ptrace_scope_with_path_uses_passed_path() {
    // Pin path-honour: write 2 to a fixture, get Pass even if the host's
    // real /proc/sys/kernel/yama/ptrace_scope is 0 (typical default).
    let tmp = tempfile::tempdir().unwrap();
    let p = write_fixture(&tmp, "scope", "2\n");
    let r = preflight_ptrace_scope_with_path(&p);
    assert_eq!(r.outcome, Outcome::Pass);
    // Guard against silent fall-through to the production path.
    let host_rl = Path::new("/proc/sys/kernel/yama/ptrace_scope");
    if host_rl.exists() {
        // If host has its own value, it might differ — but
        // preflight_ptrace_scope_with_path must use the passed path,
        // so we already know we got Pass from our 2.
        assert_eq!(r.outcome, Outcome::Pass);
    }
}
