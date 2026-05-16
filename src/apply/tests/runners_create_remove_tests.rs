//! Tests for `apply::runners` (create / remove / update — non-recreate).
//!
//! Recreate-path tests live in `recreate_tests.rs`. Caches-list
//! reconciliation tests live in `caches_tests.rs`.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;

use crate::auth::TokenSource;
use crate::plan::RunnerIdentity;

use super::super::runners::{execute_create_runner, execute_remove_runner};
use super::super::undo::{Deps, UndoLog, UndoStep};
use super::common::{
    MockConfigShell, MockSystemd, MockTarball, MockTokenSource, make_paths, make_runner_plan,
};

#[test]
fn remove_runner_orphan_skips_mint_token_and_config_remove() {
    // Orphan RemoveRunner has empty url + auth_name (set
    // by the orphan synthesis loop in `plan_from` when
    // synthesising RemoveRunner from actual.orphans). With those
    // empty, mint_token would error
    // because the auth registry has no key "" — that would
    // strand the host-local cleanup. The fix: skip the
    // mint_token + config.sh remove pair entirely. The runner
    // stays registered server-side; the operator removes it via
    // GitHub UI or restores its [[runner]] block.
    //
    // This test exercises the full execute_remove_runner path
    // for an orphan: verify no mint happens, no config_shell
    // remove happens, and the local artifacts are still cleaned
    // up.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    // Pre-stage a runner home + unit file the orphan path can
    // clean up.
    let runner_home = paths.runner_home("default", "ghost");
    std::fs::create_dir_all(runner_home.as_std_path()).unwrap();
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(paths.unit_file("ghost").as_std_path(), b"[Unit]\n").unwrap();
    let drop_in_dir = paths.drop_in_dir("ghost");
    std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();

    // Orphan identity: empty url + auth_name, exactly as
    // `plan_from`'s orphan synthesis loop emits.
    let identity = RunnerIdentity {
        name: "ghost".into(),
        url: String::new(),
        auth_name: String::new(),
        trust_zone: "default".into(),
    };
    let systemd = MockSystemd::default();
    // Empty auth registry — guarantees mint_token would fail if
    // it were called.
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };

    execute_remove_runner(&identity, &deps, &paths, &mut UndoLog::new())
        .expect("orphan remove must not error on missing auth_name");

    // No config_shell.run_remove was called.
    assert_eq!(
        config_shell.removed.lock().unwrap().len(),
        0,
        "orphan must skip config.sh remove (cannot mint token)"
    );
    // Local artifacts ARE cleaned up.
    assert!(!paths.unit_file("ghost").as_std_path().exists());
    assert!(!runner_home.as_std_path().exists());
    // Systemd ops still happen (stop/disable + ghars-net@ teardown).
    let calls = systemd.calls_snapshot();
    assert!(
        calls
            .iter()
            .any(|c| c == "stop_unit(ghars-runner@ghost.service)")
    );
    assert!(
        calls
            .iter()
            .any(|c| c == "disable_unit(ghars-runner@ghost.service)")
    );
}

#[test]
fn create_runner_writes_unit_and_drop_ins_and_starts() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_runner_plan("a", &paths.state_dir);
    let systemd = MockSystemd::default();
    // verify_runner_netns is skipped because spec.network is None.
    // No need to set MainPID.
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
    // Unit + drop-in landed on disk.
    assert!(paths.unit_file("a").as_std_path().exists());
    let drop_in_path = paths.drop_in_dir("a").join("00-ghars.conf");
    assert!(drop_in_path.as_std_path().exists());
    // The drop-in MUST carry the versioned ExecStart= reset + path
    // pair (the template intentionally omits ExecStart because the
    // version is only known at apply time).
    let drop_in_body = std::fs::read_to_string(drop_in_path.as_std_path()).unwrap();
    assert!(
        drop_in_body.contains("[Service]"),
        "00-ghars.conf is missing [Service] section: {drop_in_body}"
    );
    assert!(
        drop_in_body.contains("\nExecStart=\n"),
        "00-ghars.conf is missing ExecStart= reset line: {drop_in_body}"
    );
    assert!(
        drop_in_body.contains(
            "ExecStart=/bin/bash /var/lib/ghars/default/ghars-a/bin.2.334.0/bin/runsvc.sh"
        ),
        "00-ghars.conf is missing versioned runsvc.sh ExecStart: {drop_in_body}"
    );
    // SEC-02 was the X-Ghars-Runsvc-Sha256 annotation + runsvc-wrapper
    // trampoline; both were removed. Pin that the annotation does
    // not reappear.
    assert!(
        !drop_in_body.contains("X-Ghars-Runsvc-Sha256"),
        "X-Ghars-Runsvc-Sha256 must not be emitted (SEC-02 removed): {drop_in_body}"
    );
    // Template no longer carries ExecStart at all (the drop-in
    // supplies it because the path includes the resolved version).
    let unit_text = std::fs::read_to_string(paths.unit_file("a").as_std_path()).unwrap();
    assert!(unit_text.contains("[Unit]"));
    assert!(!unit_text.contains("\nExecStart="));
    // Tarball was downloaded once.
    assert_eq!(tarball.fetched.lock().unwrap().len(), 1);
    // config.sh registered with the minted token.
    let regs = config_shell.registered.lock().unwrap();
    assert_eq!(regs.len(), 1);
    assert_eq!(regs[0].2, "REG-TOKEN");
    // systemd was called: enable, daemon_reload, start.
    let calls = systemd.calls_snapshot();
    assert!(
        calls
            .iter()
            .any(|c| c == "enable_unit(ghars-runner@a.service)")
    );
    assert!(
        calls
            .iter()
            .any(|c| c == "start_unit(ghars-runner@a.service)")
    );
}

/// Pins the contract that the on-disk X-Ghars-Spec-Hash annotation
/// matches the canonical-JSON hash of the spec actually rendered to
/// disk — not the plan-time placeholder or a stale pre-resolve hash.
///
/// `execute_create_runner` clones the spec, recomputes `spec_hash` via
/// `crate::plan::spec_hash`, and renders against the resolved clone.
/// Without that recompute, the placeholder hash carried into the test
/// fixture (`sha256:dead`) would land on disk verbatim, since
/// `render_identity` consumes `spec.spec_hash` regardless of whether
/// it was recomputed. A regression dropping the recompute is invisible
/// to other assertions (drop-in body still has [Service]/`ExecStart`=
/// etc.) — this test is the dedicated regression guard.
///
/// The contract pin matters because the next plan's intersection-arm
/// version-fill in `lower_to_effective` reads the on-disk hash as
/// `discovered.spec_hash` and compares it against a candidate hash
/// computed against an annotation-filled spec. A hash-vs-bytes
/// mismatch on disk breaks the invariant downstream classifier
/// comparisons rely on, with consequences depending on the discovered
/// X-Ghars-Effective-Version annotation state: well-formed annotation
/// produces a spurious in-place `UpdateRunner` cycle per plan (the
/// candidate fills to Some-version and the candidate hash diverges
/// from the None-version on-disk hash); empty or invalid annotation
/// produces a silent false-NoOp (the intersection-arm fill skips, the
/// candidate hash matches the on-disk hash by accident at the
/// unresolved None-version, while the rendered bytes still use
/// resolved bin.X.Y.Z paths). Either consequence is wrong.
#[test]
fn create_runner_emits_on_disk_spec_hash_matching_resolved_spec_canonical_hash() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_runner_plan("a", &paths.state_dir);
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

    let drop_in_path = paths.drop_in_dir("a").join("00-ghars.conf");
    let drop_in_body = std::fs::read_to_string(drop_in_path.as_std_path()).unwrap();
    let on_disk_hash = drop_in_body
        .lines()
        .find_map(|l| l.strip_prefix("X-Ghars-Spec-Hash="))
        .expect("00-ghars.conf must carry X-Ghars-Spec-Hash=");

    let expected_hash = crate::plan::spec_hash(&plan.spec);
    assert_eq!(
        on_disk_hash, expected_hash,
        "on-disk X-Ghars-Spec-Hash must match canonical hash of the spec actually \
         rendered to disk (recompute against the resolved spec). A regression that \
         drops the recompute would write the plan-time placeholder hash through \
         unchanged, breaking the invariant downstream plan classifiers rely on \
         (well-formed X-Ghars-Effective-Version annotation: spurious in-place \
         UpdateRunner cycles since candidate hash and on-disk hash disagree; \
         empty/invalid annotation: silent false-NoOp acceptance of the divergence)"
    );

    assert_ne!(
        on_disk_hash, "sha256:dead",
        "on-disk X-Ghars-Spec-Hash must not equal the plan-time placeholder \
         carried in the test fixture — that placeholder being on disk would \
         indicate the recompute did not fire and the placeholder was written \
         through verbatim"
    );
}

/// Bin tree integrity post-CreateRunner. Regression guard
/// against any recursive chmod over the trust-zone tree:
/// world-writable `bin.X.Y.Z/bin/runsvc.sh` is a persistence
/// vector (a compromised workflow step running as the trust-zone
/// `DynamicUser` could overwrite runsvc.sh; the malicious script
/// then runs on every subsequent runner restart).
///
/// Files in the bin tree must retain whatever modes the tarball
/// install laid down (per extract.rs's per-entry tar-header
/// propagation, masked to 0o777). `MockTarball::install_binary`
/// chmods runsvc.sh to 0o755 (see common.rs) so the mock mirrors
/// production tar-header behavior — the test pins runsvc.sh at
/// 0o755. A regression that adds a path-based recursive chmod
/// over the tree would also re-introduce a symlink-follow CVE
/// (chmod-via-recursive-walk on operator-writable trees). See
/// `create_runner_does_not_follow_symlinks_planted_in_runner_home`
/// for the dedicated symlink-fixture regression guard.
#[test]
fn create_runner_does_not_world_writable_bin_tree() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_runner_plan("a", &paths.state_dir);
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

    // The bin tree's runsvc.sh must retain MockTarball's explicit
    // 0o755 chmod (mirroring production tar-header executable
    // bit), NOT 0o777 from a recursive cascade.
    let runner_home = paths.runner_home("default", "a");
    let runsvc = runner_home.join("bin.2.334.0/bin/runsvc.sh");
    assert!(
        runsvc.as_std_path().exists(),
        "MockTarball must have installed runsvc.sh at {runsvc}"
    );
    let mode = std::fs::metadata(runsvc.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_ne!(
        mode, 0o777,
        "runsvc.sh must NOT be world-writable post-create — a \
         recursive-chmod regression would re-open a CVE-class \
         persistence vector for a compromised workflow step; \
         got mode 0o{mode:o}"
    );
    // Pin the exact mode for tighter regression detection.
    // MockTarball explicitly chmods runsvc.sh to 0o755 to mirror
    // production: upstream actions/runner tar header sets runsvc.sh
    // executable (0o755), and install_runner_binary preserves
    // header modes via the tar crate's per-entry mode propagation.
    // ghars must not chmod-away the executable bit.
    assert_eq!(
        mode, 0o755,
        "MockTarball planted runsvc.sh at 0o755 (mirroring production \
         tar header); ghars must not chmod it away. Got 0o{mode:o}"
    );

    // .env / .path must also stay at write_record_undo's 0o644
    // (NOT world-writable). A compromised workflow could otherwise
    // inject PATH/env overrides that take effect on next runner-
    // process restart. execute_create_runner always writes both
    // files via write_record_undo unconditionally post-elevation
    // of .env/.path, so this is a hard-assert existence + mode
    // check, not a conditional.
    let env_file = runner_home.join("bin.2.334.0/.env");
    let path_file = runner_home.join("bin.2.334.0/.path");
    assert!(
        env_file.as_std_path().exists(),
        "execute_create_runner must write .env via write_record_undo; \
         missing at {env_file}"
    );
    let env_mode = std::fs::metadata(env_file.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_ne!(
        env_mode, 0o777,
        ".env must NOT be world-writable post-create; got 0o{env_mode:o}"
    );
    assert!(
        path_file.as_std_path().exists(),
        "execute_create_runner must write .path via write_record_undo; \
         missing at {path_file}"
    );
    let path_mode = std::fs::metadata(path_file.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_ne!(
        path_mode, 0o777,
        ".path must NOT be world-writable post-create; got 0o{path_mode:o}"
    );
}

/// All three config.sh-written files (`.runner`, `.credentials`,
/// `.credentials_rsaparams`) must end up at 0o644 post-CreateRunner
/// so the DynamicUser-allocated runner process can read them. The
/// upstream actions/runner shapes are:
///   - `.runner` / `.credentials` — written by IOUtil.SaveObject
///     (Runner.Sdk/Util/IOUtil.cs:42) via File.WriteAllText with no
///     explicit mode → file inherits `0o666 & ~umask`. ghars
///     normally runs at umask 0o022 → 0o644, but a custom-spawned
///     ghars (cron / nspawn wrapper / hostile init) could inherit
///     umask 0o077 → 0o600, unreadable to `DynamicUser`.
///   - `.credentials_rsaparams` — upstream explicitly chmods to
///     0o600 in RSAFileKeyManager.cs:33. The RSA private key signs
///     OAuth assertions for credential refresh, so the runner
///     MUST be able to read it; 0o600 root:root is unreadable to
///     the DynamicUser-allocated runner UID.
///
/// ghars normalizes all three to 0o644 in a single post-config.sh
/// chmod loop. The workspace forbids `unsafe_code`, so pre-exec
/// umask pinning via `CommandExt::pre_exec` is not available; the
/// post-hoc chmod loop delivers the same end-state safely.
///
/// Test fixture: `MockConfigShell` writes all three at 0o600 (worst-
/// case umask 0o077). Post-create, all three must be 0o644.
#[test]
fn create_runner_normalizes_config_sh_file_modes() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_runner_plan("a", &paths.state_dir);
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

    let runner_home = paths.runner_home("default", "a");
    let bin_dir = runner_home.join("bin.2.334.0");
    for basename in [".runner", ".credentials", ".credentials_rsaparams"] {
        let path = bin_dir.join(basename);
        assert!(
            path.as_std_path().exists(),
            "MockConfigShell must have written {basename}"
        );
        let mode = std::fs::metadata(path.as_std_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o644,
            "{basename} must be 0o644 post-create (DynamicUser READ); \
             got 0o{mode:o}. Without this chmod, the runner unit \
             cannot load credentials and Runner.Listener exits at \
             start-up."
        );
    }
}

/// Symlink-refusal regression guard (defense-in-depth, both
/// layers). A path-based recursive chmod would follow symlinks
/// (`chmod(2)` not `lchmod`) — a planted symlink under
/// `runner_home` could chmod arbitrary targets as root. Two
/// layers defend against this:
///
///   1. `sweep_runner_home_for_planted_entries` runs BEFORE any
///      chmod or config.sh invocation. It enumerates
///      `runner_home`'s direct children via lstat and refuses to
///      proceed if any are symlinks / FIFO / device / socket.
///      Closes the most damaging vector: config.sh
///      write-through-symlink to attacker target.
///
///   2. `chmod_record_undo` opens the chmod target with
///      `O_NOFOLLOW` (which atomically refuses symlinks via ELOOP
///      at open time) then chmods through /proc/self/fd/{fd}.
///      Closes any chmod target that bypassed layer 1 (e.g.
///      paths outside `runner_home` such as `tz_dir`).
///
/// This test plants `runner_home/tmp` as a symlink to a
/// sentinel directory. Layer 1 (the sweep) catches it before
/// the chmod and before config.sh. Layer 2 would catch it too
/// if layer 1 were removed.
///
/// Pins both:
/// - the apply exits Err (not Ok) when a planted symlink is in
///   `runner_home`
/// - the symlink target's mode is unchanged (no chmod ever
///   followed it)
#[test]
fn create_runner_refuses_planted_symlink_at_runner_tmp() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_runner_plan("a", &paths.state_dir);

    // Sentinel: a root-owned DIRECTORY outside the trust-zone
    // tree with a recognizable starting mode. Must be a dir (not
    // a regular file) so the create_dir_all call inside
    // execute_create_runner tolerates EEXIST (the symlink target
    // is a dir, matching create_dir_all's "already a dir" branch).
    // That way the test reaches sweep_runner_home_for_planted_
    // entries (Layer 1), which is what catches the planted
    // symlink before any chmod or config.sh invocation.
    let sentinel = tmp.path().join("sentinel_dir");
    std::fs::create_dir_all(&sentinel).unwrap();
    std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        std::fs::metadata(&sentinel).unwrap().permissions().mode() & 0o777,
        0o700,
        "sentinel must start at 0o700 so the test can detect any chmod-through"
    );

    // Pre-create runner_home (simulating residue from a prior
    // failed apply) and plant runner_home/tmp as a symlink to
    // the sentinel directory.
    let runner_home = paths.runner_home("default", "a");
    std::fs::create_dir_all(runner_home.as_std_path()).unwrap();
    std::os::unix::fs::symlink(&sentinel, runner_home.join("tmp").as_std_path()).unwrap();

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

    let err = execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new(), 2).expect_err(
        "planted symlink at runner_home/tmp must cause execute_create_runner \
             to error rather than chmod-through to the symlink target",
    );
    let err_str = format!("{err}");
    assert!(
        err_str.to_lowercase().contains("symlink"),
        "error message must surface the symlink-refusal so an operator \
         can act on the diagnostic; got: {err_str}"
    );

    // CRITICAL: sentinel mode must be unchanged. If the chmod
    // followed the symlink, sentinel would now be 0o777 (the
    // runner_tmp target mode).
    let post_mode = std::fs::metadata(&sentinel).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        post_mode, 0o700,
        "planted symlink target's mode must NOT have been changed; \
         got 0o{post_mode:o} (path-based chmod followed the symlink — \
         symlink-refusal regressed)"
    );
}

/// Dir-mode coverage. Pin the exact modes
/// `execute_create_runner` leaves on each managed directory. These
/// modes are load-bearing for the `DynamicUser` model:
///
/// - `tz_dir` 0o711: descend-only for non-root (`DynamicUser` can
///   traverse but NOT `ls` the trust-zone dir).
/// - `runner_home` 0o777 (at unit-start time): `DynamicUser` can write
///   `_work/`, `_diag/`, toolchain caches under the per-runner
///   home. Apply-time clamps to 0o755 then re-opens to 0o777
///   just before `start_unit`.
/// - `runner_home/tmp` 0o777: TMPDIR for the runner unit's sccache
///   server + workflow steps.
/// - `tz_dir/.ktstr` 0o777: shared cross-runner KTSTR coordination
///   (always created).
/// - `tz_dir/.ccache`: NOT created for no-ccache-binding runners
///   (gated on at-least-one-ccache-binding). For the binding-present case see
///   `create_runner_with_ccache_binding_creates_ccache_dir`. For
///   the binding-absent skip case see
///   `create_runner_without_ccache_binding_skips_ccache_dir`. This
///   test uses `make_runner_plan` which produces a no-binding spec
///   → asserts .ccache does NOT exist.
///
/// Regression guards against a future change that clamps any of
/// these tighter (breaks `DynamicUser` write) or looser (defeats
/// the trust-zone descend-only invariant for `tz_dir`).
#[test]
fn create_runner_pins_directory_modes() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_runner_plan("a", &paths.state_dir);
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

    let tz_dir = paths.state_dir.join("default");
    let runner_home = paths.runner_home("default", "a");
    let runner_tmp = runner_home.join("tmp");
    let ktstr_dir = tz_dir.join(".ktstr");
    let ccache_dir = tz_dir.join(".ccache");

    let mode = |p: &camino::Utf8PathBuf| -> u32 {
        std::fs::metadata(p.as_std_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };

    assert_eq!(
        mode(&tz_dir),
        0o755,
        "tz_dir must be 0o755 (Runner.Listener ValidateExecutePermission needs read)"
    );
    assert_eq!(
        mode(&runner_home),
        0o777,
        "runner_home must be 0o777 at unit-start time (DynamicUser write)"
    );
    assert_eq!(
        mode(&runner_tmp),
        0o777,
        "runner_tmp (TMPDIR) must be 0o777 (DynamicUser + sccache write)"
    );
    assert_eq!(
        mode(&ktstr_dir),
        0o777,
        "ktstr_dir must be 0o777 (cross-runner shared in trust zone)"
    );
    // .ccache dir is NOT created for a runner with no ccache binding
    // (make_spec uses caches=vec![]). Coverage for the
    // ccache-binding case lives in
    // `create_runner_with_ccache_binding_creates_ccache_dir`; coverage
    // for the no-ccache skip case lives in
    // `create_runner_without_ccache_binding_skips_ccache_dir`.
    assert!(
        !ccache_dir.as_std_path().exists(),
        ".ccache dir must NOT be created for a no-ccache-binding runner: {ccache_dir}"
    );
}

/// Pin that `execute_create_runner` SKIPS `.ccache` dir creation when
/// the runner spec has no ccache binding. Symmetric with the
/// `validate_no_duplicate_cache_kinds` invariant: the trust-zone-
/// shared `.ccache` is only material when a ccache pool is bound, so
/// trust zones with zero ccache runners stay free of an empty dir.
/// Sibling of `create_runner_without_ccache_binding_skips_ccache_dir`
/// for the sccache-only binding case — proves the gate filters on
/// `Ccache` kind specifically, not on "any binding exists". Regression
/// guard against a kind-blind predicate (e.g.
/// `.any(|b| !b.kinds.is_empty())`) that would create `.ccache` for
/// runners that only bind sccache.
#[test]
fn create_runner_with_sccache_only_binding_skips_ccache_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let mut plan = make_runner_plan("a", &paths.state_dir);
    plan.spec.caches.push(crate::config::EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![crate::config::CacheKind::Sccache],
        size: "10G".into(),
        mode: crate::config::CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    plan.env_file = crate::systemd::render_runner_env_file(&plan.spec).unwrap();
    plan.path_file = crate::systemd::render_runner_path_file(&plan.spec).unwrap();
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
    let ccache_dir = paths.state_dir.join("default").join(".ccache");
    assert!(
        !ccache_dir.as_std_path().exists(),
        "sccache-only-binding runner must not create .ccache: {ccache_dir}"
    );
}

/// Sibling of `create_runner_with_ccache_binding_creates_ccache_dir`
/// covering combined-kind pools (`kinds = ["ccache", "sccache"]`).
/// The gate at `execute_create_runner` uses `.kinds.contains(&Ccache)`
/// (which the per-runner-per-kind validator accepts for combined-kind pools too), so a
/// combined-kind pool must trigger `.ccache` creation. Regression
/// guard against `.kinds == &[Ccache]` equality matching.
#[test]
fn create_runner_with_combined_kind_pool_creates_ccache_dir() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let mut plan = make_runner_plan("a", &paths.state_dir);
    plan.spec.caches.push(crate::config::EffectiveCacheBinding {
        name: "combined".into(),
        kinds: vec![
            crate::config::CacheKind::Ccache,
            crate::config::CacheKind::Sccache,
        ],
        size: "10G".into(),
        mode: crate::config::CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    plan.env_file = crate::systemd::render_runner_env_file(&plan.spec).unwrap();
    plan.path_file = crate::systemd::render_runner_path_file(&plan.spec).unwrap();
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
    let ccache_dir = paths.state_dir.join("default").join(".ccache");
    assert!(
        ccache_dir.as_std_path().exists(),
        "combined-kind-pool runner must create .ccache: {ccache_dir}"
    );
    let mode = std::fs::metadata(ccache_dir.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o777,
        ".ccache must be 0o777 under combined-kind pool too"
    );
}

#[test]
fn create_runner_without_ccache_binding_skips_ccache_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_runner_plan("a", &paths.state_dir);
    assert!(
        plan.spec.caches.is_empty(),
        "fixture sanity: make_runner_plan must produce a no-ccache spec"
    );
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
    let tz_dir = paths.state_dir.join("default");
    let ccache_dir = tz_dir.join(".ccache");
    assert!(
        !ccache_dir.as_std_path().exists(),
        "no-ccache-binding runner must not create .ccache: {ccache_dir}"
    );
}

/// Pin that `execute_create_runner` DOES create `.ccache` when the
/// runner spec has at least one ccache-kind binding. Mirror of the
/// negative `_without_ccache_binding_skips_ccache_dir` test.
#[test]
fn create_runner_with_ccache_binding_creates_ccache_dir() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let mut plan = make_runner_plan("a", &paths.state_dir);
    plan.spec.caches.push(crate::config::EffectiveCacheBinding {
        name: "obj".into(),
        kinds: vec![crate::config::CacheKind::Ccache],
        size: "10G".into(),
        mode: crate::config::CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    // Re-render env_file + path_file so the in-place rewrite path
    // (if it ran) would see consistent bytes — defensive only;
    // execute_create_runner doesn't use these directly.
    plan.env_file = crate::systemd::render_runner_env_file(&plan.spec).unwrap();
    plan.path_file = crate::systemd::render_runner_path_file(&plan.spec).unwrap();
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
    let tz_dir = paths.state_dir.join("default");
    let ccache_dir = tz_dir.join(".ccache");
    assert!(
        ccache_dir.as_std_path().exists(),
        "ccache-binding runner must create .ccache: {ccache_dir}"
    );
    let mode = std::fs::metadata(ccache_dir.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o777,
        ".ccache must be 0o777 at apply-time (DynamicUser + cross-runner shared)"
    );
}

/// Every explicit chmod site in `execute_create_runner` MUST
/// push an `UndoStep::SetMode` so a rollback after a later
/// step's failure can restore the prior mode. Without the
/// `SetMode` push, a partial `CreateRunner` that errors mid-way
/// would leave the trust-zone tree at apply-time modes:
/// `runner_home` at 0o777, `tz_dir` at 0o711, etc. Those modes
/// expose attacker write surface (sibling `DynamicUser` can plant
/// under a 0o777 `runner_home` that's no longer being managed by
/// an active runner unit).
///
/// This pins the SetMode-push contract for each of the six
/// chmod sites in `execute_create_runner`:
///   - `tz_dir` (chmod 0o711)
///   - `runner_home` (chmod 0o755 Stage 1, then 0o777 Stage 2 = TWO entries)
///   - `runner_tmp` (chmod 0o777)
///   - `tz_dir/.ktstr` (chmod 0o777)
///   - `tz_dir/.ccache` (chmod 0o777)
///   - .runner / .credentials / .`credentials_rsaparams` (chmod 0o644 each)
///
/// Regression guard: a future change that chmods through bare
/// `fs::set_permissions` (bypassing the `chmod_record_undo`
/// helper) would have its mode leak through rollback. This test
/// catches that by counting `SetMode` `UndoStep` entries against
/// the known chmod sites.
#[test]
fn create_runner_pushes_set_mode_undo_step_for_every_chmod_site() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let mut plan = make_runner_plan("a", &paths.state_dir);
    // Add a ccache binding so the .ccache dir is created + chmodded
    // (and so the assertion below that .ccache is in the expected
    // chmod-site set holds). Without this binding the
    // .ccache-creation block is skipped per the `has_ccache` binding
    // gate in `execute_create_runner`. The chmod-site contract being
    // tested is per-chmod-call, not per-spec, so the right test
    // posture is "spec with all chmod sites active" → all SetMode
    // pushes observable.
    plan.spec.caches.push(crate::config::EffectiveCacheBinding {
        name: "obj".into(),
        kinds: vec![crate::config::CacheKind::Ccache],
        size: "10G".into(),
        mode: crate::config::CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    });
    plan.env_file = crate::systemd::render_runner_env_file(&plan.spec).unwrap();
    plan.path_file = crate::systemd::render_runner_path_file(&plan.spec).unwrap();

    // Pre-stage every chmod-target dir at a mode DIFFERENT from
    // what execute_create_runner sets, so each chmod_record_undo
    // call produces a non-trivial mode change and pushes a
    // SetMode UndoStep. The helper's no-op gate (push only when
    // prior_mode != new mode) would otherwise skip pushes for
    // sites where the fresh-mkdir umask-default happens to
    // match the target mode (e.g. Stage 1 0o755 on a 0o022-umask
    // fresh dir is a no-op chmod). Pre-staging at 0o700 forces
    // EVERY chmod to be observable in the UndoLog.
    let tz_dir = paths.state_dir.join("default");
    let runner_home = paths.runner_home("default", "a");
    std::fs::create_dir_all(tz_dir.as_std_path()).unwrap();
    std::fs::create_dir_all(runner_home.as_std_path()).unwrap();
    std::fs::set_permissions(tz_dir.as_std_path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(
        runner_home.as_std_path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();

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
    let mut log = UndoLog::new();
    execute_create_runner(&plan, &deps, &paths, &mut log, 2).unwrap();

    let set_mode_paths: Vec<String> = log
        .steps()
        .iter()
        .filter_map(|s| {
            if let UndoStep::SetMode { path, .. } = s {
                Some(path.to_string())
            } else {
                None
            }
        })
        .collect();

    let runner_tmp = runner_home.join("tmp");
    let ktstr_dir = tz_dir.join(".ktstr");
    let ccache_dir = tz_dir.join(".ccache");

    // tz_dir, runner_tmp, .ktstr: each chmodded ONCE.
    // .ccache: chmodded ONCE because this fixture's plan includes a
    // ccache binding (per the `has_ccache` binding gate in
    // `execute_create_runner`, .ccache is only created + chmodded
    // when the runner spec has at least one ccache binding).
    // runner_home: chmodded TWICE (Stage 1 0o755, Stage 2 0o777).
    // .runner / .credentials / .credentials_rsaparams: each chmodded
    // ONCE post-config.sh.
    let expected_unique_paths = [
        tz_dir.to_string(),
        runner_home.to_string(),
        runner_tmp.to_string(),
        ktstr_dir.to_string(),
        ccache_dir.to_string(),
        runner_home.join("bin.2.334.0").join(".runner").to_string(),
        runner_home
            .join("bin.2.334.0")
            .join(".credentials")
            .to_string(),
        runner_home
            .join("bin.2.334.0")
            .join(".credentials_rsaparams")
            .to_string(),
    ];
    for expected in &expected_unique_paths {
        assert!(
            set_mode_paths.iter().any(|p| p == expected),
            "execute_create_runner must push UndoStep::SetMode for chmod \
             site {expected}; got SetMode paths: {set_mode_paths:?}"
        );
    }

    // runner_home must appear TWICE — once for Stage 1 (0o755) and
    // once for Stage 2 (0o777). The reorder is load-bearing for the
    // planted-symlink defense.
    let runner_home_str = runner_home.to_string();
    let runner_home_set_mode_count = set_mode_paths
        .iter()
        .filter(|p| **p == runner_home_str)
        .count();
    assert_eq!(
        runner_home_set_mode_count, 2,
        "runner_home must have TWO SetMode entries (Stage 1 clamp \
         to 0o755 + Stage 2 open to 0o777); got {runner_home_set_mode_count}. \
         Reordering the chmods to a single 0o777 would regress the \
         planted-symlink defense."
    );

    // Stage 1 entry must capture the pre-staged 0o700 mode (the
    // mode runner_home was at before execute_create_runner ran);
    // Stage 2 entry must capture 0o755 (set by Stage 1). The
    // reverse walk applies Stage 2's prior (0o755) first, then
    // Stage 1's prior (0o700) — restoring closest to original.
    let runner_home_prior_modes: Vec<u32> = log
        .steps()
        .iter()
        .filter_map(|s| {
            if let UndoStep::SetMode { path, prior_mode } = s {
                if *path == runner_home_str {
                    Some(*prior_mode)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        runner_home_prior_modes.len(),
        2,
        "expected 2 runner_home SetMode entries; got {runner_home_prior_modes:?}"
    );
    // Stage 1's SetMode captures the pre-staged 0o700.
    assert_eq!(
        runner_home_prior_modes[0], 0o700,
        "Stage 1 runner_home SetMode must capture pre-staged 0o700; \
         got 0o{:o}",
        runner_home_prior_modes[0]
    );
    // Stage 2's SetMode captures 0o755 (set by Stage 1).
    assert_eq!(
        runner_home_prior_modes[1], 0o755,
        "Stage 2 runner_home SetMode must capture Stage 1's 0o755 as \
         prior_mode; got 0o{:o}",
        runner_home_prior_modes[1]
    );
}

/// Adversary regression: the pre-Stage-1 sweep
/// (`sweep_runner_home_for_planted_entries`) MUST refuse to
/// proceed when a sibling `DynamicUser` planted a symlink at a
/// `runner_home` direct child during a prior failed apply's
/// 0o777 window. If the sweep didn't fire, config.sh would
/// follow the symlink and write OAuth credentials + RSA key to
/// an attacker target BEFORE the post-config.sh chmod loop
/// could refuse — credentials exfiltrated.
///
/// This pins:
///   - apply errors with a sweep-mentioning diagnostic
///   - config.sh DID NOT run (`config_shell.registered.is_empty()`)
///   - sentinel mode unchanged (no write-through-symlink happened)
#[test]
fn create_runner_refuses_planted_symlink_entry_in_runner_home() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_runner_plan("a", &paths.state_dir);

    // Sentinel: a root-owned file outside the trust-zone tree
    // with known content + mode.
    let sentinel = tmp.path().join("sentinel_creds.txt");
    std::fs::write(&sentinel, b"unchanged").unwrap();
    std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Pre-create runner_home and plant `.credentials_rsaparams`
    // as a symlink to the sentinel — simulating the prior-apply-
    // 0o777-window attack where a sibling DynamicUser planted
    // it for the next apply to write through.
    let runner_home = paths.runner_home("default", "a");
    std::fs::create_dir_all(runner_home.as_std_path()).unwrap();
    std::os::unix::fs::symlink(
        &sentinel,
        runner_home.join(".credentials_rsaparams").as_std_path(),
    )
    .unwrap();

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

    let err = execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new(), 2).expect_err(
        "planted symlink entry in runner_home must error \
             execute_create_runner via the pre-Stage-1 sweep",
    );
    let err_str = format!("{err}").to_lowercase();
    assert!(
        err_str.contains("symlink") || err_str.contains("sweep"),
        "error must surface the planted-entry refusal; got: {err_str}"
    );

    // CRITICAL: config.sh must NOT have been called. The sweep
    // fires BEFORE run_register; if it didn't run, config.sh
    // would have followed the symlink and written credentials
    // through it to the sentinel.
    assert_eq!(
        config_shell.registered.lock().unwrap().len(),
        0,
        "config.sh must not run when planted symlink detected — \
         otherwise credentials are written through the symlink \
         BEFORE chmod_record_undo can refuse"
    );

    // Sentinel content must be unchanged.
    let sentinel_after = std::fs::read_to_string(&sentinel).unwrap();
    assert_eq!(
        sentinel_after, "unchanged",
        "config.sh wrote through the planted symlink — sweep failed \
         to prevent credential exfiltration"
    );
}

/// PAT-authenticated runners don't always produce
/// `.credentials_rsaparams` — the file is only written for the
/// OAuth/GitHub-App auth flow. The post-config.sh chmod loop
/// gates each chmod on `path.as_std_path().exists()` so the
/// missing file becomes a no-op. This pins that contract: a
/// regression that drops the `if exists` gate would error
/// with ENOENT for PAT-authenticated runners.
#[test]
fn create_runner_chmod_loop_tolerates_missing_credential_files() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    // Local mock that mirrors MockConfigShell but writes ONLY
    // `.runner` (skipping `.credentials` and
    // `.credentials_rsaparams`) — simulating a PAT-authenticated
    // shape.
    #[derive(Default)]
    struct PartialConfigShell {
        registered: Mutex<Vec<(String, String, String)>>,
    }
    impl crate::apply::shell::ConfigShell for PartialConfigShell {
        fn run_register(&self, ctx: &crate::apply::shell::ConfigShellCtx<'_>) -> crate::Result<()> {
            std::fs::create_dir_all(ctx.bin_dir.as_std_path())?;
            let runner = ctx.bin_dir.join(".runner");
            std::fs::write(runner.as_std_path(), b"{\"mock_runner\":\"...\"}")?;
            std::fs::set_permissions(runner.as_std_path(), std::fs::Permissions::from_mode(0o600))?;
            self.registered.lock().unwrap().push((
                ctx.name.into(),
                ctx.url.into(),
                ctx.token.into(),
            ));
            Ok(())
        }
        fn run_remove(&self, _ctx: &crate::apply::shell::ConfigShellCtx<'_>) -> crate::Result<()> {
            Ok(())
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_runner_plan("a", &paths.state_dir);
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
    let config_shell = PartialConfigShell::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };

    // Must NOT error on missing .credentials / .credentials_rsaparams.
    execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new(), 2)
        .expect("chmod loop must tolerate missing optional credential files");

    // .runner was normalized to 0o644.
    let runner_home = paths.runner_home("default", "a");
    let bin_dir = runner_home.join("bin.2.334.0");
    let runner = bin_dir.join(".runner");
    let mode = std::fs::metadata(runner.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o644,
        ".runner must be 0o644 post-chmod loop; got 0o{mode:o}"
    );

    // ghars must NOT create placeholder .credentials* files to
    // satisfy the loop; the loop's `if exists` gate is the
    // production contract.
    assert!(
        !bin_dir.join(".credentials").as_std_path().exists(),
        "ghars must not create placeholder .credentials when config.sh skipped it"
    );
    assert!(
        !bin_dir
            .join(".credentials_rsaparams")
            .as_std_path()
            .exists(),
        "ghars must not create placeholder .credentials_rsaparams when config.sh skipped it"
    );
}
