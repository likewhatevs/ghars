//! Tests for `apply::runners` (create / remove / update — non-recreate).
//!
//! Recreate-path tests live in `recreate_tests.rs`. Caches-list
//! reconciliation tests live in `caches_tests.rs`.

use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::PermissionsExt;

use crate::auth::TokenSource;
use crate::error::GharsError;
use crate::plan::{DropInChangeKind, RunnerDelta, RunnerIdentity};

use super::super::runners::{
    execute_create_runner, execute_remove_runner, execute_update_runner, poll_dynamic_user_uid,
    poll_dynamic_user_uid_with_budget,
};
use super::super::undo::{Deps, UndoLog, UndoStep};
use super::common::{
    MockConfigShell, MockSystemd, MockTarball, MockTokenSource, make_paths, make_runner_plan,
    make_spec, running_as_root_apply_test_helper,
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
        drop_in_body.contains("ExecStart=/bin/bash /var/lib/ghars/default/ghars-a/bin.2.334.0/bin/runsvc.sh"),
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

/// Bin tree integrity post-CreateRunner. The pre-fix
/// `set_tree_permissions(tz_dir, 0o777)` cascade chmodded every
/// file in the trust-zone tree to 0o777, including
/// `bin.X.Y.Z/bin/runsvc.sh` — the script systemd ExecStart=
/// invokes as the runner's DynamicUser. World-writable runsvc.sh
/// is a persistence vector: a compromised workflow step running
/// as the trust-zone DynamicUser overwrites runsvc.sh; the
/// malicious script then runs on every subsequent runner
/// restart, intercepting all future jobs in that trust zone.
///
/// Post-fix, the cascade is gone. Files in the bin tree retain
/// whatever modes the tarball install laid down (per
/// extract.rs's per-entry tar-header propagation, masked to
/// 0o777). MockTarball::install_binary explicitly chmods
/// runsvc.sh to 0o755 (see common.rs) so the mock mirrors
/// production tar-header behavior — the test pins the file at
/// 0o755 (NOT 0o777). A regression that re-introduces the
/// cascade would flip this back to 0o777 and fail the
/// assertion.
///
/// This pins the regression guard against any future change
/// that re-adds a recursive chmod over the trust-zone tree
/// (for ANY reason — copy-paste from a related fix, misguided
/// cleanup, a chown-by-UID rewrite done incorrectly): it would
/// silently re-open the persistence vector.
///
/// The deleted set_tree_permissions also used path-based
/// fs::set_permissions which follows symlinks (it's chmod, not
/// lchmod); paired with the recursive walk and the fact that
/// ghars runs as root, a symlink planted by a compromised
/// workflow step under runner_home pointing at /etc would have
/// resulted in /etc/* being chmodded 0o777 — a full local
/// privilege escalation. The cascade's removal closes that
/// vector by construction (no walk = no follow). See
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
        "runsvc.sh must NOT be world-writable post-create — the \
         set_tree_permissions cascade was a CVE-class persistence \
         vector for a compromised workflow step; got mode 0o{:o}",
        mode
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
         tar header); ghars must not chmod it away. Got 0o{:o}",
        mode
    );

    // .env / .path must also stay at write_record_undo's 0o644
    // (NOT world-writable). A compromised workflow could otherwise
    // inject PATH/env overrides that take effect on next runner-
    // process restart. execute_create_runner always writes both
    // files via write_record_undo post-#24, so this is a hard-
    // assert existence + mode check, not a conditional.
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
///     umask 0o077 → 0o600, unreadable to DynamicUser.
///   - `.credentials_rsaparams` — upstream explicitly chmods to
///     0o600 in RSAFileKeyManager.cs:33. The RSA private key signs
///     OAuth assertions for credential refresh, so the runner
///     MUST be able to read it; 0o600 root:root is unreadable to
///     the DynamicUser-allocated runner UID.
///
/// ghars normalizes all three to 0o644 in a single post-config.sh
/// chmod loop. The workspace forbids unsafe_code, so pre-exec
/// umask pinning via CommandExt::pre_exec is not available; the
/// post-hoc chmod loop delivers the same end-state safely.
///
/// Test fixture: MockConfigShell writes all three at 0o600 (worst-
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
    for basename in [".runner", ".credentials", ".credentials_rsaparams"] {
        let path = runner_home.join(basename);
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
/// layers). The deleted `set_tree_permissions` cascade used
/// path-based `fs::set_permissions` (chmod, not lchmod) — a
/// planted symlink under runner_home would have followed and
/// chmodded the symlink target. The post-fix defense is two
/// layers:
///
///   1. `sweep_runner_home_for_planted_entries` runs BEFORE any
///      chmod or config.sh invocation. It enumerates
///      runner_home's direct children via lstat and refuses to
///      proceed if any are symlinks / FIFO / device / socket.
///      Closes the most damaging vector: config.sh
///      write-through-symlink to attacker target.
///
///   2. `chmod_record_undo` opens the chmod target with
///      O_NOFOLLOW (which atomically refuses symlinks via ELOOP
///      at open time) then chmods through /proc/self/fd/{fd}.
///      Closes any chmod target that bypassed layer 1 (e.g.
///      paths outside runner_home such as tz_dir).
///
/// This test plants `runner_home/tmp` as a symlink to a
/// sentinel directory. Layer 1 (the sweep) catches it before
/// the chmod and before config.sh. Layer 2 would catch it too
/// if layer 1 were removed.
///
/// Pins both:
/// - the apply exits Err (not Ok) when a planted symlink is in
///   runner_home
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
    std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o700))
        .unwrap();
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
    std::os::unix::fs::symlink(&sentinel, runner_home.join("tmp").as_std_path())
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

    let err = execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new(), 2)
        .expect_err(
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
    let post_mode = std::fs::metadata(&sentinel)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        post_mode, 0o700,
        "planted symlink target's mode must NOT have been changed; \
         got 0o{post_mode:o} (path-based chmod followed the symlink — \
         symlink-refusal regressed)"
    );
}

/// Dir-mode coverage. Pin the exact modes
/// `execute_create_runner` leaves on each managed directory. These
/// modes are load-bearing for the DynamicUser model:
///
/// - tz_dir 0o711: descend-only for non-root (DynamicUser can
///   traverse but NOT `ls` the trust-zone dir).
/// - runner_home 0o777 (at unit-start time): DynamicUser can write
///   `_work/`, `_diag/`, toolchain caches under the per-runner
///   home. Apply-time clamps to 0o755 then re-opens to 0o777
///   just before `start_unit`.
/// - runner_home/tmp 0o777: TMPDIR for the runner unit's sccache
///   server + workflow steps.
/// - tz_dir/.ktstr 0o777: shared cross-runner KTSTR coordination
///   (always created).
/// - tz_dir/.ccache: NOT created for no-ccache-binding runners
///   (gated per #10). For the binding-present case see
///   `create_runner_with_ccache_binding_creates_ccache_dir`. For
///   the binding-absent skip case see
///   `create_runner_without_ccache_binding_skips_ccache_dir`. This
///   test uses `make_runner_plan` which produces a no-binding spec
///   → asserts .ccache does NOT exist.
///
/// Regression guards against a future change that clamps any of
/// these tighter (breaks DynamicUser write) or looser (defeats
/// the trust-zone descend-only invariant for tz_dir).
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
        0o711,
        "tz_dir must be 0o711 (descend-only, no `ls`)"
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
/// The gate at execute_create_runner uses `.kinds.contains(&Ccache)`
/// (which #38's validator accepts for combined-kind pools too), so a
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
/// SetMode push, a partial CreateRunner that errors mid-way
/// would leave the trust-zone tree at apply-time modes:
/// runner_home at 0o777, tz_dir at 0o711, etc. Those modes
/// expose attacker write surface (sibling DynamicUser can plant
/// under a 0o777 runner_home that's no longer being managed by
/// an active runner unit).
///
/// This pins the SetMode-push contract for each of the six
/// chmod sites in execute_create_runner:
///   - tz_dir (chmod 0o711)
///   - runner_home (chmod 0o755 Stage 1, then 0o777 Stage 2 = TWO entries)
///   - runner_tmp (chmod 0o777)
///   - tz_dir/.ktstr (chmod 0o777)
///   - tz_dir/.ccache (chmod 0o777)
///   - .runner / .credentials / .credentials_rsaparams (chmod 0o644 each)
///
/// Regression guard: a future change that chmods through bare
/// `fs::set_permissions` (bypassing the chmod_record_undo
/// helper) would have its mode leak through rollback. This test
/// catches that by counting SetMode UndoStep entries against
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
    // .ccache-creation block is skipped per #10's gating. The
    // chmod-site contract being tested is per-chmod-call, not per-
    // spec, so the right test posture is "spec with all chmod sites
    // active" → all SetMode pushes observable.
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
    std::fs::set_permissions(
        tz_dir.as_std_path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
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
    // ccache binding (per #10's gating, .ccache is only created +
    // chmodded when the runner spec has at least one ccache binding).
    // runner_home: chmodded TWICE (Stage 1 0o755, Stage 2 0o777).
    // .runner / .credentials / .credentials_rsaparams: each chmodded
    // ONCE post-config.sh.
    let expected_unique_paths = [
        tz_dir.to_string(),
        runner_home.to_string(),
        runner_tmp.to_string(),
        ktstr_dir.to_string(),
        ccache_dir.to_string(),
        runner_home.join(".runner").to_string(),
        runner_home.join(".credentials").to_string(),
        runner_home.join(".credentials_rsaparams").to_string(),
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
                if path.to_string() == runner_home_str {
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
/// proceed when a sibling DynamicUser planted a symlink at a
/// runner_home direct child during a prior failed apply's
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
    std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o600))
        .unwrap();

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

    let err = execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new(), 2)
        .expect_err(
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
    use std::sync::Mutex;
    use std::os::unix::fs::PermissionsExt;

    // Local mock that mirrors MockConfigShell but writes ONLY
    // `.runner` (skipping `.credentials` and
    // `.credentials_rsaparams`) — simulating a PAT-authenticated
    // shape.
    #[derive(Default)]
    struct PartialConfigShell {
        registered: Mutex<Vec<(String, String, String)>>,
    }
    impl crate::apply::shell::ConfigShell for PartialConfigShell {
        fn run_register(
            &self,
            ctx: &crate::apply::shell::ConfigShellCtx<'_>,
        ) -> crate::Result<()> {
            std::fs::create_dir_all(ctx.runner_home.as_std_path())?;
            let runner = ctx.runner_home.join(".runner");
            std::fs::write(runner.as_std_path(), b"{\"mock_runner\":\"...\"}")?;
            std::fs::set_permissions(
                runner.as_std_path(),
                std::fs::Permissions::from_mode(0o600),
            )?;
            self.registered.lock().unwrap().push((
                ctx.name.into(),
                ctx.url.into(),
                ctx.token.into(),
            ));
            Ok(())
        }
        fn run_remove(
            &self,
            _ctx: &crate::apply::shell::ConfigShellCtx<'_>,
        ) -> crate::Result<()> {
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
    let runner = runner_home.join(".runner");
    let mode = std::fs::metadata(runner.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o644,
        ".runner must be 0o644 post-chmod loop; got 0o{:o}",
        mode
    );

    // ghars must NOT create placeholder .credentials* files to
    // satisfy the loop; the loop's `if exists` gate is the
    // production contract.
    assert!(
        !runner_home.join(".credentials").as_std_path().exists(),
        "ghars must not create placeholder .credentials when config.sh skipped it"
    );
    assert!(
        !runner_home
            .join(".credentials_rsaparams")
            .as_std_path()
            .exists(),
        "ghars must not create placeholder .credentials_rsaparams when config.sh skipped it"
    );
}

/// fchown_record_undo on a path the test process already owns
/// (chown-to-self) succeeds without EPERM and — critically —
/// records NO `UndoStep::SetOwner` because the no-op gate at
/// runners.rs:320 (`if (prior_uid, prior_gid) != (uid, gid)`)
/// fires. Regression catch: a future change that flipped the
/// gate to always-record would pollute the rollback advisory
/// with no-op chown-restore entries on every re-apply.
#[test]
fn fchown_record_undo_chown_to_self_is_no_op_and_records_nothing() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let file = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("victim.file");
    std::fs::write(file.as_std_path(), b"x").unwrap();
    let meta = std::fs::metadata(file.as_std_path()).unwrap();
    let our_uid = meta.uid();
    let our_gid = meta.gid();

    let mut log = UndoLog::new();
    crate::apply::runners::fchown_record_undo(&file, our_uid, our_gid, "test", &mut log)
        .expect("fchown to current owner must succeed");
    assert!(
        log.steps().is_empty(),
        "no-op chown must not push UndoStep::SetOwner (prior == requested); \
         got steps: {:?}",
        log.steps()
    );
}

/// fchown_record_undo refuses to chown through a symlink target
/// — the open with O_NOFOLLOW returns ELOOP, the helper wraps it
/// in a typed GharsError::Apply with "symlink" in the message.
/// Verifies the symlink-target's uid/gid is UNCHANGED (no
/// chown-through happened).
#[test]
fn fchown_record_undo_refuses_planted_symlink() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let victim = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("victim.real");
    std::fs::write(victim.as_std_path(), b"original").unwrap();
    let original_meta = std::fs::metadata(victim.as_std_path()).unwrap();
    let original_uid = original_meta.uid();
    let original_gid = original_meta.gid();

    let symlink = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("evil.symlink");
    std::os::unix::fs::symlink(victim.as_std_path(), symlink.as_std_path()).unwrap();

    let mut log = UndoLog::new();
    // prior_uid/gid 0 (root) so any chown-through would EPERM as
    // non-root — but the refusal makes it ELOOP-Err first.
    let err = crate::apply::runners::fchown_record_undo(&symlink, 0, 0, "test", &mut log)
        .expect_err("planted symlink at chown target must error with ELOOP");
    assert!(
        format!("{err}").to_lowercase().contains("symlink"),
        "error must mention the symlink-refusal; got: {err}"
    );

    let post_meta = std::fs::metadata(victim.as_std_path()).unwrap();
    assert_eq!(
        post_meta.uid(),
        original_uid,
        "victim.real uid must NOT have been chowned through the symlink"
    );
    assert_eq!(
        post_meta.gid(),
        original_gid,
        "victim.real gid must NOT have been chowned through the symlink"
    );
}

/// chown_and_tighten_runner_state is the production helper that
/// runs after the post-StartUnit DynamicUser UID query. The
/// helper chowns runner_home, runner_tmp, .ktstr, optionally
/// .ccache (per #10's gating — this test passes Some; see
/// `chown_and_tighten_runner_state_skips_ccache_when_none` for
/// the None branch), and the credential files to the DynamicUser
/// UID, then tightens modes (0o700 dirs, 0o770 shared, 0o600
/// credentials).
///
/// This test exercises the FULL helper directly (not via
/// execute_create_runner's root-gate, which skips it under non-
/// root) by passing the test process's own UID — Linux allows
/// chown-to-own-UID without CAP_CHOWN. Verifies the post-state
/// modes are exactly the production tightening targets and that
/// each chmod/chown produced its expected UndoLog entries (with
/// no-op gates correctly skipping no-change pushes).
///
/// Adversary F3 regression guard for #4: catches a future
/// refactor that flips the chown-then-chmod ordering (breaks
/// DynamicUser access during the window), drops a mode-tighten
/// site (leaves runner_home or credentials at world-readable
/// modes after the runner is started), or changes a target
/// mode (silent permission drift).
#[test]
fn chown_and_tighten_runner_state_chowns_and_tightens_all_paths() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let tmp = tempfile::tempdir().unwrap();
    let our_meta = std::fs::metadata("/proc/self").unwrap();
    let our_uid = our_meta.uid();
    let our_gid = our_meta.gid();

    // Construct a synthetic trust-zone tree:
    //   tz_dir/
    //     ghars-a/         (runner_home)
    //       tmp/           (runner_tmp)
    //       .runner
    //       .credentials
    //       .credentials_rsaparams
    //     .ktstr/
    //     .ccache/
    let tz_dir = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("default");
    let runner_home = tz_dir.join("ghars-a");
    let runner_tmp = runner_home.join("tmp");
    let ktstr_dir = tz_dir.join(".ktstr");
    let ccache_dir = tz_dir.join(".ccache");
    for d in [&tz_dir, &runner_home, &runner_tmp, &ktstr_dir, &ccache_dir] {
        std::fs::create_dir_all(d.as_std_path()).unwrap();
    }
    // Plant the 3 credential files at 0o644 (post-#14 normalize state).
    for basename in [".runner", ".credentials", ".credentials_rsaparams"] {
        let p = runner_home.join(basename);
        std::fs::write(p.as_std_path(), b"{}").unwrap();
        std::fs::set_permissions(p.as_std_path(), std::fs::Permissions::from_mode(0o644))
            .unwrap();
    }
    // Pre-stage dir modes to the apply-time pre-tighten state.
    std::fs::set_permissions(runner_home.as_std_path(), std::fs::Permissions::from_mode(0o777))
        .unwrap();
    std::fs::set_permissions(runner_tmp.as_std_path(), std::fs::Permissions::from_mode(0o777))
        .unwrap();
    std::fs::set_permissions(ktstr_dir.as_std_path(), std::fs::Permissions::from_mode(0o777))
        .unwrap();
    std::fs::set_permissions(ccache_dir.as_std_path(), std::fs::Permissions::from_mode(0o777))
        .unwrap();

    let mut log = UndoLog::new();
    crate::apply::runners::chown_and_tighten_runner_state(
        &runner_home,
        &runner_tmp,
        &ktstr_dir,
        Some(ccache_dir.as_path()),
        our_uid,
        our_gid,
        &mut log,
    )
    .expect("chown+tighten with our own (uid, gid) must succeed");

    // Post-state assertions: ownership is our_uid (no-op chown,
    // but the helper still went through the open+fchown loop);
    // modes are the production-tightened values.
    let mode_of = |p: &camino::Utf8PathBuf| -> u32 {
        std::fs::metadata(p.as_std_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    let uid_of = |p: &camino::Utf8PathBuf| std::fs::metadata(p.as_std_path()).unwrap().uid();
    assert_eq!(
        mode_of(&runner_home),
        0o700,
        "runner_home must be 0o700 (was 0o777, tightened post-chown)"
    );
    assert_eq!(uid_of(&runner_home), our_uid, "runner_home chowned to our UID");
    assert_eq!(
        mode_of(&runner_tmp),
        0o700,
        "runner_tmp must be 0o700 (was 0o777, tightened post-chown)"
    );
    assert_eq!(uid_of(&runner_tmp), our_uid, "runner_tmp chowned to our UID");
    assert_eq!(
        mode_of(&ktstr_dir),
        0o770,
        ".ktstr must be 0o770 (cross-runner shared via trust-zone UID group)"
    );
    assert_eq!(uid_of(&ktstr_dir), our_uid, ".ktstr chowned to our UID");
    assert_eq!(
        mode_of(&ccache_dir),
        0o770,
        ".ccache must be 0o770 (cross-runner shared via trust-zone UID group)"
    );
    assert_eq!(uid_of(&ccache_dir), our_uid, ".ccache chowned to our UID");
    for basename in [".runner", ".credentials", ".credentials_rsaparams"] {
        let p = runner_home.join(basename);
        assert_eq!(
            mode_of(&p),
            0o600,
            "{basename} must be 0o600 (owner-only read; world no longer sees credentials)"
        );
        assert_eq!(uid_of(&p), our_uid, "{basename} chowned to our UID");
    }

    // UndoLog has at minimum a SetMode entry per chmod site that
    // actually changed a mode. We pre-staged dirs at 0o777 (not
    // 0o700/0o770) and credentials at 0o644 (not 0o600), so all
    // 7 SetMode entries must exist. SetOwner entries are gated on
    // (prior_uid, prior_gid) != (uid, gid); the chown-to-self is a
    // no-op so the gate skips them all (clean undo log — no
    // pointless chown-restore entries on rollback).
    let set_mode_count = log
        .steps()
        .iter()
        .filter(|s| matches!(s, UndoStep::SetMode { .. }))
        .count();
    let set_owner_count = log
        .steps()
        .iter()
        .filter(|s| matches!(s, UndoStep::SetOwner { .. }))
        .count();
    assert_eq!(
        set_mode_count, 7,
        "expected 7 SetMode entries (4 dirs + 3 creds); got {set_mode_count}"
    );
    assert_eq!(
        set_owner_count, 0,
        "expected 0 SetOwner entries (chown-to-self is a no-op, gate skips); got {set_owner_count}"
    );
}

/// Sibling of `chown_and_tighten_runner_state_chowns_and_tightens_all_paths`
/// for the `ccache_dir: None` branch (#10 gating). The helper must:
/// - succeed with no `.ccache` path on disk + `None` arg
/// - skip fchown AND chmod-tighten for `.ccache`
/// - still tighten runner_home / runner_tmp / .ktstr / creds as usual
/// - NOT push any UndoStep referencing a `.ccache` path
///
/// Regression guard against:
/// - inverting the `Option` branch (`if let None` instead of `if let Some`)
/// - falling back to a sentinel path when `None`
/// - any code path that touches `.ccache` despite the None signal
#[test]
fn chown_and_tighten_runner_state_skips_ccache_when_none() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let tmp = tempfile::tempdir().unwrap();
    let our_meta = std::fs::metadata("/proc/self").unwrap();
    let our_uid = our_meta.uid();
    let our_gid = our_meta.gid();

    // Construct the runner tree WITHOUT `.ccache` (matches the post-
    // #10 no-ccache-binding runner shape).
    let tz_dir = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("default");
    let runner_home = tz_dir.join("ghars-a");
    let runner_tmp = runner_home.join("tmp");
    let ktstr_dir = tz_dir.join(".ktstr");
    for d in [&tz_dir, &runner_home, &runner_tmp, &ktstr_dir] {
        std::fs::create_dir_all(d.as_std_path()).unwrap();
    }
    // Affirmatively assert .ccache does NOT exist as a precondition.
    let ccache_dir = tz_dir.join(".ccache");
    assert!(
        !ccache_dir.as_std_path().exists(),
        "fixture sanity: .ccache must not exist for the None-branch test"
    );
    // Plant the 3 credential files so the helper exercises the
    // credential-loop branches too.
    for basename in [".runner", ".credentials", ".credentials_rsaparams"] {
        let p = runner_home.join(basename);
        std::fs::write(p.as_std_path(), b"{}").unwrap();
        std::fs::set_permissions(p.as_std_path(), std::fs::Permissions::from_mode(0o644))
            .unwrap();
    }
    // Pre-stage dirs at apply-time pre-tighten modes.
    std::fs::set_permissions(runner_home.as_std_path(), std::fs::Permissions::from_mode(0o777))
        .unwrap();
    std::fs::set_permissions(runner_tmp.as_std_path(), std::fs::Permissions::from_mode(0o777))
        .unwrap();
    std::fs::set_permissions(ktstr_dir.as_std_path(), std::fs::Permissions::from_mode(0o777))
        .unwrap();

    let mut log = UndoLog::new();
    crate::apply::runners::chown_and_tighten_runner_state(
        &runner_home,
        &runner_tmp,
        &ktstr_dir,
        None,
        our_uid,
        our_gid,
        &mut log,
    )
    .expect("chown+tighten with None ccache_dir must succeed");

    // Modes: 3 dirs + 3 creds tightened; .ccache untouched (still
    // doesn't exist).
    let mode_of = |p: &camino::Utf8PathBuf| -> u32 {
        std::fs::metadata(p.as_std_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode_of(&runner_home), 0o700);
    assert_eq!(mode_of(&runner_tmp), 0o700);
    assert_eq!(mode_of(&ktstr_dir), 0o770);
    assert!(
        !ccache_dir.as_std_path().exists(),
        "None branch must not create .ccache: {ccache_dir}"
    );

    // UndoLog must NOT reference any .ccache path.
    let ccache_path_str = ccache_dir.to_string();
    for step in log.steps() {
        let path_str = match step {
            UndoStep::SetMode { path, .. } => Some(path.to_string()),
            UndoStep::SetOwner { path, .. } => Some(path.to_string()),
            _ => None,
        };
        if let Some(p) = path_str {
            assert!(
                p != ccache_path_str && !p.ends_with("/.ccache"),
                "None branch must not push UndoStep referencing .ccache; got: {p}"
            );
        }
    }

    // Expected SetMode count: 6 = 3 dirs (runner_home, runner_tmp,
    // .ktstr) + 3 creds. .ccache is not counted.
    let set_mode_count = log
        .steps()
        .iter()
        .filter(|s| matches!(s, UndoStep::SetMode { .. }))
        .count();
    assert_eq!(
        set_mode_count, 6,
        "expected 6 SetMode entries (3 dirs + 3 creds, no .ccache); got {set_mode_count}"
    );
}

/// poll_dynamic_user_uid returns immediately when the mock has
/// a pre-populated UID. Production systemd has a per-name UID
/// allocated by `dynamic_user_realize` during ExecStart child
/// setup; subsequent runners in the same trust zone hit this
/// "already-populated" branch.
#[test]
fn poll_dynamic_user_uid_returns_immediately_when_populated() {
    let systemd = MockSystemd::default();
    systemd.set_dynamic_user_uid("ghars-tz-default", 65532);
    let uid =
        poll_dynamic_user_uid(&systemd, "ghars-tz-default").expect("poll must succeed");
    assert_eq!(
        uid, 65532,
        "poll must return the pre-populated UID without waiting"
    );
}

/// poll_dynamic_user_uid_with_budget hits the budget-exhaustion
/// path when the systemd mock unconditionally returns
/// `Ok(None)` (simulating a DynamicUser name that never gets
/// realized — e.g. the runner unit failed to start before
/// ExecStart's dynamic_user_realize ran). The error's action
/// label must name the trust-zone user the poll was waiting on
/// so operator triage from `ghars apply` stderr can correlate to
/// the right systemd unit; the error hint must point at the
/// systemctl status diagnostic.
///
/// Uses the `_with_budget` variant with a 50ms budget so the test
/// trips the timeout deterministically without stalling the suite
/// for the production 5s default.
#[test]
fn poll_dynamic_user_uid_returns_err_on_budget_exhaustion() {
    let systemd = MockSystemd::default();
    systemd.set_force_no_dynamic_user();
    let started = std::time::Instant::now();
    let err = poll_dynamic_user_uid_with_budget(
        &systemd,
        "ghars-tz-default",
        std::time::Duration::from_millis(50),
    )
    .expect_err("poll must time out and return Err");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(50),
        "poll must wait at least the budget before erroring; got {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "poll must not stall past 2s on a 50ms budget; got {elapsed:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("ghars-tz-default"),
        "error must name the trust_zone_user being polled; got: {msg}"
    );
    assert!(
        msg.to_lowercase().contains("nosuchdynamicuser"),
        "error must mention NoSuchDynamicUser (the underlying systemd D-Bus error); got: {msg}"
    );
}

#[test]
fn update_runner_in_place_preserves_operator_drop_ins() {
    // In-place update path must preserve operator-managed drop-ins.
    // Anything outside MANAGED_DROP_IN_BASENAMES is operator
    // territory (typically `99-*.conf` from `systemctl edit`) and
    // must survive every apply. The `Drift` classifier already
    // flags such files at plan time; deleting them here would
    // silently undo `systemctl edit`.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    // Pre-stage drop-in dir with both a stale managed drop-in (one
    // the new plan no longer emits — must be deleted) and operator
    // drop-ins (must be preserved).
    let drop_in_dir = paths.drop_in_dir("a");
    std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    let stale_managed = drop_in_dir.join("10-memory.conf");
    let operator = drop_in_dir.join("99-operator.conf");
    let unrelated = drop_in_dir.join("custom-tweak.conf");
    std::fs::write(stale_managed.as_std_path(), b"[Service]\nMemoryMax=8G\n").unwrap();
    std::fs::write(operator.as_std_path(), b"[Service]\nLimitNOFILE=1048576\n").unwrap();
    std::fs::write(unrelated.as_std_path(), b"[Service]\nNice=-5\n").unwrap();

    let plan = make_runner_plan("a", &paths.state_dir);
    let delta = RunnerDelta {
        identity: RunnerIdentity {
            name: "a".into(),
            url: "https://github.com/example/repo".into(),
            auth_name: "pat".into(),
            trust_zone: "default".into(),
        },
        after: plan,
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: crate::plan::DriftCause::DriftDetected,
        field_changes: Vec::new(),
        // The deletion pass reads from `drop_in_changes`
        // (Stage 2 byte-comparison result), not from a fresh
        // on-disk dir scan. Stage 2 walks the union of rendered
        // + discovered keys, so an operator-edited
        // `99-operator.conf` discovered on disk but absent from
        // the rendered set DOES appear here as a Removed entry.
        // The operator-drop-in-survival invariant is enforced by
        // the MANAGED_DROP_IN_BASENAMES guard inside
        // execute_update_runner's deletion loop: it deletes only
        // basenames ghars itself would emit. We synthesize both
        // a managed `10-memory.conf` Removed (must be deleted)
        // AND a `99-operator.conf` Removed (must be guarded and
        // preserved) so this test exercises both branches.
        drop_in_changes: vec![
            crate::plan::DropInChange {
                basename: "10-memory.conf".into(),
                change: DropInChangeKind::Removed {
                    before: "[Service]\nMemoryMax=8G\n".into(),
                },
            },
            crate::plan::DropInChange {
                basename: "99-operator.conf".into(),
                change: DropInChangeKind::Removed {
                    before: "[Service]\nLimitNOFILE=1048576\n".into(),
                },
            },
        ],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let systemd = MockSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2).unwrap();

    // The stale MANAGED file is gone (the new plan omits it).
    assert!(
        !stale_managed.as_std_path().exists(),
        "stale managed drop-in 10-memory.conf was not deleted"
    );
    // The 99-operator.conf is preserved.
    assert!(
        operator.as_std_path().exists(),
        "operator drop-in 99-operator.conf was deleted"
    );
    let body = std::fs::read_to_string(operator.as_std_path()).unwrap();
    assert!(
        body.contains("LimitNOFILE=1048576"),
        "operator drop-in body was modified: {body}"
    );
    // Any other operator-named file (no recognized prefix) is
    // also preserved.
    assert!(
        unrelated.as_std_path().exists(),
        "non-managed drop-in custom-tweak.conf was deleted"
    );
}

#[test]
fn update_runner_in_place_treats_already_missing_managed_dropin_as_no_op() {
    // Regression pin for the ENOENT branch of the deletion loop.
    // Stage 2 may flag a managed drop-in as Removed even when an
    // earlier concurrent operation (operator manual `rm`, prior
    // partial apply) already deleted it. The deletion loop must
    // accept ENOENT as "convergence target satisfied" and
    // continue without bumping files_changed (we did NOT mutate
    // disk this run) and without pushing an UndoStep (nothing
    // to restore — there's no prior bytes to read).
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let drop_in_dir = paths.drop_in_dir("a");
    std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    // Pre-stage the unit file (so the path checks succeed) but
    // do NOT plant 10-memory.conf — the Removed entry below
    // refers to a file that's already missing.
    let unit_file = paths.unit_file("a");
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(
        unit_file.as_std_path(),
        crate::systemd::runner_template_text().as_bytes(),
    )
    .unwrap();

    let mut after = make_spec("a", &paths.state_dir);
    after.spec_hash = "sha256:after".into();
    let delta = crate::plan::RunnerDelta {
        identity: crate::plan::RunnerIdentity {
            name: "a".into(),
            url: after.url.clone(),
            auth_name: after.auth_name.clone(),
            trust_zone: after.trust_zone.clone(),
        },
        after: crate::plan::RunnerPlan {
            spec: after.clone(),
            resolved_release: None,
            effective_unit_text: crate::systemd::runner_template_text(),
            drop_ins: BTreeMap::new(),
            env_file: String::new(),
            path_file: String::new(),
            spec_hash: "sha256:after".into(),
        },
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: crate::plan::DriftCause::SpecChanged,
        field_changes: vec![],
        drop_in_changes: vec![crate::plan::DropInChange {
            basename: "10-memory.conf".into(),
            change: DropInChangeKind::Removed {
                before: "[Service]\nMemoryMax=8G\n".into(),
            },
        }],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let systemd = MockSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    // Must NOT propagate ENOENT — Stage 2's Removed verdict is
    // satisfied by "file already absent on disk".
    execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2)
        .expect("ENOENT during managed-drop-in removal must be tolerated");
}

#[test]
fn update_runner_in_place_propagates_eacces_on_managed_dropin_remove() {
    // Regression pin for the EACCES (and other non-ENOENT)
    // branch. The pre-fix `is_ok()` collapse silently dropped
    // every error class, so a read-only mount, a held
    // descriptor, or operator chmod 0500 on the drop-in dir
    // would let `apply` claim success while leaving the stale
    // drop-in in place. The post-fix path propagates as
    // GharsError::Io.
    if running_as_root_apply_test_helper() {
        // chmod 0500 doesn't deny root via DAC; the test would
        // fail to provoke EACCES on a root-running suite.
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let drop_in_dir = paths.drop_in_dir("a");
    std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    // Plant the managed drop-in so the file exists; then chmod
    // the dir to read-only so `unlink` returns EACCES.
    let stale = drop_in_dir.join("10-memory.conf");
    std::fs::write(stale.as_std_path(), b"[Service]\nMemoryMax=8G\n").unwrap();
    let unit_file = paths.unit_file("a");
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(
        unit_file.as_std_path(),
        crate::systemd::runner_template_text().as_bytes(),
    )
    .unwrap();
    // Make the dir non-writable so unlink(2) fails with EACCES.
    let mut perms = std::fs::metadata(drop_in_dir.as_std_path())
        .unwrap()
        .permissions();
    perms.set_mode(0o500);
    std::fs::set_permissions(drop_in_dir.as_std_path(), perms).unwrap();

    let mut after = make_spec("a", &paths.state_dir);
    after.spec_hash = "sha256:after".into();
    let delta = crate::plan::RunnerDelta {
        identity: crate::plan::RunnerIdentity {
            name: "a".into(),
            url: after.url.clone(),
            auth_name: after.auth_name.clone(),
            trust_zone: after.trust_zone.clone(),
        },
        after: crate::plan::RunnerPlan {
            spec: after.clone(),
            resolved_release: None,
            effective_unit_text: crate::systemd::runner_template_text(),
            drop_ins: BTreeMap::new(),
            env_file: String::new(),
            path_file: String::new(),
            spec_hash: "sha256:after".into(),
        },
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: crate::plan::DriftCause::SpecChanged,
        field_changes: vec![],
        drop_in_changes: vec![crate::plan::DropInChange {
            basename: "10-memory.conf".into(),
            change: DropInChangeKind::Removed {
                before: "[Service]\nMemoryMax=8G\n".into(),
            },
        }],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let systemd = MockSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let err = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2)
        .expect_err("EACCES on managed-drop-in remove must propagate, not silently succeed");
    assert!(
        matches!(err, GharsError::Io(_)),
        "expected GharsError::Io for EACCES; got {err:?}"
    );

    // Restore perms so tempdir cleanup works.
    let mut perms = std::fs::metadata(drop_in_dir.as_std_path())
        .unwrap()
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(drop_in_dir.as_std_path(), perms).unwrap();
}

#[test]
fn remove_runner_unregisters_and_cleans_up() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    // Pre-stage a runner home + unit file so remove can clean them.
    let runner_home = paths.runner_home("default", "a");
    std::fs::create_dir_all(runner_home.as_std_path()).unwrap();
    // find_active_bin_dir scans for bin.X.Y.Z/ subdirs containing
    // config.sh — pre-stage one so the deregister branch reaches
    // config.sh remove (the assertion below counts config_shell.removed).
    let bin_dir = runner_home.join("bin.2.334.0");
    std::fs::create_dir_all(bin_dir.as_std_path()).unwrap();
    std::fs::write(bin_dir.join("config.sh").as_std_path(), b"#!/bin/sh\n").unwrap();
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
    let drop_in_dir = paths.drop_in_dir("a");
    std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
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
    assert!(!paths.unit_file("a").as_std_path().exists());
    assert!(!runner_home.as_std_path().exists());
    assert_eq!(config_shell.removed.lock().unwrap().len(), 1);
    let calls = systemd.calls_snapshot();
    assert!(
        calls
            .iter()
            .any(|c| c == "stop_unit(ghars-runner@a.service)")
    );
    assert!(
        calls
            .iter()
            .any(|c| c == "disable_unit(ghars-runner@a.service)")
    );
}

#[test]
fn execute_create_runner_records_unit_start_in_log() {
    // Verify the threading: a successful execute_create_runner
    // step pushes StartUnit. (DynamicUser handles the runner
    // identity, so there's no UserAdd step under the new model.)
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let plan = make_runner_plan("rt", &paths.state_dir);
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let mut auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..Default::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut log = UndoLog::new();
    execute_create_runner(&plan, &deps, &paths, &mut log, 2).unwrap();
    let has_start = log
        .steps()
        .iter()
        .any(|s| matches!(s, UndoStep::StartUnit { name } if name == "ghars-runner@rt.service"));
    assert!(
        has_start,
        "execute_create_runner must push StartUnit; got {:?}",
        log.steps()
    );
}

#[test]
fn execute_create_runner_invokes_prune_with_keep_versions() {
    // Part 9f retention plumbing: after a successful tarball
    // install, execute_create_runner MUST call prune_old_versions
    // with the runner home + the keep_versions threaded from the
    // Plan. Regression guard against accidentally dropping the
    // prune step from the create flow.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let plan = make_runner_plan("rt", &paths.state_dir);
    let systemd = MockSystemd::default();
    let config_shell = MockConfigShell::default();
    let tarball = MockTarball::default();
    let mut auth: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..Default::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    execute_create_runner(&plan, &deps, &paths, &mut UndoLog::new(), 5).unwrap();
    let pruned = tarball.pruned.lock().unwrap();
    assert_eq!(
        pruned.len(),
        1,
        "expected exactly one prune call after install; got {pruned:?}"
    );
    let (_runner_home, keep_versions) = &pruned[0];
    assert_eq!(
        *keep_versions, 5,
        "keep_versions must thread through verbatim"
    );
}

#[test]
fn update_runner_in_place_rewrites_env_and_path_when_content_differs() {
    // #24 regression: in-place updates must rewrite bin.X.Y.Z/.env
    // AND bin.X.Y.Z/.path when the rendered bodies differ from
    // on-disk content. Pre-fix, execute_update_runner only touched
    // the systemd drop-ins and left .env/.path stale — workflow steps
    // then inherited obsolete env from Runner.Listener::LoadAndSetEnv
    // reading the old .env at process start.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();

    // Pre-stage runner_home + a bin.2.334.0 dir with STALE .env + .path
    // so read_then_write_if_changed sees a content mismatch.
    // make_spec sets runner_version = Some("2.334.0").
    let runner_home = paths.runner_home("default", "a");
    let bin_dir = runner_home.join("bin.2.334.0");
    std::fs::create_dir_all(bin_dir.as_std_path()).unwrap();
    std::fs::write(bin_dir.join(".env").as_std_path(), b"STALE=true\n").unwrap();
    std::fs::write(bin_dir.join(".path").as_std_path(), b"/old/path\n").unwrap();

    let unit_file = paths.unit_file("a");
    std::fs::write(
        unit_file.as_std_path(),
        crate::systemd::runner_template_text().as_bytes(),
    ).unwrap();

    let mut after = make_spec("a", &paths.state_dir);
    after.spec_hash = "sha256:after".into();
    let rendered = crate::systemd::render_runner_unit(&after).unwrap();
    let expected_env = rendered.env_file.clone();
    let expected_path = rendered.path_file.clone();
    let delta = crate::plan::RunnerDelta {
        identity: crate::plan::RunnerIdentity {
            name: "a".into(),
            url: after.url.clone(),
            auth_name: after.auth_name.clone(),
            trust_zone: after.trust_zone.clone(),
        },
        after: crate::plan::RunnerPlan {
            spec: after.clone(),
            resolved_release: None,
            effective_unit_text: crate::systemd::runner_template_text(),
            drop_ins: BTreeMap::new(),
            env_file: expected_env.clone(),
            path_file: expected_path.clone(),
            spec_hash: "sha256:after".into(),
        },
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: crate::plan::DriftCause::SpecChanged,
        field_changes: vec![],
        drop_in_changes: vec![],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let systemd = MockSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd, auth: &auth_map,
        tarball: &tarball, config_shell: &config_shell,
    };
    execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2).unwrap();

    // The bug-proof assertions: post-update bytes match render_*_file
    // output. Pre-fix, these would fail because in-place left both
    // files untouched.
    let post_env = std::fs::read_to_string(bin_dir.join(".env").as_std_path()).unwrap();
    assert_eq!(post_env, expected_env,
               "in-place update must rewrite .env to match render_runner_env_file output");
    let post_path = std::fs::read_to_string(bin_dir.join(".path").as_std_path()).unwrap();
    assert_eq!(post_path, expected_path,
               "in-place update must rewrite .path to match render_runner_path_file output");
}

#[test]
fn update_runner_in_place_does_not_rewrite_env_when_content_matches() {
    // Counter-fixture: byte-compare short-circuit must NOT bump
    // files_changed when .env/.path on-disk already match what the
    // renderer would produce. Without this, every in-place update
    // (even a no-op) would force a daemon-reload + restart cycle.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();

    let mut after = make_spec("a", &paths.state_dir);
    after.spec_hash = "sha256:after".into();
    let rendered = crate::systemd::render_runner_unit(&after).unwrap();
    let expected_env = rendered.env_file.clone();
    let expected_path = rendered.path_file.clone();

    // Pre-stage runner_home + bin.2.334.0/ with .env/.path matching
    // the rendered output exactly.
    let runner_home = paths.runner_home("default", "a");
    let bin_dir = runner_home.join("bin.2.334.0");
    std::fs::create_dir_all(bin_dir.as_std_path()).unwrap();
    std::fs::write(bin_dir.join(".env").as_std_path(), expected_env.as_bytes()).unwrap();
    std::fs::write(bin_dir.join(".path").as_std_path(), expected_path.as_bytes()).unwrap();

    // Pre-stage drop-in dir so the dir-creation arm doesn't bump
    // files_changed. Pre-stage every rendered drop-in with byte-
    // identical content so the per-basename loop short-circuits too.
    let drop_in_dir = paths.drop_in_dir("a");
    std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    for (name, body) in &rendered.drop_ins {
        std::fs::write(drop_in_dir.join(name).as_std_path(), body.as_bytes()).unwrap();
    }

    // Pre-stage the unit file (matches rendered template — no drop-ins
    // changing — so files_changed for THIS path stays at 0 too).
    let unit_file = paths.unit_file("a");
    std::fs::write(
        unit_file.as_std_path(),
        rendered.template.as_bytes(),
    ).unwrap();

    let delta = crate::plan::RunnerDelta {
        identity: crate::plan::RunnerIdentity {
            name: "a".into(),
            url: after.url.clone(),
            auth_name: after.auth_name.clone(),
            trust_zone: after.trust_zone.clone(),
        },
        after: crate::plan::RunnerPlan {
            spec: after.clone(),
            resolved_release: None,
            effective_unit_text: crate::systemd::runner_template_text(),
            drop_ins: BTreeMap::new(),
            env_file: expected_env.clone(),
            path_file: expected_path.clone(),
            spec_hash: "sha256:after".into(),
        },
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: crate::plan::DriftCause::SpecChanged,
        field_changes: vec![],
        drop_in_changes: vec![],
        before_caches: Some(vec![]),
        before_drop_in_basenames: None,
    };
    let systemd = MockSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let deps = Deps {
        systemd: &systemd, auth: &auth_map,
        tarball: &tarball, config_shell: &config_shell,
    };
    let outcome = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2).unwrap();

    // When everything on disk already matches, the daemon-reload + restart
    // gate fires InPlaceSkipped. No systemd stop_unit / start_unit calls.
    assert!(
        matches!(outcome, crate::apply::ApplyOutcome::InPlaceSkipped),
        "byte-identical inputs must short-circuit to InPlaceSkipped; got {outcome:?}",
    );
    let calls = systemd.calls_snapshot();
    assert!(
        !calls.iter().any(|c| c.starts_with("stop_unit")),
        "byte-identical inputs must NOT stop the unit; calls: {calls:?}",
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("start_unit")),
        "byte-identical inputs must NOT restart the unit; calls: {calls:?}",
    );
}
