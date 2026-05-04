//! Tests for `apply::runners` (create / remove / update — non-recreate).
//!
//! Recreate-path tests live in `recreate_tests.rs`. Caches-list
//! reconciliation tests live in `caches_tests.rs`.

use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::PermissionsExt;

use crate::auth::TokenSource;
use crate::error::GharsError;
use crate::plan::{DropInChangeKind, RunnerDelta, RunnerIdentity};

use super::super::runners::{execute_create_runner, execute_remove_runner, execute_update_runner};
use super::super::tarball::sha256_of_runsvc;
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
    // SEC-02: the freshly-rendered 00-ghars.conf
    // MUST carry an `X-Ghars-Runsvc-Sha256=sha256:HEX` line under
    // `[Service]`. Without this, runsvc-wrapper exits
    // ANNOTATION_MISSING on every restart and the runner unit
    // can never start.
    let drop_in_body = std::fs::read_to_string(drop_in_path.as_std_path()).unwrap();
    assert!(
        drop_in_body.contains("[Service]"),
        "00-ghars.conf is missing [Service] section: {drop_in_body}"
    );
    assert!(
        drop_in_body.contains("X-Ghars-Runsvc-Sha256=sha256:"),
        "00-ghars.conf is missing X-Ghars-Runsvc-Sha256 annotation: {drop_in_body}"
    );
    // The recorded hash must match what re-reading the same
    // runsvc.sh would produce — otherwise every unit start would
    // fail the integrity check.
    let runsvc_path = paths.runner_home("default", "a").join("runsvc.sh");
    let expected_hash = sha256_of_runsvc(&runsvc_path).unwrap();
    assert!(
        drop_in_body.contains(&format!("X-Ghars-Runsvc-Sha256={expected_hash}")),
        "annotation digest does not match on-disk runsvc.sh ({expected_hash}): {drop_in_body}"
    );
    // Unit text written to disk is the canonical template.
    let unit_text = std::fs::read_to_string(paths.unit_file("a").as_std_path()).unwrap();
    assert!(unit_text.contains("[Unit]"));
    assert!(unit_text.contains("\nExecStart=/usr/lib/ghars/runsvc-wrapper %i\n"));
    assert!(!unit_text.contains("ExecStart=!"));
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

#[test]
fn create_runner_runsvc_sha_matches_wrapper_recompute() {
    use sha2::{Digest, Sha256};
    // SEC-02 round-trip: the value apply records as
    // `X-Ghars-Runsvc-Sha256=...` MUST equal what runsvc-wrapper
    // computes when it re-reads the same file at unit start. Both
    // sides hash via SHA-256 of the full file with the
    // `sha256:HEX` prefix; if either side drifts (e.g. one uses
    // hex-uppercase, one strips trailing newline), the integrity
    // check fails on every start. This test pins the agreement.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = make_runner_plan("rt", &paths.state_dir);
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

    // Recompute the digest the way runsvc-wrapper would: read the
    // raw bytes the MockConfigShell wrote, hash with sha2::Sha256,
    // format with the `sha256:HEX` lowercase-hex prefix.
    let runsvc = paths.runner_home("default", "rt").join("runsvc.sh");
    let bytes = std::fs::read(runsvc.as_std_path()).unwrap();
    let mut h = Sha256::new();
    h.update(&bytes);
    let direct = format!("sha256:{}", hex::encode(h.finalize()));

    let drop_in =
        std::fs::read_to_string(paths.drop_in_dir("rt").join("00-ghars.conf").as_std_path())
            .unwrap();
    assert!(
        drop_in.contains(&format!("X-Ghars-Runsvc-Sha256={direct}")),
        "drop-in did not carry round-trip digest {direct}: {drop_in}"
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
    std::fs::write(runner_home.join("config.sh").as_std_path(), b"#!/bin/sh\n").unwrap();
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
    let has_start = log.steps().iter().any(
        |s| matches!(s, UndoStep::StartUnit { name } if name == "ghars-runner@rt.service"),
    );
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
    assert_eq!(*keep_versions, 5, "keep_versions must thread through verbatim");
}

