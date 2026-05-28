//! Tests for `apply::runners` chown/chmod/undo helpers.
//!
//! Split sibling of `runners_create_remove_tests.rs`; both modules
//! share the same `use` graph (`TokenSource`, runners helpers, common
//! mock fixtures).

use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::PermissionsExt;

use crate::auth::TokenSource;
use crate::error::GharsError;
use crate::plan::{DropInChangeKind, RunnerDelta, RunnerIdentity};

use super::super::runners::{
    execute_create_runner, execute_remove_runner, find_active_bin_dir, poll_dynamic_user_uid,
    poll_dynamic_user_uid_with_budget,
};
use super::super::undo::{Deps, UndoLog, UndoStep};
use super::super::update_runner::execute_update_runner;
use super::common::{
    MockConfigShell, MockSystemd, MockTarball, MockTokenSource, make_paths, make_runner_plan,
    make_spec, running_as_root_apply_test_helper,
};

/// `fchown_record_undo` on a path the test process already owns
/// (chown-to-self) succeeds without EPERM and — critically —
/// records NO `UndoStep::SetOwner` because the no-op gate inside
/// `fchown_record_undo` (`if (prior_uid, prior_gid) != (uid, gid)`)
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

/// `fchown_record_undo` refuses to chown through a symlink target
/// — the open with `O_NOFOLLOW` returns ELOOP, the helper wraps it
/// in a typed `GharsError::Apply` with "symlink" in the message.
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

/// `chown_and_tighten_runner_state` is the production helper that
/// runs after the post-StartUnit `DynamicUser` UID query. The
/// helper chowns `runner_home`, `runner_tmp`, .ktstr, optionally
/// .ccache (per the `has_ccache` binding gate in
/// `execute_create_runner` — this test passes Some; see
/// `chown_and_tighten_runner_state_skips_ccache_when_none` for
/// the None branch), and the credential files to the `DynamicUser`
/// UID, then tightens modes (0o700 dirs, 0o770 shared, 0o600
/// credentials).
///
/// This test exercises the FULL helper directly (not via
/// `execute_create_runner`'s root-gate, which skips it under non-
/// root) by passing the test process's own UID — Linux allows
/// chown-to-own-UID without `CAP_CHOWN`. Verifies the post-state
/// modes are exactly the production tightening targets and that
/// each chmod/chown produced its expected `UndoLog` entries (with
/// no-op gates correctly skipping no-change pushes).
///
/// Regression guard for the post-StartUnit
/// `DynamicUser` chown+tighten path: catches a future refactor
/// that flips the chown-then-chmod ordering (breaks
/// `DynamicUser` access during the window), drops a mode-tighten
/// site (leaves `runner_home` or credentials at world-readable
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
    //     ghars-a/             (runner_home)
    //       tmp/               (runner_tmp)
    //       bin.2.334.0/       (bin_dir)
    //         .runner
    //         .credentials
    //         .credentials_rsaparams
    //     .ktstr/
    //     .ccache/
    let tz_dir = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("default");
    let runner_home = tz_dir.join("ghars-a");
    let runner_tmp = runner_home.join("tmp");
    let bin_dir = runner_home.join("bin.2.334.0");
    let ktstr_dir = tz_dir.join(".ktstr");
    let ccache_dir = tz_dir.join(".ccache");
    for d in [
        &tz_dir,
        &runner_home,
        &runner_tmp,
        &bin_dir,
        &ktstr_dir,
        &ccache_dir,
    ] {
        std::fs::create_dir_all(d.as_std_path()).unwrap();
    }
    // Plant the 3 credential files in bin_dir (Runner.Listener
    // writes them relative to its assembly Root, not runner_home).
    for basename in [".runner", ".credentials", ".credentials_rsaparams"] {
        let p = bin_dir.join(basename);
        std::fs::write(p.as_std_path(), b"{}").unwrap();
        std::fs::set_permissions(p.as_std_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    // Pre-stage dir modes to the apply-time pre-tighten state.
    std::fs::set_permissions(
        runner_home.as_std_path(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    std::fs::set_permissions(
        runner_tmp.as_std_path(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    std::fs::set_permissions(
        ktstr_dir.as_std_path(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    std::fs::set_permissions(
        ccache_dir.as_std_path(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();

    let mut log = UndoLog::new();
    crate::apply::runners::chown_and_tighten_runner_state(
        &runner_home,
        &runner_tmp,
        &ktstr_dir,
        Some(ccache_dir.as_path()),
        &bin_dir,
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
    assert_eq!(
        uid_of(&runner_home),
        our_uid,
        "runner_home chowned to our UID"
    );
    assert_eq!(
        mode_of(&runner_tmp),
        0o700,
        "runner_tmp must be 0o700 (was 0o777, tightened post-chown)"
    );
    assert_eq!(
        uid_of(&runner_tmp),
        our_uid,
        "runner_tmp chowned to our UID"
    );
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
        let p = bin_dir.join(basename);
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
/// for the `ccache_dir: None` branch (the `has_ccache` binding
/// gate in `execute_create_runner`). The helper must:
/// - succeed with no `.ccache` path on disk + `None` arg
/// - skip fchown AND chmod-tighten for `.ccache`
/// - still tighten `runner_home` / `runner_tmp` / .ktstr / creds as usual
/// - NOT push any `UndoStep` referencing a `.ccache` path
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

    // Construct the runner tree WITHOUT `.ccache` (matches the
    // no-ccache-binding runner shape per the `has_ccache` binding gate in `execute_create_runner`).
    let tz_dir = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("default");
    let runner_home = tz_dir.join("ghars-a");
    let runner_tmp = runner_home.join("tmp");
    let bin_dir = runner_home.join("bin.2.334.0");
    let ktstr_dir = tz_dir.join(".ktstr");
    for d in [&tz_dir, &runner_home, &runner_tmp, &bin_dir, &ktstr_dir] {
        std::fs::create_dir_all(d.as_std_path()).unwrap();
    }
    // Affirmatively assert .ccache does NOT exist as a precondition.
    let ccache_dir = tz_dir.join(".ccache");
    assert!(
        !ccache_dir.as_std_path().exists(),
        "fixture sanity: .ccache must not exist for the None-branch test"
    );
    // Plant the 3 credential files in bin_dir so the helper
    // exercises the credential-loop branches too.
    for basename in [".runner", ".credentials", ".credentials_rsaparams"] {
        let p = bin_dir.join(basename);
        std::fs::write(p.as_std_path(), b"{}").unwrap();
        std::fs::set_permissions(p.as_std_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    // Pre-stage dirs at apply-time pre-tighten modes.
    std::fs::set_permissions(
        runner_home.as_std_path(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    std::fs::set_permissions(
        runner_tmp.as_std_path(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    std::fs::set_permissions(
        ktstr_dir.as_std_path(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();

    let mut log = UndoLog::new();
    crate::apply::runners::chown_and_tighten_runner_state(
        &runner_home,
        &runner_tmp,
        &ktstr_dir,
        None,
        &bin_dir,
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

/// `poll_dynamic_user_uid` returns immediately when the mock has
/// a pre-populated UID. Production systemd has a per-name UID
/// allocated by `dynamic_user_realize` during `ExecStart` child
/// setup; subsequent runners in the same trust zone hit this
/// "already-populated" branch.
#[test]
fn poll_dynamic_user_uid_returns_immediately_when_populated() {
    let systemd = MockSystemd::default();
    systemd.set_dynamic_user_uid("ghars-tz-default", 65532);
    let uid = poll_dynamic_user_uid(&systemd, "ghars-tz-default").expect("poll must succeed");
    assert_eq!(
        uid, 65532,
        "poll must return the pre-populated UID without waiting"
    );
}

/// `poll_dynamic_user_uid_with_budget` hits the budget-exhaustion
/// path when the systemd mock unconditionally returns
/// `Ok(None)` (simulating a `DynamicUser` name that never gets
/// realized — e.g. the runner unit failed to start before
/// `ExecStart`'s `dynamic_user_realize` ran). The error's action
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
    execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, false).unwrap();

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
            // Populate via the real renderers so test inputs match
            // bytes the apply layer would actually write. The
            // ENOENT-tolerance assertion below targets drop-in
            // deletion, not .env/.path bytes — but uniform
            // renderer-bytes-everywhere across the test suite
            // prevents future tests that DO read these fields from
            // tripping on empty-string fixtures.
            env_file: crate::systemd::render_runner_env_file(&after).unwrap(),
            path_file: crate::systemd::render_runner_path_file(&after).unwrap(),
            cleanup_script: crate::systemd::render_cleanup_script(&after).unwrap(),
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
    execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, false)
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
            // Populate via the real renderers so test inputs match
            // bytes the apply layer would actually write
            // (post-snapshot-coverage uniformity cleanup; the EACCES
            // assertion below
            // targets drop-in deletion, not .env/.path bytes).
            env_file: crate::systemd::render_runner_env_file(&after).unwrap(),
            path_file: crate::systemd::render_runner_path_file(&after).unwrap(),
            cleanup_script: crate::systemd::render_cleanup_script(&after).unwrap(),
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
    let err = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, false)
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
    // Pre-fix regression: in-place updates must rewrite bin.X.Y.Z/.env
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
    )
    .unwrap();

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
            cleanup_script: rendered.cleanup_script.clone(),
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
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, false).unwrap();

    // The bug-proof assertions: post-update bytes match render_*_file
    // output. Pre-fix, these would fail because in-place left both
    // files untouched.
    let post_env = std::fs::read_to_string(bin_dir.join(".env").as_std_path()).unwrap();
    assert_eq!(
        post_env, expected_env,
        "in-place update must rewrite .env to match render_runner_env_file output"
    );
    let post_path = std::fs::read_to_string(bin_dir.join(".path").as_std_path()).unwrap();
    assert_eq!(
        post_path, expected_path,
        "in-place update must rewrite .path to match render_runner_path_file output"
    );
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
    std::fs::write(
        bin_dir.join(".path").as_std_path(),
        expected_path.as_bytes(),
    )
    .unwrap();

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
    std::fs::write(unit_file.as_std_path(), rendered.template.as_bytes()).unwrap();

    // Pre-stage ghars-cleanup.sh at runner_home with byte-identical
    // body + 0o755 mode so the in-place cleanup-script write +
    // chmod both short-circuit.
    let cleanup_path = paths.runner_cleanup_script("default", "a");
    std::fs::write(cleanup_path.as_std_path(), rendered.cleanup_script.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            cleanup_path.as_std_path(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

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
            cleanup_script: rendered.cleanup_script.clone(),
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
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let outcome =
        execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, false).unwrap();

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

/// `--no-restart` flag (via `ApplyOptions::no_restart`, threaded as
/// the 6th positional arg to `execute_update_runner`): when bytes
/// differ on disk (`files_changed` > 0) AND the flag is set, the
/// handler MUST return `InPlaceRewroteNoRestart` AND skip every
/// systemd lifecycle call (`daemon_reload`, `stop_unit`,
/// `start_unit`). Operator's maintenance-window workflow: files
/// are rewritten to disk now; restart is deferred until manual
/// `systemctl restart ghars-runner@NAME.service` or a re-apply
/// without `--no-restart`.
///
/// Pre-staged drop-in body bytes intentionally differ from what the
/// renderer produces so the byte-equality short-circuit at
/// `execute_update_runner`'s `files_changed == 0` gate does NOT fire
/// (that would return `InPlaceSkipped` instead of exercising the
/// new flag gate). Without this fixture-mismatch step the test
/// would prove nothing about the new code path.
#[test]
fn update_runner_in_place_with_no_restart_returns_rewrote_no_restart_and_skips_systemd_calls() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    // Pre-stage runner_home + bin.X.Y.Z so the .env/.path rewrite
    // step has a destination dir to write into.
    let runner_home = paths.runner_home("default", "a");
    let bin_dir = runner_home.join("bin.2.334.0");
    std::fs::create_dir_all(bin_dir.as_std_path()).unwrap();

    let mut after = make_spec("a", &paths.state_dir);
    after.spec_hash = "sha256:after".into();
    let rendered = crate::systemd::render_runner_unit(&after).unwrap();

    // Pre-stage unit file with content that DIFFERS from what the
    // renderer will produce so read_then_write_if_changed bumps
    // files_changed by 1 — drives execution past the byte-equality
    // short-circuit at runners.rs `files_changed == 0` and INTO
    // the new `--no-restart` gate.
    let unit_file = paths.unit_file("a");
    std::fs::write(unit_file.as_std_path(), b"[Unit]\nDescription=stale\n").unwrap();

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
            env_file: rendered.env_file.clone(),
            path_file: rendered.path_file.clone(),
            cleanup_script: rendered.cleanup_script.clone(),
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
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    // 6th arg `true` = `--no-restart` set.
    let outcome =
        execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, true).unwrap();

    // The new variant must surface — operator's apply row depends
    // on this for the detail-string "restart deferred (--no-restart)"
    // remediation hint and the `audit_summary() = "deferred-restart"`
    // token. (The `[disruption]` bracket tag stays `[none]` per
    // `disruption()` mapping at outcome.rs — apply-time blast-radius
    // is zero — so operators distinguish "no-op skip" from "deferred
    // restart" via the detail string + audit token, NOT the bracket.)
    assert!(
        matches!(
            &outcome,
            crate::apply::ApplyOutcome::InPlaceRewroteNoRestart { name, files_changed, .. }
                if *files_changed > 0 && name == "a"
        ),
        "no_restart=true with files_changed>0 must return InPlaceRewroteNoRestart \
         with name='a' so detail() can render `systemctl restart ghars-runner@a.service`; \
         got {outcome:?}",
    );
    // Pin that detail() renders the actual runner name (not a literal
    // "NAME" placeholder), so an operator copy-pasting the systemctl
    // command gets the right unit.
    let detail = outcome.detail();
    assert!(
        detail.contains("ghars-runner@a.service"),
        "detail string must substitute runner name into the systemctl \
         remediation hint; got: {detail}",
    );
    assert!(
        !detail.contains("NAME"),
        "detail string must NOT contain literal `NAME` placeholder \
         (operator copy-paste would target the wrong unit); got: {detail}",
    );
    // The point of the flag: ZERO systemd lifecycle calls fire. If
    // any of daemon_reload / stop_unit / start_unit / restart_unit
    // surface in the mock's call log, the gate leaked.
    let calls = systemd.calls_snapshot();
    assert!(
        !calls.iter().any(|c| c.starts_with("daemon_reload")),
        "no_restart=true must NOT issue daemon_reload from the handler; \
         the end-of-apply daemon_reload at orchestrator::apply still fires \
         (cache-flush only, harmless to running workloads); calls: {calls:?}",
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("stop_unit")),
        "no_restart=true must NOT issue stop_unit (preserves in-flight workloads); calls: {calls:?}",
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("start_unit")),
        "no_restart=true must NOT issue start_unit (paired with stop_unit gate); calls: {calls:?}",
    );
}

/// Symmetric counter-fixture to the test above: when no bytes
/// differ on disk (`files_changed == 0`), the byte-equality
/// short-circuit at `execute_update_runner`'s first gate (returning
/// `InPlaceSkipped`) MUST fire BEFORE the `--no-restart` gate runs.
/// `--no-restart` must NEVER promote `InPlaceSkipped` to
/// `InPlaceRewroteNoRestart` — the latter implies bytes were
/// written and restart was deferred, while the former implies
/// nothing happened at all. Audit-log readers grep on
/// `"deferred-restart"` to find runners needing follow-up manual
/// restart; an `InPlaceSkipped`-misclassified-as-rewrote would put
/// non-rewritten runners into that follow-up bucket and cause
/// spurious operator action.
#[test]
fn update_runner_in_place_byte_match_returns_skipped_regardless_of_no_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    // drop_in_dir MUST pre-exist or the `!drop_in_dir_existed`
    // branch at execute_update_runner bumps files_changed by 1
    // (CreateDir is a filesystem mutation) — which would prevent
    // the byte-equality short-circuit and turn this into the
    // `InPlaceRewroteNoRestart` path.
    std::fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
    let runner_home = paths.runner_home("default", "a");
    let bin_dir = runner_home.join("bin.2.334.0");
    std::fs::create_dir_all(bin_dir.as_std_path()).unwrap();

    let mut after = make_spec("a", &paths.state_dir);
    after.spec_hash = "sha256:after".into();
    let rendered = crate::systemd::render_runner_unit(&after).unwrap();

    // Pre-stage unit file with the EXACT bytes the renderer will
    // produce — files_changed stays at 0 through every write check
    // and the byte-equality short-circuit fires.
    let unit_file = paths.unit_file("a");
    std::fs::write(
        unit_file.as_std_path(),
        crate::systemd::runner_template_text().as_bytes(),
    )
    .unwrap();
    // Pre-stage .env/.path too so the write_env_path_files checks
    // don't bump files_changed either.
    std::fs::write(
        bin_dir.join(".env").as_std_path(),
        rendered.env_file.as_bytes(),
    )
    .unwrap();
    std::fs::write(
        bin_dir.join(".path").as_std_path(),
        rendered.path_file.as_bytes(),
    )
    .unwrap();
    // Pre-stage ghars-cleanup.sh at runner_home with byte-identical
    // body + 0o755 mode so the in-place cleanup-script write +
    // chmod both short-circuit (otherwise files_changed bumps and
    // the InPlaceSkipped path doesn't fire).
    let cleanup_path = paths.runner_cleanup_script("default", "a");
    std::fs::write(cleanup_path.as_std_path(), rendered.cleanup_script.as_bytes()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            cleanup_path.as_std_path(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

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
            env_file: rendered.env_file.clone(),
            path_file: rendered.path_file.clone(),
            cleanup_script: rendered.cleanup_script.clone(),
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
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    // 6th arg `true` = `--no-restart` set; the byte-match short-circuit
    // fires first, so the flag is moot.
    let outcome =
        execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, true).unwrap();
    assert!(
        matches!(outcome, crate::apply::ApplyOutcome::InPlaceSkipped),
        "byte-identical inputs with no_restart=true must STILL return InPlaceSkipped \
         (byte-equality short-circuit fires before the --no-restart gate); got {outcome:?}",
    );
    let calls = systemd.calls_snapshot();
    assert!(
        !calls.iter().any(|c| c.starts_with("stop_unit")
            || c.starts_with("start_unit")
            || c.starts_with("daemon_reload")),
        "byte-identical short-circuit must NOT issue any systemd lifecycle calls; calls: {calls:?}",
    );
}

#[test]
fn find_active_bin_dir_picks_newest_by_mtime_not_lex() {
    // Regression: lexicographic sort would order `bin.2.334.0` BEFORE
    // `bin.2.34.0` (because '3' < '4'), so `.pop()` returned the older
    // 2.34.0. mtime-sort returns whichever was installed most recently
    // regardless of version-string digit width.
    let tmp = tempfile::tempdir().unwrap();
    let runner_home = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    let old = runner_home.join("bin.2.334.0");
    let new = runner_home.join("bin.2.34.0");
    std::fs::create_dir_all(old.as_std_path()).unwrap();
    std::fs::write(old.join("config.sh").as_std_path(), b"#!/bin/sh\n").unwrap();
    std::fs::create_dir_all(new.as_std_path()).unwrap();
    std::fs::write(new.join("config.sh").as_std_path(), b"#!/bin/sh\n").unwrap();
    // Backdate `old` so `new` is unambiguously the more recent install,
    // even though `new` would lex-sort BEFORE `old`. utimensat via nix
    // (already a dev/build dep) doesn't follow symlinks.
    let earlier = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    let ts = nix::sys::time::TimeSpec::from_duration(
        earlier.duration_since(std::time::UNIX_EPOCH).unwrap(),
    );
    let dirfd = std::fs::File::open("/").unwrap();
    nix::sys::stat::utimensat(
        &dirfd,
        old.as_std_path(),
        &ts,
        &ts,
        nix::sys::stat::UtimensatFlags::NoFollowSymlink,
    )
    .unwrap();
    let picked = find_active_bin_dir(&runner_home).unwrap();
    assert_eq!(
        picked, new,
        "mtime sort must pick the newer install ({new}) even though lex sort would pick {old}",
    );
}
