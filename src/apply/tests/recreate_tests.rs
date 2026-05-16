//! Tests for `execute_update_runner`'s recreate branch (`delta.requires_recreate=true`).

use std::collections::HashMap;

use crate::auth::TokenSource;
use crate::plan::{Action, Plan};

use super::super::orchestrator::apply;
use super::super::outcome::{ApplyOptions, ApplyOutcome};
use super::super::undo::{Deps, UndoLog, UndoStep};
use super::caches_tests::make_caches_delta;
use super::common::{
    MockConfigShell, MockSystemd, MockTarball, MockTokenSource, make_paths, make_release,
};

/// T1: recreate full-success log ordering pin. When
/// `delta.requires_recreate=true`, the ordered side-effect log
/// must be: `stop_unit` → `disable_unit` (remove) → unit + drop-in
/// writes → `enable_unit` → `start_unit` (create). Pin the
/// systemd-call sequence so a refactor that reorders
/// stop/disable vs enable/start (which would race the
/// runner's lifecycle on real hosts) is caught at test time.
#[test]
fn execute_update_runner_recreate_full_success_systemd_call_sequence() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    // Pre-populate state so execute_remove_runner has unit + home
    // to clean up.
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(
        paths.unit_file("a").as_std_path(),
        b"[Unit]\nX-Ghars-Managed=true\n",
    )
    .unwrap();
    std::fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
    delta.requires_recreate = true;
    delta.recreate_reasons = vec!["url"];
    delta.after.resolved_release = Some(make_release());

    execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, false).unwrap();

    let calls = systemd.calls_snapshot();
    let unit = "ghars-runner@a.service";
    let stop_idx = calls
        .iter()
        .position(|c| c == &format!("stop_unit({unit})"))
        .expect("stop_unit must fire (remove path)");
    let disable_idx = calls
        .iter()
        .position(|c| c == &format!("disable_unit({unit})"))
        .expect("disable_unit must fire (remove path)");
    let enable_idx = calls
        .iter()
        .position(|c| c == &format!("enable_unit({unit})"))
        .expect("enable_unit must fire (create path)");
    let start_idx = calls
        .iter()
        .position(|c| c == &format!("start_unit({unit})"))
        .expect("start_unit must fire (create path)");
    // Recreate ordering: stop then disable (remove), enable then
    // start (create). The remove-side stop+disable MUST precede
    // the create-side enable+start; otherwise the unit could
    // race "enable a unit that is about to be stopped".
    assert!(
        stop_idx < disable_idx,
        "stop must precede disable; got calls: {calls:?}"
    );
    assert!(
        disable_idx < enable_idx,
        "remove (stop+disable) must precede create (enable+start); got calls: {calls:?}"
    );
    assert!(
        enable_idx < start_idx,
        "enable must precede start; got calls: {calls:?}"
    );
}

/// `--no-restart` opt-out MUST NOT suppress the recreate path's
/// destroy+create lifecycle. Recreate is STRUCTURAL — `execute_remove_runner`
/// deregisters from GitHub + stops/disables the unit; `execute_create_runner`
/// re-registers + starts the new unit. There's no coherent "skip restart"
/// for a recreate (the runner identity / binary / address-space changed).
/// Operator's contract: `--no-restart` defers in-place restarts only.
///
/// Pin via: same recreate fixture as
/// `execute_update_runner_recreate_full_success_systemd_call_sequence`
/// but with `no_restart=true` passed to `execute_update_runner`.
/// Asserts (i) the outcome is `Recreated` (not
/// `InPlaceRewroteNoRestart`), (ii) both stop+disable+enable+start
/// systemd calls fire — the recreate lifecycle proceeds normally.
#[test]
fn execute_update_runner_recreate_with_no_restart_still_runs_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(
        paths.unit_file("a").as_std_path(),
        b"[Unit]\nX-Ghars-Managed=true\n",
    )
    .unwrap();
    std::fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
    delta.requires_recreate = true;
    delta.recreate_reasons = vec!["url"];
    delta.after.resolved_release = Some(make_release());

    // 6th arg `true` = `--no-restart` set; the recreate branch at
    // `execute_update_runner`'s `delta.requires_recreate` early-out
    // ignores the flag entirely.
    let outcome =
        execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, true).unwrap();
    assert!(
        matches!(outcome, crate::apply::ApplyOutcome::Recreated),
        "no_restart=true on a recreate-class delta must still return Recreated \
         (the recreate path is structurally undeferrable); got {outcome:?}",
    );
    let calls = systemd.calls_snapshot();
    let unit = "ghars-runner@a.service";
    assert!(
        calls.contains(&format!("stop_unit({unit})")),
        "recreate path's stop_unit must fire regardless of no_restart; calls: {calls:?}",
    );
    assert!(
        calls.contains(&format!("start_unit({unit})")),
        "recreate path's start_unit must fire regardless of no_restart; calls: {calls:?}",
    );
}

/// T2: remove-failure short-circuits create. When the
/// recreate path's first half (`execute_remove_runner`) errors
/// out, the second half (`execute_create_runner`) MUST NOT fire
/// — the `?` operator on the `execute_remove_runner` call inside
/// the recreate branch propagates the Err. Pin via
/// an empty `auth_map`: `mint_token` inside `execute_remove_runner`
/// fails at the deregister step. Asserts (i) the function
/// returns Err, (ii) `tarball.installed` is empty (no create
/// side effect ran).
#[test]
fn execute_update_runner_recreate_remove_failure_skips_create() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
    std::fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    // EMPTY auth_map → execute_remove_runner's mint_token fails
    // because identity.auth_name="pat" is not in the registry.
    // (orphan-skip would only fire if auth_name was empty; with a
    // populated auth_name and an empty registry, mint_token
    // returns Err.)
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
    delta.requires_recreate = true;
    delta.recreate_reasons = vec!["url"];
    delta.after.resolved_release = Some(make_release());

    let err = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, false).unwrap_err();
    // Sanity: the error originated from the auth path (mint_token
    // for the remove deregister step).
    let rendered = format!("{err}");
    assert!(
        rendered.contains("auth source") || rendered.contains("not in the registry"),
        "expected auth-mint failure; got: {rendered}"
    );
    // Create side effects MUST NOT have fired:
    assert!(
        tarball.installed.lock().unwrap().is_empty(),
        "tarball.install_binary must not run when remove fails; got: {:?}",
        tarball.installed.lock().unwrap(),
    );
    assert!(
        tarball.fetched.lock().unwrap().is_empty(),
        "tarball.fetch_or_verify must not run when remove fails; got: {:?}",
        tarball.fetched.lock().unwrap(),
    );
    // Create-path config_shell.run_register must not have fired
    // either (it is keyed off the create path's run_register
    // call). MockConfigShell has separate `registered`/`removed`
    // Vecs; remove may or may not have called run_remove
    // depending on where the failure landed (mint_token is
    // BEFORE run_remove), so the registered Vec is what we pin.
    assert!(
        config_shell.registered.lock().unwrap().is_empty(),
        "config_shell.run_register must not run when remove fails; got: {:?}",
        config_shell.registered.lock().unwrap(),
    );
}

/// T3: create-failure-after-remove. Remove succeeds, then
/// create errors out at the "no `runner_tarball` and no resolved
/// release" Validation gate inside `execute_create_runner`. The
/// function returns
/// Err with the create-side failure; `execute_remove_runner`'s
/// successful side effects (deregister + cleanup) already
/// landed, mirroring the production "partial new state" trade-off
/// documented at the recreate path's call site.
///
/// Pin: (i) function returns Err, (ii) the error mentions the
/// create-path Validation message, (iii) `execute_remove_runner`
/// side effects fired (tarball NOT installed because create
/// bailed before install, but `config_shell.removed` has the
/// runner — proves remove ran).
#[test]
fn execute_update_runner_recreate_create_failure_after_remove() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
    std::fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
    let runner_home = paths.runner_home("default", "a");
    std::fs::create_dir_all(runner_home.as_std_path()).unwrap();
    // Pre-stage a bin.X.Y.Z/config.sh so find_active_bin_dir succeeds
    // inside execute_remove_runner and config_shell.run_remove fires.
    let bin_dir = runner_home.join("bin.2.334.0");
    std::fs::create_dir_all(bin_dir.as_std_path()).unwrap();
    std::fs::write(bin_dir.join("config.sh").as_std_path(), b"#!/bin/sh\n").unwrap();
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
    delta.requires_recreate = true;
    delta.recreate_reasons = vec!["url"];
    // Trigger the create-path Validation gate: no runner_tarball
    // AND no resolved_release. make_caches_delta already sets
    // runner_tarball=None; resolved_release defaults to None
    // here too, so the create branch fails at the
    // `execute_create_runner` Validation gate.
    assert!(delta.after.spec.runner_tarball.is_none());
    assert!(delta.after.resolved_release.is_none());

    let err = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, false).unwrap_err();
    let rendered = format!("{err}");
    assert!(
        rendered.contains("no runner_tarball") && rendered.contains("no resolved release"),
        "expected create-path Validation failure; got: {rendered}"
    );
    // Remove side effects MUST have fired before create errored:
    // run_remove for the runner appears in config_shell.removed.
    let removed = config_shell.removed.lock().unwrap().clone();
    assert_eq!(
        removed.len(),
        1,
        "remove path's run_remove must have fired before create errored; got: {removed:?}",
    );
    // tarball.install_binary did NOT run (step 2 hit the gate).
    assert!(
        tarball.installed.lock().unwrap().is_empty(),
        "install_binary must not run; got: {:?}",
        tarball.installed.lock().unwrap(),
    );
}

/// T4: orphan-skip-token-mint inside the recreate path.
/// `execute_remove_runner`'s deregister branch checks
/// `identity.auth_name.is_empty() || identity.url.is_empty()`
/// and skips `mint_token` + `run_remove` when either is empty.
/// Pin: drive the recreate path with an orphan-shaped identity;
/// assert (i) Recreated outcome, (ii) `config_shell.removed`
/// is empty (`run_remove` never ran — the deregister step
/// short-circuited), (iii) the create path still ran fully
/// (registered Vec has the runner, tarball install + config.sh
/// register both ran).
#[test]
fn execute_update_runner_recreate_orphan_identity_skips_token_mint() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
    std::fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    // Auth registry contains "pat" so the create-path mint
    // (which uses spec.auth_name="pat" from make_spec) succeeds;
    // the orphan-skip we're testing is on the REMOVE side, where
    // identity.auth_name is empty.
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
    delta.requires_recreate = true;
    delta.recreate_reasons = vec!["url"];
    // Empty auth_name + url on the IDENTITY only (the create-side
    // spec still has auth_name="pat" / url=populated). This is
    // the orphan-shape produced by plan.rs when synthesizing
    // RemoveRunner from `actual.orphans`.
    delta.identity.auth_name = String::new();
    delta.identity.url = String::new();
    delta.after.resolved_release = Some(make_release());

    let outcome = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, false).unwrap();
    assert!(
        matches!(outcome, ApplyOutcome::Recreated),
        "recreate path returns Recreated; got {outcome:?}"
    );
    // Orphan-skip fires: run_remove never called, so
    // config_shell.removed is empty.
    assert!(
        config_shell.removed.lock().unwrap().is_empty(),
        "orphan-skip: run_remove must not have fired; got: {:?}",
        config_shell.removed.lock().unwrap(),
    );
    // Create-side run_register DID fire (the create path's spec
    // still has auth_name="pat" + url populated).
    assert_eq!(
        config_shell.registered.lock().unwrap().len(),
        1,
        "create-side run_register must have run; got: {:?}",
        config_shell.registered.lock().unwrap(),
    );
}

/// T5: outcome-is-Recreated. The recreate path explicitly
/// returns `Ok(ApplyOutcome::Recreated)` from the recreate
/// branch of `execute_update_runner` — NOT the inner remove's
/// `Removed` or create's `Created`. Pin
/// because `cmd_apply` rendering and the apply summary
/// footer both branch on the outcome variant; a
/// refactor that returned `Created` instead would silently
/// re-classify recreate actions and break the operator-visible
/// disruption-class accounting.
#[test]
fn execute_update_runner_recreate_returns_recreated_outcome_not_inner() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
    std::fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
    delta.requires_recreate = true;
    delta.recreate_reasons = vec!["url"];
    delta.after.resolved_release = Some(make_release());

    let outcome = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, false).unwrap();
    match outcome {
        ApplyOutcome::Recreated => {}
        ApplyOutcome::Removed | ApplyOutcome::Created => panic!(
            "recreate path must collapse inner Removed+Created into the Recreated \
             variant; got {outcome:?}"
        ),
        other => panic!("expected Recreated; got {other:?}"),
    }
}

/// T7: `MockSystemd` `stop_unit` failure
/// short-circuits the entire recreate path. The recreate branch
/// dispatches `execute_remove_runner` first; that function's very
/// first systemd call is `deps.systemd.stop_unit(&unit_name)?` —
/// when it fails, the `?` propagates and `execute_create_runner`
/// MUST NOT run. Pin via `MockSystemd::fail_stop_unit` injection.
/// Asserts (i) Err returns, (ii) the error surface mentions the
/// injected `stop_unit` failure, (iii) tarball.installed is empty
/// (create-side step 1 was never reached), (iv) `config_shell.registered`
/// is empty. Symmetric with T2 which proves create-skip via an
/// empty `auth_map` (which fails inside `mint_token` AFTER `stop_unit`
/// already succeeded); T7 closes the gap for the more upstream
/// `stop_unit` failure path that T2 cannot reach.
#[test]
fn execute_update_runner_recreate_stop_unit_failure_skips_create() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
    std::fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

    let systemd = MockSystemd::default();
    // Inject failure on the runner unit's stop_unit. The recreate
    // path's execute_remove_runner reaches stop_unit first
    // (apply.rs `execute_remove_runner` step 1).
    *systemd.fail_stop_unit.lock().unwrap() = Some("ghars-runner@a.service".into());
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
    delta.requires_recreate = true;
    delta.recreate_reasons = vec!["url"];
    delta.after.resolved_release = Some(make_release());

    let err = execute_update_runner(&delta, &deps, &paths, &mut UndoLog::new(), 2, false).unwrap_err();
    let rendered = format!("{err}");
    assert!(
        rendered.contains("stop_unit") && rendered.contains("injected failure"),
        "expected MockSystemd stop_unit fault to surface; got: {rendered}"
    );
    // (iii) tarball.install_binary not invoked.
    assert!(
        tarball.installed.lock().unwrap().is_empty(),
        "install_binary must not run when stop_unit fails; got: {:?}",
        tarball.installed.lock().unwrap(),
    );
    // (v) config_shell.run_register not invoked.
    assert!(
        config_shell.registered.lock().unwrap().is_empty(),
        "run_register must not run when stop_unit fails; got: {:?}",
        config_shell.registered.lock().unwrap(),
    );
}

/// T8: on the create-failure-
/// after-remove recreate path, the per-action `UndoLog` MUST contain
/// the remove-side mutation steps recorded BEFORE create errored.
/// Pinned because the rollback advisory and the rollback-on-
/// failure walk both consume that log; if the create-fail
/// path inadvertently reset / dropped the remove-side steps, the
/// operator would see a misleading "no mutations recorded" advisory
/// despite a half-removed runner on disk.
///
/// Setup mirrors T3 (`execute_update_runner_recreate_create_failure_
/// after_remove`) — recreate goes through `execute_remove_runner`
/// (succeeds), then `execute_create_runner` (fails at the no-tarball
/// Validation gate). T3 verifies the side-effect surface; T8
/// verifies the per-action `UndoLog` manifest. Together they pin the
/// "partial new state on create-fail" contract from both
/// directions.
#[test]
fn execute_update_runner_recreate_create_failure_after_remove_includes_remove_steps_in_log() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
    std::fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
    delta.requires_recreate = true;
    delta.recreate_reasons = vec!["url"];
    // Trigger the no-tarball Validation gate so create errors
    // AFTER remove succeeded.
    assert!(delta.after.spec.runner_tarball.is_none());
    assert!(delta.after.resolved_release.is_none());

    let mut log = UndoLog::new();
    execute_update_runner(&delta, &deps, &paths, &mut log, 2, false)
        .expect_err("create-side Validation gate must error");

    let steps = log.steps();
    // Remove-side steps that MUST have landed before create errored,
    // pushed by `execute_remove_runner` in this order:
    //   StopUnit("ghars-runner@a.service")
    //   DisableUnit("ghars-runner@a.service")
    //   teardown_netns_artifacts step push    — Stop+Disable for
    //                                            ghars-net@a.service
    //   RemoveDir(home_dir)
    //
    // We pin the load-bearing primary remove-side mutations:
    //   StopUnit + DisableUnit on the runner unit. DynamicUser=
    //   handles runner identity, so there is no UserDel/UserAdd
    //   step in either the remove-side or the create-side log.
    let unit = "ghars-runner@a.service";
    let stop_runner = steps
        .iter()
        .any(|s| matches!(s, UndoStep::StopUnit { name } if name == unit));
    let disable_runner = steps
        .iter()
        .any(|s| matches!(s, UndoStep::DisableUnit { name } if name == unit));
    assert!(
        stop_runner,
        "remove-side StopUnit must appear in log; got: {steps:?}",
    );
    assert!(
        disable_runner,
        "remove-side DisableUnit must appear in log; got: {steps:?}",
    );
}

/// T3-sibling pin for the recreate path with
/// `rollback_on_failure = true`. The T3 test at
/// `execute_update_runner_recreate_create_failure_after_remove`
/// drives the same fixture (remove succeeds, create fails at the
/// no-tarball Validation gate) but at the `execute_update_runner`
/// boundary; this test drives the full `apply()` so the
/// `rollback_on_failure` gate inside `apply()` actually fires
/// and `undo` walks the per-action `UndoLog` in reverse.
///
/// Setup pre-populates the on-disk paths so `execute_remove_runner`
/// can walk past its filesystem-cleanup steps without erroring on
/// missing paths. The fixture does not populate any drop-in files
/// (`drop_in_dir` is created but empty), so no `RemoveFile` is pushed
/// to the `UndoLog` from the remove path; the load-bearing remove-
/// side steps for this test are `StopUnit` and `DisableUnit`. There
/// is no system-user delete step under `DynamicUser` — systemd
/// recycles the transient UID/GID on unit stop, and the remove
/// path's `fs::remove_dir_all(runner_home)` cleans up the per-
/// runner state subtree.
///
/// Discriminator design: the test asserts that the recreate
/// path's remove leg ran (`StopUnit` + `DisableUnit` pushed to the
/// `UndoLog`) BEFORE the create leg's Validation gate fired,
/// AND that `apply()` walked the per-action `UndoLog` in reverse
/// when `rollback_on_failure=true` (the inverse `StartUnit` /
/// `EnableUnit` ops would land on the rollback walk).
#[test]
fn execute_update_runner_recreate_create_failure_with_rollback() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    std::fs::write(paths.unit_file("a").as_std_path(), b"[Unit]\n").unwrap();
    std::fs::create_dir_all(paths.drop_in_dir("a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runner_home("default", "a").as_std_path()).unwrap();
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let mut auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    auth_map.insert(
        "pat".into(),
        Box::new(MockTokenSource {
            name: "pat".into(),
            ..MockTokenSource::default()
        }),
    );
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut delta = make_caches_delta(&paths, Some(vec![]), vec![]);
    delta.requires_recreate = true;
    delta.recreate_reasons = vec!["url"];
    // T3-sibling fixture: trigger the create-path no-tarball
    // Validation gate so create errors AFTER remove succeeded.
    // make_caches_delta sets runner_tarball=None;
    // resolved_release defaults to None too.
    assert!(delta.after.spec.runner_tarball.is_none());
    assert!(delta.after.resolved_release.is_none());

    let plan = Plan {
        actions: vec![Action::UpdateRunner(delta)],
        warnings: vec![],
        keep_versions: 2,
    };
    // Key delta from T3: opt into rollback_on_failure so apply()'s
    // `rollback_on_failure` gate fires and undo walks the
    // per-action UndoLog.
    let opts = ApplyOptions {
        rollback_on_failure: true,
        ..ApplyOptions::default()
    };

    let result = apply(&plan, &deps, &paths, &opts).unwrap();

    // (a) one failure recorded — the create-side Validation gate.
    assert_eq!(
        result.failed.len(),
        1,
        "expected 1 failed action (create-side Validation gate); got: {:?}",
        result.failed
    );
    // (b) per-action UndoLog manifest is non-empty — the
    // rollback advisory consumer needs it. Mirror the T8 pin
    // shape (`failed_undo_logs` carries the recorded steps).
    assert_eq!(
        result.failed_undo_logs.len(),
        1,
        "expected 1 failed_undo_logs entry; got: {:?}",
        result.failed_undo_logs
    );
    let (_label, steps) = &result.failed_undo_logs[0];
    assert!(
        !steps.is_empty(),
        "expected non-empty UndoLog manifest after recreate-with-rollback failure; got empty",
    );
    // (c) remove-side StopUnit / DisableUnit landed before the
    // create-side Validation gate. Mirror T8 assertion.
    let unit = "ghars-runner@a.service";
    let stop_runner = steps
        .iter()
        .any(|s| matches!(s, UndoStep::StopUnit { name } if name == unit));
    let disable_runner = steps
        .iter()
        .any(|s| matches!(s, UndoStep::DisableUnit { name } if name == unit));
    assert!(
        stop_runner,
        "remove-side StopUnit must appear in log; got: {steps:?}",
    );
    assert!(
        disable_runner,
        "remove-side DisableUnit must appear in log; got: {steps:?}",
    );
    // End-to-end advisory shape pin. Run the result through
    // `render_rollback_advisory` and assert the operator-visible
    // output ties back to the recorded mutations: header present,
    // label sub-block present, at least one remove-side step in
    // the body.
    let advisory = crate::cli::render_rollback_advisory(&result)
        .expect("rollback advisory must render when failed.len() > 0");
    assert!(
        advisory.starts_with("Rollback advisory: 1 action(s) failed."),
        "advisory must lead with failed-count header; got: {advisory}"
    );
    // Per-action label sub-block.
    assert!(
        advisory.contains("\n  UpdateRunner"),
        "advisory must include per-action UpdateRunner sub-block; got: {advisory}"
    );
    // Remove-side StopUnit on the runner unit lands as a body bullet.
    assert!(
        advisory.contains("\n    - stopped ghars-runner@a.service"),
        "advisory must include remove-side StopUnit bullet via describe(); got: {advisory}"
    );
}
