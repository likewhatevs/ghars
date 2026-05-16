//! In-place runner update path: caches reconciliation, byte-equality
//! short-circuit, and managed-orphan deletion.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;

use crate::Result;
use crate::auth::TokenSource;
use crate::paths::Paths;
use crate::plan::{Action, DropInChangeKind, Plan, RunnerDelta, RunnerIdentity, RunnerPlan};
use crate::systemd::render_runner_unit;

use super::super::orchestrator::apply;
use super::super::outcome::{ApplyOptions, ApplyOutcome};
use super::super::undo::{Deps, UndoLog};
use super::common::{MockConfigShell, MockSystemd, MockTarball, make_paths, make_spec};

/// Build a delta with `before_caches` populated and the spec
/// `caches` set to `after`.
pub(super) fn make_caches_delta(
    paths: &Paths,
    before: Option<Vec<&str>>,
    after: Vec<&str>,
) -> RunnerDelta {
    let mut spec = make_spec("a", &paths.state_dir);
    spec.caches = after
        .iter()
        .map(|n| crate::config::EffectiveCacheBinding {
            name: (*n).into(),
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "10G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        })
        .collect();
    let rendered = render_runner_unit(&spec).unwrap();
    let plan = RunnerPlan {
        spec_hash: spec.spec_hash.clone(),
        spec,
        resolved_release: None,
        effective_unit_text: rendered.template,
        drop_ins: rendered.drop_ins,
        env_file: rendered.env_file,
        path_file: rendered.path_file,
    };
    RunnerDelta {
        identity: RunnerIdentity {
            name: "a".into(),
            url: "https://github.com/example/repo".into(),
            auth_name: "pat".into(),
            trust_zone: "default".into(),
        },
        after: plan,
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: crate::plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: before.map(|v| v.into_iter().map(String::from).collect()),
        before_drop_in_basenames: None,
    }
}

/// Pin that `execute_update_runner` populates the
/// `InPlaceRestarted.pools_added` / `pools_removed` Vecs from the
/// caches diff so `cmd_apply`'s per-action detail line surfaces the
/// pool NAMES (not just a count). This is the construction-side
/// counterpart to the detail-string pin at
/// `apply_outcome_detail_strings_are_stable` — together they
/// guarantee an end-to-end "operator sees which pools moved".
/// Three sub-cases mirror the existing in-place-caches tests:
///   - grow: `[]` → `["new-pool"]`     ⇒ `pools_added`=[new-pool], `pools_removed`=[]
///   - shrink: `["old-pool"]` → `[]`   ⇒ `pools_added`=[], `pools_removed`=[old-pool]
///   - replace: `["a","z"]` → `["m"]`  ⇒ `pools_added`=[m], `pools_removed`=[a,z] (sorted)
/// The `replace` case also pins `BTreeSet::difference`'s alphabetical
/// ordering — `pools_removed` must be `[a, z]` not `[z, a]` so the
/// rendered detail string is deterministic across runs.
#[test]
fn execute_update_runner_in_place_populates_pool_name_vecs() {
    fn run_case(before: Option<Vec<&str>>, after: Vec<&str>) -> ApplyOutcome {
        let tmp = tempfile::tempdir().unwrap();
        let paths = make_paths(&tmp);
        let systemd = MockSystemd::default();
        let tarball = MockTarball::default();
        let config_shell = MockConfigShell::default();
        let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
        let deps = Deps {
            systemd: &systemd,
            auth: &auth_map,
            tarball: &tarball,
            config_shell: &config_shell,
        };
        let delta = make_caches_delta(&paths, before, after);
        let mut log = UndoLog::new();
        execute_update_runner(&delta, &deps, &paths, &mut log, 2, false).unwrap()
    }

    // Pure grow.
    match run_case(Some(vec![]), vec!["new-pool"]) {
        ApplyOutcome::InPlaceRestarted {
            pools_added,
            pools_removed,
            ..
        } => {
            assert_eq!(pools_added, vec!["new-pool".to_string()]);
            assert!(pools_removed.is_empty());
        }
        other => panic!("expected InPlaceRestarted, got {other:?}"),
    }

    // Pin the new in-place .ccache materialization: a runner that
    // transitions from no-cache to ccache-binding in-place must have
    // `.ccache` created in its trust-zone dir. Symmetric with
    // `create_runner_with_ccache_binding_creates_ccache_dir` in the
    // CreateRunner path. Regression guard against an inverted gate or
    // a missing `create_dir_all` at runners.rs in-place block.
    let tmp_inplace_add = tempfile::tempdir().unwrap();
    let paths_inplace_add = make_paths(&tmp_inplace_add);
    let systemd_inplace_add = MockSystemd::default();
    let tarball_inplace_add = MockTarball::default();
    let config_shell_inplace_add = MockConfigShell::default();
    let auth_map_inplace_add: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps_inplace_add = Deps {
        systemd: &systemd_inplace_add,
        auth: &auth_map_inplace_add,
        tarball: &tarball_inplace_add,
        config_shell: &config_shell_inplace_add,
    };
    let delta_inplace_add =
        make_caches_delta(&paths_inplace_add, Some(vec![]), vec!["new-ccache-pool"]);
    let ccache_dir_inplace_add = paths_inplace_add.state_dir.join("default").join(".ccache");
    assert!(
        !ccache_dir_inplace_add.as_std_path().exists(),
        "fixture sanity: .ccache must NOT exist before in-place add-binding apply"
    );
    let mut log_inplace_add = UndoLog::new();
    execute_update_runner(
        &delta_inplace_add,
        &deps_inplace_add,
        &paths_inplace_add,
        &mut log_inplace_add,
        2,
        false,
    )
    .unwrap();
    assert!(
        ccache_dir_inplace_add.as_std_path().exists(),
        "in-place add-ccache-binding apply must create .ccache: {ccache_dir_inplace_add}"
    );
    let mode_inplace_add = std::fs::metadata(ccache_dir_inplace_add.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode_inplace_add, 0o777,
        ".ccache must be 0o777 in in-place path (matches CreateRunner apply-time mode; \
         post-StartUnit tightening to 0o770 is a known gap on the in-place add-ccache \
         path — execute_update_runner does not call chown_and_tighten_runner_state)"
    );

    // Sibling: pre-existing .ccache from a sibling runner's prior
    // apply must NOT be re-chmodded by the in-place path. Pins the
    // `if !exists()` short-circuit at runners.rs in the in-place block.
    let tmp_existing = tempfile::tempdir().unwrap();
    let paths_existing = make_paths(&tmp_existing);
    let tz_dir_existing = paths_existing.state_dir.join("default");
    std::fs::create_dir_all(tz_dir_existing.as_std_path()).unwrap();
    let ccache_dir_existing = tz_dir_existing.join(".ccache");
    std::fs::create_dir_all(ccache_dir_existing.as_std_path()).unwrap();
    // Pre-stage at a NON-0o777 mode so a redundant chmod would be
    // observable.
    std::fs::set_permissions(
        ccache_dir_existing.as_std_path(),
        std::fs::Permissions::from_mode(0o770),
    )
    .unwrap();
    let systemd_existing = MockSystemd::default();
    let tarball_existing = MockTarball::default();
    let config_shell_existing = MockConfigShell::default();
    let auth_map_existing: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps_existing = Deps {
        systemd: &systemd_existing,
        auth: &auth_map_existing,
        tarball: &tarball_existing,
        config_shell: &config_shell_existing,
    };
    let delta_existing =
        make_caches_delta(&paths_existing, Some(vec![]), vec!["sibling-shared-pool"]);
    let mut log_existing = UndoLog::new();
    execute_update_runner(
        &delta_existing,
        &deps_existing,
        &paths_existing,
        &mut log_existing,
        2,
        false,
    )
    .unwrap();
    let mode_existing = std::fs::metadata(ccache_dir_existing.as_std_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode_existing, 0o770,
        "pre-existing .ccache from a sibling runner's apply must NOT be chmod-thrashed by the \
         in-place path: the exists() short-circuit at runners.rs in the in-place block must \
         skip chmod when the dir already exists. Cross-runner sharing relies on this."
    );

    // Pure shrink.
    match run_case(Some(vec!["old-pool"]), vec![]) {
        ApplyOutcome::InPlaceRestarted {
            pools_added,
            pools_removed,
            ..
        } => {
            assert!(pools_added.is_empty());
            assert_eq!(pools_removed, vec!["old-pool".to_string()]);
        }
        other => panic!("expected InPlaceRestarted, got {other:?}"),
    }

    // Replace: alphabetical ordering pin (BTreeSet::difference).
    match run_case(Some(vec!["a", "z"]), vec!["m"]) {
        ApplyOutcome::InPlaceRestarted {
            pools_added,
            pools_removed,
            ..
        } => {
            assert_eq!(pools_added, vec!["m".to_string()]);
            assert_eq!(
                pools_removed,
                vec!["a".to_string(), "z".to_string()],
                "pools_removed must be sorted (BTreeSet::difference order)",
            );
        }
        other => panic!("expected InPlaceRestarted, got {other:?}"),
    }
}

/// Pin the detail-string surface end-to-end — feed a
/// real-world replace into `execute_update_runner`, assert the
/// outcome's `detail()` output reads "(added: m; removed: a, z)".
/// This is the integration counterpart to
/// `apply_outcome_detail_strings_are_stable` (which builds the
/// outcome by hand): together they prove the construction site
/// emits the same shape the unit-level test pins.
#[test]
fn execute_update_runner_in_place_detail_string_surfaces_pool_names() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let delta = make_caches_delta(&paths, Some(vec!["a", "z"]), vec!["m"]);
    let mut log = UndoLog::new();
    let outcome = execute_update_runner(&delta, &deps, &paths, &mut log, 2, false).unwrap();
    let detail = outcome.detail();
    // 3 group ops total: one add (`m`) plus two removes (`a`,`z`);
    // the group-op count rendered in the detail string is
    // `pools_added.len() + pools_removed.len() = 1 + 2 = 3`.
    // files_changed depends on whether the unit/drop-in bytes
    // diverge from make_paths's empty starting state (they always
    // do, since there are no prior files), so we use a stable
    // substring match on the pool-name parenthetical and on the
    // group-op count to keep the assertion robust to file-count
    // drift.
    assert!(
        detail.contains("(added: m; removed: a, z)"),
        "detail must surface pool names with `;` separator and \
         alphabetical ordering inside each group; got: {detail}",
    );
    assert!(
        detail.contains("3 group op(s)"),
        "detail group_ops count must equal pools_added.len() + \
         pools_removed.len(); got: {detail}",
    );
    let _ = Result::<()>::Ok(());
}

#[test]
fn apply_dry_run_with_caches_change_is_skipped() {
    // dry_run=true at the apply() level short-circuits each action
    // before execute_*. A caches-list change routed through dry-run
    // apply lands in `result.skipped` instead of executing.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

    let delta = make_caches_delta(&paths, Some(vec!["pool-old"]), vec!["pool-new"]);
    let plan = Plan {
        actions: vec![Action::UpdateRunner(delta)],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let opts = ApplyOptions {
        dry_run: true,
        ..ApplyOptions::default()
    };
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let result = apply(&plan, &deps, &paths, &opts).unwrap();

    assert_eq!(result.skipped.len(), 1, "dry-run must skip the action");
    // Dry-run-skipped actions still land in `details` so cmd_apply
    // can render the per-action `dry-run (skipped)` line. The
    // label tracks the skipped action verbatim.
    assert_eq!(result.details.len(), 1);
    assert!(matches!(result.details[0].1, ApplyOutcome::DryRunSkipped));
}

/// Build a delta whose `drop_in_changes` matches the rendered drop-in
/// set with every basename marked Preserved. Used by the skip
/// tests to express "every byte on disk already equals what we
/// would render".
pub(super) fn delta_with_all_preserved_drop_ins(paths: &Paths) -> RunnerDelta {
    let spec = make_spec("a", &paths.state_dir);
    let rendered = render_runner_unit(&spec).unwrap();
    let drop_in_changes: Vec<crate::plan::DropInChange> = rendered
        .drop_ins
        .keys()
        .map(|k| crate::plan::DropInChange {
            basename: k.clone(),
            change: DropInChangeKind::Preserved,
        })
        .collect();
    let plan = RunnerPlan {
        spec_hash: spec.spec_hash.clone(),
        spec,
        resolved_release: None,
        effective_unit_text: rendered.template,
        drop_ins: rendered.drop_ins,
        env_file: rendered.env_file,
        path_file: rendered.path_file,
    };
    RunnerDelta {
        identity: RunnerIdentity {
            name: "a".into(),
            url: "https://github.com/example/repo".into(),
            auth_name: "pat".into(),
            trust_zone: "default".into(),
        },
        after: plan,
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: crate::plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes,
        // No before_caches mismatch ⇒ no group ops. The skip path
        // requires both file-byte equality AND group-op no-op.
        before_caches: Some(vec![]),
        before_drop_in_basenames: None,
    }
}

/// Pre-populate `paths.unit_dir` with the rendered unit + every
/// drop-in body that `delta.after` would emit, plus `.env` and `.path`
/// in the versioned bin dir. Mirrors what `execute_update_runner` (and
/// the prior `CreateRunner`) would have written on a successful prior
/// apply. Used by the skip tests.
pub(super) fn prepopulate_on_disk(paths: &Paths, delta: &RunnerDelta) {
    std::fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    let unit_file = paths.unit_file(&delta.identity.name);
    std::fs::write(
        unit_file.as_std_path(),
        delta.after.effective_unit_text.as_bytes(),
    )
    .unwrap();
    let drop_in_dir = paths.drop_in_dir(&delta.identity.name);
    std::fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    for (name, body) in &delta.after.drop_ins {
        let dest = drop_in_dir.join(name);
        std::fs::write(dest.as_std_path(), body.as_bytes()).unwrap();
    }
    // Pre-stage .env and .path in bin.<runner_version>/ so the in-place
    // skip path sees byte-identical content. execute_update_runner
    // computes bin_dir from delta.after.spec.runner_version directly.
    if let Some(version) = delta.after.spec.runner_version.as_deref() {
        let runner_home = paths.runner_home(
            &delta.identity.trust_zone,
            &delta.identity.name,
        );
        let bin_dir = runner_home.join(format!("bin.{version}"));
        std::fs::create_dir_all(bin_dir.as_std_path()).unwrap();
        std::fs::write(
            bin_dir.join(".env").as_std_path(),
            delta.after.env_file.as_bytes(),
        )
        .unwrap();
        std::fs::write(
            bin_dir.join(".path").as_std_path(),
            delta.after.path_file.as_bytes(),
        )
        .unwrap();
    }
}

/// When every managed file on disk byte-matches what we would
/// render AND the caches-list diff is empty, the in-place path
/// skips daemon-reload + stop + start entirely.
#[test]
fn execute_update_runner_in_place_skips_restart_when_bytes_match() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let delta = delta_with_all_preserved_drop_ins(&paths);
    prepopulate_on_disk(&paths, &delta);
    let mut log = UndoLog::new();
    let outcome = execute_update_runner(&delta, &deps, &paths, &mut log, 2, false).unwrap();
    // The byte-equality short-circuit must surface
    // as `InPlaceSkipped` so cmd_apply renders the per-action
    // detail line as `no-op (bytes match)`.
    assert_eq!(outcome, ApplyOutcome::InPlaceSkipped);

    let calls = systemd.calls_snapshot();
    assert!(
        calls.is_empty(),
        "skip path must not touch systemd; got: {calls:?}",
    );
    assert!(
        log.is_empty(),
        "skip path must not push any UndoStep; got len={}",
        log.len(),
    );
}

/// When the on-disk unit-file bytes drift from the rendered
/// `effective_unit_text`, the helper writes through and the
/// daemon-reload + stop + start cycle fires as before.
#[test]
fn execute_update_runner_in_place_restarts_when_unit_file_differs() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let delta = delta_with_all_preserved_drop_ins(&paths);
    prepopulate_on_disk(&paths, &delta);
    // Tamper with the on-disk unit-file so its bytes no longer
    // match `delta.after.effective_unit_text`. The drop-ins on
    // disk still match, and `drop_in_changes` says Preserved for
    // each — but the unit-file mismatch alone must force the
    // restart cycle.
    let unit_file = paths.unit_file(&delta.identity.name);
    std::fs::write(unit_file.as_std_path(), b"[Unit]\nDescription=stale\n").unwrap();
    let mut log = UndoLog::new();
    execute_update_runner(&delta, &deps, &paths, &mut log, 2, false).unwrap();

    let calls = systemd.calls_snapshot();
    assert!(
        calls.iter().any(|c| c == "daemon_reload"),
        "unit-file drift must trigger daemon_reload; got: {calls:?}",
    );
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("stop_unit(ghars-runner@a")),
        "unit-file drift must stop the unit; got: {calls:?}",
    );
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("start_unit(ghars-runner@a")),
        "unit-file drift must start the unit; got: {calls:?}",
    );
}

/// When one drop-in's on-disk body drifts (and Stage 2 marks
/// it Modified instead of Preserved), the write happens and the
/// restart cycle fires.
#[test]
fn execute_update_runner_in_place_restarts_when_drop_in_differs() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut delta = delta_with_all_preserved_drop_ins(&paths);
    // Pick the first drop-in basename and flip its Stage 2 entry
    // from Preserved to Modified — this mirrors what plan.rs does
    // when a managed drop-in's bytes drift on disk relative to the
    // re-render.
    let basename = delta
        .after
        .drop_ins
        .keys()
        .next()
        .cloned()
        .expect("rendered drop-ins must be non-empty for this fixture");
    let after_body = delta.after.drop_ins.get(&basename).cloned().unwrap();
    for change in &mut delta.drop_in_changes {
        if change.basename == basename {
            change.change = DropInChangeKind::Modified {
                before: "[Unit]\nX-Drift=stale\n".into(),
                after: after_body.clone(),
            };
            break;
        }
    }
    // On disk: unit-file matches (skip-eligible) but the drifted
    // drop-in does NOT match the rendered body. The Modified
    // classification routes the basename through
    // read_then_write_if_changed, which detects the byte mismatch
    // and writes through.
    prepopulate_on_disk(&paths, &delta);
    let drop_in_dir = paths.drop_in_dir(&delta.identity.name);
    std::fs::write(
        drop_in_dir.join(&basename).as_std_path(),
        b"[Unit]\nX-Drift=stale\n",
    )
    .unwrap();
    let mut log = UndoLog::new();
    execute_update_runner(&delta, &deps, &paths, &mut log, 2, false).unwrap();

    let calls = systemd.calls_snapshot();
    assert!(
        calls.iter().any(|c| c == "daemon_reload"),
        "drop-in drift must trigger daemon_reload; got: {calls:?}",
    );
    // And confirm the on-disk bytes were rewritten to the
    // rendered body — read_then_write_if_changed only writes when
    // bytes differ, so this proves the rewrite happened.
    let after_disk = std::fs::read(drop_in_dir.join(&basename).as_std_path()).unwrap();
    assert_eq!(after_disk, after_body.as_bytes());
}

/// When a managed drop-in is present on disk but absent from
/// `delta.after.drop_ins` (Stage 2 classifies it as Removed), the
/// file is deleted, `files_changed` increments, and the restart
/// cycle fires. Operator drop-ins CAN appear in `drop_in_changes`
/// as Removed entries (Stage 2 walks the union of rendered +
/// discovered keys); the deletion loop's `MANAGED_DROP_IN_BASENAMES`
/// guard keeps them safe — see the regression test
/// `update_runner_in_place_preserves_operator_drop_ins` for the
/// guarded-operator-basename branch.
#[test]
fn execute_update_runner_in_place_restarts_when_managed_orphan_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let mut delta = delta_with_all_preserved_drop_ins(&paths);
    // Inject a Stage 2 Removed entry for a managed basename
    // (50-numa.conf): the rendered side has no entry for it, but
    // the on-disk side does. The basename MUST be in
    // MANAGED_DROP_IN_BASENAMES — otherwise the defense-in-depth
    // guard inside execute_update_runner correctly refuses to
    // delete it.
    let orphan = "50-numa.conf";
    delta.drop_in_changes.push(crate::plan::DropInChange {
        basename: orphan.into(),
        change: DropInChangeKind::Removed {
            before: "[Service]\nNUMAPolicy=interleave\n".into(),
        },
    });
    prepopulate_on_disk(&paths, &delta);
    let drop_in_dir = paths.drop_in_dir(&delta.identity.name);
    std::fs::write(
        drop_in_dir.join(orphan).as_std_path(),
        b"[Service]\nNUMAPolicy=interleave\n",
    )
    .unwrap();
    let mut log = UndoLog::new();
    execute_update_runner(&delta, &deps, &paths, &mut log, 2, false).unwrap();

    let calls = systemd.calls_snapshot();
    assert!(
        calls.iter().any(|c| c == "daemon_reload"),
        "managed orphan deletion must trigger daemon_reload; got: {calls:?}",
    );
    assert!(
        !drop_in_dir.join(orphan).as_std_path().exists(),
        "managed orphan must be removed from disk",
    );
}

#[test]
fn execute_update_runner_in_place_before_caches_none_skips_diff() {
    // before_caches == None ⇒ pre-annotation runner. Skip the diff;
    // neither add nor remove must fire even though `after.caches`
    // is non-empty (a fresh apply will land annotations and a
    // future edit can reconcile).
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    // In-place path doesn't mint tokens; empty registry suffices.
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let delta = make_caches_delta(&paths, None, vec!["pool"]);
    let mut log = UndoLog::new();
    execute_update_runner(&delta, &deps, &paths, &mut log, 2, false).unwrap();
    // before_caches=None ⇒ no caches-list diff is computed.
    // Exercising the no-panic path is the remaining signal.
}
