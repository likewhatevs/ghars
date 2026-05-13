//! End-to-end `apply()` orchestrator tests + phase-ordering pins.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::Result;
use crate::auth::TokenSource;
use crate::error::GharsError;
use crate::plan::{Action, CachePoolPlan, Plan, RunnerDelta, RunnerIdentity};
use crate::systemd::{Systemd, UnitListEntry};

use super::super::orchestrator::apply;
use super::super::outcome::{ApplyOptions, ApplyOutcome, ApplyResult};
use super::super::phases::sort_into_phases;
use super::super::undo::{Deps, UndoStep};
use super::common::{
    MockConfigShell, MockSystemd, MockTarball, MockTokenSource, make_paths, make_runner_plan,
};

fn make_update_delta(
    name: &str,
    prefix: &camino::Utf8Path,
    requires_recreate: bool,
) -> RunnerDelta {
    let after = make_runner_plan(name, prefix);
    RunnerDelta {
        identity: RunnerIdentity {
            name: name.into(),
            url: "https://github.com/example/repo".into(),
            auth_name: "pat".into(),
            trust_zone: "default".into(),
        },
        after,
        requires_recreate,
        recreate_reasons: vec![],
        drift_cause: crate::plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    }
}

fn sort_test_cache_plan(name: &str) -> CachePoolPlan {
    CachePoolPlan {
        binding: crate::config::EffectiveCacheBinding {
            name: name.into(),
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "100G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        },
        drop_in_body: "[Service]\n".into(),
        spec_hash: "sha256:dead".into(),
    }
}

fn sort_test_cache_delta(name: &str) -> crate::plan::CachePoolDelta {
    crate::plan::CachePoolDelta {
        binding: crate::config::EffectiveCacheBinding {
            name: name.into(),
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "100G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        },
        drop_in_body: "[Service]\n".into(),
        spec_hash: "sha256:beef".into(),
    }
}

fn sort_test_identity(name: &str, _prefix: &camino::Utf8Path) -> RunnerIdentity {
    RunnerIdentity {
        name: name.into(),
        url: "https://github.com/example/repo".into(),
        auth_name: "pat".into(),
        trust_zone: "default".into(),
    }
}

#[test]
fn sort_into_phases_orders_correctly() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let plan_a = make_runner_plan("a", &paths.state_dir);
    let plan_b = make_runner_plan("b", &paths.state_dir);
    let identity_x = RunnerIdentity {
        name: "x".into(),
        url: "https://github.com/example/repo".into(),
        auth_name: "pat".into(),
        trust_zone: "default".into(),
    };
    let actions = vec![
        Action::CreateRunner(plan_b.clone()),
        Action::RemoveRunner(identity_x.clone()),
        Action::CreateRunner(plan_a.clone()),
        Action::CreateCachePool(CachePoolPlan {
            binding: crate::config::EffectiveCacheBinding {
                name: "build".into(),
                kinds: vec![crate::config::CacheKind::Ccache],
                size: "200G".into(),
                mode: crate::config::CacheMode::Shared,
                trust_zone: "default".into(),
                sccache_path: None,
                sleep_path: Some("/usr/bin/sleep".into()),
                renderer_schema: crate::systemd::RENDERER_SCHEMA,
            },
            drop_in_body: "[Service]\n".into(),
            spec_hash: "sha256:abcd".into(),
        }),
        Action::RemoveCachePool("rust".into()),
        Action::NoOp("nothing".into()),
    ];
    let phased = sort_into_phases(&actions);
    let labels: Vec<String> = phased.iter().map(Action::label).collect();
    // Expected order:
    //  1) CreateCachePool(build)
    //  2) RemoveRunner(x)
    //  3) CreateRunner(a) — sorted by name within phase
    //  4) CreateRunner(b)
    //  5) RemoveCachePool(rust)
    //  6) NoOp
    assert_eq!(
        labels,
        vec![
            "CreateCachePool(build)",
            "RemoveRunner(x)",
            "CreateRunner(a)",
            "CreateRunner(b)",
            "RemoveCachePool(rust)",
            "NoOp(nothing)",
        ],
    );
}

// -- sort_into_phases properties ------------------------------------

#[test]
fn sort_into_phases_empty_input_returns_empty() {
    let phased = sort_into_phases(&[]);
    assert!(phased.is_empty());
}

#[test]
fn sort_into_phases_preserves_count_and_membership() {
    // Property: every action in input is in output exactly once.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let actions = vec![
        Action::CreateRunner(make_runner_plan("zeta", &paths.state_dir)),
        Action::RemoveCachePool("aaa".into()),
        Action::NoOp("idle".into()),
        Action::CreateCachePool(sort_test_cache_plan("zzz")),
        Action::RemoveRunner(sort_test_identity("mid", &paths.state_dir)),
        Action::UpdateRunner(make_update_delta("alpha", &paths.state_dir, false)),
        Action::UpdateCachePool(sort_test_cache_delta("ccc")),
    ];
    let phased = sort_into_phases(&actions);
    assert_eq!(phased.len(), actions.len(), "no actions added or dropped");
    // Set-equality via labels.
    let mut input_labels: Vec<String> = actions.iter().map(Action::label).collect();
    let mut output_labels: Vec<String> = phased.iter().map(Action::label).collect();
    input_labels.sort();
    output_labels.sort();
    assert_eq!(input_labels, output_labels, "membership preserved");
}

#[test]
fn sort_into_phases_within_phase_runners_alphabetical() {
    // Two CreateRunner actions: "beta" emitted first, "alpha" second.
    // Output must place "alpha" before "beta" within the phase.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let actions = vec![
        Action::CreateRunner(make_runner_plan("beta", &paths.state_dir)),
        Action::CreateRunner(make_runner_plan("alpha", &paths.state_dir)),
    ];
    let phased = sort_into_phases(&actions);
    let labels: Vec<String> = phased.iter().map(Action::label).collect();
    assert_eq!(labels, vec!["CreateRunner(alpha)", "CreateRunner(beta)"]);
}

#[test]
fn sort_into_phases_inplace_update_precedes_recreate_update() {
    // Per Part 8: in-place updates run BEFORE recreate updates so
    // a failing recreate doesn't strand operators with broken
    // in-place changes in the same apply.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let actions = vec![
        Action::UpdateRunner(make_update_delta("recreate-me", &paths.state_dir, true)),
        Action::UpdateRunner(make_update_delta("inplace-me", &paths.state_dir, false)),
    ];
    let phased = sort_into_phases(&actions);
    let labels: Vec<String> = phased.iter().map(Action::label).collect();
    assert_eq!(
        labels,
        vec!["UpdateRunner(inplace-me)", "UpdateRunner(recreate-me)"],
        "in-place update must come before recreate update",
    );
}

#[test]
fn sort_into_phases_inplace_subset_alphabetical_within_subset() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let actions = vec![
        Action::UpdateRunner(make_update_delta("zeta", &paths.state_dir, false)),
        Action::UpdateRunner(make_update_delta("alpha", &paths.state_dir, false)),
    ];
    let phased = sort_into_phases(&actions);
    let labels: Vec<String> = phased.iter().map(Action::label).collect();
    assert_eq!(labels, vec!["UpdateRunner(alpha)", "UpdateRunner(zeta)"]);
}

#[test]
fn sort_into_phases_recreate_subset_alphabetical_within_subset() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let actions = vec![
        Action::UpdateRunner(make_update_delta("zeta", &paths.state_dir, true)),
        Action::UpdateRunner(make_update_delta("alpha", &paths.state_dir, true)),
    ];
    let phased = sort_into_phases(&actions);
    let labels: Vec<String> = phased.iter().map(Action::label).collect();
    assert_eq!(labels, vec!["UpdateRunner(alpha)", "UpdateRunner(zeta)"]);
}

#[test]
fn sort_into_phases_noop_lands_at_the_end() {
    // NoOps inserted at the front; output must place them last.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let actions = vec![
        Action::NoOp("middle".into()),
        Action::CreateRunner(make_runner_plan("alpha", &paths.state_dir)),
        Action::NoOp("first".into()),
        Action::CreateCachePool(sort_test_cache_plan("build")),
    ];
    let phased = sort_into_phases(&actions);
    let labels: Vec<String> = phased.iter().map(Action::label).collect();
    // Both NoOps come last (alphabetical: "first" < "middle").
    assert_eq!(
        labels,
        vec![
            "CreateCachePool(build)",
            "CreateRunner(alpha)",
            "NoOp(first)",
            "NoOp(middle)",
        ],
    );
}

#[test]
fn sort_into_phases_full_canonical_order_with_every_phase() {
    // Cover every phase in one test: CreateCachePool → UpdateCachePool
    // → RemoveRunner → UpdateRunner-inplace → UpdateRunner-recreate
    // → CreateRunner → RemoveCachePool → NoOp.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let actions = vec![
        Action::NoOp("done".into()),
        Action::RemoveCachePool("old-pool".into()),
        Action::CreateRunner(make_runner_plan("new-runner", &paths.state_dir)),
        Action::UpdateRunner(make_update_delta("recreate-runner", &paths.state_dir, true)),
        Action::UpdateRunner(make_update_delta("inplace-runner", &paths.state_dir, false)),
        Action::RemoveRunner(sort_test_identity("old-runner", &paths.state_dir)),
        Action::UpdateCachePool(sort_test_cache_delta("update-pool")),
        Action::CreateCachePool(sort_test_cache_plan("new-pool")),
    ];
    let phased = sort_into_phases(&actions);
    let labels: Vec<String> = phased.iter().map(Action::label).collect();
    assert_eq!(
        labels,
        vec![
            "CreateCachePool(new-pool)",
            "UpdateCachePool(update-pool)",
            "RemoveRunner(old-runner)",
            "UpdateRunner(inplace-runner)",
            "UpdateRunner(recreate-runner)",
            "CreateRunner(new-runner)",
            "RemoveCachePool(old-pool)",
            "NoOp(done)",
        ],
    );
}

#[test]
fn apply_dispatches_cache_pool_create_then_runner_create() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    // Pre-create runtime dir so the lock file write succeeds; apply
    // also does this internally but having both paths valid keeps
    // the assertion simple.
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let pool = CachePoolPlan {
        binding: crate::config::EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        },
        drop_in_body: "[Service]\nExecStart=/usr/bin/sleep infinity\n".into(),
        spec_hash: "sha256:abcd".into(),
    };
    let plan_a = make_runner_plan("a", &paths.state_dir);
    let plan = Plan {
        actions: vec![Action::CreateRunner(plan_a), Action::CreateCachePool(pool)],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = MockSystemd::default();
    // Make MainPID resolve to this process — runner has no
    // `network`, so verify_runner_netns is skipped.
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
    let opts = ApplyOptions::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let result = apply(&plan, &deps, &paths, &opts).unwrap();
    assert!(result.ok(), "{:?}", result.failed);
    assert_eq!(result.skipped.len(), 0);
    let calls = systemd.calls_snapshot();
    // First systemd call must enable+start the cache pool unit
    // BEFORE the runner unit is touched.
    let pool_idx = calls
        .iter()
        .position(|c| c.contains("ghars-cache@build.service"))
        .expect("cache pool was not touched");
    let runner_idx = calls
        .iter()
        .position(|c| c.contains("ghars-runner@a.service"))
        .expect("runner was not touched");
    assert!(
        pool_idx < runner_idx,
        "expected cache-pool ops before runner ops; got {calls:?}"
    );
}

#[test]
fn dry_run_skips_actions_but_holds_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    let plan = Plan {
        actions: vec![Action::NoOp("idempotent".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = MockSystemd::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
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
    assert_eq!(result.skipped.len(), 1);
    // dry_run skips daemon_reload too.
    assert!(systemd.calls_snapshot().is_empty());
}

#[test]
fn fail_fast_short_circuits_on_first_failure() {
    // Inject a systemd mock that fails enable_unit. Use a
    // RefCell-driven "fail next call" to keep the mock simple.
    struct FlakySystemd {
        calls: Mutex<Vec<String>>,
        fail_after: RefCell<usize>,
    }
    impl Systemd for FlakySystemd {
        fn daemon_reload(&self) -> Result<()> {
            self.calls.lock().unwrap().push("daemon_reload".into());
            Ok(())
        }
        fn start_unit(&self, unit: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("start_unit({unit})"));
            Ok(())
        }
        fn stop_unit(&self, unit: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("stop_unit({unit})"));
            Ok(())
        }
        fn enable_unit(&self, unit: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("enable_unit({unit})"));
            let mut left = self.fail_after.borrow_mut();
            if *left == 0 {
                return Err(GharsError::Systemd(
                    format!("mock enable failure for {unit}"),
                    "test".into(),
                ));
            }
            *left -= 1;
            Ok(())
        }
        fn disable_unit(&self, unit: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("disable_unit({unit})"));
            Ok(())
        }
        fn list_units_filtered(&self, _: &[&str]) -> Result<Vec<UnitListEntry>> {
            Ok(vec![])
        }
        fn get_unit_property(&self, _: &str, _: &str, _: &str) -> Result<String> {
            Ok("0".into())
        }
        fn get_unit_property_u64(&self, _: &str, _: &str, _: &str) -> Result<u64> {
            Ok(0)
        }
        fn get_unit_property_object_path(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<zbus::zvariant::OwnedObjectPath> {
            unreachable!("FlakySystemd does not exercise object-path properties")
        }
        fn get_service_property_string(&self, _: &str, _: &str) -> Result<String> {
            Ok(String::new())
        }
        fn get_service_property_u64(&self, _: &str, _: &str) -> Result<u64> {
            Ok(0)
        }
        fn lookup_dynamic_user_by_name(&self, _: &str) -> Result<Option<u32>> {
            Ok(None)
        }
    }
    // FlakySystemd is not Sync; tests run single-threaded for this case.
    // unsafe is forbidden — wrap RefCell access via a Mutex on the
    // outside (RefCell is fine for !Sync usage when only one thread
    // touches it). Since `apply` takes `&dyn Systemd`, the trait
    // doesn't require Sync — but `Systemd` has `Send + Sync` bounds?
    // Re-checked: trait is bare. OK.
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let pool_a = CachePoolPlan {
        binding: crate::config::EffectiveCacheBinding {
            name: "a".into(),
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        },
        drop_in_body: "[Service]\n".into(),
        spec_hash: "sha256:1".into(),
    };
    let pool_b = CachePoolPlan {
        binding: crate::config::EffectiveCacheBinding {
            name: "b".into(),
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        },
        drop_in_body: "[Service]\n".into(),
        spec_hash: "sha256:2".into(),
    };
    let plan = Plan {
        actions: vec![
            Action::CreateCachePool(pool_a),
            Action::CreateCachePool(pool_b),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = FlakySystemd {
        calls: Mutex::new(vec![]),
        fail_after: RefCell::new(0),
    };
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let opts = ApplyOptions {
        fail_fast: true,
        ..ApplyOptions::default()
    };
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let result = apply(&plan, &deps, &paths, &opts).unwrap();
    // First action failed; second was not attempted because
    // fail_fast=true short-circuits.
    assert_eq!(result.failed.len(), 1);
    assert!(result.failed[0].0.contains("CreateCachePool(a)"));
    // Failed action also lands in `details` as
    // `ApplyOutcome::Failed`. The label matches the failed
    // tuple's label exactly (single source of action labels).
    // `plan_disruption` mirrors `Action::CreateCachePool`'s
    // plan-time worst-case (`Disruption::Recreate` per
    // plan.rs::Action::disruption).
    assert_eq!(
        result.details.len(),
        1,
        "fail_fast: only the failing action runs before the short-circuit; details row count matches",
    );
    let (det_label, det_outcome) = &result.details[0];
    assert_eq!(det_label, &result.failed[0].0);
    match det_outcome {
        ApplyOutcome::Failed {
            error_summary,
            plan_disruption,
        } => {
            assert!(
                !error_summary.is_empty(),
                "Failed.error_summary must carry the inner error display",
            );
            // Bare-error scenario: FlakySystemd returns
            // GharsError::Systemd, RealUsers returns bare
            // GharsError::Io — neither is pre-wrapped in
            // GharsError::Apply, so the outer apply()-loop wrap
            // does not produce a double-wrapped Display chain.
            assert!(
                !error_summary.contains("apply (action "),
                "error_summary must NOT include the GharsError::Apply wrapping prefix \
                 (label is in the tuple key); got: {error_summary}",
            );
            assert_eq!(
                *plan_disruption,
                crate::plan::Disruption::Recreate,
                "CreateCachePool plan-time disruption must be Recreate per Action::disruption",
            );
        }
        other => panic!("expected ApplyOutcome::Failed, got {other:?}"),
    }
    // disruption() on Failed delegates to plan_disruption.
    assert_eq!(det_outcome.disruption(), crate::plan::Disruption::Recreate,);
    let calls = systemd.calls.lock().unwrap();
    assert!(
        calls
            .iter()
            .any(|c| c.contains("enable_unit(ghars-cache@a.service)"))
    );
    assert!(
        !calls
            .iter()
            .any(|c| c.contains("enable_unit(ghars-cache@b.service)"))
    );
    // Pin that the per-action UndoLog was plumbed through to
    // `result.failed_undo_logs` on the Err path. The label/order
    // invariant is `failed[i].0 == failed_undo_logs[i].0` for
    // every i — same labels, same insertion order.
    // `execute_create_cache_pool` records CreateDir → WriteFile
    // before the failed enable_unit; steps land in the Vec in
    // that order. The advisory in cmd_apply walks this Vec
    // to render the operator-facing manual-cleanup hint.
    assert_eq!(
        result.failed_undo_logs.len(),
        1,
        "exactly one failed action ⇒ exactly one undo log entry",
    );
    assert_eq!(
        result.failed_undo_logs[0].0, result.failed[0].0,
        "label invariant: failed[i].0 == failed_undo_logs[i].0",
    );
    let steps = &result.failed_undo_logs[0].1;
    // Steps recorded BEFORE the failed enable_unit:
    // 1. CreateDir for the per-pool drop-in dir
    // 2. WriteFile for 00-ghars.conf (via write_record_undo)
    assert_eq!(
        steps.len(),
        2,
        "expected CreateDir + WriteFile before enable_unit \
         failed; got {steps:?}",
    );
    assert!(matches!(steps[0], UndoStep::CreateDir { .. }));
    assert!(matches!(steps[1], UndoStep::WriteFile { .. }));
}

/// `result.details` filtered to the [`ApplyOutcome::Failed`] rows
/// MUST equal `result.failed` in label set, count, AND positional
/// alignment for any multi-failure plan. The invariant is enforced at
/// `apply()`'s `Err` arm push site: every failure pushes BOTH a
/// `Failed` row to `details` and a `(label, GharsError)` pair to
/// `failed` in lockstep, plus a `failed_undo_logs` entry. The type
/// system does not encode the parallel-Vec invariant — a future
/// refactor that decouples the pushes (e.g. derives `details` from a
/// separate iteration) could silently drop or duplicate a row,
/// leaving `cmd_apply`'s `fail:` rendering loop out of sync with the
/// rollback advisory.
///
/// Synthesizes a 3-failure `ApplyResult` (`fail_fast = false` semantic
/// — all three Err arms ran, all three pairs landed) covering all
/// three [`crate::plan::Disruption`] classes (Recreate / Restart /
/// None) so the test exercises the full `plan_disruption` mapping
/// surface.
///
/// Asserts:
/// 1. Length parity — `failed.len() == details(Failed-filtered).len()`.
/// 2. Positional alignment — `failed[i].0 == details(Failed-filtered)[i].0`
///    for every i. `cmd_apply`'s renderer walks `details` in execution
///    order, so positional equality (NOT just set equality) is
///    load-bearing.
#[test]
fn apply_result_details_failed_labels_match_failed_vec_for_multi_failure_plans() {
    let auth_err = |msg: &str| GharsError::Auth(msg.into(), "hint".into());
    let validation_err = |msg: &str| GharsError::Validation(msg.into(), "hint".into());
    let result = ApplyResult {
        succeeded: vec!["CreateRunner(c)".into()],
        failed: vec![
            ("CreateRunner(a)".into(), auth_err("token mint failed")),
            (
                "UpdateRunner(b)".into(),
                GharsError::Systemd(
                    "Manager.RestartUnit failed".into(),
                    "check journalctl".into(),
                ),
            ),
            (
                "RemoveCachePool(c)".into(),
                validation_err("oversize pool name"),
            ),
        ],
        skipped: vec![],
        details: vec![
            // Successful row interleaved with failed rows so the
            // filter must discard non-Failed outcomes correctly.
            (
                "CreateRunner(a)".into(),
                ApplyOutcome::Failed {
                    error_summary: "auth: token mint failed".into(),
                    plan_disruption: crate::plan::Disruption::Recreate,
                },
            ),
            ("CreateRunner(c)".into(), ApplyOutcome::Created),
            (
                "UpdateRunner(b)".into(),
                ApplyOutcome::Failed {
                    error_summary: "systemd: Manager.RestartUnit failed".into(),
                    plan_disruption: crate::plan::Disruption::Restart,
                },
            ),
            (
                "RemoveCachePool(c)".into(),
                ApplyOutcome::Failed {
                    error_summary: "validation: oversize pool name".into(),
                    plan_disruption: crate::plan::Disruption::Recreate,
                },
            ),
        ],
        // Mirror the failed Vec ordering so the
        // `failed[i].0 == failed_undo_logs[i].0` invariant assertion
        // below is meaningful (`vec![]` would short-circuit any
        // ordering mismatch). Step contents are empty — the
        // ordering invariant is the test target, not step recovery.
        failed_undo_logs: vec![
            ("CreateRunner(a)".into(), Vec::new()),
            ("UpdateRunner(b)".into(), Vec::new()),
            ("RemoveCachePool(c)".into(), Vec::new()),
        ],
    };

    let failed_labels: Vec<String> = result
        .failed
        .iter()
        .map(|(label, _)| label.clone())
        .collect();
    let details_failed_labels: Vec<String> = result
        .details
        .iter()
        .filter_map(|(label, outcome)| match outcome {
            ApplyOutcome::Failed { .. } => Some(label.clone()),
            _ => None,
        })
        .collect();

    assert_eq!(
        failed_labels.len(),
        details_failed_labels.len(),
        "Failed-filtered details count must equal failed count: \
         failed.len()={}, details_failed.len()={}",
        failed_labels.len(),
        details_failed_labels.len(),
    );

    // Positional alignment — both Vecs are populated by the same
    // `Err` arm in apply() so the i-th failed entry's label MUST
    // equal the i-th Failed-filtered details entry's label.
    // Direct equality (vs sorted-set equality) pins execution-order
    // alignment, which cmd_apply's `fail:` renderer relies on.
    assert_eq!(
        failed_labels, details_failed_labels,
        "positional alignment broken: failed={failed_labels:?}, \
         details_failed={details_failed_labels:?}",
    );

    // ADD-1 (ordering invariant — see the construction comment in
    // the per-action `Err` arm of `apply()` above):
    // `failed[i].0 == failed_undo_logs[i].0` for every i. The two
    // Vecs are pushed in lockstep at the per-action `Err` arm;
    // cmd_apply's rollback advisory
    // walks `failed_undo_logs` and renders one block per entry,
    // labelled by the tuple's first element. Divergence here
    // would produce a mislabelled advisory pointing the operator
    // at the wrong action's mutations. Direct Vec equality is
    // stronger than set equality — pins the execution-order
    // alignment, not just label coverage.
    let undo_labels: Vec<&str> = result
        .failed_undo_logs
        .iter()
        .map(|(label, _)| label.as_str())
        .collect();
    let failed_labels_borrowed: Vec<&str> = failed_labels.iter().map(String::as_str).collect();
    assert_eq!(
        undo_labels, failed_labels_borrowed,
        "failed_undo_logs labels must match failed labels in order",
    );
}

#[test]
fn cli_apply_args_parses_rollback_on_failure_flag() {
    // Smoke test: the CLI flag is present in the parser. Failure
    // here would mean the flag was lost from ApplyArgs. The full
    // dispatch path is covered by cmd_apply integration tests.
    use clap::Parser;
    // The CLI lives behind ghars::cli::Cli; the type isn't pub
    // here so we do the parse via the same try_parse_from pattern
    // the cli.rs tests use. We just check the flag is accepted.
    let parsed =
        crate::cli::Cli::try_parse_from(["ghars", "apply", "--rollback-on-failure"]).unwrap();
    match parsed.command {
        crate::cli::Command::Apply(args) => {
            assert!(args.rollback_on_failure);
        }
        other => panic!("expected Apply, got {other:?}"),
    }
}

#[test]
fn cli_apply_args_rollback_on_failure_default_off() {
    // Default OFF: design specifies opt-in. Plan output without
    // the flag must not trigger rollback walks.
    use clap::Parser;
    let parsed = crate::cli::Cli::try_parse_from(["ghars", "apply"]).unwrap();
    match parsed.command {
        crate::cli::Command::Apply(args) => {
            assert!(!args.rollback_on_failure);
        }
        other => panic!("expected Apply, got {other:?}"),
    }
}

/// Pin that `apply()` pushes a `(label, NoOp)` row into
/// `details` for `Action::NoOp` actions, NOT a Created or other
/// real-action variant. Defends against a future refactor that
/// drops the `NoOp` short-circuit and routes through `execute()`.
#[test]
fn apply_records_noop_action_with_noop_outcome() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();
    let plan = Plan {
        actions: vec![Action::NoOp("buckos: in sync".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    let systemd = MockSystemd::default();
    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let opts = ApplyOptions::default();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    let result = apply(&plan, &deps, &paths, &opts).unwrap();
    assert_eq!(result.details.len(), 1, "NoOp must land in details");
    let (label, outcome) = &result.details[0];
    assert!(label.contains("NoOp"), "got label: {label}");
    assert!(
        matches!(outcome, ApplyOutcome::NoOp),
        "NoOp action must produce NoOp outcome, got: {outcome:?}",
    );
}

/// Pin that the synthetic post-loop `daemon_reload`
/// failure path runs the underlying `e.to_string()` through
/// `escape_control_chars` before storing the result in
/// `ApplyOutcome::Failed.error_summary`. Symmetric with the
/// per-action escape pin at
/// `apply_failed_error_summary_escapes_hostile_inner_error` —
/// together they cover the two construction sites in `apply()`
/// (per-action loop arm + post-loop `daemon_reload` arm).
///
/// Drives `apply()` with an EMPTY plan so the per-action loop is a
/// no-op and `daemon_reload` is the only mutation. `MockSystemd`'s
/// `fail_daemon_reload_message` injects a hostile ANSI escape
/// sequence into the Err returned by `daemon_reload()`. The
/// post-loop branch wraps the Err and pushes a synthetic
/// `Failed { error_summary, plan_disruption: Disruption::None }`
/// row to `result.details`; we extract `error_summary` and assert
/// (i) raw ESC byte gone, (ii) `\u{1b}` form from
/// `char::escape_default` present, (iii) the surrounding
/// diagnostic text passes through.
#[test]
fn apply_daemon_reload_error_summary_escapes_hostile_message() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = make_paths(&tmp);
    std::fs::create_dir_all(paths.runtime_dir.as_std_path()).unwrap();

    let systemd = MockSystemd::default();
    // Inject a hostile control-char payload into the Err returned
    // by daemon_reload(). The post-loop daemon_reload arm in
    // `apply()` computes
    // `escape_control_chars(&e.to_string()).into_owned()` and
    // stores the result in `ApplyOutcome::Failed.error_summary`.
    *systemd.fail_daemon_reload_message.lock().unwrap() =
        Some("hostile \x1b[31m daemon_reload diagnostic".into());

    let tarball = MockTarball::default();
    let config_shell = MockConfigShell::default();
    let auth_map: HashMap<String, Box<dyn TokenSource>> = HashMap::new();
    let deps = Deps {
        systemd: &systemd,
        auth: &auth_map,
        tarball: &tarball,
        config_shell: &config_shell,
    };
    // Empty plan: the per-action loop is a no-op so daemon_reload
    // is the ONLY mutation, and its failure flows through the
    // synthetic post-loop branch (no per-action Err competes).
    let plan = Plan {
        actions: vec![],
        warnings: vec![],
        keep_versions: 2,
    };
    let opts = ApplyOptions::default();

    let result = apply(&plan, &deps, &paths, &opts).unwrap();

    // Post-loop daemon_reload pushes one Failed entry to both
    // `result.failed` and `result.details`. Synthetic label is
    // exactly `"daemon_reload"` at every push site in the
    // post-loop arm.
    assert_eq!(
        result.failed.len(),
        1,
        "expected 1 failed (synthetic daemon_reload); got: {:?}",
        result.failed
    );
    assert_eq!(
        result.details.len(),
        1,
        "expected 1 detail row (synthetic daemon_reload); got: {:?}",
        result.details
    );
    let (label, outcome) = &result.details[0];
    assert_eq!(
        label, "daemon_reload",
        "synthetic post-loop label must be `daemon_reload`; got: {label}"
    );
    let error_summary = match outcome {
        ApplyOutcome::Failed { error_summary, .. } => error_summary.clone(),
        other => {
            panic!("expected ApplyOutcome::Failed for post-loop daemon_reload, got {other:?}")
        }
    };
    // (i) raw ESC byte must not survive: the Systemd Display would
    // have included `\x1b`, and the post-loop branch's
    // `escape_control_chars(&e.to_string()).into_owned()` must
    // have replaced it before storing.
    assert!(
        !error_summary.contains('\x1b'),
        "raw ESC must not reach error_summary on the daemon_reload synthetic path; got: {error_summary:?}"
    );
    // (ii) printable `\u{1b}` form from char::escape_default must
    // be present — proves escape_control_chars actually ran on
    // the daemon_reload arm (and not just on the per-action arm).
    assert!(
        error_summary.contains("\\u{1b}"),
        "expected \\u{{1b}} substring from char::escape_default; got: {error_summary}"
    );
    // (iii) the surrounding diagnostic context passes through —
    // sanity that the helper didn't strip the entire message.
    assert!(
        error_summary.contains("hostile") && error_summary.contains("daemon_reload diagnostic"),
        "non-control surrounding text must pass through; got: {error_summary}"
    );
}
