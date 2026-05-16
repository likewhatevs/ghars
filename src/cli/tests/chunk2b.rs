//! Test chunk - co-located with cli/ submodules. See tests/mod.rs for fixture sharing rationale.
#![allow(clippy::unwrap_used)]

use super::*;

// ---------- D-6 addendum: schema_version ---------------------

#[test]
fn plan_to_json_value_emits_schema_version_at_top_level() {
    // Top-level `schema_version` is a forward-compat hook for
    // CI consumers. Set to `"2"` because
    // FieldChange.before/after are tagged FieldValue objects;
    // any future shape change that breaks v2 consumers requires
    // another bump and CHANGELOG/devadv re-review.
    let plan = Plan {
        actions: vec![Action::NoOp("a: in sync".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    for diff in [false, true] {
        let body = plan_to_json_value(&plan, diff);
        assert_eq!(
            body["schema_version"].as_str(),
            Some("2"),
            "schema_version must be \"2\": diff={diff}, body={body}",
        );
    }
}

#[test]
fn plan_to_json_value_empty_plan_still_carries_schema_version_and_summary() {
    let plan = Plan {
        actions: vec![],
        warnings: vec![],
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    assert_eq!(body["schema_version"], "2");
    assert_eq!(body["summary"]["total_actions"], 0);
    assert_eq!(body["summary"]["any_recreate"], false);
    assert_eq!(body["summary"]["by_disruption"]["none"], 0);
    assert_eq!(body["summary"]["by_disruption"]["restart"], 0);
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 0);
}

// ---------- D-7 addendum: summary ----------------------------

#[test]
fn plan_to_json_value_summary_counts_match_action_disruptions() {
    // 1 NoOp + 2 in-place UpdateRunner + 1 CreateRunner +
    // 1 RemoveCachePool → none=1, restart=2, recreate=2,
    // any_recreate=true.
    let in_place = || plan::RunnerDelta {
        identity: fake_identity("ip"),
        after: fake_runner_plan("ip"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let plan = Plan {
        actions: vec![
            Action::NoOp("a: in sync".into()),
            Action::UpdateRunner(in_place()),
            Action::UpdateRunner(in_place()),
            Action::CreateRunner(fake_runner_plan("c")),
            Action::RemoveCachePool("p".into()),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    let s = &body["summary"];
    assert_eq!(s["total_actions"], 5);
    assert_eq!(s["by_disruption"]["none"], 1);
    assert_eq!(s["by_disruption"]["restart"], 2);
    assert_eq!(s["by_disruption"]["recreate"], 2);
    assert_eq!(s["any_recreate"], true);
}

#[test]
fn plan_to_json_value_summary_any_recreate_false_when_only_restart_and_none() {
    // CI policy gates branch on `any_recreate` — pin that
    // restart-only + noop plans report false.
    let in_place = plan::RunnerDelta {
        identity: fake_identity("ip"),
        after: fake_runner_plan("ip"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let plan = Plan {
        actions: vec![
            Action::NoOp("a: in sync".into()),
            Action::UpdateRunner(in_place),
            Action::UpdateCachePool(plan::CachePoolDelta {
                binding: fake_cache_binding("p"),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            }),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    let s = &body["summary"];
    assert_eq!(s["total_actions"], 3);
    assert_eq!(s["by_disruption"]["none"], 1);
    assert_eq!(s["by_disruption"]["restart"], 2);
    assert_eq!(s["by_disruption"]["recreate"], 0);
    assert_eq!(s["any_recreate"], false);
}

#[test]
fn plan_to_json_value_summary_any_recreate_true_for_any_recreate_action() {
    // Single recreate-class action flips the `any_recreate`
    // gate — CI policy guards on this.
    let plan = Plan {
        actions: vec![
            Action::NoOp("a: in sync".into()),
            Action::CreateRunner(fake_runner_plan("c")),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    assert_eq!(body["summary"]["any_recreate"], true);
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 1);
}

// ---------- summary.recreates --------------------------------

/// Empty plan must still emit `recreates: []` as a key
/// (stable shape so CI consumers can `jq '.summary.recreates |
/// length'` without conditional checks for key presence).
#[test]
fn plan_to_json_value_summary_recreates_empty_when_no_actions() {
    let plan = Plan {
        actions: vec![],
        warnings: vec![],
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    assert_eq!(
        body["summary"]["recreates"],
        serde_json::json!([] as [&str; 0]),
        "empty plan must emit recreates: []",
    );
}

/// Every recreate-class action lands in `recreates` and the
/// list is sorted alphabetically by `Action::label()`. Non-
/// recreate actions (`NoOp`, in-place `UpdateRunner`, `UpdateCachePool`)
/// must NOT appear in `recreates`. Pin the full label vocabulary
/// (`CreateRunner(...)`, `RemoveRunner(...)`, `CreateCachePool(...)`,
/// `RemoveCachePool(...)`, `UpdateRunner(...)` when
/// `requires_recreate=true`) so a future refactor that drops a
/// recreate-class action from the filter is caught.
#[test]
fn plan_to_json_value_summary_recreates_lists_all_recreate_actions_sorted() {
    let in_place = plan::RunnerDelta {
        identity: fake_identity("inplace-r"),
        after: fake_runner_plan("inplace-r"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let recreate_delta = plan::RunnerDelta {
        identity: fake_identity("recreate-r"),
        after: fake_runner_plan("recreate-r"),
        requires_recreate: true,
        // recreate_reasons intentionally empty: Action::label() ignores
        // recreate_reasons content and emits only the entity name, so
        // its value is irrelevant to summary.recreates output.
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    };
    // Insert in deliberately UNSORTED order — the production
    // sort is what gives us the canonical alphabetical output
    // regardless of upstream order.
    let plan = Plan {
        actions: vec![
            Action::CreateRunner(fake_runner_plan("zzz")),
            Action::NoOp("a: in sync".into()),
            Action::RemoveCachePool("aaa-pool".into()),
            Action::UpdateRunner(in_place),
            Action::CreateCachePool(plan::CachePoolPlan {
                binding: fake_cache_binding("mmm-pool"),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            }),
            Action::UpdateRunner(recreate_delta),
            Action::RemoveRunner(fake_identity("bbb-r")),
            Action::UpdateCachePool(plan::CachePoolDelta {
                binding: fake_cache_binding("upd-pool"),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            }),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    // Expected: every Recreate action's label, alphabetically.
    // Excludes NoOp (none), in-place UpdateRunner (restart),
    // UpdateCachePool (restart).
    let actual: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        actual,
        vec![
            "CreateCachePool(mmm-pool)",
            "CreateRunner(zzz)",
            "RemoveCachePool(aaa-pool)",
            "RemoveRunner(bbb-r)",
            "UpdateRunner(recreate-r)",
        ],
        "summary.recreates must list every Recreate-class action label, sorted alphabetically",
    );
    // Structural pin: post-refactor,
    // by_disruption["recreate"] is sourced from `recreates.len()`
    // inside `plan_summary_value`, so the two fields cannot
    // diverge on input — they share a single counter. Asserting
    // equality here pins the source-shared invariant against a
    // future refactor that re-splits the count from the Vec.
    assert_eq!(
        body["summary"]["by_disruption"]["recreate"],
        serde_json::json!(actual.len()),
        "summary.recreates length must equal summary.by_disruption.recreate (shared counter)",
    );
    assert_eq!(body["summary"]["any_recreate"], true);
}

/// Restart-only + noop plan reports `recreates: []` even
/// when `total_actions` > 0. Symmetric pin against
/// `summary_any_recreate_false_when_only_restart_and_none`.
#[test]
fn plan_to_json_value_summary_recreates_empty_when_only_restart_and_none() {
    let in_place = plan::RunnerDelta {
        identity: fake_identity("ip"),
        after: fake_runner_plan("ip"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let plan = Plan {
        actions: vec![
            Action::NoOp("a: in sync".into()),
            Action::UpdateRunner(in_place),
            Action::UpdateCachePool(plan::CachePoolDelta {
                binding: fake_cache_binding("p"),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            }),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    assert_eq!(
        body["summary"]["recreates"],
        serde_json::json!([] as [&str; 0]),
        "no-recreate plan must emit recreates: []",
    );
    assert_eq!(body["summary"]["any_recreate"], false);
}

/// Cross-type entity-name collision contract.
///
/// A runner named `alpha` and a cache pool named `alpha` are
/// disambiguated in `summary.recreates` by their `Action::label()`
/// variant prefix: `RemoveRunner(alpha)` vs `RemoveCachePool(alpha)`.
/// Pins the doc-block claim that "Same-name entities of different
/// kinds disambiguate via the variant prefix" — bare-name output
/// would collide here and lose information.
#[test]
fn plan_to_json_value_summary_recreates_disambiguates_same_name_runner_and_pool() {
    let plan = Plan {
        actions: vec![
            Action::RemoveRunner(fake_identity("alpha")),
            Action::RemoveCachePool("alpha".into()),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let actual: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        actual,
        vec!["RemoveCachePool(alpha)", "RemoveRunner(alpha)"],
        "same-name runner and pool must produce two distinct labeled entries",
    );
}

/// `recreates` is `--diff`-independent.
///
/// `summary.recreates` carries only `Action::label()` strings and
/// derives nothing from drop-in bodies or per-action diff payload.
/// Toggling the `diff` argument to `plan_to_json_value` MUST NOT
/// change `summary.recreates`. Pins the doc-block invariant
/// "Output is `--diff`-independent" against a future refactor that
/// accidentally couples `recreates` to diff-mode payload.
#[test]
fn plan_to_json_value_summary_recreates_is_diff_invariant() {
    let recreate_delta = plan::RunnerDelta {
        identity: fake_identity("alpha"),
        after: fake_runner_plan("alpha"),
        requires_recreate: true,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        // Modified drop-in: with `diff=true`, plan_to_json_value
        // emits unified_diff bodies in actions[]; `recreates`
        // must remain unchanged regardless.
        drop_in_changes: vec![plan::DropInChange {
            basename: "10-memory.conf".into(),
            change: plan::DropInChangeKind::Modified {
                before: "[Service]\nMemoryMax=1G\n".into(),
                after: "[Service]\nMemoryMax=2G\n".into(),
            },
        }],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let plan = Plan {
        actions: vec![
            Action::CreateRunner(fake_runner_plan("beta")),
            Action::UpdateRunner(recreate_delta),
            Action::RemoveCachePool("gamma".into()),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let no_diff = plan_to_json_value(&plan, false);
    let with_diff = plan_to_json_value(&plan, true);
    assert_eq!(
        no_diff["summary"]["recreates"], with_diff["summary"]["recreates"],
        "summary.recreates must be identical across diff=false and diff=true",
    );
    // Sanity: also verify the array is non-empty, otherwise the
    // assertion above would trivially pass on `[] == []`.
    assert!(
        !no_diff["summary"]["recreates"]
            .as_array()
            .unwrap()
            .is_empty(),
        "test must drive a non-empty recreates array; otherwise diff-invariance is trivial",
    );
}

/// All-recreate-only plan boundary pin.
///
/// When every action is recreate-class (no `NoOp`, no
/// `Restart`-class actions), `recreates.len()` must equal
/// `total_actions` and `by_disruption.{none,restart}` must be 0.
/// Symmetric counterpart to
/// `summary_recreates_empty_when_only_restart_and_none` — the
/// "everything fires the recreate gate" boundary against the
/// "nothing fires the recreate gate" boundary. Pins both endpoints
/// of the disruption-class spectrum.
#[test]
fn plan_to_json_value_summary_recreates_only_recreate_class_actions() {
    let plan = Plan {
        actions: vec![
            Action::CreateRunner(fake_runner_plan("a")),
            Action::RemoveRunner(fake_identity("b")),
            Action::RemoveCachePool("c".into()),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    let s = &body["summary"];
    let recreates = s["recreates"].as_array().unwrap();
    assert_eq!(s["total_actions"], 3);
    assert_eq!(
        recreates.len(),
        3,
        "all-recreate plan: recreates.len() must equal total_actions",
    );
    assert_eq!(s["by_disruption"]["none"], 0);
    assert_eq!(s["by_disruption"]["restart"], 0);
    assert_eq!(s["by_disruption"]["recreate"], 3);
    assert_eq!(s["any_recreate"], true);
}

/// Pool-only plan pin.
///
/// A plan with only cache-pool actions (no runner actions) must
/// still produce the correct `recreates` set. `CreateCachePool`
/// and `RemoveCachePool` are recreate-class; `UpdateCachePool` is
/// `Restart` and MUST be excluded. Guards against a future
/// refactor that narrows the recreate filter to runner-only
/// (e.g. by switching from `disruption()` to a runner-specific
/// predicate).
#[test]
fn plan_to_json_value_summary_recreates_pool_only_plan() {
    let plan = Plan {
        actions: vec![
            Action::CreateCachePool(plan::CachePoolPlan {
                binding: fake_cache_binding("x"),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            }),
            Action::UpdateCachePool(plan::CachePoolDelta {
                binding: fake_cache_binding("u"),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            }),
            Action::RemoveCachePool("y".into()),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let body = plan_to_json_value(&plan, false);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let actual: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        actual,
        vec!["CreateCachePool(x)", "RemoveCachePool(y)"],
        "pool-only plan: recreates must contain only CreateCachePool + RemoveCachePool, UpdateCachePool excluded",
    );
    assert_eq!(body["summary"]["by_disruption"]["restart"], 1);
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 2);
    assert_eq!(body["summary"]["any_recreate"], true);
}

/// End-to-end pin: a count-expanded `[[runner]]` config with no
/// discovered runners produces N `CreateRunner` actions, and every
/// expanded label appears in `summary.recreates` (sorted).
/// Closes the integration gap between the count expansion at
/// `plan::expand_counts` and the recreate listing at
/// `plan_summary_value`.
///
/// Existing summary.recreates tests synthesize Action vectors
/// directly; this test threads through the real plan pipeline:
/// build a Config with `count = 3`, run `plan_from`, then call
/// `plan_summary_value` on the resulting Vec<Action>. The
/// composition has been the load-bearing operator path
/// (`ghars plan --json | jq '.summary.recreates'`) since the
/// recreates field landed; this test pins the e2e contract so a
/// regression at any stage (`expand_counts`, `plan_from`'s `CreateRunner`
/// emission, `summary_value`'s recreate filter) surfaces here.
///
/// **Count-fixture choice**: count=3 is chosen so single-digit
/// naming keeps lex-order coincident with natural-order
/// (`ci-1, ci-2, ci-3`). For count >= 10 lex-sort produces
/// `ci-1, ci-10, ci-2, ...` — operator-confusing but contractually
/// correct (`sort_unstable` on `Vec<String>` is byte-wise). The
/// count=0 + discovered-runner shape is pinned by the sibling
/// `plan_from_count_zero_with_discovered_runner_emits_remove_in_summary_recreates`
/// test below.
///
/// Asserts:
/// - `summary.total_actions == 3` — fan-out arity.
/// - `summary.recreates == ["CreateRunner(ci-1)", "CreateRunner(ci-2)",
///   "CreateRunner(ci-3)"]` (sorted by `Action::label`, which is
///   what `plan_summary_value` emits).
/// - `summary.by_disruption["recreate"] == 3`.
/// - `summary.any_recreate == true`.
#[test]
fn plan_from_count_expanded_recreate_class_lists_all_in_summary_recreates() {
    // Build a config with `[[runner]] name = "ci" count = 3`. Use
    // the existing trust_zone fixture as a base, then promote it
    // to a count block.
    let mut cfg = cfg_with_runner_trust_zone("ci", "default".into());
    cfg.runners[0].count = Some(3);

    // No discovered runners ⇒ all 3 expanded names emit
    // CreateRunner.
    let actual = state::ActualState::default();
    let paths = Paths::default();

    let plan =
        plan::plan_from(&cfg, &actual, &paths).expect("count-expanded plan_from must succeed");

    // Sanity: 3 CreateRunner actions, no UpdateRunner / RemoveRunner.
    let create_count = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::CreateRunner(_)))
        .count();
    assert_eq!(
        create_count,
        3,
        "count = 3 with no discovered must emit 3 CreateRunner actions; \
         got {} actions: {:?}",
        plan.actions.len(),
        plan.actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    );

    let body = plan_to_json_value(&plan, false);
    assert_eq!(
        body["summary"]["total_actions"], 3,
        "count-expansion fan-out: count=3 must produce 3 actions in \
         total_actions",
    );
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let actual_labels: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        actual_labels,
        vec![
            "CreateRunner(ci-1)",
            "CreateRunner(ci-2)",
            "CreateRunner(ci-3)",
        ],
        "summary.recreates must list every count-expanded CreateRunner \
         label; sort is plan_summary_value's sort_unstable() pass over \
         Action::label() output (byte-wise lex; coincides with \
         operator-readable alphabetical for ci-1/ci-2/ci-3).",
    );
    assert_eq!(
        body["summary"]["by_disruption"]["recreate"], 3,
        "by_disruption.recreate count must equal recreates.len() — \
         plan_summary_value sources both fields from the same Vec",
    );
    assert_eq!(body["summary"]["any_recreate"], true);
}

/// Count >= 10 sibling pin: byte-wise lex-sort produces
/// `ci-1, ci-10, ci-11, ci-12, ci-2, ...` rather than natural-order
/// `ci-1, ci-2, ..., ci-9, ci-10, ci-11, ci-12`. This is the
/// contractually-correct behavior of `Vec::<String>::sort_unstable`
/// (a byte-wise lex comparison defined by `<str as Ord>`); the
/// count=3 sibling above only exercises the digit-coincident regime
/// where lex order matches natural order. This test pins the
/// regime where they DIVERGE so a future change that introduces
/// natural-order sorting (e.g. `recreates.sort_by_key(|s|
/// natural_key(s))`) must update this expectation explicitly
/// rather than landing as a silent operator-visible reorder.
///
/// **Byte-wise derivation**: every label has the common prefix
/// `CreateRunner(ci-`. The first divergent byte across the 12
/// labels is at offset 16 (the first character of the index). For
/// names whose index begins with `1` (`ci-1`, `ci-10`, `ci-11`,
/// `ci-12`), the next position decides the ordering: `)` (0x29) <
/// `0` (0x30) < `1` (0x31) < `2` (0x32), giving
/// `ci-1` < `ci-10` < `ci-11` < `ci-12`. Names with first byte
/// `2..=9` (`ci-2` through `ci-9`) all sort AFTER the `1`-prefix
/// cluster because `2` (0x32) > `1` (0x31).
///
/// **Choice of count=12**: smallest count that exercises BOTH the
/// `1?`-prefix cluster (ci-10, ci-11, ci-12) AND single-digit
/// names that sort after it (ci-2..ci-9), proving the divergence
/// across the full 1-prefix vs 2-prefix boundary rather than just
/// the ci-1/ci-10 transition.
#[test]
fn plan_from_count_expanded_double_digit_summary_recreates_byte_wise_lex_sorted() {
    let mut cfg = cfg_with_runner_trust_zone("ci", "default".into());
    cfg.runners[0].count = Some(12);

    let actual = state::ActualState::default();
    let paths = Paths::default();

    let plan = plan::plan_from(&cfg, &actual, &paths).expect("count=12 plan_from must succeed");

    let create_count = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::CreateRunner(_)))
        .count();
    assert_eq!(
        create_count, 12,
        "count = 12 with no discovered must emit 12 CreateRunner actions",
    );

    let body = plan_to_json_value(&plan, false);
    assert_eq!(body["summary"]["total_actions"], 12);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let actual_labels: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        actual_labels,
        vec![
            "CreateRunner(ci-1)",
            "CreateRunner(ci-10)",
            "CreateRunner(ci-11)",
            "CreateRunner(ci-12)",
            "CreateRunner(ci-2)",
            "CreateRunner(ci-3)",
            "CreateRunner(ci-4)",
            "CreateRunner(ci-5)",
            "CreateRunner(ci-6)",
            "CreateRunner(ci-7)",
            "CreateRunner(ci-8)",
            "CreateRunner(ci-9)",
        ],
        "summary.recreates must use byte-wise lex order — \
         ci-10/11/12 sort BETWEEN ci-1 and ci-2, NOT after ci-9 \
         (natural-order would put ci-10..ci-12 at the end). A \
         future change to natural-order sorting must update this \
         expected Vec explicitly.",
    );
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 12);
    assert_eq!(body["summary"]["any_recreate"], true);
}

/// Count=0 orphan-removal shape: a managed runner exists
/// on disk (surfaced via `actual.orphans`) with no matching
/// `[[runner]]` block, so `plan_from` emits one `RemoveRunner` action.
/// `RemoveRunner` is recreate-class, so its label appears in
/// `summary.recreates`.
///
/// `actual.orphans` is the upstream-callable orphan path (`cmd_status`
/// populates it inline; `state::discover` itself never does). The
/// (false, true) discovery branch in `plan_from` would cover the same
/// ground but requires a fully-built `DiscoveredRunner` fixture.
/// Using `orphans` keeps the fixture minimal — only an
/// `OrphanedUnit { name }` is needed.
#[test]
fn plan_from_orphan_remove_runner_lists_label_in_summary_recreates() {
    // Empty config (no runners) — only the orphan triggers an action.
    let mut cfg = cfg_with_runner_trust_zone("placeholder", "default".into());
    cfg.runners.clear();

    let mut actual = state::ActualState::default();
    actual.orphans.push(state::OrphanedUnit {
        name: "legacy".into(),
    });
    let paths = Paths::default();

    let plan = plan::plan_from(&cfg, &actual, &paths).expect("orphan plan_from must succeed");

    let remove_count = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::RemoveRunner(_)))
        .count();
    assert_eq!(
        remove_count,
        1,
        "one orphan must produce one RemoveRunner; got {} actions",
        plan.actions.len(),
    );

    let body = plan_to_json_value(&plan, false);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let labels: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        labels,
        vec!["RemoveRunner(legacy)"],
        "summary.recreates must contain the orphan's RemoveRunner label",
    );
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 1);
    assert_eq!(body["summary"]["any_recreate"], true);
}

/// Empty plan shape: no runners in config, no discovered
/// state. `plan_from` emits zero actions; `summary.recreates` is the
/// empty array `[]` (stable JSON shape so CI consumers can `jq
/// '.summary.recreates | length'` without conditional key checks).
/// Pinned via `plan_from` end-to-end (sibling
/// `plan_to_json_value_summary_recreates_empty_when_no_actions`
/// pins the same shape from a hand-built `Plan { actions: vec![] }`
/// — this test threads through the count-expansion + diff
/// pipeline to catch a regression that emits stray actions for
/// the empty-vs-empty case).
#[test]
fn plan_from_no_desired_no_actual_emits_empty_summary_recreates() {
    let mut cfg = cfg_with_runner_trust_zone("placeholder", "default".into());
    cfg.runners.clear();
    let actual = state::ActualState::default();
    let paths = Paths::default();

    let plan = plan::plan_from(&cfg, &actual, &paths)
        .expect("empty desired + empty actual plan_from must succeed");

    assert!(
        plan.actions.is_empty(),
        "empty desired + empty actual must yield zero actions; got: {:?}",
        plan.actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    );

    let body = plan_to_json_value(&plan, false);
    assert_eq!(
        body["summary"]["recreates"],
        serde_json::json!([] as [&str; 0]),
        "empty plan must emit recreates: [] not null/missing",
    );
    assert_eq!(body["summary"]["total_actions"], 0);
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 0);
    assert_eq!(body["summary"]["any_recreate"], false);
}

/// Shared scaffold for the explicit-collision precedence sibling
/// tests (forward: explicit Some > count None, and inverse:
/// explicit None > count Some).
///
/// Sets up a `Config` with a count=3 block named `ci` (whose
/// `memory_max` is set to `count_block_memory_max`) plus an
/// explicit `[[runner]] name = "ci-1"` (whose `memory_max` is set
/// to `explicit_memory_max`), invokes `plan_from`, and runs the
/// invariants every direction must satisfy:
///
/// 1. The plan emits exactly 3 `CreateRunner` actions — `expand_counts`

/// Count expansion with explicit collision: a count block
/// `name = "ci" count = 3` plus an explicit `[[runner]] name =
/// "ci-1"` produces 3 distinct expanded names — the explicit ci-1
/// pre-empts the count-block ci-1, so the plan has `CreateRunner`
/// for ci-1, ci-2, ci-3 (one each, no duplicates). The
/// `expand_counts_auto_skips_explicit_collision` test in plan.rs
/// pins the expansion-side count; this test extends the contract
/// to the rendered `summary.recreates` shape — the count and
/// explicit blocks share a single recreates entry per name.
///
/// Body delegates to `assert_explicit_collision_precedence` for
/// the shared 6-invariant scaffold; this test contributes the
/// forward direction (count `memory_max = None`, explicit
/// `memory_max = Some("8G")`, expected ci-1 `Some("8G")`).
#[test]
fn plan_from_count_with_explicit_collision_lists_each_name_once_in_recreates() {
    assert_explicit_collision_precedence(None, Some("8G".into()), Some("8G".into()));
}

/// Inverse of `plan_from_count_with_explicit_collision_lists_each_name_once_in_recreates`:
/// the explicit ci-1 carries `memory_max = None` while the count
/// block carries `memory_max = Some("4G")`. `expand_counts`'s
/// `if explicit_names.contains(...)` arm still auto-skips the
/// count-expanded ci-1, so the explicit ci-1's `RunnerSpec` —
/// with its None `memory_max` — is what flows through
/// `merge_defaults` and into the resulting `EffectiveRunnerSpec`.
/// `merge_defaults`'s `runner.memory_max OR defaults.memory_max`
/// or-chain then resolves to None (defaults left None by
/// `cfg_with_runner_trust_zone`).
///
/// The forward-direction sibling proves the explicit block wins
/// when it carries MORE configuration than the count block (the
/// "richer-spec wins" hypothesis would also pass that test). This
/// inverse direction proves the explicit block wins when it
/// carries LESS configuration than the count block — falsifying
/// any "richer-spec wins" alternative. Together they pin the
/// invariant that explicit-block precedence is positional/identity
/// based, not field-density based.
///
/// Body delegates to `assert_explicit_collision_precedence` for
/// the shared 6-invariant scaffold; this test contributes the
/// inverse direction (count `memory_max = Some("4G")`, explicit
/// `memory_max = None`, expected ci-1 `None`).
#[test]
fn plan_from_count_with_explicit_collision_explicit_none_wins_over_count_some() {
    assert_explicit_collision_precedence(Some("4G".into()), None, None);
}

/// Count=0 → orphan `RemoveRunner` end-to-end shape: a `[[runner]]`
/// block with `count = Some(0)` is dropped at `expand_counts`
/// (`expand_counts`'s `matches!(spec.count, Some(0)) => continue`
/// arm — the explicit early-return for the count=0 case keeps
/// count=Some(1) and count=None passing through unchanged), so
/// the desired-set has zero runners after expansion. A managed
/// runner discovered on disk (`actual.runners["ci-1"]`, populated
/// by `state::discover` in production) has no matching desired
/// entry — `plan_from`'s `(false, true)` arm fires, emitting
/// `RemoveRunner(ci-1)`. `RemoveRunner` is recreate-class
/// (`Disruption::Recreate` per `Action::disruption()`), so its
/// label appears in `summary.recreates`.
///
/// Distinct from the sibling test
/// `plan_from_orphan_remove_runner_lists_label_in_summary_recreates`
/// — that fixture uses `cfg.runners.clear()` plus an
/// `actual.orphans` push, exercising step 9's
/// `for orphan in &actual.orphans` arm in `plan_from`. This test
/// instead routes through `expand_counts`'s count=0 skip + the
/// `(false, true)` discovery branch (the shape `state::discover`
/// + `actual.runners` produces in production, since
/// `state::discover` itself never populates orphans). Together
/// they pin both surfaces.
#[test]
fn plan_from_count_zero_with_discovered_runner_emits_remove_in_summary_recreates() {
    // [[runner]] name = "ci" count = 0. expand_counts skips the
    // block entirely (count=0 → continue), so desired_names is
    // empty after expansion.
    let mut cfg = cfg_with_runner_trust_zone("ci", "default".into());
    cfg.runners[0].count = Some(0);

    // Discovered "ci-1" on disk with no matching desired entry.
    // Minimal DiscoveredRunner is sufficient — reconstruct_identity
    // tolerates empty on_disk_unit_text via unwrap_or_else fallbacks
    // for User= and WorkingDirectory= parsing, and the assertion
    // here only reads RemoveRunner's name field via Action::label
    // ("RemoveRunner(ci-1)"). InSync drift is the canonical
    // "no drift" classification — the (false, true) branch in
    // plan_from doesn't gate on drift, so any value works; InSync
    // is the simplest.
    let mut actual = state::ActualState::default();
    actual.runners.insert(
        "ci-1".into(),
        state::DiscoveredRunner {
            name: "ci-1".into(),
            spec_hash: String::new(),
            on_disk_unit_text: String::new(),
            drop_ins: std::collections::BTreeMap::new(),
            running: false,
            enabled: false,
            drift: state::Drift::InSync,
        },
    );
    let paths = Paths::default();

    let plan = plan::plan_from(&cfg, &actual, &paths)
        .expect("count=0 + discovered plan_from must succeed");

    // Sanity: exactly one RemoveRunner action, no Create/Update.
    let remove_count = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::RemoveRunner(_)))
        .count();
    assert_eq!(
        remove_count,
        1,
        "count=0 + one discovered runner must yield one RemoveRunner; \
         got {} actions: {:?}",
        plan.actions.len(),
        plan.actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    );
    assert!(
        !plan
            .actions
            .iter()
            .any(|a| matches!(a, Action::CreateRunner(_) | Action::UpdateRunner(_))),
        "count=0 must NOT emit Create/Update; got: {:?}",
        plan.actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    );

    let body = plan_to_json_value(&plan, false);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let labels: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        labels,
        vec!["RemoveRunner(ci-1)"],
        "summary.recreates must contain the count=0 → orphan \
         RemoveRunner label",
    );
    assert_eq!(body["summary"]["by_disruption"]["recreate"], 1);
    assert_eq!(body["summary"]["any_recreate"], true);
    assert_eq!(body["summary"]["total_actions"], 1);
}

/// Discovered-only runner with POPULATED annotations: extends
/// the count=0 sibling above by feeding `plan_from`'s
/// discovered-only diff arm a `DiscoveredRunner` whose
/// `00-ghars.conf` drop-in carries a full annotation set.
/// `reconstruct_identity` reads
/// `discovered.drop_ins["00-ghars.conf"]` via
/// `DiscoveredAnnotations::from_discovered` for url and
/// `auth_name`. A populated fixture therefore produces a
/// `RunnerIdentity` with non-empty url + `auth_name` — matching
/// what `apply.rs::execute_remove_runner` needs to mint a
/// deregistration token on recreate.
///
/// The count=0 sibling
/// (`plan_from_count_zero_with_discovered_runner_emits_remove_in_summary_recreates`)
/// uses an empty fixture (empty `on_disk_unit_text` + empty
/// `drop_ins`), exercising `reconstruct_identity`'s `unwrap_or_else`
/// fallbacks. This test takes the populated path, distinct from
/// that fallback.
///
/// Distinct config shape: no count block; one explicit runner
/// "web" desired, one different-named "old-web" discovered. The
/// desired-only arm fires for "web" (`CreateRunner`), the
/// discovered-only arm fires for "old-web" (`RemoveRunner`). The
/// assertion focuses on the `RemoveRunner` — its identity must
/// carry the annotation values, not the fallback empty strings.
#[test]
fn plan_from_discovered_only_runner_populates_remove_runner_identity() {
    // Desired: explicit runner "web" (no count block).
    let cfg = cfg_with_runner_trust_zone("web", "default".into());

    // Discovered: a different runner "old-web" — managed unit
    // present on disk, no matching desired entry. The
    // discovered-only arm in plan_from emits RemoveRunner("old-web").
    // Build the discovered runner's spec + render to populate
    // drop_ins["00-ghars.conf"] (which DiscoveredAnnotations::
    // from_discovered reads for url + auth_name).
    let discovered_spec = crate::config::EffectiveRunnerSpec {
        environment: crate::config::EnvironmentSpec::default(),
        name: "old-web".into(),
        url: "https://github.com/example/old-web".into(),
        arch: crate::config::Arch::X86_64,
        labels: vec!["old-web".into()],
        memory_max: None,
        runner_version: None,
        runner_sha256: None,
        runner_tarball: None,
        auth_name: "pat".into(),
        caches: vec![],
        trust_zone: "default".into(),
        network: None,
        proxy: None,
        hooks: None,
        hardening: crate::config::Hardening::default(),
        allowed_cpus: None,
        allowed_memory_nodes: None,
        spec_hash: "sha256:0".into(),
        config_source: "/etc/ghars/ghars.toml".into(),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };
    let rendered = crate::systemd::render_runner_unit(&discovered_spec)
        .expect("render_runner_unit must succeed for valid spec");
    // Use the production-shape unit body (the runner template
    // verbatim). The url + auth_name assertions below pass only
    // when `reconstruct_identity` reads the
    // `X-Ghars-Runner-Url` / `X-Ghars-Auth-Name` annotations
    // emitted by `render_runner_unit` into
    // `rendered.drop_ins["00-ghars.conf"]`, not from the
    // template body.
    let on_disk_unit_text = crate::systemd::runner_template_text();
    let mut actual = state::ActualState::default();
    actual.runners.insert(
        "old-web".into(),
        state::DiscoveredRunner {
            name: "old-web".into(),
            spec_hash: discovered_spec.spec_hash.clone(),
            on_disk_unit_text,
            drop_ins: rendered.drop_ins,
            running: false,
            enabled: false,
            drift: state::Drift::InSync,
        },
    );
    let paths = Paths::default();

    let plan = plan::plan_from(&cfg, &actual, &paths)
        .expect("discovered-only branch with populated annotations must succeed");

    // The plan must contain a RemoveRunner("old-web") AND a
    // CreateRunner("web") — both arms fire. Extract the
    // RemoveRunner's identity for the populated-fields pin.
    let remove_identity = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::RemoveRunner(id) => Some(id),
            _ => None,
        })
        .expect("discovered-only arm must emit RemoveRunner");
    assert_eq!(
        remove_identity.name, "old-web",
        "RemoveRunner must target the discovered-only runner",
    );
    assert_eq!(
        remove_identity.url, "https://github.com/example/old-web",
        "RemoveRunner.url must reflect the X-Ghars-Runner-Url \
         annotation in the discovered 00-ghars.conf, not the \
         empty fallback that DiscoveredAnnotations::default \
         would produce on a missing drop-in",
    );
    assert_eq!(
        remove_identity.auth_name, "pat",
        "RemoveRunner.auth_name must reflect the X-Ghars-Auth-Name \
         annotation, not the empty fallback",
    );

    // Pin the docstring's "desired-only arm fires for 'web'
    // (CreateRunner)" claim. The doc states both arms fire in
    // this fixture; without this assertion that claim is
    // unverified and could silently regress (e.g. plan_from
    // refactor that drops the desired-only arm in mixed plans).
    assert!(
        plan.actions
            .iter()
            .any(|a| matches!(a, Action::CreateRunner(p) if p.spec.name == "web")),
        "desired-only arm must emit CreateRunner(web); got actions: {:?}",
        plan.actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    );

    // Full-Vec pin on summary.recreates: the plan has exactly
    // 2 actions — CreateRunner("web") from the desired-only arm
    // and RemoveRunner("old-web") from the discovered-only arm.
    // Both are recreate-class (per Action::disruption()), so both
    // labels appear in summary.recreates. plan_summary_value
    // sorts via sort_unstable() over Action::label() output, so
    // "CreateRunner(web)" < "RemoveRunner(old-web)" by byte-wise
    // lex order. assert_eq! catches both ordering regressions
    // and any spurious/missing entries — strictly tighter than
    // a single .contains() check.
    let body = plan_to_json_value(&plan, false);
    let recreates = body["summary"]["recreates"].as_array().unwrap();
    let labels: Vec<&str> = recreates.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        labels,
        vec!["CreateRunner(web)", "RemoveRunner(old-web)"],
        "summary.recreates must equal exactly [CreateRunner(web), \
         RemoveRunner(old-web)] (sorted by Action::label byte-wise); \
         got: {labels:?}",
    );
}

// ---------- colorized unified diff ----------------------------

#[test]
fn render_action_line_diff_modified_color_wraps_plus_lines_green() {
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: vec![plan::DropInChange {
            basename: "10-memory.conf".into(),
            change: plan::DropInChangeKind::Modified {
                before: "[Service]\nMemoryMax=1G\n".into(),
                after: "[Service]\nMemoryMax=2G\n".into(),
            },
        }],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let line = render_action_line(
        &Action::UpdateRunner(delta),
        ColorMode { enabled: true },
        true,
    );
    // `+MemoryMax=2G` wrapped in green (\x1b[32m ... \x1b[0m).
    assert!(
        line.contains("\x1b[32m+MemoryMax=2G\x1b[0m"),
        "expected green-wrapped + line: {line}",
    );
    // `-MemoryMax=1G` wrapped in red (\x1b[31m ... \x1b[0m).
    assert!(
        line.contains("\x1b[31m-MemoryMax=1G\x1b[0m"),
        "expected red-wrapped - line: {line}",
    );
}

#[test]
fn render_action_line_diff_modified_no_color_emits_plain_unified_diff() {
    // Same Modified payload, color disabled — no ANSI escape
    // sequences in the body, but `+`/`-` sigils still present.
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: vec![plan::DropInChange {
            basename: "10-memory.conf".into(),
            change: plan::DropInChangeKind::Modified {
                before: "[Service]\nMemoryMax=1G\n".into(),
                after: "[Service]\nMemoryMax=2G\n".into(),
            },
        }],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let line = render_action_line(
        &Action::UpdateRunner(delta),
        ColorMode { enabled: false },
        true,
    );
    // Unified-diff body has the +/- sigils but no ANSI bytes
    // around them.
    assert!(line.contains("+MemoryMax=2G"), "got: {line}");
    assert!(line.contains("-MemoryMax=1G"), "got: {line}");
    assert!(
        !line.contains("\x1b[32m+MemoryMax"),
        "no-color must not wrap + lines in green: {line}",
    );
    assert!(
        !line.contains("\x1b[31m-MemoryMax"),
        "no-color must not wrap - lines in red: {line}",
    );
}

#[test]
fn render_action_line_diff_modified_color_does_not_wrap_hunk_header() {
    // `@@` hunk headers are NOT colored — operator scripts
    // grepping `^@@` on color-stripped output still match.
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: vec![plan::DropInChange {
            basename: "10-memory.conf".into(),
            change: plan::DropInChangeKind::Modified {
                before: "[Service]\nMemoryMax=1G\n".into(),
                after: "[Service]\nMemoryMax=2G\n".into(),
            },
        }],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let line = render_action_line(
        &Action::UpdateRunner(delta),
        ColorMode { enabled: true },
        true,
    );
    // The `@@` line itself is uncolored; check that no ANSI
    // prefix immediately precedes it.
    assert!(line.contains("@@"), "expected hunk header: {line}");
    assert!(
        !line.contains("\x1b[32m@@") && !line.contains("\x1b[31m@@"),
        "hunk header must not be wrapped in ANSI color: {line}",
    );
}

#[test]
fn render_action_line_diff_modified_unified_diff_uses_on_disk_desired_headers() {
    // Header labels track the in-memory-vs-disk semantics:
    // `--- on-disk` (the discovered drop-in body) and
    // `+++ desired` (the post-render bytes). Pin the strings
    // so the convention doesn't silently revert to the
    // ambiguous `before`/`after` (or `None` → no labels).
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: vec![plan::DropInChange {
            basename: "10-memory.conf".into(),
            change: plan::DropInChangeKind::Modified {
                before: "[Service]\nMemoryMax=1G\n".into(),
                after: "[Service]\nMemoryMax=2G\n".into(),
            },
        }],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let line = render_action_line(
        &Action::UpdateRunner(delta),
        ColorMode { enabled: false },
        true,
    );
    assert!(line.contains("--- on-disk"), "got: {line}");
    assert!(line.contains("+++ desired"), "got: {line}");
}

#[test]
fn render_action_line_diff_modified_color_does_not_wrap_unified_diff_headers() {
    // `--- on-disk` and `+++ desired` are header lines, not
    // change lines, and must NOT be wrapped in red/green —
    // matches `git diff --color`, which renders headers in
    // bold/cyan, not the change-line palette. Pin both
    // headers stay uncolored when color is enabled.
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: vec![plan::DropInChange {
            basename: "10-memory.conf".into(),
            change: plan::DropInChangeKind::Modified {
                before: "[Service]\nMemoryMax=1G\n".into(),
                after: "[Service]\nMemoryMax=2G\n".into(),
            },
        }],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let line = render_action_line(
        &Action::UpdateRunner(delta),
        ColorMode { enabled: true },
        true,
    );
    assert!(line.contains("--- on-disk"), "got: {line}");
    assert!(line.contains("+++ desired"), "got: {line}");
    assert!(
        !line.contains("\x1b[31m--- on-disk"),
        "--- on-disk header must not be red-wrapped: {line}",
    );
    assert!(
        !line.contains("\x1b[32m+++ desired"),
        "+++ desired header must not be green-wrapped: {line}",
    );
}

#[test]
fn render_action_line_diff_created_no_color_wrap_on_created_body() {
    // Created bodies render under `        after:` with the
    // raw drop-in body — those bytes are NOT a unified diff,
    // so no `+`/`-` sigils, and color must not wrap them.
    // Pin that the body text appears verbatim and no ANSI
    // bytes wrap individual content lines.
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: vec![plan::DropInChange {
            basename: "60-proxy.conf".into(),
            change: plan::DropInChangeKind::Created {
                after: "[Service]\nEnvironment=HTTP_PROXY=http://p:8080\n".into(),
            },
        }],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let line = render_action_line(
        &Action::UpdateRunner(delta),
        ColorMode { enabled: true },
        true,
    );
    // The `+ 60-proxy.conf` sigil-line sits on the basename
    // line (not body); the body itself has no `+`/`-` to color.
    assert!(line.contains("    + 60-proxy.conf"), "got: {line}");
    assert!(line.contains("            [Service]"), "got: {line}");
    // `Environment=` is part of the body — must not be color-
    // wrapped because it was never `+` or `-` prefixed.
    assert!(
        !line.contains("\x1b[32m            [Service]"),
        "Created body lines must not be color-wrapped: {line}",
    );
}

// ---------- --diff argv parsing -------------------------------

#[test]
fn cli_plan_diff_default_is_false() {
    let cli = Cli::try_parse_from(["ghars", "plan"]).unwrap();
    match cli.command {
        Command::Plan(args) => assert!(!args.diff),
        other => panic!("expected Plan, got {other:?}"),
    }
}

#[test]
fn cli_plan_diff_flag_sets_true() {
    let cli = Cli::try_parse_from(["ghars", "plan", "--diff"]).unwrap();
    match cli.command {
        Command::Plan(args) => assert!(args.diff),
        other => panic!("expected Plan, got {other:?}"),
    }
}

#[test]
fn cli_plan_diff_does_not_take_value() {
    // Bool flag, not enum — a positional value following --diff
    // is a parse error (or in clap's case, attaches as another
    // positional — try_parse_from rejects unknown positionals
    // for a strict subcommand). Pin that --diff itself does not
    // consume its argument.
    let res = Cli::try_parse_from(["ghars", "plan", "--diff", "verbose"]);
    assert!(
        res.is_err(),
        "expected parse error for --diff with positional 'verbose', got: {res:?}",
    );
}

#[test]
fn cli_apply_diff_default_is_false() {
    let cli = Cli::try_parse_from(["ghars", "apply"]).unwrap();
    match cli.command {
        Command::Apply(args) => assert!(!args.diff),
        other => panic!("expected Apply, got {other:?}"),
    }
}

#[test]
fn cli_apply_diff_flag_sets_true() {
    let cli = Cli::try_parse_from(["ghars", "apply", "--diff"]).unwrap();
    match cli.command {
        Command::Apply(args) => assert!(args.diff),
        other => panic!("expected Apply, got {other:?}"),
    }
}

// render_plan covers the multi-action assembly path. We test the
// empty-plan branch, the warnings tail, and the JSON path here.

#[test]
fn render_plan_json_emits_action_array_per_variant() {
    let warnings = vec!["shared user disables isolation".to_owned()];
    let plan = Plan {
        actions: vec![
            Action::CreateRunner(fake_runner_plan("a")),
            Action::UpdateRunner(plan::RunnerDelta {
                identity: fake_identity("b"),
                after: fake_runner_plan("b"),
                requires_recreate: true,
                recreate_reasons: vec!["runner_version"],
                drift_cause: plan::DriftCause::SpecChanged,
                field_changes: Vec::new(),
                drop_in_changes: Vec::new(),
                before_caches: None,
                before_drop_in_basenames: None,
            }),
            Action::RemoveRunner(fake_identity("c")),
            Action::CreateCachePool(plan::CachePoolPlan {
                binding: fake_cache_binding("p"),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            }),
            Action::UpdateCachePool(plan::CachePoolDelta {
                binding: fake_cache_binding("p2"),
                drop_in_body: String::new(),
                spec_hash: "sha256:0".into(),
            }),
            Action::RemoveCachePool("p3".into()),
            Action::NoOp("d: in sync".into()),
        ],
        warnings,
        keep_versions: 2,
    };
    // Drive the production Value-construction directly. No test
    // mirror — `plan_to_json_value` IS the production code.
    let body = plan_to_json_value(&plan, false);
    let actions = body["actions"].as_array().expect("actions array");
    let kinds: Vec<&str> = actions
        .iter()
        .filter_map(|v| v.get("kind").and_then(|s| s.as_str()))
        .collect();
    assert_eq!(
        kinds,
        vec![
            "create_runner",
            "update_runner",
            "remove_runner",
            "create_cache_pool",
            "update_cache_pool",
            "remove_cache_pool",
            "noop",
        ]
    );
    // update_runner carries drift_cause + recreate_reasons.
    let upd = actions
        .iter()
        .find(|v| v["kind"] == "update_runner")
        .unwrap();
    assert_eq!(upd["drift_cause"], "spec_changed");
    assert_eq!(upd["requires_recreate"], true);
    // No payload exposes raw token values or env-var references.
    let serialized = serde_json::to_string(&body).unwrap();
    assert!(!serialized.contains("token"), "no token leakage");
}

#[test]
fn render_plan_quiet_writes_nothing() -> Result<()> {
    // quiet=true short-circuits BEFORE printing anything to stdout.
    // We verify the function returns Ok(()) and does not panic
    // when given a non-empty plan; the absence of output is
    // structural in the function body (`if quiet { return Ok(()) }`).
    let plan = Plan {
        actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
        warnings: vec![],
        keep_versions: 2,
    };
    render_plan(&plan, ColorMode { enabled: false }, false, true, false)
}

#[test]
fn render_plan_empty_emits_no_changes_line_when_not_quiet() -> Result<()> {
    // The `Plan: no changes.` early-return path. Tested through
    // the public helper; the assertion is that the call succeeds
    // without panicking on an empty action list.
    let plan = Plan::default();
    render_plan(&plan, ColorMode { enabled: false }, false, false, false)
}

#[test]
fn render_plan_json_path_succeeds_for_full_plan() -> Result<()> {
    // render_plan with json=true delegates to render_plan_json.
    // Drives the helper end-to-end; all-variant JSON shape is
    // pinned by render_plan_json_emits_action_array_per_variant.
    let plan = Plan {
        actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
        warnings: vec!["shared user".into()],
        keep_versions: 2,
    };
    render_plan(&plan, ColorMode { enabled: false }, true, false, false)
}

/// Item 6: end-to-end exercise of `render_plan_json` against an
/// `UpdateRunner` action carrying a populated `field_changes` Vec
/// AND a `drop_in_changes` Vec covering all four
/// `DropInChangeKind` variants. The production renderer takes
/// `&Plan` and writes to stdout — there is no return value, so
/// the assertion is structural: render must succeed without
/// panic on the most complex Update shape the planner can emit.
/// The shape contract (top-level `actions` + `warnings`,
/// per-action `field_changes` + `drop_in_changes`) is pinned by
/// `render_plan_json_emits_action_array_per_variant` which
/// drives `plan_to_json_value` directly (no test mirror).
/// Together the two tests cover both the happy-path output shape
/// AND the non-panicking end-to-end pipe.
#[test]
fn render_plan_json_handles_update_runner_with_full_diff_payload() -> Result<()> {
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::SpecChangedAndDriftDetected,
        field_changes: vec![
            plan::FieldChange {
                path: "auth_name",
                before: plan::FieldValue::String("pat".into()),
                after: plan::FieldValue::String("pat-new".into()),
            },
            plan::FieldChange {
                path: "labels",
                before: plan::FieldValue::List(vec!["ci".into()]),
                after: plan::FieldValue::List(vec!["ci".into(), "gpu".into()]),
            },
        ],
        drop_in_changes: vec![
            plan::DropInChange {
                basename: "00-ghars.conf".into(),
                change: plan::DropInChangeKind::Modified {
                    before: "old".into(),
                    after: "new".into(),
                },
            },
            plan::DropInChange {
                basename: "10-memory.conf".into(),
                change: plan::DropInChangeKind::Removed {
                    before: "MemoryMax=8G".into(),
                },
            },
            plan::DropInChange {
                basename: "60-proxy.conf".into(),
                change: plan::DropInChangeKind::Created {
                    after: "Environment=HTTP_PROXY=...".into(),
                },
            },
            plan::DropInChange {
                basename: "15-resolv.conf".into(),
                change: plan::DropInChangeKind::Preserved,
            },
        ],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let plan = Plan {
        actions: vec![Action::UpdateRunner(delta)],
        warnings: vec!["mixed signal: hash + drift".into()],
        keep_versions: 2,
    };
    // Production renderer writes to stdout; the test assertion is
    // that the call succeeds (no panic, no Err). Output-shape
    // contract is enforced by the all-variants test that mirrors
    // the Value construction.
    render_plan_json(&plan, false)
}

#[test]
fn render_plan_with_warnings_does_not_panic() -> Result<()> {
    let plan = Plan {
        actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
        warnings: vec![
            "shared user disables isolation".into(),
            "memory_max in defaults overridden by runner".into(),
        ],
        keep_versions: 2,
    };
    render_plan(&plan, ColorMode { enabled: false }, false, false, false)
}

/// Plan.warnings reaches both text and JSON renderers in the same
/// order it was emitted, with a `warning: ` prefix on the text side
/// and a raw string array on the JSON side. Pins the contract that
/// the planner's RenderedUnit.warnings flow doesn't get silently
/// dropped on the way to the operator.
#[test]
fn plan_warnings_round_trip_to_text_and_json() {
    let plan = Plan {
        actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
        warnings: vec![
            "hardening.kvm=false drops /dev/kvm rw".into(),
            "memory_max in defaults overridden by runner".into(),
        ],
        keep_versions: 2,
    };
    let value = plan_to_json_value(&plan, false);
    let warnings = value
        .get("warnings")
        .expect("plan_to_json_value must emit a top-level `warnings` key");
    let arr = warnings.as_array().expect("warnings is a JSON array");
    assert_eq!(arr.len(), 2, "all warnings must round-trip; got {arr:?}");
    assert_eq!(
        arr[0].as_str().unwrap(),
        "hardening.kvm=false drops /dev/kvm rw",
        "JSON ordering must match Plan.warnings ordering"
    );
    assert_eq!(
        arr[1].as_str().unwrap(),
        "memory_max in defaults overridden by runner",
    );
}

// ColorMode::from_cli — the no_color flag branch is testable
// structurally; the env var + TTY branches require std::env mutation
// (forbidden under unsafe_code = "forbid" since Rust 2024).
#[test]
fn color_mode_from_cli_no_color_flag_disables_ansi() {
    let mode = ColorMode::from_cli(true);
    assert!(
        !mode.enabled,
        "--no-color must force ANSI output off regardless of env / TTY"
    );
}

#[test]
fn render_action_line_create_cache_pool_color_path_emits_green() {
    // CreateCachePool also gets the green ANSI prefix (matches
    // CreateRunner). Without color, no escapes.
    let action = Action::CreateCachePool(plan::CachePoolPlan {
        binding: fake_cache_binding("build"),
        drop_in_body: String::new(),
        spec_hash: "sha256:0".into(),
    });
    let plain = render_action_line(&action, ColorMode { enabled: false }, false);
    assert!(!plain.contains("\x1b["), "no ANSI without color");
    let colored = render_action_line(&action, ColorMode { enabled: true }, false);
    assert!(colored.contains("\x1b[32m"), "expected green ANSI prefix");
    assert!(colored.contains("\x1b[0m"), "expected ANSI reset");
}

#[test]
fn render_action_line_update_cache_pool_color_path_emits_yellow() {
    let action = Action::UpdateCachePool(plan::CachePoolDelta {
        binding: fake_cache_binding("build"),
        drop_in_body: String::new(),
        spec_hash: "sha256:0".into(),
    });
    let plain = render_action_line(&action, ColorMode { enabled: false }, false);
    assert!(!plain.contains("\x1b["));
    let colored = render_action_line(&action, ColorMode { enabled: true }, false);
    assert!(colored.contains("\x1b[33m"), "expected yellow ANSI prefix");
    assert!(colored.contains("\x1b[0m"));
}

#[test]
fn render_action_line_remove_cache_pool_color_path_emits_red() {
    let action = Action::RemoveCachePool("build".into());
    let plain = render_action_line(&action, ColorMode { enabled: false }, false);
    assert!(!plain.contains("\x1b["));
    let colored = render_action_line(&action, ColorMode { enabled: true }, false);
    assert!(colored.contains("\x1b[31m"), "expected red ANSI prefix");
    assert!(colored.contains("\x1b[0m"));
}

#[test]
fn render_action_line_update_runner_color_path_emits_yellow() {
    // Update is yellow regardless of recreate-vs-in-place.
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::DriftDetected,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let colored = render_action_line(
        &Action::UpdateRunner(delta),
        ColorMode { enabled: true },
        false,
    );
    assert!(colored.contains("\x1b[33m"), "expected yellow ANSI prefix");
}

#[test]
fn render_plan_json_create_runner_kind_label_is_create_runner() {
    // Per-variant JSON shape pin (operator-facing API contract).
    // Constructs a plan with each variant in turn and confirms
    // the kind discriminator. (Full-plan version exists at
    // render_plan_json_emits_action_array_per_variant; these
    // smaller per-variant tests fail with a clearer signal when
    // a single variant's shape regresses.)
    let plan = Plan {
        actions: vec![Action::CreateRunner(fake_runner_plan("a"))],
        warnings: vec![],
        keep_versions: 2,
    };
    let v = plan_to_json_value(&plan, false);
    let actions = v["actions"].as_array().expect("actions array");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["kind"], "create_runner");
    assert_eq!(actions[0]["name"], "a");
    assert!(actions[0]["url"].is_string());
    assert!(
        actions[0]["spec_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
}

#[test]
fn render_plan_json_remove_runner_kind_label_is_remove_runner() {
    let plan = Plan {
        actions: vec![Action::RemoveRunner(fake_identity("legacy"))],
        warnings: vec![],
        keep_versions: 2,
    };
    let v = plan_to_json_value(&plan, false);
    let actions = v["actions"].as_array().unwrap();
    assert_eq!(actions[0]["kind"], "remove_runner");
    assert_eq!(actions[0]["name"], "legacy");
}

#[test]
fn render_plan_json_create_cache_pool_kind_label() {
    let plan = Plan {
        actions: vec![Action::CreateCachePool(plan::CachePoolPlan {
            binding: fake_cache_binding("build"),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        })],
        warnings: vec![],
        keep_versions: 2,
    };
    let v = plan_to_json_value(&plan, false);
    let actions = v["actions"].as_array().unwrap();
    assert_eq!(actions[0]["kind"], "create_cache_pool");
    assert_eq!(actions[0]["name"], "build");
}

#[test]
fn render_plan_json_update_cache_pool_kind_label() {
    let plan = Plan {
        actions: vec![Action::UpdateCachePool(plan::CachePoolDelta {
            binding: fake_cache_binding("build"),
            drop_in_body: String::new(),
            spec_hash: "sha256:0".into(),
        })],
        warnings: vec![],
        keep_versions: 2,
    };
    let v = plan_to_json_value(&plan, false);
    let actions = v["actions"].as_array().unwrap();
    assert_eq!(actions[0]["kind"], "update_cache_pool");
}

#[test]
fn render_plan_json_remove_cache_pool_kind_label() {
    let plan = Plan {
        actions: vec![Action::RemoveCachePool("build".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    let v = plan_to_json_value(&plan, false);
    let actions = v["actions"].as_array().unwrap();
    assert_eq!(actions[0]["kind"], "remove_cache_pool");
    assert_eq!(actions[0]["name"], "build");
}
