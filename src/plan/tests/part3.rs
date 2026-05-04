//! Test split part 3: covers caches classifier edge cases, labels classifier
//! edge cases (parity with caches), `delta.before_caches` sort site, C-6
//! regression (operator 99-*.conf masks recreate), `trust_zone` in-place
//! contract, network mode recreate contract, missing-annotation tolerance +
//! empty-value handling, round-trip annotation symmetry, empty-value vs
//! absent-line annotation contract, `runsvc_integrity` recreate when annotation
//! missing, and `recreate_reasons` type-level invariant. Migrated verbatim
//! from plan.rs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

// ---- caches classifier edge cases ---------------------------------
//
// These tests exercise the `caches` branch of
// `classify_recreate_reasons_from_annotations` directly (no
// plan_from integration) so each edge case is pinned in isolation.
// The branch lives at plan.rs's "caches change is in-place per
// design Part 3" block — annotation-side `discovered.caches:
// Option<Vec<String>>` vs spec-side `desired.caches:
// Vec<EffectiveCacheBinding>`.
//
// Set-semantic contract: the plan classifier sorts both sides
// before comparison so its FieldChange firing semantics match
// apply.rs's BTreeSet diff at execute_update_runner. A pure
// reorder (set-equal) is silent on both sides; any element
// add/remove surfaces a FieldChange in plan output AND
// triggers a per-runner drop-in body rewrite + unit cycle at
// apply time.

/// Helper: build an `EffectiveRunnerSpec` whose `caches` is a list
/// of bindings with the given names. All other fields use
/// minimal-runner defaults via `spec_with_url` + `merge_defaults`,
/// then `caches` is overwritten with synthesized
/// `EffectiveCacheBinding`s (the classifier only reads
/// `binding.name`, so `kinds/size/mode/trust_zone` are arbitrary).
fn spec_with_cache_names(names: &[&str]) -> EffectiveRunnerSpec {
    let mut spec = spec_with_url("a", "https://github.com/example/repo");
    spec.caches = names
        .iter()
        .map(|n| EffectiveCacheBinding {
            name: (*n).to_owned(),
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
        })
        .collect();
    spec
}

/// Helper: build a `DiscoveredAnnotations` with caches set to the
/// given list (Some) or unset (None for the post-upgrade fixture).
/// All other fields default; the classifier reads each branch
/// independently so this isolates the caches comparison.
fn anns_with_caches(caches: Option<&[&str]>) -> DiscoveredAnnotations {
    DiscoveredAnnotations {
        caches: caches.map(|s| s.iter().map(|c| (*c).to_owned()).collect()),
        ..DiscoveredAnnotations::default()
    }
}

/// Edge case 1: discovered.caches = None (older runner that
/// predates the unconditional X-Ghars-Caches emit). Classifier
/// MUST skip the caches comparison entirely so no spurious
/// `FieldChange` and no recreate reason fire — the post-upgrade
/// runner's first plan/apply lands the annotation and a future
/// edit can reconcile from there.
#[test]
fn classify_caches_none_annotation_skips_diff() {
    let anns = anns_with_caches(None);
    let desired = spec_with_cache_names(&["pool-a", "pool-b"]);
    let mut changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
    assert!(
        reasons.is_empty(),
        "no recreate reason on None; got {reasons:?}"
    );
    assert!(
        !changes.iter().any(|c| c.path == "caches"),
        "no caches FieldChange on None; got {changes:?}"
    );
}

/// Edge case 2: empty-on-both (discovered = Some(vec![]), desired
/// = empty Vec). Classifier MUST treat this as no-change — the
/// runner was registered with no cache pools and still has none.
#[test]
fn classify_caches_empty_both_sides_no_change() {
    let anns = anns_with_caches(Some(&[]));
    let desired = spec_with_cache_names(&[]);
    let mut changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
    assert!(reasons.is_empty(), "no recreate reason; got {reasons:?}");
    assert!(
        !changes.iter().any(|c| c.path == "caches"),
        "no caches FieldChange on empty=empty; got {changes:?}"
    );
}

/// Edge case 3: same single-element list (discovered =
/// Some(["pool-a"]), desired = ["pool-a"]). Classifier MUST be
/// silent — the membership set is unchanged.
#[test]
fn classify_caches_same_single_element_no_change() {
    let anns = anns_with_caches(Some(&["pool-a"]));
    let desired = spec_with_cache_names(&["pool-a"]);
    let mut changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
    assert!(reasons.is_empty(), "no recreate reason; got {reasons:?}");
    assert!(
        !changes.iter().any(|c| c.path == "caches"),
        "no caches FieldChange on same single-element; got {changes:?}"
    );
}

/// Edge case 4 (set-semantic contract): same multi-element
/// list in DIFFERENT order (discovered = ["a", "b"], desired =
/// ["b", "a"]). Classifier MUST be silent — apply.rs uses
/// `BTreeSet` semantics and would do nothing, so plan output must
/// agree. This pins the sort-then-compare contract.
#[test]
fn classify_caches_reorder_is_silent() {
    let anns = anns_with_caches(Some(&["pool-a", "pool-b"]));
    let desired = spec_with_cache_names(&["pool-b", "pool-a"]);
    let mut changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
    assert!(reasons.is_empty(), "no recreate reason; got {reasons:?}");
    assert!(
        !changes.iter().any(|c| c.path == "caches"),
        "reorder is set-equal ⇒ no FieldChange; got {changes:?}"
    );
}

/// Edge case 5: caches grows from N to N+1 elements. Classifier
/// MUST record a `FieldChange` with both sides rendered in sorted
/// order (the canonical form apply will execute against).
#[test]
fn classify_caches_grow_emits_field_change_sorted() {
    let anns = anns_with_caches(Some(&["pool-b"]));
    let desired = spec_with_cache_names(&["pool-a", "pool-b"]);
    let mut changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
    assert!(reasons.is_empty(), "grow is in-place; got {reasons:?}");
    let caches_change = changes
        .iter()
        .find(|c| c.path == "caches")
        .expect("grow must record caches FieldChange");
    // Both sides sorted: before is just ["pool-b"], after is
    // ["pool-a","pool-b"] (sorted, not insertion-order).
    assert_eq!(
        caches_change.before,
        FieldValue::List(vec!["pool-b".into()])
    );
    assert_eq!(
        caches_change.after,
        FieldValue::List(vec!["pool-a".into(), "pool-b".into()])
    );
}

/// Edge case 6: caches shrinks from N to N-1 elements. Symmetric
/// to grow — `FieldChange` recorded, sides sorted.
#[test]
fn classify_caches_shrink_emits_field_change_sorted() {
    let anns = anns_with_caches(Some(&["pool-b", "pool-a"]));
    let desired = spec_with_cache_names(&["pool-b"]);
    let mut changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
    assert!(reasons.is_empty(), "shrink is in-place; got {reasons:?}");
    let caches_change = changes
        .iter()
        .find(|c| c.path == "caches")
        .expect("shrink must record caches FieldChange");
    // before sorted from input ["pool-b","pool-a"] → ["pool-a","pool-b"]
    assert_eq!(
        caches_change.before,
        FieldValue::List(vec!["pool-a".into(), "pool-b".into()])
    );
    assert_eq!(caches_change.after, FieldValue::List(vec!["pool-b".into()]));
}

/// Edge case 7: multi-element replacement (different sets of same
/// size). Classifier records `FieldChange`; both sides sorted.
#[test]
fn classify_caches_multi_element_replacement_sorted() {
    let anns = anns_with_caches(Some(&["pool-c", "pool-a"]));
    let desired = spec_with_cache_names(&["pool-d", "pool-b"]);
    let mut changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
    assert!(
        reasons.is_empty(),
        "replacement is in-place; got {reasons:?}"
    );
    let caches_change = changes
        .iter()
        .find(|c| c.path == "caches")
        .expect("replacement must record caches FieldChange");
    assert_eq!(
        caches_change.before,
        FieldValue::List(vec!["pool-a".into(), "pool-c".into()])
    );
    assert_eq!(
        caches_change.after,
        FieldValue::List(vec!["pool-b".into(), "pool-d".into()])
    );
}

// ---- labels classifier edge cases (parity with caches) ------------
//
// These tests exercise the `labels` branch of
// `classify_recreate_reasons_from_annotations` directly. Labels are
// set-semantic for GitHub Actions registration (workflow `runs-on:`
// matches the registered label set order-independently), so the
// classifier sorts BOTH sides before comparison — a pure reorder
// must not surface as a `labels` recreate reason / FieldChange.

/// Helper: build a `DiscoveredAnnotations` with labels set to the
/// given list (Some) or unset (None for the post-upgrade fixture).
/// All other fields default; the classifier reads each branch
/// independently so this isolates the labels comparison.
fn anns_with_labels(labels: Option<&[&str]>) -> DiscoveredAnnotations {
    DiscoveredAnnotations {
        labels: labels.map(|s| s.iter().map(|c| (*c).to_owned()).collect()),
        ..DiscoveredAnnotations::default()
    }
}

/// Helper: build an `EffectiveRunnerSpec` whose `labels` is the
/// given list. `spec_with_url` invokes `merge_defaults`, which
/// already sorts labels — but the helper accepts a Vec the caller
/// has set explicitly so tests can control the ordering at the
/// pre-classifier boundary. Mirrors `spec_with_cache_names` for
/// the caches edge cases above.
fn spec_with_label_names(names: &[&str]) -> EffectiveRunnerSpec {
    let mut spec = spec_with_url("a", "https://github.com/example/repo");
    spec.labels = names.iter().map(|n| (*n).to_owned()).collect();
    spec
}

/// Pure reorder (discovered = ["beta","alpha"], desired = ["alpha","beta"])
/// MUST be silent. Mirrors `classify_caches_reorder_is_silent` —
/// labels share the set-semantic treatment per the comment block
/// above the labels branch in `classify_recreate_reasons_from_annotations`.
/// A regression that drops the sort on either side would surface
/// here as a spurious `labels` reason + `FieldChange`.
#[test]
fn classify_labels_reorder_is_silent() {
    let anns = anns_with_labels(Some(&["beta", "alpha"]));
    let desired = spec_with_label_names(&["alpha", "beta"]);
    let mut changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
    assert!(
        !reasons.contains(&"labels"),
        "reorder is set-equal ⇒ no labels recreate reason; got {reasons:?}"
    );
    assert!(
        !changes.iter().any(|c| c.path == "labels"),
        "reorder is set-equal ⇒ no FieldChange; got {changes:?}"
    );
}

/// Grow from N to N+1 labels. Membership change MUST surface as a
/// `FieldChange` with both before/after rendered in sorted order
/// (the canonical form GitHub will see at registration time).
/// Symmetric with `classify_caches_grow_emits_field_change_sorted`.
#[test]
fn classify_labels_grow_emits_field_change_sorted() {
    let anns = anns_with_labels(Some(&["a"]));
    let desired = spec_with_label_names(&["b", "a"]);
    let mut changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
    // Labels are recreate-class per the classifier — record the
    // typed reason AND the FieldChange.
    assert!(
        reasons.contains(&"labels"),
        "grow must record `labels` recreate reason; got {reasons:?}"
    );
    let labels_change = changes
        .iter()
        .find(|c| c.path == "labels")
        .expect("grow must record labels FieldChange");
    // Both sides sorted: before is ["a"]; after is ["a","b"]
    // (sorted, NOT desired's insertion order ["b","a"]).
    assert_eq!(labels_change.before, FieldValue::List(vec!["a".into()]));
    assert_eq!(
        labels_change.after,
        FieldValue::List(vec!["a".into(), "b".into()])
    );
}

/// `discovered.labels = None` (pre-upgrade runner that predates the
/// X-Ghars-Labels emit, or a runner whose 00-ghars.conf was
/// hand-edited to drop the line). Classifier MUST skip the labels
/// comparison — comparing None against any desired Vec would
/// falsely fire on the first apply post-upgrade. Mirrors
/// `classify_caches_none_annotation_skips_diff`.
#[test]
fn classify_labels_none_annotation_skips() {
    let anns = anns_with_labels(None);
    let desired = spec_with_label_names(&["a", "b"]);
    let mut changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
    assert!(
        !reasons.contains(&"labels"),
        "None annotation must skip labels comparison; got {reasons:?}"
    );
    assert!(
        !changes.iter().any(|c| c.path == "labels"),
        "None annotation must NOT emit labels FieldChange; got {changes:?}"
    );
}

// ---- delta.before_caches sort site --------------------------------

/// `RunnerDelta.before_caches` is sorted at the population site in
/// `plan_from`'s intersection branch so operator-facing surfaces
/// (--diff output, plan JSON, error messages naming "removed
/// pools") see canonical alphabetical order regardless of the
/// order the on-disk `X-Ghars-Caches=` annotation happened to be
/// written in. Drive `plan_from` end-to-end with a discovered
/// annotation in non-canonical order; assert the populated
/// `delta.before_caches` is sorted. A regression that drops the
/// sort would surface here as Vec equality against the unsorted
/// input order.
#[test]
fn delta_before_caches_is_sorted_for_display() {
    // Strategy: synthesize an old EffectiveRunnerSpec with caches
    // ["pool-a","pool-m","pool-z"] (canonical order so render
    // produces a clean drop-in body), then overwrite the
    // X-Ghars-Caches annotation in the discovered drop-in with a
    // non-canonical order (`pool-z,pool-a,pool-m`). The
    // intersection branch in plan_from reads this annotation and
    // populates `delta.before_caches` after `sort_unstable()` at
    // the population site. New desired spec adds a `pool-new`
    // cache, forcing an UpdateRunner whose `before_caches` we
    // inspect.
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec![
            "pool-a".into(),
            "pool-m".into(),
            "pool-new".into(),
            "pool-z".into(),
        ];
        r
    }]);
    // Inject the cache pool definitions so lower_to_effective can
    // resolve the bindings. ccache (not sccache) — the
    // multi-sccache-pool-per-runner gate in lower_to_effective
    // would reject 4 sccache pools, but ccache pools have no
    // single-valued env to clobber and freely compose.
    for name in ["pool-a", "pool-m", "pool-new", "pool-z"] {
        cfg.cache_pools.insert(
            name.into(),
            crate::config::CachePoolSpec {
                kinds: vec![CacheKind::Ccache],
                size: "5G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
            },
        );
    }
    // Old runner had only 3 caches (no pool-new) so the desired
    // diff is "grow by one new pool" — in-place UpdateRunner.
    let mut old_runner = cfg.runners[0].clone();
    old_runner.caches.retain(|n| n != "pool-new");
    let old_bindings: Vec<EffectiveCacheBinding> = ["pool-a", "pool-m", "pool-z"]
        .iter()
        .map(|n| EffectiveCacheBinding {
            name: (*n).into(),
            kinds: vec![CacheKind::Ccache],
            size: "5G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
        })
        .collect();
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        old_bindings,
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    // Build a discovered runner whose 00-ghars.conf body lists the
    // caches in non-canonical order. parse-side accepts whatever
    // is on disk; the sort happens at the population site.
    let mut discovered = discovered_for("a", &old_spec, Drift::InSync);
    let body = discovered
        .drop_ins
        .get("00-ghars.conf")
        .expect("renderer always emits 00-ghars.conf")
        .clone();
    let new_body = body
        .lines()
        .map(|line| {
            if line.starts_with("X-Ghars-Caches=") {
                "X-Ghars-Caches=pool-z,pool-a,pool-m".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    discovered.drop_ins.insert("00-ghars.conf".into(), new_body);

    let mut actual = empty_actual();
    actual.runners.insert("a".into(), discovered);
    let plan = plan_from(&cfg, &actual, &empty_paths()).expect("plan must succeed");
    let delta = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("caches grow must emit UpdateRunner");
    let before = delta
        .before_caches
        .as_ref()
        .expect("intersection branch must populate before_caches");
    // Sorted (alphabetical), NOT the on-disk order ["pool-z","pool-a","pool-m"].
    assert_eq!(
        before,
        &vec![
            "pool-a".to_string(),
            "pool-m".to_string(),
            "pool-z".to_string()
        ],
        "before_caches must be sorted; got: {before:?}"
    );
}

// ---- C-6 regression — operator 99-*.conf masks recreate -----------

/// C-6 invariant: the `any_drop_in_modified` filter in
/// `plan_from`'s intersection branch (the closure that filters
/// `MANAGED_DROP_IN_BASENAMES` against
/// `Created|Modified|Removed`) must NOT count an operator-added
/// unmanaged drop-in (e.g. 99-tuning.conf) as in-place evidence —
/// it must NOT mask a co-occurring recreate-class change.
///
/// Setup: discovered runner has 99-tuning.conf in `drop_ins` +
/// `Drift::DropInsModified(["99-tuning.conf"])`. Desired spec
/// changes `runner_sha256`. Result: recreate must fire with the typed
/// `runner_sha256` reason (Stage 1 annotation detection),
/// NOT silently fall through to in-place.
#[test]
fn plan_recreate_on_runner_sha256_change_with_operator_drop_in() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.runner_sha256 = Some("a".repeat(64));
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.runner_sha256 = Some("b".repeat(64));
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut discovered = discovered_for(
        "a",
        &old_spec,
        Drift::DropInsModified(vec!["99-tuning.conf".into()]),
    );
    // Inject the operator drop-in body into the discovered drop_ins
    // map. Without this, the in-place classifier's drop-in body
    // diff would not see 99-tuning.conf at all and the test would
    // pass for the wrong reason. `discover` (via `read_drop_ins`)
    // reads every *.conf in the runner drop-in dir, so the
    // discovered drop_ins must include the unmanaged file.
    discovered
        .drop_ins
        .insert("99-tuning.conf".into(), "[Service]\nNice=-5\n".into());
    let mut actual = empty_actual();
    actual.runners.insert("a".into(), discovered);
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("runner_sha256 change must emit UpdateRunner");
    assert!(
        upd.requires_recreate,
        "runner_sha256 change must recreate even with operator drop-in present; \
         got reasons {:?}",
        upd.recreate_reasons
    );
    assert!(
        upd.recreate_reasons.contains(&"runner_sha256"),
        "C-6 invariant: operator drop-in must NOT mask the \
         recreate, AND runner_sha256 is Stage 1 detectable; expected \
         typed `runner_sha256` reason, got {:?}",
        upd.recreate_reasons
    );
}

// ---- trust_zone in-place contract ---------------------------------

/// `trust_zone` is in `EffectiveRunnerSpec` `spec_hash` but has no
/// runner-unit body dependency once cache-pool cross-references
/// validate at config-load time. A trust_zone-only edit must be
/// in-place: `FieldChange` recorded, no recreate reason, no
/// `uncovered` fallback (gated on `field_changes.is_empty()`).
#[test]
fn plan_update_runner_trust_zone_change_is_in_place_with_field_change() {
    // Two trust zones; the runner moves from `default` → `audited`.
    // No cache_pool references — trust_zone validation only kicks
    // in when the runner's caches list is non-empty (the
    // cache-resolution loop in lower_to_effective only enforces
    // pool.trust_zone == runner_zone for declared caches). With
    // caches=[] both zones are valid for the runner; the
    // classifier's job is to detect the zone string change in
    // X-Ghars-Trust-Zone and report it as in-place.
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.trust_zone = "audited".into();
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.trust_zone = "default".into();
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("trust_zone change must emit UpdateRunner");
    assert!(
        !upd.requires_recreate,
        "trust_zone change must be in-place; got reasons {:?}",
        upd.recreate_reasons
    );
    assert!(
        !upd.recreate_reasons.contains(&"uncovered"),
        "trust_zone change must NOT trip uncovered fallback; got reasons {:?}",
        upd.recreate_reasons
    );
    let tz_change = upd
        .field_changes
        .iter()
        .find(|fc| fc.path == "trust_zone")
        .expect("field_changes must include trust_zone entry");
    assert_eq!(tz_change.before, FieldValue::String("default".into()));
    assert_eq!(tz_change.after, FieldValue::String("audited".into()));
}

/// Pin that `lower_to_effective` still rejects a runner whose
/// declared `trust_zone` doesn't match a referenced
/// `cache_pool`'s `trust_zone`, REGARDLESS of the `trust_zone`
/// annotation's in-place classification. The validation lives at
/// `plan.rs::lower_to_effective` (around the cache resolution
/// loop) and runs BEFORE the classifier ever sees the spec —
/// so a cross-zone reference is a config-load error, not an
/// in-place update.
#[test]
fn plan_validates_trust_zone_mismatch_with_referenced_cache_pool() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec!["pool".into()];
        r.trust_zone = "audited".into();
        r
    }]);
    cfg.cache_pools.insert(
        "pool".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
        },
    );
    let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("trust_zone"), "got: {msg}");
    assert!(msg.contains("audited"), "got: {msg}");
    assert!(msg.contains("default"), "got: {msg}");
}

// ---- network mode recreate contract -------------------------------

/// Open→Netns transition MUST recreate. The in-place rewrite path
/// would write 40-network.conf with `NetworkNamespacePath`= but
/// leave the ghars-net@INSTANCE side-units / netns / nft rules
/// missing, which fail-closes the unit at restart. Recreate
/// (`execute_remove_runner` + `execute_create_runner`) calls
/// `provision_netns_artifacts` so all side-units land before the
/// runner starts.
#[test]
fn plan_update_recreate_on_network_mode_open_to_netns() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.network = Some("isolated".into());
        r
    }]);
    cfg.networks.insert(
        "isolated".into(),
        NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            address_families: vec![],
            dns: crate::config::DnsMode::Forward,
            ipv6: crate::config::Ipv6Mode::Disabled,
        },
    );
    // Discovered side: Open mode (no network binding).
    let old_runner = minimal_runner("a"); // network=None ⇒ Open
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("Open→Netns must emit UpdateRunner");
    assert!(
        upd.requires_recreate,
        "Open→Netns must recreate (provision_netns_artifacts only \
         runs on the recreate path); got reasons {:?}",
        upd.recreate_reasons
    );
    assert!(
        upd.recreate_reasons.contains(&"network"),
        "expected typed `network` recreate reason; got: {:?}",
        upd.recreate_reasons
    );
    let mode_change = upd
        .field_changes
        .iter()
        .find(|fc| fc.path == "network")
        .expect("field_changes must include network entry");
    assert_eq!(mode_change.before, FieldValue::String("open".into()));
    assert_eq!(mode_change.after, FieldValue::String("netns".into()));
}

/// Netns→Open transition MUST recreate. Without recreate the
/// in-place rewrite would remove 40-network.conf cleanly but
/// leave ghars-net@INSTANCE active + nft files + the netns
/// itself orphaned on the host. The recreate path's
/// `execute_remove_runner` runs `teardown_netns_artifacts`.
#[test]
fn plan_update_recreate_on_network_mode_netns_to_open() {
    let cfg = config_with_runners(vec![minimal_runner("a")]); // network=None ⇒ Open
    // Discovered side: Netns mode.
    let mut old_runner = minimal_runner("a");
    old_runner.network = Some("isolated".into());
    let netns_spec = NetworkSpec {
        mode: NetworkMode::Netns,
        allowed_egress: vec![],
        ip_allow: vec![],
        ip_deny: vec![],
        address_families: vec![],
        dns: crate::config::DnsMode::Forward,
        ipv6: crate::config::Ipv6Mode::Disabled,
    };
    let netns_binding = EffectiveNetworkBinding {
        name: "isolated".into(),
        spec: netns_spec,
        subnet: ipnet::IpNet::V4(
            ipnet::Ipv4Net::new(std::net::Ipv4Addr::new(10, 200, 0, 0), 30).unwrap(),
        ),
    };
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        Some(netns_binding),
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("Netns→Open must emit UpdateRunner");
    assert!(
        upd.requires_recreate,
        "Netns→Open must recreate (teardown_netns_artifacts only \
         runs on the recreate path); got reasons {:?}",
        upd.recreate_reasons
    );
    assert!(
        upd.recreate_reasons.contains(&"network"),
        "expected typed `network` recreate reason; got: {:?}",
        upd.recreate_reasons
    );
    let mode_change = upd
        .field_changes
        .iter()
        .find(|fc| fc.path == "network")
        .expect("field_changes must include network entry");
    assert_eq!(mode_change.before, FieldValue::String("netns".into()));
    assert_eq!(mode_change.after, FieldValue::String("open".into()));
}

// ---- missing-annotation tolerance + empty-value handling ---------

/// When the discovered unit has no X-Ghars-Runner-Sha256 line at
/// all and the desired spec ALSO has no `runner_sha256` set, the
/// missing-on-both-sides shape does not perturb `spec_hash` — both
/// sides hash the same `None` — so the planner produces a `NoOp`
/// (the classifier never runs for `NoOp` paths). The test asserts
/// no `UpdateRunner` action is emitted, pinning that the empty-
/// vs-empty case stays in-sync rather than spuriously firing
/// recreate.
#[test]
fn plan_update_runner_sha256_none_on_both_sides_does_not_recreate() {
    // Both sides leave runner_sha256 unset. With no other diff
    // and matching specs this is an in-sync NoOp; we just verify
    // no spurious recreate reason fires.
    let cfg = config_with_runners(vec![minimal_runner("a")]);
    let runner = cfg.runners[0].clone();
    let mut spec = merge_defaults(
        &runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    spec.spec_hash = spec_hash(&spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &spec, Drift::InSync));
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    // Should be a NoOp (no Update at all).
    let any_update = plan
        .actions
        .iter()
        .any(|a| matches!(a, Action::UpdateRunner(_)));
    assert!(
        !any_update,
        "matching None-on-both-sides must produce NoOp, not UpdateRunner"
    );
}

/// When the discovered unit predates the X-Ghars-Runner-Sha256
/// annotation (no annotation emitted) but the desired spec sets
/// a value, Stage
/// 1 SKIPS the comparison (annotation == None). The `spec_hash`
/// mismatch propagates the change once via the recreate-class
/// `runner_sha256` reason emitted on the next apply (after the
/// fresh annotation lands). The point of this test: don't
/// false-fire a comparison "None != desired" that would surface
/// as misleading FieldChange{before: "", after: "..."}.
#[test]
fn plan_runner_sha256_missing_annotation_skips_classification() {
    // Build a discovered drop-in body WITHOUT the Runner-Sha256
    // annotation. The classifier reads from
    // discovered.drop_ins["00-ghars.conf"] (see
    // DiscoveredAnnotations::from_discovered /
    // from_drop_in_body), so we hand-craft the body and call
    // from_drop_in_body directly rather than going through
    // discovered_for.
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.runner_sha256 = Some("a".repeat(64));
        r
    }]);
    let mut desired_spec = merge_defaults(
        &cfg.runners[0],
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    desired_spec.spec_hash = spec_hash(&desired_spec);

    // Discovered drop-in body omits X-Ghars-Runner-Sha256 entirely;
    // every other annotation matches the desired spec so Stage 1
    // sees no recreate-class diff except the missing-on-both-
    // sides skip we are testing. This synthesises the same shape
    // `crate::systemd::render_identity` would write into
    // `00-ghars.conf` MINUS the `X-Ghars-Runner-Sha256` line.
    let arch_str = "x86_64";
    let drop_in_body = format!(
        "[Unit]\nX-Ghars-Runner-Url={url}\n\
         X-Ghars-Auth-Name=pat\nX-Ghars-Labels=a\n\
         X-Ghars-Arch={arch_str}\n\
         X-Ghars-Effective-Version=\n\
         X-Ghars-Trust-Zone=default\nX-Ghars-Network-Mode=open\n",
        url = desired_spec.url,
    );
    let annotations = DiscoveredAnnotations::from_drop_in_body(&drop_in_body);
    // Sanity: the parser sees no Runner-Sha256.
    assert!(
        annotations.runner_sha256.is_none(),
        "missing line must yield None (skip), not Some(\"\")"
    );
    let mut field_changes = Vec::new();
    let reasons =
        classify_recreate_reasons_from_annotations(&annotations, &desired_spec, &mut field_changes);
    assert!(
        !reasons.contains(&"runner_sha256"),
        "Stage 1 must skip when annotation is None (post-upgrade tolerance); \
         got reasons {reasons:?}"
    );
    assert!(
        !field_changes.iter().any(|c| c.path == "runner_sha256"),
        "no FieldChange should fire on None-side comparison; got: {field_changes:?}"
    );
}

// ---- round-trip annotation symmetry -------------------------------

/// `render_identity` ↔ `DiscoveredAnnotations::from_drop_in_body`
/// round-trip for the production-emitted annotation fields.
/// We render a spec via `render_runner_unit`, parse the resulting
/// 00-ghars.conf body, and assert each annotation flows back
/// into the right field. Catches mutants on either side that
/// spell the key wrong or encode the value differently.
///
/// Coverage: url, `auth_name`, `runner_version`, labels, arch,
/// `runner_sha256`, `runner_tarball_hash`, `trust_zone`,
/// `network_mode`, caches. The spec is built with non-default values
/// for every field so a single mismatch surfaces as a per-field
/// assertion failure rather than a spec_hash-derived
/// false-positive.
#[test]
fn discovered_annotations_round_trip_for_all_fields() {
    let cache_bindings = vec![
        EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "audited".into(),
        },
        EffectiveCacheBinding {
            name: "rust".into(),
            kinds: vec![CacheKind::Sccache],
            size: "5G".into(),
            mode: CacheMode::Shared,
            trust_zone: "audited".into(),
        },
    ];
    let mut spec = merge_defaults(
        &{
            let mut r = minimal_runner("rt");
            // url (default: "https://github.com/example/rt") is
            // exercised by the round-trip; keep the default.
            // auth_name = "pat" (default).
            r.labels = vec!["self-hosted".into(), "linux".into()];
            r.runner_version = Some("v2.999.0".into());
            r.arch = Some(Arch::Aarch64);
            r.runner_sha256 = Some("c".repeat(64));
            r.runner_tarball = Some(Utf8PathBuf::from("/var/lib/ghars/rt.tar.gz"));
            r.trust_zone = "audited".into();
            r.caches = vec!["build".into(), "rust".into()];
            r
        },
        &Defaults::default(),
        "pat".into(),
        cache_bindings,
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    spec.spec_hash = spec_hash(&spec);
    let rendered = crate::systemd::render_runner_unit(&spec).unwrap();
    let body = rendered
        .drop_ins
        .get("00-ghars.conf")
        .expect("00-ghars.conf");
    let anns = DiscoveredAnnotations::from_drop_in_body(body);

    assert_eq!(
        anns.url.as_deref(),
        Some("https://github.com/example/rt"),
        "Runner-Url round-trip"
    );
    assert_eq!(
        anns.auth_name.as_deref(),
        Some("pat"),
        "Auth-Name round-trip"
    );
    assert_eq!(
        anns.runner_version.as_deref(),
        Some("v2.999.0"),
        "Effective-Version round-trip"
    );
    // Labels are set-semantic, sorted by `merge_defaults` before
    // emission, so the round-trip surfaces them in canonical
    // alphabetical order regardless of the operator's input
    // order.
    assert_eq!(
        anns.labels.as_deref(),
        Some(&["linux".to_owned(), "self-hosted".to_owned()][..]),
        "Labels round-trip (comma-joined → split, canonically sorted)"
    );
    assert_eq!(anns.arch.as_deref(), Some("aarch64"), "Arch round-trip");
    assert_eq!(
        anns.runner_sha256.as_deref(),
        Some(&*"c".repeat(64)),
        "Runner-Sha256 round-trip"
    );
    // Tarball annotation is the SHA256 of the path string, not
    // the path itself.
    let expected_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"/var/lib/ghars/rt.tar.gz");
        format!("sha256:{}", hex::encode(h.finalize()))
    };
    assert_eq!(
        anns.runner_tarball_hash.as_deref(),
        Some(expected_hash.as_str()),
        "Runner-Tarball-Hash round-trip"
    );
    assert_eq!(
        anns.trust_zone.as_deref(),
        Some("audited"),
        "Trust-Zone round-trip"
    );
    assert_eq!(
        anns.network_mode.as_deref(),
        Some("open"),
        "Network-Mode round-trip (no [network] → \"open\")"
    );
    assert_eq!(
        anns.caches.as_deref(),
        Some(&["build".to_owned(), "rust".to_owned()][..]),
        "Caches round-trip (comma-joined → split)"
    );
}

// ---- empty-value vs absent-line annotation contract --------------

/// Pin the contract `from_drop_in_body` honors for every
/// annotation field whose semantics differ between
/// "key absent" and "key present with empty value":
///
/// - `X-Ghars-Caches=` (empty) ⇒ `caches = Some(vec![])`
///   (operator registered the runner with NO cache pools — the
///   apply.rs cache-pool diff runs and the rendered drop-in
///   carries an empty pool list).
/// - `X-Ghars-Caches` line absent ⇒ `caches = None`
///   ("unknown" — the runner predates the unconditional-emit
///   change in `render_identity`; apply.rs SKIPS the diff
///   rendering to avoid spurious "removed: …" detail strings).
/// - Symmetric for `X-Ghars-Labels`.
///
/// The state.rs `extract_x_ghars_value` tests at
/// `extract_x_ghars_value_returns_some_empty_for_empty_value` and
/// `extract_x_ghars_value_returns_none_for_absent_key` pin the
/// helper-layer contract. This test pins the SAME contract one
/// layer up where the bulk consumer (`extract_x_ghars` in
/// `from_drop_in_body`) actually drives behavior — without it a
/// future refactor that switches the bulk consumer to
/// `unwrap_or_default()` (collapsing absent into "empty") would
/// silently flip the apply-time semantics for the absent case
/// without breaking any helper-level test.
#[test]
fn from_drop_in_body_distinguishes_empty_value_from_absent_line() {
    // Body 1: BOTH lines present, BOTH empty values. This is the
    // shape `render_identity` emits for `spec.caches.is_empty()` /
    // `spec.labels.is_empty()` — the renderer always emits the
    // line so absent indicates a runner that predates the
    // unconditional-emit change.
    let empty_value_body = "[Unit]\n\
                            X-Ghars-Managed=true\n\
                            X-Ghars-Caches=\n\
                            X-Ghars-Labels=\n";
    let anns = DiscoveredAnnotations::from_drop_in_body(empty_value_body);
    assert_eq!(
        anns.caches.as_deref(),
        Some(&[][..]),
        "X-Ghars-Caches= (empty value) must yield Some(vec![]); got {:?}",
        anns.caches,
    );
    assert_eq!(
        anns.labels.as_deref(),
        Some(&[][..]),
        "X-Ghars-Labels= (empty value) must yield Some(vec![]); got {:?}",
        anns.labels,
    );

    // Body 2: NEITHER line present (legacy 00-ghars.conf rendered
    // before `render_identity` started emitting Caches /
    // Labels unconditionally). Both fields must stay `None` so
    // apply.rs gates know not to drive a diff.
    let absent_line_body = "[Unit]\n\
                            X-Ghars-Managed=true\n";
    let anns = DiscoveredAnnotations::from_drop_in_body(absent_line_body);
    assert!(
        anns.caches.is_none(),
        "absent X-Ghars-Caches line must yield None; got {:?}",
        anns.caches,
    );
    assert!(
        anns.labels.is_none(),
        "absent X-Ghars-Labels line must yield None; got {:?}",
        anns.labels,
    );
}

/// Parse-time sort pin for `from_drop_in_body`. The
/// `X-Ghars-Labels=` and `X-Ghars-Caches=` annotation values are
/// CSV-joined at render time but set-semantic at the apply layer
/// (GitHub matches labels order-independently; cache-pool
/// bindings are unordered — the rendered drop-in body sorts pool
/// names alphabetically). Sorting at the parse boundary makes
/// the classifier's sort and the renderer's sort defense-in-depth
/// rather than load-bearing.
///
/// Feeds an unsorted CSV to `from_drop_in_body` for both fields and
/// asserts both `caches` and `labels` Vec come out sorted by
/// byte-wise Ord (matches the `sort_unstable` + ASCII-only charset
/// invariant validators enforce). A regression that drops the
/// sort at the parse boundary (e.g. a refactor that bypasses
/// `from_drop_in_body` and round-trips through `extract_x_ghars`
/// directly) would surface here.
#[test]
fn from_drop_in_body_sorts_labels_and_caches_at_parse_time() {
    // Unsorted-on-the-wire body: operator may have been registered
    // with these comma-orders, or a pre-canonicalization renderer
    // may have written them. Either way, the parse boundary must
    // deliver them sorted.
    let body = "[Unit]\n\
                X-Ghars-Managed=true\n\
                X-Ghars-Labels=zeta,alpha,middle,beta\n\
                X-Ghars-Caches=ccache-pool,sccache-pool,build-pool\n";
    let anns = DiscoveredAnnotations::from_drop_in_body(body);
    assert_eq!(
        anns.labels.as_deref(),
        Some(
            &[
                "alpha".to_owned(),
                "beta".into(),
                "middle".into(),
                "zeta".into()
            ][..]
        ),
        "X-Ghars-Labels must be sorted at parse time; got {:?}",
        anns.labels,
    );
    assert_eq!(
        anns.caches.as_deref(),
        Some(
            &[
                "build-pool".to_owned(),
                "ccache-pool".into(),
                "sccache-pool".into()
            ][..]
        ),
        "X-Ghars-Caches must be sorted at parse time; got {:?}",
        anns.caches,
    );
}

// ---- runsvc_integrity recreate when annotation missing -----------

/// In-place class change (`memory_max` edit) on a discovered
/// runner whose 00-ghars.conf is missing X-Ghars-Runsvc-Sha256
/// MUST route to the recreate path with the `runsvc_integrity`
/// reason. Hashing runsvc.sh from disk would weaken SEC-02 (the
/// file lives in the runner-writable home and may be tampered);
/// recreate forces config.sh to mint a fresh trusted digest
/// under our control.
#[test]
fn plan_update_recreate_on_runsvc_integrity_when_annotation_missing() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.memory_max = Some("64G".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.memory_max = Some("32G".into());
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    // The default fixture injects a fake runsvc_sha256 digest so
    // every other in-place test stays in-place. Here we want to
    // exercise the MISSING-annotation path (older unit, or
    // operator-stripped). Rebuild the discovered runner by hand
    // so the 00-ghars.conf body has NO X-Ghars-Runsvc-Sha256
    // line — render_identity at systemd.rs only emits the line
    // when spec.runsvc_sha256 is non-empty, so feeding it the
    // empty original spec produces exactly the wire format we
    // want to test.
    let mut discovered = discovered_for("a", &old_spec, Drift::InSync);
    let rendered_no_digest = crate::systemd::render_runner_unit(&old_spec).unwrap();
    discovered.drop_ins = rendered_no_digest.drop_ins;
    // Sanity: confirm the rebuilt fixture really did omit the digest.
    let body = discovered
        .drop_ins
        .get("00-ghars.conf")
        .expect("00-ghars.conf in fixture");
    assert!(
        !body.contains("X-Ghars-Runsvc-Sha256="),
        "fixture invariant: discovered 00-ghars.conf must omit the digest \
         line so the recovery path is exercised; got body:\n{body}"
    );
    let mut actual = empty_actual();
    actual.runners.insert("a".into(), discovered);
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("missing-digest in-place delta must emit UpdateRunner");
    assert!(
        upd.requires_recreate,
        "missing X-Ghars-Runsvc-Sha256 must force recreate (SEC-02); \
         got reasons {:?}",
        upd.recreate_reasons
    );
    assert!(
        upd.recreate_reasons.contains(&"runsvc_integrity"),
        "expected typed `runsvc_integrity` reason for missing-digest path; \
         got: {:?}",
        upd.recreate_reasons
    );
}

/// Pin that v1 consumers (which read
/// `field_changes[].before` / `field_changes[].after` as bare
/// scalar JSON values) fail predictably when reading the v2
/// tagged-object shape from `FieldValue::to_json`. The v2 JSON
/// for a String `FieldValue` is `{"type": "string", "value": "x"}`;
/// a v1 consumer doing `value.as_str()` returns `None` because
/// the outer value is an Object, not a String. Same predictable-
/// failure contract for List: v2 wraps in an Object, so a v1
/// `as_array()` returns `None`. This is the load-bearing schema-
/// version contract: a v1 consumer cannot silently misread a v2
/// payload — it must surface the type error so downstream tooling
/// knows to bump.
#[test]
fn field_value_to_json_v1_consumer_predictable_failure() {
    // String variant: v2 shape is an Object, NOT a bare string.
    let fv = FieldValue::String("https://example.com".into());
    let json = fv.to_json();
    // v1 consumer expectation: `as_str() -> Some(_)`. v2 reality:
    // `as_str() -> None`. Predictable failure — Object ≠ String.
    assert!(
        json.as_str().is_none(),
        "v2 FieldValue::String must render as JSON Object (NOT bare \
         string) so v1 consumers fail predictably via \
         `as_str() == None`; got: {json}",
    );
    // The Object IS structured the v2 way:
    assert!(json.is_object());
    assert_eq!(json["type"], "string");
    assert_eq!(json["value"], "https://example.com");

    // List variant: same predictable-failure contract.
    let fv = FieldValue::List(vec!["a".into(), "b".into()]);
    let json = fv.to_json();
    // v1 consumer expectation for a list-typed field could have
    // been `as_array() -> Some(_)` (raw JSON array). v2 wraps in
    // an Object, so `as_array() -> None`.
    assert!(
        json.as_array().is_none(),
        "v2 FieldValue::List must render as JSON Object (NOT bare \
         array) so v1 consumers fail predictably via \
         `as_array() == None`; got: {json}",
    );
    // The Object IS structured the v2 way:
    assert!(json.is_object());
    assert_eq!(json["type"], "list");
    assert!(json["values"].is_array());
    assert_eq!(json["values"][0], "a");
    assert_eq!(json["values"][1], "b");
}

// ---- recreate_reasons type-level invariant ----------------------
//
// The two tests below pin the invariants the type system does NOT
// enforce on `RunnerDelta`:
//   (1) `requires_recreate == true` ⇒ `!recreate_reasons.is_empty()`
//   (2) `requires_recreate == false` ⇒ `recreate_reasons.is_empty()`
//
// Both directions are load-bearing: the construction site at
// `plan_from` derives `requires_recreate` from
// `!recreate_reasons.is_empty()` (see the
// `let requires_recreate = !recreate_reasons.is_empty();` line),
// but a future refactor that splits that derivation could break the
// invariant silently. The CLI summary path
// (`cli.rs::plan_summary_value` → `summary.recreates`) and the
// operator-visible "(reasons)" tail in `render_action_line` both
// assume the invariant; recreating without a reason would produce
// empty parens in the operator output and an empty-string entry
// mid-list — confusing for triage.
//
// Each test drives every path that reaches `Action::UpdateRunner`
// through `plan_from` end-to-end (no synthetic delta construction),
// collects the resulting deltas, and asserts the invariant holds
// for every one. The (path, scenario) labels in assertion messages
// identify which scenario a future regression broke.
//
// The "uncovered" recreate reason — emitted by the spec_hash
// mismatch fallback at `plan_from` when neither Stage 1 nor Stage 2
// detect the change — is not exercised by any in-tree test
// scenario today; retained as defense-in-depth against future
// classifier gaps (see plan_from's spec_hash fallback). It is
// covered by the invariant by construction: the only site that
// pushes `"uncovered"` does so before `requires_recreate` is set
// from `!recreate_reasons.is_empty()`, so the Vec is non-empty
// whenever that branch fires. No direct scenario drives it here.

/// Drive every annotation-detected recreate-class path (url,
/// `runner_version`, labels, `runner_sha256`, `runner_tarball`, arch,
/// network) plus the `runsvc_integrity` guard through
/// `plan_from` end-to-end. For each scenario, assert that the
/// resulting `RunnerDelta` satisfies the invariant
/// `requires_recreate=true ⇒ !recreate_reasons.is_empty()` AND
/// pin the expected typed reason token so a regression that
/// drives recreate via a DIFFERENT classifier branch (e.g. arch
/// scenario silently routes through `uncovered` when host arch
/// happens to match `discovered_arch` on aarch64 CI) still fails
/// rather than passing for the wrong reason.
///
/// Runs each scenario with a fresh config + actual state pair so
/// scenarios don't interfere. The scenario label in each loop
/// iteration's assertion identifies which path failed.
#[test]
fn plan_invariant_recreate_implies_non_empty_reasons_across_all_field_classes() {
    // Helper: build (cfg, actual) for a desired-vs-discovered
    // scenario. The mutators take a fresh `RunnerSpec` named "a"
    // and modify the desired-side / discovered-side specs
    // independently so each scenario exercises exactly one
    // recreate path.
    type SpecMutate = fn(&mut RunnerSpec);
    type ConfigMutate = fn(&mut Config);

    struct Scenario {
        label: &'static str,
        // Apply to the desired-side runner spec (cfg.runners[0]).
        desired: SpecMutate,
        // Apply to the discovered-side runner spec used to
        // synthesize the on-disk fixture. None means "same as
        // minimal_runner default".
        discovered: Option<SpecMutate>,
        // Optional config-level mutation (for network specs). Runs
        // before the runner-level mutators so cross-references
        // resolve.
        cfg: Option<ConfigMutate>,
        // host_arch parameter for merge_defaults on the discovered
        // side. The desired side ALWAYS pins
        // `cfg.runners[0].arch = Some(Arch::X86_64)` so the host
        // arch never determines the desired side's classifier
        // input — without this, on aarch64 CI the host_arch fallback
        // would make the desired side land on Aarch64 and silently
        // match the discovered side for non-arch scenarios, hiding
        // bugs. The arch scenario uses `Arch::Aarch64` here to
        // exercise the arch recreate path.
        discovered_arch: Arch,
        // The typed recreate reason this scenario MUST surface.
        // Pinned per-scenario so the invariant test catches a
        // regression that drives recreate through the wrong
        // classifier branch (e.g. a scenario silently routing
        // through `uncovered` while still asserting non-empty
        // recreate_reasons).
        expected_reason: &'static str,
    }

    fn url_change(r: &mut RunnerSpec) {
        r.url = "https://github.com/example/desired-url".into();
    }
    fn url_old(r: &mut RunnerSpec) {
        r.url = "https://github.com/example/old-url".into();
    }
    fn version_new(r: &mut RunnerSpec) {
        r.runner_version = Some("2.300.0".into());
    }
    fn version_old(r: &mut RunnerSpec) {
        r.runner_version = Some("2.200.0".into());
    }
    fn labels_new(r: &mut RunnerSpec) {
        r.labels = vec!["beta".into()];
    }
    fn labels_old(r: &mut RunnerSpec) {
        r.labels = vec!["alpha".into()];
    }
    fn sha_new(r: &mut RunnerSpec) {
        r.runner_sha256 = Some("a".repeat(64));
    }
    fn sha_old(r: &mut RunnerSpec) {
        r.runner_sha256 = Some("b".repeat(64));
    }
    fn tarball_new(r: &mut RunnerSpec) {
        r.runner_tarball = Some(Utf8PathBuf::from("/var/lib/ghars/runner-desired.tar.gz"));
    }
    fn tarball_old(r: &mut RunnerSpec) {
        r.runner_tarball = Some(Utf8PathBuf::from("/var/lib/ghars/runner-discovered.tar.gz"));
    }
    fn network_isolated(r: &mut RunnerSpec) {
        r.network = Some("isolated".into());
    }
    fn add_isolated_netns(c: &mut Config) {
        c.networks.insert(
            "isolated".into(),
            NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                address_families: vec![],
                dns: crate::config::DnsMode::Forward,
                ipv6: crate::config::Ipv6Mode::Disabled,
            },
        );
    }

    let scenarios = vec![
        Scenario {
            label: "url",
            desired: url_change,
            discovered: Some(url_old),
            cfg: None,
            discovered_arch: Arch::X86_64,
            expected_reason: "url",
        },
        Scenario {
            label: "runner_version",
            desired: version_new,
            discovered: Some(version_old),
            cfg: None,
            discovered_arch: Arch::X86_64,
            expected_reason: "runner_version",
        },
        Scenario {
            label: "labels",
            desired: labels_new,
            discovered: Some(labels_old),
            cfg: None,
            discovered_arch: Arch::X86_64,
            expected_reason: "labels",
        },
        Scenario {
            label: "runner_sha256",
            desired: sha_new,
            discovered: Some(sha_old),
            cfg: None,
            discovered_arch: Arch::X86_64,
            expected_reason: "runner_sha256",
        },
        Scenario {
            label: "runner_tarball",
            desired: tarball_new,
            discovered: Some(tarball_old),
            cfg: None,
            discovered_arch: Arch::X86_64,
            expected_reason: "runner_tarball",
        },
        // arch: discovered side renders against Aarch64; desired
        // side pins X86_64 explicitly via cfg.runners[0].arch
        // (set in the loop body for ALL scenarios). The mismatch
        // fires the arch annotation-classifier branch.
        Scenario {
            label: "arch",
            desired: |_| {},
            discovered: None,
            cfg: None,
            discovered_arch: Arch::Aarch64,
            expected_reason: "arch",
        },
        Scenario {
            label: "network",
            desired: network_isolated,
            discovered: None,
            cfg: Some(add_isolated_netns),
            discovered_arch: Arch::X86_64,
            expected_reason: "network",
        },
    ];

    for scenario in &scenarios {
        // Build desired-side config (the "after" the operator
        // wants). Apply config-level mutator first so network
        // refs resolve, then runner-level desired mutator.
        let mut cfg = config_with_runners(vec![minimal_runner("a")]);
        if let Some(cfg_mut) = scenario.cfg {
            cfg_mut(&mut cfg);
        }
        (scenario.desired)(&mut cfg.runners[0]);
        // Pin desired arch to X86_64 EXPLICITLY for every scenario
        // (including non-arch ones). plan_from's lower_to_effective
        // resolves host_arch from RunnerSpec.arch ⇒ defaults.arch
        // ⇒ Arch::current() — without this pin, on aarch64 CI the
        // desired side would land on Aarch64 and accidentally
        // match the discovered side's Arch::X86_64 host_arch input,
        // making non-arch scenarios silently take the arch
        // recreate branch (8 of 9 scenarios passing for the wrong
        // reason). The arch scenario remains correct because its
        // discovered_arch is Aarch64 — the desired/discovered
        // mismatch is preserved.
        cfg.runners[0].arch = Some(Arch::X86_64);

        // Build discovered-side spec ("before" — what's on disk).
        // Start from minimal, apply discovered mutator if present.
        let mut discovered_runner = minimal_runner("a");
        if let Some(disc_mut) = scenario.discovered {
            disc_mut(&mut discovered_runner);
        }
        let mut old_spec = merge_defaults(
            &discovered_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            scenario.discovered_arch,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);

        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(
            updates.len(),
            1,
            "[{}] scenario must produce exactly 1 UpdateRunner; got {} actions: {:?}",
            scenario.label,
            plan.actions.len(),
            plan.actions
                .iter()
                .map(|a| format!("{a:?}"))
                .collect::<Vec<_>>(),
        );
        let upd = updates[0];
        assert!(
            upd.requires_recreate,
            "[{}] scenario must drive recreate-class UpdateRunner; got \
             requires_recreate=false with reasons {:?}",
            scenario.label, upd.recreate_reasons,
        );
        // The load-bearing invariant: requires_recreate=true MUST
        // imply non-empty recreate_reasons.
        assert!(
            !upd.recreate_reasons.is_empty(),
            "[{}] invariant violation: requires_recreate=true MUST imply \
             !recreate_reasons.is_empty(); empty Vec produces empty parens \
             in render_action_line and confuses operators triaging the \
             plan",
            scenario.label,
        );
        // Pin the typed recreate reason: the scenario must drive
        // recreate via the EXPECTED classifier branch, not via a
        // different one (e.g. silent `uncovered` fallback). Without
        // this pin, a host_arch leak on aarch64 CI could make
        // non-arch scenarios pass with `recreate_reasons = ["arch"]`
        // and still satisfy `!is_empty()` — false-positive coverage
        // for the field the scenario claims to test.
        assert!(
            upd.recreate_reasons.contains(&scenario.expected_reason),
            "[{}] scenario must surface typed `{}` recreate reason; got: {:?}",
            scenario.label,
            scenario.expected_reason,
            upd.recreate_reasons,
        );
    }

    // Bonus: runsvc_integrity recreate path. The fixture used by
    // the loop above injects a fake runsvc_sha256 so every
    // scenario stays in-place on that field. Drive the runsvc-
    // missing-annotation path explicitly to round out coverage of
    // every path that pushes a recreate reason.
    let upd = drive_runsvc_integrity_recreate();
    assert!(
        upd.requires_recreate,
        "[runsvc_integrity] scenario must drive recreate; got \
         requires_recreate=false with reasons {:?}",
        upd.recreate_reasons,
    );
    assert!(
        !upd.recreate_reasons.is_empty(),
        "[runsvc_integrity] invariant violation: requires_recreate=true \
         MUST imply !recreate_reasons.is_empty()",
    );
    assert!(
        upd.recreate_reasons.contains(&"runsvc_integrity"),
        "[runsvc_integrity] scenario must surface typed `runsvc_integrity` \
         recreate reason; got: {:?}",
        upd.recreate_reasons,
    );
}

/// Build a plan that drives the `runsvc_integrity` recreate path
/// (missing X-Ghars-Runsvc-Sha256 annotation in 00-ghars.conf)
/// and return the resulting `UpdateRunner` delta. Mirrors the
/// existing `plan_update_recreate_on_runsvc_integrity_when_annotation_missing`
/// fixture: `render_identity` at systemd.rs only emits the annotation
/// when `spec.runsvc_sha256` is non-empty; feeding the empty
/// original spec produces the wire format that triggers the
/// `runsvc_integrity` recreate guard.
fn drive_runsvc_integrity_recreate() -> RunnerDelta {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.memory_max = Some("64G".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.memory_max = Some("32G".into());
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut discovered = discovered_for("a", &old_spec, Drift::InSync);
    let rendered_no_digest = crate::systemd::render_runner_unit(&old_spec).unwrap();
    discovered.drop_ins = rendered_no_digest.drop_ins;
    let mut actual = empty_actual();
    actual.runners.insert("a".into(), discovered);
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    plan.actions
        .into_iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("[runsvc_integrity] missing-digest fixture must emit UpdateRunner")
}

/// Drive every in-place classifier path (`memory_max`, `auth_name`,
/// `trust_zone`, caches) through `plan_from` end-to-end. For each
/// scenario, assert the inverse invariant
/// `requires_recreate=false ⇒ recreate_reasons.is_empty()`.
///
/// The inverse direction is load-bearing too. A future regression
/// that pushed a recreate reason without flipping `requires_recreate`
/// (e.g. by hard-coding `requires_recreate=false` instead of
/// deriving it from `!recreate_reasons.is_empty()`) would surface
/// here as a non-empty reasons Vec on a non-recreate delta — and
/// the operator-facing summary would silently undercount the
/// recreate plan disruption tier.
#[test]
fn plan_invariant_no_recreate_implies_empty_recreate_reasons() {
    // memory_max: in-place via Stage 2 drop-in body diff.
    assert_in_place_invariant("memory_max", build_memory_max_in_place_plan());

    // auth_name: in-place per design Part 3. Two PATs registered;
    // runner moves from pat-old → pat-new. The classifier records
    // a FieldChange but pushes no recreate reason — apply rebuilds
    // the auth registry every run, so no host-state migration is
    // needed.
    assert_in_place_invariant("auth_name", build_auth_name_in_place_plan());

    // trust_zone: in-place per design Part 3. Mirrors the existing
    // `plan_update_runner_trust_zone_change_is_in_place_with_field_change`
    // fixture — once cache-pool cross-references resolve at config
    // load, the runner unit body has no trust_zone dependency.
    assert_in_place_invariant("trust_zone", build_trust_zone_in_place_plan());

    // caches: in-place per design Part 3. Two pools in same
    // trust_zone; runner moves from caches=["pool-old"] →
    // ["pool-new"]. The classifier records a FieldChange but
    // apply rewrites the per-runner 30-cache-pool.conf drop-in
    // body and cycles the unit so the post-update BindPaths
    // take effect — no recreate.
    assert_in_place_invariant("caches", build_caches_in_place_plan());
}

/// Run a plan-builder, extract the single `UpdateRunner` delta,
/// and assert the in-place invariant
/// (`requires_recreate=false ⇒ recreate_reasons.is_empty()`).
/// Panics with the scenario label if the plan emits no
/// `UpdateRunner`, surfaces `requires_recreate=true`, or surfaces a
/// non-empty `recreate_reasons` Vec.
fn assert_in_place_invariant(label: &str, plan: Plan) {
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .unwrap_or_else(|| panic!("[{label}] must emit UpdateRunner"));
    assert!(
        !upd.requires_recreate,
        "[{label}] scenario must be in-place; got requires_recreate=true \
         with reasons {:?}",
        upd.recreate_reasons,
    );
    assert!(
        upd.recreate_reasons.is_empty(),
        "[{label}] invariant violation: requires_recreate=false MUST imply \
         recreate_reasons.is_empty(); got {:?}",
        upd.recreate_reasons,
    );
}

fn build_memory_max_in_place_plan() -> Plan {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.memory_max = Some("64G".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.memory_max = Some("32G".into());
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
    plan_from(&cfg, &actual, &empty_paths()).unwrap()
}

fn build_auth_name_in_place_plan() -> Plan {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.auth = Some("pat-new".into());
        r
    }]);
    cfg.auth = IndexMap::new();
    cfg.auth.insert(
        "pat-old".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT_OLD".into()),
            token_file: None,
        },
    );
    cfg.auth.insert(
        "pat-new".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT_NEW".into()),
            token_file: None,
        },
    );
    let old_runner = cfg.runners[0].clone();
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat-old".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
    plan_from(&cfg, &actual, &empty_paths()).unwrap()
}

fn build_trust_zone_in_place_plan() -> Plan {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.trust_zone = "audited".into();
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.trust_zone = "default".into();
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
    plan_from(&cfg, &actual, &empty_paths()).unwrap()
}

fn build_caches_in_place_plan() -> Plan {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec!["pool-new".into()];
        r
    }]);
    cfg.cache_pools.insert(
        "pool-old".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
        },
    );
    cfg.cache_pools.insert(
        "pool-new".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
        },
    );
    let mut old_runner = cfg.runners[0].clone();
    old_runner.caches = vec!["pool-old".into()];
    let old_binding = EffectiveCacheBinding {
        name: "pool-old".into(),
        kinds: vec![CacheKind::Ccache],
        size: "10G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
    };
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![old_binding],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
    plan_from(&cfg, &actual, &empty_paths()).unwrap()
}

#[test]
fn plan_from_resolves_default_keep_versions_when_unset() {
    // Defaults.keep_versions = None → Plan.keep_versions = 2
    // (DEFAULT_KEEP_VERSIONS). The pruner default is "current
    // bin tree + 1 rollback target".
    let cfg = config_with_runners(vec![]);
    assert!(cfg.defaults.keep_versions.is_none());
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    assert_eq!(plan.keep_versions, crate::config::DEFAULT_KEEP_VERSIONS);
}

#[test]
fn plan_from_threads_explicit_keep_versions_through_to_plan() {
    // Operator-set Defaults.keep_versions plumbs verbatim into
    // Plan.keep_versions. apply.rs threads this from Plan into
    // execute_create_runner → tarball.prune_old_versions.
    let mut cfg = config_with_runners(vec![]);
    cfg.defaults.keep_versions = Some(7);
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    assert_eq!(plan.keep_versions, 7);
}

#[test]
fn plan_from_clamps_keep_versions_zero_to_one_at_lower_bound() {
    // Defense in depth: keep_versions=0 would prune the
    // just-installed bin tree (extract.rs::prune_old_bin_versions
    // explicitly errors on zero). Plan-side clamp via .max(1)
    // surfaces a sensible value to the apply path even if a
    // hostile config sneaks past the validator.
    let mut cfg = config_with_runners(vec![]);
    cfg.defaults.keep_versions = Some(0);
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    assert_eq!(
        plan.keep_versions, 1,
        "zero must clamp up to 1 to keep the just-installed bin tree"
    );
}
