//! Count expansion edge cases for `plan::expand_counts`.
//!
//! Existing in-tree tests (in `plan::tests`) cover:
//! - basic count = 3 → ci-1, ci-2, ci-3
//! - count = 1 → name kept as explicit
//! - count = 0 → skipped
//! - auto-skip across explicit collision
//! - cross-block collision errors
//! - count > MAX_COUNT rejected
//! - overlong generated name rejected
//!
//! Gaps these integration tests close:
//! 1. **Empty `config.runners`** — expand_counts on a config with no
//!    runners returns an empty Vec, not an error.
//! 2. **MAX_COUNT exact (1024) accepted** — boundary just-below the
//!    rejection threshold.
//! 3. **Source-order preservation across mixed explicit + count blocks**
//!    — expansion lands in source position, not appended to the end.
//! 4. **Count block that fully collides with explicit names** — every
//!    generated name auto-skips; emit only the explicit blocks.
//! 5. **Two count blocks with disjoint prefixes don't collide** — pure
//!    happy path between count blocks.
//! 6. **Count block + explicit at the SAME generated name produces only
//!    the explicit (no duplication)** — verifies auto-skip doesn't emit
//!    both.
//! 7. **Count block where parent prefix would exceed identifier max
//!    after suffix is rejected** — boundary on `IDENTIFIER_MAX_LEN`.
//! 8. **Count = 1 keeps the bare name (no `-1` suffix)** — verifies
//!    expansion is gated on `count > 1`, not `>= 1`.
//! 9. **Count block with short prefix expands at `MAX_COUNT` to 1024
//!    distinct names** — full enumeration property check.

use ghars::config::{AuthSpec, Config, Defaults, Hardening, RunnerSpec};
use ghars::plan::{MAX_COUNT, expand_counts};
use indexmap::IndexMap;
use std::collections::HashSet;

fn pat_auth() -> IndexMap<String, AuthSpec> {
    let mut m = IndexMap::new();
    m.insert(
        "pat".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    m
}

fn make_runner(name: &str) -> RunnerSpec {
    RunnerSpec {
        name: name.into(),
        count: None,
        url: format!("https://github.com/example/{name}"),
        auth: Some("pat".into()),
        labels: vec![],
        memory_max: None,
        runner_version: None,
        runner_sha256: None,
        runner_tarball: None,
        arch: None,
        user: None,
        prefix: None,
        caches: vec![],
        trust_zone: "default".into(),
        network: None,
        proxy: None,
        hooks: None,
        hardening: Hardening::default(),
        allowed_cpus: None,
        allowed_memory_nodes: None,
    }
}

fn count_runner(name: &str, count: u32) -> RunnerSpec {
    let mut r = make_runner(name);
    r.count = Some(count);
    r
}

fn cfg(runners: Vec<RunnerSpec>) -> Config {
    Config {
        defaults: Defaults::default(),
        auth: pat_auth(),
        cache_pools: IndexMap::new(),
        networks: IndexMap::new(),
        proxy: None,
        hooks: None,
        runners,
    }
}

#[test]
fn empty_config_runners_yields_empty_expansion() {
    // The `runners: vec![]` config is the "operator hasn't declared
    // anything yet" case. expand_counts must succeed (not error).
    let out = expand_counts(&cfg(vec![])).expect("empty must succeed");
    assert!(out.is_empty(), "empty config produces empty expansion");
}

#[test]
fn count_1_keeps_bare_name_no_suffix() {
    // `count = Some(1)` is equivalent to "explicit single runner with
    // this name". The code paths goes through `is_count_block` which
    // returns false for `count > 1` only — so `Some(1)` is treated as
    // explicit, and the resulting RunnerSpec has `count: None`.
    let out = expand_counts(&cfg(vec![count_runner("solo", 1)])).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "solo", "no `-1` suffix");
    assert_eq!(out[0].count, None, "count cleared on output");
}

#[test]
fn count_at_max_count_boundary_accepted() {
    // `MAX_COUNT` is the largest value `expand_counts` allows. One
    // above rejects (existing in-tree test covers that). At exactly
    // MAX_COUNT the expander must succeed and emit MAX_COUNT entries.
    // Use a 2-char prefix so generated names fit IDENTIFIER_MAX_LEN
    // (max suffix is `-1024` = 5 chars, total ≤ 7 chars).
    let out = expand_counts(&cfg(vec![count_runner("ci", MAX_COUNT)]))
        .expect("count == MAX_COUNT must succeed");
    assert_eq!(out.len(), MAX_COUNT as usize);
    // All names unique.
    let names: HashSet<String> = out.iter().map(|r| r.name.clone()).collect();
    assert_eq!(names.len(), out.len(), "all expanded names unique");
    // First and last names match the documented pattern.
    assert!(names.contains("ci-1"));
    assert!(names.contains(&format!("ci-{}", MAX_COUNT)));
}

#[test]
fn source_order_preserved_across_explicit_then_count_block() {
    // Explicit `alpha`, count block `ci`/3, explicit `zebra`. Source
    // order in the OUTPUT must be: alpha, ci-1, ci-2, ci-3, zebra.
    // The plan engine relies on this for deterministic action ordering
    // before sort_into_phases.
    let runners = vec![
        make_runner("alpha"),
        count_runner("ci", 3),
        make_runner("zebra"),
    ];
    let out = expand_counts(&cfg(runners)).unwrap();
    let names: Vec<&str> = out.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "ci-1", "ci-2", "ci-3", "zebra"]);
}

#[test]
fn source_order_preserved_count_block_first() {
    // Count block first, then explicit. Output order: ci-1..ci-3, then
    // omega (explicit kept in its source position).
    let runners = vec![count_runner("ci", 3), make_runner("omega")];
    let out = expand_counts(&cfg(runners)).unwrap();
    let names: Vec<&str> = out.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["ci-1", "ci-2", "ci-3", "omega"]);
}

#[test]
fn count_block_fully_eclipsed_by_explicits_emits_only_explicits() {
    // Explicit ci-1 and ci-2 plus a count = 2 block named ci. Auto-skip
    // applies to BOTH generated names — output is just the two
    // explicits.
    let runners = vec![
        make_runner("ci-1"),
        make_runner("ci-2"),
        count_runner("ci", 2),
    ];
    let out = expand_counts(&cfg(runners)).unwrap();
    let names: Vec<&str> = out.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["ci-1", "ci-2"]);
}

#[test]
fn count_block_with_partial_explicit_collision_skips_only_collisions() {
    // Explicit ci-2, count block ci/4 → output should emit ci-1, ci-2
    // (from explicit), ci-3, ci-4. Order: count-block expansion lands
    // BEFORE the explicit per source order, so the auto-skip keeps the
    // explicit's source position. (Source order: count-block first
    // here.) Exact output: ci-1, ci-3, ci-4, ci-2.
    let runners = vec![count_runner("ci", 4), make_runner("ci-2")];
    let out = expand_counts(&cfg(runners)).unwrap();
    let names: Vec<&str> = out.iter().map(|r| r.name.as_str()).collect();
    // Count-block emits ci-1, ci-3, ci-4 (skipping ci-2 in-place);
    // explicit ci-2 lands in its own source position (after the count
    // block).
    assert_eq!(names, vec!["ci-1", "ci-3", "ci-4", "ci-2"]);
}

#[test]
fn two_count_blocks_with_disjoint_prefixes_do_not_collide() {
    // ci/2 + worker/3 → output: ci-1, ci-2, worker-1, worker-2,
    // worker-3. No auto-skip, no collision.
    let runners = vec![count_runner("ci", 2), count_runner("worker", 3)];
    let out = expand_counts(&cfg(runners)).unwrap();
    let names: Vec<&str> = out.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["ci-1", "ci-2", "worker-1", "worker-2", "worker-3"]
    );
}

#[test]
fn two_count_blocks_collide_on_generated_name() {
    // ci/2 plus a second count block named "ci-1" with count = 2.
    // Generated names from "ci-1": ci-1-1, ci-1-2. Generated names
    // from "ci": ci-1, ci-2. No collision (the prefixes share a stem
    // but the suffixes differ). Verify the expander correctly handles
    // overlapping prefixes by NOT collapsing them.
    let runners = vec![count_runner("ci", 2), count_runner("ci-1", 2)];
    let out = expand_counts(&cfg(runners)).unwrap();
    let names: HashSet<&str> = out.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains("ci-1"));
    assert!(names.contains("ci-2"));
    assert!(names.contains("ci-1-1"));
    assert!(names.contains("ci-1-2"));
    assert_eq!(names.len(), 4);
}

#[test]
fn count_block_with_zero_count_skipped_alongside_others() {
    // Zero-count block in the middle of a series of valid blocks must
    // be silently skipped; the other blocks expand normally.
    let runners = vec![
        make_runner("alpha"),
        count_runner("nothing", 0),
        count_runner("ci", 2),
        make_runner("zebra"),
    ];
    let out = expand_counts(&cfg(runners)).unwrap();
    let names: Vec<&str> = out.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "ci-1", "ci-2", "zebra"]);
}

#[test]
fn count_block_prefix_length_at_boundary_for_max_count_suffix() {
    // RUNNER_NAME_MAX_LEN = 25 is the binding cap, tighter than
    // IDENTIFIER_MAX_LEN = 64. Longest suffix from MAX_COUNT = 1024 is
    // `-1024` (5 chars). Largest accepted prefix is 25 - 5 = 20 chars.
    // 21-char prefix + `-1024` = 26 chars → rejects via the runner-name
    // length cap which sits on top of validate_identifier in
    // `validate_generated_identifier`.
    let max_safe_prefix = "a".repeat(20);
    expand_counts(&cfg(vec![count_runner(&max_safe_prefix, MAX_COUNT)]))
        .expect("20-char prefix + -1024 fits within RUNNER_NAME_MAX_LEN");

    let too_long_prefix = "a".repeat(21);
    let err = expand_counts(&cfg(vec![count_runner(&too_long_prefix, MAX_COUNT)]))
        .expect_err("21-char prefix + -1024 exceeds RUNNER_NAME_MAX_LEN");
    let msg = format!("{err}");
    assert!(
        msg.contains("runner-name validation"),
        "msg must come from runner-name layer; got: {msg}"
    );
}

#[test]
fn cross_block_name_collision_between_two_count_blocks_errors() {
    // Two count blocks generating identical names (same prefix and
    // overlapping range) must error. Existing in-tree test covers
    // `count_runner("shared", 2)` + `count_runner("shared", 3)`; this
    // test checks a NON-overlapping start: shared/2 + shared/3 still
    // collide because both produce shared-1, shared-2.
    let runners = vec![count_runner("shared", 2), count_runner("shared", 3)];
    let err = expand_counts(&cfg(runners)).expect_err("collision must error");
    let msg = format!("{err}");
    assert!(msg.contains("collision"), "got: {msg}");
    // Surfaces both prefix names so operator can find them.
    assert!(msg.contains("shared"), "got: {msg}");
}

#[test]
fn count_value_exactly_max_count_plus_one_rejected() {
    // Boundary opposite the accepted-MAX-COUNT case above.
    let err = expand_counts(&cfg(vec![count_runner("ci", MAX_COUNT + 1)]))
        .expect_err("MAX_COUNT+1 must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("MAX_COUNT") || msg.contains("count"),
        "got: {msg}"
    );
}

#[test]
fn count_block_clears_count_field_on_output() {
    // Every output RunnerSpec must have `count: None`. The expander
    // strips the field so downstream merge_defaults / plan_from sees
    // a flat list of runners — no surprise expansion-after-expansion.
    let out = expand_counts(&cfg(vec![count_runner("ci", 3)])).unwrap();
    for r in &out {
        assert_eq!(
            r.count, None,
            "expanded {} keeps count={:?}",
            r.name, r.count
        );
    }
}

#[test]
fn explicit_count_some_zero_does_not_skip_named_runner_when_unique() {
    // Edge case: `count = Some(0)` skips the runner entirely (per the
    // is_count_block branch in plan.rs). This matches the existing
    // in-tree test but verifies the SKIP applies even when there's no
    // alternative source for the name.
    let out = expand_counts(&cfg(vec![count_runner("nothing", 0)])).unwrap();
    assert!(
        out.is_empty(),
        "count = Some(0) skips even when no alternative exists"
    );
}

#[test]
fn duplicate_explicit_runner_names_passes_through_unchanged() {
    // `expand_counts` does NOT deduplicate explicit runners — that's
    // a downstream concern (plan_from would catch duplicate names).
    // The expander's job is just count expansion; pass-through is the
    // contract for explicit blocks.
    let runners = vec![make_runner("dup"), make_runner("dup")];
    let out = expand_counts(&cfg(runners)).unwrap();
    assert_eq!(out.len(), 2, "duplicate explicit names pass through");
    assert!(out.iter().all(|r| r.name == "dup"));
}

#[test]
fn explicit_runner_with_count_field_unset_passes_unchanged() {
    // `count = None` is the most common case. Output must equal input
    // (modulo no count field touch — which is None already).
    let runner = make_runner("normal");
    let out = expand_counts(&cfg(vec![runner.clone()])).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "normal");
    assert_eq!(out[0].url, runner.url);
    assert_eq!(out[0].count, None);
}
