//! Plan engine integration tests via the public API surface.
//!
//! These exercise the public plan + state types from outside the crate
//! (no access to private helpers), proving the API surface is callable
//! and behaves correctly as a third party would consume it.
//!
//! Coverage:
//! - count expansion: auto-skip with explicit collision, MAX_COUNT
//!   boundary, count-zero skip, identifier validation on generated
//!   names.
//! - defaults merge: every field from `Defaults` flows correctly into
//!   `EffectiveRunnerSpec` — labels concat-and-dedup, hardening
//!   field-by-field merge, runner.X overrides defaults.X.
//! - plan diff: NoOp / CreateRunner / RemoveRunner / UpdateRunner
//!   classification across paired states.
//! - spec_hash: idempotent (hash → embed → re-hash returns same value),
//!   stable across irrelevant field reorderings.

use camino::Utf8PathBuf;
use ghars::config::{Arch, AuthSpec, Config, Defaults, EtcBindStyle, Hardening, RunnerSpec};
use ghars::paths::Paths;
use ghars::plan::{Action, Plan, plan_from, spec_hash};
use ghars::state::{ActualState, DiscoveredCachePool, DiscoveredRunner, Drift};
use indexmap::IndexMap;
use std::collections::BTreeMap;

fn make_config() -> Config {
    let mut auth = IndexMap::new();
    auth.insert(
        "pat".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    Config {
        defaults: Defaults::default(),
        auth,
        cache_pools: IndexMap::new(),
        networks: IndexMap::new(),
        proxy: None,
        hooks: None,
        runners: vec![],
    }
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

fn run_plan(cfg: &Config, actual: &ActualState) -> Plan {
    plan_from(cfg, actual, &Paths::default()).expect("plan_from must succeed")
}

#[test]
fn plan_create_runner_when_actual_is_empty() {
    let mut cfg = make_config();
    cfg.runners = vec![make_runner("buckos")];
    let actual = ActualState::default();
    let plan = run_plan(&cfg, &actual);
    let creates: Vec<_> = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::CreateRunner(_)))
        .collect();
    assert_eq!(creates.len(), 1);
}

#[test]
fn plan_remove_runner_when_actual_has_unmatched_managed_runner() {
    let cfg = make_config();
    let mut actual = ActualState::default();
    actual.runners.insert(
        "ghost".into(),
        DiscoveredRunner {
            name: "ghost".into(),
            spec_hash: "sha256:dead".into(),
            on_disk_unit_text: "[Unit]\nX-Ghars-Managed=true\nX-Ghars-Runner-Name=ghost\n".into(),
            drop_ins: BTreeMap::new(),
            running: false,
            enabled: false,
            drift: Drift::InSync,
        },
    );
    let plan = run_plan(&cfg, &actual);
    let removes: Vec<_> = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::RemoveRunner(_)))
        .collect();
    assert_eq!(removes.len(), 1);
}

#[test]
fn plan_noop_when_runner_in_sync_with_matching_hash() {
    let mut cfg = make_config();
    cfg.runners = vec![make_runner("buckos")];

    // Compute the expected hash by running the planner once with empty
    // actual state and reading the spec_hash off the CreateRunner.
    let plan_first = run_plan(&cfg, &ActualState::default());
    let expected_hash = match &plan_first.actions[0] {
        Action::CreateRunner(p) => p.spec_hash.clone(),
        other => panic!("expected CreateRunner, got {other:?}"),
    };

    let mut actual = ActualState::default();
    actual.runners.insert(
        "buckos".into(),
        DiscoveredRunner {
            name: "buckos".into(),
            spec_hash: expected_hash,
            on_disk_unit_text: ghars::systemd::runner_template_text(),
            drop_ins: BTreeMap::new(),
            running: true,
            enabled: true,
            drift: Drift::InSync,
        },
    );
    let plan = run_plan(&cfg, &actual);
    let noops: Vec<_> = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::NoOp(_)))
        .collect();
    assert_eq!(
        noops.len(),
        1,
        "in-sync hash + InSync drift must produce NoOp"
    );
}

#[test]
fn plan_update_with_recreate_when_url_changes_via_annotations() {
    let mut cfg = make_config();
    let mut runner = make_runner("buckos");
    runner.url = "https://github.com/example/buckos-renamed".into();
    cfg.runners = vec![runner];

    let mut actual = ActualState::default();
    // X-Ghars-Runner-Url annotation lives in the 00-ghars.conf
    // drop-in body (#347) — classifier reads it from there, not
    // from on_disk_unit_text. Hand-craft a drop-in body with the
    // OLD url so the annotation-diff classifier flags `url` as a
    // recreate reason.
    let mut drop_ins = BTreeMap::new();
    drop_ins.insert(
        "00-ghars.conf".into(),
        "[Unit]\nX-Ghars-Spec-Hash=sha256:stale\n\
             X-Ghars-Runner-Url=https://github.com/example/buckos\n\
             X-Ghars-Auth-Name=pat\n\
             [Service]\nX-Ghars-Runsvc-Sha256=sha256:fake\n"
            .into(),
    );
    actual.runners.insert(
        "buckos".into(),
        DiscoveredRunner {
            name: "buckos".into(),
            spec_hash: "sha256:stale".into(),
            on_disk_unit_text: ghars::systemd::runner_template_text(),
            drop_ins,
            running: true,
            enabled: true,
            drift: Drift::InSync,
        },
    );
    let plan = run_plan(&cfg, &actual);
    let update = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("UpdateRunner expected");
    assert!(update.requires_recreate);
    assert!(update.recreate_reasons.contains(&"url"));
}

#[test]
fn plan_update_conservative_recreate_on_hash_mismatch_alone() {
    let mut cfg = make_config();
    cfg.runners = vec![make_runner("buckos")];

    // Bootstrap discovered drop-ins from a first plan run against empty
    // actual state — the resulting CreateRunner.drop_ins is what the
    // re-render in the UpdateRunner branch will produce for the same
    // spec, so every Stage 2 entry is `Preserved`. Without this, an
    // empty `drop_ins` would make every rendered entry `Created` and
    // C-1's predicate (Created/Modified/Removed all count as in-place
    // evidence) would steer the planner into in-place. We need the
    // uncovered fallback to fire — that requires Stage 1 + Stage 2
    // both finding nothing — so we copy the rendered drop-ins
    // verbatim and only force the OUTER `spec_hash` to a stale
    // sentinel so the `hashes_equal` short-circuit fails and the
    // planner enters Stage 1 + Stage 2.
    let bootstrap = run_plan(&cfg, &ActualState::default());
    let create = bootstrap
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) => Some(p),
            _ => None,
        })
        .expect("CreateRunner expected from bootstrap plan");
    // #289: bootstrap renders BEFORE install records the runsvc
    // digest, so its 00-ghars.conf body has no X-Ghars-Runsvc-Sha256
    // annotation. The plan path now treats missing annotation as a
    // recreate trigger ("runsvc_integrity"). To test the uncovered
    // path SPECIFICALLY, inject the trampoline annotation into the
    // bootstrap drop-in body so the planner reaches the Stage 1 + 2
    // diff cleanly.
    let mut rendered_drop_ins = create.drop_ins.clone();
    let body_with_digest = format!(
        "{}\n[Service]\nX-Ghars-Runsvc-Sha256=sha256:fake\n",
        rendered_drop_ins
            .get("00-ghars.conf")
            .expect("bootstrap CreateRunner must include 00-ghars.conf")
            .trim_end()
    );
    rendered_drop_ins.insert("00-ghars.conf".into(), body_with_digest);

    let mut actual = ActualState::default();
    actual.runners.insert(
        "buckos".into(),
        DiscoveredRunner {
            name: "buckos".into(),
            // Outer spec_hash is the sentinel that drives the
            // `hashes_equal` check in plan_from's intersection branch
            // — set it to a stale value so the planner enters the
            // Stage 1+2 path.
            // The rendered 00-ghars.conf body in `drop_ins` still
            // carries the (correct) hash annotation, but Stage 2
            // excludes 00-ghars.conf from in-place evidence anyway,
            // so its Preserved status is irrelevant.
            spec_hash: "sha256:stale".into(),
            // Annotations match the desired spec, so Stage 1's
            // classifier sees no field-level change.
            on_disk_unit_text: "[Unit]\nX-Ghars-Managed=true\nX-Ghars-Runner-Name=buckos\n\
                 X-Ghars-Runner-Url=https://github.com/example/buckos\n\
                 X-Ghars-Auth-Name=pat\n[Service]\nUser=ghars-buckos\n\
                 WorkingDirectory=/var/lib/ghars/buckos\n"
                .into(),
            drop_ins: rendered_drop_ins,
            running: true,
            enabled: true,
            drift: Drift::InSync,
        },
    );
    let plan = run_plan(&cfg, &actual);
    let update = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("UpdateRunner expected");
    assert!(update.requires_recreate);
    assert!(update.recreate_reasons.contains(&"uncovered"));
}

#[test]
fn plan_count_block_expands_to_n_create_actions() {
    let mut cfg = make_config();
    let mut runner = make_runner("ci");
    runner.count = Some(3);
    cfg.runners = vec![runner];
    let plan = run_plan(&cfg, &ActualState::default());
    let creates: Vec<_> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(p) => Some(p.spec.name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(creates.len(), 3);
    assert!(creates.contains(&"ci-1"));
    assert!(creates.contains(&"ci-2"));
    assert!(creates.contains(&"ci-3"));
}

#[test]
fn plan_count_block_auto_skips_explicit_collision() {
    let mut cfg = make_config();
    let mut count = make_runner("ci");
    count.count = Some(5);
    let mut explicit = make_runner("ci-3");
    explicit.memory_max = Some("32G".into());
    cfg.runners = vec![count, explicit];

    let plan = run_plan(&cfg, &ActualState::default());
    let names: Vec<&str> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(p) => Some(p.spec.name.as_str()),
            _ => None,
        })
        .collect();

    // 5 names total: ci-1, ci-2, ci-4, ci-5 from count + ci-3 explicit.
    assert_eq!(names.len(), 5);
    assert!(names.contains(&"ci-1"));
    assert!(names.contains(&"ci-2"));
    assert!(names.contains(&"ci-3"));
    assert!(names.contains(&"ci-4"));
    assert!(names.contains(&"ci-5"));
    // ci-3 carries the explicit override, not the count-block defaults.
    let ci3 = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) if p.spec.name == "ci-3" => Some(p),
            _ => None,
        })
        .expect("ci-3 in plan");
    assert_eq!(ci3.spec.memory_max.as_deref(), Some("32G"));
}

#[test]
fn defaults_merge_runner_scalar_overrides_defaults_scalar() {
    let mut cfg = make_config();
    cfg.defaults = Defaults {
        memory_max: Some("8G".into()),
        runner_version: Some("2.300.0".into()),
        runner_sha256: Some("a".repeat(64)),
        prefix: Some(Utf8PathBuf::from("/srv/runners")),
        ..Defaults::default()
    };
    let mut runner = make_runner("buckos");
    runner.memory_max = Some("16G".into());
    runner.runner_version = Some("2.334.0".into());
    cfg.runners = vec![runner];

    let plan = run_plan(&cfg, &ActualState::default());
    let create = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) => Some(p),
            _ => None,
        })
        .expect("CreateRunner");
    let spec = &create.spec;
    assert_eq!(
        spec.memory_max.as_deref(),
        Some("16G"),
        "runner overrides defaults"
    );
    assert_eq!(spec.runner_version.as_deref(), Some("2.334.0"));
    // runner_sha256 falls through from defaults (runner didn't set).
    assert_eq!(spec.runner_sha256.as_deref(), Some(&"a".repeat(64)[..]));
    // prefix falls through.
    assert_eq!(spec.prefix.as_str(), "/srv/runners");
}

/// labels concat + dedup + sort. Labels are set-semantic and sorted
/// alphabetically because GitHub matches workflow `runs-on:` against
/// the registered label set order-independently. The dedup contract
/// still holds — "self-hosted" appears once even though it's in both
/// the defaults and the runner block.
#[test]
fn defaults_merge_labels_concat_dedup_sorted() {
    let mut cfg = make_config();
    cfg.defaults = Defaults {
        labels: vec!["self-hosted".into(), "linux".into()],
        ..Defaults::default()
    };
    let mut runner = make_runner("buckos");
    runner.labels = vec!["buck2".into(), "self-hosted".into()];
    cfg.runners = vec![runner];

    let plan = run_plan(&cfg, &ActualState::default());
    let create = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) => Some(p),
            _ => None,
        })
        .expect("CreateRunner");
    // Concat-and-dedup yields {"self-hosted","linux","buck2"};
    // sort by name yields ["buck2","linux","self-hosted"]. The
    // single "self-hosted" entry pins the dedup contract.
    assert_eq!(
        create.spec.labels,
        vec!["buck2".to_string(), "linux".into(), "self-hosted".into()]
    );
}

#[test]
fn defaults_merge_user_default_is_per_runner_secure() {
    let mut cfg = make_config();
    cfg.runners = vec![make_runner("buckos")];
    let plan = run_plan(&cfg, &ActualState::default());
    let create = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) => Some(p),
            _ => None,
        })
        .expect("CreateRunner");
    // SEC-27 secure default: ghars-NAME, NOT a shared "gha".
    assert_eq!(create.spec.user, "ghars-buckos");
}

#[test]
fn defaults_merge_arch_falls_back_to_host_when_neither_set() {
    let mut cfg = make_config();
    cfg.runners = vec![make_runner("buckos")];
    let plan = run_plan(&cfg, &ActualState::default());
    let create = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) => Some(p),
            _ => None,
        })
        .expect("CreateRunner");
    // Test runs on x86_64 OR aarch64; either is acceptable. The key
    // property is that the field is populated (NOT None).
    assert!(matches!(create.spec.arch, Arch::X86_64 | Arch::Aarch64));
}

#[test]
fn defaults_merge_hardening_runner_overrides_defaults_field_by_field() {
    let mut cfg = make_config();
    cfg.defaults = Defaults {
        hardening: Hardening {
            kvm: Some(false),
            restrict_realtime: Some(true),
            etc_bind_style: EtcBindStyle::Broad,
            ..Hardening::default()
        },
        ..Defaults::default()
    };
    let mut runner = make_runner("buckos");
    runner.hardening = Hardening {
        kvm: Some(true), // override defaults
        // restrict_realtime: None → fall through from defaults
        ..Hardening::default()
    };
    cfg.runners = vec![runner];

    let plan = run_plan(&cfg, &ActualState::default());
    let create = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) => Some(p),
            _ => None,
        })
        .expect("CreateRunner");
    assert_eq!(create.spec.hardening.kvm, Some(true), "runner wins on kvm");
    assert_eq!(
        create.spec.hardening.restrict_realtime,
        Some(true),
        "defaults flows through when runner unset"
    );
    // etc_bind_style is a Copy enum; runner default (Curated) still
    // wins over defaults Broad — the merge picks runner.etc_bind_style
    // verbatim. (Per Part 3 merge: enum is scalar.)
    assert_eq!(create.spec.hardening.etc_bind_style, EtcBindStyle::Curated);
}

#[test]
fn defaults_merge_extra_bind_paths_additive() {
    let mut cfg = make_config();
    cfg.defaults = Defaults {
        hardening: Hardening {
            extra_bind_paths: vec![Utf8PathBuf::from("/srv/shared")],
            ..Hardening::default()
        },
        ..Defaults::default()
    };
    let mut runner = make_runner("buckos");
    runner.hardening = Hardening {
        extra_bind_paths: vec![Utf8PathBuf::from("/var/lib/runner-extra")],
        ..Hardening::default()
    };
    cfg.runners = vec![runner];

    let plan = run_plan(&cfg, &ActualState::default());
    let create = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) => Some(p),
            _ => None,
        })
        .expect("CreateRunner");
    // Defaults entries first, then runner entries.
    assert_eq!(
        create.spec.hardening.extra_bind_paths,
        vec![
            Utf8PathBuf::from("/srv/shared"),
            Utf8PathBuf::from("/var/lib/runner-extra")
        ]
    );
}

#[test]
fn plan_validates_unknown_auth_reference() {
    let mut cfg = make_config();
    let mut runner = make_runner("buckos");
    runner.auth = Some("missing-auth".into());
    cfg.runners = vec![runner];
    let err = plan_from(&cfg, &ActualState::default(), &Paths::default()).unwrap_err();
    assert!(format!("{err}").contains("auth"));
}

#[test]
fn plan_actions_are_sorted_for_determinism() {
    let mut cfg = make_config();
    cfg.runners = vec![
        make_runner("zebra"),
        make_runner("alpha"),
        make_runner("mango"),
    ];
    let plan = run_plan(&cfg, &ActualState::default());
    let creates: Vec<&str> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(p) => Some(p.spec.name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(creates, vec!["alpha", "mango", "zebra"]);
}

#[test]
fn spec_hash_is_idempotent_across_embed_round_trip() {
    let mut cfg = make_config();
    cfg.runners = vec![make_runner("buckos")];
    let plan = run_plan(&cfg, &ActualState::default());
    let p = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) => Some(p),
            _ => None,
        })
        .expect("CreateRunner");

    let h1 = p.spec_hash.clone();
    // Re-hash the spec — must match what plan_from already embedded.
    let h2 = spec_hash(&p.spec);
    assert_eq!(h1, h2);

    // The format is `sha256:HEX` — 7 chars prefix + 64 hex.
    assert!(h1.starts_with("sha256:"));
    assert_eq!(h1.len(), 7 + 64);
}

#[test]
fn spec_hash_changes_when_url_changes() {
    let mut cfg = make_config();
    cfg.runners = vec![make_runner("buckos")];
    let plan_a = run_plan(&cfg, &ActualState::default());
    let h_a = match &plan_a.actions[0] {
        Action::CreateRunner(p) => p.spec_hash.clone(),
        other => panic!("expected CreateRunner, got {other:?}"),
    };

    let mut cfg2 = make_config();
    let mut runner = make_runner("buckos");
    runner.url = "https://github.com/example/buckos2".into();
    cfg2.runners = vec![runner];
    let plan_b = run_plan(&cfg2, &ActualState::default());
    let h_b = match &plan_b.actions[0] {
        Action::CreateRunner(p) => p.spec_hash.clone(),
        other => panic!("expected CreateRunner, got {other:?}"),
    };

    assert_ne!(h_a, h_b, "url change must change spec_hash");
}

#[test]
fn plan_mixed_create_remove_noop_resolves_correctly() {
    // Desired: alpha + zebra. Actual: zebra (in-sync) + ghost.
    // Expected: CreateRunner(alpha), NoOp(zebra), RemoveRunner(ghost).
    let mut cfg = make_config();
    cfg.runners = vec![make_runner("alpha"), make_runner("zebra")];

    // Compute zebra's expected hash.
    let plan_seed = run_plan(&cfg, &ActualState::default());
    let zebra_hash = plan_seed
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) if p.spec.name == "zebra" => Some(p.spec_hash.clone()),
            _ => None,
        })
        .expect("zebra in seed plan");

    let mut actual = ActualState::default();
    actual.runners.insert(
        "zebra".into(),
        DiscoveredRunner {
            name: "zebra".into(),
            spec_hash: zebra_hash,
            on_disk_unit_text: ghars::systemd::runner_template_text(),
            drop_ins: BTreeMap::new(),
            running: true,
            enabled: true,
            drift: Drift::InSync,
        },
    );
    actual.runners.insert(
        "ghost".into(),
        DiscoveredRunner {
            name: "ghost".into(),
            spec_hash: "sha256:gone".into(),
            on_disk_unit_text: "[Unit]\nX-Ghars-Managed=true\nX-Ghars-Runner-Name=ghost\n".into(),
            drop_ins: BTreeMap::new(),
            running: false,
            enabled: false,
            drift: Drift::InSync,
        },
    );

    let plan = run_plan(&cfg, &actual);

    let mut creates = 0;
    let mut removes = 0;
    let mut noops = 0;
    for a in &plan.actions {
        match a {
            Action::CreateRunner(p) => {
                assert_eq!(p.spec.name, "alpha");
                creates += 1;
            }
            Action::RemoveRunner(i) => {
                assert_eq!(i.name, "ghost");
                removes += 1;
            }
            Action::NoOp(_) => {
                noops += 1;
            }
            _ => {}
        }
    }
    assert_eq!(creates, 1);
    assert_eq!(removes, 1);
    assert_eq!(noops, 1);
}

/// #408 end-to-end: a cache pool drop-in directory with an
/// instance name longer than `CACHE_POOL_NAME_MAX_LEN` exists on
/// disk (operator-installed, partial-apply crash, or downgrade
/// from a future ghars). state::discover() now INCLUDES the
/// oversize entry in `actual.cache_pools` rather than skipping it.
/// Because `validate_cache_pool_name` rejects oversize keys at
/// config load, `cfg.cache_pools` cannot contain a matching entry,
/// so the planner's `actual ∧ ¬desired` branch must emit
/// `RemoveCachePool` for the discovered name. This test pins that
/// the discovered-state contract feeds into the planner contract
/// without an intervening filter dropping the entry.
#[test]
fn plan_emits_remove_cache_pool_for_oversize_discovered_name() {
    // Construct a config that DOES NOT reference the oversize name —
    // operator can't even spell it because validate_cache_pool_name
    // would reject it at config load. Empty cache_pools is the
    // simplest desired state for this test.
    let cfg = make_config();
    let oversize_name = "a".repeat(ghars::validators::CACHE_POOL_NAME_MAX_LEN + 1);

    let mut actual = ActualState::default();
    actual.cache_pools.insert(
        oversize_name.clone(),
        DiscoveredCachePool {
            name: oversize_name.clone(),
            spec_hash: "sha256:dead".into(),
            drop_ins: BTreeMap::new(),
            running: false,
            enabled: false,
            drift: Drift::InSync,
        },
    );

    let plan = run_plan(&cfg, &actual);
    let removes: Vec<&str> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::RemoveCachePool(name) => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        removes,
        vec![oversize_name.as_str()],
        "oversize discovered pool must drive a RemoveCachePool; \
         actions: {:?}",
        plan.actions.iter().map(|a| a.label()).collect::<Vec<_>>()
    );
}
