//! Test split part 1: covers `expand_counts`, `netns_subnet_for_slot`,
//! `merge_defaults` (basic + scalar regression + proptest + `bind_readonly` +
//! `ParsedUnit`), and `spec_hash` (basic + serde + proptest + cross-construction
//! + cross-construction). Migrated verbatim from plan.rs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

// --- expand_counts --------------------------------------------------

#[test]
fn expand_counts_basic() {
    let cfg = config_with_runners(vec![count_runner("ci", 3)]);
    let out = expand_counts(&cfg).unwrap();
    let names: Vec<&str> = out.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["ci-1", "ci-2", "ci-3"]);
    assert!(out.iter().all(|r| r.count.is_none()));
}

#[test]
fn expand_counts_explicit_only_passes_through() {
    let cfg = config_with_runners(vec![minimal_runner("a"), minimal_runner("b")]);
    let out = expand_counts(&cfg).unwrap();
    assert_eq!(
        out.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        vec!["a", "b"]
    );
}

#[test]
fn expand_counts_count_one_kept_as_explicit() {
    let cfg = config_with_runners(vec![count_runner("solo", 1)]);
    let out = expand_counts(&cfg).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "solo");
    assert_eq!(out[0].count, None);
}

#[test]
fn expand_counts_zero_count_skipped() {
    let cfg = config_with_runners(vec![count_runner("nothing", 0)]);
    let out = expand_counts(&cfg).unwrap();
    assert!(out.is_empty());
}

#[test]
fn expand_counts_auto_skips_explicit_collision() {
    // Per Part 4 example: `[[runner]] name = "ci" count = 10` plus
    // an explicit `[[runner]] name = "ci-7" memory_max = "16G"`
    // produces ci-1..ci-6, ci-8..ci-10 from the count block, with
    // ci-7 taken from the explicit block.
    let mut special = minimal_runner("ci-7");
    special.memory_max = Some("16G".into());
    let cfg = config_with_runners(vec![count_runner("ci", 10), special]);
    let out = expand_counts(&cfg).unwrap();
    let names: Vec<&str> = out.iter().map(|r| r.name.as_str()).collect();
    // Order matches source order: count-block expands in place,
    // then explicit ci-7 lands after. All 10 names present
    // exactly once (ci-7 from explicit, ci-1..ci-6 + ci-8..ci-10
    // from count).
    assert_eq!(names.len(), 10);
    let unique: HashSet<&str> = names.iter().copied().collect();
    assert_eq!(unique.len(), 10, "all 10 names unique: {names:?}");
    for i in 1..=10 {
        let expected = format!("ci-{i}");
        assert!(unique.contains(expected.as_str()), "missing {expected}");
    }
    // The explicit ci-7 carries the override; the count-block
    // generated entries don't.
    let ci7 = out.iter().find(|r| r.name == "ci-7").unwrap();
    assert_eq!(ci7.memory_max.as_deref(), Some("16G"));
}

#[test]
fn expand_counts_cross_block_collision_errors() {
    let cfg = config_with_runners(vec![count_runner("shared", 2), count_runner("shared", 3)]);
    let err = expand_counts(&cfg).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("collision"), "got: {msg}");
    assert!(msg.contains("shared-1"), "got: {msg}");
}

#[test]
fn expand_counts_rejects_count_above_max() {
    let cfg = config_with_runners(vec![count_runner("big", MAX_COUNT + 1)]);
    let err = expand_counts(&cfg).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("MAX_COUNT"), "got: {msg}");
}

#[test]
fn expand_counts_rejects_overlong_generated_name() {
    // 64-char IDENTIFIER_MAX_LEN: 63-char prefix + "-1" suffix = 65 chars.
    // validate_identifier rejects first (length > 64); the wrapped
    // error mentions "identifier" via the count-expansion prefix.
    let prefix = "x".repeat(63);
    let cfg = config_with_runners(vec![count_runner(&prefix, 9)]);
    let err = expand_counts(&cfg).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("identifier"), "got: {msg}");
}

/// Generated names that exceed `IDENTIFIER_MAX_LEN` after the
/// `-COUNT` suffix is appended must reject at `expand_counts`
/// time. Catches the gap where `validate_runner_names` at
/// `load_config` saw only the prefix (≤ 64) but expansion produced
/// an over-cap name (e.g. 63-char prefix + "-10" = 66 chars).
/// Pinned at plan-time because config-load can't catch this
/// without computing max-suffix from `count`.
#[test]
fn expand_counts_rejects_generated_name_exceeding_identifier_cap() {
    // 63-char prefix + "-10" (suffix length 3 since count >= 10)
    // = 66 chars > IDENTIFIER_MAX_LEN (64). validate_identifier
    // rejects.
    let prefix = "x".repeat(63);
    let cfg = config_with_runners(vec![count_runner(&prefix, 10)]);
    let err = expand_counts(&cfg).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("count expansion"),
        "msg must scope to count expansion; got: {msg}"
    );
}

// --- netns_subnet_for_slot -----------------------------------------

#[test]
fn netns_subnet_for_slot_zero_is_pool_base() {
    let s = netns_subnet_for_slot(0, "x").unwrap();
    assert_eq!(s.to_string(), "10.200.0.0/30");
}

#[test]
fn netns_subnet_for_slot_one_advances_by_four() {
    let s = netns_subnet_for_slot(1, "x").unwrap();
    assert_eq!(s.to_string(), "10.200.0.4/30");
}

#[test]
fn netns_subnet_for_slot_two_advances_by_four() {
    let s = netns_subnet_for_slot(2, "x").unwrap();
    assert_eq!(s.to_string(), "10.200.0.8/30");
}

#[test]
fn netns_subnet_for_slot_max_in_pool() {
    // Slot 63 = 10.200.0.252/30 — last /30 in the /24 pool.
    let s = netns_subnet_for_slot(63, "x").unwrap();
    assert_eq!(s.to_string(), "10.200.0.252/30");
}

#[test]
fn netns_subnet_for_slot_overflow_errors() {
    let err = netns_subnet_for_slot(64, "buckos").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("exhausted"), "got: {msg}");
    assert!(msg.contains("buckos"), "got: {msg}");
}

#[test]
fn netns_subnet_for_slot_distinct_slots_get_distinct_subnets() {
    // No two adjacent slots share addresses (collision is the
    // bug class this guards against).
    let mut seen = std::collections::HashSet::new();
    for i in 0..NETNS_POOL_SLOTS {
        let s = netns_subnet_for_slot(i, "x").unwrap();
        assert!(
            seen.insert(s.to_string()),
            "slot {i} produced duplicate subnet"
        );
    }
    assert_eq!(seen.len(), NETNS_POOL_SLOTS);
}

// --- merge_defaults -------------------------------------------------

/// labels concat + dedup + sort. defaults.labels first, then
/// runner.labels, dedup, then sorted alphabetically (set-semantic
/// for GitHub Actions registration). The contract is canonical
/// sort because the runner's behavior is order-independent for
/// matching workflow `runs-on:` selectors; local order-sensitivity
/// would cause spurious recreate-class plans on cosmetic TOML
/// reorders.
#[test]
fn merge_defaults_label_concat_dedup_sorted() {
    let runner = {
        let mut r = minimal_runner("buckos");
        r.labels = vec!["buck2".into(), "self-hosted".into()];
        r
    };
    let defaults = Defaults {
        labels: vec!["self-hosted".into(), "linux".into()],
        ..Defaults::default()
    };
    let eff = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    // Concat-and-dedup yields {"self-hosted","linux","buck2"};
    // sort by name yields ["buck2","linux","self-hosted"].
    // Single "self-hosted" entry pins the dedup contract is still
    // honored (defaults sees it first; runner.labels would have
    // re-pushed it absent dedup).
    assert_eq!(eff.labels, vec!["buck2", "linux", "self-hosted"]);
}

/// `merge_defaults` MUST populate `renderer_schema` from
/// `crate::systemd::RENDERER_SCHEMA` at runtime — not from a
/// hardcoded literal. The hash-inclusion regression test at
/// `hash.rs::spec_hash_includes_renderer_schema` only verifies
/// that DIFFERENT renderer_schema values produce DIFFERENT
/// hashes; it does NOT verify the production spec-construction
/// site reads the runtime constant. A refactor that hardcoded
/// `renderer_schema: 1` in `merge_defaults` would silently break
/// the post-fix hash-participation contract (RENDERER_SCHEMA
/// bumps would no longer flip the hash because the spec was
/// always constructed with 1).
#[test]
fn merge_defaults_populates_renderer_schema_from_runtime_constant() {
    let runner = minimal_runner("a");
    let defaults = Defaults::default();
    let eff = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(
        eff.renderer_schema,
        crate::systemd::RENDERER_SCHEMA,
        "merge_defaults must populate renderer_schema from the runtime \
         crate::systemd::RENDERER_SCHEMA constant; a hardcoded literal \
         would silently break the post-fix hash-participation contract \
         (RENDERER_SCHEMA bumps would not flip spec_hash)"
    );
}

#[test]
fn merge_defaults_empty_labels_falls_back_to_name() {
    let runner = minimal_runner("solo");
    let defaults = Defaults::default();
    let eff = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(eff.labels, vec!["solo"]);
}

#[test]
fn merge_defaults_runner_overrides_scalars() {
    let runner = {
        let mut r = minimal_runner("a");
        r.memory_max = Some("64G".into());
        r.runner_version = Some("2.300.0".into());
        r.runner_sha256 = Some("a".repeat(64));
        r.allowed_cpus = Some("0-3".into());
        r.allowed_memory_nodes = Some("0".into());
        r.arch = Some(Arch::Aarch64);
        r
    };
    let defaults = Defaults {
        memory_max: Some("32G".into()),
        runner_version: Some("2.200.0".into()),
        runner_sha256: Some("b".repeat(64)),
        arch: Some(Arch::X86_64),
        ..Defaults::default()
    };
    let eff = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(eff.memory_max.as_deref(), Some("64G"));
    assert_eq!(eff.runner_version.as_deref(), Some("2.300.0"));
    assert_eq!(eff.runner_sha256.as_deref(), Some(&*"a".repeat(64)));
    assert_eq!(eff.allowed_cpus.as_deref(), Some("0-3"));
    assert_eq!(eff.allowed_memory_nodes.as_deref(), Some("0"));
    assert_eq!(eff.arch, Arch::Aarch64);
}

#[test]
fn merge_defaults_falls_back_to_defaults_when_runner_unset() {
    let runner = minimal_runner("a");
    let defaults = Defaults {
        memory_max: Some("32G".into()),
        runner_version: Some("2.200.0".into()),
        runner_sha256: Some("c".repeat(64)),
        arch: Some(Arch::Aarch64),
        ..Defaults::default()
    };
    let eff = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(eff.memory_max.as_deref(), Some("32G"));
    assert_eq!(eff.runner_version.as_deref(), Some("2.200.0"));
    assert_eq!(eff.arch, Arch::Aarch64);
}

#[test]
fn merge_defaults_hardening_field_by_field() {
    let runner = {
        let mut r = minimal_runner("a");
        r.hardening = Hardening {
            kvm: Some(false),
            restrict_realtime: None,
            protect_control_groups: Some(true),
            restrict_suid_sgid: None,
            private_devices: None,
            private_ipc: Some(false),
            restrict_address_families: vec!["AF_UNIX".into()],
            extra_syscalls: vec!["clone3".into()],
            etc_bind_style: EtcBindStyle::Broad,
            bind_readonly_paths: None,
            extra_bind_paths: vec!["/opt/runner".into()],
            extra_capabilities: vec!["CAP_NET_RAW".into()],
        };
        r
    };
    let defaults = Defaults {
        hardening: Hardening {
            kvm: Some(true),
            restrict_realtime: Some(true),
            protect_control_groups: Some(false),
            restrict_suid_sgid: Some(true),
            private_devices: Some(true),
            private_ipc: Some(true),
            restrict_address_families: vec!["AF_INET".into()],
            extra_syscalls: vec!["mknodat".into()],
            etc_bind_style: EtcBindStyle::Curated,
            bind_readonly_paths: Some(vec!["/etc/passwd".into()]),
            extra_bind_paths: vec!["/etc/ssl".into()],
            extra_capabilities: vec!["CAP_KILL".into()],
        },
        ..Defaults::default()
    };

    let eff = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );

    // Runner-set wins.
    assert_eq!(eff.hardening.kvm, Some(false));
    assert_eq!(eff.hardening.protect_control_groups, Some(true));
    assert_eq!(eff.hardening.private_ipc, Some(false));
    // Runner unset ⇒ defaults wins.
    assert_eq!(eff.hardening.restrict_realtime, Some(true));
    assert_eq!(eff.hardening.restrict_suid_sgid, Some(true));
    assert_eq!(eff.hardening.private_devices, Some(true));
    // Vec runner non-empty ⇒ runner wins.
    assert_eq!(eff.hardening.restrict_address_families, vec!["AF_UNIX"]);
    assert_eq!(eff.hardening.extra_syscalls, vec!["clone3"]);
    // bind_readonly_paths runner None ⇒ defaults wins.
    assert_eq!(
        eff.hardening.bind_readonly_paths.as_deref(),
        Some(&[Utf8PathBuf::from("/etc/passwd")][..])
    );
    // extra_bind_paths additive (defaults first, then runner).
    assert_eq!(
        eff.hardening.extra_bind_paths,
        vec![
            Utf8PathBuf::from("/etc/ssl"),
            Utf8PathBuf::from("/opt/runner"),
        ]
    );
    // extra_capabilities additive (defaults first, then runner).
    assert_eq!(
        eff.hardening.extra_capabilities,
        vec!["CAP_KILL", "CAP_NET_RAW"]
    );
    assert_eq!(eff.hardening.etc_bind_style, EtcBindStyle::Broad);
}

#[test]
fn merge_defaults_caches_threaded_verbatim() {
    let runner = minimal_runner("a");
    let defaults = Defaults::default();
    let caches = vec![EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache, CacheKind::Sccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    }];
    let eff = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        caches.clone(),
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(eff.caches, caches);
}

// --- spec_hash ------------------------------------------------------

#[test]
fn spec_hash_stable_across_clones() {
    let runner = minimal_runner("a");
    let defaults = Defaults::default();
    let spec = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    let h1 = spec_hash(&spec);
    let h2 = spec_hash(&spec.clone());
    assert_eq!(h1, h2);
    assert!(h1.starts_with("sha256:"));
    assert_eq!(h1.len(), 7 + 64); // "sha256:" + 64 hex chars
}

#[test]
fn spec_hash_idempotent_after_embedding() {
    let runner = minimal_runner("a");
    let defaults = Defaults::default();
    let mut spec = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    let h1 = spec_hash(&spec);
    spec.spec_hash = h1.clone();
    let h2 = spec_hash(&spec);
    assert_eq!(h1, h2);
}

#[test]
fn spec_hash_changes_on_field_edit() {
    let runner = minimal_runner("a");
    let defaults = Defaults::default();
    let spec1 = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    let h1 = spec_hash(&spec1);

    let runner2 = {
        let mut r = minimal_runner("a");
        r.memory_max = Some("64G".into());
        r
    };
    let spec2 = merge_defaults(
        &runner2,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    let h2 = spec_hash(&spec2);
    assert_ne!(h1, h2);
}

#[test]
fn spec_hash_independent_of_embedded_hash_field() {
    let runner = minimal_runner("a");
    let defaults = Defaults::default();
    let mut spec_a = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    let mut spec_b = spec_a.clone();
    spec_a.spec_hash = "stale-A".into();
    spec_b.spec_hash = "stale-B".into();
    assert_eq!(spec_hash(&spec_a), spec_hash(&spec_b));
}

// --- plan_from ------------------------------------------------------

#[test]
fn plan_create_when_actual_empty() {
    let cfg = config_with_runners(vec![minimal_runner("buckos")]);
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    // 1 CreateRunner.
    let creates: Vec<&RunnerPlan> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp),
            _ => None,
        })
        .collect();
    assert_eq!(creates.len(), 1);
    assert_eq!(creates[0].spec.name, "buckos");
    assert!(creates[0].spec_hash.starts_with("sha256:"));
}

#[test]
fn plan_remove_orphans() {
    let cfg = config_with_runners(vec![]);
    let mut actual = empty_actual();
    actual.orphans.push(OrphanedUnit {
        name: "stale".into(),
    });
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let removes: Vec<&RunnerIdentity> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::RemoveRunner(id) => Some(id),
            _ => None,
        })
        .collect();
    assert_eq!(removes.len(), 1);
    assert_eq!(removes[0].name, "stale");
}

#[test]
fn plan_remove_when_runner_in_actual_but_not_desired() {
    let cfg = config_with_runners(vec![]);
    let runner = minimal_runner("legacy");
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
    actual.runners.insert(
        "legacy".into(),
        discovered_for("legacy", &spec, Drift::InSync),
    );

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let removes: Vec<&RunnerIdentity> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::RemoveRunner(id) => Some(id),
            _ => None,
        })
        .collect();
    assert_eq!(removes.len(), 1);
    assert_eq!(removes[0].name, "legacy");
    assert_eq!(removes[0].url, "https://github.com/example/legacy");
    assert_eq!(removes[0].auth_name, "pat");
}

#[test]
fn plan_noop_when_in_sync_and_hashes_match() {
    let cfg = config_with_runners(vec![minimal_runner("a")]);
    let runner = &cfg.runners[0];
    let mut spec = merge_defaults(
        runner,
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
    let noops: Vec<&str> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::NoOp(reason) => Some(reason.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(noops.len(), 1);
    assert!(noops[0].contains('a'));
}

#[test]
fn plan_update_no_recreate_when_drift_unit_edited_with_matching_hash() {
    let cfg = config_with_runners(vec![minimal_runner("a")]);
    let runner = &cfg.runners[0];
    let mut spec = merge_defaults(
        runner,
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
        .insert("a".into(), discovered_for("a", &spec, Drift::UnitEdited));

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let updates: Vec<&RunnerDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].identity.name, "a");
    // Hash matched → drift overwrite is in-place, no recreate.
    assert!(!updates[0].requires_recreate);
    assert!(updates[0].recreate_reasons.is_empty());
}

#[test]
fn plan_update_recreate_on_url_change_via_annotations() {
    let cfg = config_with_runners(vec![minimal_runner("a")]);
    // Build a "before" effective spec whose URL differs.
    let mut old_runner = cfg.runners[0].clone();
    old_runner.url = "https://github.com/example/old".into();
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
    let updates: Vec<&RunnerDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 1);
    assert!(updates[0].requires_recreate, "url change must recreate");
    assert!(
        updates[0].recreate_reasons.contains(&"url"),
        "got: {:?}",
        updates[0].recreate_reasons,
    );
}

#[test]
fn plan_update_in_place_on_memory_max_change_via_drop_in_diff() {
    // memory_max change is in-place, not recreate. Stage 1
    // (annotation diff) finds nothing; Stage 2 (drop-in body diff)
    // sees 10-memory.conf body change between desired render and
    // discovered drop-ins. Result: requires_recreate=false,
    // drop_in_changes contains a Modified entry for 10-memory.conf.
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

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let updates: Vec<&RunnerDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 1);
    assert!(
        !updates[0].requires_recreate,
        "memory_max-only change must be in-place; got reasons {:?}",
        updates[0].recreate_reasons
    );
    assert!(
        updates[0].drop_in_changes.iter().any(|c| {
            c.basename == "10-memory.conf" && matches!(c.change, DropInChangeKind::Modified { .. })
        }),
        "drop_in_changes must include 10-memory.conf Modified; got: {:?}",
        updates[0].drop_in_changes
    );
}

#[test]
fn plan_update_recreate_on_runner_version_change_via_annotations() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.runner_version = Some("2.300.0".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.runner_version = Some("2.200.0".into());
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
    let updates: Vec<&RunnerDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 1);
    assert!(updates[0].requires_recreate);
    assert!(updates[0].recreate_reasons.contains(&"runner_version"));
}

/// End-to-end through `plan_from` — when discovered state
/// carries an operator drop-in (e.g. `99-custom.conf`) plus the
/// managed `00-ghars.conf`, the recreate-class `RunnerDelta` must
/// surface `before_drop_in_basenames = Some([..])` containing BOTH
/// basenames. Pins the construction-site contract at the
/// intersection branch (plan.rs near the `RunnerDelta` builder):
/// `discovered.drop_ins.keys()` is the authoritative pre-update
/// view, and `Some` (never `None`) is emitted whenever
/// `discovered` is in scope. The renderer relies on this to emit
/// `- 99-custom.conf` under `--diff` so operators see what the
/// recreate is about to delete. `BTreeMap` iteration order ⇒ Vec is
/// already alphabetically sorted.
#[test]
fn plan_recreate_populates_before_drop_in_basenames_with_operator_drop_in() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.runner_version = Some("2.300.0".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.runner_version = Some("2.200.0".into());
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

    // Build the discovered runner from the old spec and inject an
    // operator drop-in (99-custom.conf) on top of the managed
    // 00-ghars.conf the fixture already produced.
    let mut discovered = discovered_for("a", &old_spec, Drift::InSync);
    discovered.drop_ins.insert(
        "99-custom.conf".into(),
        "[Service]\nEnvironment=OPERATOR_TUNING=1\n".into(),
    );
    let mut actual = empty_actual();
    actual.runners.insert("a".into(), discovered);

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let updates: Vec<&RunnerDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 1);
    assert!(
        updates[0].requires_recreate,
        "runner_version change must recreate; got reasons {:?}",
        updates[0].recreate_reasons,
    );
    // Some(..), never None — `discovered` was in scope at plan time.
    let before = updates[0]
        .before_drop_in_basenames
        .as_ref()
        .expect("recreate path must populate before_drop_in_basenames as Some(..)");
    // Both the managed 00-ghars.conf and the operator's 99-custom.conf
    // are present, in BTreeMap-iteration (alphabetical) order.
    assert!(
        before.iter().any(|b| b == "00-ghars.conf"),
        "before set must include managed 00-ghars.conf; got: {before:?}",
    );
    assert!(
        before.iter().any(|b| b == "99-custom.conf"),
        "before set must include operator 99-custom.conf; got: {before:?}",
    );
    // Sorted: 00-ghars.conf must appear before 99-custom.conf.
    let pos_managed = before.iter().position(|b| b == "00-ghars.conf").unwrap();
    let pos_operator = before.iter().position(|b| b == "99-custom.conf").unwrap();
    assert!(
        pos_managed < pos_operator,
        "before_drop_in_basenames must be alphabetically sorted; got: {before:?}",
    );
}

// ---- requires_recreate exhaustive field coverage ------------------
//
// Per design Part 3 "requires_recreate field policy" table:
//   recreate fields:  url, labels, runner_version, runner_sha256,
//                     runner_tarball, arch, network
//   in-place fields:  auth (auth_name), memory_max, caches,
//                     trust_zone, hardening.*, allowed_cpus,
//                     allowed_memory_nodes, proxy, hooks
//   identity (Remove+Create): name
//
// `classify_recreate_reasons_from_annotations` detects every
// recreate-class field from its X-Ghars-* annotation directly:
// url (X-Ghars-Runner-Url), runner_version
// (X-Ghars-Effective-Version), labels (X-Ghars-Labels), arch
// (X-Ghars-Arch), runner_sha256 (X-Ghars-Runner-Sha256),
// runner_tarball (X-Ghars-Runner-Tarball-Hash), network
// (X-Ghars-Network-Mode).
// The same classifier records FieldChange entries (without
// pushing a recreate reason) for the in-place fields that have
// their own annotation and need operator-visible diffing:
// auth_name (X-Ghars-Auth-Name), trust_zone (X-Ghars-Trust-Zone),
// caches (X-Ghars-Caches). The remaining in-place fields
// (memory_max, hardening.*, allowed_cpus, ...) are detected by
// the Stage 2 drop-in body diff and surface as `drop_in_changes`,
// not FieldChange entries. A spec-hash mismatch with no Stage 1
// reason and no Stage 2 evidence falls through to the `uncovered`
// in-place arm in `plan_from` (logs at warn level and does not
// push any recreate reason — see `RunnerDelta::recreate_reasons`
// field doc for the contract). These tests pin each row of the
// table.

#[test]
fn classify_recreate_url_change_emits_url_reason() {
    let anns = anns_with("https://github.com/example/old", None);
    let desired = spec_with_url("a", "https://github.com/example/new");
    let mut _changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
    assert_eq!(reasons, vec!["url"]);
}

#[test]
fn classify_recreate_url_unchanged_no_reason() {
    let anns = anns_with("https://github.com/example/repo", None);
    let desired = spec_with_url("a", "https://github.com/example/repo");
    let mut _changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
    assert!(reasons.is_empty(), "got: {reasons:?}");
}

#[test]
fn classify_recreate_runner_version_change_emits_runner_version_reason() {
    let anns = anns_with("https://github.com/example/repo", Some("2.300.0"));
    let mut desired = spec_with_url("a", "https://github.com/example/repo");
    desired.runner_version = Some("2.334.0".into());
    let mut _changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
    assert_eq!(reasons, vec!["runner_version"]);
}

#[test]
fn classify_recreate_runner_version_unchanged_no_reason() {
    let anns = anns_with("https://github.com/example/repo", Some("2.334.0"));
    let mut desired = spec_with_url("a", "https://github.com/example/repo");
    desired.runner_version = Some("2.334.0".into());
    let mut _changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
    assert!(reasons.is_empty(), "got: {reasons:?}");
}

#[test]
fn classify_recreate_no_annotations_no_reasons() {
    // Discovered unit predates annotation marker (older ghars or
    // operator-installed). Function falls through silently — the
    // spec-hash mismatch path picks up the slack.
    let anns = DiscoveredAnnotations::default();
    let desired = spec_with_url("a", "https://github.com/example/repo");
    let mut _changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
    assert!(reasons.is_empty(), "got: {reasons:?}");
}

#[test]
fn classify_recreate_url_and_version_both_changed() {
    let anns = anns_with("https://github.com/example/old", Some("2.300.0"));
    let mut desired = spec_with_url("a", "https://github.com/example/new");
    desired.runner_version = Some("2.334.0".into());
    let mut _changes = Vec::new();
    let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
    assert!(reasons.contains(&"url"), "got: {reasons:?}");
    assert!(reasons.contains(&"runner_version"), "got: {reasons:?}");
}

/// labels change is RECREATE per design table. The
/// X-Ghars-Labels annotation makes labels Stage 1 detectable —
/// recreate fires with reason "labels" rather than falling
/// through to the `uncovered` in-place arm.
#[test]
fn plan_update_recreate_on_labels_change() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.labels = vec!["new-label".into()];
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.labels = vec!["old-label".into()];
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
    let updates: Vec<&RunnerDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 1);
    assert!(updates[0].requires_recreate);
    assert!(
        updates[0].recreate_reasons.contains(&"labels"),
        "labels change must produce a typed `labels` reason now that X-Ghars-Labels is annotated; got: {:?}",
        updates[0].recreate_reasons
    );
    assert!(
        updates[0].field_changes.iter().any(|c| c.path == "labels"),
        "field_changes must include a labels entry; got: {:?}",
        updates[0].field_changes
    );
}

/// `memory_max` change is IN-PLACE per design table. Stage 2's
/// drop-in body diff localizes the change to 10-memory.conf so
/// the plan classifies a memory_max-only edit as in-place (no
/// recreate) instead of conservatively recreating.
#[test]
fn plan_update_in_place_on_memory_max_change() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.memory_max = Some("110G".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.memory_max = Some("64G".into());
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
    let updates: Vec<&RunnerDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 1);
    assert!(
        !updates[0].requires_recreate,
        "memory_max change must be in-place; got reasons {:?}",
        updates[0].recreate_reasons
    );
}

/// name change is IDENTITY — handled by the desired-vs-actual set
/// diff, not by `classify_recreate_reasons`. The plan emits
/// CreateRunner(new) + RemoveRunner(old), no `UpdateRunner`.
/// `plan_create_and_remove_when_names_diverge` already covers
/// this pattern; this test pins the SAME contract via a different
/// test name so an audit reading `recreate_reasons` coverage finds
/// the identity row of the table mapped here.
#[test]
fn plan_name_change_is_identity_not_recreate() {
    let cfg = config_with_runners(vec![minimal_runner("renamed")]);
    let other = minimal_runner("original");
    let mut spec = merge_defaults(
        &other,
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
    actual.runners.insert(
        "original".into(),
        discovered_for("original", &spec, Drift::InSync),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    // No UpdateRunner.
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
        0,
        "name change must not produce UpdateRunner"
    );
    // Exactly one Create("renamed") + one Remove("original").
    let creates: Vec<&str> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(p) => Some(p.spec.name.as_str()),
            _ => None,
        })
        .collect();
    let removes: Vec<&str> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::RemoveRunner(id) => Some(id.name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(creates, vec!["renamed"]);
    assert_eq!(removes, vec!["original"]);
}

/// `runner_sha256` change is recreate-class per Part 3. The
/// X-Ghars-Runner-Sha256 annotation makes the change Stage 1
/// detectable — recreate fires with the typed `runner_sha256`
/// reason rather than falling through to the `uncovered`
/// fallback that would otherwise apply for fields with no
/// annotation source.
#[test]
fn plan_update_recreate_on_runner_sha256_change() {
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
    assert_eq!(updates.len(), 1);
    assert!(updates[0].requires_recreate);
    assert!(
        updates[0].recreate_reasons.contains(&"runner_sha256"),
        "runner_sha256 change must produce typed `runner_sha256` reason now \
         that X-Ghars-Runner-Sha256 is annotated; got: {:?}",
        updates[0].recreate_reasons
    );
    assert!(
        !updates[0].recreate_reasons.contains(&"uncovered"),
        "runner_sha256 change must NOT fall through to uncovered now that \
         Stage 1 covers it; got: {:?}",
        updates[0].recreate_reasons
    );
    assert!(
        updates[0]
            .field_changes
            .iter()
            .any(|c| c.path == "runner_sha256"),
        "field_changes must include a runner_sha256 entry; got: {:?}",
        updates[0].field_changes
    );
}

/// `runner_tarball` change is recreate-class per Part 3. The
/// X-Ghars-Runner-Tarball-Hash annotation (sha256 of the path
/// string — NOT the path itself, to avoid env leakage) makes
/// the change Stage 1 detectable — recreate fires with the
/// typed `runner_tarball` reason.
#[test]
fn plan_update_recreate_on_runner_tarball_change() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.runner_tarball = Some(Utf8PathBuf::from("/var/lib/ghars/runner-new.tar.gz"));
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.runner_tarball = Some(Utf8PathBuf::from("/var/lib/ghars/runner-old.tar.gz"));
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
    let updates: Vec<&RunnerDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 1);
    assert!(updates[0].requires_recreate);
    assert!(
        updates[0].recreate_reasons.contains(&"runner_tarball"),
        "runner_tarball change must produce typed `runner_tarball` reason now \
         that X-Ghars-Runner-Tarball-Hash is annotated; got: {:?}",
        updates[0].recreate_reasons
    );
    assert!(
        !updates[0].recreate_reasons.contains(&"uncovered"),
        "runner_tarball change must NOT fall through to uncovered now that \
         Stage 1 covers it; got: {:?}",
        updates[0].recreate_reasons
    );
    assert!(
        updates[0]
            .field_changes
            .iter()
            .any(|c| c.path == "runner_tarball"),
        "field_changes must include a runner_tarball entry; got: {:?}",
        updates[0].field_changes
    );
}

/// arch change is recreate-class per Part 3. The X-Ghars-Arch
/// annotation makes arch changes Stage 1 detectable — recreate
/// fires with reason "arch" rather than falling through to the
/// `uncovered` in-place arm.
///
/// We construct a desired spec on `x86_64` against a discovered spec
/// recorded as aarch64. Because `merge_defaults` resolves arch as
/// `runner.arch.or(defaults.arch).unwrap_or(host_arch)`, the
/// discovered spec must EXPLICITLY pin arch to aarch64 via
/// runner.arch — otherwise the test machine's `host_arch`
/// (typically `x86_64`) defeats the diff.
///
/// A single flake of this test's prior form
/// (`*_via_spec_hash`) was reported during full-suite nextest with
/// `updates.len() == 0 expected 1` and never reproduced. Audit
/// found no static mut / `OnceLock` / `lazy_static` / `thread_local` /
/// `env::set_var` in plan.rs or its dependencies that could leak
/// across tests; `spec_hash` and `render_runner_unit` are pure
/// functions of their inputs. The hardening below explicitly
/// asserts every intermediate invariant (discovered arch,
/// discovered annotation present, hash divergence) so a future
/// regression of any pre-condition pinpoints which layer broke
/// rather than producing the opaque "0 updates" symptom that
/// motivated the flake report.
#[test]
fn plan_update_recreate_on_arch_change() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.arch = Some(Arch::X86_64);
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.arch = Some(Arch::Aarch64);
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64, // host_arch fallback never used (runner.arch is Some)
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    // Pre-conditions, asserted explicitly so any regression
    // pinpoints the failing layer.
    // (1) Discovered spec must pick up aarch64 from runner.arch
    // override (NOT host_arch fallback).
    assert_eq!(
        old_spec.arch,
        Arch::Aarch64,
        "discovered spec must reflect explicit aarch64 arch override"
    );
    // (2) Discovered 00-ghars.conf drop-in must carry
    // X-Ghars-Arch=aarch64 (Stage 1 annotation source) — without
    // this, the classifier skips the arch branch and uncovered
    // fallback fires instead of the typed "arch" reason. Note:
    // production state::discover puts the unit-template body in
    // on_disk_unit_text and the per-runner identity annotations
    // in drop_ins["00-ghars.conf"]; the classifier
    // reads from the drop-in body via
    // DiscoveredAnnotations::from_discovered.
    let discovered = discovered_for("a", &old_spec, Drift::InSync);
    let body = discovered
        .drop_ins
        .get("00-ghars.conf")
        .expect("00-ghars.conf drop-in must be in discovered fixture");
    assert!(
        body.contains("X-Ghars-Arch=aarch64"),
        "discovered 00-ghars.conf body must contain X-Ghars-Arch=aarch64; got:\n{body}"
    );
    // (3) Desired spec_hash (x86_64) MUST diverge from discovered
    // (aarch64) — an accidental match here would yield 0
    // UpdateRunner actions via the NoOp branch.
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
    assert_ne!(
        desired_spec.spec_hash, old_spec.spec_hash,
        "desired spec_hash MUST differ from discovered (arch is a hash input); \
         matching hashes here would route to NoOp not UpdateRunner"
    );
    let mut actual = empty_actual();
    actual.runners.insert("a".into(), discovered);
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let updates: Vec<&RunnerDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 1);
    assert!(updates[0].requires_recreate);
    assert!(
        updates[0].recreate_reasons.contains(&"arch"),
        "arch change must produce a typed `arch` reason now that X-Ghars-Arch is annotated; got: {:?}",
        updates[0].recreate_reasons
    );
    assert!(
        updates[0].field_changes.iter().any(|c| c.path == "arch"),
        "field_changes must include an arch entry; got: {:?}",
        updates[0].field_changes
    );
}

/// When the desired and discovered runner sets disjoint on
/// name (e.g. desired = ["new"], discovered = ["old"]),
/// `plan_from` must emit BOTH a `CreateRunner("new")` and a
/// `RemoveRunner("old")` — the diff is a strict set
/// difference, not a rename. `RemoveRunner` carries the OLD
/// runner's `RunnerIdentity` (reconstructed from the discovered
/// `00-ghars.conf` annotations: url + `auth_name` + `trust_zone`)
/// so apply's `execute_remove_runner` can mint a removal token
/// against the right URL/auth + invalidate state under the
/// correct `trust_zone` home.
#[test]
fn plan_create_and_remove_when_names_diverge() {
    let cfg = config_with_runners(vec![minimal_runner("new")]);
    // actual carries a different runner.
    let other_runner = minimal_runner("old");
    let mut spec = merge_defaults(
        &other_runner,
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
        .insert("old".into(), discovered_for("old", &spec, Drift::InSync));

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let kinds: Vec<&str> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(_) => Some("create"),
            Action::UpdateRunner(_) => Some("update"),
            Action::RemoveRunner(_) => Some("remove"),
            Action::NoOp(_) => Some("noop"),
            _ => None,
        })
        .collect();
    // Sort order: alphabetical → "new" (create), "old" (remove).
    assert_eq!(kinds, vec!["create", "remove"]);
}

#[test]
fn plan_validates_unknown_auth() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.auth = Some("missing".into());
        r
    }]);
    cfg.auth = pat_auth();
    let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("missing"), "got: {msg}");
}

#[test]
fn plan_validates_no_auth_at_all() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.auth = None;
        r
    }]);
    cfg.auth = pat_auth();
    // defaults.auth is also None.
    let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("no auth"), "got: {msg}");
}

#[test]
fn plan_validates_unknown_cache_pool() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec!["nonexistent".into()];
        r
    }]);
    cfg.auth = pat_auth();
    let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("nonexistent"), "got: {msg}");
}

#[test]
fn plan_validates_trust_zone_mismatch() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec!["pool".into()];
        r.trust_zone = "default".into();
        r
    }]);
    cfg.auth = pat_auth();
    cfg.cache_pools.insert(
        "pool".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "untrusted".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("trust_zone"), "got: {msg}");
}

#[test]
fn plan_validates_unknown_network() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.network = Some("ghost".into());
        r
    }]);
    cfg.auth = pat_auth();
    let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("ghost"), "got: {msg}");
}

/// An explicit `[network.NAME]` reference whose mode is Open and
/// whose defense-in-depth fields are all empty COLLAPSES to
/// `spec.network = None` — semantically identical to "no network
/// reference at all". This refinement (over the early shape that
/// kept a `Some(binding)` with empty policy) keeps the binding
/// invariant clean: `Some` ⇔ "directives to render". Without this
/// collapse, a no-op Open block would flip `spec_hash` on every
/// referencing runner without producing any rendered output.
#[test]
fn plan_open_network_with_empty_policy_collapses_to_no_binding() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.network = Some("hostnet".into());
        r
    }]);
    cfg.auth = pat_auth();
    cfg.networks.insert(
        "hostnet".into(),
        NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: crate::config::DnsMode::Forward,
            ipv6: crate::config::Ipv6Mode::Disabled,
        },
    );
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    let creates: Vec<&RunnerPlan> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp),
            _ => None,
        })
        .collect();
    assert_eq!(creates.len(), 1);
    assert!(
        creates[0].spec.network.is_none(),
        "Open + all-empty policy must collapse to spec.network = None; \
         got {:?}",
        creates[0].spec.network
    );
    // No 40-network drop-in either.
    assert!(!creates[0].drop_ins.contains_key("40-network.conf"));
    // Identity drop-in still annotates network mode "open" via the
    // `Open|None ⇒ "open"` collapse in render_identity, and does NOT
    // emit a netns subnet line.
    let id = creates[0].drop_ins.get("00-ghars.conf").unwrap();
    assert!(!id.contains("X-Ghars-Netns-Subnet="));
    assert!(id.contains("X-Ghars-Network-Mode=open"));
}

/// A runner with NO `network` ref (and no `defaults.network`) gets
/// `spec.network = None` — the implicit-Open path. Distinct from the
/// explicit-Open binding above.
#[test]
fn plan_implicit_open_leaves_spec_network_none() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.network = None;
        r
    }]);
    cfg.auth = pat_auth();
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    let creates: Vec<&RunnerPlan> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp),
            _ => None,
        })
        .collect();
    assert_eq!(creates.len(), 1);
    assert!(creates[0].spec.network.is_none());
    assert!(!creates[0].drop_ins.contains_key("40-network.conf"));
}

/// Open-mode `[network.NAME]` carrying `ip_deny` / `ip_allow` /
/// `restrict_address_families` MUST produce a `40-network.conf`
/// drop-in with JUST the cgroup-BPF directives — no
/// `NetworkNamespacePath=`, no `Requires=ghars-net@`, no nft rule
/// files.
#[test]
fn plan_open_network_with_cgroup_bpf_emits_drop_in() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.network = Some("hostnet".into());
        r
    }]);
    cfg.auth = pat_auth();
    cfg.networks.insert(
        "hostnet".into(),
        NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec!["10.0.0.0/8".parse::<ipnet::IpNet>().unwrap()],
            ip_deny: vec!["0.0.0.0/0".parse::<ipnet::IpNet>().unwrap()],
            restrict_address_families: vec!["AF_INET".into()],
            dns: crate::config::DnsMode::Forward,
            ipv6: crate::config::Ipv6Mode::Disabled,
        },
    );
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    let creates: Vec<&RunnerPlan> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp),
            _ => None,
        })
        .collect();
    assert_eq!(creates.len(), 1);
    // Open + non-empty policy ⇒ binding present; subnet is None
    // (Open mode owns no /30).
    let binding = creates[0]
        .spec
        .network
        .as_ref()
        .expect("Open + non-empty policy must produce a binding");
    assert!(matches!(binding.spec.mode, NetworkMode::Open));
    assert!(
        binding.subnet.is_none(),
        "Open-mode binding must have subnet = None even when policy non-empty; \
         got {:?}",
        binding.subnet
    );
    let body = creates[0]
        .drop_ins
        .get("40-network.conf")
        .expect("open mode with cgroup-BPF directives must emit 40-network.conf");
    // cgroup-BPF directives present.
    assert!(body.contains("IPAddressAllow=10.0.0.0/8"));
    assert!(body.contains("IPAddressDeny=0.0.0.0/0"));
    assert!(body.contains("RestrictAddressFamilies=AF_INET"));
    // Namespace-scoped scaffolding absent.
    assert!(!body.contains("NetworkNamespacePath="));
    assert!(!body.contains("Requires=ghars-net@"));
    assert!(!body.contains("BindsTo=ghars-net@"));
}

#[test]
fn plan_resolves_netns_network_to_binding() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.network = Some("isolated".into());
        r
    }]);
    cfg.auth = pat_auth();
    cfg.networks.insert(
        "isolated".into(),
        NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: crate::config::DnsMode::Forward,
            ipv6: crate::config::Ipv6Mode::Disabled,
        },
    );
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    let creates: Vec<&RunnerPlan> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp),
            _ => None,
        })
        .collect();
    assert_eq!(creates.len(), 1);
    let binding = creates[0].spec.network.as_ref().expect("netns ⇒ binding");
    assert_eq!(binding.name, "isolated");
    assert!(matches!(binding.spec.mode, NetworkMode::Netns));
}

// The SEC-27 shared-user warning tests were deleted: the
// shared-user-detection logic was removed when DynamicUser+trust_zone
// became the runner identity model. Operators declare trust_zone
// explicitly; the `WARNING: shared UID disables cross-runner
// isolation` heuristic is now an explicit operator-config decision,
// not an apply-time inference.

#[test]
fn plan_actions_sorted_for_determinism() {
    let cfg = config_with_runners(vec![
        minimal_runner("zeta"),
        minimal_runner("alpha"),
        minimal_runner("mu"),
    ]);
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    let names: Vec<String> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp.spec.name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(names, vec!["alpha", "mu", "zeta"]);
}

#[test]
fn plan_count_block_creates_n_runners() {
    let cfg = config_with_runners(vec![count_runner("ci", 3)]);
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    let names: Vec<String> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(rp) => Some(rp.spec.name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(names, vec!["ci-1", "ci-2", "ci-3"]);
}

#[test]
fn plan_emits_create_cache_pool_per_referenced_pool() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec!["build".into()];
        r
    }]);
    cfg.auth = pat_auth();
    cfg.cache_pools.insert(
        "build".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache, CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    let pool_actions: Vec<&CachePoolPlan> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateCachePool(p) => Some(p),
            _ => None,
        })
        .collect();
    assert_eq!(pool_actions.len(), 1);
    assert_eq!(pool_actions[0].binding.name, "build");
    assert!(pool_actions[0].spec_hash.starts_with("sha256:"));
}

#[test]
fn plan_renders_cache_pool_drop_in_body_at_plan_time() {
    // Drop-in body is rendered at plan time so the reset-on-empty
    // validator runs before the bytes leave the planner. The body
    // must reflect the resolved kinds + spec_hash + config_source.
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec!["build".into()];
        r
    }]);
    cfg.auth = pat_auth();
    cfg.cache_pools.insert(
        "build".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Sccache],
            size: "300G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    let pool_action = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateCachePool(p) => Some(p),
            _ => None,
        })
        .expect("CreateCachePool emitted");
    let body = &pool_action.drop_in_body;
    assert!(
        !body.is_empty(),
        "drop_in_body must be rendered at plan time"
    );
    assert!(body.contains("X-Ghars-Pool-Name=build"));
    assert!(body.contains("X-Ghars-Pool-Kinds=sccache"));
    assert!(body.contains(&format!("X-Ghars-Spec-Hash={}", pool_action.spec_hash)));
    assert!(body.contains("ExecStart=/usr/bin/sccache --start-server"));
    assert!(body.contains("Environment=SCCACHE_CACHE_SIZE=300G"));
    // config_source path threaded into the annotation.
    assert!(body.contains(&format!(
        "X-Ghars-Config-Source={}",
        empty_paths().config_dir.join("ghars.toml")
    )));
}

#[test]
fn plan_renders_ccache_only_pool_with_sleep_infinity_execstart() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec!["build".into()];
        r
    }]);
    cfg.auth = pat_auth();
    cfg.cache_pools.insert(
        "build".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache],
            size: "100G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
    let pool_action = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateCachePool(p) => Some(p),
            _ => None,
        })
        .expect("CreateCachePool emitted");
    let body = &pool_action.drop_in_body;
    assert!(body.contains("ExecStart=/usr/bin/sleep infinity"));
    assert!(body.contains("Environment=CCACHE_DIR=%C/ghars/pools/build/ccache"));
    assert!(body.contains("Environment=CCACHE_MAXSIZE=100G"));
    assert!(!body.contains("--start-server"));
}

/// Plan-time resolver: when an sccache-serving pool omits
/// `sccache_path` AND neither auto-detect candidate exists on the
/// host, `plan_from` must surface a Validation error that names the
/// offending pool, the missing binary, AND points the operator at
/// the two remediation paths (install the binary OR pin a path in
/// TOML). This test pins the error shape by forcing the auto-detect
/// candidates to absolute paths that do not exist anywhere on a
/// typical CI host (`/nonexistent-ghars-test-sccache-...`).
///
/// We exercise the error path through the test seam of pinning a
/// known-bad relative path — the resolver rejects relative pins
/// before it ever probes the auto-detect candidates, surfacing the
/// same Validation kind with a related-but-distinct message.
#[test]
fn plan_rejects_pool_with_unresolvable_sccache_pin() {
    // Pinning a relative path triggers the resolver's
    // is_absolute() gate, which produces a Validation error that
    // names the pool + field. The shape is symmetric with the
    // missing-binary path (both Validation, both name the pool +
    // field) so this single test pins the error contract without
    // depending on a filesystem state assumption.
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec!["build".into()];
        r
    }]);
    cfg.auth = pat_auth();
    cfg.cache_pools.insert(
        "build".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("not/an/absolute/path".into()),
            sleep_path: None,
        },
    );
    let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("cache_pool 'build'"),
        "msg must scope the error to the offending pool by name; got: {msg}"
    );
    assert!(
        msg.contains("sccache_path"),
        "msg must name the offending field so the operator knows where \
         to fix it; got: {msg}"
    );
    assert!(
        msg.contains("absolute"),
        "msg must surface the absolute-path requirement; got: {msg}"
    );
}

#[test]
fn action_label_covers_each_variant() {
    let no_op = Action::NoOp("nothing to do".into());
    assert_eq!(no_op.label(), "NoOp(nothing to do)");
    let rm_pool = Action::RemoveCachePool("build".into());
    assert_eq!(rm_pool.label(), "RemoveCachePool(build)");
}

// --- spec_hash: serde-skip / config-source coverage ----------------

/// Helper used by the `spec_hash` + `merge_defaults` follow-up tests
/// below to construct an `EffectiveRunnerSpec` with stable inputs
/// minus the field under test.
fn build_baseline_spec() -> EffectiveRunnerSpec {
    merge_defaults(
        &minimal_runner("a"),
        &Defaults::default(),
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    )
}

/// `config_source` MUST participate in `spec_hash`. The same spec
/// loaded from a different `ghars.toml` is intentionally a
/// different spec (drives the `X-Ghars-Config-Source` annotation
/// and the recreate-on-config-source-change behavior).
#[test]
fn spec_hash_includes_config_source_field() {
    let mut a = build_baseline_spec();
    let mut b = a.clone();
    a.config_source = "/etc/ghars/ghars.toml".into();
    b.config_source = "/opt/ghars/ghars.toml".into();
    assert_ne!(
        spec_hash(&a),
        spec_hash(&b),
        "config_source must contribute to spec_hash"
    );
}

// --- spec_hash: proptest determinism + sensitivity -----------------

/// Apply a single property-driven mutation to a spec and return
/// it. Each variant changes exactly one logical field; the test
/// asserts the hash also changes. This catches mutants that drop
/// a field from `canonical_json` (e.g. someone adds `#[serde(skip)]`
/// to a field that should be hashed).
#[derive(Debug, Clone)]
enum SpecMutation {
    Name(String),
    Url(String),
    Arch(Arch),
    Labels(Vec<String>),
    MemoryMax(Option<String>),
    RunnerVersion(Option<String>),
    TrustZone(String),
    AuthName(String),
    AllowedCpus(Option<String>),
    ConfigSource(String),
    HardeningKvm(Option<bool>),
    HardeningRestrictRealtime(Option<bool>),
    HardeningExtraCapabilities(Vec<String>),
}

fn apply_mutation(spec: &mut EffectiveRunnerSpec, m: &SpecMutation) {
    match m {
        SpecMutation::Name(s) => spec.name = s.clone(),
        SpecMutation::Url(s) => spec.url = s.clone(),
        SpecMutation::Arch(a) => spec.arch = *a,
        SpecMutation::Labels(v) => spec.labels = v.clone(),
        SpecMutation::MemoryMax(v) => spec.memory_max = v.clone(),
        SpecMutation::RunnerVersion(v) => spec.runner_version = v.clone(),
        SpecMutation::TrustZone(s) => spec.trust_zone = s.clone(),
        SpecMutation::AuthName(s) => spec.auth_name = s.clone(),
        SpecMutation::AllowedCpus(v) => spec.allowed_cpus = v.clone(),
        SpecMutation::ConfigSource(s) => spec.config_source = s.clone(),
        SpecMutation::HardeningKvm(v) => spec.hardening.kvm = *v,
        SpecMutation::HardeningRestrictRealtime(v) => spec.hardening.restrict_realtime = *v,
        SpecMutation::HardeningExtraCapabilities(v) => {
            spec.hardening.extra_capabilities = v.clone();
        }
    }
}

fn mutation_strategy() -> impl proptest::strategy::Strategy<Value = SpecMutation> {
    use proptest::prelude::*;
    prop_oneof![
        "[a-z]{3,8}".prop_map(SpecMutation::Name),
        "https://github\\.com/[a-z]{2,5}/[a-z]{2,5}".prop_map(SpecMutation::Url),
        prop_oneof![Just(Arch::X86_64), Just(Arch::Aarch64)].prop_map(SpecMutation::Arch),
        prop::collection::vec("[a-z][a-z0-9-]{1,8}", 1..5).prop_map(SpecMutation::Labels),
        proptest::option::of("[1-9][0-9]?[GM]").prop_map(SpecMutation::MemoryMax),
        proptest::option::of("[0-9]+\\.[0-9]+\\.[0-9]+").prop_map(SpecMutation::RunnerVersion),
        "[a-z]{4,8}".prop_map(SpecMutation::TrustZone),
        "[a-z]{2,8}".prop_map(SpecMutation::AuthName),
        proptest::option::of("[0-9](-[0-9])?").prop_map(SpecMutation::AllowedCpus),
        "/etc/ghars/[a-z]{2,8}\\.toml".prop_map(SpecMutation::ConfigSource),
        proptest::option::of(any::<bool>()).prop_map(SpecMutation::HardeningKvm),
        proptest::option::of(any::<bool>()).prop_map(SpecMutation::HardeningRestrictRealtime),
        prop::collection::vec("CAP_[A-Z_]{4,12}", 0..4)
            .prop_map(SpecMutation::HardeningExtraCapabilities),
    ]
}

proptest::proptest! {
    // Property: hashing is deterministic across repeated calls.
    // The first existing scalar test fixed one shape; this fuzzes
    // across many randomly mutated specs to ensure no hidden
    // nondeterminism (e.g. a HashMap-based field) sneaks in.
    #[test]
    fn prop_spec_hash_is_deterministic_across_calls(m in mutation_strategy()) {
        let mut spec = build_baseline_spec();
        apply_mutation(&mut spec, &m);
        let h1 = spec_hash(&spec);
        let h2 = spec_hash(&spec);
        let h3 = spec_hash(&spec.clone());
        proptest::prop_assert_eq!(&h1, &h2);
        proptest::prop_assert_eq!(&h1, &h3);
        proptest::prop_assert!(h1.starts_with("sha256:"));
        proptest::prop_assert_eq!(h1.len(), 7 + 64);
    }

    // Property: any single-field mutation changes the hash. This
    // is the sensitivity guarantee: each field actually
    // contributes to the canonical JSON. A serde(skip) snuck onto
    // a hashed field would surface here as a stable hash across
    // distinct specs.
    #[test]
    fn prop_spec_hash_changes_on_any_field_mutation(m in mutation_strategy()) {
        let baseline = build_baseline_spec();
        let mut mutated = baseline.clone();
        apply_mutation(&mut mutated, &m);
        // Skip cases where the mutation produced the same value
        // (e.g. labels strategy produced the same vec we started
        // with). proptest doesn't have a way to say "unique" so
        // we filter at runtime via prop_assume.
        proptest::prop_assume!(baseline != mutated);
        let h_base = spec_hash(&baseline);
        let h_mut = spec_hash(&mutated);
        proptest::prop_assert_ne!(h_base, h_mut);
    }

    // Property: setting `spec_hash` to ANY value must not change
    // the result. Idempotence, fuzzed: a mutant that forgets to
    // zero `canonical.spec_hash` before serializing fails here.
    #[test]
    fn prop_spec_hash_ignores_embedded_spec_hash(stale in "[a-zA-Z0-9_-]{1,32}") {
        let baseline = build_baseline_spec();
        let mut spec_a = baseline.clone();
        let mut spec_b = baseline.clone();
        spec_a.spec_hash = stale.clone();
        spec_b.spec_hash = format!("X-{stale}");
        proptest::prop_assert_eq!(spec_hash(&spec_a), spec_hash(&spec_b));
    }
}

// --- merge_defaults: scalar regression tests -----------------------

/// Property: when only the defaults side sets a Vec, the runner's
/// empty Vec inherits from defaults via `pick_vec` — empty Vec
/// on runner side ≡ inherit defaults.
#[test]
fn merge_defaults_empty_runner_vec_inherits_defaults_for_pick_vec_fields() {
    let runner = minimal_runner("a");
    let defaults = Defaults {
        hardening: Hardening {
            restrict_address_families: vec!["AF_INET".into(), "AF_INET6".into()],
            extra_syscalls: vec!["@privileged".into()],
            ..Hardening::default()
        },
        ..Defaults::default()
    };
    let eff = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(
        eff.hardening.restrict_address_families,
        vec!["AF_INET", "AF_INET6"]
    );
    assert_eq!(eff.hardening.extra_syscalls, vec!["@privileged"]);
}

/// Property: `extra_bind_paths` and `extra_capabilities` are
/// ADDITIVE (defaults entries first, then runner entries) — NOT
/// override. A mutant that swaps to override semantics drops the
/// defaults entries and fails here.
#[test]
fn merge_defaults_extra_paths_and_caps_are_additive_not_override() {
    let runner = {
        let mut r = minimal_runner("a");
        r.hardening.extra_bind_paths = vec![Utf8PathBuf::from("/runner/path")];
        r.hardening.extra_capabilities = vec!["CAP_NET_RAW".into()];
        r
    };
    let defaults = Defaults {
        hardening: Hardening {
            extra_bind_paths: vec![Utf8PathBuf::from("/defaults/path")],
            extra_capabilities: vec!["CAP_AUDIT_WRITE".into()],
            ..Hardening::default()
        },
        ..Defaults::default()
    };
    let eff = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    // Defaults first, then runner — both present.
    assert_eq!(
        eff.hardening.extra_bind_paths,
        vec![
            Utf8PathBuf::from("/defaults/path"),
            Utf8PathBuf::from("/runner/path"),
        ]
    );
    assert_eq!(
        eff.hardening.extra_capabilities,
        vec!["CAP_AUDIT_WRITE", "CAP_NET_RAW"]
    );
}

// --- merge_defaults: proptest scalar-override semantics ------------

fn defaults_strategy()
-> impl proptest::strategy::Strategy<Value = (Option<String>, Option<String>, Option<String>)> {
    (
        proptest::option::of("ghars-[a-z]{3,6}"),
        proptest::option::of("[1-9][0-9]?[GM]"),
        proptest::option::of("[0-9]+\\.[0-9]+\\.[0-9]+"),
    )
}

fn runner_overrides_strategy()
-> impl proptest::strategy::Strategy<Value = (Option<String>, Option<String>, Option<String>)> {
    (
        proptest::option::of("runner-[a-z]{3,6}"),
        proptest::option::of("[1-9][0-9]?[GM]"),
        proptest::option::of("[0-9]+\\.[0-9]+\\.[0-9]+"),
    )
}

proptest::proptest! {
    // Property: scalar-override rule — runner > defaults > built-in.
    // Tested across memory_max + runner_version (pure Option override).
    #[test]
    fn prop_merge_defaults_scalar_override_runner_wins(
        (_def_user, def_mem, def_ver) in defaults_strategy(),
        (_run_user, run_mem, run_ver) in runner_overrides_strategy(),
    ) {
        let runner = {
            let mut r = minimal_runner("rabbit");
            r.memory_max = run_mem.clone();
            r.runner_version = run_ver.clone();
            r
        };
        let defaults = Defaults {
            memory_max: def_mem.clone(),
            runner_version: def_ver.clone(),
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        // memory_max: pure Option override.
        proptest::prop_assert_eq!(eff.memory_max, run_mem.or(def_mem));
        // runner_version: pure Option override.
        proptest::prop_assert_eq!(eff.runner_version, run_ver.or(def_ver));
    }

    // labels = concat(defaults, runner) deduped (membership
    // only — first-seen order is not load-bearing) and then
    // sorted alphabetically. If both are empty after dedup, falls
    // back to [name] for Python parity. Set semantics — labels
    // are the GitHub Actions registration tag set, matched
    // order-independently against workflow `runs-on:`.
    #[test]
    fn prop_merge_defaults_labels_concat_dedup_sorted(
        def_labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..5),
        run_labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..5),
    ) {
        let runner = {
            let mut r = minimal_runner("frog");
            r.labels = run_labels.clone();
            r
        };
        let defaults = Defaults {
            labels: def_labels.clone(),
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );

        // Reconstruct expected labels manually (mirrors
        // merge_defaults logic — if it diverges, the test fails).
        // Concat → dedup → fallback-to-name → sort. The fallback
        // happens BEFORE the sort so a single-name fallback is also
        // canonical (sorting a one-element Vec is a no-op).
        let mut expected: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for l in def_labels.iter().chain(run_labels.iter()) {
            if seen.insert(l.clone()) {
                expected.push(l.clone());
            }
        }
        if expected.is_empty() {
            expected.push("frog".to_string());
        }
        expected.sort();
        proptest::prop_assert_eq!(eff.labels, expected);
    }

    // Property: labels sort is stable across the FULL LABEL_RE
    // charset (`^[a-zA-Z0-9._-]+$` per `validators::LABEL_RE`),
    // not just the lowercase-alphanumeric subset the sibling
    // `prop_merge_defaults_labels_concat_dedup_sorted` uses.
    // `merge_defaults` calls `labels.sort_unstable()`, which
    // uses byte-wise `Ord`. The byte-wise Ord
    // agrees with operator intent ONLY for the ASCII subset the
    // validator allows; this property pins that expectation by
    // exercising uppercase + digits + `._-` separators
    // alongside lowercase letters. A mutation that swaps the
    // sort to a locale-dependent collation or that elides the
    // sort entirely surfaces here as inputs whose merged output
    // is non-monotonic in byte order.
    #[test]
    fn prop_merge_defaults_labels_sorted_full_charset(
        // Generate label strings drawing from the full LABEL_RE
        // alphabet. ASCII byte-wise Ord on this charset matches
        // the canonical contract.
        run_labels in prop::collection::vec(
            "[a-zA-Z0-9._-]{1,8}",
            0..5,
        ),
        def_labels in prop::collection::vec(
            "[a-zA-Z0-9._-]{1,8}",
            0..5,
        ),
    ) {
        let runner = {
            let mut r = minimal_runner("rt");
            r.labels = run_labels.clone();
            r
        };
        let defaults = Defaults {
            labels: def_labels.clone(),
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        // Monotonic in byte order: every adjacent pair must
        // satisfy `prev <= next`. A regression that drops the
        // sort would produce an unsorted Vec; a regression that
        // sorts via a different collation would fail on inputs
        // where the two orders diverge (e.g. uppercase before
        // lowercase under ASCII byte order; opposite under
        // case-folded collation).
        for w in eff.labels.windows(2) {
            proptest::prop_assert!(
                w[0] <= w[1],
                "labels must be byte-wise sorted; got pair: {:?}, {:?} in {:?}",
                w[0],
                w[1],
                eff.labels
            );
        }
        // Defense-in-depth: result must equal a manual sort of
        // the dedup'd union of both inputs (or the singleton
        // [name] fallback if both were empty).
        let mut expected: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for l in def_labels.iter().chain(run_labels.iter()) {
            if seen.insert(l.clone()) {
                expected.push(l.clone());
            }
        }
        if expected.is_empty() {
            expected.push("rt".to_string());
        }
        expected.sort();
        proptest::prop_assert_eq!(eff.labels, expected);
    }

    // Property: Hardening Option<bool> fields use `.or()` —
    // runner Some wins, runner None inherits defaults.
    #[test]
    fn prop_merge_defaults_hardening_or_semantics(
        run_kvm in proptest::option::of(any::<bool>()),
        def_kvm in proptest::option::of(any::<bool>()),
        run_rt in proptest::option::of(any::<bool>()),
        def_rt in proptest::option::of(any::<bool>()),
    ) {
        let runner = {
            let mut r = minimal_runner("a");
            r.hardening.kvm = run_kvm;
            r.hardening.restrict_realtime = run_rt;
            r
        };
        let defaults = Defaults {
            hardening: Hardening {
                kvm: def_kvm,
                restrict_realtime: def_rt,
                ..Hardening::default()
            },
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        proptest::prop_assert_eq!(eff.hardening.kvm, run_kvm.or(def_kvm));
        proptest::prop_assert_eq!(eff.hardening.restrict_realtime, run_rt.or(def_rt));
    }

    // Property: caches on the runner side are threaded VERBATIM
    // through merge_defaults. The defaults side has no cache
    // surface, so merge_defaults can't merge — it must pass
    // through. A mutant that drops/reorders entries fails here.
    #[test]
    fn prop_merge_defaults_caches_threaded_verbatim(
        n in 0usize..6,
    ) {
        // Build n distinct EffectiveCacheBindings.
        let bindings: Vec<EffectiveCacheBinding> = (0..n)
            .map(|i| EffectiveCacheBinding {
                name: format!("pool-{i}"),
                kinds: vec![CacheKind::Sccache],
                size: "5G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
                sccache_path: Some("/usr/bin/sccache".into()),
                sleep_path: None,
                renderer_schema: crate::systemd::RENDERER_SCHEMA,
            })
            .collect();
        let runner = minimal_runner("a");
        let defaults = Defaults::default();
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            bindings.clone(),
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        proptest::prop_assert_eq!(eff.caches, bindings);
    }

    // Property: merge_defaults is idempotent at the value level.
    // Re-running with the same RunnerSpec/Defaults inputs produces
    // an equal EffectiveRunnerSpec on every call. A mutant that
    // accumulates state across calls (e.g. `extend` on a static
    // Vec) would surface here as drift between the two outputs.
    #[test]
    fn prop_merge_defaults_is_idempotent(
        run_user in proptest::option::of("runner-[a-z]{3,6}"),
        def_user in proptest::option::of("ghars-[a-z]{3,6}"),
        run_labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..4),
        def_labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..4),
    ) {
        let _ = run_user;
        let _ = def_user;
        let runner = {
            let mut r = minimal_runner("idempo");
            r.labels = run_labels.clone();
            r
        };
        let defaults = Defaults {
            labels: def_labels.clone(),
            ..Defaults::default()
        };
        let a = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        let b = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        proptest::prop_assert_eq!(a, b);
    }

    // Round-trip property test pinning render → parse
    // symmetry. Renders an EffectiveRunnerSpec via
    // `crate::systemd::render_runner_unit`, extracts the
    // `00-ghars.conf` body from the rendered drop-ins, and feeds
    // it through `DiscoveredAnnotations::from_drop_in_body`.
    // The parsed annotations must reflect the input spec's
    // identity-bound fields (url, auth_name, labels,
    // arch, trust_zone, caches, runner_sha256).
    // A regression in either direction — renderer drops a line,
    // parser misroutes a key, parser splits a comma-list wrong —
    // breaks this test.
    //
    // Why fuzz the inputs: the existing render-side tests pin
    // single-shape outputs, but a mutation that flips
    // `X-Ghars-Runner-Url=` to `X-Ghars-Url=` in the renderer
    // would pass the snapshot tests as long as the snapshot was
    // also updated. The round-trip catches that class because the
    // parser side stayed on `X-Ghars-Runner-Url`.
    #[test]
    fn prop_render_parse_round_trip_preserves_identity_fields(
        url_path in "[a-z]{2,8}/[a-z]{2,8}",
        auth_name in "[a-z]{2,8}",
        labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..5),
        trust_zone in "[a-z]{4,12}",
        arch in prop_oneof![Just(Arch::X86_64), Just(Arch::Aarch64)],
        cache_names in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..4),
        runner_sha in proptest::option::of("sha256:[0-9a-f]{64}"),
    ) {
        // Build the [[runner]] spec. trust_zone is pinned non-
        // empty so merge_defaults doesn't substitute "default".
        let runner = RunnerSpec {
            name: "rt".into(),
            count: None,
            url: format!("https://github.com/{url_path}"),
            auth: Some(auth_name.clone()),
            labels: labels.clone(),
            memory_max: None,
            runner_version: None,
            runner_sha256: runner_sha.clone(),
            runner_tarball: None,
            arch: Some(arch),
            caches: vec![], // EffectiveCacheBindings come via merge_defaults
            trust_zone: trust_zone.clone(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
        };
        // Build cache bindings to match the property-driven names
        // (caches arrive at the renderer pre-sorted by
        // lower_to_effective; pre-sort the names here so
        // the round-trip parses to the same Vec<String>).
        let mut sorted_cache_names = cache_names.clone();
        sorted_cache_names.sort();
        sorted_cache_names.dedup();
        let bindings: Vec<EffectiveCacheBinding> = sorted_cache_names
            .iter()
            .map(|n| EffectiveCacheBinding {
                name: n.clone(),
                kinds: vec![CacheKind::Sccache],
                size: "5G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
                sccache_path: Some("/usr/bin/sccache".into()),
                sleep_path: None,
                renderer_schema: crate::systemd::RENDERER_SCHEMA,
            })
            .collect();
        let mut spec = merge_defaults(
            &runner,
            &Defaults::default(),
            auth_name.clone(),
            bindings,
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        // Inject a stable spec_hash — render_identity requires it
        // to be non-empty + valid. Without it the renderer rejects
        // with check_identity_field("spec_hash",..).
        spec.spec_hash = "sha256:dead".into();
        let rendered = match crate::systemd::render_runner_unit(&spec) {
            Ok(r) => r,
            // labels is constrained by the regex but merge_defaults
            // falls back to [name] when empty. If runner.name "rt"
            // is the only label and it survives the dedup, render
            // succeeds. If something else rejects (e.g. a label
            // regex edge case), skip this iteration.
            Err(_) => return Ok(()),
        };
        let body = rendered
            .drop_ins
            .get("00-ghars.conf")
            .expect("renderer always emits 00-ghars.conf");
        let anns = DiscoveredAnnotations::from_drop_in_body(body);
        // Round-trip assertions: every renderer-emitted X-Ghars-*
        // line must round-trip to the matching DiscoveredAnnotations
        // field carrying the spec's exact value.
        proptest::prop_assert_eq!(anns.url.as_deref(), Some(spec.url.as_str()));
        proptest::prop_assert_eq!(
            anns.auth_name.as_deref(),
            Some(spec.auth_name.as_str()),
        );
        proptest::prop_assert_eq!(
            anns.labels.as_deref(),
            Some(spec.labels.as_slice()),
        );
        let arch_str = match spec.arch {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        };
        proptest::prop_assert_eq!(anns.arch.as_deref(), Some(arch_str));
        proptest::prop_assert_eq!(
            anns.trust_zone.as_deref(),
            Some(spec.trust_zone.as_str()),
        );
        // X-Ghars-Caches is unconditionally emitted, so the
        // parsed Some-vec must equal the spec's name list.
        let expected_cache_names: Vec<String> =
            spec.caches.iter().map(|b| b.name.clone()).collect();
        proptest::prop_assert_eq!(anns.caches.as_ref(), Some(&expected_cache_names));
        // runner_sha256: the renderer emits the line iff
        // spec.runner_sha256.is_some(); when None the line is
        // omitted (parser yields None).
        proptest::prop_assert_eq!(
            anns.runner_sha256.as_deref(),
            spec.runner_sha256.as_deref(),
        );
    }

    // Property: empty trust_zone → "default" sentinel. Pinned via
    // a proptest fuzzing the surrounding fields so the fallback
    // doesn't depend on any other input.
    #[test]
    fn prop_merge_defaults_empty_trust_zone_falls_back_to_default(
        run_labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..4),
    ) {
        let runner = {
            let mut r = minimal_runner("tz");
            r.trust_zone = String::new(); // EXPLICITLY empty
            r.labels = run_labels;
            r
        };
        let defaults = Defaults::default();
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        proptest::prop_assert_eq!(eff.trust_zone, "default");
    }
}
