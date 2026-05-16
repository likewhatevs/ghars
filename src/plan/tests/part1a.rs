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
/// that DIFFERENT `renderer_schema` values produce DIFFERENT
/// hashes; it does NOT verify the production spec-construction
/// site reads the runtime constant. A refactor that hardcoded
/// `renderer_schema: 1` in `merge_defaults` would silently break
/// the post-fix hash-participation contract (`RENDERER_SCHEMA`
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

/// Companion to `merge_defaults_populates_renderer_schema_from_runtime_constant`
/// covering the OTHER construction site that builds an
/// `EffectiveCacheBinding`: `into_cache_pool_plan` in
/// `plan/compute.rs`. A refactor that hardcoded the value here
/// would silently break the cache-pool drop-in rewrite cascade on
/// `RENDERER_SCHEMA` bumps (`cache_pool_hash` would not flip), even
/// though the `merge_defaults` test continues to pass.
#[test]
fn into_cache_pool_plan_populates_renderer_schema_from_runtime_constant() {
    let pool = CachePoolSpec {
        kinds: vec![CacheKind::Ccache],
        size: "10G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
    };
    let plan = into_cache_pool_plan("build".into(), &pool, "/etc/ghars/ghars.toml")
        .expect("into_cache_pool_plan must succeed for a ccache-only pool");
    assert_eq!(
        plan.binding.renderer_schema,
        crate::systemd::RENDERER_SCHEMA,
        "into_cache_pool_plan must populate renderer_schema from the runtime \
         crate::systemd::RENDERER_SCHEMA constant; a hardcoded literal would \
         silently break the cache-pool drop-in rewrite cascade on \
         RENDERER_SCHEMA bumps (cache_pool_hash would not flip)"
    );
}

/// Permutation invariance of `cache_pool_hash` across operator-
/// supplied `[cache_pools.NAME].kinds` Vec order. The renderer-side
/// defensive sort at `render_cache_drop_in` makes the rendered
/// drop-in body byte-stable across operator TOML reorders; this
/// test pins the matching upstream sort at `into_cache_pool_plan`
/// so the embedded `X-Ghars-Spec-Hash` annotation stays equal too.
/// Without the upstream sort, `cache_pool_hash` (`serde_json::to_value`
/// preserves `Vec` order) flipped between equivalent operator configs
/// and triggered spurious `UpdateCachePool` plan actions with empty
/// drop-in body diffs.
///
/// Two `CachePoolSpec` fixtures differing ONLY in `kinds` Vec order
/// — `[Sccache, Ccache]` vs `[Ccache, Sccache]` — must produce
/// identical `CachePoolPlan.spec_hash` values.
///
/// Sister to the `caches`-Vec permutation invariance at
/// `lower_to_effective` (per-runner caches sorted by name during
/// cache-pool resolution).
#[test]
fn into_cache_pool_plan_kinds_permutation_invariant_for_spec_hash() {
    let base = CachePoolSpec {
        kinds: vec![CacheKind::Sccache, CacheKind::Ccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
    };
    let permuted = CachePoolSpec {
        kinds: vec![CacheKind::Ccache, CacheKind::Sccache],
        ..base.clone()
    };

    let plan_base = into_cache_pool_plan("build".into(), &base, "/etc/ghars/ghars.toml")
        .expect("into_cache_pool_plan must succeed for a sccache+ccache pool");
    let plan_permuted = into_cache_pool_plan("build".into(), &permuted, "/etc/ghars/ghars.toml")
        .expect("into_cache_pool_plan must succeed for the permuted-kinds variant");

    assert_eq!(
        plan_base.spec_hash, plan_permuted.spec_hash,
        "into_cache_pool_plan must canonicalize the kinds Vec so \
         cache_pool_hash is permutation-invariant across operator \
         TOML reorders of [cache_pools.NAME].kinds; otherwise a \
         cosmetic ordering swap triggers a spurious UpdateCachePool \
         plan action with an empty drop-in body diff. Sister to the \
         renderer-site defensive sort in render_cache_drop_in."
    );

    assert_eq!(
        plan_base.drop_in_body, plan_permuted.drop_in_body,
        "with both upstream + renderer-site sorts in place, the \
         rendered drop-in body must also be byte-identical across \
         permuted-kinds fixtures (full body-byte invariance, matching \
         the labels + caches + pool-kinds defensive-sort triplet)."
    );
}

/// Runner-side sister of
/// `into_cache_pool_plan_kinds_permutation_invariant_for_spec_hash`.
/// The pool-side test pins the `cache_pool_hash` invariant via
/// `into_cache_pool_plan`; this test pins the matching `spec_hash`
/// invariant via the runner-side `lower_to_effective` construction
/// path.
///
/// Without canonicalization at the `lower_to_effective` inner loop
/// (the per-binding `EffectiveCacheBinding` construction site for
/// each pool a runner references), `EffectiveRunnerSpec.caches[i].kinds`
/// stays in operator TOML order. `spec_hash` then includes the
/// preserved Vec order via canonical-JSON serde, so an operator
/// reorder of `[cache_pools.NAME].kinds = ["sccache", "ccache"]`
/// ↔ `["ccache", "sccache"]` flipped the runner's `spec_hash` and
/// triggered spurious `UpdateRunner` plans for every runner that
/// bound the pool — much wider blast radius than just the
/// `cache_pool_hash` desync that the `into_cache_pool_plan` site
/// solves alone.
///
/// `canonicalize_kinds()` (called at BOTH `EffectiveCacheBinding`
/// construction sites — `lower_to_effective` and
/// `into_cache_pool_plan`) makes both `spec_hash` and
/// `cache_pool_hash` permutation-invariant.
#[test]
fn lower_to_effective_kinds_permutation_invariant_for_runner_spec_hash() {
    fn build_cfg(pool_kinds: Vec<CacheKind>) -> Config {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("buckos");
            r.caches = vec!["build".into()];
            r
        }]);
        cfg.auth = pat_auth();
        cfg.cache_pools.insert(
            "build".into(),
            CachePoolSpec {
                kinds: pool_kinds,
                size: "200G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
                sccache_path: Some("/usr/bin/sccache".into()),
                sleep_path: None,
            },
        );
        cfg
    }

    let cfg_base = build_cfg(vec![CacheKind::Sccache, CacheKind::Ccache]);
    let cfg_permuted = build_cfg(vec![CacheKind::Ccache, CacheKind::Sccache]);

    let expanded_base = expand_counts(&cfg_base).expect("count expansion must succeed");
    let expanded_permuted = expand_counts(&cfg_permuted).expect("count expansion must succeed");

    let eff_base = lower_to_effective(
        &expanded_base[0],
        &cfg_base,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
        0,
    )
    .expect("lower_to_effective must succeed for the base [Sccache, Ccache] fixture");

    let eff_permuted = lower_to_effective(
        &expanded_permuted[0],
        &cfg_permuted,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
        0,
    )
    .expect("lower_to_effective must succeed for the permuted [Ccache, Sccache] fixture");

    assert_eq!(
        eff_base.caches[0].kinds, eff_permuted.caches[0].kinds,
        "lower_to_effective must canonicalize the kinds Vec on each \
         EffectiveCacheBinding so EffectiveRunnerSpec.caches stays \
         byte-stable across operator [cache_pools.NAME].kinds reorders; \
         got base={:?} permuted={:?}",
        eff_base.caches[0].kinds, eff_permuted.caches[0].kinds,
    );

    assert_eq!(
        spec_hash(&eff_base),
        spec_hash(&eff_permuted),
        "spec_hash must be permutation-invariant across operator \
         [cache_pools.NAME].kinds reorders; otherwise every runner \
         binding the pool sees a spurious UpdateRunner plan when the \
         operator cosmetically reorders the kinds list. Sister to the \
         into_cache_pool_plan_kinds_permutation_invariant_for_spec_hash \
         test for the pool-side cache_pool_hash."
    );
}

/// Companion to `merge_defaults_populates_renderer_schema_from_runtime_constant`
/// covering the THIRD construction site: the inner loop of
/// `lower_to_effective` that builds an `EffectiveCacheBinding` per
/// pool the runner references. Two-binding fixture so a future
/// refactor that hardcoded the constant for one iteration (loop
/// unroll, first-iteration optimization) is still caught.
#[test]
fn lower_to_effective_populates_renderer_schema_on_every_cache_binding() {
    // Two bindings of different kinds (1 ccache + 1 sccache) so
    // the runner passes the `validate_no_duplicate_cache_kinds`
    // gate in lower_to_effective. The loop being tested iterates
    // all bindings regardless of kind, so a 1c+1s fixture proves
    // the same "later iterations populate renderer_schema" property
    // as the historical 2-ccache fixture.
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("buckos");
        r.caches = vec!["pool-a".into(), "pool-b".into()];
        r
    }]);
    cfg.auth = pat_auth();
    cfg.cache_pools.insert(
        "pool-a".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    cfg.cache_pools.insert(
        "pool-b".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Sccache],
            size: "20G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );

    let expanded = expand_counts(&cfg).expect("count expansion must succeed");
    let eff = lower_to_effective(
        &expanded[0],
        &cfg,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
        0,
    )
    .expect("lower_to_effective must succeed for a two-pool runner");
    assert_eq!(
        eff.caches.len(),
        2,
        "fixture sanity: runner must resolve to exactly 2 cache bindings"
    );
    for binding in &eff.caches {
        assert_eq!(
            binding.renderer_schema,
            crate::systemd::RENDERER_SCHEMA,
            "every cache binding from lower_to_effective must populate \
             renderer_schema from the runtime constant; binding `{name}` \
             got {actual}, expected {expected}",
            name = binding.name,
            actual = binding.renderer_schema,
            expected = crate::systemd::RENDERER_SCHEMA,
        );
    }
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

/// `merge_defaults` threads the caller-supplied `caches` Vec into
/// `EffectiveRunnerSpec.caches` verbatim — no sort, no dedup, no
/// reordering. The lowering layer (`lower_to_effective`'s
/// `caches.sort_by(|a, b| a.name.cmp(&b.name))` block) is the
/// source-of-truth sort site for caches; `merge_defaults` is just
/// the bind-bag assembler called from below the sort. Direct
/// `merge_defaults` callers (test fixtures, future synthetic spec
/// builders) must sort their own caches Vec if they care about
/// hash stability across operator-supplied orderings.
///
/// Pins both shape and order:
/// - Single-element fixture catches Vec-corrupting regressions
///   (e.g. accidental drop or duplicate inside `merge_defaults`).
/// - Three-element non-canonical-order fixture catches
///   sort-introducing regressions: if `merge_defaults` silently
///   added `caches.sort_by_name()`, the 1-element check would still
///   pass (trivially sorted), but the 3-element check would observe
///   the input order `[pool-z, pool-a, pool-m]` flatten to canonical
///   `[pool-a, pool-m, pool-z]` and fail.
#[test]
fn merge_defaults_caches_threaded_verbatim() {
    let runner = minimal_runner("a");
    let defaults = Defaults::default();

    // Single-element shape pin (catches Vec-corrupting regressions).
    let single = vec![EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache, CacheKind::Sccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    }];
    let eff_single = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        single.clone(),
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(eff_single.caches, single);

    // Three-element non-canonical-order pin (catches
    // sort-introducing regressions in merge_defaults). Names chosen
    // in lex-descending order ["pool-z", "pool-a", "pool-m"] — if
    // merge_defaults silently sorted, eff.caches would surface as
    // lex-ascending ["pool-a", "pool-m", "pool-z"] and the assertion
    // would fail.
    let multi = vec![
        EffectiveCacheBinding {
            name: "pool-z".into(),
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        },
        EffectiveCacheBinding {
            name: "pool-a".into(),
            kinds: vec![CacheKind::Sccache],
            size: "5G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        },
        EffectiveCacheBinding {
            name: "pool-m".into(),
            kinds: vec![CacheKind::Ccache],
            size: "20G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        },
    ];
    let eff_multi = merge_defaults(
        &runner,
        &defaults,
        "pat".into(),
        multi.clone(),
        None,
        None,
        None,
        Arch::X86_64,
        "/etc/ghars/ghars.toml".into(),
    );
    assert_eq!(
        eff_multi.caches, multi,
        "merge_defaults must thread caches verbatim (no sort, no dedup, no reorder); \
         a regression that introduced sort here would flatten the non-canonical \
         order [pool-z, pool-a, pool-m] to canonical [pool-a, pool-m, pool-z]"
    );
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
    // Both old and new specs must carry runner_version because
    // lower_to_effective rejects tarball-pinned runners that don't
    // pin a version (validates the broken-from-birth case where
    // the tarball install would name bin.local but the unit drop-in
    // would reference bin.latest).
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.runner_tarball = Some(Utf8PathBuf::from("/var/lib/ghars/runner-new.tar.gz"));
        r.runner_version = Some("2.334.0".into());
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

/// `lower_to_effective` MUST reject a runner that sets
/// `runner_tarball` but no `runner_version` (on the runner AND no
/// `defaults.runner_version`). The apply path's tarball install
/// names the on-disk bin dir as `bin.{runner_version}` and the unit
/// drop-in interpolates the same version into `WorkingDirectory=`,
/// `ExecStart=`, and `ConditionPathExists=`. Without a `runner_version`
/// the install falls back to `bin.local/` while the drop-in falls
/// back to `bin.latest/`, so systemd's `ConditionPathExists=` fails
/// and the unit silently refuses to start (broken-from-birth).
///
/// The reject happens at plan time so the operator gets an actionable
/// error before any disk mutation.
#[test]
fn plan_rejects_runner_tarball_without_runner_version() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.runner_tarball = Some(Utf8PathBuf::from("/var/lib/ghars/runner.tar.gz"));
        // No runner_version on the runner, no defaults.runner_version.
        r
    }]);
    let actual = empty_actual();
    let err = plan_from(&cfg, &actual, &empty_paths())
        .expect_err("plan_from must reject tarball-pinned runner without runner_version");
    let msg = format!("{err}");
    assert!(
        msg.contains("runner_tarball") && msg.contains("runner_version"),
        "error must name both runner_tarball and runner_version; got: {msg}"
    );
    assert!(
        msg.contains("'a'"),
        "error must name the specific runner; got: {msg}"
    );
}

/// Sibling to `plan_rejects_runner_tarball_without_runner_version`:
/// the same tarball-pinned runner WITH `defaults.runner_version`
/// MUST be accepted. `merge_defaults`'s `runner_version`
/// `or_else(|| defaults.runner_version.clone())` inheritance block
/// fills the per-runner `runner_version` from `[defaults]`,
/// satisfying the `lower_to_effective` validation gate without
/// requiring the operator to repeat the version on every runner.
#[test]
fn plan_accepts_runner_tarball_when_defaults_pin_runner_version() {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.runner_tarball = Some(Utf8PathBuf::from("/var/lib/ghars/runner.tar.gz"));
        r
    }]);
    cfg.defaults.runner_version = Some("2.334.0".into());
    let actual = empty_actual();
    let plan = plan_from(&cfg, &actual, &empty_paths())
        .expect("plan_from must accept tarball-pinned runner with defaults.runner_version");
    // Confirm the CreateRunner was emitted (and not silently
    // dropped / converted to NoOp).
    let creates: Vec<_> = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::CreateRunner(_)))
        .collect();
    assert_eq!(
        creates.len(),
        1,
        "expected one CreateRunner; got actions: {:?}",
        plan.actions
    );
    if let Action::CreateRunner(p) = creates[0] {
        assert_eq!(
            p.spec.runner_version.as_deref(),
            Some("2.334.0"),
            "merge_defaults must inherit runner_version from defaults"
        );
    }
}
