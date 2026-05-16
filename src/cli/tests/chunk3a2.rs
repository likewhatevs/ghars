//! chunk3a continued: dispatch + `cmd_completions` + `cmd_init` coverage.
#![allow(clippy::unwrap_used)]

use super::*;

/// dispatch's Completions arm should return Ok(0) — the
/// `clap_complete::generate` write to stdout is infallible (in
/// the sense that the writer is `io::stdout()` which doesn't
/// surface errors back to the caller in this code path), and
/// the dispatch arm wraps in `Ok(0)` after the call. Pin so a
/// future refactor that returns the wrong exit code surfaces.
/// Note: this writes to the test runner's captured stdout.
#[test]
fn dispatch_completions_returns_ok_zero() {
    let cli = Cli::try_parse_from(["ghars", "completions", "bash"]).unwrap();
    let exit = dispatch(cli).expect("completions must succeed");
    assert_eq!(exit, 0);
}

/// dispatch's `NetnsVeth` arm propagates `run_in_netns`'s empty-
/// program rejection. Pins the wiring; complementary to
/// `netns::tests::run_in_netns_rejects_empty_program` which
/// covers the helper directly.
#[test]
fn dispatch_netns_veth_propagates_empty_program_rejection() {
    // clap's `trailing_var_arg` requires the trailing program
    // arg, but we can synthesize an empty program by hand.
    let cli = Cli {
        config: Utf8PathBuf::from("/etc/ghars/ghars.toml"),
        no_color: false,
        quiet: false,
        verbose: 0,
        command: Command::NetnsVeth {
            instance: "buckos".into(),
            program: Vec::new(),
        },
    };
    let err = dispatch(cli).unwrap_err();
    // run_in_netns surfaces a Validation error; dispatch
    // bubbles it up unwrapped.
    assert!(
        matches!(err, GharsError::Validation(_, _)),
        "expected Validation, got {err:?}"
    );
}

// -------- trust_zone charset validator ------------------------------

/// Helper for the `trust_zone` tests: build the minimal Config that
/// `validate_identity_fields` expects, then mutate the runner /
/// pool's `trust_zone` in-place. We bypass `toml::from_str` because
/// embedding raw `\n` / `\0` in a TOML basic string would also be
/// rejected by the parser before our validator ran — we want to
/// prove our validator catches the chars, not that TOML happens to
/// reject the literal escape sequences.

/// A `runner.trust_zone` containing `\n` must be rejected at
/// config-load by `validate_identity_fields`. Without this gate
/// the only check would be `render_identity`, which surfaces the
/// error during `plan` rather than `validate` and without the
/// `runner "NAME"` scope prefix the operator needs to locate the
/// offending block.
#[test]
fn validate_identity_fields_rejects_runner_trust_zone_with_newline() {
    let cfg = cfg_with_runner_trust_zone("buckos", "secure\nzone".into());
    let err = validate_identity_fields(&cfg).expect_err("must reject newline");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner") && msg.contains("buckos"),
                "msg must scope to the offending runner; got: {msg}"
            );
            assert!(
                msg.contains("trust_zone") && msg.contains("newline"),
                "msg must name the field + char class; got: {msg}"
            );
            // Config-load gate is NOT render_identity. The
            // bare check_identity_field error must not bake in the
            // render_identity prefix, and validate_identity_fields
            // must not accidentally route through render_identity.
            assert!(
                !msg.contains("render_identity"),
                "msg must NOT contain \"render_identity\" prefix at \
                 config-load time; got: {msg}"
            );
            // The runner scope prefix must be adjacent to
            // `field "trust_zone"` — no infix between them.
            // Catches a regression that re-introduces a
            // function-name prefix between the block scope and
            // the field name.
            assert!(
                msg.contains("runner \"buckos\": field"),
                "msg must contain `runner \"buckos\": field` as adjacent \
                 substring (no infix between scope and field); got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// A `runner.trust_zone` containing `\0` (NUL byte) must be
/// rejected. Pinned alongside the newline test because NUL is a
/// distinct branch in `check_identity_field`'s NUL-class branch
/// — a future regression that broadened the newline check but
/// dropped NUL would slip past the newline-only test.
#[test]
fn validate_identity_fields_rejects_runner_trust_zone_with_nul() {
    let cfg = cfg_with_runner_trust_zone("buckos", "zone\0nul".into());
    let err = validate_identity_fields(&cfg).expect_err("must reject NUL byte");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner") && msg.contains("buckos"),
                "msg must scope to the offending runner; got: {msg}"
            );
            assert!(
                msg.contains("trust_zone") && msg.contains("NUL"),
                "msg must name the field + char class; got: {msg}"
            );
            // Config-load gate must NOT emit "render_identity:" prefix.
            assert!(
                !msg.contains("render_identity"),
                "msg must NOT contain \"render_identity\" prefix at \
                 config-load time; got: {msg}"
            );
            // Adjacent-substring pin — runner scope must be
            // directly followed by `field`, no infix.
            assert!(
                msg.contains("runner \"buckos\": field"),
                "msg must contain `runner \"buckos\": field` as adjacent \
                 substring (no infix between scope and field); got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// A `[cache_pools.NAME].trust_zone` containing `\n` must be
/// rejected with the `cache_pool "NAME":` scope prefix. The runner
/// branch is exercised by the two tests above; this test pins the
/// SECOND iteration in `validate_identity_fields` (the one over
/// `cfg.cache_pools`). Without this test the cleaner could remove
/// the `cache_pool` loop and only the runner tests would notice.
#[test]
fn validate_identity_fields_rejects_cache_pool_trust_zone_with_newline() {
    // Reuse the runner-flavored fixture for everything but the
    // cache_pools map, which we attach with a single
    // newline-injected pool.
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "build".into(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "secure\nzone".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );
    let err = validate_identity_fields(&cfg).expect_err("must reject newline");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("cache_pool") && msg.contains("build"),
                "msg must scope to the offending cache_pool; got: {msg}"
            );
            assert!(
                msg.contains("trust_zone") && msg.contains("newline"),
                "msg must name the field + char class; got: {msg}"
            );
            // Config-load gate must NOT emit "render_identity:" prefix.
            assert!(
                !msg.contains("render_identity"),
                "msg must NOT contain \"render_identity\" prefix at \
                 config-load time; got: {msg}"
            );
            // Adjacent-substring pin — cache_pool scope must be
            // directly followed by `field`, no infix.
            assert!(
                msg.contains("cache_pool \"build\": field"),
                "msg must contain `cache_pool \"build\": field` as adjacent \
                 substring (no infix between scope and field); got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

// -------- trust_zone length cap ----------------------------------

/// A runner `trust_zone` of exactly `TRUST_ZONE_MAX_LEN` chars MUST
/// pass — the cap is inclusive (the longest accepted, not
/// exclusive). Pins that the comparison is `>` not `>=`.
#[test]
fn validate_trust_zone_lengths_accepts_runner_at_max_len() {
    let at_max = "a".repeat(crate::validators::TRUST_ZONE_MAX_LEN);
    let cfg = cfg_with_runner_trust_zone("buckos", at_max.clone());
    validate_trust_zone_lengths(&cfg).unwrap_or_else(|e| {
        panic!(
            "{}-char (== TRUST_ZONE_MAX_LEN) runner trust_zone must accept; \
             got: {e}",
            crate::validators::TRUST_ZONE_MAX_LEN
        )
    });
}

/// A runner `trust_zone` one char past `TRUST_ZONE_MAX_LEN` MUST
/// reject. Error message must (a) scope to the offending runner,
/// (b) echo the offending value, (c) name the cap, and (d) cite
/// the systemd 31-char ceiling so the operator understands why.
#[test]
fn validate_trust_zone_lengths_rejects_runner_one_past_max_len() {
    let oversize = "a".repeat(crate::validators::TRUST_ZONE_MAX_LEN + 1);
    let cfg = cfg_with_runner_trust_zone("buckos", oversize.clone());
    let err = validate_trust_zone_lengths(&cfg).expect_err("must reject");
    match err {
        GharsError::Validation(msg, hint) => {
            assert!(
                msg.contains("runner \"buckos\"") && msg.contains(&oversize),
                "msg must scope to the offending runner by name and echo \
                 the trust_zone value; got: {msg}"
            );
            assert!(
                msg.contains("trust_zone") && msg.contains("too long"),
                "msg must name the field and the cap class; got: {msg}"
            );
            assert!(
                msg.contains(&crate::validators::TRUST_ZONE_MAX_LEN.to_string()),
                "msg must echo the cap value; got: {msg}"
            );
            assert!(
                msg.contains("31-char") || msg.contains("ghars-tz-"),
                "msg must cite the systemd ceiling or the User= prefix \
                 so the operator understands the constraint; got: {msg}"
            );
            assert!(
                hint.contains(&crate::validators::TRUST_ZONE_MAX_LEN.to_string()),
                "hint must restate the cap; got: {hint}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// A `cache_pool` `trust_zone` of exactly `TRUST_ZONE_MAX_LEN` chars
/// MUST pass — symmetric to the runner-side acceptance test.
#[test]
fn validate_trust_zone_lengths_accepts_cache_pool_at_max_len() {
    let at_max = "a".repeat(crate::validators::TRUST_ZONE_MAX_LEN);
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "build".into(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: at_max,
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );
    validate_trust_zone_lengths(&cfg).unwrap_or_else(|e| {
        panic!(
            "{}-char (== TRUST_ZONE_MAX_LEN) cache_pool trust_zone must \
             accept; got: {e}",
            crate::validators::TRUST_ZONE_MAX_LEN
        )
    });
}

/// A `cache_pool` `trust_zone` one char past `TRUST_ZONE_MAX_LEN` MUST
/// reject — symmetric to the runner-side rejection test, scoped
/// to the `cache_pool` surface.
#[test]
fn validate_trust_zone_lengths_rejects_cache_pool_one_past_max_len() {
    let oversize = "a".repeat(crate::validators::TRUST_ZONE_MAX_LEN + 1);
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "build".into(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: oversize.clone(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );
    let err = validate_trust_zone_lengths(&cfg).expect_err("must reject");
    match err {
        GharsError::Validation(msg, hint) => {
            assert!(
                msg.contains("cache_pool \"build\"") && msg.contains(&oversize),
                "msg must scope to the offending cache_pool by name and \
                 echo the trust_zone value; got: {msg}"
            );
            assert!(
                msg.contains("trust_zone") && msg.contains("too long"),
                "msg must name the field and the cap class; got: {msg}"
            );
            assert!(
                msg.contains(&crate::validators::TRUST_ZONE_MAX_LEN.to_string()),
                "msg must echo the cap value; got: {msg}"
            );
            assert!(
                msg.contains("31-char") || msg.contains("ghars-tz-"),
                "msg must cite the systemd ceiling or the User= prefix \
                 so the operator understands the constraint; got: {msg}"
            );
            assert!(
                hint.contains(&crate::validators::TRUST_ZONE_MAX_LEN.to_string()),
                "hint must restate the cap; got: {hint}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

// -------- config_source charset (plan-time gate) -------------------

/// `config_source` is composed at plan time from
/// `paths.config_dir.join("ghars.toml")` (`plan_from`'s `config_source`
/// synthesis). A `Paths`
/// instance with a `\n` in `config_dir` (synthesizable in tests
/// today, plumbable via a future `--config-dir` flag) must reject
/// at the start of `plan_from` before `lower_to_effective` clones
/// the value into every effective spec. Pinned because the
/// production-time guarantee that `config_dir` is hard-coded
/// (`Paths::default()` returns `/etc/ghars`) is a code-time
/// invariant, not a type-system one — a future caller that
/// constructs its own `Paths` would skip the gate without this
/// regression test.
#[test]
fn plan_from_rejects_config_source_with_newline_in_paths_config_dir() {
    // Build a minimal config that plan_from would otherwise accept
    // (one runner, one auth) and a Paths with a newline-injected
    // config_dir.
    let cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    let paths = Paths {
        config_dir: Utf8PathBuf::from("/etc/ghars\ninjected"),
        ..Paths::default()
    };
    let actual = state::ActualState::default();
    let err =
        plan::plan_from(&cfg, &actual, &paths).expect_err("config_source with newline must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("config_source") && msg.contains("newline"),
                "msg must name the field + char class; got: {msg}"
            );
            // plan_from invokes check_identity_field directly
            // (no render_identity wrapper). The bare error must
            // not carry the "render_identity:" prefix.
            assert!(
                !msg.contains("render_identity"),
                "msg must NOT contain \"render_identity\" prefix at \
                 plan_from config_source gate; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

// -------- duplicate cache references in [[runner]].caches ---------

/// `[[runner]] caches = ["build", "build"]` must reject at
/// config load. The duplicate would render two identical
/// X-Ghars-Caches comma-elements (`render_identity` joins the
/// Vec via `cache_names.join(",")`), and apply.rs canonicalizes
/// through `BTreeSet`, so plan would oscillate the `spec_hash` on
/// every re-run as the Vec equality flips between
/// duplicate-preserved and dedup-canonical forms.
#[test]
fn validate_no_duplicate_caches_rejects_repeated_pool_in_one_runner() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.runners[0].caches = vec!["build".into(), "build".into()];
    let err =
        validate_no_duplicate_caches(&cfg).expect_err("must reject duplicate cache reference");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner") && msg.contains("buckos"),
                "msg must scope to the offending runner; got: {msg}"
            );
            assert!(
                msg.contains("build") && msg.contains("duplicate"),
                "msg must name the duplicated pool + describe the issue; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// A runner with non-duplicate caches passes. Pinned so a
/// future regression that broadened the validator into rejecting
/// the multi-element happy path is caught.
#[test]
fn validate_no_duplicate_caches_accepts_distinct_pools() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.runners[0].caches = vec!["build".into(), "test".into(), "release".into()];
    validate_no_duplicate_caches(&cfg).expect("distinct cache references must pass validation");
}

/// Cross-runner reuse of the same pool is FINE — pools are
/// designed to be referenced by multiple runners
/// (`CacheMode::Shared` is `CachePoolSpec.mode`'s `#[default]`).
/// The validator must check each runner's caches independently,
/// not the union.
#[test]
fn validate_no_duplicate_caches_accepts_same_pool_across_runners() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.runners[0].caches = vec!["build".into()];
    // Add a second runner referencing the same pool.
    let mut second = cfg.runners[0].clone();
    second.name = "ci".into();
    second.url = "https://github.com/example/ci".into();
    second.caches = vec!["build".into()];
    cfg.runners.push(second);
    validate_no_duplicate_caches(&cfg).expect("cross-runner pool reuse must pass validation");
}

// -------- no duplicate cache kinds per runner ----------------------

/// A runner referencing two sccache pools must reject. The renderer
/// would emit two `Environment=SCCACHE_SERVER_UDS=` lines in the
/// 30-cache-pool drop-in; systemd's last-writer-wins Environment=
/// semantics mean the second value silently shadows the first,
/// routing every sccache call to one pool while the operator
/// expected both to receive traffic.
#[test]
fn validate_no_duplicate_cache_kinds_rejects_two_sccache_refs() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(&mut cfg, "build", vec![crate::config::CacheKind::Sccache]);
    insert_cache_pool(&mut cfg, "test", vec![crate::config::CacheKind::Sccache]);
    cfg.runners[0].caches = vec!["build".into(), "test".into()];
    let err =
        validate_no_duplicate_cache_kinds(&cfg).expect_err("must reject two sccache pool refs");
    match err {
        GharsError::Validation(msg, hint) => {
            assert!(
                msg.contains("runner") && msg.contains("buckos"),
                "msg must scope to the offending runner; got: {msg}"
            );
            assert!(
                msg.contains("sccache") && msg.contains("build") && msg.contains("test"),
                "msg must name both conflicting pools; got: {msg}"
            );
            assert!(
                hint.contains("SCCACHE_SERVER_UDS")
                    || hint.contains("last-writer")
                    || hint.contains("single-valued"),
                "hint must explain the env-clobber root cause; got: {hint}"
            );
            assert!(
                hint.contains("merge"),
                "hint must offer the merge-into-one-pool remediation; got: {hint}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// Three ccache pools on one runner must reject AND the error must
/// name ALL three pools (not just the first two). Pins the
/// `refs.join(", ")` format in the validator's error message at
/// load.rs for n>2 — a regression that took `.take(2)` on the
/// refs Vec would pass the 2-pool tests silently but break the
/// operator UX for "I bound 3 ccache pools".
#[test]
fn validate_no_duplicate_cache_kinds_rejects_three_ccache_refs_names_all() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(&mut cfg, "obj-a", vec![crate::config::CacheKind::Ccache]);
    insert_cache_pool(&mut cfg, "obj-b", vec![crate::config::CacheKind::Ccache]);
    insert_cache_pool(&mut cfg, "obj-c", vec![crate::config::CacheKind::Ccache]);
    cfg.runners[0].caches = vec!["obj-a".into(), "obj-b".into(), "obj-c".into()];
    let err =
        validate_no_duplicate_cache_kinds(&cfg).expect_err("must reject three ccache pool refs");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains('3'),
                "msg must surface the count for n>2; got: {msg}"
            );
            assert!(
                msg.contains("obj-a") && msg.contains("obj-b") && msg.contains("obj-c"),
                "msg must name ALL conflicting pools (not just first 2); got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// A runner referencing two ccache pools must reject. ccache is
/// single-`CCACHE_DIR`-per-process by upstream design
/// (`Config::read` in ccache's `src/ccache/config.cpp`); ghars wires
/// a single trust-zone-shared `CCACHE_DIR` in `.env` plus one
/// `CCACHE_MAXSIZE` per binding (last wins). Two pools cannot
/// deliver distinct cache dirs and the second pool's
/// `CCACHE_MAXSIZE` silently shadows the first. Mirror of
/// `validate_no_duplicate_cache_kinds_rejects_two_sccache_refs`.
///
/// REPLACES `validate_single_sccache_pool_per_runner_accepts_two_ccache_pools`
/// from before the generalization to per-kind enforcement: the
/// prior accept-behavior was wrong (it claimed "distinct
/// `CCACHE_DIR` values do compose" — false, the .env emits one
/// trust-zone-fixed `CCACHE_DIR`, see src/systemd/units.rs:653).
#[test]
fn validate_no_duplicate_cache_kinds_rejects_two_ccache_refs() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(&mut cfg, "obj-a", vec![crate::config::CacheKind::Ccache]);
    insert_cache_pool(&mut cfg, "obj-b", vec![crate::config::CacheKind::Ccache]);
    cfg.runners[0].caches = vec!["obj-a".into(), "obj-b".into()];
    let err =
        validate_no_duplicate_cache_kinds(&cfg).expect_err("must reject two ccache pool refs");
    match err {
        GharsError::Validation(msg, hint) => {
            assert!(
                msg.contains("runner") && msg.contains("buckos"),
                "msg must scope to the offending runner; got: {msg}"
            );
            assert!(
                msg.contains("ccache") && msg.contains("obj-a") && msg.contains("obj-b"),
                "msg must name both conflicting pools; got: {msg}"
            );
            assert!(
                hint.contains("CCACHE_DIR")
                    || hint.contains("CCACHE_MAXSIZE")
                    || hint.contains("single-CCACHE_DIR"),
                "hint must explain the ccache env-clobber root cause; got: {hint}"
            );
            assert!(
                hint.contains("merge"),
                "hint must offer the merge-into-one-pool remediation; got: {hint}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// A runner referencing a combined-kind pool (`["ccache","sccache"]`)
/// AND a ccache-only pool must reject — the combined pool contributes
/// a ccache binding, the second pool contributes another; the
/// per-kind gate trips on ccache. Pins that the validator inspects
/// resolved KINDS (each pool's `kinds.contains()`) not pool names.
#[test]
fn validate_no_duplicate_cache_kinds_rejects_combined_plus_ccache() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(
        &mut cfg,
        "build",
        vec![
            crate::config::CacheKind::Ccache,
            crate::config::CacheKind::Sccache,
        ],
    );
    insert_cache_pool(&mut cfg, "obj", vec![crate::config::CacheKind::Ccache]);
    cfg.runners[0].caches = vec!["build".into(), "obj".into()];
    let err = validate_no_duplicate_cache_kinds(&cfg)
        .expect_err("must reject combined-kind + ccache-only when both contribute ccache");
    match err {
        GharsError::Validation(msg, hint) => {
            assert!(
                msg.contains("ccache") && msg.contains("build") && msg.contains("obj"),
                "msg must name both pools contributing ccache; got: {msg}"
            );
            assert!(
                hint.contains("merge"),
                "hint must offer the merge-into-one-pool remediation \
                 even when the conflict comes from a combined-kind pool; got: {hint}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// Symmetric counterpart to `_rejects_combined_plus_ccache`: a
/// combined-kind pool (`["ccache","sccache"]`) AND an sccache-only
/// pool. The combined pool contributes one sccache binding; the
/// sccache-only pool contributes another; the per-kind gate trips
/// on sccache. Proves the per-kind tally counts combined-pool
/// contributions for either side.
#[test]
fn validate_no_duplicate_cache_kinds_rejects_combined_plus_sccache() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(
        &mut cfg,
        "build",
        vec![
            crate::config::CacheKind::Ccache,
            crate::config::CacheKind::Sccache,
        ],
    );
    insert_cache_pool(&mut cfg, "test", vec![crate::config::CacheKind::Sccache]);
    cfg.runners[0].caches = vec!["build".into(), "test".into()];
    let err = validate_no_duplicate_cache_kinds(&cfg)
        .expect_err("must reject combined-kind + sccache-only when both contribute sccache");
    match err {
        GharsError::Validation(msg, hint) => {
            assert!(
                msg.contains("sccache") && msg.contains("build") && msg.contains("test"),
                "msg must name both pools contributing sccache; got: {msg}"
            );
            assert!(
                hint.contains("merge"),
                "hint must offer merge remediation even when conflict is mixed; got: {hint}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// Two combined-kind pools on one runner: each contributes one
/// ccache binding AND one sccache binding; both per-kind tallies
/// hit 2. The validator returns the first-detected violation; we
/// don't pin which kind fires first (avoids coupling to the KINDS
/// tuple iteration order in load.rs), only that the error names
/// both pools.
#[test]
fn validate_no_duplicate_cache_kinds_rejects_two_combined_pools() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(
        &mut cfg,
        "alpha",
        vec![
            crate::config::CacheKind::Ccache,
            crate::config::CacheKind::Sccache,
        ],
    );
    insert_cache_pool(
        &mut cfg,
        "beta",
        vec![
            crate::config::CacheKind::Ccache,
            crate::config::CacheKind::Sccache,
        ],
    );
    cfg.runners[0].caches = vec!["alpha".into(), "beta".into()];
    let err =
        validate_no_duplicate_cache_kinds(&cfg).expect_err("two combined-kind pools must reject");
    match err {
        GharsError::Validation(msg, hint) => {
            assert!(
                msg.contains("alpha") && msg.contains("beta"),
                "msg must name both conflicting pools; got: {msg}"
            );
            assert!(
                msg.contains("ccache") || msg.contains("sccache"),
                "msg must name at least one offending kind; got: {msg}"
            );
            assert!(
                hint.contains("merge"),
                "hint must offer merge remediation for two-combined-pools conflict; got: {hint}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// A runner referencing one sccache pool plus one ccache-only pool
/// must pass — the per-kind gate checks each kind independently and
/// neither kind exceeds 1. Sccache binding contributes 1 sccache;
/// ccache binding contributes 1 ccache. No conflict.
#[test]
fn validate_no_duplicate_cache_kinds_accepts_one_sccache_plus_one_ccache() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(&mut cfg, "build", vec![crate::config::CacheKind::Sccache]);
    insert_cache_pool(&mut cfg, "obj", vec![crate::config::CacheKind::Ccache]);
    cfg.runners[0].caches = vec!["build".into(), "obj".into()];
    validate_no_duplicate_cache_kinds(&cfg).expect("one sccache + one ccache must pass validation");
}

/// A runner referencing one combined-kind pool (both ccache and
/// sccache in the same `[cache_pools.NAME]`) must pass. The single
/// pool contributes exactly one ccache binding + one sccache
/// binding; per-kind count = 1 for both.
#[test]
fn validate_no_duplicate_cache_kinds_accepts_one_combined_pool() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(
        &mut cfg,
        "build",
        vec![
            crate::config::CacheKind::Ccache,
            crate::config::CacheKind::Sccache,
        ],
    );
    cfg.runners[0].caches = vec!["build".into()];
    validate_no_duplicate_cache_kinds(&cfg)
        .expect("single combined-kind pool must pass validation");
}

/// Control: a runner with NO caches must pass — the most-common
/// operator config (runner with no caching at all). Guards against
/// a future over-restrictive change that misreads "zero bindings
/// per kind" as a violation.
#[test]
fn validate_no_duplicate_cache_kinds_accepts_empty_caches() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.runners[0].caches = vec![];
    validate_no_duplicate_cache_kinds(&cfg).expect("empty caches must pass validation");
}

/// Control: a runner referencing exactly one ccache pool must pass.
/// Guards against a future over-restrictive change that rejects the
/// single-ccache happy path (the most common config). Mirror of the
/// implicit single-sccache happy path covered by
/// `_accepts_cross_runner_sccache` below.
#[test]
fn validate_no_duplicate_cache_kinds_accepts_single_ccache_pool() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(&mut cfg, "obj", vec![crate::config::CacheKind::Ccache]);
    cfg.runners[0].caches = vec!["obj".into()];
    validate_no_duplicate_cache_kinds(&cfg).expect("single ccache pool must pass validation");
}

/// Cross-runner binding does NOT trip the per-runner gate. Each
/// runner is checked independently; two runners each with one sccache
/// pool (or one ccache pool) must pass even if the pools differ.
#[test]
fn validate_no_duplicate_cache_kinds_accepts_cross_runner_sccache() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(&mut cfg, "build", vec![crate::config::CacheKind::Sccache]);
    insert_cache_pool(&mut cfg, "test", vec![crate::config::CacheKind::Sccache]);
    cfg.runners[0].caches = vec!["build".into()];
    let mut second = cfg.runners[0].clone();
    second.name = "ci".into();
    second.url = "https://github.com/example/ci".into();
    second.caches = vec!["test".into()];
    cfg.runners.push(second);
    validate_no_duplicate_cache_kinds(&cfg)
        .expect("distinct sccache pool per runner must pass validation");
}

/// Cross-runner ccache binding sibling of `_accepts_cross_runner_sccache`:
/// two runners each with one ccache pool, distinct pools, must pass
/// even though the underlying trust-zone-shared `CCACHE_DIR` is the
/// same (filesystem-flock coordinates concurrent access — see
/// `validate_no_duplicate_cache_kinds` doc).
#[test]
fn validate_no_duplicate_cache_kinds_accepts_cross_runner_ccache() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(&mut cfg, "obj-a", vec![crate::config::CacheKind::Ccache]);
    insert_cache_pool(&mut cfg, "obj-b", vec![crate::config::CacheKind::Ccache]);
    cfg.runners[0].caches = vec!["obj-a".into()];
    let mut second = cfg.runners[0].clone();
    second.name = "ci".into();
    second.url = "https://github.com/example/ci".into();
    second.caches = vec!["obj-b".into()];
    cfg.runners.push(second);
    validate_no_duplicate_cache_kinds(&cfg)
        .expect("distinct ccache pool per runner must pass validation");
}

/// Unknown pool refs (referenced but not declared in
/// `[cache_pools.NAME]`) are silently skipped here — `plan_from`'s
/// unknown-pool gate surfaces them later. The validator must not
/// panic on `cfg.cache_pools.get(unknown) == None`.
#[test]
fn validate_no_duplicate_cache_kinds_skips_unknown_refs() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(&mut cfg, "build", vec![crate::config::CacheKind::Sccache]);
    insert_cache_pool(&mut cfg, "obj", vec![crate::config::CacheKind::Ccache]);
    cfg.runners[0].caches = vec![
        "build".into(),
        "no-such-pool".into(),
        "obj".into(),
        "ghost".into(),
    ];
    validate_no_duplicate_cache_kinds(&cfg)
        .expect("unknown refs must not interact with per-kind counts");
}

// -------- validate_cache_pool_kinds_nonempty ------------------------

/// Reject `[cache_pools.NAME] kinds = []` — empty Vec reaches
/// render path without contributing any per-pool emission AND fails
/// at apply-time path resolution. Operator probably meant `kinds =
/// ["ccache"]` or `kinds = ["sccache"]`. Sibling of the duplicate-
/// kinds validator; both are operator-typed-wrong-number-of-kinds
/// failure modes that the deserializer can't catch.
#[test]
fn validate_cache_pool_kinds_nonempty_rejects_empty_kinds_vec() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    // Insert pool with empty kinds (cannot go via insert_cache_pool
    // helper which always sets kinds).
    cfg.cache_pools.insert(
        "empty-kinds".into(),
        crate::config::CachePoolSpec {
            kinds: vec![],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    let err = validate_cache_pool_kinds_nonempty(&cfg)
        .expect_err("empty kinds Vec must reject at config-load");
    let msg = err.to_string();
    assert!(
        msg.contains("empty-kinds") && msg.contains("kinds = []"),
        "error must name the pool and identify the empty-kinds failure: {msg}"
    );
}

#[test]
fn validate_cache_pool_kinds_nonempty_accepts_ccache_only_pool() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(&mut cfg, "obj", vec![crate::config::CacheKind::Ccache]);
    validate_cache_pool_kinds_nonempty(&cfg).expect("single-kind ccache pool must pass validation");
}

#[test]
fn validate_cache_pool_kinds_nonempty_accepts_sccache_only_pool() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(&mut cfg, "build", vec![crate::config::CacheKind::Sccache]);
    validate_cache_pool_kinds_nonempty(&cfg)
        .expect("single-kind sccache pool must pass validation");
}

#[test]
fn validate_cache_pool_kinds_nonempty_accepts_combined_kind_pool() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(
        &mut cfg,
        "combined",
        vec![
            crate::config::CacheKind::Ccache,
            crate::config::CacheKind::Sccache,
        ],
    );
    validate_cache_pool_kinds_nonempty(&cfg)
        .expect("combined-kind pool (Ccache + Sccache) must pass validation");
}

#[test]
fn validate_cache_pool_kinds_nonempty_accepts_zero_pools() {
    let cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    // No cache_pools at all — vacuously satisfied (no pools to check).
    validate_cache_pool_kinds_nonempty(&cfg)
        .expect("config with zero cache_pools must pass validation vacuously");
}

// -------- validate_no_duplicate_kinds_within_pool -------------------

/// Reject `[cache_pools.NAME] kinds = ["ccache", "ccache"]` — the
/// Vec layer accepts the duplicate at deserialization but each cache
/// kind is single-valued per process. Duplicate within one pool's
/// kinds Vec inflates `cache_pool_hash` (`serde_json` preserves
/// duplicates) and renders to `X-Ghars-Pool-Kinds=ccache,ccache` —
/// operator-visible artifacts that misrepresent the effective set
/// without any semantic effect. Surfacing at config-load gives a
/// scoped error the operator can act on.
#[test]
fn validate_no_duplicate_kinds_within_pool_rejects_duplicate_ccache() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "dup-ccache".into(),
        crate::config::CachePoolSpec {
            kinds: vec![
                crate::config::CacheKind::Ccache,
                crate::config::CacheKind::Ccache,
            ],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    let err = validate_no_duplicate_kinds_within_pool(&cfg)
        .expect_err("duplicate ccache within one pool kinds Vec must reject");
    let msg = err.to_string();
    // Anchor on the validator's specific phrasing "declares ccache"
    // (not just "ccache") so the assertion can't pass via the pool
    // name "dup-ccache" overlapping the substring.
    assert!(
        msg.contains("dup-ccache") && msg.contains("declares `ccache`") && msg.contains("2 times"),
        "error must name the pool, the duplicated kind via 'declares `ccache`', \
         and the count: {msg}"
    );
}

/// Sister of `..._rejects_duplicate_ccache` — same validator must
/// catch within-pool duplicates of `Sccache`. The validator iterates
/// `CacheKind::ALL` so any variant in that slice is covered
/// automatically; compile-time exhaustiveness lives in
/// `CacheKind::label()` (config.rs) — adding a variant without a
/// `label()` arm breaks the build, which surfaces the need to also
/// append it to `ALL`. This test pins runtime reachability of the
/// Sccache arm so a future refactor that special-cased Ccache (or
/// accidentally dropped Sccache from `ALL`) doesn't silently regress.
#[test]
fn validate_no_duplicate_kinds_within_pool_rejects_duplicate_sccache() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "dup-sccache".into(),
        crate::config::CachePoolSpec {
            kinds: vec![
                crate::config::CacheKind::Sccache,
                crate::config::CacheKind::Sccache,
            ],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );
    let err = validate_no_duplicate_kinds_within_pool(&cfg)
        .expect_err("duplicate sccache within one pool kinds Vec must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("dup-sccache")
            && msg.contains("declares `sccache`")
            && msg.contains("2 times"),
        "error must name the pool, the duplicated sccache kind, and the count: {msg}"
    );
}

/// Sister covering the `CacheKind::Ktstr` first-class variant
/// (alongside `Ccache` and `Sccache`). The validator at
/// `validate_no_duplicate_kinds_within_pool` iterates
/// `CacheKind::ALL` (a static slice declared at config.rs alongside
/// the enum); any variant added to that slice gets the
/// duplicate-detect treatment automatically. Compile-time
/// exhaustiveness for the enum lives in `CacheKind::label()` —
/// adding a variant without a `label()` arm breaks the build,
/// which surfaces the need to also append it to `ALL` per the
/// convention pinned at config.rs. This test pins runtime
/// reachability for ktstr specifically so a future refactor that
/// special-cased one of the older kinds (or accidentally dropped
/// Ktstr from ALL) doesn't silently regress ktstr.
#[test]
fn validate_no_duplicate_kinds_within_pool_rejects_duplicate_ktstr() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "dup-ktstr".into(),
        crate::config::CachePoolSpec {
            kinds: vec![
                crate::config::CacheKind::Ktstr,
                crate::config::CacheKind::Ktstr,
            ],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    let err = validate_no_duplicate_kinds_within_pool(&cfg)
        .expect_err("duplicate ktstr within one pool kinds Vec must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("dup-ktstr") && msg.contains("declares `ktstr`") && msg.contains("2 times"),
        "error must name the pool, the duplicated ktstr kind, and the count: {msg}"
    );
}

/// Pins the count format in the error message: a regression that
/// hardcoded "2 times" instead of using the runtime `{count}`
/// would pass the ccache-pair test but produce misleading text for
/// triples or larger duplicates. This test catches the hardcoded-2
/// regression by asserting the message says "3 times" specifically.
#[test]
fn validate_no_duplicate_kinds_within_pool_rejects_triple_ccache() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "triple-ccache".into(),
        crate::config::CachePoolSpec {
            kinds: vec![
                crate::config::CacheKind::Ccache,
                crate::config::CacheKind::Ccache,
                crate::config::CacheKind::Ccache,
            ],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    let err = validate_no_duplicate_kinds_within_pool(&cfg)
        .expect_err("triple ccache within one pool kinds Vec must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("triple-ccache")
            && msg.contains("declares `ccache`")
            && msg.contains("3 times"),
        "error must report the correct count (3, not hardcoded 2): {msg}"
    );
}

/// Pins the validator's behavior when a duplicate co-occurs with
/// other distinct kinds in the same pool. The pool kinds=[Sccache,
/// Ccache, Ccache] has one duplicate (Ccache appears twice) plus one
/// other kind (Sccache). The validator must still reject — the
/// duplicate is the operator-redundant artifact even when paired
/// with legitimate other kinds. Sister case to the pure-duplicate
/// fixtures above.
#[test]
fn validate_no_duplicate_kinds_within_pool_rejects_dup_in_mixed_kinds_pool() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "mixed-dup".into(),
        crate::config::CachePoolSpec {
            kinds: vec![
                crate::config::CacheKind::Sccache,
                crate::config::CacheKind::Ccache,
                crate::config::CacheKind::Ccache,
            ],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );
    let err = validate_no_duplicate_kinds_within_pool(&cfg)
        .expect_err("duplicate ccache in mixed-kinds pool must still reject");
    let msg = err.to_string();
    assert!(
        msg.contains("mixed-dup") && msg.contains("declares `ccache`") && msg.contains("2 times"),
        "error must name the pool, the duplicated kind (ccache, not sccache), \
         and the count (2): {msg}"
    );
}

#[test]
fn validate_no_duplicate_kinds_within_pool_accepts_distinct_kinds_combo() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(
        &mut cfg,
        "combined",
        vec![
            crate::config::CacheKind::Ccache,
            crate::config::CacheKind::Sccache,
        ],
    );
    validate_no_duplicate_kinds_within_pool(&cfg)
        .expect("distinct-kind pool [Ccache, Sccache] must pass — no within-pool duplicate");
}

#[test]
fn validate_no_duplicate_kinds_within_pool_accepts_single_kind() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    insert_cache_pool(&mut cfg, "solo", vec![crate::config::CacheKind::Ccache]);
    validate_no_duplicate_kinds_within_pool(&cfg)
        .expect("single-kind pool must pass — trivially no duplicate");
}

// -------- validate_proxy_ca_certs_nonempty --------------------------

/// Build a `ProxySpec` with one `CaCertBinding` parameterized by
/// `env` and `path` for the proxy validator tests below. Both fields
/// individually testable; default `ProxySpec` is otherwise empty (no
/// `http/https/no_proxy`).
pub(super) fn proxy_with_one_ca_cert(env: &str, path: &str) -> crate::config::ProxySpec {
    crate::config::ProxySpec {
        http: None,
        https: None,
        no_proxy: vec![],
        ca_certs: vec![crate::config::CaCertBinding {
            env: env.into(),
            path: Utf8PathBuf::from(path),
        }],
    }
}

/// Reject defaults.proxy `ca_certs` entry with empty env. The
/// rendered systemd directive would be `Environment==<path>` (no
/// var name), which unit-start parses as malformed.
#[test]
fn validate_proxy_ca_certs_nonempty_rejects_defaults_empty_env() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(proxy_with_one_ca_cert("", "/etc/ssl/certs/ca.pem"));
    let err = validate_proxy_ca_certs_nonempty(&cfg)
        .expect_err("defaults.proxy ca_certs with empty env must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("defaults.proxy ca_certs[0]")
            && msg.contains("empty or whitespace-only `env`"),
        "error must name defaults.proxy + index + empty-or-whitespace env: {msg}"
    );
}

#[test]
fn validate_proxy_ca_certs_nonempty_rejects_defaults_empty_path() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(proxy_with_one_ca_cert("NODE_EXTRA_CA_CERTS", ""));
    let err = validate_proxy_ca_certs_nonempty(&cfg)
        .expect_err("defaults.proxy ca_certs with empty path must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("defaults.proxy ca_certs[0]")
            && msg.contains("empty or whitespace-only `path`"),
        "error must name defaults.proxy + index + empty-or-whitespace path: {msg}"
    );
}

#[test]
fn validate_proxy_ca_certs_nonempty_rejects_runner_empty_env() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.runners[0].proxy = Some(proxy_with_one_ca_cert("", "/etc/ssl/certs/ca.pem"));
    let err = validate_proxy_ca_certs_nonempty(&cfg)
        .expect_err("runner.proxy ca_certs with empty env must reject");
    let msg = err.to_string();
    // Tightened from substring soup to full scope prefix —
    // matching only `ca_certs[0]` would falsely accept a regression
    // that walked defaults.proxy first and reported the wrong scope.
    assert!(
        msg.contains("runner \"buckos\" proxy ca_certs[0]"),
        "error must name full runner-scope prefix: {msg}"
    );
}

/// Sibling of `validate_proxy_ca_certs_nonempty_rejects_runner_empty_env`
/// for the empty-path field — closes the runner-layer × field-class
/// coverage matrix to 2x2 (defaults gets both env+path branches,
/// runner now gets both too). A regression that broke the
/// `binding.path.as_str().trim().is_empty()` check specifically on
/// the runner layer (without breaking the defaults layer) wouldn't
/// be caught by the existing tests; this closes the gap.
#[test]
fn validate_proxy_ca_certs_nonempty_rejects_runner_empty_path() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.runners[0].proxy = Some(proxy_with_one_ca_cert("NODE_EXTRA_CA_CERTS", ""));
    let err = validate_proxy_ca_certs_nonempty(&cfg)
        .expect_err("runner.proxy ca_certs with empty path must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("runner \"buckos\" proxy ca_certs[0]")
            && msg.contains("empty or whitespace-only `path`"),
        "error must name full runner-scope prefix + the empty-or-whitespace path failure: {msg}"
    );
}

/// Reject `CaCertBinding` with whitespace-only `env`. systemd's
/// Environment= grammar requires `[a-zA-Z_][a-zA-Z0-9_]*` for var
/// names — a space-only `env` would fail at unit-start the same as
/// an empty `env`. The validator's `trim().is_empty()` check
/// catches both classes uniformly.
#[test]
fn validate_proxy_ca_certs_nonempty_rejects_whitespace_only_env() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(proxy_with_one_ca_cert("   ", "/etc/ssl/certs/ca.pem"));
    let err = validate_proxy_ca_certs_nonempty(&cfg)
        .expect_err("whitespace-only env must reject (same failure mode as empty)");
    let msg = err.to_string();
    assert!(
        msg.contains("empty or whitespace-only `env`"),
        "error must name the whitespace-or-empty failure mode: {msg}"
    );
}

#[test]
fn validate_proxy_ca_certs_nonempty_rejects_whitespace_only_path() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(proxy_with_one_ca_cert("NODE_EXTRA_CA_CERTS", "  "));
    let err = validate_proxy_ca_certs_nonempty(&cfg).expect_err("whitespace-only path must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("empty or whitespace-only `path`"),
        "error must name the whitespace-or-empty failure mode: {msg}"
    );
}
