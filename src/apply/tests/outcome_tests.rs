//! Tests for `apply::outcome` (detail / disruption mappings) and the
//! escape-control-chars wiring on `UndoStep::describe()`.

use camino::Utf8PathBuf;

use super::super::outcome::ApplyOutcome;
use super::super::undo::{UndoLog, UndoStep};

// ---------- ApplyOutcome::detail() string contracts -----------------

/// Pin the per-variant detail string vocabulary so a future
/// rename of the strings is a single-place audit. cmd_apply renders
/// `ok: LABEL ({detail})` and downstream operators may grep on
/// these tokens.
#[test]
fn apply_outcome_detail_strings_are_stable() {
    assert_eq!(
        ApplyOutcome::InPlaceSkipped.detail(),
        "noop (bytes match)"
    );
    // Pool-membership Vecs empty ⇒ no parenthetical
    // suffix, preserving the no-suffix shape so operators with
    // downstream parsers see no churn on plans that rewrite
    // files but don't touch caches.
    assert_eq!(
        ApplyOutcome::InPlaceRestarted {
            files_changed: 2,
            pools_added: Vec::new(),
            pools_removed: Vec::new(),
        }
        .detail(),
        "in-place: 2 file(s) changed, 0 group op(s)"
    );
    // Added-only ⇒ `(added: ...)` suffix, comma-separated
    // names in BTreeSet::difference (alphabetical) order.
    assert_eq!(
        ApplyOutcome::InPlaceRestarted {
            files_changed: 1,
            pools_added: vec!["build-cache".into(), "ccache".into()],
            pools_removed: Vec::new(),
        }
        .detail(),
        "in-place: 1 file(s) changed, 2 group op(s) (added: build-cache, ccache)"
    );
    // Removed-only ⇒ `(removed: ...)` suffix.
    assert_eq!(
        ApplyOutcome::InPlaceRestarted {
            files_changed: 0,
            pools_added: Vec::new(),
            pools_removed: vec!["old-cache".into()],
        }
        .detail(),
        "in-place: 0 file(s) changed, 1 group op(s) (removed: old-cache)"
    );
    // Both-non-empty ⇒ semicolon-separated added/removed
    // groups so the suffix parses unambiguously even when pool
    // names contain commas (cache_pool name validator rejects
    // commas, so this is defensive — semicolon delimiter still
    // adds a layer of clarity for human readers).
    assert_eq!(
        ApplyOutcome::InPlaceRestarted {
            files_changed: 0,
            pools_added: vec!["new-cache".into()],
            pools_removed: vec!["old-cache".into()],
        }
        .detail(),
        "in-place: 0 file(s) changed, 2 group op(s) (added: new-cache; removed: old-cache)"
    );
    assert_eq!(
        ApplyOutcome::Recreated.detail(),
        "recreated (deregister + teardown + register + start)"
    );
    assert_eq!(
        ApplyOutcome::Created.detail(),
        "created (GitHub registration + unit start)"
    );
    assert_eq!(
        ApplyOutcome::Removed.detail(),
        "removed (GitHub deregister + unit + home)"
    );
    assert_eq!(
        ApplyOutcome::PoolCreated.detail(),
        "pool created (storage + unit)"
    );
    assert_eq!(
        ApplyOutcome::PoolUpdated.detail(),
        "pool updated (drop-in rewrite + restart)"
    );
    assert_eq!(
        ApplyOutcome::PoolSkipped.detail(),
        "pool noop (drop-in bytes match)"
    );
    assert_eq!(
        ApplyOutcome::PoolRemoved.detail(),
        "pool removed (storage + drop-in)"
    );
    assert_eq!(ApplyOutcome::NoOp.detail(), "noop (in sync)");
    assert_eq!(ApplyOutcome::DryRunSkipped.detail(), "dry-run (skipped)");
    // Failed.detail() returns the captured error_summary
    // verbatim — no rewrapping, no prefix.
    assert_eq!(
        ApplyOutcome::Failed {
            error_summary: "systemd: enable_unit failed".into(),
            plan_disruption: crate::plan::Disruption::Recreate,
        }
        .detail(),
        "systemd: enable_unit failed",
    );
}

/// Pin `InPlaceRestarted.detail()` output for the
/// `before_caches = None` short-circuit path (pre-annotation runner
/// with no `X-Ghars-Caches` annotation). Empty
/// `pools_added`/`pools_removed` MUST render "0 group op(s)" with NO
/// parenthetical, preserving the no-suffix shape.
/// Construction-side coverage lives at
/// `execute_update_runner_in_place_before_caches_none_skips_diff`
/// (sibling — verifies the construction-site short-circuit produces
/// the empty Vecs this test consumes).
#[test]
fn apply_outcome_in_place_restarted_none_before_caches_detail_no_parenthetical() {
    let outcome = ApplyOutcome::InPlaceRestarted {
        files_changed: 1,
        pools_added: Vec::new(),
        pools_removed: Vec::new(),
    };
    // Empty Vecs ⇒ detail() must NOT include any `(added:...)` or
    // `(removed:...)` parenthetical. No-suffix shape preserved.
    assert_eq!(
        outcome.detail(),
        "in-place: 1 file(s) changed, 0 group op(s)",
        "before_caches=None ⇒ pools_added/pools_removed empty ⇒ \
         detail() emits no parenthetical suffix",
    );
}

/// Multi-element detail() coverage for InPlaceRestarted.
/// Existing `apply_outcome_detail_strings_are_stable` covers the
/// 1-element and 2-element add cases. Defense-in-depth format
/// pin for multi-element pool lists (3+ adds / 2+ removes).
/// Format pin:
///   "in-place: F file(s) changed, G group op(s) (added: a, b, c; removed: d, e)"
#[test]
fn apply_outcome_in_place_restarted_detail_multi_element() {
    // 3 adds + 2 removes, both non-empty — pin both
    // comma-separated lists + semicolon between groups.
    let outcome = ApplyOutcome::InPlaceRestarted {
        files_changed: 5,
        pools_added: vec!["alpha".into(), "beta".into(), "gamma".into()],
        pools_removed: vec!["delta".into(), "epsilon".into()],
    };
    assert_eq!(
        outcome.detail(),
        "in-place: 5 file(s) changed, 5 group op(s) \
         (added: alpha, beta, gamma; removed: delta, epsilon)",
    );
}

/// Pin the ApplyOutcome → Disruption mapping. The mapping
/// must mirror plan-time `Action::disruption` so cmd_apply's
/// `[disruption]` bracket tag uses the same vocabulary as
/// plan output. Operator grep on `[recreate]` matches both
/// surfaces.
#[test]
fn apply_outcome_disruption_mapping_mirrors_plan_vocabulary() {
    use crate::plan::Disruption;
    // None: no host mutation actually happened.
    assert_eq!(ApplyOutcome::InPlaceSkipped.disruption(), Disruption::None);
    assert_eq!(ApplyOutcome::PoolSkipped.disruption(), Disruption::None);
    assert_eq!(ApplyOutcome::NoOp.disruption(), Disruption::None);
    assert_eq!(ApplyOutcome::DryRunSkipped.disruption(), Disruption::None);
    // Restart: stop+start of an existing unit.
    assert_eq!(
        ApplyOutcome::InPlaceRestarted {
            files_changed: 1,
            pools_added: Vec::new(),
            pools_removed: Vec::new(),
        }
        .disruption(),
        Disruption::Restart,
    );
    assert_eq!(ApplyOutcome::PoolUpdated.disruption(), Disruption::Restart);
    // Recreate: full host-state lifecycle change.
    assert_eq!(ApplyOutcome::Recreated.disruption(), Disruption::Recreate);
    assert_eq!(ApplyOutcome::Created.disruption(), Disruption::Recreate);
    assert_eq!(ApplyOutcome::Removed.disruption(), Disruption::Recreate);
    assert_eq!(ApplyOutcome::PoolCreated.disruption(), Disruption::Recreate,);
    assert_eq!(ApplyOutcome::PoolRemoved.disruption(), Disruption::Recreate,);
    // Failed.disruption() returns the action's plan-time
    // worst-case disruption stored in `plan_disruption`. All
    // three variants must round-trip — apply-time impact is
    // unknown, so we report the plan-time bound.
    for d in [Disruption::None, Disruption::Restart, Disruption::Recreate] {
        assert_eq!(
            ApplyOutcome::Failed {
                error_summary: String::new(),
                plan_disruption: d,
            }
            .disruption(),
            d,
            "Failed.disruption() must echo plan_disruption for {d:?}",
        );
    }
}

/// Pin the `UndoStep::describe()` output for every variant.
/// cmd_apply's rollback-state advisory greps these strings in tests
/// and operators may grep them in production output, so the
/// vocabulary is stable. Past-tense per the doc-comment ("wrote",
/// "started", "created", etc.). Byte-content fields
/// (`WriteFile.prior_content`, `RemoveFile.content`) are
/// intentionally absent from the rendering — they are recovery
/// payloads for `undo()`, not advisory details.
#[test]
fn undo_step_describe_strings_are_stable() {
    let path = camino::Utf8PathBuf::from("/etc/ghars/runners/a/00-ghars.conf");
    assert_eq!(
        UndoStep::WriteFile {
            path: path.clone(),
            prior_content: None,
        }
        .describe(),
        "wrote /etc/ghars/runners/a/00-ghars.conf",
    );
    assert_eq!(
        UndoStep::RemoveFile {
            path: path.clone(),
            content: vec![1, 2, 3],
        }
        .describe(),
        "removed file /etc/ghars/runners/a/00-ghars.conf",
    );
    assert_eq!(
        UndoStep::CreateDir { path: path.clone() }.describe(),
        "created directory /etc/ghars/runners/a/00-ghars.conf",
    );
    assert_eq!(
        UndoStep::RemoveDir { path }.describe(),
        "removed directory /etc/ghars/runners/a/00-ghars.conf",
    );
    assert_eq!(
        UndoStep::StartUnit {
            name: "ghars-runner@foo.service".into(),
        }
        .describe(),
        "started ghars-runner@foo.service",
    );
    assert_eq!(
        UndoStep::StopUnit {
            name: "ghars-runner@foo.service".into(),
        }
        .describe(),
        "stopped ghars-runner@foo.service",
    );
    assert_eq!(
        UndoStep::EnableUnit {
            name: "ghars-runner@foo.service".into(),
        }
        .describe(),
        "enabled ghars-runner@foo.service",
    );
    assert_eq!(
        UndoStep::DisableUnit {
            name: "ghars-runner@foo.service".into(),
        }
        .describe(),
        "disabled ghars-runner@foo.service",
    );
    assert_eq!(
        UndoStep::GitHubRegistration {
            name: "foo".into(),
            url: "https://github.com/example/repo".into(),
            auth_name: "pat".into(),
            runner_home: camino::Utf8PathBuf::from("/var/lib/ghars/foo"),
        }
        .describe(),
        "registered runner foo against https://github.com/example/repo",
    );
}

/// Pin that `UndoLog::into_steps` returns the recorded steps
/// in insertion order (matches `steps()` semantics) and consumes
/// the log. The Err path in `apply()` calls this to plumb the
/// per-action mutation manifest into `ApplyResult.failed_undo_logs`,
/// so order-preservation is the visible operator-facing contract
/// (the advisory lists steps in the order they happened on disk).
#[test]
fn undo_log_into_steps_preserves_insertion_order() {
    let mut log = UndoLog::new();
    log.push(UndoStep::WriteFile {
        path: camino::Utf8PathBuf::from("/a"),
        prior_content: None,
    });
    log.push(UndoStep::CreateDir {
        path: camino::Utf8PathBuf::from("/b"),
    });
    log.push(UndoStep::StartUnit {
        name: "x.service".into(),
    });
    let steps = log.into_steps();
    assert_eq!(steps.len(), 3);
    assert!(matches!(&steps[0], UndoStep::WriteFile { path, .. } if path == "/a"));
    assert!(matches!(&steps[1], UndoStep::CreateDir { path } if path == "/b"));
    assert!(matches!(&steps[2], UndoStep::StartUnit { name } if name == "x.service"),);
}

// ---------- call-site sanitization wiring pins (apply.rs) -----------

/// Pin that `UndoStep::WriteFile::describe()` runs the
/// path through `escape_control_chars`. Helper-level coverage
/// already lives in `lib.rs`; this test drives the real production
/// `describe()` method with a hostile path containing `\x1b[31m`,
/// asserts (i) raw ESC byte is gone, (ii) the printable
/// `\u{1b}` escape form `char::escape_default` emits is present,
/// and (iii) the surrounding `wrote ` prefix is intact.
///
/// Pinned because the `describe()` method has 9 variant arms
/// (RemoveFile, StartUnit, GitHubRegistration, etc.); a future
/// refactor that drops `escape_control_chars` from one arm would
/// compile and pass other describe() tests, but re-introduce the
/// ANSI-hijack attack surface for that variant. WriteFile is the
/// canary — symmetric coverage is one assertion chain across all 9
/// (a separate field-set audit covers the rest).
#[test]
fn undo_step_write_file_describe_escapes_hostile_path() {
    let hostile = Utf8PathBuf::from("/etc/ghars/\x1b[31mshim.conf");
    let step = UndoStep::WriteFile {
        path: hostile,
        prior_content: None,
    };
    let described = step.describe();
    assert!(
        !described.contains('\x1b'),
        "raw ESC must not survive describe(); got: {described:?}"
    );
    assert!(
        described.contains("\\u{1b}"),
        "expected \\u{{1b}} escape form from char::escape_default; got: {described}"
    );
    // Sanity: the production prefix and the non-control suffix
    // both pass through. Pins that the format string didn't drop
    // identifying context.
    assert!(described.starts_with("wrote "), "got: {described}");
    assert!(
        described.contains("shim.conf"),
        "non-control suffix must pass through; got: {described}"
    );
}

// ---------- ApplyOutcome::Failed.detail() with newline -------------

/// Pin that `ApplyOutcome::Failed.detail()` returns
/// the pre-sanitized `error_summary` verbatim with no raw newline
/// surviving. The escape happens at construction time inside
/// `apply()` (apply.rs `escape_control_chars(&e.to_string()).into_owned()`,
/// also tested at `apply_failed_error_summary_escapes_hostile_inner_error`);
/// this companion test pins the END-USER consumer surface — when
/// cmd_apply renders the `fail:` row via `outcome.detail()`, the
/// rendered string must have no embedded `\n` byte that would split
/// the row across multiple stderr lines.
///
/// Two assertions:
///   (i) Constructed via `escape_control_chars` (the production
///       wiring): the resulting `Failed.detail()` must contain no
///       raw `\n` and must contain the printable `\\n` form
///       `char::escape_default('\n')` emits.
///   (ii) Round-trip integrity: detail() returns the same bytes
///        that were stored in error_summary (no double-escape, no
///        mutation). The doc-comment on
///        `ApplyOutcome::Failed.error_summary` says detail() is
///        verbatim from error_summary.
#[test]
fn apply_outcome_failed_detail_has_no_raw_newline_when_pre_sanitized() {
    // Simulate what the apply()-loop construction site does:
    // `escape_control_chars(&e.to_string()).into_owned()` on an
    // error message containing a raw newline. The newline's
    // `char::escape_default` form is the literal two-byte sequence
    // backslash + 'n' (`"\\n"` in Rust source).
    let raw = "config: invalid value\nhint: re-read TOML";
    let sanitized = crate::escape_control_chars(raw).into_owned();
    // Sanity: the helper produced an owned string with no raw
    // newline. (Helper-level coverage in lib.rs — repeating here
    // makes the wiring chain self-contained.)
    assert!(
        !sanitized.contains('\n'),
        "escape_control_chars must remove raw \\n; got: {sanitized:?}"
    );

    let outcome = ApplyOutcome::Failed {
        error_summary: sanitized.clone(),
        plan_disruption: crate::plan::Disruption::Restart,
    };
    let rendered = outcome.detail();

    // (i) No raw newline survived in the consumer-facing detail().
    // cmd_apply's `fail: LABEL [...] (DETAIL)` row would otherwise
    // split across multiple stderr lines and break operator
    // grep-on-`fail:` pipelines.
    assert!(
        !rendered.contains('\n'),
        "Failed.detail() must not contain a raw \\n byte; got: {rendered:?}"
    );
    // The printable `\\n` escape form from char::escape_default
    // must appear — proves the construction site escaped (vs.
    // stripping the newline entirely or leaving it raw).
    assert!(
        rendered.contains("\\n"),
        "Failed.detail() must contain the \\\\n escape form; got: {rendered}"
    );

    // (ii) Round-trip with error_summary: detail() returns the
    // stored bytes verbatim, no double-escape. The doc-comment on
    // ApplyOutcome::Failed.error_summary specifies
    // pre-sanitized-at-construction; detail() simply clones.
    assert_eq!(
        rendered, sanitized,
        "Failed.detail() must return error_summary verbatim (no \
         double-escape, no mutation); got rendered={rendered:?} \
         expected={sanitized:?}"
    );
    // The non-control text passes through.
    assert!(
        rendered.contains("invalid value") && rendered.contains("hint:"),
        "non-control surrounding text must pass through; got: {rendered}"
    );
}

/// Per-variant `UndoStep::describe()` escape pin.
/// Helper-level coverage already lives in `lib.rs`; the WriteFile
/// arm is pinned at
/// `undo_step_write_file_describe_escapes_hostile_path`.
/// This test extends the wiring pin to the remaining variants and
/// the second interpolated field of `GitHubRegistration`.
///
/// `UndoStep` has 9 variants total. Eight are covered here
/// (every variant except `WriteFile`), plus a second
/// `GitHubRegistration` row so the `name` and `url` interpolation
/// paths each get an independent pin. A 10th sub-case
/// (`GitHubRegistration[hostile-runner_home]`)
/// is included as a forward-looking pin: today `describe()` does
/// NOT interpolate `runner_home`, so the case asserts only the
/// "no raw ESC survives" property — if a future refactor adds
/// `runner_home` interpolation without `escape_control_chars`,
/// that assertion trips with the labeled prefix.
///
/// Pinned because a regression dropping `escape_control_chars`
/// from one variant arm would compile and pass the WriteFile
/// test, but reintroduce the ANSI-hijack vector for that
/// variant. Table-driven layout names the broken arm via the
/// `[{label}]` assertion-message prefix.
#[test]
fn undo_step_all_variants_describe_escapes_hostile_input() {
    let hostile_path = Utf8PathBuf::from("/etc/ghars/\x1b[31mevil");
    let hostile_name = "ghars-runner@\x1b[31mevil.service";
    let hostile_url = "https://github.com/\x1b[31mevil/repo";
    let hostile_runner_home = Utf8PathBuf::from("/var/lib/ghars/\x1b[31mevil");
    let benign_runner_home = Utf8PathBuf::from("/var/lib/ghars/buckos");
    // `expects_interpolation` (the 3rd tuple element) is true for
    // arms whose hostile field flows through `describe()`'s
    // format strings — those rows assert (a) no raw ESC, (b)
    // `\u{1b}` form present, and (c) the printable "evil" suffix
    // survives (catches over-escape regressions where the entire
    // string collapses to `\u{1b}...`). `false` rows assert ONLY
    // (a) — for fields not currently interpolated, the absence
    // of raw ESC is the only meaningful invariant; (b) and (c)
    // would be vacuously false today and would falsely fail.
    let cases: Vec<(&str, UndoStep, bool)> = vec![
        (
            "RemoveFile",
            UndoStep::RemoveFile {
                path: hostile_path.clone(),
                content: vec![],
            },
            true,
        ),
        (
            "CreateDir",
            UndoStep::CreateDir {
                path: hostile_path.clone(),
            },
            true,
        ),
        (
            "RemoveDir",
            UndoStep::RemoveDir {
                path: hostile_path.clone(),
            },
            true,
        ),
        (
            "StartUnit",
            UndoStep::StartUnit {
                name: hostile_name.into(),
            },
            true,
        ),
        (
            "StopUnit",
            UndoStep::StopUnit {
                name: hostile_name.into(),
            },
            true,
        ),
        (
            "EnableUnit",
            UndoStep::EnableUnit {
                name: hostile_name.into(),
            },
            true,
        ),
        (
            "DisableUnit",
            UndoStep::DisableUnit {
                name: hostile_name.into(),
            },
            true,
        ),
        // GitHubRegistration interpolates `name` and `url` (the
        // two operator-readable fields). Cover hostile-name and
        // hostile-url separately so a refactor that escapes only
        // one of the two would still fail this test. Other fields
        // (auth_name, runner_home) are not interpolated by
        // `describe()`'s `GitHubRegistration` arm, so the
        // hostile-runner_home row below uses the
        // `expects_interpolation=false` mode.
        (
            "GitHubRegistration[hostile-name]",
            UndoStep::GitHubRegistration {
                name: hostile_name.into(),
                url: "https://github.com/example/repo".into(),
                auth_name: "pat".into(),
                runner_home: benign_runner_home.clone(),
            },
            true,
        ),
        (
            "GitHubRegistration[hostile-url]",
            UndoStep::GitHubRegistration {
                name: "buckos".into(),
                url: hostile_url.into(),
                auth_name: "pat".into(),
                runner_home: benign_runner_home.clone(),
            },
            true,
        ),
        // Forward-looking pin for runner_home.
        // Today `describe()`'s `GitHubRegistration` arm does NOT
        // interpolate `runner_home` (it reads only `name` and
        // `url`), so the hostile bytes never reach the format
        // string and the
        // (a) "no raw ESC" assertion is vacuously true. A future
        // refactor that exposes runner_home in the rendered
        // string WITHOUT routing through `escape_control_chars`
        // flips (a) to false — this row catches that regression
        // before it lands. (b) and (c) cannot apply: today there
        // is no `\u{1b}` form to find and no "evil" suffix to
        // match, so we suppress those assertions via
        // `expects_interpolation=false`.
        (
            "GitHubRegistration[hostile-runner_home]",
            UndoStep::GitHubRegistration {
                name: "buckos".into(),
                url: "https://github.com/example/repo".into(),
                auth_name: "pat".into(),
                runner_home: hostile_runner_home.clone(),
            },
            false,
        ),
    ];
    for (label, step, expects_interpolation) in &cases {
        let described = step.describe();
        // (a) raw ESC must not survive on this arm. A regression
        // that drops escape_control_chars from one variant fails
        // here with the label naming the broken arm. Universal
        // — every arm asserts this regardless of interpolation
        // status.
        assert!(
            !described.contains('\x1b'),
            "[{label}] raw ESC must not survive describe(); got: {described:?}"
        );
        if *expects_interpolation {
            // (b) printable `\u{1b}` from char::escape_default
            // must appear — proves the helper actually ran on
            // this arm (and didn't silently strip the bytes).
            assert!(
                described.contains("\\u{1b}"),
                "[{label}] expected \\u{{1b}} escape form from char::escape_default; got: {described}"
            );
            // (c) the printable "evil" suffix must survive —
            // catches an over-escape regression where the
            // entire string collapses to `\u{1b}...` with no
            // readable text. The hostile fixtures embed "evil"
            // immediately after the ESC sequence on every
            // interpolated field.
            assert!(
                described.contains("evil"),
                "[{label}] non-control suffix `evil` must pass through unchanged; got: {described}"
            );
        }
    }
}
