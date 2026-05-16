//! Test chunk - co-located with cli/ submodules. See tests/mod.rs for fixture sharing rationale.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn render_plan_json_update_runner_emits_field_changes_and_drop_in_changes() {
    // JSON output must surface
    // RunnerDelta.field_changes and RunnerDelta.drop_in_changes so
    // CI / dashboard consumers can render the same per-field
    // detail the text path renders. drop_in_changes carries one
    // entry per basename in the union of rendered + discovered
    // drop-ins (including Preserved — JSON consumers may want to
    // render the audit trail), each tagged with a `change_kind`
    // string (distinct from the per-action `kind`).
    let plan = Plan {
        actions: vec![Action::UpdateRunner(plan::RunnerDelta {
            identity: fake_identity("buckos"),
            after: fake_runner_plan("buckos"),
            requires_recreate: true,
            recreate_reasons: vec!["url"],
            drift_cause: plan::DriftCause::SpecChanged,
            field_changes: vec![plan::FieldChange {
                path: "url",
                before: plan::FieldValue::String("before".into()),
                after: plan::FieldValue::String("after".into()),
            }],
            drop_in_changes: vec![
                plan::DropInChange {
                    basename: "10-memory.conf".into(),
                    change: plan::DropInChangeKind::Modified {
                        before: "old".into(),
                        after: "new".into(),
                    },
                },
                plan::DropInChange {
                    basename: "15-resolv.conf".into(),
                    change: plan::DropInChangeKind::Preserved,
                },
            ],
            before_caches: None,
            before_drop_in_basenames: None,
        })],
        warnings: vec![],
        keep_versions: 2,
    };
    let v = plan_to_json_value(&plan, false);
    // Assert schema_version on the full-payload smoke test
    // so a renderer-level bump can't bypass the dedicated
    // `plan_to_json_value_emits_schema_version_at_top_level` pin.
    assert_eq!(v["schema_version"], "2");
    let action = &v["actions"][0];
    assert_eq!(action["kind"], "update_runner");

    let fcs = action["field_changes"].as_array().unwrap();
    assert_eq!(fcs.len(), 1);
    assert_eq!(fcs[0]["path"], "url");
    // Schema v2: `before`/`after` are tagged FieldValue
    // objects ({"type": "string", "value": ..} for scalars,
    // {"type": "list", "values": [..]} for lists).
    assert_eq!(fcs[0]["before"]["type"], "string");
    assert_eq!(fcs[0]["before"]["value"], "before");
    assert_eq!(fcs[0]["after"]["type"], "string");
    assert_eq!(fcs[0]["after"]["value"], "after");

    let dics = action["drop_in_changes"].as_array().unwrap();
    assert_eq!(dics.len(), 2);
    assert_eq!(dics[0]["basename"], "10-memory.conf");
    // Inner discriminator is `change_kind`, distinct from
    // the per-action `kind`, so JSON consumers can disambiguate
    // without context.
    assert_eq!(dics[0]["change_kind"], "modified");
    assert_eq!(dics[1]["basename"], "15-resolv.conf");
    assert_eq!(dics[1]["change_kind"], "preserved");
    // Drop-in body content (`before`, `after`) is intentionally
    // NOT in the JSON — full body diff is reserved for --diff.
    assert!(
        dics[0].get("before").is_none(),
        "no body diff in basic JSON"
    );
    assert!(dics[0].get("after").is_none(), "no body diff in basic JSON");
}

/// Pin the List-typed `FieldValue` JSON shape end-to-end.
/// Symmetric with the String-typed pin in
/// `render_plan_json_update_runner_emits_field_changes_and_drop_in_changes` —
/// catches drift where a renderer change accidentally collapses
/// `{"type": "list", "values": [...]}` into a bare array or
/// reuses the scalar `value` key for List entries.
#[test]
fn render_plan_json_update_runner_emits_typed_list_field_value_for_labels() {
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: true,
        recreate_reasons: vec!["labels"],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: vec![plan::FieldChange {
            path: "labels",
            before: plan::FieldValue::List(vec!["ci".into()]),
            after: plan::FieldValue::List(vec!["ci".into(), "gpu".into()]),
        }],
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let plan = Plan {
        actions: vec![Action::UpdateRunner(delta)],
        warnings: vec![],
        keep_versions: 2,
    };
    let v = plan_to_json_value(&plan, false);
    let fcs = v["actions"][0]["field_changes"].as_array().unwrap();
    assert_eq!(fcs.len(), 1);
    let fc = &fcs[0];
    assert_eq!(fc["path"], "labels");
    // Tagged list shape: `type: "list"`, `values: [..]`.
    assert_eq!(fc["before"]["type"], "list");
    assert_eq!(fc["after"]["type"], "list");
    let before_values = fc["before"]["values"]
        .as_array()
        .expect("List variant must carry `values` array");
    let after_values = fc["after"]["values"]
        .as_array()
        .expect("List variant must carry `values` array");
    assert_eq!(before_values, &vec![serde_json::json!("ci")]);
    assert_eq!(
        after_values,
        &vec![serde_json::json!("ci"), serde_json::json!("gpu")],
    );
    // List variants MUST NOT emit the scalar `value` key.
    assert!(
        fc["before"].get("value").is_none(),
        "List variant must not carry scalar `value` key, got: {}",
        fc["before"],
    );
    assert!(
        fc["after"].get("value").is_none(),
        "List variant must not carry scalar `value` key, got: {}",
        fc["after"],
    );
}

#[test]
fn render_plan_json_noop_kind_label_with_reason() {
    let plan = Plan {
        actions: vec![Action::NoOp("a: in sync".into())],
        warnings: vec![],
        keep_versions: 2,
    };
    let v = plan_to_json_value(&plan, false);
    let actions = v["actions"].as_array().unwrap();
    assert_eq!(actions[0]["kind"], "noop");
    assert_eq!(actions[0]["reason"], "a: in sync");
}

#[test]
fn render_plan_json_warnings_array_includes_each_string() {
    let plan = Plan {
        actions: vec![],
        warnings: vec!["w1".into(), "w2".into(), "w3".into()],
        keep_versions: 2,
    };
    let v = plan_to_json_value(&plan, false);
    let warnings = v["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 3);
    assert_eq!(warnings[0], "w1");
    assert_eq!(warnings[1], "w2");
    assert_eq!(warnings[2], "w3");
}

#[test]
fn render_plan_json_no_token_or_secret_keys() {
    // Secrets must never appear in either format. We feed
    // a plan with auth + cache references and assert the JSON keys
    // are bounded by the documented set.
    let plan = Plan {
        actions: vec![
            Action::CreateRunner(fake_runner_plan("a")),
            Action::UpdateRunner(plan::RunnerDelta {
                identity: fake_identity("b"),
                after: fake_runner_plan("b"),
                requires_recreate: true,
                recreate_reasons: vec!["url"],
                drift_cause: plan::DriftCause::SpecChanged,
                field_changes: Vec::new(),
                drop_in_changes: Vec::new(),
                before_caches: None,
                before_drop_in_basenames: None,
            }),
        ],
        warnings: vec![],
        keep_versions: 2,
    };
    let serialized = serde_json::to_string(&plan_to_json_value(&plan, false)).unwrap();
    for forbidden in ["token", "secret", "private_key", "password"] {
        assert!(
            !serialized.contains(forbidden),
            "JSON must not leak `{forbidden}`: {serialized}"
        );
    }
}

// ---------- cmd_init mode + cmd_add labels coverage -------------

#[test]
fn cmd_init_returns_zero_and_writes_canonical_body() {
    // Positive path: init with a fresh path lands the verbatim
    // INIT_EXAMPLE_CONFIG and returns rc=0.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let rc = cmd_init(&config_path, &InitArgs { output: None }, true).unwrap();
    assert_eq!(rc, 0);
    let body = fs::read_to_string(config_path.as_std_path()).unwrap();
    assert_eq!(body, INIT_EXAMPLE_CONFIG);
    assert!(body.contains("# ghars config"));
    // OWNER/REPO placeholder.
    assert!(body.contains("OWNER/REPO"));
}

#[test]
fn init_example_config_content_invariants() {
    // Pin specific content invariants on INIT_EXAMPLE_CONFIG that
    // the byte-equality tests at chunk3.rs:217 +
    // chunk1.rs:767 cannot catch — those compare the WRITTEN
    // bytes to the SAME constant, so any field deletion
    // propagates to both sides and the equality assertion still
    // passes. These invariants guard against silent regressions
    // in the shipped template.
    //
    // Constructive design: every assertion is a positive presence
    // check OR a constructive pattern check (every github.com URL
    // must use a placeholder), not a destructive deny-list naming
    // any specific banned token in the test source.

    // POSITIVE: required fields the template ships. Line-start
    // anchoring (via `lines().any(|l| l.starts_with(...))`) so
    // commented-out lines (`# runner_version = ...`) do not
    // silently satisfy the invariant — only active TOML
    // directives count.
    assert!(
        INIT_EXAMPLE_CONFIG
            .lines()
            .any(|l| l.starts_with("runner_version =")),
        "INIT_EXAMPLE_CONFIG must declare a runner_version default \
         on an un-commented line"
    );
    assert!(
        INIT_EXAMPLE_CONFIG
            .lines()
            .any(|l| l.starts_with("token_env = \"GHARS_PAT\"")),
        "INIT_EXAMPLE_CONFIG must use GHARS_PAT as the default PAT \
         env var name on an un-commented line"
    );
    assert!(
        INIT_EXAMPLE_CONFIG
            .lines()
            .any(|l| l.starts_with("arch = \"x86_64\"")),
        "INIT_EXAMPLE_CONFIG must declare arch = x86_64 by default \
         on an un-commented line"
    );
    assert!(
        INIT_EXAMPLE_CONFIG
            .lines()
            .any(|l| l.starts_with("[auth.pat]")),
        "INIT_EXAMPLE_CONFIG must define an [auth.pat] section header \
         on an un-commented line"
    );
    assert!(
        INIT_EXAMPLE_CONFIG
            .lines()
            .any(|l| l.starts_with("kind = \"pat\"")),
        "INIT_EXAMPLE_CONFIG must declare auth kind = pat on an \
         un-commented line inside the [auth.pat] section"
    );

    // POSITIVE: the shipped template must parse as valid TOML so
    // `ghars init` produces a parseable config on first run.
    // Catches quoting bugs, unclosed brackets, mis-escaped strings
    // that the substring checks above don't see. Parses to a
    // generic toml::Value (grammar check only); Config-shape
    // validation lives in the loader's own test surface.
    toml::from_str::<toml::Value>(INIT_EXAMPLE_CONFIG)
        .expect("INIT_EXAMPLE_CONFIG must parse as valid TOML");

    // POSITIVE + CONSTRUCTIVE: every `github.com/` URL uses a
    // generic placeholder path segment (`github.com/OWNER/` or
    // `github.com/owner/`), never a real handle. The full-pattern
    // match (with trailing slash) avoids substring-bypass via
    // handles containing "owner" as a substring (e.g. "landowner",
    // "OWNERSHIP"). Sidesteps env-leakage by avoiding any specific
    // banned-token literal in the test source.
    //
    // Scope: this check guards github.com URLs only. Handle leaks
    // via non-github URL hosts, non-URL contexts (bare comments,
    // emails, file paths), are NOT caught here — they rely on the
    // pre-publish audit gate for defense in depth. Extend the
    // check when the template grows to include such surfaces.
    let mut github_url_count = 0usize;
    for (idx, line) in INIT_EXAMPLE_CONFIG.lines().enumerate() {
        if !line.contains("github.com/") {
            continue;
        }
        github_url_count += 1;
        assert!(
            line.contains("github.com/OWNER/") || line.contains("github.com/owner/"),
            "INIT_EXAMPLE_CONFIG line {} carries a `github.com/` URL \
             without the `github.com/OWNER/` or `github.com/owner/` \
             placeholder pattern — env-leakage risk. Replace the \
             handle with the placeholder.\nOffending line: {:?}",
            idx + 1,
            line
        );
    }
    // Vacuous-truth guard: if a future template restructure drops
    // github.com URLs, the loop above iterates fewer times and
    // silently weakens the placeholder check. Pin the template's
    // didactic intent: it must demonstrate the OWNER/REPO pattern
    // via BOTH the schema link (current line 26) and the runner
    // example URL (current line 43). Drop of either is caught.
    assert!(
        github_url_count >= 2,
        "INIT_EXAMPLE_CONFIG must demonstrate at least two \
         `github.com/` URLs with the placeholder pattern (schema \
         link + runner example) — got {github_url_count}"
    );
}

#[test]
fn cmd_init_output_override_writes_to_alt_path_not_global() {
    // When `--output` is set, the global --config path stays
    // untouched. This pins the override semantics so a future
    // refactor can't silently use --config when --output is set.
    let tmp = tempfile::tempdir().unwrap();
    let global_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let alt_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("alt.toml");
    let args = InitArgs {
        output: Some(alt_path.clone()),
    };
    cmd_init(&global_path, &args, true).unwrap();
    assert!(alt_path.exists(), "--output path must exist");
    assert!(!global_path.exists(), "--config path must stay untouched");
}

#[test]
fn cmd_add_appends_labels_when_provided() {
    // Labels list must round-trip into the [[runner]] block.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    write_minimal_config(&config_path);
    let paths = Paths::default();
    let args = AddArgs {
        repo: "owner/repo".into(),
        name: Some("owner-repo-1".into()),
        labels: vec!["x64".into(), "self-hosted".into()],
        auth: Some("pat".into()),
        no_apply: true,
        auto_approve: false,
    };
    let rc = cmd_add(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .unwrap();
    assert_eq!(rc, 0);
    let after = fs::read_to_string(config_path.as_std_path()).unwrap();
    assert!(after.contains("labels = [\"x64\", \"self-hosted\"]"));
}

#[test]
fn cmd_add_omits_auth_when_match_defaults() {
    // When --auth matches defaults.auth the appended block omits
    // the `auth = ...` line (avoids redundant overrides cluttering
    // the operator's config).
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // Config has defaults.auth = "pat", which matches the --auth.
    let body = "\
[defaults]
auth = \"pat\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"
";
    fs::write(config_path.as_std_path(), body).unwrap();
    let paths = Paths::default();
    let args = AddArgs {
        repo: "owner/repo".into(),
        name: Some("owner-repo-1".into()),
        labels: vec![],
        auth: Some("pat".into()),
        no_apply: true,
        auto_approve: false,
    };
    cmd_add(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .unwrap();
    let after = fs::read_to_string(config_path.as_std_path()).unwrap();
    // The added block should not duplicate `auth = "pat"` since
    // it matches defaults.
    let added_block = after.split("[[runner]]").nth(1).unwrap_or("");
    assert!(
        !added_block.contains("auth = "),
        "auth match-defaults should not write redundant `auth = ...`: \n{added_block}"
    );
}

// ---------- gap-filling cmd_init/cmd_add tests --------------------

#[test]
fn cmd_init_creates_parent_dir_when_missing() {
    // dest.parent() doesn't exist → create_dir_all. Operator runs
    // `ghars init --output /etc/ghars-new/ghars.toml` on a host
    // with no /etc/ghars-new yet; the command must create the dir
    // tree, not error out.
    let tmp = tempfile::tempdir().unwrap();
    let nested = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("a")
        .join("b")
        .join("c")
        .join("ghars.toml");
    // Sanity: the parent didn't exist before the call.
    assert!(!nested.parent().unwrap().exists());
    cmd_init(
        &Utf8PathBuf::from("/never-used"),
        &InitArgs {
            output: Some(nested.clone()),
        },
        true,
    )
    .unwrap();
    assert!(nested.exists(), "config file landed at the nested path");
}

#[test]
fn cmd_add_auto_name_first_index_when_no_existing_runners() {
    // No runners → owner-repo-1 (auto-numbered).
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    write_minimal_config(&config_path);
    let paths = Paths::default();
    let args = AddArgs {
        repo: "owner/repo".into(),
        name: None,
        labels: vec![],
        auth: Some("pat".into()),
        no_apply: true,
        auto_approve: false,
    };
    cmd_add(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .unwrap();
    let after = fs::read_to_string(config_path.as_std_path()).unwrap();
    assert!(after.contains("name = \"owner-repo-1\""), "got:\n{after}");
}

#[test]
fn cmd_add_auto_name_next_index_when_first_taken() {
    // owner-repo-1 already exists → owner-repo-2.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let body = "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"owner-repo-1\"
url = \"https://github.com/owner/repo\"
auth = \"pat\"
";
    fs::write(config_path.as_std_path(), body).unwrap();
    let paths = Paths::default();
    let args = AddArgs {
        repo: "owner/repo".into(),
        name: None,
        labels: vec![],
        auth: Some("pat".into()),
        no_apply: true,
        auto_approve: false,
    };
    cmd_add(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .unwrap();
    let after = fs::read_to_string(config_path.as_std_path()).unwrap();
    // The new block uses owner-repo-2 (the first free index).
    assert!(
        after.contains("name = \"owner-repo-2\""),
        "expected next-free-index name; got:\n{after}"
    );
    // The original owner-repo-1 block is intact.
    assert_eq!(after.matches("name = \"owner-repo-1\"").count(), 1);
}

#[test]
fn cmd_add_writes_auth_line_when_args_auth_differs_from_defaults() {
    // defaults.auth = "pat" but --auth = "secondary" → the new
    // block writes auth = "secondary" because it diverges from
    // the inherited default.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let body = "\
[defaults]
auth = \"pat\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[auth.secondary]
kind = \"interactive\"
";
    fs::write(config_path.as_std_path(), body).unwrap();
    let paths = Paths::default();
    let args = AddArgs {
        repo: "owner/repo".into(),
        name: Some("owner-repo-1".into()),
        labels: vec![],
        auth: Some("secondary".into()),
        no_apply: true,
        auto_approve: false,
    };
    cmd_add(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .unwrap();
    let after = fs::read_to_string(config_path.as_std_path()).unwrap();
    let added_block = after.split("[[runner]]").last().unwrap_or("");
    assert!(
        added_block.contains("auth = \"secondary\""),
        "auth-differs-from-defaults must write the override line:\n{added_block}"
    );
}

#[test]
fn cmd_add_omits_labels_line_when_empty() {
    // labels=[] → the appended block does NOT include a
    // `labels = []` line. Keeps the operator's TOML clean.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    write_minimal_config(&config_path);
    let paths = Paths::default();
    let args = AddArgs {
        repo: "owner/repo".into(),
        name: Some("owner-repo-1".into()),
        labels: vec![],
        auth: Some("pat".into()),
        no_apply: true,
        auto_approve: false,
    };
    cmd_add(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .unwrap();
    let after = fs::read_to_string(config_path.as_std_path()).unwrap();
    let added_block = after.split("[[runner]]").last().unwrap_or("");
    assert!(
        !added_block.contains("labels ="),
        "empty labels list must not emit a labels= line:\n{added_block}"
    );
}

#[test]
fn cmd_add_url_strips_leading_slash_from_repo() {
    // args.repo = "/owner/repo" → trim_start_matches('/') → URL
    // is https://github.com/owner/repo (no leading slash, no `//`).
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    write_minimal_config(&config_path);
    let paths = Paths::default();
    let args = AddArgs {
        repo: "/owner/repo".into(),
        name: Some("owner-repo-1".into()),
        labels: vec![],
        auth: Some("pat".into()),
        no_apply: true,
        auto_approve: false,
    };
    cmd_add(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .unwrap();
    let after = fs::read_to_string(config_path.as_std_path()).unwrap();
    assert!(
        after.contains("url = \"https://github.com/owner/repo\""),
        "leading slash must be stripped; got:\n{after}"
    );
    assert!(
        !after.contains("https://github.com//"),
        "double slash must not appear in URL:\n{after}"
    );
}

#[test]
fn cmd_add_appends_newline_when_existing_file_lacks_one() {
    // Edge case: existing config doesn't end with `\n`. cmd_add
    // must push a newline before the [[runner]] block so the new
    // block doesn't run into the previous line.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // Note: NO trailing newline.
    let body = "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"";
    fs::write(config_path.as_std_path(), body).unwrap();
    let paths = Paths::default();
    let args = AddArgs {
        repo: "owner/repo".into(),
        name: Some("owner-repo-1".into()),
        labels: vec![],
        auth: Some("pat".into()),
        no_apply: true,
        auto_approve: false,
    };
    cmd_add(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .unwrap();
    let after = fs::read_to_string(config_path.as_std_path()).unwrap();
    // The trailing `token_env = "GHARS_PAT"` line + the new
    // [[runner]] block must not be on the same line.
    assert!(
        !after.contains("token_env = \"GHARS_PAT\"[[runner]]"),
        "missing newline between original tail and appended block:\n{after}"
    );
    // And the appended block lands.
    assert!(after.contains("[[runner]]"));
    assert!(after.contains("name = \"owner-repo-1\""));
}

// ---------- drift_cause label coverage ----------------------------

#[test]
fn drift_cause_labels_cover_each_variant() {
    assert_eq!(plan::DriftCause::SpecChanged.label(), "spec_changed");
    assert_eq!(plan::DriftCause::DriftDetected.label(), "drift_detected");
    assert_eq!(
        plan::DriftCause::SpecChangedAndDriftDetected.label(),
        "spec_changed_and_drift_detected"
    );
}

// ---------- cmd_completions / cmd_manpages ------------------------

#[test]
fn cmd_completions_to_writes_bash_completion_script() {
    // Capture into Vec<u8> via the test seam. Bash completions
    // begin with `_ghars()` (the bash function definition that
    // clap_complete emits as the entry point).
    let mut buf: Vec<u8> = Vec::new();
    cmd_completions_to(clap_complete::Shell::Bash, &mut buf);
    let text = String::from_utf8(buf).expect("bash completion is utf-8");
    assert!(
        text.contains("_ghars()"),
        "bash completion missing _ghars(): {}",
        &text[..text.len().min(200)]
    );
    // The completion script must reference at least one
    // subcommand so a regression that drops the subcommand
    // tree surfaces here.
    assert!(text.contains("apply"), "bash completion missing 'apply'");
}

#[test]
fn cmd_completions_to_writes_zsh_completion_script() {
    // Zsh completions begin with `#compdef ghars`.
    let mut buf: Vec<u8> = Vec::new();
    cmd_completions_to(clap_complete::Shell::Zsh, &mut buf);
    let text = String::from_utf8(buf).expect("zsh completion is utf-8");
    assert!(
        text.contains("#compdef ghars"),
        "zsh completion missing #compdef header"
    );
}

#[test]
fn cmd_completions_to_writes_fish_completion_script() {
    // Fish completions use `complete -c ghars`.
    let mut buf: Vec<u8> = Vec::new();
    cmd_completions_to(clap_complete::Shell::Fish, &mut buf);
    let text = String::from_utf8(buf).expect("fish completion is utf-8");
    assert!(
        text.contains("complete -c ghars"),
        "fish completion missing 'complete -c ghars' marker"
    );
}

#[test]
fn cmd_completions_to_writes_powershell_completion_script() {
    // PowerShell completions use `Register-ArgumentCompleter`.
    let mut buf: Vec<u8> = Vec::new();
    cmd_completions_to(clap_complete::Shell::PowerShell, &mut buf);
    let text = String::from_utf8(buf).expect("pwsh completion is utf-8");
    assert!(
        text.contains("Register-ArgumentCompleter"),
        "powershell completion missing 'Register-ArgumentCompleter'"
    );
    assert!(
        text.contains("'ghars'"),
        "powershell completion missing 'ghars' command name"
    );
}

#[test]
fn cmd_completions_to_writes_elvish_completion_script() {
    // Elvish completions use `set edit:completion:arg-completer`.
    let mut buf: Vec<u8> = Vec::new();
    cmd_completions_to(clap_complete::Shell::Elvish, &mut buf);
    let text = String::from_utf8(buf).expect("elvish completion is utf-8");
    assert!(
        text.contains("edit:completion:arg-completer"),
        "elvish completion missing 'edit:completion:arg-completer'"
    );
    assert!(
        text.contains("ghars"),
        "elvish completion missing 'ghars' command name"
    );
}

#[test]
fn cmd_manpages_creates_missing_output_directory() {
    // Pass a non-existent path inside tempdir. cmd_manpages must
    // call `fs::create_dir_all` and produce the man page tree.
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("does").join("not").join("exist");
    let out = Utf8PathBuf::from_path_buf(nested.clone()).unwrap();
    assert!(!nested.exists(), "precondition: target must not exist");
    let exit = cmd_manpages(&out).unwrap();
    assert_eq!(exit, 0);
    assert!(
        nested.exists() && nested.is_dir(),
        "cmd_manpages must create the output directory"
    );
    assert!(
        out.join("ghars.1").as_std_path().exists(),
        "top-level manpage missing in created dir"
    );
}

#[test]
fn cmd_manpages_top_level_body_contains_troff_header() {
    // The manpage body emitted by clap_mangen begins with a
    // `.TH "GHARS" "1" ...` header line (troff title-header).
    // Pin the macro name + section number so a future
    // clap_mangen output regression that drops the header
    // (producing an unrenderable manpage that `man` can't parse)
    // surfaces here.
    let dir = tempfile::tempdir().unwrap();
    let out = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
    cmd_manpages(&out).unwrap();
    let body = std::fs::read_to_string(out.join("ghars.1").as_std_path()).unwrap();
    assert!(
        body.contains(".TH ghars 1"),
        "manpage missing .TH ghars 1 troff header: preview {}",
        &body[..body.len().min(300)]
    );
    // The NAME section follows immediately after .TH per troff
    // convention; pin so clap_mangen reorderings surface here.
    assert!(
        body.contains(".SH NAME"),
        "manpage missing .SH NAME section: preview {}",
        &body[..body.len().min(300)]
    );
}

#[test]
fn cmd_manpages_writes_top_level_and_per_subcommand_files() {
    let dir = tempfile::tempdir().unwrap();
    let out = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
    let exit = cmd_manpages(&out).unwrap();
    assert_eq!(exit, 0);
    // Top-level page must exist.
    let top = out.join("ghars.1");
    assert!(
        top.as_std_path().exists(),
        "top-level manpage missing: {top}"
    );
    // Each visible subcommand also gets a `ghars-NAME.1` file.
    // Pick a few stable ones.
    for sub in ["apply", "plan", "status", "init", "validate"] {
        let path = out.join(format!("ghars-{sub}.1"));
        assert!(
            path.as_std_path().exists(),
            "missing manpage for `{sub}`: {path}"
        );
    }
    // Hidden subcommands must NOT be emitted (the loop in
    // cmd_manpages skips `is_hide_set()`).
    let hidden = out.join("ghars-_netns-setup.1");
    assert!(
        !hidden.as_std_path().exists(),
        "hidden subcommand should not have a manpage: {hidden}"
    );
    // The body of the top-level manpage must mention the binary
    // name in nroff format. This kills a mutant that writes an
    // empty file.
    let body = std::fs::read_to_string(top.as_std_path()).unwrap();
    assert!(
        body.contains("ghars"),
        "manpage body missing 'ghars': preview {}",
        &body[..body.len().min(200)]
    );
}

// ---------- dispatch routing parses every Command variant ---------
//
// The `dispatch` function itself touches systemd / D-Bus / netns
// helpers, so it can't be invoked directly in unit tests. The
// testable obligation is that EVERY Command variant has an argv
// shape that parses correctly and produces the expected
// Command::* discriminant. An exhaustive match in the test body
// ensures that adding a new variant without a parse test fails
// the compile (the `match cli.command` would emit a
// non-exhaustive-pattern error).

#[test]
fn dispatch_routing_validate() {
    assert!(matches!(
        parse_command(&["ghars", "validate"]),
        Command::Validate(_)
    ));
}

#[test]
fn dispatch_routing_plan() {
    assert!(matches!(
        parse_command(&["ghars", "plan"]),
        Command::Plan(_)
    ));
}

#[test]
fn dispatch_routing_apply() {
    assert!(matches!(
        parse_command(&["ghars", "apply"]),
        Command::Apply(_)
    ));
}

#[test]
fn dispatch_routing_status() {
    assert!(matches!(
        parse_command(&["ghars", "status"]),
        Command::Status(_)
    ));
}

#[test]
fn dispatch_routing_init() {
    assert!(matches!(
        parse_command(&["ghars", "init"]),
        Command::Init(_)
    ));
}

#[test]
fn dispatch_routing_add() {
    assert!(matches!(
        parse_command(&["ghars", "add", "--repo", "owner/repo", "--auth", "pat",]),
        Command::Add(_)
    ));
}

#[test]
fn dispatch_routing_logs() {
    assert!(matches!(
        parse_command(&["ghars", "logs"]),
        Command::Logs(_)
    ));
}

#[test]
fn dispatch_routing_metrics() {
    assert!(matches!(
        parse_command(&["ghars", "metrics"]),
        Command::Metrics(_)
    ));
}

#[test]
fn dispatch_routing_completions() {
    let cmd = parse_command(&["ghars", "completions", "bash"]);
    match cmd {
        Command::Completions { shell } => {
            assert!(matches!(shell, clap_complete::Shell::Bash));
        }
        other => panic!("expected Command::Completions, got {other:?}"),
    }
}

#[test]
fn dispatch_routing_manpages() {
    let cmd = parse_command(&["ghars", "manpages", "/tmp/man-out"]);
    match cmd {
        Command::Manpages { output } => {
            assert_eq!(output, Utf8PathBuf::from("/tmp/man-out"));
        }
        other => panic!("expected Command::Manpages, got {other:?}"),
    }
}

#[test]
fn dispatch_routing_netns_setup_hidden() {
    let cmd = parse_command(&["ghars", "_netns-setup", "buckos"]);
    match cmd {
        Command::NetnsSetup { instance } => assert_eq!(instance, "buckos"),
        other => panic!("expected Command::NetnsSetup, got {other:?}"),
    }
}

#[test]
fn dispatch_routing_netns_teardown_hidden() {
    let cmd = parse_command(&["ghars", "_netns-teardown", "buckos"]);
    match cmd {
        Command::NetnsTeardown { instance } => assert_eq!(instance, "buckos"),
        other => panic!("expected Command::NetnsTeardown, got {other:?}"),
    }
}

#[test]
fn dispatch_routing_netns_veth_hidden() {
    // Argv pattern matches what the netns template's ExecStart= emits
    // (bare `nft`, no absolute path). systemd hands the unit's PATH
    // to the spawned ghars process, which forwards it through
    // `ip netns exec`; the netns'd execvp resolves `nft` against
    // that PATH inside the netns child. See NETNS_TEMPLATE in
    // src/systemd/units.rs and `run_in_netns` in src/netns.rs.
    let cmd = parse_command(&[
        "ghars",
        "_netns-veth",
        "buckos",
        "nft",
        "-f",
        "/etc/ghars/nft.d/buckos-ns.nft",
    ]);
    match cmd {
        Command::NetnsVeth { instance, program } => {
            assert_eq!(instance, "buckos");
            assert_eq!(
                program,
                vec!["nft", "-f", "/etc/ghars/nft.d/buckos-ns.nft",]
            );
        }
        other => panic!("expected Command::NetnsVeth, got {other:?}"),
    }
}

/// Compile-time exhaustiveness gate: this test fails to COMPILE
/// if a new Command variant is added without extending the
/// `dispatch_routing`_* test suite. The match must list every
/// variant by name so the rustc non-exhaustive-pattern error
/// surfaces during routine `cargo check --tests`.
#[test]
fn dispatch_routing_variants_are_exhaustively_tested() {
    // Build one of each variant and pattern-match exhaustively.
    // Adding a new Command variant without updating the match
    // arms causes a compile error here.
    let variants: Vec<Command> = vec![
        parse_command(&["ghars", "validate"]),
        parse_command(&["ghars", "plan"]),
        parse_command(&["ghars", "apply"]),
        parse_command(&["ghars", "status"]),
        parse_command(&["ghars", "init"]),
        parse_command(&["ghars", "add", "--repo", "o/r"]),
        parse_command(&["ghars", "cleanup"]),
        parse_command(&["ghars", "logs"]),
        parse_command(&["ghars", "metrics"]),
        parse_command(&["ghars", "completions", "bash"]),
        parse_command(&["ghars", "manpages", "/tmp/x"]),
        parse_command(&["ghars", "_netns-setup", "x"]),
        parse_command(&["ghars", "_netns-teardown", "x"]),
        parse_command(&["ghars", "_netns-veth", "x", "/bin/true"]),
    ];
    // Verify exhaustively.
    let mut counts = [0usize; 14];
    for v in variants {
        #[allow(clippy::match_same_arms)]
        let idx = match v {
            Command::Validate(_) => 0,
            Command::Plan(_) => 1,
            Command::Apply(_) => 2,
            Command::Status(_) => 3,
            Command::Init(_) => 4,
            Command::Add(_) => 5,
            Command::Cleanup => 6,
            Command::Logs(_) => 7,
            Command::Metrics(_) => 8,
            Command::Completions { .. } => 9,
            Command::Manpages { .. } => 10,
            Command::NetnsSetup { .. } => 11,
            Command::NetnsTeardown { .. } => 12,
            Command::NetnsVeth { .. } => 13,
        };
        counts[idx] += 1;
    }
    // Exactly one of each variant landed.
    assert_eq!(
        counts, [1; 14],
        "every Command variant must round-trip exactly once: {counts:?}"
    );
}
