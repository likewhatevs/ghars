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
         link + runner example) — got {}",
        github_url_count
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
    // Pick a few that are stable in v0.1.
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
    let err = validate_no_duplicate_cache_kinds(&cfg)
        .expect_err("must reject three ccache pool refs");
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
    let err = validate_no_duplicate_cache_kinds(&cfg)
        .expect_err("two combined-kind pools must reject");
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
    validate_no_duplicate_cache_kinds(&cfg)
        .expect("one sccache + one ccache must pass validation");
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
    cfg.runners[0].caches =
        vec!["build".into(), "no-such-pool".into(), "obj".into(), "ghost".into()];
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
    validate_cache_pool_kinds_nonempty(&cfg)
        .expect("single-kind ccache pool must pass validation");
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
        msg.contains("dup-ktstr")
            && msg.contains("declares `ktstr`")
            && msg.contains("2 times"),
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
        msg.contains("mixed-dup")
            && msg.contains("declares `ccache`")
            && msg.contains("2 times"),
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

/// Build a ProxySpec with one CaCertBinding parameterized by
/// `env` and `path` for the proxy validator tests below. Both fields
/// individually testable; default ProxySpec is otherwise empty (no
/// http/https/no_proxy).
fn proxy_with_one_ca_cert(env: &str, path: &str) -> crate::config::ProxySpec {
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

/// Reject defaults.proxy ca_certs entry with empty env. The
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
        msg.contains("defaults.proxy ca_certs[0]") && msg.contains("empty or whitespace-only `env`"),
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
        msg.contains("defaults.proxy ca_certs[0]") && msg.contains("empty or whitespace-only `path`"),
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
        msg.contains("runner \"buckos\" proxy ca_certs[0]") && msg.contains("empty or whitespace-only `path`"),
        "error must name full runner-scope prefix + the empty-or-whitespace path failure: {msg}"
    );
}

/// Reject CaCertBinding with whitespace-only `env`. systemd's
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
    let err = validate_proxy_ca_certs_nonempty(&cfg)
        .expect_err("whitespace-only path must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("empty or whitespace-only `path`"),
        "error must name the whitespace-or-empty failure mode: {msg}"
    );
}

/// Reject CaCertBinding with non-absolute `path`. systemd's
/// `BindReadOnlyPaths=` requires absolute paths; a relative path
/// would resolve against systemd's working directory (`/`) at
/// unit-start and fail. Parallel to
/// `validate_cache_pool_binary_paths` enforcing the same gate for
/// sccache_path / sleep_path.
#[test]
fn validate_proxy_ca_certs_nonempty_rejects_non_absolute_path() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(proxy_with_one_ca_cert("NODE_EXTRA_CA_CERTS", "ca.pem"));
    let err = validate_proxy_ca_certs_nonempty(&cfg)
        .expect_err("relative path must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("non-absolute `path`") && msg.contains("ca.pem"),
        "error must name the non-absolute failure mode and cite the offending path: {msg}"
    );
}

// Runner-layer symmetry coverage: the three runner.path tests below
// mirror the defaults-side tests above (empty / whitespace / non-
// absolute). Without these, a regression that skipped path
// validation specifically on the runner-loop branch would not be
// caught by ANY existing path test — every other path-failure test
// exercises `cfg.proxy` (the defaults layer). Plus the runner.env
// whitespace test closes the env coverage matrix to 2x2 (defaults
// gets empty+whitespace; runner now gets both too).

#[test]
fn validate_proxy_ca_certs_nonempty_rejects_runner_whitespace_only_env() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.runners[0].proxy = Some(proxy_with_one_ca_cert("\t", "/etc/ssl/certs/ca.pem"));
    let err = validate_proxy_ca_certs_nonempty(&cfg)
        .expect_err("runner.proxy ca_certs with whitespace-only env must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("runner \"buckos\" proxy ca_certs[0]") && msg.contains("empty or whitespace-only `env`"),
        "error must name full runner-scope prefix + whitespace-or-empty env failure: {msg}"
    );
}

#[test]
fn validate_proxy_ca_certs_nonempty_rejects_runner_whitespace_only_path() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.runners[0].proxy = Some(proxy_with_one_ca_cert("NODE_EXTRA_CA_CERTS", "   "));
    let err = validate_proxy_ca_certs_nonempty(&cfg)
        .expect_err("runner.proxy ca_certs with whitespace-only path must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("runner \"buckos\" proxy ca_certs[0]") && msg.contains("empty or whitespace-only `path`"),
        "error must name full runner-scope prefix + whitespace-or-empty path failure: {msg}"
    );
}

#[test]
fn validate_proxy_ca_certs_nonempty_rejects_runner_non_absolute_path() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.runners[0].proxy = Some(proxy_with_one_ca_cert("NODE_EXTRA_CA_CERTS", "ca.pem"));
    let err = validate_proxy_ca_certs_nonempty(&cfg)
        .expect_err("runner.proxy ca_certs with relative path must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("runner \"buckos\" proxy ca_certs[0]") && msg.contains("non-absolute `path`") && msg.contains("ca.pem"),
        "error must name full runner-scope prefix + non-absolute failure + offending path: {msg}"
    );
}

#[test]
fn validate_proxy_ca_certs_nonempty_accepts_fully_populated_binding() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(proxy_with_one_ca_cert(
        "NODE_EXTRA_CA_CERTS",
        "/etc/ssl/certs/ca-bundle.pem",
    ));
    validate_proxy_ca_certs_nonempty(&cfg)
        .expect("fully-populated ca_cert binding must pass");
}

#[test]
fn validate_proxy_ca_certs_nonempty_accepts_no_proxy_block() {
    let cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    // cfg.proxy = None; no runner.proxy either. Validator must
    // pass vacuously when no proxy block exists.
    validate_proxy_ca_certs_nonempty(&cfg)
        .expect("config with no proxy block must pass vacuously");
}

#[test]
fn validate_proxy_ca_certs_nonempty_accepts_empty_ca_certs_list() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(crate::config::ProxySpec::default());
    // Default ca_certs is `vec![]` — vacuously satisfied (no
    // bindings to check). Distinct from rejecting one with empty
    // fields.
    validate_proxy_ca_certs_nonempty(&cfg)
        .expect("empty ca_certs Vec must pass (nothing to check)");
}

// -------- validate_proxy_no_proxy_nonempty_entries ------------------

#[test]
fn validate_proxy_no_proxy_nonempty_entries_rejects_defaults_empty_entry() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(crate::config::ProxySpec {
        http: None,
        https: None,
        no_proxy: vec!["".into()],
        ca_certs: vec![],
    });
    let err = validate_proxy_no_proxy_nonempty_entries(&cfg)
        .expect_err("defaults.proxy no_proxy = [\"\"] must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("defaults.proxy no_proxy[0]") && msg.contains("empty or whitespace-only entry"),
        "error must name defaults.proxy + index + empty-or-whitespace entry: {msg}"
    );
}

#[test]
fn validate_proxy_no_proxy_nonempty_entries_rejects_middle_empty_entry() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(crate::config::ProxySpec {
        http: None,
        https: None,
        no_proxy: vec![
            "host.example.com".into(),
            "".into(),
            "other.example.com".into(),
        ],
        ca_certs: vec![],
    });
    let err = validate_proxy_no_proxy_nonempty_entries(&cfg)
        .expect_err("mid-list empty no_proxy entry must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("no_proxy[1]"),
        "error must name the specific index of the empty entry: {msg}"
    );
}

#[test]
fn validate_proxy_no_proxy_nonempty_entries_rejects_runner_empty_entry() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.runners[0].proxy = Some(crate::config::ProxySpec {
        http: None,
        https: None,
        no_proxy: vec!["".into()],
        ca_certs: vec![],
    });
    let err = validate_proxy_no_proxy_nonempty_entries(&cfg)
        .expect_err("runner.proxy no_proxy = [\"\"] must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("runner \"buckos\"") && msg.contains("no_proxy[0]"),
        "error must name runner scope + index: {msg}"
    );
}

#[test]
fn validate_proxy_no_proxy_nonempty_entries_accepts_empty_list() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(crate::config::ProxySpec::default());
    // Default no_proxy is `vec![]` — vacuously satisfied. The
    // semantic of "proxy applies to all hosts" is a valid operator
    // intent and must not be rejected.
    validate_proxy_no_proxy_nonempty_entries(&cfg)
        .expect("empty no_proxy Vec must pass (proxy applies to all hosts)");
}

/// Reject whitespace-only no_proxy entry. systemd's `Environment=`
/// would render `Environment=NO_PROXY=host,   ,host2` — strict HTTP
/// clients still reject the adjacent-empty token. The validator's
/// `trim().is_empty()` check catches both empty and whitespace-only
/// uniformly.
#[test]
fn validate_proxy_no_proxy_nonempty_entries_rejects_whitespace_only_entry() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(crate::config::ProxySpec {
        http: None,
        https: None,
        no_proxy: vec!["   ".into()],
        ca_certs: vec![],
    });
    let err = validate_proxy_no_proxy_nonempty_entries(&cfg)
        .expect_err("whitespace-only no_proxy entry must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("empty or whitespace-only entry"),
        "error must name the whitespace-or-empty failure mode: {msg}"
    );
}

#[test]
fn validate_proxy_no_proxy_nonempty_entries_accepts_populated_entries() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(crate::config::ProxySpec {
        http: None,
        https: None,
        no_proxy: vec![
            "host.example.com".into(),
            "*.internal.example.com".into(),
            "10.0.0.0/8".into(),
        ],
        ca_certs: vec![],
    });
    validate_proxy_no_proxy_nonempty_entries(&cfg)
        .expect("non-empty entries must pass");
}

// -------- AuthSpec::Pat XOR shape gate ------------------------------

/// Build a fixture Config with a single `[auth.NAME]` entry of
/// `AuthSpec::Pat` and the runner's auth ref pointing at `name`. The
/// 4+ reject tests below all share this scaffold — the helper
/// collapses the boilerplate and pins the auth-name → error
/// scope linkage in one place.
///
/// `cfg_with_runner_trust_zone` inserts `[auth.pat]` by default;
/// this helper unconditionally clears the inherited `[auth.pat]`
/// entry then inserts `[auth.NAME]` so the resulting Config has
/// exactly one auth entry under `name`.

/// Run `validate_pat_xor(cfg)`, expect a `GharsError::Validation`,
/// and assert every substring in `msg_parts` appears in the
/// message, every substring in `hint_parts` appears in the
/// hint, and every substring in `must_not_contain` appears in
/// NEITHER the message NOR the hint. Always pins:
///   - variant is `Validation` (no Ok, no other error class).
///   - msg contains the colon-space `auth "NAME": ` scope shape
///     emitted by `prepend_validation_scope`.
///   - msg does NOT contain a redundant `kind = pat`/`kind =
///     "pat"` prefix — the scope already identifies
///     the offending `[auth.NAME]` block and `AuthSpec::Pat` is the
///     only variant the loop checks.
///   - hint is non-empty.
#[track_caller]

/// `[auth.NAME]` with `kind = "pat"` and BOTH `token_env` and
/// `token_file` set must reject at config-load. `PatToken::new`
/// re-validates at apply time, but `cmd_validate` / `cmd_plan`
/// short-circuit before reaching `build_token_source` — the
/// `load_config` gate is the operator-visible rejection point for
/// `ghars validate`.
#[test]
fn validate_pat_xor_rejects_both_token_env_and_token_file_set() {
    let cfg = cfg_with_pat_auth("pat", Some("GHARS_PAT"), Some("/etc/ghars/pat"));
    assert_pat_xor_rejects(&cfg, "pat", &["mutually exclusive"], &["remove one"], &[]);
}

/// `[auth.NAME]` with `kind = "pat"` and NEITHER
/// `token_env` nor `token_file` set must reject at config-load.
/// Symmetric with the (Some, Some) gate — the only Ok shape is
/// (Some, None) or (None, Some).
#[test]
fn validate_pat_xor_rejects_both_token_env_and_token_file_unset() {
    let cfg = cfg_with_pat_auth("pat", None, None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["exactly one"],
        &["token_env", "token_file"],
        &[],
    );
}

/// Env-only PAT (the `cfg_with_runner_trust_zone` default
/// shape) is the canonical Ok arm. Pinned so a future regression
/// that broadened the validator into rejecting the happy path is
/// caught.
#[test]
fn validate_pat_xor_accepts_token_env_only() {
    let cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    // The fixture inserts AuthSpec::Pat { token_env: Some, token_file: None }
    validate_pat_xor(&cfg).expect("env-only PAT must pass validation");
}

/// File-only PAT — the symmetric Ok arm. The shape-only gate
/// MUST accept (None, Some) at config-load; `PatToken::new` runs
/// the SEC-25 mode-0600 + owner-root + not-symlink check at apply
/// time. Pinned so a future regression that rejects (None, Some)
/// (e.g. a confused negation) is caught.
#[test]
fn validate_pat_xor_accepts_token_file_only() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/pat"));
    validate_pat_xor(&cfg).expect("file-only PAT must pass validation");
}

/// `token_env = ""` (empty string) is shape-valid TOML but
/// useless — `std::env::var("")` always returns `NotPresent`. The
/// shape gate must reject this at config-load with an actionable
/// message instead of falling through to apply where it surfaces
/// as "env var unset".
///
/// Hint shape is pinned via `assert_pat_xor_rejects` —
/// asserts the hint references "environment variable" (the
/// remediation domain) and the canonical example `token_env` =
/// "`GHARS_PAT`" so a future regression that drops the example
/// value or shifts the field-name reference is caught.
#[test]
fn validate_pat_xor_rejects_empty_token_env() {
    let cfg = cfg_with_pat_auth("pat", Some(""), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable", "GHARS_PAT"],
        &[],
    );
}

/// `token_file = ""` (empty string) is shape-valid TOML but
/// useless — `Utf8PathBuf::from("")` is empty and `read_root_owned_0600`
/// would fail with a confusing "open failed" error. The shape gate
/// must reject this at config-load with an actionable message.
///
/// Hint shape pinned — references the SEC-25 invariant
/// ("0600 root-owned file") and the canonical example
/// `token_file` = "/etc/ghars/pat".
#[test]
fn validate_pat_xor_rejects_empty_token_file() {
    let cfg = cfg_with_pat_auth("pat", None, Some(""));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "is empty or whitespace-only"],
        &["0600 root-owned file", "/etc/ghars/pat"],
        &[],
    );
}

/// A single-space `token_env = " "` is shape-valid TOML but
/// useless for the same reason `token_env = ""` is — env-var
/// names cannot contain spaces. Without this gate the check ran
/// `is_empty()` which returned false for `" "`, so a misconfigured
/// whitespace-only value flowed through to apply where
/// `std::env::var(" ")` returns `NotPresent` (or worse, succeeds
/// on a shell that exported a literal-space env var). The post-fix
/// gate uses `trim().is_empty()` so all-whitespace values reject
/// with the same actionable diagnostic as truly empty ones.
#[test]
fn validate_pat_xor_rejects_whitespace_only_token_env_space() {
    let cfg = cfg_with_pat_auth("pat", Some(" "), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable", "GHARS_PAT"],
        &[],
    );
}

/// Tab-only `token_env = "\t"` — same gate, different
/// whitespace class (HT, U+0009). `str::trim` strips Unicode
/// whitespace per `char::is_whitespace`, of which `\t` is one.
/// Pinned so a regression that narrows `trim()` to spaces only
/// (e.g. `s.replace(' ', "").is_empty()`) is caught.
#[test]
fn validate_pat_xor_rejects_whitespace_only_token_env_tab() {
    let cfg = cfg_with_pat_auth("pat", Some("\t"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable"],
        &[],
    );
}

/// CRLF `token_env = "\r\n"` — operators occasionally paste
/// from Windows tools that include `\r\n`. `str::trim` strips
/// both. Pinned so the gate covers the full Unicode-whitespace
/// surface, not just ASCII-32.
#[test]
fn validate_pat_xor_rejects_whitespace_only_token_env_crlf() {
    let cfg = cfg_with_pat_auth("pat", Some("\r\n"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable"],
        &[],
    );
}

/// Mixed whitespace `token_env = " \t\n "` — must reject.
/// Pins that the gate rejects ANY all-whitespace combination, not
/// just single-class runs.
#[test]
fn validate_pat_xor_rejects_whitespace_only_token_env_mixed() {
    let cfg = cfg_with_pat_auth("pat", Some(" \t\n "), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable"],
        &[],
    );
}

/// Whitespace-only `token_file = " "` — symmetric with the
/// `token_env` gate. `Utf8PathBuf::from(" ")` is a path with a
/// single-space basename which would surface as a confusing
/// "open failed" or "stat failed" error inside `PatToken::new`.
#[test]
fn validate_pat_xor_rejects_whitespace_only_token_file_space() {
    let cfg = cfg_with_pat_auth("pat", None, Some(" "));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "is empty or whitespace-only"],
        &["0600 root-owned file", "/etc/ghars/pat"],
        &[],
    );
}

/// Tab-only `token_file = "\t"`.
#[test]
fn validate_pat_xor_rejects_whitespace_only_token_file_tab() {
    let cfg = cfg_with_pat_auth("pat", None, Some("\t"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "is empty or whitespace-only"],
        &["0600 root-owned file"],
        &[],
    );
}

/// CRLF `token_file = "\r\n"` — symmetric with the
/// `token_env` CRLF gate. Operators occasionally paste from
/// Windows tools that include `\r\n`. `str::trim` strips both,
/// so the gate rejects.
#[test]
fn validate_pat_xor_rejects_whitespace_only_token_file_crlf() {
    let cfg = cfg_with_pat_auth("pat", None, Some("\r\n"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "is empty or whitespace-only"],
        &["0600 root-owned file"],
        &[],
    );
}

/// Mixed whitespace `token_file = " \t\n "` — symmetric
/// with the `token_env` mixed-whitespace gate. Pins that the
/// `token_file` gate rejects ANY all-whitespace combination, not
/// just single-class runs.
#[test]
fn validate_pat_xor_rejects_whitespace_only_token_file_mixed() {
    let cfg = cfg_with_pat_auth("pat", None, Some(" \t\n "));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "is empty or whitespace-only"],
        &["0600 root-owned file"],
        &[],
    );
}

/// (Unicode pin): NBSP `token_env = "\u{00A0}"`
/// (no-break space, U+00A0) — Unicode whitespace beyond ASCII.
/// `str::trim` defers to `char::is_whitespace` which includes
/// the Unicode `White_Space` property; NBSP is one. Pinned so
/// the gate's coverage extends past ASCII-32/9/10/13 to the
/// full Unicode whitespace surface — a regression that narrows
/// to ASCII-only (e.g. `s.bytes().all(u8::is_ascii_whitespace)`)
/// would silently let NBSP-only env-var names flow through.
#[test]
fn validate_pat_xor_rejects_whitespace_only_token_env_nbsp() {
    let cfg = cfg_with_pat_auth("pat", Some("\u{00A0}"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable"],
        &[],
    );
}

/// `token_env = "X "` (trailing space on real content) rejects
/// via the env-side trim-mismatch gate, BEFORE the POSIX charset
/// gate. Without the trim-mismatch gate, "X " would fall through
/// to the POSIX charset gate, surfacing "is not a valid POSIX
/// environment variable name" — technically correct but
/// misleading: the operator's intent is almost certainly a
/// shell-quoting hiccup, not a charset violation. The
/// trim-mismatch arm fires first with a dedicated diagnostic
/// that names the condition.
#[test]
fn validate_pat_xor_rejects_token_env_trailing_space_on_real_content() {
    let cfg = cfg_with_pat_auth("pat", Some("X "), None);
    // Precedence pin: the trim-mismatch arm fires AFTER the
    // empty/whitespace and hidden-char arms but BEFORE the POSIX
    // charset arm; the diagnostic must NOT carry either of those
    // other gates' text.
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "leading or trailing whitespace"],
        &["GHARS_PAT"],
        &[
            "is empty or whitespace-only",
            "hidden character",
            "POSIX environment variable name",
        ],
    );
}

/// `token_file = "/etc/ghars/pat "` (trailing space on real
/// content) rejects via the trim-mismatch gate. The trim-mismatch
/// check catches a path whose edges carry extra whitespace which
/// would surface as `open(2)` ENOENT on a literal-space basename.
/// Pinned so a future regression that drops the trim-mismatch
/// gate is caught.
#[test]
fn validate_pat_xor_rejects_token_file_trailing_space_on_real_content() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/pat "));
    // Precedence pin: the trim-mismatch arm fires AFTER the
    // empty/whitespace and hidden-char arms; the diagnostic
    // emitted here must NOT carry either preceding gate's text.
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "leading or trailing whitespace"],
        &["/etc/ghars/pat"],
        &["is empty or whitespace-only", "hidden character"],
    );
}

/// `token_env = " X"` (leading-only whitespace on real
/// content) rejects via the trim-mismatch gate before reaching
/// the POSIX charset check. Symmetric with the trailing-space
/// pin.
#[test]
fn validate_pat_xor_rejects_token_env_leading_space_on_real_content() {
    let cfg = cfg_with_pat_auth("pat", Some(" X"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "leading or trailing whitespace"],
        &["GHARS_PAT"],
        &[
            "is empty or whitespace-only",
            "hidden character",
            "POSIX environment variable name",
        ],
    );
}

/// `token_env = " X "` (leading + trailing whitespace on
/// real content) rejects via the trim-mismatch gate. Pinned
/// alongside the leading-only and trailing-only cases so a
/// regression that only handles one edge is caught.
#[test]
fn validate_pat_xor_rejects_token_env_both_sides_space_on_real_content() {
    let cfg = cfg_with_pat_auth("pat", Some(" X "), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "leading or trailing whitespace"],
        &["GHARS_PAT"],
        &[
            "is empty or whitespace-only",
            "hidden character",
            "POSIX environment variable name",
        ],
    );
}

/// `token_file = " /etc/ghars/pat"` (leading-only
/// whitespace on real content) rejects via the trim-mismatch
/// gate. Symmetric with the trailing-space pin; `path !=
/// path.trim()` catches both edges.
#[test]
fn validate_pat_xor_rejects_token_file_leading_space_on_real_content() {
    let cfg = cfg_with_pat_auth("pat", None, Some(" /etc/ghars/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "leading or trailing whitespace"],
        &["/etc/ghars/pat"],
        &["is empty or whitespace-only", "hidden character"],
    );
}

/// `token_file = " /etc/ghars/pat "` (leading + trailing
/// whitespace on real content) rejects via the trim-mismatch
/// gate. Pinned alongside the leading-only and trailing-only
/// cases.
#[test]
fn validate_pat_xor_rejects_token_file_both_sides_space_on_real_content() {
    let cfg = cfg_with_pat_auth("pat", None, Some(" /etc/ghars/pat "));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "leading or trailing whitespace"],
        &["/etc/ghars/pat"],
        &["is empty or whitespace-only", "hidden character"],
    );
}

/// A POSIX-violating `token_env` (e.g. `"FOO-BAR"` with a
/// dash, which `std::env::var` accepts as a lookup key but whose
/// shape is not a portable POSIX env var name) rejects with a
/// charset diagnostic. Pinned independently of the
/// leading/trailing-whitespace tests so a regression that
/// narrows the POSIX gate to just whitespace rejection (and
/// silently accepts arbitrary punctuation) is caught.
#[test]
fn validate_pat_xor_rejects_token_env_with_non_posix_chars() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO-BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &["is empty or whitespace-only", "hidden character"],
    );
}

/// `token_env` starting with a digit (e.g. `"1FOO"`)
/// rejects via POSIX charset. POSIX names must start with a
/// letter or underscore — digit-leading shells often accept it
/// in practice but the standard forbids it, and a portable
/// runner config should reject the unportable form.
#[test]
fn validate_pat_xor_rejects_token_env_starting_with_digit() {
    let cfg = cfg_with_pat_auth("pat", Some("1FOO"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &["is empty or whitespace-only", "hidden character"],
    );
}

/// NEGATIVE pin: a clean POSIX-conformant `token_env`
/// (canonical `"GHARS_PAT"`) MUST pass the charset gate. Pinned
/// so a future regression that over-tightens the regex (e.g.
/// drops `_` from the first-char class, or rejects all-uppercase
/// names) is caught.
#[test]
fn validate_pat_xor_accepts_token_env_canonical_posix_name() {
    let cfg = cfg_with_pat_auth("pat", Some("GHARS_PAT"), None);
    validate_pat_xor(&cfg).expect("canonical POSIX token_env must pass shape gate");
}

/// NEGATIVE pin: a single-letter `token_env` (`"X"`) — the
/// shortest legal POSIX form — MUST pass. Boundary check on the
/// regex's `*` quantifier (zero or more trailing chars).
#[test]
fn validate_pat_xor_accepts_token_env_single_letter() {
    let cfg = cfg_with_pat_auth("pat", Some("X"), None);
    validate_pat_xor(&cfg).expect("single-letter POSIX token_env must pass shape gate");
}

/// NEGATIVE pin: a leading-underscore `token_env` (`"_FOO"`)
/// — the second legal POSIX first-char — MUST pass. POSIX env
/// var names start with `[A-Za-z_]`, so `_` is in the legal set.
#[test]
fn validate_pat_xor_accepts_token_env_leading_underscore() {
    let cfg = cfg_with_pat_auth("pat", Some("_FOO"), None);
    validate_pat_xor(&cfg).expect("leading-underscore POSIX token_env must pass shape gate");
}

/// `token_env` containing a NUL (U+0000) rejects via the
/// hidden-char gate. Surfaces the codepoint + byte offset so
/// the operator can locate the invisible char in their editor.
/// NUL is a control char so it would also be caught by the
/// `is_control()` arm of `is_disallowed_hidden_char`; pinning
/// it explicitly catches a regression that narrows the
/// explicit list and the control-char rule simultaneously.
#[test]
fn validate_pat_xor_rejects_token_env_with_nul() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{0000}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+0000", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_env` containing a BOM (U+FEFF) rejects via the
/// hidden-char gate. Operators occasionally paste from
/// Windows tools that prefix the value with a BOM; the byte
/// is invisible in most editors and would silently break
/// `std::env::var` lookup.
#[test]
fn validate_pat_xor_rejects_token_env_with_bom() {
    let cfg = cfg_with_pat_auth("pat", Some("\u{FEFF}GHARS_PAT"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+FEFF", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_env` containing a zero-width space (U+200B)
/// rejects via the hidden-char gate. Pinned alongside BOM and
/// NUL so the entire default-ignorable set defends against
/// invisible breakage.
#[test]
fn validate_pat_xor_rejects_token_env_with_zero_width_space() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{200B}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+200B", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_env` containing a zero-width non-joiner (U+200C)
/// rejects via the hidden-char gate. Together with the ZWSP /
/// ZWJ / WJ pins, covers the default-ignorable format
/// characters most likely to survive a copy-paste from a
/// rich-text doc.
#[test]
fn validate_pat_xor_rejects_token_env_with_zero_width_non_joiner() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{200C}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+200C", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_env` containing a soft hyphen (U+00AD) rejects
/// via the hidden-char gate. SHY is not a control char, so
/// `is_control()` would not catch it — the explicit list arm
/// fires.
#[test]
fn validate_pat_xor_rejects_token_env_with_soft_hyphen() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{00AD}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+00AD", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_file` containing a BOM (U+FEFF) at the start
/// rejects via the hidden-char gate. Symmetric with the
/// `token_env` BOM pin; the path-side surface is independent
/// because paths lack the POSIX charset gate that catches BOM
/// implicitly on the env-var side.
#[test]
fn validate_pat_xor_rejects_token_file_with_bom() {
    let cfg = cfg_with_pat_auth("pat", None, Some("\u{FEFF}/etc/ghars/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "hidden character", "U+FEFF", "byte offset"],
        &["/etc/ghars/pat"],
        &[],
    );
}

/// `token_file` containing a NUL (U+0000) rejects via the
/// hidden-char gate. NUL terminates C strings, so an embedded
/// NUL in a path would surface as a confusing kernel error
/// (or worse, silently truncate the path) at apply time.
#[test]
fn validate_pat_xor_rejects_token_file_with_nul() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/\u{0000}ghars/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "hidden character", "U+0000", "byte offset"],
        &["/etc/ghars/pat"],
        &[],
    );
}

/// `token_file` containing a zero-width joiner (U+200D)
/// rejects via the hidden-char gate. Symmetric with the
/// `token_env` ZWNJ pin.
#[test]
fn validate_pat_xor_rejects_token_file_with_zero_width_joiner() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{200D}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "hidden character", "U+200D", "byte offset"],
        &["/etc/ghars/pat"],
        &[],
    );
}

/// `token_env` containing a word joiner (U+2060) rejects
/// via the hidden-char gate. Each explicit codepoint slot in
/// `is_disallowed_hidden_char` (NUL/SHY/CGJ/ALM/MVS, the
/// ZWSP-ZWNJ-ZWJ-LRM-RLM block, the bidi-override block,
/// the WJ + invisible-math block, the bidi-isolate block,
/// the variation-selector block, and BOM) is pinned by at least
/// one test so a regression that drops a slot from the matches
/// arm is caught. ZWJ is covered by the `token_file` pin; this
/// test pins WJ on the `token_env` side.
#[test]
fn validate_pat_xor_rejects_token_env_with_word_joiner() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{2060}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+2060", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_env` containing an ESC control char (U+001B)
/// rejects via the `is_control()` arm of `is_disallowed_hidden_char`.
/// Pinned independently of the explicit-codepoint matches so a
/// regression that narrows the control-char arm (e.g. drops it
/// in favor of the explicit-only list) is caught — the explicit
/// arm covers a finite set of default-ignorable / format
/// codepoints; the control-char arm covers the rest of category
/// Cc. ESC is the canonical attacker vector for terminal-escape
/// injection, so this test doubles as a defense-in-depth pin
/// against ANSI escapes flowing through env-var values.
#[test]
fn validate_pat_xor_rejects_token_env_with_control_char_esc() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{001B}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+001B", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// Precedence pin: hidden-char gate fires BEFORE the POSIX
/// charset gate. Input `"\u{FEFF}foo-bar"` would fail BOTH:
/// the BOM is in the explicit hidden-char list, AND the dash
/// in `foo-bar` violates POSIX charset. The hidden-char gate is
/// reached first (cli.rs `check_empty_or_hidden` runs before the
/// regex match), so the diagnostic must surface as
/// "hidden character ... U+FEFF" — not "POSIX environment
/// variable name". Pinned so a future restructure that flips
/// gate ordering (and surfaces the less-actionable POSIX
/// diagnostic for invisible-char inputs) is caught.
#[test]
fn validate_pat_xor_precedence_hidden_char_before_posix_charset() {
    let cfg = cfg_with_pat_auth("pat", Some("\u{FEFF}foo-bar"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["hidden character", "U+FEFF"],
        &["GHARS_PAT"],
        &["POSIX environment variable name"],
    );
}

/// `token_env = "X\u{FEFF}FOO"` — non-zero byte offset
/// pin. The hidden char (BOM, 3-byte UTF-8 sequence) sits at
/// byte offset 1 (after a 1-byte ASCII 'X'). The diagnostic
/// must surface "byte offset 1" — not 0 or any character index.
/// Pinned so a regression that emits a character index instead
/// of a byte offset (e.g. swapping `char_indices` for chars) is
/// caught.
#[test]
fn validate_pat_xor_rejects_token_env_hidden_char_at_nonzero_byte_offset() {
    let cfg = cfg_with_pat_auth("pat", Some("X\u{FEFF}FOO"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["hidden character", "U+FEFF", "byte offset 1"],
        &["GHARS_PAT"],
        &[],
    );
}

/// NEGATIVE pin: `token_file = "/etc/ghars/my pat"` (real
/// path with internal whitespace, no edge whitespace) MUST
/// PASS the shape gate. `path_str != path_str.trim()` is FALSE
/// when whitespace is purely internal — Unix paths can legally
/// contain spaces (mount points, user-chosen filenames).
/// Pinned so a regression that broadens the gate (e.g. to
/// `path.contains(char::is_whitespace)`) and silently rejects
/// valid paths with embedded spaces is caught.
#[test]
fn validate_pat_xor_accepts_token_file_with_internal_space() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/my pat"));
    validate_pat_xor(&cfg).expect("token_file with internal-only whitespace must pass shape gate");
}

/// Precedence pin: per-field gates fire BEFORE the XOR
/// tuple-match. Input `(Some("FOO-BAR"), Some("/etc/ghars/pat"))`
/// is BOTH XOR-violating (both fields set) AND charset-violating
/// on `token_env` (dash in "FOO-BAR"). The per-field charset gate
/// is reached on the env-side first, so the diagnostic surfaces
/// as "POSIX environment variable name" — not "mutually
/// exclusive". Pinned so a future restructure that hoists the
/// XOR check above the per-field gates is caught.
#[test]
fn validate_pat_xor_precedence_bad_env_clean_file_emits_charset_not_xor() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO-BAR"), Some("/etc/ghars/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["POSIX environment variable name"],
        &["GHARS_PAT"],
        &["mutually exclusive"],
    );
}

/// Scope-propagation pin: an unusual auth name combined
/// with the (true,true) XOR shape MUST scope the error to the
/// operator's chosen name. Sibling test
/// `validate_pat_xor_rejects_unusual_auth_name` exercises the
/// empty-env arm with the same auth name; this test exercises
/// the XOR arm so scope propagation is pinned across BOTH
/// rejection sites the function emits. Defense-in-depth: a
/// regression that hardcodes the "pat" substring inside the
/// XOR arm's error rendering would slip past the empty-arm
/// pin alone.
#[test]
fn validate_pat_xor_rejects_unusual_auth_name_xor_both_set() {
    let cfg = cfg_with_pat_auth(
        "alpha-zone-creds",
        Some("GHARS_PAT"),
        Some("/etc/ghars/pat"),
    );
    assert_pat_xor_rejects(
        &cfg,
        "alpha-zone-creds",
        &["mutually exclusive"],
        &["GHARS_PAT", "/etc/ghars/pat"],
        &[],
    );
}

/// An unusual auth name that does NOT contain "pat" as a
/// substring (e.g. `"alpha-zone-creds"`) MUST scope the error
/// correctly via `assert_pat_xor_rejects`. The helper pins the
/// scope shape (`auth "NAME": `) and the absence of redundant
/// `kind = pat` prefix; this test exercises the case where any
/// hardcoded substring drift in the rejector would slip past
/// the canonical "pat" name. Defense-in-depth — the validator
/// MUST identify the offending block by the operator's chosen
/// name, not by a hardcoded substring of the `AuthSpec` variant.
#[test]
fn validate_pat_xor_rejects_unusual_auth_name() {
    let cfg = cfg_with_pat_auth("alpha-zone-creds", Some(""), None);
    assert_pat_xor_rejects(
        &cfg,
        "alpha-zone-creds",
        &["token_env", "is empty or whitespace-only"],
        &["GHARS_PAT"],
        &[],
    );
}

/// The (true,true) XOR error hint includes both canonical
/// example values (`GHARS_PAT` and `/etc/ghars/pat`) so an
/// operator reading the rejection sees the same remediation
/// breadcrumb the empty-string / charset arms already provide.
/// Pinned so a future regression that strips the examples (or
/// only includes one) is caught.
#[test]
fn validate_pat_xor_rejects_both_set_with_concrete_example_hints() {
    let cfg = cfg_with_pat_auth("pat", Some("GHARS_PAT"), Some("/etc/ghars/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["mutually exclusive"],
        &["GHARS_PAT", "/etc/ghars/pat"],
        &[],
    );
}

/// The (false,false) "exactly one" hint includes both
/// canonical example values. Symmetric with the (true,true) pin.
#[test]
fn validate_pat_xor_rejects_neither_set_with_concrete_example_hints() {
    let cfg = cfg_with_pat_auth("pat", None, None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["exactly one"],
        &["GHARS_PAT", "/etc/ghars/pat"],
        &[],
    );
}

/// Precedence — `(Some(""), Some(""))` is BOTH XOR-violating
/// (both fields set) AND empty (each value is empty). The
/// validator emits the empty-token_env diagnostic FIRST because
/// the empty/whitespace gate fires before the XOR tuple match.
/// Pinned so a future restructure that flips the order (and
/// surfaces "mutually exclusive" instead of the more specific
/// "is empty" rejection) is caught — empty-string is the more
/// useful diagnostic because the operator is more likely to
/// have left the field as a placeholder than to have
/// genuinely intended both fields to coexist.
#[test]
fn validate_pat_xor_precedence_both_empty_emits_empty_env_not_xor() {
    let cfg = cfg_with_pat_auth("pat", Some(""), Some(""));
    // Inverse pin via must_not_contain: the XOR diagnostic must
    // NOT fire for this shape — the empty-token_env arm
    // short-circuits before the tuple match.
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable"],
        &["mutually exclusive"],
    );
}

/// Whitespace variant: `(Some(" "), Some(" "))` — same
/// precedence as the (Some(""), Some("")) case. Both fields are
/// whitespace-only AND both are set. The empty-or-whitespace
/// gate fires first; the XOR gate is unreachable. Pinned so the
/// whitespace path of the empty-env arm preserves the same
/// short-circuit behavior as the empty-string path.
#[test]
fn validate_pat_xor_precedence_both_whitespace_emits_empty_env_not_xor() {
    let cfg = cfg_with_pat_auth("pat", Some(" "), Some(" "));
    // Inverse pin via must_not_contain: whitespace-env arm must
    // fire BEFORE the XOR arm (same precedence as the empty-string
    // case).
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable"],
        &["mutually exclusive"],
    );
}

/// `Token_file` precedence: `(None, Some(""))` — only
/// `token_file` is set, and it is empty. The empty-token_file arm
/// must fire and emit the "`token_file` is empty or whitespace-
/// only" diagnostic, NOT the (false, false) "exactly one"
/// diagnostic. Pinned so a regression that confuses
/// `token_file.is_some()` with `token_file.as_ref().is_some_and(non_empty)`
/// — falling through to the (false, false) tuple match because
/// the empty-string is treated as "unset" — is caught.
#[test]
fn validate_pat_xor_precedence_token_file_only_empty_emits_empty_file_not_required() {
    let cfg = cfg_with_pat_auth("pat", None, Some(""));
    // Inverse pin via must_not_contain: the "exactly one" arm
    // must NOT fire — the empty-token_file arm short-circuits
    // before the tuple match.
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "is empty or whitespace-only"],
        &["0600 root-owned file"],
        &["exactly one"],
    );
}

/// Loop continuation — when `[auth.interactive]` (a non-Pat
/// variant) precedes a misconfigured `[auth.pat]` in source
/// order, the validator must walk past the non-Pat entry and
/// surface the Pat error. The loop no-ops on non-Pat variants,
/// but without this test the continuation contract is unpinned —
/// a regression that early-returned on
/// the first non-Pat variant would silently let bad Pat configs
/// flow through `cmd_plan/cmd_status`. `IndexMap` preserves insert
/// order, so the fixture builds [interactive, pat] in that
/// order and asserts the error scopes to "pat".
#[test]
fn validate_pat_xor_rejects_bad_pat_after_non_pat_variant() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth
        .insert("interactive".into(), crate::config::AuthSpec::Interactive);
    cfg.auth.insert(
        "pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: None,
            token_file: None,
        },
    );
    cfg.runners[0].auth = Some("pat".into());
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["exactly one"],
        &["token_env", "token_file"],
        &[],
    );
}

/// Reverse direction: bad Pat FIRST, non-Pat variant after.
/// The validator must surface the Pat error on the first iteration
/// (early return) without examining the trailing non-Pat entry.
/// Pinned alongside the [interactive, pat] direction so a
/// regression that swaps to "skip Pat then fall through to
/// non-Pat" is caught from both sides — the loop body must not
/// depend on insertion order to fire correctly.
#[test]
fn validate_pat_xor_rejects_bad_pat_before_non_pat_variant() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: None,
            token_file: None,
        },
    );
    cfg.auth
        .insert("interactive".into(), crate::config::AuthSpec::Interactive);
    cfg.runners[0].auth = Some("pat".into());
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["exactly one"],
        &["token_env", "token_file"],
        &[],
    );
}

/// Multi-Pat — when one `[auth.NAME]` is a valid Pat and a
/// second `[auth.NAME]` is a bad Pat, the validator surfaces only
/// the bad one (and scopes the error to its name). Pinned so a
/// regression that aborts on the first Pat regardless of shape
/// (or that misattributes the error to the first auth name) is
/// caught. `IndexMap` preserves insert order: [good-pat, bad-pat].
#[test]
fn validate_pat_xor_rejects_only_the_bad_pat_in_multi_pat_auth() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "good-pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT_GOOD".into()),
            token_file: None,
        },
    );
    cfg.auth.insert(
        "bad-pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some(String::new()),
            token_file: None,
        },
    );
    cfg.runners[0].auth = Some("good-pat".into());
    // assert_pat_xor_rejects pins that the error scope contains
    // "bad-pat" — not "good-pat" — so a regression that
    // misattributes is caught. Inverse pin via must_not_contain:
    // the error must NOT mention the well-formed Pat's name —
    // the validator stopped on the bad one.
    assert_pat_xor_rejects(
        &cfg,
        "bad-pat",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable"],
        &["\"good-pat\""],
    );
}

/// Reverse direction: bad Pat FIRST, good Pat SECOND. The
/// validator iterates in `IndexMap` insert order and must early-
/// return on the bad Pat without examining the trailing good
/// one. Pins the early-return contract: the loop fires on the
/// first Pat that fails the shape gate and never visits later
/// entries. Pinned alongside the [good-pat, bad-pat] case so a
/// regression that filters/skips Pat entries (e.g. a hypothetical
/// "`find_first(predicate)`" rewrite that misorders) is caught
/// from both sides.
#[test]
fn validate_pat_xor_rejects_first_bad_pat_before_trailing_good_pat() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "bad-pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some(String::new()),
            token_file: None,
        },
    );
    cfg.auth.insert(
        "good-pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT_GOOD".into()),
            token_file: None,
        },
    );
    cfg.runners[0].auth = Some("good-pat".into());
    // Inverse pin via must_not_contain: the error must NOT
    // mention the trailing good Pat's name — early-return: the
    // validator stopped on the first bad one and never iterated
    // to the second.
    assert_pat_xor_rejects(
        &cfg,
        "bad-pat",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable"],
        &["\"good-pat\""],
    );
}

/// Both-bad-Pat: when BOTH Pat entries are misconfigured,
/// the validator early-returns on the FIRST bad Pat (insert
/// order) and never examines the second. Pinned so a regression
/// that "accumulates" failures across multiple Pat entries (or
/// that misattributes the error to the second bad one) is
/// caught. `IndexMap` preserves insert order: [bad1, bad2]. The
/// fixture uses `cfg_with_pat_auth` for bad1, then manually
/// inserts bad2 with the same fault shape (`token_env=Some`("")).
#[test]
fn validate_pat_xor_rejects_first_bad_pat_when_both_pats_faulted() {
    let mut cfg = cfg_with_pat_auth("bad1", Some(""), None);
    cfg.auth.insert(
        "bad2".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some(String::new()),
            token_file: None,
        },
    );
    // Inverse pin via must_not_contain: the error must NOT
    // mention "bad2" — the validator early-returned on bad1
    // and never iterated to the second bad entry.
    assert_pat_xor_rejects(
        &cfg,
        "bad1",
        &["token_env", "is empty or whitespace-only"],
        &["environment variable"],
        &["\"bad2\""],
    );
}

/// Non-Pat `AuthSpec` variants (`Interactive`, `TokenFile`,
/// `GithubApp`) have no XOR shape to validate. The validator
/// loop walks every entry but no-ops on non-Pat variants. Pinned
/// so a future regression that fires on non-Pat variants is
/// caught.
///
/// Named `_accepts_` for naming
/// consistency with sibling positive tests
/// (`_accepts_token_env_only`, `_accepts_token_file_only`) —
/// "accepts" describes the observable contract (Ok return);
/// "skips" was implementation-coupled (the loop body's no-op
/// branch).
#[test]
fn validate_pat_xor_accepts_non_pat_auth_variants() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    // Replace the default [auth.pat] with a non-Pat variant (Interactive).
    cfg.auth.clear();
    cfg.auth
        .insert("interactive".into(), crate::config::AuthSpec::Interactive);
    cfg.auth.insert(
        "tokenfile".into(),
        crate::config::AuthSpec::TokenFile {
            path: camino::Utf8PathBuf::from("/etc/ghars/regtok"),
        },
    );
    cfg.runners[0].auth = Some("interactive".into());
    validate_pat_xor(&cfg).expect("non-Pat AuthSpec variants must pass validation");
}

// -------- token_env / token_file shape gate tests -----------------

/// RLO Trojan Source: `token_env` containing U+202E
/// (Right-to-Left Override) rejects via the hidden-char gate.
/// Load-bearing for the security claim that bidi-override
/// attacks (Boucher & Anderson 2021) cannot reach apply-time
/// `env::var` lookup. RLO renders subsequent characters
/// right-to-left in operator terminals, allowing visually
/// identical strings to be different bytewise.
#[test]
fn validate_pat_xor_rejects_token_env_with_right_to_left_override() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{202E}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+202E", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// RLO Trojan Source on `token_file`: symmetric with the
/// `token_env` RLO pin above. A `token_file` path containing U+202E
/// (Right-to-Left Override) rejects via the hidden-char gate.
/// RLO inside a path is a credible attack surface — bidi-rendered
/// paths can disguise their actual byte sequence to a reviewing
/// operator (e.g. `/etc/ghars/Pat.txt` rendered as
/// `/etc/ghars/txt.taP` after RLO). Defense-in-depth pin so a
/// regression that drops U+202E from the matches arm but leaves
/// the `token_env` pin intact is still caught.
#[test]
fn validate_pat_xor_rejects_token_file_with_right_to_left_override() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/\u{202E}pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "hidden character", "U+202E", "byte offset"],
        &["/etc/ghars/pat"],
        &[],
    );
}

/// `token_env` containing U+200E (LRM, Left-to-Right Mark)
/// rejects via the hidden-char gate. LRM is in the U+200B..U+200F
/// block. Pinned to catch a regression that
/// re-narrows the explicit set to just ZWSP/ZWNJ/ZWJ.
#[test]
fn validate_pat_xor_rejects_token_env_with_left_to_right_mark() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{200E}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+200E", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_env` containing U+2066 (LRI, Left-to-Right
/// Isolate) rejects via the hidden-char gate. Bidi isolate from
/// the U+2066..U+2069 block.
#[test]
fn validate_pat_xor_rejects_token_env_with_bidi_isolate() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{2066}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+2066", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_file` containing U+FE0F (VS-16, emoji variant selector)
/// rejects via the hidden-char gate. Variation selectors are Mn
/// (Mark, nonspacing) — NOT in the Cc class. Routes to the
/// remove-only sub-arm (no precomposed equivalent exists for VS).
#[test]
fn validate_pat_xor_rejects_token_file_with_variation_selector() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{FE0F}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+FE0F",
            "byte offset",
            "remove the codepoint",
            "no precomposed equivalent exists",
        ],
        &["/etc/ghars/pat"],
        &[
            "NFC",
            "if the character was intentional",
            "hidden character",
        ],
    );
}

/// `token_file` containing U+034F (COMBINING GRAPHEME JOINER)
/// routes to the remove-only sub-arm of the Mn branch. CGJ is Mn
/// but has no precomposed NFC form, so NFC advice would mislead.
#[test]
fn validate_pat_xor_rejects_token_file_with_combining_grapheme_joiner() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{034F}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+034F",
            "byte offset",
            "remove the codepoint",
            "no precomposed equivalent exists",
        ],
        &["/etc/ghars/pat"],
        &[
            "NFC",
            "if the character was intentional",
            "hidden character",
        ],
    );
}

/// `token_file` containing U+FE00 (VARIATION SELECTOR-1, low
/// boundary of U+FE00..=U+FE0F) routes to the remove-only
/// sub-arm. Pins the lower edge of the BMP VS range against an
/// off-by-one regression in the matches arm.
#[test]
fn validate_pat_xor_rejects_token_file_with_variation_selector_1() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{FE00}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+FE00",
            "byte offset",
            "remove the codepoint",
            "no precomposed equivalent exists",
        ],
        &["/etc/ghars/pat"],
        &[
            "NFC",
            "if the character was intentional",
            "hidden character",
        ],
    );
}

/// `token_file` containing U+E0100 (VARIATION SELECTOR-17, low
/// boundary of the supplementary VS17..=VS256 range at
/// U+E0100..=U+E01EF). Same threat shape as BMP VS chars: Mn but
/// no NFC composition. Pins the SMP boundary so a regression
/// that lists only the BMP range surfaces here.
#[test]
fn validate_pat_xor_rejects_token_file_with_variation_selector_17() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{E0100}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+E0100",
            "byte offset",
            "remove the codepoint",
            "no precomposed equivalent exists",
        ],
        &["/etc/ghars/pat"],
        &[
            "NFC",
            "if the character was intentional",
            "hidden character",
        ],
    );
}

/// `token_file` containing U+E01EF (VARIATION SELECTOR-256, high
/// boundary of the supplementary VS17..=VS256 range at
/// U+E0100..=U+E01EF). Pins the SMP closed-range upper edge —
/// symmetric with VS-16 (U+FE0F) pinning the BMP upper edge. A
/// regression that flips `..=` to `..` or truncates to U+E01EE
/// surfaces here.
#[test]
fn validate_pat_xor_rejects_token_file_with_variation_selector_256() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{E01EF}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+E01EF",
            "byte offset",
            "remove the codepoint",
            "no precomposed equivalent exists",
        ],
        &["/etc/ghars/pat"],
        &[
            "NFC",
            "if the character was intentional",
            "hidden character",
        ],
    );
}

/// `token_file` containing U+0483 (COMBINING CYRILLIC TITLO)
/// routes to the diacritical sub-arm: "combining mark" + offer
/// both remove-or-NFC remediations. The diacritical sub-arm is
/// the conservative default for any Mn codepoint not explicitly
/// listed in the no-NFC-form match.
#[test]
fn validate_pat_xor_rejects_token_file_with_cyrillic_combining_mark() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars\u{0483}/pat"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+0483",
            "byte offset",
            "remove the codepoint",
            "precomposed (NFC) form",
            "if the character was intentional",
        ],
        &["/etc/ghars/pat"],
        &["no precomposed equivalent exists", "hidden character"],
    );
}

/// `token_env` containing U+061C (Arabic Letter Mark)
/// rejects via the hidden-char gate. ALM is one of the
/// individually-listed Cf-class chars.
#[test]
fn validate_pat_xor_rejects_token_env_with_arabic_letter_mark() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{061C}BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "hidden character", "U+061C", "byte offset"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_file = "/etc/ghars/with\nnewline"` (embedded
/// newline in a path) rejects via the hidden-char gate.
/// ALL Cc chars reject in `token_file` — there is no `\t`
/// `\n` `\r` carve-out, so a path with a literal newline
/// cannot survive the hidden-char scan and slip past the
/// trim-mismatch gate (which only catches whitespace at the
/// path's edges) into apply where `open(2)` would either
/// succeed on a bizarre path or fail with confusing
/// diagnostics. Defense-in-depth pin against operator typos
/// and attacker-injected paths.
#[test]
fn validate_pat_xor_rejects_token_file_with_embedded_newline() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/with\nnewline"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "hidden character", "U+000A", "byte offset"],
        &["/etc/ghars/pat"],
        &["leading or trailing whitespace"],
    );
}

/// `token_file` with embedded TAB (U+0009) rejects via the
/// control-char arm. Symmetric with the embedded-newline pin;
/// the all-Cc rejection covers \t \n \r uniformly. Pinned
/// so a regression that carves out any one of the three is
/// caught.
#[test]
fn validate_pat_xor_rejects_token_file_with_embedded_tab() {
    let cfg = cfg_with_pat_auth("pat", None, Some("/etc/ghars/with\tab"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_file", "hidden character", "U+0009", "byte offset"],
        &["/etc/ghars/pat"],
        &["leading or trailing whitespace"],
    );
}

/// `token_env = "_"` (single underscore) — the shortest
/// legal POSIX env var name MUST pass. Boundary check on the
/// regex's first-char class `[A-Za-z_]` paired with the `*`
/// quantifier on the trailing chars (zero-or-more allows a
/// single-char name).
#[test]
fn validate_pat_xor_accepts_token_env_single_underscore() {
    let cfg = cfg_with_pat_auth("pat", Some("_"), None);
    validate_pat_xor(&cfg).expect("single-underscore POSIX token_env must pass shape gate");
}

/// Multi-Pat where the first bad Pat fails on charset and
/// the second bad Pat fails on hidden-char. The validator
/// early-returns on the FIRST bad Pat — the diagnostic must
/// surface the charset gate's text, never the hidden-char text.
/// Pinned so a regression that "accumulates" or reorders the
/// fault evaluation across multi-Pat surfaces is caught.
#[test]
fn validate_pat_xor_rejects_first_bad_pat_charset_before_hidden_char_pat() {
    let mut cfg = cfg_with_pat_auth("bad-charset", Some("FOO-BAR"), None);
    cfg.auth.insert(
        "bad-hidden".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("FOO\u{FEFF}BAR".into()),
            token_file: None,
        },
    );
    assert_pat_xor_rejects(
        &cfg,
        "bad-charset",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &["\"bad-hidden\"", "hidden character"],
    );
}

/// Reverse-ordering pin: multi-Pat where the FIRST entry
/// (`IndexMap` insertion order — `cfg.auth` is
/// `IndexMap<String, AuthSpec>` so iteration follows insertion,
/// NOT alphabetical) fails on hidden-char and the second entry
/// fails on charset. The validator early-returns on the first
/// bad Pat — the diagnostic must surface the hidden-char gate's
/// text, never the charset text. Symmetric with the
/// charset-before-hidden pin above; together they pin
/// iteration-order independence: whichever fault comes first in
/// `IndexMap` insertion order is the one surfaced, regardless of
/// fault class.
#[test]
fn validate_pat_xor_rejects_first_bad_pat_hidden_char_before_charset_pat() {
    let mut cfg = cfg_with_pat_auth("aa-bad-hidden", Some("FOO\u{FEFF}BAR"), None);
    cfg.auth.insert(
        "zz-bad-charset".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("FOO-BAR".into()),
            token_file: None,
        },
    );
    assert_pat_xor_rejects(
        &cfg,
        "aa-bad-hidden",
        &["token_env", "hidden character", "U+FEFF"],
        &["GHARS_PAT"],
        &["\"zz-bad-charset\"", "POSIX environment variable name"],
    );
}

/// `token_env` with a Cyrillic letter (U+0411 CYRILLIC
/// CAPITAL LETTER BE) rejects via the POSIX charset gate. The
/// regex's `[A-Za-z]` class is ASCII-only; non-ASCII letters
/// fail. Pinned so a regression that loosens the regex to
/// `\w` (Unicode word character) is caught.
#[test]
fn validate_pat_xor_rejects_token_env_with_cyrillic_letter() {
    let cfg = cfg_with_pat_auth("pat", Some("\u{0411}FOO"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &["hidden character"],
    );
}

/// `token_env` with a fullwidth digit (U+FF11 FULLWIDTH
/// DIGIT ONE) rejects via the POSIX charset gate. Fullwidth
/// digits are Unicode `Nd` general category but outside the
/// ASCII `[0-9]` class. Pinned alongside Cyrillic so a future
/// regression that switches to `\d` is caught.
#[test]
fn validate_pat_xor_rejects_token_env_with_fullwidth_digit() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO\u{FF11}"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &["hidden character"],
    );
}

/// `token_env = "FOO.BAR"` (embedded dot) rejects via the
/// POSIX charset gate. Dot is a common shell-config typo for
/// underscore — operators sometimes write `MY.VAR` thinking
/// it's valid. The regex anchors charset to `[A-Za-z0-9_]` so
/// dot fails.
#[test]
fn validate_pat_xor_rejects_token_env_with_dot() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO.BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &[],
    );
}

/// `token_env = "FOO$BAR"` (embedded dollar) rejects via
/// the POSIX charset gate. Dollar is the shell variable
/// expansion sigil — operators sometimes paste the SHELL
/// REFERENCE form instead of the NAME. Pinned so the gate
/// catches this common shape.
#[test]
fn validate_pat_xor_rejects_token_env_with_dollar() {
    let cfg = cfg_with_pat_auth("pat", Some("FOO$BAR"), None);
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &["token_env", "POSIX environment variable name"],
        &["GHARS_PAT"],
        &[],
    );
}

// -------- Mn-class combining-mark rejection ------------------------

/// `is_disallowed_hidden_char(U+0300)` (COMBINING GRAVE
/// ACCENT, general category Mn — Mark, nonspacing) returns
/// true via the Mn-class arm. Without this arm only the explicit
/// listed Mn codepoints (CGJ U+034F, variation selectors
/// U+FE00..=U+FE0F) rejected; arbitrary combining marks like
/// U+0300..=U+036F passed through. Pinned to catch a regression
/// that drops the `GeneralCategory` check.
#[test]
fn is_disallowed_hidden_char_rejects_combining_grave_accent() {
    assert!(is_disallowed_hidden_char('\u{0300}'));
}

/// `is_disallowed_hidden_char(U+0301)` (COMBINING ACUTE
/// ACCENT, also Mn) returns true. Pinned alongside U+0300 so
/// the property is exercised at both ends of the
/// combining-diacritical-marks block (U+0300..=U+036F).
#[test]
fn is_disallowed_hidden_char_rejects_combining_acute_accent() {
    assert!(is_disallowed_hidden_char('\u{0301}'));
}

/// `is_disallowed_hidden_char('a')` returns false — base
/// ASCII letters are not Mn, not Cc, not in the explicit list.
/// Negative pin so a regression that broadens the
/// general-category check (e.g. accidentally rejects all
/// `Mark` rather than `NonspacingMark`) is caught.
#[test]
fn is_disallowed_hidden_char_accepts_ascii_letter() {
    assert!(!is_disallowed_hidden_char('a'));
}

/// `is_disallowed_hidden_char(U+00E0)` (LATIN SMALL LETTER
/// A WITH GRAVE, the precomposed NFC form of `a + U+0300`)
/// returns false. U+00E0 is `Ll` (Letter, lowercase) — NOT Mn —
/// so the precomposed form is safe to use in
/// internationalized config paths. Pinned so the doc-comment
/// claim "operators with internationalized paths should use
/// precomposed (NFC) forms" is empirically grounded.
#[test]
fn is_disallowed_hidden_char_accepts_precomposed_a_grave() {
    assert!(!is_disallowed_hidden_char('\u{00E0}'));
}

/// `token_file = "pa\u{0300}t"` (path containing a base
/// `t` overlaid with COMBINING GRAVE ACCENT) rejects via the
/// hidden-char gate. The Mn arm catches the U+0300 codepoint;
/// without the Mn-class arm this would flow through every shape gate
/// because `is_control()` doesn't catch combining marks and
/// the explicit list doesn't cover the generic combining-
/// diacriticals block. The diagnostic is the
/// dedicated "combining mark" + "precomposed (NFC)" form, not
/// the generic "hidden character" framing — pinned alongside
/// codepoint + byte offset so a regression that reverts the
/// Mn-specific branch surfaces here.
#[test]
fn validate_pat_xor_rejects_token_file_with_combining_mark() {
    let cfg = cfg_with_pat_auth("pat", None, Some("pa\u{0300}t"));
    assert_pat_xor_rejects(
        &cfg,
        "pat",
        &[
            "token_file",
            "combining mark",
            "U+0300",
            "byte offset",
            "precomposed",
            "NFC",
        ],
        &["/etc/ghars/pat"],
        &["hidden character"],
    );
}

/// Regression pin — CGJ (U+034F COMBINING GRAPHEME JOINER)
/// is rejected via the Mn-class arm of
/// `is_disallowed_hidden_char`. There is no explicit codepoint
/// listing for U+034F, so the Mn arm is the only line of
/// defense. If the `unicode-general-category` crate ever
/// misclassifies U+034F (e.g. via a UCD-table regeneration
/// bug), this test surfaces the regression.
#[test]
fn is_disallowed_hidden_char_rejects_combining_grapheme_joiner() {
    assert!(is_disallowed_hidden_char('\u{034F}'));
}

/// Regression pin — VS-16 (U+FE0F VARIATION SELECTOR-16,
/// the emoji variant selector) is rejected via the Mn-class
/// arm of `is_disallowed_hidden_char`. There is no explicit
/// codepoint listing for U+FE0F, so the Mn arm is the only
/// line of defense. If the unicode-general-category crate
/// ever misclassifies U+FE0F, this test surfaces it.
#[test]
fn is_disallowed_hidden_char_rejects_variation_selector() {
    assert!(is_disallowed_hidden_char('\u{FE0F}'));
}

/// Negative pin — U+0903 DEVANAGARI SIGN VISARGA is Mc
/// (`Spacing_Mark`), NOT Mn. Defends against accidentally
/// broadening the check to all Mark class (Mn+Mc+Me). Without
/// this pin a future regression that swaps the
/// `GeneralCategory::NonspacingMark` check for a generic
/// `Mark` predicate would silently start rejecting legitimate
/// internationalized scripts that rely on spacing marks.
#[test]
fn is_disallowed_hidden_char_accepts_spacing_mark() {
    assert!(!is_disallowed_hidden_char('\u{0903}'));
}

// -------- validate_auth_keys tests ---------------------------------

/// A properly-shaped auth key (matches `IDENTIFIER_REGEX`:
/// lowercase letters + digits + dashes, starts with letter,
/// ends with letter/digit) MUST pass `validate_auth_keys`. The
/// canonical "pat" key from `cfg_with_runner_trust_zone` is the
/// happy-path pin.
#[test]
fn validate_auth_keys_accepts_canonical_pat() {
    let cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    validate_auth_keys(&cfg).expect("canonical 'pat' auth key must pass");
}

/// An auth key matching the kebab-case identifier shape
/// (multi-segment with internal dashes) MUST pass. Pinned so
/// the regex `^[a-z]([a-z0-9-]*[a-z0-9])?$` is exercised at the
/// multi-segment boundary, not just the single-word case.
#[test]
fn validate_auth_keys_accepts_kebab_case_multi_segment() {
    let cfg = cfg_with_pat_auth("alpha-zone-creds", Some("GHARS_PAT"), None);
    validate_auth_keys(&cfg).expect("kebab-case multi-segment auth key must pass");
}

/// An auth key with an underscore (e.g. "`alpha_zone_creds`")
/// rejects via `validate_identifier` — `IDENTIFIER_REGEX` is
/// kebab-only (`[a-z0-9-]`), no underscores. Operators
/// migrating from `snake_case` TOML conventions need a clear
/// rejection rather than a confusing apply-time error.
#[test]
fn validate_auth_keys_rejects_underscore() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "alpha_zone_creds".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("underscore must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("auth \"alpha_zone_creds\""),
                "msg must scope to auth key; got: {msg}"
            );
            assert!(
                msg.contains("identifier invalid"),
                "msg must come from validate_identifier; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// An auth key with an uppercase letter rejects.
/// `IDENTIFIER_REGEX` is lowercase-only.
#[test]
fn validate_auth_keys_rejects_uppercase() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "PAT".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("uppercase auth key must reject");
    assert!(matches!(err, GharsError::Validation(..)));
}

/// An auth key starting with a dash rejects.
/// `IDENTIFIER_REGEX` requires a leading letter.
#[test]
fn validate_auth_keys_rejects_dash_leading() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "-pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("dash-leading auth key must reject");
    assert!(matches!(err, GharsError::Validation(..)));
}

/// An empty auth key rejects via the empty-input arm of
/// `validate_identifier`. TOML allows empty quoted keys
/// (`[auth.""]`), so this is reachable from operator input.
#[test]
fn validate_auth_keys_rejects_empty() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        String::new(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("empty auth key must reject");
    assert!(matches!(err, GharsError::Validation(..)));
}

/// An auth key with embedded whitespace rejects. Pinned
/// to catch the case where TOML's quoted-key syntax allows
/// `[auth."FOO BAR"]` as a literal string but the validator
/// still surfaces a clear rejection.
#[test]
fn validate_auth_keys_rejects_embedded_whitespace() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "foo bar".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("whitespace in auth key must reject");
    assert!(matches!(err, GharsError::Validation(..)));
}

/// `validate_auth_keys` walks every entry. When the first
/// entry passes and the second fails, the validator surfaces
/// the second's error. Pinned to catch a regression that early-
/// returns on the first entry (only checking entry 0).
#[test]
fn validate_auth_keys_walks_past_valid_to_invalid() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.auth.clear();
    cfg.auth.insert(
        "good-pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    cfg.auth.insert(
        "bad_pat".into(),
        crate::config::AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    let err = validate_auth_keys(&cfg).expect_err("second invalid auth key must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("auth \"bad_pat\""),
                "must scope to second key; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// `Load_config` integration pin: a TOML config that has a
/// shape-valid `[auth.NAME]` Pat block but uses a quoted key
/// containing whitespace (`[auth."bad key"]`) MUST reject at
/// `load_config` time via the `validate_auth_keys` gate, BEFORE the
/// downstream `validate_pat_xor` gate ever runs. Pinned end-to-end
/// (file → `load_config` → first failing validator) because
/// `load_config` is the single chokepoint that every CLI subcommand
/// (`cmd_validate`, `cmd_plan`, `cmd_apply`, `cmd_status`, `cmd_add`) routes
/// through; a regression that drops `validate_auth_keys` from the
/// `load_config` sequence would silently accept hostile keys at all
/// five callsites at once. The Pat block's `token_env` is shape-valid
/// (`GHARS_PAT` passes POSIX charset and hidden-char gates) so the
/// rejection here can ONLY come from `validate_auth_keys` — proves
/// `load_config` wiring order.
#[test]
fn load_config_rejects_auth_key_with_space_before_pat_xor_gate() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // Quoted key syntax: TOML accepts `[auth."bad key"]` as a
    // literal string key with embedded whitespace. The Pat block
    // is otherwise valid (token_env = "GHARS_PAT" passes every
    // validate_pat_xor gate).
    let body = "\
[defaults]

[auth.\"bad key\"]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/owner/repo\"
auth = \"bad key\"
";
    fs::write(config_path.as_std_path(), body).unwrap();
    let err = load_config(&config_path).expect_err("space-bearing auth key must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("auth \"bad key\""),
                "msg must scope to the offending auth key; got: {msg}"
            );
            assert!(
                msg.contains("identifier invalid"),
                "msg must come from validate_identifier (validate_auth_keys), \
                 not validate_pat_xor; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

// -------- cache pool name validation --------------------------------

/// Pins (a) `validate_cache_pool_names` returns a Validation error
/// scoped to the offending pool, (b) the rejection reaches the
/// identifier-shape gate, and (c) Validation maps to exit code 6
/// via `err_to_exit_code`. Wire-up at `cmd_validate` / `cmd_plan` /
/// `cmd_apply` is structurally verified by code review; end-to-end
/// integration coverage is pending in the `cmd_validate` / `cmd_plan`
/// / `cmd_apply` integration suite.
#[test]
fn validate_cache_pool_names_rejects_oversize_pool_with_exit_code_six() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    let pool_name = "a".repeat(crate::config::IDENTIFIER_MAX_LEN + 1);
    cfg.cache_pools.insert(
        pool_name.clone(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );
    let err = validate_cache_pool_names(&cfg).expect_err("oversize pool name must reject");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("cache_pool") && msg.contains(&pool_name),
                "msg must scope to the offending cache_pool by name; got: {msg}"
            );
            assert!(
                msg.contains("identifier") && msg.contains("too long"),
                "msg must come from the identifier-shape gate; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
    assert_eq!(
        err_to_exit_code(&err),
        6,
        "Validation must map to exit code 6 (Part 5)"
    );
}

/// Acceptance boundary: a runner.caches entry whose length
/// exactly equals `IDENTIFIER_MAX_LEN` must pass — and the same
/// name as a `cache_pools` key must also pass. Pins the
/// inclusive-of-cap contract so a future tightening of the
/// identifier cap (e.g. accidental change to `<` instead of `<=`)
/// is caught by this test rather than by an operator hitting a
/// previously-valid config.
#[test]
fn validate_cache_pool_names_accepts_runner_caches_at_max_len() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    let at_max = "a".repeat(crate::config::IDENTIFIER_MAX_LEN);
    // Both the cache_pools key AND the runner.caches reference use
    // the same MAX_LEN string — this exercises both inner loops in
    // validate_cache_pool_names.
    cfg.cache_pools.insert(
        at_max.clone(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
        },
    );
    cfg.runners[0].caches = vec![at_max.clone()];
    validate_cache_pool_names(&cfg).unwrap_or_else(|e| {
        panic!(
            "{}-char (== IDENTIFIER_MAX_LEN) cache name must accept; got: {e}",
            crate::config::IDENTIFIER_MAX_LEN
        )
    });
}

// ---- validate_cache_pool_binary_paths -----------------------------------

/// Pins the config-load gate: a relative `sccache_path` must reject
/// with a Validation error scoped to the offending pool by name.
/// Without this gate the plan-time resolver still rejects the bad
/// path, but the operator sees the error one phase later (after
/// per-pool name + `trust_zone` validations) and without the
/// `cache_pool "NAME":` scope prefix.
#[test]
fn validate_cache_pool_binary_paths_rejects_relative_sccache_path() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "build".into(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: Some("relative/sccache".into()),
            sleep_path: None,
        },
    );
    let err =
        validate_cache_pool_binary_paths(&cfg).expect_err("relative sccache_path must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("cache_pool \"build\"") && msg.contains("sccache_path"),
                "msg must scope to the offending pool by name and field; got: {msg}"
            );
            assert!(
                msg.contains("absolute"),
                "msg must name the absolute-path requirement; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// Symmetric to the `sccache_path` test: relative `sleep_path` must
/// reject at config load with the same scope prefix.
#[test]
fn validate_cache_pool_binary_paths_rejects_relative_sleep_path() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.cache_pools.insert(
        "build".into(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("relative/sleep".into()),
        },
    );
    let err = validate_cache_pool_binary_paths(&cfg).expect_err("relative sleep_path must reject");
    match err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("cache_pool \"build\"") && msg.contains("sleep_path"),
                "msg must scope to the offending pool by name and field; got: {msg}"
            );
            assert!(
                msg.contains("absolute"),
                "msg must name the absolute-path requirement; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got {other:?}"),
    }
}

/// Absolute paths must pass — the gate is opt-in (None) and absolute
/// pins. This pins the accept path so a future tightening (e.g.
/// rejecting symlinks, or enforcing a `starts_with(/usr)` constraint)
/// is caught here rather than silently breaking valid configs.
#[test]
fn validate_cache_pool_binary_paths_accepts_absolute_pins_and_none() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    // Pool 1: both fields pinned absolutely.
    cfg.cache_pools.insert(
        "pinned".into(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Sccache],
            size: "200G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: Some("/opt/sccache/bin/sccache".into()),
            sleep_path: Some("/usr/bin/sleep".into()),
        },
    );
    // Pool 2: both fields None (auto-detect at plan time).
    cfg.cache_pools.insert(
        "auto".into(),
        crate::config::CachePoolSpec {
            kinds: vec![crate::config::CacheKind::Ccache],
            size: "100G".into(),
            mode: crate::config::CacheMode::default(),
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: None,
        },
    );
    validate_cache_pool_binary_paths(&cfg).expect("absolute pins + None must pass");
}
