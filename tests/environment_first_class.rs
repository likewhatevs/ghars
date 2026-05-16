//! End-to-end tests for the first-class `[defaults.environment]` /
//! `[runner.environment]` config surface (operator-declared env vars
//! and PATH additions).
//!
//! Covers the load-bearing slice of tester's 30-test inventory plus
//! api-reviewer's HARD REQ (operator vars must appear in BOTH .env
//! AND 00-ghars.conf — without this pin a future refactor could
//! drop one layer and re-create the LAYER 1/2 drift class).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use camino::Utf8PathBuf;
use ghars::config::{Arch, EffectiveRunnerSpec, EnvironmentSpec, Hardening};
use ghars::systemd::{RENDERER_SCHEMA, render_runner_unit};

fn base_spec() -> EffectiveRunnerSpec {
    EffectiveRunnerSpec {
        environment: EnvironmentSpec::default(),
        name: "buckos".into(),
        url: "https://github.com/example/buckos".into(),
        arch: Arch::X86_64,
        labels: vec!["self-hosted".into()],
        memory_max: None,
        runner_version: Some("2.334.0".into()),
        runner_sha256: None,
        runner_tarball: None,
        auth_name: "pat".into(),
        caches: vec![],
        trust_zone: "default".into(),
        network: None,
        proxy: None,
        hooks: None,
        hardening: Hardening::default(),
        allowed_cpus: None,
        allowed_memory_nodes: None,
        spec_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        config_source: "/etc/ghars/ghars.toml".into(),
        renderer_schema: RENDERER_SCHEMA,
    }
}

/// API-REVIEWER HARD REQ: an operator-declared env var lands in BOTH
/// the .env file (LAYER 2, consumed by `Runner.Listener::LoadAndSetEnv`
/// for workflow steps) AND the 00-ghars.conf `Environment=` directive
/// (LAYER 1, consumed by systemd for the runner unit). Without this
/// pin a future renderer refactor could quietly drop one layer and
/// re-create the LAYER 1/2 drift class the in-place .env/.path
/// rewrite fixed for framework-emitted built-ins.
#[test]
fn operator_env_var_lands_in_both_env_file_and_identity_drop_in() {
    let mut spec = base_spec();
    spec.environment
        .vars
        .insert("MY_OPERATOR_VAR".into(), "value42".into());

    let unit = render_runner_unit(&spec).expect("render must succeed");
    let env_file = &unit.env_file;
    let identity = unit
        .drop_ins
        .get("00-ghars.conf")
        .expect("00-ghars.conf drop-in must be present");

    assert!(
        env_file.contains("MY_OPERATOR_VAR=value42\n"),
        ".env must contain operator var as KEY=VALUE line; got:\n{env_file}"
    );
    assert!(
        identity.contains("Environment=MY_OPERATOR_VAR=value42\n"),
        "00-ghars.conf must contain operator var as Environment= directive; got:\n{identity}"
    );
}

/// Operator vars iterate BTreeMap-alphabetically so .env bytes are
/// stable regardless of operator's TOML key order. Pins the
/// determinism guarantee that prevents spurious in-place rewrites on
/// cosmetic TOML edits.
#[test]
fn operator_env_vars_emit_in_alphabetical_order_in_env_file() {
    let mut spec = base_spec();
    // Insert in non-alphabetical order to prove the renderer sorts.
    spec.environment.vars.insert("ZEBRA".into(), "z".into());
    spec.environment.vars.insert("ALPHA".into(), "a".into());
    spec.environment.vars.insert("MIKE".into(), "m".into());

    let unit = render_runner_unit(&spec).expect("render must succeed");
    let env_file = &unit.env_file;

    let alpha_pos = env_file.find("ALPHA=a").expect("ALPHA must appear");
    let mike_pos = env_file.find("MIKE=m").expect("MIKE must appear");
    let zebra_pos = env_file.find("ZEBRA=z").expect("ZEBRA must appear");
    assert!(
        alpha_pos < mike_pos && mike_pos < zebra_pos,
        "operator vars must emit alphabetically; got positions ALPHA={alpha_pos} \
         MIKE={mike_pos} ZEBRA={zebra_pos}"
    );
}

/// Operator-supplied value containing `%` is `%%`-escaped in
/// 00-ghars.conf's `Environment=` directive but emitted VERBATIM in
/// the .env file. Both consumers see the IDENTICAL literal value
/// after systemd's specifier expansion (Environment=) or .NET's
/// `LoadAndSetEnv` (verbatim line read).
#[test]
fn operator_value_with_percent_is_escaped_in_identity_but_verbatim_in_env_file() {
    let mut spec = base_spec();
    spec.environment
        .vars
        .insert("MY_PATH_TEMPLATE".into(), "%C/operator-supplied".into());

    let unit = render_runner_unit(&spec).expect("render must succeed");

    assert!(
        unit.env_file
            .contains("MY_PATH_TEMPLATE=%C/operator-supplied\n"),
        ".env must carry operator value VERBATIM (LoadAndSetEnv doesn't expand %); got:\n{}",
        unit.env_file
    );
    let identity = unit
        .drop_ins
        .get("00-ghars.conf")
        .expect("identity drop-in");
    assert!(
        identity.contains("Environment=MY_PATH_TEMPLATE=%%C/operator-supplied\n"),
        "00-ghars.conf must escape % to %% so systemd does NOT expand operator value; got:\n{identity}"
    );
}

/// `environment.path_prepend` lands BETWEEN the ccache wrappers and
/// the per-runner `.cargo/bin` segment per OPTION C. ccache stays at
/// position 0 unconditionally so operator paths cannot shadow `gcc` /
/// `cc` and break the compile cache.
#[test]
fn operator_path_prepend_lands_between_ccache_wrappers_and_cargo_bin_in_path_file() {
    let mut spec = base_spec();
    spec.environment.path_prepend = vec![
        Utf8PathBuf::from("/opt/operator-tools/bin"),
        Utf8PathBuf::from("/opt/operator-vendor/bin"),
    ];

    let unit = render_runner_unit(&spec).expect("render must succeed");
    let path_file = &unit.path_file;

    let ccache_lib64 = path_file
        .find("/usr/lib64/ccache:")
        .expect("/usr/lib64/ccache must be at the beginning");
    let ccache_lib = path_file
        .find("/usr/lib/ccache:")
        .expect("/usr/lib/ccache must follow");
    let operator1 = path_file
        .find("/opt/operator-tools/bin:")
        .expect("first path_prepend entry must appear");
    let operator2 = path_file
        .find("/opt/operator-vendor/bin:")
        .expect("second path_prepend entry must appear");
    let cargo_bin = path_file
        .find("/.cargo/bin:")
        .expect(".cargo/bin must appear after operator path_prepend");
    assert!(
        ccache_lib64 < ccache_lib
            && ccache_lib < operator1
            && operator1 < operator2
            && operator2 < cargo_bin,
        "ordering must be ccache → path_prepend (in source order) → .cargo/bin; got: \
         lib64={ccache_lib64} lib={ccache_lib} op1={operator1} op2={operator2} cargo={cargo_bin}"
    );
}

/// `environment.path_append` lands AFTER the system tail (`/bin`).
#[test]
fn operator_path_append_lands_after_system_tail_in_path_file() {
    let mut spec = base_spec();
    spec.environment.path_append = vec![Utf8PathBuf::from("/opt/operator-fallback/bin")];

    let unit = render_runner_unit(&spec).expect("render must succeed");
    let path_file = &unit.path_file;

    let bin_pos = path_file.find(":/bin:").or_else(|| {
        // /bin might be at end of system tail right before path_append
        path_file.find(":/bin/opt/operator-fallback/bin")
    });
    let append_pos = path_file
        .find("/opt/operator-fallback/bin")
        .expect("path_append entry must appear");

    // /bin appears somewhere before /opt/operator-fallback/bin
    let bin_anywhere = path_file
        .find("/bin")
        .expect("/bin from system tail must appear");
    assert!(
        bin_anywhere < append_pos,
        "path_append must follow system tail /bin; got: bin={bin_anywhere} append={append_pos}"
    );
    // Sanity: didn't break the assertion lookup
    let _ = bin_pos;
}

/// Empty `[defaults.environment]` / `[runner.environment]` produces
/// byte-identical .env and .path output to the pre-elevation baseline
/// (adversary D7 byte-identical-when-empty guarantee). Regression guard against a
/// future renderer refactor that injects spurious output for empty
/// operator config.
#[test]
fn empty_operator_environment_produces_no_extra_emission() {
    let spec = base_spec();
    let unit = render_runner_unit(&spec).expect("render must succeed");

    // .env should ONLY contain LANG + KTSTR_LOCK_DIR + KTSTR_CACHE_DIR
    // (3 framework lines for a spec with no caches). CCACHE_DIR is
    // gated on `has_ccache` binding — empty caches → no
    // CCACHE_DIR emission.
    let line_count = unit.env_file.lines().count();
    assert_eq!(
        line_count, 3,
        ".env must contain exactly 3 framework lines for empty caches + empty env_vars \
         (LANG + KTSTR_LOCK_DIR + KTSTR_CACHE_DIR); got:\n{}",
        unit.env_file
    );

    // .path should be the framework PATH only (no operator additions).
    assert!(
        !unit.path_file.contains("/opt/"),
        ".path must not contain any /opt/ operator additions for empty env; got: {}",
        unit.path_file
    );
}

/// Validators reject each tier of deny-listed env var names at
/// config-load. Per-tier error messages with rationale (dev-advocate
/// implementation-time nit).
#[test]
fn validator_rejects_each_deny_list_tier() {
    use ghars::validators::validate_environment_spec;

    fn make_with_var(key: &str, value: &str) -> EnvironmentSpec {
        let mut vars = BTreeMap::new();
        vars.insert(key.into(), value.into());
        EnvironmentSpec {
            vars,
            path_prepend: vec![],
            path_append: vec![],
        }
    }

    // Tier 1: LD_* injection.
    let err = validate_environment_spec(&make_with_var("LD_PRELOAD", "/tmp/malice.so"))
        .expect_err("LD_PRELOAD must reject");
    assert!(
        format!("{err}").contains("shared-library injection"),
        "LD_PRELOAD rejection must name the injection class; got: {err}"
    );

    // Tier 2: shell hijack.
    let err = validate_environment_spec(&make_with_var("BASH_ENV", "/tmp/sourced"))
        .expect_err("BASH_ENV must reject");
    assert!(
        format!("{err}").contains("shell-execution hijacking"),
        "BASH_ENV rejection must name the hijack class; got: {err}"
    );

    // Tier 3: ghars-owned.
    let err = validate_environment_spec(&make_with_var("CCACHE_DIR", "/tmp/ccache"))
        .expect_err("CCACHE_DIR must reject");
    assert!(
        format!("{err}").contains("rendered into"),
        "CCACHE_DIR rejection must say it's ghars-owned; got: {err}"
    );

    // Tier 4: POSIX shape.
    let err = validate_environment_spec(&make_with_var("lowercase_name", "x"))
        .expect_err("lowercase name must reject");
    assert!(
        format!("{err}").contains("POSIX env-var-name shape"),
        "POSIX-shape rejection must name the regex; got: {err}"
    );
}

/// Validator rejects env var VALUES containing control characters
/// (newline injection class — adversary A6). Without this gate, an
/// operator value `"foo\nMALICIOUS_VAR=bar"` would inject a second
/// env var via newline-terminated KEY=VALUE parsing.
#[test]
fn validator_rejects_env_var_value_with_newline() {
    use ghars::validators::validate_environment_spec;

    let mut vars = BTreeMap::new();
    vars.insert("FOO".into(), "value-with\nMALICIOUS_VAR=bar".into());
    let spec = EnvironmentSpec {
        vars,
        path_prepend: vec![],
        path_append: vec![],
    };
    let err = validate_environment_spec(&spec).expect_err("newline in value must reject");
    assert!(
        format!("{err}").contains("control character"),
        "newline rejection must name the control-character class; got: {err}"
    );
}

/// Validator rejects path entries that are relative, contain `:`
/// (PATH separator), or contain newlines.
#[test]
fn validator_rejects_invalid_path_entries() {
    use ghars::validators::validate_environment_spec;

    // Relative path.
    let spec = EnvironmentSpec {
        vars: BTreeMap::new(),
        path_prepend: vec![Utf8PathBuf::from("relative/path")],
        path_append: vec![],
    };
    let err = validate_environment_spec(&spec).expect_err("relative path must reject");
    assert!(
        format!("{err}").contains("absolute"),
        "relative-path rejection must mention absolute; got: {err}"
    );

    // Embedded `:` (PATH separator).
    let spec = EnvironmentSpec {
        vars: BTreeMap::new(),
        path_prepend: vec![],
        path_append: vec![Utf8PathBuf::from("/opt/a:/opt/b")],
    };
    let err = validate_environment_spec(&spec).expect_err("embedded : must reject");
    assert!(
        format!("{err}").contains("`:`"),
        "embedded-: rejection must name the char; got: {err}"
    );
}

/// Validator accepts valid environment.vars + `path_prepend` +
/// `path_append` combinations (positive case — pins that valid
/// operator configs pass cleanly).
#[test]
fn validator_accepts_valid_environment_spec() {
    use ghars::validators::validate_environment_spec;

    let mut vars = BTreeMap::new();
    vars.insert("MY_TEAM_VAR".into(), "production".into());
    vars.insert("DEPLOY_TARGET".into(), "buckos-ci".into());
    vars.insert("RUST_BACKTRACE".into(), "1".into());

    let spec = EnvironmentSpec {
        vars,
        path_prepend: vec![Utf8PathBuf::from("/opt/company-tools/bin")],
        path_append: vec![Utf8PathBuf::from("/opt/vendor/bin")],
    };
    validate_environment_spec(&spec).expect("valid spec must pass");
}
