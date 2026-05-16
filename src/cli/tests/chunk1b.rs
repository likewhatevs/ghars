//! Test chunk - co-located with cli/ submodules. See tests/mod.rs for fixture sharing rationale.
#![allow(clippy::unwrap_used)]

use super::*;

/// End-to-end: a `[[runner]] trust_zone` containing a control
/// character (here `\n`) must reject through `cmd_status` because
/// `validate_identity_fields` is wired into `load_config` as one
/// of the post-load validators (see the validator-order comment
/// in `load_config`). Symmetric to the cache-pool / runner-name
/// end-to-end tests above. Pins the runner-scoped
/// surface of `validate_identity_fields`
/// — the existing `validate_identity_fields_*` unit tests pin the
/// helper directly; this exercises the end-to-end CLI path so a
/// future refactor that drops `validate_identity_fields` from
/// `load_config` (or moves it to a per-cmd pre-step) will break
/// here.
#[test]
fn cmd_status_rejects_runner_trust_zone_with_newline_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // The TOML literal `"audited\nInjected=stuff"` survives the
    // serde-toml decoder verbatim because `\n` inside a basic
    // string is the standard escape; the validator runs on the
    // decoded String. This is the attack shape the `\n` rejection
    // is supposed to close (an operator config edit smuggling a
    // second X-Ghars-* line into the rendered drop-in body).
    let body = "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
trust_zone = \"audited\\nInjected=stuff\"
"
    .to_string();
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        github: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("trust_zone with newline must propagate via load_config");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner") && msg.contains("buckos"),
                "msg must scope to the offending runner; got: {msg}"
            );
            assert!(
                msg.contains("trust_zone"),
                "msg must name the trust_zone field; got: {msg}"
            );
            assert!(
                msg.contains("newline"),
                "msg must classify the offending char; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
    assert_eq!(
        err_to_exit_code(&err),
        6,
        "Validation must map to exit code 6 (Part 5)"
    );
}

/// End-to-end: a `[cache_pools.NAME] trust_zone` containing
/// a control character (here `\r`) must reject through `cmd_status`.
/// Symmetric to the runner-scoped `trust_zone` test above —
/// `validate_identity_fields` walks both `cfg.runners` and
/// `cfg.cache_pools`, so the e2e gate must cover both surfaces.
#[test]
fn cmd_status_rejects_cache_pool_trust_zone_with_carriage_return_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let body = "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[cache_pools.build]
kinds = [\"sccache\"]
size = \"200G\"
trust_zone = \"audited\\rsmuggled\"
"
    .to_string();
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        github: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("cache_pool trust_zone with carriage return must propagate via load_config");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("cache_pool") && msg.contains("build"),
                "msg must scope to the offending cache_pool; got: {msg}"
            );
            assert!(
                msg.contains("trust_zone"),
                "msg must name the trust_zone field; got: {msg}"
            );
            assert!(
                msg.contains("carriage return"),
                "msg must classify the offending char; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
    assert_eq!(err_to_exit_code(&err), 6);
}

/// End-to-end happy path: `cmd_status` ACCEPTS a config whose
/// `trust_zone` fields are clean (no control chars). Pins the
/// negative — without it, a future regression that always rejects
/// `trust_zone` (e.g. validator misuse) would only fail the rejection
/// tests above as "no error fired", which is symmetric ambiguity.
/// Asserts `cmd_status` returns Ok (with --runners-only the D-Bus
/// path is skipped, so no live systemd is needed) and the `trust_zone`
/// values pass through `validate_identity_fields` unaltered.
///
/// rc=1 (no preflight check ran the runners-only path through it)
/// is the expected return when the discovered state has no runners
/// matching the empty filter; the `load_config` gate is what we
/// pin here (Ok return ≡ `load_config` accepted).
#[test]
fn cmd_status_accepts_clean_trust_zone_via_load_config() {
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
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
trust_zone = \"audited\"

[cache_pools.build]
kinds = [\"sccache\"]
size = \"200G\"
trust_zone = \"audited\"
";
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        github: false,
        names: vec![],
    };
    // Expect Ok — load_config + validate_identity_fields pass for
    // clean ASCII values; runners-only mode short-circuits the
    // D-Bus discovery so the result is independent of the test
    // environment.
    let result = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    );
    assert!(
        result.is_ok(),
        "clean trust_zone must pass load_config; got: {result:?}"
    );
}

/// End-to-end: a `[[runner]] trust_zone` longer than
/// `TRUST_ZONE_MAX_LEN` must reject through `cmd_status` because
/// `validate_trust_zone_lengths` is wired into `load_config`.
/// Pins that the lift covers the `trust_zone` length surface
/// end-to-end via the public CLI.
#[test]
fn cmd_status_rejects_oversize_runner_trust_zone_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let oversize_tz = "a".repeat(crate::validators::TRUST_ZONE_MAX_LEN + 1);
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
trust_zone = \"{oversize_tz}\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        github: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("oversize runner trust_zone must propagate via load_config");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner") && msg.contains("buckos"),
                "msg must scope to the offending runner; got: {msg}"
            );
            assert!(
                msg.contains("trust_zone") && msg.contains("too long"),
                "msg must come from the trust_zone length cap; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
    assert_eq!(
        err_to_exit_code(&err),
        6,
        "Validation must map to exit code 6 (Part 5)"
    );
}

/// End-to-end: a `[cache_pools.NAME] trust_zone` longer than
/// `TRUST_ZONE_MAX_LEN` must reject through `cmd_status`. Sister
/// to the runner-side e2e test — the validator walks both
/// surfaces and the cap applies symmetrically.
#[test]
fn cmd_status_rejects_oversize_cache_pool_trust_zone_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let oversize_tz = "a".repeat(crate::validators::TRUST_ZONE_MAX_LEN + 1);
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[cache_pools.build]
kinds = [\"sccache\"]
size = \"200G\"
trust_zone = \"{oversize_tz}\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        github: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("oversize cache_pool trust_zone must propagate via load_config");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("cache_pool") && msg.contains("build"),
                "msg must scope to the offending cache_pool; got: {msg}"
            );
            assert!(
                msg.contains("trust_zone") && msg.contains("too long"),
                "msg must come from the trust_zone length cap; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
    assert_eq!(err_to_exit_code(&err), 6);
}

/// End-to-end: a `[[runner]] runner_tarball = "/nonexistent..."`
/// must reject through `cmd_status` because `validate_runner_tarballs`
/// is the 8th post-load validator wired into `load_config`. Symmetric
/// to the runner-name / cache-pool end-to-end tests above —
/// proves the lift covers the operator-supplied `runner_tarball`
/// surface so `cmd_validate` / `cmd_plan` / `cmd_apply` / `cmd_status` /
/// `cmd_add` all share the same gate.
///
/// The validator's lstat path is the gate: a non-existent path
/// returns `validation()` from `validators::validate_runner_tarball`
/// at the `!p.exists()` arm, so this test pins the missing-file
/// branch end-to-end. Symlink and non-regular-file branches are
/// pinned by the validator's own unit tests in validators.rs.
#[test]
fn cmd_status_rejects_nonexistent_runner_tarball_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // Path is comfortably under the tempdir but never created.
    // Using a child of the tempdir (rather than a hardcoded
    // /nonexistent...) avoids env leakage AND prevents collisions
    // with anything an operator might have on disk.
    let nonexistent = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("absent.tar.gz");
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
runner_tarball = \"{nonexistent}\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        github: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("nonexistent runner_tarball must propagate via load_config");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner") && msg.contains("buckos"),
                "msg must scope to the offending runner by name; got: {msg}"
            );
            assert!(
                msg.contains("runner-tarball") && msg.contains("does not exist"),
                "msg must come from the validate_runner_tarball layer; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
    assert_eq!(
        err_to_exit_code(&err),
        6,
        "Validation must map to exit code 6 (Part 5)"
    );
}

/// Symlink branch: `validate_runner_tarball` lstat's the path
/// BEFORE `is_file()` so a symlink-to-regular-file is rejected with
/// the "not a symlink" error from the symlink-rejection arm of
/// `validators::validate_runner_tarball`. This pins the rejection
/// end-to-end through `cmd_status` → `load_config` →
/// `validate_runner_tarballs`. Pairs with the nonexistent-file
/// branch above and the directory-branch test below to cover all
/// three error arms of the validator.
#[test]
fn cmd_status_rejects_symlink_runner_tarball_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // Plant a real regular file so the symlink target exists; the
    // gate is on the lstat-determined type of the runner_tarball
    // path itself, not the resolved target.
    let target = tmp.path().join("real.tar.gz");
    fs::write(&target, b"fake tarball bytes\n").unwrap();
    let symlink_path = tmp.path().join("link.tar.gz");
    std::os::unix::fs::symlink(&target, &symlink_path).unwrap();
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
runner_tarball = \"{}\"
",
        symlink_path.display()
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        github: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("symlink runner_tarball must propagate via load_config");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner") && msg.contains("buckos"),
                "msg must scope to the offending runner by name; got: {msg}"
            );
            assert!(
                msg.contains("symlink"),
                "msg must come from the symlink-rejection branch; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
    assert_eq!(
        err_to_exit_code(&err),
        6,
        "Validation must map to exit code 6 (Part 5)"
    );
}

/// Directory branch: `validate_runner_tarball` rejects a path
/// that exists, is not a symlink, but `is_file()` returns false —
/// covering the directory case (the `is_file()` arm of
/// `validators::validate_runner_tarball`). Pairs with the
/// nonexistent and symlink branch tests to give end-to-end
/// coverage of all three rejection arms via `cmd_status`.
#[test]
fn cmd_status_rejects_directory_runner_tarball_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // Create a directory at the runner_tarball path. Existence
    // check passes; lstat is_symlink check passes (real dir, no
    // symlink); is_file() returns false → directory branch.
    let dir_path = tmp.path().join("not-a-tarball");
    fs::create_dir_all(&dir_path).unwrap();
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"buckos\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
runner_tarball = \"{}\"
",
        dir_path.display()
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        github: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("directory runner_tarball must propagate via load_config");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner") && msg.contains("buckos"),
                "msg must scope to the offending runner by name; got: {msg}"
            );
            assert!(
                msg.contains("regular file"),
                "msg must come from the not-a-regular-file branch; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
    assert_eq!(
        err_to_exit_code(&err),
        6,
        "Validation must map to exit code 6 (Part 5)"
    );
}

/// End-to-end: a `[[runner]] name` exceeding
/// `NETNS_RUNNER_NAME_MAX_LEN` (= 7) MUST reject through
/// `cmd_status` when the runner's effective network mode is
/// `Netns`. The kernel hard-caps interface names at IFNAMSIZ-1
/// (= 15) in `dev_valid_name`; ghars's veth shape
/// `"ghars-{name}-h"` adds 8 bytes of overhead, so the operator-
/// controlled segment cannot exceed 7. Without this gate the
/// failure surfaces as an opaque `RTNETLINK answers: Numerical
/// result out of range` from `ip link add` during apply.
///
/// Uses `runners_only=true` to skip state.discover (which needs
/// D-Bus) — `load_config` is the only code path under test here.
#[test]
fn cmd_status_rejects_oversize_netns_runner_name_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // 8-char name (one over the cap) — fits the IDENTIFIER_MAX_LEN
    // (64) global cap so the identifier-shape gate does not
    // pre-reject; the failure must come from the netns gate.
    let oversize_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{oversize_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
network = \"isolated\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        github: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("oversize netns runner name must propagate via load_config");
    match &err {
        GharsError::Validation(msg, hint) => {
            assert!(
                msg.contains("runner") && msg.contains(&oversize_name),
                "msg must scope to the offending runner by name; got: {msg}"
            );
            assert!(
                msg.contains("netns") && msg.contains("IFNAMSIZ"),
                "msg must come from the netns IFNAMSIZ-cap layer; got: {msg}"
            );
            assert!(
                hint.contains("'open'"),
                "hint must offer 'open' as the alternate mode; got: {hint}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
    assert_eq!(
        err_to_exit_code(&err),
        6,
        "Validation must map to exit code 6 (Part 5)"
    );
}

/// Defaults-inheritance pin: a `[[runner]]` with NO per-runner
/// `network = "..."` must INHERIT `[defaults] network = "isolated"`
/// and therefore be subject to the netns IFNAMSIZ gate. Without
/// this test a regression that walked only `runner.network`
/// (skipping the defaults fallback) would silently exempt
/// inheriting runners from the IFNAMSIZ cap, producing the same
/// opaque `RTNETLINK ... Numerical result out of range` failure at
/// apply time that the netns-name-length gate prevents.
///
/// 8-char name = `NETNS_RUNNER_NAME_MAX_LEN + 1` — the smallest
/// shape that breaks IFNAMSIZ. Symmetric with the explicit-mode
/// test above; the only difference is `network = "isolated"` lives
/// at `[defaults]` level instead of `[[runner]]` level.
#[test]
fn cmd_status_rejects_oversize_netns_runner_name_via_defaults_inheritance() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let oversize_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
    // [defaults] network = "isolated" — the runner has NO explicit
    // network field, so the validator MUST resolve through the
    // defaults inheritance.
    let body = format!(
        "\
[defaults]
network = \"isolated\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{oversize_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        github: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err(
        "oversize netns runner name must propagate via load_config (defaults.network \
         inheritance path)",
    );
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner") && msg.contains(&oversize_name),
                "msg must scope to the offending runner by name; got: {msg}"
            );
            assert!(
                msg.contains("netns") && msg.contains("IFNAMSIZ"),
                "msg must come from the netns IFNAMSIZ-cap layer (defaults.network \
                 resolution must reach the same gate as the explicit-mode path); got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
    assert_eq!(
        err_to_exit_code(&err),
        6,
        "Validation must map to exit code 6 (Part 5)"
    );
}

/// Contract pin: the same 8-char runner name that fails the
/// netns gate above MUST PASS when no [network.NAME] is referenced
/// (implicit Open mode — no veth allocated, no IFNAMSIZ exposure).
/// Without this test a regression that hoisted
/// `NETNS_RUNNER_NAME_MAX_LEN` into the global runner-name gate
/// would silently break operator configs that legitimately use
/// longer names in Open mode.
#[test]
fn cmd_status_accepts_oversize_runner_name_in_open_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let oversize_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
    // No [network.NAME], no defaults.network → implicit Open mode.
    // The name is well under IDENTIFIER_MAX_LEN (64) so the
    // identifier-shape gate accepts it.
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"{oversize_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    // Direct load_config call: cmd_status would reach state.discover
    // which needs D-Bus access. This test is about the validators
    // accepting the config, not about cmd_status's full flow.
    let cfg_path = config_path;
    load_config(&cfg_path)
        .expect("8-char runner name in Open mode must pass all validators (no IFNAMSIZ exposure)");
}

/// Contract pin: the netns gate (= 7) is ADDITIONAL only for
/// Netns-mode runners — it MUST NOT retroactively tighten the
/// global runner-name cap on Open mode. A regression that
/// applied `NETNS_RUNNER_NAME_MAX_LEN` in `load_config`'s
/// runner-name check (instead of the surface-bound
/// `IDENTIFIER_MAX_LEN`) would silently break every operator on
/// Open mode.
#[test]
fn validate_runner_name_in_open_mode_allows_above_netns_cap() {
    // Pick a length above NETNS_RUNNER_NAME_MAX_LEN (= 7) but
    // within IDENTIFIER_MAX_LEN. Open mode means no netns gate
    // applies. Construct a minimal valid Config directly to
    // exercise validate_runner_names + the load_config sweep
    // without TOML parsing.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // One char above NETNS_RUNNER_NAME_MAX_LEN — the smallest
    // shape that would trip the netns gate. Open mode (no
    // [network.NAME] reference) means that gate is skipped, so
    // the name MUST pass the load_config sweep.
    let above_netns_cap_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[[runner]]
name = \"{above_netns_cap_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();
    load_config(&config_path).expect(
        "name above NETNS_RUNNER_NAME_MAX_LEN in Open mode must pass — \
         netns-name-length gate must NOT retroactively tighten Open-mode runners",
    );
}

/// Count-block expansion: a count block whose worst-case
/// expanded instance name exceeds `NETNS_RUNNER_NAME_MAX_LEN` MUST
/// reject. The expanded shape is `{prefix}-{i}` for `i in 1..=N`,
/// so the worst case is `prefix.len() + 1 + count.to_string().len()`.
/// With `NETNS_RUNNER_NAME_MAX_LEN` = 7, prefix len 5 + count digits
/// 2 + the literal '-' = 8 chars, one over the cap.
#[test]
fn cmd_status_rejects_netns_count_block_with_expanded_oversize() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // prefix = 5 chars; count = 99 (2 digits); worst-case expansion
    // = 5 + 1 + 2 = 8 > 7 = NETNS_RUNNER_NAME_MAX_LEN. The bare
    // prefix alone (5 chars) WOULD pass; the gate must catch the
    // count expansion.
    let prefix = "abcde"; // 5 chars
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{prefix}\"
count = 99
url = \"https://github.com/example/repo\"
auth = \"pat\"
network = \"isolated\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: false,
        runners_only: true,
        score: false,
        github: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("netns count-block worst-case oversize must propagate via load_config");
    match &err {
        GharsError::Validation(msg, _) => {
            assert!(
                msg.contains("runner") && msg.contains(prefix),
                "msg must scope to the offending runner prefix; got: {msg}"
            );
            assert!(
                msg.contains("count block") && msg.contains("worst-case"),
                "msg must come from the count-expansion branch of the netns gate; got: {msg}"
            );
            assert!(
                msg.contains("IFNAMSIZ"),
                "msg must cite the kernel constant for operator orientation; got: {msg}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
    assert_eq!(
        err_to_exit_code(&err),
        6,
        "Validation must map to exit code 6 (Part 5)"
    );
}

/// Boundary pin: a runner name of EXACTLY
/// `NETNS_RUNNER_NAME_MAX_LEN` chars in netns mode must ACCEPT.
/// Together with the `_rejects_oversize_` test (cap+1), this pins
/// the exact boundary the validator enforces. A regression that
/// off-by-ones the comparison (`>=` instead of `>`) would flip
/// this test from pass to fail.
#[test]
fn cmd_status_accepts_max_len_netns_runner_name_via_load_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let max_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN);
    // Drift guard: NETNS_RUNNER_NAME_MAX_LEN is derived from
    // IFNAMSIZ - 1 - VETH_NAME_OVERHEAD = 16 - 1 - 8 = 7. If
    // either bookend changes, this assertion catches the drift
    // before the rest of the test reasons about a stale cap.
    assert_eq!(
        max_name.len(),
        7,
        "NETNS_RUNNER_NAME_MAX_LEN drift would invalidate this test's invariant"
    );
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{max_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
network = \"isolated\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();
    load_config(&config_path).expect(
        "name at exactly NETNS_RUNNER_NAME_MAX_LEN must pass — \
         cap is inclusive (the longest accepted), not exclusive",
    );
}

/// Count-block boundary pin: `count = Some(1)` MUST be
/// treated as bare-name (no suffix), matching `plan::is_count_block`
/// which only returns `true` for `count >= 2`. A 7-char name with
/// `count = 1` produces a single instance with name `"aaaaaaa"` —
/// no `-1` suffix — so it MUST pass the netns gate. A regression
/// that included `count.to_string().len()` for `count = 1` would
/// falsely reject this config.
#[test]
fn cmd_status_accepts_count_one_at_max_len_in_netns_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN);
    assert_eq!(name.len(), 7, "drift guard for NETNS_RUNNER_NAME_MAX_LEN");
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{name}\"
count = 1
url = \"https://github.com/example/repo\"
auth = \"pat\"
network = \"isolated\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();
    load_config(&config_path).expect(
        "count = 1 keeps the bare name in plan::expand_counts (no `-1` suffix), \
         so a name at the cap must still pass — the validator's count semantics \
         must mirror `plan::is_count_block` (count >= 2 ONLY)",
    );
}

/// Count-block boundary pin: `count = Some(0)` produces
/// ZERO runners (see `plan::expand_counts` early-return on
/// `Some(0)`), so no veth is ever allocated for that block. The
/// netns gate MUST NOT reject an oversize name when `count = 0`
/// because the planner will emit zero instances regardless. A
/// regression that gates blindly on `name.len()` (ignoring
/// `count = 0`) would falsely reject this config.
#[test]
fn cmd_status_accepts_count_zero_oversize_in_netns_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    // 8-char name (one over the netns cap). count = 0 means the
    // planner emits zero instances — no veth allocation, no
    // IFNAMSIZ exposure — so the gate must let this through.
    let name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
    let body = format!(
        "\
[defaults]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{name}\"
count = 0
url = \"https://github.com/example/repo\"
auth = \"pat\"
network = \"isolated\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();
    load_config(&config_path).expect(
        "count = 0 produces zero runners (see `plan::expand_counts` early-return), \
         so no veth is ever allocated — the netns gate must mirror this and \
         accept oversize names when the block expands to zero instances",
    );
}

/// When `[defaults] network = "isolated"` is set and a
/// `[[runner]]` block has no `network = ...` override, the
/// netns gate MUST resolve the network reference through the
/// defaults inheritance path (`runner.network → defaults.network
/// → cfg.networks[name].mode`) and reject an oversize name. This
/// pins the exact resolution order documented at the top of
/// `validate_netns_runner_name_lengths`. A regression that only
/// reads `runner.network` without falling back to
/// `defaults.network` would silently accept an oversize name in
/// netns deployments where operators rely on the defaults
/// pattern (the canonical Part 3 idiom for fleets where every
/// runner shares a network policy).
#[test]
fn cmd_status_rejects_oversize_netns_via_defaults_network_inheritance() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    let oversize_name = "a".repeat(crate::validators::NETNS_RUNNER_NAME_MAX_LEN + 1);
    // [defaults] network = "isolated" — no per-runner override.
    let body = format!(
        "\
[defaults]
network = \"isolated\"

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

[network.isolated]
mode = \"netns\"
allowed_egress = [{{ addr = \"140.82.121.4\", port = 443, comment = \"github\" }}]

[[runner]]
name = \"{oversize_name}\"
url = \"https://github.com/example/repo\"
auth = \"pat\"
"
    );
    fs::write(config_path.as_std_path(), body).unwrap();

    let err = load_config(&config_path).expect_err(
        "oversize netns runner name MUST reject when network mode is \
         inherited from [defaults] (validator must walk the resolution chain)",
    );
    match &err {
        GharsError::Validation(msg, hint) => {
            assert!(
                msg.contains("runner") && msg.contains(&oversize_name),
                "msg must scope to the offending runner; got: {msg}"
            );
            assert!(
                msg.contains("netns") && msg.contains("IFNAMSIZ"),
                "msg must come from the netns IFNAMSIZ gate, not an unrelated \
                 validator; got: {msg}"
            );
            assert!(
                hint.contains("'open'"),
                "hint must offer 'open' as an alternate mode; got: {hint}"
            );
        }
        other => panic!("expected GharsError::Validation, got: {other:?}"),
    }
}

#[test]
fn cmd_status_health_only_still_loads_config() {
    // Even when output is health-only (skips state.discover
    // entirely), cmd_status must still call load_config. The
    // "every command path validates config first" project
    // standard prevents users from getting a misleading "PASS" on
    // health checks while their config is silently broken.
    let tmp = tempfile::tempdir().unwrap();
    let config_path = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf())
        .unwrap()
        .join("ghars.toml");
    fs::write(
        config_path.as_std_path(),
        "this is not toml at all = = = =\n",
    )
    .unwrap();

    let paths = Paths::default();
    let args = StatusArgs {
        json: false,
        metrics: false,
        health_only: true,
        runners_only: false,
        score: false,
        github: false,
        names: vec![],
    };
    let err = cmd_status(
        &config_path,
        &paths,
        &args,
        ColorMode { enabled: false },
        true,
    )
    .expect_err("malformed config + --health-only must still error");
    assert!(
        matches!(err, GharsError::Config(_, _)),
        "expected GharsError::Config; got {err:?}"
    );
}

#[test]
fn argv_init_takes_optional_output_override() {
    let cli = Cli::try_parse_from(["ghars", "init", "--output", "/etc/ghars/foo.toml"]).unwrap();
    match cli.command {
        Command::Init(args) => {
            assert_eq!(
                args.output.as_deref(),
                Some(Utf8Path::new("/etc/ghars/foo.toml"))
            );
        }
        _ => panic!("expected Init"),
    }
}

#[test]
fn argv_add_minimum_repo_only() {
    let cli = Cli::try_parse_from(["ghars", "add", "--repo", "owner/repo"]).unwrap();
    match cli.command {
        Command::Add(args) => {
            assert_eq!(args.repo, "owner/repo");
            assert!(args.name.is_none());
            assert!(args.labels.is_empty());
            assert!(args.auth.is_none());
            assert!(!args.no_apply);
        }
        _ => panic!("expected Add"),
    }
}

#[test]
fn argv_add_full_with_labels_and_no_apply() {
    let cli = Cli::try_parse_from([
        "ghars",
        "add",
        "--repo",
        "owner/repo",
        "--name",
        "owner-repo-3",
        "--labels",
        "x64,linux,buck2",
        "--auth",
        "pat",
        "--no-apply",
    ])
    .unwrap();
    match cli.command {
        Command::Add(args) => {
            assert_eq!(args.repo, "owner/repo");
            assert_eq!(args.name.as_deref(), Some("owner-repo-3"));
            assert_eq!(
                args.labels,
                vec!["x64".to_owned(), "linux".to_owned(), "buck2".to_owned()]
            );
            assert_eq!(args.auth.as_deref(), Some("pat"));
            assert!(args.no_apply);
        }
        _ => panic!("expected Add"),
    }
}

#[test]
fn argv_logs_default_lines_100_no_follow() {
    let cli = Cli::try_parse_from(["ghars", "logs"]).unwrap();
    match cli.command {
        Command::Logs(args) => {
            assert!(args.names.is_empty());
            assert!(!args.follow);
            assert_eq!(args.lines, 100);
            assert!(args.since.is_none());
        }
        _ => panic!("expected Logs"),
    }
}

#[test]
fn argv_logs_with_since_and_explicit_lines() {
    let cli = Cli::try_parse_from([
        "ghars",
        "logs",
        "--since",
        "1 hour ago",
        "-n",
        "500",
        "buckos",
    ])
    .unwrap();
    match cli.command {
        Command::Logs(args) => {
            assert_eq!(args.since.as_deref(), Some("1 hour ago"));
            assert_eq!(args.lines, 500);
            assert_eq!(args.names, vec!["buckos".to_owned()]);
        }
        _ => panic!("expected Logs"),
    }
}

#[test]
fn argv_metrics_defaults() {
    let cli = Cli::try_parse_from(["ghars", "metrics"]).unwrap();
    match cli.command {
        Command::Metrics(args) => {
            assert!(args.names.is_empty());
            assert!(!args.json);
            assert!(!args.no_total);
        }
        _ => panic!("expected Metrics"),
    }
}

#[test]
fn argv_metrics_json_no_total_with_names() {
    let cli =
        Cli::try_parse_from(["ghars", "metrics", "buckos,ktstr", "--json", "--no-total"]).unwrap();
    match cli.command {
        Command::Metrics(args) => {
            assert_eq!(args.names, vec!["buckos".to_owned(), "ktstr".to_owned()]);
            assert!(args.json);
            assert!(args.no_total);
        }
        _ => panic!("expected Metrics"),
    }
}

#[test]
fn argv_completions_each_supported_shell_parses() {
    // clap_complete::Shell variants. Pick a handful of well-known
    // ones; clap rejects unknown shells, so success here proves we
    // expose the same enum surface.
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let cli = Cli::try_parse_from(["ghars", "completions", shell]).unwrap();
        match cli.command {
            Command::Completions { .. } => {}
            _ => panic!("expected Completions for {shell}"),
        }
    }
}

#[test]
fn argv_manpages_requires_output_path() {
    let cli = Cli::try_parse_from(["ghars", "manpages", "/tmp/ghars-manpages"]).unwrap();
    match cli.command {
        Command::Manpages { output } => {
            assert_eq!(output, Utf8Path::new("/tmp/ghars-manpages"));
        }
        _ => panic!("expected Manpages"),
    }
    // Without an output positional, parse fails.
    let r = Cli::try_parse_from(["ghars", "manpages"]);
    assert!(r.is_err(), "manpages without OUTPUT must fail at parse");
}

#[test]
fn argv_hidden_netns_setup_requires_instance() {
    let cli = Cli::try_parse_from(["ghars", "_netns-setup", "buckos"]).unwrap();
    assert!(matches!(cli.command, Command::NetnsSetup { .. }));
    let r = Cli::try_parse_from(["ghars", "_netns-setup"]);
    assert!(r.is_err(), "_netns-setup without instance must fail");
}

#[test]
fn argv_hidden_netns_teardown_requires_instance() {
    let cli = Cli::try_parse_from(["ghars", "_netns-teardown", "ci-1"]).unwrap();
    assert!(matches!(cli.command, Command::NetnsTeardown { .. }));
}

#[test]
fn argv_hidden_netns_veth_passes_program_args_through() {
    // trailing_var_arg + allow_hyphen_values is the contract for
    // `ghars _netns-veth INST -- /usr/sbin/ip -4 addr`.
    let cli = Cli::try_parse_from(["ghars", "_netns-veth", "ci-1", "/usr/sbin/ip", "-4", "addr"])
        .unwrap();
    match cli.command {
        Command::NetnsVeth { instance, program } => {
            assert_eq!(instance, "ci-1");
            assert_eq!(program, vec!["/usr/sbin/ip", "-4", "addr"]);
        }
        _ => panic!("expected NetnsVeth"),
    }
}

#[test]
fn argv_global_quiet_and_verbose_count() {
    let cli = Cli::try_parse_from(["ghars", "--quiet", "-vv", "validate"]).unwrap();
    assert!(cli.quiet);
    assert_eq!(cli.verbose, 2);
}

#[test]
fn argv_apply_only_value_delimiter_splits_csv() {
    // The `value_delimiter = ','` annotation is the only thing
    // turning a single CSV token into a vec. Drop it and the
    // operator's filter becomes a literal string match. Pin it.
    let cli = Cli::try_parse_from(["ghars", "apply", "--only", "ci-1,ci-2,ci-3"]).unwrap();
    match cli.command {
        Command::Apply(args) => {
            assert_eq!(
                args.only,
                vec!["ci-1".to_owned(), "ci-2".to_owned(), "ci-3".to_owned()]
            );
        }
        _ => panic!("expected Apply"),
    }
}

#[test]
fn argv_logs_short_follow_flag() {
    // `-f` short form must be equivalent to `--follow`.
    let cli = Cli::try_parse_from(["ghars", "logs", "buckos", "-f"]).unwrap();
    match cli.command {
        Command::Logs(args) => {
            assert!(args.follow);
            assert_eq!(args.names, vec!["buckos".to_owned()]);
        }
        _ => panic!("expected Logs"),
    }
}

#[test]
fn argv_global_config_explicit_flag_path_used() {
    // --config CLI flag is honored. We don't test env-fallback or
    // default-fallback here because both require std::env::set_var
    // / remove_var which are `unsafe` since Rust 2024 (race with
    // other threads), and the workspace forbids unsafe_code.
    // The clap derive itself wires `env = "GHARS_CONFIG"` and
    // `default_value = "/etc/ghars/ghars.toml"` — those are clap's
    // contract; if either of them broke at the source level the
    // doc comment for `Cli::config` would no longer compile.
    let cli =
        Cli::try_parse_from(["ghars", "--config", "/tmp/ghars-flag.toml", "validate"]).unwrap();
    assert_eq!(cli.config, Utf8Path::new("/tmp/ghars-flag.toml"));
}

#[test]
fn argv_global_verbose_count_three_v_flags() {
    // Count action: `-vvv` increments three times.
    let cli = Cli::try_parse_from(["ghars", "-vvv", "plan"]).unwrap();
    assert_eq!(cli.verbose, 3);
}

/// Pin single `-v` shape. Without this, a regression that
/// changed the clap action from `Count` to `SetTrue` would still
/// pass the -vv/-vvv tests (clap-derive's `Count` collapses
/// repeated short flags) but silently break the single-flag case
/// because `SetTrue` stores 1 only on first occurrence.
#[test]
fn argv_global_verbose_count_single_v_flag() {
    let cli = Cli::try_parse_from(["ghars", "-v", "plan"]).unwrap();
    assert_eq!(cli.verbose, 1);
}

/// Pin `--verbose` long-form shape. Operators may pass the
/// long form (CI scripts often do for readability); a regression
/// that dropped `long` from the clap derive would silently break
/// it without affecting the short-form `-v` tests.
#[test]
fn argv_global_verbose_long_form() {
    let cli = Cli::try_parse_from(["ghars", "--verbose", "plan"]).unwrap();
    assert_eq!(cli.verbose, 1);
}

// ---------- verbose_to_filter_level truth table ---------------

/// Row 1/6: default operator state. No flags = info.
#[test]
fn verbose_to_filter_level_quiet_false_verbose_0_returns_info() {
    assert_eq!(verbose_to_filter_level(false, 0), "info");
}

/// Row 2/6: --quiet alone collapses info chatter to warn.
#[test]
fn verbose_to_filter_level_quiet_true_verbose_0_returns_warn() {
    assert_eq!(verbose_to_filter_level(true, 0), "warn");
}

/// Row 3/6: -v alone bumps to debug.
#[test]
fn verbose_to_filter_level_quiet_false_verbose_1_returns_debug() {
    assert_eq!(verbose_to_filter_level(false, 1), "debug");
}

/// Row 4/6: --quiet AND -v → -v wins; debug. Pins the
/// "verbose overrides quiet" contract documented in the helper's
/// doc-comment.
#[test]
fn verbose_to_filter_level_quiet_true_verbose_1_returns_debug() {
    assert_eq!(verbose_to_filter_level(true, 1), "debug");
}

/// Row 5/6: -vv = trace (any v >= 2 lands here).
#[test]
fn verbose_to_filter_level_quiet_false_verbose_2_returns_trace() {
    assert_eq!(verbose_to_filter_level(false, 2), "trace");
}

/// Row 6/6: --quiet AND -vv → -vv wins; trace.
#[test]
fn verbose_to_filter_level_quiet_true_verbose_2_returns_trace() {
    assert_eq!(verbose_to_filter_level(true, 2), "trace");
}

/// Saturation: any verbose >= 2 maps to trace, not just 2.
/// Pins that the `_ => "trace"` arm catches arbitrary higher
/// counts (operators sometimes type -vvvvv).
#[test]
fn verbose_to_filter_level_high_verbose_counts_saturate_at_trace() {
    for v in [3, 5, 10, u8::MAX] {
        assert_eq!(
            verbose_to_filter_level(false, v),
            "trace",
            "verbose={v} must saturate at trace"
        );
        assert_eq!(
            verbose_to_filter_level(true, v),
            "trace",
            "verbose={v} with quiet must still saturate at trace"
        );
    }
}

// ---------- render_plan + render_action_line all variants ---------

/// Build a recreate-class `RunnerDelta` with the given name +
/// `recreate_reasons`. All other fields default to the same values
/// callers would otherwise inline. Use for any recreate-class
/// `UpdateRunner` test fixture where only name + reasons matter.

/// Build an in-place `RunnerDelta` (no recreate) with the
/// given name. Symmetric to `recreate_delta` for the `~` sigil
/// branch.

#[test]
fn render_action_line_create_runner_plain_and_color() {
    let action = Action::CreateRunner(fake_runner_plan("buckos"));
    let plain = render_action_line(&action, ColorMode { enabled: false }, false);
    assert!(plain.starts_with("+ "));
    assert!(plain.contains("runner buckos"));
    assert!(plain.contains("create"));
    // No ANSI when color off.
    assert!(!plain.contains("\x1b["));
    let colored = render_action_line(&action, ColorMode { enabled: true }, false);
    assert!(colored.contains("\x1b[32m"), "expected green ANSI prefix");
    assert!(colored.contains("\x1b[0m"), "expected ANSI reset");
}

#[test]
fn render_action_line_update_runner_emits_field_changes_indented() {
    // Per-field FieldChange entries render as
    // 4-space-indented `path: before → after` lines under the
    // header. The test exercises a recreate-class field (url) and
    // a list-typed field (labels) to confirm both paths produce a
    // line; list rendering uses Display of the whole vec for now —
    // the +/- per-item form is reserved for the full --diff flag.
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: true,
        recreate_reasons: vec!["url"],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: vec![
            plan::FieldChange {
                path: "url",
                before: plan::FieldValue::String("https://github.com/example/buckos".into()),
                after: plan::FieldValue::String("https://github.com/example/buckos-new".into()),
            },
            plan::FieldChange {
                path: "labels",
                before: plan::FieldValue::List(vec!["ci".into()]),
                after: plan::FieldValue::List(vec!["ci".into(), "gpu".into()]),
            },
        ],
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let line = render_action_line(
        &Action::UpdateRunner(delta),
        ColorMode { enabled: false },
        false,
    );
    let lines: Vec<&str> = line.split('\n').collect();
    assert_eq!(lines.len(), 3, "header + 2 field lines, got: {line}");
    // Recreate-class UpdateRunner uses `!` sigil at column 0.
    assert!(lines[0].starts_with("! "), "got: {}", lines[0]);
    assert_eq!(
        lines[1],
        "    url: https://github.com/example/buckos → https://github.com/example/buckos-new",
    );
    // List-typed FieldValue renders comma-joined in text
    // (no surrounding brackets — same v1 contract as the
    // pre-typed `labels.join(",")`). Operator grep pipelines
    // that key off `labels:.*gpu` keep working.
    assert_eq!(lines[2], "    labels: ci → ci,gpu");
}

#[test]
fn render_action_line_update_runner_emits_drop_in_change_lines() {
    // Created (`+ basename`), Modified (`~ basename`), and
    // Removed (`- basename`) all surface in the brief view under
    // the action header so toggling a per-family drop-in
    // (enabling [proxy] → 60-proxy.conf created, clearing
    // memory_max → 10-memory.conf removed) is operator-visible
    // without re-running the planner with --diff. Preserved is
    // the audit-trail "no edit" tag and stays out of the brief
    // view — JSON output covers all four variants for tooling.
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::DriftDetected,
        field_changes: Vec::new(),
        drop_in_changes: vec![
            plan::DropInChange {
                basename: "10-memory.conf".into(),
                change: plan::DropInChangeKind::Modified {
                    before: "old".into(),
                    after: "new".into(),
                },
            },
            plan::DropInChange {
                basename: "60-proxy.conf".into(),
                change: plan::DropInChangeKind::Created {
                    after: "new".into(),
                },
            },
            plan::DropInChange {
                basename: "70-hooks.conf".into(),
                change: plan::DropInChangeKind::Removed {
                    before: "old".into(),
                },
            },
            plan::DropInChange {
                basename: "15-resolv.conf".into(),
                change: plan::DropInChangeKind::Preserved,
            },
        ],
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let line = render_action_line(
        &Action::UpdateRunner(delta),
        ColorMode { enabled: false },
        false,
    );
    let lines: Vec<&str> = line.split('\n').collect();
    // header + 3 drop-in lines (Modified / Created / Removed);
    // Preserved is suppressed from the brief view.
    assert_eq!(
        lines.len(),
        4,
        "header + Modified + Created + Removed lines, got: {line}"
    );
    assert!(lines[0].starts_with("~ "), "got: {}", lines[0]);
    assert_eq!(lines[1], "    ~ 10-memory.conf");
    assert_eq!(lines[2], "    + 60-proxy.conf");
    assert_eq!(lines[3], "    - 70-hooks.conf");
    assert!(
        !line.contains("15-resolv.conf"),
        "Preserved drop-in must not appear in brief view: {line}"
    );
}

#[test]
fn render_action_line_update_runner_in_place_includes_drift_cause() {
    // In-place update without recreate must carry the
    // drift_cause label so operators can tell config edit vs
    // detected drift.
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: false,
        recreate_reasons: vec![],
        drift_cause: plan::DriftCause::DriftDetected,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let line = render_action_line(
        &Action::UpdateRunner(delta),
        ColorMode { enabled: false },
        false,
    );
    assert!(line.starts_with("~ "));
    assert!(line.contains("drift_detected"), "got: {line}");
    assert!(line.contains("update: in-place"), "got: {line}");
}

#[test]
fn render_action_line_update_runner_recreate_lists_reasons_and_cause() {
    // Existing recreate-reasons formatting: spec_changed
    // cause + requires_recreate path emits both labels.
    let delta = plan::RunnerDelta {
        identity: fake_identity("buckos"),
        after: fake_runner_plan("buckos"),
        requires_recreate: true,
        recreate_reasons: vec!["url", "runner_version"],
        drift_cause: plan::DriftCause::SpecChanged,
        field_changes: Vec::new(),
        drop_in_changes: Vec::new(),
        before_caches: None,
        before_drop_in_basenames: None,
    };
    let line = render_action_line(
        &Action::UpdateRunner(delta),
        ColorMode { enabled: false },
        false,
    );
    assert!(line.contains("spec_changed"), "got: {line}");
    assert!(line.contains("update: recreate"), "got: {line}");
    assert!(line.contains("url,runner_version"), "got: {line}");
}
