//! Test chunk - co-located with cli/ submodules. See tests/mod.rs for fixture sharing rationale.
#![allow(clippy::unwrap_used)]

use super::chunk3a2::proxy_with_one_ca_cert;
use super::*;

/// Reject `CaCertBinding` with non-absolute `path`. systemd's
/// `BindReadOnlyPaths=` requires absolute paths; a relative path
/// would resolve against systemd's working directory (`/`) at
/// unit-start and fail. Parallel to
/// `validate_cache_pool_binary_paths` enforcing the same gate for
/// `sccache_path` / `sleep_path`.
#[test]
fn validate_proxy_ca_certs_nonempty_rejects_non_absolute_path() {
    let mut cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    cfg.proxy = Some(proxy_with_one_ca_cert("NODE_EXTRA_CA_CERTS", "ca.pem"));
    let err = validate_proxy_ca_certs_nonempty(&cfg).expect_err("relative path must reject");
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
        msg.contains("runner \"buckos\" proxy ca_certs[0]")
            && msg.contains("empty or whitespace-only `env`"),
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
        msg.contains("runner \"buckos\" proxy ca_certs[0]")
            && msg.contains("empty or whitespace-only `path`"),
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
        msg.contains("runner \"buckos\" proxy ca_certs[0]")
            && msg.contains("non-absolute `path`")
            && msg.contains("ca.pem"),
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
    validate_proxy_ca_certs_nonempty(&cfg).expect("fully-populated ca_cert binding must pass");
}

#[test]
fn validate_proxy_ca_certs_nonempty_accepts_no_proxy_block() {
    let cfg = cfg_with_runner_trust_zone("buckos", "default".into());
    // cfg.proxy = None; no runner.proxy either. Validator must
    // pass vacuously when no proxy block exists.
    validate_proxy_ca_certs_nonempty(&cfg).expect("config with no proxy block must pass vacuously");
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
        no_proxy: vec![String::new()],
        ca_certs: vec![],
    });
    let err = validate_proxy_no_proxy_nonempty_entries(&cfg)
        .expect_err("defaults.proxy no_proxy = [\"\"] must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("defaults.proxy no_proxy[0]")
            && msg.contains("empty or whitespace-only entry"),
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
            String::new(),
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
        no_proxy: vec![String::new()],
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

/// Reject whitespace-only `no_proxy` entry. systemd's `Environment=`
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
    validate_proxy_no_proxy_nonempty_entries(&cfg).expect("non-empty entries must pass");
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
