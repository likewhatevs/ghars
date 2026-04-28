//! Error type for the ghars library surface.
//!
//! Design spec: Part 3 (`error.rs`). Every variant carries an actionable
//! hint string; the bin layer adds "next steps" command suggestions on top
//! of the error chain.
//!
//! # Secret-leakage policy
//!
//! `cli.rs::cmd_apply` renders failed actions via `writeln!(io::stderr(),
//! "fail: {label}: {err}")`, which formats `GharsError` through `Display`.
//! Operator stderr can be captured by journalctl, log shippers, CI
//! transcripts, or the operator's terminal scrollback — none of which are
//! authoritative on whether they will be transmitted off-host.
//!
//! Therefore: **`GharsError` `Display` output MUST NOT contain**
//!   - registration / removal token values (`RegistrationToken.value`),
//!   - PAT bytes (`PatToken.token`),
//!   - environment variable VALUES (the *name* is fine — config, not
//!     secret),
//!   - GitHub App private-key PEM bytes,
//!   - the contents of any file read by `read_root_owned_0600` or any
//!     other auth-credential reader.
//!
//! What IS allowed in messages:
//!   - file paths (auth.rs:659/679/689 emit `path.display()` — the
//!     existence/permissions of a credential file is operator-actionable
//!     info that doesn't disclose the credential itself),
//!   - environment variable names (auth.rs:263 emits `{env:?}` where
//!     `env` is the variable NAME like `"GHARS_PAT"`),
//!   - `octocrab::Error` Display output. In octocrab 0.42.1 (verified
//!     against octocrab-0.42.1/src/error.rs and snafu-derive-0.8.9/
//!     src/shared.rs:537-549) the `GitHub` variant carries no
//!     `#[snafu(display(...))]` attribute, so its Display output is
//!     literally the variant-name string `"GitHub"` — no message,
//!     no status code, no URL, no header, no body. Other variants
//!     (`Hyper`, `Service`, `Http`, `Json`, `Serde`, `JWT`,
//!     `Installation`, etc.) chain to the wrapped error's Display
//!     plus a `snafu::Backtrace`. Operator-actionable status code
//!     and hint text are extracted by `auth::octocrab_to_auth`
//!     from the typed `source.status_code` field
//!     (auth.rs::octocrab_to_auth), not from the upstream Display
//!     surface. The supply-chain pin in
//!     `auth.rs::octocrab_to_auth_display_does_not_leak_pat_or_
//!     request_body` fails loudly if a future octocrab cargo update
//!     changes the GitHub-variant Display.
//!
//! When constructing a new `GharsError` variant, audit any value
//! interpolated into the message string against this list. There are
//! NO exceptions for echoing token bytes — `auth.rs::validate_
//! interactive_token_shape` emits a class label ("NUL byte",
//! "whitespace", "control character") rather than the offending
//! character itself (#273). Token bytes, env values, and PEM bytes
//! must never appear via direct interpolation, derived encodings
//! (base64, hex), or partial slices.
//!
//! The `tests` module below pins the variant `Display` outputs against
//! a forbidden-substring set covering build-machine paths and stack
//! traces. The secret-leakage half of this contract is enforced
//! convention-based at construction sites, not runtime — a
//! `format!("...{token}...")` mistake at a future call site cannot be
//! caught by Display tests because the test inputs don't include real
//! secrets. Reviewers must cross-reference this policy block when
//! editing error construction code.

/// Library error type. Each variant pairs a one-line message with a hint.
#[derive(thiserror::Error, Debug)]
pub enum GharsError {
    /// Config parse / shape errors.
    #[error("config: {0}\n  hint: {hint}", hint = .1)]
    Config(String, String),
    /// Validation errors (regex, range, cross-reference).
    #[error("validation: {0}\n  hint: {hint}", hint = .1)]
    Validation(String, String),
    /// Interactive prompting required but unavailable. Distinct from
    /// `Validation` so non-TTY apply attempts surface a dedicated
    /// exit code (7, see `cli::err_to_exit_code`) rather than
    /// colliding with config-shape rejections (6). The
    /// operator-actionable answer is always "pass `--auto-approve`"
    /// or "run from a TTY"; mapping these to a separate variant lets
    /// shell wrappers and CI gating scripts branch on the cause
    /// without parsing the error message. (#390)
    #[error("interactive: {0}\n  hint: {hint}", hint = .1)]
    Interactive(String, String),
    /// Preflight checks failing (OS, KVM, systemd version, etc).
    #[error("preflight: {0}\n  hint: {hint}", hint = .1)]
    Preflight(String, String),
    /// GitHub API errors.
    #[error("github API: {0}\n  hint: {hint}", hint = .1)]
    GitHub(String, String),
    /// Systemd / D-Bus interaction errors.
    #[error("systemd: {0}\n  hint: {hint}", hint = .1)]
    Systemd(String, String),
    /// Auth subsystem errors.
    #[error("auth: {0}\n  hint: {hint}", hint = .1)]
    Auth(String, String),
    /// An apply Action failed; wraps the underlying error with the action
    /// label for diagnostics.
    #[error("apply (action {action}): {source}")]
    Apply {
        /// Display label for the failing Action.
        action: String,
        /// Underlying error.
        #[source]
        source: Box<GharsError>,
    },
    /// Plain io errors.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Tarball extraction errors.
    #[error("tarball: {0}")]
    Tarball(String),
    /// SHA256 mismatch on a downloaded or local tarball.
    #[error(
        "sha256 mismatch on {path}: expected {expected} got {actual}\n  hint: re-download via `ghars apply --refresh-releases` or pass --runner-tarball with a verified file"
    )]
    Sha256Mismatch {
        /// Path of the file that failed verification.
        path: String,
        /// Expected hex digest.
        expected: String,
        /// Actual hex digest.
        actual: String,
    },
    /// `apply.lock` is held by another process.
    ///
    /// The `stale` field records whether the recorded PID is still
    /// alive (false ⇒ no `/proc/PID/status` entry at the moment the
    /// error was constructed). The `Display` impl branches on `stale`
    /// so the operator sees an actionable hint: either "wait for PID
    /// to finish" (live holder) or "stale lock — remove
    /// `<path>`" (no living holder; the previous `ghars apply`
    /// crashed without releasing the file). SEC-19.
    #[error(
        "apply lock held by PID {pid} at {path}\n  hint: {}",
        if *stale {
            format!("PID {pid} is not running — the lock is stale; remove `{path}` to retry")
        } else {
            format!("another `ghars apply` (PID {pid}) is in progress; wait for it to finish")
        }
    )]
    ApplyLocked {
        /// PID of the lock holder (read from the lock file).
        pid: i32,
        /// Path to the lock file.
        path: String,
        /// True iff `/proc/<pid>/status` did not exist when the error
        /// was constructed. Tells the operator whether to wait or to
        /// clean up a stale lock. Determined per SEC-19 by
        /// [`crate::apply::pid_is_alive`].
        stale: bool,
    },
}

/// Convenience `Result` alias for the library surface.
pub type Result<T> = std::result::Result<T, GharsError>;

/// Prepend a scope label to a `GharsError::Validation`'s message, leaving
/// the hint untouched. Non-Validation variants pass through unchanged.
///
/// Validators that walk a config tree (per-runner, per-pool,
/// `[defaults]`) need to attribute a single underlying validator's error
/// to the source TOML block the operator authored — e.g. so an invalid
/// `extra_capabilities` entry surfaces as
/// `validation: runner "buckos": <original message>` instead of an
/// unscoped error the operator must hunt down.
///
/// The pattern was open-coded as a 7-line closure in three validators
/// in `cli.rs` (`validate_security_overrides`,
/// `validate_cache_pool_names`, `validate_identity_fields`), each
/// closure used at multiple call sites within its function. Single-
/// sourced here so future validators get the same scope-prefix shape
/// and the non-Validation passthrough cannot drift between sites.
///
/// `scope` is `&str` so callers may pass either a string literal
/// (`"defaults"`) or a heap-built scope (`format!("runner {:?}",
/// name)`) without an extra allocation when the source is already
/// owned. Callers that own a `String` can pass `&scope`.
///
/// Relies on `Validation` being a `(msg, hint)` tuple variant —
/// several other variants share the same shape (`Config`, `Interactive`,
/// `Preflight`, `GitHub`, `Systemd`, `Auth`) but are intentionally NOT
/// prefixed; the `other => other` arm passes them through unchanged. If
/// `Validation` is ever split or restructured into a struct variant or
/// has its tuple arity changed, this helper must be updated — the
/// `other => other` arm will silently no-op on new shapes (the compiler
/// will only catch the first arm's pattern mismatch, not the semantic
/// regression of failing to prefix).
#[must_use]
pub(crate) fn prepend_validation_scope(scope: &str, err: GharsError) -> GharsError {
    match err {
        GharsError::Validation(msg, hint) => {
            GharsError::Validation(format!("{scope}: {msg}"), hint)
        }
        other => other,
    }
}

/// Depth cap for `format_error_chain` traversal. Defends against
/// pathological cyclic source chains that would otherwise loop
/// forever. 16 layers exceeds any realistic nesting (reqwest →
/// hyper → rustls → io::Error is 4 layers; doubling that again
/// covers any future wrapper additions).
pub(crate) const FORMAT_ERROR_CHAIN_MAX_DEPTH: usize = 16;

/// Walk the `std::error::Error::source()` chain of an arbitrary error
/// and concatenate each layer's Display with ": " separators. The
/// outer Display of types like `std::io::Error` and `reqwest::Error`
/// only formats the outermost layer, so nested causes (e.g.
/// reqwest::Error wrapping hyper::Error wrapping a rustls error, or
/// reqwest::Error wrapping a TLS/DNS error) are dropped if the
/// operator only sees `format!("{err}")`. This helper preserves the
/// full chain so an operator triaging a
/// connection-reset-during-TLS-handshake sees both the outer "request
/// failed" framing and the inner rustls reason code. The depth cap
/// `FORMAT_ERROR_CHAIN_MAX_DEPTH` defends against cyclic source
/// chains.
///
/// Accepts `&dyn std::error::Error` so the same helper covers both
/// the `io::Error` post-decompression path (`read_body_capped` in
/// `github.rs`), the `reqwest::Error` send-failure path, and the
/// `?`-propagation paths in `extract.rs`'s `http_download_with_cap`
/// where `io::Error` is wrapped via `From<io::Error> for GharsError`
/// — `reqwest::Error` is not an `io::Error`, so a separate walker
/// would be required otherwise.
#[must_use]
pub(crate) fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    let mut depth = 0;
    while let Some(cause) = source {
        if depth >= FORMAT_ERROR_CHAIN_MAX_DEPTH {
            break;
        }
        out.push_str(": ");
        out.push_str(&cause.to_string());
        depth += 1;
        source = cause.source();
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! #248: ApplyResult error rendering must not leak build-machine
    //! paths or stack traces. The cli.rs cmd_apply at line 723 prints
    //! `{err}` per failed action — `err: &GharsError` resolves to
    //! Display, NOT Debug. These tests pin the Display contract: only
    //! operator-actionable content (variant tag + free-form message +
    //! optional hint), nothing from rustc, file!/line!, or std
    //! backtrace machinery.
    //!
    //! What we explicitly forbid:
    //! - `src/` path fragments (build-machine source layout);
    //! - `target/` path fragments (build artifacts);
    //! - `at <file>:<line>:<col>` (rust panic / backtrace format);
    //! - `stack backtrace:` markers (env_logger / RUST_BACKTRACE);
    //! - absolute path prefixes `/home/`, `/Users/`, `/root/` (Unix
    //!   home dirs) and `C:\` (Windows) — the operator should never
    //!   see "where the developer's source tree lived";
    //! - `#0`, `#1`, ... frame markers from `std::backtrace::Backtrace`.
    //!
    //! The tests construct each GharsError variant directly (no I/O)
    //! and assert the Display output against a forbidden-fragment set.

    use super::*;

    /// Forbidden substrings that would indicate a leak. Any of these
    /// appearing in Display output is a contract violation.
    ///
    /// `"at /"` is intentionally NOT in this list. The Rust panic
    /// location format uses `at <path>:<line>:<col>` (with a colon
    /// before the line number), which is caught by the
    /// `<path>:<line>:<col>` shape — a benign English use of "at"
    /// before a path is operator-facing meaningful info (e.g.
    /// `apply lock held by PID 12345 at /run/ghars/apply.lock`).
    /// Adding `"at /"` to the forbidden set produces false positives
    /// against every error variant whose Display includes a path
    /// reference, including the SEC-19 ApplyLocked variant whose
    /// hint is the operator's primary signal for stale-lock cleanup.
    const FORBIDDEN: &[&str] = &[
        "src/",    // source path fragment
        "target/", // build-artifact path
        "/home/",  // Unix dev home
        "/Users/", // macOS home
        "/root/",  // root home (developer sometimes `sudo cargo`)
        "C:\\",    // Windows path
        "stack backtrace:",
    ];

    fn assert_clean(label: &str, msg: &str) {
        for f in FORBIDDEN {
            assert!(
                !msg.contains(f),
                "{label}: Display output leaks {f:?}\n  full msg: {msg}",
            );
        }
        // Frame markers `#N` would only appear if std::backtrace is
        // somehow displayed. Check the start-of-line form to avoid
        // false positives on legitimate text containing `#`.
        for line in msg.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#0 ")
                || trimmed.starts_with("#1 ")
                || trimmed.starts_with("#2 ")
            {
                panic!("{label}: backtrace frame marker on line: {line:?}");
            }
        }
    }

    #[test]
    fn config_display_is_clean() {
        let e = GharsError::Config(
            "missing field `name` in [[runner]]".into(),
            "add a `name = ...` key".into(),
        );
        assert_clean("Config", &format!("{e}"));
    }

    #[test]
    fn validation_display_is_clean() {
        let e = GharsError::Validation(
            "runner-name invalid: 'BadName'".into(),
            "use lowercase letters and digits only".into(),
        );
        assert_clean("Validation", &format!("{e}"));
    }

    #[test]
    fn interactive_display_is_clean() {
        let e = GharsError::Interactive(
            "stdin is not a terminal; cannot prompt for confirmation".into(),
            "pass `--auto-approve` for non-interactive use, or run from a TTY".into(),
        );
        let msg = format!("{e}");
        assert_clean("Interactive", &msg);
        // The Display tag must distinguish from Validation so log-shipper
        // grep rules can branch on the operator-actionable cause.
        assert!(
            msg.starts_with("interactive:"),
            "Interactive Display must use the 'interactive:' tag, not 'validation:'; got: {msg}",
        );
    }

    #[test]
    fn preflight_display_is_clean() {
        let e = GharsError::Preflight(
            "systemd 254+ required (found 252)".into(),
            "upgrade or use a newer distro release".into(),
        );
        assert_clean("Preflight", &format!("{e}"));
    }

    #[test]
    fn github_display_is_clean() {
        let e = GharsError::GitHub(
            "API request failed: 404 Not Found".into(),
            "verify the version exists upstream".into(),
        );
        assert_clean("GitHub", &format!("{e}"));
    }

    #[test]
    fn systemd_display_is_clean() {
        let e = GharsError::Systemd(
            "D-Bus method call failed: AccessDenied".into(),
            "run with sudo or check polkit rules".into(),
        );
        assert_clean("Systemd", &format!("{e}"));
    }

    #[test]
    fn auth_display_is_clean() {
        let e = GharsError::Auth(
            "PAT token rejected by GitHub".into(),
            "verify the token has `repo` or `admin:org` scope".into(),
        );
        assert_clean("Auth", &format!("{e}"));
    }

    #[test]
    fn apply_display_is_clean_and_chains() {
        let inner = GharsError::Auth("token mint failed".into(), "check auth config".into());
        let e = GharsError::Apply {
            action: "CreateRunner(buckos)".into(),
            source: Box::new(inner),
        };
        let msg = format!("{e}");
        assert_clean("Apply", &msg);
        // Chains through the source — operator-relevant — but the
        // chain itself (an Auth error here) is itself clean.
        assert!(msg.contains("CreateRunner(buckos)"), "got: {msg}");
    }

    #[test]
    fn io_display_is_clean_for_synthetic_io_error() {
        // A std::io::Error built in Rust source includes only what the
        // caller passes — no path leak unless the caller embedded one.
        let e = GharsError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert_clean("Io", &format!("{e}"));
    }

    #[test]
    fn tarball_display_is_clean() {
        let e = GharsError::Tarball("download failed: HTTP 502".into());
        assert_clean("Tarball", &format!("{e}"));
    }

    #[test]
    fn sha256_mismatch_display_is_clean() {
        // The path field is operator-supplied (the tarball they
        // pointed at), so it's allowed in the message — but it must
        // not be a build-machine src/ or target/ path. Our test feeds
        // an operator-style /var/lib path which clears the forbidden
        // set.
        let e = GharsError::Sha256Mismatch {
            path: "/var/lib/ghars/buckos/runner.tar.gz".into(),
            expected: "a".repeat(64),
            actual: "b".repeat(64),
        };
        assert_clean("Sha256Mismatch", &format!("{e}"));
    }

    #[test]
    fn apply_locked_live_display_is_clean() {
        let e = GharsError::ApplyLocked {
            pid: 12345,
            path: "/run/ghars/apply.lock".into(),
            stale: false,
        };
        let msg = format!("{e}");
        assert_clean("ApplyLocked(live)", &msg);
        // Live branch: hint must say "wait", not "stale".
        assert!(msg.contains("wait"), "got: {msg}");
    }

    #[test]
    fn apply_locked_stale_display_is_clean() {
        let e = GharsError::ApplyLocked {
            pid: 99999,
            path: "/run/ghars/apply.lock".into(),
            stale: true,
        };
        let msg = format!("{e}");
        assert_clean("ApplyLocked(stale)", &msg);
        assert!(msg.contains("stale"), "got: {msg}");
    }

    #[test]
    fn display_does_not_include_debug_field_names() {
        // `format!("{err}")` must use Display, not Debug — Debug would
        // expose struct field names like `Apply { action: ..., source: ... }`
        // which is implementation detail.
        let e = GharsError::Apply {
            action: "Test".into(),
            source: Box::new(GharsError::Validation("x".into(), "y".into())),
        };
        let msg = format!("{e}");
        // Debug would render `Apply {`; Display per thiserror omits.
        assert!(!msg.contains("Apply {"), "got: {msg}");
        assert!(!msg.contains("source:"), "got: {msg}");
    }

    /// Sanity-check: the FORBIDDEN list catches what it's supposed to.
    /// If a future error variant accidentally embeds `concat!(env!("OUT_DIR"), ...)`
    /// or similar, this test demonstrates the assertion would fire.
    #[test]
    fn assert_clean_catches_known_bad_strings() {
        for bad in FORBIDDEN {
            let synthetic = format!("error: something happened {bad}suffix");
            let result = std::panic::catch_unwind(|| assert_clean("synthetic", &synthetic));
            assert!(
                result.is_err(),
                "FORBIDDEN entry {bad:?} did not trigger panic on synthetic input"
            );
        }
    }

    // -------- prepend_validation_scope contract tests --------

    #[test]
    fn prepend_validation_scope_prefixes_validation_msg_and_keeps_hint() {
        let original = GharsError::Validation(
            "value out of range".into(),
            "use a value between 1 and 20".into(),
        );
        let scoped = prepend_validation_scope("runner \"buckos\"", original);
        match scoped {
            GharsError::Validation(msg, hint) => {
                assert_eq!(msg, "runner \"buckos\": value out of range");
                assert_eq!(hint, "use a value between 1 and 20");
            }
            other => panic!("expected Validation after prepend; got: {other:?}"),
        }
    }

    #[test]
    fn prepend_validation_scope_passes_auth_through_unchanged() {
        // Non-Validation variant must pass through bit-identical. Auth is
        // a representative two-string tuple variant that pattern-matches
        // similarly to Validation but is a distinct enum arm.
        let original = GharsError::Auth("PAT token rejected".into(), "verify scope".into());
        let scoped = prepend_validation_scope("runner \"x\"", original);
        match scoped {
            GharsError::Auth(msg, hint) => {
                assert_eq!(msg, "PAT token rejected");
                assert_eq!(hint, "verify scope");
            }
            other => panic!("expected Auth passthrough; got: {other:?}"),
        }
    }

    #[test]
    fn prepend_validation_scope_passes_preflight_through_unchanged() {
        // Preflight is structurally identical to Validation (two strings)
        // but a distinct variant — pinning passthrough here proves the
        // helper does not match by shape, only by variant tag.
        let original = GharsError::Preflight("systemd 254+ required".into(), "upgrade".into());
        let scoped = prepend_validation_scope("defaults", original);
        match scoped {
            GharsError::Preflight(msg, hint) => {
                assert_eq!(msg, "systemd 254+ required");
                assert_eq!(hint, "upgrade");
            }
            other => panic!("expected Preflight passthrough; got: {other:?}"),
        }
    }

    #[test]
    fn prepend_validation_scope_with_empty_scope_emits_colon_space_prefix() {
        // Pin the format-string contract for the empty-scope edge case:
        // `format!("{scope}: {msg}")` with scope="" produces ": msg".
        // This is the documented behavior — empty scope is unusual but
        // not invalid; callers that want unscoped errors should not
        // call this helper at all.
        let original = GharsError::Validation("x".into(), "y".into());
        let scoped = prepend_validation_scope("", original);
        match scoped {
            GharsError::Validation(msg, hint) => {
                assert_eq!(msg, ": x");
                assert_eq!(hint, "y");
            }
            other => panic!("expected Validation after empty-scope prepend; got: {other:?}"),
        }
    }
}
