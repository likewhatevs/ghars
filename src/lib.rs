//! ghars: declaratively manage self-hosted GitHub Actions runners on
//! systemd-based Linux hosts.
//!
//! Public surface re-exports the load-bearing types from each submodule.
//! See the design spec, Part 2 (module layout) and Part 3 (core types).

use std::borrow::Cow;

pub mod apply;
pub mod auth;
pub mod cli;
pub mod config;
pub mod error;
pub mod extract;
pub mod github;
pub mod netns;
pub mod paths;
pub mod plan;
pub mod preflight;
pub mod state;
pub mod systemd;
pub mod unit_verify;
pub mod validators;

pub use error::{GharsError, Result};
pub use paths::Paths;

/// Crate-wide HTTP User-Agent for outbound requests (GitHub API,
/// tarball download, etc.). Versioned form `ghars/<crate-version>` per
/// GitHub's API guidance. Centralized here so github.rs and
/// extract.rs can't drift.
pub const USER_AGENT: &str = concat!("ghars/", env!("CARGO_PKG_VERSION"));

/// Defense-in-depth: escape ASCII control characters (C0 + DEL) before
/// terminal emission. Preserves printable ASCII and valid UTF-8
/// multibyte. Returns `Cow::Borrowed` when no escaping needed.
///
/// Identifies escape candidates via `char::is_ascii_control()` — true
/// for `0x00..=0x1f` (C0) and `0x7f` (DEL). Each control char is
/// rewritten via `char::escape_default()`, which produces `\n`/`\r`/
/// `\t` for the three named ones and `\u{NN}` for the rest (NUL
/// emits `\u{0}`, ESC `\u{1b}`, DEL `\u{7f}`, etc.). All output is
/// printable ASCII; no terminal escape sequence survives.
///
/// Bytes `>= 0x80` (the start of every multibyte UTF-8 sequence) pass
/// through unchanged. This preserves i18n filenames (Cyrillic, Han,
/// emoji) at the cost of leaving the C1 control range
/// (`U+0080..=U+009F`) unescaped — those codepoints are valid UTF-8
/// continuation bytes inside multibyte sequences and aggressive
/// escaping would mangle non-ASCII strings.
///
/// Used by:
/// - `apply::ApplyOutcome::Failed.error_summary` construction at apply
///   time (defends downstream `cmd_apply` stderr emission against
///   ANSI-escape-laden `GharsError::to_string()` output);
/// - `apply::UndoStep::describe` when formatting per-variant path /
///   name / url fields (defends every consumer of the rollback log,
///   not just the cli.rs advisory render path);
/// - `cli::render_rollback_advisory` interpolates two operator-
///   supplied fields per failure entry; both are escaped before
///   stderr emission:
///   - **per-failure label** (`Action::label()` keys of
///     `result.failed_undo_logs`) — escaped at the per-failure
///     sub-block emission inside `render_rollback_advisory` via
///     `escape_control_chars(label)`. Defense-in-depth —
///     `IDENTIFIER_REGEX` rejects control chars at config-load, but
///     a regex relaxation must not silently reintroduce ANSI hijack
///     risk on the rollback advisory.
///   - **per-step `describe()` output** — second pass over
///     `UndoStep::describe()`'s already-escaped output. Idempotent
///     (pinned by `escape_control_chars_is_idempotent` in lib.rs),
///     so the redundancy costs only one byte scan; closes the seam
///     if a future `describe()` arm forgets the per-field escape.
/// - `cli::render_action_line` and `cli::plan_to_json_value` when
///   emitting drop-in basenames (defends against on-disk filesystem
///   entries that bypassed config-load validation). Two distinct call
///   site classes share this defense:
///   - **recreate path**: iterates
///     `RunnerDelta::before_drop_in_basenames` (text in
///     `render_action_line`, JSON inline inside `plan_to_json_value`).
///   - **in-place path**: iterates `RunnerDelta::drop_in_changes`,
///     where each `DropInChange::basename` is escaped — text in
///     `render_action_line` and JSON inside `drop_in_change_to_json`
///     (the helper called from the in-place mapper inside
///     `plan_to_json_value`).
/// - `cli::push_indented_body` and `cli::push_indented_unified_diff`
///   when emitting drop-in body content under `--diff`. The
///   `Created.after`, `Removed.before`, and `Modified.{before,after}`
///   bytes originate from operator-authored drop-in files (or on-disk
///   discovery). Each line passes through `escape_control_chars`
///   before emission — so the 12-space indent prefix and the
///   intentional `\x1b[32m` / `\x1b[31m` / `\x1b[0m` ANSI wraps
///   (only the unified-diff path emits these, and only with color
///   enabled) survive structurally while hostile body bytes are
///   replaced with the printable `\u{NN}` form. The escape happens
///   on the line CONTENT before any color wrapping, so the
///   `+`/`-`/`@` sigil-detection branches still match.
///
/// Fast path: scans bytes (not chars) — `is_ascii_control` is a
/// byte-level test and the scan terminates at the first hit, so clean
/// ASCII / clean UTF-8 inputs return `Cow::Borrowed` with one O(n)
/// linear scan and no allocation. Inputs containing at least one
/// control byte allocate once (`String::with_capacity(s.len())`) and
/// pay one additional O(n) char-iter pass to build the escaped form.
#[must_use]
pub(crate) fn escape_control_chars(s: &str) -> Cow<'_, str> {
    if !s.bytes().any(|b| b.is_ascii_control()) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_control() {
            for esc in c.escape_default() {
                out.push(esc);
            }
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn escape_control_chars_passes_clean_ascii_unchanged_as_borrowed() {
        let s = "fail: CreateRunner(buckos): systemd: Manager.StartUnit failed";
        let out = escape_control_chars(s);
        assert!(
            matches!(out, Cow::Borrowed(_)),
            "clean input must be Borrowed"
        );
        assert_eq!(out, s);
    }

    #[test]
    fn escape_control_chars_escapes_ansi_escape() {
        // ESC `\x1b` is `is_ascii_control()` ⇒ escape via
        // char::escape_default which emits `\u{1b}` for non-named
        // controls (fall-through to `\u{NN}` form).
        let s = "\x1b[31mhostile\x1b[0m";
        let out = escape_control_chars(s);
        assert!(matches!(out, Cow::Owned(_)), "must allocate when escaping");
        // `\x1b` byte must be gone from the output.
        assert!(!out.contains('\x1b'), "ESC byte must be escaped: {out:?}");
        // Printable text passes through.
        assert!(out.contains("hostile"), "got: {out:?}");
    }

    #[test]
    fn escape_control_chars_escapes_newline() {
        let out = escape_control_chars("a\nb");
        assert!(matches!(out, Cow::Owned(_)));
        assert!(!out.contains('\n'), "raw newline must not survive: {out:?}");
        // char::escape_default('\n') is `\n` (literal backslash + n).
        assert!(out.contains("\\n"), "got: {out:?}");
    }

    #[test]
    fn escape_control_chars_escapes_carriage_return() {
        let out = escape_control_chars("a\rb");
        assert!(matches!(out, Cow::Owned(_)));
        assert!(!out.contains('\r'), "raw CR must not survive: {out:?}");
        assert!(out.contains("\\r"), "got: {out:?}");
    }

    #[test]
    fn escape_control_chars_escapes_nul() {
        // NUL is NOT one of `char::escape_default`'s short-form names
        // (only `\n`, `\r`, `\t`, `\\`, `\'`, `\"` are). NUL goes
        // through the generic Unicode-escape branch and emits
        // `\u{0}` (literal backslash, u, brace, 0, brace) — a 6-char
        // string the test checks for as a substring.
        let out = escape_control_chars("a\0b");
        assert!(matches!(out, Cow::Owned(_)));
        assert!(!out.contains('\0'), "raw NUL must not survive: {out:?}");
        assert!(out.contains("\\u{0}"), "got: {out:?}");
    }

    #[test]
    fn escape_control_chars_escapes_tab() {
        let out = escape_control_chars("a\tb");
        assert!(matches!(out, Cow::Owned(_)));
        assert!(!out.contains('\t'), "raw TAB must not survive: {out:?}");
        assert!(out.contains("\\t"), "got: {out:?}");
    }

    #[test]
    fn escape_control_chars_escapes_del() {
        // DEL is `0x7f`, classified as `is_ascii_control()` despite
        // being above the C0 range. char::escape_default emits the
        // `\u{7f}` form for non-named controls.
        let out = escape_control_chars("a\x7fb");
        assert!(matches!(out, Cow::Owned(_)));
        assert!(!out.contains('\x7f'), "raw DEL must not survive: {out:?}");
    }

    #[test]
    fn escape_control_chars_preserves_utf8_multibyte() {
        // Cyrillic (Файл) + emoji (👍 = U+1F44D, 4-byte UTF-8) — none
        // are `is_ascii_control()`, all pass through. Borrowed.
        let s = "Файл-test \u{1F44D}";
        let out = escape_control_chars(s);
        assert!(
            matches!(out, Cow::Borrowed(_)),
            "non-ASCII must be Borrowed"
        );
        assert_eq!(out, s);
    }

    #[test]
    fn escape_control_chars_handles_empty_input() {
        let out = escape_control_chars("");
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, "");
    }

    #[test]
    fn escape_control_chars_preserves_c1_unicode_codepoints() {
        // U+009B (CSI) is a C1 control. We deliberately do NOT escape
        // C1 because they are valid UTF-8 continuation bytes inside
        // multibyte sequences and `is_ascii_control()` returns false
        // for them. Pin the contract so a future regression to a
        // broader `is_control()` check is caught.
        let s = "before\u{009B}after";
        let out = escape_control_chars(s);
        assert!(
            matches!(out, Cow::Borrowed(_)),
            "C1 codepoint must not trigger escaping"
        );
        assert_eq!(out, s);
    }

    #[test]
    fn escape_control_chars_handles_all_c0_input() {
        // Pure C0 input — every char gets escaped.
        let s = "\x01\x02\x03\x07\x08\x0B\x0C";
        let out = escape_control_chars(s);
        assert!(matches!(out, Cow::Owned(_)));
        // Every char in the original was C0; the output must contain
        // none of them as raw bytes. Each is emitted via
        // char::escape_default.
        for c in s.chars() {
            assert!(!out.contains(c), "raw {c:?} must not survive: {out:?}");
        }
    }

    /// Pin the second-pass-Borrowed property that follows from
    /// the helper's escape vocabulary. Several call sites re-feed
    /// already-escaped output through `escape_control_chars` as
    /// defense-in-depth (e.g. `cli::render_rollback_advisory`
    /// re-escapes `UndoStep::describe()` output even though
    /// `describe()` itself runs the helper at every interpolation
    /// site). For that layered defense to cost only a byte scan, the
    /// second pass must (i) return `Cow::Borrowed` (no allocation)
    /// and (ii) produce a bytewise-equal result.
    ///
    /// Why it holds: the first pass replaces every C0/DEL byte with
    /// a `char::escape_default` sequence — backslash + ASCII letter
    /// (`\n`/`\r`/`\t`) or backslash + `u{NN}`. Both forms are pure
    /// printable ASCII (no byte ≥ 0x80, no byte `is_ascii_control()`),
    /// so the byte-scan in the helper short-circuits on
    /// `!s.bytes().any(|b| b.is_ascii_control())` and returns
    /// `Cow::Borrowed`.
    ///
    /// Scope: this catches *vocabulary-change regressions* — e.g. a
    /// future swap to a non-printable escape form like `^[` (which
    /// embeds raw ESC) or `\e` (a non-`escape_default` form that
    /// some renderers use). It is NOT a general "idempotent under
    /// arbitrary inputs" pin; the helper has no logic for
    /// already-escaped strings beyond the byte-scan short-circuit,
    /// so anything that breaks that short-circuit is what this test
    /// detects. Mixed payload exercises three short-form vocabulary
    /// paths in a single pass (ESC → `\u{1b}` brace form, NUL →
    /// `\u{0}` brace form, newline → `\n` short form).
    #[test]
    fn escape_control_chars_is_idempotent() {
        let hostile = "a\x1b[31mb\0c\nd";
        let first = escape_control_chars(hostile).into_owned();
        // Sanity: the first pass actually escaped the input — ESC/NUL/
        // newline all gone, char::escape_default forms present.
        assert!(
            !first.contains('\x1b') && !first.contains('\0') && !first.contains('\n'),
            "first pass must remove all C0 control bytes; got: {first:?}"
        );
        // Second pass on already-escaped output. Must be Borrowed
        // (no allocation) and byte-equal to the first-pass result —
        // proves the layered defense inside `render_rollback_advisory`
        // (and other call sites that escape already-escaped describe()
        // output) costs zero beyond the `bytes().any(is_ascii_control)`
        // scan.
        let second = escape_control_chars(&first);
        assert!(
            matches!(second, Cow::Borrowed(_)),
            "second pass on already-escaped string must return Cow::Borrowed; got Owned"
        );
        assert_eq!(
            second, first,
            "second pass must equal first pass byte-for-byte; got second={second:?} first={first:?}"
        );
    }
}
