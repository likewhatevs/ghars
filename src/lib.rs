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
pub(crate) mod http_cap;
pub mod netns;
pub(crate) mod path_util;
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

/// Escape ASCII control characters (C0 + DEL) before terminal emission;
/// preserve printable ASCII and valid UTF-8 multibyte. Returns
/// `Cow::Borrowed` when no escaping is needed. C1 controls
/// (`U+0080..=U+009F`) pass through — they collide with UTF-8
/// continuation bytes and aggressive escaping mangles non-ASCII text.
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
