//! Cross-command CLI helpers. Things that two or more `cmd_*` modules
//! need but that aren't part of any command's primary responsibility.

use crate::state;
use crate::systemd::DbusSystemd;
use crate::{GharsError, Result, paths::Paths};

/// Discover on-disk runner state via systemd D-Bus. On D-Bus failure,
/// emit a single canonical warning to stderr and return an empty
/// `ActualState` so the caller can still render the rest of its output.
/// Use this instead of open-coding `DbusSystemd::new() + state::discover`
/// — three commands (`status`, `metrics`, `logs`) need the same fallback.
pub(super) fn discover_or_warn(paths: &Paths) -> Result<state::ActualState> {
    match DbusSystemd::new() {
        Ok(s) => state::discover(&s, paths),
        Err(err) => {
            eprintln!("warning: systemd D-Bus connection failed: {err}; runner state unavailable.");
            Ok(state::ActualState::default())
        }
    }
}

/// Validate a runner name against the identifier regex with the
/// operator-actionable hint baked in. Centralizes the format!(...)
/// pair so the message stays consistent across `metrics`, `logs`,
/// and any future command that takes a `[--name <NAME>]` argument.
pub(super) fn validate_runner_name_with_hint(name: &str) -> Result<()> {
    crate::validators::validate_runner_name(name).map_err(|e| match e {
        GharsError::Validation(msg, _) => GharsError::Validation(
            format!("invalid runner name {name:?}: {msg}"),
            format!(
                "runner names must use lowercase letters, digits, and dashes; \
                 start with a letter; end with a letter or digit; \
                 and be ≤{} characters",
                crate::config::IDENTIFIER_MAX_LEN,
            ),
        ),
        other => other,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn validate_runner_name_with_hint_accepts_canonical_identifier() {
        validate_runner_name_with_hint("buckos").expect("canonical name must pass");
        validate_runner_name_with_hint("a-1-z").expect("digits + dashes allowed");
    }

    #[test]
    fn validate_runner_name_with_hint_rewrites_message_with_quoted_name() {
        let err = validate_runner_name_with_hint("UPPER").unwrap_err();
        let GharsError::Validation(msg, hint) = err else {
            panic!("expected Validation error, got {err:?}");
        };
        assert!(
            msg.starts_with("invalid runner name \"UPPER\":"),
            "outer message must quote the bad name; got: {msg}"
        );
        assert!(
            hint.contains("lowercase letters, digits, and dashes"),
            "hint must enumerate the legal character classes; got: {hint}"
        );
        assert!(
            hint.contains(&crate::config::IDENTIFIER_MAX_LEN.to_string()),
            "hint must mention the length cap; got: {hint}"
        );
    }

    #[test]
    fn validate_runner_name_with_hint_rejects_empty() {
        validate_runner_name_with_hint("").expect_err("empty name must reject");
    }

    #[test]
    fn validate_runner_name_with_hint_rejects_leading_digit() {
        validate_runner_name_with_hint("1foo").expect_err("leading digit must reject");
    }

    #[test]
    fn validate_runner_name_with_hint_rejects_trailing_dash() {
        validate_runner_name_with_hint("foo-").expect_err("trailing dash must reject");
    }
}
