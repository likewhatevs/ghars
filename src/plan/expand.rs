//! Pre-plan flattening of `[[runner]]` entries with `count > 1` into
//! one `RunnerSpec` per generated name (Part 8 "Count expansion").

use std::collections::{HashMap, HashSet};

use crate::Result;
use crate::config::{Config, RunnerSpec};
use crate::error::GharsError;

/// Maximum value of `RunnerSpec.count` accepted by the expander —
/// per-`[[runner]]`-block sanity cap on the auto-generated
/// `name-1, name-2, ..., name-N` instances. Operator can split
/// across multiple blocks to exceed this per-block cap. Decoupled
/// from netns capacity: netns mode is gated separately by
/// [`super::NETNS_POOL_SLOTS`] (64 /30 slots in the default
/// `10.200.0.0/24` pool); the operator hits whichever cap binds
/// first for their config (Part 4 schema rules).
pub const MAX_COUNT: u32 = 1024;

/// Expand `[[runner]]` entries with `count > 1` into one `RunnerSpec`
/// per generated name (Part 8 "Count expansion").
///
/// Algorithm:
/// 1. Collect explicit names (entries with `count` unset, `Some(0)`,
///    or `Some(1)`) into a set.
/// 2. Walk the source order. For each entry:
///    - Explicit ⇒ pass through with `count = None`.
///    - `count = Some(0)` ⇒ skip (zero runners).
///    - `count = Some(n) where n > 1` ⇒ emit `name-1` .. `name-n`,
///      auto-skipping any index whose name matches an explicit, and
///      rejecting cross-block name collisions.
///
/// `count = Some(1)` is treated as an explicit (no expansion, name
/// kept as-is). The output preserves source order: count-block
/// expansions appear in the position the count block was declared,
/// and explicit blocks land in their own source positions.
///
/// # Errors
///
/// Returns `GharsError::Validation` on:
/// - generated name fails identifier regex / length validation;
/// - count > [`MAX_COUNT`];
/// - two count-blocks generate the same name (cross-block collision).
pub fn expand_counts(config: &Config) -> Result<Vec<RunnerSpec>> {
    let explicit_names: HashSet<&str> = config
        .runners
        .iter()
        .filter(|r| !is_count_block(r))
        .map(|r| r.name.as_str())
        .collect();

    let mut expanded: Vec<RunnerSpec> = Vec::with_capacity(config.runners.len());
    // Owners of each generated name → the parent block's prefix. Used
    // to surface both source positions on collision.
    let mut from_counts: HashMap<String, String> = HashMap::new();

    for spec in &config.runners {
        if !is_count_block(spec) {
            // Explicit, count = Some(1), or count = Some(0). Treat
            // count = Some(0) as a no-op (skip); pass count = Some(1)
            // and count = None through with name kept as-is.
            if matches!(spec.count, Some(0)) {
                continue;
            }
            let mut clone = spec.clone();
            clone.count = None;
            expanded.push(clone);
            continue;
        }

        let count = spec.count.unwrap_or(1);
        if count > MAX_COUNT {
            return Err(GharsError::Validation(
                format!(
                    "runner '{}' count = {count} exceeds MAX_COUNT = {MAX_COUNT}",
                    spec.name
                ),
                format!("split into multiple [[runner]] blocks or reduce count to ≤ {MAX_COUNT}"),
            ));
        }

        for i in 1..=count {
            let name = format!("{}-{i}", spec.name);
            validate_generated_identifier(&name, &spec.name)?;
            if explicit_names.contains(name.as_str()) {
                // Auto-skip — the explicit block "wins".
                continue;
            }
            if let Some(existing_prefix) = from_counts.get(&name) {
                return Err(GharsError::Validation(
                    format!(
                        "count expansion collision: '{name}' produced by both \
                         '{existing_prefix}' and '{}'",
                        spec.name
                    ),
                    "two count-blocks generated the same runner name; declare \
                     them as separate explicit [[runner]] blocks instead"
                        .into(),
                ));
            }
            from_counts.insert(name.clone(), spec.name.clone());

            let mut child = spec.clone();
            child.name = name;
            child.count = None;
            expanded.push(child);
        }
    }

    Ok(expanded)
}

pub(super) fn is_count_block(spec: &RunnerSpec) -> bool {
    matches!(spec.count, Some(n) if n > 1)
}

fn validate_generated_identifier(name: &str, parent_prefix: &str) -> Result<()> {
    crate::validators::validate_identifier(name).map_err(|e| match e {
        GharsError::Validation(msg, _) => GharsError::Validation(
            format!(
                "count expansion: generated name '{name}' from prefix \
                 '{parent_prefix}' fails identifier validation: {msg}"
            ),
            format!(
                "shorten prefix '{parent_prefix}' so the longest generated \
                 name (prefix-COUNT) fits identifier rules"
            ),
        ),
        other => other,
    })
}

