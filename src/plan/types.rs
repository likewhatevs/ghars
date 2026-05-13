//! Plan output types: the [`Plan`] returned by `plan_from`, the
//! per-action data carriers it owns ([`RunnerPlan`], [`RunnerDelta`],
//! [`CachePoolPlan`], [`CachePoolDelta`], [`RunnerIdentity`]), and the
//! supporting per-field / per-drop-in classification surfaces
//! ([`DriftCause`], [`FieldValue`], [`FieldChange`], [`DropInChange`],
//! [`DropInChangeKind`]).

use std::collections::BTreeMap;

use crate::config::{EffectiveCacheBinding, EffectiveRunnerSpec};
use crate::github::Release;

use super::action::{Action, Disruption};

/// Result of `plan_from`: ordered actions + non-fatal warnings to surface
/// at the CLI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Actions in source-emit order. `apply` re-orders into Part 8's
    /// canonical execution order via `apply::sort_into_phases`:
    /// `CreateCachePool` → `UpdateCachePool` → `RemoveRunner` →
    /// `UpdateRunner` (in-place subset) → `UpdateRunner` (recreate
    /// subset) → `CreateRunner` → `RemoveCachePool` → `NoOp`.
    pub actions: Vec<Action>,
    /// Non-fatal warnings. Currently always empty: `plan_from` has no
    /// producers (the field's reader infrastructure exists in
    /// `cli.rs` for both text and JSON output, but no plan-time site
    /// pushes into this Vec today).
    pub warnings: Vec<String>,
    /// `bin.X.Y.Z/` retention count resolved from
    /// `Defaults.keep_versions` (or the
    /// `crate::config::DEFAULT_KEEP_VERSIONS` fallback when unset).
    /// `apply` threads this into `extract::prune_old_bin_versions` at
    /// the tail of every successful tarball install. Always >= 1.
    pub keep_versions: u32,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            actions: Vec::new(),
            warnings: Vec::new(),
            keep_versions: crate::config::DEFAULT_KEEP_VERSIONS,
        }
    }
}

impl Plan {
    /// True iff this plan contains any action whose
    /// [`Action::disruption`] is [`Disruption::Recreate`]. Drives the
    /// `--detailed-exitcode-recreate` exit-code 8 path.
    ///
    /// Recreate-class actions per [`Action::disruption`]:
    /// `CreateRunner`, `UpdateRunner` with `requires_recreate=true`,
    /// `RemoveRunner`, `CreateCachePool`, and `RemoveCachePool`.
    /// `UpdateCachePool` is always `Disruption::Restart`. Ignores
    /// `Disruption::Restart` (in-place restart) and
    /// `Disruption::None` (`NoOp`).
    ///
    /// Lives on `Plan` rather than as a free function in cli.rs
    /// because the predicate reads only plan data and the disruption
    /// taxonomy is defined in this module — no CLI state is involved.
    /// CLI exit-code helpers wrap this in renderer-side gating.
    #[must_use]
    pub fn has_recreate(&self) -> bool {
        self.actions
            .iter()
            .any(|a| a.disruption() == Disruption::Recreate)
    }
}

/// Data carried by a `CreateRunner` action: the resolved spec, the
/// rendered template + drop-ins, the spec hash, and (when not pinned to
/// `runner_tarball`) the resolved release metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerPlan {
    /// Effective spec after defaults merge + count expansion.
    pub spec: EffectiveRunnerSpec,
    /// Resolved release tuple. `Some` when the runner version was looked
    /// up via the GitHub releases API or pinned but otherwise installable
    /// from a downloadable URL. `None` when `spec.runner_tarball` already
    /// points at a verified local file.
    pub resolved_release: Option<Release>,
    /// Canonical template body (`/etc/systemd/system/ghars-runner@.service`).
    pub effective_unit_text: String,
    /// Drop-in basename → contents.
    pub drop_ins: BTreeMap<String, String>,
    /// Body of `<bin_dir>/.env`. Read once by
    /// `Runner.Listener::LoadAndSetEnv` at runner-process start; each
    /// `KEY=VALUE` is set via `Environment.SetEnvironmentVariable` and
    /// inherited by worker / workflow-step subprocesses through
    /// fork+exec. The next unit stop+start picks up changes.
    pub env_file: String,
    /// Body of `<bin_dir>/.path`. Read once by `runsvc.sh`
    /// (`export PATH=\`cat .path\``) at runner-process start; inherited
    /// across exec by every worker / workflow-step subprocess. The
    /// next unit stop+start picks up changes.
    pub path_file: String,
    /// `sha256:HEX` of the spec; emitted into the 00-ghars.conf
    /// X-Ghars-Spec-Hash annotation.
    pub spec_hash: String,
}

/// What caused an `UpdateRunner` to be emitted. Drives operator-facing
/// rendering — a config edit looks the same on disk as detected drift,
/// but the operator action needed differs (commit the config change vs
/// investigate why the on-disk unit drifted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftCause {
    /// The desired spec hash differs from the discovered annotation.
    /// Operator changed the config; apply will reconverge.
    SpecChanged,
    /// Hash matches but the on-disk unit text or drop-ins were edited
    /// out-of-band (operator hand-edit, package upgrade, tampering).
    /// Apply will overwrite the drift to restore the canonical bytes.
    DriftDetected,
    /// Both: hash mismatch AND on-disk drift. Apply does the same
    /// recreate/in-place rewrite either way; the label tells the
    /// operator both signals fired.
    SpecChangedAndDriftDetected,
}

impl DriftCause {
    /// Stable `snake_case` label for text + JSON rendering. Mirrors the
    /// drift-label vocabulary used by `state::Drift` rendering so a
    /// single `grep spec_changed` finds both surfaces.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::SpecChanged => "spec_changed",
            Self::DriftDetected => "drift_detected",
            Self::SpecChangedAndDriftDetected => "spec_changed_and_drift_detected",
        }
    }
}

/// Typed value for a [`FieldChange`] before/after slot.
///
/// Distinguishes scalar string fields (e.g. `url`, `runner_version`)
/// from list-typed fields (`labels`, `caches`) so JSON consumers can
/// programmatically detect "added gpu label" via set-difference on
/// the after.values vs before.values arrays without re-splitting a
/// pre-stringified comma-joined value.
///
/// JSON shape under `"schema_version": "2"` (tagged):
/// - `String("x")` ⇒ `{"type": "string", "value": "x"}`
/// - `List(["a","b"])` ⇒ `{"type": "list", "values": ["a","b"]}`
///
/// Consumer-side branching on the `type` tag picks the matching
/// payload key (`value` for `string`, `values` for `list`):
///
/// ```text
/// jq:
/// .actions[].field_changes[]?
///   | if .before.type == "string"
///     then .before.value
///     else (.before.values | join(","))
///     end
/// ```
///
/// ```text
/// python:
/// fc = ...  # one .actions[*].field_changes[*] element
/// before = (
///     fc["before"]["value"]
///     if fc["before"]["type"] == "string"
///     else fc["before"]["values"]
/// )
/// ```
///
/// Text rendering preserves the v1 operator-visible format:
/// String → `value`, List → `a,b` (comma-joined), so existing
/// `grep "labels:.*gpu"` operator pipelines keep working.
///
/// No `Number` variant: every current producer in
/// `classify_recreate_reasons_from_annotations` emits either a
/// scalar string (8 paths) or a list of strings (2 paths).
/// Adding `Number` now would be premature — bump schema and add
/// the variant when a numeric field appears. Likely v0.2
/// candidates: `count` (pre-expansion runner count),
/// `keep_versions` (retention prune count). `memory_max` is NOT
/// a candidate — stays `Option<String>` with `bytesize` parsing
/// at validate time, so the wire shape is the existing
/// `String` variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    /// Scalar string. Used for: `url`, `runner_version`, `arch`,
    /// `runner_sha256`, `runner_tarball`, `network`, `auth_name`,
    /// `trust_zone`.
    String(String),
    /// Ordered list of strings. Used for: `labels` (sorted
    /// alphabetically per canonicalization — `merge_defaults`,
    /// `render_identity` defense-in-depth, and parse-time sort in
    /// `DiscoveredAnnotations::from_drop_in_body` all converge on
    /// byte-order ascending), `caches` (sorted by classifier).
    /// Renderers MUST NOT re-sort — display order is canonical at
    /// construction time.
    List(Vec<String>),
}

impl FieldValue {
    /// Comma-joined text rendering. Stable across schema versions
    /// because the v1 → v2 migration is JSON-only — text consumers
    /// (operator grep) see the same surface.
    #[must_use]
    pub fn render_text(&self) -> String {
        match self {
            FieldValue::String(s) => s.clone(),
            FieldValue::List(items) => items.join(","),
        }
    }

    /// Tagged JSON rendering for schema v2.
    ///
    /// This manual constructor IS the wire-format contract — the
    /// shape is NOT serde-derived from the `FieldValue` enum, so
    /// a `#[serde(rename)]` or variant rename would not propagate
    /// here. Any change to the emitted `{"type": ..., "value":
    /// ...}` / `{"type": ..., "values": ...}` keys, the tag
    /// vocabulary, or the per-variant payload field names is
    /// wire-breaking and requires a `schema_version` bump in
    /// `cli::plan_to_json_value`, even when the in-memory enum
    /// shape is preserved.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            FieldValue::String(s) => serde_json::json!({
                "type": "string",
                "value": s,
            }),
            FieldValue::List(items) => serde_json::json!({
                "type": "list",
                "values": items,
            }),
        }
    }
}

/// One field-level change between the discovered runner's annotation-
/// reconstructed before-state and the desired effective spec. Emitted
/// by `classify_recreate_reasons_from_annotations` for every annotation-
/// covered field whose value differs — both recreate-class fields (the
/// emit pushes a matching `recreate_reasons` token) and in-place fields
/// (`auth_name`, `trust_zone`, `caches` — emit without pushing a token
/// so the diff is visible without forcing a recreate). CLI consumers
/// render this as `path: before → after`.
///
/// `path` is a stable static identifier — see [`Self::path`] field
/// doc for the full enumeration. `before` and `after` carry typed
/// values (schema v2) — see [`FieldValue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldChange {
    /// Field path identifier. Stable across releases — operator
    /// scripts can grep on it.
    ///
    /// Flat tokens for schema v2 (the value the JSON renderer
    /// emits under `"schema_version": "2"`):
    /// - Recreate-class (apply does remove → create): `url`,
    ///   `runner_version`, `labels`, `arch`, `runner_sha256`,
    ///   `runner_tarball`, `network`.
    /// - In-place (apply rewrites the per-runner drop-in body and
    ///   cycles the unit, no remove → create): `auth_name`,
    ///   `trust_zone`, `caches`.
    ///
    /// The flat-token list mixes both classes; presence of a
    /// `FieldChange` does NOT imply `requires_recreate=true` — read
    /// `RunnerDelta.recreate_reasons` for that signal.
    ///
    /// Dotted notation (e.g. `network.mode`, `hardening.kvm`,
    /// `network.allowed_egress`) is reserved for future schema
    /// versions; bumping `schema_version` is the migration path
    /// so existing consumers' grep-on-flat-token gates do not
    /// silently match nested paths.
    pub path: &'static str,
    /// Typed before-value, parsed from the discovered unit's
    /// `X-Ghars-*` annotation. List variants carry the items in
    /// the order the classifier read them — both `caches` and
    /// `labels` are sorted alphabetically (renderer emits sorted,
    /// parser preserves on-disk order; the parse-time sort in
    /// `DiscoveredAnnotations::from_drop_in_body` keeps the
    /// invariant when the on-disk bytes were ever non-canonical).
    pub before: FieldValue,
    /// Typed after-value from the desired effective spec. Same
    /// ordering contract as `before`.
    pub after: FieldValue,
}

/// Per-drop-in change classification on the in-place update path.
/// Populated by Stage 2 of plan classification (drop-in body diff).
///
/// "Modified" carries before/after bodies for diff display; "Created"
/// and "Removed" carry only the side that exists. The CLI renderer
/// uses the variant tag to pick the sigil (+/-/~).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropInChangeKind {
    /// Drop-in present in desired render, absent on disk.
    Created {
        /// Body that will be written.
        after: String,
    },
    /// Drop-in present on both sides, body bytes differ.
    Modified {
        /// Body found on disk.
        before: String,
        /// Body that will be written.
        after: String,
    },
    /// Drop-in absent from desired render, present on disk.
    /// Operator-edited or remnant from a prior config that referenced
    /// a now-removed field family (e.g. `memory_max` set then unset).
    Removed {
        /// Body found on disk that will be deleted.
        before: String,
    },
    /// Drop-in present and identical on both sides; reported as part
    /// of the audit trail so operators can confirm the "no edit"
    /// status when reading plan output, even though apply skips the
    /// write.
    Preserved,
}

/// One drop-in's classification + body content. Aggregated into
/// `RunnerDelta::drop_in_changes` for in-place updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropInChange {
    /// Drop-in basename (e.g. `10-memory.conf`). Sorted by basename
    /// in the surrounding Vec for determinism.
    pub basename: String,
    /// What kind of change this is and the relevant body content.
    pub change: DropInChangeKind,
}

/// Data carried by an `UpdateRunner` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerDelta {
    /// Identity of the runner being updated.
    pub identity: RunnerIdentity,
    /// Fully-rendered post-update plan. `apply` consumes this for the
    /// in-place rewrite branch and the recreate branch alike.
    pub after: RunnerPlan,
    /// True when the change touches an identity-bound field
    /// (`url`/`labels`/`runner_version`/`runner_sha256`/
    /// `runner_tarball`/`arch`/`network`); apply must do
    /// remove → create. False ⇒ in-place rewrite + daemon-reload.
    pub requires_recreate: bool,
    /// Human-readable reasons to surface on the CLI (only meaningful when
    /// `requires_recreate` is true). Each entry names the field whose
    /// change triggered the recreate decision; CLI consumers display
    /// them verbatim.
    ///
    /// These are raw classifier tokens. Field-name tokens (`url`,
    /// `labels`, `arch`, …) render verbatim because the corresponding
    /// `FieldChange` row already shows the before→after pair on the
    /// preceding line; the `uncovered` non-field token is glossed for
    /// operator display by `cli::recreate_reason_note` — keep that
    /// match arm in lockstep with the vocabulary below.
    ///
    /// Vocabulary (every string this Vec may contain):
    /// - `"url"` — runner URL changed (registration is URL-bound).
    /// - `"runner_version"` — release version changed.
    /// - `"labels"` — registration label set changed.
    /// - `"arch"` — binary architecture changed.
    /// - `"runner_sha256"` — operator-pinned tarball digest changed.
    /// - `"runner_tarball"` — operator-supplied tarball path changed
    ///   (detected via SHA256 of the path string).
    /// - `"network"` — `NetworkMode` toggled between Open and Netns
    ///   (provision/teardown of netns side-units only run on the
    ///   recreate path).
    /// - `"uncovered"` — conservative fallback for hash-mismatch with
    ///   no Stage 1 reason and no Stage 2 drop-in diff (should be
    ///   unreachable in practice; logs at warn level).
    pub recreate_reasons: Vec<&'static str>,
    /// Why this update was emitted: `SpecChanged` (config edit),
    /// `DriftDetected` (on-disk drift only), or both. Drives the CLI
    /// renderer's drift-cause label so the operator can tell the two
    /// apart at a glance.
    pub drift_cause: DriftCause,
    /// Per-field before→after diff for fields the Stage 1 annotation
    /// classifier detected. CLI renderer prints one line per entry.
    ///
    /// Populated for both recreate-class diffs (e.g. `url`,
    /// `runner_version`, `labels`, `arch`, `runner_sha256`,
    /// `runner_tarball`, `network`) and in-place diffs that have
    /// an annotation source (`auth_name`, `trust_zone`, `caches` —
    /// the apply-time reconciliation rewrites the per-runner drop-in
    /// body and cycles the unit, not remove → create). The presence
    /// of a `FieldChange` does NOT imply `requires_recreate=true`;
    /// check `recreate_reasons` for that.
    ///
    /// Empty when:
    /// - the recreate fired via the `"uncovered"` fallback (no
    ///   annotation source for the before-value), or
    /// - the change was confined to drop-in body deltas with no
    ///   annotation-classified field touched (those land in
    ///   `drop_in_changes` instead).
    pub field_changes: Vec<FieldChange>,
    /// Per-drop-in classification for in-place updates. Sorted by
    /// basename. Empty when `requires_recreate` is true (the recreate
    /// path drops + recreates all drop-ins atomically; field-level
    /// drop-in diff is meaningless there).
    pub drop_in_changes: Vec<DropInChange>,
    /// Pre-update cache pool list reconstructed from the discovered
    /// `X-Ghars-Caches` annotation. Drives apply.rs's in-place
    /// drop-in reconciliation: apply diffs this against
    /// `delta.after.spec.caches` to surface added / removed pool
    /// names in the per-action `ApplyOutcome::InPlaceRestarted`
    /// detail string, and the rendered 30-cache-pool.conf drop-in
    /// reflects the new pool list verbatim (cache reach is
    /// materialized by the trust_zone-shared `DynamicUser` + the
    /// `BindPaths=` entries in the drop-in). `None` ⇒ the runner
    /// predates the unconditional `X-Ghars-Caches` emit; apply skips
    /// the diff rendering to avoid spurious "removed: …" messages
    /// (the next apply will land annotations and a future change
    /// can show the proper diff).
    ///
    /// Order: when `Some`, the Vec is sorted alphabetically.
    /// `plan_from` sorts the discovered annotation at population time
    /// so operator-facing surfaces (--diff output, plan JSON
    /// serialization, error messages that name "removed pools") see a
    /// canonical order regardless of the order the on-disk
    /// `X-Ghars-Caches=` annotation happened to be written in.
    pub before_caches: Option<Vec<String>>,
    /// Pre-update on-disk drop-in basenames discovered in the runner's
    /// drop-in directory (alphabetically ordered, parity with
    /// [`Self::before_caches`]). Drives the recreate-class `--diff`
    /// path in cli.rs: under `--diff`, recreate-class `UpdateRunner`
    /// emits a `Removed` line for every basename in this Vec that is
    /// NOT present in `after.drop_ins`, so the operator sees their
    /// `99-custom.conf` (or any other unmanaged drop-in) is being
    /// deleted by the recreate rather than vanishing silently.
    ///
    /// Value semantics:
    /// - `Some(vec![..])` ⇒ discovered state was available at plan
    ///   time; the Vec is an exact snapshot of the on-disk drop-in
    ///   basenames (`BTreeMap` iteration order ⇒ already sorted).
    ///   Renderers MAY use this directly to compute the
    ///   "removed by recreate" set.
    /// - `Some(vec![])` ⇒ the discovered drop-in directory was
    ///   present but empty. Distinct from `None` — renderers can
    ///   confidently emit "no removed drop-ins".
    /// - `None` ⇒ no discovered state available (test fixtures, or
    ///   any future construction site that doesn't have a
    ///   `DiscoveredRunner` in scope).
    ///   Renderers must NOT treat `None` as "no removed drop-ins" —
    ///   it means "unknown", and they should suppress the Removed
    ///   section entirely rather than risk a misleading silence.
    ///
    /// Body content is intentionally NOT carried (basenames only).
    /// The recreate-class `--diff` rendering of Removed entries is
    /// basename-only — bodies would be redundant ("rm PATH" doesn't
    /// need the file content) and would re-introduce the credential
    /// leakage surface for any drop-in that embedded `Environment=`
    /// lines (e.g. `60-proxy.conf` with an authenticated proxy URL).
    /// The basename alone is the
    /// operator-actionable signal: they recognize their custom
    /// drop-in by name and decide whether to migrate the contents
    /// before applying.
    pub before_drop_in_basenames: Option<Vec<String>>,
}

/// Identity of a runner — the minimum surface `apply` needs to remove or
/// reference an existing runner. `apply` looks up the rendered spec via
/// state discovery for removals; the identity carries everything required
/// to drive systemd D-Bus calls (`ghars-runner@NAME.service`),
/// home-directory rmrf safety checks (name + `trust_zone`), and
/// registration-token mints (`url` + `auth_name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerIdentity {
    /// Final runner name (post count-expansion).
    pub name: String,
    /// Repo / org URL (drives token mint).
    pub url: String,
    /// Auth registry key.
    pub auth_name: String,
    /// Trust zone — drives the per-runner home location under
    /// `<state_dir>/<trust_zone>/ghars-<name>/`.
    pub trust_zone: String,
}

/// Data carried by a `CreateCachePool` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePoolPlan {
    /// Resolved pool binding (name + kinds + size + mode + `trust_zone`).
    pub binding: EffectiveCacheBinding,
    /// Rendered `ghars-cache@POOL.service.d/00-ghars.conf` body. Built
    /// at plan time by `systemd::render_cache_drop_in` so the
    /// reset-on-empty validator runs before the bytes leave the planner.
    pub drop_in_body: String,
    /// `sha256:HEX` of the pool config; annotated into the drop-in.
    pub spec_hash: String,
}

/// Data carried by an `UpdateCachePool` action. Same shape as
/// `CachePoolPlan` (the drop-in is regenerated, the unit name is
/// stable); kept distinct so `apply` can branch cleanly on creation vs
/// update without inspecting actual state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePoolDelta {
    /// Resolved pool binding for the post-update state.
    pub binding: EffectiveCacheBinding,
    /// Regenerated `00-ghars.conf` body.
    pub drop_in_body: String,
    /// Spec hash of the post-update binding.
    pub spec_hash: String,
}
