//! Plan computation: diff desired config against discovered actual state
//! and emit an ordered list of `Action`s.
//!
//! Design spec: Part 3 (`plan.rs`) + Part 8 (plan/apply engine).
//!
//! This module owns four orthogonal pieces:
//!
//! 1. [`expand_counts`] — pre-plan flattening of `[[runner]]` entries
//!    with `count > 1` into one `RunnerSpec` per generated name. Auto-
//!    skips collisions with explicit `[[runner]]` blocks; errors on
//!    cross-block overlap (Part 8 "Count expansion", F76 amended).
//! 2. [`merge_defaults`] — produces an [`EffectiveRunnerSpec`] from a
//!    `RunnerSpec` + `Defaults` per the Part 3 merge table (scalars
//!    override, labels concatenate-and-dedup, hardening field-by-field).
//! 3. [`spec_hash`] — canonical-JSON sha256 of an
//!    [`EffectiveRunnerSpec`] (Part 3 spec-hash, F17).
//! 4. [`plan_from`] — diff desired effective specs against
//!    [`ActualState`] and emit ordered [`Action`]s applying the
//!    `requires_recreate` policy (Part 3).
//!
//! Per Part 8, `apply::sort_into_phases` re-orders the emitted actions
//! into the canonical execution order (CreateCachePool → UpdateCachePool
//! → RemoveRunner → UpdateRunner-inplace → UpdateRunner-recreate →
//! CreateRunner → RemoveCachePool → NoOp). plan_from itself emits in
//! alphabetical name order — apply owns phase ordering, plan owns
//! per-name determinism.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use camino::{Utf8Path, Utf8PathBuf};

use crate::Result;
use crate::config::{
    Arch, CachePoolSpec, Config, Defaults, EffectiveCacheBinding, EffectiveNetworkBinding,
    EffectiveRunnerSpec, Hardening, NetworkMode, RunnerSpec,
};
use crate::error::GharsError;
use crate::github::Release;
use crate::paths::Paths;
use crate::state::{ActualState, DiscoveredRunner, Drift, extract_x_ghars};

/// Default state-dir prefix when neither runner nor defaults pin one
/// (matches `Paths::default().state_dir`).
const DEFAULT_PREFIX: &str = "/var/lib/ghars";

/// Default trust zone — keeps the merge in lock-step with config.rs's
/// `default_trust_zone` (SEC-03).
const DEFAULT_TRUST_ZONE: &str = "default";

/// First octet of the default netns subnet pool. The full pool is
/// `NETNS_POOL_BASE.0.0/24` — i.e. `10.200.0.0/24` — yielding 64 /30
/// slots (Part 9c "IP allocation"). v0.1 hardcodes this; making it
/// configurable via `[defaults] netns_subnet` is design future scope.
const NETNS_POOL_BASE: [u8; 4] = [10, 200, 0, 0];

/// Number of /30 slots in the default `/24` pool.
const NETNS_POOL_SLOTS: usize = 64;

/// Compute the /30 subnet for the given slot index in the
/// `10.200.0.0/24` pool. Slot 0 → `10.200.0.0/30`, slot 1 →
/// `10.200.0.4/30`, ..., slot 63 → `10.200.0.252/30`.
///
/// # Errors
///
/// Returns `GharsError::Validation` when `slot_idx >= NETNS_POOL_SLOTS`,
/// which means the operator has more netns runners than the v0.1
/// hardcoded /24 pool can accommodate. The error names the runner
/// hitting the cap so the operator can identify which entry to move.
fn netns_subnet_for_slot(slot_idx: usize, runner_name: &str) -> Result<ipnet::IpNet> {
    if slot_idx >= NETNS_POOL_SLOTS {
        return Err(GharsError::Validation(
            format!(
                "netns subnet pool 10.200.0.0/24 exhausted: runner '{runner_name}' \
                 needs slot {slot_idx} but only {NETNS_POOL_SLOTS} /30 slots fit"
            ),
            "reduce the number of netns runners (max 64 in v0.1) or split across hosts".into(),
        ));
    }
    let offset = (slot_idx as u32) * 4;
    let base = u32::from(std::net::Ipv4Addr::new(
        NETNS_POOL_BASE[0],
        NETNS_POOL_BASE[1],
        NETNS_POOL_BASE[2],
        NETNS_POOL_BASE[3],
    ));
    let net = std::net::Ipv4Addr::from(base + offset);
    let net = ipnet::Ipv4Net::new(net, 30).map_err(|e| {
        GharsError::Validation(
            format!("netns subnet construction failed for slot {slot_idx}: {e}"),
            "this is a ghars bug; please report".into(),
        )
    })?;
    Ok(ipnet::IpNet::V4(net))
}

/// Maximum value of `RunnerSpec.count` accepted by the expander —
/// per-`[[runner]]`-block sanity cap on the auto-generated
/// `name-1, name-2, ..., name-N` instances. Operator can split
/// across multiple blocks to exceed this per-block cap. Decoupled
/// from netns capacity: netns mode is gated separately by
/// [`NETNS_POOL_SLOTS`] (64 /30 slots in the default
/// `10.200.0.0/24` pool); the operator hits whichever cap binds
/// first for their config (Part 4 schema rules, F76 amended).
pub const MAX_COUNT: u32 = 1024;

/// One scheduled action in a `Plan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Create a new runner from scratch (registration + systemd unit + start).
    CreateRunner(RunnerPlan),
    /// Update an existing runner. The delta carries `requires_recreate` so
    /// `apply` knows whether to rewrite drop-ins in place or stop+remove+
    /// create.
    UpdateRunner(RunnerDelta),
    /// Stop + unregister + remove a runner.
    RemoveRunner(RunnerIdentity),
    /// Create a new cache pool (writes ghars-cache@POOL.service).
    CreateCachePool(CachePoolPlan),
    /// Update an existing cache pool (size, kinds, mode).
    UpdateCachePool(CachePoolDelta),
    /// Remove a cache pool unit + storage.
    RemoveCachePool(String),
    /// Nothing to do; carries a human-readable reason.
    NoOp(String),
}

/// Worst-case operational disruption an [`Action`] inflicts on a
/// running runner or cache pool when applied. Computed at plan time
/// so operators reading `ghars plan` can see the blast radius before
/// they approve.
///
/// "Worst-case" because plan time cannot know whether `apply` will
/// short-circuit at apply time. `execute_update_runner`'s in-place
/// path (apply.rs) skips daemon-reload + restart when every managed
/// drop-in's bytes already match disk AND the supplementary-group
/// diff is empty — a route that is genuinely [`Disruption::None`]
/// when it fires but cannot be predicted from the plan because the
/// optimization keys on on-disk bytes the planner does not consult.
/// The disruption tag therefore reports the maximum disruption an
/// in-place `UpdateRunner` could cause.
///
/// Variants are ordered from least to most disruptive so callers
/// that compare or sort by severity get a consistent ordering.
/// Backed by derived `PartialOrd` / `Ord` — `None < Restart <
/// Recreate` matches variant declaration order, so callers can
/// guard with `disruption >= Disruption::Recreate` without
/// hand-rolling a comparator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Disruption {
    /// No scheduled host mutation. `Action::NoOp` emits this; the
    /// in-place `UpdateRunner` short-circuit at
    /// `apply::execute_update_runner` lands here at apply time but
    /// is reported as [`Disruption::Restart`] from plan because the
    /// short-circuit is byte-equality-driven and not plan-visible.
    /// At apply time the short-circuit logs a `tracing::info!`
    /// "skipping daemon-reload + restart" message so the operator
    /// can confirm `apply` recognized the no-op state.
    None,
    /// Stop + start of the affected unit. Disrupts in-flight runner
    /// jobs (SIGTERM at stop) and brings the unit back up with
    /// refreshed exec credentials and any updated drop-in bodies.
    /// `apply` reaches this for every non-skip in-place
    /// `UpdateRunner` (covers both file-byte changes and pure
    /// supplementary-group reconciliation, where the unit cycles
    /// even though no managed file moved) and every
    /// `UpdateCachePool`.
    Restart,
    /// Tear down + reconstruct the unit, including a GitHub-side
    /// re-registration when the action is runner-class. Strictly
    /// more disruptive than [`Disruption::Restart`] because it
    /// consumes a registration token mint (runners) or destroys
    /// host-state (cache pools: storage dir + user group). Reached
    /// by `CreateRunner`, recreate-class `UpdateRunner`,
    /// `RemoveRunner`, `CreateCachePool`, and `RemoveCachePool`.
    Recreate,
}

impl Disruption {
    /// Stable snake_case label for text + JSON rendering. Mirrors
    /// the `DriftCause::label` vocabulary so a single `grep recreate`
    /// finds every action surface.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Restart => "restart",
            Self::Recreate => "recreate",
        }
    }
}

impl Action {
    /// Diagnostic label for this action — used by `apply` when wrapping
    /// failures in `GharsError::Apply { action, .. }`.
    ///
    /// Load-bearing for `summary.recreates` JSON output (#469);
    /// renames require schema_version bump. Format relies on
    /// entity names being paren-free per `IDENTIFIER_REGEX`
    /// (`^[a-z]([a-z0-9-]*[a-z0-9])?$`).
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::CreateRunner(p) => format!("CreateRunner({})", p.spec.name),
            Self::UpdateRunner(d) => format!("UpdateRunner({})", d.identity.name),
            Self::RemoveRunner(i) => format!("RemoveRunner({})", i.name),
            Self::CreateCachePool(p) => format!("CreateCachePool({})", p.binding.name),
            Self::UpdateCachePool(d) => format!("UpdateCachePool({})", d.binding.name),
            Self::RemoveCachePool(name) => format!("RemoveCachePool({name})"),
            Self::NoOp(reason) => format!("NoOp({reason})"),
        }
    }

    /// Worst-case [`Disruption`] this action inflicts when applied.
    /// See the [`Disruption`] doc-comment for why this is plan-time
    /// worst-case rather than apply-time actual.
    ///
    /// Mapping (verified against `apply.rs`):
    /// - [`Self::CreateRunner`] → `Recreate` —
    ///   `execute_create_runner` mints a registration token and runs
    ///   `config.sh` against the GitHub API; the runner unit is
    ///   constructed from scratch.
    /// - [`Self::UpdateRunner`] with `requires_recreate = true` →
    ///   `Recreate` — `execute_update_runner` calls
    ///   `execute_remove_runner` followed by `execute_create_runner`,
    ///   both of which hit the GitHub registration API.
    /// - [`Self::UpdateRunner`] with `requires_recreate = false` →
    ///   `Restart` — `execute_update_runner`'s in-place branch issues
    ///   `daemon-reload` + `stop_unit` + `start_unit` whenever any
    ///   managed file body changes or the supplementary-group diff
    ///   is non-empty. The byte-equality short-circuit at
    ///   `apply.rs::execute_update_runner` IS in-place's
    ///   [`Disruption::None`] path at apply time, but plan cannot
    ///   predict it (keys on on-disk bytes), so we report `Restart`.
    /// - [`Self::RemoveRunner`] → `Recreate` —
    ///   `execute_remove_runner` first stops + disables the unit
    ///   and tears down per-runner netns side-units (apply.rs step
    ///   1, 1b), THEN mints a removal token and calls
    ///   `config.sh remove` to deregister with GitHub (step 2),
    ///   THEN deletes the home directory + system user (steps 3+).
    ///   The GitHub-side mutation is the same disruption class as
    ///   a fresh registration, regardless of execution order.
    /// - [`Self::CreateCachePool`] → `Recreate` —
    ///   `execute_create_cache_pool` provisions per-pool group +
    ///   storage dir + unit drop-in; the host-state construction is
    ///   the symmetric counterpart of `RemoveCachePool` and the
    ///   parity preserves the "create/remove → recreate" rule.
    /// - [`Self::UpdateCachePool`] → `Restart` — drop-in rewrite +
    ///   `daemon-reload` + `stop_unit` + `start_unit` on the
    ///   existing `ghars-cache@POOL.service`. Group + storage
    ///   identity unchanged.
    /// - [`Self::RemoveCachePool`] → `Recreate` —
    ///   `execute_remove_cache_pool` deletes the per-pool group,
    ///   storage dir, and drop-ins. Strictly more disruptive than
    ///   `Restart` because the host-state is destroyed.
    /// - [`Self::NoOp`] → `None`.
    #[must_use]
    pub fn disruption(&self) -> Disruption {
        match self {
            Self::CreateRunner(_) => Disruption::Recreate,
            Self::UpdateRunner(d) => {
                if d.requires_recreate {
                    Disruption::Recreate
                } else {
                    Disruption::Restart
                }
            }
            Self::RemoveRunner(_) => Disruption::Recreate,
            Self::CreateCachePool(_) => Disruption::Recreate,
            Self::UpdateCachePool(_) => Disruption::Restart,
            Self::RemoveCachePool(_) => Disruption::Recreate,
            Self::NoOp(_) => Disruption::None,
        }
    }
}

/// Result of `plan_from`: ordered actions + non-fatal warnings to surface
/// at the CLI layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Actions in source-emit order. `apply` re-orders into Part 8's
    /// canonical execution order (`CreateCachePool` →
    /// `UpdateCachePool` → `RemoveRunner` → `UpdateRunner` →
    /// `CreateRunner` → `RemoveCachePool` + daemon-reload).
    pub actions: Vec<Action>,
    /// Non-fatal warnings (e.g. "shared UID disables cross-runner isolation").
    pub warnings: Vec<String>,
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
    /// Stable snake_case label for text + JSON rendering. Mirrors the
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

/// Typed value for a [`FieldChange`] before/after slot (#463).
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
/// Text rendering preserves the v1 operator-visible format:
/// String → `value`, List → `a,b` (comma-joined), so existing
/// `grep "labels:.*gpu"` operator pipelines keep working.
///
/// No `Number` variant: every current producer in
/// `classify_recreate_reasons_from_annotations` emits either a
/// scalar string (10 paths) or a list of strings (2 paths).
/// Adding `Number` now would be premature — bump schema and add
/// the variant when a numeric field appears.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    /// Scalar string. Used for: `url`, `runner_version`, `arch`,
    /// `user`, `prefix`, `runner_sha256`, `runner_tarball`,
    /// `network`, `auth_name`, `trust_zone`.
    String(String),
    /// Ordered list of strings. Used for: `labels` (operator
    /// authoring order), `caches` (sorted by classifier; #353).
    /// Renderers MUST NOT re-sort — display order is canonical
    /// at construction time.
    List(Vec<String>),
}

impl FieldValue {
    /// Comma-joined text rendering. Stable across schema versions
    /// because the v1 → v2 migration is JSON-only — text consumers
    /// (operator grep) see the same surface.
    pub fn render_text(&self) -> String {
        match self {
            FieldValue::String(s) => s.clone(),
            FieldValue::List(items) => items.join(","),
        }
    }

    /// Tagged JSON rendering for schema v2.
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
/// by `classify_recreate_reasons_from_annotations` for every recreate-
/// bound field whose value differs. CLI consumers render this as
/// `path: before → after`.
///
/// `path` is a stable static identifier — see [`Self::path`] field
/// doc for the full enumeration. `before` and `after` carry typed
/// values (#463 schema v2) — see [`FieldValue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldChange {
    /// Field path identifier. Stable across releases — operator
    /// scripts can grep on it.
    ///
    /// Flat tokens for schema v2 (the value the JSON renderer
    /// emits under `"schema_version": "2"`) — `url`,
    /// `runner_version`, `labels`, `arch`, `user`, `prefix`,
    /// `runner_sha256`, `runner_tarball`, `network`, `auth_name`,
    /// `trust_zone`, `caches`. Dotted notation (e.g.
    /// `network.mode`, `hardening.kvm`,
    /// `network.allowed_egress`) is reserved for future schema
    /// versions; bumping `schema_version` is the migration path
    /// so existing consumers' grep-on-flat-token gates do not
    /// silently match nested paths.
    pub path: &'static str,
    /// Typed before-value, parsed from the discovered unit's
    /// `X-Ghars-*` annotation. List variants carry the items in
    /// the order the classifier read them (sorted for `caches`,
    /// authoring order for `labels`).
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
    /// a now-removed field family (e.g. memory_max set then unset).
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
    /// (`name`/`url`/`labels`/`runner_version`/`runner_sha256`/
    /// `runner_tarball`/`user`/`prefix`); apply must do
    /// remove → create. False ⇒ in-place rewrite + daemon-reload.
    pub requires_recreate: bool,
    /// Human-readable reasons to surface on the CLI (only meaningful when
    /// `requires_recreate` is true). Each entry names the field whose
    /// change triggered the recreate decision; CLI consumers display
    /// them verbatim.
    ///
    /// Vocabulary (every string this Vec may contain):
    /// - `"url"` — runner URL changed (registration is URL-bound).
    /// - `"runner_version"` — release version changed.
    /// - `"labels"` — registration label set changed.
    /// - `"arch"` — binary architecture changed.
    /// - `"user"` — process credential identity changed.
    /// - `"prefix"` — state-dir / home-dir prefix changed.
    /// - `"runner_sha256"` — operator-pinned tarball digest changed.
    /// - `"runner_tarball"` — operator-supplied tarball path changed
    ///   (detected via SHA256 of the path string).
    /// - `"network"` — `NetworkMode` toggled between Open and Netns
    ///   (provision/teardown of netns side-units only run on the
    ///   recreate path).
    /// - `"runsvc_integrity"` — discovered 00-ghars.conf is missing
    ///   `X-Ghars-Runsvc-Sha256`; recreate forces config.sh to mint
    ///   a fresh trusted digest (SEC-02). No FieldChange — this is a
    ///   host-state recovery trigger, not a per-field diff.
    /// - `"uncovered"` — conservative fallback for hash-mismatch with
    ///   no Stage 1 reason and no Stage 2 drop-in diff (should be
    ///   unreachable in practice; logs at warn level).
    pub recreate_reasons: Vec<&'static str>,
    /// Why this update was emitted: SpecChanged (config edit),
    /// DriftDetected (on-disk drift only), or both. Drives the CLI
    /// renderer's drift-cause label so the operator can tell the two
    /// apart at a glance (#260).
    pub drift_cause: DriftCause,
    /// Per-field before→after diff for fields the Stage 1 annotation
    /// classifier detected. CLI renderer prints one line per entry.
    ///
    /// Populated for both recreate-class diffs (e.g. `url`,
    /// `runner_version`, `labels`, `arch`, `user`, `prefix`,
    /// `runner_sha256`, `runner_tarball`, `network`) and in-place
    /// diffs that have an annotation source (`auth_name` per #306,
    /// `trust_zone` per #290, `caches` per #271 — the apply-time
    /// reconciliation runs supplementary-group diffs, not unit
    /// rewrites). The presence of a FieldChange does NOT imply
    /// `requires_recreate=true`; check `recreate_reasons` for that.
    ///
    /// Empty when:
    /// - the recreate fired via the `"uncovered"` fallback (no
    ///   annotation source for the before-value), or
    /// - the recreate fired via the `"runsvc_integrity"` host-state
    ///   recovery trigger (which is not a per-field diff), or
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
    /// supplementary-group reconciliation: apply diffs this against
    /// `delta.after.spec.caches` and calls
    /// `users.add_user_to_group` / `users.remove_user_from_group`
    /// for added / removed pools (#271). `None` ⇒ the runner predates
    /// the unconditional `X-Ghars-Caches` emit; apply skips the
    /// group-diff to avoid spurious gpasswd churn (the next apply
    /// will land annotations and a future change can reconcile).
    ///
    /// Order: when `Some`, the Vec is sorted alphabetically.
    /// `plan_from` sorts the discovered annotation at population time
    /// so operator-facing surfaces (--diff output, plan JSON
    /// serialization, error messages that name "removed pools") see a
    /// canonical order regardless of the order the on-disk
    /// `X-Ghars-Caches=` annotation happened to be written in.
    /// Membership reconciliation in apply collects this Vec into a
    /// BTreeSet before computing the gpasswd diff, so the sort is
    /// correctness-neutral for that path; it only normalizes display.
    pub before_caches: Option<Vec<String>>,
    /// Pre-update on-disk drop-in basenames discovered in the runner's
    /// drop-in directory (alphabetically ordered, parity with
    /// [`Self::before_caches`]). Drives the recreate-class `--diff`
    /// path in cli.rs: under `--diff`, recreate-class `UpdateRunner`
    /// emits a `Removed` line for every basename in this Vec that is
    /// NOT present in `after.drop_ins`, so the operator sees their
    /// `99-custom.conf` (or any other unmanaged drop-in) is being
    /// deleted by the recreate rather than vanishing silently
    /// (#468).
    ///
    /// Value semantics:
    /// - `Some(vec![..])` ⇒ discovered state was available at plan
    ///   time; the Vec is an exact snapshot of the on-disk drop-in
    ///   basenames (BTreeMap iteration order ⇒ already sorted).
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
    /// leakage surface called out in #461 for any drop-in that
    /// embedded `Environment=` lines (e.g. `60-proxy.conf` with an
    /// authenticated proxy URL). The basename alone is the
    /// operator-actionable signal: they recognize their custom
    /// drop-in by name and decide whether to migrate the contents
    /// before applying.
    pub before_drop_in_basenames: Option<Vec<String>>,
}

/// Identity of a runner — the minimum surface `apply` needs to remove or
/// reference an existing runner. `apply` looks up the rendered spec via
/// state discovery for removals; the identity carries everything required
/// to drive systemd D-Bus calls (`ghars-runner@NAME.service`),
/// home-directory rmrf safety checks (prefix + name), and registration-
/// token mints (`url` + `auth_name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerIdentity {
    /// Final runner name (post count-expansion).
    pub name: String,
    /// Repo / org URL (drives token mint).
    pub url: String,
    /// Auth registry key.
    pub auth_name: String,
    /// State-dir prefix (typically `/var/lib/ghars`); `apply`'s
    /// `guard_home_dir_rmrf` refuses to delete anything outside this
    /// prefix.
    pub prefix: camino::Utf8PathBuf,
    /// Resolved system user. `apply` uses this when the runner's home
    /// directory needs to be removed.
    pub user: String,
}

/// Data carried by a `CreateCachePool` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePoolPlan {
    /// Resolved pool binding (name + kinds + size + mode + `trust_zone`).
    pub binding: EffectiveCacheBinding,
    /// Rendered `ghars-cache@POOL.service.d/00-ghars.conf` body. Built
    /// at plan time by `systemd::render_cache_drop_in` so the F48
    /// reset-on-empty validator runs before the bytes leave the planner
    /// (Part 9b).
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

/// Expand `[[runner]]` entries with `count > 1` into one `RunnerSpec`
/// per generated name (Part 8 "Count expansion", F76 amended).
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

fn is_count_block(spec: &RunnerSpec) -> bool {
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
    })?;
    // #427: layer the runner-name length cap on top. Catches the case
    // where the prefix passes validate_identifier on its own but the
    // generated `prefix-COUNT` overflows RUNNER_NAME_MAX_LEN. The cap
    // is unconditional on runner.name (independent of any explicit
    // user= override) — symmetric to validate_cache_pool_name's
    // unconditional layering: if the operator sets user= today and
    // removes it later, removal must not silently break apply with
    // an opaque `useradd: name too long` error.
    crate::validators::validate_runner_name(name).map_err(|e| match e {
        GharsError::Validation(msg, hint) => GharsError::Validation(
            format!(
                "count expansion: generated name '{name}' from prefix \
                 '{parent_prefix}' fails runner-name validation: {msg}"
            ),
            hint,
        ),
        other => other,
    })
}

/// Merge `[defaults]` into a `RunnerSpec`, producing an
/// [`EffectiveRunnerSpec`] (Part 3 "Defaults merge rules" table).
///
/// Per-field rules:
/// - `name`, `url` — from runner only (identity, no merge).
/// - `arch` — runner overrides defaults; both unset ⇒ host arch
///   (resolved by the caller and threaded in via `host_arch`).
/// - `user` — runner overrides defaults; both unset ⇒
///   `{RUNNER_USER_PREFIX}{name}` (SEC-27 per-runner-user secure default).
/// - `prefix` — runner overrides defaults; both unset ⇒
///   `/var/lib/ghars`.
/// - `labels` — `concat(defaults.labels, runner.labels)` then dedup
///   preserving first-seen order; empty after merge ⇒ defaults to
///   `[name]` (F34 Python parity).
/// - `memory_max`, `runner_version`, `runner_sha256` — scalar
///   override (runner > defaults).
/// - `runner_tarball` — runner only (no defaults form).
/// - `caches` — runner verbatim (no merge — Part 3 explicit).
/// - `trust_zone` — runner only; empty ⇒ `"default"`.
/// - `network` — caller resolves the binding; merger receives the
///   already-resolved `Option<EffectiveNetworkBinding>`.
/// - `proxy` — runner overrides top-level; merger receives the
///   resolved `Option<ProxySpec>`.
/// - `hooks` — runner overrides top-level; merger receives the
///   resolved `Option<HooksSpec>`.
/// - `hardening` — field-by-field; runner field set ⇒ runner wins;
///   else defaults field set ⇒ defaults wins; `extra_bind_paths` and
///   `extra_capabilities` are additive (defaults entries first, then
///   runner entries).
/// - `allowed_cpus`, `allowed_memory_nodes` — scalar override.
///
/// Inputs threaded by the caller (because merge_defaults can't fetch
/// them on its own):
/// - `auth_name` — already validated against `[auth.NAME]`.
/// - `caches` — `EffectiveCacheBinding` list (resolved against
///   `[cache_pools.NAME]`).
/// - `network` — resolved binding (`None` for Open mode).
/// - `proxy` — resolved spec after runner-overrides-top-level.
/// - `hooks` — resolved spec after runner-overrides-top-level.
/// - `host_arch` — fallback when neither side specifies arch.
/// - `config_source` — path to ghars.toml (drives X-Ghars-Config-Source).
///
/// `spec_hash` is left empty in the returned spec — call
/// [`spec_hash`] on the result to fill it. Two-step pattern keeps the
/// hash domain (canonical_json of the spec) and the spec construction
/// orthogonal.
///
/// Canonicalization asymmetry between `caches` and `labels`:
///
/// - `caches`: `merge_defaults` threads the caller-supplied bindings
///   verbatim. Reorder-invariant spec_hash for caches requires going
///   through [`lower_to_effective`], which sorts `caches` by name as
///   part of cache-pool resolution. Direct `merge_defaults` callers
///   (test fixtures, future synthetic spec builders) must sort their
///   caches Vec themselves if they care about hash stability across
///   operator-supplied orderings.
///
/// - `labels`: `merge_defaults` DOES canonicalize labels. After
///   concat-and-dedup of `defaults.labels` and `runner.labels`,
///   `merge_defaults` sorts the resulting Vec alphabetically (and
///   applies `dedup` as defense-in-depth). Direct callers therefore
///   inherit reorder-invariant spec_hash for labels without going
///   through `lower_to_effective`. Labels are set-semantic for
///   GitHub Actions runner registration, so canonicalization at
///   merge time keeps the on-disk `X-Ghars-Labels=` annotation,
///   `spec_hash`, and the Stage 1 classifier's annotation diff all
///   consistent regardless of operator-supplied ordering.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn merge_defaults(
    runner: &RunnerSpec,
    defaults: &Defaults,
    auth_name: String,
    caches: Vec<EffectiveCacheBinding>,
    network: Option<EffectiveNetworkBinding>,
    proxy: Option<crate::config::ProxySpec>,
    hooks: Option<crate::config::HooksSpec>,
    host_arch: Arch,
    config_source: String,
) -> EffectiveRunnerSpec {
    let arch = runner.arch.or(defaults.arch).unwrap_or(host_arch);

    let user = runner
        .user
        .clone()
        .or_else(|| defaults.user.clone())
        .unwrap_or_else(|| {
            format!(
                "{prefix}{name}",
                prefix = crate::validators::RUNNER_USER_PREFIX,
                name = runner.name,
            )
        });

    let prefix = runner
        .prefix
        .clone()
        .or_else(|| defaults.prefix.clone())
        .unwrap_or_else(|| Utf8PathBuf::from(DEFAULT_PREFIX));

    let mut labels: Vec<String> = Vec::with_capacity(defaults.labels.len() + runner.labels.len());
    let mut seen: HashSet<String> = HashSet::new();
    for label in defaults.labels.iter().chain(runner.labels.iter()) {
        if seen.insert(label.clone()) {
            labels.push(label.clone());
        }
    }
    if labels.is_empty() {
        labels.push(runner.name.clone());
    }
    // Labels form an unordered set for GitHub Actions runner matching:
    // a workflow `runs-on: [linux, gpu]` matches a runner registered
    // with `[gpu, linux]` identically. The `--labels CSV` argv passed
    // to `config.sh` at runner-registration time produces a runner
    // whose behavior is order-independent for matching workflow
    // `runs-on:` selectors, so local order-sensitivity would cause
    // spurious recreate-class plans on cosmetic TOML reorders.
    //
    // Sort + dedup so every downstream consumer — `spec_hash`,
    // `render_identity`'s `X-Ghars-Labels` line, and the Stage 1
    // classifier comparison in
    // `classify_recreate_reasons_from_annotations` — sees a canonical
    // form. The HashSet pass above already removes duplicates seen
    // from `defaults.labels.iter().chain(runner.labels.iter())`; the
    // post-sort `dedup` is defense-in-depth in case a future caller
    // injects an already-non-unique Vec into the merge stream.
    // Sort is unstable because label strings are unique by
    // construction so stable order between equal elements is
    // irrelevant; byte-wise `Ord` agrees with operator intent for
    // the ASCII subset enforced by `validate_label`.
    labels.sort_unstable();
    labels.dedup();

    let trust_zone = if runner.trust_zone.is_empty() {
        DEFAULT_TRUST_ZONE.to_string()
    } else {
        runner.trust_zone.clone()
    };

    EffectiveRunnerSpec {
        name: runner.name.clone(),
        url: runner.url.clone(),
        arch,
        user,
        prefix,
        labels,
        memory_max: runner
            .memory_max
            .clone()
            .or_else(|| defaults.memory_max.clone()),
        runner_version: runner
            .runner_version
            .clone()
            .or_else(|| defaults.runner_version.clone()),
        runner_sha256: runner
            .runner_sha256
            .clone()
            .or_else(|| defaults.runner_sha256.clone()),
        runner_tarball: runner.runner_tarball.clone(),
        auth_name,
        caches,
        trust_zone,
        network,
        proxy,
        hooks,
        hardening: merge_hardening(&runner.hardening, &defaults.hardening),
        allowed_cpus: runner.allowed_cpus.clone(),
        allowed_memory_nodes: runner.allowed_memory_nodes.clone(),
        spec_hash: String::new(),
        // runsvc_sha256 is filled by apply.rs after the tarball install
        // phase records the on-disk runsvc.sh digest. Plan operates
        // before install so it cannot know the value; the field is
        // serde-skipped (config.rs) to keep spec_hash stable across
        // pre/post install.
        runsvc_sha256: String::new(),
        config_source,
    }
}

fn merge_hardening(runner: &Hardening, defaults: &Hardening) -> Hardening {
    let mut merged = Hardening {
        kvm: runner.kvm.or(defaults.kvm),
        restrict_realtime: runner.restrict_realtime.or(defaults.restrict_realtime),
        protect_control_groups: runner
            .protect_control_groups
            .or(defaults.protect_control_groups),
        restrict_suid_sgid: runner.restrict_suid_sgid.or(defaults.restrict_suid_sgid),
        private_devices: runner.private_devices.or(defaults.private_devices),
        private_ipc: runner.private_ipc.or(defaults.private_ipc),
        // Vec fields: runner overrides if non-empty; else defaults.
        // Treats "set to empty" as "inherit defaults" — operators who
        // truly want an empty list set the field on defaults.
        restrict_address_families: pick_vec(
            &runner.restrict_address_families,
            &defaults.restrict_address_families,
        ),
        extra_syscalls: pick_vec(&runner.extra_syscalls, &defaults.extra_syscalls),
        etc_bind_style: runner.etc_bind_style,
        // bind_readonly_paths is Option<Vec>: None ⇒ inherit defaults.
        // NOT sorted: BindReadOnlyPaths= entries are mount-order-sensitive
        // when paths overlap (systemd processes them sequentially; a later
        // mount over an earlier ro mount can override or fail), so the
        // operator's source order is load-bearing.
        bind_readonly_paths: runner
            .bind_readonly_paths
            .clone()
            .or_else(|| defaults.bind_readonly_paths.clone()),
        // extra_bind_paths is additive across both sides — both apply.
        // NOT sorted: same mount-ordering rationale as bind_readonly_paths.
        extra_bind_paths: {
            let mut out = defaults.extra_bind_paths.clone();
            out.extend(runner.extra_bind_paths.iter().cloned());
            out
        },
        extra_capabilities: {
            let mut out = defaults.extra_capabilities.clone();
            out.extend(runner.extra_capabilities.iter().cloned());
            out
        },
    };

    // #384: Canonicalize set-semantic Vec fields by sorting AND deduping
    // in place so a pure operator reorder (or accidental duplicate) in
    // TOML produces an identical EffectiveRunnerSpec → identical
    // spec_hash → NoOp instead of an unnecessary recreate. Mirrors the
    // #371 caches canonicalization.
    //
    // Only canonicalized fields here are set-semantic (the operator's
    // intent is "use exactly this set"; order and duplicates do not
    // change effective behavior):
    //   - `restrict_address_families` → RestrictAddressFamilies= appends
    //     with union semantics across drop-in lines, set-semantic.
    //   - `extra_syscalls` → SystemCallFilter= is APPEND with union
    //     semantics (consecutive lines union the allowlist), so order
    //     is not load-bearing.
    //   - `extra_capabilities` → CapabilityBoundingSet= unions across
    //     drop-in lines.
    //
    // The `.dedup()` call lands AFTER `.sort()` because `Vec::dedup`
    // collapses only *consecutive* equal elements; sort first puts
    // duplicates adjacent, then dedup removes them.
    //
    // Two distinct sources of duplicates:
    //   - Additive merge (`extra_capabilities`: `defaults.extend(runner)`)
    //     can produce duplicates when both sides list the same entry.
    //   - Pick merge (`extra_syscalls`, `restrict_address_families` via
    //     `pick_vec`) can produce duplicates when the picked side itself
    //     contains repeated entries; `pick_vec` is XOR — runner OR
    //     defaults, never both — so cross-side overlap is not the
    //     source.
    //
    // Both classes of duplicates would otherwise survive into the
    // rendered drop-in body and the spec_hash, re-introducing the same
    // spurious drift class the sort itself was added to fix.
    //
    // Fields explicitly NOT sorted (mount-order-sensitive — see the
    // bind_readonly_paths and extra_bind_paths comments above).
    merged.restrict_address_families.sort();
    merged.restrict_address_families.dedup();
    merged.extra_syscalls.sort();
    merged.extra_syscalls.dedup();
    merged.extra_capabilities.sort();
    merged.extra_capabilities.dedup();
    merged
}

fn pick_vec<T: Clone>(runner: &[T], defaults: &[T]) -> Vec<T> {
    if runner.is_empty() {
        defaults.to_vec()
    } else {
        runner.to_vec()
    }
}

/// Compute the canonical-JSON sha256 of an [`EffectiveRunnerSpec`]
/// (Part 3 spec-hash, F17 / Part 17 #18).
///
/// Canonicalization:
/// - Round-trip through `serde_json::Value` whose `Object` map is
///   `BTreeMap`-backed (no `preserve_order` feature) — keys land in
///   sorted order at every depth.
/// - Arrays preserve source order in canonical JSON (`Vec` is
///   ordered by intent). `caches` and `labels` are the set-semantic
///   exceptions: `lower_to_effective` sorts `caches` by name during
///   cache-pool resolution; `merge_defaults` sorts `labels` by name
///   after the concat-and-dedup pass. So the spec arriving here is
///   canonical regardless of the operator's TOML ordering. `spec_hash`
///   itself does NOT re-sort — callers that bypass the lowering
///   pipeline (e.g. hand-built test fixtures) must sort their own
///   `caches` / `labels` Vecs before hashing if they want the
///   reorder-invariance contract. First apply post-upgrade will
///   rewrite `00-ghars.conf` and `30-cache-pool.conf` with sorted
///   caches/labels for any runner whose TOML order differed.
///
///   Set-semantic rationale for `labels`: GitHub Actions matches
///   workflow `runs-on:` against the registered label set
///   identically regardless of order — `runs-on: [linux, gpu]`
///   selects a runner whose registered labels are `[gpu, linux]` the
///   same as `[linux, gpu]`. The `--labels CSV` argv passed to
///   `config.sh` (assembled at `apply.rs::build_register_cmd`) is
///   handed to GitHub at registration time; the runner's behavior
///   is order-independent for matching workflow `runs-on:`
///   selectors. Local order-sensitivity in the spec_hash would cause
///   spurious recreate-class `UpdateRunner` plans (registration is
///   labels-bound, so a hash flip drives a recreate reason) on
///   cosmetic TOML edits.
///
///   `allowed_egress` and other Vec fields stay order-sensitive
///   because their semantic value depends on order (`allowed_egress`
///   rules apply first-match-wins).
/// - The `spec_hash` field of the input is zeroed before hashing so
///   the function is idempotent: hashing a spec, embedding the hash,
///   and re-hashing yields the same value.
/// - The `config_source` field is INCLUDED — same spec sourced from
///   different files is intentionally treated as different (drives
///   X-Ghars-Config-Source). Operators who want stable hashes across
///   path moves are using the wrong input.
///
/// Output: `sha256:HEX` lowercase 64-hex. Prefix matches the value
/// emitted into the X-Ghars-Spec-Hash annotation.
///
/// # Panics
///
/// Panics only if `serde_json::to_value` fails on
/// `EffectiveRunnerSpec` — which can't happen because every field
/// type implements `Serialize`. The expect message names the bug.
#[must_use]
pub fn spec_hash(spec: &EffectiveRunnerSpec) -> String {
    use sha2::{Digest, Sha256};

    let mut canonical = spec.clone();
    canonical.spec_hash.clear();

    let value = serde_json::to_value(&canonical)
        .expect("EffectiveRunnerSpec must be serde_json-serializable");
    let json =
        serde_json::to_string(&value).expect("serde_json::Value always serializes to a string");

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

/// Annotation values pulled out of the `[Unit]` section of a
/// discovered runner's `00-ghars.conf` drop-in body — the subset
/// that drives `requires_recreate` decisions and the field-level
/// diff payload on `RunnerDelta`. NOT the runner template body
/// (`ghars-runner@.service`); that file carries only the
/// non-per-runner `X-Ghars-Managed=true` and
/// `X-Ghars-Schema-Version=1` lines. Per-runner identity
/// annotations live entirely in the drop-in (#347).
///
/// State discovery doesn't carry the full `EffectiveRunnerSpec` of
/// the discovered unit (only the spec_hash + raw text), so the plan
/// engine reconstructs the comparable subset from the X-Ghars-*
/// annotations the unit-text generator emits in `00-ghars.conf`.
///
/// Annotations covered: `X-Ghars-Runner-Url`,
/// `X-Ghars-Auth-Name`, `X-Ghars-Effective-Version`,
/// `X-Ghars-Labels`, `X-Ghars-Arch`, `X-Ghars-User`,
/// `X-Ghars-Prefix`, `X-Ghars-Runner-Sha256` (when set),
/// `X-Ghars-Runner-Tarball-Hash` (when set; sha256 of operator
/// path string, NOT the path), `X-Ghars-Trust-Zone`,
/// `X-Ghars-Network-Mode`, `X-Ghars-Caches` (comma-joined cache
/// pool names, sorted by `lower_to_effective` per #371; empty
/// value parses as `Some(vec![])` to distinguish from missing
/// annotation). Fields still NOT annotated
/// (memory_max, hardening, allowed_cpus, proxy, hooks) live in
/// their own drop-ins; the in-place classification (Stage 2 in
/// `classify_recreate_reasons_from_annotations`) detects them by
/// comparing rendered drop-in bodies against the discovered drop-
/// ins, which avoids the need to round-trip those values through
/// annotations.
///
/// Missing-annotation handling: when a field's annotation is `None`
/// (older ghars-applied unit predating BATCH C, or operator-edited
/// unit with the line stripped), the corresponding Stage 1 check is
/// skipped rather than treated as "annotation==empty != desired".
/// Without this, every existing runner would falsely recreate on the
/// first apply post-upgrade because their on-disk units lack the new
/// keys. The spec-hash mismatch path picks up the change once and
/// the freshly-applied unit then carries the new annotations for
/// subsequent runs.
#[derive(Debug, Default)]
struct DiscoveredAnnotations {
    url: Option<String>,
    auth_name: Option<String>,
    runner_version: Option<String>,
    labels: Option<Vec<String>>,
    arch: Option<String>,
    user: Option<String>,
    prefix: Option<String>,
    runner_sha256: Option<String>,
    runner_tarball_hash: Option<String>,
    trust_zone: Option<String>,
    network_mode: Option<String>,
    /// `X-Ghars-Caches` value (#271). Comma-split list of cache pool
    /// names the runner was registered against. Drives in-place
    /// supplementary-group reconciliation: apply diffs this against
    /// `delta.after.spec.caches` and calls `add_user_to_group` /
    /// `remove_user_from_group` for added / removed pools.
    caches: Option<Vec<String>>,
}

impl DiscoveredAnnotations {
    /// Extract annotations from a discovered runner. Reads the
    /// `00-ghars.conf` drop-in body — that's where
    /// `crate::systemd::render_identity` writes every X-Ghars-* line
    /// (the `[Unit]` section of the drop-in). The runner template
    /// `ghars-runner@.service` itself carries only `X-Ghars-Managed=true`
    /// + `X-Ghars-Schema-Version=1`, NOT the per-runner identity
    /// annotations.
    ///
    /// `state::discover` populates `discovered.on_disk_unit_text`
    /// from the unit-template path on disk (state.rs:220) and
    /// `discovered.drop_ins["00-ghars.conf"]` from the per-runner
    /// drop-in dir (state.rs:228-229). Reading the unit text would
    /// therefore find nothing — Stage 1 annotation classification
    /// would silently break in production while passing under any
    /// fixture that happens to put the lines in the unit text.
    ///
    /// Missing drop-in handling: a runner whose `00-ghars.conf` is
    /// absent (pre-BATCH-C apply, operator-stripped) yields a default
    /// `DiscoveredAnnotations` with every field `None`. The classifier
    /// treats `None` as "skip this field" (avoiding spurious recreates
    /// on first apply post-upgrade), so no annotations + a hash
    /// mismatch falls through to the `uncovered` recreate fallback —
    /// the conservative correct behavior.
    fn from_discovered(discovered: &DiscoveredRunner) -> Self {
        let body = match discovered.drop_ins.get("00-ghars.conf") {
            Some(b) => b.as_str(),
            None => return Self::default(),
        };
        Self::from_drop_in_body(body)
    }

    fn from_drop_in_body(body: &str) -> Self {
        let mut out = DiscoveredAnnotations::default();
        for (k, v) in extract_x_ghars(body) {
            match k.as_str() {
                "X-Ghars-Runner-Url" => out.url = Some(v),
                "X-Ghars-Auth-Name" => out.auth_name = Some(v),
                "X-Ghars-Effective-Version" => out.runner_version = Some(v),
                "X-Ghars-Labels" => {
                    // Empty annotation value ⇒ empty label vec
                    // (consistent with the renderer emitting
                    // `X-Ghars-Labels=` for spec.labels.is_empty()).
                    let parsed: Vec<String> = if v.is_empty() {
                        Vec::new()
                    } else {
                        v.split(',').map(str::to_owned).collect()
                    };
                    out.labels = Some(parsed);
                }
                "X-Ghars-Arch" => out.arch = Some(v),
                "X-Ghars-User" => out.user = Some(v),
                "X-Ghars-Prefix" => out.prefix = Some(v),
                "X-Ghars-Runner-Sha256" => out.runner_sha256 = Some(v),
                // #296: persist HASH of tarball path, not the path
                // itself. The on-disk operator path can leak
                // environment fingerprints (mount points, usernames,
                // kernel-private dirs); the hash is sufficient for
                // change detection without persisting the original
                // path string.
                "X-Ghars-Runner-Tarball-Hash" => out.runner_tarball_hash = Some(v),
                "X-Ghars-Trust-Zone" => out.trust_zone = Some(v),
                "X-Ghars-Network-Mode" => out.network_mode = Some(v),
                "X-Ghars-Caches" => {
                    // #271: distinguish "key present with empty value"
                    // (X-Ghars-Caches=) from "key absent" (line not
                    // emitted at all):
                    // - Present here ⇒ this arm runs ⇒ Some(parsed),
                    //   where empty value parses to Some(vec![])
                    //   (matches labels handling above; the runner
                    //   was registered with no cache pools).
                    // - Absent ⇒ this arm never runs ⇒ out.caches
                    //   stays at its default None ⇒ "unknown" ⇒ the
                    //   planner skips the supplementary-group diff
                    //   at apply time. render_identity emits the line
                    //   unconditionally, so None means the runner
                    //   predates that unconditional-emit change.
                    let parsed: Vec<String> = if v.is_empty() {
                        Vec::new()
                    } else {
                        v.split(',').map(str::to_owned).collect()
                    };
                    out.caches = Some(parsed);
                }
                _ => {}
            }
        }
        out
    }
}

/// Classify recreate-bound field changes between an annotation-
/// reconstructed view of the discovered runner and the desired
/// effective spec.
///
/// Returns the list of recreate-bound fields that differ. A non-empty
/// list ⇒ `requires_recreate = true`.
///
/// Fields covered (Part 3 `requires_recreate` table — annotation-
/// derived subset):
/// - `url` — recreate (config.sh registration is URL-bound).
/// - `runner_version` — recreate (re-extract tarball).
/// - `labels` — recreate (registration is labels-bound).
/// - `arch` — recreate (binary architecture differs).
/// - `user` — recreate (process credential identity bound).
/// - `prefix` — recreate (state-dir / home-dir paths bound).
/// - `runner_sha256` — recreate (re-extract tarball under new digest).
/// - `runner_tarball` — recreate (operator-supplied binary swap;
///   detected via SHA256 of the path string, not the path itself,
///   to avoid persisting operator environment fingerprints in the
///   on-disk unit).
/// - `network` — recreate (Open↔Netns toggle requires
///   `provision_netns_artifacts` / `teardown_netns_artifacts`, which
///   only execute_create_runner / execute_remove_runner call; the
///   in-place rewrite path leaves orphan netns side-units or
///   unprovisioned netns paths). Within-mode config edits (egress
///   rules, DNS mode) stay in-place via the 40-network.conf body
///   diff at Stage 2.
///
/// In-place-only detection (FieldChange recorded, no recreate
/// reason):
/// - `auth_name` — auth-ref change is in-place per design Part 3.
///   The underlying secret is rotated out-of-band and apply
///   rebuilds the auth registry every run.
/// - `trust_zone` — once cache-pool cross-references validate at
///   `lower_to_effective` time, the runner unit body has no
///   `trust_zone` dependency. The annotation lets the operator-
///   visible diff surface `trust_zone: a → b` while keeping the
///   apply path in-place (no host-state migration).
/// - `caches` — supplementary-group reconciliation is in-place
///   per design Part 3 (#271). `apply::execute_update_runner`'s
///   in-place path diffs `delta.before_caches` against the
///   desired list and calls `add_user_to_group` /
///   `remove_user_from_group` for added / removed pools — no
///   recreate needed.
///
/// All three of these record FieldChanges WITHOUT pushing a
/// recreate reason; the `uncovered` guard at the call site gates
/// on `field_changes.is_empty()` so any one signal alone prevents
/// the spurious recreate-class fallback (#306).
///
/// Missing-annotation handling: a field whose discovered annotation
/// is `None` (older ghars-applied unit pre-BATCH-C, or operator-
/// stripped) is SKIPPED here — comparing `None` against any desired
/// value would falsely fire on first apply post-upgrade. The spec-
/// hash mismatch propagates the change once; subsequent applies see
/// the freshly-emitted annotations and Stage 1 covers the field.
///
/// # Field-level diff payload
///
/// For each detected change, the function ALSO emits a `FieldChange`
/// into `out_changes` with the before/after values rendered as
/// strings. CLI consumers display this as `field: before → after`.

/// Compare two set-semantic string fields and return a `FieldChange`
/// when the sets differ. Used by both the labels and caches branches
/// of `classify_recreate_reasons_from_annotations` — both fields are
/// set-semantic (GitHub Actions matches labels order-independently;
/// supplementary-group membership is unordered) and must use the same
/// sort-then-compare contract that apply enforces.
///
/// `before`: the discovered annotation Vec, or `None` for the
/// post-upgrade fixture (skips the comparison entirely).
/// `after`: an iterator over the desired set's string values. Caller
/// extracts `.name` for caches or hands `String::as_str` for labels.
///
/// Both sides are sorted via `sort_unstable` (byte-wise Ord; matches
/// the validator-enforced ASCII charset). When the sets differ, the
/// returned `FieldChange.before/after` carry the SORTED Vecs so
/// operator-facing surfaces (plan JSON, --diff) see the canonical
/// ordering GitHub / apply will use.
///
/// Returns `None` when discovered is `None` (skip) or the sorted sets
/// match (no-op). The caller decides whether to push a recreate
/// reason — labels does, caches does not (in-place per design Part 3).
fn sorted_set_field_diff<'a>(
    path: &'static str,
    before: Option<&'a [String]>,
    after: impl Iterator<Item = &'a str>,
) -> Option<FieldChange> {
    let before = before?;
    let mut before_sorted: Vec<&str> = before.iter().map(String::as_str).collect();
    before_sorted.sort_unstable();
    let mut after_sorted: Vec<&str> = after.collect();
    after_sorted.sort_unstable();
    if before_sorted == after_sorted {
        return None;
    }
    Some(FieldChange {
        path,
        before: FieldValue::List(before_sorted.iter().map(|s| (*s).to_owned()).collect()),
        after: FieldValue::List(after_sorted.iter().map(|s| (*s).to_owned()).collect()),
    })
}

fn classify_recreate_reasons_from_annotations(
    discovered: &DiscoveredAnnotations,
    desired: &EffectiveRunnerSpec,
    out_changes: &mut Vec<FieldChange>,
) -> Vec<&'static str> {
    let mut reasons: Vec<&'static str> = Vec::new();

    if let Some(url) = discovered.url.as_deref()
        && url != desired.url
    {
        reasons.push("url");
        out_changes.push(FieldChange {
            path: "url",
            before: FieldValue::String(url.to_owned()),
            after: FieldValue::String(desired.url.clone()),
        });
    }
    if let Some(version) = discovered.runner_version.as_deref() {
        let desired_version = desired.runner_version.as_deref().unwrap_or("");
        if version != desired_version {
            reasons.push("runner_version");
            out_changes.push(FieldChange {
                path: "runner_version",
                before: FieldValue::String(version.to_owned()),
                after: FieldValue::String(desired_version.to_owned()),
            });
        }
    }
    // Labels are set-semantic for GitHub Actions matching, mirror the
    // caches treatment below. Sort BOTH sides before equality so a
    // pure reorder (older ghars-applied unit wrote
    // `X-Ghars-Labels=beta,alpha` then operator reorders TOML to
    // `[alpha, beta]`) does not record a misleading `labels` recreate
    // reason / FieldChange even though GitHub's view of the
    // registration is identical. Recreate-class: a labels diff must
    // re-register the runner with GitHub.
    if let Some(change) = sorted_set_field_diff(
        "labels",
        discovered.labels.as_deref(),
        desired.labels.iter().map(String::as_str),
    ) {
        reasons.push("labels");
        out_changes.push(change);
    }
    if let Some(arch) = discovered.arch.as_deref() {
        let desired_arch = match desired.arch {
            crate::config::Arch::X86_64 => "x86_64",
            crate::config::Arch::Aarch64 => "aarch64",
        };
        if arch != desired_arch {
            reasons.push("arch");
            out_changes.push(FieldChange {
                path: "arch",
                before: FieldValue::String(arch.to_owned()),
                after: FieldValue::String(desired_arch.to_owned()),
            });
        }
    }
    if let Some(user) = discovered.user.as_deref()
        && user != desired.user
    {
        reasons.push("user");
        out_changes.push(FieldChange {
            path: "user",
            before: FieldValue::String(user.to_owned()),
            after: FieldValue::String(desired.user.clone()),
        });
    }
    if let Some(prefix) = discovered.prefix.as_deref() {
        let desired_prefix = desired.prefix.as_str();
        if prefix != desired_prefix {
            reasons.push("prefix");
            out_changes.push(FieldChange {
                path: "prefix",
                before: FieldValue::String(prefix.to_owned()),
                after: FieldValue::String(desired_prefix.to_owned()),
            });
        }
    }
    // #296: runner_sha256 change is recreate-class. Annotation is
    // emitted only when non-empty (systemd.rs::render_identity), so
    // a `None` here means either (a) the operator never pinned a
    // digest or (b) the runner predates the annotation. Either way
    // we skip — comparing None against any desired value would
    // falsely fire on the first apply post-upgrade. The classifier
    // sees the change once via spec_hash mismatch; the next apply
    // carries the freshly-emitted annotation and Stage 1 covers it.
    if let Some(sha) = discovered.runner_sha256.as_deref() {
        let desired_sha = desired.runner_sha256.as_deref().unwrap_or("");
        if sha != desired_sha {
            reasons.push("runner_sha256");
            out_changes.push(FieldChange {
                path: "runner_sha256",
                before: FieldValue::String(sha.to_owned()),
                after: FieldValue::String(desired_sha.to_owned()),
            });
        }
    }
    // #296: runner_tarball change is recreate-class (operator-
    // supplied binary swap). The on-disk annotation is the SHA256
    // of the tarball PATH STRING, not the path itself, to avoid
    // leaking operator environment fingerprints into the persisted
    // unit. The before-value here is therefore the discovered
    // hash; the after-value is the recomputed hash of the desired
    // path. FieldChange records both hashes so operators can grep
    // for the typed reason without ever seeing the path.
    if let Some(disc_hash) = discovered.runner_tarball_hash.as_deref() {
        let desired_hash = desired
            .runner_tarball
            .as_deref()
            .map(|p| {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(p.as_str().as_bytes());
                format!("sha256:{}", hex::encode(h.finalize()))
            })
            .unwrap_or_default();
        if disc_hash != desired_hash {
            reasons.push("runner_tarball");
            out_changes.push(FieldChange {
                path: "runner_tarball",
                before: FieldValue::String(disc_hash.to_owned()),
                after: FieldValue::String(desired_hash),
            });
        }
    }
    // #308: network mode change MUST recreate. The in-place rewrite
    // path (apply.rs::execute_update_runner non-recreate branch)
    // does not call provision_netns_artifacts /
    // teardown_netns_artifacts. An Open→Netns transition routed
    // in-place would write 40-network.conf + 15-resolv.conf with
    // NetworkNamespacePath= but leave the netns missing — the
    // unit's fail-closed `Requires=ghars-net@%i.service` would then
    // fail at restart. A Netns→Open transition routed in-place
    // would orphan ghars-net@INSTANCE + nft rule files + the
    // /var/run/netns/ghars-INSTANCE iface. Stage 1 detection here
    // forces the recreate path, which DOES run both lifecycle
    // helpers via execute_remove_runner + execute_create_runner
    // (#311 collapsed into this fix).
    //
    // Within-mode config changes (egress rule edits, DNS mode
    // toggles inside Netns) do NOT recreate — the 40-network.conf
    // body diff is in-place safe and Stage 2 picks it up via the
    // managed-drop-in body diff in plan_from's intersection branch
    // (the `any_drop_in_modified` check that filters
    // MANAGED_DROP_IN_BASENAMES against Created|Modified|Removed).
    //
    // Caveat (#350): within-Netns egress rule changes are NOT yet
    // detected by Stage 2 — `render_network` (systemd.rs) emits a
    // 40-network.conf that does NOT carry allowed_egress; the rules
    // flow into nft.d/ files written by apply, which Stage 2 doesn't
    // diff. A pure egress edit therefore presents as a spec-hash
    // mismatch with no Stage 1 reason and no Stage 2 evidence, and
    // falls through to the conservative `uncovered` recreate
    // fallback. Tracked separately; not a correctness bug (recreate
    // is safe, just operator-disruptive).
    if let Some(mode) = discovered.network_mode.as_deref() {
        let desired_mode = match desired.network.as_ref().map(|n| &n.spec.mode) {
            Some(crate::config::NetworkMode::Netns) => "netns",
            Some(crate::config::NetworkMode::Open) | None => "open",
        };
        if mode != desired_mode {
            reasons.push("network");
            out_changes.push(FieldChange {
                path: "network",
                before: FieldValue::String(mode.to_owned()),
                after: FieldValue::String(desired_mode.to_owned()),
            });
        }
    }
    // #306: auth_name change is in-place per design Part 3 — apply
    // rebuilds the auth registry every run and re-mints tokens
    // against whatever PAT/App/file source is referenced now, so
    // there is no host-state migration to do. Without this branch
    // an auth-name-only change had no Stage 1 reason and no Stage 2
    // managed-drop-in-body delta (since `00-ghars.conf` carries the
    // X-Ghars-Auth-Name annotation but is excluded from the in-
    // place filter), falling through to the `uncovered` recreate
    // fallback at the spec_hash mismatch check below. Recording a
    // FieldChange WITHOUT pushing to `reasons` keeps the operator-
    // visible diff payload (the rendered text/JSON shows
    // `auth_name: before → after`) AND prevents the spurious
    // recreate. The uncovered guard below also gates on
    // `out_changes.is_empty()` so this signal alone is sufficient
    // evidence that the classifier saw the change.
    if let Some(auth_name) = discovered.auth_name.as_deref()
        && auth_name != desired.auth_name
    {
        out_changes.push(FieldChange {
            path: "auth_name",
            before: FieldValue::String(auth_name.to_owned()),
            after: FieldValue::String(desired.auth_name.clone()),
        });
    }
    // #290: trust_zone change is in-place per design Part 3. Once
    // cache-pool cross-reference validation passes at
    // `lower_to_effective` time, the runner unit body has no
    // `trust_zone` dependency — the field exists only to enforce
    // SEC-03 (cache-pool isolation) at config-load time. trust_zone
    // is in EffectiveRunnerSpec spec_hash so any change does
    // surface as a hash mismatch; without this branch, that
    // mismatch fell through to the `uncovered` recreate fallback
    // even though the apply path has nothing to migrate.
    if let Some(zone) = discovered.trust_zone.as_deref()
        && zone != desired.trust_zone
    {
        out_changes.push(FieldChange {
            path: "trust_zone",
            before: FieldValue::String(zone.to_owned()),
            after: FieldValue::String(desired.trust_zone.clone()),
        });
    }
    // #271: caches change is in-place per design Part 3 — apply.rs's
    // execute_update_runner in-place path reconciles supplementary
    // group membership via add_user_to_group / remove_user_from_group
    // diffs against `delta.before_caches`. Recording a FieldChange here
    // (without pushing a recreate reason) makes the change visible in
    // plan output and gates the `uncovered` fallback the same way
    // auth_name / trust_zone do.
    //
    // #353: cache pool membership is set-semantics (group memberships
    // are unordered; execute_update_runner's BTreeSet difference
    // block in apply.rs runs the actual gpasswd diff). The plan
    // classifier MUST mirror that contract or a pure reorder
    // ["a","b"] → ["b","a"] would record a misleading FieldChange in
    // plan output even though apply does no group ops.
    //
    // In-place class: emit the FieldChange but DO NOT push a recreate
    // reason. Apply reconciles the membership delta in-place via
    // gpasswd ops; the runner identity is unchanged.
    if let Some(change) = sorted_set_field_diff(
        "caches",
        discovered.caches.as_deref(),
        desired.caches.iter().map(|c| c.name.as_str()),
    ) {
        out_changes.push(change);
    }

    reasons
}

/// Compute a [`Plan`] from desired config + discovered actual state.
///
/// v0.1 scope (Part 8 step coverage):
/// 1. `expand_counts(config)` — flatten count-blocks.
/// 2. Defaults-merge — runs in [`lower_to_effective`]. Cross-reference
///    resolution for auth, caches, network is validated and threaded
///    through.
/// 3. Release lookup (Part 8 step 3) — NOT done here; the unit-text
///    generator (B4) is responsible for resolving `runner_version`
///    against the releases API. Plan emits the spec with whatever
///    `runner_version` is pinned in config; if unset it stays
///    `None` and the generator decides.
/// 4. Spec hash (Part 8 step 4) — computed via [`spec_hash`].
/// 5/6. Set diff against `actual`:
///    - desired - actual ⇒ `CreateRunner`.
///    - actual - desired ⇒ `RemoveRunner` (managed unit, no matching
///      desired entry).
///    - intersection ⇒ `NoOp` if hashes match AND drift is `InSync`;
///      `UpdateRunner` otherwise. Field-level classification populates
///      `requires_recreate` + `recreate_reasons` from annotation diff;
///      hash mismatch with no identifiable Stage 1 reason and no
///      Stage 2 drop-in body diff falls back to a conservative
///      `"uncovered"` recreate reason (BATCH C / Part 2 item 8 — the
///      reason was renamed from `spec_hash_mismatch` because the
///      condition is broader than a hash mismatch alone).
/// 7. Apply Part 3 `requires_recreate` policy — done in
///    [`classify_recreate_reasons_from_annotations`].
/// 8. Cache-pool diffs against the discovered set. State discovery
///    does not yet enumerate `ghars-cache@*.service` units, so v0.1
///    emits `CreateCachePool` for every desired pool referenced by
///    at least one effective spec. Update/Remove classification
///    lands when state.discover gains pool discovery (B4 #109).
/// 9. Orphan handling — `actual.orphans` always become `RemoveRunner`
///    (matches Part 7 — managed unit, no matching desired). External
///    units are never touched. Identity reconstructed from
///    annotations + unit body when possible (apply needs `url` /
///    `auth_name` to mint a remove token; `prefix` / `user` to clean
///    home directories).
///
/// `paths` threads through to record `config_source` on each
/// effective spec.
///
/// # Errors
///
/// Returns `GharsError::Validation` when:
/// - `expand_counts` fails (count > MAX_COUNT, regex mismatch, cross-
///   block name collision);
/// - a runner references an unknown auth name (no
///   `[defaults] auth` and no `[[runner]] auth`);
/// - a runner references an unknown cache pool;
/// - a runner references an unknown network;
/// - a runner's `trust_zone` doesn't match a referenced cache pool's.
pub fn plan_from(config: &Config, actual: &ActualState, paths: &Paths) -> Result<Plan> {
    let host_arch = host_arch();
    let config_source = paths.config_dir.join("ghars.toml").to_string();
    // #345/#346 — defense-in-depth: reject control chars in
    // `config_source` before any rendered drop-in body picks it up via
    // `render_identity`'s X-Ghars-Config-Source line or
    // `render_cache_drop_in`'s same annotation.
    // Today `paths.config_dir` is hard-coded to `/etc/ghars` via
    // `Paths::default()`, so the production path always produces a
    // control-char-free string. The validation is here anyway because:
    //   (a) any future code path that constructs a `Paths` with an
    //       operator-influenced `config_dir` (env var, future
    //       `--config-dir`, or test redirection in production)
    //       inherits the gate without bypass;
    //   (b) `render_identity` itself runs the same check at unit
    //       render time, but that's strictly inside this function
    //       (lower_to_effective → render_runner_unit), so any caller
    //       that synthesizes an `EffectiveRunnerSpec` outside
    //       `plan_from` would skip it. Validating here closes the
    //       gap before `lower_to_effective` clones the value into
    //       every effective spec.
    crate::systemd::check_identity_field("config_source", &config_source)?;

    // Step 1: count-expand.
    let expanded = expand_counts(config)?;

    // Step 2: lower each RunnerSpec → EffectiveRunnerSpec.
    //
    // The runner's index in `expanded` is the netns subnet slot
    // (sequential /30 from the 10.200.0.0/24 default pool — Part 9c
    // "IP allocation"). Open-mode runners still consume an index; the
    // /30 they would have gotten is simply unused. With 64 slots in
    // /24 this leaves headroom for typical deployments while keeping
    // the slot rule trivially deterministic across plan/apply runs.
    // (#195.)
    let mut desired: BTreeMap<String, EffectiveRunnerSpec> = BTreeMap::new();
    let mut warnings: Vec<String> = Vec::new();
    for (slot_idx, runner) in expanded.iter().enumerate() {
        let effective = lower_to_effective(
            runner,
            config,
            host_arch,
            config_source.clone(),
            slot_idx,
            &mut warnings,
        )?;
        desired.insert(effective.name.clone(), effective);
    }

    let mut actions: Vec<Action> = Vec::new();

    // Step 5/6/7: diff desired vs actual.
    let actual_names: HashSet<&String> = actual.runners.keys().collect();
    let desired_names: HashSet<&String> = desired.keys().collect();

    // Sort for deterministic plan output (Part 8 "Within each phase,
    // runners sorted by name for determinism").
    let mut all: Vec<&String> = actual_names.union(&desired_names).copied().collect();
    all.sort();

    for name in all {
        let in_desired = desired_names.contains(name);
        let in_actual = actual_names.contains(name);
        match (in_desired, in_actual) {
            (true, false) => {
                // Pure create.
                let spec = desired
                    .get(name)
                    .expect("name was in desired_names")
                    .clone();
                actions.push(Action::CreateRunner(into_runner_plan(spec)?));
            }
            (false, true) => {
                // Pure remove (managed unit, no matching desired).
                let discovered = actual.runners.get(name).expect("name was in actual_names");
                actions.push(Action::RemoveRunner(reconstruct_identity(
                    name, discovered, paths,
                )));
            }
            (true, true) => {
                let after_spec = with_hash(
                    desired
                        .get(name)
                        .expect("name was in desired_names")
                        .clone(),
                );
                let discovered = actual.runners.get(name).expect("name was in actual_names");
                let hashes_equal = after_spec.spec_hash == discovered.spec_hash
                    && !discovered.spec_hash.is_empty();
                let in_sync = matches!(discovered.drift, Drift::InSync);

                if hashes_equal && in_sync {
                    actions.push(Action::NoOp(format!("{name}: in sync")));
                } else {
                    let annotations = DiscoveredAnnotations::from_discovered(discovered);
                    // BATCH C / Part 2 / phd1 fix #10: thread the
                    // already-recorded X-Ghars-Runsvc-Sha256 from the
                    // discovered drop-in body into after_spec BEFORE
                    // re-rendering. Without this, the plan-time
                    // re-render (#216 fix below) emits a 00-ghars.conf
                    // with an empty/missing Runsvc-Sha256 line, the
                    // in-place rewrite path overwrites the drop-in,
                    // and runsvc-wrapper's annotation check fails on
                    // the next runner restart (SEC-02 trampoline
                    // rejects). Pull the value from the existing
                    // 00-ghars.conf body so an in-place update
                    // preserves the install-phase digest.
                    //
                    // #289 (revised): if the discovered drop-in is
                    // missing X-Ghars-Runsvc-Sha256 entirely (pre-BATCH-C
                    // runner or operator-stripped 00-ghars.conf), we
                    // CANNOT silently emit an in-place update — the
                    // freshly-rendered drop-in would lack the annotation
                    // and runsvc-wrapper would fail-stop on the next
                    // start. We also CANNOT hash runsvc.sh from disk
                    // here: the file lives in the runner-writable home
                    // and a tampered binary would propagate as a
                    // "trusted" digest (SEC-02 design Part 8). Force
                    // the recreate path instead — `config.sh` re-runs
                    // there, writes a fresh runsvc.sh under our
                    // control, and apply records the trusted digest in
                    // execute_create_runner. The recreate_reason
                    // `runsvc_integrity` flags this for operator
                    // visibility; `tracing::warn!` records the trigger.
                    let mut after_spec = after_spec;
                    let mut runsvc_integrity_recreate = false;
                    if after_spec.runsvc_sha256.is_empty() {
                        if let Some(existing) = extract_runsvc_sha256(&discovered.drop_ins) {
                            after_spec.runsvc_sha256 = existing;
                            // Re-call with_hash defensively after
                            // mutating runsvc_sha256. Today
                            // EffectiveRunnerSpec.runsvc_sha256 is
                            // `#[serde(skip)]` (config.rs:297) so it
                            // is NOT a canonical-JSON spec_hash input
                            // — `prop_spec_hash_ignores_runsvc_sha256`
                            // pins that property. The re-hash is
                            // therefore a no-op for the current set of
                            // hash inputs but stays in place to keep
                            // the invariant holding if a future
                            // revision lifts the serde(skip) and brings
                            // the digest into the hash domain.
                            after_spec = with_hash(strip_hash(after_spec));
                        } else {
                            tracing::warn!(
                                runner = name.as_str(),
                                "X-Ghars-Runsvc-Sha256 annotation missing from \
                                 discovered 00-ghars.conf; refusing in-place \
                                 update path and forcing recreate so config.sh \
                                 mints a fresh trusted digest (SEC-02)."
                            );
                            runsvc_integrity_recreate = true;
                        }
                    }

                    // BATCH C / Part 2 / item 7: Stage 2 — re-render
                    // the desired spec and diff drop-in bodies against
                    // the discovered drop-ins on disk. A change
                    // confined to drop-in bodies (memory_max, proxy,
                    // hooks, hardening, allowed_cpus, ...) is in-place
                    // safe; a change that touches the recreate-bound
                    // annotations falls through to Stage 1 above.
                    let rendered = match crate::systemd::render_runner_unit(&after_spec) {
                        Ok(r) => r,
                        Err(e) => {
                            return Err(e);
                        }
                    };

                    let mut field_changes: Vec<FieldChange> = Vec::new();
                    let mut recreate_reasons = classify_recreate_reasons_from_annotations(
                        &annotations,
                        &after_spec,
                        &mut field_changes,
                    );

                    // #289 (revised): if runsvc_sha256 recovery failed
                    // above, force recreate. Pushed AFTER the
                    // classifier so the typed reasons (url, labels, …)
                    // still appear when those fields ALSO changed; this
                    // entry just guarantees the recreate path runs
                    // regardless.
                    if runsvc_integrity_recreate && !recreate_reasons.contains(&"runsvc_integrity")
                    {
                        recreate_reasons.push("runsvc_integrity");
                    }

                    // Stage 2: drop-in body diff. Compare each rendered
                    // basename's body against the discovered body.
                    // Iterate over the union (BTreeMap key sorted) so
                    // we catch both newly-added and removed drop-ins.
                    let mut drop_in_changes: Vec<DropInChange> = Vec::new();
                    let mut all_basenames: BTreeSet<&str> = BTreeSet::new();
                    for k in rendered.drop_ins.keys() {
                        all_basenames.insert(k.as_str());
                    }
                    for k in discovered.drop_ins.keys() {
                        all_basenames.insert(k.as_str());
                    }
                    for basename in all_basenames {
                        let in_rendered = rendered.drop_ins.get(basename);
                        let in_disk = discovered.drop_ins.get(basename);
                        let kind = match (in_rendered, in_disk) {
                            (Some(after), Some(before)) if after == before => {
                                DropInChangeKind::Preserved
                            }
                            (Some(after), Some(before)) => DropInChangeKind::Modified {
                                before: before.clone(),
                                after: after.clone(),
                            },
                            (Some(after), None) => DropInChangeKind::Created {
                                after: after.clone(),
                            },
                            (None, Some(before)) => DropInChangeKind::Removed {
                                before: before.clone(),
                            },
                            (None, None) => unreachable!("union iteration"),
                        };
                        drop_in_changes.push(DropInChange {
                            basename: basename.to_owned(),
                            change: kind,
                        });
                    }

                    // BATCH C / C-1 + C-6 + #295: classify as
                    // in-place when ANY managed non-`00-ghars.conf`
                    // drop-in shows a body change of one of three
                    // positively-named shapes: Created, Modified, or
                    // Removed.
                    //
                    // Gates (all three must hold for a change entry to
                    // count as in-place evidence):
                    //   1. basename != "00-ghars.conf" — its body
                    //      always changes when spec_hash changes
                    //      (carries the `X-Ghars-Spec-Hash`
                    //      annotation), so counting it would mask
                    //      recreate-class changes whose only signal
                    //      IS the hash (e.g. runner_sha256,
                    //      runner_tarball — both spec-hash inputs
                    //      that don't surface in any other drop-in
                    //      body).
                    //   2. basename ∈ MANAGED_DROP_IN_BASENAMES (C-6
                    //      / #297) — operator drop-ins (99-*.conf
                    //      from `systemctl edit`, anything outside
                    //      the ghars-managed numbering) are NOT
                    //      in-place evidence. Without this gate, an
                    //      operator-edited `99-operator.conf` whose
                    //      body happens to differ from one apply to
                    //      the next would mask a co-occurring
                    //      recreate-class field change (e.g. labels,
                    //      runner_version) that has no
                    //      annotation source — the in-place path
                    //      would silently swallow the recreate-
                    //      class change AND blow away the operator
                    //      override during the in-place rewrite
                    //      (apply.rs preserves operator drop-ins
                    //      but not their content if the apply path
                    //      runs at all). Filtering to MANAGED here
                    //      keeps unmanaged drop-ins out of the
                    //      classification signal where they don't
                    //      belong.
                    //   3. matches Created | Modified | Removed
                    //      (#295) — three real in-place signals
                    //      named positively rather than `!Preserved`
                    //      so a future variant added to
                    //      `DropInChangeKind` doesn't silently flip
                    //      classification semantics. Preserved bytes
                    //      match on both sides (no edit). Created /
                    //      Removed each map to a per-field-family
                    //      toggle: enabling `[proxy]` Creates
                    //      `60-proxy.conf` from nothing, and clearing
                    //      `memory_max` Removes `10-memory.conf`.
                    //      Both are in-place updates per design
                    //      Part 3.
                    let any_drop_in_modified = drop_in_changes.iter().any(|c| {
                        c.basename != "00-ghars.conf"
                            && crate::state::MANAGED_DROP_IN_BASENAMES
                                .contains(&c.basename.as_str())
                            && matches!(
                                c.change,
                                DropInChangeKind::Created { .. }
                                    | DropInChangeKind::Modified { .. }
                                    | DropInChangeKind::Removed { .. }
                            )
                    });

                    // BATCH C / Part 2 / item 8: rename
                    // `spec_hash_mismatch` → `uncovered`. Fires only
                    // when hashes differ AND Stage 1 found neither
                    // a recreate reason NOR a non-recreate FieldChange
                    // (e.g. auth_name; #306) AND Stage 2 found nothing
                    // — which should be unreachable in a deterministic
                    // renderer. Log tracing::warn! so we surface
                    // coverage gaps.
                    //
                    // #306 / item 3: gate on `field_changes.is_empty()`
                    // alongside `recreate_reasons.is_empty()`.
                    // classify_recreate_reasons_from_annotations now
                    // records a FieldChange for auth_name without
                    // pushing a recreate reason (auth-name change is
                    // in-place per design Part 3). Without the
                    // field_changes gate, every auth-name-only change
                    // would fall through to the uncovered recreate
                    // fallback even though the classifier did detect
                    // it.
                    if !hashes_equal
                        && recreate_reasons.is_empty()
                        && field_changes.is_empty()
                        && !any_drop_in_modified
                    {
                        tracing::warn!(
                            runner = name.as_str(),
                            discovered_hash = discovered.spec_hash.as_str(),
                            desired_hash = after_spec.spec_hash.as_str(),
                            "BATCH C uncovered fallback: spec_hash differs but neither Stage 1 \
                             (annotation diff) nor Stage 2 (drop-in body diff) detected the change. \
                             This indicates a coverage gap in classify_recreate_reasons or a non-\
                             deterministic renderer. Falling back to recreate."
                        );
                        recreate_reasons.push("uncovered");
                    }

                    let requires_recreate = !recreate_reasons.is_empty();

                    // #260: classify why this update fired.
                    //   - hashes differ → operator changed the config
                    //   - on-disk drift → out-of-band edit
                    //   - both → both signals fired
                    //
                    // #333: the (false, false) arm is logically
                    // unreachable — the enclosing `if hashes_equal &&
                    // in_sync` short-circuit at the NoOp branch above
                    // ensures at least one of the two flags is false
                    // when control reaches here. debug_assert! pins
                    // that invariant in dev/CI builds; the release
                    // fallback returns SpecChangedAndDriftDetected so
                    // the operator sees the most-informative label
                    // (and a tracing::warn) rather than the process
                    // crashing on a coverage gap.
                    let drift_cause = match (!hashes_equal, !in_sync) {
                        (true, true) => DriftCause::SpecChangedAndDriftDetected,
                        (true, false) => DriftCause::SpecChanged,
                        (false, true) => DriftCause::DriftDetected,
                        (false, false) => {
                            debug_assert!(
                                false,
                                "drift_cause (false, false) reached for runner {name}: \
                                 NoOp short-circuit at the intersection branch should have \
                                 filtered this case",
                            );
                            tracing::warn!(
                                runner = name.as_str(),
                                "drift_cause classifier reached the unreachable \
                                 (hashes_equal=true, in_sync=true) arm — defaulting to \
                                 SpecChangedAndDriftDetected. This indicates a NoOp gating \
                                 bug; please file a ghars issue."
                            );
                            DriftCause::SpecChangedAndDriftDetected
                        }
                    };

                    // BATCH C item 9 / fix #216: populate
                    // effective_unit_text + drop_ins on RunnerPlan
                    // from the rendered output we already computed
                    // above. apply.rs's in-place rewrite path consumes
                    // these directly.
                    let after_plan = RunnerPlan {
                        spec_hash: after_spec.spec_hash.clone(),
                        spec: after_spec,
                        resolved_release: None,
                        effective_unit_text: rendered.template,
                        drop_ins: rendered.drop_ins,
                    };

                    // Recreate path collapses drop-in diff (the path
                    // is "rm + mkdir + write all from scratch", so
                    // per-basename diff isn't actionable). In-place
                    // path keeps the per-drop-in diff for the operator.
                    let drop_in_changes_payload = if requires_recreate {
                        Vec::new()
                    } else {
                        drop_in_changes
                    };

                    actions.push(Action::UpdateRunner(RunnerDelta {
                        identity: reconstruct_identity(name, discovered, paths),
                        after: after_plan,
                        requires_recreate,
                        recreate_reasons,
                        drift_cause,
                        field_changes,
                        drop_in_changes: drop_in_changes_payload,
                        // #271: thread the discovered caches list
                        // through to apply.rs so it can compute the
                        // group-membership diff. Source is the same
                        // 00-ghars.conf body the rest of Stage 1 reads
                        // from.
                        //
                        // Sort `before_caches` so operator-facing
                        // surfaces (--diff output, plan JSON, error
                        // messages that name "removed pools") see a
                        // canonical alphabetical order regardless of
                        // the order the on-disk X-Ghars-Caches=
                        // annotation happened to be written in. Apply
                        // collects this Vec into a BTreeSet at
                        // apply.rs::execute_update_runner before
                        // computing the gpasswd diff, so sorting at
                        // this population site is correctness-neutral
                        // for the membership reconciliation; it only
                        // affects display order for downstream
                        // consumers that iterate the Vec directly.
                        before_caches: annotations.caches.as_ref().map(|v| {
                            let mut sorted = v.clone();
                            sorted.sort_unstable();
                            sorted
                        }),
                        // #468: snapshot the discovered drop-in
                        // basenames (BTreeMap keys, already
                        // alphabetically ordered) so the recreate
                        // `--diff` path can show operator-visible
                        // drop-ins (e.g. `99-custom.conf`) that the
                        // recreate is about to delete. Always Some
                        // here — `discovered` is in scope and its
                        // `drop_ins` map is the authoritative
                        // pre-update on-disk view.
                        before_drop_in_basenames: Some(
                            discovered
                                .drop_ins
                                .keys()
                                .cloned()
                                .collect(),
                        ),
                    }));
                }
            }
            (false, false) => {
                // #376 (symmetric with #333 and #369): logically
                // unreachable — `union` is built as
                // `actual.union(&desired)` so every name in the loop is
                // in at least one set; `(false, false)` would mean a
                // name appeared in the union but neither input, which
                // contradicts BTreeSet semantics. debug_assert! pins
                // the invariant in dev/CI; the release fallback emits
                // no action and logs a tracing::warn so a coverage
                // gap surfaces in operator logs without crashing the
                // plan.
                debug_assert!(
                    false,
                    "runner '{name}' appeared in union but neither in_actual nor in_desired: \
                     BTreeSet::union semantics violated",
                );
                tracing::warn!(
                    runner = name.as_str(),
                    "runner classifier reached the unreachable \
                     (in_actual=false, in_desired=false) arm — emitting no action. \
                     This indicates a BTreeSet::union invariant violation; please \
                     file a ghars issue."
                );
            }
        }
    }

    // Step 9: orphans surfaced upstream by callers that have both
    // sides of the comparison (state.discover itself does NOT
    // populate orphans because it lacks the desired set; see the
    // ActualState doc). Treated identically to (false, true) above
    // when present.
    for orphan in &actual.orphans {
        actions.push(Action::RemoveRunner(RunnerIdentity {
            name: orphan.name.clone(),
            url: String::new(),
            auth_name: String::new(),
            prefix: paths.state_dir.clone(),
            user: format!(
                "{prefix}{name}",
                prefix = crate::validators::RUNNER_USER_PREFIX,
                name = orphan.name,
            ),
        }));
    }

    // Step 8: cache-pool diffs. #201 added actual.cache_pools so we
    // can now diff desired vs actual instead of always emitting
    // CreateCachePool. Three branches:
    //   - desired ∧ ¬actual                      → CreateCachePool
    //   - desired ∧ actual ∧ spec_hash differs   → UpdateCachePool
    //   - actual ∧ ¬desired                      → RemoveCachePool
    //   - desired ∧ actual ∧ spec_hash matches   → no-op (in-sync)
    //
    // BTreeMap ordering (alphabetical by pool name) is preserved so
    // plan output stays deterministic across runs.
    let referenced_pools = collect_referenced_cache_pools(&desired);
    let actual_pool_names: BTreeSet<&str> = actual.cache_pools.keys().map(String::as_str).collect();
    let desired_pool_names: BTreeSet<&str> = referenced_pools.keys().map(String::as_str).collect();
    let pool_union: BTreeSet<&str> = actual_pool_names
        .union(&desired_pool_names)
        .copied()
        .collect();
    for pool_name in pool_union {
        let in_desired = desired_pool_names.contains(pool_name);
        let in_actual = actual_pool_names.contains(pool_name);
        match (in_desired, in_actual) {
            (true, false) => {
                let spec = referenced_pools
                    .get(pool_name)
                    .expect("name was in desired_pool_names");
                actions.push(Action::CreateCachePool(into_cache_pool_plan(
                    pool_name.to_owned(),
                    spec,
                    &config_source,
                )?));
            }
            (true, true) => {
                let spec = referenced_pools
                    .get(pool_name)
                    .expect("name was in desired_pool_names");
                let plan = into_cache_pool_plan(pool_name.to_owned(), spec, &config_source)?;
                let actual_pool = actual
                    .cache_pools
                    .get(pool_name)
                    .expect("name was in actual_pool_names");
                // #299: also consult the discovered drift signal so
                // an operator-added unmanaged drop-in (e.g.
                // `99-tuning.conf`) triggers UpdateCachePool even when
                // the spec_hash matches. Mirrors the runner-side
                // pattern at the per-runner intersection branch above,
                // which gates NoOp on `hashes_equal && in_sync`.
                // Without this, drift on cache pools is invisible to
                // plan output until the operator also edits the
                // managed body.
                let pool_in_sync = matches!(actual_pool.drift, Drift::InSync);
                if plan.spec_hash != actual_pool.spec_hash || !pool_in_sync {
                    // F79i invariant (design Part 17 ~line 5060):
                    // pool-kind change is a runner-membership no-op.
                    // The per-pool group is `ghars-cache-NAME` —
                    // parameterized by pool name only, NOT by kinds.
                    // Group identity is unchanged across the update,
                    // so runners enrolled at create-time retain valid
                    // membership. The Delta therefore carries no
                    // `referencing_users` field; apply just rewrites
                    // the drop-in + restarts the unit. The
                    // runner-caches-list-change case (a runner's
                    // `caches = [...]` set in TOML changed) IS a
                    // separate apply path handled by
                    // execute_update_runner via usermod.
                    actions.push(Action::UpdateCachePool(CachePoolDelta {
                        binding: plan.binding,
                        drop_in_body: plan.drop_in_body,
                        spec_hash: plan.spec_hash,
                    }));
                }
                // Otherwise in-sync: emit no action. NoOp is reserved
                // for placeholder actions, not "this resource is fine".
            }
            (false, true) => {
                actions.push(Action::RemoveCachePool(pool_name.to_owned()));
            }
            (false, false) => {
                // #369 (symmetric with #333): logically unreachable —
                // `pool_union` is built as `actual.union(desired)` so
                // every name in the loop is in at least one set;
                // `(false, false)` would mean a name appeared in the
                // union but neither input, which contradicts BTreeSet
                // semantics. debug_assert! pins the invariant in
                // dev/CI; the release fallback emits no action and
                // logs a tracing::warn so a coverage gap surfaces in
                // operator logs without crashing the apply.
                debug_assert!(
                    false,
                    "cache pool '{pool_name}' appeared in pool_union but neither in_desired \
                     nor in_actual: BTreeSet::union semantics violated",
                );
                tracing::warn!(
                    pool = pool_name,
                    "cache pool classifier reached the unreachable \
                     (in_desired=false, in_actual=false) arm — emitting no action. \
                     This indicates a BTreeSet::union invariant violation; please \
                     file a ghars issue."
                );
            }
        }
    }

    Ok(Plan { actions, warnings })
}

fn with_hash(mut spec: EffectiveRunnerSpec) -> EffectiveRunnerSpec {
    let hash = spec_hash(&spec);
    spec.spec_hash = hash;
    spec
}

/// Clear the spec_hash so it can be re-computed. Used by the
/// in-place update path after mutating a field that *might* be a
/// hash input on some future revision (e.g. `runsvc_sha256`, which is
/// `#[serde(skip)]` today and therefore NOT a hash input). Re-call
/// `with_hash` afterward.
fn strip_hash(mut spec: EffectiveRunnerSpec) -> EffectiveRunnerSpec {
    spec.spec_hash.clear();
    spec
}

/// Pull `X-Ghars-Runsvc-Sha256` out of a `00-ghars.conf` body.
/// Returns `None` if the drop-in or annotation is absent. Used by the
/// in-place update path to preserve the install-phase digest across
/// re-renders (BATCH C / phd1 finding #10).
///
/// The annotation lives in `[Service]` per design Part 17 — that's
/// where `crate::systemd::render_identity` emits it (when
/// `spec.runsvc_sha256` is non-empty, the renderer appends a
/// `[Service]` section with the line). `crate::state::extract_x_ghars`
/// is restricted to `[Unit]`, so this lookup MUST go through
/// [`crate::state::extract_x_ghars_value`] with
/// [`crate::state::SystemdSection::Service`] to find the digest.
/// Without this section selection the lookup below would return
/// `None` for every real 00-ghars.conf and the in-place update at
/// the call site emitted a freshly-rendered drop-in without the
/// annotation, which would fail-stop runsvc-wrapper's SEC-02
/// trampoline at the next runner restart with ANNOTATION_MISSING.
fn extract_runsvc_sha256(drop_ins: &BTreeMap<String, String>) -> Option<String> {
    let body = drop_ins.get("00-ghars.conf")?;
    // #327: point-lookup via extract_x_ghars_value avoids the full
    // Vec<(String, String)> allocation we'd pay for the bulk
    // extract_x_ghars_in_section call followed by a single-key search.
    let v = crate::state::extract_x_ghars_value(
        body,
        crate::state::SystemdSection::Service,
        "X-Ghars-Runsvc-Sha256",
    )?;
    if v.is_empty() { None } else { Some(v) }
}

/// Build a RunnerPlan from an effective spec, computing the spec_hash
/// (if not already set) and rendering the unit text + drop-ins. Closes
/// #216 — RunnerPlan now carries the rendered bytes that apply.rs
/// writes to disk verbatim, instead of re-rendering.
fn into_runner_plan(spec: EffectiveRunnerSpec) -> Result<RunnerPlan> {
    let spec_with_hash = if spec.spec_hash.is_empty() {
        with_hash(spec)
    } else {
        spec
    };
    let rendered = crate::systemd::render_runner_unit(&spec_with_hash)?;
    Ok(RunnerPlan {
        spec_hash: spec_with_hash.spec_hash.clone(),
        spec: spec_with_hash,
        resolved_release: None,
        effective_unit_text: rendered.template,
        drop_ins: rendered.drop_ins,
    })
}

fn into_cache_pool_plan(
    name: String,
    pool: &CachePoolSpec,
    config_source: &str,
) -> Result<CachePoolPlan> {
    let binding = EffectiveCacheBinding {
        name,
        kinds: pool.kinds.clone(),
        size: pool.size.clone(),
        mode: pool.mode,
        trust_zone: pool.trust_zone.clone(),
    };
    let spec_hash = cache_pool_hash(&binding);
    let drop_in_body = crate::systemd::render_cache_drop_in(&binding, config_source, &spec_hash)?;
    Ok(CachePoolPlan {
        binding,
        drop_in_body,
        spec_hash,
    })
}

fn cache_pool_hash(binding: &EffectiveCacheBinding) -> String {
    use sha2::{Digest, Sha256};
    let value = serde_json::to_value(binding)
        .expect("EffectiveCacheBinding must be serde_json-serializable");
    let json =
        serde_json::to_string(&value).expect("serde_json::Value always serializes to a string");
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn collect_referenced_cache_pools(
    desired: &BTreeMap<String, EffectiveRunnerSpec>,
) -> BTreeMap<String, CachePoolSpec> {
    // Dedup by pool name. BTreeMap key ordering produces alphabetical
    // emit order in plan_from (matches the runner phase's
    // determinism guarantee).
    let mut out: BTreeMap<String, CachePoolSpec> = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for spec in desired.values() {
        for binding in &spec.caches {
            if !seen.insert(binding.name.clone()) {
                continue;
            }
            // Reconstruct CachePoolSpec from the binding (lossless —
            // every field round-trips).
            out.insert(
                binding.name.clone(),
                CachePoolSpec {
                    kinds: binding.kinds.clone(),
                    size: binding.size.clone(),
                    mode: binding.mode,
                    trust_zone: binding.trust_zone.clone(),
                },
            );
        }
    }
    out
}

fn reconstruct_identity(
    name: &str,
    discovered: &DiscoveredRunner,
    paths: &Paths,
) -> RunnerIdentity {
    // Annotations live in `00-ghars.conf` drop-in body, not in the
    // template. parse_user_from_unit / parse_working_directory_from_unit
    // continue to read on_disk_unit_text because User= and
    // WorkingDirectory= ARE in the [Service] section of the template
    // (or operator-edited unit body) — those are NOT X-Ghars-* keys.
    //
    // The unit body comes from `crate::systemd::runner_template_text`
    // which contains literal `%i` specifiers (systemd substitutes
    // these at unit-parse time, but state.rs reads the file bytes
    // verbatim). Substitute `%i` → instance name here so callers see
    // the resolved values rather than the template form. Without this,
    // apply.rs::execute_remove_runner would `userdel ghars-%i` which
    // is not a real user (SEC-27 per-runner UID is `ghars-INSTANCE`).
    let annotations = DiscoveredAnnotations::from_discovered(discovered);
    let user = parse_user_from_unit(&discovered.on_disk_unit_text)
        .map(|u| u.replace("%i", name))
        .unwrap_or_else(|| {
            format!(
                "{prefix}{name}",
                prefix = crate::validators::RUNNER_USER_PREFIX,
            )
        });
    let prefix = parse_working_directory_from_unit(&discovered.on_disk_unit_text)
        .map(|wd| Utf8PathBuf::from(wd.as_str().replace("%i", name)))
        .and_then(|wd| wd.parent().map(Utf8Path::to_path_buf))
        .unwrap_or_else(|| paths.state_dir.clone());
    RunnerIdentity {
        name: name.to_owned(),
        url: annotations.url.unwrap_or_default(),
        auth_name: annotations.auth_name.unwrap_or_default(),
        prefix,
        user,
    }
}

fn parse_user_from_unit(unit_text: &str) -> Option<String> {
    // Find `User=NAME` (first occurrence in any section). Drop-ins
    // can override at apply-time, but for identity reconstruction the
    // first hit is sufficient — apply.rs's `User=` lookup is by
    // discovered runner home directory anyway.
    for line in unit_text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("User=") {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn parse_working_directory_from_unit(unit_text: &str) -> Option<Utf8PathBuf> {
    for line in unit_text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("WorkingDirectory=") {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(Utf8PathBuf::from(value));
            }
        }
    }
    None
}

fn lower_to_effective(
    runner: &RunnerSpec,
    config: &Config,
    host_arch: Arch,
    config_source: String,
    slot_idx: usize,
    warnings: &mut Vec<String>,
) -> Result<EffectiveRunnerSpec> {
    // Auth resolution.
    let auth_name = runner
        .auth
        .clone()
        .or_else(|| config.defaults.auth.clone())
        .ok_or_else(|| {
            GharsError::Validation(
                format!(
                    "runner '{}' has no auth and no [defaults] auth",
                    runner.name
                ),
                "set `auth = \"NAME\"` on the runner or in [defaults]".into(),
            )
        })?;
    if !config.auth.contains_key(&auth_name) {
        return Err(GharsError::Validation(
            format!(
                "runner '{}' references unknown auth '{auth_name}'",
                runner.name
            ),
            format!("declare an [auth.{auth_name}] block or fix the auth reference"),
        ));
    }

    // Cache resolution.
    let mut caches: Vec<EffectiveCacheBinding> = Vec::with_capacity(runner.caches.len());
    let runner_zone = if runner.trust_zone.is_empty() {
        DEFAULT_TRUST_ZONE
    } else {
        runner.trust_zone.as_str()
    };
    for cache_name in &runner.caches {
        let pool = config.cache_pools.get(cache_name).ok_or_else(|| {
            GharsError::Validation(
                format!(
                    "runner '{}' references unknown cache pool '{cache_name}'",
                    runner.name
                ),
                format!("declare a [cache_pools.{cache_name}] block or fix the caches list"),
            )
        })?;
        if pool.trust_zone != runner_zone {
            return Err(GharsError::Validation(
                format!(
                    "runner '{}' (trust_zone='{runner_zone}') cannot reference \
                     cache_pool '{cache_name}' (trust_zone='{}')",
                    runner.name, pool.trust_zone
                ),
                "split into separate pools or align trust_zones (SEC-03)".into(),
            ));
        }
        caches.push(EffectiveCacheBinding {
            name: cache_name.clone(),
            kinds: pool.kinds.clone(),
            size: pool.size.clone(),
            mode: pool.mode,
            trust_zone: pool.trust_zone.clone(),
        });
    }
    // #371: caches form an unordered set (group memberships are
    // unordered, cache pools provide isolated services, and apply.rs
    // reconciles via BTreeSet diff). Sort by name so every downstream
    // consumer — `spec_hash`, `render_identity`'s X-Ghars-Caches line,
    // and `render_cache_pool`'s 30-cache-pool.conf body — sees a
    // canonical order. Without this, a TOML reorder
    // `["pool-b", "pool-a"]` → `["pool-a", "pool-b"]` would flip
    // spec_hash and rewrite the 30-cache-pool.conf drop-in even though
    // membership is identical, producing a spurious in-place
    // UpdateRunner. Cache names are ASCII-only per IDENTIFIER_REGEX
    // (validators.rs), so byte-wise `Ord` agrees with operator intent.
    caches.sort_by(|a, b| a.name.cmp(&b.name));

    // Network resolution. None ⇒ implicit Open. defaults.network is
    // the fallback; explicit `runner.network = "open"` is rejected by
    // schema validation upstream (#20 — `open` is reserved).
    let network_ref = runner
        .network
        .clone()
        .or_else(|| config.defaults.network.clone());
    let network_binding = match network_ref {
        Some(network_name) => {
            let spec = config.networks.get(&network_name).ok_or_else(|| {
                GharsError::Validation(
                    format!(
                        "runner '{}' references unknown network '{network_name}'",
                        runner.name
                    ),
                    format!(
                        "declare a [network.{network_name}] block or fix the network reference"
                    ),
                )
            })?;
            // Open mode entries are tolerated but produce no binding —
            // 40-network.conf is skipped.
            if matches!(spec.mode, NetworkMode::Open) {
                None
            } else {
                // Sequential /30 from the default 10.200.0.0/24 pool,
                // indexed by `slot_idx` (the runner's position in the
                // expanded list). 64 /30 slots in a /24 = 64 max
                // simultaneous netns runners under v0.1's hardcoded
                // pool. Open-mode runners still consume an index but
                // don't get a binding, so the slot is wasted; that
                // matches the team-lead's "use the runner's index in
                // the expanded list" directive (#195). Persistent
                // [defaults] netns_subnet config is design Part 9c
                // future scope.
                let subnet = netns_subnet_for_slot(slot_idx, &runner.name)?;
                Some(EffectiveNetworkBinding {
                    name: network_name,
                    spec: spec.clone(),
                    subnet,
                })
            }
        }
        None => None,
    };

    // Proxy: runner.proxy overrides config.proxy entirely.
    let proxy = runner.proxy.clone().or_else(|| config.proxy.clone());
    // Hooks: runner.hooks overrides config.hooks entirely.
    let hooks = runner.hooks.clone().or_else(|| config.hooks.clone());

    // Surface SEC-27 warning ONLY when the resolved user is shared
    // across runners. The effective user mirrors merge_defaults
    // precedence — runner.user wins over defaults.user, falling back
    // to the per-runner-secure default `ghars-{runner.name}`. That
    // single resolution captures every shared/safe outcome:
    //   - operator sets `runner.user = "ghars-foo"` for runner "foo"
    //     (per-runner-secure pin) ⇒ effective_user == per_runner_secure ⇒ no warn
    //   - operator sets `runner.user = "svc"` ⇒ different ⇒ warn
    //   - operator sets `defaults.user = "svc"` and no runner.user ⇒
    //     effective resolves to "svc" ⇒ warn
    //   - operator sets `defaults.user = "svc"` AND `runner.user =
    //     "ghars-foo"` for runner "foo" ⇒ runner.user wins, effective
    //     "ghars-foo" matches secure pattern ⇒ no warn (matches
    //     apply-time semantics; defaults.user is dead code for this
    //     runner)
    //   - nothing set ⇒ effective = per_runner_secure ⇒ no warn
    let per_runner_secure = format!(
        "{prefix}{name}",
        prefix = crate::validators::RUNNER_USER_PREFIX,
        name = runner.name,
    );
    let effective_user: &str = runner
        .user
        .as_deref()
        .or(config.defaults.user.as_deref())
        .unwrap_or(per_runner_secure.as_str());
    if effective_user != per_runner_secure {
        warnings.push(format!(
            "runner '{}' uses shared user '{effective_user}'; cross-runner \
             isolation disabled (SEC-27)",
            runner.name
        ));
    }

    Ok(merge_defaults(
        runner,
        &config.defaults,
        auth_name,
        caches,
        network_binding,
        proxy,
        hooks,
        host_arch,
        config_source,
    ))
}

fn host_arch() -> Arch {
    // Fallback when defaults.arch and runner.arch are both unset.
    // x86_64 is the v0.1 reference arch; aarch64 hosts override on
    // [defaults] per Part 4 example.
    if cfg!(target_arch = "aarch64") {
        Arch::Aarch64
    } else {
        Arch::X86_64
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::{AuthSpec, CacheKind, CacheMode, CachePoolSpec, EtcBindStyle, NetworkSpec};
    use crate::state::{ActualState, DiscoveredRunner, OrphanedUnit};
    use indexmap::IndexMap;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn pat_auth() -> IndexMap<String, AuthSpec> {
        let mut m = IndexMap::new();
        m.insert(
            "pat".into(),
            AuthSpec::Pat {
                token_env: Some("GHARS_PAT".into()),
                token_file: None,
            },
        );
        m
    }

    fn minimal_runner(name: &str) -> RunnerSpec {
        RunnerSpec {
            name: name.into(),
            count: None,
            url: format!("https://github.com/example/{name}"),
            auth: Some("pat".into()),
            labels: vec![],
            memory_max: None,
            runner_version: None,
            runner_sha256: None,
            runner_tarball: None,
            arch: None,
            user: None,
            prefix: None,
            caches: vec![],
            trust_zone: "default".into(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
        }
    }

    fn count_runner(name: &str, count: u32) -> RunnerSpec {
        let mut r = minimal_runner(name);
        r.count = Some(count);
        r
    }

    fn config_with_runners(runners: Vec<RunnerSpec>) -> Config {
        Config {
            defaults: Defaults::default(),
            auth: pat_auth(),
            cache_pools: IndexMap::new(),
            networks: IndexMap::new(),
            proxy: None,
            hooks: None,
            runners,
        }
    }

    fn empty_paths() -> Paths {
        Paths::default()
    }

    fn empty_actual() -> ActualState {
        ActualState::default()
    }

    fn cfg_source_default() -> String {
        Paths::default().config_dir.join("ghars.toml").to_string()
    }

    /// Build a `DiscoveredRunner` whose `00-ghars.conf` drop-in body
    /// carries the per-runner X-Ghars-* annotations matching `spec`.
    /// Used to drive the annotation-based recreate-reason classifier.
    ///
    /// `on_disk_unit_text` is the runner template body verbatim — that
    /// matches production: `state::discover` reads the unit file
    /// (`ghars-runner@INSTANCE.service`) which is the unmodified
    /// template, while the per-runner identity lives entirely in
    /// `drop_ins["00-ghars.conf"]` (the [Unit]-section X-Ghars-* lines
    /// emitted by `crate::systemd::render_identity`). Putting the
    /// annotations in `on_disk_unit_text` here would mask the
    /// production bug fixed by reading
    /// `DiscoveredAnnotations::from_discovered`.
    ///
    /// If `spec.runsvc_sha256` is empty, the fixture injects a stable
    /// fake digest so the rendered 00-ghars.conf carries a
    /// `[Service] X-Ghars-Runsvc-Sha256=` line. This mirrors the
    /// post-install steady state that `discover` would observe in
    /// production (apply.rs::execute_create_runner records the
    /// digest after config.sh writes runsvc.sh; subsequent
    /// `discover` reads the annotation back). Without this default,
    /// every fixture-built in-place test would trip the
    /// recreate-on-missing-digest path and surface as a recreate
    /// reason of `runsvc_integrity` rather than the in-place
    /// behavior the test is actually exercising. Tests that
    /// SPECIFICALLY want to exercise the missing-annotation path
    /// (e.g. plan_update_recreate_on_runsvc_integrity_when_annotation_missing)
    /// build the fixture with a different shape.
    fn discovered_for(name: &str, spec: &EffectiveRunnerSpec, drift: Drift) -> DiscoveredRunner {
        // Inject a stable fake runsvc_sha256 when the caller didn't
        // pin one. See doc above for rationale.
        let mut spec_for_render = spec.clone();
        if spec_for_render.runsvc_sha256.is_empty() {
            spec_for_render.runsvc_sha256 =
                "sha256:9999999999999999999999999999999999999999999999999999999999999999"
                    .to_owned();
        }
        let rendered = crate::systemd::render_runner_unit(&spec_for_render)
            .expect("test fixture: render_runner_unit must succeed for valid spec");
        DiscoveredRunner {
            name: name.to_owned(),
            spec_hash: spec.spec_hash.clone(),
            on_disk_unit_text: rendered.template,
            drop_ins: rendered.drop_ins,
            running: false,
            enabled: false,
            drift,
        }
    }

    // --- expand_counts --------------------------------------------------

    #[test]
    fn expand_counts_basic() {
        let cfg = config_with_runners(vec![count_runner("ci", 3)]);
        let out = expand_counts(&cfg).unwrap();
        let names: Vec<&str> = out.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["ci-1", "ci-2", "ci-3"]);
        assert!(out.iter().all(|r| r.count.is_none()));
    }

    #[test]
    fn expand_counts_explicit_only_passes_through() {
        let cfg = config_with_runners(vec![minimal_runner("a"), minimal_runner("b")]);
        let out = expand_counts(&cfg).unwrap();
        assert_eq!(
            out.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn expand_counts_count_one_kept_as_explicit() {
        let cfg = config_with_runners(vec![count_runner("solo", 1)]);
        let out = expand_counts(&cfg).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "solo");
        assert_eq!(out[0].count, None);
    }

    #[test]
    fn expand_counts_zero_count_skipped() {
        let cfg = config_with_runners(vec![count_runner("nothing", 0)]);
        let out = expand_counts(&cfg).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn expand_counts_auto_skips_explicit_collision() {
        // Per Part 4 example: `[[runner]] name = "ci" count = 10` plus
        // an explicit `[[runner]] name = "ci-7" memory_max = "16G"`
        // produces ci-1..ci-6, ci-8..ci-10 from the count block, with
        // ci-7 taken from the explicit block.
        let mut special = minimal_runner("ci-7");
        special.memory_max = Some("16G".into());
        let cfg = config_with_runners(vec![count_runner("ci", 10), special]);
        let out = expand_counts(&cfg).unwrap();
        let names: Vec<&str> = out.iter().map(|r| r.name.as_str()).collect();
        // Order matches source order: count-block expands in place,
        // then explicit ci-7 lands after. All 10 names present
        // exactly once (ci-7 from explicit, ci-1..ci-6 + ci-8..ci-10
        // from count).
        assert_eq!(names.len(), 10);
        let unique: HashSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), 10, "all 10 names unique: {names:?}");
        for i in 1..=10 {
            let expected = format!("ci-{i}");
            assert!(unique.contains(expected.as_str()), "missing {expected}");
        }
        // The explicit ci-7 carries the override; the count-block
        // generated entries don't.
        let ci7 = out.iter().find(|r| r.name == "ci-7").unwrap();
        assert_eq!(ci7.memory_max.as_deref(), Some("16G"));
    }

    #[test]
    fn expand_counts_cross_block_collision_errors() {
        let cfg = config_with_runners(vec![count_runner("shared", 2), count_runner("shared", 3)]);
        let err = expand_counts(&cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("collision"), "got: {msg}");
        assert!(msg.contains("shared-1"), "got: {msg}");
    }

    #[test]
    fn expand_counts_rejects_count_above_max() {
        let cfg = config_with_runners(vec![count_runner("big", MAX_COUNT + 1)]);
        let err = expand_counts(&cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("MAX_COUNT"), "got: {msg}");
    }

    #[test]
    fn expand_counts_rejects_overlong_generated_name() {
        // 64-char IDENTIFIER_MAX_LEN: 63-char prefix + "-1" suffix = 65 chars.
        // validate_identifier rejects first (length > 64); the wrapped
        // error mentions "identifier" via the count-expansion prefix.
        let prefix = "x".repeat(63);
        let cfg = config_with_runners(vec![count_runner(&prefix, 9)]);
        let err = expand_counts(&cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("identifier"), "got: {msg}");
    }

    /// #427: generated names that pass `validate_identifier` (length
    /// ≤ IDENTIFIER_MAX_LEN) but exceed `RUNNER_NAME_MAX_LEN` after
    /// the `-COUNT` suffix is appended must reject at expand_counts
    /// time. Catches the gap where validate_runner_names at
    /// load_config saw only the prefix (≤ 25) but expansion produced
    /// an over-cap name (e.g. 24-char prefix + "-12" = 27 chars).
    /// Pinned at plan-time per devadv-s5 finding (config-load can't
    /// catch this without computing max-suffix from `count`).
    #[test]
    fn expand_counts_rejects_generated_name_exceeding_runner_name_cap() {
        // 24-char prefix + "-10" (suffix length 3 since count >= 10)
        // = 27 chars > RUNNER_NAME_MAX_LEN (25). validate_identifier
        // accepts (27 ≤ 64); validate_runner_name rejects.
        let prefix = "x".repeat(24);
        let cfg = config_with_runners(vec![count_runner(&prefix, 10)]);
        let err = expand_counts(&cfg).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("runner-name validation"),
            "msg must come from runner-name layer (not identifier); got: {msg}"
        );
        assert!(
            msg.contains("count expansion"),
            "msg must scope to count expansion; got: {msg}"
        );
    }

    // --- netns_subnet_for_slot -----------------------------------------

    #[test]
    fn netns_subnet_for_slot_zero_is_pool_base() {
        let s = netns_subnet_for_slot(0, "x").unwrap();
        assert_eq!(s.to_string(), "10.200.0.0/30");
    }

    #[test]
    fn netns_subnet_for_slot_one_advances_by_four() {
        let s = netns_subnet_for_slot(1, "x").unwrap();
        assert_eq!(s.to_string(), "10.200.0.4/30");
    }

    #[test]
    fn netns_subnet_for_slot_two_advances_by_four() {
        let s = netns_subnet_for_slot(2, "x").unwrap();
        assert_eq!(s.to_string(), "10.200.0.8/30");
    }

    #[test]
    fn netns_subnet_for_slot_max_in_pool() {
        // Slot 63 = 10.200.0.252/30 — last /30 in the /24 pool.
        let s = netns_subnet_for_slot(63, "x").unwrap();
        assert_eq!(s.to_string(), "10.200.0.252/30");
    }

    #[test]
    fn netns_subnet_for_slot_overflow_errors() {
        let err = netns_subnet_for_slot(64, "buckos").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("exhausted"), "got: {msg}");
        assert!(msg.contains("buckos"), "got: {msg}");
    }

    #[test]
    fn netns_subnet_for_slot_distinct_slots_get_distinct_subnets() {
        // No two adjacent slots share addresses (#195: collision was
        // the original bug).
        let mut seen = std::collections::HashSet::new();
        for i in 0..NETNS_POOL_SLOTS {
            let s = netns_subnet_for_slot(i, "x").unwrap();
            assert!(
                seen.insert(s.to_string()),
                "slot {i} produced duplicate subnet"
            );
        }
        assert_eq!(seen.len(), NETNS_POOL_SLOTS);
    }

    // --- merge_defaults -------------------------------------------------

    /// labels concat + dedup + sort. defaults.labels first, then
    /// runner.labels, dedup, then sorted alphabetically (set-semantic
    /// for GitHub Actions registration). The contract is canonical
    /// sort because the runner's behavior is order-independent for
    /// matching workflow `runs-on:` selectors; local order-sensitivity
    /// would cause spurious recreate-class plans on cosmetic TOML
    /// reorders.
    #[test]
    fn merge_defaults_label_concat_dedup_sorted() {
        let runner = {
            let mut r = minimal_runner("buckos");
            r.labels = vec!["buck2".into(), "self-hosted".into()];
            r
        };
        let defaults = Defaults {
            labels: vec!["self-hosted".into(), "linux".into()],
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        // Concat-and-dedup yields {"self-hosted","linux","buck2"};
        // sort by name yields ["buck2","linux","self-hosted"].
        // Single "self-hosted" entry pins the dedup contract is still
        // honored (defaults sees it first; runner.labels would have
        // re-pushed it absent dedup).
        assert_eq!(eff.labels, vec!["buck2", "linux", "self-hosted"]);
    }

    #[test]
    fn merge_defaults_empty_labels_falls_back_to_name() {
        let runner = minimal_runner("solo");
        let defaults = Defaults::default();
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        assert_eq!(eff.labels, vec!["solo"]);
    }

    #[test]
    fn merge_defaults_runner_overrides_scalars() {
        let runner = {
            let mut r = minimal_runner("a");
            r.memory_max = Some("64G".into());
            r.runner_version = Some("2.300.0".into());
            r.runner_sha256 = Some("a".repeat(64));
            r.user = Some("alice".into());
            r.prefix = Some(Utf8PathBuf::from("/srv/runners"));
            r.allowed_cpus = Some("0-3".into());
            r.allowed_memory_nodes = Some("0".into());
            r.arch = Some(Arch::Aarch64);
            r
        };
        let defaults = Defaults {
            memory_max: Some("32G".into()),
            runner_version: Some("2.200.0".into()),
            runner_sha256: Some("b".repeat(64)),
            user: Some("bob".into()),
            prefix: Some(Utf8PathBuf::from("/var/lib/ghars")),
            arch: Some(Arch::X86_64),
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        assert_eq!(eff.memory_max.as_deref(), Some("64G"));
        assert_eq!(eff.runner_version.as_deref(), Some("2.300.0"));
        assert_eq!(eff.runner_sha256.as_deref(), Some(&*"a".repeat(64)));
        assert_eq!(eff.user, "alice");
        assert_eq!(eff.prefix, "/srv/runners");
        assert_eq!(eff.allowed_cpus.as_deref(), Some("0-3"));
        assert_eq!(eff.allowed_memory_nodes.as_deref(), Some("0"));
        assert_eq!(eff.arch, Arch::Aarch64);
    }

    #[test]
    fn merge_defaults_falls_back_to_defaults_when_runner_unset() {
        let runner = minimal_runner("a");
        let defaults = Defaults {
            memory_max: Some("32G".into()),
            runner_version: Some("2.200.0".into()),
            runner_sha256: Some("c".repeat(64)),
            user: Some("svc".into()),
            prefix: Some(Utf8PathBuf::from("/opt/ghars")),
            arch: Some(Arch::Aarch64),
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        assert_eq!(eff.memory_max.as_deref(), Some("32G"));
        assert_eq!(eff.runner_version.as_deref(), Some("2.200.0"));
        assert_eq!(eff.user, "svc");
        assert_eq!(eff.prefix, "/opt/ghars");
        assert_eq!(eff.arch, Arch::Aarch64);
    }

    #[test]
    fn merge_defaults_user_default_is_per_runner_secure_default() {
        // SEC-27: no user set anywhere ⇒ ghars-{name}.
        let runner = minimal_runner("buckos");
        let defaults = Defaults::default();
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        assert_eq!(eff.user, "ghars-buckos");
    }

    #[test]
    fn merge_defaults_prefix_default_under_var_lib_ghars() {
        let runner = minimal_runner("a");
        let defaults = Defaults::default();
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        assert_eq!(eff.prefix, "/var/lib/ghars");
    }

    #[test]
    fn merge_defaults_hardening_field_by_field() {
        let runner = {
            let mut r = minimal_runner("a");
            r.hardening = Hardening {
                kvm: Some(false),
                restrict_realtime: None,
                protect_control_groups: Some(true),
                restrict_suid_sgid: None,
                private_devices: None,
                private_ipc: Some(false),
                restrict_address_families: vec!["AF_UNIX".into()],
                extra_syscalls: vec!["clone3".into()],
                etc_bind_style: EtcBindStyle::Broad,
                bind_readonly_paths: None,
                extra_bind_paths: vec!["/opt/runner".into()],
                extra_capabilities: vec!["CAP_NET_RAW".into()],
            };
            r
        };
        let defaults = Defaults {
            hardening: Hardening {
                kvm: Some(true),
                restrict_realtime: Some(true),
                protect_control_groups: Some(false),
                restrict_suid_sgid: Some(true),
                private_devices: Some(true),
                private_ipc: Some(true),
                restrict_address_families: vec!["AF_INET".into()],
                extra_syscalls: vec!["mknodat".into()],
                etc_bind_style: EtcBindStyle::Curated,
                bind_readonly_paths: Some(vec!["/etc/passwd".into()]),
                extra_bind_paths: vec!["/etc/ssl".into()],
                extra_capabilities: vec!["CAP_KILL".into()],
            },
            ..Defaults::default()
        };

        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );

        // Runner-set wins.
        assert_eq!(eff.hardening.kvm, Some(false));
        assert_eq!(eff.hardening.protect_control_groups, Some(true));
        assert_eq!(eff.hardening.private_ipc, Some(false));
        // Runner unset ⇒ defaults wins.
        assert_eq!(eff.hardening.restrict_realtime, Some(true));
        assert_eq!(eff.hardening.restrict_suid_sgid, Some(true));
        assert_eq!(eff.hardening.private_devices, Some(true));
        // Vec runner non-empty ⇒ runner wins.
        assert_eq!(eff.hardening.restrict_address_families, vec!["AF_UNIX"]);
        assert_eq!(eff.hardening.extra_syscalls, vec!["clone3"]);
        // bind_readonly_paths runner None ⇒ defaults wins.
        assert_eq!(
            eff.hardening.bind_readonly_paths.as_deref(),
            Some(&[Utf8PathBuf::from("/etc/passwd")][..])
        );
        // extra_bind_paths additive (defaults first, then runner).
        assert_eq!(
            eff.hardening.extra_bind_paths,
            vec![
                Utf8PathBuf::from("/etc/ssl"),
                Utf8PathBuf::from("/opt/runner"),
            ]
        );
        // extra_capabilities additive (defaults first, then runner).
        assert_eq!(
            eff.hardening.extra_capabilities,
            vec!["CAP_KILL", "CAP_NET_RAW"]
        );
        assert_eq!(eff.hardening.etc_bind_style, EtcBindStyle::Broad);
    }

    #[test]
    fn merge_defaults_caches_threaded_verbatim() {
        let runner = minimal_runner("a");
        let defaults = Defaults::default();
        let caches = vec![EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Ccache, CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
        }];
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            caches.clone(),
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        assert_eq!(eff.caches, caches);
    }

    // --- spec_hash ------------------------------------------------------

    #[test]
    fn spec_hash_stable_across_clones() {
        let runner = minimal_runner("a");
        let defaults = Defaults::default();
        let spec = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        let h1 = spec_hash(&spec);
        let h2 = spec_hash(&spec.clone());
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
        assert_eq!(h1.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn spec_hash_idempotent_after_embedding() {
        let runner = minimal_runner("a");
        let defaults = Defaults::default();
        let mut spec = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        let h1 = spec_hash(&spec);
        spec.spec_hash = h1.clone();
        let h2 = spec_hash(&spec);
        assert_eq!(h1, h2);
    }

    #[test]
    fn spec_hash_changes_on_field_edit() {
        let runner = minimal_runner("a");
        let defaults = Defaults::default();
        let spec1 = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        let h1 = spec_hash(&spec1);

        let runner2 = {
            let mut r = minimal_runner("a");
            r.memory_max = Some("64G".into());
            r
        };
        let spec2 = merge_defaults(
            &runner2,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        let h2 = spec_hash(&spec2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn spec_hash_independent_of_embedded_hash_field() {
        let runner = minimal_runner("a");
        let defaults = Defaults::default();
        let mut spec_a = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        let mut spec_b = spec_a.clone();
        spec_a.spec_hash = "stale-A".into();
        spec_b.spec_hash = "stale-B".into();
        assert_eq!(spec_hash(&spec_a), spec_hash(&spec_b));
    }

    // --- plan_from ------------------------------------------------------

    #[test]
    fn plan_create_when_actual_empty() {
        let cfg = config_with_runners(vec![minimal_runner("buckos")]);
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        // 1 CreateRunner.
        let creates: Vec<&RunnerPlan> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::CreateRunner(rp) => Some(rp),
                _ => None,
            })
            .collect();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0].spec.name, "buckos");
        assert!(creates[0].spec_hash.starts_with("sha256:"));
    }

    #[test]
    fn plan_remove_orphans() {
        let cfg = config_with_runners(vec![]);
        let mut actual = empty_actual();
        actual.orphans.push(OrphanedUnit {
            name: "stale".into(),
        });
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let removes: Vec<&RunnerIdentity> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::RemoveRunner(id) => Some(id),
                _ => None,
            })
            .collect();
        assert_eq!(removes.len(), 1);
        assert_eq!(removes[0].name, "stale");
    }

    #[test]
    fn plan_remove_when_runner_in_actual_but_not_desired() {
        let cfg = config_with_runners(vec![]);
        let runner = minimal_runner("legacy");
        let mut spec = merge_defaults(
            &runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        spec.spec_hash = spec_hash(&spec);
        let mut actual = empty_actual();
        actual.runners.insert(
            "legacy".into(),
            discovered_for("legacy", &spec, Drift::InSync),
        );

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let removes: Vec<&RunnerIdentity> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::RemoveRunner(id) => Some(id),
                _ => None,
            })
            .collect();
        assert_eq!(removes.len(), 1);
        assert_eq!(removes[0].name, "legacy");
        assert_eq!(removes[0].url, "https://github.com/example/legacy");
        assert_eq!(removes[0].auth_name, "pat");
        assert_eq!(removes[0].user, "ghars-legacy");
    }

    #[test]
    fn plan_noop_when_in_sync_and_hashes_match() {
        let cfg = config_with_runners(vec![minimal_runner("a")]);
        let runner = &cfg.runners[0];
        let mut spec = merge_defaults(
            runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        spec.spec_hash = spec_hash(&spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &spec, Drift::InSync));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let noops: Vec<&str> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::NoOp(reason) => Some(reason.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(noops.len(), 1);
        assert!(noops[0].contains('a'));
    }

    #[test]
    fn plan_update_no_recreate_when_drift_unit_edited_with_matching_hash() {
        let cfg = config_with_runners(vec![minimal_runner("a")]);
        let runner = &cfg.runners[0];
        let mut spec = merge_defaults(
            runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        spec.spec_hash = spec_hash(&spec);

        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &spec, Drift::UnitEdited));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].identity.name, "a");
        // Hash matched → drift overwrite is in-place, no recreate.
        assert!(!updates[0].requires_recreate);
        assert!(updates[0].recreate_reasons.is_empty());
    }

    #[test]
    fn plan_update_recreate_on_url_change_via_annotations() {
        let cfg = config_with_runners(vec![minimal_runner("a")]);
        // Build a "before" effective spec whose URL differs.
        let mut old_runner = cfg.runners[0].clone();
        old_runner.url = "https://github.com/example/old".into();
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);

        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert!(updates[0].requires_recreate, "url change must recreate");
        assert!(
            updates[0].recreate_reasons.contains(&"url"),
            "got: {:?}",
            updates[0].recreate_reasons,
        );
    }

    #[test]
    fn plan_update_in_place_on_memory_max_change_via_drop_in_diff() {
        // BATCH C: memory_max change is in-place, not recreate. Stage 1
        // (annotation diff) finds nothing; Stage 2 (drop-in body diff)
        // sees 10-memory.conf body change between desired render and
        // discovered drop-ins. Result: requires_recreate=false,
        // drop_in_changes contains a Modified entry for 10-memory.conf.
        // Replaces the pre-BATCH-C "spec_hash_mismatch" fallback test
        // (which over-recreated for memory-only edits).
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.memory_max = Some("64G".into());
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.memory_max = Some("32G".into());
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);

        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert!(
            !updates[0].requires_recreate,
            "memory_max-only change must be in-place; got reasons {:?}",
            updates[0].recreate_reasons
        );
        assert!(
            updates[0].drop_in_changes.iter().any(|c| {
                c.basename == "10-memory.conf"
                    && matches!(c.change, DropInChangeKind::Modified { .. })
            }),
            "drop_in_changes must include 10-memory.conf Modified; got: {:?}",
            updates[0].drop_in_changes
        );
    }

    #[test]
    fn plan_update_recreate_on_runner_version_change_via_annotations() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.runner_version = Some("2.300.0".into());
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.runner_version = Some("2.200.0".into());
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);

        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert!(updates[0].requires_recreate);
        assert!(updates[0].recreate_reasons.contains(&"runner_version"));
    }

    /// #468 T6: end-to-end through `plan_from` — when discovered state
    /// carries an operator drop-in (e.g. `99-custom.conf`) plus the
    /// managed `00-ghars.conf`, the recreate-class RunnerDelta must
    /// surface `before_drop_in_basenames = Some([..])` containing BOTH
    /// basenames. Pins the construction-site contract at the
    /// intersection branch (plan.rs near the RunnerDelta builder):
    /// `discovered.drop_ins.keys()` is the authoritative pre-update
    /// view, and `Some` (never `None`) is emitted whenever
    /// `discovered` is in scope. The renderer relies on this to emit
    /// `- 99-custom.conf` under `--diff` so operators see what the
    /// recreate is about to delete. BTreeMap iteration order ⇒ Vec is
    /// already alphabetically sorted.
    #[test]
    fn plan_recreate_populates_before_drop_in_basenames_with_operator_drop_in() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.runner_version = Some("2.300.0".into());
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.runner_version = Some("2.200.0".into());
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);

        // Build the discovered runner from the old spec and inject an
        // operator drop-in (99-custom.conf) on top of the managed
        // 00-ghars.conf the fixture already produced.
        let mut discovered = discovered_for("a", &old_spec, Drift::InSync);
        discovered.drop_ins.insert(
            "99-custom.conf".into(),
            "[Service]\nEnvironment=OPERATOR_TUNING=1\n".into(),
        );
        let mut actual = empty_actual();
        actual.runners.insert("a".into(), discovered);

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert!(
            updates[0].requires_recreate,
            "runner_version change must recreate; got reasons {:?}",
            updates[0].recreate_reasons,
        );
        // Some(..), never None — `discovered` was in scope at plan time.
        let before = updates[0]
            .before_drop_in_basenames
            .as_ref()
            .expect("recreate path must populate before_drop_in_basenames as Some(..)");
        // Both the managed 00-ghars.conf and the operator's 99-custom.conf
        // are present, in BTreeMap-iteration (alphabetical) order.
        assert!(
            before.iter().any(|b| b == "00-ghars.conf"),
            "before set must include managed 00-ghars.conf; got: {before:?}",
        );
        assert!(
            before.iter().any(|b| b == "99-custom.conf"),
            "before set must include operator 99-custom.conf; got: {before:?}",
        );
        // Sorted: 00-ghars.conf must appear before 99-custom.conf.
        let pos_managed = before.iter().position(|b| b == "00-ghars.conf").unwrap();
        let pos_operator = before.iter().position(|b| b == "99-custom.conf").unwrap();
        assert!(
            pos_managed < pos_operator,
            "before_drop_in_basenames must be alphabetically sorted; got: {before:?}",
        );
    }

    // ---- #205: requires_recreate exhaustive field coverage ------------
    //
    // Per design Part 3 "requires_recreate field policy" table:
    //   recreate fields:  url, labels, runner_version, runner_sha256,
    //                     runner_tarball, user, prefix, arch, network
    //   in-place fields:  auth (auth_name), memory_max, caches,
    //                     trust_zone, hardening.*, allowed_cpus,
    //                     allowed_memory_nodes, proxy, hooks
    //   identity (Remove+Create): name
    //
    // `classify_recreate_reasons_from_annotations` now detects every
    // recreate-class field from its X-Ghars-* annotation directly:
    // url (X-Ghars-Runner-Url), runner_version
    // (X-Ghars-Effective-Version), labels (X-Ghars-Labels), arch
    // (X-Ghars-Arch), user (X-Ghars-User), prefix (X-Ghars-Prefix),
    // runner_sha256 (X-Ghars-Runner-Sha256), runner_tarball
    // (X-Ghars-Runner-Tarball-Hash), network (X-Ghars-Network-Mode).
    // The same classifier records FieldChange entries (without
    // pushing a recreate reason) for the in-place fields that have
    // their own annotation and need operator-visible diffing:
    // auth_name (X-Ghars-Auth-Name), trust_zone (X-Ghars-Trust-Zone),
    // caches (X-Ghars-Caches). The remaining in-place fields
    // (memory_max, hardening.*, allowed_cpus, ...) are detected by
    // the Stage 2 drop-in body diff and surface as `drop_in_changes`,
    // not FieldChange entries. A spec-hash mismatch with no Stage 1
    // reason and no Stage 2 evidence falls through to the
    // conservative `"uncovered"` recreate reason (renamed from
    // `spec_hash_mismatch` in BATCH C / Part 2 item 8). These tests
    // pin each row of the table.

    fn anns_with(url: &str, runner_version: Option<&str>) -> DiscoveredAnnotations {
        DiscoveredAnnotations {
            url: Some(url.into()),
            runner_version: runner_version.map(|v| v.into()),
            ..DiscoveredAnnotations::default()
        }
    }

    fn spec_with_url(name: &str, url: &str) -> EffectiveRunnerSpec {
        let mut r = minimal_runner(name);
        r.url = url.into();
        merge_defaults(
            &r,
            &Defaults::default(),
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        )
    }

    #[test]
    fn classify_recreate_url_change_emits_url_reason() {
        let anns = anns_with("https://github.com/example/old", None);
        let desired = spec_with_url("a", "https://github.com/example/new");
        let mut _changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
        assert_eq!(reasons, vec!["url"]);
    }

    #[test]
    fn classify_recreate_url_unchanged_no_reason() {
        let anns = anns_with("https://github.com/example/repo", None);
        let desired = spec_with_url("a", "https://github.com/example/repo");
        let mut _changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
        assert!(reasons.is_empty(), "got: {reasons:?}");
    }

    #[test]
    fn classify_recreate_runner_version_change_emits_runner_version_reason() {
        let anns = anns_with("https://github.com/example/repo", Some("2.300.0"));
        let mut desired = spec_with_url("a", "https://github.com/example/repo");
        desired.runner_version = Some("2.334.0".into());
        let mut _changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
        assert_eq!(reasons, vec!["runner_version"]);
    }

    #[test]
    fn classify_recreate_runner_version_unchanged_no_reason() {
        let anns = anns_with("https://github.com/example/repo", Some("2.334.0"));
        let mut desired = spec_with_url("a", "https://github.com/example/repo");
        desired.runner_version = Some("2.334.0".into());
        let mut _changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
        assert!(reasons.is_empty(), "got: {reasons:?}");
    }

    #[test]
    fn classify_recreate_no_annotations_no_reasons() {
        // Discovered unit predates annotation marker (older ghars or
        // operator-installed). Function falls through silently — the
        // spec-hash mismatch path picks up the slack.
        let anns = DiscoveredAnnotations::default();
        let desired = spec_with_url("a", "https://github.com/example/repo");
        let mut _changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
        assert!(reasons.is_empty(), "got: {reasons:?}");
    }

    #[test]
    fn classify_recreate_url_and_version_both_changed() {
        let anns = anns_with("https://github.com/example/old", Some("2.300.0"));
        let mut desired = spec_with_url("a", "https://github.com/example/new");
        desired.runner_version = Some("2.334.0".into());
        let mut _changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut _changes);
        assert!(reasons.contains(&"url"), "got: {reasons:?}");
        assert!(reasons.contains(&"runner_version"), "got: {reasons:?}");
    }

    /// labels change is RECREATE per design table. BATCH C added
    /// X-Ghars-Labels annotation so labels are now Stage 1 detectable
    /// — recreate fires with reason "labels" (not the old
    /// "spec_hash_mismatch" / "uncovered" fallback).
    #[test]
    fn plan_update_recreate_on_labels_change() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.labels = vec!["new-label".into()];
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.labels = vec!["old-label".into()];
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert!(updates[0].requires_recreate);
        assert!(
            updates[0].recreate_reasons.contains(&"labels"),
            "labels change must produce a typed `labels` reason now that X-Ghars-Labels is annotated; got: {:?}",
            updates[0].recreate_reasons
        );
        assert!(
            updates[0].field_changes.iter().any(|c| c.path == "labels"),
            "field_changes must include a labels entry; got: {:?}",
            updates[0].field_changes
        );
    }

    /// memory_max change is IN-PLACE per design table. BATCH C added
    /// Stage 2 drop-in body diff so the plan now correctly classifies
    /// memory_max-only edits as in-place (no recreate). Replaces the
    /// pre-BATCH-C "conservatively recreate" assertion which over-
    /// recreated to avoid under-recreating; with the body-diff stage
    /// we can localize the change to 10-memory.conf and skip the
    /// recreate.
    #[test]
    fn plan_update_in_place_on_memory_max_change() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.memory_max = Some("110G".into());
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.memory_max = Some("64G".into());
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert!(
            !updates[0].requires_recreate,
            "memory_max change must be in-place; got reasons {:?}",
            updates[0].recreate_reasons
        );
    }

    /// name change is IDENTITY — handled by the desired-vs-actual set
    /// diff, not by `classify_recreate_reasons`. The plan emits
    /// CreateRunner(new) + RemoveRunner(old), no UpdateRunner.
    /// `plan_create_and_remove_when_names_diverge` already covers
    /// this pattern; this test pins the SAME contract via a different
    /// test name so an audit reading recreate_reasons coverage finds
    /// the identity row of the table mapped here.
    #[test]
    fn plan_name_change_is_identity_not_recreate() {
        let cfg = config_with_runners(vec![minimal_runner("renamed")]);
        let other = minimal_runner("original");
        let mut spec = merge_defaults(
            &other,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        spec.spec_hash = spec_hash(&spec);
        let mut actual = empty_actual();
        actual.runners.insert(
            "original".into(),
            discovered_for("original", &spec, Drift::InSync),
        );
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        // No UpdateRunner.
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(
            updates.len(),
            0,
            "name change must not produce UpdateRunner"
        );
        // Exactly one Create("renamed") + one Remove("original").
        let creates: Vec<&str> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::CreateRunner(p) => Some(p.spec.name.as_str()),
                _ => None,
            })
            .collect();
        let removes: Vec<&str> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::RemoveRunner(id) => Some(id.name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(creates, vec!["renamed"]);
        assert_eq!(removes, vec!["original"]);
    }

    /// runner_sha256 change is recreate-class per Part 3. #296 added
    /// X-Ghars-Runner-Sha256 annotation so the change is now Stage 1
    /// detectable — recreate fires with the typed `runner_sha256`
    /// reason (not the older `uncovered` fallback that fired when
    /// runner_sha256 had no annotation source).
    #[test]
    fn plan_update_recreate_on_runner_sha256_change() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.runner_sha256 = Some("a".repeat(64));
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.runner_sha256 = Some("b".repeat(64));
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert!(updates[0].requires_recreate);
        assert!(
            updates[0].recreate_reasons.contains(&"runner_sha256"),
            "runner_sha256 change must produce typed `runner_sha256` reason now \
             that X-Ghars-Runner-Sha256 is annotated; got: {:?}",
            updates[0].recreate_reasons
        );
        assert!(
            !updates[0].recreate_reasons.contains(&"uncovered"),
            "runner_sha256 change must NOT fall through to uncovered now that \
             Stage 1 covers it; got: {:?}",
            updates[0].recreate_reasons
        );
        assert!(
            updates[0]
                .field_changes
                .iter()
                .any(|c| c.path == "runner_sha256"),
            "field_changes must include a runner_sha256 entry; got: {:?}",
            updates[0].field_changes
        );
    }

    /// runner_tarball change is recreate-class per Part 3. #296 added
    /// X-Ghars-Runner-Tarball-Hash annotation (sha256 of the path
    /// string — NOT the path itself, to avoid env leakage) so the
    /// change is now Stage 1 detectable — recreate fires with the
    /// typed `runner_tarball` reason.
    #[test]
    fn plan_update_recreate_on_runner_tarball_change() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.runner_tarball = Some(Utf8PathBuf::from("/var/lib/ghars/runner-new.tar.gz"));
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.runner_tarball = Some(Utf8PathBuf::from("/var/lib/ghars/runner-old.tar.gz"));
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert!(updates[0].requires_recreate);
        assert!(
            updates[0].recreate_reasons.contains(&"runner_tarball"),
            "runner_tarball change must produce typed `runner_tarball` reason now \
             that X-Ghars-Runner-Tarball-Hash is annotated; got: {:?}",
            updates[0].recreate_reasons
        );
        assert!(
            !updates[0].recreate_reasons.contains(&"uncovered"),
            "runner_tarball change must NOT fall through to uncovered now that \
             Stage 1 covers it; got: {:?}",
            updates[0].recreate_reasons
        );
        assert!(
            updates[0]
                .field_changes
                .iter()
                .any(|c| c.path == "runner_tarball"),
            "field_changes must include a runner_tarball entry; got: {:?}",
            updates[0].field_changes
        );
    }

    /// arch change is recreate-class per Part 3. BATCH C added
    /// X-Ghars-Arch annotation so arch changes are now Stage 1
    /// detectable — recreate fires with reason "arch" (not the old
    /// "spec_hash_mismatch" / "uncovered" fallback).
    ///
    /// We construct a desired spec on x86_64 against a discovered spec
    /// recorded as aarch64. Because `merge_defaults` resolves arch as
    /// `runner.arch.or(defaults.arch).unwrap_or(host_arch)`, the
    /// discovered spec must EXPLICITLY pin arch to aarch64 via
    /// runner.arch — otherwise the test machine's host_arch
    /// (typically x86_64) defeats the diff.
    ///
    /// #274: a single flake of this test's prior form
    /// (`*_via_spec_hash`) was reported during full-suite nextest with
    /// `updates.len() == 0 expected 1` and never reproduced. Audit
    /// found no static mut / OnceLock / lazy_static / thread_local /
    /// env::set_var in plan.rs or its dependencies that could leak
    /// across tests; spec_hash and render_runner_unit are pure
    /// functions of their inputs. The hardening below explicitly
    /// asserts every intermediate invariant (discovered arch,
    /// discovered annotation present, hash divergence) so a future
    /// regression of any pre-condition pinpoints which layer broke
    /// rather than producing the opaque "0 updates" symptom that
    /// motivated the flake report.
    #[test]
    fn plan_update_recreate_on_arch_change() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.arch = Some(Arch::X86_64);
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.arch = Some(Arch::Aarch64);
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64, // host_arch fallback never used (runner.arch is Some)
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        // #274: pre-conditions, asserted explicitly so any regression
        // pinpoints the failing layer.
        // (1) Discovered spec must pick up aarch64 from runner.arch
        // override (NOT host_arch fallback).
        assert_eq!(
            old_spec.arch,
            Arch::Aarch64,
            "discovered spec must reflect explicit aarch64 arch override"
        );
        // (2) Discovered 00-ghars.conf drop-in must carry
        // X-Ghars-Arch=aarch64 (Stage 1 annotation source) — without
        // this, the classifier skips the arch branch and uncovered
        // fallback fires instead of the typed "arch" reason. Note:
        // production state::discover puts the unit-template body in
        // on_disk_unit_text and the per-runner identity annotations
        // in drop_ins["00-ghars.conf"] (#347 fix); the classifier
        // reads from the drop-in body via
        // DiscoveredAnnotations::from_discovered.
        let discovered = discovered_for("a", &old_spec, Drift::InSync);
        let body = discovered
            .drop_ins
            .get("00-ghars.conf")
            .expect("00-ghars.conf drop-in must be in discovered fixture");
        assert!(
            body.contains("X-Ghars-Arch=aarch64"),
            "discovered 00-ghars.conf body must contain X-Ghars-Arch=aarch64; got:\n{body}"
        );
        // (3) Desired spec_hash (x86_64) MUST diverge from discovered
        // (aarch64) — an accidental match here would yield 0
        // UpdateRunner actions via the NoOp branch.
        let mut desired_spec = merge_defaults(
            &cfg.runners[0],
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        desired_spec.spec_hash = spec_hash(&desired_spec);
        assert_ne!(
            desired_spec.spec_hash, old_spec.spec_hash,
            "desired spec_hash MUST differ from discovered (arch is a hash input); \
             matching hashes here would route to NoOp not UpdateRunner"
        );
        let mut actual = empty_actual();
        actual.runners.insert("a".into(), discovered);
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert!(updates[0].requires_recreate);
        assert!(
            updates[0].recreate_reasons.contains(&"arch"),
            "arch change must produce a typed `arch` reason now that X-Ghars-Arch is annotated; got: {:?}",
            updates[0].recreate_reasons
        );
        assert!(
            updates[0].field_changes.iter().any(|c| c.path == "arch"),
            "field_changes must include an arch entry; got: {:?}",
            updates[0].field_changes
        );
    }

    /// `RunnerDelta.identity.user` reflects the OLD user from the
    /// discovered unit text (`parse_user_from_unit`, called from
    /// `reconstruct_identity`). This matters because
    /// `apply::Users::userdel_if_present` uses identity.user for
    /// userdel — if it took the desired (new) user instead, the
    /// actual on-disk user would never get cleaned up after a
    /// user-rename recreate.
    ///
    /// We construct a discovered runner whose unit text carries
    /// `User=ghars-old`, then change the desired spec to user=ghars-new,
    /// and assert the resulting RunnerDelta.identity.user is "ghars-old"
    /// (NOT "ghars-new").
    #[test]
    fn plan_update_runner_delta_identity_user_reflects_old_user_not_new() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.user = Some("ghars-new".into());
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.user = Some("ghars-old".into());
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut discovered = discovered_for("a", &old_spec, Drift::InSync);
        // Override the test fixture's hardcoded User= line with the
        // explicit old-user value so parse_user_from_unit picks it up.
        discovered.on_disk_unit_text = format!(
            "[Unit]\nX-Ghars-Managed=true\nX-Ghars-Runner-Name=a\n\
             X-Ghars-Runner-Url={url}\nX-Ghars-Auth-Name={auth}\n\
             X-Ghars-Effective-Version={ver}\n\
             [Service]\nUser=ghars-old\nWorkingDirectory=/var/lib/ghars/a\n",
            url = old_spec.url,
            auth = old_spec.auth_name,
            ver = old_spec.runner_version.clone().unwrap_or_default(),
        );
        let mut actual = empty_actual();
        actual.runners.insert("a".into(), discovered);
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert_eq!(
            updates[0].identity.user, "ghars-old",
            "identity.user must reflect the OLD discovered user, not the desired new user"
        );
    }

    /// `RunnerDelta.identity.prefix` reflects the OLD prefix from the
    /// discovered unit text (`parse_working_directory_from_unit`,
    /// called from `reconstruct_identity`). apply.rs uses
    /// identity.prefix to clean home directories on recreate — taking
    /// the new prefix would orphan the old home dir.
    ///
    /// Discovered WorkingDirectory= points at a custom prefix; the
    /// resulting identity.prefix must be its parent (per the
    /// `parent()` call inside `reconstruct_identity`), not the
    /// desired-side prefix.
    #[test]
    fn plan_update_runner_delta_identity_prefix_reflects_old_prefix_not_new() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.prefix = Some(Utf8PathBuf::from("/srv/runners-new"));
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.prefix = Some(Utf8PathBuf::from("/srv/runners-old"));
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut discovered = discovered_for("a", &old_spec, Drift::InSync);
        // The fixture's parse_working_directory_from_unit reads the
        // WorkingDirectory= line; reconstruct_identity then takes the
        // parent. We point the WD at /srv/runners-old/a so the parent
        // is /srv/runners-old (matching the OLD prefix).
        discovered.on_disk_unit_text = format!(
            "[Unit]\nX-Ghars-Managed=true\nX-Ghars-Runner-Name=a\n\
             X-Ghars-Runner-Url={url}\nX-Ghars-Auth-Name={auth}\n\
             X-Ghars-Effective-Version={ver}\n\
             [Service]\nUser=ghars-a\nWorkingDirectory=/srv/runners-old/a\n",
            url = old_spec.url,
            auth = old_spec.auth_name,
            ver = old_spec.runner_version.clone().unwrap_or_default(),
        );
        let mut actual = empty_actual();
        actual.runners.insert("a".into(), discovered);
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert_eq!(
            updates[0].identity.prefix,
            Utf8PathBuf::from("/srv/runners-old"),
            "identity.prefix must reflect the OLD discovered prefix, not the desired new prefix"
        );
    }

    #[test]
    fn plan_create_and_remove_when_names_diverge() {
        let cfg = config_with_runners(vec![minimal_runner("new")]);
        // actual carries a different runner.
        let other_runner = minimal_runner("old");
        let mut spec = merge_defaults(
            &other_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        spec.spec_hash = spec_hash(&spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("old".into(), discovered_for("old", &spec, Drift::InSync));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let kinds: Vec<&str> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::CreateRunner(_) => Some("create"),
                Action::UpdateRunner(_) => Some("update"),
                Action::RemoveRunner(_) => Some("remove"),
                Action::NoOp(_) => Some("noop"),
                _ => None,
            })
            .collect();
        // Sort order: alphabetical → "new" (create), "old" (remove).
        assert_eq!(kinds, vec!["create", "remove"]);
    }

    #[test]
    fn plan_validates_unknown_auth() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.auth = Some("missing".into());
            r
        }]);
        cfg.auth = pat_auth();
        let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("missing"), "got: {msg}");
    }

    #[test]
    fn plan_validates_no_auth_at_all() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.auth = None;
            r
        }]);
        cfg.auth = pat_auth();
        // defaults.auth is also None.
        let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("no auth"), "got: {msg}");
    }

    #[test]
    fn plan_validates_unknown_cache_pool() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.caches = vec!["nonexistent".into()];
            r
        }]);
        cfg.auth = pat_auth();
        let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("nonexistent"), "got: {msg}");
    }

    #[test]
    fn plan_validates_trust_zone_mismatch() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.caches = vec!["pool".into()];
            r.trust_zone = "default".into();
            r
        }]);
        cfg.auth = pat_auth();
        cfg.cache_pools.insert(
            "pool".into(),
            CachePoolSpec {
                kinds: vec![CacheKind::Ccache],
                size: "10G".into(),
                mode: CacheMode::Shared,
                trust_zone: "untrusted".into(),
            },
        );
        let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("trust_zone"), "got: {msg}");
    }

    #[test]
    fn plan_validates_unknown_network() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.network = Some("ghost".into());
            r
        }]);
        cfg.auth = pat_auth();
        let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("ghost"), "got: {msg}");
    }

    #[test]
    fn plan_resolves_open_network_to_no_binding() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.network = Some("hostnet".into());
            r
        }]);
        cfg.auth = pat_auth();
        cfg.networks.insert(
            "hostnet".into(),
            NetworkSpec {
                mode: NetworkMode::Open,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                address_families: vec![],
                dns: crate::config::DnsMode::Forward,
                ipv6: crate::config::Ipv6Mode::Disabled,
            },
        );
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        let creates: Vec<&RunnerPlan> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::CreateRunner(rp) => Some(rp),
                _ => None,
            })
            .collect();
        assert_eq!(creates.len(), 1);
        // Open mode → no 40-network drop-in.
        assert!(creates[0].spec.network.is_none());
    }

    #[test]
    fn plan_resolves_netns_network_to_binding() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.network = Some("isolated".into());
            r
        }]);
        cfg.auth = pat_auth();
        cfg.networks.insert(
            "isolated".into(),
            NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                address_families: vec![],
                dns: crate::config::DnsMode::Forward,
                ipv6: crate::config::Ipv6Mode::Disabled,
            },
        );
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        let creates: Vec<&RunnerPlan> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::CreateRunner(rp) => Some(rp),
                _ => None,
            })
            .collect();
        assert_eq!(creates.len(), 1);
        let binding = creates[0].spec.network.as_ref().expect("netns ⇒ binding");
        assert_eq!(binding.name, "isolated");
        assert!(matches!(binding.spec.mode, NetworkMode::Netns));
    }

    #[test]
    fn plan_warns_on_shared_user() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.user = Some("legacy-shared".into());
            r
        }]);
        cfg.auth = pat_auth();
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        assert!(
            plan.warnings.iter().any(|w| w.contains("SEC-27")),
            "warnings: {:?}",
            plan.warnings,
        );
    }

    /// #329: `runner.user = "ghars-{name}"` is per-runner-secure (the
    /// operator pinning the SEC-27 default explicitly). Same UID-per-
    /// runner guarantee as the implicit default ⇒ MUST NOT warn.
    /// Pre-fix the classifier emitted a false-positive warning naming
    /// the operator's own pin.
    #[test]
    fn plan_does_not_warn_on_per_runner_secure_user_pin() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.user = Some(format!("ghars-{}", r.name));
            r
        }]);
        cfg.auth = pat_auth();
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        assert!(
            !plan.warnings.iter().any(|w| w.contains("SEC-27")),
            "per-runner-secure pin must NOT trigger SEC-27 warning; \
             warnings: {:?}",
            plan.warnings,
        );
    }

    /// #329: `defaults.user` is inherently shared — one [defaults]
    /// block applies to every [[runner]] that doesn't override it,
    /// so any value there propagates as a shared UID. MUST warn.
    #[test]
    fn plan_warns_on_defaults_user() {
        let mut cfg = config_with_runners(vec![minimal_runner("a")]);
        cfg.auth = pat_auth();
        cfg.defaults.user = Some("svc".into());
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        let sec27: Vec<&String> = plan
            .warnings
            .iter()
            .filter(|w| w.contains("SEC-27"))
            .collect();
        assert!(
            !sec27.is_empty(),
            "defaults.user must trigger SEC-27 warning; got warnings: {:?}",
            plan.warnings,
        );
        assert!(
            sec27.iter().any(|w| w.contains("svc")),
            "warning must name the actual shared user; got: {sec27:?}",
        );
    }

    /// #329: even when an operator sets `runner.user` to ANOTHER
    /// runner's per-runner-secure name (e.g. runner "b" with
    /// `user = "ghars-a"`), the resulting UID is shared across the
    /// two runners (both end up running as the same UID) ⇒ MUST
    /// warn. The per-runner-secure check is keyed on the CURRENT
    /// runner's name; copying another runner's per-runner-secure
    /// value does NOT make this runner per-runner-secure.
    #[test]
    fn plan_warns_on_runner_user_pointing_at_other_runner() {
        let mut cfg = config_with_runners(vec![minimal_runner("a"), {
            let mut r = minimal_runner("b");
            r.user = Some("ghars-a".into());
            r
        }]);
        cfg.auth = pat_auth();
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        let sec27: Vec<&String> = plan
            .warnings
            .iter()
            .filter(|w| w.contains("SEC-27"))
            .collect();
        assert!(
            sec27
                .iter()
                .any(|w| w.contains("'b'") && w.contains("ghars-a")),
            "runner 'b' pointing at runner 'a's UID must warn naming both; \
             got SEC-27 warnings: {sec27:?}",
        );
    }

    /// #378 (regression for #329 fix): when `defaults.user` is set to
    /// a shared value (e.g. `"legacy-gha"`) AND `runner.user` is set
    /// to the per-runner-secure pin (`"ghars-{name}"`), the resolved
    /// effective user is the per-runner-secure pin (runner.user wins
    /// per merge_defaults precedence). Since the effective UID is
    /// per-runner-unique, SEC-27 MUST NOT warn. Pre-fix, the
    /// 3-arm classifier checked `defaults.user.is_some()` first and
    /// emitted a false-positive warning naming the defaults-level
    /// shared user even when runner.user overrode it. This test
    /// pins the override-precedence invariant so a future
    /// classifier rewrite cannot re-introduce the bug.
    #[test]
    fn plan_does_not_warn_on_per_runner_secure_runner_user_overriding_shared_defaults() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.user = Some(format!("ghars-{}", r.name));
            r
        }]);
        cfg.auth = pat_auth();
        cfg.defaults.user = Some("legacy-gha".into());
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        assert!(
            !plan.warnings.iter().any(|w| w.contains("SEC-27")),
            "runner.user='ghars-a' overrides defaults.user='legacy-gha' per merge_defaults \
             precedence; effective user is per-runner-secure ⇒ MUST NOT warn. \
             warnings: {:?}",
            plan.warnings,
        );
    }

    #[test]
    fn plan_actions_sorted_for_determinism() {
        let cfg = config_with_runners(vec![
            minimal_runner("zeta"),
            minimal_runner("alpha"),
            minimal_runner("mu"),
        ]);
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        let names: Vec<String> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::CreateRunner(rp) => Some(rp.spec.name.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["alpha", "mu", "zeta"]);
    }

    #[test]
    fn plan_count_block_creates_n_runners() {
        let cfg = config_with_runners(vec![count_runner("ci", 3)]);
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        let names: Vec<String> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::CreateRunner(rp) => Some(rp.spec.name.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["ci-1", "ci-2", "ci-3"]);
    }

    #[test]
    fn plan_emits_create_cache_pool_per_referenced_pool() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.caches = vec!["build".into()];
            r
        }]);
        cfg.auth = pat_auth();
        cfg.cache_pools.insert(
            "build".into(),
            CachePoolSpec {
                kinds: vec![CacheKind::Ccache, CacheKind::Sccache],
                size: "200G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
            },
        );
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        let pool_actions: Vec<&CachePoolPlan> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::CreateCachePool(p) => Some(p),
                _ => None,
            })
            .collect();
        assert_eq!(pool_actions.len(), 1);
        assert_eq!(pool_actions[0].binding.name, "build");
        assert!(pool_actions[0].spec_hash.starts_with("sha256:"));
    }

    #[test]
    fn plan_renders_cache_pool_drop_in_body_at_plan_time() {
        // Drop-in body is rendered at plan time so the F48 reset-on-empty
        // validator runs before the bytes leave the planner. The body
        // must reflect the resolved kinds + spec_hash + config_source.
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.caches = vec!["build".into()];
            r
        }]);
        cfg.auth = pat_auth();
        cfg.cache_pools.insert(
            "build".into(),
            CachePoolSpec {
                kinds: vec![CacheKind::Sccache],
                size: "300G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
            },
        );
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        let pool_action = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::CreateCachePool(p) => Some(p),
                _ => None,
            })
            .expect("CreateCachePool emitted");
        let body = &pool_action.drop_in_body;
        assert!(
            !body.is_empty(),
            "drop_in_body must be rendered at plan time"
        );
        assert!(body.contains("X-Ghars-Pool-Name=build"));
        assert!(body.contains("X-Ghars-Pool-Kinds=sccache"));
        assert!(body.contains(&format!("X-Ghars-Spec-Hash={}", pool_action.spec_hash)));
        assert!(body.contains("ExecStart=/usr/bin/sccache --start-server"));
        assert!(body.contains("Environment=SCCACHE_CACHE_SIZE=300G"));
        // config_source path threaded into the annotation.
        assert!(body.contains(&format!(
            "X-Ghars-Config-Source={}",
            empty_paths().config_dir.join("ghars.toml")
        )));
    }

    #[test]
    fn plan_renders_ccache_only_pool_with_sleep_infinity_execstart() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.caches = vec!["build".into()];
            r
        }]);
        cfg.auth = pat_auth();
        cfg.cache_pools.insert(
            "build".into(),
            CachePoolSpec {
                kinds: vec![CacheKind::Ccache],
                size: "100G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
            },
        );
        let plan = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap();
        let pool_action = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::CreateCachePool(p) => Some(p),
                _ => None,
            })
            .expect("CreateCachePool emitted");
        let body = &pool_action.drop_in_body;
        assert!(body.contains("ExecStart=/usr/bin/sleep infinity"));
        assert!(body.contains("Environment=CCACHE_DIR=%C/ghars/pools/build/ccache"));
        assert!(body.contains("Environment=CCACHE_MAXSIZE=100G"));
        assert!(!body.contains("--start-server"));
    }

    #[test]
    fn action_label_covers_each_variant() {
        let no_op = Action::NoOp("nothing to do".into());
        assert_eq!(no_op.label(), "NoOp(nothing to do)");
        let rm_pool = Action::RemoveCachePool("build".into());
        assert_eq!(rm_pool.label(), "RemoveCachePool(build)");
    }

    // --- spec_hash: serde-skip / config-source coverage (#207) ---------

    /// Helper used by the spec_hash + merge_defaults follow-up tests
    /// below to construct an `EffectiveRunnerSpec` with stable inputs
    /// minus the field under test.
    fn build_baseline_spec() -> EffectiveRunnerSpec {
        merge_defaults(
            &minimal_runner("a"),
            &Defaults::default(),
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        )
    }

    /// `runsvc_sha256` must NOT participate in `spec_hash`. The field
    /// is `#[serde(skip, default)]` (config.rs line 297) so plan
    /// (pre-install) and apply (post-install, with the digest filled
    /// in) hash identically. A mutation that strips the skip would
    /// surface here as a hash change.
    #[test]
    fn spec_hash_excludes_runsvc_sha256_field() {
        let mut a = build_baseline_spec();
        let mut b = a.clone();
        a.runsvc_sha256 = "sha256:".to_string() + &"a".repeat(64);
        b.runsvc_sha256 = "sha256:".to_string() + &"b".repeat(64);
        assert_eq!(
            spec_hash(&a),
            spec_hash(&b),
            "runsvc_sha256 must be excluded from spec_hash"
        );

        // And empty vs populated must hash the same so plan -> apply
        // doesn't surface a spurious recreate.
        let mut empty = build_baseline_spec();
        let mut filled = empty.clone();
        empty.runsvc_sha256.clear();
        filled.runsvc_sha256 = "sha256:".to_string() + &"c".repeat(64);
        assert_eq!(spec_hash(&empty), spec_hash(&filled));
    }

    /// `config_source` MUST participate in `spec_hash`. The same spec
    /// loaded from a different `ghars.toml` is intentionally a
    /// different spec (drives the `X-Ghars-Config-Source` annotation
    /// and the recreate-on-config-source-change behavior).
    #[test]
    fn spec_hash_includes_config_source_field() {
        let mut a = build_baseline_spec();
        let mut b = a.clone();
        a.config_source = "/etc/ghars/ghars.toml".into();
        b.config_source = "/opt/ghars/ghars.toml".into();
        assert_ne!(
            spec_hash(&a),
            spec_hash(&b),
            "config_source must contribute to spec_hash"
        );
    }

    // --- spec_hash: proptest determinism + sensitivity (#207) ----------

    /// Apply a single property-driven mutation to a spec and return
    /// it. Each variant changes exactly one logical field; the test
    /// asserts the hash also changes. This catches mutants that drop
    /// a field from canonical_json (e.g. someone adds `#[serde(skip)]`
    /// to a field that should be hashed).
    #[derive(Debug, Clone)]
    enum SpecMutation {
        Name(String),
        Url(String),
        Arch(Arch),
        User(String),
        Prefix(String),
        Labels(Vec<String>),
        MemoryMax(Option<String>),
        RunnerVersion(Option<String>),
        TrustZone(String),
        AuthName(String),
        AllowedCpus(Option<String>),
        ConfigSource(String),
        HardeningKvm(Option<bool>),
        HardeningRestrictRealtime(Option<bool>),
        HardeningExtraCapabilities(Vec<String>),
    }

    fn apply_mutation(spec: &mut EffectiveRunnerSpec, m: &SpecMutation) {
        match m {
            SpecMutation::Name(s) => spec.name = s.clone(),
            SpecMutation::Url(s) => spec.url = s.clone(),
            SpecMutation::Arch(a) => spec.arch = *a,
            SpecMutation::User(s) => spec.user = s.clone(),
            SpecMutation::Prefix(s) => spec.prefix = Utf8PathBuf::from(s),
            SpecMutation::Labels(v) => spec.labels = v.clone(),
            SpecMutation::MemoryMax(v) => spec.memory_max = v.clone(),
            SpecMutation::RunnerVersion(v) => spec.runner_version = v.clone(),
            SpecMutation::TrustZone(s) => spec.trust_zone = s.clone(),
            SpecMutation::AuthName(s) => spec.auth_name = s.clone(),
            SpecMutation::AllowedCpus(v) => spec.allowed_cpus = v.clone(),
            SpecMutation::ConfigSource(s) => spec.config_source = s.clone(),
            SpecMutation::HardeningKvm(v) => spec.hardening.kvm = *v,
            SpecMutation::HardeningRestrictRealtime(v) => spec.hardening.restrict_realtime = *v,
            SpecMutation::HardeningExtraCapabilities(v) => {
                spec.hardening.extra_capabilities = v.clone();
            }
        }
    }

    fn mutation_strategy() -> impl proptest::strategy::Strategy<Value = SpecMutation> {
        use proptest::prelude::*;
        prop_oneof![
            "[a-z]{3,8}".prop_map(SpecMutation::Name),
            "https://github\\.com/[a-z]{2,5}/[a-z]{2,5}".prop_map(SpecMutation::Url),
            prop_oneof![Just(Arch::X86_64), Just(Arch::Aarch64)].prop_map(SpecMutation::Arch),
            "ghars-[a-z]{3,6}".prop_map(SpecMutation::User),
            "/(opt|var/lib|srv)/[a-z]{2,6}".prop_map(SpecMutation::Prefix),
            prop::collection::vec("[a-z][a-z0-9-]{1,8}", 1..5).prop_map(SpecMutation::Labels),
            proptest::option::of("[1-9][0-9]?[GM]").prop_map(SpecMutation::MemoryMax),
            proptest::option::of("[0-9]+\\.[0-9]+\\.[0-9]+").prop_map(SpecMutation::RunnerVersion),
            "[a-z]{4,8}".prop_map(SpecMutation::TrustZone),
            "[a-z]{2,8}".prop_map(SpecMutation::AuthName),
            proptest::option::of("[0-9](-[0-9])?").prop_map(SpecMutation::AllowedCpus),
            "/etc/ghars/[a-z]{2,8}\\.toml".prop_map(SpecMutation::ConfigSource),
            proptest::option::of(any::<bool>()).prop_map(SpecMutation::HardeningKvm),
            proptest::option::of(any::<bool>()).prop_map(SpecMutation::HardeningRestrictRealtime),
            prop::collection::vec("CAP_[A-Z_]{4,12}", 0..4)
                .prop_map(SpecMutation::HardeningExtraCapabilities),
        ]
    }

    proptest::proptest! {
        // Property: hashing is deterministic across repeated calls.
        // The first existing scalar test fixed one shape; this fuzzes
        // across many randomly mutated specs to ensure no hidden
        // nondeterminism (e.g. a HashMap-based field) sneaks in.
        #[test]
        fn prop_spec_hash_is_deterministic_across_calls(m in mutation_strategy()) {
            let mut spec = build_baseline_spec();
            apply_mutation(&mut spec, &m);
            let h1 = spec_hash(&spec);
            let h2 = spec_hash(&spec);
            let h3 = spec_hash(&spec.clone());
            proptest::prop_assert_eq!(&h1, &h2);
            proptest::prop_assert_eq!(&h1, &h3);
            proptest::prop_assert!(h1.starts_with("sha256:"));
            proptest::prop_assert_eq!(h1.len(), 7 + 64);
        }

        // Property: any single-field mutation changes the hash. This
        // is the sensitivity guarantee: each field actually
        // contributes to the canonical JSON. A serde(skip) snuck onto
        // a hashed field would surface here as a stable hash across
        // distinct specs.
        #[test]
        fn prop_spec_hash_changes_on_any_field_mutation(m in mutation_strategy()) {
            let baseline = build_baseline_spec();
            let mut mutated = baseline.clone();
            apply_mutation(&mut mutated, &m);
            // Skip cases where the mutation produced the same value
            // (e.g. labels strategy produced the same vec we started
            // with). proptest doesn't have a way to say "unique" so
            // we filter at runtime via prop_assume.
            proptest::prop_assume!(baseline != mutated);
            let h_base = spec_hash(&baseline);
            let h_mut = spec_hash(&mutated);
            proptest::prop_assert_ne!(h_base, h_mut);
        }

        // Property: setting `runsvc_sha256` to ANY value must not
        // change the hash, no matter what other fields look like.
        // Stronger than the scalar test above: it pins the invariant
        // across the random mutation surface.
        #[test]
        fn prop_spec_hash_ignores_runsvc_sha256(
            m in mutation_strategy(),
            sha in "[0-9a-f]{64}",
        ) {
            let mut spec = build_baseline_spec();
            apply_mutation(&mut spec, &m);
            let h_empty = spec_hash(&spec);
            let mut filled = spec.clone();
            filled.runsvc_sha256 = format!("sha256:{sha}");
            let h_filled = spec_hash(&filled);
            proptest::prop_assert_eq!(h_empty, h_filled);
        }

        // Property: setting `spec_hash` to ANY value must not change
        // the result. Idempotence, fuzzed: a mutant that forgets to
        // zero `canonical.spec_hash` before serializing fails here.
        #[test]
        fn prop_spec_hash_ignores_embedded_spec_hash(stale in "[a-zA-Z0-9_-]{1,32}") {
            let baseline = build_baseline_spec();
            let mut spec_a = baseline.clone();
            let mut spec_b = baseline.clone();
            spec_a.spec_hash = stale.clone();
            spec_b.spec_hash = format!("X-{stale}");
            proptest::prop_assert_eq!(spec_hash(&spec_a), spec_hash(&spec_b));
        }
    }

    // --- merge_defaults: scalar regression tests (#208) ----------------

    /// Property: when only the runner side sets a scalar, the runner
    /// value wins regardless of what defaults say. Pinned scalar to
    /// keep the assertion direction-locked: a mutant that swaps the
    /// `or_else` branches in merge_defaults inverts the override
    /// direction and surfaces here.
    #[test]
    fn merge_defaults_runner_user_overrides_defaults_user() {
        let runner = {
            let mut r = minimal_runner("buckos");
            r.user = Some("runner-side-user".into());
            r
        };
        let defaults = Defaults {
            user: Some("defaults-side-user".into()),
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        assert_eq!(eff.user, "runner-side-user");
    }

    /// Property: when only the defaults side sets a Vec, the runner's
    /// empty Vec inherits from defaults via `pick_vec`. (#208 calls
    /// out: empty Vec on runner side = inherit defaults.)
    #[test]
    fn merge_defaults_empty_runner_vec_inherits_defaults_for_pick_vec_fields() {
        let runner = minimal_runner("a");
        let defaults = Defaults {
            hardening: Hardening {
                restrict_address_families: vec!["AF_INET".into(), "AF_INET6".into()],
                extra_syscalls: vec!["@privileged".into()],
                ..Hardening::default()
            },
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        assert_eq!(
            eff.hardening.restrict_address_families,
            vec!["AF_INET", "AF_INET6"]
        );
        assert_eq!(eff.hardening.extra_syscalls, vec!["@privileged"]);
    }

    /// Property: extra_bind_paths and extra_capabilities are
    /// ADDITIVE (defaults entries first, then runner entries) — NOT
    /// override. A mutant that swaps to override semantics drops the
    /// defaults entries and fails here.
    #[test]
    fn merge_defaults_extra_paths_and_caps_are_additive_not_override() {
        let runner = {
            let mut r = minimal_runner("a");
            r.hardening.extra_bind_paths = vec![Utf8PathBuf::from("/runner/path")];
            r.hardening.extra_capabilities = vec!["CAP_NET_RAW".into()];
            r
        };
        let defaults = Defaults {
            hardening: Hardening {
                extra_bind_paths: vec![Utf8PathBuf::from("/defaults/path")],
                extra_capabilities: vec!["CAP_AUDIT_WRITE".into()],
                ..Hardening::default()
            },
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        // Defaults first, then runner — both present.
        assert_eq!(
            eff.hardening.extra_bind_paths,
            vec![
                Utf8PathBuf::from("/defaults/path"),
                Utf8PathBuf::from("/runner/path"),
            ]
        );
        assert_eq!(
            eff.hardening.extra_capabilities,
            vec!["CAP_AUDIT_WRITE", "CAP_NET_RAW"]
        );
    }

    // --- merge_defaults: proptest scalar-override semantics (#208) -----

    fn defaults_strategy()
    -> impl proptest::strategy::Strategy<Value = (Option<String>, Option<String>, Option<String>)>
    {
        (
            proptest::option::of("ghars-[a-z]{3,6}"),
            proptest::option::of("[1-9][0-9]?[GM]"),
            proptest::option::of("[0-9]+\\.[0-9]+\\.[0-9]+"),
        )
    }

    fn runner_overrides_strategy()
    -> impl proptest::strategy::Strategy<Value = (Option<String>, Option<String>, Option<String>)>
    {
        (
            proptest::option::of("runner-[a-z]{3,6}"),
            proptest::option::of("[1-9][0-9]?[GM]"),
            proptest::option::of("[0-9]+\\.[0-9]+\\.[0-9]+"),
        )
    }

    proptest::proptest! {
        // Property: scalar-override rule — runner > defaults > built-in.
        // Tested across user (path 1: defaults fallback to "ghars-{name}"),
        // memory_max (path 2: pure Option override), runner_version (path 3:
        // optional scalar with no built-in default).
        #[test]
        fn prop_merge_defaults_scalar_override_runner_wins(
            (def_user, def_mem, def_ver) in defaults_strategy(),
            (run_user, run_mem, run_ver) in runner_overrides_strategy(),
        ) {
            let runner = {
                let mut r = minimal_runner("rabbit");
                r.user = run_user.clone();
                r.memory_max = run_mem.clone();
                r.runner_version = run_ver.clone();
                r
            };
            let defaults = Defaults {
                user: def_user.clone(),
                memory_max: def_mem.clone(),
                runner_version: def_ver.clone(),
                ..Defaults::default()
            };
            let eff = merge_defaults(
                &runner,
                &defaults,
                "pat".into(),
                vec![],
                None,
                None,
                None,
                Arch::X86_64,
                "/etc/ghars/ghars.toml".into(),
            );
            // user: runner > defaults > "ghars-{name}".
            let expected_user = run_user
                .or(def_user)
                .unwrap_or_else(|| "ghars-rabbit".to_string());
            proptest::prop_assert_eq!(eff.user, expected_user);
            // memory_max: pure Option override.
            proptest::prop_assert_eq!(eff.memory_max, run_mem.or(def_mem));
            // runner_version: pure Option override.
            proptest::prop_assert_eq!(eff.runner_version, run_ver.or(def_ver));
        }

        // labels = concat(defaults, runner) deduped (membership
        // only — first-seen order is no longer meaningful) and then
        // sorted alphabetically. If both are empty after dedup, falls
        // back to [name] (F34 Python parity). Set semantics — labels
        // are the GitHub Actions registration tag set, matched
        // order-independently against workflow `runs-on:`.
        #[test]
        fn prop_merge_defaults_labels_concat_dedup_sorted(
            def_labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..5),
            run_labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..5),
        ) {
            let runner = {
                let mut r = minimal_runner("frog");
                r.labels = run_labels.clone();
                r
            };
            let defaults = Defaults {
                labels: def_labels.clone(),
                ..Defaults::default()
            };
            let eff = merge_defaults(
                &runner,
                &defaults,
                "pat".into(),
                vec![],
                None,
                None,
                None,
                Arch::X86_64,
                "/etc/ghars/ghars.toml".into(),
            );

            // Reconstruct expected labels manually (mirrors
            // merge_defaults logic — if it diverges, the test fails).
            // Concat → dedup → fallback-to-name → sort. The fallback
            // happens BEFORE the sort so a single-name fallback is also
            // canonical (sorting a one-element Vec is a no-op).
            let mut expected: Vec<String> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            for l in def_labels.iter().chain(run_labels.iter()) {
                if seen.insert(l.clone()) {
                    expected.push(l.clone());
                }
            }
            if expected.is_empty() {
                expected.push("frog".to_string());
            }
            expected.sort();
            proptest::prop_assert_eq!(eff.labels, expected);
        }

        // Property: labels sort is stable across the FULL LABEL_RE
        // charset (`^[a-zA-Z0-9._-]+$` per validators.rs:173), not
        // just the lowercase-alphanumeric subset the sibling
        // `prop_merge_defaults_labels_concat_dedup_sorted` uses.
        // `merge_defaults` calls `labels.sort_unstable()` (plan.rs
        // line 924), which uses byte-wise `Ord`. The byte-wise Ord
        // agrees with operator intent ONLY for the ASCII subset the
        // validator allows; this property pins that expectation by
        // exercising uppercase + digits + `._-` separators
        // alongside lowercase letters. A mutation that swaps the
        // sort to a locale-dependent collation or that elides the
        // sort entirely surfaces here as inputs whose merged output
        // is non-monotonic in byte order.
        #[test]
        fn prop_merge_defaults_labels_sorted_full_charset(
            // Generate label strings drawing from the full LABEL_RE
            // alphabet. ASCII byte-wise Ord on this charset matches
            // the canonical contract.
            run_labels in prop::collection::vec(
                "[a-zA-Z0-9._-]{1,8}",
                0..5,
            ),
            def_labels in prop::collection::vec(
                "[a-zA-Z0-9._-]{1,8}",
                0..5,
            ),
        ) {
            let runner = {
                let mut r = minimal_runner("rt");
                r.labels = run_labels.clone();
                r
            };
            let defaults = Defaults {
                labels: def_labels.clone(),
                ..Defaults::default()
            };
            let eff = merge_defaults(
                &runner,
                &defaults,
                "pat".into(),
                vec![],
                None,
                None,
                None,
                Arch::X86_64,
                "/etc/ghars/ghars.toml".into(),
            );
            // Monotonic in byte order: every adjacent pair must
            // satisfy `prev <= next`. A regression that drops the
            // sort would produce an unsorted Vec; a regression that
            // sorts via a different collation would fail on inputs
            // where the two orders diverge (e.g. uppercase before
            // lowercase under ASCII byte order; opposite under
            // case-folded collation).
            for w in eff.labels.windows(2) {
                proptest::prop_assert!(
                    w[0] <= w[1],
                    "labels must be byte-wise sorted; got pair: {:?}, {:?} in {:?}",
                    w[0],
                    w[1],
                    eff.labels
                );
            }
            // Defense-in-depth: result must equal a manual sort of
            // the dedup'd union of both inputs (or the singleton
            // [name] fallback if both were empty).
            let mut expected: Vec<String> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            for l in def_labels.iter().chain(run_labels.iter()) {
                if seen.insert(l.clone()) {
                    expected.push(l.clone());
                }
            }
            if expected.is_empty() {
                expected.push("rt".to_string());
            }
            expected.sort();
            proptest::prop_assert_eq!(eff.labels, expected);
        }

        // Property: Hardening Option<bool> fields use `.or()` —
        // runner Some wins, runner None inherits defaults.
        #[test]
        fn prop_merge_defaults_hardening_or_semantics(
            run_kvm in proptest::option::of(any::<bool>()),
            def_kvm in proptest::option::of(any::<bool>()),
            run_rt in proptest::option::of(any::<bool>()),
            def_rt in proptest::option::of(any::<bool>()),
        ) {
            let runner = {
                let mut r = minimal_runner("a");
                r.hardening.kvm = run_kvm;
                r.hardening.restrict_realtime = run_rt;
                r
            };
            let defaults = Defaults {
                hardening: Hardening {
                    kvm: def_kvm,
                    restrict_realtime: def_rt,
                    ..Hardening::default()
                },
                ..Defaults::default()
            };
            let eff = merge_defaults(
                &runner,
                &defaults,
                "pat".into(),
                vec![],
                None,
                None,
                None,
                Arch::X86_64,
                "/etc/ghars/ghars.toml".into(),
            );
            proptest::prop_assert_eq!(eff.hardening.kvm, run_kvm.or(def_kvm));
            proptest::prop_assert_eq!(eff.hardening.restrict_realtime, run_rt.or(def_rt));
        }

        // Property: caches on the runner side are threaded VERBATIM
        // through merge_defaults. The defaults side has no cache
        // surface, so merge_defaults can't merge — it must pass
        // through. A mutant that drops/reorders entries fails here.
        #[test]
        fn prop_merge_defaults_caches_threaded_verbatim(
            n in 0usize..6,
        ) {
            // Build n distinct EffectiveCacheBindings.
            let bindings: Vec<EffectiveCacheBinding> = (0..n)
                .map(|i| EffectiveCacheBinding {
                    name: format!("pool-{i}"),
                    kinds: vec![CacheKind::Sccache],
                    size: "5G".into(),
                    mode: CacheMode::Shared,
                    trust_zone: "default".into(),
                })
                .collect();
            let runner = minimal_runner("a");
            let defaults = Defaults::default();
            let eff = merge_defaults(
                &runner,
                &defaults,
                "pat".into(),
                bindings.clone(),
                None,
                None,
                None,
                Arch::X86_64,
                "/etc/ghars/ghars.toml".into(),
            );
            proptest::prop_assert_eq!(eff.caches, bindings);
        }

        // Property: merge_defaults is idempotent at the value level.
        // Re-running with the same RunnerSpec/Defaults inputs produces
        // an equal EffectiveRunnerSpec on every call. A mutant that
        // accumulates state across calls (e.g. `extend` on a static
        // Vec) would surface here as drift between the two outputs.
        #[test]
        fn prop_merge_defaults_is_idempotent(
            run_user in proptest::option::of("runner-[a-z]{3,6}"),
            def_user in proptest::option::of("ghars-[a-z]{3,6}"),
            run_labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..4),
            def_labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..4),
        ) {
            let runner = {
                let mut r = minimal_runner("idempo");
                r.user = run_user.clone();
                r.labels = run_labels.clone();
                r
            };
            let defaults = Defaults {
                user: def_user.clone(),
                labels: def_labels.clone(),
                ..Defaults::default()
            };
            let a = merge_defaults(
                &runner,
                &defaults,
                "pat".into(),
                vec![],
                None,
                None,
                None,
                Arch::X86_64,
                "/etc/ghars/ghars.toml".into(),
            );
            let b = merge_defaults(
                &runner,
                &defaults,
                "pat".into(),
                vec![],
                None,
                None,
                None,
                Arch::X86_64,
                "/etc/ghars/ghars.toml".into(),
            );
            proptest::prop_assert_eq!(a, b);
        }

        // #332: Round-trip property test pinning render → parse
        // symmetry. Renders an EffectiveRunnerSpec via
        // `crate::systemd::render_runner_unit`, extracts the
        // `00-ghars.conf` body from the rendered drop-ins, and feeds
        // it through `DiscoveredAnnotations::from_drop_in_body`.
        // The parsed annotations must reflect the input spec's
        // identity-bound fields (url, auth_name, labels,
        // arch, user, prefix, trust_zone, caches, runner_sha256).
        // A regression in either direction — renderer drops a line,
        // parser misroutes a key, parser splits a comma-list wrong —
        // breaks this test.
        //
        // Why fuzz the inputs: the existing render-side tests pin
        // single-shape outputs, but a mutation that flips
        // `X-Ghars-User=` to `X-Ghars-Owner=` in the renderer would
        // pass the snapshot tests as long as the snapshot was also
        // updated. The round-trip catches that class because the
        // parser side stayed on `X-Ghars-User`.
        #[test]
        fn prop_render_parse_round_trip_preserves_identity_fields(
            url_path in "[a-z]{2,8}/[a-z]{2,8}",
            auth_name in "[a-z]{2,8}",
            labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..5),
            user in "ghars-[a-z]{3,8}",
            prefix in "/(opt|var/lib|srv)/[a-z]{2,8}",
            trust_zone in "[a-z]{4,12}",
            arch in prop_oneof![Just(Arch::X86_64), Just(Arch::Aarch64)],
            cache_names in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..4),
            runner_sha in proptest::option::of("sha256:[0-9a-f]{64}"),
        ) {
            // Build the [[runner]] spec. trust_zone is pinned non-
            // empty so merge_defaults doesn't substitute "default".
            let runner = RunnerSpec {
                name: "rt".into(),
                count: None,
                url: format!("https://github.com/{url_path}"),
                auth: Some(auth_name.clone()),
                labels: labels.clone(),
                memory_max: None,
                runner_version: None,
                runner_sha256: runner_sha.clone(),
                runner_tarball: None,
                arch: Some(arch),
                user: Some(user.clone()),
                prefix: Some(Utf8PathBuf::from(&prefix)),
                caches: vec![], // EffectiveCacheBindings come via merge_defaults
                trust_zone: trust_zone.clone(),
                network: None,
                proxy: None,
                hooks: None,
                hardening: Hardening::default(),
                allowed_cpus: None,
                allowed_memory_nodes: None,
            };
            // Build cache bindings to match the property-driven names
            // (caches arrive at the renderer pre-sorted by
            // lower_to_effective per #371; pre-sort the names here so
            // the round-trip parses to the same Vec<String>).
            let mut sorted_cache_names = cache_names.clone();
            sorted_cache_names.sort();
            sorted_cache_names.dedup();
            let bindings: Vec<EffectiveCacheBinding> = sorted_cache_names
                .iter()
                .map(|n| EffectiveCacheBinding {
                    name: n.clone(),
                    kinds: vec![CacheKind::Sccache],
                    size: "5G".into(),
                    mode: CacheMode::Shared,
                    trust_zone: "default".into(),
                })
                .collect();
            let mut spec = merge_defaults(
                &runner,
                &Defaults::default(),
                auth_name.clone(),
                bindings,
                None,
                None,
                None,
                Arch::X86_64,
                "/etc/ghars/ghars.toml".into(),
            );
            // Inject a stable spec_hash + runsvc_sha256 — render_identity
            // requires both to be non-empty + valid. Without these the
            // renderer rejects with check_identity_field("spec_hash",..).
            spec.spec_hash = "sha256:dead".into();
            spec.runsvc_sha256 =
                "sha256:9999999999999999999999999999999999999999999999999999999999999999"
                    .into();
            let rendered = match crate::systemd::render_runner_unit(&spec) {
                Ok(r) => r,
                // labels is constrained by the regex but merge_defaults
                // falls back to [name] when empty. If runner.name "rt"
                // is the only label and it survives the dedup, render
                // succeeds. If something else rejects (e.g. a label
                // regex edge case), skip this iteration.
                Err(_) => return Ok(()),
            };
            let body = rendered
                .drop_ins
                .get("00-ghars.conf")
                .expect("renderer always emits 00-ghars.conf");
            let anns = DiscoveredAnnotations::from_drop_in_body(body);
            // Round-trip assertions: every renderer-emitted X-Ghars-*
            // line must round-trip to the matching DiscoveredAnnotations
            // field carrying the spec's exact value.
            proptest::prop_assert_eq!(anns.url.as_deref(), Some(spec.url.as_str()));
            proptest::prop_assert_eq!(
                anns.auth_name.as_deref(),
                Some(spec.auth_name.as_str()),
            );
            proptest::prop_assert_eq!(
                anns.labels.as_ref().map(|v| v.as_slice()),
                Some(spec.labels.as_slice()),
            );
            let arch_str = match spec.arch {
                Arch::X86_64 => "x86_64",
                Arch::Aarch64 => "aarch64",
            };
            proptest::prop_assert_eq!(anns.arch.as_deref(), Some(arch_str));
            proptest::prop_assert_eq!(anns.user.as_deref(), Some(spec.user.as_str()));
            proptest::prop_assert_eq!(
                anns.prefix.as_deref(),
                Some(spec.prefix.as_str()),
            );
            proptest::prop_assert_eq!(
                anns.trust_zone.as_deref(),
                Some(spec.trust_zone.as_str()),
            );
            // X-Ghars-Caches is unconditionally emitted (#271), so the
            // parsed Some-vec must equal the spec's name list.
            let expected_cache_names: Vec<String> =
                spec.caches.iter().map(|b| b.name.clone()).collect();
            proptest::prop_assert_eq!(anns.caches.as_ref(), Some(&expected_cache_names));
            // runner_sha256: the renderer emits the line iff
            // spec.runner_sha256.is_some(); when None the line is
            // omitted (parser yields None).
            proptest::prop_assert_eq!(
                anns.runner_sha256.as_deref(),
                spec.runner_sha256.as_deref(),
            );
        }

        // Property: empty trust_zone → "default" sentinel. Pinned via
        // a proptest fuzzing the surrounding fields so the fallback
        // doesn't depend on any other input.
        #[test]
        fn prop_merge_defaults_empty_trust_zone_falls_back_to_default(
            run_user in proptest::option::of("runner-[a-z]{3,6}"),
            run_labels in prop::collection::vec("[a-z][a-z0-9-]{0,8}", 0..4),
        ) {
            let runner = {
                let mut r = minimal_runner("tz");
                r.trust_zone = String::new(); // EXPLICITLY empty
                r.user = run_user;
                r.labels = run_labels;
                r
            };
            let defaults = Defaults::default();
            let eff = merge_defaults(
                &runner,
                &defaults,
                "pat".into(),
                vec![],
                None,
                None,
                None,
                Arch::X86_64,
                "/etc/ghars/ghars.toml".into(),
            );
            proptest::prop_assert_eq!(eff.trust_zone, "default");
        }
    }

    // --- merge_defaults: bind_readonly_paths Some(empty) semantics -----

    /// `bind_readonly_paths` is `Option<Vec<Utf8PathBuf>>` to encode
    /// THREE semantically-distinct states (#208 case 7):
    /// - `None` ⇒ inherit defaults (the `or_else` chain returns
    ///   `defaults.bind_readonly_paths`).
    /// - `Some(vec![])` ⇒ replace defaults with an empty list (the
    ///   operator deliberately wants no entries; this overrides
    ///   defaults' list to nothing).
    /// - `Some(vec![/a])` ⇒ override defaults with the runner's list.
    ///
    /// Pin the middle case (Some(empty) replaces) — it's the
    /// ambiguous one that a future refactor might silently flatten
    /// to "Some(empty) inherits defaults". The other two are
    /// covered implicitly by the existing hardening field-by-field
    /// test, but the empty-vec semantics deserves its own pin.
    #[test]
    fn merge_defaults_bind_readonly_paths_some_empty_replaces_defaults() {
        let runner = {
            let mut r = minimal_runner("a");
            // Some(empty) — explicit override to "no readonly bind paths".
            r.hardening.bind_readonly_paths = Some(vec![]);
            r
        };
        let defaults = Defaults {
            hardening: Hardening {
                bind_readonly_paths: Some(vec![Utf8PathBuf::from("/defaults/path")]),
                ..Hardening::default()
            },
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        // Some(empty) on the runner side wins via `runner.or_else(...)`
        // — the `or_else` only fires when runner is None, so Some(vec![])
        // short-circuits and the defaults' Some([/defaults/path]) is
        // ignored. Eff is Some(empty), NOT Some([/defaults/path]).
        assert_eq!(eff.hardening.bind_readonly_paths, Some(vec![]));
    }

    #[test]
    fn merge_defaults_bind_readonly_paths_runner_none_inherits_defaults() {
        // Sanity: complementary case to confirm the inherit path
        // also lands correctly (runner None → defaults wins).
        let runner = {
            let mut r = minimal_runner("a");
            r.hardening.bind_readonly_paths = None;
            r
        };
        let defaults = Defaults {
            hardening: Hardening {
                bind_readonly_paths: Some(vec![Utf8PathBuf::from("/defaults/path")]),
                ..Hardening::default()
            },
            ..Defaults::default()
        };
        let eff = merge_defaults(
            &runner,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        assert_eq!(
            eff.hardening.bind_readonly_paths,
            Some(vec![Utf8PathBuf::from("/defaults/path")])
        );
    }

    // --- ParsedUnit comprehensive parser tests (#204) ------------------
    //
    // The state.rs parser is private (`struct ParsedUnit`), so these
    // tests live there. This block deliberately stays empty — see
    // `crate::state::tests` for the new ParsedUnit edge cases.

    // --- spec_hash: cross-construction / TOML-source / order tests -----

    /// Property: two specs constructed via DIFFERENT call sequences but
    /// landing at the same logical value must hash identically. This
    /// catches a mutant that tags hash output by construction-path
    /// (e.g. encoding the merge step into the canonical JSON) instead
    /// of by value alone. The two paths used here:
    ///   - one with explicit empty-vec defaults
    ///   - one with the same field set on the runner side
    /// Both produce identical `EffectiveRunnerSpec` values; spec_hash
    /// must agree.
    #[test]
    fn spec_hash_path_independent_when_logical_value_matches() {
        // Path A: defaults declares the labels, runner has none.
        let runner_a = minimal_runner("buckos");
        let defaults_a = Defaults {
            labels: vec!["self-hosted".into(), "linux".into()],
            ..Defaults::default()
        };
        let spec_a = merge_defaults(
            &runner_a,
            &defaults_a,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        // Path B: runner declares the labels, defaults has none.
        let runner_b = {
            let mut r = minimal_runner("buckos");
            r.labels = vec!["self-hosted".into(), "linux".into()];
            r
        };
        let defaults_b = Defaults::default();
        let spec_b = merge_defaults(
            &runner_b,
            &defaults_b,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        assert_eq!(
            spec_a, spec_b,
            "construction paths must produce equal specs"
        );
        assert_eq!(spec_hash(&spec_a), spec_hash(&spec_b));
    }

    /// Property: shuffling `labels` MUST NOT change the hash. Labels
    /// are set-semantic for GitHub Actions runner registration —
    /// workflow `runs-on: [linux, gpu]` matches a runner registered
    /// with `[gpu, linux]` identically because the runner's behavior
    /// is order-independent for matching workflow `runs-on:` selectors
    /// once the `--labels CSV` argv is passed at registration.
    /// Locally flipping `spec_hash` on a cosmetic operator reorder
    /// would drive a recreate-class `UpdateRunner` (registration is
    /// labels-bound, so a hash mismatch with no Stage 1 typed reason
    /// fell to the `uncovered` recreate fallback) for a no-op edit.
    /// Mirrors the caches canonicalization at the same function's
    /// `caches.sort_by` site (paired in `lower_to_effective`).
    ///
    /// Construct two specs with the same label SET in different ORDER
    /// and assert `spec_hash` is identical. See `merge_defaults`'s
    /// `labels.sort_unstable() + labels.dedup()` block for the
    /// implementation site.
    #[test]
    fn spec_hash_unchanged_on_labels_reorder() {
        let runner1 = {
            let mut r = minimal_runner("a");
            r.labels = vec!["alpha".into(), "beta".into()];
            r
        };
        let runner2 = {
            let mut r = minimal_runner("a");
            r.labels = vec!["beta".into(), "alpha".into()];
            r
        };
        let defaults = Defaults::default();
        let spec1 = merge_defaults(
            &runner1,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        let spec2 = merge_defaults(
            &runner2,
            &defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        // Both labels Vecs are sorted by `merge_defaults`, so the
        // resulting EffectiveRunnerSpec.labels is `["alpha","beta"]`
        // for both runner1 and runner2. spec_hash must agree.
        assert_eq!(
            spec1.labels,
            vec!["alpha".to_string(), "beta".to_string()],
            "merge_defaults must sort labels; got: {:?}",
            spec1.labels
        );
        assert_eq!(
            spec2.labels, spec1.labels,
            "reordered TOML input must produce identical sorted labels Vec; got: {:?} vs {:?}",
            spec2.labels, spec1.labels
        );
        assert_eq!(spec_hash(&spec1), spec_hash(&spec2));
    }

    /// Property: two TOML files that produce semantically-identical
    /// configs (but with formatting differences — comments,
    /// whitespace, key order across runner blocks) must lower to the
    /// same `EffectiveRunnerSpec` and produce equal `spec_hash`.
    /// This is the round-trip determinism guarantee — a mutant that
    /// captured TOML source bytes into the hash would fail here.
    #[test]
    fn spec_hash_equal_for_semantically_identical_toml_sources() {
        // TOML A: sparse, no comments.
        let toml_a = r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "buckos"
url = "https://github.com/example/buckos"
auth = "pat"
labels = ["alpha", "beta"]
"#;
        // TOML B: same content, plus comments, whitespace, blank
        // lines — semantically identical, byte-different.
        let toml_b = r#"
# auth section
[auth.pat]
kind      = "pat"
token_env = "GHARS_PAT"   # comment

# the only runner

[[runner]]
name    = "buckos"
url     = "https://github.com/example/buckos"
auth    = "pat"
labels  = ["alpha", "beta"]
"#;
        let cfg_a: crate::config::Config = toml::from_str(toml_a).unwrap();
        let cfg_b: crate::config::Config = toml::from_str(toml_b).unwrap();
        let runner_a = &cfg_a.runners[0];
        let runner_b = &cfg_b.runners[0];
        let spec_a = merge_defaults(
            runner_a,
            &cfg_a.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        let spec_b = merge_defaults(
            runner_b,
            &cfg_b.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            "/etc/ghars/ghars.toml".into(),
        );
        assert_eq!(
            spec_hash(&spec_a),
            spec_hash(&spec_b),
            "comment/whitespace differences in TOML source must not affect spec_hash"
        );
    }

    // ---- #291: runsvc_sha256 preserved across in-place update --------

    /// SEC-02 trampoline contract: the X-Ghars-Runsvc-Sha256 annotation
    /// recorded into 00-ghars.conf at apply-time must survive a
    /// subsequent in-place plan/apply cycle. Otherwise the next runner
    /// restart would observe a 00-ghars.conf without the digest, the
    /// runsvc-wrapper trampoline would exit ANNOTATION_MISSING, and
    /// the runner would never start.
    ///
    /// Setup: discovered runner has spec.runsvc_sha256 populated, so
    /// `discovered_for` renders 00-ghars.conf carrying
    /// `X-Ghars-Runsvc-Sha256=sha256:...`. Desired spec is identical
    /// except memory_max changes (drives an in-place UpdateRunner).
    /// plan_from re-renders the desired drop-ins; the runsvc_sha256
    /// recovery block in `plan_from`'s (true, true) match arm must
    /// thread the discovered digest into after_spec.runsvc_sha256
    /// BEFORE re-render (via `extract_runsvc_sha256` +
    /// `with_hash(strip_hash(...))`) so the freshly-emitted
    /// 00-ghars.conf preserves the annotation.
    #[test]
    fn plan_in_place_preserves_runsvc_sha256_in_drop_in() {
        let recorded_digest = "sha256:c0ffee".to_string() + &"a".repeat(58); // 6 + 58 = 64 hex chars after "sha256:" (matches typical render)
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.memory_max = Some("64G".into());
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.memory_max = Some("32G".into());
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        // Inject the install-phase digest BEFORE computing spec_hash so
        // the discovered drop-ins (rendered from old_spec) carry the
        // X-Ghars-Runsvc-Sha256 annotation. spec_hash itself excludes
        // this field via #[serde(skip)] (config.rs:297) — pinned by
        // `prop_spec_hash_ignores_runsvc_sha256`.
        old_spec.runsvc_sha256 = recorded_digest.clone();
        old_spec.spec_hash = spec_hash(&old_spec);
        // Sanity: discovered drop-in carries the digest before plan runs.
        let discovered = discovered_for("a", &old_spec, Drift::InSync);
        assert!(
            discovered
                .drop_ins
                .get("00-ghars.conf")
                .map(|b| b.contains(&format!("X-Ghars-Runsvc-Sha256={recorded_digest}")))
                .unwrap_or(false),
            "fixture invariant: discovered 00-ghars.conf must already carry the digest; \
             got body: {:?}",
            discovered.drop_ins.get("00-ghars.conf")
        );

        let mut actual = empty_actual();
        actual.runners.insert("a".into(), discovered);
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&RunnerDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1, "memory_max-only must emit one update");
        assert!(
            !updates[0].requires_recreate,
            "memory_max-only must be in-place; got reasons {:?}",
            updates[0].recreate_reasons
        );
        // Re-rendered 00-ghars.conf in the in-place payload must carry
        // the discovered digest verbatim. Without the plan-time
        // preserve-then-re-hash logic in `plan_from`'s (true, true)
        // match arm (extract_runsvc_sha256 + with_hash(strip_hash(...))),
        // the freshly rendered drop-in would be missing the annotation
        // entirely (render_identity in systemd.rs only emits the line
        // when spec.runsvc_sha256 is non-empty).
        let after_dropin = updates[0]
            .after
            .drop_ins
            .get("00-ghars.conf")
            .expect("00-ghars.conf must be in the after.drop_ins payload");
        assert!(
            after_dropin.contains(&format!("X-Ghars-Runsvc-Sha256={recorded_digest}")),
            "in-place re-render must preserve discovered runsvc digest; got body:\n{after_dropin}"
        );
    }

    // ---- #292: cache pool diff branches + drift_cause + recreate-empties-drop-in-changes -----

    /// Helper: insert a desired pool referenced by runner `a`. Mirrors
    /// the inline `cfg.cache_pools.insert(...)` pattern other pool
    /// tests use.
    fn cfg_with_pool(name: &str, kinds: Vec<crate::config::CacheKind>) -> Config {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.caches = vec![name.into()];
            r
        }]);
        cfg.cache_pools.insert(
            name.into(),
            CachePoolSpec {
                kinds,
                size: "10G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
            },
        );
        cfg
    }

    /// Helper: build a DiscoveredCachePool with the given spec_hash +
    /// drop-in body content, and the requested Drift. Matches the
    /// shape produced by state.rs's `discover` (state.rs:301-312).
    fn discovered_pool(
        name: &str,
        spec_hash: &str,
        drift: Drift,
    ) -> crate::state::DiscoveredCachePool {
        let mut drop_ins: BTreeMap<String, String> = BTreeMap::new();
        drop_ins.insert(
            "00-ghars.conf".into(),
            format!("[Unit]\nX-Ghars-Spec-Hash={spec_hash}\n"),
        );
        // For DropInsModified payloads, also stage the unmanaged file
        // so the test's drop-in shape reflects what discover() would
        // see. Caller passes the basename via the Drift payload Vec —
        // we don't expand it here because each test fabricates Drift
        // directly.
        crate::state::DiscoveredCachePool {
            name: name.to_owned(),
            spec_hash: spec_hash.to_owned(),
            drop_ins,
            running: false,
            enabled: false,
            drift,
        }
    }

    /// Branch 1: spec_hash matches AND drift InSync ⇒ no
    /// UpdateCachePool / RemoveCachePool emitted (NoOp on the pool
    /// side — plan_from emits no action when both signals are clean).
    #[test]
    fn plan_cache_pool_in_sync_emits_no_pool_action() {
        let cfg = cfg_with_pool("build", vec![CacheKind::Ccache]);
        // Compute the pool's spec_hash by running into_cache_pool_plan
        // with the same desired binding. plan_from calls this path
        // internally; we mirror it so the test's discovered hash
        // matches.
        let cfg_source = empty_paths().config_dir.join("ghars.toml").to_string();
        let spec = cfg.cache_pools.get("build").unwrap();
        let plan_for_pool = into_cache_pool_plan("build".into(), spec, &cfg_source).unwrap();
        let mut actual = empty_actual();
        actual.cache_pools.insert(
            "build".into(),
            discovered_pool("build", &plan_for_pool.spec_hash, Drift::InSync),
        );
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let pool_actions: Vec<&Action> = plan
            .actions
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    Action::CreateCachePool(_)
                        | Action::UpdateCachePool(_)
                        | Action::RemoveCachePool(_)
                )
            })
            .collect();
        assert!(
            pool_actions.is_empty(),
            "in-sync pool must emit no pool action; got: {:?}",
            pool_actions.iter().map(|a| a.label()).collect::<Vec<_>>(),
        );
    }

    /// Branch 2: spec_hash differs ⇒ UpdateCachePool. Pool drift
    /// stays InSync; the spec_hash mismatch alone drives the action.
    #[test]
    fn plan_cache_pool_update_on_spec_hash_change() {
        let cfg = cfg_with_pool("build", vec![CacheKind::Ccache]);
        let mut actual = empty_actual();
        actual.cache_pools.insert(
            "build".into(),
            discovered_pool("build", "sha256:stale", Drift::InSync),
        );
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&CachePoolDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateCachePool(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].binding.name, "build");
    }

    /// Branch 3: spec_hash matches but drift signals DropInsModified
    /// ⇒ UpdateCachePool (the #299 fix gates UpdateCachePool on
    /// `spec_hash != actual || !pool_in_sync`).
    #[test]
    fn plan_cache_pool_update_on_drift_only() {
        let cfg = cfg_with_pool("build", vec![CacheKind::Ccache]);
        let cfg_source = empty_paths().config_dir.join("ghars.toml").to_string();
        let spec = cfg.cache_pools.get("build").unwrap();
        let plan_for_pool = into_cache_pool_plan("build".into(), spec, &cfg_source).unwrap();
        let mut actual = empty_actual();
        // spec_hash matches BUT drift carries an unmanaged drop-in:
        // operator added 99-tuning.conf via `systemctl edit`.
        actual.cache_pools.insert(
            "build".into(),
            discovered_pool(
                "build",
                &plan_for_pool.spec_hash,
                Drift::DropInsModified(vec!["99-tuning.conf".into()]),
            ),
        );
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let updates: Vec<&CachePoolDelta> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateCachePool(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(
            updates.len(),
            1,
            "operator drift on a hash-matched pool must trigger UpdateCachePool (#299)"
        );
    }

    /// Branch 4: pool present in actual but NOT referenced by any
    /// desired runner ⇒ RemoveCachePool. Pinned by the
    /// `actual.cache_pools` − `desired_pool_names` set difference in
    /// `plan_from`'s cache-pool diffing block.
    #[test]
    fn plan_cache_pool_remove_when_orphan() {
        // No runner references the pool; cfg has runner "a" with no
        // caches. Discovered actual carries a "stale-pool" pool.
        let cfg = config_with_runners(vec![minimal_runner("a")]);
        let mut actual = empty_actual();
        actual.cache_pools.insert(
            "stale-pool".into(),
            discovered_pool("stale-pool", "sha256:dead", Drift::InSync),
        );
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let removes: Vec<&Action> = plan
            .actions
            .iter()
            .filter(|a| matches!(a, Action::RemoveCachePool(_)))
            .collect();
        assert_eq!(removes.len(), 1);
        match removes[0] {
            Action::RemoveCachePool(name) => assert_eq!(name, "stale-pool"),
            other => panic!("expected RemoveCachePool, got {other:?}"),
        }
    }

    /// drift_cause on UpdateRunner: SpecChanged when hashes differ but
    /// discovered Drift is InSync. Pins the
    /// `(!hashes_equal, !in_sync)` match arms in `plan_from`'s
    /// intersection branch (the block that emits
    /// `Action::UpdateRunner` after the NoOp short-circuit).
    #[test]
    fn plan_update_runner_drift_cause_spec_changed() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.memory_max = Some("64G".into());
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.memory_max = Some("32G".into());
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let upd = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("expected exactly one UpdateRunner");
        assert_eq!(upd.drift_cause, DriftCause::SpecChanged);
    }

    /// drift_cause: DriftDetected when spec_hash matches but discovered
    /// Drift is non-InSync. Hash equality means no config change;
    /// drift means out-of-band edit. Confirms the `(false, true)`
    /// arm of the `drift_cause` match in `plan_from`.
    #[test]
    fn plan_update_runner_drift_cause_drift_detected() {
        // Use minimal_runner unchanged on both sides so spec_hash
        // matches but the discovered runner reports DropInsModified.
        let cfg = config_with_runners(vec![minimal_runner("a")]);
        let runner = cfg.runners[0].clone();
        let mut spec = merge_defaults(
            &runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        spec.spec_hash = spec_hash(&spec);
        let mut actual = empty_actual();
        actual.runners.insert(
            "a".into(),
            discovered_for(
                "a",
                &spec,
                Drift::DropInsModified(vec!["99-operator.conf".into()]),
            ),
        );
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let upd = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("expected one UpdateRunner");
        assert_eq!(upd.drift_cause, DriftCause::DriftDetected);
    }

    /// drift_cause: SpecChangedAndDriftDetected when BOTH hashes differ
    /// AND on-disk drift is non-InSync. Confirms the `(true, true)`
    /// arm of the `drift_cause` match in `plan_from`.
    #[test]
    fn plan_update_runner_drift_cause_spec_changed_and_drift_detected() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.memory_max = Some("64G".into());
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.memory_max = Some("32G".into());
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual.runners.insert(
            "a".into(),
            discovered_for(
                "a",
                &old_spec,
                Drift::DropInsModified(vec!["99-operator.conf".into()]),
            ),
        );
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let upd = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("expected one UpdateRunner");
        assert_eq!(upd.drift_cause, DriftCause::SpecChangedAndDriftDetected);
    }

    /// recreate-class change must produce an empty `drop_in_changes`
    /// payload. The recreate path drops + recreates all drop-ins
    /// atomically; per-basename diff is meaningless and would mislead
    /// CLI consumers. Pinned by the `requires_recreate` short-circuit
    /// in `plan_from`'s (true, true) match arm — when
    /// `requires_recreate` is true, `drop_in_changes` is set to
    /// `Vec::new()` instead of the rendered Stage 2 diff.
    #[test]
    fn plan_update_runner_recreate_empties_drop_in_changes() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.runner_version = Some("2.300.0".into());
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.runner_version = Some("2.200.0".into());
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let upd = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("expected one UpdateRunner");
        assert!(upd.requires_recreate, "runner_version change must recreate");
        assert!(
            upd.drop_in_changes.is_empty(),
            "recreate path must empty drop_in_changes; got {:?}",
            upd.drop_in_changes
        );
    }

    // ---- #310: auth_name in-place contract --------------------------

    /// auth_name change is in-place per design Part 3 (#306). The
    /// classifier must:
    ///   - record a FieldChange { path: "auth_name", before, after };
    ///   - NOT push to recreate_reasons;
    ///   - NOT trip the `uncovered` fallback (gated on
    ///     `field_changes.is_empty()` alongside `recreate_reasons.is_empty()`
    ///     in `plan_from`'s uncovered-fallback predicate).
    /// This test pins all three at once so a regression in any branch
    /// is caught before commit.
    #[test]
    fn plan_update_runner_auth_name_change_is_in_place_with_field_change() {
        // Two distinct PATs; the runner moves from `pat-old` →
        // `pat-new`. config_with_runners' default config registers only
        // "pat", so we extend with both.
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.auth = Some("pat-new".into());
            r
        }]);
        cfg.auth = IndexMap::new();
        cfg.auth.insert(
            "pat-old".into(),
            AuthSpec::Pat {
                token_env: Some("GHARS_PAT_OLD".into()),
                token_file: None,
            },
        );
        cfg.auth.insert(
            "pat-new".into(),
            AuthSpec::Pat {
                token_env: Some("GHARS_PAT_NEW".into()),
                token_file: None,
            },
        );

        // Discovered runner was registered against pat-old.
        let old_runner = cfg.runners[0].clone();
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat-old".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let upd = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("auth_name change must emit UpdateRunner");
        assert!(
            !upd.requires_recreate,
            "auth_name change must be in-place; got reasons {:?}",
            upd.recreate_reasons
        );
        assert!(
            !upd.recreate_reasons.contains(&"uncovered"),
            "auth_name change must NOT trip uncovered fallback; got reasons {:?}",
            upd.recreate_reasons
        );
        let auth_name_change = upd
            .field_changes
            .iter()
            .find(|fc| fc.path == "auth_name")
            .expect("field_changes must include auth_name entry");
        assert_eq!(auth_name_change.before, FieldValue::String("pat-old".into()));
        assert_eq!(auth_name_change.after, FieldValue::String("pat-new".into()));
    }

    // ---- caches in-place contract (#271) ----------------------------

    /// caches change is in-place per design Part 3 (#271). The
    /// classifier branch added in WO-B must:
    ///   - record a FieldChange { path: "caches", before, after };
    ///   - NOT push to recreate_reasons;
    ///   - NOT trip the `uncovered` fallback (gated on
    ///     `field_changes.is_empty()` at the spec_hash mismatch
    ///     check in `plan_from`).
    /// apply.rs's in-place execute_update_runner reconciles
    /// supplementary-group membership via add_user_to_group /
    /// remove_user_from_group diffs against `delta.before_caches`,
    /// so no host-state migration requires the recreate path.
    #[test]
    fn plan_update_runner_caches_change_is_in_place_with_field_change() {
        // Two cache pools in the same trust_zone (so the runner
        // can reference either without trust_zone-validation noise).
        // Runner moves from caches=["pool-old"] → ["pool-new"].
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.caches = vec!["pool-new".into()];
            r
        }]);
        cfg.cache_pools.insert(
            "pool-old".into(),
            CachePoolSpec {
                kinds: vec![CacheKind::Ccache],
                size: "10G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
            },
        );
        cfg.cache_pools.insert(
            "pool-new".into(),
            CachePoolSpec {
                kinds: vec![CacheKind::Ccache],
                size: "10G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
            },
        );

        // Discovered runner was registered against pool-old.
        let mut old_runner = cfg.runners[0].clone();
        old_runner.caches = vec!["pool-old".into()];
        let old_binding = EffectiveCacheBinding {
            name: "pool-old".into(),
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
        };
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![old_binding],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let upd = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("caches change must emit UpdateRunner");
        assert!(
            !upd.requires_recreate,
            "caches change must be in-place (#271); got reasons {:?}",
            upd.recreate_reasons
        );
        assert!(
            !upd.recreate_reasons.contains(&"uncovered"),
            "caches change must NOT trip uncovered fallback; got reasons {:?}",
            upd.recreate_reasons
        );
        let caches_change = upd
            .field_changes
            .iter()
            .find(|fc| fc.path == "caches")
            .expect("field_changes must include caches entry");
        assert_eq!(caches_change.before, FieldValue::List(vec!["pool-old".into()]));
        assert_eq!(caches_change.after, FieldValue::List(vec!["pool-new".into()]));
    }

    /// #371/#372: a pure caches reorder (operator rewrites
    /// `caches = ["pool-b", "pool-a"]` as `caches = ["pool-a", "pool-b"]`
    /// in TOML, no membership change) MUST end-to-end produce a
    /// `NoOp`, not an `UpdateRunner`. Without `lower_to_effective`
    /// sorting the caches Vec by name, the spec_hash flips on reorder
    /// (Vec preserves source order in canonical JSON); after the sort,
    /// both orderings produce the same spec, the same spec_hash, and
    /// the same rendered drop-in bytes (X-Ghars-Caches=, the
    /// 30-cache-pool.conf body) — so plan diff sees nothing to do.
    ///
    /// Built end-to-end through `plan_from` so this test exercises
    /// the full pipeline — `lower_to_effective` sort → spec_hash
    /// canonical-JSON → `render_identity` X-Ghars-Caches → `render_cache_pool`
    /// 30-cache-pool.conf body. A regression that dropped the sort
    /// from `lower_to_effective` would trip the Stage 2 body diff
    /// (the `30-cache-pool.conf` rendered for the second config would
    /// iterate `spec.caches` in operator-supplied order, differing
    /// from what `discovered_for` wrote for the first config) and
    /// surface as an UpdateRunner with `any_drop_in_modified=true`.
    #[test]
    fn plan_noop_when_caches_reorder_only() {
        // Build a config with two cache pools in the same trust_zone
        // and a runner that references both.
        let make_cfg = |order: Vec<&str>| -> Config {
            let mut cfg = config_with_runners(vec![{
                let mut r = minimal_runner("a");
                r.caches = order.into_iter().map(String::from).collect();
                r
            }]);
            cfg.cache_pools.insert(
                "pool-a".into(),
                CachePoolSpec {
                    kinds: vec![CacheKind::Ccache],
                    size: "10G".into(),
                    mode: CacheMode::Shared,
                    trust_zone: "default".into(),
                },
            );
            cfg.cache_pools.insert(
                "pool-b".into(),
                CachePoolSpec {
                    kinds: vec![CacheKind::Sccache],
                    size: "10G".into(),
                    mode: CacheMode::Shared,
                    trust_zone: "default".into(),
                },
            );
            cfg
        };

        // First config: operator wrote ["pool-b", "pool-a"]. Run
        // plan_from once with empty actual state — produces a
        // CreateRunner whose spec carries the canonical sorted spec.
        let cfg_first = make_cfg(vec!["pool-b", "pool-a"]);
        let plan_first = plan_from(&cfg_first, &empty_actual(), &empty_paths())
            .expect("first plan must succeed");
        let first_spec = plan_first
            .actions
            .iter()
            .find_map(|a| match a {
                Action::CreateRunner(rp) => Some(rp.spec.clone()),
                _ => None,
            })
            .expect("first plan must emit CreateRunner");

        // Discovered state mirrors the first config's apply: same
        // spec_hash, render_runner_unit-derived drop-ins (via
        // discovered_for), Drift::InSync.
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &first_spec, Drift::InSync));

        // Second config: operator reorders to ["pool-a", "pool-b"].
        // After lower_to_effective sorts by name, both configs lower
        // to the same EffectiveRunnerSpec → same spec_hash → no diff.
        let cfg_second = make_cfg(vec!["pool-a", "pool-b"]);
        let plan_second =
            plan_from(&cfg_second, &actual, &empty_paths()).expect("second plan must succeed");

        // The reorder must produce a NoOp, not UpdateRunner.
        let noops: Vec<_> = plan_second
            .actions
            .iter()
            .filter(|a| matches!(a, Action::NoOp(_)))
            .collect();
        let updates: Vec<_> = plan_second
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert!(
            updates.is_empty(),
            "caches reorder must NOT produce UpdateRunner; got: {updates:?}"
        );
        assert_eq!(
            noops.len(),
            1,
            "caches reorder must produce exactly one NoOp; got plan: {:?}",
            plan_second.actions
        );
    }

    /// A pure labels reorder (operator rewrites
    /// `labels = ["beta","alpha"]` as `labels = ["alpha","beta"]` in
    /// TOML, no membership change) MUST end-to-end produce a `NoOp`,
    /// not an `UpdateRunner`. Mirrors `plan_noop_when_caches_reorder_only`
    /// for the caches treatment. Labels are set-semantic for GitHub
    /// Actions runner registration — workflow `runs-on:` matches
    /// against the registered label set order-independently — so a
    /// cosmetic reorder must NOT drive a recreate-class UpdateRunner.
    ///
    /// Without `merge_defaults` sorting `labels` by name, the
    /// `spec_hash` flips on reorder (Vec preserves source order in
    /// canonical JSON; Stage 1 classifier would then either fire the
    /// `labels` typed reason on the annotation diff or fall through
    /// to the `uncovered` recreate fallback). After the sort, both
    /// orderings produce the same spec, the same `spec_hash`, and the
    /// same rendered `X-Ghars-Labels=` annotation, so plan diff sees
    /// nothing to do.
    ///
    /// Built end-to-end through `plan_from` so this test exercises
    /// the full pipeline — `lower_to_effective` (calls `merge_defaults`)
    /// → `spec_hash` canonical-JSON → `render_identity` X-Ghars-Labels.
    /// A regression that dropped the sort from `merge_defaults` would
    /// trip the Stage 1 classifier or the spec_hash mismatch and
    /// surface as an UpdateRunner with the `labels` recreate reason.
    #[test]
    fn plan_noop_when_labels_reorder_only() {
        let make_cfg = |order: Vec<&str>| -> Config {
            config_with_runners(vec![{
                let mut r = minimal_runner("a");
                r.labels = order.into_iter().map(String::from).collect();
                r
            }])
        };

        // First config: operator wrote ["beta","alpha"]. Run plan_from
        // once with empty actual state — produces a CreateRunner
        // whose spec carries the canonical sorted spec.
        let cfg_first = make_cfg(vec!["beta", "alpha"]);
        let plan_first = plan_from(&cfg_first, &empty_actual(), &empty_paths())
            .expect("first plan must succeed");
        let first_spec = plan_first
            .actions
            .iter()
            .find_map(|a| match a {
                Action::CreateRunner(rp) => Some(rp.spec.clone()),
                _ => None,
            })
            .expect("first plan must emit CreateRunner");
        // Pin the canonical-sorted contract on the first spec so any
        // regression dropping the sort fails this assertion before
        // the NoOp check. Both ["beta","alpha"] and ["alpha","beta"]
        // must lower to ["alpha","beta"].
        assert_eq!(
            first_spec.labels,
            vec!["alpha".to_string(), "beta".to_string()],
            "merge_defaults must sort labels; got: {:?}",
            first_spec.labels
        );

        // Discovered state mirrors the first config's apply: same
        // spec_hash, render_runner_unit-derived drop-ins (via
        // discovered_for), Drift::InSync.
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &first_spec, Drift::InSync));

        // Second config: operator reorders to ["alpha","beta"]. After
        // merge_defaults sorts, both configs lower to the same
        // EffectiveRunnerSpec → same spec_hash → no diff.
        let cfg_second = make_cfg(vec!["alpha", "beta"]);
        let plan_second =
            plan_from(&cfg_second, &actual, &empty_paths()).expect("second plan must succeed");

        // The reorder must produce a NoOp, not UpdateRunner.
        let noops: Vec<_> = plan_second
            .actions
            .iter()
            .filter(|a| matches!(a, Action::NoOp(_)))
            .collect();
        let updates: Vec<_> = plan_second
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert!(
            updates.is_empty(),
            "labels reorder must NOT produce UpdateRunner; got: {updates:?}"
        );
        assert_eq!(
            noops.len(),
            1,
            "labels reorder must produce exactly one NoOp; got plan: {:?}",
            plan_second.actions
        );
    }

    // ---- #384: hardening Vec canonicalization (3 set-semantic fields) -

    /// `merge_hardening` sorts `restrict_address_families` in place so
    /// a pure operator reorder of the TOML list does not perturb the
    /// rendered drop-in body or the spec_hash. Mirrors the #371 caches
    /// canonicalization. Built directly on `merge_hardening` (the only
    /// site that touches the post-sort spec) rather than going through
    /// `lower_to_effective` so the test pins the sort regardless of
    /// what other layers do downstream.
    #[test]
    fn merge_hardening_sorts_restrict_address_families() {
        let runner = Hardening {
            restrict_address_families: vec![
                "AF_UNIX".into(),
                "AF_NETLINK".into(),
                "AF_INET".into(),
            ],
            ..Hardening::default()
        };
        let merged = merge_hardening(&runner, &Hardening::default());
        assert_eq!(
            merged.restrict_address_families,
            vec!["AF_INET", "AF_NETLINK", "AF_UNIX"],
            "merge_hardening must sort restrict_address_families in place"
        );
    }

    /// Same contract for `extra_syscalls`. The tokens here are
    /// systemd-syntax syscall names; ordering changes the drop-in body
    /// (`SystemCallFilter=` line) but does NOT change the cumulative
    /// allowlist semantic (consecutive lines union). Sorting is safe
    /// and pins the canonical form.
    #[test]
    fn merge_hardening_sorts_extra_syscalls() {
        let runner = Hardening {
            extra_syscalls: vec!["rseq".into(), "clone3".into(), "memfd_create".into()],
            ..Hardening::default()
        };
        let merged = merge_hardening(&runner, &Hardening::default());
        assert_eq!(
            merged.extra_syscalls,
            vec!["clone3", "memfd_create", "rseq"],
            "merge_hardening must sort extra_syscalls in place"
        );
    }

    /// Same contract for `extra_capabilities`. Note this also exercises
    /// the additive-merge path: defaults + runner are concatenated then
    /// sorted, so the final order is alphabetic regardless of which
    /// side contributed which entry.
    #[test]
    fn merge_hardening_sorts_extra_capabilities_after_additive_merge() {
        let defaults = Hardening {
            extra_capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
            ..Hardening::default()
        };
        let runner = Hardening {
            extra_capabilities: vec!["CAP_DAC_OVERRIDE".into(), "CAP_AUDIT_WRITE".into()],
            ..Hardening::default()
        };
        let merged = merge_hardening(&runner, &defaults);
        // defaults entry + 2 runner entries, then sorted alphabetically.
        assert_eq!(
            merged.extra_capabilities,
            vec![
                "CAP_AUDIT_WRITE",
                "CAP_DAC_OVERRIDE",
                "CAP_NET_BIND_SERVICE",
            ],
            "merge_hardening must sort extra_capabilities after additive merge"
        );
    }

    /// `merge_hardening` deduplicates `restrict_address_families` after
    /// sorting. A pick-merge path can carry duplicates from the picked
    /// side (operator-supplied repeat in TOML); dedup-after-sort
    /// collapses adjacent duplicates so the spec_hash + rendered drop-in
    /// body do not drift on a pure dup edit.
    #[test]
    fn merge_hardening_dedupes_restrict_address_families() {
        let runner = Hardening {
            restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into(), "AF_UNIX".into()],
            ..Hardening::default()
        };
        let merged = merge_hardening(&runner, &Hardening::default());
        assert_eq!(
            merged.restrict_address_families,
            vec!["AF_INET", "AF_UNIX"],
            "merge_hardening must dedup restrict_address_families after sort"
        );
    }

    /// Same dedup contract for `extra_syscalls`. Pick-merge of a single
    /// side that itself contains a repeat must produce a deduped
    /// canonical Vec.
    #[test]
    fn merge_hardening_dedupes_extra_syscalls() {
        let runner = Hardening {
            extra_syscalls: vec!["clone3".into(), "rseq".into(), "clone3".into()],
            ..Hardening::default()
        };
        let merged = merge_hardening(&runner, &Hardening::default());
        assert_eq!(
            merged.extra_syscalls,
            vec!["clone3", "rseq"],
            "merge_hardening must dedup extra_syscalls after sort"
        );
    }

    /// `extra_capabilities` exercises the OTHER source of duplicates:
    /// the additive merge concatenates defaults + runner, so an entry
    /// listed on BOTH sides becomes a duplicate even if neither side
    /// individually repeated. dedup-after-sort collapses it.
    #[test]
    fn merge_hardening_dedupes_extra_capabilities_across_additive_merge() {
        let defaults = Hardening {
            extra_capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
            ..Hardening::default()
        };
        let runner = Hardening {
            extra_capabilities: vec!["CAP_NET_BIND_SERVICE".into(), "CAP_DAC_OVERRIDE".into()],
            ..Hardening::default()
        };
        let merged = merge_hardening(&runner, &defaults);
        // defaults["CAP_NET_BIND_SERVICE"] + runner["CAP_NET_BIND_SERVICE",
        // "CAP_DAC_OVERRIDE"] → after sort+dedup: 2 unique entries.
        assert_eq!(
            merged.extra_capabilities,
            vec!["CAP_DAC_OVERRIDE", "CAP_NET_BIND_SERVICE"],
            "merge_hardening must dedup extra_capabilities across the additive concat"
        );
    }

    /// `bind_readonly_paths` is mount-order-sensitive (overlapping
    /// paths are processed sequentially, so a later mount can override
    /// or fail relative to an earlier one) and MUST NOT be sorted.
    /// This test pins the non-sort contract for `bind_readonly_paths`
    /// — a regression that "helpfully" added `.sort()` here would
    /// silently change the operator's mount-order semantics.
    #[test]
    fn merge_hardening_preserves_bind_readonly_paths_order() {
        let runner = Hardening {
            bind_readonly_paths: Some(vec![
                camino::Utf8PathBuf::from("/srv/z-mount"),
                camino::Utf8PathBuf::from("/srv/a-mount"),
                camino::Utf8PathBuf::from("/srv/m-mount"),
            ]),
            ..Hardening::default()
        };
        let merged = merge_hardening(&runner, &Hardening::default());
        assert_eq!(
            merged.bind_readonly_paths,
            Some(vec![
                camino::Utf8PathBuf::from("/srv/z-mount"),
                camino::Utf8PathBuf::from("/srv/a-mount"),
                camino::Utf8PathBuf::from("/srv/m-mount"),
            ]),
            "bind_readonly_paths must preserve operator-supplied mount order"
        );
    }

    /// `extra_bind_paths` is mount-order-sensitive for the same reason
    /// as `bind_readonly_paths`. Pin the non-sort contract here too.
    /// This also covers the additive-merge path for extra_bind_paths
    /// (defaults entries land first, then runner entries — the order
    /// inside each contributing list is preserved).
    #[test]
    fn merge_hardening_preserves_extra_bind_paths_order() {
        let defaults = Hardening {
            extra_bind_paths: vec![
                camino::Utf8PathBuf::from("/srv/zzz-default"),
                camino::Utf8PathBuf::from("/srv/aaa-default"),
            ],
            ..Hardening::default()
        };
        let runner = Hardening {
            extra_bind_paths: vec![
                camino::Utf8PathBuf::from("/srv/zzz-runner"),
                camino::Utf8PathBuf::from("/srv/aaa-runner"),
            ],
            ..Hardening::default()
        };
        let merged = merge_hardening(&runner, &defaults);
        assert_eq!(
            merged.extra_bind_paths,
            vec![
                camino::Utf8PathBuf::from("/srv/zzz-default"),
                camino::Utf8PathBuf::from("/srv/aaa-default"),
                camino::Utf8PathBuf::from("/srv/zzz-runner"),
                camino::Utf8PathBuf::from("/srv/aaa-runner"),
            ],
            "extra_bind_paths must preserve operator-supplied mount order across both layers"
        );
    }

    /// End-to-end: a runner whose only TOML change is a reorder of a
    /// set-semantic hardening field (`restrict_address_families` here)
    /// must produce a NoOp through `plan_from`, NOT an UpdateRunner.
    /// Mirrors the structure of `plan_noop_when_caches_reorder_only`
    /// — drives the full plan pipeline against an actual state that
    /// reflects a prior apply.
    #[test]
    fn plan_noop_when_restrict_address_families_reorder_only() {
        let make_cfg = |order: Vec<&str>| -> Config {
            let cfg = config_with_runners(vec![{
                let mut r = minimal_runner("a");
                r.hardening.restrict_address_families =
                    order.into_iter().map(String::from).collect();
                r
            }]);
            cfg
        };
        let cfg_first = make_cfg(vec!["AF_UNIX", "AF_NETLINK", "AF_INET"]);
        let plan_first = plan_from(&cfg_first, &empty_actual(), &empty_paths())
            .expect("first plan must succeed");
        let first_spec = plan_first
            .actions
            .iter()
            .find_map(|a| match a {
                Action::CreateRunner(rp) => Some(rp.spec.clone()),
                _ => None,
            })
            .expect("first plan must emit CreateRunner");
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &first_spec, Drift::InSync));
        let cfg_second = make_cfg(vec!["AF_INET", "AF_UNIX", "AF_NETLINK"]);
        let plan_second =
            plan_from(&cfg_second, &actual, &empty_paths()).expect("second plan must succeed");
        let updates: Vec<_> = plan_second
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert!(
            updates.is_empty(),
            "restrict_address_families reorder must NOT produce UpdateRunner; got: {updates:?}"
        );
        let noops: Vec<_> = plan_second
            .actions
            .iter()
            .filter(|a| matches!(a, Action::NoOp(_)))
            .collect();
        assert_eq!(noops.len(), 1, "expected exactly one NoOp");
    }

    /// Same end-to-end shape for `extra_syscalls`.
    #[test]
    fn plan_noop_when_extra_syscalls_reorder_only() {
        let make_cfg = |order: Vec<&str>| -> Config {
            let cfg = config_with_runners(vec![{
                let mut r = minimal_runner("a");
                r.hardening.extra_syscalls = order.into_iter().map(String::from).collect();
                r
            }]);
            cfg
        };
        let cfg_first = make_cfg(vec!["rseq", "clone3", "memfd_create"]);
        let plan_first = plan_from(&cfg_first, &empty_actual(), &empty_paths())
            .expect("first plan must succeed");
        let first_spec = plan_first
            .actions
            .iter()
            .find_map(|a| match a {
                Action::CreateRunner(rp) => Some(rp.spec.clone()),
                _ => None,
            })
            .expect("first plan must emit CreateRunner");
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &first_spec, Drift::InSync));
        let cfg_second = make_cfg(vec!["memfd_create", "rseq", "clone3"]);
        let plan_second =
            plan_from(&cfg_second, &actual, &empty_paths()).expect("second plan must succeed");
        let updates: Vec<_> = plan_second
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert!(
            updates.is_empty(),
            "extra_syscalls reorder must NOT produce UpdateRunner; got: {updates:?}"
        );
    }

    /// Same end-to-end shape for `extra_capabilities`.
    #[test]
    fn plan_noop_when_extra_capabilities_reorder_only() {
        let make_cfg = |order: Vec<&str>| -> Config {
            let cfg = config_with_runners(vec![{
                let mut r = minimal_runner("a");
                r.hardening.extra_capabilities = order.into_iter().map(String::from).collect();
                r
            }]);
            cfg
        };
        let cfg_first = make_cfg(vec![
            "CAP_NET_BIND_SERVICE",
            "CAP_AUDIT_WRITE",
            "CAP_DAC_OVERRIDE",
        ]);
        let plan_first = plan_from(&cfg_first, &empty_actual(), &empty_paths())
            .expect("first plan must succeed");
        let first_spec = plan_first
            .actions
            .iter()
            .find_map(|a| match a {
                Action::CreateRunner(rp) => Some(rp.spec.clone()),
                _ => None,
            })
            .expect("first plan must emit CreateRunner");
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &first_spec, Drift::InSync));
        let cfg_second = make_cfg(vec![
            "CAP_DAC_OVERRIDE",
            "CAP_NET_BIND_SERVICE",
            "CAP_AUDIT_WRITE",
        ]);
        let plan_second =
            plan_from(&cfg_second, &actual, &empty_paths()).expect("second plan must succeed");
        let updates: Vec<_> = plan_second
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .collect();
        assert!(
            updates.is_empty(),
            "extra_capabilities reorder must NOT produce UpdateRunner; got: {updates:?}"
        );
    }

    // ---- #359: caches classifier edge cases ---------------------------
    //
    // These tests exercise the `caches` branch of
    // `classify_recreate_reasons_from_annotations` directly (no
    // plan_from integration) so each edge case is pinned in isolation.
    // The branch lives at plan.rs's "caches change is in-place per
    // design Part 3" block — annotation-side `discovered.caches:
    // Option<Vec<String>>` vs spec-side `desired.caches:
    // Vec<EffectiveCacheBinding>`.
    //
    // #353 contract: the plan classifier sorts both sides before
    // comparison so its FieldChange firing semantics match apply.rs's
    // BTreeSet diff at execute_update_runner. A pure reorder
    // (set-equal) is silent on both sides; any element add/remove
    // surfaces a FieldChange in plan output AND triggers gpasswd ops
    // at apply time.

    /// Helper: build an `EffectiveRunnerSpec` whose `caches` is a list
    /// of bindings with the given names. All other fields use
    /// minimal-runner defaults via `spec_with_url` + `merge_defaults`,
    /// then `caches` is overwritten with synthesized
    /// `EffectiveCacheBinding`s (the classifier only reads
    /// `binding.name`, so kinds/size/mode/trust_zone are arbitrary).
    fn spec_with_cache_names(names: &[&str]) -> EffectiveRunnerSpec {
        let mut spec = spec_with_url("a", "https://github.com/example/repo");
        spec.caches = names
            .iter()
            .map(|n| EffectiveCacheBinding {
                name: (*n).to_owned(),
                kinds: vec![CacheKind::Ccache],
                size: "10G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
            })
            .collect();
        spec
    }

    /// Helper: build a `DiscoveredAnnotations` with caches set to the
    /// given list (Some) or unset (None for the post-upgrade fixture).
    /// All other fields default; the classifier reads each branch
    /// independently so this isolates the caches comparison.
    fn anns_with_caches(caches: Option<&[&str]>) -> DiscoveredAnnotations {
        DiscoveredAnnotations {
            caches: caches.map(|s| s.iter().map(|c| (*c).to_owned()).collect()),
            ..DiscoveredAnnotations::default()
        }
    }

    /// Edge case 1: discovered.caches = None (pre-BATCH-C runner that
    /// predates the unconditional X-Ghars-Caches emit). Classifier
    /// MUST skip the caches comparison entirely so no spurious
    /// FieldChange and no recreate reason fire — the post-upgrade
    /// runner's first plan/apply lands the annotation and a future
    /// edit can reconcile from there.
    #[test]
    fn classify_caches_none_annotation_skips_diff() {
        let anns = anns_with_caches(None);
        let desired = spec_with_cache_names(&["pool-a", "pool-b"]);
        let mut changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
        assert!(
            reasons.is_empty(),
            "no recreate reason on None; got {reasons:?}"
        );
        assert!(
            !changes.iter().any(|c| c.path == "caches"),
            "no caches FieldChange on None; got {changes:?}"
        );
    }

    /// Edge case 2: empty-on-both (discovered = Some(vec![]), desired
    /// = empty Vec). Classifier MUST treat this as no-change — the
    /// runner was registered with no cache pools and still has none.
    #[test]
    fn classify_caches_empty_both_sides_no_change() {
        let anns = anns_with_caches(Some(&[]));
        let desired = spec_with_cache_names(&[]);
        let mut changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
        assert!(reasons.is_empty(), "no recreate reason; got {reasons:?}");
        assert!(
            !changes.iter().any(|c| c.path == "caches"),
            "no caches FieldChange on empty=empty; got {changes:?}"
        );
    }

    /// Edge case 3: same single-element list (discovered =
    /// Some(["pool-a"]), desired = ["pool-a"]). Classifier MUST be
    /// silent — the membership set is unchanged.
    #[test]
    fn classify_caches_same_single_element_no_change() {
        let anns = anns_with_caches(Some(&["pool-a"]));
        let desired = spec_with_cache_names(&["pool-a"]);
        let mut changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
        assert!(reasons.is_empty(), "no recreate reason; got {reasons:?}");
        assert!(
            !changes.iter().any(|c| c.path == "caches"),
            "no caches FieldChange on same single-element; got {changes:?}"
        );
    }

    /// Edge case 4 (#353 contract): same multi-element list in
    /// DIFFERENT order (discovered = ["a", "b"], desired = ["b", "a"]).
    /// Classifier MUST be silent — apply.rs uses BTreeSet semantics
    /// and would do nothing, so plan output must agree. This pins the
    /// sort-then-compare fix from #353.
    #[test]
    fn classify_caches_reorder_is_silent() {
        let anns = anns_with_caches(Some(&["pool-a", "pool-b"]));
        let desired = spec_with_cache_names(&["pool-b", "pool-a"]);
        let mut changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
        assert!(reasons.is_empty(), "no recreate reason; got {reasons:?}");
        assert!(
            !changes.iter().any(|c| c.path == "caches"),
            "reorder is set-equal ⇒ no FieldChange (#353); got {changes:?}"
        );
    }

    /// Edge case 5: caches grows from N to N+1 elements. Classifier
    /// MUST record a FieldChange with both sides rendered in sorted
    /// order (the canonical form apply will execute against).
    #[test]
    fn classify_caches_grow_emits_field_change_sorted() {
        let anns = anns_with_caches(Some(&["pool-b"]));
        let desired = spec_with_cache_names(&["pool-a", "pool-b"]);
        let mut changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
        assert!(reasons.is_empty(), "grow is in-place; got {reasons:?}");
        let caches_change = changes
            .iter()
            .find(|c| c.path == "caches")
            .expect("grow must record caches FieldChange");
        // Both sides sorted: before is just ["pool-b"], after is
        // ["pool-a","pool-b"] (sorted, not insertion-order).
        assert_eq!(caches_change.before, FieldValue::List(vec!["pool-b".into()]));
        assert_eq!(
            caches_change.after,
            FieldValue::List(vec!["pool-a".into(), "pool-b".into()])
        );
    }

    /// Edge case 6: caches shrinks from N to N-1 elements. Symmetric
    /// to grow — FieldChange recorded, sides sorted.
    #[test]
    fn classify_caches_shrink_emits_field_change_sorted() {
        let anns = anns_with_caches(Some(&["pool-b", "pool-a"]));
        let desired = spec_with_cache_names(&["pool-b"]);
        let mut changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
        assert!(reasons.is_empty(), "shrink is in-place; got {reasons:?}");
        let caches_change = changes
            .iter()
            .find(|c| c.path == "caches")
            .expect("shrink must record caches FieldChange");
        // before sorted from input ["pool-b","pool-a"] → ["pool-a","pool-b"]
        assert_eq!(
            caches_change.before,
            FieldValue::List(vec!["pool-a".into(), "pool-b".into()])
        );
        assert_eq!(caches_change.after, FieldValue::List(vec!["pool-b".into()]));
    }

    /// Edge case 7: multi-element replacement (different sets of same
    /// size). Classifier records FieldChange; both sides sorted.
    #[test]
    fn classify_caches_multi_element_replacement_sorted() {
        let anns = anns_with_caches(Some(&["pool-c", "pool-a"]));
        let desired = spec_with_cache_names(&["pool-d", "pool-b"]);
        let mut changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
        assert!(
            reasons.is_empty(),
            "replacement is in-place; got {reasons:?}"
        );
        let caches_change = changes
            .iter()
            .find(|c| c.path == "caches")
            .expect("replacement must record caches FieldChange");
        assert_eq!(
            caches_change.before,
            FieldValue::List(vec!["pool-a".into(), "pool-c".into()])
        );
        assert_eq!(
            caches_change.after,
            FieldValue::List(vec!["pool-b".into(), "pool-d".into()])
        );
    }

    // ---- labels classifier edge cases (parity with caches) ------------
    //
    // These tests exercise the `labels` branch of
    // `classify_recreate_reasons_from_annotations` directly. Labels are
    // set-semantic for GitHub Actions registration (workflow `runs-on:`
    // matches the registered label set order-independently), so the
    // classifier sorts BOTH sides before comparison — a pure reorder
    // must not surface as a `labels` recreate reason / FieldChange.

    /// Helper: build a `DiscoveredAnnotations` with labels set to the
    /// given list (Some) or unset (None for the post-upgrade fixture).
    /// All other fields default; the classifier reads each branch
    /// independently so this isolates the labels comparison.
    fn anns_with_labels(labels: Option<&[&str]>) -> DiscoveredAnnotations {
        DiscoveredAnnotations {
            labels: labels.map(|s| s.iter().map(|c| (*c).to_owned()).collect()),
            ..DiscoveredAnnotations::default()
        }
    }

    /// Helper: build an `EffectiveRunnerSpec` whose `labels` is the
    /// given list. `spec_with_url` invokes `merge_defaults`, which
    /// already sorts labels — but the helper accepts a Vec the caller
    /// has set explicitly so tests can control the ordering at the
    /// pre-classifier boundary. Mirrors `spec_with_cache_names` for
    /// the caches edge cases above.
    fn spec_with_label_names(names: &[&str]) -> EffectiveRunnerSpec {
        let mut spec = spec_with_url("a", "https://github.com/example/repo");
        spec.labels = names.iter().map(|n| (*n).to_owned()).collect();
        spec
    }

    /// Pure reorder (discovered = ["beta","alpha"], desired = ["alpha","beta"])
    /// MUST be silent. Mirrors `classify_caches_reorder_is_silent` —
    /// labels share the set-semantic treatment per the comment block
    /// above the labels branch in `classify_recreate_reasons_from_annotations`.
    /// A regression that drops the sort on either side would surface
    /// here as a spurious `labels` reason + FieldChange.
    #[test]
    fn classify_labels_reorder_is_silent() {
        let anns = anns_with_labels(Some(&["beta", "alpha"]));
        let desired = spec_with_label_names(&["alpha", "beta"]);
        let mut changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
        assert!(
            !reasons.iter().any(|r| *r == "labels"),
            "reorder is set-equal ⇒ no labels recreate reason; got {reasons:?}"
        );
        assert!(
            !changes.iter().any(|c| c.path == "labels"),
            "reorder is set-equal ⇒ no FieldChange; got {changes:?}"
        );
    }

    /// Grow from N to N+1 labels. Membership change MUST surface as a
    /// FieldChange with both before/after rendered in sorted order
    /// (the canonical form GitHub will see at registration time).
    /// Symmetric with `classify_caches_grow_emits_field_change_sorted`.
    #[test]
    fn classify_labels_grow_emits_field_change_sorted() {
        let anns = anns_with_labels(Some(&["a"]));
        let desired = spec_with_label_names(&["b", "a"]);
        let mut changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
        // Labels are recreate-class per the classifier — record the
        // typed reason AND the FieldChange.
        assert!(
            reasons.iter().any(|r| *r == "labels"),
            "grow must record `labels` recreate reason; got {reasons:?}"
        );
        let labels_change = changes
            .iter()
            .find(|c| c.path == "labels")
            .expect("grow must record labels FieldChange");
        // Both sides sorted: before is ["a"]; after is ["a","b"]
        // (sorted, NOT desired's insertion order ["b","a"]).
        assert_eq!(labels_change.before, FieldValue::List(vec!["a".into()]));
        assert_eq!(
            labels_change.after,
            FieldValue::List(vec!["a".into(), "b".into()])
        );
    }

    /// `discovered.labels = None` (pre-upgrade runner that predates the
    /// X-Ghars-Labels emit, or a runner whose 00-ghars.conf was
    /// hand-edited to drop the line). Classifier MUST skip the labels
    /// comparison — comparing None against any desired Vec would
    /// falsely fire on the first apply post-upgrade. Mirrors
    /// `classify_caches_none_annotation_skips_diff`.
    #[test]
    fn classify_labels_none_annotation_skips() {
        let anns = anns_with_labels(None);
        let desired = spec_with_label_names(&["a", "b"]);
        let mut changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(&anns, &desired, &mut changes);
        assert!(
            !reasons.iter().any(|r| *r == "labels"),
            "None annotation must skip labels comparison; got {reasons:?}"
        );
        assert!(
            !changes.iter().any(|c| c.path == "labels"),
            "None annotation must NOT emit labels FieldChange; got {changes:?}"
        );
    }

    // ---- delta.before_caches sort site (plan.rs:2074) ------------------

    /// `RunnerDelta.before_caches` is sorted at the population site in
    /// `plan_from`'s intersection branch so operator-facing surfaces
    /// (--diff output, plan JSON, error messages naming "removed
    /// pools") see canonical alphabetical order regardless of the
    /// order the on-disk `X-Ghars-Caches=` annotation happened to be
    /// written in. Drive plan_from end-to-end with a discovered
    /// annotation in non-canonical order; assert the populated
    /// `delta.before_caches` is sorted. A regression that drops the
    /// sort would surface here as Vec equality against the unsorted
    /// input order.
    #[test]
    fn delta_before_caches_is_sorted_for_display() {
        // Strategy: synthesize an old EffectiveRunnerSpec with caches
        // ["pool-a","pool-m","pool-z"] (canonical order so render
        // produces a clean drop-in body), then overwrite the
        // X-Ghars-Caches annotation in the discovered drop-in with a
        // non-canonical order (`pool-z,pool-a,pool-m`). The
        // intersection branch in plan_from reads this annotation and
        // populates `delta.before_caches` after sorting at the
        // population site (plan.rs:2080 — `sort_unstable()`). New
        // desired spec adds a `pool-new` cache, forcing an
        // UpdateRunner whose `before_caches` we inspect.
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.caches = vec![
                "pool-a".into(),
                "pool-m".into(),
                "pool-new".into(),
                "pool-z".into(),
            ];
            r
        }]);
        // Inject the cache pool definitions so lower_to_effective can
        // resolve the bindings.
        for name in ["pool-a", "pool-m", "pool-new", "pool-z"] {
            cfg.cache_pools.insert(
                name.into(),
                crate::config::CachePoolSpec {
                    kinds: vec![CacheKind::Sccache],
                    size: "5G".into(),
                    mode: CacheMode::Shared,
                    trust_zone: "default".into(),
                },
            );
        }
        // Old runner had only 3 caches (no pool-new) so the desired
        // diff is "grow by one new pool" — in-place UpdateRunner.
        let mut old_runner = cfg.runners[0].clone();
        old_runner.caches.retain(|n| n != "pool-new");
        let old_bindings: Vec<EffectiveCacheBinding> = ["pool-a", "pool-m", "pool-z"]
            .iter()
            .map(|n| EffectiveCacheBinding {
                name: (*n).into(),
                kinds: vec![CacheKind::Sccache],
                size: "5G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
            })
            .collect();
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            old_bindings,
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        // Build a discovered runner whose 00-ghars.conf body lists the
        // caches in non-canonical order. parse-side accepts whatever
        // is on disk; the sort happens at the population site.
        let mut discovered = discovered_for("a", &old_spec, Drift::InSync);
        let body = discovered
            .drop_ins
            .get("00-ghars.conf")
            .expect("renderer always emits 00-ghars.conf")
            .clone();
        let new_body = body
            .lines()
            .map(|line| {
                if line.starts_with("X-Ghars-Caches=") {
                    "X-Ghars-Caches=pool-z,pool-a,pool-m".to_string()
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        discovered.drop_ins.insert("00-ghars.conf".into(), new_body);

        let mut actual = empty_actual();
        actual.runners.insert("a".into(), discovered);
        let plan = plan_from(&cfg, &actual, &empty_paths()).expect("plan must succeed");
        let delta = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("caches grow must emit UpdateRunner");
        let before = delta
            .before_caches
            .as_ref()
            .expect("intersection branch must populate before_caches");
        // Sorted (alphabetical), NOT the on-disk order ["pool-z","pool-a","pool-m"].
        assert_eq!(
            before,
            &vec![
                "pool-a".to_string(),
                "pool-m".to_string(),
                "pool-z".to_string()
            ],
            "before_caches must be sorted; got: {before:?}"
        );
    }

    // ---- #314: C-6 regression — operator 99-*.conf masks recreate -----

    /// C-6 invariant: the `any_drop_in_modified` filter in
    /// `plan_from`'s intersection branch (the closure that filters
    /// `MANAGED_DROP_IN_BASENAMES` against
    /// `Created|Modified|Removed`) must NOT count an operator-added
    /// unmanaged drop-in (e.g. 99-tuning.conf) as in-place evidence —
    /// it must NOT mask a co-occurring recreate-class change.
    ///
    /// Setup: discovered runner has 99-tuning.conf in drop_ins +
    /// `Drift::DropInsModified(["99-tuning.conf"])`. Desired spec
    /// changes runner_sha256. Result: recreate must fire with the typed
    /// `runner_sha256` reason (#296 added Stage 1 annotation detection),
    /// NOT silently fall through to in-place.
    #[test]
    fn plan_recreate_on_runner_sha256_change_with_operator_drop_in() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.runner_sha256 = Some("a".repeat(64));
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.runner_sha256 = Some("b".repeat(64));
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut discovered = discovered_for(
            "a",
            &old_spec,
            Drift::DropInsModified(vec!["99-tuning.conf".into()]),
        );
        // Inject the operator drop-in body into the discovered drop_ins
        // map. Without this, the in-place classifier's drop-in body
        // diff would not see 99-tuning.conf at all and the test would
        // pass for the wrong reason. discover() (state.rs:228-229)
        // reads every *.conf in the runner drop-in dir, so the
        // discovered drop_ins must include the unmanaged file.
        discovered
            .drop_ins
            .insert("99-tuning.conf".into(), "[Service]\nNice=-5\n".into());
        let mut actual = empty_actual();
        actual.runners.insert("a".into(), discovered);
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let upd = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("runner_sha256 change must emit UpdateRunner");
        assert!(
            upd.requires_recreate,
            "runner_sha256 change must recreate even with operator drop-in present; \
             got reasons {:?}",
            upd.recreate_reasons
        );
        assert!(
            upd.recreate_reasons.contains(&"runner_sha256"),
            "C-6 + #297 + #296 invariant: operator drop-in must NOT mask the \
             recreate, AND runner_sha256 is now Stage 1 detectable; expected \
             typed `runner_sha256` reason, got {:?}",
            upd.recreate_reasons
        );
    }

    // ---- #290: trust_zone in-place contract -------------------------

    /// trust_zone is in EffectiveRunnerSpec spec_hash but has no
    /// runner-unit body dependency once cache-pool cross-references
    /// validate at config-load time. A trust_zone-only edit must be
    /// in-place: FieldChange recorded, no recreate reason, no
    /// `uncovered` fallback (gated on `field_changes.is_empty()`).
    #[test]
    fn plan_update_runner_trust_zone_change_is_in_place_with_field_change() {
        // Two trust zones; the runner moves from `default` → `audited`.
        // No cache_pool references — trust_zone validation only kicks
        // in when the runner's caches list is non-empty (the
        // cache-resolution loop in lower_to_effective only enforces
        // pool.trust_zone == runner_zone for declared caches). With
        // caches=[] both zones are valid for the runner; the
        // classifier's job is to detect the zone string change in
        // X-Ghars-Trust-Zone and report it as in-place.
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.trust_zone = "audited".into();
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.trust_zone = "default".into();
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let upd = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("trust_zone change must emit UpdateRunner");
        assert!(
            !upd.requires_recreate,
            "trust_zone change must be in-place (#290); got reasons {:?}",
            upd.recreate_reasons
        );
        assert!(
            !upd.recreate_reasons.contains(&"uncovered"),
            "trust_zone change must NOT trip uncovered fallback; got reasons {:?}",
            upd.recreate_reasons
        );
        let tz_change = upd
            .field_changes
            .iter()
            .find(|fc| fc.path == "trust_zone")
            .expect("field_changes must include trust_zone entry");
        assert_eq!(tz_change.before, FieldValue::String("default".into()));
        assert_eq!(tz_change.after, FieldValue::String("audited".into()));
    }

    /// T-290.4: pin that lower_to_effective still rejects a runner
    /// whose declared trust_zone doesn't match a referenced
    /// cache_pool's trust_zone, REGARDLESS of #290's annotation
    /// in-place classification. The validation lives at
    /// plan.rs::lower_to_effective (around the cache resolution
    /// loop) and runs BEFORE the classifier ever sees the spec —
    /// so a cross-zone reference is a config-load error, not an
    /// in-place update.
    #[test]
    fn plan_validates_trust_zone_mismatch_with_referenced_cache_pool() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.caches = vec!["pool".into()];
            r.trust_zone = "audited".into();
            r
        }]);
        cfg.cache_pools.insert(
            "pool".into(),
            CachePoolSpec {
                kinds: vec![CacheKind::Ccache],
                size: "10G".into(),
                mode: CacheMode::Shared,
                trust_zone: "default".into(),
            },
        );
        let err = plan_from(&cfg, &empty_actual(), &empty_paths()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("trust_zone"), "got: {msg}");
        assert!(msg.contains("audited"), "got: {msg}");
        assert!(msg.contains("default"), "got: {msg}");
    }

    // ---- #308 (#311 collapsed): network mode recreate contract --------

    /// Open→Netns transition MUST recreate. The in-place rewrite path
    /// would write 40-network.conf with NetworkNamespacePath= but
    /// leave the ghars-net@INSTANCE side-units / netns / nft rules
    /// missing, which fail-closes the unit at restart. Recreate
    /// (execute_remove_runner + execute_create_runner) calls
    /// provision_netns_artifacts so all side-units land before the
    /// runner starts.
    #[test]
    fn plan_update_recreate_on_network_mode_open_to_netns() {
        let mut cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.network = Some("isolated".into());
            r
        }]);
        cfg.networks.insert(
            "isolated".into(),
            NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![],
                ip_deny: vec![],
                address_families: vec![],
                dns: crate::config::DnsMode::Forward,
                ipv6: crate::config::Ipv6Mode::Disabled,
            },
        );
        // Discovered side: Open mode (no network binding).
        let old_runner = minimal_runner("a"); // network=None ⇒ Open
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let upd = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("Open→Netns must emit UpdateRunner");
        assert!(
            upd.requires_recreate,
            "Open→Netns must recreate (provision_netns_artifacts only \
             runs on the recreate path); got reasons {:?}",
            upd.recreate_reasons
        );
        assert!(
            upd.recreate_reasons.contains(&"network"),
            "expected typed `network` recreate reason; got: {:?}",
            upd.recreate_reasons
        );
        let mode_change = upd
            .field_changes
            .iter()
            .find(|fc| fc.path == "network")
            .expect("field_changes must include network entry");
        assert_eq!(mode_change.before, FieldValue::String("open".into()));
        assert_eq!(mode_change.after, FieldValue::String("netns".into()));
    }

    /// Netns→Open transition MUST recreate. Without recreate the
    /// in-place rewrite would remove 40-network.conf cleanly but
    /// leave ghars-net@INSTANCE active + nft files + the netns
    /// itself orphaned on the host. The recreate path's
    /// execute_remove_runner runs teardown_netns_artifacts.
    #[test]
    fn plan_update_recreate_on_network_mode_netns_to_open() {
        let cfg = config_with_runners(vec![minimal_runner("a")]); // network=None ⇒ Open
        // Discovered side: Netns mode.
        let mut old_runner = minimal_runner("a");
        old_runner.network = Some("isolated".into());
        let netns_spec = NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            address_families: vec![],
            dns: crate::config::DnsMode::Forward,
            ipv6: crate::config::Ipv6Mode::Disabled,
        };
        let netns_binding = EffectiveNetworkBinding {
            name: "isolated".into(),
            spec: netns_spec,
            subnet: ipnet::IpNet::V4(
                ipnet::Ipv4Net::new(std::net::Ipv4Addr::new(10, 200, 0, 0), 30).unwrap(),
            ),
        };
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            Some(netns_binding),
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let upd = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("Netns→Open must emit UpdateRunner");
        assert!(
            upd.requires_recreate,
            "Netns→Open must recreate (teardown_netns_artifacts only \
             runs on the recreate path); got reasons {:?}",
            upd.recreate_reasons
        );
        assert!(
            upd.recreate_reasons.contains(&"network"),
            "expected typed `network` recreate reason; got: {:?}",
            upd.recreate_reasons
        );
        let mode_change = upd
            .field_changes
            .iter()
            .find(|fc| fc.path == "network")
            .expect("field_changes must include network entry");
        assert_eq!(mode_change.before, FieldValue::String("netns".into()));
        assert_eq!(mode_change.after, FieldValue::String("open".into()));
    }

    // ---- T-296: missing-annotation tolerance + empty-value handling ---

    /// When the discovered unit has no X-Ghars-Runner-Sha256 line at
    /// all and the desired spec ALSO has no runner_sha256 set, the
    /// missing-on-both-sides shape does not perturb spec_hash — both
    /// sides hash the same `None` — so the planner produces a NoOp
    /// (the classifier never runs for NoOp paths). The test asserts
    /// no `UpdateRunner` action is emitted, pinning that the empty-
    /// vs-empty case stays in-sync rather than spuriously firing
    /// recreate.
    #[test]
    fn plan_update_runner_sha256_none_on_both_sides_does_not_recreate() {
        // Both sides leave runner_sha256 unset. With no other diff
        // and matching specs this is an in-sync NoOp; we just verify
        // no spurious recreate reason fires.
        let cfg = config_with_runners(vec![minimal_runner("a")]);
        let runner = cfg.runners[0].clone();
        let mut spec = merge_defaults(
            &runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        spec.spec_hash = spec_hash(&spec);
        let mut actual = empty_actual();
        actual
            .runners
            .insert("a".into(), discovered_for("a", &spec, Drift::InSync));
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        // Should be a NoOp (no Update at all).
        let any_update = plan
            .actions
            .iter()
            .any(|a| matches!(a, Action::UpdateRunner(_)));
        assert!(
            !any_update,
            "matching None-on-both-sides must produce NoOp, not UpdateRunner"
        );
    }

    /// When the discovered unit predates #296 (no Runner-Sha256
    /// annotation emitted) but the desired spec sets a value, Stage
    /// 1 SKIPS the comparison (annotation == None). The spec_hash
    /// mismatch propagates the change once via the recreate-class
    /// `runner_sha256` reason emitted on the next apply (after the
    /// fresh annotation lands). The point of this test: don't
    /// false-fire a comparison "None != desired" that would surface
    /// as misleading FieldChange{before: "", after: "..."}.
    #[test]
    fn plan_runner_sha256_missing_annotation_skips_classification() {
        // Build a discovered drop-in body WITHOUT the Runner-Sha256
        // annotation. The classifier reads from
        // discovered.drop_ins["00-ghars.conf"] (see
        // DiscoveredAnnotations::from_discovered /
        // from_drop_in_body), so we hand-craft the body and call
        // from_drop_in_body directly rather than going through
        // discovered_for.
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.runner_sha256 = Some("a".repeat(64));
            r
        }]);
        let mut desired_spec = merge_defaults(
            &cfg.runners[0],
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        desired_spec.spec_hash = spec_hash(&desired_spec);

        // Discovered drop-in body omits X-Ghars-Runner-Sha256 entirely;
        // every other annotation matches the desired spec so Stage 1
        // sees no recreate-class diff except the missing-on-both-
        // sides skip we are testing. This synthesises the same shape
        // `crate::systemd::render_identity` would write into
        // `00-ghars.conf` MINUS the `X-Ghars-Runner-Sha256` line.
        let arch_str = "x86_64";
        let drop_in_body = format!(
            "[Unit]\nX-Ghars-Runner-Url={url}\n\
             X-Ghars-Auth-Name=pat\nX-Ghars-Labels=a\n\
             X-Ghars-Arch={arch_str}\nX-Ghars-User=ghars-a\n\
             X-Ghars-Prefix=/var/lib/ghars\n\
             X-Ghars-Effective-Version=\n\
             X-Ghars-Trust-Zone=default\nX-Ghars-Network-Mode=open\n",
            url = desired_spec.url,
        );
        let annotations = DiscoveredAnnotations::from_drop_in_body(&drop_in_body);
        // Sanity: the parser sees no Runner-Sha256.
        assert!(
            annotations.runner_sha256.is_none(),
            "missing line must yield None (skip), not Some(\"\")"
        );
        let mut field_changes = Vec::new();
        let reasons = classify_recreate_reasons_from_annotations(
            &annotations,
            &desired_spec,
            &mut field_changes,
        );
        assert!(
            !reasons.contains(&"runner_sha256"),
            "Stage 1 must skip when annotation is None (post-upgrade tolerance); \
             got reasons {:?}",
            reasons
        );
        assert!(
            !field_changes.iter().any(|c| c.path == "runner_sha256"),
            "no FieldChange should fire on None-side comparison; got: {:?}",
            field_changes
        );
    }

    // ---- T-296: round-trip annotation symmetry -----------------------

    /// `render_identity` ↔ `DiscoveredAnnotations::from_drop_in_body`
    /// round-trip for ALL 12 annotation fields the parser tracks.
    /// We render a spec via `render_runner_unit`, parse the resulting
    /// 00-ghars.conf body, and assert each annotation flows back
    /// into the right field. Catches mutants on either side that
    /// spell the key wrong or encode the value differently.
    ///
    /// Coverage: url, auth_name, runner_version, labels, arch, user,
    /// prefix, runner_sha256, runner_tarball_hash, trust_zone,
    /// network_mode, caches. The spec is built with non-default values
    /// for every field so a single mismatch surfaces as a per-field
    /// assertion failure rather than a spec_hash-derived
    /// false-positive.
    #[test]
    fn discovered_annotations_round_trip_for_all_fields() {
        let cache_bindings = vec![
            EffectiveCacheBinding {
                name: "build".into(),
                kinds: vec![CacheKind::Ccache],
                size: "10G".into(),
                mode: CacheMode::Shared,
                trust_zone: "audited".into(),
            },
            EffectiveCacheBinding {
                name: "rust".into(),
                kinds: vec![CacheKind::Sccache],
                size: "5G".into(),
                mode: CacheMode::Shared,
                trust_zone: "audited".into(),
            },
        ];
        let mut spec = merge_defaults(
            &{
                let mut r = minimal_runner("rt");
                // url (default: "https://github.com/example/rt") is
                // exercised by the round-trip; keep the default.
                // auth_name = "pat" (default).
                r.labels = vec!["self-hosted".into(), "linux".into()];
                r.runner_version = Some("v2.999.0".into());
                r.arch = Some(Arch::Aarch64);
                r.user = Some("ghars-rt-explicit".into());
                r.prefix = Some(Utf8PathBuf::from("/srv/ghars-rt"));
                r.runner_sha256 = Some("c".repeat(64));
                r.runner_tarball = Some(Utf8PathBuf::from("/var/lib/ghars/rt.tar.gz"));
                r.trust_zone = "audited".into();
                r.caches = vec!["build".into(), "rust".into()];
                r
            },
            &Defaults::default(),
            "pat".into(),
            cache_bindings,
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        spec.spec_hash = spec_hash(&spec);
        let rendered = crate::systemd::render_runner_unit(&spec).unwrap();
        let body = rendered
            .drop_ins
            .get("00-ghars.conf")
            .expect("00-ghars.conf");
        let anns = DiscoveredAnnotations::from_drop_in_body(body);

        assert_eq!(
            anns.url.as_deref(),
            Some("https://github.com/example/rt"),
            "Runner-Url round-trip"
        );
        assert_eq!(
            anns.auth_name.as_deref(),
            Some("pat"),
            "Auth-Name round-trip"
        );
        assert_eq!(
            anns.runner_version.as_deref(),
            Some("v2.999.0"),
            "Effective-Version round-trip"
        );
        // Labels are set-semantic, sorted by `merge_defaults` before
        // emission, so the round-trip surfaces them in canonical
        // alphabetical order regardless of the operator's input
        // order.
        assert_eq!(
            anns.labels.as_deref(),
            Some(&["linux".to_owned(), "self-hosted".to_owned()][..]),
            "Labels round-trip (comma-joined → split, canonically sorted)"
        );
        assert_eq!(anns.arch.as_deref(), Some("aarch64"), "Arch round-trip");
        assert_eq!(
            anns.user.as_deref(),
            Some("ghars-rt-explicit"),
            "User round-trip"
        );
        assert_eq!(
            anns.prefix.as_deref(),
            Some("/srv/ghars-rt"),
            "Prefix round-trip"
        );
        assert_eq!(
            anns.runner_sha256.as_deref(),
            Some(&*"c".repeat(64)),
            "Runner-Sha256 round-trip"
        );
        // Tarball annotation is the SHA256 of the path string, not
        // the path itself.
        let expected_hash = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"/var/lib/ghars/rt.tar.gz");
            format!("sha256:{}", hex::encode(h.finalize()))
        };
        assert_eq!(
            anns.runner_tarball_hash.as_deref(),
            Some(expected_hash.as_str()),
            "Runner-Tarball-Hash round-trip"
        );
        assert_eq!(
            anns.trust_zone.as_deref(),
            Some("audited"),
            "Trust-Zone round-trip"
        );
        assert_eq!(
            anns.network_mode.as_deref(),
            Some("open"),
            "Network-Mode round-trip (no [network] → \"open\")"
        );
        assert_eq!(
            anns.caches.as_deref(),
            Some(&["build".to_owned(), "rust".to_owned()][..]),
            "Caches round-trip (comma-joined → split)"
        );
    }

    // ---- #331: empty-value vs absent-line annotation contract --------

    /// Pin the contract `from_drop_in_body` honors for every
    /// annotation field whose semantics differ between
    /// "key absent" and "key present with empty value":
    ///
    /// - `X-Ghars-Caches=` (empty) ⇒ `caches = Some(vec![])`
    ///   (operator registered the runner with NO cache pools — the
    ///   apply.rs supplementary-group diff runs and removes any
    ///   stale pool memberships).
    /// - `X-Ghars-Caches` line absent ⇒ `caches = None`
    ///   ("unknown" — the runner predates the unconditional-emit
    ///   change in `render_identity`; apply.rs SKIPS the diff to
    ///   avoid clobbering operator-managed groups).
    /// - Symmetric for `X-Ghars-Labels`.
    ///
    /// The state.rs `extract_x_ghars_value` tests at
    /// `extract_x_ghars_value_returns_some_empty_for_empty_value` and
    /// `extract_x_ghars_value_returns_none_for_absent_key` pin the
    /// helper-layer contract. This test pins the SAME contract one
    /// layer up where the bulk consumer (`extract_x_ghars` in
    /// `from_drop_in_body`) actually drives behavior — without it a
    /// future refactor that switches the bulk consumer to
    /// `unwrap_or_default()` (collapsing absent into "empty") would
    /// silently flip the apply-time semantics for the absent case
    /// without breaking any helper-level test.
    #[test]
    fn from_drop_in_body_distinguishes_empty_value_from_absent_line() {
        // Body 1: BOTH lines present, BOTH empty values. This is the
        // shape `render_identity` emits for `spec.caches.is_empty()` /
        // `spec.labels.is_empty()` — the renderer always emits the
        // line so absent indicates a pre-#296 runner.
        let empty_value_body = "[Unit]\n\
                                X-Ghars-Managed=true\n\
                                X-Ghars-Caches=\n\
                                X-Ghars-Labels=\n";
        let anns = DiscoveredAnnotations::from_drop_in_body(empty_value_body);
        assert_eq!(
            anns.caches.as_deref(),
            Some(&[][..]),
            "X-Ghars-Caches= (empty value) must yield Some(vec![]); got {:?}",
            anns.caches,
        );
        assert_eq!(
            anns.labels.as_deref(),
            Some(&[][..]),
            "X-Ghars-Labels= (empty value) must yield Some(vec![]); got {:?}",
            anns.labels,
        );

        // Body 2: NEITHER line present (legacy 00-ghars.conf rendered
        // before `render_identity` started emitting Caches /
        // Labels unconditionally). Both fields must stay `None` so
        // apply.rs gates know not to drive a diff.
        let absent_line_body = "[Unit]\n\
                                X-Ghars-Managed=true\n";
        let anns = DiscoveredAnnotations::from_drop_in_body(absent_line_body);
        assert!(
            anns.caches.is_none(),
            "absent X-Ghars-Caches line must yield None; got {:?}",
            anns.caches,
        );
        assert!(
            anns.labels.is_none(),
            "absent X-Ghars-Labels line must yield None; got {:?}",
            anns.labels,
        );
    }

    // ---- T-289: runsvc_integrity recreate when annotation missing ----

    /// In-place class change (memory_max edit) on a discovered
    /// runner whose 00-ghars.conf is missing X-Ghars-Runsvc-Sha256
    /// MUST route to the recreate path with the `runsvc_integrity`
    /// reason. Hashing runsvc.sh from disk would weaken SEC-02 (the
    /// file lives in the runner-writable home and may be tampered);
    /// recreate forces config.sh to mint a fresh trusted digest
    /// under our control.
    #[test]
    fn plan_update_recreate_on_runsvc_integrity_when_annotation_missing() {
        let cfg = config_with_runners(vec![{
            let mut r = minimal_runner("a");
            r.memory_max = Some("64G".into());
            r
        }]);
        let mut old_runner = cfg.runners[0].clone();
        old_runner.memory_max = Some("32G".into());
        let mut old_spec = merge_defaults(
            &old_runner,
            &cfg.defaults,
            "pat".into(),
            vec![],
            None,
            None,
            None,
            Arch::X86_64,
            cfg_source_default(),
        );
        old_spec.spec_hash = spec_hash(&old_spec);
        // The default fixture injects a fake runsvc_sha256 digest so
        // every other in-place test stays in-place. Here we want to
        // exercise the MISSING-annotation path (pre-BATCH-C unit, or
        // operator-stripped). Rebuild the discovered runner by hand
        // so the 00-ghars.conf body has NO X-Ghars-Runsvc-Sha256
        // line — render_identity at systemd.rs only emits the line
        // when spec.runsvc_sha256 is non-empty, so feeding it the
        // empty original spec produces exactly the wire format we
        // want to test.
        let mut discovered = discovered_for("a", &old_spec, Drift::InSync);
        let rendered_no_digest = crate::systemd::render_runner_unit(&old_spec).unwrap();
        discovered.drop_ins = rendered_no_digest.drop_ins;
        // Sanity: confirm the rebuilt fixture really did omit the digest.
        let body = discovered
            .drop_ins
            .get("00-ghars.conf")
            .expect("00-ghars.conf in fixture");
        assert!(
            !body.contains("X-Ghars-Runsvc-Sha256="),
            "fixture invariant: discovered 00-ghars.conf must omit the digest \
             line so the recovery path is exercised; got body:\n{body}"
        );
        let mut actual = empty_actual();
        actual.runners.insert("a".into(), discovered);
        let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
        let upd = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::UpdateRunner(d) => Some(d),
                _ => None,
            })
            .expect("missing-digest in-place delta must emit UpdateRunner");
        assert!(
            upd.requires_recreate,
            "missing X-Ghars-Runsvc-Sha256 must force recreate (SEC-02); \
             got reasons {:?}",
            upd.recreate_reasons
        );
        assert!(
            upd.recreate_reasons.contains(&"runsvc_integrity"),
            "expected typed `runsvc_integrity` reason for missing-digest path; \
             got: {:?}",
            upd.recreate_reasons
        );
    }

    /// #575: pin that v1 consumers (which read
    /// `field_changes[].before` / `field_changes[].after` as bare
    /// scalar JSON values) fail predictably when reading the v2
    /// tagged-object shape from `FieldValue::to_json`. The v2 JSON
    /// for a String FieldValue is `{"type": "string", "value": "x"}`;
    /// a v1 consumer doing `value.as_str()` returns `None` because
    /// the outer value is an Object, not a String. Same predictable-
    /// failure contract for List: v2 wraps in an Object, so a v1
    /// `as_array()` returns `None`. This is the load-bearing schema-
    /// version contract: a v1 consumer cannot silently misread a v2
    /// payload — it must surface the type error so downstream tooling
    /// knows to bump.
    #[test]
    fn field_value_to_json_v1_consumer_predictable_failure() {
        // String variant: v2 shape is an Object, NOT a bare string.
        let fv = FieldValue::String("https://example.com".into());
        let json = fv.to_json();
        // v1 consumer expectation: `as_str() -> Some(_)`. v2 reality:
        // `as_str() -> None`. Predictable failure — Object ≠ String.
        assert!(
            json.as_str().is_none(),
            "v2 FieldValue::String must render as JSON Object (NOT bare \
             string) so v1 consumers fail predictably via \
             `as_str() == None`; got: {json}",
        );
        // The Object IS structured the v2 way:
        assert!(json.is_object());
        assert_eq!(json["type"], "string");
        assert_eq!(json["value"], "https://example.com");

        // List variant: same predictable-failure contract.
        let fv = FieldValue::List(vec!["a".into(), "b".into()]);
        let json = fv.to_json();
        // v1 consumer expectation for a list-typed field could have
        // been `as_array() -> Some(_)` (raw JSON array). v2 wraps in
        // an Object, so `as_array() -> None`.
        assert!(
            json.as_array().is_none(),
            "v2 FieldValue::List must render as JSON Object (NOT bare \
             array) so v1 consumers fail predictably via \
             `as_array() == None`; got: {json}",
        );
        // The Object IS structured the v2 way:
        assert!(json.is_object());
        assert_eq!(json["type"], "list");
        assert!(json["values"].is_array());
        assert_eq!(json["values"][0], "a");
        assert_eq!(json["values"][1], "b");
    }
}
