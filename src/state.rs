//! Discover actual state: scan `<unit_dir>` for `ghars-runner@*.service`,
//! parse the unit + drop-ins, query systemd via D-Bus.
//!
//! Design spec: Part 3 (`state.rs`) + Part 7 (state discovery, annotation
//! marker, drift classification).
//!
//! Boundaries:
//! - Filesystem walk + unit-text parsing live in pure functions; tests
//!   redirect `Paths.unit_dir` into a tempdir.
//! - Live state (`ActiveState`, `UnitFileState`) flows through the
//!   `Systemd` trait, so tests inject a `MockSystemd` rather than
//!   speaking real D-Bus.
//! - Drift classification is structural — `UnitEdited` is on-disk
//!   template text mismatching [`crate::systemd::runner_template_text`];
//!   `DropInsModified` is any drop-in file whose basename is outside the
//!   ghars-managed set (template-vs-spec_hash drift is computed by the
//!   plan engine which has both sides of the comparison).

use std::collections::BTreeMap;
use std::fs;

use camino::{Utf8Path, Utf8PathBuf};

use crate::systemd::{Systemd, runner_template_text};
use crate::{GharsError, Paths, Result};

/// `X-Ghars-Managed=true` annotation on the `[Unit]` section marks a
/// ghars-owned unit; missing or anything else means the operator owns
/// the file.
pub const X_GHARS_MANAGED_KEY: &str = "X-Ghars-Managed";
/// `X-Ghars-Spec-Hash` annotation on the `[Unit]` section of the
/// `00-ghars.conf` drop-in.
pub const X_GHARS_SPEC_HASH_KEY: &str = "X-Ghars-Spec-Hash";
/// Drop-in basenames ghars writes per Part 9 numbering (00..89).
/// Anything else under a managed `*.service.d/` directory is operator
/// territory and triggers [`Drift::DropInsModified`].
pub const MANAGED_DROP_IN_BASENAMES: &[&str] = &[
    "00-ghars.conf",
    "10-memory.conf",
    "15-resolv.conf",
    "20-hardening.conf",
    "30-cache-pool.conf",
    "40-network.conf",
    "50-numa.conf",
    "60-proxy.conf",
    "70-hooks.conf",
    "80-lognamespace.conf",
];

/// Drop-in basenames that ghars writes under
/// `<unit_dir>/ghars-cache@POOL.service.d/`. Cache pools have a single
/// per-pool drop-in (`render_cache_drop_in` in
/// `crate::systemd`) carrying spec-hash, kinds, group, env, and
/// `ExecStart`; nothing else is ghars-managed. Anything outside this set
/// (e.g. operator-added `99-tuning.conf`) is treated as drift by
/// [`classify_cache_pool_drift`].
pub const MANAGED_CACHE_DROP_IN_BASENAMES: &[&str] = &["00-ghars.conf"];

/// Snapshot of every `ghars-runner@*.service` unit on the host plus
/// its classification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActualState {
    /// Discovered ghars-managed runners keyed by name.
    pub runners: BTreeMap<String, DiscoveredRunner>,
    /// Managed units whose runner-name has no matching `[[runner]]`
    /// block in the desired config. Populated by the plan engine when
    /// it cross-references against `Config.runners`; discovery itself
    /// always returns an empty `orphans` list because at this layer we
    /// only know "managed" vs "external", not "in-config" vs "out-of-
    /// config".
    pub orphans: Vec<OrphanedUnit>,
    /// `ghars-runner@*.service` files without `X-Ghars-Managed=true` —
    /// operator-managed; ghars never modifies them. Stored as runner
    /// names (the `%i` instance portion) for plan-time reporting.
    pub external: Vec<String>,
    /// Discovered ghars-managed cache-pool template instances
    /// (`ghars-cache@POOL.service`). Populated by the same on-disk
    /// scan that finds runners. Keyed by pool name (the `%i` portion).
    /// Plan-time pool diffing reads this map; previously the planner
    /// always emitted `CreateCachePool` for every referenced pool
    /// because no actual state existed, making `UpdateCachePool` /
    /// `RemoveCachePool` unreachable.
    pub cache_pools: BTreeMap<String, DiscoveredCachePool>,
}

/// One ghars-managed cache pool discovered on disk. Mirrors
/// [`DiscoveredRunner`]'s shape: the per-pool drop-in body holds the
/// `X-Ghars-Spec-Hash` and `X-Ghars-Pool-Kinds` annotations so the
/// plan engine can detect "kinds changed" / "size changed" without
/// re-rendering against actual state.
///
/// The `ghars-cache@.service` *template* file (no instance) is shared
/// across all pools — it carries no per-pool data — so this struct
/// captures only per-pool drop-in state. Template-text drift on the
/// shared template is read separately (the planner re-writes it on
/// any cache-pool action so any drift is auto-healed at the next apply).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredCachePool {
    /// Pool name (the `%i` portion of `ghars-cache@POOL.service`).
    pub name: String,
    /// `X-Ghars-Spec-Hash` value read from the pool's `00-ghars.conf`
    /// drop-in. Empty when missing — treated as drift by the plan engine.
    pub spec_hash: String,
    /// All `*.conf` drop-ins under
    /// `<unit_dir>/ghars-cache@POOL.service.d/`, basename → contents.
    pub drop_ins: BTreeMap<String, String>,
    /// `ActiveState=active` from D-Bus. Cache pools are
    /// `StopWhenUnneeded=yes` template instances, so an inactive pool
    /// usually means no runners reference it (lifecycle, not drift).
    pub running: bool,
    /// `UnitFileState` is `enabled` / `enabled-runtime`.
    pub enabled: bool,
    /// Drift classification for the pool's drop-in directory. Reuses
    /// [`Drift`] but only `InSync` and `DropInsModified` are produced
    /// here — cache pools share one `ghars-cache@.service` template, so
    /// per-pool unit-text drift is not measured (and is auto-healed
    /// on the next apply when the planner re-writes the template).
    /// `UnitEdited` / `Both` are runner-only.
    pub drift: Drift,
}

/// One managed runner discovered on disk, with the on-disk text + drop-
/// ins + live systemd state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRunner {
    /// Runner identifier (the `%i` portion of the unit filename).
    pub name: String,
    /// `X-Ghars-Spec-Hash` value read from the `00-ghars.conf` drop-in.
    /// Empty when the drop-in is missing or the annotation is absent
    /// (in which case the unit is considered drifted anyway).
    pub spec_hash: String,
    /// Raw unit text (verbatim bytes from `<unit_dir>/<name>.service`).
    pub on_disk_unit_text: String,
    /// Drop-in basename → contents.
    pub drop_ins: BTreeMap<String, String>,
    /// `ActiveState=active` from D-Bus. False when the unit is
    /// `inactive`, `failed`, etc., or when the lookup fails (e.g. the
    /// unit exists on disk but hasn't been `daemon-reload`ed yet).
    pub running: bool,
    /// `UnitFileState` is `enabled` / `enabled-runtime`. Static or
    /// disabled units report `false`.
    pub enabled: bool,
    /// Drift classification (in-sync vs unit-edited vs drop-ins-
    /// modified vs both).
    pub drift: Drift,
}

/// Discovered-vs-canonical drift classification. Comparison is
/// structural at this layer: the unit text is compared byte-for-byte
/// against [`crate::systemd::runner_template_text`] and drop-in
/// basenames against [`MANAGED_DROP_IN_BASENAMES`]. Spec-hash drift
/// (the desired spec re-rendered with a different hash than the
/// recorded one) is detected later by the plan engine.
///
/// `DropInsModified` and `Both` carry the list of unmanaged drop-in
/// basenames (sorted by `BTreeMap` key iteration order) so the plan
/// engine and CLI renderer can name the offending files without
/// re-walking the directory. The list is non-empty by construction;
/// `Vec::new()` would mean "no drift" and that's `InSync`. The
/// variant is not `Copy` because `Vec` isn't `Copy`; callers
/// pattern-match by reference or clone explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// On-disk content matches the canonical template + only managed
    /// drop-in basenames present.
    InSync,
    /// Top-level unit text differs from the canonical template.
    UnitEdited,
    /// One or more drop-ins are outside ghars's managed set (e.g.
    /// `99-operator.conf`). Carries the sorted list of unmanaged
    /// basenames.
    DropInsModified(Vec<String>),
    /// Both unit and drop-ins drifted. Carries the sorted list of
    /// unmanaged basenames (same shape as `DropInsModified`).
    Both(Vec<String>),
}

/// A managed unit with no matching desired entry. Populated by the
/// plan engine, never by `discover` itself (see [`ActualState::orphans`]
/// for the rationale).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanedUnit {
    /// Runner name parsed out of the unit filename.
    pub name: String,
}

/// Discover the actual state of every `ghars-runner@*.service` unit on
/// the host.
///
/// Algorithm (Part 7):
/// 1. Glob `<paths.unit_dir>/ghars-runner@*.service`.
/// 2. Parse the file body; check `[Unit]` for `X-Ghars-Managed=true`.
///    External (no annotation) units → `external` list.
/// 3. For each managed unit, read `<unit_dir>/<name>.service.d/*.conf`
///    drop-ins.
/// 4. Read `X-Ghars-Spec-Hash` from `00-ghars.conf`.
/// 5. Query systemd for `ActiveState` + `UnitFileState`.
/// 6. Classify drift by comparing the on-disk template text against
///    [`crate::systemd::runner_template_text`] and the drop-in
///    basenames against [`MANAGED_DROP_IN_BASENAMES`].
///
/// # Errors
///
/// Returns `GharsError::Io` on filesystem read failure, and
/// `GharsError::Systemd` on D-Bus lookup failure. A missing or
/// unreadable `unit_dir` is treated as "no managed runners present"
/// and yields an empty `ActualState`.
pub fn discover(systemd: &dyn Systemd, paths: &Paths) -> Result<ActualState> {
    let unit_dir = paths.unit_dir.as_path();
    let entries = match list_runner_unit_files(unit_dir) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ActualState::default()),
        Err(e) => return Err(GharsError::Io(e)),
    };

    let mut state = ActualState::default();

    for (name, unit_path) in entries {
        let on_disk_unit_text = fs::read_to_string(&unit_path).map_err(GharsError::Io)?;
        let parsed = ParsedUnit::from_text(&on_disk_unit_text);

        if !parsed.is_ghars_managed() {
            state.external.push(name);
            continue;
        }

        let drop_in_dir = paths.drop_in_dir(&name);
        let drop_ins = read_drop_ins(drop_in_dir.as_path()).map_err(GharsError::Io)?;
        let spec_hash = drop_ins
            .get("00-ghars.conf")
            .map(|body| {
                ParsedUnit::from_text(body)
                    .first("Unit", X_GHARS_SPEC_HASH_KEY)
                    .map(str::to_owned)
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        let unit_name = crate::paths::runner_unit_name(&name);
        let running = systemd
            .get_unit_property(&unit_name, "org.freedesktop.systemd1.Unit", "ActiveState")
            .is_ok_and(|s| s.trim() == "active");
        let enabled = systemd
            .get_unit_property(&unit_name, "org.freedesktop.systemd1.Unit", "UnitFileState")
            .is_ok_and(|s| matches!(s.trim(), "enabled" | "enabled-runtime"));

        let drift = classify_drift(&on_disk_unit_text, &drop_ins);

        state.runners.insert(
            name.clone(),
            DiscoveredRunner {
                name,
                spec_hash,
                on_disk_unit_text,
                drop_ins,
                running,
                enabled,
                drift,
            },
        );
    }

    // Enumerate cache-pool template instances by globbing the
    // per-pool drop-in directories `ghars-cache@*.service.d/`.
    // Per-pool unit files don't exist on disk — systemd template
    // instantiation produces virtual units at load time from
    // `ghars-cache@.service` + the per-instance drop-in directory.
    // The drop-in directory is the on-disk evidence that the pool
    // exists from ghars's POV. See list_cache_pool_drop_in_dirs for
    // the full rationale. Previously the planner emitted
    // CreateCachePool unconditionally because no actual state existed;
    // with this scan the planner can diff against a real picture.
    let pool_entries = list_cache_pool_drop_in_dirs(unit_dir).map_err(GharsError::Io)?;
    for (pool_name, drop_in_dir_path) in pool_entries {
        // Defense-in-depth length cap. Config-load already rejects
        // oversize pool names via `validators::validate_cache_pool_name`
        // (which enforces `IDENTIFIER_MAX_LEN`), but a manually-created
        // `ghars-cache@LONG.service.d/` directory (operator-installed,
        // partial-apply crash, or a downgrade from a future ghars where
        // the cap was relaxed) might carry a name longer than the
        // identifier cap. We INCLUDE the pool in `actual.cache_pools`
        // rather than skipping it — the planner diff against
        // `cfg.cache_pools` (which CANNOT contain the oversize key
        // thanks to `validate_cache_pool_name`) will surface the
        // discovered-but-not-desired pool as a RemoveCachePool action.
        // The warning here surfaces the offender to operator output
        // before the next plan/apply cycle reconciles state.
        if pool_name.len() > crate::config::IDENTIFIER_MAX_LEN {
            tracing::warn!(
                pool = %pool_name,
                limit = crate::config::IDENTIFIER_MAX_LEN,
                "discovered cache pool exceeds name length limit; will be removed at next apply"
            );
        }
        // The drop_in_dir_path returned by the lister is the path we
        // just identified — read its contents directly rather than
        // re-deriving via paths.cache_drop_in_dir(). This shaves a
        // potential discrepancy if paths::cache_drop_in_dir ever drifts
        // from the on-disk naming convention parsed by
        // parse_cache_pool_drop_in_dir_name.
        let drop_ins = read_drop_ins(drop_in_dir_path.as_path()).map_err(GharsError::Io)?;
        let spec_hash = drop_ins
            .get("00-ghars.conf")
            .map(|body| {
                ParsedUnit::from_text(body)
                    .first("Unit", X_GHARS_SPEC_HASH_KEY)
                    .map(str::to_owned)
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        let unit_name = crate::paths::cache_unit_name(&pool_name);
        let running = systemd
            .get_unit_property(&unit_name, "org.freedesktop.systemd1.Unit", "ActiveState")
            .is_ok_and(|s| s.trim() == "active");
        let enabled = systemd
            .get_unit_property(&unit_name, "org.freedesktop.systemd1.Unit", "UnitFileState")
            .is_ok_and(|s| matches!(s.trim(), "enabled" | "enabled-runtime"));

        let drift = classify_cache_pool_drift(&drop_ins);

        state.cache_pools.insert(
            pool_name.clone(),
            DiscoveredCachePool {
                name: pool_name,
                spec_hash,
                drop_ins,
                running,
                enabled,
                drift,
            },
        );
    }

    Ok(state)
}

/// Glob `<unit_dir>/ghars-runner@*.service` and return `(name,
/// path)` pairs sorted by name for deterministic ordering.
fn list_runner_unit_files(unit_dir: &Utf8Path) -> std::io::Result<Vec<(String, Utf8PathBuf)>> {
    let mut out: Vec<(String, Utf8PathBuf)> = Vec::new();
    let read = fs::read_dir(unit_dir.as_std_path())?;
    for entry in read {
        let entry = entry?;
        let file_type = entry.file_type()?;
        // Reject symlinks. ghars apply only ever writes regular
        // files into `unit_dir`; a symlink at `ghars-runner@X.service`
        // is operator tampering or filesystem corruption. Treating
        // it as a managed runner would (a) read state from a path
        // ghars does not control and (b) provoke `apply` to remove
        // the symlink target via `fs::remove_file`, possibly
        // affecting state outside `unit_dir`. Skip + warn so
        // discovery does not fail on neighbouring valid units, and
        // the operator sees the offender in journald.
        if file_type.is_symlink() {
            tracing::warn!(
                path = %entry.path().display(),
                "state::list_runner_unit_files skipping symlink — \
                 ghars-managed unit files are always regular files; \
                 remove or replace the symlink"
            );
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        // Non-UTF8 unit filenames cannot be ghars-managed (we only
        // write ASCII names), so we skip them silently.
        let Ok(path) = Utf8PathBuf::try_from(entry.path()) else {
            continue;
        };
        let Some(file_name) = path.file_name() else {
            continue;
        };
        if let Some(name) = parse_runner_unit_name(file_name) {
            out.push((name, path));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Extract the `%i` instance from `ghars-runner@INSTANCE.service`. The
/// canonical template (`ghars-runner@.service` — empty instance) is
/// NOT returned; only per-instance files are managed runners.
fn parse_runner_unit_name(file_name: &str) -> Option<String> {
    let rest = file_name.strip_prefix("ghars-runner@")?;
    let instance = rest.strip_suffix(".service")?;
    if instance.is_empty() {
        return None;
    }
    Some(instance.to_owned())
}

/// Glob `<unit_dir>/ghars-cache@*.service.d/` and return `(pool_name,
/// drop_in_dir_path)` pairs sorted by name.
///
/// Critical asymmetry vs runner discovery: cache pools are systemd
/// template instances. `apply.rs::execute_create_cache_pool` writes only
/// (a) the shared template file `ghars-cache@.service` (no `%i`) and
/// (b) the per-pool drop-in directory `ghars-cache@POOL.service.d/`.
/// Per-pool unit *files* (`ghars-cache@POOL.service`) NEVER exist on
/// disk — systemd materializes them virtually at unit-load time from
/// the template + drop-ins. So the on-disk evidence that pool `POOL`
/// exists from ghars's perspective is the drop-in directory, not a
/// per-pool unit file. Globbing `ghars-cache@*.service` would find
/// nothing (or only the empty-instance template, which we skip).
///
/// Globbing the drop-in dirs also surfaces partial state that
/// `Manager.ListUnitsFiltered` would hide: a pool whose template is
/// masked, whose drop-in dir was created by a partial-apply crash, or
/// which is in `not-found`/`failed` state still has a drop-in dir on
/// disk and so still needs to be reconciled. The filesystem is the
/// configuration source of truth; D-Bus is the runtime status source.
fn list_cache_pool_drop_in_dirs(
    unit_dir: &Utf8Path,
) -> std::io::Result<Vec<(String, Utf8PathBuf)>> {
    let mut out: Vec<(String, Utf8PathBuf)> = Vec::new();
    let read = match fs::read_dir(unit_dir.as_std_path()) {
        Ok(r) => r,
        // Missing unit_dir is a no-op for cache-pool discovery (the
        // runner pass already aborted with an empty ActualState in
        // that case via the entries match at the top of discover()).
        // We still tolerate the case here so list_cache_pool_drop_in_dirs
        // is independently safe to call.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in read {
        let entry = entry?;
        let file_type = entry.file_type()?;
        // Reject symlinks. apply.rs writes a real directory at
        // `ghars-cache@POOL.service.d/`; a symlink there is operator
        // tampering and would let ghars apply remove or rewrite a
        // path outside `unit_dir`. Skip + warn so discovery proceeds
        // for neighbouring valid pools.
        if file_type.is_symlink() {
            tracing::warn!(
                path = %entry.path().display(),
                "state::list_cache_pool_drop_in_dirs skipping symlink — \
                 ghars-managed drop-in directories are always real directories; \
                 remove or replace the symlink"
            );
            continue;
        }
        if !file_type.is_dir() {
            continue;
        }
        let Ok(path) = Utf8PathBuf::try_from(entry.path()) else {
            continue;
        };
        let Some(file_name) = path.file_name() else {
            continue;
        };
        if let Some(name) = parse_cache_pool_drop_in_dir_name(file_name) {
            out.push((name, path));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Extract the `%i` pool name from `ghars-cache@POOL.service.d`. The
/// shared template's drop-in dir would be `ghars-cache@.service.d`
/// (empty instance) — not currently emitted by apply, but rejected
/// here defensively.
fn parse_cache_pool_drop_in_dir_name(file_name: &str) -> Option<String> {
    let rest = file_name.strip_prefix("ghars-cache@")?;
    let pool = rest.strip_suffix(".service.d")?;
    if pool.is_empty() {
        return None;
    }
    Some(pool.to_owned())
}

/// Read every `*.conf` file under `dir` into a sorted basename-keyed
/// map. Missing dir → empty map.
fn read_drop_ins(dir: &Utf8Path) -> std::io::Result<BTreeMap<String, String>> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let read = match fs::read_dir(dir.as_std_path()) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in read {
        let entry = entry?;
        let file_type = entry.file_type()?;
        // Reject symlinks. ghars apply writes drop-in `*.conf`
        // bodies as real files; a symlink there could redirect a
        // read/rewrite outside the drop-in directory. Skip + warn
        // so neighbouring valid drop-ins still surface.
        if file_type.is_symlink() {
            tracing::warn!(
                path = %entry.path().display(),
                "state::read_drop_ins skipping symlink — \
                 ghars-managed drop-in *.conf files are always regular files; \
                 remove or replace the symlink"
            );
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let Ok(path) = Utf8PathBuf::try_from(entry.path()) else {
            continue;
        };
        let Some(basename) = path.file_name().map(str::to_owned) else {
            continue;
        };
        // Match `*.conf` case-insensitively (systemd treats unit + drop-
        // in suffixes as case-insensitive on disk; we mirror that for
        // discovery so an operator-named `OPS.CONF` still surfaces as
        // a drop-in).
        let is_conf = std::path::Path::new(&basename)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("conf"));
        if !is_conf {
            continue;
        }
        let body = fs::read_to_string(path.as_std_path())?;
        out.insert(basename, body);
    }
    Ok(out)
}

/// Classify drift structurally. `UnitEdited` is byte-mismatch against
/// [`crate::systemd::runner_template_text`]; `DropInsModified` is any
/// drop-in basename outside [`MANAGED_DROP_IN_BASENAMES`].
///
/// Collect the unmanaged basenames into the
/// `DropInsModified(Vec<String>)` / `Both(Vec<String>)` payload. Sort
/// is implicit — `BTreeMap` keys iterate in lexicographic order, so
/// the resulting Vec is sorted without an explicit `.sort()` call.
fn classify_drift(on_disk_unit_text: &str, drop_ins: &BTreeMap<String, String>) -> Drift {
    let unit_drifted = on_disk_unit_text != runner_template_text();
    let unmanaged: Vec<String> = drop_ins
        .keys()
        .filter(|name| !MANAGED_DROP_IN_BASENAMES.contains(&name.as_str()))
        .cloned()
        .collect();
    let drop_ins_drifted = !unmanaged.is_empty();
    match (unit_drifted, drop_ins_drifted) {
        (false, false) => Drift::InSync,
        (true, false) => Drift::UnitEdited,
        (false, true) => Drift::DropInsModified(unmanaged),
        (true, true) => Drift::Both(unmanaged),
    }
}

/// Classify drop-in drift for one cache pool. Symmetric to
/// [`classify_drift`] but cache pools share one
/// `ghars-cache@.service` template, so this only inspects drop-in
/// basenames against [`MANAGED_CACHE_DROP_IN_BASENAMES`]. Returns
/// `Drift::InSync` when every basename is managed, `DropInsModified`
/// (carrying the unmanaged basenames sorted by `BTreeMap` key order)
/// otherwise. `UnitEdited` / `Both` are never produced for cache pools.
fn classify_cache_pool_drift(drop_ins: &BTreeMap<String, String>) -> Drift {
    let unmanaged: Vec<String> = drop_ins
        .keys()
        .filter(|name| !MANAGED_CACHE_DROP_IN_BASENAMES.contains(&name.as_str()))
        .cloned()
        .collect();
    if unmanaged.is_empty() {
        Drift::InSync
    } else {
        Drift::DropInsModified(unmanaged)
    }
}

// --- Minimal systemd unit / drop-in parser -------------------------------

/// One parsed unit / drop-in. Sections map to a vector of `(key,
/// value)` pairs preserving source order; multiple assignments to the
/// same key are kept (systemd treats list-typed directives as
/// append).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ParsedUnit {
    sections: Vec<(String, Vec<(String, String)>)>,
}

impl ParsedUnit {
    /// Parse a unit file body. Mirrors systemd's `conf-parser.c`:
    /// - leading-whitespace `#` or `;` lines are comments,
    /// - trailing `\` is a continuation (joined with a single space),
    /// - section headers `[NAME]` introduce a new section,
    /// - everything else is `KEY=VALUE` (both strstrip'd).
    ///
    /// Lines outside any section are ignored (matches systemd's
    /// `Assignment outside of section` warning behaviour without
    /// `CONFIG_PARSE_RELAXED`).
    fn from_text(text: &str) -> Self {
        let mut out = ParsedUnit::default();
        let mut current_section: Option<String> = None;
        let mut continuation: Option<String> = None;

        for raw_line in text.lines() {
            // Comment-strip per systemd: only when the FIRST non-
            // whitespace char is `#` or `;`.
            let trimmed_left = raw_line.trim_start();
            let is_comment = matches!(trimmed_left.chars().next(), Some('#' | ';'));
            // Comments are skipped UNLESS we're mid-continuation —
            // systemd does NOT splice a comment line into the
            // continuation buffer (parse_line strstrips and drops
            // empties before the trailing-`\` check). The continuation
            // state survives a comment line because the prior `\`
            // already moved us into "expecting continuation" mode.
            if is_comment {
                continue;
            }

            // Combine with the pending continuation (if any).
            let logical: String = match continuation.take() {
                Some(prev) => format!("{prev}{raw_line}"),
                None => raw_line.to_owned(),
            };

            // Detect trailing `\` (with even-count escapes — `\\` is
            // a literal backslash, not a continuation marker). We walk
            // backwards so we don't re-scan the entire string.
            if has_unescaped_trailing_backslash(&logical) {
                let mut next = logical;
                // Replace the trailing `\` with a space, matching
                // conf-parser.c:397 (`*(e-1) = ' '`).
                let _ = next.pop();
                next.push(' ');
                continuation = Some(next);
                continue;
            }

            let l = logical.trim();
            if l.is_empty() {
                continue;
            }

            if let Some(section_name) = parse_section_header(l) {
                current_section = Some(section_name.to_owned());
                // Establish the section in `sections` if missing so
                // empty sections still register.
                if !out.sections.iter().any(|(name, _)| name == section_name) {
                    out.sections.push((section_name.to_owned(), Vec::new()));
                }
                continue;
            }

            // Outside any section → ignore (matches systemd's behaviour
            // without CONFIG_PARSE_RELAXED).
            let Some(section) = current_section.as_deref() else {
                continue;
            };

            // Split on the FIRST `=`. Lines without `=` are warnings
            // in systemd; here we silently drop them.
            let Some((key, value)) = l.split_once('=') else {
                continue;
            };
            let key = key.trim().to_owned();
            let value = value.trim().to_owned();
            if key.is_empty() {
                continue;
            }

            // Append to the section's bucket. We have already created
            // the bucket on `[NAME]` parse (see section-header branch
            // above), so `find` always returns Some — but if a buggy
            // future edit breaks that invariant we silently drop the
            // assignment rather than panicking.
            if let Some((_, bucket)) = out.sections.iter_mut().find(|(name, _)| name == section) {
                bucket.push((key, value));
            }
        }

        // A trailing-continuation buffer at EOF is treated as a logical
        // line per conf-parser.c:432-444 (else branch after the read
        // loop). Re-feed it through the same key=value path.
        if let Some(prev) = continuation.take() {
            let l = prev.trim();
            if let (Some((key, value)), Some(section)) = (l.split_once('='), current_section) {
                let key = key.trim().to_owned();
                let value = value.trim().to_owned();
                if !key.is_empty()
                    && let Some((_, bucket)) =
                        out.sections.iter_mut().find(|(name, _)| *name == section)
                {
                    bucket.push((key, value));
                }
            }
        }

        out
    }

    /// First value for `(section, key)`, or None.
    fn first<'a>(&'a self, section: &str, key: &str) -> Option<&'a str> {
        self.values(section, key).next()
    }

    /// All values for `(section, key)` in source order.
    fn values<'a>(&'a self, section: &str, key: &str) -> impl Iterator<Item = &'a str> {
        self.sections
            .iter()
            .filter(move |(name, _)| name == section)
            .flat_map(|(_, kv)| kv.iter())
            .filter(move |(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// True iff `[Unit] X-Ghars-Managed=true` is present (case-sensitive
    /// match — we only emit the lowercase `true` form).
    fn is_ghars_managed(&self) -> bool {
        self.first("Unit", X_GHARS_MANAGED_KEY)
            .is_some_and(|v| v == "true")
    }
}

/// Match `[NAME]` (no leading whitespace; trailing `]` mandatory).
/// Returns the section name on success.
fn parse_section_header(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('[')?;
    let inner = rest.strip_suffix(']')?;
    if inner.is_empty() {
        return None;
    }
    Some(inner)
}

/// True iff `line` ends with a `\` that is NOT itself escaped by an
/// even number of preceding `\\`. Mirrors conf-parser.c:389-394 which
/// flips the `escaped` flag on each `\\`.
fn has_unescaped_trailing_backslash(line: &str) -> bool {
    let bytes = line.as_bytes();
    if bytes.last().is_none_or(|b| *b != b'\\') {
        return false;
    }
    // Count the run of trailing backslashes; odd ⇒ unescaped.
    let mut n = 0usize;
    for b in bytes.iter().rev() {
        if *b == b'\\' {
            n += 1;
        } else {
            break;
        }
    }
    n % 2 == 1
}

// --- X-Ghars-* annotation accessor --------------------------------------

/// Systemd unit section name for [`extract_x_ghars_in_section`].
/// Replaces free-form `&str` so callers can't pass a typoed
/// `"service"` (lowercase) or `"unit"` and silently get an empty
/// result — `ParsedUnit` matches section headers byte-for-byte.
///
/// `Unit` and `Service` are the only sections [`extract_x_ghars`] /
/// [`extract_x_ghars_in_section`] callers need today: every
/// `X-Ghars-*` key `crate::systemd::render_identity` emits today
/// lives in `[Unit]`. The `Service` variant is retained for future
/// `[Service]`-section annotations and so callers don't have to
/// pass free-form strings. New variants get added here when a new
/// section is introduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdSection {
    /// `[Unit]` — identity + spec-hash X-Ghars-* annotations.
    Unit,
    /// `[Service]` — retained for future `[Service]`-section
    /// X-Ghars-* annotations; no current production emitter.
    Service,
}

impl SystemdSection {
    /// Section header name as it appears (without brackets) inside the
    /// drop-in body. Used by [`extract_x_ghars_in_section`] for the
    /// `ParsedUnit::sections` filter — must match the casing the
    /// systemd renderers produce in their `[Section]` headers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unit => "Unit",
            Self::Service => "Service",
        }
    }
}

/// Read every `X-Ghars-*` annotation from the `[Unit]` section of
/// `unit_text`. Useful for `ghars status` rendering and adversary
/// audits. Returned in source order; duplicate keys preserved.
///
/// Restricted to `[Unit]` because every `X-Ghars-*` key emitted
/// today by `crate::systemd::render_identity` lives there. Future
/// annotations in other sections require [`extract_x_ghars_in_section`]
/// with the matching [`SystemdSection`] variant.
#[must_use]
pub fn extract_x_ghars(unit_text: &str) -> Vec<(String, String)> {
    extract_x_ghars_in_section(unit_text, SystemdSection::Unit)
}

/// Read every `X-Ghars-*` annotation from the named section of
/// `unit_text`. Generalises [`extract_x_ghars`] to other sections —
/// pass [`SystemdSection::Service`] (or another variant) when an
/// `X-Ghars-*` annotation lands outside `[Unit]`. Returned in source
/// order; duplicate keys preserved.
///
/// Use [`extract_x_ghars_value`] when only one specific annotation
/// is needed — it avoids allocating the full `Vec<(String, String)>`
/// for the common single-key lookup.
#[must_use]
pub fn extract_x_ghars_in_section(
    unit_text: &str,
    section: SystemdSection,
) -> Vec<(String, String)> {
    let want = section.as_str();
    let parsed = ParsedUnit::from_text(unit_text);
    parsed
        .sections
        .iter()
        .filter(|(name, _)| name == want)
        .flat_map(|(_, kv)| kv.iter())
        .filter(|(k, _)| k.starts_with("X-Ghars-"))
        .cloned()
        .collect()
}

/// Look up the first value for one specific X-Ghars-* annotation
/// inside the given section. Point-lookup variant of
/// [`extract_x_ghars_in_section`] — no full Vec allocation, just
/// returns the first matching value (or `None`).
///
/// `key` is the full annotation key including the `X-Ghars-` prefix
/// (e.g. `"X-Ghars-Runner-Name"`). Mirrors the semantics of
/// `ParsedUnit::first`: section header match is byte-for-byte
/// (use [`SystemdSection`] to avoid casing typos), key match is
/// exact-string. Empty values return `Some("")`; absent keys return
/// `None`.
#[must_use]
pub fn extract_x_ghars_value(
    unit_text: &str,
    section: SystemdSection,
    key: &str,
) -> Option<String> {
    ParsedUnit::from_text(unit_text)
        .first(section.as_str(), key)
        .map(str::to_owned)
}

// --- Tests ---------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "state_tests.rs"]
mod tests;
