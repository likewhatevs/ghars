//! Defaults merge for runner specs (Part 3 "Defaults merge rules" table)
//! and the supporting hardening field-by-field merge. Produces an
//! [`EffectiveRunnerSpec`] from a `RunnerSpec` + `Defaults` plus
//! caller-resolved cross-references (auth, caches, network, proxy,
//! hooks, host arch, config source).

use std::collections::HashSet;

use crate::config::{
    Arch, Defaults, EffectiveCacheBinding, EffectiveNetworkBinding, EffectiveRunnerSpec,
    EnvironmentSpec, Hardening, RunnerSpec,
};

use super::DEFAULT_TRUST_ZONE;

/// Merge `[defaults]` into a `RunnerSpec`, producing an
/// [`EffectiveRunnerSpec`] (Part 3 "Defaults merge rules" table).
///
/// Per-field rules:
/// - `name`, `url` — from runner only (identity, no merge).
/// - `arch` — runner overrides defaults; both unset ⇒ host arch
///   (resolved by the caller and threaded in via `host_arch`).
/// - `labels` — `concat(defaults.labels, runner.labels)`, HashSet-dedup
///   (drop entries already inserted), sort alphabetically (byte-wise
///   `Ord`) for `spec_hash` reorder-invariance, then `Vec::dedup` as
///   defense-in-depth. Empty after merge ⇒ defaults to `[name]` (Python
///   parity), then sorted (no-op for one element).
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
/// Inputs threaded by the caller (because `merge_defaults` can't fetch
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
/// [`super::spec_hash`] on the result to fill it. Two-step pattern keeps
/// the hash domain (`canonical_json` of the spec) and the spec
/// construction orthogonal.
///
/// Canonicalization asymmetry between `caches` and `labels`:
///
/// - `caches`: `merge_defaults` threads the caller-supplied bindings
///   verbatim. Reorder-invariant `spec_hash` for caches requires going
///   through [`super::compute::lower_to_effective`], which sorts
///   `caches` by name as part of cache-pool resolution. Direct
///   `merge_defaults` callers (test fixtures, future synthetic spec
///   builders) must sort their caches Vec themselves if they care about
///   hash stability across operator-supplied orderings.
///
/// - `labels`: `merge_defaults` DOES canonicalize labels. After
///   concat-and-dedup of `defaults.labels` and `runner.labels`,
///   `merge_defaults` sorts the resulting Vec alphabetically (and
///   applies `dedup` as defense-in-depth). Direct callers therefore
///   inherit reorder-invariant `spec_hash` for labels without going
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
    // the ASCII subset enforced by `validate_labels`.
    //
    // TRIPLE-SORT COUPLING (defense-in-depth): three independent sort
    // sites must all agree on byte-order ascending sort to keep label
    // canonicalization consistent across the produce/render/parse
    // pipeline. Removing or weakening any one of them silently breaks
    // the round-trip identity that drives reorder-invariant plans.
    //
    //   1. `merge_defaults` (HERE) — produces canonical labels Vec on
    //      EffectiveRunnerSpec; feeds spec_hash and the renderer.
    //   2. `crate::systemd::render_identity` — defensive re-sort at
    //      `X-Ghars-Labels=` emission for direct EffectiveRunnerSpec
    //      callers that bypass merge_defaults.
    //   3. `DiscoveredAnnotations::from_drop_in_body` — defensive
    //      re-sort at parse boundary so every consumer of `out.labels`
    //      sees canonical order regardless of on-disk byte order.
    //
    // All three must use the same comparator (byte-order, ascending)
    // and the same sort discipline (sort the Vec, not the iter-derived
    // copy). A divergence — for example, switching one site to
    // case-insensitive or locale-aware sort — would produce a
    // canonical-spec_hash ↔ on-disk-annotation drift undetectable by
    // the Stage 1 classifier and silently re-trigger spurious
    // recreates.
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
        labels,
        // Collapse Some("") → None for string-valued optionals so the
        // spec_hash domain matches the render domain. `render_memory`
        // returns Ok(None) for an empty string (no 10-memory.conf
        // emitted), but Some("") and None serialize differently in
        // canonical-JSON. Without the filter, operator-toggled empty
        // strings flip spec_hash without changing any rendered byte —
        // a dark input that drives spurious cascades.
        memory_max: runner
            .memory_max
            .clone()
            .or_else(|| defaults.memory_max.clone())
            .filter(|s| !s.is_empty()),
        runner_version: runner
            .runner_version
            .clone()
            .or_else(|| defaults.runner_version.clone()),
        // Same Some("") → None collapse as memory_max above —
        // `render_identity` emits X-Ghars-Runner-Sha256 only when
        // Some(non-empty), so the empty and absent cases render
        // identically.
        runner_sha256: runner
            .runner_sha256
            .clone()
            .or_else(|| defaults.runner_sha256.clone())
            .filter(|s| !s.is_empty()),
        // Same Some("") → None collapse as memory_max / runner_sha256
        // above. `render_identity` emits `X-Ghars-Runner-Tarball-Hash`
        // only when Some(non-empty); without the filter, empty and
        // absent would render different drop-in bytes (None → no
        // line; Some("") → sha256 of the empty string), flipping
        // spec_hash. Unlike memory_max / allowed_cpus, operator TOML
        // cannot reach this filter — `validate_runner_tarball` at
        // config-load (`cli/load.rs` `validate_runner_tarballs`)
        // rejects empty paths with "must be absolute" (empty paths
        // are not absolute per `Path::new("").is_absolute() == false`).
        // The filter is defense-in-depth for direct-construct callers
        // (test fixtures, future programmatic spec builders) that
        // bypass `cli::load`. No `.or_else(defaults.runner_tarball)`
        // cascade: `Defaults` carries no `runner_tarball` field today.
        runner_tarball: runner
            .runner_tarball
            .clone()
            .filter(|p| !p.as_str().is_empty()),
        auth_name,
        caches,
        trust_zone,
        network,
        proxy,
        hooks,
        hardening: merge_hardening(&runner.hardening, &defaults.hardening),
        // Same Some("") → None collapse as memory_max / runner_sha256
        // above — `render_numa` returns Ok(None) for empty strings,
        // so the empty and absent cases render identically, and
        // normalizing at merge time keeps spec_hash byte-stable
        // across the operator-toggled empty-string dark input. No
        // `.or_else(defaults.allowed_*)` cascade: `Defaults` carries
        // no `allowed_cpus` / `allowed_memory_nodes` field today.
        allowed_cpus: runner.allowed_cpus.clone().filter(|s| !s.is_empty()),
        allowed_memory_nodes: runner
            .allowed_memory_nodes
            .clone()
            .filter(|s| !s.is_empty()),
        environment: merge_environment(&runner.environment, &defaults.environment),
        spec_hash: String::new(),
        config_source,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    }
}

/// Merge `[defaults.environment]` into `[[runner]].environment`:
///   - `vars`: per-key overlay — defaults `BTreeMap` is the base, runner
///     entries extend AND override on collision (runner-set keys win
///     per the standard scalar-override semantic mirrored from
///     `memory_max` etc.).
///   - `path_prepend` / `path_append`: additive — defaults entries
///     first, then runner entries; dedup preserves first-occurrence
///     order to keep PATH search-order semantics intact while
///     stripping duplicate segments (mirrors `extra_bind_paths`'s
///     additive pattern with added dedup since PATH lookups would
///     repeat the second hit but waste cycles re-searching the same
///     dir).
///
/// Note: this helper does NOT consult the framework-emitted env vars
/// (LANG / `CCACHE_DIR` / KTSTR_* / SCCACHE_* / HOME / PATH / TMPDIR /
/// `HTTP_PROXY` family / `ACTIONS_RUNNER_HOOK`_*). Framework < operator
/// precedence is enforced by (a) renderer composition order (framework
/// emitted first, operator vars appended) and (b) config-load
/// validation that rejects operator keys colliding with framework-
/// emitted ones (see `crate::validators::validate_environment_spec`).
pub(super) fn merge_environment(
    runner: &EnvironmentSpec,
    defaults: &EnvironmentSpec,
) -> EnvironmentSpec {
    let mut vars = defaults.vars.clone();
    for (k, v) in &runner.vars {
        vars.insert(k.clone(), v.clone());
    }
    let path_prepend = additive_path_merge(&defaults.path_prepend, &runner.path_prepend);
    let path_append = additive_path_merge(&defaults.path_append, &runner.path_append);
    EnvironmentSpec {
        vars,
        path_prepend,
        path_append,
    }
}

fn additive_path_merge(
    defaults: &[camino::Utf8PathBuf],
    runner: &[camino::Utf8PathBuf],
) -> Vec<camino::Utf8PathBuf> {
    let mut out: Vec<camino::Utf8PathBuf> =
        Vec::with_capacity(defaults.len() + runner.len());
    let mut seen: HashSet<camino::Utf8PathBuf> = HashSet::new();
    for p in defaults.iter().chain(runner.iter()) {
        if seen.insert(p.clone()) {
            out.push(p.clone());
        }
    }
    out
}

pub(super) fn merge_hardening(runner: &Hardening, defaults: &Hardening) -> Hardening {
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
        // NOT sorted in this layer because systemd's PID 1 user-space
        // sorts mount entries parent-first via `mount_path_compare`
        // (`systemd/src/core/namespace.c:1003`, called from
        // `sort_and_drop_unused_mounts` at namespace.c:2306-2318)
        // BEFORE issuing any `mount(2)` syscall, so operator-declared
        // order is discarded in user-space and never reaches the
        // kernel's mount-overlay state. The sort abstention here is
        // for byte-equality between the
        // operator's TOML and the rendered `BindReadOnlyPaths=`
        // drop-in line: a sort-induced reorder would (a) flip
        // `spec_hash` (different JSON → different SHA256 →
        // spurious in-place UpdateRunner cascade per
        // RENDERER_SCHEMA semantics) and (b) make the operator's
        // TOML order non-canonical (re-deploy with the original
        // ordering would not produce a NoOp).
        bind_readonly_paths: runner
            .bind_readonly_paths
            .clone()
            .or_else(|| defaults.bind_readonly_paths.clone()),
        // extra_bind_paths is additive across both sides — both apply.
        // NOT sorted: same byte-equality rationale as
        // bind_readonly_paths above (systemd's PID 1 user-space sort
        // discards operator order before any `mount(2)` syscall reaches
        // the kernel; the renderer preserves operator order for
        // spec_hash stability).
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

    // Canonicalize set-semantic Vec fields by sorting AND deduping
    // in place so a pure operator reorder (or accidental duplicate) in
    // TOML produces an identical EffectiveRunnerSpec → identical
    // spec_hash → NoOp instead of an unnecessary recreate. Mirrors the
    // caches canonicalization in `lower_to_effective`.
    //
    // Only canonicalized fields here are set-semantic (the operator's
    // intent is "use exactly this set"; order and duplicates do not
    // change effective behavior):
    //   - `restrict_address_families` → RestrictAddressFamilies= appends
    //     with union semantics across drop-in lines, set-semantic.
    //     Token shape gated upstream by `validate_restrict_address_families`
    //     (validators.rs) — `AF_FAMILY_RE` (`^AF_[A-Z0-9_]+$`) rejects
    //     `~`-prefix tokens at config-load by shape, so a `~AF_*` token
    //     never reaches this sort and cannot subvert systemd's polarity.
    //   - `extra_syscalls` → SystemCallFilter= is APPEND with union
    //     semantics (consecutive lines union the allowlist), so order
    //     is not load-bearing. Token shape gated upstream by
    //     `validate_extra_syscalls` (validators.rs) — `SYSCALL_NAME_RE`
    //     (`^[a-z_][a-z0-9_]*$`) + explicit `~`-prefix / `@`-prefix /
    //     `:` / surrounding-whitespace rejects, so a `~`-prefix token
    //     never reaches this sort. Without the upstream gate, systemd's
    //     `config_parse_syscall_filter` parser (`systemd/src/core/
    //     load-fragment.c` line 3238-3241) would flip the WHOLE
    //     directive from allow-list to deny-list whenever a `~`-prefix
    //     token landed at position 0 of the joined directive value
    //     (which happens trivially when it's the only token in the
    //     Vec).
    //   - `extra_capabilities` → CapabilityBoundingSet= unions across
    //     drop-in lines. Token shape gated upstream by
    //     `validate_extra_capabilities` — `CAP_RE` (`^CAP_[A-Z0-9_]+$`)
    //     rejects `~`-prefix tokens at config-load by shape, so a
    //     `~CAP_*` token never reaches this sort.
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
    // spurious drift class the sort prevents.
    //
    // Fields explicitly NOT sorted (byte-equality between operator
    // TOML and rendered drop-in line; systemd's own mount-order
    // normalization runs in user-space — `mount_path_compare`
    // in `systemd/src/core/namespace.c` — before the kernel sees
    // any mount syscall — see the bind_readonly_paths and
    // extra_bind_paths comments above).
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
