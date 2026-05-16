//! Config-file loading + post-load validator sweep.
//!
//! `load_config` reads `ghars.toml`, parses it via serde, and runs the
//! semantic validators in a fixed order. Every cmd_* entry point that
//! consumes a config goes through this single chokepoint so the gate
//! cannot drift across surfaces.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::LazyLock;

use camino::Utf8Path;
use regex::Regex;
use unicode_general_category::{GeneralCategory, get_general_category};

use crate::Result;
use crate::auth::{TokenSource, build_token_source};
use crate::config::{AuthSpec, Config, Hardening, HooksSpec};
use crate::error::GharsError;
use crate::validators;

/// Load config.toml from `path` using `toml::from_str` +
/// `std::fs::read_to_string`. The CLI owns the IO + post-load
/// validator sweep; `config::Config` is pure serde.
pub(super) fn load_config(path: &Utf8Path) -> Result<Config> {
    let raw = fs::read_to_string(path.as_std_path()).map_err(|e| {
        GharsError::Config(
            format!("read {path}: {e}"),
            "ensure the config file exists and is readable".into(),
        )
    })?;
    let cfg: Config = toml::from_str(&raw).map_err(|e| {
        GharsError::Config(
            format!("parse {path}: {e}"),
            "fix the TOML syntax / schema; see `ghars validate`".into(),
        )
    })?;
    // SEC-30: deserialize-time serde validation only enforces
    // structural shape (#[serde(deny_unknown_fields)] + the typed
    // EgressRule fields). The semantic validators below live behind
    // post-load helpers — running them eagerly here means every CLI
    // entry point that calls load_config (cmd_validate, cmd_plan,
    // cmd_apply, cmd_status, cmd_add) gets the same gate. A missed
    // call site at any of them would re-introduce the corresponding
    // SEC attack surface (e.g. operator-controlled EgressRule.comment
    // with quote-breaking chars reaches render_nft_rules without going
    // through validate_egress_comment).
    //
    // build_auth_registry in cmd_validate / cmd_apply runs AFTER
    // load_config's full sweep: config-shape gates run before
    // external-IO / file-mode gates so an operator with both invalid
    // auth AND a config-validation failure addresses the structurally-
    // broken config first, then fixes auth.
    //
    // Each section below documents one validator. Order is
    // semantically meaningful and preserved across this section.
    //
    // --- validate_networks ---
    // SEC-30 (egress comment) + DNS / address-family shape.
    //
    // --- validate_security_overrides ---
    // SEC-01 (extra_capabilities / extra_bind_paths) + SEC-12 (hooks).
    // Conditionally filesystem-touching: when [hooks] or
    // [[runner]].hooks is set, validate_hook_script opens the script
    // with O_NOFOLLOW and inspects mode / uid. With no hooks
    // configured, the validator is shape-only.
    //
    // --- validate_identity_fields ---
    // trust_zone control-char rejection.
    //
    // --- validate_trust_zone_lengths ---
    // trust_zone length cap (≤ TRUST_ZONE_MAX_LEN = 22) so the
    // rendered DynamicUser identity ghars-tz-<TRUST_ZONE> fits
    // systemd's strict 31-char valid_user_group_name ceiling.
    //
    // --- validate_no_duplicate_caches ---
    // Dedup-loop trap.
    //
    // --- validate_no_duplicate_cache_kinds ---
    // At-most-one-pool-per-CacheKind per runner. Sibling of
    // validate_no_duplicate_caches at the resolved-kind layer — two
    // distinct pools each contributing the same kind would clobber
    // CCACHE_DIR / CCACHE_MAXSIZE / SCCACHE_SERVER_UDS via
    // last-writer-wins shell .env and systemd Environment= semantics.
    //
    // --- validate_cache_pool_kinds_nonempty ---
    // Reject [cache_pools.NAME] kinds = [] (empty Vec). Empty kinds
    // produces a silently-dead `ghars-cache@NAME.service` (sleep
    // infinity stub, no env vars) that operators only notice when
    // workflows fail to find expected env vars. Sibling of
    // validate_no_duplicate_cache_kinds at the dual boundary —
    // duplicates and emptiness are both "wrong number of kinds"
    // failure modes serde can't catch.
    //
    // --- validate_cache_pool_names ---
    // Identifier-shape gate on pool keys and runner.caches refs.
    //
    // --- validate_runner_names ---
    // Identifier-shape gate on every [[runner]] name. Netns-mode
    // runners face an additional tighter cap enforced separately by
    // validate_netns_runner_name_lengths below.
    //
    //
    // --- validate_pat_xor ---
    // AuthSpec::Pat shape-only XOR check on token_env /
    // token_file (re-validated by PatToken::new at apply). Shape-only
    // (no filesystem access). PatToken::new runs SEC-25 (mode / owner
    // / symlink) at apply.
    //
    // --- validate_proxy_ca_certs_nonempty ---
    // [proxy] ca_certs entry shape gate. Rejects empty/whitespace-
    // only `env` (would emit `Environment==<path>` rejected by
    // systemd's `[a-zA-Z_][a-zA-Z0-9_]*` Environment= grammar),
    // empty/whitespace-only `path` (would emit `Environment=NAME=`
    // empty value defeating CA-bundle purpose), and non-absolute
    // `path` (rejected by BindReadOnlyPaths= which requires
    // absolute paths). Walks both [defaults] proxy and per-runner
    // [[runner]].proxy because runner.proxy entirely overrides
    // defaults via or_else, so a malformed defaults still leaks
    // into runners that don't override.
    //
    // --- validate_proxy_no_proxy_nonempty_entries ---
    // [proxy] no_proxy entry shape gate. Rejects empty/whitespace-
    // only string entries that would comma-join into a malformed
    // NO_PROXY env var (e.g. `host,,host2` or `host,   ,host2`)
    // that strict-parsing HTTP clients reject. Walks both layers
    // for the same reason as validate_proxy_ca_certs_nonempty
    // above.
    //
    // --- validate_runner_tarballs ---
    // O_NOFOLLOW open + fstat regular-file gate on operator-supplied
    // runner_tarball paths. Filesystem-touching (alongside
    // validate_security_overrides when hooks are configured).
    // Placed after the identifier-shape gates so an operator hitting
    // a typo in another [defaults.*] key sees that error before a
    // separate "tarball missing" error from a per-runner override.
    //
    // --- validate_netns_runner_name_lengths ---
    // IFNAMSIZ (kernel veth name) cap (= NETNS_RUNNER_NAME_MAX_LEN,
    // 7) on operator-chosen runner names whose effective network mode
    // resolves to Netns. Runs LAST because it depends on
    // validate_networks having already accepted the [network.NAME] map
    // shape — an unresolved network key here falls through (the
    // validate_networks gate will have surfaced the error) so we don't
    // double-report. Skipped for Open-mode runners which don't allocate
    // a veth pair.
    crate::config::validate_networks(&cfg)?;
    validate_security_overrides(&cfg)?;
    validate_identity_fields(&cfg)?;
    validate_trust_zone_lengths(&cfg)?;
    validate_no_duplicate_caches(&cfg)?;
    validate_no_duplicate_cache_kinds(&cfg)?;
    validate_cache_pool_kinds_nonempty(&cfg)?;
    validate_no_duplicate_kinds_within_pool(&cfg)?;
    validate_cache_pool_names(&cfg)?;
    validate_cache_pool_binary_paths(&cfg)?;
    validate_runner_names(&cfg)?;
    validate_auth_keys(&cfg)?;
    validate_pat_xor(&cfg)?;
    validate_proxy_ca_certs_nonempty(&cfg)?;
    validate_proxy_no_proxy_nonempty_entries(&cfg)?;
    validate_runner_tarballs(&cfg)?;
    validate_netns_runner_name_lengths(&cfg)?;
    crate::config::validate_environments(&cfg)?;
    crate::config::validate_runner_versions(&cfg)?;
    Ok(cfg)
}

/// Build the auth registry — one `TokenSource` per `[auth.NAME]` block.
/// Each source is constructed eagerly so `validate --deep` and `apply`
/// surface env / file-mode misconfiguration before any GitHub call.
pub(super) fn build_auth_registry(
    auth: &indexmap::IndexMap<String, AuthSpec>,
) -> Result<HashMap<String, Box<dyn TokenSource>>> {
    let mut out: HashMap<String, Box<dyn TokenSource>> = HashMap::with_capacity(auth.len());
    for (name, spec) in auth {
        out.insert(name.clone(), build_token_source(spec, name)?);
    }
    Ok(out)
}

// ---------- security-override validators (SEC-01, SEC-12) ---------------

/// Run SEC-01 + SEC-12 validators across the [defaults] block and every
/// `[[runner]]` block.
///
/// SEC-01 — `Hardening.extra_capabilities` and
/// `Hardening.extra_bind_paths` go through the deny-list validators
/// in `validators::validate_extra_capabilities` /
/// `validators::validate_extra_bind_paths`. Both `[defaults.hardening]`
/// and per-runner `[[runner]].hardening` are checked; a value at
/// either layer that hits a deny entry rejects the entire config.
///
/// SEC-12 — `HooksSpec.pre_job` and `post_job` go through
/// `validators::validate_hook_script` which lstat's the path and
/// rejects symlinks, non-files, mode missing owner-execute, or
/// ownership != root.
///
/// Defaults are validated FIRST so a denied default surfaces with the
/// `[defaults]` label instead of being attributed to whichever runner
/// inherited it. Runners are walked in source order; the first
/// failure short-circuits.
///
/// # Errors
///
/// `GharsError::Validation` wrapping the underlying validator error.
/// The wrapper prepends `"defaults: "` or `"runner NAME: "` so the
/// operator can locate the offending block in their TOML.
pub(super) fn validate_security_overrides(cfg: &Config) -> Result<()> {
    // [defaults.hardening]
    validate_hardening_block(&cfg.defaults.hardening)
        .map_err(|e| crate::error::prepend_validation_scope("defaults", e))?;
    // [defaults.hooks]
    if let Some(hooks) = cfg.hooks.as_ref() {
        validate_hooks_block(hooks)
            .map_err(|e| crate::error::prepend_validation_scope("hooks", e))?;
    }

    for runner in &cfg.runners {
        validate_hardening_block(&runner.hardening)
            .map_err(|e| crate::error::prepend_runner_scope(&runner.name, e))?;
        if let Some(hooks) = runner.hooks.as_ref() {
            validate_hooks_block(hooks)
                .map_err(|e| crate::error::prepend_runner_scope(&runner.name, e))?;
        }
    }
    Ok(())
}

pub(super) fn validate_hardening_block(h: &Hardening) -> Result<()> {
    validators::validate_extra_capabilities(&h.extra_capabilities)?;
    validators::validate_extra_bind_paths(&h.extra_bind_paths)?;
    validators::validate_restrict_address_families(
        "hardening.restrict_address_families",
        &h.restrict_address_families,
    )?;
    validators::validate_extra_syscalls(&h.extra_syscalls)?;
    Ok(())
}

pub(super) fn validate_hooks_block(h: &HooksSpec) -> Result<()> {
    if let Some(pre) = h.pre_job.as_ref() {
        validators::validate_hook_script(pre.as_path())?;
    }
    if let Some(post) = h.post_job.as_ref() {
        validators::validate_hook_script(post.as_path())?;
    }
    Ok(())
}

// ---------- duplicate-cache validator -----------------------------------

/// Reject `[[runner]] caches = ["a", "a"]` at config load. A duplicate
/// in the source `Vec<String>` would render two identical
/// `X-Ghars-Caches=` entries (X-Ghars-Caches is a comma-joined CSV
/// emitted in `render_identity`) and would trigger an in-place
/// spec-hash bump every time the apply path canonicalizes the
/// bindings into a `BTreeSet`. Catching the duplicate at load time
/// gives the operator a scoped error (`runner "NAME": ...`) instead
/// of a confusing drift loop.
///
/// The runner's index in `cfg.runners` is the iteration order; first
/// duplicate found inside a single `[[runner]]` block aborts the
/// validator. Cross-runner reuse of the same pool is fine — pools
/// are explicitly designed to be referenced by multiple runners
/// (`CacheMode::Shared` is `CachePoolSpec.mode`'s `#[default]`).
///
/// # Errors
///
/// `GharsError::Validation` naming the runner and the duplicated pool
/// name. The hint tells the operator to remove the duplicate entry.
pub(super) fn validate_no_duplicate_caches(cfg: &Config) -> Result<()> {
    for runner in &cfg.runners {
        let mut seen: HashSet<&str> = HashSet::with_capacity(runner.caches.len());
        for cache in &runner.caches {
            if !seen.insert(cache.as_str()) {
                return Err(GharsError::Validation(
                    format!(
                        "runner {:?}: duplicate cache pool reference {cache:?} in caches list",
                        runner.name
                    ),
                    "remove the duplicate entry from [[runner]].caches; pools may be \
                     referenced from multiple runners but never twice from one"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

// ---------- no-duplicate-cache-kinds-per-runner validator ---------------

/// Reject configs where a runner references 2+ cache pools that share
/// any single `CacheKind`. Sibling of [`validate_no_duplicate_caches`]
/// at the literal-pool-ref layer; this validator works at the resolved-
/// kind layer (two distinct pools, both contributing the same kind to
/// the runner).
///
/// Singleton-per-kind is enforced because each kind's renderer emits
/// per-pool / per-binding env vars that would silently shadow each
/// other under last-writer-wins semantics — either systemd
/// `Environment=` (Layer 1: `00-ghars.conf` / `30-cache-pool.conf`) or
/// shell `.env` loader (Layer 2: actions/runner's
/// `Runner.Listener::LoadAndSetEnv`). The operator's mental model
/// ("this runner uses two ccache pools") cannot be satisfied:
/// ccache is single-`CCACHE_DIR`-per-process by hard upstream design
/// (`Config::read` in ccache's `src/ccache/config.cpp` picks ONE
/// `cache_dir` from a strict resolution chain with no loop / list /
/// multi-pool concept; config-file `cache_dir` is explicitly ignored
/// to prevent recursion; the only multi-storage path is
/// `remote_storage` for secondary HTTP/Redis backends on top of the
/// primary local `CCACHE_DIR`); sccache similarly reads a single
/// `SCCACHE_SERVER_UDS`. Multi-pool-of-same-kind silently reduces to
/// "one effective pool, last-wins on `*_MAXSIZE`".
///
/// Adding a new `CacheKind` variant: append a `lww_reason` match
/// arm IFF the variant's renderer emits per-pool `Environment=KEY=value`
/// or per-binding `.env KEY=value` entries that would clash with
/// another binding of the same kind. Singleton-per-kind enforcement is
/// correct only when the per-pool emissions actually exist — a kind
/// that emits no per-pool env entries doesn't need this gate.
///
/// # Errors
///
/// `GharsError::Validation` naming the runner, the kind, and the
/// conflicting pools. The hint offers two remediations: drop all but
/// one pool of that kind, OR merge the kinds into one
/// `[cache_pools.NAME]` entry.
pub(super) fn validate_no_duplicate_cache_kinds(cfg: &Config) -> Result<()> {
    use crate::config::CacheKind;
    // Per-kind `lww_reason` text. Kind iteration uses
    // `CacheKind::ALL` so a new variant added to the enum surfaces
    // here at compile time via the exhaustive match.
    let lww_reason = |kind: CacheKind| -> &'static str {
        match kind {
            CacheKind::Ccache => {
                "ghars wires a trust-zone-shared CCACHE_DIR \
                 (/var/lib/ghars/<TRUST_ZONE>/.ccache) and emits one \
                 CCACHE_MAXSIZE per binding in the runner's .env — ccache \
                 is single-CCACHE_DIR-per-process by upstream design, so \
                 multiple ccache pools cannot deliver distinct cache dirs \
                 and the per-binding CCACHE_MAXSIZE values race in the \
                 .env load (last wins)"
            }
            CacheKind::Sccache => {
                "SCCACHE_SERVER_UDS is single-valued and additional pools \
                 would be silently shadowed by systemd's last-writer-wins \
                 Environment= semantics"
            }
            CacheKind::Ktstr => {
                "ghars wires a trust-zone-shared KTSTR_CACHE_DIR + KTSTR_LOCK_DIR \
                 (/var/lib/ghars/<TRUST_ZONE>/.ktstr) — ktstr resolves a single \
                 KTSTR_CACHE_DIR per process (env::var lookup with no list \
                 semantics), so multiple ktstr pools cannot deliver distinct \
                 cache dirs and the env emission would be silently shadowed"
            }
        }
    };
    for runner in &cfg.runners {
        for &kind in CacheKind::ALL {
            let label = kind.label();
            let refs: Vec<&str> = runner
                .caches
                .iter()
                .filter_map(|cache_ref| {
                    cfg.cache_pools
                        .get(cache_ref)
                        .filter(|spec| spec.kinds.contains(&kind))
                        .map(|_| cache_ref.as_str())
                })
                .collect();
            if refs.len() > 1 {
                return Err(GharsError::Validation(
                    format!(
                        "runner {:?}: references {} {label} pools ({}); only one pool of \
                         each cache kind is permitted per runner",
                        runner.name,
                        refs.len(),
                        refs.join(", "),
                    ),
                    format!(
                        "either drop all but one {label} pool from [[runner]].caches, or \
                         merge the kinds into a single [cache_pools.NAME] entry — {}",
                        lww_reason(kind),
                    ),
                ));
            }
        }
    }
    Ok(())
}

// ---------- cache-pool-kinds-nonempty validator -------------------------

/// Reject `[cache_pools.NAME] kinds = []` at config load. An empty
/// kinds Vec reaches `render_cache_pool` and `render_cache_drop_in`
/// without contributing any per-pool emission. The pool's
/// `ghars-cache@NAME.service` still renders, falling through to
/// `render_cache_drop_in`'s ccache-only else branch which emits
/// `ExecStart=<sleep_path> infinity` — a silently-dead cache pool
/// unit that runs but contributes no env vars and serves no
/// workload. The operator probably meant `kinds = ["ccache"]`,
/// `kinds = ["sccache"]`, or `kinds = ["ktstr"]`; surfacing the
/// error at config load gives
/// a scoped `cache_pool "NAME":` prefix instead of a silent dead
/// pool that operators only notice when workflows fail to find
/// expected env vars.
///
/// Sibling of [`validate_no_duplicate_cache_kinds`] at the dual
/// boundary — duplicates and emptiness are both "operator typed the
/// wrong number of kinds" failure modes the deserializer can't
/// catch (the `Vec<CacheKind>` field has no minimum-length
/// constraint).
///
/// # Errors
///
/// `GharsError::Validation` naming the pool and recommending the
/// canonical fixes (specify at least one of `ccache`, `sccache`,
/// or `ktstr`).
pub(super) fn validate_cache_pool_kinds_nonempty(cfg: &Config) -> Result<()> {
    for (name, pool) in &cfg.cache_pools {
        if pool.kinds.is_empty() {
            return Err(GharsError::Validation(
                format!("cache_pool {name:?}: declared empty `kinds = []`"),
                "specify at least one of `ccache`, `sccache`, or `ktstr` in \
                 [cache_pools.NAME] kinds — an empty kinds list contributes no \
                 per-pool emissions and produces a silently-dead \
                 `ghars-cache@NAME.service` unit (ExecStart falls through to \
                 `sleep infinity` with no env vars) that operators only notice \
                 when workflows fail to find expected env vars"
                    .into(),
            ));
        }
    }
    Ok(())
}

/// Reject `[cache_pools.NAME] kinds = ["ccache", "ccache"]` at config
/// load. Duplicate kinds within a single pool's `kinds` Vec are
/// semantically redundant (each kind is single-valued per process —
/// see [`validate_no_duplicate_cache_kinds`] for the upstream-tool
/// contract for each kind) but the deserializer accepts the
/// duplicate at the Vec layer.
///
/// Even with `canonicalize_kinds` (the per-kinds-Vec sort helper at
/// `src/plan/compute.rs`) sorting
/// the Vec at the lowering boundary, the duplicate persists into
/// `cache_pool_hash` (`serde_json` serializes `["ccache","ccache"]`
/// distinctly from `["ccache"]`) AND into the rendered
/// `X-Ghars-Pool-Kinds=ccache,ccache` CSV — operator-visible
/// artifacts that misrepresent the pool's effective kind set.
///
/// Surfacing the duplicate at config-load gives a scoped
/// `cache_pool "NAME":` prefix the operator can act on, rather
/// than silently rendering the duplicate through to disk.
///
/// Sibling of [`validate_cache_pool_kinds_nonempty`] —
/// both are within-pool kind-Vec sanity gates the deserializer
/// can't catch (the `Vec<CacheKind>` field has no length-bound
/// or set-semantic constraint at the serde layer).
///
/// # Errors
///
/// `GharsError::Validation` naming the pool and the duplicated
/// kind label, with a remediation hint to drop the duplicate.
pub(super) fn validate_no_duplicate_kinds_within_pool(cfg: &Config) -> Result<()> {
    use crate::config::CacheKind;
    for (name, pool) in &cfg.cache_pools {
        for &kind in CacheKind::ALL {
            let count = pool.kinds.iter().filter(|&&k| k == kind).count();
            if count > 1 {
                let label = kind.label();
                return Err(GharsError::Validation(
                    format!("cache_pool {name:?}: declares `{label}` {count} times in `kinds`"),
                    format!(
                        "drop the duplicate `{label}` entry from [cache_pools.{name}] \
                         kinds — each cache kind is single-valued per process and a \
                         duplicate within one pool's kinds Vec is operator-redundant. \
                         `canonicalize_kinds` sorts the Vec at the lowering boundary \
                         but does not dedup, so the duplicate persists into both \
                         `cache_pool_hash` (inflating the SHA256 input) and the \
                         rendered `X-Ghars-Pool-Kinds` CSV (the duplicate `{label}` \
                         tokens land alongside any other distinct kinds in the same \
                         pool) without any semantic effect"
                    ),
                ));
            }
        }
    }
    Ok(())
}

// ---------- cache-pool-name validation ----------------------------------

/// Apply identifier-shape validation to every `[cache_pools.NAME]`
/// key and every `[[runner]] caches = [...]` reference. Validation
/// runs through `validators::validate_cache_pool_name` (a wrapper
/// over `validate_identifier`); the per-name surface bound is
/// [`crate::config::IDENTIFIER_MAX_LEN`].
///
/// Defense-in-depth on runner.caches: the plan-time cross-reference
/// in `plan::lower_to_effective` matches the entry against
/// `cfg.cache_pools.keys()` and rejects unknown names ("unknown
/// cache pool"). Validating each entry here closes the gap for any
/// future code path that synthesizes an `EffectiveCacheBinding`
/// without that lookup — every config-surface reference still passes
/// through the identifier shape gate.
///
/// # Errors
///
/// `GharsError::Validation` wrapping `validators::validate_cache_pool_name`
/// with the `cache_pool "NAME":` or `runner "NAME" caches[]:` scope prefix.
pub(super) fn validate_cache_pool_names(cfg: &Config) -> Result<()> {
    for name in cfg.cache_pools.keys() {
        let scope = format!("cache_pool {name:?}");
        validators::validate_cache_pool_name(name)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
    }
    // Validate every runner.caches entry. The cross-reference
    // check in plan_from rejects unknown names ("unknown cache pool"),
    // but that error fires at plan time and is shape-agnostic — an
    // oversize entry that also happens to match a (hypothetical)
    // oversize pool key is the case `validate_cache_pool_name` is
    // designed to reject before plan_from is even reached.
    for runner in &cfg.runners {
        for cache in &runner.caches {
            let scope = format!("runner {:?} caches[]", runner.name);
            validators::validate_cache_pool_name(cache)
                .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
        }
    }
    Ok(())
}

/// Reject non-absolute operator-pinned `sccache_path` / `sleep_path`
/// values at config load. Relative paths resolve against process CWD
/// — which differs between operator-shell `ghars plan` and root
/// `ghars apply` — and would silently flip the rendered `ExecStart=`
/// between invocations. The plan-time resolver
/// (`resolve_cache_pool_paths`) carries a fallback gate too, but
/// surfacing the error at config load gives the operator a single
/// remediation point with a block-scoped `cache_pool "NAME":` prefix
/// before `ghars plan` runs filesystem probes for the unpinned-path
/// case.
///
/// # Errors
///
/// `GharsError::Validation` wrapping the absolute-path requirement
/// with the `cache_pool "NAME":` scope prefix.
pub(super) fn validate_cache_pool_binary_paths(cfg: &Config) -> Result<()> {
    for (name, pool) in &cfg.cache_pools {
        let scope = format!("cache_pool {name:?}");
        if let Some(p) = pool.sccache_path.as_ref()
            && !p.is_absolute()
        {
            return Err(crate::error::prepend_validation_scope(
                &scope,
                crate::error::GharsError::Validation(
                    format!("sccache_path must be absolute, got: {p}"),
                    "relative paths resolve against process CWD which varies between \
                     invocations (operator shell vs. root apply); use an absolute path \
                     (e.g. /usr/local/bin/sccache)"
                        .into(),
                ),
            ));
        }
        if let Some(p) = pool.sleep_path.as_ref()
            && !p.is_absolute()
        {
            return Err(crate::error::prepend_validation_scope(
                &scope,
                crate::error::GharsError::Validation(
                    format!("sleep_path must be absolute, got: {p}"),
                    "relative paths resolve against process CWD which varies between \
                     invocations (operator shell vs. root apply); use an absolute path \
                     (e.g. /usr/bin/sleep)"
                        .into(),
                ),
            ));
        }
    }
    Ok(())
}

// ---------- runner-name validation --------------------------------------

/// Apply identifier-shape validation to every `[[runner]] name`.
/// Validation runs through `validators::validate_runner_name` (a
/// wrapper over `validate_identifier`); the per-name surface bound is
/// [`crate::config::IDENTIFIER_MAX_LEN`]. Netns-mode runners face an
/// additional tighter cap [`validators::NETNS_RUNNER_NAME_MAX_LEN`]
/// enforced separately by [`validate_netns_runner_name_lengths`]
/// (the rendered veth name `ghars-{name}-h` must fit `IFNAMSIZ - 1`).
///
/// # Errors
///
/// `GharsError::Validation` wrapping `validators::validate_runner_name`
/// with the `runner "NAME":` scope prefix.
pub(super) fn validate_runner_names(cfg: &Config) -> Result<()> {
    for runner in &cfg.runners {
        validators::validate_runner_name(&runner.name)
            .map_err(|e| crate::error::prepend_runner_scope(&runner.name, e))?;
    }
    Ok(())
}

/// POSIX-portable shell environment variable name shape, with the
/// common bash/zsh extension that permits lowercase letters.
///
/// IEEE Std 1003.1-2017 strictly limits portable name characters to
/// ASCII uppercase letters, digits, and underscores, with the first
/// character not a digit. Mainstream shells (bash, zsh, dash, ksh)
/// accept lowercase letters in practice, and operator configs
/// frequently use mixed case. The regex below allows lowercase to
/// match operator expectation; the portability-strict subset
/// (uppercase only) is a runtime concern of whatever consumes
/// `std::env::var`, not a config-load shape gate. `validate_pat_xor`
/// rejects `token_env` values that don't match — values that pass
/// the trim/whitespace gate but cannot be looked up because no
/// portable shell exports the name, so apply surfaces a misleading
/// "env var unset" diagnostic (`std::env::var` returns `NotPresent`)
/// on inputs like embedded whitespace, dashes, or other punctuation.
pub(super) static POSIX_ENV_VAR_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$")
        .expect("POSIX env var name regex is a compile-time constant")
});

/// Hints reused by every `validate_pat_xor` rejection arm so the
/// canonical example value (`GHARS_PAT` / `/etc/ghars/pat`) appears
/// in operator output regardless of which gate fires first.
const TOKEN_ENV_HINT: &str = "set token_env to the name of an environment variable holding the PAT \
     (e.g. token_env = \"GHARS_PAT\"), or remove the field";
const TOKEN_FILE_HINT: &str = "set token_file to the absolute path of a 0600 root-owned file holding \
     the PAT (e.g. token_file = \"/etc/ghars/pat\"), or remove the field";

/// Returns true for characters disallowed inside non-empty
/// `token_env` / `token_file` values — characters that survive the
/// trim/whitespace gate but break apply-time lookups (`std::env::var`
/// returning `NotPresent` on a name with an embedded BOM, `open(2)`
/// failing on a path with an embedded NUL, etc.). Three classes:
///   - explicit codepoints: NUL (U+0000), SOFT HYPHEN
///     (U+00AD), Arabic Letter Mark (U+061C), Mongolian Vowel
///     Separator (U+180E), the ZWSP/ZWNJ/ZWJ/LRM/RLM block
///     (U+200B..=U+200F), the bidi embedding controls including
///     LRO/RLO/PDF (U+202A..=U+202E — the Trojan Source attack
///     vector, Boucher & Anderson 2021), the WJ + invisible math
///     operators block (U+2060..=U+2064), bidi isolates LRI/RLI/FSI/
///     PDI (U+2066..=U+2069), and BOM (U+FEFF). These render
///     invisibly in operator terminals and would survive a copy-paste
///     from a docs site that injected them as formatting. NUL
///     belongs to general-category Cc (and is also caught by the
///     `is_control()` arm below); listing it explicitly keeps the
///     diagnostic tight on the well-known invisible chars even if a
///     future regression narrows the control-char arm.
///   - ALL control chars (`char::is_control()`). The `\t` `\n` `\r`
///     trio is rejected too — there is no carve-out. They could be
///     whitelisted on the speculative grounds that paths or env-var
///     names might contain them. Unix permits these chars in paths,
///     but PAT-token deployment paths never legitimately contain
///     them: PAT tokens are small static credentials and their
///     declared paths/env-var names are operator-authored config
///     identifiers, not arbitrary Unix file names. Rejecting all Cc
///     chars in both fields closes the gap that an embedded `\n` in
///     `token_file` would survive every other shape gate.
///   - ALL Mn-class combining marks: Mn-class combining marks
///     (Unicode `NonspacingMark`) are rejected uniformly — they can
///     produce visually deceptive paths via combining diacritical
///     marks that overlay ASCII characters. Token paths are
///     operator-authored config identifiers, not arbitrary file
///     paths; operators with internationalized paths should use
///     precomposed (NFC) forms. The Mn-class arm subsumes Combining
///     Grapheme Joiner (U+034F) and variation selectors VS1..=VS16
///     (U+FE00..=U+FE0F), which are all Mn — no per-codepoint entry
///     for them is needed.
///
/// `char::is_control()` covers the Unicode general-category Cc class
/// (ASCII 0x00-0x1F + 0x7F + various U+0080-U+009F C1 controls); the
/// explicit list adds Cf-class default-ignorables (SHY, ALM, MVS, the
/// ZWSP/ZWNJ/ZWJ/LRM/RLM/bidi-control blocks, WJ + invisible math
/// operators, bidi isolates, BOM); the Mn-class arm covers all
/// combining marks (`NonspacingMark`) — none of which are in Cc.
pub(super) fn is_disallowed_hidden_char(c: char) -> bool {
    matches!(
        c,
        '\u{0000}'
            | '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    ) || c.is_control()
        || get_general_category(c) == GeneralCategory::NonspacingMark
}

/// Walk every `[auth.NAME]` entry and, for `AuthSpec::Pat`,
/// reject configurations that violate the documented XOR invariant
/// (the `AuthSpec::Pat` doc-comment in `config.rs` and the
/// `PatToken::new` constructor in `auth.rs`): exactly one of
/// `token_env` / `token_file` MUST be set. `PatToken::new` re-validates this at
/// apply time.
///
/// Wiring landscape — which CLI commands rely on this gate vs the
/// registry-construction backstop:
///   - `cmd_validate` and `cmd_apply` unconditionally call
///     `build_auth_registry`, which constructs every `PatToken`
///     eagerly — these surface the XOR error via the registry path
///     even without this gate (note: `--deep` only gates the
///     registration-token MINT step, not auth construction).
///   - `cmd_plan`, `cmd_status`, and `cmd_add` do NOT call
///     `build_auth_registry`; without this gate they would accept
///     misconfigured `[auth.NAME]` entries and the failure would
///     first surface at apply time, by which point state may have
///     changed (`ghars plan` printing an Ok plan that immediately
///     fails `ghars apply`).
///
/// Wiring at `load_config` means every entry point sees the same
/// gate uniformly — the gate is load-bearing for `cmd_plan` /
/// `cmd_status` / `cmd_add`, redundant-but-harmless for `cmd_validate` /
/// `cmd_apply` (the registry construction catches it anyway).
///
/// This is a SHAPE-ONLY check. It does NOT lstat `token_file` —
/// `PatToken::new` runs the SEC-25 mode-0600 + owner-root + not-
/// symlink check at apply time, where the file is actually read.
/// Splitting the responsibilities: config-load rejects mis-shaped
/// `AuthSpec` entries; apply rejects badly-permissioned token files.
///
/// What "mis-shaped" means here:
///   - Both `token_env` AND `token_file` set: violates the XOR
///     invariant.
///   - Neither set: violates the "exactly one" invariant.
///   - `token_env` empty / whitespace-only / hidden-char-bearing /
///     leading-or-trailing-whitespace / not a POSIX env var name:
///     shape-valid TOML but useless — `std::env::var` would either
///     return `NotPresent` or look up the wrong name and surface
///     deep in apply as a confusing "env var unset" error after
///     partial state has changed.
///   - `token_file` empty / whitespace-only / hidden-char-bearing /
///     leading-or-trailing-whitespace: shape-valid TOML but useless
///     — `Utf8PathBuf::from("")` is empty, a whitespace-only path
///     fails at `open(2)` with a confusing "no such file" message,
///     and a path with edge whitespace looks correct in error output
///     but fails the open at a literal-space basename. The empty
///     check fires first so `" "` rejects with the empty-or-
///     whitespace diagnostic (more informative than "leading
///     whitespace"); the hidden-char check fires next so an embedded
///     BOM or NUL surfaces a codepoint+offset diagnostic; the
///     trim-mismatch check fires last so a real path with extra
///     edge spaces surfaces with a path-shape diagnostic.
///
/// Gate ordering for each field (independent — each field walks the
/// sequence on its own value, with no cross-field interaction):
///   1. `trim().is_empty()` — empty / all-whitespace.
///   2. hidden-char scan — surface byte offset + codepoint.
///      Fires BEFORE the edge-whitespace and shape checks so an
///      embedded BOM in a value that would also fail trim-mismatch
///      or charset surfaces as a hidden-char diagnostic (more
///      actionable than the downstream check).
///   3. trim-mismatch on BOTH fields — value is non-empty and
///      contains no hidden chars but its edges carry whitespace.
///      Fires for both fields when the value is non-empty and
///      contains no hidden chars but its edges carry whitespace.
///      Both produce "leading or trailing whitespace". Fires BEFORE
///      the POSIX charset gate so `"X "` / `" X"` surface as
///      whitespace-mismatch rather than the less-specific "POSIX env
///      var name" diagnostic.
///   4. POSIX charset — `token_env` only. Catches dashes, dots,
///      embedded whitespace, and other punctuation that pass the
///      trim/hidden/edge gates but break env var name shape.
///      `token_file` has no analogous step-4 gate; filesystem paths
///      accept arbitrary printable bytes so the trim-mismatch step
///      is the last domain check.
/// The XOR tuple-match at the end fires only when BOTH fields'
/// per-field gates pass — it catches (true,true) when both fields
/// are present and shape-valid, and (false,false) when neither is
/// set. A misconfigured per-field value short-circuits before the
/// tuple-match is reached.
///
/// Other `AuthSpec` variants (`GithubApp`, `Interactive`, `TokenFile`)
/// have no XOR shape to validate; they are accepted without validation.
///
/// # Errors
///
/// `GharsError::Validation` wrapping a hint specific to the offending
/// field — empty/whitespace, mutual-exclusivity, or missing-field —
/// scoped to `[auth.NAME]`.
pub(super) fn validate_pat_xor(cfg: &Config) -> Result<()> {
    for (name, spec) in &cfg.auth {
        if let AuthSpec::Pat {
            token_env,
            token_file,
        } = spec
        {
            let scope = format!("auth {name:?}");
            // Three diagnostic forms: empty/whitespace, Mn combining-mark with NFC hint, Cf/Cc hidden-char.
            let check_empty_or_hidden = |val: &str, field: &str, hint: &str| -> Result<()> {
                if val.trim().is_empty() {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            format!("{field} is empty or whitespace-only"),
                            hint.into(),
                        ),
                    ));
                }
                // Hidden default-ignorable / control characters
                // pass the trim/whitespace check but surface as
                // confusing apply-time errors (env::var lookup
                // mismatch, open(2) ENOENT on a path with embedded
                // BOM, etc.). Surface byte offset + codepoint so the
                // operator can locate the invisible char in their
                // editor. Mn-class combining marks (Unicode
                // NonspacingMark — U+0300 family + variation
                // selectors + CGJ) get a dedicated diagnostic
                // suggesting precomposed (NFC) forms instead of the
                // generic "hidden character" framing — the
                // remediation differs from removing a stray BOM /
                // ZWSP.
                if let Some((idx, ch)) = val
                    .char_indices()
                    .find(|(_, c)| is_disallowed_hidden_char(*c))
                {
                    let msg = if get_general_category(ch) == GeneralCategory::NonspacingMark {
                        // CGJ + variation selectors (incl. supplement) are Mn but have no NFC form; route to "remove" advice.
                        if matches!(
                            ch,
                            '\u{034F}' | '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}'
                        ) {
                            format!(
                                "{field} contains a disallowed combining mark \
                                 U+{codepoint:04X} at byte offset {idx}; remove the \
                                 codepoint (no precomposed equivalent exists)",
                                codepoint = ch as u32,
                            )
                        } else {
                            format!(
                                "{field} contains a disallowed combining mark \
                                 U+{codepoint:04X} at byte offset {idx}; remove the \
                                 codepoint, or use the precomposed (NFC) form if \
                                 the character was intentional",
                                codepoint = ch as u32,
                            )
                        }
                    } else {
                        format!(
                            "{field} contains a disallowed hidden character \
                             U+{codepoint:04X} at byte offset {idx}",
                            codepoint = ch as u32,
                        )
                    };
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(msg, hint.into()),
                    ));
                }
                Ok(())
            };

            if let Some(env) = token_env.as_deref() {
                check_empty_or_hidden(env, "token_env", TOKEN_ENV_HINT)?;
                // Leading / trailing whitespace on real content
                // (e.g. `"X "`, `" X"`, `" X "`) rejects with a
                // dedicated diagnostic before the POSIX charset gate.
                // Without this dedicated branch, those inputs would
                // fall through to the POSIX gate which surfaces "is
                // not a valid POSIX environment variable name" —
                // technically correct but misleading: the operator's
                // intent is almost certainly a shell-quoting hiccup,
                // not a charset violation. The dedicated diagnostic
                // names the condition. This fires only for non-empty
                // values
                // (trim-empty already short-circuited inside
                // check_empty_or_hidden) whose edges carry extra
                // whitespace.
                if env != env.trim() {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            format!("token_env {env:?} has leading or trailing whitespace"),
                            TOKEN_ENV_HINT.into(),
                        ),
                    ));
                }
                // POSIX env var name charset. Values that pass
                // the trim/hidden-char/edge-whitespace gates but
                // contain dashes, dots, embedded whitespace, or
                // other punctuation would either fail `std::env::var`
                // outright or look up an unrelated name.
                if !POSIX_ENV_VAR_NAME_RE.is_match(env) {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            format!(
                                "token_env {env:?} is not a valid POSIX environment variable name \
                                 (must start with a letter or underscore and contain only ASCII \
                                 letters, digits, and underscores)"
                            ),
                            TOKEN_ENV_HINT.into(),
                        ),
                    ));
                }
            }

            if let Some(path) = token_file.as_ref() {
                let path_str = path.as_str();
                check_empty_or_hidden(path_str, "token_file", TOKEN_FILE_HINT)?;
                // Leading / trailing whitespace on a real path
                // (e.g. `" /etc/ghars/pat"`, `"/etc/ghars/pat "`,
                // `" /etc/ghars/pat "`) would surface as `open(2)`
                // ENOENT on a literal-space basename. Reject here
                // with an actionable diagnostic that names the
                // condition. trim()-empty already short-circuited;
                // this fires only for non-empty values whose edges
                // carry extra whitespace.
                if path_str != path_str.trim() {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            format!("token_file {path_str:?} has leading or trailing whitespace"),
                            "remove leading and trailing whitespace from the path to a 0600 \
                             root-owned file holding the PAT (e.g. token_file = \
                             \"/etc/ghars/pat\")"
                                .into(),
                        ),
                    ));
                }
            }

            // Error messages omit the "kind = \"pat\":" prefix —
            // `prepend_validation_scope` already adds the
            // `auth "NAME"` scope which identifies the offending block,
            // and `AuthSpec::Pat` is the only variant the loop checks.
            // Every hint arm names a concrete example value
            // (GHARS_PAT / /etc/ghars/pat) so an operator reading the
            // (true,true) or (false,false) error gets the same
            // remediation breadcrumb the empty-string / charset arms
            // already provide.
            match (token_env.is_some(), token_file.is_some()) {
                (true, true) => {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            "token_env and token_file are mutually exclusive".into(),
                            "remove one — set token_env (read PAT from env, e.g. \
                             token_env = \"GHARS_PAT\") OR token_file (read PAT from a \
                             0600 root-owned file, e.g. token_file = \"/etc/ghars/pat\"), \
                             never both"
                                .into(),
                        ),
                    ));
                }
                (false, false) => {
                    return Err(crate::error::prepend_validation_scope(
                        &scope,
                        GharsError::Validation(
                            "exactly one of token_env / token_file is required".into(),
                            "set token_env (read PAT from env, e.g. token_env = \"GHARS_PAT\") \
                             OR token_file (read PAT from a 0600 root-owned file, e.g. \
                             token_file = \"/etc/ghars/pat\")"
                                .into(),
                        ),
                    ));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Walk every `[auth.NAME]` key and gate it through
/// `validators::validate_identifier` — the `IDENTIFIER_REGEX`
/// (defined in `config.rs`) is shared by runner names, auth keys,
/// cache pool keys, and network keys. Auth keys are user-chosen identifiers that flow
/// into:
///   - the auth-name → `TokenSource` map (`build_auth_registry`);
///   - error scopes via `prepend_validation_scope("auth {name:?}", ...)`,
///     where bizarre keys could surface as confusing
///     `auth "FOO BAR\n!!!": ...` diagnostics;
///   - operator-visible configuration in TOML editors, where a key
///     containing whitespace or punctuation would be hard to
///     reference from `[[runner]] auth = "NAME"`.
///
/// Without this gate, `[auth.NAME]` keys could be any TOML bare-key-
/// or-quoted-string shape — far broader than `IDENTIFIER_REGEX`. Wiring
/// at `load_config` means `cmd_validate` / `cmd_plan` / `cmd_apply` /
/// `cmd_status` / `cmd_add` all see the same gate, matching the existing
/// pattern for runner / cache pool / network names.
///
/// # Errors
///
/// `GharsError::Validation` wrapping the underlying `validate_identifier`
/// error with the `auth "NAME"` scope prefix.
pub(super) fn validate_auth_keys(cfg: &Config) -> Result<()> {
    for name in cfg.auth.keys() {
        let scope = format!("auth {name:?}");
        validators::validate_identifier(name)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
    }
    Ok(())
}

/// Walk every `[[runner]] runner_tarball = "..."` and gate the
/// path through `validators::validate_runner_tarball`. The validator
/// opens the path with `O_NOFOLLOW` (the kernel ELOOPs symlinks at
/// open(2) time, closing the lstat-then-open TOCTOU window) and
/// rejects non-regular files via fstat on the open fd — the same
/// shape `extract::install_runner_binary` requires before
/// extraction. Wiring it into `load_config` means `cmd_validate` /
/// `cmd_plan` / `cmd_apply` / `cmd_status` / `cmd_add` all see the same gate;
/// without this wiring the validator would be orphaned (defined
/// but with no callsite).
///
/// `defaults.runner_tarball` does NOT exist in the schema — see
/// `config::Defaults` for the actual default-level fields. Per-runner
/// is the only surface walked here.
///
/// `runner_tarball` on `RunnerSpec` is `Option<Utf8PathBuf>`. We forward
/// the infallible `as_str()` view to the validator — `Utf8PathBuf` is
/// UTF-8 by construction (the wrapper rejects non-UTF-8 input at
/// construction time), so the conversion never loses data.
///
/// # Errors
///
/// `GharsError::Validation` wrapping the underlying validator error
/// with the `runner "NAME"` scope prefix.
pub(super) fn validate_runner_tarballs(cfg: &Config) -> Result<()> {
    for runner in &cfg.runners {
        if let Some(p) = runner.runner_tarball.as_ref() {
            validators::validate_runner_tarball(p.as_str())
                .map_err(|e| crate::error::prepend_runner_scope(&runner.name, e))?;
        }
    }
    Ok(())
}

// ---------- netns runner-name length cap --------------------------------

/// Reject runner names whose rendered veth interface name
/// `"ghars-{name}-h"` would exceed the kernel's `IFNAMSIZ - 1 = 15`
/// limit (`net/core/dev.c:dev_valid_name`). The hard cap on the
/// operator-controlled `{name}` segment is
/// [`validators::NETNS_RUNNER_NAME_MAX_LEN`] (= 7) — see
/// `validators.rs` for the kernel source citation and the
/// const-derivation chain.
///
/// Only runners whose effective network mode resolves to `Netns`
/// face this cap. Open-mode runners do not allocate a veth pair, so
/// they inherit only the identifier-shape cap
/// [`crate::config::IDENTIFIER_MAX_LEN`]. Effective network mode is
/// computed via the documented inheritance chain (Part 3 /
/// `plan::merge_defaults`):
///   1. `runner.network` (Some) → use that network key.
///   2. else `defaults.network` (Some) → use that network key.
///   3. else implicit Open mode (no [network.NAME] reference) — skip
///      the cap.
/// When the resolved key exists in `cfg.networks`, we check
/// `mode == Netns`. An unresolved key does NOT short-circuit the
/// gate here — `validate_networks` is responsible
/// for surfacing the unknown-network error; the lookup miss in this
/// validator falls through to "no netns gating" so a single
/// rejection (the unknown key) surfaces without piggybacking an
/// unrelated length-cap error.
///
/// For count blocks (`[[runner]] count = N`) the rendered veth
/// instance is `{name}-{i}` for `i in 1..=N`. The worst-case
/// instance length is `name.len() + 1 + count.to_string().len()`
/// (the `+1` is the literal '-' between prefix and index). We cap
/// the worst case rather than every expansion individually so the
/// gate is O(runners) not O(runners + total expanded count).
///
/// # Errors
///
/// `GharsError::Validation` wrapping a message naming both the
/// `IFNAMSIZ` source and the actual oversize length, with the
/// `runner "NAME":` scope prefix.
pub(super) fn validate_netns_runner_name_lengths(cfg: &Config) -> Result<()> {
    use crate::config::NetworkMode;
    for runner in &cfg.runners {
        // Resolve effective network reference: per-runner override
        // wins over [defaults] (Part 3 merge table). None at both
        // layers ≡ implicit Open mode → no veth, no cap.
        let net_key = runner
            .network
            .as_deref()
            .or(cfg.defaults.network.as_deref());
        let Some(key) = net_key else { continue };
        // Look up the [network.NAME] block. A missing key here means
        // validate_networks will reject upstream — we
        // skip this runner so we don't double-report the unknown-
        // network error with an irrelevant length cap. (validate_
        // networks runs first so in practice load_config's
        // short-circuit hits that error before we get here.)
        let Some(spec) = cfg.networks.get(key) else {
            continue;
        };
        if !matches!(spec.mode, NetworkMode::Netns) {
            continue;
        }
        // count = Some(0) is a no-op in `plan::expand_counts` — the
        // planner emits ZERO instances for that block, so no veth is
        // ever allocated. Skip the gate entirely; otherwise we'd
        // false-reject configs that the planner would expand to
        // nothing.
        if matches!(runner.count, Some(0)) {
            continue;
        }
        // Worst-case expanded instance length. The semantics here
        // mirror `plan::is_count_block` exactly: `count >= 2` is the
        // ONLY shape that produces multi-instance `{name}-{i}`
        // expansion. `count = None` and `count = Some(1)` both keep
        // the bare name (no suffix). Treating those two cases as
        // "no suffix" prevents false rejections of bare-name
        // configs that the planner would happily accept.
        let suffix_digits = match runner.count {
            Some(n) if n > 1 => n.to_string().len(),
            _ => 0,
        };
        let worst_case_len = if suffix_digits == 0 {
            runner.name.len()
        } else {
            // +1 for the '-' separator between prefix and index.
            runner.name.len() + 1 + suffix_digits
        };
        if worst_case_len > validators::NETNS_RUNNER_NAME_MAX_LEN {
            let msg = if suffix_digits == 0 {
                format!(
                    "netns mode requires runner name <= {max} chars (kernel \
                     IFNAMSIZ {ifn} caps veth name 'ghars-{{name}}-h'); got {got} chars",
                    max = validators::NETNS_RUNNER_NAME_MAX_LEN,
                    ifn = validators::IFNAMSIZ,
                    got = runner.name.len(),
                )
            } else {
                format!(
                    "netns mode requires runner instance name <= {max} chars (kernel \
                     IFNAMSIZ {ifn} caps veth name 'ghars-{{name}}-h'); count block \
                     '{prefix}-N' worst-case expands to {got} chars (prefix {plen} + \
                     1 + count digits {dlen})",
                    max = validators::NETNS_RUNNER_NAME_MAX_LEN,
                    ifn = validators::IFNAMSIZ,
                    prefix = runner.name,
                    got = worst_case_len,
                    plen = runner.name.len(),
                    dlen = suffix_digits,
                )
            };
            let hint = format!(
                "shorten the runner name to ≤{} chars or switch to network mode 'open'",
                validators::NETNS_RUNNER_NAME_MAX_LEN
            );
            return Err(crate::error::prepend_runner_scope(
                &runner.name,
                GharsError::Validation(msg, hint),
            ));
        }
    }
    Ok(())
}

// ---------- identity-field validators -----------------------------------

/// Reject control characters in TOML fields that flow into
/// `render_identity` X-Ghars-* annotations. Today the only operator-
/// controllable surface that lands in `render_identity` without
/// per-character validation upstream is `trust_zone` (`RunnerSpec` +
/// `CachePoolSpec`). `render_identity` itself runs `check_identity_field`
/// at render time as defense-in-depth, but rejecting at config
/// load lets the operator see the error WITH the offending block name
/// (`runner "NAME"` / `cache_pool "NAME"`) instead of an opaque
/// "field \"`trust_zone`\" contains forbidden newline" surfacing during
/// `plan` or `apply`.
///
/// `config_source` is NOT validated here — it is composed at plan time
/// from `paths.config_dir` (`plan_from`'s `config_source` synthesis) and
/// is not a TOML field.
/// That validation lives at the plan-time composition site so it
/// covers any future caller that synthesizes a `config_source` value
/// without going through this load-time gate.
///
/// # Errors
///
/// `GharsError::Validation` wrapping the underlying `check_identity_field`
/// error with the scope prefix (`runner "NAME":` / `cache_pool "NAME":`).
pub(super) fn validate_identity_fields(cfg: &Config) -> Result<()> {
    for runner in &cfg.runners {
        crate::systemd::check_identity_field("trust_zone", &runner.trust_zone)
            .map_err(|e| crate::error::prepend_runner_scope(&runner.name, e))?;
    }
    for (name, pool) in &cfg.cache_pools {
        let scope = format!("cache_pool {name:?}");
        crate::systemd::check_identity_field("trust_zone", &pool.trust_zone)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
    }
    Ok(())
}

// ---------- trust_zone shape + length cap -------------------------------

/// Walk every runner and `cache_pool` `trust_zone` and gate the value
/// through `validators::validate_trust_zone`. Same loop-and-scope
/// pattern as `validate_runner_names` / `validate_cache_pool_names`
/// — the per-value validator owns the gates and error wording; this
/// function owns iteration and scope-prefixing.
///
/// `validate_trust_zone` enforces two layers: (1) the shared
/// `IDENTIFIER_REGEX` shape (lowercase letters, digits, dashes;
/// kebab-case only), then (2) the 22-char `TRUST_ZONE_MAX_LEN` cap so
/// the rendered `DynamicUser` identity `User=ghars-tz-<TRUST_ZONE>`
/// fits systemd's strict 31-char `valid_user_group_name` ceiling.
///
/// # Errors
///
/// `GharsError::Validation` wrapping the underlying validator error
/// with the `runner "NAME":` / `cache_pool "NAME":` scope prefix.
pub(super) fn validate_trust_zone_lengths(cfg: &Config) -> Result<()> {
    for runner in &cfg.runners {
        validators::validate_trust_zone(&runner.trust_zone)
            .map_err(|e| crate::error::prepend_runner_scope(&runner.name, e))?;
    }
    for (name, pool) in &cfg.cache_pools {
        let scope = format!("cache_pool {name:?}");
        validators::validate_trust_zone(&pool.trust_zone)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
    }
    Ok(())
}

// ---------- proxy shape validators --------------------------------------

/// Reject `[proxy] ca_certs` entries with empty/whitespace-only
/// `env`, empty/whitespace-only `path`, or non-absolute `path` at
/// config load. A `CaCertBinding` with these shapes reaches
/// `render_proxy`, passes `check_identity_field` (empty/whitespace
/// strings contain no control chars), and emits a malformed
/// systemd directive that fails at unit-start time:
/// - empty/whitespace `env` → `Environment==<path>` (no var name,
///   fails systemd's `[a-zA-Z_][a-zA-Z0-9_]*` Environment= grammar)
/// - empty/whitespace `path` → `Environment=NAME=` (empty value,
///   silently defeats the CA-bundle purpose)
/// - relative `path` → `BindReadOnlyPaths=<rel>` which systemd
///   rejects (`BindReadOnlyPaths` requires absolute paths, parallel
///   to [`validate_cache_pool_binary_paths`])
///
/// Catching at load surfaces the typo with the operator's
/// `[[proxy.ca_certs]]` block scope before unit-start blows up at
/// apply.
///
/// Both `[defaults] proxy` and per-runner `[[runner]].proxy` are
/// walked. Per-runner `proxy` entirely overrides `defaults.proxy`
/// for that runner via `runner.proxy.or_else(|| defaults.proxy)`
/// at `lower_to_effective`, but a malformed `defaults.proxy` would
/// still leak into any runner that DOESN'T override — so validating
/// defaults independently catches the "operator fixed one runner's
/// override but left defaults broken for other inheriting runners"
/// case.
///
/// # Errors
///
/// `GharsError::Validation` with `defaults.proxy.ca_certs[N]:` or
/// `runner "NAME" proxy.ca_certs[N]:` scope naming the offending
/// entry index and which field failed.
pub(super) fn validate_proxy_ca_certs_nonempty(cfg: &Config) -> Result<()> {
    fn check_one_proxy(proxy: &crate::config::ProxySpec, scope_prefix: &str) -> Result<()> {
        for (idx, binding) in proxy.ca_certs.iter().enumerate() {
            if binding.env.trim().is_empty() {
                return Err(GharsError::Validation(
                    format!("{scope_prefix} ca_certs[{idx}]: empty or whitespace-only `env` field"),
                    "set ca_certs[N].env to the env var name systemd should export \
                     for this CA bundle (e.g. NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE) \
                     — an empty/whitespace `env` emits a malformed `Environment==<path>` \
                     directive that systemd rejects at unit-start (Environment= var \
                     names must match `[a-zA-Z_][a-zA-Z0-9_]*`)"
                        .into(),
                ));
            }
            if binding.path.as_str().trim().is_empty() {
                return Err(GharsError::Validation(
                    format!(
                        "{scope_prefix} ca_certs[{idx}]: empty or whitespace-only `path` field (env = {:?})",
                        binding.env
                    ),
                    "set ca_certs[N].path to the absolute path of the CA bundle \
                     file — an empty/whitespace `path` emits a malformed \
                     `Environment=NAME=` directive (empty value) that defeats the \
                     CA-bundle purpose"
                        .into(),
                ));
            }
            if !binding.path.is_absolute() {
                return Err(GharsError::Validation(
                    format!(
                        "{scope_prefix} ca_certs[{idx}]: non-absolute `path` {:?} (env = {:?})",
                        binding.path.as_str(),
                        binding.env
                    ),
                    "set ca_certs[N].path to an absolute path. Relative paths resolve \
                     against systemd's working directory at unit-start (root /) and \
                     would emit a `BindReadOnlyPaths=<rel>` that systemd rejects \
                     (BindReadOnlyPaths requires absolute paths). Sibling of \
                     `validate_cache_pool_binary_paths` enforcing the same gate for \
                     sccache_path / sleep_path"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    if let Some(proxy) = cfg.proxy.as_ref() {
        check_one_proxy(proxy, "defaults.proxy")?;
    }
    for runner in &cfg.runners {
        if let Some(proxy) = runner.proxy.as_ref() {
            let scope = format!("runner {:?} proxy", runner.name);
            check_one_proxy(proxy, &scope)?;
        }
    }
    Ok(())
}

/// Reject empty/whitespace-only entries in `[proxy] no_proxy` at
/// config load. An empty or whitespace-only entry comma-joins into
/// the rendered `Environment=NO_PROXY=` directive as a leading /
/// trailing / adjacent empty token (e.g.
/// `Environment=NO_PROXY=host,,host2` or
/// `Environment=NO_PROXY=host,   ,host2`), which is malformed per
/// HTTP-proxy convention and silently disabled by curl / Node /
/// Python clients that strict-parse the list. Operator probably
/// meant `no_proxy = []` (empty list ⇒ proxy applies to all hosts)
/// or `no_proxy = ["host"]` (real entry). Both [defaults] and
/// per-runner proxy layers are walked for the same reason as
/// [`validate_proxy_ca_certs_nonempty`] — defaults remain a
/// fallback for runners that don't override.
///
/// # Errors
///
/// `GharsError::Validation` with `defaults.proxy.no_proxy[N]:` or
/// `runner "NAME" proxy.no_proxy[N]:` scope naming the offending
/// entry index.
pub(super) fn validate_proxy_no_proxy_nonempty_entries(cfg: &Config) -> Result<()> {
    fn check_one_proxy(proxy: &crate::config::ProxySpec, scope_prefix: &str) -> Result<()> {
        for (idx, entry) in proxy.no_proxy.iter().enumerate() {
            if entry.trim().is_empty() {
                return Err(GharsError::Validation(
                    format!("{scope_prefix} no_proxy[{idx}]: empty or whitespace-only entry"),
                    "remove the empty/whitespace entry — it produces a malformed \
                     comma-separated NO_PROXY env var (leading/trailing/adjacent \
                     empty token) that strict-parsing HTTP clients reject. If you \
                     intended `proxy applies to all hosts`, set `no_proxy = []`"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    if let Some(proxy) = cfg.proxy.as_ref() {
        check_one_proxy(proxy, "defaults.proxy")?;
    }
    for runner in &cfg.runners {
        if let Some(proxy) = runner.proxy.as_ref() {
            let scope = format!("runner {:?} proxy", runner.name);
            check_one_proxy(proxy, &scope)?;
        }
    }
    Ok(())
}
