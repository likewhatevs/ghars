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
/// `std::fs::read_to_string`. The library `config::load` is still a
/// stub; the CLI does the IO.
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
    validate_single_sccache_pool_per_runner(&cfg)?;
    validate_cache_pool_names(&cfg)?;
    validate_cache_pool_binary_paths(&cfg)?;
    validate_runner_names(&cfg)?;
    validate_auth_keys(&cfg)?;
    validate_pat_xor(&cfg)?;
    validate_runner_tarballs(&cfg)?;
    validate_netns_runner_name_lengths(&cfg)?;
    crate::config::validate_environments(&cfg)?;
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
        let scope = format!("runner {:?}", runner.name);
        validate_hardening_block(&runner.hardening)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
        if let Some(hooks) = runner.hooks.as_ref() {
            validate_hooks_block(hooks)
                .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
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

// ---------- single-sccache-pool-per-runner validator --------------------

/// Reject configs where a runner references 2+ cache pools that each
/// host an sccache server. The runner unit emits one
/// `Environment=SCCACHE_SERVER_UDS=` per sccache pool referenced;
/// systemd's last-writer-wins semantics for `Environment=` would route
/// every sccache call to the LAST pool's UDS, silently dropping cache
/// hits from earlier pools and entangling builds across what the
/// operator declared as separate pools. Catching at config load
/// surfaces a scoped error (`runner "NAME": ...`) before any units are
/// rendered or applied.
///
/// ccache pools are not affected — they use filesystem-mode bindings
/// keyed on `CCACHE_DIR=%h/.cache/ccache/{pool}` (no per-pool UDS), and
/// distinct `CCACHE_DIR` values do compose. Only the sccache UDS is
/// single-valued.
///
/// # Errors
///
/// `GharsError::Validation` naming the runner and the conflicting
/// sccache pools. The hint tells the operator to merge or drop one.
pub(super) fn validate_single_sccache_pool_per_runner(cfg: &Config) -> Result<()> {
    use crate::config::CacheKind;
    for runner in &cfg.runners {
        let mut sccache_refs: Vec<&str> = Vec::new();
        for cache_ref in &runner.caches {
            if let Some(spec) = cfg.cache_pools.get(cache_ref)
                && spec.kinds.contains(&CacheKind::Sccache)
            {
                sccache_refs.push(cache_ref.as_str());
            }
        }
        if sccache_refs.len() > 1 {
            return Err(GharsError::Validation(
                format!(
                    "runner {:?}: references {} sccache pools ({}); only one sccache pool \
                     binding is permitted per runner",
                    runner.name,
                    sccache_refs.len(),
                    sccache_refs.join(", ")
                ),
                "remove all but one sccache pool from [[runner]].caches; \
                 SCCACHE_SERVER_UDS is single-valued and additional pools \
                 would be silently shadowed by systemd's last-writer-wins \
                 Environment= semantics"
                    .into(),
            ));
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
        let scope = format!("runner {:?}", runner.name);
        validators::validate_runner_name(&runner.name)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
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
            let scope = format!("runner {:?}", runner.name);
            validators::validate_runner_tarball(p.as_str())
                .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
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
            let scope = format!("runner {:?}", runner.name);
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
            return Err(crate::error::prepend_validation_scope(
                &scope,
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
        let scope = format!("runner {:?}", runner.name);
        crate::systemd::check_identity_field("trust_zone", &runner.trust_zone)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
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
        let scope = format!("runner {:?}", runner.name);
        validators::validate_trust_zone(&runner.trust_zone)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
    }
    for (name, pool) in &cfg.cache_pools {
        let scope = format!("cache_pool {name:?}");
        validators::validate_trust_zone(&pool.trust_zone)
            .map_err(|e| crate::error::prepend_validation_scope(&scope, e))?;
    }
    Ok(())
}
