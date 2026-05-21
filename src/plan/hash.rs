//! Canonical-JSON sha256 hashing for [`EffectiveRunnerSpec`] (Part 3
//! "spec-hash") and the parallel hash for cache-pool bindings consumed
//! by the cache-pool create/update plan path.

#![allow(clippy::expect_used)]

use crate::config::{EffectiveCacheBinding, EffectiveRunnerSpec};

/// Compute the canonical-JSON sha256 of an [`EffectiveRunnerSpec`]
/// (Part 3 spec-hash / Part 17).
///
/// Canonicalization:
/// - Round-trip through `serde_json::Value` whose `Object` map is
///   `BTreeMap`-backed (no `preserve_order` feature) — keys land in
///   sorted order at every depth.
/// - Arrays preserve source order in canonical JSON (`Vec` is
///   ordered by intent). Three set-semantic exceptions get
///   pre-sorted at the lowering boundary so `serde_json` sees
///   canonical input regardless of operator TOML ordering:
///     - `caches` (the outer per-runner Vec) — `lower_to_effective`
///       sorts by name during cache-pool resolution.
///     - `labels` — `merge_defaults` sorts by name after the
///       concat-and-dedup pass.
///     - `pool.kinds` (the inner per-`EffectiveCacheBinding` Vec) —
///       `canonicalize_kinds()` sorts by label at BOTH
///       `EffectiveCacheBinding` construction sites (the per-pool
///       `into_cache_pool_plan` consumed by `cache_pool_hash`, and
///       the per-runner inner loop of `lower_to_effective`
///       consumed by `spec_hash`).
///   So the spec arriving here is canonical regardless of the
///   operator's TOML ordering. `spec_hash` itself does NOT re-sort
///   — callers that bypass the lowering pipeline (e.g. hand-built
///   test fixtures) must sort their own `caches` / `labels` Vecs
///   and the inner `kinds` Vec on each binding before hashing if
///   they want the reorder-invariance contract. First apply
///   post-upgrade will rewrite `00-ghars.conf` and
///   `30-cache-pool.conf` with canonical sorted output for any
///   runner whose TOML order differed.
///
///   Set-semantic rationale for `labels`: GitHub Actions matches
///   workflow `runs-on:` against the registered label set
///   identically regardless of order — `runs-on: [linux, gpu]`
///   selects a runner whose registered labels are `[gpu, linux]` the
///   same as `[linux, gpu]`. The `--labels CSV` argv passed to
///   `config.sh` (assembled at `apply.rs::build_register_cmd`) is
///   handed to GitHub at registration time; the runner's behavior
///   is order-independent for matching workflow `runs-on:`
///   selectors. Local order-sensitivity in the `spec_hash` would cause
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
/// - The `renderer_schema` field is INCLUDED — populated by
///   `merge_defaults` from [`crate::systemd::RENDERER_SCHEMA`] so a
///   ghars binary upgrade that bumps the constant flips every managed
///   runner's hash, triggering the in-place rewrite + restart cascade
///   described at the `RENDERER_SCHEMA` constant. See
///   `docs/src/operations.md` "Why did my fleet restart on a ghars
///   binary upgrade?" for operator-facing semantics + in-flight
///   workload impact.
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

pub(super) fn cache_pool_hash(binding: &EffectiveCacheBinding) -> String {
    use sha2::{Digest, Sha256};
    let value = serde_json::to_value(binding)
        .expect("EffectiveCacheBinding must be serde_json-serializable");
    let json =
        serde_json::to_string(&value).expect("serde_json::Value always serializes to a string");
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::{CacheKind, CacheMode};

    /// Cache-pool hash invariance under host-resolved path changes.
    /// `EffectiveCacheBinding.sccache_path` and `.sleep_path` carry
    /// host-resolved paths (which `/usr/{local/,}bin/sccache` is
    /// present on this box), not operator config. Including them in
    /// `cache_pool_hash` would flip `X-Ghars-Spec-Hash` between hosts
    /// whose sccache lives at different prefixes, driving spurious
    /// recreate-class plans. The `#[serde(skip)]` on those fields
    /// (config.rs `EffectiveCacheBinding`) keeps them out of the
    /// canonical-JSON input to `cache_pool_hash`. Pin that here so a
    /// future regression dropping the `serde(skip)` annotation
    /// surfaces immediately as a hash mismatch.
    #[test]
    fn cache_pool_hash_ignores_sccache_path() {
        let base = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
            server_mode: crate::config::SccacheServerMode::Pooled,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let other = EffectiveCacheBinding {
            sccache_path: Some("/usr/local/bin/sccache".into()),
            ..base.clone()
        };
        assert_eq!(
            cache_pool_hash(&base),
            cache_pool_hash(&other),
            "sccache_path must not feed cache_pool_hash; hash drift on \
             host-resolved value would flip spec_hash between hosts"
        );
    }

    /// `cache_pool_hash` MUST include `renderer_schema` in its hash
    /// domain. The whole point of the field is that a ghars binary
    /// upgrade bumping `RENDERER_SCHEMA` flips every managed pool's
    /// hash so the apply path detects the renderer-output change and
    /// rewrites the drop-in. A future regression that added
    /// `#[serde(skip)]` to `renderer_schema` would silently break
    /// this contract; this test catches that by constructing two
    /// bindings differing ONLY in `renderer_schema` and asserting
    /// distinct hashes.
    #[test]
    fn cache_pool_hash_includes_renderer_schema() {
        let base = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: None,
            server_mode: crate::config::SccacheServerMode::Pooled,
            renderer_schema: 1,
        };
        let bumped = EffectiveCacheBinding {
            renderer_schema: 2,
            ..base.clone()
        };
        assert_ne!(
            cache_pool_hash(&base),
            cache_pool_hash(&bumped),
            "renderer_schema MUST participate in cache_pool_hash so a \
             ghars binary upgrade that bumps RENDERER_SCHEMA forces an \
             apply-time pool drop-in rewrite"
        );
    }

    /// Mirror of `cache_pool_hash_includes_renderer_schema` for
    /// `spec_hash`. Two `EffectiveRunnerSpec` values identical except
    /// for `renderer_schema` MUST produce distinct hashes — that's
    /// what drives the in-place rewrite cascade on a ghars binary
    /// upgrade.
    #[test]
    fn spec_hash_includes_renderer_schema() {
        use crate::config::{EffectiveRunnerSpec, EnvironmentSpec, Hardening};
        let base = EffectiveRunnerSpec {
            environment: EnvironmentSpec::default(),
            name: "a".into(),
            url: "https://github.com/example/a".into(),
            arch: crate::config::Arch::X86_64,
            labels: vec!["a".into()],
            memory_max: None,
            runner_version: None,
            runner_sha256: None,
            runner_tarball: None,
            auth_name: "pat".into(),
            caches: vec![],
            trust_zone: "default".into(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
            spec_hash: String::new(),
            config_source: "/etc/ghars/ghars.toml".into(),
            renderer_schema: 1,
        };
        let bumped = EffectiveRunnerSpec {
            renderer_schema: 2,
            ..base.clone()
        };
        assert_ne!(
            spec_hash(&base),
            spec_hash(&bumped),
            "renderer_schema MUST participate in spec_hash so a ghars \
             binary upgrade that bumps RENDERER_SCHEMA forces an \
             apply-time drop-in rewrite + restart"
        );
    }

    /// `cache_pool_hash` MUST include `server_mode` in its hash domain.
    /// A flip from `Pooled` to `PerRunner` (or back) changes the pool
    /// drop-in body — `ExecStart` switches between
    /// `<sccache_path> --start-server` and `<sleep_path> infinity`,
    /// the `SCCACHE_*` env block appears or vanishes. Without
    /// participation in the hash, the plan layer would emit `NoOp` on
    /// `server_mode` flips and the on-disk drop-in would diverge from
    /// the operator's stated topology.
    ///
    /// A future regression adding `#[serde(skip)]` to `server_mode`
    /// (mirroring the pattern at `sccache_path` / `sleep_path` which
    /// ARE host-resolved fields legitimately skipped from the hash)
    /// would silently break this contract; this test catches that by
    /// constructing two bindings differing ONLY in `server_mode` and
    /// asserting distinct hashes.
    #[test]
    fn cache_pool_hash_includes_server_mode() {
        let base = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: None,
            server_mode: crate::config::SccacheServerMode::Pooled,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let flipped = EffectiveCacheBinding {
            server_mode: crate::config::SccacheServerMode::PerRunner,
            ..base.clone()
        };
        assert_ne!(
            cache_pool_hash(&base),
            cache_pool_hash(&flipped),
            "server_mode MUST participate in cache_pool_hash so an \
             operator flipping `[cache_pools.NAME] server_mode = ...` \
             forces an apply-time pool drop-in rewrite (ExecStart + \
             SCCACHE_* env block differ between Pooled and PerRunner)"
        );
    }

    /// Mirror of `cache_pool_hash_includes_server_mode` for `spec_hash`.
    /// `EffectiveCacheBinding` is embedded in `EffectiveRunnerSpec.caches`,
    /// so a `server_mode` flip on a referenced pool MUST also flip the
    /// runner's `spec_hash` and drive an `UpdateRunner` cascade — the
    /// runner-side `30-cache-pool.conf` body differs between modes
    /// (`SCCACHE_SERVER_UDS` override + `SCCACHE_NO_DAEMON` vs
    /// `SCCACHE_DIR` override; `/run/ghars` bind only in Pooled).
    /// Without participation,
    /// the runner's drop-in would stay frozen in the prior mode while
    /// the pool's drop-in flipped, producing a split-brain runtime.
    #[test]
    fn spec_hash_includes_server_mode() {
        use crate::config::{EffectiveRunnerSpec, EnvironmentSpec, Hardening};
        let binding_pooled = EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: None,
            server_mode: crate::config::SccacheServerMode::Pooled,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let binding_per_runner = EffectiveCacheBinding {
            server_mode: crate::config::SccacheServerMode::PerRunner,
            ..binding_pooled.clone()
        };
        let base = EffectiveRunnerSpec {
            environment: EnvironmentSpec::default(),
            name: "a".into(),
            url: "https://github.com/example/a".into(),
            arch: crate::config::Arch::X86_64,
            labels: vec!["a".into()],
            memory_max: None,
            runner_version: None,
            runner_sha256: None,
            runner_tarball: None,
            auth_name: "pat".into(),
            caches: vec![binding_pooled],
            trust_zone: "default".into(),
            network: None,
            proxy: None,
            hooks: None,
            hardening: Hardening::default(),
            allowed_cpus: None,
            allowed_memory_nodes: None,
            spec_hash: String::new(),
            config_source: "/etc/ghars/ghars.toml".into(),
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        };
        let flipped = EffectiveRunnerSpec {
            caches: vec![binding_per_runner],
            ..base.clone()
        };
        assert_ne!(
            spec_hash(&base),
            spec_hash(&flipped),
            "server_mode flip on a referenced cache pool MUST flip \
             the runner's spec_hash so the runner's 30-cache-pool.conf \
             drop-in rewrites in lockstep with the pool's drop-in"
        );
    }
}
