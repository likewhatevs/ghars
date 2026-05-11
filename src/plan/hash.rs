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
}
