//! Test module split: plan/ test sections grouped by topic and
//! threaded through shared fixture helpers. The historical
//! `mod tests` in `plan.rs` is preserved verbatim across submodules
//! so every assertion still runs.

#![allow(clippy::unwrap_used, clippy::expect_used, unused_imports)]

use camino::Utf8PathBuf;
use indexmap::IndexMap;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::Result;
use crate::config::{
    Arch, AuthSpec, CacheKind, CacheMode, CachePoolSpec, Config, Defaults, EffectiveCacheBinding,
    EffectiveNetworkBinding, EffectiveRunnerSpec, EtcBindStyle, Hardening, NetworkMode,
    NetworkSpec, RunnerSpec,
};
use crate::error::GharsError;
use crate::paths::Paths;
use crate::state::{ActualState, DiscoveredRunner, Drift, OrphanedUnit};

// Re-exports from parent plan/ module — both the public surface and
// the pub(super) internals each test submodule needs to drive plan
// computation directly.
pub(super) use super::action::{Action, Disruption};
pub(super) use super::classify::{
    DiscoveredAnnotations, classify_recreate_reasons_from_annotations,
};
pub(super) use super::compute::{
    NETNS_POOL_SLOTS, host_arch, into_cache_pool_plan, into_runner_plan, lower_to_effective,
    netns_subnet_for_slot, plan_from, plan_from_with_latest, with_hash,
};
pub(super) use super::expand::{MAX_COUNT, expand_counts};
pub(super) use super::hash::{cache_pool_hash, spec_hash};
pub(super) use super::merge::{merge_defaults, merge_hardening};
pub(super) use super::types::{
    CachePoolDelta, CachePoolPlan, DriftCause, DropInChange, DropInChangeKind, FieldChange,
    FieldValue, LatestReleases, Plan, RunnerDelta, RunnerIdentity, RunnerPlan,
};

mod part1a;
mod part1b;
mod part2a1;
mod part2a2;
mod part2b1;
mod part2b2;
mod part3;

pub(super) fn pat_auth() -> IndexMap<String, AuthSpec> {
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

pub(super) fn minimal_runner(name: &str) -> RunnerSpec {
    RunnerSpec {
        environment: crate::config::EnvironmentSpec::default(),
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

pub(super) fn count_runner(name: &str, count: u32) -> RunnerSpec {
    let mut r = minimal_runner(name);
    r.count = Some(count);
    r
}

pub(super) fn config_with_runners(runners: Vec<RunnerSpec>) -> Config {
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

pub(super) fn empty_paths() -> Paths {
    Paths::default()
}

pub(super) fn empty_actual() -> ActualState {
    ActualState::default()
}

pub(super) fn cfg_source_default() -> String {
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
pub(super) fn discovered_for(
    name: &str,
    spec: &EffectiveRunnerSpec,
    drift: Drift,
) -> DiscoveredRunner {
    let rendered = crate::systemd::render_runner_unit(spec)
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

pub(super) fn anns_with(url: &str, runner_version: Option<&str>) -> DiscoveredAnnotations {
    DiscoveredAnnotations {
        url: Some(url.into()),
        runner_version: runner_version.map(std::convert::Into::into),
        ..DiscoveredAnnotations::default()
    }
}

pub(super) fn spec_with_url(name: &str, url: &str) -> EffectiveRunnerSpec {
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
