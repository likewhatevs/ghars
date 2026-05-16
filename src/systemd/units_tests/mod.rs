//! Tests for `systemd/units.rs`. Split into `part_a` (template,
//! identity, `runner_env_file`, `render_hardening`) and `part_b`
//! (networks, cgroup-bpf, proxy/hooks/numa, cache drop-ins,
//! integration). Shared fixtures live here so both parts inherit
//! the same `minimal_spec` baseline.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(unused_imports)]

use super::*;

pub(super) use camino::Utf8PathBuf;
pub(super) use ipnet::IpNet;

pub(super) use crate::config::{
    Arch, CaCertBinding, CacheMode, DnsMode, EffectiveNetworkBinding, EgressRule, HooksSpec,
    Ipv6Mode, NetworkSpec, PortSpec, Proto, ProxySpec,
};

pub(super) fn minimal_spec() -> EffectiveRunnerSpec {
    EffectiveRunnerSpec {
        environment: crate::config::EnvironmentSpec::default(),
        name: "buckos".into(),
        url: "https://github.com/example/buckos".into(),
        arch: Arch::X86_64,
        labels: vec!["self-hosted".into(), "linux".into()],
        memory_max: None,
        runner_version: Some("2.334.0".into()),
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
        spec_hash: "sha256:dead".into(),
        config_source: "/etc/ghars/ghars.toml".into(),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    }
}

mod part_a;
mod part_b;
