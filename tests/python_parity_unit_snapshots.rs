//! Snapshot tests over the unit-text generators (Part 13 Tier 1).
//!
//! `python_parity_unit_text.rs` covers per-directive assertions —
//! it answers "does the generated unit have ProtectKernelLogs=yes?".
//! These tests answer the orthogonal question: "does the FULL
//! generated text still match the bytes we last reviewed?". Any drift
//! — a stray newline, a renamed annotation, a directive added to the
//! template without a doc-update — fails one of these snapshots, and
//! the operator can `cargo insta review` to inspect every line of the
//! diff.
//!
//! Coverage map:
//! - `runner_template`            — canonical runner template body
//!   (`/etc/systemd/system/ghars-runner@.service`).
//! - `netns_template`             — `ghars-net@.service` template body.
//! - `cache_template`             — `ghars-cache@.service` template body.
//! - `dropin_00_identity`         — identity annotations only (always emitted).
//! - `dropin_10_memory`           — `MemoryMax=` only.
//! - `dropin_20_hardening_kvm_off`— operator-strict profile that revokes
//!   `DeviceAllow=/dev/kvm rw` (exercises the reset-on-empty
//!   validator's exemption).
//! - `dropin_20_hardening_strict` — every overridable directive flipped.
//! - `dropin_30_cache_pool_ccache`/`_sccache`/`_unified` — three pool
//!   shapes (Part 9b).
//! - `dropin_40_network_netns`    — fail-closed netns binding.
//! - `dropin_50_numa`             — `AllowedCPUs=` + `AllowedMemoryNodes=`.
//! - `dropin_60_proxy`            — proxy + CA-trust env.
//! - `dropin_70_hooks`            — pre/post-job hooks.
//! - `dropin_80_lognamespace`     — `LogNamespace=ghars-NAME` (always).
//! - `cache_drop_in_*`            — `ghars-cache@NAME.service.d/00-ghars.conf`
//!   per-pool drop-ins (ccache-only, sccache-only, both).
//! - `nft_rules_minimal`/`_full`  — nft rule pair (host + ns) per
//!   Part 9c.
//!
//! The fixture builder uses pinned, deterministic field values
//! (`spec_hash`, `config_source`) so the snapshot bytes
//! don't shift across runs. Operator-supplied paths and IPs in the
//! fixtures are documentation examples lifted from the design spec —
//! `/var/lib/ghars`, `192.168.2.84` (squid proxy example), `10.200.0.0/30`
//! (the design's first /30 slot) — none are environment-derived.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use camino::Utf8PathBuf;
use ghars::config::{
    Arch, CaCertBinding, CacheKind, CacheMode, DnsMode, EffectiveCacheBinding,
    EffectiveNetworkBinding, EffectiveRunnerSpec, EgressRule, EtcBindStyle, Hardening, HooksSpec,
    Ipv6Mode, NetworkMode, NetworkSpec, PortSpec, Proto, ProxySpec,
};
use ghars::systemd::{
    cache_template_text, netns_template_text, render_cache_drop_in, render_nft_rules,
    render_runner_unit, runner_template_text,
};
use ipnet::IpNet;

/// Build a deterministic baseline `EffectiveRunnerSpec` for snapshot
/// fixtures. Every field has a stable, hand-picked value so the
/// generated unit bytes are reproducible across CI runs / hosts /
/// arches. Tests compose by mutating fields on top of this baseline.
fn base_spec() -> EffectiveRunnerSpec {
    EffectiveRunnerSpec {
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
        spec_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        config_source: "/etc/ghars/ghars.toml".into(),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    }
}

/// Pull a drop-in body out of `RenderedUnit.drop_ins` by basename, or
/// panic with a clear message — every snapshot expects exactly one
/// known drop-in to exist.
fn dropin<'a>(drop_ins: &'a BTreeMap<String, String>, name: &str) -> &'a str {
    drop_ins
        .get(name)
        .unwrap_or_else(|| {
            panic!(
                "expected drop-in {name} to be present; got keys {:?}",
                drop_ins.keys().collect::<Vec<_>>()
            )
        })
        .as_str()
}

// ---- Templates ----------------------------------------------------------

#[test]
fn runner_template_snapshot() {
    insta::assert_snapshot!("runner_template", runner_template_text());
}

#[test]
fn netns_template_snapshot() {
    insta::assert_snapshot!("netns_template", netns_template_text());
}

#[test]
fn cache_template_snapshot() {
    insta::assert_snapshot!("cache_template", cache_template_text());
}

// ---- Per-instance drop-ins (ranges 00..80) ------------------------------

#[test]
fn dropin_00_identity_snapshot() {
    let r = render_runner_unit(&base_spec()).unwrap();
    insta::assert_snapshot!("dropin_00_identity", dropin(&r.drop_ins, "00-ghars.conf"));
}

#[test]
fn dropin_10_memory_snapshot() {
    let mut spec = base_spec();
    spec.memory_max = Some("110G".into());
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("dropin_10_memory", dropin(&r.drop_ins, "10-memory.conf"));
}

#[test]
fn dropin_20_hardening_kvm_off_snapshot() {
    // Regression: kvm=false MUST emit a bare `DeviceAllow=` reset
    // (revoking the template's /dev/kvm grant). The snapshot pins the
    // exact rendered text so a future edit that re-regresses this
    // (e.g. flipping render_hardening to skip the line) fails the
    // snapshot review.
    let mut spec = base_spec();
    spec.hardening.kvm = Some(false);
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_20_hardening_kvm_off",
        dropin(&r.drop_ins, "20-hardening.conf")
    );
}

#[test]
fn dropin_20_hardening_strict_snapshot() {
    // The user's actual config (Part 4 example) is stricter than the
    // Python tool defaults across 7+ directives. This fixture mirrors
    // that profile so the snapshot exercises every `Some(...)` branch
    // in `render_hardening`.
    let mut spec = base_spec();
    spec.hardening = Hardening {
        kvm: Some(true),
        restrict_realtime: Some(true),
        protect_control_groups: Some(true),
        restrict_suid_sgid: Some(true),
        private_devices: Some(true),
        private_ipc: Some(true),
        restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
        extra_syscalls: vec![
            "clone3".into(),
            "rseq".into(),
            "close_range".into(),
            "memfd_create".into(),
            "membarrier".into(),
            "mknodat".into(),
            "chroot".into(),
        ],
        etc_bind_style: EtcBindStyle::Broad,
        bind_readonly_paths: None,
        extra_bind_paths: vec![Utf8PathBuf::from("/opt/gha-hooks")],
        extra_capabilities: vec![],
    };
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_20_hardening_strict",
        dropin(&r.drop_ins, "20-hardening.conf")
    );
}

#[test]
fn dropin_30_cache_pool_ccache_only_snapshot() {
    let mut spec = base_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_30_cache_pool_ccache",
        dropin(&r.drop_ins, "30-cache-pool.conf")
    );
}

#[test]
fn dropin_30_cache_pool_sccache_only_snapshot() {
    let mut spec = base_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_30_cache_pool_sccache",
        dropin(&r.drop_ins, "30-cache-pool.conf")
    );
}

#[test]
fn dropin_30_cache_pool_unified_snapshot() {
    // A pool can serve BOTH kinds out of one ghars-cache@.service.
    // The drop-in must layer ccache + sccache env vars in deterministic
    // order so two reviewers comparing the output see identical bytes.
    let mut spec = base_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache, CacheKind::Ccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_30_cache_pool_unified",
        dropin(&r.drop_ins, "30-cache-pool.conf")
    );
}

#[test]
fn dropin_40_network_netns_snapshot() {
    // Fail-closed binding: NetworkNamespacePath= REFUSES TO START
    // when the netns bind-mount path is missing (per
    // exec-invoke.c:4760-4761). The snapshot pins the binding line +
    // every defense-in-depth directive (IPAddressAllow / IPAddressDeny
    // / RestrictAddressFamilies).
    let mut spec = base_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![EgressRule {
                addr: "192.168.2.84".into(),
                port: PortSpec::Single(3128),
                proto: Proto::Tcp,
                comment: Some("squid proxy".into()),
            }],
            ip_allow: vec!["192.168.2.84/32".parse::<IpNet>().unwrap()],
            ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
            restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
            dns: DnsMode::Forward,
            ipv6: Ipv6Mode::Disabled,
        },
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_40_network_netns",
        dropin(&r.drop_ins, "40-network.conf")
    );
}

#[test]
fn dropin_40_network_open_snapshot() {
    // Byte-exact pin for the Open-mode 40-network.conf shape: just
    // the `[Service]` section with cgroup-BPF directives, NO `[Unit]`
    // section, NO `NetworkNamespacePath=`, NO `Requires=ghars-net@`.
    // A regression that mistakenly emits any of the namespace-bound
    // scaffolding under Open mode would fail the snapshot diff.
    let mut spec = base_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
            ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
            restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
            dns: DnsMode::Forward,
            ipv6: Ipv6Mode::Disabled,
        },
        subnet: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_40_network_open",
        dropin(&r.drop_ins, "40-network.conf")
    );
}

#[test]
fn dropin_50_numa_snapshot() {
    let mut spec = base_spec();
    spec.allowed_cpus = Some("0-31".into());
    spec.allowed_memory_nodes = Some("0".into());
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("dropin_50_numa", dropin(&r.drop_ins, "50-numa.conf"));
}

#[test]
fn dropin_60_proxy_snapshot() {
    let mut spec = base_spec();
    spec.proxy = Some(ProxySpec {
        http: Some("http://192.168.2.84:3128".into()),
        https: Some("http://192.168.2.84:3128".into()),
        no_proxy: vec!["192.168.2.84".into()],
        ca_certs: vec![
            CaCertBinding {
                env: "NODE_EXTRA_CA_CERTS".into(),
                path: Utf8PathBuf::from("/etc/pki/ca-trust/source/anchors/squid-proxy-ca.pem"),
            },
            CaCertBinding {
                env: "REQUESTS_CA_BUNDLE".into(),
                path: Utf8PathBuf::from("/etc/pki/tls/certs/ca-bundle.crt"),
            },
            CaCertBinding {
                env: "SSL_CERT_FILE".into(),
                path: Utf8PathBuf::from("/etc/pki/tls/certs/ca-bundle.crt"),
            },
        ],
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("dropin_60_proxy", dropin(&r.drop_ins, "60-proxy.conf"));
}

#[test]
fn dropin_70_hooks_snapshot() {
    let mut spec = base_spec();
    spec.hooks = Some(HooksSpec {
        pre_job: Some(Utf8PathBuf::from("/opt/gha-hooks/pre-job.sh")),
        post_job: Some(Utf8PathBuf::from("/opt/gha-hooks/post-job.sh")),
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("dropin_70_hooks", dropin(&r.drop_ins, "70-hooks.conf"));
}

#[test]
fn dropin_80_lognamespace_snapshot() {
    // Unconditional. The snapshot anchors the exact
    // line so a future edit that drops/renames LogNamespace fails
    // here AND in `python_parity_unit_text.rs` (defense in depth).
    let r = render_runner_unit(&base_spec()).unwrap();
    insta::assert_snapshot!(
        "dropin_80_lognamespace",
        dropin(&r.drop_ins, "80-lognamespace.conf")
    );
}

// ---- ghars-cache@.service per-pool drop-ins (Part 9b) ------------------

#[test]
fn cache_drop_in_ccache_only_snapshot() {
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    };
    let body = render_cache_drop_in(
        &binding,
        "/etc/ghars/ghars.toml",
        "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef0123",
    )
    .unwrap();
    insta::assert_snapshot!("cache_drop_in_ccache_only", body);
}

#[test]
fn cache_drop_in_sccache_only_snapshot() {
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    };
    let body = render_cache_drop_in(
        &binding,
        "/etc/ghars/ghars.toml",
        "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef0123",
    )
    .unwrap();
    insta::assert_snapshot!("cache_drop_in_sccache_only", body);
}

#[test]
fn cache_drop_in_unified_snapshot() {
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache, CacheKind::Ccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    };
    let body = render_cache_drop_in(
        &binding,
        "/etc/ghars/ghars.toml",
        "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef0123",
    )
    .unwrap();
    insta::assert_snapshot!("cache_drop_in_unified", body);
}

// ---- nft rule pairs (Part 9c) ------------------------------------------

#[test]
fn nft_rules_minimal_snapshot() {
    // Single TCP egress entry — the smallest non-trivial Netns
    // policy. Exercises every load-bearing chain (output_filter,
    // forward, postroute, input) and the per-runner masquerade scope
    // (Challenge 7 / SEC-07).
    let binding = EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![EgressRule {
                addr: "192.168.2.84".into(),
                port: PortSpec::Single(3128),
                proto: Proto::Tcp,
                comment: Some("squid proxy".into()),
            }],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::Forward,
            ipv6: Ipv6Mode::Disabled,
        },
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    };
    let rules = render_nft_rules("buckos", &binding).unwrap();
    insta::assert_snapshot!("nft_rules_minimal_host", rules.host_rules);
    insta::assert_snapshot!("nft_rules_minimal_ns", rules.ns_rules);
}

#[test]
fn nft_rules_full_snapshot() {
    // Exercises every PortSpec variant (Single/Set/Range), Proto::Both
    // (emits one rule per L4), and a comment carrying characters that
    // are inside the safe set (`[A-Za-z0-9 _.,:/-]`). Anything outside
    // that set is rejected by validate_egress_comment at config-load
    // time and never reaches the renderer (SEC-30).
    let binding = EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![
                EgressRule {
                    addr: "192.168.2.84".into(),
                    port: PortSpec::Single(3128),
                    proto: Proto::Tcp,
                    comment: Some("squid proxy".into()),
                },
                EgressRule {
                    addr: "10.0.0.1".into(),
                    port: PortSpec::Set(vec![80, 443]),
                    proto: Proto::Tcp,
                    comment: None,
                },
                EgressRule {
                    addr: "10.0.0.2".into(),
                    port: PortSpec::Range {
                        start: 1024,
                        end: 2048,
                    },
                    proto: Proto::Tcp,
                    comment: None,
                },
                EgressRule {
                    addr: "1.1.1.1".into(),
                    port: PortSpec::Single(53),
                    proto: Proto::Both,
                    comment: Some("DoT/DoH upstream".into()),
                },
            ],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::Forward,
            ipv6: Ipv6Mode::Disabled,
        },
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    };
    let rules = render_nft_rules("buckos", &binding).unwrap();
    insta::assert_snapshot!("nft_rules_full_host", rules.host_rules);
    insta::assert_snapshot!("nft_rules_full_ns", rules.ns_rules);
}
