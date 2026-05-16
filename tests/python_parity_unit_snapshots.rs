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
//! - `env_file_*`                 — `bin.X.Y.Z/.env` body for the
//!   canonical operator shapes (no-caches, ccache-only, sccache-only,
//!   combined-kind, multi-binding direct-construct, operator env vars,
//!   non-default `trust_zone`). `env_file_ccache_only_binding` /
//!   `env_file_non_default_trust_zone` pin the `has_ccache` binding
//!   gate on the positive side (`CCACHE_DIR` line present);
//!   `env_file_no_caches_no_operator_env` / `env_file_sccache_only_binding`
//!   pin the negative side (no `CCACHE_DIR` line).
//! - `path_file_*`                — `bin.X.Y.Z/.path` body for the
//!   minimal, operator-augmented, and non-default `name+trust_zone`
//!   shapes.
//! - `nft_rules_minimal`/`_full`  — nft rule pair (host + ns) per
//!   Part 9c.
//!
//! Per-area variant fixtures cover renderer-branch gaps the base
//! fixtures above leave unpinned. Each area's `<area>_*` family
//! includes:
//! - `dropin_00_identity_*` — `runner_version=None`, `runner_sha256/tarball`
//!   Some, `arch_aarch64`, `non_default_trust_zone` / `runner_name`, %-escape
//!   in operator env vars, `DnsMode::Static`, `Ipv6Mode::Enabled`, Open-mode
//!   dns/ipv6 emission.
//! - `dropin_15_resolv_*` — Open vs Netns bind sources (the always-
//!   emitted drop-in had zero coverage before).
//! - `dropin_20_hardening_*` — `extra_capabilities`, `bind_readonly_paths`,
//!   `etc_broad_only`, and `kvm_on_only` per-branch isolation pins
//!   beyond the bundled `_strict` fixture.
//! - `dropin_30_cache_pool_multi_binding` — per-binding [Unit]
//!   accumulation + `BindPaths` multi-entry join.
//! - `dropin_40_network_open_*_only` — per-field cgroup-BPF isolation
//!   (`ip_allow` / `ip_deny` / `restrict_address_families` standalone).
//! - `dropin_50_numa_{cpus,memory}_only` — per-field NUMA isolation.
//! - `dropin_60_proxy_{http,no_proxy,ca_certs}_only` — per-field
//!   proxy isolation.
//! - `dropin_70_hooks_{pre,post}_only` + `_different_parents` —
//!   per-side isolation + parent-dedup non-branch.
//! - `cache_drop_in_non_default_{trust_zone,pool_name}` — interpolation
//!   pins for the cache pool drop-in's User= and per-name sites.
//! - `cache_drop_in_ktstr_only` + `env_file_ktstr_kind_binding` —
//!   forward-compat fixtures for `CacheKind::Ktstr` that will be
//!   re-accepted when the pending ktstr-first-class work gates KTSTR_*
//!   emission.
//! - `env_file_{operator_env_var_with_percent,arch_aarch64,two_sccache_bindings}`
//!   — Site A verbatim sister to the Site B %-escape pin, arch-
//!   invariance negative pin, sccache per-binding emission pin.
//! - `nft_rules_{udp_only,dns_static_two_servers,non_default_runner_name}`
//!   — proto independence, Static-mode dns auto-allow, runner-name
//!   interpolation pin pairs.
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
        environment: ghars::config::EnvironmentSpec::default(),
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

/// Build an `EffectiveRunnerSpec` with a Netns-mode
/// `EffectiveNetworkBinding` for fixture matrices that vary `dns` /
/// `ipv6` while keeping every other network field at a stable baseline.
/// Concentrates the boilerplate that the `dns_static` / `ipv6_enabled` /
/// 15-resolv-netns fixtures would otherwise copy-paste verbatim.
///
/// The populated `ip_allow` / `ip_deny` / `restrict_address_families`
/// values are forward-looking — no current consumer renders
/// `40-network.conf` via this helper, so those fields are
/// unobservable in any of the current consumers' snapshot bytes. They
/// are pinned here so a future fixture that DOES exercise the
/// 40-network.conf path via this helper inherits a consistent
/// baseline shape (mirroring `dropin_40_network_netns_snapshot`'s
/// inline construction).
fn spec_with_netns_network(dns: DnsMode, ipv6: Ipv6Mode) -> EffectiveRunnerSpec {
    let mut spec = base_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec!["192.168.2.84/32".parse::<IpNet>().unwrap()],
            ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
            restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
            dns,
            ipv6,
        },
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    });
    spec
}

/// Sister to [`spec_with_netns_network`]. Open-mode binding has no
/// subnet (per `lower_to_effective`'s mode⇒subnet contract).
///
/// Same forward-looking-baseline caveat as [`spec_with_netns_network`]:
/// the populated `ip_allow` / `ip_deny` / `restrict_address_families`
/// values are pinned to mirror `dropin_40_network_open_snapshot`'s
/// inline construction, but no current consumer of this helper renders
/// `40-network.conf` — those fields are unobservable in current
/// consumers' snapshot bytes. The signature accepts any
/// `(dns, ipv6)` combo (no `validate_network_spec` mirror) because
/// direct-construct fixtures are exactly the surface that bypasses
/// the apply-time validator — adding a `debug_assert` here would
/// reject legitimate fixtures that exercise the validator-bypassed
/// render path.
fn spec_with_open_network(dns: DnsMode, ipv6: Ipv6Mode) -> EffectiveRunnerSpec {
    let mut spec = base_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
            ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
            restrict_address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
            dns,
            ipv6,
        },
        subnet: None,
    });
    spec
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
fn dropin_00_identity_runner_version_none_snapshot() {
    // Byte-exact pin for the runner_version=None render-time path
    // (implicit-latest CreateRunner preview). Anchors three coupled
    // emissions: X-Ghars-Effective-Version= (empty rvalue per
    // unwrap_or("")), WorkingDirectory=.../bin.latest,
    // ExecStart=.../bin.latest/bin/runsvc.sh, and
    // ConditionPathExists=.../bin.latest/bin/runsvc.sh. A regression
    // that emitted a literal "latest" in the annotation OR dropped
    // the "latest" fallback in path lines would surface as
    // plan/apply asymmetry — operator runs `ghars plan --diff`
    // against an implicit-latest config and sees an unexpected diff
    // on every subsequent plan.
    let mut spec = base_spec();
    spec.runner_version = None;
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_00_identity_runner_version_none",
        dropin(&r.drop_ins, "00-ghars.conf")
    );
}

#[test]
fn dropin_00_identity_with_runner_sha256_snapshot() {
    // Byte-exact pin for the runner_sha256 Some(non-empty) emission
    // branch in render_identity. base_spec() uses None (line absent
    // — pinned by dropin_00_identity_snapshot); this fixture pins
    // the Some-non-empty positive path: `X-Ghars-Runner-Sha256=<64-hex>`.
    // The empty-string short-circuit (Some("") collapses to no
    // emission, matching None) is pinned upstream at merge_defaults.
    // Sister to the negative-side renderer test
    // `render_identity_treats_some_empty_runner_tarball_as_none_at_renderer`
    // in `systemd/units.rs` tests.
    //
    // Input is the bare 64-hex digest shape that `validate_sha256`
    // accepts (validators.rs rejects any `sha256:` prefix AND
    // rejects non-64-char input); this matches what an operator-
    // loaded config produces on the production path. The renderer
    // emits whatever the field holds VERBATIM, so the on-disk
    // annotation lands as `X-Ghars-Runner-Sha256=<bare-hex>`.
    let mut spec = base_spec();
    spec.runner_sha256 =
        Some("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef0123".into());
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_00_identity_with_runner_sha256",
        dropin(&r.drop_ins, "00-ghars.conf")
    );
}

#[test]
fn dropin_00_identity_with_runner_tarball_snapshot() {
    // Byte-exact pin for the runner_tarball Some(non-empty) emission
    // branch: X-Ghars-Runner-Tarball-Hash=sha256:HEX where HEX is
    // sha256 of the path string. The operator's PATH itself is never
    // persisted (env-leakage); the hash is the change-detection
    // signal. A regression that emitted the path verbatim would
    // expose operator filesystem layout in on-disk drop-ins. Sister
    // to the negative-side renderer test
    // `render_identity_treats_some_empty_runner_tarball_as_none_at_renderer`
    // in `systemd/units.rs` tests.
    let mut spec = base_spec();
    spec.runner_tarball = Some(Utf8PathBuf::from(
        "/var/cache/ghars/runners/actions-runner-linux-x64-2.334.0.tar.gz",
    ));
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_00_identity_with_runner_tarball",
        dropin(&r.drop_ins, "00-ghars.conf")
    );
}

#[test]
fn dropin_00_identity_arch_aarch64_snapshot() {
    // Byte-exact pin for the Arch::Aarch64 → "aarch64" match arm in
    // render_identity. Every other 00-ghars.conf fixture uses
    // X86_64 (base_spec). A regression that swapped the two match
    // arms would land an annotation mismatch — operator's aarch64
    // runner gets registered with x86_64 metadata on GitHub side,
    // causing workflow `runs-on:` failures.
    let mut spec = base_spec();
    spec.arch = Arch::Aarch64;
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_00_identity_arch_aarch64",
        dropin(&r.drop_ins, "00-ghars.conf")
    );
}

#[test]
fn dropin_00_identity_non_default_trust_zone_snapshot() {
    // Byte-exact pin for trust_zone interpolation across 9+ sites
    // in 00-ghars.conf: X-Ghars-Trust-Zone=, User=ghars-tz-,
    // BindPaths=, WorkingDirectory=, ExecStart= (set form),
    // Environment=HOME=, Environment=TMPDIR=,
    // Environment=KTSTR_LOCK_DIR=, Environment=KTSTR_CACHE_DIR=,
    // ConditionPathExists=. Every other 00-ghars.conf snapshot uses
    // trust_zone="default"; a regression that hardcoded the literal
    // at any site would pass dropin_00_identity_snapshot but fail
    // this one (trust-zone isolation broken at DynamicUser
    // allocation — runners run with the wrong UID). Sister to
    // env_file_non_default_trust_zone_snapshot (env-file side) and
    // path_file_non_default_name_and_trust_zone_snapshot
    // (path-file side).
    let mut spec = base_spec();
    spec.trust_zone = "buckos-prod".into();
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_00_identity_non_default_trust_zone",
        dropin(&r.drop_ins, "00-ghars.conf")
    );
}

#[test]
fn dropin_00_identity_non_default_runner_name_snapshot() {
    // Byte-exact pin for runner-name interpolation across 5+ sites
    // in 00-ghars.conf: X-Ghars-Runner-Name=,
    // WorkingDirectory=.../ghars-NAME/, ExecStart=.../ghars-NAME/,
    // Environment=HOME=.../ghars-NAME,
    // Environment=TMPDIR=.../ghars-NAME/tmp,
    // ConditionPathExists=.../ghars-NAME/.../runsvc.sh,
    // SyslogIdentifier=ghars-NAME, LogNamespace=ghars-NAME (the
    // 80-lognamespace.conf basename uses NAME too, but its own
    // snapshot covers that side). Every other 00-ghars.conf
    // snapshot uses name="buckos" (base_spec). A regression that
    // hardcoded the literal would pass other fixtures.
    let mut spec = base_spec();
    spec.name = "ci-worker".into();
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_00_identity_non_default_runner_name",
        dropin(&r.drop_ins, "00-ghars.conf")
    );
}

#[test]
fn dropin_00_identity_with_environment_vars_percent_escape_snapshot() {
    // Byte-exact pin for the operator environment.vars Site B
    // (Environment= directives in 00-ghars.conf) %-escape contract.
    // systemd parses %-specifiers in Environment= values per
    // systemd.exec(5), so operator values containing `%` MUST be
    // emitted as `%%` to preserve the literal value. Site A (.env
    // file) carries operator values VERBATIM because
    // Runner.Listener's LoadAndSetEnv (.NET) does not interpret `%`.
    // Sister to env_file_operator_env_var_with_percent_snapshot
    // (Site A verbatim side). A regression that dropped the
    // .replace('%', "%%") in render_identity's operator-vars loop
    // would silently expand `%H` to hostname inside Environment=
    // values — drift between .env (literal) and Environment=
    // (expanded). Cross-ref render_identity's operator-vars loop in
    // `systemd/units.rs`.
    let mut spec = base_spec();
    spec.environment
        .vars
        .insert("WITH_PERCENT".into(), "100%done".into());
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_00_identity_with_environment_vars_percent_escape",
        dropin(&r.drop_ins, "00-ghars.conf")
    );
}

#[test]
fn dropin_00_identity_netns_dns_static_snapshot() {
    // Byte-exact pin for X-Ghars-Dns=static:CSV annotation emission
    // in 00-ghars.conf when DnsMode::Static{servers} is configured.
    // Every other network-bound fixture uses DnsMode::Forward
    // (annotation emits literal "forward"). A regression in
    // dns_to_annotation (src/config.rs) that swapped the `,` server
    // separator for `;` would land silently — only the Static
    // branch's CSV emission changes; the classifier's parser splits
    // on `,` so a `,`→`;` swap would silently desync from the
    // parser. Closes the gap by pinning the static:1.1.1.1 byte-form.
    let spec = spec_with_netns_network(
        DnsMode::Static {
            servers: vec!["1.1.1.1".parse().unwrap()],
        },
        Ipv6Mode::Disabled,
    );
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_00_identity_netns_dns_static",
        dropin(&r.drop_ins, "00-ghars.conf")
    );
}

#[test]
fn dropin_00_identity_netns_ipv6_enabled_snapshot() {
    // Byte-exact pin for X-Ghars-Ipv6=enabled annotation emission
    // in 00-ghars.conf when Ipv6Mode::Enabled is configured.
    // Defensive forward-compat: v0.1 apply hard-errors on Enabled
    // (per Ipv6Mode::Enabled doc in `config.rs`), but the renderer
    // emits the annotation regardless. Direct-construct fixtures
    // (this one) reach the renderer bypassing the apply gate. Pins
    // the annotation surface so v0.2 validator relaxation does not
    // silently drop the line.
    let spec = spec_with_netns_network(DnsMode::Forward, Ipv6Mode::Enabled);
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_00_identity_netns_ipv6_enabled",
        dropin(&r.drop_ins, "00-ghars.conf")
    );
}

#[test]
fn dropin_00_identity_open_mode_emits_dns_ipv6_without_subnet_snapshot() {
    // Byte-exact pin for Open-mode 00-ghars.conf shape: X-Ghars-Dns
    // and X-Ghars-Ipv6 ARE emitted in Open mode (gated on
    // network.is_some(), NOT mode == Netns), but X-Ghars-Netns-Subnet
    // is NOT (gated on subnet.is_some() which only Netns mode sets).
    // Catches a regression that gates dns/ipv6 emission on Netns
    // mode instead of network.is_some(). Anchors the per-#97 decision
    // that surfaced dns/ipv6 emission for both modes.
    let spec = spec_with_open_network(DnsMode::Forward, Ipv6Mode::Disabled);
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_00_identity_open_mode_emits_dns_ipv6_without_subnet",
        dropin(&r.drop_ins, "00-ghars.conf")
    );
}

#[test]
fn dropin_10_memory_snapshot() {
    let mut spec = base_spec();
    spec.memory_max = Some("110G".into());
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("dropin_10_memory", dropin(&r.drop_ins, "10-memory.conf"));
}

#[test]
fn dropin_15_resolv_open_snapshot() {
    // Byte-exact pin for the Open-mode 15-resolv.conf shape:
    // BindReadOnlyPaths=/etc/resolv.conf — the host's resolver is
    // bound into the runner's mount namespace. A regression that
    // swapped BindReadOnlyPaths= for BindReadWritePaths= would expose
    // a writable host /etc/resolv.conf bind (unit-level container-
    // escape vector). 15-resolv.conf is one of only 3 unconditionally-
    // emitted drop-ins (alongside 00-ghars.conf and 80-lognamespace.conf)
    // but had zero snapshot coverage before this fixture. Cross-ref
    // `render_resolv_bind` open-mode branch in `systemd/units.rs`.
    let r = render_runner_unit(&base_spec()).unwrap();
    insta::assert_snapshot!(
        "dropin_15_resolv_open",
        dropin(&r.drop_ins, "15-resolv.conf")
    );
}

#[test]
fn dropin_15_resolv_netns_snapshot() {
    // Byte-exact pin for the Netns-mode 15-resolv.conf shape:
    // BindReadOnlyPaths=/run/ghars/netns-resolv/NAME:/etc/resolv.conf
    // fail-closed (no `-` prefix). The `_netns-setup` helper writes
    // the source file at unit start; a missing file fails the unit.
    // A regression that hardcoded the runner-name interpolation
    // (e.g. literal "default") would silently let runner A read
    // runner B's resolv config — netns isolation broken. Cross-ref
    // `render_resolv_bind` netns branch in `systemd/units.rs`.
    let spec = spec_with_netns_network(DnsMode::Forward, Ipv6Mode::Disabled);
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_15_resolv_netns",
        dropin(&r.drop_ins, "15-resolv.conf")
    );
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
    // that profile so the snapshot exercises most `Some(...)` branches
    // in `render_hardening`. extra_capabilities and bind_readonly_paths
    // are covered by separate fixtures (dropin_20_hardening_extra_capabilities,
    // dropin_20_hardening_bind_readonly_paths) — including them here
    // would bundle too many directives into one snapshot diff.
    //
    // The fixture-supplied operator order for `restrict_address_families`
    // (AF_UNIX, AF_INET) and `extra_syscalls` (clone3, rseq, ...) is
    // intentionally non-canonical at the input — `render_hardening`'s
    // defense-in-depth sort canonicalizes both lines at the renderer
    // boundary, so the snapshot pins the lexicographically-sorted on-disk
    // emission. This is the direct-construct sister to the
    // `plan::merge_hardening` upstream sort and to the
    // `restrict_address_families` defensive sort at `render_network`.
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
fn dropin_20_hardening_extra_capabilities_snapshot() {
    // Byte-exact pin for the extra_capabilities → CapabilityBoundingSet=
    // renderer branch. Pins the union-semantics contract: the
    // template sets CapabilityBoundingSet= empty (no CAP_SETUID /
    // CAP_SETGID per DynamicUser=) and the drop-in's value UNIONS
    // with that empty base, becoming the runner's full bounding
    // set. dropin_20_hardening_strict has extra_capabilities:
    // vec![] — this is the only positive-emission pin. Multi-token
    // (2 caps) catches join-vs-index regressions (e.g. a future
    // edit that swapped `.join(" ")` for indexing the first element).
    // Cross-ref `render_hardening` extra_capabilities branch in
    // `systemd/units.rs`.
    let mut spec = base_spec();
    spec.hardening.extra_capabilities = vec!["CAP_NET_BIND_SERVICE".into(), "CAP_NET_RAW".into()];
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_20_hardening_extra_capabilities",
        dropin(&r.drop_ins, "20-hardening.conf")
    );
}

#[test]
fn dropin_20_hardening_bind_readonly_paths_snapshot() {
    // Byte-exact pin for the bind_readonly_paths Some(non-empty) →
    // BindReadOnlyPaths= renderer branch. Pins the append-not-replace
    // contract per systemd.exec(5) — the operator's entries on one
    // BindReadOnlyPaths= line APPEND to the template's accumulated
    // list. Reset-on-empty validator forbids the bare-= form; this
    // fixture pins the non-empty positive shape. Existing
    // dropin_20_hardening_strict has bind_readonly_paths: None. A
    // regression that joined with commas instead of spaces would
    // produce invalid systemd directive (systemd parses
    // BindReadOnlyPaths=/etc/foo,/etc/bar as ONE path with literal
    // comma). Cross-ref `render_hardening` bind_readonly_paths
    // branch in `systemd/units.rs`.
    let mut spec = base_spec();
    spec.hardening.bind_readonly_paths = Some(vec![
        Utf8PathBuf::from("/etc/ghars/secrets"),
        Utf8PathBuf::from("/var/lib/operator-trust"),
    ]);
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_20_hardening_bind_readonly_paths",
        dropin(&r.drop_ins, "20-hardening.conf")
    );
}

#[test]
fn dropin_20_hardening_extra_syscalls_only_snapshot() {
    // Per-field independence pin for the `has_lists` rollup
    // early-return inside `render_hardening` (the OR-of-5 predicate
    // that emits the drop-in when ANY of restrict_address_families /
    // extra_syscalls / extra_capabilities / extra_bind_paths /
    // bind_readonly_paths is non-empty). The rollup variable couples
    // these fields at the gate; a regression that accidentally
    // collapses the OR to AND-semantics would silently drop the
    // operator's extra syscalls when other Hardening list fields
    // are empty.
    // dropin_20_hardening_strict bundles extra_syscalls with
    // restrict_address_families + extra_bind_paths set — only an
    // isolated extra_syscalls fixture catches the
    // collapsed-OR-to-AND regression class. Operator-visible
    // failure mode: declares `extra_syscalls = ["clone3", "rseq"]`
    // for an io_uring workflow, gets EPERM at runtime with no
    // diagnostic. Cross-ref `render_hardening` extra_syscalls
    // branch in `systemd/units.rs`.
    let mut spec = base_spec();
    spec.hardening.extra_syscalls = vec!["clone3".into(), "rseq".into()];
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_20_hardening_extra_syscalls_only",
        dropin(&r.drop_ins, "20-hardening.conf")
    );
}

#[test]
fn dropin_20_hardening_etc_broad_only_snapshot() {
    // Byte-exact pin for the etc_bind_style=Broad ISOLATED branch.
    // dropin_20_hardening_strict has etc_bind_style: Broad bundled
    // with many other directives. This fixture isolates the Broad
    // branch (Hardening::default() apart from etc_bind_style) so a
    // regression that breaks ONLY the Broad emission (e.g. a future
    // edit that swapped `BindReadOnlyPaths=/etc` for
    // `BindReadOnlyPaths=/etc/all`) doesn't get masked by other
    // directive changes in the strict snapshot. Cross-ref
    // `render_hardening` etc_bind_style branch in `systemd/units.rs`.
    let mut spec = base_spec();
    spec.hardening.etc_bind_style = EtcBindStyle::Broad;
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_20_hardening_etc_broad_only",
        dropin(&r.drop_ins, "20-hardening.conf")
    );
}

#[test]
fn dropin_20_hardening_kvm_on_only_snapshot() {
    // Byte-exact pin for the kvm=Some(true) ISOLATED branch.
    // dropin_20_hardening_kvm_off pins Some(false); strict pins
    // Some(true) bundled with many other directives. This fixture
    // isolates the Some(true) → DeviceAllow=/dev/kvm rw emission so
    // a regression that breaks ONLY the kvm=true branch isn't
    // masked. Cross-ref `render_hardening` kvm branch (the `if
    // profile.kvm` arm) in `systemd/units.rs`.
    let mut spec = base_spec();
    spec.hardening.kvm = Some(true);
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_20_hardening_kvm_on_only",
        dropin(&r.drop_ins, "20-hardening.conf")
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
fn dropin_30_cache_pool_multi_binding_snapshot() {
    // Byte-exact pin for the multi-binding 30-cache-pool.conf shape:
    // 2 bindings (one ccache-only, one sccache-only). Verifies
    // [Unit] section accumulation: Requires=/After= per sccache
    // pool only (ccache pools have no server unit so they're absent
    // from the [Unit] block) AND the BindPaths= pool-dir + /run/ghars
    // join (the ccache binding contributes NO entry to bind_paths
    // per the LAYER 1/2 contract — `render_cache_pool`'s Ccache
    // branch in `systemd/units.rs` is empty by design, ccache uses
    // shared HOME under trust_zone NOT a per-pool BindPath; the
    // Sccache binding contributes the per-pool dir + /run/ghars
    // needed for the UDS). Existing dropin_30_cache_pool_sccache +
    // dropin_30_cache_pool_unified are single-binding fixtures —
    // this exercises the per-binding emission loop for the
    // runner-side drop-in. Cross-ref `render_cache_pool`'s
    // unit_section_pools accumulator + per-binding loop in
    // `systemd/units.rs`.
    let mut spec = base_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "50G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    spec.caches.push(EffectiveCacheBinding {
        name: "test".into(),
        kinds: vec![CacheKind::Sccache],
        size: "100G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_30_cache_pool_multi_binding",
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
fn dropin_40_network_open_ip_allow_only_snapshot() {
    // Per-field independence pin: dropin_40_network_open populates
    // all 3 cgroup-BPF fields (ip_allow + ip_deny +
    // restrict_address_families). A regression that conditionally
    // drops the wrong directive when its sibling fields are empty
    // would not be caught. This fixture isolates ip_allow-only
    // emission (no IPAddressDeny=, no RestrictAddressFamilies=
    // lines). Cross-ref `render_network`'s per-field loops in
    // `systemd/units.rs`.
    let mut spec = base_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec!["10.0.0.0/8".parse::<IpNet>().unwrap()],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::Forward,
            ipv6: Ipv6Mode::Disabled,
        },
        subnet: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_40_network_open_ip_allow_only",
        dropin(&r.drop_ins, "40-network.conf")
    );
}

#[test]
fn dropin_40_network_open_ip_deny_only_snapshot() {
    // Per-field independence pin: isolates ip_deny-only emission
    // (no IPAddressAllow=, no RestrictAddressFamilies= lines).
    // Sister to dropin_40_network_open_ip_allow_only_snapshot.
    let mut spec = base_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
            restrict_address_families: vec![],
            dns: DnsMode::Forward,
            ipv6: Ipv6Mode::Disabled,
        },
        subnet: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_40_network_open_ip_deny_only",
        dropin(&r.drop_ins, "40-network.conf")
    );
}

#[test]
fn dropin_40_network_open_restrict_address_families_only_snapshot() {
    // Per-field independence pin: isolates
    // restrict_address_families-only emission (no IPAddressAllow=,
    // no IPAddressDeny= lines). Sister to
    // dropin_40_network_open_ip_allow_only_snapshot.
    let mut spec = base_spec();
    spec.network = Some(EffectiveNetworkBinding {
        name: "hostnet".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Open,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec!["AF_INET".into()],
            dns: DnsMode::Forward,
            ipv6: Ipv6Mode::Disabled,
        },
        subnet: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_40_network_open_restrict_address_families_only",
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
fn dropin_50_numa_cpus_only_snapshot() {
    // Per-field independence pin: isolates allowed_cpus-only
    // emission. Existing dropin_50_numa has BOTH fields. A
    // regression that gated AllowedCPUs= on allowed_memory_nodes
    // also being Some would silently drop CPU pinning for operators
    // who set only cpus. Cross-ref `render_numa` per-field arms in
    // `systemd/units.rs`.
    let mut spec = base_spec();
    spec.allowed_cpus = Some("0-15".into());
    spec.allowed_memory_nodes = None;
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_50_numa_cpus_only",
        dropin(&r.drop_ins, "50-numa.conf")
    );
}

#[test]
fn dropin_50_numa_memory_only_snapshot() {
    // Per-field independence pin: isolates allowed_memory_nodes-only
    // emission. Sister to dropin_50_numa_cpus_only_snapshot.
    let mut spec = base_spec();
    spec.allowed_cpus = None;
    spec.allowed_memory_nodes = Some("0".into());
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_50_numa_memory_only",
        dropin(&r.drop_ins, "50-numa.conf")
    );
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
fn dropin_60_proxy_http_only_snapshot() {
    // Per-field independence pin: isolates http-only proxy emission.
    // Existing dropin_60_proxy has ALL 4 ProxySpec fields populated.
    // This fixture pins HTTP_PROXY+http_proxy only (no HTTPS_PROXY,
    // no NO_PROXY, no CA bindings, no BindReadOnlyPaths). A
    // regression that emits HTTPS_PROXY using the HTTP value would
    // silently mis-route HTTPS traffic. Cross-ref `render_proxy`
    // per-field arms in `systemd/units.rs`.
    let mut spec = base_spec();
    spec.proxy = Some(ProxySpec {
        http: Some("http://192.168.2.84:3128".into()),
        https: None,
        no_proxy: vec![],
        ca_certs: vec![],
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_60_proxy_http_only",
        dropin(&r.drop_ins, "60-proxy.conf")
    );
}

#[test]
fn dropin_60_proxy_no_proxy_only_snapshot() {
    // Per-field independence pin: isolates no_proxy-only emission
    // (multi-entry CSV join shape — NO_PROXY=entry,entry,entry).
    // Catches a regression that joins with a different separator
    // (semicolon, space) instead of comma. Existing dropin_60_proxy
    // has all fields populated.
    let mut spec = base_spec();
    spec.proxy = Some(ProxySpec {
        http: None,
        https: None,
        no_proxy: vec![
            "192.168.2.84".into(),
            "localhost".into(),
            ".internal".into(),
        ],
        ca_certs: vec![],
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_60_proxy_no_proxy_only",
        dropin(&r.drop_ins, "60-proxy.conf")
    );
}

#[test]
fn dropin_60_proxy_ca_certs_only_snapshot() {
    // Per-field independence pin: isolates ca_certs-only emission
    // (Environment=NODE_EXTRA_CA_CERTS=... + BindReadOnlyPaths=).
    // Catches a regression that gates ca_certs emission on having a
    // proxy URL set. Existing dropin_60_proxy bundles ca_certs with
    // http+https+no_proxy.
    let mut spec = base_spec();
    spec.proxy = Some(ProxySpec {
        http: None,
        https: None,
        no_proxy: vec![],
        ca_certs: vec![CaCertBinding {
            env: "NODE_EXTRA_CA_CERTS".into(),
            path: Utf8PathBuf::from("/etc/pki/ca-trust/source/anchors/squid-proxy-ca.pem"),
        }],
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_60_proxy_ca_certs_only",
        dropin(&r.drop_ins, "60-proxy.conf")
    );
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
fn dropin_70_hooks_pre_only_snapshot() {
    // Per-field independence pin: isolates pre_job-only emission
    // (single Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED line +
    // single parent BindReadOnlyPaths entry). Existing
    // dropin_70_hooks has BOTH set so a regression that gates one
    // on the other is unobservable there. Cross-ref `render_hooks`
    // per-field arms in `systemd/units.rs`.
    let mut spec = base_spec();
    spec.hooks = Some(HooksSpec {
        pre_job: Some(Utf8PathBuf::from("/opt/gha-hooks/pre-job.sh")),
        post_job: None,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_70_hooks_pre_only",
        dropin(&r.drop_ins, "70-hooks.conf")
    );
}

#[test]
fn dropin_70_hooks_post_only_snapshot() {
    // Per-field independence pin: isolates post_job-only emission
    // (single Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED line).
    // Sister to dropin_70_hooks_pre_only_snapshot.
    let mut spec = base_spec();
    spec.hooks = Some(HooksSpec {
        pre_job: None,
        post_job: Some(Utf8PathBuf::from("/opt/gha-hooks/post-job.sh")),
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_70_hooks_post_only",
        dropin(&r.drop_ins, "70-hooks.conf")
    );
}

#[test]
fn dropin_70_hooks_different_parents_snapshot() {
    // Byte-exact pin for the "different parents emit both entries"
    // shape. The complete parent-dedup contract is established
    // PAIRWISE across this fixture + the baseline `dropin_70_hooks`
    // (which uses both hooks under `/opt/gha-hooks/` and emits a
    // single deduped `BindReadOnlyPaths=/opt/gha-hooks`); this
    // fixture provides the "different parents → 2 entries on one
    // line" sister case. Together they pin: same parent dedups,
    // distinct parents do not. A regression that breaks the dedup
    // PREDICATE itself (e.g. `if true` always-push) surfaces in
    // the baseline `dropin_70_hooks` (parent count goes from 1 to
    // 2); a regression that always dedups (broken for distinct
    // parents) surfaces here (entry count goes from 2 to 1). Both
    // halves of the contract are observable only across the pair.
    // Cross-ref `render_hooks` parent-dedup loop in
    // `systemd/units.rs`.
    let mut spec = base_spec();
    spec.hooks = Some(HooksSpec {
        pre_job: Some(Utf8PathBuf::from("/opt/gha-pre-hooks/pre.sh")),
        post_job: Some(Utf8PathBuf::from("/opt/gha-post-hooks/post.sh")),
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!(
        "dropin_70_hooks_different_parents",
        dropin(&r.drop_ins, "70-hooks.conf")
    );
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

#[test]
fn cache_drop_in_non_default_trust_zone_snapshot() {
    // Byte-exact pin for trust_zone interpolation in the cache pool
    // drop-in's User=ghars-tz-TZ line. Existing 3 cache_drop_in_*
    // fixtures all use trust_zone="default" — a regression that
    // hardcoded the literal would pass them all. Sister to
    // dropin_00_identity_non_default_trust_zone_snapshot
    // (runner-side User= line). The two together pin the trust_zone
    // identity contract across both unit types in the same
    // trust_zone.
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Sccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "buckos-prod".into(),
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
    insta::assert_snapshot!("cache_drop_in_non_default_trust_zone", body);
}

#[test]
fn cache_drop_in_non_default_pool_name_snapshot() {
    // Byte-exact pin for pool-name interpolation across 4 sites in
    // the cache pool drop-in: X-Ghars-Pool-Name=,
    // SCCACHE_DIR=%C/ghars/pools/NAME/sccache,
    // SCCACHE_SERVER_UDS=%t/ghars/cache-NAME.sock,
    // ReadWritePaths=%C/ghars/pools/NAME ... Existing 3
    // cache_drop_in_* fixtures all use name="build" — a regression
    // that hardcoded the literal at any of the 4 sites would not
    // surface.
    let binding = EffectiveCacheBinding {
        name: "rust-incremental".into(),
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
    insta::assert_snapshot!("cache_drop_in_non_default_pool_name", body);
}

#[test]
fn cache_drop_in_ktstr_only_snapshot() {
    // Byte-exact pin for the ktstr-only cache pool drop-in shape.
    // Per the CacheKind::Ktstr doc-comment in `config.rs`, ktstr is
    // a filesystem-mode kind (like ccache) — a ktstr-only pool's
    // drop-in currently falls through to the sleep-stub branch
    // (ExecStart=<sleep_path> infinity + ReadWritePaths=
    // %C/ghars/pools/NAME) because serves_sccache is false and
    // serves_ccache is false. The pending Phase 2 work for
    // ktstr-as-first-class will gate KTSTR_* env emission and may
    // change this body; when that lands the snapshot must be
    // re-accepted with the new shape.
    let binding = EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ktstr],
        size: "50G".into(),
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
    insta::assert_snapshot!("cache_drop_in_ktstr_only", body);
}

// ---- bin.X.Y.Z/.env + bin.X.Y.Z/.path renderers ------------------------
//
// `render_runner_unit` calls the env_file + path_file renderers
// internally and stores their output on `RenderedUnit.env_file` /
// `.path_file`. The snapshots below pin byte-exact output for the
// canonical shapes operators land on (no caches, ccache-bound,
// sccache-bound, combined-kind-bound, multi-binding direct-construct,
// operator env vars, non-default trust_zone, minimal PATH,
// operator-augmented PATH, non-default name+trust_zone PATH).
//
// Per the has_ccache binding gate, `CCACHE_DIR=` emission and
// `.ccache` dir creation are both gated on at-least-one-ccache-
// kind-binding. These
// snapshots are the byte-level pin that guards the renderer side of
// that symmetry.

#[test]
fn env_file_no_caches_no_operator_env_snapshot() {
    let r = render_runner_unit(&base_spec()).unwrap();
    insta::assert_snapshot!("env_file_no_caches_no_operator_env", r.env_file);
}

#[test]
fn env_file_ccache_only_binding_snapshot() {
    let mut spec = base_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "50G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("env_file_ccache_only_binding", r.env_file);
}

#[test]
fn env_file_combined_kind_binding_snapshot() {
    let mut spec = base_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache, CacheKind::Sccache],
        size: "200G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("env_file_combined_kind_binding", r.env_file);
}

#[test]
fn env_file_sccache_only_binding_snapshot() {
    // Pins the sccache-only env_file shape: NO CCACHE_DIR (gated on
    // Ccache kind), NO CCACHE_MAXSIZE, all 4 SCCACHE_* lines
    // emitted. The combined-kind snapshot does NOT prove the
    // CCACHE_DIR gate because that fixture INCLUDES Ccache in kinds
    // by design — only an sccache-only fixture catches a regression
    // that gates CCACHE_DIR on "any binding" instead of "Ccache kind".
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
    insta::assert_snapshot!("env_file_sccache_only_binding", r.env_file);
}

#[test]
fn env_file_non_default_trust_zone_snapshot() {
    // Pins trust_zone interpolation at 3 sites: CCACHE_DIR,
    // KTSTR_LOCK_DIR, KTSTR_CACHE_DIR. Every other env_file snapshot
    // uses trust_zone="default"; a regression that hardcoded the
    // literal string would pass all of them. Uses a ccache binding
    // so CCACHE_DIR is emitted and the interpolation at
    // `render_runner_env_file`'s CCACHE_DIR site (cross-ref the
    // `has_ccache` gate + format string in `systemd/units.rs`) is
    // observable.
    let mut spec = base_spec();
    spec.trust_zone = "buckos-prod".into();
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "50G".into(),
        mode: CacheMode::Shared,
        trust_zone: "buckos-prod".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("env_file_non_default_trust_zone", r.env_file);
}

#[test]
fn env_file_multi_binding_direct_construct_snapshot() {
    // Two ccache bindings on one runner. Per the
    // `validate_no_duplicate_cache_kinds` validator, this is rejected
    // at config-load + plan-time; direct-construct test paths (this
    // fixture) bypass both gates so the renderer's per-binding
    // emission contract is still observable. Byte-level pin of the
    // existing unit-test `_emits_one_ccache_maxsize_per_binding_in_source_order`
    // contract — turns the line-level assertion into a full-body
    // snapshot guard. Catches regressions like `caches.first()`
    // instead of `caches.iter()` or a missing per-binding loop body.
    let mut spec = base_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "50G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    spec.caches.push(EffectiveCacheBinding {
        name: "test".into(),
        kinds: vec![CacheKind::Ccache],
        size: "100G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("env_file_multi_binding_direct_construct", r.env_file);
}

#[test]
fn env_file_operator_environment_vars_snapshot() {
    let mut spec = base_spec();
    spec.environment
        .vars
        .insert("DEPLOY_TARGET".into(), "buckos-ci".into());
    spec.environment
        .vars
        .insert("RUST_LOG".into(), "info".into());
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ccache],
        size: "50G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("env_file_operator_environment_vars", r.env_file);
}

#[test]
fn env_file_operator_env_var_with_percent_snapshot() {
    // Byte-exact pin for the operator environment.vars Site A (.env
    // file) emission with a value containing `%`. .env carries
    // operator values VERBATIM — Runner.Listener's LoadAndSetEnv
    // (.NET) does NOT interpret `%`. Sister to
    // dropin_00_identity_with_environment_vars_percent_escape_snapshot
    // (Site B / 00-ghars.conf — the same operator value emits as
    // `%%` there). The two-site pair pins the Site A / Site B
    // divergence contract: same operator input, different on-disk
    // representations because systemd interprets `%` and .NET does
    // not.
    let mut spec = base_spec();
    spec.environment
        .vars
        .insert("WITH_PERCENT".into(), "100%done".into());
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("env_file_operator_env_var_with_percent", r.env_file);
}

#[test]
fn env_file_arch_aarch64_snapshot() {
    // Negative-invariance pin: .env content must be BYTE-IDENTICAL
    // whether arch is X86_64 or Aarch64 (render_runner_env_file
    // doesn't consume spec.arch). Catches a regression that adds an
    // arch-conditional emission to the .env body. Companion to
    // dropin_00_identity_arch_aarch64_snapshot (positive side: arch
    // emits to X-Ghars-Arch= annotation in 00-ghars.conf).
    let mut spec = base_spec();
    spec.arch = Arch::Aarch64;
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("env_file_arch_aarch64", r.env_file);
}

#[test]
fn env_file_two_sccache_bindings_snapshot() {
    // Per-binding emission pin for the Sccache branch (sister to
    // env_file_multi_binding_direct_construct_snapshot which pins
    // two Ccache bindings). The `validate_no_duplicate_cache_kinds`
    // validator forbids this at config-load + plan-time, but direct-
    // construct test paths (this fixture) bypass both gates so the
    // renderer's per-binding emission contract for the Sccache
    // branch is observable. Catches a regression like
    // `caches.first()` instead of `caches.iter()` on the Sccache
    // branch — same regression class as the existing ccache-multi
    // pin.
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
    spec.caches.push(EffectiveCacheBinding {
        name: "test".into(),
        kinds: vec![CacheKind::Sccache],
        size: "100G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: Some("/usr/bin/sccache".into()),
        sleep_path: None,
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("env_file_two_sccache_bindings", r.env_file);
}

#[test]
fn env_file_ktstr_kind_binding_snapshot() {
    // Byte-exact pin for env_file when a ktstr binding is present.
    // Currently ktstr binding hits NEITHER the Ccache branch (no
    // CCACHE_DIR) NOR the Sccache branch (no SCCACHE_* lines); the
    // unconditional KTSTR_LOCK_DIR + KTSTR_CACHE_DIR are emitted at
    // the trust-zone path regardless. The pending Phase 2 work for
    // ktstr-as-first-class will gate KTSTR_* env emission on
    // has_ktstr binding; when that lands this snapshot will be
    // re-accepted with the gated emission shape.
    let mut spec = base_spec();
    spec.caches.push(EffectiveCacheBinding {
        name: "build".into(),
        kinds: vec![CacheKind::Ktstr],
        size: "50G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        renderer_schema: ghars::systemd::RENDERER_SCHEMA,
    });
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("env_file_ktstr_kind_binding", r.env_file);
}

#[test]
fn path_file_minimal_no_operator_path_snapshot() {
    let r = render_runner_unit(&base_spec()).unwrap();
    insta::assert_snapshot!("path_file_minimal_no_operator_path", r.path_file);
}

#[test]
fn path_file_non_default_name_and_trust_zone_snapshot() {
    // Pins name + trust_zone interpolation in the per-runner
    // .cargo/bin segment (`/var/lib/ghars/{trust_zone}/ghars-{name}/
    // .cargo/bin`). Every other path_file snapshot uses the default
    // fixture (name="buckos", trust_zone="default"); a regression
    // that hardcoded either would pass all of them. This snapshot
    // uses name="ci-worker" + trust_zone="buckos-prod" so both
    // interpolations are observable byte-for-byte.
    let mut spec = base_spec();
    spec.name = "ci-worker".into();
    spec.trust_zone = "buckos-prod".into();
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("path_file_non_default_name_and_trust_zone", r.path_file);
}

#[test]
fn path_file_operator_path_prepend_append_snapshot() {
    let mut spec = base_spec();
    spec.environment
        .path_prepend
        .push(Utf8PathBuf::from("/opt/buckos/bin"));
    spec.environment
        .path_prepend
        .push(Utf8PathBuf::from("/opt/buck2/bin"));
    spec.environment
        .path_append
        .push(Utf8PathBuf::from("/opt/operator-fallback/bin"));
    let r = render_runner_unit(&spec).unwrap();
    insta::assert_snapshot!("path_file_operator_path_prepend_append", r.path_file);
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

#[test]
fn nft_rules_udp_only_snapshot() {
    // Per-proto independence pin: existing nft_rules_minimal uses
    // Proto::Tcp; nft_rules_full mixes both via Proto::Both. NO
    // fixture exercises Proto::Udp standalone (operator emits
    // udp-only egress rule — e.g. NTP at 123/udp, syslog at
    // 514/udp). Catches a regression in `proto_tokens` that
    // handles Tcp/Both but not Udp.
    //
    // NB: this fixture's body also incidentally contains the
    // Forward-mode dns auto-allow lines (the netns binding's
    // `dns: DnsMode::Forward` default reaches
    // `dns_auto_allow_destinations` which adds udp+tcp/53 to the
    // host_ip derived from the /30 subnet). Proto::Udp isolation
    // is via comparison against nft_rules_minimal (Tcp-only) and
    // nft_rules_full (mixed) — the udp dport 123 NTP line is the
    // load-bearing pin specific to this fixture.
    let binding = EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![EgressRule {
                addr: "192.168.2.84".into(),
                port: PortSpec::Single(123),
                proto: Proto::Udp,
                comment: Some("NTP".into()),
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
    insta::assert_snapshot!("nft_rules_udp_only_host", rules.host_rules);
    insta::assert_snapshot!("nft_rules_udp_only_ns", rules.ns_rules);
}

#[test]
fn nft_rules_dns_static_two_servers_snapshot() {
    // Byte-exact pin for DnsMode::Static dns auto-allow emission
    // (per-server udp+tcp/53 lines). Existing nft fixtures all use
    // DnsMode::Forward (auto-allow targets host_ip derived from the
    // /30 subnet). A regression in the Static branch of
    // `dns_auto_allow_destinations` (systemd/nft.rs) would silently
    // drop operator-specified DNS servers from the netns egress
    // allow-list, causing DNS resolution failure inside the netns.
    // Two servers exercise the per-server emission loop.
    let binding = EffectiveNetworkBinding {
        name: "buck2-isolated".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::Static {
                servers: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
            },
            ipv6: Ipv6Mode::Disabled,
        },
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    };
    let rules = render_nft_rules("buckos", &binding).unwrap();
    insta::assert_snapshot!("nft_rules_dns_static_two_servers_host", rules.host_rules);
    insta::assert_snapshot!("nft_rules_dns_static_two_servers_ns", rules.ns_rules);
}

#[test]
fn nft_rules_non_default_runner_name_snapshot() {
    // Byte-exact pin for runner_name interpolation across 7+ sites:
    // `table inet ghars_NAME`, `iifname "ghars-NAME-h"` +
    // `iifname "ghars-NAME-r"`, `oifname "ghars-NAME-*"` masquerade
    // exclusion, log prefix `"ghars-NAME drop: "` +
    // `"ghars-NAME ns-drop: "` + `"ghars-NAME ns-in-drop: "`, and
    // the ns-side table `ghars_NAME_ns`. Existing nft fixtures use
    // runner_name="buckos". A regression that hardcoded the
    // literal at any of the 7+ sites would not surface in current
    // fixtures.
    let binding = EffectiveNetworkBinding {
        name: "wkr-2".into(),
        spec: NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![],
            ip_deny: vec![],
            restrict_address_families: vec![],
            dns: DnsMode::Forward,
            ipv6: Ipv6Mode::Disabled,
        },
        subnet: Some("10.200.0.0/30".parse::<IpNet>().unwrap()),
    };
    let rules = render_nft_rules("wkr-2", &binding).unwrap();
    insta::assert_snapshot!("nft_rules_non_default_runner_name_host", rules.host_rules);
    insta::assert_snapshot!("nft_rules_non_default_runner_name_ns", rules.ns_rules);
}

/// Regression pin for the `.snap.new`-hand-rename anti-pattern.
///
/// `insta`'s `trim_for_persistence` (snapshot.rs:307-322) strips the
/// `assertion_line:` metadata field from `.snap` files written via the
/// canonical `save()` path (snapshot.rs:560-564) — `insta`'s explicit
/// intent is "those we only use for display while reviewing". A
/// `.snap` file with the `assertion_line:` header indicates someone
/// hand-renamed `.snap.new` → `.snap` (bypassing `cargo insta accept`,
/// which round-trips through `save()`), an older `insta` version
/// without the trim, or a build script that bypassed `save()`. The
/// per-snap header drifts on the next test reorder because nothing
/// rewrites it, producing confusing `cargo insta show` jump-to-source
/// behavior.
///
/// This test fails fast on the anti-pattern so a stale
/// `.snap`-with-`assertion_line:` cannot land or persist undetected.
/// Sister to the `.snap.new`-in-tree CI gate, but at the test layer
/// (catches locally before push).
#[test]
fn snap_files_must_not_carry_assertion_line_header() {
    // CARGO_MANIFEST_DIR is the crate root at compile time — deterministic
    // regardless of test runner cwd. Avoids the silent-misdetect class
    // where a workspace-member sub-Cargo invocation lands cwd elsewhere
    // and `read_dir("tests/snapshots")` errors with a misleading message.
    let snap_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots");
    let entries =
        std::fs::read_dir(&snap_dir).expect("tests/snapshots/ directory must be readable");
    let mut violations: Vec<String> = Vec::new();
    for entry in entries {
        let path = entry.expect("snap dir entry must be readable").path();
        if path.extension().is_none_or(|e| e != "snap") {
            continue;
        }
        let content = std::fs::read_to_string(&path).expect("snap file must be readable");
        // Scope the scan to the YAML frontmatter (between the first and
        // second `---` delimiters). Body lines after the closing `---`
        // are operator-snapshot content and could legitimately start
        // with `assertion_line:` (a config-file fragment, log line,
        // etc.) without indicating an insta-metadata anti-pattern.
        let mut in_frontmatter = false;
        let mut frontmatter_closed = false;
        for (idx, line) in content.lines().enumerate() {
            if frontmatter_closed {
                break;
            }
            if line.trim() == "---" {
                if in_frontmatter {
                    frontmatter_closed = true;
                } else {
                    in_frontmatter = true;
                }
                continue;
            }
            if in_frontmatter && line.trim_start().starts_with("assertion_line:") {
                violations.push(format!(
                    "{}:{}",
                    path.file_name()
                        .expect("snap path must have a basename")
                        .to_string_lossy(),
                    idx + 1
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "\n\n.snap files carrying `assertion_line:` header (canonical \
         `insta` save path strips this field — its presence indicates \
         a `.snap.new` → `.snap` hand-rename or a stale older-`insta` \
         artifact). Delete the line from each file; the header is \
         metadata-only and the canonical `insta` save path strips it \
         via `trim_for_persistence` (snapshot.rs:307-322). \
         Violations:\n  {}\n",
        violations.join("\n  ")
    );
}
