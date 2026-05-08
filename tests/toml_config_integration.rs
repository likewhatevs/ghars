//! Integration tests for TOML config parsing — round-trip via the
//! `Config` serde derives. The library exposes `config::load` as a
//! `todo!()` placeholder pending B1 wiring; these tests use
//! `toml::from_str::<Config>()` directly, which is the implementation
//! the loader will eventually call. They verify the schema accepts the
//! shapes documented in Part 4 and rejects malformed shapes via the
//! `deny_unknown_fields` discipline.
//!
//! These are END-TO-END tests of the schema layer in the sense that
//! they consume operator-authored TOML and assert what `Config` looks
//! like after parsing. Plan-time validation (unknown auth refs, etc.)
//! runs separately in `plan_engine_integration.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ghars::config::{
    Arch, AuthSpec, CacheKind, CacheMode, Config, EtcBindStyle, NetworkMode, PortSpec, Proto,
};

fn parse(toml_text: &str) -> Result<Config, toml::de::Error> {
    toml::from_str::<Config>(toml_text)
}

#[test]
fn minimal_config_with_one_runner_round_trips() {
    let text = r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "buckos"
url = "https://github.com/example/buckos"
auth = "pat"
"#;
    let cfg = parse(text).unwrap();
    assert_eq!(cfg.runners.len(), 1);
    assert_eq!(cfg.runners[0].name, "buckos");
    assert_eq!(cfg.runners[0].url, "https://github.com/example/buckos");
    assert_eq!(cfg.runners[0].auth.as_deref(), Some("pat"));
    assert_eq!(cfg.auth.len(), 1);
    assert!(matches!(
        cfg.auth.get("pat"),
        Some(AuthSpec::Pat {
            token_env: Some(_),
            token_file: None,
        })
    ));
}

#[test]
fn defaults_block_parses_and_propagates_through_serde() {
    let text = r#"
[defaults]
runner_version = "2.334.0"
labels = ["self-hosted", "linux"]
arch = "x86_64"

[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "buckos"
url = "https://github.com/example/buckos"
auth = "pat"
"#;
    let cfg = parse(text).unwrap();
    assert_eq!(cfg.defaults.runner_version.as_deref(), Some("2.334.0"));
    assert_eq!(cfg.defaults.labels, vec!["self-hosted", "linux"]);
    assert_eq!(cfg.defaults.arch, Some(Arch::X86_64));
}

#[test]
fn auth_kind_pat_with_token_env() {
    let text = r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"
"#;
    let cfg = parse(text).unwrap();
    let auth = cfg.auth.get("pat").unwrap();
    assert!(matches!(
        auth,
        AuthSpec::Pat {
            token_env: Some(_),
            token_file: None
        }
    ));
}

#[test]
fn auth_kind_pat_with_token_file() {
    let text = r#"
[auth.pat]
kind = "pat"
token_file = "/etc/ghars/pat.token"
"#;
    let cfg = parse(text).unwrap();
    let auth = cfg.auth.get("pat").unwrap();
    assert!(matches!(
        auth,
        AuthSpec::Pat {
            token_env: None,
            token_file: Some(_)
        }
    ));
}

#[test]
fn auth_kind_github_app_parses() {
    let text = r#"
[auth.app]
kind = "github_app"
app_id = 12345
installation_id = 67890
private_key_path = "/etc/ghars/app.pem"
"#;
    let cfg = parse(text).unwrap();
    let auth = cfg.auth.get("app").unwrap();
    match auth {
        AuthSpec::GithubApp {
            app_id,
            installation_id,
            private_key_path,
        } => {
            assert_eq!(*app_id, 12345);
            assert_eq!(*installation_id, 67890);
            assert_eq!(private_key_path.as_str(), "/etc/ghars/app.pem");
        }
        other => panic!("expected GithubApp, got {other:?}"),
    }
}

#[test]
fn auth_kind_interactive() {
    let text = r#"
[auth.tty]
kind = "interactive"
"#;
    let cfg = parse(text).unwrap();
    assert!(matches!(cfg.auth.get("tty"), Some(AuthSpec::Interactive)));
}

#[test]
fn auth_kind_token_file() {
    let text = r#"
[auth.tf]
kind = "token_file"
path = "/etc/ghars/registration.token"
"#;
    let cfg = parse(text).unwrap();
    match cfg.auth.get("tf").unwrap() {
        AuthSpec::TokenFile { path } => {
            assert_eq!(path.as_str(), "/etc/ghars/registration.token");
        }
        other => panic!("expected TokenFile, got {other:?}"),
    }
}

#[test]
fn cache_pool_with_both_kinds_size_and_default_mode() {
    let text = r#"
[cache_pools.build]
kinds = ["ccache", "sccache"]
size = "200G"
"#;
    let cfg = parse(text).unwrap();
    let pool = cfg.cache_pools.get("build").unwrap();
    assert_eq!(pool.kinds, vec![CacheKind::Ccache, CacheKind::Sccache]);
    assert_eq!(pool.size, "200G");
    assert_eq!(pool.mode, CacheMode::Shared);
    assert_eq!(pool.trust_zone, "default");
}

#[test]
fn cache_pool_isolated_mode_and_explicit_trust_zone() {
    let text = r#"
[cache_pools.private]
kinds = ["sccache"]
size = "50G"
mode = "isolated"
trust_zone = "secrets"
"#;
    let cfg = parse(text).unwrap();
    let pool = cfg.cache_pools.get("private").unwrap();
    assert_eq!(pool.mode, CacheMode::Isolated);
    assert_eq!(pool.trust_zone, "secrets");
}

#[test]
fn network_with_egress_rules_parses_with_proto_default() {
    let text = r#"
[network.isolated]
mode = "netns"
allowed_egress = [
    { addr = "192.168.2.84", port = 3128 },
    { addr = "1.1.1.1", port = 53, proto = "udp" },
    { addr = "10.0.0.0/8", port = { start = 1024, end = 2048 } },
    { addr = "8.8.8.8", port = [80, 443], proto = "both", comment = "google" },
]
"#;
    let cfg = parse(text).unwrap();
    let net = cfg.networks.get("isolated").unwrap();
    assert_eq!(net.mode, NetworkMode::Netns);
    assert_eq!(net.allowed_egress.len(), 4);
    assert_eq!(net.allowed_egress[0].port, PortSpec::Single(3128));
    assert_eq!(net.allowed_egress[0].proto, Proto::Tcp);
    assert_eq!(net.allowed_egress[1].proto, Proto::Udp);
    assert!(matches!(net.allowed_egress[2].port, PortSpec::Range { .. }));
    assert!(matches!(net.allowed_egress[3].port, PortSpec::Set(_)));
    assert_eq!(net.allowed_egress[3].proto, Proto::Both);
    assert_eq!(net.allowed_egress[3].comment.as_deref(), Some("google"));
}

#[test]
fn proxy_section_parses_with_ca_cert_bindings() {
    let text = r#"
[proxy]
http = "http://192.168.2.84:3128"
https = "http://192.168.2.84:3128"
no_proxy = ["192.168.2.84", "localhost"]
ca_certs = [
    { env = "REQUESTS_CA_BUNDLE", path = "/etc/pki/tls/certs/ca-bundle.crt" },
    { env = "NODE_EXTRA_CA_CERTS", path = "/etc/pki/tls/certs/ca-bundle.crt" },
]
"#;
    let cfg = parse(text).unwrap();
    let proxy = cfg.proxy.unwrap();
    assert_eq!(proxy.http.as_deref(), Some("http://192.168.2.84:3128"));
    assert_eq!(proxy.https.as_deref(), Some("http://192.168.2.84:3128"));
    assert_eq!(proxy.no_proxy, vec!["192.168.2.84", "localhost"]);
    assert_eq!(proxy.ca_certs.len(), 2);
    assert_eq!(proxy.ca_certs[0].env, "REQUESTS_CA_BUNDLE");
    assert_eq!(
        proxy.ca_certs[0].path.as_str(),
        "/etc/pki/tls/certs/ca-bundle.crt"
    );
}

#[test]
fn hooks_section_parses_with_pre_and_post_paths() {
    let text = r#"
[hooks]
pre_job = "/opt/gha/hooks/pre.sh"
post_job = "/opt/gha/hooks/post.sh"
"#;
    let cfg = parse(text).unwrap();
    let hooks = cfg.hooks.unwrap();
    assert_eq!(hooks.pre_job.unwrap().as_str(), "/opt/gha/hooks/pre.sh");
    assert_eq!(hooks.post_job.unwrap().as_str(), "/opt/gha/hooks/post.sh");
}

#[test]
fn runner_count_block_parses() {
    let text = r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "ci"
count = 3
url = "https://github.com/example/repo"
auth = "pat"
"#;
    let cfg = parse(text).unwrap();
    assert_eq!(cfg.runners[0].count, Some(3));
}

#[test]
fn full_realistic_config_parses() {
    // A more realistic config covering most schema surface in one TOML
    // file. Tracks the example in Part 4.
    let text = r#"
[defaults]
runner_version = "2.334.0"
labels = ["self-hosted", "linux"]

[defaults.hardening]
kvm = true
restrict_realtime = false
etc_bind_style = "broad"
extra_syscalls = ["clone3", "rseq"]

[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[cache_pools.build]
kinds = ["ccache", "sccache"]
size = "200G"

[network.isolated]
mode = "netns"
allowed_egress = [
    { addr = "192.168.2.84", port = 3128, comment = "proxy" },
]

[proxy]
http = "http://192.168.2.84:3128"
https = "http://192.168.2.84:3128"

[[runner]]
name = "buckos"
url = "https://github.com/example/buckos"
auth = "pat"
caches = ["build"]
network = "isolated"
memory_max = "110G"

[[runner]]
name = "ci"
count = 4
url = "https://github.com/example/ci"
auth = "pat"
"#;
    let cfg = parse(text).unwrap();
    assert_eq!(cfg.runners.len(), 2);
    assert_eq!(cfg.runners[0].name, "buckos");
    assert_eq!(cfg.runners[0].caches, vec!["build"]);
    assert_eq!(cfg.runners[0].network.as_deref(), Some("isolated"));
    assert_eq!(cfg.runners[0].memory_max.as_deref(), Some("110G"));
    assert_eq!(cfg.runners[1].count, Some(4));

    // Defaults hardening flowed through the deny_unknown_fields gate.
    assert_eq!(cfg.defaults.hardening.kvm, Some(true));
    assert_eq!(cfg.defaults.hardening.restrict_realtime, Some(false));
    assert_eq!(cfg.defaults.hardening.etc_bind_style, EtcBindStyle::Broad);
    assert_eq!(
        cfg.defaults.hardening.extra_syscalls,
        vec!["clone3", "rseq"]
    );
}

// -- Invalid configs: schema must reject ----------------------------------

#[test]
fn rejects_unknown_top_level_key() {
    let text = r#"
[defaults]
runner_version = "2.334.0"

[bogus]
key = "value"
"#;
    let err = parse(text).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("bogus") || msg.contains("unknown"),
        "got: {msg}"
    );
}

#[test]
fn rejects_unknown_runner_field() {
    let text = r#"
[[runner]]
name = "buckos"
url = "https://github.com/example/buckos"
auth = "pat"
typo_field = "should-fail"
"#;
    let err = parse(text).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("typo_field") || msg.contains("unknown"));
}

#[test]
fn rejects_unknown_defaults_field() {
    let text = r#"
[defaults]
not_a_real_field = "bad"
"#;
    let err = parse(text).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("not_a_real_field") || msg.contains("unknown"));
}

#[test]
fn rejects_unknown_hardening_field() {
    let text = r"
[defaults.hardening]
made_up = true
";
    let err = parse(text).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("made_up") || msg.contains("unknown"));
}

#[test]
fn rejects_invalid_arch_enum_value() {
    let text = r#"
[defaults]
arch = "riscv64"
"#;
    let err = parse(text).unwrap_err();
    let msg = format!("{err}");
    // serde error: variant or expected one of
    assert!(
        msg.contains("riscv64") || msg.contains("variant") || msg.contains("expected"),
        "got: {msg}"
    );
}

#[test]
fn rejects_invalid_network_mode() {
    let text = r#"
[network.iso]
mode = "container"
"#;
    let err = parse(text).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("container") || msg.contains("variant"));
}

#[test]
fn rejects_invalid_cache_kind() {
    let text = r#"
[cache_pools.build]
kinds = ["ccache", "weird"]
size = "200G"
"#;
    let err = parse(text).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("weird") || msg.contains("variant"));
}

#[test]
fn rejects_invalid_egress_proto() {
    let text = r#"
[network.iso]
mode = "netns"
allowed_egress = [
    { addr = "1.1.1.1", port = 53, proto = "icmp" },
]
"#;
    let err = parse(text).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("icmp") || msg.contains("variant"));
}

#[test]
fn rejects_invalid_auth_kind() {
    let text = r#"
[auth.bad]
kind = "oauth"
"#;
    let err = parse(text).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("oauth") || msg.contains("variant"));
}

#[test]
fn rejects_invalid_etc_bind_style() {
    let text = r#"
[defaults.hardening]
etc_bind_style = "minimal"
"#;
    let err = parse(text).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("minimal") || msg.contains("variant"));
}

#[test]
fn rejects_proxy_with_unknown_field() {
    let text = r#"
[proxy]
http = "http://x"
unknown = true
"#;
    let err = parse(text).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("unknown"));
}

// -- [network.NAME] field parsing + post-load validation -----------------
//
// `parse()` only exercises serde's deny_unknown_fields gate. The
// mode-scoped invariants (Open rejects allowed_egress / non-Forward dns /
// ipv6=enabled; Netns requires egress-or-ip_allow) live in
// `validators::validate_network_spec`, which `cli::load_config` runs
// after parse. The tests below combine `parse() + validate_network_spec`
// to mirror the load-config gate end-to-end without needing a full
// CLI invocation.

#[test]
fn network_block_parses_with_cgroup_bpf_fields() {
    // Full `[network.NAME]` block with every cgroup-BPF policy field
    // populated. Round-trips cleanly through serde and validates.
    let text = r#"
[network.isolated]
mode = "netns"
allowed_egress = [
    { addr = "10.0.0.1", port = 443, proto = "tcp" },
]
ip_allow = ["10.0.0.0/8", "192.0.2.0/24"]
ip_deny = ["0.0.0.0/0"]
restrict_address_families = ["AF_UNIX", "AF_INET", "AF_INET6"]
"#;
    let cfg = parse(text).unwrap();
    let spec = cfg
        .networks
        .get("isolated")
        .expect("[network.isolated] must parse");
    assert!(matches!(spec.mode, NetworkMode::Netns));
    assert_eq!(spec.ip_allow.len(), 2);
    assert_eq!(spec.ip_deny.len(), 1);
    assert_eq!(
        spec.restrict_address_families,
        vec!["AF_UNIX", "AF_INET", "AF_INET6"]
    );
    // Validates cleanly under the post-load gate.
    ghars::validators::validate_network_spec(spec).expect("valid network spec must pass");
}

#[test]
fn network_open_block_rejects_allowed_egress_at_validate_time() {
    // serde parse passes (the field exists on `NetworkSpec`), but
    // post-load validation rejects: nft rules are netns-only, so an
    // operator who put `allowed_egress` on `mode = "open"` is in a
    // silent-partial-enforcement shape.
    let text = r#"
[network.host-policy]
mode = "open"
allowed_egress = [
    { addr = "10.0.0.1", port = 443, proto = "tcp" },
]
"#;
    let cfg = parse(text).expect("TOML parses (shape is valid)");
    let spec = cfg
        .networks
        .get("host-policy")
        .expect("[network.host-policy] must parse");
    let err = ghars::validators::validate_network_spec(spec)
        .expect_err("Open + allowed_egress must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("allowed_egress requires mode = netns"),
        "msg must name the rule: {msg}"
    );
}

#[test]
fn network_open_block_with_cgroup_bpf_parses_and_validates() {
    // The motivating shape for this work: an `[network.NAME]` block
    // with `mode = "open"` carrying `ip_deny` (and friends) MUST parse
    // cleanly AND pass validation. The cgroup-BPF directives apply at
    // the cgroup layer regardless of namespace, so neither the
    // serde-shape gate nor the mode-scoped post-load gate rejects.
    let text = r#"
[network.host-policy]
mode = "open"
ip_allow = ["10.0.0.0/8"]
ip_deny = ["0.0.0.0/0"]
restrict_address_families = ["AF_INET", "AF_INET6"]
"#;
    let cfg = parse(text).unwrap();
    let spec = cfg
        .networks
        .get("host-policy")
        .expect("[network.host-policy] must parse");
    assert!(matches!(spec.mode, NetworkMode::Open));
    assert_eq!(spec.ip_allow.len(), 1);
    assert_eq!(spec.ip_deny.len(), 1);
    assert_eq!(spec.restrict_address_families, vec!["AF_INET", "AF_INET6"]);
    ghars::validators::validate_network_spec(spec).expect("Open + cgroup-BPF policy must validate");
}

#[test]
fn network_open_block_rejects_static_dns_at_validate_time() {
    // `DnsMode::Static` is netns-only — open-mode runners inherit
    // the host's `/etc/resolv.conf`. The TOML serde encoding for
    // `DnsMode` is `tag = "mode", content = "servers"`, so the
    // Rust API path is the cleanest way to construct a Static
    // variant for this unit-style integration check; the parse
    // path is exercised separately in the round-trip tests above.
    use ghars::config::DnsMode;
    let mut spec = ghars::config::NetworkSpec {
        mode: NetworkMode::Open,
        allowed_egress: vec![],
        ip_allow: vec!["10.0.0.0/8".parse().unwrap()],
        ip_deny: vec![],
        restrict_address_families: vec![],
        dns: DnsMode::default(),
        ipv6: ghars::config::Ipv6Mode::default(),
    };
    spec.dns = DnsMode::Static {
        servers: vec!["1.1.1.1".parse().unwrap()],
    };
    let err =
        ghars::validators::validate_network_spec(&spec).expect_err("Open + static dns must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("dns requires mode = netns"),
        "msg must name the rule: {msg}"
    );
}

#[test]
fn network_open_block_rejects_ipv6_enabled_at_validate_time() {
    // ipv6 = "enabled" is a netns ULA-allocation artifact — open-mode
    // runners share the host's IPv6 stack.
    let text = r#"
[network.host-policy]
mode = "open"
ip_allow = ["10.0.0.0/8"]
ipv6 = "enabled"
"#;
    let cfg = parse(text).unwrap();
    let spec = cfg.networks.get("host-policy").unwrap();
    let err = ghars::validators::validate_network_spec(spec)
        .expect_err("Open + ipv6 = enabled must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("ipv6 = enabled requires mode = netns"),
        "msg must name the rule: {msg}"
    );
}

#[test]
fn network_block_rejects_malformed_af_token_at_validate_time() {
    // Per-entry AF_* shape gate: lowercase / typos / missing prefix
    // fail at validate time with a structured "not a valid AF_* token"
    // message before reaching systemd's opaque unit-load rejection.
    // Pin both Netns and Open so the shape gate runs in both
    // mode-scoped paths.
    let text_netns = r#"
[network.isolated]
mode = "netns"
ip_allow = ["10.0.0.0/8"]
restrict_address_families = ["AF_UNIX", "af_inet"]
"#;
    let cfg = parse(text_netns).unwrap();
    let spec = cfg.networks.get("isolated").unwrap();
    let err = ghars::validators::validate_network_spec(spec)
        .expect_err("malformed AF_* token must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a valid AF_* token"),
        "msg must name the violation: {msg}"
    );
    assert!(msg.contains("\"af_inet\""), "msg must quote token: {msg}");

    let text_open = r#"
[network.host-policy]
mode = "open"
restrict_address_families = ["INET6"]
"#;
    let cfg = parse(text_open).unwrap();
    let spec = cfg.networks.get("host-policy").unwrap();
    let err = ghars::validators::validate_network_spec(spec)
        .expect_err("malformed AF_* token must reject under Open too");
    let msg = format!("{err}");
    assert!(msg.contains("\"INET6\""), "msg must quote token: {msg}");
}

#[test]
fn network_open_block_with_empty_policy_parses() {
    // Empty Open block parses (no shape error). Validation passes
    // (all fields default-empty). The plan-time collapse to None
    // happens in `lower_to_effective`, not at TOML parse / validate
    // time — so this test pins the parse + validate seams ONLY,
    // mirroring what `load_config` sees.
    let text = r#"
[network.empty-open]
mode = "open"
"#;
    let cfg = parse(text).unwrap();
    let spec = cfg.networks.get("empty-open").unwrap();
    assert!(matches!(spec.mode, NetworkMode::Open));
    assert!(spec.allowed_egress.is_empty());
    assert!(spec.ip_allow.is_empty());
    assert!(spec.ip_deny.is_empty());
    assert!(spec.restrict_address_families.is_empty());
    ghars::validators::validate_network_spec(spec).expect("empty Open block must pass validation");
}

#[test]
fn network_block_rejects_address_families_field_renamed() {
    // After the rename, `address_families` is no longer a known
    // field; serde's deny_unknown_fields rejects it at parse time.
    // This pins the rename so a future regression that re-adds the
    // alias as a serde rename is caught.
    let text = r#"
[network.isolated]
mode = "netns"
ip_allow = ["10.0.0.0/8"]
address_families = ["AF_UNIX"]
"#;
    let err = parse(text).expect_err("address_families is not a valid field");
    let msg = format!("{err}");
    assert!(
        msg.contains("address_families") || msg.contains("unknown"),
        "msg must name the unknown field: {msg}"
    );
}
