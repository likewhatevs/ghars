//! Plan engine end-to-end tests with full TOML fixtures.
//!
//! Each test loads a realistic `ghars.toml` fixture (parsed via
//! `toml::from_str::<Config>`), runs `plan_from` against
//! `ActualState::default()` (empty host), and verifies the action list.
//! Mirrors the Python tool's plan-driven configs translated to ghars's
//! TOML schema.
//!
//! Coverage:
//! - Single runner, default config — one `CreateRunner` action.
//! - Single runner with cache pool reference — Create cache pool +
//!   Create runner; ordering verified by `sort_into_phases` (apply layer)
//!   not `plan_from` output.
//! - Single runner with netns network — netns binding flows into
//!   `EffectiveNetworkBinding`; subnet allocated per /30.
//! - Multi-runner config (3 explicit + count=4) — 7 `CreateRunner`
//!   actions, all unique names.
//! - Auto-skip across explicit collision — count="ci"/3 + explicit
//!   "ci-2" produces ci-1, ci-2 (explicit), ci-3 only.
//! - Defaults flow into per-runner specs.
//! - Auth + cache + network cross-references resolve correctly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ghars::config::{AuthSpec, Config, NetworkMode};
use ghars::paths::Paths;
use ghars::plan::{Action, plan_from};
use ghars::state::ActualState;

fn parse(toml_text: &str) -> Config {
    toml::from_str::<Config>(toml_text).unwrap_or_else(|e| panic!("parse failed: {e}\n{toml_text}"))
}

fn run(cfg: &Config) -> ghars::plan::Plan {
    plan_from(cfg, &ActualState::default(), &Paths::default())
        .unwrap_or_else(|e| panic!("plan_from failed: {e}"))
}

fn create_runner_names(plan: &ghars::plan::Plan) -> Vec<String> {
    plan.actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateRunner(p) => Some(p.spec.name.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn single_runner_minimal_config() {
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "buckos"
url = "https://github.com/example/buckos"
auth = "pat"
"#,
    );
    let plan = run(&cfg);
    let creates = create_runner_names(&plan);
    assert_eq!(creates, vec!["buckos"]);
    // No cache pool referenced → no CreateCachePool actions.
    let pool_creates: Vec<_> = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::CreateCachePool(_)))
        .collect();
    assert!(pool_creates.is_empty());
}

#[test]
fn single_runner_with_cache_pool() {
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[cache_pools.build]
kinds = ["ccache", "sccache"]
size = "200G"
# Pin sccache_path so the test does not depend on a real
# /usr/local/bin or /usr/bin install of the sccache binary.
sccache_path = "/usr/bin/sccache"

[[runner]]
name = "buckos"
url = "https://github.com/example/buckos"
auth = "pat"
caches = ["build"]
"#,
    );
    let plan = run(&cfg);
    // 1 runner + 1 cache pool.
    let creates = create_runner_names(&plan);
    assert_eq!(creates, vec!["buckos"]);
    let pool_names: Vec<String> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateCachePool(p) => Some(p.binding.name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(pool_names, vec!["build"]);
    // Verify caches resolved correctly into the runner spec.
    let runner_create = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!(runner_create.spec.caches.len(), 1);
    assert_eq!(runner_create.spec.caches[0].name, "build");
}

#[test]
fn single_runner_with_netns_resolves_binding() {
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[network.isolated]
mode = "netns"
allowed_egress = [
    { addr = "192.168.2.84", port = 3128, comment = "proxy" },
]

[[runner]]
name = "buckos"
url = "https://github.com/example/buckos"
auth = "pat"
network = "isolated"
"#,
    );
    let plan = run(&cfg);
    let runner = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) => Some(p),
            _ => None,
        })
        .unwrap();
    // Network binding resolved and stamped on the spec.
    let binding = runner.spec.network.as_ref().unwrap();
    assert_eq!(binding.name, "isolated");
    assert!(matches!(binding.spec.mode, NetworkMode::Netns));
    assert_eq!(binding.spec.allowed_egress.len(), 1);
    assert_eq!(binding.spec.allowed_egress[0].addr, "192.168.2.84");
    assert_eq!(
        binding.spec.allowed_egress[0].comment.as_deref(),
        Some("proxy")
    );
}

#[test]
fn multi_explicit_runners_with_count_block() {
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "alpha"
url = "https://github.com/example/alpha"
auth = "pat"

[[runner]]
name = "ci"
count = 4
url = "https://github.com/example/ci"
auth = "pat"

[[runner]]
name = "zebra"
url = "https://github.com/example/zebra"
auth = "pat"
"#,
    );
    let plan = run(&cfg);
    let mut creates = create_runner_names(&plan);
    creates.sort();
    let mut expected = vec![
        "alpha".to_string(),
        "ci-1".into(),
        "ci-2".into(),
        "ci-3".into(),
        "ci-4".into(),
        "zebra".into(),
    ];
    expected.sort();
    assert_eq!(creates, expected);
}

#[test]
fn count_block_auto_skips_explicit_collision() {
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "ci"
count = 5
url = "https://github.com/example/ci"
auth = "pat"

[[runner]]
name = "ci-2"
url = "https://github.com/example/ci-2-special"
auth = "pat"
memory_max = "32G"
"#,
    );
    let plan = run(&cfg);
    let mut creates = create_runner_names(&plan);
    creates.sort();
    let mut expected = vec![
        "ci-1".to_string(),
        "ci-2".into(),
        "ci-3".into(),
        "ci-4".into(),
        "ci-5".into(),
    ];
    expected.sort();
    assert_eq!(creates, expected);
    // ci-2 carries the explicit override; the count-block expansions
    // do not.
    let ci2 = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) if p.spec.name == "ci-2" => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!(ci2.spec.memory_max.as_deref(), Some("32G"));
    assert!(ci2.spec.url.contains("ci-2-special"));
    // The count-block ci-1, ci-3, ci-4, ci-5 do NOT carry memory_max.
    for name in ["ci-1", "ci-3", "ci-4", "ci-5"] {
        let r = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::CreateRunner(p) if p.spec.name == name => Some(p),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            r.spec.memory_max, None,
            "count-block runner {name} got memory_max override"
        );
    }
}

#[test]
fn defaults_flow_into_each_runner() {
    let cfg = parse(
        r#"
[defaults]
runner_version = "2.334.0"
labels = ["self-hosted", "linux"]

[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "alpha"
url = "https://github.com/example/alpha"
auth = "pat"
labels = ["alpha-tag"]

[[runner]]
name = "beta"
url = "https://github.com/example/beta"
auth = "pat"
"#,
    );
    let plan = run(&cfg);
    for name in ["alpha", "beta"] {
        let r = plan
            .actions
            .iter()
            .find_map(|a| match a {
                Action::CreateRunner(p) if p.spec.name == name => Some(p),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing {name}"));
        // defaults.runner_version → spec.runner_version.
        assert_eq!(r.spec.runner_version.as_deref(), Some("2.334.0"));
        // defaults.labels concatenated with runner.labels (and deduped
        // in source order).
        assert!(r.spec.labels.contains(&"self-hosted".to_string()));
        assert!(r.spec.labels.contains(&"linux".to_string()));
    }
    // Alpha additionally has its own label.
    let alpha = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) if p.spec.name == "alpha" => Some(p),
            _ => None,
        })
        .unwrap();
    assert!(alpha.spec.labels.contains(&"alpha-tag".to_string()));
}

#[test]
fn auth_cross_reference_resolves() {
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[auth.app]
kind = "github_app"
app_id = 12345
installation_id = 67890
private_key_path = "/etc/ghars/app.pem"

[[runner]]
name = "with-pat"
url = "https://github.com/example/with-pat"
auth = "pat"

[[runner]]
name = "with-app"
url = "https://github.com/example/with-app"
auth = "app"
"#,
    );
    let plan = run(&cfg);
    let with_pat = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) if p.spec.name == "with-pat" => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!(with_pat.spec.auth_name, "pat");
    let with_app = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) if p.spec.name == "with-app" => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!(with_app.spec.auth_name, "app");
    // Auth registry contents reflect both kinds.
    assert!(matches!(cfg.auth.get("pat"), Some(AuthSpec::Pat { .. })));
    assert!(matches!(
        cfg.auth.get("app"),
        Some(AuthSpec::GithubApp { .. })
    ));
}

#[test]
fn realistic_full_config_parses_and_plans() {
    // Mirrors the Part 4 example: defaults + multiple auth + cache pool
    // + netns + proxy + 2 runners (1 explicit, 1 count=4).
    let cfg = parse(
        r#"
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
sccache_path = "/usr/bin/sccache"

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
"#,
    );
    let plan = run(&cfg);
    // 1 + 4 = 5 runners; one cache pool.
    let mut creates = create_runner_names(&plan);
    creates.sort();
    let mut expected = vec![
        "buckos".to_string(),
        "ci-1".into(),
        "ci-2".into(),
        "ci-3".into(),
        "ci-4".into(),
    ];
    expected.sort();
    assert_eq!(creates, expected);

    let pools: Vec<String> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateCachePool(p) => Some(p.binding.name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(pools, vec!["build"]);

    // Buckos carries the network + cache + memory_max + labels merged
    // through defaults.
    let buckos = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) if p.spec.name == "buckos" => Some(p),
            _ => None,
        })
        .unwrap();
    assert!(buckos.spec.network.is_some());
    assert_eq!(buckos.spec.caches.len(), 1);
    assert_eq!(buckos.spec.memory_max.as_deref(), Some("110G"));
    assert!(buckos.spec.labels.contains(&"self-hosted".to_string()));
    assert!(buckos.spec.proxy.is_some());

    // ci-N runners do NOT carry caches / network / memory_max because
    // those weren't set on the count block.
    let ci1 = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::CreateRunner(p) if p.spec.name == "ci-1" => Some(p),
            _ => None,
        })
        .unwrap();
    assert!(ci1.spec.caches.is_empty());
    assert!(ci1.spec.network.is_none());
    assert_eq!(ci1.spec.memory_max, None);
}

#[test]
fn unknown_auth_reference_errors() {
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "broken"
url = "https://github.com/example/broken"
auth = "missing-key"
"#,
    );
    let err = plan_from(&cfg, &ActualState::default(), &Paths::default()).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("auth") && msg.contains("missing-key"),
        "expected unknown-auth error: {msg}"
    );
}

#[test]
fn unknown_cache_pool_reference_errors() {
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[cache_pools.build]
kinds = ["ccache"]
size = "200G"

[[runner]]
name = "broken"
url = "https://github.com/example/broken"
auth = "pat"
caches = ["nonexistent-pool"]
"#,
    );
    let err = plan_from(&cfg, &ActualState::default(), &Paths::default()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("cache") || msg.contains("nonexistent-pool"));
}

#[test]
fn multi_sccache_pool_binding_rejected_at_plan_time() {
    // sccache supports only ONE server UDS per process, so a runner
    // bound to 2+ sccache pools would have its
    // SCCACHE_SERVER_UDS / SCCACHE_CACHE_SIZE clobbered last-writer-
    // wins in the rendered drop-in (systemd.exec(5) directive
    // semantics). All but one pool would be silently unreachable
    // from the runner. Plan-time rejection points the operator at
    // the three viable remediations: split into multiple runners,
    // merge the pools, or downgrade all-but-one to ccache-only
    // (filesystem mode is multi-bind safe).
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[cache_pools.build]
kinds = ["sccache"]
size = "200G"
sccache_path = "/usr/bin/sccache"

[cache_pools.test]
kinds = ["sccache"]
size = "100G"
sccache_path = "/usr/bin/sccache"

[[runner]]
name = "multi"
url = "https://github.com/example/multi"
auth = "pat"
caches = ["build", "test"]
"#,
    );
    let err = plan_from(&cfg, &ActualState::default(), &Paths::default()).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("sccache pools"),
        "msg must name the directive: {msg}"
    );
    assert!(
        msg.contains("clobbered") || msg.contains("last-writer-wins"),
        "msg must explain the clobber: {msg}"
    );
    // Both offending pool names appear in the error so the
    // operator knows which to split / merge / downgrade.
    assert!(msg.contains("build"), "must name pool 'build': {msg}");
    assert!(msg.contains("test"), "must name pool 'test': {msg}");
}

#[test]
fn unified_cache_pool_with_sccache_plus_ccache_pool_does_not_double_count() {
    // Defense in depth: the multi-sccache check counts pools whose
    // `kinds` LIST contains Sccache, not pools whose ONLY kind is
    // Sccache. A `kinds = ["sccache", "ccache"]` unified pool is
    // ONE sccache server, so binding ONE such pool plus a
    // ccache-only pool must NOT trigger rejection.
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[cache_pools.unified]
kinds = ["sccache", "ccache"]
size = "200G"
sccache_path = "/usr/bin/sccache"

[cache_pools.fsonly]
kinds = ["ccache"]
size = "100G"

[[runner]]
name = "ok"
url = "https://github.com/example/ok"
auth = "pat"
caches = ["unified", "fsonly"]
"#,
    );
    plan_from(&cfg, &ActualState::default(), &Paths::default())
        .expect("one sccache pool + one ccache-only pool must NOT reject");
}

#[test]
fn unknown_network_reference_errors() {
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[network.real-net]
mode = "netns"
allowed_egress = [{ addr = "1.1.1.1", port = 53 }]

[[runner]]
name = "broken"
url = "https://github.com/example/broken"
auth = "pat"
network = "no-such-network"
"#,
    );
    let err = plan_from(&cfg, &ActualState::default(), &Paths::default()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("network") || msg.contains("no-such-network"));
}

#[test]
fn empty_config_produces_empty_plan() {
    let cfg = parse(""); // empty TOML — no auth, no runners
    let plan = run(&cfg);
    assert!(plan.actions.is_empty());
}

#[test]
fn multiple_pools_referenced_dedupes_to_unique_creates() {
    let cfg = parse(
        r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[cache_pools.build]
kinds = ["ccache"]
size = "200G"

[cache_pools.test]
kinds = ["sccache"]
size = "100G"
sccache_path = "/usr/bin/sccache"

[[runner]]
name = "alpha"
url = "https://github.com/example/alpha"
auth = "pat"
caches = ["build", "test"]

[[runner]]
name = "beta"
url = "https://github.com/example/beta"
auth = "pat"
caches = ["build"]
"#,
    );
    let plan = run(&cfg);
    let pools: Vec<String> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::CreateCachePool(p) => Some(p.binding.name.clone()),
            _ => None,
        })
        .collect();
    // Both build and test must appear; build appears only ONCE despite
    // two runner references.
    let mut sorted = pools.clone();
    sorted.sort();
    assert_eq!(sorted, vec!["build".to_string(), "test".into()]);
}
