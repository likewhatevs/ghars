//! part2a continued: `spec_hash` CIDR equivalence + `ParsedUnit` parser tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ipnet::IpNet;

use super::*;
use crate::config::{DnsMode, EffectiveNetworkBinding, Ipv6Mode, NetworkMode, NetworkSpec};

/// Property: two operator TOMLs that differ only in CIDR host bits
/// (e.g., `10.0.0.5/24` vs `10.0.0.0/24`) produce equal `spec_hash`
/// after lowering. Pins the cosmetic-equivalence guarantee at the
/// hash level — without trunc-before-sort+dedup, the two forms
/// would produce different JSON bytes during `spec_hash`
/// computation and trigger a spurious in-place `UpdateRunner`
/// cascade on re-deploy.
#[test]
fn spec_hash_equal_for_host_bits_set_vs_zero() {
    let mk = |ip: &str, deny: &str| -> EffectiveRunnerSpec {
        let mut cfg = config_with_runners(vec![minimal_runner("a")]);
        cfg.networks.insert(
            "net-a".into(),
            NetworkSpec {
                mode: NetworkMode::Netns,
                allowed_egress: vec![],
                ip_allow: vec![ip.parse::<IpNet>().unwrap()],
                ip_deny: vec![deny.parse::<IpNet>().unwrap()],
                restrict_address_families: vec![],
                dns: DnsMode::default(),
                ipv6: Ipv6Mode::default(),
            },
        );
        cfg.runners[0].network = Some("net-a".into());
        let expanded = expand_counts(&cfg).expect("count expansion must succeed");
        lower_to_effective(&expanded[0], &cfg, Arch::X86_64, cfg_source_default(), 0)
            .expect("lower_to_effective must succeed")
    };
    let eff_with_host_bits = mk("10.0.0.5/24", "172.16.42.99/16");
    let eff_canonical = mk("10.0.0.0/24", "172.16.0.0/16");
    assert_eq!(
        eff_with_host_bits.spec_hash, eff_canonical.spec_hash,
        "spec_hash must be byte-stable across operator host-bits-set vs \
         host-bits-zero forms; got {} vs {}",
        eff_with_host_bits.spec_hash, eff_canonical.spec_hash
    );
}

/// Property: `canonicalize_network_spec` emits a `tracing::warn!`
/// for each operator-supplied CIDR with host bits set (one warn per
/// CIDR, naming both the operator form and the normalized form +
/// the field). Educational signal for operators who may have
/// confused CIDR notation (e.g., `10.0.0.5/24` could mean "single
/// host 10.0.0.5 in subnet /24" — they actually want `/32`).
/// Canonical CIDRs (already host-bits-zero) MUST NOT emit a warn —
/// no log noise for legitimate input.
#[test]
#[tracing_test::traced_test]
fn canonicalize_network_spec_warns_on_host_bits_set() {
    let mut cfg = config_with_runners(vec![minimal_runner("a")]);
    cfg.networks.insert(
        "net-a".into(),
        NetworkSpec {
            mode: NetworkMode::Netns,
            allowed_egress: vec![],
            ip_allow: vec![
                "10.0.0.5/24".parse::<IpNet>().unwrap(),    // host bits set
                "192.168.0.0/16".parse::<IpNet>().unwrap(), // canonical
            ],
            ip_deny: vec![
                "172.16.42.42/12".parse::<IpNet>().unwrap(), // host bits set
            ],
            restrict_address_families: vec![],
            dns: DnsMode::default(),
            ipv6: Ipv6Mode::default(),
        },
    );
    cfg.runners[0].network = Some("net-a".into());
    let expanded = expand_counts(&cfg).expect("count expansion must succeed");
    let _eff = lower_to_effective(&expanded[0], &cfg, Arch::X86_64, cfg_source_default(), 0)
        .expect("lower_to_effective must succeed");
    // Two host-bits-set CIDRs → two warns naming the operator + normalized forms.
    assert!(
        logs_contain("CIDR has host bits set"),
        "warn message must name the violation class"
    );
    assert!(
        logs_contain("10.0.0.5/24"),
        "warn must name the operator form for ip_allow violation"
    );
    assert!(
        logs_contain("10.0.0.0/24"),
        "warn must name the normalized form for ip_allow violation"
    );
    assert!(
        logs_contain("172.16.42.42/12"),
        "warn must name the operator form for ip_deny violation"
    );
    assert!(
        logs_contain("172.16.0.0/12"),
        "warn must name the normalized form for ip_deny violation"
    );
    assert!(
        logs_contain("ip_allow"),
        "warn must name ip_allow field for the .5/24 violation"
    );
    assert!(
        logs_contain("ip_deny"),
        "warn must name ip_deny field for the .42/12 violation"
    );
    // The already-canonical 192.168.0.0/16 must NOT warn — pin no-noise.
    assert!(
        !logs_contain("192.168.0.0/16"),
        "canonical CIDR (192.168.0.0/16) must not appear in warn output \
         — no false-positive log noise for legitimate input"
    );
}

/// Property: two TOML files that produce semantically-identical
/// configs (but with formatting differences — comments,
/// whitespace, key order across runner blocks) must lower to the
/// same `EffectiveRunnerSpec` and produce equal `spec_hash`.
/// This is the round-trip determinism guarantee — a mutant that
/// captured TOML source bytes into the hash would fail here.
#[test]
fn spec_hash_equal_for_semantically_identical_toml_sources() {
    // TOML A: sparse, no comments.
    let toml_a = r#"
[auth.pat]
kind = "pat"
token_env = "GHARS_PAT"

[[runner]]
name = "buckos"
url = "https://github.com/example/buckos"
auth = "pat"
labels = ["alpha", "beta"]
"#;
    // TOML B: same content, plus comments, whitespace, blank
    // lines — semantically identical, byte-different.
    let toml_b = r#"
# auth section
[auth.pat]
kind      = "pat"
token_env = "GHARS_PAT"   # comment

# the only runner

[[runner]]
name    = "buckos"
url     = "https://github.com/example/buckos"
auth    = "pat"
labels  = ["alpha", "beta"]
"#;
    let cfg_a: crate::config::Config = toml::from_str(toml_a).unwrap();
    let cfg_b: crate::config::Config = toml::from_str(toml_b).unwrap();
    let runner_a = &cfg_a.runners[0];
    let runner_b = &cfg_b.runners[0];
    let spec_a = merge_defaults(
        runner_a,
        &cfg_a.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    let spec_b = merge_defaults(
        runner_b,
        &cfg_b.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    assert_eq!(
        spec_hash(&spec_a),
        spec_hash(&spec_b),
        "comment/whitespace differences in TOML source must not affect spec_hash"
    );
}

// ---- cache pool diff branches + drift_cause + recreate-empties-drop-in-changes -----

/// Helper: insert a desired pool referenced by runner `a`. Mirrors
/// the inline `cfg.cache_pools.insert(...)` pattern other pool
/// tests use.
fn cfg_with_pool(name: &str, kinds: Vec<crate::config::CacheKind>) -> Config {
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec![name.into()];
        r
    }]);
    cfg.cache_pools.insert(
        name.into(),
        CachePoolSpec {
            kinds,
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            // Pin both binaries so the plan-time auto-detect probe
            // never reads the test host's filesystem — `/usr/bin/sccache`
            // is not present on every CI image. Pinning both fields
            // (not just the relevant one) keeps this helper kind-agnostic.
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: Some("/usr/bin/sleep".into()),
            server_mode: crate::config::SccacheServerMode::Pooled,
        },
    );
    cfg
}

/// Helper: build a `DiscoveredCachePool` with the given `spec_hash` +
/// drop-in body content, and the requested Drift. Matches the
/// shape produced by `state::discover` for cache-pool drop-in
/// dirs.
fn discovered_pool(name: &str, spec_hash: &str, drift: Drift) -> crate::state::DiscoveredCachePool {
    let mut drop_ins: BTreeMap<String, String> = BTreeMap::new();
    drop_ins.insert(
        "00-ghars.conf".into(),
        format!("[Unit]\nX-Ghars-Spec-Hash={spec_hash}\n"),
    );
    // For DropInsModified payloads, also stage the unmanaged file
    // so the test's drop-in shape reflects what discover() would
    // see. Caller passes the basename via the Drift payload Vec —
    // we don't expand it here because each test fabricates Drift
    // directly.
    crate::state::DiscoveredCachePool {
        name: name.to_owned(),
        spec_hash: spec_hash.to_owned(),
        drop_ins,
        running: false,
        enabled: false,
        drift,
    }
}

/// Branch 1: `spec_hash` matches AND drift `InSync` ⇒ no
/// `UpdateCachePool` / `RemoveCachePool` emitted (`NoOp` on the pool
/// side — `plan_from` emits no action when both signals are clean).
#[test]
fn plan_cache_pool_in_sync_emits_no_pool_action() {
    let cfg = cfg_with_pool("build", vec![CacheKind::Ccache]);
    // Compute the pool's spec_hash by running into_cache_pool_plan
    // with the same desired binding. plan_from calls this path
    // internally; we mirror it so the test's discovered hash
    // matches.
    let cfg_source = empty_paths().config_dir.join("ghars.toml").to_string();
    let spec = cfg.cache_pools.get("build").unwrap();
    let plan_for_pool = into_cache_pool_plan("build".into(), spec, &cfg_source).unwrap();
    let mut actual = empty_actual();
    actual.cache_pools.insert(
        "build".into(),
        discovered_pool("build", &plan_for_pool.spec_hash, Drift::InSync),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let pool_actions: Vec<&Action> = plan
        .actions
        .iter()
        .filter(|a| {
            matches!(
                a,
                Action::CreateCachePool(_)
                    | Action::UpdateCachePool(_)
                    | Action::RemoveCachePool(_)
            )
        })
        .collect();
    assert!(
        pool_actions.is_empty(),
        "in-sync pool must emit no pool action; got: {:?}",
        pool_actions.iter().map(|a| a.label()).collect::<Vec<_>>(),
    );
}

/// Branch 2: `spec_hash` differs ⇒ `UpdateCachePool`. Pool drift
/// stays `InSync`; the `spec_hash` mismatch alone drives the action.
#[test]
fn plan_cache_pool_update_on_spec_hash_change() {
    let cfg = cfg_with_pool("build", vec![CacheKind::Ccache]);
    let mut actual = empty_actual();
    actual.cache_pools.insert(
        "build".into(),
        discovered_pool("build", "sha256:stale", Drift::InSync),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let updates: Vec<&CachePoolDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateCachePool(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].binding.name, "build");
}

/// Branch 3: `spec_hash` matches but drift signals `DropInsModified`
/// ⇒ `UpdateCachePool` (the gate is
/// `spec_hash != actual || !pool_in_sync`).
#[test]
fn plan_cache_pool_update_on_drift_only() {
    let cfg = cfg_with_pool("build", vec![CacheKind::Ccache]);
    let cfg_source = empty_paths().config_dir.join("ghars.toml").to_string();
    let spec = cfg.cache_pools.get("build").unwrap();
    let plan_for_pool = into_cache_pool_plan("build".into(), spec, &cfg_source).unwrap();
    let mut actual = empty_actual();
    // spec_hash matches BUT drift carries an unmanaged drop-in:
    // operator added 99-tuning.conf via `systemctl edit`.
    actual.cache_pools.insert(
        "build".into(),
        discovered_pool(
            "build",
            &plan_for_pool.spec_hash,
            Drift::DropInsModified(vec!["99-tuning.conf".into()]),
        ),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let updates: Vec<&CachePoolDelta> = plan
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::UpdateCachePool(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(
        updates.len(),
        1,
        "operator drift on a hash-matched pool must trigger UpdateCachePool"
    );
}

/// Branch 4: pool present in actual but NOT referenced by any
/// desired runner ⇒ `RemoveCachePool`. Pinned by the
/// `actual.cache_pools` − `desired_pool_names` set difference in
/// `plan_from`'s cache-pool diffing block.
#[test]
fn plan_cache_pool_remove_when_orphan() {
    // No runner references the pool; cfg has runner "a" with no
    // caches. Discovered actual carries a "stale-pool" pool.
    let cfg = config_with_runners(vec![minimal_runner("a")]);
    let mut actual = empty_actual();
    actual.cache_pools.insert(
        "stale-pool".into(),
        discovered_pool("stale-pool", "sha256:dead", Drift::InSync),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let removes: Vec<&Action> = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::RemoveCachePool(_)))
        .collect();
    assert_eq!(removes.len(), 1);
    match removes[0] {
        Action::RemoveCachePool(name) => assert_eq!(name, "stale-pool"),
        other => panic!("expected RemoveCachePool, got {other:?}"),
    }
}

/// `drift_cause` on `UpdateRunner`: `SpecChanged` when hashes differ but
/// discovered Drift is `InSync`. Pins the
/// `(!hashes_equal, !in_sync)` match arms in `plan_from`'s
/// intersection branch (the block that emits
/// `Action::UpdateRunner` after the `NoOp` short-circuit).
#[test]
fn plan_update_runner_drift_cause_spec_changed() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.memory_max = Some("64G".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.memory_max = Some("32G".into());
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("expected exactly one UpdateRunner");
    assert_eq!(upd.drift_cause, DriftCause::SpecChanged);
}

/// `drift_cause`: `DriftDetected` when `spec_hash` matches but discovered
/// Drift is non-InSync. Hash equality means no config change;
/// drift means out-of-band edit. Confirms the `(false, true)`
/// arm of the `drift_cause` match in `plan_from`.
#[test]
fn plan_update_runner_drift_cause_drift_detected() {
    // Use minimal_runner unchanged on both sides so spec_hash
    // matches but the discovered runner reports DropInsModified.
    let cfg = config_with_runners(vec![minimal_runner("a")]);
    let runner = cfg.runners[0].clone();
    let mut spec = merge_defaults(
        &runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    spec.spec_hash = spec_hash(&spec);
    let mut actual = empty_actual();
    actual.runners.insert(
        "a".into(),
        discovered_for(
            "a",
            &spec,
            Drift::DropInsModified(vec!["99-operator.conf".into()]),
        ),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("expected one UpdateRunner");
    assert_eq!(upd.drift_cause, DriftCause::DriftDetected);
}

/// `drift_cause`: `SpecChangedAndDriftDetected` when BOTH hashes differ
/// AND on-disk drift is non-InSync. Confirms the `(true, true)`
/// arm of the `drift_cause` match in `plan_from`.
#[test]
fn plan_update_runner_drift_cause_spec_changed_and_drift_detected() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.memory_max = Some("64G".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.memory_max = Some("32G".into());
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual.runners.insert(
        "a".into(),
        discovered_for(
            "a",
            &old_spec,
            Drift::DropInsModified(vec!["99-operator.conf".into()]),
        ),
    );
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("expected one UpdateRunner");
    assert_eq!(upd.drift_cause, DriftCause::SpecChangedAndDriftDetected);
}

/// recreate-class change must produce an empty `drop_in_changes`
/// payload. The recreate path drops + recreates all drop-ins
/// atomically; per-basename diff is meaningless and would mislead
/// CLI consumers. Pinned by the `requires_recreate` short-circuit
/// in `plan_from`'s (true, true) match arm — when
/// `requires_recreate` is true, `drop_in_changes` is set to
/// `Vec::new()` instead of the rendered Stage 2 diff.
#[test]
fn plan_update_runner_recreate_empties_drop_in_changes() {
    let cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.runner_version = Some("2.300.0".into());
        r
    }]);
    let mut old_runner = cfg.runners[0].clone();
    old_runner.runner_version = Some("2.200.0".into());
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));
    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("expected one UpdateRunner");
    assert!(upd.requires_recreate, "runner_version change must recreate");
    assert!(
        upd.drop_in_changes.is_empty(),
        "recreate path must empty drop_in_changes; got {:?}",
        upd.drop_in_changes
    );
}

// ---- auth_name in-place contract --------------------------------

/// Same-discriminant fixture for the auth-name in-place contract:
/// both `[auth.NAME]` blocks are `AuthSpec::Pat`, distinct
/// auth-ref names (`pat-old` → `pat-new`). Same-discriminant
/// Pat→Pat with different auth-ref names is the most common
/// operator transition (token rotation: retire one
/// `[auth.pat-old]` block, point runners at `[auth.pat-new]`),
/// distinct from the same-name `pat`→`github_app` sibling that
/// also uses two `AuthSpec::Pat` blocks but exercises the
/// auth-name strings the cross-discriminant siblings use as
/// labels.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`
/// (`recreate_reasons` empty, `requires_recreate=false`, single
/// `auth_name` `field_change` with expected before/after,
/// `drift_cause=SpecChanged`, no `auth_kind` leakage, Modified
/// 00-ghars.conf drop-in entry). See the helper docstring for
/// the contract.
#[test]
fn plan_update_in_place_on_auth_name_change_pat_old_to_pat_new_has_empty_recreate_reasons() {
    // Two `[auth.NAME]` blocks named `pat-old` and `pat-new`,
    // both `AuthSpec::Pat`. The runner moves from auth-ref
    // `pat-old` → `pat-new`.
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "pat-old".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT_OLD".into()),
            token_file: None,
        },
    );
    auth_blocks.insert(
        "pat-new".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT_NEW".into()),
            token_file: None,
        },
    );
    assert_auth_name_change_is_in_place(auth_blocks, "pat-old", "pat-new");
}

/// Same-discriminant pin: both `[auth.NAME]` blocks are
/// `AuthSpec::Interactive` — the unit variant carries no payload,
/// so the two blocks are bytewise identical except for their
/// `IndexMap` key. The classifier must still treat the auth-name
/// string change as in-place: `merge_defaults` lowers each block
/// to a bare `EffectiveRunnerSpec.auth_name` string regardless
/// of discriminant or payload, so the discovered/desired diff is
/// purely on the name string. Degenerate but load-bearing — pins
/// that the classifier never inspects upstream `AuthSpec` content
/// (which would falsely report "no change" here and skip the
/// 00-ghars.conf rewrite).
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_interactive_old_to_interactive_new_has_empty_recreate_reasons()
 {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert("interactive-old".into(), AuthSpec::Interactive);
    auth_blocks.insert("interactive-new".into(), AuthSpec::Interactive);
    assert_auth_name_change_is_in_place(auth_blocks, "interactive-old", "interactive-new");
}

/// Same-discriminant pin: both `[auth.NAME]` blocks are
/// `AuthSpec::TokenFile` with distinct `path` fields. Operator
/// rotates the on-disk registration token file (e.g. moves
/// `/etc/ghars/reg.token` → `/etc/ghars/reg2.token`) while
/// keeping the variant. The classifier sees only the
/// auth-name string diff at the `EffectiveRunnerSpec.auth_name`
/// level and must classify in-place; the path diff in the
/// upstream `AuthSpec::TokenFile { path }` is invisible to
/// `merge_defaults` and irrelevant to the
/// `00-ghars.conf` annotation rewrite.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_token_file_old_to_token_file_new_has_empty_recreate_reasons()
 {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "token-file-old".into(),
        AuthSpec::TokenFile {
            path: Utf8PathBuf::from("/etc/ghars/reg.token"),
        },
    );
    auth_blocks.insert(
        "token-file-new".into(),
        AuthSpec::TokenFile {
            path: Utf8PathBuf::from("/etc/ghars/reg2.token"),
        },
    );
    assert_auth_name_change_is_in_place(auth_blocks, "token-file-old", "token-file-new");
}

/// Same-discriminant pin: both `[auth.NAME]` blocks are
/// `AuthSpec::GithubApp` with distinct `app_id`,
/// `installation_id`, AND `private_key_path` fields. Operator
/// rotates from one App to another (different `app_id`) and
/// updates the install + key alongside. Same-discriminant change
/// must classify in-place because `merge_defaults` reduces both
/// blocks to a bare `EffectiveRunnerSpec.auth_name` string;
/// `app_id`/`installation_id`/`private_key_path` differences
/// don't reach the planner.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_github_app_old_to_github_app_new_has_empty_recreate_reasons()
 {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "github-app-old".into(),
        AuthSpec::GithubApp {
            app_id: 11111,
            installation_id: 22222,
            private_key_path: Utf8PathBuf::from("/etc/ghars/app-old.pem"),
        },
    );
    auth_blocks.insert(
        "github-app-new".into(),
        AuthSpec::GithubApp {
            app_id: 33333,
            installation_id: 44444,
            private_key_path: Utf8PathBuf::from("/etc/ghars/app-new.pem"),
        },
    );
    assert_auth_name_change_is_in_place(auth_blocks, "github-app-old", "github-app-new");
}

/// Shared scaffold for the auth-name in-place sibling tests
/// (same-discriminant Pat→Pat, cross-discriminant Pat→GithubApp,
/// cross-discriminant GithubApp→Pat).
///
/// Sets up a `Config` with the operator-supplied `auth_blocks`,
/// points the lone runner at `desired_auth_name`, builds a
/// `DiscoveredRunner` whose `EffectiveRunnerSpec.auth_name` is
/// `discovered_auth_name` (modeling a runner registered against
/// that auth ref at a prior apply), invokes `plan_from`, and
/// runs the seven invariants every direction must satisfy:
///
/// 1. `recreate_reasons == vec![]` exactly. Any token pushed into
///    `recreate_reasons` (whether `uncovered`, `auth_name`, or a
///    new token) fails this pin.
/// 2. `requires_recreate == false` — derived from
///    `!recreate_reasons.is_empty()` at `plan_from`'s
///    spec-hash-mismatch arm, so an empty `recreate_reasons`
///    implies false here. Pinned independently because a future
///    refactor could decouple the two.
/// 3. `field_changes.len() == 1` — phantom fields signal regression.
/// 4. `field_changes` contains an `auth_name` `FieldChange` whose
///    `before` matches `FieldValue::String(discovered_auth_name)`
///    and `after` matches `FieldValue::String(desired_auth_name)`.
/// 5. `drift_cause == DriftCause::SpecChanged` — the `auth_name`
///    string diff drives a `spec_hash` mismatch with no on-disk
///    drift (the discovered drop-in is freshly rendered by
///    `discovered_for`, so `DriftDetected` cannot fire).
/// 6. `auth_kind` does NOT appear in `field_changes` —
///    `merge_defaults` strips the `AuthSpec` discriminant when
///    lowering to `EffectiveRunnerSpec.auth_name`, so the
///    classifier never observes an `auth_kind` surface and must
///    not synthesize one.
/// 7. `drop_in_changes` contains a `Modified` entry for
///    `00-ghars.conf` — `render_identity` emits the `auth_name`
///    string into the `X-Ghars-Auth-Name` annotation, so an
///    auth-name change always produces an observable drop-in
///    diff. A regression that classifies as in-place but skips
///    the file rewrite would silently leave the annotation
///    pointing at the discovered side after the apply, breaking
///    the next planner cycle's annotation-vs-config comparison.
///
/// Each caller passes its own `auth_blocks`
/// (`IndexMap<String, AuthSpec>`) so same-discriminant vs
/// cross-discriminant fixture shapes stay caller-controlled —
/// the helper does not fabricate `AuthSpec` content. The expected
/// `FieldChange` before/after are derived from the two name
/// arguments (`merge_defaults` lowers the auth ref to a bare
/// `EffectiveRunnerSpec.auth_name` string with no normalization,
/// so the rendered before/after are literal pass-through of the
/// caller-supplied names).
fn assert_auth_name_change_is_in_place(
    auth_blocks: IndexMap<String, AuthSpec>,
    discovered_auth_name: &str,
    desired_auth_name: &str,
) {
    let expected_before = FieldValue::String(discovered_auth_name.into());
    let expected_after = FieldValue::String(desired_auth_name.into());
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.auth = Some(desired_auth_name.into());
        r
    }]);
    cfg.auth = auth_blocks;

    // Discovered runner was registered against discovered_auth_name.
    // Building the discovered spec via merge_defaults exercises the
    // production lowering path; the resulting
    // EffectiveRunnerSpec.auth_name is the bare string, matching
    // what state.rs would parse out of the on-disk
    // X-Ghars-Auth-Name annotation.
    let old_runner = cfg.runners[0].clone();
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        discovered_auth_name.into(),
        vec![],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("auth-name change must emit UpdateRunner");

    // 1. recreate_reasons exactly empty.
    assert_eq!(
        upd.recreate_reasons,
        Vec::<&'static str>::new(),
        "auth-name change ({discovered_auth_name} → {desired_auth_name}) must \
         produce empty recreate_reasons (no \"uncovered\", no \"auth_name\", \
         nothing); got: {:?}",
        upd.recreate_reasons,
    );
    // 2. requires_recreate false.
    assert!(
        !upd.requires_recreate,
        "auth-name change ({discovered_auth_name} → {desired_auth_name}) must \
         remain in-place — requires_recreate must be false (derived from \
         plan_from's `requires_recreate = !recreate_reasons.is_empty()` gate)",
    );
    // 3. field_changes has exactly one entry.
    assert_eq!(
        upd.field_changes.len(),
        1,
        "auth_name change must be the only field_changes entry; \
         phantom fields signal regression — got: {:?}",
        upd.field_changes,
    );
    // 4. field_changes contains auth_name with correct before/after.
    let auth_name_change = upd
        .field_changes
        .iter()
        .find(|fc| fc.path == "auth_name")
        .expect("field_changes must include auth_name entry");
    assert_eq!(
        auth_name_change.before, expected_before,
        "before must reflect the discovered side's auth_name string",
    );
    assert_eq!(
        auth_name_change.after, expected_after,
        "after must reflect the desired side's auth_name string",
    );
    // 5. drift_cause is SpecChanged.
    assert_eq!(
        upd.drift_cause,
        DriftCause::SpecChanged,
        "auth-name change ({discovered_auth_name} → {desired_auth_name}) must \
         classify as SpecChanged: the auth_name string diff drives a \
         spec_hash mismatch with no on-disk drift",
    );
    // 6. auth_kind discriminant must NOT leak into field_changes.
    assert!(
        !upd.field_changes.iter().any(|fc| fc.path == "auth_kind"),
        "auth_kind must NOT appear — discriminant is stripped by \
         merge_defaults; got field_changes: {:?}",
        upd.field_changes,
    );
    // 7. 00-ghars.conf drop-in is Modified (X-Ghars-Auth-Name rewrite).
    assert!(
        upd.drop_in_changes.iter().any(|dc| {
            dc.basename == "00-ghars.conf" && matches!(dc.change, DropInChangeKind::Modified { .. })
        }),
        "auth-name change ({discovered_auth_name} → {desired_auth_name}) must \
         produce Modified 00-ghars.conf drop-in change; got: {:?}",
        upd.drop_in_changes,
    );
}

/// Shared cross-discriminant `[auth.NAME]` fixture: a `pat` block
/// of kind `AuthSpec::Pat` paired with a `github_app` block of
/// kind `AuthSpec::GithubApp`. Used by the forward
/// (`pat → github_app`) and inverse (`github_app → pat`) sibling
/// tests of the auth-name in-place contract — the two directions
/// share an identical fixture and differ only in which auth-ref
/// name appears on the discovered vs desired side.
///
/// Centralizing the construction keeps the two siblings in lock-
/// step: if the `GithubApp` content changes (e.g. `private_key_path`
/// moves to a different convention), both directions re-derive
/// from a single source.
fn auth_blocks_with_pat_and_github_app() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "pat".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    auth_blocks.insert(
        "github_app".into(),
        AuthSpec::GithubApp {
            app_id: 12345,
            installation_id: 67890,
            private_key_path: Utf8PathBuf::from("/etc/ghars/app.pem"),
        },
    );
    auth_blocks
}

/// Naming-vs-discriminant pin for the auth-name in-place
/// contract: the two `[auth.NAME]` blocks have different names
/// (`pat` → `github_app`) but identical `AuthSpec::Pat`
/// discriminants — the auth-name string change must drive the
/// in-place classifier on its own, with the matching discriminant
/// providing no information to the planner. Confirms the
/// classifier reads `EffectiveRunnerSpec.auth_name` (the bare
/// string after `merge_defaults` lowering) and never the upstream
/// `AuthSpec` variant.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`
/// (`recreate_reasons` empty, `requires_recreate=false`, single
/// `auth_name` `field_change` with expected before/after,
/// `drift_cause=SpecChanged`, no `auth_kind` leakage, Modified
/// 00-ghars.conf drop-in entry). See the helper docstring for
/// the contract; this test contributes the same-discriminant
/// fixture.
#[test]
fn plan_update_in_place_on_auth_name_change_has_empty_recreate_reasons() {
    // Two `[auth.NAME]` blocks named `pat` and `github_app`. Both
    // are AuthSpec::Pat under the hood — merge_defaults only sees
    // the auth_name string, so this is an auth-name string change
    // end-to-end.
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "pat".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    auth_blocks.insert(
        "github_app".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT_GHAPP".into()),
            token_file: None,
        },
    );
    assert_auth_name_change_is_in_place(auth_blocks, "pat", "github_app");
}

/// Cross-discriminant pin for the auth-name in-place contract:
/// the discovered side carries `AuthSpec::Pat`, the desired side
/// carries `AuthSpec::GithubApp`. Direction is `pat → github_app`
/// (the common operator transition: PAT for personal automation
/// → GitHub App for org-scale rollout). `merge_defaults` lowers
/// the `[auth.NAME]` block to a bare `auth_name` string, so the
/// classifier sees a pure `auth_name` string diff regardless of
/// which discriminants the two blocks carry. The same-discriminant
/// sibling test
/// `plan_update_in_place_on_auth_name_change_has_empty_recreate_reasons`
/// pins the matching-discriminant case; the
/// `github_app → pat` sibling pins the inverse direction.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`
/// (`recreate_reasons` empty, `requires_recreate=false`, single
/// `auth_name` `field_change` with expected before/after,
/// `drift_cause=SpecChanged`, no `auth_kind` leakage, Modified
/// 00-ghars.conf drop-in entry). See the helper docstring for
/// the contract.
#[test]
fn plan_update_in_place_on_auth_name_change_pat_to_github_app_has_empty_recreate_reasons() {
    // REAL cross-discriminant shape (Pat + GithubApp) shared with
    // the inverse-direction sibling test. The runner.auth ref
    // switches from "pat" (discovered side) to "github_app"
    // (desired side).
    assert_auth_name_change_is_in_place(auth_blocks_with_pat_and_github_app(), "pat", "github_app");
}

/// Inverse-direction cross-discriminant pin: discovered side
/// carries `AuthSpec::GithubApp`, desired side switches to
/// `AuthSpec::Pat`. Direction is `github_app → pat` — the
/// operator-rare but classifier-important rollback case
/// (App → PAT for break-glass debug or App credential rotation
/// hotfix). The forward `pat → github_app` sibling alone would
/// leave a coverage hole: a regression that inspects only one
/// direction's discriminant pair could pass forward and break
/// inverse. Pinning both directions enforces the classifier's
/// discriminant-stripping invariant symmetrically — `merge_defaults`
/// lowers the `[auth.NAME]` block to a bare `auth_name` string
/// regardless of `AuthSpec` variant.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`
/// (`recreate_reasons` empty, `requires_recreate=false`, single
/// `auth_name` `field_change` with expected before/after,
/// `drift_cause=SpecChanged`, no `auth_kind` leakage, Modified
/// 00-ghars.conf drop-in entry). See the helper docstring for
/// the contract.
#[test]
fn plan_update_in_place_on_auth_name_change_github_app_to_pat_has_empty_recreate_reasons() {
    // REAL cross-discriminant shape (Pat + GithubApp) shared with
    // the forward-direction sibling test. The runner.auth ref
    // switches in the OPPOSITE direction: from "github_app"
    // (discovered side) to "pat" (desired side).
    assert_auth_name_change_is_in_place(auth_blocks_with_pat_and_github_app(), "github_app", "pat");
}

/// Cross-discriminant fixture: a `pat` block (`AuthSpec::Pat`)
/// paired with an `interactive` block (`AuthSpec::Interactive`).
/// Shared by the `pat ↔ interactive` direction-pair tests so
/// both directions re-derive from a single source.
fn auth_blocks_with_pat_and_interactive() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "pat".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    auth_blocks.insert("interactive".into(), AuthSpec::Interactive);
    auth_blocks
}

/// Cross-discriminant fixture: a `pat` block (`AuthSpec::Pat`)
/// paired with a `token_file` block (`AuthSpec::TokenFile`).
/// Shared by the `pat ↔ token_file` direction-pair tests.
fn auth_blocks_with_pat_and_token_file() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "pat".into(),
        AuthSpec::Pat {
            token_env: Some("GHARS_PAT".into()),
            token_file: None,
        },
    );
    auth_blocks.insert(
        "token_file".into(),
        AuthSpec::TokenFile {
            path: Utf8PathBuf::from("/etc/ghars/registration.token"),
        },
    );
    auth_blocks
}

/// Cross-discriminant fixture: a `github_app` block
/// (`AuthSpec::GithubApp`) paired with an `interactive` block
/// (`AuthSpec::Interactive`). Shared by the
/// `github_app ↔ interactive` direction-pair tests.
fn auth_blocks_with_github_app_and_interactive() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "github_app".into(),
        AuthSpec::GithubApp {
            app_id: 12345,
            installation_id: 67890,
            private_key_path: Utf8PathBuf::from("/etc/ghars/app.pem"),
        },
    );
    auth_blocks.insert("interactive".into(), AuthSpec::Interactive);
    auth_blocks
}

/// Cross-discriminant fixture: a `github_app` block
/// (`AuthSpec::GithubApp`) paired with a `token_file` block
/// (`AuthSpec::TokenFile`). Shared by the
/// `github_app ↔ token_file` direction-pair tests.
fn auth_blocks_with_github_app_and_token_file() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert(
        "github_app".into(),
        AuthSpec::GithubApp {
            app_id: 12345,
            installation_id: 67890,
            private_key_path: Utf8PathBuf::from("/etc/ghars/app.pem"),
        },
    );
    auth_blocks.insert(
        "token_file".into(),
        AuthSpec::TokenFile {
            path: Utf8PathBuf::from("/etc/ghars/registration.token"),
        },
    );
    auth_blocks
}

/// Cross-discriminant fixture: an `interactive` block
/// (`AuthSpec::Interactive`) paired with a `token_file` block
/// (`AuthSpec::TokenFile`). Shared by the
/// `interactive ↔ token_file` direction-pair tests.
fn auth_blocks_with_interactive_and_token_file() -> IndexMap<String, AuthSpec> {
    let mut auth_blocks = IndexMap::new();
    auth_blocks.insert("interactive".into(), AuthSpec::Interactive);
    auth_blocks.insert(
        "token_file".into(),
        AuthSpec::TokenFile {
            path: Utf8PathBuf::from("/etc/ghars/registration.token"),
        },
    );
    auth_blocks
}

/// Cross-discriminant pin: discovered side `AuthSpec::Pat`,
/// desired side `AuthSpec::Interactive`. Direction is
/// `pat → interactive`. Note: `AuthSpec::Interactive` is a
/// unit variant — it carries no payload fields. The
/// auth-name-in-place contract still holds because
/// `merge_defaults` strips the discriminant when lowering
/// to `EffectiveRunnerSpec.auth_name` (a bare String); the
/// classifier sees a pure `auth_name` string diff regardless of
/// whether either side has a payload. This test pins that the
/// payload-free Interactive variant participates in the
/// auth-name in-place contract identically to the
/// payload-bearing Pat / `GithubApp` / `TokenFile` variants.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`
/// (`recreate_reasons` empty, `requires_recreate=false`, single
/// `auth_name` `field_change` with expected before/after,
/// `drift_cause=SpecChanged`, no `auth_kind` leakage, Modified
/// 00-ghars.conf drop-in entry). See the helper docstring for
/// the contract.
#[test]
fn plan_update_in_place_on_auth_name_change_pat_to_interactive_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_pat_and_interactive(),
        "pat",
        "interactive",
    );
}

/// Inverse-direction pin of `pat_to_interactive`: discovered
/// side `AuthSpec::Interactive`, desired side `AuthSpec::Pat`.
/// Direction is `interactive → pat`. Pinned independently
/// because a regression that inspected only one direction's
/// discriminant pair could pass forward and break inverse.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_interactive_to_pat_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_pat_and_interactive(),
        "interactive",
        "pat",
    );
}

/// Cross-discriminant pin: discovered side `AuthSpec::Pat`,
/// desired side `AuthSpec::TokenFile`. Direction is
/// `pat → token_file` — the operator-rare but
/// classifier-important transition (long-lived PAT
/// → short-lived pre-minted registration token). The
/// classifier must treat this as a pure `auth_name` string diff
/// despite the upstream discriminant flip.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_pat_to_token_file_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(auth_blocks_with_pat_and_token_file(), "pat", "token_file");
}

/// Inverse-direction pin of `pat_to_token_file`: discovered
/// side `AuthSpec::TokenFile`, desired side `AuthSpec::Pat`.
/// Direction is `token_file → pat`.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_token_file_to_pat_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(auth_blocks_with_pat_and_token_file(), "token_file", "pat");
}

/// Cross-discriminant pin: discovered side
/// `AuthSpec::GithubApp`, desired side `AuthSpec::Interactive`.
/// Direction is `github_app → interactive` — break-glass
/// debug after App credential issues.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_github_app_to_interactive_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_github_app_and_interactive(),
        "github_app",
        "interactive",
    );
}

/// Inverse-direction pin of `github_app_to_interactive`:
/// discovered side `AuthSpec::Interactive`, desired side
/// `AuthSpec::GithubApp`. Direction is `interactive → github_app`
/// — typical promotion from operator-pasted token to
/// org-scale App.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_interactive_to_github_app_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_github_app_and_interactive(),
        "interactive",
        "github_app",
    );
}

/// Cross-discriminant pin: discovered side
/// `AuthSpec::GithubApp`, desired side `AuthSpec::TokenFile`.
/// Direction is `github_app → token_file`.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_github_app_to_token_file_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_github_app_and_token_file(),
        "github_app",
        "token_file",
    );
}

/// Inverse-direction pin of `github_app_to_token_file`:
/// discovered side `AuthSpec::TokenFile`, desired side
/// `AuthSpec::GithubApp`. Direction is `token_file → github_app`.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_token_file_to_github_app_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_github_app_and_token_file(),
        "token_file",
        "github_app",
    );
}

/// Cross-discriminant pin: discovered side
/// `AuthSpec::Interactive`, desired side `AuthSpec::TokenFile`.
/// Direction is `interactive → token_file` — the operator
/// formalizes the token-paste workflow into a managed file.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_interactive_to_token_file_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_interactive_and_token_file(),
        "interactive",
        "token_file",
    );
}

/// Inverse-direction pin of `interactive_to_token_file`:
/// discovered side `AuthSpec::TokenFile`, desired side
/// `AuthSpec::Interactive`. Direction is `token_file → interactive`.
///
/// Satisfies invariants 1-7 of `assert_auth_name_change_is_in_place`.
#[test]
fn plan_update_in_place_on_auth_name_change_token_file_to_interactive_has_empty_recreate_reasons() {
    assert_auth_name_change_is_in_place(
        auth_blocks_with_interactive_and_token_file(),
        "token_file",
        "interactive",
    );
}

// ---- caches in-place contract -----------------------------------

/// caches change is in-place per design Part 3. The
/// caches in-place classifier branch must:
///   - record a `FieldChange` { path: "caches", before, after };
///   - NOT push to `recreate_reasons`;
///   - NOT trip the `uncovered` fallback (gated on
///     `field_changes.is_empty()` at the `spec_hash` mismatch
///     check in `plan_from`).
/// apply.rs's in-place `execute_update_runner` rewrites the
/// 30-cache-pool.conf drop-in body and cycles the unit so the
/// post-update `BindPaths` take effect; no host-state migration
/// requires the recreate path.
#[test]
fn plan_update_runner_caches_change_is_in_place_with_field_change() {
    // Two cache pools in the same trust_zone (so the runner
    // can reference either without trust_zone-validation noise).
    // Runner moves from caches=["pool-old"] → ["pool-new"].
    let mut cfg = config_with_runners(vec![{
        let mut r = minimal_runner("a");
        r.caches = vec!["pool-new".into()];
        r
    }]);
    cfg.cache_pools.insert(
        "pool-old".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            server_mode: crate::config::SccacheServerMode::Pooled,
        },
    );
    cfg.cache_pools.insert(
        "pool-new".into(),
        CachePoolSpec {
            kinds: vec![CacheKind::Ccache],
            size: "10G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: None,
            sleep_path: Some("/usr/bin/sleep".into()),
            server_mode: crate::config::SccacheServerMode::Pooled,
        },
    );

    // Discovered runner was registered against pool-old.
    let mut old_runner = cfg.runners[0].clone();
    old_runner.caches = vec!["pool-old".into()];
    let old_binding = EffectiveCacheBinding {
        name: "pool-old".into(),
        kinds: vec![CacheKind::Ccache],
        size: "10G".into(),
        mode: CacheMode::Shared,
        trust_zone: "default".into(),
        sccache_path: None,
        sleep_path: Some("/usr/bin/sleep".into()),
        server_mode: crate::config::SccacheServerMode::Pooled,
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };
    let mut old_spec = merge_defaults(
        &old_runner,
        &cfg.defaults,
        "pat".into(),
        vec![old_binding],
        None,
        None,
        None,
        Arch::X86_64,
        cfg_source_default(),
    );
    old_spec.spec_hash = spec_hash(&old_spec);
    let mut actual = empty_actual();
    actual
        .runners
        .insert("a".into(), discovered_for("a", &old_spec, Drift::InSync));

    let plan = plan_from(&cfg, &actual, &empty_paths()).unwrap();
    let upd = plan
        .actions
        .iter()
        .find_map(|a| match a {
            Action::UpdateRunner(d) => Some(d),
            _ => None,
        })
        .expect("caches change must emit UpdateRunner");
    assert!(
        !upd.requires_recreate,
        "caches change must be in-place; got reasons {:?}",
        upd.recreate_reasons
    );
    assert!(
        !upd.recreate_reasons.contains(&"uncovered"),
        "caches change must NOT trip uncovered fallback; got reasons {:?}",
        upd.recreate_reasons
    );
    let caches_change = upd
        .field_changes
        .iter()
        .find(|fc| fc.path == "caches")
        .expect("field_changes must include caches entry");
    assert_eq!(
        caches_change.before,
        FieldValue::List(vec!["pool-old".into()])
    );
    assert_eq!(
        caches_change.after,
        FieldValue::List(vec!["pool-new".into()])
    );
}
