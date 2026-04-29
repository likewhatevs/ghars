//! Port of the upstream Python tool's unit-text generation tests.
//! The Python tool generated a single per-runner unit file via
//! `generate_unit(UnitInputs)`; ghars splits the unit into a
//! template body (`runner_template_text`) plus drop-ins
//! (`render_runner_unit`).
//!
//! These tests verify the SAME load-bearing security properties — no
//! proxy-var leak, PATH within allowed roots, kernel hardening directives
//! present, KVM device allow line, RT priority cap, etc. — by inspecting
//! the rendered template + identity drop-in.
//!
//! Each Python test maps to one or more Rust assertions:
//! - `test_unit_privilege_isolation`     → kernel-hardening assertions
//! - `test_unit_kernel_hardening`        → all 12 directives
//! - `test_unit_cgroup_no_permits_cpuset`→ ProtectControlGroups=no
//! - `test_unit_rt_priority`             → RestrictRealtime=no, LimitRTPRIO=2
//! - `test_unit_kvm_device_allow`        → DevicePolicy=closed + DeviceAllow
//! - `test_unit_syscall_filter`          → @system-service + denylist
//! - `test_unit_path_env_*`              → PATH structure, no leak, etc.
//! - `test_unit_no_proxy_leak`           → forbidden env-var fragments absent
//! - `test_unit_filesystem_allowlist`    → BindReadOnlyPaths set
//! - `test_unit_private_devices`         → PrivateDevices=yes

use ghars::config::{Arch, EffectiveRunnerSpec, Hardening};
use ghars::systemd::{render_runner_unit, runner_template_text};

fn minimal_spec(name: &str) -> EffectiveRunnerSpec {
    EffectiveRunnerSpec {
        name: name.into(),
        url: format!("https://github.com/example/{name}"),
        arch: Arch::X86_64,
        labels: vec!["self-hosted".into()],
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
        runsvc_sha256: String::new(),
        config_source: "/etc/ghars/ghars.toml".into(),
    }
}

#[test]
fn unit_privilege_isolation_directives_present() {
    // Python parity: test_unit_privilege_isolation.
    let t = runner_template_text();
    assert!(t.contains("NoNewPrivileges=yes"));
    assert!(t.contains("CapabilityBoundingSet="));
    assert!(t.contains("AmbientCapabilities="));
}

#[test]
fn unit_kernel_hardening_directives_all_present() {
    // Python parity: test_unit_kernel_hardening — except cgroup tweaks
    // intentionally diverge (ProtectControlGroups=no by design).
    // Verifies every directive listed in the Python tool, plus the new
    // hardening fields ghars adds.
    let t = runner_template_text();
    for d in [
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes",
        "ProtectClock=yes",
        "ProtectHostname=yes",
        "LockPersonality=yes",
        "ProtectProc=invisible",
        "ProtectHome=yes",
        "RemoveIPC=yes",
        "RestrictNamespaces=yes",
        "PrivateIPC=yes",
        "RestrictSUIDSGID=yes",
    ] {
        assert!(t.contains(d), "missing directive: {d}");
    }
}

#[test]
fn unit_cgroup_permits_cpuset_writes() {
    // Python parity: test_unit_cgroup_no_permits_cpuset. KVM workloads
    // need to write cpuset/memory cgroups.
    let t = runner_template_text();
    assert!(t.contains("ProtectControlGroups=no"));
}

#[test]
fn unit_rt_priority_capped_at_two() {
    // Python parity: test_unit_rt_priority. KVM vCPU SCHED_FIFO needs
    // realtime; LimitRTPRIO=2 caps the priority workloads can request.
    let t = runner_template_text();
    assert!(t.contains("RestrictRealtime=no"));
    assert!(t.contains("LimitRTPRIO=2"));
}

#[test]
fn unit_kvm_device_allow_present() {
    // Python parity: test_unit_kvm_device_allow.
    let t = runner_template_text();
    assert!(t.contains("DevicePolicy=closed"));
    assert!(t.contains("DeviceAllow=/dev/kvm rw"));
}

#[test]
fn unit_syscall_filter_baseline_and_denylist() {
    // Python parity: test_unit_syscall_filter. The pkey/perf_event_open
    // additions and the ~@-prefixed denylist must both be present.
    let t = runner_template_text();
    assert!(t.contains(
        "SystemCallFilter=@system-service pkey_alloc pkey_mprotect pkey_free perf_event_open"
    ));
    assert!(t.contains(
        "SystemCallFilter=~@mount @clock @keyring @module @raw-io @reboot @swap @obsolete"
    ));
    assert!(t.contains("SystemCallErrorNumber=EPERM"));
    assert!(t.contains("SystemCallArchitectures=native"));
}

#[test]
fn unit_syscall_filter_positive_line_precedes_inverse_line() {
    // Per systemd.exec(5), `SystemCallFilter=~X` removes X from
    // the running allowlist when emitted AFTER a positive
    // (non-`~`) line, but is a no-op when emitted BEFORE one (no
    // running set to subtract from). A subsequent positive line
    // would then re-include the groups the operator wanted to
    // deny. The runner template MUST emit the positive line first,
    // then the `~`-prefixed denylist.
    //
    // This test pins the order at the template-text level so a
    // refactor that re-orders the lines (e.g. alphabetizing
    // directives, moving the comment block) cannot silently
    // disable the denylist.
    let t = runner_template_text();
    let positive_idx = t
        .find(
            "SystemCallFilter=@system-service pkey_alloc pkey_mprotect pkey_free perf_event_open",
        )
        .expect("positive SystemCallFilter line must be present");
    let inverse_idx = t
        .find("SystemCallFilter=~@mount @clock @keyring")
        .expect("inverse SystemCallFilter line must be present");
    assert!(
        positive_idx < inverse_idx,
        "positive SystemCallFilter= line must precede the ~-prefixed denylist; \
         positive@{positive_idx} inverse@{inverse_idx}"
    );
}

#[test]
fn unit_path_env_present_and_well_formed() {
    // Python parity: test_unit_path_env_present + test_unit_path_env_no_*.
    let t = runner_template_text();
    let path_lines: Vec<&str> = t
        .lines()
        .filter(|l| l.starts_with("Environment=PATH="))
        .collect();
    assert_eq!(
        path_lines.len(),
        1,
        "expected exactly one Environment=PATH= line"
    );
    let value = path_lines[0]
        .strip_prefix("Environment=PATH=")
        .expect("we just filtered for this prefix");
    // No empty components.
    assert!(!value.is_empty());
    assert!(!value.starts_with(':'));
    assert!(!value.ends_with(':'));
    assert!(!value.contains("::"));
}

#[test]
fn unit_path_env_contains_required_dirs() {
    // Python parity: test_unit_path_env_contains_required_dirs.
    let t = runner_template_text();
    let path_line = t
        .lines()
        .find(|l| l.starts_with("Environment=PATH="))
        .expect("PATH line present");
    let value = path_line
        .strip_prefix("Environment=PATH=")
        .expect("we just filtered for this prefix");
    let entries: Vec<&str> = value.split(':').collect();
    for required in [
        "/usr/lib64/ccache",
        "/usr/lib/ccache",
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ] {
        assert!(entries.contains(&required), "PATH missing {required}");
    }
    let pos_lib64_ccache = entries.iter().position(|e| *e == "/usr/lib64/ccache");
    let pos_lib_ccache = entries.iter().position(|e| *e == "/usr/lib/ccache");
    let pos_usr_bin = entries.iter().position(|e| *e == "/usr/bin");
    assert!(
        pos_lib64_ccache < pos_usr_bin,
        "ccache must shadow real compilers"
    );
    assert!(
        pos_lib_ccache < pos_usr_bin,
        "ccache must shadow real compilers"
    );
}

#[test]
fn unit_path_env_within_allowed_roots() {
    // Python parity: test_unit_path_env_within_allowed_roots.
    // Every PATH entry must be /usr/* or /bin[/...] or /sbin[/...]. All
    // three roots are bound into the runner's locked-down namespace via
    // BindReadOnlyPaths.
    let t = runner_template_text();
    let path_line = t
        .lines()
        .find(|l| l.starts_with("Environment=PATH="))
        .expect("PATH line present");
    let value = path_line
        .strip_prefix("Environment=PATH=")
        .expect("we just filtered for this prefix");
    for entry in value.split(':') {
        assert!(entry.starts_with('/'), "PATH entry not absolute: {entry:?}");
        assert!(entry.len() > 1, "PATH entry too short: {entry:?}");
        let in_usr = entry.starts_with("/usr/");
        let in_bin = entry == "/bin" || entry.starts_with("/bin/");
        let in_sbin = entry == "/sbin" || entry.starts_with("/sbin/");
        assert!(
            in_usr || in_bin || in_sbin,
            "PATH entry {entry} not under /usr, /bin, or /sbin"
        );
    }
}

#[test]
fn unit_path_env_excludes_runner_state_dir() {
    // Python parity: test_unit_path_env_excludes_runner_dirs. The
    // template uses /var/lib/ghars/%i — that path must NOT appear in
    // PATH. Tools resolve via the runner's own scripts, not via PATH
    // lookup.
    let t = runner_template_text();
    let path_line = t
        .lines()
        .find(|l| l.starts_with("Environment=PATH="))
        .expect("PATH line present");
    let value = path_line
        .strip_prefix("Environment=PATH=")
        .expect("we just filtered for this prefix");
    let entries: Vec<&str> = value.split(':').collect();
    assert!(!entries.contains(&"/var/lib/ghars"));
    for entry in &entries {
        assert!(
            !entry.starts_with("/var/lib/ghars/"),
            "PATH leaks runner state: {entry}"
        );
        assert!(
            !entry.starts_with("/var/cache/ghars"),
            "PATH leaks runner cache: {entry}"
        );
    }
}

#[test]
fn unit_lang_env_present() {
    // Python parity: test_unit_lang_env_present.
    let t = runner_template_text();
    assert!(t.contains("Environment=LANG=C.UTF-8"));
}

#[test]
fn unit_template_has_no_proxy_leak() {
    // Python parity: test_unit_no_proxy_leak. The template must NOT
    // hardcode any of these env-var names — proxy + CA-bundle + LD_*
    // env vars are emitted only by the proxy drop-in (60-proxy.conf)
    // when [proxy] config is set.
    let t = runner_template_text();
    for forbidden in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "CARGO_HTTP_MULTIPLEXING",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LD_AUDIT",
    ] {
        assert!(!t.contains(forbidden), "template leaks {forbidden}");
    }
}

#[test]
fn unit_template_has_no_nft_or_legacy_address_filtering() {
    // Python parity: test_unit_no_nft. The runner template must not
    // bake in nft commands or IPAddressDeny/Allow / RestrictAddressFamilies
    // lines — those are emitted by 40-network.conf only when a netns
    // mode is selected.
    let t = runner_template_text();
    assert!(!t.contains("nft"));
    assert!(!t.contains("IPAddressDeny"));
    assert!(!t.contains("IPAddressAllow"));
    assert!(!t.contains("RestrictAddressFamilies"));
}

#[test]
fn unit_filesystem_allowlist_curated_etc_paths() {
    // Python parity: test_unit_filesystem_allowlist. Curated /etc list +
    // /usr root + optional merged-usr `-/lib /lib64` paths.
    let t = runner_template_text();
    assert!(t.contains("TemporaryFileSystem=/:ro"));
    assert!(t.contains("BindReadOnlyPaths=/usr -/lib -/lib64 -/bin -/sbin"));
    // /etc/resolv.conf is intentionally OUTSIDE the curated /etc list:
    // netns-mode runners bind-mount a generated resolv.conf via
    // `ghars _netns-setup` (Part 9c Challenge 1, DnsMode::Forward) so
    // baking the host's resolv.conf into the runner template would
    // either fight that mount or leak host DNS into open-mode runners
    // who shouldn't see it. Open-mode runners read resolv.conf from
    // the host filesystem through TemporaryFileSystem=/:ro's pass-
    // through of /etc bind targets that ARE in the list below.
    assert!(t.contains("BindReadOnlyPaths=/etc/hosts /etc/nsswitch.conf"));
    assert!(t.contains("BindReadOnlyPaths=/etc/passwd /etc/group"));
    assert!(t.contains("BindReadOnlyPaths=/etc/ssl /etc/ca-certificates -/etc/pki"));
    assert!(t.contains("BindReadOnlyPaths=-/etc/locale.conf /etc/localtime"));
    assert!(t.contains("BindReadOnlyPaths=/etc/ld.so.cache -/etc/ld.so.conf.d"));
    assert!(t.contains("BindReadOnlyPaths=-/etc/protocols -/etc/services"));
    assert!(t.contains("BindReadOnlyPaths=-/etc/alternatives"));
    assert!(t.contains("BindReadOnlyPaths=-/etc/os-release"));
    assert!(t.contains("BindReadOnlyPaths=-/etc/gitconfig"));
    // Bare /etc and /sys binds must not appear.
    for line in t.lines() {
        let trimmed = line.trim();
        assert_ne!(trimmed, "BindReadOnlyPaths=/etc", "uncurated /etc bind");
        assert_ne!(trimmed, "BindReadOnlyPaths=/sys", "redundant /sys bind");
    }
}

#[test]
fn unit_private_devices_yes() {
    // Python parity: test_unit_private_devices.
    let t = runner_template_text();
    assert!(t.contains("PrivateDevices=yes"));
}

#[test]
fn unit_restart_and_start_limit() {
    // Python parity: test_unit_restart_and_start_limit.
    let t = runner_template_text();
    assert!(t.contains("Restart=always"));
    assert!(t.contains("RestartSec=10"));
    assert!(t.contains("StartLimitIntervalSec=300"));
    assert!(t.contains("StartLimitBurst=5"));
}

#[test]
fn unit_journal_rate_limit() {
    // Python parity: test_unit_journal_rate_limit.
    let t = runner_template_text();
    assert!(t.contains("LogRateLimitIntervalSec=30s"));
    assert!(t.contains("LogRateLimitBurst=10000"));
}

#[test]
fn unit_uses_dynamic_user_not_root() {
    // The template declares DynamicUser=yes and has no per-runner
    // User= or Group= line — the User= name (ghars-tz-<TRUST_ZONE>)
    // is set in the per-runner 00-ghars.conf drop-in so trust-zone-
    // shared runners receive the same DynamicUser-allocated UID.
    let t = runner_template_text();
    assert!(t.contains("\nDynamicUser=yes\n"));
    assert!(!t.contains("User=ghars-%i"));
    assert!(!t.contains("Group=ghars-%i"));
    assert!(!t.contains("User=root"), "runner must not run as root");
}

#[test]
fn render_runner_unit_no_proxy_drop_in_when_proxy_unset() {
    // The template carries no proxy env vars. Without a [proxy] config
    // the 60-proxy.conf drop-in must also be absent — otherwise the
    // proxy env would slip in via the drop-in.
    let spec = minimal_spec("buckos");
    let r = render_runner_unit(&spec).unwrap();
    assert!(!r.drop_ins.contains_key("60-proxy.conf"));
    // No drop-in body contains a proxy env var either.
    for body in r.drop_ins.values() {
        for forbidden in ["HTTP_PROXY", "HTTPS_PROXY", "REQUESTS_CA_BUNDLE"] {
            assert!(!body.contains(forbidden), "drop-in leaks {forbidden}");
        }
    }
}

#[test]
fn render_runner_unit_memory_drop_in_emitted_when_set() {
    // Python parity: test_unit_memory_max_sets_directive. The template
    // doesn't carry MemoryMax= — it lives in 10-memory.conf.
    for value in ["110G", "50%", "infinity"] {
        let mut spec = minimal_spec("buckos");
        spec.memory_max = Some((*value).into());
        let r = render_runner_unit(&spec).unwrap();
        let m = r.drop_ins.get("10-memory.conf").unwrap();
        assert!(m.contains(&format!("MemoryMax={value}")));
    }
}

#[test]
fn render_runner_unit_no_memory_drop_in_when_unset() {
    // Python parity: test_unit_memory_max_empty_has_no_directive.
    let spec = minimal_spec("buckos");
    let r = render_runner_unit(&spec).unwrap();
    assert!(!r.drop_ins.contains_key("10-memory.conf"));
}

#[test]
fn render_runner_unit_state_directory_paths_per_trust_zone() {
    // ConditionPathExists / WorkingDirectory / StateDirectory / HOME
    // live in the per-runner drop-in because the path components
    // depend on the runner's trust_zone (a render-time substitution
    // the systemd `%i` specifier cannot express alone). The template
    // body contains only the `StateDirectoryMode=0700` directive.
    let spec = minimal_spec("buckos");
    let r = render_runner_unit(&spec).unwrap();
    let body = r
        .drop_ins
        .get("00-ghars.conf")
        .expect("00-ghars.conf");
    assert!(body.contains("ConditionPathExists=/var/lib/ghars/default/ghars-buckos/runsvc.sh"));
    assert!(body.contains("WorkingDirectory=/var/lib/ghars/default/ghars-buckos"));
    assert!(body.contains("Environment=HOME=/var/lib/ghars/default/ghars-buckos"));
    assert!(body.contains("StateDirectory=ghars/default/ghars-buckos"));
    let t = runner_template_text();
    assert!(t.contains("StateDirectoryMode=0700"));
}
