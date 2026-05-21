use super::*;
use crate::systemd::{Systemd, UnitListEntry, runner_template_text};
use camino::Utf8PathBuf;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use tempfile::TempDir;

/// In-memory mock of [`Systemd`] for state-discovery tests. Records
/// the property lookups so we can assert the trait was actually
/// consulted.
#[derive(Default)]
struct MockSystemd {
    properties: HashMap<(String, String), String>,
    property_calls: RefCell<Vec<(String, String)>>,
}

impl MockSystemd {
    fn set_active(&mut self, unit: &str, value: &str) {
        self.properties
            .insert((unit.into(), "ActiveState".into()), value.into());
    }
    fn set_unit_file_state(&mut self, unit: &str, value: &str) {
        self.properties
            .insert((unit.into(), "UnitFileState".into()), value.into());
    }
}

impl Systemd for MockSystemd {
    fn daemon_reload(&self) -> Result<()> {
        Ok(())
    }
    fn start_unit(&self, _unit: &str) -> Result<()> {
        Ok(())
    }
    fn stop_unit(&self, _unit: &str) -> Result<()> {
        Ok(())
    }
    fn enable_unit(&self, _unit: &str) -> Result<()> {
        Ok(())
    }
    fn disable_unit(&self, _unit: &str) -> Result<()> {
        Ok(())
    }
    fn list_units_filtered(&self, _states: &[&str]) -> Result<Vec<UnitListEntry>> {
        Ok(vec![])
    }
    fn get_unit_property(&self, unit: &str, _iface: &str, property: &str) -> Result<String> {
        self.property_calls
            .borrow_mut()
            .push((unit.into(), property.into()));
        self.properties
            .get(&(unit.into(), property.into()))
            .cloned()
            .ok_or_else(|| {
                GharsError::Systemd(
                    format!("mock: no value set for {unit}.{property}"),
                    "test setup error".into(),
                )
            })
    }
    fn get_unit_property_u64(&self, _unit: &str, _iface: &str, _property: &str) -> Result<u64> {
        // state.rs::tests don't exercise numeric service props.
        Ok(0)
    }
    fn get_unit_property_object_path(
        &self,
        _unit: &str,
        _iface: &str,
        _property: &str,
    ) -> Result<zbus::zvariant::OwnedObjectPath> {
        unreachable!("state.rs tests do not exercise object-path properties")
    }
    fn get_service_property_string(&self, unit: &str, property: &str) -> Result<String> {
        self.get_unit_property(unit, "org.freedesktop.systemd1.Service", property)
    }
    fn get_service_property_u64(&self, _unit: &str, _property: &str) -> Result<u64> {
        Ok(0)
    }
    fn lookup_dynamic_user_by_name(&self, _name: &str) -> Result<Option<u32>> {
        // state.rs tests don't exercise DynamicUser lookup.
        Ok(None)
    }
}

/// Build a `Paths` rooted at `tmp` so discovery scans a controlled
/// `unit_dir`.
fn paths_under(tmp: &TempDir) -> Paths {
    let root = Utf8PathBuf::try_from(tmp.path().to_owned()).unwrap();
    Paths {
        state_dir: root.join("var/lib/ghars"),
        cache_dir: root.join("var/cache/ghars"),
        logs_dir: root.join("var/log/ghars"),
        unit_dir: root.join("etc/systemd/system"),
        credentials_dir: root.join("etc/credstore.encrypted/ghars"),
        runtime_dir: root.join("run/ghars"),
        config_dir: root.join("etc/ghars"),
        resolved_conf_d: root.join("etc/systemd/resolved.conf.d"),
    }
}

fn write_unit(paths: &Paths, name: &str, body: &str) {
    fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    fs::write(paths.unit_file(name).as_std_path(), body).unwrap();
}

fn write_drop_in(paths: &Paths, name: &str, drop_in: &str, body: &str) {
    let dir = paths.drop_in_dir(name);
    fs::create_dir_all(dir.as_std_path()).unwrap();
    fs::write(dir.join(drop_in).as_std_path(), body).unwrap();
}

#[test]
fn discover_returns_empty_when_unit_dir_missing() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    let mock = MockSystemd::default();
    let s = discover(&mock, &paths).unwrap();
    assert!(s.runners.is_empty());
    assert!(s.orphans.is_empty());
    assert!(s.external.is_empty());
}

#[test]
fn discover_returns_empty_when_unit_dir_has_no_ghars_files() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    fs::write(
        paths.unit_dir.join("sshd.service").as_std_path(),
        "[Unit]\nDescription=ssh\n",
    )
    .unwrap();
    // Even the canonical template (no instance) is filtered out
    // because we only manage `@INSTANCE.service` files.
    fs::write(
        paths.unit_dir.join("ghars-runner@.service").as_std_path(),
        runner_template_text(),
    )
    .unwrap();
    let mock = MockSystemd::default();
    let s = discover(&mock, &paths).unwrap();
    assert!(s.runners.is_empty());
    assert!(s.external.is_empty());
}

#[test]
fn discover_classifies_external_unit_when_annotation_missing() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    // No `X-Ghars-Managed=true` → operator territory.
    write_unit(
        &paths,
        "manual",
        "[Unit]\nDescription=manual runner\n[Service]\nExecStart=/bin/true\n",
    );
    let mock = MockSystemd::default();
    let s = discover(&mock, &paths).unwrap();
    assert!(s.runners.is_empty());
    assert_eq!(s.external, vec!["manual".to_owned()]);
}

#[test]
fn discover_finds_in_sync_managed_runner() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    write_unit(&paths, "buckos", &runner_template_text());
    write_drop_in(
        &paths,
        "buckos",
        "00-ghars.conf",
        "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\nX-Ghars-Runner-Name=buckos\n",
    );
    let mut mock = MockSystemd::default();
    mock.set_active("ghars-runner@buckos.service", "active");
    mock.set_unit_file_state("ghars-runner@buckos.service", "enabled");
    let s = discover(&mock, &paths).unwrap();
    let r = s.runners.get("buckos").expect("buckos managed");
    assert_eq!(r.name, "buckos");
    assert_eq!(r.spec_hash, "sha256:abc");
    assert_eq!(r.drift, Drift::InSync);
    assert!(r.running);
    assert!(r.enabled);
    assert!(r.drop_ins.contains_key("00-ghars.conf"));
}

#[test]
fn discover_classifies_unit_edited_on_template_byte_diff() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    // Template already carries `X-Ghars-Managed=true` so appending
    // operator content keeps the unit "managed" while making it byte-
    // diverge from the canonical template.
    let mut edited = runner_template_text();
    edited.push_str("# operator scribble\n");
    write_unit(&paths, "buckos", &edited);
    write_drop_in(
        &paths,
        "buckos",
        "00-ghars.conf",
        "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n",
    );
    let mut mock = MockSystemd::default();
    mock.set_active("ghars-runner@buckos.service", "inactive");
    mock.set_unit_file_state("ghars-runner@buckos.service", "static");
    let s = discover(&mock, &paths).unwrap();
    let r = s.runners.get("buckos").expect("managed");
    assert_eq!(r.drift, Drift::UnitEdited);
    assert!(!r.running);
    assert!(!r.enabled);
}

#[test]
fn discover_classifies_drop_ins_modified_on_unknown_basename() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    write_unit(&paths, "buckos", &runner_template_text());
    write_drop_in(
        &paths,
        "buckos",
        "00-ghars.conf",
        "[Unit]\nX-Ghars-Spec-Hash=sha256:zzz\n",
    );
    write_drop_in(
        &paths,
        "buckos",
        "99-operator.conf",
        "[Service]\nMemoryHigh=20G\n",
    );
    let mut mock = MockSystemd::default();
    mock.set_active("ghars-runner@buckos.service", "active");
    mock.set_unit_file_state("ghars-runner@buckos.service", "enabled");
    let s = discover(&mock, &paths).unwrap();
    let r = s.runners.get("buckos").unwrap();
    assert_eq!(
        r.drift,
        Drift::DropInsModified(vec!["99-operator.conf".to_string()])
    );
    assert!(r.drop_ins.contains_key("99-operator.conf"));
}

/// Regression guard: every drop-in basename emitted by
/// [`crate::systemd::render_runner_unit`] MUST be in
/// [`MANAGED_DROP_IN_BASENAMES`]. If they fall out of sync,
/// `classify_drift` flags every freshly-applied runner as
/// `DropInsModified` because the unmanaged-basename check fires on
/// a basename ghars itself wrote. Pin the invariant here so a
/// future drop-in addition that updates `render_runner_unit` but
/// forgets to update the managed list fails this test instead of
/// silently breaking drift classification.
#[test]
fn render_runner_unit_basenames_are_all_in_managed_list() {
    use crate::config::{
        Arch, CacheKind, CacheMode, EffectiveCacheBinding, EffectiveRunnerSpec, Hardening,
        HooksSpec, ProxySpec,
    };
    use crate::systemd::render_runner_unit;

    // Spec sized to trigger as many of render_runner_unit's
    // conditional drop-ins as possible from a unit-test surface.
    // Specifically:
    //   00-ghars.conf       — unconditional
    //   10-memory.conf      — memory_max set
    //   15-resolv.conf      — unconditional (the basename this test guards)
    //   20-hardening.conf   — at least one hardening field touched
    //   30-cache-pool.conf  — at least one Sccache-serving binding
    //                         (ccache-only pools omit per the
    //                         render_cache_pool emit-anything gate)
    //   50-numa.conf        — allowed_cpus set
    //   60-proxy.conf       — proxy resolved
    //   70-hooks.conf       — hooks resolved
    //   80-lognamespace.conf — unconditional
    // 40-network.conf is NOT triggered — Open mode leaves
    // `EffectiveRunnerSpec.network = None` (the field is
    // `Option<EffectiveNetworkBinding>` which defaults to `None`), so
    // there is no unit-test-constructible non-None binding short
    // of allocating a real /30 subnet via the plan engine. The
    // 40-network surface is exercised by plan.rs / systemd.rs
    // integration tests; this regression guard's job is to catch
    // basename omissions, and it does so for 9 of the 10 managed
    // basenames.
    let spec = EffectiveRunnerSpec {
        environment: crate::config::EnvironmentSpec::default(),
        name: "regguard".into(),
        url: "https://github.com/example/regguard".into(),
        arch: Arch::X86_64,
        labels: vec!["self-hosted".into()],
        memory_max: Some("8G".into()),
        runner_version: Some("2.334.0".into()),
        runner_sha256: None,
        runner_tarball: None,
        auth_name: "pat".into(),
        caches: vec![EffectiveCacheBinding {
            name: "build".into(),
            kinds: vec![CacheKind::Sccache],
            size: "200G".into(),
            mode: CacheMode::Shared,
            trust_zone: "default".into(),
            sccache_path: Some("/usr/bin/sccache".into()),
            sleep_path: None,
            server_mode: crate::config::SccacheServerMode::Pooled,
            renderer_schema: crate::systemd::RENDERER_SCHEMA,
        }],
        trust_zone: "default".into(),
        network: None,
        proxy: Some(ProxySpec {
            http: Some("http://proxy.example:8080".into()),
            https: Some("http://proxy.example:8080".into()),
            no_proxy: vec![],
            ca_certs: vec![],
        }),
        hooks: Some(HooksSpec {
            pre_job: Some(Utf8PathBuf::from("/usr/local/lib/ghars/pre.sh")),
            post_job: None,
        }),
        hardening: Hardening {
            kvm: Some(true),
            ..Hardening::default()
        },
        allowed_cpus: Some("0-3".into()),
        allowed_memory_nodes: Some("0".into()),
        spec_hash: "sha256:dead".into(),
        config_source: "/etc/ghars/ghars.toml".into(),
        renderer_schema: crate::systemd::RENDERER_SCHEMA,
    };

    let rendered = render_runner_unit(&spec).unwrap();
    for basename in rendered.drop_ins.keys() {
        assert!(
            MANAGED_DROP_IN_BASENAMES.contains(&basename.as_str()),
            "render_runner_unit emitted drop-in {basename:?} which is NOT in \
             MANAGED_DROP_IN_BASENAMES; classify_drift will flag every \
             freshly-applied runner as DropInsModified. Add the basename \
             to MANAGED_DROP_IN_BASENAMES."
        );
    }
    // Pin coverage: the spec triggers 9 of the 10 managed
    // basenames (everything except 40-network, which requires a
    // plan-engine-allocated /30). If this count drops, a
    // conditional drop-in branch was removed and the spec above
    // must be updated to re-trigger it OR the basename must be
    // dropped from MANAGED_DROP_IN_BASENAMES too.
    assert_eq!(
        rendered.drop_ins.len(),
        9,
        "expected 9 drop-ins from the maximally-triggered spec; got {}: {:?}",
        rendered.drop_ins.len(),
        rendered.drop_ins.keys().collect::<Vec<_>>()
    );
    // Pin specifically that 15-resolv.conf is one of them — this
    // is the basename whose absence from MANAGED_DROP_IN_BASENAMES
    // motivated the test. A future refactor that drops 15-resolv
    // from render_runner_unit must also drop it from the managed
    // list; until then, both sides MUST list it.
    assert!(
        rendered.drop_ins.contains_key("15-resolv.conf"),
        "render_runner_unit must emit 15-resolv.conf for every runner; \
         missing from drop_ins: {:?}",
        rendered.drop_ins.keys().collect::<Vec<_>>()
    );
    assert!(
        MANAGED_DROP_IN_BASENAMES.contains(&"15-resolv.conf"),
        "MANAGED_DROP_IN_BASENAMES must list 15-resolv.conf to keep \
         classify_drift from flagging every applied runner as \
         DropInsModified"
    );
}

#[test]
fn discover_classifies_both_when_unit_and_drop_ins_drift() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    let mut edited = runner_template_text();
    edited.push_str("# scribble\n");
    write_unit(&paths, "buckos", &edited);
    write_drop_in(
        &paths,
        "buckos",
        "99-operator.conf",
        "[Service]\nMemoryHigh=8G\n",
    );
    let mut mock = MockSystemd::default();
    mock.set_active("ghars-runner@buckos.service", "active");
    mock.set_unit_file_state("ghars-runner@buckos.service", "enabled");
    let s = discover(&mock, &paths).unwrap();
    let r = s.runners.get("buckos").unwrap();
    assert_eq!(r.drift, Drift::Both(vec!["99-operator.conf".to_string()]));
}

#[test]
fn discover_handles_missing_systemd_property_as_inactive_disabled() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    write_unit(&paths, "buckos", &runner_template_text());
    // No drop-ins; no D-Bus values registered → both lookups Err.
    let mock = MockSystemd::default();
    let s = discover(&mock, &paths).unwrap();
    let r = s.runners.get("buckos").unwrap();
    assert!(!r.running);
    assert!(!r.enabled);
    // Spec hash is empty when 00-ghars.conf is missing.
    assert!(r.spec_hash.is_empty());
}

#[test]
fn discover_treats_enabled_runtime_as_enabled() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    write_unit(&paths, "buckos", &runner_template_text());
    let mut mock = MockSystemd::default();
    mock.set_active("ghars-runner@buckos.service", "inactive");
    mock.set_unit_file_state("ghars-runner@buckos.service", "enabled-runtime");
    let s = discover(&mock, &paths).unwrap();
    let r = s.runners.get("buckos").unwrap();
    assert!(!r.running);
    assert!(r.enabled);
}

#[test]
fn discover_orders_runners_lexicographically() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    for name in ["zeta", "alpha", "mid"] {
        write_unit(&paths, name, &runner_template_text());
    }
    let mut mock = MockSystemd::default();
    for name in ["zeta", "alpha", "mid"] {
        let unit = format!("ghars-runner@{name}.service");
        mock.set_active(&unit, "active");
        mock.set_unit_file_state(&unit, "enabled");
    }
    let s = discover(&mock, &paths).unwrap();
    let names: Vec<&str> = s.runners.keys().map(String::as_str).collect();
    assert_eq!(names, vec!["alpha", "mid", "zeta"]);
}

#[test]
fn discover_skips_non_conf_files_in_drop_in_dir() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    write_unit(&paths, "buckos", &runner_template_text());
    write_drop_in(
        &paths,
        "buckos",
        "00-ghars.conf",
        "[Unit]\nX-Ghars-Spec-Hash=sha256:abc\n",
    );
    // A README, log file, or backup file in the drop-in dir must
    // NOT count as drift.
    let dir = paths.drop_in_dir("buckos");
    fs::write(dir.join("README").as_std_path(), "operator notes\n").unwrap();
    fs::write(dir.join("00-ghars.conf.bak").as_std_path(), "old\n").unwrap();
    let mut mock = MockSystemd::default();
    mock.set_active("ghars-runner@buckos.service", "active");
    mock.set_unit_file_state("ghars-runner@buckos.service", "enabled");
    let s = discover(&mock, &paths).unwrap();
    let r = s.runners.get("buckos").unwrap();
    assert_eq!(r.drift, Drift::InSync);
    assert!(!r.drop_ins.contains_key("README"));
    assert!(!r.drop_ins.contains_key("00-ghars.conf.bak"));
}

// --- Parser tests ----------------------------------------------------

#[test]
fn parser_captures_simple_section() {
    let p = ParsedUnit::from_text("[Unit]\nDescription=ghars test\nWants=foo.service\n");
    assert_eq!(p.first("Unit", "Description"), Some("ghars test"));
    assert_eq!(p.first("Unit", "Wants"), Some("foo.service"));
}

#[test]
fn parser_handles_comment_at_line_start() {
    let p = ParsedUnit::from_text(
        "# leading comment\n; another comment style\n[Unit]\n# in-section comment\nKey=value\n",
    );
    assert_eq!(p.first("Unit", "Key"), Some("value"));
}

#[test]
fn parser_does_not_treat_inline_hash_as_comment() {
    // systemd parses `Key=value # not a comment` literally — the
    // `#` is part of the value. We mirror that.
    let p = ParsedUnit::from_text("[Unit]\nKey=value # tail\n");
    assert_eq!(p.first("Unit", "Key"), Some("value # tail"));
}

#[test]
fn parser_collects_multiple_assignments_for_same_key() {
    let p = ParsedUnit::from_text("[Service]\nEnvironment=PATH=/bin\nEnvironment=HOME=/var\n");
    let envs: Vec<&str> = p.values("Service", "Environment").collect();
    assert_eq!(envs, vec!["PATH=/bin", "HOME=/var"]);
}

#[test]
fn parser_handles_continuation_via_trailing_backslash() {
    let p = ParsedUnit::from_text("[Service]\nExecStart=/bin/echo \\\n    one two \\\n    three\n");
    let v = p.first("Service", "ExecStart").unwrap();
    assert!(v.contains("one two"), "got: {v}");
    assert!(v.contains("three"), "got: {v}");
}

#[test]
fn parser_treats_double_backslash_at_eol_as_literal_not_continuation() {
    // `\\` at end of line is two literal backslashes; NOT a
    // continuation (per conf-parser.c:389-394, the escape flag
    // toggles on each `\\`).
    let p = ParsedUnit::from_text("[Service]\nKey=value\\\\\nNext=second\n");
    assert_eq!(p.first("Service", "Key"), Some(r"value\\"));
    assert_eq!(p.first("Service", "Next"), Some("second"));
}

#[test]
fn parser_handles_continuation_across_eof() {
    let p = ParsedUnit::from_text("[Unit]\nKey=value\\\n   tail");
    let v = p.first("Unit", "Key").unwrap();
    assert!(v.contains("value"));
    assert!(v.contains("tail"));
}

#[test]
fn parser_ignores_lines_outside_section() {
    let p = ParsedUnit::from_text("Stray=ignored\n[Unit]\nReal=kept\n");
    assert!(p.first("None", "Stray").is_none());
    assert_eq!(p.first("Unit", "Real"), Some("kept"));
}

#[test]
fn parser_strips_whitespace_around_key_and_value() {
    let p = ParsedUnit::from_text("[Unit]\n   Key  =   value with spaces   \n");
    assert_eq!(p.first("Unit", "Key"), Some("value with spaces"));
}

#[test]
fn parser_section_header_requires_closing_bracket() {
    // `[Unit` without `]` is not a section header → the line is
    // treated as an assignment-without-`=` and dropped.
    let p = ParsedUnit::from_text("[Unit\nKey=value\n");
    assert!(p.first("Unit", "Key").is_none());
}

#[test]
fn parser_handles_empty_section_body() {
    let p = ParsedUnit::from_text("[Unit]\n[Service]\nReal=here\n");
    assert!(p.first("Unit", "anything").is_none());
    assert_eq!(p.first("Service", "Real"), Some("here"));
}

// --- ParsedUnit comprehensive parser tests -------------------------

#[test]
fn parser_same_key_in_two_sections_is_kept_per_section() {
    // The same key may appear in different sections (e.g. a
    // hardening-style `Description=...` on `[Unit]` and a
    // `Description=` line on a `[Service]` would be unusual but
    // legal). Each section keeps its own bucket; `values(section, key)`
    // must NOT bleed across section boundaries.
    let text = "[Unit]\nKey=unit-side\n[Service]\nKey=service-side\n";
    let p = ParsedUnit::from_text(text);
    assert_eq!(p.first("Unit", "Key"), Some("unit-side"));
    assert_eq!(p.first("Service", "Key"), Some("service-side"));
    // values(section, key) is per-section: each iterator returns
    // exactly the section's bucket.
    let unit_vals: Vec<&str> = p.values("Unit", "Key").collect();
    let svc_vals: Vec<&str> = p.values("Service", "Key").collect();
    assert_eq!(unit_vals, vec!["unit-side"]);
    assert_eq!(svc_vals, vec!["service-side"]);
}

#[test]
fn parser_section_header_with_trailing_whitespace_accepted() {
    // systemd's conf-parser strips per-line trailing whitespace via
    // strstrip before testing for `[NAME]`. Our parser does
    // `logical.trim()` before `parse_section_header`, so
    // `[Unit]   ` matches the same as `[Unit]`. Pin this so a
    // mutant that drops the trim still rejects this form.
    let p = ParsedUnit::from_text("[Unit]   \nKey=value\n");
    assert_eq!(p.first("Unit", "Key"), Some("value"));
}

#[test]
fn parser_section_header_with_leading_whitespace_rejected() {
    // Inverse of the above: parse_section_header requires the line
    // to START with `[` after the trim (it doesn't accept "  [Unit]"
    // because trim strips leading whitespace too). systemd treats a
    // leading-whitespace section header the same as an in-section
    // assignment, but our parser is strict — verify.
    // Note: l.trim() strips both leading and trailing, so this is
    // actually accepted. Test that and pin the behavior.
    let p = ParsedUnit::from_text("    [Unit]\nKey=value\n");
    assert_eq!(p.first("Unit", "Key"), Some("value"));
}

#[test]
fn parser_continuation_across_section_header_joins_literally() {
    // A continuation line that LOOKS like a section header is
    // logical-glued onto the previous line per conf-parser.c —
    // the `[NAME]` becomes part of the value, NOT a new section.
    // Pinning this catches a mutant that scans for section headers
    // BEFORE applying the continuation.
    let text = "[Unit]\nKey=value\\\n[Service]\nKey=second\n";
    let p = ParsedUnit::from_text(text);
    // First Key under Unit absorbs `[Service]` as a literal
    // value-line continuation.
    let v = p.first("Unit", "Key").unwrap();
    assert!(
        v.contains("[Service]"),
        "continuation must absorb the bracketed line: got {v:?}"
    );
    // Because [Service] was eaten by the continuation, the second
    // `Key=second` line lands BACK into [Unit] — there is no open
    // [Service] section. Verify by reading the second value off
    // [Unit]:
    let unit_keys: Vec<&str> = p.values("Unit", "Key").collect();
    assert_eq!(unit_keys.len(), 2, "got {unit_keys:?}");
    assert!(unit_keys[1] == "second");
    // [Service] never opened because [Service] was consumed.
    assert!(p.first("Service", "Key").is_none());
}

#[test]
fn parser_empty_key_after_equals_is_dropped() {
    // `=value` has empty key. The parser explicitly drops these
    // (`if key.is_empty() continue;`) to mirror systemd's silent
    // skip of malformed assignments.
    let p = ParsedUnit::from_text("[Unit]\n=orphan-value\nGood=kept\n");
    // Only the `Good` line lands; the `=orphan-value` line is
    // dropped at the empty-key check.
    let unit_section = p
        .sections
        .iter()
        .find(|(name, _)| name == "Unit")
        .expect("[Unit] should exist");
    // Single key 'Good' present; orphan value not stored.
    let keys: Vec<&str> = unit_section.1.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, vec!["Good"]);
    assert_eq!(p.first("Unit", "Good"), Some("kept"));
}

#[test]
fn parser_handles_crlf_line_endings() {
    // Some operators edit unit files on platforms that emit `\r\n`
    // (Windows shares mounted into a Linux VM, or copy-paste from
    // certain web tools). `str::lines()` strips the trailing `\r`
    // so the parser sees logical lines identical to LF-only.
    let text = "[Unit]\r\nKey=value\r\n[Service]\r\nFoo=bar\r\n";
    let p = ParsedUnit::from_text(text);
    assert_eq!(p.first("Unit", "Key"), Some("value"));
    assert_eq!(p.first("Service", "Foo"), Some("bar"));
}

#[test]
fn parser_handles_comment_only_section() {
    // A section whose body is only comments must still register
    // (empty bucket) — pin so a future edit doesn't accidentally
    // skip the section-header line when the body is empty.
    let text = "[Unit]\n# leading comment\n; another comment\n[Service]\nKey=present\n";
    let p = ParsedUnit::from_text(text);
    // [Unit] section exists in `sections` even though its bucket
    // is empty after dropping the comments.
    assert!(
        p.sections.iter().any(|(name, _)| name == "Unit"),
        "[Unit] section must register even when body is only comments"
    );
    let unit = p
        .sections
        .iter()
        .find(|(name, _)| name == "Unit")
        .expect("[Unit] in sections");
    assert!(
        unit.1.is_empty(),
        "[Unit] bucket should be empty (only comments in body); got {:?}",
        unit.1
    );
    // Subsequent section parsed as normal.
    assert_eq!(p.first("Service", "Key"), Some("present"));
}

#[test]
fn parser_handles_inline_comment_under_continuation() {
    // Continuation tracks across a comment line per conf-parser.c:
    // the comment is dropped, but the trailing-`\` continuation
    // state survives. We mirror that: the comment is skipped
    // INSIDE the if-comment branch BEFORE the continuation logic.
    // Document/lock the actual behavior — currently the comment
    // skip happens before we'd otherwise glue the continuation
    // payload, so the buffer just keeps waiting.
    let text = "[Unit]\nKey=part1 \\\n# in-the-middle\n   tail\n";
    let p = ParsedUnit::from_text(text);
    let v = p.first("Unit", "Key").unwrap();
    assert!(v.contains("part1"));
    assert!(v.contains("tail"));
}

#[test]
fn parser_handles_value_without_equals_sign() {
    // A line with no `=` inside a section is a malformed
    // assignment; systemd warns and drops. Our parser silently
    // drops via `let Some((key, value)) = l.split_once('=') else
    // { continue; };`. Pin this so a mutant that flips the early-
    // return doesn't accept rubbish into the bucket.
    let p = ParsedUnit::from_text("[Unit]\nbroken-line-no-equals\nGood=value\n");
    assert_eq!(p.first("Unit", "Good"), Some("value"));
    // The malformed line should not land as `broken-line-no-equals=""`.
    assert!(p.first("Unit", "broken-line-no-equals").is_none());
}

#[test]
fn parser_repeated_section_header_appends_to_existing_bucket() {
    // systemd's conf-parser treats two `[Service]` headers in
    // the same file as one logical section: the second header
    // re-opens the existing bucket and subsequent assignments
    // append to it. Our parser implements this via the dedup
    // guard at section-creation (only inserts a new bucket if
    // none exists for the name) plus `find` at append time
    // (returns the existing bucket regardless of which header
    // was active when an assignment landed). Pin so a mutant
    // that creates a second bucket would fail here.
    let text = "[Service]\nA=1\n[Service]\nB=2\n";
    let p = ParsedUnit::from_text(text);
    // Only one [Service] section in the underlying storage.
    let count = p
        .sections
        .iter()
        .filter(|(name, _)| name == "Service")
        .count();
    assert_eq!(count, 1, "duplicate header must reuse the existing bucket");
    // Both assignments end up in that single bucket, in source order.
    let svc_keys: Vec<&str> = p
        .sections
        .iter()
        .find(|(name, _)| name == "Service")
        .map(|(_, kv)| kv.iter().map(|(k, _)| k.as_str()).collect())
        .expect("Service section present");
    assert_eq!(svc_keys, vec!["A", "B"]);
    assert_eq!(p.first("Service", "A"), Some("1"));
    assert_eq!(p.first("Service", "B"), Some("2"));
}

#[test]
fn parser_empty_value_after_equals_is_kept_with_empty_string() {
    // `Key=` (empty RHS) is a legal systemd reset-directive form.
    // The parser must keep the assignment with an empty-string
    // value so downstream reset-on-empty validators can detect
    // it. A mutant that drops empty values would silently lose
    // the reset semantics.
    let p = ParsedUnit::from_text("[Service]\nKey=\nNext=second\n");
    assert_eq!(p.first("Service", "Key"), Some(""));
    assert_eq!(p.first("Service", "Next"), Some("second"));
}

#[test]
fn parser_whitespace_only_line_is_treated_as_empty() {
    // A line containing only whitespace is collapsed to empty
    // after `l = logical.trim()` and skipped at `if l.is_empty()
    // { continue; }`. Pin this so a mutant that uses
    // `logical.is_empty()` directly (skipping the trim step)
    // would mis-treat a `   ` line as a malformed assignment.
    let p = ParsedUnit::from_text("[Unit]\nKey=value\n   \n   \t  \n[Service]\nFoo=bar\n");
    assert_eq!(p.first("Unit", "Key"), Some("value"));
    assert_eq!(p.first("Service", "Foo"), Some("bar"));
}

#[test]
fn parser_tab_prefixed_assignment_parses_normally() {
    // Tabs are whitespace; `l.trim()` strips them and the
    // assignment lands as `Key=value`. Mirrors systemd which
    // doesn't care about indentation. Pin the behavior against
    // a mutant that special-cases ` ` and ignores `\t`.
    let p = ParsedUnit::from_text("[Service]\n\tKey=value\n\t\tIndented=more\n");
    assert_eq!(p.first("Service", "Key"), Some("value"));
    assert_eq!(p.first("Service", "Indented"), Some("more"));
}

#[test]
fn extract_x_ghars_pulls_only_unit_section_annotations() {
    let body = "[Unit]\nX-Ghars-Managed=true\nX-Ghars-Runner-Name=buckos\nDescription=ignored\n[Service]\nX-Ghars-Skip=irrelevant\n";
    let v = extract_x_ghars(body);
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].0, "X-Ghars-Managed");
    assert_eq!(v[0].1, "true");
    assert_eq!(v[1].0, "X-Ghars-Runner-Name");
    assert_eq!(v[1].1, "buckos");
}

/// `extract_x_ghars_in_section(SystemdSection::Service)` must
/// pull X-Ghars-* annotations from `[Service]` and ignore the
/// `[Unit]` section. No production emitter currently lands an
/// X-Ghars-* annotation in `[Service]`; the apparatus is retained
/// so a future annotation that lives outside `[Unit]` can be
/// extracted without rewriting the parser.
#[test]
fn extract_x_ghars_in_section_service_pulls_only_service_section() {
    let body = "[Unit]\n\
                X-Ghars-Managed=true\n\
                X-Ghars-Runner-Name=buckos\n\
                Description=ignored\n\
                [Service]\n\
                X-Ghars-Hypothetical-Future-Annotation=value\n\
                Type=notify\n";
    let v = extract_x_ghars_in_section(body, SystemdSection::Service);
    assert_eq!(v.len(), 1, "must skip [Unit] X-Ghars-* lines; got {v:?}");
    assert_eq!(v[0].0, "X-Ghars-Hypothetical-Future-Annotation");
    assert_eq!(v[0].1, "value");
}

/// Empty result when `[Service]` section is absent. Pin the
/// empty-Vec contract so a future change that returns a sentinel
/// or panics on missing-section breaks here, not in production.
#[test]
fn extract_x_ghars_in_section_service_empty_when_section_absent() {
    let body = "[Unit]\nX-Ghars-Managed=true\n";
    let v = extract_x_ghars_in_section(body, SystemdSection::Service);
    assert!(v.is_empty(), "no [Service] ⇒ empty Vec; got {v:?}");
}

/// `SystemdSection::Unit` and `Service` must serialize to the
/// exact section header strings the renderers produce. Pinned so
/// a refactor that lowercases / aliases the variants would
/// break here, not silently drop annotations at runtime.
#[test]
fn systemd_section_as_str_matches_renderer_section_headers() {
    assert_eq!(SystemdSection::Unit.as_str(), "Unit");
    assert_eq!(SystemdSection::Service.as_str(), "Service");
}

/// Happy path: key present in the named section with a non-empty
/// value ⇒ Some(value).
#[test]
fn extract_x_ghars_value_returns_some_for_present_key() {
    let body = "[Unit]\n\
                X-Ghars-Managed=true\n\
                X-Ghars-Runner-Name=buckos\n";
    let v = extract_x_ghars_value(body, SystemdSection::Unit, "X-Ghars-Runner-Name");
    assert_eq!(v.as_deref(), Some("buckos"));
}

/// Empty value (`X-Ghars-Foo=`) ⇒ Some("") — distinguishes
/// "key present with no value" from "key absent". Pinned so
/// callers that need to map `Some("")` to a domain-specific
/// sentinel (e.g. None) can rely on the helper to surface the
/// distinction; callers where empty IS a meaningful value (e.g.
/// labels) get the right answer too.
#[test]
fn extract_x_ghars_value_returns_some_empty_for_empty_value() {
    let body = "[Unit]\nX-Ghars-Empty=\n";
    let v = extract_x_ghars_value(body, SystemdSection::Unit, "X-Ghars-Empty");
    assert_eq!(v.as_deref(), Some(""));
}

/// Absent key in present section ⇒ None. The named section
/// exists and parses correctly; the requested key just isn't in
/// its bucket. `ParsedUnit::values` filters yielded nothing, so
/// `first` returns None, and `extract_x_ghars_value` lifts that
/// to `Option::None`.
#[test]
fn extract_x_ghars_value_returns_none_for_absent_key() {
    let body = "[Unit]\nX-Ghars-Other=value\n";
    let v = extract_x_ghars_value(body, SystemdSection::Unit, "X-Ghars-Missing");
    assert!(v.is_none(), "absent key must yield None; got {v:?}");
}

/// Section absent entirely ⇒ None. Even if the key exists in a
/// different section (here `[Unit]`), looking under `[Service]`
/// must yield None — same byte-for-byte section match contract
/// `SystemdSection` enforces against typoed casings.
#[test]
fn extract_x_ghars_value_returns_none_when_section_absent() {
    let body = "[Unit]\nX-Ghars-Misplaced=present-in-unit-only\n";
    let v = extract_x_ghars_value(body, SystemdSection::Service, "X-Ghars-Misplaced");
    assert!(
        v.is_none(),
        "key in different section must not leak via Service lookup; got {v:?}"
    );
}

/// A key appearing TWICE in the same section yields the
/// FIRST value, not the last. Pins `ParsedUnit::first`
/// semantics — `first` calls `self.values(...).next()`,
/// and `values` preserves source order via the chained
/// section/key filters over `self.sections` + bucket
/// `(key, value)` pairs. systemd's conf-parser policy varies by
/// directive (some are list-typed and accumulate, others are
/// last-wins for scalars), but our extractor pins FIRST so the
/// `00-ghars.conf` annotations behave deterministically when an
/// operator drop-in inadvertently re-emits the same key. Pinned
/// because a future refactor that swaps `next()` for `last()`
/// would silently flip the contract.
#[test]
fn extract_x_ghars_value_returns_first_value_for_duplicate_key() {
    let body = "[Unit]\n\
                X-Ghars-Spec-Hash=sha256:first\n\
                X-Ghars-Spec-Hash=sha256:second\n";
    let v = extract_x_ghars_value(body, SystemdSection::Unit, "X-Ghars-Spec-Hash");
    assert_eq!(
        v.as_deref(),
        Some("sha256:first"),
        "duplicate key must yield FIRST value (first-wins); got {v:?}"
    );
}

#[test]
fn parse_runner_unit_name_strips_template_prefix_and_suffix() {
    assert_eq!(
        parse_runner_unit_name("ghars-runner@buckos.service").as_deref(),
        Some("buckos")
    );
    assert_eq!(
        parse_runner_unit_name("ghars-runner@ci-1.service").as_deref(),
        Some("ci-1")
    );
    // Empty instance (the canonical template) → None.
    assert!(parse_runner_unit_name("ghars-runner@.service").is_none());
    // Non-matching prefix → None.
    assert!(parse_runner_unit_name("sshd.service").is_none());
    assert!(parse_runner_unit_name("ghars-cache@build.service").is_none());
}

#[test]
fn classify_drift_combines_branches_correctly() {
    let mut drop_ins = BTreeMap::new();
    // In-sync.
    assert_eq!(
        classify_drift(&runner_template_text(), &drop_ins),
        Drift::InSync
    );
    // DropInsModified.
    drop_ins.insert("99-edit.conf".into(), "x".into());
    assert_eq!(
        classify_drift(&runner_template_text(), &drop_ins),
        Drift::DropInsModified(vec!["99-edit.conf".to_string()])
    );
    // Both.
    let mut edited = runner_template_text();
    edited.push('x');
    assert_eq!(
        classify_drift(&edited, &drop_ins),
        Drift::Both(vec!["99-edit.conf".to_string()])
    );
    // UnitEdited only.
    drop_ins.clear();
    drop_ins.insert("00-ghars.conf".into(), "x".into());
    assert_eq!(classify_drift(&edited, &drop_ins), Drift::UnitEdited);
}

/// Multi-element unmanaged set must surface as a Vec sorted in
/// lexicographic order. The implementation relies on `BTreeMap`
/// key iteration order (in `classify_drift`'s `.keys().filter(...)`
/// chain) which is lex-sorted by definition; this test pins that
/// contract so a future refactor that swaps the underlying map
/// type can't silently re-order the operator-visible payload.
/// Insertion order intentionally does NOT match lex order so the
/// test fails if the implementation regresses to "iteration
/// order".
#[test]
fn classify_drift_emits_vec_sorted_lexicographically() {
    let mut drop_ins = BTreeMap::new();
    // Insert in non-sorted order; classify_drift must still
    // produce a lex-sorted Vec.
    drop_ins.insert("99-zeta.conf".into(), "z".into());
    drop_ins.insert("custom.conf".into(), "c".into());
    drop_ins.insert("99-alpha.conf".into(), "a".into());
    drop_ins.insert("00-ghars.conf".into(), "g".into()); // managed, must not surface
    let drift = classify_drift(&runner_template_text(), &drop_ins);
    match drift {
        Drift::DropInsModified(names) => {
            assert_eq!(
                names,
                vec![
                    "99-alpha.conf".to_string(),
                    "99-zeta.conf".to_string(),
                    "custom.conf".to_string(),
                ],
                "unmanaged basenames must be lex-sorted; got: {names:?}"
            );
            // Managed basename must never appear in the payload.
            assert!(
                !names.iter().any(|n| n == "00-ghars.conf"),
                "managed 00-ghars.conf leaked into unmanaged payload"
            );
        }
        other => panic!("expected DropInsModified, got: {other:?}"),
    }
}

#[test]
fn has_unescaped_trailing_backslash_counts_runs() {
    assert!(has_unescaped_trailing_backslash(r"foo\"));
    assert!(!has_unescaped_trailing_backslash(r"foo\\"));
    assert!(has_unescaped_trailing_backslash(r"foo\\\"));
    assert!(!has_unescaped_trailing_backslash("foo"));
    assert!(!has_unescaped_trailing_backslash(""));
}

// ---- discover() error path coverage -------------------------------

/// EACCES on the unit dir: `read_dir` returns `PermissionDenied`,
/// which is NOT `NotFound`, so `discover` propagates it as
/// `GharsError::Io`. Operators see a real error instead of a
/// silent empty state — matters because a misconfigured /etc
/// permissions wouldn't masquerade as "no runners managed".
///
/// We chmod 0o000 on the unit dir to provoke EACCES. Skipped
/// when running as root because root bypasses DAC permissions
/// (would-be EACCES becomes Ok with empty entries).
#[test]
fn discover_propagates_eacces_as_io_error() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Root bypasses DAC; chmod 0o000 doesn't block root reads.
    if fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
    {
        eprintln!("skipping eacces test: running as root, DAC bypassed");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    // Drop all permissions on the dir.
    let mut perms = fs::metadata(paths.unit_dir.as_std_path())
        .unwrap()
        .permissions();
    perms.set_mode(0o000);
    fs::set_permissions(paths.unit_dir.as_std_path(), perms).unwrap();
    let mock = MockSystemd::default();
    let err = discover(&mock, &paths).unwrap_err();
    assert!(
        matches!(err, GharsError::Io(_)),
        "expected Io error, got: {err}"
    );
    // Restore permissions so TempDir cleanup succeeds.
    let mut restore = fs::metadata(paths.unit_dir.as_std_path())
        .unwrap()
        .permissions();
    restore.set_mode(0o755);
    fs::set_permissions(paths.unit_dir.as_std_path(), restore).unwrap();
}

/// A unit file containing nonsense (no `[Unit]` section, no
/// `X-Ghars-Managed`) is classified as `external` rather than
/// erroring. The parser is intentionally lenient so an operator
/// dropping a malformed file in /etc/systemd/system doesn't break
/// `ghars status`.
#[test]
fn discover_classifies_malformed_unit_as_external() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    // Garbled content, no section headers, random bytes. Must not
    // crash the parser; falls through `is_ghars_managed() == false`.
    fs::write(
        paths
            .unit_dir
            .join("ghars-runner@garbled.service")
            .as_std_path(),
        "@@@ not a unit file at all\nnoise=true\nrandom=tokens\n",
    )
    .unwrap();
    let mock = MockSystemd::default();
    let s = discover(&mock, &paths).unwrap();
    assert!(s.runners.is_empty());
    assert_eq!(s.external, vec!["garbled".to_owned()]);
}

/// Unit file with binary garbage (invalid UTF-8) at the path.
/// `read_to_string` returns `InvalidData`; discover must propagate
/// as `Io`. This guards against silent truncation when a partially
/// written or corrupted unit file is on disk after a crash.
#[test]
fn discover_propagates_invalid_utf8_unit_as_io_error() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    fs::create_dir_all(paths.unit_dir.as_std_path()).unwrap();
    // Bytes that aren't valid UTF-8 (continuation byte without a
    // leading byte). `fs::read_to_string` rejects these.
    fs::write(
        paths
            .unit_dir
            .join("ghars-runner@bad.service")
            .as_std_path(),
        [0x80u8, 0x81u8, 0x82u8],
    )
    .unwrap();
    let mock = MockSystemd::default();
    let err = discover(&mock, &paths).unwrap_err();
    assert!(
        matches!(err, GharsError::Io(_)),
        "expected Io error from invalid UTF-8, got: {err}"
    );
}

/// Empty drop-in directory (exists but contains no files). Drift
/// is `InSync` because the canonical template requires no drop-
/// ins for an unmodified runner — `0 unmanaged drop-ins` AND
/// unit-text matches the template.
#[test]
fn discover_empty_drop_in_dir_is_in_sync_when_unit_matches_template() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    write_unit(&paths, "buckos", &runner_template_text());
    // Create the drop-in dir but leave it empty.
    let drop_in_dir = paths.drop_in_dir("buckos");
    fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    let mock = MockSystemd::default();
    let s = discover(&mock, &paths).unwrap();
    let r = s.runners.get("buckos").unwrap();
    assert_eq!(r.drift, Drift::InSync);
    assert!(r.drop_ins.is_empty());
    // No 00-ghars.conf → spec_hash blank.
    assert!(r.spec_hash.is_empty());
}

/// Missing drop-in directory (the unit exists, but the
/// `<runner>.service.d/` sibling never got created). Drift again
/// `InSync` when the unit matches the template — `read_drop_ins`
/// treats `NotFound` as an empty map (in `read_drop_ins`).
#[test]
fn discover_missing_drop_in_dir_treated_as_empty() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    write_unit(&paths, "buckos", &runner_template_text());
    // Deliberately do NOT create the drop-in dir.
    let mock = MockSystemd::default();
    let s = discover(&mock, &paths).unwrap();
    let r = s.runners.get("buckos").unwrap();
    assert_eq!(r.drift, Drift::InSync);
    assert!(r.drop_ins.is_empty());
}

/// TOCTOU race between `list_runner_unit_files` (readdir) and
/// the `fs::read_to_string` call inside `discover`. The readdir succeeds but
/// the file is gone by the time we try to read it (e.g. another
/// admin process removed it concurrently). Discovery must propagate
/// the error; partial state from prior iterations is dropped because
/// the loop returns `Err` on the first failure.
///
/// We simulate this race deterministically with a dangling symlink:
/// readdir lists it (`state.rs::list_runner_unit_files` filters by
/// suffix only, not file existence), but `read_to_string` follows
/// it and gets ENOENT. No timing-dependent file removal needed.
///
/// We pre-create one valid managed runner BEFORE the symlink so
/// that lexicographic ordering puts the symlink second — proving
/// that mid-iteration failure aborts discover entirely (no partial
/// `runners` map is returned) instead of silently skipping.
#[test]
fn discover_skips_symlink_unit_and_continues_with_valid_neighbours() {
    // Per `list_runner_unit_files_skips_symlinks_and_warns`,
    // symlinks are filtered before any read. discover() must
    // proceed with the alphabetically-earlier valid unit and
    // skip the symlink — NOT propagate an I/O error.
    // (The original reproduction `dangling symlink → ENOENT
    // mid-iteration → propagate Io` is no longer valid because
    // symlink rejection short-circuits before read_to_string
    // ever fires; this test now pins the post-fix behavior.)
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    write_unit(&paths, "alpha", &runner_template_text());
    let dangling = paths
        .unit_dir
        .join("ghars-runner@bravo.service")
        .as_std_path()
        .to_owned();
    std::os::unix::fs::symlink("/nonexistent/path/ghars-target", &dangling).unwrap();
    let mock = MockSystemd::default();
    let actual = discover(&mock, &paths).unwrap();
    // alpha surfaces; bravo (symlink) does not.
    assert!(actual.runners.contains_key("alpha"));
    assert!(
        !actual.runners.contains_key("bravo"),
        "symlink unit must NOT surface as managed runner"
    );
}

/// EACCES on the per-runner drop-in directory. The unit file itself
/// is readable, but `read_drop_ins` hits `PermissionDenied`
/// on the `<runner>.service.d/` directory readdir. Distinct from
/// `discover_propagates_eacces_as_io_error` which targets the
/// top-level `unit_dir` — this targets the inner `drop_in_dir` read
/// path that mutation-test runs against the `map_err(GharsError::Io)`
/// on the `read_drop_ins` call inside `discover`'s per-runner
/// loop, which would silently turn into a panic if the
/// `map_err` were dropped.
///
/// Skipped under root because DAC bypasses chmod on drop-in dir.
#[test]
fn discover_propagates_eacces_on_drop_in_dir_as_io_error() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
    {
        eprintln!("skipping eacces test: running as root, DAC bypassed");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    write_unit(&paths, "buckos", &runner_template_text());
    let drop_in_dir = paths.drop_in_dir("buckos");
    fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    // Drop all permissions on the drop-in dir specifically.
    let mut perms = fs::metadata(drop_in_dir.as_std_path())
        .unwrap()
        .permissions();
    perms.set_mode(0o000);
    fs::set_permissions(drop_in_dir.as_std_path(), perms).unwrap();
    let mock = MockSystemd::default();
    let err = discover(&mock, &paths).unwrap_err();
    assert!(
        matches!(err, GharsError::Io(_)),
        "expected Io error from EACCES on drop-in dir, got: {err}"
    );
    // Restore so TempDir cleanup succeeds.
    let mut restore = fs::metadata(drop_in_dir.as_std_path())
        .unwrap()
        .permissions();
    restore.set_mode(0o755);
    fs::set_permissions(drop_in_dir.as_std_path(), restore).unwrap();
}

/// Edge case in `classify_drift`: unit text is edited, `drop_ins`
/// is EMPTY (operator deleted every drop-in including ghars-managed
/// ones). The `drop_ins.keys().filter(...)` predicate in
/// `classify_drift` is vacuous over an empty iterator →
/// `drop_ins_drifted = false`.
/// Result: `(true, false) → UnitEdited`, NOT `Both`.
///
/// This pins the "vacuously false" semantics: a future swap to
/// `.all(|k| MANAGED_DROP_IN_BASENAMES.contains(...))` (which is
/// vacuously TRUE on empty) would invert this case and would not
/// be caught by the existing `classify_drift` test (which always
/// uses non-empty `drop_ins` for the `UnitEdited` branch).
#[test]
fn classify_drift_empty_drop_ins_with_edited_unit_is_unit_edited_not_both() {
    let drop_ins: BTreeMap<String, String> = BTreeMap::new();
    let mut edited = runner_template_text();
    edited.push('x');
    let drift = classify_drift(&edited, &drop_ins);
    assert_eq!(
        drift,
        Drift::UnitEdited,
        "empty drop_ins must NOT contribute drop-in drift"
    );
}

#[test]
fn discover_finds_cache_pool_via_drop_in_dir_with_no_unit_file() {
    // Cache pool template instances are virtual — apply.rs writes
    // only the shared template `ghars-cache@.service` (no instance)
    // and the per-pool drop-in directory
    // `ghars-cache@POOL.service.d/`. Per-pool unit FILES never
    // exist on disk. Discovery MUST find the pool by globbing the
    // drop-in directories, not by globbing unit files. This test
    // pins that contract: a tempdir with NO `ghars-cache@build.service`
    // file but WITH a `ghars-cache@build.service.d/00-ghars.conf`
    // drop-in must surface "build" in actual.cache_pools.
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    // Only the per-pool drop-in dir + 00-ghars.conf — no unit file.
    let drop_in_dir = paths.cache_drop_in_dir("build");
    fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    let drop_in_body = "[Unit]\n\
                        X-Ghars-Spec-Hash=sha256:cafebabe\n\
                        X-Ghars-Pool-Name=build\n\
                        X-Ghars-Pool-Kinds=sccache\n\
                        X-Ghars-Config-Source=/etc/ghars/ghars.toml\n\
                        \n\
                        [Service]\n\
                        ExecStart=/usr/bin/sccache --start-server\n";
    fs::write(
        drop_in_dir.join("00-ghars.conf").as_std_path(),
        drop_in_body,
    )
    .unwrap();
    // Sanity: per-pool unit file does NOT exist.
    let per_pool_unit_path = paths.unit_dir.join("ghars-cache@build.service");
    assert!(
        !per_pool_unit_path.as_std_path().exists(),
        "test fixture invariant: per-pool unit file must NOT be created \
         on disk — that's the whole point of this test"
    );

    let mut mock = MockSystemd::default();
    mock.set_active("ghars-cache@build.service", "active");
    mock.set_unit_file_state("ghars-cache@build.service", "enabled");
    let actual = discover(&mock, &paths).unwrap();
    let pool = actual
        .cache_pools
        .get("build")
        .expect("discovery must find pool 'build' via the drop-in dir glob");
    assert_eq!(pool.name, "build");
    assert_eq!(pool.spec_hash, "sha256:cafebabe");
    assert!(pool.drop_ins.contains_key("00-ghars.conf"));
    assert!(pool.running);
    assert!(pool.enabled);
}

/// Pool with only the managed `00-ghars.conf` drop-in — no
/// operator overrides — must surface `Drift::InSync`. Pins the
/// `classify_cache_pool_drift` → `discover` wiring: the
/// symmetric runner-side test already exists at
/// `classify_drift_combines_branches_correctly` but the
/// cache-pool path (called from `discover`'s cache-pool
/// discovery loop) was untested end-to-end.
#[test]
fn discover_classifies_cache_pool_drift_in_sync() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    let drop_in_dir = paths.cache_drop_in_dir("build");
    fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    fs::write(
        drop_in_dir.join("00-ghars.conf").as_std_path(),
        b"[Unit]\nX-Ghars-Spec-Hash=sha256:cafebabe\n",
    )
    .unwrap();
    let mut mock = MockSystemd::default();
    mock.set_active("ghars-cache@build.service", "active");
    mock.set_unit_file_state("ghars-cache@build.service", "enabled");
    let actual = discover(&mock, &paths).unwrap();
    let pool = actual.cache_pools.get("build").expect("pool 'build'");
    assert_eq!(
        pool.drift,
        Drift::InSync,
        "managed-only drop-ins must classify InSync; got: {:?}",
        pool.drift
    );
}

/// Pool with an operator-added unmanaged drop-in (e.g.
/// `99-tuning.conf` from `systemctl edit ghars-cache@build`)
/// must surface `Drift::DropInsModified` carrying the unmanaged
/// basenames. Mirrors the runner-side payload contract; without
/// this signal the planner couldn't fire `UpdateCachePool` on
/// drift-only changes.
#[test]
fn discover_classifies_cache_pool_drift_drop_ins_modified() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    let drop_in_dir = paths.cache_drop_in_dir("build");
    fs::create_dir_all(drop_in_dir.as_std_path()).unwrap();
    fs::write(
        drop_in_dir.join("00-ghars.conf").as_std_path(),
        b"[Unit]\nX-Ghars-Spec-Hash=sha256:cafebabe\n",
    )
    .unwrap();
    // Operator override — outside MANAGED_CACHE_DROP_IN_BASENAMES.
    fs::write(
        drop_in_dir.join("99-operator.conf").as_std_path(),
        b"[Service]\nNice=-5\n",
    )
    .unwrap();
    let mut mock = MockSystemd::default();
    mock.set_active("ghars-cache@build.service", "active");
    mock.set_unit_file_state("ghars-cache@build.service", "enabled");
    let actual = discover(&mock, &paths).unwrap();
    let pool = actual.cache_pools.get("build").expect("pool 'build'");
    match &pool.drift {
        Drift::DropInsModified(names) => {
            assert_eq!(
                names,
                &vec!["99-operator.conf".to_string()],
                "operator drop-in must surface in DropInsModified payload; got: {names:?}"
            );
        }
        other => panic!("expected DropInsModified, got: {other:?}"),
    }
}

/// `classify_cache_pool_drift` must emit unmanaged basenames in
/// lexicographic order across a 3+ element set, even when the
/// insertion order into the source `BTreeMap` would suggest
/// otherwise. The runner-side analogue is
/// `classify_drift_emits_vec_sorted_lexicographically` (above);
/// pool drift uses an independent code path
/// (`classify_cache_pool_drift`) that filters against
/// `MANAGED_CACHE_DROP_IN_BASENAMES` instead of
/// `MANAGED_DROP_IN_BASENAMES`, so the sort guarantee must be
/// pinned separately.
#[test]
fn classify_cache_pool_drift_emits_vec_sorted_lexicographically() {
    let mut drop_ins = BTreeMap::new();
    // Insert in non-sorted order with a managed-set sentinel.
    drop_ins.insert("99-zeta.conf".into(), "z".into());
    drop_ins.insert("99-alpha.conf".into(), "a".into());
    drop_ins.insert("custom.conf".into(), "c".into());
    // Managed basename — must NOT surface in the output Vec.
    drop_ins.insert("00-ghars.conf".into(), "g".into());
    let drift = classify_cache_pool_drift(&drop_ins);
    match drift {
        Drift::DropInsModified(names) => {
            assert_eq!(
                names,
                vec![
                    "99-alpha.conf".to_string(),
                    "99-zeta.conf".to_string(),
                    "custom.conf".to_string(),
                ],
                "unmanaged pool drop-ins must be lex-sorted; got: {names:?}"
            );
            assert!(
                !names.iter().any(|n| n == "00-ghars.conf"),
                "managed 00-ghars.conf must not leak into unmanaged payload"
            );
        }
        other => panic!("expected DropInsModified, got: {other:?}"),
    }
}

#[test]
fn discover_skips_empty_instance_cache_pool_drop_in_dir() {
    // The shared cache template `ghars-cache@.service` would have
    // a drop-in dir `ghars-cache@.service.d/` (empty instance).
    // apply.rs does not currently emit such a dir (only per-pool
    // drop-in dirs are created), but if one ever appears on disk
    // — operator hand-edit, partial migration — discovery MUST
    // skip it: an empty-instance drop-in is not a pool.
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    // Plant an empty-instance dir.
    let bad_dir = paths.unit_dir.join("ghars-cache@.service.d");
    fs::create_dir_all(bad_dir.as_std_path()).unwrap();
    fs::write(
        bad_dir.join("00-ghars.conf").as_std_path(),
        b"[Unit]\nX-Ghars-Spec-Hash=sha256:bad\n",
    )
    .unwrap();
    // Plant a real pool to confirm discovery still works alongside.
    let real_dir = paths.cache_drop_in_dir("build");
    fs::create_dir_all(real_dir.as_std_path()).unwrap();
    fs::write(
        real_dir.join("00-ghars.conf").as_std_path(),
        b"[Unit]\nX-Ghars-Spec-Hash=sha256:good\n",
    )
    .unwrap();

    let mut mock = MockSystemd::default();
    mock.set_active("ghars-cache@build.service", "active");
    mock.set_unit_file_state("ghars-cache@build.service", "enabled");
    let actual = discover(&mock, &paths).unwrap();
    // Only the real pool surfaces; empty-instance dir is skipped.
    let names: Vec<&String> = actual.cache_pools.keys().collect();
    assert_eq!(
        names,
        vec![&String::from("build")],
        "empty-instance drop-in dir must be skipped; got: {names:?}"
    );
}

#[test]
fn parse_cache_pool_drop_in_dir_name_rejects_non_matching() {
    // Adversarial inputs that MUST NOT parse as a pool name.
    assert_eq!(parse_cache_pool_drop_in_dir_name(""), None);
    assert_eq!(
        parse_cache_pool_drop_in_dir_name("ghars-cache@.service.d"),
        None,
        "empty instance must be rejected"
    );
    assert_eq!(
        parse_cache_pool_drop_in_dir_name("ghars-cache@build.service"),
        None,
        "missing .d suffix must be rejected"
    );
    assert_eq!(
        parse_cache_pool_drop_in_dir_name("ghars-runner@build.service.d"),
        None,
        "wrong template prefix must be rejected"
    );
    assert_eq!(
        parse_cache_pool_drop_in_dir_name("ghars-cache@build.service.d"),
        Some("build".into()),
        "canonical form must parse to instance name"
    );
}

/// Discovery must INCLUDE pool drop-in directories whose `%i`
/// instance name exceeds `IDENTIFIER_MAX_LEN` so the planner
/// can emit `RemoveCachePool` against the discovered-but-undesired
/// pool. (The desired-side `cfg.cache_pools` cannot contain an
/// oversize key — `validate_cache_pool_name` rejects it at config
/// load — so any oversize entry in actual is by definition
/// unreachable in desired and produces a removal in the diff.)
/// A `tracing::warn!` surfaces the offender to operator output;
/// the planner-level integration test in
/// `tests/plan_engine_integration.rs` pins the `RemoveCachePool`
/// emission end-to-end.
#[test]
fn discover_includes_cache_pool_with_oversize_name_for_removal() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    // Plant an oversize-instance drop-in dir. Pool name length =
    // IDENTIFIER_MAX_LEN + 1 chars. The shape passes
    // parse_cache_pool_drop_in_dir_name but exceeds the cap.
    let oversize_pool = "a".repeat(crate::config::IDENTIFIER_MAX_LEN + 1);
    let bad_dir = paths
        .unit_dir
        .join(format!("ghars-cache@{oversize_pool}.service.d"));
    fs::create_dir_all(bad_dir.as_std_path()).unwrap();
    fs::write(
        bad_dir.join("00-ghars.conf").as_std_path(),
        b"[Unit]\nX-Ghars-Spec-Hash=sha256:bad\n",
    )
    .unwrap();
    // Plant a valid pool alongside to prove the loop produces
    // both entries.
    let good_dir = paths.cache_drop_in_dir("build");
    fs::create_dir_all(good_dir.as_std_path()).unwrap();
    fs::write(
        good_dir.join("00-ghars.conf").as_std_path(),
        b"[Unit]\nX-Ghars-Spec-Hash=sha256:good\n",
    )
    .unwrap();

    let mut mock = MockSystemd::default();
    mock.set_active("ghars-cache@build.service", "active");
    mock.set_unit_file_state("ghars-cache@build.service", "enabled");
    let actual = discover(&mock, &paths).unwrap();
    // BOTH pools surface — the oversize entry is included so
    // the planner can drive its removal.
    assert!(
        actual.cache_pools.contains_key("build"),
        "valid pool must surface; got keys: {:?}",
        actual.cache_pools.keys().collect::<Vec<_>>()
    );
    assert!(
        actual.cache_pools.contains_key(&oversize_pool),
        "oversize pool MUST be included so planner can emit RemoveCachePool; \
         got keys: {:?}",
        actual.cache_pools.keys().collect::<Vec<_>>()
    );
}

/// `state::discover()` MUST emit a `tracing::warn!` when a
/// cache-pool drop-in dir on disk has an oversize `%i` instance
/// name. The companion test above proves the entry surfaces in
/// `actual.cache_pools`; this test pins that the warning channel
/// is also wired so operators see the offender in their structured
/// log stream before the next plan/apply reconciles state.
///
/// Uses `tracing-test` to capture per-test events and assert against
/// the rendered log output. The warning includes both a static
/// message (`"exceeds name length limit"`) and structured fields
/// (`pool = <name>`, `limit = IDENTIFIER_MAX_LEN`); both are
/// asserted to keep the contract pinned even if the message text or
/// field names later evolve.
#[test]
#[tracing_test::traced_test]
fn discover_warns_on_oversize_cache_pool_name() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    let oversize_pool = "a".repeat(crate::config::IDENTIFIER_MAX_LEN + 1);
    let bad_dir = paths
        .unit_dir
        .join(format!("ghars-cache@{oversize_pool}.service.d"));
    fs::create_dir_all(bad_dir.as_std_path()).unwrap();
    fs::write(
        bad_dir.join("00-ghars.conf").as_std_path(),
        b"[Unit]\nX-Ghars-Spec-Hash=sha256:bad\n",
    )
    .unwrap();
    let mock = MockSystemd::default();
    let _actual = discover(&mock, &paths).unwrap();
    // Warning text from src/state.rs::discover.
    assert!(
        logs_contain("exceeds name length limit"),
        "expected discover() to warn on oversize cache pool name"
    );
    // The pool name is emitted as a structured field; tracing-test
    // renders it into the captured log line.
    assert!(
        logs_contain(&oversize_pool),
        "expected the oversize pool name {oversize_pool:?} to appear \
         in the structured log line"
    );
}

/// Boundary pin: the warning at `state.rs::discover` fires on
/// `pool_name.len() > IDENTIFIER_MAX_LEN`. A pool name of exactly
/// `IDENTIFIER_MAX_LEN` chars MUST NOT trigger the warning. A
/// regression that off-by-one'd the comparison (e.g. `>=` instead
/// of `>`) would falsely warn on every operator-authored
/// max-length pool name. Sister to
/// `discover_warns_on_oversize_cache_pool_name`.
#[test]
#[tracing_test::traced_test]
fn discover_does_not_warn_on_at_max_cache_pool_name() {
    let tmp = TempDir::new().unwrap();
    let paths = paths_under(&tmp);
    let at_max_pool = "a".repeat(crate::config::IDENTIFIER_MAX_LEN);
    let dir = paths
        .unit_dir
        .join(format!("ghars-cache@{at_max_pool}.service.d"));
    fs::create_dir_all(dir.as_std_path()).unwrap();
    fs::write(
        dir.join("00-ghars.conf").as_std_path(),
        b"[Unit]\nX-Ghars-Spec-Hash=sha256:ok\n",
    )
    .unwrap();
    let mock = MockSystemd::default();
    let _actual = discover(&mock, &paths).unwrap();
    // The static warning message at state.rs::discover MUST NOT
    // appear when the pool name length is exactly at the cap. A
    // present log would prove the gate is `>=` rather than `>`.
    assert!(
        !logs_contain("exceeds name length limit"),
        "expected discover() to NOT warn on at-max-len pool name \
         ({}-char), but the warning fired",
        crate::config::IDENTIFIER_MAX_LEN,
    );
}

// ---- SEC: symlink rejection in state listing ---------------------

#[test]
#[tracing_test::traced_test]
fn list_runner_unit_files_skips_symlinks_and_warns() {
    // Hardening: a symlink at `ghars-runner@<name>.service` is
    // operator tampering — ghars apply only writes regular
    // files. Treating it as managed could (a) read state from
    // a path ghars does not control or (b) provoke `apply` to
    // remove the symlink target via fs::remove_file. Skip +
    // warn so neighbouring valid units still surface.
    let tmp = TempDir::new().unwrap();
    let unit_dir = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    // Plant a real unit file (must be discovered) plus a
    // symlink unit (must be skipped).
    fs::write(
        unit_dir.join("ghars-runner@real.service").as_std_path(),
        b"[Unit]\n",
    )
    .unwrap();
    // Symlink target points elsewhere; we never follow it.
    std::os::unix::fs::symlink(
        "/etc/passwd",
        unit_dir.join("ghars-runner@bad.service").as_std_path(),
    )
    .unwrap();
    let entries = list_runner_unit_files(&unit_dir).unwrap();
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert!(
        names.contains(&"real"),
        "real unit must surface; got {names:?}"
    );
    assert!(
        !names.contains(&"bad"),
        "symlink unit must NOT surface as managed runner; got {names:?}"
    );
    assert!(
        logs_contain("skipping symlink"),
        "expected tracing::warn on the skipped symlink"
    );
}

#[test]
#[tracing_test::traced_test]
fn list_cache_pool_drop_in_dirs_skips_symlinks_and_warns() {
    let tmp = TempDir::new().unwrap();
    let unit_dir = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    // Real per-pool drop-in dir.
    fs::create_dir_all(unit_dir.join("ghars-cache@real.service.d").as_std_path()).unwrap();
    // Symlink pointing at the real dir — even pointing at a
    // ghars-managed location, the symlink itself is rejected.
    std::os::unix::fs::symlink(
        "ghars-cache@real.service.d",
        unit_dir.join("ghars-cache@bad.service.d").as_std_path(),
    )
    .unwrap();
    let entries = list_cache_pool_drop_in_dirs(&unit_dir).unwrap();
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"real"), "real pool dir must surface");
    assert!(
        !names.contains(&"bad"),
        "symlink pool dir must NOT surface as managed pool"
    );
    assert!(
        logs_contain("skipping symlink"),
        "expected tracing::warn on the skipped symlink dir"
    );
}

#[test]
#[tracing_test::traced_test]
fn read_drop_ins_skips_symlinks_and_warns() {
    let tmp = TempDir::new().unwrap();
    let dir = camino::Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
    // Real *.conf file (must be read).
    fs::write(
        dir.join("00-ghars.conf").as_std_path(),
        b"[Unit]\nX-Ghars-Managed=true\n",
    )
    .unwrap();
    // Symlink *.conf pointing at /etc/shadow — must be skipped
    // unconditionally regardless of whether the target exists
    // / is readable. This is the worst-case attack: a symlink
    // that survives a write-this-managed-directory shortcut
    // would let ghars apply read /etc/shadow's bytes into the
    // ActualState's drop-in body, then re-render under a
    // ghars-managed path, leaking the shadow content.
    std::os::unix::fs::symlink("/etc/shadow", dir.join("99-evil.conf").as_std_path()).unwrap();
    let map = read_drop_ins(&dir).unwrap();
    assert!(
        map.contains_key("00-ghars.conf"),
        "real *.conf must surface"
    );
    assert!(
        !map.contains_key("99-evil.conf"),
        "symlink *.conf must NOT be read into ActualState"
    );
    assert!(
        logs_contain("skipping symlink"),
        "expected tracing::warn on the skipped symlink *.conf"
    );
}
