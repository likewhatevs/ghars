//! `ghars init`, `ghars add`, `ghars logs`, `ghars cleanup`,
//! `ghars completions`, `ghars manpages` command handlers, plus the
//! static `INIT_EXAMPLE_CONFIG` template.

use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command as ProcCommand, Stdio};

use camino::Utf8Path;
use clap::CommandFactory;

use crate::Result;
use crate::error::GharsError;
use crate::paths::Paths;
use crate::state;
use crate::systemd::{DbusSystemd, Systemd};
use crate::validators;

use super::args::{AddArgs, ApplyArgs, Cli, ColorMode, InitArgs, LogsArgs};
use super::cmd_apply::cmd_apply;
use super::load::load_config;

pub(super) const INIT_EXAMPLE_CONFIG: &str = "\
# ghars config — see https://github.com/OWNER/REPO for the full schema.
# All identifier keys (auth.*, cache_pools.*, network.*, [[runner]].name)
# must match `^[a-z]([a-z0-9-]*[a-z0-9])?$` and be ≤ 64 chars.

[defaults]
runner_version = \"2.334.0\"
auth = \"pat\"
arch = \"x86_64\"
labels = [\"self-hosted\", \"linux\"]

[auth.pat]
kind = \"pat\"
token_env = \"GHARS_PAT\"

# Uncomment when adding runners.
# [[runner]]
# name = \"example\"
# url = \"https://github.com/owner/repo\"
# labels = [\"x64\"]
";

pub(super) fn cmd_init(config_path: &Utf8Path, args: &InitArgs, quiet: bool) -> Result<i32> {
    let dest = args
        .output
        .clone()
        .unwrap_or_else(|| config_path.to_owned());
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent.as_std_path())?;
    }
    if dest.exists() {
        return Err(GharsError::Validation(
            format!("{dest} already exists; refusing to overwrite"),
            "delete the file or pass `--output PATH` for a different location".into(),
        ));
    }
    // Mode 0640: owner rw, group r, world none. The default umask leaves
    // /etc/ghars/ghars.toml world-readable (0644) which would expose the
    // [auth.*] section's `token_env` / `token_file` references — those
    // are paths/env-var names, not secrets, but they fingerprint the
    // operator's secrets layout. Enforce 0640 from creation so the
    // window where the file is world-readable doesn't exist (compared to
    // a write-then-chmod sequence).
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(dest.as_std_path())?;
    f.write_all(INIT_EXAMPLE_CONFIG.as_bytes())?;
    f.flush()?;

    // SEC-27: ghars does not create any system users at init time.
    // Per-runner identity is handled by DynamicUser=yes in the runner
    // unit — systemd allocates a transient UID per trust_zone, giving
    // cross-runner ptrace/signal/DAC isolation for free. A vestigial shared
    // `ghars` user contradicts that model and would have led operators
    // into the SEC-27 hole that per-runner UIDs are designed to close.
    if !quiet {
        let _ = writeln!(io::stdout(), "wrote {dest}");
    }
    Ok(0)
}

// ---------- add ---------------------------------------------------------

/// Escape a string for safe interpolation into a TOML basic string
/// (`"..."`). Per TOML spec, basic strings may not contain raw `"` or
/// `\`, and control characters (U+0000..U+001F, U+007F) MUST appear
/// only via Unicode escape sequences. This helper substitutes every
/// such byte with its TOML-canonical escape so the output is
/// guaranteed parseable when wrapped in `"..."`.
///
/// Used by `cmd_add` to defend the manual `[[runner]]` block-emit
/// path against operator-supplied strings (label tokens, --name,
/// --auth, --url) that would otherwise inject TOML keys / break the
/// quote balance. Validators upstream (`validate_runner_name`,
/// `validate_url`, `validate_labels`) already reject the offending
/// characters, but defense-in-depth — a future relaxation of any of
/// those regexes must not regress into TOML injection here.
pub(super) fn toml_basic_string_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            // Other C0 control characters and DEL: TOML requires
            // \uXXXX form for U+0000..U+001F (except the named
            // escapes above) and U+007F.
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

pub(super) fn cmd_add(
    config_path: &Utf8Path,
    paths: &Paths,
    args: &AddArgs,
    color: ColorMode,
    quiet: bool,
) -> Result<i32> {
    let cfg = load_config(config_path)?;

    let url = format!("https://github.com/{}", args.repo.trim_start_matches('/'));
    let name = args.name.clone().unwrap_or_else(|| {
        // OWNER/REPO → owner-repo-N (next free index); OWNER → owner-N.
        let base = args.repo.replace('/', "-");
        let mut i: u32 = 1;
        loop {
            let candidate = format!("{base}-{i}");
            if !cfg.runners.iter().any(|r| r.name == candidate) {
                break candidate;
            }
            i += 1;
        }
    });
    let auth = args
        .auth
        .clone()
        .or_else(|| cfg.defaults.auth.clone())
        .unwrap_or_else(|| "interactive".into());

    // Validate the constructed URL + auth ref BEFORE appending the
    // [[runner]] block. Catching a typo here avoids leaving a malformed
    // block in the user's config that the next `apply` would reject.
    validators::validate_url(&url)?;
    if !cfg.auth.contains_key(&auth) {
        let known: Vec<&str> = cfg.auth.keys().map(String::as_str).collect();
        let known_msg = if known.is_empty() {
            "no [auth.*] entries are declared in the config".to_string()
        } else {
            format!("known auth keys: {}", known.join(", "))
        };
        return Err(GharsError::Validation(
            format!("auth {auth:?} is not declared in [auth.*]"),
            format!(
                "add a `[auth.{auth}]` block (e.g. `[auth.{auth}] kind = \"interactive\"`) or pass \
                 `--auth NAME` referencing an existing entry; {known_msg}"
            ),
        ));
    }
    // The runner name is generated above (auto-numbered) when the
    // operator omits --name; either way it must satisfy
    // IDENTIFIER_REGEX so apply downstream accepts it.
    super::util::validate_runner_name_with_hint(&name)?;

    // Filter empty entries from clap's value_delimiter parse — a
    // trailing or adjacent comma in `--labels foo,,bar` produces a
    // zero-length string that downstream merge logic would fold into
    // an unlabeled runner.
    let labels: Vec<&str> = args
        .labels
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    // Validate every label against LABEL_RE before interpolation.
    // `validate_labels` takes a CSV string for parity with the TOML
    // surface; join into the same shape it expects. After this gate,
    // every entry is `[a-zA-Z0-9._-]+` — no TOML metacharacters
    // (quote / backslash / control char) can survive.
    if !labels.is_empty() {
        validators::validate_labels(&labels.join(","))?;
    }

    // Build the [[runner]] TOML block manually. We avoid round-tripping
    // the full config because that would erase comments + key order.
    use std::fmt::Write as _;
    let mut block = String::new();
    block.push_str("\n[[runner]]\n");
    let _ = writeln!(block, "name = \"{}\"", toml_basic_string_escape(&name));
    let _ = writeln!(block, "url = \"{}\"", toml_basic_string_escape(&url));
    if !labels.is_empty() {
        // Defense in depth: even though validate_labels above rejects
        // quote / backslash / control chars, escape on the way out so
        // a future relaxation of LABEL_RE cannot regress this surface
        // into TOML injection.
        let escaped: Vec<String> = labels
            .iter()
            .map(|l| format!("\"{}\"", toml_basic_string_escape(l)))
            .collect();
        let _ = writeln!(block, "labels = [{}]", escaped.join(", "));
    }
    if cfg.defaults.auth.as_deref() != Some(auth.as_str()) {
        let _ = writeln!(block, "auth = \"{}\"", toml_basic_string_escape(&auth));
    }

    let mut existing = fs::read_to_string(config_path.as_std_path())?;
    if !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(&block);
    fs::write(config_path.as_std_path(), existing)?;

    if !quiet {
        let _ = writeln!(io::stdout(), "added [[runner]] {name}");
    }

    if args.no_apply {
        return Ok(0);
    }

    let apply_args = ApplyArgs {
        only: vec![name],
        auto_approve: args.auto_approve,
        fail_fast: false,
        dry_run: false,
        detailed_exitcode: false,
        detailed_exitcode_recreate: false,
        rollback_on_failure: false,
        diff: false,
        no_restart: false,
    };
    cmd_apply(config_path, paths, &apply_args, color, quiet)
}

// ---------- logs --------------------------------------------------------

pub(super) fn cmd_logs(paths: &Paths, args: &LogsArgs) -> Result<i32> {
    let names = if args.names.is_empty() {
        super::util::discover_or_warn(paths)?
            .runners
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    } else {
        // Validate operator-supplied names against IDENTIFIER_REGEX so
        // `journalctl -u ghars-runner@$NAME.service` only ever sees a
        // shape known to the identifier regex.
        for name in &args.names {
            super::util::validate_runner_name_with_hint(name)?;
        }
        args.names.clone()
    };

    if names.is_empty() {
        return Err(GharsError::Validation(
            "no runners to tail".into(),
            "pass NAMES or run after `ghars apply` so managed units exist".into(),
        ));
    }

    let mut cmd = ProcCommand::new("journalctl");
    for name in &names {
        cmd.arg("-u").arg(crate::paths::runner_unit_name(name));
    }
    if args.follow {
        cmd.arg("-f");
    }
    cmd.arg("-n").arg(args.lines.to_string());
    if let Some(since) = &args.since {
        cmd.arg("--since").arg(since);
    }
    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::inherit())
        .status()
        .map_err(GharsError::Io)?;
    Ok(status.code().unwrap_or(1))
}

// ---------- completions / manpages --------------------------------------

pub(super) fn cmd_completions(shell: clap_complete::Shell) {
    cmd_completions_to(shell, &mut io::stdout());
}

/// `cmd_completions` with a caller-supplied writer. Tests
/// pass a `Vec<u8>` to capture the generated shell-completion script
/// and assert the per-shell preamble lands as expected. Production
/// always passes `io::stdout()`.
pub(super) fn cmd_completions_to<W: io::Write>(shell: clap_complete::Shell, w: &mut W) {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_owned();
    clap_complete::generate(shell, &mut cmd, bin_name, w);
}

pub(super) fn cmd_manpages(output: &Utf8Path) -> Result<i32> {
    fs::create_dir_all(output.as_std_path())?;
    let cmd = Cli::command();
    let mut buffer: Vec<u8> = Vec::new();
    clap_mangen::Man::new(cmd.clone())
        .render(&mut buffer)
        .map_err(GharsError::Io)?;
    fs::write(
        output.join(format!("{}.1", cmd.get_name())).as_std_path(),
        buffer,
    )?;
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        let sub_name = format!("{}-{}", cmd.get_name(), sub.get_name());
        // `Man::title()` overrides the manpage title without requiring
        // a `&'static` Command name — no Box::leak needed.
        let mut buffer: Vec<u8> = Vec::new();
        clap_mangen::Man::new(sub.clone())
            .title(sub_name.clone())
            .render(&mut buffer)
            .map_err(GharsError::Io)?;
        fs::write(output.join(format!("{sub_name}.1")).as_std_path(), buffer)?;
    }
    Ok(0)
}

/// Remove all ghars-managed state from the host: stop and disable
/// every managed unit, remove unit files, drop-in dirs, runner
/// homes, cache pool storage, runtime files, nft rules, and netns
/// bind-mounts. Config (`/etc/ghars/ghars.toml`) is left intact so
/// `ghars apply` can rebuild from scratch.
pub(super) fn cmd_cleanup(paths: &Paths) -> Result<i32> {
    if !nix::unistd::geteuid().is_root() {
        return Err(GharsError::Validation(
            "cleanup requires root".into(),
            "run with sudo".into(),
        ));
    }
    // Refuse to proceed without D-Bus: tearing down unit files while
    // systemd still has the units loaded leaves managed runners running
    // with no on-disk unit to control. Fail fast with an actionable hint
    // instead of half-cleaning.
    let systemd = DbusSystemd::new().map_err(|e| {
        GharsError::Systemd(
            format!("cleanup requires systemd D-Bus: {e}"),
            "ensure dbus is running and the caller has access to the system bus".into(),
        )
    })?;

    // 1) Stop and disable all managed runner, cache, and netns units.
    {
        let sd = &systemd;
        let actual = state::discover(sd, paths).unwrap_or_default();
        for name in actual.runners.keys() {
            let unit = crate::paths::runner_unit_name(name);
            let _ = sd.stop_unit(&unit);
            let _ = sd.disable_unit(&unit);
        }
        for name in actual.cache_pools.keys() {
            let unit = crate::paths::cache_unit_name(name);
            let _ = sd.stop_unit(&unit);
            let _ = sd.disable_unit(&unit);
        }
        // Netns units discovered by glob since state::discover
        // doesn't track them separately.
        if let Ok(entries) = fs::read_dir(paths.unit_dir.as_std_path()) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("ghars-net@") && name.ends_with(".service") {
                    let _ = sd.stop_unit(&name);
                    let _ = sd.disable_unit(&name);
                }
            }
        }
    }

    // 2) Remove unit files and drop-in directories.
    remove_glob(&paths.unit_dir, "ghars-runner@*");
    remove_glob(&paths.unit_dir, "ghars-cache@*");
    remove_glob(&paths.unit_dir, "ghars-net@*");

    // 3) Remove runner state, cache pools, runtime, nft rules.
    rm_rf(&paths.state_dir);
    rm_rf(&paths.cache_dir);
    rm_rf(&paths.runtime_dir);
    let nft_dir = paths.config_dir.join("nft.d");
    rm_rf(&nft_dir);

    // 4) Remove resolved drop-ins and netns bind-mounts.
    if let Ok(entries) = fs::read_dir(paths.resolved_conf_d.as_std_path()) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("ghars-") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    let netns_dir = std::path::Path::new("/var/run/netns");
    if netns_dir.exists()
        && let Ok(entries) = fs::read_dir(netns_dir)
    {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("ghars-") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    // 5) daemon-reload so systemd forgets the removed units.
    let _ = systemd.daemon_reload();

    eprintln!(
        "cleanup complete. Config at {} is intact — run `ghars apply` to rebuild.",
        paths.config_dir.join("ghars.toml")
    );
    Ok(0)
}

fn rm_rf(path: &camino::Utf8Path) {
    if path.exists() {
        let _ = fs::remove_dir_all(path.as_std_path());
    }
}

fn remove_glob(dir: &camino::Utf8Path, pattern: &str) {
    let prefix = pattern.trim_end_matches('*');
    if let Ok(entries) = fs::read_dir(dir.as_std_path()) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(prefix) {
                let path = entry.path();
                if path.is_dir() {
                    let _ = fs::remove_dir_all(&path);
                } else {
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;

    #[test]
    fn rm_rf_silently_succeeds_on_nonexistent_path() {
        // No assertion: rm_rf takes a non-existent path and must not
        // panic / propagate. The `if path.exists()` guard handles this.
        let p = Utf8PathBuf::from("/tmp/ghars-nonexistent-path-for-test-12345");
        rm_rf(&p);
    }

    #[test]
    fn rm_rf_removes_directory_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let nested = root.join("a/b/c");
        std::fs::create_dir_all(nested.as_std_path()).unwrap();
        std::fs::write(nested.join("file").as_std_path(), b"hi").unwrap();
        let target = root.join("a");
        rm_rf(&target);
        assert!(!target.as_std_path().exists(), "target dir must be gone");
    }

    #[test]
    fn remove_glob_removes_matching_files_only() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        std::fs::write(root.join("ghars-runner@a.service").as_std_path(), b"").unwrap();
        std::fs::write(root.join("ghars-runner@b.service").as_std_path(), b"").unwrap();
        std::fs::write(root.join("unrelated.service").as_std_path(), b"").unwrap();
        remove_glob(&root, "ghars-runner@*");
        assert!(!root.join("ghars-runner@a.service").as_std_path().exists());
        assert!(!root.join("ghars-runner@b.service").as_std_path().exists());
        assert!(root.join("unrelated.service").as_std_path().exists());
    }

    #[test]
    fn remove_glob_removes_matching_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let drop_in = root.join("ghars-runner@a.service.d");
        std::fs::create_dir_all(drop_in.as_std_path()).unwrap();
        std::fs::write(drop_in.join("00-ghars.conf").as_std_path(), b"x").unwrap();
        remove_glob(&root, "ghars-runner@*");
        assert!(
            !drop_in.as_std_path().exists(),
            "directory matching prefix must be removed (recursively)"
        );
    }

    #[test]
    fn remove_glob_tolerates_nonexistent_dir() {
        // No assertion: must not panic. fs::read_dir returns Err which
        // the function silently absorbs.
        remove_glob(
            &Utf8PathBuf::from("/tmp/ghars-no-such-dir-for-glob-test"),
            "anything-*",
        );
    }
}
