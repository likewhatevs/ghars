//! SEC-05 regression tests for the `ConfigShell` command builders.

use std::ffi::OsStr;
use std::process::Command;

use camino::Utf8Path;

use super::super::shell::{ConfigShellCtx, RUNNER_TOKEN_ENV, build_register_cmd, build_remove_cmd};

/// Construct a `ConfigShellCtx` with a recognisable token sentinel
/// so each SEC-05 test can scan for it across argv vs env.
fn sec05_ctx<'a>(home: &'a Utf8Path, token: &'a str) -> ConfigShellCtx<'a> {
    ConfigShellCtx {
        runner_home: home,
        name: "buckos",
        url: "https://github.com/example/repo",
        labels: &[],
        token,
    }
}

/// Helper: collect Command argv into `Vec<String>` for assertions.
fn argv_strings(cmd: &Command) -> Vec<String> {
    cmd.get_args()
        .map(|s| s.to_string_lossy().into_owned())
        .collect()
}

/// Helper: lookup a single env var on a Command.
fn env_value(cmd: &Command, key: &str) -> Option<String> {
    cmd.get_envs().find_map(|(k, v)| {
        if k == OsStr::new(key) {
            v.map(|v| v.to_string_lossy().into_owned())
        } else {
            None
        }
    })
}

#[test]
fn sec05_register_argv_does_not_contain_token() {
    let token = "GHARS-SEC05-TOKEN-SENTINEL-123456";
    let home = Utf8Path::new("/var/lib/ghars/buckos");
    let ctx = sec05_ctx(home, token);
    let cmd = build_register_cmd(&ctx);
    let argv = argv_strings(&cmd);
    for arg in &argv {
        assert!(
            !arg.contains(token),
            "register argv leaked token: {arg:?} (full argv: {argv:?})",
        );
    }
    // Also assert there is no `--token` flag at all.
    assert!(
        !argv.iter().any(|a| a == "--token"),
        "register argv contains --token flag: {argv:?}",
    );
}

#[test]
fn sec05_register_env_carries_token() {
    let token = "GHARS-SEC05-TOKEN-SENTINEL-123456";
    let home = Utf8Path::new("/var/lib/ghars/buckos");
    let ctx = sec05_ctx(home, token);
    let cmd = build_register_cmd(&ctx);
    assert_eq!(
        env_value(&cmd, RUNNER_TOKEN_ENV).as_deref(),
        Some(token),
        "register did not set ACTIONS_RUNNER_INPUT_TOKEN env var",
    );
}

// sec05_register_includes_preserve_env was deleted: the
// pre-DynamicUser model wrapped config.sh in `sudo --preserve-env=
// ACTIONS_RUNNER_INPUT_TOKEN -u USER --` so sudo's env_reset
// wouldn't strip the token before exec. Under DynamicUser, apply
// runs config.sh directly as root (systemd takes ownership of
// StateDirectory at unit start) so there's no sudo wrapper and
// no --preserve-env argv slot. The SEC-05 token-via-env contract
// still holds — `sec05_register_argv_does_not_contain_token`
// (sibling) pins that argv carries no token.

#[test]
fn sec05_remove_argv_does_not_contain_token() {
    let token = "GHARS-SEC05-REMOVE-TOKEN-654321";
    let home = Utf8Path::new("/var/lib/ghars/buckos");
    let ctx = sec05_ctx(home, token);
    let cmd = build_remove_cmd(&ctx);
    let argv = argv_strings(&cmd);
    for arg in &argv {
        assert!(
            !arg.contains(token),
            "remove argv leaked token: {arg:?} (full argv: {argv:?})",
        );
    }
    assert!(
        !argv.iter().any(|a| a == "--token"),
        "remove argv contains --token flag: {argv:?}",
    );
}

#[test]
fn sec05_remove_env_carries_token() {
    let token = "GHARS-SEC05-REMOVE-TOKEN-654321";
    let home = Utf8Path::new("/var/lib/ghars/buckos");
    let ctx = sec05_ctx(home, token);
    let cmd = build_remove_cmd(&ctx);
    assert_eq!(
        env_value(&cmd, RUNNER_TOKEN_ENV).as_deref(),
        Some(token),
        "remove did not set ACTIONS_RUNNER_INPUT_TOKEN env var",
    );
}

#[test]
fn sec05_register_argv_includes_expected_flags() {
    // Sanity check that the new argv still drives the runner.
    let ctx = sec05_ctx(Utf8Path::new("/var/lib/ghars/buckos"), "TOKEN");
    let cmd = build_register_cmd(&ctx);
    let argv = argv_strings(&cmd);
    for required in ["--url", "--name", "--labels", "--unattended", "--replace"] {
        assert!(
            argv.iter().any(|a| a == required),
            "register argv missing {required}: {argv:?}",
        );
    }
}

#[test]
fn sec05_remove_argv_includes_remove_subcommand() {
    let ctx = sec05_ctx(Utf8Path::new("/var/lib/ghars/buckos"), "TOKEN");
    let cmd = build_remove_cmd(&ctx);
    let argv = argv_strings(&cmd);
    assert!(argv.iter().any(|a| a == "remove"), "{argv:?}");
    assert!(argv.iter().any(|a| a == "--unattended"), "{argv:?}");
}
