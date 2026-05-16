//! `ghars validate` + `ghars plan` command handlers and the shared
//! D-Bus / plan-construction plumbing they call.

use std::io::{self, Write};

use camino::Utf8Path;

use crate::Result;
use crate::config::Config;
use crate::error::GharsError;
use crate::paths::Paths;
use crate::plan::{self, Action, Plan};
use crate::state;
use crate::systemd::DbusSystemd;

use super::args::{ColorMode, PlanArgs, ValidateArgs};
use super::exit_codes::dry_run_exit_code;
use super::load::{build_auth_registry, load_config};
use super::render::render_plan;

pub(super) fn cmd_validate(
    config_path: &Utf8Path,
    args: &ValidateArgs,
    quiet: bool,
) -> Result<i32> {
    // load_config runs the full post-load validator sweep
    // (validate_networks + validate_security_overrides +
    // validate_identity_fields + validate_no_duplicate_caches +
    // validate_cache_pool_names + validate_runner_names +
    // validate_pat_xor + validate_runner_tarballs +
    // validate_netns_runner_name_lengths).
    // cmd_validate need not repeat them.
    let cfg = load_config(config_path)?;
    // Structural validation: build the registry (constructors enforce
    // env / file / mode), then plan against an empty actual state. The
    // planner runs cross-reference validators (auth / cache / network)
    // as a side-effect of expansion + lower_to_effective.
    let registry = build_auth_registry(&cfg.auth).map_err(|e| match e {
        GharsError::Auth(msg, hint) => {
            GharsError::Validation(format!("auth registry: {msg}"), hint)
        }
        other => other,
    })?;
    let paths = Paths::default();
    let actual = state::ActualState::default();
    let plan = plan::plan_from(&cfg, &actual, &paths)?;
    // `cmd_plan` / `cmd_apply` route through `compute_plan`, which runs
    // `unit_verify::verify_plan` on the rendered drop-ins (Part 13
    // Tier 5: `systemd-analyze verify` gate). `cmd_validate` ALSO renders drop-ins (via
    // `plan_from` above), so without the same gate here, an operator
    // running `ghars validate` and getting "config OK" would still see
    // a `systemd-analyze verify` failure on `ghars plan` / `ghars
    // apply`. The validate command must be a strict superset gate —
    // anything `plan` would reject, `validate` must reject too.
    let verifier = crate::unit_verify::RealVerifier;
    crate::unit_verify::verify_plan(&plan, &paths.runtime_dir, &verifier)?;

    if args.deep {
        // Round-trip token mints. We do NOT print or persist the
        // token; success is the only signal needed.
        for (name, source) in &registry {
            if let Some(spec) = cfg.runners.iter().find(|r| match &r.auth {
                Some(a) => a == name,
                None => cfg.defaults.auth.as_deref() == Some(name),
            }) {
                source
                    .mint_registration_token(&spec.url)
                    .map_err(|e| match e {
                        GharsError::Auth(msg, hint) => {
                            GharsError::Auth(format!("auth {name:?}: {msg}"), hint)
                        }
                        other => other,
                    })?;
            }
        }
    }

    if !quiet {
        let _ = writeln!(io::stdout(), "config OK ({config_path})");
    }
    Ok(0)
}

pub(super) fn cmd_plan(
    config_path: &Utf8Path,
    paths: &Paths,
    args: &PlanArgs,
    color: ColorMode,
    quiet: bool,
) -> Result<i32> {
    // load_config runs the full post-load validator sweep — the
    // pre-batch-18 per-cmd repeats (validate_identity_fields,
    // validate_no_duplicate_caches, validate_cache_pool_names,
    // validate_runner_names,
    // validate_runner_tarballs) were moved into load_config so
    // cmd_plan, cmd_status, cmd_add etc. all share the same gate.
    let cfg = load_config(config_path)?;
    let plan = compute_plan(&cfg, paths, &args.only)?;
    render_plan(&plan, color, args.json, quiet, args.diff)?;
    // `--detailed-exitcode` opts into terraform-plan parity:
    // exit 2 when the plan contains any non-NoOp action, 0 otherwise.
    // `--detailed-exitcode-recreate` opts in independently:
    // exit 8 when the plan contains a recreate-class action.
    // Mirrors `dry_run_exit_code` and `apply_exit_code` so all three
    // paths (`plan`, `apply --dry-run`, `apply`) emit the same code
    // for "changes detected" / "recreates detected" when the flags
    // are set. Without either flag, this returns 0 — the default-mode
    // behavior CI scripts currently rely on stays unchanged.
    Ok(dry_run_exit_code(
        args.detailed_exitcode,
        args.detailed_exitcode_recreate,
        &plan,
    ))
}

/// Open the system D-Bus and wrap the failure mode that operators
/// most often hit when running `ghars plan` or `ghars apply --dry-run`
/// without root.
///
/// Without this wrapper, `DbusSystemd::new()` propagates a raw
/// zbus connection error like `"system D-Bus connect failed:
/// permission denied"` which doesn't tell the operator what to do
/// next. The wrapper preserves the underlying message but rewrites
/// the hint so `Display` of the resulting `GharsError::Validation`
/// includes the actionable instruction (run as root or grant a
/// polkit policy).
pub(super) fn open_dbus() -> Result<DbusSystemd> {
    DbusSystemd::new().map_err(|e| match e {
        GharsError::Systemd(msg, _) => GharsError::Validation(
            format!("ghars plan / apply requires system D-Bus access: {msg}"),
            "run as root, or grant the calling user a polkit policy that \
             allows access to org.freedesktop.systemd1 (typically \
             /usr/share/polkit-1/rules.d/)"
                .into(),
        ),
        other => other,
    })
}

pub(super) fn compute_plan(cfg: &Config, paths: &Paths, only: &[String]) -> Result<Plan> {
    let systemd = open_dbus()?;
    let actual = state::discover(&systemd, paths)?;
    let mut plan = plan::plan_from(cfg, &actual, paths)?;
    if !only.is_empty() {
        plan.actions.retain(|a| action_matches_filter(a, only));
    }
    // Plan-time `systemd-analyze verify` gate (Part 13 Tier 5).
    // Run AFTER the `--only` filter so operators who scope
    // a partial apply only pay the verification cost for the actions
    // they're actually going to apply. Errors propagate as
    // GharsError::Validation; cmd_plan / cmd_apply surface them
    // verbatim alongside config-time validation failures.
    let verifier = crate::unit_verify::RealVerifier;
    crate::unit_verify::verify_plan(&plan, &paths.runtime_dir, &verifier)?;
    Ok(plan)
}

pub(super) fn action_matches_filter(action: &Action, only: &[String]) -> bool {
    let label = action.label();
    only.iter().any(|frag| label.contains(frag.as_str()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn action_matches_filter_empty_filter_matches_nothing() {
        let action = Action::NoOp("buckos: in sync".into());
        assert!(
            !action_matches_filter(&action, &[]),
            "empty filter must NOT match — callers gate on `!only.is_empty()` upstream",
        );
    }

    #[test]
    fn action_matches_filter_substring_matches_runner_name() {
        let action = Action::NoOp("buckos: in sync".into());
        assert!(action_matches_filter(&action, &["buckos".into()]));
    }

    #[test]
    fn action_matches_filter_no_substring_does_not_match() {
        let action = Action::NoOp("buckos: in sync".into());
        assert!(!action_matches_filter(&action, &["other".into()]));
    }

    #[test]
    fn action_matches_filter_any_fragment_matches() {
        // OR semantics across fragments — operator passes `--only a,b`
        // and either match triggers retention.
        let action = Action::NoOp("buckos: in sync".into());
        assert!(action_matches_filter(
            &action,
            &["other".into(), "buckos".into()]
        ));
    }

    #[test]
    fn action_matches_filter_label_substring_in_brackets_matches() {
        // `Action::label()` for NoOp produces `NoOp(REASON)`; the
        // substring match catches `NoOp` as well as inner tokens.
        let action = Action::NoOp("buckos".into());
        assert!(action_matches_filter(&action, &["NoOp".into()]));
    }
}
