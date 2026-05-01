# Architecture

The lifecycle is **config → plan → apply**. The TOML file is the
source of truth; `ghars plan` reads desired state and discovers
actual state; `ghars apply` converges. Side effects flow through a
single critical section serialized by an exclusive POSIX advisory
lock on `<runtime_dir>/apply.lock`.

## Module map

The library crate (`ghars`) is composed of these modules
(`src/lib.rs`):

| module        | role                                                       |
|---------------|------------------------------------------------------------|
| `cli`         | clap definitions + command dispatch + exit-code mapping    |
| `config`      | TOML schema + serde types + `[defaults]` merge             |
| `plan`        | desired vs actual diff → ordered `Vec<Action>`             |
| `apply`       | execute a `Plan` against the host                          |
| `state`       | discover actual state from systemd + disk                  |
| `systemd`     | D-Bus adapter (`zbus` blocking) + unit/drop-in renderer    |
| `auth`        | `TokenSource` trait + PAT/GitHub App/Interactive/TokenFile |
| `github`      | `octocrab`-backed registration / removal / release queries |
| `extract`     | streaming download + sha256 verify + safe tar extract      |
| `paths`       | filesystem layout (`Paths` struct)                         |
| `preflight`   | host-readiness checks                                      |
| `netns`       | per-runner netns + veth + nft rule helpers                 |
| `validators`  | post-parse semantic gates                                  |
| `unit_verify` | inspect on-disk drop-ins for runtime drift                 |
| `error`       | `GharsError` enum + exit-code mapping types                |

The two `[[bin]]` targets:

- `ghars` (`src/main.rs`) — the CLI binary. Calls into the lib
  via `ghars::cli::dispatch`.
- `runsvc-wrapper` (`src/bin/runsvc_wrapper.rs`) — the
  integrity-checking trampoline. Installed by packaging at
  `/usr/lib/ghars/runsvc-wrapper`. Compiled binary, NOT a shell
  script.

## Lifecycle: config → plan → apply

### 1. Config load (`config.rs`, `cli.rs::load_config`)

`cli::load_config` reads `--config PATH` (default
`/etc/ghars/ghars.toml`), runs `toml::from_str`, then runs the
post-parse validator chain documented in
[Configuration](./configuration.md#validators). Every validator
short-circuits on the first failure and prepends a scope
(`runner "NAME":`, `[network.NAME]:`, etc.) so the operator can
locate the offending block.

`AuthSpec` resolution (`build_auth_registry`) is deferred to
`validate --deep` and `apply` so config-shape failures surface
before external IO / file-mode gates fire.

### 2. State discovery (`state.rs`)

`state::discover` enumerates:

- `ghars-runner@*` and `ghars-cache@*` instances by `fs::read_dir`
  on `<unit_dir>` and matching the filename shape. The on-disk
  scan is the source of truth — it picks up units that exist on
  disk but have not been `daemon-reload`ed yet, which a D-Bus
  `Manager.ListUnitsFiltered` query would miss.
- Per-instance drop-ins on disk under
  `<unit_dir>/ghars-runner@NAME.service.d/` and
  `<unit_dir>/ghars-cache@POOL.service.d/`.
- The `X-Ghars-*` annotations in each `00-ghars.conf` drop-in
  (`extract_x_ghars`).
- `ActiveState` and `UnitFileState` per discovered unit via the
  `Systemd` D-Bus trait (`zbus` blocking-API).

The result is `ActualState`: known runners and pools with their
discovered annotations and drop-in basenames. The plan engine
diffs the desired specs against this.

### 3. Plan computation (`plan.rs::plan_from`)

Four orthogonal pieces (see the `plan.rs` module-level doc):

1. `expand_counts` — flatten `[[runner]] count = N` blocks into one
   `RunnerSpec` per generated name. Auto-skip collisions with
   explicit blocks; error on cross-block overlap.
2. `merge_defaults` — produce an `EffectiveRunnerSpec` from a
   `RunnerSpec` + `Defaults` per the merge rules.
3. `spec_hash` — canonical-JSON SHA-256 of the
   `EffectiveRunnerSpec`. The on-disk `X-Ghars-Spec-Hash`
   annotation is what plan compares against to detect config
   changes.
4. `plan_from` — diff desired effective specs against
   `ActualState` and emit the ordered `Vec<Action>`.

The `Action` enum:

| variant            | summary                                        |
|--------------------|------------------------------------------------|
| `CreateRunner`     | new runner: registration + unit + start        |
| `UpdateRunner`     | existing runner: in-place rewrite OR recreate  |
| `RemoveRunner`     | stop + deregister + remove                     |
| `CreateCachePool`  | new pool: drop-in + storage + start            |
| `UpdateCachePool`  | existing pool: rewrite drop-in + restart       |
| `RemoveCachePool`  | drop-in + storage removal                      |
| `NoOp`             | in sync; carries a human-readable reason       |

`UpdateRunner` carries `requires_recreate: bool`; the plan
classifier sets it true when an identity-bound field changed
(`url`, `runner_version`, `labels`, `arch`, `runner_sha256`,
`runner_tarball`, `network`), or when `runsvc.sh` integrity is
missing (no `X-Ghars-Runsvc-Sha256` annotation), or as the
conservative `"uncovered"` fallback. The full vocabulary lives in
`RunnerDelta::recreate_reasons`.

`plan_from` itself emits actions in alphabetical name order;
`apply::sort_into_phases` re-orders into the canonical execution
order.

### 4. Plan disruption taxonomy (`plan::Disruption`)

Every `Action` carries a worst-case `Disruption`:

| level      | meaning                                                              |
|------------|----------------------------------------------------------------------|
| `None`     | no scheduled host mutation (`NoOp`; in-place restart at apply time can also short-circuit here, but plan reports `Restart` because the optimization keys on byte-equality which plan does not consult) |
| `Restart`  | stop + start of the affected unit (in-place `UpdateRunner`, `UpdateCachePool`)                              |
| `Recreate` | tear down + reconstruct (`CreateRunner`, recreate-class `UpdateRunner`, `RemoveRunner`, `CreateCachePool`, `RemoveCachePool`) |

Variants are ordered least → most disruptive; derived `PartialOrd`
/ `Ord` lets callers guard with `disruption >=
Disruption::Recreate` without a hand-rolled comparator. `Plan::has_recreate`
walks the action vec and drives the `--detailed-exitcode-recreate`
exit-code 8 path.

### 5. Apply (`apply.rs::apply`)

`apply` is the single entry point. Its lifecycle:

1. Acquire `<runtime_dir>/apply.lock` via `fs2::FileExt`
   (POSIX advisory exclusive lock). The lock file embeds the
   holding apply's PID; another apply that finds the file fails
   with `GharsError::ApplyLocked` carrying the lock-holder's PID.
2. (skipped under `--dry-run`) GC stale
   `.NAME.tmp.PID.COUNTER` temp files under `unit_dir`,
   per-runner drop-in dirs, per-pool drop-in dirs,
   `config_dir/nft.d/`, and `config_dir/netns.d/` — leftovers from
   `write_root_owned` calls that crashed between `create_new` and
   the final rename. Best-effort, never fails apply.
3. (skipped under `--dry-run`) GC stale
   `<state_dir>/.staging/<name>-<version>-<pid>/` directories —
   leftovers from `extract::install_runner_binary` calls that
   crashed past their own cleanup branch.
4. Sort `plan.actions` into the canonical phase order (next
   section).
5. For each action: capture `plan_disruption =
   action.disruption()`, dispatch through `execute(&action,
   deps, paths, &mut log, plan.keep_versions)`. On Ok: append a
   `(label, ApplyOutcome)` row to `result.details`. On Err:
   under `--rollback-on-failure`, walk this action's `UndoLog`
   in reverse via `undo`. Either way, record a
   `(label, ApplyOutcome::Failed { error_summary,
   plan_disruption })` row in `result.details` and a
   `(label, GharsError::Apply)` pair in `result.failed`. Push
   the consumed `UndoLog` steps into
   `result.failed_undo_logs` (preserves the
   `failed[i].0 == failed_undo_logs[i].0` invariant). Append a
   line to `<logs_dir>/apply.log` (SEC-36 audit log) per action.
6. (skipped under `--dry-run`) Issue a single
   `Manager.Reload` (`daemon-reload`) at the end.
7. Release the lock on Drop (the `_lock` variable goes out of
   scope; `fs2`'s `FileExt::unlock` runs as the file handle
   drops).

### 6. Phase order (`apply::sort_into_phases`)

The canonical execution order:

```
CreateCachePool
UpdateCachePool
RemoveRunner
UpdateRunner   (in-place subset first)
UpdateRunner   (recreate subset second)
CreateRunner
RemoveCachePool
NoOp           (skipped at the loop head)
```

Within each phase, actions sort by their identifier
(`action_sort_key`) for determinism. The order is invariant under
plan-emit order — `plan_from` sorts by name, but apply re-sorts
into phases regardless.

Why this order:

- Cache pools come first because runners depend on the
  `BindPaths=` entries in their drop-ins resolving to existing
  pool storage and unit names.
- `RemoveRunner` runs before `UpdateRunner` and `CreateRunner`
  so a removal followed by a recreate of the same name doesn't
  collide.
- `UpdateRunner` in-place precedes `UpdateRunner` recreate so
  the in-place subset (cheap; just a daemon-reload + restart)
  doesn't get blocked behind a long-running registration.
- `RemoveCachePool` runs last so a removal-then-create across
  pool names sees the new pool registered before it tries to
  unbind from the old one.

### 7. ApplyOutcome and ApplyResult

Each action produces exactly one `ApplyOutcome` row in
`ApplyResult.details`:

| variant                    | meaning                                                              |
|----------------------------|----------------------------------------------------------------------|
| `InPlaceSkipped`           | byte-equality short-circuit fired; no reload, no restart             |
| `InPlaceRestarted`         | files changed AND/OR cache-pool diff; reload + stop + start          |
| `Recreated`                | recreate-class `UpdateRunner` (remove → create flatten)              |
| `Created`                  | `CreateRunner` finished                                              |
| `Removed`                  | `RemoveRunner` finished                                              |
| `PoolCreated`              | `CreateCachePool` finished                                           |
| `PoolUpdated`              | `UpdateCachePool` rewrote the drop-in                                |
| `PoolSkipped`              | byte-equality short-circuit fired on the pool path                   |
| `PoolRemoved`              | `RemoveCachePool` finished                                           |
| `NoOp`                     | planner emitted in-sync                                              |
| `DryRunSkipped`            | `--dry-run` short-circuited the handler                              |
| `Failed`                   | execute returned Err; carries `error_summary` + `plan_disruption`    |

`ApplyResult` carries Vecs for `succeeded`, `failed`, `skipped`,
`details` (per-action audit trail in execution order), and
`failed_undo_logs` (per-failure mutation manifest for the
rollback advisory).

## Exit codes

`cli::dispatch` and `cli::err_to_exit_code` map outcomes to the
following codes (`main.rs` calls into the lib and exits with the
returned int):

| code | meaning                                                                  |
|------|--------------------------------------------------------------------------|
| 0    | success                                                                  |
| 1    | generic error (default; `GharsError::GitHub` / `Systemd` / `Io` / `Tarball` / `Sha256Mismatch` / `ApplyLocked` / `Apply`) |
| 2    | with `--detailed-exitcode`, plan diff non-empty (terraform parity)       |
| 3    | preflight failure (`GharsError::Preflight` or explicit `Ok(3)` from `cmd_apply` / `cmd_status`) |
| 4    | partial apply failure (some actions succeeded, some failed) — wins over 5 even when an Auth error is among the failures |
| 5    | full-failure apply with at least one Auth failure; also returned when top-level `GharsError::Auth` is raised |
| 6    | config-class rejection — `GharsError::Config` / `Validation`             |
| 7    | interactive prompting required but unavailable (`GharsError::Interactive`) |
| 8    | with `--detailed-exitcode-recreate`, plan contains a recreate-class action |

Failure precedence: 1, 4, and 5 always win over 8 (recreate is a
plan-shape signal; structural / post-execution failures are
stronger). 4 wins over 5 (partial-failure mix dominates pure-auth
failure).

## CLI surface

| command                       | summary                                                       |
|-------------------------------|---------------------------------------------------------------|
| `ghars validate [--deep]`     | parse + structural validation. `--deep` round-trips auth tokens against GitHub. |
| `ghars plan [...]`            | discover + diff + print. Flags: `--only`, `--json`, `--diff`, `--detailed-exitcode`, `--detailed-exitcode-recreate`. |
| `ghars apply [...]`           | run plan, prompt, execute. Flags: `--auto-approve`, `--fail-fast`, `--rollback-on-failure`, `--dry-run`, `--diff`, `--detailed-exitcode`, `--detailed-exitcode-recreate`. |
| `ghars status [...]`          | SYSTEM HEALTH + RUNNERS table. Flags: `--json`, `--metrics`, `--health-only`, `--runners-only`, plus positional names. |
| `ghars init [--output PATH]`  | scaffold `ghars.toml`. Per-runner system identities are NOT created here. |
| `ghars add [...]`             | append `[[runner]]` block + run `apply` unless `--no-apply`. Flags: `--repo`, `--name`, `--labels`, `--auth`. |
| `ghars logs [...]`            | wraps `journalctl -u ghars-runner@NAME.service`. Flags: `--follow`, `-n LINES`, `--since SPEC`. |
| `ghars metrics [...]`         | per-runner + total memory / CPU / IO / tasks via systemd D-Bus. |
| `ghars completions <shell>`   | emit shell completions to stdout.                              |
| `ghars manpages OUTPUT_DIR`   | generate man pages via `clap_mangen`.                          |

Three hidden subcommands (`_netns-setup`, `_netns-teardown`,
`_netns-veth`) are invoked by `ghars-net@INSTANCE.service` units
and are not part of the operator-facing surface. They bypass the
config loader and read per-instance state from
`<config_dir>/netns.d/INSTANCE.toml` written ahead of time by
`apply`.

## Async surface

`fn main()` is sync. `OnceLock<Runtime>` provides `block_on(...)`
for the small `octocrab`-driven async surface; zbus runs its own
executor in blocking mode. See
[Internals](./internals.md#async-runtime-surface) for the full
runtime selection rationale and feature-flag detail.

## Where to read next

- [Security](./security.md) — DynamicUser, trust zones, runtime
  integrity, sandbox hardening.
- [Internals](./internals.md) — `renameat2` atomicity, fsync
  durability, TOCTOU-safe file ops.
- [Operations](./operations.md) — `validate`, `status`,
  `plan --dry-run`, troubleshooting.
