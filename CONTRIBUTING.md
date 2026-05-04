# Contributing to ghars

ghars is pre-1.0. Breaking changes are expected; backward-compatibility
shims (`serde(default)` for renamed fields, deprecated re-exports,
compat wrappers) are not accepted.

## Build, test, lint

```sh
cargo build
cargo nextest run         # do NOT use `cargo test`
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

`cargo test` runs the same tests but does not give per-test isolation;
this repository standardizes on nextest. CI uses nextest exclusively.

The `runsvc-wrapper` binary is a SEC-02 root-owned trampoline. It builds
as part of `cargo build`. Tests that exercise privileged paths (chown,
fexecve, real systemd D-Bus) are gated on running as root and do not
run in default unprivileged CI; integration coverage for those paths
runs in a separate root-only job.

## Architectural rules (load-bearing)

These three rules exist because violating any of them causes wrong
behavior or panics that are hard to diagnose. Reviewers will block PRs
that break them.

### 1. `fn main()` is sync

`src/main.rs` is plain sync code. ghars does NOT use `#[tokio::main]`.
The only async code in the crate is the small octocrab-driven path in
`auth.rs` and `github.rs`; those modules use a `OnceLock<Runtime>` and
`runtime.block_on(...)` to bridge sync callers into async land at the
exact entry points they need.

### 2. `OnceLock<Runtime>` for octocrab only

The single tokio Runtime instance lives behind `OnceLock<Runtime>` and
is used only to drive octocrab's HTTP work. Do not pull more of tokio
into the dep graph (`Cargo.toml` declares `tokio = { default-features
= false, features = ["rt"] }` deliberately — no `macros`, no `time`,
no `rt-multi-thread`). Do not introduce `async fn` to module surfaces
that don't talk to GitHub.

### 3. zbus blocking-api is never inside an async block

`src/systemd/dbus.rs` uses `zbus::blocking::{Connection, Proxy}`. zbus's
blocking layer drives its own executor; calling it from inside a
tokio `async fn` (or from a future polled by the OnceLock runtime)
deadlocks the executor. Keep all zbus calls in sync functions reached
from the main thread, never from within `runtime.block_on(...)`.

A useful mental model: there are two cooperating worlds in ghars —
GitHub I/O is async (octocrab/reqwest/tokio) and everything else is
sync (zbus, file I/O, process spawning). The boundary is one-way:
sync code calls into async via `block_on`; async code does not call
back out into zbus.

## Module overview

Source tree: `src/lib.rs`, `src/main.rs`, the modules listed in
`lib.rs`, and the `runsvc-wrapper` binary under `src/bin/`.

| File | Responsibility |
|---|---|
| `lib.rs` | Public surface. Re-exports `GharsError`, `Result`, `Paths`. Defines the crate-wide `USER_AGENT` constant. |
| `main.rs` | Binary entrypoint. Initializes `tracing_subscriber`, parses `Cli`, dispatches, maps errors to exit code 1. |
| `error.rs` | `GharsError` enum (Config / Validation / Interactive / Preflight / GitHub / Systemd / Auth / Apply / Io / Tarball / Sha256Mismatch / ApplyLocked) + `Result<T>` alias. Every variant carries an actionable hint. |
| `paths.rs` | `Paths` struct. Centralizes `/etc/ghars/`, `/var/lib/ghars/`, `/usr/lib/ghars/`, runner-home, unit-file, drop-in-dir, cache-unit-file, cache-drop-in-dir, resolved-drop-in resolution. Test code redirects via constructor. |
| `validators.rs` | All regex/range validators ported from the Python tool: identifier, URL, sha256, semver, memory_max, label charset, hook script (lstat-based), CIDR, capability denylist, bind-path denylist. |
| `config.rs` | Top-level `Config` plus `Defaults`, `RunnerSpec`, `EffectiveRunnerSpec`, `Hardening`, `AuthSpec`, `CachePoolSpec`, `NetworkSpec`, `ProxySpec`, `HooksSpec`, `Arch`. `serde(deny_unknown_fields)` everywhere. |
| `state.rs` | `discover()` reads systemd's view of the world (managed `ghars-runner@*.service` units, drop-ins, drift status) into `ActualState`. `Drift` tracks whether the unit text or drop-ins were edited out-of-band. |
| `plan/` | `Plan`, `Action` (CreateRunner / UpdateRunner / RemoveRunner / CreateCachePool / UpdateCachePool / RemoveCachePool / NoOp), `RunnerDelta`, `RunnerPlan`, `plan_from()`. Owns count-block expansion, defaults-merge, spec-hash computation, and recreate-vs-in-place classification. Submodules: `action`, `types`, `expand`, `merge`, `hash`, `classify`, `compute`. |
| `apply/` | Executor. Sorts actions into phases, takes `apply.lock`, runs each `Action` against the `Systemd` / `Tarball` / `ConfigShell` traits plus the auth registry, accumulates results, surfaces `--fail-fast`. Submodules: `orchestrator`, `runners`, `pools`, `netns`, `undo`, `lock`, `writes`, `outcome`, `phases`, `gc`, `audit`, `rmrf`, `shell`, `tarball`. |
| `systemd/` | `Systemd` adapter trait + `DbusSystemd` (zbus blocking) impl, plus the unit-text generator (template service file + numbered drop-ins for hardening, network, proxy, hooks, cache, operator overrides) and the nft rule generator for netns. Submodules: `dbus`, `units`, `nft`. |
| `github.rs` | Octocrab wrapper: `parse_url` (URL → Scope), release fetching, registration-token minting, sha256 extraction from release notes, blocking reqwest client construction with system trust roots. |
| `auth.rs` | `TokenSource` trait + `PatToken`, `TokenFileToken`, `GithubAppToken`, `InteractiveToken`. App auth uses `jsonwebtoken::EncodingKey`. Private keys are read with `O_NOFOLLOW` and mode/owner enforcement (SEC-06). |
| `extract.rs` | Streaming tarball download (sha256 verified during stream), tarball safe-filter (path traversal + symlink escape rejected), runner-binary install with versioned `bin.X.Y.Z` directories and atomic directory swap via `renameat2(RENAME_EXCHANGE)` (with a remove-then-rename fallback when the kernel/FS lacks `RENAME_EXCHANGE`). |
| `preflight.rs` | OS / kernel / systemd-version / `/dev/kvm` / D-Bus / required-tools / root checks. Returns a `Vec<CheckResult>` for `ghars status`. |
| `netns.rs` | Network namespace lifecycle: `setup` (create netns, veth, addresses, routes, nft rules), `teardown`, `run_in_netns` (nsenter wrapper for the hidden `_netns-veth` subcommand). |
| `cli/` | `Cli`, `Command`, all `*Args` structs, dispatch logic, color/quiet handling, plan/status/metrics rendering (table + JSON), `init` scaffold contents, `add` TOML appender. Submodules: `args`, `load`, `render`, `json`, `cmd_apply`, `cmd_plan`, `cmd_status`, `cmd_metrics`, `cmd_misc`, `exit_codes`. |
| `bin/runsvc_wrapper.rs` | Verify-only trampoline running at the unit's `DynamicUser`-allocated identity. Verifies `runsvc.sh` against the `X-Ghars-Runsvc-Sha256` annotation by file descriptor, then `fexecve`s the verified fd. No `setuid`/`setgid`/`setgroups` — `DynamicUser=yes` establishes runner identity before the wrapper starts. SEC-02. |

## PR process

1. Branch off `main`. Keep PRs scoped to one logical change.
2. Run `cargo build`, `cargo nextest run`, `cargo clippy`, `cargo fmt --check` locally before pushing.
3. Open the PR against `likewhatevs/ghars`. Fill in the test plan with a checklist of what you exercised — only items that are done, every box checked.
4. CI must be green before review. CI runs build + nextest + clippy + fmt + coverage + (nightly) cargo-mutants.
5. Reviewers will read both the diff and the call sites of anything you changed. The architectural rules above are non-negotiable; expect to be asked to refactor if you cross the sync/async boundary or introduce a new tokio dependency.
6. Squash on merge. Commit subject is imperative; the body explains why.

## Deferred to v0.2

The following capabilities are scoped out of v0.1. The CLI surface
deliberately omits flags for them so operators don't see options that
silently do nothing. They will land in v0.2 with the underlying
implementation.

- **`--refresh-releases` on `plan` / `apply`.** v0.1 always queries
  the actions/runner releases API on demand whenever a runner
  spec lacks `runner_version` + `runner_sha256`. Forcing a fresh
  lookup when those fields ARE pinned (to pick up a republished
  asset) is v0.2 work that requires plumbing through the cache
  invalidation path; the flag is omitted until then so it cannot
  silently no-op.

- **`--output-dir` on `plan`.** v0.1 renders plans only to stdout
  (text + `--json`) and to the host's canonical paths under `Paths`
  during apply. Writing the rendered unit files + drop-ins into a
  caller-chosen scratch directory (for diff review, manifest
  generation, audit pipelines) is v0.2 work; the flag is omitted
  until the artifact-writer abstraction lands.

## Reporting security issues

Do not file public issues for security findings. Email
`patso@likewhatevs.io` with the details. ghars touches privileged
operations (root-owned trampoline, network namespaces, systemd unit
generation, GitHub registration tokens), so the security envelope is a
first-class concern; we'll prioritize and credit reporters in the
release notes once a fix has shipped.
