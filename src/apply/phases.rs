//! Part 8 phase ordering for `apply()` — sort the planner-emitted
//! [`crate::plan::Action`] slice into canonical execution order.

use crate::plan::Action;

/// Stable sort key for action ordering within a phase.
fn action_sort_key(a: &Action) -> String {
    match a {
        Action::CreateRunner(p) => p.spec.name.clone(),
        Action::UpdateRunner(d) => d.identity.name.clone(),
        Action::RemoveRunner(i) => i.name.clone(),
        Action::CreateCachePool(p) => p.binding.name.clone(),
        Action::UpdateCachePool(d) => d.binding.name.clone(),
        Action::RemoveCachePool(name) => name.clone(),
        Action::NoOp(reason) => reason.clone(),
    }
}

/// Sort actions into Part 8's canonical execution order. Within each
/// phase, runners + pools are sorted by their identifier for
/// determinism (so `apply` is reproducible across plan invocations).
pub(super) fn sort_into_phases(actions: &[Action]) -> Vec<Action> {
    let mut create_cache: Vec<&Action> = Vec::new();
    let mut update_cache: Vec<&Action> = Vec::new();
    let mut remove_runner: Vec<&Action> = Vec::new();
    let mut update_runner_inplace: Vec<&Action> = Vec::new();
    let mut update_runner_recreate: Vec<&Action> = Vec::new();
    let mut create_runner: Vec<&Action> = Vec::new();
    let mut remove_cache: Vec<&Action> = Vec::new();
    let mut noops: Vec<&Action> = Vec::new();
    for a in actions {
        match a {
            Action::CreateCachePool(_) => create_cache.push(a),
            Action::UpdateCachePool(_) => update_cache.push(a),
            Action::RemoveRunner(_) => remove_runner.push(a),
            Action::UpdateRunner(d) if !d.requires_recreate => update_runner_inplace.push(a),
            Action::UpdateRunner(_) => update_runner_recreate.push(a),
            Action::CreateRunner(_) => create_runner.push(a),
            Action::RemoveCachePool(_) => remove_cache.push(a),
            Action::NoOp(_) => noops.push(a),
        }
    }
    for v in [
        &mut create_cache,
        &mut update_cache,
        &mut remove_runner,
        &mut update_runner_inplace,
        &mut update_runner_recreate,
        &mut create_runner,
        &mut remove_cache,
        &mut noops,
    ] {
        v.sort_by_key(|a| action_sort_key(a));
    }
    let mut out: Vec<Action> = Vec::new();
    for chunk in [
        create_cache,
        update_cache,
        remove_runner,
        update_runner_inplace,
        update_runner_recreate,
        create_runner,
        remove_cache,
        noops,
    ] {
        for a in chunk {
            out.push(a.clone());
        }
    }
    out
}
