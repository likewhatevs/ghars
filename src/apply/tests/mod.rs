//! In-tree tests for the `apply` module. Split across submodules to
//! keep individual files under the 3500-line limit; common mocks +
//! fixtures live in [`common`].

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod apply_tests;
mod audit_tests;
mod caches_tests;
mod common;
mod gc_tests;
mod lock_tests;
mod netns_tests;
mod outcome_tests;
mod pools_tests;
mod recreate_tests;
mod rmrf_tests;
mod runners_tests;
mod shell_tests;
mod undo_tests;
mod writes_tests;
