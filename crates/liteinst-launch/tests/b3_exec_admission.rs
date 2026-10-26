#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Five finite public outcomes. The private same-tracer and complete retained
//! history controls have separate native evidence; public counts cannot replace them.
#[path = "support/b3_exec/mod.rs"]
mod b3_exec;
use b3_exec::{Fixture, raw, run};
use std::sync::Arc;

// The same helper is included by the unit harness, whose crate-root lock also
// protects other fixture writers. Integration tests have their own process.
#[cfg(test)]
pub(crate) static TEST_FILE_FORK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn original_exec_replacement_matches_raw_replay_and_native_full_state() {
    let fixture = Fixture::new();
    let reference = Arc::new(raw::original(Arc::clone(&fixture)));
    run::positive(fixture, reference);
}
#[test]
fn stale_exec_source_reply_preserves_actual_replacement_without_commit() {
    let fixture = Fixture::new();
    let reference = Arc::new(raw::original(Arc::clone(&fixture)));
    run::stale(fixture, reference);
}
#[test]
fn resolver_panic_after_actual_exec_keeps_original_failure_and_cleanup() {
    let fixture = Fixture::new();
    let reference = Arc::new(raw::original(Arc::clone(&fixture)));
    run::panic(fixture, reference);
}
#[test]
fn blocked_exec_resolver_uses_original_deadline_and_owner_cleanup() {
    let fixture = Fixture::new();
    let reference = Arc::new(raw::original(Arc::clone(&fixture)));
    run::timeout(fixture, reference);
}
#[test]
fn exec_full_comparator_rejects_each_state_input_map_and_identity_corruption() {
    let fixture = Fixture::new();
    let reference = Arc::new(raw::original(Arc::clone(&fixture)));
    let observed = run::positive(fixture, reference);
    run::corrupt(&observed);
}
