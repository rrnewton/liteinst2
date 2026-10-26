#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Finite original anonymous mapping lifecycle. Five exact outer outcomes are
//! distinct from the original instruction counts and the corruption subcases.
#[path = "support/b3_mapping/mod.rs"]
mod b3_mapping;
use b3_mapping::{fixture::Fixture, raw, run};
use std::sync::Arc;

#[test]
fn original_rw_rx_rw_rx_unmap_matches_raw_full_state_and_two_runtime_sources() {
    let fixture = Fixture::new();
    let rows = Arc::new(raw::original(Arc::clone(&fixture)));
    run::positive(fixture, rows);
}

#[test]
fn stale_capture_reply_after_real_second_rx_preserves_partial_kernel_history() {
    let fixture = Fixture::new();
    let rows = Arc::new(raw::original(Arc::clone(&fixture)));
    run::stale(fixture, rows);
}

#[test]
fn resolver_panic_after_real_rx_keeps_failure_and_original_physical_cleanup() {
    let fixture = Fixture::new();
    let rows = Arc::new(raw::original(Arc::clone(&fixture)));
    run::panic(fixture, rows);
}

#[test]
fn blocked_resolver_expires_original_deadline_before_callback_is_released() {
    let fixture = Fixture::new();
    let rows = Arc::new(raw::original(Arc::clone(&fixture)));
    run::timeout(fixture, rows);
}

#[test]
fn full_native_mapping_comparator_rejects_each_state_source_and_map_corruption() {
    let fixture = Fixture::new();
    let rows = Arc::new(raw::original(Arc::clone(&fixture)));
    let observed = run::positive(fixture, rows);
    run::corrupt(&observed);
}
