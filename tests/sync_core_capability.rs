//! Integration tests for Linux core synchronization capabilities.

#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[path = "support/sync_core_isolation.rs"]
mod isolation;
#[path = "support/sync_core_witness.rs"]
mod witness;

/// Run the process-bound synchronization capability lifetime witness.
pub fn run_sync_core_capability_lifetime() {
    witness::run();
}

/// Dispatch the selected fixture on the fresh process main thread.
pub fn isolated_main() {
    isolation::main_thread_driver();
}

#[test]
fn sync_core_capability_lifetime() {
    isolation::run_parent("sync_core_capability_lifetime");
}
