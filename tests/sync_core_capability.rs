#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[path = "support/sync_core_isolation.rs"]
mod isolation;
#[path = "support/sync_core_witness.rs"]
mod witness;

pub fn run_sync_core_capability_lifetime() {
    witness::run();
}

pub fn isolated_main() {
    isolation::main_thread_driver();
}

#[test]
fn sync_core_capability_lifetime() {
    isolation::run_parent("sync_core_capability_lifetime");
}
