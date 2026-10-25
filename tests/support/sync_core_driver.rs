//! Isolated entry point for Linux core synchronization checks.

#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "../sync_core_capability.rs"]
mod fixture;
fn main() {
    fixture::isolated_main();
}
