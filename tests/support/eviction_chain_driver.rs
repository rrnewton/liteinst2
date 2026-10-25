//! Isolated entry point for the eviction-chain native oracle.

#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "../eviction_chain_oracle.rs"]
mod fixture;
fn main() {
    fixture::isolated_main();
}
