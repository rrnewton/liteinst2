//! Isolated entry point for the extended eviction-chain native oracle.

#![deny(warnings)]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "../eviction_chain_extensions.rs"]
mod fixture;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    fixture::isolated_main();
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    panic!("extended eviction-chain native oracle requires Linux x86-64");
}
