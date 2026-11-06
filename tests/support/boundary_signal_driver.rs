//! Isolated entry point for the boundary signal native oracle.

#![deny(warnings)]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "../boundary_signal_oracle.rs"]
mod fixture;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    fixture::isolated_main();
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    panic!("boundary signal native oracle requires Linux x86-64");
}
