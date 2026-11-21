//! Isolated entry point for the successor eviction native oracle.

#![deny(warnings)]

// This is compiled as an ordinary binary, never with --test. The exact same
// fixture bodies and strict oracle module are shared with the parent test.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "../successor_eviction_oracle.rs"]
mod fixture;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    fixture::isolated_main();
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    panic!("successor eviction native oracle requires Linux x86-64");
}
