#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

// This is compiled as an ordinary binary, never with --test. The exact same
// fixture bodies and strict oracle module are shared with the parent test.
#[allow(dead_code)]
#[path = "../successor_eviction_oracle.rs"]
mod fixture;

fn main() {
    fixture::isolated_main();
}
