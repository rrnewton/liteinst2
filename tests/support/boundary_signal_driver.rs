#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "../boundary_signal_oracle.rs"]
mod fixture;
fn main() {
    fixture::isolated_main();
}
