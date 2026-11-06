//! Standalone finite-corpus software preemption; no Hermit or PMU dependency.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
include!("preempt_main.rs");

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    panic!("liteinst-preempt requires Linux x86-64");
}
