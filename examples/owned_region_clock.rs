//! One owned scalar region, two clocked backedges and real quiescent publication.
//! Positive client integration only: no retirement, throughput or full-state
//! comparison after callbacks. Code and installed routes remain process-lived.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
include!("owned_region_clock/real.rs");

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    panic!("owned_region_clock requires Linux x86-64");
}
