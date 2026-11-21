//! Stable disabled managed points: one worker, one control, two real images.
//! Direct generated-entry calls, not source publication or interval conversion.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
include!("real.rs");

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    panic!("point-throughput requires Linux x86-64");
}
