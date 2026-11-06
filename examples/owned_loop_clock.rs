//! One private SysV buffer transform with synchronous BEFORE-backedge stops.
//! Explicit standalone example for a fixed call-free function and owned buffer.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
include!("owned_loop_clock/real.rs");

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    panic!("owned_loop_clock requires Linux x86-64");
}
