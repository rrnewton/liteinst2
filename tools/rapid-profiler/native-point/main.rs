//! Finite real byte point controls. No interval, coalesced redirect, Word,
//! concurrent publication, saved-PC translation or performance qualification.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
include!("real.rs");

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    panic!("frontend-native-point requires Linux x86-64");
}
