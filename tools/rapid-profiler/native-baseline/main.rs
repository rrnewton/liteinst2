//! Fixed uninstrumented tree through the separately qualified private ABI stub.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
include!("real.rs");

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    panic!("tree-native-baseline requires Linux x86-64");
}
