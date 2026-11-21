//! Separately invoked target / produce / verify / controls / run stages.
//! Ordinary tests never execute this example. Output bindings are written last.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
extern crate li2core as liteinst;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
extern crate li2core as liteinst2;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
include!("adjacent_b2_native.rs");

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    panic!("adjacent B2 native campaign requires Linux x86-64");
}
