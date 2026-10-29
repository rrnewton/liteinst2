//! Required fixed native optional-profile cases; not profiler/performance evidence.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[macro_use]
#[path = "support/native_fixture_registration.rs"]
mod native_fixture_registration;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[expect(
    unused_imports,
    reason = "harness=false omits inherited test bodies; calibration target runs them separately"
)]
#[path = "support/native_interval_oracle.rs"]
mod oracle;
fn main() {
    assert_eq!(std::env::args_os().len(), 1, "no filters or omitted cases");
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    oracle::native_ordinary::precontext::run();
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    panic!("required pre-context oracle needs Linux x86-64");
}
