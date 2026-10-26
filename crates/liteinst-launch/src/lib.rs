#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux::*;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod gate;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod core_remote;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod publication;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod selected;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod trap_coverage;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod lifecycle;

// Unit fixtures exclude writable executable FDs from concurrent fork inheritance.
#[cfg(all(
    any(test, feature = "dev-exec-backing-cleanup"),
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(crate) static TEST_FILE_FORK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Shared source is public only inside the existing unit-test crate.
#[cfg(all(
    any(test, feature = "dev-exec-backing-cleanup"),
    target_os = "linux",
    target_arch = "x86_64"
))]
extern crate self as liteinst_launch;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
#[doc(hidden)]
#[path = "../tests/support/b3_exec/mod.rs"]
pub mod exec_oracle_support;
#[cfg(all(
    not(test),
    feature = "dev-exec-backing-cleanup",
    target_os = "linux",
    target_arch = "x86_64"
))]
#[path = "../tests/support/b3_exec/mod.rs"]
pub(crate) mod exec_oracle_support;

#[cfg(all(
    test,
    feature = "dev-exec-backing-cleanup",
    target_os = "linux",
    target_arch = "x86_64"
))]
#[doc(hidden)]
#[path = "../tests/support/b3_exec_cleanup.rs"]
pub mod exec_cleanup_support;
#[cfg(all(
    not(test),
    feature = "dev-exec-backing-cleanup",
    target_os = "linux",
    target_arch = "x86_64"
))]
#[path = "../tests/support/b3_exec_cleanup.rs"]
pub(crate) mod exec_cleanup_support;

/// Run the closed development-only backing-cleanup controls.
/// No caller-supplied native or admission authority is accepted or returned.
#[cfg(all(
    feature = "dev-exec-backing-cleanup",
    target_os = "linux",
    target_arch = "x86_64"
))]
#[doc(hidden)]
pub fn __run_exec_backing_cleanup() -> std::process::ExitCode {
    linux::exec_backing_cleanup_main()
}
