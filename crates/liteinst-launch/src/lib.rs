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
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
pub(crate) static TEST_FILE_FORK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Shared native-oracle helpers are available only in the unit-test build.
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
extern crate self as liteinst_launch;
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
#[doc(hidden)]
#[path = "../tests/support/b3_exec/mod.rs"]
pub mod exec_oracle_support;
