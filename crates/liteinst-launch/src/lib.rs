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
