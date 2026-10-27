//! Caller-owned Linux/x86-64 in-process execute admission.
//!
//! Core publication is completed eagerly before this crate is armed. The
//! SIGSEGV handler only verifies final bytes and releases a prepared page bundle.
//! This is not a loader, a ptrace adapter, or proof of arbitrary ELF entry coverage.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("liteinst-inprocess requires Linux x86-64");

mod fault;
mod gate;
mod plan;
mod raw;
mod signal;

pub mod selected;

pub use gate::{ArmedGate, GateMetrics, PreparedGate};
pub use plan::{InstructionExtent, PageBundle};

/// A preparation or fully restored setup failure. Uncertain live ownership
/// failures terminate the process instead of returning an ordinary error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateError {
    Invalid(&'static str),
    Os { operation: &'static str, errno: i32 },
}

impl core::fmt::Display for GateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "in-process page gate: {self:?}")
    }
}
impl std::error::Error for GateError {}
