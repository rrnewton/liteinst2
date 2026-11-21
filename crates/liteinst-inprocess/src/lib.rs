//! Caller-owned Linux/x86-64 in-process execute admission.
//!
//! Core publication is completed eagerly before this crate is armed. The
//! SIGSEGV handler only verifies final bytes and releases a prepared page bundle.
//! This is not a loader, a ptrace adapter, or proof of arbitrary ELF entry coverage.
//!
//! The gate runtime (fault handling, raw syscalls, signals, selected-output
//! publication, and zpoline) exists only on Linux x86-64. Off that target
//! this crate still compiles with its portable planning surface
//! (`InstructionExtent`, `PageBundle`, `GateError`) so workspace builds do
//! not fail; there is no gate to arm there.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod fault;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod gate;
mod plan;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod raw;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod signal;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod selected;
/// Typed syscall-strategy selection, placement, outcome, and refusal names,
/// plus the one-site zpoline runtime. Selecting a config alone does not alter
/// process state; only zpoline publication does.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod syscall;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use gate::{ArmedGate, GateMetrics, PreparedGate};
pub use plan::{InstructionExtent, PageBundle};

/// Test-only allocation tracker: records whether one registered heap
/// pointer is ever deallocated, so custody regressions can detect actual
/// table deallocation deterministically instead of inferring it.
#[cfg(test)]
pub(crate) mod test_alloc {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    static TARGET_PTR: AtomicUsize = AtomicUsize::new(0);
    static TARGET_FREED: AtomicBool = AtomicBool::new(false);

    pub(crate) fn watch(ptr: usize) {
        TARGET_FREED.store(false, Ordering::Release);
        TARGET_PTR.store(ptr, Ordering::Release);
    }

    pub(crate) fn target_freed() -> bool {
        TARGET_FREED.load(Ordering::Acquire)
    }

    pub(crate) struct Tracking;

    unsafe impl GlobalAlloc for Tracking {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: forwards the caller's layout contract to System.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if ptr as usize == TARGET_PTR.load(Ordering::Acquire) && !ptr.is_null() {
                TARGET_FREED.store(true, Ordering::Release);
            }
            // SAFETY: forwards the caller's layout contract to System.
            unsafe { System.dealloc(ptr, layout) }
        }
    }
}

#[cfg(test)]
#[global_allocator]
static TEST_ALLOC: test_alloc::Tracking = test_alloc::Tracking;

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
