//! Per-product constructor. It does not make arbitrary catalog activation safe.
#![forbid(unsafe_op_in_unsafe_fn)]
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("the named startup profile requires Linux x86-64");

use std::sync::atomic::{AtomicU64, Ordering};

// Private Rust visibility, hidden non-preemptible ELF data symbol for an
// external read-only observer. The package must verify its exact owned DSO,
// OBJECT type, size/alignment, non-TLS section and hidden/local binding before
// the observer joins its offset with that owner's load bias. This is completion
// only, never a qualification receipt.
#[used]
#[unsafe(no_mangle)]
static LITEINST_BOOTSTRAP_COMPLETION_V1: AtomicU64 = AtomicU64::new(0);
const _: [(); 8] = [(); std::mem::size_of::<AtomicU64>()];
const _: [(); 8] = [(); std::mem::align_of::<AtomicU64>()];
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
std::arch::global_asm!(".hidden LITEINST_BOOTSTRAP_COMPLETION_V1");

#[cfg(not(test))]
static CATALOG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/main.li2boot"));

fn terminate_startup() -> ! {
    // SAFETY: this is the terminal startup boundary. No stderr operation,
    // formatting, unwinding, panic payload drop, or application handoff occurs.
    unsafe { libc::_exit(125) }
}

/// Run only while the reviewed startup contract owns process-global panic-hook
/// state. The sole startup thread must not already be panicking; no concurrent
/// thread, callback or signal handler may use/change this Rust runtime's hook,
/// and `activate` must not replace it. These are caller obligations, not facts
/// established by the core's later observed single-thread check. Allocator,
/// Rust TLS and libc readiness are part of the same loader/startup contract.
/// Never expose this as a recoverable activation or general preload API.
unsafe fn initialize_terminal<F, E>(activate: F)
where
    F: FnOnce() -> Result<(), E> + std::panic::UnwindSafe,
{
    // take_hook returns the actual prior Box, including any captured state.
    // The exclusive startup lease covers the temporary default-hook interval.
    let prior_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| terminate_startup()));
    let result = std::panic::catch_unwind(activate);
    if !matches!(&result, Ok(Ok(()))) {
        // The installed hook already terminates ordinary Rust panics. Keep
        // catch_unwind's refusal branch terminal too, without dropping an Err
        // value or unwind payload that could execute arbitrary destructor code.
        terminate_startup();
    }
    // Restore the identical Box before the success flag. Replacing our inert,
    // capture-free hook cannot run a caller-controlled destructor here.
    std::panic::set_hook(prior_hook);
    LITEINST_BOOTSTRAP_COMPLETION_V1.store(1, Ordering::Release);
}

#[cfg(not(test))]
unsafe extern "C" fn initialize() {
    // SAFETY: this artifact is admitted only as the sole constructor in the
    // explicitly reviewed static-exec package/loader contract, including the
    // exclusive process-global panic-hook lease stated above. Integration must
    // qualify that contract before launch. The core independently enforces
    // measurable file/map/target/signal facts; it cannot infer historical
    // quiescence, semantic/lifetime facts, or the hook lease. This DSO must never
    // be distributed as a generic safe preload or dlopen library.
    unsafe {
        initialize_terminal(|| liteinst2::offline_router::initialize_static_exec(CATALOG));
    }
}

// Unit controls invoke the exact private boundary explicitly. Their build
// still requires normal build.rs catalog validation; there is no build bypass.
#[cfg(not(test))]
#[used]
#[unsafe(link_section = ".init_array")]
static INITIALIZE: unsafe extern "C" fn() = initialize;

/// Constructor completion only; never a semantic/native qualification receipt.
#[unsafe(no_mangle)]
pub extern "C" fn liteinst_bootstrap_status() -> u64 {
    LITEINST_BOOTSTRAP_COMPLETION_V1.load(Ordering::Acquire)
}

#[cfg(test)]
#[path = "../../../tests/support/isolated_native_test.rs"]
mod isolated_native_test;
#[cfg(test)]
mod tests;
