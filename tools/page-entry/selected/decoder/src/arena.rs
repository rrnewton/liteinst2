//! One bounded allocator, usable only while the decoder tables initialize.
//! Deallocated initialization blocks remain charged/owned in the arena.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use crate::abi::{self, DecoderStats};

const FRESH: u32 = 0;
const INITIALIZING: u32 = 1;
const SEALED: u32 = 2;
const POISONED: u32 = 3;
const MAX_ARENA: usize = 16 * 1024 * 1024;

pub(crate) const FATAL_ALLOC_PHASE: u32 = 101;
pub(crate) const FATAL_ARENA_EXHAUSTED: u32 = 102;
pub(crate) const FATAL_DEALLOC_PHASE: u32 = 103;
pub(crate) const FATAL_PANIC: u32 = 104;
pub(crate) const FATAL_COUNTER: u32 = 105;
pub(crate) const FATAL_UNSUPPORTED_UNWIND: u32 = 106;

static PHASE: AtomicU32 = AtomicU32::new(FRESH);
static FIRST_FATAL: AtomicU32 = AtomicU32::new(0);
static BASE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static CAPACITY: AtomicUsize = AtomicUsize::new(0);
static USED: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static DEALLOCS: AtomicUsize = AtomicUsize::new(0);
static IN_CALL: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    // Supplied freestanding implementation must retain the reason and terminate
    // the process; returning, unwinding or entering target libc is forbidden.
    fn li2_decoder_abort(reason: u32) -> !;
}

pub(crate) fn fatal(reason: u32) -> ! {
    let _ = FIRST_FATAL.compare_exchange(0, reason, Ordering::AcqRel, Ordering::Acquire);
    PHASE.store(POISONED, Ordering::Release);
    // SAFETY: the required linked callback is a nonreturning raw fail-stop.
    unsafe { li2_decoder_abort(FIRST_FATAL.load(Ordering::Acquire)) }
}

fn increment(counter: &AtomicUsize) {
    if counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
        .is_err()
    {
        fatal(FATAL_COUNTER);
    }
}

pub(crate) struct Arena;

// SAFETY: initialization is single-owner; atomics additionally serialize every
// monotone reservation. The caller keeps the complete arena uniquely owned and
// mapped for the process lifetime. No returned block overlaps an earlier one.
unsafe impl GlobalAlloc for Arena {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if PHASE.load(Ordering::Acquire) != INITIALIZING {
            fatal(FATAL_ALLOC_PHASE);
        }
        increment(&ALLOCS);
        let base = BASE.load(Ordering::Acquire);
        let capacity = CAPACITY.load(Ordering::Acquire);
        let mut old = USED.load(Ordering::Acquire);
        loop {
            let address = (base as usize)
                .checked_add(old)
                .and_then(|n| n.checked_add(layout.align() - 1))
                .map(|n| n & !(layout.align() - 1));
            let offset = address.and_then(|n| n.checked_sub(base as usize));
            let end = offset.and_then(|n| n.checked_add(layout.size().max(1)));
            let (offset, end) = match (offset, end) {
                (Some(offset), Some(end)) if end <= capacity => (offset, end),
                _ => fatal(FATAL_ARENA_EXHAUSTED),
            };
            match USED.compare_exchange_weak(old, end, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    // SAFETY: caller's allocation is live and this exact range
                    // was checked in bounds and uniquely reserved above.
                    return unsafe { base.add(offset) };
                }
                Err(next) => old = next,
            }
        }
    }

    unsafe fn dealloc(&self, _pointer: *mut u8, _layout: Layout) {
        if PHASE.load(Ordering::Acquire) != INITIALIZING {
            fatal(FATAL_DEALLOC_PHASE);
        }
        increment(&DEALLOCS);
        // No refund or reuse: all initialization high-water storage is retained.
    }
}

pub(crate) fn begin(pointer: *mut u8, bytes: usize) -> u32 {
    if pointer.is_null()
        || bytes == 0
        || bytes > MAX_ARENA
        || (pointer as usize).checked_add(bytes).is_none()
    {
        return abi::BAD_ARGUMENT;
    }
    if PHASE
        .compare_exchange(FRESH, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return abi::ALREADY_INITIALIZED;
    }
    BASE.store(pointer, Ordering::Release);
    CAPACITY.store(bytes, Ordering::Release);
    abi::OK
}

pub(crate) fn seal() {
    if PHASE
        .compare_exchange(INITIALIZING, SEALED, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        fatal(FATAL_ALLOC_PHASE);
    }
}

pub(crate) struct Call;

pub(crate) fn enter() -> Result<Call, u32> {
    if PHASE.load(Ordering::Acquire) != SEALED {
        return Err(abi::NOT_READY);
    }
    if IN_CALL
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(abi::BUSY);
    }
    Ok(Call)
}

impl Drop for Call {
    fn drop(&mut self) {
        IN_CALL.store(false, Ordering::Release);
    }
}

pub(crate) fn stats() -> DecoderStats {
    DecoderStats {
        abi_version: abi::VERSION,
        phase: PHASE.load(Ordering::Acquire),
        first_fatal_reason: FIRST_FATAL.load(Ordering::Acquire),
        reserved: 0,
        arena_bytes: CAPACITY.load(Ordering::Acquire) as u64,
        retained_high_water: USED.load(Ordering::Acquire) as u64,
        allocation_calls: ALLOCS.load(Ordering::Acquire) as u64,
        deallocation_calls: DEALLOCS.load(Ordering::Acquire) as u64,
    }
}
