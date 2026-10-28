#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(
    target_arch = "x86_64",
    target_os = "linux",
    target_pointer_width = "64"
)))]
compile_error!("this prototype's ABI and raw failure hook require x86_64 Linux");

mod abi;
mod arena;
mod decode;
mod scan;
mod admission_oneshot;

pub use abi::{Decoded, DecoderStats, Scan};

#[global_allocator]
static ALLOCATOR: arena::Arena = arena::Arena;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    arena::fatal(arena::FATAL_PANIC)
}

// Precompiled x86-64 Linux core retains a personality reference for the
// panic_nounwind_fmt guard even with this crate's panic=abort. Match the
// platform Itanium/SysV ABI: two C ints, a u64 exception class, two opaque
// pointers, and a C-int reason result. This deliberately never returns a reason
// and never dereferences foreign unwind data. It is a fatal unsupported-unwind
// boundary, not an unwinder, recovery path, or foreign-exception guarantee.
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality(
    _version: core::ffi::c_int,
    _actions: core::ffi::c_int,
    _exception_class: u64,
    _exception_object: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    arena::fatal(arena::FATAL_UNSUPPORTED_UNWIND)
}

/// # Safety
/// The single caller owns a writable arena allocation for the entire process
/// lifetime, excluding signal/parallel entry during initialization. It must not
/// overlap this library, out, any future source/output buffer or target writes.
/// `out` is aligned, writable and uniquely borrowed. Allocation exhaustion is
/// an explicit fatal initialization outcome, not a recoverable half-init.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_initialize(
    arena: *mut u8,
    bytes: usize,
    out: *mut DecoderStats,
) -> u32 {
    if out.is_null() {
        return abi::BAD_ARGUMENT;
    }
    let status = arena::begin(arena, bytes);
    // SAFETY: caller supplied the unique writable output header.
    unsafe {
        out.write(arena::stats());
    }
    if status != abi::OK {
        return status;
    }
    decode::warm_tables();
    arena::seal();
    // SAFETY: same retained output header; all table ownership is now sealed.
    unsafe {
        out.write(arena::stats());
    }
    abi::OK
}

/// # Safety
/// `out` is a uniquely writable aligned header. Descriptive only; not a lease.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_stats(out: *mut DecoderStats) -> u32 {
    if out.is_null() {
        return abi::BAD_ARGUMENT;
    }
    // SAFETY: supplied unique output; no decoder initialization or allocation.
    unsafe {
        out.write(arena::stats());
    }
    abi::OK
}

/// # Safety
/// Input is a readable, immutable owned allocation of length 1..=15, disjoint
/// from the initialized arena and the uniquely writable aligned output. Raw
/// address/generation/live-byte authentication remains the caller's obligation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_decode(
    pc: u64,
    bytes: *const u8,
    length: usize,
    out: *mut Decoded,
) -> u32 {
    if out.is_null() {
        return abi::BAD_ARGUMENT;
    }
    // SAFETY: the caller supplied this writable header even on input refusal.
    unsafe {
        out.write(Decoded::default());
    }
    if bytes.is_null()
        || !(1..=15).contains(&length)
        || (bytes as usize).checked_add(length).is_none()
    {
        return abi::BAD_ARGUMENT;
    }
    let _call = match arena::enter() {
        Ok(call) => call,
        Err(error) => return error,
    };
    // SAFETY: input validity, lifetime and nonaliasing are caller contracts.
    let source = unsafe { core::slice::from_raw_parts(bytes, length) };
    match decode::one(pc, source) {
        Ok(row) => {
            unsafe {
                out.write(row);
            }
            abi::OK
        }
        Err(error) => error,
    }
}

/// # Safety
/// Own the contiguous immutable page+halo window, all candidate rows and the
/// summary as disjoint valid allocations. Output holds `capacity` Decoded rows.
/// Boundary flags may be one only for authenticated nonexecutecutable logical
/// neighbors, never merely currently NX pages. A complete result is not RX
/// permission, not instruction-head completeness, and not entry proof.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_scan_page(
    base: u64,
    bytes: *const u8,
    length: usize,
    page: u64,
    before_nonexec: u32,
    after_nonexec: u32,
    rows: *mut Decoded,
    capacity: usize,
    out: *mut Scan,
) -> u32 {
    if out.is_null() {
        return abi::BAD_ARGUMENT;
    }
    // SAFETY: summary remains present on every partial/failed scan.
    unsafe {
        out.write(Scan {
            abi_version: abi::VERSION,
            ..Scan::default()
        });
    }
    if bytes.is_null()
        || length == 0
        || length > scan::MAX_WINDOW
        || before_nonexec > 1
        || after_nonexec > 1
        || (bytes as usize).checked_add(length).is_none()
    {
        return abi::BAD_ARGUMENT;
    }
    let _call = match arena::enter() {
        Ok(call) => call,
        Err(error) => return error,
    };
    // SAFETY: validated bounded extents and the caller's allocation contract.
    unsafe {
        scan::page(
            base,
            core::slice::from_raw_parts(bytes, length),
            page,
            before_nonexec != 0,
            after_nonexec != 0,
            rows,
            capacity,
            &mut *out,
        )
    }
}

// Insert only this module declaration, re-export and new function into lib.rs.
mod tf;
pub use tf::Classification as TfClassification;

/// # Safety
/// Same immutable, disjoint source/output and sealed-arena obligations as
/// li2_decoder_decode. This classification is descriptive, never an RX lease.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_tf_classify(
    pc: u64, bytes: *const u8, length: usize, out: *mut TfClassification,
) -> u32 {
    if out.is_null() { return abi::BAD_ARGUMENT; }
    // SAFETY: unique writable output is required even on input refusal.
    unsafe { out.write(TfClassification::default()); }
    if bytes.is_null() || !(1..=15).contains(&length)
        || (bytes as usize).checked_add(length).is_none()
    { return abi::BAD_ARGUMENT; }
    let _call = match arena::enter() { Ok(call) => call, Err(error) => return error };
    // SAFETY: caller owns this bounded, immutable, disjoint allocation.
    let source = unsafe { core::slice::from_raw_parts(bytes, length) };
    match tf::one(pc, source) {
        Ok(row) => { unsafe { out.write(row); } abi::OK }
        Err(error) => error,
    }
}

mod write_footprint;
pub use write_footprint::{Footprint as WriteFootprint, Registers as WriteRegisters};

/// # Safety
/// Same immutable owned source and sealed-arena/single-caller contract as
/// li2_decoder_tf_classify. Registers and output are aligned, live, disjoint
/// owned buffers and cannot alias the source or arena. This is descriptive
/// only; the caller must bind all identity fields to the held instruction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_write_footprint(
    pc: u64, bytes: *const u8, length: usize,
    registers: *const WriteRegisters, out: *mut WriteFootprint,
) -> u32 {
    if out.is_null() { return abi::BAD_ARGUMENT; }
    // SAFETY: caller supplies the uniquely writable output even on refusal.
    unsafe { out.write(WriteFootprint::default()); }
    if bytes.is_null() || registers.is_null() || !(1..=15).contains(&length)
        || (bytes as usize).checked_add(length).is_none()
    { return abi::BAD_ARGUMENT; }
    let _call = match arena::enter() { Ok(call) => call, Err(error) => return error };
    // SAFETY: retained immutable source and register allocations are caller obligations.
    let source = unsafe { core::slice::from_raw_parts(bytes, length) };
    let state = unsafe { &*registers };
    match write_footprint::one(pc, source, state) {
        Ok(row) => { unsafe { out.write(row); } abi::OK }
        Err(error) => error,
    }
}
