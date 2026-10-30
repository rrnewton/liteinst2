
// Appended only to a separately retained test crate. Never production exports.
// The held guard and allocator are the real implementations; no forged state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_region_test_busy(
    pc: u64, bytes: *const u8, length: usize, out: *mut RegionDescription,
) -> u32 {
    let _held = match arena::enter() { Ok(value) => value, Err(error) => return error };
    // SAFETY: identical C caller-owned source/output contract to the real API.
    unsafe { li2_decoder_region_describe(pc, bytes, length, out) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_region_test_allocate() {
    // SAFETY: a real valid allocation request after seal must fail-stop 101.
    // Do not replace this with a direct fatal() call or synthetic phase value.
    let layout = core::alloc::Layout::from_size_align(64, 64).unwrap();
    let pointer = unsafe { core::alloc::GlobalAlloc::alloc(&arena::Arena, layout) };
    core::hint::black_box(pointer);
}
