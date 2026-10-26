//! S never executes Rust, libc, TLS access, a callback, or a signal handler.
use super::*;

std::arch::global_asm!(
    include_str!("machine.S"),
    stack = const std::mem::offset_of!(Context, stack),
    descriptor = const std::mem::offset_of!(Context, descriptor),
    packet_pid = const std::mem::offset_of!(Context, packet) + std::mem::offset_of!(Packet, pid),
    channel = const std::mem::offset_of!(Context, channels) + 4,
    control_fd = const std::mem::offset_of!(Context, control) + 16,
    message = const std::mem::offset_of!(Context, message),
    send_result = const std::mem::offset_of!(Context, send_result),
    send_observed = const std::mem::offset_of!(Context, send_observed),
    fault = const std::mem::offset_of!(Context, test_fault),
    test_enabled = const cfg!(test) as usize,
    reaper = sym reaper,
);
unsafe extern "C" {
    // Assembly receives an address and uses the offset_of! constants above;
    // nested Rust-only payloads are not passed or interpreted as C values.
    fn liteinst_anchor_reset_spawn(context: *mut libc::c_void, descriptor: *mut i32) -> i64;
}
pub(super) unsafe fn spawn(context: *mut Context, descriptor: *mut i32) -> i64 {
    unsafe { liteinst_anchor_reset_spawn(context.cast(), descriptor) }
}
unsafe extern "C" fn reaper(context: *const libc::c_void) -> ! {
    let context = context.cast::<Context>();
    // R has a private mm and copied descriptor table. Only existing bounded
    // raw broker code is called, never arbitrary Rust or caller hooks.
    unsafe { broker::anchor_child((*context).broker, (*context).channels) }
}
