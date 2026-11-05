//! O1 oracle child: map the fixture, report buffer addresses on
//! stdout, then stop under ptrace. The parent overwrites all
//! registers and single-steps the fixture natively; code after the
//! stop never runs. Argument is a fixture name or `hex:<bytes>`.

use std::io::Write;

use liteinst_jit::fixtures;
use liteinst_jit::harness::{GuardedDst, MappedGuest, REDZONE_MARKER};
use liteinst_jit::o1::ChildInfo;

fn main() {
    let arg = std::env::args().nth(1).expect("fixture name or hex arg");
    let bytes: Vec<u8> = if let Some(hex) = arg.strip_prefix("hex:") {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex bytes"))
            .collect()
    } else {
        fixtures::by_name(&arg).bytes
    };
    let guest = MappedGuest::map(&bytes).expect("map fixture");
    guest.plant_below_rsp(REDZONE_MARKER);
    let data: &'static mut [u64; 16] = Box::leak(Box::new(core::array::from_fn(|i| i as u64)));
    let dst: &'static mut [u8; 32] = Box::leak(Box::new([0u8; 32]));
    let src: &'static mut [u8; 32] = Box::leak(Box::new(core::array::from_fn(|i| i as u8)));
    let dst_addr = if arg == "rep_stosb_partial" {
        Box::leak(Box::new(GuardedDst::new().expect("guarded dst"))).ptr
    } else {
        dst.as_mut_ptr() as u64
    };
    let info = ChildInfo {
        base: guest.base,
        stack_top: guest.stack_top(),
        data: data.as_ptr() as u64,
        dst: dst_addr,
        src: src.as_ptr() as u64,
    };
    let mut out = std::io::stdout().lock();
    out.write_all(&info.to_bytes()).expect("write info");
    out.flush().expect("flush info");
    drop(out);
    // SAFETY: standard self-trace handshake; the parent is our
    // spawner and is already waiting to step us. int3 (not SIGSTOP)
    // so the child parks in a ptrace signal-delivery stop where
    // SETREGS is accepted.
    unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            core::ptr::null_mut::<u8>(),
            core::ptr::null_mut::<u8>(),
        );
        core::arch::asm!("int3");
        // Parent rewrites RIP before stepping; park defensively.
        loop {
            libc::pause();
        }
    }
}
