//! O1 oracle child: map the fixture, report buffer addresses on
//! stdout, then stop under ptrace. The parent overwrites all
//! registers and single-steps the fixture natively; code after the
//! stop never runs.

use std::io::Write;

use liteinst_jit::fixtures;
use liteinst_jit::harness::MappedGuest;
use liteinst_jit::o1::ChildInfo;

fn main() {
    let name = std::env::args().nth(1).expect("fixture name arg");
    let fixture = fixtures::by_name(&name);
    let guest = MappedGuest::map(&fixture.bytes).expect("map fixture");
    let data: &'static mut [u64; 16] = Box::leak(Box::new(core::array::from_fn(|i| i as u64)));
    let dst: &'static mut [u8; 32] = Box::leak(Box::new([0u8; 32]));
    let src: &'static mut [u8; 32] = Box::leak(Box::new(core::array::from_fn(|i| i as u8)));
    let info = ChildInfo {
        base: guest.base,
        stack_top: guest.stack_top(),
        data: data.as_ptr() as u64,
        dst: dst.as_mut_ptr() as u64,
        src: src.as_ptr() as u64,
    };
    let mut out = std::io::stdout().lock();
    out.write_all(&info.to_bytes()).expect("write info");
    out.flush().expect("flush info");
    drop(out);
    // SAFETY: standard self-trace handshake; the parent is our
    // spawner and is already waiting to step us.
    unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            core::ptr::null_mut::<u8>(),
            core::ptr::null_mut::<u8>(),
        );
        // int3 (not SIGSTOP): park in a ptrace signal-delivery
        // stop where SETREGS is accepted.
        core::arch::asm!("int3");
        // Parent rewrites RIP before stepping; park defensively.
        loop {
            libc::pause();
        }
    }
}
