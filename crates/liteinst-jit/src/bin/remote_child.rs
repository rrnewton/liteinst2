//! Remote-substrate fixture child: map the fixture and a cache
//! arena, report addresses on stdout, then park under ptrace.
//! The tracer overwrites registers and runs translated code in
//! the arena; this process's own code after the park loop never
//! runs as guest code. Argument is a fixture name or
//! `hex:<bytes>`, mirroring the O1 child.
//!
//! Park protocol: each loop iteration stops with `int3`; when
//! the mailbox word is `MAILBOX_PUBLISH` on resume, the child
//! mprotects the arena code region RX, writes
//! `MAILBOX_PUBLISHED`, and parks again. The tracer only ever
//! resumes the child either to service that publish command or
//! with a full guest register set pointing into the cache.

use std::io::Write;

use liteinst_jit::exec::CODE_CAP;
use liteinst_jit::fixtures;
use liteinst_jit::harness::{GuardedDst, MappedGuest, REDZONE_MARKER};
use liteinst_jit::remote::{ARENA_LEN, MAILBOX_PUBLISH, MAILBOX_PUBLISHED, RemoteChildInfo};

fn map_rw(len: usize) -> *mut u8 {
    // SAFETY: anonymous private mapping of `len` bytes.
    let p = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(p != libc::MAP_FAILED, "mmap arena");
    p.cast()
}

fn main() {
    let arg = std::env::args().nth(1).expect("fixture name or hex arg");
    // Optional guest initial signal mask: `block:<signum>,...`
    // blocks those signals before anything else, so queued
    // signals stay pending until the tracer's poll check.
    if let Some(block) = std::env::args()
        .nth(2)
        .and_then(|a| a.strip_prefix("block:").map(str::to_string))
    {
        // SAFETY: building and applying a signal mask in our
        // own single-threaded process before any guest code.
        unsafe {
            let mut set: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&mut set);
            for part in block.split(',') {
                if let Ok(sig) = part.parse::<i32>() {
                    libc::sigaddset(&mut set, sig);
                }
            }
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, core::ptr::null_mut());
        }
    }
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
    let dst: &'static mut [u8; 8192] = Box::leak(Box::new([0u8; 8192]));
    let src: &'static mut [u8; 8192] = Box::leak(Box::new(core::array::from_fn(|i| i as u8)));
    let dst_addr = if arg == "rep_stosb_partial" {
        Box::leak(Box::new(GuardedDst::new().expect("guarded dst"))).ptr
    } else {
        dst.as_mut_ptr() as u64
    };
    let arena = map_rw(ARENA_LEN);
    let mailbox_page = map_rw(4096);
    let info = RemoteChildInfo {
        base: guest.base,
        stack_top: guest.stack_top(),
        data: data.as_ptr() as u64,
        dst: dst_addr,
        src: src.as_ptr() as u64,
        arena_base: arena as u64,
        mailbox: mailbox_page as u64,
    };
    let mut out = std::io::stdout().lock();
    out.write_all(&info.to_bytes()).expect("write info");
    out.flush().expect("flush info");
    drop(out);
    // SAFETY: standard self-trace handshake; the parent is our
    // spawner and is already waiting to drive us. The park loop
    // services the publish command between stops.
    unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            core::ptr::null_mut::<u8>(),
            core::ptr::null_mut::<u8>(),
        );
        loop {
            core::arch::asm!("int3");
            if core::ptr::read_volatile(mailbox_page.cast::<u64>()) == MAILBOX_PUBLISH {
                let rc = libc::mprotect(arena.cast(), CODE_CAP, libc::PROT_READ | libc::PROT_EXEC);
                let ack = if rc == 0 { MAILBOX_PUBLISHED } else { u64::MAX };
                core::ptr::write_volatile(mailbox_page.cast::<u64>(), ack);
            }
        }
    }
}
