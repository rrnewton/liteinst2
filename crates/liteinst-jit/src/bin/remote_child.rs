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

/// Kernel `rt_sigaction` layout (32 bytes): handler, flags,
/// restorer, one-word mask. Raw syscalls with an all-zero
/// struct install a true four-zero-word default — unlike
/// libc's `signal()`, which installs its own flags/restorer —
/// and the queried tuple is verified exactly zero right after
/// each install, before the handshake reports the dump below.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct KernelSigaction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

fn rt_sigaction(sig: i32, act: Option<&KernelSigaction>, old: Option<&mut KernelSigaction>) -> i64 {
    // SAFETY: raw syscall through libc's variadic stub with
    // exactly the kernel's [signum, act, oldact, sigsetsize=8]
    // argument shape; pointers are null or to the live structs.
    unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            sig,
            act.map_or(core::ptr::null(), |a| a as *const KernelSigaction),
            old.map_or(core::ptr::null_mut(), |o| o as *mut KernelSigaction),
            8usize,
        )
    }
}

/// Query one action tuple from the kernel (used for
/// normalization verification and for the initial dump).
fn query_action(sig: i32) -> KernelSigaction {
    let mut old = KernelSigaction {
        handler: u64::MAX,
        flags: u64::MAX,
        restorer: u64::MAX,
        mask: u64::MAX,
    };
    if rt_sigaction(sig, None, Some(&mut old)) != 0 {
        std::process::exit(2);
    }
    old
}

fn main() {
    // Normalize guest initial signal state with raw zeroed
    // kernel sigaction structs and verify each queried tuple
    // is exactly zero before any handshake byte is written, so
    // the tracer's zero mirror is a verified fact for every
    // normalized signal rather than an assumption about libc.
    // SIGKILL/SIGSTOP dispositions cannot change, and the
    // glibc-reserved 32/33 are not installed into; their
    // tuples are still reported verbatim in the dump below.
    // SAFETY: single-threaded setup before any guest code.
    unsafe {
        let zero = KernelSigaction {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        for sig in 1..=64 {
            if sig != libc::SIGKILL && sig != libc::SIGSTOP && sig != 32 && sig != 33 {
                if rt_sigaction(sig, Some(&zero), None) != 0 {
                    std::process::exit(2);
                }
                if query_action(sig) != zero {
                    std::process::exit(2);
                }
            }
        }
        let mut empty: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut empty);
        if libc::pthread_sigmask(libc::SIG_SETMASK, &empty, core::ptr::null_mut()) != 0 {
            std::process::exit(2);
        }
        let disabled = libc::stack_t {
            ss_sp: core::ptr::null_mut(),
            ss_flags: libc::SS_DISABLE,
            ss_size: 0,
        };
        if libc::sigaltstack(&disabled, core::ptr::null_mut()) != 0 {
            std::process::exit(2);
        }
    }
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
    let dst_addr = if arg == "rep_stosb_partial" || std::env::args().any(|a| a == "guarded-dst") {
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
    // Initial kernel action dump: tuples for signals 1..=64
    // as queried after normalization (2,080 bytes; index 0
    // zero). The tracer seeds its mirror from these kernel
    // answers verbatim, never from an assumed zero state.
    let mut dump = Vec::with_capacity(65 * 32);
    for sig in 0..=64 {
        let act = if sig == 0 {
            KernelSigaction {
                handler: 0,
                flags: 0,
                restorer: 0,
                mask: 0,
            }
        } else {
            query_action(sig)
        };
        for word in [act.handler, act.flags, act.restorer, act.mask] {
            dump.extend_from_slice(&word.to_le_bytes());
        }
    }
    let mut out = std::io::stdout().lock();
    out.write_all(&info.to_bytes()).expect("write info");
    out.write_all(&dump).expect("write action dump");
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
