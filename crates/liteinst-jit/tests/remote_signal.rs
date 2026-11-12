//! I1-D one-signal genuine round trip: the same fixture
//! bytes run translated in the remote child and natively in
//! the signal native child, with SIGUSR1 blocked at spawn,
//! sent by this parent, and unblocked by the guest after it
//! installs an `SA_SIGINFO` handler. Witness words, final
//! state, and fault outcomes must agree; translated counts
//! are pinned to the fixture enumeration below. One
//! sequential test: ptrace children and signals must not
//! overlap.
//!
//! Fixture layout (all buffer offsets are `[rbx]`, rbx=dst):
//! handler at 0 (21 insns), restorer (`mov eax,15; syscall`),
//! main: build/install/query the action, preset r13, a
//! never-taken `jne handler` (translator reachability for the
//! handler block), `rt_sigprocmask` unblock, then a bounded
//! flag-wait loop that only the handler can satisfy. The
//! handler records signum/`si_code`/`si_pid`, ucontext
//! RIP/RBX/RSP/EFLAGS/old-R13, mutates ucontext R13, sets the
//! progress flag, clobbers RAX, and returns to the restorer.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

#[path = "common/corpus.rs"]
mod corpus;
#[path = "common/deadline.rs"]
mod deadline;

use liteinst_jit::exec::{FaultKind, RunError};
use liteinst_jit::harness::RETURN_SENTINEL;
use liteinst_jit::o1::O1sEnd;
use liteinst_jit::remote::{GuestAction, RemoteChildInfo, RemoteExecutable};
use liteinst_jit::types::{CountProfile, Generation, RegionFacts};

const REMOTE_CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-remote-child");
const NATIVE_CHILD: &str = env!("CARGO_BIN_EXE_liteinst-jit-signal-native-child");

const FLAGS_SIGINFO: u32 = 0x0400_0004; // SA_RESTORER | SA_SIGINFO
const FLAGS_NO_SIGINFO: u32 = 0x0400_0000;
const FLAGS_ONSTACK: u32 = 0x0c00_0004; // + SA_ONSTACK
const OLD_R13: u64 = 0x5eed_0001;
const NEW_R13: u64 = 0x1122_3344_5566_7788;

// SA_SIGINFO handler (rdi=sig, rsi=siginfo, rdx=ucontext).
const HANDLER: &[u8] = &[
    0x48, 0xff, 0x83, 0x00, 0x02, 0x00, 0x00, // inc qword [rbx+512]
    0x48, 0x89, 0xbb, 0x08, 0x02, 0x00, 0x00, // mov [rbx+520], rdi
    0x8b, 0x46, 0x08, // mov eax, [rsi+8] (si_code)
    0x48, 0x89, 0x83, 0x10, 0x02, 0x00, 0x00, // mov [rbx+528], rax
    0x8b, 0x46, 0x10, // mov eax, [rsi+16] (si_pid)
    0x48, 0x89, 0x83, 0x18, 0x02, 0x00, 0x00, // mov [rbx+536], rax
    0x48, 0x8b, 0x82, 0xa8, 0x00, 0x00, 0x00, // mov rax, [rdx+168] (uc rip)
    0x48, 0x89, 0x83, 0x20, 0x02, 0x00, 0x00, // mov [rbx+544], rax
    0x48, 0x8b, 0x82, 0x80, 0x00, 0x00, 0x00, // mov rax, [rdx+128] (uc rbx)
    0x48, 0x89, 0x83, 0x28, 0x02, 0x00, 0x00, // mov [rbx+552], rax
    0x48, 0x8b, 0x82, 0xa0, 0x00, 0x00, 0x00, // mov rax, [rdx+160] (uc rsp)
    0x48, 0x89, 0x83, 0x30, 0x02, 0x00, 0x00, // mov [rbx+560], rax
    0x48, 0x8b, 0x82, 0xb0, 0x00, 0x00, 0x00, // mov rax, [rdx+176] (uc eflags)
    0x48, 0x89, 0x83, 0x60, 0x02, 0x00, 0x00, // mov [rbx+608], rax
    0x48, 0x8b, 0x42, 0x50, // mov rax, [rdx+80] (uc r13)
    0x48, 0x89, 0x83, 0x38, 0x02, 0x00, 0x00, // mov [rbx+568], rax
    0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov rax, NEW_R13
    0x48, 0x89, 0x42, 0x50, // mov [rdx+80], rax
    0x48, 0xc7, 0x83, 0x40, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, // mov qword [rbx+576], 1
    0xb8, 0xed, 0x5e, 0xad, 0xde, // mov eax, 0xDEAD5EED
    0xc3, // ret
];
const RESTORER: &[u8] = &[0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05];

// I1-F mask handler: records fields, queries its own current
// mask via rt_sigprocmask into [rbx+624] (rc at [rbx+616],
// saved uc pointer at [rbx+632]), repairs R13, sets flag.
const MASK_HANDLER: &[u8] = &[
    0x48, 0xff, 0x83, 0x00, 0x02, 0x00, 0x00, // inc [rbx+512]
    0x48, 0x89, 0xbb, 0x08, 0x02, 0x00, 0x00, // mov [rbx+520], rdi
    0x48, 0x89, 0x93, 0x78, 0x02, 0x00, 0x00, // mov [rbx+632], rdx
    0x31, 0xff, // xor edi, edi
    0x31, 0xf6, // xor esi, esi
    0x48, 0x8d, 0x93, 0x70, 0x02, 0x00, 0x00, // lea rdx, [rbx+624]
    0x41, 0xba, 0x08, 0x00, 0x00, 0x00, // mov r10d, 8
    0xb8, 0x0e, 0x00, 0x00, 0x00, // mov eax, 14
    0x0f, 0x05, // syscall
    0x48, 0x89, 0x83, 0x68, 0x02, 0x00, 0x00, // mov [rbx+616], rax
    0x48, 0x8b, 0x93, 0x78, 0x02, 0x00, 0x00, // mov rdx, [rbx+632]
    0x48, 0x8b, 0x82, 0xa8, 0x00, 0x00, 0x00, // mov rax, [rdx+168]
    0x48, 0x89, 0x83, 0x20, 0x02, 0x00, 0x00, // mov [rbx+544], rax
    0x48, 0x8b, 0x42, 0x50, // mov rax, [rdx+80]
    0x48, 0x89, 0x83, 0x38, 0x02, 0x00, 0x00, // mov [rbx+568], rax
    0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov rax, NEW_R13
    0x48, 0x89, 0x42, 0x50, // mov [rdx+80], rax
    0x48, 0xc7, 0x83, 0x40, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // flag=1
    0xc3,
];

struct FixtureBytes {
    bytes: Vec<u8>,
    restorer_off: u64,
    main_off: u64,
    resume_off: u64,
    done_off: u64,
    fault_off: u64,
}

fn fixture(flags: u32) -> FixtureBytes {
    fixture_v(
        flags,
        libc::SIGUSR1 as u8,
        RESTORER,
        false,
        0,
        0,
        HANDLER,
        false,
    )
}

#[allow(clippy::too_many_arguments)] // test fixture axes, all call-site explicit
fn fixture_v(
    flags: u32,
    sig: u8,
    restorer: &[u8],
    alias_install: bool,
    body_repeats: usize,
    sa_mask: u32,
    handler_bytes: &[u8],
    alt_install: bool,
) -> FixtureBytes {
    let mut v = Vec::new();
    v.extend_from_slice(handler_bytes);
    let restorer_off = v.len() as u64;
    v.extend_from_slice(restorer);
    let main_off = v.len() as u64;
    // Build act at [rbx]: handler=rbp, flags, restorer=r12,
    // mask=0. (4 insns)
    v.extend_from_slice(&[0x48, 0x89, 0x2b]);
    v.extend_from_slice(&[0x48, 0xc7, 0x43, 0x08]);
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&[0x4c, 0x89, 0x63, 0x10]);
    v.extend_from_slice(&[0x48, 0xc7, 0x43, 0x18]);
    v.extend_from_slice(&sa_mask.to_le_bytes());
    // rt_sigaction(sig, rbx, rbx+32, 8); [rbx+64]=rax. (7)
    v.extend_from_slice(&[0xbf, sig, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[
        0x48, 0x89, 0xde, 0x48, 0x8d, 0x53, 0x20, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00,
    ]);
    if alias_install {
        // movabs rax, 0x1_0000000d (high-32 alias of 13)
        v.extend_from_slice(&[0x48, 0xb8, 0x0d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    } else {
        v.extend_from_slice(&[0xb8, 0x0d, 0x00, 0x00, 0x00]);
    }
    v.extend_from_slice(&[0x0f, 0x05, 0x48, 0x89, 0x43, 0x40]);
    // Query act to [rbx+272]; [rbx+72]=rax. (7 insns)
    v.extend_from_slice(&[0xbf, sig, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[
        0x31, 0xf6, 0x48, 0x8d, 0x93, 0x10, 0x01, 0x00, 0x00, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00,
        0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43, 0x48,
    ]);
    if alt_install {
        // sigaltstack(src in r13, 8192) at [rbx+160]; rc at [rbx+96]. (8 insns)
        v.extend_from_slice(&[
            0x4c, 0x89, 0xab, 0xa0, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x83, 0xa8, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x83, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x48, 0x8d, 0xbb, 0xa0, 0x00, 0x00, 0x00, 0x48, 0x8d, 0xb3, 0xb8, 0x00, 0x00,
            0x00, 0xb8, 0x83, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43, 0x60,
        ]);
    }
    v.extend_from_slice(&[0x49, 0xc7, 0xc5, 0x01, 0x00, 0xed, 0x5e]); // mov r13, OLD_R13
    v.extend_from_slice(&[0x48, 0x39, 0xc9]); // cmp rcx, rcx
    let jne_pos = v.len();
    v.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]); // jne handler (never taken)
    let rel = (0i64 - (jne_pos as i64 + 6)) as i32;
    v[jne_pos + 2..jne_pos + 6].copy_from_slice(&rel.to_le_bytes());
    // rt_sigprocmask(SIG_UNBLOCK=1, {sig}, old, 8). (7 insns)
    v.extend_from_slice(&[0x48, 0xc7, 0x83, 0x80, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&(1u32 << (sig - 1)).to_le_bytes());
    v.extend_from_slice(&[
        0xbf, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0xb3, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x93,
        0x88, 0x00, 0x00, 0x00, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0e, 0x00, 0x00, 0x00,
        0x0f, 0x05,
    ]);
    let resume_off = v.len() as u64;
    v.extend_from_slice(&[0x48, 0x89, 0x43, 0x50]); // mov [rbx+80], rax
    if body_repeats > 0 {
        v.extend_from_slice(&[0xb9, 0x80, 0xf0, 0xaf, 0x02]); // mov ecx, 50000000
    } else {
        v.extend_from_slice(&[0xb9, 0xa0, 0x86, 0x01, 0x00]); // mov ecx, 100000
    }
    let loop_pos = v.len();
    v.extend_from_slice(&[0x48, 0x83, 0xbb, 0x40, 0x02, 0x00, 0x00, 0x00]); // cmp flag, 0
    let near = body_repeats > 0;
    let jne_done = v.len();
    if near {
        v.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]); // jne DONE (near)
    } else {
        v.extend_from_slice(&[0x75, 0]); // jne DONE
    }
    for _ in 0..body_repeats {
        // Idempotent body insn: final state is timing-free.
        v.extend_from_slice(&[
            0x48, 0xc7, 0x83, 0x68, 0x02, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        ]); // mov qword [rbx+616], 7
    }
    v.extend_from_slice(&[0x48, 0xff, 0xc9]); // dec rcx
    let jne_loop = v.len();
    if near {
        v.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]); // jne LOOP (near)
    } else {
        v.extend_from_slice(&[0x75, 0]); // jne LOOP
    }
    v.extend_from_slice(&[0xb8, 0xf9, 0xff, 0xff, 0xff, 0xc3]); // timeout: eax=-7; ret
    let done_pos = v.len();
    if near {
        let d1 = (done_pos as i64 - (jne_done as i64 + 6)) as i32;
        v[jne_done + 2..jne_done + 6].copy_from_slice(&d1.to_le_bytes());
        let d2 = (loop_pos as i64 - (jne_loop as i64 + 6)) as i32;
        v[jne_loop + 2..jne_loop + 6].copy_from_slice(&d2.to_le_bytes());
    } else {
        v[jne_done + 1] = (done_pos - (jne_done + 2)) as u8;
        v[jne_loop + 1] = ((loop_pos as i64 - (jne_loop as i64 + 2)) as i8) as u8;
    }
    // DONE: record post-resume rax/r13/rsp, return 42. (5 insns)
    v.extend_from_slice(&[
        0x48, 0x89, 0x83, 0x48, 0x02, 0x00, 0x00, 0x4c, 0x89, 0xab, 0x50, 0x02, 0x00, 0x00, 0x48,
        0x89, 0xa3, 0x58, 0x02, 0x00, 0x00, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3,
    ]);
    FixtureBytes {
        bytes: v,
        restorer_off,
        main_off,
        resume_off,
        done_off: done_pos as u64,
        fault_off: 0,
    }
}

// Synchronous-fault handlers: record the kernel witness,
// repair the faulting operand register inside the ucontext,
// set the progress flag, return to the restorer.
const SEGV_HANDLER: &[u8] = &[
    0x48, 0xff, 0x83, 0x00, 0x02, 0x00, 0x00, // inc [rbx+512]
    0x48, 0x89, 0xbb, 0x08, 0x02, 0x00, 0x00, // mov [rbx+520], rdi
    0x8b, 0x46, 0x08, // mov eax, [rsi+8]
    0x48, 0x89, 0x83, 0x10, 0x02, 0x00, 0x00, // mov [rbx+528], rax
    0x48, 0x8b, 0x46, 0x10, // mov rax, [rsi+16] (si_addr)
    0x48, 0x89, 0x83, 0x18, 0x02, 0x00, 0x00, // mov [rbx+536], rax
    0x48, 0x8b, 0x82, 0xa8, 0x00, 0x00, 0x00, // mov rax, [rdx+168] (uc rip)
    0x48, 0x89, 0x83, 0x20, 0x02, 0x00, 0x00, // mov [rbx+544], rax
    0x48, 0x8b, 0x82, 0x68, 0x00, 0x00, 0x00, // mov rax, [rdx+104] (uc rdi)
    0x48, 0x89, 0x83, 0x38, 0x02, 0x00, 0x00, // mov [rbx+568], rax
    0x4c, 0x89, 0xb2, 0x68, 0x00, 0x00, 0x00, // mov [rdx+104], r14
    0x48, 0xc7, 0x83, 0x40, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // flag=1
    0xc3,
];
const FPE_HANDLER: &[u8] = &[
    0x48, 0xff, 0x83, 0x00, 0x02, 0x00, 0x00, 0x48, 0x89, 0xbb, 0x08, 0x02, 0x00, 0x00, 0x8b, 0x46,
    0x08, 0x48, 0x89, 0x83, 0x10, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x46, 0x10, 0x48, 0x89, 0x83, 0x18,
    0x02, 0x00, 0x00, 0x48, 0x8b, 0x82, 0xa8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x83, 0x20, 0x02, 0x00,
    0x00, 0x48, 0x8b, 0x82, 0x98, 0x00, 0x00, 0x00, // uc rcx
    0x48, 0x89, 0x83, 0x38, 0x02, 0x00, 0x00, 0x48, 0xc7, 0x82, 0x98, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, // uc rcx=2
    0x48, 0xc7, 0x83, 0x40, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc3,
];

fn fault_prefix(sig: u8, handler: &[u8]) -> (Vec<u8>, u64, u64) {
    let mut v = Vec::new();
    v.extend_from_slice(handler);
    let restorer_off = v.len() as u64;
    v.extend_from_slice(RESTORER);
    let main_off = v.len() as u64;
    v.extend_from_slice(&[0x48, 0x89, 0x2b]);
    v.extend_from_slice(&[0x48, 0xc7, 0x43, 0x08]);
    v.extend_from_slice(&FLAGS_SIGINFO.to_le_bytes());
    v.extend_from_slice(&[0x4c, 0x89, 0x63, 0x10]);
    v.extend_from_slice(&[0x48, 0xc7, 0x43, 0x18, 0, 0, 0, 0]);
    v.extend_from_slice(&[0xbf, sig, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[
        0x48, 0x89, 0xde, 0x48, 0x8d, 0x53, 0x20, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d,
        0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43, 0x40,
    ]);
    v.extend_from_slice(&[0xbf, sig, 0x00, 0x00, 0x00]);
    v.extend_from_slice(&[
        0x31, 0xf6, 0x48, 0x8d, 0x93, 0x10, 0x01, 0x00, 0x00, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00,
        0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43, 0x48,
    ]);
    v.extend_from_slice(&[0x48, 0x39, 0xc9]); // cmp rcx, rcx
    let jne_pos = v.len();
    v.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]);
    let rel = (0i64 - (jne_pos as i64 + 6)) as i32;
    v[jne_pos + 2..jne_pos + 6].copy_from_slice(&rel.to_le_bytes());
    (v, restorer_off, main_off)
}

fn segv_fixture() -> FixtureBytes {
    let (mut v, restorer_off, main_off) = fault_prefix(libc::SIGSEGV as u8, SEGV_HANDLER);
    v.extend_from_slice(&[0x4d, 0x89, 0xee]); // mov r14, r13 (valid src)
    v.extend_from_slice(&[0xbf, 0x10, 0x00, 0x00, 0x00]); // mov edi, 16
    let fault_off = v.len() as u64;
    v.extend_from_slice(&[0x48, 0x8b, 0x07]); // mov rax, [rdi] ; faults
    v.extend_from_slice(&[
        0x48, 0x89, 0x83, 0x48, 0x02, 0x00, 0x00, 0x48, 0x89, 0xbb, 0x50, 0x02, 0x00, 0x00, 0xb8,
        0x2a, 0x00, 0x00, 0x00, 0xc3,
    ]);
    FixtureBytes {
        bytes: v,
        restorer_off,
        main_off,
        resume_off: fault_off,
        done_off: 0,
        fault_off,
    }
}

fn fpe_fixture() -> FixtureBytes {
    let (mut v, restorer_off, main_off) = fault_prefix(libc::SIGFPE as u8, FPE_HANDLER);
    v.extend_from_slice(&[0xb8, 0x54, 0x00, 0x00, 0x00]); // mov eax, 84
    v.extend_from_slice(&[0x31, 0xd2]); // xor edx, edx
    v.extend_from_slice(&[0x31, 0xc9]); // xor ecx, ecx
    let fault_off = v.len() as u64;
    v.extend_from_slice(&[0xf7, 0xf1]); // div ecx ; faults
    v.extend_from_slice(&[
        0x48, 0x89, 0x83, 0x48, 0x02, 0x00, 0x00, 0xb8, 0x09, 0x00, 0x00, 0x00, 0xc3,
    ]);
    FixtureBytes {
        bytes: v,
        restorer_off,
        main_off,
        resume_off: fault_off,
        done_off: 0,
        fault_off,
    }
}

fn word(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

/// Address-normalized witness comparable across children.
#[derive(Debug, Eq, PartialEq)]
struct Witness {
    install_rc: u64,
    query_rc: u64,
    queried_handler_off: u64,
    queried_flags: u64,
    queried_restorer_off: u64,
    queried_mask: u64,
    unblock_rc: u64,
    unblock_old_mask: u64,
    handler_runs: u64,
    signum: u64,
    si_code: u64,
    si_pid: u64,
    uc_rip_off: u64,
    uc_rbx_is_dst: bool,
    uc_rsp_is_stack_top: bool,
    uc_eflags_cmp: u64,
    uc_old_r13: u64,
    flag: u64,
    post_rax: u64,
    final_r13: u64,
    final_rsp_is_stack_top: bool,
}

fn witness(data: &[u8], base: u64, dst: u64, stack_top: u64) -> Witness {
    Witness {
        install_rc: word(data, 64),
        query_rc: word(data, 72),
        queried_handler_off: word(data, 272).wrapping_sub(base),
        queried_flags: word(data, 280),
        queried_restorer_off: word(data, 288).wrapping_sub(base),
        queried_mask: word(data, 296),
        unblock_rc: word(data, 80),
        unblock_old_mask: word(data, 136),
        handler_runs: word(data, 512),
        signum: word(data, 520),
        si_code: word(data, 528),
        si_pid: word(data, 536),
        uc_rip_off: word(data, 544).wrapping_sub(base),
        uc_rbx_is_dst: word(data, 552) == dst,
        uc_rsp_is_stack_top: word(data, 560) == stack_top,
        uc_eflags_cmp: word(data, 608) & 0xcd5,
        uc_old_r13: word(data, 568),
        flag: word(data, 576),
        post_rax: word(data, 584),
        final_r13: word(data, 592),
        final_rsp_is_stack_top: word(data, 600) == stack_top,
    }
}

fn guest_state(
    remote: &RemoteExecutable,
    info: RemoteChildInfo,
    fix: &FixtureBytes,
) -> liteinst_jit::GuestState {
    let mut s = remote.initial_state();
    s.rip = info.base + fix.main_off;
    s.rbx = info.dst;
    s.rbp = info.base;
    s.r12 = info.base + fix.restorer_off;
    s.r13 = info.src;
    s
}

/// `id`: the fixture's SIGNAL-CORPUS.md ID, checked first.
fn run_translated_sig(
    id: &str,
    fix: &FixtureBytes,
    blocked_sig: i32,
    send: bool,
) -> (
    RemoteExecutable,
    RemoteChildInfo,
    Result<liteinst_jit::exec::Outcome, RunError>,
    Vec<u8>,
) {
    corpus::check(id, &fix.bytes);
    let (mut remote, _deadline) =
        deadline::remote_bytes_with_blocked(REMOTE_CHILD, &fix.bytes, &[blocked_sig])
            .expect("spawn remote");
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: fix.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    remote
        .prepare(
            &region,
            info.base + fix.main_off,
            CountProfile::BranchesAndInstructions,
        )
        .expect("prepare remote");
    if send {
        // SAFETY: signalling the test's traced child, which
        // has the signal blocked, so it stays pending.
        let rc = unsafe { libc::kill(remote.child_pid_for_test(), blocked_sig) };
        assert_eq!(rc, 0, "kill remote child");
    }
    let out = remote.run(guest_state(&remote, info, fix), RETURN_SENTINEL);
    let mut data = vec![0u8; 640];
    assert!(remote.read_mem(info.dst, &mut data));
    if send && let Ok(o) = &out {
        let pid = remote.child_pid_for_test() as u32;
        o1s_agrees(fix, Some(blocked_sig), &info, pid, o, &data);
    }
    (remote, info, out, data)
}

/// I1-H, the I1-D completion: O1-S steps the same bytes natively
/// in the remote child with the same signal arrangement (the
/// signal blocked at spawn and sent by this parent before the
/// first step, or none for the synchronous fixtures), every
/// delivery made by the kernel for real. A completed translated
/// run must equal it: retired instructions and branches, the
/// number of deliveries, the final register image (addresses as
/// region offsets, RFLAGS exact), and the whole 640-byte guest
/// buffer, address-normalized.
fn o1s_agrees(
    fix: &FixtureBytes,
    sent: Option<i32>,
    info: &RemoteChildInfo,
    pid: u32,
    out: &liteinst_jit::exec::Outcome,
    data: &[u8],
) {
    let block = sent.map(|s| format!("block:{s}"));
    let args: Vec<&str> = block.iter().map(String::as_str).collect();
    let (main, restorer) = (fix.main_off, fix.restorer_off);
    let o = deadline::o1s(
        REMOTE_CHILD,
        &fix.bytes,
        &args,
        |r, i| {
            r.rip = i.base + main;
            r.rbx = i.dst;
            r.rbp = i.base;
            r.r12 = i.base + restorer;
            r.r13 = i.src;
        },
        None,
        |pid| {
            if let Some(sig) = sent {
                // SAFETY: signalling this test's own stopped,
                // unreaped O1-S child, which has it blocked.
                assert_eq!(unsafe { libc::kill(pid, sig) }, 0, "kill O1-S child");
            }
        },
    );
    assert_eq!(o.end, O1sEnd::Returned, "O1-S end");
    assert_eq!(
        (out.instructions, out.branches),
        (o.instructions, o.branches),
        "translated vs O1-S counts"
    );
    assert!(!o.deliveries.is_empty(), "O1-S delivered");
    let code_len = fix.bytes.len().div_ceil(4096) as u64 * 4096;
    let tn = norm_state(&out.state, info, pid, code_len);
    let on = norm_state(&o.state, &o.info, o.pid as u32, code_len);
    assert_eq!(tn, on, "translated vs O1-S final state (normalized)");
    // The whole guest buffer, address-normalized (every fixture
    // layout, not only the base witness).
    let buf = |d: &[u8], i: &RemoteChildInfo| -> Vec<u64> {
        (0..640 / 8)
            .map(|k| norm_word(word(d, 8 * k), i, code_len))
            .collect()
    };
    assert_eq!(
        buf(data, info),
        buf(&o.dst_bytes[..640], &o.info),
        "translated vs O1-S guest buffer (normalized)"
    );
}

/// A value as `(region << 56) | offset` when it points into one
/// of the child's regions (code, stack, dst, src, data); other
/// values stay raw.
fn norm_word(v: u64, info: &RemoteChildInfo, code_len: u64) -> u64 {
    let stack_lo = info.stack_top - 64 * 1024 + 8;
    let regions = [
        (info.base, code_len),
        (stack_lo, info.stack_top + 8 - stack_lo),
        (info.dst, 8192),
        (info.src, 8192),
        (info.data, 128),
    ];
    for (r, &(lo, len)) in regions.iter().enumerate() {
        if v >= lo && v <= lo + len {
            return ((r as u64 + 1) << 56) | (v - lo);
        }
    }
    v
}

/// Registers in ucontext order, addresses normalized by
/// [`norm_word`], the child's own pid (left in a register by a
/// self-send) as one token; RFLAGS compares exactly.
fn norm_state(
    s: &liteinst_jit::GuestState,
    info: &RemoteChildInfo,
    pid: u32,
    code_len: u64,
) -> [u64; 18] {
    let regs = [
        s.r8, s.r9, s.r10, s.r11, s.r12, s.r13, s.r14, s.r15, s.rdi, s.rsi, s.rbp, s.rbx, s.rdx,
        s.rax, s.rcx, s.rsp, s.rip, s.rflags,
    ];
    core::array::from_fn(|i| {
        if i == 17 {
            regs[i]
        } else if regs[i] == u64::from(pid) {
            0x7e00_0000_0000_0000
        } else {
            norm_word(regs[i], info, code_len)
        }
    })
}

// Native info needed for witness normalization on that side.
struct NativeOut {
    result: u64,
    data: Vec<u8>,
    base: u64,
    dst: u64,
    stack_top: u64,
    src: u64,
}

fn native_run(fix: &FixtureBytes, send_sig: Option<i32>) -> NativeOut {
    let hex: String = fix.bytes.iter().map(|b| format!("{b:02x}")).collect();
    let (mut child, deadline) = deadline::command_child(
        Command::new(NATIVE_CHILD)
            .args([
                format!("hex:{hex}"),
                fix.main_off.to_string(),
                fix.restorer_off.to_string(),
                send_sig.unwrap_or(libc::SIGUSR1).to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    )
    .expect("spawn native child");
    let pid = child.id() as i32;
    let mut stdout = child.stdout.take().expect("native stdout");
    let mut raw = [0u8; 32];
    stdout.read_exact(&mut raw).expect("native info");
    let get = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
    let (base, stack_top, dst, src) = (get(0), get(1), get(2), get(3));
    if let Some(sig) = send_sig {
        // SAFETY: signalling the test's native child (blocked).
        let rc = unsafe { libc::kill(pid, sig) };
        assert_eq!(rc, 0, "kill native child");
    }
    child
        .stdin
        .as_mut()
        .expect("native stdin")
        .write_all(&[1u8])
        .expect("native go byte");
    // The child reports dst[0..1024]; these fixtures use 640.
    let mut out = vec![0u8; 8 + 1024];
    stdout.read_exact(&mut out).expect("native result");
    let status = child.wait().expect("wait native child");
    drop(deadline);
    assert!(status.success(), "native child status {status}");
    let result = u64::from_le_bytes(out[0..8].try_into().unwrap());
    NativeOut {
        result,
        data: out[8..8 + 640].to_vec(),
        base,
        dst,
        stack_top,
        src,
    }
}

fn native_witness(fix: &FixtureBytes, send: bool) -> (u64, Witness) {
    let n = native_run(fix, send.then_some(libc::SIGUSR1));
    let w = witness(&n.data, n.base, n.dst, n.stack_top);
    (n.result, w)
}

/// Translated run without any blocked/sent signal (sync
/// fault fixtures generate their own signal).
fn run_translated_plain(
    id: &str,
    fix: &FixtureBytes,
) -> (
    RemoteExecutable,
    RemoteChildInfo,
    Result<liteinst_jit::exec::Outcome, RunError>,
    Vec<u8>,
) {
    corpus::check(id, &fix.bytes);
    let (mut remote, _deadline) =
        deadline::remote_bytes(REMOTE_CHILD, &fix.bytes).expect("spawn remote");
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: fix.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    remote
        .prepare(
            &region,
            info.base + fix.main_off,
            CountProfile::BranchesAndInstructions,
        )
        .expect("prepare remote");
    let out = remote.run(guest_state(&remote, info, fix), RETURN_SENTINEL);
    let mut data = vec![0u8; 640];
    assert!(remote.read_mem(info.dst, &mut data));
    if let Ok(o) = &out {
        let pid = remote.child_pid_for_test() as u32;
        o1s_agrees(fix, None, &info, pid, o, &data);
    }
    (remote, info, out, data)
}

fn check_round_trip() {
    let fix = fixture(FLAGS_SIGINFO);
    let (remote, info, out, data) = run_translated_sig("D1 round trip", &fix, libc::SIGUSR1, true);
    let out = out.expect("translated round trip");
    let tw = witness(&data, info.base, info.dst, info.stack_top);
    let (native_result, nw) = native_witness(&fix, true);
    assert_eq!(native_result, 42, "native result");
    assert_eq!(out.state.rax, 42, "translated result");
    // Exact translated counts by fixture enumeration: main
    // 28 (build 4 + install 7 + query 7 + preset 1 +
    // reach 2 + unblock 7) + resume 4 + done 5 + handler 21
    // + restorer 2 credited at sigreturn = 60 instructions;
    // retired conditional branches: reach 1 + wait-loop 1 = 2.
    assert_eq!(out.instructions, 60, "translated instructions");
    assert_eq!(out.branches, 2, "translated branches");
    assert_eq!(tw, nw, "translated vs native witness");
    assert_eq!(tw.install_rc, 0);
    assert_eq!(tw.query_rc, 0);
    assert_eq!(tw.queried_handler_off, 0, "virtualized handler query");
    assert_eq!(tw.queried_flags, u64::from(FLAGS_SIGINFO));
    assert_eq!(tw.queried_restorer_off, fix.restorer_off);
    assert_eq!(tw.queried_mask, 0);
    assert_eq!(tw.unblock_rc, 0);
    assert_eq!(tw.unblock_old_mask, 0x200, "USR1 was blocked");
    assert_eq!(tw.handler_runs, 1, "handler ran exactly once");
    assert_eq!(tw.signum, libc::SIGUSR1 as u64);
    assert_eq!(tw.si_code, 0, "SI_USER from parent kill");
    // SAFETY: reading our own pid for comparison.
    assert_eq!(tw.si_pid, unsafe { libc::getpid() } as u64);
    assert_eq!(tw.uc_rip_off, fix.resume_off, "source resume PC in frame");
    assert!(tw.uc_rbx_is_dst && tw.uc_rsp_is_stack_top);
    assert_eq!(tw.uc_old_r13, OLD_R13);
    assert_eq!(tw.flag, 1, "progress only through handler");
    assert_eq!(tw.post_rax, 0, "handler RAX clobber must not leak");
    assert_eq!(tw.final_r13, NEW_R13, "ucontext scratch mutation honored");
    assert!(tw.final_rsp_is_stack_top);
    assert_eq!(out.state.r13, NEW_R13);
    assert_eq!(out.state.rbx, info.dst);
    assert_eq!(out.state.rsp, info.stack_top + 8);
    assert_eq!(out.state.rip, RETURN_SENTINEL);
    let reg = remote.registry();
    assert_eq!(
        reg.action(libc::SIGUSR1),
        GuestAction {
            handler: info.base,
            flags: u64::from(FLAGS_SIGINFO),
            restorer: info.base + fix.restorer_off,
            sa_mask: 0,
        },
        "guest-visible action still mirrored after delivery"
    );
    assert_eq!(reg.mask(), 0, "mask restored by sigreturn, re-mirrored");
}

fn check_no_send_control() {
    // Same guest without the signal: the bounded wait must
    // expire with the handler never run — progress causally
    // requires delivery.
    let fix = fixture(FLAGS_SIGINFO);
    let (_remote, _info, out, data) =
        run_translated_sig("D1 round trip", &fix, libc::SIGUSR1, false);
    let out = out.expect("control run");
    assert_eq!(out.state.rax, 0xffff_fff9, "wait expired (mov eax, -7)");
    assert_eq!(out.instructions, 400_032, "control instructions");
    assert_eq!(out.branches, 200_001, "control branches");
    assert_eq!(word(&data, 512), 0, "handler never ran");
    assert_eq!(word(&data, 576), 0, "flag never set");
}

fn check_ineligible_shape(flags: u32, label: &str) {
    let fix = fixture(flags);
    let (_remote, info, out, data) =
        run_translated_sig(&format!("D2 ineligible {label}"), &fix, libc::SIGUSR1, true);
    let f = match out {
        Err(RunError::Fault(f)) => f,
        other => panic!("{label}: expected recovered async fault, got {other:?}"),
    };
    assert_eq!(f.kind, FaultKind::AsyncSignal, "{label}");
    assert_eq!(f.signum, libc::SIGUSR1, "{label}");
    assert_eq!(f.src_pc, info.base + fix.resume_off, "{label}");
    assert_eq!(f.state.rip, info.base + fix.resume_off, "{label}");
    assert_eq!(word(&data, 512), 0, "{label}: handler must not run");
    assert_eq!(word(&data, 576), 0, "{label}: flag must not be set");
}

fn check_ineligible_fixture(fix: &FixtureBytes, sig: i32, label: &str) {
    let (_remote, info, out, data) =
        run_translated_sig(&format!("D2 ineligible {label}"), fix, sig, true);
    let f = match out {
        Err(RunError::Fault(f)) => f,
        other => panic!("{label}: expected recovered async fault, got {other:?}"),
    };
    assert_eq!(f.kind, FaultKind::AsyncSignal, "{label}");
    assert_eq!(f.signum, sig, "{label}");
    assert_eq!(f.src_pc, info.base + fix.resume_off, "{label}");
    assert_eq!(word(&data, 512), 0, "{label}: handler must not run");
    assert_eq!(word(&data, 576), 0, "{label}: flag must not be set");
}

/// P1 probe: a failed `rt_sigaction` copies nothing out, so
/// oldact virtualization must leave guest memory untouched.
fn check_oldact_sentinel_on_error() {
    const SENTINEL: u64 = 0xa5a5_a5a5_a5a5_a5a5;
    let mut bytes: Vec<u8> = vec![
        0x48, 0xff, 0x83, 0x00, 0x02, 0x00, 0x00, 0xc3, // 0 handler: inc + ret
        0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05, // 8 restorer
    ];
    let main_off = bytes.len() as u64; // 15
    // Build + install custom action (mask 0).
    bytes.extend_from_slice(&[
        0x48, 0x89, 0x2b, 0x48, 0xc7, 0x43, 0x08, 0x04, 0x00, 0x00, 0x04, 0x4c, 0x89, 0x63, 0x10,
        0x48, 0xc7, 0x43, 0x18, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x0a, 0x00, 0x00, 0x00, 0x48, 0x89,
        0xde, 0x48, 0x8d, 0x53, 0x20, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d, 0x00, 0x00,
        0x00, 0x0f, 0x05, 0x48, 0x89, 0x43, 0x40,
    ]);
    bytes.extend_from_slice(&[0x48, 0xb8]);
    bytes.extend_from_slice(&SENTINEL.to_le_bytes());
    for disp in [272u32, 280, 288, 296] {
        bytes.extend_from_slice(&[0x48, 0x89, 0x83]);
        bytes.extend_from_slice(&disp.to_le_bytes());
    }
    // Failed query: sigsetsize 0 -> EINVAL, no copy-out.
    bytes.extend_from_slice(&[
        0xbf, 0x0a, 0x00, 0x00, 0x00, 0x31, 0xf6, 0x48, 0x8d, 0x93, 0x10, 0x01, 0x00, 0x00, 0x41,
        0xba, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43,
        0x48, 0xc3,
    ]);
    corpus::check("D4 oldact sentinel", &bytes);
    let (mut remote, _deadline) = deadline::remote_bytes(REMOTE_CHILD, &bytes).expect("spawn");
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    remote
        .prepare(
            &region,
            info.base + main_off,
            CountProfile::BranchesAndInstructions,
        )
        .expect("prepare");
    let mut state = remote.initial_state();
    state.rip = info.base + main_off;
    state.rbx = info.dst;
    state.rbp = info.base;
    state.r12 = info.base + 8;
    state.r13 = info.src;
    remote
        .run(state, RETURN_SENTINEL)
        .expect("sentinel guest run");
    let mut data = vec![0u8; 640];
    assert!(remote.read_mem(info.dst, &mut data));
    assert_eq!(word(&data, 64), 0, "install result");
    assert_eq!(word(&data, 72) as i64, -22, "failed query is EINVAL");
    for off in [272, 280, 288, 296] {
        assert_eq!(
            word(&data, off),
            SENTINEL,
            "oldact sentinel at {off} untouched on error"
        );
    }
}

/// P1 probe: a high-32 RAX alias of the syscall number must
/// take the same stubbing/mirror path as the plain form.
fn check_alias_install_mirrored() {
    // Full round trip on the alias install: only a stubbed
    // kernel disposition can complete it under cache control
    // with exact counts; an unstubbed handler escapes to
    // native execution and the run faults at the sentinel.
    let fix = fixture_v(
        FLAGS_SIGINFO,
        libc::SIGUSR1 as u8,
        RESTORER,
        true,
        0,
        0,
        HANDLER,
        false,
    );
    let (remote, info, out, data) =
        run_translated_sig("D3 alias install", &fix, libc::SIGUSR1, true);
    let out = out.expect("alias round trip");
    assert_eq!(out.state.rax, 42, "alias result");
    assert_eq!(out.instructions, 60, "alias instructions");
    assert_eq!(out.branches, 2, "alias branches");
    assert_eq!(word(&data, 64), 0, "alias install result");
    assert_eq!(word(&data, 512), 1, "alias handler ran translated");
    assert_eq!(word(&data, 272), info.base, "alias queried handler");
    assert_eq!(
        remote.registry().action(libc::SIGUSR1),
        GuestAction {
            handler: info.base,
            flags: u64::from(FLAGS_SIGINFO),
            restorer: info.base + fix.restorer_off,
            sa_mask: 0,
        },
        "alias install reconciled in mirror"
    );
}

/// I1-E sync SEGV: data fault at a mid-block copied load,
/// handler repairs the pointer register in the ucontext,
/// the same load re-executes. Native child is the oracle
/// for witness/final-state words; counts are enumerated:
/// main 27 + handler 13 + restorer 2 = 42 insns, 1 branch.
fn check_sync_segv() {
    let fix = segv_fixture();
    let (_remote, info, out, data) = run_translated_plain("E1 sync SIGSEGV", &fix);
    let out = out.expect("translated sync SEGV round trip");
    assert_eq!(out.state.rax, 42, "translated segv result");
    assert_eq!(out.instructions, 42, "segv instructions");
    assert_eq!(out.branches, 1, "segv branches");
    let n = native_run(&fix, None);
    assert_eq!(n.result, 42, "native segv result");
    for (label, d, base, src) in [
        ("translated", &data, info.base, info.src),
        ("native", &n.data, n.base, n.src),
    ] {
        assert_eq!(word(d, 64), 0, "{label} install");
        assert_eq!(word(d, 272), base, "{label} queried handler");
        assert_eq!(word(d, 512), 1, "{label} handler runs");
        assert_eq!(word(d, 520), libc::SIGSEGV as u64, "{label} signum");
        assert_eq!(word(d, 528), 1, "{label} si_code SEGV_MAPERR");
        assert_eq!(word(d, 536), 16, "{label} si_addr is raw fault addr");
        assert_eq!(word(d, 544) - base, fix.fault_off, "{label} uc rip at load");
        assert_eq!(word(d, 568), 16, "{label} uc old rdi");
        assert_eq!(word(d, 576), 1, "{label} flag");
        assert_eq!(word(d, 584), 0x0706_0504_0302_0100, "{label} loaded value");
        assert_eq!(word(d, 592), src, "{label} repaired rdi after resume");
    }
}

/// I1-E sync FPE: div-by-zero, handler repairs the divisor
/// in the ucontext; `si_addr` must name the SOURCE div PC,
/// not the generated copy. Counts: main 27 + handler 13 +
/// restorer 2 = 42 insns, 1 branch.
fn check_sync_fpe() {
    let fix = fpe_fixture();
    let (_remote, info, out, data) = run_translated_plain("E2 sync SIGFPE", &fix);
    let out = out.expect("translated sync FPE round trip");
    assert_eq!(out.state.rax, 9, "translated fpe result");
    assert_eq!(out.instructions, 42, "fpe instructions");
    assert_eq!(out.branches, 1, "fpe branches");
    let n = native_run(&fix, None);
    assert_eq!(n.result, 9, "native fpe result");
    for (label, d, base) in [
        ("translated", &data, info.base),
        ("native", &n.data, n.base),
    ] {
        assert_eq!(word(d, 512), 1, "{label} handler runs");
        assert_eq!(word(d, 520), libc::SIGFPE as u64, "{label} signum");
        assert_eq!(word(d, 528), 1, "{label} si_code FPE_INTDIV");
        assert_eq!(
            word(d, 536) - base,
            fix.fault_off,
            "{label} si_addr at source div"
        );
        assert_eq!(word(d, 544) - base, fix.fault_off, "{label} uc rip at div");
        assert_eq!(word(d, 568), 0, "{label} uc old rcx");
        assert_eq!(word(d, 584), 42, "{label} quotient 84/2");
    }
}

/// I1-E async arbitrary phase: USR1 sent repeatedly while a
/// long copied-instruction loop runs; delivery may land at
/// block-head stubs, copied insns, branch stubs, or exit
/// machinery. Timing makes counts non-pin-able, so this is a
/// completion + witness-PC-range check (exact counts stay
/// with the deterministic I1-D/sync cases above).
fn check_async_arbitrary_phase() {
    let fix = fixture_v(
        FLAGS_SIGINFO,
        libc::SIGUSR1 as u8,
        RESTORER,
        false,
        64,
        0,
        HANDLER,
        false,
    );
    corpus::check("E3 async arbitrary phase", &fix.bytes);
    let (mut remote, _deadline) =
        deadline::remote_bytes_with_blocked(REMOTE_CHILD, &fix.bytes, &[libc::SIGUSR1])
            .expect("spawn remote");
    let info = remote.info();
    let region = RegionFacts {
        base: info.base,
        bytes: fix.bytes.clone(),
        generation: Generation(1),
        immutable_private: true,
    };
    remote
        .prepare(
            &region,
            info.base + fix.main_off,
            CountProfile::BranchesAndInstructions,
        )
        .expect("prepare remote");
    let pid = remote.child_pid_for_test();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done2 = done.clone();
    let killer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        for _ in 0..600 {
            if done2.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            // SAFETY: signalling the test's traced child.
            unsafe {
                libc::kill(pid, libc::SIGUSR1);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });
    let out = remote.run(guest_state(&remote, info, &fix), RETURN_SENTINEL);
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    killer.join().expect("killer thread");
    let out = out.expect("arbitrary-phase round trip");
    assert_eq!(out.state.rax, 42, "arbitrary-phase result");
    let mut data = vec![0u8; 640];
    assert!(remote.read_mem(info.dst, &mut data));
    assert!(word(&data, 512) >= 1, "handler ran: {}", word(&data, 512));
    assert_eq!(word(&data, 576), 1, "progress through handler");
    assert_eq!(word(&data, 616), 7, "idempotent body value");
    let rip_off = word(&data, 544) - info.base;
    assert!(
        (fix.resume_off..fix.done_off).contains(&rip_off),
        "uc rip offset {rip_off:#x} in loop range {:#x}..{:#x}",
        fix.resume_off,
        fix.done_off
    );
}

/// I1-F second async signal: the plain SIGUSR2 round trip
/// has the same enumerated counts as SIGUSR1 (60/2) and a
/// matching native witness with signum 12.
fn check_usr2_round_trip() {
    let fix = fixture_v(
        FLAGS_SIGINFO,
        libc::SIGUSR2 as u8,
        RESTORER,
        false,
        0,
        0,
        HANDLER,
        false,
    );
    let (_remote, info, out, data) =
        run_translated_sig("F1 SIGUSR2 round trip", &fix, libc::SIGUSR2, true);
    let out = out.expect("translated USR2 round trip");
    assert_eq!(out.state.rax, 42, "usr2 result");
    assert_eq!(out.instructions, 60, "usr2 instructions");
    assert_eq!(out.branches, 2, "usr2 branches");
    let n = native_run(&fix, Some(libc::SIGUSR2));
    assert_eq!(n.result, 42, "native usr2 result");
    let tw = witness(&data, info.base, info.dst, info.stack_top);
    let nw = witness(&n.data, n.base, n.dst, n.stack_top);
    assert_eq!(tw, nw, "usr2 translated vs native witness");
    assert_eq!(tw.signum, libc::SIGUSR2 as u64);
}

/// I1-F mask matrix: handler-entry mask is the kernel's
/// (baseline + sa_mask + delivered unless SA_NODEFER),
/// queried by the handler itself; sigreturn restores the
/// pre-delivery mask in the mirror. Counts: main 37 +
/// mask handler 19 + restorer 2 = 58 insns, 2 branches.
fn check_mask(nodefer: bool) {
    let flags = FLAGS_SIGINFO | if nodefer { 0x4000_0000 } else { 0 };
    let sa_mask: u32 = 0x2800; // SIGUSR2 | SIGALRM bits
    let fix = fixture_v(
        flags,
        libc::SIGUSR1 as u8,
        RESTORER,
        false,
        0,
        sa_mask,
        MASK_HANDLER,
        false,
    );
    let expected_entry = u64::from(sa_mask) | if nodefer { 0 } else { 0x200 };
    let (remote, info, out, data) = run_translated_sig(
        &format!("F2 mask nodefer={nodefer}"),
        &fix,
        libc::SIGUSR1,
        true,
    );
    let out = out.expect("translated mask round trip");
    assert_eq!(out.state.rax, 42, "mask result nodefer={nodefer}");
    assert_eq!(out.instructions, 58, "mask instructions");
    assert_eq!(out.branches, 2, "mask branches");
    let n = native_run(&fix, Some(libc::SIGUSR1));
    assert_eq!(n.result, 42, "native mask result");
    for (label, d, base) in [
        ("translated", &data, info.base),
        ("native", &n.data, n.base),
    ] {
        assert_eq!(word(d, 280), u64::from(flags), "{label} queried flags");
        assert_eq!(word(d, 296), u64::from(sa_mask), "{label} queried sa_mask");
        assert_eq!(word(d, 512), 1, "{label} handler runs");
        assert_eq!(word(d, 616), 0, "{label} mask query rc");
        assert_eq!(word(d, 624), expected_entry, "{label} handler-entry mask");
        assert_eq!(word(d, 544) - base, fix.resume_off, "{label} uc rip");
        assert_eq!(word(d, 592), NEW_R13, "{label} repaired r13");
    }
    assert_eq!(remote.registry().mask(), 0, "mirror mask restored");
    assert_eq!(
        remote.registry().action(libc::SIGUSR1).sa_mask,
        u64::from(sa_mask),
        "mirror sa_mask retained"
    );
}

/// I1-F altstack: SA_ONSTACK delivery lands the frame on
/// the guest altstack (src buffer) while the interrupted
/// RSP stays the main stack. Counts: main 45 (incl. 8-insn
/// altstack install) + handler 22 (rsp store + I1-D handler)
/// + restorer 2 = 69 insns, 2 branches.
fn check_altstack() {
    let mut alt_handler = vec![0x48, 0x89, 0xa3, 0x68, 0x02, 0x00, 0x00]; // mov [rbx+616], rsp
    alt_handler.extend_from_slice(HANDLER);
    let fix = fixture_v(
        FLAGS_ONSTACK,
        libc::SIGUSR1 as u8,
        RESTORER,
        false,
        0,
        0,
        &alt_handler,
        true,
    );
    let (remote, info, out, data) = run_translated_sig("F3 altstack", &fix, libc::SIGUSR1, true);
    let out = out.expect("translated altstack round trip");
    assert_eq!(out.state.rax, 42, "altstack result");
    assert_eq!(out.instructions, 69, "altstack instructions");
    assert_eq!(out.branches, 2, "altstack branches");
    assert_eq!(word(&data, 96), 0, "sigaltstack install rc");
    let n = native_run(&fix, Some(libc::SIGUSR1));
    assert_eq!(n.result, 42, "native altstack result");
    for (label, d, src, stack_top) in [
        ("translated", &data, info.src, info.stack_top),
        ("native", &n.data, n.src, n.stack_top),
    ] {
        let frame_rsp = word(d, 616);
        assert!(
            (src..src + 8192).contains(&frame_rsp),
            "{label} frame rsp {frame_rsp:#x} on altstack {src:#x}..{:#x}",
            src + 8192
        );
        assert_eq!(word(d, 560), stack_top, "{label} uc rsp stays main stack");
        assert_eq!(word(d, 512), 1, "{label} handler runs");
    }
    assert_eq!(remote.registry().altstack().sp, info.src);
    assert_eq!(remote.registry().altstack().size, 8192);
}

fn seq_store(slot: u32) -> Vec<u8> {
    // mov rax,[rbx+600]; inc rax; mov [rbx+600],rax; mov [rbx+slot],rax
    let mut v = vec![
        0x48, 0x8b, 0x83, 0x58, 0x02, 0x00, 0x00, 0x48, 0xff, 0xc0, 0x48, 0x89, 0x83, 0x58, 0x02,
        0x00, 0x00, 0x48, 0x89, 0x83,
    ];
    v.extend_from_slice(&slot.to_le_bytes());
    v
}

fn send_self(sig: u8) -> Vec<u8> {
    // getpid; kill(pid, sig) — 6 insns, rc left in rax.
    vec![
        0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0xc7, 0xbe, sig, 0x00, 0x00, 0x00,
        0xb8, 0x3e, 0x00, 0x00, 0x00, 0x0f, 0x05,
    ]
}

/// Distinct-signal nesting: USR1 handler self-sends USR2;
/// USR2 handler runs nested inside it (seq 1,2,3,4).
fn nest_fixture() -> FixtureBytes {
    let mut inner: Vec<u8> = vec![0x48, 0xff, 0x83, 0x08, 0x02, 0x00, 0x00]; // inc [rbx+520]
    inner.extend(seq_store(616));
    inner.extend_from_slice(&[
        0x48, 0x8b, 0x82, 0xa8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x83, 0x28, 0x02, 0x00, 0x00,
    ]); // uc rip -> [rbx+552]
    inner.extend_from_slice(&[
        0x48, 0xc7, 0x83, 0x48, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ]); // inner_done=1
    inner.extend(seq_store(624));
    inner.push(0xc3);
    let mut outer: Vec<u8> = vec![0x48, 0xff, 0x83, 0x00, 0x02, 0x00, 0x00]; // inc [rbx+512]
    outer.extend(seq_store(608));
    outer.extend_from_slice(&[
        0x48, 0xc7, 0x83, 0x40, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ]); // entered=1
    outer.extend(send_self(libc::SIGUSR2 as u8));
    outer.extend_from_slice(&[0x48, 0x89, 0x83, 0x18, 0x02, 0x00, 0x00]); // mov [rbx+536], rax
    outer.extend_from_slice(&[
        0x48, 0x8b, 0x82, 0xa8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x83, 0x20, 0x02, 0x00, 0x00,
    ]); // uc rip -> [rbx+544]
    outer.extend_from_slice(&[0xb9, 0x40, 0x42, 0x0f, 0x00]); // mov ecx, 1000000
    outer.extend_from_slice(&[
        0x48, 0x83, 0xbb, 0x48, 0x02, 0x00, 0x00, 0x00, 0x75, 0x05, 0x48, 0xff, 0xc9, 0x75, 0xf1,
    ]); // spin until inner_done
    outer.extend(seq_store(632));
    outer.extend_from_slice(&[
        0x48, 0xc7, 0x83, 0x50, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc3,
    ]); // outer_done=1; ret
    let mut v = Vec::new();
    v.extend_from_slice(&outer);
    let inner_off = v.len() as u64;
    v.extend_from_slice(&inner);
    let restorer_off = v.len() as u64;
    v.extend_from_slice(RESTORER);
    let main_off = v.len() as u64;
    // Build act (handler=rbp=outer, flags, restorer=r12, mask 0); install USR1.
    v.extend_from_slice(&[0x48, 0x89, 0x2b, 0x48, 0xc7, 0x43, 0x08]);
    v.extend_from_slice(&FLAGS_SIGINFO.to_le_bytes());
    v.extend_from_slice(&[
        0x4c, 0x89, 0x63, 0x10, 0x48, 0xc7, 0x43, 0x18, 0, 0, 0, 0, 0xbf, 0x0a, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xde, 0x48, 0x8d, 0x53, 0x20, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d,
        0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43, 0x40,
    ]);
    // Point act at inner handler; install USR2.
    v.extend_from_slice(&[0x48, 0x8d, 0x85]);
    v.extend_from_slice(&(inner_off as u32).to_le_bytes());
    v.extend_from_slice(&[
        0x48, 0x89, 0x03, 0xbf, 0x0c, 0x00, 0x00, 0x00, 0x48, 0x89, 0xde, 0x48, 0x8d, 0x53, 0x20,
        0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89,
        0x43, 0x48,
    ]);
    // Reachability devices for both handlers.
    for target in [0u64, inner_off] {
        v.extend_from_slice(&[0x48, 0x39, 0xc9]);
        let pos = v.len();
        v.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]);
        let rel = (target as i64 - (pos as i64 + 6)) as i32;
        v[pos + 2..pos + 6].copy_from_slice(&rel.to_le_bytes());
    }
    // Unblock USR1|USR2.
    v.extend_from_slice(&[
        0x48, 0xc7, 0x83, 0x80, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00,
    ]);
    v.extend_from_slice(&[
        0xbf, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0xb3, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x93,
        0x88, 0x00, 0x00, 0x00, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0e, 0x00, 0x00, 0x00,
        0x0f, 0x05,
    ]);
    let resume_off = v.len() as u64;
    v.extend_from_slice(&[
        0x48, 0x89, 0x43, 0x50, 0xb9, 0x80, 0xf0, 0xaf, 0x02, 0x48, 0x83, 0xbb, 0x50, 0x02, 0x00,
        0x00, 0x00, 0x75, 0x0b, 0x48, 0xff, 0xc9, 0x75, 0xf1, 0xb8, 0xf9, 0xff, 0xff, 0xff, 0xc3,
        0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3,
    ]);
    FixtureBytes {
        bytes: v,
        restorer_off,
        main_off,
        resume_off,
        done_off: inner_off,
        fault_off: 0,
    }
}

fn check_nested_distinct() {
    let fix = nest_fixture();
    let (_remote, info, out, data) =
        run_translated_sig("F4 nested distinct", &fix, libc::SIGUSR1, true);
    let out = out.expect("translated nested round trip");
    assert_eq!(out.state.rax, 42, "nested result");
    // Enumerated: main 37 + outer 24 + inner 13 + 2 sigreturn restorers.
    assert_eq!(out.instructions, 78, "nested instructions");
    assert_eq!(out.branches, 4, "nested branches");
    let n = native_run(&fix, Some(libc::SIGUSR1));
    assert_eq!(n.result, 42, "native nested result");
    for (label, d) in [("translated", &data), ("native", &n.data)] {
        assert_eq!(word(d, 64), 0, "{label} install USR1");
        assert_eq!(word(d, 72), 0, "{label} install USR2");
        assert_eq!(word(d, 536), 0, "{label} self-kill rc");
        assert_eq!(word(d, 512), 1, "{label} outer runs");
        assert_eq!(word(d, 520), 1, "{label} inner runs");
        assert_eq!(word(d, 608), 1, "{label} outer enter seq");
        assert_eq!(word(d, 616), 2, "{label} inner enter seq");
        assert_eq!(word(d, 624), 3, "{label} inner exit seq");
        assert_eq!(word(d, 632), 4, "{label} outer exit seq (LIFO)");
    }
    let inner_rip_off = word(&data, 552) - info.base;
    assert!(
        inner_rip_off < fix.done_off,
        "inner uc rip in outer handler range: {inner_rip_off:#x}"
    );
    assert_eq!(
        word(&data, 552) - info.base,
        word(&n.data, 552) - n.base,
        "inner uc rip offset match"
    );
}

/// Same-signal reentry: with SA_NODEFER the handler
/// self-sends SIGUSR1 and its second instance runs nested
/// inside the first (count reaches 2 before outer return).
fn same_reentry_fixture() -> FixtureBytes {
    let mut handler: Vec<u8> = vec![
        0x48, 0xff, 0x83, 0x00, 0x02, 0x00, 0x00, // inc [rbx+512]
        0x48, 0x83, 0xbb, 0x00, 0x02, 0x00, 0x00, 0x01, // cmp qword [rbx+512], 1
    ];
    let jne_pos = handler.len();
    handler.extend_from_slice(&[0x75, 0]); // jne INNER
    handler.extend(send_self(libc::SIGUSR1 as u8));
    handler.extend_from_slice(&[0x48, 0x89, 0x83, 0x18, 0x02, 0x00, 0x00]); // mov [rbx+536], rax
    handler.extend_from_slice(&[0xb9, 0x40, 0x42, 0x0f, 0x00]); // mov ecx, 1000000
    handler.extend_from_slice(&[
        0x48, 0x83, 0xbb, 0x48, 0x02, 0x00, 0x00, 0x00, 0x75, 0x05, 0x48, 0xff, 0xc9, 0x75, 0xf1,
    ]); // spin until inner flag
    handler.extend_from_slice(&[
        0x48, 0xc7, 0x83, 0x50, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc3,
    ]); // outer done; ret
    let inner_pos = handler.len();
    handler[jne_pos + 1] = (inner_pos - (jne_pos + 2)) as u8;
    handler.extend_from_slice(&[
        0x48, 0xc7, 0x83, 0x48, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc3,
    ]); // INNER: flag; ret
    let mut v = Vec::new();
    v.extend_from_slice(&handler);
    let restorer_off = v.len() as u64;
    v.extend_from_slice(RESTORER);
    let main_off = v.len() as u64;
    v.extend_from_slice(&[0x48, 0x89, 0x2b, 0x48, 0xc7, 0x43, 0x08]);
    v.extend_from_slice(&(FLAGS_SIGINFO | 0x4000_0000).to_le_bytes());
    v.extend_from_slice(&[
        0x4c, 0x89, 0x63, 0x10, 0x48, 0xc7, 0x43, 0x18, 0, 0, 0, 0, 0xbf, 0x0a, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xde, 0x48, 0x8d, 0x53, 0x20, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d,
        0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43, 0x40, 0x48, 0x39, 0xc9,
    ]);
    let pos = v.len();
    v.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]);
    let rel = (0i64 - (pos as i64 + 6)) as i32;
    v[pos + 2..pos + 6].copy_from_slice(&rel.to_le_bytes());
    v.extend_from_slice(&[
        0x48, 0xc7, 0x83, 0x80, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    ]);
    v.extend_from_slice(&[
        0xbf, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0xb3, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x93,
        0x88, 0x00, 0x00, 0x00, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0e, 0x00, 0x00, 0x00,
        0x0f, 0x05,
    ]);
    let resume_off = v.len() as u64;
    v.extend_from_slice(&[
        0x48, 0x89, 0x43, 0x50, 0xb9, 0x80, 0xf0, 0xaf, 0x02, 0x48, 0x83, 0xbb, 0x50, 0x02, 0x00,
        0x00, 0x00, 0x75, 0x0b, 0x48, 0xff, 0xc9, 0x75, 0xf1, 0xb8, 0xf9, 0xff, 0xff, 0xff, 0xc3,
        0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3,
    ]);
    FixtureBytes {
        bytes: v,
        restorer_off,
        main_off,
        resume_off,
        done_off: 0,
        fault_off: 0,
    }
}

fn check_same_signal_reentry() {
    let fix = same_reentry_fixture();
    let (_remote, _info, out, data) =
        run_translated_sig("F5 same-signal reentry", &fix, libc::SIGUSR1, true);
    let out = out.expect("translated same-signal reentry");
    assert_eq!(out.state.rax, 42, "reentry result");
    // Main 26 + outer handler 15 + inner instance 5 + 2 restorers.
    assert_eq!(out.instructions, 50, "reentry instructions");
    assert_eq!(out.branches, 5, "reentry branches");
    let n = native_run(&fix, Some(libc::SIGUSR1));
    assert_eq!(n.result, 42, "native reentry result");
    for (label, d) in [("translated", &data), ("native", &n.data)] {
        assert_eq!(word(d, 512), 2, "{label} handler entered twice (nested)");
        assert_eq!(word(d, 536), 0, "{label} self-kill rc");
        assert_eq!(word(d, 584), 1, "{label} inner ran");
        assert_eq!(word(d, 592), 1, "{label} outer completed after inner");
    }
}

/// Disposition change under a live frame: handler 1 installs
/// handler 2 (different handler + restorer) for its own
/// signal, still returns through the ORIGINAL restorer; the
/// next delivery uses handler 2. done_off holds the second
/// delivery's expected uc-rip offset (wait-2 block head).
fn disposition_fixture() -> FixtureBytes {
    let h1: &[u8] = &[
        0x48, 0xff, 0x83, 0x00, 0x02, 0x00, 0x00, // inc [rbx+512]
        0x48, 0x8b, 0x82, 0xa8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x83, 0x20, 0x02, 0x00,
        0x00, // uc rip -> [544]
        0x4c, 0x89, 0xbb, 0x80, 0x01, 0x00, 0x00, // mov [rbx+384], r15
        0x48, 0xc7, 0x83, 0x88, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x04, // flags
        0x4c, 0x89, 0xb3, 0x90, 0x01, 0x00, 0x00, // mov [rbx+400], r14
        0x48, 0xc7, 0x83, 0x98, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mask 0
        0xbf, 0x0a, 0x00, 0x00, 0x00, 0x48, 0x8d, 0xb3, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8d, 0x93,
        0xa0, 0x01, 0x00, 0x00, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d, 0x00, 0x00, 0x00,
        0x0f, 0x05, 0x48, 0x89, 0x83, 0x18, 0x02, 0x00, 0x00, // install; rc -> [536]
        0x48, 0xc7, 0x83, 0x40, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc3, // flag1; ret
    ];
    let h2: &[u8] = &[
        0x48, 0xff, 0x83, 0x08, 0x02, 0x00, 0x00, // inc [rbx+520]
        0x48, 0x8b, 0x82, 0xa8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x83, 0x28, 0x02, 0x00,
        0x00, // uc rip -> [552]
        0x48, 0xc7, 0x83, 0x48, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc3, // flag2; ret
    ];
    let mut v = Vec::new();
    v.extend_from_slice(h1);
    let h2_off = v.len() as u64;
    v.extend_from_slice(h2);
    let restorer_off = v.len() as u64;
    v.extend_from_slice(RESTORER);
    let restorer2_off = v.len() as u64;
    v.extend_from_slice(RESTORER);
    let main_off = v.len() as u64;
    v.extend_from_slice(&[0x48, 0x89, 0x2b, 0x48, 0xc7, 0x43, 0x08]);
    v.extend_from_slice(&FLAGS_SIGINFO.to_le_bytes());
    v.extend_from_slice(&[
        0x4c, 0x89, 0x63, 0x10, 0x48, 0xc7, 0x43, 0x18, 0, 0, 0, 0, 0xbf, 0x0a, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xde, 0x48, 0x8d, 0x53, 0x20, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0d,
        0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0x43, 0x40,
    ]);
    v.extend_from_slice(&[0x4c, 0x8d, 0xbd]);
    v.extend_from_slice(&(h2_off as u32).to_le_bytes());
    v.extend_from_slice(&[0x4c, 0x8d, 0xb5]);
    v.extend_from_slice(&(restorer2_off as u32).to_le_bytes());
    for target in [0u64, h2_off] {
        v.extend_from_slice(&[0x48, 0x39, 0xc9]);
        let pos = v.len();
        v.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]);
        let rel = (target as i64 - (pos as i64 + 6)) as i32;
        v[pos + 2..pos + 6].copy_from_slice(&rel.to_le_bytes());
    }
    v.extend_from_slice(&[
        0x48, 0xc7, 0x83, 0x80, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    ]);
    v.extend_from_slice(&[
        0xbf, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0xb3, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x93,
        0x88, 0x00, 0x00, 0x00, 0x41, 0xba, 0x08, 0x00, 0x00, 0x00, 0xb8, 0x0e, 0x00, 0x00, 0x00,
        0x0f, 0x05,
    ]);
    let resume_off = v.len() as u64;
    // wait flag1 (mov rc store, mov ecx, cmp [576], jne, dec, jne, timeout)
    v.extend_from_slice(&[
        0x48, 0x89, 0x43, 0x50, 0xb9, 0x80, 0xf0, 0xaf, 0x02, 0x48, 0x83, 0xbb, 0x40, 0x02, 0x00,
        0x00, 0x00, 0x75, 0x0b, 0x48, 0xff, 0xc9, 0x75, 0xf1, 0xb8, 0xf9, 0xff, 0xff, 0xff, 0xc3,
    ]);
    v.extend(send_self(libc::SIGUSR1 as u8));
    let done_off = v.len() as u64;
    v.extend_from_slice(&[0x48, 0x89, 0x43, 0x60]); // mov [rbx+96], rax
    v.extend_from_slice(&[
        0xb9, 0x80, 0xf0, 0xaf, 0x02, 0x48, 0x83, 0xbb, 0x48, 0x02, 0x00, 0x00, 0x00, 0x75, 0x0b,
        0x48, 0xff, 0xc9, 0x75, 0xf1, 0xb8, 0xf9, 0xff, 0xff, 0xff, 0xc3, 0xb8, 0x2a, 0x00, 0x00,
        0x00, 0xc3,
    ]);
    FixtureBytes {
        bytes: v,
        restorer_off,
        main_off,
        resume_off,
        done_off,
        fault_off: h2_off,
    }
}

fn check_disposition_change() {
    let fix = disposition_fixture();
    let h2_off = fix.fault_off;
    let (remote, info, out, data) =
        run_translated_sig("F6 disposition change", &fix, libc::SIGUSR1, true);
    let out = out.expect("translated disposition change");
    assert_eq!(out.state.rax, 42, "disposition result");
    assert_eq!(out.instructions, 65, "disposition instructions");
    assert_eq!(out.branches, 4, "disposition branches");
    let n = native_run(&fix, Some(libc::SIGUSR1));
    assert_eq!(n.result, 42, "native disposition result");
    for (label, d, base) in [
        ("translated", &data, info.base),
        ("native", &n.data, n.base),
    ] {
        assert_eq!(word(d, 512), 1, "{label} handler1 runs");
        assert_eq!(word(d, 520), 1, "{label} handler2 runs");
        assert_eq!(word(d, 536), 0, "{label} in-handler install rc");
        assert_eq!(word(d, 416), base, "{label} oldact is handler1");
        assert_eq!(word(d, 544) - base, fix.resume_off, "{label} h1 uc rip");
        assert_eq!(word(d, 552) - base, fix.done_off, "{label} h2 uc rip");
        assert_eq!(word(d, 96), 0, "{label} second self-kill rc");
    }
    let act = remote.registry().action(libc::SIGUSR1);
    assert_eq!(
        act.handler,
        info.base + h2_off,
        "mirror follows new handler"
    );
    assert_eq!(
        act.restorer,
        info.base + fix.restorer_off + 7,
        "mirror follows new restorer"
    );
}

#[test]
fn remote_signal_all() {
    let _bound = deadline::TestBound::arm();
    // Every fixture this test builds is pinned (see `corpus`).
    let _corpus = corpus::guard();
    check_round_trip();
    check_no_send_control();
    check_ineligible_shape(FLAGS_NO_SIGINFO, "no SA_SIGINFO");
    check_ineligible_shape(FLAGS_SIGINFO | 0x8000_0000, "SA_RESETHAND");
    check_oldact_sentinel_on_error();
    check_alias_install_mirrored();
    // P1 probe: a restorer that is not exactly
    // `mov eax,15; syscall` must never execute natively.
    let mut nop_restorer = vec![0x90u8];
    nop_restorer.extend_from_slice(RESTORER);
    check_ineligible_fixture(
        &fixture_v(
            FLAGS_SIGINFO,
            libc::SIGUSR1 as u8,
            &nop_restorer,
            false,
            0,
            0,
            HANDLER,
            false,
        ),
        libc::SIGUSR1,
        "NOP-prefixed restorer",
    );
    check_usr2_round_trip();
    check_sync_segv();
    check_sync_fpe();
    check_async_arbitrary_phase();
    check_mask(false);
    check_mask(true);
    check_altstack();
    check_same_signal_reentry();
    check_disposition_change();
    check_nested_distinct();
}

/// Spawn census (I1-H H2c): every child this binary starts carries
/// a run deadline (`common/deadline.rs`).
#[test]
fn spawn_census() {
    deadline::spawn_census(include_str!("remote_signal.rs"), "remote_signal.rs");
}

/// Bound census (I1-H H2d): every test here arms a `TestBound`
/// (`common/deadline.rs`).
#[test]
fn bound_census() {
    deadline::bound_census(
        include_str!("remote_signal.rs"),
        "remote_signal.rs",
        &["spawn_census", "bound_census"],
    );
}
