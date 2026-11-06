//! Native differential child for I1-D signal tests: run the
//! same fixture bytes natively (no translation, no ptrace
//! dispatcher) with the same register/stack setup and the
//! same blocked-then-sent signal arrangement as the remote
//! run, and report the guest witness buffer verbatim.
//!
//! Protocol: argv is `hex:<bytes>` plus the decimal entry
//! offset. The child blocks SIGUSR1, writes setup
//! `(base, stack_top, dst, src)` as four LE u64s, reads one
//! go byte from stdin (the parent sends the pending signal
//! first), enters the fixture on the guest stack with
//! `rbx=dst, rbp=base, r12=base+restorer_off, r13=src`, then
//! writes `(result rax, dst[0..640])` and exits. The handler
//! and restorer offsets are fixture conventions shared with
//! the test: handler at 0, restorer immediately after it —
//! the entry trampoline only needs `rbp`/`r12` values the
//! parent test also presets remotely, passed here as two
//! extra decimal offset arguments to stay layout-agnostic.

use std::io::{Read, Write};

use liteinst_jit::harness::MappedGuest;

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelSigaction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[unsafe(no_mangle)]
static mut HOST_RSP: u64 = 0;

// Native entry trampoline: save host callee-saved state,
// plant the resume label as the guest return sentinel at
// [stack_top], switch to the guest stack with the fixture
// register preset (other GPRs zeroed, flags 0x202), and
// `ret` into the fixture so guest-entry RSP is exactly
// stack_top. The fixture's final `ret` lands on the resume
// label, which restores the host stack and returns RAX.
core::arch::global_asm!(
    r#"
    .globl liteinst_native_enter
liteinst_native_enter:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov QWORD PTR [rip + HOST_RSP], rsp
    mov rbx, QWORD PTR [rdx]
    mov rbp, QWORD PTR [rdx + 8]
    mov r12, QWORD PTR [rdx + 16]
    mov r13, QWORD PTR [rdx + 24]
    mov rsp, rsi
    lea rcx, [rip + 2f]
    mov QWORD PTR [rsp], rcx
    push rdi
    xor eax, eax
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor edi, edi
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r14d, r14d
    xor r15d, r15d
    push 0x202
    popfq
    ret
2:
    mov rsp, QWORD PTR [rip + HOST_RSP]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    "#
);

unsafe extern "C" {
    fn liteinst_native_enter(entry: u64, stack_top: u64, regs: *const u64) -> u64;
}

fn main() {
    let arg = std::env::args().nth(1).expect("hex arg");
    let entry_off: u64 = std::env::args()
        .nth(2)
        .expect("entry offset")
        .parse()
        .expect("entry offset decimal");
    let restorer_off: u64 = std::env::args()
        .nth(3)
        .expect("restorer offset")
        .parse()
        .expect("restorer offset decimal");
    let block_sig: i32 = std::env::args()
        .nth(4)
        .map_or(libc::SIGUSR1, |a| a.parse().expect("block signum decimal"));
    let hex = arg.strip_prefix("hex:").expect("hex bytes only");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex bytes"))
        .collect();
    // Normalize SIGUSR1 to a true zero default, disable the
    // altstack, and block SIGUSR1 so the parent's signal
    // stays pending until the guest unblocks it — the same
    // arrangement the remote child starts from.
    // SAFETY: single-threaded setup before any guest code.
    unsafe {
        let zero = KernelSigaction {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        for sig in [libc::SIGUSR1, libc::SIGUSR2] {
            let rc = libc::syscall(
                libc::SYS_rt_sigaction,
                sig,
                &zero as *const KernelSigaction,
                core::ptr::null_mut::<KernelSigaction>(),
                8usize,
            );
            assert_eq!(rc, 0, "normalize signal");
        }
        let disabled = libc::stack_t {
            ss_sp: core::ptr::null_mut(),
            ss_flags: libc::SS_DISABLE,
            ss_size: 0,
        };
        assert_eq!(
            libc::sigaltstack(&disabled, core::ptr::null_mut()),
            0,
            "disable altstack"
        );
        let mut set: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, block_sig);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, core::ptr::null_mut()),
            0,
            "block signal"
        );
    }
    let guest = MappedGuest::map(&bytes).expect("map fixture");
    let dst: &'static mut [u8; 8192] = Box::leak(Box::new([0u8; 8192]));
    let src: &'static mut [u8; 8192] = Box::leak(Box::new(core::array::from_fn(|i| i as u8)));
    let mut info = [0u8; 32];
    for (i, v) in [
        guest.base,
        guest.stack_top(),
        dst.as_ptr() as u64,
        src.as_ptr() as u64,
    ]
    .iter()
    .enumerate()
    {
        info[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    let mut out = std::io::stdout().lock();
    out.write_all(&info).expect("write info");
    out.flush().expect("flush info");
    drop(out);
    let mut go = [0u8; 1];
    std::io::stdin()
        .lock()
        .read_exact(&mut go)
        .expect("read go byte");
    let regs: [u64; 4] = [
        dst.as_ptr() as u64,
        guest.base,
        guest.base + restorer_off,
        src.as_ptr() as u64,
    ];
    // SAFETY: the trampoline preserves the host callee-saved
    // set and stack across the guest call; the fixture
    // returns through the planted resume sentinel.
    let result =
        unsafe { liteinst_native_enter(guest.base + entry_off, guest.stack_top(), regs.as_ptr()) };
    let mut out = std::io::stdout().lock();
    out.write_all(&result.to_le_bytes()).expect("write result");
    out.write_all(&dst[0..640]).expect("write witness");
    out.flush().expect("flush output");
}
