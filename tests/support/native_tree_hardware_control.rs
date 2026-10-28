//! Actual positive prerequisite for the new fixture-only hardware-stop owner.
//! This is separate from all application-state comparison populations.
use super::super::{CHILD_BUDGET, Mapping, PAGE, Tracee, Walk, canonical_xstate, seeded_xstate};
use super::*;
use std::cell::Cell;
use std::time::Instant;

const CONTROL_TF: u64 = 1 << 8;
const CONTROL_RF: u64 = 1 << 16;
const CONTROL_CAUSES: u64 = 0xe00f; // B0..B3, BD, BS and BT.

// Every field, including original syscall number, RIP, segments and TLS bases.
// No comparator/flags mask is borrowed or broadened for this positive control.
fn words(r: &libc::user_regs_struct) -> [u64; 27] {
    [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ]
}

// Independent positive readback. Writes and temporary ownership belong solely
// to the helper under test. A failed read is fatal under existing Tracee custody.
fn debug_words(child: &Tracee) -> [u64; 3] {
    assert_eq!(std::mem::size_of::<usize>(), 8);
    assert_eq!(std::mem::size_of::<libc::c_ulonglong>(), 8);
    [0, 6, 7].map(|index| {
        let offset = std::mem::offset_of!(libc::user, u_debugreg)
            + index * std::mem::size_of::<libc::c_ulonglong>();
        let result;
        let error;
        // SAFETY: native user layout offset and an exact stopped owned tracee;
        // errno is thread-local and captured before any intervening operation.
        unsafe {
            *libc::__errno_location() = 0;
            result = libc::ptrace(libc::PTRACE_PEEKUSER, child.pid, offset, 0_usize);
            error = *libc::__errno_location();
        }
        assert!(
            result != -1 || error == 0,
            "control debug read failed: {error}"
        );
        result as u64
    })
}

fn memory_and_xstate(child: &Tracee, mappings: &[&Mapping; 3], xstate: &[u8]) {
    for mapping in mappings {
        assert_eq!(
            child.memory(mapping.address(), mapping.bytes().len()),
            mapping.bytes()
        );
    }
    assert_eq!(canonical_xstate(&child.xstate()), xstate);
}

#[test]
#[ignore = "requires explicit fresh-process release hardware-stop prerequisite"]
fn owned_execution_breakpoint_restores_then_steps_then_stops() {
    // The deadline precedes every allocation and fork. Nothing renews it.
    let deadline = Instant::now() + CHILD_BUDGET;
    let code = Mapping::new(PAGE);
    let data = Mapping::new(PAGE);
    let stack = Mapping::new(PAGE);
    // Three NOPs, then a private ordinary exit(0) syscall; UD2 is unreachable.
    code.initialize(
        0,
        &[
            0x90, 0x90, 0x90, 0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05, 0x0f, 0x0b,
        ],
    );
    data.initialize(0, &[0x6b; PAGE]);
    stack.initialize(0, &[0xa5; PAGE]);
    code.protect(libc::PROT_READ | libc::PROT_EXEC);
    assert!(Instant::now() < deadline);
    // SAFETY: child uses only async-signal-safe syscalls, never returns into the
    // libtest harness and runs only the parent's private RX literal after stop.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize) == -1 {
                libc::_exit(120);
            }
            libc::kill(libc::getpid(), libc::SIGSTOP);
            libc::_exit(121);
        }
    }
    let child = Tracee {
        pid,
        deadline,
        reaped: Cell::new(false),
    };
    let status = child.wait();
    assert!(Instant::now() < deadline);
    assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP);
    assert_eq!((status as u32) >> 16, 0);
    let mut seed = child.registers();
    seed.rax = 0x1111_2222_3333_4444;
    seed.rbx = 0x5555_6666_7777_8888;
    seed.rcx = 0x9999_aaaa_bbbb_cccc;
    seed.rdx = 0xdddd_eeee_ffff_0000;
    seed.rsi = data.address() + 64;
    seed.rdi = data.address();
    seed.rbp = 0x0123_4567_89ab_cdef;
    seed.r8 = 8;
    seed.r9 = 9;
    seed.r10 = 10;
    seed.r11 = 11;
    seed.r12 = 12;
    seed.r13 = 13;
    seed.r14 = 14;
    seed.r15 = 15;
    seed.orig_rax = u64::MAX;
    seed.rip = code.address();
    seed.rsp = stack.address() + PAGE as u64 - 8;
    seed.eflags = 0x202; // TF/RF clear, no application instruction produces RF.
    let seeded = seeded_xstate(child.xstate(), 0x1234_5678_8765_4320);
    child.set_registers(&seed);
    child.set_xstate(&seeded);
    assert_eq!(words(&child.registers()), words(&seed));
    let xstate = canonical_xstate(&child.xstate());
    let mappings = [&code, &data, &stack];
    memory_and_xstate(&child, &mappings, &xstate);
    let mut walk = Walk {
        child: &child,
        steps: 0,
    };
    let mut rf_observed = 0;
    let mut step_tf_bits = 0;
    for (index, offset) in [0, 2].into_iter().enumerate() {
        let before_debug = debug_words(&child);
        let target = code.address() + offset;
        let stopped = stop_at(&child, Target::probe(target)).unwrap();
        assert_eq!(debug_words(&child), before_debug);
        assert_eq!(stopped.dr6() & CONTROL_CAUSES, 1);
        let raw = stopped.raw();
        assert_eq!(words(&child.registers()), words(raw));
        let normalized = stopped.harness().unwrap();
        let mut expected = seed;
        expected.rip = target;
        assert_eq!(words(&normalized), words(&expected));
        assert!(matches!(raw.eflags ^ normalized.eflags, 0 | CONTROL_RF));
        assert_eq!(raw.eflags & CONTROL_TF, 0);
        rf_observed += usize::from(raw.eflags & CONTROL_RF != 0);
        memory_and_xstate(&child, &mappings, &xstate);
        // Step the actual NOP with the debug registers already restored. This
        // explicit step charges the same counter; no register repair occurs.
        walk.step("hardware-control-nop");
        let stepped = child.registers();
        assert_eq!(stepped.eflags & CONTROL_RF, 0);
        expected.rip = target + 1;
        // Only the inherited debugger TF exposure can differ after SINGLESTEP.
        // The following CONT must still reach a genuine B0-only hardware event.
        expected.eflags |= stepped.eflags & CONTROL_TF;
        step_tf_bits |= usize::from(stepped.eflags & CONTROL_TF != 0) << index;
        assert_eq!(words(&stepped), words(&expected));
        memory_and_xstate(&child, &mappings, &xstate);
        assert!(Instant::now() < deadline);
    }
    assert_eq!(walk.steps, 2);
    assert_eq!(child.registers().rip, code.address() + 3);
    child.request(libc::PTRACE_CONT, 0, 0);
    let status = child.wait();
    assert!(Instant::now() < deadline);
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    assert!(child.reaped.get());
    let mut extra = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut extra, libc::WNOHANG | libc::__WALL) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert!(Instant::now() < deadline);
    println!(
        "tree-hardware-stop PASS children=1 stops=2 steps=2 rf_observed={rf_observed} step_tf_bits={step_tf_bits} rf_clear_after_steps=true debug_restored=true state_unchanged=true exit=0 reaped=1 echild=1"
    );
}
