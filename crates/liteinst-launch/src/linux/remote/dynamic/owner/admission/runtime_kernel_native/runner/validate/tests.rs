//! Pure ABI/equality controls, without native binding or outcome authority.
use super::*;

fn state() -> TaskStateSnapshot {
    let mut registers: RegisterSnapshot =
        unsafe { std::mem::zeroed::<libc::user_regs_struct>() }.into();
    registers.rip = 0x400000;
    registers.rsp = 0x800000;
    registers.cs = 0x33;
    registers.ss = 0x2b;
    registers.eflags = 0x202;
    registers.orig_rax = u64::MAX;
    registers.rax = libc::SYS_getpid as u64;
    TaskStateSnapshot {
        registers,
        xstate: vec![0x5a; 832],
        mask: 0x200,
    }
}
fn invalid<T>(result: Result<T, LaunchError>, expected: &'static str) {
    assert!(matches!(result, Err(LaunchError::Invalid(actual)) if actual == expected));
}

#[test]
fn runtime_kernel_projection_keeps_real_orig_rax_rcx_r11_and_flags() {
    let original = state();
    let projected = entry_registers(original.registers, 0x400002, libc::SYS_getpid as u64);
    assert_eq!(
        projected,
        RegisterSnapshot {
            rip: 0x400002,
            rcx: 0x400002,
            r11: 0x202,
            orig_rax: libc::SYS_getpid as u64,
            rax: (-i64::from(libc::ENOSYS)) as u64,
            ..original.registers
        }
    );
    assert_eq!(original.registers.orig_rax, u64::MAX);
    let mut prior = original.registers;
    prior.orig_rax = libc::SYS_gettid as u64;
    prior.eflags |= 0x10000;
    let next = entry_registers(prior, 0x400004, libc::SYS_exit as u64);
    assert_eq!(next.orig_rax, libc::SYS_exit as u64);
    assert_eq!(next.r11, 0x202);
    assert_eq!(next.eflags, 0x202);
    assert_eq!(prior.orig_rax, libc::SYS_gettid as u64);
    // This pure syscall projection does not authorize RF execution: the native
    // state precondition still refuses it before effects.
    let mut invalid_flags = original;
    invalid_flags.registers = prior;
    invalid(
        super::super::require_state(&invalid_flags),
        "runtime kernel state profile differs",
    );
}

#[test]
fn runtime_kernel_full_architecture_comparison_rejects_every_field_change() {
    let before = state();
    let registers = entry_registers(before.registers, 0x400002, libc::SYS_getpid as u64);
    let expected = TaskStateSnapshot {
        registers,
        xstate: before.xstate.clone(),
        mask: before.mask,
    };
    assert!(same_architecture(&expected, registers, &before));
    let mutations: [fn(&mut RegisterSnapshot); 27] = [
        |r| r.r15 ^= 1,
        |r| r.r14 ^= 1,
        |r| r.r13 ^= 1,
        |r| r.r12 ^= 1,
        |r| r.rbp ^= 1,
        |r| r.rbx ^= 1,
        |r| r.r11 ^= 1,
        |r| r.r10 ^= 1,
        |r| r.r9 ^= 1,
        |r| r.r8 ^= 1,
        |r| r.rax ^= 1,
        |r| r.rcx ^= 1,
        |r| r.rdx ^= 1,
        |r| r.rsi ^= 1,
        |r| r.rdi ^= 1,
        |r| r.orig_rax ^= 1,
        |r| r.rip ^= 1,
        |r| r.cs ^= 1,
        |r| r.eflags ^= 1,
        |r| r.rsp ^= 1,
        |r| r.ss ^= 1,
        |r| r.fs_base ^= 1,
        |r| r.gs_base ^= 1,
        |r| r.ds ^= 1,
        |r| r.es ^= 1,
        |r| r.fs ^= 1,
        |r| r.gs ^= 1,
    ];
    for mutate in mutations {
        let mut changed = expected.clone();
        mutate(&mut changed.registers);
        assert!(!same_architecture(&changed, registers, &before));
    }
    for index in [0, expected.xstate.len() - 1] {
        let mut changed = expected.clone();
        changed.xstate[index] ^= 1;
        assert!(!same_architecture(&changed, registers, &before));
    }
    let mut changed = expected.clone();
    changed.xstate.pop();
    assert!(!same_architecture(&changed, registers, &before));
    let mut changed = expected;
    changed.mask ^= 1;
    assert!(!same_architecture(&changed, registers, &before));
}

#[test]
fn runtime_kernel_native_syscall_wait_refuses_signal_event_and_terminal_lookalikes() {
    let status = ((libc::SIGTRAP | 0x80) << 8) | 0x7f;
    syscall_event(42, 42, status).unwrap();
    invalid(
        syscall_event(43, 42, status),
        "runtime kernel expected native syscall stop differs",
    );
    for other in [
        (libc::SIGTRAP << 8) | 0x7f,
        (libc::SIGSEGV << 8) | 0x7f,
        status | (libc::PTRACE_EVENT_EXIT << 16),
        0,
        7 << 8,
        libc::SIGKILL,
    ] {
        invalid(
            syscall_event(42, 42, other),
            "runtime kernel expected native syscall stop differs",
        );
    }
}

#[test]
fn runtime_kernel_state_profile_refuses_debug_flags_mode_and_partial_xstate() {
    let original = state();
    super::super::require_state(&original).unwrap();
    for flags in [0, 0x302, 0x10202] {
        let mut changed = original.clone();
        changed.registers.eflags = flags;
        invalid(
            super::super::require_state(&changed),
            "runtime kernel state profile differs",
        );
    }
    for length in [0, 511, MAX_XSTATE, MAX_XSTATE + 1] {
        let mut changed = original.clone();
        changed.xstate.resize(length, 0);
        invalid(
            super::super::require_state(&changed),
            "runtime kernel state profile differs",
        );
    }
    let mut changed = original;
    changed.registers.cs = 0x23;
    invalid(
        super::super::require_state(&changed),
        "runtime kernel state profile differs",
    );
}
