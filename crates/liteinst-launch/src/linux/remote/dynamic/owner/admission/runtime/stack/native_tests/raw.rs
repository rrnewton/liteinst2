//! Independent raw lane: authentic EXEC/EXIT and entry INT3 restoration, then
//! PTRACE_SINGLESTEP. No runtime classifier, profile, census or native seal
//! supplies its expected state. Each lane keeps its own absolute stack address.
use super::*;

#[derive(Clone)]
pub(super) struct Step {
    pub(super) before: TaskStateSnapshot,
    pub(super) after: TaskStateSnapshot,
    pub(super) stack_before: Vec<u8>,
    pub(super) stack_after: Vec<u8>,
    pub(super) stack_start: u64,
    pub(super) signal: (i32, i32, i32, u64),
    pub(super) maps: Vec<u8>,
}
pub(super) struct Pair {
    pub(super) call: Step,
    pub(super) ret: Step,
}
fn request(operation: u32, pid: i32, address: usize, data: usize) -> NativeRequest {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let result = unsafe { libc::ptrace(operation, pid, address, data) };
    let error = unsafe { *libc::__errno_location() };
    NativeRequest {
        result,
        errno: (result == -1 && error != 0).then_some(error),
    }
}
pub(super) fn checked(operation: u32, pid: i32, address: usize, data: usize) {
    let observed = request(operation, pid, address, data);
    assert_eq!(
        observed,
        NativeRequest {
            result: 0,
            errno: None
        }
    );
}
pub(super) fn wait(owner: &mut Owner, until: Instant, signal: i32) -> i32 {
    let (pid, status) = owner.wait_raw(until, "independent stack raw wait").unwrap();
    assert_eq!(pid, owner.pid);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), signal);
    assert_eq!(status >> 16, 0);
    assert_eq!(owner.stopped.get(&pid), Some(&status));
    support::held(owner, until);
    status
}
pub(super) fn first(
    owner: &mut Owner,
    initial: &DynamicStop,
    until: Instant,
    original: &Before,
    entry: u64,
) -> TaskStateSnapshot {
    owner.resume(initial, DynamicResume::Continue).unwrap();
    wait(owner, until, libc::SIGTRAP | 0x80);
    let mut raw = [0_u8; 88];
    let result = request(
        libc::PTRACE_GET_SYSCALL_INFO,
        owner.pid,
        raw.len(),
        raw.as_mut_ptr() as usize,
    );
    assert_eq!(result.errno, None);
    assert!((33..=88).contains(&result.result));
    assert_eq!(size_of::<libc::ptrace_syscall_info>(), 88);
    let info =
        unsafe { std::ptr::read_unaligned(raw.as_ptr().cast::<libc::ptrace_syscall_info>()) };
    let exit = state(owner.pid);
    let mut expected = original.state.clone();
    expected.registers.rax = 0;
    assert_eq!(exit, expected);
    assert_eq!(info.op, libc::PTRACE_SYSCALL_INFO_EXIT);
    assert_eq!(info.arch, 0xc000003e);
    assert_eq!(info.instruction_pointer, entry);
    assert_eq!(info.stack_pointer, exit.registers.rsp);
    let returned = unsafe { info.u.exit };
    assert_eq!(returned.sval, 0);
    assert_eq!(returned.is_error, 0);
    let offset = usize::try_from(entry - BASE).unwrap();
    let original_word: [u8; 8] = original.source[offset..offset + 8].try_into().unwrap();
    let mut patch = original_word;
    patch[0] = 0xcc;
    checked(
        libc::PTRACE_POKEDATA,
        owner.pid,
        entry as usize,
        u64::from_ne_bytes(patch) as usize,
    );
    assert_eq!(memory(owner.pid, entry, 8), patch);
    checked(libc::PTRACE_CONT, owner.pid, 0, 0);
    owner.released(owner.pid);
    wait(owner, until, libc::SIGTRAP);
    let signal = signal(owner.pid);
    assert_eq!(signal.0, libc::SIGTRAP);
    assert_eq!(signal.1, 0);
    assert!(matches!(signal.2, libc::SI_KERNEL | libc::TRAP_BRKPT));
    let first = state(owner.pid);
    let mut registers = exit.registers;
    registers.rip = entry + 1;
    registers.orig_rax = u64::MAX;
    assert_eq!(first.registers, registers);
    assert_eq!(first.mask, exit.mask);
    checked(
        libc::PTRACE_POKEDATA,
        owner.pid,
        entry as usize,
        u64::from_ne_bytes(original_word) as usize,
    );
    let mut before = first;
    before.registers.rip = entry;
    let regs: libc::user_regs_struct = before.registers.into();
    checked(
        libc::PTRACE_SETREGS,
        owner.pid,
        0,
        (&raw const regs) as usize,
    );
    assert_eq!(state(owner.pid), before);
    assert_eq!(maps(owner.pid), original.maps);
    original.require_source(owner, until);
    before
}
pub(super) fn signal(pid: i32) -> (i32, i32, i32, u64) {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    checked(libc::PTRACE_GETSIGINFO, pid, 0, (&raw mut info) as usize);
    (
        info.si_signo,
        info.si_errno,
        info.si_code,
        unsafe { info.si_addr() } as usize as u64,
    )
}
pub(super) fn step(
    owner: &mut Owner,
    until: Instant,
    original: &Before,
    expected_signal: i32,
) -> Step {
    let before = state(owner.pid);
    let stack_before = original.read_stack(owner, until);
    checked(libc::PTRACE_SINGLESTEP, owner.pid, 0, 0);
    owner.released(owner.pid);
    wait(owner, until, expected_signal);
    let signal = signal(owner.pid);
    let after = state(owner.pid);
    let stack_after = original.read_stack(owner, until);
    original.require_source(owner, until);
    assert_eq!(maps(owner.pid), original.maps);
    Step {
        before,
        after,
        stack_before,
        stack_after,
        stack_start: original.stack_range.start,
        signal,
        maps: original.maps.clone(),
    }
}
pub(super) fn pair(program: &Program) -> Pair {
    support::with_owner(
        program,
        true,
        |owner, initial, until, original| {
            let mut before = first(owner, initial, until, original, program.entry);
            for ordinal in 0..program.setup {
                let observed = step(owner, until, original, libc::SIGTRAP);
                assert_eq!(observed.before, before);
                let expected = compare::setup(&before, ordinal);
                assert_eq!(observed.after, expected);
                assert_eq!(observed.signal.2, libc::TRAP_TRACE);
                assert_eq!(observed.stack_after, observed.stack_before);
                before = expected;
            }
            assert_eq!(before.registers.rip, program.call_pc);
            let call = step(owner, until, original, libc::SIGTRAP);
            compare::raw_step(&call, program.call_pc, program.target, program.next, true);
            let ret = step(owner, until, original, libc::SIGTRAP);
            compare::raw_step(
                &ret,
                program.target,
                program.next,
                program.target + 1,
                false,
            );
            assert_eq!(call.after, ret.before);
            assert_eq!(call.stack_after, ret.stack_before);
            Pair { call, ret }
        },
        |_, _| {},
    )
}

/// Test-fixture-only kernel setup. Actual number/arguments and ENTRY/EXIT are
/// observed; original code, complete registers/XSTATE/mask are restored before
/// interpreting metadata. This is never a runtime-admitted syscall claim.
pub(super) fn syscall(owner: &mut Owner, until: Instant, number: u64, args: [u64; 6]) -> i64 {
    support::held(owner, until);
    let before = state(owner.pid);
    let site = BASE + 0x1e00;
    let saved: [u8; 8] = memory(owner.pid, site, 8).try_into().unwrap();
    let mut patch = saved;
    patch[..2].copy_from_slice(&[0x0f, 0x05]);
    checked(
        libc::PTRACE_POKEDATA,
        owner.pid,
        site as usize,
        u64::from_ne_bytes(patch) as usize,
    );
    let mut regs = before.registers;
    regs.rip = site;
    regs.rax = number;
    regs.orig_rax = u64::MAX;
    [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9] = args;
    let native: libc::user_regs_struct = regs.into();
    checked(
        libc::PTRACE_SETREGS,
        owner.pid,
        0,
        (&raw const native) as usize,
    );
    for phase in [
        libc::PTRACE_SYSCALL_INFO_ENTRY,
        libc::PTRACE_SYSCALL_INFO_EXIT,
    ] {
        checked(libc::PTRACE_SYSCALL, owner.pid, 0, 0);
        owner.released(owner.pid);
        wait(owner, until, libc::SIGTRAP | 0x80);
        let mut raw = [0_u8; 88];
        let result = request(
            libc::PTRACE_GET_SYSCALL_INFO,
            owner.pid,
            88,
            raw.as_mut_ptr() as usize,
        );
        assert_eq!(result.errno, None);
        assert!((33..=88).contains(&result.result));
        let info =
            unsafe { std::ptr::read_unaligned(raw.as_ptr().cast::<libc::ptrace_syscall_info>()) };
        assert_eq!(info.op, phase);
        assert_eq!(info.arch, 0xc000003e);
        assert_eq!(info.instruction_pointer, site + 2);
        if phase == libc::PTRACE_SYSCALL_INFO_ENTRY {
            assert!(result.result >= 80);
            let entry = unsafe { info.u.entry };
            assert_eq!(entry.nr, number);
            assert_eq!(entry.args, args);
        }
    }
    let result = state(owner.pid).registers.rax as i64;
    checked(
        libc::PTRACE_POKEDATA,
        owner.pid,
        site as usize,
        u64::from_ne_bytes(saved) as usize,
    );
    let restore: libc::user_regs_struct = before.registers.into();
    checked(
        libc::PTRACE_SETREGS,
        owner.pid,
        0,
        (&raw const restore) as usize,
    );
    let vector = libc::iovec {
        iov_base: before.xstate.as_ptr().cast_mut().cast(),
        iov_len: before.xstate.len(),
    };
    checked(
        libc::PTRACE_SETREGSET,
        owner.pid,
        NT_X86_XSTATE,
        (&raw const vector) as usize,
    );
    checked(
        libc::PTRACE_SETSIGMASK,
        owner.pid,
        8,
        (&raw const before.mask) as usize,
    );
    assert_eq!(state(owner.pid), before);
    assert_eq!(memory(owner.pid, site, 8), saved);
    support::held(owner, until);
    result
}

/// Actual fork with both parent event and newborn initial stop consumed and
/// pinned. Neither task returns to userspace after sharing the stack page.
pub(super) fn fork_held(owner: &mut Owner, until: Instant) -> [(i32, i32); 2] {
    support::held(owner, until);
    let parent = owner.pid;
    let before = state(parent);
    let site = BASE + 0x1e00;
    let saved: [u8; 8] = memory(parent, site, 8).try_into().unwrap();
    let mut patch = saved;
    patch[..2].copy_from_slice(&[0x0f, 0x05]);
    checked(
        libc::PTRACE_POKEDATA,
        parent,
        site as usize,
        u64::from_ne_bytes(patch) as usize,
    );
    let mut regs = before.registers;
    regs.rip = site;
    regs.rax = libc::SYS_fork as u64;
    regs.orig_rax = u64::MAX;
    let native: libc::user_regs_struct = regs.into();
    checked(
        libc::PTRACE_SETREGS,
        parent,
        0,
        (&raw const native) as usize,
    );
    checked(libc::PTRACE_SYSCALL, parent, 0, 0);
    owner.released(parent);
    wait(owner, until, libc::SIGTRAP | 0x80);
    let mut info = [0_u8; 88];
    let received = request(
        libc::PTRACE_GET_SYSCALL_INFO,
        parent,
        88,
        info.as_mut_ptr() as usize,
    );
    assert_eq!(received.errno, None);
    assert!((80..=88).contains(&received.result));
    let entry =
        unsafe { std::ptr::read_unaligned(info.as_ptr().cast::<libc::ptrace_syscall_info>()) };
    assert_eq!(entry.op, libc::PTRACE_SYSCALL_INFO_ENTRY);
    assert_eq!(unsafe { entry.u.entry }.nr, libc::SYS_fork as u64);
    checked(libc::PTRACE_SYSCALL, parent, 0, 0);
    owner.released(parent);
    let mut parent_stop = None;
    let mut child_stop = None;
    let mut announced = None;
    while parent_stop.is_none() || child_stop.is_none() {
        let (tid, status) = owner
            .wait_raw(until, "raw stack actual fork custody")
            .unwrap();
        assert!(libc::WIFSTOPPED(status));
        if tid == parent {
            assert_eq!(status >> 16, libc::PTRACE_EVENT_FORK);
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            let mut child = 0_u64;
            checked(
                libc::PTRACE_GETEVENTMSG,
                parent,
                0,
                (&raw mut child) as usize,
            );
            let child = i32::try_from(child).unwrap();
            assert!(child > 0 && child != parent);
            announced = Some(child);
            owner.discover_event_child(tid, status);
            owner.pin_process(child).unwrap();
            parent_stop = Some(status);
        } else {
            assert!(child_stop.is_none());
            assert_eq!(status >> 16, libc::PTRACE_EVENT_STOP);
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            owner.pin_process(tid).unwrap();
            child_stop = Some((tid, status));
        }
    }
    let child = child_stop.unwrap();
    assert_eq!(announced, Some(child.0));
    assert_eq!(owner.owned.len(), 2);
    [(parent, parent_stop.unwrap()), child]
}
