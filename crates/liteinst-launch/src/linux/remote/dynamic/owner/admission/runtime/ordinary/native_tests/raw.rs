//! Separate pristine lane: actual kernel EXEC/EXIT, one owned entry trap,
//! then direct PTRACE_SINGLESTEP of the literal NOP. No runtime/bootstrap,
//! profile, classifier, census or production permit supplies expected values.
use super::*;

pub(super) struct RawNop {
    before: TaskStateSnapshot,
    after: TaskStateSnapshot,
    original_maps: Vec<u8>,
}
fn stack_pointer(maps: &[u8], pointer: u64) {
    let stack = rows(maps)
        .into_iter()
        .filter(|row| row.raw.ends_with(b"[stack]"))
        .collect::<Vec<_>>();
    assert_eq!(stack.len(), 1);
    assert_eq!(stack[0].permissions, *b"rw-p");
    assert!(stack[0].start <= pointer && pointer < stack[0].end);
}
impl RawNop {
    pub(super) fn compare(
        &self,
        before: &TaskStateSnapshot,
        after: &TaskStateSnapshot,
        maps: &[u8],
    ) {
        let mut raw_expected = self.before.clone();
        raw_expected.registers.rip += 1;
        assert_eq!(self.after, raw_expected);
        let mut expected = before.clone();
        expected.registers.rip += 1;
        assert_eq!(*after, expected);
        stack_pointer(&self.original_maps, self.before.registers.rsp);
        stack_pointer(maps, before.registers.rsp);
        assert_eq!(self.after.registers.rsp, self.before.registers.rsp);
        assert_eq!(after.registers.rsp, before.registers.rsp);
        // Only this independently identified launch-specific stack address may
        // differ across processes. Neither actual operation changes it. Every
        // other register, CS, flags, XSTATE byte and signal-mask bit is exact.
        let mut same_stack_before = self.before.clone();
        same_stack_before.registers.rsp = before.registers.rsp;
        let mut same_stack_after = self.after.clone();
        same_stack_after.registers.rsp = before.registers.rsp;
        assert_eq!(same_stack_before, *before);
        assert_eq!(same_stack_after, *after);
    }
}

pub(super) fn nop(fixture: &Fixture, code: &[u8]) -> RawNop {
    assert_eq!(code[0], 0x90);
    with_owner(
        fixture,
        code,
        |owner, initial, until, original| {
            owner.resume(initial, DynamicResume::Continue).unwrap();
            let (pid, status) = owner.wait_raw(until, "raw ordinary actual EXIT").unwrap();
            assert_eq!(pid, owner.pid);
            assert!(libc::WIFSTOPPED(status));
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP | 0x80);
            assert_eq!(status >> 16, 0);
            assert_eq!(owner.stopped.get(&pid), Some(&status));
            assert!(owner.handles.get(&pid).is_some_and(|pin| !broker::hup(pin)));
            let mut bytes = [0_u8; 88];
            let count = unsafe {
                libc::ptrace(
                    libc::PTRACE_GET_SYSCALL_INFO,
                    pid,
                    bytes.len() as *mut libc::c_void,
                    bytes.as_mut_ptr().cast::<libc::c_void>(),
                )
            };
            assert!((33..=88).contains(&count));
            assert_eq!(size_of::<libc::ptrace_syscall_info>(), bytes.len());
            let info = unsafe {
                std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::ptrace_syscall_info>())
            };
            let exit = state(pid);
            let mut expected = original.state.clone();
            expected.registers.rax = 0;
            assert_eq!(exit, expected);
            assert_eq!(info.op, libc::PTRACE_SYSCALL_INFO_EXIT);
            assert_eq!(info.arch, 0xc000003e);
            assert_eq!(info.instruction_pointer, exit.registers.rip);
            assert_eq!(info.stack_pointer, exit.registers.rsp);
            let returned = unsafe { info.u.exit };
            assert_eq!(returned.sval, 0);
            assert_eq!(returned.is_error, 0);
            let original_word: [u8; 8] = original.source[4096..4104].try_into().unwrap();
            let mut patch = original_word;
            patch[0] = 0xcc;
            owner.time_left(until, "raw ordinary entry patch").unwrap();
            ptrace(
                libc::PTRACE_POKEDATA,
                pid,
                ENTRY as usize,
                u64::from_ne_bytes(patch) as usize,
            )
            .unwrap();
            assert_eq!(memory(pid, ENTRY, 8), patch);
            owner
                .time_left(until, "raw ordinary first-user release")
                .unwrap();
            ptrace(libc::PTRACE_CONT, pid, 0, 0).unwrap();
            owner.released(pid);
            let (tid, status) = owner.wait_raw(until, "raw ordinary first user").unwrap();
            assert_eq!(tid, pid);
            assert!(libc::WIFSTOPPED(status));
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            assert_eq!(status >> 16, 0);
            assert_eq!(owner.stopped.get(&pid), Some(&status));
            assert!(owner.handles.get(&pid).is_some_and(|pin| !broker::hup(pin)));
            let mut signal: libc::siginfo_t = unsafe { std::mem::zeroed() };
            ptrace(libc::PTRACE_GETSIGINFO, pid, 0, (&raw mut signal) as usize).unwrap();
            assert_eq!(signal.si_signo, libc::SIGTRAP);
            assert_eq!(signal.si_errno, 0);
            assert!(matches!(signal.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
            let first = state(pid);
            let mut registers = exit.registers;
            registers.rip = ENTRY + 1;
            registers.orig_rax = u64::MAX;
            assert_eq!(first.registers, registers);
            assert_eq!(first.mask, exit.mask);
            owner
                .time_left(until, "raw ordinary original restoration")
                .unwrap();
            ptrace(
                libc::PTRACE_POKEDATA,
                pid,
                ENTRY as usize,
                u64::from_ne_bytes(original_word) as usize,
            )
            .unwrap();
            let mut before = first;
            before.registers.rip = ENTRY;
            let native: libc::user_regs_struct = before.registers.into();
            ptrace(libc::PTRACE_SETREGS, pid, 0, (&raw const native) as usize).unwrap();
            assert_eq!(state(pid), before);
            assert_eq!(memory(pid, BASE, 8192), original.source);
            assert_eq!(maps(pid), original.maps);
            owner
                .time_left(until, "raw ordinary original NOP release")
                .unwrap();
            ptrace(libc::PTRACE_SINGLESTEP, pid, 0, 0).unwrap();
            owner.released(pid);
            let (tid, status) = owner.wait_raw(until, "raw ordinary actual trace").unwrap();
            assert_eq!(tid, pid);
            assert!(libc::WIFSTOPPED(status));
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            assert_eq!(status >> 16, 0);
            assert_eq!(owner.stopped.get(&pid), Some(&status));
            assert!(owner.handles.get(&pid).is_some_and(|pin| !broker::hup(pin)));
            let mut signal: libc::siginfo_t = unsafe { std::mem::zeroed() };
            ptrace(libc::PTRACE_GETSIGINFO, pid, 0, (&raw mut signal) as usize).unwrap();
            let after = state(pid);
            let mut expected = before.clone();
            expected.registers.rip += 1;
            assert_eq!(after, expected);
            assert_eq!(signal.si_signo, libc::SIGTRAP);
            assert_eq!(signal.si_errno, 0);
            assert_eq!(signal.si_code, libc::TRAP_TRACE);
            assert_eq!(
                unsafe { signal.si_addr() } as usize as u64,
                after.registers.rip
            );
            let offset = std::mem::offset_of!(libc::user, u_debugreg) + 6 * size_of::<u64>();
            unsafe {
                *libc::__errno_location() = 0;
            }
            let dr6 = unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, pid, offset, 0) };
            assert_eq!(unsafe { *libc::__errno_location() }, 0);
            assert_eq!(dr6 as u64, 0xffff_4ff0);
            assert_eq!(memory(pid, BASE, 8192), original.source);
            assert_eq!(maps(pid), original.maps);
            original.stack_unchanged(owner, until);
            assert!(
                owner.runtime.is_none() && owner.lifecycle.is_none() && owner.admission.is_none()
            );
            owner
                .time_left(until, "raw ordinary observation complete")
                .unwrap();
            RawNop {
                before,
                after,
                original_maps: original.maps.clone(),
            }
        },
        |owner, _| {
            assert!(
                owner.runtime.is_none() && owner.lifecycle.is_none() && owner.admission.is_none()
            );
        },
    )
}
