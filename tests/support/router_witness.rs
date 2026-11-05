// Shared bounded witness for the actual private production router.
// Moving these bodies does not change their budget or delivery checks.
use super::*;
use liteinst::contracts::EntryRoute;

// Implemented only inside entry_router::imp's cfg(test) child. The counter
// coordinate is read from the stopped child, never dereferenced in the parent.
pub trait Router: Sized {
    fn prepare();
    fn verify();
    fn stage(routes: &[EntryRoute]) -> Self;
    fn counter_address(&self) -> u64;
    fn deactivate(&self);
    fn assert_active(&self);
}
pub(super) struct Budget { pub(super) used: usize }
impl Budget {
    pub(super) fn charge(&mut self, child: &Tracee, count: usize) {
        self.used = self.used.checked_add(count).unwrap();
        assert!(self.used <= MAX_STEPS, "native instruction budget exhausted");
        assert!(Instant::now() < child.deadline, "native wall budget exhausted");
    }
    pub(super) fn step(&mut self, child: &Tracee) {
        self.charge(child, 1); child.step(&[]);
    }
}
pub(super) fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset+8].try_into().unwrap())
}
pub(super) fn counter(child: &Tracee, address: u64) -> u64 { word(&child.memory(address, 8), 0) }
pub(super) fn trap(child: &Tracee, signal: i32) {
    let status = child.wait();
    assert!(libc::WIFSTOPPED(status), "owned tracee exited: {status:#x}");
    assert_eq!(libc::WSTOPSIG(status), signal);
}
pub(super) fn deliver(child: &Tracee, budget: &mut Budget, route: EntryRoute, counter_address: u64, before: u64) {
    assert_eq!(child.registers().rip, route.original);
    assert_eq!(counter(child,counter_address), before);
    budget.charge(child, 1);
    child.request(libc::PTRACE_SINGLESTEP, 0, 0); trap(child, libc::SIGILL);
    assert_eq!(child.registers().rip, route.original);
    // SAFETY: initialized native output for this stopped tracee's synchronous #UD.
    let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
    child.request(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
    assert_eq!((info.si_signo, info.si_code), (libc::SIGILL, 2));
    assert_eq!(unsafe { info.si_addr() } as usize as u64, route.original);
    budget.charge(child, 1);
    child.request(libc::PTRACE_SINGLESTEP, 0, libc::SIGILL as usize); trap(child, libc::SIGTRAP);
    // Step the actual production handler and its actual libc restorer. No PC
    // setter, injected context, synthetic delivery, or inferred receipt exists.
    loop {
        let registers = child.registers();
        if registers.rax == libc::SYS_rt_sigreturn as u64 && child.memory(registers.rip, 2) == [0x0f,0x05] {
            child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_TRACESYSGOOD as usize);
            budget.charge(child, 1);
            child.request(libc::PTRACE_SYSCALL, 0, 0); trap(child, libc::SIGTRAP | 0x80);
            assert_eq!(child.registers().orig_rax, libc::SYS_rt_sigreturn as u64);
            child.request(libc::PTRACE_SYSCALL, 0, 0); trap(child, libc::SIGTRAP | 0x80);
            child.request(libc::PTRACE_SETOPTIONS, 0, 0);
            assert_eq!(child.registers().rip, route.generated);
            assert_eq!(counter(child,counter_address), before+1, "child handler receipt after this exact delivery");
            return;
        }
        assert_ne!(registers.rip, route.generated, "route destination without witnessed rt_sigreturn");
        budget.step(child);
    }
}
pub(super) fn finish(child: &Tracee) {
    // SAFETY: exact still-owned traced child; Drop retains its existing 2s cleanup.
    assert_eq!(unsafe { libc::kill(child.pid, libc::SIGKILL) }, 0);
    let status=child.wait();
    assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status)==libc::SIGKILL && child.reaped.get());
}
pub(super) fn assert_hook_context(oracle: &NativeOracle, state: liteinst::trampoline::SavedExtendedStateLayout, hook: u64, child: &Tracee, expected: &Snapshot, returned: u64) {
    let r=child.registers(); let e=&expected.registers;
    assert_eq!(r.rip,hook); assert_eq!(r.rsp%16,8);
    let reserve=oracle.initial_rsp-128;
    assert!(r.rsp>=oracle.stack.address()+PAGE as u64 && r.rsp+8<=reserve);
    assert_eq!(word(&child.memory(r.rsp,8),0),returned);
    assert!(r.rdi>=oracle.stack.address()+PAGE as u64 && r.rdi+176<=reserve);
    let c=child.memory(r.rdi,176);
    let words=[expected.logical_pc,e.rsp,e.r15,e.r14,e.r13,e.r12,e.r11,e.r10,e.r9,e.r8,e.rdi,e.rsi,e.rbp,e.rbx,e.rdx,e.rcx,e.rax];
    for (i,&value) in words.iter().enumerate() { assert_eq!(word(&c,i*8),value); }
    assert_eq!(word(&c,136)&!DEBUGGER_FLAGS,e.eflags&!DEBUGGER_FLAGS);
    let address=word(&c,144); assert_eq!(address%64,0);
    assert_eq!((word(&c,152),word(&c,160),word(&c,168)),(state.len(),state.mask(),state.format().raw()));
    assert!(address>=oracle.stack.address()+PAGE as u64 && address+state.len()<=r.rdi);
    let bytes=child.memory(address,state.len() as usize);
    assert_eq!(canonical_xstate(&bytes[..state.image_len() as usize]),expected.xstate);
}
