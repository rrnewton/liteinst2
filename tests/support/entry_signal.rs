// Additive test-only support, included as a child of ordered_trace.
// It witnesses a genuine kernel signal frame and rt_sigreturn. It does not
// publish code while a context is parked and does not claim that lifecycle.
use super::*;

core::arch::global_asm!(
    ".pushsection .text",
    ".global liteinst_entry_signal_handler",
    ".type liteinst_entry_signal_handler,@function",
    "liteinst_entry_signal_handler:",
    "int3",
    ".global liteinst_entry_signal_captured",
    "liteinst_entry_signal_captured:",
    "ret",
    ".size liteinst_entry_signal_handler, .-liteinst_entry_signal_handler",
    ".global liteinst_entry_signal_restorer",
    ".type liteinst_entry_signal_restorer,@function",
    "liteinst_entry_signal_restorer:",
    "mov rax, 15",
    ".global liteinst_entry_signal_syscall",
    "liteinst_entry_signal_syscall:",
    "syscall",
    "ud2",
    ".size liteinst_entry_signal_restorer, .-liteinst_entry_signal_restorer",
    ".popsection",
);

unsafe extern "C" {
    fn liteinst_entry_signal_handler();
    fn liteinst_entry_signal_captured();
    fn liteinst_entry_signal_restorer();
    fn liteinst_entry_signal_syscall();
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

pub struct SignalResume {
    stack: Mapping,
    previous_stack: libc::stack_t,
    previous_action: KernelAction,
    previous_mask: libc::sigset_t,
    captures: Cell<usize>,
}

impl SignalResume {
    /// # Safety
    /// Call only inside the fixture's isolated single-threaded exec child.
    /// SIGUSR1, its alternate stack and disposition must have no other user;
    /// all ptrace descendants must be reaped before this object is dropped.
    pub unsafe fn new() -> Self {
        assert_eq!(libc::SYS_rt_sigreturn, 15);
        let stack = Mapping::new(16 * PAGE);
        stack.initialize(0, &vec![0xa6; 16 * PAGE]);
        let configured = libc::stack_t {
            ss_sp: stack.writable().cast(),
            ss_flags: 0,
            ss_size: 16 * PAGE,
        };
        let mut previous_stack: libc::stack_t = unsafe { core::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaltstack(&configured, &mut previous_stack) },
            0
        );
        let action = KernelAction {
            handler: liteinst_entry_signal_handler as *const () as u64,
            flags: (libc::SA_SIGINFO | libc::SA_ONSTACK) as u64 | 0x0400_0000,
            restorer: liteinst_entry_signal_restorer as *const () as u64,
            mask: 0,
        };
        let mut previous_action = KernelAction {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigaction,
                    libc::SIGUSR1,
                    &action,
                    &mut previous_action,
                    8_usize,
                )
            },
            0
        );
        let mut signal: libc::sigset_t = unsafe { core::mem::zeroed() };
        let mut previous_mask: libc::sigset_t = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { libc::sigemptyset(&mut signal) }, 0);
        assert_eq!(unsafe { libc::sigaddset(&mut signal, libc::SIGUSR1) }, 0);
        assert_eq!(
            unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &signal, &mut previous_mask) },
            0
        );
        Self {
            stack,
            previous_stack,
            previous_action,
            previous_mask,
            captures: Cell::new(0),
        }
    }

    pub fn completed_roundtrips(&self) -> usize {
        self.captures.get()
    }

    fn contains(&self, address: u64, len: usize) -> bool {
        self.stack.address() <= address
            && address
                .checked_add(len as u64)
                .is_some_and(|end| end <= self.stack.address() + 16 * PAGE as u64)
    }

    pub(super) fn resume(&self, oracle: &NativeOracle, child: &Tracee) {
        let before = child.registers();
        let original = oracle.snapshot(child, before.rip, oracle.code.bytes());
        assert_eq!(before.orig_rax, u64::MAX);
        child.request(libc::PTRACE_CONT, 0, libc::SIGUSR1 as usize);
        let status = child.wait();
        assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP);
        let captured = child.registers();
        assert_eq!(
            captured.rip,
            liteinst_entry_signal_captured as *const () as u64
        );
        assert!(self.contains(captured.rsp, 8));
        assert!(self.contains(captured.rdx, core::mem::size_of::<libc::ucontext_t>()));
        assert!(self.contains(captured.rsi, core::mem::size_of::<libc::siginfo_t>()));
        let info = child.memory(captured.rsi, core::mem::size_of::<libc::siginfo_t>());
        assert_eq!(
            i32::from_ne_bytes(info[..4].try_into().unwrap()),
            libc::SIGUSR1
        );
        let bytes = child.memory(captured.rdx, core::mem::size_of::<libc::ucontext_t>());
        let context =
            unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<libc::ucontext_t>()) };
        let g = context.uc_mcontext.gregs;
        for (slot, value) in [
            (libc::REG_RIP, before.rip),
            (libc::REG_RSP, before.rsp),
            (libc::REG_RAX, before.rax),
            (libc::REG_RBX, before.rbx),
            (libc::REG_RCX, before.rcx),
            (libc::REG_RDX, before.rdx),
            (libc::REG_RSI, before.rsi),
            (libc::REG_RDI, before.rdi),
            (libc::REG_RBP, before.rbp),
            (libc::REG_R8, before.r8),
            (libc::REG_R9, before.r9),
            (libc::REG_R10, before.r10),
            (libc::REG_R11, before.r11),
            (libc::REG_R12, before.r12),
            (libc::REG_R13, before.r13),
            (libc::REG_R14, before.r14),
            (libc::REG_R15, before.r15),
        ] {
            assert_eq!(
                g[slot as usize] as u64, value,
                "saved ucontext register {slot}"
            );
        }
        assert_eq!(
            g[libc::REG_EFL as usize] as u64 & !DEBUGGER_FLAGS,
            before.eflags & !DEBUGGER_FLAGS
        );
        assert!(self.contains(context.uc_mcontext.fpregs as u64, 576));
        // From this capture onward no SETREGS/SETREGSET is allowed. The actual
        // handler returns to the explicit kernel restorer, then rt_sigreturn
        // restores the original state. Syscall tracing stops before application
        // execution, independently of the restored TF value.
        child.step(&[]);
        assert_eq!(
            child.registers().rip,
            liteinst_entry_signal_restorer as *const () as u64
        );
        child.step(&[]);
        assert_eq!(
            child.registers().rip,
            liteinst_entry_signal_syscall as *const () as u64
        );
        assert_eq!(child.registers().rax, libc::SYS_rt_sigreturn as u64);
        child.request(
            libc::PTRACE_SETOPTIONS,
            0,
            libc::PTRACE_O_TRACESYSGOOD as usize,
        );
        child.request(libc::PTRACE_SYSCALL, 0, 0);
        let entry = child.wait();
        assert!(libc::WIFSTOPPED(entry) && libc::WSTOPSIG(entry) == (libc::SIGTRAP | 0x80));
        assert_eq!(child.registers().orig_rax, libc::SYS_rt_sigreturn as u64);
        child.request(libc::PTRACE_SYSCALL, 0, 0);
        let exit = child.wait();
        assert!(libc::WIFSTOPPED(exit) && libc::WSTOPSIG(exit) == (libc::SIGTRAP | 0x80));
        assert_eq!(child.registers().rip, before.rip);
        child.request(libc::PTRACE_SETOPTIONS, 0, 0);
        assert_state(
            &original,
            &oracle.snapshot(child, before.rip, oracle.code.bytes()),
        );
        self.captures
            .set(self.captures.get().checked_add(1).unwrap());
    }
}

impl Drop for SignalResume {
    fn drop(&mut self) {
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigaction,
                    libc::SIGUSR1,
                    &self.previous_action,
                    core::ptr::null_mut::<KernelAction>(),
                    8_usize,
                )
            },
            0
        );
        assert_eq!(
            unsafe { libc::sigaltstack(&self.previous_stack, core::ptr::null_mut()) },
            0
        );
        assert_eq!(
            unsafe {
                libc::sigprocmask(
                    libc::SIG_SETMASK,
                    &self.previous_mask,
                    core::ptr::null_mut(),
                )
            },
            0
        );
    }
}
