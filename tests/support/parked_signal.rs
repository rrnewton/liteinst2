// Private additive support. This closed fixture does not make the publisher
// generally async-signal-safe. See DESIGN.md for its actual-frame gate proof.
use super::*;
use liteinst2::contracts::{
    AddressRange, FailureStage, PlanKind, QuiescenceLease, Refusal, ResumeObligation,
};
use liteinst2::quiescent::PlannedInstall;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

const STACK_LEN: usize = 16 * PAGE;
const RECORD_WORDS: usize = 12;
const MAGIC: u64 = 0x5041_524b_4544_3031;
static ACTIVE: AtomicPtr<ParkedPublication> = AtomicPtr::new(core::ptr::null_mut());

core::arch::global_asm!(
    ".pushsection .text",
    ".global liteinst_parked_handler",
    ".type liteinst_parked_handler,@function",
    "liteinst_parked_handler:",
    "int3",
    ".global liteinst_parked_captured",
    "liteinst_parked_captured:",
    "sub rsp, 8",
    "mov rdi, rdx",
    "call liteinst_parked_publish",
    "int3",
    ".global liteinst_parked_published",
    "liteinst_parked_published:",
    "test rax, rax",
    "jne 2f",
    "add rsp, 8",
    "ret",
    "2: ud2",
    "jmp 2b",
    ".size liteinst_parked_handler, .-liteinst_parked_handler",
    ".global liteinst_parked_restorer",
    ".type liteinst_parked_restorer,@function",
    "liteinst_parked_restorer:",
    "mov rax, 15",
    ".global liteinst_parked_syscall",
    "liteinst_parked_syscall:",
    "syscall",
    "ud2",
    ".size liteinst_parked_restorer, .-liteinst_parked_restorer",
    ".popsection",
);

unsafe extern "C" {
    fn liteinst_parked_handler();
    fn liteinst_parked_captured();
    fn liteinst_parked_published();
    fn liteinst_parked_restorer();
    fn liteinst_parked_syscall();
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[repr(C)]
struct PublicationRecord {
    words: [AtomicU64; RECORD_WORDS],
}
impl PublicationRecord {
    fn new() -> Self {
        Self {
            words: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
    fn store(&self, index: usize, value: u64) {
        self.words[index].store(value, Ordering::Release);
    }
    fn address(&self) -> u64 {
        self as *const Self as u64
    }
}

/// The real signal frame and the handler's success-only return path own this
/// continuation. This is not an unrelated exclusion token or a Boolean lock.
struct ParkedFrameGuard {
    context: *mut libc::ucontext_t,
    saved_pc: u64,
}

pub struct ParkedPublication {
    plan: PlannedInstall,
    source: AddressRange,
    before: Vec<u8>,
    after: Vec<u8>,
    stack: Mapping,
    previous_stack: libc::stack_t,
    previous_action: KernelAction,
    previous_mask: libc::sigset_t,
    record: Box<PublicationRecord>,
    roundtrips: Cell<usize>,
}

pub(super) struct ActivePublication<'a> {
    fixture: &'a ParkedPublication,
}
impl Drop for ActivePublication<'_> {
    fn drop(&mut self) {
        let pointer = self.fixture as *const ParkedPublication as *mut ParkedPublication;
        assert_eq!(
            ACTIVE.compare_exchange(
                pointer,
                core::ptr::null_mut(),
                Ordering::AcqRel,
                Ordering::Acquire
            ),
            Ok(pointer)
        );
    }
}

fn permissions(address: u64, flags: i32) -> Result<(), Refusal> {
    if unsafe { libc::mprotect(address as *mut libc::c_void, PAGE, flags) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn liteinst_parked_publish(context: *mut libc::ucontext_t) -> u64 {
    let pointer = ACTIVE.load(Ordering::Acquire);
    assert!(!pointer.is_null());
    // This exact pointer was installed before fork and remains live until the
    // owned child is reaped. The callee runs only below the held real frame.
    let fixture = unsafe { &*pointer };
    fixture.publish_in_child(context)
}

impl ParkedPublication {
    /// # Safety
    /// Isolated sequential exec fixture only. No other signal/altstack user or
    /// lock holder may race fork; the child interrupts only seeded handwritten
    /// code, owns one execution thread and cannot return before the receipt.
    /// All descendants must be reaped before this fixture or its plan drops.
    pub unsafe fn new(plan: &PlannedInstall, code: &Mapping) -> Self {
        assert_eq!(code.len, PAGE);
        assert_eq!(core::mem::size_of::<PublicationRecord>(), RECORD_WORDS * 8);
        assert_eq!(plan.plan().parts().kind, PlanKind::Relocation);
        plan.plan().check_entry_obligations().unwrap();
        let source = AddressRange::new(code.address(), PAGE).unwrap();
        let parts = plan.plan().parts();
        assert_eq!(parts.physical_pc, source.start());
        assert_eq!(
            parts.displaced,
            AddressRange::new(source.start(), 5).unwrap()
        );
        assert_eq!(parts.writes.len(), 1);
        assert_eq!(parts.writes[0].address, source.start());
        assert_eq!(parts.writes[0].bytes.len(), 5);
        assert!(
            parts.requirements.quiescent
                && parts.requirements.sync_core
                && parts.requirements.sigill_router
        );
        assert!(matches!(
            parts.entries.resumes,
            ResumeObligation::Enumerated(_)
        ));
        assert!(parts.dependencies.iter().all(|range| source.covers(*range)));
        let before = code.bytes().to_vec();
        for read in &parts.reads {
            let offset =
                usize::try_from(read.address.checked_sub(source.start()).unwrap()).unwrap();
            assert_eq!(&before[offset..offset + read.bytes.len()], read.bytes);
        }
        let mut after = before.clone();
        for edit in &parts.writes {
            let offset =
                usize::try_from(edit.address.checked_sub(source.start()).unwrap()).unwrap();
            after[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
        assert_ne!(before, after);
        assert_eq!(parts.generated.len(), 1);
        assert_eq!(parts.generated[0].address, plan.image().address());
        assert_eq!(parts.generated[0].bytes, plan.image().bytes());
        assert_eq!(parts.allocations.len(), 1);
        assert!(parts.allocations[0].range.len() <= 8192);
        let stack = Mapping::new(STACK_LEN);
        stack.initialize(0, &vec![0xa6; STACK_LEN]);
        let configured = libc::stack_t {
            ss_sp: stack.writable().cast(),
            ss_flags: 0,
            ss_size: STACK_LEN,
        };
        let mut previous_stack: libc::stack_t = unsafe { core::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaltstack(&configured, &mut previous_stack) },
            0
        );
        let action = KernelAction {
            handler: liteinst_parked_handler as *const () as u64,
            flags: (libc::SA_SIGINFO | libc::SA_ONSTACK) as u64 | 0x0400_0000,
            restorer: liteinst_parked_restorer as *const () as u64,
            // SIGILL must remain unblocked for router preparation/verification.
            mask: !(1_u64 << (libc::SIGILL - 1)),
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
        let mut signals: libc::sigset_t = unsafe { core::mem::zeroed() };
        let mut previous_mask: libc::sigset_t = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { libc::sigemptyset(&mut signals) }, 0);
        for signal in [libc::SIGUSR1, libc::SIGILL] {
            assert_eq!(unsafe { libc::sigaddset(&mut signals, signal) }, 0);
        }
        assert_eq!(
            unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &signals, &mut previous_mask) },
            0
        );
        Self {
            plan: plan.clone(),
            source,
            before,
            after,
            stack,
            previous_stack,
            previous_action,
            previous_mask,
            record: Box::new(PublicationRecord::new()),
            roundtrips: Cell::new(0),
        }
    }

    pub(super) fn activate(&self) -> ActivePublication<'_> {
        let pointer = self as *const Self as *mut Self;
        assert_eq!(
            ACTIVE.compare_exchange(
                core::ptr::null_mut(),
                pointer,
                Ordering::AcqRel,
                Ordering::Acquire
            ),
            Ok(core::ptr::null_mut())
        );
        ActivePublication { fixture: self }
    }

    pub fn completed_roundtrips(&self) -> usize {
        self.roundtrips.get()
    }
    pub(super) fn expected_source(&self) -> &[u8] {
        &self.after
    }
    fn contains(&self, address: u64, len: usize) -> bool {
        self.stack.address() <= address
            && address
                .checked_add(len as u64)
                .is_some_and(|end| end <= self.stack.address() + STACK_LEN as u64)
    }

    fn publish_in_child(&self, context: *mut libc::ucontext_t) -> u64 {
        assert!(self.contains(context as u64, core::mem::size_of::<libc::ucontext_t>()));
        let saved = unsafe { core::ptr::read_unaligned(context) };
        let saved_pc = saved.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
        let ResumeObligation::Enumerated(resumes) = &self.plan.plan().parts().entries.resumes
        else {
            unreachable!()
        };
        assert!(resumes.contains(&saved_pc));
        assert_eq!(self.record.words[2].fetch_add(1, Ordering::AcqRel), 0);
        let mut guard = ParkedFrameGuard { context, saved_pc };
        assert_eq!(guard.context, context);
        assert_eq!(guard.saved_pc, saved_pc);
        // Actual exclusion: this is the sole execution thread, its saved
        // application continuation is held above this handler stack, other
        // signal reentry is blocked, and assembly permits no failure return.
        let mut lease = unsafe {
            QuiescenceLease::new(
                &mut guard,
                self.plan.plan().parts().identity,
                vec![self.source],
            )
        };
        self.record.store(0, MAGIC);
        self.record.store(9, context as u64);
        if permissions(self.source.start(), libc::PROT_READ | libc::PROT_WRITE).is_err() {
            self.record.store(8, 1);
            self.record.store(1, 2);
            return 1;
        }
        let result = unsafe {
            self.plan
                .publish_with(self.source.start() as *mut u8, &mut lease, || {
                    permissions(self.source.start(), libc::PROT_READ | libc::PROT_EXEC)
                })
        };
        match result {
            Ok((installed, receipt)) => {
                assert_eq!(receipt.plan(), self.plan.plan());
                assert!(!lease.is_poisoned());
                assert_eq!(installed.plan(), self.plan.plan());
                assert_eq!(
                    installed.trampoline().address(),
                    self.plan.image().address()
                );
                let identity = receipt.plan().parts().identity;
                self.record.store(3, identity.mapping);
                self.record.store(4, identity.generation);
                self.record.store(5, receipt.plan().parts().physical_pc);
                self.record.store(6, installed.trampoline().address());
                self.record.store(7, self.plan.image().bytes().len() as u64);
                // Exactly one bounded retained handle per trace process. It
                // cannot drop/deactivate routing before the frame resumes.
                self.record
                    .store(10, Box::into_raw(Box::new(installed)) as u64);
                self.record.store(11, u64::from(lease.is_poisoned()));
                drop(lease);
                self.record.store(8, 3);
                self.record.store(1, 1);
                0
            }
            Err(failure) => {
                self.record.store(
                    8,
                    match failure.stage {
                        FailureStage::BeforeWrite => 1,
                        FailureStage::KeepGated => 2,
                        FailureStage::RolledBack => 4,
                    },
                );
                self.record.store(11, u64::from(lease.is_poisoned()));
                self.record.store(1, 2);
                // The actual frame remains gated by assembly; failure can
                // only trap/terminate, including after this lease is dropped.
                1
            }
        }
    }

    fn record(&self, child: &Tracee) -> Vec<u64> {
        child
            .memory(self.record.address(), RECORD_WORDS * 8)
            .chunks_exact(8)
            .map(|bytes| u64::from_ne_bytes(bytes.try_into().unwrap()))
            .collect()
    }

    fn assert_rx(child: &Tracee, range: AddressRange) {
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", child.pid)).unwrap();
        let mut next = range.start();
        for line in maps.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            let (start, end) = fields[0].split_once('-').unwrap();
            let (start, end) = (
                u64::from_str_radix(start, 16).unwrap(),
                u64::from_str_radix(end, 16).unwrap(),
            );
            if start <= next && next < end {
                assert_eq!(&fields[1][..3], "r-x", "source/image mapping permissions");
                next = end.min(range.end());
                if next == range.end() {
                    return;
                }
            }
        }
        panic!("incomplete source/image RX mapping coverage");
    }

    pub(super) fn publish_and_resume(
        &self,
        oracle: &NativeOracle,
        child: &Tracee,
        log: &HookEventLog,
    ) {
        assert_eq!(
            std::fs::read_dir(format!("/proc/{}/task", child.pid))
                .unwrap()
                .map(Result::unwrap)
                .count(),
            1
        );
        assert_eq!(oracle.code.address(), self.source.start());
        assert_eq!(oracle.code.bytes(), self.before);
        let before = child.registers();
        assert_eq!(before.orig_rax, u64::MAX);
        let original = oracle.snapshot(child, before.rip, &self.before);
        assert_eq!(self.record(child), vec![0; RECORD_WORDS]);
        log.assert_events(child, &[]);
        child.request(libc::PTRACE_CONT, 0, libc::SIGUSR1 as usize);
        let stop = child.wait();
        assert!(libc::WIFSTOPPED(stop) && libc::WSTOPSIG(stop) == libc::SIGTRAP);
        let captured = child.registers();
        assert_eq!(captured.rip, liteinst_parked_captured as *const () as u64);
        assert_eq!(child.memory(self.source.start(), PAGE), self.before);
        assert_eq!(self.record(child), vec![0; RECORD_WORDS]);
        assert!(self.contains(captured.rsp, 8));
        assert_eq!(captured.rsp % 16, 8, "handler call alignment prerequisite");
        assert_eq!(
            captured.eflags & (1 << 10),
            0,
            "live handler DF must be clear before its Rust call"
        );
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
            assert_eq!(context.uc_mcontext.gregs[slot as usize] as u64, value);
        }
        assert_eq!(
            context.uc_mcontext.gregs[libc::REG_EFL as usize] as u64 & !DEBUGGER_FLAGS,
            before.eflags & !DEBUGGER_FLAGS
        );
        assert_eq!(
            u64::from_ne_bytes(child.memory(captured.rsp, 8).try_into().unwrap()),
            liteinst_parked_restorer as *const () as u64
        );
        let fp = context.uc_mcontext.fpregs as u64;
        assert!(self.contains(fp, 512));
        let sw = child.memory(fp + 464, 48);
        assert_eq!(u32::from_le_bytes(sw[..4].try_into().unwrap()), 0x4650_5853);
        let extent = u32::from_le_bytes(sw[4..8].try_into().unwrap()) as usize;
        let xstate_size = u32::from_le_bytes(sw[16..20].try_into().unwrap()) as usize;
        assert!(xstate_size >= 576 && extent == xstate_size.checked_add(4).unwrap());
        assert!(self.contains(fp, extent));
        assert_eq!(
            u32::from_le_bytes(child.memory(fp + extent as u64 - 4, 4).try_into().unwrap()),
            0x4650_5845
        );
        let frame_end = [
            captured.rsp + 8,
            captured.rdx + bytes.len() as u64,
            captured.rsi + info.len() as u64,
            fp + extent as u64,
        ]
        .into_iter()
        .max()
        .unwrap();
        assert!(captured.rdx >= captured.rsp && captured.rsi >= captured.rsp && fp >= captured.rsp);
        let frame_len = usize::try_from(frame_end - captured.rsp).unwrap();
        assert!(self.contains(captured.rsp, frame_len));
        let frame = child.memory(captured.rsp, frame_len);

        // No ptrace/register/memory write after this point. The real handler
        // performs an ordinary CALL; source publication occurs only in child.
        child.request(libc::PTRACE_CONT, 0, 0);
        let published = child.wait();
        assert!(libc::WIFSTOPPED(published) && libc::WSTOPSIG(published) == libc::SIGTRAP);
        assert_eq!(
            std::fs::read_dir(format!("/proc/{}/task", child.pid))
                .unwrap()
                .map(Result::unwrap)
                .count(),
            1
        );
        assert_eq!(
            child.registers().rip,
            liteinst_parked_published as *const () as u64
        );
        assert_eq!(child.registers().rax, 0, "publisher did not return success");
        // Publication itself must not substitute a callback for later application execution.
        // This checks the complete log page, including unused storage and overflow.
        log.assert_events(child, &[]);
        assert_frame(&frame, &child.memory(captured.rsp, frame_len));
        let record = self.record(child);
        assert_receipt(
            &record,
            self.plan.plan().parts().identity.mapping,
            self.plan.plan().parts().identity.generation,
            self.source.start(),
            self.plan.image().address(),
            self.plan.image().bytes().len() as u64,
            captured.rdx,
        );
        assert_source(&self.after, &child.memory(self.source.start(), PAGE));
        Self::assert_rx(child, self.source);
        let allocation = self.plan.plan().parts().allocations[0].range;
        let mut allocated = vec![0; allocation.len() as usize];
        let at = usize::try_from(self.plan.image().address() - allocation.start()).unwrap();
        allocated[at..at + self.plan.image().bytes().len()]
            .copy_from_slice(self.plan.image().bytes());
        assert_eq!(
            child.memory(allocation.start(), allocation.len() as usize),
            allocated
        );
        Self::assert_rx(child, allocation);
        assert_eq!(
            oracle.code.bytes(),
            self.before,
            "child publication modified parent source"
        );

        // TEST, JNE-not-taken, ADD and RET are all real handler instructions.
        for _ in 0..4 {
            child.step(&[]);
        }
        assert_eq!(
            child.registers().rip,
            liteinst_parked_restorer as *const () as u64
        );
        child.step(&[]);
        assert_eq!(
            child.registers().rip,
            liteinst_parked_syscall as *const () as u64
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
        assert_state(&original, &oracle.snapshot(child, before.rip, &self.after));
        self.roundtrips
            .set(self.roundtrips.get().checked_add(1).unwrap());
    }
}

fn assert_frame(expected: &[u8], actual: &[u8]) {
    assert_eq!(actual, expected, "parked signal frame changed");
}
fn assert_source(expected: &[u8], actual: &[u8]) {
    assert_eq!(
        actual, expected,
        "child source differs from exact authorized edits"
    );
}
fn assert_receipt(
    words: &[u64],
    mapping: u64,
    generation: u64,
    source: u64,
    image: u64,
    length: u64,
    context: u64,
) {
    assert_eq!(words.len(), RECORD_WORDS);
    assert_eq!(
        &words[..10],
        &[
            MAGIC, 1, 1, mapping, generation, source, image, length, 3, context
        ],
        "child publication receipt mismatch"
    );
    assert_ne!(words[10], 0, "installed handle was not retained");
    assert_eq!(words[11], 0, "lease remains poisoned");
}

impl Drop for ParkedPublication {
    fn drop(&mut self) {
        assert!(ACTIVE.load(Ordering::Acquire).is_null());
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

#[cfg(test)]
mod calibration {
    use super::*;
    #[test]
    #[should_panic(expected = "parked signal frame changed")]
    fn rejects_frame_mutation() {
        assert_frame(&[0x12, 0x34], &[0x12, 0x35]);
    }
    #[test]
    #[should_panic(expected = "child source differs from exact authorized edits")]
    fn rejects_old_source_after_publication() {
        assert_source(&[0xe9, 1, 2, 3, 4], &[0x90; 5]);
    }
    #[test]
    #[should_panic(expected = "child source differs from exact authorized edits")]
    fn rejects_extra_source_write() {
        assert_source(&[0xe9, 1, 2, 3, 4, 0xc3], &[0xe9, 1, 2, 3, 4, 0xcc]);
    }
    #[test]
    #[should_panic(expected = "child publication receipt mismatch")]
    fn rejects_wrong_receipt_identity() {
        assert_receipt(&[MAGIC, 1, 1, 9, 2, 3, 4, 5, 3, 6, 7, 0], 1, 2, 3, 4, 5, 6);
    }
    #[test]
    #[should_panic(expected = "child publication receipt mismatch")]
    fn rejects_failed_publication_status() {
        assert_receipt(&[MAGIC, 2, 1, 1, 2, 3, 4, 5, 3, 6, 7, 0], 1, 2, 3, 4, 5, 6);
    }
}
