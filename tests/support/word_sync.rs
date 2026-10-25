// Child-owned deterministic publication schedules; not general async admission.
use super::*;
use liteinst2::contracts::AddressRange;
use liteinst2::patcher::synchronized::{Direction, Phase, SyncJumpPatch, SynchronizedBatch};
use liteinst2::patcher::{JumpPatchPlan, PatchStrategy};
use liteinst2::sync_core::SyncCore;
use liteinst2::trampoline::TrampolineImage;
use std::ops::Deref;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

const STACK_LEN: usize = 16 * PAGE;
const RECORD_WORDS: usize = 12;
const MAGIC: u64 = 0x574f_5244_5359_4e43;
static ACTIVE: AtomicPtr<WordPublication> = AtomicPtr::new(core::ptr::null_mut());

core::arch::global_asm!(
    ".pushsection .text",
    ".global word_oracle_handler",
    ".type word_oracle_handler,@function",
    "word_oracle_handler:",
    "int3",
    ".global word_oracle_captured",
    "word_oracle_captured:",
    "sub rsp, 8",
    "mov rdi, rdx",
    "call word_oracle_publish",
    "int3",
    ".global word_oracle_published",
    "word_oracle_published:",
    "test rax, rax",
    "jne 2f",
    "add rsp, 8",
    "ret",
    "2: ud2",
    "jmp 2b",
    ".size word_oracle_handler, .-word_oracle_handler",
    ".global word_oracle_restorer",
    ".type word_oracle_restorer,@function",
    "word_oracle_restorer:",
    "mov rax, 15",
    ".global word_oracle_syscall",
    "word_oracle_syscall:",
    "syscall",
    "ud2",
    ".size word_oracle_restorer, .-word_oracle_restorer",
    ".popsection",
);
unsafe extern "C" {
    fn word_oracle_handler();
    fn word_oracle_captured();
    fn word_oracle_published();
    fn word_oracle_restorer();
    fn word_oracle_syscall();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleKind {
    Guard,
    Parked,
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
struct Record {
    words: [AtomicU64; RECORD_WORDS],
}
impl Record {
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

pub struct WordPublication {
    plan: JumpPatchPlan,
    source: AddressRange,
    pristine: Vec<u8>,
    before: Vec<u8>,
    after: Vec<u8>,
    guarded: Vec<u8>,
    image_address: u64,
    image_bytes: Vec<u8>,
    image_page: Vec<u8>,
    direction: Direction,
    kind: ScheduleKind,
    entry: u64,
    stack: Mapping,
    previous_stack: libc::stack_t,
    previous_action: KernelAction,
    previous_mask: libc::sigset_t,
    patch: AtomicPtr<SyncJumpPatch>,
    record: Box<Record>,
    ready: AtomicU64,
    guards_seen: AtomicU64,
    completed: Cell<usize>,
    roundtrips: Cell<usize>,
    guards: Cell<usize>,
}

pub(super) struct ActivePublication<'a>(&'a WordPublication);
impl Drop for ActivePublication<'_> {
    fn drop(&mut self) {
        assert_eq!(
            ACTIVE.swap(core::ptr::null_mut(), Ordering::AcqRel),
            self.0 as *const WordPublication as *mut WordPublication
        );
    }
}

pub(super) struct ScheduledChild {
    child: Tracee,
    control: i32,
}
impl Deref for ScheduledChild {
    type Target = Tracee;
    fn deref(&self) -> &Tracee {
        &self.child
    }
}
impl Drop for ScheduledChild {
    fn drop(&mut self) {
        if self.control >= 0 {
            assert_eq!(unsafe { libc::close(self.control) }, 0);
        }
    }
}

fn permissions(address: u64, flags: i32) {
    assert_eq!(
        unsafe { libc::mprotect(address as *mut libc::c_void, PAGE, flags) },
        0
    );
}
fn live_bytes(address: u64, len: usize) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(address as *const u8, len).to_vec() }
}
fn child_word(child: &Tracee, word: &AtomicU64) -> u64 {
    u64::from_ne_bytes(
        child
            .memory(word as *const AtomicU64 as u64, 8)
            .try_into()
            .unwrap(),
    )
}

#[unsafe(no_mangle)]
unsafe extern "C" fn word_oracle_publish(context: *mut libc::ucontext_t) -> u64 {
    let pointer = ACTIVE.load(Ordering::Acquire);
    assert!(!pointer.is_null());
    // Only the held real frame invokes this closed-fixture publisher. Failure
    // aborts/traps; assembly permits no failed return to application code.
    unsafe { (&*pointer).publish_in_child(context) }
}

impl WordPublication {
    /// # Safety
    /// Fresh sole-main-thread fixture only, with no inherited allocator/router
    /// lock holder. The child interrupts only the declared handwritten body.
    /// All children/worker threads must be reaped before this owner drops.
    pub unsafe fn new(
        plan: JumpPatchPlan,
        code: &Mapping,
        image: &TrampolineImage,
        direction: Direction,
        kind: ScheduleKind,
        entry: u64,
    ) -> Self {
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        assert_eq!(code.len, PAGE);
        assert!((5..=8).contains(&plan.displaced_len()));
        let source = AddressRange::new(code.address(), PAGE).unwrap();
        let offset = usize::try_from(plan.execute_address() - source.start()).unwrap();
        assert!(offset + 8 <= PAGE);
        let pristine = code.bytes().to_vec();
        assert_eq!(&pristine[offset..offset + 8], &plan.original_bytes());
        let mut patched = pristine.clone();
        patched[offset..offset + 8].copy_from_slice(&plan.replacement_bytes());
        assert_eq!(&patched[..offset], &pristine[..offset]);
        assert_eq!(&patched[offset + 5..], &pristine[offset + 5..]);
        let (before, after) = match direction {
            Direction::Apply => (pristine.clone(), patched),
            Direction::Revert => (patched, pristine.clone()),
        };
        let mut guarded = before.clone();
        if kind == ScheduleKind::Guard {
            let PatchStrategy::GuardedSplit { front_len, .. } = plan.strategy() else {
                panic!("guard schedule requires a real split");
            };
            assert!(
                entry == plan.execute_address()
                    || entry == plan.execute_address() + plan.displaced_len() as u64
                        && plan.displaced_len() < front_len
            );
            guarded[offset..offset + front_len].fill(0xcc);
        } else {
            assert_eq!(entry, plan.execute_address());
        }
        assert_eq!(image.address(), plan.target_address());
        assert_eq!(image.instruction_boundaries().len(), 1);
        assert_eq!(image.instruction_boundaries()[0].0, plan.execute_address());
        assert_eq!(image.layout().instrumentation_len, 0);
        assert!(image.controls().is_empty() && image.bytes().len() <= PAGE);
        let mut image_page = vec![0; PAGE];
        image_page[..image.bytes().len()].copy_from_slice(image.bytes());
        assert_eq!(live_bytes(image.address(), PAGE), image_page);
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
            handler: word_oracle_handler as *const () as u64,
            flags: (libc::SA_SIGINFO | libc::SA_ONSTACK) as u64 | 0x0400_0000,
            restorer: word_oracle_restorer as *const () as u64,
            mask: !(1_u64 << (libc::SIGTRAP - 1)),
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
        for signal in [libc::SIGUSR1, libc::SIGTRAP] {
            assert_eq!(unsafe { libc::sigaddset(&mut signals, signal) }, 0);
        }
        assert_eq!(
            unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &signals, &mut previous_mask) },
            0
        );
        Self {
            plan,
            source,
            pristine,
            before,
            after,
            guarded,
            image_address: image.address(),
            image_bytes: image.bytes().to_vec(),
            image_page,
            direction,
            kind,
            entry,
            stack,
            previous_stack,
            previous_action,
            previous_mask,
            patch: AtomicPtr::new(core::ptr::null_mut()),
            record: Box::new(Record::new()),
            ready: AtomicU64::new(0),
            guards_seen: AtomicU64::new(0),
            completed: Cell::new(0),
            roundtrips: Cell::new(0),
            guards: Cell::new(0),
        }
    }

    pub fn completed(&self) -> usize {
        self.completed.get()
    }
    pub fn signal_roundtrips(&self) -> usize {
        self.roundtrips.get()
    }
    pub fn guard_deliveries(&self) -> usize {
        self.guards.get()
    }
    pub(super) fn expected_source(&self) -> &[u8] {
        &self.after
    }
    pub(super) fn activate(&self) -> ActivePublication<'_> {
        assert!(
            ACTIVE
                .compare_exchange(
                    core::ptr::null_mut(),
                    self as *const Self as *mut Self,
                    Ordering::AcqRel,
                    Ordering::Acquire
                )
                .is_ok()
        );
        ActivePublication(self)
    }
    fn contains(&self, address: u64, len: usize) -> bool {
        self.stack.address() <= address
            && address
                .checked_add(len as u64)
                .is_some_and(|end| end <= self.stack.address() + STACK_LEN as u64)
    }
    fn record(&self, child: &Tracee) -> Vec<u64> {
        child
            .memory(self.record.address(), RECORD_WORDS * 8)
            .chunks_exact(8)
            .map(|bytes| u64::from_ne_bytes(bytes.try_into().unwrap()))
            .collect()
    }
    fn patch(&self) -> &SyncJumpPatch {
        let pointer = self.patch.load(Ordering::Acquire);
        assert!(!pointer.is_null());
        unsafe { &*pointer }
    }

    fn transition(
        &self,
        direction: Direction,
        initial: &[u8],
        phases: &[Phase],
        batch: &mut SynchronizedBatch<'_>,
    ) {
        let offset = (self.plan.execute_address() - self.source.start()) as usize;
        let front = match self.plan.strategy() {
            PatchStrategy::AtomicWord => 8,
            PatchStrategy::GuardedSplit { front_len, .. } => front_len,
        };
        let desired = match direction {
            Direction::Apply => self.plan.replacement_bytes(),
            Direction::Revert => self.plan.original_bytes(),
        };
        for &phase in phases {
            let result = unsafe { batch.advance().unwrap() };
            assert_eq!(result.phase, phase);
            assert_eq!(result.members, 1);
            assert_eq!(
                result.mutated,
                front != 8 || matches!(phase, Phase::FrontsPublished | Phase::Complete)
            );
            assert_eq!(
                result.synchronizations,
                match phase {
                    Phase::GuardsPublished => 0,
                    Phase::GuardsSynchronized | Phase::BacksPublished => 1,
                    Phase::BacksSynchronized | Phase::FrontsPublished => 2,
                    Phase::Complete => 3,
                    _ => panic!("non-publication phase"),
                }
            );
            assert_eq!(result.failure, None);
            assert_eq!(result.writer_ownership_retained, phase != Phase::Complete);
            let mut expected = initial.to_vec();
            if matches!(phase, Phase::FrontsPublished | Phase::Complete) {
                expected[offset..offset + 8].copy_from_slice(&desired);
            } else if front != 8 {
                expected[offset..offset + front].fill(0xcc);
                if matches!(phase, Phase::BacksPublished | Phase::BacksSynchronized) {
                    expected[offset + front..offset + 8].copy_from_slice(&desired[front..]);
                }
            }
            assert_eq!(live_bytes(self.source.start(), PAGE), expected);
            assert_eq!(live_bytes(self.image_address, PAGE), self.image_page);
        }
    }

    fn full_transition(&self, direction: Direction, initial: &[u8]) {
        let refs = [self.patch()];
        let mut batch = unsafe { SynchronizedBatch::prepare(&refs, direction).unwrap() };
        assert_eq!(batch.receipt().phase, Phase::Prepared);
        self.transition(
            direction,
            initial,
            &[
                Phase::GuardsPublished,
                Phase::GuardsSynchronized,
                Phase::BacksPublished,
                Phase::BacksSynchronized,
                Phase::FrontsPublished,
                Phase::Complete,
            ],
            &mut batch,
        );
        assert_eq!(batch.receipt().synchronizations, 3);
    }

    fn prepare_child(&self) {
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        assert_eq!(live_bytes(self.source.start(), PAGE), self.pristine);
        // Fixture-local private COW page: the tracee alone owns this RWX scratch
        // view while its publisher runs. This does not assert W^X publication.
        permissions(
            self.source.start(),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        );
        let capability = SyncCore::prepare().unwrap();
        let patch = unsafe {
            SyncJumpPatch::bind(
                self.plan.clone(),
                self.plan.execute_address() as *mut u8,
                capability,
            )
            .unwrap()
        };
        self.patch
            .store(Box::into_raw(Box::new(patch)), Ordering::Release);
        if self.direction == Direction::Revert {
            self.full_transition(Direction::Apply, &self.pristine);
        }
        assert_eq!(live_bytes(self.source.start(), PAGE), self.before);
        assert_eq!(self.patch().handled_guard_traps(), 0);
    }

    fn finish_record(&self, context: u64) {
        self.record.store(0, MAGIC);
        self.record.store(2, 1);
        self.record.store(3, unsafe { libc::getpid() } as u64);
        self.record
            .store(4, u64::from(self.direction == Direction::Revert));
        self.record.store(5, self.plan.execute_address());
        self.record.store(6, self.image_address);
        self.record.store(7, self.image_bytes.len() as u64);
        self.record.store(8, 3);
        self.record.store(9, context);
        self.record
            .store(10, self.patch.load(Ordering::Acquire) as u64);
        self.record.store(11, 0);
        self.record.store(1, 1);
    }

    fn publish_in_child(&self, context: *mut libc::ucontext_t) -> u64 {
        assert_eq!(self.kind, ScheduleKind::Parked);
        assert!(self.contains(context as u64, core::mem::size_of::<libc::ucontext_t>()));
        let saved = unsafe { core::ptr::read_unaligned(context) };
        assert_eq!(
            saved.uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
            self.entry
        );
        assert_eq!(self.record.words[1].load(Ordering::Acquire), 0);
        assert_eq!(live_bytes(self.source.start(), PAGE), self.before);
        self.full_transition(self.direction, &self.before);
        assert_eq!(live_bytes(self.source.start(), PAGE), self.after);
        permissions(self.source.start(), libc::PROT_READ | libc::PROT_EXEC);
        self.finish_record(context as u64);
        0
    }

    fn guard_worker(&self, command: i32) {
        let refs = [self.patch()];
        let mut batch = unsafe { SynchronizedBatch::prepare(&refs, self.direction).unwrap() };
        self.transition(
            self.direction,
            &self.before,
            &[Phase::GuardsPublished],
            &mut batch,
        );
        assert_eq!(live_bytes(self.source.start(), PAGE), self.guarded);
        self.ready.store(1, Ordering::Release);
        let mut byte = 0_u8;
        assert_eq!(unsafe { libc::read(command, (&raw mut byte).cast(), 1) }, 1);
        assert_eq!(byte, 1);
        assert_eq!(unsafe { libc::close(command) }, 0);
        self.transition(
            self.direction,
            &self.before,
            &[
                Phase::GuardsSynchronized,
                Phase::BacksPublished,
                Phase::BacksSynchronized,
                Phase::FrontsPublished,
                Phase::Complete,
            ],
            &mut batch,
        );
        assert_eq!(batch.receipt().synchronizations, 3);
        assert_eq!(live_bytes(self.source.start(), PAGE), self.after);
        permissions(self.source.start(), libc::PROT_READ | libc::PROT_EXEC);
        self.finish_record(0);
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.patch().handled_guard_traps() == 0 {
            assert!(Instant::now() < deadline, "owned guard was not delivered");
            std::thread::yield_now();
        }
        assert_eq!(self.patch().handled_guard_traps(), 1);
        self.guards_seen.store(1, Ordering::Release);
    }

    pub(super) fn fork(&self) -> ScheduledChild {
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        let mut pipe = [-1; 2];
        if self.kind == ScheduleKind::Guard {
            assert_eq!(
                unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
        }
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if pipe[1] >= 0 {
                assert_eq!(unsafe { libc::close(pipe[1]) }, 0);
            }
            self.prepare_child();
            if self.kind == ScheduleKind::Guard {
                let pointer = self as *const Self as usize;
                let command = pipe[0];
                let worker = std::thread::spawn(move || {
                    // This immutable fixture outlives the entire owned child;
                    // mutable rendezvous fields are atomic and application
                    // storage is touched only under its actual Word writer.
                    unsafe { (&*(pointer as *const WordPublication)).guard_worker(command) };
                });
                drop(worker); // Detached, but owned and killed/reaped with this tracee.
                let deadline = Instant::now() + Duration::from_secs(2);
                while self.ready.load(Ordering::Acquire) != 1 {
                    assert!(Instant::now() < deadline);
                    std::thread::yield_now();
                }
            }
            unsafe {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0_usize, 0_usize) == -1 {
                    libc::_exit(120);
                }
                libc::syscall(
                    libc::SYS_tgkill,
                    libc::getpid(),
                    libc::syscall(libc::SYS_gettid),
                    libc::SIGSTOP,
                );
                libc::_exit(121);
            }
        }
        if pipe[0] >= 0 {
            assert_eq!(unsafe { libc::close(pipe[0]) }, 0);
        }
        let child = Tracee {
            pid,
            deadline: Instant::now() + CHILD_BUDGET,
            reaped: Cell::new(false),
        };
        let stop = child.wait();
        assert!(libc::WIFSTOPPED(stop) && libc::WSTOPSIG(stop) == libc::SIGSTOP);
        ScheduledChild {
            child,
            control: pipe[1],
        }
    }

    pub(super) fn publish_and_resume(
        &self,
        oracle: &NativeOracle,
        child: &ScheduledChild,
        log: &HookEventLog,
    ) -> usize {
        assert_eq!(child.registers().rip, self.entry);
        match self.kind {
            ScheduleKind::Guard => self.guard_resume(oracle, child, log),
            ScheduleKind::Parked => self.parked_resume(oracle, child, log),
        }
    }

    fn verify_record(&self, child: &Tracee, context: u64) {
        let pointer = u64::from_ne_bytes(
            child
                .memory(&self.patch as *const AtomicPtr<SyncJumpPatch> as u64, 8)
                .try_into()
                .unwrap(),
        );
        assert_ne!(pointer, 0);
        let expected = [
            MAGIC,
            1,
            1,
            child.pid as u64,
            u64::from(self.direction == Direction::Revert),
            self.plan.execute_address(),
            self.image_address,
            self.image_bytes.len() as u64,
            3,
            context,
            pointer,
            0,
        ];
        assert_record(&self.record(child), &expected);
    }

    fn guard_resume(
        &self,
        oracle: &NativeOracle,
        child: &ScheduledChild,
        log: &HookEventLog,
    ) -> usize {
        assert_eq!(child_word(child, &self.ready), 1);
        assert_eq!(self.record(child), vec![0; RECORD_WORDS]);
        assert_eq!(child.memory(self.source.start(), PAGE), self.guarded);
        assert_eq!(child.memory(self.image_address, PAGE), self.image_page);
        log.assert_events(child, &[]);
        let initial = oracle.snapshot(child, self.entry, &self.guarded);
        child.request(libc::PTRACE_SINGLESTEP, 0, 0);
        let stop = child.wait();
        assert!(libc::WIFSTOPPED(stop) && libc::WSTOPSIG(stop) == libc::SIGTRAP);
        let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
        child.request(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
        assert_eq!(
            (info.si_signo, info.si_code),
            (libc::SIGTRAP, libc::SI_KERNEL)
        );
        assert_eq!(child.registers().rip, self.entry + 1);
        // Only fixture-owned pipe I/O; no ptrace register/frame/memory write.
        assert_eq!(
            unsafe { libc::write(child.control, (&1_u8 as *const u8).cast(), 1) },
            1
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.record(child)[1] != 1 {
            assert!(Instant::now() < deadline && Instant::now() < child.deadline);
            std::thread::yield_now();
        }
        self.verify_record(child, 0);
        assert_eq!(child_word(child, &self.guards_seen), 0);
        assert_eq!(child.memory(self.source.start(), PAGE), self.after);
        Self::assert_rx(child, self.source);
        Self::assert_rx(child, AddressRange::new(self.image_address, PAGE).unwrap());
        log.assert_events(child, &[]);
        child.request(libc::PTRACE_SINGLESTEP, 0, libc::SIGTRAP as usize);
        let delivered = child.wait();
        assert!(libc::WIFSTOPPED(delivered) && libc::WSTOPSIG(delivered) == libc::SIGTRAP);
        // Step the real installed handler until its actual rt_sigreturn. Every
        // handler instruction is charged to the same 20k budget as the trace.
        for charged in 2..MAX_STEPS {
            assert!(Instant::now() < child.deadline);
            let registers = child.registers();
            if registers.rax == libc::SYS_rt_sigreturn as u64
                && child.memory(registers.rip, 2) == [0x0f, 0x05]
            {
                child.request(
                    libc::PTRACE_SETOPTIONS,
                    0,
                    libc::PTRACE_O_TRACESYSGOOD as usize,
                );
                child.request(libc::PTRACE_SYSCALL, 0, 0);
                let entered = child.wait();
                assert!(
                    libc::WIFSTOPPED(entered) && libc::WSTOPSIG(entered) == (libc::SIGTRAP | 0x80)
                );
                assert_eq!(child.registers().orig_rax, libc::SYS_rt_sigreturn as u64);
                child.request(libc::PTRACE_SYSCALL, 0, 0);
                let returned = child.wait();
                assert!(
                    libc::WIFSTOPPED(returned)
                        && libc::WSTOPSIG(returned) == (libc::SIGTRAP | 0x80)
                );
                assert_eq!(child.registers().rip, self.entry);
                child.request(libc::PTRACE_SETOPTIONS, 0, 0);
                assert_state(&initial, &oracle.snapshot(child, self.entry, &self.after));
                let deadline = Instant::now() + Duration::from_secs(2);
                while child_word(child, &self.guards_seen) != 1 {
                    assert!(Instant::now() < deadline && Instant::now() < child.deadline);
                    std::thread::yield_now();
                }
                assert_eq!(child_word(child, &self.guards_seen), 1);
                assert_eq!(child.memory(self.image_address, PAGE), self.image_page);
                log.assert_events(child, &[]);
                self.completed.set(self.completed.get() + 1);
                self.roundtrips.set(self.roundtrips.get() + 1);
                self.guards.set(self.guards.get() + 1);
                return charged + 1;
            }
            child.step(&[]);
        }
        panic!("owned guard handler exhausted the unchanged instruction bound")
    }
}

impl WordPublication {
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

    fn parked_resume(
        &self,
        oracle: &NativeOracle,
        child: &ScheduledChild,
        log: &HookEventLog,
    ) -> usize {
        assert_eq!(
            std::fs::read_dir(format!("/proc/{}/task", child.pid))
                .unwrap()
                .map(Result::unwrap)
                .count(),
            1
        );
        assert_eq!(oracle.code.address(), self.source.start());
        assert_eq!(oracle.code.bytes(), self.pristine);
        let before = child.registers();
        assert_eq!(before.orig_rax, u64::MAX);
        let original = oracle.snapshot(child, before.rip, &self.before);
        assert_eq!(self.record(child), vec![0; RECORD_WORDS]);
        log.assert_events(child, &[]);
        child.request(libc::PTRACE_CONT, 0, libc::SIGUSR1 as usize);
        let stop = child.wait();
        assert!(libc::WIFSTOPPED(stop) && libc::WSTOPSIG(stop) == libc::SIGTRAP);
        let captured = child.registers();
        assert_eq!(captured.rip, word_oracle_captured as *const () as u64);
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
            word_oracle_restorer as *const () as u64
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
            word_oracle_published as *const () as u64
        );
        assert_eq!(child.registers().rax, 0, "publisher did not return success");
        // Publication itself must not substitute a callback for later application execution.
        // This checks the complete log page, including unused storage and overflow.
        log.assert_events(child, &[]);
        assert_frame(&frame, &child.memory(captured.rsp, frame_len));
        self.verify_record(child, captured.rdx);
        assert_source(&self.after, &child.memory(self.source.start(), PAGE));
        Self::assert_rx(child, self.source);
        assert_eq!(child.memory(self.image_address, PAGE), self.image_page);
        Self::assert_rx(child, AddressRange::new(self.image_address, PAGE).unwrap());
        assert_eq!(
            oracle.code.bytes(),
            self.pristine,
            "child publication modified parent source"
        );

        // TEST, JNE-not-taken, ADD and RET are all real handler instructions.
        for _ in 0..4 {
            child.step(&[]);
        }
        assert_eq!(
            child.registers().rip,
            word_oracle_restorer as *const () as u64
        );
        child.step(&[]);
        assert_eq!(
            child.registers().rip,
            word_oracle_syscall as *const () as u64
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
        self.completed
            .set(self.completed.get().checked_add(1).unwrap());
        assert_eq!(child_word(child, &self.guards_seen), 0);
        // Four return-path instructions, MOV syscall number, and rt_sigreturn.
        // Publication itself runs under the unchanged 15-second child deadline.
        6
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

impl Drop for WordPublication {
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

fn assert_record(actual: &[u64], expected: &[u64; RECORD_WORDS]) {
    assert_eq!(
        actual, expected,
        "child publication receipt identity/status differs"
    );
}

#[cfg(test)]
mod word_calibration {
    use super::{MAGIC, RECORD_WORDS, assert_record};

    fn expected() -> [u64; RECORD_WORDS] {
        [MAGIC, 1, 1, 42, 0, 0x1000, 0x2000, 24, 3, 0x3000, 0x4000, 0]
    }

    #[test]
    fn accepts_exact_child_publication_record() {
        assert_record(&expected(), &expected());
    }

    #[test]
    #[should_panic(expected = "child publication receipt identity/status differs")]
    fn rejects_wrong_child_process() {
        let mut actual = expected();
        actual[3] = 43;
        assert_record(&actual, &expected());
    }

    #[test]
    #[should_panic(expected = "child publication receipt identity/status differs")]
    fn rejects_wrong_transition_direction() {
        let mut actual = expected();
        actual[4] = 1;
        assert_record(&actual, &expected());
    }

    #[test]
    #[should_panic(expected = "child publication receipt identity/status differs")]
    fn rejects_failed_publication_status() {
        let mut actual = expected();
        actual[1] = 0;
        assert_record(&actual, &expected());
    }

    #[test]
    #[should_panic(expected = "child publication receipt identity/status differs")]
    fn rejects_missing_synchronization() {
        let mut actual = expected();
        actual[8] = 2;
        assert_record(&actual, &expected());
    }

    #[test]
    #[should_panic(expected = "child publication receipt identity/status differs")]
    fn rejects_wrong_bound_patch_identity() {
        let mut actual = expected();
        actual[10] = 0x5000;
        assert_record(&actual, &expected());
    }

    #[test]
    #[should_panic(expected = "child publication receipt identity/status differs")]
    fn rejects_trailing_receipt_field() {
        let mut actual = expected().to_vec();
        actual.push(0);
        assert_record(&actual, &expected());
    }
}
