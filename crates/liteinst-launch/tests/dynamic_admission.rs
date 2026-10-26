#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Native seized-owner admission puzzles. Image heads and complete expected
//! register transitions below are independently specified, not derived through
//! the production decoder/completer. These assertions make no throughput claim.
use liteinst_launch::gate::{GateError, ImageFacts, SelectedExecution};
use liteinst_launch::selected::{
    InstructionProvider, NativeProvider, Operation, ProviderDecision, SelectedInput,
    SelectedResult, SemanticsError,
};
use liteinst_launch::trap_coverage::TrapCoverageBudget;
use liteinst_launch::{
    DynamicAdmissionBackend, DynamicAdmissionCompletion, DynamicAdmissionEvent,
    DynamicAdmissionOptions, DynamicAdmissionSession, DynamicCreationPolicy, DynamicEvent,
    DynamicLifecycleOptions, LaunchCommand, LaunchError, RegisterSnapshot,
};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const INTERP: u64 = 0x800000;
const DATA: u64 = 0x600000;
const STACK: u64 = DATA + 2 * PAGE as u64 - 128;
const TIMEOUT: Duration = Duration::from_secs(3);
static NEXT: AtomicUsize = AtomicUsize::new(0);
static FILE_FORK: Mutex<()> = Mutex::new(());

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "dynamic-admission-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(directory.parent().unwrap()).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        Self(directory)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Image {
    base: u64,
    bytes: Vec<u8>,
    heads: BTreeSet<u64>,
    cursor: usize,
}
fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
impl Image {
    fn new(base: u64, pages: usize) -> Self {
        let mut bytes = vec![0; pages * PAGE];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2), (18, 62), (52, 64), (54, 56), (56, 3)] {
            put16(&mut bytes, at, value);
        }
        for (at, value) in [
            (20, 1),
            (64, 1),
            (68, 5),
            (120, 1),
            (124, 6),
            (176, 0x6474e551),
            (180, 6),
        ] {
            put32(&mut bytes, at, value);
        }
        for (at, value) in [
            (24, base + PAGE as u64),
            (32, 64),
            (80, base),
            (96, (pages * PAGE) as u64),
            (104, (pages * PAGE) as u64),
            (112, PAGE as u64),
            (128, (pages * PAGE) as u64),
            (136, if base == BASE { DATA } else { DATA + 0x100000 }),
            (152, (2 * PAGE) as u64),
            (160, (2 * PAGE) as u64),
            (168, PAGE as u64),
            (224, 16),
        ] {
            put64(&mut bytes, at, value);
        }
        Self {
            base,
            bytes,
            heads: BTreeSet::new(),
            cursor: PAGE,
        }
    }
    fn emit(&mut self, bytes: &[u8]) -> u64 {
        let pc = self.base + self.cursor as u64;
        assert!(self.heads.insert(pc));
        self.bytes[self.cursor..self.cursor + bytes.len()].copy_from_slice(bytes);
        self.cursor += bytes.len();
        pc
    }
    fn mov(&mut self, reg: u8, value: u64) {
        assert!(reg < 16);
        let mut bytes = vec![0x48 | (reg >> 3), 0xb8 | (reg & 7)];
        bytes.extend_from_slice(&value.to_le_bytes());
        self.emit(&bytes);
    }
    fn interpreter(&mut self, path: &Path) {
        let path = path.as_os_str().as_encoded_bytes();
        assert!(path.len() + 1 < 512);
        self.bytes[512..512 + path.len()].copy_from_slice(path);
        put16(&mut self.bytes, 56, 4);
        put32(&mut self.bytes, 232, 3);
        put32(&mut self.bytes, 236, 4);
        for (at, value) in [
            (240, 512),
            (248, self.base + 512),
            (264, path.len() as u64 + 1),
            (272, path.len() as u64 + 1),
            (280, 1),
        ] {
            put64(&mut self.bytes, at, value);
        }
    }
    fn facts(&self) -> ImageFacts {
        ImageFacts {
            start: self.base,
            bytes: self.bytes.clone(),
            heads: self.heads.clone(),
        }
    }
    fn write(&self, directory: &Directory, name: &str) -> PathBuf {
        let path = directory.0.join(name);
        let _file_fork = FILE_FORK.lock().unwrap();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&self.bytes).unwrap();
        file.write_all(&vec![0x5a; 2 * PAGE]).unwrap();
        drop(file);
        path
    }
    fn spin(&mut self) {
        self.emit(&[0xeb, 0xfe]);
    }
}

fn pin(pid: i32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0, "pidfd_open: {}", io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}
fn assert_reaped(pin: &OwnedFd) {
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&raw mut poll, 1, 0) }, 1);
    assert_eq!(poll.revents, libc::POLLIN | libc::POLLHUP);
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pin.as_raw_fd() as u32,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}
fn cleanup<P: InstructionProvider>(session: DynamicAdmissionSession<P>, pin: &OwnedFd) {
    let pid = session.pid();
    let receipt = session.terminate(TIMEOUT).unwrap();
    assert_eq!(receipt.reaped, [pid]);
    assert_reaped(pin);
}
fn launch<P: InstructionProvider>(
    path: &Path,
    facts: Vec<ImageFacts>,
    options: DynamicAdmissionOptions,
    provider: P,
) -> DynamicAdmissionSession<P> {
    // SAFETY: the private ELF images contain exactly the declared instruction
    // heads and immutable RX segments. There are no aliases, code reads, signal
    // frames, external writers or unqualified control transfers in these puzzles.
    let file_fork = FILE_FORK.lock().unwrap();
    let result = unsafe {
        DynamicAdmissionSession::launch(
            &LaunchCommand::new(path),
            facts,
            options,
            provider,
            TIMEOUT,
        )
    };
    drop(file_fork);
    result.unwrap()
}
fn completion<P: InstructionProvider>(
    session: &mut DynamicAdmissionSession<P>,
) -> DynamicAdmissionCompletion {
    completion_with_events(session, &mut Vec::new())
}
fn completion_with_events<P: InstructionProvider>(
    session: &mut DynamicAdmissionSession<P>,
    events: &mut Vec<DynamicEvent>,
) -> DynamicAdmissionCompletion {
    for _ in 0..8 {
        match session.next_event().unwrap() {
            DynamicAdmissionEvent::Completed(done) => return *done,
            DynamicAdmissionEvent::Lifecycle(event) => {
                assert!(matches!(
                    event.kind,
                    liteinst_launch::DynamicEventKind::Created { .. }
                        | liteinst_launch::DynamicEventKind::Newborn { .. }
                ));
                events.push(event);
            }
            other => panic!("unexpected admission event: {other:?}"),
        }
    }
    panic!("bounded completion event inventory exhausted")
}
fn expected_cpuid(mut before: RegisterSnapshot, values: [u32; 4]) -> RegisterSnapshot {
    before.rax = u64::from(values[0]);
    before.rbx = u64::from(values[1]);
    before.rcx = u64::from(values[2]);
    before.rdx = u64::from(values[3]);
    before.rip += 2;
    before
}
#[derive(Default)]
struct Script {
    calls: usize,
}
impl InstructionProvider for Script {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        self.calls += 1;
        Ok(match input.instruction().operation() {
            Operation::Cpuid => ProviderDecision::Complete(SelectedResult::Cpuid {
                eax: 0x12345678,
                ebx: 0x87654321,
                ecx: 0x10203040,
                edx: 0xfedcba98,
            }),
            Operation::Syscall { .. } => ProviderDecision::Native,
            _ => return Err(SemanticsError::ScriptMismatch),
        })
    }
}

#[test]
fn literal_first_cpuid_preserves_complete_state_and_native_memory() {
    let directory = Directory::new();
    let mut image = Image::new(BASE, 2);
    image.emit(&[0x0f, 0xa2]);
    image.spin();
    let path = image.write(&directory, "cpuid");
    for native in [false, true] {
        struct Choose {
            native: bool,
            calls: usize,
        }
        impl InstructionProvider for Choose {
            fn decide(
                &mut self,
                input: &SelectedInput,
            ) -> Result<ProviderDecision, SemanticsError> {
                assert_eq!(input.instruction().bytes(), [0x0f, 0xa2]);
                self.calls += 1;
                Ok(if self.native {
                    ProviderDecision::Native
                } else {
                    ProviderDecision::Complete(SelectedResult::Cpuid {
                        eax: 1,
                        ebx: 2,
                        ecx: 3,
                        edx: 4,
                    })
                })
            }
        }
        let mut session = launch(
            &path,
            vec![image.facts()],
            DynamicAdmissionOptions::default(),
            Choose { native, calls: 0 },
        );
        let pin = pin(session.pid());
        let initial = session.initial_state().clone();
        assert_eq!(initial.registers.rip, BASE + PAGE as u64);
        assert_eq!(initial.registers.rax, 0);
        assert_eq!(initial.registers.orig_rax, u64::MAX);
        let stack = session
            .read_memory(initial.task.task, initial.registers.rsp, 256)
            .unwrap();
        let data = session
            .read_memory(initial.task.task, DATA, 2 * PAGE)
            .unwrap();
        let result = completion(&mut session);
        let values = if native {
            // CPUID leaf zero's vendor/max-leaf result is stable across this
            // machine; use the independent host instruction, no production model.
            let value = std::arch::x86_64::__cpuid_count(
                initial.registers.rax as u32,
                initial.registers.rcx as u32,
            );
            [value.eax, value.ebx, value.ecx, value.edx]
        } else {
            [1, 2, 3, 4]
        };
        assert_eq!(result.selected.input.registers(), &initial.registers);
        assert_eq!(
            result.selected.after,
            expected_cpuid(initial.registers, values)
        );
        assert_eq!(result.selected.before_xstate, initial.xstate);
        assert_eq!(result.selected.xstate, initial.xstate);
        assert_eq!(result.before_signal_mask, initial.signal_mask);
        assert_eq!(result.signal_mask, initial.signal_mask);
        assert_eq!(
            result.selected.execution,
            if native {
                SelectedExecution::Native
            } else {
                SelectedExecution::Scripted
            }
        );
        assert_eq!(session.provider().calls, 1);
        assert_eq!(
            session
                .read_memory(initial.task.task, initial.registers.rsp, 256)
                .unwrap(),
            stack
        );
        assert_eq!(
            session
                .read_memory(initial.task.task, DATA, 2 * PAGE)
                .unwrap(),
            data
        );
        assert_eq!(
            session.state(initial.task.task).unwrap().registers,
            result.selected.after
        );
        assert_eq!(result.after_task.task, initial.task.task);
        assert_eq!(result.after_task.generation, 1);
        let metrics = session.metrics().unwrap();
        assert_eq!(metrics.fetch_faults, 1);
        assert_eq!(metrics.guard_stops, 1);
        cleanup(session, &pin);
    }
}

#[test]
fn interpreter_and_executable_literal_first_instructions_are_both_gated() {
    let directory = Directory::new();
    let mut interpreter = Image::new(INTERP, 2);
    interpreter.emit(&[0x0f, 0xa2]);
    interpreter.mov(0, BASE + PAGE as u64);
    interpreter.emit(&[0xff, 0xe0]);
    let interpreter_path = interpreter.write(&directory, "interpreter");
    let mut main = Image::new(BASE, 2);
    main.emit(&[0x0f, 0xa2]);
    main.spin();
    main.interpreter(&interpreter_path);
    let path = main.write(&directory, "main");
    let mut session = launch(
        &path,
        vec![main.facts(), interpreter.facts()],
        DynamicAdmissionOptions::default(),
        Script::default(),
    );
    let pin = pin(session.pid());
    let first = session.initial_state().clone();
    assert_eq!(first.registers.rip, INTERP + PAGE as u64);
    let stack = session
        .read_memory(first.task.task, first.registers.rsp, 256)
        .unwrap();
    let first_done = completion(&mut session);
    assert_eq!(first_done.selected.input.registers(), &first.registers);
    let first_after = expected_cpuid(
        first.registers,
        [0x12345678, 0x87654321, 0x10203040, 0xfedcba98],
    );
    assert_eq!(first_done.selected.after, first_after);
    let mut second_before = first_after;
    second_before.rax = BASE + PAGE as u64;
    second_before.rip = BASE + PAGE as u64;
    let second_done = completion(&mut session);
    assert_eq!(second_done.selected.input.registers(), &second_before);
    assert_eq!(
        second_done.selected.after,
        expected_cpuid(
            second_before,
            [0x12345678, 0x87654321, 0x10203040, 0xfedcba98]
        )
    );
    assert_eq!(second_done.selected.before_xstate, first.xstate);
    assert_eq!(second_done.selected.xstate, first.xstate);
    assert_eq!(second_done.before_signal_mask, first.signal_mask);
    assert_eq!(second_done.signal_mask, first.signal_mask);
    assert_eq!(
        session
            .read_memory(first.task.task, first.registers.rsp, 256)
            .unwrap(),
        stack
    );
    assert_eq!(session.provider().calls, 2);
    cleanup(session, &pin);
}

#[test]
fn clone_return_at_page_boundary_gates_each_first_instruction_once() {
    let directory = Directory::new();
    let mut image = Image::new(BASE, 3);
    image.mov(0, libc::SYS_clone as u64);
    image.mov(7, 0x10f00);
    image.mov(6, STACK);
    for reg in [2, 10, 8, 9] {
        image.mov(reg, 0);
    }
    let next = BASE + 2 * PAGE as u64;
    let displacement = (2 * PAGE - 2) as i64 - (image.cursor + 5) as i64;
    let mut jump = vec![0xe9];
    jump.extend_from_slice(&i32::try_from(displacement).unwrap().to_le_bytes());
    image.emit(&jump);
    image.cursor = 2 * PAGE - 2;
    let clone = image.emit(&[0x0f, 0x05]);
    assert_eq!(image.cursor, 2 * PAGE);
    image.emit(&[0x0f, 0xa2]);
    image.spin();
    let path = image.write(&directory, "clone");
    let options = DynamicAdmissionOptions {
        lifecycle: DynamicLifecycleOptions {
            creation: DynamicCreationPolicy::ThreadClone,
            max_tasks: 2,
        },
        ..DynamicAdmissionOptions::default()
    };
    let mut session = launch(&path, vec![image.facts()], options, Script::default());
    let pin = pin(session.pid());
    let initial = session.initial_state().clone();
    let data = session
        .read_memory(initial.task.task, DATA, 2 * PAGE)
        .unwrap();
    let kernel = completion(&mut session);
    assert_eq!(kernel.selected.input.instruction().logical_pc(), clone);
    assert_eq!(kernel.selected.execution, SelectedExecution::Native);
    let mut clone_before = initial.registers;
    clone_before.rax = libc::SYS_clone as u64;
    clone_before.rdi = 0x10f00;
    clone_before.rsi = STACK;
    clone_before.rdx = 0;
    clone_before.r10 = 0;
    clone_before.r8 = 0;
    clone_before.r9 = 0;
    clone_before.rip = clone;
    assert_eq!(*kernel.selected.input.registers(), clone_before);
    assert_eq!(kernel.selected.before_xstate, initial.xstate);
    assert_eq!(kernel.selected.xstate, initial.xstate);
    let mut events = Vec::new();
    let first = completion_with_events(&mut session, &mut events);
    let second = completion_with_events(&mut session, &mut events);
    assert_eq!(events.len(), 2);
    let newborn = events
        .iter()
        .find(|event| {
            matches!(
                event.kind,
                liteinst_launch::DynamicEventKind::Newborn { .. }
            )
        })
        .unwrap();
    let child = newborn.task.unwrap();
    assert_ne!(child.task, initial.task.task);
    assert!(events.iter().any(|event|matches!(event.kind,liteinst_launch::DynamicEventKind::Created {child:created} if created.task==child.task)));
    let child_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, newborn.tid, 0x80) };
    assert!(child_fd >= 0);
    let child_pin = unsafe { OwnedFd::from_raw_fd(child_fd as i32) };
    let mut clone_after = clone_before;
    clone_after.rip = next;
    clone_after.rcx = next;
    clone_after.r11 = clone_before.eflags;
    clone_after.rax = newborn.tid as u64;
    clone_after.orig_rax = libc::SYS_clone as u64;
    assert_eq!(kernel.selected.after, clone_after);
    let tasks = BTreeSet::from([first.before_task.task, second.before_task.task]);
    assert_eq!(tasks.len(), 2);
    assert!(tasks.contains(&initial.task.task));
    for done in [&first, &second] {
        let input = done.selected.input.registers();
        assert_eq!(input.rip, next);
        let mut expected = clone_after;
        expected.orig_rax = u64::MAX;
        if done.before_task.task != initial.task.task {
            expected.rax = 0;
            expected.rsp = STACK;
        }
        assert_eq!(*input, expected);
        assert_eq!(
            done.selected.after,
            expected_cpuid(expected, [0x12345678, 0x87654321, 0x10203040, 0xfedcba98])
        );
        assert_eq!(done.selected.before_xstate, initial.xstate);
        assert_eq!(done.selected.xstate, initial.xstate);
        assert_eq!(done.before_signal_mask, initial.signal_mask);
        assert_eq!(done.signal_mask, initial.signal_mask);
        assert_eq!(done.before_task.process, initial.task.process);
        assert_eq!(done.before_task.address_space, initial.task.address_space);
        assert_eq!(
            session
                .read_memory(done.before_task.task, DATA, 2 * PAGE)
                .unwrap(),
            data
        );
    }
    assert_eq!(session.provider().calls, 3);
    // The next page starts NX after the completed clone. Both tasks must
    // generate their own authenticated fetch fault before either first CPUID.
    let metrics = session.metrics().unwrap();
    assert_eq!(metrics.fetch_faults, 3);
    assert_eq!(metrics.guard_stops, 3);
    let leader = session.pid();
    let receipt = session.terminate(TIMEOUT).unwrap();
    let mut expected_reaped = vec![leader, newborn.tid];
    expected_reaped.sort_unstable();
    let mut actual_reaped = receipt.reaped;
    actual_reaped.sort_unstable();
    assert_eq!(actual_reaped, expected_reaped);
    assert_reaped(&pin);
    assert_reaped(&child_pin);
}

#[test]
fn default_rdpid_requires_explicit_coverage_and_keeps_all_registers() {
    let directory = Directory::new();
    let mut image = Image::new(BASE, 2);
    image.emit(&[0xf3, 0x0f, 0xc7, 0xf8]);
    image.spin();
    let path = image.write(&directory, "rdpid");
    struct Rdpid(usize);
    impl InstructionProvider for Rdpid {
        fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
            assert_eq!(input.instruction().bytes(), [0xf3, 0x0f, 0xc7, 0xf8]);
            self.0 += 1;
            Ok(ProviderDecision::Complete(SelectedResult::Rdpid {
                auxiliary: 0x12345678,
            }))
        }
    }
    let mut strict = launch(
        &path,
        vec![image.facts()],
        DynamicAdmissionOptions::default(),
        Rdpid(0),
    );
    let strict_pin = pin(strict.pid());
    let error = strict.next_event().unwrap_err();
    let GateError::Scan(obligations) = error else {
        panic!("strict RDPID failed outside its scanner obligation: {error:?}")
    };
    assert!(obligations.iter().any(|obligation| matches!(obligation,liteinst_admission::scan::Obligation::EmbeddedCandidate(address) if *address==BASE+PAGE as u64+1)));
    assert_eq!(strict.provider().0, 0);
    assert!(strict.is_closed());
    cleanup(strict, &strict_pin);
    let options = DynamicAdmissionOptions {
        backend: DynamicAdmissionBackend::CoverageTrap(TrapCoverageBudget::default()),
        ..DynamicAdmissionOptions::default()
    };
    let mut covered = launch(&path, vec![image.facts()], options, Rdpid(0));
    let covered_pin = pin(covered.pid());
    let before = covered.initial_state().clone();
    let done = completion(&mut covered);
    let mut after = before.registers;
    after.rax = 0x12345678;
    after.rip += 4;
    assert_eq!(done.selected.input.registers(), &before.registers);
    assert_eq!(done.selected.after, after);
    assert_eq!(done.selected.before_xstate, before.xstate);
    assert_eq!(done.selected.xstate, before.xstate);
    assert_eq!(done.before_signal_mask, before.signal_mask);
    assert_eq!(done.signal_mask, before.signal_mask);
    assert_eq!(covered.provider().0, 1);
    // This also audits retained embedded guards after the completion rebind.
    let metrics = covered.metrics().unwrap();
    assert_eq!(metrics.fetch_faults, 1);
    assert_eq!(metrics.guard_stops, 1);
    assert_eq!(metrics.generation_changes, 1);
    cleanup(covered, &covered_pin);
}

#[test]
fn forbidden_native_mapping_syscall_closes_before_any_kernel_effect() {
    let directory = Directory::new();
    let mut image = Image::new(BASE, 2);
    image.mov(0, libc::SYS_mprotect as u64);
    image.mov(7, DATA);
    image.mov(6, PAGE as u64);
    image.mov(2, libc::PROT_NONE as u64);
    image.emit(&[0x0f, 0x05]);
    image.spin();
    let path = image.write(&directory, "mapping");
    let mut session = launch(
        &path,
        vec![image.facts()],
        DynamicAdmissionOptions::default(),
        NativeProvider,
    );
    let pin = pin(session.pid());
    assert!(matches!(
        session.next_event(),
        Err(GateError::Refused(
            "dynamic selected syscall has unqualified effects"
        ))
    ));
    assert!(session.is_closed());
    cleanup(session, &pin);
}

#[test]
fn provider_panic_cancels_actual_owner_and_physically_reaps() {
    let directory = Directory::new();
    let mut image = Image::new(BASE, 2);
    image.emit(&[0x0f, 0xa2]);
    image.spin();
    let path = image.write(&directory, "panic");
    struct Panic(usize);
    impl InstructionProvider for Panic {
        fn decide(&mut self, _: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
            self.0 += 1;
            panic!("intentional native admission provider panic")
        }
    }
    let mut session = launch(
        &path,
        vec![image.facts()],
        DynamicAdmissionOptions::default(),
        Panic(0),
    );
    let pin = pin(session.pid());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| session.next_event()))
        .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"intentional native admission provider panic")
    );
    assert_eq!(session.provider().0, 1);
    assert!(session.is_closed());
    cleanup(session, &pin);
}

#[test]
fn blocked_provider_observes_owner_cleanup_before_returning_a_decision() {
    let directory = Directory::new();
    let mut image = Image::new(BASE, 2);
    image.emit(&[0x0f, 0xa2]);
    image.spin();
    let path = image.write(&directory, "blocked");
    struct Blocked {
        pin: Option<OwnedFd>,
        calls: usize,
    }
    impl InstructionProvider for Blocked {
        fn decide(&mut self, _: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
            self.calls += 1;
            let pin = self.pin.as_ref().unwrap();
            let until = Instant::now() + TIMEOUT + TIMEOUT;
            loop {
                let mut poll = libc::pollfd {
                    fd: pin.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                assert!(unsafe { libc::poll(&raw mut poll, 1, 20) } >= 0);
                if poll.revents & libc::POLLHUP != 0 {
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "owner did not independently expire the pending provider"
                );
            }
            assert_reaped(pin);
            Ok(ProviderDecision::Native)
        }
    }
    let mut session = launch(
        &path,
        vec![image.facts()],
        DynamicAdmissionOptions::default(),
        Blocked {
            pin: None,
            calls: 0,
        },
    );
    let pin = pin(session.pid());
    let duplicated = unsafe { libc::fcntl(pin.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    assert!(duplicated >= 0);
    session.provider_mut().pin = Some(unsafe { OwnedFd::from_raw_fd(duplicated) });
    assert!(matches!(
        session.next_event(),
        Err(GateError::Control(LaunchError::Timeout(
            "dynamic admission provider"
        )))
    ));
    assert_eq!(session.provider().calls, 1);
    assert!(session.is_closed());
    cleanup(session, &pin);
}

#[path = "support/dynamic_admission_matrix.rs"]
mod matrix;

#[path = "support/dynamic_admission_call.rs"]
mod call_boundary;
