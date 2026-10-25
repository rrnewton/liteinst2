#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Hand-authored closed-world ELF programs. The native differential observer
//! below uses its own ptrace operations, not the remote-control or page-gate API.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use liteinst_admission::AddressRange;
use liteinst_admission::scan::{Policy, SiteClass};
use liteinst_launch::gate::{GateError, GateEvent, ImageFacts, Observation, SingleThreadPageGate};
use liteinst_launch::{ExecCheckpoint, LaunchCommand, LaunchError, RegisterSnapshot};

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const TIMEOUT: Duration = Duration::from_secs(3);
const CPUID: &[u8] = &[0x0f, 0xa2];
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);
// A concurrent fork must not inherit another test's writable fixture FD.
// CLOEXEC alone leaves that FD live until the other child completes exec.
// Hold this only across file writes/close and child launch, never execution.
static FIXTURE_FORK_LOCK: Mutex<()> = Mutex::new(());

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-tmp");
        fs::create_dir_all(&root).unwrap();
        for _ in 0..100 {
            let path = root.join(format!(
                "page-gate-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("fixture directory: {error}"),
            }
        }
        panic!("fixture directory allocation exhausted");
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct ElfBuilder {
    bytes: Vec<u8>,
    heads: BTreeSet<usize>,
    cursor: usize,
    entry: usize,
    pie: bool,
}

impl ElfBuilder {
    fn new(pages: usize, entry: usize, pie: bool) -> Self {
        assert!(pages >= 2 && entry >= PAGE && entry < pages * PAGE);
        let mut bytes = vec![0xcc; pages * PAGE];
        bytes[..PAGE].fill(0);
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, if pie { 3 } else { 2 });
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        let base = if pie { 0 } else { BASE };
        put64(&mut bytes, 24, base + entry as u64);
        put64(&mut bytes, 32, 64);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 54, 56);
        put16(&mut bytes, 56, 2);
        // One private RX PT_LOAD contains the headers and all code pages.
        put32(&mut bytes, 64, 1);
        put32(&mut bytes, 68, 5);
        put64(&mut bytes, 80, base);
        put64(&mut bytes, 96, (pages * PAGE) as u64);
        put64(&mut bytes, 104, (pages * PAGE) as u64);
        put64(&mut bytes, 112, PAGE as u64);
        // Explicit non-executable stack; tests never depend on ELF defaults.
        put32(&mut bytes, 120, 0x6474_e551);
        put32(&mut bytes, 124, 6);
        put64(&mut bytes, 168, 16);
        Self {
            bytes,
            heads: BTreeSet::new(),
            cursor: entry,
            entry,
            pie,
        }
    }

    fn seek(&mut self, offset: usize) {
        assert!(offset >= PAGE && offset < self.bytes.len());
        self.cursor = offset;
    }

    /// Each call supplies exactly one manually encoded reachable instruction.
    /// Padding and mapped ELF headers are not executable instruction streams.
    fn push_instruction(&mut self, instruction: &[u8]) -> usize {
        assert!(!instruction.is_empty());
        let start = self.cursor;
        assert!(self.heads.insert(start), "duplicate fixture head");
        self.bytes[start..start + instruction.len()].copy_from_slice(instruction);
        self.cursor += instruction.len();
        start
    }

    fn relative(&mut self, opcode: u8, destination: usize) -> usize {
        let displacement = i32::try_from(destination as i64 - (self.cursor + 5) as i64).unwrap();
        let mut bytes = vec![opcode];
        bytes.extend_from_slice(&displacement.to_le_bytes());
        self.push_instruction(&bytes)
    }

    fn mov64(&mut self, register: u8, value: u64) {
        assert!(register < 16);
        let mut bytes = vec![0x48 | (register >> 3), 0xb8 | (register & 7)];
        bytes.extend_from_slice(&value.to_le_bytes());
        self.push_instruction(&bytes);
    }

    fn exit(&mut self, code: u32) {
        let mut status = vec![0xbf]; // mov edi, imm32
        status.extend_from_slice(&code.to_le_bytes());
        self.push_instruction(&status);
        self.push_instruction(&[0xb8, 60, 0, 0, 0]); // mov eax, SYS_exit
        self.push_instruction(&[0x0f, 0x05]);
    }

    fn write(
        mut self,
        directory: &FixtureDirectory,
        name: &str,
        interpreter: Option<&Path>,
    ) -> ElfImage {
        if let Some(interpreter) = interpreter {
            let name = interpreter.as_os_str().as_bytes();
            assert!(name.len() < 2048);
            put16(&mut self.bytes, 56, 3);
            put32(&mut self.bytes, 176, 3); // PT_INTERP
            put32(&mut self.bytes, 180, 4);
            put64(&mut self.bytes, 184, 512);
            put64(
                &mut self.bytes,
                192,
                if self.pie { 512 } else { BASE + 512 },
            );
            put64(&mut self.bytes, 208, (name.len() + 1) as u64);
            put64(&mut self.bytes, 216, (name.len() + 1) as u64);
            put64(&mut self.bytes, 224, 1);
            self.bytes[512..512 + name.len()].copy_from_slice(name);
        }
        let path = directory.0.join(name);
        let _fork_guard = FIXTURE_FORK_LOCK.lock().unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&self.bytes).unwrap();
        drop(file);
        ElfImage {
            path,
            bytes: self.bytes,
            heads: self.heads,
            entry: self.entry,
        }
    }
}

struct ElfImage {
    path: PathBuf,
    bytes: Vec<u8>,
    heads: BTreeSet<usize>,
    entry: usize,
}

impl ElfImage {
    fn facts(&self, base: u64) -> ImageFacts {
        ImageFacts {
            start: base,
            bytes: self.bytes.clone(),
            heads: self
                .heads
                .iter()
                .map(|offset| base + *offset as u64)
                .collect(),
        }
    }
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

fn checkpoint(image: &ElfImage) -> ExecCheckpoint {
    let _fork_guard = FIXTURE_FORK_LOCK.lock().unwrap();
    let checkpoint = ExecCheckpoint::launch(&LaunchCommand::new(&image.path), TIMEOUT).unwrap();
    assert_eq!(
        checkpoint.entries().executable_entry,
        BASE + image.entry as u64
    );
    checkpoint
}

fn gate(checkpoint: ExecCheckpoint, facts: Vec<ImageFacts>) -> SingleThreadPageGate {
    gate_with_timeout(checkpoint, facts, TIMEOUT)
}

fn gate_with_timeout(
    checkpoint: ExecCheckpoint,
    facts: Vec<ImageFacts>,
    timeout: Duration,
) -> SingleThreadPageGate {
    // SAFETY: these private, uniquely named fixture files have no external
    // writer or writable alias. The closed-world hand-authored programs have
    // exactly the supplied heads, one task, no signal handlers or executable
    // stores, and no PKRU changes. This test is their sole tracer/reaper. Every
    // indirect transfer has a fixed declared target. The denied-syscall tests
    // deliberately test the controller's refusal before lifecycle changes.
    unsafe {
        SingleThreadPageGate::new(
            checkpoint,
            facts,
            Policy {
                version: 1,
                selected: [SiteClass::Cpuid].into_iter().collect(),
            },
            timeout,
        )
    }
    .unwrap()
}

fn observe(gate: &mut SingleThreadPageGate) -> Observation {
    match gate.next_event().unwrap() {
        GateEvent::Observe(observation) => observation,
        other => panic!("expected selected-instruction observation, got {other:?}"),
    }
}

fn assert_exit(gate: &mut SingleThreadPageGate, expected: i32) {
    match gate.next_event().unwrap() {
        GateEvent::Exited(code) => assert_eq!(code, expected),
        other => panic!("expected exit {expected}, got {other:?}"),
    }
}

fn assert_kernel_nx(pid: libc::pid_t, address: u64) {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next().unwrap().split_once('-').unwrap();
        let start = u64::from_str_radix(start, 16).unwrap();
        let end = u64::from_str_radix(end, 16).unwrap();
        if start <= address && address < end {
            assert_ne!(
                fields.next().unwrap().as_bytes()[2],
                b'x',
                "page is executable"
            );
            return;
        }
    }
    panic!("expected NX mapping at {address:#x}");
}

#[test]
fn cpuid_at_the_first_instruction_is_observed_before_execution_then_exits() {
    let directory = FixtureDirectory::new();
    let mut builder = ElfBuilder::new(2, PAGE, false);
    builder.push_instruction(CPUID);
    builder.exit(23);
    let image = builder.write(&directory, "first-cpuid", None);
    let checkpoint = checkpoint(&image);
    let initial = *checkpoint.initial_registers();
    let mut gate = gate(checkpoint, vec![image.facts(BASE)]);
    assert!(!gate.is_admitted(initial.rip));
    assert_kernel_nx(gate.pid(), initial.rip);
    let observation = observe(&mut gate);
    assert_eq!(observation.site.address, BASE + PAGE as u64);
    assert_eq!(observation.site.class, SiteClass::Cpuid);
    assert_eq!(observation.registers.rip, initial.rip);
    // The kernel exec event precedes exec's successful syscall return. The
    // independent untraced first_user_instruction_observes_natural_successful_exec_result
    // regression in checkpoint.rs calibrates the actual first-user RAX as zero.
    assert_eq!(initial.rax, (-i64::from(libc::ENOSYS)) as u64);
    assert_eq!(observation.registers.rax, 0);
    assert_eq!(observation.registers.rbx, initial.rbx);
    assert_eq!(observation.registers.rcx, initial.rcx);
    assert_eq!(observation.registers.rdx, initial.rdx);
    assert_eq!(gate.metrics().observations, 1);
    assert_eq!(gate.metrics().admitted_pages, 1);
    assert_exit(&mut gate, 23);
    assert_eq!(gate.metrics().observations, 1);
    assert_eq!(gate.metrics().first_touch.len(), 1);
}

#[test]
fn custom_interpreter_and_main_are_both_observed_at_instruction_one() {
    let directory = FixtureDirectory::new();
    let mut interpreter = ElfBuilder::new(2, PAGE, true);
    interpreter.push_instruction(CPUID);
    interpreter.mov64(0, BASE + PAGE as u64);
    interpreter.push_instruction(&[0xff, 0xe0]); // jmp rax, the main's declared entry
    let interpreter = interpreter.write(&directory, "interpreter", None);
    let mut main = ElfBuilder::new(2, PAGE, false);
    main.push_instruction(CPUID);
    main.exit(29);
    let main = main.write(&directory, "main", Some(&interpreter.path));
    let checkpoint = checkpoint(&main);
    let interpreter_base = checkpoint.entries().interpreter_base;
    assert_ne!(interpreter_base, 0);
    let mut gate = gate(
        checkpoint,
        vec![main.facts(BASE), interpreter.facts(interpreter_base)],
    );
    let first = observe(&mut gate);
    assert_eq!(first.site.address, interpreter_base + PAGE as u64);
    assert!(!gate.is_admitted(BASE + PAGE as u64));
    assert_kernel_nx(gate.pid(), BASE + PAGE as u64);
    let second = observe(&mut gate);
    assert_eq!(second.site.address, BASE + PAGE as u64);
    assert_eq!(gate.metrics().observations, 2);
    assert_eq!(gate.metrics().admitted_pages, 2);
    assert_exit(&mut gate, 29);
    assert_eq!(gate.metrics().observations, 2);
    assert_eq!(gate.metrics().first_touch.len(), 2);
}

#[test]
fn selected_instruction_split_across_pages_admits_both_pages_once() {
    let directory = FixtureDirectory::new();
    let start = 2 * PAGE - 1;
    let mut builder = ElfBuilder::new(3, start, false);
    builder.push_instruction(CPUID);
    builder.exit(31);
    let image = builder.write(&directory, "split-cpuid", None);
    let mut gate = gate(checkpoint(&image), vec![image.facts(BASE)]);
    assert_kernel_nx(gate.pid(), BASE + start as u64);
    assert_kernel_nx(gate.pid(), BASE + start as u64 + 1);
    let observation = observe(&mut gate);
    assert_eq!(observation.site.address, BASE + start as u64);
    assert_eq!(observation.site.len, 2);
    assert!(gate.is_admitted(BASE + start as u64));
    assert!(gate.is_admitted(BASE + start as u64 + 1));
    assert_eq!(gate.metrics().admitted_pages, 2);
    assert_eq!(gate.metrics().observations, 1);
    assert_exit(&mut gate, 31);
    assert_eq!(gate.metrics().admitted_pages, 2);
    assert_eq!(gate.metrics().observations, 1);
}

fn call_boundary_fixture(
    directory: &FixtureDirectory,
    selected_destination: bool,
) -> (ElfImage, u64, u64) {
    let call = 2 * PAGE - 5;
    let callee = PAGE + 64;
    let mut builder = ElfBuilder::new(3, PAGE, false);
    builder.relative(0xe9, call);
    builder.seek(callee);
    builder.push_instruction(CPUID);
    builder.push_instruction(&[0xc3]);
    builder.seek(call);
    builder.relative(0xe8, callee);
    assert_eq!(builder.cursor, 2 * PAGE);
    if selected_destination {
        builder.push_instruction(CPUID);
    }
    builder.exit(37);
    (
        builder.write(directory, "boundary-call", None),
        BASE + call as u64,
        BASE + callee as u64,
    )
}

fn check_live_return(gate: &mut SingleThreadPageGate, call: u64, callee: u64) {
    let destination = BASE + (2 * PAGE) as u64;
    let observation = observe(gate);
    assert_eq!(observation.site.address, callee);
    assert!(!gate.is_admitted(destination));
    assert_kernel_nx(gate.pid(), destination);
    let stack: [u8; 8] = gate
        .read_memory(observation.registers.rsp, 8)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(u64::from_le_bytes(stack), destination);
    let obligations: Vec<_> = gate
        .call_returns()
        .obligations_in(AddressRange::new(destination, destination + PAGE as u64).unwrap())
        .collect();
    assert_eq!(obligations.len(), 1);
    assert_eq!(obligations[0].call_address, call);
    assert_eq!(obligations[0].return_pc, destination);
    assert_eq!(obligations[0].call_bytes[0], 0xe8);
    assert_eq!(gate.metrics().observations, 1);
}

#[test]
fn call_records_return_into_never_executed_nx_page_and_plain_return_completes() {
    let directory = FixtureDirectory::new();
    let (image, call, callee) = call_boundary_fixture(&directory, false);
    let mut gate = gate(checkpoint(&image), vec![image.facts(BASE)]);
    check_live_return(&mut gate, call, callee);
    assert_exit(&mut gate, 37);
    assert_eq!(gate.metrics().admitted_pages, 2);
    assert_eq!(gate.metrics().observations, 1);
}

#[test]
fn selected_destination_with_saved_call_return_is_refused_while_still_nx() {
    let directory = FixtureDirectory::new();
    let (image, call, callee) = call_boundary_fixture(&directory, true);
    let mut gate = gate(checkpoint(&image), vec![image.facts(BASE)]);
    check_live_return(&mut gate, call, callee);
    assert!(matches!(
        gate.next_event(),
        Err(GateError::Refused(
            "potential saved CALL return intersects selected publication"
        ))
    ));
    let destination = BASE + (2 * PAGE) as u64;
    assert!(!gate.is_admitted(destination));
    assert_kernel_nx(gate.pid(), destination);
    assert_eq!(gate.read_registers().unwrap().rip, destination);
    assert_eq!(gate.read_memory(destination, CPUID.len()).unwrap(), CPUID);
    assert_eq!(gate.metrics().observations, 1);
    assert!(
        gate.next_event().is_err(),
        "refused execution must remain closed"
    );
}

#[test]
fn unselected_mmap_and_clone_syscalls_are_refused_before_kernel_execution() {
    for number in [libc::SYS_mmap, libc::SYS_clone] {
        let directory = FixtureDirectory::new();
        let mut builder = ElfBuilder::new(2, PAGE, false);
        builder.mov64(0, number as u64);
        // Invalid clone flags prevent descendant creation even if a broken
        // controller accidentally executes it; either syscall must be refused
        // by number before the kernel can return EINVAL/EBADF or create a VMA.
        builder.mov64(7, u64::MAX);
        builder.mov64(6, PAGE as u64);
        builder.push_instruction(&[0x0f, 0x05]);
        builder.exit(41);
        let image = builder.write(&directory, "denied-syscall", None);
        let mut gate = gate(checkpoint(&image), vec![image.facts(BASE)]);
        assert!(matches!(
            gate.next_event(),
            Err(GateError::Control(LaunchError::Invalid(
                "syscall is outside the single-task launch allowlist"
            )))
        ));
        assert_eq!(
            gate.metrics().observations,
            0,
            "syscall was deliberately unselected"
        );
        assert!(
            gate.next_event().is_err(),
            "denied syscall cannot be retried"
        );
    }
}

#[test]
fn selected_syscall_remains_selected_and_is_refused_before_any_original_instruction() {
    let directory = FixtureDirectory::new();
    let mut builder = ElfBuilder::new(2, PAGE, false);
    builder.exit(43);
    let image = builder.write(&directory, "selected-syscall", None);

    // Positive control: these original bytes exit successfully under the
    // independent observer; an invalid fixture cannot explain the gate refusal.
    let mut native = NativeTrace::launch(&image.path);
    trace(libc::PTRACE_CONT, native.pid(), 0, 0);
    let status = native.wait();
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 43);

    // SAFETY: the same private closed-world fixture contract as gate() applies.
    // This program contains only declared register moves and the native exit
    // syscall. The policy explicitly selects that syscall; it is not hidden by
    // omitting its instruction class from the scan.
    let mut gate = unsafe {
        SingleThreadPageGate::new(
            checkpoint(&image),
            vec![image.facts(BASE)],
            Policy {
                version: 1,
                selected: [SiteClass::Syscall].into_iter().collect(),
            },
            TIMEOUT,
        )
    }
    .unwrap();
    let before = gate.read_registers().unwrap();
    assert_eq!(before.rip, BASE + PAGE as u64);
    assert_eq!(
        gate.read_memory(BASE, image.bytes.len()).unwrap(),
        image.bytes
    );
    assert!(matches!(
        gate.next_event(),
        Err(GateError::Refused(
            "selected class lacks reference single-step qualification"
        ))
    ));
    let after = gate.read_registers().unwrap();
    assert_eq!(after.rip, before.rip);
    assert_eq!(after.rdi, before.rdi); // The first mov edi,43 has not run.
    assert_ne!(after.rdi, 43);
    assert_eq!(after.rax, before.rax);
    assert_eq!(
        gate.read_memory(BASE, image.bytes.len()).unwrap(),
        image.bytes
    );
    assert_kernel_nx(gate.pid(), after.rip);
    assert_eq!(gate.metrics().admitted_pages, 0);
    assert_eq!(gate.metrics().observations, 0);
    assert!(
        gate.next_event().is_err(),
        "class refusal must remain closed"
    );
}

#[test]
fn repeated_allowed_syscall_stops_do_not_restart_the_whole_event_deadline() {
    let directory = FixtureDirectory::new();
    let mut builder = ElfBuilder::new(2, PAGE, false);
    builder.push_instruction(&[0xb8, 39, 0, 0, 0]); // mov eax, SYS_getpid
    builder.push_instruction(&[0x0f, 0x05]);
    builder.relative(0xe9, PAGE);
    let image = builder.write(&directory, "getpid-loop", None);
    let budget = Duration::from_millis(250);
    let hard_limit = budget + Duration::from_secs(2);
    let mut gate = gate_with_timeout(checkpoint(&image), vec![image.facts(BASE)], budget);

    // A regression must fail within a bound even if next_event never returns.
    // The pidfd binds the watchdog to this child, avoiding a PID-reuse race.
    // SAFETY: pidfd_open takes the owned child's ID and zero flags.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, gate.pid(), 0) };
    assert!(
        descriptor >= 0,
        "pidfd_open: {}",
        io::Error::last_os_error()
    );
    // SAFETY: pidfd_open returned one new owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
    let (complete, waiting) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        if waiting.recv_timeout(hard_limit) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
            // SAFETY: the stable descriptor identifies only this owned child;
            // no siginfo is supplied and the flags are zero.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
            true
        } else {
            false
        }
    });
    let start = Instant::now();
    let event = gate.next_event();
    let elapsed = start.elapsed();
    let _ = complete.send(());
    assert!(
        !watchdog.join().unwrap(),
        "whole-event deadline needed external watchdog"
    );
    assert!(
        elapsed < hard_limit,
        "whole-event deadline exceeded fixed cleanup margin: {elapsed:?}"
    );
    assert!(
        matches!(
            event,
            Err(GateError::Refused("whole-event deadline exhausted"))
                | Err(GateError::Control(LaunchError::Timeout(_)))
        ),
        "getpid loop did not stop at its deadline: {event:?}"
    );
    assert_eq!(gate.metrics().observations, 0);
    assert!(
        gate.next_event().is_err(),
        "timeout must permanently close execution"
    );
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TerminalEvidence {
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    initialized_stack: Vec<u8>,
}

impl TerminalEvidence {
    fn normalize_declared_stack_address(mut self, entry_rsp: u64) -> (i128, Self) {
        // Each fresh exec chooses its stack address independently. The fixture
        // leaves no stack-derived address in another GPR or in the compared
        // memory. Preserve the exact signed change from that run's entry RSP;
        // only the absolute address is normalized. All flags, segments, other
        // GPRs, xstate bytes and initialized stack bytes remain exact.
        let stack_delta = i128::from(self.registers.rsp) - i128::from(entry_rsp);
        self.registers.rsp = 0;
        (stack_delta, self)
    }
}

#[test]
fn no_op_cpuid_observer_matches_independent_native_gprs_xstate_and_memory() {
    let directory = FixtureDirectory::new();
    let mut builder = ElfBuilder::new(2, PAGE, false);
    builder.push_instruction(&[0x48, 0x83, 0xec, 0x20]); // sub rsp, 32
    for (offset, value) in [
        (0, 0x1122_3344_u32),
        (8, 0x5566_7788),
        (16, 0x1357_2468),
        (24, 0x0246_1357),
    ] {
        let mut bytes = vec![0x48, 0xc7, 0x44, 0x24, offset];
        bytes.extend_from_slice(&value.to_le_bytes());
        builder.push_instruction(&bytes);
    }
    builder.push_instruction(&[0xdb, 0xe3]); // fninit
    builder.push_instruction(&[0xd9, 0xe8]); // fld1: nontrivial, fixed x87 state
    builder.push_instruction(&[0x66, 0x0f, 0x76, 0xc9]); // pcmpeqd xmm1, xmm1
    builder.push_instruction(&[0x66, 0x0f, 0x6f, 0xd1]); // movdqa xmm2, xmm1
    for register in 0..16 {
        if register != 4 {
            builder.mov64(
                register,
                if matches!(register, 0 | 1) {
                    0
                } else {
                    0x1000 + u64::from(register)
                },
            );
        }
    }
    builder.push_instruction(&[0x68, 0x02, 0x02, 0, 0]); // push 0x202
    builder.push_instruction(&[0x9d]); // popfq: fixed arithmetic flags
    let cpuid = builder.push_instruction(CPUID);
    builder.push_instruction(&[0x48, 0x89, 0x04, 0x24]); // mov [rsp], rax
    builder.push_instruction(&[0x48, 0x89, 0x5c, 0x24, 8]); // mov [rsp+8], rbx
    builder.push_instruction(&[0x48, 0x89, 0x4c, 0x24, 16]); // mov [rsp+16], rcx
    builder.push_instruction(&[0x48, 0x89, 0x54, 0x24, 24]); // mov [rsp+24], rdx
    let terminal = builder.push_instruction(&[0x0f, 0x0b]); // UD2, never swallowed
    let image = builder.write(&directory, "differential", None);

    let mut native = NativeTrace::launch(&image.path);
    let native_entry_rsp = native.registers().rsp;
    native.run_to_ud2(BASE + terminal as u64);
    let native_registers = native.registers();
    let native_evidence = TerminalEvidence {
        registers: native_registers,
        xstate: native.xstate(),
        initialized_stack: native.memory(native_registers.rsp, 32),
    };

    let checkpoint = checkpoint(&image);
    let gated_entry_rsp = checkpoint.initial_registers().rsp;
    let mut gate = gate(checkpoint, vec![image.facts(BASE)]);
    let observation = observe(&mut gate);
    assert_eq!(observation.site.address, BASE + cpuid as u64);
    assert_eq!(
        observation.registers.rax, 0,
        "CPUID leaf zero is deterministic"
    );
    assert_eq!(observation.registers.rcx, 0);
    let registers = match gate.next_event().unwrap() {
        GateEvent::ApplicationSignal {
            signal, registers, ..
        } => {
            assert_eq!(signal, libc::SIGILL);
            assert_eq!(registers.rip, BASE + terminal as u64);
            registers
        }
        other => panic!("expected owned fixture's terminal UD2, got {other:?}"),
    };
    let gated_evidence = TerminalEvidence {
        registers,
        xstate: gate.read_xstate().unwrap(),
        initialized_stack: gate.read_memory(registers.rsp, 32).unwrap(),
    };
    assert_eq!(gate.metrics().observations, 1);
    assert_eq!(
        native_evidence.registers.rsp % 16,
        gated_evidence.registers.rsp % 16
    );
    let mut wrong_rsp = native_evidence.clone();
    wrong_rsp.registers.rsp += 16;
    let wrong_rsp = wrong_rsp.normalize_declared_stack_address(native_entry_rsp);
    let native_evidence = native_evidence.normalize_declared_stack_address(native_entry_rsp);
    let gated_evidence = gated_evidence.normalize_declared_stack_address(gated_entry_rsp);
    assert_eq!(native_evidence.0, -32, "native fixture's exact RSP delta");
    assert_eq!(gated_evidence.0, -32, "gated fixture's exact RSP delta");
    assert_eq!(gated_evidence, native_evidence);
    assert_ne!(gated_evidence, wrong_rsp, "RSP+16 must remain observable");

    // Negative controls ensure the exact comparison observes each state class.
    let mut wrong = native_evidence.clone();
    wrong.1.registers.r12 ^= 1;
    assert_ne!(gated_evidence, wrong);
    let mut wrong = native_evidence.clone();
    wrong.1.xstate[160] ^= 1; // First XMM0 byte in the architectural legacy area.
    assert_ne!(gated_evidence, wrong);
    let mut wrong = native_evidence;
    wrong.1.initialized_stack[0] ^= 1;
    assert_ne!(gated_evidence, wrong);
}

/// Independent native observer. It does not create a syscall island, gate pages,
/// install traps, use a production wait loop, or obtain state from the gate.
struct NativeTrace {
    child: Option<Child>,
    reaped: bool,
}

impl NativeTrace {
    fn launch(path: &Path) -> Self {
        let _fork_guard = FIXTURE_FORK_LOCK.lock().unwrap();
        let mut command = Command::new(path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the post-fork closure only invokes ptrace and reads errno;
        // Command performs exec. No Rust allocation or user locks are used.
        unsafe {
            command.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut result = Self {
            child: Some(command.spawn().unwrap()),
            reaped: false,
        };
        let status = result.wait();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        trace(
            libc::PTRACE_SETOPTIONS,
            result.pid(),
            0,
            libc::PTRACE_O_EXITKILL as usize,
        );
        result
    }

    fn pid(&self) -> libc::pid_t {
        self.child.as_ref().unwrap().id() as libc::pid_t
    }

    fn wait(&mut self) -> i32 {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let mut status = 0;
            // SAFETY: this observer exclusively owns the named child and status.
            let result =
                unsafe { libc::waitpid(self.pid(), &mut status, libc::WNOHANG | libc::__WALL) };
            if result == self.pid() {
                self.reaped = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                return status;
            }
            if result == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EINTR) {
                    self.reaped = error.raw_os_error() == Some(libc::ECHILD);
                    panic!("native waitpid: {error}");
                }
            }
            assert!(
                Instant::now() < deadline,
                "native observer wait exceeded deadline"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn run_to_ud2(&mut self, expected: u64) {
        trace(libc::PTRACE_CONT, self.pid(), 0, 0);
        let status = self.wait();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGILL);
        assert_eq!(self.registers().rip, expected);
    }

    fn registers(&self) -> RegisterSnapshot {
        let mut raw = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
        trace(
            libc::PTRACE_GETREGS,
            self.pid(),
            0,
            raw.as_mut_ptr() as usize,
        );
        // SAFETY: GETREGS successfully initialized the complete kernel structure.
        unsafe { raw.assume_init() }.into()
    }

    fn xstate(&self) -> Vec<u8> {
        let mut bytes = vec![0; 64 * 1024];
        let mut vector = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        trace(
            libc::PTRACE_GETREGSET,
            self.pid(),
            0x202,
            (&raw mut vector) as usize,
        );
        assert!(vector.iov_len >= 512 && vector.iov_len < bytes.len());
        bytes.truncate(vector.iov_len);
        bytes
    }

    fn memory(&self, address: u64, len: usize) -> Vec<u8> {
        assert_eq!(address % 8, 0);
        assert_eq!(len % 8, 0);
        let mut bytes = Vec::new();
        for offset in (0..len).step_by(8) {
            // SAFETY: errno is thread-local and PEEKDATA only reads the owned,
            // stopped native child. No tracee address is locally dereferenced.
            let word = unsafe {
                *libc::__errno_location() = 0;
                let value = libc::ptrace(
                    libc::PTRACE_PEEKDATA,
                    self.pid(),
                    address as usize + offset,
                    0,
                );
                assert!(value != -1 || *libc::__errno_location() == 0);
                value as u64
            };
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

impl Drop for NativeTrace {
    fn drop(&mut self) {
        if !self.reaped {
            if let Some(child) = self.child.take() {
                reap_native_child(child);
            }
        }
    }
}

// Takes cleanup ownership, including the exceptional delayed-reap handoff.
fn reap_native_child(mut child: Child) {
    let _ = child.kill();
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let mut status = 0;
        // SAFETY: cleanup retains exclusive ownership of this child only.
        let result = unsafe {
            libc::waitpid(
                child.id() as libc::pid_t,
                &mut status,
                libc::WNOHANG | libc::__WALL,
            )
        };
        if result > 0 && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            // Our raw ptrace wait consumed the terminal status. Reconcile
            // std's Child owner as well; ECHILD is expected and nonblocking.
            let _ = child.wait();
            return;
        }
        if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
            let _ = child.wait();
            return;
        }
        if Instant::now() >= deadline {
            // Retain cleanup ownership if kernel exit is unexpectedly slow.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn trace(request: u32, pid: libc::pid_t, address: usize, data: usize) {
    // SAFETY: callers own a stopped child and supply request-valid local output
    // storage or scalar ptrace arguments. This is independent native test code.
    let result = unsafe { libc::ptrace(request, pid, address, data) };
    assert_ne!(
        result,
        -1,
        "native ptrace {request}: {}",
        io::Error::last_os_error()
    );
}

fn core_gate(checkpoint: ExecCheckpoint, facts: Vec<ImageFacts>) -> SingleThreadPageGate {
    // SAFETY: the private, hand-authored fixtures satisfy the same closed-world
    // contract as gate(): exhaustive reachable heads, one task, no external
    // writers/aliases, no code-as-data reads, and no signal or mapping lifecycle
    // changes. The gate alone owns publication and all child execution.
    unsafe {
        SingleThreadPageGate::new_core(
            checkpoint,
            facts,
            Policy {
                version: 1,
                selected: [SiteClass::Cpuid].into_iter().collect(),
            },
            TIMEOUT,
        )
    }
    .unwrap()
}

fn assert_published_cpuid_pun(
    gate: &SingleThreadPageGate,
    image: &ElfImage,
    base: u64,
    offset: usize,
) {
    // The real core uses a two-byte source MOV to form E9 with three unchanged
    // successor bytes. A source INT3 reference cannot satisfy this evidence.
    let original = &image.bytes[offset..offset + 5];
    assert_eq!(&original[..2], CPUID);
    let published = gate.read_memory(base + offset as u64, 5).unwrap();
    assert_eq!(published[0], 0xe9);
    assert_eq!(&published[2..], &original[2..]);
}

#[test]
fn core_pun_observes_first_cpuid_before_native_child_replacement_and_exits() {
    let directory = FixtureDirectory::new();
    let mut builder = ElfBuilder::new(2, PAGE, false);
    builder.push_instruction(CPUID);
    // BF 35 00 fixes a positive rel32 pun window; these are executable
    // successor bytes and must survive publication at their original address.
    builder.exit(53);
    let image = builder.write(&directory, "core-first-cpuid", None);
    let checkpoint = checkpoint(&image);
    let entry = checkpoint.entries().initial_instruction;
    let mut gate = core_gate(checkpoint, vec![image.facts(BASE)]);
    assert_kernel_nx(gate.pid(), entry);
    let observation = observe(&mut gate);
    assert_eq!(observation.site.address, entry);
    assert_eq!(observation.site.class, SiteClass::Cpuid);
    assert_eq!(observation.registers.rip, entry);
    assert_eq!(observation.registers.rax, 0);
    assert_eq!(observation.registers.rcx, 0);
    assert_published_cpuid_pun(&gate, &image, BASE, PAGE);
    assert_eq!(gate.metrics().observations, 1);
    assert_exit(&mut gate, 53);
    assert_eq!(gate.metrics().observations, 1);
    assert_eq!(gate.metrics().admitted_pages, 1);
}

#[test]
fn core_pun_observes_custom_interpreter_and_main_first_instructions_once_each() {
    let directory = FixtureDirectory::new();
    let mut interpreter = ElfBuilder::new(2, PAGE, true);
    interpreter.push_instruction(CPUID);
    interpreter.mov64(0, BASE + PAGE as u64);
    interpreter.push_instruction(&[0xff, 0xe0]);
    let interpreter = interpreter.write(&directory, "core-interpreter", None);
    let mut main = ElfBuilder::new(2, PAGE, false);
    main.push_instruction(CPUID);
    main.exit(59);
    let main = main.write(&directory, "core-main", Some(&interpreter.path));
    let checkpoint = checkpoint(&main);
    let interpreter_base = checkpoint.entries().interpreter_base;
    assert_ne!(interpreter_base, 0);
    let mut gate = core_gate(
        checkpoint,
        vec![main.facts(BASE), interpreter.facts(interpreter_base)],
    );
    let first = observe(&mut gate);
    assert_eq!(first.site.address, interpreter_base + PAGE as u64);
    assert_eq!(first.registers.rip, first.site.address);
    assert_eq!(first.registers.rax, 0);
    assert_published_cpuid_pun(&gate, &interpreter, interpreter_base, PAGE);
    assert_kernel_nx(gate.pid(), BASE + PAGE as u64);
    let second = observe(&mut gate);
    assert_eq!(second.site.address, BASE + PAGE as u64);
    assert_eq!(second.registers.rip, second.site.address);
    assert_eq!(second.registers.rax, BASE + PAGE as u64);
    assert_published_cpuid_pun(&gate, &main, BASE, PAGE);
    assert_eq!(gate.metrics().observations, 2);
    assert_exit(&mut gate, 59);
    assert_eq!(gate.metrics().observations, 2);
    assert_eq!(gate.metrics().admitted_pages, 2);
}

#[test]
fn core_native_cpuid_replacement_matches_independent_native_complete_state() {
    let directory = FixtureDirectory::new();
    let mut builder = ElfBuilder::new(2, PAGE, false);
    builder.push_instruction(&[0x48, 0x83, 0xec, 0x20]); // sub rsp, 32
    for (offset, value) in [
        (0, 0x1122_3344_u32),
        (8, 0x5566_7788),
        (16, 0x1357_2468),
        (24, 0x0246_1357),
    ] {
        let mut bytes = vec![0x48, 0xc7, 0x44, 0x24, offset];
        bytes.extend_from_slice(&value.to_le_bytes());
        builder.push_instruction(&bytes);
    }
    builder.push_instruction(&[0xdb, 0xe3]); // fninit
    builder.push_instruction(&[0xd9, 0xe8]); // fld1
    builder.push_instruction(&[0x66, 0x0f, 0x76, 0xc9]); // pcmpeqd xmm1,xmm1
    builder.push_instruction(&[0x66, 0x0f, 0x6f, 0xd1]); // movdqa xmm2,xmm1
    for register in 0..16 {
        if register != 4 {
            builder.mov64(
                register,
                if matches!(register, 0 | 1) {
                    0
                } else {
                    0x1000 + u64::from(register)
                },
            );
        }
    }
    builder.push_instruction(&[0x68, 0x02, 0x02, 0, 0]);
    builder.push_instruction(&[0x9d]);
    let cpuid = builder.push_instruction(CPUID);
    // The first store contributes 48 89 04 as fixed high displacement bytes,
    // producing a positive target window without changing successor semantics.
    builder.push_instruction(&[0x48, 0x89, 0x04, 0x24]);
    builder.push_instruction(&[0x48, 0x89, 0x5c, 0x24, 8]);
    builder.push_instruction(&[0x48, 0x89, 0x4c, 0x24, 16]);
    builder.push_instruction(&[0x48, 0x89, 0x54, 0x24, 24]);
    let terminal = builder.push_instruction(&[0x0f, 0x0b]);
    let image = builder.write(&directory, "core-differential", None);

    let mut native = NativeTrace::launch(&image.path);
    let native_entry_rsp = native.registers().rsp;
    native.run_to_ud2(BASE + terminal as u64);
    let native_registers = native.registers();
    let native_evidence = TerminalEvidence {
        registers: native_registers,
        xstate: native.xstate(),
        initialized_stack: native.memory(native_registers.rsp, 32),
    };
    // Leaf zero returns a nonzero maximum basic leaf on this x86-64 platform.
    // A replacement that merely skips CPUID and preserves input RAX=0 fails.
    assert_ne!(native_evidence.registers.rax, 0);

    let checkpoint = checkpoint(&image);
    let core_entry_rsp = checkpoint.initial_registers().rsp;
    let mut gate = core_gate(checkpoint, vec![image.facts(BASE)]);
    let observation = observe(&mut gate);
    assert_eq!(observation.site.address, BASE + cpuid as u64);
    assert_eq!(observation.registers.rip, observation.site.address);
    assert_eq!(observation.registers.rax, 0);
    assert_eq!(observation.registers.rcx, 0);
    assert_eq!(observation.registers.rdx, 0x1002);
    assert_eq!(observation.registers.rbx, 0x1003);
    assert_eq!(observation.registers.rbp, 0x1005);
    assert_eq!(observation.registers.rsi, 0x1006);
    assert_eq!(observation.registers.rdi, 0x1007);
    assert_eq!(observation.registers.r8, 0x1008);
    assert_eq!(observation.registers.r9, 0x1009);
    assert_eq!(observation.registers.r10, 0x100a);
    assert_eq!(observation.registers.r11, 0x100b);
    assert_eq!(observation.registers.r12, 0x100c);
    assert_eq!(observation.registers.r13, 0x100d);
    assert_eq!(observation.registers.r14, 0x100e);
    assert_eq!(observation.registers.r15, 0x100f);
    assert_eq!(observation.registers.eflags, 0x202);
    let initial_stack: Vec<_> = [0x1122_3344_u64, 0x5566_7788, 0x1357_2468, 0x0246_1357]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    assert_eq!(
        gate.read_memory(observation.registers.rsp, 32).unwrap(),
        initial_stack
    );
    // CPUID, the following GPR stores and terminal UD2 do not modify extended
    // state, so the independent native snapshot also checks the observation.
    assert_eq!(observation.xstate, native_evidence.xstate);
    assert_published_cpuid_pun(&gate, &image, BASE, cpuid);
    let registers = match gate.next_event().unwrap() {
        GateEvent::ApplicationSignal {
            signal, registers, ..
        } => {
            assert_eq!(signal, libc::SIGILL);
            assert_eq!(registers.rip, BASE + terminal as u64);
            registers
        }
        other => panic!("expected terminal UD2 after core CPUID replacement, got {other:?}"),
    };
    assert_published_cpuid_pun(&gate, &image, BASE, cpuid);
    let core_evidence = TerminalEvidence {
        registers,
        xstate: gate.read_xstate().unwrap(),
        initialized_stack: gate.read_memory(registers.rsp, 32).unwrap(),
    };
    assert_eq!(registers.rsp, observation.registers.rsp);
    assert_eq!(gate.metrics().observations, 1);
    assert_eq!(
        native_evidence.registers.rsp % 16,
        core_evidence.registers.rsp % 16
    );
    let mut wrong_rsp = native_evidence.clone();
    wrong_rsp.registers.rsp += 16;
    let wrong_rsp = wrong_rsp.normalize_declared_stack_address(native_entry_rsp);
    let native_evidence = native_evidence.normalize_declared_stack_address(native_entry_rsp);
    let core_evidence = core_evidence.normalize_declared_stack_address(core_entry_rsp);
    assert_eq!(native_evidence.0, -32, "native fixture's exact RSP delta");
    assert_eq!(core_evidence.0, -32, "core fixture's exact RSP delta");
    assert_eq!(
        core_evidence, native_evidence,
        "real A1 CPUID replacement must preserve every compared architectural field"
    );
    assert_ne!(core_evidence, wrong_rsp, "RSP+16 must remain observable");
}

#[test]
fn core_pun_cache_line_constraint_refuses_without_source_changes_or_execution() {
    let directory = FixtureDirectory::new();
    let entry = PAGE + 63;
    let mut builder = ElfBuilder::new(2, entry, false);
    builder.push_instruction(CPUID); // Its two-byte publication crosses a cache line.
    builder.exit(61);
    let image = builder.write(&directory, "core-invalid-pun", None);
    let mut native = NativeTrace::launch(&image.path);
    trace(libc::PTRACE_CONT, native.pid(), 0, 0);
    let status = native.wait();
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 61);

    let mut gate = core_gate(checkpoint(&image), vec![image.facts(BASE)]);
    let before = gate.read_registers().unwrap();
    assert_eq!(before.rip, BASE + entry as u64);
    assert_kernel_nx(gate.pid(), before.rip);
    assert_eq!(
        gate.read_memory(BASE, image.bytes.len()).unwrap(),
        image.bytes
    );
    assert!(matches!(
        gate.next_event(),
        Err(GateError::Core(
            liteinst2::contracts::Refusal::NoPatchWindow
        ))
    ));
    let after = gate.read_registers().unwrap();
    assert_eq!(after.rip, before.rip);
    assert_eq!(after.rax, before.rax);
    assert_eq!(after.rbx, before.rbx);
    assert_eq!(after.rcx, before.rcx);
    assert_eq!(after.rdx, before.rdx);
    assert_eq!(
        gate.read_memory(BASE, image.bytes.len()).unwrap(),
        image.bytes
    );
    assert_kernel_nx(gate.pid(), after.rip);
    assert!(!gate.is_admitted(after.rip));
    assert_eq!(gate.metrics().admitted_pages, 0);
    assert_eq!(gate.metrics().observations, 0);
    assert!(
        gate.next_event().is_err(),
        "failed core plan must close execution"
    );
}

#[test]
fn core_pun_consumed_jump_fetch_admits_both_pages_once() {
    let directory = FixtureDirectory::new();
    let entry = 2 * PAGE - CPUID.len();
    let mut builder = ElfBuilder::new(3, entry, false);
    builder.push_instruction(CPUID);
    assert_eq!(builder.cursor, 2 * PAGE);
    builder.exit(71);
    let image = builder.write(&directory, "core-consumed-cross-page", None);
    let source = BASE + entry as u64;
    let successor = BASE + (2 * PAGE) as u64;
    let mut gate = core_gate(checkpoint(&image), vec![image.facts(BASE)]);
    assert_kernel_nx(gate.pid(), source);
    assert_kernel_nx(gate.pid(), successor);

    let observation = observe(&mut gate);
    assert_eq!(observation.site.address, source);
    assert_eq!(observation.site.len, CPUID.len() as u8);
    assert_eq!(observation.registers.rip, source);
    assert_eq!(observation.registers.rax, 0);
    // The original two-byte CPUID is wholly on the first page. The published
    // E9 consumes five bytes, so its instruction fetch also needs the next page.
    assert!(gate.is_admitted(source));
    assert!(gate.is_admitted(successor));
    assert_published_cpuid_pun(&gate, &image, BASE, entry);
    assert_eq!(
        gate.read_memory(successor, 3).unwrap(),
        image.bytes[2 * PAGE..2 * PAGE + 3]
    );
    assert_eq!(gate.metrics().admitted_pages, 2);
    assert_eq!(gate.metrics().observations, 1);
    assert_exit(&mut gate, 71);
    assert_eq!(gate.metrics().admitted_pages, 2);
    assert_eq!(gate.metrics().observations, 1);
}

#[test]
fn core_selected_destination_refuses_a_saved_call_return_while_still_nx() {
    let directory = FixtureDirectory::new();
    let call = 2 * PAGE - 5;
    let callee = PAGE + 64;
    let mut builder = ElfBuilder::new(3, PAGE, false);
    builder.relative(0xe9, call);
    builder.seek(callee);
    builder.push_instruction(CPUID);
    // The declared MOV supplies a valid five-byte core source and a positive
    // target window. RET still uses the original CALL's saved stack address.
    builder.push_instruction(&[0xbf, 67, 0, 0, 0]);
    builder.push_instruction(&[0xc3]);
    builder.seek(call);
    builder.relative(0xe8, callee);
    assert_eq!(builder.cursor, 2 * PAGE);
    builder.push_instruction(CPUID);
    builder.exit(67);
    let image = builder.write(&directory, "core-saved-return", None);

    let mut native = NativeTrace::launch(&image.path);
    trace(libc::PTRACE_CONT, native.pid(), 0, 0);
    let status = native.wait();
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 67);

    let mut gate = core_gate(checkpoint(&image), vec![image.facts(BASE)]);
    check_live_return(&mut gate, BASE + call as u64, BASE + callee as u64);
    assert_published_cpuid_pun(&gate, &image, BASE, callee);
    assert!(matches!(
        gate.next_event(),
        Err(GateError::Refused(
            "potential saved CALL return intersects selected publication"
        ))
    ));
    let destination = BASE + (2 * PAGE) as u64;
    assert!(!gate.is_admitted(destination));
    assert_kernel_nx(gate.pid(), destination);
    assert_eq!(gate.read_registers().unwrap().rip, destination);
    assert_eq!(
        gate.read_memory(destination, PAGE).unwrap(),
        image.bytes[2 * PAGE..3 * PAGE]
    );
    assert_eq!(gate.metrics().admitted_pages, 1);
    assert_eq!(gate.metrics().observations, 1);
    assert!(
        gate.next_event().is_err(),
        "saved-return refusal must close execution"
    );
}

#[test]
fn core_bundle_budget_is_checked_before_planning_site_sixty_five() {
    let directory = FixtureDirectory::new();
    let mut builder = ElfBuilder::new(2, PAGE, false);
    for _ in 0..64 {
        assert_eq!(builder.cursor % 8, 0);
        builder.push_instruction(CPUID);
        builder.push_instruction(&[0xbf, 1, 0, 0, 0]);
        builder.push_instruction(&[0x90]);
    }
    // The first 64 sites admit the core's static pun constraints. The next
    // native CPUID is also valid, but its publication would cross a cache line.
    // Requiring the budget error instead of NoPatchWindow proves the cap is
    // enforced before the sixty-fifth plan is constructed.
    for _ in 0..63 {
        builder.push_instruction(&[0x90]);
    }
    assert_eq!(builder.cursor % 64, 63);
    builder.push_instruction(CPUID);
    builder.exit(73);
    let image = builder.write(&directory, "core-bundle-budget", None);

    let mut native = NativeTrace::launch(&image.path);
    trace(libc::PTRACE_CONT, native.pid(), 0, 0);
    let status = native.wait();
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 73);

    let mut gate = core_gate(checkpoint(&image), vec![image.facts(BASE)]);
    let before = gate.read_registers().unwrap();
    assert_eq!(before.rip, BASE + PAGE as u64);
    assert_kernel_nx(gate.pid(), before.rip);
    assert!(matches!(
        gate.next_event(),
        Err(GateError::Refused(
            "core publication bundle budget exceeded"
        ))
    ));
    let after = gate.read_registers().unwrap();
    assert_eq!(after.rip, before.rip);
    assert_eq!(after.rsp, before.rsp);
    assert_eq!(after.rax, before.rax);
    assert_eq!(after.rbx, before.rbx);
    assert_eq!(after.rcx, before.rcx);
    assert_eq!(after.rdx, before.rdx);
    assert_eq!(after.rdi, before.rdi);
    assert_eq!(
        gate.read_memory(BASE, image.bytes.len()).unwrap(),
        image.bytes
    );
    assert_kernel_nx(gate.pid(), after.rip);
    assert!(!gate.is_admitted(after.rip));
    assert_eq!(gate.metrics().admitted_pages, 0);
    assert_eq!(gate.metrics().observations, 0);
    assert!(gate.metrics().first_touch.is_empty());
    assert!(
        gate.next_event().is_err(),
        "bundle budget refusal must close execution"
    );
}
