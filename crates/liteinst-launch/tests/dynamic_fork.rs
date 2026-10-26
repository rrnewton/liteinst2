#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Actual fork ownership, not a model or a publication lease. The independent
//! raw-ptrace oracle runs in an exec-isolated local subreaper; no host process
//! signal disposition, subreaper flag or unrelated wait domain is changed.
use liteinst_launch::lifecycle::{ExitStatus, TaskState, TerminalReason};
use liteinst_launch::{
    DynamicCreationPolicy, DynamicEvent, DynamicEventKind, DynamicLifecycleOptions, DynamicResume,
    DynamicSession, LaunchCommand, LaunchError, RegisterSnapshot,
};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const ENTRY: u64 = 0x401000;
const DATA: u64 = 0x600000;
const STACK: u64 = DATA + PAGE as u64 - 64;
const FLAGS: u64 = 0xed7;
const TIMEOUT: Duration = Duration::from_secs(3);
const ORACLE_ROLE: &str = "LITEINST_FORK_NATIVE_ORACLE";
const ORACLE_IMAGE: &str = "LITEINST_FORK_NATIVE_IMAGE";
const ORACLE_RECORD: &str = "LITEINST_FORK_NATIVE_RECORD";
const ORACLE_TEST: &str = "fork_returns_cow_wait_and_terminal_match_independent_native_state";
const FIRST_USER_TEST: &str = "child_first_original_ud2_matches_independent_native_full_state";
static NEXT: AtomicUsize = AtomicUsize::new(0);
static FILE_FORK: Mutex<()> = Mutex::new(());

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    code: Vec<u8>,
}
impl Fixture {
    fn new(code: Vec<u8>) -> Self {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "dynamic-fork-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(directory.parent().unwrap()).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("original");
        let mut image = vec![0; 3 * PAGE];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 3)] {
            image[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (at, value) in [
            (20, 1_u32),
            (64, 1),
            (68, 5),
            (120, 1),
            (124, 6),
            (176, 0x6474e551),
            (180, 6),
        ] {
            image[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (at, value) in [
            (24, ENTRY),
            (32, 64),
            (80, 0x400000),
            (96, 8192),
            (104, 8192),
            (112, 4096),
            (128, 8192),
            (136, DATA),
            (152, 4096),
            (160, 4096),
            (168, 4096),
            (224, 16),
        ] {
            image[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        assert!(code.len() < PAGE);
        image[PAGE..PAGE + code.len()].copy_from_slice(&code);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&image).unwrap();
        drop(file);
        Self {
            directory,
            path,
            code,
        }
    }
    fn launch(&self) -> DynamicSession {
        DynamicSession::launch_with_lifecycle(
            &LaunchCommand::new(&self.path),
            DynamicLifecycleOptions::fork_only(),
            TIMEOUT,
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn mov(code: &mut Vec<u8>, reg: u8, value: u64) {
    code.extend_from_slice(&[if reg < 8 { 0x48 } else { 0x49 }, 0xb8 + (reg & 7)]);
    code.extend_from_slice(&value.to_le_bytes());
}
fn syscall(code: &mut Vec<u8>, number: u64) {
    mov(code, 0, number);
    code.extend_from_slice(&[0x0f, 0x05]);
}
fn seed() -> Vec<u8> {
    let mut code = Vec::new();
    mov(&mut code, 4, STACK);
    for (offset, value) in [
        (0, 0x11223344_u32),
        (8, 0x55667788),
        (16, 0x13572468),
        (24, 0x24681357),
    ] {
        code.extend_from_slice(&[0x48, 0xc7, 0x44, 0x24, offset]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    code.extend_from_slice(&[
        0xdb, 0xe3, 0xd9, 0xe8, 0x66, 0x0f, 0x76, 0xc9, 0x66, 0x0f, 0x6f, 0xd1,
    ]);
    for reg in 0..16 {
        if reg != 4 {
            mov(&mut code, reg, 0x1234567890000000 + u64::from(reg));
        }
    }
    code.push(0x68);
    code.extend_from_slice(&(FLAGS as u32).to_le_bytes());
    code.push(0x9d);
    code
}
fn seed_flags(code: &mut Vec<u8>) {
    code.push(0x68);
    code.extend_from_slice(&(FLAGS as u32).to_le_bytes());
    code.push(0x9d);
}
fn write_marker(code: &mut Vec<u8>, value: u32) {
    // MOV dword ptr [absolute sign-extended disp32], imm32; no flag changes.
    code.extend_from_slice(&[0xc7, 0x04, 0x25]);
    code.extend_from_slice(&(DATA as u32).to_le_bytes());
    code.extend_from_slice(&value.to_le_bytes());
}
fn fork_program(second_fork: bool) -> Vec<u8> {
    let mut code = seed();
    syscall(&mut code, libc::SYS_fork as u64);
    code.extend_from_slice(&[0x48, 0x85, 0xc0, 0x0f, 0x84]); // TEST RAX; JZ child.
    let branch = code.len();
    code.extend_from_slice(&[0; 4]);
    // Branch selection observes the actual PID, including parity. Restore a
    // fixed original-program flag seed before later full-state checkpoints.
    seed_flags(&mut code);
    code.extend_from_slice(&[0x48, 0x89, 0xc7]); // Parent RDI = exact child PID.
    write_marker(&mut code, 0x11112222);
    mov(&mut code, 6, DATA + 16);
    mov(&mut code, 2, 0);
    mov(&mut code, 10, 0);
    syscall(&mut code, libc::SYS_wait4 as u64);
    // Reset only application values which carried the native PID. The oracle
    // compares the earlier PID-bearing stops too, with explicit identity proof.
    mov(&mut code, 7, 0x1357246813572468);
    mov(&mut code, 0, 0x2468135724681357);
    if second_fork {
        syscall(&mut code, libc::SYS_fork as u64);
    }
    code.extend_from_slice(&[0x0f, 0x0b]);
    let child = code.len();
    code[branch..branch + 4]
        .copy_from_slice(&i32::try_from(child - branch - 4).unwrap().to_le_bytes());
    seed_flags(&mut code);
    write_marker(&mut code, 0x33334444);
    mov(&mut code, 7, 23);
    syscall(&mut code, libc::SYS_exit as u64);
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
fn first_user_fault_program() -> Vec<u8> {
    let mut code = seed();
    syscall(&mut code, libc::SYS_fork as u64);
    // This is the first original user instruction after the child's fork return.
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
fn spin_fork_program() -> Vec<u8> {
    let mut code = seed();
    syscall(&mut code, libc::SYS_fork as u64);
    code.extend_from_slice(&[0xeb, 0xfe]);
    code
}
fn pin(pid: i32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0, "pidfd_open: {}", io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}
fn poll_bits(fd: &OwnedFd) -> i16 {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert!(unsafe { libc::poll(&raw mut poll, 1, 0) } >= 0);
    poll.revents
}
fn signal(fd: &OwnedFd, sig: i32) {
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
}
fn reaped(fd: &OwnedFd) {
    assert_ne!(
        poll_bits(fd) & libc::POLLHUP,
        0,
        "original incarnation remains physically present"
    );
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                fd.as_raw_fd() as u32,
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
fn finish(session: DynamicSession, handles: &[(i32, OwnedFd)]) {
    let mut actual = session.terminate(TIMEOUT).unwrap().reaped;
    let mut expected: Vec<_> = handles.iter().map(|(pid, _)| *pid).collect();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
    for (_, fd) in handles {
        reaped(fd);
    }
}
fn release(session: &mut DynamicSession, event: &DynamicEvent) {
    session
        .resume(event.stop_token().unwrap(), DynamicResume::Continue)
        .unwrap();
}
fn initialize(session: &mut DynamicSession) -> DynamicEvent {
    assert!(session.lifecycle_snapshot().unwrap().is_none());
    let original = session.initial_event().clone();
    assert!(original.task.is_none());
    assert!(matches!(original.kind, DynamicEventKind::Exec { .. }));
    let mut expected = session
        .read_registers(original.stop_token().unwrap())
        .unwrap();
    assert_eq!(expected.rax as i64, -i64::from(libc::ENOSYS));
    release(session, &original);
    let exit = session.next_event(TIMEOUT).unwrap();
    assert_eq!(
        exit.kind,
        DynamicEventKind::SyscallExit {
            result: 0,
            is_error: false
        }
    );
    expected.rax = 0;
    assert_eq!(
        session.read_registers(exit.stop_token().unwrap()).unwrap(),
        expected
    );
    let task = exit.task.unwrap();
    let snapshot = session.lifecycle_snapshot().unwrap().unwrap();
    assert_eq!(snapshot.tasks().count(), 1);
    let record = snapshot.tasks().next().unwrap();
    assert_eq!(record.id, task.task);
    assert_eq!(
        record.origin,
        liteinst_launch::lifecycle::TaskOrigin::InitialExecSyscallExit
    );
    assert_eq!(
        record.state,
        TaskState::Held {
            pc: ENTRY,
            reason: liteinst_launch::lifecycle::HoldReason::ExecSyscallExit
        }
    );
    assert!(
        session
            .read_registers(original.stop_token().unwrap())
            .is_err()
    );
    exit
}
fn next_entry(session: &mut DynamicSession, number: u64) -> DynamicEvent {
    let event = next_forward_sigchld(session);
    assert!(
        matches!(event.kind, DynamicEventKind::SyscallEntry { number: actual, .. } if actual == number),
        "{event:?}"
    );
    event
}
fn next_forward_sigchld(session: &mut DynamicSession) -> DynamicEvent {
    for _ in 0..16 {
        let event = session.next_event(TIMEOUT).unwrap();
        if let DynamicEventKind::SignalDelivery(info) = &event.kind {
            if info.signal() == libc::SIGCHLD {
                assert_eq!(info.code(), libc::CLD_EXITED);
                session
                    .resume(event.stop_token().unwrap(), DynamicResume::DeliverOriginal)
                    .unwrap();
                continue;
            }
        }
        return event;
    }
    panic!("signal forwarding bound");
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    stack: Vec<u8>,
    data: Vec<u8>,
    mask: u64,
}
fn snapshot(session: &mut DynamicSession, event: &DynamicEvent, code: &[u8]) -> Snapshot {
    let stop = event.stop_token().unwrap();
    assert_eq!(session.read_memory(stop, ENTRY, code.len()).unwrap(), code);
    Snapshot {
        registers: session.read_registers(stop).unwrap(),
        xstate: session.read_xstate(stop).unwrap(),
        stack: session.read_memory(stop, STACK, 32).unwrap(),
        data: session.read_memory(stop, DATA, 64).unwrap(),
        mask: session.signal_mask(stop).unwrap(),
    }
}
struct Pair {
    created: DynamicEvent,
    newborn: DynamicEvent,
    child: i32,
    handle: OwnedFd,
}
fn create(session: &mut DynamicSession, entry: &DynamicEvent) -> Pair {
    release(session, entry);
    let created = session.next_event(TIMEOUT).unwrap();
    let DynamicEventKind::Created { child } = created.kind else {
        panic!("{created:?}")
    };
    let newborn = session.next_event(TIMEOUT).unwrap();
    assert_eq!(newborn.task, Some(child));
    assert_eq!(
        newborn.kind,
        DynamicEventKind::Newborn {
            parent: entry.task.unwrap()
        }
    );
    assert_ne!(entry.task.unwrap().task, child.task);
    assert_ne!(entry.task.unwrap().process, child.process);
    assert_ne!(entry.task.unwrap().address_space, child.address_space);
    assert_eq!(child.generation, 0);
    let handle = pin(newborn.tid);
    let records = session.lifecycle_snapshot().unwrap().unwrap();
    assert_eq!(records.tasks().count(), 2);
    assert_eq!(
        records
            .tasks()
            .find(|record| record.id == child.task)
            .unwrap()
            .state,
        TaskState::Held {
            pc: session
                .read_registers(newborn.stop_token().unwrap())
                .unwrap()
                .rip,
            reason: liteinst_launch::lifecycle::HoldReason::NewbornReturnReady,
        }
    );
    assert!(
        records
            .tasks()
            .all(|task| matches!(task.state, TaskState::Held { .. }))
    );
    Pair {
        created,
        child: newborn.tid,
        newborn,
        handle,
    }
}
fn returned(session: &mut DynamicSession, held: &DynamicEvent, result: i64) -> DynamicEvent {
    release(session, held);
    let event = next_forward_sigchld(session);
    assert_eq!(event.tid, held.tid);
    assert_eq!(
        event.kind,
        DynamicEventKind::SyscallExit {
            result,
            is_error: false
        }
    );
    event
}
struct Run {
    child: i32,
    phases: Vec<Snapshot>,
}
fn observed(fixture: &Fixture, second_fork: bool) -> Run {
    let mut session = fixture.launch();
    let parent = session.pid();
    let parent_handle = pin(parent);
    let initial = initialize(&mut session);
    release(&mut session, &initial);
    let fork_entry = next_entry(&mut session, libc::SYS_fork as u64);
    let mut phases = vec![snapshot(&mut session, &fork_entry, &fixture.code)];
    assert_eq!(phases[0].registers.eflags, FLAGS);
    let pair = create(&mut session, &fork_entry);
    let parent_exit = returned(&mut session, &pair.created, i64::from(pair.child));
    phases.push(snapshot(&mut session, &parent_exit, &fixture.code));
    // This is the actual automatic return-ready checkpoint, not a syscall EXIT.
    let child_return_ready = pair.newborn.clone();
    phases.push(snapshot(&mut session, &child_return_ready, &fixture.code));
    release(&mut session, &parent_exit);
    let wait_entry = next_entry(&mut session, libc::SYS_wait4 as u64);
    assert_eq!(wait_entry.tid, parent);
    phases.push(snapshot(&mut session, &wait_entry, &fixture.code));
    release(&mut session, &child_return_ready);
    let exit_entry = next_entry(&mut session, libc::SYS_exit as u64);
    assert_eq!(exit_entry.tid, pair.child);
    phases.push(snapshot(&mut session, &exit_entry, &fixture.code));
    assert_eq!(&phases[3].data[..4], &0x11112222_u32.to_le_bytes());
    assert_eq!(&phases[4].data[..4], &0x33334444_u32.to_le_bytes());
    release(&mut session, &exit_entry);
    let terminal = session.next_event(TIMEOUT).unwrap();
    assert_eq!(terminal.task, pair.newborn.task);
    assert_eq!(
        terminal.kind,
        DynamicEventKind::TaskTerminal {
            status: ExitStatus::Code(23)
        }
    );
    assert!(terminal.stop_token().is_none());
    assert_ne!(poll_bits(&pair.handle) & libc::POLLIN, 0);
    assert_eq!(
        poll_bits(&pair.handle) & libc::POLLHUP,
        0,
        "stopped real parent has not waited yet"
    );
    let state = session.lifecycle_snapshot().unwrap().unwrap();
    assert_eq!(
        state
            .tasks()
            .find(|record| record.tid == pair.child)
            .unwrap()
            .state,
        TaskState::Terminal(TerminalReason::Exit(ExitStatus::Code(23)))
    );
    assert!(
        session
            .read_registers(exit_entry.stop_token().unwrap())
            .is_err()
    );
    let wait_exit = returned(&mut session, &wait_entry, i64::from(pair.child));
    phases.push(snapshot(&mut session, &wait_exit, &fixture.code));
    assert_eq!(&phases[5].data[16..20], &(23_u32 << 8).to_le_bytes());
    assert_eq!(
        &phases[5].data[..4],
        &0x11112222_u32.to_le_bytes(),
        "fork copy-on-write changed parent data"
    );
    reaped(&pair.handle);
    release(&mut session, &wait_exit);
    if second_fork {
        let again = next_entry(&mut session, libc::SYS_fork as u64);
        assert_eq!(
            session
                .lifecycle_snapshot()
                .unwrap()
                .unwrap()
                .tasks()
                .count(),
            2
        );
        assert!(matches!(
            session.resume(again.stop_token().unwrap(), DynamicResume::Continue),
            Err(LaunchError::Invalid(
                "dynamic lifetime task bound exhausted"
            ))
        ));
    } else {
        let marker = next_forward_sigchld(&mut session);
        let DynamicEventKind::SignalDelivery(ref signal) = marker.kind else {
            panic!("{marker:?}")
        };
        assert_eq!(signal.signal(), libc::SIGILL);
        assert_eq!(signal.code(), 2);
        phases.push(snapshot(&mut session, &marker, &fixture.code));
    }
    finish(
        session,
        &[(parent, parent_handle), (pair.child, pair.handle)],
    );
    Run {
        child: pair.child,
        phases,
    }
}

// The original program is identical in both runs. Only explicitly asserted
// native child-PID values are substituted, at their exact ABI output/argument
// fields. All flags, kernel orig_rax, other GPRs, XSTATE, stack and data are exact.
fn comparable(run: &Run) -> Vec<Snapshot> {
    // Entry, actual parent EXIT, automatic child return-ready, parent wait
    // ENTRY, child exit ENTRY, parent wait EXIT, and original parent UD2 fault.
    assert_eq!(run.phases.len(), 7);
    assert_eq!(run.phases[0].registers.orig_rax, libc::SYS_fork as u64);
    assert_eq!(run.phases[1].registers.rax, run.child as u64);
    assert_eq!(run.phases[2].registers.rax, 0);
    assert_eq!(run.phases[3].registers.rdi, run.child as u64);
    assert_eq!(run.phases[5].registers.rax, run.child as u64);
    assert_eq!(run.phases[5].registers.rdi, run.child as u64);
    for index in 0..6 {
        assert_eq!(
            run.phases[index].registers.eflags, FLAGS,
            "original program must seed exact flags at phase {index}"
        );
    }
    let mut output = run.phases.clone();
    output[1].registers.rax = 1;
    output[3].registers.rdi = 1;
    output[5].registers.rax = 1;
    output[5].registers.rdi = 1;
    output
}

// Independent raw implementation; it does not import any owner transition,
// lifecycle registry, production snapshot, or production cleanup routine.
struct Raw {
    parent: Child,
    pins: BTreeMap<i32, OwnedFd>,
    stopped: BTreeMap<i32, i32>,
    done: bool,
}
fn trace(tid: i32, request: u32, addr: usize, data: usize) {
    assert_ne!(
        unsafe { libc::ptrace(request, tid, addr, data) },
        -1,
        "raw ptrace: {}",
        io::Error::last_os_error()
    );
}
fn raw_registers(tid: i32) -> RegisterSnapshot {
    let mut raw = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
    trace(tid, libc::PTRACE_GETREGS, 0, raw.as_mut_ptr() as usize);
    unsafe { raw.assume_init() }.into()
}
fn raw_memory(tid: i32, address: u64, len: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for offset in (0..len).step_by(8) {
        let word = unsafe {
            *libc::__errno_location() = 0;
            let word = libc::ptrace(libc::PTRACE_PEEKDATA, tid, address + offset as u64, 0);
            assert_eq!(*libc::__errno_location(), 0);
            word
        };
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    bytes.truncate(len);
    bytes
}
fn raw_snapshot(tid: i32, code: &[u8]) -> Snapshot {
    assert_eq!(raw_memory(tid, ENTRY, code.len()), code);
    let mut xstate = vec![0; 65536];
    let mut iov = libc::iovec {
        iov_base: xstate.as_mut_ptr().cast(),
        iov_len: xstate.len(),
    };
    trace(tid, libc::PTRACE_GETREGSET, 0x202, (&raw mut iov) as usize);
    xstate.truncate(iov.iov_len);
    let mut mask = 0_u64;
    trace(tid, libc::PTRACE_GETSIGMASK, 8, (&raw mut mask) as usize);
    Snapshot {
        registers: raw_registers(tid),
        xstate,
        stack: raw_memory(tid, STACK, 32),
        data: raw_memory(tid, DATA, 64),
        mask,
    }
}
impl Raw {
    fn launch(path: &Path) -> Self {
        // This branch is an exec-isolated test process with no other children.
        let mut no_child: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    &raw mut no_child,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                )
            },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let mut command = Command::new(path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let parent = command.spawn().unwrap();
        let pid = parent.id() as i32;
        let mut raw = Self {
            parent,
            pins: BTreeMap::new(),
            stopped: BTreeMap::new(),
            done: false,
        };
        raw.pins.insert(pid, pin(pid));
        let (tid, status) = raw.wait();
        assert_eq!(tid, pid);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        trace(
            pid,
            libc::PTRACE_SETOPTIONS,
            0,
            (libc::PTRACE_O_TRACEFORK
                | libc::PTRACE_O_TRACEEXIT
                | libc::PTRACE_O_TRACESYSGOOD
                | libc::PTRACE_O_EXITKILL) as usize,
        );
        raw
    }
    fn resume(&mut self, tid: i32, request: u32, signal: i32) {
        assert!(matches!(request, libc::PTRACE_SYSCALL | libc::PTRACE_CONT));
        trace(tid, request, 0, signal as usize);
        self.stopped.remove(&tid);
    }
    fn wait(&mut self) -> (i32, i32) {
        let until = Instant::now() + TIMEOUT;
        loop {
            // WNOWAIT authenticates a waitable direct/ptraced child before any
            // terminal consumption, so pidfd ownership never follows a reuse.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    &raw mut info,
                    libc::WEXITED | libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                )
            };
            assert_eq!(result, 0, "raw waitid: {}", io::Error::last_os_error());
            let tid = unsafe { info.si_pid() };
            if tid != 0 {
                self.pins.entry(tid).or_insert_with(|| pin(tid));
                let mut status = 0;
                assert_eq!(
                    unsafe { libc::waitpid(tid, &raw mut status, libc::WNOHANG | libc::__WALL) },
                    tid
                );
                if libc::WIFSTOPPED(status) {
                    self.stopped.insert(tid, status);
                } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.stopped.remove(&tid);
                }
                return (tid, status);
            }
            assert!(Instant::now() < until, "raw fork event deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn syscall_stop(&mut self, pid: i32, op: u8, number: u64) {
        for _ in 0..16 {
            let (tid, status) = self.wait();
            assert_eq!(tid, pid);
            assert!(libc::WIFSTOPPED(status));
            if libc::WSTOPSIG(status) == libc::SIGCHLD {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                trace(pid, libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
                assert_eq!(info.si_code, libc::CLD_EXITED);
                self.resume(pid, libc::PTRACE_SYSCALL, libc::SIGCHLD);
                continue;
            }
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP | 0x80);
            let mut info: libc::ptrace_syscall_info = unsafe { std::mem::zeroed() };
            trace(
                pid,
                libc::PTRACE_GET_SYSCALL_INFO,
                std::mem::size_of_val(&info),
                (&raw mut info) as usize,
            );
            assert_eq!(info.arch, 0xc000003e);
            assert_eq!(info.op, op);
            let regs = raw_registers(pid);
            assert_eq!(regs.orig_rax, number);
            assert_eq!(info.instruction_pointer, regs.rip);
            assert_eq!(info.stack_pointer, regs.rsp);
            if op == libc::PTRACE_SYSCALL_INFO_ENTRY {
                assert_eq!(unsafe { info.u.entry.nr }, number);
            }
            return;
        }
        panic!("raw signal forwarding bound");
    }
    fn cleanup(&mut self) -> bool {
        if self.done {
            return true;
        }
        let until = Instant::now() + TIMEOUT;
        loop {
            // No asserting helper is called during ownership cleanup. A failed
            // syscall retains its pinned owner and is retried; only positive
            // SIGKILL or a kernel pre-exit stop permits a CONT below.
            for (&tid, handle) in &self.pins {
                if raw_hup(handle) {
                    self.stopped.remove(&tid);
                    continue;
                }
                let killed = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        handle.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                } == 0;
                if let Some(&status) = self.stopped.get(&tid) {
                    if (killed || status >> 16 == libc::PTRACE_EVENT_EXIT)
                        && unsafe { libc::ptrace(libc::PTRACE_CONT, tid, 0, 0) } != -1
                    {
                        self.stopped.remove(&tid);
                    }
                }
            }
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    &raw mut info,
                    libc::WEXITED | libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                )
            };
            if result == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                && self.pins.values().all(raw_hup)
            {
                self.done = true;
                return true;
            }
            let tid = unsafe { info.si_pid() };
            if result == 0 && tid != 0 {
                // A held WNOWAIT child is real ownership, never a /proc PID
                // guess. Do not consume it if its stable descriptor is missing.
                if let std::collections::btree_map::Entry::Vacant(entry) = self.pins.entry(tid) {
                    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, 0) };
                    if fd >= 0 {
                        entry.insert(unsafe { OwnedFd::from_raw_fd(fd as i32) });
                    }
                }
                if self.pins.contains_key(&tid) {
                    let mut status = 0;
                    if unsafe { libc::waitpid(tid, &raw mut status, libc::WNOHANG | libc::__WALL) }
                        == tid
                    {
                        if libc::WIFSTOPPED(status) {
                            self.stopped.insert(tid, status);
                        } else if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                            self.stopped.remove(&tid);
                        }
                    }
                }
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
fn raw_hup(handle: &OwnedFd) -> bool {
    let mut poll = libc::pollfd {
        fd: handle.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&raw mut poll, 1, 0) == 1 && poll.revents & libc::POLLHUP != 0 }
}
impl Drop for Raw {
    fn drop(&mut self) {
        // This is the exec-isolated reaper process, not the embedding test
        // process. An uncertain foreground deadline must not kill/abort its
        // natural-parent authority. Retain it through bounded nonblocking
        // cleanup passes until both ECHILD and all original HUP witnesses hold.
        while !self.cleanup() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn raw_run(path: &Path, code: &[u8]) -> Run {
    let mut raw = Raw::launch(path);
    let parent = raw.parent.id() as i32;
    raw.resume(parent, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        parent,
        libc::PTRACE_SYSCALL_INFO_ENTRY,
        libc::SYS_fork as u64,
    );
    let mut phases = vec![raw_snapshot(parent, code)];
    raw.resume(parent, libc::PTRACE_SYSCALL, 0);
    let mut child = None;
    let mut born = None;
    while child.is_none() || born.is_none() {
        let (tid, status) = raw.wait();
        assert!(libc::WIFSTOPPED(status));
        if tid == parent {
            assert_eq!(status >> 16, libc::PTRACE_EVENT_FORK);
            let mut value = 0_u64;
            trace(
                parent,
                libc::PTRACE_GETEVENTMSG,
                0,
                (&raw mut value) as usize,
            );
            let value = i32::try_from(value).unwrap();
            assert!(value > 0);
            raw.pins.entry(value).or_insert_with(|| pin(value));
            assert!(child.replace(value).is_none());
        } else {
            assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP); // TRACEME, not SEIZE.
            assert!(born.replace(tid).is_none());
        }
    }
    let child = child.unwrap();
    assert_eq!(born, Some(child));
    raw.resume(parent, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        parent,
        libc::PTRACE_SYSCALL_INFO_EXIT,
        libc::SYS_fork as u64,
    );
    phases.push(raw_snapshot(parent, code));
    // TRACEME's original SIGSTOP is also in the late return-to-user path.
    // Preserve it as the automatic checkpoint; no child fork EXIT is invented.
    phases.push(raw_snapshot(child, code));
    raw.resume(parent, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        parent,
        libc::PTRACE_SYSCALL_INFO_ENTRY,
        libc::SYS_wait4 as u64,
    );
    phases.push(raw_snapshot(parent, code));
    raw.resume(child, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        child,
        libc::PTRACE_SYSCALL_INFO_ENTRY,
        libc::SYS_exit as u64,
    );
    phases.push(raw_snapshot(child, code));
    raw.resume(child, libc::PTRACE_SYSCALL, 0);
    loop {
        let (tid, status) = raw.wait();
        assert_eq!(tid, child);
        if libc::WIFEXITED(status) {
            assert_eq!(libc::WEXITSTATUS(status), 23);
            break;
        }
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(status >> 16, libc::PTRACE_EVENT_EXIT);
        raw.resume(child, libc::PTRACE_CONT, 0);
    }
    assert_ne!(poll_bits(&raw.pins[&child]) & libc::POLLIN, 0);
    assert_eq!(poll_bits(&raw.pins[&child]) & libc::POLLHUP, 0);
    raw.resume(parent, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        parent,
        libc::PTRACE_SYSCALL_INFO_EXIT,
        libc::SYS_wait4 as u64,
    );
    phases.push(raw_snapshot(parent, code));
    assert_ne!(poll_bits(&raw.pins[&child]) & libc::POLLHUP, 0);
    raw.resume(parent, libc::PTRACE_SYSCALL, 0);
    loop {
        let (tid, status) = raw.wait();
        assert_eq!(tid, parent);
        assert!(libc::WIFSTOPPED(status));
        if libc::WSTOPSIG(status) == libc::SIGCHLD {
            raw.resume(parent, libc::PTRACE_SYSCALL, libc::SIGCHLD);
            continue;
        }
        assert_eq!(libc::WSTOPSIG(status), libc::SIGILL);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        trace(parent, libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
        assert_eq!(info.si_code, 2);
        phases.push(raw_snapshot(parent, code));
        break;
    }
    assert!(
        raw.cleanup(),
        "independent oracle foreground cleanup deadline"
    );
    Run { child, phases }
}

fn words(r: RegisterSnapshot) -> [u64; 27] {
    [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ]
}
fn registers(w: [u64; 27]) -> RegisterSnapshot {
    RegisterSnapshot {
        r15: w[0],
        r14: w[1],
        r13: w[2],
        r12: w[3],
        rbp: w[4],
        rbx: w[5],
        r11: w[6],
        r10: w[7],
        r9: w[8],
        r8: w[9],
        rax: w[10],
        rcx: w[11],
        rdx: w[12],
        rsi: w[13],
        rdi: w[14],
        orig_rax: w[15],
        rip: w[16],
        cs: w[17],
        eflags: w[18],
        rsp: w[19],
        ss: w[20],
        fs_base: w[21],
        gs_base: w[22],
        ds: w[23],
        es: w[24],
        fs: w[25],
        gs: w[26],
    }
}
fn save(path: &Path, run: &Run) {
    assert_eq!(run.phases.len(), 7);
    save_counted(path, run, 7);
}
fn save_counted(path: &Path, run: &Run, count: usize) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(b"LIFORK01").unwrap();
    file.write_all(&run.child.to_le_bytes()).unwrap();
    assert_eq!(run.phases.len(), count);
    for phase in &run.phases {
        for word in words(phase.registers).into_iter().chain([phase.mask]) {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
        for blob in [&phase.xstate, &phase.stack, &phase.data] {
            file.write_all(&u32::try_from(blob.len()).unwrap().to_le_bytes())
                .unwrap();
            file.write_all(blob).unwrap();
        }
    }
}
fn load(path: &Path) -> Run {
    load_counted(path, 7)
}
fn load_counted(path: &Path, count: usize) -> Run {
    let mut file = fs::File::open(path).unwrap();
    let mut magic = [0; 8];
    file.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"LIFORK01");
    let mut id = [0; 4];
    file.read_exact(&mut id).unwrap();
    let child = i32::from_le_bytes(id);
    assert!(child > 0);
    let mut phases = Vec::new();
    for _ in 0..count {
        let mut w = [0; 28];
        for word in &mut w {
            let mut bytes = [0; 8];
            file.read_exact(&mut bytes).unwrap();
            *word = u64::from_le_bytes(bytes);
        }
        let mut blobs = Vec::new();
        for max in [65536, 32, 64] {
            let mut n = [0; 4];
            file.read_exact(&mut n).unwrap();
            let n = u32::from_le_bytes(n) as usize;
            assert!(n <= max);
            let mut bytes = vec![0; n];
            file.read_exact(&mut bytes).unwrap();
            blobs.push(bytes);
        }
        assert_eq!(blobs[1].len(), 32);
        assert_eq!(blobs[2].len(), 64);
        assert!(!blobs[0].is_empty());
        phases.push(Snapshot {
            registers: registers(w[..27].try_into().unwrap()),
            mask: w[27],
            xstate: blobs.remove(0),
            stack: blobs.remove(0),
            data: blobs.remove(0),
        });
    }
    let mut tail = [0];
    assert_eq!(file.read(&mut tail).unwrap(), 0);
    Run { child, phases }
}
struct Isolated(Option<Child>);
impl Drop for Isolated {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            // The isolated native oracle owns its own bounded cleanup and must
            // finish it; killing its reaper would manufacture orphan zombies.
            // Retain the wait owner if the outer assertion deadline expires.
            std::thread::spawn(move || {
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => break,
                        Err(error) if error.raw_os_error() == Some(libc::ECHILD) => break,
                        _ => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            });
        }
    }
}
fn isolated(fixture: &Fixture, role: &str, record: &Path, witness: &str) {
    isolated_test(fixture, role, record, witness, ORACLE_TEST);
}
fn isolated_test(fixture: &Fixture, role: &str, record: &Path, witness: &str, test: &str) {
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=1", "--nocapture"])
        .env(ORACLE_ROLE, role)
        .env("RUST_BACKTRACE", "0")
        .env(ORACLE_IMAGE, &fixture.path)
        .env(ORACLE_RECORD, record)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut owner = Isolated(Some(child));
    let until = Instant::now() + Duration::from_secs(12);
    while owner.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(Instant::now() < until, "isolated oracle outer deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
    let output = owner.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
    assert!(text.lines().any(|line| line.ends_with(witness)));
}
fn native(fixture: &Fixture) -> Run {
    let record = fixture.directory.join("native.bin");
    isolated(
        fixture,
        "state",
        &record,
        "FORK_NATIVE_PHYSICAL_CLEANUP_COMPLETE",
    );
    let evidence = load(&record);
    isolated(
        fixture,
        "cleanup",
        &record,
        "FORK_NATIVE_UNWIND_PHYSICAL_CLEANUP_COMPLETE",
    );
    evidence
}

fn raw_unwind_cleanup(path: &Path) {
    let mut raw = Raw::launch(path);
    let parent = raw.parent.id() as i32;
    raw.resume(parent, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        parent,
        libc::PTRACE_SYSCALL_INFO_ENTRY,
        libc::SYS_fork as u64,
    );
    raw.resume(parent, libc::PTRACE_SYSCALL, 0);
    let mut parent_seen = false;
    let mut child_seen = None;
    while !parent_seen || child_seen.is_none() {
        let (tid, status) = raw.wait();
        assert!(libc::WIFSTOPPED(status));
        if tid == parent {
            assert_eq!(status >> 16, libc::PTRACE_EVENT_FORK);
            assert!(!parent_seen);
            parent_seen = true;
        } else {
            assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
            assert!(child_seen.replace(tid).is_none());
        }
    }
    assert_eq!(raw.pins.len(), 2);
    let retained: Vec<_> = raw
        .pins
        .values()
        .map(|handle| {
            let fd = unsafe { libc::fcntl(handle.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            assert!(fd >= 0);
            unsafe { OwnedFd::from_raw_fd(fd) }
        })
        .collect();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned = raw;
        panic!("intentional raw fork cleanup unwind");
    }));
    let panic = failed.expect_err("the cleanup negative control must actually unwind");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"intentional raw fork cleanup unwind")
    );
    for handle in &retained {
        reaped(handle);
    }
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
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

#[test]
fn fork_returns_cow_wait_and_terminal_match_independent_native_state() {
    if let Some(role) = std::env::var_os(ORACLE_ROLE) {
        let path = PathBuf::from(std::env::var_os(ORACLE_IMAGE).unwrap());
        if role == "cleanup" {
            raw_unwind_cleanup(&path);
            println!("FORK_NATIVE_UNWIND_PHYSICAL_CLEANUP_COMPLETE");
        } else {
            assert_eq!(role, "state");
            let record = PathBuf::from(std::env::var_os(ORACLE_RECORD).unwrap());
            let code = fork_program(false);
            let run = raw_run(&path, &code);
            save(&record, &run);
            println!("FORK_NATIVE_PHYSICAL_CLEANUP_COMPLETE");
        }
        return;
    }
    let _serial = FILE_FORK.lock().unwrap();
    let fixture = Fixture::new(fork_program(false));
    let original = native(&fixture);
    let actual = observed(&fixture, false);
    let expected = comparable(&original);
    let actual = comparable(&actual);
    assert_eq!(actual, expected);
    for corruption in 0..6 {
        let mut corrupted = expected.clone();
        match corruption {
            0 => corrupted[1].registers.r15 ^= 1,
            1 => corrupted[2].registers.eflags ^= 1,
            2 => corrupted[2].registers.rsp ^= 8,
            3 => corrupted[1].xstate[0] ^= 1,
            4 => corrupted[4].data[0] ^= 1,
            5 => corrupted[2].mask ^= 1,
            _ => unreachable!(),
        }
        assert_ne!(
            actual, corrupted,
            "full-state comparator accepted corruption {corruption}"
        );
    }
}
#[test]
fn retired_child_does_not_replenish_lifetime_creation_budget() {
    let _serial = FILE_FORK.lock().unwrap();
    let fixture = Fixture::new(fork_program(true));
    assert_eq!(observed(&fixture, true).phases.len(), 6);
}
#[test]
fn fork_options_keep_default_and_other_lifecycle_refusals_before_execution() {
    let _serial = FILE_FORK.lock().unwrap();
    for max_tasks in [0, 3, usize::MAX] {
        let command = LaunchCommand::new("unopened-invalid-lifecycle-options");
        assert!(matches!(
            DynamicSession::launch_with_lifecycle(
                &command,
                DynamicLifecycleOptions {
                    creation: DynamicCreationPolicy::Fork,
                    max_tasks
                },
                TIMEOUT
            ),
            Err(LaunchError::Invalid(
                "dynamic lifecycle task bound must be one or two"
            ))
        ));
    }
    for (number, options, expected) in [
        (
            libc::SYS_fork,
            None,
            "dynamic creation and later exec are not yet qualified",
        ),
        (
            libc::SYS_fork,
            Some(DynamicLifecycleOptions {
                creation: DynamicCreationPolicy::Refuse,
                max_tasks: 2,
            }),
            "dynamic fork policy refuses creation",
        ),
        (
            libc::SYS_fork,
            Some(DynamicLifecycleOptions {
                creation: DynamicCreationPolicy::Fork,
                max_tasks: 1,
            }),
            "dynamic lifetime task bound exhausted",
        ),
        (
            libc::SYS_clone,
            Some(DynamicLifecycleOptions::fork_only()),
            "dynamic creation and later exec are not yet qualified",
        ),
        (
            libc::SYS_clone3,
            Some(DynamicLifecycleOptions::fork_only()),
            "dynamic creation and later exec are not yet qualified",
        ),
        (
            libc::SYS_vfork,
            Some(DynamicLifecycleOptions::fork_only()),
            "dynamic creation and later exec are not yet qualified",
        ),
        (
            libc::SYS_execve,
            Some(DynamicLifecycleOptions::fork_only()),
            "dynamic creation and later exec are not yet qualified",
        ),
        (
            libc::SYS_execveat,
            Some(DynamicLifecycleOptions::fork_only()),
            "dynamic creation and later exec are not yet qualified",
        ),
    ] {
        let mut code = seed();
        syscall(&mut code, number as u64);
        write_marker(&mut code, 0x55556666);
        code.extend_from_slice(&[0x0f, 0x0b]);
        let fixture = Fixture::new(code);
        let command = LaunchCommand::new(&fixture.path);
        let mut session = match options {
            Some(options) => DynamicSession::launch_with_lifecycle(&command, options, TIMEOUT),
            None => DynamicSession::launch(&command, TIMEOUT),
        }
        .unwrap();
        let pid = session.pid();
        let handle = pin(pid);
        let initial = session.initial_event().clone();
        release(&mut session, &initial);
        let exit = session.next_event(TIMEOUT).unwrap();
        release(&mut session, &exit);
        let entry = next_entry(&mut session, number as u64);
        assert_eq!(
            snapshot(&mut session, &entry, &fixture.code).data,
            vec![0; 64]
        );
        assert!(
            matches!(session.resume(entry.stop_token().unwrap(),DynamicResume::Continue),Err(LaunchError::Invalid(message)) if message == expected)
        );
        finish(session, &[(pid, handle)]);
    }
}
#[test]
fn per_task_tokens_interrupts_and_parent_death_keep_two_owned_incarnations() {
    let _serial = FILE_FORK.lock().unwrap();
    let fixture = Fixture::new(spin_fork_program());
    let mut session = fixture.launch();
    let parent = session.pid();
    let parent_handle = pin(parent);
    let initial = initialize(&mut session);
    release(&mut session, &initial);
    let entry = next_entry(&mut session, libc::SYS_fork as u64);
    let pair = create(&mut session, &entry);
    let parent_exit = returned(&mut session, &pair.created, i64::from(pair.child));
    // This is the actual automatic return-ready checkpoint, not a syscall EXIT.
    let child_return_ready = pair.newborn.clone();
    let old = pair.created.stop_token().unwrap().clone();
    let parent_before = snapshot(&mut session, &parent_exit, &fixture.code);
    let child_before = snapshot(&mut session, &child_return_ready, &fixture.code);
    let mut other = fixture.launch();
    let other_pid = other.pid();
    let other_handle = pin(other_pid);
    let foreign = initialize(&mut other);
    let foreign_before = snapshot(&mut other, &foreign, &fixture.code);
    assert!(
        session
            .read_registers(foreign.stop_token().unwrap())
            .is_err()
    );
    assert!(session.read_xstate(foreign.stop_token().unwrap()).is_err());
    assert!(
        session
            .resume(foreign.stop_token().unwrap(), DynamicResume::Continue)
            .is_err()
    );
    assert!(
        session
            .interrupt_task(foreign.task.unwrap().task, TIMEOUT)
            .is_err()
    );
    assert!(
        other
            .read_registers(parent_exit.stop_token().unwrap())
            .is_err()
    );
    assert!(
        other
            .resume(
                child_return_ready.stop_token().unwrap(),
                DynamicResume::Continue
            )
            .is_err()
    );
    assert!(
        other
            .interrupt_task(entry.task.unwrap().task, TIMEOUT)
            .is_err()
    );
    assert_eq!(
        snapshot(&mut other, &foreign, &fixture.code),
        foreign_before
    );
    assert!(session.read_registers(&old).is_err());
    assert!(session.resume(&old, DynamicResume::Continue).is_err());
    assert_eq!(
        snapshot(&mut session, &parent_exit, &fixture.code),
        parent_before
    );
    assert_eq!(
        snapshot(&mut session, &child_return_ready, &fixture.code),
        child_before
    );
    release(&mut session, &parent_exit);
    release(&mut session, &child_return_ready);
    let child_stop = session
        .interrupt_task(pair.newborn.task.unwrap().task, TIMEOUT)
        .unwrap();
    assert_eq!(child_stop.task, pair.newborn.task);
    assert_eq!(child_stop.kind, DynamicEventKind::Interrupted);
    let child_held = snapshot(&mut session, &child_stop, &fixture.code);
    assert_eq!(child_held.registers.rip, child_before.registers.rip);
    assert_eq!(child_held.registers.rsp, STACK);
    assert_eq!(child_held.registers.rax, 0);
    assert_eq!(child_held.xstate, child_before.xstate);
    assert_eq!(child_held.stack, child_before.stack);
    assert_eq!(child_held.data, child_before.data);
    let parent_stop = session
        .interrupt_task(entry.task.unwrap().task, TIMEOUT)
        .unwrap();
    assert_eq!(parent_stop.task, entry.task);
    let parent_held = snapshot(&mut session, &parent_stop, &fixture.code);
    assert_eq!(parent_held.registers.rip, parent_before.registers.rip);
    assert_eq!(parent_held.registers.rsp, STACK);
    assert_eq!(parent_held.registers.rax, pair.child as u64);
    assert_eq!(parent_held.xstate, parent_before.xstate);
    assert_eq!(parent_held.stack, parent_before.stack);
    assert_eq!(parent_held.data, parent_before.data);
    // Full snapshots are compared at the same authenticated interrupt phase;
    // syscall orig_rax bookkeeping is not a fabricated user register invariant.
    release(&mut session, &child_stop);
    release(&mut session, &parent_stop);
    let child_again = session
        .interrupt_task(pair.newborn.task.unwrap().task, TIMEOUT)
        .unwrap();
    let parent_again = session
        .interrupt_task(entry.task.unwrap().task, TIMEOUT)
        .unwrap();
    assert_ne!(child_again.stop_token(), child_stop.stop_token());
    assert_ne!(parent_again.stop_token(), parent_stop.stop_token());
    assert!(
        session
            .read_registers(child_stop.stop_token().unwrap())
            .is_err()
    );
    assert_eq!(
        snapshot(&mut session, &child_again, &fixture.code),
        child_held
    );
    assert_eq!(
        snapshot(&mut session, &parent_again, &fixture.code),
        parent_held
    );
    // Kill the real parent before it ever waits. The session broker must adopt
    // and physically reap the child; tracer terminal alone cannot satisfy this.
    signal(&parent_handle, libc::SIGKILL);
    finish(
        session,
        &[(parent, parent_handle), (pair.child, pair.handle)],
    );
    assert_eq!(
        snapshot(&mut other, &foreign, &fixture.code),
        foreign_before
    );
    finish(other, &[(other_pid, other_handle)]);
}
#[test]
fn running_fork_pair_deadline_closes_and_physically_reaps_both() {
    let _serial = FILE_FORK.lock().unwrap();
    let fixture = Fixture::new(spin_fork_program());
    let mut session = fixture.launch();
    let parent = session.pid();
    let handle = pin(parent);
    let initial = initialize(&mut session);
    release(&mut session, &initial);
    let entry = next_entry(&mut session, libc::SYS_fork as u64);
    let pair = create(&mut session, &entry);
    let parent_exit = returned(&mut session, &pair.created, i64::from(pair.child));
    // This is the actual automatic return-ready checkpoint, not a syscall EXIT.
    let child_return_ready = pair.newborn.clone();
    release(&mut session, &parent_exit);
    release(&mut session, &child_return_ready);
    assert!(matches!(
        session.next_event(Duration::from_millis(20)),
        Err(LaunchError::Timeout(_))
    ));
    finish(session, &[(parent, handle), (pair.child, pair.handle)]);
}

#[test]
fn failed_native_fork_retries_do_not_invent_child_records() {
    let _serial = FILE_FORK.lock().unwrap();
    // The original child alone lowers its own RLIMIT_NPROC to zero. This is an
    // unprivileged profile: a host running with root/resource override is not
    // silently skipped or presented as equivalent failed-fork evidence.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "unprivileged fork-failure fixture required"
    );
    let mut code = seed();
    mov(&mut code, 7, libc::RLIMIT_NPROC as u64);
    mov(&mut code, 6, DATA + 32);
    syscall(&mut code, libc::SYS_setrlimit as u64);
    syscall(&mut code, libc::SYS_fork as u64);
    syscall(&mut code, libc::SYS_fork as u64);
    code.extend_from_slice(&[0x0f, 0x0b]);
    let fixture = Fixture::new(code);
    let mut session = fixture.launch();
    let pid = session.pid();
    let handle = pin(pid);
    let initial = initialize(&mut session);
    release(&mut session, &initial);
    let limits = next_entry(&mut session, libc::SYS_setrlimit as u64);
    let applied = returned(&mut session, &limits, 0);
    release(&mut session, &applied);
    for _ in 0..2 {
        let entry = next_entry(&mut session, libc::SYS_fork as u64);
        let before = snapshot(&mut session, &entry, &fixture.code);
        release(&mut session, &entry);
        let failed = session.next_event(TIMEOUT).unwrap();
        assert_eq!(
            failed.kind,
            DynamicEventKind::SyscallExit {
                result: -i64::from(libc::EAGAIN),
                is_error: true
            }
        );
        let actual = snapshot(&mut session, &failed, &fixture.code);
        let mut expected = before;
        expected.registers.rax = (-i64::from(libc::EAGAIN)) as u64;
        assert_eq!(actual, expected);
        assert_eq!(failed.task, entry.task);
        let state = session.lifecycle_snapshot().unwrap().unwrap();
        assert_eq!(state.tasks().count(), 1);
        assert_eq!(state.address_spaces().count(), 1);
        release(&mut session, &failed);
    }
    let terminal = session.next_event(TIMEOUT).unwrap();
    assert!(
        matches!(terminal.kind,DynamicEventKind::SignalDelivery(ref signal) if signal.signal()==libc::SIGILL && signal.code()==2)
    );
    finish(session, &[(pid, handle)]);
}

fn observed_first_user(fixture: &Fixture) -> Run {
    let mut session = fixture.launch();
    let parent = session.pid();
    let parent_handle = pin(parent);
    let initial = initialize(&mut session);
    release(&mut session, &initial);
    let entry = next_entry(&mut session, libc::SYS_fork as u64);
    let mut phases = vec![snapshot(&mut session, &entry, &fixture.code)];
    let pair = create(&mut session, &entry);
    let parent_exit = returned(&mut session, &pair.created, i64::from(pair.child));
    phases.push(snapshot(&mut session, &parent_exit, &fixture.code));
    phases.push(snapshot(&mut session, &pair.newborn, &fixture.code));
    release(&mut session, &pair.newborn);
    let fault = session.next_event(TIMEOUT).unwrap();
    assert_eq!(fault.task, pair.newborn.task);
    let DynamicEventKind::SignalDelivery(ref info) = fault.kind else {
        panic!("first original child instruction must fault: {fault:?}")
    };
    assert_eq!(info.signal(), libc::SIGILL);
    assert_eq!(info.code(), 2);
    assert_eq!(
        info.fault_address(),
        Some(ENTRY + fixture.code.len() as u64 - 2)
    );
    phases.push(snapshot(&mut session, &fault, &fixture.code));
    assert_eq!(
        snapshot(&mut session, &parent_exit, &fixture.code),
        phases[1]
    );
    assert!(
        session
            .read_registers(pair.newborn.stop_token().unwrap())
            .is_err()
    );
    finish(
        session,
        &[(parent, parent_handle), (pair.child, pair.handle)],
    );
    Run {
        child: pair.child,
        phases,
    }
}

fn raw_first_user(path: &Path, code: &[u8]) -> Run {
    let mut raw = Raw::launch(path);
    let parent = raw.parent.id() as i32;
    raw.resume(parent, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        parent,
        libc::PTRACE_SYSCALL_INFO_ENTRY,
        libc::SYS_fork as u64,
    );
    let mut phases = vec![raw_snapshot(parent, code)];
    raw.resume(parent, libc::PTRACE_SYSCALL, 0);
    let mut child = None;
    let mut born = None;
    while child.is_none() || born.is_none() {
        let (tid, status) = raw.wait();
        assert!(libc::WIFSTOPPED(status));
        if tid == parent {
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            assert_eq!(status >> 16, libc::PTRACE_EVENT_FORK);
            let mut value = 0_u64;
            trace(
                parent,
                libc::PTRACE_GETEVENTMSG,
                0,
                (&raw mut value) as usize,
            );
            let value = i32::try_from(value).unwrap();
            assert!(value > 0);
            raw.pins.entry(value).or_insert_with(|| pin(value));
            assert!(child.replace(value).is_none());
        } else {
            assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
            assert_eq!(status >> 16, 0);
            assert!(born.replace(tid).is_none());
        }
    }
    let child = child.unwrap();
    assert_eq!(born, Some(child));
    raw.resume(parent, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        parent,
        libc::PTRACE_SYSCALL_INFO_EXIT,
        libc::SYS_fork as u64,
    );
    phases.push(raw_snapshot(parent, code));
    phases.push(raw_snapshot(child, code));
    raw.resume(child, libc::PTRACE_SYSCALL, 0);
    let (tid, status) = raw.wait();
    assert_eq!(tid, child);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGILL);
    assert_eq!(status >> 16, 0);
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    trace(child, libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
    assert_eq!(info.si_signo, libc::SIGILL);
    assert_eq!(info.si_code, 2);
    assert_eq!(
        unsafe { info.si_addr() } as u64,
        ENTRY + code.len() as u64 - 2
    );
    phases.push(raw_snapshot(child, code));
    assert_eq!(raw_snapshot(parent, code), phases[1]);
    assert!(
        raw.cleanup(),
        "first-user oracle foreground cleanup deadline"
    );
    Run { child, phases }
}

fn first_user_comparable(run: &Run, code: &[u8]) -> Vec<Snapshot> {
    assert_eq!(run.phases.len(), 4);
    let entry = &run.phases[0];
    assert_eq!(entry.registers.orig_rax, libc::SYS_fork as u64);
    assert_eq!(entry.registers.eflags, FLAGS);
    assert_eq!(entry.registers.rip, ENTRY + code.len() as u64 - 2);
    let mut parent_return = entry.clone();
    parent_return.registers.rax = run.child as u64;
    assert_eq!(run.phases[1], parent_return);
    let mut child_return_ready = entry.clone();
    child_return_ready.registers.rax = 0;
    assert_eq!(run.phases[2], child_return_ready);
    // These are the native UD2 exception effects. Keep both RF and orig_rax in
    // the full-state comparison rather than masking fault-entry bookkeeping.
    let mut fault = child_return_ready;
    fault.registers.orig_rax = u64::MAX;
    fault.registers.eflags |= 1 << 16;
    assert_eq!(run.phases[3], fault);
    let mut output = run.phases.clone();
    // Only the actual, independently asserted parent PID result differs by run.
    output[1].registers.rax = 1;
    output
}

#[test]
fn child_first_original_ud2_matches_independent_native_full_state() {
    if let Some(role) = std::env::var_os(ORACLE_ROLE) {
        assert_eq!(role, "first-user");
        let path = PathBuf::from(std::env::var_os(ORACLE_IMAGE).unwrap());
        let record = PathBuf::from(std::env::var_os(ORACLE_RECORD).unwrap());
        let run = raw_first_user(&path, &first_user_fault_program());
        save_counted(&record, &run, 4);
        println!("FORK_FIRST_USER_NATIVE_PHYSICAL_CLEANUP_COMPLETE");
        return;
    }
    let _serial = FILE_FORK.lock().unwrap();
    let fixture = Fixture::new(first_user_fault_program());
    let record = fixture.directory.join("native-first-user.bin");
    isolated_test(
        &fixture,
        "first-user",
        &record,
        "FORK_FIRST_USER_NATIVE_PHYSICAL_CLEANUP_COMPLETE",
        FIRST_USER_TEST,
    );
    let original = load_counted(&record, 4);
    let actual = observed_first_user(&fixture);
    let expected = first_user_comparable(&original, &fixture.code);
    let actual = first_user_comparable(&actual, &fixture.code);
    assert_eq!(actual, expected);
    for corruption in 0..10 {
        let mut corrupted = expected.clone();
        match corruption {
            0 => corrupted[3].registers.rax ^= 1,
            1 => corrupted[3].registers.r15 ^= 1,
            2 => corrupted[3].registers.eflags ^= 1 << 16,
            3 => corrupted[3].registers.orig_rax ^= 1,
            4 => corrupted[3].registers.rip += 1,
            5 => corrupted[3].registers.rsp ^= 8,
            6 => corrupted[3].xstate[0] ^= 1,
            7 => corrupted[3].stack[0] ^= 1,
            8 => corrupted[3].data[0] ^= 1,
            9 => corrupted[3].mask ^= 1,
            _ => unreachable!(),
        }
        assert_ne!(
            actual, corrupted,
            "first-user comparator accepted corruption {corruption}"
        );
    }
}
