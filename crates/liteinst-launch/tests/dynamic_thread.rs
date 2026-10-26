#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Bounded native thread ownership. The independent raw oracle runs in an
//! exec-isolated natural-parent subreaper and pins nonleaders with PIDFD_THREAD.
//! A thread terminal is distinct from leader/process physical reaping.
use liteinst_launch::lifecycle::{ExitStatus, HoldReason, TaskOrigin, TaskState, TerminalReason};
use liteinst_launch::{
    DynamicCreationPolicy, DynamicEvent, DynamicEventKind, DynamicExecPolicy,
    DynamicLifecycleOptions, DynamicResume, DynamicSession, DynamicSessionOptions, FirstImage,
    LaunchCommand, LaunchError, RegisterSnapshot,
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
const WORKER_STACK: u64 = DATA + 2 * PAGE as u64 - 64;
const THREAD_FLAGS: u64 = 0x10f00;
const PIDFD_THREAD: i32 = 0x80;
const FLAGS: u64 = 0xed7;
const RESULT_SIZE: usize = 512;
const MASK: u64 = 1 << (libc::SIGUSR2 - 1);
const MARKER: u64 = 0x123456789abcdef0;
const TIMEOUT: Duration = Duration::from_secs(3);
const ORACLE_ROLE: &str = "LITEINST_THREAD_NATIVE_ORACLE";
const ORACLE_IMAGE: &str = "LITEINST_THREAD_NATIVE_IMAGE";
const ORACLE_RECORD: &str = "LITEINST_THREAD_NATIVE_RECORD";
const ORACLE_TEST: &str =
    "clone_phases_and_first_original_instructions_match_independent_native_state";
static NEXT: AtomicUsize = AtomicUsize::new(0);
static FILE_FORK: Mutex<()> = Mutex::new(());

struct Fixture {
    directory: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "dynamic-thread-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(directory.parent().unwrap()).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        Self { directory }
    }
    fn image(
        &self,
        name: &str,
        code: &[u8],
        data: &[u8],
        pie: bool,
        interp: Option<&Path>,
    ) -> PathBuf {
        let path = self.directory.join(name);
        let mut image = vec![0; 7 * PAGE];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [
            (16, if pie { 3_u16 } else { 2 }),
            (18, 62),
            (52, 64),
            (54, 56),
            (56, if interp.is_some() { 4 } else { 3 }),
        ] {
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
            (24, if pie { 4096 } else { ENTRY }),
            (32, 64),
            (80, if pie { 0 } else { 0x400000 }),
            (96, 8192),
            (104, 8192),
            (112, 4096),
            (128, 8192),
            (136, if pie { 8192 } else { DATA }),
            (152, 5 * 4096),
            (160, 5 * 4096),
            (168, 4096),
            (224, 16),
        ] {
            image[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        if let Some(interp) = interp {
            let path = interp.as_os_str().as_encoded_bytes();
            assert!(path.len() + 1 < 512);
            image[512..512 + path.len()].copy_from_slice(path);
            for (at, value) in [(232, 3_u32), (236, 4)] {
                image[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            for (at, value) in [
                (240, 512_u64),
                (248, 512),
                (264, path.len() as u64 + 1),
                (272, path.len() as u64 + 1),
                (280, 1),
            ] {
                image[at..at + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        assert!(code.len() < PAGE && data.len() <= 5 * PAGE);
        image[PAGE..PAGE + code.len()].copy_from_slice(code);
        image[2 * PAGE..2 * PAGE + data.len()].copy_from_slice(data);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&image).unwrap();
        drop(file);
        path
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
fn syscall(code: &mut Vec<u8>, nr: u64) {
    mov(code, 0, nr);
    code.extend_from_slice(&[0x0f, 0x05]);
}
fn store_rax(code: &mut Vec<u8>, address: u64) {
    code.extend_from_slice(&[0x48, 0xa3]);
    code.extend_from_slice(&address.to_le_bytes());
}
fn call(code: &mut Vec<u8>, nr: i64, args: &[(u8, u64)]) {
    for &(reg, value) in args {
        mov(code, reg, value);
    }
    syscall(code, nr as u64);
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
    mov(&mut code, 4, WORKER_STACK);
    for (offset, value) in [
        (0, 0x10203040_u32),
        (8, 0x50607080),
        (16, 0x11225566),
        (24, 0x33447788),
    ] {
        code.extend_from_slice(&[0x48, 0xc7, 0x44, 0x24, offset]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    mov(&mut code, 4, STACK);
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
fn initial_data() -> Vec<u8> {
    let mut data = vec![0; 2048];
    for offset in [
        0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 88, 96, 104, 112, 120, 128, 144, 152, 160, 168, 176,
        184,
    ] {
        data[offset..offset + 8].copy_from_slice(&MARKER.to_le_bytes());
    }
    data[512..520].copy_from_slice(&MASK.to_le_bytes());
    data[608..616].copy_from_slice(&(DATA + 3 * PAGE as u64).to_le_bytes());
    data[624..632].copy_from_slice(&8192_u64.to_le_bytes());
    data
}
fn prefix(altstack: bool) -> Vec<u8> {
    let mut code = Vec::new();
    call(
        &mut code,
        libc::SYS_arch_prctl,
        &[(7, 0x5005), (6, DATA + 176)],
    );
    store_rax(&mut code, DATA + 184);
    call(
        &mut code,
        libc::SYS_rt_sigprocmask,
        &[
            (7, libc::SIG_SETMASK as u64),
            (6, DATA + 512),
            (2, 0),
            (10, 8),
        ],
    );
    store_rax(&mut code, DATA + 160);
    if altstack {
        call(&mut code, libc::SYS_sigaltstack, &[(7, DATA + 608), (6, 0)]);
        store_rax(&mut code, DATA + 168);
    }
    code.extend_from_slice(&seed());
    code
}
fn seed_flags(code: &mut Vec<u8>) {
    code.push(0x68);
    code.extend_from_slice(&(FLAGS as u32).to_le_bytes());
    code.push(0x9d);
}
fn clone_instruction(code: &mut Vec<u8>, flags: u64, stack: u64, extra: [u64; 3]) {
    call(
        code,
        libc::SYS_clone,
        &[
            (7, flags),
            (6, stack),
            (2, extra[0]),
            (10, extra[1]),
            (8, extra[2]),
        ],
    );
}
fn first_user_program() -> Vec<u8> {
    let mut code = prefix(false);
    clone_instruction(&mut code, THREAD_FLAGS, WORKER_STACK, [0; 3]);
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
fn store_imm(code: &mut Vec<u8>, address: u64, value: u32) {
    code.extend_from_slice(&[0xc7, 0x04, 0x25]);
    code.extend_from_slice(&(address as u32).to_le_bytes());
    code.extend_from_slice(&value.to_le_bytes());
}
fn branch_worker(code: &mut Vec<u8>) -> usize {
    code.extend_from_slice(&[0x48, 0x85, 0xc0, 0x0f, 0x84]);
    let at = code.len();
    code.extend_from_slice(&[0; 4]);
    at
}
fn bind_worker(code: &mut [u8], at: usize, worker: usize) {
    code[at..at + 4].copy_from_slice(&i32::try_from(worker - at - 4).unwrap().to_le_bytes());
}
fn shared_program(second_clone: bool) -> Vec<u8> {
    let mut code = prefix(true);
    clone_instruction(&mut code, THREAD_FLAGS, WORKER_STACK, [0; 3]);
    let branch = branch_worker(&mut code);
    seed_flags(&mut code);
    call(&mut code, libc::SYS_sigaltstack, &[(7, 0), (6, DATA + 64)]);
    store_rax(&mut code, DATA + 88);
    store_imm(&mut code, DATA + 16, 0x11223344);
    syscall(&mut code, libc::SYS_getpid as u64);
    if second_clone {
        clone_instruction(&mut code, THREAD_FLAGS, WORKER_STACK, [0; 3]);
    }
    code.extend_from_slice(&[0x0f, 0x0b]);
    let worker = code.len();
    bind_worker(&mut code, branch, worker);
    seed_flags(&mut code);
    call(&mut code, libc::SYS_sigaltstack, &[(7, 0), (6, DATA + 128)]);
    store_rax(&mut code, DATA + 152);
    store_imm(&mut code, DATA + 24, 0x55667788);
    call(&mut code, libc::SYS_exit, &[(7, 23)]);
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
fn spin_program(leader_exits: bool) -> Vec<u8> {
    let mut code = prefix(false);
    clone_instruction(&mut code, THREAD_FLAGS, WORKER_STACK, [0; 3]);
    let branch = branch_worker(&mut code);
    if leader_exits {
        call(&mut code, libc::SYS_exit, &[(7, 17)]);
    }
    code.extend_from_slice(&[0xeb, 0xfe]);
    let worker = code.len();
    bind_worker(&mut code, branch, worker);
    code.extend_from_slice(&[0xeb, 0xfe]);
    code
}
fn options(exec: bool) -> DynamicSessionOptions {
    DynamicSessionOptions {
        lifecycle: DynamicLifecycleOptions::thread_only(),
        exec: if exec {
            DynamicExecPolicy::ExecveOnce
        } else {
            DynamicExecPolicy::Refuse
        },
    }
}
fn pin(pid: i32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0, "pidfd_open: {}", io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}
fn pin_task(tid: i32, leader: i32) -> OwnedFd {
    if tid == leader {
        return pin(tid);
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, PIDFD_THREAD) };
    assert!(fd >= 0, "thread pidfd_open: {}", io::Error::last_os_error());
    let handle = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let status = fs::read_to_string(format!("/proc/{tid}/status")).unwrap();
    let tgid = status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:\t"))
        .unwrap()
        .parse::<i32>()
        .unwrap();
    assert_eq!(tgid, leader);
    handle
}
fn poll_bits(fd: &OwnedFd) -> i16 {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert!(unsafe { libc::poll(&raw mut p, 1, 0) } >= 0);
    p.revents
}
fn reaped(fd: &OwnedFd) {
    assert_ne!(poll_bits(fd) & libc::POLLIN, 0);
    assert_ne!(poll_bits(fd) & libc::POLLHUP, 0);
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
fn finish(s: DynamicSession, handles: &[(i32, OwnedFd)]) {
    let mut actual = s.terminate(TIMEOUT).unwrap().reaped;
    let mut expected = handles.iter().map(|(tid, _)| *tid).collect::<Vec<_>>();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
    for (_, pin) in handles {
        reaped(pin);
    }
}
fn release(s: &mut DynamicSession, e: &DynamicEvent) {
    s.resume(e.stop_token().unwrap(), DynamicResume::Continue)
        .unwrap();
}
fn next(s: &mut DynamicSession) -> DynamicEvent {
    s.next_event(TIMEOUT).unwrap()
}
fn initialize(s: &mut DynamicSession) -> DynamicEvent {
    let e = s.initial_event().clone();
    let mut expected = s.read_registers(e.stop_token().unwrap()).unwrap();
    assert_eq!(expected.rax as i64, -i64::from(libc::ENOSYS));
    release(s, &e);
    let exit = next(s);
    assert_eq!(
        exit.kind,
        DynamicEventKind::SyscallExit {
            result: 0,
            is_error: false
        }
    );
    expected.rax = 0;
    assert_eq!(
        s.read_registers(exit.stop_token().unwrap()).unwrap(),
        expected
    );
    exit
}
fn entry(s: &mut DynamicSession, held: &DynamicEvent, nr: u64) -> DynamicEvent {
    release(s, held);
    for _ in 0..32 {
        let e = next(s);
        match e.kind {
            DynamicEventKind::SyscallEntry { number, .. } if number == nr => return e,
            DynamicEventKind::SyscallEntry { .. } | DynamicEventKind::SyscallExit { .. } => {
                release(s, &e)
            }
            _ => panic!("unexpected seeking syscall {nr}: {e:?}"),
        }
    }
    panic!("entry bound")
}
fn returned(s: &mut DynamicSession, held: &DynamicEvent, result: i64) -> DynamicEvent {
    release(s, held);
    let e = next(s);
    assert_eq!(e.tid, held.tid);
    assert_eq!(
        e.kind,
        DynamicEventKind::SyscallExit {
            result,
            is_error: false
        }
    );
    e
}
fn fault(s: &mut DynamicSession, held: &DynamicEvent) -> DynamicEvent {
    release(s, held);
    let e = next(s);
    let DynamicEventKind::SignalDelivery(ref i) = e.kind else {
        panic!("{e:?}")
    };
    assert_eq!(i.signal(), libc::SIGILL);
    assert_eq!(i.code(), 2);
    assert_eq!(
        i.fault_address(),
        Some(s.read_registers(e.stop_token().unwrap()).unwrap().rip)
    );
    e
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    stack: Vec<u8>,
    data: Vec<u8>,
    mask: u64,
}
fn snapshot(s: &mut DynamicSession, e: &DynamicEvent, code: &[u8]) -> Snapshot {
    let t = e.stop_token().unwrap();
    assert_eq!(s.read_memory(t, ENTRY, code.len()).unwrap(), code);
    let mut stack = s.read_memory(t, STACK, 32).unwrap();
    stack.extend(s.read_memory(t, WORKER_STACK, 32).unwrap());
    Snapshot {
        registers: s.read_registers(t).unwrap(),
        xstate: s.read_xstate(t).unwrap(),
        stack,
        data: s.read_memory(t, DATA, RESULT_SIZE).unwrap(),
        mask: s.signal_mask(t).unwrap(),
    }
}
fn create(s: &mut DynamicSession, e: &DynamicEvent) -> (DynamicEvent, DynamicEvent, OwnedFd) {
    let before = s.lifecycle_snapshot().unwrap().unwrap();
    let prior_tasks = before.tasks().count();
    let prior_mms = before.address_spaces().count();
    release(s, e);
    let parent = next(s);
    let DynamicEventKind::Created { child } = parent.kind else {
        panic!("{parent:?}")
    };
    let born = next(s);
    assert_eq!(born.task, Some(child));
    assert_eq!(
        born.kind,
        DynamicEventKind::Newborn {
            parent: e.task.unwrap()
        }
    );
    let original = e.task.unwrap();
    assert_ne!(child.task, original.task);
    assert_eq!(child.process, original.process);
    assert_eq!(child.address_space, original.address_space);
    assert_eq!(child.generation, original.generation);
    let pin = pin_task(born.tid, parent.tid);
    let records = s.lifecycle_snapshot().unwrap().unwrap();
    assert_eq!(records.tasks().count(), prior_tasks + 1);
    assert_eq!(records.address_spaces().count(), prior_mms);
    assert_eq!(
        records.tasks().find(|t| t.id == child.task).unwrap().origin,
        TaskOrigin::Created {
            parent: original.task,
            request: liteinst_launch::lifecycle::CreationRequest::Clone {
                flags: THREAD_FLAGS
            }
        }
    );
    assert_eq!(
        records.tasks().find(|t| t.id == child.task).unwrap().state,
        TaskState::Held {
            pc: s.read_registers(born.stop_token().unwrap()).unwrap().rip,
            reason: HoldReason::NewbornReturnReady
        }
    );
    (parent, born, pin)
}
include!("support/dynamic_thread_raw.rs");
fn raw_snapshot(tid: i32, code: &[u8]) -> Snapshot {
    assert_eq!(raw_memory(tid, ENTRY, code.len()), code);
    let mut xstate = vec![0; 65536];
    let mut iov = libc::iovec {
        iov_base: xstate.as_mut_ptr().cast(),
        iov_len: xstate.len(),
    };
    trace(tid, libc::PTRACE_GETREGSET, 0x202, (&raw mut iov) as usize);
    xstate.truncate(iov.iov_len);
    let mut mask = 0;
    trace(tid, libc::PTRACE_GETSIGMASK, 8, (&raw mut mask) as usize);
    let mut stack = raw_memory(tid, STACK, 32);
    stack.extend(raw_memory(tid, WORKER_STACK, 32));
    Snapshot {
        registers: raw_registers(tid),
        xstate,
        stack,
        data: raw_memory(tid, DATA, RESULT_SIZE),
        mask,
    }
}
fn raw_entry(raw: &mut Raw, pid: i32, nr: u64) {
    for _ in 0..32 {
        let (tid, status) = raw.wait();
        assert_eq!(tid, pid);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP | 0x80);
        let mut info: libc::ptrace_syscall_info = unsafe { std::mem::zeroed() };
        trace(
            pid,
            libc::PTRACE_GET_SYSCALL_INFO,
            std::mem::size_of_val(&info),
            (&raw mut info) as usize,
        );
        assert_eq!(info.arch, 0xc000003e);
        if info.op == libc::PTRACE_SYSCALL_INFO_ENTRY && unsafe { info.u.entry.nr } == nr {
            return;
        }
        assert!(matches!(
            info.op,
            libc::PTRACE_SYSCALL_INFO_ENTRY | libc::PTRACE_SYSCALL_INFO_EXIT
        ));
        raw.resume(pid, libc::PTRACE_SYSCALL, 0);
    }
    panic!("raw entry bound")
}
fn raw_fault(raw: &mut Raw, pid: i32) {
    let (tid, status) = raw.wait();
    assert_eq!(tid, pid);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGILL);
    assert_eq!(status >> 16, 0);
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    trace(pid, libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
    assert_eq!(info.si_code, 2);
    assert_eq!(unsafe { info.si_addr() } as u64, raw_registers(pid).rip);
}
struct Run {
    leader: i32,
    worker: i32,
    phases: Vec<Snapshot>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// This certifies only user shadow-stack/WRSS state, never unrelated CET modes.
enum RawCetCertificate {
    StatusZero,
    AbiAbsent,
}
struct CertifiedRun {
    run: Run,
    certificate: RawCetCertificate,
}
fn original_cet_output(data: &[u8], certificate: RawCetCertificate) {
    let (state, result) = match certificate {
        RawCetCertificate::StatusZero => (0, 0),
        RawCetCertificate::AbiAbsent => (MARKER, (-i64::from(libc::EINVAL)) as u64),
    };
    assert_eq!(&data[176..184], &state.to_le_bytes());
    assert_eq!(&data[184..192], &result.to_le_bytes());
}
fn raw_tracer_unfiltered() {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    assert!(tid > 0 && tid <= i64::from(i32::MAX));
    let file = fs::File::open("/proc/thread-self/status").unwrap();
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::fstatfs(file.as_raw_fd(), &raw mut filesystem) },
        0
    );
    assert_eq!(filesystem.f_type, 0x9fa0);
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 16 * 1024);
    let status = std::str::from_utf8(&bytes).unwrap();
    assert!(status.ends_with('\n') && !status.contains('\0'));
    let (mut pid, mut seccomp) = (None, None);
    for line in status.lines() {
        let (field, value) = line.split_once(':').expect("malformed proc status field");
        assert!(
            !field.is_empty()
                && field
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        );
        if field == "Pid" || field == "Seccomp" {
            let values = value.split_ascii_whitespace().collect::<Vec<_>>();
            assert_eq!(values.len(), 1);
            if field == "Pid" {
                assert!(pid.replace(values[0]).is_none());
            } else {
                assert!(seccomp.replace(values[0]).is_none());
            }
        }
    }
    let expected_pid = tid.to_string();
    assert_eq!(pid, Some(expected_pid.as_str()));
    assert_eq!(seccomp, Some("0"));
}
fn raw_status_absent(tid: i32) {
    let mut state = MARKER;
    let result = unsafe { libc::ptrace(30_u32, tid, (&raw mut state) as usize, 0x5005_usize) };
    let error = io::Error::last_os_error().raw_os_error();
    assert_eq!(result, -1);
    assert_eq!(error, Some(libc::EINVAL));
    assert_eq!(state, MARKER);
}
fn raw_cet_disabled(tid: i32) -> RawCetCertificate {
    let mut state = MARKER;
    let result = unsafe { libc::ptrace(30_u32, tid, (&raw mut state) as usize, 0x5005_usize) };
    let error = io::Error::last_os_error().raw_os_error();
    let certificate = if result == 0 {
        assert_eq!(state, 0, "per-task CET state must be observed disabled");
        RawCetCertificate::StatusZero
    } else {
        assert_eq!(result, -1);
        assert_eq!(error, Some(libc::EINVAL));
        assert_eq!(state, MARKER);
        // Under the conforming native Linux ABI, an absent SHSTK regset gives
        // EINVAL; the present getter can return ENODEV, which is not proof.
        // Repeat STATUS inside the seccomp-free interval. A concurrent TSYNC
        // filter cannot disappear before the final per-thread mode check.
        raw_tracer_unfiltered();
        let before = raw_registers(tid);
        assert_eq!(before.cs, 0x33);
        let mut general = [MARKER; 27];
        let general_base = general.as_mut_ptr().cast();
        let mut general_iov = libc::iovec {
            iov_base: general_base,
            iov_len: 216,
        };
        trace(
            tid,
            libc::PTRACE_GETREGSET,
            1,
            (&raw mut general_iov) as usize,
        );
        assert_eq!(general_iov.iov_base, general_base);
        assert_eq!(general_iov.iov_len, 216);
        assert_eq!(registers(general), before);
        let mut fs_base = !before.fs_base;
        trace(tid, 30, (&raw mut fs_base) as usize, 0x1003);
        assert_eq!(fs_base, before.fs_base);
        raw_status_absent(tid);
        let mut shadow_stack = MARKER;
        let shadow_base = (&raw mut shadow_stack).cast();
        let mut shadow_iov = libc::iovec {
            iov_base: shadow_base,
            iov_len: 8,
        };
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                tid,
                0x204_usize,
                (&raw mut shadow_iov) as usize,
            )
        };
        let error = io::Error::last_os_error().raw_os_error();
        assert_eq!(result, -1);
        assert_eq!(error, Some(libc::EINVAL));
        assert_eq!(shadow_stack, MARKER);
        assert_eq!(shadow_iov.iov_base, shadow_base);
        assert_eq!(shadow_iov.iov_len, 8);
        raw_tracer_unfiltered();
        assert_eq!(raw_registers(tid), before);
        RawCetCertificate::AbiAbsent
    };
    original_cet_output(&raw_memory(tid, DATA, RESULT_SIZE), certificate);
    certificate
}
fn raw_run(path: &Path, code: &[u8]) -> CertifiedRun {
    let mut raw = Raw::launch(path);
    let leader = raw.parent.id() as i32;
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    raw_entry(&mut raw, leader, libc::SYS_clone as u64);
    let mut phases = vec![raw_snapshot(leader, code)];
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    let (mut created, mut newborn) = (None, None);
    while created.is_none() || newborn.is_none() {
        let (tid, status) = raw.wait();
        assert!(libc::WIFSTOPPED(status));
        if tid == leader {
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            assert_eq!(status >> 16, libc::PTRACE_EVENT_CLONE);
            let mut id = 0_u64;
            trace(tid, libc::PTRACE_GETEVENTMSG, 0, (&raw mut id) as usize);
            let worker = i32::try_from(id).unwrap();
            raw.pins
                .entry(worker)
                .or_insert_with(|| pin_task(worker, leader));
            assert!(created.replace(worker).is_none());
        } else {
            assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
            assert!(newborn.replace(tid).is_none());
        }
    }
    let worker = created.unwrap();
    assert_eq!(newborn, Some(worker));
    let certificate = raw_cet_disabled(leader);
    assert_eq!(raw_cet_disabled(worker), certificate);
    phases.push(raw_snapshot(leader, code));
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        leader,
        libc::PTRACE_SYSCALL_INFO_EXIT,
        libc::SYS_clone as u64,
    );
    phases.push(raw_snapshot(leader, code));
    phases.push(raw_snapshot(worker, code));
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    raw_fault(&mut raw, leader);
    phases.push(raw_snapshot(leader, code));
    raw.resume(worker, libc::PTRACE_SYSCALL, 0);
    raw_fault(&mut raw, worker);
    phases.push(raw_snapshot(worker, code));
    assert!(raw.cleanup(), "native foreground physical cleanup deadline");
    CertifiedRun {
        run: Run {
            leader,
            worker,
            phases,
        },
        certificate,
    }
}
fn observed(path: &Path, code: &[u8]) -> Run {
    let mut s =
        DynamicSession::launch_with_options(&LaunchCommand::new(path), options(false), TIMEOUT)
            .unwrap();
    let leader = s.pid();
    let leaderpin = pin(leader);
    let initial = initialize(&mut s);
    let e = entry(&mut s, &initial, libc::SYS_clone as u64);
    let mut phases = vec![snapshot(&mut s, &e, code)];
    let (created, born, workerpin) = create(&mut s, &e);
    phases.push(snapshot(&mut s, &created, code));
    let parent = returned(&mut s, &created, i64::from(born.tid));
    phases.push(snapshot(&mut s, &parent, code));
    phases.push(snapshot(&mut s, &born, code));
    let parentfault = fault(&mut s, &parent);
    phases.push(snapshot(&mut s, &parentfault, code));
    let childfault = fault(&mut s, &born);
    phases.push(snapshot(&mut s, &childfault, code));
    finish(s, &[(leader, leaderpin), (born.tid, workerpin)]);
    Run {
        leader,
        worker: born.tid,
        phases,
    }
}
fn comparable(run: &Run, certificate: RawCetCertificate) -> Vec<Snapshot> {
    assert_eq!(run.phases.len(), 6);
    for at in 0..4 {
        assert_eq!(run.phases[at].registers.eflags, FLAGS);
        assert_eq!(run.phases[at].mask, MASK);
        assert_eq!(&run.phases[at].data[160..168], &0_u64.to_le_bytes());
        original_cet_output(&run.phases[at].data, certificate);
    }
    assert_eq!(run.phases[0].registers.orig_rax, libc::SYS_clone as u64);
    assert_eq!(run.phases[1].registers.rax as i64, -i64::from(libc::ENOSYS));
    assert_eq!(run.phases[2].registers.rax, run.worker as u64);
    assert_eq!(run.phases[3].registers.rax, 0);
    assert_eq!(run.phases[3].registers.rsp, WORKER_STACK);
    assert_eq!(run.phases[4].registers.rax, run.worker as u64);
    assert_eq!(run.phases[5].registers.rax, 0);
    assert_eq!(run.phases[5].registers.rsp, WORKER_STACK);
    for at in [0, 1, 2, 4] {
        assert_eq!(run.phases[at].registers.rsp, STACK);
    }
    let mut out = run.phases.clone();
    out[2].registers.rax = 1;
    out[4].registers.rax = 1;
    out
}

struct CapturedOutput {
    bytes: Vec<u8>,
    overflow: bool,
}
struct OutputDrain {
    input: std::sync::mpsc::SyncSender<Box<dyn Read + Send>>,
    reader: std::thread::JoinHandle<io::Result<CapturedOutput>>,
}
impl OutputDrain {
    fn reserve() -> Self {
        let (input, receive) = std::sync::mpsc::sync_channel::<Box<dyn Read + Send>>(1);
        let reader = std::thread::Builder::new()
            .name("thread-oracle-output".into())
            .spawn(move || {
                let Ok(mut stream) = receive.recv() else {
                    return Ok(CapturedOutput {
                        bytes: Vec::new(),
                        overflow: false,
                    });
                };
                const LIMIT: usize = 2 * 1024 * 1024;
                let mut captured = CapturedOutput {
                    bytes: Vec::new(),
                    overflow: false,
                };
                let mut buffer = [0; 8192];
                loop {
                    let count = match stream.read(&mut buffer) {
                        Ok(0) => return Ok(captured),
                        Ok(count) => count,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    };
                    let keep = count.min(LIMIT - captured.bytes.len());
                    captured.bytes.extend_from_slice(&buffer[..keep]);
                    captured.overflow |= keep != count;
                    // Continue draining even after overflow so a failing assertion
                    // cannot block the oracle before its ownership Drop executes.
                }
            })
            .unwrap();
        Self { input, reader }
    }
    fn attach(&self, stream: impl Read + Send + 'static) {
        assert!(self.input.send(Box::new(stream)).is_ok());
    }
    fn finish(self) -> CapturedOutput {
        self.reader.join().unwrap().unwrap()
    }
}
fn completion_witness(role: &str) -> &'static str {
    if role == "unwind" {
        "THREAD_NATIVE_OUTPUT_UNWIND_PHYSICAL_CLEANUP_COMPLETE"
    } else {
        "THREAD_NATIVE_PHYSICAL_CLEANUP_COMPLETE"
    }
}
fn isolated(
    path: &Path,
    record: &Path,
    target_code: &Path,
    interpreter_code: Option<&Path>,
    role: &str,
) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", ORACLE_TEST, "--test-threads=1", "--nocapture"])
        .env(ORACLE_ROLE, role)
        .env("RUST_BACKTRACE", "0")
        .env(ORACLE_IMAGE, path)
        .env(ORACLE_RECORD, record)
        .env("LITEINST_THREAD_TARGET_CODE", target_code)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(code) = interpreter_code {
        command.env("LITEINST_THREAD_INTERPRETER_CODE", code);
    } else {
        command.env_remove("LITEINST_THREAD_INTERPRETER_CODE");
    }
    // Reserve both readers before creating a child. On timeout their detached
    // threads retain the streams and drain to EOF while Isolated retains the
    // child wait owner; the natural-parent reaper is never killed here.
    let stdout = OutputDrain::reserve();
    let stderr = OutputDrain::reserve();
    let mut owner = Isolated(Some(command.spawn().unwrap()));
    stdout.attach(owner.0.as_mut().unwrap().stdout.take().unwrap());
    let error_stream = owner.0.as_mut().unwrap().stderr.take().unwrap();
    if role == "unwind" {
        let capacity = unsafe { libc::fcntl(error_stream.as_raw_fd(), libc::F_GETPIPE_SZ) };
        assert!(
            capacity > 0 && capacity < 256 * 1024,
            "unwind payload must exceed the actual stderr pipe capacity"
        );
    }
    stderr.attach(error_stream);
    let until = Instant::now() + Duration::from_secs(12);
    while owner.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(Instant::now() < until, "isolated oracle outer deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
    let output = owner.0.take().unwrap().wait_with_output().unwrap();
    let stdout = stdout.finish();
    let stderr = stderr.finish();
    assert!(
        !stdout.overflow && !stderr.overflow,
        "oracle diagnostic output exceeded its retained bound"
    );
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&stdout.bytes),
        String::from_utf8_lossy(&stderr.bytes)
    );
    let text = String::from_utf8(stdout.bytes).unwrap();
    assert_eq!(
        text.matches("test result: ok. 1 passed; 0 failed; 0 ignored;")
            .count(),
        1
    );
    assert_eq!(
        text.lines()
            .filter(|l| l.starts_with("test result:"))
            .count(),
        1
    );
    assert_eq!(
        text.lines()
            .filter(|l| l.ends_with(completion_witness(role)))
            .count(),
        1
    );
}
fn save(path: &Path, captured: &CertifiedRun, count: usize) {
    let run = &captured.run;
    assert_eq!(run.phases.len(), count);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(b"LITHRD02").unwrap();
    f.write_all(&[match captured.certificate {
        RawCetCertificate::StatusZero => 0,
        RawCetCertificate::AbiAbsent => 1,
    }])
    .unwrap();
    for tid in [run.leader, run.worker] {
        f.write_all(&tid.to_le_bytes()).unwrap();
    }
    for phase in &run.phases {
        for word in words(phase.registers).into_iter().chain([phase.mask]) {
            f.write_all(&word.to_le_bytes()).unwrap();
        }
        for b in [&phase.xstate, &phase.stack, &phase.data] {
            f.write_all(&(b.len() as u32).to_le_bytes()).unwrap();
            f.write_all(b).unwrap();
        }
    }
}
fn load(path: &Path, count: usize) -> CertifiedRun {
    let mut f = fs::File::open(path).unwrap();
    let mut magic = [0; 8];
    f.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"LITHRD02");
    let mut proof = [0xff];
    f.read_exact(&mut proof).unwrap();
    let certificate = match proof[0] {
        0 => RawCetCertificate::StatusZero,
        1 => RawCetCertificate::AbiAbsent,
        _ => panic!("invalid native CET certificate"),
    };
    let mut id = || {
        let mut bytes = [0; 4];
        f.read_exact(&mut bytes).unwrap();
        let id = i32::from_le_bytes(bytes);
        assert!(id > 0);
        id
    };
    let leader = id();
    let worker = id();
    assert_ne!(leader, worker);
    let mut phases = Vec::new();
    for _ in 0..count {
        let mut w = [0; 28];
        for value in &mut w {
            let mut b = [0; 8];
            f.read_exact(&mut b).unwrap();
            *value = u64::from_le_bytes(b);
        }
        let mut blobs = Vec::new();
        for maximum in [65536, 64, RESULT_SIZE] {
            let mut n = [0; 4];
            f.read_exact(&mut n).unwrap();
            let n = u32::from_le_bytes(n) as usize;
            assert!(n <= maximum);
            let mut b = vec![0; n];
            f.read_exact(&mut b).unwrap();
            blobs.push(b);
        }
        assert!(!blobs[0].is_empty());
        assert_eq!(blobs[1].len(), 64);
        assert_eq!(blobs[2].len(), RESULT_SIZE);
        phases.push(Snapshot {
            registers: registers(w[..27].try_into().unwrap()),
            mask: w[27],
            xstate: blobs.remove(0),
            stack: blobs.remove(0),
            data: blobs.remove(0),
        });
    }
    let mut extra = [0];
    assert_eq!(f.read(&mut extra).unwrap(), 0);
    CertifiedRun {
        run: Run {
            leader,
            worker,
            phases,
        },
        certificate,
    }
}
fn native(f: &Fixture, path: &Path, code: &[u8], role: &str, count: usize) -> CertifiedRun {
    let record = f.directory.join(format!("{role}.bin"));
    let source = f.directory.join(format!("{role}-code.bin"));
    fs::write(&source, code).unwrap();
    isolated(path, &record, &source, None, role);
    load(&record, count)
}
fn corruption_controls(expected: &Snapshot) {
    for index in [0, 6, 10, 11, 15, 16, 18, 19, 21, 22] {
        let mut changed = expected.clone();
        let mut w = words(changed.registers);
        w[index] ^= 1;
        changed.registers = registers(w);
        assert_ne!(&changed, expected);
    }
    for field in 0..4 {
        let mut changed = expected.clone();
        match field {
            0 => changed.xstate[0] ^= 1,
            1 => changed.stack[32] ^= 1,
            2 => changed.data[0] ^= 1,
            3 => changed.mask ^= 1,
            _ => unreachable!(),
        };
        assert_ne!(&changed, expected);
    }
}
fn raw_created(raw: &mut Raw, leader: i32) -> (i32, RawCetCertificate) {
    let (mut parent, mut child) = (None, None);
    while parent.is_none() || child.is_none() {
        let (tid, status) = raw.wait();
        assert!(libc::WIFSTOPPED(status));
        if tid == leader {
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
            assert_eq!(status >> 16, libc::PTRACE_EVENT_CLONE);
            let mut id = 0_u64;
            trace(tid, libc::PTRACE_GETEVENTMSG, 0, (&raw mut id) as usize);
            let id = i32::try_from(id).unwrap();
            raw.pins.entry(id).or_insert_with(|| pin_task(id, leader));
            assert!(parent.replace(id).is_none());
        } else {
            assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
            assert!(child.replace(tid).is_none());
        }
    }
    let worker = parent.unwrap();
    assert_eq!(child, Some(worker));
    let certificate = raw_cet_disabled(leader);
    assert_eq!(raw_cet_disabled(worker), certificate);
    (worker, certificate)
}
fn raw_unwind(path: &Path) {
    let mut retained = Vec::new();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut raw = Raw::launch(path);
        let leader = raw.parent.id() as i32;
        raw.resume(leader, libc::PTRACE_SYSCALL, 0);
        raw_entry(&mut raw, leader, libc::SYS_clone as u64);
        raw.resume(leader, libc::PTRACE_SYSCALL, 0);
        let (worker, _) = raw_created(&mut raw, leader);
        retained.push(pin(leader));
        retained.push(pin_task(worker, leader));
        let payload = vec![b'X'; 256 * 1024];
        let mut stderr = io::stderr().lock();
        stderr.write_all(&payload).unwrap();
        stderr.write_all(b"\n").unwrap();
        stderr.flush().unwrap();
        drop(stderr);
        panic!("intentional thread oracle output unwind");
    }));
    assert_eq!(
        failure
            .expect_err("missing expected panic")
            .downcast_ref::<&str>(),
        Some(&"intentional thread oracle output unwind")
    );
    assert_eq!(retained.len(), 2);
    for fd in &retained {
        reaped(fd);
    }
    let mut i: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
                &raw mut i,
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
fn clone_phases_and_first_original_instructions_match_independent_native_state() {
    if let Ok(role) = std::env::var(ORACLE_ROLE) {
        let path = PathBuf::from(std::env::var_os(ORACLE_IMAGE).unwrap());
        let record = PathBuf::from(std::env::var_os(ORACLE_RECORD).unwrap());
        let code = fs::read(std::env::var_os("LITEINST_THREAD_TARGET_CODE").unwrap()).unwrap();
        match role.as_str() {
            "first" => save(&record, &raw_run(&path, &code), 6),
            "shared" => save(&record, &raw_shared(&path, &code), 8),
            "unwind" => raw_unwind(&path),
            "leader_first" => {
                let result = raw_leader_exit(&path);
                let bytes = result
                    .into_iter()
                    .flat_map(i32::to_le_bytes)
                    .collect::<Vec<_>>();
                fs::write(&record, bytes).unwrap();
            }
            _ => panic!("unknown private oracle role"),
        };
        println!("{}", completion_witness(&role));
        return;
    }
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let code = first_user_program();
    let path = f.image("original", &code, &initial_data(), false, None);
    let raw = native(&f, &path, &code, "first", 6);
    let controlled = observed(&path, &code);
    let expected = comparable(&raw.run, raw.certificate);
    let actual = comparable(&controlled, raw.certificate);
    assert_eq!(actual, expected);
    corruption_controls(&actual[5]);
    isolated(
        &path,
        &f.directory.join("unused-unwind.bin"),
        &f.directory.join("first-code.bin"),
        None,
        "unwind",
    );
}
fn thread_terminal(s: &mut DynamicSession, exit: &DynamicEvent, status: u8) -> DynamicEvent {
    release(s, exit);
    let exiting = next(s);
    assert_eq!(exiting.task, exit.task);
    assert_eq!(
        exiting.kind,
        DynamicEventKind::TaskExiting {
            status: ExitStatus::Code(status)
        }
    );
    assert!(exiting.stop_token().is_none());
    let terminal = next(s);
    assert_eq!(terminal.task, exit.task);
    assert_eq!(
        terminal.kind,
        DynamicEventKind::TaskTerminal {
            status: ExitStatus::Code(status)
        }
    );
    assert!(terminal.stop_token().is_none());
    terminal
}
fn shared_observed(path: &Path, code: &[u8], second: bool) -> Run {
    let mut s =
        DynamicSession::launch_with_options(&LaunchCommand::new(path), options(false), TIMEOUT)
            .unwrap();
    let leader = s.pid();
    let leaderpin = pin(leader);
    let initial = initialize(&mut s);
    let entry = entry(&mut s, &initial, libc::SYS_clone as u64);
    let mut phases = vec![snapshot(&mut s, &entry, code)];
    let (created, born, workerpin) = create(&mut s, &entry);
    phases.push(snapshot(&mut s, &created, code));
    let returned = returned(&mut s, &created, i64::from(born.tid));
    phases.push(snapshot(&mut s, &returned, code));
    phases.push(snapshot(&mut s, &born, code));
    let parent = crate::entry(&mut s, &returned, libc::SYS_getpid as u64);
    phases.push(snapshot(&mut s, &parent, code));
    let worker = crate::entry(&mut s, &born, libc::SYS_exit as u64);
    phases.push(snapshot(&mut s, &worker, code));
    let shared = snapshot(&mut s, &parent, code);
    assert_eq!(shared.data, phases[5].data);
    assert_eq!(&shared.data[16..20], &0x11223344_u32.to_le_bytes());
    assert_eq!(&shared.data[24..28], &0x55667788_u32.to_le_bytes());
    thread_terminal(&mut s, &worker, 23);
    reaped(&workerpin);
    assert_eq!(poll_bits(&leaderpin) & (libc::POLLIN | libc::POLLHUP), 0);
    assert_eq!(
        s.read_registers(parent.stop_token().unwrap()).unwrap(),
        phases[4].registers
    );
    let parent = crate::returned(&mut s, &parent, i64::from(leader));
    phases.push(snapshot(&mut s, &parent, code));
    if second {
        let denied = crate::entry(&mut s, &parent, libc::SYS_clone as u64);
        assert_eq!(s.lifecycle_snapshot().unwrap().unwrap().tasks().count(), 2);
        assert_eq!(
            s.read_memory(denied.stop_token().unwrap(), ENTRY, code.len())
                .unwrap(),
            code
        );
        assert!(matches!(
            s.resume(denied.stop_token().unwrap(), DynamicResume::Continue),
            Err(LaunchError::Invalid(
                "dynamic lifetime task bound exhausted"
            ))
        ));
    } else {
        let fault = fault(&mut s, &parent);
        phases.push(snapshot(&mut s, &fault, code));
    }
    finish(s, &[(leader, leaderpin), (born.tid, workerpin)]);
    Run {
        leader,
        worker: born.tid,
        phases,
    }
}
fn raw_shared(path: &Path, code: &[u8]) -> CertifiedRun {
    let mut raw = Raw::launch(path);
    let leader = raw.parent.id() as i32;
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    raw_entry(&mut raw, leader, libc::SYS_clone as u64);
    let mut phases = vec![raw_snapshot(leader, code)];
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    let (worker, certificate) = raw_created(&mut raw, leader);
    phases.push(raw_snapshot(leader, code));
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        leader,
        libc::PTRACE_SYSCALL_INFO_EXIT,
        libc::SYS_clone as u64,
    );
    phases.push(raw_snapshot(leader, code));
    phases.push(raw_snapshot(worker, code));
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    raw_entry(&mut raw, leader, libc::SYS_getpid as u64);
    phases.push(raw_snapshot(leader, code));
    raw.resume(worker, libc::PTRACE_SYSCALL, 0);
    raw_entry(&mut raw, worker, libc::SYS_exit as u64);
    phases.push(raw_snapshot(worker, code));
    raw.resume(worker, libc::PTRACE_SYSCALL, 0);
    assert_eq!(raw_exit_event(&mut raw, worker), 23);
    raw.resume(worker, libc::PTRACE_CONT, 0);
    let (tid, status) = raw.wait();
    assert_eq!(tid, worker);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 23);
    reaped(&raw.pins[&worker]);
    assert_eq!(
        poll_bits(&raw.pins[&leader]) & (libc::POLLIN | libc::POLLHUP),
        0
    );
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        leader,
        libc::PTRACE_SYSCALL_INFO_EXIT,
        libc::SYS_getpid as u64,
    );
    phases.push(raw_snapshot(leader, code));
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    raw_fault(&mut raw, leader);
    phases.push(raw_snapshot(leader, code));
    assert!(
        raw.cleanup(),
        "shared native foreground physical cleanup deadline"
    );
    CertifiedRun {
        run: Run {
            leader,
            worker,
            phases,
        },
        certificate,
    }
}
fn shared_comparable(run: &Run, certificate: RawCetCertificate) -> Vec<Snapshot> {
    assert_eq!(run.phases.len(), 8);
    assert_eq!(run.phases[2].registers.rax, run.worker as u64);
    assert_eq!(run.phases[3].registers.rax, 0);
    assert_eq!(run.phases[6].registers.rax, run.leader as u64);
    assert_eq!(run.phases[7].registers.rax, run.leader as u64);
    let data = &run.phases[5].data;
    let word = |at| u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
    assert_eq!(word(168), 0);
    original_cet_output(data, certificate);
    assert_eq!(word(64), DATA + 3 * PAGE as u64);
    assert_eq!(word(72), 0);
    assert_eq!(word(80), 8192);
    assert_eq!(word(88), 0);
    assert_eq!(word(128), 0);
    assert_eq!(word(136), libc::SS_DISABLE as u64);
    assert_eq!(word(144), 0);
    assert_eq!(word(152), 0);
    let mut out = run.phases.clone();
    out[2].registers.rax = 1;
    out[6].registers.rax = 1;
    out[7].registers.rax = 1;
    out
}
#[test]
fn shared_writes_altstack_reset_and_thread_exit_match_native_with_leader_alive() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let code = shared_program(false);
    let path = f.image("original", &code, &initial_data(), false, None);
    let raw = native(&f, &path, &code, "shared", 8);
    let controlled = shared_observed(&path, &code, false);
    let expected = shared_comparable(&raw.run, raw.certificate);
    let actual = shared_comparable(&controlled, raw.certificate);
    assert_eq!(actual, expected);
    corruption_controls(&actual[5]);
}
#[test]
fn removed_worker_does_not_refund_the_lifetime_clone_budget() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let code = shared_program(true);
    let path = f.image("original", &code, &initial_data(), false, None);
    let _ = shared_observed(&path, &code, true);
}
fn wait_physical(handles: &[OwnedFd]) {
    let until = Instant::now() + TIMEOUT;
    while handles.iter().any(|fd| poll_bits(fd) & libc::POLLHUP == 0) {
        assert!(
            Instant::now() < until,
            "original thread/process cleanup deadline"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    for fd in handles {
        reaped(fd);
    }
}
fn spinning_pair(
    path: &Path,
) -> (
    DynamicSession,
    DynamicEvent,
    DynamicEvent,
    Vec<(i32, OwnedFd)>,
) {
    let mut s =
        DynamicSession::launch_with_options(&LaunchCommand::new(path), options(false), TIMEOUT)
            .unwrap();
    let leader = s.pid();
    let leaderpin = pin(leader);
    let initial = initialize(&mut s);
    let e = entry(&mut s, &initial, libc::SYS_clone as u64);
    let (created, born, workerpin) = create(&mut s, &e);
    let parent = returned(&mut s, &created, i64::from(born.tid));
    let handles = vec![(leader, leaderpin), (born.tid, workerpin)];
    (s, parent, born, handles)
}
#[test]
fn held_and_running_thread_cancellation_and_unwind_retain_physical_ownership() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let code = spin_program(false);
    let path = f.image("original", &code, &initial_data(), false, None);
    for running in [false, true] {
        let (mut s, parent, worker, handles) = spinning_pair(&path);
        if running {
            release(&mut s, &parent);
            release(&mut s, &worker);
        }
        finish(s, &handles);
    }
    let (mut s, parent, worker, handles) = spinning_pair(&path);
    let pins = handles.into_iter().map(|(_, fd)| fd).collect::<Vec<_>>();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        release(&mut s, &parent);
        release(&mut s, &worker);
        let _owner = s;
        panic!("intentional dynamic thread owner unwind");
    }));
    assert_eq!(
        failure
            .expect_err("missing expected panic")
            .downcast_ref::<&str>(),
        Some(&"intentional dynamic thread owner unwind")
    );
    wait_physical(&pins);
}
#[test]
fn syscall_free_thread_pair_deadline_closes_and_physically_reaps_both() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let code = spin_program(false);
    let path = f.image("original", &code, &initial_data(), false, None);
    let (mut s, parent, worker, handles) = spinning_pair(&path);
    release(&mut s, &parent);
    release(&mut s, &worker);
    let start = Instant::now();
    assert!(matches!(
        s.next_event(Duration::from_millis(100)),
        Err(LaunchError::Timeout("native lifecycle event"))
    ));
    assert!(start.elapsed() < TIMEOUT);
    assert!(s.next_event(TIMEOUT).is_err());
    finish(s, &handles);
}
#[test]
fn stale_foreign_and_wrong_task_tokens_do_not_release_held_siblings() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let code = spin_program(false);
    let path = f.image("original", &code, &initial_data(), false, None);
    let (mut first, parent, worker, handles) = spinning_pair(&path);
    let (mut other, other_parent, other_worker, other_handles) = spinning_pair(&path);
    let before = snapshot(&mut first, &parent, &code);
    let worker_before = snapshot(&mut first, &worker, &code);
    let other_before = snapshot(&mut other, &other_parent, &code);
    let other_worker_before = snapshot(&mut other, &other_worker, &code);
    assert!(
        first
            .read_registers(other_parent.stop_token().unwrap())
            .is_err()
    );
    assert!(
        first
            .resume(other_worker.stop_token().unwrap(), DynamicResume::Continue)
            .is_err()
    );
    assert!(
        first
            .interrupt_task(other_worker.task.unwrap().task, TIMEOUT)
            .is_err()
    );
    assert_eq!(snapshot(&mut first, &parent, &code), before);
    assert_eq!(snapshot(&mut first, &worker, &code), worker_before);
    assert_eq!(snapshot(&mut other, &other_parent, &code), other_before);
    assert_eq!(
        snapshot(&mut other, &other_worker, &code),
        other_worker_before
    );
    let stale = worker.stop_token().unwrap().clone();
    release(&mut first, &worker);
    let stopped = first
        .interrupt_task(worker.task.unwrap().task, TIMEOUT)
        .unwrap();
    assert_eq!(stopped.task, worker.task);
    assert_eq!(stopped.kind, DynamicEventKind::Interrupted);
    let stopped_before = snapshot(&mut first, &stopped, &code);
    assert!(first.read_registers(&stale).is_err());
    assert!(first.resume(&stale, DynamicResume::Continue).is_err());
    assert_eq!(snapshot(&mut first, &stopped, &code), stopped_before);
    assert_eq!(snapshot(&mut first, &parent, &code), before);
    finish(first, &handles);
    finish(other, &other_handles);
}
fn leader_exit_program() -> Vec<u8> {
    let mut code = prefix(false);
    clone_instruction(&mut code, THREAD_FLAGS, WORKER_STACK, [0; 3]);
    let branch = branch_worker(&mut code);
    call(&mut code, libc::SYS_exit, &[(7, 17)]);
    code.extend_from_slice(&[0x0f, 0x0b]);
    let worker = code.len();
    bind_worker(&mut code, branch, worker);
    call(&mut code, libc::SYS_exit, &[(7, 7)]);
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
fn raw_exit_event(raw: &mut Raw, tid: i32) -> i32 {
    let (actual, status) = raw.wait();
    assert_eq!(actual, tid);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(status >> 16, libc::PTRACE_EVENT_EXIT);
    assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
    let mut value = 0_u64;
    trace(tid, libc::PTRACE_GETEVENTMSG, 0, (&raw mut value) as usize);
    assert!(libc::WIFEXITED(value as i32));
    libc::WEXITSTATUS(value as i32)
}
fn raw_leader_exit(path: &Path) -> [i32; 4] {
    let mut raw = Raw::launch(path);
    let leader = raw.parent.id() as i32;
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    raw_entry(&mut raw, leader, libc::SYS_clone as u64);
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    let (worker, _) = raw_created(&mut raw, leader);
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(
        leader,
        libc::PTRACE_SYSCALL_INFO_EXIT,
        libc::SYS_clone as u64,
    );
    let child_before = raw_registers(worker);
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    raw_entry(&mut raw, leader, libc::SYS_exit as u64);
    raw.resume(leader, libc::PTRACE_SYSCALL, 0);
    let leader_event = raw_exit_event(&mut raw, leader);
    assert_eq!(leader_event, 17);
    raw.resume(leader, libc::PTRACE_CONT, 0);
    assert_eq!(raw_registers(worker), child_before);
    assert_eq!(
        poll_bits(&raw.pins[&leader]) & (libc::POLLIN | libc::POLLHUP),
        0
    );
    let mut pending: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                raw.pins[&leader].as_raw_fd() as u32,
                &raw mut pending,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        },
        0
    );
    assert_eq!(unsafe { pending.si_pid() }, 0);
    raw.resume(worker, libc::PTRACE_SYSCALL, 0);
    raw_entry(&mut raw, worker, libc::SYS_exit as u64);
    raw.resume(worker, libc::PTRACE_SYSCALL, 0);
    let worker_event = raw_exit_event(&mut raw, worker);
    assert_eq!(worker_event, 7);
    raw.resume(worker, libc::PTRACE_CONT, 0);
    let mut terminals = BTreeMap::new();
    while terminals.len() < 2 {
        let (tid, status) = raw.wait();
        assert!(tid == leader || tid == worker);
        assert!(libc::WIFEXITED(status));
        assert!(terminals.insert(tid, libc::WEXITSTATUS(status)).is_none());
    }
    let result = [
        leader_event,
        worker_event,
        terminals[&leader],
        terminals[&worker],
    ];
    assert_eq!(result, [17, 7, 7, 7]);
    assert!(raw.cleanup(), "leader-first raw physical cleanup deadline");
    result
}
#[test]
fn leader_exit_event_retains_worker_control_and_separate_actual_group_terminal() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let code = leader_exit_program();
    let path = f.image("original", &code, &initial_data(), false, None);
    let codefile = f.directory.join("leader-code.bin");
    fs::write(&codefile, &code).unwrap();
    let record = f.directory.join("leader.bin");
    isolated(&path, &record, &codefile, None, "leader_first");
    let record = fs::read(record).unwrap();
    assert_eq!(record.len(), 16);
    let native = record
        .chunks_exact(4)
        .map(|b| u8::try_from(i32::from_le_bytes(b.try_into().unwrap())).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(native, [17, 7, 7, 7]);
    let (mut s, parent, worker, handles) = spinning_pair(&path);
    let before = snapshot(&mut s, &worker, &code);
    let leader_exit = entry(&mut s, &parent, libc::SYS_exit as u64);
    release(&mut s, &leader_exit);
    let exiting = next(&mut s);
    assert_eq!(exiting.task, parent.task);
    assert_eq!(
        exiting.kind,
        DynamicEventKind::TaskExiting {
            status: ExitStatus::Code(native[0])
        }
    );
    assert!(exiting.stop_token().is_none());
    assert!(s.read_registers(leader_exit.stop_token().unwrap()).is_err());
    assert!(
        s.interrupt_task(parent.task.unwrap().task, TIMEOUT)
            .is_err()
    );
    assert_eq!(snapshot(&mut s, &worker, &code), before);
    assert_eq!(poll_bits(&handles[0].1) & (libc::POLLIN | libc::POLLHUP), 0);
    let worker_exit = entry(&mut s, &worker, libc::SYS_exit as u64);
    release(&mut s, &worker_exit);
    let event = next(&mut s);
    assert_eq!(event.task, worker.task);
    assert_eq!(
        event.kind,
        DynamicEventKind::TaskExiting {
            status: ExitStatus::Code(native[1])
        }
    );
    assert!(event.stop_token().is_none());
    let mut terminal = BTreeMap::new();
    for _ in 0..2 {
        let event = next(&mut s);
        let DynamicEventKind::TaskTerminal {
            status: ExitStatus::Code(code),
        } = event.kind
        else {
            panic!("{event:?}")
        };
        assert!(event.stop_token().is_none());
        assert!(terminal.insert(event.tid, code).is_none());
    }
    assert_eq!(terminal.get(&parent.tid), Some(&native[2]));
    assert_eq!(terminal.get(&worker.tid), Some(&native[3]));
    finish(s, &handles);
}
#[test]
fn exact_thread_flags_stack_arguments_and_default_policy_refuse_before_execution() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    for max_tasks in [0, 3, usize::MAX] {
        assert!(matches!(
            DynamicSession::launch_with_options(
                &LaunchCommand::new("unopened-invalid-thread-options"),
                DynamicSessionOptions {
                    lifecycle: DynamicLifecycleOptions {
                        creation: DynamicCreationPolicy::ThreadClone,
                        max_tasks
                    },
                    exec: DynamicExecPolicy::Refuse
                },
                TIMEOUT
            ),
            Err(LaunchError::Invalid(
                "dynamic lifecycle task bound must be one or two"
            ))
        ));
    }
    let invalid = "native thread clone profile refuses arguments";
    let stack_error = "native thread stack lacks writable storage";
    let unsupported = "dynamic creation and later exec are not yet qualified";
    for (index, (nr, flags, stack, args, mode, error)) in [
        (
            libc::SYS_clone,
            THREAD_FLAGS,
            WORKER_STACK,
            [0; 3],
            0,
            unsupported,
        ),
        (
            libc::SYS_clone,
            THREAD_FLAGS,
            WORKER_STACK,
            [0; 3],
            1,
            "dynamic lifetime task bound exhausted",
        ),
        (
            libc::SYS_clone,
            THREAD_FLAGS | (1_u64 << 32),
            WORKER_STACK,
            [0; 3],
            2,
            invalid,
        ),
        (
            libc::SYS_clone,
            THREAD_FLAGS | libc::CLONE_SETTLS as u64,
            WORKER_STACK,
            [0, 0, DATA],
            2,
            invalid,
        ),
        (
            libc::SYS_clone,
            THREAD_FLAGS | libc::CLONE_PARENT_SETTID as u64,
            WORKER_STACK,
            [DATA + 32, 0, 0],
            2,
            invalid,
        ),
        (
            libc::SYS_clone,
            THREAD_FLAGS | libc::CLONE_CHILD_SETTID as u64,
            WORKER_STACK,
            [0, DATA + 40, 0],
            2,
            invalid,
        ),
        (
            libc::SYS_clone,
            THREAD_FLAGS | libc::CLONE_CHILD_CLEARTID as u64,
            WORKER_STACK,
            [0, DATA + 40, 0],
            2,
            invalid,
        ),
        (
            libc::SYS_clone,
            THREAD_FLAGS & !(libc::CLONE_THREAD as u64),
            WORKER_STACK,
            [0; 3],
            2,
            invalid,
        ),
        (
            libc::SYS_clone,
            THREAD_FLAGS,
            WORKER_STACK,
            [DATA + 32, 0, 0],
            2,
            invalid,
        ),
        (
            libc::SYS_clone,
            THREAD_FLAGS,
            WORKER_STACK,
            [0, DATA + 40, 0],
            2,
            invalid,
        ),
        (
            libc::SYS_clone,
            THREAD_FLAGS,
            WORKER_STACK,
            [0, 0, DATA + 48],
            2,
            invalid,
        ),
        (libc::SYS_clone, THREAD_FLAGS, 0, [0; 3], 2, stack_error),
        (
            libc::SYS_clone,
            THREAD_FLAGS,
            ENTRY + 128,
            [0; 3],
            2,
            stack_error,
        ),
        (
            libc::SYS_clone3,
            THREAD_FLAGS,
            WORKER_STACK,
            [0; 3],
            2,
            unsupported,
        ),
        (
            libc::SYS_fork,
            THREAD_FLAGS,
            WORKER_STACK,
            [0; 3],
            2,
            "dynamic fork policy refuses creation",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut code = prefix(false);
        if nr == libc::SYS_clone {
            clone_instruction(&mut code, flags, stack, args);
        } else {
            syscall(&mut code, nr as u64);
        }
        store_imm(&mut code, DATA, 0x12345678);
        code.extend_from_slice(&[0x0f, 0x0b]);
        let path = f.image(
            &format!("refusal{index}"),
            &code,
            &initial_data(),
            false,
            None,
        );
        let command = LaunchCommand::new(path);
        let mut s = if mode == 0 {
            DynamicSession::launch(&command, TIMEOUT)
        } else {
            let mut options = options(false);
            if mode == 1 {
                options.lifecycle.max_tasks = 1;
            }
            DynamicSession::launch_with_options(&command, options, TIMEOUT)
        }
        .unwrap();
        let leader = s.pid();
        let leaderpin = pin(leader);
        let initial = initialize(&mut s);
        let e = entry(&mut s, &initial, nr as u64);
        let before = snapshot(&mut s, &e, &code);
        assert_eq!(before.registers.orig_rax, nr as u64);
        assert_eq!(before.registers.rax as i64, -i64::from(libc::ENOSYS));
        assert_eq!(&before.data[..8], &MARKER.to_le_bytes());
        if mode != 0 {
            assert_eq!(s.lifecycle_snapshot().unwrap().unwrap().tasks().count(), 1);
        }
        assert!(
            matches!(s.resume(e.stop_token().unwrap(),DynamicResume::Continue),Err(LaunchError::Invalid(actual))if actual==error)
        );
        finish(s, &[(leader, leaderpin)]);
    }
}
fn path_data(path: &Path) -> Vec<u8> {
    let mut data = initial_data();
    let name = path.as_os_str().as_encoded_bytes();
    assert!(name.len() < 512);
    data[1024..1024 + name.len()].copy_from_slice(name);
    data
}
fn exec_args(code: &mut Vec<u8>) {
    call(code, libc::SYS_execve, &[(7, DATA + 1024), (6, 0), (2, 0)]);
}
fn exec_caller() -> Vec<u8> {
    let mut code = prefix(false);
    exec_args(&mut code);
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
fn replaced_exit(s: &mut DynamicSession, entry: &DynamicEvent) -> DynamicEvent {
    let old = entry.task.unwrap();
    release(s, entry);
    let replaced = next(s);
    let DynamicEventKind::ExecReplaced {
        previous,
        ref evidence,
    } = replaced.kind
    else {
        panic!("{replaced:?}")
    };
    assert_eq!(previous, old);
    assert_eq!(evidence.first_image, FirstImage::Executable);
    assert_eq!(evidence.initial_instruction, ENTRY);
    let fresh = replaced.task.unwrap();
    assert_ne!(fresh.task, old.task);
    assert_eq!(fresh.process, old.process);
    assert_ne!(fresh.address_space, old.address_space);
    let mut expected = s.read_registers(replaced.stop_token().unwrap()).unwrap();
    assert_eq!(expected.rax as i64, -i64::from(libc::ENOSYS));
    assert!(s.read_registers(entry.stop_token().unwrap()).is_err());
    release(s, &replaced);
    let exit = next(s);
    assert_eq!(exit.task, Some(fresh));
    assert_eq!(
        exit.kind,
        DynamicEventKind::SyscallExit {
            result: 0,
            is_error: false
        }
    );
    expected.rax = 0;
    assert_eq!(
        s.read_registers(exit.stop_token().unwrap()).unwrap(),
        expected
    );
    exit
}
fn assert_three_records(s: &mut DynamicSession) {
    let state = s.lifecycle_snapshot().unwrap().unwrap();
    assert_eq!(state.tasks().count(), 3);
    assert_eq!(state.address_spaces().count(), 2);
    let process = state.tasks().next().unwrap().process;
    assert!(state.tasks().all(|t| t.process == process));
    assert_eq!(
        state
            .tasks()
            .filter(|t| t.state == TaskState::Terminal(TerminalReason::ExecReplaced))
            .count(),
        1
    );
}
#[test]
fn exec_before_thread_creation_reserves_three_tasks_and_two_mms_in_one_process() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let targetcode = shared_program(false);
    let target = f.image("replacement", &targetcode, &initial_data(), false, None);
    let code = exec_caller();
    let path = f.image("original", &code, &path_data(&target), false, None);
    let mut s =
        DynamicSession::launch_with_options(&LaunchCommand::new(path), options(true), TIMEOUT)
            .unwrap();
    let leader = s.pid();
    let leaderpin = pin(leader);
    let initial = initialize(&mut s);
    let exec = entry(&mut s, &initial, libc::SYS_execve as u64);
    let exit = replaced_exit(&mut s, &exec);
    let clone = entry(&mut s, &exit, libc::SYS_clone as u64);
    let (created, born, workerpin) = create(&mut s, &clone);
    assert_three_records(&mut s);
    let parent = returned(&mut s, &created, i64::from(born.tid));
    let parent = entry(&mut s, &parent, libc::SYS_getpid as u64);
    let worker = entry(&mut s, &born, libc::SYS_exit as u64);
    thread_terminal(&mut s, &worker, 23);
    reaped(&workerpin);
    assert_three_records(&mut s);
    let parent = returned(&mut s, &parent, i64::from(leader));
    let stopped = fault(&mut s, &parent);
    assert_eq!(
        s.read_memory(stopped.stop_token().unwrap(), ENTRY, targetcode.len())
            .unwrap(),
        targetcode
    );
    finish(s, &[(leader, leaderpin), (born.tid, workerpin)]);
}
fn worker_then_exec_program() -> Vec<u8> {
    let mut code = prefix(false);
    clone_instruction(&mut code, THREAD_FLAGS, WORKER_STACK, [0; 3]);
    let branch = branch_worker(&mut code);
    syscall(&mut code, libc::SYS_getpid as u64);
    exec_args(&mut code);
    code.extend_from_slice(&[0x0f, 0x0b]);
    let worker = code.len();
    bind_worker(&mut code, branch, worker);
    call(&mut code, libc::SYS_exit, &[(7, 23)]);
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
#[test]
fn leader_exec_after_physical_worker_removal_keeps_clone_budget_spent() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let mut targetcode = Vec::new();
    store_rax(&mut targetcode, DATA);
    targetcode.extend_from_slice(&first_user_program());
    let target = f.image("replacement", &targetcode, &initial_data(), false, None);
    let code = worker_then_exec_program();
    let path = f.image("original", &code, &path_data(&target), false, None);
    let mut s =
        DynamicSession::launch_with_options(&LaunchCommand::new(path), options(true), TIMEOUT)
            .unwrap();
    let leader = s.pid();
    let leaderpin = pin(leader);
    let initial = initialize(&mut s);
    let clone = entry(&mut s, &initial, libc::SYS_clone as u64);
    let (created, born, workerpin) = create(&mut s, &clone);
    let parent = returned(&mut s, &created, i64::from(born.tid));
    let parent = entry(&mut s, &parent, libc::SYS_getpid as u64);
    let worker = entry(&mut s, &born, libc::SYS_exit as u64);
    thread_terminal(&mut s, &worker, 23);
    reaped(&workerpin);
    assert_eq!(poll_bits(&leaderpin) & (libc::POLLIN | libc::POLLHUP), 0);
    let parent = returned(&mut s, &parent, i64::from(leader));
    let exec = entry(&mut s, &parent, libc::SYS_execve as u64);
    let exit = replaced_exit(&mut s, &exec);
    assert_three_records(&mut s);
    let denied = entry(&mut s, &exit, libc::SYS_clone as u64);
    assert_eq!(
        s.read_memory(denied.stop_token().unwrap(), DATA, 8)
            .unwrap(),
        0_u64.to_le_bytes()
    );
    assert_eq!(
        s.read_memory(denied.stop_token().unwrap(), ENTRY, targetcode.len())
            .unwrap(),
        targetcode
    );
    assert!(matches!(
        s.resume(denied.stop_token().unwrap(), DynamicResume::Continue),
        Err(LaunchError::Invalid(
            "dynamic lifetime task bound exhausted"
        ))
    ));
    finish(s, &[(leader, leaderpin), (born.tid, workerpin)]);
}
fn live_exec_program() -> Vec<u8> {
    let mut code = prefix(false);
    clone_instruction(&mut code, THREAD_FLAGS, WORKER_STACK, [0; 3]);
    exec_args(&mut code);
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
#[test]
fn live_sibling_and_nonleader_exec_refuse_without_replacing_either_task() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let target = f.image("replacement", &[0x0f, 0x0b], &initial_data(), false, None);
    let code = live_exec_program();
    let path = f.image("original", &code, &path_data(&target), false, None);
    for worker_exec in [false, true] {
        let mut s =
            DynamicSession::launch_with_options(&LaunchCommand::new(&path), options(true), TIMEOUT)
                .unwrap();
        let leader = s.pid();
        let leaderpin = pin(leader);
        let initial = initialize(&mut s);
        let clone = entry(&mut s, &initial, libc::SYS_clone as u64);
        let (created, born, workerpin) = create(&mut s, &clone);
        let parent = returned(&mut s, &created, i64::from(born.tid));
        let exec = entry(
            &mut s,
            if worker_exec { &born } else { &parent },
            libc::SYS_execve as u64,
        );
        let held = if worker_exec { &parent } else { &born };
        let before = snapshot(&mut s, &exec, &code);
        let sibling = snapshot(&mut s, held, &code);
        assert_eq!(before.data, sibling.data);
        assert_eq!(s.lifecycle_snapshot().unwrap().unwrap().tasks().count(), 2);
        assert_eq!(
            s.lifecycle_snapshot()
                .unwrap()
                .unwrap()
                .address_spaces()
                .count(),
            1
        );
        let message = if worker_exec {
            "native nonleader exec is not qualified"
        } else {
            "native exec requires physically removed workers"
        };
        assert!(
            matches!(s.resume(exec.stop_token().unwrap(),DynamicResume::Continue),Err(LaunchError::Invalid(actual))if actual==message)
        );
        finish(s, &[(leader, leaderpin), (born.tid, workerpin)]);
    }
}

#[test]
fn failed_native_thread_clone_retries_preserve_state_without_inventing_tasks() {
    let _serial = FILE_FORK.lock().unwrap();
    // Only the original tracee lowers its own limit. Root and the two Linux
    // RLIMIT_NPROC override capabilities cannot qualify this failure fixture.
    // They fail explicitly rather than skipping a required native assertion.
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .unwrap();
    let effective = u64::from_str_radix(effective, 16).unwrap();
    assert_eq!(effective & ((1 << 21) | (1 << 24)), 0);
    let f = Fixture::new();
    let mut code = prefix(false);
    call(
        &mut code,
        libc::SYS_setrlimit,
        &[(7, libc::RLIMIT_NPROC as u64), (6, DATA + 800)],
    );
    for _ in 0..2 {
        clone_instruction(&mut code, THREAD_FLAGS, WORKER_STACK, [0; 3]);
    }
    code.extend_from_slice(&[0x0f, 0x0b]);
    let data = initial_data();
    assert_eq!(&data[800..816], &[0; 16]);
    let path = f.image("failed-thread", &code, &data, false, None);
    let mut s =
        DynamicSession::launch_with_options(&LaunchCommand::new(path), options(false), TIMEOUT)
            .unwrap();
    let leader = s.pid();
    let handle = pin(leader);
    let initial = initialize(&mut s);
    let limits = entry(&mut s, &initial, libc::SYS_setrlimit as u64);
    let mut held = returned(&mut s, &limits, 0);
    let original = held.task.unwrap();
    for _ in 0..2 {
        let clone = entry(&mut s, &held, libc::SYS_clone as u64);
        let before = snapshot(&mut s, &clone, &code);
        assert_eq!(before.registers.rdi, THREAD_FLAGS);
        assert_eq!(before.registers.rsi, WORKER_STACK);
        assert_eq!(before.registers.rdx, 0);
        assert_eq!(before.registers.r10, 0);
        assert_eq!(before.registers.r8, 0);
        release(&mut s, &clone);
        let failed = next(&mut s);
        assert_eq!(
            failed.kind,
            DynamicEventKind::SyscallExit {
                result: -i64::from(libc::EAGAIN),
                is_error: true
            }
        );
        assert_eq!(failed.task, Some(original));
        let mut expected = before;
        expected.registers.rax = (-i64::from(libc::EAGAIN)) as u64;
        assert_eq!(snapshot(&mut s, &failed, &code), expected);
        let records = s.lifecycle_snapshot().unwrap().unwrap();
        assert_eq!(records.tasks().count(), 1);
        assert_eq!(records.address_spaces().count(), 1);
        let task = records.tasks().next().unwrap();
        assert_eq!(task.id, original.task);
        assert_eq!(task.process, original.process);
        assert_eq!(task.address_space, original.address_space);
        held = failed;
    }
    let stopped = fault(&mut s, &held);
    assert_eq!(stopped.task, Some(original));
    assert_eq!(
        s.read_registers(stopped.stop_token().unwrap()).unwrap().rip,
        ENTRY + code.len() as u64 - 2
    );
    finish(s, &[(leader, handle)]);
}
