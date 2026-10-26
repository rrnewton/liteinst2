#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Native later-exec evidence. Raw oracles use an exec-isolated real-parent
//! subreaper; kernel EXEC, syscall EXIT and original first-user effects are
//! separate observations. No register, flags or XSTATE output is masked.
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
const FLAGS: u64 = 0xed7;
const RESULT_SIZE: usize = 512;
const MASK: u64 = 1 << (libc::SIGUSR2 - 1);
const MARKER: u64 = 0x123456789abcdef0;
const TIMEOUT: Duration = Duration::from_secs(3);
const ORACLE_ROLE: &str = "LITEINST_EXEC_NATIVE_ORACLE";
const ORACLE_IMAGE: &str = "LITEINST_EXEC_NATIVE_IMAGE";
const ORACLE_RECORD: &str = "LITEINST_EXEC_NATIVE_RECORD";
const ORACLE_TEST: &str = "later_static_exec_matches_native_event_exit_and_first_user_state";
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
                "dynamic-exec-{}-{}",
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
fn caller_data(target: &Path) -> Vec<u8> {
    let mut data = vec![0; 2048];
    data[512..520].copy_from_slice(&MASK.to_le_bytes());
    let path = target.as_os_str().as_encoded_bytes();
    assert!(path.len() < 350);
    data[1024..1024 + path.len()].copy_from_slice(path);
    data[1408..1418].copy_from_slice(b"/dev/null\0");
    data
}
fn exec_args(code: &mut Vec<u8>) {
    mov(code, 7, DATA + 1024);
    mov(code, 6, 0);
    mov(code, 2, 0);
    syscall(code, libc::SYS_execve as u64);
}
fn caller(target: &Path, effects: bool) -> (Vec<u8>, Vec<u8>) {
    let mut data = caller_data(target);
    for offset in [184, 192, 200, 208, 216, 224, 232, 240] {
        data[offset..offset + 8].copy_from_slice(&MARKER.to_le_bytes());
    }
    data[248..256].copy_from_slice(&u64::from(effects).to_le_bytes());
    let mut code = Vec::new();
    if effects {
        call(
            &mut code,
            libc::SYS_close_range,
            &[(7, 3), (6, u32::MAX as u64), (2, 0)],
        );
        store_rax(&mut code, DATA + 184);
    }
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
    store_rax(&mut code, DATA + 192);
    if effects {
        // Original program installs a caught handler, an ignored disposition,
        // an altstack, and a private fixed CLOEXEC descriptor before exec.
        for (offset, handler) in [(544, ENTRY), (576, libc::SIG_IGN as u64)] {
            data[offset..offset + 8].copy_from_slice(&handler.to_le_bytes());
        }
        for (sig, offset, result) in [(libc::SIGUSR1, 544, 200), (libc::SIGPIPE, 576, 208)] {
            call(
                &mut code,
                libc::SYS_rt_sigaction,
                &[(7, sig as u64), (6, DATA + offset), (2, 0), (10, 8)],
            );
            store_rax(&mut code, DATA + result);
        }
        data[608..616].copy_from_slice(&(DATA + 8192).to_le_bytes());
        data[624..632].copy_from_slice(&8192_u64.to_le_bytes());
        call(&mut code, libc::SYS_sigaltstack, &[(7, DATA + 608), (6, 0)]);
        store_rax(&mut code, DATA + 216);
        call(
            &mut code,
            libc::SYS_openat,
            &[
                (7, libc::AT_FDCWD as u64),
                (6, DATA + 1408),
                (2, (libc::O_RDONLY | libc::O_CLOEXEC) as u64),
                (10, 0),
            ],
        );
        store_rax(&mut code, DATA + 224);
        code.extend_from_slice(&[0x48, 0x89, 0xc7]); // RDI actual returned descriptor.
        mov(&mut code, 6, 63);
        mov(&mut code, 2, libc::O_CLOEXEC as u64);
        syscall(&mut code, libc::SYS_dup3 as u64);
        store_rax(&mut code, DATA + 232);
        // RDI still names the actual open result; close it before deterministic seeding.
        syscall(&mut code, libc::SYS_close as u64);
        store_rax(&mut code, DATA + 240);
    }
    code.extend_from_slice(&seed());
    exec_args(&mut code);
    code.extend_from_slice(&[0x0f, 0x0b]);
    (code, data)
}
fn target_data() -> Vec<u8> {
    let mut data = vec![0; RESULT_SIZE];
    data[..8].copy_from_slice(&MARKER.to_le_bytes());
    // Query outputs must be visibly written by the original replacement image.
    // Leave ABI padding zero rather than treating it as an output field.
    for offset in [32, 40, 48, 64, 80, 88, 96, 128, 168, 176] {
        data[offset..offset + 8].copy_from_slice(&MARKER.to_le_bytes());
    }
    data[8..16].copy_from_slice(&ENTRY.to_le_bytes());
    data
}
fn first_user_code() -> Vec<u8> {
    let mut code = Vec::new();
    store_rax(&mut code, DATA);
    mov(&mut code, 4, STACK);
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
fn query_code() -> Vec<u8> {
    let mut code = Vec::new();
    store_rax(&mut code, DATA);
    mov(&mut code, 4, STACK);
    call(
        &mut code,
        libc::SYS_rt_sigprocmask,
        &[
            (7, libc::SIG_SETMASK as u64),
            (6, 0),
            (2, DATA + 32),
            (10, 8),
        ],
    );
    store_rax(&mut code, DATA + 40);
    call(
        &mut code,
        libc::SYS_fcntl,
        &[(7, 63), (6, libc::F_GETFD as u64), (2, 0)],
    );
    store_rax(&mut code, DATA + 48);
    call(&mut code, libc::SYS_sigaltstack, &[(7, 0), (6, DATA + 64)]);
    store_rax(&mut code, DATA + 88);
    for (sig, offset, result) in [(libc::SIGUSR1, 96, 168), (libc::SIGPIPE, 128, 176)] {
        call(
            &mut code,
            libc::SYS_rt_sigaction,
            &[(7, sig as u64), (6, 0), (2, DATA + offset), (10, 8)],
        );
        store_rax(&mut code, DATA + result);
    }
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
fn options(fork: bool) -> DynamicSessionOptions {
    DynamicSessionOptions {
        lifecycle: DynamicLifecycleOptions {
            creation: if fork {
                DynamicCreationPolicy::Fork
            } else {
                DynamicCreationPolicy::Refuse
            },
            max_tasks: if fork { 2 } else { 1 },
        },
        exec: DynamicExecPolicy::ExecveOnce,
    }
}
fn pin(pid: i32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0, "pidfd_open: {}", io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
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
    let mut i: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                fd.as_raw_fd() as u32,
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
fn finish(session: DynamicSession, handles: &[(i32, OwnedFd)]) {
    let mut actual = session.terminate(TIMEOUT).unwrap().reaped;
    let mut expected = handles.iter().map(|(pid, _)| *pid).collect::<Vec<_>>();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
    for (_, fd) in handles {
        reaped(fd);
    }
}
fn release(s: &mut DynamicSession, e: &DynamicEvent) {
    s.resume(e.stop_token().unwrap(), DynamicResume::Continue)
        .unwrap();
}
fn next(s: &mut DynamicSession) -> DynamicEvent {
    for _ in 0..16 {
        let e = s.next_event(TIMEOUT).unwrap();
        if let DynamicEventKind::SignalDelivery(ref i) = e.kind {
            if i.signal() == libc::SIGCHLD {
                assert_eq!(i.code(), libc::CLD_EXITED);
                s.resume(e.stop_token().unwrap(), DynamicResume::DeliverOriginal)
                    .unwrap();
                continue;
            }
        }
        return e;
    }
    panic!("signal forwarding bound")
}
fn initialize(s: &mut DynamicSession) -> DynamicEvent {
    let e = s.initial_event().clone();
    assert!(e.task.is_none());
    let mut regs = s.read_registers(e.stop_token().unwrap()).unwrap();
    assert_eq!(regs.rax as i64, -i64::from(libc::ENOSYS));
    release(s, &e);
    let exit = next(s);
    assert_eq!(
        exit.kind,
        DynamicEventKind::SyscallExit {
            result: 0,
            is_error: false
        }
    );
    regs.rax = 0;
    assert_eq!(s.read_registers(exit.stop_token().unwrap()).unwrap(), regs);
    assert_eq!(s.lifecycle_snapshot().unwrap().unwrap().tasks().count(), 1);
    exit
}
fn entry(s: &mut DynamicSession, held: &DynamicEvent, nr: u64) -> DynamicEvent {
    release(s, held);
    for _ in 0..64 {
        let e = next(s);
        match e.kind {
            DynamicEventKind::SyscallEntry { number, .. } if number == nr => return e,
            DynamicEventKind::SyscallEntry { .. } | DynamicEventKind::SyscallExit { .. } => {
                release(s, &e)
            }
            _ => panic!("unexpected while seeking entry {nr}: {e:?}"),
        }
    }
    panic!("entry bound")
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    stack: Vec<u8>,
    data: Vec<u8>,
    mask: u64,
}
fn snapshot(s: &mut DynamicSession, e: &DynamicEvent) -> Snapshot {
    let t = e.stop_token().unwrap();
    Snapshot {
        registers: s.read_registers(t).unwrap(),
        xstate: s.read_xstate(t).unwrap(),
        stack: s.read_memory(t, STACK, 32).unwrap(),
        data: s.read_memory(t, DATA, RESULT_SIZE).unwrap(),
        mask: s.signal_mask(t).unwrap(),
    }
}
include!("support/dynamic_exec_raw.rs");

fn raw_state(pid: i32) -> Snapshot {
    raw_snapshot(pid, &[])
}
fn raw_entry(raw: &mut Raw, pid: i32, nr: u64) {
    for _ in 0..64 {
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
    for _ in 0..64 {
        let (tid, status) = raw.wait();
        assert_eq!(tid, pid);
        assert!(libc::WIFSTOPPED(status));
        if libc::WSTOPSIG(status) == libc::SIGTRAP | 0x80 {
            raw.resume(pid, libc::PTRACE_SYSCALL, 0);
            continue;
        }
        assert_eq!(libc::WSTOPSIG(status), libc::SIGILL);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        trace(pid, libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
        assert_eq!(info.si_code, 2);
        assert_eq!(unsafe { info.si_addr() } as u64, raw_registers(pid).rip);
        return;
    }
    panic!("raw terminal bound")
}
fn fault(s: &mut DynamicSession, held: &DynamicEvent) -> DynamicEvent {
    release(s, held);
    for _ in 0..64 {
        let e = next(s);
        if let DynamicEventKind::SignalDelivery(ref info) = e.kind {
            assert_eq!(info.signal(), libc::SIGILL);
            assert_eq!(info.code(), 2);
            assert_eq!(
                info.fault_address(),
                Some(s.read_registers(e.stop_token().unwrap()).unwrap().rip)
            );
            return e;
        }
        assert!(matches!(
            e.kind,
            DynamicEventKind::SyscallEntry { .. } | DynamicEventKind::SyscallExit { .. }
        ));
        release(s, &e);
    }
    panic!("terminal bound")
}

struct Run {
    phases: Vec<Snapshot>,
    entry_pc: u64,
    initial_sp: u64,
}
fn auxv(pid: i32) -> BTreeMap<u64, u64> {
    let bytes = fs::read(format!("/proc/{pid}/auxv")).unwrap();
    assert_eq!(bytes.len() % 16, 0);
    bytes
        .chunks_exact(16)
        .map(|b| {
            (
                u64::from_ne_bytes(b[..8].try_into().unwrap()),
                u64::from_ne_bytes(b[8..].try_into().unwrap()),
            )
        })
        .collect()
}
fn authenticate_exec_frame(frame: &Snapshot, entry_pc: u64, sp: u64) {
    let mut expected = registers([0; 27]);
    expected.rax = (-i64::from(libc::ENOSYS)) as u64;
    expected.orig_rax = libc::SYS_execve as u64;
    expected.rip = entry_pc;
    expected.rsp = sp;
    expected.cs = 0x33;
    expected.ss = 0x2b;
    expected.eflags = 0x202;
    assert_eq!(frame.registers, expected);
    assert_eq!(sp & 15, 0);
    assert_ne!(sp, STACK);
    assert_eq!(frame.mask, MASK);
    assert_eq!(&frame.data[..8], &MARKER.to_le_bytes());
}
fn verify_setup(entry: &Snapshot) {
    let word = |at| u64::from_le_bytes(entry.data[at..at + 8].try_into().unwrap());
    assert_eq!(word(192), 0, "original mask setup failed");
    if word(248) == 1 {
        for at in [184, 200, 208, 216, 240] {
            assert_eq!(word(at), 0, "original setup failed at {at}");
        }
        assert_eq!(
            word(224),
            3,
            "original close_range must establish descriptor inputs"
        );
        assert_ne!(
            word(224),
            63,
            "open result collides with fixed CLOEXEC destination"
        );
        assert_eq!(word(232), 63);
    } else {
        assert_eq!(word(248), 0);
    }
}
fn verify_phases(run: &Run) {
    assert_eq!(run.phases.len(), 4);
    let entry = &run.phases[0];
    verify_setup(entry);
    assert_eq!(entry.registers.orig_rax, libc::SYS_execve as u64);
    assert_eq!(entry.registers.eflags, FLAGS);
    assert_eq!(entry.mask, MASK);
    authenticate_exec_frame(&run.phases[1], run.entry_pc, run.initial_sp);
    let mut expected = run.phases[1].registers;
    expected.rax = 0;
    assert_eq!(run.phases[2].registers, expected);
    assert_eq!(run.phases[1].stack, run.phases[2].stack);
    assert_eq!(run.phases[1].data, run.phases[2].data);
    assert_eq!(run.phases[2].mask, MASK);
    let terminal = &run.phases[3];
    assert_eq!(terminal.registers.rsp, STACK);
    assert_eq!(&terminal.data[..8], &0_u64.to_le_bytes());
    assert_eq!(terminal.mask, MASK);
    assert_ne!(
        run.phases[1].xstate, entry.xstate,
        "original seeded x87/XMM survived exec reset"
    );
}
fn raw_run(path: &Path, target_code: &[u8], interpreter_code: Option<&[u8]>) -> Run {
    let mut raw = Raw::launch(path);
    let pid = raw.parent.id() as i32;
    raw.resume(pid, libc::PTRACE_SYSCALL, 0);
    raw_entry(&mut raw, pid, libc::SYS_execve as u64);
    let mut phases = vec![raw_state(pid)];
    verify_setup(&phases[0]);
    raw.resume(pid, libc::PTRACE_SYSCALL, 0);
    let (tid, status) = raw.wait();
    assert_eq!(tid, pid);
    assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
    assert_eq!(status >> 16, libc::PTRACE_EVENT_EXEC);
    let mut former = 0_u64;
    trace(pid, libc::PTRACE_GETEVENTMSG, 0, (&raw mut former) as usize);
    assert_eq!(former, pid as u64);
    let aux = auxv(pid);
    assert_eq!(aux[&9], ENTRY);
    let entry_pc = if interpreter_code.is_some() {
        assert_ne!(aux[&7], 0);
        aux[&7] + PAGE as u64
    } else {
        assert_eq!(aux[&7], 0);
        ENTRY
    };
    assert_eq!(
        raw_memory(pid, entry_pc, interpreter_code.unwrap_or(target_code).len()),
        interpreter_code.unwrap_or(target_code)
    );
    assert_eq!(raw_memory(pid, ENTRY, target_code.len()), target_code);
    let initial_sp = raw_registers(pid).rsp;
    // The actual fresh user stack is retained as an observation, never zeroed
    // in a full-state comparator. Both pointer-bearing words must be mapped.
    assert_eq!(
        u64::from_ne_bytes(raw_memory(pid, initial_sp, 8).try_into().unwrap()),
        1
    );
    let argv = u64::from_ne_bytes(raw_memory(pid, initial_sp + 8, 8).try_into().unwrap());
    assert_eq!(raw_memory(pid, argv, 1), [0]);
    phases.push(raw_state(pid));
    raw.resume(pid, libc::PTRACE_SYSCALL, 0);
    raw.syscall_stop(pid, libc::PTRACE_SYSCALL_INFO_EXIT, libc::SYS_execve as u64);
    phases.push(raw_state(pid));
    raw.resume(pid, libc::PTRACE_SYSCALL, 0);
    raw_fault(&mut raw, pid);
    assert_eq!(raw_memory(pid, ENTRY, target_code.len()), target_code);
    phases.push(raw_state(pid));
    assert!(
        raw.cleanup(),
        "native oracle foreground physical cleanup deadline"
    );
    let run = Run {
        phases,
        entry_pc,
        initial_sp,
    };
    verify_phases(&run);
    run
}
fn observed(path: &Path, target_code: &[u8], interpreter_code: Option<&[u8]>) -> Run {
    let mut s =
        DynamicSession::launch_with_options(&LaunchCommand::new(path), options(false), TIMEOUT)
            .unwrap();
    let pid = s.pid();
    let handle = pin(pid);
    let initial = initialize(&mut s);
    let before = entry(&mut s, &initial, libc::SYS_execve as u64);
    let old = before.task.unwrap();
    let mut phases = vec![snapshot(&mut s, &before)];
    verify_setup(&phases[0]);
    release(&mut s, &before);
    let replaced = next(&mut s);
    let DynamicEventKind::ExecReplaced {
        previous,
        ref evidence,
    } = replaced.kind
    else {
        panic!("{replaced:?}")
    };
    assert_eq!(previous, old);
    assert_eq!(replaced.tid, pid);
    let new = replaced.task.unwrap();
    assert_ne!(new.task, old.task);
    assert_eq!(new.process, old.process);
    assert_ne!(new.address_space, old.address_space);
    assert_eq!(new.generation, 0);
    assert_eq!(evidence.executable_entry, ENTRY);
    let entry_pc = evidence.initial_instruction;
    if interpreter_code.is_some() {
        assert_eq!(evidence.first_image, FirstImage::Interpreter);
        assert_ne!(evidence.interpreter_base, 0);
        assert_eq!(entry_pc, evidence.interpreter_base + PAGE as u64);
    } else {
        assert_eq!(evidence.first_image, FirstImage::Executable);
        assert_eq!(evidence.interpreter_base, 0);
        assert_eq!(entry_pc, ENTRY);
    }
    let token = replaced.stop_token().unwrap();
    assert_eq!(
        s.read_memory(
            token,
            entry_pc,
            interpreter_code.unwrap_or(target_code).len()
        )
        .unwrap(),
        interpreter_code.unwrap_or(target_code)
    );
    assert_eq!(
        s.read_memory(token, ENTRY, target_code.len()).unwrap(),
        target_code
    );
    let initial_sp = s.read_registers(token).unwrap().rsp;
    assert_eq!(
        u64::from_ne_bytes(
            s.read_memory(token, initial_sp, 8)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        1
    );
    let argv = u64::from_ne_bytes(
        s.read_memory(token, initial_sp + 8, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(s.read_memory(token, argv, 1).unwrap(), [0]);
    let records = s.lifecycle_snapshot().unwrap().unwrap();
    assert_eq!(records.tasks().count(), 2);
    assert_eq!(records.address_spaces().count(), 2);
    assert_eq!(
        records.tasks().find(|t| t.id == old.task).unwrap().state,
        TaskState::Terminal(TerminalReason::ExecReplaced)
    );
    let fresh = records.tasks().find(|t| t.id == new.task).unwrap();
    assert_eq!(fresh.origin, TaskOrigin::Exec { previous: old.task });
    assert_eq!(fresh.sequence, 0);
    assert_eq!(
        fresh.state,
        TaskState::Held {
            pc: entry_pc,
            reason: HoldReason::ExecEvent
        }
    );
    // Old tokens do not acquire authority over the new image at the same TID.
    assert!(s.read_registers(before.stop_token().unwrap()).is_err());
    phases.push(snapshot(&mut s, &replaced));
    release(&mut s, &replaced);
    let exit = next(&mut s);
    assert_eq!(exit.task, Some(new));
    assert_eq!(
        exit.kind,
        DynamicEventKind::SyscallExit {
            result: 0,
            is_error: false
        }
    );
    phases.push(snapshot(&mut s, &exit));
    let terminal = fault(&mut s, &exit);
    assert_eq!(
        s.read_memory(terminal.stop_token().unwrap(), ENTRY, target_code.len())
            .unwrap(),
        target_code
    );
    phases.push(snapshot(&mut s, &terminal));
    finish(s, &[(pid, handle)]);
    let run = Run {
        phases,
        entry_pc,
        initial_sp,
    };
    verify_phases(&run);
    run
}
fn save(path: &Path, run: &Run) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(b"LIEXEC01").unwrap();
    for w in [run.entry_pc, run.initial_sp] {
        f.write_all(&w.to_le_bytes()).unwrap();
    }
    assert_eq!(run.phases.len(), 4);
    for phase in &run.phases {
        for w in words(phase.registers).into_iter().chain([phase.mask]) {
            f.write_all(&w.to_le_bytes()).unwrap();
        }
        for b in [&phase.xstate, &phase.stack, &phase.data] {
            f.write_all(&(b.len() as u32).to_le_bytes()).unwrap();
            f.write_all(b).unwrap();
        }
    }
}
fn load(path: &Path) -> Run {
    let mut f = fs::File::open(path).unwrap();
    let mut magic = [0; 8];
    f.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"LIEXEC01");
    let mut number = || {
        let mut b = [0; 8];
        f.read_exact(&mut b).unwrap();
        u64::from_le_bytes(b)
    };
    let entry_pc = number();
    let initial_sp = number();
    let mut phases = Vec::new();
    for _ in 0..4 {
        let mut w = [0; 28];
        for x in &mut w {
            let mut b = [0; 8];
            f.read_exact(&mut b).unwrap();
            *x = u64::from_le_bytes(b);
        }
        let mut blobs = Vec::new();
        for max in [65536, 32, RESULT_SIZE] {
            let mut n = [0; 4];
            f.read_exact(&mut n).unwrap();
            let n = u32::from_le_bytes(n) as usize;
            assert!(n <= max);
            let mut b = vec![0; n];
            f.read_exact(&mut b).unwrap();
            blobs.push(b);
        }
        assert!(!blobs[0].is_empty());
        assert_eq!(blobs[1].len(), 32);
        assert_eq!(blobs[2].len(), RESULT_SIZE);
        phases.push(Snapshot {
            registers: registers(w[..27].try_into().unwrap()),
            mask: w[27],
            xstate: blobs.remove(0),
            stack: blobs.remove(0),
            data: blobs.remove(0),
        });
    }
    let mut tail = [0];
    assert_eq!(f.read(&mut tail).unwrap(), 0);
    Run {
        phases,
        entry_pc,
        initial_sp,
    }
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
            .name("exec-oracle-output".into())
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
        "EXEC_NATIVE_OUTPUT_UNWIND_PHYSICAL_CLEANUP_COMPLETE"
    } else {
        "EXEC_NATIVE_PHYSICAL_CLEANUP_COMPLETE"
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
        .env("LITEINST_EXEC_TARGET_CODE", target_code)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(code) = interpreter_code {
        command.env("LITEINST_EXEC_INTERPRETER_CODE", code);
    } else {
        command.env_remove("LITEINST_EXEC_INTERPRETER_CODE");
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
fn native(f: &Fixture, caller: &Path, target_code: &[u8], interpreter_code: Option<&[u8]>) -> Run {
    let record = f.directory.join("native.bin");
    let target = f.directory.join("target-code.bin");
    fs::write(&target, target_code).unwrap();
    let interpreter = interpreter_code.map(|code| {
        let path = f.directory.join("interpreter-code.bin");
        fs::write(&path, code).unwrap();
        path
    });
    isolated(caller, &record, &target, interpreter.as_deref(), "state");
    load(&record)
}
fn compare(native: &Run, controlled: &Run) {
    verify_phases(native);
    verify_phases(controlled);
    assert_eq!(
        native.phases[0], controlled.phases[0],
        "original pre-exec seeded state"
    );
    // Randomized exec-stack coordinates are retained and authenticated in each
    // run, with exact full EXEC->EXIT comparisons above. After the original
    // program sets its own fixed stack, every GPR is compared across runs.
    for phase in 1..3 {
        assert_eq!(native.phases[phase].xstate, controlled.phases[phase].xstate);
        assert_eq!(native.phases[phase].mask, controlled.phases[phase].mask);
        assert_eq!(native.phases[phase].stack, controlled.phases[phase].stack);
        assert_eq!(native.phases[phase].data, controlled.phases[phase].data);
    }
    assert_eq!(
        native.phases[3], controlled.phases[3],
        "complete first-user terminal state"
    );
    for word in [0, 6, 10, 11, 15, 16, 18, 19, 21, 22] {
        let mut changed = controlled.phases[3].clone();
        let mut w = words(changed.registers);
        w[word] ^= 1;
        changed.registers = registers(w);
        assert_ne!(native.phases[3], changed);
    }
    for field in 0..4 {
        let mut changed = controlled.phases[3].clone();
        match field {
            0 => changed.xstate[0] ^= 1,
            1 => changed.stack[0] ^= 1,
            2 => changed.data[0] ^= 1,
            3 => changed.mask ^= 1,
            _ => unreachable!(),
        };
        assert_ne!(native.phases[3], changed);
    }
}
#[test]
fn later_static_exec_matches_native_event_exit_and_first_user_state() {
    if let Ok(role) = std::env::var(ORACLE_ROLE) {
        let image = PathBuf::from(std::env::var_os(ORACLE_IMAGE).unwrap());
        let record = PathBuf::from(std::env::var_os(ORACLE_RECORD).unwrap());
        let code = fs::read(std::env::var_os("LITEINST_EXEC_TARGET_CODE").unwrap()).unwrap();
        if role == "unwind" {
            raw_output_unwind(&image);
        } else if role == "state" {
            let interp =
                std::env::var_os("LITEINST_EXEC_INTERPRETER_CODE").map(|p| fs::read(p).unwrap());
            let run = raw_run(&image, &code, interp.as_deref());
            save(&record, &run);
        } else {
            assert!(role == "early_failure" || role == "late_failure" || role == "fault_failure");
            let result = raw_failure(
                &image,
                &code,
                role == "late_failure",
                if role == "fault_failure" {
                    libc::EFAULT
                } else if role == "early_failure" {
                    libc::ENOENT
                } else {
                    libc::EINVAL
                },
            );
            fs::write(record, result.to_le_bytes()).unwrap();
        }
        println!("{}", completion_witness(&role));
        return;
    }
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let code = first_user_code();
    let target = f.image("target", &code, &target_data(), false, None);
    let (c, d) = caller(&target, false);
    let path = f.image("caller", &c, &d, false, None);
    compare(
        &native(&f, &path, &code, None),
        &observed(&path, &code, None),
    );
    isolated(
        &path,
        &f.directory.join("unwind-unused.bin"),
        &f.directory.join("target-code.bin"),
        None,
        "unwind",
    );
}
#[test]
fn later_custom_interpreter_exec_matches_native_first_instruction_and_state() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let mut interpreter = Vec::new();
    store_rax(&mut interpreter, DATA);
    mov(&mut interpreter, 4, STACK);
    interpreter.extend_from_slice(&[0xff, 0x24, 0x25]);
    interpreter.extend_from_slice(&((DATA + 8) as u32).to_le_bytes());
    let ipath = f.image("interpreter", &interpreter, &[], true, None);
    let code = vec![0x0f, 0x0b];
    let target = f.image("target", &code, &target_data(), false, Some(&ipath));
    let (c, d) = caller(&target, false);
    let path = f.image("caller", &c, &d, false, None);
    compare(
        &native(&f, &path, &code, Some(&interpreter)),
        &observed(&path, &code, Some(&interpreter)),
    );
}
#[test]
fn exec_preserves_mask_resets_caught_handler_and_altstack_and_closes_cloexec_fd() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let code = query_code();
    let target = f.image("target", &code, &target_data(), false, None);
    let (c, d) = caller(&target, true);
    let path = f.image("caller", &c, &d, false, None);
    let raw = native(&f, &path, &code, None);
    let controlled = observed(&path, &code, None);
    compare(&raw, &controlled);
    let data = &controlled.phases[3].data;
    let word = |at| u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
    assert_eq!(word(32), MASK);
    assert_eq!(word(40), 0);
    assert_eq!(word(48), (-i64::from(libc::EBADF)) as u64);
    assert_eq!(word(64), 0);
    assert_eq!(word(72), libc::SS_DISABLE as u64);
    assert_eq!(word(80), 0);
    assert_eq!(word(88), 0);
    assert_eq!(word(96), libc::SIG_DFL as u64);
    assert_eq!(word(128), libc::SIG_IGN as u64);
    assert_eq!(word(168), 0);
    assert_eq!(word(176), 0);
}

fn replaced_exit(s: &mut DynamicSession, before: &DynamicEvent) -> (DynamicEvent, DynamicEvent) {
    let old = before.task.unwrap();
    release(s, before);
    let event = next(s);
    let DynamicEventKind::ExecReplaced { previous, .. } = event.kind else {
        panic!("{event:?}")
    };
    assert_eq!(previous, old);
    assert_eq!(event.tid, before.tid);
    let new = event.task.unwrap();
    assert_eq!(new.process, old.process);
    assert_ne!(new.task, old.task);
    assert_ne!(new.address_space, old.address_space);
    assert_eq!(new.generation, 0);
    let mut expected = s.read_registers(event.stop_token().unwrap()).unwrap();
    assert_eq!(expected.rax as i64, -i64::from(libc::ENOSYS));
    assert_eq!(s.signal_mask(event.stop_token().unwrap()).unwrap(), MASK);
    release(s, &event);
    let exit = next(s);
    assert_eq!(exit.task, Some(new));
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
    (event, exit)
}
fn pair(s: &mut DynamicSession, before: &DynamicEvent) -> (DynamicEvent, DynamicEvent, OwnedFd) {
    release(s, before);
    let created = next(s);
    let DynamicEventKind::Created { child } = created.kind else {
        panic!("{created:?}")
    };
    let born = next(s);
    assert_eq!(
        born.kind,
        DynamicEventKind::Newborn {
            parent: before.task.unwrap()
        }
    );
    assert_eq!(born.task, Some(child));
    let pin = pin(born.tid);
    (created, born, pin)
}
fn returned(s: &mut DynamicSession, held: &DynamicEvent, result: i64) -> DynamicEvent {
    release(s, held);
    let event = next(s);
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
fn fork_wait_code(second_fork: bool) -> Vec<u8> {
    let mut code = Vec::new();
    store_rax(&mut code, DATA);
    mov(&mut code, 4, STACK);
    syscall(&mut code, libc::SYS_fork as u64);
    code.extend_from_slice(&[0x48, 0x85, 0xc0, 0x0f, 0x84]);
    let branch = code.len();
    code.extend_from_slice(&[0; 4]);
    code.extend_from_slice(&[0x48, 0x89, 0xc7]);
    call(
        &mut code,
        libc::SYS_wait4,
        &[(6, DATA + 256), (2, 0), (10, 0)],
    );
    if second_fork {
        syscall(&mut code, libc::SYS_fork as u64);
    }
    code.extend_from_slice(&[0x0f, 0x0b]);
    let child = code.len();
    code[branch..branch + 4]
        .copy_from_slice(&i32::try_from(child - branch - 4).unwrap().to_le_bytes());
    call(&mut code, libc::SYS_exit, &[(7, 23)]);
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
fn fork_exec_caller(target: &Path) -> (Vec<u8>, Vec<u8>) {
    let (_, data) = caller(target, false);
    let mut code = Vec::new();
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
    code.extend_from_slice(&seed());
    syscall(&mut code, libc::SYS_fork as u64);
    code.extend_from_slice(&[0x48, 0x85, 0xc0, 0x0f, 0x84]);
    let branch = code.len();
    code.extend_from_slice(&[0; 4]);
    code.extend_from_slice(&[0x48, 0x89, 0xc7]);
    call(
        &mut code,
        libc::SYS_wait4,
        &[(6, DATA + 256), (2, 0), (10, 0)],
    );
    code.extend_from_slice(&[0x0f, 0x0b]);
    let child = code.len();
    code[branch..branch + 4]
        .copy_from_slice(&i32::try_from(child - branch - 4).unwrap().to_le_bytes());
    code.extend_from_slice(&seed());
    exec_args(&mut code);
    code.extend_from_slice(&[0x0f, 0x0b]);
    (code, data)
}
fn three_incarnations(s: &mut DynamicSession) {
    let state = s.lifecycle_snapshot().unwrap().unwrap();
    assert_eq!(state.tasks().count(), 3);
    assert_eq!(state.address_spaces().count(), 3);
    let processes = state
        .tasks()
        .map(|t| t.process)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(processes.len(), 2);
    assert_eq!(
        state
            .tasks()
            .filter(|t| t.state == TaskState::Terminal(TerminalReason::ExecReplaced))
            .count(),
        1
    );
}
fn child_terminal(s: &mut DynamicSession, held: &DynamicEvent, pin: &OwnedFd) {
    let exit = entry(s, held, libc::SYS_exit as u64);
    assert_eq!(
        s.read_registers(exit.stop_token().unwrap()).unwrap().rdi,
        23
    );
    assert_eq!(
        s.read_memory(exit.stop_token().unwrap(), DATA, 8).unwrap(),
        0_u64.to_le_bytes(),
        "original replacement-image AX store did not run"
    );
    release(s, &exit);
    let terminal = next(s);
    assert_eq!(terminal.task, exit.task);
    assert_eq!(
        terminal.kind,
        DynamicEventKind::TaskTerminal {
            status: ExitStatus::Code(23)
        }
    );
    assert!(terminal.stop_token().is_none());
    assert_ne!(poll_bits(pin) & libc::POLLIN, 0);
    assert_eq!(
        poll_bits(pin) & libc::POLLHUP,
        0,
        "held natural parent has not waited"
    );
}
#[test]
fn fork_child_exec_retains_process_identity_and_parent_wait_physically_reaps_it() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let mut targetcode = Vec::new();
    store_rax(&mut targetcode, DATA);
    mov(&mut targetcode, 4, STACK);
    call(&mut targetcode, libc::SYS_exit, &[(7, 23)]);
    targetcode.extend_from_slice(&[0x0f, 0x0b]);
    let target = f.image("target", &targetcode, &target_data(), false, None);
    let (code, data) = fork_exec_caller(&target);
    let path = f.image("caller", &code, &data, false, None);
    let mut s =
        DynamicSession::launch_with_options(&LaunchCommand::new(path), options(true), TIMEOUT)
            .unwrap();
    let parent = s.pid();
    let parentpin = pin(parent);
    let initial = initialize(&mut s);
    let fork = entry(&mut s, &initial, libc::SYS_fork as u64);
    let (created, born, childpin) = pair(&mut s, &fork);
    let parentexit = returned(&mut s, &created, i64::from(born.tid));
    let wait = entry(&mut s, &parentexit, libc::SYS_wait4 as u64);
    let exec = entry(&mut s, &born, libc::SYS_execve as u64);
    let (_, exit) = replaced_exit(&mut s, &exec);
    three_incarnations(&mut s);
    child_terminal(&mut s, &exit, &childpin);
    let waited = returned(&mut s, &wait, i64::from(born.tid));
    reaped(&childpin);
    assert_eq!(
        s.read_memory(waited.stop_token().unwrap(), DATA + 256, 4)
            .unwrap(),
        (23_u32 << 8).to_le_bytes()
    );
    three_incarnations(&mut s);
    let _fault = fault(&mut s, &waited);
    finish(s, &[(parent, parentpin), (born.tid, childpin)]);
}
#[test]
fn exec_then_fork_keeps_two_physical_processes_and_three_lifetime_records() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let targetcode = fork_wait_code(true);
    let target = f.image("target", &targetcode, &target_data(), false, None);
    let (code, data) = caller(&target, false);
    let path = f.image("caller", &code, &data, false, None);
    let mut s =
        DynamicSession::launch_with_options(&LaunchCommand::new(path), options(true), TIMEOUT)
            .unwrap();
    let parent = s.pid();
    let parentpin = pin(parent);
    let initial = initialize(&mut s);
    let exec = entry(&mut s, &initial, libc::SYS_execve as u64);
    let (_, exit) = replaced_exit(&mut s, &exec);
    let fork = entry(&mut s, &exit, libc::SYS_fork as u64);
    let (created, born, childpin) = pair(&mut s, &fork);
    three_incarnations(&mut s);
    let parentexit = returned(&mut s, &created, i64::from(born.tid));
    let wait = entry(&mut s, &parentexit, libc::SYS_wait4 as u64);
    child_terminal(&mut s, &born, &childpin);
    let waited = returned(&mut s, &wait, i64::from(born.tid));
    reaped(&childpin);
    three_incarnations(&mut s);
    let second = entry(&mut s, &waited, libc::SYS_fork as u64);
    let before = snapshot(&mut s, &second);
    assert_eq!(before.registers.orig_rax, libc::SYS_fork as u64);
    assert_eq!(before.registers.rax as i64, -i64::from(libc::ENOSYS));
    assert_eq!(
        s.read_memory(second.stop_token().unwrap(), ENTRY, targetcode.len())
            .unwrap(),
        targetcode
    );
    assert!(matches!(
        s.resume(second.stop_token().unwrap(), DynamicResume::Continue),
        Err(LaunchError::Invalid(
            "dynamic lifetime task bound exhausted"
        ))
    ));
    // Public policy refusal starts cleanup. The private native owner suite
    // checks complete held-state/registry/source equality before that drain.

    finish(s, &[(parent, parentpin), (born.tid, childpin)]);
}
#[test]
fn later_exec_tokens_are_new_and_second_success_is_refused_before_execution() {
    let _serial = FILE_FORK.lock().unwrap();
    let f = Fixture::new();
    let finaltarget = f.image("final", &first_user_code(), &target_data(), false, None);
    let (targetcode, targetdata) = caller(&finaltarget, false);
    let target = f.image("target", &targetcode, &targetdata, false, None);
    let (code, data) = caller(&target, false);
    let path = f.image("caller", &code, &data, false, None);
    let mut s =
        DynamicSession::launch_with_options(&LaunchCommand::new(&path), options(false), TIMEOUT)
            .unwrap();
    let parent = s.pid();
    let pin = pin(parent);
    let initial = initialize(&mut s);
    let exec = entry(&mut s, &initial, libc::SYS_execve as u64);
    let oldtoken = exec.stop_token().unwrap().clone();
    let (_, exit) = replaced_exit(&mut s, &exec);
    let second = entry(&mut s, &exit, libc::SYS_execve as u64);
    let before = snapshot(&mut s, &second);
    assert!(s.resume(&oldtoken, DynamicResume::Continue).is_err());
    assert_eq!(snapshot(&mut s, &second), before);
    let foreign =
        DynamicSession::launch_with_options(&LaunchCommand::new(path), options(false), TIMEOUT)
            .unwrap();
    let foreignpid = foreign.pid();
    let foreignpin = crate::pin(foreignpid);
    let token = foreign.initial_event().stop_token().unwrap().clone();
    assert!(s.read_registers(&token).is_err());
    assert!(s.resume(&token, DynamicResume::Continue).is_err());
    assert_eq!(snapshot(&mut s, &second), before);
    finish(foreign, &[(foreignpid, foreignpin)]);
    assert_eq!(s.lifecycle_snapshot().unwrap().unwrap().tasks().count(), 2);
    assert_eq!(before.registers.orig_rax, libc::SYS_execve as u64);
    assert_eq!(before.registers.rax as i64, -i64::from(libc::ENOSYS));
    assert_eq!(
        s.read_memory(second.stop_token().unwrap(), ENTRY, targetcode.len())
            .unwrap(),
        targetcode
    );
    assert!(matches!(
        s.resume(second.stop_token().unwrap(), DynamicResume::Continue),
        Err(LaunchError::Invalid("native exec success budget exhausted"))
    ));

    finish(s, &[(parent, pin)]);
}
#[test]
fn default_composed_default_and_execveat_remain_pre_execution_refusals() {
    let _serial = FILE_FORK.lock().unwrap();
    for max_tasks in [0, 3, usize::MAX] {
        for exec in [DynamicExecPolicy::Refuse, DynamicExecPolicy::ExecveOnce] {
            assert!(matches!(
                DynamicSession::launch_with_options(
                    &LaunchCommand::new("unopened-invalid-exec-options"),
                    DynamicSessionOptions {
                        lifecycle: DynamicLifecycleOptions {
                            creation: DynamicCreationPolicy::Refuse,
                            max_tasks
                        },
                        exec
                    },
                    TIMEOUT
                ),
                Err(LaunchError::Invalid(
                    "dynamic lifecycle task bound must be one or two"
                ))
            ));
        }
    }
    let f = Fixture::new();
    let target = f.image("target", &first_user_code(), &target_data(), false, None);
    for mode in 0..3 {
        let (mut code, data) = caller(&target, false);
        let nr = if mode == 2 {
            libc::SYS_execveat
        } else {
            libc::SYS_execve
        };
        if mode == 2 {
            code = seed();
            call(
                &mut code,
                libc::SYS_execveat,
                &[
                    (7, libc::AT_FDCWD as u64),
                    (6, DATA + 1024),
                    (2, 0),
                    (10, 0),
                    (8, 0),
                ],
            );
            code.extend_from_slice(&[0x0f, 0x0b]);
        }
        let path = f.image(&format!("caller{mode}"), &code, &data, false, None);
        let command = LaunchCommand::new(path);
        let mut s = match mode {
            0 => DynamicSession::launch(&command, TIMEOUT),
            1 => DynamicSession::launch_with_options(
                &command,
                DynamicSessionOptions::default(),
                TIMEOUT,
            ),
            _ => DynamicSession::launch_with_options(&command, options(false), TIMEOUT),
        }
        .unwrap();
        let pid = s.pid();
        let pin = pin(pid);
        let initial = s.initial_event().clone();
        release(&mut s, &initial);
        let bootexit = next(&mut s);
        assert_eq!(
            bootexit.kind,
            DynamicEventKind::SyscallExit {
                result: 0,
                is_error: false
            }
        );
        if mode < 2 {
            assert!(s.lifecycle_snapshot().unwrap().is_none());
        }
        let denied = entry(&mut s, &bootexit, nr as u64);
        let before = snapshot(&mut s, &denied);
        assert_eq!(before.registers.orig_rax, nr as u64);
        assert_eq!(before.registers.rax as i64, -i64::from(libc::ENOSYS));
        assert_eq!(
            s.read_memory(denied.stop_token().unwrap(), ENTRY, code.len())
                .unwrap(),
            code
        );
        assert!(matches!(
            s.resume(denied.stop_token().unwrap(), DynamicResume::Continue),
            Err(LaunchError::Invalid(
                "dynamic creation and later exec are not yet qualified"
            ))
        ));
        finish(s, &[(pid, pin)]);
    }
}

fn raw_output_unwind(path: &Path) {
    let mut retained = None;
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let raw = Raw::launch(path);
        retained = Some(pin(raw.parent.id() as i32));
        // Larger than a pipe's capacity, below the retained diagnostic bound.
        // The original child remains held throughout this deliberate failure.
        let payload = vec![b'X'; 256 * 1024];
        let mut stderr = io::stderr().lock();
        stderr.write_all(&payload).unwrap();
        stderr.write_all(b"\n").unwrap();
        stderr.flush().unwrap();
        drop(stderr);
        panic!("intentional exec oracle output unwind");
    }));
    let payload = failure.expect_err("intentional oracle panic did not occur");
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"intentional exec oracle output unwind")
    );
    reaped(retained.as_ref().unwrap());
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

fn raw_failure(path: &Path, caller_code: &[u8], late: bool, errno: i32) -> i64 {
    let mut raw = Raw::launch(path);
    let pid = raw.parent.id() as i32;
    raw.resume(pid, libc::PTRACE_SYSCALL, 0);
    raw_entry(&mut raw, pid, libc::SYS_execve as u64);
    assert_eq!(raw_memory(pid, ENTRY, caller_code.len()), caller_code);
    raw.resume(pid, libc::PTRACE_SYSCALL, 0);
    // This next status must be the actual errno EXIT, not EXEC or a relabelled
    // fault. A later fatal signal does not turn it into old-mm survival proof.
    raw.syscall_stop(pid, libc::PTRACE_SYSCALL_INFO_EXIT, libc::SYS_execve as u64);
    let result = raw_registers(pid).rax as i64;
    assert_eq!(result, -i64::from(errno));
    let mut info: libc::ptrace_syscall_info = unsafe { std::mem::zeroed() };
    trace(
        pid,
        libc::PTRACE_GET_SYSCALL_INFO,
        std::mem::size_of_val(&info),
        (&raw mut info) as usize,
    );
    assert_ne!(unsafe { info.u.exit.is_error }, 0);
    assert_eq!(unsafe { info.u.exit.sval }, result);
    raw.resume(pid, libc::PTRACE_SYSCALL, 0);
    let (tid, status) = raw.wait();
    assert_eq!(tid, pid);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(status >> 16, 0);
    let mut signal: libc::siginfo_t = unsafe { std::mem::zeroed() };
    trace(pid, libc::PTRACE_GETSIGINFO, 0, (&raw mut signal) as usize);
    if late {
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSEGV);
        assert_eq!(signal.si_code, libc::SI_KERNEL);
        raw.resume(pid, libc::PTRACE_SYSCALL, libc::SIGSEGV);
        loop {
            let (tid, status) = raw.wait();
            assert_eq!(tid, pid);
            if libc::WIFSIGNALED(status) {
                assert_eq!(libc::WTERMSIG(status), libc::SIGSEGV);
                break;
            }
            assert!(libc::WIFSTOPPED(status));
            assert_eq!(status >> 16, libc::PTRACE_EVENT_EXIT);
            raw.resume(pid, libc::PTRACE_CONT, 0);
        }
    } else {
        assert_eq!(libc::WSTOPSIG(status), libc::SIGILL);
        assert_eq!(signal.si_code, 2);
        assert_eq!(raw_memory(pid, ENTRY, caller_code.len()), caller_code);
        assert_eq!(raw_registers(pid).rax as i64, result);
    }
    assert!(
        raw.cleanup(),
        "native failure oracle physical cleanup deadline"
    );
    result
}
#[test]
fn early_and_postpoint_exec_failures_are_explicit_refusals_with_physical_cleanup() {
    let _serial = FILE_FORK.lock().unwrap();
    for (role, errno) in [
        ("fault_failure", libc::EFAULT),
        ("early_failure", libc::ENOENT),
        ("late_failure", libc::EINVAL),
    ] {
        let late = role == "late_failure";
        let f = Fixture::new();
        let target = if late {
            let path = f.image("malformed", &first_user_code(), &target_data(), false, None);
            let mut bytes = fs::read(&path).unwrap();
            // Linux v7.1.3 load_elf_binary calls begin_new_exec before loading and
            // checking this PT_LOAD filesz > memsz relation (fs/binfmt_elf.c).
            // do_execveat_common forces fatal SIGSEGV on postpoint failure. The
            // independent trace below must observe both errno EXIT and that fault.
            bytes[104..112].copy_from_slice(&4096_u64.to_le_bytes());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
            path
        } else {
            f.directory.join("does-not-exist")
        };
        let (mut code, data) = caller(&target, false);
        if errno == libc::EFAULT {
            let mut original = Vec::new();
            mov(&mut original, 7, DATA + 1024);
            let sites = code
                .windows(original.len())
                .enumerate()
                .filter(|(_, bytes)| *bytes == original.as_slice())
                .map(|(at, _)| at)
                .collect::<Vec<_>>();
            assert_eq!(sites.len(), 1);
            code[sites[0] + 2..sites[0] + 10].copy_from_slice(&0_u64.to_le_bytes());
        }
        let path = f.image("caller", &code, &data, false, None);
        let codefile = f.directory.join("caller-code.bin");
        fs::write(&codefile, &code).unwrap();
        let record = f.directory.join("failure.bin");
        isolated(&path, &record, &codefile, None, role);
        let rawresult = i64::from_le_bytes(fs::read(record).unwrap().try_into().unwrap());
        assert_eq!(rawresult, -i64::from(errno));
        let mut s =
            DynamicSession::launch_with_options(&LaunchCommand::new(path), options(false), TIMEOUT)
                .unwrap();
        let pid = s.pid();
        let handle = pin(pid);
        let initial = initialize(&mut s);
        let exec = entry(&mut s, &initial, libc::SYS_execve as u64);
        assert_eq!(
            s.read_memory(exec.stop_token().unwrap(), ENTRY, code.len())
                .unwrap(),
            code
        );
        release(&mut s, &exec);
        assert!(matches!(
            s.next_event(TIMEOUT),
            Err(LaunchError::Invalid(
                "native exec failure has no proved old-mm continuity"
            ))
        ));
        finish(s, &[(pid, handle)]);
    }
}
