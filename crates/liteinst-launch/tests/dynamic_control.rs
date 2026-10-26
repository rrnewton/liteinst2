#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Native controller evidence, independent of page publication. The terminal
//! oracle uses raw TRACEME on the original hand-encoded ELF, not DynamicSession.

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

use liteinst_launch::{
    DynamicEvent, DynamicEventKind, DynamicResume, DynamicSession, FirstImage, LaunchCommand,
    LaunchError, RegisterSnapshot,
};

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const ENTRY: u64 = BASE + PAGE as u64;
const DATA: u64 = 0x600000;
const STACK: u64 = DATA + PAGE as u64 - 64;
const FLAGS: u64 = 0xed7;
const ILL_ILLOPN: i32 = 2; // Linux x86-64 UD2 siginfo cause.
const TIMEOUT: Duration = Duration::from_secs(3);
const FIRST: [u8; 4] = [0x0f, 0xa2, 0x0f, 0x0b];
static NEXT: AtomicUsize = AtomicUsize::new(0);
// No fork may inherit a writable executable FD from another fixture in this
// binary. Running sessions still exercise independent native tracer threads.
static TEST_LOCK: Mutex<()> = Mutex::new(());

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "dynamic-control-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn image(&self, name: &str, code: &[u8], pie: bool, interpreter: Option<&Path>) -> Image {
        assert!(code.len() <= PAGE);
        let mut bytes = vec![0; 3 * PAGE];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, if pie { 3 } else { 2 });
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        let base = if pie { 0 } else { BASE };
        put64(&mut bytes, 24, base + PAGE as u64);
        put64(&mut bytes, 32, 64);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 54, 56);
        put16(&mut bytes, 56, if interpreter.is_some() { 4 } else { 3 });
        put32(&mut bytes, 64, 1);
        put32(&mut bytes, 68, 5);
        put64(&mut bytes, 80, base);
        put64(&mut bytes, 96, (2 * PAGE) as u64);
        put64(&mut bytes, 104, (2 * PAGE) as u64);
        put64(&mut bytes, 112, PAGE as u64);
        put32(&mut bytes, 120, 1);
        put32(&mut bytes, 124, 6);
        put64(&mut bytes, 128, (2 * PAGE) as u64);
        put64(&mut bytes, 136, if pie { 2 * PAGE as u64 } else { DATA });
        put64(&mut bytes, 152, PAGE as u64);
        put64(&mut bytes, 160, PAGE as u64);
        put64(&mut bytes, 168, PAGE as u64);
        put32(&mut bytes, 176, 0x6474e551);
        put32(&mut bytes, 180, 6);
        put64(&mut bytes, 224, 16);
        if let Some(interpreter) = interpreter {
            let name = interpreter.as_os_str().as_bytes();
            assert!(name.len() < PAGE - 512);
            put32(&mut bytes, 232, 3);
            put32(&mut bytes, 236, 4);
            put64(&mut bytes, 240, 512);
            put64(&mut bytes, 248, base + 512);
            put64(&mut bytes, 264, (name.len() + 1) as u64);
            put64(&mut bytes, 272, (name.len() + 1) as u64);
            put64(&mut bytes, 280, 1);
            bytes[512..512 + name.len()].copy_from_slice(name);
        }
        bytes[PAGE..PAGE + code.len()].copy_from_slice(code);
        let path = self.0.join(name);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        drop(file);
        Image {
            path,
            bytes,
            code: code.to_vec(),
        }
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Image {
    path: PathBuf,
    bytes: Vec<u8>,
    code: Vec<u8>,
}

impl Image {
    fn launch(&self) -> DynamicSession {
        DynamicSession::launch(&LaunchCommand::new(&self.path), TIMEOUT).unwrap()
    }
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn mov(code: &mut Vec<u8>, register: u8, value: u64) {
    code.extend_from_slice(&[
        if register < 8 { 0x48 } else { 0x49 },
        0xb8 + (register & 7),
    ]);
    code.extend_from_slice(&value.to_le_bytes());
}
fn exit_code(status: u64) -> Vec<u8> {
    let mut code = Vec::new();
    mov(&mut code, 0, libc::SYS_exit as u64);
    mov(&mut code, 7, status);
    code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    code
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
    code.extend_from_slice(&[0xdb, 0xe3, 0xd9, 0xe8]); // FNINIT; FLD1.
    code.extend_from_slice(&[0x66, 0x0f, 0x76, 0xc9, 0x66, 0x0f, 0x6f, 0xd1]);
    for register in 0..16 {
        if register != 4 {
            mov(
                &mut code,
                register,
                0x1234567890000000 + u64::from(register),
            );
        }
    }
    code.push(0x68);
    code.extend_from_slice(&(FLAGS as u32).to_le_bytes());
    code.push(0x9d); // POPFQ, including DF; no implicit flag masking.
    code
}
fn spinner() -> (Vec<u8>, u64) {
    let mut code = seed();
    mov(&mut code, 0, libc::SYS_getpid as u64);
    code.extend_from_slice(&[0x0f, 0x05]);
    let pc = ENTRY + code.len() as u64;
    code.extend_from_slice(&[0xeb, 0xfe]); // One original, syscall-free self jump.
    (code, pc)
}

fn pidfd(pid: i32) -> OwnedFd {
    // SAFETY: this is the exact held or unreaped child owned by the caller.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0, "pidfd_open: {}", io::Error::last_os_error());
    // SAFETY: the successful syscall returned one new descriptor.
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}
fn caller_signal_mask() -> u64 {
    let mut mask = 0_u64;
    // SAFETY: a null input leaves the calling thread's mask unchanged; the
    // kernel writes its complete x86-64 eight-byte signal set to this output.
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                std::ptr::null::<u64>(),
                &raw mut mask,
                std::mem::size_of::<u64>(),
            )
        },
        0,
        "rt_sigprocmask: {}",
        io::Error::last_os_error()
    );
    mask
}
fn assert_reaped(handle: &OwnedFd) {
    let mut poll = libc::pollfd {
        fd: handle.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized descriptor record, with a zero waiting interval.
    assert_eq!(unsafe { libc::poll(&raw mut poll, 1, 0) }, 1);
    assert_ne!(poll.revents & libc::POLLIN, 0);
    // A ptrace terminal wait may leave a real-parent zombie. HUP additionally
    // requires this pinned PID to have no remaining task.
    assert_ne!(poll.revents & libc::POLLHUP, 0);
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
    // SAFETY: a stable descriptor and WNOWAIT prevent unrelated or competing reaps.
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                handle.as_raw_fd() as u32,
                info.as_mut_ptr(),
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
fn finish(session: DynamicSession, handle: &OwnedFd, pid: i32) {
    assert_eq!(session.terminate(TIMEOUT).unwrap().reaped, vec![pid]);
    assert_reaped(handle);
}
fn release(session: &mut DynamicSession, event: &DynamicEvent) {
    session
        .resume(event.stop_token().unwrap(), DynamicResume::Continue)
        .unwrap();
}
fn exec_exit(session: &mut DynamicSession) -> DynamicEvent {
    let initial = session.initial_event().clone();
    assert!(matches!(initial.kind, DynamicEventKind::Exec { .. }));
    release(session, &initial);
    let event = session.next_event(TIMEOUT).unwrap();
    assert!(matches!(
        event.kind,
        DynamicEventKind::SyscallExit {
            result: 0,
            is_error: false
        }
    ));
    event
}
fn getpid_exit(session: &mut DynamicSession) -> DynamicEvent {
    let event = exec_exit(session);
    release(session, &event);
    let event = session.next_event(TIMEOUT).unwrap();
    assert!(
        matches!(event.kind, DynamicEventKind::SyscallEntry { number, .. } if number == libc::SYS_getpid as u64)
    );
    release(session, &event);
    let event = session.next_event(TIMEOUT).unwrap();
    assert!(
        matches!(event.kind, DynamicEventKind::SyscallExit { result, is_error: false } if result == i64::from(session.pid()))
    );
    event
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Evidence {
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    stack: Vec<u8>,
    marker: Vec<u8>,
}

fn evidence(session: &mut DynamicSession, event: &DynamicEvent) -> Evidence {
    let token = event.stop_token().unwrap();
    Evidence {
        registers: session.read_registers(token).unwrap(),
        xstate: session.read_xstate(token).unwrap(),
        stack: session.read_memory(token, STACK, 32).unwrap(),
        marker: session.read_memory(token, DATA, 8).unwrap(),
    }
}

#[test]
fn static_exec_stop_and_exact_kernel_exec_return_preserve_original_entry() {
    let _serial = TEST_LOCK.lock().unwrap();
    let directory = Directory::new();
    let image = directory.image("static", &FIRST, false, None);
    let caller_mask = caller_signal_mask();
    let mut session = image.launch();
    assert_eq!(caller_signal_mask(), caller_mask);
    let pid = session.pid();
    let handle = pidfd(pid);
    let event = session.initial_event().clone();
    let DynamicEventKind::Exec { evidence: entry } = &event.kind else {
        panic!("not an exec event")
    };
    assert_eq!(entry.first_image, FirstImage::Executable);
    assert_eq!(entry.initial_instruction, ENTRY);
    assert_eq!(entry.executable_entry, ENTRY);
    assert_eq!(entry.interpreter_base, 0);
    let token = event.stop_token().unwrap();
    let before = session.read_registers(token).unwrap();
    let xstate = session.read_xstate(token).unwrap();
    let mask = session.signal_mask(token).unwrap();
    assert_eq!(mask, caller_mask);
    assert_eq!(before.rip, ENTRY);
    assert_eq!(before.rax as i64, -i64::from(libc::ENOSYS));
    assert_eq!(before.orig_rax, libc::SYS_execve as u64);
    assert_eq!(session.read_registers(token).unwrap(), before);
    assert_eq!(session.read_xstate(token).unwrap(), xstate);
    assert_eq!(session.signal_mask(token).unwrap(), mask);
    assert_eq!(
        session.read_memory(token, BASE, 2 * PAGE).unwrap(),
        image.bytes[..2 * PAGE]
    );
    assert_eq!(
        session.read_memory(token, DATA, PAGE).unwrap(),
        image.bytes[2 * PAGE..]
    );
    let returned = exec_exit(&mut session);
    let mut expected = before;
    expected.rax = 0;
    assert_eq!(
        session
            .read_registers(returned.stop_token().unwrap())
            .unwrap(),
        expected
    );
    assert_eq!(
        session
            .read_memory(returned.stop_token().unwrap(), ENTRY, FIRST.len())
            .unwrap(),
        FIRST
    );
    // This is the actual syscall-exit phase, never relabelled first-user entry.
    assert_eq!(fs::read(&image.path).unwrap(), image.bytes);
    finish(session, &handle, pid);
    assert_eq!(caller_signal_mask(), caller_mask);
}

#[test]
fn pie_exec_event_authenticates_relocated_original_entry() {
    let _serial = TEST_LOCK.lock().unwrap();
    let directory = Directory::new();
    let image = directory.image("pie", &FIRST, true, None);
    let mut session = image.launch();
    let pid = session.pid();
    let handle = pidfd(pid);
    let event = session.initial_event().clone();
    let DynamicEventKind::Exec { evidence: entry } = &event.kind else {
        panic!("not exec")
    };
    assert_eq!(entry.first_image, FirstImage::Executable);
    assert_eq!(entry.initial_instruction, entry.executable_entry);
    assert_ne!(entry.initial_instruction, PAGE as u64);
    assert_eq!(entry.interpreter_base, 0);
    let token = event.stop_token().unwrap();
    let before = session.read_registers(token).unwrap();
    assert_eq!(before.rip, entry.initial_instruction);
    assert_eq!(
        session.read_memory(token, before.rip, FIRST.len()).unwrap(),
        FIRST
    );
    assert_eq!(session.read_registers(token).unwrap(), before);
    finish(session, &handle, pid);
}

#[test]
fn interpreter_exec_event_preserves_both_selected_first_instructions() {
    let _serial = TEST_LOCK.lock().unwrap();
    let directory = Directory::new();
    let interpreter = directory.image("interpreter", &FIRST, true, None);
    let image = directory.image("interpreted", &FIRST, false, Some(&interpreter.path));
    let mut session = image.launch();
    let pid = session.pid();
    let handle = pidfd(pid);
    let event = session.initial_event().clone();
    let DynamicEventKind::Exec { evidence: entry } = &event.kind else {
        panic!("not exec")
    };
    assert_eq!(entry.first_image, FirstImage::Interpreter);
    assert_eq!(
        entry.interpreter.as_deref(),
        Some(interpreter.path.as_path())
    );
    assert_ne!(entry.interpreter_base, 0);
    assert_eq!(
        entry.initial_instruction,
        entry.interpreter_base + PAGE as u64
    );
    assert_eq!(entry.executable_entry, ENTRY);
    assert_ne!(entry.initial_instruction, ENTRY);
    let token = event.stop_token().unwrap();
    let before = session.read_registers(token).unwrap();
    let xstate = session.read_xstate(token).unwrap();
    assert_eq!(before.rip, entry.initial_instruction);
    assert_eq!(
        session.read_memory(token, before.rip, FIRST.len()).unwrap(),
        FIRST
    );
    assert_eq!(
        session.read_memory(token, ENTRY, FIRST.len()).unwrap(),
        FIRST
    );
    assert_eq!(session.read_registers(token).unwrap(), before);
    assert_eq!(session.read_xstate(token).unwrap(), xstate);
    finish(session, &handle, pid);
}

#[test]
fn active_interrupt_preserves_seeded_state_and_rejects_stale_or_foreign_tokens() {
    let _serial = TEST_LOCK.lock().unwrap();
    let directory = Directory::new();
    let (code, loop_pc) = spinner();
    let image = directory.image("spinner", &code, false, None);
    let mut session = image.launch();
    let pid = session.pid();
    let handle = pidfd(pid);
    let mut other = image.launch();
    let other_pid = other.pid();
    let other_handle = pidfd(other_pid);
    let foreign = other.initial_event().stop_token().unwrap().clone();
    let old = session.initial_event().stop_token().unwrap().clone();
    let event = getpid_exit(&mut session);
    release(&mut session, &event);
    let first = session.interrupt(TIMEOUT).unwrap();
    assert_eq!(first.kind, DynamicEventKind::Interrupted);
    let expected = evidence(&mut session, &first);
    assert_eq!(expected.registers.rip, loop_pc);
    assert_eq!(expected.registers.rsp, STACK);
    assert_eq!(expected.registers.rax, pid as u64);
    assert_eq!(expected.registers.rcx, loop_pc);
    assert_eq!(expected.registers.r11, FLAGS);
    assert_eq!(expected.registers.eflags, FLAGS);
    assert_eq!(expected.marker, [0; 8]);
    assert_eq!(evidence(&mut session, &first), expected);
    assert!(session.read_registers(&old).is_err());
    assert!(session.read_registers(&foreign).is_err());
    assert!(session.resume(&old, DynamicResume::Continue).is_err());
    assert!(session.resume(&foreign, DynamicResume::Continue).is_err());
    assert!(
        other
            .resume(first.stop_token().unwrap(), DynamicResume::Continue)
            .is_err()
    );
    assert_eq!(evidence(&mut session, &first), expected);
    assert_eq!(
        session
            .read_memory(first.stop_token().unwrap(), ENTRY, code.len())
            .unwrap(),
        code
    );
    release(&mut session, &first);
    let second = session.interrupt(TIMEOUT).unwrap();
    assert_eq!(second.kind, DynamicEventKind::Interrupted);
    assert_ne!(first.stop_token(), second.stop_token());
    assert!(session.read_xstate(first.stop_token().unwrap()).is_err());
    assert_eq!(evidence(&mut session, &second), expected);
    finish(session, &handle, pid);
    finish(other, &other_handle, other_pid);
}

struct Native {
    child: Child,
    handle: Option<OwnedFd>,
    reaped: bool,
}

impl Native {
    fn launch(image: &Image, traced: bool) -> Self {
        let mut command = Command::new(&image.path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if traced {
            // SAFETY: the child closure only invokes ptrace and errno access.
            unsafe {
                command.pre_exec(|| {
                    if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
        }
        let mut native = Self {
            child: command.spawn().unwrap(),
            handle: None,
            reaped: false,
        };
        native.handle = Some(pidfd(native.pid()));
        native
    }
    fn pid(&self) -> i32 {
        self.child.id() as i32
    }
    fn wait(&mut self) -> i32 {
        let until = Instant::now() + TIMEOUT;
        loop {
            let mut status = 0;
            // SAFETY: only this particular unreaped native child is waited on.
            let result =
                unsafe { libc::waitpid(self.pid(), &raw mut status, libc::WNOHANG | libc::__WALL) };
            if result == self.pid() {
                self.reaped = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                return status;
            }
            if result == -1 {
                let error = io::Error::last_os_error();
                self.reaped = error.raw_os_error() == Some(libc::ECHILD);
                assert_eq!(error.raw_os_error(), Some(libc::EINTR));
            }
            assert!(Instant::now() < until, "independent native wait deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn ptrace(&self, request: u32, address: usize, data: usize) {
        // SAFETY: each request uses its native ABI on this owned stopped child.
        assert_ne!(
            unsafe { libc::ptrace(request, self.pid(), address, data) },
            -1,
            "raw ptrace: {}",
            io::Error::last_os_error()
        );
    }
    fn memory(&self, address: u64, len: usize) -> Vec<u8> {
        assert_eq!(address % 8, 0);
        assert_eq!(len % 8, 0);
        let mut bytes = Vec::new();
        for offset in (0..len).step_by(8) {
            // SAFETY: errno is local; this only reads the held native child.
            let value = unsafe {
                *libc::__errno_location() = 0;
                let value = libc::ptrace(
                    libc::PTRACE_PEEKDATA,
                    self.pid(),
                    address + offset as u64,
                    0,
                );
                assert!(value != -1 || *libc::__errno_location() == 0);
                value as u64
            };
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }
    fn terminal_evidence(&mut self, terminal: u64) -> Evidence {
        let status = self.wait();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        self.ptrace(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        self.ptrace(libc::PTRACE_CONT, 0, 0);
        let status = self.wait();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGILL);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        self.ptrace(libc::PTRACE_GETSIGINFO, 0, (&raw mut info) as usize);
        assert_eq!(info.si_code, ILL_ILLOPN);
        // SAFETY: synchronous SIGILL carries the fault-address union.
        assert_eq!(unsafe { info.si_addr() } as u64, terminal);
        let mut registers = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
        self.ptrace(libc::PTRACE_GETREGS, 0, registers.as_mut_ptr() as usize);
        // SAFETY: successful GETREGS initialized the complete native structure.
        let registers: RegisterSnapshot = unsafe { registers.assume_init() }.into();
        assert_eq!(registers.rip, terminal);
        let mut xstate = vec![0; 64 * 1024];
        let mut vector = libc::iovec {
            iov_base: xstate.as_mut_ptr().cast(),
            iov_len: xstate.len(),
        };
        self.ptrace(libc::PTRACE_GETREGSET, 0x202, (&raw mut vector) as usize);
        assert!((512..xstate.len()).contains(&vector.iov_len));
        xstate.truncate(vector.iov_len);
        Evidence {
            registers,
            xstate,
            stack: self.memory(STACK, 32),
            marker: self.memory(DATA, 8),
        }
    }
}

impl Drop for Native {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // SAFETY: numeric signalling is used only before pinning and while this
        // exact child remains exclusively owned and unreaped.
        unsafe {
            if let Some(handle) = &self.handle {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    handle.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            } else {
                libc::kill(self.pid(), libc::SIGKILL);
            }
        }
        let until = Instant::now() + TIMEOUT;
        while Instant::now() < until {
            let mut status = 0;
            // SAFETY: one cleanup owner waits only for this original child.
            let result =
                unsafe { libc::waitpid(self.pid(), &raw mut status, libc::WNOHANG | libc::__WALL) };
            if result == self.pid() && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                self.reaped = true;
                break;
            }
            if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                self.reaped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(self.reaped, "independent native cleanup deadline");
    }
}

#[test]
fn native_terminal_general_flags_xstate_and_memory_equal_raw_ptrace_oracle() {
    let _serial = TEST_LOCK.lock().unwrap();
    let directory = Directory::new();
    let mut code = seed();
    code.extend_from_slice(&[0x4d, 0x8d, 0x52, 0x07]); // LEA R10,[R10+7], no flags changed.
    code.extend_from_slice(&[0x48, 0xa3]); // MOV moffs64,RAX.
    code.extend_from_slice(&DATA.to_le_bytes());
    let terminal = ENTRY + code.len() as u64;
    code.extend_from_slice(&[0x0f, 0x0b]);
    let image = directory.image("terminal", &code, false, None);
    let mut native = Native::launch(&image, true);
    let expected = native.terminal_evidence(terminal);
    assert_eq!(expected.registers.rsp, STACK);
    assert_eq!(expected.marker, 0x1234567890000000_u64.to_le_bytes());
    let native_handle = pidfd(native.pid());
    drop(native);
    assert_reaped(&native_handle);

    let mut session = image.launch();
    let pid = session.pid();
    let handle = pidfd(pid);
    let event = exec_exit(&mut session);
    release(&mut session, &event);
    let event = session.next_event(TIMEOUT).unwrap();
    let DynamicEventKind::SignalDelivery(info) = &event.kind else {
        panic!("not original UD2 signal")
    };
    assert_eq!(info.signal(), libc::SIGILL);
    assert_eq!(info.code(), ILL_ILLOPN);
    assert_eq!(info.fault_address(), Some(terminal));
    let actual = evidence(&mut session, &event);
    assert_eq!(actual, expected);
    for field in 0..5 {
        let mut wrong = expected.clone();
        match field {
            0 => wrong.registers.rsp += 16,
            1 => wrong.registers.r11 ^= 1,
            2 => wrong.registers.eflags ^= 1,
            3 => wrong.xstate[160] ^= 1,
            4 => wrong.stack[0] ^= 1,
            _ => unreachable!(),
        }
        assert_ne!(actual, wrong);
    }
    assert_eq!(
        session
            .read_memory(event.stop_token().unwrap(), ENTRY, code.len())
            .unwrap(),
        code
    );
    finish(session, &handle, pid);
}

#[test]
fn running_wait_deadline_closes_session_and_explicit_cleanup_reaps() {
    let _serial = TEST_LOCK.lock().unwrap();
    let directory = Directory::new();
    let (code, _) = spinner();
    let image = directory.image("timeout", &code, false, None);
    let mut session = image.launch();
    let pid = session.pid();
    let handle = pidfd(pid);
    let event = getpid_exit(&mut session);
    release(&mut session, &event);
    let started = Instant::now();
    assert!(matches!(
        session.next_event(Duration::from_millis(20)),
        Err(LaunchError::Timeout(_))
    ));
    assert!(started.elapsed() < TIMEOUT);
    assert!(session.next_event(TIMEOUT).is_err());
    assert!(
        session
            .resume(event.stop_token().unwrap(), DynamicResume::Continue)
            .is_err()
    );
    finish(session, &handle, pid);
}

fn run_exit(session: &mut DynamicSession, expected: i32) {
    let event = exec_exit(session);
    release(session, &event);
    let event = session.next_event(TIMEOUT).unwrap();
    assert!(
        matches!(event.kind, DynamicEventKind::SyscallEntry { number, arguments }
        if number == libc::SYS_exit as u64 && arguments[0] == expected as u64)
    );
    release(session, &event);
    let event = session.next_event(TIMEOUT).unwrap();
    assert_eq!(event.kind, DynamicEventKind::Exited { code: expected });
    assert!(event.stop_token().is_none());
}

fn host_subreaper() -> i32 {
    let mut setting = -1_i32;
    // SAFETY: PR_GET_CHILD_SUBREAPER writes one initialized native integer.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &raw mut setting, 0, 0, 0) },
        0
    );
    assert!(matches!(setting, 0 | 1));
    setting
}

fn real_parent(pid: i32) -> i32 {
    // This is an observation in the test, never production signaling authority.
    // The application is held while its real-parent pidfd is acquired below.
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let parents: Vec<_> = status
        .lines()
        .filter_map(|line| line.strip_prefix("PPid:"))
        .collect();
    assert_eq!(parents.len(), 1);
    parents[0].trim().parse().unwrap()
}

#[test]
fn independent_sessions_never_reap_each_other_or_an_unrelated_host_child() {
    let _serial = TEST_LOCK.lock().unwrap();
    let original_subreaper = host_subreaper();
    let directory = Directory::new();
    let host_image = directory.image("host", &exit_code(23), false, None);
    let mut host = Native::launch(&host_image, false);
    let first_image = directory.image("first", &exit_code(11), false, None);
    let second_image = directory.image("second", &exit_code(17), false, None);
    let mut first = first_image.launch();
    let mut second = second_image.launch();
    let first_pid = first.pid();
    let second_pid = second.pid();
    assert_ne!(first_pid, second_pid);
    assert_ne!(host.pid(), first_pid);
    assert_ne!(host.pid(), second_pid);
    let first_parent = real_parent(first_pid);
    let second_parent = real_parent(second_pid);
    let host_pid = std::process::id() as i32;
    assert!(first_parent > 0 && second_parent > 0);
    assert_ne!(first_parent, second_parent);
    assert_ne!(first_parent, host_pid);
    assert_ne!(second_parent, host_pid);
    assert_eq!(real_parent(first_parent), host_pid);
    assert_eq!(real_parent(second_parent), host_pid);
    let first_parent_handle = pidfd(first_parent);
    let second_parent_handle = pidfd(second_parent);
    assert_eq!(host_subreaper(), original_subreaper);
    let first_handle = pidfd(first_pid);
    let second_handle = pidfd(second_pid);
    run_exit(&mut second, 17);
    let first_initial = first.initial_event().clone();
    assert_eq!(
        first
            .read_memory(
                first_initial.stop_token().unwrap(),
                ENTRY,
                first_image.code.len()
            )
            .unwrap(),
        first_image.code
    );
    run_exit(&mut first, 11);
    finish(second, &second_handle, second_pid);
    assert_reaped(&second_parent_handle);
    assert_eq!(host_subreaper(), original_subreaper);
    finish(first, &first_handle, first_pid);
    assert_reaped(&first_parent_handle);
    assert_eq!(host_subreaper(), original_subreaper);
    let status = host.wait(); // It must still be waitable by its original owner.
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 23);
    assert_reaped(host.handle.as_ref().unwrap());
}

#[test]
fn lifecycle_and_non_native_syscall_encodings_refuse_before_execution() {
    let _serial = TEST_LOCK.lock().unwrap();
    let directory = Directory::new();
    let native = [
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_execve,
        libc::SYS_execveat,
    ];
    let mut rows: Vec<(u64, [u8; 2], bool)> = native
        .into_iter()
        .map(|number| (number as u64, [0x0f, 0x05], true))
        .collect();
    for number in [libc::SYS_fork as u64, libc::SYS_execve as u64] {
        rows.push((number | 0x40000000, [0x0f, 0x05], false));
        rows.push((number | 0x100000000, [0x0f, 0x05], false));
        rows.push((number | 0xffffffff00000000, [0x0f, 0x05], false));
    }
    rows.extend([(2, [0xcd, 0x80], false), (11, [0xcd, 0x80], false)]);
    assert_eq!(rows.len(), 14);
    for (index, (number, encoding, native_abi)) in rows.into_iter().enumerate() {
        let mut code = Vec::new();
        mov(&mut code, 0, number);
        for argument in [7, 6, 2, 10, 8, 9] {
            mov(&mut code, argument, 0);
        }
        code.extend_from_slice(&encoding);
        code.extend_from_slice(&[0x48, 0xc7, 0x04, 0x25]); // MOV qword [DATA],1.
        code.extend_from_slice(&(DATA as u32).to_le_bytes());
        code.extend_from_slice(&1_u32.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x0b]);
        let image = directory.image(&format!("denied-{index}"), &code, false, None);
        let mut session = image.launch();
        let pid = session.pid();
        let handle = pidfd(pid);
        let event = exec_exit(&mut session);
        assert_eq!(
            session
                .read_memory(event.stop_token().unwrap(), BASE, 2 * PAGE)
                .unwrap(),
            image.bytes[..2 * PAGE]
        );
        assert_eq!(
            session
                .read_memory(event.stop_token().unwrap(), DATA, 8)
                .unwrap(),
            [0; 8]
        );
        release(&mut session, &event);
        if native_abi {
            let entry = session.next_event(TIMEOUT).unwrap();
            assert!(
                matches!(entry.kind, DynamicEventKind::SyscallEntry { number: actual, arguments: [0, 0, 0, 0, 0, 0] } if actual == number)
            );
            assert_eq!(
                session
                    .read_memory(entry.stop_token().unwrap(), DATA, 8)
                    .unwrap(),
                [0; 8]
            );
            assert_eq!(
                session
                    .read_memory(entry.stop_token().unwrap(), ENTRY, code.len())
                    .unwrap(),
                code
            );
            assert!(matches!(
                session.resume(entry.stop_token().unwrap(), DynamicResume::Continue),
                Err(LaunchError::Invalid(
                    "dynamic creation and later exec are not yet qualified"
                ))
            ));
        } else {
            assert!(matches!(
                session.next_event(TIMEOUT),
                Err(LaunchError::Invalid(_))
            ));
        }
        assert!(session.next_event(TIMEOUT).is_err());
        finish(session, &handle, pid); // Exactly one reaped child; no hidden fork.
        assert_eq!(fs::read(image.path).unwrap(), image.bytes);
    }
}
