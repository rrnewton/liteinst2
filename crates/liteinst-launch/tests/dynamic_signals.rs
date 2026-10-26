#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! These hand-encoded original ELFs also run as ordinary, untraced children.
//! The oracle does not use a production decoder, stop classifier, signal router,
//! or register transition. Entire handler records and continuation bytes compare
//! exactly; no sender identity, payload, mask or stack address is normalized.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use liteinst_launch::{
    DynamicEvent, DynamicEventKind, DynamicResume, DynamicSession, DynamicStop, LaunchCommand,
};

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const DATA: u64 = 0x600000;
const STACK: u64 = DATA + 16 * PAGE as u64 - 64;
const ALT_START: u64 = DATA + 4 * PAGE as u64;
const ALT_SIZE: u64 = 8 * PAGE as u64;
const READY: u64 = DATA + 0x80;
const AFTER: u64 = DATA + 0x88;
const RECORD: u64 = DATA + 0x100;
const RECORD_LEN: usize = 144; // siginfo[128], handler RSP, exact kernel mask.
const READ_RESULT: u64 = DATA + 0x200;
const READ_BYTE: u64 = READ_RESULT + 8;
const READY_VALUE: u64 = 0x1122334455667788;
const AFTER_VALUE: u64 = 0x8877665544332211;
const PAYLOAD_BYTE: u8 = 0x5a;
const TIMEOUT: Duration = Duration::from_secs(3);
const SA_RESTORER: u64 = 0x04000000;
static NEXT: AtomicUsize = AtomicUsize::new(0);
// Also excludes writable fixture FDs and inherited pipe FDs from another test's
// fork. The applications themselves run normally after their explicit release.
static TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
enum Program {
    Queued,
    JobControl,
    Read { restart: bool, altstack: bool },
}

impl Program {
    fn signal(self) -> Option<i32> {
        match self {
            Self::Queued => Some(libc::SIGRTMIN()),
            Self::JobControl => None,
            Self::Read { .. } => Some(libc::SIGUSR1),
        }
    }

    fn exit_code(self) -> i32 {
        if matches!(self, Self::JobControl) {
            37
        } else {
            0
        }
    }
}

struct Fixture {
    directory: PathBuf,
    executable: PathBuf,
    program: Program,
    kill_return: u64,
}

impl Fixture {
    fn new(program: Program, read_fd: Option<i32>) -> Self {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "dynamic-signals-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(directory.parent().unwrap()).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = directory.join("fixture");
        let handler = BASE + PAGE as u64 + 0x500;
        let restorer = BASE + PAGE as u64 + 0x800;
        let failure = BASE + PAGE as u64 + 0x900;
        let mut image = vec![0_u8; 3 * PAGE];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut image, 16, 2);
        put16(&mut image, 18, 62);
        put32(&mut image, 20, 1);
        put64(&mut image, 24, BASE + PAGE as u64);
        put64(&mut image, 32, 64);
        put16(&mut image, 52, 64);
        put16(&mut image, 54, 56);
        put16(&mut image, 56, 3);
        put32(&mut image, 64, 1);
        put32(&mut image, 68, 5);
        put64(&mut image, 80, BASE);
        put64(&mut image, 96, (2 * PAGE) as u64);
        put64(&mut image, 104, (2 * PAGE) as u64);
        put64(&mut image, 112, PAGE as u64);
        put32(&mut image, 120, 1);
        put32(&mut image, 124, 6);
        put64(&mut image, 128, (2 * PAGE) as u64);
        put64(&mut image, 136, DATA);
        put64(&mut image, 152, PAGE as u64);
        put64(&mut image, 160, (16 * PAGE) as u64);
        put64(&mut image, 168, PAGE as u64);
        put32(&mut image, 176, 0x6474e551);
        put32(&mut image, 180, 6);
        put64(&mut image, 224, 16);

        let flags = SA_RESTORER
            | libc::SA_SIGINFO as u64
            | match program {
                Program::Read { restart, altstack } => {
                    (if restart { libc::SA_RESTART as u64 } else { 0 })
                        | (if altstack { libc::SA_ONSTACK as u64 } else { 0 })
                }
                _ => 0,
            };
        for (offset, value) in [(0, handler), (8, flags), (16, restorer), (24, 0)] {
            put64(&mut image, 2 * PAGE + offset, value);
        }
        put64(&mut image, 2 * PAGE + 0x60, ALT_START);
        put64(&mut image, 2 * PAGE + 0x70, ALT_SIZE);
        put64(&mut image, 2 * PAGE + 0x80, READY_VALUE);

        let mut code = Assembly::new(BASE + PAGE as u64, failure);
        code.bytes(&[0x48, 0x8b, 0x74, 0x24, 0x10]); // RSI = argv[1].
        code.mov(4, STACK);
        code.mov(0, libc::SYS_openat as u64);
        code.mov(7, libc::AT_FDCWD as i64 as u64);
        code.mov(2, (libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL) as u64);
        code.mov(10, 0o600);
        code.syscall();
        code.bytes(&[0x48, 0x85, 0xc0]); // TEST RAX,RAX.
        code.branch_failure(0x88); // JS.
        code.bytes(&[0x49, 0x89, 0xc4]); // R12 = result file descriptor.
        code.mov(0, libc::SYS_rt_sigprocmask as u64);
        code.mov(7, libc::SIG_SETMASK as u64);
        code.mov(6, DATA + 0x40); // Empty eight-byte kernel mask.
        code.mov(2, 0);
        code.mov(10, 8);
        code.syscall();
        code.expect_rax(0);
        if let Some(signal) = program.signal() {
            code.mov(0, libc::SYS_rt_sigaction as u64);
            code.mov(7, signal as u64);
            code.mov(6, DATA);
            code.mov(2, 0);
            code.mov(10, 8);
            code.syscall();
            code.expect_rax(0);
        }
        if matches!(program, Program::Read { altstack: true, .. }) {
            code.mov(0, libc::SYS_sigaltstack as u64);
            code.mov(7, DATA + 0x60);
            code.mov(6, 0);
            code.syscall();
            code.expect_rax(0);
        }
        code.write(READY, 8);
        code.mov(0, libc::SYS_getpid as u64);
        code.syscall();
        code.bytes(&[0x48, 0x89, 0xc7]); // RDI = this child, never the host group.
        code.mov(0, libc::SYS_kill as u64);
        code.mov(6, libc::SIGSTOP as u64);
        code.syscall();
        let kill_return = code.pc();
        code.expect_rax(0);
        if matches!(program, Program::Read { .. }) {
            code.mov(0, libc::SYS_read as u64);
            code.mov(7, read_fd.unwrap() as u64);
            code.mov(6, READ_BYTE);
            code.mov(2, 1);
            code.syscall();
            code.mov(3, READ_RESULT);
            code.bytes(&[0x48, 0x89, 0x03]); // Store the actual kernel return.
            code.write(READ_RESULT, 9);
        } else {
            code.mov(0, AFTER_VALUE);
            code.mov(3, AFTER);
            code.bytes(&[0x48, 0x89, 0x03]);
            code.write(AFTER, 8);
        }
        code.exit(program.exit_code());
        assert!(code.data.len() < 0x500);
        image[PAGE..PAGE + code.data.len()].copy_from_slice(&code.data);

        let mut code = Assembly::new(handler, failure);
        code.bytes(&[0xfc]); // CLD; the incoming signal ABI supplies RSI=siginfo.
        code.mov(7, RECORD);
        code.mov(1, 16);
        code.bytes(&[0xf3, 0x48, 0xa5]); // Copy every siginfo byte, not a projection.
        code.mov(3, RECORD + 128);
        code.bytes(&[0x48, 0x89, 0x23]); // Handler RSP before any PUSH/CALL.
        code.mov(0, libc::SYS_rt_sigprocmask as u64);
        code.mov(7, libc::SIG_SETMASK as u64);
        code.mov(6, 0);
        code.mov(2, RECORD + 136);
        code.mov(10, 8);
        code.syscall();
        code.expect_rax(0);
        code.write(RECORD, RECORD_LEN as u32);
        code.bytes(&[0xc3]); // RET to the kernel-provided restorer frame.
        assert!(code.data.len() < 0x300);
        image[PAGE + 0x500..PAGE + 0x500 + code.data.len()].copy_from_slice(&code.data);
        let mut code = Assembly::new(restorer, failure);
        code.mov(0, libc::SYS_rt_sigreturn as u64);
        code.syscall();
        code.bytes(&[0x0f, 0x0b]);
        image[PAGE + 0x800..PAGE + 0x800 + code.data.len()].copy_from_slice(&code.data);
        let mut code = Assembly::new(failure, failure);
        code.exit(99);
        image[PAGE + 0x900..PAGE + 0x900 + code.data.len()].copy_from_slice(&code.data);

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&executable)
            .unwrap();
        file.write_all(&image).unwrap();
        drop(file);
        Self {
            directory,
            executable,
            program,
            kill_return,
        }
    }

    fn output(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    fn launch(&self, output: &Path) -> DynamicSession {
        let mut command = LaunchCommand::new(&self.executable);
        command.args.push(output.as_os_str().to_owned());
        DynamicSession::launch(&command, TIMEOUT).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct Assembly {
    start: u64,
    failure: u64,
    data: Vec<u8>,
}

impl Assembly {
    fn new(start: u64, failure: u64) -> Self {
        Self {
            start,
            failure,
            data: Vec::new(),
        }
    }
    fn pc(&self) -> u64 {
        self.start + self.data.len() as u64
    }
    fn bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }
    fn mov(&mut self, register: u8, value: u64) {
        self.bytes(&[
            if register < 8 { 0x48 } else { 0x49 },
            0xb8 + (register & 7),
        ]);
        self.bytes(&value.to_le_bytes());
    }
    fn syscall(&mut self) {
        self.bytes(&[0x0f, 0x05]);
    }
    fn branch_failure(&mut self, condition: u8) {
        self.bytes(&[0x0f, condition]);
        let displacement = i32::try_from(self.failure as i64 - (self.pc() + 4) as i64).unwrap();
        self.bytes(&displacement.to_le_bytes());
    }
    fn expect_rax(&mut self, value: u32) {
        self.bytes(&[0x48, 0x3d]);
        self.bytes(&value.to_le_bytes());
        self.branch_failure(0x85); // JNE.
    }
    fn write(&mut self, address: u64, len: u32) {
        self.mov(0, libc::SYS_write as u64);
        self.bytes(&[0x4c, 0x89, 0xe7]); // RDI = R12, preserving the caller's fd.
        self.mov(6, address);
        self.mov(2, u64::from(len));
        self.syscall();
        self.expect_rax(len);
    }
    fn exit(&mut self, code: i32) {
        self.mov(0, libc::SYS_exit as u64);
        self.mov(7, code as u64);
        self.syscall();
        self.bytes(&[0x0f, 0x0b]);
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

#[repr(C, align(8))]
struct SignalPacket([u8; 128]);

impl SignalPacket {
    fn queued(signal: i32, value: u64) -> Self {
        let mut bytes = [0_u8; 128];
        // Exact Linux x86-64 siginfo layout, independently authored here.
        put32(&mut bytes, 0, signal as u32);
        put32(&mut bytes, 8, libc::SI_QUEUE as u32);
        put32(&mut bytes, 16, std::process::id());
        // SAFETY: getuid has no pointer arguments or ownership side effects.
        put32(&mut bytes, 20, unsafe { libc::getuid() });
        put64(&mut bytes, 24, value);
        Self(bytes)
    }

    fn signal(&self) -> i32 {
        i32::from_le_bytes(self.0[..4].try_into().unwrap())
    }
}

fn pidfd(pid: i32) -> OwnedFd {
    // SAFETY: caller retains this exact unreaped child or held dynamic stop.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0, "pidfd_open: {}", io::Error::last_os_error());
    // SAFETY: a successful syscall returned one newly owned descriptor.
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

fn send_signal(handle: &OwnedFd, signal: i32, packet: Option<&SignalPacket>) {
    let pointer = packet.map_or(std::ptr::null(), |info| info.0.as_ptr());
    // SAFETY: the stable handle pins the intended child; packet is initialized
    // and aligned for the exact 128-byte native siginfo ABI, or is null.
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                handle.as_raw_fd(),
                signal,
                pointer,
                0,
            )
        },
        0,
        "pidfd_send_signal: {}",
        io::Error::last_os_error()
    );
}

fn is_terminal(handle: &OwnedFd) -> bool {
    let mut poll = libc::pollfd {
        fd: handle.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll points to one initialized descriptor record and never waits.
    let count = unsafe { libc::poll(&raw mut poll, 1, 0) };
    assert!(count >= 0);
    count == 1 && poll.revents & libc::POLLIN != 0
}

fn assert_reaped(handle: &OwnedFd) {
    assert!(is_terminal(handle));
    // SAFETY: the stable pidfd cannot name a reused PID; WNOWAIT never consumes
    // a status, including if an assertion exposes an incomplete owner cleanup.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            handle.as_raw_fd() as u32,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
        )
    };
    assert_eq!(result, -1);
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

struct Native {
    child: Child,
    handle: Option<OwnedFd>,
    reaped: bool,
}

impl Native {
    fn launch(fixture: &Fixture, output: &Path) -> Self {
        let child = Command::new(&fixture.executable)
            .arg(output)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Cleanup ownership precedes the fallible pidfd operation.
        let mut native = Self {
            child,
            handle: None,
            reaped: false,
        };
        native.handle = Some(pidfd(native.pid()));
        native
    }
    fn pid(&self) -> i32 {
        self.child.id() as i32
    }
    fn handle(&self) -> &OwnedFd {
        self.handle.as_ref().unwrap()
    }
    fn wait(&mut self, until: Instant) -> i32 {
        loop {
            let mut status = 0;
            // SAFETY: this observer owns this particular unreaped child; no
            // production tracer or global wait participates in the oracle.
            let result = unsafe {
                libc::waitpid(self.pid(), &raw mut status, libc::WNOHANG | libc::WUNTRACED)
            };
            if result == self.pid() {
                self.reaped = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                return status;
            }
            if result == -1 {
                let error = io::Error::last_os_error();
                self.reaped = error.raw_os_error() == Some(libc::ECHILD);
                assert_eq!(error.raw_os_error(), Some(libc::EINTR));
            }
            assert!(Instant::now() < until, "untraced native wait deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn ready(&mut self, output: &Path, until: Instant) {
        let status = self.wait(until);
        assert!(
            libc::WIFSTOPPED(status),
            "native readiness status {status:#x}"
        );
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        assert_eq!(fs::read(output).unwrap(), READY_VALUE.to_le_bytes());
    }
    fn finish(&mut self, code: i32, until: Instant) {
        let status = self.wait(until);
        assert!(
            libc::WIFEXITED(status),
            "native terminal status {status:#x}"
        );
        assert_eq!(libc::WEXITSTATUS(status), code);
        assert_reaped(self.handle());
    }
}

impl Drop for Native {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // SAFETY: either a stable pidfd or this still exclusively owned,
        // unreaped child supplies signalling authority. No global wait occurs.
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
            // SAFETY: this specific child remains owned until terminal wait.
            let result = unsafe { libc::waitpid(self.pid(), &raw mut status, libc::WNOHANG) };
            if result == self.pid() {
                self.reaped = true;
                break;
            }
            if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                self.reaped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(self.reaped, "native signal fixture cleanup deadline");
    }
}

fn remaining(until: Instant) -> Duration {
    let remaining = until.saturating_duration_since(Instant::now());
    assert!(!remaining.is_zero(), "signal fixture overall deadline");
    remaining
}

fn resume(session: &mut DynamicSession, event: &DynamicEvent, action: DynamicResume) {
    session.resume(event.stop_token().unwrap(), action).unwrap();
}

fn group_stop(session: &mut DynamicSession, fixture: &Fixture, until: Instant) -> DynamicStop {
    let initial = session.initial_event().clone();
    assert!(matches!(initial.kind, DynamicEventKind::Exec { .. }));
    resume(session, &initial, DynamicResume::Continue);
    let mut delivered_stop = 0;
    for _ in 0..128 {
        let event = session.next_event(remaining(until)).unwrap();
        assert_eq!(event.tid, session.pid());
        match &event.kind {
            DynamicEventKind::SyscallEntry { .. } | DynamicEventKind::SyscallExit { .. } => {
                resume(session, &event, DynamicResume::Continue);
            }
            DynamicEventKind::SignalDelivery(info) => {
                assert_eq!(info.signal(), libc::SIGSTOP);
                assert_eq!(info.code(), libc::SI_USER);
                assert_eq!(info.sender_pid(), Some(session.pid()));
                delivered_stop += 1;
                resume(session, &event, DynamicResume::DeliverOriginal);
            }
            DynamicEventKind::GroupStop { signal } => {
                assert_eq!(*signal, libc::SIGSTOP);
                assert_eq!(delivered_stop, 1);
                let stop = event.stop_token().unwrap();
                let registers = session.read_registers(stop).unwrap();
                assert_eq!(registers.rsp, STACK);
                assert_eq!(registers.rip, fixture.kill_return);
                assert_eq!(session.signal_mask(stop).unwrap(), 0);
                assert_eq!(session.read_memory(stop, AFTER, 8).unwrap(), [0; 8]);
                return stop.clone();
            }
            _ => panic!("unexpected setup event: {event:?}"),
        }
    }
    panic!("group-stop setup exceeded its finite event budget");
}

fn listen(session: &mut DynamicSession, stop: &DynamicStop, handle: &OwnedFd, output: &Path) {
    session.resume(stop, DynamicResume::Listen).unwrap();
    // LISTEN must not authorize the post-stop application instruction. This is
    // also checked by exact continuation output after an actual SIGCONT below.
    std::thread::sleep(Duration::from_millis(20));
    assert!(!is_terminal(handle));
    assert_eq!(fs::read(output).unwrap(), READY_VALUE.to_le_bytes());
}

fn finish(session: DynamicSession, handle: &OwnedFd, pid: i32) {
    let cleanup = session.terminate(TIMEOUT).unwrap();
    assert_eq!(cleanup.reaped, vec![pid]);
    assert_reaped(handle);
}

fn verify_record(record: &[u8], packet: &SignalPacket, altstack: bool) {
    assert_eq!(record.len(), RECORD_LEN);
    assert_eq!(&record[..128], &packet.0);
    let stack = u64::from_le_bytes(record[128..136].try_into().unwrap());
    assert_eq!(stack % 16, 8);
    if altstack {
        assert!((ALT_START..ALT_START + ALT_SIZE).contains(&stack));
    } else {
        assert!((DATA + 12 * PAGE as u64..STACK).contains(&stack));
    }
    assert_eq!(
        u64::from_le_bytes(record[136..144].try_into().unwrap()),
        1_u64 << (packet.signal() - 1)
    );
}

fn assert_delivery(info: &liteinst_launch::DynamicSignalInfo, packet: &SignalPacket) {
    assert_eq!(info.raw_bytes(), &packet.0);
    assert_eq!(info.signal(), packet.signal());
    assert_eq!(info.code(), libc::SI_QUEUE);
    assert_eq!(info.errno(), 0);
    assert_eq!(info.sender_pid(), Some(std::process::id() as i32));
    // SAFETY: getuid has no pointer arguments or ownership side effects.
    assert_eq!(info.sender_uid(), Some(unsafe { libc::getuid() }));
    assert_eq!(
        info.value(),
        Some(u64::from_le_bytes(packet.0[24..32].try_into().unwrap()))
    );
    assert_eq!(info.fault_address(), None);
}

#[test]
fn queued_realtime_payloads_and_handler_frames_match_untraced_native_exactly() {
    let _serial = TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new(Program::Queued, None);
    let packets = [
        SignalPacket::queued(libc::SIGRTMIN(), 0x1020304050607080),
        SignalPacket::queued(libc::SIGRTMIN(), 0xfedcba9876543210),
    ];
    let native_output = fixture.output("native-output");
    let mut native = Native::launch(&fixture, &native_output);
    let until = Instant::now() + TIMEOUT;
    native.ready(&native_output, until);
    for packet in &packets {
        send_signal(native.handle(), packet.signal(), Some(packet));
    }
    send_signal(native.handle(), libc::SIGCONT, None);
    native.finish(0, until);
    let expected = fs::read(&native_output).unwrap();
    assert_eq!(expected.len(), 16 + 2 * RECORD_LEN);
    assert_eq!(&expected[..8], &READY_VALUE.to_le_bytes());
    for (index, packet) in packets.iter().enumerate() {
        verify_record(
            &expected[8 + index * RECORD_LEN..8 + (index + 1) * RECORD_LEN],
            packet,
            false,
        );
    }
    assert_eq!(&expected[8 + 2 * RECORD_LEN..], &AFTER_VALUE.to_le_bytes());

    let output = fixture.output("dynamic-output");
    let mut session = fixture.launch(&output);
    let pid = session.pid();
    let handle = pidfd(pid);
    let until = Instant::now() + TIMEOUT;
    let stop = group_stop(&mut session, &fixture, until);
    listen(&mut session, &stop, &handle, &output);
    for packet in &packets {
        send_signal(&handle, packet.signal(), Some(packet));
    }
    send_signal(&handle, libc::SIGCONT, None);
    let mut deliveries = 0;
    let mut continued = 0;
    let mut handler_writes = 0;
    let mut returned = 0;
    let mut exited = false;
    for _ in 0..128 {
        let event = session.next_event(remaining(until)).unwrap();
        match &event.kind {
            DynamicEventKind::GroupContinued => {
                continued += 1;
                resume(&mut session, &event, DynamicResume::Continue);
            }
            DynamicEventKind::SignalDelivery(info) => {
                if info.signal() == libc::SIGCONT {
                    assert_eq!(info.code(), libc::SI_USER);
                    assert_eq!(info.sender_pid(), Some(std::process::id() as i32));
                } else {
                    assert!(deliveries < packets.len());
                    assert_delivery(info, &packets[deliveries]);
                    assert_eq!(session.signal_mask(event.stop_token().unwrap()).unwrap(), 0);
                    deliveries += 1;
                }
                resume(&mut session, &event, DynamicResume::DeliverOriginal);
            }
            DynamicEventKind::SyscallEntry { number, arguments } => {
                if *number == libc::SYS_write as u64 && arguments[1] == RECORD {
                    assert_eq!(arguments[2], RECORD_LEN as u64);
                    assert!(handler_writes < packets.len());
                    let stop = event.stop_token().unwrap();
                    verify_record(
                        &session.read_memory(stop, RECORD, RECORD_LEN).unwrap(),
                        &packets[handler_writes],
                        false,
                    );
                    handler_writes += 1;
                }
                if *number == libc::SYS_rt_sigreturn as u64 {
                    returned += 1;
                }
                resume(&mut session, &event, DynamicResume::Continue);
            }
            DynamicEventKind::SyscallExit { .. } => {
                resume(&mut session, &event, DynamicResume::Continue)
            }
            DynamicEventKind::Exited { code } => {
                assert_eq!(*code, 0);
                exited = true;
                break;
            }
            _ => panic!("unexpected queued-signal event: {event:?}"),
        }
    }
    assert!(exited);
    assert_eq!(continued, 1);
    assert_eq!(deliveries, 2);
    assert_eq!(handler_writes, 2);
    assert_eq!(returned, 2);
    assert_eq!(fs::read(output).unwrap(), expected);
    finish(session, &handle, pid);
}

#[test]
fn listen_keeps_sigstop_until_real_sigcont_and_matches_native_continuation() {
    let _serial = TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new(Program::JobControl, None);
    let native_output = fixture.output("native-output");
    let mut native = Native::launch(&fixture, &native_output);
    let until = Instant::now() + TIMEOUT;
    native.ready(&native_output, until);
    std::thread::sleep(Duration::from_millis(20));
    assert!(!is_terminal(native.handle()));
    assert_eq!(fs::read(&native_output).unwrap(), READY_VALUE.to_le_bytes());
    send_signal(native.handle(), libc::SIGCONT, None);
    native.finish(fixture.program.exit_code(), until);
    let expected = [READY_VALUE.to_le_bytes(), AFTER_VALUE.to_le_bytes()].concat();
    assert_eq!(fs::read(native_output).unwrap(), expected);

    let output = fixture.output("dynamic-output");
    let mut session = fixture.launch(&output);
    let pid = session.pid();
    let handle = pidfd(pid);
    let until = Instant::now() + TIMEOUT;
    let stop = group_stop(&mut session, &fixture, until);
    let before = session.read_registers(&stop).unwrap();
    let xstate = session.read_xstate(&stop).unwrap();
    assert_eq!(session.read_registers(&stop).unwrap(), before);
    assert_eq!(session.read_xstate(&stop).unwrap(), xstate);
    listen(&mut session, &stop, &handle, &output);
    send_signal(&handle, libc::SIGCONT, None);
    let mut continued = 0;
    let mut delivered_cont = 0;
    let mut exited = false;
    for _ in 0..64 {
        let event = session.next_event(remaining(until)).unwrap();
        match &event.kind {
            DynamicEventKind::GroupContinued => {
                continued += 1;
                let token = event.stop_token().unwrap();
                assert_eq!(session.read_registers(token).unwrap(), before);
                assert_eq!(session.read_xstate(token).unwrap(), xstate);
                assert_eq!(session.read_memory(token, AFTER, 8).unwrap(), [0; 8]);
                resume(&mut session, &event, DynamicResume::Continue);
            }
            DynamicEventKind::SignalDelivery(info) => {
                assert_eq!(info.signal(), libc::SIGCONT);
                assert_eq!(info.code(), libc::SI_USER);
                assert_eq!(info.sender_pid(), Some(std::process::id() as i32));
                delivered_cont += 1;
                resume(&mut session, &event, DynamicResume::DeliverOriginal);
            }
            DynamicEventKind::SyscallEntry { .. } | DynamicEventKind::SyscallExit { .. } => {
                resume(&mut session, &event, DynamicResume::Continue);
            }
            DynamicEventKind::Exited { code } => {
                assert_eq!(*code, 37);
                exited = true;
                break;
            }
            _ => panic!("unexpected job-control event: {event:?}"),
        }
    }
    assert!(exited);
    assert_eq!(continued, 1);
    assert_eq!(delivered_cont, 1);
    assert_eq!(fs::read(output).unwrap(), expected);
    finish(session, &handle, pid);
}

struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
}

impl Pipe {
    fn new() -> Self {
        let mut pair = [-1; 2];
        // SAFETY: pair contains two writable descriptor slots.
        assert_eq!(
            unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: both successful pipe2 results are adopted exactly once.
        let pipe = unsafe {
            Self {
                read: OwnedFd::from_raw_fd(pair[0]),
                write: OwnedFd::from_raw_fd(pair[1]),
            }
        };
        // Only the read end is deliberately inherited. Tests are serialized and
        // each child exits/reaps before the next launch using this same pipe.
        assert_eq!(
            unsafe { libc::fcntl(pipe.read.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        pipe
    }
    fn release(&self) {
        let byte = PAYLOAD_BYTE;
        // SAFETY: one initialized byte is written to this owned pipe. The parent
        // retains its read end, so a premature child exit cannot raise SIGPIPE.
        assert_eq!(
            unsafe { libc::write(self.write.as_raw_fd(), (&raw const byte).cast(), 1) },
            1
        );
    }
}

fn wait_blocked_read(pid: i32, handle: &OwnedFd, read_fd: i32, until: Instant) {
    loop {
        assert!(!is_terminal(handle), "child exited before blocking read");
        let text = fs::read_to_string(format!("/proc/{pid}/syscall")).unwrap();
        let mut fields = text.split_whitespace();
        if fields.next() == Some("0") {
            let fd = fields.next().unwrap().trim_start_matches("0x");
            if u64::from_str_radix(fd, 16).unwrap() == read_fd as u64 {
                return;
            }
        }
        assert!(
            Instant::now() < until,
            "owned child never entered its blocking read"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn wait_handler_output(output: &Path, handle: &OwnedFd, until: Instant) {
    loop {
        if fs::metadata(output).unwrap().len() >= (8 + RECORD_LEN) as u64 {
            return;
        }
        assert!(
            !is_terminal(handle),
            "native handler exited before writing its record"
        );
        assert!(Instant::now() < until, "native handler output deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn blocked_read(restart: bool, altstack: bool) {
    let _serial = TEST_LOCK.lock().unwrap();
    let native_pipe = Pipe::new();
    let fixture = Fixture::new(
        Program::Read { restart, altstack },
        Some(native_pipe.read.as_raw_fd()),
    );
    let packet = SignalPacket::queued(libc::SIGUSR1, 0x13579bdf2468ace0);
    let native_output = fixture.output("native-output");
    let mut native = Native::launch(&fixture, &native_output);
    let until = Instant::now() + TIMEOUT;
    native.ready(&native_output, until);
    send_signal(native.handle(), libc::SIGCONT, None);
    wait_blocked_read(
        native.pid(),
        native.handle(),
        native_pipe.read.as_raw_fd(),
        until,
    );
    send_signal(native.handle(), packet.signal(), Some(&packet));
    wait_handler_output(&native_output, native.handle(), until);
    if restart {
        native_pipe.release();
    }
    native.finish(0, until);
    let expected = fs::read(&native_output).unwrap();
    assert_eq!(expected.len(), 8 + RECORD_LEN + 9);
    assert_eq!(&expected[..8], &READY_VALUE.to_le_bytes());
    verify_record(&expected[8..8 + RECORD_LEN], &packet, altstack);
    let result = i64::from_le_bytes(
        expected[8 + RECORD_LEN..16 + RECORD_LEN]
            .try_into()
            .unwrap(),
    );
    assert_eq!(result, if restart { 1 } else { -i64::from(libc::EINTR) });
    assert_eq!(
        expected[16 + RECORD_LEN],
        if restart { PAYLOAD_BYTE } else { 0 }
    );

    // The same empty pipe and immutable ELF are reused after native consumption.
    let output = fixture.output("dynamic-output");
    let mut session = fixture.launch(&output);
    let pid = session.pid();
    let handle = pidfd(pid);
    let until = Instant::now() + TIMEOUT;
    let stop = group_stop(&mut session, &fixture, until);
    listen(&mut session, &stop, &handle, &output);
    send_signal(&handle, libc::SIGCONT, None);
    let mut continued = 0;
    let mut read_entries = 0;
    let mut read_restarts = 0;
    let mut deliveries = 0;
    let mut handler_writes = 0;
    let mut sigreturns = 0;
    let mut last_entry = None;
    let mut exited = false;
    for _ in 0..128 {
        let event = session.next_event(remaining(until)).unwrap();
        match &event.kind {
            DynamicEventKind::GroupContinued => {
                continued += 1;
                resume(&mut session, &event, DynamicResume::Continue);
            }
            DynamicEventKind::SignalDelivery(info) => {
                if info.signal() == libc::SIGCONT {
                    assert_eq!(info.code(), libc::SI_USER);
                    assert_eq!(info.sender_pid(), Some(std::process::id() as i32));
                } else {
                    assert_delivery(info, &packet);
                    assert_eq!(session.signal_mask(event.stop_token().unwrap()).unwrap(), 0);
                    deliveries += 1;
                }
                resume(&mut session, &event, DynamicResume::DeliverOriginal);
            }
            DynamicEventKind::SyscallEntry { number, arguments } => {
                last_entry = Some((*number, *arguments));
                if *number == libc::SYS_read as u64 {
                    read_entries += 1;
                    assert_eq!(
                        &arguments[..3],
                        &[native_pipe.read.as_raw_fd() as u64, READ_BYTE, 1]
                    );
                    resume(&mut session, &event, DynamicResume::Continue);
                    if read_entries == 1 {
                        wait_blocked_read(pid, &handle, native_pipe.read.as_raw_fd(), until);
                        send_signal(&handle, packet.signal(), Some(&packet));
                    }
                } else {
                    if *number == libc::SYS_write as u64 && arguments[1] == RECORD {
                        assert_eq!(arguments[2], RECORD_LEN as u64);
                        verify_record(
                            &session
                                .read_memory(event.stop_token().unwrap(), RECORD, RECORD_LEN)
                                .unwrap(),
                            &packet,
                            altstack,
                        );
                        handler_writes += 1;
                    }
                    if *number == libc::SYS_rt_sigreturn as u64 {
                        sigreturns += 1;
                    }
                    resume(&mut session, &event, DynamicResume::Continue);
                }
            }
            DynamicEventKind::SyscallExit { result, is_error } => {
                if let Some((number, arguments)) = last_entry.take() {
                    if number == libc::SYS_read as u64 && *result == -512 {
                        // Linux ERESTARTSYS is retained as an actual syscall-exit
                        // event. It is not substituted with final user EINTR.
                        assert!(*is_error);
                        read_restarts += 1;
                    }
                    if number == libc::SYS_write as u64 && arguments[1] == RECORD {
                        assert_eq!(*result, RECORD_LEN as i64);
                        assert!(!is_error);
                        assert_eq!(
                            fs::metadata(&output).unwrap().len(),
                            (8 + RECORD_LEN) as u64
                        );
                        if restart {
                            native_pipe.release();
                        }
                    }
                }
                resume(&mut session, &event, DynamicResume::Continue);
            }
            DynamicEventKind::Exited { code } => {
                assert_eq!(*code, 0);
                exited = true;
                break;
            }
            _ => panic!("unexpected blocked-read event: {event:?}"),
        }
    }
    assert!(exited);
    assert_eq!(continued, 1);
    assert_eq!(deliveries, 1);
    assert_eq!(handler_writes, 1);
    assert_eq!(sigreturns, 1);
    assert_eq!(read_restarts, 1);
    assert_eq!(read_entries, if restart { 2 } else { 1 });
    assert_eq!(fs::read(output).unwrap(), expected);
    finish(session, &handle, pid);
}

#[test]
fn blocked_read_without_restart_preserves_native_eintr_and_handler_state() {
    blocked_read(false, false);
}

#[test]
fn blocked_read_with_restart_and_altstack_preserves_native_result_and_handler_state() {
    blocked_read(true, true);
}
