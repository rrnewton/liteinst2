#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! The oracle uses raw ptrace on the original ELF and never creates a
//! production checkpoint, island, gate, or syscall-return bridge. Linux i386
//! numbers/arguments and complete state transitions are asserted independently.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use liteinst_admission::scan::{Policy, SiteClass};
use liteinst_launch::gate::{ImageFacts, SelectedEvent, SelectedExecution, SelectedPageGate};
use liteinst_launch::selected::{
    InstructionProvider, NativeProvider, ProviderDecision, ScriptEntry, ScriptedProvider,
    SelectedArguments, SelectedInput, SelectedResult, SemanticsError, SyscallAbi, SyscallAliases,
    SyscallResult, decode,
};
use liteinst_launch::{
    ExecCheckpoint, LaunchCommand, LaunchError, NativeSyscallOutcome, ProcessEvent,
    RegisterSnapshot, StoppedProcess,
};

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const DATA: u64 = 0x600000;
const STACK: u64 = DATA + PAGE as u64 - 64;
const FLAGS: u64 = 0xed7; // CF/PF/AF/ZF/SF/OF/DF set, plus IF and reserved bit 1.
const HIGH_NUMBER: u64 = 0xa1b2_c3d4_0000_0000;
const TIMEOUT: Duration = Duration::from_secs(3);
static NEXT: AtomicUsize = AtomicUsize::new(0);
// A fork must not inherit another test's writable executable-file descriptor.
static FORK_LOCK: Mutex<()> = Mutex::new(());

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    image: Vec<u8>,
    site: u64,
    terminal: u64,
    encoding: Vec<u8>,
    number: u64,
}

impl Fixture {
    fn new(encoding: &[u8], number: u64) -> Self {
        Self::build(encoding, number, 0xcc)
    }

    fn page(encoding: &[u8], number: u64) -> Self {
        Self::build(encoding, number, 0x90)
    }

    fn build(encoding: &[u8], number: u64, marker: u8) -> Self {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "native-int80-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(directory.parent().unwrap()).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("fixture");
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
        put64(&mut image, 160, PAGE as u64);
        put64(&mut image, 168, PAGE as u64);
        put32(&mut image, 176, 0x6474_e551);
        put32(&mut image, 180, 6);
        put64(&mut image, 224, 16);
        let mut code = Vec::new();
        mov64(&mut code, 4, STACK);
        for (offset, value) in [
            (0_u8, 0x11223344_u32),
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
                mov64(
                    &mut code,
                    register,
                    0x1234_5678_9000_0000 + u64::from(register),
                );
            }
        }
        mov64(&mut code, 0, number);
        code.push(0x68);
        code.extend_from_slice(&(FLAGS as u32).to_le_bytes());
        code.extend_from_slice(&[0x9d, marker]); // POPFQ; marker or original NOP.
        let site = BASE + PAGE as u64 + code.len() as u64;
        code.extend_from_slice(encoding);
        // A visible successor write proves the bridge never executes the next
        // application instruction. It runs exactly once after explicit resume.
        let next = BASE + PAGE as u64 + code.len() as u64 + 10;
        code.extend_from_slice(&[0xc7, 0x05]);
        code.extend_from_slice(&(i32::try_from(DATA as i64 - next as i64).unwrap()).to_le_bytes());
        code.extend_from_slice(&0x12345678_u32.to_le_bytes());
        let terminal = BASE + PAGE as u64 + code.len() as u64;
        code.extend_from_slice(&[0x0f, 0x0b]);
        image[PAGE..PAGE + code.len()].copy_from_slice(&code);
        let _guard = FORK_LOCK.lock().unwrap();
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
            image,
            site,
            terminal,
            encoding: encoding.to_vec(),
            number,
        }
    }

    fn controlled(&self) -> StoppedProcess {
        let checkpoint = {
            let _guard = FORK_LOCK.lock().unwrap();
            ExecCheckpoint::launch(&LaunchCommand::new(&self.path), TIMEOUT).unwrap()
        };
        let mut process = checkpoint.into_stopped_process(TIMEOUT).unwrap();
        let ProcessEvent::Signal(stop) = process.resume_until_event(TIMEOUT).unwrap() else {
            panic!("fixture did not reach its pre-instruction marker");
        };
        assert_eq!(stop.signal, libc::SIGTRAP);
        assert!(matches!(stop.code, libc::SI_KERNEL | libc::TRAP_BRKPT));
        assert_eq!(stop.instruction_pointer, self.site);
        process
            .hold()
            .unwrap()
            .acknowledge_owned_signal(&stop)
            .unwrap();
        assert_seed(process.read_registers().unwrap(), self.site);
        process
    }

    fn gate<P: InstructionProvider>(&self, provider: P) -> SelectedPageGate<P> {
        assert_eq!(self.image[(self.site - BASE - 1) as usize], 0x90);
        // This closed fixture has one straight-line stream ending at UD2.
        // Decoding supplies census metadata, never oracle state expectations.
        let mut decoder = iced_x86::Decoder::with_ip(
            64,
            &self.image[PAGE..2 * PAGE],
            BASE + PAGE as u64,
            iced_x86::DecoderOptions::NONE,
        );
        let mut heads = std::collections::BTreeSet::new();
        loop {
            let instruction = decoder.decode();
            assert!(!instruction.is_invalid());
            assert!(heads.insert(instruction.ip()));
            if instruction.ip() == self.terminal {
                assert_eq!(instruction.code(), iced_x86::Code::Ud2);
                break;
            }
            assert!(instruction.next_ip() <= self.terminal);
        }
        let checkpoint = {
            let _guard = FORK_LOCK.lock().unwrap();
            ExecCheckpoint::launch(&LaunchCommand::new(&self.path), TIMEOUT).unwrap()
        };
        let mut policy = Policy::default();
        policy.selected.insert(SiteClass::Int80);
        // SAFETY: exclusive immutable private fixture with complete heads,
        // no code readers/aliases, no other tasks or saved resumes. The seeded
        // flags have TF/RF clear; only the declared allowlisted syscall runs.
        unsafe {
            SelectedPageGate::new_with_coverage(
                checkpoint,
                vec![ImageFacts {
                    start: BASE,
                    bytes: self.image[..2 * PAGE].to_vec(),
                    heads,
                }],
                policy,
                self.aliases(),
                provider,
                TIMEOUT,
            )
            .unwrap()
        }
    }

    fn aliases(&self) -> SyscallAliases {
        let mut aliases = SyscallAliases::new();
        // Each finite test row is CD80, 66 CD80, or 48 CD80. Both the
        // prefixed original and its selected suffix get exact declarations.
        assert_eq!(&self.encoding[self.encoding.len() - 2..], &[0xcd, 0x80]);
        for offset in 0..self.encoding.len() - 1 {
            aliases
                .declare(self.site + offset as u64, SyscallAbi::LinuxI386Int80)
                .unwrap();
        }
        aliases
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
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
fn mov64(bytes: &mut Vec<u8>, register: u8, value: u64) {
    bytes.extend_from_slice(&[0x48 | (register >> 3), 0xb8 | (register & 7)]);
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn assert_seed(registers: RegisterSnapshot, pc: u64) {
    assert_eq!(registers.rip, pc);
    assert_eq!(registers.rsp, STACK);
    assert_eq!(registers.eflags, FLAGS);
    assert_eq!(registers.rcx, 0x1234_5678_9000_0001);
    assert_eq!(registers.r11, 0x1234_5678_9000_000b);
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Evidence {
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    stack: Vec<u8>,
    memory: Vec<u8>,
}

impl Evidence {
    fn check_own_pid(mut self, pid: libc::pid_t) -> Self {
        assert_eq!(
            self.registers.rax, pid as u64,
            "single-task getpid/gettid must return this run's exact identity"
        );
        // This is the sole declared cross-run substitution, after asserting
        // both independently known identities. No register output is masked.
        self.registers.rax = 0xfeed;
        self
    }
}

struct Native {
    child: Option<Child>,
    reaped: bool,
}

impl Native {
    fn launch(fixture: &Fixture) -> Self {
        let _guard = FORK_LOCK.lock().unwrap();
        let mut command = Command::new(&fixture.path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: only ptrace and errno access occur after fork before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut native = Self {
            child: Some(command.spawn().unwrap()),
            reaped: false,
        };
        let status = native.wait();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        native.ptrace(
            libc::PTRACE_SETOPTIONS,
            0,
            (libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACESYSGOOD) as usize,
        );
        let marker_pc = fixture.site - 1;
        let original_marker = fixture.image[(marker_pc - BASE) as usize];
        assert!(matches!(original_marker, 0xcc | 0x90));
        if original_marker == 0x90 {
            native.write_byte(marker_pc, 0x90, 0xcc);
        }
        native.ptrace(libc::PTRACE_CONT, 0, 0);
        native.marker(fixture.site, libc::SIGTRAP);
        if original_marker == 0x90 {
            native.write_byte(marker_pc, 0xcc, 0x90);
        }
        assert_seed(native.registers(), fixture.site);
        native
    }

    fn pid(&self) -> libc::pid_t {
        self.child.as_ref().unwrap().id() as libc::pid_t
    }

    fn wait(&mut self) -> i32 {
        assert!(!self.reaped);
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let mut status = 0;
            // SAFETY: this observer owns this exact unreaped child exclusively.
            let result =
                unsafe { libc::waitpid(self.pid(), &mut status, libc::WNOHANG | libc::__WALL) };
            if result == self.pid() {
                self.reaped = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                return status;
            }
            if result == -1 {
                let error = io::Error::last_os_error();
                self.reaped = error.raw_os_error() == Some(libc::ECHILD);
                assert_eq!(
                    error.raw_os_error(),
                    Some(libc::EINTR),
                    "native wait: {error}"
                );
            }
            assert!(
                Instant::now() < deadline,
                "independent native wait deadline"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn ptrace(&self, request: u32, address: usize, data: usize) {
        // SAFETY: request-valid pointers/scalars refer only to this held child.
        assert_ne!(
            unsafe { libc::ptrace(request, self.pid(), address, data) },
            -1,
            "native ptrace {request}: {}",
            io::Error::last_os_error()
        );
    }

    fn registers(&self) -> RegisterSnapshot {
        let mut registers = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
        self.ptrace(libc::PTRACE_GETREGS, 0, registers.as_mut_ptr() as usize);
        // SAFETY: successful GETREGS initialized the complete output.
        unsafe { registers.assume_init() }.into()
    }

    fn write_byte(&self, pc: u64, expected: u8, replacement: u8) {
        let address = pc & !7;
        let offset = (pc - address) as usize;
        let mut bytes: [u8; 8] = self.memory(address, 8).try_into().unwrap();
        assert_eq!(bytes[offset], expected);
        bytes[offset] = replacement;
        self.ptrace(
            libc::PTRACE_POKETEXT,
            address as usize,
            u64::from_le_bytes(bytes) as usize,
        );
        assert_eq!(self.memory(address, 8), bytes);
    }

    fn xstate(&self) -> Vec<u8> {
        let mut bytes = vec![0; 64 * 1024];
        let mut vector = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        self.ptrace(libc::PTRACE_GETREGSET, 0x202, (&raw mut vector) as usize);
        assert!((512..bytes.len()).contains(&vector.iov_len));
        bytes.truncate(vector.iov_len);
        bytes
    }

    fn memory(&self, address: u64, len: usize) -> Vec<u8> {
        assert_eq!(address % 8, 0);
        assert_eq!(len % 8, 0);
        let mut bytes = Vec::new();
        for offset in (0..len).step_by(8) {
            // SAFETY: errno is thread local; PEEKDATA reads the held child only.
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

    fn evidence(&self) -> Evidence {
        Evidence {
            registers: self.registers(),
            xstate: self.xstate(),
            stack: self.memory(STACK, 32),
            memory: self.memory(DATA, PAGE),
        }
    }

    fn marker(&mut self, pc: u64, signal: i32) {
        let status = self.wait();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), signal);
        assert_eq!(status >> 16, 0);
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
        self.ptrace(libc::PTRACE_GETSIGINFO, 0, info.as_mut_ptr() as usize);
        // SAFETY: successful GETSIGINFO initialized the whole output.
        let info = unsafe { info.assume_init() };
        assert_eq!(info.si_signo, signal);
        if signal == libc::SIGTRAP {
            assert!(matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
        } else if signal == libc::SIGILL {
            assert_eq!(info.si_code, 2); // Linux ILL_ILLOPN for original UD2.
        }
        assert_eq!(self.registers().rip, pc);
    }

    fn finish(mut self) {
        let handle = pidfd(self.pid());
        self.child.as_mut().unwrap().kill().unwrap();
        let status = self.wait();
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        assert_reaped(&handle);
    }

    fn syscall(&mut self, fixture: &Fixture) -> Evidence {
        let before = self.evidence();
        assert_eq!(before.registers.rax, fixture.number);
        let number = fixture.number & 0xffff_ffff;
        assert!(number == 20 || number == 224);
        let raw_arguments = [
            before.registers.rbx,
            before.registers.rcx,
            before.registers.rdx,
            before.registers.rsi,
            before.registers.rdi,
            before.registers.rbp,
        ];
        assert!(raw_arguments.iter().all(|value| value >> 32 != 0));
        for operation in [
            libc::PTRACE_SYSCALL_INFO_ENTRY,
            libc::PTRACE_SYSCALL_INFO_EXIT,
        ] {
            self.ptrace(libc::PTRACE_SYSCALL, 0, 0);
            let status = self.wait();
            assert!(libc::WIFSTOPPED(status));
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP | 0x80);
            assert_eq!(status >> 16, 0);
            // SAFETY: the kernel receives initialized writable output storage.
            let mut info: libc::ptrace_syscall_info = unsafe { std::mem::zeroed() };
            let bytes = unsafe {
                libc::ptrace(
                    libc::PTRACE_GET_SYSCALL_INFO,
                    self.pid(),
                    std::mem::size_of_val(&info),
                    &raw mut info,
                )
            };
            assert!(
                bytes
                    >= if operation == libc::PTRACE_SYSCALL_INFO_ENTRY {
                        80
                    } else {
                        33
                    }
            );
            assert_eq!(info.op, operation);
            assert_eq!(info.arch, 0x4000_0003);
            assert_eq!(
                info.instruction_pointer,
                fixture.site + fixture.encoding.len() as u64
            );
            assert_eq!(info.stack_pointer, STACK);
            let mut expected = before.registers;
            expected.rip = fixture.site + fixture.encoding.len() as u64;
            expected.orig_rax = number;
            if operation == libc::PTRACE_SYSCALL_INFO_ENTRY {
                // SAFETY: ENTRY authenticates this initialized union member.
                let entry = unsafe { info.u.entry };
                assert_eq!(entry.nr, number);
                assert_eq!(entry.args, raw_arguments);
                assert_eq!(
                    entry.args.map(|value| value & 0xffff_ffff),
                    raw_arguments.map(|value| value & 0xffff_ffff)
                );
                expected.rax = (-i64::from(libc::ENOSYS)) as u64;
            } else {
                // SAFETY: EXIT authenticates this initialized union member.
                let exit = unsafe { info.u.exit };
                assert_eq!(exit.sval, i64::from(self.pid()));
                assert_eq!(exit.is_error, 0);
                expected.rax = self.pid() as u64;
            }
            let actual = self.evidence();
            assert_eq!(actual.registers, expected);
            assert_eq!(actual.xstate, before.xstate);
            assert_eq!(actual.stack, before.stack);
            assert_eq!(actual.memory, before.memory);
        }
        assert_eq!(self.memory(DATA, 8), [0; 8]);
        self.evidence()
    }
}

impl Drop for Native {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if self.reaped {
            return;
        }
        let _ = child.kill(); // Unreaped exclusive ownership pins this numeric PID.
        let pid = child.id() as libc::pid_t;
        let until = Instant::now() + TIMEOUT;
        while !raw_reaped(pid) {
            if Instant::now() >= until {
                std::thread::spawn(move || {
                    while !raw_reaped(pid) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    drop(child);
                });
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(child); // Raw wait consumed the status; never wait again via Child.
    }
}

fn raw_reaped(pid: libc::pid_t) -> bool {
    let mut status = 0;
    // SAFETY: this exact unreaped child has one cleanup owner, which stops on true.
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
    (result == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)))
        || (result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
}

fn pidfd(pid: libc::pid_t) -> OwnedFd {
    // SAFETY: pid identifies the still-owned, stopped child.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(descriptor >= 0);
    // SAFETY: successful pidfd_open returned one new descriptor.
    unsafe { OwnedFd::from_raw_fd(descriptor as i32) }
}

fn assert_reaped(handle: &OwnedFd) {
    let mut poll = libc::pollfd {
        fd: handle.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: zero-time polling observes only the original pinned incarnation.
    assert_eq!(unsafe { libc::poll(&raw mut poll, 1, 0) }, 1);
    assert_eq!(
        poll.revents & (libc::POLLIN | libc::POLLHUP),
        libc::POLLIN | libc::POLLHUP
    );

    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
    // SAFETY: a stable pidfd cannot target a recycled numeric PID. WNOWAIT also
    // ensures this assertion never consumes a cleanup owner's terminal status.
    let result = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            handle.as_raw_fd() as libc::id_t,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    assert_eq!(result, -1, "child has not been reaped");
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn controlled_evidence(process: &StoppedProcess) -> Evidence {
    Evidence {
        registers: process.read_registers().unwrap(),
        xstate: process.read_xstate().unwrap(),
        stack: process.read_memory(STACK, 32).unwrap(),
        memory: process.read_memory(DATA, PAGE).unwrap(),
    }
}

fn compare_with_corruption_controls(actual: Evidence, expected: Evidence) {
    assert_eq!(actual, expected);
    let corrupt_registers: [fn(&mut RegisterSnapshot); 9] = [
        |r: &mut RegisterSnapshot| r.rax ^= 1 << 32,
        |r: &mut RegisterSnapshot| r.rcx ^= 1,
        |r: &mut RegisterSnapshot| r.r11 ^= 0x100,
        |r: &mut RegisterSnapshot| r.r8 ^= 1 << 32,
        |r: &mut RegisterSnapshot| r.r15 ^= 1,
        |r: &mut RegisterSnapshot| r.eflags ^= 1,
        |r: &mut RegisterSnapshot| r.rsp += 16,
        |r: &mut RegisterSnapshot| r.rip += 1,
        |r: &mut RegisterSnapshot| r.orig_rax ^= 1,
    ];
    for field in corrupt_registers {
        let mut wrong = expected.clone();
        field(&mut wrong.registers);
        assert_ne!(actual, wrong);
    }
    let mut wrong = expected.clone();
    wrong.xstate[160] ^= 1;
    assert_ne!(actual, wrong);
    let mut wrong = expected.clone();
    wrong.stack[0] ^= 1;
    assert_ne!(actual, wrong);
    let mut wrong = expected;
    wrong.memory[0] ^= 1;
    assert_ne!(actual, wrong);
}

#[test]
fn int80_getid_bridge_matches_original_native_entry_completion_and_continuation() {
    // Six explicit source rows: two i386 numbers times three accepted encodings.
    for encoding in [&[0xcd, 0x80][..], &[0x66, 0xcd, 0x80], &[0x48, 0xcd, 0x80]] {
        for number in [20, 224] {
            let fixture = Fixture::new(encoding, HIGH_NUMBER | number);
            let mut native = Native::launch(&fixture);
            let before = native.evidence();
            let native_completion = native.syscall(&fixture);
            native.ptrace(libc::PTRACE_CONT, 0, 0);
            native.marker(fixture.terminal, libc::SIGILL);
            let native_terminal = native.evidence();
            let mut terminal_memory = before.memory.clone();
            terminal_memory[..4].copy_from_slice(&0x12345678_u32.to_le_bytes());
            assert_eq!(native_terminal.memory, terminal_memory);

            let mut process = fixture.controlled();
            let handle = pidfd(process.pid());
            assert_eq!(controlled_evidence(&process), before);
            let NativeSyscallOutcome::Completed(completion) = process
                .hold()
                .unwrap()
                .execute_linux_int80_getid(fixture.site, encoding, TIMEOUT)
                .unwrap()
            else {
                panic!("INT80 getid did not complete");
            };
            let mut expected = before.registers;
            expected.rip = fixture.site + encoding.len() as u64;
            expected.rax = process.pid() as u64;
            expected.orig_rax = number;
            assert_eq!(completion.registers, expected);
            assert_eq!(completion.xstate, before.xstate);
            assert_eq!(completion.result, i64::from(process.pid()));
            assert!(!completion.is_error);
            let controlled_completion = controlled_evidence(&process);
            assert_eq!(controlled_completion.registers, completion.registers);
            assert_eq!(controlled_completion.xstate, completion.xstate);
            assert_eq!(controlled_completion.memory, before.memory);
            assert_eq!(
                process.read_memory(BASE, 2 * PAGE).unwrap(),
                fixture.image[..2 * PAGE]
            );

            // A real bridge permits rearming/synchronization without changing
            // completed state or running the original successor write.
            let mut stop = process.hold().unwrap();
            stop.write_memory_checked(fixture.site, &encoding[..1], &[0xcc])
                .unwrap();
            stop.sync_core(TIMEOUT).unwrap();
            assert_eq!(stop.read_registers().unwrap(), completion.registers);
            assert_eq!(stop.read_xstate().unwrap(), completion.xstate);
            let ProcessEvent::Signal(signal) = process.resume_until_event(TIMEOUT).unwrap() else {
                panic!("missing original continuation UD2");
            };
            assert_eq!(signal.signal, libc::SIGILL);
            assert_eq!(signal.code, 2); // Linux ILL_ILLOPN.
            assert_eq!(signal.instruction_pointer, fixture.terminal);
            let controlled_terminal = controlled_evidence(&process);
            assert_eq!(controlled_terminal.memory, terminal_memory);
            for (actual, expected) in [
                (controlled_completion, native_completion),
                (controlled_terminal, native_terminal),
            ] {
                compare_with_corruption_controls(
                    actual.check_own_pid(process.pid()),
                    expected.check_own_pid(native.pid()),
                );
            }
            drop(process);
            assert_reaped(&handle);
            native.finish();
        }
    }
}

#[test]
fn declared_int80_native_page_callbacks_match_independent_full_native_state() {
    for encoding in [&[0xcd, 0x80][..], &[0x66, 0xcd, 0x80], &[0x48, 0xcd, 0x80]] {
        for number in [20, 224] {
            let fixture = Fixture::page(encoding, HIGH_NUMBER | number);
            let mut native = Native::launch(&fixture);
            let before = native.evidence();
            let native_completion = native.syscall(&fixture);
            native.ptrace(libc::PTRACE_CONT, 0, 0);
            native.marker(fixture.terminal, libc::SIGILL);
            let native_terminal = native.evidence();

            let mut gate = fixture.gate(NativeProvider);
            let handle = pidfd(gate.pid());
            let SelectedEvent::Completed(completed) = gate.next_event().unwrap() else {
                panic!("declared INT80 must complete natively");
            };
            assert_eq!(completed.execution, SelectedExecution::Native);
            assert_eq!(*completed.input.registers(), before.registers);
            assert_eq!(completed.before_xstate, before.xstate);
            assert_eq!(completed.after.orig_rax, number);
            assert_eq!(gate.read_registers().unwrap(), completed.after);
            assert_eq!(gate.read_xstate().unwrap(), completed.xstate);
            let actual_completion = Evidence {
                registers: completed.after,
                xstate: completed.xstate,
                stack: gate.read_memory(STACK, 32).unwrap(),
                memory: gate.read_memory(DATA, PAGE).unwrap(),
            };
            assert_eq!(actual_completion.memory, before.memory);
            let mut armed = fixture.image[..2 * PAGE].to_vec();
            for offset in 0..encoding.len() - 1 {
                armed[(fixture.site - BASE) as usize + offset] = 0xcc;
            }
            assert_eq!(gate.read_memory(BASE, 2 * PAGE).unwrap(), armed);
            assert_eq!(gate.metrics().callbacks.get(&SiteClass::Int80), Some(&1));
            assert_eq!(gate.metrics().callbacks.len(), 1);
            assert_eq!(gate.metrics().native_completions, 1);
            assert_eq!(gate.metrics().scripted_completions, 0);
            assert_eq!(gate.metrics().refusals, 0);
            let SelectedEvent::ApplicationSignal(signal) = gate.next_event().unwrap() else {
                panic!("original INT80 continuation did not reach UD2");
            };
            assert_eq!(signal.signal, libc::SIGILL);
            assert_eq!(signal.code, 2);
            assert_eq!(signal.registers.rip, fixture.terminal);
            assert!(signal.input.is_none());
            let actual_terminal = Evidence {
                registers: signal.registers,
                xstate: signal.xstate,
                stack: gate.read_memory(STACK, 32).unwrap(),
                memory: gate.read_memory(DATA, PAGE).unwrap(),
            };
            for (actual, expected) in [
                (actual_completion, native_completion),
                (actual_terminal, native_terminal),
            ] {
                compare_with_corruption_controls(
                    actual.check_own_pid(gate.pid()),
                    expected.check_own_pid(native.pid()),
                );
            }
            assert!(gate.next_event().is_err());
            assert_eq!(gate.metrics().callbacks.get(&SiteClass::Int80), Some(&1));
            drop(gate);
            assert_reaped(&handle);
            native.finish();
        }
    }
}

#[test]
fn typed_scripted_int80_getid_preserves_rcx_r11_flags_and_replacement_metadata() {
    for number in [20, 224] {
        let fixture = Fixture::page(&[0xcd, 0x80], HIGH_NUMBER | number);
        let mut native = Native::launch(&fixture);
        let before = native.evidence();
        native.syscall(&fixture);
        native.ptrace(libc::PTRACE_CONT, 0, 0);
        native.marker(fixture.terminal, libc::SIGILL);
        let mut expected_terminal = native.evidence();
        assert_eq!(expected_terminal.registers.rax, native.pid() as u64);
        assert_eq!(expected_terminal.registers.orig_rax, u64::MAX);
        // The original execution independently supplies the exact UD2 fault
        // state, including RF. Only the authenticated native identity result
        // is replaced by the scripted result. The non-syscall orig_rax sentinel
        // is asserted explicitly and agrees with the replacement model.
        expected_terminal.registers.rax = 735;
        let input = SelectedInput::new(
            decode(fixture.site, &fixture.encoding, &fixture.aliases()).unwrap(),
            before.registers,
        )
        .unwrap();
        let raw = &before.registers;
        assert_eq!(
            input.arguments(),
            SelectedArguments::Syscall {
                abi: SyscallAbi::LinuxI386Int80,
                number,
                arguments: [raw.rbx, raw.rcx, raw.rdx, raw.rsi, raw.rdi, raw.rbp]
                    .map(|value| value & 0xffff_ffff),
            }
        );
        let provider = ScriptedProvider::new([ScriptEntry {
            input,
            decision: ProviderDecision::Complete(SelectedResult::Syscall(
                SyscallResult::LinuxI386Int80GetId { value: 735 },
            )),
        }]);
        let mut gate = fixture.gate(provider);
        let handle = pidfd(gate.pid());
        let SelectedEvent::Completed(completed) = gate.next_event().unwrap() else {
            panic!("typed INT80 replacement did not complete");
        };
        let mut expected = before.registers;
        expected.rax = 735;
        expected.rip += 2;
        assert_eq!(before.registers.orig_rax, u64::MAX);
        assert_eq!(*completed.input.registers(), before.registers);
        assert_eq!(completed.before_xstate, before.xstate);
        assert_eq!(completed.after, expected);
        assert_eq!(completed.xstate, before.xstate);
        assert_eq!(completed.execution, SelectedExecution::Scripted);
        assert_eq!(gate.read_registers().unwrap(), expected);
        assert_eq!(gate.read_xstate().unwrap(), before.xstate);
        assert_eq!(gate.read_memory(DATA, PAGE).unwrap(), before.memory);
        assert_eq!(gate.provider().consumed(), 1);
        gate.provider().finish().unwrap();
        assert_eq!(gate.metrics().native_completions, 0);
        assert_eq!(gate.metrics().scripted_completions, 1);
        assert_eq!(gate.metrics().callbacks.get(&SiteClass::Int80), Some(&1));
        let SelectedEvent::ApplicationSignal(signal) = gate.next_event().unwrap() else {
            panic!("scripted INT80 continuation did not reach UD2");
        };
        assert_eq!(signal.signal, libc::SIGILL);
        assert_eq!(signal.code, 2);
        assert_eq!(signal.registers.orig_rax, before.registers.orig_rax);
        let actual_terminal = Evidence {
            registers: signal.registers,
            xstate: signal.xstate,
            stack: gate.read_memory(STACK, 32).unwrap(),
            memory: gate.read_memory(DATA, PAGE).unwrap(),
        };
        compare_with_corruption_controls(actual_terminal, expected_terminal);
        let mut memory = before.memory;
        memory[..4].copy_from_slice(&0x12345678_u32.to_le_bytes());
        assert_eq!(gate.read_memory(DATA, PAGE).unwrap(), memory);
        assert!(gate.next_event().is_err());
        assert_eq!(gate.provider().consumed(), 1);
        drop(gate);
        assert_reaped(&handle);
        native.finish();
    }
}

#[test]
fn int80_bridge_refuses_other_requests_flags_and_encodings_before_execution() {
    for number in [0, 1, 2, 4, 11, 39, 186] {
        let fixture = Fixture::new(&[0xcd, 0x80], HIGH_NUMBER | number);
        let mut process = fixture.controlled();
        let handle = pidfd(process.pid());
        let before = controlled_evidence(&process);
        assert!(
            process
                .hold()
                .unwrap()
                .execute_linux_int80_getid(fixture.site, &fixture.encoding, TIMEOUT)
                .is_err()
        );
        assert_eq!(controlled_evidence(&process), before);
        assert_eq!(
            process.read_memory(BASE, 2 * PAGE).unwrap(),
            fixture.image[..2 * PAGE]
        );
        drop(process);
        assert_reaped(&handle);
    }
    for extra_flags in [0x100, 0x10000, 0x40000] {
        let fixture = Fixture::new(&[0xcd, 0x80], HIGH_NUMBER | 20);
        let mut process = fixture.controlled();
        let handle = pidfd(process.pid());
        let mut registers = process.read_registers().unwrap();
        registers.eflags |= extra_flags;
        process.hold().unwrap().write_registers(&registers).unwrap();
        let before = controlled_evidence(&process);
        assert_eq!(before.registers, registers);
        assert!(
            process
                .hold()
                .unwrap()
                .execute_linux_int80_getid(fixture.site, &fixture.encoding, TIMEOUT)
                .is_err()
        );
        assert_eq!(controlled_evidence(&process), before);
        drop(process);
        assert_reaped(&handle);
    }
    for wrong in [
        &[0x0f, 0x05][..],
        &[0x0f, 0x34],
        &[0xcd, 0x80, 0x90],
        &[0x66, 0xcd, 0x80],
    ] {
        let fixture = Fixture::new(&[0xcd, 0x80], HIGH_NUMBER | 20);
        let mut process = fixture.controlled();
        let handle = pidfd(process.pid());
        let before = controlled_evidence(&process);
        assert!(
            process
                .hold()
                .unwrap()
                .execute_linux_int80_getid(fixture.site, wrong, TIMEOUT)
                .is_err()
        );
        assert_eq!(controlled_evidence(&process), before);
        drop(process);
        assert_reaped(&handle);
    }
}

#[test]
fn unqualified_int80_native_page_request_stays_guarded_and_cannot_resume() {
    let fixture = Fixture::page(&[0xcd, 0x80], HIGH_NUMBER | 2); // i386 fork.
    let mut gate = fixture.gate(NativeProvider);
    let handle = pidfd(gate.pid());
    assert!(matches!(
        gate.next_event(),
        Err(liteinst_launch::gate::GateError::Selected(
            SemanticsError::UnsupportedScriptedSyscall
        ))
    ));
    let mut armed = fixture.image[..2 * PAGE].to_vec();
    armed[(fixture.site - BASE) as usize] = 0xcc;
    assert_eq!(gate.read_memory(BASE, 2 * PAGE).unwrap(), armed);
    assert_eq!(gate.read_memory(DATA, 8).unwrap(), [0; 8]);
    assert_eq!(gate.metrics().native_completions, 0);
    assert_eq!(gate.metrics().scripted_completions, 0);
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Int80), Some(&1));
    assert!(gate.next_event().is_err());
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Int80), Some(&1));
    drop(gate);
    assert_reaped(&handle);
}

#[test]
fn ordinary_owner_resume_still_refuses_the_i386_syscall_abi() {
    let fixture = Fixture::new(&[0xcd, 0x80], HIGH_NUMBER | 20);
    let mut process = fixture.controlled();
    let handle = pidfd(process.pid());
    assert!(matches!(
        process.resume_until_event(TIMEOUT),
        Err(LaunchError::Invalid("non-native syscall ABI"))
    ));
    assert!(process.resume_until_event(TIMEOUT).is_err());
    drop(process);
    assert_reaped(&handle);
}
