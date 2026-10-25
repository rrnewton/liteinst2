#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Independent native samples are replayed as typed outputs, never compared
//! with an unrelated hardware sample. The raw oracle executes the original
//! opcode with CONT, not SINGLESTEP; separate NOPs serve as authenticated
//! before/after breakpoints. Every GPR, flag, XSTATE byte and data byte is checked.

use std::collections::BTreeSet;
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
    InstructionFault, InstructionProvider, NativeProvider, ProviderDecision, SelectedInput,
    SelectedResult, SemanticsError, SyscallAliases,
};
use liteinst_launch::{ExecCheckpoint, LaunchCommand, RegisterSnapshot};

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const DATA: u64 = 0x600000;
const STACK: u64 = DATA + PAGE as u64 - 64;
const RF: u64 = 1 << 16;
const TIMEOUT: Duration = Duration::from_secs(3);
static NEXT: AtomicUsize = AtomicUsize::new(0);
// A fork must not inherit another test's writable executable-file descriptor.
static FORK_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug)]
struct Case {
    class: SiteClass,
    destination: usize,
    flags: u64,
    cpuid_input: Option<(u32, u32)>,
}

impl Case {
    fn encoding(self) -> Vec<u8> {
        assert!(self.destination < 8);
        match self.class {
            SiteClass::Cpuid => vec![0x0f, 0xa2],
            SiteClass::Rdrand => vec![0x0f, 0xc7, 0xf0 + self.destination as u8],
            SiteClass::Rdseed => vec![0x0f, 0xc7, 0xf8 + self.destination as u8],
            SiteClass::Rdpid => vec![0xf3, 0x0f, 0xc7, 0xf8 + self.destination as u8],
            SiteClass::Rdtsc => vec![0x0f, 0x31],
            SiteClass::Rdtscp => vec![0x0f, 0x01, 0xf9],
            _ => panic!("not a native CPU fixture"),
        }
    }

    // Extract only the hardware's typed outputs, independently of the production
    // decoder, register helper, native_result and completion implementation.
    fn sample(self, registers: &RegisterSnapshot) -> SelectedResult {
        match self.class {
            SiteClass::Cpuid => SelectedResult::Cpuid {
                eax: u32::try_from(registers.rax).unwrap(),
                ebx: u32::try_from(registers.rbx).unwrap(),
                ecx: u32::try_from(registers.rcx).unwrap(),
                edx: u32::try_from(registers.rdx).unwrap(),
            },
            SiteClass::Rdrand => SelectedResult::Rdrand {
                value: gprs(registers)[self.destination],
                carry: registers.eflags & 1 != 0,
            },
            SiteClass::Rdseed => SelectedResult::Rdseed {
                value: gprs(registers)[self.destination],
                carry: registers.eflags & 1 != 0,
            },
            SiteClass::Rdpid => SelectedResult::Rdpid {
                auxiliary: u32::try_from(gprs(registers)[self.destination]).unwrap(),
            },
            SiteClass::Rdtsc => SelectedResult::Rdtsc {
                counter: (u64::from(u32::try_from(registers.rdx).unwrap()) << 32)
                    | u64::from(u32::try_from(registers.rax).unwrap()),
            },
            SiteClass::Rdtscp => SelectedResult::Rdtscp {
                counter: (u64::from(u32::try_from(registers.rdx).unwrap()) << 32)
                    | u64::from(u32::try_from(registers.rax).unwrap()),
                auxiliary: u32::try_from(registers.rcx).unwrap(),
            },
            _ => unreachable!(),
        }
    }

    fn check_transition(self, before: RegisterSnapshot, after: RegisterSnapshot, next: u64) {
        let mut expected = before;
        expected.rip = next;
        expected.eflags &= !RF;
        let mut expected_gprs = gprs(&expected);
        let actual_gprs = gprs(&after);
        match self.class {
            SiteClass::Cpuid => {
                for index in [0, 1, 2, 3] {
                    assert!(actual_gprs[index] <= u64::from(u32::MAX));
                    expected_gprs[index] = actual_gprs[index];
                }
                if self.cpuid_input == Some((0, 0)) {
                    // Qualify the highest basic leaf used by this matrix using
                    // the actual child's native CPUID result.
                    assert!(after.rax >= 7);
                }
            }
            SiteClass::Rdrand | SiteClass::Rdseed => {
                // These fixtures are bare 32-bit encodings: success and failure
                // both zero-extend. Failure writes zero, not the old destination.
                let value = actual_gprs[self.destination];
                assert!(value <= u64::from(u32::MAX));
                if after.eflags & 1 == 0 {
                    assert_eq!(value, 0);
                }
                expected_gprs[self.destination] = value;
                expected.eflags = (expected.eflags & !0x8d5) | (after.eflags & 1);
            }
            SiteClass::Rdpid => {
                let value = actual_gprs[self.destination];
                assert!(value <= u64::from(u32::MAX));
                expected_gprs[self.destination] = value;
            }
            SiteClass::Rdtsc | SiteClass::Rdtscp => {
                for index in [0, 2] {
                    assert!(actual_gprs[index] <= u64::from(u32::MAX));
                    expected_gprs[index] = actual_gprs[index];
                }
                if self.class == SiteClass::Rdtscp {
                    assert!(actual_gprs[1] <= u64::from(u32::MAX));
                    expected_gprs[1] = actual_gprs[1];
                }
            }
            _ => unreachable!(),
        }
        write_gprs(&mut expected, expected_gprs);
        assert_eq!(
            after, expected,
            "independent architectural transition: {self:?}"
        );
    }

    fn seed(self, register: usize) -> u64 {
        if register == 4 {
            return STACK;
        }
        if let Some((leaf, subleaf)) = self.cpuid_input {
            match register {
                // Nonzero upper halves must still be cleared by CPUID outputs.
                0 => return 0x1234_5678_0000_0000 | u64::from(leaf),
                1 => return 0x1234_5678_0000_0000 | u64::from(subleaf),
                _ => {}
            }
        }
        0x1234_5678_9000_0000 + register as u64
    }

    fn random_carry(self, registers: &RegisterSnapshot) -> Option<u8> {
        matches!(self.class, SiteClass::Rdrand | SiteClass::Rdseed)
            .then_some((registers.eflags & 1) as u8)
    }
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-tmp");
        fs::create_dir_all(&root).unwrap();
        let path = root.join(format!(
            "native-selected-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let directory = Self(path);
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _directory: Directory,
    path: PathBuf,
    image: Vec<u8>,
    heads: BTreeSet<u64>,
    site: u64,
    successor: u64,
    terminal: u64,
    case: Case,
}

impl Fixture {
    fn new(case: Case) -> Self {
        let directory = Directory::new();
        let path = directory.0.join("fixture");
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
        let mut code = Code::default();
        code.mov64(4, STACK);
        for (offset, value) in [
            (0_u8, 0x11223344_u32),
            (8, 0x55667788),
            (16, 0x13572468),
            (24, 0x24681357),
        ] {
            let mut instruction = vec![0x48, 0xc7, 0x44, 0x24, offset];
            instruction.extend_from_slice(&value.to_le_bytes());
            code.emit(&instruction);
        }
        code.emit(&[0xdb, 0xe3]); // FNINIT; FLD1 and nontrivial SSE state.
        code.emit(&[0xd9, 0xe8]);
        code.emit(&[0x66, 0x0f, 0x76, 0xc9]);
        code.emit(&[0x66, 0x0f, 0x6f, 0xd1]);
        for register in 0..16 {
            if register != 4 {
                code.mov64(register, case.seed(register));
            }
        }
        let mut push_flags = vec![0x68];
        push_flags.extend_from_slice(&(case.flags as u32).to_le_bytes());
        code.emit(&push_flags);
        code.emit(&[0x9d]);
        code.emit(&[0x90]); // Independent oracle's pre-instruction marker.
        let site = code.emit(&case.encoding());
        let successor = code.emit(&[0x90]); // Independent post-instruction marker.
        for register in 0..16 {
            // MOV [RIP+disp32], r64 does not use or change RSP or flags. This
            // remains safe when a selected instruction writes an arbitrary RSP.
            let next = code.pc() + 7;
            let mut instruction = vec![
                0x48 | ((register as u8 >> 3) << 2),
                0x89,
                0x05 | ((register as u8 & 7) << 3),
            ];
            instruction.extend_from_slice(
                &i32::try_from((DATA + register as u64 * 8) as i64 - next as i64)
                    .unwrap()
                    .to_le_bytes(),
            );
            code.emit(&instruction);
        }
        let next = code.pc() + 7;
        let mut set_carry = vec![0x0f, 0x92, 0x05];
        set_carry.extend_from_slice(
            &i32::try_from((DATA + 128) as i64 - next as i64)
                .unwrap()
                .to_le_bytes(),
        );
        code.emit(&set_carry);
        let terminal = code.emit(&[0x0f, 0x0b]);
        assert!(code.bytes.len() < PAGE);
        image[PAGE..PAGE + code.bytes.len()].copy_from_slice(&code.bytes);
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
            _directory: directory,
            path,
            image,
            heads: code.heads,
            site,
            successor,
            terminal,
            case,
        }
    }

    fn gate<P: InstructionProvider>(&self, provider: P) -> SelectedPageGate<P> {
        let checkpoint = {
            let _guard = FORK_LOCK.lock().unwrap();
            ExecCheckpoint::launch(&LaunchCommand::new(&self.path), TIMEOUT).unwrap()
        };
        // SAFETY: this hand-authored ELF has one private immutable RX image and
        // one private RW/NX data mapping. emit records every possible original
        // head; execution is straight line and has no external readers, writers,
        // aliases, threads, signals, code-as-data or private-island entries. We
        // exclusively own the child and never trace/reap it outside this gate.
        unsafe {
            SelectedPageGate::new(
                checkpoint,
                vec![ImageFacts {
                    start: BASE,
                    bytes: self.image[..2 * PAGE].to_vec(),
                    heads: self.heads.clone(),
                }],
                // RDPID-only is intentional: default-policy RDSEED suffix
                // overlap remains a separate mandatory refusal fixture.
                Policy {
                    version: 1,
                    selected: BTreeSet::from([self.case.class]),
                },
                SyscallAliases::new(),
                provider,
                TIMEOUT,
            )
            .unwrap()
        }
    }
}

#[derive(Default)]
struct Code {
    bytes: Vec<u8>,
    heads: BTreeSet<u64>,
}
impl Code {
    fn pc(&self) -> u64 {
        BASE + PAGE as u64 + self.bytes.len() as u64
    }
    fn emit(&mut self, instruction: &[u8]) -> u64 {
        let pc = self.pc();
        assert!(self.heads.insert(pc));
        self.bytes.extend_from_slice(instruction);
        pc
    }
    fn mov64(&mut self, register: usize, value: u64) {
        let mut instruction = vec![0x48 | (register as u8 >> 3), 0xb8 | (register as u8 & 7)];
        instruction.extend_from_slice(&value.to_le_bytes());
        self.emit(&instruction);
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
fn gprs(registers: &RegisterSnapshot) -> [u64; 16] {
    [
        registers.rax,
        registers.rcx,
        registers.rdx,
        registers.rbx,
        registers.rsp,
        registers.rbp,
        registers.rsi,
        registers.rdi,
        registers.r8,
        registers.r9,
        registers.r10,
        registers.r11,
        registers.r12,
        registers.r13,
        registers.r14,
        registers.r15,
    ]
}
fn write_gprs(registers: &mut RegisterSnapshot, values: [u64; 16]) {
    [
        registers.rax,
        registers.rcx,
        registers.rdx,
        registers.rbx,
        registers.rsp,
        registers.rbp,
        registers.rsi,
        registers.rdi,
        registers.r8,
        registers.r9,
        registers.r10,
        registers.r11,
        registers.r12,
        registers.r13,
        registers.r14,
        registers.r15,
    ] = values;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Evidence {
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    // Entire fixed data mapping: output slots, unused bytes and initialized
    // application stack, including PUSHFQ's stack write before selection.
    memory: Vec<u8>,
}

struct Native {
    child: Option<Child>,
    handle: Option<OwnedFd>,
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
        // Install the cleanup owner before the first fallible post-spawn step.
        let mut native = Self {
            child: Some(command.spawn().unwrap()),
            handle: None,
            reaped: false,
        };
        native.handle = Some(pidfd(native.pid()));
        let status = native.wait();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        native.ptrace(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        native.patch_byte(fixture.site - 1, 0x90, 0xcc);
        native.patch_byte(fixture.successor, 0x90, 0xcc);
        native.ptrace(libc::PTRACE_CONT, 0, 0);
        native.marker(fixture.site, libc::SIGTRAP);
        native.patch_byte(fixture.site - 1, 0xcc, 0x90);
        let before = native.registers();
        assert_eq!(before.rip, fixture.site);
        assert_eq!(before.eflags, fixture.case.flags);
        assert_eq!(before.rsp, STACK);
        assert_eq!(before.orig_rax, u64::MAX);
        let mut seeded = [0_u64; 16];
        for (register, value) in seeded.iter_mut().enumerate() {
            *value = fixture.case.seed(register);
        }
        assert_eq!(gprs(&before), seeded);
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
            // SAFETY: exclusive unreaped-child ownership pins this numeric PID.
            let result =
                unsafe { libc::waitpid(self.pid(), &mut status, libc::WNOHANG | libc::__WALL) };
            if result == self.pid() {
                // Retire ownership before the caller can assert on this status.
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
        assert!(!self.reaped);
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
    fn set_registers(&self, registers: RegisterSnapshot) {
        let raw: libc::user_regs_struct = registers.into();
        self.ptrace(libc::PTRACE_SETREGS, 0, (&raw const raw) as usize);
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
    fn patch_byte(&self, address: u64, expected: u8, replacement: u8) {
        let aligned = address & !7;
        let mut word = self.memory(aligned, 8);
        let offset = (address - aligned) as usize;
        assert_eq!(word[offset], expected);
        word[offset] = replacement;
        self.ptrace(
            libc::PTRACE_POKEDATA,
            aligned as usize,
            u64::from_le_bytes(word.try_into().unwrap()) as usize,
        );
    }
    fn evidence(&self) -> Evidence {
        Evidence {
            registers: self.registers(),
            xstate: self.xstate(),
            memory: self.memory(DATA, PAGE),
        }
    }
    fn signal(&self, status: i32) -> libc::siginfo_t {
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(status >> 16, 0);
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
        self.ptrace(libc::PTRACE_GETSIGINFO, 0, info.as_mut_ptr() as usize);
        // SAFETY: successful GETSIGINFO initialized the whole output.
        let info = unsafe { info.assume_init() };
        assert_eq!(info.si_signo, libc::WSTOPSIG(status));
        info
    }
    fn marker(&mut self, pc: u64, signal: i32) {
        let status = self.wait();
        let info = self.signal(status);
        assert_eq!(info.si_signo, signal);
        if signal == libc::SIGTRAP {
            assert!(matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
        }
        assert_eq!(self.registers().rip, pc);
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
        if let Some(handle) = self.handle.as_ref() {
            // SAFETY: the pidfd targets the original child even across PID reuse.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    handle.as_raw_fd(),
                    libc::SIGKILL,
                    0,
                    0,
                );
            }
        } else {
            // A partial constructor still owns an unreaped child exclusively.
            let _ = child.kill();
        }
        let pid = child.id() as libc::pid_t;
        let until = Instant::now() + TIMEOUT;
        while !raw_reaped(pid) {
            if Instant::now() >= until {
                let handle = self.handle.take();
                std::thread::spawn(move || {
                    while !raw_reaped(pid) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    drop(child);
                    drop(handle);
                });
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(child); // Raw wait consumed status; never call Child::wait again.
    }
}
fn raw_reaped(pid: libc::pid_t) -> bool {
    let mut status = 0;
    // SAFETY: this unreaped child has one cleanup owner, which stops on true.
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
    (result == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)))
        || (result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
}
fn pidfd(pid: libc::pid_t) -> OwnedFd {
    // SAFETY: pid identifies the still-owned child.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(descriptor >= 0);
    // SAFETY: successful pidfd_open returned one new descriptor.
    unsafe { OwnedFd::from_raw_fd(descriptor as i32) }
}
fn assert_reaped(handle: &OwnedFd) {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
    // SAFETY: stable pidfd and WNOWAIT cannot consume another cleanup owner's
    // status or refer to a recycled numeric PID.
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

struct Replay {
    before: RegisterSnapshot,
    site: u64,
    bytes: Vec<u8>,
    decision: ProviderDecision,
    called: bool,
}
impl InstructionProvider for Replay {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        assert!(!self.called, "duplicate callback");
        assert_eq!(input.registers(), &self.before);
        assert_eq!(input.instruction().logical_pc(), self.site);
        assert_eq!(input.instruction().bytes(), self.bytes);
        self.called = true;
        Ok(self.decision)
    }
}
fn gate_evidence<P: InstructionProvider>(gate: &SelectedPageGate<P>) -> Evidence {
    Evidence {
        registers: gate.read_registers().unwrap(),
        xstate: gate.read_xstate().unwrap(),
        memory: gate.read_memory(DATA, PAGE).unwrap(),
    }
}
fn check_dataflow(completion: &Evidence, terminal: &Evidence, terminal_pc: u64) {
    let mut expected = completion.clone();
    expected.registers.rip = terminal_pc;
    expected.registers.eflags |= RF; // Actual UD2 fault sets resume flag.
    for (index, value) in gprs(&completion.registers).into_iter().enumerate() {
        expected.memory[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    expected.memory[128] = (completion.registers.eflags & 1) as u8;
    assert_eq!(
        terminal, &expected,
        "full native result-to-application-memory dataflow"
    );
}
fn terminal<P: InstructionProvider>(gate: &mut SelectedPageGate<P>, fixture: &Fixture) -> Evidence {
    let event = gate.next_event().unwrap();
    let SelectedEvent::ApplicationSignal(signal) = event else {
        panic!("expected terminal UD2: {event:?}");
    };
    assert_eq!(signal.signal, libc::SIGILL);
    assert_eq!(signal.registers.rip, fixture.terminal);
    assert!(signal.input.is_none());
    let evidence = gate_evidence(gate);
    assert_eq!(signal.registers, evidence.registers);
    assert_eq!(signal.xstate, evidence.xstate);
    assert!(
        gate.next_event().is_err(),
        "terminal loop must remain closed"
    );
    evidence
}
fn check_counters<P: InstructionProvider>(
    gate: &SelectedPageGate<P>,
    case: Case,
    native: bool,
    fault: bool,
) {
    let metrics = gate.metrics();
    assert_eq!(metrics.callbacks.len(), 1);
    assert_eq!(metrics.callbacks.get(&case.class), Some(&1));
    assert_eq!(metrics.native_completions, usize::from(native && !fault));
    assert_eq!(metrics.scripted_completions, usize::from(!native && !fault));
    assert_eq!(metrics.native_signals, usize::from(native && fault));
    assert_eq!(metrics.provider_faults, usize::from(!native && fault));
    assert_eq!(metrics.refusals, 0);
}

enum EvaluationOutcome {
    Completed {
        raw_native_random_cf: Option<u8>,
        native_gate_random_cf: Option<u8>,
    },
    Fault,
}

fn emit_evaluation(case: Case, outcome: EvaluationOutcome) {
    if !std::env::var("LITEINST_EVALUATION").is_ok_and(|value| value == "1") {
        return;
    }
    let class = match case.class {
        SiteClass::Cpuid => "cpuid",
        SiteClass::Rdrand => "rdrand",
        SiteClass::Rdseed => "rdseed",
        SiteClass::Rdpid => "rdpid",
        SiteClass::Rdtsc => "rdtsc",
        SiteClass::Rdtscp => "rdtscp",
        _ => unreachable!("not a native CPU fixture"),
    };
    let (completed, fault, raw_cf, gate_cf) = match outcome {
        EvaluationOutcome::Completed {
            raw_native_random_cf,
            native_gate_random_cf,
        } => (1, 0, raw_native_random_cf, native_gate_random_cf),
        EvaluationOutcome::Fault => (0, 1, None, None),
    };
    let number_or_null =
        |value: Option<u32>| value.map_or_else(|| "null".to_owned(), |value| value.to_string());
    // Only validated outcome categories and random carry bits are emitted.
    // Addresses, register values, paths and raw process state stay out of JSON.
    eprintln!(
        concat!(
            "LITEINST_EVALUATION_NATIVE_SELECTED ",
            "{{\"schema_version\":1,\"class\":\"{}\",\"destination\":{},\"input_flags\":{},",
            "\"cpuid_leaf\":{},\"cpuid_subleaf\":{},",
            "\"raw_native_completed\":{},\"scripted_completed\":{},",
            "\"native_gate_completed\":{},\"raw_native_fault\":{},",
            "\"scripted_fault\":{},\"native_gate_signal\":{},",
            "\"raw_native_random_cf\":{},\"native_gate_random_cf\":{}}}"
        ),
        class,
        case.destination,
        case.flags,
        number_or_null(case.cpuid_input.map(|input| input.0)),
        number_or_null(case.cpuid_input.map(|input| input.1)),
        completed,
        completed,
        completed,
        fault,
        fault,
        fault,
        number_or_null(raw_cf.map(u32::from)),
        number_or_null(gate_cf.map(u32::from)),
    );
}

fn exercise(case: Case) {
    let fixture = Fixture::new(case);
    let mut native = Native::launch(&fixture);
    let native_handle = pidfd(native.pid());
    let before = native.evidence();
    native.ptrace(libc::PTRACE_CONT, 0, 0);
    let status = native.wait();
    let info = native.signal(status);
    let outcome = if info.si_signo == libc::SIGILL {
        // Unsupported CPU instructions are explicit fault qualifications, never
        // successful coverage or a silent test skip. Scripted semantic positives
        // are mandatory in the independent selected_gate suite on every host.
        assert_eq!(native.registers().rip, fixture.site);
        let fault = native.evidence();
        eprintln!("native capability fault, no positive native qualification: {case:?}");
        exercise_fault(&fixture, &before, &fault, info.si_code);
        EvaluationOutcome::Fault
    } else {
        assert_eq!(info.si_signo, libc::SIGTRAP);
        assert!(matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
        let mut registers = native.registers();
        assert_eq!(registers.rip, fixture.successor + 1);
        native.patch_byte(fixture.successor, 0xcc, 0x90);
        // Authenticate the separate observer marker before restoring precisely
        // its original NOP PC. No register, flags or output value is normalized.
        registers.rip = fixture.successor;
        native.set_registers(registers);
        let completion = native.evidence();
        case.check_transition(before.registers, completion.registers, fixture.successor);
        assert_eq!(completion.xstate, before.xstate);
        assert_eq!(completion.memory, before.memory);
        native.ptrace(libc::PTRACE_CONT, 0, 0);
        native.marker(fixture.terminal, libc::SIGILL);
        let native_terminal = native.evidence();
        check_dataflow(&completion, &native_terminal, fixture.terminal);
        exercise_replay(&fixture, &before, &completion, &native_terminal);
        let native_gate_random_cf = exercise_native_provider(&fixture, &before);
        EvaluationOutcome::Completed {
            raw_native_random_cf: case.random_carry(&completion.registers),
            native_gate_random_cf,
        }
    };
    drop(native);
    assert_reaped(&native_handle);
    drop(native_handle);
    drop(fixture);
    // A receipt exists only after every oracle, counter and cleanup assertion
    // has succeeded. Missing receipts must never imply successful completion.
    emit_evaluation(case, outcome);
}

fn exercise_replay(
    fixture: &Fixture,
    before: &Evidence,
    completion: &Evidence,
    native_terminal: &Evidence,
) {
    let provider = Replay {
        before: before.registers,
        site: fixture.site,
        bytes: fixture.case.encoding(),
        decision: ProviderDecision::Complete(fixture.case.sample(&completion.registers)),
        called: false,
    };
    let mut gate = fixture.gate(provider);
    let handle = pidfd(gate.pid());
    let event = gate.next_event().unwrap();
    let SelectedEvent::Completed(actual) = event else {
        panic!("expected scripted completion: {event:?}");
    };
    assert_eq!(actual.execution, SelectedExecution::Scripted);
    assert_eq!(actual.input.registers(), &before.registers);
    assert_eq!(actual.before_xstate, before.xstate);
    assert_eq!(actual.after, completion.registers);
    assert_eq!(actual.xstate, completion.xstate);
    assert_eq!(gate_evidence(&gate), *completion);
    assert!(gate.provider().called);
    assert_eq!(terminal(&mut gate, fixture), *native_terminal);
    check_counters(&gate, fixture.case, false, false);
    assert_comparator_rejects_corruption(completion);
    drop(gate);
    assert_reaped(&handle);
}

fn exercise_native_provider(fixture: &Fixture, before: &Evidence) -> Option<u8> {
    let mut gate = fixture.gate(NativeProvider);
    let handle = pidfd(gate.pid());
    let event = gate.next_event().unwrap();
    let SelectedEvent::Completed(actual) = event else {
        panic!("expected native completion after actual native qualification: {event:?}");
    };
    assert_eq!(actual.execution, SelectedExecution::Native);
    assert_eq!(actual.input.registers(), &before.registers);
    assert_eq!(actual.before_xstate, before.xstate);
    assert_eq!(actual.xstate, before.xstate);
    fixture
        .case
        .check_transition(before.registers, actual.after, fixture.successor);
    let completion = gate_evidence(&gate);
    assert_eq!(completion.registers, actual.after);
    assert_eq!(completion.xstate, actual.xstate);
    assert_eq!(completion.memory, before.memory);
    let terminal = terminal(&mut gate, fixture);
    // This run's actual sample is compared with this run's application state.
    // A different hardware invocation is never an expected output value.
    check_dataflow(&completion, &terminal, fixture.terminal);
    check_counters(&gate, fixture.case, true, false);
    drop(gate);
    assert_reaped(&handle);
    fixture.case.random_carry(&completion.registers)
}

fn exercise_fault(fixture: &Fixture, before: &Evidence, fault: &Evidence, code: i32) {
    let provider = Replay {
        before: before.registers,
        site: fixture.site,
        bytes: fixture.case.encoding(),
        decision: ProviderDecision::Fault(InstructionFault::InvalidOpcode),
        called: false,
    };
    let mut scripted = fixture.gate(provider);
    let handle = pidfd(scripted.pid());
    let event = scripted.next_event().unwrap();
    let SelectedEvent::Fault(actual) = event else {
        panic!("expected explicit scripted fault: {event:?}");
    };
    assert_eq!(actual.fault, InstructionFault::InvalidOpcode);
    assert_eq!(actual.input.registers(), &before.registers);
    assert_eq!(gate_evidence(&scripted), *before);
    assert!(scripted.provider().called);
    assert!(scripted.next_event().is_err());
    check_counters(&scripted, fixture.case, false, true);
    drop(scripted);
    assert_reaped(&handle);

    let mut gate = fixture.gate(NativeProvider);
    let handle = pidfd(gate.pid());
    let event = gate.next_event().unwrap();
    let SelectedEvent::ApplicationSignal(actual) = event else {
        panic!("expected actual native SIGILL: {event:?}");
    };
    assert_eq!(actual.signal, libc::SIGILL);
    assert_eq!(actual.code, code);
    assert_eq!(actual.registers.rip, fixture.site);
    assert_eq!(actual.input.unwrap().registers(), &before.registers);
    assert_eq!(actual.registers, fault.registers);
    assert_eq!(actual.xstate, fault.xstate);
    assert_eq!(gate_evidence(&gate), *fault);
    assert!(gate.next_event().is_err());
    check_counters(&gate, fixture.case, true, true);
    drop(gate);
    assert_reaped(&handle);
}

fn assert_comparator_rejects_corruption(expected: &Evidence) {
    let mut changed = expected.clone();
    changed.registers.rax ^= 1;
    assert_ne!(&changed, expected);
    changed = expected.clone();
    changed.registers.rdx ^= 1;
    assert_ne!(&changed, expected);
    changed = expected.clone();
    changed.registers.rcx ^= 1; // RDTSCP auxiliary value is not exempted.
    assert_ne!(&changed, expected);
    changed = expected.clone();
    changed.registers.eflags ^= 1; // Neither success nor failure CF is masked.
    assert_ne!(&changed, expected);
    changed = expected.clone();
    changed.registers.rsp = changed.registers.rsp.wrapping_add(16);
    assert_ne!(&changed, expected);
    changed = expected.clone();
    changed.xstate[160] ^= 1;
    assert_ne!(&changed, expected);
    changed = expected.clone();
    changed.memory[(STACK - DATA) as usize] ^= 1;
    assert_ne!(&changed, expected);
}

macro_rules! native_cases {
    ($($name:ident: $class:ident, $destination:expr, $flags:expr;)+) => {
        $(#[test]
        fn $name() {
            exercise(Case { class: SiteClass::$class, destination: $destination, flags: $flags, cpuid_input: None });
        })+
    };
}

native_cases! {
    rdrand_eax: Rdrand, 0, 0xed7;
    rdrand_ecx: Rdrand, 1, 0xed7;
    rdrand_edx: Rdrand, 2, 0xed7;
    rdrand_ebx: Rdrand, 3, 0xed7;
    rdrand_esp: Rdrand, 4, 0xed7;
    rdrand_ebp: Rdrand, 5, 0xed7;
    rdrand_esi: Rdrand, 6, 0xed7;
    rdrand_edi: Rdrand, 7, 0xed7;
    rdseed_eax: Rdseed, 0, 0xed7;
    rdseed_ecx: Rdseed, 1, 0xed7;
    rdseed_edx: Rdseed, 2, 0xed7;
    rdseed_ebx: Rdseed, 3, 0xed7;
    rdseed_esp: Rdseed, 4, 0xed7;
    rdseed_ebp: Rdseed, 5, 0xed7;
    rdseed_esi: Rdseed, 6, 0xed7;
    rdseed_edi: Rdseed, 7, 0xed7;
    rdpid_rax: Rdpid, 0, 0xed7;
    rdpid_rcx: Rdpid, 1, 0xed7;
    rdpid_rdx: Rdpid, 2, 0xed7;
    rdpid_rbx: Rdpid, 3, 0xed7;
    rdpid_rsp: Rdpid, 4, 0xed7;
    rdpid_rbp: Rdpid, 5, 0xed7;
    rdpid_rsi: Rdpid, 6, 0xed7;
    rdpid_rdi: Rdpid, 7, 0xed7;
    rdtsc_all_flags: Rdtsc, 0, 0xed7;
    rdtsc_clear_flags: Rdtsc, 0, 0x202;
    rdtsc_zero_parity: Rdtsc, 0, 0x246;
    rdtscp_all_flags: Rdtscp, 0, 0xed7;
    rdtscp_clear_flags: Rdtscp, 0, 0x202;
    rdtscp_zero_parity: Rdtscp, 0, 0x246;
}

#[test]
fn cpuid_basic_vendor_leaf() {
    exercise(Case {
        class: SiteClass::Cpuid,
        destination: 0,
        flags: 0xed7,
        cpuid_input: Some((0, 0)),
    });
}

#[test]
fn cpuid_processor_features_leaf() {
    exercise(Case {
        class: SiteClass::Cpuid,
        destination: 0,
        flags: 0x202,
        cpuid_input: Some((1, 0)),
    });
}

#[test]
fn cpuid_structured_features_leaf() {
    exercise(Case {
        class: SiteClass::Cpuid,
        destination: 0,
        flags: 0x246,
        cpuid_input: Some((7, 0)),
    });
}
