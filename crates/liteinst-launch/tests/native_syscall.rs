#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! The oracle uses raw ptrace on the original ELF and never creates a
//! production checkpoint, island, gate, or syscall-return bridge.

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
use liteinst_launch::selected::{NativeProvider, SyscallAliases};
use liteinst_launch::{
    ExecCheckpoint, LaunchCommand, LaunchError, NativeSyscallOutcome, ProcessEvent,
    RegisterSnapshot, StoppedProcess,
};

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const DATA: u64 = 0x600000;
const STACK: u64 = DATA + PAGE as u64 - 64;
const FLAGS: u64 = 0xed7; // CF/PF/AF/ZF/SF/OF/DF set, plus IF and reserved bit 1.
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
                "native-syscall-{}-{}",
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
        mov64(
            &mut code,
            7,
            if number == libc::SYS_exit as u64 {
                37
            } else {
                1
            },
        );
        // An out-of-user-range extent fails Linux access_ok even if stdout is
        // /dev/null, whose write implementation need not copy an unmapped NULL.
        mov64(&mut code, 6, u64::MAX); // write(1, invalid_extent, 1): EFAULT.
        mov64(&mut code, 2, 1);
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

    fn gate(&self) -> SelectedPageGate<NativeProvider> {
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
        // SAFETY: exclusive immutable private fixture with complete heads,
        // no code readers/aliases, no other tasks or saved resumes. The seeded
        // flags have TF/RF clear; only the declared allowlisted syscall runs.
        unsafe {
            SelectedPageGate::new(
                checkpoint,
                vec![ImageFacts {
                    start: BASE,
                    bytes: self.image[..2 * PAGE].to_vec(),
                    heads,
                }],
                Policy::default(),
                SyscallAliases::default(),
                NativeProvider,
                TIMEOUT,
            )
            .unwrap()
        }
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
}

impl Evidence {
    fn check_own_pid(mut self, pid: libc::pid_t) -> Self {
        assert_eq!(
            self.registers.rax, pid as u64,
            "getpid must return this run's exact PID"
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

    fn write_registers(&self, registers: &RegisterSnapshot) {
        let raw: libc::user_regs_struct = (*registers).into();
        self.ptrace(libc::PTRACE_SETREGS, 0, (&raw const raw) as usize);
        assert_eq!(self.registers(), *registers);
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
        }
        assert_eq!(self.registers().rip, pc);
    }

    fn syscall(&mut self, fixture: &Fixture, number: u64) -> Evidence {
        for operation in [
            libc::PTRACE_SYSCALL_INFO_ENTRY,
            libc::PTRACE_SYSCALL_INFO_EXIT,
        ] {
            self.ptrace(libc::PTRACE_SYSCALL, 0, 0);
            let status = self.wait();
            assert!(libc::WIFSTOPPED(status));
            assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP | 0x80);
            assert_eq!(status >> 16, 0);
            // SAFETY: zero initialized output is filled by the kernel.
            let mut info: libc::ptrace_syscall_info = unsafe { std::mem::zeroed() };
            // SAFETY: the kernel receives valid writable output storage.
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
            assert_eq!(info.arch, 0xc000_003e);
            assert_eq!(
                info.instruction_pointer,
                fixture.site + fixture.encoding.len() as u64
            );
            assert_eq!(info.stack_pointer, STACK);
            if operation == libc::PTRACE_SYSCALL_INFO_ENTRY {
                // SAFETY: ENTRY authenticates the initialized union member.
                assert_eq!(unsafe { info.u.entry }.nr, number);
            } else {
                // SAFETY: EXIT authenticates the initialized union member.
                let exit = unsafe { info.u.exit };
                assert_eq!(exit.sval as u64, self.registers().rax);
                assert_eq!(exit.is_error != 0, number == libc::SYS_write as u64);
            }
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

#[test]
fn native_syscall_bridge_matches_independent_complete_state_without_tf_leakage() {
    for encoding in [&[0x0f, 0x05][..], &[0x66, 0x0f, 0x05], &[0x48, 0x0f, 0x05]] {
        for number in [libc::SYS_write as u64, libc::SYS_getpid as u64] {
            let fixture = Fixture::new(encoding, number);
            let mut native = Native::launch(&fixture);
            let native_completion = native.syscall(&fixture, number);
            native.ptrace(libc::PTRACE_CONT, 0, 0);
            native.marker(fixture.terminal, libc::SIGILL);
            let native_terminal = native.evidence();
            assert_eq!(&native.memory(DATA, 8)[..4], &0x12345678_u32.to_le_bytes());

            let mut process = fixture.controlled();
            let handle = pidfd(process.pid());
            let outcome = process
                .hold()
                .unwrap()
                .execute_native_syscall(fixture.site, encoding, TIMEOUT)
                .unwrap();
            let NativeSyscallOutcome::Completed(completion) = outcome else {
                panic!("expected native completion");
            };
            assert_eq!(completion.registers, process.read_registers().unwrap());
            assert_eq!(completion.xstate, process.read_xstate().unwrap());
            assert_eq!(
                completion.registers.rip,
                fixture.site + encoding.len() as u64
            );
            assert_eq!(
                completion.registers.rcx,
                fixture.site + encoding.len() as u64
            );
            assert_eq!(completion.registers.r11, FLAGS);
            assert_eq!(completion.registers.eflags, FLAGS);
            assert_eq!(completion.registers.orig_rax, number);
            assert_eq!(completion.registers.rsp, STACK);
            assert_eq!(completion.is_error, number == libc::SYS_write as u64);
            assert_eq!(
                completion.result,
                if number == libc::SYS_write as u64 {
                    -i64::from(libc::EFAULT)
                } else {
                    i64::from(process.pid())
                }
            );
            assert_eq!(
                process.read_memory(DATA, 8).unwrap(),
                [0; 8],
                "bridge executed application continuation"
            );
            assert_eq!(
                process.read_memory(BASE, 2 * PAGE).unwrap(),
                fixture.image[..2 * PAGE]
            );
            let controlled_completion = Evidence {
                registers: completion.registers,
                xstate: completion.xstate.clone(),
                stack: process.read_memory(STACK, 32).unwrap(),
            };
            let mut hold = process.hold().unwrap();
            hold.write_memory_checked(fixture.site, &encoding[..1], &[0xcc])
                .unwrap();
            hold.sync_core(TIMEOUT).unwrap();
            assert_eq!(hold.read_registers().unwrap(), completion.registers);
            assert_eq!(hold.read_xstate().unwrap(), completion.xstate);
            let ProcessEvent::Signal(stop) = process.resume_until_event(TIMEOUT).unwrap() else {
                panic!("missing original UD2");
            };
            assert_eq!(stop.signal, libc::SIGILL);
            assert_eq!(stop.instruction_pointer, fixture.terminal);
            let controlled_terminal = Evidence {
                registers: process.read_registers().unwrap(),
                xstate: process.read_xstate().unwrap(),
                stack: process.read_memory(STACK, 32).unwrap(),
            };
            assert_eq!(
                &process.read_memory(DATA, 8).unwrap()[..4],
                &0x12345678_u32.to_le_bytes()
            );
            for (actual, expected) in [
                (controlled_completion, native_completion),
                (controlled_terminal, native_terminal),
            ] {
                let (actual, expected) = if number == libc::SYS_getpid as u64 {
                    (
                        actual.check_own_pid(process.pid()),
                        expected.check_own_pid(native.pid()),
                    )
                } else {
                    (actual, expected)
                };
                assert_eq!(
                    actual, expected,
                    "native syscall state diverged for {encoding:02x?}"
                );
                let mut wrong = expected.clone();
                wrong.registers.r11 ^= 0x100;
                assert_ne!(actual, wrong, "TF contamination must fail");
                let mut wrong = expected.clone();
                wrong.registers.rcx += 1;
                assert_ne!(actual, wrong);
                let mut wrong = expected.clone();
                wrong.registers.eflags ^= 1;
                assert_ne!(actual, wrong);
                let mut wrong = expected.clone();
                wrong.registers.rsp += 16;
                assert_ne!(actual, wrong);
                let mut wrong = expected.clone();
                wrong.xstate[160] ^= 1;
                assert_ne!(actual, wrong);
                let mut wrong = expected;
                wrong.stack[0] ^= 1;
                assert_ne!(actual, wrong);
            }
            drop(process);
            assert_reaped(&handle);
        }
    }
}

#[test]
fn malformed_alias_stale_and_disallowed_syscalls_refuse_before_execution() {
    for encoding in [
        &[0x0f, 0x34][..],
        &[0xcd, 0x80],
        &[0xf0, 0x0f, 0x05],
        &[0x0f, 0x05, 0x90],
    ] {
        let fixture = Fixture::new(encoding, libc::SYS_getpid as u64);
        let mut process = fixture.controlled();
        let before = process.read_registers().unwrap();
        let extended = process.read_xstate().unwrap();
        assert!(matches!(
            process
                .hold()
                .unwrap()
                .execute_native_syscall(fixture.site, encoding, TIMEOUT),
            Err(LaunchError::Invalid(
                "requires one native SYSCALL instruction"
            ))
        ));
        assert_eq!(process.read_registers().unwrap(), before);
        assert_eq!(process.read_xstate().unwrap(), extended);
        assert_eq!(
            process.read_memory(BASE, 2 * PAGE).unwrap(),
            fixture.image[..2 * PAGE]
        );
        assert_eq!(process.read_memory(DATA, 8).unwrap(), [0; 8]);
    }
    for case in 0..5 {
        let fixture = Fixture::new(
            &[0x0f, 0x05],
            if case == 4 {
                libc::SYS_mmap as u64
            } else {
                libc::SYS_getpid as u64
            },
        );
        let mut process = fixture.controlled();
        if case == 3 {
            let mut registers = process.read_registers().unwrap();
            registers.eflags |= 0x100;
            process.hold().unwrap().write_registers(&registers).unwrap();
        }
        let before = process.read_registers().unwrap();
        let extended = process.read_xstate().unwrap();
        let (pc, bytes): (u64, &[u8]) = match case {
            0 => (fixture.site, &[]),
            1 => (fixture.site + 1, &[0x0f, 0x05]),
            2 => (fixture.site, &[0x66, 0x0f, 0x05]),
            _ => (fixture.site, &[0x0f, 0x05]),
        };
        assert!(matches!(
            process
                .hold()
                .unwrap()
                .execute_native_syscall(pc, bytes, TIMEOUT),
            Err(LaunchError::Invalid(_))
        ));
        assert_eq!(process.read_registers().unwrap(), before);
        assert_eq!(process.read_xstate().unwrap(), extended);
        assert_eq!(
            process.read_memory(BASE, 2 * PAGE).unwrap(),
            fixture.image[..2 * PAGE]
        );
        assert_eq!(process.read_memory(DATA, 8).unwrap(), [0; 8]);
    }
}

#[test]
fn native_exit_is_explicit_and_already_reaped() {
    let fixture = Fixture::new(&[0x0f, 0x05], libc::SYS_exit as u64);
    let mut process = fixture.controlled();
    let handle = pidfd(process.pid());
    assert_eq!(
        process
            .hold()
            .unwrap()
            .execute_native_syscall(fixture.site, &fixture.encoding, TIMEOUT)
            .unwrap(),
        NativeSyscallOutcome::Exited { code: 37 }
    );
    assert!(process.read_registers().is_err());
    assert_reaped(&handle);
}

#[test]
fn native_fetch_fault_is_explicit_and_never_acknowledged_as_completion() {
    let fixture = Fixture::new(&[0x0f, 0x05], libc::SYS_getpid as u64);
    let mut process = fixture.controlled();
    let handle = pidfd(process.pid());
    process
        .hold()
        .unwrap()
        .mprotect(BASE + PAGE as u64, PAGE, libc::PROT_READ, TIMEOUT)
        .unwrap();
    let NativeSyscallOutcome::ApplicationSignal {
        stop,
        registers,
        xstate,
    } = process
        .hold()
        .unwrap()
        .execute_native_syscall(fixture.site, &fixture.encoding, TIMEOUT)
        .unwrap()
    else {
        panic!("NX fetch must remain an application fault");
    };
    assert_eq!(stop.signal, libc::SIGSEGV);
    assert_eq!(stop.code, 2);
    assert_eq!(stop.address, Some(fixture.site));
    assert_eq!(registers.rip, fixture.site);
    assert_eq!(*registers, process.read_registers().unwrap());
    assert_eq!(xstate, process.read_xstate().unwrap());
    assert_eq!(process.read_memory(DATA, 8).unwrap(), [0; 8]);
    assert!(process.hold().unwrap().sync_core(TIMEOUT).is_err());
    assert!(process.resume_until_event(TIMEOUT).is_err());
    drop(process);
    assert_reaped(&handle);
}

#[test]
fn selected_page_native_syscalls_match_raw_completion_and_continuation() {
    for number in [libc::SYS_write as u64, libc::SYS_getpid as u64] {
        let fixture = Fixture::page(&[0x0f, 0x05], number);
        let mut native = Native::launch(&fixture);
        let before = native.evidence();
        let before_memory = native.memory(DATA, PAGE);
        assert_eq!(native.memory(BASE, 2 * PAGE), fixture.image[..2 * PAGE]);
        let expected_completion = native.syscall(&fixture, number);
        let completed_memory = native.memory(DATA, PAGE);
        native.ptrace(libc::PTRACE_CONT, 0, 0);
        native.marker(fixture.terminal, libc::SIGILL);
        let expected_terminal = native.evidence();
        let terminal_memory = native.memory(DATA, PAGE);

        let mut gate = fixture.gate();
        let handle = pidfd(gate.pid());
        let SelectedEvent::Completed(completion) = gate.next_event().unwrap() else {
            panic!("selected syscall must complete through its native owner");
        };
        assert_eq!(completion.execution, SelectedExecution::Native);
        assert_eq!(*completion.input.registers(), before.registers);
        assert_eq!(completion.before_xstate, before.xstate);
        assert_eq!(before_memory, completed_memory);
        assert_eq!(gate.read_memory(DATA, PAGE).unwrap(), completed_memory);
        assert_eq!(gate.read_registers().unwrap(), completion.after);
        assert_eq!(gate.read_xstate().unwrap(), completion.xstate);
        let actual_completion = Evidence {
            registers: completion.after,
            xstate: completion.xstate,
            stack: gate.read_memory(STACK, 32).unwrap(),
        };
        let mut patched = fixture.image[..2 * PAGE].to_vec();
        patched[(fixture.site - BASE) as usize] = 0xcc;
        assert_eq!(gate.read_memory(BASE, 2 * PAGE).unwrap(), patched);
        assert_eq!(gate.metrics().callbacks.get(&SiteClass::Syscall), Some(&1));
        assert_eq!(gate.metrics().callbacks.len(), 1);
        assert_eq!(gate.metrics().native_completions, 1);
        assert_eq!(gate.metrics().scripted_completions, 0);
        assert_eq!(gate.metrics().refusals, 0);
        let SelectedEvent::ApplicationSignal(signal) = gate.next_event().unwrap() else {
            panic!("the original continuation must reach its UD2");
        };
        assert_eq!(signal.signal, libc::SIGILL);
        assert_eq!(signal.registers.rip, fixture.terminal);
        assert!(signal.input.is_none());
        let actual_terminal = Evidence {
            registers: signal.registers,
            xstate: signal.xstate,
            stack: gate.read_memory(STACK, 32).unwrap(),
        };
        assert_eq!(gate.read_memory(DATA, PAGE).unwrap(), terminal_memory);
        for (actual, expected) in [
            (actual_completion, expected_completion),
            (actual_terminal, expected_terminal),
        ] {
            let (actual, expected) = if number == libc::SYS_getpid as u64 {
                (
                    actual.check_own_pid(gate.pid()),
                    expected.check_own_pid(native.pid()),
                )
            } else {
                (actual, expected)
            };
            assert_eq!(actual, expected);
        }
        assert!(gate.next_event().is_err());
        assert_eq!(gate.metrics().callbacks.get(&SiteClass::Syscall), Some(&1));
        drop(gate);
        assert_reaped(&handle);
    }
}

#[test]
fn selected_page_native_exit_has_one_dispatch_and_no_fabricated_completion() {
    let fixture = Fixture::page(&[0x0f, 0x05], libc::SYS_exit as u64);
    let mut gate = fixture.gate();
    let handle = pidfd(gate.pid());
    let SelectedEvent::Terminated { input, code } = gate.next_event().unwrap() else {
        panic!("selected exit must report actual termination");
    };
    assert_eq!(input.registers().rax, libc::SYS_exit as u64);
    assert_eq!(input.registers().rdi, 37);
    assert_eq!(input.instruction().logical_pc(), fixture.site);
    assert_eq!(code, 37);
    assert_eq!(gate.metrics().callbacks.get(&SiteClass::Syscall), Some(&1));
    assert_eq!(gate.metrics().native_completions, 0);
    assert_eq!(gate.metrics().scripted_completions, 0);
    assert_eq!(gate.metrics().refusals, 0);
    assert!(gate.next_event().is_err());
    assert_reaped(&handle);
}

#[test]
fn direct_native_syscall_preserves_rf_input_semantics_against_raw_oracle() {
    // This qualifies the direct native syscall bridge, not the inserted
    // pre-instruction trap in SelectedPageGate (whose contract excludes RF).
    let fixture = Fixture::new(&[0x0f, 0x05], libc::SYS_write as u64);
    let mut native = Native::launch(&fixture);
    let mut before = native.registers();
    before.eflags |= 1 << 16;
    native.write_registers(&before);
    let expected_completion = native.syscall(&fixture, libc::SYS_write as u64);
    let expected_completed_memory = native.memory(DATA, PAGE);
    native.ptrace(libc::PTRACE_CONT, 0, 0);
    native.marker(fixture.terminal, libc::SIGILL);
    let expected_terminal = native.evidence();
    let expected_terminal_memory = native.memory(DATA, PAGE);

    let mut process = fixture.controlled();
    process.hold().unwrap().write_registers(&before).unwrap();
    assert_eq!(process.read_registers().unwrap(), before);
    let NativeSyscallOutcome::Completed(completion) = process
        .hold()
        .unwrap()
        .execute_native_syscall(fixture.site, &fixture.encoding, TIMEOUT)
        .unwrap()
    else {
        panic!("RF-bearing syscall must produce an actual completed return");
    };
    assert_eq!(completion.result, -i64::from(libc::EFAULT));
    assert!(completion.is_error);
    assert_eq!(
        Evidence {
            registers: completion.registers,
            xstate: completion.xstate,
            stack: process.read_memory(STACK, 32).unwrap(),
        },
        expected_completion
    );
    assert_eq!(
        process.read_memory(DATA, PAGE).unwrap(),
        expected_completed_memory
    );
    let ProcessEvent::Signal(signal) = process.resume_until_event(TIMEOUT).unwrap() else {
        panic!("RF-bearing continuation must reach its original UD2");
    };
    assert_eq!(signal.signal, libc::SIGILL);
    assert_eq!(signal.instruction_pointer, fixture.terminal);
    assert_eq!(
        Evidence {
            registers: process.read_registers().unwrap(),
            xstate: process.read_xstate().unwrap(),
            stack: process.read_memory(STACK, 32).unwrap(),
        },
        expected_terminal
    );
    assert_eq!(
        process.read_memory(DATA, PAGE).unwrap(),
        expected_terminal_memory
    );
}
