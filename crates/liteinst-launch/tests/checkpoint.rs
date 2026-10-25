#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use liteinst_launch::{
    ExecCheckpoint, FirstImage, LaunchCommand, LaunchError, MAX_MEMORY_READ, ProcessEvent,
    SignalStop, StoppedProcess,
};
use liteinst2::contracts::{AddressRange, CodeIdentity, SourceIdentity};

const SEGV_ACCERR: i32 = 2;
const ENTRY_OFFSET: usize = 4096;
const IMAGE_LEN: usize = 8192;
const EXEC_BASE: u64 = 0x400000;
const FIRST_BYTES: [u8; 4] = [0x0f, 0xa2, 0x0f, 0x0b]; // CPUID; UD2.
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixtures(PathBuf);

impl Fixtures {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-tmp");
        fs::create_dir_all(&root).unwrap();
        for _ in 0..100 {
            let name = format!(
                "liteinst-launch-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            );
            let path = root.join(name);
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create fixture directory: {error}"),
            }
        }
        panic!("fixture directory allocation exhausted");
    }

    fn elf(&self, name: &str, pie: bool, interpreter: Option<&Path>) -> PathBuf {
        let mut image = vec![0_u8; IMAGE_LEN];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut image, 16, if pie { 3 } else { 2 });
        put16(&mut image, 18, 62);
        put32(&mut image, 20, 1);
        let base = if pie { 0 } else { EXEC_BASE };
        put64(&mut image, 24, base + ENTRY_OFFSET as u64);
        put64(&mut image, 32, 64);
        put16(&mut image, 52, 64);
        put16(&mut image, 54, 56);
        put16(&mut image, 56, if interpreter.is_some() { 2 } else { 1 });
        // One immutable RX PT_LOAD contains the ELF headers and original code.
        put32(&mut image, 64, 1);
        put32(&mut image, 68, 5);
        put64(&mut image, 80, base);
        put64(&mut image, 96, IMAGE_LEN as u64);
        put64(&mut image, 104, IMAGE_LEN as u64);
        put64(&mut image, 112, 4096);
        if let Some(interpreter) = interpreter {
            let name = interpreter.as_os_str().as_bytes();
            assert!(name.len() < 2048);
            put32(&mut image, 120, 3);
            put32(&mut image, 124, 4);
            put64(&mut image, 128, 512);
            put64(&mut image, 136, base + 512);
            put64(&mut image, 152, (name.len() + 1) as u64);
            put64(&mut image, 160, (name.len() + 1) as u64);
            put64(&mut image, 168, 1);
            image[512..512 + name.len()].copy_from_slice(name);
        }
        image[ENTRY_OFFSET..ENTRY_OFFSET + FIRST_BYTES.len()].copy_from_slice(&FIRST_BYTES);
        let path = self.0.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
            .unwrap();
        file.write_all(&image).unwrap();
        path
    }
}

impl Drop for Fixtures {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn put16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(image: &mut [u8], offset: usize, value: u64) {
    image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn checkpoint(path: &Path) -> ExecCheckpoint {
    ExecCheckpoint::launch(&LaunchCommand::new(path), Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("first-instruction checkpoint failed: {error}"))
}

fn assert_reaped(pid: libc::pid_t) {
    let mut status = 0;
    // SAFETY: this names only the formerly owned child, after checkpoint teardown.
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    assert_eq!(result, -1, "checkpoint left an unreaped child");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn static_executable_is_stopped_at_its_selected_first_instruction() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("static", false, None);
    let stopped = checkpoint(&path);
    assert_eq!(stopped.entries().first_image, FirstImage::Executable);
    assert_eq!(
        stopped.entries().executable_entry,
        EXEC_BASE + ENTRY_OFFSET as u64
    );
    assert_eq!(stopped.entries().interpreter_base, 0);
    let initial = *stopped.initial_registers();
    let bytes = stopped.read_memory(initial.rip, FIRST_BYTES.len()).unwrap();
    assert_eq!(bytes, FIRST_BYTES);
    assert_eq!(stopped.read_registers().unwrap(), initial);
    assert_eq!(
        stopped.read_memory(initial.rip, bytes.len()).unwrap(),
        bytes
    );
    let pid = stopped.pid();
    stopped.terminate().unwrap();
    assert_reaped(pid);
}

#[test]
fn pie_without_interpreter_uses_relocated_executable_entry() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("pie", true, None);
    let stopped = checkpoint(&path);
    assert_eq!(stopped.entries().first_image, FirstImage::Executable);
    assert_eq!(
        stopped.initial_registers().rip,
        stopped.entries().executable_entry
    );
    assert_eq!(
        stopped
            .read_memory(stopped.initial_registers().rip, 4)
            .unwrap(),
        FIRST_BYTES
    );
    let pid = stopped.pid();
    drop(stopped);
    assert_reaped(pid);
}

#[test]
fn custom_interpreter_and_main_both_retain_their_selected_first_instruction() {
    let fixtures = Fixtures::new();
    let interpreter = fixtures.elf("interpreter", true, None);
    let path = fixtures.elf("interpreted", false, Some(&interpreter));
    let stopped = checkpoint(&path);
    let entries = stopped.entries();
    assert_eq!(entries.first_image, FirstImage::Interpreter);
    assert_eq!(entries.interpreter.as_deref(), Some(interpreter.as_path()));
    assert_ne!(entries.interpreter_base, 0);
    assert_eq!(
        entries.initial_instruction,
        entries.interpreter_base + ENTRY_OFFSET as u64
    );
    assert_ne!(entries.initial_instruction, entries.executable_entry);
    assert_eq!(stopped.initial_registers().rip, entries.initial_instruction);
    assert_eq!(
        stopped.read_memory(entries.initial_instruction, 4).unwrap(),
        FIRST_BYTES
    );
    assert_eq!(
        stopped.read_memory(entries.executable_entry, 4).unwrap(),
        FIRST_BYTES
    );
    assert_eq!(
        &stopped.read_registers().unwrap(),
        stopped.initial_registers()
    );
    let pid = stopped.pid();
    drop(stopped);
    assert_reaped(pid);
}

#[test]
fn invalid_commands_and_exec_failures_are_reported() {
    let fixtures = Fixtures::new();
    let missing = LaunchCommand::new(fixtures.0.join("missing"));
    assert!(matches!(
        ExecCheckpoint::launch(&missing, Duration::from_secs(2)),
        Err(LaunchError::System { .. })
    ));
    let not_elf = fixtures.0.join("script");
    fs::write(&not_elf, b"#!/bin/sh\nexit 0\n").unwrap();
    assert!(ExecCheckpoint::launch(&LaunchCommand::new(not_elf), Duration::from_secs(2)).is_err());
    let path = fixtures.elf("no-execute", false, None);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let error = match ExecCheckpoint::launch(&LaunchCommand::new(path), Duration::from_secs(2)) {
        Err(error) => error,
        Ok(_) => panic!("non-executable ELF unexpectedly launched"),
    };
    assert!(
        matches!(error, LaunchError::System { operation: "child execve", source } if source.raw_os_error() == Some(libc::EACCES))
    );
}

#[test]
fn memory_and_timeout_bounds_refuse_without_resuming() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("bounds", false, None);
    let command = LaunchCommand::new(&path);
    assert!(matches!(
        ExecCheckpoint::launch(&command, Duration::ZERO),
        Err(LaunchError::Invalid(_))
    ));
    assert!(matches!(
        ExecCheckpoint::launch(&command, Duration::from_secs(31)),
        Err(LaunchError::Invalid(_))
    ));
    let stopped = checkpoint(&path);
    assert!(stopped.read_memory(0, MAX_MEMORY_READ + 1).is_err());
    assert!(stopped.read_memory(u64::MAX, 2).is_err());
    assert!(stopped.read_memory(0, 8).is_err());
    assert_eq!(
        &stopped.read_registers().unwrap(),
        stopped.initial_registers()
    );
    assert_eq!(
        stopped
            .read_memory(stopped.initial_registers().rip, 4)
            .unwrap(),
        FIRST_BYTES
    );
}

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

fn process(path: &Path) -> StoppedProcess {
    checkpoint(path)
        .into_stopped_process(CONTROL_TIMEOUT)
        .unwrap_or_else(|error| panic!("remote bootstrap failed: {error}"))
}

fn signal(event: ProcessEvent, expected: i32) -> SignalStop {
    match event {
        ProcessEvent::Signal(stop) => {
            assert_eq!(stop.signal, expected);
            stop
        }
        other => panic!("expected signal {expected}, got {other:?}"),
    }
}

fn replace_fixture_code(path: &Path, bytes: &[u8]) {
    let mut image = fs::read(path).unwrap();
    image[ENTRY_OFFSET..ENTRY_OFFSET + bytes.len()].copy_from_slice(bytes);
    fs::write(path, image).unwrap();
}

// Reserve a child-specific cleanup worker before launching the independent
// untraced baseline, so even a test panic cannot leave its child running.
struct NativeChild {
    child: Option<std::process::Child>,
    cleanup: std::sync::mpsc::SyncSender<std::process::Child>,
}

impl NativeChild {
    fn launch(path: &Path) -> Self {
        Self::launch_command(&mut std::process::Command::new(path))
    }

    fn launch_command(command: &mut std::process::Command) -> Self {
        let (cleanup, pending) = std::sync::mpsc::sync_channel::<std::process::Child>(1);
        std::thread::spawn(move || {
            if let Ok(mut child) = pending.recv() {
                let _ = child.kill();
                let _ = child.wait();
            }
        });
        let child = command.spawn().unwrap();
        Self {
            child: Some(child),
            cleanup,
        }
    }

    fn exit_code(&mut self) -> i32 {
        self.exit_status()
            .code()
            .expect("native fixture died from a signal")
    }

    fn exit_status(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        let child = self.child.as_mut().unwrap();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "native fixture timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

// This observer executes a fixture whose first instruction is already INT3.
// It does not use checkpoint capture, injected syscalls, or production readers.
fn independent_entry_xstate(path: &Path) -> Vec<u8> {
    let mut command = std::process::Command::new(path);
    // SAFETY: only raw ptrace and errno access occur between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut native = NativeChild::launch_command(&mut command);
    let pid = native.child.as_ref().unwrap().id() as libc::pid_t;
    let trace = |request: libc::c_uint, address: usize, data: usize| {
        // SAFETY: requests name only this helper's child, and data is either
        // an ABI scalar or a valid local output buffer for the named request.
        let result = unsafe { libc::ptrace(request, pid, address, data) };
        assert_ne!(
            result,
            -1,
            "native ptrace: {}",
            std::io::Error::last_os_error()
        );
    };
    for step in 0..2 {
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        let status = loop {
            let mut status = 0;
            // SAFETY: the native guard exclusively owns this named child.
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
            if result == pid {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    // Already reaped: Drop must never signal a reused PID.
                    native.child.take();
                    panic!("native entry fixture terminated before its trap");
                }
                break status;
            }
            if result == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    native.child.take();
                }
                assert_eq!(error.raw_os_error(), Some(libc::EINTR));
            }
            assert!(Instant::now() < deadline, "native entry trap timed out");
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        assert_eq!(status >> 16, 0);
        if step == 0 {
            trace(
                libc::PTRACE_SETOPTIONS,
                0_usize,
                libc::PTRACE_O_EXITKILL as usize,
            );
            trace(libc::PTRACE_CONT, 0, 0);
        }
    }
    let mut raw = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
    trace(libc::PTRACE_GETREGS, 0, raw.as_mut_ptr() as usize);
    // SAFETY: successful GETREGS initialized the complete local structure.
    let registers = unsafe { raw.assume_init() };
    assert_eq!(registers.rax, 0);
    assert_eq!(registers.orig_rax, u64::MAX);
    assert_eq!(registers.rip % 4096, 1);
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
    trace(libc::PTRACE_GETSIGINFO, 0, info.as_mut_ptr() as usize);
    // SAFETY: successful GETSIGINFO initialized the local structure.
    let info = unsafe { info.assume_init() };
    assert_eq!(info.si_signo, libc::SIGTRAP);
    assert!(matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT));
    let mut bytes = vec![0_u8; 64 * 1024];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    trace(libc::PTRACE_GETREGSET, 0x202, (&raw mut vector) as usize);
    assert!(vector.iov_len >= 512 && vector.iov_len < bytes.len());
    bytes.truncate(vector.iov_len);
    native.child.as_mut().unwrap().kill().unwrap();
    assert_eq!(native.exit_status().signal(), Some(libc::SIGKILL));
    assert_reaped(pid);
    bytes
}

impl Drop for NativeChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        if let Err(mut error) = self.cleanup.send(child) {
            // The reserved worker has no panicking operations. Retain ownership
            // and reap if its channel nevertheless closed unexpectedly.
            let _ = error.0.wait();
        }
    }
}

#[test]
fn first_execution_xstate_matches_independent_native_entry_trap() {
    let fixtures = Fixtures::new();
    let standalone = fixtures.elf("entry-state-static", false, None);
    replace_fixture_code(&standalone, &[0xcc]);
    let interpreter = fixtures.elf("entry-state-interpreter", true, None);
    replace_fixture_code(&interpreter, &[0xcc]);
    let interpreted = fixtures.elf("entry-state-main", false, Some(&interpreter));
    for path in [&standalone, &interpreted] {
        let native = independent_entry_xstate(path);
        let initial = checkpoint(path);
        let exec_event = initial.read_xstate().unwrap();
        let stopped = initial.into_stopped_process(CONTROL_TIMEOUT).unwrap();
        assert_eq!(stopped.exec_event_xstate(), exec_event);
        // Every byte, including PKRU and XSTATE_BV, comes from the independent
        // first-user trap. Restoring stale exec-stop state fails this oracle.
        assert_eq!(stopped.first_execution_xstate(), native);
        assert_eq!(stopped.read_xstate().unwrap(), native);
        let pid = stopped.pid();
        stopped.terminate().unwrap();
        assert_reaped(pid);
    }
}

#[test]
fn first_user_instruction_observes_natural_successful_exec_result() {
    let fixtures = Fixtures::new();
    // Capture entry EAX directly as the exit status, before any overwrite:
    // mov edi,eax; mov eax,exit; syscall.
    let code = [0x89, 0xc7, 0xb8, 60, 0, 0, 0, 0x0f, 0x05];
    let standalone = fixtures.elf("entry-rax-static", false, None);
    replace_fixture_code(&standalone, &code);
    let interpreter = fixtures.elf("entry-rax-interpreter", true, None);
    replace_fixture_code(&interpreter, &code);
    let interpreted = fixtures.elf("entry-rax-main", false, Some(&interpreter));
    for path in [&standalone, &interpreted] {
        let mut native = NativeChild::launch(path);
        let native_pid = native.child.as_ref().unwrap().id() as libc::pid_t;
        assert_eq!(native.exit_code(), 0);
        assert_reaped(native_pid);
        drop(native);

        let mut stopped = process(path);
        assert_eq!(
            stopped.exec_event_registers().rax,
            (-i64::from(libc::ENOSYS)) as u64
        );
        assert_eq!(stopped.first_execution_registers().rax, 0);
        let pid = stopped.pid();
        assert_eq!(
            stopped.resume_until_event(CONTROL_TIMEOUT).unwrap(),
            ProcessEvent::SyscallEntry {
                number: libc::SYS_exit as u64,
                arguments: [0; 6],
            }
        );
        assert_eq!(
            stopped.resume_until_event(CONTROL_TIMEOUT).unwrap(),
            ProcessEvent::Exited { code: 0 }
        );
        assert_reaped(pid);
    }
}

#[test]
fn syscall_island_bootstrap_preserves_original_code_gprs_and_xstate() {
    let fixtures = Fixtures::new();
    let interpreter = fixtures.elf("remote-interpreter", true, None);
    let path = fixtures.elf("remote-main", false, Some(&interpreter));
    let initial = checkpoint(&path);
    let registers = *initial.initial_registers();
    let extended = initial.read_xstate().unwrap();
    let original = initial.read_memory(registers.rip - 8, 32).unwrap();
    let main_entry = initial.entries().executable_entry;
    let main_bytes = initial.read_memory(main_entry, 32).unwrap();
    let stopped = initial.into_stopped_process(CONTROL_TIMEOUT).unwrap();
    assert_eq!(*stopped.exec_event_registers(), registers);
    assert_eq!(registers.rax, (-i64::from(libc::ENOSYS)) as u64);
    let mut first_execution = registers;
    first_execution.rax = 0;
    assert_eq!(*stopped.first_execution_registers(), first_execution);
    assert_eq!(stopped.read_registers().unwrap(), first_execution);
    assert_eq!(stopped.exec_event_xstate(), extended);
    assert_eq!(
        stopped.read_xstate().unwrap(),
        stopped.first_execution_xstate()
    );
    assert_eq!(
        stopped.read_memory(registers.rip - 8, 32).unwrap(),
        original
    );
    assert_eq!(stopped.read_memory(main_entry, 32).unwrap(), main_bytes);
    let island = stopped.island_range();
    assert_eq!(
        stopped.read_memory(island.start, 3).unwrap(),
        [0x0f, 0x05, 0xcc]
    );
    assert!(stopped.mappings().iter().any(|mapping| {
        mapping.start <= island.start
            && island.end <= mapping.end
            && mapping.permissions == "r-xp"
            && mapping.pathname.is_none()
    }));
    assert!(
        !stopped
            .initial_image_mappings()
            .iter()
            .any(|mapping| { mapping.start < island.end && island.start < mapping.end })
    );
    let pid = stopped.pid();
    stopped.terminate().unwrap();
    assert_reaped(pid);
}

#[test]
fn actual_nx_gate_requires_owned_fault_before_restoring_permissions() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-nx", false, None);
    let mut stopped = process(&path);
    let original_rip = stopped.read_registers().unwrap().rip;
    let original_xstate = stopped.read_xstate().unwrap();
    let images = stopped.gate_initial_images(CONTROL_TIMEOUT).unwrap();
    assert!(
        images
            .iter()
            .any(|mapping| mapping.pathname.as_deref() == Some("[vdso]"))
    );
    assert!(
        !images
            .iter()
            .any(|mapping| mapping.pathname.as_deref() == Some("[vsyscall]"))
    );
    for image in &images {
        let mut cursor = image.start;
        while cursor < image.end {
            let mapping = stopped
                .mappings()
                .iter()
                .find(|mapping| mapping.start <= cursor && cursor < mapping.end)
                .unwrap();
            assert_eq!(mapping.permissions.as_bytes()[2], b'-');
            cursor = mapping.end.min(image.end);
        }
    }
    let fault = signal(
        stopped.resume_until_event(CONTROL_TIMEOUT).unwrap(),
        libc::SIGSEGV,
    );
    assert_eq!(fault.code, SEGV_ACCERR);
    assert_eq!(fault.address, Some(original_rip));
    assert_eq!(fault.instruction_pointer, original_rip);
    assert!(stopped.resume_until_event(CONTROL_TIMEOUT).is_err());
    assert!(stopped.hold().unwrap().sync_core(CONTROL_TIMEOUT).is_err());
    assert!(
        stopped
            .hold()
            .unwrap()
            .mprotect(
                images[0].start,
                (images[0].end - images[0].start) as usize,
                libc::PROT_READ | libc::PROT_EXEC,
                CONTROL_TIMEOUT
            )
            .is_err()
    );
    assert_eq!(stopped.read_memory(original_rip, 4).unwrap(), FIRST_BYTES);
    stopped
        .hold()
        .unwrap()
        .acknowledge_owned_signal(&fault)
        .unwrap();
    stopped
        .restore_initial_permissions(CONTROL_TIMEOUT)
        .unwrap();
    stopped.hold().unwrap().sync_core(CONTROL_TIMEOUT).unwrap();
    assert!(
        stopped
            .hold()
            .unwrap()
            .acknowledge_owned_signal(&fault)
            .is_err()
    );
    assert_eq!(stopped.read_registers().unwrap().rip, original_rip);
    assert_eq!(stopped.read_xstate().unwrap(), original_xstate);
    let stepped = signal(
        stopped
            .hold()
            .unwrap()
            .single_step_until_event(CONTROL_TIMEOUT)
            .unwrap(),
        libc::SIGTRAP,
    );
    assert_eq!(stepped.instruction_pointer, original_rip + 2);
    assert_eq!(stepped.code, libc::TRAP_TRACE);
}

#[test]
fn checked_writes_and_island_guards_refuse_without_mutating_source() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-checked-write", false, None);
    let mut stopped = process(&path);
    let rip = stopped.read_registers().unwrap().rip;
    let original = stopped.read_memory(rip, 8).unwrap();
    let island = stopped.island_range();
    let page_size = stopped.page_size();
    let mut hold = stopped.hold().unwrap();
    assert!(hold.write_memory_checked(rip, &[0xcc], &[0x90]).is_err());
    assert_eq!(hold.read_memory(rip, 8).unwrap(), original);
    assert!(
        hold.write_memory_checked(island.start, &[0x0f], &[0xcc])
            .is_err()
    );
    assert!(
        hold.mprotect(
            island.start,
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            CONTROL_TIMEOUT
        )
        .is_err()
    );
    assert_eq!(
        hold.read_memory(island.start, 3).unwrap(),
        [0x0f, 0x05, 0xcc]
    );
    hold.write_memory_checked(rip, &original[..1], &[0xcc])
        .unwrap();
    assert_eq!(
        hold.read_memory(rip, 8).unwrap(),
        [&[0xcc][..], &original[1..]].concat()
    );
    hold.write_memory_checked(rip, &[0xcc], &original[..1])
        .unwrap();
    hold.sync_core(CONTROL_TIMEOUT).unwrap();
    assert_eq!(hold.read_memory(rip, 8).unwrap(), original);
}

#[test]
fn unapproved_syscall_is_refused_before_kernel_execution_and_reaped() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-denied-syscall", false, None);
    replace_fixture_code(
        &path,
        &[0xb8, libc::SYS_fork as u8, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b],
    );
    let mut stopped = process(&path);
    let pid = stopped.pid();
    let error = stopped.resume_until_event(CONTROL_TIMEOUT).unwrap_err();
    assert!(matches!(
        error,
        LaunchError::Invalid("syscall is outside the single-task launch allowlist")
    ));
    assert!(stopped.read_registers().is_err());
    assert_reaped(pid);
}

#[test]
fn raw_getpid_and_exit_single_steps_report_exact_kernel_events() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-syscall-step", false, None);
    // mov eax,getpid; syscall; mov eax,exit; xor edi,edi; syscall.
    replace_fixture_code(
        &path,
        &[
            0xb8,
            libc::SYS_getpid as u8,
            0,
            0,
            0,
            0x0f,
            0x05,
            0xb8,
            libc::SYS_exit as u8,
            0,
            0,
            0,
            0x31,
            0xff,
            0x0f,
            0x05,
        ],
    );
    let mut stopped = process(&path);
    let entry = stopped.entries().executable_entry;
    let pid = stopped.pid();
    for expected_offset in [5, 7, 12, 14] {
        let before = stopped.read_registers().unwrap();
        let event = signal(
            stopped
                .hold()
                .unwrap()
                .single_step_until_event(CONTROL_TIMEOUT)
                .unwrap(),
            libc::SIGTRAP,
        );
        assert_eq!(event.instruction_pointer, entry + expected_offset);
        assert_eq!(
            event.code,
            if expected_offset == 7 {
                libc::TRAP_BRKPT
            } else {
                libc::TRAP_TRACE
            },
            "step offset {expected_offset}"
        );
        if expected_offset == 7 {
            let after = stopped.read_registers().unwrap();
            assert_eq!(after.rax, pid as u64);
            assert_eq!(after.rcx, entry + expected_offset);
            assert_eq!(after.orig_rax, libc::SYS_getpid as u64);
            assert_eq!(after.eflags, before.eflags);
            // Raw ptrace stepping leaks its installed TF through SYSCALL's
            // R11 output. This fixture does not qualify no-op observation.
            assert_eq!(before.eflags & 0x100, 0);
            assert_eq!(after.r11, before.eflags | 0x100);
        }
        stopped
            .hold()
            .unwrap()
            .acknowledge_owned_signal(&event)
            .unwrap();
    }
    assert_eq!(
        stopped
            .hold()
            .unwrap()
            .single_step_until_event(CONTROL_TIMEOUT)
            .unwrap(),
        ProcessEvent::Exited { code: 0 }
    );
    assert_reaped(pid);
}

#[test]
fn unknown_signal_cannot_be_suppressed_as_an_owned_fault() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-unowned-signal", false, None);
    let mut stopped = process(&path);
    let pid = stopped.pid();
    // SAFETY: this deliberately signals only the owned stopped fixture child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGUSR1) }, 0);
    let event = signal(
        stopped.resume_until_event(CONTROL_TIMEOUT).unwrap(),
        libc::SIGUSR1,
    );
    assert!(
        stopped
            .hold()
            .unwrap()
            .acknowledge_owned_signal(&event)
            .is_err()
    );
    assert!(stopped.resume_until_event(CONTROL_TIMEOUT).is_err());
    stopped.terminate().unwrap();
    assert_reaped(pid);
}

#[test]
fn resumed_loop_timeout_kills_and_reaps_the_owned_child() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-timeout", false, None);
    replace_fixture_code(&path, &[0xeb, 0xfe]);
    let mut stopped = process(&path);
    let pid = stopped.pid();
    assert!(matches!(
        stopped.resume_until_event(Duration::from_millis(10)),
        Err(LaunchError::Timeout(_))
    ));
    assert!(stopped.read_registers().is_err());
    assert_reaped(pid);
}

#[test]
fn application_jump_to_private_syscall_island_is_refused() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-island-entry", false, None);
    let mut stopped = process(&path);
    let entry = stopped.entries().executable_entry;
    let island = stopped.island_range();
    // movabs r11,island; mov eax,getpid; jmp r11.
    let mut code = vec![0x49, 0xbb];
    code.extend_from_slice(&island.start.to_le_bytes());
    code.extend_from_slice(&[0xb8, libc::SYS_getpid as u8, 0, 0, 0, 0x41, 0xff, 0xe3]);
    let original = stopped.read_memory(entry, code.len()).unwrap();
    let mut hold = stopped.hold().unwrap();
    hold.write_memory_checked(entry, &original, &code).unwrap();
    hold.sync_core(CONTROL_TIMEOUT).unwrap();
    let pid = stopped.pid();
    assert!(matches!(
        stopped.resume_until_event(CONTROL_TIMEOUT),
        Err(LaunchError::Invalid(
            "application entered private syscall island"
        ))
    ));
    assert_reaped(pid);
}

fn unused_code_address(stopped: &StoppedProcess, len: usize) -> u64 {
    for candidate in (0x1000_0000_u64..0x2000_0000).step_by(0x10000) {
        if stopped
            .mappings()
            .iter()
            .all(|mapping| candidate + len as u64 <= mapping.start || mapping.end <= candidate)
        {
            return candidate;
        }
    }
    panic!("no bounded test allocation gap");
}

#[test]
fn exact_code_allocation_initializes_offsets_and_refuses_collisions() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-fixed-code", false, None);
    let mut stopped = process(&path);
    let page = stopped.page_size();
    let address = unused_code_address(&stopped, page * 3);
    let mut image = vec![0_u8; page * 2];
    image[17..20].copy_from_slice(&[0x0f, 0xa2, 0xc3]);
    image[page + 31..page + 34].copy_from_slice(&[0x90, 0x90, 0xc3]);
    let registers = stopped.read_registers().unwrap();
    let extended = stopped.read_xstate().unwrap();
    let original_entry = stopped.entries().executable_entry;
    let original = stopped.read_memory(original_entry, 32).unwrap();
    let island = stopped.island_range();
    let mut hold = stopped.hold().unwrap();
    assert_eq!(
        hold.map_private_code(address, &image, CONTROL_TIMEOUT)
            .unwrap(),
        address..address + image.len() as u64
    );
    assert_eq!(hold.read_memory(address, image.len()).unwrap(), image);
    assert!(hold.mappings().iter().any(|mapping| {
        mapping.start <= address
            && address + image.len() as u64 <= mapping.end
            && mapping.permissions == "r-xp"
            && mapping.pathname.is_none()
    }));
    assert!(
        hold.map_private_code(address, &vec![0xcc; page], CONTROL_TIMEOUT)
            .is_err()
    );
    assert!(
        hold.map_private_code(EXEC_BASE, &vec![0xcc; page], CONTROL_TIMEOUT)
            .is_err()
    );
    assert!(
        hold.map_private_code(island.start, &vec![0xcc; page], CONTROL_TIMEOUT)
            .is_err()
    );
    assert!(
        hold.map_private_code(address + 1, &image, CONTROL_TIMEOUT)
            .is_err()
    );
    assert!(hold.map_private_code(0, &image, CONTROL_TIMEOUT).is_err());
    assert!(
        hold.map_private_code(address + 0x10000, &[], CONTROL_TIMEOUT)
            .is_err()
    );
    assert!(
        hold.map_private_code(address + 0x10000, &image[..page - 1], CONTROL_TIMEOUT)
            .is_err()
    );
    assert!(
        hold.map_private_code(
            address + 0x10000,
            &vec![0; MAX_MEMORY_READ + page],
            CONTROL_TIMEOUT
        )
        .is_err()
    );
    assert_eq!(hold.read_memory(address, image.len()).unwrap(), image);
    assert_eq!(
        hold.read_memory(original_entry, original.len()).unwrap(),
        original
    );
    assert_eq!(hold.read_registers().unwrap(), registers);
    assert_eq!(hold.read_xstate().unwrap(), extended);
    let pid = hold.pid();
    stopped.terminate().unwrap();
    assert_reaped(pid);
}

#[test]
fn exact_native_stores_cover_all_widths_alignments_and_page_splits() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-width-stores", false, None);
    let mut stopped = process(&path);
    let page = stopped.page_size();
    let address = unused_code_address(&stopped, page * 3);
    let island = stopped.island_range();
    let registers = stopped.read_registers().unwrap();
    let extended = stopped.read_xstate().unwrap();
    let mut image = vec![0xa5_u8; page * 2];
    let mut hold = stopped.hold().unwrap();
    hold.map_private_code(address, &image, CONTROL_TIMEOUT)
        .unwrap();
    hold.mprotect(
        address,
        image.len(),
        libc::PROT_READ | libc::PROT_WRITE,
        CONTROL_TIMEOUT,
    )
    .unwrap();
    for (offset, bytes) in [
        (16, &[0x88, 0x07, 0xcc][..]),
        (32, &[0x66, 0x89, 0x07, 0xcc][..]),
        (48, &[0x89, 0x07, 0xcc][..]),
        (64, &[0x48, 0x89, 0x07, 0xcc][..]),
    ] {
        assert_eq!(
            hold.read_memory(island.start + offset, bytes.len())
                .unwrap(),
            bytes
        );
    }
    for width in [1_usize, 2, 4, 8] {
        let offsets = (64..80).chain((1..width).map(|split| page - split));
        for offset in offsets {
            let expected = image[offset..offset + width].to_vec();
            let replacement: Vec<u8> = (0..width)
                .map(|index| {
                    (offset as u8)
                        .wrapping_add(index as u8)
                        .wrapping_add(width as u8)
                })
                .collect();
            hold.exact_store_checked(
                address + offset as u64,
                &expected,
                &replacement,
                CONTROL_TIMEOUT,
            )
            .unwrap();
            image[offset..offset + width].copy_from_slice(&replacement);
            assert_eq!(hold.read_memory(address, image.len()).unwrap(), image);
            assert_eq!(hold.read_registers().unwrap(), registers);
            assert_eq!(hold.read_xstate().unwrap(), extended);
        }
    }
    hold.sync_core(CONTROL_TIMEOUT).unwrap();
    hold.mprotect(
        address,
        image.len(),
        libc::PROT_READ | libc::PROT_EXEC,
        CONTROL_TIMEOUT,
    )
    .unwrap();
    assert_eq!(hold.read_registers().unwrap(), registers);
    assert_eq!(hold.read_xstate().unwrap(), extended);
    let pid = hold.pid();
    stopped.terminate().unwrap();
    assert_reaped(pid);
}

#[test]
fn exact_stores_reject_stale_rx_readonly_island_and_unmapped_ranges() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-store-refusal", false, None);
    let mut stopped = process(&path);
    let page = stopped.page_size();
    let address = unused_code_address(&stopped, page * 2);
    let island = stopped.island_range();
    let image = vec![0x5a; page];
    let mut hold = stopped.hold().unwrap();
    hold.map_private_code(address, &image, CONTROL_TIMEOUT)
        .unwrap();
    assert!(
        hold.exact_store_checked(address, &[0x5a], &[0x42], CONTROL_TIMEOUT)
            .is_err()
    );
    assert!(
        hold.exact_store_checked(island.start, &[0x0f], &[0x42], CONTROL_TIMEOUT)
            .is_err()
    );
    hold.mprotect(address, page, libc::PROT_READ, CONTROL_TIMEOUT)
        .unwrap();
    assert!(
        hold.exact_store_checked(address, &[0x5a], &[0x42], CONTROL_TIMEOUT)
            .is_err()
    );
    hold.mprotect(
        address,
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        CONTROL_TIMEOUT,
    )
    .unwrap();
    assert!(
        hold.exact_store_checked(address, &[0xff], &[0x42], CONTROL_TIMEOUT)
            .is_err()
    );
    for width in [0, 3, 16] {
        assert!(
            hold.exact_store_checked(
                address,
                &vec![0x5a; width],
                &vec![0x42; width],
                CONTROL_TIMEOUT
            )
            .is_err()
        );
    }
    assert!(
        hold.exact_store_checked(address, &[0x5a], &[0x42; 2], CONTROL_TIMEOUT)
            .is_err()
    );
    assert!(
        hold.exact_store_checked(
            address + page as u64 - 4,
            &[0x5a; 8],
            &[0x42; 8],
            CONTROL_TIMEOUT
        )
        .is_err()
    );
    assert!(
        hold.exact_store_checked(u64::MAX - 3, &[0x5a; 8], &[0x42; 8], CONTROL_TIMEOUT)
            .is_err()
    );
    assert_eq!(hold.read_memory(address, image.len()).unwrap(), image);
    assert_eq!(
        hold.read_memory(island.start, 3).unwrap(),
        [0x0f, 0x05, 0xcc]
    );
    let pid = hold.pid();
    stopped.terminate().unwrap();
    assert_reaped(pid);
}

#[test]
fn exact_store_from_resume_flag_state_restores_every_register_and_neighbor() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-store-resume-flag", false, None);
    let mut stopped = process(&path);
    let page = stopped.page_size();
    let address = unused_code_address(&stopped, page);
    let extended = stopped.read_xstate().unwrap();
    let mut image = vec![0xa5; page];
    let mut hold = stopped.hold().unwrap();
    hold.map_private_code(address, &image, CONTROL_TIMEOUT)
        .unwrap();
    hold.mprotect(
        address,
        page,
        libc::PROT_READ | libc::PROT_WRITE,
        CONTROL_TIMEOUT,
    )
    .unwrap();
    let mut registers = hold.read_registers().unwrap();
    registers.eflags |= 0x10000; // RF is present at an instruction-fetch fault.
    hold.write_registers(&registers).unwrap();
    hold.exact_store_checked(address + 7, &[0xa5; 2], &[0xe9, 0x42], CONTROL_TIMEOUT)
        .unwrap();
    image[7..9].copy_from_slice(&[0xe9, 0x42]);
    assert_eq!(hold.read_memory(address, image.len()).unwrap(), image);
    assert_eq!(hold.read_registers().unwrap(), registers);
    assert_eq!(hold.read_xstate().unwrap(), extended);
    let pid = hold.pid();
    stopped.terminate().unwrap();
    assert_reaped(pid);
}

fn lease_identity() -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([7; 32]),
        mapping: 1,
        generation: 1,
    }
}

#[test]
fn core_lease_borrows_real_stop_and_preserves_state_on_success() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-core-lease", false, None);
    let mut stopped = process(&path);
    let page = stopped.page_size();
    let address = unused_code_address(&stopped, page * 2);
    let registers = stopped.read_registers().unwrap();
    let extended = stopped.read_xstate().unwrap();
    let range = AddressRange::new(address, page).unwrap();
    let mut hold = stopped.hold().unwrap();
    // SAFETY: the declared fixture has one exclusively held task, no aliases,
    // external accesses, handlers, saved resumes, or references to this unused
    // generated range. Only narrow island operations run within the lease.
    unsafe {
        hold.with_core_lease(lease_identity(), vec![range], |ops, lease| {
            assert_eq!(lease.identity(), lease_identity());
            assert!(lease.covers(range));
            assert_eq!(ops.read_registers()?, registers);
            assert_eq!(ops.read_xstate()?, extended);
            ops.map_private_code(address, &vec![0; page], CONTROL_TIMEOUT)?;
            ops.mprotect(
                address,
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                CONTROL_TIMEOUT,
            )?;
            ops.exact_store_checked(address + 3, &[0; 4], &[1, 2, 3, 4], CONTROL_TIMEOUT)?;
            ops.sync_core(CONTROL_TIMEOUT)?;
            ops.mprotect(
                address,
                page,
                libc::PROT_READ | libc::PROT_EXEC,
                CONTROL_TIMEOUT,
            )?;
            Ok(())
        })
    }
    .unwrap();
    assert_eq!(hold.read_registers().unwrap(), registers);
    assert_eq!(hold.read_xstate().unwrap(), extended);
    let pid = hold.pid();
    stopped.terminate().unwrap();
    assert_reaped(pid);
}

#[test]
fn core_lease_error_poison_and_panic_kill_and_reap() {
    let fixtures = Fixtures::new();
    let path = fixtures.elf("remote-core-lease-failure", false, None);
    for failure in 0..3 {
        let mut stopped = process(&path);
        let pid = stopped.pid();
        let page = stopped.page_size();
        let address = unused_code_address(&stopped, page);
        let range = AddressRange::new(address, page).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: same closed-world fixture ownership as the success case;
            // each failure happens while its sole task remains excluded.
            unsafe {
                stopped.hold().unwrap().with_core_lease(
                    lease_identity(),
                    vec![range],
                    |ops, lease| {
                        ops.map_private_code(address, &vec![0; page], CONTROL_TIMEOUT)?;
                        match failure {
                            0 => {
                                lease.poison();
                                Err(LaunchError::Invalid("injected publication failure"))
                            }
                            1 => {
                                lease.poison();
                                Ok(())
                            }
                            _ => panic!("injected publication unwind"),
                        }
                    },
                )
            }
        }));
        match result {
            Ok(result) => match failure {
                0 => assert!(matches!(
                    result,
                    Err(LaunchError::Invalid("injected publication failure"))
                )),
                1 => assert!(matches!(
                    result,
                    Err(LaunchError::Invalid(
                        "core publication lease remained poisoned"
                    ))
                )),
                _ => panic!("publication panic was swallowed"),
            },
            Err(_) => assert_eq!(failure, 2),
        }
        assert!(stopped.read_registers().is_err());
        assert_reaped(pid);
    }
}
