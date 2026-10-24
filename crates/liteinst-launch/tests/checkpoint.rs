#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use liteinst_launch::{ExecCheckpoint, FirstImage, LaunchCommand, LaunchError, MAX_MEMORY_READ};

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
