//! Fresh-process SUD trap-substrate test.
//!
//! The positive child installs SUD, registers two threads concurrently,
//! forwards first-profile syscalls, and unregisters/uninstalls cleanly. On a
//! host where prctl or handler custody is unavailable it exits 42 with the
//! named refusal; the parent never labels that as a positive trap run.
#![deny(unsafe_op_in_unsafe_fn)]

use liteinst_inprocess::syscall::sud::SudInstallation;
use liteinst_inprocess::syscall::{
    DiscoverySubstrate, SyscallRefusal, SyscallStrategy, SyscallStrategyConfig,
};
use std::ffi::c_void;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const CHILD_ENV: &str = "LITEINST_SUD_CHILD";
const UNSUPPORTED_ENV: &str = "LITEINST_SUD_UNSUPPORTED_CHILD";
const CODE: [u8; 12] = [
    0x0f, 0x05, 0xc3, 0x0f, 0x05, 0xc3, 0x0f, 0x05, 0xc3, 0x0f, 0x05, 0xc3,
];
const DATA: &[u8; 13] = b"sud-forward!!";

static SECOND_READY: AtomicBool = AtomicBool::new(false);
static RELEASE_SECOND: AtomicBool = AtomicBool::new(false);
static SECOND_DONE: AtomicBool = AtomicBool::new(false);
static SECOND_RESULT: AtomicU64 = AtomicU64::new(0);

core::arch::global_asm!(
    r#"
    .global sud_probe_invoke
    .type sud_probe_invoke, @function
sud_probe_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rsi
    mov r15, rdi
    mov qword ptr [rbx], rsp
    mov rdi, qword ptr [rbx + 104]
    mov rsi, qword ptr [rbx + 112]
    mov rdx, qword ptr [rbx + 120]
    mov r10, qword ptr [rbx + 128]
    mov r8, qword ptr [rbx + 136]
    mov r9, qword ptr [rbx + 144]
    mov eax, dword ptr [rbx + 96]
    mov ecx, 14
    cmp edi, edi
    call r15
    mov qword ptr [rbx + 8], rsp
    mov qword ptr [rbx + 16], rax
    mov qword ptr [rbx + 24], rcx
    mov qword ptr [rbx + 32], r11
    pushfq
    pop rax
    mov qword ptr [rbx + 40], rax
    mov qword ptr [rbx + 48], rdi
    mov qword ptr [rbx + 56], rsi
    mov qword ptr [rbx + 64], rdx
    mov qword ptr [rbx + 72], r10
    mov qword ptr [rbx + 80], r8
    mov qword ptr [rbx + 88], r9
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
"#
);

unsafe extern "C" {
    fn sud_probe_invoke(entry: usize, state: *mut u64);
}

struct Region {
    address: *mut u8,
    len: usize,
}

impl Region {
    fn new(page: usize) -> Self {
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(raw, libc::MAP_FAILED);
        let address = raw.cast::<u8>();
        unsafe { std::ptr::copy_nonoverlapping(CODE.as_ptr(), address, CODE.len()) };
        let region = Self { address, len: page };
        region.permissions(libc::PROT_READ | libc::PROT_EXEC);
        region
    }
    fn permissions(&self, flags: i32) {
        assert_eq!(
            unsafe { libc::mprotect(self.address.cast::<c_void>(), self.len, flags) },
            0
        );
    }
    fn bytes(&self) -> [u8; CODE.len()] {
        unsafe { std::ptr::read(self.address.cast::<[u8; CODE.len()]>()) }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.address.cast::<c_void>(), self.len) };
    }
}

fn invoke(entry: usize, nr: u32, args: [u64; 6]) -> [u64; 19] {
    let mut state = [0_u64; 19];
    state[12] = u64::from(nr);
    state[13..19].copy_from_slice(&args);
    unsafe { sud_probe_invoke(entry, state.as_mut_ptr()) };
    state
}

fn check(state: [u64; 19], entry: usize, expected: u64) {
    assert_eq!(state[0], state[1], "rsp round-trip");
    assert_eq!(state[2], expected, "syscall result");
    assert_eq!(state[3], entry as u64 + 2, "RCX");
    assert_eq!(state[4], state[5], "R11/flags");
    assert_eq!(&state[6..12], &state[13..19], "argument registers");
}

fn pipe_pair() -> (i32, i32) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    (fds[0], fds[1])
}

fn config() -> SyscallStrategyConfig {
    SyscallStrategyConfig::new(SyscallStrategy::Trap)
        .with_discovery(DiscoverySubstrate::Sud)
        .unwrap()
}

fn child_main() -> Result<(), SyscallRefusal> {
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    let region = Region::new(page);
    let base = region.address as usize;
    let entries = [base, base + 3, base + 6, base + 9];
    let pid = u64::try_from(unsafe { libc::getpid() }).unwrap();
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;

    let (read_fd, write_fd) = pipe_pair();
    let mut buffers = [[0_u8; DATA.len()]; 3];
    let mut preload = [0_u8; DATA.len() * 3];
    preload[0..13].copy_from_slice(&[b'A'; DATA.len()]);
    preload[13..26].copy_from_slice(&[b'B'; DATA.len()]);
    preload[26..39].copy_from_slice(&[b'C'; DATA.len()]);
    assert_eq!(
        unsafe { libc::write(write_fd, preload.as_ptr().cast(), preload.len()) },
        preload.len() as isize
    );

    // Native oracle phase before any SUD registration.
    check(
        invoke(
            entries[0],
            libc::SYS_read as u32,
            [
                read_fd as u64,
                buffers[0].as_mut_ptr() as u64,
                DATA.len() as u64,
                0,
                0,
                0,
            ],
        ),
        entries[0],
        DATA.len() as u64,
    );
    assert_eq!(&buffers[0], &[b'A'; DATA.len()]);

    let installation = SudInstallation::install(config())?;
    let installation_addr = (&installation as *const SudInstallation) as usize;
    let second_entry = entries[2];
    let second = std::thread::spawn(move || {
        // SAFETY: main retains the installation until this thread is joined
        // after both registrations drain in the ordered sequence below.
        let installation = unsafe { &*(installation_addr as *const SudInstallation) };
        let token = installation.register_current_thread().unwrap();
        SECOND_READY.store(true, Ordering::Release);
        while !RELEASE_SECOND.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        let state = invoke(second_entry, libc::SYS_getpid as u32, [0; 6]);
        SECOND_RESULT.store(state[2], Ordering::Release);
        token.unregister().unwrap();
        SECOND_DONE.store(true, Ordering::Release);
        state
    });
    while !SECOND_READY.load(Ordering::Acquire) {
        std::hint::spin_loop();
    }

    let registration = installation.register_current_thread()?;
    assert_eq!(registration.tid(), tid);
    // From here until unregister, avoid ordinary libc/Rust syscalls: only
    // the preallocated fixture invokes below and atomic spins.
    check(
        invoke(
            entries[0],
            libc::SYS_read as u32,
            [
                read_fd as u64,
                buffers[1].as_mut_ptr() as u64,
                DATA.len() as u64,
                0,
                0,
                0,
            ],
        ),
        entries[0],
        DATA.len() as u64,
    );
    check(
        invoke(
            entries[1],
            libc::SYS_write as u32,
            [
                write_fd as u64,
                DATA.as_ptr() as u64,
                DATA.len() as u64,
                0,
                0,
                0,
            ],
        ),
        entries[1],
        DATA.len() as u64,
    );
    check(
        invoke(entries[2], libc::SYS_getpid as u32, [0; 6]),
        entries[2],
        pid,
    );
    check(
        invoke(entries[3], libc::SYS_gettid as u32, [0; 6]),
        entries[3],
        tid,
    );
    RELEASE_SECOND.store(true, Ordering::Release);
    while !SECOND_DONE.load(Ordering::Acquire) {
        std::hint::spin_loop();
    }
    registration.unregister()?;

    let second_state = second.join().unwrap();
    check(second_state, entries[2], pid);
    assert_eq!(SECOND_RESULT.load(Ordering::Acquire), pid);
    assert_eq!(&buffers[1], &[b'B'; DATA.len()]);
    let counters = installation.counters();
    assert_eq!(counters.traps, 5, "{counters:?}");
    assert_eq!(counters.forwarded, 5, "{counters:?}");
    assert_eq!(counters.refused, 0, "{counters:?}");
    assert_eq!(counters.recorded_sites, 4, "{counters:?}");
    let sites = installation.sites();
    assert_eq!(sites.len(), 4);
    assert_eq!(
        sites.iter().map(|site| site.site_pc).collect::<Vec<_>>(),
        entries
            .iter()
            .map(|entry| *entry as u64)
            .collect::<Vec<_>>()
    );
    assert_eq!(sites[2].hits, 2);
    assert_eq!(region.bytes(), CODE);

    installation.uninstall()?;
    check(
        invoke(
            entries[0],
            libc::SYS_read as u32,
            [
                read_fd as u64,
                buffers[2].as_mut_ptr() as u64,
                DATA.len() as u64,
                0,
                0,
                0,
            ],
        ),
        entries[0],
        DATA.len() as u64,
    );
    assert_eq!(&buffers[2], &[b'C'; DATA.len()]);
    let mut written = [0_u8; DATA.len()];
    assert_eq!(
        unsafe { libc::read(read_fd, written.as_mut_ptr().cast(), written.len()) },
        DATA.len() as isize
    );
    assert_eq!(&written, DATA);
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
    println!("SUD_POSITIVE traps=5 forwarded=5 sites=4 pid={pid}");
    Ok(())
}

fn unsupported_child_main() -> Result<(), SyscallRefusal> {
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    let region = Region::new(page);
    let installation = SudInstallation::install(config())?;
    let _registration = installation.register_current_thread()?;
    // getuid is outside the first forwarding profile; handler must fail closed
    // with the selected refusal exit instead of forwarding it.
    let _ = invoke(region.address as usize, libc::SYS_getuid as u32, [0; 6]);
    eprintln!("SUD_UNSUPPORTED_RETURNED");
    std::process::exit(44);
}

fn run_child(env: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .env(env, "1")
        .args([
            "--exact",
            "sud_probe_positive_or_named_environment_refusal",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap()
}

#[test]
fn sud_probe_positive_or_named_environment_refusal() {
    if std::env::var_os(UNSUPPORTED_ENV).is_some() {
        match unsupported_child_main() {
            Ok(()) => std::process::exit(44),
            Err(error) => {
                eprintln!("SUD_ENV_REFUSAL {error:?}");
                std::process::exit(42);
            }
        }
    }
    if std::env::var_os(CHILD_ENV).is_some() {
        match child_main() {
            Ok(()) => std::process::exit(0),
            Err(error) => {
                eprintln!("SUD_ENV_REFUSAL {error:?}");
                std::process::exit(42);
            }
        }
    }

    let output = run_child(CHILD_ENV);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        assert!(
            stdout.contains("SUD_POSITIVE traps=5"),
            "stdout={stdout} stderr={stderr}"
        );
    } else {
        assert_eq!(
            output.status.code(),
            Some(42),
            "stdout={stdout} stderr={stderr}"
        );
        assert!(
            stderr.contains("SUD_ENV_REFUSAL SudUnavailable")
                || stderr.contains("SUD_ENV_REFUSAL SignalContract")
                || stderr.contains("SUD_ENV_REFUSAL CetUnsupported"),
            "stdout={stdout} stderr={stderr}"
        );
        eprintln!("sud positive not run: {stderr}");
        return;
    }

    let unsupported = run_child(UNSUPPORTED_ENV);
    assert_eq!(
        unsupported.status.code(),
        Some(126),
        "unsupported getuid must fail closed: stdout={} stderr={}",
        String::from_utf8_lossy(&unsupported.stdout),
        String::from_utf8_lossy(&unsupported.stderr)
    );
}
