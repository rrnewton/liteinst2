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
const INTERRUPT_ENV: &str = "LITEINST_SUD_INTERRUPT_CHILD";
static POSITIVE_STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static USR1_SEEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

extern "C" fn usr1_handler(_signal: i32) {
    USR1_SEEN.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}
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
        let disabled = libc::stack_t {
            ss_sp: std::ptr::null_mut(),
            ss_flags: libc::SS_DISABLE,
            ss_size: 0,
        };
        assert_eq!(
            unsafe { libc::sigaltstack(&disabled, std::ptr::null_mut()) },
            0
        );
        let token = installation.register_current_thread().unwrap();
        SECOND_READY.store(true, Ordering::Release);
        while !RELEASE_SECOND.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        let state = invoke(second_entry, libc::SYS_getpid as u32, [0; 6]);
        SECOND_RESULT.store(state[2], Ordering::Release);
        token.unregister().unwrap();
        let mut restored: libc::stack_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaltstack(std::ptr::null(), &mut restored) },
            0
        );
        assert_ne!(restored.ss_flags & libc::SS_DISABLE, 0);
        SECOND_DONE.store(true, Ordering::Release);
        state
    });
    while !SECOND_READY.load(Ordering::Acquire) {
        std::hint::spin_loop();
    }

    let registration = installation.register_current_thread()?;
    POSITIVE_STARTED.store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(registration.tid(), tid);
    match installation.register_current_thread() {
        Err(SyscallRefusal::ConflictingStrategyInstalled) => {}
        Err(error) => panic!("duplicate registration returned wrong refusal: {error:?}"),
        Ok(token) => {
            let _ = token.unregister();
            panic!("duplicate registration unexpectedly succeeded");
        }
    }
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

fn interrupt_child_main() -> Result<(), SyscallRefusal> {
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    let region = Region::new(page);
    let entry = region.address as usize;
    let (read_fd, write_fd) = pipe_pair();
    let mut byte = [0_u8; 1];
    let main_thread = unsafe { libc::pthread_self() } as u64;
    let signaler = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(
            unsafe { libc::pthread_kill(main_thread as libc::pthread_t, libc::SIGUSR1) },
            0
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
        // Fallback only: an incorrectly masked handler returns data instead
        // of -EINTR and the assertions below fail rather than hanging.
        unsafe { libc::write(write_fd, DATA.as_ptr().cast(), 1) };
    });

    let installation = SudInstallation::install(config())?;
    // The interrupting handler returns through the substrate gateway
    // restorer; an arbitrary libc restorer outside the gateway would itself
    // be dispatched as an unsupported rt_sigreturn site. Flags remain zero:
    // no SA_RESTART, so the forwarded read must observe -EINTR.
    #[repr(C)]
    struct KernelAction {
        handler: usize,
        flags: usize,
        restorer: usize,
        mask: u64,
    }
    let action = KernelAction {
        handler: usr1_handler as *const () as usize,
        flags: 0x0400_0000,
        restorer: (installation.gateway_range().0 + 32) as usize,
        mask: 0,
    };
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                libc::SIGUSR1,
                &action as *const KernelAction,
                std::ptr::null_mut::<KernelAction>(),
                8_usize,
            )
        },
        0
    );
    let registration = installation.register_current_thread()?;
    POSITIVE_STARTED.store(true, std::sync::atomic::Ordering::Release);
    let state = invoke(
        entry,
        libc::SYS_read as u32,
        [read_fd as u64, byte.as_mut_ptr() as u64, 1, 0, 0, 0],
    );
    assert_eq!(state[0], state[1]);
    assert_eq!(state[2], (-libc::EINTR as i64) as u64);
    assert_eq!(state[3], entry as u64 + 2);
    assert_eq!(state[4], state[5]);
    assert_eq!(USR1_SEEN.load(std::sync::atomic::Ordering::Acquire), 1);
    registration.unregister()?;
    installation.uninstall()?;
    signaler.join().unwrap();
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
    println!("SUD_INTERRUPT_POSITIVE eintr=-4 usr1=1");
    Ok(())
}

fn unsupported_child_main() -> Result<(), SyscallRefusal> {
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    let region = Region::new(page);
    let installation = SudInstallation::install(config())?;
    let registration = installation.register_current_thread()?;
    POSITIVE_STARTED.store(true, std::sync::atomic::Ordering::Release);
    // getuid is outside the first forwarding profile; handler must fail closed
    // with the selected refusal exit instead of forwarding it.
    let _ = invoke(region.address as usize, libc::SYS_getuid as u32, [0; 6]);
    registration.unregister()?;
    installation.uninstall()?;
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
    if std::env::var_os(INTERRUPT_ENV).is_some() {
        match interrupt_child_main() {
            Ok(()) => std::process::exit(0),
            Err(error) => {
                if POSITIVE_STARTED.load(std::sync::atomic::Ordering::Acquire) {
                    panic!("late interrupt-child failure after registration: {error:?}");
                }
                eprintln!("SUD_ENV_REFUSAL {error:?}");
                std::process::exit(42);
            }
        }
    }
    if std::env::var_os(UNSUPPORTED_ENV).is_some() {
        match unsupported_child_main() {
            Ok(()) => std::process::exit(44),
            Err(error) => {
                if POSITIVE_STARTED.load(std::sync::atomic::Ordering::Acquire) {
                    panic!("late unsupported-child failure after registration: {error:?}");
                }
                eprintln!("SUD_ENV_REFUSAL {error:?}");
                std::process::exit(42);
            }
        }
    }
    if std::env::var_os(CHILD_ENV).is_some() {
        match child_main() {
            Ok(()) => std::process::exit(0),
            Err(error) => {
                if POSITIVE_STARTED.load(std::sync::atomic::Ordering::Acquire) {
                    panic!("late SUD child failure after registration: {error:?}");
                }
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
    assert!(
        !String::from_utf8_lossy(&unsupported.stderr).contains("SUD_UNSUPPORTED_RETURNED"),
        "unsupported child returned instead of failing closed"
    );
}

#[test]
fn sud_blocking_read_preserves_signal_interruption() {
    if std::env::var_os(INTERRUPT_ENV).is_some() {
        match interrupt_child_main() {
            Ok(()) => std::process::exit(0),
            Err(error) => {
                if POSITIVE_STARTED.load(std::sync::atomic::Ordering::Acquire) {
                    panic!("late interrupt-child failure after registration: {error:?}");
                }
                eprintln!("SUD_ENV_REFUSAL {error:?}");
                std::process::exit(42);
            }
        }
    }
    let output = run_child(INTERRUPT_ENV);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        assert!(
            stdout.contains("SUD_INTERRUPT_POSITIVE eintr=-4 usr1=1"),
            "stdout={stdout} stderr={stderr}"
        );
        return;
    }
    assert_eq!(
        output.status.code(),
        Some(42),
        "stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("SUD_ENV_REFUSAL"),
        "stdout={stdout} stderr={stderr}"
    );
    eprintln!("sud interrupt positive not run: {stderr}");
}
