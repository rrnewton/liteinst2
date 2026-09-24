#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! An observing hook must preserve addresses computed by displaced instructions.

use liteinst2::patcher::StalenessBudget;
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::{HookContext, HookSite, InstalledHook};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "LITEINST_PC_RELATIVE_CHILD";
const EVIDENCE_ENV: &str = "LITEINST_PC_RELATIVE_EVIDENCE";
const TEST: &str = "observing_hook_preserves_self_lea_address";
const COMPLETE: i32 = 102;
const PAGE: usize = 4096;
const SITE: usize = 128;
static CALLBACKS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn observe(_context: *mut HookContext) {
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
}

fn child_body() {
    // Process-lifetime aliases satisfy the patch registry's lifetime contract.
    let (writable, executable) = unsafe {
        let fd = libc::memfd_create(c"liteinst-pc-relative".as_ptr(), libc::MFD_CLOEXEC);
        assert!(fd >= 0);
        assert_eq!(libc::ftruncate(fd, PAGE as libc::off_t), 0);
        let writable = libc::mmap(
            ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        let executable = libc::mmap(
            ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_SHARED,
            fd,
            0,
        );
        assert_ne!(writable, libc::MAP_FAILED);
        assert_ne!(executable, libc::MAP_FAILED);
        assert_eq!(libc::close(fd), 0);
        (writable.cast::<u8>(), executable.cast::<u8>())
    };
    let mut image = [0x90_u8; 160];
    image[SITE - 4..SITE].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]); // ENDBR64
    // LEA computes the original instruction's address without reading code data.
    image[SITE..SITE + 8].copy_from_slice(&[0x48, 0x8d, 0x05, 0xf9, 0xff, 0xff, 0xff, 0xc3]);
    // SAFETY: initialization precedes execution and registration of either alias.
    unsafe { ptr::copy_nonoverlapping(image.as_ptr(), writable, image.len()) };
    let base = executable as u64;
    let expected = base + SITE as u64;
    // SAFETY: ENDBR64, LEA RAX,[RIP-7], RET is a no-argument C ABI function.
    let function: extern "C" fn() -> u64 = unsafe { std::mem::transmute(executable.add(SITE - 4)) };
    let native = function();
    assert_eq!(native, expected);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 0);
    let scanner = InstructionScanner::default();
    let scan = scanner.scan(&image, base).unwrap();
    let site = HookSite::new(&scanner, &scan, &image, base, expected, unsafe {
        writable.add(SITE)
    });
    // SAFETY: the aliases and callback live for the process lifetime; the
    // fixture has no interior control-flow entry and the callback does not unwind.
    let hook =
        unsafe { InstalledHook::install(site, observe, StalenessBudget::new(20_000).unwrap()) }
            .unwrap();
    let inactive = function();
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 0);
    println!("pc-relative-ready:site={expected:#x}");
    std::io::stdout().flush().unwrap();
    assert!(hook.activate().unwrap());
    let active = function();
    let active_callbacks = CALLBACKS.load(Ordering::Relaxed);
    assert!(hook.deactivate().unwrap());
    let deactivated = function();
    println!(
        "pc-relative-results:native={native:#x};inactive={inactive:#x};active={active:#x};deactivated={deactivated:#x};relocated={:#x};callbacks={active_callbacks}",
        hook.trampoline().relocated_tail_address(),
    );
    assert_eq!(inactive, expected);
    assert_eq!(deactivated, expected);
    assert_eq!(active_callbacks, 1);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);
    assert_eq!(
        active, expected,
        "an observing hook changed the LEA address"
    );
    println!("pc-relative-complete");
    std::io::stdout().flush().unwrap();
    unsafe { libc::_exit(COMPLETE) };
}

fn unique_evidence_root() -> PathBuf {
    let template = std::env::temp_dir().join("liteinst-pc-relative-XXXXXX");
    let mut bytes = template.as_os_str().as_bytes().to_vec();
    bytes.push(0);
    // SAFETY: the template is writable, NUL-terminated and ends in six Xs.
    assert!(!unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) }.is_null());
    bytes.pop();
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

#[test]
fn observing_hook_preserves_self_lea_address() {
    if std::env::var_os(CHILD_ENV).is_some() {
        child_body();
    }
    let retained = std::env::var_os(EVIDENCE_ENV);
    let root = retained
        .clone()
        .map_or_else(unique_evidence_root, PathBuf::from);
    std::fs::create_dir_all(&root).unwrap();
    let output = |name| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(name))
            .unwrap()
    };
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .env("RUST_BACKTRACE", "0")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(output("stdout"))
        .stderr(output("stderr"));
    // SAFETY: the post-fork closure performs only async-signal-safe setrlimit.
    unsafe {
        command.pre_exec(|| {
            for (resource, value) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_FSIZE, 64 * 1024)] {
                let limit = libc::rlimit {
                    rlim_cur: value,
                    rlim_max: value,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let start = Instant::now();
    let mut child = command.spawn().unwrap();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() >= Duration::from_secs(5) {
            timed_out = true;
            // SAFETY: the live child's dedicated process group is owned here.
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = std::fs::read_to_string(root.join("stdout")).unwrap();
    let stderr = std::fs::read_to_string(root.join("stderr")).unwrap();
    std::fs::write(
        root.join("status"),
        format!(
            "raw_status={}; code={:?}; signal={:?}; timeout={timed_out}; seconds={}\n",
            status.into_raw(),
            status.code(),
            status.signal(),
            start.elapsed().as_secs_f64(),
        ),
    )
    .unwrap();
    assert!(
        !timed_out
            && status.code() == Some(COMPLETE)
            && stdout.contains("pc-relative-ready:")
            && stdout.contains("pc-relative-complete"),
        "status={status}; timeout={timed_out}; evidence={}\nstdout: {stdout}\nstderr: {stderr}",
        root.display(),
    );
    if retained.is_none() {
        std::fs::remove_dir_all(root).unwrap();
    }
}
