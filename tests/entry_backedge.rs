#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! An observing hook must run on every visit to its application entry.

use liteinst2::patcher::StalenessBudget;
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::{HookContext, HookSite, InstalledHook};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "LITEINST_ENTRY_BACKEDGE_CHILD";
const EVIDENCE_ENV: &str = "LITEINST_ENTRY_BACKEDGE_EVIDENCE";
const TEST: &str = "observing_hook_runs_on_every_entry_backedge";
const COMPLETE: i32 = 102;
const PAGE: usize = 4096;
const SITE: usize = 128;
static CALLBACKS: AtomicUsize = AtomicUsize::new(0);
static TRACE: AtomicU64 = AtomicU64::new(0);
static SHORTEN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn observe(context: *mut HookContext) {
    // SAFETY: the trampoline supplies an exclusive live callback frame.
    let context = unsafe { &mut *context };
    let visit = CALLBACKS.fetch_add(1, Ordering::Relaxed);
    if visit < 8 {
        TRACE.fetch_or((context.rcx & 0xff) << (8 * visit), Ordering::Relaxed);
    }
    if SHORTEN.load(Ordering::Relaxed) && visit == 1 {
        context.rcx = 1;
    }
}

fn child_body() {
    // Process-lifetime aliases satisfy the patch registry's lifetime contract.
    let (writable, executable) = unsafe {
        let fd = libc::memfd_create(c"liteinst-entry-backedge".as_ptr(), libc::MFD_CLOEXEC);
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
    // ENDBR64; MOV ECX,EDI; XOR EAX,EAX initializes an independent native
    // iteration counter. The five-byte patch window is INC EAX; LOOP site; NOP.
    image[SITE - 8..SITE].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa, 0x89, 0xf9, 0x31, 0xc0]);
    image[SITE..SITE + 6].copy_from_slice(&[0xff, 0xc0, 0xe2, 0xfc, 0x90, 0xc3]);
    // SAFETY: initialization precedes execution and registration of either alias.
    unsafe { ptr::copy_nonoverlapping(image.as_ptr(), writable, image.len()) };
    let base = executable as u64;
    let entry = base + SITE as u64;
    // SAFETY: the fixture implements extern C fn(u32) -> u32 for positive inputs.
    let function: extern "C" fn(u32) -> u32 =
        unsafe { std::mem::transmute(executable.add(SITE - 8)) };
    let native = function(7);
    assert_eq!(native, 7);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 0);
    let scanner = InstructionScanner::default();
    let scan = scanner.scan(&image, base).unwrap();
    let site = HookSite::new(&scanner, &scan, &image, base, entry, unsafe {
        writable.add(SITE)
    });
    // SAFETY: the aliases and callback live for the process lifetime. The only
    // backedge targets the patch entry, never its interior; the hook cannot unwind.
    let hook =
        unsafe { InstalledHook::install(site, observe, StalenessBudget::new(20_000).unwrap()) }
            .unwrap();
    let inactive = function(7);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 0);
    println!("entry-backedge-ready:site={entry:#x};native={native};inactive={inactive}");
    std::io::stdout().flush().unwrap();
    assert!(hook.activate().unwrap());
    let active = function(7);
    let active_callbacks = CALLBACKS.load(Ordering::Relaxed);
    let active_trace = TRACE.load(Ordering::Relaxed);
    assert!(hook.deactivate().unwrap());
    let deactivated = function(7);
    println!(
        "entry-backedge-results:native={native};inactive={inactive};active={active};deactivated={deactivated};relocated={:#x};callbacks={active_callbacks};rcx_trace={active_trace:#x}",
        hook.trampoline().relocated_tail_address(),
    );
    assert_eq!(inactive, native);
    assert_eq!(active, native);
    assert_eq!(deactivated, native);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), active_callbacks);
    assert_eq!(
        active_callbacks, native as usize,
        "one callback per native entry visit"
    );
    assert_eq!(active_trace, 0x0001_0203_0405_0607);

    // A mutation on the second visit must affect the next displaced LOOP.
    CALLBACKS.store(0, Ordering::Relaxed);
    TRACE.store(0, Ordering::Relaxed);
    SHORTEN.store(true, Ordering::Relaxed);
    assert!(hook.activate().unwrap());
    let shortened = function(7);
    println!(
        "entry-backedge-mutation:result={shortened};callbacks={};rcx_trace={:#x}",
        CALLBACKS.load(Ordering::Relaxed),
        TRACE.load(Ordering::Relaxed)
    );
    assert_eq!(shortened, 2);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 2);
    assert_eq!(TRACE.load(Ordering::Relaxed), 0x0607);
    assert!(hook.deactivate().unwrap());
    assert_eq!(function(7), native);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 2);

    // Re-enabling restores per-visit observation after the previous deactivation.
    CALLBACKS.store(0, Ordering::Relaxed);
    TRACE.store(0, Ordering::Relaxed);
    SHORTEN.store(false, Ordering::Relaxed);
    assert!(hook.activate().unwrap());
    assert_eq!(function(3), 3);
    assert_eq!(CALLBACKS.load(Ordering::Relaxed), 3);
    assert_eq!(TRACE.load(Ordering::Relaxed), 0x010203);
    assert!(hook.deactivate().unwrap());

    println!("entry-backedge-complete");
    std::io::stdout().flush().unwrap();
    unsafe { libc::_exit(COMPLETE) };
}

fn unique_evidence_root() -> PathBuf {
    let template = std::env::temp_dir().join("liteinst-entry-backedge-XXXXXX");
    let mut bytes = template.as_os_str().as_bytes().to_vec();
    bytes.push(0);
    // SAFETY: the template is writable, NUL-terminated and ends in six Xs.
    assert!(!unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) }.is_null());
    bytes.pop();
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

#[test]
fn observing_hook_runs_on_every_entry_backedge() {
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
            && stdout.contains("entry-backedge-ready:")
            && stdout.contains("entry-backedge-complete"),
        "status={status}; timeout={timed_out}; evidence={}\nstdout: {stdout}\nstderr: {stderr}",
        root.display(),
    );
    if retained.is_none() {
        std::fs::remove_dir_all(root).unwrap();
    }
}
