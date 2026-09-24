#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Application-generated SIGTRAP must not be mistaken for a patch guard.

use liteinst2::patcher::{JumpPatchPlan, LiveJumpPatch, PatchStrategy, StalenessBudget};
use liteinst2::scanner::InstructionScanner;
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "LITEINST_SIGTRAP_ORIGIN_CHILD";
const EVIDENCE_ENV: &str = "LITEINST_SIGTRAP_ORIGIN_EVIDENCE";
const COMPLETE: i32 = 102;
const OUTPUT_LIMIT: u64 = 64 * 1024;
const PAGE: usize = 4096;
const ENTRY: usize = 51;
const SITE: usize = 60;

fn child_body(mode: &str) {
    let ignored = mode.starts_with("ignore");
    let bound = mode.ends_with("bound");
    // SAFETY: the isolated child owns SIGTRAP and installs an admitted sentinel.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = if ignored {
            libc::SIG_IGN
        } else {
            libc::SIG_DFL
        };
        assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
        assert_eq!(libc::sigaction(libc::SIGTRAP, &action, ptr::null_mut()), 0);
    }

    // These dual aliases deliberately live until this isolated process exits,
    // as required by a concurrent patch registration's lifetime contract.
    let (writable, executable) = unsafe {
        let fd = libc::memfd_create(c"liteinst-sigtrap-origin".as_ptr(), libc::MFD_CLOEXEC);
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
    image[ENTRY..ENTRY + 4].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]); // ENDBR64
    image[ENTRY + 4] = 0xb8; // mov eax, SYS_tgkill
    image[ENTRY + 5..SITE].copy_from_slice(&(libc::SYS_tgkill as u32).to_le_bytes());
    // Native execution returns tgkill's zero result. An incorrect RIP-1 retry
    // starts at 05 and executes add eax,0xc3909090 followed by the second RET.
    image[SITE..SITE + 8].copy_from_slice(&[0x0f, 0x05, 0x90, 0x90, 0x90, 0xc3, 0xc3, 0x90]);
    image[128] = 0xc3; // Valid unused jump target; this test never applies a patch.
    // SAFETY: initialization precedes execution and registration of either alias.
    unsafe { ptr::copy_nonoverlapping(image.as_ptr(), writable, image.len()) };
    let patch = if bound {
        let scanner = InstructionScanner::default();
        let base = executable as u64;
        let scan = scanner.scan(&image, base).unwrap();
        let plan = JumpPatchPlan::from_scan(
            &scanner,
            &scan,
            &image,
            base,
            base + SITE as u64,
            base + 128,
        )
        .unwrap();
        assert_eq!(
            plan.strategy(),
            PatchStrategy::GuardedSplit {
                front_len: 4,
                back_len: 4
            }
        );
        // SAFETY: the complete aligned envelope has process-lifetime aliases.
        // No publication is performed, so this budget is never consumed.
        Some(
            unsafe {
                LiveJumpPatch::bind(
                    plan,
                    writable.add(SITE),
                    StalenessBudget::new(20_000).unwrap(),
                )
            }
            .unwrap(),
        )
    } else {
        None
    };
    // SAFETY: ENTRY starts an ENDBR64 function implementing tgkill with the
    // three integer arguments in the x86-64 C ABI registers. The syscall changes
    // caller-clobbered RAX, RCX and R11, preserving the C ABI.
    let function: extern "C" fn(libc::pid_t, libc::pid_t, libc::c_int) -> u32 =
        unsafe { std::mem::transmute(executable.add(ENTRY)) };
    let pid = unsafe { libc::getpid() };
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
    println!("sigtrap-origin-ready:{mode}");
    std::io::stdout().flush().unwrap();
    let result = function(pid, tid, libc::SIGTRAP);
    println!("sigtrap-origin-return:{mode}:{result:#x}");
    if !ignored {
        // A swallowed default-action signal must not masquerade as completion.
        std::io::stdout().flush().unwrap();
        unsafe { libc::_exit(103) };
    }
    assert_eq!(
        result, 0,
        "an ignored application SIGTRAP changed the return value"
    );
    if let Some(patch) = patch {
        assert_eq!(
            patch.handled_guard_traps(),
            0,
            "application signal counted as a guard"
        );
    }
    println!("sigtrap-origin-complete:{mode}");
    std::io::stdout().flush().unwrap();
    unsafe { libc::_exit(COMPLETE) };
}

fn unique_evidence_root() -> PathBuf {
    let template = std::env::temp_dir().join("liteinst-sigtrap-origin-XXXXXX");
    let mut bytes = template.as_os_str().as_bytes().to_vec();
    bytes.push(0);
    // SAFETY: the template is writable, NUL-terminated and ends in six Xs.
    assert!(!unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) }.is_null());
    bytes.pop();
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

fn run(name: &str, mode: &str) {
    let retained = std::env::var_os(EVIDENCE_ENV);
    let root = retained
        .clone()
        .map_or_else(unique_evidence_root, PathBuf::from);
    let directory = root.join(mode);
    std::fs::create_dir_all(&directory).unwrap();
    let output = |name| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))
            .unwrap()
    };
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, mode)
        .env("RUST_BACKTRACE", "0")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(output("stdout"))
        .stderr(output("stderr"));
    // SAFETY: the post-fork closure performs only async-signal-safe setrlimit.
    unsafe {
        command.pre_exec(|| {
            for (resource, value) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_FSIZE, OUTPUT_LIMIT)] {
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
    let stdout = std::fs::read_to_string(directory.join("stdout")).unwrap();
    let stderr = std::fs::read_to_string(directory.join("stderr")).unwrap();
    std::fs::write(
        directory.join("status"),
        format!(
            "raw_status={}; code={:?}; signal={:?}; timeout={timed_out}; seconds={}\n",
            status.into_raw(),
            status.code(),
            status.signal(),
            start.elapsed().as_secs_f64(),
        ),
    )
    .unwrap();
    let expected = if mode.starts_with("ignore") {
        status.code() == Some(COMPLETE)
            && stdout.contains(&format!("sigtrap-origin-complete:{mode}"))
    } else {
        status.signal() == Some(libc::SIGTRAP)
    };
    assert!(
        !timed_out && expected && stdout.contains(&format!("sigtrap-origin-ready:{mode}")),
        "{mode}: status={status}; timeout={timed_out}; evidence={}\nstdout: {stdout}\nstderr: {stderr}",
        directory.display(),
    );
    if retained.is_none() {
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn ignored_application_sigtrap_at_guarded_site_preserves_return() {
    if let Ok(mode) = std::env::var(CHILD_ENV) {
        child_body(&mode);
    }
    let name = "ignored_application_sigtrap_at_guarded_site_preserves_return";
    run(name, "ignore-native");
    run(name, "ignore-bound");
}

#[test]
fn default_application_sigtrap_at_guarded_site_terminates() {
    if let Ok(mode) = std::env::var(CHILD_ENV) {
        child_body(&mode);
    }
    let name = "default_application_sigtrap_at_guarded_site_terminates";
    run(name, "default-native");
    run(name, "default-bound");
}
