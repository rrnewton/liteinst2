//! Test-process isolation for the twenty-six actual runtime controls. This removes
//! unrelated libtest cases from the tracer mm, not the real public API threads.
//! A child result and a separately owned post-body receipt are both mandatory.
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests;

const ROLE: &str = "LITEINST_RUNTIME_ISOLATED_CASE_V1";
const RECEIPT_FD: &str = "LITEINST_RUNTIME_ISOLATED_RECEIPT_FD_V1";
const OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
// Separate process watchdog, never a replacement or renewal of any inner 3s
// operation/cleanup deadline. The full recorder command retains its own bound.
const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
static NONCE: AtomicU64 = AtomicU64::new(1);

const CASES: [&str; 26] = [
    "linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_expired_original_deadline_keeps_pristine_exec",
    "linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_one_short_bootstrap_reservation_keeps_pristine_exec",
    "linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_owner_refuses_raw_bypass_and_repeated_start",
    "linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_source_window_refusal_retains_completed_bootstrap",
    "linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_startup_preserves_real_boundary_state_sources_and_nx",
    "linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_unwind_retains_native_bootstrap_until_physical_cleanup",
    "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_conditional_branch_preserves_complete_state",
    "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_literal_moves_and_add_preserve_exact_checkpoints",
    "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_nop_matches_independent_raw_single_step",
    "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_same_pc_loop_consumes_distinct_origin",
    "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_single_step_stops_before_same_page_marker",
    "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_actual_dr7_refuses_before_original_release",
    "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_ordinary_memory_and_stack_refuse_before_effects",
    "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_selected_cpu_and_ordinary_keep_exact_control_lineage",
    "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_selected_native_refuses_without_ordinary_fallback",
    "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_selected_syscall_refuses_without_ordinary_fallback",
    "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::cross_page::runtime_ordinary_cross_page_move_preserves_exact_two_page_fetch",
    "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::cross_page::runtime_selected_cross_page_cpuid_preserves_nx_and_successor",
    "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_public_getpid_selected_ordinary_exit_preserves_lineage",
    "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_gettid_exit_group_retains_real_terminal",
    "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_cross_page_syscall_preserves_exact_fetch",
    "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_default_native_and_cpu_refusals_keep_current_state",
    "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_fault_and_unsupported_syscalls_never_release",
    "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_stale_reply_keeps_physical_custody",
    "linux::remote::dynamic::owner::admission::runtime::launch_cleanup_native_tests::runtime_launch_alias_refusal_retains_pending_cleanup_and_physical_custody",
    "linux::remote::dynamic::owner::admission::runtime::launch_cleanup_native_tests::runtime_launch_pre_ready_failure_preserves_original_error_and_cleanup",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    case: u64,
    parent: u64,
    nonce: u64,
    device: u64,
    inode: u64,
}

impl Identity {
    fn bytes(self, child: Option<u32>) -> [u8; 64] {
        let mut result = [0; 64];
        result[..8].copy_from_slice(if child.is_some() {
            b"RTISOC01"
        } else {
            b"RTISOH01"
        });
        for (index, value) in [
            1,
            self.case,
            self.parent,
            self.nonce,
            self.device,
            self.inode,
            child.map_or(0, u64::from),
        ]
        .into_iter()
        .enumerate()
        {
            result[8 + index * 8..16 + index * 8].copy_from_slice(&value.to_le_bytes());
        }
        result
    }

    fn header(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 || &bytes[..8] != b"RTISOH01" {
            return None;
        }
        let word = |index| u64::from_le_bytes(bytes[index..index + 8].try_into().unwrap());
        let identity = Self {
            case: word(16),
            parent: word(24),
            nonce: word(32),
            device: word(40),
            inode: word(48),
        };
        (word(8) == 1
            && word(56) == 0
            && identity.case > 0
            && identity.case <= CASES.len() as u64
            && identity.parent > 0
            && identity.nonce > 0
            && identity.inode > 0)
            .then_some(identity)
    }
}

fn expected_args(name: &str) -> [&str; 5] {
    [
        "--exact",
        name,
        "--test-threads=1",
        "--format=pretty",
        "--color=never",
    ]
}

fn role_matches(name: &str, role: &str, args: &[String], parent: u32, identity: Identity) -> bool {
    identity.case > 0
        && identity.case <= CASES.len() as u64
        && CASES.get(identity.case.saturating_sub(1) as usize) == Some(&name)
        && role == name
        && args.iter().map(String::as_str).eq(expected_args(name))
        && identity.parent == u64::from(parent)
        && parent != 0
        && identity.nonce != 0
        && identity.inode != 0
}

fn receipt_matches(bytes: &[u8], identity: Identity, child: u32) -> bool {
    child != 0
        && bytes.len() == 128
        && bytes[..64] == identity.bytes(None)
        && bytes[64..] == identity.bytes(Some(child))
}

fn result_matches(bytes: &[u8], name: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    if !text.ends_with('\n') || text.contains(['\r', '\0']) || !CASES.contains(&name) {
        return false;
    }
    let mut lines = text.lines().filter(|line| !line.is_empty());
    if lines.next() != Some("running 1 test")
        || lines.next() != Some(format!("test {name} ... ok").as_str())
    {
        return false;
    }
    let Some(summary) = lines.next() else {
        return false;
    };
    if lines.next().is_some() {
        return false;
    }
    let Some(tail) =
        summary.strip_prefix("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
    else {
        return false;
    };
    let Some((filtered, duration)) = tail.split_once(" filtered out; finished in ") else {
        return false;
    };
    let Some(duration) = duration.strip_suffix('s') else {
        return false;
    };
    let Some((seconds, fraction)) = duration.split_once('.') else {
        return false;
    };
    let digits = |value: &str| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
    digits(filtered)
        && filtered.parse::<usize>().is_ok()
        && digits(seconds)
        && fraction.len() == 2
        && digits(fraction)
}

fn anonymous_file(name: &'static std::ffi::CStr) -> io::Result<File> {
    // SAFETY: a fixed NUL-terminated name; a successful new descriptor is owned once.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_bounded(file: &File, limit: usize) -> io::Result<Vec<u8>> {
    let length = usize::try_from(file.metadata()?.len())
        .map_err(|_| io::Error::other("isolated output length overflow"))?;
    if length > limit {
        return Err(io::Error::other("isolated output exceeds bound"));
    }
    let mut bytes = vec![0; length];
    file.read_exact_at(&mut bytes, 0)?;
    let mut extra = [0];
    if file.read_at(&mut extra, length as u64)? != 0 || file.metadata()?.len() != length as u64 {
        return Err(io::Error::other(
            "isolated output changed after terminal wait",
        ));
    }
    Ok(bytes)
}

fn regular_unlinked(file: &File) -> io::Result<(u64, u64)> {
    let stat = file.metadata()?;
    if !stat.is_file() || stat.nlink() != 0 || stat.ino() == 0 {
        return Err(io::Error::other(
            "isolated receipt is not an owned anonymous file",
        ));
    }
    Ok((stat.dev(), stat.ino()))
}

fn run_body(name: &str, role: &str, descriptor: &str, body: impl FnOnce()) {
    let fd = descriptor
        .parse::<i32>()
        .expect("exact inherited receipt descriptor");
    assert!(fd > 2, "receipt must not alias standard streams");
    assert_eq!(fd.to_string(), descriptor);
    // SAFETY: this inherited descriptor has no Rust owner in the exec child.
    // CLOEXEC is restored before launching any application/broker in the body.
    assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    let receipt = unsafe { File::from_raw_fd(fd) };
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    let (device, inode) = regular_unlinked(&receipt).unwrap();
    let header = read_bounded(&receipt, 64).unwrap();
    let identity = Identity::header(&header).expect("exact parent-initialized receipt header");
    assert_eq!((identity.device, identity.inode), (device, inode));
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    assert!(role_matches(
        name,
        role,
        &args,
        unsafe { libc::getppid() } as u32,
        identity
    ));
    assert_eq!(unsafe { libc::getpgrp() }, unsafe { libc::getpid() });
    body(); // The original complete test body, including all its cleanup checks.
    assert_eq!(regular_unlinked(&receipt).unwrap(), (device, inode));
    assert_eq!(read_bounded(&receipt, 64).unwrap(), header);
    receipt
        .write_all_at(&identity.bytes(Some(std::process::id())), 64)
        .unwrap();
    assert_eq!(receipt.metadata().unwrap().len(), 128);
}

struct ChildOwner {
    child: Child,
    pin: Option<OwnedFd>,
    reaped: bool,
    complete: bool,
}

impl ChildOwner {
    fn pin(&mut self) -> io::Result<()> {
        // Child is still owned and unreaped even if it exited before pidfd_open.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, self.child.id(), 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        self.pin = Some(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        Ok(())
    }

    fn terminal(&self, until: Instant) -> io::Result<()> {
        loop {
            let remaining = until
                .checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::other("isolated process watchdog expired"))?;
            let mut poll = libc::pollfd {
                fd: self.pin.as_ref().unwrap().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout = i32::try_from(remaining.as_millis().min(1000))
                .unwrap()
                .max(1);
            let result = unsafe { libc::poll(&raw mut poll, 1, timeout) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                continue;
            }
            if result != 1 || poll.revents != libc::POLLIN {
                return Err(io::Error::other(
                    "isolated child lost unreaped pidfd custody",
                ));
            }
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    &raw mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if Instant::now() >= until {
                return Err(io::Error::other(
                    "isolated terminal observation exceeded watchdog",
                ));
            }
            if unsafe { info.si_pid() } != self.child.id() as i32
                || info.si_signo != libc::SIGCHLD
                || info.si_code != libc::CLD_EXITED
                || unsafe { info.si_status() } != 0
            {
                return Err(io::Error::other(format!(
                    "isolated child did not exit normally with zero: signal={}, code={}, status={}, expected_pid={}",
                    info.si_signo,
                    info.si_code,
                    unsafe { info.si_status() },
                    unsafe { info.si_pid() } == self.child.id() as i32
                )));
            }
            return Ok(());
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        // Called only after WNOWAIT terminal evidence, exact result and receipt.
        let result = self.child.wait()?;
        self.reaped = true;
        if !result.success() {
            return Err(io::Error::other("isolated exact reap disagrees"));
        }
        let mut poll = libc::pollfd {
            fd: self.pin.as_ref().unwrap().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&raw mut poll, 1, 0) } != 1
            || poll.revents & libc::POLLHUP == 0
            || poll.revents & !(libc::POLLIN | libc::POLLHUP) != 0
        {
            return Err(io::Error::other(
                "isolated child lacks physical reap receipt",
            ));
        }
        self.complete = true;
        Ok(())
    }
}

impl Drop for ChildOwner {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        // Never send a group signal after consuming the group leader's PID.
        // Prior to reap the owned direct child reserves this numeric identity.
        if !self.reaped {
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let until = Instant::now() + CLEANUP_TIMEOUT;
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => {
                        self.reaped = true;
                        break;
                    }
                    Ok(None) if Instant::now() < until => {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    _ => break,
                }
            }
        }
        // A direct-child reap alone is not proof that its applications/broker
        // were cleaned. Without the complete body receipt the validation
        // command must fail-stop; its outer supervisor retains subtree cleanup.
        // Write directly: libtest's thread-local print capture is lost on abort.
        let _ = writeln!(
            io::stderr().lock(),
            "runtime isolation failed closed; direct child reaped={}",
            self.reaped
        );
        std::process::abort();
    }
}

fn run_parent(name: &str) {
    let until = Instant::now() + PROCESS_TIMEOUT;
    let stdout = anonymous_file(c"liteinst-runtime-out").unwrap();
    let stderr = anonymous_file(c"liteinst-runtime-err").unwrap();
    let receipt = anonymous_file(c"liteinst-runtime-receipt").unwrap();
    let (device, inode) = regular_unlinked(&receipt).unwrap();
    let identity = Identity {
        case: CASES
            .iter()
            .position(|candidate| *candidate == name)
            .unwrap() as u64
            + 1,
        parent: u64::from(std::process::id()),
        nonce: NONCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                old.checked_add(1)
            })
            .unwrap(),
        device,
        inode,
    };
    receipt.write_all_at(&identity.bytes(None), 0).unwrap();
    let fd = receipt.as_raw_fd();
    assert!(fd > 2);
    let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut disposition) },
        0
    );
    assert!(
        disposition.sa_sigaction != libc::SIG_IGN && disposition.sa_flags & libc::SA_NOCLDWAIT == 0
    );
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(expected_args(name))
        .env(ROLE, name)
        .env(RECEIPT_FD, fd.to_string())
        .env_remove("RUST_TEST_THREADS")
        .env_remove("RUST_TEST_NOCAPTURE")
        .env("RUST_BACKTRACE", "0")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().unwrap())
        .stderr(stderr.try_clone().unwrap());
    // SAFETY: only initialized scalar captures and async-signal-safe native
    // calls are used between fork and exec. Parent FD flags/limits are unchanged.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            let limit = libc::rlimit {
                rlim_cur: OUTPUT_LIMIT as libc::rlim_t,
                rlim_max: OUTPUT_LIMIT as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &raw const limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // This is the existing file-writer/fork serialization seam, held only for
    // spawn. No parent reader thread or test body is created under this lock.
    let child = {
        let _guard = crate::TEST_FILE_FORK.lock().unwrap();
        assert!(Instant::now() < until, "isolated spawn watchdog expired");
        command.spawn().unwrap()
    };
    let mut owner = ChildOwner {
        child,
        pin: None,
        reaped: false,
        complete: false,
    };
    let outcome = (|| -> io::Result<()> {
        owner.pin()?;
        owner.terminal(until)?;
        let out = read_bounded(&stdout, OUTPUT_LIMIT)?;
        let err = read_bounded(&stderr, OUTPUT_LIMIT)?;
        let proof = read_bounded(&receipt, 128)?;
        if !err.is_empty()
            || !result_matches(&out, name)
            || regular_unlinked(&receipt)? != (device, inode)
            || !receipt_matches(&proof, identity, owner.child.id())
        {
            return Err(io::Error::other(
                "isolated result or completed-body receipt disagrees",
            ));
        }
        if Instant::now() >= until {
            return Err(io::Error::other(
                "isolated authentication exceeded watchdog",
            ));
        }
        owner.finish()
    })();
    if let Err(error) = outcome {
        // Escaped, bounded diagnostics cannot masquerade as outer libtest rows.
        // Bypass libtest capture so fail-stop cannot discard the diagnosis.
        // These bounded escaped bytes stay in the recorder's private log.
        {
            let mut diagnostics = io::stderr().lock();
            let _ = writeln!(
                diagnostics,
                "runtime isolated case {name:?} failed: {error}"
            );
            for (label, file) in [("stdout", &stdout), ("stderr", &stderr)] {
                if let Ok(bytes) = read_bounded(file, OUTPUT_LIMIT) {
                    let _ = writeln!(
                        diagnostics,
                        "isolated {label} prefix: {:?}",
                        String::from_utf8_lossy(&bytes[..bytes.len().min(8192)])
                    );
                }
            }
        }
        drop(owner); // Kill/reap attempt then command abort; never a passing test.
    }
}

pub(super) fn run(name: &'static str, body: impl FnOnce()) {
    assert!(CASES.contains(&name), "unlisted runtime isolation case");
    match (std::env::var(ROLE), std::env::var(RECEIPT_FD)) {
        (Ok(role), Ok(descriptor)) => run_body(name, &role, &descriptor, body),
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => {
            run_parent(name)
        }
        _ => panic!("incomplete or invalid runtime isolation role"),
    }
}
