//! Per-run deadline for every child a test starts (I1-H H2b, made
//! shared in H2c). In I1-H H2b, a persistent test seam made one run
//! loop for 59 minutes, and nothing bounded it. Every child the
//! suite starts, remote, O1 or O1-S, or a plain helper process, is
//! armed through the helpers below once it is running and before
//! any guest instruction runs. If the run still holds the deadline
//! `RUN_DEADLINE` later, the watchdog SIGKILLs exactly that child
//! through a pidfd opened while it was this test's unreaped child,
//! so a recycled pid can never be reached. The test's next wait or
//! ptrace call then fails, and `Drop` fails the test by name.
//!
//! Limit (H2b review P3-4): this bounds only loops that keep calling
//! ptrace or waiting on the child. A tracer-internal loop that never
//! touches the child again is not bounded; a process-level bound is
//! the next follow-up after H2c.
//!
//! Coverage: each test binary runs [`spawn_census`] over its own
//! source, which fails on any spelling in [`RAW_SPAWNS`] outside a
//! comment. The census checks spellings, not semantics. The gate's
//! `deadline_helpers_arm_their_child` checks that every helper arms
//! the child it starts, with `RUN_DEADLINE` (see [`take_last_armed`]).

#![allow(dead_code)]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Child, Command, ExitStatus};
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use liteinst_jit::Refuse;
use liteinst_jit::o1::{
    ChildInfo, O1sOutcome, OracleOutcome, run_o1_bytes_observed, run_o1_observed, run_o1s,
};
use liteinst_jit::remote::{RemoteChildInfo, RemoteExecutable};

/// Bound on one child's life in this suite. A whole run of the
/// largest binary takes under 10 s, and one run takes milliseconds.
pub const RUN_DEADLINE: Duration = Duration::from_secs(120);

thread_local! {
    /// The last child this thread armed, with its bound. Helpers
    /// arm on the calling thread (the O1 and O1-S hooks run inline),
    /// so a test reads back exactly what its own call armed, never
    /// a concurrent test's.
    static LAST_ARMED: core::cell::Cell<Option<(i32, Duration)>> =
        const { core::cell::Cell::new(None) };
}

/// Take the `(pid, bound)` this thread armed last, if any, and clear
/// it: the arming check of every helper (H2c follow-up).
pub fn take_last_armed() -> Option<(i32, Duration)> {
    LAST_ARMED.with(|c| c.take())
}

/// One armed child: see the module doc.
pub struct Deadline {
    pid: i32,
    done: Option<std::sync::mpsc::Sender<()>>,
    watchdog: Option<std::thread::JoinHandle<bool>>,
}

impl Deadline {
    /// Arm `RUN_DEADLINE` on this test's own unreaped child `pid`.
    pub fn arm(pid: i32) -> Deadline {
        Deadline::arm_for(pid, RUN_DEADLINE)
    }

    /// Arm a custom bound (the module self-test only).
    pub fn arm_for(pid: i32, limit: Duration) -> Deadline {
        // SAFETY: pidfd_open on this test's own child, spawned and
        // not reaped.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(
            fd >= 0,
            "deadline: pidfd_open({pid}): {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: a fresh descriptor that only this owner closes.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        LAST_ARMED.with(|c| c.set(Some((pid, limit))));
        let (done, rx) = std::sync::mpsc::channel::<()>();
        let watchdog = std::thread::spawn(move || {
            let fired = matches!(rx.recv_timeout(limit), Err(RecvTimeoutError::Timeout));
            if fired {
                // SAFETY: SIGKILL to the one process this pidfd names.
                let rc = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd.as_raw_fd(),
                        libc::SIGKILL,
                        core::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
                eprintln!("DEADLINE: child {pid} outlived {limit:?}; SIGKILL via pidfd rc={rc}");
            }
            fired
        });
        Deadline {
            pid,
            done: Some(done),
            watchdog: Some(watchdog),
        }
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        drop(self.done.take());
        let fired = self
            .watchdog
            .take()
            .is_some_and(|w| w.join().unwrap_or(true));
        if fired && !std::thread::panicking() {
            panic!(
                "child {} outlived its run deadline and was killed",
                self.pid
            );
        }
    }
}

fn armed(remote: RemoteExecutable) -> (RemoteExecutable, Deadline) {
    let deadline = Deadline::arm(remote.child_pid_for_test());
    (remote, deadline)
}

/// `RemoteExecutable::spawn_bytes`, armed. A failed spawn arms
/// nothing and returns its refusal unchanged.
pub fn remote_bytes(bin: &str, bytes: &[u8]) -> Result<(RemoteExecutable, Deadline), Refuse> {
    RemoteExecutable::spawn_bytes(std::path::Path::new(bin), bytes).map(armed)
}

/// `RemoteExecutable::spawn_bytes_with_blocked`, armed.
pub fn remote_bytes_with_blocked(
    bin: &str,
    bytes: &[u8],
    blocked: &[i32],
) -> Result<(RemoteExecutable, Deadline), Refuse> {
    RemoteExecutable::spawn_bytes_with_blocked(std::path::Path::new(bin), bytes, blocked).map(armed)
}

/// `RemoteExecutable::spawn_bytes_guarded`, armed.
pub fn remote_bytes_guarded(
    bin: &str,
    bytes: &[u8],
) -> Result<(RemoteExecutable, Deadline), Refuse> {
    RemoteExecutable::spawn_bytes_guarded(std::path::Path::new(bin), bytes).map(armed)
}

/// `RemoteExecutable::spawn_named`, armed.
pub fn remote_named(bin: &str, name: &str) -> Result<(RemoteExecutable, Deadline), Refuse> {
    RemoteExecutable::spawn_named(std::path::Path::new(bin), name).map(armed)
}

/// `RemoteExecutable::spawn_named_with_blocked`, armed.
pub fn remote_named_with_blocked(
    bin: &str,
    name: &str,
    blocked: &[i32],
) -> Result<(RemoteExecutable, Deadline), Refuse> {
    RemoteExecutable::spawn_named_with_blocked(std::path::Path::new(bin), name, blocked).map(armed)
}

/// `run_o1` with its child armed (I1-H H2c: `run_o1_observed`).
pub fn o1(
    bin: &str,
    name: &str,
    tweaks: impl FnOnce(&mut libc::user_regs_struct, &ChildInfo),
) -> OracleOutcome {
    let mut deadline = None;
    let o = run_o1_observed(std::path::Path::new(bin), name, tweaks, |pid| {
        deadline = Some(Deadline::arm(pid));
    });
    drop(deadline);
    o
}

/// `run_o1_bytes` with its child armed.
pub fn o1_bytes(
    bin: &str,
    bytes: &[u8],
    tweaks: impl FnOnce(&mut libc::user_regs_struct, &ChildInfo),
) -> OracleOutcome {
    let mut deadline = None;
    let o = run_o1_bytes_observed(std::path::Path::new(bin), bytes, tweaks, |pid| {
        deadline = Some(Deadline::arm(pid));
    });
    drop(deadline);
    o
}

/// `run_o1s` with its child armed before the caller's `on_spawn`.
pub fn o1s(
    bin: &str,
    bytes: &[u8],
    child_args: &[&str],
    setup: impl FnOnce(&mut libc::user_regs_struct, &RemoteChildInfo),
    arrival: Option<(u64, i32)>,
    on_spawn: impl FnOnce(i32),
) -> O1sOutcome {
    let mut deadline = None;
    let o = run_o1s(
        std::path::Path::new(bin),
        bytes,
        child_args,
        setup,
        arrival,
        |pid| {
            deadline = Some(Deadline::arm(pid));
            on_spawn(pid);
        },
    );
    drop(deadline);
    o
}

/// Spawn `cmd` and arm it: for a child that is read before the
/// wait. Hold the deadline until after the wait.
pub fn command_child(cmd: &mut Command) -> std::io::Result<(Child, Deadline)> {
    let child = cmd.spawn()?;
    let deadline = Deadline::arm(child.id() as i32);
    Ok((child, deadline))
}

/// `Command::status`, armed: spawn, arm, wait, then drop the
/// deadline (a kill fails the test by name).
pub fn command_status(cmd: &mut Command) -> std::io::Result<ExitStatus> {
    let (mut child, deadline) = command_child(cmd)?;
    let status = child.wait();
    drop(deadline);
    status
}

/// Raw spawn spellings that bypass this module's arming. Each is
/// how a test starts a child directly:
/// - `RemoteExecutable::spawn` (every `spawn_*` constructor);
/// - `run_o1(`, `run_o1_bytes(`, `run_o1s(`, `run_o1_observed(`,
///   `run_o1_bytes_observed(` (the oracle runners; the two
///   `_observed` hooks came with H2c and are listed since its
///   follow-up);
/// - `.spawn()`, `.status()`, `.output()` (starting a built
///   `Command`; building one is fine, starting it must go through
///   `command_child` or `command_status`). `std::thread::spawn`
///   takes a closure, so it never matches `.spawn()`. These start
///   methods replace the design's `Command::new(` token: the
///   helpers take a caller-built `Command`, and a `Command` built
///   in one place and started in another is still caught.
///
/// This file is not scanned, so the helpers' own calls never match.
const RAW_SPAWNS: [&str; 9] = [
    "RemoteExecutable::spawn",
    "run_o1(",
    "run_o1_bytes(",
    "run_o1s(",
    "run_o1_observed(",
    "run_o1_bytes_observed(",
    ".spawn()",
    ".status()",
    ".output()",
];

/// The spawn census (I1-H H2c): fail if `src` (a test binary's own
/// source, passed with `include_str!`) contains a raw spawn outside
/// a comment. Every child must come from this module's helpers, so
/// that every child carries a deadline. This checks spellings, not
/// semantics: a new spawn API needs a new entry in `RAW_SPAWNS`.
pub fn spawn_census(src: &str, file: &str) {
    let raw: Vec<String> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .filter(|(_, l)| RAW_SPAWNS.iter().any(|t| l.contains(t)))
        .map(|(i, l)| format!("{file}:{}: {}", i + 1, l.trim()))
        .collect();
    assert!(
        raw.is_empty(),
        "spawn census: raw spawns bypass the run deadline:\n{}",
        raw.join("\n")
    );
}

/// Self-test (I1-H H2c): a child that would outlive its deadline is
/// SIGKILLed, and dropping the deadline fails by name. The child is
/// this test binary itself, running only `deadline::sleeper_probe`,
/// which sleeps for an hour when `LITEINST_DEADLINE_SLEEPER` is set.
/// It is not ptraced, so the caller needs no SERIAL lock.
///
/// Called from a `#[test]` in two binaries (remote_signal_gate,
/// remote_signal_rt). More copies would be redundant: the self-test
/// exercises this shared module, which compiles identically into
/// every binary, not the binary it runs in.
pub fn self_test() {
    use std::os::unix::process::ExitStatusExt;
    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .args(["--exact", "deadline::sleeper_probe", "--ignored"])
        .env("LITEINST_DEADLINE_SLEEPER", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sleeper probe");
    let deadline = Deadline::arm_for(child.id() as i32, Duration::from_millis(200));
    let mut status = None;
    for _ in 0..200 {
        if let Some(s) = child.try_wait().expect("try_wait") {
            status = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(deadline)));
        panic!("deadline self-test: the child was still alive 10 s after a 200 ms deadline");
    };
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "deadline self-test: the child ended by SIGKILL: {status:?}"
    );
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(deadline)));
    let msg = dropped
        .err()
        .and_then(|e| {
            e.downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
        })
        .expect("deadline self-test: dropping a fired deadline must panic");
    assert!(
        msg.contains("outlived its run deadline"),
        "deadline self-test: panic names the deadline: {msg}"
    );
}

/// The self-test's child: sleeps an hour only when run by it.
#[test]
#[ignore = "run only as the deadline self-test's child"]
fn sleeper_probe() {
    if std::env::var_os("LITEINST_DEADLINE_SLEEPER").is_some() {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
