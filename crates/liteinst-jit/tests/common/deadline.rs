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
//! Limit (H2b lead review P3-4): this bounds only loops that keep calling
//! ptrace or waiting on the child. A tracer-internal loop that never
//! touches the child again is not bounded by it; [`TestBound`] below
//! is the process-level bound for that case (I1-H H2d).
//!
//! Coverage: each test binary runs [`spawn_census`] over its own
//! source, which fails on any spelling in [`RAW_SPAWNS`] outside a
//! comment. The census checks spellings, not semantics. The gate's
//! `deadline_helpers_arm_their_child` checks that every helper arms
//! the child it starts, with `RUN_DEADLINE` (see [`take_last_armed`]).
//!
//! Process-level bound (I1-H H2d): every test arms a [`TestBound`]
//! (through `lock()` in the gate and rt, or as its first line
//! elsewhere; [`bound_census`] checks the exact line). If a test is
//! still running `TEST_BOUND` after it armed, a watchdog thread
//! kills every direct child of the test process, waits for open
//! [`custody`] sections to close, kills again, writes one line naming
//! the test and aborts the process. Every child creation in the
//! helpers runs inside a custody section, so once the watchdog holds
//! the spawn gate's write lock no fork is in progress and none can
//! start. If a section is still open after `DRAIN_CAP`, the watchdog
//! aborts anyway and says so: termination is guaranteed, complete
//! cleanup only when the drain succeeds.

#![allow(dead_code)]

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError, mpsc,
};
use std::time::{Duration, Instant};

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
/// nothing and returns its refusal unchanged. Every helper below
/// runs its whole library call inside one [`custody`] section.
pub fn remote_bytes(bin: &str, bytes: &[u8]) -> Result<(RemoteExecutable, Deadline), Refuse> {
    custody(|| RemoteExecutable::spawn_bytes(std::path::Path::new(bin), bytes)).map(armed)
}

/// `RemoteExecutable::spawn_bytes_with_blocked`, armed.
pub fn remote_bytes_with_blocked(
    bin: &str,
    bytes: &[u8],
    blocked: &[i32],
) -> Result<(RemoteExecutable, Deadline), Refuse> {
    custody(|| {
        RemoteExecutable::spawn_bytes_with_blocked(std::path::Path::new(bin), bytes, blocked)
    })
    .map(armed)
}

/// `RemoteExecutable::spawn_bytes_guarded`, armed.
pub fn remote_bytes_guarded(
    bin: &str,
    bytes: &[u8],
) -> Result<(RemoteExecutable, Deadline), Refuse> {
    custody(|| RemoteExecutable::spawn_bytes_guarded(std::path::Path::new(bin), bytes)).map(armed)
}

/// `RemoteExecutable::spawn_named`, armed.
pub fn remote_named(bin: &str, name: &str) -> Result<(RemoteExecutable, Deadline), Refuse> {
    custody(|| RemoteExecutable::spawn_named(std::path::Path::new(bin), name)).map(armed)
}

/// `RemoteExecutable::spawn_named_with_blocked`, armed.
pub fn remote_named_with_blocked(
    bin: &str,
    name: &str,
    blocked: &[i32],
) -> Result<(RemoteExecutable, Deadline), Refuse> {
    custody(|| RemoteExecutable::spawn_named_with_blocked(std::path::Path::new(bin), name, blocked))
        .map(armed)
}

/// `run_o1` with its child armed (I1-H H2c: `run_o1_observed`).
pub fn o1(
    bin: &str,
    name: &str,
    tweaks: impl FnOnce(&mut libc::user_regs_struct, &ChildInfo),
) -> OracleOutcome {
    custody(|| {
        let mut deadline = None;
        let o = run_o1_observed(std::path::Path::new(bin), name, tweaks, |pid| {
            deadline = Some(Deadline::arm(pid));
        });
        drop(deadline);
        o
    })
}

/// `run_o1_bytes` with its child armed.
pub fn o1_bytes(
    bin: &str,
    bytes: &[u8],
    tweaks: impl FnOnce(&mut libc::user_regs_struct, &ChildInfo),
) -> OracleOutcome {
    custody(|| {
        let mut deadline = None;
        let o = run_o1_bytes_observed(std::path::Path::new(bin), bytes, tweaks, |pid| {
            deadline = Some(Deadline::arm(pid));
        });
        drop(deadline);
        o
    })
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
    custody(|| {
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
    })
}

/// Spawn `cmd` and arm it: for a child that is read before the
/// wait. Hold the deadline until after the wait.
pub fn command_child(cmd: &mut Command) -> std::io::Result<(Child, Deadline)> {
    command_child_for(cmd, RUN_DEADLINE)
}

/// `command_child` with a custom bound (the subreaper harness).
fn command_child_for(cmd: &mut Command, limit: Duration) -> std::io::Result<(Child, Deadline)> {
    let child = custody(|| cmd.spawn())?;
    let deadline = Deadline::arm_for(child.id() as i32, limit);
    Ok((child, deadline))
}

/// `Command::status`, armed: spawn, arm, wait, then drop the
/// deadline (a kill fails the test by name). The whole call is one
/// custody section; the nested `command_child` takes no second
/// guard.
pub fn command_status(cmd: &mut Command) -> std::io::Result<ExitStatus> {
    custody(|| {
        let (mut child, deadline) = command_child(cmd)?;
        let status = child.wait();
        drop(deadline);
        status
    })
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
    let mut child = custody(|| {
        Command::new(std::env::current_exe().expect("current exe"))
            .args(["--exact", "deadline::sleeper_probe", "--ignored"])
            .env("LITEINST_DEADLINE_SLEEPER", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
    })
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

// ---------------------------------------------------------------
// Process-level test bound (I1-H H2d). See the module doc.
// ---------------------------------------------------------------

/// Bound on one test's whole run. Above `RUN_DEADLINE`, so a child
/// that loops still fails first with the per-run deadline's message.
pub const TEST_BOUND: Duration = Duration::from_secs(300);

/// How long the expiring watchdog waits for open custody sections.
pub const DRAIN_CAP: Duration = Duration::from_secs(5);

/// How long the watchdog waits for the writer's acknowledgement.
const WRITER_ACK: Duration = Duration::from_secs(1);

/// Watchdog period.
const WATCHDOG_TICK: Duration = Duration::from_secs(1);

/// Drain-loop pause between gate attempts.
const DRAIN_PAUSE: Duration = Duration::from_millis(10);

struct Entry {
    name: String,
    thread: std::thread::ThreadId,
    start: Instant,
    limit: Duration,
    seq: u64,
}

static REGISTRY: Mutex<BTreeMap<u64, Entry>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// One sequence shared by [`serial_lock`] and [`TestBound::arm`], so
/// a test can check that its bound started after its lock was held
/// (ordering, not timing).
pub static SEQ: AtomicU64 = AtomicU64::new(1);

type WriterMsg = (String, mpsc::Sender<()>);
static WRITER: OnceLock<mpsc::Sender<WriterMsg>> = OnceLock::new();

/// The spawn custody gate: every custody section holds a read guard;
/// the expiring watchdog takes the write guard for its final sweep
/// and keeps it until the abort.
static SPAWN_GATE: RwLock<()> = RwLock::new(());

/// Set once by an expiring watchdog; no custody section starts after.
static CLOSING: AtomicBool = AtomicBool::new(false);

type Hook = Box<dyn FnMut() + Send>;

/// Probe-only hook run after the first sweep (`late_spawn_probe`).
static AFTER_FIRST_SWEEP: Mutex<Option<Hook>> = Mutex::new(None);

thread_local! {
    /// Set while this thread runs a custody section: a nested call
    /// runs its closure directly and takes no second guard.
    static IN_CUSTODY: Cell<bool> = const { Cell::new(false) };
    /// This thread's [`serial_lock`] sequence number.
    static LOCK_SEQ: Cell<Option<u64>> = const { Cell::new(None) };
}

fn registry() -> MutexGuard<'static, BTreeMap<u64, Entry>> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// One armed test: see the module doc. Dropping it unregisters.
pub struct TestBound {
    id: u64,
}

impl TestBound {
    /// Arm `TEST_BOUND` for the current test (its thread name).
    pub fn arm() -> TestBound {
        TestBound::arm_for(TEST_BOUND)
    }

    /// Arm a custom bound (the probes only).
    pub fn arm_for(limit: Duration) -> TestBound {
        start_threads();
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let me = std::thread::current();
        let name = me.name().unwrap_or("<unnamed>").to_owned();
        registry().insert(
            id,
            Entry {
                name,
                thread: me.id(),
                start: Instant::now(),
                limit,
                seq,
            },
        );
        TestBound { id }
    }
}

impl Drop for TestBound {
    fn drop(&mut self) {
        registry().remove(&self.id);
    }
}

/// Take the serial lock `m` and record this thread's lock sequence
/// number right after it is held (gate and rt `lock()`).
pub fn serial_lock(m: &'static Mutex<()>) -> MutexGuard<'static, ()> {
    let g = m.lock().unwrap_or_else(|e| e.into_inner());
    LOCK_SEQ.with(|c| c.set(Some(SEQ.fetch_add(1, Ordering::SeqCst))));
    g
}

/// The names of every armed test.
pub fn armed_names() -> Vec<String> {
    registry().values().map(|e| e.name.clone()).collect()
}

/// `test_bound_starts_after_lock`: inside `lock()`, this thread's
/// bound was armed after its serial lock was held.
pub fn assert_bound_started_after_lock() {
    let lock = LOCK_SEQ
        .with(|c| c.get())
        .expect("serial_lock recorded this thread's lock number");
    let me = std::thread::current().id();
    let arm = registry()
        .values()
        .filter(|e| e.thread == me)
        .map(|e| e.seq)
        .max()
        .expect("this thread holds an armed TestBound");
    assert!(
        arm > lock,
        "the bound must start after the lock is held: arming number {arm}, lock number {lock}"
    );
}

/// Start the watchdog and the writer once, at first arm, so expiry
/// spawns nothing.
fn start_threads() {
    WRITER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<WriterMsg>();
        std::thread::Builder::new()
            .name("test-bound-writer".into())
            .spawn(move || {
                for (line, ack) in rx {
                    write_all_fd(2, format!("{line}\n").as_bytes());
                    let _ = ack.send(());
                }
            })
            .expect("start the test-bound writer");
        let writer = tx.clone();
        std::thread::Builder::new()
            .name("test-bound-watchdog".into())
            .spawn(move || watchdog(writer))
            .expect("start the test-bound watchdog");
        tx
    });
}

fn watchdog(writer: mpsc::Sender<WriterMsg>) {
    loop {
        std::thread::sleep(WATCHDOG_TICK);
        let expired = registry()
            .values()
            .find(|e| e.start.elapsed() >= e.limit)
            .map(|e| (e.name.clone(), e.limit));
        if let Some((name, limit)) = expired {
            expire(&name, limit, &writer);
        }
    }
}

/// Expiry: close custody, sweep, run the probe hook, drain and sweep
/// under the write guard, hand the line to the writer, abort.
fn expire(name: &str, limit: Duration, writer: &mpsc::Sender<WriterMsg>) -> ! {
    CLOSING.store(true, Ordering::SeqCst);
    let mut swept = BTreeSet::new();
    sweep_children(&mut swept);
    let hook = AFTER_FIRST_SWEEP
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if let Some(mut hook) = hook {
        hook();
    }
    let drained =
        drain_then_final_sweep(&SPAWN_GATE, &mut |_| sweep_children(&mut swept), DRAIN_CAP);
    let tail = match &drained {
        Drain::Drained(_) => "",
        Drain::NotDrained => " (custody not drained)",
    };
    let line = format!(
        "TEST BOUND: {name} still running after {} ms; swept {} children; aborting{tail}",
        limit.as_millis(),
        swept.len()
    );
    let (ack, acked) = mpsc::channel();
    if writer.send((line, ack)).is_ok() {
        let _ = acked.recv_timeout(WRITER_ACK);
    }
    // `drained` still holds the write guard here: no custody section
    // can start between the final sweep and the abort.
    std::process::abort();
}

/// Which sweep [`drain_then_final_sweep`] asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SweepKind {
    Loop,
    Final,
}

/// [`drain_then_final_sweep`]'s result. The write guard is not
/// `Send`: a caller on another thread drops it there.
pub enum Drain<'a> {
    Drained(RwLockWriteGuard<'a, ()>),
    NotDrained,
}

/// Wait for every custody section on `gate` to close: while
/// `try_write` would block, run a `Loop` sweep and retry after
/// `DRAIN_PAUSE`. Once the write guard is held, run one `Final`
/// sweep under it and return the guard. After `cap`, give up with
/// `NotDrained` (no final sweep).
pub fn drain_then_final_sweep<'a>(
    gate: &'a RwLock<()>,
    sweep: &mut dyn FnMut(SweepKind),
    cap: Duration,
) -> Drain<'a> {
    let start = Instant::now();
    loop {
        let held = match gate.try_write() {
            Ok(g) => Some(g),
            Err(TryLockError::Poisoned(p)) => Some(p.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        };
        if let Some(g) = held {
            sweep(SweepKind::Final);
            return Drain::Drained(g);
        }
        if start.elapsed() >= cap {
            return Drain::NotDrained;
        }
        sweep(SweepKind::Loop);
        std::thread::sleep(DRAIN_PAUSE);
    }
}

/// The spawn gate, for the in-process drain test.
pub fn spawn_gate() -> &'static RwLock<()> {
    &SPAWN_GATE
}

/// The result of one `try_write` on the spawn gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateTry {
    Acquired,
    WouldBlock,
}

/// Run the drain's own `try_write` on the spawn gate once, drop any
/// guard at once, and say which result it got.
pub fn custody_gate_try_write() -> GateTry {
    match SPAWN_GATE.try_write() {
        Ok(g) => {
            drop(g);
            GateTry::Acquired
        }
        Err(TryLockError::Poisoned(p)) => {
            drop(p.into_inner());
            GateTry::Acquired
        }
        Err(TryLockError::WouldBlock) => GateTry::WouldBlock,
    }
}

/// Join `h` if it finishes within `limit` (polling `is_finished`).
/// `None` if it panicked or is still running; a running thread is
/// abandoned.
pub fn join_within<T>(h: std::thread::JoinHandle<T>, limit: Duration) -> Option<T> {
    let until = Instant::now() + limit;
    while !h.is_finished() {
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    h.join().ok()
}

/// Register the probe-only hook run after the first sweep.
pub fn set_after_first_sweep(hook: Hook) {
    *AFTER_FIRST_SWEEP.lock().unwrap_or_else(|e| e.into_inner()) = Some(hook);
}

/// One custody section's hold: the read guard, and the thread's
/// nesting flag, cleared on return or unwind.
struct Section {
    _guard: RwLockReadGuard<'static, ()>,
}

impl Drop for Section {
    fn drop(&mut self) {
        IN_CUSTODY.with(|c| c.set(false));
    }
}

fn park_forever() -> ! {
    loop {
        std::thread::park();
    }
}

/// Run `f` (one child creation, plus whatever handshake the call
/// blocks in) as a custody section: park forever if the bound is
/// closing, otherwise hold the spawn gate's read guard until `f`
/// returns or unwinds. A nested call runs `f` directly.
pub fn custody<T>(f: impl FnOnce() -> T) -> T {
    if IN_CUSTODY.with(|c| c.get()) {
        return f();
    }
    if CLOSING.load(Ordering::SeqCst) {
        park_forever();
    }
    let guard = SPAWN_GATE.read().unwrap_or_else(|e| e.into_inner());
    if CLOSING.load(Ordering::SeqCst) {
        drop(guard);
        park_forever();
    }
    let _section = Section { _guard: guard };
    IN_CUSTODY.with(|c| c.set(true));
    f()
}

struct ProcStat {
    state: char,
    ppid: i32,
    start: u64,
}

/// Fields 3, 4 and 22 of `/proc/<pid>/stat` (state, ppid, start
/// time). Field 2, the command name, is raw bytes: it need not be
/// UTF-8 and may contain spaces and `)`. So the file is read as
/// bytes and only the ASCII tail after its last `)` is parsed.
fn proc_stat(pid: i32) -> Option<ProcStat> {
    let b = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let tail = &b[b.iter().rposition(|&c| c == b')')? + 1..];
    let rest = std::str::from_utf8(tail).ok()?;
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some(ProcStat {
        state: f.first()?.chars().next()?,
        ppid: f.get(1)?.parse().ok()?,
        start: f.get(19)?.parse().ok()?,
    })
}

/// A process's start time (clock ticks since boot).
pub fn proc_start(pid: i32) -> Option<u64> {
    proc_stat(pid).map(|s| s.start)
}

/// Every process whose parent is this process. The host kernel is
/// built without `CONFIG_PROC_CHILDREN`, so there are no
/// `/proc/<pid>/task/<tid>/children` files; this reads every
/// `/proc/<pid>/stat` instead, so one call costs O(processes on the
/// host). It runs only on expiry and in the harness. Callers recheck
/// identity through a pidfd.
fn direct_children() -> BTreeSet<i32> {
    let me = std::process::id() as i32;
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return BTreeSet::new();
    };
    dir.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter(|&pid| proc_stat(pid).is_some_and(|s| s.ppid == me))
        .collect()
}

fn pidfd(pid: i32) -> Option<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags and returns a new
    // descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    // SAFETY: a fresh descriptor that only this owner closes.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn pidfd_kill(fd: &OwnedFd) -> bool {
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
    rc == 0
}

/// One sweep: SIGKILL every live direct child through a pidfd, after
/// rechecking that its stat still names this process as parent.
/// `swept` holds the (pid, start time) of every child killed so far;
/// a child already in it (a zombie nobody reaped yet) is skipped, and
/// a child that exits first is skipped without error.
fn sweep_children(swept: &mut BTreeSet<(i32, u64)>) {
    let me = std::process::id() as i32;
    for pid in direct_children() {
        let Some(fd) = pidfd(pid) else { continue };
        let Some(st) = proc_stat(pid) else { continue };
        if st.ppid != me || st.state == 'Z' || swept.contains(&(pid, st.start)) {
            continue;
        }
        if pidfd_kill(&fd) {
            swept.insert((pid, st.start));
        }
    }
}

/// Write all of `buf` to `fd` with raw `write(2)`, retrying on
/// `EINTR` and partial writes; give up on any other error.
fn write_all_fd(fd: RawFd, mut buf: &[u8]) {
    while !buf.is_empty() {
        // SAFETY: write(2) from a live slice to a descriptor this
        // process owns.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        buf = &buf[n as usize..];
    }
}

/// One harness record: `"\n" + line + "\n"` written to fd 1 with
/// raw `write(2)`. libtest captures `print!`, and with one test
/// thread it prints `test <name> ... ` without a newline before the
/// test body runs; the leading newline keeps the record on its own
/// line.
pub fn record(line: &str) {
    write_all_fd(1, format!("\n{line}\n").as_bytes());
}

// ---------------------------------------------------------------
// Subreaper harness (I1-H H2d): runs one probe under an intermediate
// subreaper and reports how every process ended.
// ---------------------------------------------------------------

/// What the intermediate does with the probe's stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StderrMode {
    /// Read it and relay it as `stderr` records.
    Drain,
    /// Hold the read end open and never read it.
    Hold,
}

/// One child record: pid, start time (`unknown` if the probe could
/// not read it, `unlisted` for an adoptee the probe never recorded)
/// and status (`signaled <n>`, `exited <n>`, `killed-by-harness`,
/// `harness-kill-unreaped`, `harness-unkilled-unreaped` or
/// `missing`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildRecord {
    pub pid: String,
    pub start: String,
    pub status: String,
}

/// The intermediate's report, parsed from its records.
#[derive(Clone, Debug, Default)]
pub struct SubreaperReport {
    /// `signaled <n>`, `exited <n>`, `killed-by-harness` or one of
    /// the harness's unreaped statuses (see [`ChildRecord`]).
    pub probe: String,
    pub children: Vec<ChildRecord>,
    pub stderr: Vec<String>,
    /// The intermediate's whole stdout, for failure messages.
    pub raw: String,
}

/// The parent test's bound on the intermediate: above the sum of its
/// own limits (10 s for the probe and 5 s to reap it, then 10 s for
/// the adoptees and 5 s to reap them: 30 s), with 10 s to spare.
const SUBREAPER_PARENT_BOUND: Duration = Duration::from_secs(40);
/// The intermediate's limit on the probe, then on the adoptees.
const HARNESS_LIMIT: Duration = Duration::from_secs(10);
/// The intermediate's polling period.
const HARNESS_POLL: Duration = Duration::from_millis(10);

/// Set in a probe's environment by the intermediate.
const PROBE_ENV: &str = "LITEINST_BOUND_PROBE";
/// The probe the intermediate runs.
const SUBREAPER_PROBE_ENV: &str = "LITEINST_SUBREAPER_PROBE";
/// `drain` or `hold`.
const SUBREAPER_MODE_ENV: &str = "LITEINST_SUBREAPER_MODE";

/// Run `probe` (a test name in this binary) under an intermediate
/// subreaper, which is this test binary running
/// `deadline::subreaper_intermediate`. The test process itself is
/// never a subreaper. The intermediate runs in a custody section and
/// under a 40 s per-run deadline. Each run prints its wall time and
/// the probe's lifetime to stderr (`subreaper <probe>: ...`), so a
/// `--nocapture` log shows the bound probes' timing under load.
pub fn subreaper_run(probe: &str, env: &[(&str, &str)], mode: StderrMode) -> SubreaperReport {
    let mut cmd = Command::new(std::env::current_exe().expect("current exe"));
    cmd.args([
        "--exact",
        "deadline::subreaper_intermediate",
        "--ignored",
        "--test-threads=1",
    ])
    .env(SUBREAPER_PROBE_ENV, probe)
    .env(
        SUBREAPER_MODE_ENV,
        match mode {
            StderrMode::Drain => "drain",
            StderrMode::Hold => "hold",
        },
    )
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let t0 = Instant::now();
    let (mut child, deadline) = command_child_for(&mut cmd, SUBREAPER_PARENT_BOUND)
        .expect("spawn the subreaper intermediate");
    let mut out = child.stdout.take().expect("the intermediate's stdout");
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        String::from_utf8_lossy(&b).into_owned()
    });
    let status = child.wait();
    drop(deadline);
    let raw = reader.join().unwrap_or_default();
    let probe_ms = raw
        .lines()
        .find_map(|l| l.strip_prefix("probe-ms "))
        .unwrap_or("?");
    eprintln!(
        "subreaper {probe}: {} ms in all; probe lived {probe_ms} ms",
        t0.elapsed().as_millis()
    );
    let status = status.expect("wait for the subreaper intermediate");
    assert!(
        status.success(),
        "subreaper intermediate for {probe} failed: {status:?}\n{raw}"
    );
    parse_report(raw)
}

/// The lines of `r`, split on newline bytes and decoded lossily, so a
/// line that is not UTF-8 neither ends the stream nor is dropped.
fn byte_lines(r: impl Read) -> impl Iterator<Item = String> {
    BufReader::new(r)
        .split(b'\n')
        .map_while(Result::ok)
        .map(|l| String::from_utf8_lossy(&l).into_owned())
}

fn parse_report(raw: String) -> SubreaperReport {
    let mut r = SubreaperReport::default();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("probe ") {
            r.probe = rest.to_owned();
        } else if let Some(rest) = line.strip_prefix("child ") {
            let mut f = rest.splitn(3, ' ');
            r.children.push(ChildRecord {
                pid: f.next().unwrap_or_default().to_owned(),
                start: f.next().unwrap_or_default().to_owned(),
                status: f.next().unwrap_or_default().to_owned(),
            });
        } else if let Some(rest) = line.strip_prefix("stderr ") {
            r.stderr.push(rest.to_owned());
        }
    }
    r.raw = raw;
    r
}

fn describe_status(st: i32) -> String {
    if libc::WIFSIGNALED(st) {
        format!("signaled {}", libc::WTERMSIG(st))
    } else if libc::WIFEXITED(st) {
        format!("exited {}", libc::WEXITSTATUS(st))
    } else {
        format!("status {st:#x}")
    }
}

/// Reap every child that has ended, without blocking. Returns true
/// while this process still has children.
fn reap_ready(reaped: &mut BTreeMap<i32, String>) -> bool {
    loop {
        let mut st = 0;
        // SAFETY: waitpid on this process's own children, WNOHANG.
        let pid = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
        if pid > 0 {
            reaped.insert(pid, describe_status(st));
            continue;
        }
        return pid == 0;
    }
}

/// How long the harness polls to reap a child after its kill.
const HARNESS_REAP: Duration = Duration::from_secs(5);

/// Send SIGKILL to `pid` through a pidfd if it is still this
/// process's live child (and, when known, still has start time
/// `start`). A zombie is not signalled. True when the signal was sent.
fn harness_signal(pid: i32, start: Option<u64>) -> bool {
    let me = std::process::id() as i32;
    pidfd(pid).is_some_and(|fd| {
        proc_stat(pid)
            .is_some_and(|s| s.ppid == me && s.state != 'Z' && start.is_none_or(|t| t == s.start))
            && pidfd_kill(&fd)
    })
}

/// Reap `pid`, polling until `until`, and name how it ended. The
/// status is `killed-by-harness` only when the harness sent the kill
/// AND the reaped status is death by SIGKILL. A child that ended some
/// other way keeps its own wait status, even when the kill was sent:
/// a child that exits between the harness's stat check and its signal
/// accepts SIGKILL as a zombie, and the signal call still succeeds.
/// A child not reaped in time gets `harness-kill-unreaped` or
/// `harness-unkilled-unreaped`.
fn harness_reap(pid: i32, killed: bool, until: Instant) -> String {
    loop {
        let mut st = 0;
        // SAFETY: waitpid on this process's own child, WNOHANG.
        let rc = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
        if rc == pid {
            return if killed && libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGKILL {
                "killed-by-harness".to_owned()
            } else {
                describe_status(st)
            };
        }
        if rc < 0 || Instant::now() >= until {
            return if killed {
                "harness-kill-unreaped"
            } else {
                "harness-unkilled-unreaped"
            }
            .to_owned();
        }
        std::thread::sleep(HARNESS_POLL);
    }
}

/// Kill the given children (each with its recorded start time, when
/// known), then reap them all within one shared `HARNESS_REAP`.
fn harness_kill(victims: &[(i32, Option<u64>)], reaped: &mut BTreeMap<i32, String>) {
    let sent: Vec<(i32, bool)> = victims
        .iter()
        .map(|&(pid, start)| (pid, harness_signal(pid, start)))
        .collect();
    let until = Instant::now() + HARNESS_REAP;
    for (pid, killed) in sent {
        reaped.insert(pid, harness_reap(pid, killed, until));
    }
}

/// The children a probe recorded: pid and start time (`None` when the
/// probe could not read it).
type Listed = Arc<Mutex<Vec<(i32, Option<u64>)>>>;

/// Wait on `done` until `until`, at least `min` from now.
fn wait_reader(done: &mpsc::Receiver<()>, until: Instant, min: Duration) {
    let limit = until.max(Instant::now() + min);
    let _ = done.recv_timeout(limit.saturating_duration_since(Instant::now()));
}

/// The intermediate subreaper: see [`subreaper_run`]. It runs the
/// probe under its own supervised limits (10 s for the probe, then
/// 10 s for the adopted orphans) and kills what is left at either
/// limit, reaping it within 5 s and marking it `killed-by-harness`
/// only if it died by that SIGKILL. No
/// blocking read or wait runs outside a limit: reader threads own the
/// probe's pipes, and the main thread only polls.
#[test]
#[ignore = "run only by deadline::subreaper_run"]
fn subreaper_intermediate() {
    let Some(probe) = std::env::var_os(SUBREAPER_PROBE_ENV) else {
        return;
    };
    let probe = probe.into_string().expect("probe name");
    let hold = std::env::var(SUBREAPER_MODE_ENV).as_deref() == Ok("hold");
    no_core_dumps();
    // SAFETY: process-attribute calls on this process only.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0), 0);
        assert_eq!(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0), 0);
    }
    let first_limit = Instant::now() + HARNESS_LIMIT;
    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .args(["--exact", probe.as_str(), "--ignored", "--test-threads=1"])
        .env_remove(SUBREAPER_PROBE_ENV)
        .env(PROBE_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the probe");
    let probe_pid = child.id() as i32;
    let probe_start = proc_start(probe_pid);

    // A child the probe recorded without a readable start time
    // (`unknown`) is still listed: it is never treated as absent.
    let listed: Listed = Arc::default();
    let (out_done_tx, out_done) = mpsc::channel::<()>();
    let stdout = child.stdout.take().expect("the probe's stdout");
    let sink = Arc::clone(&listed);
    std::thread::spawn(move || {
        for line in byte_lines(stdout) {
            let Some(rest) = line.strip_prefix("child ") else {
                continue;
            };
            let mut f = rest.split(' ');
            if let (Some(Ok(pid)), Some(start)) = (f.next().map(str::parse::<i32>), f.next()) {
                sink.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((pid, start.parse::<u64>().ok()));
            }
        }
        let _ = out_done_tx.send(());
    });
    let stderr_lines: Arc<Mutex<Vec<String>>> = Arc::default();
    let (err_done_tx, err_done) = mpsc::channel::<()>();
    let stderr = child.stderr.take().expect("the probe's stderr");
    // In `Hold` mode the read end stays open, unread, until exit.
    let _held = if hold {
        drop(err_done_tx);
        Some(stderr)
    } else {
        let sink = Arc::clone(&stderr_lines);
        std::thread::spawn(move || {
            for line in byte_lines(stderr) {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push(line);
            }
            let _ = err_done_tx.send(());
        });
        None
    };
    // The probe is reaped through waitpid below, never through `child`.
    drop(child);

    let mut reaped = BTreeMap::new();
    let probe_status = loop {
        reap_ready(&mut reaped);
        if let Some(s) = reaped.remove(&probe_pid) {
            break s;
        }
        if Instant::now() >= first_limit {
            harness_kill(&[(probe_pid, probe_start)], &mut reaped);
            break reaped
                .remove(&probe_pid)
                .unwrap_or_else(|| "missing".to_owned());
        }
        std::thread::sleep(HARNESS_POLL);
    };
    let probe_end = Instant::now();
    let second_limit = Instant::now() + HARNESS_LIMIT;
    while reap_ready(&mut reaped) {
        if Instant::now() >= second_limit {
            let listed = listed.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let victims: Vec<(i32, Option<u64>)> = direct_children()
                .into_iter()
                .map(|pid| {
                    let start = listed.iter().find(|(p, _)| *p == pid).and_then(|&(_, s)| s);
                    (pid, start)
                })
                .collect();
            harness_kill(&victims, &mut reaped);
            break;
        }
        std::thread::sleep(HARNESS_POLL);
    }
    // The probe is gone, so its pipes reach EOF unless a survivor
    // holds them; a reader still blocked here is abandoned at exit.
    wait_reader(&out_done, second_limit, Duration::from_secs(1));
    if !hold {
        wait_reader(&err_done, second_limit, Duration::from_secs(1));
    }

    record(&format!(
        "probe-ms {}",
        (probe_end - (first_limit - HARNESS_LIMIT)).as_millis()
    ));
    record(&format!("probe {probe_status}"));
    let listed = listed.lock().unwrap_or_else(|e| e.into_inner()).clone();
    for &(pid, start) in &listed {
        let status = reaped
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| "missing".to_owned());
        let start = start.map_or_else(|| "unknown".to_owned(), |s| s.to_string());
        record(&format!("child {pid} {start} {status}"));
    }
    for (pid, status) in &reaped {
        if !listed.iter().any(|(p, _)| p == pid) {
            record(&format!("child {pid} unlisted {status}"));
        }
    }
    for line in stderr_lines
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
    {
        record(&format!("stderr {line}"));
    }
}

/// `RLIMIT_CORE` 0 for this process and its children: an aborting
/// probe leaves no core file.
fn no_core_dumps() {
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit on this process with a live struct.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
    assert_eq!(rc, 0, "setrlimit(RLIMIT_CORE, 0)");
}

/// True only in a probe run by the intermediate; the probe then turns
/// core dumps off before it does anything else.
fn probe_enabled() -> bool {
    let on = std::env::var_os(PROBE_ENV).is_some();
    if on {
        no_core_dumps();
    }
    on
}

/// How long a probe and its sleepers last if nothing kills them. It
/// outlives the intermediate's limits (30 s in all) and the parent's
/// 40 s bound on the intermediate, so every harness
/// observation is made while they are alive. It also bounds how long
/// they can outlive a failed intermediate: they end by themselves.
const SLEEPER_SECS: u64 = 60;

/// A sleeper with no inherited stdio, so a survivor never holds the
/// probe's pipes open.
fn sleeper() -> Command {
    sleeper_at(std::path::Path::new("/bin/sleep"))
}

fn sleeper_at(path: &std::path::Path) -> Command {
    let mut c = Command::new(path);
    c.arg(SLEEPER_SECS.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    c
}

/// Spawn, inside custody, a sleeper whose process name (`comm`) is
/// not valid UTF-8. It runs `/bin/sleep` through a symlink whose name
/// has a 0xff byte; `comm` is the base name of the path given to
/// exec. The symlink is removed once the exec has happened. Panics
/// unless the child's `comm` really is not UTF-8.
fn spawn_odd_name_sleeper() -> Child {
    use std::os::unix::ffi::OsStrExt;
    let mut name = b"odd\xffname-".to_vec();
    name.extend_from_slice(std::process::id().to_string().as_bytes());
    let link =
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(std::ffi::OsStr::from_bytes(&name));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink("/bin/sleep", &link).expect("symlink the odd-name sleeper");
    let child = custody(|| sleeper_at(&link).spawn()).expect("spawn the odd-name sleeper");
    let _ = std::fs::remove_file(&link);
    let comm = std::fs::read(format!("/proc/{}/comm", child.id())).expect("read the child's comm");
    assert!(
        std::str::from_utf8(&comm).is_err(),
        "the odd-name sleeper's comm must not be UTF-8: {comm:?}"
    );
    child
}

fn record_child(pid: u32) {
    let start = proc_start(pid as i32).map_or_else(|| "unknown".to_owned(), |s| s.to_string());
    record(&format!("child {pid} {start}"));
}

/// The self-test's probe: a 300 ms bound, one armed sleeper and one
/// unarmed sleeper (a bare `Command` inside custody, standing in for
/// a child stuck in a handshake).
#[test]
#[ignore = "run only under deadline::subreaper_run"]
fn bound_probe() {
    if !probe_enabled() {
        return;
    }
    let (armed, _deadline) = command_child(&mut sleeper()).expect("spawn the armed sleeper");
    record_child(armed.id());
    // Never waited on here: the sweep must kill it and the harness must
    // reap it after this probe aborts, to read its signal.
    #[allow(clippy::zombie_processes)]
    let unarmed = custody(|| sleeper().spawn()).expect("spawn the unarmed sleeper");
    record_child(unarmed.id());
    // Armed only now, after both spawns: no spawn races the expiry.
    let _bound = TestBound::arm_for(Duration::from_millis(300));
    std::thread::sleep(Duration::from_secs(SLEEPER_SECS));
}

/// The late-spawn probe: a thread holds a custody section from before
/// the bound is armed; the after-first-sweep hook lets it fork a
/// sleeper only after the first sweep has run.
#[test]
#[ignore = "run only under deadline::subreaper_run"]
fn late_spawn_probe() {
    if !probe_enabled() {
        return;
    }
    let (entered_tx, entered) = mpsc::channel::<()>();
    let (go_tx, go) = mpsc::channel::<()>();
    let (forked_tx, forked) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        custody(|| {
            let _ = entered_tx.send(());
            if go.recv().is_ok() {
                // Never waited on here, as in `bound_probe`.
                #[allow(clippy::zombie_processes)]
                let child = sleeper().spawn().expect("spawn the late sleeper");
                record_child(child.id());
                let _ = forked_tx.send(());
            }
        });
    });
    entered
        .recv_timeout(Duration::from_secs(10))
        .expect("the probe thread entered its custody section");
    set_after_first_sweep(Box::new(move || {
        let _ = go_tx.send(());
        let _ = forked.recv_timeout(Duration::from_secs(2));
    }));
    let _bound = TestBound::arm_for(Duration::from_millis(300));
    std::thread::sleep(Duration::from_secs(SLEEPER_SECS));
}

/// Fill the pipe behind fd 2 through a second, non-blocking open file
/// description (fd 2's own description keeps its flags).
fn fill_stderr_pipe() {
    let f = std::fs::OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/proc/self/fd/2")
        .expect("reopen stderr");
    let chunk = [b'x'; 4096];
    let mut written = 0usize;
    loop {
        match (&f).write(&chunk) {
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("fill stderr after {written} bytes: {e}"),
        }
    }
}

/// The blocked-stderr probe: nobody reads the probe's stderr and the
/// pipe is full before the bound is armed.
#[test]
#[ignore = "run only under deadline::subreaper_run"]
fn bound_probe_blocked() {
    if !probe_enabled() {
        return;
    }
    fill_stderr_pipe();
    let (armed, _deadline) = command_child(&mut sleeper()).expect("spawn the armed sleeper");
    record_child(armed.id());
    // Armed only now, after the spawn: no spawn races the expiry.
    let _bound = TestBound::arm_for(Duration::from_millis(300));
    std::thread::sleep(Duration::from_secs(SLEEPER_SECS));
}

/// The non-UTF-8 sweep probe: one sleeper whose process name is not
/// UTF-8, then a 300 ms bound. The expiring bound's sweep must find
/// and kill the sleeper.
#[test]
#[ignore = "run only under deadline::subreaper_run"]
fn bound_probe_odd_name() {
    if !probe_enabled() {
        return;
    }
    // Never waited on here, as in `bound_probe`.
    #[allow(clippy::zombie_processes)]
    let child = spawn_odd_name_sleeper();
    record_child(child.id());
    let _bound = TestBound::arm_for(Duration::from_millis(300));
    std::thread::sleep(Duration::from_secs(SLEEPER_SECS));
}

/// The non-UTF-8 orphan probe: one sleeper whose process name is not
/// UTF-8, left running when the probe returns. No bound expires; the
/// intermediate must find, kill and reap the orphan at its limit.
#[test]
#[ignore = "run only under deadline::subreaper_run"]
fn orphan_probe_odd_name() {
    if !probe_enabled() {
        return;
    }
    // Never waited on: it must outlive this probe.
    #[allow(clippy::zombie_processes)]
    let child = spawn_odd_name_sleeper();
    record_child(child.id());
}

/// `test_bound_self_test` (gate, rt): the probe aborts, both its
/// sleepers die by the sweep's SIGKILL, and the line names the test.
pub fn bound_self_test() {
    let r = subreaper_run("deadline::bound_probe", &[], StderrMode::Drain);
    assert_eq!(
        r.probe, "signaled 6",
        "expected `probe signaled 6`:\n{}",
        r.raw
    );
    assert_eq!(
        r.children.len(),
        2,
        "expected two child records:\n{}",
        r.raw
    );
    for c in &r.children {
        assert_eq!(
            c.status, "signaled 9",
            "expected child {} `signaled 9`:\n{}",
            c.pid, r.raw
        );
    }
    let line = "TEST BOUND: deadline::bound_probe still running after 300 ms; \
                swept 2 children; aborting";
    assert!(
        r.stderr.iter().any(|l| l == line),
        "expected the exact line `{line}`:\n{}",
        r.raw
    );
}

/// The one child record of a non-UTF-8 probe, after its status.
fn odd_name_child<'a>(r: &'a SubreaperReport, what: &str, want: &str) -> &'a ChildRecord {
    assert_eq!(r.children.len(), 1, "expected one child record:\n{}", r.raw);
    let c = &r.children[0];
    assert_eq!(
        c.status, want,
        "expected the non-UTF-8 {what} `{want}`:\n{}",
        r.raw
    );
    let pid: i32 = c.pid.parse().expect("the child's pid");
    let start: u64 = c
        .start
        .parse()
        .unwrap_or_else(|_| panic!("expected the child listed with its start time:\n{}", r.raw));
    assert_ne!(
        proc_start(pid),
        Some(start),
        "child {pid} (start {start}) is still alive:\n{}",
        r.raw
    );
    c
}

/// `test_bound_sweeps_non_utf8_child` (gate): a child whose process
/// name is not UTF-8 is still found and killed by the expiring bound's
/// sweep, and it is gone afterwards.
pub fn odd_name_sweep_test() {
    let r = subreaper_run("deadline::bound_probe_odd_name", &[], StderrMode::Drain);
    assert_eq!(
        r.probe, "signaled 6",
        "expected `probe signaled 6`:\n{}",
        r.raw
    );
    odd_name_child(&r, "child", "signaled 9");
    let line = "TEST BOUND: deadline::bound_probe_odd_name still running after 300 ms; \
                swept 1 children; aborting";
    assert!(
        r.stderr.iter().any(|l| l == line),
        "expected the exact line `{line}`:\n{}",
        r.raw
    );
}

/// `harness_kills_non_utf8_orphan` (gate): an orphan whose process
/// name is not UTF-8 is found, killed and reaped by the intermediate,
/// and it is gone afterwards.
pub fn odd_name_orphan_test() {
    let r = subreaper_run("deadline::orphan_probe_odd_name", &[], StderrMode::Drain);
    assert_eq!(r.probe, "exited 0", "expected `probe exited 0`:\n{}", r.raw);
    odd_name_child(&r, "orphan", "killed-by-harness");
}

/// `harness_keeps_status_of_child_that_exited_first` (gate): the
/// ordering the harness can meet between its stat check and its
/// signal, made deterministic. A child exits on its own and is left an
/// unreaped zombie; SIGKILL through its pidfd still succeeds; the
/// harness must report the child's own `exited 0`, not
/// `killed-by-harness`.
pub fn harness_status_witness() {
    let pid = custody(|| {
        // SAFETY: fork in a multithreaded process; the child calls only
        // the async-signal-safe `_exit`, at once.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: the forked child exits without running Rust code.
            unsafe { libc::_exit(0) };
        }
        pid
    });
    assert!(pid > 0, "fork: {}", std::io::Error::last_os_error());
    let fd = pidfd(pid).expect("pidfd_open on the child");
    // SAFETY: an all-zero siginfo_t is a valid out-parameter.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waitid on this process's own child, with a live siginfo;
    // WNOWAIT leaves the child unreaped.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT,
        )
    };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
    assert_eq!(
        proc_stat(pid).map(|s| s.state),
        Some('Z'),
        "the child must be an unreaped zombie"
    );
    assert!(
        pidfd_kill(&fd),
        "SIGKILL to an unreaped zombie through its pidfd must succeed (the race's precondition)"
    );
    let status = harness_reap(pid, true, Instant::now() + HARNESS_REAP);
    assert_eq!(
        status, "exited 0",
        "a child that exited before the harness's SIGKILL must keep its own status"
    );
}

/// The kinds of `tests/*.rs` file in [`bound_inventory`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundRole {
    /// Every test armed and checked by its own `bound_census`.
    Armed,
    /// Starts no child and arms nothing (translation only).
    Exempt,
}

/// The first body lines that arm a bound.
const BOUND_FIRST_LINES: [&str; 2] = [
    "let _g = lock();",
    "let _bound = deadline::TestBound::arm();",
];

/// One attribute as the census reads it, from a line that starts one
/// (`#[`, `#![`, or a lone `#`): its text with comments, whitespace and
/// string contents removed, the index of its last line, and whether its
/// brackets closed within 20 lines.
struct Attr {
    text: String,
    last: usize,
    closed: bool,
}

fn read_attribute(lines: &[&str], i: usize) -> Option<Attr> {
    let head = lines[i].trim().split("//").next().unwrap_or("").trim_end();
    let rest = head.strip_prefix('#')?.trim_start();
    let rest = rest.strip_prefix('!').unwrap_or(rest).trim_start();
    if !(rest.is_empty() || rest.starts_with('[')) {
        return None;
    }
    let (mut text, mut depth, mut opened, mut in_str, mut esc) =
        (String::new(), 0i32, false, false, false);
    let mut j = i;
    while j < lines.len() && j <= i + 20 {
        let mut chars = lines[j].chars().peekable();
        while let Some(c) = chars.next() {
            if in_str {
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    in_str = false;
                    text.push('"');
                }
                continue;
            }
            match c {
                '/' if chars.peek() == Some(&'/') => break,
                '"' => {
                    in_str = true;
                    text.push('"');
                }
                '[' => {
                    depth += 1;
                    opened = true;
                    text.push(c);
                }
                ']' => {
                    depth -= 1;
                    text.push(c);
                }
                c if c.is_whitespace() => {}
                c => text.push(c),
            }
        }
        if opened && depth <= 0 {
            return Some(Attr {
                text,
                last: j,
                closed: true,
            });
        }
        j += 1;
    }
    Some(Attr {
        text,
        last: (j - 1).min(lines.len() - 1),
        closed: false,
    })
}

/// Classify the attribute starting at `lines[i]` for the census, and
/// return the index of its last line with the verdict:
/// - `Some(true)`: the one supported test attribute, `#[test]` alone
///   on its line, optionally followed by a `//` comment;
/// - `Some(false)`: refused, rather than skipped: any other attribute
///   with an identifier containing `test` outside string literals,
///   such as `#[test] fn f() {}`, `#[ignore] #[test]`, `# [test]`,
///   `#[tokio::test]`, `#[cfg_attr(unix, test)]`, `#[cfg(test)]` or a
///   multiline `#[` / `test` / `]`; and any attribute whose brackets do
///   not close within 20 lines;
/// - `None`: not an attribute, or one without a `test` identifier.
fn test_attribute(lines: &[&str], i: usize) -> (Option<bool>, usize) {
    let Some(a) = read_attribute(lines, i) else {
        return (None, i);
    };
    let exact = lines[i].trim().split("//").next().unwrap_or("").trim_end() == "#[test]";
    if exact && a.closed && a.last == i {
        return (Some(true), i);
    }
    let names_test = a
        .text
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|w| w.contains("test"));
    if names_test || !a.closed {
        (Some(false), a.last)
    } else {
        (None, a.last)
    }
}

/// The bound census (I1-H H2d): every `#[test]` fn in `src` must
/// start, after blank and `//` lines, with exactly one of
/// `BOUND_FIRST_LINES`, except the pure tests named in `exempt`
/// (each of which must exist). Unsupported test attribute forms are
/// refused (see [`test_attribute`]).
pub fn bound_census(src: &str, file: &str, exempt: &[&str]) {
    let bad = census_violations(src, file, exempt);
    assert!(
        bad.is_empty(),
        "bound census: tests without a TestBound:\n{}",
        bad.join("\n")
    );
}

/// The census's findings for `src`, one line each.
fn census_violations(src: &str, file: &str, exempt: &[&str]) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let skipped = |l: &str| {
        let t = l.trim();
        t.is_empty() || t.starts_with("//")
    };
    let mut bad = Vec::new();
    let mut seen = BTreeSet::new();
    let mut i = 0;
    while i < lines.len() {
        let (verdict, last) = test_attribute(&lines, i);
        match verdict {
            Some(true) => {}
            Some(false) => {
                bad.push(format!(
                    "{file}:{}: unsupported test attribute `{}`",
                    i + 1,
                    lines[i].trim()
                ));
                i = last + 1;
                continue;
            }
            None => {
                i = last + 1;
                continue;
            }
        }
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim_start().starts_with("#[") {
            j += 1;
        }
        let Some(name) = lines
            .get(j)
            .and_then(|l| l.trim().strip_prefix("fn "))
            .and_then(|r| r.split('(').next())
        else {
            bad.push(format!("{file}:{}: #[test] without a fn line", j + 1));
            i = j;
            continue;
        };
        let mut k = j;
        while k < lines.len() && !lines[k].trim_end().ends_with('{') {
            k += 1;
        }
        k += 1;
        while k < lines.len() && skipped(lines[k]) {
            k += 1;
        }
        let first = lines.get(k).map_or("", |l| l.trim());
        seen.insert(name.to_owned());
        if !exempt.contains(&name) && !BOUND_FIRST_LINES.contains(&first) {
            bad.push(format!(
                "{file}:{}: {name}: first body line `{first}`",
                k + 1
            ));
        }
        i = k;
    }
    for e in exempt {
        if !seen.contains(*e) {
            bad.push(format!("{file}: exempt test {e} not found"));
        }
    }
    bad
}

/// `bound_census_refuses_unsupported_attributes` (gate): negative
/// witnesses for the census parser on synthetic sources. A test
/// whose `#[test]` carries a trailing comment is counted (and
/// refused when unbound, accepted when armed); every other test
/// attribute form is refused.
pub fn bound_census_witness() {
    let body = |first: &str| format!("fn t() {{\n    {first}\n}}\n");
    let unbound = format!("#[test] // regression case\n{}", body("loop {}"));
    let v = census_violations(&unbound, "witness.rs", &[]);
    assert!(
        v.iter().any(|l| l.contains("t: first body line `loop {}`")),
        "a `#[test] // comment` test without a bound must be counted and refused: {v:?}"
    );
    let armed = format!(
        "#[test] // regression case\n{}",
        body("let _bound = deadline::TestBound::arm();")
    );
    let v = census_violations(&armed, "witness.rs", &[]);
    assert!(
        v.is_empty(),
        "an armed `#[test] // comment` test must be accepted: {v:?}"
    );
    let strings = format!(
        "#[ignore = \"a test reason\"]\n#[test] // regression case\n{}",
        body("let _bound = deadline::TestBound::arm();")
    );
    let v = census_violations(&strings, "witness.rs", &[]);
    assert!(
        v.is_empty(),
        "`test` inside a string literal must not be refused: {v:?}"
    );
    for form in [
        "#[test] fn t() {}",
        "#[test] #[ignore]",
        "#[ignore] #[test]",
        "# [test]",
        "#[tokio::test]",
        "#[test_case(1)]",
        "#[cfg_attr(target_os = \"linux\", test)]",
        "#[cfg_attr(unix, tokio::test)]",
        "#[\ntest\n]",
        "#\n[test]",
    ] {
        let src = format!(
            "{form}\n{}",
            body("let _bound = deadline::TestBound::arm();")
        );
        let v = census_violations(&src, "witness.rs", &[]);
        assert!(
            v.iter().any(|l| l.contains("unsupported test attribute")),
            "`{form}` must be refused: {v:?}"
        );
    }
}

/// The bound inventory (gate): `tests/*.rs` must equal the reviewed
/// `table`, and every armed file must run its own `bound_census`.
pub fn bound_inventory(table: &[(&str, BoundRole)]) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut found: Vec<String> = std::fs::read_dir(&dir)
        .expect("list tests/")
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".rs"))
        .collect();
    found.sort();
    let nested: Vec<String> = std::fs::read_dir(&dir)
        .expect("list tests/")
        .flatten()
        .filter(|e| e.path().join("main.rs").exists())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    assert!(
        nested.is_empty(),
        "bound inventory: test targets outside tests/*.rs (tests/<dir>/main.rs): {nested:?}"
    );
    let mut listed: Vec<String> = table.iter().map(|(f, _)| (*f).to_owned()).collect();
    listed.sort();
    assert_eq!(
        found, listed,
        "bound inventory: tests/*.rs differs from the reviewed table"
    );
    for (f, role) in table {
        let src = std::fs::read_to_string(dir.join(f)).expect("read a test file");
        let censused = src.contains("deadline::bound_census(");
        assert_eq!(
            censused,
            *role == BoundRole::Armed,
            "bound inventory: {f} is {role:?} but runs bound_census: {censused}"
        );
    }
}
