//! Two actual constructor-failure paths. The pre-Ready error is injected after
//! a genuine held EXEC; the alias refusal is the unchanged production gate.
use super::super::runtime_capture::{CaptureFailure, CaptureFailureKind, CaptureStage};
use super::native_tests::{bytes, exact_nx_maps, maps, rows, state};
use super::*;
use crate::linux::remote::dynamic::owner::launch_cleanup_probe::Probe;
use crate::linux::remote::dynamic::owner::tests::{pin, reaped};
use crate::selected::{InstructionProvider, ProviderDecision, SelectedInput, SemanticsError};
use crate::{
    DynamicAdmissionSession, DynamicRuntimeCleanupStatus, DynamicRuntimeLaunchFailure,
    DynamicRuntimeOptions,
};
use std::any::Any;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::mpsc::{Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};

const TIMEOUT: Duration = Duration::from_secs(3);
const BASE: u64 = 0x200000;
const ENTRY: u64 = 0x201120;
const ALIAS: &str = "exec source has a visible file-offset alias";
const INJECTED: &str = "runtime cleanup oracle before Ready";
// Exact 31-byte compiler-produced body from the preserved failed C experiment.
// Its first original MOV would change RAX from zero to SYS_getpid.
const CODE: &[u8] = &[
    0xb8, 0x27, 0, 0, 0, 0x0f, 0x05, 0x48, 0x89, 0xc7, 0xb8, 0xba, 0, 0, 0, 0x0f, 0x05, 0x48, 0x31,
    0xc7, 0x48, 0x83, 0xc7, 7, 0xb8, 0xe7, 0, 0, 0, 0x0f, 0x05,
];
static NEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Alias,
    BeforeReady,
}

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    original: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let _fork = crate::TEST_FILE_FORK.lock().unwrap();
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "runtime-cleanup-alias-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(directory.parent().unwrap()).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("fixture");
        let mut original = vec![0; 992];
        original[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 4)] {
            original[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        original[20..24].copy_from_slice(&1_u32.to_le_bytes());
        original[24..32].copy_from_slice(&ENTRY.to_le_bytes());
        original[32..40].copy_from_slice(&64_u64.to_le_bytes());
        // Exact observed load geometry: logical ranges are disjoint, but both
        // PT_LOADs expose file page zero at distinct R/RX virtual addresses.
        for (index, kind, flags, offset, address, length, align) in [
            (0, 6_u32, 4_u32, 0x40_u64, BASE + 0x40, 0xe0_u64, 8_u64),
            (1, 1, 4, 0, BASE, 0x120, 0x1000),
            (2, 1, 5, 0x120, ENTRY, CODE.len() as u64, 0x1000),
            (3, 0x6474_e551, 6, 0, 0, 0, 0),
        ] {
            let at = 64 + index * 56;
            original[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            original[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            for (field, value) in [offset, address, address, length, length, align]
                .into_iter()
                .enumerate()
            {
                original[at + 8 + field * 8..at + 16 + field * 8]
                    .copy_from_slice(&value.to_le_bytes());
            }
        }
        original[0x120..0x120 + CODE.len()].copy_from_slice(CODE);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&original).unwrap();
        drop(file);
        Self {
            directory,
            path,
            original,
        }
    }
    fn command(&self) -> LaunchCommand {
        LaunchCommand::new(&self.path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

struct Provider {
    calls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    owner_cancel: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    cancelled_at_drop: Arc<AtomicBool>,
}
impl InstructionProvider for Provider {
    fn decide(&mut self, _input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("a failed constructor must never call its provider")
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        // Observation only: a failed/poisoned slot records false, never panics
        // in Drop and never supplies synthetic cancellation authority.
        let cancelled = self.owner_cancel.lock().ok().is_some_and(|slot| {
            slot.as_ref()
                .is_some_and(|cancel| cancel.load(Ordering::Acquire))
        });
        self.cancelled_at_drop.store(cancelled, Ordering::SeqCst);
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn duplicate(handle: &OwnedFd) -> OwnedFd {
    // The original Owner still holds this exact incarnation throughout copy.
    let raw = unsafe { libc::fcntl(handle.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    assert!(
        raw >= 0,
        "duplicate original pin: {}",
        std::io::Error::last_os_error()
    );
    unsafe { OwnedFd::from_raw_fd(raw) }
}
fn live(pin: &OwnedFd) {
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&raw mut poll, 1, 0) }, 0);
    assert_eq!(poll.revents, 0);
}

struct Before {
    until: Instant,
    stop: DynamicStop,
    state: TaskStateSnapshot,
    maps: Vec<u8>,
    source: Vec<u8>,
    app: OwnedFd,
    broker: OwnedFd,
    pid: i32,
    broker_pid: i32,
}
impl Before {
    fn capture(owner: &Owner, ready: &super::super::super::super::Ready, until: Instant) -> Self {
        assert_eq!(ready.pid, owner.pid);
        let stop = ready.event.stop_token().unwrap().clone();
        assert_eq!(stop.tid, owner.pid);
        assert_eq!(stop.session, owner.session);
        assert!(matches!(&ready.event.kind, DynamicEventKind::Exec { .. }));
        assert!(owner.owned.contains(&owner.pid) && owner.stopped.contains_key(&owner.pid));
        let app = duplicate(owner.handles.get(&owner.pid).unwrap());
        let broker_pid = owner.broker.as_ref().unwrap().pid;
        assert_ne!(owner.pid, broker_pid);
        // The Owner's unreaped broker reserves this PID while this borrowed
        // callback obtains its own independent stable kernel descriptor.
        let broker = pin(broker_pid);
        live(&app);
        live(&broker);
        let actual = state(owner.pid);
        assert_eq!(
            (actual.registers.rip, actual.registers.orig_rax),
            (ENTRY, libc::SYS_execve as u64)
        );
        assert_eq!(actual.registers.rax, (-i64::from(libc::ENOSYS)) as u64);
        let maps = maps(owner.pid);
        let parsed = rows(&maps);
        let main = parsed
            .iter()
            .filter(|r| r.start == BASE || r.start == BASE + 4096)
            .collect::<Vec<_>>();
        assert_eq!(main.len(), 2);
        for (index, row) in main.iter().enumerate() {
            assert_eq!(row.start, BASE + index as u64 * 4096);
            assert_eq!(row.end, row.start + 4096);
            assert_eq!(
                row.permissions,
                if index == 0 { *b"r--p" } else { *b"r-xp" }
            );
        }
        let a = std::str::from_utf8(&main[0].raw)
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>();
        let b = std::str::from_utf8(&main[1].raw)
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(a[2], "00000000");
        assert_eq!(b[2], "00000000");
        assert_eq!(&a[3..], &b[3..]);
        assert_ne!(a[4], "0");
        let source = bytes(owner.pid, BASE, 8192);
        assert_eq!(&source[0x1120..0x1120 + CODE.len()], CODE);
        assert_eq!(&source[..4096], &source[4096..]);
        live(&app);
        live(&broker);
        Self {
            until,
            stop,
            state: actual,
            maps,
            source,
            app,
            broker,
            pid: owner.pid,
            broker_pid,
        }
    }
}

struct Observed {
    before: Before,
    cancel: Arc<AtomicBool>,
    journal: crate::KernelProgressReader,
}
fn observe_cleanup(owner: &Owner, until: Instant, before: Before, scenario: Scenario) -> Observed {
    assert_eq!(
        until, before.until,
        "cleanup observation must retain original operation until"
    );
    assert_eq!(owner.pid, before.pid);
    assert_eq!(owner.session, before.stop.session);
    assert_eq!(owner.broker.as_ref().unwrap().pid, before.broker_pid);
    live(&before.app);
    live(&before.broker);
    assert_eq!(bytes(owner.pid, BASE, 8192), before.source);
    match scenario {
        Scenario::BeforeReady => {
            assert!(owner.runtime.is_none() && owner.admission.is_none());
            assert_eq!(state(owner.pid), before.state);
            assert_eq!(maps(owner.pid), before.maps);
        }
        Scenario::Alias => {
            let runtime = owner.runtime.as_ref().unwrap();
            assert_eq!(runtime.until, until);
            assert_eq!(runtime.stage, RuntimeStage::RuntimeCapture);
            assert!(!runtime.ready_issued && runtime.census.is_none());
            assert!(
                runtime.ordinary_attempts.is_empty()
                    && runtime.selected_attempts.is_empty()
                    && runtime.kernel_attempts.is_empty()
            );
            let prepared = runtime.bootstrap.as_ref().unwrap();
            let boot = prepared.completed().unwrap();
            assert_eq!(boot.evidence.exec_event, before.state);
            let mut exit = before.state.clone();
            exit.registers.rax = 0;
            assert_eq!(boot.evidence.exec_exit, exit);
            let mut first_registers = exit.registers;
            first_registers.rip = ENTRY + 1;
            first_registers.orig_rax = u64::MAX;
            assert_eq!(boot.evidence.entry_trap.registers, first_registers);
            assert_eq!(boot.evidence.entry_trap.mask, exit.mask);
            let mut restored = boot.evidence.entry_trap.clone();
            restored.registers.rip = ENTRY;
            assert_eq!(boot.evidence.restored_entry, restored);
            assert_eq!(state(owner.pid), restored);
            assert_eq!(restored.registers.rax, 0, "first original MOV executed");
            exact_nx_maps(&before.maps, &maps(owner.pid), &boot.island.range);
            let progress = prepared.progress();
            assert!(progress.first_failure.is_none());
            for (wait, signal) in [
                (progress.exec_wait, libc::SIGTRAP | 0x80),
                (progress.first_user_wait, libc::SIGTRAP),
                (progress.runner_wait, libc::SIGTRAP),
            ] {
                let (pid, status) = wait.unwrap();
                assert_eq!(pid, owner.pid);
                assert!(libc::WIFSTOPPED(status));
                assert_eq!(libc::WSTOPSIG(status), signal);
                assert_eq!(status >> 16, 0);
            }
            assert_eq!(
                runtime.sources.failure(),
                Some(CaptureFailure {
                    stage: CaptureStage::Inventory,
                    window: None,
                    kind: CaptureFailureKind::Refused(ALIAS),
                })
            );
            assert!(runtime.sources.original_complete());
            assert!(!runtime.sources.capture_complete() && !runtime.sources.recheck_complete());
            assert_eq!(runtime.sources.window_count(), 0);
            for (storage, progress, expected) in [
                {
                    let (s, p) = runtime.sources.original_maps();
                    (s, p, before.maps.clone())
                },
                {
                    let (s, p) = runtime.sources.quarantine_maps();
                    (s, p, maps(owner.pid))
                },
            ] {
                assert_eq!(storage.len(), 65536);
                assert!(progress.complete && progress.failure.is_none());
                assert_eq!(&storage[..progress.copied_bytes], expected);
                assert!(storage[progress.copied_bytes..].iter().all(|b| *b == 0));
            }
        }
    }
    let journal = owner.kernel_journal.reader();
    let snapshot = journal.snapshot();
    assert!(
        !snapshot.archive_poisoned
            && snapshot.attempts.is_empty()
            && snapshot.runtime_attempts.is_empty()
    );
    live(&before.app);
    live(&before.broker);
    Observed {
        before,
        cancel: Arc::clone(&owner.cancel),
        journal,
    }
}

struct Release(Option<Sender<()>>);
impl Release {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        self.release();
    }
}
type ObservedResult = Result<Observed, Box<dyn Any + Send>>;

fn original(error: &DynamicRuntimeLaunchFailure, scenario: Scenario) {
    match scenario {
        Scenario::Alias => assert!(matches!(error.error(), GateError::Refused(ALIAS))),
        Scenario::BeforeReady => assert!(matches!(
            error.error(),
            GateError::Control(LaunchError::Invalid(INJECTED))
        )),
    }
}
fn required_receipt(error: &mut DynamicRuntimeLaunchFailure) -> crate::DynamicCleanup {
    match error.wait_cleanup(TIMEOUT) {
        Ok(DynamicRuntimeCleanupStatus::Complete(receipt)) => receipt.clone(),
        other => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "actual cleanup did not complete: {other:?}; physical ownership is not qualified"
            );
            std::process::abort();
        }
    }
}

fn run(scenario: Scenario) {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let owner_cancel = Arc::new(Mutex::new(None));
    let owner_cancel_ready = Arc::clone(&owner_cancel);
    let cancelled_at_drop = Arc::new(AtomicBool::new(false));
    let initial = Arc::new(Mutex::new(None));
    let initial_ready = Arc::clone(&initial);
    let (observed_tx, observed_rx) = channel::<ObservedResult>();
    let (release_tx, release_rx) = channel();
    let (gate_tx, gate_rx) = channel();
    // The client owns this guard before construction. Every panic/error drops
    // it and wakes the real owner. A separate 3s watchdog also fails the gate
    // test while proceeding to cleanup; it can never count as an explicit release.
    let mut release = Release(Some(release_tx));
    let probe = Probe::new(
        Box::new(move |owner, ready, until| {
            *owner_cancel_ready.lock().unwrap() = Some(Arc::clone(&owner.cancel));
            let captured = Before::capture(owner, ready, until);
            *initial_ready.lock().unwrap() = Some(captured);
            if scenario == Scenario::BeforeReady {
                Err(LaunchError::Invalid(INJECTED))
            } else {
                Ok(())
            }
        }),
        Box::new(move |owner, until| {
            let observation = catch_unwind(AssertUnwindSafe(|| {
                let before = initial
                    .lock()
                    .unwrap()
                    .take()
                    .expect("actual initial held EXEC");
                observe_cleanup(owner, until, before, scenario)
            }));
            let _ = observed_tx.send(observation);
            let explicitly_released = release_rx.recv_timeout(TIMEOUT).is_ok();
            let _ = gate_tx.send(explicitly_released);
            // The actual Owner::cleanup and actual done.send follow this hook.
        }),
    );
    let provider = Provider {
        calls: Arc::clone(&calls),
        drops: Arc::clone(&drops),
        owner_cancel,
        cancelled_at_drop: Arc::clone(&cancelled_at_drop),
    };
    let result = {
        let _fork = crate::TEST_FILE_FORK.lock().unwrap();
        // SAFETY: owned literal singleton ELF, no external writers or signals.
        // The read-only file alias intentionally exercises the gate's existing
        // refusal; no original instruction or provider decision is requested.
        unsafe {
            DynamicAdmissionSession::launch_runtime_with_cleanup_inner(
                &fixture.command(),
                DynamicRuntimeOptions::default(),
                provider,
                TIMEOUT,
                Some(probe),
            )
        }
    };
    let mut error = match result {
        Err(error) => error,
        Ok(session) => {
            release.release();
            if session.terminate(TIMEOUT).is_err() {
                std::process::abort();
            }
            panic!("the constructor unexpectedly accepted the refusal fixture");
        }
    };
    let mut observed = None;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        original(&error, scenario);
        let error_pointer = error.error() as *const GateError;
        let description = format!("{:?}", error.error());
        let value = observed_rx
            .recv_timeout(TIMEOUT)
            .expect("actual owner cleanup gate observation");
        let value = match value {
            Ok(value) => value,
            Err(payload) => resume_unwind(payload),
        };
        observed = Some(value);
        let value = observed.as_ref().unwrap();
        assert!(value.cancel.load(Ordering::Acquire));
        assert!(matches!(
            error.cleanup_status(),
            DynamicRuntimeCleanupStatus::Pending
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(cancelled_at_drop.load(Ordering::SeqCst));
        for timeout in [Duration::from_nanos(1), Duration::from_millis(1)] {
            live(&value.before.app);
            live(&value.before.broker);
            assert!(matches!(
                error.wait_cleanup(timeout),
                Err(LaunchError::Timeout(
                    "dynamic cleanup remains owned by tracer"
                ))
            ));
            assert!(matches!(
                error.cleanup_status(),
                DynamicRuntimeCleanupStatus::Pending
            ));
            original(&error, scenario);
            assert_eq!(error.error() as *const GateError, error_pointer);
            assert_eq!(format!("{:?}", error.error()), description);
            live(&value.before.app);
            live(&value.before.broker);
            assert!(
                matches!(gate_rx.try_recv(), Err(TryRecvError::Empty)),
                "owner left the parked cleanup gate"
            );
        }
    }));
    release.release();
    let receipt = required_receipt(&mut error);
    // Receipt comes only from the original Owner. Exact kernel handles are
    // checked after that receipt; no test consumes the owner's terminal wait.
    if let Some(value) = &observed {
        reaped(&value.before.app);
        reaped(&value.before.broker);
    }
    if let Err(payload) = outcome {
        resume_unwind(payload);
    }
    assert!(
        gate_rx.recv_timeout(TIMEOUT).unwrap(),
        "cleanup watchdog expired instead of explicit release"
    );
    let value = observed.unwrap();
    assert_eq!(receipt.reaped, [value.before.pid]);
    assert_ne!(value.before.pid, value.before.broker_pid);
    original(&error, scenario);
    assert_eq!(
        required_receipt(&mut error),
        receipt,
        "cached actual receipt changed"
    );
    original(&error, scenario);
    let journal = value.journal.snapshot();
    assert_eq!(journal.writer, crate::KernelWriterStatus::Cleaned);
    assert!(
        !journal.archive_poisoned
            && journal.attempts.is_empty()
            && journal.runtime_attempts.is_empty()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(cancelled_at_drop.load(Ordering::SeqCst));
    assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.original);
}

#[test]
fn runtime_launch_alias_refusal_retains_pending_cleanup_and_physical_custody() {
    isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::launch_cleanup_native_tests::runtime_launch_alias_refusal_retains_pending_cleanup_and_physical_custody",
        || run(Scenario::Alias),
    );
}

#[test]
fn runtime_launch_pre_ready_failure_preserves_original_error_and_cleanup() {
    isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::launch_cleanup_native_tests::runtime_launch_pre_ready_failure_preserves_original_error_and_cleanup",
        || run(Scenario::BeforeReady),
    );
}
