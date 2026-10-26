//! Real selected-kernel failure prefixes. Expected original states come from a
//! separate raw-ptrace run of the unchanged ELF, never from journal projection,
//! production lifecycle validation or the selected semantic transition helper.
use super::super::fault::{
    JournalFault, JournalFaultAction, JournalFaultPoint, JournalFaultRelease, JournalFaultWitness,
};
use super::super::*;
use crate::gate::{GateError, ImageFacts};
use crate::linux::remote::dynamic::admission::{AdmissionReply, AdmissionRequest, PendingToken};
use std::ffi::CString;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::mpsc::sync_channel;

pub(in crate::linux::remote::dynamic::owner) mod raw;
mod transport;

pub(in crate::linux::remote::dynamic::owner) const TIMEOUT: Duration = Duration::from_secs(3);
pub(in crate::linux::remote::dynamic::owner) const BASE: u64 = 0x400000;
pub(in crate::linux::remote::dynamic::owner) const ENTRY: u64 = BASE + 4096;
pub(in crate::linux::remote::dynamic::owner) const DATA: u64 = 0x600000;
pub(in crate::linux::remote::dynamic::owner) const SOURCE_BYTES: usize = 8192;
pub(in crate::linux::remote::dynamic::owner) const DATA_BYTES: usize = 16384;
pub(in crate::linux::remote::dynamic::owner) const PARENT_SP: u64 = DATA + 0x1f00;
pub(in crate::linux::remote::dynamic::owner) const CHILD_SP: u64 = DATA + 0x3f00;
pub(in crate::linux::remote::dynamic::owner) const FLAGS: u64 = 0xed7;
pub(in crate::linux::remote::dynamic::owner) const APP_MASK: u64 =
    (1 << (libc::SIGUSR1 - 1)) | (1 << (libc::SIGUSR2 - 1));
pub(in crate::linux::remote::dynamic::owner) const PIDFD_THREAD: i32 = libc::O_EXCL;
static NEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct Frame {
    pub(in crate::linux::remote::dynamic::owner) state: KernelCapturedState,
    pub(in crate::linux::remote::dynamic::owner) storage: Vec<u8>,
    pub(in crate::linux::remote::dynamic::owner) source: Vec<u8>,
}

pub(in crate::linux::remote::dynamic::owner) struct Fixture {
    directory: PathBuf,
    pub(in crate::linux::remote::dynamic::owner) path: PathBuf,
    pub(in crate::linux::remote::dynamic::owner) source: Vec<u8>,
    pub(in crate::linux::remote::dynamic::owner) heads: BTreeSet<u64>,
    pub(in crate::linux::remote::dynamic::owner) number: u64,
    pub(in crate::linux::remote::dynamic::owner) selected_pc: u64,
}

impl Fixture {
    pub(in crate::linux::remote::dynamic::owner) fn new(number: i64) -> Arc<Self> {
        assert!(matches!(
            number,
            libc::SYS_getpid | libc::SYS_gettid | libc::SYS_clone
        ));
        let mut source = vec![0_u8; SOURCE_BYTES];
        source[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 3)] {
            source[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        source[20..24].copy_from_slice(&1_u32.to_le_bytes());
        source[24..32].copy_from_slice(&ENTRY.to_le_bytes());
        source[32..40].copy_from_slice(&64_u64.to_le_bytes());
        for (at, offset, address, bytes, protection) in [
            (64_usize, 0_u64, BASE, SOURCE_BYTES as u64, 5_u32),
            (120, SOURCE_BYTES as u64, DATA, DATA_BYTES as u64, 6),
        ] {
            source[at..at + 4].copy_from_slice(&1_u32.to_le_bytes());
            source[at + 4..at + 8].copy_from_slice(&protection.to_le_bytes());
            for (slot, value) in [
                (8, offset),
                (16, address),
                (32, bytes),
                (40, bytes),
                (48, 4096),
            ] {
                source[at + slot..at + slot + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        source[176..180].copy_from_slice(&0x6474e551_u32.to_le_bytes());
        source[180..184].copy_from_slice(&6_u32.to_le_bytes());
        source[224..232].copy_from_slice(&16_u64.to_le_bytes());
        let mut cursor = 4096;
        let mut heads = BTreeSet::new();
        let mut emit = |bytes: &[u8]| {
            let pc = BASE + cursor as u64;
            assert!(heads.insert(pc));
            source[cursor..cursor + bytes.len()].copy_from_slice(bytes);
            cursor += bytes.len();
            pc
        };
        let literal = |register: u8, value: u64| {
            let mut bytes = vec![0x48 | (register >> 3), 0xb8 | (register & 7)];
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes
        };
        for register in 0..16 {
            emit(&literal(
                register,
                0x1234_5678_0000_0000 | u64::from(register),
            ));
        }
        emit(&literal(4, PARENT_SP));
        emit(&[0xdb, 0xe3]); // FNINIT
        emit(&[0xd9, 0xe8]); // FLD1
        emit(&[0x66, 0x0f, 0x76, 0xc0]); // PCMPEQD XMM0,XMM0
        emit(&literal(0, number as u64));
        if number == libc::SYS_clone {
            for (register, value) in [(7, 0x10f00), (6, CHILD_SP), (2, 0), (10, 0), (8, 0)] {
                emit(&literal(register, value));
            }
        }
        let mut push = vec![0x68];
        push.extend_from_slice(&(FLAGS as u32).to_le_bytes());
        emit(&push);
        emit(&[0x9d]);
        let selected_pc = emit(&[0x0f, 0x05]);
        emit(&[0x0f, 0x0b]); // No fault case resumes this original continuation.
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-tmp")
            .join(format!(
                "kernel-journal-native-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let file_guard = crate::TEST_FILE_FORK.lock().unwrap();
        std::fs::create_dir_all(directory.parent().unwrap()).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("original");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&source).unwrap();
        let data: Vec<u8> = (0..DATA_BYTES)
            .map(|i| ((17 * i + 43) & 255) as u8)
            .collect();
        file.write_all(&data).unwrap();
        drop(file);
        drop(file_guard);
        Arc::new(Self {
            directory,
            path,
            source,
            heads,
            number: number as u64,
            selected_pc,
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn facts(&self) -> ImageFacts {
        ImageFacts {
            start: BASE,
            bytes: self.source.clone(),
            heads: self.heads.clone(),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

// Establish the exclusive thread-child wait domain before the worker exists.
// Copied application handlers must never run on a tracer before it blocks its
// signals. APP_MASK is supplied separately to the held application at launch.
pub(in crate::linux::remote::dynamic::owner) fn spawn_masked<T: Send + 'static>(
    action: impl FnOnce() -> T + Send + 'static,
) -> std::thread::JoinHandle<T> {
    const BLOCKED: u64 = !((1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1)));
    fn read_mask() -> u64 {
        let mut actual = 0_u64;
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    std::ptr::null::<u64>(),
                    &mut actual,
                    8,
                )
            },
            0
        );
        actual
    }
    struct CallerMask(u64);
    impl Drop for CallerMask {
        fn drop(&mut self) {
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_rt_sigprocmask,
                        libc::SIG_SETMASK,
                        &self.0,
                        std::ptr::null_mut::<u64>(),
                        8,
                    )
                },
                0
            );
            assert_eq!(read_mask(), self.0);
        }
    }
    let blocked = u64::MAX;
    let mut previous = 0_u64;
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &blocked,
                &mut previous,
                8,
            )
        },
        0
    );
    let caller = CallerMask(previous);
    assert_eq!(read_mask(), BLOCKED);
    let worker = std::thread::spawn(move || {
        // Reblock libc-reserved signals at the first Rust worker boundary too;
        // no worker code ever installs the application mask on this tracer.
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    &blocked,
                    std::ptr::null_mut::<u64>(),
                    8,
                )
            },
            0
        );
        assert_eq!(read_mask(), BLOCKED);
        action()
    });
    drop(caller);
    worker
}
pub(in crate::linux::remote::dynamic::owner) fn physically_gone(pin: &OwnedFd) -> bool {
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    (unsafe { libc::poll(&mut poll, 1, 0) }) == 1 && poll.revents == (libc::POLLIN | libc::POLLHUP)
}
pub(in crate::linux::remote::dynamic::owner) fn assert_echild(pin: &OwnedFd) {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pin.as_raw_fd() as u32,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}
pub(in crate::linux::remote::dynamic::owner) fn duplicate(pin: &OwnedFd) -> OwnedFd {
    let fd = unsafe { libc::fcntl(pin.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    assert!(fd >= 0);
    unsafe { OwnedFd::from_raw_fd(fd) }
}

struct Setup {
    reader: KernelProgressReader,
    input: SelectedInput,
    token: PendingToken,
    parent: i32,
    until: Instant,
}
#[derive(Debug, Eq, PartialEq)]
struct Held {
    tid: i32,
    status: i32,
    frame: Frame,
}
enum Outcome {
    Completed(Box<DynamicAdmissionCompletion>),
    Error(GateError),
    Panic(String),
}
struct Finished {
    outcome: Outcome,
    reader: KernelProgressReader,
    before_cleanup: KernelProgressSnapshot,
    held: Vec<Held>,
    admission_retained: bool,
    pins: Vec<(i32, OwnedFd)>,
    cleanup: Result<DynamicCleanup, LaunchError>,
}
struct Trial {
    setup: Setup,
    witness: Option<JournalFaultWitness>,
    during: Option<KernelProgressSnapshot>,
    finished: Finished,
}

fn panic_text(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(value) = panic.downcast_ref::<&str>() {
        (*value).to_owned()
    } else if let Some(value) = panic.downcast_ref::<String>() {
        value.clone()
    } else {
        "unrecognized native test panic".into()
    }
}

pub(in crate::linux::remote::dynamic::owner) fn launch_owner(
    owner: &mut Owner,
    fixture: &Fixture,
    options: DynamicAdmissionOptions,
    inherited_mask: u64,
) -> (DynamicEvent, KernelProgressReader) {
    owner.lifecycle_options = Some(options.lifecycle);
    let until = Instant::now() + TIMEOUT;
    let file_guard = crate::TEST_FILE_FORK.lock().unwrap();
    let launched = launch::start(
        owner,
        &LaunchCommand::new(&fixture.path),
        inherited_mask,
        until,
    );
    drop(file_guard);
    let initial = launched.unwrap().event;
    let ready = owner
        .execute_admission(
            AdmissionRequest::Start {
                initial: initial.stop_token().unwrap().clone(),
                facts: vec![fixture.facts()],
                options,
            },
            until,
        )
        .unwrap();
    let AdmissionReply::Ready(state, reader) = ready else {
        panic!("actual admission Ready")
    };
    assert_eq!(state.registers.rip, ENTRY);
    assert_eq!(state.registers.orig_rax, u64::MAX);
    assert_eq!(state.signal_mask, APP_MASK);
    (initial, reader)
}

fn execute(
    fixture: Arc<Fixture>,
    point: Option<JournalFaultPoint>,
    release_action: Option<JournalFaultRelease>,
) -> Trial {
    let (start_tx, start_rx) = sync_channel(1);
    let (witness_tx, witness_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let (done_tx, done_rx) = sync_channel(1);
    let worker = spawn_masked(move || {
        let blocked = launch::BlockedSignals::new().unwrap();
        let mut owner = Owner::new(
            NEXT.fetch_add(1, Ordering::Relaxed),
            Arc::new(AtomicBool::new(false)),
        );
        let reader = owner.kernel_journal.reader();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let options = DynamicAdmissionOptions {
                lifecycle: if fixture.number == libc::SYS_clone as u64 {
                    DynamicLifecycleOptions::thread_only()
                } else {
                    DynamicLifecycleOptions::default()
                },
                ..DynamicAdmissionOptions::default()
            };
            let (_, live_reader) = launch_owner(&mut owner, &fixture, options, APP_MASK);
            assert_eq!(live_reader.snapshot(), reader.snapshot());
            let until = Instant::now() + TIMEOUT;
            let reply = owner
                .execute_admission(AdmissionRequest::Advance, until)
                .unwrap();
            let AdmissionReply::Provider(pending) = reply else {
                panic!("one original syscall provider input")
            };
            assert_eq!(
                pending.input.instruction().logical_pc(),
                fixture.selected_pc
            );
            assert_eq!(pending.input.registers().rax, fixture.number);
            assert_eq!(pending.input.registers().eflags, FLAGS);
            start_tx
                .send(Setup {
                    reader: reader.clone(),
                    input: pending.input.clone(),
                    token: pending.token.clone(),
                    parent: owner.pid,
                    until,
                })
                .unwrap();
            if let Some(point) = point {
                owner.journal_fault = Some(JournalFault {
                    point,
                    memory: vec![
                        BASE..BASE + SOURCE_BYTES as u64,
                        DATA..DATA + DATA_BYTES as u64,
                    ],
                    action: JournalFaultAction::AwaitRelease {
                        ready: witness_tx,
                        release: release_rx,
                    },
                });
            }
            match owner.execute_admission(
                AdmissionRequest::Complete {
                    token: pending.token,
                    decision: crate::selected::ProviderDecision::Native,
                },
                until,
            ) {
                Ok(AdmissionReply::Event(DynamicAdmissionEvent::Completed(done))) => {
                    Outcome::Completed(done)
                }
                Ok(_) => panic!("kernel trial returned another phase"),
                Err(error) => Outcome::Error(error),
            }
        }));
        let outcome = match result {
            Ok(result) => result,
            Err(panic) => Outcome::Panic(panic_text(panic)),
        };
        let captured = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let held = owner
                .stopped
                .iter()
                .map(|(&tid, &status)| Held {
                    tid,
                    status,
                    frame: raw::frame(tid),
                })
                .collect::<Vec<_>>();
            let pins = owner
                .handles
                .iter()
                .map(|(&tid, pin)| (tid, duplicate(pin)))
                .collect();
            if matches!(&outcome, Outcome::Error(_)) {
                assert!(owner.closing);
                assert!(owner.cancel.load(Ordering::Acquire));
                let prefix = reader.snapshot();
                // Cancellation is checked before time or any native action.
                // The repeated request cannot renew the original deadline or
                // retry an invocation whose kernel effects may have occurred.
                let repeated = owner.execute_admission(AdmissionRequest::Advance, Instant::now());
                assert!(matches!(
                    repeated,
                    Err(GateError::Control(LaunchError::Invalid(
                        "dynamic operation cancelled"
                    )))
                ));
                assert_eq!(reader.snapshot(), prefix);
                let after = owner
                    .stopped
                    .iter()
                    .map(|(&tid, &status)| Held {
                        tid,
                        status,
                        frame: raw::frame(tid),
                    })
                    .collect::<Vec<_>>();
                assert_eq!(after, held);
            }
            (held, pins)
        }));
        let before_cleanup = reader.snapshot();
        let admission_retained = owner.admission.is_some();
        // No assertion path can bypass cleanup; the owner stays on its original
        // tracer thread if kernel physical reaping requires more time.
        let cleanup = owner.cleanup();
        let mask_restored = blocked.restore();
        if let Err(error) = mask_restored {
            let _ = done_tx.send(Err(format!(
                "owner test signal-mask restoration: {error:?}"
            )));
            return;
        }
        let (held, pins) = match captured {
            Ok(value) => value,
            Err(panic) => {
                let _ = done_tx.send(Err(panic_text(panic)));
                return;
            }
        };
        let _ = done_tx.send(Ok(Finished {
            outcome,
            reader,
            before_cleanup,
            held,
            admission_retained,
            pins,
            cleanup,
        }));
    });
    let setup_result = start_rx.recv_timeout(2 * TIMEOUT);
    let witness = if point.is_some() {
        witness_rx.recv_timeout(2 * TIMEOUT).ok()
    } else {
        None
    };
    let during = setup_result
        .as_ref()
        .ok()
        .map(|setup| setup.reader.snapshot());
    if let Some(action) = release_action {
        let _ = release_tx.send(action);
    }
    // With no release action, the exact original operation deadline expires
    // inside the actual owner latch; a channel sleep is never a phase witness.
    let done_result = done_rx.recv_timeout(3 * TIMEOUT);
    drop(release_tx);
    let finished = done_result
        .expect("native journal caller deadline; original owner retains cleanup")
        .unwrap();
    worker.join().unwrap();
    let setup = setup_result.expect("native invocation setup");
    assert_eq!(
        point.is_some(),
        witness.is_some(),
        "actual phase witness is required"
    );
    let mut expected = finished
        .pins
        .iter()
        .map(|(tid, _)| *tid)
        .collect::<Vec<_>>();
    let mut reaped = finished.cleanup.as_ref().unwrap().reaped.clone();
    expected.sort_unstable();
    reaped.sort_unstable();
    assert_eq!(reaped, expected);
    for (_, pin) in &finished.pins {
        assert!(physically_gone(pin));
        assert_echild(pin);
    }
    if let Some(witness) = &witness {
        assert_eq!(witness.until, setup.until);
        for (_, pin) in &witness.owned {
            assert!(physically_gone(pin));
            assert_echild(pin);
        }
    }
    assert_eq!(
        finished.reader.snapshot().writer,
        KernelWriterStatus::Cleaned
    );
    assert_eq!(
        finished.reader.snapshot().attempts,
        finished.before_cleanup.attempts
    );
    Trial {
        setup,
        witness,
        during,
        finished,
    }
}

fn attempt(snapshot: &KernelProgressSnapshot) -> &KernelAttemptSnapshot {
    assert!(!snapshot.archive_poisoned);
    assert_eq!(snapshot.attempts.len(), 1);
    &snapshot.attempts[0]
}
fn stored(attempt: &KernelAttemptSnapshot, slot: KernelStateSlot) -> Option<&KernelCapturedState> {
    let rows = attempt
        .states
        .iter()
        .filter(|row| row.slot == slot)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    match rows[0].status {
        KernelCaptureStatus::Complete => Some(rows[0].state.as_ref().unwrap()),
        KernelCaptureStatus::Unused => {
            assert!(rows[0].state.is_none());
            None
        }
        other => panic!("unexpected partial native capture: {other:?}"),
    }
}
fn count(attempt: &KernelAttemptSnapshot, predicate: impl Fn(&KernelJournalFact) -> bool) -> usize {
    attempt.facts.iter().filter(|fact| predicate(fact)).count()
}
fn child_tid(attempt: &KernelAttemptSnapshot) -> Option<i32> {
    let tids = attempt
        .facts
        .iter()
        .filter_map(|fact| match fact {
            KernelJournalFact::RawStop {
                tid,
                pin: KernelPinKind::Thread,
                task: None,
                ..
            } => Some(*tid),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(tids.len() <= 1);
    tids.into_iter().next()
}
fn expected_state(
    oracle: &raw::Oracle,
    slot: KernelStateSlot,
    parent: i32,
    child: Option<i32>,
) -> Option<KernelCapturedState> {
    let frame = match slot {
        KernelStateSlot::Original => Some(&oracle.original),
        KernelStateSlot::Entry => Some(&oracle.entry),
        KernelStateSlot::Creation => oracle.creation.as_ref(),
        KernelStateSlot::Newborn | KernelStateSlot::NewbornBridge => oracle.newborn.as_ref(),
        KernelStateSlot::Exit | KernelStateSlot::ParentBridge => Some(&oracle.exit),
        KernelStateSlot::Unexpected => None,
    }?;
    let mut state = frame.state.clone();
    if matches!(slot, KernelStateSlot::Exit | KernelStateSlot::ParentBridge) {
        // This is the only cross-process substitution: assert each native
        // identity result before replacing the independently known PID/TID.
        assert_eq!(
            state.registers.rax,
            oracle.child.unwrap_or(oracle.parent) as u64
        );
        state.registers.rax = child.unwrap_or(parent) as u64;
    }
    Some(state)
}

fn compare_prefix(trial: &Trial, oracle: &raw::Oracle, fixture: &Fixture) {
    let snapshot = trial.finished.reader.snapshot();
    let a = attempt(&snapshot);
    assert_eq!(a.original_until, trial.setup.until);
    assert_eq!(a.input, trial.setup.input);
    assert_eq!(
        a.original_stop,
        KernelStopIdentity::from(&trial.setup.token.stop)
    );
    assert_eq!(a.source_generation, trial.setup.token.epoch);
    assert_eq!(a.source_plan, trial.setup.token.plan);
    assert_eq!(a.id.session, trial.setup.token.stop.session);
    assert_eq!(a.id.invocation, trial.setup.token.invocation);
    assert_eq!(a.states.len(), 8);
    assert_eq!(a.input.registers(), &oracle.original.state.registers);
    assert!(a.reserved_bytes >= 8 * 64 * 1024);
    let child = child_tid(a);
    for row in &a.states {
        if let Some(actual) = stored(a, row.slot) {
            let expected = expected_state(oracle, row.slot, trial.setup.parent, child)
                .expect("captured only an independently observed original phase");
            assert_eq!(
                *actual, expected,
                "exact complete {:?} native state",
                row.slot
            );
        }
    }
    assert!(stored(a, KernelStateSlot::Original).is_some());
    assert!(stored(a, KernelStateSlot::Entry).is_some());
    let mut raw_records = BTreeMap::new();
    for fact in &a.facts {
        match *fact {
            KernelJournalFact::RawStop {
                record,
                tid,
                status,
                pin,
                task,
            } => {
                assert_eq!(usize::from(record), raw_records.len());
                assert!(raw_records.insert(record, (tid, status)).is_none());
                if tid == trial.setup.parent {
                    assert_eq!(pin, KernelPinKind::Process);
                    assert_eq!(task, Some(trial.setup.token.task));
                } else {
                    assert_eq!(Some(tid), child);
                    assert_eq!(pin, KernelPinKind::Thread);
                    assert!(task.is_none());
                    assert_eq!(
                        status,
                        (libc::PTRACE_EVENT_STOP << 16) | (libc::SIGTRAP << 8) | 0x7f
                    );
                }
            }
            KernelJournalFact::SyscallInfo { record, info } => {
                let (tid, status) = raw_records[&record];
                assert_eq!(tid, trial.setup.parent);
                assert_eq!(status, ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
                let (length, mut expected) = if info.operation() == 1 {
                    oracle.entry_info
                } else {
                    oracle.exit_info
                };
                if info.operation() == 2 {
                    assert_eq!(
                        u64::from_ne_bytes(expected[24..32].try_into().unwrap()),
                        oracle.child.unwrap_or(oracle.parent) as u64
                    );
                    expected[24..32].copy_from_slice(
                        &(child.unwrap_or(trial.setup.parent) as u64).to_ne_bytes(),
                    );
                }
                assert_eq!(info.returned_bytes, length);
                assert_eq!(info.initialized, expected);
            }
            KernelJournalFact::EventMessage { record, value } => {
                assert_eq!(value, child.unwrap() as u64);
                assert_eq!(
                    raw_records[&record],
                    (
                        trial.setup.parent,
                        (libc::PTRACE_EVENT_CLONE << 16) | (libc::SIGTRAP << 8) | 0x7f
                    )
                );
            }
            KernelJournalFact::BridgeBegin {
                source_record,
                task,
            } => {
                let (tid, _) = raw_records[&source_record];
                let expected_slot = if tid == trial.setup.parent {
                    KernelStateSlot::Exit
                } else {
                    KernelStateSlot::Newborn
                };
                assert!(a.facts.contains(&KernelJournalFact::StateCaptured {
                    record: source_record,
                    slot: expected_slot
                }));
                if tid == trial.setup.parent {
                    assert_eq!(task, trial.setup.token.task);
                } else {
                    assert_eq!(Some(tid), child);
                    assert_ne!(task.task, trial.setup.token.task.task);
                    assert_eq!(task.process, trial.setup.token.task.process);
                    assert_eq!(task.address_space, trial.setup.token.task.address_space);
                    assert_eq!(task.generation, trial.setup.token.task.generation);
                    assert!(a.facts.iter().any(|fact| matches!(fact, KernelJournalFact::ValidatedCreation { newborn, .. } if newborn.tid == tid && newborn.task == Some(task.task))));
                }
            }
            _ => {}
        }
    }
    if let Some(witness) = &trial.witness {
        let during = attempt(trial.during.as_ref().unwrap());
        assert!(
            a.facts.starts_with(&during.facts),
            "published prefix must survive every later error"
        );
        for held in &witness.held {
            let slot = if held.tid != trial.setup.parent {
                if matches!(
                    witness.point,
                    JournalFaultPoint::AfterChildBridge
                        | JournalFaultPoint::AfterTransport
                        | JournalFaultPoint::BeforeRebind
                        | JournalFaultPoint::AfterRebind
                ) {
                    KernelStateSlot::NewbornBridge
                } else {
                    KernelStateSlot::Newborn
                }
            } else if matches!(
                witness.point,
                JournalFaultPoint::AfterRawEntry | JournalFaultPoint::AfterValidatedEntry
            ) {
                KernelStateSlot::Entry
            } else if witness.point == JournalFaultPoint::AfterRawNewborn {
                KernelStateSlot::Creation
            } else {
                KernelStateSlot::Exit
            };
            let expected = expected_state(oracle, slot, trial.setup.parent, child).unwrap();
            assert_eq!(held.state.registers, expected.registers);
            assert_eq!(held.state.xstate, expected.xstate);
            assert_eq!(held.state.mask, expected.signal_mask);
            assert_eq!(held.memory.len(), 2);
            assert_eq!(
                held.memory[0],
                (BASE..BASE + SOURCE_BYTES as u64, fixture.source.clone())
            );
            assert_eq!(
                held.memory[1],
                (
                    DATA..DATA + DATA_BYTES as u64,
                    oracle.original.storage.clone()
                )
            );
            let retained = trial
                .finished
                .held
                .iter()
                .find(|item| item.tid == held.tid)
                .unwrap();
            assert_eq!(retained.status, held.raw_status);
            assert_eq!(retained.frame.state, expected);
            assert_eq!(retained.frame.storage, oracle.original.storage);
            assert_eq!(retained.frame.source, fixture.source);
        }
    }
}

fn failed(point: JournalFaultPoint, number: i64) {
    let fixture = Fixture::new(number);
    let oracle = raw::original(Arc::clone(&fixture));
    let trial = execute(
        Arc::clone(&fixture),
        Some(point),
        Some(JournalFaultRelease::Error),
    );
    assert!(matches!(
        &trial.finished.outcome,
        Outcome::Error(GateError::Control(LaunchError::Invalid(
            "injected kernel journal failure"
        )))
    ));
    assert!(trial.finished.admission_retained);
    compare_prefix(&trial, &oracle, &fixture);
    let snapshot = trial.finished.reader.snapshot();
    let a = attempt(&snapshot);
    assert_eq!(a.failure.unwrap().kind, KernelFailureKind::Injected);
    assert_eq!(
        count(a, |fact| matches!(
            fact,
            KernelJournalFact::AdmissionComplete { .. }
        )),
        0
    );
    let entry_releases = count(a, |fact| {
        matches!(
            fact,
            KernelJournalFact::ReleaseSucceeded {
                phase: KernelReleasePhase::Entry,
                ..
            }
        )
    });
    assert_eq!(
        entry_releases,
        usize::from(!matches!(
            point,
            JournalFaultPoint::AfterRawEntry | JournalFaultPoint::AfterValidatedEntry
        ))
    );
    let transport = count(a, |fact| {
        matches!(fact, KernelJournalFact::TransportComplete { .. })
    });
    assert_eq!(
        transport,
        usize::from(matches!(
            point,
            JournalFaultPoint::AfterTransport
                | JournalFaultPoint::BeforeRebind
                | JournalFaultPoint::AfterRebind
        ))
    );
    assert_eq!(
        count(a, |fact| matches!(
            fact,
            KernelJournalFact::ReleaseSucceeded {
                phase: KernelReleasePhase::Original,
                ..
            }
        )),
        1
    );
    let parent_bridge = !matches!(
        point,
        JournalFaultPoint::AfterRawEntry
            | JournalFaultPoint::AfterValidatedEntry
            | JournalFaultPoint::AfterRawNewborn
            | JournalFaultPoint::AfterValidatedExit
    );
    let child_bridge = matches!(
        point,
        JournalFaultPoint::AfterChildBridge | JournalFaultPoint::AfterTransport
    );
    assert_eq!(
        count(a, |fact| matches!(
            fact,
            KernelJournalFact::BridgeBegin { .. }
        )),
        usize::from(parent_bridge) + usize::from(child_bridge)
    );
    for (slot, expected) in [
        (KernelStateSlot::ParentBridge, parent_bridge),
        (KernelStateSlot::NewbornBridge, child_bridge),
    ] {
        assert_eq!(
            count(
                a,
                |fact| matches!(fact, KernelJournalFact::BridgeComplete { slot: found, .. } if *found == slot)
            ),
            usize::from(expected)
        );
        assert_eq!(stored(a, slot).is_some(), expected);
    }
    if point == JournalFaultPoint::AfterRawEntry {
        assert_eq!(
            count(a, |fact| matches!(
                fact,
                KernelJournalFact::ValidatedEntry { .. }
            )),
            0
        );
    }
    if point == JournalFaultPoint::AfterValidatedEntry {
        assert_eq!(
            count(a, |fact| matches!(
                fact,
                KernelJournalFact::ValidatedEntry { .. }
            )),
            1
        );
    }
    if point == JournalFaultPoint::AfterRawNewborn {
        assert!(stored(a, KernelStateSlot::Newborn).is_some());
        assert_eq!(
            count(a, |fact| matches!(
                fact,
                KernelJournalFact::ValidatedCreation { .. }
            )),
            0
        );
        assert!(stored(a, KernelStateSlot::Exit).is_none());
    }
}

#[test]
fn native_getid_success_journals_actual_entry_exit_and_rearmed_admission() {
    for number in [libc::SYS_getpid, libc::SYS_gettid] {
        let fixture = Fixture::new(number);
        let oracle = raw::original(Arc::clone(&fixture));
        let trial = execute(Arc::clone(&fixture), None, None);
        compare_prefix(&trial, &oracle, &fixture);
        let Outcome::Completed(done) = &trial.finished.outcome else {
            panic!("native getid must complete")
        };
        let snapshot = trial.finished.reader.snapshot();
        let a = attempt(&snapshot);
        assert_eq!(a.failure, None);
        assert_eq!(
            count(a, |fact| matches!(
                fact,
                KernelJournalFact::AdmissionComplete { .. }
            )),
            1
        );
        assert_eq!(
            count(a, |fact| matches!(
                fact,
                KernelJournalFact::TransportComplete { .. }
            )),
            1
        );
        assert_eq!(
            done.selected.after,
            expected_state(&oracle, KernelStateSlot::Exit, trial.setup.parent, None)
                .unwrap()
                .registers
        );
        assert_eq!(done.selected.before_xstate, oracle.original.state.xstate);
        assert_eq!(done.selected.xstate, oracle.exit.state.xstate);
        assert_eq!(done.before_signal_mask, APP_MASK);
        assert_eq!(done.signal_mask, APP_MASK);
        assert_eq!(trial.finished.held.len(), 1);
        let held = &trial.finished.held[0];
        assert_eq!(held.tid, trial.setup.parent);
        assert_eq!(
            held.frame.state,
            expected_state(&oracle, KernelStateSlot::Exit, trial.setup.parent, None).unwrap()
        );
        assert_eq!(held.frame.storage, oracle.original.storage);
        let mut armed = fixture.source.clone();
        armed[(fixture.selected_pc - BASE) as usize] = 0xcc;
        assert_eq!(
            held.frame.source, armed,
            "the completed source is exactly rearmed"
        );
        assert_eq!(
            count(a, |fact| matches!(
                fact,
                KernelJournalFact::ReleaseSucceeded {
                    phase: KernelReleasePhase::Original,
                    ..
                }
            )),
            1
        );
        assert_eq!(
            count(a, |fact| matches!(
                fact,
                KernelJournalFact::ReleaseSucceeded {
                    phase: KernelReleasePhase::Entry,
                    ..
                }
            )),
            1
        );
    }
}

#[test]
fn raw_entry_failure_retains_full_native_stop_without_entry_release() {
    failed(JournalFaultPoint::AfterRawEntry, libc::SYS_getpid);
}
#[test]
fn validated_entry_failure_precedes_original_kernel_execution() {
    failed(JournalFaultPoint::AfterValidatedEntry, libc::SYS_gettid);
}
#[test]
fn actual_exit_failure_precedes_any_return_bridge() {
    failed(JournalFaultPoint::AfterValidatedExit, libc::SYS_getpid);
}
#[test]
fn raw_newborn_failure_retains_unjoined_native_identity_and_actual_prefix() {
    failed(JournalFaultPoint::AfterRawNewborn, libc::SYS_clone);
}
#[test]
fn parent_bridge_failure_preserves_raw_exit_and_unbridged_child() {
    failed(JournalFaultPoint::AfterParentBridge, libc::SYS_clone);
}
#[test]
fn child_bridge_failure_preserves_both_native_return_states() {
    failed(JournalFaultPoint::AfterChildBridge, libc::SYS_clone);
}
#[test]
fn transport_failure_does_not_become_admission_completion() {
    failed(JournalFaultPoint::AfterTransport, libc::SYS_clone);
}
#[test]
fn before_rebind_failure_keeps_transport_prefix_without_completed_event() {
    failed(JournalFaultPoint::BeforeRebind, libc::SYS_getpid);
}
#[test]
fn after_rebind_failure_keeps_original_generation_prefix_without_completed_event() {
    failed(JournalFaultPoint::AfterRebind, libc::SYS_gettid);
}

#[test]
fn panic_while_admission_is_taken_retains_actual_exit_and_physical_cleanup() {
    let fixture = Fixture::new(libc::SYS_getpid);
    let oracle = raw::original(Arc::clone(&fixture));
    let trial = execute(
        Arc::clone(&fixture),
        Some(JournalFaultPoint::AfterValidatedExit),
        Some(JournalFaultRelease::Panic),
    );
    assert!(
        matches!(&trial.finished.outcome, Outcome::Panic(message) if message == "injected kernel journal panic")
    );
    assert!(
        !trial.finished.admission_retained,
        "actual take/unwind must discard the local admission owner"
    );
    compare_prefix(&trial, &oracle, &fixture);
    let snapshot = trial.finished.reader.snapshot();
    let a = attempt(&snapshot);
    assert_eq!(a.failure.unwrap().kind, KernelFailureKind::CaughtPanic);
    assert_eq!(
        count(a, |fact| matches!(
            fact,
            KernelJournalFact::AdmissionComplete { .. }
                | KernelJournalFact::TransportComplete { .. }
        )),
        0
    );
    assert!(stored(a, KernelStateSlot::Exit).is_some());
}

#[test]
fn native_latch_deadline_preserves_exit_prefix_without_renewal_or_completion() {
    let fixture = Fixture::new(libc::SYS_gettid);
    let oracle = raw::original(Arc::clone(&fixture));
    let trial = execute(
        Arc::clone(&fixture),
        Some(JournalFaultPoint::AfterValidatedExit),
        None,
    );
    assert!(matches!(
        &trial.finished.outcome,
        Outcome::Error(GateError::Control(LaunchError::Timeout(
            "kernel journal fault latch"
        )))
    ));
    compare_prefix(&trial, &oracle, &fixture);
    let snapshot = trial.finished.reader.snapshot();
    let a = attempt(&snapshot);
    assert_eq!(a.failure.unwrap().kind, KernelFailureKind::Timeout);
    assert_eq!(a.original_until, trial.witness.as_ref().unwrap().until);
    assert_eq!(
        count(a, |fact| matches!(
            fact,
            KernelJournalFact::AdmissionComplete { .. }
                | KernelJournalFact::TransportComplete { .. }
        )),
        0
    );
}

#[test]
fn independent_full_state_comparator_rejects_register_xstate_mask_and_memory_corruption() {
    let fixture = Fixture::new(libc::SYS_getpid);
    let oracle = raw::original(fixture);
    let baseline = oracle.entry.clone();
    let mut changed = Vec::new();
    for field in 0..10 {
        let mut item = baseline.clone();
        match field {
            0 => item.state.registers.r11 ^= 1,
            1 => item.state.registers.orig_rax ^= 1,
            2 => item.state.xstate[0] ^= 1,
            3 => item.state.signal_mask ^= 1,
            4 => item.storage[0] ^= 1,
            5 => item.state.registers.eflags ^= 0x10000,
            6 => item.state.registers.rip ^= 1,
            7 => item.state.registers.rsp ^= 1,
            8 => item.state.registers.rcx ^= 1,
            _ => item.source[0] ^= 1,
        }
        changed.push(item);
    }
    for item in changed {
        assert_ne!(item, baseline);
    }
}
