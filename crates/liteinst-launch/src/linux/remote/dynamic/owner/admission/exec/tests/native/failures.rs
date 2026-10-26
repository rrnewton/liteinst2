//! Actual refused native paths. The two faults are one-shot and owner-local;
//! limits, valid observations and ordinary execution paths remain unchanged.
use super::super::super::inputs::{InputFailureCause, InputPhase, StringRole};
use super::super::super::native_support::*;
use super::super::super::*;
use crate::exec_oracle_support::{
    self as support, APP_MASK, Architecture, CODE, DATA_LEN, Fixture, INPUT, Maps, NEW, NEW_DATA,
    OLD, OLD_DATA, PAGE, TIMEOUT, compare, raw,
};
use crate::{
    ExecBootstrapEffect, ExecJournalFact, ExecJournalStage, ExecMapsStatus, ExecProgressReader,
    ExecReadOutcome, ExecReleasePhase, KernelFailureKind,
};
use std::cell::RefCell;
use std::os::fd::OwnedFd;
use std::rc::Rc;
use std::sync::atomic::Ordering as AtomicOrdering;
use std::sync::mpsc::sync_channel;

#[derive(Clone, Copy)]
enum FailureCase {
    Capacity,
    Getregs,
    WriteStub,
    InputBound,
    SourceBound,
    PendingFlags,
}

struct OldRead {
    architecture: Architecture,
    maps: Maps,
    source: Vec<u8>,
    data: Vec<u8>,
    inputs: Vec<u8>,
}
impl OldRead {
    fn read(owner: &Owner, fixture: &Fixture, pin: &OwnedFd) -> Self {
        support::alive(pin);
        let result = Self {
            architecture: raw::architecture(owner.pid),
            maps: Maps::read(owner.pid, pin),
            source: raw::memory(owner.pid, OLD, CODE),
            data: raw::memory(owner.pid, OLD_DATA, DATA_LEN),
            inputs: raw::memory(owner.pid, INPUT, PAGE),
        };
        assert_eq!(result.source, fixture.armed(false));
        assert_eq!(result.data, fixture.old_memory());
        assert_eq!(result.inputs, fixture.inputs);
        support::alive(pin);
        result
    }
    fn unchanged(&self, owner: &Owner, pin: &OwnedFd) {
        support::alive(pin);
        assert_eq!(raw::architecture(owner.pid), self.architecture);
        assert_eq!(Maps::read(owner.pid, pin), self.maps);
        assert_eq!(raw::memory(owner.pid, OLD, CODE), self.source);
        assert_eq!(raw::memory(owner.pid, OLD_DATA, DATA_LEN), self.data);
        assert_eq!(raw::memory(owner.pid, INPUT, PAGE), self.inputs);
        support::alive(pin);
    }
}

// These are detached diagnostic copies. They cannot be installed as native,
// census, pending-provider or source authority.
fn unchanged_control(owner: &Owner) -> Box<dyn Fn(&Owner)> {
    let admission = owner.admission.as_ref().unwrap();
    let pending = admission.pending.as_ref().unwrap();
    let token = pending.token.clone();
    let stop = pending.stop.clone();
    let before = pending.before.clone();
    let input = pending.input.clone();
    let until = pending.until;
    let registry = admission.native.admission_snapshot();
    let current = admission.native.admission_current(token.task.task).unwrap();
    let charged = admission.census.charged();
    let used = admission.census.used();
    let rows = admission.census.rows().cloned().collect::<Vec<_>>();
    let history = admission.census.history().to_vec();
    let active = admission
        .census
        .active()
        .map(|origin| (origin.row.clone(), origin.current.clone()))
        .collect::<Vec<_>>();
    let origins = admission.origins.clone();
    let generation = admission.census.generation();
    let completions = admission.completion_history.len();
    Box::new(move |owner| {
        let admission = owner.admission.as_ref().unwrap();
        assert_eq!(admission.native.admission_snapshot(), registry);
        assert_eq!(
            admission.native.admission_current(token.task.task).unwrap(),
            current
        );
        assert!(admission.native.admission_events_empty());
        assert_eq!(admission.census.charged(), charged);
        assert_eq!(admission.census.used(), used);
        assert_eq!(admission.census.rows().cloned().collect::<Vec<_>>(), rows);
        assert_eq!(admission.census.history(), history);
        assert_eq!(
            admission
                .census
                .active()
                .map(|origin| (origin.row.clone(), origin.current.clone()))
                .collect::<Vec<_>>(),
            active
        );
        assert_eq!(admission.census.generation(), generation);
        assert_eq!(admission.origins, origins);
        assert_eq!(admission.completion_history.len(), completions);
        let pending = admission.pending.as_ref().unwrap();
        assert_eq!(pending.token, token);
        assert_eq!(pending.stop, stop);
        assert_eq!(pending.before, before);
        assert_eq!(pending.input, input);
        assert_eq!(pending.until, until);
        let exec = admission.exec.as_ref().unwrap();
        assert!(exec.attempt.is_none() && exec.retired.is_none());
    })
}

fn maps_complete(record: &crate::ExecMapsRecord, maps: &Maps, tid: i32, status: i32) {
    assert_eq!((record.tid, record.raw_status), (tid, status));
    assert_eq!(record.status, ExecMapsStatus::Complete);
    assert_eq!(record.observed_bytes, maps.raw.len());
    assert_eq!(&record.initialized[..record.observed_bytes], maps.raw);
    assert_eq!(record.initialized.len(), 65536);
    assert!(
        record.initialized[record.observed_bytes..]
            .iter()
            .all(|byte| *byte == 0)
    );
    let open = record.open.unwrap();
    assert!(open.result >= 0);
    assert_eq!(open.errno, None);
    for result in [record.filesystem, record.last_read, record.close] {
        assert_eq!(
            result.unwrap(),
            ExecReadOutcome {
                result: 0,
                errno: None
            }
        );
    }
    assert_eq!(record.filesystem_type, libc::PROC_SUPER_MAGIC);
    assert!(record.read_calls > 0);
}

fn read_outcome(result: i64) -> ExecReadOutcome {
    ExecReadOutcome {
        result,
        errno: (result == -1)
            .then(|| std::io::Error::last_os_error().raw_os_error())
            .flatten(),
    }
}

fn failed_getregs(
    owner: &Owner,
    fixture: &Fixture,
    reference: &raw::Transcript,
    pin: &OwnedFd,
    progress: &ExecProgressReader,
    reply: Result<AdmissionReply, GateError>,
) {
    match reply {
        Err(GateError::Control(LaunchError::System { operation, source })) => {
            assert_eq!(operation, "exec journal GETREGS");
            assert_eq!(source.raw_os_error(), Some(libc::EFAULT));
        }
        _ => panic!("actual GETREGS EFAULT must be returned"),
    }
    let snapshot = progress.snapshot();
    assert_eq!(
        snapshot.first_failure,
        Some((
            ExecJournalStage::RawCapture,
            KernelFailureKind::NativeIo(Some(libc::EFAULT))
        ))
    );
    let attempt = snapshot.attempt.as_ref().unwrap();
    assert_eq!(attempt.raw.len(), 1);
    let raw = &attempt.raw[0];
    assert_eq!(
        (raw.ordinal, raw.tid, raw.status),
        (0, owner.pid, ((libc::SIGTRAP | 0x80) << 8) | 0x7f)
    );
    assert_eq!(owner.stopped.get(&owner.pid), Some(&raw.status));
    assert!(raw.held && !raw.complete);
    assert_eq!(raw.pin, crate::KernelPinKind::Process);
    assert_eq!(
        raw.registers_read,
        Some(ExecReadOutcome {
            result: -1,
            errno: Some(libc::EFAULT)
        })
    );
    let zero: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    assert_eq!(raw.registers, crate::RegisterSnapshot::from(zero));
    // A second actual read succeeds at the very same held ENTRY. Its expected
    // state is the independent pristine trajectory, not the failed substrate.
    let actual = raw::architecture(owner.pid);
    assert_eq!(actual, reference.entry.architecture);
    compare::entry(&reference.before_exec.architecture, &actual, fixture.exec);
    let x = raw.xstate_query.unwrap();
    assert_eq!(
        x.outcome,
        ExecReadOutcome {
            result: 0,
            errno: None
        }
    );
    assert!(x.pointer_unchanged);
    assert_eq!(x.reported_bytes, actual.xstate.len());
    assert_eq!(&raw.initialized_xstate[..x.reported_bytes], actual.xstate);
    assert_eq!(raw.initialized_xstate.len(), 65536);
    assert!(
        raw.initialized_xstate[x.reported_bytes..]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        raw.mask_read,
        Some(ExecReadOutcome {
            result: 0,
            errno: None
        })
    );
    assert_eq!(raw.signal_mask, actual.mask);
    let mut syscall = [0_u8; 88];
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GET_SYSCALL_INFO,
            owner.pid,
            syscall.len(),
            syscall.as_mut_ptr(),
        )
    };
    assert_eq!(raw.syscall_read, Some(read_outcome(result)));
    assert!((80..=88).contains(&result));
    assert_eq!(syscall[0], 1);
    assert_eq!(raw.syscall_info, syscall);
    assert_eq!(syscall, reference.entry_info.1);
    let mut event = 0_u64;
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG,
            owner.pid,
            0,
            &mut event as *mut u64,
        )
    };
    assert_eq!(raw.event_read, Some(read_outcome(result)));
    assert_eq!(raw.event_message, event);
    let mut siginfo = [0_u8; 128];
    let result =
        unsafe { libc::ptrace(libc::PTRACE_GETSIGINFO, owner.pid, 0, siginfo.as_mut_ptr()) };
    assert_eq!(raw.siginfo_read, Some(read_outcome(result)));
    assert_eq!(raw.siginfo, siginfo);
    let maps = Maps::read(owner.pid, pin);
    maps_complete(&raw.maps, &maps, owner.pid, raw.status);
    let mut restored = fixture.armed(false);
    restored[(fixture.exec - OLD) as usize] = fixture.old_source[(fixture.exec - OLD) as usize];
    assert_eq!(raw::memory(owner.pid, OLD, CODE), restored);
    assert_eq!(
        raw::memory(owner.pid, OLD_DATA, DATA_LEN),
        fixture.old_memory()
    );
    assert_eq!(raw::memory(owner.pid, INPUT, PAGE), fixture.inputs);
    assert!(attempt.replacement.is_none());
    assert!(attempt.restored_entry.is_none() && attempt.final_state.is_none());
    assert!(matches!(
        attempt.facts.last(),
        Some(ExecJournalFact::Raw { ordinal: 0 })
    ));
    for succeeded in [false, true] {
        assert_eq!(
            attempt
                .facts
                .iter()
                .filter(|fact| match fact {
                    ExecJournalFact::ReleaseAttempt {
                        phase: ExecReleasePhase::Original,
                        ..
                    } => !succeeded,
                    ExecJournalFact::ReleaseSucceeded {
                        phase: ExecReleasePhase::Original,
                        ..
                    } => succeeded,
                    _ => false,
                })
                .count(),
            1
        );
    }
    assert!(!attempt.facts.iter().any(|fact| matches!(
        fact,
        ExecJournalFact::Validated { .. }
            | ExecJournalFact::ReleaseAttempt {
                phase: ExecReleasePhase::Entry | ExecReleasePhase::ExecEvent,
                ..
            }
            | ExecJournalFact::EffectAttempt { .. }
            | ExecJournalFact::AdmissionComplete { .. }
    )));
    assert_eq!(raw::architecture(owner.pid), actual);
    support::alive(pin);
}

fn after_first_user(
    owner: &Owner,
    fixture: &Fixture,
    evidence: &Evidence,
    pin: &OwnedFd,
    progress: &ExecProgressReader,
    source_bound: bool,
) {
    assert_eq!((evidence.before, evidence.after), (0, 0));
    let snapshot = progress.snapshot();
    let attempt = snapshot.attempt.as_ref().unwrap();
    assert_eq!(attempt.raw.len(), 4);
    raw_matches(
        &attempt.raw[0],
        evidence.entry.as_ref().unwrap(),
        evidence.entry_maps.as_ref().unwrap(),
        ((libc::SIGTRAP | 0x80) << 8) | 0x7f,
    );
    let first = evidence.first.as_ref().unwrap();
    raw_matches(
        &attempt.raw[3],
        &first.architecture,
        &first.maps,
        first.status,
    );
    assert_eq!(attempt.raw[3].ordinal, 3);
    let mut expected = first.architecture.clone();
    expected.registers.rip -= 1;
    let actual = raw::architecture(owner.pid);
    assert_eq!(actual, expected);
    assert_eq!(
        Architecture::captured(attempt.restored_entry.as_ref().unwrap()),
        expected
    );
    let maps = Maps::read(owner.pid, pin);
    assert_eq!(raw::stack(owner.pid, &maps, actual.registers), first.stack);
    assert_eq!(raw::memory(owner.pid, NEW, CODE), fixture.new_source);
    assert_eq!(raw::memory(owner.pid, NEW_DATA, DATA_LEN), fixture.new_data);
    if source_bound {
        assert_eq!(
            snapshot.first_failure,
            Some((
                ExecJournalStage::QuarantinedMaps,
                KernelFailureKind::AdmissionRejected
            ))
        );
        assert_eq!(
            Architecture::captured(attempt.final_state.as_ref().unwrap()),
            expected
        );
        maps_complete(
            &attempt.quarantined_maps,
            &maps,
            owner.pid,
            *owner.stopped.get(&owner.pid).unwrap(),
        );
        let admission = owner.admission.as_ref().unwrap();
        let retained = admission.exec.as_ref().unwrap().attempt.as_ref().unwrap();
        let bootstrap = retained.bootstrap.as_ref().unwrap().bootstrap();
        assert_eq!(
            bootstrap.evidence.restored_entry.registers,
            actual.registers
        );
        assert_eq!(bootstrap.evidence.restored_entry.xstate, actual.xstate);
        assert_eq!(bootstrap.evidence.restored_entry.mask, actual.mask);
        for map in maps
            .rows
            .iter()
            .filter(|map| map.permissions.as_bytes()[2] == b'x')
        {
            assert!(
                map.path.as_deref() == Some("[vsyscall]")
                    || (map.start == bootstrap.island.range.start
                        && map.end == bootstrap.island.range.end)
            );
        }
        assert_eq!(maps.covering(NEW, CODE).permissions, "r--p");
        assert!(
            retained.captured.is_none() && retained.request.is_none() && retained.reply.is_none()
        );
        assert!(matches!(
            attempt.facts.last(),
            Some(ExecJournalFact::QuarantinedMapsComplete { .. })
        ));
    } else {
        assert_eq!(
            snapshot.first_failure,
            Some((ExecJournalStage::Bootstrap, KernelFailureKind::InvalidState))
        );
        assert!(attempt.final_state.is_none());
        assert_eq!(attempt.quarantined_maps.status, ExecMapsStatus::Unused);
        assert_eq!(maps, first.maps);
        assert!(matches!(
            attempt.facts.last(),
            Some(ExecJournalFact::EffectAttempt {
                effect: ExecBootstrapEffect::WriteStub
            })
        ));
        assert!(!attempt.facts.iter().any(|fact| matches!(
            fact,
            ExecJournalFact::EffectComplete {
                effect: ExecBootstrapEffect::WriteStub,
                ..
            } | ExecJournalFact::EffectAttempt {
                effect: ExecBootstrapEffect::MapIsland,
                ..
            } | ExecJournalFact::BootstrapComplete { .. }
        )));
    }
    assert!(!attempt.facts.iter().any(|fact| matches!(
        fact,
        ExecJournalFact::SourcesRequested { .. }
            | ExecJournalFact::SourcesAccepted { .. }
            | ExecJournalFact::AdmissionComplete { .. }
    )));
    support::alive(pin);
}

fn run_failure(case: FailureCase) {
    let fixture = {
        let guard = crate::TEST_FILE_FORK.lock().unwrap();
        let fixture = Fixture::new();
        drop(guard);
        fixture
    };
    let reference = Arc::new(raw::original(Arc::clone(&fixture)));
    let (send, receive) = sync_channel(1);
    let worker = support::spawn_masked(move || {
        let mut owner = Owner::new(
            NEXT_SESSION.fetch_add(1, AtomicOrdering::Relaxed),
            Arc::new(AtomicBool::new(false)),
        );
        let mut pin = None;
        let mut reader = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let options = fixture.options();
            assert_eq!(options.limits, crate::DynamicAdmissionLimits::default());
            assert_eq!(options.limits.source_fact_bytes, 64 * 1024 * 1024);
            assert_eq!(
                options.cache,
                liteinst_admission::oracle_chain::CacheLimits::default()
            );
            let mut profile = fixture.profile();
            match case {
                FailureCase::InputBound => profile.max_string_bytes = 1,
                FailureCase::SourceBound => {
                    profile.max_capture_bytes = PAGE;
                    profile.max_total_capture_bytes = PAGE;
                }
                _ => {}
            }
            owner.lifecycle_options = Some(options.lifecycle);
            owner.exec_policy = DynamicExecPolicy::ExecveOnce;
            let launch_until = Instant::now() + TIMEOUT;
            let guard = crate::TEST_FILE_FORK.lock().unwrap();
            let started = launch::start(
                &mut owner,
                &LaunchCommand::new(&fixture.old_path),
                APP_MASK,
                launch_until,
            );
            drop(guard);
            let initial = started.unwrap().event;
            pin = Some(support::duplicate(owner.handles.get(&owner.pid).unwrap()));
            let started = owner
                .execute_admission(
                    AdmissionRequest::StartExec {
                        initial: initial.stop_token().unwrap().clone(),
                        facts: fixture.facts(),
                        options,
                        profile,
                    },
                    launch_until,
                )
                .unwrap();
            let AdmissionReply::ReadyExec(_, _, progress) = started else {
                panic!("exec Ready")
            };
            reader = Some(progress);
            let old_until = Instant::now() + TIMEOUT;
            let old = provider(&mut owner, fixture.old_cpu, old_until);
            assert_eq!(
                *old.input.registers(),
                reference.old_cpu.before.architecture.registers
            );
            complete_cpu(
                &mut owner,
                old,
                old_until,
                Some(&reference.old_cpu.after.architecture),
            );
            let until = Instant::now() + TIMEOUT;
            let exec = provider(&mut owner, fixture.exec, until);
            assert_eq!(
                *exec.input.registers(),
                reference.before_exec.architecture.registers
            );
            let evidence = Rc::new(RefCell::new(Evidence::default()));
            owner.exec_oracle = Some(Box::new(Inspector {
                fixture: Arc::clone(&fixture),
                reference: Arc::clone(&reference),
                evidence: Rc::clone(&evidence),
                until,
                retired: None,
            }));
            let pin = pin.as_ref().unwrap();
            let progress = reader.as_ref().unwrap();
            if matches!(case, FailureCase::Capacity) {
                let admission = owner.admission.as_mut().unwrap();
                let used = admission.census.used();
                let charged = admission.census.charged();
                let fill = (64 * 1024 * 1024_usize)
                    .checked_sub(charged.source_fact_bytes)
                    .unwrap()
                    .checked_sub(1)
                    .unwrap();
                assert!(fill > 0);
                let reservation = admission
                    .census
                    .reserve(BudgetCharge {
                        source_fact_bytes: fill,
                        ..BudgetCharge::default()
                    })
                    .unwrap();
                admission.census.finish_reservation(reservation).unwrap();
                assert_eq!(admission.census.used(), used);
                assert_eq!(
                    admission.census.charged(),
                    BudgetCharge {
                        source_fact_bytes: 64 * 1024 * 1024 - 1,
                        ..charged
                    }
                );
                // Charged unused reservations never become fabricated used bytes.
            }
            if matches!(case, FailureCase::PendingFlags) {
                let original = raw::architecture(owner.pid);
                assert_eq!(original.registers.eflags & 0x100, 0);
                let mut changed = original.clone();
                changed.registers.eflags |= 0x100;
                let registers: libc::user_regs_struct = changed.registers.into();
                raw::trace(
                    owner.pid,
                    libc::PTRACE_SETREGS,
                    0,
                    &registers as *const libc::user_regs_struct as usize,
                );
                assert_eq!(raw::architecture(owner.pid), changed);
            }
            match case {
                FailureCase::Getregs => owner.exec_fault.set(Some(ExecFault::RawGetregs(0))),
                FailureCase::WriteStub => owner.exec_fault.set(Some(ExecFault::BeforeWriteStub)),
                _ => {}
            }
            let before = OldRead::read(&owner, &fixture, pin);
            let unchanged = unchanged_control(&owner);
            let completed_before = owner.admission.as_ref().unwrap().completion_history.len();
            let archive_before = progress.snapshot();
            assert!(archive_before.attempt.is_none() && archive_before.first_failure.is_none());
            assert!(Instant::now() < until);
            let reply = owner.execute_admission(
                AdmissionRequest::Complete {
                    token: exec.token,
                    decision: ProviderDecision::Native,
                },
                until,
            );
            assert!(Instant::now() < until);
            assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
            assert!(owner.admission.as_ref().unwrap().closed);
            assert!(
                owner
                    .admission
                    .as_ref()
                    .unwrap()
                    .exec
                    .as_ref()
                    .unwrap()
                    .retired
                    .is_none()
            );
            assert_eq!(owner.exec_fault.get(), None);
            assert_eq!(
                owner.admission.as_ref().unwrap().completion_history.len(),
                completed_before
            );
            match case {
                FailureCase::Capacity | FailureCase::PendingFlags => {
                    let reason = if matches!(case, FailureCase::Capacity) {
                        "dynamic continuation lifetime capacity exhausted"
                    } else {
                        "dynamic completion full before-state or phase differs"
                    };
                    assert!(matches!(reply, Err(GateError::Refused(actual)) if actual == reason));
                    before.unchanged(&owner, pin);
                    unchanged(&owner);
                    assert_eq!(
                        progress.snapshot().first_failure,
                        Some((
                            ExecJournalStage::Prepared,
                            KernelFailureKind::AdmissionRejected
                        ))
                    );
                    let failed = progress.snapshot();
                    assert!(failed.attempt.is_none());
                    if matches!(case, FailureCase::Capacity) {
                        assert!(failed.allocated_bytes > archive_before.allocated_bytes);
                    } else {
                        assert_eq!(failed.allocated_bytes, archive_before.allocated_bytes);
                    }
                    assert!(evidence.borrow().entry.is_none() && evidence.borrow().first.is_none());
                }
                FailureCase::InputBound => {
                    const REASON: &str = "exec combined string bound lacks a terminating NUL";
                    assert!(matches!(reply, Err(GateError::Refused(REASON))));
                    before.unchanged(&owner, pin);
                    let snapshot = progress.snapshot();
                    assert_eq!(
                        snapshot.first_failure,
                        Some((
                            ExecJournalStage::Prepared,
                            KernelFailureKind::AdmissionRejected
                        ))
                    );
                    let attempt = snapshot.attempt.as_ref().unwrap();
                    assert_eq!(attempt.facts, [ExecJournalFact::Attached]);
                    assert!(attempt.raw.is_empty() && attempt.restored_original_stop.is_none());
                    let admission = owner.admission.as_ref().unwrap();
                    let retained = admission.exec.as_ref().unwrap().attempt.as_ref().unwrap();
                    assert!(retained.window.is_none() && retained.bootstrap.is_none());
                    let inputs = retained.inputs.view();
                    assert!(!inputs.capture_complete && !inputs.recheck_complete);
                    assert!(inputs.pointers.is_empty());
                    assert_eq!(inputs.strings.len(), 1);
                    let string = &inputs.strings[0];
                    assert_eq!(string.role, StringRole::Filename);
                    assert_eq!(string.address, before.architecture.registers.rdi);
                    assert_eq!((string.requested_bytes, string.observed_bytes), (1, 1));
                    assert!(
                        string.capture.attempted && string.capture.complete && !string.terminated
                    );
                    assert_eq!(string.capture.reported_bytes, 1);
                    assert_eq!(
                        inputs.initialized_strings,
                        &fixture.inputs[(string.address - INPUT) as usize..][..1]
                    );
                    assert_ne!(inputs.initialized_strings[0], 0);
                    assert!(inputs.initialized_recheck.iter().all(|byte| *byte == 0));
                    let failure = inputs.failure.unwrap();
                    assert_eq!(failure.phase, InputPhase::Capture);
                    assert_eq!(failure.location, None);
                    assert_eq!(failure.cause, InputFailureCause::Refused(REASON));
                    assert!(evidence.borrow().entry.is_none() && evidence.borrow().first.is_none());
                }
                FailureCase::Getregs => {
                    failed_getregs(&owner, &fixture, &reference, pin, progress, reply);
                    assert!(evidence.borrow().entry.is_none() && evidence.borrow().first.is_none());
                }
                FailureCase::WriteStub => {
                    assert!(matches!(
                        reply,
                        Err(GateError::Control(LaunchError::Invalid(
                            "private exec WriteStub refusal"
                        )))
                    ));
                    after_first_user(&owner, &fixture, &evidence.borrow(), pin, progress, false);
                }
                FailureCase::SourceBound => {
                    assert!(matches!(
                        reply,
                        Err(GateError::Refused(
                            "exec whole source VMA exceeds its declared profile"
                        ))
                    ));
                    after_first_user(&owner, &fixture, &evidence.borrow(), pin, progress, true);
                }
            }
            assert_eq!((evidence.borrow().before, evidence.borrow().after), (0, 0));
            let terminal = progress.snapshot();
            if let Some(attempt) = &terminal.attempt {
                assert_eq!(attempt.original_until, until);
                assert!(
                    !attempt
                        .facts
                        .iter()
                        .any(|fact| matches!(fact, ExecJournalFact::AdmissionComplete { .. }))
                );
            }
            let repeated = owner.execute_admission(AdmissionRequest::Advance, until);
            assert!(matches!(
                repeated,
                Err(GateError::Control(LaunchError::Invalid(
                    "dynamic operation cancelled"
                )))
            ));
            assert_eq!(progress.snapshot(), terminal);
            assert!(Instant::now() < until);
        }));
        let before_cleanup = reader.as_ref().map(ExecProgressReader::snapshot);
        let cleanup = match owner.cleanup() {
            Ok(value) => value,
            Err(_) => std::process::abort(),
        };
        if let Some(pin) = &pin {
            if !support::gone(pin) {
                std::process::abort();
            }
            support::reaped(pin);
            assert_eq!(cleanup.reaped, [owner.pid]);
        }
        if let Some(reader) = &reader {
            let after = reader.snapshot();
            let before = before_cleanup.as_ref().unwrap();
            assert_eq!(after.cleanup_complete, Some(true));
            if result.is_ok() || before.first_failure.is_some() {
                assert_eq!(after.first_failure, before.first_failure);
            }
            assert_eq!(after.attempt, before.attempt);
        }
        let _ = send.send(result);
    });
    let result = match receive.recv_timeout(6 * TIMEOUT) {
        Ok(result) => result,
        Err(_) => std::process::abort(),
    };
    if worker.join().is_err() {
        std::process::abort();
    }
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

#[test]
fn admitted_exec_native_prefix_capacity_refuses_before_restore() {
    run_failure(FailureCase::Capacity);
}
#[test]
fn admitted_exec_native_getregs_capture_failure_retains_other_reads() {
    run_failure(FailureCase::Getregs);
}
#[test]
fn admitted_exec_native_bootstrap_failure_retains_first_user_prefix() {
    run_failure(FailureCase::WriteStub);
}
#[test]
fn admitted_exec_native_input_bound_refuses_before_restore() {
    run_failure(FailureCase::InputBound);
}
#[test]
fn admitted_exec_native_source_profile_bound_refuses_after_exec() {
    run_failure(FailureCase::SourceBound);
}
#[test]
fn admitted_exec_native_pending_flags_change_refuses_before_restore() {
    run_failure(FailureCase::PendingFlags);
}
