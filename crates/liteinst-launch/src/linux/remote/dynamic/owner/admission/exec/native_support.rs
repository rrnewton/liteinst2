//! Same-tracer native controls. The public fixtures remain a separate cohort.
//! Expected instruction/state semantics come from the independent raw helper;
//! the archive is compared with a second native read, never with itself.
use super::oracle::*;
use super::*;
#[cfg(test)]
use crate::ExecValidatedPhase;
use crate::exec_oracle_support::{
    self as support, APP_MASK, Architecture, CODE, DATA_LEN, Fixture, INPUT, Maps, NEW, NEW_DATA,
    OLD, OLD_DATA, PAGE, Stack, TIMEOUT, compare, raw,
};
use crate::{
    DynamicSourceHeads, ExecJournalFact, ExecJournalStage, ExecProgressReader, ExecRawRecord,
    KernelFailureKind,
};
use std::cell::RefCell;
use std::os::fd::OwnedFd;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
#[cfg(test)]
use std::sync::mpsc::sync_channel;

#[path = "native_support/backing_cleanup.rs"]
mod backing_cleanup;

pub(in crate::linux::remote::dynamic::owner::admission::exec) static NEXT_SESSION: AtomicU64 =
    AtomicU64::new(90_000);

#[derive(Clone)]
pub(in crate::linux::remote::dynamic::owner::admission::exec) struct FirstRead {
    pub(in crate::linux::remote::dynamic::owner::admission::exec) architecture: Architecture,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) source: Vec<u8>,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) data: Vec<u8>,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) stack: Stack,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) maps: Maps,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) status: i32,
}
#[derive(Default)]
pub(in crate::linux::remote::dynamic::owner::admission::exec) struct Evidence {
    pub(in crate::linux::remote::dynamic::owner::admission::exec) entry: Option<Architecture>,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) entry_maps: Option<Maps>,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) first: Option<FirstRead>,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) before: usize,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) after: usize,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) source: Option<SourceObservation>,
}

// These owned descriptions are never converted back into a request, accepted
// reply, native witness, census, or permit. Only the private comparator reads
// them. The ID types themselves are public diagnostic values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::exec) struct CaptureObservation {
    pub(in crate::linux::remote::dynamic::owner::admission::exec) id: crate::DynamicSourceCaptureId,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) incarnation: u64,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) original: MemoryMapping,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) quarantined: MemoryMapping,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) bytes: Vec<u8>,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) lower: Option<MemoryMapping>,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) upper: Option<MemoryMapping>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::exec) struct SourceObservation {
    pub(in crate::linux::remote::dynamic::owner::admission::exec) token: PendingSourceToken,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) captures: Vec<CaptureObservation>,
}
impl SourceObservation {
    fn read(request: &DynamicSourceRequest) -> Self {
        Self {
            token: request.token.clone(),
            captures: request
                .images()
                .iter()
                .map(|image| CaptureObservation {
                    id: image.id(),
                    incarnation: image.mapping_incarnation(),
                    original: image.original_mapping().clone(),
                    quarantined: image.quarantined_mapping().clone(),
                    bytes: image.bytes().to_vec(),
                    lower: image.lower_neighbor().cloned(),
                    upper: image.upper_neighbor().cloned(),
                })
                .collect(),
        }
    }
    fn check(&self, request: &DynamicSourceRequest) {
        let observed = Self::read(request);
        inspect(InspectionField::SourceRequest, self, &observed).unwrap();
        assert_eq!(observed.captures.len(), 1);
        assert_eq!(observed.captures[0].id.index(), 0);
        assert!(observed.captures[0].incarnation > 0);
        for field in 0..3 {
            let mut changed = observed.clone();
            match field {
                0 => changed.captures[0].id.index = 1,
                1 => changed.captures[0].incarnation = 0,
                2 => {
                    changed.captures[0].incarnation =
                        changed.captures[0].incarnation.checked_add(1).unwrap()
                }
                _ => unreachable!(),
            }
            assert_eq!(
                inspect(InspectionField::SourceRequest, self, &changed),
                Err(InspectionField::SourceRequest)
            );
        }
    }
}

pub(in crate::linux::remote::dynamic::owner::admission::exec) type RetiredCheck =
    Box<dyn for<'a> Fn(AfterRetire<'a>)>;
pub(in crate::linux::remote::dynamic::owner::admission::exec) struct Inspector {
    pub(in crate::linux::remote::dynamic::owner::admission::exec) fixture: Arc<Fixture>,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) reference: Arc<raw::Transcript>,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) evidence: Rc<RefCell<Evidence>>,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) until: Instant,
    pub(in crate::linux::remote::dynamic::owner::admission::exec) retired: Option<RetiredCheck>,
}
impl ExecOracle for Inspector {
    fn old_entry(&mut self, view: OldEntry<'_>) {
        assert_eq!(view.until, self.until);
        assert!(Instant::now() < self.until);
        support::alive(view.pin);
        let event = view.event;
        assert!(
            matches!(event.kind, DynamicEventKind::SyscallEntry { number, .. }
            if number == libc::SYS_execve as u64)
        );
        assert_eq!(
            event.stop_token().unwrap().task,
            event.task.map(|task| task.task)
        );
        let actual = raw::architecture(event.tid);
        assert_eq!(actual, self.reference.entry.architecture);
        compare::entry(
            &self.reference.before_exec.architecture,
            &actual,
            self.fixture.exec,
        );
        let maps = Maps::read(event.tid, view.pin);
        let args = raw::memory(event.tid, INPUT, PAGE);
        compare::arguments(&self.fixture, &actual.registers, &maps, &args);
        let mut restored = self.fixture.armed(false);
        restored[(self.fixture.exec - OLD) as usize] =
            self.fixture.old_source[(self.fixture.exec - OLD) as usize];
        assert_eq!(
            &restored[(self.fixture.exec - OLD) as usize..][..2],
            &[0x0f, 0x05]
        );
        assert_eq!(restored[(self.fixture.old_cpu - OLD) as usize], 0xcc);
        assert_eq!(raw::memory(event.tid, OLD, CODE), restored);
        assert_eq!(
            raw::memory(event.tid, OLD_DATA, DATA_LEN),
            self.fixture.old_memory()
        );
        let mut evidence = self.evidence.borrow_mut();
        assert!(evidence.entry.replace(actual).is_none());
        assert!(evidence.entry_maps.replace(maps).is_none());
        support::alive(view.pin);
        // This is the final old-address inspection. No later hook reads that mm.
        assert!(Instant::now() < self.until);
    }

    fn first_user(&mut self, view: FirstUser<'_>) {
        assert_eq!(view.until, self.until);
        assert!(Instant::now() < self.until);
        support::alive(view.pin);
        assert_eq!(view.status, (libc::SIGTRAP << 8) | 0x7f);
        assert_eq!(view.exit.tid, view.tid);
        assert!(view.exit.task.is_some());
        let actual = raw::architecture(view.tid);
        let maps = Maps::read(view.tid, view.pin);
        let stack = raw::stack(view.tid, &maps, actual.registers);
        compare::initial_stack(&self.fixture, &stack);
        let mut expected = compare::exec_registers(&stack, self.fixture.first_cpu + 1);
        expected.rax = 0;
        expected.orig_rax = u64::MAX;
        assert_eq!(actual.registers, expected);
        assert_eq!(actual.mask, APP_MASK);
        // Compare every byte with the independent pristine lane's actual trap,
        // including deferred user-return state; EXIT is not its replacement.
        assert_eq!(actual.xstate, self.reference.trap.architecture.xstate);
        let mut source = self.fixture.new_source.clone();
        source[(self.fixture.first_cpu - NEW) as usize] = 0xcc;
        assert_eq!(raw::memory(view.tid, NEW, CODE), source);
        let data = raw::memory(view.tid, NEW_DATA, DATA_LEN);
        assert_eq!(data, self.fixture.new_data);
        let map = maps.covering(NEW, CODE);
        assert_eq!(
            (map.start, map.end, map.offset),
            (NEW, NEW + CODE as u64, 0)
        );
        assert_eq!(map.permissions, "r-xp");
        assert_eq!(map.path.as_deref(), self.fixture.new_path.to_str());
        assert!(maps.rows.iter().all(|map| {
            ![
                (OLD, OLD + CODE as u64),
                (OLD_DATA, OLD_DATA + DATA_LEN as u64),
                (INPUT, INPUT + PAGE as u64),
            ]
            .iter()
            .any(|&(start, end)| map.start < end && start < map.end)
        }));
        assert!(
            self.evidence
                .borrow_mut()
                .first
                .replace(FirstRead {
                    architecture: actual,
                    source,
                    data,
                    stack,
                    maps,
                    status: view.status,
                })
                .is_none()
        );
        support::alive(view.pin);
        assert!(Instant::now() < self.until);
    }

    fn before_retire(&mut self, view: BeforeRetire<'_>) {
        assert_eq!(view.until, self.until);
        assert!(Instant::now() < self.until);
        let obligations = view.domain.returns.obligations().collect::<Vec<_>>();
        assert!(
            obligations.iter().any(
                |row| row.return_pc == self.fixture.call_return && row.source_generation.0 == 0
            )
        );
        assert!(!view.domain.plans.is_empty());
        assert!(!view.domain.generations.is_empty());
        let source = self
            .evidence
            .borrow()
            .source
            .clone()
            .expect("actual owner-issued capture");
        source.check(view.request);
        let domain = view.domain.exec_oracle_check();
        let census = view.census.exec_oracle_check();
        let island = (
            view.island.address_space,
            view.island.generation,
            view.island.range.clone(),
            view.island.page_size,
        );
        let bootstrap = (
            view.bootstrap.exec_event.clone(),
            view.bootstrap.exec_exit.clone(),
            view.bootstrap.entry_trap.clone(),
            view.bootstrap.restored_entry.clone(),
        );
        let origins = view.origins.clone();
        let old_stop = view.old_stop.clone();
        let initial = view.initial.clone();
        let until = self.until;
        assert!(self.retired.is_none());
        self.retired = Some(Box::new(move |after| {
            assert_eq!(after.until, until);
            assert!(Instant::now() < until);
            assert_eq!(after.initial, &initial);
            source.check(after.request);
            domain(&after.retired.domain);
            census(&after.retired.census, after.live, after.initial);
            assert_eq!(
                (
                    after.retired.island.address_space,
                    after.retired.island.generation,
                    after.retired.island.range.clone(),
                    after.retired.island.page_size
                ),
                island
            );
            assert_eq!(
                (
                    &after.retired.bootstrap.exec_event,
                    &after.retired.bootstrap.exec_exit,
                    &after.retired.bootstrap.entry_trap,
                    &after.retired.bootstrap.restored_entry
                ),
                (&bootstrap.0, &bootstrap.1, &bootstrap.2, &bootstrap.3)
            );
            assert_eq!(after.retired.origins, origins);
            let registry = after.native.admission_snapshot();
            assert!(matches!(
                after.native.require_admission_stop(&old_stop),
                Err(LaunchError::Invalid(
                    "task is not at an admission injection phase"
                ))
            ));
            assert_eq!(after.native.admission_snapshot(), registry);
            let current = after.native.admission_current(initial.task.task).unwrap();
            assert_eq!(current.token, initial.token);
            assert_eq!(current.identity, initial.task);
        }));
        let mut evidence = self.evidence.borrow_mut();
        assert_eq!(evidence.before, 0);
        evidence.before += 1;
    }

    fn after_retire(&mut self, view: AfterRetire<'_>) {
        self.retired.take().expect("exact precommit inspection")(view);
        let mut evidence = self.evidence.borrow_mut();
        assert_eq!(evidence.after, 0);
        evidence.after += 1;
    }
}

pub(in crate::linux::remote::dynamic::owner::admission::exec) fn raw_matches(
    actual: &ExecRawRecord,
    expected: &Architecture,
    maps: &Maps,
    status: i32,
) {
    assert!(actual.held && actual.complete);
    assert_eq!(actual.pin, crate::KernelPinKind::Process);
    assert_eq!(
        (actual.maps.tid, actual.maps.raw_status),
        (actual.tid, actual.status)
    );
    assert_eq!(actual.status, status);
    let registers = actual.registers_read.unwrap();
    assert_eq!((registers.result, registers.errno), (0, None));
    assert_eq!(actual.registers, expected.registers);
    let x = actual.xstate_query.unwrap();
    assert_eq!(
        (x.outcome.result, x.outcome.errno, x.pointer_unchanged),
        (0, None, true)
    );
    assert_eq!(x.reported_bytes, expected.xstate.len());
    assert_eq!(
        &actual.initialized_xstate[..x.reported_bytes],
        expected.xstate
    );
    assert_eq!(actual.initialized_xstate.len(), 65536);
    assert!(
        actual.initialized_xstate[x.reported_bytes..]
            .iter()
            .all(|byte| *byte == 0)
    );
    let mask = actual.mask_read.unwrap();
    assert_eq!((mask.result, mask.errno), (0, None));
    assert_eq!(actual.signal_mask, expected.mask);
    assert_eq!(actual.maps.status, crate::ExecMapsStatus::Complete);
    assert_eq!(actual.maps.observed_bytes, maps.raw.len());
    let open = actual.maps.open.unwrap();
    assert!(open.result >= 0);
    assert_eq!(open.errno, None);
    for outcome in [
        actual.maps.filesystem,
        actual.maps.last_read,
        actual.maps.close,
    ] {
        let outcome = outcome.unwrap();
        assert_eq!((outcome.result, outcome.errno), (0, None));
    }
    assert_eq!(actual.maps.filesystem_type, libc::PROC_SUPER_MAGIC);
    assert!(actual.maps.read_calls > 0);
    assert_eq!(actual.maps.initialized.len(), 65536);
    assert!(
        actual.maps.initialized[actual.maps.observed_bytes..]
            .iter()
            .all(|byte| *byte == 0)
    );
    if libc::WSTOPSIG(status) == (libc::SIGTRAP | 0x80) {
        let info = actual.syscall_read.unwrap();
        assert_eq!(info.errno, None);
        let minimum = match actual.syscall_info[0] {
            1 => 80,
            2 => 33,
            _ => panic!("exact syscall phase"),
        };
        assert!((minimum..=88).contains(&info.result));
    } else {
        let info = actual.siginfo_read.unwrap();
        assert_eq!((info.result, info.errno), (0, None));
        assert_eq!(
            i32::from_ne_bytes(actual.siginfo[..4].try_into().unwrap()),
            libc::SIGTRAP
        );
        assert_eq!(
            i32::from_ne_bytes(actual.siginfo[8..12].try_into().unwrap()),
            libc::SI_KERNEL
        );
    }
    assert_eq!(
        &actual.maps.initialized[..actual.maps.observed_bytes],
        maps.raw
    );
}

pub(in crate::linux::remote::dynamic::owner::admission::exec) fn provider(
    owner: &mut Owner,
    pc: u64,
    until: Instant,
) -> ProviderInput {
    // Lifecycle diagnostics may precede work, but a finite fixture does not
    // silently discard any other admission event.
    for _ in 0..8 {
        match owner
            .execute_admission(AdmissionRequest::Advance, until)
            .unwrap()
        {
            AdmissionReply::Provider(input) => {
                assert_eq!(input.input.instruction().logical_pc(), pc);
                return *input;
            }
            AdmissionReply::Event(DynamicAdmissionEvent::Lifecycle(_)) => {}
            _ => panic!("expected exact original provider boundary"),
        }
    }
    panic!("bounded lifecycle diagnostics did not reach provider")
}
pub(in crate::linux::remote::dynamic::owner::admission::exec) fn complete_cpu(
    owner: &mut Owner,
    input: ProviderInput,
    until: Instant,
    expected: Option<&Architecture>,
) -> Architecture {
    let before = raw::architecture(owner.pid);
    assert_eq!(before.registers, *input.input.registers());
    let reply = owner
        .execute_admission(
            AdmissionRequest::Complete {
                token: input.token,
                decision: ProviderDecision::Native,
            },
            until,
        )
        .unwrap();
    let AdmissionReply::Event(DynamicAdmissionEvent::Completed(done)) = reply else {
        panic!("native CPU must complete")
    };
    let after = raw::architecture(owner.pid);
    compare::cpu(&before, &after);
    assert_eq!(*done.selected.input.registers(), before.registers);
    assert_eq!(done.selected.before_xstate, before.xstate);
    assert_eq!(done.before_signal_mask, before.mask);
    assert_eq!(done.selected.after, after.registers);
    assert_eq!(done.selected.xstate, after.xstate);
    assert_eq!(done.signal_mask, after.mask);
    assert_eq!(
        done.selected.execution,
        crate::gate::SelectedExecution::Native
    );
    if let Some(expected) = expected {
        assert_eq!(&after, expected);
    }
    after
}

#[derive(Clone, Copy)]
pub(in crate::linux::remote::dynamic::owner::admission::exec) enum Case {
    Complete,
    #[cfg(test)]
    SourceRefusal,
    #[cfg(test)]
    Errno,
}

#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner::admission::exec) fn run(case: Case) {
    let (fixture, reference) = prepare(case);
    let (send, receive) = sync_channel(1);
    let worker = support::spawn_masked(move || {
        let result = owner_body(case, None, fixture, reference);
        let _ = send.send(result);
    });
    // Matches the independent helper's bounded constructor/four-invocation/
    // cleanup envelope; every actual operation retains its own original 3s.
    let result = match receive.recv_timeout(6 * TIMEOUT) {
        Ok(value) => value,
        Err(_) => std::process::abort(),
    };
    if worker.join().is_err() {
        std::process::abort();
    }
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn prepare(_case: Case) -> (Arc<Fixture>, Arc<raw::Transcript>) {
    #[cfg(test)]
    let case = _case;
    let fixture = {
        let guard = crate::TEST_FILE_FORK.lock().unwrap();
        let fixture = Fixture::new();
        drop(guard);
        fixture
    };
    let reference = Arc::new(raw::original(Arc::clone(&fixture)));
    #[cfg(test)]
    if matches!(case, Case::Errno) {
        let guard = crate::TEST_FILE_FORK.lock().unwrap();
        std::fs::set_permissions(&fixture.new_path, std::fs::Permissions::from_mode(0o400))
            .unwrap();
        assert_eq!(
            std::fs::metadata(&fixture.new_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o400
        );
        drop(guard);
    }
    (fixture, reference)
}

fn owner_body(
    _case: Case,
    backing: Option<backing_cleanup::Scenario>,
    fixture: Arc<Fixture>,
    reference: Arc<raw::Transcript>,
) -> std::thread::Result<()> {
    #[cfg(test)]
    let case = _case;
    let mut owner = Owner::new(
        NEXT_SESSION.fetch_add(1, AtomicOrdering::Relaxed),
        Arc::new(AtomicBool::new(false)),
    );
    let inspection = backing.map(|_| Rc::new(ExecBackingInspection::new(None)));
    owner.exec_backing = inspection.as_ref().map(Rc::clone);
    let mut pin: Option<OwnedFd> = None;
    let mut reader: Option<ExecProgressReader> = None;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let options = fixture.options();
        assert_eq!(
            options.cache,
            liteinst_admission::oracle_chain::CacheLimits::default()
        );
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
                    profile: fixture.profile(),
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
        if let Some(scenario) = backing.filter(|scenario| {
            !matches!(
                scenario,
                backing_cleanup::Scenario::Complete | backing_cleanup::Scenario::Legacy
            )
        }) {
            backing_cleanup::failed_attempt(
                &mut owner,
                exec,
                until,
                backing_cleanup::FailedView {
                    scenario,
                    fixture: &fixture,
                    evidence: &evidence,
                    pin: pin.as_ref().unwrap(),
                    progress: reader.as_ref().unwrap(),
                    inspection: inspection.as_ref().unwrap(),
                },
            );
            return;
        }
        if backing == Some(backing_cleanup::Scenario::Legacy) {
            owner.exec_fault.set(Some(ExecFault::MapsQueryUnsupported));
        }
        let reply = owner.execute_admission(
            AdmissionRequest::Complete {
                token: exec.token,
                decision: ProviderDecision::Native,
            },
            until,
        );
        let progress = reader.as_ref().unwrap();
        #[cfg(test)]
        if matches!(case, Case::Errno) {
            assert!(matches!(
                reply,
                Err(GateError::Control(LaunchError::Invalid(
                    "native exec failure has no proved old-mm continuity"
                )))
            ));
            let snapshot = progress.snapshot();
            assert_eq!(
                snapshot.first_failure,
                Some((
                    ExecJournalStage::RawCapture,
                    KernelFailureKind::InvalidState
                ))
            );
            let attempt = snapshot.attempt.as_ref().unwrap();
            assert_eq!(attempt.raw.len(), 2);
            assert!(attempt.replacement.is_none());
            assert!(attempt.restored_entry.is_none() && attempt.final_state.is_none());
            let evidence = evidence.borrow();
            assert!(evidence.first.is_none());
            assert_eq!((evidence.before, evidence.after), (0, 0));
            let entry = evidence.entry.as_ref().unwrap();
            raw_matches(
                &attempt.raw[0],
                entry,
                evidence.entry_maps.as_ref().unwrap(),
                ((libc::SIGTRAP | 0x80) << 8) | 0x7f,
            );
            let actual = raw::architecture(owner.pid);
            let mut expected = entry.clone();
            expected.registers.rax = (-i64::from(libc::EACCES)) as u64;
            assert_eq!(actual, expected);
            let exit = &attempt.raw[1];
            let maps = Maps::read(owner.pid, pin.as_ref().unwrap());
            raw_matches(exit, &expected, &maps, ((libc::SIGTRAP | 0x80) << 8) | 0x7f);
            let syscall = exit.syscall_read.unwrap();
            assert_eq!(syscall.errno, None);
            assert!((33..=88).contains(&syscall.result));
            assert_eq!(exit.syscall_info[0], 2);
            assert_eq!(
                i64::from_ne_bytes(exit.syscall_info[24..32].try_into().unwrap()),
                -i64::from(libc::EACCES)
            );
            assert_eq!(exit.syscall_info[32], 1);
            assert!(!attempt.facts.iter().any(|fact| matches!(
                fact,
                ExecJournalFact::Validated {
                    phase: ExecValidatedPhase::Replaced | ExecValidatedPhase::Exit,
                    ..
                } | ExecJournalFact::AdmissionComplete { .. }
            )));
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
            return;
        }
        let AdmissionReply::AcquireSources(request) = reply.unwrap() else {
            panic!("actual exec source request")
        };
        assert_eq!(request.images().len(), 1);
        assert_eq!(request.images()[0].bytes(), fixture.new_source);
        let snapshot = progress.snapshot();
        let attempt = snapshot.attempt.as_ref().unwrap();
        assert_eq!(attempt.raw.len(), 4);
        {
            let evidence = evidence.borrow();
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
            assert_eq!(attempt.raw[3].registers.rip, fixture.first_cpu + 1);
            let now = raw::architecture(owner.pid);
            let mut expected = first.architecture.clone();
            expected.registers.rip -= 1;
            assert_eq!(now, expected);
            assert_eq!(
                Architecture::captured(attempt.restored_entry.as_ref().unwrap()),
                expected
            );
            assert_eq!(
                Architecture::captured(attempt.final_state.as_ref().unwrap()),
                expected
            );
            assert_eq!(
                raw::stack(
                    owner.pid,
                    &Maps::read(owner.pid, pin.as_ref().unwrap()),
                    now.registers
                ),
                first.stack
            );
            assert_eq!(raw::memory(owner.pid, NEW_DATA, DATA_LEN), first.data);
            let mut restored = first.source.clone();
            restored[(fixture.first_cpu - NEW) as usize] =
                fixture.new_source[(fixture.first_cpu - NEW) as usize];
            assert_eq!(raw::memory(owner.pid, NEW, CODE), restored);
        }
        assert!(
            evidence
                .borrow_mut()
                .source
                .replace(SourceObservation::read(&request))
                .is_none()
        );
        let before = raw::architecture(owner.pid);
        let maps = Maps::read(owner.pid, pin.as_ref().unwrap());
        #[cfg(test)]
        let facts = if matches!(case, Case::SourceRefusal) {
            DynamicSourceFacts { images: Vec::new() }
        } else {
            DynamicSourceFacts {
                images: vec![DynamicSourceHeads {
                    capture: request.images()[0].id(),
                    heads: fixture.new_heads.clone(),
                }],
            }
        };
        #[cfg(not(test))]
        let facts = DynamicSourceFacts {
            images: vec![DynamicSourceHeads {
                capture: request.images()[0].id(),
                heads: fixture.new_heads.clone(),
            }],
        };
        let result = owner.execute_admission(
            AdmissionRequest::ResolveSources {
                token: request.token,
                facts,
            },
            until,
        );
        #[cfg(test)]
        if matches!(case, Case::SourceRefusal) {
            assert!(matches!(
                result,
                Err(GateError::Refused("dynamic source reply image set differs"))
            ));
            assert_eq!(raw::architecture(owner.pid), before);
            assert_eq!(Maps::read(owner.pid, pin.as_ref().unwrap()), maps);
            assert_eq!(raw::memory(owner.pid, NEW, CODE), fixture.new_source);
            assert_eq!(raw::memory(owner.pid, NEW_DATA, DATA_LEN), fixture.new_data);
            let evidence = evidence.borrow();
            assert_eq!((evidence.before, evidence.after), (0, 0));
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
            let failed = progress.snapshot();
            assert_eq!(
                failed.first_failure,
                Some((
                    ExecJournalStage::Sources,
                    KernelFailureKind::AdmissionRejected
                ))
            );
            assert_eq!(failed.attempt.as_ref().unwrap().raw, attempt.raw);
            assert!(
                !failed
                    .attempt
                    .as_ref()
                    .unwrap()
                    .facts
                    .iter()
                    .any(|fact| matches!(fact, ExecJournalFact::AdmissionComplete { .. }))
            );
            return;
        }
        let AdmissionReply::Event(DynamicAdmissionEvent::ImageReplaced(done)) = result.unwrap()
        else {
            panic!("replacement event")
        };
        assert_eq!(Architecture::admitted(&done.ready), before);
        assert_eq!(raw::architecture(owner.pid), before);
        assert_eq!(Maps::read(owner.pid, pin.as_ref().unwrap()), maps);
        assert_eq!((evidence.borrow().before, evidence.borrow().after), (1, 1));
        let after_commit = progress.snapshot();
        assert!(after_commit.first_failure.is_none());
        assert_eq!(
            after_commit
                .attempt
                .as_ref()
                .unwrap()
                .facts
                .iter()
                .filter(|fact| matches!(fact, ExecJournalFact::AdmissionComplete { .. }))
                .count(),
            1
        );
        if let Some(inspection) = &inspection {
            assert_eq!(owner.exec_fault.get(), None);
            inspection.check(
                6,
                until,
                (backing == Some(backing_cleanup::Scenario::Legacy))
                    .then_some(ExecFault::MapsQueryUnsupported),
            );
        }
        owner.exec_oracle = None;
        let next_until = Instant::now() + TIMEOUT;
        let first = provider(&mut owner, fixture.first_cpu, next_until);
        let first_after = complete_cpu(&mut owner, first, next_until, None);
        let last_until = Instant::now() + TIMEOUT;
        let last = provider(&mut owner, fixture.final_cpu, last_until);
        assert_eq!(
            *last.input.registers(),
            reference.final_cpu.before.architecture.registers
        );
        complete_cpu(
            &mut owner,
            last,
            last_until,
            Some(&reference.final_cpu.after.architecture),
        );
        assert_eq!(
            raw::memory(owner.pid, NEW_DATA, DATA_LEN),
            fixture.new_memory(compare::outputs(first_after.registers))
        );
        assert_eq!(raw::memory(owner.pid, NEW, CODE), fixture.armed(true));
    }));
    // Even a hook assertion leaves the actual owner and complete retired
    // objects in custody. Failure to establish cleanup aborts validation.
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
        let after_cleanup = reader.snapshot();
        let before_cleanup = before_cleanup.as_ref().unwrap();
        assert_eq!(after_cleanup.cleanup_complete, Some(true));
        if result.is_ok() || before_cleanup.first_failure.is_some() {
            assert_eq!(after_cleanup.first_failure, before_cleanup.first_failure);
        }
        assert_eq!(after_cleanup.attempt, before_cleanup.attempt);
    }
    result
}

#[cfg(feature = "dev-exec-backing-cleanup")]
pub(crate) fn backing_child(role: crate::exec_cleanup_support::Role, receipt: &std::fs::File) {
    use crate::exec_cleanup_support::{Role, assert_main_singleton};
    use std::os::fd::AsRawFd;
    if role == Role::InvalidUnmap {
        crate::exec_cleanup_support::prepare_abort();
        assert_main_singleton();
        let until = Instant::now() + TIMEOUT;
        let mut owner = Owner::new(
            NEXT_SESSION.fetch_add(1, AtomicOrdering::Relaxed),
            Arc::new(AtomicBool::new(false)),
        );
        assert!(owner.broker.is_none() && owner.admission.is_none() && owner.owned.is_empty());
        owner.exec_backing = Some(Rc::new(ExecBackingInspection::new(Some(
            receipt.as_raw_fd(),
        ))));
        owner.exec_fault.set(Some(ExecFault::MunmapUnaligned));
        super::sources::backing_cleanup_leaf(&owner, &std::env::current_exe().unwrap(), until);
        unreachable!("invalid unmap must fail-stop");
    }
    let scenario = match role {
        Role::Complete => backing_cleanup::Scenario::Complete,
        Role::ReadError => backing_cleanup::Scenario::ReadError,
        Role::QueryError => backing_cleanup::Scenario::QueryError,
        Role::Legacy => backing_cleanup::Scenario::Legacy,
        Role::Unwind => backing_cleanup::Scenario::Unwind,
        Role::InvalidUnmap => unreachable!(),
    };
    let (fixture, reference) = prepare(Case::Complete);
    // raw::original returned only after its worker joined and native cleanup.
    assert_main_singleton();
    if let Err(payload) = owner_body(Case::Complete, Some(scenario), fixture, reference) {
        std::panic::resume_unwind(payload);
    }
}
