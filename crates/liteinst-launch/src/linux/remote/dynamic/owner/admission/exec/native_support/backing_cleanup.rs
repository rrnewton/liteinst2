//! Three native controls. Child-role dispatch is isolated; no shared fault switch.
//! The complete case reuses all existing state/history/CALL/census comparisons.
use super::*;
use crate::ExecMapsStatus;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Scenario {
    Complete,
    ReadError,
    Unwind,
}
pub(super) struct FailedView<'a> {
    pub(super) scenario: Scenario,
    pub(super) fixture: &'a Fixture,
    pub(super) evidence: &'a Rc<RefCell<Evidence>>,
    pub(super) pin: &'a OwnedFd,
    pub(super) progress: &'a ExecProgressReader,
    pub(super) inspection: &'a ExecBackingInspection,
}
pub(super) fn failed_attempt(
    owner: &mut Owner,
    exec: ProviderInput,
    until: Instant,
    view: FailedView<'_>,
) {
    let panic = view.scenario == Scenario::Unwind;
    assert!(matches!(
        view.scenario,
        Scenario::ReadError | Scenario::Unwind
    ));
    owner.exec_fault.set(Some(if panic {
        ExecFault::AfterMapPanic
    } else {
        ExecFault::MapsRead
    }));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.execute_admission(
            AdmissionRequest::Complete {
                token: exec.token,
                decision: ProviderDecision::Native,
            },
            until,
        )
    }));
    if panic {
        let payload = match result {
            Err(payload) => payload,
            Ok(_) => panic!("post-map panic must unwind"),
        };
        assert_eq!(
            payload.downcast_ref::<&'static str>(),
            Some(&"private exec backing post-map panic")
        );
    } else {
        match result {
            Ok(Err(GateError::Control(LaunchError::System { operation, source }))) => {
                assert_eq!(operation, "read exec identity self maps");
                assert_eq!(source.raw_os_error(), Some(libc::EFAULT));
            }
            _ => panic!("actual null maps-read EFAULT must remain an error"),
        }
    }
    assert_eq!(owner.exec_fault.get(), None);
    view.inspection.check(1, until, Some(panic));
    let snapshot = view.progress.snapshot();
    assert_eq!(
        snapshot.first_failure,
        Some((
            ExecJournalStage::QuarantinedMaps,
            if panic {
                KernelFailureKind::CaughtPanic
            } else {
                KernelFailureKind::NativeIo(Some(libc::EFAULT))
            }
        ))
    );
    let attempt = snapshot.attempt.as_ref().unwrap();
    assert_eq!(attempt.raw.len(), 4);
    assert!(matches!(
        attempt.facts.last(),
        Some(ExecJournalFact::QuarantinedMapsComplete { .. })
    ));
    assert!(!attempt.facts.iter().any(|fact| matches!(
        fact,
        ExecJournalFact::SourcesRequested { .. } | ExecJournalFact::AdmissionComplete { .. }
    )));
    let evidence = view.evidence.borrow();
    assert_eq!((evidence.before, evidence.after), (0, 0));
    assert!(evidence.source.is_none());
    raw_matches(
        &attempt.raw[0],
        evidence.entry.as_ref().unwrap(),
        evidence.entry_maps.as_ref().unwrap(),
        ((libc::SIGTRAP | 0x80) << 8) | 0x7f,
    );
    let first = evidence.first.as_ref().unwrap();
    let mut expected_first_source = view.fixture.new_source.clone();
    expected_first_source[(view.fixture.first_cpu - NEW) as usize] = 0xcc;
    assert_eq!(first.source, expected_first_source);
    assert_eq!(first.data, view.fixture.new_data);
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
    assert_eq!(
        Architecture::captured(attempt.final_state.as_ref().unwrap()),
        expected
    );
    let maps = Maps::read(owner.pid, view.pin);
    assert_eq!(raw::stack(owner.pid, &maps, actual.registers), first.stack);
    assert_eq!(raw::memory(owner.pid, NEW, CODE), view.fixture.new_source);
    assert_eq!(
        raw::memory(owner.pid, NEW_DATA, DATA_LEN),
        view.fixture.new_data
    );
    let capture = &attempt.quarantined_maps;
    assert_eq!(
        (capture.tid, capture.raw_status),
        (owner.pid, *owner.stopped.get(&owner.pid).unwrap())
    );
    assert_eq!(capture.status, ExecMapsStatus::Complete);
    assert_eq!(capture.observed_bytes, maps.raw.len());
    assert_eq!(&capture.initialized[..capture.observed_bytes], maps.raw);
    assert_eq!(capture.initialized.len(), 65536);
    assert!(
        capture.initialized[capture.observed_bytes..]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(capture.open.unwrap().result >= 0);
    assert_eq!(capture.open.unwrap().errno, None);
    for result in [capture.filesystem, capture.last_read, capture.close] {
        assert_eq!(
            result,
            Some(crate::ExecReadOutcome {
                result: 0,
                errno: None
            })
        );
    }
    assert_eq!(capture.filesystem_type, libc::PROC_SUPER_MAGIC);
    assert!(capture.read_calls > 0);
    let admission = owner.admission.as_ref().unwrap();
    let state = admission.exec.as_ref().unwrap();
    let retained = state.attempt.as_ref().unwrap();
    assert!(state.retired.is_none());
    assert_eq!(retained.original.until, until);
    assert!(
        retained.captured.is_none()
            && retained.request.is_none()
            && retained.reply.is_none()
            && !retained.admitted
    );
    let bootstrap = retained.bootstrap.as_ref().unwrap().bootstrap();
    assert_eq!(
        bootstrap.evidence.restored_entry.registers,
        actual.registers
    );
    assert_eq!(bootstrap.evidence.restored_entry.xstate, actual.xstate);
    assert_eq!(bootstrap.evidence.restored_entry.mask, actual.mask);
    assert_eq!(maps.covering(NEW, CODE).permissions, "r--p");
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
    support::alive(view.pin);
    assert!(Instant::now() < until);
    // The enclosing unchanged harness performs actual cleanup, original-pin
    // HUP/ECHILD, exact attempt preservation and unchanged first-failure checks.
}
