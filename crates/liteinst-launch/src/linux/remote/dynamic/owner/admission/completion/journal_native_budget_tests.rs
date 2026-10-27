//! Actual held original state at a one-byte-short journal-prefix reservation.
//! Unused setup reservations are retained lifetime charges, never fabricated
//! retained payloads or refunded capacity. No native release is authorized here.
use super::super::super::kernel_journal::KernelWriterStatus;
use super::super::super::kernel_journal::tests::native::{
    self, BASE, Fixture, TIMEOUT, assert_echild, duplicate, physically_gone, raw, spawn_masked,
};
use super::*;
use std::sync::mpsc::sync_channel;

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

fn body(
    owner: &mut Owner,
    fixture: &Fixture,
    oracle: &raw::Oracle,
    inherited_mask: u64,
    retained: &mut Option<AdmissionOwner>,
) {
    let options = DynamicAdmissionOptions::default();
    let limit = options.limits.source_fact_bytes;
    assert_eq!(limit, 64 * 1024 * 1024);
    let (_, reader) = native::launch_owner(owner, fixture, options, inherited_mask);
    let until = Instant::now() + TIMEOUT;
    let AdmissionReply::Provider(provider) = owner
        .execute_admission(AdmissionRequest::Advance, until)
        .unwrap()
    else {
        panic!("actual original getpid provider input")
    };
    assert_eq!(
        provider.input.instruction().logical_pc(),
        fixture.selected_pc
    );
    assert_eq!(provider.input.registers().rax, libc::SYS_getpid as u64);
    *retained = Some(owner.admission.take().unwrap());
    let admission = retained.as_mut().unwrap();
    admission
        .authenticate_pending(owner, &provider.token, until)
        .unwrap();
    admission
        .check_native_policy(owner, &provider.input)
        .unwrap();
    let pending = admission.pending.as_ref().unwrap();
    let pending_token = pending.token.clone();
    let pending_stop = pending.stop.clone();
    let pending_before = pending.before.clone();
    let pending_input = pending.input.clone();
    let prepared = owner
        .kernel_journal
        .prepare(KernelAttemptBinding {
            pending: pending.token.clone(),
            original_stop: pending.stop.clone(),
            input: pending.input.clone(),
            before: TaskStateSnapshot {
                registers: pending.before.registers,
                xstate: pending.before.xstate.clone(),
                mask: pending.before.signal_mask,
            },
            until,
        })
        .unwrap();
    let journal_bytes = prepared.retained_bytes();
    assert!(journal_bytes > 8 * MAX_XSTATE);
    drop(prepared); // No attachment, execution identity use, or accounting.
    let archive = reader.snapshot();
    assert_eq!(archive.writer, KernelWriterStatus::Active);
    assert!(!archive.archive_poisoned);
    assert!(archive.attempts.is_empty());
    let before = raw::frame(owner.pid);
    assert_eq!(before.state, oracle.original.state);
    assert_eq!(before.storage, oracle.original.storage);
    let mut armed = fixture.source.clone();
    armed[usize::try_from(fixture.selected_pc - BASE).unwrap()] = 0xcc;
    assert_eq!(before.source, armed);

    // Authenticate and reserve the unchanged ordinary completion envelope once.
    // Finishing it does not refund its unused lifetime charge. No payload use,
    // source operation or native state transition occurs during this setup.
    let used = admission.census.used();
    let before_measure = admission.census.charged();
    let measure = admission
        .reserve_transition_with_prefix(owner, 1, true, 1, 0)
        .unwrap();
    let measured = admission.census.charged();
    let ordinary_bytes = measured
        .source_fact_bytes
        .checked_sub(before_measure.source_fact_bytes)
        .unwrap();
    assert!(ordinary_bytes > 0);
    admission.census.finish_reservation(measure).unwrap();
    assert_eq!(admission.census.charged(), measured);
    assert_eq!(admission.census.used(), used);
    // The ordinary envelope still fits, but its additional journal component
    // has exactly journal_bytes-1 bytes left. The actual production Complete
    // must reserve the combined envelope and refuse before native mutation.
    let remaining = ordinary_bytes
        .checked_add(journal_bytes)
        .unwrap()
        .checked_sub(1)
        .unwrap();
    let fill = limit
        .checked_sub(measured.source_fact_bytes)
        .unwrap()
        .checked_sub(remaining)
        .unwrap();
    assert!(fill > 0);
    let filler = admission
        .census
        .reserve(BudgetCharge {
            source_fact_bytes: fill,
            ..BudgetCharge::default()
        })
        .unwrap();
    admission.census.finish_reservation(filler).unwrap();
    let charged = admission.census.charged();
    assert_eq!(limit - charged.source_fact_bytes, remaining);
    assert_eq!(remaining - ordinary_bytes, journal_bytes - 1);
    assert_eq!(
        admission.census.used(),
        used,
        "unused reservations do not fabricate retained-byte use"
    );
    assert_eq!(raw::frame(owner.pid), before);
    assert_eq!(reader.snapshot(), archive);
    let registry = admission.native.admission_snapshot();
    let current = admission
        .native
        .admission_current(provider.token.task.task)
        .unwrap();
    let rows = admission.census.rows().cloned().collect::<Vec<_>>();
    let history = admission.census.history_snapshot().unwrap();
    let origins = admission.origins.clone();
    let generation = admission.census.generation();
    owner.admission = retained.take();
    let result = owner.execute_admission(
        AdmissionRequest::Complete {
            token: provider.token,
            decision: ProviderDecision::Native,
        },
        until,
    );
    assert!(matches!(
        result,
        Err(GateError::Refused(
            "dynamic continuation lifetime capacity exhausted"
        ))
    ));
    assert!(owner.closing);
    assert!(owner.cancel.load(Ordering::Acquire));
    let admission = owner.admission.as_ref().unwrap();
    assert!(admission.closed);
    assert!(admission.completion_history.is_empty());
    assert_eq!(admission.native.admission_snapshot(), registry);
    assert_eq!(
        admission
            .native
            .admission_current(pending_token.task.task)
            .unwrap(),
        current
    );
    assert!(admission.native.admission_events_empty());
    assert_eq!(admission.census.charged(), charged);
    assert_eq!(admission.census.used(), used);
    assert_eq!(admission.census.rows().cloned().collect::<Vec<_>>(), rows);
    assert_eq!(admission.census.history_snapshot().unwrap(), history);
    assert_eq!(admission.census.generation(), generation);
    assert_eq!(admission.origins, origins);
    let pending = admission.pending.as_ref().unwrap();
    assert_eq!(pending.token, pending_token);
    assert_eq!(pending.stop, pending_stop);
    assert_eq!(pending.before, pending_before);
    assert_eq!(pending.input, pending_input);
    assert_eq!(pending.until, until);
    assert_eq!(raw::frame(owner.pid), before);
    // An unattached prepared attempt creates no row and therefore no release,
    // kernel-effect, transport or completion fact. Do not fabricate a row to
    // turn this pre-effect refusal into a recorded native execution.
    assert_eq!(reader.snapshot(), archive);
    assert!(reader.snapshot().attempts.is_empty());
    let repeated = owner.execute_admission(AdmissionRequest::Advance, until);
    assert!(matches!(
        repeated,
        Err(GateError::Control(LaunchError::Invalid(
            "dynamic operation cancelled"
        )))
    ));
    assert_eq!(raw::frame(owner.pid), before);
    assert_eq!(reader.snapshot(), archive);
}

#[test]
fn actual_held_journal_prefix_capacity_refusal_precedes_attachment_and_release() {
    let fixture = Fixture::new(libc::SYS_getpid);
    let oracle = raw::original(Arc::clone(&fixture));
    let (send, receive) = sync_channel(1);
    let worker = spawn_masked(move || {
        let blocked = launch::BlockedSignals::new().unwrap();
        let mut owner = Owner::new(
            NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
            Arc::new(AtomicBool::new(false)),
        );
        let reader = owner.kernel_journal.reader();
        let mut retained = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            body(
                &mut owner,
                &fixture,
                &oracle,
                native::APP_MASK,
                &mut retained,
            );
        }));
        let pins = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.handles.values().map(duplicate).collect::<Vec<_>>()
        }));
        let parent = owner.pid;
        let cleanup = owner.cleanup();
        drop(retained);
        let restored = blocked.restore();
        let _ = send.send((result, pins, parent, reader, cleanup, restored));
    });
    let (result, pins, parent, reader, cleanup, restored) = receive
        .recv_timeout(3 * TIMEOUT)
        .expect("native budget caller deadline; original owner retains cleanup");
    worker.join().unwrap();
    restored.unwrap();
    let pins = match pins {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert_eq!(cleanup.unwrap().reaped, [parent]);
    assert_eq!(pins.len(), 1);
    for pin in &pins {
        assert!(physically_gone(pin));
        assert_echild(pin);
    }
    assert_eq!(reader.snapshot().writer, KernelWriterStatus::Cleaned);
    assert!(reader.snapshot().attempts.is_empty());
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
