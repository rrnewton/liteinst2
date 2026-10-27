//! Prospective pure transaction controls. The physical test backend records
//! injected observations; it never executes generated code or substitutes for
//! the unchanged 838 native word cases, 26 calibrations or actual byte protocol.
use super::*;
use crate::frontend_tls::{self, PointObservation};
use crate::generation::{Completion, FunctionId};
use liteinst2::rapid::RapidTogglePlan;
use liteinst2::scanner::InstructionScanner;
use std::sync::atomic::{AtomicUsize, Ordering};

type Inject = Arc<dyn Fn(&[(usize, bool)], &mut Progress) -> PhysicalResult + Send + Sync>;
type Calls = Arc<Mutex<Vec<Vec<(usize, bool)>>>>;
type SessionSlot = Arc<Mutex<Option<std::sync::Weak<Inner>>>>;
type OwnerSlot = Arc<Mutex<Option<(std::sync::Weak<Inner>, EpochHandle)>>>;
pub(super) struct Contract {
    calls: Calls,
    inject: Option<Inject>,
}
impl Contract {
    pub(super) fn perform(
        &self,
        changes: &[(usize, bool)],
        progress: &mut Progress,
    ) -> PhysicalResult {
        self.calls.lock().unwrap().push(changes.to_vec());
        if let Some(f) = &self.inject {
            return f(changes, progress);
        }
        *progress = Progress::Bytes {
            stores_completed: changes.len(),
            store_may_have_started: true,
            synchronized: true,
        };
        Ok(())
    }
}
const A: FunctionId = FunctionId(11);
const B: FunctionId = FunctionId(12);
const C: FunctionId = FunctionId(13);
unsafe extern "C" fn optional(_: *mut liteinst2::trampoline::HookContext) {}
fn specs() -> [PointSpec; 4] {
    [
        PointSpec {
            pc: 0x1000,
            group: 0,
            function: Some(A),
            callback: optional,
        },
        PointSpec {
            pc: 0x1005,
            group: 0,
            function: Some(B),
            callback: optional,
        },
        PointSpec {
            pc: 0x1010,
            group: 1,
            function: Some(C),
            callback: optional,
        },
        PointSpec {
            pc: 0x1015,
            group: 1,
            function: None,
            callback: optional,
        },
    ]
}
fn limits() -> frontend::Limits {
    frontend::Limits {
        epochs: 4,
        threads: 4,
        depth: 4,
        records_per_epoch: 16,
        actions: 32,
    }
}
fn config() -> Config {
    Config {
        retained_per_function: 1,
        max_inflight: 4,
        max_invocations: 16,
    }
}
fn fixture(inject: Option<Inject>) -> (CodePointSession, Calls) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let c = Builder::new(71, &specs(), limits())
        .unwrap()
        .finish(Physical::Contract(Contract {
            calls: Arc::clone(&calls),
            inject,
        }))
        .unwrap();
    (c, calls)
}
fn enter(
    c: &CodePointSession,
    registration: &frontend_tls::ThreadRegistration,
    function: FunctionId,
) -> Completion {
    let owner = c
        .inner
        .binding
        .session
        .acquire(registration.identity(), 71)
        .unwrap();
    match registration.observe_point(&owner, function, 9, || frontend::Observation::Value(23)) {
        PointObservation::Completed {
            completion,
            payload,
        } => {
            assert_eq!(completion.admission, payload.admission);
            completion
        }
        _ => panic!("expected a complete real frontend point reservation"),
    }
}

#[test]
fn pending_releases_both_metadata_locks_and_refuses_reentrant_writer() {
    let slot: SessionSlot = Arc::new(Mutex::new(None));
    let callback_slot = Arc::clone(&slot);
    let observed = Arc::new(AtomicUsize::new(0));
    let callback_observed = Arc::clone(&observed);
    let inject: Inject = Arc::new(move |changes, progress| {
        let inner = callback_slot
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap();
        let c = CodePointSession { inner };
        assert_eq!(
            c.inner.binding.session.code_groups(None).unwrap(),
            vec![false, true]
        );
        assert!(matches!(c.stage(config()), Err(Error::Busy)));
        assert_eq!(c.inner.binding.session.snapshot().unwrap().current, None);
        assert_eq!(
            c.history().unwrap().last().unwrap().progress,
            Progress::Pending
        );
        callback_observed.fetch_add(1, Ordering::SeqCst);
        *progress = Progress::Bytes {
            stores_completed: changes.len(),
            store_may_have_started: true,
            synchronized: true,
        };
        Ok(())
    });
    let (c, calls) = fixture(Some(inject));
    *slot.lock().unwrap() = Some(Arc::downgrade(&c.inner));
    let epoch = c.stage(config()).unwrap();
    let arm = c.begin_arm(epoch).unwrap();
    let registration = frontend_tls::attach_current_thread(&c.inner.binding.session).unwrap();
    assert!(
        c.inner
            .binding
            .session
            .acquire(registration.identity(), 71)
            .is_ok()
    );
    assert!(matches!(c.begin_arm(epoch), Err(Error::Busy)));
    let ticket = arm.execute().unwrap();
    assert_eq!(c.complete(&ticket).unwrap(), Visibility::Complete);
    let pending = c.begin_disarm(epoch).unwrap();
    assert!(matches!(
        c.inner.binding.session.acquire(registration.identity(), 71),
        Err(frontend::EntryError::NoCurrent)
    ));
    assert!(matches!(c.begin_disarm(epoch), Err(Error::Busy)));
    pending.execute().unwrap();
    assert_eq!(observed.load(Ordering::SeqCst), 1);
    assert_eq!(*calls.lock().unwrap(), vec![vec![(0, false), (1, false)]]);
}

#[test]
fn all_closed_and_not_mandatory_select_exact_physical_group() {
    let (c, calls) = fixture(None);
    let epoch = c.stage(config()).unwrap();
    c.begin_arm(epoch).unwrap().execute().unwrap();
    let registration = frontend_tls::attach_current_thread(&c.inner.binding.session).unwrap();
    let a = enter(&c, &registration, A);
    c.begin_deactivate(a.deactivate.unwrap())
        .unwrap()
        .unwrap()
        .execute()
        .unwrap();
    assert!(
        calls.lock().unwrap().is_empty(),
        "B remains open in the same physical group"
    );
    let b = enter(&c, &registration, B);
    c.begin_deactivate(b.deactivate.unwrap())
        .unwrap()
        .unwrap()
        .execute()
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), vec![vec![(0, false), (1, false)]]);
    let mandatory_neighbor = enter(&c, &registration, C);
    c.begin_deactivate(mandatory_neighbor.deactivate.unwrap())
        .unwrap()
        .unwrap()
        .execute()
        .unwrap();
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "mandatory neighbor forbids group removal"
    );
    c.begin_disarm(epoch).unwrap().execute().unwrap();
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(
        c.history().unwrap().last().unwrap().desired_groups,
        vec![false, true]
    );
    assert!(
        c.inner
            .binding
            .controls
            .iter()
            .all(ProbeControl::is_enabled)
    );
    assert_eq!(c.report(epoch).unwrap().unwrap().records().count(), 3);
}

#[test]
fn stale_k_and_foreign_ticket_never_gain_a_store_or_completion() {
    let (c, calls) = fixture(None);
    let a = c.stage(config()).unwrap();
    let b = c.stage(config()).unwrap();
    let first = c.begin_arm(a).unwrap().execute().unwrap();
    let registration = frontend_tls::attach_current_thread(&c.inner.binding.session).unwrap();
    let completion = enter(&c, &registration, A);
    let latest = c.begin_arm(b).unwrap().execute().unwrap();
    assert!(
        c.begin_deactivate(completion.deactivate.unwrap())
            .unwrap()
            .is_none()
    );
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(
        c.inner
            .binding
            .session
            .snapshot()
            .unwrap()
            .actions
            .last()
            .unwrap()
            .kind,
        frontend::ActionKind::Stale
    );
    assert_eq!(c.complete(&first), Err(Error::Stale));
    let (foreign, _) = fixture(None);
    assert_eq!(foreign.complete(&latest), Err(Error::Stale));
    assert_eq!(c.complete(&latest), Ok(Visibility::Complete));
}

#[test]
fn old_acquisition_refuses_after_rearm_but_old_reservation_finishes_with_old_owner() {
    let (c, _) = fixture(None);
    let a = c.stage(config()).unwrap();
    let b = c.stage(config()).unwrap();
    let d = c.stage(config()).unwrap();
    c.begin_arm(a).unwrap().execute().unwrap();
    let registration = frontend_tls::attach_current_thread(&c.inner.binding.session).unwrap();
    let acquired = c
        .inner
        .binding
        .session
        .acquire(registration.identity(), 71)
        .unwrap();
    c.begin_arm(b).unwrap().execute().unwrap();
    let ran = AtomicUsize::new(0);
    assert!(matches!(
        registration.observe_point(&acquired, A, 0, || {
            ran.fetch_add(1, Ordering::SeqCst);
            frontend::Observation::Value(0)
        }),
        PointObservation::Refused(_)
    ));
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    let old = c
        .inner
        .binding
        .session
        .acquire(registration.identity(), 71)
        .unwrap();
    match registration.observe_point(&old, A, 19, || {
        c.begin_arm(d).unwrap().execute().unwrap();
        assert!(
            c.report(b).unwrap().is_none(),
            "old reservation is still held"
        );
        frontend::Observation::Value(29)
    }) {
        PointObservation::Completed {
            completion,
            payload,
        } => {
            assert_eq!(completion.admission.generation.get(), b.0);
            assert_eq!(payload.admission, completion.admission);
        }
        _ => panic!("reserved old point must finish"),
    }
    assert_eq!(c.report(b).unwrap().unwrap().records().count(), 1);
    assert_eq!(c.inner.state.lock().unwrap().current, Some(d));
}

#[test]
fn byte_store_then_barrier_refusal_is_terminal_without_rollback() {
    let error = SyncCoreError::UnsupportedPlatform;
    let inject: Inject = Arc::new(move |changes, progress| {
        *progress = Progress::Bytes {
            stores_completed: changes.len(),
            store_may_have_started: true,
            synchronized: false,
        };
        Err((Error::Synchronize(error), None))
    });
    let (c, calls) = fixture(Some(inject));
    let epoch = c.stage(config()).unwrap();
    let arm = c.begin_arm(epoch).unwrap().execute().unwrap();
    assert!(matches!(
        c.begin_disarm(epoch).unwrap().execute(),
        Err(Error::Synchronize(SyncCoreError::UnsupportedPlatform))
    ));
    let records = c.history().unwrap();
    let r = records.last().unwrap();
    assert_eq!(r.status, Status::Failed);
    assert_eq!(r.old_current, Some(epoch));
    assert_eq!(r.new_current, None);
    assert_eq!(
        r.progress,
        Progress::Bytes {
            stores_completed: 2,
            store_may_have_started: true,
            synchronized: false
        }
    );
    assert!(matches!(c.begin_arm(epoch), Err(Error::Terminal)));
    assert_eq!(c.complete(&arm), Err(Error::Stale));
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert!(c.report(epoch).unwrap().is_some());
}

#[test]
fn word_receipts_preserve_pre_store_aborts_three_partial_barriers_and_unwind() {
    let sync = SyncPatchError::Synchronize(SyncCoreError::UnsupportedPlatform);
    let cases = [
        Receipt {
            phase: Phase::Aborted,
            members: 2,
            synchronizations: 0,
            mutated: false,
            writer_ownership_retained: false,
            failure: Some(sync),
        },
        Receipt {
            phase: Phase::Aborted,
            members: 2,
            synchronizations: 1,
            mutated: false,
            writer_ownership_retained: false,
            failure: Some(sync),
        },
        Receipt {
            phase: Phase::GuardsPublished,
            members: 2,
            synchronizations: 0,
            mutated: true,
            writer_ownership_retained: true,
            failure: Some(sync),
        },
        Receipt {
            phase: Phase::BacksPublished,
            members: 2,
            synchronizations: 1,
            mutated: true,
            writer_ownership_retained: true,
            failure: Some(sync),
        },
        Receipt {
            phase: Phase::FrontsPublished,
            members: 2,
            synchronizations: 2,
            mutated: true,
            writer_ownership_retained: true,
            failure: Some(sync),
        },
        Receipt {
            phase: Phase::Prepared,
            members: 2,
            synchronizations: 0,
            mutated: true,
            writer_ownership_retained: true,
            failure: Some(SyncPatchError::IncompleteOperation),
        },
        Receipt {
            phase: Phase::Prepared,
            members: 2,
            synchronizations: 0,
            mutated: false,
            writer_ownership_retained: true,
            failure: Some(SyncPatchError::IncompleteOperation),
        },
    ];
    for receipt in cases {
        let inject: Inject = Arc::new(move |_, progress| {
            *progress = Progress::Words { receipt };
            Err((Error::Patch(receipt.failure.unwrap()), None))
        });
        let (c, calls) = fixture(Some(inject));
        let epoch = c.stage(config()).unwrap();
        c.begin_arm(epoch).unwrap().execute().unwrap();
        assert!(c.begin_disarm(epoch).unwrap().execute().is_err());
        let history = c.history().unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.progress, Progress::Words { receipt });
        assert_eq!(last.status, Status::Failed);
        assert!(matches!(c.begin_arm(epoch), Err(Error::Terminal)));
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(c.report(epoch).unwrap().is_some());
    }
}

#[test]
fn complete_word_receipt_finalizes_only_the_exact_selected_points() {
    let receipt = Receipt {
        phase: Phase::Complete,
        members: 2,
        synchronizations: 3,
        mutated: true,
        writer_ownership_retained: false,
        failure: None,
    };
    let inject: Inject = Arc::new(move |changes, progress| {
        assert_eq!(changes, &[(0, false), (1, false)]);
        *progress = Progress::Words { receipt };
        Ok(())
    });
    let (c, calls) = fixture(Some(inject));
    let epoch = c.stage(config()).unwrap();
    c.begin_arm(epoch).unwrap().execute().unwrap();
    let ticket = c.begin_disarm(epoch).unwrap().execute().unwrap();
    assert_eq!(c.complete(&ticket), Ok(Visibility::Complete));
    let history = c.history().unwrap();
    let last = history.last().unwrap();
    assert_eq!(last.progress, Progress::Words { receipt });
    assert_eq!(last.status, Status::Complete);
    assert_eq!(last.desired_groups, vec![false, true]);
    assert!(last.failure.is_none());
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn panic_progress_is_recorded_before_resuming_the_same_unwind() {
    let inject: Inject = Arc::new(|_, progress| {
        *progress = Progress::Bytes {
            stores_completed: 1,
            store_may_have_started: true,
            synchronized: false,
        };
        std::panic::panic_any(71_u32)
    });
    let (c, calls) = fixture(Some(inject));
    let epoch = c.stage(config()).unwrap();
    c.begin_arm(epoch).unwrap().execute().unwrap();
    let panic = catch_unwind(AssertUnwindSafe(|| {
        c.begin_disarm(epoch).unwrap().execute()
    }))
    .err()
    .unwrap();
    assert_eq!(panic.downcast_ref::<u32>(), Some(&71));
    let history = c.history().unwrap();
    let r = history.last().unwrap();
    assert_eq!(r.failure, Some(Error::Unwound));
    assert_eq!(r.status, Status::Failed);
    assert_eq!(
        r.progress,
        Progress::Bytes {
            stores_completed: 1,
            store_may_have_started: true,
            synchronized: false
        }
    );
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert!(matches!(c.stage(config()), Err(Error::Terminal)));
}

#[test]
fn dropped_pending_owner_retains_closed_failed_metadata_and_no_store() {
    let (c, calls) = fixture(None);
    let epoch = c.stage(config()).unwrap();
    drop(c.begin_arm(epoch).unwrap());
    let history = c.history().unwrap();
    let r = &history[0];
    assert_eq!(r.failure, Some(Error::Abandoned));
    assert_eq!(r.progress, Progress::NoStore);
    assert!(r.metadata_changed);
    assert!(calls.lock().unwrap().is_empty());
    assert!(c.report(epoch).unwrap().is_some());
    assert!(matches!(c.begin_arm(epoch), Err(Error::Terminal)));
}

#[test]
fn terminal_last_drop_retains_binding_and_physical_owners() {
    let inject: Inject = Arc::new(|_, progress| {
        *progress = Progress::Bytes {
            stores_completed: 1,
            store_may_have_started: true,
            synchronized: false,
        };
        Err((Error::Synchronize(SyncCoreError::UnsupportedPlatform), None))
    });
    let (c, calls) = fixture(Some(inject));
    let weak = Arc::downgrade(&c.inner.binding);
    let epoch = c.stage(config()).unwrap();
    c.begin_arm(epoch).unwrap().execute().unwrap();
    assert!(c.begin_disarm(epoch).unwrap().execute().is_err());
    let before = Arc::strong_count(&calls);
    assert_eq!(before, 2);
    assert_eq!(c.history().unwrap().last().unwrap().status, Status::Failed);
    drop(c);
    assert!(
        weak.upgrade().is_some(),
        "terminal binding and old metadata owners are retained"
    );
    assert_eq!(
        Arc::strong_count(&calls),
        before,
        "the physical owner is not released on terminal Drop"
    );
}

#[test]
fn physical_success_with_failed_final_join_keeps_physical_receipt_and_failed_owner() {
    let slot: OwnerSlot = Arc::new(Mutex::new(None));
    let hook = Arc::clone(&slot);
    let inject: Inject = Arc::new(move |changes, progress| {
        *progress = Progress::Bytes {
            stores_completed: changes.len(),
            store_may_have_started: true,
            synchronized: true,
        };
        // Deliberate private test corruption of the metadata join after stores;
        // no public API exposes this competing Session publication authority.
        let held = hook.lock().unwrap();
        let (inner, owner) = held.as_ref().unwrap();
        inner
            .upgrade()
            .unwrap()
            .binding
            .session
            .publish(owner, FailurePoint::None)
            .unwrap();
        Ok(())
    });
    let (c, _) = fixture(Some(inject));
    let a = c.stage(config()).unwrap();
    let b = c.stage(config()).unwrap();
    let owner = CodePointSession::owner(&c.state().unwrap(), b)
        .unwrap()
        .clone();
    *slot.lock().unwrap() = Some((Arc::downgrade(&c.inner), owner));
    c.begin_arm(a).unwrap().execute().unwrap();
    assert!(matches!(
        c.begin_disarm(a).unwrap().execute(),
        Err(Error::FinalConfirmation)
    ));
    let history = c.history().unwrap();
    let r = history.last().unwrap();
    assert_eq!(r.status, Status::Failed);
    assert_eq!(
        r.progress,
        Progress::Bytes {
            stores_completed: 2,
            store_may_have_started: true,
            synchronized: true
        }
    );
    assert!(c.report(a).unwrap().is_some());
    assert!(c.report(b).unwrap().is_some());
}

#[test]
fn real_controlled_plans_bind_exact_owner_at_same_pc_and_never_expose_a_writer() {
    let builder = Builder::new(71, &specs(), limits()).unwrap();
    let foreign = Builder::new(72, &specs(), limits()).unwrap();
    let action = builder.actions().remove(0);
    let wrong = foreign.actions().remove(0);
    let bytes = [0xb8, 0x78, 0x56, 0x34, 0x12];
    let scanner = InstructionScanner::default();
    let scan = scanner.scan(&bytes, 0x1000).unwrap();
    let plan =
        RapidTogglePlan::from_controlled_scan(&scanner, &scan, &bytes, 0x1000, 0x1000, &action)
            .unwrap();
    assert!(matches_point(
        plan.execute_address(),
        plan.controlled_actions(),
        &action
    ));
    assert!(!matches_point(
        plan.execute_address(),
        plan.controlled_actions(),
        &wrong
    ));
    let shifted = ControlledAction {
        logical_pc: 0x1005,
        control: action.control.clone(),
    };
    assert!(!matches_point(
        plan.execute_address(),
        plan.controlled_actions(),
        &shifted
    ));
    assert_eq!(plan.original_window(), bytes);
    assert_eq!(&plan.original_window()[1..], &bytes[1..]);
    assert!(action.control.try_set_enabled(false).is_err());
    assert!(action.control.is_enabled());
    assert!(wrong.control.try_set_enabled(false).is_err());
    assert!(wrong.control.is_enabled());
}
