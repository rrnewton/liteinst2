use super::*;
use crate::generation::storage::allocation_probe;
use crate::generation::{CancelReason, Disposition, Terminal};
use std::panic::{AssertUnwindSafe, catch_unwind};

const INSTALL: u64 = 71;
const A: FunctionId = FunctionId(11);
fn limits(e: usize) -> Limits {
    Limits {
        epochs: e,
        threads: 2,
        depth: 4,
        records_per_epoch: 8,
        actions: 16,
    }
}
fn config() -> Config {
    Config {
        retained_per_function: 1,
        max_inflight: 8,
        max_invocations: 8,
    }
}
fn session(e: usize) -> Session {
    Session::new_streaming_history(
        INSTALL,
        &[FunctionSpec {
            function: A,
            group: 0,
        }],
        &[GroupSpec { mandatory: true }],
        limits(e),
    )
    .unwrap()
}
fn prepared(e: usize) -> (Session, Vec<EpochStorage>) {
    let mut s = session(e);
    let banks = s.prepare_epoch_storage(config()).unwrap();
    (s, banks)
}
fn rs(identity: u64) -> ModelReturnSlot {
    ModelReturnSlot {
        identity,
        word: 0x1000 + identity,
    }
}
#[derive(Debug, Eq, PartialEq)]
struct BankView {
    spec: usize,
    index: usize,
    config: Config,
    model: [(usize, usize, usize); 2],
    payload: (usize, usize, usize),
    clean: bool,
}
fn bank_view(b: &EpochStorage) -> BankView {
    BankView {
        spec: Arc::as_ptr(&b.spec) as usize,
        index: b.index,
        config: b.config,
        model: b.model.geometry(),
        payload: (
            b.payloads.as_ptr() as usize,
            b.payloads.len(),
            b.payloads.capacity(),
        ),
        clean: b.model.clean() && b.payloads.iter().all(|p| p.get().is_none()),
    }
}
#[derive(Debug, Eq, PartialEq)]
struct OwnerView {
    outer: usize,
    inner: usize,
    generation: GenerationId,
    config: Config,
    payload: (usize, usize, usize),
    model: [(usize, usize, usize); 2],
    records: Vec<RecordObservation>,
    owners: [usize; 4],
    reserved: usize,
    permits: usize,
}
fn owner_view(s: &Session, slot: &Option<EpochHandle>) -> OwnerView {
    let h = slot.as_ref().unwrap();
    OwnerView {
        outer: Arc::as_ptr(&h.owner) as usize,
        inner: Arc::as_ptr(&h.owner.epoch) as usize,
        generation: h.generation(),
        config: h.owner.epoch.config(),
        payload: (
            h.owner.payloads.as_ptr() as usize,
            h.owner.payloads.len(),
            h.owner.payloads.capacity(),
        ),
        model: storage::epoch_geometry(&h.owner.epoch),
        records: h.records().collect(),
        owners: [
            Arc::strong_count(&h.owner),
            Arc::weak_count(&h.owner),
            Arc::strong_count(&h.owner.epoch),
            Arc::weak_count(&h.owner.epoch),
        ],
        reserved: h.reservations(),
        permits: s.retained_epochs(),
    }
}
fn refuses(s: &Session, slot: &mut Option<EpochHandle>, expected: StorageReclaimError) {
    let before = owner_view(s, slot);
    assert_eq!(s.reclaim_epoch_storage(slot).err(), Some(expected));
    assert_eq!(owner_view(s, slot), before);
}

#[test]
fn preparation_requires_exact_pristine_state_and_once_issued_mode() {
    let mut legacy = Session::new(
        INSTALL,
        &[FunctionSpec {
            function: A,
            group: 0,
        }],
        &[GroupSpec { mandatory: true }],
        limits(2),
    )
    .unwrap();
    assert_eq!(
        legacy.prepare_epoch_storage(config()).err(),
        Some(SetupError::StorageMode)
    );
    assert!(legacy.stage(config()).is_ok());
    let mut s = session(2);
    for (c, expected) in [
        (
            Config {
                retained_per_function: 0,
                ..config()
            },
            SetupError::Generation(CreateError::ZeroRetainedBudget),
        ),
        (
            Config {
                max_inflight: 0,
                ..config()
            },
            SetupError::Generation(CreateError::InvalidInflightLimit),
        ),
        (
            Config {
                max_invocations: 0,
                ..config()
            },
            SetupError::Generation(CreateError::InvalidInvocationLimit),
        ),
        (
            Config {
                max_invocations: 9,
                ..config()
            },
            SetupError::InvalidLimits,
        ),
    ] {
        assert_eq!(s.prepare_epoch_storage(c).err(), Some(expected));
        assert!(s.inner.storage_mode.is_none());
        assert_eq!(s.retained_epochs(), 0);
    }
    let banks = s.prepare_epoch_storage(config()).unwrap();
    assert_eq!(banks.len(), 2);
    assert_eq!(banks.iter().map(|b| b.index).collect::<Vec<_>>(), [0, 1]);
    assert!(banks.iter().all(|b| bank_view(b).clean));
    assert_eq!(s.retained_epochs(), 0);
    assert!(!s.inner.ever_staged.load(Ordering::Acquire));
    drop(banks);
    assert_eq!(
        s.prepare_epoch_storage(config()).err(),
        Some(SetupError::StorageMode)
    );
    assert_eq!(s.stage(config()).err(), Some(SetupError::StorageMode));
    assert_eq!(s.retained_epochs(), 0);

    let mut staged = session(1);
    let old = staged.stage(config()).unwrap();
    staged.publish(&old, FailurePoint::None).unwrap();
    staged.remove_current().unwrap();
    assert_eq!(staged.drain_history().unwrap().unwrap().range, 0..2);
    drop(old);
    assert_eq!(staged.retained_epochs(), 0);
    assert_eq!(
        staged.prepare_epoch_storage(config()).err(),
        Some(SetupError::InvalidStorage)
    );
    let mut registered = session(1);
    drop(registered.register_thread(7).unwrap());
    assert_eq!(
        registered.prepare_epoch_storage(config()).err(),
        Some(SetupError::InvalidStorage)
    );
    let mut aliased = session(1);
    let alias = Arc::clone(&aliased.inner);
    assert_eq!(
        aliased.prepare_epoch_storage(config()).err(),
        Some(SetupError::InvalidStorage)
    );
    drop(alias);
    let weak = Arc::downgrade(&aliased.inner);
    assert_eq!(
        aliased.prepare_epoch_storage(config()).err(),
        Some(SetupError::InvalidStorage)
    );
    drop(weak);
    assert_eq!(aliased.prepare_epoch_storage(config()).unwrap().len(), 1);

    for part in 0..5 {
        let mut dirty = session(1);
        {
            let mut w = dirty.inner.writer.lock().unwrap();
            match part {
                0 => w.history.base = 1,
                1 => w.history.number = 1,
                2 => dirty.inner.committed_end.store(1, Ordering::Release),
                3 => w.enabled[0] = true,
                4 => w.status = ControllerStatus::TerminalFailure,
                _ => unreachable!(),
            }
        }
        assert_eq!(
            dirty.prepare_epoch_storage(config()).err(),
            Some(SetupError::InvalidStorage)
        );
        assert!(dirty.inner.storage_mode.is_none());
    }
}

#[test]
fn preparation_allocation_failures_leave_mode_and_all_ownership_unchanged() {
    // Outer E vector, then functions/slots/payloads for each of two banks.
    for fail in 0..7 {
        let mut s = session(2);
        let before = s.history_window().unwrap();
        let _probe = allocation_probe::start(Some(fail));
        let error = s.prepare_epoch_storage(config()).err().unwrap();
        assert!(matches!(
            error,
            SetupError::Allocation | SetupError::Generation(CreateError::Allocation)
        ));
        assert_eq!(allocation_probe::calls(), fail + 1);
        assert_eq!(s.history_window().unwrap(), before);
        assert!(s.inner.storage_mode.is_none());
        assert!(!s.inner.ever_staged.load(Ordering::Acquire));
        assert_eq!(Arc::strong_count(&s.inner.spec), 1);
        assert_eq!(s.retained_epochs(), 0);
        drop(_probe);
        assert_eq!(s.prepare_epoch_storage(config()).unwrap().len(), 2);
    }
    let mut s = session(2);
    let _probe = allocation_probe::start(None);
    assert_eq!(s.prepare_epoch_storage(config()).unwrap().len(), 2);
    assert_eq!(allocation_probe::calls(), 7);
}

#[test]
fn prepared_stage_refusals_return_same_bank_and_release_failed_permit() {
    let (s, mut banks) = prepared(1);
    let foreign = session(1);
    let mut bank = banks.pop().unwrap();
    let before = bank_view(&bank);
    let (error, returned) = foreign.stage_prepared_storage(bank).err().unwrap();
    assert_eq!(error, SetupError::InvalidStorage);
    assert_eq!(bank_view(&returned), before);
    bank = returned;
    for part in 0..4 {
        match part {
            0 => bank.index = 1,
            1 => bank.config.retained_per_function = 2,
            2 => {
                let _ = bank.payloads.pop();
            }
            3 => {}
            _ => unreachable!(),
        }
        let malformed = bank_view(&bank);
        let result = if part == 3 {
            let permit = s.inner.pool.reserve().unwrap();
            let result = s.stage_prepared_storage(bank);
            assert_eq!(s.retained_epochs(), 1);
            drop(permit);
            result
        } else {
            s.stage_prepared_storage(bank)
        };
        let (error, returned) = result.err().unwrap();
        assert_eq!(
            error,
            if part == 3 {
                SetupError::EpochLimit
            } else {
                SetupError::InvalidStorage
            }
        );
        assert_eq!(bank_view(&returned), malformed);
        bank = returned;
        match part {
            0 => bank.index = 0,
            1 => bank.config = config(),
            2 => bank.payloads.push(OnceLock::new()),
            _ => {}
        }
        assert_eq!(s.retained_epochs(), 0);
    }
    let before = bank_view(&bank);
    let (error, bank) = s
        .stage_storage_with(bank, Storage::test_exhausted)
        .err()
        .unwrap();
    assert_eq!(
        error,
        SetupError::Generation(CreateError::GenerationExhausted)
    );
    assert_eq!(bank_view(&bank), before);
    assert_eq!(s.retained_epochs(), 0);
    assert!(!s.inner.ever_staged.load(Ordering::Acquire));
    let _probe = allocation_probe::start(Some(0));
    let owner = s.stage_prepared_storage(bank).unwrap();
    assert_eq!(s.retained_epochs(), 1);
    assert_eq!(allocation_probe::calls(), 0);
    drop(owner);
}

#[test]
fn reclaim_requires_closed_noncurrent_and_valid_controller_authority() {
    let (s, mut banks) = prepared(1);
    let mut slot = Some(s.stage_prepared_storage(banks.pop().unwrap()).unwrap());
    refuses(&s, &mut slot, StorageReclaimError::NotDrained);
    s.publish(slot.as_ref().unwrap(), FailurePoint::None)
        .unwrap();
    slot.as_ref().unwrap().close();
    refuses(&s, &mut slot, StorageReclaimError::Current);
    s.remove_current().unwrap();
    let (foreign, _) = prepared(1);
    refuses(&foreign, &mut slot, StorageReclaimError::InvalidStorage);
    let bank = s.reclaim_epoch_storage(&mut slot).unwrap();
    assert!(slot.is_none());
    assert_eq!(s.retained_epochs(), 0);
    assert_eq!(
        s.reclaim_epoch_storage(&mut slot).err(),
        Some(StorageReclaimError::InvalidStorage)
    );
    drop(bank);

    let (failed, mut banks) = prepared(1);
    let mut slot = Some(failed.stage_prepared_storage(banks.pop().unwrap()).unwrap());
    assert_eq!(
        failed.publish(slot.as_ref().unwrap(), FailurePoint::AfterMutation),
        Err(ControlError::InjectedAfter)
    );
    refuses(
        &failed,
        &mut slot,
        StorageReclaimError::Control(ControlError::TerminalFailure),
    );
    let (poisoned, mut banks) = prepared(1);
    let mut slot = Some(
        poisoned
            .stage_prepared_storage(banks.pop().unwrap())
            .unwrap(),
    );
    slot.as_ref().unwrap().close();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _guard = poisoned.inner.writer.lock().unwrap();
            panic!("intentional writer poison");
        }))
        .is_err()
    );
    refuses(
        &poisoned,
        &mut slot,
        StorageReclaimError::Control(ControlError::Poisoned),
    );
}

#[test]
fn reclaim_checks_outer_and_nested_strong_and_weak_owners_before_extraction() {
    let (s, mut banks) = prepared(1);
    let mut thread = s.register_thread(1).unwrap();
    let mut slot = Some(s.stage_prepared_storage(banks.pop().unwrap()).unwrap());
    s.publish(slot.as_ref().unwrap(), FailurePoint::None)
        .unwrap();
    let acquired = s.acquire(1, INSTALL).unwrap();
    let mut word = rs(1);
    thread.enter(INSTALL, A, 10, &mut word).unwrap();
    thread.finish(&mut word, Observation::Value(20)).unwrap();
    s.remove_current().unwrap();
    refuses(&s, &mut slot, StorageReclaimError::SharedOwner);
    drop(acquired);
    let report = slot.as_ref().unwrap().try_report().unwrap();
    refuses(&s, &mut slot, StorageReclaimError::SharedOwner);
    drop(report);
    let clone = slot.as_ref().unwrap().clone();
    refuses(&s, &mut slot, StorageReclaimError::SharedOwner);
    drop(clone);
    let weak = Arc::downgrade(&slot.as_ref().unwrap().owner);
    refuses(&s, &mut slot, StorageReclaimError::SharedOwner);
    drop(weak);
    let nested = Arc::clone(&slot.as_ref().unwrap().owner.epoch);
    assert_eq!(Arc::strong_count(&slot.as_ref().unwrap().owner), 1);
    refuses(&s, &mut slot, StorageReclaimError::SharedOwner);
    drop(nested);
    let weak = Arc::downgrade(&slot.as_ref().unwrap().owner.epoch);
    refuses(&s, &mut slot, StorageReclaimError::SharedOwner);
    drop(weak);
    let tail = Arc::get_mut(&mut slot.as_mut().unwrap().owner)
        .unwrap()
        .payloads
        .pop()
        .unwrap();
    refuses(&s, &mut slot, StorageReclaimError::InvalidStorage);
    Arc::get_mut(&mut slot.as_mut().unwrap().owner)
        .unwrap()
        .payloads
        .push(tail);
    let bank = s.reclaim_epoch_storage(&mut slot).unwrap();
    assert!(slot.is_none());
    assert!(bank_view(&bank).clean);
    assert_eq!(s.retained_epochs(), 0);
}

#[test]
fn sampled_and_function_closed_receipts_keep_owners_across_history_drains() {
    let (s, mut banks) = prepared(1);
    let mut thread = s.register_thread(1).unwrap();
    let mut slot = Some(s.stage_prepared_storage(banks.pop().unwrap()).unwrap());
    let generation = slot.as_ref().unwrap().generation();
    s.publish(slot.as_ref().unwrap(), FailurePoint::None)
        .unwrap();
    let mut word = rs(1);
    let mut sampled = thread.enter_interval(INSTALL, A, 10, &mut word).unwrap();
    // An actual outstanding frame/OwnedTicket is not drained, even if closed.
    slot.as_ref().unwrap().close();
    s.remove_current().unwrap();
    refuses(&s, &mut slot, StorageReclaimError::NotDrained);
    let first = s.drain_history().unwrap().unwrap();
    assert_eq!(first.range, 0..2);
    thread
        .finish_interval(&mut sampled, &mut word, Observation::Value(20))
        .unwrap();
    assert_eq!(thread.completed_sequence(), 1);
    let bank = s.reclaim_epoch_storage(&mut slot).unwrap();
    let mut slot = Some(s.stage_prepared_storage(bank).unwrap());
    assert_ne!(slot.as_ref().unwrap().generation(), generation);
    s.publish(slot.as_ref().unwrap(), FailurePoint::None)
        .unwrap();
    let mut sample = thread.enter_interval(INSTALL, A, 30, &mut word).unwrap();
    thread
        .finish_interval(&mut sample, &mut word, Observation::Value(40))
        .unwrap();
    let mut closed = thread.enter_interval(INSTALL, A, 50, &mut word).unwrap();
    let summary = closed.summary().unwrap();
    assert!(matches!(
        summary,
        IntervalEntrySummary::Unsampled {
            reason: UnsampledSummary::FunctionClosed { .. },
            history_len: 3,
            ..
        }
    ));
    s.remove_current().unwrap();
    let report = slot.as_ref().unwrap().try_report().unwrap();
    let rows: Vec<_> = report.records().collect();
    assert_eq!(rows.len(), 1);
    drop(report);
    let second = s.drain_history().unwrap().unwrap();
    assert_eq!(second.range, 2..4);
    refuses(&s, &mut slot, StorageReclaimError::SharedOwner);
    assert_eq!(closed.summary(), Some(summary));
    thread
        .finish_interval(&mut closed, &mut word, Observation::Value(60))
        .unwrap();
    assert_eq!(thread.completed_sequence(), 2);
    let bank = s.reclaim_epoch_storage(&mut slot).unwrap();
    assert_eq!(s.history_committed_end(), 4);
    assert!(s.drain_history().unwrap().is_none());
    assert_eq!(
        s.register_thread(1).err(),
        Some(SetupError::DuplicateThread)
    );
    assert!(bank_view(&bank).clean);
    assert_eq!(rows[0].payload.unwrap().start_sequence, 1);
}

#[test]
fn reuse_preserves_complete_payloads_history_sequences_and_old_id_refusal() {
    let (s, mut banks) = prepared(1);
    let mut bank = banks.pop().unwrap();
    let geometry = bank_view(&bank);
    let mut first = s.register_thread(1).unwrap();
    let mut second = s.register_thread(2).unwrap();
    let mut previous = None;
    for round in 0..3 {
        let _probe = allocation_probe::start(Some(0));
        let mut slot = Some(s.stage_prepared_storage(bank).unwrap());
        let owner = slot.as_ref().unwrap();
        let generation = owner.generation();
        assert_ne!(Some(generation), previous);
        s.publish(owner, FailurePoint::None).unwrap();
        if let Some(stale) = previous {
            let history_before = s.history_window().unwrap();
            assert_eq!(
                s.remove_with_controls(Some(stale), |_| {}),
                Err(ControlError::ForeignEpoch)
            );
            assert_eq!(s.history_window().unwrap(), history_before);
        }
        let mut cancelled = rs(1);
        let mut dropped = rs(2);
        let mut retained = rs(3);
        let mut excess = rs(4);
        first.enter(INSTALL, A, 10, &mut cancelled).unwrap();
        first.cancel(&mut cancelled).unwrap();
        first.enter(INSTALL, A, 11, &mut dropped).unwrap();
        first.cancel_on_unwind(&mut dropped).unwrap();
        first.enter(INSTALL, A, 12, &mut retained).unwrap();
        second.enter(INSTALL, A, 13, &mut excess).unwrap();
        let kept = first.finish(&mut retained, Observation::Value(22)).unwrap();
        let lost = second.finish(&mut excess, Observation::Value(23)).unwrap();
        assert_eq!(kept.0.disposition, Disposition::Retained { rank: 0 });
        assert_eq!(lost.0.disposition, Disposition::DroppedAfterBudget);
        s.remove_current().unwrap();
        let report = owner.try_report().unwrap();
        let copied: Vec<_> = report.records().collect();
        assert_eq!(copied.len(), 4);
        assert_eq!(
            copied[0].record.terminal,
            Some(Terminal::Cancelled(CancelReason::Explicit))
        );
        assert_eq!(
            copied[1].record.terminal,
            Some(Terminal::Cancelled(CancelReason::DroppedTicket))
        );
        for (n, row) in copied.iter().enumerate() {
            assert_eq!(row.record.admission.generation, generation);
            assert_eq!(row.record.admission.invocation, n);
            let payload = row.payload.unwrap();
            assert_eq!(payload.admission, row.record.admission);
            assert_eq!(payload.thread, if n == 3 { 2 } else { 1 });
            assert_eq!(payload.start_sequence, round);
        }
        assert_eq!(
            copied[2].record.terminal,
            Some(Terminal::Completed {
                value: 2,
                disposition: Disposition::Retained { rank: 0 }
            })
        );
        assert_eq!(
            copied[3].record.terminal,
            Some(Terminal::Completed {
                value: 3,
                disposition: Disposition::DroppedAfterBudget
            })
        );
        assert_eq!(
            copied[2].payload.unwrap().outcome,
            PayloadOutcome::Completed {
                end: Observation::Value(22),
                completed_children: 0
            }
        );
        assert_eq!(
            copied[3].payload.unwrap().outcome,
            PayloadOutcome::Completed {
                end: Observation::Value(23),
                completed_children: 0
            }
        );
        drop(report);
        let history = s.drain_history().unwrap().unwrap();
        assert_eq!(history.range, 2 * round..2 * round + 2);
        assert_eq!(
            history.actions.iter().map(|a| a.kind).collect::<Vec<_>>(),
            [ActionKind::Published, ActionKind::Removed]
        );
        bank = s.reclaim_epoch_storage(&mut slot).unwrap();
        assert!(slot.is_none());
        assert_eq!(bank_view(&bank), geometry);
        assert_eq!(s.retained_epochs(), 0);
        assert_eq!(first.completed_sequence(), round + 1);
        assert_eq!(second.completed_sequence(), round + 1);
        assert_eq!(s.history_committed_end(), 2 * round + 2);
        assert_eq!(allocation_probe::calls(), 0);
        previous = Some(generation);
    }
    let mut slot = Some(s.stage_prepared_storage(bank).unwrap());
    let owner = slot.as_ref().unwrap();
    s.publish(owner, FailurePoint::None).unwrap();
    let current = owner.generation();
    s.deactivate(
        DeactivationRequest {
            generation: previous.unwrap(),
            function: A,
        },
        FailurePoint::None,
    )
    .unwrap();
    assert_eq!(owner.owner.epoch.function_closed(A), Some(false));
    let history = s.history_window().unwrap();
    assert_eq!(history.current, Some(current));
    assert_eq!(
        history.chunk.actions.last().unwrap().kind,
        ActionKind::Stale
    );
    assert_eq!(history.chunk.actions.last().unwrap().current, Some(current));
    s.remove_current().unwrap();
    drop(s.reclaim_epoch_storage(&mut slot).unwrap());
    assert_eq!(s.stage(config()).err(), Some(SetupError::StorageMode));
}

#[test]
fn discarded_banks_and_legacy_epochs_cannot_mint_replacement_storage() {
    let (mut s, mut banks) = prepared(2);
    let mut first = Some(s.stage_prepared_storage(banks.pop().unwrap()).unwrap());
    let second = s.stage_prepared_storage(banks.pop().unwrap()).unwrap();
    second.close();
    let report = second.try_report().unwrap();
    drop(second); // Legacy retirement/discard retains its bank through Report.
    assert_eq!(s.retained_epochs(), 2);
    first.as_ref().unwrap().close();
    let bank = s.reclaim_epoch_storage(&mut first).unwrap();
    assert_eq!(s.retained_epochs(), 1);
    drop(bank);
    assert_eq!(
        s.prepare_epoch_storage(config()).err(),
        Some(SetupError::StorageMode)
    );
    assert_eq!(s.stage(config()).err(), Some(SetupError::StorageMode));
    drop(report);
    assert_eq!(s.retained_epochs(), 0);
    assert_eq!(
        s.prepare_epoch_storage(config()).err(),
        Some(SetupError::StorageMode)
    );
    assert_eq!(s.stage(config()).err(), Some(SetupError::StorageMode));
    // A legacy epoch from another Session is not an issued bank.
    let legacy = session(1);
    let mut old = Some(legacy.stage(config()).unwrap());
    old.as_ref().unwrap().close();
    refuses(&s, &mut old, StorageReclaimError::InvalidStorage);
}
