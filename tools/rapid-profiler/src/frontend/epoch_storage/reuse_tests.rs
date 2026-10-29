use super::*;
use crate::generation::{CancelReason, Disposition, Terminal};

const INSTALL: u64 = 83;
const A: FunctionId = FunctionId(21);
const B: FunctionId = FunctionId(22);

fn prepared(e: usize, k: usize) -> (Session, Vec<EpochStorage>) {
    let mut session = Session::new_streaming_history(
        INSTALL,
        &[
            FunctionSpec {
                function: A,
                group: 0,
            },
            FunctionSpec {
                function: B,
                group: 0,
            },
        ],
        &[GroupSpec { mandatory: true }],
        Limits {
            epochs: e,
            threads: 1,
            depth: 1,
            records_per_epoch: 8,
            actions: 16,
        },
    )
    .unwrap();
    let banks = session
        .prepare_epoch_storage(Config {
            retained_per_function: k,
            max_inflight: 2,
            max_invocations: 8,
        })
        .unwrap();
    (session, banks)
}

fn word() -> ModelReturnSlot {
    ModelReturnSlot {
        identity: 7,
        word: 0x1234,
    }
}

fn shells(owner: &Arc<FrontendEpoch>) -> [usize; 2] {
    [
        Arc::as_ptr(owner) as usize,
        Arc::as_ptr(&owner.epoch) as usize,
    ]
}

fn recycled(bank: &EpochStorage) -> &Arc<FrontendEpoch> {
    match &bank.storage {
        Bank::Recycled { owner } => owner,
        Bank::Fresh { .. } => panic!("expected actual reclaimed bank"),
    }
}

fn recycled_mut(bank: &mut EpochStorage) -> &mut Arc<FrontendEpoch> {
    match &mut bank.storage {
        Bank::Recycled { owner } => owner,
        Bank::Fresh { .. } => panic!("expected actual reclaimed bank"),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct OwnerCopy {
    shells: [usize; 2],
    generation: GenerationId,
    config: Config,
    geometry: [(usize, usize, usize); 3],
    records: Vec<RecordObservation>,
    counts: [usize; 4],
    reservations: usize,
    permit: bool,
    active: usize,
    history: history_stream::HistoryView,
}

fn owner_copy(s: &Session, slot: &Option<EpochHandle>) -> OwnerCopy {
    let owner = &slot.as_ref().unwrap().owner;
    let model = storage::epoch_geometry(&owner.epoch);
    OwnerCopy {
        shells: shells(owner),
        generation: owner.epoch.id(),
        config: owner.epoch.config(),
        geometry: [
            model[0],
            model[1],
            (
                owner.payloads.as_ptr() as usize,
                owner.payloads.len(),
                owner.payloads.capacity(),
            ),
        ],
        records: owner.records().collect(),
        counts: [
            Arc::strong_count(owner),
            Arc::weak_count(owner),
            Arc::strong_count(&owner.epoch),
            Arc::weak_count(&owner.epoch),
        ],
        reservations: owner.epoch.reservations(),
        permit: owner._permit.is_some(),
        active: s.retained_epochs(),
        history: s.history_window().unwrap(),
    }
}

fn refuse_reclaim(s: &Session, slot: &mut Option<EpochHandle>) {
    let before = owner_copy(s, slot);
    for _ in 0..2 {
        assert_eq!(
            s.reclaim_epoch_storage(slot).err(),
            Some(StorageReclaimError::SharedOwner)
        );
        assert_eq!(owner_copy(s, slot), before);
    }
}

fn refuse_stage(s: &Session, bank: EpochStorage) -> EpochStorage {
    let before = bank.test_fingerprint();
    let active = s.retained_epochs();
    let history = s.history_window().unwrap();
    let (error, bank) = s.stage_prepared_storage(bank).err().unwrap();
    assert_eq!(error, SetupError::InvalidStorage);
    assert_eq!(bank.test_fingerprint(), before);
    assert_eq!(s.retained_epochs(), active);
    assert_eq!(s.history_window().unwrap(), history);
    bank
}

#[test]
fn recycled_shells_keep_full_partial_empty_populations_and_all_vector_geometry() {
    let _shells = shell_probe::start();
    let (s, mut banks) = prepared(1, 8);
    assert_eq!(shell_probe::calls(), 0);
    let mut bank = banks.pop().unwrap();
    let (model, payloads, _) = bank.test_parts();
    let payload_geometry = (
        payloads.as_ptr() as usize,
        payloads.len(),
        payloads.capacity(),
    );
    let mut thread = s.register_thread(1).unwrap();
    let mut original_shells = None;
    let mut generations = Vec::new();
    let mut copies = Vec::new();
    let mut completed = 0;
    for (round, count) in [8, 3, 0, 8].into_iter().enumerate() {
        let _vectors = storage::allocation_probe::start(Some(0));
        let mut slot = Some(s.stage_prepared_storage(bank).unwrap());
        let owner = slot.as_ref().unwrap();
        let pointers = shells(&owner.owner);
        assert_eq!(*original_shells.get_or_insert(pointers), pointers);
        assert_eq!(shell_probe::calls(), 2);
        assert_eq!(s.retained_epochs(), 1);
        let generation = owner.generation();
        assert!(!generations.contains(&generation));
        generations.push(generation);
        s.publish(owner, FailurePoint::None).unwrap();
        let mut w = word();
        let mut starts = Vec::new();
        for n in 0..count {
            starts.push(thread.completed_sequence());
            thread
                .enter(INSTALL, if n % 2 == 0 { A } else { B }, n as u64, &mut w)
                .unwrap();
            match n % 3 {
                0 => {
                    thread
                        .finish(&mut w, Observation::Value(100 + n as u64))
                        .unwrap();
                    completed += 1;
                }
                1 => {
                    thread.cancel(&mut w).unwrap();
                }
                _ => thread.cancel_on_unwind(&mut w).unwrap(),
            }
            assert_eq!(w, word());
        }
        s.remove_current().unwrap();
        let report = owner.try_report().unwrap();
        let rows: Vec<_> = report.records().collect();
        assert_eq!(rows.len(), count);
        let mut ranks = [0, 0];
        for (n, row) in rows.iter().enumerate() {
            assert_eq!(row.record.admission.generation, generation);
            assert_eq!(
                row.record.admission.function,
                if n % 2 == 0 { A } else { B }
            );
            assert_eq!(row.record.admission.invocation, n);
            let payload = row.payload.unwrap();
            assert_eq!(payload.admission, row.record.admission);
            assert_eq!(payload.start_sequence, starts[n]);
            let terminal = match n % 3 {
                0 => {
                    let rank = ranks[n % 2];
                    ranks[n % 2] += 1;
                    Terminal::Completed {
                        value: n as u64,
                        disposition: Disposition::Retained { rank },
                    }
                }
                1 => Terminal::Cancelled(CancelReason::Explicit),
                _ => Terminal::Cancelled(CancelReason::DroppedTicket),
            };
            assert_eq!(row.record.terminal, Some(terminal));
            if n % 3 == 0 {
                assert_eq!(
                    payload.outcome,
                    PayloadOutcome::Completed {
                        end: Observation::Value(100 + n as u64),
                        completed_children: 0,
                    }
                );
            } else {
                assert_eq!(
                    payload.outcome,
                    PayloadOutcome::Cancelled(if n % 3 == 1 {
                        CancelReason::Explicit
                    } else {
                        CancelReason::DroppedTicket
                    })
                );
            }
        }
        copies.push(rows);
        drop(report);
        let history = s.drain_history().unwrap().unwrap();
        assert_eq!(history.range, 2 * round as u64..2 * round as u64 + 2);
        bank = s.reclaim_epoch_storage(&mut slot).unwrap();
        assert!(slot.is_none());
        let (now_model, payloads, clean) = bank.test_parts();
        assert_eq!(now_model, model);
        assert_eq!(
            (
                payloads.as_ptr() as usize,
                payloads.len(),
                payloads.capacity()
            ),
            payload_geometry
        );
        assert!(clean && payloads.iter().all(|p| p.get().is_none()));
        assert_eq!(shells(recycled(&bank)), pointers);
        assert_eq!(recycled(&bank).epoch.id(), generation);
        assert!(recycled(&bank).epoch.is_closed());
        assert!(recycled(&bank)._permit.is_none());
        assert_eq!(s.retained_epochs(), 0);
        assert_eq!(thread.completed_sequence(), completed);
        assert_eq!(storage::allocation_probe::calls(), 0);
        for (i, saved) in copies.iter().enumerate() {
            assert!(
                saved
                    .iter()
                    .all(|row| row.record.admission.generation == generations[i])
            );
        }
    }
    assert_eq!(shell_probe::calls(), 2);
}

#[test]
fn fresh_and_recycled_owners_refuse_all_four_alias_classes_without_mutation() {
    let _shells = shell_probe::start();
    let (s, mut banks) = prepared(1, 1);
    let mut bank = banks.pop().unwrap();
    let mut thread = s.register_thread(1).unwrap();
    for _ in 0..2 {
        let mut slot = Some(s.stage_prepared_storage(bank).unwrap());
        s.publish(slot.as_ref().unwrap(), FailurePoint::None)
            .unwrap();
        let mut w = word();
        thread.enter(INSTALL, A, 10, &mut w).unwrap();
        thread.finish(&mut w, Observation::Value(20)).unwrap();
        s.remove_current().unwrap();
        let clone = slot.as_ref().unwrap().clone();
        refuse_reclaim(&s, &mut slot);
        drop(clone);
        let weak = Arc::downgrade(&slot.as_ref().unwrap().owner);
        refuse_reclaim(&s, &mut slot);
        drop(weak);
        let nested = Arc::clone(&slot.as_ref().unwrap().owner.epoch);
        refuse_reclaim(&s, &mut slot);
        drop(nested);
        let weak = Arc::downgrade(&slot.as_ref().unwrap().owner.epoch);
        refuse_reclaim(&s, &mut slot);
        drop(weak);
        bank = s.reclaim_epoch_storage(&mut slot).unwrap();
        assert!(slot.is_none());
        assert_eq!(s.retained_epochs(), 0);
    }
    assert_eq!(shell_probe::calls(), 2);
}

#[test]
fn fresh_and_recycled_id_or_permit_exhaustion_returns_the_exact_bank() {
    let _shells = shell_probe::start();
    let (s, mut banks) = prepared(1, 1);
    let mut bank = banks.pop().unwrap();
    for _ in 0..2 {
        for start in [0, u64::MAX] {
            let before = bank.test_fingerprint();
            let staged = s.inner.ever_staged.load(Ordering::Acquire);
            let next = AtomicU64::new(start);
            let (error, returned) = s
                .stage_storage_with(
                    bank,
                    |storage| storage.test_into_epoch_with(&next),
                    |epoch| storage::test_restart_with(epoch, &next),
                )
                .err()
                .unwrap();
            bank = returned;
            assert_eq!(
                error,
                SetupError::Generation(CreateError::GenerationExhausted)
            );
            assert_eq!(bank.test_fingerprint(), before);
            assert_eq!(next.load(Ordering::Acquire), start);
            assert_eq!(s.retained_epochs(), 0);
            assert_eq!(s.inner.ever_staged.load(Ordering::Acquire), staged);
        }
        let before = bank.test_fingerprint();
        let permit = s.inner.pool.reserve().unwrap();
        let next = AtomicU64::new(37);
        let (error, returned) = s
            .stage_storage_with(
                bank,
                |storage| storage.test_into_epoch_with(&next),
                |epoch| storage::test_restart_with(epoch, &next),
            )
            .err()
            .unwrap();
        bank = returned;
        assert_eq!(error, SetupError::EpochLimit);
        assert_eq!(bank.test_fingerprint(), before);
        assert_eq!(next.load(Ordering::Acquire), 37);
        assert_eq!(s.retained_epochs(), 1);
        drop(permit);
        let mut slot = Some(s.stage_prepared_storage(bank).unwrap());
        slot.as_ref().unwrap().close();
        bank = s.reclaim_epoch_storage(&mut slot).unwrap();
        assert_eq!(s.retained_epochs(), 0);
    }
    assert_eq!(shell_probe::calls(), 2);
}

#[test]
fn recycled_stage_refuses_aliases_and_private_identity_or_permit_drift() {
    let (s, mut banks) = prepared(1, 1);
    let mut slot = Some(s.stage_prepared_storage(banks.pop().unwrap()).unwrap());
    slot.as_ref().unwrap().close();
    let mut bank = s.reclaim_epoch_storage(&mut slot).unwrap();
    let (foreign, _) = prepared(1, 1);
    Arc::get_mut(recycled_mut(&mut bank)).unwrap().spec = Arc::clone(&foreign.inner.spec);
    bank = refuse_stage(&s, bank);
    Arc::get_mut(recycled_mut(&mut bank)).unwrap().spec = Arc::clone(&s.inner.spec);
    let clone = Arc::clone(recycled(&bank));
    bank = refuse_stage(&s, bank);
    drop(clone);
    let weak = Arc::downgrade(recycled(&bank));
    bank = refuse_stage(&s, bank);
    drop(weak);
    let nested = Arc::clone(&recycled(&bank).epoch);
    bank = refuse_stage(&s, bank);
    drop(nested);
    let weak = Arc::downgrade(&recycled(&bank).epoch);
    bank = refuse_stage(&s, bank);
    drop(weak);
    bank.index = 1;
    bank = refuse_stage(&s, bank);
    bank.index = 0;
    bank.config.retained_per_function = 2;
    bank = refuse_stage(&s, bank);
    bank.config.retained_per_function = 1;
    let tail = bank.test_payloads_mut().pop().unwrap();
    bank = refuse_stage(&s, bank);
    bank.test_payloads_mut().push(tail);
    Arc::get_mut(recycled_mut(&mut bank)).unwrap().storage_bank = None;
    bank = refuse_stage(&s, bank);
    Arc::get_mut(recycled_mut(&mut bank)).unwrap().storage_bank = Some(0);
    Arc::get_mut(recycled_mut(&mut bank)).unwrap()._permit = Some(s.inner.pool.reserve().unwrap());
    bank = refuse_stage(&s, bank);
    let permit = Arc::get_mut(recycled_mut(&mut bank))
        .unwrap()
        ._permit
        .take()
        .unwrap();
    drop(permit);
    assert_eq!(s.retained_epochs(), 0);
    // Private corruption controls use the actual restart/admission helpers and
    // a local ID allocator; no fake owner, permit, ticket or publication is made.
    let next = AtomicU64::new(41);
    {
        let owner = Arc::get_mut(recycled_mut(&mut bank)).unwrap();
        storage::test_restart_with(Arc::get_mut(&mut owner.epoch).unwrap(), &next).unwrap();
    }
    bank = refuse_stage(&s, bank); // Open even though there are no reservations.
    let ticket = recycled(&bank).epoch.enter_owned(A, 70).unwrap();
    ticket.complete(71);
    recycled(&bank).epoch.close();
    bank = refuse_stage(&s, bank); // Closed+zero, but assigned storage was not reset.
    {
        let owner = Arc::get_mut(recycled_mut(&mut bank)).unwrap();
        storage::reset_recycled(Arc::get_mut(&mut owner.epoch).unwrap());
    }
    let mut slot = Some(s.stage_prepared_storage(bank).unwrap());
    slot.as_ref().unwrap().close();
    assert!(s.reclaim_epoch_storage(&mut slot).is_ok());
}

#[test]
fn closed_receipt_and_stale_generation_cannot_follow_reused_shells() {
    let (s, mut banks) = prepared(1, 1);
    let mut thread = s.register_thread(1).unwrap();
    let mut slot = Some(s.stage_prepared_storage(banks.pop().unwrap()).unwrap());
    let original = shells(&slot.as_ref().unwrap().owner);
    let old = slot.as_ref().unwrap().generation();
    s.publish(slot.as_ref().unwrap(), FailurePoint::None)
        .unwrap();
    let mut w = word();
    for function in [A, B] {
        let mut receipt = thread
            .enter_interval(INSTALL, function, 10, &mut w)
            .unwrap();
        thread
            .finish_interval(&mut receipt, &mut w, Observation::Value(20))
            .unwrap();
    }
    let mut closed = thread.enter_interval(INSTALL, A, 30, &mut w).unwrap();
    let summary = closed.summary();
    assert!(matches!(summary, Some(IntervalEntrySummary::Unsampled {
        reason: UnsampledSummary::FunctionClosed { generation, function }, ..
    }) if generation == old && function == A));
    s.remove_current().unwrap();
    let report = slot.as_ref().unwrap().try_report().unwrap();
    let saved: Vec<_> = report.records().collect();
    assert_eq!(saved.len(), 2);
    drop(report);
    refuse_reclaim(&s, &mut slot);
    assert_eq!(closed.summary(), summary);
    assert_eq!(thread.completed_sequence(), 2);
    thread
        .finish_interval(&mut closed, &mut w, Observation::Value(40))
        .unwrap();
    assert_eq!(thread.completed_sequence(), 2);
    let bank = s.reclaim_epoch_storage(&mut slot).unwrap();
    let first = s.drain_history().unwrap().unwrap();
    assert_eq!(first.range, 0..2);
    slot = Some(s.stage_prepared_storage(bank).unwrap());
    assert_eq!(shells(&slot.as_ref().unwrap().owner), original);
    let fresh = slot.as_ref().unwrap().generation();
    assert_ne!(fresh, old);
    s.publish(slot.as_ref().unwrap(), FailurePoint::None)
        .unwrap();
    let before = s.history_window().unwrap();
    assert_eq!(
        s.remove_with_controls(Some(old), |_| {}),
        Err(ControlError::ForeignEpoch)
    );
    assert_eq!(s.history_window().unwrap(), before);
    s.deactivate(
        DeactivationRequest {
            generation: old,
            function: A,
        },
        FailurePoint::None,
    )
    .unwrap();
    assert_eq!(
        slot.as_ref().unwrap().owner.epoch.function_closed(A),
        Some(false)
    );
    for function in [A, B] {
        thread.enter(INSTALL, function, 50, &mut w).unwrap();
        let (completion, payload) = thread.finish(&mut w, Observation::Value(60)).unwrap();
        assert_eq!(completion.admission.generation, fresh);
        assert_eq!(completion.disposition, Disposition::Retained { rank: 0 });
        assert_eq!(payload.start_sequence, 2 + u64::from(function == B));
    }
    assert_eq!(thread.completed_sequence(), 4);
    assert!(
        saved
            .iter()
            .all(|row| row.record.admission.generation == old)
    );
    s.remove_current().unwrap();
    assert_eq!(s.drain_history().unwrap().unwrap().range, 2..5);
    assert!(s.reclaim_epoch_storage(&mut slot).is_ok());
}

#[test]
fn idle_drop_forget_and_old_report_owners_never_mint_replacement_banks() {
    let _shells = shell_probe::start();
    let (mut s, mut banks) = prepared(3, 1);
    let mut slot = Some(s.stage_prepared_storage(banks.pop().unwrap()).unwrap());
    slot.as_ref().unwrap().close();
    let dropped = s.reclaim_epoch_storage(&mut slot).unwrap();
    let weak = Arc::downgrade(recycled(&dropped));
    drop(dropped);
    assert!(weak.upgrade().is_none());
    drop(weak);
    slot = Some(s.stage_prepared_storage(banks.pop().unwrap()).unwrap());
    slot.as_ref().unwrap().close();
    let forgotten = s.reclaim_epoch_storage(&mut slot).unwrap();
    std::mem::forget(forgotten); // A lost bank leaks bounded storage, not a live permit.
    assert_eq!(s.retained_epochs(), 0);
    let owner = s.stage_prepared_storage(banks.pop().unwrap()).unwrap();
    owner.close();
    let report = owner.try_report().unwrap();
    let generation = owner.generation();
    drop(owner);
    assert_eq!(s.retained_epochs(), 1);
    assert_eq!(report.generation(), generation);
    assert_eq!(report.records().count(), 0);
    assert!(banks.is_empty());
    let config = Config {
        retained_per_function: 1,
        max_inflight: 2,
        max_invocations: 8,
    };
    assert_eq!(
        s.prepare_epoch_storage(config).err(),
        Some(SetupError::StorageMode)
    );
    assert_eq!(s.stage(config).err(), Some(SetupError::StorageMode));
    drop(report);
    assert_eq!(s.retained_epochs(), 0);
    assert_eq!(
        s.prepare_epoch_storage(config).err(),
        Some(SetupError::StorageMode)
    );
    assert_eq!(s.stage(config).err(), Some(SetupError::StorageMode));
    assert_eq!(shell_probe::calls(), 6);
}
