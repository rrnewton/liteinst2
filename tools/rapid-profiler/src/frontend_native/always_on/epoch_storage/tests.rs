//! Real metadata ownership controls only. Synthetic sites/slots grant no native
//! CALL/RET, fork, source, publication, checkpoint or executable-drain evidence.
use super::*;
use crate::frontend::{ActionKind, PayloadOutcome, RecordObservation};
use crate::generation::{Disposition, Terminal};

const INSTALL: u64 = 71;
const FUNCTION: FunctionId = FunctionId(11);
fn config() -> Config {
    Config {
        retained_per_function: 1,
        max_inflight: 2,
        max_invocations: 4,
    }
}
fn prepared(two: bool, absolute: bool, epochs: usize) -> PreparedIntervalController {
    let limits = Limits {
        epochs,
        threads: if two { 2 } else { 1 },
        depth: 1,
        records_per_epoch: 4,
        actions: 4,
    };
    let constructor = if absolute {
        PreparedIntervalController::new_streaming_history
    } else {
        PreparedIntervalController::new
    };
    constructor(site::synthetic_normal_site(two), INSTALL, FUNCTION, limits).unwrap()
}
fn fixture(epochs: usize) -> (IntervalController, Vec<IntervalEpochStorage>) {
    let mut p = prepared(false, true, epochs);
    let banks = prepare(&mut p, config()).unwrap();
    // SAFETY: synthetic metadata only; no fork/publication/native callback or TLS.
    let (controller, client) = unsafe { p.activate_concurrent() }.unwrap();
    drop(client);
    (controller, banks)
}
#[derive(Debug, Eq, PartialEq)]
struct Slot {
    generation: GenerationId,
    reservations: usize,
    ready: bool,
    rows: Vec<RecordObservation>,
}
#[derive(Debug, Eq, PartialEq)]
struct View {
    snapshot: Result<ControllerSnapshot, ControlError>,
    slots: Vec<Option<Slot>>,
    retained: usize,
}
fn view(c: &IntervalController) -> View {
    View {
        snapshot: c.binding.session.snapshot_for_bridge(),
        slots: c
            .epochs
            .iter()
            .map(|owner| {
                owner.as_ref().map(|owner| Slot {
                    generation: owner.generation(),
                    reservations: owner.reservations(),
                    ready: owner.try_report().is_some(),
                    rows: owner.records().collect(),
                })
            })
            .collect(),
        retained: c.binding.session.retained_epochs(),
    }
}
fn token_key(e: &IntervalEpoch) -> (*const (), usize, GenerationId) {
    (Arc::as_ptr(&e.key), e.index, e.generation())
}
fn stage_refused(
    c: &mut IntervalController,
    bank: IntervalEpochStorage,
    cause: Cause,
) -> IntervalEpochStorage {
    let before = view(c);
    let key = Arc::as_ptr(&bank.key);
    let (failure, bank) = match c.stage_prepared(bank) {
        Err(pair) => pair,
        Ok(_) => panic!("stage accepted"),
    };
    assert_eq!(failure, error(cause));
    assert_eq!(Arc::as_ptr(&bank.key), key);
    assert_eq!(view(c), before);
    bank
}
fn refused(
    c: &mut IntervalController,
    epoch: IntervalEpoch,
    failure: EpochStorageReclaimError,
) -> IntervalEpoch {
    let before = view(c);
    let identity = token_key(&epoch);
    let (actual, epoch) = match c.reclaim_storage(epoch) {
        Err(pair) => pair,
        Ok(_) => panic!("reclaim accepted"),
    };
    assert_eq!(actual, failure);
    assert_eq!(token_key(&epoch), identity);
    assert_eq!(view(c), before);
    epoch
}
fn reclaim(c: &mut IntervalController, epoch: IntervalEpoch) -> IntervalEpochStorage {
    match c.reclaim_storage(epoch) {
        Ok(bank) => bank,
        Err((e, _)) => panic!("reclaim refused: {e:?}"),
    }
}
fn bridge(cause: Cause) -> EpochStorageReclaimError {
    EpochStorageReclaimError::Bridge(error(cause))
}
fn enter(model: &mut ThreadModel, value: u64) -> (IntervalEntry, ModelReturnSlot) {
    let mut slot = ModelReturnSlot {
        identity: 0x8000,
        word: 0x2005,
    };
    let entry = model
        .enter_interval(INSTALL, FUNCTION, value, &mut slot)
        .unwrap();
    (entry, slot)
}
fn finish(
    model: &mut ThreadModel,
    entry: &mut IntervalEntry,
    slot: &mut ModelReturnSlot,
    value: u64,
) {
    model
        .finish_interval(entry, slot, Observation::Value(value))
        .unwrap();
    assert_eq!(
        *slot,
        ModelReturnSlot {
            identity: 0x8000,
            word: 0x2005
        }
    );
}

#[test]
fn preparation_requires_pristine_absolute_normal_profile_and_commits_once() {
    for two in [false, true] {
        let mut p = prepared(two, false, 2);
        assert!(matches!(
            prepare(&mut p, config()),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::StorageMode)
            })
        ));
        assert!(p.stage(config()).is_ok()); // Refused preparation did not enter banked mode.
        let mut p = prepared(two, true, 2);
        let mut invalid = config();
        invalid.max_invocations = 5;
        assert!(matches!(
            prepare(&mut p, invalid),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::InvalidLimits)
            })
        ));
        let banks = prepare(&mut p, config()).unwrap();
        assert_eq!(banks.len(), 2);
        assert_eq!(p.session.retained_epochs(), 0);
        assert!(p.epochs.is_empty());
        assert!(matches!(
            prepare(&mut p, config()),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::StorageMode)
            })
        ));
        assert!(matches!(
            p.stage(config()),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::StorageMode)
            })
        ));
        let mut used = prepared(two, true, 2);
        used.stage(config()).unwrap();
        assert!(matches!(
            prepare(&mut used, config()),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::InvalidStorage)
            })
        ));
        let mut registered = prepared(two, true, 2);
        let model = registered.session.register_thread(7).unwrap();
        assert!(matches!(
            prepare(&mut registered, config()),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::InvalidStorage)
            })
        ));
        drop(model);
        assert!(matches!(
            prepare(&mut registered, config()),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::InvalidStorage)
            })
        ));
    }
    let mut wrong = prepared(false, true, 1);
    wrong.profile = BindingProfile::Single {
        site: site::synthetic_site().site,
        function: wrong.profile.single().unwrap().1,
    };
    assert!(matches!(
        prepare(&mut wrong, config()),
        Err(BridgeError {
            cause: Cause::Identity
        })
    ));
    let mut p = prepared(false, true, 1);
    {
        let _scope = ControllerScope::enter().unwrap();
        assert!(matches!(
            prepare(&mut p, config()),
            Err(BridgeError {
                cause: Cause::ControllerReentry
            })
        ));
        assert!(CONTROLLER_ACTIVE.get());
    }
    assert_eq!(prepare(&mut p, config()).unwrap().len(), 1);
}

#[test]
fn prepared_stage_returns_bank_on_identity_process_scope_and_capacity_refusal() {
    let (mut c, mut banks) = fixture(1);
    let (mut foreign, _) = fixture(1);
    let mut bank = stage_refused(&mut foreign, banks.pop().unwrap(), Cause::Epoch);
    Arc::get_mut(&mut c.binding).unwrap().pid ^= 1;
    bank = stage_refused(&mut c, bank, Cause::Process);
    Arc::get_mut(&mut c.binding).unwrap().pid ^= 1;
    {
        let _scope = ControllerScope::enter().unwrap();
        bank = stage_refused(&mut c, bank, Cause::ControllerReentry);
        assert!(CONTROLLER_ACTIVE.get());
    }
    // Private corruption probe: no valid E-bank population can have both a spare
    // bank and E occupied slots. Exercise the actual facade bound nonetheless.
    Arc::get_mut(&mut c.binding).unwrap().limits.epochs = 0;
    bank = stage_refused(&mut c, bank, Cause::Capacity);
    Arc::get_mut(&mut c.binding).unwrap().limits.epochs = 1;
    let e = c.stage_prepared(bank).unwrap();
    assert_eq!(c.binding.session.retained_epochs(), 1);
    c.arm(&e).unwrap();
    c.disarm(&e).unwrap();
    drop(reclaim(&mut c, e));
    assert_eq!(c.binding.session.retained_epochs(), 0);
}

#[test]
fn reclaim_authenticates_token_process_scope_and_stale_generation_without_mutation() {
    let (mut c, mut banks) = fixture(2);
    let mut e = c.stage_prepared(banks.pop().unwrap()).unwrap();
    let other = c.stage_prepared(banks.pop().unwrap()).unwrap();
    c.arm(&e).unwrap();
    c.disarm(&e).unwrap();
    for bad in [
        IntervalEpoch {
            key: Arc::new(()),
            index: e.index,
            generation: e.generation,
        },
        IntervalEpoch {
            key: Arc::clone(&e.key),
            index: usize::MAX,
            generation: e.generation,
        },
        IntervalEpoch {
            key: Arc::clone(&e.key),
            index: e.index,
            generation: other.generation,
        },
    ] {
        drop(refused(&mut c, bad, bridge(Cause::Epoch)));
    }
    Arc::get_mut(&mut c.binding).unwrap().pid ^= 1;
    e = refused(&mut c, e, bridge(Cause::Process));
    Arc::get_mut(&mut c.binding).unwrap().pid ^= 1;
    {
        let _scope = ControllerScope::enter().unwrap();
        e = refused(&mut c, e, bridge(Cause::ControllerReentry));
        assert!(CONTROLLER_ACTIVE.get());
    }
    let stale = IntervalEpoch {
        key: Arc::clone(&e.key),
        index: e.index,
        generation: e.generation,
    };
    let bank = reclaim(&mut c, e);
    let fresh = c.stage_prepared(bank).unwrap();
    assert_eq!(fresh.index, stale.index);
    assert_ne!(fresh.generation(), stale.generation());
    drop(refused(&mut c, stale, bridge(Cause::Epoch)));
}

#[test]
fn reclaim_refuses_open_current_and_outstanding_before_unique_storage_transfer() {
    let (mut c, mut banks) = fixture(1);
    let mut e = c.stage_prepared(banks.pop().unwrap()).unwrap();
    e = refused(&mut c, e, bridge(Cause::NotDrained));
    c.arm(&e).unwrap();
    e = refused(&mut c, e, bridge(Cause::CurrentEpoch));
    let mut model = c.binding.session.register_thread(7).unwrap();
    let (mut entry, mut slot) = enter(&mut model, 1);
    c.disarm(&e).unwrap();
    e = refused(&mut c, e, bridge(Cause::NotDrained));
    finish(&mut model, &mut entry, &mut slot, 9);
    assert_eq!(model.completed_sequence(), 1);
    drop(reclaim(&mut c, e));
    assert_eq!(c.binding.session.retained_epochs(), 0);
}

#[test]
fn report_and_acquired_owners_refuse_reclamation_until_each_is_released() {
    let (mut c, mut banks) = fixture(1);
    let mut e = c.stage_prepared(banks.pop().unwrap()).unwrap();
    c.arm(&e).unwrap();
    let mut model = c.binding.session.register_thread(7).unwrap();
    let acquired = c.binding.session.acquire(7, INSTALL).unwrap();
    let (mut entry, mut slot) = enter(&mut model, 1);
    finish(&mut model, &mut entry, &mut slot, 9);
    c.disarm(&e).unwrap();
    let report = c.report(&e).unwrap().unwrap();
    let copied: Vec<_> = report.records().collect();
    e = refused(&mut c, e, EpochStorageReclaimError::SharedOwner);
    drop(report);
    e = refused(&mut c, e, EpochStorageReclaimError::SharedOwner);
    drop(acquired);
    let bank = reclaim(&mut c, e);
    assert_eq!(copied.len(), 1);
    assert_eq!(
        copied[0].record.terminal,
        Some(Terminal::Completed {
            value: 0,
            disposition: Disposition::Retained { rank: 0 }
        })
    );
    let fresh = c.stage_prepared(bank).unwrap();
    assert_eq!(c.owner(&fresh).unwrap().records().count(), 0);
    assert_eq!(
        copied[0].payload.unwrap().outcome,
        PayloadOutcome::Completed {
            end: Observation::Value(9),
            completed_children: 0
        }
    );
}

#[test]
fn function_closed_receipt_keeps_exclusive_reclaim_blocked_after_report_drop() {
    let (mut c, mut banks) = fixture(1);
    let mut e = c.stage_prepared(banks.pop().unwrap()).unwrap();
    c.arm(&e).unwrap();
    let mut model = c.binding.session.register_thread(7).unwrap();
    let (mut first, mut first_slot) = enter(&mut model, 1);
    finish(&mut model, &mut first, &mut first_slot, 9);
    let (mut closed, mut slot) = enter(&mut model, 2);
    assert!(
        matches!(closed.summary(), Some(IntervalEntrySummary::Unsampled {
        reason: UnsampledSummary::FunctionClosed { generation, function: FUNCTION }, ..
    }) if generation == e.generation())
    );
    assert_eq!(c.owner(&e).unwrap().reservations(), 0);
    c.disarm(&e).unwrap();
    let report = c.report(&e).unwrap().unwrap();
    assert_eq!(report.records().count(), 1);
    drop(report);
    e = refused(&mut c, e, EpochStorageReclaimError::SharedOwner);
    finish(&mut model, &mut closed, &mut slot, 10);
    assert_eq!(model.completed_sequence(), 1); // Unsampled completion is not a sample.
    drop(reclaim(&mut c, e));
    assert_eq!(c.binding.session.retained_epochs(), 0);
}

#[test]
fn terminal_or_poisoned_controller_refuses_reclaim_without_removing_owner() {
    for poisoned in [false, true] {
        let (mut c, mut banks) = fixture(2);
        let old = c.stage_prepared(banks.pop().unwrap()).unwrap();
        let next = c.stage_prepared(banks.pop().unwrap()).unwrap();
        c.arm(&old).unwrap();
        c.disarm(&old).unwrap();
        let owner = c.owner(&next).unwrap().clone();
        let cause = if poisoned {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                c.binding
                    .session
                    .publish_with_controls(&owner, FailurePoint::None, |_| {
                        panic!("required epoch-storage writer-poison control");
                    })
                    .unwrap();
            }));
            assert!(result.is_err());
            ControlError::Poisoned
        } else {
            assert_eq!(
                c.binding
                    .session
                    .publish(&owner, FailurePoint::AfterMutation),
                Err(ControlError::InjectedAfter)
            );
            ControlError::TerminalFailure
        };
        drop(refused(&mut c, old, bridge(Cause::Control(cause))));
    }
}

#[test]
fn reused_banks_preserve_absolute_history_registration_and_completion_sequence() {
    let (mut c, mut banks) = fixture(1);
    let mut bank = banks.pop().unwrap();
    let mut model = c.binding.session.register_thread(7).unwrap();
    let mut previous_generation = 0;
    let mut chunks: Vec<HistoryBatch> = Vec::new();
    let mut copied = Vec::new();
    for i in 0..6_u64 {
        let e = c.stage_prepared(bank).unwrap();
        assert_eq!(e.index, 0);
        assert!(e.generation().get() > previous_generation);
        previous_generation = e.generation().get();
        c.arm(&e).unwrap();
        let (mut entry, mut slot) = enter(&mut model, i + 1);
        assert!(
            matches!(entry.summary(), Some(IntervalEntrySummary::Admitted { history_len, invocation: 0, .. }) if history_len == (2 * i + 1) as usize)
        );
        finish(&mut model, &mut entry, &mut slot, i + 10);
        c.disarm(&e).unwrap();
        let report = c.report(&e).unwrap().unwrap();
        let rows: Vec<_> = report.records().collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record.admission.generation, e.generation());
        assert_eq!(rows[0].payload.unwrap().start_sequence, i);
        copied.extend(rows);
        drop(report);
        bank = reclaim(&mut c, e);
        assert_eq!(c.binding.session.retained_epochs(), 0);
        assert_eq!(
            (model.identity(), model.depth(), model.completed_sequence()),
            (7, 0, i + 1)
        );
        let chunk = c.drain_history().unwrap().unwrap();
        assert_eq!(chunk.range(), 2 * i..2 * i + 2);
        assert_eq!(chunk.number(), i + 1);
        assert_eq!(chunk.actions().len(), 2);
        assert_eq!(
            (chunk.actions()[0].kind, chunk.actions()[1].kind),
            (ActionKind::Published, ActionKind::Removed)
        );
        assert_eq!(chunk.actions()[0].generation.get(), previous_generation);
        if let Some(previous) = chunks.last() {
            assert!(chunk.follows(previous));
        }
        chunks.push(chunk);
    }
    assert_eq!(copied.len(), 6);
    assert_eq!(c.history_window().unwrap().range(), 12..12);
    drop(bank);
}

#[test]
fn dropping_bank_or_legacy_retirement_does_not_refill_fixed_storage() {
    for retire in [false, true] {
        let (mut c, mut banks) = fixture(1);
        let bank = banks.pop().unwrap();
        if retire {
            let e = c.stage_prepared(bank).unwrap();
            c.arm(&e).unwrap();
            c.disarm(&e).unwrap();
            let report = c.retire(&e).unwrap();
            drop(refused(&mut c, e, bridge(Cause::Epoch)));
            drop(report);
        } else {
            drop(bank);
        }
        assert_eq!(c.binding.session.retained_epochs(), 0);
        let before = view(&c);
        assert!(matches!(
            c.stage(config()),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::StorageMode)
            })
        ));
        assert_eq!(view(&c), before);
    }
}
