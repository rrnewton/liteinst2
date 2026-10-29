//! Pure production-helper controls; no native return or executable publication.
use super::super::session::tests::{ENTRY, Fixture, IDS, controller, reclaim};
use super::*;
use crate::frontend::ActionKind;
use liteinst2::contracts::SourceIdentity;

fn copy(batch: &NormalModuleHistoryBatch) -> NormalModuleHistoryBatch {
    NormalModuleHistoryBatch {
        stream: batch.stream.clone(),
        chunk: HistoryChunk {
            range: batch.chunk.range.clone(),
            number: batch.chunk.number,
            before: batch.chunk.before,
            after: batch.chunk.after,
            actions: batch.chunk.actions.clone(),
        },
    }
}
fn cycle(
    c: &mut NormalModuleSessionController,
    bank: IntervalEpochStorage,
) -> (IntervalEpochStorage, NormalModuleHistoryBatch) {
    let e = c.stage_prepared(bank).unwrap();
    c.arm(&e).unwrap();
    c.disarm(&e).unwrap();
    let report = c.report(&e).unwrap().unwrap();
    assert_eq!(report.records().count(), 0);
    drop(report);
    let bank = reclaim(c, e);
    (bank, c.drain_history().unwrap().unwrap())
}

#[test]
fn module_history_stream_joins_key_pid_install_code_functions_and_entries() {
    let (mut c, mut banks) = controller(10);
    let original = stream_for(&c.0.binding).unwrap();
    assert_eq!(original.pid(), c.0.binding.pid);
    assert_eq!(original.install(), 71);
    assert_eq!(original.functions(), &IDS);
    assert_eq!(original.entries(), &ENTRY);
    assert_eq!(original.format(), HistoryFormat::AbsoluteV1);
    assert_eq!(original, original.clone());
    for field in 0..10 {
        let mut bad = original.clone();
        match field {
            0 => bad.key = Arc::new(()),
            1 => bad.pid ^= 1,
            2 => bad.install ^= 1,
            3 => bad.identity.source = SourceIdentity([0; 32]),
            4 => bad.identity.mapping += 1,
            5 => bad.identity.generation += 1,
            6 => bad.functions[0] = FunctionId(99),
            7 => bad.functions[1] = FunctionId(99),
            8 => bad.entries[0] += 1,
            9 => bad.entries[1] += 1,
            _ => unreachable!(),
        }
        assert_ne!(original, bad);
    }
    let e = c.stage_prepared(banks.pop().unwrap()).unwrap();
    c.arm(&e).unwrap();
    c.disarm(&e).unwrap();
    let retained = [original.clone(), original.clone()];
    let bank = reclaim(&mut c, e); // Stream clones do not hold either epoch Arc.
    assert_eq!(c.0.binding.session.retained_epochs(), 0);
    assert!(retained.iter().all(|s| s == &original));
    drop(bank);
}

#[test]
fn module_history_chain_refuses_foreign_missing_duplicate_reordered_chunks() {
    let (mut c, mut banks) = controller(10);
    let (bank, first) = cycle(&mut c, banks.pop().unwrap());
    let (_, second) = cycle(&mut c, bank);
    assert!(second.follows(&first));
    assert!(!first.follows(&second));
    assert!(!first.follows(&first));
    assert_eq!(first.number(), 1);
    assert_eq!(first.range(), 0..2);
    assert_eq!(first.before(), HistoryBinding::Initial);
    for mutate in 0..5 {
        let mut bad = copy(&second);
        match mutate {
            0 => bad.stream.key = Arc::new(()),
            1 => bad.chunk.number += 1,
            2 => bad.chunk.range.start += 1,
            3 => bad.chunk.before = HistoryBinding::Initial,
            4 => bad.stream.functions.swap(0, 1),
            _ => unreachable!(),
        }
        assert!(!bad.follows(&first));
    }
    assert_eq!(first.binding_at(0), Some(HistoryBinding::Initial));
    assert_eq!(
        first.binding_at(1),
        Some(HistoryBinding::Published {
            action_index: 0,
            generation: first.actions()[0].generation
        })
    );
    assert_eq!(first.binding_at(2), Some(first.after()));
    assert_eq!(first.binding_at(3), None);
    let mut bad = copy(&first);
    bad.chunk.range.end += 1;
    assert_eq!(bad.binding_at(1), None);
    let mut bad = copy(&first);
    bad.chunk.actions[0].current = None;
    assert_eq!(bad.binding_at(1), None);
    let mut bad = copy(&first);
    bad.chunk.actions[0].function = Some(IDS[1]);
    assert_eq!(bad.binding_at(1), None);
    let mut bad = copy(&first);
    bad.chunk.actions[0].kind = ActionKind::FailedAfter;
    assert_eq!(bad.binding_at(1), None);
}

#[test]
fn module_history_replays_saved_owner_after_512_actions() {
    for closed in [false, true] {
        let mut f = Fixture::new(10);
        if closed {
            for _ in 0..10 {
                f.call(0);
            }
        }
        f.call(0);
        let old = f.epoch.take().unwrap();
        let old_generation = old.generation();
        f.controller.disarm(&old).unwrap();
        let mut chunks = vec![f.controller.drain_history().unwrap().unwrap()];
        let mut bank = f.banks.pop().unwrap();
        for _ in 0..260 {
            let (returned, chunk) = cycle(&mut f.controller, bank);
            assert!(chunk.follows(chunks.last().unwrap()));
            chunks.push(chunk);
            bank = returned;
        }
        assert_eq!(chunks.last().unwrap().range().end, 522);
        assert_eq!(f.state.binding.session.history_committed_end(), 522);
        f.enter(1); // Confirms saved function0 under its original prefix, not current state.
        let report = f.controller.report(&old).unwrap().unwrap();
        assert_eq!(report.records().count(), if closed { 10 } else { 1 });
        drop(report);
        let old_bank = reclaim(&mut f.controller, old);
        f.observe(1);
        let batch = f.transfer();
        assert_eq!(batch.history_high_water(), Some(522));
        assert_eq!(batch.history_stream(), Some(chunks[0].stream()));
        let saved = &batch.records()[batch.records().len() - 2];
        assert_eq!(saved.function, IDS[0]);
        assert_eq!(saved.record.history_prefix, 1);
        assert_eq!(
            chunks[0].binding_at(1),
            Some(HistoryBinding::Published {
                action_index: 0,
                generation: old_generation
            })
        );
        if closed {
            assert_eq!(
                saved.record.raw.owner,
                RawIntervalOwner::FunctionClosed {
                    generation: old_generation.get()
                }
            );
        } else {
            assert_eq!(
                saved.record.raw.owner,
                RawIntervalOwner::Sampled {
                    generation: old_generation.get(),
                    invocation: 0
                }
            );
        }
        let last = batch.records().last().unwrap();
        assert_eq!(last.function, IDS[1]);
        assert_eq!(last.record.history_prefix, 522);
        assert!(matches!(
            last.record.raw.owner,
            RawIntervalOwner::Removed { .. }
        ));
        assert_eq!(f.controller.history_window().unwrap().range(), 522..522);
        assert_eq!(f.state.binding.session.retained_epochs(), 0);
        drop((bank, old_bank));
    }
}

#[test]
fn module_history_drain_allocation_failure_is_atomic_and_window_is_qualified() {
    let (mut c, mut banks) = controller(10);
    let e = c.stage_prepared(banks.pop().unwrap()).unwrap();
    c.arm(&e).unwrap();
    let before = c.history_window().unwrap();
    c.0.binding.session.test_history_reserve_failure(true);
    let refused = c.drain_history();
    let window_refused = c.history_window();
    c.0.binding.session.test_history_reserve_failure(false);
    assert!(matches!(
        refused,
        Err(BridgeError {
            cause: Cause::Control(ControlError::HistoryAllocation)
        })
    ));
    assert!(matches!(
        window_refused,
        Err(BridgeError {
            cause: Cause::Control(ControlError::HistoryAllocation)
        })
    ));
    assert_eq!(c.history_window().unwrap(), before);
    let first = c.drain_history().unwrap().unwrap();
    assert_eq!(first.number(), 1);
    assert_eq!(first.range(), 0..1);
    let window = c.history_window().unwrap();
    assert_eq!(window.range(), 1..1);
    assert_eq!(window.last_batch_number(), 1);
    assert_eq!(window.before(), first.after());
    assert_eq!(window.current(), Some(e.generation()));
    assert_eq!(window.enabled(), &[true]);
    assert_eq!(window.retained_failed_generation(), None);
    assert_eq!(window.status(), ControllerStatus::Ready);
    assert!(window.actions().is_empty());
    assert!(c.drain_history().unwrap().is_none());
    let next = c.stage_prepared(banks.pop().unwrap()).unwrap();
    let owner = c.0.owner(&next).unwrap().clone();
    assert_eq!(
        c.0.binding
            .session
            .publish(&owner, FailurePoint::AfterMutation),
        Err(ControlError::InjectedAfter)
    );
    let diagnostic = c.history_window().unwrap();
    assert_ne!(diagnostic.status(), ControllerStatus::Ready);
    assert_eq!(
        diagnostic.retained_failed_generation(),
        Some(next.generation())
    );
    assert!(matches!(
        c.drain_history(),
        Err(BridgeError {
            cause: Cause::Control(ControlError::TerminalFailure)
        })
    ));
}
