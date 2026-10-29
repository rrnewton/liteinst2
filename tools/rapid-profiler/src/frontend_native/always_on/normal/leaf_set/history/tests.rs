//! Real core history chunks and metadata owners; no callbacks or source execution.
use super::super::tests::{ENTRY, Fixture, IDS, controller, reclaim};
use super::*;
use crate::frontend::ActionKind;
use liteinst2::contracts::SourceIdentity;
fn copy(batch: &NormalLeafSetHistoryBatch) -> NormalLeafSetHistoryBatch {
    NormalLeafSetHistoryBatch {
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
    c: &mut NormalLeafSetSessionController,
    bank: IntervalEpochStorage,
) -> (IntervalEpochStorage, NormalLeafSetHistoryBatch) {
    let e = c.stage_prepared(bank).unwrap();
    c.arm(&e).unwrap();
    c.disarm(&e).unwrap();
    assert_eq!(c.report(&e).unwrap().unwrap().records().count(), 0);
    let bank = reclaim(c, e);
    (bank, c.drain_history().unwrap().unwrap())
}
#[test]
fn leaf_set_history_full_identity_and_replay_are_exact() {
    let (mut c, mut banks) = controller(4, 10);
    let original = stream_for(&c.0.binding).unwrap();
    assert_eq!(original.functions(), &IDS);
    assert_eq!(original.entries(), &ENTRY);
    assert_eq!(original.pid(), c.0.binding.pid);
    assert_eq!(original.install(), 71);
    assert_eq!(original.format(), HistoryFormat::AbsoluteV1);
    for field in 0..15 {
        let mut bad = original.clone();
        match field {
            0 => bad.key = Arc::new(()),
            1 => bad.pid ^= 1,
            2 => bad.install ^= 1,
            3 => bad.identity.source = SourceIdentity([0; 32]),
            4 => bad.identity.mapping += 1,
            5 => bad.identity.generation += 1,
            6 => bad.functions.len = 3,
            7..=10 => bad.functions.ids[field - 7] = FunctionId(99),
            11..=14 => bad.entries[field - 11] += 1,
            _ => unreachable!(),
        }
        assert_ne!(original, bad);
    }
    let (bank, first) = cycle(&mut c, banks.pop().unwrap());
    let (_, second) = cycle(&mut c, bank);
    assert!(second.follows(&first));
    assert!(!first.follows(&second));
    assert!(!first.follows(&first));
    for field in 0..5 {
        let mut bad = copy(&second);
        match field {
            0 => bad.stream.key = Arc::new(()),
            1 => bad.chunk.number += 1,
            2 => bad.chunk.range.start += 1,
            3 => bad.chunk.before = HistoryBinding::Initial,
            4 => bad.stream.functions.ids.swap(2, 3),
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
    for field in 0..4 {
        let mut bad = copy(&first);
        match field {
            0 => bad.chunk.range.end += 1,
            1 => bad.chunk.actions[0].current = None,
            2 => bad.chunk.actions[0].function = Some(IDS[3]),
            3 => bad.chunk.actions[0].kind = ActionKind::FailedAfter,
            _ => unreachable!(),
        }
        assert_eq!(bad.binding_at(1), None);
    }
    let e = c.stage_prepared(banks.pop().unwrap()).unwrap();
    c.arm(&e).unwrap();
    let before = c.history_window().unwrap();
    c.0.binding.session.test_history_reserve_failure(true);
    let refused = c.drain_history();
    c.0.binding.session.test_history_reserve_failure(false);
    assert!(matches!(
        refused,
        Err(BridgeError {
            cause: Cause::Control(ControlError::HistoryAllocation)
        })
    ));
    assert_eq!(c.history_window().unwrap(), before);
}
#[test]
fn leaf_set_history_streams_do_not_retain_epochs() {
    let mut f = Fixture::new(4, 10);
    f.call(0);
    let old = f.epoch.take().unwrap();
    let generation = old.generation();
    f.controller.disarm(&old).unwrap();
    let mut chunks = vec![f.controller.drain_history().unwrap().unwrap()];
    let retained = [chunks[0].stream().clone(), chunks[0].stream().clone()];
    let mut bank = f.banks.pop().unwrap();
    for _ in 0..260 {
        let (returned, chunk) = cycle(&mut f.controller, bank);
        assert!(chunk.follows(chunks.last().unwrap()));
        chunks.push(chunk);
        bank = returned;
    }
    f.enter(3);
    let old_bank = reclaim(&mut f.controller, old);
    f.observe(3);
    let batch = f.transfer();
    assert_eq!(batch.history_high_water(), 522);
    assert_eq!(batch.history_stream(), &retained[0]);
    assert_eq!(retained[0], retained[1]);
    assert_eq!(batch.records()[0].function, IDS[0]);
    assert_eq!(batch.records()[0].record.history_prefix, 1);
    assert_eq!(
        batch.records()[0].record.raw.owner,
        RawIntervalOwner::Sampled {
            generation: generation.get(),
            invocation: 0
        }
    );
    assert_eq!(
        chunks[0].binding_at(1),
        Some(HistoryBinding::Published {
            action_index: 0,
            generation
        })
    );
    assert_eq!(batch.records()[1].function, IDS[3]);
    assert_eq!(batch.records()[1].record.history_prefix, 522);
    assert!(matches!(
        batch.records()[1].record.raw.owner,
        RawIntervalOwner::Removed { .. }
    ));
    assert_eq!(f.controller.history_window().unwrap().range(), 522..522);
    assert_eq!(f.state.binding.session.retained_epochs(), 0);
    drop((bank, old_bank));
}
