//! Pure optional facade/model controls. Simulated gate metadata is not native work.
use super::super::history as encoding;
use super::*;
use crate::frontend::{HistoryBinding, MAX_HISTORY_POSITION};

fn limits(actions: usize) -> Limits {
    Limits {
        epochs: 2,
        threads: 1,
        depth: 1,
        records_per_epoch: 128,
        actions,
    }
}
fn config() -> Config {
    Config {
        retained_per_function: 1,
        max_inflight: 1,
        max_invocations: 128,
    }
}
fn prepared() -> PreparedOptionalController {
    PreparedOptionalController::new_streaming_history(
        metadata_site(),
        71,
        FunctionId(11),
        limits(8),
    )
    .unwrap()
}
fn controller() -> (OptionalController, OptionalClient) {
    unsafe { prepared().activate_concurrent() }.unwrap()
}
impl Fixture {
    fn history_mode(base: u64, absolute: bool, actions: usize) -> Self {
        POISONED.set(false);
        frames::idle_at(base);
        let site = metadata_site();
        let gate = site.site.gate.clone();
        let p = if absolute {
            PreparedOptionalController::new_streaming_history(
                site,
                71,
                FunctionId(11),
                limits(actions),
            )
        } else {
            PreparedOptionalController::new(site, 71, FunctionId(11), limits(actions))
        }
        .unwrap();
        let (c, client) = unsafe { p.activate_concurrent() }.unwrap();
        let thread = unsafe {
            client.attach(
                1,
                ReadableStack {
                    start: 0x7000,
                    end: 0x9000,
                },
                IntervalJournal::allocate(),
            )
        }
        .unwrap();
        Self { thread, c, gate }
    }
}
fn transfer(c: &mut OptionalController, out: &mut Vec<HistoryBatch>) {
    out.extend(c.drain_history().unwrap());
}
fn cycle(c: &mut OptionalController, out: &mut Vec<HistoryBatch>) {
    let e = c.stage(config()).unwrap();
    c.arm(&e).unwrap();
    c.disarm(&e).unwrap();
    drop(c.retire(&e).unwrap());
    transfer(c, out);
}
fn event(n: usize) -> [u64; 7] {
    state(|s| s.journal.page.0[4 + n * 7..11 + n * 7].try_into().unwrap())
}

#[test]
fn old_optional_owner_returns_below_drained_base_and_new_owner_crosses_512() {
    let mut f = Fixture::history_mode(96, true, 8);
    let a = f.stage(1);
    f.c.arm(&a).unwrap();
    let (before, previous) = f.begin(true).unwrap();
    let original = event(0);
    assert_eq!(original[6], 0x2001);
    let mut chunks = Vec::new();
    transfer(&mut f.c, &mut chunks);
    f.c.disarm(&a).unwrap();
    transfer(&mut f.c, &mut chunks);
    assert!(f.c.report(&a).unwrap().is_none());
    assert!(matches!(
        f.c.retire(&a),
        Err(BridgeError {
            cause: Cause::NotDrained
        })
    ));
    for _ in 0..255 {
        cycle(&mut f.c, &mut chunks);
    }
    let b = f.stage(1);
    f.c.arm(&b).unwrap();
    transfer(&mut f.c, &mut chunks);
    assert_eq!(f.c.history_window().unwrap().range(), 513..513);
    f.finish(true, before, previous).unwrap();
    assert_eq!(event(1)[5..], original[5..]);
    let held_report = f.c.retire(&a).unwrap();
    assert_eq!(held_report.records().count(), 1);
    assert!(matches!(
        f.c.stage(config()),
        Err(BridgeError {
            cause: Cause::Setup(SetupError::EpochLimit)
        })
    ));
    f.call(true).unwrap();
    assert_eq!(event(2)[6], 0x0100_2001);
    assert_eq!(event(3)[5..], event(2)[5..]);
    let full = state(|s| s.journal.page.0);
    let batch = f.thread.drain_completed().unwrap().unwrap();
    assert_eq!(batch.journal(), full);
    assert_eq!(batch.history_high_water(), Some(513));
    assert_eq!(batch.history_stream(), Some(chunks[0].stream()));
    assert_eq!(
        (
            batch.history_prefix(0),
            batch.history_prefix(1),
            batch.history_prefix(2),
            batch.history_prefix(3),
            batch.history_prefix(4)
        ),
        (Some(1), Some(1), Some(513), Some(513), None)
    );
    assert_eq!(batch.physical_range(), 0..2);
    assert_eq!(batch.raw_range(), 0..2);
    assert_eq!(batch.event_range(), 0..4);
    assert_eq!((batch.gate_base(), batch.gate_sequence()), (96, 98));
    assert_eq!(batch.observed_gate_sequences(), [97, 98]);
    assert_eq!(
        chunks[0].binding_at(1),
        Some(HistoryBinding::Published {
            action_index: 0,
            generation: a.generation()
        })
    );
    assert_eq!(
        chunks.last().unwrap().binding_at(513),
        Some(HistoryBinding::Published {
            action_index: 512,
            generation: b.generation()
        })
    );
    assert_eq!(
        batch.rows()[0].owner,
        RawIntervalOwner::Sampled {
            generation: a.generation().get(),
            invocation: 0
        }
    );
    assert_eq!(
        batch.rows()[1].owner,
        RawIntervalOwner::Sampled {
            generation: b.generation().get(),
            invocation: 0
        }
    );
    drop(held_report);
    f.c.disarm(&b).unwrap();
    transfer(&mut f.c, &mut chunks);
    drop(f.c.retire(&b).unwrap());
    assert_eq!(chunks[0].number(), 1);
    assert!(chunks.windows(2).all(|p| p[1].follows(&p[0])));
    assert_eq!(chunks.iter().map(|c| c.actions().len()).sum::<usize>(), 514);
    assert_eq!(chunks.last().unwrap().range().end, 514);
    assert_eq!(batch.journal(), full);
    assert_eq!(batch.history_high_water(), Some(513));
    assert!(f.c.stage(config()).is_ok());
    assert!(f.thread.drain_completed().unwrap().is_none());
}

#[test]
fn absolute_closed_and_removed_entries_keep_their_own_stamp_across_rearm() {
    let mut f = Fixture::history_mode(0, true, 8);
    let a = f.stage(1);
    f.c.arm(&a).unwrap();
    f.call(true).unwrap();
    let (before, previous) = f.begin(true).unwrap();
    let closed = event(2);
    f.c.disarm(&a).unwrap();
    drop(f.c.retire(&a).unwrap());
    let mut chunks = Vec::new();
    transfer(&mut f.c, &mut chunks);
    for _ in 0..256 {
        cycle(&mut f.c, &mut chunks);
    }
    assert_eq!(f.c.binding.session.retained_epochs(), 1); // The unsampled receipt owns A.
    f.finish(true, before, previous).unwrap();
    assert_eq!(event(3)[5..], closed[5..]);
    let (before, previous) = f.begin(true).unwrap();
    let removed = event(4);
    let b = f.stage(1);
    f.c.arm(&b).unwrap();
    transfer(&mut f.c, &mut chunks);
    f.finish(true, before, previous).unwrap();
    assert_eq!(event(5)[5..], removed[5..]);
    let batch = f.thread.drain_completed().unwrap().unwrap();
    assert_eq!(
        (batch.history_prefix(2), batch.history_prefix(4)),
        (Some(1), Some(514))
    );
    assert_eq!(batch.history_high_water(), Some(515));
    assert_eq!(batch.totals().1.observed.unsampled, 2);
    assert_eq!(
        batch.rows()[1].owner,
        RawIntervalOwner::FunctionClosed {
            generation: a.generation().get()
        }
    );
    assert!(matches!(
        batch.rows()[2].owner,
        RawIntervalOwner::Removed { .. }
    ));
}

#[test]
fn legacy_constructor_limit_and_257_word_refusal_remain_explicit() {
    let mut f = Fixture::history_mode(0, false, 256);
    assert!(matches!(
        f.c.drain_history(),
        Err(BridgeError {
            cause: Cause::Control(ControlError::HistoryMode)
        })
    ));
    assert!(f.c.history().is_ok());
    f.call(true).unwrap();
    let legacy = f.thread.drain_completed().unwrap().unwrap();
    assert_eq!(legacy.history_stream(), None);
    assert_eq!(legacy.history_high_water(), None);
    assert_eq!(legacy.history_prefix(0), None);
    for _ in 0..128 {
        let e = f.stage(1);
        f.c.arm(&e).unwrap();
        f.c.disarm(&e).unwrap();
        drop(f.c.retire(&e).unwrap());
    }
    assert_eq!(f.c.history().unwrap().actions.len(), 256);
    let summary = IntervalEntrySummary::Unsampled {
        reason: UnsampledSummary::InitialDisarmed,
        history_len: 256,
        binding: BindingChange::Initial,
    };
    assert_eq!(
        encoding::packed_for(&f.c.binding, summary),
        Ok((3, 0, 0x0060_0000))
    );
    let summary = IntervalEntrySummary::Unsampled {
        reason: UnsampledSummary::InitialDisarmed,
        history_len: 257,
        binding: BindingChange::Initial,
    };
    assert_eq!(
        encoding::packed_for(&f.c.binding, summary),
        Err(error(Cause::Capacity))
    );
    let e = f.stage(1);
    assert_eq!(
        f.c.arm(&e),
        Err(error(Cause::Control(ControlError::HistoryFull)))
    );
    assert_eq!(f.c.history().unwrap().actions.len(), 256);
}

#[test]
fn optional_batch_refuses_high_water_corruption_without_consuming_storage() {
    let mut f = Fixture::history_mode(7, true, 8);
    let mut chunks = Vec::new();
    for _ in 0..256 {
        cycle(&mut f.c, &mut chunks);
    }
    let e = f.stage(1);
    f.c.arm(&e).unwrap();
    transfer(&mut f.c, &mut chunks);
    f.call(false).unwrap();
    f.call(true).unwrap();
    let full = state(|s| s.journal.page.0);
    let joins = state(|s| s.joins);
    let cursor = f.thread.cursor;
    let totals = f.thread.totals().unwrap();
    assert_eq!(full[10], 0x0100_2001);
    for bit in [0, 22, 63] {
        state(|s| {
            s.journal.page.0[10] ^= 1 << bit;
            s.journal.page.0[17] ^= 1 << bit;
        });
        let bad = state(|s| s.journal.page.0);
        assert!(f.thread.drain_completed().is_err());
        assert_eq!(state(|s| s.journal.page.0), bad);
        assert_eq!(state(|s| s.joins), joins);
        assert_eq!(f.thread.cursor, cursor);
        assert_eq!(f.thread.totals().unwrap(), totals);
        state(|s| s.journal.page.0 = full);
    }
    let out = f.thread.drain_completed().unwrap().unwrap();
    assert_eq!(out.journal(), full);
    assert_eq!(out.physical_range(), 0..2);
    assert_eq!(out.raw_range(), 0..1);
    assert_eq!(out.observed_gate_sequences(), [9]);
    f.call(false).unwrap();
    let fast = f.thread.drain_completed().unwrap().unwrap();
    assert!(fast.rows().is_empty());
    assert_eq!(fast.history_high_water(), Some(513));
    assert_eq!(fast.history_prefix(0), None);
    assert_eq!(fast.history_stream(), out.history_stream());
    assert_eq!(
        encoding::decode(0xffff_ffff_ff7f_e000, MAX_HISTORY_POSITION),
        Some((0, MAX_HISTORY_POSITION, 1))
    );
    assert_eq!(
        encoding::decode(0xffff_ffff_ff7f_e000, MAX_HISTORY_POSITION - 1),
        None
    );
    assert_eq!(encoding::decode(0, MAX_HISTORY_POSITION + 1), None);
    assert_eq!(encoding::decode(4097, 513), None);
    let future = IntervalEntrySummary::Admitted {
        generation: e.generation(),
        invocation: 0,
        history_len: 514,
        binding: BindingChange::Published {
            action_index: 512,
            generation: e.generation(),
        },
    };
    assert_eq!(
        encoding::packed_for(&f.c.binding, future),
        Err(error(Cause::Capacity))
    );
}

#[test]
fn opaque_stream_identity_same_public_ids_and_contiguous_chunks_are_required() {
    let (mut a, _) = controller();
    let (mut b, _) = controller();
    let mut first = Vec::new();
    let mut foreign = Vec::new();
    cycle(&mut a, &mut first);
    cycle(&mut a, &mut first);
    cycle(&mut b, &mut foreign);
    assert_eq!(first[0].stream().pid(), foreign[0].stream().pid());
    assert_eq!(first[0].stream().install(), foreign[0].stream().install());
    assert_eq!(first[0].stream().function(), foreign[0].stream().function());
    assert_ne!(first[0].stream(), foreign[0].stream());
    assert!(first[1].follows(&first[0]));
    assert!(!first[0].follows(&first[0]));
    assert!(!first[0].follows(&first[1]));
    assert!(!foreign[0].follows(&first[0]));
    // The decoder authenticates a bound only; the consumer must reject this Removed binding for a sampled owner.
    assert_eq!(encoding::decode(0x4001, 4), Some((1, 2, 0)));
    assert!(matches!(
        first[0].binding_at(2),
        Some(HistoryBinding::Removed { .. })
    ));
}

#[test]
fn reserve_reentry_and_process_refusals_preserve_optional_history() {
    let (mut c, client) = controller();
    drop(client);
    let e = c.stage(config()).unwrap();
    c.arm(&e).unwrap();
    let before = c.history_window().unwrap();
    c.binding.session.test_history_reserve_failure(true);
    let failure = c.drain_history();
    c.binding.session.test_history_reserve_failure(false);
    assert!(matches!(
        failure,
        Err(BridgeError {
            cause: Cause::Control(ControlError::HistoryAllocation)
        })
    ));
    assert!(!c.binding.failed.load(Ordering::Acquire));
    assert_eq!(c.history_window().unwrap(), before);
    let scope = ControllerScope::enter().unwrap();
    assert!(matches!(
        c.drain_history(),
        Err(BridgeError {
            cause: Cause::ControllerReentry
        })
    ));
    assert!(matches!(
        c.history_window(),
        Err(BridgeError {
            cause: Cause::ControllerReentry
        })
    ));
    drop(scope);
    let pid = c.binding.pid;
    Arc::get_mut(&mut c.binding).unwrap().pid = 0;
    assert!(matches!(
        c.drain_history(),
        Err(BridgeError {
            cause: Cause::Process
        })
    ));
    Arc::get_mut(&mut c.binding).unwrap().pid = pid;
    assert_eq!(c.history_window().unwrap(), before);
    let out = c.drain_history().unwrap().unwrap();
    assert_eq!(out.number(), 1);
    assert_eq!(out.range(), 0..1);
}

#[test]
fn terminal_and_poison_are_diagnostics_never_authority_for_false_selector_calls() {
    for poison in [false, true] {
        let mut f = Fixture::history_mode(0, true, 8);
        let e = f.stage(1);
        if poison {
            let owner = f.c.owner(&e).unwrap().clone();
            let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                f.c.binding
                    .session
                    .publish_with_controls(&owner, FailurePoint::None, |_| {
                        panic!("required history poison")
                    })
                    .unwrap();
            }));
            assert!(failed.is_err());
            assert!(matches!(
                f.c.history_window(),
                Err(BridgeError {
                    cause: Cause::Control(ControlError::Poisoned)
                })
            ));
        } else {
            assert_eq!(
                f.c.publish(&e, FailurePoint::AfterMutation),
                Err(error(Cause::Control(ControlError::InjectedAfter)))
            );
            let window = f.c.history_window().unwrap();
            assert_eq!(window.status(), ControllerStatus::TerminalFailure);
            assert_eq!(
                window.actions().last().unwrap().kind,
                crate::frontend::ActionKind::FailedAfter
            );
        }
        assert!(f.c.binding.failed.load(Ordering::Acquire));
        assert!(!f.c.binding.site.selector.is_enabled());
        assert!(matches!(
            f.c.drain_history(),
            Err(BridgeError {
                cause: Cause::Control(ControlError::TerminalFailure)
            })
        ));
        assert!(f.call(false).is_err());
        assert_eq!(f.gate.idle_checkpoint(), Ok(0));
    }
}

#[test]
fn metadata_fixture_closes_real_model_owner_without_gate_or_native_credit() {
    let (mut c, _) = controller();
    let mut model = c.metadata_model().unwrap();
    let e = c.stage(config()).unwrap();
    c.arm(&e).unwrap();
    assert_eq!(c.scan_closed().unwrap(), 0);
    c.metadata_complete(&mut model, &e, 1).unwrap();
    assert_eq!(model.completed_sequence(), 1);
    assert_eq!(c.scan_closed().unwrap(), 1);
    assert!(!c.binding.site.selector.is_enabled());
    c.disarm(&e).unwrap();
    let report = c.retire(&e).unwrap();
    assert_eq!(report.records().count(), 1);
    drop(report);
    let out = c.drain_history().unwrap().unwrap();
    assert_eq!(
        out.actions().iter().map(|a| a.kind).collect::<Vec<_>>(),
        [
            crate::frontend::ActionKind::Published,
            crate::frontend::ActionKind::Disabled,
            crate::frontend::ActionKind::Removed
        ]
    );
    let e = c.stage(config()).unwrap();
    c.arm(&e).unwrap();
    c.metadata_complete(&mut model, &e, 1).unwrap();
    assert_eq!(model.completed_sequence(), 2);
}
