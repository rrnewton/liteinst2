//! Pure callback/protocol models; no actual installation, CALL/RET or export credit.
use super::super::gate::drain_tests as frames;
use super::*;

const F: FunctionId = FunctionId(11);
fn limits(epochs: usize) -> Limits {
    Limits {
        epochs,
        threads: 1,
        depth: 2,
        records_per_epoch: 4,
        actions: 4,
    }
}
fn config() -> Config {
    Config {
        retained_per_function: 1,
        max_inflight: 1,
        max_invocations: 4,
    }
}
fn prepared(epochs: usize) -> PreparedIntervalController {
    PreparedIntervalController::new_streaming_history(site::synthetic_site(), 71, F, limits(epochs))
        .unwrap()
}
fn controller(epochs: usize) -> (IntervalController, IntervalClient) {
    // SAFETY: metadata-only synthetic site, no executable publication or fork.
    unsafe { prepared(epochs).activate_concurrent() }.unwrap()
}
fn state(client: &IntervalClient) -> State {
    let model = client.binding.session.register_thread(1).unwrap();
    let mut journal = IntervalJournal::allocate();
    journal.header(7, 0);
    State {
        binding: Arc::clone(&client.binding),
        actual_thread: thread::current().id(),
        tid: 7,
        registration: 1,
        stack: ReadableStack {
            start: 0x7000,
            end: 0x9000,
        },
        model,
        pairs: std::array::from_fn(|_| None),
        depth: 0,
        next: 1,
        totals: PairTotals::default(),
        journal,
        failure: None,
        timing: None,
    }
}
fn event(s: &State, n: usize) -> [u64; 7] {
    s.journal.page.0[4 + n * 7..11 + n * 7].try_into().unwrap()
}
fn cycle(c: &mut IntervalController, batches: &mut Vec<HistoryBatch>) {
    if c.history_window().unwrap().actions().len() > 2 {
        batches.push(c.drain_history().unwrap().unwrap());
    }
    let e = c.stage(config()).unwrap();
    c.arm(&e).unwrap();
    c.disarm(&e).unwrap();
    drop(c.retire(&e).unwrap());
    if c.history_window().unwrap().actions().len() == 4 {
        batches.push(c.drain_history().unwrap().unwrap());
    }
}

#[test]
fn late_sampled_owner_keeps_prefix_across_600_actions_and_retirement_after_drains() {
    let (mut c, client) = controller(2);
    let mut s = state(&client);
    let a = c.stage(config()).unwrap();
    c.arm(&a).unwrap();
    s.enter(0x1000, 0x8008, 0x2005).unwrap();
    let first = event(&s, 0);
    let mut batches = vec![c.drain_history().unwrap().unwrap()];
    c.disarm(&a).unwrap();
    assert!(c.report(&a).unwrap().is_none());
    assert!(matches!(
        c.retire(&a),
        Err(BridgeError {
            cause: Cause::NotDrained
        })
    ));
    for _ in 0..298 {
        cycle(&mut c, &mut batches);
    }
    // Explicitly drain any suffix before the final arm; no action is evicted.
    if !c.history_window().unwrap().actions().is_empty() {
        batches.push(c.drain_history().unwrap().unwrap());
    }
    let b = c.stage(config()).unwrap();
    c.arm(&b).unwrap();
    assert_eq!(c.binding.session.history_committed_end(), 599);
    batches.push(c.drain_history().unwrap().unwrap());
    s.finish(0x1012, 0x8008, 0x2005).unwrap();
    assert_eq!(&event(&s, 1)[5..], &first[5..]);
    assert_eq!(decode_absolute(event(&s, 1)[6], 599).unwrap().1, 1);
    let report = c.retire(&a).unwrap();
    assert_eq!(report.records().count(), 1);
    assert!(matches!(
        c.stage(config()),
        Err(BridgeError {
            cause: Cause::Setup(SetupError::EpochLimit)
        })
    ));
    drop(report);
    s.enter(0x1000, 0x8008, 0x2005).unwrap();
    s.finish(0x1012, 0x8008, 0x2005).unwrap();
    assert_eq!(decode_absolute(event(&s, 2)[6], 599).unwrap().1, 599);
    assert_eq!(event(&s, 2)[5], b.generation().get());
    assert_eq!(event(&s, 2)[5..], event(&s, 3)[5..]);
    c.disarm(&b).unwrap();
    batches.push(c.drain_history().unwrap().unwrap());
    drop(c.retire(&b).unwrap());
    assert_eq!(
        batches.iter().map(|b| b.actions().len()).sum::<usize>(),
        600
    );
    assert!(batches.windows(2).all(|b| b[1].follows(&b[0])));
    assert_eq!(batches[0].range().start, 0);
    assert_eq!(batches.last().unwrap().range().end, 600);
    assert_eq!(c.binding.session.retained_epochs(), 0);
    assert_eq!(
        s.totals,
        PairTotals {
            entries: 2,
            returns: 2,
            completed: 2,
            unsampled: 0
        }
    );
    assert!(matches!(
        c.history(),
        Err(BridgeError {
            cause: Cause::Control(ControlError::HistoryMode)
        })
    ));
    assert!(c.stage(config()).is_ok()); // Batches never consume E; reuse still works.
}

#[test]
fn function_closed_and_removed_receipts_keep_original_stamp_through_many_drains() {
    let (mut c, client) = controller(2);
    let mut s = state(&client);
    let a = c.stage(config()).unwrap();
    c.arm(&a).unwrap();
    s.enter(0x1000, 0x8008, 0x2005).unwrap();
    s.finish(0x1012, 0x8008, 0x2005).unwrap();
    s.enter(0x1000, 0x8008, 0x2005).unwrap(); // Actual FunctionClosed model receipt.
    let closed = event(&s, 2);
    c.disarm(&a).unwrap();
    let report = c.retire(&a).unwrap();
    drop(report);
    let mut batches = vec![c.drain_history().unwrap().unwrap()];
    for _ in 0..260 {
        cycle(&mut c, &mut batches);
    }
    assert_eq!(c.binding.session.retained_epochs(), 1); // Receipt alone keeps A.
    let b = c.stage(config()).unwrap();
    assert!(matches!(
        c.stage(config()),
        Err(BridgeError {
            cause: Cause::Setup(SetupError::EpochLimit)
        })
    ));
    s.finish(0x1012, 0x8008, 0x2005).unwrap();
    assert_eq!(event(&s, 3)[5..], closed[5..]);
    assert_eq!(decode_absolute(closed[6], 522).unwrap(), (0, 1, 3));
    s.enter(0x1000, 0x8008, 0x2005).unwrap(); // Removed last transient owner.
    let removed = event(&s, 4);
    c.arm(&b).unwrap();
    batches.push(c.drain_history().unwrap().unwrap());
    s.finish(0x1012, 0x8008, 0x2005).unwrap();
    assert_eq!(event(&s, 5)[5..], removed[5..]);
    assert_eq!(decode_absolute(removed[6], 523).unwrap(), (0, 522, 2));
    c.disarm(&b).unwrap();
    drop(c.retire(&b).unwrap());
    assert_eq!(c.binding.session.retained_epochs(), 0);
    assert_eq!(s.model.completed_sequence(), 1);
}

#[test]
fn chunk_identity_order_and_consumer_prefix_association_are_independent_checks() {
    let (mut a, _) = controller(1);
    let (mut b, _) = controller(1);
    let mut batches = Vec::new();
    for _ in 0..3 {
        cycle(&mut a, &mut batches);
        batches.extend(a.drain_history().unwrap());
    }
    let mut foreign = Vec::new();
    cycle(&mut b, &mut foreign);
    foreign.extend(b.drain_history().unwrap());
    assert_eq!(batches[0].stream().pid(), foreign[0].stream().pid());
    assert_eq!(batches[0].stream().install(), foreign[0].stream().install());
    assert_eq!(
        batches[0].stream().function(),
        foreign[0].stream().function()
    );
    assert_ne!(batches[0].stream(), foreign[0].stream()); // Arc<()> value equality would fail this.
    assert!(batches[1].follows(&batches[0]));
    assert!(!batches[0].follows(&batches[0]));
    assert!(!batches[2].follows(&batches[0]));
    assert!(!batches[0].follows(&batches[1]));
    assert!(!foreign[0].follows(&batches[0]));
    let generation = batches[0].actions()[0].generation;
    assert_eq!(
        batches[0].binding_at(1),
        Some(HistoryBinding::Published {
            action_index: 0,
            generation
        })
    );
    assert_eq!(
        batches[0].binding_at(2),
        Some(HistoryBinding::Removed {
            action_index: 1,
            generation
        })
    );
    assert_eq!(batches[0].binding_at(3), None);
    // An in-range low-prefix corruption can pass a bound-only decoder. Replay
    // still refuses its association with a sampled generation: Removed != Published.
    assert_eq!(decode_absolute(1 | (2 << 13), 6), Some((1, 2, 0)));
    assert_ne!(
        batches[0].binding_at(2),
        Some(HistoryBinding::Published {
            action_index: 0,
            generation
        })
    );
}

#[test]
fn checked_absolute_encoding_boundaries_keep_legacy_words_and_refusal_literal() {
    let (mut c, _) = controller(1);
    let e = c.stage(config()).unwrap();
    c.arm(&e).unwrap();
    // Literal wire words keep mutually wrong pack/decode shifts from agreeing.
    for (prefix, word) in [
        (0, 0x0040_0000),
        (256, 0x0060_0000),
        (257, 0x0060_2000),
        (511, 0x007f_e000),
        (512, 0x0140_0000),
        (MAX_HISTORY_POSITION, 0xffff_ffff_ff7f_e000),
    ] {
        let summary = IntervalEntrySummary::Unsampled {
            reason: UnsampledSummary::InitialDisarmed,
            history_len: prefix as usize,
            binding: BindingChange::Initial,
        };
        let encoded = packed_absolute(summary, F, prefix).unwrap();
        assert_eq!(encoded, (3, 0, word));
        assert_eq!(decode_absolute(word, prefix), Some((0, prefix, 1)));
        assert_eq!(decode_absolute(encoded.2, prefix), Some((0, prefix, 1)));
        if prefix <= 256 {
            assert_eq!(packed(summary, F).unwrap(), encoded);
        } else {
            assert_eq!(packed(summary, F), Err(error(Cause::Capacity)));
        }
        if prefix != 0 {
            assert!(decode_absolute(encoded.2, prefix - 1).is_none());
        }
    }
    let sampled = IntervalEntrySummary::Admitted {
        generation: e.generation(),
        invocation: 0,
        history_len: 513,
        binding: BindingChange::Published {
            action_index: 512,
            generation: e.generation(),
        },
    };
    assert_eq!(
        packed_absolute(sampled, F, 513),
        Ok((1, e.generation().get(), 0x0100_2001))
    );
    assert_eq!(decode_absolute(0x0100_2001, 513), Some((1, 513, 0)));
    let summary = IntervalEntrySummary::Admitted {
        generation: e.generation(),
        invocation: 0,
        history_len: (MAX_HISTORY_POSITION + 1) as usize,
        binding: BindingChange::Published {
            action_index: 0,
            generation: e.generation(),
        },
    };
    assert_eq!(
        packed_absolute(summary, F, MAX_HISTORY_POSITION),
        Err(error(Cause::Capacity))
    );
    assert!(decode_absolute(1 << 63, 512).is_none());
    assert!(decode_absolute(4097, 512).is_none());
    let wrong = IntervalEntrySummary::Admitted {
        generation: e.generation(),
        invocation: 0,
        history_len: 512,
        binding: BindingChange::Removed {
            action_index: 1,
            generation: e.generation(),
        },
    };
    assert_eq!(packed_absolute(wrong, F, 512), Err(error(Cause::Invariant)));
}

#[test]
fn unsupported_mode_process_and_same_thread_reentry_refuse_without_drain() {
    // SAFETY: metadata-only synthetic sites; no invocation/publication or fork.
    assert!(matches!(
        unsafe { prepared(1).activate() },
        Err(BridgeError {
            cause: Cause::Control(ControlError::HistoryMode)
        })
    ));
    let p = PreparedIntervalController::new(site::synthetic_site(), 71, F, limits(1)).unwrap();
    let (mut legacy, _) = unsafe { p.activate_concurrent() }.unwrap();
    assert!(matches!(
        legacy.drain_history(),
        Err(BridgeError {
            cause: Cause::Control(ControlError::HistoryMode)
        })
    ));
    assert!(legacy.history().is_ok());
    let (mut c, client) = controller(1);
    drop(client);
    let e = c.stage(config()).unwrap();
    c.arm(&e).unwrap();
    let before = c.history_window().unwrap();
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
}

#[test]
fn absolute_buffer_drain_preserves_full_journal_and_opaque_history_identity() {
    let _frames = frames::FrameScope::new();
    let mut site = site::synthetic_site();
    let gate = frames::descriptor();
    let inner = Arc::get_mut(&mut site.site).unwrap();
    inner.terminal = gate.continuation();
    inner.gate = Some(gate);
    let p = PreparedIntervalController::new_streaming_history(site, 71, F, limits(1)).unwrap();
    // SAFETY: synthetic metadata and fake gate frame only, no executable code.
    let (mut c, client) = unsafe { p.activate_concurrent() }.unwrap();
    let mut thread = unsafe {
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
    let mut histories = Vec::new();
    for _ in 0..256 {
        cycle(&mut c, &mut histories);
    }
    let e = c.stage(config()).unwrap();
    c.arm(&e).unwrap();
    let history = c.drain_history().unwrap().unwrap();
    assert_eq!(history.range().end, 513);
    let before = thread.totals().unwrap();
    let previous = thread.finished.replace(None);
    STATE.with(|cell| {
        let mut borrowed = cell.borrow_mut();
        let s = borrowed.as_mut().unwrap();
        frames::begin(s, RawTimestamp { ticks: 10, aux: 7 });
        frames::complete(s, RawTimestamp { ticks: 13, aux: 7 });
        frames::resume(s);
    });
    thread.finished.set(drain::completed_checkpoint(
        previous,
        before,
        thread.totals().unwrap(),
    ));
    let full = STATE.with(|cell| cell.borrow().as_ref().unwrap().journal.page.0);
    let rows_before = thread.raw_intervals().unwrap();
    let totals_before = thread.totals().unwrap();
    let cursor_before = thread.drain_cursor;
    for bit in [0, 22, 63] {
        STATE.with(|cell| {
            let mut borrowed = cell.borrow_mut();
            let s = borrowed.as_mut().unwrap();
            s.journal.page.0[10] ^= 1u64 << bit;
            s.journal.page.0[17] ^= 1u64 << bit;
        });
        let corrupt = STATE.with(|cell| cell.borrow().as_ref().unwrap().journal.page.0);
        assert!(matches!(
            thread.drain_completed(),
            Err(BridgeError {
                cause: Cause::Invariant
            })
        ));
        assert_eq!(
            STATE.with(|cell| cell.borrow().as_ref().unwrap().journal.page.0),
            corrupt
        );
        assert_eq!(thread.raw_intervals().unwrap(), rows_before);
        assert_eq!(thread.totals().unwrap(), totals_before);
        assert_eq!(thread.drain_cursor, cursor_before);
        STATE.with(|cell| cell.borrow_mut().as_mut().unwrap().journal.page.0 = full);
    }
    let batch = thread.drain_completed().unwrap().unwrap();
    assert_eq!(batch.journal(), full);
    assert_eq!(batch.history_stream(), Some(history.stream()));
    assert_eq!(batch.history_high_water(), Some(513));
    assert_eq!(
        (
            batch.history_prefix(0),
            batch.history_prefix(1),
            batch.history_prefix(2)
        ),
        (Some(513), Some(513), None)
    );
    assert_eq!(
        batch.rows()[0].owner,
        RawIntervalOwner::Sampled {
            generation: e.generation().get(),
            invocation: 0
        }
    );
    assert_eq!(
        history.binding_at(513),
        Some(HistoryBinding::Published {
            action_index: 512,
            generation: e.generation()
        })
    );
    c.disarm(&e).unwrap();
    c.drain_history().unwrap();
    drop(c.retire(&e).unwrap());
    assert_eq!(batch.journal(), full);
    assert_eq!(batch.history_high_water(), Some(513));
    thread.detach().unwrap();
}
