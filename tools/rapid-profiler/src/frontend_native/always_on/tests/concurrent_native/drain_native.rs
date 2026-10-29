//! One fresh exact release process; finite native buffer reuse, not timing accuracy.
use super::*;

const INSTALL: u64 = 0x6472_6169_6e01;
const COUNT: usize = 64;

fn totals(count: u64) -> PairTotals {
    PairTotals {
        entries: count,
        returns: count,
        completed: count,
        unsampled: 0,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    identity: (u32, u64, u64, u64, FunctionId),
    journal_address: u64,
    totals: PairTotals,
    next: u64,
    sequence: u64,
    gate_sequence: u64,
    rows: Vec<RawInterval>,
    journal: [u64; 512],
}

fn snapshot(attached: &IntervalThread, gate: &CallGate) -> Snapshot {
    let rows = attached.raw_intervals().unwrap();
    let gate_sequence = gate.idle_checkpoint().unwrap();
    STATE.with(|cell| {
        let storage = cell.borrow();
        let state = storage.as_ref().unwrap();
        assert!(attached.matches(state));
        assert!(!POISONED.get());
        assert!(state.failure.is_none());
        assert_eq!((state.depth, state.model.depth()), (0, 0));
        assert!(state.pairs.iter().all(Option::is_none));
        assert_eq!(state.model.identity(), state.registration);
        assert_eq!(state.model.completed_sequence(), state.totals.completed);
        assert_eq!(state.next, state.totals.entries + 1);
        assert_eq!(attached.finished.get(), Some(state.totals));
        assert!(std::ptr::eq(
            Arc::as_ptr(state.binding.single_site().unwrap().gate.as_ref().unwrap()),
            gate
        ));
        Snapshot {
            identity: (
                state.binding.pid,
                state.tid,
                state.registration,
                state.binding.install,
                state.binding.single_function().unwrap(),
            ),
            journal_address: state.journal.address(),
            totals: state.totals,
            next: state.next,
            sequence: state.model.completed_sequence(),
            gate_sequence,
            rows,
            // Same-thread exclusive observation outside callbacks; copy EVERY word.
            journal: state.journal.page.0,
        }
    })
}

// Copy all public batch fields, including both complete buffers, so retaining
// batch 1 across refill is checked independently of the reused live storage.
#[derive(Debug, Eq, PartialEq)]
struct SavedBatch {
    identity: (u32, u64, u64, u64, FunctionId),
    number: u64,
    totals: (PairTotals, PairTotals),
    sequences: (u64, u64),
    next: u64,
    gate_sequence: u64,
    raw_range: std::ops::Range<u64>,
    event_range: std::ops::Range<u64>,
    rows: Vec<RawInterval>,
    journal: Vec<u64>,
}

fn saved(batch: &IntervalBatch) -> SavedBatch {
    SavedBatch {
        identity: (
            batch.pid(),
            batch.tid(),
            batch.registration(),
            batch.install(),
            batch.function(),
        ),
        number: batch.number(),
        totals: batch.totals(),
        sequences: batch.completed_sequences(),
        next: batch.next_ordinal(),
        gate_sequence: batch.gate_sequence(),
        raw_range: batch.raw_range(),
        event_range: batch.event_range(),
        rows: batch.rows().to_vec(),
        journal: batch.journal().to_vec(),
    }
}

fn empty_drain(attached: &mut IntervalThread, gate: &CallGate, controller: &IntervalController) {
    let before = snapshot(attached, gate);
    let cursor = attached.drain_cursor;
    let history = controller.history().unwrap();
    assert!(attached.drain_completed().unwrap().is_none());
    assert_eq!(snapshot(attached, gate), before);
    assert_eq!(attached.drain_cursor, cursor);
    assert_eq!(controller.history().unwrap(), history);
}

#[test]
#[ignore = "requires release fixture reproducer"]
fn ordinary_native_two_completed_batches() {
    let candidate = std::env::var_os("RAPID_CONCURRENT_CANDIDATE").expect("candidate ELF");
    let expected = std::env::var_os("RAPID_CONCURRENT_EXPECTED").expect("independent expected ELF");
    let candidate = Path::new(&candidate);
    let bytes = expected_file(candidate, Path::new(&expected));
    pin(None);
    // SAFETY: one exact test in a fresh process; the trusted constructor/dependency-
    // free local DSO has no foreign entry capability, CET, signal, unwind, alias
    // writer or unload. Existing loader and complete-source publication checks apply.
    let owner = unsafe {
        LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum_nonempty", CONTRACT)
    }
    .unwrap();
    let entry = owner.entry();
    let returns: BTreeSet<_> = owner.certificate().returns().iter().copied().collect();
    let gate = CallGate::new(owner.certificate()).unwrap();
    let continuation = gate.continuation();
    let mut prep = OrdinarySitePreparation::new(owner, Arc::clone(&gate), identity(entry)).unwrap();
    assert_eq!(
        prep.role_pcs().collect::<Vec<_>>(),
        std::iter::once(entry)
            .chain(returns.iter().copied())
            .collect::<Vec<_>>()
    );
    let before_input = guarded();
    let input = Arc::new(before_input);
    // Labels and input schedule are fixed before any invocation.
    let requests: Vec<_> = (0..COUNT)
        .map(|i| (1000 + i as u64, if i % 2 == 0 { 1 } else { 64 }))
        .collect();
    let readable = stack();
    let mut originals = Vec::with_capacity(COUNT);
    for &(id, length) in &requests {
        let slice = &input[16..16 + length];
        // SAFETY: exclusive uninstalled source, immutable nonempty input, actual
        // mapped stack and normal SysV return; no asynchronous entry or unwind.
        let result =
            unsafe { prep.invoke_original(slice.as_ptr(), slice.len(), &readable) }.unwrap();
        assert_eq!(result.value, model(slice));
        assert_eq!(result.pre_call_rsp, result.resumed_rsp);
        assert_eq!(*input, before_input);
        originals.push((id, result.value));
    }
    let mut prepared = PreparedIntervalController::new(
        publish(prep),
        INSTALL,
        FUNCTION,
        Limits {
            epochs: 1,
            threads: 1,
            depth: 1,
            records_per_epoch: COUNT,
            actions: 2,
        },
    )
    .unwrap();
    let epoch = prepared
        .stage(Config {
            retained_per_function: COUNT,
            max_inflight: 1,
            max_invocations: COUNT,
        })
        .unwrap();
    let generation = epoch.generation();
    // SAFETY: no fork, previous attachment, callback or acquired model lock.
    // Only this pinned thread invokes; controller operations occur outside calls.
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    let journal = IntervalJournal::allocate();
    let journal_address = journal.address();
    // SAFETY: sealed process-lived source/images, unchanged valid input and stack,
    // no signal/nonlocal exit or foreign entry; all calls use the immutable gate.
    let mut attached = unsafe { client.attach(1, stack(), journal) }.unwrap();
    let initial = snapshot(&attached, &gate);
    assert_eq!(
        initial.identity,
        (std::process::id(), tid(), 1, INSTALL, FUNCTION)
    );
    assert_eq!(initial.journal_address, journal_address);
    assert_eq!(
        (initial.totals, initial.next, initial.sequence),
        (totals(0), 1, 0)
    );
    assert!(initial.rows.is_empty());
    let mut empty_page = [0; 512];
    empty_page[2] = initial.identity.1;
    assert_eq!(initial.journal, empty_page);
    let g0 = initial.gate_sequence; // Actual TLS sequence AFTER the 64 original calls.
    empty_drain(&mut attached, &gate, &controller);
    let mut empty_drains = 1;
    controller.arm(&epoch).unwrap();
    let armed = controller.history().unwrap();
    assert_eq!(armed.status, ControllerStatus::Ready);
    assert_eq!(armed.current, Some(generation));
    assert_eq!(armed.enabled, [true]);
    assert_eq!(armed.retained_failed_generation, None);
    assert_eq!(
        armed.actions,
        [Action {
            kind: ActionKind::Published,
            generation,
            function: None,
            current: Some(generation),
            group: None,
        }]
    );
    let mut calls = Vec::with_capacity(COUNT);
    let mut rows = Vec::with_capacity(COUNT);
    let mut batches = Vec::with_capacity(2);
    let mut first_saved = None;
    let mut capacity_refusals = 0;
    for (index, &(id, length)) in requests.iter().enumerate() {
        let base = index / 32 * 32;
        let prefix = attached.raw_intervals().unwrap();
        assert_eq!(prefix, rows[base..]);
        assert_eq!(prefix.len(), index % 32);
        let slice = &input[16..16 + length];
        // SAFETY: same exact admitted ABI/memory/normal-return and pinned-thread contract.
        let call = unsafe { attached.invoke_integer_leaf(slice) }.unwrap();
        assert_eq!((id, call.value), originals[index]);
        assert_eq!(call.value, model(slice));
        assert_eq!(call.pre_call_rsp, call.resumed_rsp);
        assert_eq!(call.entry_rsp.checked_add(8), Some(call.pre_call_rsp));
        assert_eq!(*input, before_input);
        let current = attached.raw_intervals().unwrap();
        assert_eq!(current.len(), prefix.len() + 1);
        assert_eq!(current[..prefix.len()], prefix);
        let row = *current.last().unwrap();
        assert_eq!((id, row.ordinal), (1000 + index as u64, index as u64 + 1));
        assert_eq!((row.entry_pc, row.return_pc), (entry, call.return_pc));
        assert!(returns.contains(&row.return_pc));
        assert_eq!(
            row.owner,
            RawIntervalOwner::Sampled {
                generation: generation.get(),
                invocation: index
            }
        );
        assert!(
            row.elapsed_ticks().is_some(),
            "clock failure is not timing success"
        );
        calls.push((id, call));
        rows.push(row);
        if current.len() != 32 {
            continue;
        }

        let end = index + 1;
        let before = snapshot(&attached, &gate);
        assert_eq!(before.identity, initial.identity);
        assert_eq!(before.journal_address, journal_address);
        assert_eq!(
            (before.totals, before.next, before.sequence),
            (totals(end as u64), end as u64 + 1, end as u64)
        );
        assert_eq!(before.gate_sequence, g0.checked_add(end as u64).unwrap());
        assert_eq!(controller.history().unwrap(), armed);
        if base == 32 {
            assert_eq!(saved(&batches[0]), *first_saved.as_ref().unwrap());
        }
        let cursor = attached.drain_cursor;
        let records = controller
            .owner(&epoch)
            .unwrap()
            .records()
            .collect::<Vec<_>>();
        assert_eq!(controller.owner(&epoch).unwrap().reservations(), 0);
        // A valid-input extra call is refused before the gate: it earns no call,
        // reservation, completion or sequence credit and must not poison drain.
        assert_eq!(
            unsafe { attached.invoke_integer_leaf(slice) },
            Err(error(Cause::Capacity))
        );
        capacity_refusals += 1;
        assert_eq!(snapshot(&attached, &gate), before);
        assert_eq!(attached.drain_cursor, cursor);
        assert_eq!(controller.history().unwrap(), armed);
        assert_eq!(
            controller
                .owner(&epoch)
                .unwrap()
                .records()
                .collect::<Vec<_>>(),
            records
        );
        assert_eq!(controller.owner(&epoch).unwrap().reservations(), 0);
        assert_eq!(*input, before_input);

        let batch = attached
            .drain_completed()
            .unwrap()
            .expect("full completed batch");
        let copy = saved(&batch);
        assert_eq!(copy.identity, initial.identity);
        assert_eq!(copy.number, (end / 32) as u64);
        assert_eq!(copy.totals, (totals(base as u64), totals(end as u64)));
        assert_eq!(copy.sequences, (base as u64, end as u64));
        assert_eq!(copy.next, end as u64 + 1);
        assert_eq!(copy.gate_sequence, g0.checked_add(end as u64).unwrap());
        assert_eq!(copy.raw_range, base as u64..end as u64);
        assert_eq!(copy.event_range, 2 * base as u64..2 * end as u64);
        assert_eq!(batch.rows(), before.rows);
        assert_eq!(batch.rows(), &rows[base..end]);
        assert_eq!(batch.journal(), before.journal);
        let mut expected_page = empty_page;
        expected_page[0] = 64;
        for (lifetime, &(actual_id, actual)) in calls.iter().enumerate().take(end).skip(base) {
            assert_eq!(actual_id, requests[lifetime].0);
            for side in 0..2 {
                let offset = 4 + ((lifetime - base) * 2 + side) * 7;
                expected_page[offset..offset + 7].copy_from_slice(&[
                    1 + side as u64,
                    lifetime as u64 + 1,
                    if side == 0 { entry } else { actual.return_pc },
                    actual.entry_rsp,
                    continuation,
                    generation.get(),
                    (lifetime as u64 + 1) | (1 << 13),
                ]);
            }
        }
        assert_eq!(batch.journal(), expected_page); // All 512 words, including zero tail.
        let mut after = before.clone();
        after.rows.clear();
        after.journal = empty_page;
        assert_eq!(snapshot(&attached, &gate), after);
        assert_eq!(controller.history().unwrap(), armed);
        assert_eq!(
            controller
                .owner(&epoch)
                .unwrap()
                .records()
                .collect::<Vec<_>>(),
            records
        );
        assert_eq!(controller.owner(&epoch).unwrap().reservations(), 0);
        assert!(controller.report(&epoch).unwrap().is_none());
        batches.push(batch);
        if end == 32 {
            first_saved = Some(copy);
            empty_drain(&mut attached, &gate, &controller);
            empty_drains += 1;
        } else {
            assert_eq!(saved(&batches[0]), *first_saved.as_ref().unwrap());
        }
    }
    assert_eq!(
        (
            originals.len(),
            calls.len(),
            rows.len(),
            batches.len(),
            capacity_refusals
        ),
        (64, 64, 64, 2, 2)
    );
    assert_eq!(
        rows.iter().map(|r| r.return_pc).collect::<BTreeSet<_>>(),
        returns
    );
    assert_eq!(
        batches
            .iter()
            .flat_map(|b| b.rows().iter().copied())
            .collect::<Vec<_>>(),
        rows
    );
    controller.disarm(&epoch).unwrap();
    let mut final_history = armed.clone();
    final_history.current = None;
    final_history.actions.push(Action {
        kind: ActionKind::Removed,
        generation,
        function: None,
        current: None,
        group: None,
    });
    assert_eq!(controller.history().unwrap(), final_history);
    let report = controller
        .report(&epoch)
        .unwrap()
        .expect("all 64 actual completions");
    check_report(&report, &rows, generation.get(), 0);
    let records = report.records().collect::<Vec<_>>();
    assert_eq!(records.len(), COUNT);
    empty_drain(&mut attached, &gate, &controller);
    empty_drains += 1;
    assert_eq!(report.records().collect::<Vec<_>>(), records);
    assert_eq!(saved(&batches[0]), *first_saved.as_ref().unwrap());
    let final_state = snapshot(&attached, &gate);
    assert_eq!(
        (final_state.totals, final_state.next, final_state.sequence),
        (totals(64), 65, 64)
    );
    assert_eq!(final_state.journal_address, journal_address);
    assert_eq!(final_state.journal, empty_page);
    assert!(final_state.rows.is_empty());
    assert_eq!(final_state.gate_sequence, g0.checked_add(64).unwrap());
    assert_eq!(
        (empty_drains, controller.binding.session.retained_epochs()),
        (3, 1)
    );
    assert_eq!(attached.detach().unwrap(), totals(64));
    assert!(!attached.active);
    assert!(STATE.with(|cell| cell.borrow().is_none()));
    assert!(!POISONED.get());
    assert_eq!(*input, before_input);
    assert_eq!(Arc::strong_count(&input), 1);
    println!(
        "drain-native PASS originals=64 calls=64 sampled=64 batches=2 rows=64 events=128 actions=2 registrations=1 capacity_refusals=2 empty_drains=3 report_records=64 detached=true input_unchanged=true"
    );
}
