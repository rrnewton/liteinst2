//! One finite native history/owner qualification; no full-state or timing credit.
use super::*;
use std::ops::Range;

const INSTALL: u64 = 0x0068_6973_7401;
const INPUTS: [usize; 2] = [1, 64];
const CONFIG: Config = Config {
    retained_per_function: 1,
    max_inflight: 1,
    max_invocations: 2,
};

fn totals(n: u64) -> PairTotals {
    PairTotals {
        entries: n,
        returns: n,
        completed: n,
        unsampled: 0,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct WorkerState {
    identity: (u32, u64, u64, u64, FunctionId),
    journal_address: u64,
    totals: PairTotals,
    next: u64,
    sequence: u64,
    gate_sequence: u64,
    rows: Vec<RawInterval>,
    journal: [u64; 512],
}
fn worker_state(attached: &IntervalThread, gate: &CallGate) -> WorkerState {
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
        WorkerState {
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
            // The owning worker is outside generated execution and holds this TLS borrow.
            journal: state.journal.page.0,
        }
    })
}

struct Fixture {
    // Resume/close/join first on every failure; no controller or data can die
    // while its worker may execute the process-lived published installation.
    worker: Worker,
    controller: IntervalController,
    ack: mpsc::Receiver<(u64, IntervalBatch)>,
    initial: WorkerState,
    input: Arc<[u8; 96]>,
    input_before: [u8; 96],
    originals: Vec<u64>,
    entry: u64,
    continuation: u64,
    returns: BTreeSet<u64>,
}
impl Fixture {
    fn new() -> Self {
        let candidate = std::env::var_os("RAPID_CONCURRENT_CANDIDATE").expect("candidate ELF");
        let expected =
            std::env::var_os("RAPID_CONCURRENT_EXPECTED").expect("independent expected ELF");
        let candidate = Path::new(&candidate);
        let bytes = expected_file(candidate, Path::new(&expected));
        let cpu = pin(None);
        // SAFETY: one exact test in a fresh process; trusted constructor/dependency-
        // free DSO, no foreign entry, CET, signal, unwind, alias writer or unload.
        let owner = unsafe {
            LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum_nonempty", CONTRACT)
        }
        .unwrap();
        let entry = owner.entry();
        let returns: BTreeSet<_> = owner.certificate().returns().iter().copied().collect();
        let gate = CallGate::new(owner.certificate()).unwrap();
        let continuation = gate.continuation();
        let mut prep =
            OrdinarySitePreparation::new(owner, Arc::clone(&gate), identity(entry)).unwrap();
        assert_eq!(
            prep.role_pcs().collect::<Vec<_>>(),
            std::iter::once(entry)
                .chain(returns.iter().copied())
                .collect::<Vec<_>>()
        );
        let input_before = guarded();
        let input = Arc::new(input_before);
        let readable = stack();
        let mut originals = Vec::with_capacity(2);
        for length in INPUTS {
            let slice = &input[16..16 + length];
            // SAFETY: exclusive original code, immutable valid input, actual mapped
            // stack and ordinary SysV return; no asynchronous entry/nonlocal exit.
            let call =
                unsafe { prep.invoke_original(slice.as_ptr(), slice.len(), &readable) }.unwrap();
            assert_eq!(call.value, model(slice));
            assert_eq!(call.pre_call_rsp, call.resumed_rsp);
            assert_eq!(*input, input_before);
            originals.push(call.value);
        }
        let prepared = PreparedIntervalController::new_streaming_history(
            publish(prep),
            INSTALL,
            FUNCTION,
            Limits {
                epochs: 2,
                threads: 1,
                depth: 1,
                records_per_epoch: 2,
                actions: 8,
            },
        )
        .unwrap();
        // SAFETY: no fork, attachment, callback or outstanding call; only the
        // guarded worker below receives invocation authority after publication.
        let (controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
        let pause = Arc::new(EntryPause::new(1));
        assert!(
            controller
                .binding
                .native_entry_pause
                .set(Arc::clone(&pause))
                .is_ok()
        );
        let (command_tx, command_rx) = mpsc::sync_channel(1);
        // Exactly two exports fit even if the controller unwinds before receiving.
        let (ack_tx, ack) = mpsc::sync_channel(2);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker_input = Arc::clone(&input);
        let handle = thread::spawn(move || {
            pin(Some(cpu));
            let readable = stack();
            // SAFETY: sole worker; sealed code/input/actual stack live through
            // every RET. No reentry, signal, nonlocal exit or source mutation.
            let mut attached =
                unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
            let initial = worker_state(&attached, &gate);
            assert_eq!(
                initial.identity,
                (std::process::id(), tid(), 1, INSTALL, FUNCTION)
            );
            assert_eq!(
                (initial.totals, initial.next, initial.sequence),
                (totals(0), 1, 0)
            );
            assert!(initial.rows.is_empty());
            let mut empty = [0_u64; 512];
            empty[2] = initial.identity.1;
            assert_eq!(initial.journal, empty);
            let identity = initial.identity;
            let journal_address = initial.journal_address;
            let g0 = initial.gate_sequence;
            let mut calls = Vec::with_capacity(2);
            let mut rows = Vec::with_capacity(2);
            ready_tx.send(initial).unwrap();
            for (index, length) in INPUTS.into_iter().enumerate() {
                let id = 1000 + index as u64;
                assert_eq!(command_rx.recv_timeout(WAIT).unwrap(), (id, length));
                assert!(attached.raw_intervals().unwrap().is_empty());
                let slice = &worker_input[16..16 + length];
                // SAFETY: fixed trusted leaf, immutable nonempty input and real CALL gate.
                let call = unsafe { attached.invoke_integer_leaf(slice) }.unwrap();
                assert_eq!(call.value, model(slice));
                assert_eq!(call.pre_call_rsp, call.resumed_rsp);
                assert_eq!(call.entry_rsp.checked_add(8), Some(call.pre_call_rsp));
                assert_eq!(*worker_input, input_before);
                let mut before = worker_state(&attached, &gate);
                let n = index as u64 + 1;
                assert_eq!(before.identity, identity);
                assert_eq!(before.journal_address, journal_address);
                assert_eq!(
                    (before.totals, before.next, before.sequence),
                    (totals(n), n + 1, n)
                );
                assert_eq!(before.gate_sequence, g0.checked_add(n).unwrap());
                assert_eq!(before.rows.len(), 1);
                assert_eq!(before.rows[0].ordinal, n);
                rows.push(before.rows[0]);
                calls.push(call);
                let batch = attached
                    .drain_completed()
                    .unwrap()
                    .expect("completed actual return");
                assert_eq!(batch.rows(), before.rows);
                assert_eq!(batch.journal(), before.journal);
                before.rows.clear();
                before.journal = empty;
                assert_eq!(worker_state(&attached, &gate), before);
                ack_tx.send((id, batch)).unwrap();
            }
            let final_state = worker_state(&attached, &gate);
            assert_eq!(final_state.totals, totals(2));
            assert!(final_state.rows.is_empty());
            assert_eq!(final_state.journal, empty);
            assert_eq!(attached.detach().unwrap(), totals(2));
            assert!(STATE.with(|cell| cell.borrow().is_none()));
            assert!(!POISONED.get());
            Done {
                calls,
                rows,
                totals: final_state.totals,
                journal: final_state.journal,
                tid: identity.1,
            }
        });
        let worker = Worker {
            commands: Some(command_tx),
            pause,
            handle: Some(handle),
        };
        let initial = ready_rx.recv_timeout(WAIT).expect("attached worker ready");
        Self {
            worker,
            controller,
            ack,
            initial,
            input,
            input_before,
            originals,
            entry,
            continuation,
            returns,
        }
    }
    fn send(&self, index: usize) {
        self.worker
            .commands
            .as_ref()
            .unwrap()
            .send((1000 + index as u64, INPUTS[index]))
            .unwrap();
    }
    fn receive(&self, index: usize) -> IntervalBatch {
        let (id, batch) = self.ack.recv_timeout(WAIT).unwrap();
        assert_eq!(id, 1000 + index as u64);
        assert_eq!(batch.rows().len(), 1);
        assert_eq!(batch.rows()[0].ordinal, index as u64 + 1);
        batch
    }
}

#[derive(Debug, Eq, PartialEq)]
struct OwnerState {
    retained: usize,
    slots: Vec<Option<(GenerationId, usize)>>,
}
fn owners(c: &IntervalController) -> OwnerState {
    OwnerState {
        retained: c.binding.session.retained_epochs(),
        slots: c
            .epochs
            .iter()
            .map(|o| o.as_ref().map(|e| (e.generation(), e.reservations())))
            .collect(),
    }
}
fn action(kind: ActionKind, generation: GenerationId) -> Action {
    Action {
        kind,
        generation,
        function: None,
        current: (kind == ActionKind::Published).then_some(generation),
        group: None,
    }
}
// Independent finite replay, not the production stamp or HistoryBatch::binding_at.
fn advance(binding: HistoryBinding, row: &Action, index: u64) -> Option<HistoryBinding> {
    if row.function.is_some() || row.group.is_some() {
        return None;
    }
    match row.kind {
        ActionKind::Published if row.current == Some(row.generation) => {
            Some(HistoryBinding::Published {
                action_index: index,
                generation: row.generation,
            })
        }
        ActionKind::Removed
            if row.current.is_none()
                && matches!(binding, HistoryBinding::Published { generation, .. } if generation == row.generation) =>
        {
            Some(HistoryBinding::Removed {
                action_index: index,
                generation: row.generation,
            })
        }
        _ => None,
    }
}
fn binding_at(actions: &[Action], prefix: u64) -> Option<HistoryBinding> {
    let end = usize::try_from(prefix).ok()?;
    let mut binding = HistoryBinding::Initial;
    for (index, row) in actions.get(..end)?.iter().enumerate() {
        binding = advance(binding, row, index as u64)?;
    }
    Some(binding)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SavedHistory {
    stream: HistoryStream,
    number: u64,
    range: Range<u64>,
    before: HistoryBinding,
    after: HistoryBinding,
    actions: Vec<Action>,
}
fn saved_history(batch: &HistoryBatch) -> SavedHistory {
    SavedHistory {
        stream: batch.stream().clone(),
        number: batch.number(),
        range: batch.range(),
        before: batch.before(),
        after: batch.after(),
        actions: batch.actions().to_vec(),
    }
}
fn unchanged(batch: &HistoryBatch, saved: &SavedHistory) {
    assert_eq!(batch.stream(), &saved.stream);
    assert_eq!(batch.number(), saved.number);
    assert_eq!(batch.range(), saved.range);
    assert_eq!(batch.before(), saved.before);
    assert_eq!(batch.after(), saved.after);
    assert_eq!(batch.actions(), saved.actions);
}
fn replay(chunks: &[SavedHistory], expected: &[Action]) -> Option<HistoryBinding> {
    let stream = &chunks.first()?.stream;
    let mut end = 0_usize;
    let mut binding = HistoryBinding::Initial;
    for (index, chunk) in chunks.iter().enumerate() {
        if &chunk.stream != stream
            || chunk.number != index as u64 + 1
            || chunk.range.start != end as u64
            || chunk.before != binding
            || chunk.actions.is_empty()
            || chunk.actions.len() > 8
        {
            return None;
        }
        let next = end.checked_add(chunk.actions.len())?;
        if chunk.range.end != next as u64 || chunk.actions != expected.get(end..next)? {
            return None;
        }
        for (offset, row) in chunk.actions.iter().enumerate() {
            binding = advance(binding, row, (end + offset) as u64)?;
        }
        if chunk.after != binding {
            return None;
        }
        end = next;
    }
    (end == expected.len()).then_some(binding)
}
fn pair_words(actions: &[Action], entry: u64, exit: u64, generation: GenerationId) -> bool {
    let prefix = ((entry >> 13) & 0x1ff) | ((entry >> 24) << 9);
    entry == exit
        && entry & 0x1fff == 1
        && (entry >> 22) & 3 == 0
        && matches!(binding_at(actions, prefix), Some(HistoryBinding::Published { generation: owner, .. }) if owner == generation)
}
#[derive(Debug, Eq, PartialEq)]
struct SavedInterval {
    identity: (u32, u64, u64, u64, FunctionId),
    number: u64,
    totals: (PairTotals, PairTotals),
    completed: (u64, u64),
    next: u64,
    gate: u64,
    raw: Range<u64>,
    events: Range<u64>,
    rows: Vec<RawInterval>,
    journal: Vec<u64>,
    stream: Option<HistoryStream>,
    high_water: Option<u64>,
    prefixes: [Option<u64>; 3],
}
fn saved_interval(batch: &IntervalBatch) -> SavedInterval {
    SavedInterval {
        identity: (
            batch.pid(),
            batch.tid(),
            batch.registration(),
            batch.install(),
            batch.function(),
        ),
        number: batch.number(),
        totals: batch.totals(),
        completed: batch.completed_sequences(),
        next: batch.next_ordinal(),
        gate: batch.gate_sequence(),
        raw: batch.raw_range(),
        events: batch.event_range(),
        rows: batch.rows().to_vec(),
        journal: batch.journal().to_vec(),
        stream: batch.history_stream().cloned(),
        high_water: batch.history_high_water(),
        prefixes: [
            batch.history_prefix(0),
            batch.history_prefix(1),
            batch.history_prefix(2),
        ],
    }
}
struct HistoryLog {
    batches: Vec<HistoryBatch>,
    saved: Vec<SavedHistory>,
    expected: Vec<Action>,
    generations: Vec<GenerationId>,
    max_resident: usize,
}
impl HistoryLog {
    fn new() -> Self {
        Self {
            batches: Vec::with_capacity(77),
            saved: Vec::with_capacity(77),
            expected: Vec::with_capacity(600),
            generations: Vec::with_capacity(300),
            max_resident: 0,
        }
    }
    fn staged(&mut self, epoch: &IntervalEpoch) {
        assert!(
            self.generations
                .last()
                .is_none_or(|g| g.get() < epoch.generation().get())
        );
        self.generations.push(epoch.generation());
    }
    fn pushed(&mut self, kind: ActionKind, epoch: &IntervalEpoch, c: &IntervalController) {
        self.expected.push(action(kind, epoch.generation()));
        let window = c.history_window().unwrap();
        self.max_resident = self.max_resident.max(window.actions().len());
        assert!(window.actions().len() <= 8);
        assert_eq!(window.status(), ControllerStatus::Ready);
        assert_eq!(window.enabled(), [true]);
        assert_eq!(window.retained_failed_generation(), None);
        assert_eq!(window.range().end, self.expected.len() as u64);
        assert_eq!(
            window.actions(),
            &self.expected[usize::try_from(window.range().start).unwrap()..]
        );
        assert_eq!(
            window.before(),
            binding_at(&self.expected, window.range().start).unwrap()
        );
        assert_eq!(
            window.after(),
            binding_at(&self.expected, window.range().end).unwrap()
        );
        assert_eq!(window.current(), self.expected.last().unwrap().current);
        assert_eq!(window.last_batch_number(), self.batches.len() as u64);
        for (batch, saved) in self.batches.iter().zip(&self.saved) {
            unchanged(batch, saved);
        }
    }
    fn drain(&mut self, c: &mut IntervalController) {
        let before = c.history_window().unwrap();
        let held = owners(c);
        assert!(!before.actions().is_empty());
        let batch = c.drain_history().unwrap().expect("nonempty history");
        assert_eq!(batch.range(), before.range());
        assert_eq!(batch.before(), before.before());
        assert_eq!(batch.after(), before.after());
        assert_eq!(batch.actions(), before.actions());
        assert_eq!(batch.stream(), before.stream());
        assert_eq!(batch.stream().format(), HistoryFormat::AbsoluteV1);
        assert_eq!(
            (
                batch.stream().pid(),
                batch.stream().install(),
                batch.stream().function()
            ),
            (std::process::id(), INSTALL, FUNCTION)
        );
        assert_eq!(batch.number(), self.batches.len() as u64 + 1);
        if let Some(previous) = self.batches.last() {
            assert!(batch.follows(previous));
        }
        for prefix in batch.range().start..=batch.range().end {
            assert_eq!(batch.binding_at(prefix), binding_at(&self.expected, prefix));
        }
        self.saved.push(saved_history(&batch));
        self.batches.push(batch);
        assert_eq!(
            replay(&self.saved, &self.expected),
            binding_at(&self.expected, self.expected.len() as u64)
        );
        let after = c.history_window().unwrap();
        assert_eq!(after.stream(), before.stream());
        assert_eq!(after.range(), before.range().end..before.range().end);
        assert_eq!(after.before(), before.after());
        assert_eq!(after.after(), before.after());
        assert!(after.actions().is_empty());
        assert_eq!(after.last_batch_number(), self.batches.len() as u64);
        assert_eq!(after.status(), before.status());
        assert_eq!(after.current(), before.current());
        assert_eq!(after.enabled(), before.enabled());
        assert_eq!(
            after.retained_failed_generation(),
            before.retained_failed_generation()
        );
        assert_eq!(owners(c), held);
        for (batch, saved) in self.batches.iter().zip(&self.saved) {
            unchanged(batch, saved);
        }
    }
    fn drain_full(&mut self, c: &mut IntervalController) {
        if c.history_window().unwrap().actions().len() == 8 {
            self.drain(c);
        }
    }
}

#[test]
#[ignore = "requires release fixture reproducer"]
fn ordinary_native_history_stream_old_owner() {
    let mut log = HistoryLog::new(); // All outer capacity exists before the paused interval.
    let mut fixture = Fixture::new();
    let c = &mut fixture.controller;
    assert!(matches!(
        c.history(),
        Err(BridgeError {
            cause: Cause::Control(ControlError::HistoryMode)
        })
    ));
    let first = c.stage(CONFIG).unwrap();
    log.staged(&first);
    assert_eq!(first.index, 0);
    c.arm(&first).unwrap();
    log.pushed(ActionKind::Published, &first, c);
    fixture.send(0);
    until(|| fixture.worker.pause.entered.load(Ordering::Acquire));
    assert!(matches!(
        fixture.ack.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(!fixture.worker.handle.as_ref().unwrap().is_finished());
    assert_eq!(fixture.controller.owner(&first).unwrap().reservations(), 1);
    log.drain(&mut fixture.controller);
    let before = fixture.controller.history_window().unwrap();
    let held = owners(&fixture.controller);
    assert!(fixture.controller.drain_history().unwrap().is_none());
    assert_eq!(fixture.controller.history_window().unwrap(), before);
    assert_eq!(owners(&fixture.controller), held);
    fixture.controller.disarm(&first).unwrap();
    log.pushed(ActionKind::Removed, &first, &fixture.controller);
    let before = fixture.controller.history_window().unwrap();
    let held = owners(&fixture.controller);
    assert!(fixture.controller.report(&first).unwrap().is_none());
    assert!(matches!(
        fixture.controller.retire(&first),
        Err(BridgeError {
            cause: Cause::NotDrained
        })
    ));
    assert_eq!(fixture.controller.history_window().unwrap(), before);
    assert_eq!(owners(&fixture.controller), held);
    let mut full_refusals = 0;
    let mut stale = None;
    for _ in 0..298 {
        assert_eq!(fixture.controller.binding.session.retained_epochs(), 1);
        let epoch = fixture.controller.stage(CONFIG).unwrap();
        assert_eq!(epoch.index, 1);
        log.staged(&epoch);
        fixture.controller.arm(&epoch).unwrap();
        log.pushed(ActionKind::Published, &epoch, &fixture.controller);
        if log.expected.len() == 9 {
            let before = fixture.controller.history_window().unwrap();
            let held = owners(&fixture.controller);
            assert_eq!(before.range(), 1..9);
            assert_eq!(before.actions().len(), 8);
            assert!(matches!(
                fixture.controller.disarm(&epoch),
                Err(BridgeError {
                    cause: Cause::Control(ControlError::HistoryFull)
                })
            ));
            assert_eq!(fixture.controller.history_window().unwrap(), before);
            assert_eq!(owners(&fixture.controller), held);
            full_refusals += 1;
        }
        log.drain_full(&mut fixture.controller);
        fixture.controller.disarm(&epoch).unwrap(); // Same operation after the explicit full drain.
        log.pushed(ActionKind::Removed, &epoch, &fixture.controller);
        log.drain_full(&mut fixture.controller);
        let before = fixture.controller.history_window().unwrap();
        let report = fixture.controller.retire(&epoch).unwrap();
        assert_eq!(report.generation(), epoch.generation());
        assert_eq!(report.records().count(), 0);
        assert_eq!(fixture.controller.history_window().unwrap(), before);
        assert_eq!(fixture.controller.binding.session.retained_epochs(), 2);
        drop(report);
        assert_eq!(fixture.controller.binding.session.retained_epochs(), 1);
        if stale.is_none() {
            stale = Some(epoch);
        }
        assert_eq!(fixture.controller.owner(&first).unwrap().reservations(), 1);
        assert!(fixture.controller.report(&first).unwrap().is_none());
    }
    assert_eq!(log.expected.len(), 598);
    assert_eq!(full_refusals, 1);
    let second = fixture.controller.stage(CONFIG).unwrap();
    assert_eq!(second.index, 1);
    log.staged(&second);
    fixture.controller.arm(&second).unwrap();
    log.pushed(ActionKind::Published, &second, &fixture.controller);
    assert_eq!(
        fixture.controller.history_window().unwrap().range(),
        593..599
    );
    log.drain(&mut fixture.controller);
    let before = fixture.controller.history_window().unwrap();
    let held = owners(&fixture.controller);
    assert!(matches!(
        fixture.controller.report(stale.as_ref().unwrap()),
        Err(BridgeError {
            cause: Cause::Epoch
        })
    ));
    assert_eq!(fixture.controller.history_window().unwrap(), before);
    assert_eq!(owners(&fixture.controller), held);
    assert!(matches!(
        fixture.ack.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    fixture.worker.pause.resume.store(true, Ordering::Release);
    let first_batch = fixture.receive(0); // Full actual return and completed-buffer postcheck.
    let first_saved = saved_interval(&first_batch);
    let old = fixture.controller.retire(&first).unwrap();
    let old_records: Vec<_> = old.records().collect();
    check_report(&old, first_batch.rows(), first.generation().get(), 0);
    let before = fixture.controller.history_window().unwrap();
    let held = owners(&fixture.controller);
    assert!(fixture.controller.epochs[0].is_none());
    assert_eq!(held.retained, 2);
    assert!(matches!(
        fixture.controller.stage(CONFIG),
        Err(BridgeError {
            cause: Cause::Setup(SetupError::EpochLimit)
        })
    ));
    assert_eq!(fixture.controller.history_window().unwrap(), before);
    assert_eq!(owners(&fixture.controller), held);
    fixture.send(1);
    let second_batch = fixture.receive(1);
    let second_saved = saved_interval(&second_batch);
    fixture.controller.disarm(&second).unwrap();
    log.pushed(ActionKind::Removed, &second, &fixture.controller);
    assert_eq!(
        fixture.controller.history_window().unwrap().range(),
        599..600
    );
    log.drain(&mut fixture.controller);
    let new = fixture.controller.retire(&second).unwrap();
    check_report(&new, second_batch.rows(), second.generation().get(), 1);
    assert_eq!(old.records().collect::<Vec<_>>(), old_records);
    let done = fixture.worker.join();
    assert_eq!(*fixture.input, fixture.input_before);
    assert_eq!(Arc::strong_count(&fixture.input), 1);
    assert_eq!(done.totals, totals(2));
    assert_eq!((done.calls.len(), done.rows.len()), (2, 2));
    let batches = [first_batch, second_batch];
    assert_eq!(saved_interval(&batches[0]), first_saved);
    assert_eq!(saved_interval(&batches[1]), second_saved);
    let prefixes = [1_u64, 599];
    let words = [8193_u64, 17_489_921];
    let generations = [first.generation(), second.generation()];
    for (index, batch) in batches.iter().enumerate() {
        let n = index as u64;
        let call = &done.calls[index];
        let row = done.rows[index];
        assert_eq!(
            (
                batch.pid(),
                batch.tid(),
                batch.registration(),
                batch.install(),
                batch.function()
            ),
            fixture.initial.identity
        );
        assert_eq!(batch.history_stream(), Some(log.batches[0].stream()));
        assert_eq!(batch.history_high_water(), Some(599));
        assert_eq!(batch.history_prefix(0), Some(prefixes[index]));
        assert_eq!(batch.history_prefix(1), Some(prefixes[index]));
        assert_eq!(batch.history_prefix(2), None);
        assert_eq!(batch.number(), n + 1);
        assert_eq!(batch.totals(), (totals(n), totals(n + 1)));
        assert_eq!(batch.completed_sequences(), (n, n + 1));
        assert_eq!(batch.next_ordinal(), n + 2);
        assert_eq!(
            batch.gate_sequence(),
            fixture.initial.gate_sequence.checked_add(n + 1).unwrap()
        );
        assert_eq!(batch.raw_range(), n..n + 1);
        assert_eq!(batch.event_range(), 2 * n..2 * n + 2);
        assert_eq!(batch.rows(), [row]);
        assert_eq!(row.ordinal, n + 1);
        assert_eq!(
            (row.entry_pc, row.return_pc),
            (fixture.entry, call.return_pc)
        );
        assert_eq!(
            row.owner,
            RawIntervalOwner::Sampled {
                generation: generations[index].get(),
                invocation: 0
            }
        );
        assert_eq!(call.value, fixture.originals[index]);
        assert_eq!(call.pre_call_rsp, call.resumed_rsp);
        assert_eq!(call.entry_rsp.checked_add(8), Some(call.pre_call_rsp));
        assert!(
            row.elapsed_ticks().is_some(),
            "clock failure is not timing success"
        );
        assert_eq!(
            words[index],
            1 | ((prefixes[index] & 0x1ff) << 13) | ((prefixes[index] >> 9) << 24)
        );
        let mut page = [0_u64; 512];
        page[..4].copy_from_slice(&[2, 0, done.tid, 0]);
        for side in 0..2 {
            let offset = 4 + side * 7;
            page[offset..offset + 7].copy_from_slice(&[
                1 + side as u64,
                n + 1,
                if side == 0 {
                    fixture.entry
                } else {
                    call.return_pc
                },
                call.entry_rsp,
                fixture.continuation,
                generations[index].get(),
                words[index],
            ]);
        }
        assert_eq!(batch.journal(), page); // Every word, including the entire zero tail.
        assert!(pair_words(
            &log.expected,
            page[10],
            page[17],
            generations[index]
        ));
    }
    assert_eq!(
        done.rows
            .iter()
            .map(|r| r.return_pc)
            .collect::<BTreeSet<_>>(),
        fixture.returns
    );
    let mut empty = [0; 512];
    empty[2] = done.tid;
    assert_eq!(done.journal, empty);
    assert_eq!(
        (
            log.generations.len(),
            log.expected.len(),
            log.batches.len(),
            log.max_resident
        ),
        (300, 600, 77, 8)
    );
    assert_eq!(
        log.expected,
        log.generations
            .iter()
            .flat_map(|&g| [
                action(ActionKind::Published, g),
                action(ActionKind::Removed, g)
            ])
            .collect::<Vec<_>>()
    );
    let ranges: Vec<Range<u64>> = std::iter::once(0..1)
        .chain((0..74).map(|j| 1 + 8 * j..9 + 8 * j))
        .chain([593..599, 599..600])
        .collect();
    assert_eq!(
        log.batches
            .iter()
            .map(HistoryBatch::range)
            .collect::<Vec<_>>(),
        ranges
    );
    let final_binding = HistoryBinding::Removed {
        action_index: 599,
        generation: second.generation(),
    };
    assert_eq!(replay(&log.saved, &log.expected), Some(final_binding));
    let window = fixture.controller.history_window().unwrap();
    assert_eq!(window.range(), 600..600);
    assert_eq!(window.before(), final_binding);
    assert_eq!(window.after(), final_binding);
    assert_eq!(window.current(), None);
    assert_eq!(window.status(), ControllerStatus::Ready);
    assert_eq!(window.enabled(), [true]);
    assert_eq!(window.retained_failed_generation(), None);
    assert_eq!(window.last_batch_number(), 77);
    assert!(window.actions().is_empty());
    let held = owners(&fixture.controller);
    assert!(fixture.controller.drain_history().unwrap().is_none());
    assert_eq!(fixture.controller.history_window().unwrap(), window);
    assert_eq!(owners(&fixture.controller), held);
    assert!(fixture.controller.epochs.iter().all(Option::is_none));
    assert_eq!(fixture.controller.binding.session.retained_epochs(), 2);
    drop(old);
    assert_eq!(fixture.controller.binding.session.retained_epochs(), 1);
    drop(new);
    assert_eq!(fixture.controller.binding.session.retained_epochs(), 0);
    assert_eq!(saved_interval(&batches[0]), first_saved);
    assert_eq!(saved_interval(&batches[1]), second_saved);
    for (batch, saved) in log.batches.iter().zip(&log.saved) {
        unchanged(batch, saved);
    }
    // Tamper only copied export values. The same full replay must reject them.
    let mut missing = log.saved.clone();
    missing.remove(1);
    assert_eq!(replay(&missing, &log.expected), None);
    let mut duplicate = log.saved.clone();
    duplicate[1] = duplicate[0].clone();
    assert_eq!(replay(&duplicate, &log.expected), None);
    assert!(!pair_words(
        &log.expected,
        words[1] & !(1 << 24),
        words[1] & !(1 << 24),
        second.generation()
    ));
    assert!(!pair_words(
        &log.expected,
        words[0],
        words[1],
        first.generation()
    ));
    println!(
        "history-native PASS originals=2 calls=2 sampled=2 rows=2 events=4 actions=600 history_batches=77 max_resident=8 epochs=300 retired=300 replacements=298 interval_batches=2 registrations=1 old_prefix=1 new_prefix=599 history_full_refusals=1 not_drained_refusals=1 report_permit_refusals=1 stale_refusals=1 empty_drains=2 replay_refusals=4 joined=true"
    );
}
