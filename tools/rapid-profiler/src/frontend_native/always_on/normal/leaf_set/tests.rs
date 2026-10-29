//! Real Session/receipt metadata controls only. No fabricated loaded owner,
//! opaque callback token, physical CALL/RET, publication or scheduling evidence.
use super::*;
use crate::frontend::RecordObservation;
use crate::generation::storage::allocation_probe;
use crate::generation::{Disposition, Terminal};
use liteinst2::contracts::SourceIdentity;

pub(super) const IDS: [FunctionId; 4] = [
    FunctionId(0),
    FunctionId(29),
    FunctionId(31),
    FunctionId(47),
];
pub(super) const ENTRY: [u64; 4] = [0x1000, 0x1100, 0x1200, 0x1300];
const RSP: u64 = 0x8008;
const WORD: u64 = 0x9000;
fn site(n: usize) -> Arc<site::ordinary::LeafSetSite> {
    let geometry: Vec<_> = ENTRY[..n]
        .iter()
        .map(|&entry| (entry, entry + 32, vec![entry + 16, entry + 24]))
        .collect();
    site::ordinary::LeafSetSite::synthetic(
        CodeIdentity {
            source: SourceIdentity([193; 32]),
            mapping: ENTRY[0],
            generation: 1,
        },
        &geometry,
    )
}
fn prepared(n: usize, k: usize) -> PreparedNormalLeafSetSessionController {
    PreparedNormalLeafSetSessionController::prepare(site(n), 71, &IDS[..n], k).unwrap()
}
pub(super) fn controller(
    n: usize,
    k: usize,
) -> (NormalLeafSetSessionController, Vec<IntervalEpochStorage>) {
    let mut p = prepared(n, k);
    let banks = p.prepare_epoch_storage().unwrap();
    // SAFETY: inert metadata only, no publication/native entry/fork.
    let (c, client) = unsafe { p.activate_concurrent() }.unwrap();
    drop(client);
    (c, banks)
}
pub(super) struct Fixture {
    pub(super) state: NormalState,
    pub(super) controller: NormalLeafSetSessionController,
    pub(super) epoch: Option<IntervalEpoch>,
    pub(super) banks: Vec<IntervalEpochStorage>,
}
impl Fixture {
    pub(super) fn new(n: usize, k: usize) -> Self {
        let (mut controller, mut banks) = controller(n, k);
        let epoch = controller.stage_prepared(banks.pop().unwrap()).unwrap();
        let binding = Arc::clone(&controller.0.binding);
        let model = binding.session.register_thread(7).unwrap();
        let mut state = NormalState::new(
            binding,
            7,
            ReadableStack {
                start: 0x7000,
                end: 0x100000,
            },
            IntervalJournal::allocate(),
            model,
        );
        state.journal.header(state.tid, 0);
        controller.arm(&epoch).unwrap();
        Self {
            state,
            controller,
            epoch: Some(epoch),
            banks,
        }
    }
    pub(super) fn enter(&mut self, index: usize) {
        let n = self.state.next;
        let selected = self.state.selection(index).unwrap();
        self.state
            .enter_function(
                selected,
                ENTRY[index],
                RSP,
                WORD + n * 8,
                RawTimestamp {
                    ticks: n * 100,
                    aux: 7,
                },
            )
            .unwrap();
    }
    pub(super) fn observe(&mut self, index: usize) {
        let p = self.state.pending.as_ref().unwrap();
        let (n, word) = (p.ordinal, p.word);
        let selected = self.state.selection(index).unwrap();
        self.state
            .observe_function(
                selected,
                ENTRY[index] + 16 + (n % 2) * 8,
                RSP,
                word,
                RawTimestamp {
                    ticks: n * 100 + 17,
                    aux: 7,
                },
            )
            .unwrap();
    }
    pub(super) fn call(&mut self, index: usize) {
        self.enter(index);
        self.observe(index);
    }
    pub(super) fn transfer(&mut self) -> NormalLeafSetBatch {
        let (out, page) = LeafSetOutput::allocate().unwrap();
        self.state.transfer_into(out, page).unwrap().unwrap()
    }
    fn refused_transfer(&mut self) {
        let before = snapshot(&self.state);
        let (out, page) = LeafSetOutput::allocate().unwrap();
        assert!(self.state.transfer_into(out, page).is_err());
        assert_eq!(snapshot(&self.state), before);
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PendingCopy {
    selected: SelectedFunction,
    ordinal: u64,
    rsp: u64,
    word: u64,
    entry_pc: u64,
    start: RawTimestamp,
    slot: ModelReturnSlot,
    summary: Option<IntervalEntrySummary>,
    actual_summary: Option<IntervalEntrySummary>,
    returned: Option<RawInterval>,
}
#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    pending: Option<PendingCopy>,
    records: [Option<NormalRecord>; CALLS],
    functions: [Option<SelectedFunction>; CALLS],
    journal: [u64; 512],
    len: usize,
    next: u64,
    totals: NormalTotals,
    cursor: Cursor,
    depth: usize,
    sequence: u64,
    retained: usize,
    failure: Option<BridgeError>,
    busy: bool,
}
fn snapshot(s: &NormalState) -> Snapshot {
    Snapshot {
        pending: s.pending.as_ref().map(|p| PendingCopy {
            selected: p.selected,
            ordinal: p.ordinal,
            rsp: p.rsp,
            word: p.word,
            entry_pc: p.entry_pc,
            start: p.start,
            slot: p.slot,
            summary: p.summary,
            actual_summary: p.receipt.summary(),
            returned: p.returned,
        }),
        records: s.records,
        functions: s.functions,
        journal: s.journal.page.0,
        len: s.len,
        next: s.next,
        totals: s.totals,
        cursor: s.cursor,
        depth: s.model.depth(),
        sequence: s.model.completed_sequence(),
        retained: s.binding.session.retained_epochs(),
        failure: s.failure,
        busy: s.busy,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct OwnerCopy {
    generation: GenerationId,
    reservations: usize,
    ready: bool,
    records: Vec<RecordObservation>,
}
#[derive(Debug, Eq, PartialEq)]
struct ControllerCopy {
    window: NormalLeafSetHistoryWindow,
    owners: Vec<Option<OwnerCopy>>,
    retained: usize,
}
fn controller_copy(c: &NormalLeafSetSessionController) -> ControllerCopy {
    ControllerCopy {
        window: c.history_window().unwrap(),
        owners: c
            .0
            .epochs
            .iter()
            .map(|o| {
                o.as_ref().map(|o| OwnerCopy {
                    generation: o.generation(),
                    reservations: o.reservations(),
                    ready: o.try_report().is_some(),
                    records: o.records().collect(),
                })
            })
            .collect(),
        retained: c.0.binding.session.retained_epochs(),
    }
}
fn token(e: &IntervalEpoch) -> (*const (), usize, GenerationId) {
    (Arc::as_ptr(&e.key), e.index, e.generation())
}
fn refuse_reclaim(
    c: &mut NormalLeafSetSessionController,
    e: IntervalEpoch,
    expected: EpochStorageReclaimError,
) -> IntervalEpoch {
    let before = controller_copy(c);
    let key = token(&e);
    let (actual, e) = c.reclaim_storage(e).unwrap_err();
    assert_eq!(actual, expected);
    assert_eq!(token(&e), key);
    assert_eq!(controller_copy(c), before);
    e
}
fn bridge(cause: Cause) -> EpochStorageReclaimError {
    EpochStorageReclaimError::Bridge(error(cause))
}
fn stage_error(
    result: Result<IntervalEpoch, (BridgeError, IntervalEpochStorage)>,
) -> (BridgeError, IntervalEpochStorage) {
    match result {
        Err(pair) => pair,
        Ok(_) => panic!("stage accepted"),
    }
}
pub(super) fn reclaim(
    c: &mut NormalLeafSetSessionController,
    e: IntervalEpoch,
) -> IntervalEpochStorage {
    match c.reclaim_storage(e) {
        Ok(bank) => bank,
        Err((error, _)) => panic!("reclaim refused: {error:?}"),
    }
}

#[test]
fn leaf_set_profile_requires_exact_count_k_history_and_mode() {
    for n in 1..=4 {
        for k in [10, 1000] {
            let (mut c, _) = controller(n, k);
            let (limits, config) = fixed(n, k).unwrap();
            assert!(binding_matches(&c.0.binding));
            assert_eq!(limits.records_per_epoch, n * k);
            for bad in [
                Limits {
                    epochs: 1,
                    ..limits
                },
                Limits {
                    threads: 2,
                    ..limits
                },
                Limits { depth: 2, ..limits },
                Limits {
                    records_per_epoch: n * k + 1,
                    ..limits
                },
                Limits {
                    actions: 7,
                    ..limits
                },
            ] {
                assert!(!profile_matches(&c.0.binding.profile, bad, config));
            }
            for bad in [
                Config {
                    retained_per_function: 16,
                    ..config
                },
                Config {
                    max_inflight: 2,
                    ..config
                },
                Config {
                    max_invocations: n * k + 1,
                    ..config
                },
            ] {
                assert!(!profile_matches(&c.0.binding.profile, limits, bad));
            }
            let b = Arc::get_mut(&mut c.0.binding).unwrap();
            b.entry_mode = EntryMode::NonBlocking;
            assert!(!binding_matches(b));
            b.entry_mode = EntryMode::Concurrent;
            let legacy = Session::new(
                71,
                &IDS[..n]
                    .iter()
                    .map(|&function| FunctionSpec { function, group: 0 })
                    .collect::<Vec<_>>(),
                &[GroupSpec { mandatory: true }],
                limits,
            )
            .unwrap();
            let absolute = std::mem::replace(&mut b.session, legacy);
            assert!(!binding_matches(b));
            b.session = absolute;
            let BindingProfile::LeafSet { functions, .. } = &mut b.profile else {
                panic!()
            };
            if n > 1 {
                functions.ids[n - 1] = functions.ids[0];
            } else {
                functions.ids[3] = FunctionId(3);
            }
            assert!(!binding_matches(b));
        }
    }
    for k in [0, 1, 16, 999, usize::MAX] {
        assert!(
            PreparedNormalLeafSetSessionController::prepare(site(1), 71, &IDS[..1], k).is_err()
        );
    }
    for ids in [vec![], vec![FunctionId(1); 2], vec![FunctionId(1); 5]] {
        assert!(PreparedNormalLeafSetSessionController::prepare(site(1), 71, &ids, 10).is_err());
    }
    assert!(PreparedNormalLeafSetSessionController::prepare(site(4), 71, &IDS[..3], 10).is_err());
}
#[test]
fn leaf_set_banks_prepare_once_and_preserve_refused_identity() {
    let p = prepared(4, 10);
    // SAFETY: refusal before activation, inert metadata.
    assert!(matches!(
        unsafe { p.activate_concurrent() },
        Err(BridgeError {
            cause: Cause::Setup(SetupError::StorageMode)
        })
    ));
    let mut p = prepared(4, 10);
    let count = {
        let _probe = allocation_probe::start(None);
        let banks = p.prepare_epoch_storage().unwrap();
        assert_eq!(banks.len(), 3);
        allocation_probe::calls()
    };
    assert!(p.banks_prepared);
    assert!(p.prepare_epoch_storage().is_err());
    for fail in 0..count {
        let mut p = prepared(4, 10);
        let before = p.inner.session.snapshot_for_bridge().unwrap();
        {
            let _probe = allocation_probe::start(Some(fail));
            assert!(p.prepare_epoch_storage().is_err());
        }
        assert!(!p.banks_prepared);
        assert!(p.inner.epochs.is_empty());
        assert_eq!(p.inner.session.snapshot_for_bridge().unwrap(), before);
        assert_eq!(p.prepare_epoch_storage().unwrap().len(), 3);
    }
    let mut used = prepared(4, 10);
    used.inner.stage(used.config).unwrap();
    assert!(used.prepare_epoch_storage().is_err());
    assert!(!used.banks_prepared);
    let mut registered = prepared(4, 10);
    drop(registered.inner.session.register_thread(7).unwrap());
    assert!(registered.prepare_epoch_storage().is_err());
    assert!(!registered.banks_prepared);
    let (mut c, mut banks) = controller(4, 10);
    let (mut foreign, _) = controller(4, 10);
    let mut bank = banks.pop().unwrap();
    let identity = bank.test_fingerprint();
    assert_ne!(identity, banks[0].test_fingerprint());
    let before = controller_copy(&foreign);
    let (e, b) = stage_error(foreign.stage_prepared(bank));
    bank = b;
    assert_eq!(e, error(Cause::Epoch));
    assert_eq!(bank.test_fingerprint(), identity);
    assert_eq!(controller_copy(&foreign), before);
    let (e, b) = stage_error(c.0.stage_prepared(bank));
    bank = b;
    assert_eq!(e, error(Cause::Identity));
    assert_eq!(bank.test_fingerprint(), identity);
    for cause in [Cause::Process, Cause::Identity, Cause::ControllerReentry] {
        if cause == Cause::Process {
            Arc::get_mut(&mut c.0.binding).unwrap().pid ^= 1;
        }
        if cause == Cause::Identity {
            Arc::get_mut(&mut c.0.binding).unwrap().entry_mode = EntryMode::NonBlocking;
        }
        let before = c.0.binding.session.snapshot_for_bridge();
        let scope = if cause == Cause::ControllerReentry {
            Some(ControllerScope::enter().unwrap())
        } else {
            None
        };
        let (e, b) = stage_error(c.stage_prepared(bank));
        bank = b;
        assert_eq!(e, error(cause));
        assert_eq!(bank.test_fingerprint(), identity);
        assert_eq!(c.0.binding.session.snapshot_for_bridge(), before);
        drop(scope);
        if cause == Cause::Process {
            Arc::get_mut(&mut c.0.binding).unwrap().pid ^= 1;
        }
        if cause == Cause::Identity {
            Arc::get_mut(&mut c.0.binding).unwrap().entry_mode = EntryMode::Concurrent;
        }
    }
    let epoch = c.stage_prepared(bank).unwrap();
    assert!(c.report(&epoch).unwrap().is_none());
}
#[test]
fn leaf_set_runtime_keeps_saved_function_and_closed_receipt() {
    for k in [10, 1000] {
        assert_eq!(IDS.len(), 4);
        for (index, &function) in IDS.iter().enumerate() {
            let mut f = Fixture::new(4, k);
            for i in 0..k {
                f.call(index);
                if (i + 1) % CALLS == 0 {
                    f.transfer();
                }
            }
            f.call(index);
            let mut old = f.epoch.take().unwrap();
            let old_generation = old.generation();
            let next = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
            f.controller.arm(&next).unwrap();
            let report = f.controller.report(&old).unwrap().unwrap();
            let copied: Vec<_> = report.records().collect();
            drop(report);
            assert_eq!(copied.len(), k);
            for (i, row) in copied.iter().enumerate() {
                assert_eq!(row.record.admission.function, function);
                assert_eq!(row.record.admission.invocation, i);
                assert_eq!(
                    row.record.terminal,
                    Some(Terminal::Completed {
                        value: i as u64,
                        disposition: Disposition::Retained { rank: i }
                    })
                );
                let payload = row.payload.unwrap();
                assert_eq!(payload.admission, row.record.admission);
                assert_eq!((payload.thread, payload.start_sequence), (7, i as u64));
            }
            let before = snapshot(&f.state);
            for _ in 0..2 {
                old = refuse_reclaim(
                    &mut f.controller,
                    old,
                    EpochStorageReclaimError::SharedOwner,
                );
            }
            assert_eq!(snapshot(&f.state), before);
            assert_eq!(
                f.controller
                    .report(&old)
                    .unwrap()
                    .unwrap()
                    .records()
                    .collect::<Vec<_>>(),
                copied
            );
            let other = (index + 1) % 4;
            f.enter(other); // actual shared post-auth helper releases old closed owner
            let bank = reclaim(&mut f.controller, old);
            f.observe(other);
            let batch = f.transfer();
            let closed=batch.records().iter().find(|r|matches!(r.record.raw.owner,RawIntervalOwner::FunctionClosed {generation} if generation==old_generation.get())).unwrap();
            assert_eq!(closed.function, function);
            let last = batch.records().last().unwrap();
            assert_eq!(last.function, IDS[other]);
            assert_eq!(
                last.record.raw.owner,
                RawIntervalOwner::Sampled {
                    generation: next.generation().get(),
                    invocation: 0
                }
            );
            f.controller.disarm(&next).unwrap();
            drop(reclaim(&mut f.controller, next));
            f.banks.push(bank);
            assert_eq!(
                (f.state.totals.completed, f.state.totals.unsampled),
                (k as u64 + 1, 1)
            );
        }
    }
}
#[test]
fn leaf_set_transfer_validates_every_row_and_journal_word() {
    for n in 1..=4 {
        let mut f = Fixture::new(n, 10);
        for i in 0..32 {
            f.call(i % n);
        }
        let page = f.state.journal.page.0;
        assert_eq!(&page[..4], &[64, 0, f.state.tid, 1]);
        for (i, &word) in page.iter().enumerate() {
            f.state.journal.word(i, word ^ 1);
            f.refused_transfer();
            f.state.journal.word(i, word);
        }
        if n > 1 {
            for i in 0..f.state.len {
                let saved = f.state.functions[i];
                f.state.functions[i] = Some(f.state.selection((i + 1) % n).unwrap());
                f.refused_transfer();
                f.state.functions[i] = saved;
            }
        }
        let batch = f.transfer();
        let mut expected = page;
        expected[3] = 0;
        assert_eq!(batch.journal(), expected);
        assert_eq!(batch.records().len(), 32);
        for (i, row) in batch.records().iter().enumerate() {
            assert_eq!(row.function, IDS[i % n]);
        }
        assert_eq!(batch.functions(), &IDS[..n]);
        assert_eq!(batch.entries(), &ENTRY[..n]);
        assert_eq!(batch.completed_sequences().1, batch.totals().1.completed);
        assert_eq!(batch.next_ordinal(), 33);
    }
}
#[test]
fn leaf_set_transfer_refusals_leave_receipt_and_cursors_unchanged() {
    let mut f = Fixture::new(4, 10);
    f.call(0);
    f.call(3);
    let before = snapshot(&f.state);
    let window = f.controller.history_window().unwrap();
    for slot in [0, 1] {
        FAIL_RESERVE.set(Some(slot));
        let refused = LeafSetOutput::allocate().is_err();
        FAIL_RESERVE.set(None);
        assert!(refused);
        assert_eq!(snapshot(&f.state), before);
    }
    let (_, page) = LeafSetOutput::allocate().unwrap();
    assert!(
        f.state
            .transfer_into(
                LeafSetOutput {
                    records: Vec::new()
                },
                page
            )
            .is_err()
    );
    assert_eq!(snapshot(&f.state), before);
    let selected = f.state.pending.as_ref().unwrap().selected;
    f.state.pending.as_mut().unwrap().selected = f.state.selection(2).unwrap();
    f.refused_transfer();
    f.state.pending.as_mut().unwrap().selected = selected;
    let raw = f.state.pending.as_ref().unwrap().returned.unwrap();
    f.state
        .pending
        .as_mut()
        .unwrap()
        .returned
        .as_mut()
        .unwrap()
        .return_pc = ENTRY[2] + 16;
    f.refused_transfer();
    f.state.pending.as_mut().unwrap().returned = Some(raw);
    assert_eq!(snapshot(&f.state), before);
    assert_eq!(f.controller.history_window().unwrap(), window);
    assert_eq!(f.transfer().records().len(), 2);
}
#[test]
fn leaf_set_output_captures_complete_identity_before_consumption() {
    let mut f = Fixture::new(4, 1000);
    for i in 0..4 {
        f.call(i);
    }
    let before = snapshot(&f.state);
    let (out, page) = LeafSetOutput::allocate().unwrap();
    let id = out.identity(&f.state).unwrap();
    assert_eq!(snapshot(&f.state), before);
    assert_eq!(id.functions.as_slice(), &IDS);
    assert_eq!(id.entries, ENTRY);
    assert_eq!(id.stream.functions(), &IDS);
    assert_eq!(id.stream.entries(), &ENTRY);
    assert_eq!(id.history_end, 1);
    let expected = id.stream.clone();
    let batch = f.state.transfer_into(out, page).unwrap().unwrap();
    assert_eq!(batch.history_stream(), &expected);
    assert_eq!(batch.history_high_water(), 1);
    assert_eq!(batch.identity(), expected.identity());
    assert_eq!(batch.pid(), expected.pid());
    assert_eq!(batch.install(), expected.install());
    assert_eq!(batch.records().len(), 4);
    assert_eq!(f.state.model.completed_sequence(), 4);
    assert!(f.state.pending.is_none());
}
#[test]
fn leaf_set_reclaim_preserves_shared_owners_and_fresh_generation() {
    let mut f = Fixture::new(4, 10);
    for i in 0..4 {
        f.call(i);
    }
    let batch = f.transfer();
    let mut e = f.epoch.take().unwrap();
    f.controller.disarm(&e).unwrap();
    let report = f.controller.report(&e).unwrap().unwrap();
    let copied: Vec<_> = report.records().collect();
    e = refuse_reclaim(&mut f.controller, e, EpochStorageReclaimError::SharedOwner);
    drop(report);
    let acquired = f.controller.0.owner(&e).unwrap().clone();
    e = refuse_reclaim(&mut f.controller, e, EpochStorageReclaimError::SharedOwner);
    drop(acquired);
    let stale = IntervalEpoch {
        key: Arc::clone(&e.key),
        index: e.index,
        generation: e.generation,
    };
    let bank = reclaim(&mut f.controller, e);
    let fresh = f.controller.stage_prepared(bank).unwrap();
    assert_eq!(fresh.index, stale.index);
    assert!(fresh.generation().get() > stale.generation().get());
    drop(refuse_reclaim(
        &mut f.controller,
        stale,
        bridge(Cause::Epoch),
    ));
    f.controller.arm(&fresh).unwrap();
    f.call(3);
    let new_batch = f.transfer();
    assert_eq!(
        new_batch.records()[0].record.raw.owner,
        RawIntervalOwner::Sampled {
            generation: fresh.generation().get(),
            invocation: 0
        }
    );
    assert_eq!(new_batch.completed_sequences(), (4, 5));
    assert_eq!(new_batch.next_ordinal(), 6);
    f.controller.disarm(&fresh).unwrap();
    let new_report = f.controller.report(&fresh).unwrap().unwrap();
    let rows: Vec<_> = new_report.records().collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].record.admission.function, IDS[3]);
    assert_eq!(
        rows[0].record.terminal,
        Some(Terminal::Completed {
            value: 0,
            disposition: Disposition::Retained { rank: 0 }
        })
    );
    assert_eq!(rows[0].payload.unwrap().start_sequence, 4);
    assert_eq!(copied.len(), 4);
    assert_eq!(batch.records().len(), 4);
    drop(new_report);
    drop(reclaim(&mut f.controller, fresh));
}
#[test]
fn leaf_set_handles_refuse_all_old_profiles() {
    for n in 1..=4 {
        let f = Fixture::new(n, 10);
        assert!(!normal_binding_matches(&f.state.binding));
        assert!(!module::module_runtime_matches(&f.state.binding));
        assert!(!two_callers::binding_matches(&f.state.binding));
        assert!(f.state.binding.single_site().is_err());
        assert!(f.state.binding.single_function().is_err());
        let mut handle = NormalThread {
            key: Arc::clone(&f.state.binding.key),
            pid: f.state.binding.pid,
            thread: f.state.actual_thread,
            tid: f.state.tid,
            registration: f.state.registration,
            active: true,
            _local: PhantomData,
        };
        assert!(handle.matches_profile(&f.state, TransferProfile::LeafSet));
        assert!(!handle.matches_for(&f.state, false));
        assert!(!handle.matches_for(&f.state, true));
        handle.registration += 1;
        assert!(!handle.matches_profile(&f.state, TransferProfile::LeafSet));
        handle.registration -= 1;
        handle.key = Arc::new(());
        assert!(!handle.matches_profile(&f.state, TransferProfile::LeafSet));
        handle.active = false;
        let p = prepared(n, 10);
        assert!(p.inner.activate_mode(EntryMode::Concurrent).is_err());
    }
    let (mut c, _) = controller(1, 10);
    let b = Arc::get_mut(&mut c.0.binding).unwrap();
    b.profile = BindingProfile::Single {
        site: site::synthetic_normal_site(false).site,
        function: IDS[0],
    };
    assert!(!binding_matches(b));
    // Wrong-profile attachment refuses before touching any claimed stack.
    let client = NormalLeafSetClient {
        binding: Arc::clone(&c.0.binding),
    };
    assert!(
        unsafe {
            client.attach(
                7,
                ReadableStack {
                    start: 0x7000,
                    end: 0xa000,
                },
                IntervalJournal::allocate(),
            )
        }
        .is_err()
    );
    let (mut pair, _) = controller(2, 10);
    let b = Arc::get_mut(&mut pair.0.binding).unwrap();
    b.profile = BindingProfile::Module {
        site: site::ordinary::ModuleSite::synthetic(
            CodeIdentity {
                source: SourceIdentity([194; 32]),
                mapping: ENTRY[0],
                generation: 1,
            },
            [
                (ENTRY[0], ENTRY[0] + 32, vec![ENTRY[0] + 16]),
                (ENTRY[1], ENTRY[1] + 32, vec![ENTRY[1] + 16]),
            ],
        ),
        functions: [IDS[0], IDS[1]],
    };
    assert!(module::module_runtime_matches(b));
    assert!(!binding_matches(b));
    let client = NormalLeafSetClient {
        binding: Arc::clone(&pair.0.binding),
    };
    assert!(
        unsafe {
            client.attach(
                7,
                ReadableStack {
                    start: 0x7000,
                    end: 0xa000,
                },
                IntervalJournal::allocate(),
            )
        }
        .is_err()
    );
}
