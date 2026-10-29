//! Real Session/receipt metadata controls only. No fabricated loaded owner,
//! opaque callback token, physical CALL/RET, publication or scheduling evidence.
use super::*;
use crate::frontend::{PayloadOutcome, RecordObservation};
use crate::generation::storage::allocation_probe;
use crate::generation::{Disposition, Terminal};
use liteinst2::contracts::SourceIdentity;

pub(in crate::frontend_native::always_on::normal::module) const IDS: [FunctionId; 2] =
    [FunctionId(11), FunctionId(29)];
pub(in crate::frontend_native::always_on::normal::module) const ENTRY: [u64; 2] = [0x1000, 0x1100];
const RSP: u64 = 0x8008;
const WORD: u64 = 0x9000;
fn site() -> Arc<site::ordinary::ModuleSite> {
    site::ordinary::ModuleSite::synthetic(
        CodeIdentity {
            source: SourceIdentity([193; 32]),
            mapping: ENTRY[0],
            generation: 1,
        },
        [
            (ENTRY[0], ENTRY[0] + 32, vec![ENTRY[0] + 16, ENTRY[0] + 24]),
            (ENTRY[1], ENTRY[1] + 32, vec![ENTRY[1] + 16, ENTRY[1] + 24]),
        ],
    )
}
pub(in crate::frontend_native::always_on::normal::module) fn prepared(
    k: usize,
) -> PreparedNormalModuleSessionController {
    PreparedNormalModuleSessionController::prepare(site(), 71, IDS, k).unwrap()
}
pub(in crate::frontend_native::always_on::normal::module) fn controller(
    k: usize,
) -> (NormalModuleSessionController, Vec<IntervalEpochStorage>) {
    let mut p = prepared(k);
    let banks = p.prepare_epoch_storage().unwrap();
    // SAFETY: metadata-only synthetic site, no native execution/publication/fork.
    let (c, client) = unsafe { p.activate_concurrent() }.unwrap();
    drop(client);
    (c, banks)
}
pub(in crate::frontend_native::always_on::normal::module) struct Fixture {
    pub(in crate::frontend_native::always_on::normal::module) state: NormalState,
    pub(in crate::frontend_native::always_on::normal::module) controller:
        NormalModuleSessionController,
    pub(in crate::frontend_native::always_on::normal::module) epoch: Option<IntervalEpoch>,
    pub(in crate::frontend_native::always_on::normal::module) banks: Vec<IntervalEpochStorage>,
}
impl Fixture {
    pub(in crate::frontend_native::always_on::normal::module) fn new(k: usize) -> Self {
        let (mut controller, mut banks) = controller(k);
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
    pub(in crate::frontend_native::always_on::normal::module) fn enter(&mut self, index: usize) {
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
    pub(in crate::frontend_native::always_on::normal::module) fn observe(&mut self, index: usize) {
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
    pub(in crate::frontend_native::always_on::normal::module) fn call(&mut self, index: usize) {
        self.enter(index);
        self.observe(index);
    }
    pub(in crate::frontend_native::always_on::normal::module) fn transfer(
        &mut self,
    ) -> NormalModuleBatch {
        let (out, page) = ModuleOutput::allocate().unwrap();
        self.state.transfer_into(out, page).unwrap().unwrap()
    }
    fn refused_transfer(&mut self) {
        let before = snapshot(&self.state);
        let (out, page) = ModuleOutput::allocate().unwrap();
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
    window: NormalModuleHistoryWindow,
    owners: Vec<Option<OwnerCopy>>,
    retained: usize,
}
fn controller_copy(c: &NormalModuleSessionController) -> ControllerCopy {
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
    c: &mut NormalModuleSessionController,
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
pub(in crate::frontend_native::always_on::normal::module) fn reclaim(
    c: &mut NormalModuleSessionController,
    e: IntervalEpoch,
) -> IntervalEpochStorage {
    match c.reclaim_storage(e) {
        Ok(bank) => bank,
        Err((error, _)) => panic!("reclaim refused: {error:?}"),
    }
}

#[test]
fn session_profile_is_exact_and_finite_single_t2_paths_stay_separate() {
    for k in [10, 1000] {
        let f = Fixture::new(k);
        let mut handle = NormalThread {
            key: Arc::clone(&f.state.binding.key),
            pid: f.state.binding.pid,
            thread: f.state.actual_thread,
            tid: f.state.tid,
            registration: f.state.registration,
            active: true,
            _local: PhantomData,
        };
        assert!(handle.matches_for(&f.state, true));
        assert!(!handle.matches_for(&f.state, false));
        handle.active = false;
        assert!(!handle.matches_for(&f.state, true));
        handle.active = true;
        handle.pid ^= 1;
        assert!(!handle.matches_for(&f.state, true));
        handle.pid ^= 1;
        handle.tid += 1;
        assert!(!handle.matches_for(&f.state, true));
        handle.tid -= 1;
        handle.registration += 1;
        assert!(!handle.matches_for(&f.state, true));
        handle.registration -= 1;
        handle.key = Arc::new(());
        assert!(!handle.matches_for(&f.state, true));
        handle.key = Arc::clone(&f.state.binding.key);
        // Obtain a real distinct Rust ThreadId, not a forged token. No subject runs.
        handle.thread = std::thread::spawn(|| thread::current().id())
            .join()
            .unwrap();
        assert!(!handle.matches_for(&f.state, true));
        handle.thread = f.state.actual_thread;
        assert!(handle.matches_for(&f.state, true));
        handle.active = false; // Metadata-only handle must not poison unrelated TLS.
        let (c, _) = controller(k);
        assert!(binding_matches(&c.0.binding));
        assert!(module_runtime_matches(&c.0.binding));
        assert!(!super::super::binding_matches(&c.0.binding));
        assert!(!normal_binding_matches(&c.0.binding));
        assert!(!super::super::super::two_callers::binding_matches(
            &c.0.binding
        ));
        assert!(c.0.binding.single_function().is_err());
        assert!(c.0.binding.single_site().is_err());
        assert!(history::stream_for(&c.0.binding).is_none());
        let (limits, config) = fixed(k).unwrap();
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
                records_per_epoch: 32,
                ..limits
            },
            Limits {
                actions: 2,
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
                max_invocations: 32,
                ..config
            },
        ] {
            assert!(!profile_matches(&c.0.binding.profile, limits, bad));
        }
        let mut c = c;
        let b = Arc::get_mut(&mut c.0.binding).unwrap();
        b.entry_mode = EntryMode::NonBlocking;
        assert!(!binding_matches(b));
        b.entry_mode = EntryMode::Concurrent;
        let legacy = Session::new(
            71,
            &IDS.map(|function| FunctionSpec { function, group: 0 }),
            &[GroupSpec { mandatory: true }],
            limits,
        )
        .unwrap();
        let absolute = std::mem::replace(&mut b.session, legacy);
        assert!(!binding_matches(b));
        b.session = absolute;
        let module = std::mem::replace(
            &mut b.profile,
            BindingProfile::Single {
                site: site::synthetic_normal_site(false).site,
                function: IDS[0],
            },
        );
        assert!(!binding_matches(b));
        assert!(normal_binding_matches(b));
        b.profile = module;
        let BindingProfile::Module { functions, .. } = &mut b.profile else {
            panic!()
        };
        functions[1] = functions[0];
        assert!(!binding_matches(b));
    }
    for k in [0, 1, 16, 999, usize::MAX] {
        assert!(PreparedNormalModuleSessionController::prepare(site(), 71, IDS, k).is_err());
    }
    assert!(PreparedNormalModuleSessionController::prepare(site(), 71, [IDS[0]; 2], 10).is_err());
    let p = prepared(10);
    assert!(p.inner.activate_mode(EntryMode::Concurrent).is_err()); // No gated client.
}

#[test]
fn session_banks_prepare_once_and_activation_requires_preparation() {
    for k in [10, 1000] {
        let p = prepared(k);
        // SAFETY: only exercising a refusal on synthetic metadata.
        assert!(matches!(
            unsafe { p.activate_concurrent() },
            Err(BridgeError {
                cause: Cause::Setup(SetupError::StorageMode)
            })
        ));
        let mut p = prepared(k);
        let banks = p.prepare_epoch_storage().unwrap();
        assert_eq!(banks.len(), 3);
        assert!(p.banks_prepared && p.inner.epochs.is_empty());
        assert_eq!(p.inner.session.retained_epochs(), 0);
        assert!(matches!(
            p.prepare_epoch_storage(),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::StorageMode)
            })
        ));
        assert!(matches!(
            p.inner.stage(p.config),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::StorageMode)
            })
        ));
        drop(banks);
        let mut used = prepared(k);
        used.inner.stage(used.config).unwrap();
        assert!(used.prepare_epoch_storage().is_err());
        assert!(!used.banks_prepared);
        let mut registered = prepared(k);
        let model = registered.inner.session.register_thread(7).unwrap();
        drop(model);
        assert!(registered.prepare_epoch_storage().is_err());
        assert!(!registered.banks_prepared);
    }
}

#[test]
fn session_bank_allocation_refusal_preserves_pristine_preparation() {
    for k in [10, 1000] {
        let count = {
            let mut p = prepared(k);
            let _probe = allocation_probe::start(None);
            let banks = p.prepare_epoch_storage().unwrap();
            assert_eq!(banks.len(), 3);
            allocation_probe::calls()
        };
        assert!(count > 3);
        for fail_at in 0..count {
            let mut p = prepared(k);
            let before = p.inner.session.snapshot_for_bridge().unwrap();
            {
                let _probe = allocation_probe::start(Some(fail_at));
                assert!(p.prepare_epoch_storage().is_err());
            }
            assert!(!p.banks_prepared);
            assert!(p.inner.epochs.is_empty());
            assert_eq!(p.inner.session.retained_epochs(), 0);
            assert_eq!(p.inner.session.snapshot_for_bridge().unwrap(), before);
            assert_eq!(p.prepare_epoch_storage().unwrap().len(), 3);
        }
    }
}

#[test]
fn session_stage_refusals_return_same_bank() {
    let (mut c, mut banks) = controller(10);
    let (mut foreign, _) = controller(1000);
    let mut bank = banks.pop().unwrap();
    let identity = bank.test_fingerprint();
    assert_ne!(identity, banks[0].test_fingerprint());
    let before = controller_copy(&foreign);
    let (err, returned) = stage_error(foreign.stage_prepared(bank));
    assert_eq!(err, error(Cause::Epoch));
    bank = returned;
    assert_eq!(bank.test_fingerprint(), identity);
    assert_eq!(controller_copy(&foreign), before);
    // Even inside the crate, the old Single entry point refuses a module bank.
    let before = controller_copy(&c);
    let (err, returned) = stage_error(c.0.stage_prepared(bank));
    assert_eq!(err, error(Cause::Identity));
    bank = returned;
    assert_eq!(bank.test_fingerprint(), identity);
    assert_eq!(controller_copy(&c), before);
    for cause in [
        Cause::Process,
        Cause::ControllerReentry,
        Cause::Identity,
        Cause::Capacity,
    ] {
        if cause == Cause::Process {
            Arc::get_mut(&mut c.0.binding).unwrap().pid ^= 1;
        }
        if cause == Cause::Identity {
            Arc::get_mut(&mut c.0.binding).unwrap().entry_mode = EntryMode::NonBlocking;
        }
        if cause == Cause::Capacity {
            // Impossible valid population; exercise the actual vacant-slot bound.
            c.0.epochs = vec![None, None, None];
            let e = c.stage_prepared(banks.pop().unwrap()).unwrap();
            let e2 = c.stage_prepared(banks.pop().unwrap()).unwrap();
            let extra = c.0.owner(&e).unwrap().clone();
            c.0.epochs[2] = Some(extra);
            // Keep the two authentic tokens alive through this private probe.
            assert_ne!(e.generation(), e2.generation());
        }
        let before = c.0.binding.session.snapshot_for_bridge();
        let slots: Vec<_> =
            c.0.epochs
                .iter()
                .map(|o| o.as_ref().map(EpochHandle::generation))
                .collect();
        let scope = if cause == Cause::ControllerReentry {
            Some(ControllerScope::enter().unwrap())
        } else {
            None
        };
        let (err, returned) = stage_error(c.stage_prepared(bank));
        bank = returned;
        assert_eq!(bank.test_fingerprint(), identity);
        assert_eq!(err, error(cause));
        assert_eq!(c.0.binding.session.snapshot_for_bridge(), before);
        assert_eq!(
            c.0.epochs
                .iter()
                .map(|o| o.as_ref().map(EpochHandle::generation))
                .collect::<Vec<_>>(),
            slots
        );
        drop(scope);
        if cause == Cause::Process {
            Arc::get_mut(&mut c.0.binding).unwrap().pid ^= 1;
        }
        if cause == Cause::Identity {
            Arc::get_mut(&mut c.0.binding).unwrap().entry_mode = EntryMode::Concurrent;
        }
    }
    c.0.epochs.clear(); // Discard only the unused metadata owners in the capacity probe.
    assert!(c.stage_prepared(bank).is_ok()); // Original binding/config still accepts the returned bank.
}

#[test]
fn session_reclaim_refusals_return_same_epoch() {
    let (mut c, mut banks) = controller(10);
    let mut e = c.stage_prepared(banks.pop().unwrap()).unwrap();
    e = refuse_reclaim(&mut c, e, bridge(Cause::NotDrained));
    c.arm(&e).unwrap();
    e = refuse_reclaim(&mut c, e, bridge(Cause::CurrentEpoch));
    let other = c.stage_prepared(banks.pop().unwrap()).unwrap();
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
        drop(refuse_reclaim(&mut c, bad, bridge(Cause::Epoch)));
    }
    c.disarm(&e).unwrap();
    let report = c.report(&e).unwrap().unwrap();
    e = refuse_reclaim(&mut c, e, EpochStorageReclaimError::SharedOwner);
    drop(report);
    let stale = IntervalEpoch {
        key: Arc::clone(&e.key),
        index: e.index,
        generation: e.generation,
    };
    let bank = reclaim(&mut c, e);
    let fresh = c.stage_prepared(bank).unwrap();
    assert_eq!(fresh.index, stale.index);
    assert!(fresh.generation().get() > stale.generation().get());
    drop(refuse_reclaim(&mut c, stale, bridge(Cause::Epoch)));
    let before = token(&fresh);
    Arc::get_mut(&mut c.0.binding).unwrap().pid ^= 1;
    let (err, fresh) = c.reclaim_storage(fresh).unwrap_err();
    assert_eq!(err, bridge(Cause::Process));
    assert_eq!(token(&fresh), before);
    Arc::get_mut(&mut c.0.binding).unwrap().pid ^= 1;
    let _scope = ControllerScope::enter().unwrap();
    let (err, fresh) = c.reclaim_storage(fresh).unwrap_err();
    assert_eq!(err, bridge(Cause::ControllerReentry));
    assert_eq!(token(&fresh), before);
}

#[test]
fn session_function_closed_owner_survives_rearm_until_other_function_entry() {
    for k in [10, 1000] {
        for index in [0, 1] {
            let mut f = Fixture::new(k);
            for i in 0..k {
                f.call(index);
                if (i + 1) % CALLS == 0 {
                    f.transfer();
                }
            }
            f.call(index); // Real FunctionClosed receipt; retain it over rearm.
            let mut old = f.epoch.take().unwrap();
            let old_generation = old.generation();
            let next = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
            f.controller.arm(&next).unwrap();
            let report = f.controller.report(&old).unwrap().unwrap();
            let copied: Vec<_> = report.records().collect();
            assert_eq!(copied.len(), k);
            for (i, row) in copied.iter().enumerate() {
                assert_eq!(row.record.admission.function, IDS[index]);
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
            let copied_before = copied.clone();
            drop(report);
            let before = snapshot(&f.state);
            for _ in 0..2 {
                old = refuse_reclaim(
                    &mut f.controller,
                    old,
                    EpochStorageReclaimError::SharedOwner,
                );
            }
            assert_eq!(snapshot(&f.state), before);
            assert_eq!(copied, copied_before);
            assert_eq!(
                f.controller
                    .report(&old)
                    .unwrap()
                    .unwrap()
                    .records()
                    .collect::<Vec<_>>(),
                copied
            );
            f.enter(1 - index); // Consumes the old unsampled receipt, reserves new owner.
            let bank = reclaim(&mut f.controller, old);
            assert_eq!(copied.len(), k);
            f.observe(1 - index);
            let batch = f.transfer();
            let closed = batch
                .records()
                .iter()
                .find(|r| {
                    matches!(r.record.raw.owner,
            RawIntervalOwner::FunctionClosed { generation } if generation == old_generation.get())
                })
                .unwrap();
            assert_eq!(closed.function, IDS[index]);
            let last = batch.records().last().unwrap();
            assert_eq!(last.function, IDS[1 - index]);
            assert_eq!(
                last.record.raw.owner,
                RawIntervalOwner::Sampled {
                    generation: next.generation().get(),
                    invocation: 0
                }
            );
            f.controller.disarm(&next).unwrap();
            let next_report = f.controller.report(&next).unwrap().unwrap();
            let next_rows: Vec<_> = next_report.records().collect();
            assert_eq!(next_rows.len(), 1);
            assert_eq!(next_rows[0].record.admission.function, IDS[1 - index]);
            assert_eq!(next_rows[0].payload.unwrap().start_sequence, k as u64);
            drop(next_report);
            drop(reclaim(&mut f.controller, next));
            f.banks.push(bank);
            assert_eq!(f.banks.len(), 2); // One reclaimed bank was explicitly dropped.
            assert_eq!(f.state.totals.completed, k as u64 + 1);
            assert_eq!(f.state.totals.unsampled, 1);
        }
    }
}

#[test]
fn session_bank_reuse_preserves_global_coordinates_and_empty_reports() {
    let mut f = Fixture::new(10);
    let mut last_generation = 0;
    for cycle in 0..6 {
        let e = f.epoch.take().unwrap();
        assert!(e.generation().get() > last_generation);
        last_generation = e.generation().get();
        if cycle != 2 {
            f.call(0);
            f.call(1);
            let batch = f.transfer();
            assert_eq!(
                batch.records()[0].record.raw.owner,
                RawIntervalOwner::Sampled {
                    generation: e.generation().get(),
                    invocation: 0
                }
            );
            assert_eq!(
                batch.records()[1].record.raw.owner,
                RawIntervalOwner::Sampled {
                    generation: e.generation().get(),
                    invocation: 1
                }
            );
            assert_eq!(batch.completed_sequences().1, batch.totals().1.completed);
            assert_eq!(batch.next_ordinal(), batch.totals().1.entered + 1);
        }
        f.controller.disarm(&e).unwrap();
        let report = f.controller.report(&e).unwrap().unwrap();
        let rows: Vec<_> = report.records().collect();
        assert_eq!(rows.len(), if cycle == 2 { 0 } else { 2 });
        for (i, r) in rows.iter().enumerate() {
            assert_eq!(r.record.admission.function, IDS[i]);
            assert_eq!(
                r.record.terminal,
                Some(Terminal::Completed {
                    value: i as u64,
                    disposition: Disposition::Retained { rank: 0 }
                })
            );
            assert!(matches!(
                r.payload.unwrap().outcome,
                PayloadOutcome::Completed {
                    completed_children: 0,
                    ..
                }
            ));
        }
        drop(report);
        let bank = reclaim(&mut f.controller, e);
        let chunk = f.controller.drain_history().unwrap().unwrap();
        assert_eq!(chunk.range(), 2 * cycle..2 * cycle + 2);
        if cycle != 5 {
            let e = f.controller.stage_prepared(bank).unwrap();
            f.controller.arm(&e).unwrap();
            f.epoch = Some(e);
        } else {
            f.banks.push(bank);
        }
    }
    assert_eq!(f.banks.len(), 3);
    assert_eq!(f.state.model.completed_sequence(), 10);
    drop(f.banks.pop());
    assert_eq!(f.banks.len(), 2);
    assert!(matches!(
        f.controller.0.stage(fixed(10).unwrap().1),
        Err(BridgeError {
            cause: Cause::Setup(SetupError::StorageMode)
        })
    ));
}

#[test]
fn session_transfer_preserves_function_tags_all_512_words_and_receipt_on_refusal() {
    let mut f = Fixture::new(10);
    for i in 0..32 {
        f.call(i % 2);
    }
    let page = f.state.journal.page.0;
    assert_eq!(&page[..4], &[64, 0, f.state.tid, 1]);
    for (i, &word) in page.iter().enumerate() {
        f.state.journal.word(i, word ^ 1);
        f.refused_transfer();
        f.state.journal.word(i, word);
    }
    let saved = f.state.functions[0];
    f.state.functions[0] = Some(f.state.selection(1).unwrap());
    f.refused_transfer();
    f.state.functions[0] = saved;
    let selected = f.state.pending.as_ref().unwrap().selected;
    f.state.pending.as_mut().unwrap().selected = f.state.selection(0).unwrap();
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
        .return_pc = ENTRY[0] + 16;
    f.refused_transfer();
    f.state.pending.as_mut().unwrap().returned = Some(raw);
    let batch = f.transfer();
    let mut expected = page;
    expected[3] = 0; // Confirmation clears depth; word 1 is the sticky failure flag.
    assert_eq!(batch.journal(), expected);
    assert_eq!(batch.records().len(), 32);
    assert_eq!(
        (batch.totals().1.completed, batch.totals().1.unsampled),
        (20, 12)
    );
    for (i, r) in batch.records().iter().enumerate() {
        assert_eq!(r.function, IDS[i % 2]);
    }
}

#[test]
fn session_output_allocation_refusal_preserves_pending_and_history() {
    let mut f = Fixture::new(10);
    for _ in 0..11 {
        f.call(0);
    }
    let before = snapshot(&f.state);
    let history = f.controller.history_window().unwrap();
    for slot in [0, 1] {
        FAIL_RESERVE.set(Some(slot));
        let refused = ModuleOutput::allocate().is_err();
        FAIL_RESERVE.set(None);
        assert!(refused);
        assert_eq!(snapshot(&f.state), before);
        assert_eq!(f.controller.history_window().unwrap(), history);
    }
    let (_, page) = ModuleOutput::allocate().unwrap();
    assert!(
        f.state
            .transfer_into(
                ModuleOutput {
                    records: Vec::new()
                },
                page
            )
            .is_err()
    );
    assert_eq!(snapshot(&f.state), before);
    let batch = f.transfer();
    assert_eq!(batch.totals().1.unsampled, 1);
    assert_eq!(batch.history_high_water(), Some(1));
}

#[test]
fn module_batch_history_is_some_only_for_exact_session_profile() {
    for k in [10, 1000] {
        let mut f = Fixture::new(k);
        f.call(0);
        f.call(1);
        let batch = f.transfer();
        let stream = batch.history_stream().unwrap();
        assert_eq!(stream.functions(), &IDS);
        assert_eq!(stream.entries(), &ENTRY);
        assert_eq!(stream.pid(), batch.pid());
        assert_eq!(stream.install(), batch.install());
        assert_eq!(stream.identity(), batch.identity());
        assert_eq!(batch.history_high_water(), Some(1));
        assert_eq!(stream.format(), HistoryFormat::AbsoluteV1);
        assert_eq!(stream, f.controller.history_window().unwrap().stream());
    }
    // Private finite fixture uses the same production output adapter; no new fake owner.
    let mut p = PreparedIntervalController {
        session: Session::new(
            71,
            &IDS.map(|function| FunctionSpec { function, group: 0 }),
            &[GroupSpec { mandatory: true }],
            super::super::LIMITS,
        )
        .unwrap(),
        profile: BindingProfile::Module {
            site: site(),
            functions: IDS,
        },
        key: Arc::new(()),
        install: 71,
        limits: super::super::LIMITS,
        epochs: Vec::with_capacity(1),
        _exclusive: PhantomData,
    };
    let e = p
        .stage(Config {
            retained_per_function: 1,
            max_inflight: 1,
            max_invocations: 32,
        })
        .unwrap();
    let (mut c, b) = p.activate_binding(EntryMode::NonBlocking).unwrap();
    c.arm(&e).unwrap();
    let model = b.session.register_thread(7).unwrap();
    let mut s = NormalState::new(
        b,
        7,
        ReadableStack {
            start: 0x7000,
            end: 0xa000,
        },
        IntervalJournal::allocate(),
        model,
    );
    s.journal.header(s.tid, 0);
    let selected = s.selection(0).unwrap();
    s.enter_function(
        selected,
        ENTRY[0],
        RSP,
        WORD,
        RawTimestamp { ticks: 100, aux: 7 },
    )
    .unwrap();
    s.observe_function(
        selected,
        ENTRY[0] + 16,
        RSP,
        WORD,
        RawTimestamp { ticks: 117, aux: 7 },
    )
    .unwrap();
    let (out, page) = ModuleOutput::allocate().unwrap();
    let batch = s.transfer_into(out, page).unwrap().unwrap();
    assert!(batch.history_stream().is_none() && batch.history_high_water().is_none());
    assert_eq!(batch.records().len(), 1);
    assert!(!binding_matches(&s.binding));
    assert!(module_runtime_matches(&s.binding));
}
