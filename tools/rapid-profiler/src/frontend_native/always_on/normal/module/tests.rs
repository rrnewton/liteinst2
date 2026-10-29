//! Nonexecuting controls: real Session receipts and synthetic immutable metadata.
//! No loaded module, publication, opaque callback token, stack read or native RET.
use super::*;
use crate::frontend::{ActionKind, PayloadOutcome};
use crate::generation::{Disposition, Terminal};
use liteinst2::contracts::SourceIdentity;

const IDS: [FunctionId; 2] = [FunctionId(11), FunctionId(29)];
const ENTRY: [u64; 2] = [0x1000, 0x1100];
const RSP: u64 = 0x8008;
const WORD: u64 = 0x9000;
fn config(k: usize) -> Config {
    Config {
        retained_per_function: k,
        max_inflight: 1,
        max_invocations: 32,
    }
}
fn site() -> Arc<site::ordinary::ModuleSite> {
    site::ordinary::ModuleSite::synthetic(
        CodeIdentity {
            source: SourceIdentity([191; 32]),
            mapping: ENTRY[0],
            generation: 1,
        },
        [
            (ENTRY[0], ENTRY[0] + 32, vec![ENTRY[0] + 16, ENTRY[0] + 24]),
            (ENTRY[1], ENTRY[1] + 32, vec![ENTRY[1] + 16, ENTRY[1] + 24]),
        ],
    )
}
fn prepared() -> PreparedNormalModuleController {
    // Metadata only; this does not fabricate a loaded owner or publication.
    PreparedNormalModuleController(PreparedIntervalController {
        session: Session::new(
            71,
            &IDS.map(|function| FunctionSpec { function, group: 0 }),
            &[GroupSpec { mandatory: true }],
            LIMITS,
        )
        .unwrap(),
        profile: BindingProfile::Module {
            site: site(),
            functions: IDS,
        },
        key: Arc::new(()),
        install: 71,
        limits: LIMITS,
        epochs: Vec::with_capacity(1),
        _exclusive: PhantomData,
    })
}
struct Fixture {
    state: NormalState,
    controller: NormalModuleController,
    epoch: IntervalEpoch,
}
impl Fixture {
    fn new(k: usize) -> Self {
        let mut p = prepared();
        let epoch = p.stage(config(k)).unwrap();
        // Safe private activation transaction, not the public unsafe native contract.
        let (controller, binding) = p.0.activate_binding(EntryMode::NonBlocking).unwrap();
        let model = binding.session.register_thread(7).unwrap();
        let mut state = NormalState::new(
            binding,
            7,
            ReadableStack {
                start: 0x7000,
                end: 0xa000,
            },
            IntervalJournal::allocate(),
            model,
        );
        state.journal.header(state.tid, 0);
        let mut controller = NormalModuleController(controller);
        controller.arm(&epoch).unwrap();
        Self {
            state,
            controller,
            epoch,
        }
    }
    fn enter(&mut self, index: usize) {
        let ordinal = self.state.next;
        let selected = self.state.selection(index).unwrap();
        self.state
            .enter_function(
                selected,
                ENTRY[index],
                RSP,
                WORD + ordinal * 8,
                RawTimestamp {
                    ticks: ordinal * 100,
                    aux: 7,
                },
            )
            .unwrap();
    }
    fn observe(&mut self, index: usize) {
        let p = self.state.pending.as_ref().unwrap();
        let ordinal = p.ordinal;
        let word = p.word;
        let selected = self.state.selection(index).unwrap();
        self.state
            .observe_function(
                selected,
                ENTRY[index] + 16 + (ordinal % 2) * 8,
                RSP,
                word,
                RawTimestamp {
                    ticks: ordinal * 100 + 17,
                    aux: 7,
                },
            )
            .unwrap();
    }
    fn call(&mut self, index: usize) {
        self.enter(index);
        self.observe(index);
    }
    fn transfer(&mut self) -> NormalModuleBatch {
        let (output, journal) = ModuleOutput::allocate().unwrap();
        self.state.transfer_into(output, journal).unwrap().unwrap()
    }
    fn refused_transfer(&mut self) {
        let before = snapshot(&self.state);
        let (output, journal) = ModuleOutput::allocate().unwrap();
        assert!(self.state.transfer_into(output, journal).is_err());
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

#[test]
fn module_profile_and_config_keep_old_profiles_separate() {
    let f = Fixture::new(16);
    assert!(binding_matches(&f.state.binding));
    assert!(!normal_binding_matches(&f.state.binding));
    assert!(!two_callers::binding_matches(&f.state.binding));
    assert!(f.state.binding.single_site().is_err());
    assert!(f.state.binding.single_function().is_err());
    assert!(history::stream_for(&f.state.binding).is_none());
    assert!(prepared().0.activate_mode(EntryMode::NonBlocking).is_err());
    for bad in [
        Config {
            retained_per_function: 2,
            ..config(1)
        },
        Config {
            max_inflight: 2,
            ..config(1)
        },
        Config {
            max_invocations: 31,
            ..config(1)
        },
        Config {
            max_invocations: 33,
            ..config(1)
        },
    ] {
        let mut p = prepared();
        assert!(p.stage(bad).is_err());
        assert!(p.0.epochs.is_empty());
        assert_eq!(p.0.session.retained_epochs(), 0);
    }
    let mut p = prepared();
    let first = p.stage(config(1)).unwrap();
    assert!(p.stage(config(1)).is_err());
    assert_eq!(
        p.0.epochs[0].as_ref().unwrap().generation(),
        first.generation()
    );
    assert_eq!(p.0.session.retained_epochs(), 1);
    for limits in [
        Limits {
            epochs: 2,
            ..LIMITS
        },
        Limits {
            threads: 2,
            ..LIMITS
        },
        Limits { depth: 2, ..LIMITS },
        Limits {
            records_per_epoch: 31,
            ..LIMITS
        },
        Limits {
            actions: 3,
            ..LIMITS
        },
    ] {
        let mut other = Fixture::new(1);
        // Remove the controller's alias only in this nonexecuting profile control.
        drop(other.controller);
        Arc::get_mut(&mut other.state.binding).unwrap().limits = limits;
        assert!(!binding_matches(&other.state.binding));
    }
}

#[test]
fn module_k1_cross_function_confirmation_keeps_global_slots_and_local_budgets() {
    let mut f = Fixture::new(1);
    let mut order = vec![0, 0, 1, 0, 1, 1];
    for _ in 0..13 {
        order.extend([0, 1]);
    }
    for &index in &order {
        f.call(index);
    }
    assert_eq!(f.state.totals.entered, 32);
    assert_eq!(f.state.totals.confirmed, 31);
    let batch = f.transfer();
    assert_eq!(batch.functions(), &IDS);
    assert_eq!(batch.entries(), &ENTRY);
    assert_eq!(batch.completed_sequences(), (0, 2));
    assert_eq!(batch.next_ordinal(), 33);
    assert_eq!(
        batch.totals().1,
        NormalTotals {
            entered: 32,
            ret_observed: 32,
            confirmed: 32,
            completed: 2,
            unsampled: 30
        }
    );
    for (i, (&index, row)) in order.iter().zip(batch.records()).enumerate() {
        assert_eq!(row.function, IDS[index]);
        assert_eq!(row.record.raw.ordinal, i as u64 + 1);
        let expected = match i {
            0 => RawIntervalOwner::Sampled {
                generation: f.epoch.generation().get(),
                invocation: 0,
            },
            2 => RawIntervalOwner::Sampled {
                generation: f.epoch.generation().get(),
                invocation: 1,
            },
            _ => RawIntervalOwner::FunctionClosed {
                generation: f.epoch.generation().get(),
            },
        };
        assert_eq!(row.record.raw.owner, expected);
        assert_eq!(
            row.record.acknowledgement,
            if i == 31 {
                NormalAcknowledgement::CallerCheckpoint
            } else {
                NormalAcknowledgement::NextEntry {
                    ordinal: i as u64 + 2,
                }
            }
        );
    }
    f.controller.disarm(&f.epoch).unwrap();
    let report = f.controller.report(&f.epoch).unwrap().unwrap();
    let rows: Vec<_> = report.records().collect();
    assert_eq!(rows.len(), 2);
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.record.admission.function, IDS[i]);
        assert_eq!(row.record.admission.invocation, i);
        assert_eq!(
            row.record.terminal,
            Some(Terminal::Completed {
                value: i as u64,
                disposition: Disposition::Retained { rank: 0 }
            })
        );
        assert_eq!(row.payload.unwrap().start_sequence, i as u64);
    }
    assert!(batch.journal()[452..].iter().all(|&word| word == 0));
}

#[test]
fn module_k16_full_batch_joins_both_functions_all_payloads_and_512_words() {
    let mut f = Fixture::new(16);
    for i in 0..32 {
        f.call(i % 2);
    }
    let batch = f.transfer();
    assert_eq!(batch.records().len(), 32);
    assert_eq!(batch.number(), 1);
    assert_eq!(batch.totals().0, NormalTotals::default());
    assert_eq!(batch.totals().1.completed, 32);
    assert_eq!(batch.totals().1.unsampled, 0);
    assert_eq!(batch.completed_sequences(), (0, 32));
    assert_eq!(
        (
            batch.pid(),
            batch.tid(),
            batch.registration(),
            batch.install()
        ),
        (f.state.binding.pid, f.state.tid, 7, 71)
    );
    let mut expected = [0u64; 512];
    expected[..4].copy_from_slice(&[64, 0, f.state.tid, 0]);
    for (i, row) in batch.records().iter().enumerate() {
        let n = i as u64 + 1;
        assert_eq!(row.function, IDS[i % 2]);
        assert_eq!(row.record.history_prefix, 1);
        let bits = n | (1 << 13);
        expected[4 + i * 14..11 + i * 14].copy_from_slice(&[
            1,
            n,
            ENTRY[i % 2],
            RSP,
            WORD + n * 8,
            f.epoch.generation().get(),
            bits,
        ]);
        expected[11 + i * 14..18 + i * 14].copy_from_slice(&[
            2,
            n,
            ENTRY[i % 2] + 16 + (n % 2) * 8,
            RSP,
            WORD + n * 8,
            f.epoch.generation().get(),
            bits,
        ]);
    }
    assert_eq!(batch.journal(), expected);
    assert!(f.state.functions.iter().all(Option::is_none));
    assert!(f.state.records.iter().all(Option::is_none));
    let (out, page) = ModuleOutput::allocate().unwrap();
    assert!(f.state.transfer_into(out, page).unwrap().is_none());
    f.controller.disarm(&f.epoch).unwrap();
    let report = f.controller.report(&f.epoch).unwrap().unwrap();
    let rows: Vec<_> = report.records().collect();
    assert_eq!(rows.len(), 32);
    for (i, row) in rows.iter().enumerate() {
        let raw = batch.records()[i].record.raw;
        assert_eq!(row.record.admission.function, IDS[i % 2]);
        assert_eq!(row.record.admission.invocation, i);
        assert_eq!(row.record.admission.entry_value, raw.start.ticks);
        assert_eq!(
            row.record.terminal,
            Some(Terminal::Completed {
                value: i as u64,
                disposition: Disposition::Retained { rank: i / 2 }
            })
        );
        let payload = row.payload.unwrap();
        assert_eq!(payload.admission, row.record.admission);
        assert_eq!((payload.thread, payload.start_sequence), (7, i as u64));
        assert_eq!(
            payload.outcome,
            PayloadOutcome::Completed {
                end: raw.observation(),
                completed_children: 0
            }
        );
    }
    let h = f.controller.history().unwrap();
    assert_eq!(h.actions.len(), 2);
    assert_eq!(
        (h.actions[0].kind, h.actions[1].kind),
        (ActionKind::Published, ActionKind::Removed)
    );
    assert_eq!(h.current, None);
}

#[test]
fn module_wrong_legal_return_and_function_closed_reason_preserve_receipt() {
    let mut f = Fixture::new(1);
    f.call(0);
    f.enter(1);
    let before = snapshot(&f.state);
    let other = f.state.selection(0).unwrap();
    let word = f.state.pending.as_ref().unwrap().word;
    assert!(
        f.state
            .observe_function(
                other,
                ENTRY[0] + 16,
                RSP,
                word,
                RawTimestamp { ticks: 217, aux: 7 }
            )
            .is_err()
    );
    assert_eq!(snapshot(&f.state), before);
    let next = f.state.selection(0).unwrap();
    assert!(
        f.state
            .enter_function(
                next,
                ENTRY[0],
                RSP,
                WORD + 24,
                RawTimestamp { ticks: 300, aux: 7 }
            )
            .is_err()
    );
    assert_eq!(snapshot(&f.state), before); // No matching pre-RET for B yet.
    let same = f.state.selection(1).unwrap();
    assert!(
        f.state
            .observe_function(
                same,
                ENTRY[0] + 16,
                RSP,
                word,
                RawTimestamp { ticks: 217, aux: 7 }
            )
            .is_err()
    );
    assert_eq!(snapshot(&f.state), before);
    f.observe(1);
    f.enter(0);
    let p = f.state.pending.as_mut().unwrap();
    let actual = p.summary.unwrap();
    let IntervalEntrySummary::Unsampled {
        reason,
        history_len,
        binding,
    } = actual
    else {
        panic!()
    };
    assert!(
        matches!(reason, UnsampledSummary::FunctionClosed { function, .. } if function == IDS[0])
    );
    p.summary = Some(IntervalEntrySummary::Unsampled {
        reason: UnsampledSummary::FunctionClosed {
            generation: f.epoch.generation(),
            function: IDS[1],
        },
        history_len,
        binding,
    });
    let before = snapshot(&f.state);
    let selected = f.state.selection(0).unwrap();
    let word = f.state.pending.as_ref().unwrap().word;
    assert!(
        f.state
            .observe_function(
                selected,
                ENTRY[0] + 24,
                RSP,
                word,
                RawTimestamp { ticks: 317, aux: 7 }
            )
            .is_err()
    );
    assert_eq!(snapshot(&f.state), before);
    f.state.pending.as_mut().unwrap().summary = Some(actual);
    f.observe(0);
    let batch = f.transfer();
    assert_eq!(batch.totals().1.unsampled, 1);
}

#[test]
fn module_transfer_checks_every_word_and_final_function_tag_before_finish() {
    let mut f = Fixture::new(16);
    f.call(0);
    f.call(1);
    let page = f.state.journal.page.0;
    for (i, &word) in page.iter().enumerate() {
        f.state.journal.word(i, word ^ 1);
        f.refused_transfer();
        f.state.journal.word(i, word);
    }
    let tag = f.state.functions[0];
    f.state.functions[0] = Some(f.state.selection(1).unwrap());
    f.refused_transfer();
    f.state.functions[0] = tag;
    f.state.functions[1] = tag;
    f.refused_transfer();
    f.state.functions[1] = None;
    let pending = f.state.pending.as_ref().unwrap().selected;
    let other = f.state.selection(0).unwrap();
    f.state.pending.as_mut().unwrap().selected = other;
    f.refused_transfer();
    f.state.pending.as_mut().unwrap().selected = pending;
    for index in [2, usize::MAX] {
        f.state.pending.as_mut().unwrap().selected.index = index;
        f.refused_transfer();
        f.state.pending.as_mut().unwrap().selected = pending;
    }
    f.state.pending.as_mut().unwrap().selected.function = IDS[0];
    f.refused_transfer();
    f.state.pending.as_mut().unwrap().selected = pending;
    assert_eq!(f.transfer().records().len(), 2);
}

#[test]
fn module_allocation_and_output_refusal_retain_function_closed_owner() {
    let mut f = Fixture::new(1);
    f.call(0);
    f.call(0);
    f.controller.disarm(&f.epoch).unwrap();
    let report = f.controller.report(&f.epoch).unwrap().unwrap();
    assert_eq!(report.records().count(), 1);
    drop(report);
    drop(f.controller.0.epochs[0].take());
    assert_eq!(f.state.binding.session.retained_epochs(), 1);
    for slot in [0, 1] {
        let before = snapshot(&f.state);
        FAIL_RESERVE.set(Some(slot));
        assert!(ModuleOutput::allocate().is_err());
        FAIL_RESERVE.set(None);
        assert_eq!(snapshot(&f.state), before);
    }
    let before = snapshot(&f.state);
    let (rows, page) = outputs().unwrap();
    assert!(f.state.transfer(rows, page).is_err());
    assert_eq!(snapshot(&f.state), before);
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
    assert_eq!(
        batch.totals().1,
        NormalTotals {
            entered: 2,
            ret_observed: 2,
            confirmed: 2,
            completed: 1,
            unsampled: 1
        }
    );
    assert_eq!(f.state.binding.session.retained_epochs(), 0);
}

#[test]
fn module_completed_function_check_is_stronger_than_summary_equality() {
    let mut f = Fixture::new(16);
    f.call(1);
    let (record, _) = f
        .state
        .confirmation(NormalAcknowledgement::CallerCheckpoint)
        .unwrap();
    let p = f.state.pending.as_mut().unwrap();
    let result = f
        .state
        .model
        .finish_interval(&mut p.receipt, &mut p.slot, record.raw.observation())
        .unwrap();
    assert!(finished_function_matches(result, IDS[1]));
    assert!(!finished_function_matches(result, IDS[0]));
    let IntervalExit::Completed {
        completion,
        payload,
        stamp,
    } = result
    else {
        panic!()
    };
    let mut bad_completion = completion;
    bad_completion.admission.function = IDS[0];
    let bad = IntervalExit::Completed {
        completion: bad_completion,
        payload,
        stamp,
    };
    assert_eq!(bad.summary(), result.summary());
    assert!(!finished_function_matches(bad, IDS[1]));
    let mut bad_payload = payload;
    bad_payload.admission.function = IDS[0];
    assert!(!finished_function_matches(
        IntervalExit::Completed {
            completion,
            payload: bad_payload,
            stamp
        },
        IDS[1]
    ));
    bad_payload = payload;
    bad_payload.admission.invocation += 1;
    assert!(!finished_function_matches(
        IntervalExit::Completed {
            completion,
            payload: bad_payload,
            stamp
        },
        IDS[1]
    ));
    assert!(p.receipt.summary().is_none()); // This consumed result must never be retried.
}

#[test]
fn module_role_metadata_and_old_handle_checks_never_alias_functions() {
    let s = site();
    let foreign = site();
    for i in 0..2 {
        let control = s.control_for(i, false, ENTRY[i] + 16).unwrap();
        assert_eq!(s.resolve_control(ENTRY[i] + 16, control, false), Some(i));
        assert_eq!(s.resolve_control(ENTRY[1 - i] + 16, control, false), None);
        assert_eq!(s.resolve_control(ENTRY[i] + 16, control, true), None);
        assert_eq!(
            s.resolve_control(
                ENTRY[i] + 16,
                foreign.control_for(i, false, ENTRY[i] + 16).unwrap(),
                false
            ),
            None
        );
    }
    let f = Fixture::new(1);
    let mut handle = NormalThread {
        key: Arc::clone(&f.state.binding.key),
        pid: f.state.binding.pid,
        thread: f.state.actual_thread,
        tid: f.state.tid,
        registration: f.state.registration,
        active: true,
        _local: PhantomData,
    };
    assert!(!handle.matches(&f.state));
    assert!(!handle.matches_for(&f.state, false));
    assert!(handle.matches_for(&f.state, true));
    handle.registration += 1;
    assert!(!handle.matches_for(&f.state, true));
    handle.registration -= 1;
    handle.key = Arc::new(());
    assert!(!handle.matches_for(&f.state, true));
    handle.active = false; // Metadata handle only; do not poison unrelated test TLS.
}
