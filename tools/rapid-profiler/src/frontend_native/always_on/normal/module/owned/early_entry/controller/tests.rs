//! Real model/epoch metadata controls, not native or publication qualification.
use super::*;
use liteinst2::contracts::{CodeIdentity, SourceIdentity};

const ENTRIES: [u64; 2] = [0x1000, 0x1100];
const IDS: [FunctionId; 2] = [FunctionId(11), FunctionId(29)];
const WORDS: [u64; 4] = [0x9008, 0x9010, 0x9018, 0x9020];
struct Fixture {
    state: NormalState,
    physical: PhysicalState,
    controller: EarlyEntryModuleSessionController,
    banks: Vec<IntervalEpochStorage>,
    epoch: IntervalEpoch,
}
impl Fixture {
    fn new(k: usize, order: [usize; 2]) -> Self {
        let (site, writers) = site::ordinary::ModuleSite::synthetic_early(
            CodeIdentity {
                source: SourceIdentity([196; 32]),
                mapping: ENTRIES[0],
                generation: 1,
            },
            [
                (
                    ENTRIES[0],
                    ENTRIES[0] + 32,
                    vec![ENTRIES[0] + 16, ENTRIES[0] + 24],
                ),
                (
                    ENTRIES[1],
                    ENTRIES[1] + 32,
                    vec![ENTRIES[1] + 16, ENTRIES[1] + 24],
                ),
            ],
        );
        let mut p =
            PreparedEarlyEntryModuleSessionController::prepare(site, writers, 72, IDS, k).unwrap();
        let mut banks = p.prepare_epoch_storage().unwrap();
        // SAFETY: metadata only; synthetic site mints no loaded or callable owner.
        let (mut controller, client) = unsafe { p.activate_concurrent() }.unwrap();
        let epoch = controller.stage_prepared(banks.pop().unwrap()).unwrap();
        let binding = Arc::clone(&client.shared.binding);
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
        let physical = PhysicalState {
            shared: client.shared,
            local: LocalState::new(order.map(|i| state.selection(i).unwrap()), WORDS),
        };
        Self {
            state,
            physical,
            controller,
            banks,
            epoch,
        }
    }
    fn visit(&mut self, entry: bool) -> Result<(), BridgeError> {
        let b = self.physical.active.as_ref().unwrap();
        let position = b.position;
        let selected = self.physical.order[position % 2];
        let pc = ENTRIES[selected.index]
            + if entry {
                0
            } else {
                16 + (position % 2) as u64 * 8
            };
        let stamp = RawTimestamp {
            ticks: b.number * 1000 + position as u64 * 100 + u64::from(!entry) * 10,
            aux: 7,
        };
        self.physical.visit(
            &mut self.state,
            Visit {
                selected,
                pc,
                rsp: 0x8008,
                word: WORDS[position],
                stamp,
                entry,
            },
        )
    }
    fn call(&mut self, seen: bool) {
        if seen {
            self.visit(true).unwrap();
        }
        self.visit(false).unwrap();
    }
    fn finish(&mut self) -> (Option<NormalModuleBatch>, [EarlyEntryModulePhysicalRow; 4]) {
        let rows = self.physical.returned(&self.state).unwrap();
        let (out, journal) = EarlyOutput::allocate().unwrap();
        let sparse = self.state.transfer_into(out, journal).unwrap();
        self.physical
            .complete(&self.state, rows, sparse.as_ref())
            .unwrap();
        (sparse, rows)
    }
}

#[test]
fn early_entry_consecutive_all_bypass_then_partial_preserves_both_cursors() {
    for k in [10, 1000] {
        for order in [[0, 1], [1, 0]] {
            let mut f = Fixture::new(k, order);
            for batch in 1..=2 {
                f.physical.begin(&f.state).unwrap();
                for _ in 0..4 {
                    f.call(false);
                }
                let (sparse, rows) = f.finish();
                assert!(sparse.is_none());
                assert_eq!(f.state.cursor, Cursor::default());
                assert_eq!(
                    (f.physical.batches, f.physical.calls, f.state.next),
                    (batch, batch * 4, 1)
                );
                for (i, row) in rows.iter().enumerate() {
                    assert_eq!(
                        (
                            row.batch,
                            row.position,
                            row.function,
                            row.return_word,
                            row.observed_ordinal
                        ),
                        (batch, i, IDS[order[i % 2]], WORDS[i], None)
                    );
                }
            }
            f.physical.begin(&f.state).unwrap();
            f.call(false);
            f.controller.arm(&f.epoch).unwrap();
            for _ in 0..3 {
                f.call(true);
            }
            let (sparse, rows) = f.finish();
            assert_eq!(
                rows.map(|r| r.observed_ordinal),
                [None, Some(1), Some(2), Some(3)]
            );
            assert_eq!(sparse.unwrap().records().len(), 3);
            assert_eq!(
                (
                    f.physical.batches,
                    f.physical.calls,
                    f.state.next,
                    f.state.cursor.number
                ),
                (3, 12, 4, 1)
            );
            f.controller.disarm(&f.epoch).unwrap();
            assert_eq!(
                f.controller
                    .report(&f.epoch)
                    .unwrap()
                    .unwrap()
                    .records()
                    .count(),
                3
            );
        }
    }
}

#[test]
fn early_entry_returned_old_owner_survives_bypass_slot_reuse_and_rearm() {
    let mut f = Fixture::new(10, [0, 1]);
    f.controller.arm(&f.epoch).unwrap();
    f.physical.begin(&f.state).unwrap();
    f.call(true);
    let p = f.state.pending.as_ref().unwrap();
    let old = (
        p.ordinal,
        p.selected,
        p.rsp,
        p.word,
        p.slot,
        p.summary,
        p.receipt.summary(),
        p.returned,
    );
    let journal = f.state.journal.page.0;
    f.controller.disarm(&f.epoch).unwrap();
    assert!(f.controller.report(&f.epoch).unwrap().is_none());
    let second = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
    f.controller.arm(&second).unwrap();
    for _ in 0..3 {
        f.call(false); // A previously false early load remains bypass despite rearm.
        let p = f.state.pending.as_ref().unwrap();
        assert_eq!(
            (
                p.ordinal,
                p.selected,
                p.rsp,
                p.word,
                p.slot,
                p.summary,
                p.receipt.summary(),
                p.returned
            ),
            old
        );
        assert_eq!(f.state.journal.page.0, journal);
        assert!(f.controller.report(&f.epoch).unwrap().is_none());
    }
    let (batch, _) = f.finish();
    let batch = batch.unwrap();
    assert_eq!(batch.records().len(), 1);
    assert_eq!(
        batch.records()[0].record.acknowledgement,
        NormalAcknowledgement::CallerCheckpoint
    );
    assert!(
        matches!(batch.records()[0].record.raw.owner, RawIntervalOwner::Sampled { generation, .. } if generation == f.epoch.generation().get())
    );
    assert_eq!(
        f.controller
            .report(&f.epoch)
            .unwrap()
            .unwrap()
            .records()
            .count(),
        1
    );
    f.controller.disarm(&second).unwrap();
    assert_eq!(
        f.controller
            .report(&second)
            .unwrap()
            .unwrap()
            .records()
            .count(),
        0
    );
}

#[test]
fn early_entry_function_closed_receipt_is_not_fast_bypass() {
    let mut f = Fixture::new(10, [1, 0]);
    f.controller.arm(&f.epoch).unwrap();
    for _ in 0..5 {
        f.physical.begin(&f.state).unwrap();
        for _ in 0..4 {
            f.call(true);
        }
        assert_eq!(f.finish().0.unwrap().records().len(), 4);
    }
    f.physical.begin(&f.state).unwrap();
    f.visit(true).unwrap();
    assert!(matches!(
        f.state.pending.as_ref().unwrap().summary,
        Some(IntervalEntrySummary::Unsampled {
            reason: UnsampledSummary::FunctionClosed { .. },
            ..
        })
    ));
    f.visit(false).unwrap();
    for _ in 0..3 {
        f.call(false);
    }
    let batch = f.finish().0.unwrap();
    assert_eq!(batch.records().len(), 1);
    assert!(matches!(
        batch.records()[0].record.raw.owner,
        RawIntervalOwner::FunctionClosed { .. }
    ));
    assert_eq!(
        f.state.totals,
        NormalTotals {
            entered: 21,
            ret_observed: 21,
            confirmed: 21,
            completed: 20,
            unsampled: 1
        }
    );
    assert_eq!(f.controller.scan_closed().unwrap(), 2);
}

#[test]
fn early_entry_refuses_duplicate_missing_and_stale_physical_positions() {
    let mut f = Fixture::new(10, [0, 1]);
    f.physical.begin(&f.state).unwrap();
    assert!(f.physical.returned(&f.state).is_err());
    f.call(false);
    let first = f.physical.active.as_ref().unwrap().rows[0].unwrap();
    let selected = f.physical.order[0];
    assert!(
        f.physical
            .visit(
                &mut f.state,
                Visit {
                    selected,
                    pc: first.return_pc,
                    rsp: first.entry_rsp,
                    word: first.return_word,
                    stamp: RawTimestamp {
                        ticks: 1010,
                        aux: 7
                    },
                    entry: false
                }
            )
            .is_err()
    );
    for _ in 0..3 {
        f.call(false);
    }
    f.finish();
    f.physical.begin(&f.state).unwrap();
    f.call(false);
    f.physical
        .local
        .raw_mut()
        .active
        .as_mut()
        .unwrap()
        .rows
        .set(0, Some(first));
    assert!(f.physical.shape(&f.state).is_err());
}

#[test]
fn early_entry_active_seen_converse_and_poison_never_become_bypass() {
    for mutate_seen in [true, false] {
        let mut f = Fixture::new(10, [0, 1]);
        f.controller.arm(&f.epoch).unwrap();
        f.physical.begin(&f.state).unwrap();
        f.visit(true).unwrap();
        assert!(f.visit(true).is_err());
        f.controller.disarm(&f.epoch).unwrap();
        let totals = f.state.totals;
        if mutate_seen {
            f.physical
                .local
                .raw_mut()
                .active
                .as_mut()
                .unwrap()
                .seen
                .set(0, None);
        } else {
            f.physical
                .local
                .raw_mut()
                .active
                .as_mut()
                .unwrap()
                .pending_position = None;
        }
        let refusal = f.visit(false).unwrap_err();
        f.state.fail(refusal); // Exact production callback failure action.
        assert_eq!(f.state.totals, totals);
        assert!(f.state.pending.as_ref().unwrap().returned.is_none());
        assert!(f.state.health().is_err());
        assert!(f.controller.report(&f.epoch).unwrap().is_none());
    }
}

#[test]
fn early_entry_alloc_refusal_preserves_receipt_and_outer_abandonment_poison() {
    let mut f = Fixture::new(10, [0, 1]);
    f.controller.arm(&f.epoch).unwrap();
    let admission = Arc::new(Admission::new());
    let active = ActiveBatch::acquire(&admission).unwrap();
    f.physical.begin(&f.state).unwrap();
    f.call(true);
    for _ in 0..3 {
        f.call(false);
    }
    let before = (f.state.totals, f.state.journal.page.0, f.physical.calls);
    FAIL_RESERVE.set(Some(0));
    let refused = EarlyOutput::allocate().err();
    FAIL_RESERVE.set(None);
    assert_eq!(refused, Some(error(Cause::Capacity)));
    assert_eq!(
        (f.state.totals, f.state.journal.page.0, f.physical.calls),
        before
    );
    assert!(f.state.pending.as_ref().unwrap().returned.is_some());
    drop(active);
    assert_eq!(admission.state(), NormalModuleCloseState::Poisoned);
    assert!(ActiveBatch::acquire(&admission).is_err());
}

#[test]
fn early_entry_profile_banks_and_controls_cannot_enter_mandatory_facades() {
    let mut f = Fixture::new(10, [0, 1]);
    assert!(!super::super::super::super::session::binding_matches(
        &f.state.binding
    ));
    assert!(!module_runtime_matches(&f.state.binding));
    let bank = f.banks.pop().unwrap();
    let (reason, bank) = crate::frontend_native::always_on::epoch_storage::stage_module(
        &mut f.controller.inner,
        bank,
    )
    .err()
    .expect("early bank refused by mandatory facade");
    assert_eq!(reason, error(Cause::Identity));
    assert!(f.controller.stage_prepared(bank).is_ok());
    let BindingProfile::Module { site, .. } = &f.state.binding.profile else {
        panic!("module");
    };
    for role in site.roles() {
        let c = site
            .control_for(
                role.function_index,
                role.kind == site::ordinary::NormalModuleRoleKind::Entry,
                role.pc,
            )
            .unwrap();
        assert!(c.try_set_enabled(false).is_err()); // No writer authority.
        assert_eq!(
            c.is_enabled(),
            role.kind == site::ordinary::NormalModuleRoleKind::Return
        );
    }
}
