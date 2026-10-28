//! Pure metadata controls: real Session receipts, copied contexts/stack words.
//! No live gate phase is set, no native CALL/RET or source publication is credited.
use super::*;
use crate::frontend::PayloadOutcome;
use liteinst2::controls::ProbeControl;
const ROOT_RSP: u64 = 0x8008;
fn context(mut c: HookContext, pc: u64, rsp: u64, value: u64) -> HookContext {
    c.instruction_pointer = pc;
    c.stack_pointer = rsp;
    c.rax = value;
    c
}
struct Fixture {
    state: State,
    controller: TreeController,
    cursor: drain::Cursor,
}
impl Fixture {
    fn new() -> Self {
        assert!(!TREE_POISON.get());
        let limits = Limits {
            epochs: 4,
            threads: 1,
            depth: 2,
            records_per_epoch: 128,
            actions: 256,
        };
        let functions = [FunctionId(11), FunctionId(12)];
        let session = Session::new(
            71,
            &[
                FunctionSpec {
                    function: functions[0],
                    group: 0,
                },
                FunctionSpec {
                    function: functions[1],
                    group: 1,
                },
            ],
            &[GroupSpec { mandatory: true }; 2],
            limits,
        )
        .unwrap();
        let gate = TreeCallGate::metadata_descriptor();
        let pcs = [0x1000, 0x1020, 0x1046, 0x100e, 0x1016];
        let roles = std::array::from_fn(|i| {
            let (control, writer) = ProbeControl::new_managed_bound(CALLBACKS[i], true);
            drop(writer);
            site::Role {
                pc: pcs[i],
                control,
            }
        });
        let binding = Arc::new(Binding {
            session,
            site: Arc::new(site::Site {
                gate,
                root: 0x1000,
                child: 0x1020,
                roles,
            }),
            key: Arc::new(()),
            pid: std::process::id(),
            install: 71,
            functions,
            limits,
            native_pauses: std::sync::OnceLock::new(),
        });
        let model = binding.session.register_thread(7).unwrap();
        let mut state = State::new(
            Arc::clone(&binding),
            7,
            ReadableStack {
                start: 0x7000,
                end: 0x9000,
            },
            IntervalJournal::allocate(),
            model,
            9,
        );
        state.journal.header(state.tid, 0);
        Self {
            state,
            controller: TreeController {
                binding,
                epochs: Vec::with_capacity(4),
                _exclusive: PhantomData,
            },
            cursor: drain::Cursor::default(),
        }
    }
    fn stage(&mut self, k: usize) -> IntervalEpoch {
        self.controller
            .stage(Config {
                retained_per_function: k,
                max_inflight: 2,
                max_invocations: 128,
            })
            .unwrap()
    }
    fn begin(&mut self) -> TreeTotals {
        let before = self.state.totals;
        self.state
            .begin(before.roots + 1, 10 + before.roots)
            .unwrap();
        let token = self
            .state
            .binding
            .site
            .gate
            .metadata_entry(10 + before.roots, ROOT_RSP);
        let word = self.state.binding.site.gate.continuation();
        self.state
            .enter(
                0,
                &context(HookContext::default(), 0x1000, ROOT_RSP, 0),
                word,
                RawTimestamp {
                    ticks: before.roots * 100 + 10,
                    aux: 7,
                },
                Some(token),
            )
            .unwrap();
        before
    }
    fn child(&mut self) {
        self.state
            .enter(
                1,
                &context(HookContext::default(), 0x1020, ROOT_RSP - 16, 0),
                0x100e,
                RawTimestamp {
                    ticks: self.state.totals.roots * 100 + 20,
                    aux: 7,
                },
                None,
            )
            .unwrap();
    }
    fn child_return(&mut self) {
        self.state
            .observe(
                1,
                &context(HookContext::default(), 0x1046, ROOT_RSP - 16, 99),
                0x100e,
                RawTimestamp {
                    ticks: self.state.totals.roots * 100 + 30,
                    aux: 7,
                },
            )
            .unwrap();
    }
    fn ack(&mut self) {
        self.state.ack(0x100e, ROOT_RSP - 8, 0x100e, 99).unwrap();
    }
    fn root_return(&mut self) {
        let word = self.state.binding.site.gate.continuation();
        self.state
            .observe(
                0,
                &context(HookContext::default(), 0x1016, ROOT_RSP, 100),
                word,
                RawTimestamp {
                    ticks: self.state.totals.roots * 100 + 40,
                    aux: 7,
                },
            )
            .unwrap();
    }
    fn claim(&self) -> TreeCallResult {
        let active = self.state.active.unwrap();
        TreeCallResult {
            external_id: active.external,
            gate_sequence: active.sequence,
            value: 100,
            pre_call_rsp: ROOT_RSP + 8,
            entry_rsp: ROOT_RSP,
            resumed_rsp: ROOT_RSP + 8,
            return_pc: 0x1016,
        }
    }
    fn finish(&mut self, before: TreeTotals) {
        self.state.finish_root(self.claim(), before).unwrap();
    }
    fn call(&mut self) {
        let before = self.begin();
        self.child();
        self.child_return();
        self.ack();
        self.root_return();
        self.finish(before);
    }
    fn drain(&mut self) -> Option<TreeBatch> {
        drain::metadata_transfer(&mut self.state, &mut self.cursor).unwrap()
    }
}

#[test]
fn mixed_owners_remain_pending_until_child_ack_and_root_postflight() {
    let mut f = Fixture::new();
    let a = f.stage(1);
    let b = f.stage(1);
    let c = f.stage(1);
    f.controller.arm(&a).unwrap();
    let before = f.begin();
    f.controller.arm(&b).unwrap();
    f.child();
    f.controller.arm(&c).unwrap();
    f.child_return();
    assert!(f.controller.report(&a).unwrap().is_none());
    assert!(f.controller.report(&b).unwrap().is_none());
    assert!(matches!(f.controller.retire(&a), Err(e) if e == error(Cause::NotDrained)));
    assert_eq!(f.state.totals.pairs.returns, 0);
    f.ack();
    assert_eq!(
        f.controller.report(&b).unwrap().unwrap().records().count(),
        1
    );
    assert!(f.controller.report(&a).unwrap().is_none());
    f.root_return();
    assert!(f.controller.report(&a).unwrap().is_none());
    assert_eq!(f.state.journal.used(), 3);
    f.finish(before);
    f.controller.disarm(&c).unwrap();
    let batch = f.drain().unwrap();
    assert_eq!(batch.completed_sequences(), (0, 2));
    assert_eq!(batch.gate_base(), 9);
    assert_eq!(batch.gate_sequence(), 10);
    assert_eq!(
        batch.rows()[0].raw.owner,
        RawIntervalOwner::Sampled {
            generation: a.generation().get(),
            invocation: 0
        }
    );
    assert_eq!(
        batch.rows()[1].raw.owner,
        RawIntervalOwner::Sampled {
            generation: b.generation().get(),
            invocation: 0
        }
    );
    assert_eq!(batch.rows()[0].history_prefix(), 1);
    assert_eq!(batch.rows()[1].history_prefix(), 2);
    assert_eq!(batch.rows()[0].children, Some(1));
    assert_eq!(batch.rows()[1].children, Some(0));
    assert_eq!(batch.journal()[10], 8193);
    assert_eq!(batch.journal()[17], 16385);
    for (epoch, node) in [(&a, 0), (&b, 1)] {
        let report = f.controller.retire(epoch).unwrap();
        let records: Vec<_> = report.records().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].record.admission.function,
            batch.rows()[node].function
        );
        let p = records[0].payload.unwrap();
        assert_eq!(p.start_sequence, 0);
        assert!(
            matches!(p.outcome, PayloadOutcome::Completed { completed_children, .. } if completed_children == u64::from(node == 0))
        );
    }
    assert_eq!(f.controller.retire(&c).unwrap().records().count(), 0);
    assert!(f.drain().is_none());
}

#[test]
fn child_ack_rejects_early_wrong_fields_and_duplicate_without_completion() {
    let mut f = Fixture::new();
    let e = f.stage(2);
    f.controller.arm(&e).unwrap();
    let before = f.begin();
    let before_child = f.state.journal.page.0;
    assert!(
        f.state
            .enter(
                1,
                &context(HookContext::default(), 0x1020, ROOT_RSP - 16, 0),
                0x100f,
                RawTimestamp { ticks: 20, aux: 7 },
                None
            )
            .is_err()
    );
    assert_eq!(f.state.journal.page.0, before_child);
    assert_eq!(f.state.model.depth(), 1);
    assert!(f.state.pairs[1].is_none());
    f.child();
    assert!(f.state.ack(0x100e, ROOT_RSP - 8, 0x100e, 99).is_err());
    f.child_return();
    let journal = f.state.journal.page.0;
    for (pc, rsp, word, value) in [
        (0x100f, ROOT_RSP - 8, 0x100e, 99),
        (0x100e, ROOT_RSP, 0x100e, 99),
        (0x100e, ROOT_RSP - 8, 0x100f, 99),
        (0x100e, ROOT_RSP - 8, 0x100e, 100),
    ] {
        assert!(f.state.ack(pc, rsp, word, value).is_err());
        assert_eq!(f.state.journal.page.0, journal);
        assert_eq!(f.state.model.completed_sequence(), 0);
        assert_eq!(f.state.depth, 2);
    }
    f.ack();
    let journal = f.state.journal.page.0;
    assert!(f.state.ack(0x100e, ROOT_RSP - 8, 0x100e, 99).is_err());
    assert_eq!(f.state.journal.page.0, journal);
    assert_eq!(f.state.model.completed_sequence(), 1);
    f.root_return();
    f.finish(before);
}

#[test]
fn paired_return_checks_stream_function_registration_slot_and_stack() {
    let mut f = Fixture::new();
    let e = f.stage(2);
    f.controller.arm(&e).unwrap();
    let before = f.begin();
    f.child();
    let c = context(HookContext::default(), 0x1046, ROOT_RSP - 16, 99);
    let stamp = RawTimestamp { ticks: 30, aux: 7 };
    let key = Arc::clone(&f.state.pairs[1].as_ref().unwrap().key);
    f.state.pairs[1].as_mut().unwrap().key = Arc::new(());
    assert!(f.state.observe(1, &c, 0x100e, stamp).is_err());
    f.state.pairs[1].as_mut().unwrap().key = key;
    f.state.pairs[1].as_mut().unwrap().function = FunctionId(11);
    assert!(f.state.observe(1, &c, 0x100e, stamp).is_err());
    f.state.pairs[1].as_mut().unwrap().function = FunctionId(12);
    f.state.pairs[1].as_mut().unwrap().registration = 8;
    assert!(f.state.observe(1, &c, 0x100e, stamp).is_err());
    f.state.pairs[1].as_mut().unwrap().registration = 7;
    f.state.pairs[1].as_mut().unwrap().slot.identity = 1;
    assert!(f.state.observe(1, &c, 0x100e, stamp).is_err());
    f.state.pairs[1].as_mut().unwrap().slot.identity = 2;
    for (pc, rsp, word) in [
        (0x1047, ROOT_RSP - 16, 0x100e),
        (0x1046, ROOT_RSP, 0x100e),
        (0x1046, ROOT_RSP - 16, 0x100f),
    ] {
        assert!(
            f.state
                .observe(
                    1,
                    &context(HookContext::default(), pc, rsp, 99),
                    word,
                    stamp
                )
                .is_err()
        );
    }
    assert_eq!(f.state.journal.used(), 2);
    assert_eq!(f.state.model.completed_sequence(), 0);
    f.child_return();
    assert!(f.state.observe(1, &c, 0x100e, stamp).is_err());
    f.ack();
    f.root_return();
    f.finish(before);
}

#[test]
fn root_postflight_claim_cannot_consume_pending_owner_with_wrong_fields() {
    let mut f = Fixture::new();
    let e = f.stage(2);
    f.controller.arm(&e).unwrap();
    let before = f.begin();
    f.child();
    f.child_return();
    f.ack();
    f.root_return();
    f.controller.disarm(&e).unwrap();
    let good = f.claim();
    let journal = f.state.journal.page.0;
    for bad in [
        TreeCallResult {
            external_id: 2,
            ..good
        },
        TreeCallResult {
            gate_sequence: 11,
            ..good
        },
        TreeCallResult { value: 99, ..good },
        TreeCallResult {
            return_pc: 0x1046,
            ..good
        },
        TreeCallResult {
            entry_rsp: ROOT_RSP - 16,
            ..good
        },
        TreeCallResult {
            pre_call_rsp: ROOT_RSP + 24,
            ..good
        },
        TreeCallResult {
            resumed_rsp: ROOT_RSP + 24,
            ..good
        },
    ] {
        assert!(f.state.finish_root(bad, before).is_err());
        assert_eq!(f.state.journal.page.0, journal);
        assert!(f.controller.report(&e).unwrap().is_none());
    }
    f.finish(before);
    assert_eq!(
        f.controller.report(&e).unwrap().unwrap().records().count(),
        2
    );
}

#[test]
fn two_full_buffers_keep_absolute_identity_and_held_pages_unchanged() {
    let mut f = Fixture::new();
    let e = f.stage(32);
    f.controller.arm(&e).unwrap();
    let mut held: Option<TreeBatch> = None;
    let mut held_rows = Vec::new();
    let mut held_words = Vec::new();
    for n in 0..2 {
        for _ in 0..16 {
            f.call();
        }
        let totals = f.state.totals;
        let journal = f.state.journal.page.0;
        assert_eq!(
            f.state.begin(totals.roots + 1, 10 + totals.roots),
            Err(error(Cause::Capacity))
        );
        assert_eq!(f.state.journal.page.0, journal);
        assert_eq!(f.state.totals, totals);
        assert!(
            matches!(drain::metadata_unreserved(&mut f.state, &mut f.cursor), Err(e) if e == error(Cause::Capacity))
        );
        assert_eq!(f.state.journal.page.0, journal);
        assert_eq!(f.cursor.number, n);
        let batch = f.drain().unwrap();
        assert_eq!(batch.journal(), journal);
        assert_eq!(batch.rows().len(), 32);
        assert_eq!(batch.journal()[0], 64);
        assert!(batch.journal()[452..].iter().all(|&v| v == 0));
        for (i, row) in batch.rows().iter().enumerate() {
            assert_eq!(row.raw.ordinal, n * 32 + i as u64 + 1);
        }
        assert_eq!(batch.completed_sequences(), (n * 32, (n + 1) * 32));
        assert!(f.drain().is_none());
        if let Some(old) = &held {
            assert_eq!(old.rows(), held_rows);
            assert_eq!(old.journal(), held_words);
            assert!(old.same_stream(&batch));
        } else {
            held_rows = batch.rows().to_vec();
            held_words = batch.journal().to_vec();
            held = Some(batch);
        }
    }
    f.controller.disarm(&e).unwrap();
    assert_eq!(f.controller.retire(&e).unwrap().records().count(), 64);
    assert_eq!(f.state.totals.roots, 32);
    assert_eq!(f.state.model.completed_sequence(), 64);
    assert_eq!(held.unwrap().completed_sequences(), (0, 32));
}

#[test]
fn whole_page_validator_refuses_every_word_and_sparse_row_corruption() {
    let mut f = Fixture::new();
    let e = f.stage(2);
    f.controller.arm(&e).unwrap();
    f.call();
    let rows: Vec<_> = f.state.rows[..2].iter().flatten().copied().collect();
    let journal = f.state.journal.page.0;
    let history = f.controller.history().unwrap();
    assert!(drain::validate(&f.state, f.cursor, &rows, &journal, 10, &history.actions).is_ok());
    for index in 0..512 {
        let mut broken = journal;
        broken[index] ^= 1;
        assert!(
            drain::validate(&f.state, f.cursor, &rows, &broken, 10, &history.actions).is_err(),
            "word {index}"
        );
    }
    for node in 0..2 {
        let mut shifted = rows.clone();
        shifted[node].entry_rsp += 16;
        shifted[node].resume_rsp += 16;
        assert!(
            drain::validate(&f.state, f.cursor, &shifted, &journal, 10, &history.actions).is_err()
        );
        let mut wrong = rows.clone();
        wrong[node].external_id += 1;
        assert!(
            drain::validate(&f.state, f.cursor, &wrong, &journal, 10, &history.actions).is_err()
        );
        let mut wrong = rows.clone();
        wrong[node].children = Some(7);
        assert!(
            drain::validate(&f.state, f.cursor, &wrong, &journal, 10, &history.actions).is_err()
        );
    }
    f.state.journal.word(511, 1);
    let broken = f.state.journal.page.0;
    assert!(drain::metadata_transfer(&mut f.state, &mut f.cursor).is_err());
    assert_eq!(f.state.journal.page.0, broken);
    assert_eq!(f.cursor.number, 0);
    f.state.journal.word(511, 0);
    assert!(f.drain().is_some());
}

#[test]
fn sampled_unsampled_parent_child_combinations_keep_real_receipt_owners() {
    for root_on in [false, true] {
        for child_on in [false, true] {
            let mut f = Fixture::new();
            let e = f.stage(2);
            if root_on {
                f.controller.arm(&e).unwrap();
            }
            let before = f.begin();
            if child_on && !root_on {
                f.controller.arm(&e).unwrap();
            }
            if root_on && !child_on {
                f.controller.disarm(&e).unwrap();
            }
            f.child();
            f.child_return();
            f.ack();
            f.root_return();
            f.finish(before);
            let batch = f.drain().unwrap();
            assert_eq!(batch.rows()[0].start_sequence, root_on.then_some(0));
            assert_eq!(batch.rows()[1].start_sequence, child_on.then_some(0));
            assert_eq!(
                batch.rows()[0].children,
                root_on.then_some(u64::from(child_on))
            );
            assert_eq!(batch.rows()[1].children, child_on.then_some(0));
            assert_eq!(
                batch.totals().1.pairs.completed,
                u64::from(root_on) + u64::from(child_on)
            );
            assert_eq!(
                batch.totals().1.pairs.unsampled,
                2 - u64::from(root_on) - u64::from(child_on)
            );
        }
    }
}

#[test]
fn epoch_retirement_authenticates_stale_tokens_and_last_report_permit() {
    let mut f = Fixture::new();
    let a = f.stage(1);
    let b = f.stage(1);
    let c = f.stage(1);
    let d = f.stage(1);
    f.controller.arm(&a).unwrap();
    f.call();
    f.controller.disarm(&a).unwrap();
    let report = f.controller.retire(&a).unwrap();
    assert!(
        matches!(f.controller.stage(Config { retained_per_function: 1, max_inflight: 2, max_invocations: 2 }), Err(e) if e == error(Cause::Setup(SetupError::EpochLimit)))
    );
    assert!(f.controller.report(&a).is_err());
    drop(report);
    let replacement = f.stage(1);
    assert_ne!(replacement.generation(), a.generation());
    assert!(f.controller.arm(&a).is_err());
    let mut foreign = Fixture::new();
    let token = foreign.stage(1);
    assert!(f.controller.arm(&token).is_err());
    f.controller.arm(&replacement).unwrap();
    f.controller.disarm(&replacement).unwrap();
    assert_eq!(
        f.controller.retire(&replacement).unwrap().records().count(),
        0
    );
    for e in [&b, &c, &d] {
        f.controller.arm(e).unwrap();
        f.controller.disarm(e).unwrap();
        assert_eq!(f.controller.retire(e).unwrap().records().count(), 0);
    }
    assert!(f.drain().is_some());
}

#[test]
fn controller_reentry_failed_prefix_and_legacy_history_limit_remain_refusals() {
    let mut f = Fixture::new();
    let a = f.stage(1);
    {
        let _scope = ControllerScope::enter().unwrap();
        assert_eq!(f.controller.arm(&a), Err(error(Cause::ControllerReentry)));
    }
    assert_eq!(f.controller.history().unwrap().actions.len(), 0);
    for _ in 0..256 {
        assert_eq!(
            f.controller.binding.session.publish(
                f.controller.owner(&a).unwrap(),
                FailurePoint::BeforeMutation
            ),
            Err(ControlError::InjectedBefore)
        );
    }
    let before = f.controller.history().unwrap();
    assert_eq!(before.actions.len(), 256);
    assert!(f.controller.arm(&a).is_err());
    assert_eq!(f.controller.history().unwrap(), before);
    let mut failed = Fixture::new();
    let e = failed.stage(1);
    assert!(
        failed
            .controller
            .binding
            .session
            .publish(
                failed.controller.owner(&e).unwrap(),
                FailurePoint::AfterMutation
            )
            .is_err()
    );
    assert_eq!(
        failed.controller.history().unwrap().status,
        ControllerStatus::TerminalFailure
    );
    assert!(failed.controller.arm(&e).is_err());
    assert!(
        matches!(failed.controller.retire(&e), Err(x) if x == error(Cause::Control(ControlError::TerminalFailure)))
    );
}

#[test]
fn preflight_refuses_depth_budget_identity_overflow_and_poison_atomically() {
    let mut f = Fixture::new();
    for c in [
        Config {
            retained_per_function: 1,
            max_inflight: 1,
            max_invocations: 2,
        },
        Config {
            retained_per_function: 1,
            max_inflight: 2,
            max_invocations: 1,
        },
    ] {
        assert!(f.controller.stage(c).is_err());
    }
    assert_eq!(f.controller.binding.session.retained_epochs(), 0);
    let e = f.stage(2);
    f.controller.arm(&e).unwrap();
    f.call();
    f.drain();
    let journal = f.state.journal.page.0;
    let totals = f.state.totals;
    for (external, sequence) in [(0, 11), (1, 11), (2, 10)] {
        assert_eq!(
            f.state.begin(external, sequence),
            Err(error(Cause::Capacity))
        );
        assert_eq!(f.state.journal.page.0, journal);
        assert_eq!(f.state.totals, totals);
        assert!(f.state.active.is_none());
    }
    let next = f.state.next;
    f.state.next = u64::MAX;
    assert_eq!(f.state.begin(2, 11), Err(error(Cause::Capacity)));
    assert_eq!(f.state.journal.page.0, journal);
    f.state.next = next;
    f.state.fail(error(Cause::Return));
    let poisoned = f.state.journal.page.0;
    assert!(f.state.begin(2, 11).is_err());
    assert!(drain::metadata_transfer(&mut f.state, &mut f.cursor).is_err());
    assert_eq!(f.state.journal.page.0, poisoned);
    assert_eq!(f.state.totals, totals);
}

#[test]
fn function_closed_receipts_retain_epoch_through_child_ack_and_root_finish() {
    // Actual Session/receipt and tree validators, copied context/result claims.
    // This test neither arms live gate TLS nor executes a native CALL or RET.
    fn blocked(controller: &mut TreeController) {
        assert_eq!(controller.binding.session.retained_epochs(), 4);
        assert!(matches!(controller.stage(Config {
            retained_per_function: 1, max_inflight: 2, max_invocations: 2,
        }), Err(e) if e == error(Cause::Setup(SetupError::EpochLimit))));
        assert_eq!(controller.binding.session.retained_epochs(), 4);
    }
    let mut f = Fixture::new();
    let a = f.stage(1);
    let b = f.stage(1);
    let c = f.stage(1);
    let d = f.stage(1);
    f.controller.arm(&a).unwrap();
    f.call(); // K1 closes both functions after these two admitted completions.
    let first = f.drain().unwrap();
    assert_eq!(first.rows().len(), 2);
    for (node, row) in first.rows().iter().enumerate() {
        assert_eq!(
            row.raw.owner,
            RawIntervalOwner::Sampled {
                generation: a.generation().get(),
                invocation: node,
            }
        );
    }
    let before = f.begin();
    f.child();
    let summaries: [IntervalEntrySummary; 2] = std::array::from_fn(|node| {
        let pair = f.state.pairs[node].as_ref().unwrap();
        let expected = IntervalEntrySummary::Unsampled {
            reason: UnsampledSummary::FunctionClosed {
                generation: a.generation(),
                function: f.state.binding.functions[node],
            },
            history_len: 1,
            binding: BindingChange::Published {
                action_index: 0,
                generation: a.generation(),
            },
        };
        assert_eq!(pair.receipt.summary(), Some(expected));
        assert_eq!(pair.summary, Some(expected));
        expected
    });
    assert_eq!(f.state.model.depth(), 0); // Unsampled receipts still own A.
    assert_eq!(f.state.depth, 2);
    f.controller.arm(&b).unwrap();
    let held = f.controller.report(&a).unwrap().unwrap();
    let retired = f.controller.retire(&a).unwrap();
    assert_eq!(held.generation(), a.generation());
    assert_eq!(retired.generation(), a.generation());
    assert_eq!(held.records().count(), 2);
    assert_eq!(retired.records().count(), 2);
    assert!(f.controller.epochs[a.index].is_none());
    drop(held);
    drop(retired);
    assert!(matches!(f.controller.report(&a), Err(e) if e == error(Cause::Epoch)));
    blocked(&mut f.controller); // No controller slot or Report retains A now.

    f.child_return();
    assert_eq!(
        f.state.pairs[1].as_ref().unwrap().receipt.summary(),
        Some(summaries[1])
    );
    assert_eq!(f.state.totals.pairs.returns, before.pairs.returns);
    blocked(&mut f.controller);
    f.ack(); // Consumes only the child FunctionClosed receipt.
    assert!(f.state.pairs[1].is_none());
    assert_eq!(
        f.state.pairs[0].as_ref().unwrap().receipt.summary(),
        Some(summaries[0])
    );
    assert_eq!(f.state.totals.pairs.returns, before.pairs.returns + 1);
    assert_eq!(f.state.totals.pairs.unsampled, before.pairs.unsampled + 1);
    blocked(&mut f.controller);
    f.root_return(); // Observation alone cannot release the final root receipt.
    assert_eq!(
        f.state.pairs[0].as_ref().unwrap().receipt.summary(),
        Some(summaries[0])
    );
    assert_eq!(f.state.journal.used(), 3);
    blocked(&mut f.controller);
    f.finish(before); // The real finish_root validator consumes the last receipt.
    assert!(f.state.pairs.iter().all(Option::is_none));
    assert_eq!(f.controller.binding.session.retained_epochs(), 3);
    let replacement = f.stage(1);
    assert_ne!(replacement.generation(), a.generation());
    assert_eq!(f.controller.binding.session.retained_epochs(), 4);
    assert_eq!(
        f.state.totals,
        TreeTotals {
            roots: 2,
            pairs: PairTotals {
                entries: 4,
                returns: 4,
                completed: 2,
                unsampled: 2,
            }
        }
    );
    let second = f.drain().unwrap();
    assert!(second.same_stream(&first));
    assert_eq!(second.number(), 2);
    assert_eq!(second.completed_sequences(), (2, 2));
    for (node, row) in second.rows().iter().enumerate() {
        assert_eq!(row.raw.ordinal, node as u64 + 3);
        assert_eq!(
            row.raw.owner,
            RawIntervalOwner::FunctionClosed {
                generation: a.generation().get()
            }
        );
        assert_eq!(row.summary, summaries[node]);
        assert_eq!(row.history_prefix(), 1);
        assert_eq!(row.start_sequence, None);
        assert_eq!(row.children, None);
    }
    assert_eq!(second.rows().len(), 2);
    assert_eq!(first.rows()[0].raw.ordinal, 1);
    assert_eq!(first.rows()[1].raw.ordinal, 2);
    assert!(f.drain().is_none());
    f.controller.disarm(&b).unwrap();
    drop(f.controller.retire(&b).unwrap());
    for epoch in [&c, &d, &replacement] {
        f.controller.arm(epoch).unwrap();
        f.controller.disarm(epoch).unwrap();
        drop(f.controller.retire(epoch).unwrap());
    }
    assert_eq!(f.controller.binding.session.retained_epochs(), 0);
    // Both exported batches remain alive and contain no epoch owner permit.
    assert_eq!((first.rows().len(), second.rows().len()), (2, 2));
}

#[test]
fn source_batch_admission_is_nonreserving_and_checks_all_ids_and_storage_bounds() {
    let mut f = Fixture::new();
    let ids = [1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(f.state.check_source_batch(&ids), Ok(()));
    assert_eq!(f.state.last_external, 0);
    assert_eq!(f.state.next, 1);
    assert_eq!(f.state.len, 0);
    assert_eq!(f.state.journal.used(), 0);
    assert_eq!(f.state.totals, TreeTotals::default());
    assert!(f.state.active.is_none());
    for i in 0..8 {
        let mut bad = ids;
        bad[i] = 0;
        assert_eq!(
            f.state.check_source_batch(&bad),
            Err(error(Cause::Capacity))
        );
        if i != 0 {
            bad = ids;
            bad[i] = bad[i - 1];
            assert_eq!(
                f.state.check_source_batch(&bad),
                Err(error(Cause::Capacity))
            );
        }
    }
    f.state.last_external = 1;
    assert_eq!(
        f.state.check_source_batch(&ids),
        Err(error(Cause::Capacity))
    );
    f.state.last_external = 0;
    for len in 0..=33 {
        f.state.len = len;
        assert_eq!(f.state.check_source_batch(&ids).is_ok(), len <= 16);
    }
    f.state.len = 0;
    for used in 0..=65 {
        f.state.journal.word(0, used);
        assert_eq!(f.state.check_source_batch(&ids).is_ok(), used <= 32);
    }
    f.state.journal.word(0, 0);
    for field in 0..7 {
        let old_next = f.state.next;
        let old_base = f.state.gate_base;
        let old = f.state.totals;
        match field {
            0 => f.state.next = u64::MAX - 15,
            1 => f.state.gate_base = u64::MAX - 7,
            2 => f.state.totals.roots = u64::MAX - 7,
            3 => f.state.totals.pairs.entries = u64::MAX - 15,
            4 => f.state.totals.pairs.returns = u64::MAX - 15,
            5 => f.state.totals.pairs.completed = u64::MAX - 15,
            6 => f.state.totals.pairs.unsampled = u64::MAX - 15,
            _ => unreachable!(),
        }
        assert_eq!(
            f.state.check_source_batch(&ids),
            Err(error(Cause::Capacity))
        );
        f.state.next = old_next;
        f.state.gate_base = old_base;
        f.state.totals = old;
    }
    assert_eq!(f.state.check_source_batch(&ids), Ok(()));
    assert_eq!(f.state.begin(1, 10), Ok(())); // batch admission consumed no ID
}
