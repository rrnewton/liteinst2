//! Pure metadata controls: real Session receipts, copied PCs/stack words only.
//! No publication, native CALL/RET, actual checkpoint attestation or code drain.
use super::*;

const ENTRY: u64 = 0x1000;
const RET: u64 = 0x1020;
const RSP: u64 = 0x8008;
const WORD: u64 = 0x9000;
struct Fixture {
    state: NormalState,
    controller: IntervalController,
}
impl Fixture {
    fn new(epochs: usize) -> Self {
        let limits = Limits {
            epochs,
            threads: 1,
            depth: 1,
            records_per_epoch: 64,
            actions: 256,
        };
        // Opaque legacy site sentinel supplies no executable authority; these
        // controls call metadata methods only, never normal attach/callbacks.
        let site = super::super::backoff_test_site().site;
        let session = Session::new(
            71,
            &[FunctionSpec {
                function: FunctionId(11),
                group: 0,
            }],
            &[GroupSpec { mandatory: true }],
            limits,
        )
        .unwrap();
        let binding = Arc::new(Binding {
            session,
            site,
            key: Arc::new(()),
            pid: std::process::id(),
            install: 71,
            function: FunctionId(11),
            limits,
            entry_mode: EntryMode::NonBlocking,
            native_entry_pause: std::sync::OnceLock::new(),
        });
        let model = binding.session.register_thread(7).unwrap();
        let mut state = NormalState::new(
            Arc::clone(&binding),
            7,
            ReadableStack {
                start: 0x7000,
                end: 0xa000,
            },
            IntervalJournal::allocate(),
            model,
        );
        state.journal.header(state.tid, 0);
        Self {
            state,
            controller: IntervalController {
                binding,
                epochs: Vec::with_capacity(epochs),
                _exclusive: PhantomData,
            },
        }
    }
    fn stage(&mut self, k: usize) -> IntervalEpoch {
        self.controller
            .stage(Config {
                retained_per_function: k,
                max_inflight: 1,
                max_invocations: 64,
            })
            .unwrap()
    }
    fn enter(&mut self) {
        let tick = self.state.next * 100;
        self.state
            .enter(
                ENTRY,
                RSP,
                WORD,
                RawTimestamp {
                    ticks: tick,
                    aux: 7,
                },
            )
            .unwrap();
    }
    fn observe(&mut self) {
        let tick = (self.state.next - 1) * 100 + 10;
        self.state
            .observe(
                RET,
                RSP,
                WORD,
                RawTimestamp {
                    ticks: tick,
                    aux: 7,
                },
            )
            .unwrap();
    }
    fn transfer(&mut self) -> NormalBatch {
        let (rows, page) = outputs().unwrap();
        self.state.transfer(rows, page).unwrap().unwrap()
    }
}

#[test]
fn pending_ret_is_not_completion_and_k1_next_entry_finishes_before_admission() {
    let mut f = Fixture::new(2);
    let a = f.stage(1);
    f.controller.arm(&a).unwrap();
    f.enter();
    f.observe();
    assert_eq!(
        f.state.totals,
        NormalTotals {
            entered: 1,
            ret_observed: 1,
            confirmed: 0,
            completed: 0,
            unsampled: 0
        }
    );
    assert_eq!(f.state.model.depth(), 1);
    assert_eq!(f.state.model.completed_sequence(), 0);
    assert!(f.controller.report(&a).unwrap().is_none());
    assert!(
        f.state
            .pending
            .as_ref()
            .unwrap()
            .receipt
            .summary()
            .is_some()
    );
    // The second caller may reuse the same slot with a different return word.
    f.state
        .enter(ENTRY, RSP, WORD + 8, RawTimestamp { ticks: 200, aux: 7 })
        .unwrap();
    assert_eq!(f.state.totals.confirmed, 1);
    assert_eq!(f.state.model.depth(), 0);
    assert_eq!(f.state.records[0].unwrap().return_word, WORD);
    assert_eq!(
        f.state.records[0].unwrap().acknowledgement,
        NormalAcknowledgement::NextEntry { ordinal: 2 }
    );
    assert!(matches!(
        f.state.pending.as_ref().unwrap().summary,
        Some(IntervalEntrySummary::Unsampled {
            reason: UnsampledSummary::FunctionClosed { .. },
            ..
        })
    ));
    f.state
        .observe(RET, RSP, WORD + 8, RawTimestamp { ticks: 210, aux: 7 })
        .unwrap();
    let b = f.transfer();
    assert_eq!(b.records().len(), 2);
    assert_eq!(
        b.records()[1].acknowledgement,
        NormalAcknowledgement::CallerCheckpoint
    );
    assert_eq!(
        b.totals().1,
        NormalTotals {
            entered: 2,
            ret_observed: 2,
            confirmed: 2,
            completed: 1,
            unsampled: 1
        }
    );
    assert_eq!(b.completed_sequences(), (0, 1));
    assert_eq!(b.journal()[..4], [4, 0, b.tid(), 0]);
    assert!(b.journal()[32..].iter().all(|&v| v == 0));
}

#[test]
fn pending_function_closed_retains_epoch_permit_after_report_retirement() {
    let mut f = Fixture::new(1);
    let a = f.stage(1);
    f.controller.arm(&a).unwrap();
    f.enter();
    f.observe();
    f.enter();
    f.observe();
    f.controller.disarm(&a).unwrap();
    let report = f.controller.retire(&a).unwrap();
    drop(report);
    let config = Config {
        retained_per_function: 1,
        max_inflight: 1,
        max_invocations: 64,
    };
    assert!(matches!(
        f.controller.stage(config),
        Err(BridgeError {
            cause: Cause::Setup(SetupError::EpochLimit)
        })
    ));
    assert!(
        f.state
            .pending
            .as_ref()
            .unwrap()
            .receipt
            .summary()
            .is_some()
    );
    assert_eq!(f.state.totals.confirmed, 1);
    let b = f.transfer();
    assert_eq!(
        b.records()[1].raw.owner,
        RawIntervalOwner::FunctionClosed {
            generation: a.generation().get()
        }
    );
    assert!(f.controller.stage(config).is_ok());
    // Transfer retains immutable scalar evidence only, no report/epoch permit.
    assert_eq!(b.records().len(), 2);
}

#[test]
fn old_a_and_b_pending_receipts_keep_original_owner_across_rearm_c() {
    let mut f = Fixture::new(3);
    let a = f.stage(2);
    let b = f.stage(2);
    let c = f.stage(2);
    f.controller.arm(&a).unwrap();
    f.enter();
    f.observe();
    f.controller.disarm(&a).unwrap();
    f.controller.arm(&b).unwrap();
    assert!(f.controller.report(&a).unwrap().is_none());
    f.enter();
    f.observe();
    assert!(f.controller.report(&a).unwrap().is_some());
    f.controller.disarm(&b).unwrap();
    f.controller.arm(&c).unwrap();
    assert!(f.controller.report(&b).unwrap().is_none());
    let batch = f.transfer();
    assert_eq!(
        batch.records()[0].raw.owner,
        RawIntervalOwner::Sampled {
            generation: a.generation().get(),
            invocation: 0
        }
    );
    assert_eq!(
        batch.records()[1].raw.owner,
        RawIntervalOwner::Sampled {
            generation: b.generation().get(),
            invocation: 0
        }
    );
    assert_eq!(batch.records()[0].history_prefix, 1);
    assert_eq!(batch.records()[1].history_prefix, 3);
    assert_eq!(
        f.controller.history().unwrap().current,
        Some(c.generation())
    );
    assert!(f.controller.report(&b).unwrap().is_some());
    assert!(f.controller.report(&c).unwrap().is_none());
}

#[test]
fn geometry_duplicate_ret_recursion_and_wrong_ack_refuse_before_consumption() {
    let stack = ReadableStack {
        start: 0x7000,
        end: 0x9000,
    };
    assert!(stack_word_ok(&stack, RSP, WORD));
    for (rsp, word) in [
        (0x6ff8, WORD),
        (0x9008, WORD),
        (RSP + 1, WORD),
        (u64::MAX - 7, WORD),
        (RSP, 0),
    ] {
        assert!(!stack_word_ok(&stack, rsp, word));
    }
    let mut f = Fixture::new(1);
    let a = f.stage(2);
    f.controller.arm(&a).unwrap();
    f.enter();
    let initial = f.state.totals;
    assert_eq!(
        f.state
            .enter(ENTRY, RSP, WORD, RawTimestamp { ticks: 110, aux: 7 }),
        Err(error(Cause::Return))
    );
    for (rsp, word) in [(RSP + 16, WORD), (RSP, WORD + 8)] {
        assert_eq!(
            f.state
                .observe(RET, rsp, word, RawTimestamp { ticks: 120, aux: 7 }),
            Err(error(Cause::Return))
        );
        assert_eq!(f.state.totals, initial);
    }
    f.observe();
    assert_eq!(
        f.state
            .observe(RET, RSP, WORD, RawTimestamp { ticks: 130, aux: 7 }),
        Err(error(Cause::Return))
    );
    for ordinal in [0, 1, 3, u64::MAX] {
        assert!(
            f.state
                .confirm(NormalAcknowledgement::NextEntry { ordinal })
                .is_err()
        );
        assert_eq!(f.state.model.completed_sequence(), 0);
        assert!(
            f.state
                .pending
                .as_ref()
                .unwrap()
                .receipt
                .summary()
                .is_some()
        );
    }
    assert_eq!(f.transfer().records().len(), 1);
}

#[test]
fn thirty_two_call_bound_preserves_last_return_and_rejects_next_admission() {
    let mut f = Fixture::new(1);
    let a = f.stage(64);
    f.controller.arm(&a).unwrap();
    for _ in 0..CALLS {
        f.enter();
        f.observe();
    }
    assert_eq!(f.state.totals.entered, 32);
    assert_eq!(f.state.totals.confirmed, 31);
    assert_eq!(f.state.journal.used(), 64);
    let e = f
        .state
        .enter(
            ENTRY,
            RSP,
            WORD,
            RawTimestamp {
                ticks: 3300,
                aux: 7,
            },
        )
        .unwrap_err();
    assert_eq!(e, error(Cause::Capacity));
    assert_eq!(
        f.state.totals,
        NormalTotals {
            entered: 32,
            ret_observed: 32,
            confirmed: 32,
            completed: 32,
            unsampled: 0
        }
    );
    assert_eq!(f.state.next, 33);
    assert_eq!(f.state.len, 32);
    assert!(f.state.pending.is_none());
    assert_eq!(
        f.state.records[31].unwrap().acknowledgement,
        NormalAcknowledgement::NextEntry { ordinal: 33 }
    );
    assert_eq!(f.state.fail(e), e);
    assert_eq!(f.state.health(), Err(e));
    assert_eq!(f.state.fail(error(Cause::Return)), e);
}

#[test]
fn checkpoint_validates_whole_journal_and_pending_identity_before_finish() {
    for mutation in 0..7 {
        let mut f = Fixture::new(1);
        let a = f.stage(1);
        f.controller.arm(&a).unwrap();
        f.enter();
        f.observe();
        match mutation {
            0 => f.state.journal.word(4, 99),
            1 => f.state.journal.word(11 + 4, WORD + 8),
            2 => f.state.journal.word(511, 1),
            3 => f.state.journal.word(3, 0),
            4 => {
                f.state
                    .pending
                    .as_mut()
                    .unwrap()
                    .returned
                    .as_mut()
                    .unwrap()
                    .ordinal += 1
            }
            5 => {
                f.state
                    .pending
                    .as_mut()
                    .unwrap()
                    .returned
                    .as_mut()
                    .unwrap()
                    .owner = RawIntervalOwner::InitialDisarmed
            }
            6 => f.state.cursor.totals.confirmed = 1,
            _ => unreachable!(),
        }
        let before = f.state.totals;
        let (rows, page) = outputs().unwrap();
        assert!(f.state.transfer(rows, page).is_err());
        assert_eq!(f.state.totals, before);
        assert_eq!(f.state.model.completed_sequence(), 0);
        assert!(
            f.state
                .pending
                .as_ref()
                .unwrap()
                .receipt
                .summary()
                .is_some()
        );
        assert!(f.controller.report(&a).unwrap().is_none());
    }
    // An invented checkpoint label cannot replace the real next-entry evidence.
    let mut f = Fixture::new(1);
    let a = f.stage(2);
    f.controller.arm(&a).unwrap();
    f.enter();
    f.observe();
    f.enter();
    f.observe();
    f.state.records[0].as_mut().unwrap().acknowledgement = NormalAcknowledgement::CallerCheckpoint;
    let (rows, page) = outputs().unwrap();
    assert!(f.state.transfer(rows, page).is_err());
    assert_eq!(f.state.model.completed_sequence(), 1);
    assert!(
        f.state
            .pending
            .as_ref()
            .unwrap()
            .receipt
            .summary()
            .is_some()
    );
}

#[test]
fn allocation_refusal_and_caught_busy_unwind_keep_pending_first_error() {
    struct Reset(Option<usize>);
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL_RESERVE.set(self.0);
        }
    }
    let mut f = Fixture::new(1);
    let a = f.stage(1);
    f.controller.arm(&a).unwrap();
    f.enter();
    f.observe();
    let before = f.state.totals;
    let page = f.state.journal.page.0;
    for slot in 0..2 {
        let _reset = Reset(FAIL_RESERVE.replace(Some(slot)));
        assert_eq!(outputs(), Err(error(Cause::Capacity)));
        assert_eq!(f.state.totals, before);
        assert_eq!(f.state.journal.page.0, page);
        assert_eq!(f.state.model.completed_sequence(), 0);
    }
    assert!(FAIL_RESERVE.get().is_none());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f.state.busy = true;
            panic!("metadata-only interrupted transaction");
        }))
        .is_err()
    );
    assert_eq!(f.state.health(), Err(error(Cause::Outstanding)));
    assert_eq!(f.state.fail(error(Cause::Return)), error(Cause::Return));
    assert_eq!(f.state.fail(error(Cause::Capacity)), error(Cause::Return));
    assert!(
        f.state
            .pending
            .as_ref()
            .unwrap()
            .receipt
            .summary()
            .is_some()
    );
    assert_eq!(f.state.totals, before);
}

#[test]
fn transfer_reuses_buffers_without_resetting_absolute_identity_or_model_sequence() {
    let mut f = Fixture::new(1);
    let a = f.stage(4);
    f.controller.arm(&a).unwrap();
    f.enter();
    f.observe();
    let first = f.transfer();
    assert_eq!(first.number(), 1);
    assert_eq!(first.next_ordinal(), 2);
    assert_eq!(first.completed_sequences(), (0, 1));
    assert_eq!(first.journal().len(), 512);
    let (rows, page) = outputs().unwrap();
    assert_eq!(f.state.transfer(rows, page).unwrap(), None);
    f.enter();
    f.observe();
    let second = f.transfer();
    assert_eq!(second.number(), 2);
    assert_eq!(second.totals().0, first.totals().1);
    assert_eq!(second.completed_sequences(), (1, 2));
    assert_eq!(second.records()[0].raw.ordinal, 2);
    assert_eq!(
        second.records()[0].raw.owner,
        RawIntervalOwner::Sampled {
            generation: a.generation().get(),
            invocation: 1
        }
    );
    assert_eq!(f.state.journal.page.0[..4], [0, 0, f.state.tid, 0]);
    assert!(f.state.journal.page.0[4..].iter().all(|&x| x == 0));
    assert_eq!(f.state.next, 3);
    assert_eq!(f.state.model.completed_sequence(), 2);
}

#[test]
fn gated_site_cannot_be_relabelled_into_normal_preparation() {
    let legacy = super::super::backoff_test_site();
    let forged_wrapper = site::ordinary::InstalledNormalSite { site: legacy.site };
    let limits = Limits {
        epochs: 1,
        threads: 1,
        depth: 1,
        records_per_epoch: 8,
        actions: 8,
    };
    assert!(matches!(
        PreparedNormalController::new(forged_wrapper, 71, FunctionId(11), limits),
        Err(BridgeError {
            cause: Cause::Identity
        })
    ));
}
