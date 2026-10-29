//! Actual Session receipts and production post-authentication helpers only.
//! No loaded/publication owner, opaque ControlIdentity, native execution or stack
//! mapping is fabricated. Metadata contexts do not exercise the dispatch token.
use super::*;
use liteinst2::contracts::SourceIdentity;
use runtime::{View, with_context};
const IDS: [FunctionId; 2] = [FunctionId(71), FunctionId(93)];
const ENTRY: [u64; 2] = [0x1000, 0x1200];
const RSP: u64 = 0x9008;
const WORD: u64 = 0xa000;
fn site() -> Arc<CallPairSite> {
    let mut p = vec![
        0x48, 0x83, 0xec, 24, 0x48, 0x89, 0x74, 0x24, 8, 0xe8, 0, 0, 0, 0, 0x48, 0x8b, 0x54, 0x24,
        8, 0x48, 0xc1, 0xe2, 32, 0x48, 0x09, 0xd0, 0x48, 0x83, 0xc4, 24, 0xc3,
    ];
    p[10..14].copy_from_slice(
        &i32::try_from(ENTRY[1] - ENTRY[0] - 14)
            .unwrap()
            .to_le_bytes(),
    );
    let c = [0x48, 0x89, 0xf0, 0x48, 0x83, 0xc0, 1, 0xc3];
    let (parent, child) = crate::frontend_native::module::ordinary::admit_pair_for_planner_test(
        &p, ENTRY[0], &c, ENTRY[1],
    )
    .unwrap();
    CallPairSite::synthetic(
        parent,
        child,
        CodeIdentity {
            source: SourceIdentity([19; 32]),
            mapping: ENTRY[0],
            generation: 1,
        },
        SavedExtendedStateLayout::describe_target_fxsave64(),
    )
}
fn prepared(k: usize) -> PreparedNormalCallPairSessionController {
    PreparedNormalCallPairSessionController::prepare(site(), 81, IDS, k).unwrap()
}
struct Fixture {
    state: NormalState,
    controller: NormalCallPairSessionController,
    epoch: Option<IntervalEpoch>,
    banks: Vec<IntervalEpochStorage>,
}
impl Fixture {
    fn new(k: usize) -> Self {
        let mut p = prepared(k);
        let mut banks = p.prepare_epoch_storage().unwrap();
        // SAFETY: inert synthetic role metadata, no subject or publication is executed.
        let (mut controller, client) = unsafe { p.activate_concurrent() }.unwrap();
        drop(client);
        let epoch = controller.stage_prepared(banks.pop().unwrap()).unwrap();
        controller.arm(&epoch).unwrap();
        let binding = Arc::clone(&controller.0.binding);
        let model = binding.session.register_thread(7).unwrap();
        let mut state = NormalState::new(
            binding,
            7,
            ReadableStack {
                start: 0x6000,
                end: 0xb000,
            },
            IntervalJournal::allocate(),
            model,
        );
        state.call_pair = Some(Box::new(runtime::State::new()));
        state.journal.header(state.tid, 0);
        Self {
            state,
            controller,
            epoch: Some(epoch),
            banks,
        }
    }
    fn context(&self, node: usize, ret: bool) -> HookContext {
        let pair = self.state.call_pair.as_ref().unwrap();
        let (site, _) = table(&self.state.binding).unwrap();
        let mut context = HookContext::default();
        context.instruction_pointer = if ret {
            site.functions()[node].returns()[0]
        } else {
            ENTRY[node]
        };
        context.stack_pointer = RSP
            - if node == 1 {
                site.child_stack_delta()
            } else {
                0
            };
        context.rdi = 0x4000;
        context.rsi = 3;
        context.rax = if node == 1 { 4 } else { (3 << 32) | 4 };
        context.rflags = pair.next;
        context
    }
    fn enter(&mut self, node: usize) {
        let c = self.context(node, false);
        let word = if node == 0 { WORD } else { ENTRY[0] + 14 };
        let ticks = self.state.call_pair.as_ref().unwrap().next * 100;
        with_context(&mut self.state, |p, x| {
            p.entry(x, node, &c, word, RawTimestamp { ticks, aux: 7 })
        })
        .unwrap();
    }
    fn observe(&mut self, node: usize) {
        let c = self.context(node, true);
        let word = if node == 0 { WORD } else { ENTRY[0] + 14 };
        with_context(&mut self.state, |p, x| {
            p.observe(
                x,
                node,
                &c,
                word,
                RawTimestamp {
                    ticks: 9999,
                    aux: 7,
                },
            )
        })
        .unwrap();
    }
    fn ack(&mut self) {
        with_context(&mut self.state, |p, x| {
            p.ack(x, ENTRY[0] + 14, RSP - 24, ENTRY[0] + 14, 4)
        })
        .unwrap();
    }
    fn pending_root(&mut self) {
        self.enter(0);
        self.enter(1);
        self.observe(1);
        self.ack();
        self.observe(0);
    }
    fn transfer(&mut self) -> NormalCallPairBatch {
        runtime::transfer_checked(&mut self.state).unwrap().unwrap()
    }
    fn run(&mut self) -> NormalCallPairBatch {
        self.pending_root();
        self.transfer()
    }
    fn rearm(&mut self) -> IntervalEpoch {
        let new = self
            .controller
            .stage_prepared(self.banks.pop().unwrap())
            .unwrap();
        self.controller.arm(&new).unwrap();
        self.epoch.replace(new).unwrap()
    }
}
#[derive(Debug, Eq, PartialEq)]
struct FrameCopy {
    key: usize,
    registration: u64,
    function: FunctionId,
    ordinal: u64,
    rsp: u64,
    word: u64,
    slot: ModelReturnSlot,
    summary: Option<IntervalEntrySummary>,
    actual: Option<IntervalEntrySummary>,
    returned: Option<super::super::super::frame::Returned>,
}
#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    frames: [Option<FrameCopy>; 2],
    rows: [Option<NormalCallPairRecord>; 2],
    page: [u64; 512],
    totals: NormalCallPairTotals,
    sequence: u64,
    depth: usize,
    next: u64,
}
fn snapshot(s: &NormalState) -> Snapshot {
    let p = s.call_pair.as_ref().unwrap();
    Snapshot {
        frames: std::array::from_fn(|i| {
            p.frames[i].as_ref().map(|f| FrameCopy {
                key: Arc::as_ptr(&f.key) as usize,
                registration: f.registration,
                function: f.function,
                ordinal: f.ordinal,
                rsp: f.rsp,
                word: f.word,
                slot: f.slot,
                summary: f.summary,
                actual: f.receipt.summary(),
                returned: f.returned,
            })
        }),
        rows: p.rows,
        page: s.journal.page.0,
        totals: p.totals,
        sequence: s.model.completed_sequence(),
        depth: s.model.depth(),
        next: p.next,
    }
}
fn refused(f: &mut Fixture, op: impl FnOnce(&mut NormalState) -> Result<(), BridgeError>) {
    let before = snapshot(&f.state);
    assert!(op(&mut f.state).is_err());
    assert_eq!(snapshot(&f.state), before);
}
fn reclaim(c: &mut NormalCallPairSessionController, e: IntervalEpoch) -> IntervalEpochStorage {
    match c.reclaim_storage(e) {
        Ok(b) => b,
        Err((e, _)) => panic!("unexpected reclaim refusal {e:?}"),
    }
}
fn shared(c: &mut NormalCallPairSessionController, e: IntervalEpoch) -> IntervalEpoch {
    let before = (Arc::as_ptr(&e.key), e.index, e.generation());
    let (err, e) = c.reclaim_storage(e).unwrap_err();
    assert_eq!(err, EpochStorageReclaimError::SharedOwner);
    assert_eq!((Arc::as_ptr(&e.key), e.index, e.generation()), before);
    e
}
#[test]
fn profile_and_banks_reject_other_limits() {
    for k in [10, 1000] {
        let p = prepared(k);
        assert!(matches!(
            unsafe { p.activate_concurrent() },
            Err(BridgeError {
                cause: Cause::Setup(SetupError::StorageMode)
            })
        ));
        let mut p = prepared(k);
        let banks = p.prepare_epoch_storage().unwrap();
        assert_eq!(banks.len(), 3);
        assert!(p.prepare_epoch_storage().is_err());
        let (limits, config) = session::fixed(k).unwrap();
        for bad in [
            Limits {
                epochs: 1,
                ..limits
            },
            Limits {
                threads: 2,
                ..limits
            },
            Limits { depth: 1, ..limits },
            Limits {
                records_per_epoch: 32,
                ..limits
            },
            Limits {
                actions: 2,
                ..limits
            },
        ] {
            assert!(!profile_matches(&p.inner.profile, bad, config));
        }
        for bad in [
            Config {
                retained_per_function: 16,
                ..config
            },
            Config {
                max_inflight: 1,
                ..config
            },
            Config {
                max_invocations: 32,
                ..config
            },
        ] {
            assert!(!profile_matches(&p.inner.profile, limits, bad));
        }
        let mut f = Fixture::new(k);
        let bank = f.banks.pop().unwrap();
        let fingerprint = bank.test_fingerprint();
        let (_, bank) = match f.controller.0.stage_prepared(bank) {
            Err(e) => e,
            Ok(_) => panic!("old facade accepted"),
        };
        assert_eq!(bank.test_fingerprint(), fingerprint);
        let mut foreign = Fixture::new(k);
        let (_, bank) = match foreign.controller.stage_prepared(bank) {
            Err(e) => e,
            Ok(_) => panic!("foreign bank accepted"),
        };
        assert_eq!(bank.test_fingerprint(), fingerprint);
        assert!(f.controller.stage_prepared(bank).is_ok());
    }
    for k in [0, 1, 16, 999, usize::MAX] {
        assert!(PreparedNormalCallPairSessionController::prepare(site(), 81, IDS, k).is_err());
    }
    assert!(PreparedNormalCallPairSessionController::prepare(site(), 81, [IDS[0]; 2], 10).is_err());
}
#[test]
fn actual_receipts_child_ack_then_root_checkpoint() {
    let mut f = Fixture::new(10);
    f.enter(0);
    f.enter(1);
    assert_eq!(f.state.model.depth(), 2);
    f.observe(1);
    assert_eq!(f.state.model.completed_sequence(), 0);
    assert_eq!(f.state.model.depth(), 2);
    f.ack();
    assert_eq!(f.state.model.completed_sequence(), 1);
    assert_eq!(f.state.model.depth(), 1);
    f.observe(0);
    assert_eq!(f.state.model.completed_sequence(), 1);
    let b = f.transfer();
    assert_eq!(b.records().map(|r| r.function()), IDS);
    assert_eq!(b.records()[0].sampled_children(), Some(1));
    assert_eq!(b.records()[1].sampled_children(), Some(0));
    assert_eq!(b.records().map(|r| r.sequence_before()), [0, 0]);
    assert_eq!(
        b.records()
            .map(|r| r.completion().unwrap().admission.invocation),
        [0, 1]
    );
    assert_eq!(
        b.records().map(|r| r.completion().unwrap().disposition),
        [Disposition::Retained { rank: 0 }; 2]
    );
    assert_eq!(b.journal()[0], 4);
    assert_eq!(&b.journal()[32..], &[0; 480]);
    assert_eq!(b.after().pairs.completed, 2);
    assert_eq!(b.after().roots, 1);
    assert_eq!(b.after().child_acks, 1);
    assert!(runtime::transfer_checked(&mut f.state).unwrap().is_none());
}
#[test]
fn ret_observation_is_not_ack_and_rejects_identity() {
    let mut f = Fixture::new(10);
    f.enter(0);
    f.enter(1);
    f.observe(1);
    for (pc, rsp, word, value) in [
        (ENTRY[0] + 15, RSP - 24, ENTRY[0] + 14, 4),
        (ENTRY[0] + 14, RSP - 16, ENTRY[0] + 14, 4),
        (ENTRY[0] + 14, RSP - 24, WORD, 4),
        (ENTRY[0] + 14, RSP - 24, ENTRY[0] + 14, 5),
    ] {
        refused(&mut f, |s| {
            with_context(s, |p, x| p.ack(x, pc, rsp, word, value))
        });
    }
    assert_eq!(f.state.model.depth(), 2);
    f.ack();
    refused(&mut f, |s| {
        with_context(s, |p, x| {
            p.ack(x, ENTRY[0] + 14, RSP - 24, ENTRY[0] + 14, 4)
        })
    });
    f.observe(0);
    assert_eq!(f.state.model.depth(), 1);
    f.transfer();
    // Corrupt existing preflight predicates before actual ack. The retained
    // core receipts and model must remain unconsumed on every refusal.
    fn ack_refused(f: &mut Fixture) {
        let metadata = |s: &NormalState| {
            let p = s.call_pair.as_ref().unwrap();
            (
                p.slots,
                p.sequence,
                p.arguments,
                p.before,
                p.number,
                p.frames
                    .each_ref()
                    .map(|p| p.as_ref().map(|p| (p.start_sequence, p.entry_pc))),
            )
        };
        let before = metadata(&f.state);
        refused(f, |s| {
            with_context(s, |p, x| {
                p.ack(x, ENTRY[0] + 14, RSP - 24, ENTRY[0] + 14, 4)
            })
        });
        assert_eq!(metadata(&f.state), before);
    }
    let mut f = Fixture::new(10);
    f.enter(0);
    f.enter(1);
    f.observe(1);
    let initial = snapshot(&f.state);
    let page = f.state.journal.page.0;
    for (i, word) in page.into_iter().enumerate() {
        f.state.journal.word(i, word ^ u64::MAX);
        ack_refused(&mut f);
        // The standalone wrapper remains validating, even for an otherwise
        // well-formed completion and before either receipt is consumed.
        if i == 0 || i == 511 {
            refused(&mut f, |s| {
                with_context(s, |p, x| {
                    p.prepare_completion(x, 1, ENTRY[0] + 14, RSP - 24)
                        .map(|_| ())
                })
            });
        }
        f.state.journal.word(i, word);
    }
    let child_returned = f.state.call_pair.as_ref().unwrap().frames[1]
        .as_ref()
        .unwrap()
        .returned;
    for node in 0..2 {
        for field in 0..13 {
            let frame = f.state.call_pair.as_ref().unwrap().frames[node]
                .as_ref()
                .unwrap();
            let saved = (
                Arc::clone(&frame.key),
                frame.function,
                frame.registration,
                frame.ordinal,
                frame.rsp,
                frame.word,
                frame.slot,
                frame.summary,
                frame.start_sequence,
                frame.entry_pc,
                frame.returned,
            );
            let frame = f.state.call_pair.as_mut().unwrap().frames[node]
                .as_mut()
                .unwrap();
            match field {
                0 => frame.key = Arc::new(()),
                1 => frame.function = IDS[1 - node],
                2 => frame.registration += 1,
                3 => frame.ordinal += 1,
                4 => frame.rsp += 16,
                5 => frame.word = 0,
                6 => frame.slot.identity ^= 1,
                7 => frame.slot.word ^= 1,
                8 => frame.summary = None,
                9 => frame.start_sequence = Some(1),
                10 => frame.entry_pc = ENTRY[1 - node],
                11 => frame.returned = if node == 0 { child_returned } else { None },
                _ => match frame.summary.as_mut().unwrap() {
                    IntervalEntrySummary::Admitted { invocation, .. } => *invocation += 1,
                    _ => panic!("expected sampled receipt"),
                },
            }
            ack_refused(&mut f);
            let frame = f.state.call_pair.as_mut().unwrap().frames[node]
                .as_mut()
                .unwrap();
            (
                frame.key,
                frame.function,
                frame.registration,
                frame.ordinal,
                frame.rsp,
                frame.word,
                frame.slot,
                frame.summary,
                frame.start_sequence,
                frame.entry_pc,
                frame.returned,
            ) = saved;
        }
        let frame = f.state.call_pair.as_mut().unwrap().frames[node]
            .take()
            .unwrap();
        let summary = frame.receipt.summary();
        ack_refused(&mut f);
        assert_eq!(frame.receipt.summary(), summary);
        f.state.call_pair.as_mut().unwrap().frames[node] = Some(frame);
        let saved = f.state.call_pair.as_ref().unwrap().slots[node];
        f.state.call_pair.as_mut().unwrap().slots[node] = None;
        ack_refused(&mut f);
        f.state.call_pair.as_mut().unwrap().slots[node] = saved;
        f.state.call_pair.as_mut().unwrap().sequence[node] += 1;
        ack_refused(&mut f);
        f.state.call_pair.as_mut().unwrap().sequence[node] -= 1;
    }
    for field in 0..4 {
        let frame = f.state.call_pair.as_mut().unwrap().frames[1]
            .as_mut()
            .unwrap();
        let saved = frame.returned;
        let returned = frame.returned.as_mut().unwrap();
        match field {
            0 => returned.pc += 1,
            1 => returned.rsp += 16,
            2 => returned.word ^= 1,
            _ => returned.value ^= 1,
        }
        ack_refused(&mut f);
        f.state.call_pair.as_mut().unwrap().frames[1]
            .as_mut()
            .unwrap()
            .returned = saved;
    }
    // Swap actual receipts, not fabricated ownership; cached summaries must not
    // authenticate the other frame's global admission slot.
    for restore in [false, true] {
        let frames = &mut f.state.call_pair.as_mut().unwrap().frames;
        let (parent, child) = frames.split_at_mut(1);
        std::mem::swap(
            &mut parent[0].as_mut().unwrap().receipt,
            &mut child[0].as_mut().unwrap().receipt,
        );
        if !restore {
            ack_refused(&mut f);
        }
    }
    for baseline in [false, true] {
        for field in 0..7 {
            let p = f.state.call_pair.as_mut().unwrap();
            let saved = (p.totals, p.before);
            let t = if baseline {
                &mut p.before
            } else {
                &mut p.totals
            };
            match field {
                0 => t.roots += 1,
                1 => t.child_acks += 1,
                2 => t.pairs.entered += 1,
                3 => t.pairs.ret_observed += 1,
                4 => t.pairs.confirmed += 1,
                5 => t.pairs.completed += 1,
                _ => t.pairs.unsampled += 1,
            }
            ack_refused(&mut f);
            let p = f.state.call_pair.as_mut().unwrap();
            (p.totals, p.before) = saved;
        }
    }
    for number in [false, true] {
        let p = f.state.call_pair.as_mut().unwrap();
        let saved = (p.next, p.number);
        if number {
            p.number += 1;
        } else {
            p.next += 1;
        }
        ack_refused(&mut f);
        let p = f.state.call_pair.as_mut().unwrap();
        (p.next, p.number) = saved;
    }
    let mut other = Fixture::new(10);
    let rows = *other.run().records();
    for (node, row) in rows.into_iter().enumerate() {
        f.state.call_pair.as_mut().unwrap().rows[node] = Some(row);
        ack_refused(&mut f);
        f.state.call_pair.as_mut().unwrap().rows[node] = None;
    }
    std::mem::swap(&mut f.state.model, &mut other.state.model);
    ack_refused(&mut f);
    std::mem::swap(&mut f.state.model, &mut other.state.model);
    for field in 0..4 {
        let saved = (
            f.state.registration,
            f.state.tid,
            f.state.stack.start,
            f.state.stack.end,
        );
        match field {
            0 => f.state.registration = 0,
            1 => f.state.tid ^= 1,
            2 => f.state.stack.start = RSP + 8,
            _ => f.state.stack.end = RSP,
        }
        ack_refused(&mut f);
        (
            f.state.registration,
            f.state.tid,
            f.state.stack.start,
            f.state.stack.end,
        ) = saved;
    }
    assert_eq!(snapshot(&f.state), initial);
    with_context(&mut f.state, |p, x| {
        p.prepare_completion(x, 1, ENTRY[0] + 14, RSP - 24)
    })
    .unwrap();
    assert_eq!(snapshot(&f.state), initial);
    f.ack();
    assert_eq!(f.state.model.depth(), 1);
    assert_eq!(f.state.model.completed_sequence(), 1);
    f.observe(0);
    let batch = f.transfer();
    assert_eq!(
        batch.records().map(|r| r.sampled_children()),
        [Some(1), Some(0)]
    );
    assert_eq!(batch.after().pairs.completed, 2);
}
#[test]
fn stack_envelope_requires_exact_layout_and_ranges() {
    let layout = SavedExtendedStateLayout::describe_target_fxsave64();
    let stack = ReadableStack {
        start: 0x1000,
        end: 0x5000,
    };
    let rsp = 0x4808;
    let prefix = ObservationStackProfile::CallPair240.context_stack_prefix_bytes() as u64;
    let context = rsp - prefix;
    let image = (context & !15) - layout.len();
    let good = [
        rsp,
        context,
        prefix,
        image,
        layout.len(),
        layout.mask(),
        layout.format().raw(),
    ];
    let check =
        |v: [u64; 7]| runtime::envelope(&stack, v[0], v[1], v[2], layout, [v[3], v[4], v[5], v[6]]);
    assert!(check(good));
    for i in 0..7 {
        let mut bad = good;
        bad[i] += 1;
        assert!(!check(bad));
    }
    for rsp in [0, 1, 127, u64::MAX] {
        let mut bad = good;
        bad[0] = rsp;
        assert!(!check(bad));
    }
    assert!(!runtime::envelope(
        &ReadableStack {
            start: image + 1,
            end: 0x5000
        },
        rsp,
        context,
        prefix,
        layout,
        [image, layout.len(), layout.mask(), layout.format().raw()]
    ));
    assert!(!runtime::envelope(
        &stack,
        rsp,
        context,
        prefix,
        SavedExtendedStateLayout::UNAVAILABLE,
        [image, 0, 0, 0]
    ));
}
#[test]
fn wrong_role_pc_and_control_refuse() {
    let s = site();
    let roles = [
        (Role::ParentEntry, ENTRY[0]),
        (Role::ChildEntry, ENTRY[1]),
        (Role::ChildRet, ENTRY[1] + 7),
        (Role::ChildAck, ENTRY[0] + 14),
        (Role::ParentRet, ENTRY[0] + 30),
    ];
    for &(kind, pc) in &roles {
        let control = s.control_for(pc, kind).unwrap();
        assert!(s.resolve_control(pc, kind, control));
        assert!(!s.resolve_control(pc + 1, kind, control));
        for &(other, at) in &roles {
            if other != kind {
                assert!(!s.resolve_control(pc, other, control));
                assert!(!s.resolve_control(at, other, control));
            }
        }
        let foreign = site();
        assert!(!s.resolve_control(pc, kind, foreign.control_for(pc, kind).unwrap()));
    }
}
#[test]
fn transfer_checks_all_words_and_capacity_before_consume() {
    let mut f = Fixture::new(10);
    f.pending_root();
    let original = f.state.journal.page.0;
    for (i, word) in original.into_iter().enumerate() {
        f.state.journal.word(i, word ^ 1);
        refused(&mut f, |s| runtime::transfer(s).map(|_| ()));
        f.state.journal.word(i, word);
    }
    let next = f.state.call_pair.as_ref().unwrap().next;
    f.state.call_pair.as_mut().unwrap().next = u64::MAX;
    refused(&mut f, |s| runtime::transfer(s).map(|_| ()));
    f.state.call_pair.as_mut().unwrap().next = next;
    let number = f.state.call_pair.as_ref().unwrap().number;
    f.state.call_pair.as_mut().unwrap().number = u64::MAX;
    refused(&mut f, |s| runtime::transfer(s).map(|_| ()));
    f.state.call_pair.as_mut().unwrap().number = number;
    let b = f.transfer();
    let mut expected = original;
    expected[3] = 0;
    assert_eq!(b.journal(), &expected);
}
#[test]
fn mixed_generations_keep_own_receipts() {
    let mut f = Fixture::new(10);
    f.enter(0);
    let a = f.rearm();
    let b = f.epoch.as_ref().unwrap().generation();
    assert!(f.controller.report(&a).unwrap().is_none());
    f.enter(1);
    f.observe(1);
    f.ack();
    f.observe(0);
    let out = f.transfer();
    assert_eq!(
        out.records()[0].completion().unwrap().admission.generation,
        a.generation()
    );
    assert_eq!(
        out.records()[1].completion().unwrap().admission.generation,
        b
    );
    assert_eq!(
        out.records()
            .map(|r| r.completion().unwrap().admission.invocation),
        [0, 0]
    );
    assert_eq!(out.records()[0].sampled_children(), Some(1));
    let report = f.controller.report(&a).unwrap().unwrap();
    assert!(out.records()[0].matches_report(&report).unwrap());
    assert!(!out.records()[1].matches_report(&report).unwrap());
    drop(report);
    f.banks.push(reclaim(&mut f.controller, a));
    let b = f.epoch.take().unwrap();
    f.controller.disarm(&b).unwrap();
    let report = f.controller.report(&b).unwrap().unwrap();
    assert!(out.records()[1].matches_report(&report).unwrap());
    // A first cross-generation child gives B one more child than parent. After
    // nine B/B trees, the next real tree samples its parent but closes its child.
    let mut f = Fixture::new(10);
    f.enter(0);
    let a = f.rearm();
    f.enter(1);
    f.observe(1);
    f.ack();
    f.observe(0);
    f.transfer();
    drop(reclaim(&mut f.controller, a));
    for _ in 0..9 {
        f.run();
    }
    f.enter(0);
    f.enter(1);
    assert_eq!(f.state.model.depth(), 1);
    assert_eq!(f.state.call_pair.as_ref().unwrap().depth(), 2);
    f.observe(1);
    f.ack();
    f.observe(0);
    let out = f.transfer();
    assert!(out.records()[0].completion().is_some());
    assert!(out.records()[1].completion().is_none());
    assert!(matches!(
        out.records()[1].raw().owner,
        RawIntervalOwner::FunctionClosed { .. }
    ));
    assert_eq!(out.records()[0].sampled_children(), Some(0));
    assert_eq!(out.records()[0].actual_children(), 1);
    let b = f.epoch.take().unwrap();
    f.controller.disarm(&b).unwrap();
    let report = f.controller.report(&b).unwrap().unwrap();
    assert_eq!(report.records().count(), 20);
    for row in out.records() {
        assert!(row.matches_report(&report).unwrap());
    }
}
#[test]
fn removed_child_keeps_actual_tree() {
    let mut f = Fixture::new(10);
    f.enter(0);
    let a = f.epoch.take().unwrap();
    f.controller.disarm(&a).unwrap();
    f.enter(1);
    f.observe(1);
    f.ack();
    assert_eq!(f.state.model.completed_sequence(), 0);
    assert!(f.controller.report(&a).unwrap().is_none());
    f.observe(0);
    let out = f.transfer();
    let child = out.records()[1];
    assert_eq!(
        child.raw().owner,
        RawIntervalOwner::Removed {
            generation: a.generation().get()
        }
    );
    assert!(child.completion().is_none() && child.payload().is_none());
    assert_eq!(child.history_prefix(), 2);
    assert_eq!(out.records()[0].actual_children(), 1);
    assert_eq!(out.records()[0].sampled_children(), Some(0));
    assert_eq!(out.after().pairs.completed, 1);
    assert_eq!(out.after().pairs.unsampled, 1);
    assert_eq!(out.journal()[0], 4);
    let report = f.controller.report(&a).unwrap().unwrap();
    assert_eq!(report.records().count(), 1);
    assert!(out.records()[0].matches_report(&report).unwrap());
}
#[test]
fn function_closed_report_ready_but_reclaim_shared() {
    for k in [10, 1000] {
        let mut f = Fixture::new(k);
        let mut copies = Vec::new();
        for _ in 0..k {
            copies.push(f.run());
        }
        f.enter(0);
        assert!(
            matches!(f.state.call_pair.as_ref().unwrap().frames[0].as_ref().unwrap().summary,Some(IntervalEntrySummary::Unsampled { reason:UnsampledSummary::FunctionClosed { function,.. },.. }) if function==IDS[0])
        );
        let mut a = f.rearm();
        let report = f.controller.report(&a).unwrap().unwrap();
        let rows: Vec<_> = report.records().collect();
        assert_eq!(rows.len(), 2 * k);
        for b in &copies {
            for row in b.records() {
                assert!(row.matches_report(&report).unwrap());
            }
        }
        a = shared(&mut f.controller, a);
        drop(report);
        a = shared(&mut f.controller, a);
        f.enter(1);
        f.observe(1);
        f.ack();
        a = shared(&mut f.controller, a);
        f.observe(0);
        let out = f.transfer();
        assert_eq!(
            out.records()[0].raw().owner,
            RawIntervalOwner::FunctionClosed {
                generation: a.generation().get()
            }
        );
        assert_eq!(out.records()[0].sampled_children(), None);
        assert_eq!(out.records()[0].actual_children(), 1);
        let report = f.controller.report(&a).unwrap().unwrap();
        assert_eq!(report.records().collect::<Vec<_>>(), rows);
        assert!(out.records()[0].matches_report(&report).unwrap());
        drop(report);
        let old_identity = (a.index, a.generation());
        let bank = reclaim(&mut f.controller, a);
        let fresh = f.controller.stage_prepared(bank).unwrap();
        assert_eq!(fresh.index, old_identity.0);
        assert!(fresh.generation().get() > old_identity.1.get());
        f.controller.0.owner(&fresh).unwrap().close(); // staged but never published
        drop(reclaim(&mut f.controller, fresh));
    }
}
#[test]
fn sampled_parent_blocks_report_until_root() {
    let mut f = Fixture::new(10);
    f.enter(0);
    f.enter(1);
    let a = f.epoch.take().unwrap();
    f.controller.disarm(&a).unwrap();
    assert!(f.controller.report(&a).unwrap().is_none());
    f.observe(1);
    assert!(f.controller.report(&a).unwrap().is_none());
    f.ack();
    f.observe(0);
    assert!(f.controller.report(&a).unwrap().is_none());
    let out = f.transfer();
    let report = f.controller.report(&a).unwrap().unwrap();
    assert_eq!(report.records().count(), 2);
    for row in out.records() {
        assert!(row.matches_report(&report).unwrap());
    }
    let a = shared(&mut f.controller, a);
    drop(report);
    drop(reclaim(&mut f.controller, a));
}
#[test]
fn report_global_slots_and_payload_child_counts_are_independent() {
    let mut f = Fixture::new(10);
    let batch = f.run();
    let epoch = f.epoch.take().unwrap();
    f.controller.disarm(&epoch).unwrap();
    let report = f.controller.report(&epoch).unwrap().unwrap();
    for (index, mut record) in batch.records().iter().copied().enumerate() {
        let children = u64::from(index == 0);
        assert_eq!(record.sampled_children(), Some(children));
        let completion = record.completion().unwrap();
        assert_eq!(completion.admission.invocation, index);
        assert_eq!(
            report.records().nth(index).unwrap().record.terminal,
            Some(Terminal::Completed {
                value: index as u64,
                disposition: completion.disposition,
            })
        );
        assert_ne!(index as u64, children);
        assert!(record.matches_report(&report).unwrap());
        record.sampled_children = Some(children ^ 1);
        assert!(record.matches_report(&report).is_err());
        record.sampled_children = Some(children);
        let mut wrong_payload = record;
        let PayloadOutcome::Completed { end, .. } = wrong_payload.payload.unwrap().outcome else {
            panic!("expected completed payload");
        };
        wrong_payload.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
            end,
            completed_children: children ^ 1,
        };
        assert!(wrong_payload.matches_report(&report).is_err());
        record.completion.as_mut().unwrap().admission.invocation ^= 1;
        assert!(record.matches_report(&report).is_err());
    }
}
#[test]
fn full_budget_keeps_global_slots_function_ranks() {
    for k in [10, 1000] {
        let mut f = Fixture::new(k);
        for rank in 0..k {
            let b = f.run();
            assert_eq!(b.number(), rank as u64 + 1);
            for node in 0..2 {
                let row = b.records()[node];
                let c = row.completion().unwrap();
                assert_eq!(c.admission.invocation, rank * 2 + node);
                assert_eq!(c.disposition, Disposition::Retained { rank });
                assert_eq!(row.sequence_before(), rank as u64 * 2);
                assert_eq!(row.history_prefix(), 1);
            }
        }
        let b = f.run();
        assert!(
            b.records()
                .iter()
                .all(|r| matches!(r.raw().owner, RawIntervalOwner::FunctionClosed { .. }))
        );
        assert_eq!(b.after().pairs.completed, (2 * k) as u64);
        assert_eq!(b.after().pairs.unsampled, 2);
    }
}
#[test]
fn completed_payload_wrong_function_or_children_refuse() {
    let mut f = Fixture::new(10);
    let b = f.run();
    let row = b.records()[0];
    assert!(runtime::record_outcome_ok(&row, 7));
    for change in 0..8 {
        let mut bad = row;
        match change {
            0 => bad.completion.as_mut().unwrap().admission.function = IDS[1],
            1 => bad.payload.as_mut().unwrap().admission.function = IDS[1],
            2 => bad.payload.as_mut().unwrap().thread += 1,
            3 => bad.payload.as_mut().unwrap().start_sequence += 1,
            4 => bad.sampled_children = Some(0),
            5 => bad.completion.as_mut().unwrap().disposition = Disposition::Retained { rank: 10 },
            6 => bad.completion.as_mut().unwrap().admission.invocation = 20,
            _ => bad.payload = None,
        }
        assert!(!runtime::record_outcome_ok(&bad, 7));
    }
    // Raw unavailable precedence is retained in the actual payload comparator.
    for (end, expected) in [
        (
            RawTimestamp { ticks: 0, aux: 8 },
            Observation::Unavailable(1),
        ),
        (
            RawTimestamp { ticks: 0, aux: 7 },
            Observation::Unavailable(2),
        ),
        (row.raw.start, Observation::Value(row.raw.start.ticks)),
    ] {
        let mut candidate = row;
        candidate.raw.end = end;
        candidate.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
            end: expected,
            completed_children: 1,
        };
        assert!(runtime::record_outcome_ok(&candidate, 7));
    }
}
#[test]
fn history_stream_and_batch_identity_are_exact() {
    let mut f = Fixture::new(10);
    let first = f.controller.drain_history().unwrap().unwrap();
    assert_eq!(first.number(), 1);
    assert_eq!(first.range(), 0..1);
    let b = f.run();
    assert_eq!(b.stream(), first.stream());
    assert_eq!(b.stream().functions(), &IDS);
    assert_eq!(b.stream().entries(), &ENTRY);
    assert_eq!(b.stream().edge(), [ENTRY[0] + 9, ENTRY[1], ENTRY[0] + 14]);
    let old = f.rearm();
    let next = f.controller.drain_history().unwrap().unwrap();
    assert!(next.follows(&first));
    assert_eq!(next.binding_at(next.range().end), Some(next.after()));
    let foreign = Fixture::new(10);
    assert_ne!(
        foreign.controller.history_window().unwrap().stream(),
        next.stream()
    );
    let report = f.controller.report(&old).unwrap().unwrap();
    for r in b.records() {
        assert!(r.matches_report(&report).unwrap());
    }
    // Drain and reclaim do not reset lifetime sequence or ordinals.
    drop(report);
    f.banks.push(reclaim(&mut f.controller, old));
    let later = f.run();
    assert_eq!(later.records()[0].raw().ordinal, 3);
    assert_eq!(later.records()[0].sequence_before(), 2);
    // Real publication and draining can advance the absolute high-water while
    // both receipts and the complete local journal remain unchanged before ack.
    let mut f = Fixture::new(10);
    f.enter(0);
    f.enter(1);
    f.observe(1);
    let before = snapshot(&f.state);
    let first_end = f.state.binding.session.history_committed_end();
    let old = f.rearm();
    let later_end = f.state.binding.session.history_committed_end();
    assert!(later_end > first_end);
    f.controller.drain_history().unwrap().unwrap();
    assert_eq!(f.state.binding.session.history_committed_end(), later_end);
    assert_eq!(snapshot(&f.state), before);
    for (node, &function) in IDS.iter().enumerate() {
        let frame = f.state.call_pair.as_ref().unwrap().frames[node]
            .as_ref()
            .unwrap();
        let summary = frame.receipt.summary().unwrap();
        assert_eq!(Some(summary), frame.summary);
        let prefix = prefix(summary);
        assert!(prefix > 0);
        let encoded = history::packed_absolute(summary, function, prefix).unwrap();
        for end in [first_end, later_end, crate::frontend::MAX_HISTORY_POSITION] {
            assert_eq!(
                history::packed_absolute(summary, function, end).unwrap(),
                encoded
            );
        }
        assert!(history::packed_absolute(summary, function, prefix - 1).is_err());
        assert!(
            history::packed_absolute(summary, function, crate::frontend::MAX_HISTORY_POSITION + 1)
                .is_err()
        );
    }
    f.ack();
    f.observe(0);
    let batch = f.transfer();
    assert_eq!(batch.history_end(), later_end);
    let report = f.controller.report(&old).unwrap().unwrap();
    for record in batch.records() {
        assert!(record.matches_report(&report).unwrap());
        assert_eq!(
            record.completion().unwrap().admission.generation,
            old.generation()
        );
    }
}
#[test]
fn lost_handle_retains_owner_and_sticky_failure() {
    let mut f = Fixture::new(10);
    f.pending_root();
    f.state.journal.word(511, 1);
    let before = snapshot(&f.state);
    assert!(runtime::transfer_checked(&mut f.state).is_err());
    assert!(f.state.failure.is_some());
    f.state.journal.word(511, 0);
    assert!(runtime::transfer_checked(&mut f.state).is_err());
    assert_eq!(f.state.model.completed_sequence(), before.sequence);
    // Isolated actual TLS lifetime: a lost handle retains the real pending owner.
    std::thread::spawn(|| {
        let mut f = Fixture::new(10);
        for _ in 0..10 {
            f.run();
        }
        f.enter(0);
        let old = f.rearm();
        let handle = NormalCallPairThread {
            inner: NormalThread {
                key: Arc::clone(&f.state.binding.key),
                pid: f.state.binding.pid,
                thread: f.state.actual_thread,
                tid: f.state.tid,
                registration: 7,
                active: true,
                _local: PhantomData,
            },
        };
        NORMAL.with(|cell| {
            assert!(cell.borrow().0.is_none());
            cell.borrow_mut().0 = Some(Box::new(f.state));
        });
        drop(handle);
        assert!(NORMAL_POISON.get());
        let old = shared(&mut f.controller, old);
        assert!(f.controller.report(&old).unwrap().is_some());
        // TLS Storage deliberately leaks pending state at thread exit; no reset.
    })
    .join()
    .unwrap();
}
#[test]
fn order_failures_before_consumption() {
    let mut f = Fixture::new(10);
    let child = f.context(1, false);
    refused(&mut f, |s| {
        with_context(s, |p, x| {
            p.entry(
                x,
                1,
                &child,
                ENTRY[0] + 14,
                RawTimestamp { ticks: 0, aux: 7 },
            )
        })
    });
    f.enter(0);
    let parent = f.context(0, false);
    refused(&mut f, |s| {
        with_context(s, |p, x| {
            p.entry(x, 0, &parent, WORD, RawTimestamp { ticks: 0, aux: 7 })
        })
    });
    let parent_ret = f.context(0, true);
    refused(&mut f, |s| {
        with_context(s, |p, x| {
            p.observe(x, 0, &parent_ret, WORD, RawTimestamp { ticks: 1, aux: 7 })
        })
    });
    f.enter(1);
    refused(&mut f, |s| {
        with_context(s, |p, x| {
            p.entry(
                x,
                1,
                &child,
                ENTRY[0] + 14,
                RawTimestamp { ticks: 1, aux: 7 },
            )
        })
    });
    refused(&mut f, |s| {
        with_context(s, |p, x| {
            p.ack(x, ENTRY[0] + 14, RSP - 24, ENTRY[0] + 14, 4)
        })
    });
    f.observe(1);
    f.ack();
    f.observe(0);
    let ordinal = f.state.call_pair.as_ref().unwrap().frames[0]
        .as_ref()
        .unwrap()
        .ordinal;
    f.state.call_pair.as_mut().unwrap().frames[0]
        .as_mut()
        .unwrap()
        .ordinal += 1;
    refused(&mut f, |s| runtime::transfer(s).map(|_| ()));
    f.state.call_pair.as_mut().unwrap().frames[0]
        .as_mut()
        .unwrap()
        .ordinal = ordinal;
    for field in 0..8 {
        let frame = f.state.call_pair.as_ref().unwrap().frames[0]
            .as_ref()
            .unwrap();
        let saved = (
            Arc::clone(&frame.key),
            frame.function,
            frame.registration,
            frame.rsp,
            frame.word,
            frame.slot,
            frame.entry_pc,
            frame.returned,
        );
        let frame = f.state.call_pair.as_mut().unwrap().frames[0]
            .as_mut()
            .unwrap();
        match field {
            0 => frame.key = Arc::new(()),
            1 => frame.function = IDS[1],
            2 => frame.registration += 1,
            3 => frame.rsp += 16,
            4 => frame.word += 8,
            5 => frame.slot.word ^= 1,
            6 => frame.entry_pc = ENTRY[1],
            _ => frame.returned.as_mut().unwrap().pc = ENTRY[1] + 7,
        }
        refused(&mut f, |s| runtime::transfer(s).map(|_| ()));
        let frame = f.state.call_pair.as_mut().unwrap().frames[0]
            .as_mut()
            .unwrap();
        (
            frame.key,
            frame.function,
            frame.registration,
            frame.rsp,
            frame.word,
            frame.slot,
            frame.entry_pc,
            frame.returned,
        ) = saved;
    }
    f.transfer();
}
#[test]
fn old_profile_exclusions_remain() {
    let f = Fixture::new(10);
    let b = &f.state.binding;
    assert!(!normal_binding_matches(b));
    assert!(!module::module_runtime_matches(b));
    assert!(!leaf_set::binding_matches(b));
    assert!(!two_callers::binding_matches(b));
    assert!(b.single_site().is_err());
    assert!(b.single_function().is_err());
    assert!(history::stream_for(b).is_none());
    let mut h = NormalThread {
        key: Arc::clone(&b.key),
        pid: b.pid,
        thread: f.state.actual_thread,
        tid: f.state.tid,
        registration: 7,
        active: true,
        _local: PhantomData,
    };
    for p in [
        TransferProfile::Single,
        TransferProfile::Pair,
        TransferProfile::LeafSet,
    ] {
        assert!(!h.matches_profile(&f.state, p));
    }
    h.active = false;
    let p = prepared(10);
    assert!(p.inner.activate_mode(EntryMode::Concurrent).is_err());
    assert!(binding_matches(b));
    assert!(
        f.state
            .call_pair
            .as_ref()
            .unwrap()
            .validate(View::of(&f.state))
            .is_ok()
    );
}

#[test]
fn compact_journal_validation_keeps_all_words_at_every_phase() {
    fn check(f: &mut Fixture) {
        let before = snapshot(&f.state);
        assert!(
            f.state
                .call_pair
                .as_ref()
                .unwrap()
                .validate(View::of(&f.state))
                .is_ok()
        );
        assert_eq!(snapshot(&f.state), before);
        let original = f.state.journal.page.0;
        for (i, word) in original.into_iter().enumerate() {
            f.state.journal.word(i, word ^ u64::MAX);
            refused(f, |s| s.call_pair.as_ref().unwrap().validate(View::of(s)));
            f.state.journal.word(i, word);
        }
        assert_eq!(snapshot(&f.state), before);
    }
    let mut f = Fixture::new(10);
    check(&mut f);
    f.enter(0);
    check(&mut f);
    f.enter(1);
    check(&mut f);
    f.observe(1);
    check(&mut f);
    f.ack();
    check(&mut f);
    f.observe(0);
    check(&mut f);
    let mut expected = f.state.journal.page.0;
    expected[3] = 0;
    let batch = f.transfer();
    assert_eq!(batch.journal(), &expected);
    assert_eq!(batch.after().pairs.completed, 2);
    assert_eq!(batch.after().roots, 1);
    assert_eq!(batch.after().child_acks, 1);
    check(&mut f);
}
