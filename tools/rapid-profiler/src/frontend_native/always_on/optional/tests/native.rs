//! Fresh exact release subprocess only; functional accounting, not full state or speed.
use super::super::*;
use crate::frontend::{Action, ActionKind, Report};
use crate::frontend_native::LoadedIntegerLeaf;
use crate::frontend_native::always_on::site::SiteError;
use crate::frontend_native::always_on::tests::concurrent_native::{
    CONTRACT, FUNCTION, check_report, expected_file, guarded, identity, model, pin, protect, stack,
};
use crate::generation::GenerationId;
use liteinst2::bundle::WritableAlias;
use liteinst2::contracts::{AddressRange, QuiescenceLease, Refusal};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const INSTALL: u64 = 0x6f70_7469_6f6e_0001;
const COUNT: usize = 96;
const WAIT: Duration = Duration::from_secs(2);

// The callback only reaches this fixed atomic pause after its real Pair and
// journal entry are committed and after Session has released model locks.
// There is no scratch read/write or replaceable callback in this test seam.
pub(in crate::frontend_native::always_on::optional) struct EntryPause {
    ordinal: u64,
    entered: AtomicBool,
    resume: AtomicBool,
    cancelled: AtomicBool,
}
impl EntryPause {
    fn new(ordinal: u64) -> Self {
        Self {
            ordinal,
            entered: AtomicBool::new(false),
            resume: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        }
    }
    pub(in crate::frontend_native::always_on::optional) fn wait(
        &self,
        ordinal: u64,
    ) -> Result<(), BridgeError> {
        if ordinal != self.ordinal {
            return Ok(());
        }
        if self.entered.swap(true, Ordering::AcqRel) {
            return Err(error(Cause::Invariant));
        }
        let deadline = Instant::now() + WAIT;
        while !self.resume.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                return Err(error(Cause::Invariant));
            }
            thread::yield_now();
        }
        Ok(())
    }
}
struct Release(Arc<EntryPause>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.resume.store(true, Ordering::Release);
    }
}
struct HelperDone {
    controller: OptionalController,
    a: IntervalEpoch,
    b: IntervalEpoch,
    transitioned: bool,
}
struct Helper {
    pause: Arc<EntryPause>,
    handle: Option<JoinHandle<HelperDone>>,
}
impl Helper {
    fn wait(&self) {
        let deadline = Instant::now() + WAIT;
        while !self.handle.as_ref().unwrap().is_finished() {
            if Instant::now() >= deadline {
                std::process::abort();
            }
            thread::yield_now();
        }
    }
    fn join(&mut self) -> HelperDone {
        self.wait();
        self.handle
            .take()
            .unwrap()
            .join()
            .expect("optional controller helper failed")
    }
}
impl Drop for Helper {
    fn drop(&mut self) {
        self.pause.cancelled.store(true, Ordering::Release);
        self.pause.resume.store(true, Ordering::Release);
        if self.handle.is_some() {
            self.wait();
            let _ = self.handle.take().unwrap().join();
        }
    }
}

fn publish(prep: OptionalSitePreparation) -> InstalledOptionalSite {
    // One exact test in a fresh process: the passive libtest harness has no
    // DSO/gate/owner capability. This test loaded the constructor/dependency-free
    // RTLD_LOCAL fixture; no subject pointer escaped and no helper exists yet.
    let planned = prep.plan();
    let originals = planned.plan().originals();
    assert_eq!(originals.len(), 1);
    let source = AddressRange::new(originals[0].address, originals[0].bytes.len()).unwrap();
    assert_eq!(source.start() % 4096, 0);
    assert!(matches!(source.len(), 4096 | 8192));
    let mut ranges = vec![source];
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
    );
    // The preparation's only original-call authority requires its exclusive
    // borrow. No foreign/signal entry, saved resume, alias writer or unload exists.
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    let alias = unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap();
    let result = {
        // SAFETY: complete new-DSO exclusion and all source/generated ranges above.
        let mut lease =
            unsafe { QuiescenceLease::new(&mut exclusive, planned.plan().identity(), ranges) };
        let result = unsafe {
            planned.publish_with(&[alias], &mut lease, || {
                protect(source, libc::PROT_READ | libc::PROT_EXEC)
            })
        };
        if result.is_ok() {
            assert!(!lease.is_poisoned());
        }
        result
    };
    let (installed, receipt) = match result {
        Ok(pair) => pair,
        Err(failure) => {
            eprintln!("optional publication FAILED: {failure:?}");
            // No unwind/drop through a partially published native source.
            std::process::abort();
        }
    };
    // SAFETY: actual successful transaction, final RX and exclusive-entry proof.
    // Sealing retains executable/control/source/receipt owners process-lived.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}

fn expected_totals(physical: u64) -> OptionalTotals {
    assert!(physical <= COUNT as u64);
    let bypassed = physical.min(32);
    let observed = physical - bypassed;
    OptionalTotals {
        physical,
        bypassed,
        observed: PairTotals {
            entries: observed,
            returns: observed,
            completed: observed,
            unsampled: 0,
        },
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    identity: (u32, u64, u64, u64, FunctionId),
    journal_address: u64,
    totals: OptionalTotals,
    next: u64,
    completed: u64,
    gate_base: u64,
    gate_sequence: u64,
    rows: Vec<RawInterval>,
    joins: [u64; EVENTS / 2],
    journal: [u64; 512],
}
fn snapshot(attached: &OptionalThread, gate: &OptionalCallGate) -> Snapshot {
    let gate_sequence = gate.idle_checkpoint().unwrap();
    STATE.with(|cell| {
        let storage = cell.borrow();
        let state = storage.as_ref().unwrap();
        assert!(attached.matches(state));
        assert!(!POISONED.get());
        state.empty().unwrap();
        state.binding.healthy().unwrap();
        assert!(state.pair.is_none());
        assert_eq!(state.model.depth(), 0);
        assert_eq!(state.model.identity(), state.registration);
        assert_eq!(
            state.model.completed_sequence(),
            state.totals.observed.completed
        );
        assert_eq!(state.next, state.totals.observed.entries + 1);
        assert_eq!(attached.finished.get(), Some(state.totals));
        assert!(std::ptr::eq(Arc::as_ptr(&state.binding.site.gate), gate));
        Snapshot {
            identity: (
                state.binding.pid,
                state.tid,
                state.registration,
                state.binding.install,
                state.binding.function,
            ),
            journal_address: state.journal.address(),
            totals: state.totals,
            next: state.next,
            completed: state.model.completed_sequence(),
            gate_base: state.gate_base,
            gate_sequence,
            rows: state.rows.snapshot(),
            joins: state.joins,
            journal: state.journal.page.0,
        }
    })
}
#[derive(Debug, Eq, PartialEq)]
struct SavedBatch {
    identity: (u32, u64, u64, u64, FunctionId),
    number: u64,
    totals: (OptionalTotals, OptionalTotals),
    completed: (u64, u64),
    physical: std::ops::Range<u64>,
    raw: std::ops::Range<u64>,
    events: std::ops::Range<u64>,
    gate_base: u64,
    gate_sequence: u64,
    next: u64,
    rows: Vec<RawInterval>,
    joins: Vec<u64>,
    journal: Vec<u64>,
}
fn saved(batch: &OptionalIntervalBatch) -> SavedBatch {
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
        completed: batch.completed_sequences(),
        physical: batch.physical_range(),
        raw: batch.raw_range(),
        events: batch.event_range(),
        gate_base: batch.gate_base(),
        gate_sequence: batch.gate_sequence(),
        next: batch.next_ordinal(),
        rows: batch.rows().to_vec(),
        joins: batch.observed_gate_sequences().to_vec(),
        journal: batch.journal().to_vec(),
    }
}
fn empty_drain(attached: &mut OptionalThread, gate: &OptionalCallGate) {
    let before = snapshot(attached, gate);
    let cursor = attached.cursor;
    assert!(attached.drain_completed().unwrap().is_none());
    assert_eq!(snapshot(attached, gate), before);
    assert_eq!(attached.cursor, cursor);
}
fn history(controller: &OptionalController, a: GenerationId, b: GenerationId, count: usize) {
    let full = [
        Action {
            kind: ActionKind::Published,
            generation: a,
            function: None,
            current: Some(a),
            group: None,
        },
        Action {
            kind: ActionKind::Removed,
            generation: a,
            function: None,
            current: None,
            group: None,
        },
        Action {
            kind: ActionKind::Published,
            generation: b,
            function: None,
            current: Some(b),
            group: None,
        },
        Action {
            kind: ActionKind::Disabled,
            generation: b,
            function: Some(FUNCTION),
            current: Some(b),
            group: Some(0),
        },
        Action {
            kind: ActionKind::Removed,
            generation: b,
            function: None,
            current: None,
            group: None,
        },
    ];
    assert!(matches!(count, 0 | 1 | 3 | 4 | 5));
    let state = controller.history().unwrap();
    assert_eq!(state.status, ControllerStatus::Ready);
    assert_eq!(state.retained_failed_generation, None);
    assert_eq!(state.actions, full[..count]);
    assert_eq!(
        state.current,
        match count {
            1 => Some(a),
            3 | 4 => Some(b),
            _ => None,
        }
    );
    assert_eq!(state.enabled, [matches!(count, 1 | 3)]);
    assert_eq!(
        controller.binding.site.selector.is_enabled(),
        matches!(count, 1 | 3)
    );
}

#[test]
#[ignore = "requires release fixture reproducer"]
fn optional_native_reuse_and_old_owner() {
    let candidate = std::env::var_os("RAPID_CONCURRENT_CANDIDATE").expect("candidate ELF");
    let expected = std::env::var_os("RAPID_CONCURRENT_EXPECTED").expect("independent expected ELF");
    let candidate = Path::new(&candidate);
    let bytes = expected_file(candidate, Path::new(&expected));
    let cpu = pin(None);
    // SAFETY: this sole selected test owns the trusted local compiler fixture;
    // no constructors/dependencies, foreign calls, CET, signals, unwind, writer or unload.
    let negative =
        unsafe { LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum", CONTRACT) }
            .unwrap();
    assert!(
        negative
            .certificate()
            .returns()
            .iter()
            .any(|&ret| negative.certificate().blocks().contains(&(ret, ret + 1)))
    );
    let id = identity(negative.entry());
    assert!(matches!(
        OptionalSitePreparation::new(negative, id),
        Err(SiteError::Core(Refusal::NoPatchWindow))
    ));
    // SAFETY: same trusted ELF; every call to this separate symbol uses length 1..64.
    let owner = unsafe {
        LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum_nonempty", CONTRACT)
    }
    .unwrap();
    let entry = owner.entry();
    let returns: BTreeSet<_> = owner.certificate().returns().iter().copied().collect();
    let mut prep = OptionalSitePreparation::new(owner, identity(entry)).unwrap();
    assert_eq!(
        prep.role_pcs().collect::<Vec<_>>(),
        std::iter::once(entry)
            .chain(returns.iter().copied())
            .collect::<Vec<_>>()
    );
    let gate = Arc::clone(prep.gate());
    let continuation = gate.continuation();
    assert_eq!(
        gate.idle_checkpoint().unwrap(),
        0,
        "fresh exact-test executor TLS"
    );
    let input_before = guarded();
    let input = Arc::new(input_before);
    let requests: Vec<_> = (0..COUNT)
        .map(|i| (10_000 + i as u64, if i % 2 == 0 { 1 } else { 64 }))
        .collect();
    let readable = stack();
    let mut originals = Vec::with_capacity(COUNT);
    for &(id, length) in &requests {
        let slice = &input[16..16 + length];
        // SAFETY: exclusively borrowed uninstalled original; actual readable stack,
        // immutable valid input, normal SysV return and no signal/nonlocal entry.
        let call = unsafe { prep.prepare_original_call() }.unwrap();
        let result = unsafe { call.invoke(slice.as_ptr(), slice.len(), &readable) }.unwrap();
        assert_eq!(result.value, model(slice));
        assert_eq!(result.pre_call_rsp, result.resumed_rsp);
        assert_eq!(*input, input_before);
        originals.push((id, result.value));
    }
    assert_eq!(gate.idle_checkpoint().unwrap(), 96);
    let mut prepared = PreparedOptionalController::new(
        publish(prep),
        INSTALL,
        FUNCTION,
        Limits {
            epochs: 2,
            threads: 1,
            depth: 1,
            records_per_epoch: 64,
            actions: 5,
        },
    )
    .unwrap();
    let a = prepared
        .stage(Config {
            retained_per_function: 1,
            max_inflight: 1,
            max_invocations: 1,
        })
        .unwrap();
    let b = prepared
        .stage(Config {
            retained_per_function: 63,
            max_inflight: 1,
            max_invocations: 63,
        })
        .unwrap();
    let (ga, gb) = (a.generation(), b.generation());
    // SAFETY: sealed process-lived source; no fork, acquired metadata locks,
    // attachment, allocator reentry or callback/controller lock dependency.
    let (controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    let pause = Arc::new(EntryPause::new(1)); // First Slow ordinal is physical call 33.
    assert!(
        controller
            .binding
            .native_entry_pause
            .set(Arc::clone(&pause))
            .is_ok()
    );
    let journal = IntervalJournal::allocate();
    let journal_address = journal.address();
    // SAFETY: this same executor alone owns invocation/input/stack authority.
    let mut attached = unsafe { client.attach(1, readable, journal) }.unwrap();
    let initial = snapshot(&attached, &gate);
    assert_eq!(
        initial.identity,
        (std::process::id(), tid(), 1, INSTALL, FUNCTION)
    );
    assert_eq!(initial.journal_address, journal_address);
    assert_eq!((initial.gate_base, initial.gate_sequence), (96, 96));
    assert_eq!(
        (initial.totals, initial.next, initial.completed),
        (expected_totals(0), 1, 0)
    );
    let mut empty_page = [0; 512];
    empty_page[2] = initial.identity.1;
    assert_eq!(initial.journal, empty_page);
    assert!(initial.rows.is_empty());
    assert_eq!(initial.joins, [0; EVENTS / 2]);
    history(&controller, ga, gb, 0);
    let mut calls = Vec::with_capacity(COUNT);
    let mut rows = Vec::with_capacity(64);
    let mut batches = Vec::with_capacity(3);
    let mut saved_batches = Vec::with_capacity(3);
    let mut capacity_refusals = 0;
    let mut empty_drains = 0;
    let mut helper_joins = 0;
    let mut old_report: Option<Report> = None;
    // Move controller/tokens through the helper only for the one entered-call transition.
    let mut ownership = Some((controller, a, b));
    for (index, &(id, length)) in requests.iter().enumerate() {
        let mut helper = None;
        if index == 32 {
            let (mut c, a, b) = ownership.take().unwrap();
            c.arm(&a).unwrap();
            history(&c, ga, gb, 1);
            let helper_pause = Arc::clone(&pause);
            let handle = thread::spawn(move || {
                let _release = Release(Arc::clone(&helper_pause));
                pin(Some(cpu));
                let deadline = Instant::now() + WAIT;
                while !helper_pause.entered.load(Ordering::Acquire) {
                    if helper_pause.cancelled.load(Ordering::Acquire) {
                        return HelperDone {
                            controller: c,
                            a,
                            b,
                            transitioned: false,
                        };
                    }
                    assert!(
                        Instant::now() < deadline,
                        "real optional Pair entry required"
                    );
                    thread::yield_now();
                }
                c.disarm(&a).unwrap();
                assert!(c.report(&a).unwrap().is_none());
                assert!(matches!(
                    c.retire(&a),
                    Err(BridgeError {
                        cause: Cause::NotDrained
                    })
                ));
                c.arm(&b).unwrap();
                history(&c, ga, gb, 3);
                HelperDone {
                    controller: c,
                    a,
                    b,
                    transitioned: true,
                }
            });
            helper = Some(Helper {
                pause: Arc::clone(&pause),
                handle: Some(handle),
            });
        }
        let prefix = snapshot(&attached, &gate);
        let slice = &input[16..16 + length];
        // SAFETY: same trusted nonempty input, fixed CPU/stack/ABI, normal return,
        // no signal/nonlocal exit, source writer or foreign gate/callback entry.
        let call = unsafe { attached.invoke_integer_leaf(slice) }.unwrap();
        assert_eq!((id, call.value), originals[index]);
        assert_eq!(call.value, model(slice));
        assert_eq!(call.physical, index as u64 + 1);
        assert_eq!(call.gate_sequence, 96 + call.physical);
        assert_eq!(call.pre_call_rsp, call.resumed_rsp);
        assert_eq!(call.entry_rsp.checked_add(8), Some(call.pre_call_rsp));
        assert!(returns.contains(&call.return_pc));
        assert_eq!(*input, input_before);
        let current = snapshot(&attached, &gate);
        assert_eq!(current.identity, initial.identity);
        assert_eq!(current.journal_address, journal_address);
        assert_eq!(current.totals, expected_totals(call.physical));
        assert_eq!(current.gate_sequence, call.gate_sequence);
        if index < 32 {
            assert_eq!(call.path, OptionalPath::FastBypass);
            assert_eq!(current.rows, prefix.rows);
            assert_eq!(current.journal, prefix.journal);
            assert_eq!(current.joins, prefix.joins);
        } else {
            let ordinal = index as u64 - 31;
            assert_eq!(call.path, OptionalPath::Slow { ordinal });
            assert_eq!(current.rows.len(), prefix.rows.len() + 1);
            assert_eq!(current.rows[..prefix.rows.len()], prefix.rows);
            let row = *current.rows.last().unwrap();
            assert_eq!(
                (row.ordinal, row.entry_pc, row.return_pc),
                (ordinal, entry, call.return_pc)
            );
            assert_eq!(
                row.owner,
                RawIntervalOwner::Sampled {
                    generation: if ordinal == 1 { ga.get() } else { gb.get() },
                    invocation: if ordinal == 1 {
                        0
                    } else {
                        (ordinal - 2) as usize
                    }
                }
            );
            assert!(
                row.elapsed_ticks().is_some(),
                "clock refusal is not successful timing evidence"
            );
            rows.push(row);
        }
        calls.push(call);
        if let Some(ref mut helper) = helper {
            // The genuine invocation/post-return checks precede helper ownership transfer.
            let done = helper.join();
            assert!(done.transitioned);
            helper_joins += 1;
            let mut c = done.controller;
            let report = c.retire(&done.a).unwrap();
            check_report(&report, &rows, ga.get(), 0);
            assert_eq!(c.binding.session.retained_epochs(), 2);
            let before = c.history().unwrap();
            assert_eq!(c.scan_closed().unwrap(), 0);
            assert_eq!(c.history().unwrap(), before);
            history(&c, ga, gb, 3);
            old_report = Some(report);
            ownership = Some((c, done.a, done.b));
        }
        let end = index + 1;
        if !matches!(end, 32 | 64 | 96) {
            continue;
        }
        let (c, _, b) = ownership.as_mut().unwrap();
        if end == 96 {
            assert_eq!(c.scan_closed().unwrap(), 1);
            history(c, ga, gb, 4);
        }
        if end != 32 {
            let before = snapshot(&attached, &gate);
            let cursor = attached.cursor;
            let h = c.history().unwrap();
            let records = c.owner(b).unwrap().records().collect::<Vec<_>>();
            assert_eq!(c.owner(b).unwrap().reservations(), 0);
            assert_eq!(
                unsafe { attached.invoke_integer_leaf(slice) },
                Err(error(Cause::Capacity))
            );
            capacity_refusals += 1;
            assert_eq!(snapshot(&attached, &gate), before);
            assert_eq!(attached.cursor, cursor);
            assert_eq!(c.history().unwrap(), h);
            assert_eq!(c.owner(b).unwrap().records().collect::<Vec<_>>(), records);
            assert_eq!(c.owner(b).unwrap().reservations(), 0);
            assert_eq!(*input, input_before);
        }
        for (old, copy) in batches.iter().zip(&saved_batches) {
            assert_eq!(saved(old), *copy);
        }
        let before = snapshot(&attached, &gate);
        let batch = attached
            .drain_completed()
            .unwrap()
            .expect("nonempty physical batch");
        let begin = end - 32;
        let raw_begin = if begin == 0 { 0 } else { begin - 32 };
        let raw_end = end - 32;
        assert_eq!(batch.number(), (end / 32) as u64);
        assert_eq!(
            (
                batch.pid(),
                batch.tid(),
                batch.registration(),
                batch.install(),
                batch.function()
            ),
            initial.identity
        );
        assert_eq!(
            batch.totals(),
            (expected_totals(begin as u64), expected_totals(end as u64))
        );
        assert_eq!(
            batch.completed_sequences(),
            (raw_begin as u64, raw_end as u64)
        );
        assert_eq!(batch.physical_range(), begin as u64..end as u64);
        assert_eq!(batch.raw_range(), raw_begin as u64..raw_end as u64);
        assert_eq!(
            batch.event_range(),
            2 * raw_begin as u64..2 * raw_end as u64
        );
        assert_eq!(batch.next_ordinal(), raw_end as u64 + 1);
        assert_eq!(
            (batch.gate_base(), batch.gate_sequence()),
            (96, 96 + end as u64)
        );
        assert_eq!(batch.rows(), before.rows);
        assert_eq!(batch.rows(), &rows[raw_begin..raw_end]);
        assert_eq!(batch.journal(), before.journal);
        assert_eq!(
            batch.observed_gate_sequences(),
            (raw_begin..raw_end)
                .map(|n| 129 + n as u64)
                .collect::<Vec<_>>()
        );
        let mut page = empty_page;
        page[0] = (raw_end - raw_begin) as u64 * 2;
        for (local, row) in batch.rows().iter().enumerate() {
            let n = raw_begin + local;
            let actual = calls[32 + n];
            let (generation, invocation, prefix) = if n == 0 {
                (ga.get(), 0, 1)
            } else {
                (gb.get(), n - 1, 3)
            };
            for side in 0..2 {
                let at = 4 + (local * 2 + side) * 7;
                page[at..at + 7].copy_from_slice(&[
                    1 + side as u64,
                    n as u64 + 1,
                    if side == 0 { entry } else { actual.return_pc },
                    actual.entry_rsp,
                    continuation,
                    generation,
                    (invocation as u64 + 1) | (prefix << 13),
                ]);
            }
            assert_eq!(row.return_pc, actual.return_pc);
        }
        assert_eq!(batch.journal(), page); // Every one of 512 words, including all zero tails.
        let mut after = before;
        after.rows.clear();
        after.joins.fill(0);
        after.journal = empty_page;
        assert_eq!(snapshot(&attached, &gate), after);
        saved_batches.push(saved(&batch));
        batches.push(batch);
        empty_drain(&mut attached, &gate);
        empty_drains += 1;
        history(
            c,
            ga,
            gb,
            if end == 32 {
                0
            } else if end == 64 {
                3
            } else {
                4
            },
        );
    }
    let (mut controller, _, b) = ownership.take().unwrap();
    assert_eq!(
        (originals.len(), calls.len(), rows.len(), batches.len()),
        (96, 96, 64, 3)
    );
    assert_eq!((capacity_refusals, empty_drains, helper_joins), (2, 3, 1));
    assert_eq!(
        calls.iter().map(|c| c.return_pc).collect::<BTreeSet<_>>(),
        returns
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
    let report_a = old_report.take().unwrap();
    let a_records = report_a.records().collect::<Vec<_>>();
    check_report(&report_a, &rows[..1], ga.get(), 0);
    controller.disarm(&b).unwrap();
    history(&controller, ga, gb, 5);
    let report_b = controller.retire(&b).unwrap();
    check_report(&report_b, &rows[1..], gb.get(), 1);
    assert_eq!(
        (report_a.records().count(), report_b.records().count()),
        (1, 63)
    );
    assert_eq!(report_a.records().collect::<Vec<_>>(), a_records);
    assert_eq!(controller.binding.session.retained_epochs(), 2);
    for (batch, copy) in batches.iter().zip(&saved_batches) {
        assert_eq!(saved(batch), *copy);
    }
    let final_state = snapshot(&attached, &gate);
    assert_eq!(
        (final_state.totals, final_state.next, final_state.completed),
        (expected_totals(96), 65, 64)
    );
    assert_eq!(
        (final_state.gate_base, final_state.gate_sequence),
        (96, 192)
    );
    assert!(final_state.rows.is_empty());
    assert_eq!(final_state.joins, [0; EVENTS / 2]);
    assert_eq!(final_state.journal, empty_page);
    assert_eq!(attached.detach().unwrap(), expected_totals(96));
    assert!(!attached.active);
    assert!(STATE.with(|c| c.borrow().is_none()));
    assert!(!POISONED.get());
    assert_eq!(*input, input_before);
    assert_eq!(Arc::strong_count(&input), 1);
    // Report permits, not code quiescence: all physical returns, detach and the
    // actual helper join already happened. Data-only batches remain retained.
    drop(report_a);
    assert_eq!(controller.binding.session.retained_epochs(), 1);
    drop(report_b);
    assert_eq!(controller.binding.session.retained_epochs(), 0);
    println!(
        "optional-native PASS originals=96 calls=96 fast=32 slow=64 sampled=64 unsampled=0 rows=64 events=128 batches=3 capacity_refusals=2 empty_drains=3 epochs=2 report_records=64 actions=5 registrations=1 helper_joins=1 short_ret_refusals=1 detached=true input_unchanged=true"
    );
}
