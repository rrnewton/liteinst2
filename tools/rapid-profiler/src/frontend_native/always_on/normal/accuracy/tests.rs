//! Mocked kernel observations through the real counter and NORMAL transactions.
//! These controls confer no PMU, native-state, clock or physical-return credit.
use super::*;
use NormalCounterOperation::{Close, Disable, Enable, Id, Read};
use counter::{Request, System};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

type Reply = (NormalCounterOperation, NormalCounterSyscall, [u8; 32]);
struct Script {
    owner: NormalCounterIdentity,
    open: NormalCounterSyscall,
    mutate_attr: bool,
    replies: VecDeque<Reply>,
    calls: Vec<NormalCounterOperation>,
    requests: Vec<Vec<u8>>,
    ticks: u64,
    reads: u64,
}
impl Default for Script {
    fn default() -> Self {
        Self {
            owner: NormalCounterIdentity {
                pid: std::process::id(),
                tid: tid(),
            },
            open: success(19),
            mutate_attr: false,
            replies: VecDeque::new(),
            calls: Vec::new(),
            requests: Vec::new(),
            ticks: 0,
            reads: 0,
        }
    }
}
fn success(result: i64) -> NormalCounterSyscall {
    NormalCounterSyscall {
        result,
        errno: None,
    }
}
fn failure(errno: i32) -> NormalCounterSyscall {
    NormalCounterSyscall {
        result: -1,
        errno: Some(errno),
    }
}
fn words(a: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (slot, value) in bytes.chunks_exact_mut(8).zip(a) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    bytes
}
struct Mock(Rc<RefCell<Script>>);
impl System for Mock {
    fn identity(&mut self) -> NormalCounterIdentity {
        self.0.borrow().owner
    }
    fn stamp(&mut self) -> RawTimestamp {
        let mut s = self.0.borrow_mut();
        s.ticks += 1;
        RawTimestamp {
            ticks: s.ticks,
            aux: (s.ticks & 1) as u32,
        }
    }
    fn open(&mut self, a: &mut Request) -> NormalCounterSyscall {
        let mut s = self.0.borrow_mut();
        s.requests.push(a.0.to_vec());
        if s.mutate_attr {
            a.0[4..8].copy_from_slice(&64u32.to_le_bytes());
        }
        s.open
    }
    fn operate(
        &mut self,
        fd: i32,
        op: NormalCounterOperation,
        data: &mut [u8; 32],
    ) -> NormalCounterSyscall {
        assert_eq!(fd, 19);
        let mut s = self.0.borrow_mut();
        s.calls.push(op);
        if let Some((expected, result, bytes)) = s.replies.pop_front() {
            assert_eq!(op, expected);
            *data = bytes;
            return result;
        }
        match op {
            Id => {
                *data = words([41, 0, 0, 0]);
                success(0)
            }
            Read => {
                s.reads += 1;
                *data = words([s.reads * 7, s.reads * 10, s.reads * 9, 41]);
                success(32)
            }
            _ => success(0),
        }
    }
}
fn counter(script: Rc<RefCell<Script>>) -> Counter {
    Counter::with_system(Box::new(Mock(script)))
}
fn fixture(
    script: Rc<RefCell<Script>>,
) -> (
    NormalState,
    NormalLeafSetSessionController,
    Option<IntervalEpoch>,
    Vec<IntervalEpochStorage>,
) {
    let (mut state, controller, epoch, banks) = leaf_set::accuracy_fixture();
    state.accuracy = Some(Box::new(State::new(counter(script))));
    (state, controller, epoch, banks)
}
fn enter(s: &mut NormalState, index: usize) -> Result<(), BridgeError> {
    let selected = s.selection(index)?;
    s.enter_function(
        selected,
        [0x1000, 0x1100][index],
        0x8008,
        0x9000 + s.next * 8,
        RawTimestamp {
            ticks: s.next * 100,
            aux: 7,
        },
    )
}
fn observe(s: &mut NormalState, index: usize) -> Result<(), BridgeError> {
    let p = s.pending.as_ref().unwrap();
    let (ordinal, word) = (p.ordinal, p.word);
    s.observe_function(
        s.selection(index)?,
        [0x1010, 0x1110][index],
        0x8008,
        word,
        RawTimestamp {
            ticks: ordinal * 100 + 17,
            aux: 7,
        },
    )
}
fn call(s: &mut NormalState, index: usize) {
    enter(s, index).unwrap();
    observe(s, index).unwrap();
}
fn transfer(s: &mut NormalState) -> NormalLeafSetAccuracyBatch {
    let (out, journal) = Output::allocate().unwrap();
    s.transfer_into(out, journal).unwrap().unwrap()
}
#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    slots: [Option<Endpoints>; CALLS],
    records: [Option<NormalRecord>; CALLS],
    functions: [Option<SelectedFunction>; CALLS],
    journal: [u64; 512],
    len: usize,
    next: u64,
    totals: NormalTotals,
    cursor: Cursor,
    pending: Option<(SelectedFunction, u64, Option<RawInterval>)>,
    depth: usize,
    sequence: u64,
}
fn snapshot(s: &NormalState) -> Snapshot {
    Snapshot {
        slots: s.accuracy.as_ref().unwrap().slots,
        records: s.records,
        functions: s.functions,
        journal: s.journal.page.0,
        len: s.len,
        next: s.next,
        totals: s.totals,
        cursor: s.cursor,
        pending: s
            .pending
            .as_ref()
            .map(|p| (p.selected, p.ordinal, p.returned)),
        depth: s.model.depth(),
        sequence: s.model.completed_sequence(),
    }
}

#[test]
fn accuracy_attributes_are_exact_current_thread_pinned_non_inherited_instructions() {
    let script = Rc::new(RefCell::new(Script::default()));
    let c = counter(script.clone());
    let a = c.acquisition();
    let mut expected = [0u8; 128];
    expected[4..8].copy_from_slice(&128u32.to_le_bytes()); // PERF_TYPE_HARDWARE = 0.
    expected[8..16].copy_from_slice(&1u64.to_le_bytes()); // HW_INSTRUCTIONS = 1.
    expected[32..40].copy_from_slice(&7u64.to_le_bytes()); // enabled/running/ID.
    expected[40..48]
        .copy_from_slice(&((1u64 << 0) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 20)).to_le_bytes());
    assert_eq!(a.requested_attributes, expected);
    assert_eq!(a.attributes_after_open, expected);
    assert_eq!(script.borrow().requests, [expected.to_vec()]);
    assert_eq!(a.open, success(19));
    assert_eq!(a.event_id(), Some(41));
    assert_eq!(a.id.unwrap().operation, Id);
    assert_eq!(a.enable.unwrap().operation, Enable);
}
#[test]
fn accuracy_open_failure_retains_both_attr_images_and_errno_without_ioctl_or_read() {
    let script = Rc::new(RefCell::new(Script {
        open: failure(libc::E2BIG),
        mutate_attr: true,
        ..Script::default()
    }));
    let mut c = counter(script.clone());
    let a = c.acquisition();
    assert_eq!(&a.requested_attributes[4..8], &128u32.to_le_bytes());
    assert_eq!(&a.attributes_after_open[4..8], &64u32.to_le_bytes());
    assert_eq!(a.open, failure(libc::E2BIG));
    assert_eq!((a.id, a.enable), (None, None));
    let e = c.endpoint();
    assert!(e.read.is_none());
    assert_eq!(e.event_id_matches, None);
    assert!(e.owner_matches);
    assert_eq!((e.before.ticks, e.after.ticks), (1, 2));
    let close = c.close();
    assert_eq!((close.disable, close.close), (None, None));
    assert!(script.borrow().calls.is_empty());
}
#[test]
fn accuracy_each_partial_read_and_error_retains_exact_raw_buffer_and_result() {
    for result in -1..=33 {
        let script = Rc::new(RefCell::new(Script::default()));
        let mut c = counter(script.clone());
        let syscall = if result < 0 {
            failure(libc::EINTR)
        } else {
            success(result)
        };
        let bytes = words([u64::MAX, 23, 11, 41]);
        script
            .borrow_mut()
            .replies
            .push_back((Read, syscall, bytes));
        let e = c.endpoint();
        let r = e.read.unwrap();
        assert_eq!(r.syscall, syscall);
        assert_eq!(r.data, bytes);
        assert_eq!(
            r.data_len,
            if result < 0 {
                0
            } else {
                (result as usize).min(32)
            }
        );
        assert_eq!(r.reading().is_some(), result == 32);
        assert_eq!(r.event_id(), if result == 32 { Some(41) } else { None });
        assert_eq!(
            e.event_id_matches,
            if result == 32 { Some(true) } else { None }
        );
        assert_eq!(
            (e.before, e.after),
            (
                RawTimestamp { ticks: 1, aux: 1 },
                RawTimestamp { ticks: 2, aux: 0 }
            )
        );
    }
}
#[test]
fn accuracy_id_enable_and_read_identity_failures_never_discard_words() {
    for bad_id in [false, true] {
        let script = Rc::new(RefCell::new(Script::default()));
        script.borrow_mut().replies.extend([
            (
                Id,
                if bad_id {
                    failure(libc::EINVAL)
                } else {
                    success(0)
                },
                words([41, 0, 0, 0]),
            ),
            (Enable, failure(libc::EIO), [0; 32]),
            (Read, success(32), words([9, 20, 12, 42])),
        ]);
        let mut c = counter(script.clone());
        let a = c.acquisition();
        let e = c.endpoint();
        assert_eq!(a.enable.unwrap().syscall, failure(libc::EIO));
        assert_eq!(a.id.unwrap().data, words([41, 0, 0, 0]));
        assert_eq!(e.event_id_matches, if bad_id { None } else { Some(false) });
        assert_eq!(e.read.unwrap().reading().unwrap().value, 9);
        assert_eq!(e.read.unwrap().event_id(), Some(42));
        assert_eq!(script.borrow().calls, [Id, Enable, Read]);
    }
}
#[test]
fn accuracy_pid_or_tid_mismatch_cannot_read_disable_or_close_foreign_owner() {
    for process in [false, true] {
        let script = Rc::new(RefCell::new(Script::default()));
        let mut c = counter(script.clone());
        let owner = script.borrow().owner;
        if process {
            script.borrow_mut().owner.pid += 1;
        } else {
            script.borrow_mut().owner.tid += 1;
        }
        let e = c.endpoint();
        assert!(!e.owner_matches);
        assert!(e.read.is_none());
        let closed = c.close();
        assert_eq!((closed.disable, closed.close), (None, None));
        assert_ne!(closed.observer, closed.acquisition.owner);
        assert_eq!(script.borrow().calls, [Id, Enable]);
        script.borrow_mut().owner = owner;
        let closed = c.close();
        assert_eq!(closed.close.unwrap().syscall, success(0));
    }
}
#[test]
fn accuracy_disable_and_close_failures_are_retained_and_close_is_never_retried() {
    let script = Rc::new(RefCell::new(Script::default()));
    let mut c = counter(script.clone());
    script.borrow_mut().replies.extend([
        (Disable, failure(libc::EIO), [0; 32]),
        (Close, failure(libc::EINTR), [0; 32]),
    ]);
    let closed = c.close();
    assert_eq!(closed.disable.unwrap().syscall, failure(libc::EIO));
    assert_eq!(closed.close.unwrap().syscall, failure(libc::EINTR));
    assert_eq!(closed.acquisition, c.acquisition());
    assert_eq!((c.close().disable, c.close().close), (None, None));
    drop(c);
    assert_eq!(script.borrow().calls, [Id, Enable, Disable, Close]);
}
#[test]
fn accuracy_drop_has_one_owned_close_even_during_unwind() {
    let script = Rc::new(RefCell::new(Script::default()));
    let shared = script.clone();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _owned = counter(shared);
        panic!("mock owner unwind");
    }));
    assert!(outcome.is_err());
    assert_eq!(script.borrow().calls, [Id, Enable, Disable, Close]);
}
#[test]
fn accuracy_32_real_normal_calls_keep_sampled_unsampled_and_exact_acknowledgments() {
    let script = Rc::new(RefCell::new(Script::default()));
    let (mut s, _c, _e, _b) = fixture(script.clone());
    for i in 0..32 {
        call(&mut s, i % 2);
    }
    assert_eq!(
        (s.len, s.totals.confirmed, s.totals.ret_observed),
        (31, 31, 32)
    );
    let batch = transfer(&mut s);
    assert_eq!(batch.counters().len(), 32);
    let (normal, rows, acquisition) = batch.into_parts();
    assert_eq!(normal.records().len(), 32);
    assert_eq!(acquisition.event_id(), Some(41));
    assert_eq!(
        (normal.totals().1.completed, normal.totals().1.unsampled),
        (20, 12)
    );
    for (i, (row, ordinary)) in rows.iter().zip(normal.records()).enumerate() {
        assert_eq!(row.ordinal(), i as u64 + 1);
        assert_eq!(row.function(), [FunctionId(0), FunctionId(29)][i % 2]);
        assert_eq!(
            (row.function(), row.normal()),
            (ordinary.function, ordinary.record)
        );
        assert_eq!(
            row.normal().acknowledgement,
            if i == 31 {
                NormalAcknowledgement::CallerCheckpoint
            } else {
                NormalAcknowledgement::NextEntry {
                    ordinal: i as u64 + 2,
                }
            }
        );
        assert_eq!(
            row.start().read.unwrap().reading().unwrap().value,
            (i as u64 * 2 + 1) * 7
        );
        assert_eq!(
            row.end().read.unwrap().reading().unwrap().value,
            (i as u64 * 2 + 2) * 7
        );
        assert_eq!(
            row.counters(),
            CounterRecord::new(
                row.start().read.and_then(NormalCounterRead::reading),
                row.end().read.and_then(NormalCounterRead::reading)
            )
        );
        assert_eq!(
            (row.start().event_id_matches, row.end().event_id_matches),
            (Some(true), Some(true))
        );
    }
    assert_eq!(script.borrow().reads, 64);
    assert!(
        s.accuracy
            .as_ref()
            .unwrap()
            .slots
            .iter()
            .all(Option::is_none)
    );
    assert_eq!((s.next, s.len, s.cursor.number), (33, 0, 1));
    assert!(s.pending.is_none());
    let (out, page) = Output::allocate().unwrap();
    assert!(s.transfer_into(out, page).unwrap().is_none());
    call(&mut s, 1);
    let next = transfer(&mut s);
    assert_eq!(next.counters()[0].ordinal(), 33);
    assert_eq!(next.acquisition(), acquisition);
    assert_eq!(
        next.counters()[0]
            .start()
            .read
            .unwrap()
            .reading()
            .unwrap()
            .value,
        65 * 7
    );
    assert_eq!(script.borrow().requests.len(), 1); // No reopen, reset or clear-on-read.
}
#[test]
fn accuracy_all_pmu_open_failures_preserve_all_normal_work_and_missing_endpoints() {
    for errno in [
        libc::EACCES,
        libc::EPERM,
        libc::ENODEV,
        libc::EINVAL,
        libc::EMFILE,
    ] {
        let script = Rc::new(RefCell::new(Script {
            open: failure(errno),
            ..Script::default()
        }));
        let (mut s, _c, _e, _b) = fixture(script.clone());
        for i in 0..32 {
            call(&mut s, i % 2);
        }
        let batch = transfer(&mut s);
        assert_eq!(batch.counters().len(), 32);
        assert_eq!(batch.acquisition().open, failure(errno));
        assert_eq!(batch.normal().records().len(), 32);
        for r in batch.counters() {
            assert_eq!(r.counters(), CounterRecord::new(None, None));
            assert_eq!((r.start().read, r.end().read), (None, None));
        }
        assert_eq!(
            (
                batch.normal().totals().1.completed,
                batch.normal().totals().1.unsampled
            ),
            (20, 12)
        );
        assert!(script.borrow().calls.is_empty());
    }
}
#[test]
fn accuracy_short_or_error_endpoints_survive_real_normal_checkpoint() {
    let script = Rc::new(RefCell::new(Script::default()));
    let (mut s, _c, _e, _b) = fixture(script.clone());
    let start = (Read, success(17), words([41, 42, 43, 44]));
    let end = (Read, failure(libc::EINTR), words([51, 52, 53, 54]));
    script.borrow_mut().replies.extend([start, end]);
    call(&mut s, 1);
    let batch = transfer(&mut s);
    let row = batch.counters()[0];
    assert_eq!(row.start().read.unwrap().data, start.2);
    assert_eq!(row.end().read.unwrap().data, end.2);
    assert_eq!(row.start().read.unwrap().syscall, start.1);
    assert_eq!(row.end().read.unwrap().syscall, end.1);
    assert_eq!(row.counters(), CounterRecord::new(None, None));
    assert_eq!(batch.normal().totals().1.confirmed, 1);
}
#[test]
fn accuracy_pre_ret_endpoint_does_not_acknowledge_receipt_and_missing_ret_refuses() {
    let script = Rc::new(RefCell::new(Script::default()));
    let (mut s, _c, _e, _b) = fixture(script);
    enter(&mut s, 0).unwrap();
    let before = snapshot(&s);
    let (out, page) = Output::allocate().unwrap();
    assert!(s.transfer_into(out, page).is_err());
    assert_eq!(snapshot(&s), before);
    observe(&mut s, 0).unwrap();
    assert_eq!((s.totals.confirmed, s.model.depth()), (0, 1));
    assert!(s.pending.as_ref().unwrap().returned.is_some());
    assert!(s.accuracy.as_ref().unwrap().slots[0].unwrap().end.is_some());
    let batch = transfer(&mut s);
    assert_eq!(
        batch.counters()[0].normal().acknowledgement,
        NormalAcknowledgement::CallerCheckpoint
    );
    assert_eq!((s.totals.confirmed, s.model.depth()), (1, 0));
}
#[test]
fn accuracy_legacy_export_and_allocation_refusals_cannot_drop_or_ack_sidecars() {
    let script = Rc::new(RefCell::new(Script::default()));
    let (mut s, _c, _e, _b) = fixture(script);
    call(&mut s, 0);
    let before = snapshot(&s);
    let (out, page) = leaf_set::LeafSetOutput::allocate().unwrap();
    assert_eq!(s.transfer_into(out, page), Err(error(Cause::Attachment)));
    assert_eq!(snapshot(&s), before);
    for slot in [0, 1] {
        FAIL_RESERVE.set(Some(slot));
        let result = Output::allocate();
        FAIL_RESERVE.set(None);
        assert!(matches!(result,Err(e) if e==error(Cause::Capacity)));
        assert_eq!(snapshot(&s), before);
    }
    let (out, _) = Output::allocate().unwrap();
    assert_eq!(
        s.transfer_into(out, Vec::new()),
        Err(error(Cause::Capacity))
    );
    assert_eq!(snapshot(&s), before);
    assert_eq!(transfer(&mut s).counters().len(), 1);
}
#[test]
fn accuracy_33rd_call_refuses_capacity_without_an_extra_endpoint_or_reset() {
    let script = Rc::new(RefCell::new(Script::default()));
    let (mut s, _c, _e, _b) = fixture(script.clone());
    for i in 0..32 {
        call(&mut s, i % 2);
    }
    let slots = s.accuracy.as_ref().unwrap().slots;
    assert_eq!(enter(&mut s, 0), Err(error(Cause::Capacity)));
    assert_eq!(s.accuracy.as_ref().unwrap().slots, slots);
    assert_eq!(script.borrow().reads, 64);
    assert_eq!(s.next, 33);
    // The old entry contract acknowledges the previous returned receipt before
    // reserving the next call; that unchanged acknowledgment is retained exactly.
    let batch = transfer(&mut s);
    assert_eq!(batch.counters().len(), 32);
    assert_eq!(
        batch.counters()[31].normal().acknowledgement,
        NormalAcknowledgement::NextEntry { ordinal: 33 }
    );
}
#[test]
fn accuracy_sidecar_key_end_presence_and_owner_drift_refuse_without_consumption() {
    for mutation in 0..5 {
        let script = Rc::new(RefCell::new(Script::default()));
        let (mut s, _c, _e, _b) = fixture(script);
        call(&mut s, 0);
        let saved = s.accuracy.as_ref().unwrap().slots;
        let foreign = s.selection(1).unwrap();
        let a = s.accuracy.as_mut().unwrap();
        let row = a.slots[0].as_mut().unwrap();
        match mutation {
            0 => row.ordinal += 1,
            1 => row.selected = foreign,
            2 => row.end = None,
            3 => a.slots[1] = a.slots[0],
            _ => a.slots[0] = None,
        }
        let before = snapshot(&s);
        let (out, page) = Output::allocate().unwrap();
        assert_eq!(s.transfer_into(out, page), Err(error(Cause::Invariant)));
        assert_eq!(snapshot(&s), before);
        s.accuracy.as_mut().unwrap().slots = saved;
        assert_eq!(transfer(&mut s).counters().len(), 1);
    }
}

struct TlsCleanup;
impl Drop for TlsCleanup {
    fn drop(&mut self) {
        // Test-only explicit cleanup of inert metadata, never native retirement.
        NORMAL.with(|cell| drop(cell.borrow_mut().0.take()));
        NORMAL_POISON.set(false);
    }
}
fn install_tls(s: NormalState) -> NormalLeafSetAccuracyThread {
    assert!(!NORMAL_POISON.get());
    let handle = NormalThread {
        key: Arc::clone(&s.binding.key),
        pid: s.binding.pid,
        thread: s.actual_thread,
        tid: s.tid,
        registration: s.registration,
        active: true,
        _local: PhantomData,
    };
    NORMAL.with(|cell| {
        let mut slot = cell.borrow_mut();
        assert!(slot.0.is_none());
        slot.0 = Some(Box::new(s));
    });
    NormalLeafSetAccuracyThread(handle)
}
#[test]
fn accuracy_facade_checkpoint_and_empty_detach_return_all_counter_custody() {
    let script = Rc::new(RefCell::new(Script::default()));
    let (mut s, _c, _e, _b) = fixture(script.clone());
    call(&mut s, 0);
    let _cleanup = TlsCleanup;
    let mut handle = install_tls(s);
    let acquisition = handle.acquisition().unwrap();
    assert_eq!(handle.totals().unwrap().confirmed, 0);
    assert_eq!(handle.detach(), Err(error(Cause::Outstanding)));
    assert_eq!(
        handle.0.detach_profile(TransferProfile::LeafSet),
        Err(error(Cause::Outstanding))
    );
    assert_eq!(script.borrow().calls, [Id, Enable, Read, Read]);
    // SAFETY: metadata-only fixture; no executable/application call exists.
    let batch = unsafe { handle.checkpoint_after_returns() }
        .unwrap()
        .unwrap();
    assert_eq!(batch.acquisition(), acquisition);
    assert_eq!(batch.counters().len(), 1);
    script.borrow_mut().replies.extend([
        (Disable, failure(libc::EIO), [0; 32]),
        (Close, failure(libc::EINTR), [0; 32]),
    ]);
    let detached = handle.detach().unwrap();
    assert_eq!(detached.totals.confirmed, 1);
    assert_eq!(detached.counter.acquisition, acquisition);
    assert_eq!(
        detached.counter.disable.unwrap().syscall,
        failure(libc::EIO)
    );
    assert_eq!(
        detached.counter.close.unwrap().syscall,
        failure(libc::EINTR)
    );
    assert!(handle.acquisition().is_err());
    assert_eq!(handle.detach(), Err(error(Cause::Attachment)));
    drop(handle);
    assert_eq!(
        script.borrow().calls,
        [Id, Enable, Read, Read, Disable, Close]
    );
}
#[test]
fn accuracy_dropped_or_forgotten_handle_keeps_normal_receipt_and_counter_owner() {
    for forget in [false, true] {
        let script = Rc::new(RefCell::new(Script::default()));
        let (mut s, _c, _e, _b) = fixture(script.clone());
        call(&mut s, 0);
        let _cleanup = TlsCleanup;
        let handle = install_tls(s);
        if forget {
            std::mem::forget(handle);
        } else {
            drop(handle);
        }
        assert_eq!(NORMAL_POISON.get(), !forget);
        NORMAL.with(|cell| {
            let slot = cell.borrow();
            let s = slot.0.as_ref().unwrap();
            assert!(s.pending.is_some());
            assert!(s.accuracy.as_ref().unwrap().slots[0].is_some());
            assert_eq!(s.model.depth(), 1);
            assert_eq!(
                s.failure,
                if forget {
                    None
                } else {
                    Some(error(Cause::Outstanding))
                }
            );
        });
        assert_eq!(script.borrow().calls, [Id, Enable, Read, Read]);
    }
}
#[test]
fn accuracy_state_owner_drift_refuses_export_without_consumption() {
    let script = Rc::new(RefCell::new(Script::default()));
    let (mut s, _c, _e, _b) = fixture(script);
    call(&mut s, 0);
    let actual = s.tid;
    s.tid += 1;
    let before = snapshot(&s);
    let (out, page) = Output::allocate().unwrap();
    assert_eq!(s.transfer_into(out, page), Err(error(Cause::Identity)));
    assert_eq!(snapshot(&s), before);
    s.tid = actual;
    assert_eq!(transfer(&mut s).counters().len(), 1);
}
