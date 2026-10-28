//! Fresh-process native ownership controls, not a state or timing oracle.
//! The existing complete normal-caller state prerequisite remains separate.
use super::*;
use crate::frontend::{Action, ActionKind, PayloadOutcome};
use crate::frontend_native::always_on::tests::concurrent_native::{
    expected_file, identity, pin, protect, stack,
};
use crate::frontend_native::{
    InstalledTwoCallerNormalSite, LoadedTwoCallerNormalLeaf, TrustedFunctionSelection,
    TwoCallerNormalLeafContract, TwoCallerNormalSitePreparation,
};
use crate::generation::{Disposition, Terminal};
use liteinst2::bundle::WritableAlias;
use liteinst2::contracts::*;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
mod check;

const INSTALL: u64 = 0x7477_6f01;
const FUNCTION: FunctionId = FunctionId(1);
const CONFIG: Config = Config {
    retained_per_function: 1,
    max_inflight: 2,
    max_invocations: 4096,
};
const LABEL: &str = "freebsd-strnlen-14.1-v1";

#[derive(Clone, Copy)]
struct Deadline(Instant);
impl Deadline {
    fn new() -> Self {
        Self(Instant::now().checked_add(Duration::from_secs(15)).unwrap())
    }
    fn remaining(self) -> Duration {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .expect("original absolute native-control deadline")
    }
    fn check(self) {
        let _ = self.remaining();
    }
    fn recv<T>(self, rx: &Receiver<T>) -> T {
        rx.recv_timeout(self.remaining().min(Duration::from_secs(2)))
            .expect("owned bounded native-control rendezvous")
    }
    fn send<T>(self, tx: &SyncSender<T>, mut value: T) {
        loop {
            self.check();
            match tx.try_send(value) {
                Ok(()) => return,
                Err(TrySendError::Full(v)) => {
                    value = v;
                    thread::yield_now();
                }
                Err(TrySendError::Disconnected(_)) => panic!("owned native-control receiver lost"),
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingCopy {
    ordinal: u64,
    rsp: u64,
    word: u64,
    entry: u64,
    start: RawTimestamp,
    slot: ModelReturnSlot,
    summary: Option<IntervalEntrySummary>,
    receipt_summary: Option<IntervalEntrySummary>,
    raw: Option<RawInterval>,
}
fn pending_copy(p: &Pending) -> PendingCopy {
    PendingCopy {
        ordinal: p.ordinal,
        rsp: p.rsp,
        word: p.word,
        entry: p.entry_pc,
        start: p.start,
        slot: p.slot,
        summary: p.summary,
        receipt_summary: p.receipt.summary(),
        raw: p.returned,
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    pid: u32,
    tid: u64,
    registration: u64,
    actual_thread: ThreadId,
    model: (u64, usize, u64),
    totals: NormalTotals,
    cursor: Cursor,
    next: u64,
    records: [Option<NormalRecord>; CALLS],
    len: usize,
    journal: [u64; 512],
    journal_address: u64,
    pending: Option<PendingCopy>,
    failure: Option<BridgeError>,
    busy: bool,
}
fn snapshot(state: &NormalState) -> Snapshot {
    assert!(!NORMAL_POISON.get());
    Snapshot {
        pid: state.binding.pid,
        tid: state.tid,
        registration: state.registration,
        actual_thread: state.actual_thread,
        model: (
            state.model.identity(),
            state.model.depth(),
            state.model.completed_sequence(),
        ),
        totals: state.totals,
        cursor: state.cursor,
        next: state.next,
        records: state.records,
        len: state.len,
        journal: state.journal.page.0,
        journal_address: state.journal.address(),
        pending: state.pending.as_ref().map(pending_copy),
        failure: state.failure,
        busy: state.busy,
    }
}
fn local(attached: &NormalThread) -> Snapshot {
    let actual_totals = attached.totals().unwrap();
    NORMAL.with(|cell| {
        let storage = cell.borrow();
        let state = storage.0.as_ref().unwrap();
        assert!(attached.matches(state));
        assert_eq!(state.totals, actual_totals);
        state.health().unwrap();
        state.shape().unwrap();
        snapshot(state)
    })
}

// Test-only, safe-Rust custody of a genuine receipt. No NormalThread/NormalState
// is sent. Both workers are quiescent until restoration. Unexpected channel
// loss leaks this owner rather than acknowledging/cancelling a pending receipt.
struct Receipt {
    pending: Option<Box<Pending>>,
    origin: (u64, u64),
    before: PendingCopy,
    address: usize,
}
impl Drop for Receipt {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            let _ = Box::leak(pending);
        }
    }
}
impl Receipt {
    fn check(&self) {
        let pending = self.pending.as_ref().unwrap();
        assert_eq!(pending_copy(pending), self.before);
        assert_eq!(std::ptr::from_ref(&pending.receipt) as usize, self.address);
    }
}

enum Command {
    Call,
    Checkpoint,
    Snapshot,
    Take,
    Refuse(Receipt),
    Restore(Receipt),
    Stop,
}
enum Event {
    Ready {
        state: Snapshot,
        stack: (u64, u64),
    },
    Returned {
        value: u64,
        before_rsp: u64,
        after_rsp: u64,
        state: Snapshot,
    },
    Batch(Box<NormalBatch>),
    Snapshot(Snapshot),
    Receipt(Receipt),
    Restored(Snapshot),
    Finished(NormalTotals),
}
#[derive(Clone)]
struct Shared {
    entry: u64,
    returns: BTreeSet<u64>,
    spans: Arc<Vec<(u64, Vec<u8>)>>,
}
impl Shared {
    fn verify(&self) {
        for (address, bytes) in self.spans.iter() {
            // SAFETY: sealed process-lived source/images, immutable no-writer
            // contract. Reading verifies bytes, not mapping lifetime itself.
            assert_eq!(
                unsafe { std::slice::from_raw_parts(*address as usize as *const u8, bytes.len()) },
                bytes
            );
        }
    }
}
fn input(worker: usize) -> [u8; 96] {
    let mut data = [0xa5; 96];
    for (i, b) in data[16..80].iter_mut().enumerate() {
        *b = (1 + (37 * i + 128) % 255) as u8;
    }
    if worker == 1 {
        data[16] = 0;
    }
    data[80..].fill(0x5a);
    data
}
fn worker(
    index: usize,
    cpu: usize,
    deadline: Deadline,
    shared: Shared,
    client: NormalClient,
    rx: Receiver<Command>,
    tx: SyncSender<Event>,
) -> NormalTotals {
    pin(Some(cpu));
    let data = input(index);
    let before = data;
    let readable = stack();
    let range = (readable.start, readable.end);
    // SAFETY: distinct T2 owner, actual worker stack/input/journal, globally
    // quiescent setup. Main will collect BOTH Ready before dispatching any Call.
    let mut attached = unsafe {
        client.attach_two_callers(index as u64 + 1, readable, IntervalJournal::allocate())
    }
    .unwrap();
    let initial = local(&attached);
    deadline.send(
        &tx,
        Event::Ready {
            state: initial,
            stack: range,
        },
    );
    let mut taken: Option<Snapshot> = None;
    loop {
        let command = deadline.recv(&rx);
        if taken.is_some() {
            assert!(
                matches!(command, Command::Restore(_)),
                "no call/checkpoint while receipt transferred"
            );
        }
        match command {
            Command::Call => {
                assert!(
                    local(&attached).pending.is_none(),
                    "each test call explicitly confirmed before same-worker reuse"
                );
                shared.verify();
                assert_eq!(data, before);
                let before_rsp: u64;
                unsafe {
                    std::arch::asm!("mov {}, rsp", out(reg) before_rsp, options(nomem, nostack, preserves_flags));
                }
                // SAFETY: exact independently admitted strnlen C ABI, live 64B
                // immutable input, attached actual thread; no reentry/signals/
                // CET/nonlocal exit/fork/writer/unload. This is an ordinary CALL,
                // not an SDK invoke or assembly gate. Postflight prevents tail-call.
                let f: unsafe extern "C" fn(*const u8, usize) -> u64 =
                    unsafe { std::mem::transmute(shared.entry as usize) };
                let value = unsafe { f(data[16..80].as_ptr(), 64) };
                let after_rsp: u64;
                unsafe {
                    std::arch::asm!("mov {}, rsp", out(reg) after_rsp, options(nomem, nostack, preserves_flags));
                }
                assert_eq!(before_rsp, after_rsp);
                assert_eq!(value, if index == 0 { 64 } else { 0 });
                assert_eq!(data, before);
                shared.verify();
                deadline.send(
                    &tx,
                    Event::Returned {
                        value,
                        before_rsp,
                        after_rsp,
                        state: local(&attached),
                    },
                );
            }
            Command::Checkpoint => {
                assert_eq!(data, before);
                shared.verify();
                // SAFETY: the real C call above returned on this attached thread,
                // and complete input/source/image checks succeeded. No reentry.
                let batch = unsafe { attached.checkpoint_after_returns() }
                    .unwrap()
                    .expect("one pending actual return");
                assert_eq!(data, before);
                shared.verify();
                deadline.send(&tx, Event::Batch(Box::new(batch)));
            }
            Command::Snapshot => deadline.send(&tx, Event::Snapshot(local(&attached))),
            Command::Take => {
                let old = local(&attached);
                let packet = NORMAL.with(|cell| {
                    let mut storage = cell.borrow_mut();
                    let state = storage.0.as_mut().unwrap();
                    let pending = Box::new(state.pending.take().unwrap());
                    assert!(
                        pending.returned.is_some(),
                        "actual pre-RET observation already returned"
                    );
                    let packet = Receipt {
                        before: pending_copy(&pending),
                        address: std::ptr::from_ref(&pending.receipt) as usize,
                        pending: Some(pending),
                        origin: (state.registration, state.tid),
                    };
                    let mut without = old.clone();
                    without.pending = None;
                    assert_eq!(snapshot(state), without);
                    packet
                });
                taken = Some(old);
                deadline.send(&tx, Event::Receipt(packet));
            }
            Command::Refuse(mut packet) => {
                packet.check();
                let old = local(&attached);
                assert_ne!(packet.origin.0, old.registration);
                assert_ne!(packet.origin.1, old.tid);
                NORMAL.with(|cell| {
                    let mut storage = cell.borrow_mut();
                    let state = storage.0.as_mut().unwrap();
                    let p = packet.pending.as_mut().unwrap();
                    let result = state.model.finish_interval(
                        &mut p.receipt,
                        &mut p.slot,
                        p.returned.unwrap().observation(),
                    );
                    assert_eq!(result, Err(IntervalExitError::ForeignEntry));
                    assert_eq!(snapshot(state), old);
                });
                packet.check();
                assert_eq!(local(&attached), old);
                deadline.send(&tx, Event::Receipt(packet));
            }
            Command::Restore(mut packet) => {
                packet.check();
                let old = taken.take().expect("exact owning thread restoration");
                assert_eq!(packet.origin, (old.registration, old.tid));
                NORMAL.with(|cell| {
                    let mut storage = cell.borrow_mut();
                    let state = storage.0.as_mut().unwrap();
                    let mut without = old.clone();
                    without.pending = None;
                    assert_eq!(snapshot(state), without);
                    assert!(state.pending.is_none());
                    state.pending = Some(*packet.pending.take().unwrap());
                    assert_eq!(snapshot(state), old);
                });
                assert_eq!(local(&attached), old);
                deadline.send(&tx, Event::Restored(old));
            }
            Command::Stop => {
                assert!(taken.is_none());
                assert_eq!(data, before);
                shared.verify();
                let old = local(&attached);
                assert!(old.pending.is_none());
                assert!(
                    unsafe { attached.checkpoint_after_returns() }
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    local(&attached),
                    old,
                    "empty checkpoint changes no counters/page/cursor"
                );
                let totals = attached.detach().unwrap();
                assert_eq!(totals, old.totals);
                assert!(NORMAL.with(|cell| cell.borrow().0.is_none()));
                assert_eq!(data, before);
                shared.verify();
                deadline.send(&tx, Event::Finished(totals));
                deadline.check();
                return totals;
            }
        }
    }
}

struct Worker {
    command: Option<SyncSender<Command>>,
    reply: Receiver<Event>,
    handle: Option<JoinHandle<NormalTotals>>,
    deadline: Deadline,
}
impl Worker {
    fn ask(&self, command: Command) -> Event {
        self.deadline.send(self.command.as_ref().unwrap(), command);
        self.deadline.recv(&self.reply)
    }
    fn join(&mut self) -> NormalTotals {
        let Event::Finished(expected) = self.ask(Command::Stop) else {
            panic!("exact finished event");
        };
        self.command.take();
        while !self.handle.as_ref().unwrap().is_finished() {
            self.deadline.check();
            thread::yield_now();
        }
        let actual = self
            .handle
            .take()
            .unwrap()
            .join()
            .expect("actual owned worker join");
        assert_eq!(actual, expected);
        self.deadline.check();
        actual
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.command.take();
        if let Some(handle) = self.handle.take() {
            // Failure cannot detach a live native worker or turn into success.
            while !handle.is_finished() {
                if Instant::now() >= self.deadline.0 {
                    std::process::abort();
                }
                thread::yield_now();
            }
            let _ = handle.join();
        }
    }
}
fn cpus() -> [usize; 3] {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) },
        0
    );
    let selected: Vec<_> = (0..libc::CPU_SETSIZE as usize)
        .filter(|&n| unsafe { libc::CPU_ISSET(n, &set) })
        .take(3)
        .collect();
    assert_eq!(
        selected.len(),
        3,
        "three independently available CPUs are a native prerequisite"
    );
    [selected[0], selected[1], selected[2]]
}
fn decimal(name: &str) -> u64 {
    let text = std::env::var(name).expect("independent canonical selected metadata");
    assert!(!text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()));
    assert!(text == "0" || !text.starts_with('0'));
    text.parse().unwrap()
}
fn publish(prep: TwoCallerNormalSitePreparation) -> InstalledTwoCallerNormalSite {
    // Fresh exact libtest process; passive harness owns no subject capability.
    // The only test exclusively loaded this no-constructor/dependency DSO and
    // no calling worker exists until the complete retained transaction seals.
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
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    let alias = unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap();
    let result = {
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
        Err(error) => {
            eprintln!("two-caller publication FAILED: {error:?}");
            std::process::abort();
        }
    };
    unsafe { prep.seal(installed, receipt) }.unwrap()
}

struct Fixture {
    deadline: Deadline,
    controller: IntervalController,
    workers: [Worker; 2],
    shared: Shared,
    ready: [Snapshot; 2],
    history: Vec<HistoryBatch>,
    stream: HistoryStream,
    batches: Vec<NormalBatch>,
    calls: [u64; 2],
    joins: usize,
    reports: usize,
    foreign_refusals: usize,
    generations: Vec<u64>,
}
impl Fixture {
    fn new() -> Self {
        let deadline = Deadline::new(); // Before files, loader, allocation or workers.
        let cpus = cpus();
        let candidate = std::env::var_os("RAPID_NORMAL_TWO_CANDIDATE").expect("candidate ELF");
        let expected =
            std::env::var_os("RAPID_NORMAL_TWO_EXPECTED").expect("independent final ELF");
        let bytes = expected_file(Path::new(&candidate), Path::new(&expected));
        let elf_va = decimal("RAPID_NORMAL_TWO_ELF_VA");
        let length = decimal("RAPID_NORMAL_TWO_LENGTH");
        assert_eq!(
            (elf_va, length),
            (4096, 41),
            "exact independently rebuilt qualification fixture"
        );
        let selection =
            TrustedFunctionSelection::new(&bytes, elf_va, usize::try_from(length).unwrap(), LABEL)
                .unwrap();
        // SAFETY: independently rebuilt exact final strnlen module/selection,
        // no dependencies/constructors/CET/nonlocal exits; complete immutable
        // code and at most two nonrecursive callers under the Ready barrier.
        let owner = unsafe {
            LoadedTwoCallerNormalLeaf::load_selected(
                Path::new(&candidate),
                &selection,
                TwoCallerNormalLeafContract {
                    single_external_entry: true,
                    ordinary_call_ret_only: true,
                    no_active_cet: true,
                },
            )
        }
        .unwrap();
        owner.verify_original().unwrap();
        let entry = owner.entry();
        let returns: BTreeSet<_> = owner.certificate().returns().iter().copied().collect();
        assert_eq!(
            returns,
            BTreeSet::from([entry + 34, entry + 40]),
            "unchanged independently qualified complete strnlen fixture"
        );
        let prep =
            TwoCallerNormalSitePreparation::new_whole_function(owner, identity(entry)).unwrap();
        assert_eq!(
            prep.role_pcs().collect::<Vec<_>>(),
            std::iter::once(entry)
                .chain(returns.iter().copied())
                .collect::<Vec<_>>()
        );
        let mut spans: Vec<_> = prep
            .plan()
            .plan()
            .final_bytes()
            .iter()
            .map(|b| (b.address, b.bytes.clone()))
            .collect();
        spans.extend(
            prep.plan()
                .images()
                .iter()
                .map(|i| (i.address(), i.bytes().to_vec())),
        );
        let shared = Shared {
            entry,
            returns,
            spans: Arc::new(spans),
        };
        let prepared = PreparedTwoCallerNormalController::new_streaming_history(
            publish(prep),
            INSTALL,
            FUNCTION,
            Limits {
                epochs: 4,
                threads: 2,
                depth: 1,
                records_per_epoch: 4096,
                actions: 8,
            },
        )
        .unwrap();
        shared.verify();
        deadline.check();
        let (controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
        let stream = controller.history_window().unwrap().stream().clone();
        let mut owned = Vec::with_capacity(2);
        for i in 0..2 {
            let (command, rx) = mpsc::sync_channel(1);
            let (tx, reply) = mpsc::sync_channel(1);
            let shared = shared.clone();
            let client = client.clone();
            let cpu = cpus[i + 1];
            let handle = thread::Builder::new()
                .name(format!("normal-two-{i}"))
                .spawn(move || worker(i, cpu, deadline, shared, client, rx, tx))
                .unwrap();
            // Custody established immediately; a later spawn/Ready failure cannot detach this worker.
            owned.push(Worker {
                command: Some(command),
                reply,
                handle: Some(handle),
                deadline,
            });
        }
        let workers: [Worker; 2] = owned.try_into().ok().unwrap();
        let mut ranges = Vec::new();
        let ready = std::array::from_fn(|i| {
            let Event::Ready { state, stack } = deadline.recv(&workers[i].reply) else {
                panic!("both exact Ready handshakes");
            };
            check::ready(&state, i);
            ranges.push(stack);
            state
        });
        assert_ne!(ready[0].tid, ready[1].tid);
        assert_ne!(ready[0].actual_thread, ready[1].actual_thread);
        assert_ne!(ready[0].journal_address, ready[1].journal_address);
        assert!(ranges[0].1 <= ranges[1].0 || ranges[1].1 <= ranges[0].0);
        assert!(ready.iter().all(|r| r.tid != tid()));
        // Both workers inherited the original allowed set and already pinned.
        pin(Some(cpus[0]));
        deadline.check();
        Self {
            deadline,
            controller,
            workers,
            shared,
            ready,
            history: Vec::new(),
            stream,
            batches: Vec::new(),
            calls: [0, 0],
            joins: 0,
            reports: 0,
            foreign_refusals: 0,
            generations: Vec::new(),
        }
    }
    fn retained(&self) -> usize {
        self.controller.binding.session.retained_epochs()
    }
    fn stage(&mut self) -> IntervalEpoch {
        self.deadline.check();
        let epoch = self.controller.stage(CONFIG).unwrap();
        let generation = epoch.generation().get();
        assert!(generation != 0 && self.generations.last().is_none_or(|old| *old < generation));
        self.generations.push(generation);
        epoch
    }
    fn epoch_limit(&mut self) {
        let before = self.retained();
        assert!(matches!(
            self.controller.stage(CONFIG),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::EpochLimit)
            })
        ));
        assert_eq!(self.retained(), before);
    }
    fn action(&mut self, epoch: &IntervalEpoch, publish: bool) {
        self.deadline.check();
        if publish {
            self.controller.arm(epoch).unwrap();
        } else {
            self.controller.disarm(epoch).unwrap();
        }
        let chunk = self
            .controller
            .drain_history()
            .unwrap()
            .expect("one exact action");
        let n = self.history.len() as u64;
        assert_eq!(chunk.stream(), &self.stream);
        assert_eq!(chunk.number(), n + 1);
        assert_eq!(chunk.range(), n..n + 1);
        if let Some(old) = self.history.last() {
            assert!(chunk.follows(old));
        } else {
            assert_eq!(chunk.before(), HistoryBinding::Initial);
        }
        assert_eq!(
            chunk.actions(),
            &[Action {
                kind: if publish {
                    ActionKind::Published
                } else {
                    ActionKind::Removed
                },
                generation: epoch.generation(),
                function: None,
                current: publish.then_some(epoch.generation()),
                group: None
            }]
        );
        assert_eq!(
            chunk.after(),
            if publish {
                HistoryBinding::Published {
                    action_index: n,
                    generation: epoch.generation(),
                }
            } else {
                HistoryBinding::Removed {
                    action_index: n,
                    generation: epoch.generation(),
                }
            }
        );
        self.history.push(chunk);
        assert!(self.controller.drain_history().unwrap().is_none());
    }
    fn call(&mut self, worker: usize, epoch: &IntervalEpoch, sampled: Option<usize>) -> Snapshot {
        let Event::Returned {
            value,
            before_rsp,
            after_rsp,
            state,
        } = self.workers[worker].ask(Command::Call)
        else {
            panic!("one genuine returned CALL");
        };
        self.calls[worker] += 1;
        check::returned(
            &state,
            &self.ready[worker],
            &self.shared,
            self.calls[worker],
            epoch.generation().get(),
            sampled,
            self.history.len() as u64,
        );
        assert_eq!(before_rsp, after_rsp);
        assert_eq!(
            state.pending.as_ref().unwrap().rsp.checked_add(8),
            Some(before_rsp),
            "actual C CALL pushed its return word"
        );
        assert_eq!(value, if worker == 0 { 64 } else { 0 });
        state
    }
    fn checkpoint(&mut self, worker: usize, pending: &Snapshot) -> usize {
        let Event::Batch(batch) = self.workers[worker].ask(Command::Checkpoint) else {
            panic!("one complete native batch");
        };
        check::batch(&batch, pending, &self.stream, &self.history, &self.shared);
        self.batches.push(*batch);
        self.batches.len() - 1
    }
    fn foreign(&mut self, from: usize, to: usize) {
        assert_ne!(from, to);
        let epoch_records: Vec<_> = self
            .controller
            .epochs
            .iter()
            .flatten()
            .map(|e| {
                (
                    e.generation(),
                    e.reservations(),
                    e.records().collect::<Vec<_>>(),
                )
            })
            .collect();
        let window = self.controller.history_window().unwrap();
        let retained = self.retained();
        let Event::Snapshot(before) = self.workers[from].ask(Command::Snapshot) else {
            panic!("owning snapshot");
        };
        let Event::Receipt(packet) = self.workers[from].ask(Command::Take) else {
            panic!("genuine receipt custody");
        };
        let Event::Receipt(packet) = self.workers[to].ask(Command::Refuse(packet)) else {
            panic!("foreign refusal returns exact custody");
        };
        let Event::Restored(after) = self.workers[from].ask(Command::Restore(packet)) else {
            panic!("same-thread receipt restoration");
        };
        assert_eq!(after, before);
        assert_eq!(self.controller.history_window().unwrap(), window);
        assert_eq!(self.retained(), retained);
        assert_eq!(
            self.controller
                .epochs
                .iter()
                .flatten()
                .map(|e| (
                    e.generation(),
                    e.reservations(),
                    e.records().collect::<Vec<_>>()
                ))
                .collect::<Vec<_>>(),
            epoch_records
        );
        self.foreign_refusals += 1;
    }
    fn report(&mut self, epoch: &IntervalEpoch, indices: &[(usize, Disposition)]) {
        let report = self.controller.retire(epoch).unwrap();
        check::report(&report, indices, &self.batches);
        self.reports += 1;
        drop(report); // Deliberate: batches and copied history retain no epoch permit.
    }
    fn empty_epoch(&mut self, epoch: &IntervalEpoch) {
        self.action(epoch, true);
        self.action(epoch, false);
        let report = self.controller.retire(epoch).unwrap();
        assert_eq!(report.generation(), epoch.generation());
        assert_eq!(report.records().count(), 0);
        self.reports += 1;
        drop(report);
    }
    fn join(&mut self, worker: usize) -> NormalTotals {
        let totals = self.workers[worker].join();
        self.joins += 1;
        totals
    }
    fn finish(
        self,
        expected_calls: [u64; 2],
        actions: usize,
        reports: usize,
        foreign: usize,
        scenario: &str,
    ) {
        assert_eq!(self.calls, expected_calls);
        assert_eq!(self.joins, 2);
        assert_eq!(self.reports, reports);
        assert_eq!(self.generations.len(), reports);
        assert_eq!(self.foreign_refusals, foreign);
        assert!(
            self.workers
                .iter()
                .all(|w| w.handle.is_none() && w.command.is_none())
        );
        assert_eq!(self.retained(), 0);
        assert_eq!(self.history.len(), actions);
        let window = self.controller.history_window().unwrap();
        assert_eq!(window.status(), ControllerStatus::Ready);
        assert_eq!(window.current(), None);
        assert_eq!(window.enabled(), [true]);
        assert_eq!(window.retained_failed_generation(), None);
        assert_eq!(window.range(), actions as u64..actions as u64);
        assert!(window.actions().is_empty());
        assert_eq!(window.last_batch_number(), actions as u64);
        assert_eq!(window.before(), self.history.last().unwrap().after());
        assert_eq!(window.after(), window.before());
        assert_eq!(self.batches.len() as u64, self.calls.iter().sum::<u64>());
        self.shared.verify();
        assert_eq!(Arc::strong_count(&self.shared.spans), 1);
        self.deadline.check();
        println!(
            "normal-two-native PASS scenario={scenario} attachments=2 ready_before_calls=true calls={} batches={} rows={} journal_words={} reports={reports} foreign_refusals={foreign} actions={actions} worker_joins=2 retained_epochs=0",
            self.calls.iter().sum::<u64>(),
            self.batches.len(),
            self.batches.len(),
            self.batches.len() * 512
        );
        self.deadline.check();
    }
}

fn k1(first: usize) {
    let mut f = Fixture::new();
    let a = f.stage();
    f.action(&a, true);
    let p = [f.call(0, &a, Some(0)), f.call(1, &a, Some(1))];
    assert_eq!(f.controller.owner(&a).unwrap().reservations(), 2);
    let admitted: Vec<_> = f.controller.owner(&a).unwrap().records().collect();
    assert_eq!(admitted.len(), 2);
    assert!(
        admitted
            .iter()
            .all(|r| r.record.terminal.is_none() && r.payload.is_none())
    );
    assert!(f.controller.report(&a).unwrap().is_none());
    f.foreign(0, 1);
    let first_batch = f.checkpoint(first, &p[first]);
    assert_eq!(f.controller.owner(&a).unwrap().reservations(), 1);
    assert!(f.controller.report(&a).unwrap().is_none());
    let Event::Snapshot(other) = f.workers[1 - first].ask(Command::Snapshot) else {
        panic!("other remains pending");
    };
    assert_eq!(other, p[1 - first]);
    let second_batch = f.checkpoint(1 - first, &p[1 - first]);
    assert_eq!(f.controller.owner(&a).unwrap().reservations(), 0);
    assert!(
        f.controller.report(&a).unwrap().is_none(),
        "function closed is not epoch retirement"
    );
    f.action(&a, false);
    f.report(
        &a,
        &[
            (first_batch, Disposition::Retained { rank: 0 }),
            (second_batch, Disposition::DroppedAfterBudget),
        ],
    );
    for w in 0..2 {
        assert_eq!(
            f.join(w),
            NormalTotals {
                entered: 1,
                ret_observed: 1,
                confirmed: 1,
                completed: 1,
                unsampled: 0
            }
        );
    }
    f.finish(
        [1, 1],
        2,
        1,
        1,
        if first == 0 {
            "k1-first-0"
        } else {
            "k1-first-1"
        },
    );
}

#[test]
#[ignore = "requires exact fresh release process and independently rebuilt selected strnlen fixture"]
fn two_caller_native_k1_first_worker_zero() {
    k1(0);
}
#[test]
#[ignore = "requires exact fresh release process and independently rebuilt selected strnlen fixture"]
fn two_caller_native_k1_first_worker_one() {
    k1(1);
}
#[test]
#[ignore = "requires exact fresh release process and independently rebuilt selected strnlen fixture"]
fn two_caller_native_closed_owners_fill_e4_until_local_confirmation() {
    let mut f = Fixture::new();
    let a = f.stage();
    f.action(&a, true);
    let a_sample = f.call(0, &a, Some(0));
    let a_row = f.checkpoint(0, &a_sample);
    let a_closed = f.call(0, &a, None);
    f.action(&a, false);
    f.report(&a, &[(a_row, Disposition::Retained { rank: 0 })]);
    assert_eq!(
        f.retained(),
        1,
        "only genuine A FunctionClosed receipt retains A"
    );
    let b = f.stage();
    f.action(&b, true);
    let b_sample = f.call(1, &b, Some(0));
    let b_row = f.checkpoint(1, &b_sample);
    let b_closed = f.call(1, &b, None);
    f.action(&b, false);
    f.report(&b, &[(b_row, Disposition::Retained { rank: 0 })]);
    assert_eq!(
        f.retained(),
        2,
        "two different old receipts, both Reports dropped"
    );
    f.foreign(0, 1);
    let c = f.stage();
    f.action(&c, true);
    let d = f.stage();
    assert_eq!(f.retained(), 4, "A/B pending plus C current plus D fresh");
    f.epoch_limit();
    f.checkpoint(1, &b_closed);
    assert_eq!(f.retained(), 3);
    assert_eq!(
        f.join(1),
        NormalTotals {
            entered: 2,
            ret_observed: 2,
            confirmed: 2,
            completed: 1,
            unsampled: 1
        }
    );
    let Event::Snapshot(a_still) = f.workers[0].ask(Command::Snapshot) else {
        panic!("A pending after other actual join");
    };
    assert_eq!(a_still, a_closed);
    assert_eq!(f.retained(), 3);
    let e = f.stage();
    assert_eq!(f.retained(), 4);
    f.epoch_limit();
    f.checkpoint(0, &a_closed);
    assert_eq!(f.retained(), 3);
    let fresh = f.stage();
    assert_eq!(f.retained(), 4, "only A confirmation freed this permit");
    assert_eq!(
        f.join(0),
        NormalTotals {
            entered: 2,
            ret_observed: 2,
            confirmed: 2,
            completed: 1,
            unsampled: 1
        }
    );
    f.action(&c, false);
    let c_report = f.controller.retire(&c).unwrap();
    assert_eq!(c_report.generation(), c.generation());
    assert_eq!(c_report.records().count(), 0);
    f.reports += 1;
    drop(c_report);
    for epoch in [&d, &e, &fresh] {
        f.empty_epoch(epoch);
    }
    f.finish([2, 2], 12, 6, 1, "closed-e4");
}
