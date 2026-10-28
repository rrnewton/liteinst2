//! One-worker independent backoff admission with bounded, owned exports.
//!
//! K closes sampling, not the mandatory native hooks. This is not asynchronous
//! preemption, a thread-join service, durable storage, or an indefinite daemon.
//! Source/gate lifetime and the ordinary readonly-leaf unsafe contract remain.
//!
//! `prepare_optional` is a distinct opt-in profile: the same scheduler drives
//! optional selector scans and exports physical calls plus sparse Slow rows.
//! It does not change the mandatory constructors, packets or their counters.
use super::{
    BridgeError, CallResult, HistoryBatch, HistoryBinding, HistoryStream, InstalledIntervalSite,
    IntervalBatch, IntervalClient, IntervalController, IntervalEpoch, IntervalJournal,
    IntervalThread, PairTotals, PreparedIntervalController, RawIntervalOwner, ReadableStack,
};
use crate::frontend::{Limits, RecordObservation};
use crate::generation::{Config, FunctionId};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

mod driver;
mod optional;
mod sink;
mod worker;
pub use driver::{DeadlineFailure, DeadlinePhase, Driver, RunSummary, StopReason};
pub use optional::{
    OptionalCallOutcome, OptionalClient, OptionalCompletedBatch, OptionalCompletedCall,
    OptionalDriver, OptionalExport, OptionalPrepared, OptionalRunSummary, OptionalThread,
    OptionalWorkerFinish, OptionalWorkerStatus, optional_matches_history, prepare_optional,
};
pub use worker::{CallOutcome, Client, Thread, WorkerFinish};

const ROWS: usize = 4;
const SLOTS: usize = 3;
const HISTORY: usize = 8;
const WORK_QUEUE: usize = 2;
const EXPORT_QUEUE: usize = 4;
const POLL: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Policy,
    Allocation,
    AlreadyStarted,
    NotStarted,
    Stopped,
    CallLimit,
    Deadline,
    Full,
    Disconnected,
    ControllerFailed,
    Sequence,
    Owner,
    Worker,
    EpochCapacity,
    Bridge(BridgeError),
}
impl From<BridgeError> for Error {
    fn from(value: BridgeError) -> Self {
        Self::Bridge(value)
    }
}

/// Explicit finite policy. No adaptive deadline extension or catch-up arms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    k: usize,
    epochs: u32,
    calls: u64,
    worker_backpressure: bool,
    sink_backpressure: bool,
}
impl Policy {
    /// K10 or K1000, 10ms periods, at most 4096 epochs and 1,000,000 calls.
    /// Each scheduled arm has a fixed 2ms lateness budget. Shutdown gets 2s
    /// after the first observed stop, never a renewed per-operation deadline.
    pub fn ten_ms(k: usize, epochs: u32, calls: u64) -> Result<Self, Error> {
        if !matches!(k, 10 | 1000)
            || !(1..=4096).contains(&epochs)
            || !(1..=1_000_000).contains(&calls)
        {
            return Err(Error::Policy);
        }
        Ok(Self {
            k,
            epochs,
            calls,
            worker_backpressure: false,
            sink_backpressure: false,
        })
    }
    /// Opt in to waiting only for a full worker-to-controller queue, after a
    /// completed native drain. The original absolute end+shutdown is the cap;
    /// controller failure/disconnection refuses and retains the unsent packet.
    /// This alone leaves sink Full fatal. Sink backpressure is a separate opt-in.
    pub fn with_worker_backpressure(mut self) -> Self {
        self.worker_backpressure = true;
        self
    }
    pub fn worker_backpressure(&self) -> bool {
        self.worker_backpressure
    }
    /// Retry full controller-to-sink exports for one fixed 1ms window, with
    /// 250us sleeps, always capped by the original Clock deadlines. A later
    /// item gets a new local window but cannot renew an arm/shutdown deadline.
    /// Default Full, worker transport, queue caps and sink ownership are unchanged.
    pub fn with_sink_backpressure(mut self) -> Self {
        self.sink_backpressure = true;
        self
    }
    pub fn sink_backpressure(&self) -> bool {
        self.sink_backpressure
    }
    pub fn retained(&self) -> usize {
        self.k
    }
    pub fn epoch_limit(&self) -> u32 {
        self.epochs
    }
    pub fn call_limit(&self) -> u64 {
        self.calls
    }
    pub fn period(&self) -> Duration {
        Duration::from_millis(10)
    }
    pub fn lateness(&self) -> Duration {
        Duration::from_millis(2)
    }
    pub fn shutdown(&self) -> Duration {
        Duration::from_secs(2)
    }
    fn config(self) -> Config {
        Config {
            retained_per_function: self.k,
            max_inflight: 1,
            max_invocations: self.k,
        }
    }
}

#[derive(Clone)]
pub struct StopHandle(Arc<Shared>);
impl StopHandle {
    /// Idempotent cooperative request. Driver acknowledgement is its next control
    /// boundary; an arm already started may commit. Never cancels an entered call.
    pub fn request(&self) {
        self.0.stop.store(true, Ordering::Release);
    }
    pub fn requested(&self) -> bool {
        self.0.stop.load(Ordering::Acquire)
    }
}
struct Shared {
    stop: AtomicBool,
    controller_failed: AtomicBool,
    attached: AtomicBool,
    start: OnceLock<Instant>,
    finished: OnceLock<WorkerStatus>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerStatus {
    pub totals: Option<PairTotals>,
    pub detached: bool,
    pub error: Option<Error>,
    pub unexported: bool,
}

/// Actual facade return, retained even when the following export refuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletedCall {
    pub ordinal: u64,
    pub length: usize,
    pub result: CallResult,
    pub before: Duration,
    pub after: Duration,
}
#[derive(Debug)]
pub struct CompletedBatch {
    pub native: IntervalBatch,
    pub calls: [Option<CompletedCall>; ROWS],
}
/// Copied records only; retaining this value cannot retain an epoch permit.
#[derive(Debug)]
pub struct FinalReport {
    pub generation: u64,
    pub records: Vec<RecordObservation>,
}
#[derive(Debug)]
pub enum Export {
    History(HistoryBatch),
    Calls(Box<CompletedBatch>),
    Report(FinalReport),
}

/// Caller-owned endpoints; no threads are spawned or joined by preparation.
pub struct Prepared {
    pub driver: Driver,
    pub client: Client,
    pub stop: StopHandle,
    pub export: mpsc::Receiver<Export>,
}

/// Prepare and activate one installed readonly ordinary leaf. Spawn/affinity,
/// readable stack discovery, worker/sink joins and durable export belong to the
/// caller. No source execution is performed by this constructor.
///
/// # Safety
/// All activate_concurrent/publication contracts apply. Only the returned client
/// may invoke this ordinary site, on one attached worker, with valid immutable
/// input and normal termination. The caller must join the actual worker before
/// input reclamation and keep source/gate/code process-lived. Allocator/sink hooks
/// must not reenter the subject while controller metadata locks are held.
pub unsafe fn prepare(
    site: InstalledIntervalSite,
    install: u64,
    function: FunctionId,
    policy: Policy,
) -> Result<Prepared, Error> {
    let prepared = PreparedIntervalController::new_streaming_history(
        site,
        install,
        function,
        Limits {
            epochs: SLOTS,
            threads: 1,
            depth: 1,
            records_per_epoch: policy.k,
            actions: HISTORY,
        },
    )?;
    // SAFETY: delegated exact caller contract above; no relaxed activation path.
    let (controller, client) = unsafe { prepared.activate_concurrent() }?;
    let stream = controller.history_window()?.stream().clone();
    let shared = Arc::new(Shared {
        stop: AtomicBool::new(false),
        controller_failed: AtomicBool::new(false),
        attached: AtomicBool::new(false),
        start: OnceLock::new(),
        finished: OnceLock::new(),
    });
    let stop = StopHandle(Arc::clone(&shared));
    let (work_tx, work_rx) = mpsc::sync_channel(WORK_QUEUE);
    let (export_tx, export_rx) = mpsc::sync_channel(EXPORT_QUEUE);
    Ok(Prepared {
        driver: Driver::new(
            controller,
            stream,
            policy,
            Arc::clone(&shared),
            work_rx,
            export_tx,
        ),
        client: Client {
            client,
            policy,
            shared,
            tx: work_tx,
        },
        stop,
        export: export_rx,
    })
}

fn send<T>(tx: &mpsc::SyncSender<T>, value: T) -> Result<(), (Error, T)> {
    tx.try_send(value).map_err(|e| match e {
        mpsc::TrySendError::Full(v) => (Error::Full, v),
        mpsc::TrySendError::Disconnected(v) => (Error::Disconnected, v),
    })
}

/// Join one raw row to an authentic retained action chunk. A high-water alone
/// is insufficient. Consumers must retain/replay all chunks, including chunks
/// below today's resident base, and verify complete once-only chunk coverage.
pub fn matches_history(batch: &CompletedBatch, row: usize, history: &HistoryBatch) -> bool {
    if batch.native.history_stream() != Some(history.stream()) {
        return false;
    }
    let Some(raw) = batch.native.rows().get(row) else {
        return false;
    };
    let Some(prefix) = batch.native.history_prefix(row * 2) else {
        return false;
    };
    if batch.native.history_prefix(row * 2 + 1) != Some(prefix) {
        return false;
    }
    let Some(binding) = history.binding_at(prefix) else {
        return false;
    };
    binding_matches(raw.owner, binding, prefix)
}
fn binding_matches(owner: RawIntervalOwner, binding: HistoryBinding, prefix: u64) -> bool {
    match (owner, binding) {
        (RawIntervalOwner::InitialDisarmed, HistoryBinding::Initial) => true,
        (
            RawIntervalOwner::Removed { generation },
            HistoryBinding::Removed {
                action_index,
                generation: g,
            },
        ) => generation == g.get() && action_index < prefix,
        (
            RawIntervalOwner::Sampled { generation, .. }
            | RawIntervalOwner::FunctionClosed { generation },
            HistoryBinding::Published {
                action_index,
                generation: g,
            },
        ) => generation == g.get() && action_index < prefix,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Cursor {
    number: u64,
    totals: PairTotals,
    gate: Option<u64>,
}
impl Cursor {
    fn accept(&mut self, packet: &CompletedBatch, stream: &HistoryStream) -> Result<(), Error> {
        let b = &packet.native;
        let (before, after) = b.totals();
        let count = b.rows().len();
        let next = advance(*self, b.number(), before, after, count, b.gate_sequence())?;
        if b.history_stream() != Some(stream)
            || b.journal().len() != 512
            || b.raw_range() != (before.entries..after.entries)
            || b.event_range() != (before.entries * 2..after.entries * 2)
            || b.completed_sequences() != (before.completed, after.completed)
            || after.entries.checked_add(1) != Some(b.next_ordinal())
            || packet.calls[count..].iter().any(Option::is_some)
        {
            return Err(Error::Sequence);
        }
        for (i, row) in b.rows().iter().enumerate() {
            let c = packet.calls[i].ok_or(Error::Sequence)?;
            if c.ordinal != before.entries + i as u64 + 1
                || row.ordinal != c.ordinal
                || c.before > c.after
                || c.result.return_pc != row.return_pc
                || c.result.pre_call_rsp != c.result.resumed_rsp
                || c.result.entry_rsp.checked_add(8) != Some(c.result.pre_call_rsp)
                || b.history_prefix(i * 2).is_none()
                || b.history_prefix(i * 2) != b.history_prefix(i * 2 + 1)
            {
                return Err(Error::Sequence);
            }
        }
        *self = next;
        Ok(())
    }
}
fn balanced(t: PairTotals) -> bool {
    t.entries == t.returns && t.completed.checked_add(t.unsampled) == Some(t.entries)
}
fn advance(
    old: Cursor,
    number: u64,
    before: PairTotals,
    after: PairTotals,
    count: usize,
    gate: u64,
) -> Result<Cursor, Error> {
    if !(1..=ROWS).contains(&count)
        || old.number.checked_add(1) != Some(number)
        || before != old.totals
        || !balanced(before)
        || !balanced(after)
        || before.entries.checked_add(count as u64) != Some(after.entries)
        || after.completed < before.completed
        || after.unsampled < before.unsampled
        || old
            .gate
            .is_some_and(|g| g.checked_add(count as u64) != Some(gate))
    {
        return Err(Error::Sequence);
    }
    Ok(Cursor {
        number,
        totals: after,
        gate: Some(gate),
    })
}
#[cfg(test)]
mod tests;
