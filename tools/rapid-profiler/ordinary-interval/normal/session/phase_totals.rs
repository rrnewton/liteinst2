//! Fixed diagnostic accounting; never an input to runtime acceptance.
//! Top-level samples are supplied by the caller. Opt-in custody marks take
//! Instant samples only; no allocation, I/O, locking or lifecycle observation.
use std::fmt;
use std::time::{Duration, Instant};

/// Counts completed spans, not calls, records or completed operations.
/// Empty extrema are absent; an observed zero-duration span has real zero extrema.
/// Invalid observations retain the last valid statistics and latch invalidity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::normal) struct Bucket {
    valid: bool,
    count: u64,
    sum_ns: u128,
    min_ns: Option<u128>,
    max_ns: Option<u128>,
}
impl Default for Bucket {
    fn default() -> Self {
        Self {
            valid: true,
            count: 0,
            sum_ns: 0,
            min_ns: None,
            max_ns: None,
        }
    }
}
impl Bucket {
    pub(in crate::normal) fn observe(&mut self, duration: Option<Duration>) -> bool {
        if !self.valid {
            return false;
        }
        let next = duration.and_then(|duration| {
            let ns = duration.as_nanos();
            Some((self.count.checked_add(1)?, self.sum_ns.checked_add(ns)?, ns))
        });
        let Some((count, sum_ns, ns)) = next else {
            self.valid = false;
            return false;
        };
        self.count = count;
        self.sum_ns = sum_ns;
        self.min_ns = Some(self.min_ns.map_or(ns, |old| old.min(ns)));
        self.max_ns = Some(self.max_ns.map_or(ns, |old| old.max(ns)));
        true
    }
    pub(in crate::normal) fn is_valid(&self) -> bool {
        self.valid
    }
    pub(in crate::normal) fn count(&self) -> u64 {
        self.count
    }
    pub(in crate::normal) fn sum_ns(&self) -> u128 {
        self.sum_ns
    }
    pub(in crate::normal) fn min_ns(&self) -> Option<u128> {
        self.min_ns
    }
    pub(in crate::normal) fn max_ns(&self) -> Option<u128> {
        self.max_ns
    }
}
struct Nanoseconds(Option<u128>);
impl fmt::Display for Nanoseconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(ns) => write!(f, "{ns}"),
            None => f.write_str("none"),
        }
    }
}
impl fmt::Display for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "valid={} spans={} sum_ns={} min_ns={} max_ns={}",
            self.is_valid(),
            self.count(),
            self.sum_ns(),
            Nanoseconds(self.min_ns()),
            Nanoseconds(self.max_ns())
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(in crate::normal) enum WorkerPhase {
    Receive,
    Dispatch,
    Input,
    Setup,
    BeforeCustody,
    Invoke,
    AfterCustody,
    CheckpointCustody,
    Checkpoint,
    Reply,
    Cleanup,
}
const PHASES: [WorkerPhase; 11] = [
    WorkerPhase::Receive,
    WorkerPhase::Dispatch,
    WorkerPhase::Input,
    WorkerPhase::Setup,
    WorkerPhase::BeforeCustody,
    WorkerPhase::Invoke,
    WorkerPhase::AfterCustody,
    WorkerPhase::CheckpointCustody,
    WorkerPhase::Checkpoint,
    WorkerPhase::Reply,
    WorkerPhase::Cleanup,
];
impl WorkerPhase {
    fn name(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::Dispatch => "dispatch",
            Self::Input => "input",
            Self::Setup => "setup",
            Self::BeforeCustody => "before_custody",
            Self::Invoke => "invoke",
            Self::AfterCustody => "after_custody",
            Self::CheckpointCustody => "checkpoint_custody",
            Self::Checkpoint => "checkpoint",
            Self::Reply => "reply",
            Self::Cleanup => "cleanup",
        }
    }
}

/// One sequential partition. The caller starts this after READY-send returns,
/// and consumes it after detach/final custody, before the terminal Finished send.
/// There is deliberately no partial snapshot or clone of the active trace.
pub(in crate::normal) struct WorkerTrace {
    valid: bool,
    start: Option<Instant>,
    active: Option<(WorkerPhase, Instant)>,
    buckets: [Bucket; PHASES.len()],
}
impl Default for WorkerTrace {
    fn default() -> Self {
        Self::new()
    }
}
impl WorkerTrace {
    pub(in crate::normal) fn new() -> Self {
        Self {
            valid: true,
            start: None,
            active: None,
            buckets: [Bucket::default(); PHASES.len()],
        }
    }
    /// Opens Receive. A repeated start never resets already retained evidence.
    pub(in crate::normal) fn start(&mut self, at: Instant) {
        if !self.valid || self.start.is_some() {
            self.valid = false;
            return;
        }
        self.start = Some(at);
        self.active = Some((WorkerPhase::Receive, at));
    }
    fn close(&mut self, at: Instant) -> bool {
        if !self.valid {
            return false;
        }
        let Some((phase, from)) = self.active else {
            self.valid = false;
            return false;
        };
        if !self.buckets[phase as usize].observe(at.checked_duration_since(from)) {
            self.valid = false;
            return false;
        }
        true
    }
    /// Closes one span and opens the next, including for repeated same-phase marks.
    pub(in crate::normal) fn mark(&mut self, phase: WorkerPhase, at: Instant) {
        if self.close(at) {
            self.active = Some((phase, at));
        }
    }
    /// Consumes the only active trace; this API cannot finish that trace twice.
    /// This is accounting closure, not proof of detach, join or task retirement.
    pub(in crate::normal) fn finish(mut self, at: Instant) -> WorkerSnapshot {
        self.close(at);
        let elapsed = self
            .start
            .and_then(|start| at.checked_duration_since(start));
        let sum = self.buckets.iter().try_fold(0_u128, |sum, bucket| {
            if bucket.is_valid() {
                sum.checked_add(bucket.sum_ns())
            } else {
                None
            }
        });
        self.valid &= elapsed.is_some() && sum == elapsed.map(|value| value.as_nanos());
        WorkerSnapshot {
            valid: self.valid,
            start: self.start,
            finish: at,
            buckets: self.buckets,
        }
    }
}

/// Completed accounting only. Caller-owned PID/TID/totals and the actual
/// Finished/join/task-retirement checks remain separate export prerequisites.
#[derive(Debug)]
pub(in crate::normal) struct WorkerSnapshot {
    valid: bool,
    start: Option<Instant>,
    finish: Instant,
    buckets: [Bucket; PHASES.len()],
}
impl WorkerSnapshot {
    pub(in crate::normal) fn is_valid(&self) -> bool {
        self.valid
    }
    pub(in crate::normal) fn started_at(&self) -> Option<Instant> {
        self.start
    }
    pub(in crate::normal) fn finished_at(&self) -> Instant {
        self.finish
    }
    pub(in crate::normal) fn bucket(&self, phase: WorkerPhase) -> &Bucket {
        &self.buckets[phase as usize]
    }
    /// Available only for a valid, conserved complete partition.
    pub(in crate::normal) fn window_ns(&self) -> Option<u128> {
        if !self.is_valid() {
            return None;
        }
        self.observed_end_ns()
    }
    fn observed_end_ns(&self) -> Option<u128> {
        self.started_at()
            .and_then(|start| self.finished_at().checked_duration_since(start))
            .map(|duration| duration.as_nanos())
    }
}
impl fmt::Display for WorkerSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (status, scope) = if self.is_valid() {
            ("VALID", "complete_partition")
        } else {
            ("INVALID", "retained_valid_prefix")
        };
        writeln!(
            f,
            "worker_phases_v1 diagnostic_only status={status} bucket_scope={scope} \
             window_start_ns={} observed_end_ns={} partition_ns={}",
            Nanoseconds(self.started_at().map(|_| 0)),
            Nanoseconds(self.observed_end_ns()),
            Nanoseconds(self.window_ns())
        )?;
        for phase in PHASES {
            writeln!(f, "worker_phase {} {}", phase.name(), self.bucket(phase))?;
        }
        Ok(())
    }
}

// Nested diagnostics only: these windows are subsets of the existing three
// custody phases. Never add them to worker/controller elapsed totals.
const CUSTODY_PARENTS: [WorkerPhase; 3] = [
    WorkerPhase::BeforeCustody,
    WorkerPhase::AfterCustody,
    WorkerPhase::CheckpointCustody,
];
#[derive(Clone, Copy)]
#[repr(usize)]
pub(in crate::normal) enum CustodyStage {
    Identity,
    MapsRead,
    MapsParse,
    Mapping,
    Tasks,
    Stamp,
    FileRead,
    FileCompare,
    LiveBytes,
    Remainder,
}
const CUSTODY_STAGES: [CustodyStage; 10] = [
    CustodyStage::Identity,
    CustodyStage::MapsRead,
    CustodyStage::MapsParse,
    CustodyStage::Mapping,
    CustodyStage::Tasks,
    CustodyStage::Stamp,
    CustodyStage::FileRead,
    CustodyStage::FileCompare,
    CustodyStage::LiveBytes,
    CustodyStage::Remainder,
];
impl CustodyStage {
    fn name(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::MapsRead => "maps_read",
            Self::MapsParse => "maps_parse",
            Self::Mapping => "mapping",
            Self::Tasks => "tasks",
            Self::Stamp => "stamp",
            Self::FileRead => "file_read",
            Self::FileCompare => "file_compare",
            Self::LiveBytes => "live_bytes",
            Self::Remainder => "remainder",
        }
    }
}
pub(in crate::normal) struct CustodyTotals {
    valid: bool,
    started: u64,
    completed: u64,
    parents: [Bucket; 3],
    stages: [Bucket; 10],
    // An ended pass is not yet a proved subset of a completed parent phase.
    pending: Option<(WorkerPhase, Instant)>,
}
impl Default for CustodyTotals {
    fn default() -> Self {
        Self {
            valid: true,
            started: 0,
            completed: 0,
            parents: [Bucket::default(); 3],
            stages: [Bucket::default(); 10],
            pending: None,
        }
    }
}
impl WorkerTrace {
    pub(in crate::normal) fn custody_parent(&self) -> Option<(WorkerPhase, Instant)> {
        self.active
            .filter(|(phase, _)| CUSTODY_PARENTS.contains(phase))
    }
}
impl CustodyTotals {
    pub(in crate::normal) fn begin(
        &mut self,
        parent: (WorkerPhase, Instant),
        at: Instant,
    ) -> CustodyPass<'_> {
        let index = CUSTODY_PARENTS.iter().position(|phase| *phase == parent.0);
        self.valid &= index.is_some()
            && self.pending.is_none()
            && at.checked_duration_since(parent.1).is_some();
        if let Some(next) = self.started.checked_add(1) {
            self.started = next;
        } else {
            self.valid = false;
        }
        CustodyPass {
            totals: self,
            parent: parent.0,
            index,
            start: at,
            last: at,
            stage: CustodyStage::Identity,
            finished: false,
        }
    }
    // Reuses the actual next top-level mark, without taking a new sample.
    pub(in crate::normal) fn boundary(
        &mut self,
        parent: Option<(WorkerPhase, Instant)>,
        at: Instant,
    ) {
        if let Some((phase, end)) = self.pending.take() {
            self.valid &= parent.is_some_and(|(old, _)| old == phase)
                && at.checked_duration_since(end).is_some();
        }
    }
    pub(in crate::normal) fn finish(mut self, worker: &WorkerSnapshot) -> CustodySnapshot {
        self.valid &= worker.is_valid() && self.pending.is_none() && self.started == self.completed;
        let sum = |buckets: &[Bucket]| {
            buckets.iter().try_fold(0_u128, |total, bucket| {
                bucket.is_valid().then_some(())?;
                total.checked_add(bucket.sum_ns())
            })
        };
        let parent_sum = sum(&self.parents);
        self.valid &= parent_sum.is_some() && parent_sum == sum(&self.stages);
        for (index, phase) in CUSTODY_PARENTS.into_iter().enumerate() {
            let outer = worker.bucket(phase);
            let inner = &self.parents[index];
            self.valid &= inner.count() == outer.count() && inner.sum_ns() <= outer.sum_ns();
        }
        let parent_count = self
            .parents
            .iter()
            .try_fold(0_u64, |count, b| count.checked_add(b.count()));
        self.valid &= parent_count == Some(self.completed);
        CustodySnapshot {
            totals: self,
            partition: parent_sum,
        }
    }
}
pub(in crate::normal) struct CustodyPass<'a> {
    totals: &'a mut CustodyTotals,
    parent: WorkerPhase,
    index: Option<usize>,
    start: Instant,
    last: Instant,
    stage: CustodyStage,
    finished: bool,
}
impl CustodyPass<'_> {
    pub(in crate::normal) fn mark(&mut self, next: CustodyStage, at: Instant) {
        if self.totals.valid {
            self.totals.valid &= self.totals.stages[self.stage as usize]
                .observe(at.checked_duration_since(self.last));
            self.last = at;
            self.stage = next;
        }
    }
    pub(in crate::normal) fn finish(mut self, at: Instant) {
        self.mark(CustodyStage::Remainder, at);
        if self.totals.valid {
            if let Some(index) = self.index {
                self.totals.valid &=
                    self.totals.parents[index].observe(at.checked_duration_since(self.start));
            }
            if let Some(next) = self.totals.completed.checked_add(1) {
                self.totals.completed = next;
            } else {
                self.totals.valid = false;
            }
            self.totals.pending = Some((self.parent, at));
        }
        self.finished = true;
    }
}
impl Drop for CustodyPass<'_> {
    fn drop(&mut self) {
        // A read/check panic or unconsumed pass is never a completed partition.
        // This does not intercept the original refusal or disarm FailStop.
        if !self.finished {
            self.totals.valid = false;
        }
    }
}
// The disabled path takes no clocks. The caller keeps the original statements
// and their errors; these samples can affect timing, never runtime acceptance.
pub(in crate::normal) fn custody_mark(
    trace: &mut Option<&mut CustodyPass<'_>>,
    stage: CustodyStage,
) {
    if let Some(trace) = trace.as_mut() {
        trace.mark(stage, Instant::now());
    }
}
pub(in crate::normal) struct CustodySnapshot {
    totals: CustodyTotals,
    partition: Option<u128>,
}
impl fmt::Display for CustodySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = &self.totals;
        let status = if !t.valid {
            "INVALID"
        } else if t.completed == 0 {
            "UNAVAILABLE"
        } else {
            "VALID"
        };
        let partition = (t.valid && t.completed != 0)
            .then_some(self.partition)
            .flatten();
        writeln!(
            f,
            "custody_substages_v1 status={status} started={} completed={} partition_ns={} scope=nested_three_custody_phases_not_additive spans_not_operations=true",
            t.started,
            t.completed,
            Nanoseconds(partition)
        )?;
        for (index, phase) in CUSTODY_PARENTS.into_iter().enumerate() {
            writeln!(f, "custody_parent {} {}", phase.name(), t.parents[index])?;
        }
        for stage in CUSTODY_STAGES {
            writeln!(
                f,
                "custody_stage {} {}",
                stage.name(),
                t.stages[stage as usize]
            )?;
        }
        Ok(())
    }
}
// Existing worker block <=12*256 plus <=512-byte identity/scope. Nested block
// <=14*256, existing controller <=4096: combined <=11264, below unchanged16KiB.
const _: () = {
    assert!(std::mem::size_of::<CustodyTotals>() <= 4096);
    assert!(std::mem::size_of::<CustodySnapshot>() <= 4096);
    assert!(
        (PHASES.len() + CUSTODY_PARENTS.len() + CUSTODY_STAGES.len() + 2) * 256 + 512 + 4096
            <= 16 * 1024
    );
};

// No caller-controlled text, widths or collection sizes are formatted. A u128
// has at most 39 decimal digits, a u64 20; each of the fixed twelve lines is
// bounded by 256 bytes, even for invalid retained statistics at numeric maxima.
const _: () = {
    assert!(std::mem::size_of::<WorkerTrace>() <= 8192);
    assert!(std::mem::size_of::<WorkerSnapshot>() <= 8192);
    assert!((PHASES.len() + 1) * 256 <= 8192);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, ns: u64) -> Instant {
        base + Duration::from_nanos(ns)
    }
    fn statistics(bucket: &Bucket) -> (u64, u128, Option<u128>, Option<u128>) {
        (
            bucket.count(),
            bucket.sum_ns(),
            bucket.min_ns(),
            bucket.max_ns(),
        )
    }

    fn custody_partition_checks(base: Instant) {
        let mut worker = WorkerTrace::new();
        let mut totals = CustodyTotals::default();
        worker.start(base);
        assert!(worker.custody_parent().is_none());
        let mut tick = 0;
        for phase in CUSTODY_PARENTS {
            tick += 1;
            worker.mark(phase, at(base, tick));
            tick += 1;
            let mut pass = totals.begin(worker.custody_parent().unwrap(), at(base, tick));
            for next in CUSTODY_STAGES.into_iter().skip(1) {
                tick += 1;
                pass.mark(next, at(base, tick));
            }
            tick += 1;
            pass.finish(at(base, tick));
            tick += 1;
            totals.boundary(worker.custody_parent(), at(base, tick));
            worker.mark(WorkerPhase::Receive, at(base, tick));
        }
        for phase in [WorkerPhase::Setup, WorkerPhase::Cleanup] {
            worker.mark(phase, at(base, tick));
            assert!(worker.custody_parent().is_none());
        }
        let parent = worker.finish(at(base, tick));
        let nested = totals.finish(&parent);
        assert!(parent.is_valid() && nested.totals.valid);
        assert_eq!((nested.totals.started, nested.totals.completed), (3, 3));
        assert_eq!(nested.partition, Some(30));
        for b in nested.totals.stages {
            assert_eq!(statistics(&b), (3, 3, Some(1), Some(1)));
        }
        for (i, phase) in CUSTODY_PARENTS.into_iter().enumerate() {
            assert_eq!(
                statistics(&nested.totals.parents[i]),
                (1, 10, Some(10), Some(10))
            );
            assert_eq!(parent.bucket(phase).sum_ns(), 12);
        }
        // Nested spans never change the top-level39ns partition or represent
        // its unmeasured entry/exit remainder as another additive duration.
        assert_eq!(parent.window_ns(), Some(39));
        assert!(
            nested
                .to_string()
                .contains("status=VALID started=3 completed=3 partition_ns=30")
        );
        assert!(!CustodyTotals::default().finish(&parent).totals.valid);

        let mut empty = WorkerTrace::new();
        empty.start(base);
        let empty = empty.finish(base);
        let unavailable = CustodyTotals::default().finish(&empty);
        assert!(
            unavailable
                .to_string()
                .contains("status=UNAVAILABLE started=0 completed=0 partition_ns=none")
        );
    }

    fn custody_refusal_checks(base: Instant) {
        for mutation in 0..10 {
            let mut worker = WorkerTrace::new();
            worker.start(base);
            worker.mark(WorkerPhase::BeforeCustody, at(base, 1));
            let mut totals = CustodyTotals::default();
            if mutation == 6 {
                totals.started = u64::MAX;
            }
            if mutation == 7 {
                totals.stages[0].sum_ns = u128::MAX;
            }
            if mutation == 8 {
                totals.completed = u64::MAX;
            }
            let parent = if mutation == 9 {
                (WorkerPhase::Setup, at(base, 1))
            } else {
                worker.custody_parent().unwrap()
            };
            let mut pass = totals.begin(parent, at(base, if mutation == 0 { 0 } else { 2 }));
            pass.mark(
                CustodyStage::MapsRead,
                at(base, if mutation == 1 { 1 } else { 4 }),
            );
            pass.finish(at(base, if mutation == 2 { 3 } else { 5 }));
            if mutation != 5 {
                let parent = if mutation == 4 {
                    Some((WorkerPhase::AfterCustody, base))
                } else {
                    worker.custody_parent()
                };
                totals.boundary(parent, at(base, if mutation == 3 { 4 } else { 6 }));
            }
            worker.mark(WorkerPhase::Receive, at(base, 6));
            let parent = worker.finish(at(base, 7));
            let child = totals.finish(&parent);
            assert!(
                parent.is_valid(),
                "diagnostic refusal must not alter old trace"
            );
            assert!(!child.totals.valid, "nested mutation {mutation}");
            assert!(child.to_string().contains("partition_ns=none"));
        }
        // A caught read/check unwind retains a prefix but not completion.
        let mut worker = WorkerTrace::new();
        worker.start(base);
        worker.mark(WorkerPhase::BeforeCustody, at(base, 1));
        let mut totals = CustodyTotals::default();
        let refusal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut pass = totals.begin(worker.custody_parent().unwrap(), at(base, 2));
            pass.mark(CustodyStage::MapsRead, at(base, 3));
            panic!("forced read/parse/check refusal");
        }));
        assert!(refusal.is_err());
        totals.boundary(worker.custody_parent(), at(base, 4));
        worker.mark(WorkerPhase::Receive, at(base, 4));
        let child = totals.finish(&worker.finish(at(base, 5)));
        assert!(!child.totals.valid);
        assert_eq!((child.totals.started, child.totals.completed), (1, 0));
        assert_eq!(
            statistics(&child.totals.stages[0]),
            (1, 1, Some(1), Some(1))
        );
    }

    #[test]
    fn bucket_distinguishes_empty_zero_and_exact_extrema() {
        let mut bucket = Bucket::default();
        assert!(bucket.is_valid());
        assert_eq!(statistics(&bucket), (0, 0, None, None));
        assert_eq!(
            bucket.to_string(),
            "valid=true spans=0 sum_ns=0 min_ns=none max_ns=none"
        );
        for ns in [0, 9, 4, 9] {
            assert!(bucket.observe(Some(Duration::from_nanos(ns))));
        }
        assert_eq!(statistics(&bucket), (4, 22, Some(0), Some(9)));
        let mut largest = Bucket::default();
        assert!(largest.observe(Some(Duration::MAX)));
        let ns = Duration::MAX.as_nanos();
        assert_eq!(statistics(&largest), (1, ns, Some(ns), Some(ns)));
    }

    #[test]
    fn bucket_missing_and_overflow_latch_without_replacing_statistics() {
        let mut missing = Bucket::default();
        assert!(missing.observe(Some(Duration::from_nanos(7))));
        let retained = statistics(&missing);
        assert!(!missing.observe(None));
        assert!(!missing.is_valid());
        assert!(!missing.observe(Some(Duration::from_nanos(2))));
        assert_eq!(statistics(&missing), retained);
        for (count, sum_ns) in [(u64::MAX, 7), (1, u128::MAX)] {
            let mut bucket = Bucket {
                valid: true,
                count,
                sum_ns,
                min_ns: Some(7),
                max_ns: Some(7),
            };
            let retained = statistics(&bucket);
            assert!(!bucket.observe(Some(Duration::from_nanos(1))));
            assert!(!bucket.is_valid());
            assert_eq!(statistics(&bucket), retained);
            assert!(!bucket.observe(Some(Duration::ZERO)));
            assert_eq!(statistics(&bucket), retained);
        }
    }

    #[test]
    fn worker_partition_conserves_all_phases_and_repeated_marks() {
        let base = Instant::now();
        let mut trace = WorkerTrace::new();
        trace.start(base);
        let mut elapsed = 0;
        for (index, phase) in PHASES.into_iter().enumerate().skip(1) {
            elapsed += index as u64;
            trace.mark(phase, at(base, elapsed));
        }
        elapsed += 11;
        trace.mark(WorkerPhase::Cleanup, at(base, elapsed));
        elapsed += 12;
        let snapshot = trace.finish(at(base, elapsed));
        assert!(snapshot.is_valid());
        assert_eq!(snapshot.started_at(), Some(base));
        assert_eq!(snapshot.finished_at(), at(base, 78));
        assert_eq!(snapshot.window_ns(), Some(78));
        for (index, phase) in PHASES.into_iter().enumerate().take(10) {
            let ns = index as u128 + 1;
            assert_eq!(
                statistics(snapshot.bucket(phase)),
                (1, ns, Some(ns), Some(ns))
            );
        }
        assert_eq!(
            statistics(snapshot.bucket(WorkerPhase::Cleanup)),
            (2, 23, Some(11), Some(12))
        );
        assert_eq!(
            snapshot.buckets.iter().map(Bucket::sum_ns).sum::<u128>(),
            78
        );
        assert!(
            snapshot
                .to_string()
                .contains("status=VALID bucket_scope=complete_partition")
        );
        custody_partition_checks(base);
    }

    #[test]
    fn worker_missing_or_repeated_start_never_resets_a_trace() {
        let base = Instant::now();
        let missing = WorkerTrace::new().finish(base);
        assert!(!missing.is_valid());
        assert_eq!(missing.started_at(), None);
        assert_eq!(missing.window_ns(), None);
        assert!(
            missing
                .to_string()
                .contains("window_start_ns=none observed_end_ns=none partition_ns=none")
        );
        let mut early_mark = WorkerTrace::new();
        early_mark.mark(WorkerPhase::Input, base);
        early_mark.start(at(base, 1));
        let missing = early_mark.finish(at(base, 2));
        assert!(!missing.is_valid());
        assert_eq!(missing.started_at(), None);
        assert!(missing.buckets.iter().all(|bucket| bucket.count() == 0));
        let mut repeated = WorkerTrace::new();
        repeated.start(base);
        repeated.mark(WorkerPhase::Input, at(base, 3));
        repeated.start(at(base, 4));
        repeated.mark(WorkerPhase::Invoke, at(base, 5));
        let invalid = repeated.finish(at(base, 6));
        assert!(!invalid.is_valid());
        assert_eq!(invalid.started_at(), Some(base));
        assert_eq!(invalid.window_ns(), None);
        assert_eq!(
            statistics(invalid.bucket(WorkerPhase::Receive)),
            (1, 3, Some(3), Some(3))
        );
        assert_eq!(invalid.bucket(WorkerPhase::Input).count(), 0);
        assert_eq!(invalid.bucket(WorkerPhase::Invoke).count(), 0);
    }

    #[test]
    fn worker_regression_and_bucket_overflow_keep_only_valid_prefix() {
        let base = Instant::now();
        let mut trace = WorkerTrace::new();
        trace.start(base);
        trace.mark(WorkerPhase::Invoke, at(base, 5));
        trace.mark(WorkerPhase::Reply, at(base, 4));
        trace.mark(WorkerPhase::Cleanup, at(base, 9));
        let invalid = trace.finish(at(base, 10));
        assert!(!invalid.is_valid());
        assert_eq!(invalid.window_ns(), None);
        assert_eq!(
            statistics(invalid.bucket(WorkerPhase::Receive)),
            (1, 5, Some(5), Some(5))
        );
        assert!(!invalid.bucket(WorkerPhase::Invoke).is_valid());
        assert_eq!(invalid.bucket(WorkerPhase::Invoke).min_ns(), None);
        assert_eq!(invalid.bucket(WorkerPhase::Reply).count(), 0);
        assert!(
            invalid
                .to_string()
                .contains("status=INVALID bucket_scope=retained_valid_prefix")
        );
        let mut finish_regresses = WorkerTrace::new();
        finish_regresses.start(at(base, 2));
        let invalid = finish_regresses.finish(base);
        assert!(!invalid.is_valid());
        assert_eq!(invalid.observed_end_ns(), None);
        let mut overflows = WorkerTrace::new();
        overflows.start(base);
        overflows.buckets[WorkerPhase::Receive as usize].count = u64::MAX;
        let invalid = overflows.finish(at(base, 1));
        assert!(!invalid.is_valid());
        assert_eq!(invalid.bucket(WorkerPhase::Receive).count(), u64::MAX);
        assert_eq!(invalid.bucket(WorkerPhase::Receive).sum_ns(), 0);
        custody_refusal_checks(base);
    }

    #[test]
    fn worker_zero_window_is_observed_and_finish_consumes_the_active_trace() {
        let base = Instant::now();
        let mut trace = WorkerTrace::default();
        trace.start(base);
        trace.mark(WorkerPhase::Receive, base);
        // The function pointer fixes finish's consuming signature. WorkerTrace
        // has no Clone/Copy or snapshot method exposing an active partial trace.
        let finish: fn(WorkerTrace, Instant) -> WorkerSnapshot = WorkerTrace::finish;
        let snapshot = finish(trace, base);
        assert!(snapshot.is_valid());
        assert_eq!(snapshot.window_ns(), Some(0));
        assert_eq!(
            statistics(snapshot.bucket(WorkerPhase::Receive)),
            (2, 0, Some(0), Some(0))
        );
        assert_eq!(
            statistics(snapshot.bucket(WorkerPhase::Cleanup)),
            (0, 0, None, None)
        );
    }

    #[test]
    fn worker_formatter_has_fixed_numeric_and_line_bounds() {
        let base = Instant::now();
        let bucket = Bucket {
            valid: false,
            count: u64::MAX,
            sum_ns: u128::MAX,
            min_ns: Some(u128::MAX),
            max_ns: Some(u128::MAX),
        };
        let snapshot = WorkerSnapshot {
            valid: false,
            start: Some(base),
            finish: base,
            buckets: [bucket; PHASES.len()],
        };
        let output = snapshot.to_string();
        assert_eq!(output.lines().count(), 12);
        assert!(output.lines().all(|line| line.len() < 256));
        assert!(output.len() <= 8192);
        assert!(output.contains("partition_ns=none"));
        assert_eq!(output.matches(&u128::MAX.to_string()).count(), 33);
        assert_eq!(output.matches(&u64::MAX.to_string()).count(), 11);
        // Width/precision cannot expand the fixed representation.
        assert_eq!(format!("{snapshot:10000.10000}"), output);
        let nested = CustodySnapshot {
            totals: CustodyTotals {
                valid: false,
                started: u64::MAX,
                completed: u64::MAX,
                parents: [bucket; 3],
                stages: [bucket; 10],
                pending: None,
            },
            partition: Some(u128::MAX),
        };
        let child = nested.to_string();
        assert_eq!(child.lines().count(), 14);
        assert!(child.lines().all(|line| line.len() < 256));
        assert!(child.len() <= 14 * 256);
        assert!(child.contains("partition_ns=none"));
        assert_eq!(child.matches(&u128::MAX.to_string()).count(), 39);
        assert_eq!(child.matches(&u64::MAX.to_string()).count(), 15);
        assert_eq!(format!("{nested:10000.10000}"), child);
        assert!(output.len() + child.len() + 512 + 4096 <= 16 * 1024);
    }
}
