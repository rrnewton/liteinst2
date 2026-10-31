//! Fixed diagnostic accounting; never an input to runtime acceptance.
//! The caller supplies every sample. This module takes no clock samples and
//! performs no allocation, I/O, locking or worker-lifecycle observation.
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
    }
}
