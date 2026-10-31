//! Failure-only fixed loop telemetry. Never an input to Schedule or acceptance.
//! Two RUSAGE_THREAD syscalls and wall observations per iteration have real cost.
//! Accounting samples have their own brackets, not the original poll endpoints.
use super::phase_totals::Bucket;
use std::fmt::{self, Write};
use std::time::Instant;

#[derive(Clone, Copy)]
#[repr(usize)]
pub(in crate::normal) enum Phase {
    Poll,
    PollReturned,
    PollArm,
    ReplyHistory,
    Retire,
    Input,
    Dispatch,
    Finalize,
    Write,
    WaitBound,
    Wait,
    End,
}
const NAMES: [&str; 12] = [
    "poll",
    "poll_returned",
    "poll_arm",
    "reply_history",
    "retire",
    "input",
    "dispatch",
    "finalize",
    "write",
    "wait_bound",
    "wait",
    "end",
];

#[derive(Clone, Copy, Default)]
pub(in crate::normal) struct State {
    // pending: 0 none, 1 CALL, 2 FLUSH, 3 unexpected T1 STOP. No input/IDs.
    // before/after are loop endpoint snapshots, not a concurrent worker view.
    pub pending: u8,
    pub requested: bool,
    pub stopping: bool,
    pub accepted: usize,
    pub history: u64,
    pub reports: usize,
    pub finished: u8,
    pub write_blocked: u64,
    pub output_drained: bool,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("pending", &self.pending)
            .field("requested", &self.requested)
            .field("stopping", &self.stopping)
            .field("accepted", &self.accepted)
            .field("history", &self.history)
            .field("reports", &self.reports)
            .field("finished", &self.finished)
            .field("write_blocked", &self.write_blocked)
            .field("output_drained", &self.output_drained)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Usage {
    user_us: u64,
    system_us: u64,
    voluntary: u64,
    involuntary: u64,
    minor_faults: u64,
    major_faults: u64,
}
fn micros(value: libc::timeval) -> Option<u64> {
    let seconds = u64::try_from(value.tv_sec).ok()?;
    let subsecond = u64::try_from(value.tv_usec).ok()?;
    if subsecond >= 1_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000)?.checked_add(subsecond)
}
fn usage(raw: &libc::rusage) -> Option<Usage> {
    Some(Usage {
        user_us: micros(raw.ru_utime)?,
        system_us: micros(raw.ru_stime)?,
        voluntary: u64::try_from(raw.ru_nvcsw).ok()?,
        involuntary: u64::try_from(raw.ru_nivcsw).ok()?,
        minor_faults: u64::try_from(raw.ru_minflt).ok()?,
        major_faults: u64::try_from(raw.ru_majflt).ok()?,
    })
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sample {
    Value(Usage),
    OsError(i32),
    Invalid,
}
impl fmt::Debug for Sample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(value) => f.debug_tuple("Value").field(value).finish(),
            Self::OsError(code) => f.debug_tuple("OsError").field(code).finish(),
            Self::Invalid => f.write_str("Invalid"),
        }
    }
}
#[derive(Clone, Copy)]
struct Bracket {
    before: Instant,
    value: Sample,
    after: Instant,
}
impl Bracket {
    fn read() -> Self {
        let before = Instant::now();
        // SAFETY: private writable output; Linux RUSAGE_THREAD observes only this
        // controller thread. No metadata guard, worker state or process scan.
        let mut raw = unsafe { std::mem::zeroed::<libc::rusage>() };
        let rc = unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut raw) };
        let value = if rc == 0 {
            usage(&raw).map_or(Sample::Invalid, Sample::Value)
        } else {
            Sample::OsError(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        };
        let after = Instant::now();
        Self {
            before,
            value,
            after,
        }
    }
}
#[derive(PartialEq, Eq)]
enum Delta {
    Value(Usage),
    Unavailable,
    Regressed,
}
impl fmt::Debug for Delta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(value) => f.debug_tuple("Value").field(value).finish(),
            Self::Unavailable => f.write_str("Unavailable"),
            Self::Regressed => f.write_str("Regressed"),
        }
    }
}
fn delta(first: Sample, last: Sample) -> Delta {
    let (Sample::Value(a), Sample::Value(b)) = (first, last) else {
        return Delta::Unavailable;
    };
    difference(a, b).map_or(Delta::Regressed, Delta::Value)
}
fn difference(a: Usage, b: Usage) -> Option<Usage> {
    Some(Usage {
        user_us: b.user_us.checked_sub(a.user_us)?,
        system_us: b.system_us.checked_sub(a.system_us)?,
        voluntary: b.voluntary.checked_sub(a.voluntary)?,
        involuntary: b.involuntary.checked_sub(a.involuntary)?,
        minor_faults: b.minor_faults.checked_sub(a.minor_faults)?,
        major_faults: b.major_faults.checked_sub(a.major_faults)?,
    })
}

struct Iteration {
    marks: [Option<Instant>; 12],
    first: Bracket,
    last: Option<Bracket>,
    before: State,
    after: Option<State>,
    decision: &'static str,
    reply: &'static str,
    worker: usize,
    reply_calls: usize,
    command: &'static str,
    progress: bool,
}

const DECISIONS: [&str; 5] = ["arm", "stop", "wait", "refused", "other"];
const REPLIES: [&str; 4] = ["batch", "flushed", "finished", "other"];

// Fixed controller-local arithmetic only. These buckets reuse observations
// already paid for by Trace; they do not read a clock, rusage or worker state.
#[derive(Clone, Copy)]
struct Aggregate {
    spans: [Bucket; 11],
    gaps: Bucket,
    started: u64,
    completed: u64,
    zero_progress: u64,
    decisions: [u64; 5],
    replies: [u64; 4],
    reply_calls: u64,
    valid: bool,
}
impl Default for Aggregate {
    fn default() -> Self {
        Self {
            spans: [Bucket::default(); 11],
            gaps: Bucket::default(),
            started: 0,
            completed: 0,
            zero_progress: 0,
            decisions: [0; 5],
            replies: [0; 4],
            reply_calls: 0,
            valid: true,
        }
    }
}
fn add(counter: &mut u64, amount: u64) -> bool {
    if let Some(value) = counter.checked_add(amount) {
        *counter = value;
        true
    } else {
        false
    }
}
impl Aggregate {
    fn boundaries(&mut self, item: &Iteration, complete: bool) {
        // A failure's synthetic End is never a completed Wait->End span.
        let end = if complete {
            Phase::End as usize
        } else {
            item.marks[..Phase::End as usize]
                .iter()
                .rposition(Option::is_some)
                .unwrap_or(0)
        };
        for i in 0..end {
            let duration = item.marks[i]
                .zip(item.marks[i + 1])
                .and_then(|(a, b)| b.checked_duration_since(a));
            self.valid &= self.spans[i].observe(duration);
        }
    }
}
#[derive(Default)]
pub(in crate::normal) struct Trace {
    last: Option<Iteration>,
    current: Option<Iteration>,
    aggregate: Aggregate,
    aggregate_enabled: bool,
}
impl Trace {
    pub(in crate::normal) fn with_aggregates() -> Self {
        Self {
            aggregate_enabled: true,
            ..Self::default()
        }
    }
    pub(in crate::normal) fn begin(&mut self, observed: Instant, state: State) {
        self.begin_with(observed, state, Bracket::read());
    }
    pub(in crate::normal) fn refused_poll(&mut self, observed: Instant, state: State) {
        self.begin(observed, state);
        self.decision("refused");
    }
    fn begin_with(&mut self, observed: Instant, state: State, sample: Bracket) {
        if self.aggregate_enabled {
            self.aggregate.valid &= self.current.is_none();
            self.aggregate.valid &= add(&mut self.aggregate.started, 1);
            if let Some(previous) = &self.last {
                self.aggregate.valid &= self.aggregate.gaps.observe(
                    previous.marks[Phase::End as usize]
                        .and_then(|end| observed.checked_duration_since(end)),
                );
            }
        }
        let mut marks = [None; 12];
        marks[Phase::Poll as usize] = Some(observed);
        marks[Phase::PollReturned as usize] = Some(sample.before);
        self.current = Some(Iteration {
            marks,
            first: sample,
            last: None,
            before: state,
            after: None,
            decision: "unobserved",
            reply: "none",
            worker: 0,
            reply_calls: 0,
            command: "none",
            progress: false,
        });
    }
    pub(in crate::normal) fn at(&mut self, phase: Phase, at: Instant) {
        if let Some(current) = &mut self.current {
            current.marks[phase as usize] = Some(at);
        }
    }
    pub(in crate::normal) fn mark(&mut self, phase: Phase) {
        self.at(phase, Instant::now());
    }
    pub(in crate::normal) fn decision(&mut self, name: &'static str) {
        if let Some(current) = &mut self.current {
            current.decision = name;
            if self.aggregate_enabled {
                let index = DECISIONS.iter().position(|&s| s == name).unwrap_or(4);
                self.aggregate.valid &= add(&mut self.aggregate.decisions[index], 1);
            }
        }
    }
    pub(in crate::normal) fn reply(&mut self, name: &'static str, worker: usize, calls: usize) {
        if let Some(current) = &mut self.current {
            current.reply = name;
            current.worker = worker;
            current.reply_calls = calls;
            if self.aggregate_enabled {
                let index = REPLIES.iter().position(|&s| s == name).unwrap_or(3);
                self.aggregate.valid &= add(&mut self.aggregate.replies[index], 1);
                self.aggregate.valid &= u64::try_from(calls)
                    .ok()
                    .is_some_and(|calls| add(&mut self.aggregate.reply_calls, calls));
            }
        }
    }
    pub(in crate::normal) fn command(&mut self, name: &'static str) {
        if let Some(current) = &mut self.current {
            current.command = name;
        }
    }
    pub(in crate::normal) fn progress(&mut self, value: bool) {
        if let Some(current) = &mut self.current {
            current.progress = value;
        }
    }
    pub(in crate::normal) fn complete(&mut self, state: State) {
        self.complete_with(state, Bracket::read());
    }
    fn complete_with(&mut self, state: State, sample: Bracket) {
        self.end_with(sample, Some(state));
        if self.aggregate_enabled {
            if let Some(current) = &self.current {
                self.aggregate.boundaries(current, true);
                self.aggregate.valid &= add(&mut self.aggregate.completed, 1);
                if !current.progress {
                    self.aggregate.valid &= add(&mut self.aggregate.zero_progress, 1);
                }
            } else {
                self.aggregate.valid = false;
            }
        }
        self.last = self.current.take();
    }
    fn end_with(&mut self, sample: Bracket, state: Option<State>) {
        if let Some(current) = &mut self.current {
            current.marks[Phase::End as usize] = Some(sample.after);
            current.last = Some(sample);
            current.after = state;
        }
    }
    pub(in crate::normal) fn failure(&mut self) -> String {
        // Keep the prior complete iteration; a failed poll must not replace it.
        if self.current.is_some() {
            self.end_with(Bracket::read(), None);
        }
        self.report()
    }
    pub(in crate::normal) fn aggregate_report(&self) -> String {
        if !self.aggregate_enabled {
            return " controller_phase_totals_v1=[status=UNAVAILABLE reason=disabled]\n".into();
        }
        // Failure-only allocation/formatting. A copy includes the current
        // observed prefix exactly once, without consuming or duplicating it.
        let mut totals = self.aggregate;
        let mut tail = None;
        let mut unfinished_from = "none";
        if let Some(current) = &self.current {
            totals.boundaries(current, false);
            if let Some((index, at)) = current.marks[..Phase::End as usize]
                .iter()
                .enumerate()
                .rev()
                .find_map(|(i, at)| at.map(|at| (i, at)))
            {
                unfinished_from = NAMES[index];
                if let Some(last) = current.last {
                    let mut observed = Bucket::default();
                    totals.valid &= observed.observe(last.after.checked_duration_since(at));
                    tail = Some(observed);
                }
            } else {
                totals.valid = false;
            }
        }
        let status = if !totals.valid {
            "INVALID"
        } else if totals.started == 0 {
            "UNAVAILABLE"
        } else {
            "OBSERVED"
        };
        let mut out = format!(
            " controller_phase_totals_v1=[status={status} started={} completed={} current={} zero_progress_completed={} reply_calls={} decisions={{",
            totals.started,
            totals.completed,
            u8::from(self.current.is_some()),
            totals.zero_progress,
            totals.reply_calls,
        );
        for (name, count) in DECISIONS.iter().zip(totals.decisions) {
            let _ = write!(out, "{name}:{count},");
        }
        out.push_str("} replies={");
        for (name, count) in REPLIES.iter().zip(totals.replies) {
            let _ = write!(out, "{name}:{count},");
        }
        out.push_str("} completed_boundary_spans_ns={");
        for (i, bucket) in totals.spans.iter().enumerate() {
            let _ = write!(out, "{}->{}:({bucket}),", NAMES[i], NAMES[i + 1]);
        }
        let _ = write!(
            out,
            "}} inter_iteration_end_to_poll_ns=({}) unfinished_from={unfinished_from} unfinished_through_error_ns=",
            totals.gaps,
        );
        if let Some(tail) = tail {
            let _ = write!(out, "({tail})");
        } else {
            out.push_str("UNAVAILABLE");
        }
        out.push_str(" scope=controller_wall_observations_not_worker_or_performance]\n");
        out
    }
    fn report(&self) -> String {
        // Fixed two records and twelve boundaries; allocate only after failure.
        let mut out = String::new();
        for (name, item) in [("last", &self.last), ("current", &self.current)] {
            let _ = write!(out, " loop_trace_{name}=");
            if let Some(item) = item {
                let _ = write!(out, "{item}");
            } else {
                out.push_str("none");
            }
        }
        if let Some((previous, current)) = self
            .last
            .as_ref()
            .and_then(|last| last.last)
            .zip(self.current.as_ref().map(|current| current.first))
        {
            // This bridges accounting samples, not the original poll-gap interval.
            let low = current
                .before
                .checked_duration_since(previous.after)
                .map(|d| d.as_nanos());
            let high = current
                .after
                .checked_duration_since(previous.before)
                .map(|d| d.as_nanos());
            let _ = write!(
                out,
                " inter_iteration_accounting_wall_ns=({low:?},{high:?}) rusage_delta={:?}",
                delta(previous.value, current.value)
            );
        }
        out
    }
}
impl fmt::Display for Iteration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[decision={} reply={}:{}:{} command={} progress={} before={:?} after={:?} wall_spans_ns={{",
            self.decision,
            self.reply,
            self.worker,
            self.reply_calls,
            self.command,
            self.progress,
            self.before,
            self.after
        )?;
        for (i, name) in NAMES.iter().enumerate().skip(1) {
            let duration = self.marks[i - 1]
                .zip(self.marks[i])
                .and_then(|(a, b)| b.checked_duration_since(a))
                .map(|v| v.as_nanos());
            write!(f, "{}->{name}:{duration:?},", NAMES[i - 1])?;
        }
        let origin = self.marks[Phase::Poll as usize].unwrap_or(self.first.before);
        let relative = |at: Instant| at.checked_duration_since(origin).map(|d| d.as_nanos());
        write!(
            f,
            "}} accounting_start_bracket_ns=({:?},{:?}) rusage_start={:?}",
            relative(self.first.before),
            relative(self.first.after),
            self.first.value
        )?;
        if let Some(last) = self.last {
            write!(
                f,
                " accounting_end_bracket_ns=({:?},{:?}) rusage_end={:?} rusage_delta={:?}",
                relative(last.before),
                relative(last.after),
                last.value,
                delta(self.first.value, last.value)
            )?;
        } else {
            write!(f, " accounting_end=none")?;
        }
        if self.after.is_none() {
            if let Some((index, at)) = self.marks[..Phase::End as usize]
                .iter()
                .enumerate()
                .rev()
                .find_map(|(i, at)| at.map(|at| (i, at)))
            {
                let tail = self
                    .last
                    .and_then(|last| last.after.checked_duration_since(at))
                    .map(|d| d.as_nanos());
                write!(
                    f,
                    " unfinished_from={} unfinished_through_error_ns={tail:?}",
                    NAMES[index]
                )?;
            }
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn value(user_us: u64) -> Sample {
        Sample::Value(Usage {
            user_us,
            system_us: 3,
            voluntary: 4,
            involuntary: 5,
            minor_faults: 6,
            major_faults: 7,
        })
    }
    fn bracket(base: Instant, offset: u64, value: Sample) -> Bracket {
        Bracket {
            before: base + Duration::from_nanos(offset),
            value,
            after: base + Duration::from_nanos(offset + 1),
        }
    }
    #[test]
    fn failed_poll_retains_last_complete_and_distinguishes_partial_phase_coverage() {
        let base = Instant::now();
        let mut trace = Trace::default();
        assert_eq!(
            trace.report(),
            " loop_trace_last=none loop_trace_current=none"
        );
        trace.begin_with(base, State::default(), bracket(base, 1, value(10)));
        for (i, phase) in [
            Phase::PollArm,
            Phase::ReplyHistory,
            Phase::Retire,
            Phase::Input,
            Phase::Dispatch,
            Phase::Finalize,
            Phase::Write,
            Phase::WaitBound,
            Phase::Wait,
        ]
        .into_iter()
        .enumerate()
        {
            trace.at(phase, base + Duration::from_nanos(i as u64 + 3));
        }
        trace.decision("wait");
        trace.reply("batch", 2, 4);
        trace.command("flush");
        trace.progress(true);
        trace.complete_with(
            State {
                pending: 2,
                ..State::default()
            },
            bracket(base, 12, value(12)),
        );
        let completed = format!("{}", trace.last.as_ref().unwrap());
        assert!(completed.contains("poll->poll_returned:Some(1)"));
        assert!(completed.contains("poll_returned->poll_arm:Some(2)"));
        for pair in NAMES[2..11].windows(2) {
            assert!(completed.contains(&format!("{}->{}:Some(1)", pair[0], pair[1])));
        }
        assert!(completed.contains("wait->end:Some(2)"));
        assert!(completed.contains("reply=batch:2:4 command=flush progress=true"));
        trace.begin_with(
            base + Duration::from_nanos(20),
            State {
                accepted: 8,
                ..State::default()
            },
            bracket(base, 22, value(12)),
        );
        trace.decision("refused");
        trace.end_with(bracket(base, 30, value(13)), None);
        assert_eq!(format!("{}", trace.last.as_ref().unwrap()), completed);
        let report = trace.report();
        assert!(report.contains("decision=refused"));
        assert!(report.contains("poll_returned->poll_arm:None"));
        assert!(report.contains("after=None"));
        assert!(
            report.contains("unfinished_from=poll_returned unfinished_through_error_ns=Some(9)")
        );
        assert!(report.contains("inter_iteration_accounting_wall_ns=(Some(9),Some(11))"));
        assert!(report.contains("accounting_end_bracket_ns=(Some(10),Some(11))"));
        assert!(report.len() < 8192);
        let mut first = Trace::default();
        first.begin_with(base, State::default(), bracket(base, 2, Sample::OsError(5)));
        first.decision("refused");
        first.end_with(bracket(base, 4, Sample::Invalid), None);
        assert!(
            first
                .report()
                .starts_with(" loop_trace_last=none loop_trace_current=[decision=refused")
        );
        assert!(first.report().contains("rusage_delta=Unavailable"));
        let mut partial = Trace::default();
        partial.begin_with(base, State::default(), bracket(base, 1, value(10)));
        partial.at(Phase::PollArm, base + Duration::from_nanos(3));
        partial.reply("batch", 1, 4);
        partial.end_with(bracket(base, 5, value(11)), None);
        assert!(
            partial
                .report()
                .contains("unfinished_from=poll_arm unfinished_through_error_ns=Some(3)")
        );
        assert!(partial.report().contains("poll_arm->reply_history:None"));
    }
    #[test]
    fn accounting_units_unavailable_and_regression_never_become_off_cpu_claims() {
        assert_eq!(
            micros(libc::timeval {
                tv_sec: 2,
                tv_usec: 999_999
            }),
            Some(2_999_999)
        );
        assert_eq!(
            micros(libc::timeval {
                tv_sec: -1,
                tv_usec: 0
            }),
            None
        );
        assert_eq!(
            micros(libc::timeval {
                tv_sec: 0,
                tv_usec: 1_000_000
            }),
            None
        );
        assert_eq!(
            micros(libc::timeval {
                tv_sec: i64::MAX,
                tv_usec: 0
            }),
            None
        );
        let mut raw = unsafe { std::mem::zeroed::<libc::rusage>() };
        assert!(usage(&raw).is_some());
        raw.ru_nivcsw = -1;
        assert!(usage(&raw).is_none());
        assert_eq!(delta(value(20), value(19)), Delta::Regressed);
        let Sample::Value(mut changed) = value(20) else {
            unreachable!()
        };
        changed.involuntary = 4;
        assert_eq!(delta(value(20), Sample::Value(changed)), Delta::Regressed);
        assert_eq!(delta(value(20), Sample::OsError(5)), Delta::Unavailable);
        assert_eq!(delta(Sample::Invalid, value(20)), Delta::Unavailable);
        let Delta::Value(zero) = delta(value(20), value(20)) else {
            panic!("coarse zero is valid");
        };
        assert_eq!(zero.user_us, 0);
        assert_eq!(zero.voluntary, 0);
        let base = Instant::now();
        let mut trace = Trace::default();
        trace.begin_with(base, State::default(), bracket(base, 2, value(20)));
        trace.end_with(bracket(base, 100, value(21)), None);
        let report = trace.report();
        assert!(report.contains("accounting_start_bracket_ns=(Some(2),Some(3))"));
        assert!(report.contains("accounting_end_bracket_ns=(Some(100),Some(101))"));
        assert!(report.contains("user_us: 1, system_us: 0"));
        assert!(!report.contains("off_cpu"));
        assert!(!report.contains("preemption"));
    }

    #[test]
    fn controller_aggregate_counts_completed_iterations_and_partial_failure_once() {
        let base = Instant::now();
        let mut trace = Trace::with_aggregates();
        trace.begin_with(base, State::default(), bracket(base, 1, value(0)));
        for (i, phase) in [
            Phase::PollArm,
            Phase::ReplyHistory,
            Phase::Retire,
            Phase::Input,
            Phase::Dispatch,
            Phase::Finalize,
            Phase::Write,
            Phase::WaitBound,
            Phase::Wait,
        ]
        .into_iter()
        .enumerate()
        {
            trace.at(phase, base + Duration::from_nanos(i as u64 + 3));
        }
        trace.decision("wait");
        trace.complete_with(State::default(), bracket(base, 12, value(0)));
        assert_eq!(trace.aggregate.completed, 1);
        assert_eq!(trace.aggregate.zero_progress, 1);
        assert_eq!(trace.aggregate.replies, [0; 4]);
        assert_eq!(trace.aggregate.reply_calls, 0);
        assert!(trace.aggregate.spans.iter().all(|b| b.count() == 1));
        assert_eq!(
            trace
                .aggregate
                .spans
                .iter()
                .map(Bucket::sum_ns)
                .sum::<u128>(),
            13
        );
        trace.begin_with(
            base + Duration::from_nanos(20),
            State::default(),
            bracket(base, 22, value(0)),
        );
        trace.decision("refused");
        // Count actual observation events, not only the last/current label.
        trace.reply("batch", 1, 2);
        trace.reply("batch", 2, 3);
        trace.progress(true);
        assert_eq!(trace.aggregate.replies, [2, 0, 0, 0]);
        assert_eq!(trace.aggregate.reply_calls, 5);
        trace.at(Phase::PollArm, base + Duration::from_nanos(25));
        trace.at(Phase::ReplyHistory, base + Duration::from_nanos(26));
        trace.at(Phase::Retire, base + Duration::from_nanos(28));
        trace.end_with(bracket(base, 30, value(0)), None);
        let report = trace.aggregate_report();
        assert_eq!(trace.aggregate_report(), report);
        assert_eq!(trace.aggregate.completed, 1);
        assert!(trace.aggregate.spans.iter().all(|b| b.count() == 1));
        let mut with_prefix = trace.aggregate;
        with_prefix.boundaries(trace.current.as_ref().unwrap(), false);
        assert!(with_prefix.spans[..4].iter().all(|b| b.count() == 2));
        assert!(with_prefix.spans[4..].iter().all(|b| b.count() == 1));
        let named = with_prefix.spans.iter().map(Bucket::sum_ns).sum::<u128>();
        assert_eq!(named, 21);
        assert_eq!(trace.aggregate.gaps.sum_ns(), 7);
        assert_eq!(named + trace.aggregate.gaps.sum_ns() + 3, 31);
        assert!(report.contains("started=2 completed=1 current=1"));
        assert!(report.contains(
            "unfinished_from=retire unfinished_through_error_ns=(valid=true spans=1 sum_ns=3"
        ));
        assert!(!trace.report().contains("controller_phase_totals"));
    }

    #[test]
    fn controller_aggregate_refuses_clock_holes_regression_and_counter_overflow() {
        let base = Instant::now();
        let mut regression = Trace::with_aggregates();
        regression.begin_with(
            base + Duration::from_nanos(10),
            State::default(),
            bracket(base, 5, value(0)),
        );
        regression.end_with(bracket(base, 20, value(0)), None);
        assert!(regression.aggregate_report().contains("status=INVALID"));
        let mut hole = Trace::with_aggregates();
        hole.begin_with(base, State::default(), bracket(base, 1, value(0)));
        hole.at(Phase::ReplyHistory, base + Duration::from_nanos(3));
        assert!(hole.aggregate_report().contains("status=INVALID"));
        let mut overflow = Trace::with_aggregates();
        overflow.aggregate.started = u64::MAX;
        overflow.begin_with(base, State::default(), bracket(base, 1, value(0)));
        assert_eq!(overflow.aggregate.started, u64::MAX);
        assert!(!overflow.aggregate.valid);
        assert!(overflow.aggregate_report().contains("status=INVALID"));
        let mut missing = Trace::with_aggregates();
        missing.complete_with(State::default(), bracket(base, 1, value(0)));
        assert_eq!(missing.aggregate.completed, 0);
        assert!(!missing.aggregate.valid);
        // A repeated completion cannot charge any iteration a second time.
        missing.complete_with(State::default(), bracket(base, 2, value(0)));
        assert_eq!(missing.aggregate.completed, 0);
    }

    #[test]
    fn controller_aggregate_format_is_fixed_and_missing_terminal_time_is_unavailable() {
        let base = Instant::now();
        let mut inactive = Trace::default();
        inactive.begin_with(base, State::default(), bracket(base, 1, value(0)));
        inactive.decision("wait");
        inactive.reply("batch", 1, 1);
        inactive.complete_with(State::default(), bracket(base, 2, value(0)));
        assert_eq!(inactive.aggregate.started, 0);
        assert_eq!(inactive.aggregate.completed, 0);
        assert_eq!(inactive.aggregate.decisions, [0; 5]);
        assert_eq!(inactive.aggregate.replies, [0; 4]);
        assert!(inactive.aggregate.spans.iter().all(|b| b.count() == 0));
        assert!(inactive.aggregate.valid);
        assert!(
            inactive
                .aggregate_report()
                .contains("status=UNAVAILABLE reason=disabled")
        );
        let mut trace = Trace::with_aggregates();
        assert!(trace.aggregate_report().contains("status=UNAVAILABLE"));
        trace.begin_with(base, State::default(), bracket(base, 1, value(0)));
        let before = trace.report();
        let report = trace.aggregate_report();
        assert!(report.contains("status=OBSERVED"));
        assert!(
            report
                .contains("unfinished_from=poll_returned unfinished_through_error_ns=UNAVAILABLE")
        );
        assert_eq!(trace.report(), before);
        // Large duration values and maximum event counters stay bounded,
        // independent of record IDs or the original error length. Buckets
        // format only five fixed scalar fields (u64/u128/optional u128).
        trace.aggregate.started = u64::MAX;
        trace.aggregate.completed = u64::MAX;
        trace.aggregate.zero_progress = u64::MAX;
        trace.aggregate.reply_calls = u64::MAX;
        trace.aggregate.decisions = [u64::MAX; 5];
        trace.aggregate.replies = [u64::MAX; 4];
        for b in &mut trace.aggregate.spans {
            assert!(b.observe(Some(Duration::MAX)));
        }
        assert!(trace.aggregate.gaps.observe(Some(Duration::MAX)));
        let report = trace.aggregate_report();
        assert!(report.len() < 4096);
        assert!(report.ends_with('\n'));
        assert!(!report.contains("off_cpu"));
        assert!(!report.contains("preemption"));
        assert!(std::mem::size_of::<Aggregate>() < 2048);
    }
}
