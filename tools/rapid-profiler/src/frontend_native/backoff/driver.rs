use super::*;

/// Caller runs this value on its independent controller thread. It owns no
/// JoinHandle and never calls application code, a sink callback, or blocking I/O.
/// The mutable owner remains available after failure for bounded recovery.
pub struct Driver {
    controller: IntervalController,
    slots: [Option<IntervalEpoch>; SLOTS],
    current: Option<usize>,
    stream: HistoryStream,
    policy: Policy,
    shared: Arc<Shared>,
    input: mpsc::Receiver<CompletedBatch>,
    output: mpsc::SyncSender<Export>,
    pending: Option<Export>,
    cursor: Cursor,
    history_number: u64,
    history_end: u64,
    history_binding: HistoryBinding,
    arms: u32,
    reports: u32,
    exported: u64,
    started: bool,
    close_error: Option<Error>,
    close_attempted: bool,
    deadline_failure: Option<DeadlineFailure>,
}
/// Refusal location, not a diagnosis of OS scheduling or lock contention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlinePhase {
    ClockPoll,
    ArmOperation,
    FinalCompletion,
}
/// First deadline refusal only. Times are relative to the original start;
/// None means before start or an unrepresentable diagnostic endpoint.
/// Equality is late only when `at_limit_is_late` is true. No retry/reset follows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlineFailure {
    pub phase: DeadlinePhase,
    pub scheduled: Option<Duration>,
    pub limit: Option<Duration>,
    pub observed: Option<Duration>,
    /// Additional observation immediately before arm(), including its history export.
    pub arm_started: Option<Duration>,
    pub at_limit_is_late: bool,
}
impl DeadlineFailure {
    fn at(
        phase: DeadlinePhase,
        start: Instant,
        scheduled: Option<Instant>,
        limit: Option<Instant>,
        observed: Instant,
        arm_started: Option<Instant>,
        at_limit_is_late: bool,
    ) -> Self {
        Self {
            phase,
            scheduled: scheduled.and_then(|t| t.checked_duration_since(start)),
            limit: limit.and_then(|t| t.checked_duration_since(start)),
            observed: observed.checked_duration_since(start),
            arm_started: arm_started.and_then(|t| t.checked_duration_since(start)),
            at_limit_is_late,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    Requested,
    EpochLimit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunSummary {
    pub arms: u32,
    pub reports: u32,
    pub actions: u64,
    pub history_batches: u64,
    pub call_batches: u64,
    pub totals: PairTotals,
    pub accepted_exports: u64,
    /// This means explicit facade detach, not kernel task disappearance or join.
    pub worker_detached: bool,
    pub stop_reason: StopReason,
    /// Includes arm/history transfer duration; not a callback timing measure.
    pub max_arm_lateness: Duration,
    /// Clock observations relative to start; None means before that start.
    /// These are not OS join or durable-sink completion timestamps.
    pub stop_acknowledged: Option<Duration>,
    pub removal_completed: Option<Duration>,
    pub controller_completed: Option<Duration>,
}
impl Driver {
    pub(super) fn new(
        controller: IntervalController,
        stream: HistoryStream,
        policy: Policy,
        shared: Arc<Shared>,
        input: mpsc::Receiver<CompletedBatch>,
        output: mpsc::SyncSender<Export>,
    ) -> Self {
        Self {
            controller,
            slots: [None, None, None],
            current: None,
            stream,
            policy,
            shared,
            input,
            output,
            pending: None,
            cursor: Cursor::default(),
            history_number: 0,
            history_end: 0,
            history_binding: HistoryBinding::Initial,
            arms: 0,
            reports: 0,
            exported: 0,
            started: false,
            close_error: None,
            close_attempted: false,
            deadline_failure: None,
        }
    }
    /// Retained first diagnostic; absence does not classify a different failure.
    pub fn deadline_failure(&self) -> Option<DeadlineFailure> {
        self.deadline_failure
    }
    fn remember_deadline(&mut self, error: Error, failure: DeadlineFailure) -> Error {
        if error == Error::Deadline && self.deadline_failure.is_none() {
            self.deadline_failure = Some(failure);
        }
        error
    }
    fn emit(&mut self, packet: Export) -> Result<(), Error> {
        // A failed send retains ownership and immediately stops further progress.
        if self.pending.is_some() {
            return Err(Error::Sequence);
        }
        match send(&self.output, packet) {
            Ok(()) => {
                self.exported += 1;
                Ok(())
            }
            Err((e, p)) => {
                self.pending = Some(p);
                Err(e)
            }
        }
    }
    fn history(&mut self) -> Result<(), Error> {
        if let Some(batch) = self.controller.drain_history()? {
            // Store before checking so even a diagnostic refusal retains bytes.
            self.pending = Some(Export::History(batch));
            let Some(Export::History(b)) = self.pending.as_ref() else {
                unreachable!()
            };
            if b.stream() != &self.stream
                || b.number() != self.history_number + 1
                || b.range().start != self.history_end
                || b.before() != self.history_binding
                || b.range().end - b.range().start != b.actions().len() as u64
                || b.actions().len() > HISTORY
            {
                return Err(Error::Sequence);
            }
            self.history_number = b.number();
            self.history_end = b.range().end;
            self.history_binding = b.after();
            let p = self.pending.take().unwrap();
            self.emit(p)?;
        }
        Ok(())
    }
    fn receive_one(&mut self, wait: Duration) -> Result<(), Error> {
        // Wake on a completed batch instead of imposing a sleep after every
        // packet. A queued burst is still handled one packet per clock check;
        // idle waits retain the same fixed poll bound and shutdown deadlines.
        match self.input.recv_timeout(wait) {
            Ok(packet) => {
                self.pending = Some(Export::Calls(Box::new(packet)));
                let Some(Export::Calls(p)) = self.pending.as_ref() else {
                    unreachable!()
                };
                if p.native
                    .history_high_water()
                    .is_none_or(|end| end > self.history_end)
                {
                    return Err(Error::Sequence);
                }
                self.cursor.accept(p, &self.stream)?;
                let p = self.pending.take().unwrap();
                self.emit(p)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(()),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                finished_ok(self.shared.finished.get().copied())
            }
        }
    }
    fn take_report(&mut self, i: usize) -> Result<Option<FinalReport>, Error> {
        if self.current == Some(i) {
            return Ok(None);
        }
        let Some(epoch) = self.slots[i].as_ref() else {
            return Ok(None);
        };
        if self.controller.report(epoch)?.is_none() {
            return Ok(None);
        }
        // Reserve before slot removal. Report::records is Copy and A=K bounds
        // its complete iterator, so no allocation/failure follows retirement.
        let mut records = Vec::new();
        records
            .try_reserve_exact(self.policy.k)
            .map_err(|_| Error::Allocation)?;
        let report = self.controller.retire(epoch)?;
        let generation = report.generation().get();
        records.extend(report.records());
        drop(report);
        self.slots[i].take();
        self.reports += 1;
        Ok(Some(FinalReport {
            generation,
            records,
        }))
    }
    fn retire(&mut self) -> Result<(), Error> {
        for i in 0..SLOTS {
            if let Some(report) = self.take_report(i)? {
                self.emit(Export::Report(report))?;
            }
        }
        Ok(())
    }
    fn arm(&mut self) -> Result<(), Error> {
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::EpochCapacity)?;
        self.slots[index] = Some(self.controller.stage(self.policy.config())?);
        self.controller.arm(self.slots[index].as_ref().unwrap())?;
        self.current = Some(index);
        self.arms += 1;
        self.history()
    }
    fn close(&mut self) -> Result<(), Error> {
        self.close_attempted = true;
        if let Some(index) = self.current {
            if let Err(e) = self.controller.disarm(self.slots[index].as_ref().unwrap()) {
                let e = Error::Bridge(e);
                self.close_error = Some(e);
                return Err(e);
            }
            self.current = None;
        }
        Ok(())
    }
    /// Run once against caller-selected absolute start, with no per-call control
    /// rendezvous. A start already over 2ms late refuses. Each arm uses the same
    /// original clock; no deadline is shifted after contention or backpressure.
    ///
    /// Success means all worker packets accepted by the bounded output queue,
    /// genuine empty detach and copied reports. It does not mean sink durability
    /// or that the caller joined either native worker or sink OS threads.
    pub fn run(&mut self, start: Instant) -> Result<RunSummary, Error> {
        if self.started {
            self.shared.controller_failed.store(true, Ordering::Release);
            return Err(Error::AlreadyStarted);
        }
        self.started = true;
        if self.shared.start.set(start).is_err() {
            self.shared.controller_failed.store(true, Ordering::Release);
            return Err(Error::AlreadyStarted);
        }
        let result = self.run_inner(start);
        if result.is_err() {
            // A retained receiver does not imply that run() will drain again.
            // Publish before close/recovery, which can itself wait on metadata.
            self.shared.controller_failed.store(true, Ordering::Release);
            self.shared.stop.store(true, Ordering::Release);
            // Reserve capacity was maintained by draining after every arm. Keep
            // any final Removed action resident if export is already blocked.
            if !self.close_attempted {
                let _ = self.close();
            }
        }
        result
    }
    fn run_inner(&mut self, start: Instant) -> Result<RunSummary, Error> {
        let done = run_loop(DriverRef::Mandatory(&mut *self), start)?;
        Ok(RunSummary {
            arms: self.arms,
            reports: self.reports,
            actions: self.history_end,
            history_batches: self.history_number,
            call_batches: self.cursor.number,
            totals: self.cursor.totals,
            accepted_exports: self.exported,
            worker_detached: true,
            stop_reason: done.stop_reason,
            max_arm_lateness: done.max_arm_lateness,
            stop_acknowledged: done.stop_acknowledged,
            removal_completed: done.removal_completed,
            controller_completed: done.controller_completed,
        })
    }
    fn finished_ready(&self) -> Result<bool, Error> {
        if let Some(status) = self.shared.finished.get().copied() {
            finished_ok(Some(status))?;
            Ok(status.totals == Some(self.cursor.totals) && self.slots.iter().all(Option::is_none))
        } else {
            Ok(false)
        }
    }
    /// Recover an unsent export after failure. No successful run/resume is implied.
    pub fn take_pending(&mut self) -> Option<Export> {
        self.pending.take()
    }
    /// Any secondary removal refusal is retained separately from the first error.
    pub fn close_error(&self) -> Option<Error> {
        self.close_error
    }
    /// Drain queued completed packets after the real worker has stopped/joined.
    /// These values were NOT accepted by the sink; keep their original identity.
    pub fn recover_worker_packet(&mut self) -> Option<CompletedBatch> {
        self.input.try_recv().ok()
    }
    /// Explicit final history transfer for failure retention. The caller must
    /// preserve any previously returned batch; no counter or status is reset.
    pub fn recover_history(&mut self) -> Result<Option<HistoryBatch>, Error> {
        self.controller.drain_history().map_err(Into::into)
    }
    /// Recover one genuinely ready noncurrent report after failure/join. An
    /// unclosed staged/current owner remains retained; this cannot fake closure.
    pub fn recover_report(&mut self) -> Result<Option<FinalReport>, Error> {
        for i in 0..SLOTS {
            if let Some(report) = self.take_report(i)? {
                return Ok(Some(report));
            }
        }
        Ok(None)
    }
    /// Qualified failure suffix, including TerminalFailure. It is not a normal
    /// transferred HistoryBatch and must not be relabelled as one.
    pub fn history_window(&self) -> Result<super::super::HistoryWindow, Error> {
        self.controller.history_window().map_err(Into::into)
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        // No join/cancellation/Removed claim. Retain this object through actual
        // worker join if failure recovery of queued prefixes is required.
    }
}
pub(super) fn arm_due(now: Instant, due: Instant, late: Duration) -> Result<bool, Error> {
    if now < due {
        return Ok(false);
    }
    if now.duration_since(due) > late {
        return Err(Error::Deadline);
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Decision {
    Arm(Instant),
    Stop,
    Wait,
}
pub(super) struct Clock {
    start: Instant,
    end: Instant,
    absolute_end: Instant,
    policy: Policy,
    stopping: Option<Instant>,
    stop_reason: Option<StopReason>,
}
impl Clock {
    pub(super) fn new(start: Instant, policy: Policy) -> Result<Self, Error> {
        let end = start
            .checked_add(policy.period() * policy.epochs)
            .ok_or(Error::Policy)?;
        Ok(Self {
            start,
            end,
            absolute_end: end.checked_add(policy.shutdown()).ok_or(Error::Policy)?,
            policy,
            stopping: None,
            stop_reason: None,
        })
    }
    /// A channel wait must not intentionally pass the next original arm/end.
    /// POLL remains only an upper bound; no deadline or schedule is renewed.
    fn wait_bound(&self, now: Instant, arms: u32) -> Duration {
        let next = if let Some(stop) = self.stopping {
            stop
        } else if arms < self.policy.epochs {
            self.start
                .checked_add(self.policy.period() * arms)
                .unwrap_or(now)
        } else {
            self.end
        };
        POLL.min(next.min(self.absolute_end).saturating_duration_since(now))
    }
    // Diagnostic derivation only, called after an existing predicate refused.
    // These methods neither make a scheduling decision nor change clock state.
    fn diagnostic_shutdown_deadline(&self) -> Instant {
        self.stopping
            .unwrap_or(self.absolute_end)
            .min(self.absolute_end)
    }
    fn poll_failure(&self, now: Instant, request: bool, arms: u32) -> DeadlineFailure {
        let shutdown = self.diagnostic_shutdown_deadline();
        let (scheduled, limit, at_limit) = if now >= shutdown {
            (Some(shutdown), Some(shutdown), true)
        } else if !request && now >= self.end && arms < self.policy.epochs {
            (Some(self.end), Some(self.end), true)
        } else {
            let due = self.start.checked_add(self.policy.period() * arms);
            (
                due,
                due.and_then(|t| t.checked_add(self.policy.lateness())),
                false,
            )
        };
        DeadlineFailure::at(
            DeadlinePhase::ClockPoll,
            self.start,
            scheduled,
            limit,
            now,
            None,
            at_limit,
        )
    }
    pub(super) fn check_deadline(&self, now: Instant) -> Result<(), Error> {
        if now >= self.absolute_end || self.stopping.is_some_and(|d| now >= d) {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(super) fn poll(
        &mut self,
        now: Instant,
        request: bool,
        arms: u32,
    ) -> Result<Decision, Error> {
        self.check_deadline(now)?;
        if self.stopping.is_some() {
            return Ok(Decision::Wait);
        }
        if !request && now >= self.end && arms < self.policy.epochs {
            return Err(Error::Deadline);
        }
        if request || now >= self.end {
            self.stop_reason = Some(if request {
                StopReason::Requested
            } else {
                StopReason::EpochLimit
            });
            self.stopping = Some(
                now.checked_add(self.policy.shutdown())
                    .ok_or(Error::Policy)?
                    .min(self.absolute_end),
            );
            return Ok(Decision::Stop);
        }
        if arms < self.policy.epochs {
            let due = self
                .start
                .checked_add(self.policy.period() * arms)
                .ok_or(Error::Policy)?;
            if arm_due(now, due, self.policy.lateness())? {
                return Ok(Decision::Arm(due));
            }
        }
        Ok(Decision::Wait)
    }
}

pub(super) fn finished_ok(status: Option<WorkerStatus>) -> Result<(), Error> {
    match status {
        Some(s)
            if s.error.is_none()
                && s.detached
                && !s.unexported
                && s.totals.is_some_and(balanced) =>
        {
            Ok(())
        }
        _ => Err(Error::Worker),
    }
}

// One scheduling implementation, with two statically selected typed endpoints.
// No public extension trait or application callback enters this control loop.
pub(super) struct LoopCompletion {
    pub(super) stop_reason: StopReason,
    pub(super) max_arm_lateness: Duration,
    pub(super) stop_acknowledged: Option<Duration>,
    pub(super) removal_completed: Option<Duration>,
    pub(super) controller_completed: Option<Duration>,
}
enum DriverRef<'a> {
    Mandatory(&'a mut Driver),
    Optional(&'a mut super::optional::OptionalDriver),
}
macro_rules! both {
    ($value:expr, $d:ident => $body:expr) => {
        match $value {
            DriverRef::Mandatory($d) => $body,
            DriverRef::Optional($d) => $body,
        }
    };
}
impl DriverRef<'_> {
    fn policy(&self) -> Policy {
        both!(self, d => d.policy)
    }
    fn arms(&self) -> u32 {
        both!(self, d => d.arms)
    }
    fn common(&self) -> &Shared {
        match self {
            Self::Mandatory(d) => &d.shared,
            Self::Optional(d) => &d.shared.common,
        }
    }
    fn remember(&mut self, e: Error, f: DeadlineFailure) -> Error {
        both!(self, d => d.remember_deadline(e, f))
    }
    fn arm(&mut self) -> Result<(), Error> {
        both!(self, d => d.arm())
    }
    fn close(&mut self) -> Result<(), Error> {
        both!(self, d => d.close())
    }
    fn history(&mut self) -> Result<(), Error> {
        both!(self, d => d.history())
    }
    fn receive(&mut self, wait: Duration) -> Result<(), Error> {
        both!(self, d => d.receive_one(wait))
    }
    fn retire(&mut self) -> Result<(), Error> {
        both!(self, d => d.retire())
    }
    fn ready(&self) -> Result<bool, Error> {
        both!(self, d => d.finished_ready())
    }
    fn maintenance(&mut self) -> Result<(), Error> {
        match self {
            Self::Mandatory(_) => Ok(()),
            Self::Optional(d) => d.scan(),
        }
    }
}
pub(super) fn run_optional(
    driver: &mut super::optional::OptionalDriver,
    start: Instant,
) -> Result<LoopCompletion, Error> {
    run_loop(DriverRef::Optional(driver), start)
}
fn run_loop(mut driver: DriverRef<'_>, start: Instant) -> Result<LoopCompletion, Error> {
    let policy = driver.policy();
    let mut clock = Clock::new(start, policy)?;
    let mut max_arm_lateness = Duration::ZERO;
    let mut stop_acknowledged = None;
    let mut removal_completed = None;
    loop {
        let polled = Instant::now();
        let requested = driver.common().stop.load(Ordering::Acquire);
        let arms = driver.arms();
        match clock
            .poll(polled, requested, arms)
            .map_err(|error| driver.remember(error, clock.poll_failure(polled, requested, arms)))?
        {
            Decision::Stop => {
                stop_acknowledged = Instant::now().checked_duration_since(start);
                driver.common().stop.store(true, Ordering::Release);
                driver.close()?;
                removal_completed = Instant::now().checked_duration_since(start);
                driver.history()?;
            }
            Decision::Arm(due) => {
                let arm_started = Instant::now();
                driver.arm()?;
                let completed = Instant::now();
                arm_due(completed, due, policy.lateness()).map_err(|error| {
                    driver.remember(
                        error,
                        DeadlineFailure::at(
                            DeadlinePhase::ArmOperation,
                            start,
                            Some(due),
                            due.checked_add(policy.lateness()),
                            completed,
                            Some(arm_started),
                            false,
                        ),
                    )
                })?;
                max_arm_lateness = max_arm_lateness.max(completed.duration_since(due));
            }
            Decision::Wait => (),
        }
        // Mandatory is an exact no-op. Optional scan work remains charged to
        // the same original clock and never runs after stop acknowledgement.
        if clock.stopping.is_none() {
            driver.maintenance()?;
        }
        let wait = clock.wait_bound(Instant::now(), driver.arms());
        driver.receive(wait)?;
        driver.retire()?;
        if clock.stopping.is_some() && driver.ready()? {
            driver.history()?;
            let completed = Instant::now();
            clock.check_deadline(completed).map_err(|error| {
                let deadline = clock.diagnostic_shutdown_deadline();
                driver.remember(
                    error,
                    DeadlineFailure::at(
                        DeadlinePhase::FinalCompletion,
                        start,
                        Some(deadline),
                        Some(deadline),
                        completed,
                        None,
                        true,
                    ),
                )
            })?;
            return Ok(LoopCompletion {
                stop_reason: clock.stop_reason.ok_or(Error::Sequence)?,
                max_arm_lateness,
                stop_acknowledged,
                removal_completed,
                controller_completed: completed.checked_duration_since(start),
            });
        }
    }
}

#[cfg(test)]
mod backpressure_tests;
#[cfg(test)]
mod tests;
