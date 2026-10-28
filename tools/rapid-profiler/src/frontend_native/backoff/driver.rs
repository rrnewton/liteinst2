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
        }
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
    fn receive_one(&mut self) -> Result<(), Error> {
        match self.input.try_recv() {
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
            Err(mpsc::TryRecvError::Empty) => Ok(()),
            Err(mpsc::TryRecvError::Disconnected) => {
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
            return Err(Error::AlreadyStarted);
        }
        self.started = true;
        if self.shared.start.set(start).is_err() {
            return Err(Error::AlreadyStarted);
        }
        let result = self.run_inner(start);
        if result.is_err() {
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
        let mut clock = Clock::new(start, self.policy)?;
        let mut max_arm_lateness = Duration::ZERO;
        let mut stop_acknowledged = None;
        let mut removal_completed = None;
        loop {
            match clock.poll(
                Instant::now(),
                self.shared.stop.load(Ordering::Acquire),
                self.arms,
            )? {
                Decision::Stop => {
                    stop_acknowledged = Instant::now().checked_duration_since(start);
                    self.shared.stop.store(true, Ordering::Release);
                    self.close()?;
                    removal_completed = Instant::now().checked_duration_since(start);
                    self.history()?;
                }
                Decision::Arm(due) => {
                    self.arm()?;
                    // An arm itself consuming the fixed slack also refuses.
                    let completed = Instant::now();
                    arm_due(completed, due, self.policy.lateness())?;
                    max_arm_lateness = max_arm_lateness.max(completed.duration_since(due));
                }
                Decision::Wait => (),
            }
            self.receive_one()?;
            self.retire()?;
            if clock.stopping.is_some() {
                if let Some(status) = self.shared.finished.get().copied() {
                    finished_ok(Some(status))?;
                    if status.totals == Some(self.cursor.totals)
                        && self.slots.iter().all(Option::is_none)
                    {
                        self.history()?;
                        // The preceding metadata/allocation work may have stalled
                        // after the loop's check. Late completion is a failure,
                        // even with all packets exported; this cannot cancel it.
                        let completed = Instant::now();
                        clock.check_deadline(completed)?;
                        return Ok(RunSummary {
                            arms: self.arms,
                            reports: self.reports,
                            actions: self.history_end,
                            history_batches: self.history_number,
                            call_batches: self.cursor.number,
                            totals: self.cursor.totals,
                            accepted_exports: self.exported,
                            worker_detached: true,
                            stop_reason: clock.stop_reason.ok_or(Error::Sequence)?,
                            max_arm_lateness,
                            stop_acknowledged,
                            removal_completed,
                            controller_completed: completed.checked_duration_since(start),
                        });
                    }
                }
            }
            std::thread::sleep(POLL);
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

#[cfg(test)]
mod tests;
