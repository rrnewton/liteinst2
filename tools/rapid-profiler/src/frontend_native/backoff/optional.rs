//! Distinct optional physical-call accounting over the shared bounded scheduler.
use super::super::{
    InstalledOptionalSite, OptionalCallResult, OptionalIntervalBatch, OptionalPath, OptionalTotals,
    PreparedOptionalController,
};
use super::super::{OptionalClient as NativeClient, OptionalThread as NativeThread};
use super::*;
mod cursor;
mod worker;
use cursor::Cursor;
pub use worker::{OptionalCallOutcome, OptionalClient, OptionalThread, OptionalWorkerFinish};

pub(super) struct SharedOptional {
    // The old mandatory completion cell remains unused; no cross-profile receipt.
    pub(super) common: Arc<Shared>,
    finished: OnceLock<OptionalWorkerStatus>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptionalWorkerStatus {
    pub totals: Option<OptionalTotals>,
    pub detached: bool,
    pub error: Option<Error>,
    pub unexported: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptionalCompletedCall {
    pub length: usize,
    pub result: OptionalCallResult,
    pub before: Duration,
    pub after: Duration,
}
/// Up to four actual physical returns, with zero to four genuine Slow rows.
#[derive(Debug)]
pub struct OptionalCompletedBatch {
    pub native: OptionalIntervalBatch,
    pub calls: [Option<OptionalCompletedCall>; ROWS],
}
#[derive(Debug)]
pub enum OptionalExport {
    History(HistoryBatch),
    Calls(Box<OptionalCompletedBatch>),
    Report(FinalReport),
}
pub struct OptionalPrepared {
    pub driver: OptionalDriver,
    pub client: OptionalClient,
    pub stop: StopHandle,
    pub export: mpsc::Receiver<OptionalExport>,
}
/// Prepare one optional ordinary site; the caller owns all actual threads.
///
/// # Safety
/// The optional publication/ABI/input/stack/entry/normal-return contracts hold.
/// Only one attached client may call; source, generated code and gate remain
/// process-lived. Join the real worker before reclaiming input. No signal,
/// fork, cancellation, unwind or controller/callback/allocator reentry is allowed.
pub unsafe fn prepare_optional(
    site: InstalledOptionalSite,
    install: u64,
    function: FunctionId,
    policy: Policy,
) -> Result<OptionalPrepared, Error> {
    policy.require_legacy_driver()?;
    let prepared = PreparedOptionalController::new_streaming_history(
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
    // SAFETY: the caller supplies the complete optional activation contract.
    let (controller, client) = unsafe { prepared.activate_concurrent() }?;
    let stream = controller.history_window()?.stream().clone();
    let common = Arc::new(Shared {
        stop: AtomicBool::new(false),
        controller_failed: AtomicBool::new(false),
        attached: AtomicBool::new(false),
        start: OnceLock::new(),
        finished: OnceLock::new(),
    });
    let stop = StopHandle(common.clone());
    let shared = Arc::new(SharedOptional {
        common,
        finished: OnceLock::new(),
    });
    let (tx, input) = mpsc::sync_channel(WORK_QUEUE);
    let (output, export) = mpsc::sync_channel(EXPORT_QUEUE);
    Ok(OptionalPrepared {
        driver: OptionalDriver {
            controller,
            slots: [None, None, None],
            current: None,
            stream,
            policy,
            shared: shared.clone(),
            input,
            output,
            pending: None,
            sink: sink::Context::default(),
            cursor: Cursor::default(),
            history_number: 0,
            history_end: 0,
            history_binding: HistoryBinding::Initial,
            arms: 0,
            reports: 0,
            exported: 0,
            started: false,
            close_attempted: false,
            close_error: None,
            deadline_failure: None,
            disabled_generation: None,
            disabled: 0,
        },
        client: OptionalClient {
            client,
            policy,
            shared,
            tx,
        },
        stop,
        export,
    })
}
/// One unique optional controller, retained after failure for exact recovery.
pub struct OptionalDriver {
    controller: super::super::OptionalController,
    slots: [Option<IntervalEpoch>; SLOTS],
    current: Option<usize>,
    stream: HistoryStream,
    pub(super) policy: Policy,
    pub(super) shared: Arc<SharedOptional>,
    input: mpsc::Receiver<OptionalCompletedBatch>,
    output: mpsc::SyncSender<OptionalExport>,
    pending: Option<OptionalExport>,
    pub(super) sink: sink::Context,
    cursor: Cursor,
    history_number: u64,
    history_end: u64,
    history_binding: HistoryBinding,
    pub(super) arms: u32,
    reports: u32,
    exported: u64,
    started: bool,
    close_attempted: bool,
    close_error: Option<Error>,
    deadline_failure: Option<DeadlineFailure>,
    disabled_generation: Option<u64>,
    disabled: u32,
}
/// Queue acceptance and facade detach only. Relative clock checkpoints are not
/// OS joins, sink durability, or proof of a Fast interval between disable/rearm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptionalRunSummary {
    pub arms: u32,
    pub reports: u32,
    pub disabled: u32,
    pub actions: u64,
    pub history_batches: u64,
    pub call_batches: u64,
    pub totals: OptionalTotals,
    pub accepted_exports: u64,
    pub worker_detached: bool,
    pub stop_reason: StopReason,
    pub max_arm_lateness: Duration,
    pub stop_acknowledged: Option<Duration>,
    pub removal_completed: Option<Duration>,
    pub controller_completed: Option<Duration>,
}
impl OptionalDriver {
    pub fn deadline_failure(&self) -> Option<DeadlineFailure> {
        self.deadline_failure
    }
    pub(super) fn remember_deadline(&mut self, e: Error, f: DeadlineFailure) -> Error {
        if e == Error::Deadline && self.deadline_failure.is_none() {
            self.deadline_failure = Some(f);
        }
        e
    }
    /// Actual queue acceptances, including a delivery whose post-check failed.
    /// This does not assert that the sink wrote or durably stored the packets.
    pub fn accepted_exports(&self) -> u64 {
        self.exported
    }
    fn emit(&mut self, packet: OptionalExport) -> Result<(), Error> {
        if self.policy.sink_backpressure() {
            return self.sink.emit(
                &self.output,
                packet,
                &mut self.pending,
                &mut self.exported,
                &mut self.deadline_failure,
            );
        }
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
    pub(super) fn history(&mut self) -> Result<(), Error> {
        if let Some(batch) = self.controller.drain_history()? {
            self.pending = Some(OptionalExport::History(batch));
            let Some(OptionalExport::History(b)) = self.pending.as_ref() else {
                unreachable!()
            };
            if b.stream() != &self.stream
                || b.number() != self.history_number + 1
                || b.range().start != self.history_end
                || b.before() != self.history_binding
                || b.range().end.checked_sub(b.range().start) != Some(b.actions().len() as u64)
                || b.actions().len() > HISTORY
            {
                return Err(Error::Sequence);
            }
            self.history_number = b.number();
            self.history_end = b.range().end;
            self.history_binding = b.after();
            let packet = self.pending.take().unwrap();
            self.emit(packet)?;
        }
        Ok(())
    }
    pub(super) fn receive_one(&mut self, wait: Duration) -> Result<(), Error> {
        match self.input.recv_timeout(wait) {
            Ok(packet) => {
                self.pending = Some(OptionalExport::Calls(Box::new(packet)));
                let Some(OptionalExport::Calls(p)) = self.pending.as_ref() else {
                    unreachable!()
                };
                if p.native
                    .history_high_water()
                    .is_none_or(|end| end > self.history_end)
                {
                    return Err(Error::Sequence);
                }
                self.cursor.accept(p, &self.stream)?;
                let packet = self.pending.take().unwrap();
                self.emit(packet)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(()),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                optional_finished_ok(self.shared.finished.get().copied())
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
    pub(super) fn retire(&mut self) -> Result<(), Error> {
        for i in 0..SLOTS {
            if let Some(report) = self.take_report(i)? {
                self.emit(OptionalExport::Report(report))?;
            }
        }
        Ok(())
    }
    pub(super) fn arm(&mut self) -> Result<(), Error> {
        let i = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::EpochCapacity)?;
        self.slots[i] = Some(self.controller.stage(self.policy.config())?);
        self.controller.arm(self.slots[i].as_ref().unwrap())?;
        self.current = Some(i);
        self.disabled_generation = None;
        self.arms += 1;
        self.history()
    }
    // Historical history_window.enabled is not the physical selector or a
    // returned Fast disposition. Latch only the actual scan result for this owner.
    pub(super) fn scan(&mut self) -> Result<(), Error> {
        let Some(i) = self.current else {
            return Ok(());
        };
        let generation = self.slots[i]
            .as_ref()
            .ok_or(Error::Owner)?
            .generation()
            .get();
        if self.disabled_generation == Some(generation) {
            return Ok(());
        }
        match self.controller.scan_closed()? {
            0 => Ok(()),
            1 => {
                self.disabled_generation = Some(generation);
                self.disabled += 1;
                self.history()
            }
            _ => Err(Error::Sequence),
        }
    }
    pub(super) fn close(&mut self) -> Result<(), Error> {
        self.close_attempted = true;
        if let Some(i) = self.current {
            if let Err(e) = self.controller.disarm(self.slots[i].as_ref().unwrap()) {
                let e = Error::Bridge(e);
                self.close_error = Some(e);
                return Err(e);
            }
            self.current = None;
        }
        Ok(())
    }
    pub(super) fn finished_ready(&self) -> Result<bool, Error> {
        if let Some(status) = self.shared.finished.get().copied() {
            optional_finished_ok(Some(status))?;
            Ok(status.totals == Some(self.cursor.totals) && self.slots.iter().all(Option::is_none))
        } else {
            Ok(false)
        }
    }
    /// One-shot, original deadlines. Completion acknowledges queue acceptance,
    /// not sink durability or any actual worker/sink OS-thread join.
    pub fn run(&mut self, start: Instant) -> Result<OptionalRunSummary, Error> {
        let common = &self.shared.common;
        if self.started {
            self.sink.budget = None;
            common.controller_failed.store(true, Ordering::Release);
            return Err(Error::AlreadyStarted);
        }
        self.started = true;
        if common.start.set(start).is_err() {
            self.sink.budget = None;
            common.controller_failed.store(true, Ordering::Release);
            return Err(Error::AlreadyStarted);
        }
        let result = driver::run_optional(self, start).map(|done| OptionalRunSummary {
            arms: self.arms,
            reports: self.reports,
            disabled: self.disabled,
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
        });
        self.sink.budget = None;
        if result.is_err() {
            self.shared
                .common
                .controller_failed
                .store(true, Ordering::Release);
            self.shared.common.stop.store(true, Ordering::Release);
            if !self.close_attempted {
                let _ = self.close();
            }
        }
        result
    }
    pub fn take_pending(&mut self) -> Option<OptionalExport> {
        self.pending.take()
    }
    pub fn close_error(&self) -> Option<Error> {
        self.close_error
    }
    /// Recovery is valid only after the actual worker stops/joins; no sink credit.
    pub fn recover_worker_packet(&mut self) -> Option<OptionalCompletedBatch> {
        self.input.try_recv().ok()
    }
    pub fn recover_history(&mut self) -> Result<Option<HistoryBatch>, Error> {
        self.controller.drain_history().map_err(Into::into)
    }
    pub fn recover_report(&mut self) -> Result<Option<FinalReport>, Error> {
        for i in 0..SLOTS {
            if let Some(r) = self.take_report(i)? {
                return Ok(Some(r));
            }
        }
        Ok(None)
    }
    pub fn history_window(&self) -> Result<super::super::HistoryWindow, Error> {
        self.controller.history_window().map_err(Into::into)
    }
}
impl Drop for OptionalDriver {
    fn drop(&mut self) {
        self.shared.common.stop.store(true, Ordering::Release);
    }
}
fn balanced_optional(t: OptionalTotals) -> bool {
    balanced(t.observed) && t.bypassed.checked_add(t.observed.returns) == Some(t.physical)
}
fn optional_finished_ok(status: Option<OptionalWorkerStatus>) -> Result<(), Error> {
    match status {
        Some(s)
            if s.error.is_none()
                && s.detached
                && !s.unexported
                && s.totals.is_some_and(balanced_optional) =>
        {
            Ok(())
        }
        _ => Err(Error::Worker),
    }
}
/// Only genuine Slow rows have history association. Fast calls have no row.
/// Complete consumers still retain/replay every contiguous HistoryBatch.
pub fn optional_matches_history(
    batch: &OptionalCompletedBatch,
    row: usize,
    history: &HistoryBatch,
) -> bool {
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
#[cfg(test)]
mod sink_tests;
#[cfg(test)]
mod tests;
