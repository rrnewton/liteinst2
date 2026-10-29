//! Shared fixed E3 epoch transaction; exactly Single and Module controller adapters.
use super::*;
use rapid_profiler::frontend::Action;
use rapid_profiler::frontend_native::{
    BridgeError, EpochStorageReclaimError, NormalModuleHistoryBatch, NormalModuleSessionController,
};
use std::ops::Range;

mod sealed {
    pub trait Controller {}
    impl Controller for rapid_profiler::frontend_native::IntervalController {}
    impl Controller for rapid_profiler::frontend_native::NormalModuleSessionController {}
    pub trait History {}
    impl History for rapid_profiler::frontend_native::HistoryBatch {}
    impl History for rapid_profiler::frontend_native::NormalModuleHistoryBatch {}
}
pub(in crate::normal) trait History: sealed::History {
    fn number(&self) -> u64;
    fn range(&self) -> Range<u64>;
    fn before(&self) -> HistoryBinding;
    fn actions(&self) -> &[Action];
    fn follows(&self, previous: &Self) -> bool;
}
impl History for HistoryBatch {
    fn number(&self) -> u64 {
        HistoryBatch::number(self)
    }
    fn range(&self) -> Range<u64> {
        HistoryBatch::range(self)
    }
    fn before(&self) -> HistoryBinding {
        HistoryBatch::before(self)
    }
    fn actions(&self) -> &[Action] {
        HistoryBatch::actions(self)
    }
    fn follows(&self, previous: &Self) -> bool {
        HistoryBatch::follows(self, previous)
    }
}
impl History for NormalModuleHistoryBatch {
    fn number(&self) -> u64 {
        NormalModuleHistoryBatch::number(self)
    }
    fn range(&self) -> Range<u64> {
        NormalModuleHistoryBatch::range(self)
    }
    fn before(&self) -> HistoryBinding {
        NormalModuleHistoryBatch::before(self)
    }
    fn actions(&self) -> &[Action] {
        NormalModuleHistoryBatch::actions(self)
    }
    fn follows(&self, previous: &Self) -> bool {
        NormalModuleHistoryBatch::follows(self, previous)
    }
}
pub(in crate::normal) trait Controller: sealed::Controller {
    type History: History;
    fn drain_history(&mut self) -> Result<Option<Self::History>, BridgeError>;
    fn report(&self, epoch: &IntervalEpoch) -> Result<Option<Report>, BridgeError>;
    fn reclaim_storage(
        &mut self,
        epoch: IntervalEpoch,
    ) -> Result<IntervalEpochStorage, (EpochStorageReclaimError, IntervalEpoch)>;
    #[allow(clippy::result_large_err)]
    // Preserve the same bank inline on refusal; no boxed error allocation.
    fn stage_prepared(
        &mut self,
        bank: IntervalEpochStorage,
    ) -> Result<IntervalEpoch, (BridgeError, IntervalEpochStorage)>;
    fn arm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError>;
    fn disarm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError>;
    fn check_report(&self, generation: u64, rows: &[RecordObservation], capacity: usize);
    fn final_check(&self, history: &[Self::History]) -> Result<(), String>;
}
impl Controller for IntervalController {
    type History = HistoryBatch;
    fn drain_history(&mut self) -> Result<Option<Self::History>, BridgeError> {
        IntervalController::drain_history(self)
    }
    fn report(&self, epoch: &IntervalEpoch) -> Result<Option<Report>, BridgeError> {
        IntervalController::report(self, epoch)
    }
    fn reclaim_storage(
        &mut self,
        epoch: IntervalEpoch,
    ) -> Result<IntervalEpochStorage, (EpochStorageReclaimError, IntervalEpoch)> {
        IntervalController::reclaim_storage(self, epoch)
    }
    #[allow(clippy::result_large_err)]
    // Preserve the same bank inline on refusal; no boxed error allocation.
    fn stage_prepared(
        &mut self,
        bank: IntervalEpochStorage,
    ) -> Result<IntervalEpoch, (BridgeError, IntervalEpochStorage)> {
        IntervalController::stage_prepared(self, bank)
    }
    fn arm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        IntervalController::arm(self, epoch)
    }
    fn disarm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        IntervalController::disarm(self, epoch)
    }
    fn check_report(&self, _generation: u64, _rows: &[RecordObservation], _capacity: usize) {}
    fn final_check(&self, _history: &[Self::History]) -> Result<(), String> {
        Ok(())
    }
}
impl Controller for NormalModuleSessionController {
    type History = NormalModuleHistoryBatch;
    fn drain_history(&mut self) -> Result<Option<Self::History>, BridgeError> {
        NormalModuleSessionController::drain_history(self)
    }
    fn report(&self, epoch: &IntervalEpoch) -> Result<Option<Report>, BridgeError> {
        NormalModuleSessionController::report(self, epoch)
    }
    fn reclaim_storage(
        &mut self,
        epoch: IntervalEpoch,
    ) -> Result<IntervalEpochStorage, (EpochStorageReclaimError, IntervalEpoch)> {
        NormalModuleSessionController::reclaim_storage(self, epoch)
    }
    #[allow(clippy::result_large_err)]
    // Preserve the same bank inline on refusal; no boxed error allocation.
    fn stage_prepared(
        &mut self,
        bank: IntervalEpochStorage,
    ) -> Result<IntervalEpoch, (BridgeError, IntervalEpochStorage)> {
        NormalModuleSessionController::stage_prepared(self, bank)
    }
    fn arm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        NormalModuleSessionController::arm(self, epoch)
    }
    fn disarm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        NormalModuleSessionController::disarm(self, epoch)
    }
    fn check_report(&self, generation: u64, rows: &[RecordObservation], capacity: usize) {
        crate::normal::module::session::check::report_shape(generation, rows, capacity);
    }
    fn final_check(&self, history: &[Self::History]) -> Result<(), String> {
        let w = self.history_window().map_err(failure)?;
        let last = history.last().expect("complete arm/remove history");
        assert_eq!(w.stream(), last.stream());
        assert_eq!(
            w.status(),
            rapid_profiler::frontend::ControllerStatus::Ready
        );
        assert_eq!(w.current(), None);
        assert_eq!(w.enabled(), &[true]);
        assert_eq!(w.retained_failed_generation(), None);
        assert_eq!(w.last_batch_number(), last.number());
        assert_eq!(w.range().end, last.range().end);
        assert_eq!(w.after(), last.after());
        assert_eq!(
            w.before(),
            history
                .iter()
                .rev()
                .find_map(|h| h.binding_at(w.range().start))
                .unwrap()
        );
        assert_eq!(w.range().end - w.range().start, w.actions().len() as u64);
        for (i, action) in w.actions().iter().enumerate() {
            let index = w.range().start + i as u64;
            let expected = history
                .iter()
                .find_map(|h| {
                    h.range()
                        .contains(&index)
                        .then(|| &h.actions()[(index - h.range().start) as usize])
                })
                .unwrap();
            assert_eq!(action, expected);
        }
        Ok(())
    }
}

pub(in crate::normal) struct Engine<C: Controller = IntervalController> {
    pub(in crate::normal) controller: C,
    pub(in crate::normal) epochs: [Option<Slot<IntervalEpoch>>; 3],
    pub(in crate::normal) banks: Vec<IntervalEpochStorage>,
    pub(in crate::normal) current: Option<usize>,
    pub(in crate::normal) history: Vec<C::History>,
    pub(in crate::normal) reports: Vec<(u64, Vec<RecordObservation>)>,
    pub(in crate::normal) k: usize,
    pub(in crate::normal) committed_arms: u32,
}
impl<C: Controller> Engine<C> {
    pub(in crate::normal) fn final_check(&self) -> Result<(), String> {
        self.controller.final_check(&self.history)
    }
    pub(in crate::normal) fn history(&mut self, io: &mut Io) -> Result<(), String> {
        if let Some(chunk) = self.controller.drain_history().map_err(failure)? {
            if let Some(previous) = self.history.last() {
                assert!(chunk.follows(previous));
            } else {
                assert_eq!(chunk.number(), 1);
                assert_eq!(chunk.range().start, 0);
                assert_eq!(chunk.before(), HistoryBinding::Initial);
            }
            assert_eq!(
                chunk.range().end - chunk.range().start,
                chunk.actions().len() as u64
            );
            // Retain the actual transfer before any output operation may refuse.
            self.history.push(chunk);
            let h = self.history.last().unwrap();
            for (i, action) in h.actions().iter().enumerate() {
                assert_eq!(action.function, None);
                assert_eq!(action.group, None);
                let kind = match action.kind {
                    rapid_profiler::frontend::ActionKind::Published => {
                        assert_eq!(action.current, Some(action.generation));
                        "published"
                    }
                    rapid_profiler::frontend::ActionKind::Removed => {
                        assert_eq!(action.current, None);
                        "removed"
                    }
                    _ => panic!("unexpected mandatory session action"),
                };
                io.emit(format!(
                    "HISTORY,{},{},{kind},{}\n",
                    h.number(),
                    h.range().start + i as u64 + 1,
                    action.generation.get()
                ))?;
            }
        }
        Ok(())
    }
    pub(in crate::normal) fn retire(&mut self, io: &mut Io) -> Result<(), String> {
        for i in 0..3 {
            if self.current == Some(i) {
                continue;
            }
            let Some(slot) = self.epochs[i].as_mut() else {
                continue;
            };
            if slot.report_index().is_none() {
                let Some(report) = self.controller.report(slot.epoch()).map_err(failure)? else {
                    continue;
                };
                let generation = report.generation().get();
                let records: Vec<_> = report.records().collect();
                assert!(records.len() <= self.k);
                self.controller.check_report(generation, &records, self.k);
                let n = records.len();
                let index = self.reports.len();
                self.reports.push((generation, records));
                slot.copied(generation, index, format!("REPORT,{generation},{n}\n"));
                drop(report);
            }
            let index = slot.report_index().unwrap();
            assert_eq!(self.reports[index].0, slot.epoch().generation().get());
            slot.emit(|line| io.emit(line))?;
            if let Some(bank) = slot
                .reclaim(|epoch| self.controller.reclaim_storage(epoch))
                .map_err(failure)?
            {
                self.banks.push(bank); // At most the original E prepared banks.
                self.epochs[i] = None;
            }
        }
        Ok(())
    }
    pub(in crate::normal) fn arm(&mut self, io: &mut Io) -> Result<(), String> {
        self.retire(io)?;
        let i = self
            .epochs
            .iter()
            .position(Option::is_none)
            .ok_or("retained epoch capacity")?;
        let mut bank = Some(self.banks.pop().ok_or("retained epoch capacity")?);
        #[allow(clippy::result_large_err)]
        // Keep the returned bank inline until custody is restored.
        let epoch =
            match epoch_storage::transfer(&mut bank, |bank| self.controller.stage_prepared(bank)) {
                Ok(epoch) => epoch,
                Err(error) => {
                    self.banks.push(bank.take().unwrap());
                    return Err(failure(error));
                }
            };
        // Retain the staged token before the fallible publication, including
        // its failure path. Only a successful arm changes current/counts.
        self.epochs[i] = Some(Slot::new(epoch));
        self.controller
            .arm(self.epochs[i].as_ref().unwrap().epoch())
            .map_err(failure)?;
        self.committed_arms += 1; // Publication remains real if history later fails.
        self.current = Some(i);
        self.history(io)
    }
    pub(in crate::normal) fn stop(&mut self, io: &mut Io) -> Result<(), String> {
        if let Some(i) = self.current {
            self.controller
                .disarm(self.epochs[i].as_ref().unwrap().epoch())
                .map_err(failure)?;
            self.current = None;
        }
        self.history(io)
    }
}
