//! One actual controller, existing bounded control pipes and captured-TID join.
use super::*;
use crate::oracle::native_ordinary::normal_caller::ControlChild;
use rapid_profiler::frontend::Report;
use rapid_profiler::frontend_native::{
    IntervalEpoch, IntervalEpochStorage, NormalCallPairBatch, NormalCallPairClient,
    NormalCallPairThread,
};
use std::sync::mpsc;
pub(super) struct Owner {
    controller: NormalCallPairSessionController,
    banks: Vec<IntervalEpochStorage>,
    a: IntervalEpoch,
    b: Option<IntervalEpoch>,
    b_report: Option<Report>,
}
impl Owner {
    pub(super) fn prepare(
        site: InstalledNormalCallPairSite,
        case: Case,
    ) -> (Self, NormalCallPairClient) {
        let mut prepared = PreparedNormalCallPairSessionController::new(
            site,
            native::INSTALL,
            FunctionId(native::FUNCTIONS[0]),
            FunctionId(native::FUNCTIONS[1]),
            case.k,
        )
        .unwrap();
        let mut banks = prepared.prepare_epoch_storage().unwrap();
        assert_eq!(banks.len(), 3);
        // SAFETY: pristine single child, retained process-lived code, one subject
        // caller; the helper changes only metadata and never calls the subject.
        let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
        let mut stage = || match controller.stage_prepared(banks.pop().unwrap()) {
            Ok(e) => e,
            Err((e, bank)) => {
                banks.push(bank);
                panic!("stage: {e:?}")
            }
        };
        let a = stage();
        let b = (case.scenario == Scenario::RearmB).then(&mut stage);
        controller.arm(&a).unwrap();
        (
            Self {
                controller,
                banks,
                a,
                b,
                b_report: None,
            },
            client,
        )
    }
    pub(super) fn generations(&self) -> (u64, Option<u64>) {
        (
            self.a.generation().get(),
            self.b.as_ref().map(|b| b.generation().get()),
        )
    }
    fn controls(
        mut self,
        mut control: ControlChild,
        case: Case,
        deadline: Deadline,
        tx: mpsc::SyncSender<u64>,
    ) -> Self {
        let mut fail = super::super::csv::FailStop(true);
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
        tx.send(tid).unwrap();
        for stage in 1..=2 {
            deadline.check();
            assert_eq!(control.receive(), stage);
            match (case.scenario, stage) {
                (Scenario::RearmB, 1) => self.controller.arm(self.b.as_ref().unwrap()).unwrap(),
                (Scenario::RearmB, 2) => self.controller.disarm(self.b.as_ref().unwrap()).unwrap(),
                (Scenario::RemovedChild, 1) => self.controller.disarm(&self.a).unwrap(),
                (Scenario::RemovedChild, 2) => {}
                _ => panic!("helper scenario"),
            }
            assert!(
                self.controller.report(&self.a).unwrap().is_none(),
                "root receipt still held before actual parent return"
            );
            let b_ready = if let Some(b) = &self.b {
                let report = self.controller.report(b).unwrap();
                assert_eq!(report.is_some(), stage == 2);
                self.b_report = report;
                stage == 2
            } else {
                false
            };
            let window = self.controller.history_window().unwrap();
            let (g, b) = self.generations();
            control.acknowledge(
                stage,
                crate::oracle::native_ordinary::normal_caller::ControlStatus {
                    helper_tid: tid,
                    a_generation: g,
                    b_generation: b.unwrap_or(0),
                    a_ready: false,
                    b_ready,
                    history_len: usize::try_from(window.range().end).unwrap(),
                    current: window.current().map_or(0, |g| g.get()),
                },
            );
            deadline.check();
        }
        drop(control);
        deadline.check();
        fail.0 = false;
        self
    }
    pub(super) fn finish(
        mut self,
        ready: &Ready,
        batch: &NormalCallPairBatch,
        thread: &mut NormalCallPairThread,
        deadline: Deadline,
    ) {
        if ready.case.scenario == Scenario::StableA {
            self.controller.disarm(&self.a).unwrap();
        }
        let a_report = self
            .controller
            .report(&self.a)
            .unwrap()
            .expect("closed drained A");
        let mut copies = vec![(
            a_report.generation().get(),
            a_report.records().collect::<Vec<_>>(),
        )];
        if let Some(b) = &self.b {
            let report = self
                .b_report
                .as_ref()
                .expect("B ready after actual ChildAck");
            assert_eq!(report.generation(), b.generation());
            copies.push((report.generation().get(), report.records().collect()));
        }
        let facts = batch.records().each_ref().map(check::Row::from);
        check::reports(ready, &facts, &copies);
        for row in batch.records() {
            assert_eq!(
                row.matches_report(&a_report).unwrap(),
                match row.raw().owner {
                    RawIntervalOwner::Sampled { generation, .. }
                    | RawIntervalOwner::Removed { generation } =>
                        generation == a_report.generation().get(),
                    _ => panic!("owner"),
                }
            );
            if let Some(b) = &self.b_report {
                assert_eq!(
                    row.matches_report(b).unwrap(),
                    matches!(row.raw().owner,RawIntervalOwner::Sampled{generation,..} if generation==b.generation().get())
                );
            }
        }
        let history = self
            .controller
            .drain_history()
            .unwrap()
            .expect("complete history");
        check::final_history(&self.controller, ready, batch, &history);
        assert!(self.controller.drain_history().unwrap().is_none());
        assert_eq!(thread.totals().unwrap(), check::totals(ready.case, true));
        assert!(
            unsafe { thread.checkpoint_after_returns() }
                .unwrap()
                .is_none()
        );
        assert_eq!(thread.detach().unwrap(), check::totals(ready.case, true));
        drop(a_report);
        drop(self.b_report.take());
        let mut reclaim = |epoch| match self.controller.reclaim_storage(epoch) {
            Ok(bank) => self.banks.push(bank),
            Err((_error, _token)) => std::process::abort(),
        };
        reclaim(self.a);
        if let Some(b) = self.b {
            reclaim(b);
        }
        assert_eq!(self.banks.len(), 3);
        deadline.check();
    }
}
pub(super) enum Controller {
    Here(Owner),
    Helper {
        handle: crate::joined_task::Handle<Owner>,
        tid: u64,
    },
}
impl Controller {
    pub(super) fn start(
        owner: Owner,
        control: Option<ControlChild>,
        case: Case,
        deadline: Deadline,
    ) -> (Self, Option<u64>) {
        if let Some(control) = control {
            assert!(case.scenario.helper());
            let (tx, rx) = mpsc::sync_channel(1);
            let handle =
                crate::joined_task::spawn(move || owner.controls(control, case, deadline, tx));
            let tid = loop {
                deadline.check();
                match rx.try_recv() {
                    Ok(tid) => break tid,
                    Err(mpsc::TryRecvError::Empty) => std::thread::yield_now(),
                    Err(e) => panic!("helper startup: {e:?}"),
                }
            };
            assert!(tid != 0 && tid != u64::from(std::process::id()));
            (Self::Helper { handle, tid }, Some(tid))
        } else {
            assert_eq!(case.scenario, Scenario::StableA);
            (Self::Here(owner), None)
        }
    }
    pub(super) fn join(self, deadline: Deadline) -> Owner {
        match self {
            Self::Here(owner) => owner,
            Self::Helper { handle, tid } => {
                while !handle.is_finished() {
                    deadline.check();
                    std::thread::yield_now();
                }
                let mut joined = handle.join();
                assert_eq!(u64::from(joined.tid()), tid);
                joined.wait_until(native::absolute_end(deadline)).unwrap();
                let owner = joined.into_result().unwrap();
                deadline.check();
                crate::single_main();
                owner
            }
        }
    }
}
