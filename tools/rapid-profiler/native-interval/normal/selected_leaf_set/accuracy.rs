//! Separate accuracy attachment for the unchanged copied-caller state oracle.
//! Counter availability/values are not state-oracle accuracy verdicts.
use super::*;
use rapid_profiler::counter_reading::CounterRecord;
use rapid_profiler::frontend_native::{
    BridgeError, NormalAccuracyRecord, NormalCounterAcquisition, NormalCounterClose,
    NormalCounterIdentity, NormalCounterRead, NormalLeafSetAccuracyThread, NormalLeafSetBatch,
    NormalLeafSetClient, NormalLeafSetThread,
};

pub(super) enum Attachment {
    Ordinary(NormalLeafSetThread),
    Accuracy(NormalLeafSetAccuracyThread, Box<NormalCounterAcquisition>),
}
pub(super) struct Batch {
    normal: NormalLeafSetBatch,
    // Keep every copied sidecar until the normal batch has completed all checks.
    sidecars: Option<(Vec<NormalAccuracyRecord>, NormalCounterAcquisition)>,
}
impl Batch {
    pub(super) fn normal(&self) -> &NormalLeafSetBatch {
        &self.normal
    }
    pub(super) fn check(&self, accuracy: bool) {
        assert_eq!(self.sidecars.is_some(), accuracy);
        if let Some((rows, acquisition)) = &self.sidecars {
            assert_eq!(rows.len(), self.normal.records().len());
            assert_eq!(
                acquisition.owner,
                NormalCounterIdentity {
                    pid: self.normal.pid(),
                    tid: self.normal.tid(),
                }
            );
            for (row, normal) in rows.iter().zip(self.normal.records()) {
                assert_eq!(row.function(), normal.function);
                assert_eq!(row.ordinal(), normal.record.raw.ordinal);
                assert_eq!(row.normal(), normal.record);
                for endpoint in [row.start(), row.end()] {
                    assert_eq!(endpoint.observer, acquisition.owner);
                    assert!(endpoint.owner_matches);
                    assert_eq!(
                        endpoint.event_id_matches,
                        acquisition
                            .event_id()
                            .zip(endpoint.read.and_then(NormalCounterRead::event_id))
                            .map(|(opened, observed)| opened == observed)
                    );
                }
                assert_eq!(
                    row.counters(),
                    CounterRecord::new(
                        row.start().read.and_then(NormalCounterRead::reading),
                        row.end().read.and_then(NormalCounterRead::reading),
                    )
                );
            }
        }
    }
}
impl Attachment {
    /// # Safety
    /// The same actual-thread, immutable source/input/stack and ordinary return
    /// contracts as the enclosing child. Accuracy additionally retains its
    /// admitted AMD clock and actual-thread TSC access until empty detach.
    pub(super) unsafe fn attach(
        client: &NormalLeafSetClient,
        stack: ReadableStack,
        journal: IntervalJournal,
        accuracy: bool,
    ) -> Self {
        if accuracy {
            // SAFETY: inherited from this helper's explicit caller contract.
            let thread = unsafe { client.attach_accuracy(1, stack, journal) }.unwrap();
            let acquisition = thread.acquisition().unwrap();
            Self::Accuracy(thread, Box::new(acquisition))
        } else {
            // SAFETY: unchanged ordinary attachment contract.
            Self::Ordinary(unsafe { client.attach(1, stack, journal) }.unwrap())
        }
    }
    pub(super) fn totals(&self) -> Result<NormalTotals, BridgeError> {
        match self {
            Self::Ordinary(thread) => thread.totals(),
            Self::Accuracy(thread, _) => thread.totals(),
        }
    }
    /// # Safety
    /// The enclosing child has checked actual CALL/RET, caller/input/source and
    /// full stack custody before invoking the unchanged unsafe checkpoint.
    pub(super) unsafe fn checkpoint_after_returns(&mut self) -> Option<Batch> {
        match self {
            Self::Ordinary(thread) => {
                unsafe { thread.checkpoint_after_returns() }
                    .unwrap()
                    .map(|normal| Batch {
                        normal,
                        sidecars: None,
                    })
            }
            Self::Accuracy(thread, expected) => {
                assert_eq!(thread.acquisition().unwrap(), **expected);
                unsafe { thread.checkpoint_after_returns() }
                    .unwrap()
                    .map(|batch| {
                        let (normal, rows, acquisition) = batch.into_parts();
                        assert_eq!(acquisition, **expected);
                        Batch {
                            normal,
                            sidecars: Some((rows, acquisition)),
                        }
                    })
            }
        }
    }
    pub(super) fn detach(&mut self) -> (NormalTotals, Option<NormalCounterClose>) {
        match self {
            Self::Ordinary(thread) => (thread.detach().unwrap(), None),
            Self::Accuracy(thread, acquisition) => {
                let result = thread.detach().unwrap();
                assert_eq!(result.counter.acquisition, **acquisition);
                assert_eq!(result.counter.observer, acquisition.owner);
                (result.totals, Some(result.counter))
            }
        }
    }
}
