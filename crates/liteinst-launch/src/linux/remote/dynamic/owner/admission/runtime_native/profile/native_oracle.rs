//! Opaque complete profile copies. Original producers and proof fields stay private.
use super::*;
use crate::linux::remote::dynamic::owner::lifecycle::CetRetainedSnapshot;
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ProfileSnapshot {
    debug_values: [u64; 6],
    debug_requests: [Option<Request>; 6],
    rseq: [u8; 24],
    rseq_request: Option<Request>,
    cet: CetRetainedSnapshot,
    complete: bool,
    tid: Option<i32>,
}
impl ControlProfile {
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_retained_snapshot(
        &self,
    ) -> ProfileSnapshot {
        ProfileSnapshot {
            debug_values: self.debug.values,
            debug_requests: self.debug.requests,
            rseq: self.rseq,
            rseq_request: self.rseq_request,
            cet: self.cet.test_retained_snapshot(),
            complete: self.complete,
            tid: self.tid,
        }
    }
}

impl ProfileSnapshot {
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_empty(&self) {
        assert_eq!(self.debug_values, [0; 6]);
        assert_eq!(self.debug_requests, [None; 6]);
        assert_eq!(self.rseq, [0; 24]);
        assert_eq!(self.rseq_request, None);
        self.cet.require_empty();
        assert!(!self.complete);
        assert_eq!(self.tid, None);
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ControlLineageSnapshot {
    checkpoint: AdmissionStop,
    dr6: u64,
    kernel: Option<(KernelAttemptId, AdmissionStop, u64)>,
}
impl ControlLineage {
    pub(in crate::linux::remote::dynamic::owner::admission) fn test_retained_snapshot(
        &self,
    ) -> ControlLineageSnapshot {
        ControlLineageSnapshot {
            checkpoint: self.checkpoint.clone(),
            dr6: self.dr6,
            kernel: self
                .kernel
                .as_ref()
                .map(|v| (v.attempt, v.returned.clone(), v.number)),
        }
    }
}
