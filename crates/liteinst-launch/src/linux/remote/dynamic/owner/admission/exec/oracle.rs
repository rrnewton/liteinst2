//! Private same-tracer inspection points. These exist only in unit/development-control builds.
//! The checker never receives a resume, source-publication or census capability.
use super::*;
use std::os::fd::OwnedFd;

mod backing;
pub(in crate::linux::remote::dynamic::owner) use backing::{ExecBackingInspection, Probe, ProbeFd};

/// Per-owner one-shot faults; the enclosing module is test/development-only.
/// No value fabricates a successful observation or grants control authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum ExecFault {
    #[cfg(test)]
    RawGetregs(u8),
    #[cfg(test)]
    BeforeWriteStub,
    MapsRead,
    AfterMapPanic,
    MunmapUnaligned,
}

pub(in crate::linux::remote::dynamic::owner) trait ExecOracle {
    fn old_entry(&mut self, view: OldEntry<'_>);
    fn first_user(&mut self, view: FirstUser<'_>);
    fn before_retire(&mut self, view: BeforeRetire<'_>);
    fn after_retire(&mut self, view: AfterRetire<'_>);
}

pub(in crate::linux::remote::dynamic::owner) struct OldEntry<'a> {
    pub(super) event: &'a DynamicEvent,
    pub(super) pin: &'a OwnedFd,
    pub(super) until: Instant,
}
pub(in crate::linux::remote::dynamic::owner) struct FirstUser<'a> {
    pub(super) tid: i32,
    pub(super) status: i32,
    pub(super) pin: &'a OwnedFd,
    /// Historical actual EXIT token; the raw trap has no fabricated stop token.
    pub(super) exit: &'a DynamicStop,
    pub(super) until: Instant,
}
pub(in crate::linux::remote::dynamic::owner) struct BeforeRetire<'a> {
    pub(super) domain: &'a Domain,
    pub(super) census: &'a ResumeCensus,
    pub(super) island: &'a TrustedIsland,
    pub(super) bootstrap: &'a BootstrapEvidence,
    pub(super) origins: &'a BTreeMap<TaskId, OriginId>,
    pub(super) old_stop: &'a AdmissionStop,
    pub(super) initial: &'a ObservedStop,
    pub(super) request: &'a DynamicSourceRequest,
    pub(super) until: Instant,
}
pub(in crate::linux::remote::dynamic::owner) struct AfterRetire<'a> {
    pub(super) retired: &'a RetiredMm,
    pub(super) live: &'a ResumeCensus,
    pub(super) native: &'a NativeLifecycle,
    pub(super) initial: &'a ObservedStop,
    pub(super) request: &'a DynamicSourceRequest,
    pub(super) until: Instant,
}

impl Owner {
    pub(in crate::linux::remote::dynamic::owner) fn take_exec_fault(
        &self,
        fault: ExecFault,
    ) -> bool {
        if self.exec_fault.get() == Some(fault) {
            self.exec_fault.set(None);
            true
        } else {
            false
        }
    }

    fn exec_oracle_held(&self, tid: i32, status: i32, until: Instant) -> Result<(), LaunchError> {
        self.time_left(until, "private exec inspection")?;
        if self.pid != tid
            || self.owned.len() != 1
            || !self.owned.contains(&tid)
            || self.stopped.get(&tid) != Some(&status)
            || !libc::WIFSTOPPED(status)
            || self.pin_kinds.get(&tid) != Some(&PinKind::Process)
            || self.handles.get(&tid).is_none_or(broker::hup)
        {
            return Err(LaunchError::Invalid(
                "private exec inspection lost original pin/stop",
            ));
        }
        Ok(())
    }

    pub(in crate::linux::remote::dynamic::owner) fn exec_oracle_entry(
        &mut self,
        event: &DynamicEvent,
        until: Instant,
    ) -> Result<(), LaunchError> {
        if self.exec_oracle.is_none() {
            return Ok(());
        }
        let status = *self
            .stopped
            .get(&event.tid)
            .ok_or(LaunchError::Invalid("private exec ENTRY stop absent"))?;
        self.exec_oracle_held(event.tid, status, until)?;
        assert_eq!(event.stop_token().unwrap().session, self.session);
        self.exec_oracle.as_mut().unwrap().old_entry(OldEntry {
            event,
            pin: self.handles.get(&event.tid).unwrap(),
            until,
        });
        self.exec_oracle_held(event.tid, status, until)
    }

    pub(in crate::linux::remote::dynamic::owner) fn exec_oracle_first_user(
        &mut self,
        tid: i32,
        status: i32,
        exit: &DynamicStop,
        until: Instant,
    ) -> Result<(), LaunchError> {
        if self.exec_oracle.is_none() {
            return Ok(());
        }
        self.exec_oracle_held(tid, status, until)?;
        assert_eq!((exit.session, exit.tid), (self.session, tid));
        self.exec_oracle.as_mut().unwrap().first_user(FirstUser {
            tid,
            status,
            pin: self.handles.get(&tid).unwrap(),
            exit,
            until,
        });
        self.exec_oracle_held(tid, status, until)
    }
}

/// Exact private diagnostic-comparison failures. These values are never
/// interpreted by the native owner or accepted as source/census authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum InspectionField {
    Charged,
    Used,
    SourceBytes,
    SourceIdentity,
    EntryFacts,
    MappingFacts,
    PlanRoutes,
    PlanReport,
    CallObligations,
    CallHistory,
    CensusOrigins,
    CensusHistory,
    SourceRequest,
}
pub(in crate::linux::remote::dynamic::owner::admission) fn inspect<T: PartialEq + ?Sized>(
    field: InspectionField,
    expected: &T,
    actual: &T,
) -> Result<(), InspectionField> {
    if expected == actual {
        Ok(())
    } else {
        Err(field)
    }
}
pub(in crate::linux::remote::dynamic::owner::admission) fn changed_snapshot(
    original: &liteinst_admission::scan::Snapshot,
) -> liteinst_admission::scan::Snapshot {
    let mut bytes = original.bytes().to_vec();
    assert!(!bytes.is_empty());
    bytes[0] ^= 1;
    liteinst_admission::scan::Snapshot::new(
        original.mapping,
        original.generation,
        original.range().start(),
        bytes,
        original.before,
        original.after,
        original.writes,
    )
    .unwrap()
}
