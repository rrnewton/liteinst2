//! Owning full-byte diagnostic snapshots for existing test/dev-exec controls.
use super::*;

fn owned(view: ObservationView<'_>) -> ObservedStop {
    ObservedStop {
        token: view.token.clone(),
        task: view.task,
        logical_pc: view.logical_pc,
        registers: *view.registers,
        xstate: view.xstate.to_vec(),
        signal_mask: view.signal_mask,
        phase: view.phase,
        signal: view.signal.cloned(),
    }
}
/// Deep full-byte test copy plus actual physical allocation identities. This
/// grants no native capability. Default library builds without the diagnostic
/// feature retain the non-Clone archive contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct ArchiveSnapshot {
    pub(in crate::linux::remote::dynamic::owner::admission::census) address: usize,
    pub(in crate::linux::remote::dynamic::owner::admission::census) binding: BindingView,
    pub(in crate::linux::remote::dynamic::owner::admission::census) owner: OriginId,
    pub(in crate::linux::remote::dynamic::owner::admission::census) trace: Option<NativeTrace>,
    pub(in crate::linux::remote::dynamic::owner::admission::census) prior: Progress,
    pub(in crate::linux::remote::dynamic::owner::admission::census) native: Progress,
    pub(in crate::linux::remote::dynamic::owner::admission::census) roles: [CaptureRole; PAYLOADS],
    pub(in crate::linux::remote::dynamic::owner::admission::census) identities:
        [PayloadIdentity; PAYLOADS],
    pub(in crate::linux::remote::dynamic::owner::admission::census) progress: [Progress; PAYLOADS],
    pub(in crate::linux::remote::dynamic::owner::admission::census) bytes: [Vec<u8>; PAYLOADS],
    pub(in crate::linux::remote::dynamic::owner::admission::census) headers:
        [Option<ObservedStop>; ENDPOINTS],
    pub(in crate::linux::remote::dynamic::owner::admission::census) references:
        [Option<SharedObservationRef>; ENDPOINTS],
}
impl ArchiveSnapshot {
    fn of(view: ArchivePartialView<'_>) -> Self {
        Self {
            address: view.address,
            binding: view.binding,
            owner: view.owner,
            trace: view.trace,
            prior: view.prior,
            native: view.native,
            roles: std::array::from_fn(|i| view.payloads[i].role),
            identities: std::array::from_fn(|i| view.payloads[i].identity),
            progress: std::array::from_fn(|i| view.payloads[i].progress),
            bytes: std::array::from_fn(|i| view.payloads[i].bytes.to_vec()),
            headers: std::array::from_fn(|i| view.headers[i].map(owned)),
            references: view.references,
        }
    }
}
impl OrdinaryHistoryPayloads {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn test_snapshot(
        &self,
    ) -> ArchiveSnapshot {
        ArchiveSnapshot::of(self.partial_view())
    }
}
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct PreparedSnapshot {
    allocation: Progress,
    installed_bytes: usize,
    transferred: bool,
    archive: Option<ArchiveSnapshot>,
}
#[cfg(test)]
impl PreparedOrdinaryHistory {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn test_snapshot(
        &self,
    ) -> PreparedSnapshot {
        let view = self.partial_view();
        PreparedSnapshot {
            allocation: view.allocation,
            installed_bytes: view.installed_bytes,
            transferred: view.transferred,
            archive: view.archive.map(ArchiveSnapshot::of),
        }
    }
}
