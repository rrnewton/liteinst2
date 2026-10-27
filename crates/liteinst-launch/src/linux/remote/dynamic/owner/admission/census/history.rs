//! Allocation-free semantic history views. Shared handles are resolved against
//! the actual retained successor owner before a caller may filter by row kind.
use super::ordinary::shared::{
    ObservationView, ResolutionContext, SharedHistoryRecord, SharedRowView,
};
use super::*;

#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
mod snapshot;
#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
pub(in crate::linux::remote::dynamic::owner::admission) use snapshot::HistorySnapshot;
#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
pub(in crate::linux::remote::dynamic::owner::admission::census) use snapshot::retired_snapshot;

/// Public only to the admission implementation as an opaque descriptive row.
/// The actual archive/context types and constructors stay census-private.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct SharedOrdinaryRecord {
    pub(in crate::linux::remote::dynamic::owner::admission::census) row: SharedHistoryRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum ConsumptionEvidenceView<'a> {
    Owned(&'a OwnerConsumption),
    SharedOrdinary(&'a ordinary::OrdinaryEvidence),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ConsumptionView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) before: ObservationView<'a>,
    pub(in crate::linux::remote::dynamic::owner::admission) successor: ObservationView<'a>,
    pub(in crate::linux::remote::dynamic::owner::admission) evidence: ConsumptionEvidenceView<'a>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum HistoryView<'a> {
    Refreshed {
        origin: OriginId,
        before: ObservationView<'a>,
        after: ObservationView<'a>,
    },
    Consumed {
        origin: OriginId,
        evidence: ConsumptionView<'a>,
    },
    Other(&'a HistoryRecord),
}

fn shared_context(
    census: u64,
    origins: &[StoredOrigin],
    id: OriginId,
) -> Result<ResolutionContext<'_>, CensusError> {
    if id.census != census || id.serial == 0 {
        return Err(CensusError::IdentityMismatch);
    }
    let mut rows = origins.iter().filter(|row| row.row.id == id);
    let owner = rows.next().ok_or(CensusError::UnknownOrigin)?;
    if rows.next().is_some() {
        return Err(CensusError::IdentityMismatch);
    }
    let retained = owner
        .ordinary_history
        .as_ref()
        .ok_or(CensusError::InvalidConsumption)?;
    if retained.evidence.len() != 1 {
        return Err(CensusError::InvalidConsumption);
    }
    Ok(ResolutionContext::for_owner(
        census,
        &owner.row,
        &retained.evidence[0],
        &retained.archive,
    )?)
}

pub(in crate::linux::remote::dynamic::owner::admission::census) fn resolve<'a>(
    census: u64,
    origins: &'a [StoredOrigin],
    row: &'a HistoryRecord,
) -> Result<HistoryView<'a>, CensusError> {
    match row {
        HistoryRecord::Refreshed {
            origin,
            before,
            after,
        } => Ok(HistoryView::Refreshed {
            origin: *origin,
            before: ObservationView::of(before),
            after: ObservationView::of(after),
        }),
        HistoryRecord::Consumed { origin, evidence } => Ok(HistoryView::Consumed {
            origin: *origin,
            evidence: ConsumptionView {
                before: ObservationView::of(&evidence.before),
                successor: ObservationView::of(&evidence.successor),
                evidence: ConsumptionEvidenceView::Owned(evidence),
            },
        }),
        HistoryRecord::SharedOrdinary(value) => {
            let context = shared_context(census, origins, value.row.owner()?)?;
            match context.resolve_row(&value.row)? {
                SharedRowView::Refreshed {
                    origin,
                    before,
                    after,
                } => Ok(HistoryView::Refreshed {
                    origin,
                    before,
                    after,
                }),
                SharedRowView::Consumed {
                    origin,
                    before,
                    successor,
                    evidence,
                } => Ok(HistoryView::Consumed {
                    origin,
                    evidence: ConsumptionView {
                        before,
                        successor,
                        evidence: ConsumptionEvidenceView::SharedOrdinary(evidence),
                    },
                }),
            }
        }
        #[cfg(test)]
        other @ HistoryRecord::Terminal { .. } => Ok(HistoryView::Other(other)),
        other @ (HistoryRecord::RuntimeKernelTerminal { .. }
        | HistoryRecord::SignalFrameRefreshed(_)
        | HistoryRecord::SignalFrameReturned(_)
        | HistoryRecord::SignalDelivered(_)
        | HistoryRecord::Epoch { .. }) => Ok(HistoryView::Other(other)),
    }
}

impl ResumeCensus {
    pub(in crate::linux::remote::dynamic::owner::admission) fn history_view<'a>(
        &'a self,
        row: &'a HistoryRecord,
    ) -> Result<HistoryView<'a>, CensusError> {
        resolve(self.identity, &self.state.origins, row)
    }
}

/// Source-contract temporary bound for every caller's prospective operation
/// charge. It contains no allocation or payload clone. The same caller must
/// not charge this twice for sequential resolutions within one operation.
pub(in crate::linux::remote::dynamic::owner::admission) fn history_view_temporary_bytes()
-> Result<usize, CensusError> {
    use std::mem::size_of;
    let terms = [
        size_of::<ResolutionContext<'_>>(),
        size_of::<SharedRowView<'_>>(),
        size_of::<[ObservationView<'_>; 2]>(),
        size_of::<HistoryView<'_>>(),
        size_of::<ConsumptionView<'_>>(),
        size_of::<ConsumptionEvidenceView<'_>>(),
        size_of::<Result<HistoryView<'_>, CensusError>>(),
        size_of::<Result<ResolutionContext<'_>, CensusError>>(),
        size_of::<Result<SharedRowView<'_>, ordinary::shared::SharedError>>(),
        size_of::<Result<OriginId, ordinary::shared::SharedError>>(),
        size_of::<std::slice::Iter<'_, StoredOrigin>>(),
        size_of::<[&StoredOrigin; 2]>(),
        size_of::<[OriginId; 2]>(),
        size_of::<[usize; 8]>(),
        size_of::<[bool; 4]>(),
    ];
    let inner = ordinary::shared::resolution_temporary_bytes()?;
    let mut bytes = size_of::<[usize; 15]>()
        .checked_add(size_of::<std::array::IntoIter<usize, 15>>())
        .ok_or(CensusError::Capacity)?;
    bytes = bytes
        .checked_add(size_of::<(
            [usize; 3],
            Option<usize>,
            Result<usize, CensusError>,
        )>())
        .ok_or(CensusError::Capacity)?;
    for term in terms {
        bytes = bytes.checked_add(term).ok_or(CensusError::Capacity)?;
    }
    bytes = bytes.checked_add(inner).ok_or(CensusError::Capacity)?;
    // The extra nested calculator result/operand lives beside the old fold.
    bytes = bytes
        .checked_add(size_of::<(
            usize,
            Result<usize, ordinary::shared::SharedError>,
        )>())
        .ok_or(CensusError::Capacity)?;
    Ok(bytes)
}
