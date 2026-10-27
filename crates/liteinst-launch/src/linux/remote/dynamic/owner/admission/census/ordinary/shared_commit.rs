//! Installed preparation for the five-payload ordinary census route.
//! The archive is descriptive storage. Only the consuming real-seal adapter
//! below can publish it, after every original ordinary predicate succeeds.
use super::shared::{OrdinaryHistoryPayloads, PreparedOrdinaryHistory, SharedHistoryRecord};
use super::*;
use crate::linux::remote::dynamic::owner::admission::exact_storage;

mod allocation;
mod commit;
#[cfg(test)]
mod snapshot;
#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner::admission) use snapshot::OrdinaryPreparationHistorySnapshot;
#[cfg(test)]
mod tests;

#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(any(test, feature = "dev-exec-backing-cleanup"), derive(Clone))]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct SharedOrdinaryOwner {
    pub(in crate::linux::remote::dynamic::owner::admission::census) archive:
        Box<OrdinaryHistoryPayloads>,
    pub(in crate::linux::remote::dynamic::owner::admission::census) evidence:
        Box<[OrdinaryEvidence]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Empty,
    Allocating,
    Ready,
    Copying,
    Copied,
    Committed,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CopyProgress {
    started: bool,
    complete: bool,
    copied: usize,
    requested: usize,
}

/// Installed before the archive or any of the five payloads is allocated.
/// The Prior header and bytes live only in `history`; there is no sixth Vec.
pub(in crate::linux::remote::dynamic::owner::admission) struct PreparedSharedOrdinaryCensus {
    binding: Option<Binding>,
    history: PreparedOrdinaryHistory,
    origins: [Vec<u8>; 2],
    copies: [CopyProgress; 2],
    evidence: Option<Box<[OrdinaryEvidence]>>,
    stage: Stage,
    allocation_ordinal: Option<usize>,
    installed_bytes: usize,
    preparation_debit: Option<usize>,
    first_failure: Option<CensusError>,
    unwound: bool,
    #[cfg(test)]
    fault: AllocationFault,
    #[cfg(test)]
    copy_fault: Option<(usize, usize)>,
}

/// This allocation-free header is embedded in the retained runtime attempt.
/// It exists even when allocating the boxed preparation itself fails/unwinds.
pub(in crate::linux::remote::dynamic::owner::admission) struct SharedOrdinaryPreparation {
    prepared: Option<Box<PreparedSharedOrdinaryCensus>>,
    started: bool,
    first_failure: Option<CensusError>,
    unwound: bool,
    settlement: Option<Result<usize, CensusError>>,
    #[cfg(test)]
    fault: AllocationFault,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
struct AllocationFault {
    before: Option<usize>,
    after: Option<usize>,
}

fn allocation_error(value: exact_storage::AllocationError) -> CensusError {
    match value {
        exact_storage::AllocationError::Capacity => CensusError::Capacity,
        exact_storage::AllocationError::Allocation => CensusError::Allocation,
    }
}

fn shared_fixed_commit_bytes() -> Result<usize, CensusError> {
    // Fourteen observation headers already belong to the archive Box. Two
    // independent observation headers belong to the new StoredOrigin. Charge
    // the seven actual history slots and the actual successor slot once.
    add(
        mul(WITNESSES, size_of::<HistoryRecord>())?,
        size_of::<StoredOrigin>(),
    )
}

fn shared_preparation_bytes() -> Result<usize, CensusError> {
    let archive = PreparedOrdinaryHistory::reservation_bytes()?;
    let header = size_of::<PreparedSharedOrdinaryCensus>()
        .checked_sub(size_of::<PreparedOrdinaryHistory>())
        .ok_or(CensusError::Capacity)?;
    add(
        add(header, archive)?,
        add(mul(2, MAX_XSTATE_BYTES)?, size_of::<OrdinaryEvidence>())?,
    )
}

/// Concrete bounded temporary ownership, separate from measured retained
/// capacity. Payload transfer is never a refund. The embedded pending header
/// is owned/charged by RuntimeOrdinaryAttempt, not charged a second time here.
fn shared_temporary_bytes() -> Result<usize, CensusError> {
    let terms = [
        super::shared::shared_temporary_bytes()?,
        super::super::history_view_temporary_bytes()?,
        size_of::<PreparedSharedOrdinaryCensus>(), // empty constructor result
        size_of::<PreparedSharedOrdinaryCensus>(), // exact_storage::value argument
        size_of::<SharedOrdinaryOwner>(),
        size_of::<Binding>(),
        size_of::<SharedRequest>(),
        size_of::<CompletionModel<'_>>(),
        size_of::<OwnedInstructionCompletion<'_>>(),
        size_of::<[SharedHistoryRecord; WITNESSES]>(),
        size_of::<StoredOrigin>(),
        size_of::<[ObservedStop; 2]>(),
        size_of::<OrdinaryEvidence>(),
        size_of::<CommitPlan>(),
        size_of::<[BudgetCharge; 4]>(),
        size_of::<[Reservation; 2]>(),
        size_of::<[Option<CensusError>; 4]>(),
        size_of::<[Result<usize, CensusError>; 4]>(),
        size_of::<Result<Box<PreparedSharedOrdinaryCensus>, exact_storage::AllocationError>>(),
        size_of::<Result<Box<[OrdinaryEvidence]>, exact_storage::AllocationError>>(),
        size_of::<Result<Vec<u8>, exact_storage::AllocationError>>(),
        size_of::<Result<Result<(), CensusError>, Box<dyn std::any::Any + Send>>>(),
        size_of::<[usize; 12]>(),
        size_of::<[bool; 8]>(),
        size_of::<std::slice::Chunks<'_, u8>>(),
        size_of::<std::slice::Iter<'_, Vec<u8>>>(),
        size_of::<std::ops::Range<usize>>(),
    ];
    let mut bytes = add(
        std::mem::size_of_val(&terms),
        size_of::<std::array::IntoIter<usize, 27>>(),
    )?;
    bytes = add(
        bytes,
        size_of::<([usize; 4], Option<usize>, Result<usize, CensusError>)>(),
    )?;
    // The existing term above already includes the complete history resolver.
    // Prepare and commit call lineage sequentially within this reservation.
    bytes = add(
        bytes,
        super::super::runtime_kernel::lineage_caller_temporary_bytes()?,
    )?;
    for term in terms {
        bytes = add(bytes, term)?;
    }
    Ok(bytes)
}

/// Select this shape before reserve. The old sixteen-payload model charge is
/// unchanged and is never reserved and then reduced/refunded by this route.
pub(in crate::linux::remote::dynamic::owner::admission) fn ordinary_shared_census_charge()
-> Result<BudgetCharge, CensusError> {
    Ok(BudgetCharge {
        origins: 1,
        witnesses: WITNESSES,
        source_fact_bytes: add(
            add(shared_preparation_bytes()?, shared_fixed_commit_bytes()?)?,
            shared_temporary_bytes()?,
        )?,
        ..BudgetCharge::default()
    })
}

#[derive(Clone, Copy)]
struct SharedRequest {
    origin: OriginId,
    execution: ExecutionId,
    source: SourceRecord,
    encoding: Encoding,
    until: Instant,
}

#[derive(Clone, Copy)]
struct CommitPlan {
    old: usize,
    next: u64,
    remaining: BudgetCharge,
    used: BudgetCharge,
}

impl PreparedSharedOrdinaryCensus {
    fn empty() -> Self {
        Self {
            binding: None,
            history: PreparedOrdinaryHistory::empty(),
            origins: [Vec::new(), Vec::new()],
            copies: [CopyProgress::default(); 2],
            evidence: None,
            stage: Stage::Empty,
            allocation_ordinal: None,
            installed_bytes: 0,
            preparation_debit: None,
            first_failure: None,
            unwound: false,
            #[cfg(test)]
            fault: AllocationFault::default(),
            #[cfg(test)]
            copy_fault: None,
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocated_bytes(
        &self,
    ) -> Result<usize, CensusError> {
        let history = self
            .history
            .allocated_bytes()?
            .checked_sub(size_of::<PreparedOrdinaryHistory>())
            .ok_or(CensusError::Capacity)?;
        let evidence = self
            .evidence
            .as_ref()
            .map_or(0, |v| v.len() * size_of::<OrdinaryEvidence>());
        let origins = self
            .origins
            .iter()
            .try_fold(0, |sum, v| add(sum, v.capacity()))?;
        add(size_of::<Self>(), add(history, add(evidence, origins)?)?)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn remaining_charge(
        &self,
    ) -> Result<BudgetCharge, CensusError> {
        if !matches!(self.stage, Stage::Ready | Stage::Copying | Stage::Copied)
            || self.first_failure.is_some()
            || self.unwound
        {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(BudgetCharge {
            origins: 1,
            witnesses: WITNESSES,
            source_fact_bytes: shared_fixed_commit_bytes()?,
            ..BudgetCharge::default()
        })
    }
    fn fail(&mut self, error: CensusError) {
        self.first_failure.get_or_insert(error);
    }
    fn mark_aborted(&mut self) {
        if self.stage == Stage::Committed {
            return;
        }
        self.unwound = true;
        self.history.mark_aborted();
    }
}
