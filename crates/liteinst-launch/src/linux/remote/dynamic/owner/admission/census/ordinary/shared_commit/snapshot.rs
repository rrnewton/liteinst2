use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedSnapshot {
    address: usize,
    binding: Option<Binding>,
    history: shared::PreparedSnapshot,
    origins: [Vec<u8>; 2],
    identities: [(usize, usize, usize); 2],
    copies: [CopyProgress; 2],
    evidence: Option<Box<[OrdinaryEvidence]>>,
    evidence_identity: Option<(usize, usize)>,
    stage: Stage,
    allocation_ordinal: Option<usize>,
    installed_bytes: usize,
    preparation_debit: Option<usize>,
    first_failure: Option<CensusError>,
    unwound: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct OrdinaryPreparationHistorySnapshot {
    started: bool,
    first_failure: Option<CensusError>,
    unwound: bool,
    settlement: Option<Result<usize, CensusError>>,
    prepared: Option<PreparedSnapshot>,
}

impl SharedOrdinaryPreparation {
    /// Read-only ownership presence for refusal controls, including a partial
    /// preparation. Presence does not establish readiness or release authority.
    pub(in crate::linux::remote::dynamic::owner::admission) fn has_prepared_owner(&self) -> bool {
        self.prepared.is_some()
    }

    /// Captures actual original owner/Vec identities separately from full
    /// copied data, including incomplete allocation/copy prefixes after error.
    pub(in crate::linux::remote::dynamic::owner::admission) fn history_snapshot(
        &self,
    ) -> Result<OrdinaryPreparationHistorySnapshot, CensusError> {
        let prepared = self
            .prepared
            .as_ref()
            .map(|value| -> Result<PreparedSnapshot, CensusError> {
                value.allocated_bytes()?;
                Ok(PreparedSnapshot {
                    address: &**value as *const PreparedSharedOrdinaryCensus as usize,
                    binding: value.binding,
                    history: value.history.test_snapshot(),
                    origins: value.origins.clone(),
                    identities: std::array::from_fn(|i| {
                        (
                            value.origins[i].as_ptr() as usize,
                            value.origins[i].len(),
                            value.origins[i].capacity(),
                        )
                    }),
                    copies: value.copies,
                    evidence: value.evidence.clone(),
                    evidence_identity: value
                        .evidence
                        .as_ref()
                        .map(|v| (v.as_ptr() as usize, v.len())),
                    stage: value.stage,
                    allocation_ordinal: value.allocation_ordinal,
                    installed_bytes: value.installed_bytes,
                    preparation_debit: value.preparation_debit,
                    first_failure: value.first_failure,
                    unwound: value.unwound,
                })
            })
            .transpose()?;
        Ok(OrdinaryPreparationHistorySnapshot {
            started: self.started,
            first_failure: self.first_failure,
            unwound: self.unwound,
            settlement: self.settlement,
            prepared,
        })
    }
}
