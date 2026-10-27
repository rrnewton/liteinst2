//! Diagnostic copies only. A snapshot owns full bytes as well as the original
//! allocation identities; cloning a history handle is never retention proof.
use super::super::ordinary::shared::ArchiveSnapshot;
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArchiveOwnerSnapshot {
    id: OriginId,
    initial: OriginRow,
    initial_allocation: (usize, usize, usize),
    evidence_pointer: usize,
    evidence_length: usize,
    evidence: Vec<ordinary::OrdinaryEvidence>,
    archive: ArchiveSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct HistorySnapshot {
    rows: Vec<HistoryRecord>,
    owners: Vec<Option<OriginId>>,
    archives: Vec<ArchiveOwnerSnapshot>,
}

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

fn snapshot(
    census: u64,
    origins: &[StoredOrigin],
    history: &[HistoryRecord],
    end: usize,
    all_archives: bool,
) -> Result<HistorySnapshot, CensusError> {
    let prefix = history.get(..end).ok_or(CensusError::Capacity)?;
    let mut rows = Vec::new();
    let mut owners = Vec::new();
    for value in prefix {
        let view = resolve(census, origins, value)?;
        let archive_owner = match value {
            HistoryRecord::SharedOrdinary(value) => Some(value.row.owner()?),
            _ => None,
        };
        let materialized = match view {
            HistoryView::Refreshed {
                origin,
                before,
                after,
            } => HistoryRecord::Refreshed {
                origin,
                before: owned(before),
                after: owned(after),
            },
            HistoryView::Consumed { origin, evidence } => {
                let evidence = match evidence.evidence {
                    ConsumptionEvidenceView::Owned(value) => value.clone(),
                    ConsumptionEvidenceView::SharedOrdinary(value) => OwnerConsumption {
                        before: owned(evidence.before),
                        successor: owned(evidence.successor),
                        evidence: Consumption::OwnedOrdinary(
                            vec![value.clone()].into_boxed_slice(),
                        ),
                    },
                };
                HistoryRecord::Consumed { origin, evidence }
            }
            HistoryView::Other(value) => value.clone(),
        };
        rows.push(materialized);
        owners.push(archive_owner);
    }
    let mut archives = Vec::new();
    for owner in origins {
        let Some(value) = &owner.ordinary_history else {
            continue;
        };
        if !all_archives && !owners.contains(&Some(owner.row.id)) {
            continue;
        }
        // Old generation/inactive rows remain valid immutable history owners.
        // The old identity, full initial row and exact evidence are checked.
        shared_context(census, origins, owner.row.id)?;
        archives.push(ArchiveOwnerSnapshot {
            id: owner.row.id,
            initial: owner.row.clone(),
            initial_allocation: (
                owner.row.initial.xstate.as_ptr() as usize,
                owner.row.initial.xstate.len(),
                owner.row.initial.xstate.capacity(),
            ),
            evidence_pointer: value.evidence.as_ptr() as usize,
            evidence_length: value.evidence.len(),
            evidence: value.evidence.to_vec(),
            archive: value.archive.test_snapshot(),
        });
    }
    Ok(HistorySnapshot {
        rows,
        owners,
        archives,
    })
}

impl HistorySnapshot {
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn len(&self) -> usize {
        self.rows.len()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn rows(&self) -> &[HistoryRecord] {
        &self.rows
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn prefix(
        &self,
        end: usize,
    ) -> Result<Self, CensusError> {
        let rows = self.rows.get(..end).ok_or(CensusError::Capacity)?.to_vec();
        let owners = self
            .owners
            .get(..end)
            .ok_or(CensusError::Capacity)?
            .to_vec();
        let archives = self
            .archives
            .iter()
            .filter(|v| owners.contains(&Some(v.id)))
            .cloned()
            .collect();
        Ok(Self {
            rows,
            owners,
            archives,
        })
    }
}

impl ResumeCensus {
    pub(in crate::linux::remote::dynamic::owner::admission) fn history_snapshot(
        &self,
    ) -> Result<HistorySnapshot, CensusError> {
        snapshot(
            self.identity,
            &self.state.origins,
            &self.state.history,
            self.state.history.len(),
            true,
        )
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn history_snapshot_prefix(
        &self,
        end: usize,
    ) -> Result<HistorySnapshot, CensusError> {
        snapshot(
            self.identity,
            &self.state.origins,
            &self.state.history,
            end,
            false,
        )
    }
}

// The child below owns fields private to exec.rs; its exact implementation is
// supplied as an exec-child fragment, preserving the retired native identity.
pub(in crate::linux::remote::dynamic::owner::admission::census) fn retired_snapshot(
    census: u64,
    origins: &[StoredOrigin],
    history: &[HistoryRecord],
    end: usize,
    all: bool,
) -> Result<HistorySnapshot, CensusError> {
    snapshot(census, origins, history, end, all)
}
