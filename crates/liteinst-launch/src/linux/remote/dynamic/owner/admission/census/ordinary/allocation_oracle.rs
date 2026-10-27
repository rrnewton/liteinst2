//! Read-only actual census diagnostics; never updates a token or live state.
use super::*;
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct AllocationCensusSnapshot {
    identity: u64,
    session: u64,
    space: AddressSpaceId,
    limits: Limits,
    state: State,
    origin_storage: (usize, usize, usize),
    history_storage: (usize, usize, usize),
    observations: Vec<[(usize, usize, usize); 2]>,
    history: HistorySnapshot,
}
impl ResumeCensus {
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocation_custody_snapshot(
        &self,
    ) -> Result<AllocationCensusSnapshot, CensusError> {
        Ok(AllocationCensusSnapshot {
            identity: self.identity,
            session: self.session,
            space: self.space,
            limits: self.limits,
            state: self.state.clone(),
            origin_storage: (
                self.state.origins.as_ptr() as usize,
                self.state.origins.len(),
                self.state.origins.capacity(),
            ),
            history_storage: (
                self.state.history.as_ptr() as usize,
                self.state.history.len(),
                self.state.history.capacity(),
            ),
            observations: self
                .state
                .origins
                .iter()
                .map(|v| {
                    [&v.row.initial.xstate, &v.current.xstate]
                        .map(|b| (b.as_ptr() as usize, b.len(), b.capacity()))
                })
                .collect(),
            history: self.history_snapshot()?,
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_allocation_failure_accounting(
        &self,
        before: &AllocationCensusSnapshot,
        token: Reservation,
        charge: BudgetCharge,
        actual_bytes: usize,
    ) {
        assert_eq!(
            (self.identity, self.session, self.space, self.limits),
            (before.identity, before.session, before.space, before.limits)
        );
        assert_eq!(
            token,
            Reservation {
                census: self.identity,
                serial: before.state.next_serial
            }
        );
        assert_eq!(
            self.state.next_serial,
            before.state.next_serial.checked_add(1).unwrap()
        );
        assert_eq!(before.state.reservation, None);
        assert_eq!(self.state.reservation, None);
        assert_eq!(
            self.state.charged,
            before.state.charged.add(charge).unwrap()
        );
        assert_eq!(
            self.state.used,
            before
                .state
                .used
                .add(BudgetCharge {
                    source_fact_bytes: actual_bytes,
                    ..BudgetCharge::default()
                })
                .unwrap()
        );
        assert_eq!(self.state.generation, before.state.generation);
        assert_eq!(self.state.origins, before.state.origins);
        assert_eq!(self.state.history, before.state.history);
        assert_eq!(self.history_snapshot().unwrap(), before.history);
        let observed = self
            .state
            .origins
            .iter()
            .map(|v| {
                [&v.row.initial.xstate, &v.current.xstate]
                    .map(|b| (b.as_ptr() as usize, b.len(), b.capacity()))
            })
            .collect::<Vec<_>>();
        assert_eq!(observed, before.observations);
    }
}
