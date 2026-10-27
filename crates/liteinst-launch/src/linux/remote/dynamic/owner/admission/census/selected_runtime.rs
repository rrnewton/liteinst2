//! Prepared selected CPU completion bookkeeping. This module is pure: only
//! the native owner can establish that the supplied successor actually occurred.
//! All copied payloads are prepared and charged before any register mutation.
use super::*;
use std::mem::size_of;

#[cfg(test)]
mod tests;

pub(in crate::linux::remote::dynamic::owner::admission) struct PreparedRuntimeSelected {
    census: u64,
    reservation: Reservation,
    origin: OriginId,
    invocation: ExecutionId,
    candidate_serial: u64,
    evidence: Option<OwnerConsumption>,
    successor: Option<StoredOrigin>,
    committed: Option<OriginId>,
}

fn add(a: usize, b: usize) -> Result<usize, CensusError> {
    a.checked_add(b).ok_or(CensusError::Capacity)
}
fn fixed_charge() -> BudgetCharge {
    BudgetCharge {
        origins: 1,
        witnesses: 1,
        source_fact_bytes: size_of::<OwnerConsumption>()
            + 4 * size_of::<ObservedStop>()
            + size_of::<StoredOrigin>(),
        ..BudgetCharge::default()
    }
}

impl PreparedRuntimeSelected {
    pub(in crate::linux::remote::dynamic::owner::admission) fn remaining_charge(
        &self,
    ) -> Result<BudgetCharge, CensusError> {
        if self.committed.is_some() || self.evidence.is_none() || self.successor.is_none() {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(fixed_charge())
    }
    /// The old selected-consumption and insert formulas, plus the retained
    /// preparation header and exact MAX-capacity excess. No old formula changes.
    pub(in crate::linux::remote::dynamic::owner::admission) fn reservation_charge()
    -> Result<BudgetCharge, CensusError> {
        let payload = add(size_of::<Self>(), 4 * MAX_XSTATE_BYTES)?;
        let payload = add(
            payload,
            size_of::<SelectedInput>() + size_of::<CompletedInstruction>() + 30,
        )?;
        fixed_charge().add(BudgetCharge {
            source_fact_bytes: payload,
            ..BudgetCharge::default()
        })
    }
}

fn prepared_copy(
    source: &ObservedStop,
    registers: RegisterSnapshot,
    phase: StopPhase,
) -> Result<ObservedStop, CensusError> {
    let mut xstate = Vec::new();
    xstate
        .try_reserve_exact(MAX_XSTATE_BYTES)
        .map_err(|_| CensusError::Allocation)?;
    if xstate.capacity() != MAX_XSTATE_BYTES {
        return Err(CensusError::Allocation);
    }
    xstate.extend_from_slice(&source.xstate);
    Ok(ObservedStop {
        token: source.token.clone(),
        task: source.task,
        logical_pc: registers.rip,
        registers,
        xstate,
        signal_mask: source.signal_mask,
        phase,
        signal: None,
    })
}

fn prepared_successor_matches(
    expected: &ObservedStop,
    old_token: &DynamicStop,
    actual: &ObservedStop,
) -> bool {
    expected.token == *old_token
        && expected.task == actual.task
        && expected.logical_pc == actual.logical_pc
        && expected.registers == actual.registers
        && expected.xstate == actual.xstate
        && expected.signal_mask == actual.signal_mask
        && expected.phase == StopPhase::UserCheckpoint
        && expected.signal.is_none()
}

impl ResumeCensus {
    pub(in crate::linux::remote::dynamic::owner::admission) fn prepare_runtime_selected(
        &mut self,
        reservation: Reservation,
        origin: OriginId,
        invocation: ExecutionId,
        input: &SelectedInput,
        completed: &CompletedInstruction,
    ) -> Result<Box<PreparedRuntimeSelected>, CensusError> {
        self.check_reserved(reservation, PreparedRuntimeSelected::reservation_charge()?)?;
        self.state
            .next_serial
            .checked_add(1)
            .ok_or(CensusError::Capacity)?;
        let index = self.active_index(origin)?;
        let stored = &self.state.origins[index];
        if stored.row.kind != OriginKind::CurrentHeldPc
            || stored.frame.is_some()
            || stored.current.task.generation != self.state.generation
            || stored.current.phase != StopPhase::UserCheckpoint
            || stored.current.signal.is_some()
            || stored.current.logical_pc != stored.row.pc
        {
            return Err(CensusError::WrongOriginPhase);
        }
        stored.current.validate(self.session, self.space)?;
        if !(512..MAX_XSTATE_BYTES).contains(&stored.current.xstate.len()) {
            return Err(CensusError::InvalidObservation);
        }
        input_matches(&stored.current, input, invocation)?;
        if matches!(
            input.instruction().operation(),
            crate::selected::Operation::Syscall { .. }
        ) || input.instruction().bytes().is_empty()
            || input.instruction().bytes().len() > 15
            || completed.instruction != *input.instruction()
            || completed.before != *input.registers()
            || completed.after.rip != input.instruction().next_pc()
            || completed.after.cs != 0x33
            || completed.after.orig_rax != stored.current.registers.orig_rax
        {
            return Err(CensusError::InvalidConsumption);
        }
        let provenance = self.runtime_register_provenance(origin)?;
        // Construction is descriptive. In particular the old token retained
        // here is not a fabricated successor stop; commit must replace it from
        // the real native proof and require a strictly later same-task sequence.
        let before = prepared_copy(
            &stored.current,
            stored.current.registers,
            stored.current.phase,
        )?;
        let successor = prepared_copy(
            &stored.current,
            completed.after,
            StopPhase::SelectedComplete { invocation },
        )?;
        let initial = prepared_copy(&stored.current, completed.after, StopPhase::UserCheckpoint)?;
        let current = prepared_copy(&stored.current, completed.after, StopPhase::UserCheckpoint)?;
        let result = Box::new(PreparedRuntimeSelected {
            census: self.identity,
            reservation,
            origin,
            invocation,
            candidate_serial: self.state.next_serial,
            evidence: Some(OwnerConsumption {
                before,
                successor,
                evidence: Consumption::Selected {
                    invocation,
                    input: Box::new(input.clone()),
                    completed: Box::new(completed.clone()),
                },
            }),
            successor: Some(StoredOrigin {
                row: OriginRow {
                    id: origin,
                    kind: OriginKind::CurrentHeldPc,
                    pc: completed.after.rip,
                    created_generation: self.state.generation,
                    initial,
                },
                current,
                active: true,
                frame: None,
                runtime_kernel: provenance.map(|lineage| runtime_kernel::KernelOriginLineage {
                    returned: lineage.returned,
                    parent: Some(origin),
                }),
                ordinary_history: None,
            }),
            committed: None,
        });
        let evidence = result
            .evidence
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        let Consumption::Selected {
            input, completed, ..
        } = &evidence.evidence
        else {
            return Err(CensusError::InvalidConsumption);
        };
        // Measure both immutable instruction allocations through the narrow
        // crate-private getter; allocator capacity is never inferred from len.
        let input_capacity = input.instruction().retained_capacity();
        let completed_capacity = completed.instruction.retained_capacity();
        if input_capacity > 15 || completed_capacity > 15 {
            return Err(CensusError::Allocation);
        }
        let bytes = add(size_of::<PreparedRuntimeSelected>(), 4 * MAX_XSTATE_BYTES)?;
        let bytes = add(
            bytes,
            size_of::<SelectedInput>()
                + size_of::<CompletedInstruction>()
                + input_capacity
                + completed_capacity,
        )?;
        self.account_external(
            reservation,
            BudgetCharge {
                source_fact_bytes: bytes,
                ..BudgetCharge::default()
            },
        )?;
        Ok(result)
    }

    /// Check everything before taking any prepared payload or mutating the
    /// census. The final native state is borrowed; no Box/Vec is created here.
    pub(in crate::linux::remote::dynamic::owner::admission) fn commit_runtime_selected(
        &mut self,
        prepared: &mut PreparedRuntimeSelected,
        actual: &ObservedStop,
    ) -> Result<OriginId, CensusError> {
        if prepared.census != self.identity || prepared.committed.is_some() {
            return Err(CensusError::IdentityMismatch);
        }
        let index = self.active_index(prepared.origin)?;
        let stored = &self.state.origins[index];
        let evidence = prepared
            .evidence
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        let successor = prepared
            .successor
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        if stored.row.kind != OriginKind::CurrentHeldPc
            || stored.frame.is_some()
            || evidence.before != stored.current
            || stored.row.pc != evidence.before.logical_pc
            || actual.task.generation != self.state.generation
        {
            return Err(CensusError::StaleObservation);
        }
        successor_matches(&evidence.before, actual)?;
        let provenance = self.runtime_register_provenance(prepared.origin)?;
        if actual.phase
            != (StopPhase::SelectedComplete {
                invocation: prepared.invocation,
            })
            || actual.signal.is_some()
            || actual.logical_pc != evidence.successor.logical_pc
            || actual.registers != evidence.successor.registers
            || actual.xstate != evidence.successor.xstate
            || actual.signal_mask != evidence.successor.signal_mask
            || evidence.successor.token != evidence.before.token
            || evidence.successor.task != actual.task
            || evidence.successor.signal.is_some()
            || evidence.successor.phase != actual.phase
            || successor.row.kind != OriginKind::CurrentHeldPc
            || successor.row.pc != actual.logical_pc
            || successor.row.created_generation != self.state.generation
            || !successor.active
            || successor.frame.is_some()
            || successor.runtime_kernel
                != provenance.map(|lineage| runtime_kernel::KernelOriginLineage {
                    returned: lineage.returned,
                    parent: Some(prepared.origin),
                })
            || actual.registers.orig_rax != evidence.before.registers.orig_rax
            || !prepared_successor_matches(&successor.row.initial, &evidence.before.token, actual)
            || !prepared_successor_matches(&successor.current, &evidence.before.token, actual)
        {
            return Err(CensusError::InvalidConsumption);
        }
        let Consumption::Selected {
            invocation,
            input,
            completed,
        } = &evidence.evidence
        else {
            return Err(CensusError::InvalidConsumption);
        };
        input_matches(&evidence.before, input, *invocation)?;
        if *invocation != prepared.invocation
            || completed.instruction != *input.instruction()
            || completed.before != evidence.before.registers
            || completed.after != actual.registers
            || actual.logical_pc != input.instruction().next_pc()
        {
            return Err(CensusError::InvalidConsumption);
        }
        if self.state.history.len() == self.state.history.capacity()
            || self.state.origins.len() == self.state.origins.capacity()
        {
            return Err(CensusError::Allocation);
        }
        let (remaining, used) = self.prepare_debit(prepared.reservation, fixed_charge())?;
        let next = self
            .state
            .next_serial
            .checked_add(1)
            .ok_or(CensusError::Capacity)?;
        if self.state.next_serial != prepared.candidate_serial {
            return Err(CensusError::StaleObservation);
        }
        let id = OriginId {
            census: self.identity,
            serial: self.state.next_serial,
        };
        // No fallible operation, allocation, user callback or native request
        // occurs between these moves and the complete model transition.
        let mut evidence = prepared
            .evidence
            .take()
            .expect("validated prepared selected evidence");
        let mut successor = prepared
            .successor
            .take()
            .expect("validated prepared selected origin");
        evidence.successor.token = actual.token.clone();
        successor.row.id = id;
        successor.row.initial.token = actual.token.clone();
        successor.current.token = actual.token.clone();
        self.state.history.push(HistoryRecord::Consumed {
            origin: prepared.origin,
            evidence,
        });
        self.state.origins[index].active = false;
        self.state.origins.push(successor);
        self.state.next_serial = next;
        self.commit_debit(prepared.reservation, remaining, used);
        prepared.committed = Some(id);
        Ok(id)
    }
}
