//! Exact model lineage for inherited original-syscall register bookkeeping.
//! A number alone is never sufficient: a retained, sealed-return consumption
//! and each intervening selected transition must bind the complete origin rows.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct KernelOriginLineage {
    pub(in super::super) returned: OriginId,
    pub(in super::super) parent: Option<OriginId>,
}

fn same_architecture(left: &ObservedStop, right: &ObservedStop) -> bool {
    left.task == right.task
        && left.token.session == right.token.session
        && left.token.tid == right.token.tid
        && left.token.task == right.token.task
        && left.logical_pc == right.logical_pc
        && left.registers == right.registers
        && left.xstate == right.xstate
        && left.signal_mask == right.signal_mask
        && left.signal == right.signal
}
fn selected_initial(initial: &ObservedStop, successor: &ObservedStop) -> bool {
    same_architecture(initial, successor)
        && initial.token == successor.token
        && initial.phase == StopPhase::UserCheckpoint
        && initial.signal.is_none()
}
impl ResumeCensus {
    fn lineage_origin(&self, id: OriginId) -> Result<&StoredOrigin, CensusError> {
        if id.census != self.identity {
            return Err(CensusError::IdentityMismatch);
        }
        let mut rows = self.state.origins.iter().filter(|value| value.row.id == id);
        let row = rows.next().ok_or(CensusError::UnknownOrigin)?;
        if rows.next().is_some()
            || row.row.kind != OriginKind::CurrentHeldPc
            || row.frame.is_some()
            || row.row.pc != row.row.initial.logical_pc
            || row.row.pc != row.current.logical_pc
            || row.row.created_generation != 0
            || row.current.task.generation != 0
        {
            return Err(CensusError::InvalidConsumption);
        }
        row.row.initial.validate(self.session, self.space)?;
        row.current.validate(self.session, self.space)?;
        Ok(row)
    }
    fn lineage_row(&self, id: OriginId) -> Result<&StoredOrigin, CensusError> {
        let row = self.lineage_origin(id)?;
        let mut previous = &row.row.initial;
        for record in &self.state.history {
            let HistoryRecord::Refreshed {
                origin,
                before,
                after,
            } = record
            else {
                continue;
            };
            if *origin != id {
                continue;
            }
            if before != previous
                || !same_architecture(before, after)
                || after.token.sequence <= before.token.sequence
                || after.phase != StopPhase::UserCheckpoint
                || after.signal.is_some()
            {
                return Err(CensusError::InvalidConsumption);
            }
            previous = after;
        }
        if previous != &row.current {
            return Err(CensusError::StaleObservation);
        }
        Ok(row)
    }

    fn unique_consumption(&self, origin: OriginId) -> Result<&OwnerConsumption, CensusError> {
        let mut records = self.state.history.iter().filter_map(|record| match record {
            HistoryRecord::Consumed {
                origin: candidate,
                evidence,
            } if *candidate == origin => Some(evidence),
            _ => None,
        });
        let evidence = records.next().ok_or(CensusError::InvalidConsumption)?;
        if records.next().is_some() {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(evidence)
    }

    fn returned_lineage(&self, row: &StoredOrigin, number: u64) -> Result<(), CensusError> {
        let mut records = self.state.history.iter().filter_map(|record| match record {
            HistoryRecord::Consumed { origin, evidence } => match &evidence.evidence {
                Consumption::RuntimeKernel(values) if values.len() == 1 => {
                    let value = &values[0];
                    value
                        .outcome
                        .as_ref()
                        .and_then(|outcome| outcome.returned)
                        .filter(|(id, _)| *id == row.row.id)
                        .map(|(_, trace)| (*origin, evidence, value, trace))
                }
                _ => None,
            },
            _ => None,
        });
        let (old_id, evidence, value, trace) =
            records.next().ok_or(CensusError::InvalidConsumption)?;
        if records.next().is_some() {
            return Err(CensusError::InvalidConsumption);
        }
        // The kernel seal independently bound this full pre-syscall state.
        // Its earlier origin may be an ordinary #DB record with a consumed
        // control signal; it is not part of the inherited-kernel refresh chain.
        let old = self.lineage_origin(old_id)?;
        let identity = &value.identity;
        let entry = value
            .entry
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        if old.active
            || old_id.serial >= row.row.id.serial
            || identity.origin() != old_id
            || identity.number() != number
            || !identity.operation().returns()
            || identity.execution().session != self.session
            || identity.execution().serial == 0
            || identity.attempt()
                != (KernelAttemptId {
                    session: self.session,
                    invocation: identity.execution().serial,
                })
            || identity.pending().invocation != identity.execution().serial
            || identity.pending().task != identity.task()
            || identity.pending().stop.session != self.session
            || identity.pending().stop.tid != identity.tid()
            || identity.pending().stop.task != Some(identity.task().task)
            || identity.pending().generation.0 != 0
            || identity.source_id().identity().generation != 0
            || identity.source_id().identity().mapping == 0
            || identity.pending().mapping.0 != identity.source_id().identity().mapping
            || identity.pending().window != identity.source_id().index()
            || identity.pc() != evidence.before.logical_pc
            || identity.pc().checked_add(2) != Some(identity.next_pc())
            || identity.encoding() != [0x0f, 0x05]
            || evidence.before.registers.rax != number
            || identity.arguments() != validate::arguments(&evidence.before.registers)
            || identity.task() != row.current.task
            || evidence.before != old.current
            || evidence.successor != row.row.initial
            || value.outcome.as_ref().is_none_or(|v| v.terminal.is_some())
            || evidence.successor.phase
                != (StopPhase::ParentSyscallExit {
                    syscall: number,
                    result: i64::from(identity.tid()),
                    is_error: false,
                })
            || evidence.successor.registers.rax != identity.tid() as u64
            || evidence.successor.registers.orig_rax != number
            || evidence.successor.registers
                != (RegisterSnapshot {
                    rax: identity.tid() as u64,
                    ..entry.registers
                })
            || entry.phase != (StopPhase::SyscallEntry { syscall: number })
            || entry.registers
                != validate::syscall_flags(&evidence.before.registers, identity.next_pc(), number)
            || entry.task != row.current.task
            || entry.xstate != evidence.before.xstate
            || entry.signal_mask != evidence.before.signal_mask
            || entry.signal.is_some()
            || entry.token.session != self.session
            || entry.token.tid != identity.tid()
            || entry.token.task != Some(identity.task().task)
            || entry.token.sequence <= evidence.before.token.sequence
            || evidence.successor.token.sequence <= entry.token.sequence
            || evidence.successor.xstate != entry.xstate
            || evidence.successor.signal_mask != entry.signal_mask
            || trace.attempt != identity.attempt()
            || trace.released != KernelStopIdentity::from(&evidence.before.token)
            || trace.entry != KernelStopIdentity::from(&entry.token)
            || trace.exit != KernelStopIdentity::from(&row.row.initial.token)
            || trace.entry_ordinal != 3
            || trace.exit_ordinal != 4
            || trace.bridge_ordinal != 5
            || trace.closed_ordinal != 8
            || trace.original_release
                != (Request {
                    result: 0,
                    errno: None,
                })
            || trace.entry_release
                != (Request {
                    result: 0,
                    errno: None,
                })
            || trace.namespace.inode == 0
        {
            return Err(CensusError::InvalidConsumption);
        }
        let opening = self.state.history.iter().filter_map(|record| match record {
            HistoryRecord::Refreshed {
                origin,
                before,
                after,
            } if *origin == old_id && before.token.sequence >= identity.pending().stop.sequence => {
                Some((before, after))
            }
            _ => None,
        });
        let mut count = 0;
        let mut previous = None;
        for (before, after) in opening {
            if (count == 0 && before.token != identity.pending().stop)
                || previous.is_some_and(|value| value != before)
                || !same_architecture(before, after)
                || before.signal.is_some()
                || before.phase != StopPhase::UserCheckpoint
                || after.phase != StopPhase::UserCheckpoint
                || after.token.sequence <= before.token.sequence
            {
                return Err(CensusError::InvalidConsumption);
            }
            previous = Some(after);
            count += 1;
        }
        if count != 3 || previous != Some(&evidence.before) {
            return Err(CensusError::InvalidConsumption);
        }
        let mut refreshes = self.state.history.iter().filter_map(|record| match record {
            HistoryRecord::Refreshed { origin, after, .. } if *origin == row.row.id => Some(after),
            _ => None,
        });
        let bridge = refreshes.next().ok_or(CensusError::InvalidConsumption)?;
        let closed = refreshes.nth(2).ok_or(CensusError::InvalidConsumption)?;
        if trace.bridge != KernelStopIdentity::from(&bridge.token)
            || trace.closed != KernelStopIdentity::from(&closed.token)
        {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(())
    }

    /// Read-only model authentication. Native ControlLineage independently
    /// authenticates the real held checkpoint; this method grants no release.
    pub(in super::super) fn runtime_register_provenance(
        &self,
        id: OriginId,
    ) -> Result<Option<KernelOriginLineage>, CensusError> {
        let current = self.current_observation(id)?;
        let active = &self.state.origins[self.active_index(id)?];
        let Some(lineage) = active.runtime_kernel else {
            return if current.registers.orig_rax == u64::MAX {
                Ok(None)
            } else {
                Err(CensusError::StaleObservation)
            };
        };
        let number = current.registers.orig_rax;
        if number != libc::SYS_getpid as u64 && number != libc::SYS_gettid as u64 {
            return Err(CensusError::InvalidConsumption);
        }
        let mut next = id;
        for _ in 0..self.state.origins.len() {
            let row = self.lineage_row(next)?;
            let link = row.runtime_kernel.ok_or(CensusError::InvalidConsumption)?;
            if link.returned != lineage.returned
                || row.current.task != current.task
                || row.current.registers.orig_rax != number
                || row.row.initial.registers.orig_rax != number
            {
                return Err(CensusError::InvalidConsumption);
            }
            match link.parent {
                None => {
                    if next != lineage.returned {
                        return Err(CensusError::InvalidConsumption);
                    }
                    self.returned_lineage(row, number)?;
                    return Ok(Some(lineage));
                }
                Some(parent) => {
                    if parent.serial >= next.serial {
                        return Err(CensusError::InvalidConsumption);
                    }
                    let prior = self.lineage_row(parent)?;
                    let evidence = self.unique_consumption(parent)?;
                    let Consumption::Selected {
                        invocation,
                        input,
                        completed,
                    } = &evidence.evidence
                    else {
                        return Err(CensusError::InvalidConsumption);
                    };
                    input_matches(&evidence.before, input, *invocation)?;
                    if prior.active
                        || evidence.before != prior.current
                        || evidence.successor.phase
                            != (StopPhase::SelectedComplete {
                                invocation: *invocation,
                            })
                        || !selected_initial(&row.row.initial, &evidence.successor)
                        || evidence.successor.token.sequence <= evidence.before.token.sequence
                        || completed.before != evidence.before.registers
                        || completed.after != evidence.successor.registers
                        || completed.instruction != *input.instruction()
                        || matches!(
                            input.instruction().operation(),
                            crate::selected::Operation::Syscall { .. }
                        )
                        || evidence.successor.registers.orig_rax
                            != evidence.before.registers.orig_rax
                        || evidence.successor.xstate != evidence.before.xstate
                        || evidence.successor.signal_mask != evidence.before.signal_mask
                    {
                        return Err(CensusError::InvalidConsumption);
                    }
                    next = parent;
                }
            }
        }
        Err(CensusError::InvalidConsumption)
    }
}
