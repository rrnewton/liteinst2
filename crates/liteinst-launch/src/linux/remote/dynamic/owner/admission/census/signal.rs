//! Explicit saved-frame bookkeeping. Native byte/exclusion/phase authority is
//! supplied only by the parent owner; none of these records grants it.
use super::*;
use crate::lifecycle::{ObligationKind, ObligationRecord, SignalScope};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct FrameFacts {
    pub(in crate::linux::remote::dynamic::owner::admission) id: SignalFrameId,
    pub(in crate::linux::remote::dynamic::owner::admission) version: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) address: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) bytes: Vec<u8>,
    pub(in crate::linux::remote::dynamic::owner::admission) original_pc: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) prospective_pc: Option<u64>,
    pub(in crate::linux::remote::dynamic::owner::admission) obligation: ObligationRecord,
}
impl FrameFacts {
    fn validate(&self, observed: &ObservedStop) -> Result<(), CensusError> {
        if self.id.session != observed.token.session
            || self.id.serial == 0
            || self.version == 0
            || self.address == 0
            || self.bytes.is_empty()
            || self.bytes.len() > MAX_XSTATE_BYTES + 4096
            || self.address.checked_add(self.bytes.len() as u64).is_none()
            || self.bytes.len() < 184
            || ![Some(self.original_pc), self.prospective_pc].contains(&Some(u64::from_le_bytes(
                self.bytes[176..184].try_into().unwrap(),
            )))
            || self.original_pc == 0
            || self.prospective_pc == Some(0)
            || self.prospective_pc == Some(self.original_pc)
            || self.obligation.task != observed.task.task
            || self.obligation.address_space != observed.task.address_space
            || self.obligation.inherited_from.is_some()
            || !matches!(
                self.obligation.kind,
                ObligationKind::PendingSignal {
                    scope: SignalScope::Unknown,
                    ..
                }
            )
        {
            return Err(CensusError::InvalidObservation);
        }
        Ok(())
    }
    fn bytes(&self) -> Result<usize, CensusError> {
        std::mem::size_of::<Self>()
            .checked_add(self.bytes.len())
            .ok_or(CensusError::Capacity)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn same_frame(
        &self,
        other: &Self,
    ) -> bool {
        self.id == other.id
            && self.address == other.address
            && self.original_pc == other.original_pc
            && self.prospective_pc == other.prospective_pc
            && self.obligation == other.obligation
            && self.bytes.len() == other.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct FrameRefresh {
    origin: OriginId,
    before: ObservedStop,
    after: ObservedStop,
    before_frame: Arc<FrameFacts>,
    after_frame: Arc<FrameFacts>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct SignalDelivered {
    frame: SignalFrameId,
    obligation: ObligationRecord,
    delivery: ObservedStop,
    handler_fetch: ObservedStop,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct SignalReturnWitness {
    pub(in crate::linux::remote::dynamic::owner::admission) frame: SignalFrameId,
    pub(in crate::linux::remote::dynamic::owner::admission) entry: ObservedStop,
    pub(in crate::linux::remote::dynamic::owner::admission) returned: ObservedStop,
    pub(in crate::linux::remote::dynamic::owner::admission) expected: ObservedStop,
    pub(in crate::linux::remote::dynamic::owner::admission) syscall_bytes: [u8; 88],
    pub(in crate::linux::remote::dynamic::owner::admission) syscall_count: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct FrameReturn {
    origin: OriginId,
    before: ObservedStop,
    frame: Arc<FrameFacts>,
    witness: SignalReturnWitness,
}

fn increasing_holder(
    before: &ObservedStop,
    after: &ObservedStop,
    generation: u64,
) -> Result<(), CensusError> {
    after.validate(before.token.session, before.task.address_space)?;
    if after.task.task != before.task.task
        || after.task.process != before.task.process
        || after.token.tid != before.token.tid
        || after.token.sequence < before.token.sequence
        || after.task.generation != generation
        || after.task.generation < before.task.generation
    {
        return Err(CensusError::StaleObservation);
    }
    if after.token.sequence == before.token.sequence {
        let mut rebound = before.clone();
        rebound.task.generation = after.task.generation;
        if rebound != *after {
            return Err(CensusError::StaleObservation);
        }
    }
    Ok(())
}

impl ResumeCensus {
    /// Current register origins remain distinct from all live memory origins.
    /// Native task bounds use this view; projections still use every active row.
    pub(in crate::linux::remote::dynamic::owner::admission) fn active_registers(
        &self,
    ) -> impl Iterator<Item = ActiveOrigin<'_>> {
        self.active()
            .filter(|row| !matches!(row.row.kind, OriginKind::SignalFrame { .. }))
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn active_frames(
        &self,
    ) -> impl Iterator<Item = (ActiveOrigin<'_>, &FrameFacts)> {
        self.state
            .origins
            .iter()
            .filter(|stored| stored.active)
            .filter_map(|stored| {
                stored.frame.as_ref().map(|frame| {
                    (
                        ActiveOrigin {
                            row: &stored.row,
                            current: &stored.current,
                        },
                        frame.as_ref(),
                    )
                })
            })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn insert_frame(
        &mut self,
        token: Reservation,
        frame: Arc<FrameFacts>,
        prospective: bool,
        observed: ObservedStop,
    ) -> Result<OriginId, CensusError> {
        observed.validate(self.session, self.space)?;
        frame.validate(&observed)?;
        if observed.task.generation != self.state.generation
            || !matches!(
                observed.phase,
                StopPhase::OwnedFetch | StopPhase::OwnedGuard | StopPhase::UserCheckpoint
            )
            || self.rows().any(|row| {
                row.kind
                    == (OriginKind::SignalFrame {
                        frame: frame.id,
                        prospective,
                    })
            })
        {
            return Err(CensusError::StaleObservation);
        }
        for sibling in self.state.origins.iter().filter(|row| {
            matches!(row.row.kind,
            OriginKind::SignalFrame { frame: id, .. } if id == frame.id)
        }) {
            if !sibling.active
                || sibling.current != observed
                || sibling.frame.as_deref() != Some(frame.as_ref())
            {
                return Err(CensusError::StaleObservation);
            }
        }
        let pc = if prospective {
            frame
                .prospective_pc
                .ok_or(CensusError::InvalidObservation)?
        } else {
            frame.original_pc
        };
        let bytes = observed
            .retained_bytes()
            .checked_mul(2)
            .and_then(|value| value.checked_add(std::mem::size_of::<StoredOrigin>()))
            .and_then(|value| value.checked_add(frame.bytes().ok()?))
            .ok_or(CensusError::Capacity)?;
        let (remaining, used) = self.prepare_debit(
            token,
            BudgetCharge {
                origins: 1,
                source_fact_bytes: bytes,
                ..BudgetCharge::default()
            },
        )?;
        let serial = self.state.next_serial;
        let next = serial.checked_add(1).ok_or(CensusError::Capacity)?;
        let id = OriginId {
            census: self.identity,
            serial,
        };
        self.state.origins.push(StoredOrigin {
            row: OriginRow {
                id,
                kind: OriginKind::SignalFrame {
                    frame: frame.id,
                    prospective,
                },
                pc,
                created_generation: self.state.generation,
                initial: observed.clone(),
            },
            current: observed,
            active: true,
            frame: Some(frame),
            runtime_kernel: None,
            ordinary_history: None,
        });
        self.state.next_serial = next;
        self.commit_debit(token, remaining, used);
        Ok(id)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn check_frame_origin(
        &self,
        id: OriginId,
        observed: &ObservedStop,
        address: u64,
        bytes: &[u8],
    ) -> Result<&OriginRow, CensusError> {
        let stored = &self.state.origins[self.active_index(id)?];
        let frame = stored.frame.as_ref().ok_or(CensusError::WrongOriginPhase)?;
        frame.validate(observed)?;
        if !matches!(stored.row.kind, OriginKind::SignalFrame { frame: id, .. } if id == frame.id)
            || stored.current != *observed
            || observed.task.generation != self.state.generation
            || frame.address != address
            || frame.bytes != bytes
        {
            return Err(CensusError::StaleObservation);
        }
        Ok(&stored.row)
    }
    /// Exact immutable version refresh; equal PC alone never authenticates a
    /// saved frame, and an unchanged version cannot hide a changed byte.
    pub(in crate::linux::remote::dynamic::owner::admission) fn refresh_frame(
        &mut self,
        token: Reservation,
        id: OriginId,
        frame: Arc<FrameFacts>,
        after: ObservedStop,
    ) -> Result<(), CensusError> {
        let index = self.active_index(id)?;
        let stored = &self.state.origins[index];
        let old = stored.frame.as_ref().ok_or(CensusError::WrongOriginPhase)?;
        frame.validate(&after)?;
        increasing_holder(&stored.current, &after, self.state.generation)?;
        if !old.same_frame(&frame)
            || (old.bytes == frame.bytes && old.version != frame.version)
            || (old.bytes != frame.bytes && old.version.checked_add(1) != Some(frame.version))
        {
            return Err(CensusError::StaleObservation);
        }
        if stored.current == after && old == &frame {
            self.remaining(token)?;
            return Ok(());
        }
        let bytes = stored
            .current
            .retained_bytes()
            .checked_add(after.retained_bytes())
            .and_then(|value| value.checked_add(std::mem::size_of::<FrameRefresh>()))
            .and_then(|value| value.checked_add(frame.bytes().ok()?))
            .and_then(|value| {
                value.checked_add(
                    after
                        .xstate
                        .len()
                        .saturating_sub(stored.current.xstate.len()),
                )
            })
            .ok_or(CensusError::Capacity)?;
        let (remaining, used) = self.prepare_debit(
            token,
            BudgetCharge {
                witnesses: 1,
                source_fact_bytes: bytes,
                ..BudgetCharge::default()
            },
        )?;
        self.state
            .history
            .push(HistoryRecord::SignalFrameRefreshed(Box::new(
                FrameRefresh {
                    origin: id,
                    before: stored.current.clone(),
                    after: after.clone(),
                    before_frame: Arc::clone(old),
                    after_frame: Arc::clone(&frame),
                },
            )));
        self.state.origins[index].current = after;
        self.state.origins[index].frame = Some(frame);
        self.commit_debit(token, remaining, used);
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn record_delivery(
        &mut self,
        token: Reservation,
        frame: SignalFrameId,
        obligation: ObligationRecord,
        delivery: ObservedStop,
        handler_fetch: ObservedStop,
    ) -> Result<(), CensusError> {
        delivery.validate(self.session, self.space)?;
        handler_fetch.validate(self.session, self.space)?;
        if delivery.task.generation != self.state.generation
            || handler_fetch.task.generation != self.state.generation
        {
            return Err(CensusError::StaleObservation);
        }
        successor_matches(&delivery, &handler_fetch)?;
        let signal = delivery
            .signal
            .as_ref()
            .ok_or(CensusError::WrongOriginPhase)?;
        if delivery.phase != StopPhase::OriginalSignal || handler_fetch.phase != StopPhase::OwnedFetch
            || frame.session != self.session || frame.serial == 0
            || obligation.task != delivery.task.task || obligation.address_space != self.space
            || obligation.inherited_from.is_some()
            || obligation.kind != (ObligationKind::PendingSignal { signal: signal.signal() as u8,
                code: signal.code(), scope: SignalScope::Unknown })
            || self.state.history.iter().any(|row| matches!(row,
                HistoryRecord::SignalDelivered(old) if old.obligation.id == obligation.id || old.frame == frame))
        { return Err(CensusError::InvalidConsumption); }
        let bytes = delivery
            .retained_bytes()
            .checked_add(handler_fetch.retained_bytes())
            .and_then(|value| value.checked_add(std::mem::size_of::<SignalDelivered>()))
            .ok_or(CensusError::Capacity)?;
        let (remaining, used) = self.prepare_debit(
            token,
            BudgetCharge {
                witnesses: 1,
                source_fact_bytes: bytes,
                ..BudgetCharge::default()
            },
        )?;
        self.state
            .history
            .push(HistoryRecord::SignalDelivered(Box::new(SignalDelivered {
                frame,
                obligation,
                delivery,
                handler_fetch,
            })));
        self.commit_debit(token, remaining, used);
        Ok(())
    }
    /// This checks only exact retained resolutions. Every other registry
    /// obligation, including another identical-looking signal, still refuses.
    pub(in crate::linux::remote::dynamic::owner::admission) fn check_signal_obligations(
        &self,
        obligations: &[ObligationRecord],
    ) -> Result<(), CensusError> {
        for origin in &self.state.origins {
            if let OriginKind::SignalFrame { frame, .. } = origin.row.kind {
                let facts = origin
                    .frame
                    .as_ref()
                    .ok_or(CensusError::PersistentUnknown)?;
                if facts.id != frame
                    || !obligations.contains(&facts.obligation)
                    || !self.state.history.iter().any(|row| {
                        matches!(row,
                        HistoryRecord::SignalDelivered(delivery)
                            if delivery.frame == frame && delivery.obligation == facts.obligation)
                    })
                {
                    return Err(CensusError::PersistentUnknown);
                }
            }
        }
        for row in &self.state.history {
            if let HistoryRecord::SignalDelivered(delivered) = row {
                if !obligations.contains(&delivered.obligation) {
                    return Err(CensusError::PersistentUnknown);
                }
            }
        }
        for obligation in obligations {
            let delivered = self
                .state
                .history
                .iter()
                .find_map(|row| match row {
                    HistoryRecord::SignalDelivered(value) if value.obligation == *obligation => {
                        Some(value)
                    }
                    _ => None,
                })
                .ok_or(CensusError::PersistentUnknown)?;
            let rows = self
                .state
                .origins
                .iter()
                .filter(|origin| {
                    matches!(origin.row.kind,
                OriginKind::SignalFrame { frame, .. } if frame == delivered.frame)
                })
                .collect::<Vec<_>>();
            let first = *rows.first().ok_or(CensusError::PersistentUnknown)?;
            let facts = first.frame.as_ref().ok_or(CensusError::PersistentUnknown)?;
            if facts.obligation != *obligation
                || facts.id != delivered.frame
                || rows.len() != 1 + usize::from(facts.prospective_pc.is_some())
            {
                return Err(CensusError::PersistentUnknown);
            }
            let mut original = false;
            let mut prospective = false;
            let mut returned: Option<&SignalReturnWitness> = None;
            for row in rows {
                if row.frame.as_ref() != Some(facts)
                    || row.current != first.current
                    || row.active != first.active
                {
                    return Err(CensusError::StaleObservation);
                }
                match row.row.kind {
                    OriginKind::SignalFrame {
                        prospective: false, ..
                    } if !original && row.row.pc == facts.original_pc => original = true,
                    OriginKind::SignalFrame {
                        prospective: true, ..
                    } if !prospective && Some(row.row.pc) == facts.prospective_pc => {
                        prospective = true
                    }
                    _ => return Err(CensusError::PersistentUnknown),
                }
                if !row.active {
                    let witness = self
                        .state
                        .history
                        .iter()
                        .find_map(|history| match history {
                            HistoryRecord::SignalFrameReturned(value)
                                if value.origin == row.row.id
                                    && value.frame.as_ref() == facts.as_ref() =>
                            {
                                Some(&value.witness)
                            }
                            _ => None,
                        })
                        .ok_or(CensusError::PersistentUnknown)?;
                    if returned.is_some_and(|previous| previous != witness) {
                        return Err(CensusError::InvalidConsumption);
                    }
                    returned = Some(witness);
                }
            }
            if !original || prospective != facts.prospective_pc.is_some() {
                return Err(CensusError::PersistentUnknown);
            }
        }
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn consume_frame(
        &mut self,
        token: Reservation,
        id: OriginId,
        witness: SignalReturnWitness,
    ) -> Result<(), CensusError> {
        let index = self.active_index(id)?;
        let stored = &self.state.origins[index];
        let frame = stored.frame.as_ref().ok_or(CensusError::WrongOriginPhase)?;
        successor_matches(&witness.entry, &witness.returned)?;
        if witness.frame != frame.id
            || witness.entry.phase
                != (StopPhase::SyscallEntry {
                    syscall: libc::SYS_rt_sigreturn as u64,
                })
            || witness.returned.phase != StopPhase::SignalReturn
            || witness.returned.registers != witness.expected.registers
            || witness.returned.xstate != witness.expected.xstate
            || witness.returned.signal_mask != witness.expected.signal_mask
            || !same_task(&stored.current, &witness.entry)
            || witness.entry.token.sequence <= stored.current.token.sequence
            || witness.returned.task.generation != self.state.generation
            || witness.returned.logical_pc
                != u64::from_le_bytes(frame.bytes[176..184].try_into().unwrap())
            || !(33..=88).contains(&witness.syscall_count)
            || witness.syscall_bytes[0] != 2
            || u32::from_ne_bytes(witness.syscall_bytes[4..8].try_into().unwrap()) != 0xc000_003e
            || u64::from_ne_bytes(witness.syscall_bytes[8..16].try_into().unwrap())
                != witness.returned.registers.rip
            || u64::from_ne_bytes(witness.syscall_bytes[16..24].try_into().unwrap())
                != witness.returned.registers.rsp
            || u64::from_ne_bytes(witness.syscall_bytes[24..32].try_into().unwrap())
                != witness.returned.registers.rax
            || witness.syscall_bytes[32] > 1
        {
            return Err(CensusError::InvalidConsumption);
        }
        let bytes = stored
            .current
            .retained_bytes()
            .checked_add(witness.entry.retained_bytes())
            .and_then(|value| value.checked_add(witness.returned.retained_bytes()))
            .and_then(|value| value.checked_add(witness.expected.retained_bytes()))
            .and_then(|value| value.checked_add(std::mem::size_of::<FrameReturn>()))
            .ok_or(CensusError::Capacity)?;
        let (remaining, used) = self.prepare_debit(
            token,
            BudgetCharge {
                witnesses: 1,
                source_fact_bytes: bytes,
                ..BudgetCharge::default()
            },
        )?;
        self.state
            .history
            .push(HistoryRecord::SignalFrameReturned(Box::new(FrameReturn {
                origin: id,
                before: stored.current.clone(),
                frame: Arc::clone(frame),
                witness,
            })));
        self.state.origins[index].active = false;
        self.commit_debit(token, remaining, used);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum SignalConsumption {
    Rendezvous {
        execution: ExecutionId,
        first_instruction: Vec<u8>,
    },
    Delivery {
        frame: SignalFrameId,
    },
    Return(Box<SignalReturnWitness>),
}
impl SignalConsumption {
    pub(in crate::linux::remote::dynamic::owner::admission) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + match self {
                Self::Rendezvous {
                    first_instruction, ..
                } => first_instruction.len(),
                Self::Delivery { .. } => 0,
                Self::Return(witness) => {
                    std::mem::size_of::<SignalReturnWitness>()
                        + witness.entry.retained_bytes()
                        + witness.returned.retained_bytes()
                        + witness.expected.retained_bytes()
                }
            }
    }
}
impl OwnerConsumption {
    /// A real signal-delivery boundary reached under one original-run permit.
    /// This does not consume the retained signal obligation or a frame origin.
    pub(in crate::linux::remote::dynamic::owner::admission) fn signal_rendezvous(
        execution: ExecutionId,
        before: ObservedStop,
        first_instruction: Vec<u8>,
        successor: ObservedStop,
    ) -> Result<Self, CensusError> {
        decode_whole(before.logical_pc, &first_instruction)?;
        successor_matches(&before, &successor)?;
        if execution.session != before.token.session
            || successor.phase != StopPhase::OriginalSignal
            || !matches!(
                before.phase,
                StopPhase::UserCheckpoint | StopPhase::Interrupted
            )
        {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(Self {
            before,
            successor,
            evidence: Consumption::Signal(Box::new(SignalConsumption::Rendezvous {
                execution,
                first_instruction,
            })),
        })
    }
    /// The native caller retains the released signal and raw NX handler state;
    /// frame origins are inserted separately from those actual captured bytes.
    pub(in crate::linux::remote::dynamic::owner::admission) fn signal_delivery(
        frame: SignalFrameId,
        before: ObservedStop,
        successor: ObservedStop,
    ) -> Result<Self, CensusError> {
        successor_matches(&before, &successor)?;
        if frame.session != before.token.session
            || frame.serial == 0
            || before.phase != StopPhase::OriginalSignal
            || successor.phase != StopPhase::OwnedFetch
        {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(Self {
            before,
            successor,
            evidence: Consumption::Signal(Box::new(SignalConsumption::Delivery { frame })),
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn signal_return(
        before: ObservedStop,
        witness: SignalReturnWitness,
    ) -> Result<Self, CensusError> {
        successor_matches(&before, &witness.entry)?;
        successor_matches(&witness.entry, &witness.returned)?;
        if !matches!(before.phase, StopPhase::UserCheckpoint)
            || witness.entry.phase
                != (StopPhase::SyscallEntry {
                    syscall: libc::SYS_rt_sigreturn as u64,
                })
            || witness.returned.phase != StopPhase::SignalReturn
            || witness.frame.session != before.token.session
        {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(Self {
            before,
            successor: witness.returned.clone(),
            evidence: Consumption::Signal(Box::new(SignalConsumption::Return(Box::new(witness)))),
        })
    }
}

impl ResumeCensus {
    /// Signal-specific current register stop. The ordinary insert API retains
    /// its original phase restrictions and cannot manufacture this path.
    pub(in crate::linux::remote::dynamic::owner::admission) fn insert_signal_current(
        &mut self,
        token: Reservation,
        observed: ObservedStop,
    ) -> Result<OriginId, CensusError> {
        observed.validate(self.session, self.space)?;
        if observed.task.generation != self.state.generation
            || !matches!(
                observed.phase,
                StopPhase::OriginalSignal | StopPhase::SignalReturn
            )
        {
            return Err(CensusError::WrongOriginPhase);
        }
        let bytes = observed
            .retained_bytes()
            .checked_mul(2)
            .and_then(|value| value.checked_add(std::mem::size_of::<StoredOrigin>()))
            .ok_or(CensusError::Capacity)?;
        let (remaining, used) = self.prepare_debit(
            token,
            BudgetCharge {
                origins: 1,
                source_fact_bytes: bytes,
                ..BudgetCharge::default()
            },
        )?;
        let serial = self.state.next_serial;
        let next = serial.checked_add(1).ok_or(CensusError::Capacity)?;
        let id = OriginId {
            census: self.identity,
            serial,
        };
        self.state.origins.push(StoredOrigin {
            row: OriginRow {
                id,
                kind: OriginKind::CurrentHeldPc,
                pc: observed.logical_pc,
                created_generation: self.state.generation,
                initial: observed.clone(),
            },
            current: observed,
            active: true,
            frame: None,
            runtime_kernel: None,
            ordinary_history: None,
        });
        self.state.next_serial = next;
        self.commit_debit(token, remaining, used);
        Ok(id)
    }
}
