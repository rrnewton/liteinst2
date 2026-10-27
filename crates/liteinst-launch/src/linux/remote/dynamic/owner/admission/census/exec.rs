//! Atomic bookkeeping handoff after a separately authenticated native exec.
//!
//! This module never authenticates a kernel transition. The root-owned seal is
//! mandatory; descriptive bindings, model rows and source replies cannot mint
//! it. The same ResumeCensus retains the sole lifetime account across the move.

use super::super::exec::ExecCensusCommit;
use super::*;
#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
mod oracle;

/// Descriptive, non-authoritative identity fixed before the original effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct ExecCensusBinding {
    census: u64,
    pub(in super::super) session: u64,
    pub(in super::super) space: AddressSpaceId,
    pub(in super::super) generation: u64,
    pub(in super::super) reservation: Reservation,
    pub(in super::super) origin: OriginId,
    pub(in super::super) invocation: ExecutionId,
}

/// Exact model facts the native seal must bind to its retained original
/// invocation, last old-mm checkpoint and actual new bootstrap checkpoint.
pub(in super::super) struct ExecCensusIdentity<'a> {
    pub(in super::super) binding: ExecCensusBinding,
    pub(in super::super) before: &'a ObservedStop,
    pub(in super::super) after: &'a ObservedStop,
}

/// Pre-effect storage only. This is neither a census nor an execution permit.
pub(in super::super) struct PreparedExecCensus {
    binding: ExecCensusBinding,
    identity: u64,
    origins: Vec<StoredOrigin>,
    history: Vec<HistoryRecord>,
    initial_xstate: Vec<u8>,
    current_xstate: Vec<u8>,
}

impl PreparedExecCensus {
    pub(in super::super) fn binding(&self) -> ExecCensusBinding {
        self.binding
    }
}

/// Whole-mm replacement is distinct from executing any old origin's successor.
/// Full native phase evidence remains in the separately retained owner journal.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Retirement {
    binding: ExecCensusBinding,
    old_stop: DynamicStop,
    new_stop: DynamicStop,
    new_task: DynamicTask,
}

/// Immutable old rows/history moved without changing an active flag or adding
/// a fake consumption. Accounting values are diagnostic snapshots only: there
/// is no reserve, debit, projection, insertion or native-control API here.
pub(in super::super) struct RetiredCensus {
    retirement: Retirement,
    charged_at_retirement: BudgetCharge,
    used_at_retirement: BudgetCharge,
    origins: Vec<StoredOrigin>,
    history: Vec<HistoryRecord>,
}

impl RetiredCensus {
    pub(in super::super) fn binding(&self) -> ExecCensusBinding {
        self.retirement.binding
    }

    pub(in super::super) fn rows(&self) -> impl Iterator<Item = &OriginRow> {
        self.origins.iter().map(|row| &row.row)
    }

    pub(in super::super) fn history(&self) -> &[HistoryRecord] {
        &self.history
    }

    #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
    pub(in super::super) fn history_snapshot(&self) -> Result<HistorySnapshot, CensusError> {
        super::history::retired_snapshot(
            self.retirement.binding.census,
            &self.origins,
            &self.history,
            self.history.len(),
            true,
        )
    }

    /// These values must not be summed as a second active lifetime account.
    pub(in super::super) fn accounting_at_retirement(&self) -> (BudgetCharge, BudgetCharge) {
        (self.charged_at_retirement, self.used_at_retirement)
    }
}

/// Prepaid initial-record charge. Use MAX_XSTATE_BYTES before actual exec: an
/// old-mm extent certificate does not certify the replacement mm. Commit uses
/// the actual authenticated length with the identical existing insert formula.
/// Retired Vec payloads are moved, not copied or charged a second time.
pub(in super::super) fn exec_initial_charge(
    xstate_bytes: usize,
) -> Result<BudgetCharge, CensusError> {
    if xstate_bytes == 0 || xstate_bytes > MAX_XSTATE_BYTES {
        return Err(CensusError::InvalidObservation);
    }
    let origin_bytes = std::mem::size_of::<ObservedStop>()
        .checked_add(xstate_bytes)
        .and_then(|value| value.checked_mul(2))
        .and_then(|value| value.checked_add(std::mem::size_of::<StoredOrigin>()))
        .ok_or(CensusError::Capacity)?;
    let bytes = origin_bytes
        .checked_add(std::mem::size_of::<RetiredCensus>())
        .ok_or(CensusError::Capacity)?;
    Ok(BudgetCharge {
        epochs: 1,
        source_fact_bytes: bytes,
        origins: 1,
        witnesses: 1,
        ..BudgetCharge::default()
    })
}

fn next_identity(counter: &AtomicU64) -> Result<u64, CensusError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            if value == 0 {
                None
            } else {
                value.checked_add(1)
            }
        })
        .map_err(|_| CensusError::Capacity)
}

fn preallocated_copy(source: &ObservedStop, mut xstate: Vec<u8>) -> ObservedStop {
    // The caller has checked length <= capacity before any mutation of self.
    // No generic state or flags normalization occurs in either copy.
    xstate.extend_from_slice(&source.xstate);
    ObservedStop {
        token: source.token.clone(),
        task: source.task,
        logical_pc: source.logical_pc,
        registers: source.registers,
        xstate,
        signal_mask: source.signal_mask,
        phase: source.phase,
        signal: source.signal.clone(),
    }
}

impl ResumeCensus {
    fn exec_current(&self, origin: OriginId) -> Result<&ObservedStop, CensusError> {
        let index = self.active_index(origin)?;
        let stored = &self.state.origins[index];
        if self.state.origins.iter().filter(|row| row.active).count() != 1
            || stored.row.kind != OriginKind::CurrentHeldPc
        {
            return Err(CensusError::PersistentUnknown);
        }
        self.check_current_origin(origin, &stored.current)?;
        if stored.current.phase != StopPhase::UserCheckpoint
            || stored.current.signal.is_some()
            || stored.current.registers.orig_rax != u64::MAX
        {
            return Err(CensusError::WrongOriginPhase);
        }
        Ok(&stored.current)
    }

    /// Allocate the future identity, initial state copies and row/history
    /// capacity before any native effect. This does not change the live census,
    /// consume a reservation, or authenticate retirement. Nonce issuance is
    /// monotone; a dropped preparation never makes its identity reusable.
    pub(in super::super) fn prepare_exec_mm(
        &mut self,
        reservation: Reservation,
        origin: OriginId,
        invocation: ExecutionId,
    ) -> Result<PreparedExecCensus, CensusError> {
        let remaining = self.remaining(reservation)?;
        self.exec_current(origin)?;
        if invocation.session != self.session || invocation.serial == 0 {
            return Err(CensusError::IdentityMismatch);
        }
        self.check_reserved(reservation, exec_initial_charge(MAX_XSTATE_BYTES)?)?;
        let history_slots = remaining
            .witnesses
            .checked_add(remaining.epochs)
            .ok_or(CensusError::Capacity)?;
        let mut origins = Vec::new();
        origins
            .try_reserve(remaining.origins)
            .map_err(|_| CensusError::Allocation)?;
        let mut history = Vec::new();
        history
            .try_reserve(history_slots)
            .map_err(|_| CensusError::Allocation)?;
        let mut initial_xstate = Vec::new();
        initial_xstate
            .try_reserve_exact(MAX_XSTATE_BYTES)
            .map_err(|_| CensusError::Allocation)?;
        let mut current_xstate = Vec::new();
        current_xstate
            .try_reserve_exact(MAX_XSTATE_BYTES)
            .map_err(|_| CensusError::Allocation)?;
        let identity = next_identity(&NEXT_CENSUS)?;
        Ok(PreparedExecCensus {
            binding: ExecCensusBinding {
                census: self.identity,
                session: self.session,
                space: self.space,
                generation: self.state.generation,
                reservation,
                origin,
                invocation,
            },
            identity,
            origins,
            history,
            initial_xstate,
            current_xstate,
        })
    }

    /// Validate completely, then rotate this same lifetime account in place.
    /// Every returned error preserves the old logical self exactly. The root
    /// must keep original release closed on error and retain actual exec facts
    /// in its Owner-held journal; unchanged model fields do not revive old mm.
    pub(in super::super) fn commit_exec_mm(
        &mut self,
        reservation: Reservation,
        mut prepared: PreparedExecCensus,
        actual: ExecCensusCommit,
        new_initial: &ObservedStop,
    ) -> Result<(RetiredCensus, Reservation, OriginId), CensusError> {
        self.remaining(reservation)?;
        let binding = prepared.binding;
        if binding.census != self.identity
            || binding.session != self.session
            || binding.space != self.space
            || binding.generation != self.state.generation
            || binding.reservation != reservation
            || binding.invocation.session != self.session
            || binding.invocation.serial == 0
            || prepared.identity == 0
            || prepared.identity == self.identity
        {
            return Err(CensusError::IdentityMismatch);
        }
        let before = self.exec_current(binding.origin)?;
        new_initial.validate(self.session, new_initial.task.address_space)?;
        if new_initial.task.task == before.task.task
            || new_initial.task.address_space == self.space
            || new_initial.task.process != before.task.process
            || new_initial.token.tid != before.token.tid
        {
            return Err(CensusError::IdentityMismatch);
        }
        // The actual exec event creates a fresh TaskId with sequence zero.
        // Stop sequences order observations only inside one TaskId; comparing
        // this bootstrap against the old task's numeric sequence is invalid.
        // The native seal separately proves new-task EXEC(0) -> EXIT -> this
        // genuine bootstrap, and binds both complete observations below.
        if new_initial.task.generation != 0 || new_initial.token.sequence == 0 {
            return Err(CensusError::StaleObservation);
        }
        if new_initial.phase != StopPhase::UserCheckpoint
            || new_initial.signal.is_some()
            || new_initial.registers.orig_rax != u64::MAX
        {
            return Err(CensusError::WrongOriginPhase);
        }
        actual.validate_census_transition(&ExecCensusIdentity {
            binding,
            before,
            after: new_initial,
        })?;
        let charge = exec_initial_charge(new_initial.xstate.len())?;
        let (remaining, used) = self.prepare_debit(reservation, charge)?;
        let history_slots = remaining
            .witnesses
            .checked_add(remaining.epochs)
            .ok_or(CensusError::Capacity)?;
        if !prepared.origins.is_empty()
            || !prepared.history.is_empty()
            || !prepared.initial_xstate.is_empty()
            || !prepared.current_xstate.is_empty()
            || prepared.origins.capacity()
                < remaining
                    .origins
                    .checked_add(1)
                    .ok_or(CensusError::Capacity)?
            || prepared.history.capacity() < history_slots
            || prepared.initial_xstate.capacity() < new_initial.xstate.len()
            || prepared.current_xstate.capacity() < new_initial.xstate.len()
        {
            return Err(CensusError::Allocation);
        }
        let new_reservation = Reservation {
            census: prepared.identity,
            serial: 1,
        };
        let new_origin = OriginId {
            census: prepared.identity,
            serial: 2,
        };
        let retirement = Retirement {
            binding,
            old_stop: before.token.clone(),
            new_stop: new_initial.token.clone(),
            new_task: new_initial.task,
        };
        let initial = preallocated_copy(new_initial, prepared.initial_xstate);
        let current = preallocated_copy(new_initial, prepared.current_xstate);
        prepared.origins.push(StoredOrigin {
            row: OriginRow {
                id: new_origin,
                kind: OriginKind::CurrentHeldPc,
                pc: new_initial.logical_pc,
                created_generation: 0,
                initial,
            },
            current,
            active: true,
            frame: None,
            runtime_kernel: None,
            ordinary_history: None,
        });

        // All checks, allocation and arithmetic are complete. These moves are
        // infallible, preserve old rows/history exactly, and leave one account.
        let retired = RetiredCensus {
            retirement,
            charged_at_retirement: self.state.charged,
            used_at_retirement: self.state.used,
            origins: std::mem::replace(&mut self.state.origins, prepared.origins),
            history: std::mem::replace(&mut self.state.history, prepared.history),
        };
        self.identity = prepared.identity;
        self.space = new_initial.task.address_space;
        self.state.generation = 0;
        self.state.next_serial = 3;
        self.commit_debit(new_reservation, remaining, used);
        Ok((retired, new_reservation, new_origin))
    }
}

#[cfg(test)]
mod tests;
