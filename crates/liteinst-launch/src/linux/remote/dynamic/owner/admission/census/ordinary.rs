//! Consuming ordinary-instruction bookkeeping. No native operation or permit
//! constructor exists here. Pure controls exercise only private model views.
use super::super::super::trusted::{AdmissionPhase, TaskStateSnapshot};
use super::super::runtime::instruction::RuntimeInstructionBinding;
use super::super::runtime_capture::SourceWindowId;
use super::super::runtime_instruction::{CandidateKind, InstructionCandidate};
use super::super::runtime_native::{NativeCheckpoint, NativeTrace, OwnedInstructionCompletion};
use super::*;
use liteinst2::contracts::CodeIdentity;
use std::mem::size_of;
use std::time::Instant;

pub(super) mod shared;
mod shared_commit;
#[cfg(test)]
pub(in super::super) use shared_commit::OrdinaryPreparationHistorySnapshot;
pub(super) use shared_commit::SharedOrdinaryOwner;
pub(in super::super) use shared_commit::{
    SharedOrdinaryPreparation, ordinary_shared_census_charge,
};

// The separately manifested calls.rs is deliberately not declared here. Its
// production integration waits for native operand/stack custody support.
#[cfg(test)]
mod allocation_oracle;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner::admission) use allocation_oracle::AllocationCensusSnapshot;

const PRIVATE_PER_SIDE: usize = 3;
#[cfg(test)]
const NEW_STATES: usize = 16;
const WITNESSES: usize = 7;
const TRACE_DR6: u64 = 0xffff0ff0 ^ 0x4000;

/// Copy of a catalog identity, not a constructor for the opaque source handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceRecord {
    identity: CodeIdentity,
    index: usize,
}
impl From<SourceWindowId> for SourceRecord {
    fn from(value: SourceWindowId) -> Self {
        Self {
            identity: value.identity(),
            index: value.index(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Encoding {
    pc: u64,
    next: u64,
    length: usize,
    bytes: [u8; 15],
}
impl Encoding {
    fn new(pc: u64, bytes: &[u8]) -> Result<Self, CensusError> {
        let decoded = decode_whole(pc, bytes)?;
        let mut retained = [0; 15];
        retained[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            pc,
            next: decoded.next_ip(),
            length: bytes.len(),
            bytes: retained,
        })
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Binding {
    census: u64,
    reservation: Reservation,
    candidate_serial: u64,
    origin: OriginId,
    execution: ExecutionId,
    source: SourceRecord,
    encoding: Encoding,
    until: Instant,
}

/// Immutable description retained after the one-use native capability is gone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in super::super) struct OrdinaryEvidence {
    binding: Binding,
    trace: Option<NativeTrace>,
}

/// Non-Clone pre-effect storage. Its header remains retained after all payload
/// transfers. Allocation/debit happens before effects, including unused MAX.
#[cfg(test)]
pub(in super::super) struct PreparedOrdinaryCensus {
    binding: Binding,
    before: ObservedStop,
    buffers: [Vec<u8>; NEW_STATES - 1],
    evidence: Option<Box<[OrdinaryEvidence]>>,
    preparation_debit: usize,
    committed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct OrdinaryCensusResult {
    pub(in super::super) current: OriginId,
}

fn add(a: usize, b: usize) -> Result<usize, CensusError> {
    a.checked_add(b).ok_or(CensusError::Capacity)
}
fn mul(a: usize, b: usize) -> Result<usize, CensusError> {
    a.checked_mul(b).ok_or(CensusError::Capacity)
}
#[cfg(test)]
fn fixed_commit_bytes() -> Result<usize, CensusError> {
    // Exactly the existing logical refresh/consumption/insertion header
    // convention: 7 before +9 after observations, six refresh wrappers, one
    // consumption and one StoredOrigin. Evidence payload is prepaid separately.
    add(
        add(
            mul(NEW_STATES, size_of::<ObservedStop>())?,
            mul(6, size_of::<HistoryRecord>())?,
        )?,
        add(size_of::<OwnerConsumption>(), size_of::<StoredOrigin>())?,
    )
}
#[cfg(test)]
fn preparation_bytes(capacities: usize) -> Result<usize, CensusError> {
    add(
        add(size_of::<PreparedOrdinaryCensus>(), capacities)?,
        size_of::<OrdinaryEvidence>(),
    )
}

/// Six private refreshes, one original consumption and one new register origin.
/// No epoch/report/plan is fabricated. MAX is deliberately not an extent guess.
#[cfg(test)]
pub(in super::super) fn ordinary_census_charge() -> Result<BudgetCharge, CensusError> {
    Ok(BudgetCharge {
        origins: 1,
        witnesses: WITNESSES,
        source_fact_bytes: add(
            preparation_bytes(mul(NEW_STATES, MAX_XSTATE_BYTES)?)?,
            fixed_commit_bytes()?,
        )?,
        ..BudgetCharge::default()
    })
}

#[cfg(test)]
fn buffer() -> Result<Vec<u8>, CensusError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(MAX_XSTATE_BYTES)
        .map_err(|_| CensusError::Allocation)?;
    if result.capacity() != MAX_XSTATE_BYTES {
        return Err(CensusError::Capacity);
    }
    Ok(result)
}
#[cfg(test)]
fn copy_observed(source: &ObservedStop, mut bytes: Vec<u8>) -> ObservedStop {
    bytes.extend_from_slice(&source.xstate);
    ObservedStop {
        token: source.token.clone(),
        task: source.task,
        logical_pc: source.logical_pc,
        registers: source.registers,
        xstate: bytes,
        signal_mask: source.signal_mask,
        phase: source.phase,
        signal: source.signal.clone(),
    }
}
#[cfg(test)]
fn copy_checkpoint(
    source: NativeCheckpoint<'_>,
    mut bytes: Vec<u8>,
    phase: StopPhase,
    signal: Option<DynamicSignalInfo>,
) -> ObservedStop {
    bytes.extend_from_slice(&source.state.xstate);
    ObservedStop {
        token: source.stop.token.clone(),
        task: source.stop.identity,
        logical_pc: source.state.registers.rip,
        registers: source.state.registers,
        xstate: bytes,
        signal_mask: source.state.mask,
        phase,
        signal,
    }
}
fn same_architecture(observed: &ObservedStop, state: &TaskStateSnapshot) -> bool {
    observed.registers == state.registers
        && observed.xstate == state.xstate
        && observed.signal_mask == state.mask
}
fn valid_state(state: &TaskStateSnapshot) -> bool {
    state.registers.cs == 0x33
        && state.registers.rip != 0
        && state.registers.orig_rax == u64::MAX
        && (512..MAX_XSTATE_BYTES).contains(&state.xstate.len())
}
fn checkpoint_identity(before: &ObservedStop, checkpoint: NativeCheckpoint<'_>) -> bool {
    checkpoint.stop.identity == before.task
        && checkpoint.stop.token.session == before.token.session
        && checkpoint.stop.token.tid == before.token.tid
        && checkpoint.stop.token.task == before.token.task
        && valid_state(checkpoint.state)
}
// Only the logical-before/opening family may inherit an exact sealed kernel
// register value. STEP and closing retain the original MAX-only predicate.
fn opening_checkpoint_identity(before: &ObservedStop, checkpoint: NativeCheckpoint<'_>) -> bool {
    checkpoint.stop.identity == before.task
        && checkpoint.stop.token.session == before.token.session
        && checkpoint.stop.token.tid == before.token.tid
        && checkpoint.stop.token.task == before.token.task
        && checkpoint.state.registers.cs == 0x33
        && checkpoint.state.registers.rip != 0
        && checkpoint.state.registers.orig_rax == before.registers.orig_rax
        && (512..MAX_XSTATE_BYTES).contains(&checkpoint.state.xstate.len())
}
fn validate_candidate(
    source: SourceRecord,
    candidate: &InstructionCandidate<'_>,
    before: &ObservedStop,
) -> Result<Encoding, CensusError> {
    if !matches!(candidate.kind(), CandidateKind::Ordinary(_))
        || candidate.registers() != &before.registers
        || candidate.snapshot().mapping.0 != source.identity.mapping
        || candidate.snapshot().generation.0 != source.identity.generation
        || source.identity.generation != before.task.generation
        || source.identity.mapping == 0
        || candidate.range().start() != before.logical_pc
    {
        return Err(CensusError::IdentityMismatch);
    }
    let encoding = Encoding::new(before.logical_pc, candidate.bytes())?;
    if encoding.next != candidate.next_pc() {
        return Err(CensusError::InvalidConsumption);
    }
    Ok(encoding)
}

#[cfg(test)]
impl PreparedOrdinaryCensus {
    /// Current storage owned by preparation only. Moved census payload remains
    /// charged in the same account; this accessor is not a refund calculation.
    pub(in super::super) fn allocated_bytes(&self) -> Result<usize, CensusError> {
        let capacities = self
            .buffers
            .iter()
            .try_fold(self.before.xstate.capacity(), |total, bytes| {
                add(total, bytes.capacity())
            })?;
        add(
            add(size_of::<Self>(), capacities)?,
            self.evidence
                .as_ref()
                .map_or(0, |v| v.len() * size_of::<OrdinaryEvidence>()),
        )
    }
    pub(in super::super) fn remaining_charge(&self) -> Result<BudgetCharge, CensusError> {
        if self.committed {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(BudgetCharge {
            origins: 1,
            witnesses: WITNESSES,
            source_fact_bytes: fixed_commit_bytes()?,
            ..BudgetCharge::default()
        })
    }
}

/// Borrowed descriptive projection, not a native capability. Production may
/// construct this only inside the consuming shared adapter or its archive
/// copy from the borrowed genuine seal. Pure model controls remain cfg(test).
struct CompletionModel<'a> {
    source: SourceRecord,
    origin: OriginId,
    execution: ExecutionId,
    until: Instant,
    encoding: &'a [u8],
    logical: NativeCheckpoint<'a>,
    opening: [NativeCheckpoint<'a>; PRIVATE_PER_SIDE],
    step: NativeCheckpoint<'a>,
    closing: [NativeCheckpoint<'a>; PRIVATE_PER_SIDE],
    trace: NativeTrace,
}

impl ResumeCensus {
    /// Read-only model lookup. The caller still authenticates actual native
    /// custody; this borrow neither clones state nor grants release authority.
    pub(in super::super) fn current_observation(
        &self,
        id: OriginId,
    ) -> Result<&ObservedStop, CensusError> {
        let stored = &self.state.origins[self.active_index(id)?];
        if stored.row.kind != OriginKind::CurrentHeldPc || stored.frame.is_some() {
            return Err(CensusError::WrongOriginPhase);
        }
        self.check_current_origin(id, &stored.current)?;
        Ok(&stored.current)
    }

    #[cfg(test)]
    fn prepare_model(
        &mut self,
        reservation: Reservation,
        origin: OriginId,
        execution: ExecutionId,
        source: SourceRecord,
        encoding: Encoding,
        until: Instant,
    ) -> Result<PreparedOrdinaryCensus, CensusError> {
        self.check_reserved(reservation, ordinary_census_charge()?)?;
        let before = self.current_observation(origin)?;
        if execution.session != self.session
            || execution.serial == 0
            || source.identity.mapping == 0
            || source.identity.generation != self.state.generation
        {
            return Err(CensusError::IdentityMismatch);
        }
        if before.phase != StopPhase::UserCheckpoint
            || before.signal.is_some()
            || before.task.generation != 0
            || before.logical_pc != encoding.pc
            || Instant::now() >= until
            || !(512..MAX_XSTATE_BYTES).contains(&before.xstate.len())
        {
            return Err(CensusError::StaleObservation);
        }
        self.runtime_register_provenance(origin)?;
        if self.state.origins.len() == self.state.origins.capacity()
            || self
                .state
                .history
                .capacity()
                .saturating_sub(self.state.history.len())
                < WITNESSES
        {
            return Err(CensusError::Capacity);
        }
        self.state
            .next_serial
            .checked_add(1)
            .ok_or(CensusError::Capacity)?;
        let binding = Binding {
            census: self.identity,
            reservation,
            candidate_serial: self.state.next_serial,
            origin,
            execution,
            source,
            encoding,
            until,
        };
        let before = copy_observed(before, buffer()?);
        let mut buffers = std::array::from_fn(|_| Vec::new());
        for bytes in &mut buffers {
            *bytes = buffer()?;
        }
        let mut record = Vec::new();
        record
            .try_reserve_exact(1)
            .map_err(|_| CensusError::Allocation)?;
        if record.capacity() != 1 {
            return Err(CensusError::Capacity);
        }
        record.push(OrdinaryEvidence {
            binding,
            trace: None,
        });
        let mut prepared = PreparedOrdinaryCensus {
            binding,
            before,
            buffers,
            evidence: Some(record.into_boxed_slice()),
            preparation_debit: 0,
            committed: false,
        };
        let bytes = prepared.allocated_bytes()?;
        if add(bytes, fixed_commit_bytes()?)? > ordinary_census_charge()?.source_fact_bytes {
            return Err(CensusError::Capacity);
        }
        // All retained preparation, including unused MAX capacity, is debited
        // before native effects and survives a later failed or absent commit.
        self.account_external(
            reservation,
            BudgetCharge {
                source_fact_bytes: bytes,
                ..BudgetCharge::default()
            },
        )?;
        prepared.preparation_debit = bytes;
        Ok(prepared)
    }

    #[cfg(test)]
    fn validate_model(
        &self,
        reservation: Reservation,
        actual: &CompletionModel<'_>,
        prepared: &PreparedOrdinaryCensus,
    ) -> Result<(usize, u64, BudgetCharge, BudgetCharge), CensusError> {
        let expected = prepared.binding;
        if prepared.committed
            || expected.census != self.identity
            || expected.reservation != reservation
            || actual.origin != expected.origin
            || actual.execution != expected.execution
            || actual.source != expected.source
            || actual.until != expected.until
            || actual.encoding != expected.encoding.bytes()
        {
            return Err(CensusError::IdentityMismatch);
        }
        let index = self.active_index(expected.origin)?;
        let before = self.current_observation(expected.origin)?;
        if before != &prepared.before
            || Instant::now() >= expected.until
            || before.task.generation != self.state.generation
        {
            return Err(CensusError::StaleObservation);
        }
        self.runtime_register_provenance(expected.origin)?;
        if !opening_checkpoint_identity(before, actual.logical)
            || actual.logical.stop.token != before.token
            || actual.logical.stop.signal.is_some()
            || !matches!(
                actual.logical.stop.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
            || !same_architecture(before, actual.logical.state)
        {
            return Err(CensusError::InvalidConsumption);
        }
        let mut sequence = before.token.sequence;
        for stop in actual.opening {
            if !opening_checkpoint_identity(before, stop)
                || stop.stop.token.sequence <= sequence
                || stop.stop.phase != AdmissionPhase::Restored
                || stop.stop.signal.is_some()
                || !same_architecture(before, stop.state)
            {
                return Err(CensusError::InvalidConsumption);
            }
            sequence = stop.stop.token.sequence;
        }
        let step = actual.step;
        let signal = DynamicSignalInfo {
            raw: actual.trace.signal,
        };
        if !checkpoint_identity(before, step) || step.stop.token.sequence <= sequence
            || step.stop.phase != AdmissionPhase::NativeCompleted
            // NativeCompleted is an owned control stop, not a queued application
            // signal. Actual trace siginfo is retained separately by the seal.
            || step.stop.signal.is_some()
            || actual.trace.ordinal != 3 || actual.trace.tid != before.token.tid
            || !libc::WIFSTOPPED(actual.trace.status)
            || libc::WSTOPSIG(actual.trace.status) != libc::SIGTRAP
            || actual.trace.status >> 16 != 0 || actual.trace.dr6 != TRACE_DR6
            || signal.signal() != libc::SIGTRAP || signal.errno() != 0
            || signal.code() != libc::TRAP_TRACE
            || u64::from_ne_bytes(actual.trace.signal[16..24].try_into().unwrap()) != step.state.registers.rip
        {
            return Err(CensusError::InvalidConsumption);
        }
        sequence = step.stop.token.sequence;
        for stop in actual.closing {
            if !checkpoint_identity(before, stop)
                || stop.stop.token.sequence <= sequence
                || stop.stop.phase != AdmissionPhase::Restored
                || stop.stop.signal.is_some()
                || stop.state != step.state
            {
                return Err(CensusError::InvalidConsumption);
            }
            sequence = stop.stop.token.sequence;
        }
        if prepared.before.xstate.capacity() != MAX_XSTATE_BYTES
            || prepared
                .buffers
                .iter()
                .any(|bytes| !bytes.is_empty() || bytes.capacity() != MAX_XSTATE_BYTES)
            || prepared
                .evidence
                .as_ref()
                .is_none_or(|v| v.len() != 1 || v[0].binding != expected || v[0].trace.is_some())
            || prepared.preparation_debit != preparation_bytes(NEW_STATES * MAX_XSTATE_BYTES)?
            || self.state.origins.len() == self.state.origins.capacity()
            || self
                .state
                .history
                .capacity()
                .saturating_sub(self.state.history.len())
                < WITNESSES
        {
            return Err(CensusError::Capacity);
        }
        let next = self
            .state
            .next_serial
            .checked_add(1)
            .ok_or(CensusError::Capacity)?;
        if self.state.next_serial != expected.candidate_serial {
            return Err(CensusError::StaleObservation);
        }
        let (remaining, used) = self.prepare_debit(reservation, prepared.remaining_charge()?)?;
        Ok((index, next, remaining, used))
    }

    #[cfg(test)]
    fn commit_model(
        &mut self,
        reservation: Reservation,
        actual: &CompletionModel<'_>,
        prepared: &mut PreparedOrdinaryCensus,
    ) -> Result<OrdinaryCensusResult, CensusError> {
        // Includes the final row and every capacity/serial/debit check. No
        // census mutation or payload transfer occurs before this succeeds.
        let (old, next, remaining, used) = self.validate_model(reservation, actual, prepared)?;
        let id = OriginId {
            census: self.identity,
            serial: self.state.next_serial,
        };
        let phase = StopPhase::OwnedOrdinaryComplete {
            execution: prepared.binding.execution,
        };
        let signal = Some(DynamicSignalInfo {
            raw: actual.trace.signal,
        });
        let mut slot = 0;
        for index in 0..PRIVATE_PER_SIDE {
            let before = if index == 0 {
                ObservedStop {
                    token: prepared.before.token.clone(),
                    task: prepared.before.task,
                    logical_pc: prepared.before.logical_pc,
                    registers: prepared.before.registers,
                    xstate: std::mem::take(&mut prepared.before.xstate),
                    signal_mask: prepared.before.signal_mask,
                    phase: prepared.before.phase,
                    signal: prepared.before.signal.clone(),
                }
            } else {
                copy_checkpoint(
                    actual.opening[index - 1],
                    next_buffer(&mut prepared.buffers, &mut slot),
                    StopPhase::UserCheckpoint,
                    None,
                )
            };
            let after = copy_checkpoint(
                actual.opening[index],
                next_buffer(&mut prepared.buffers, &mut slot),
                StopPhase::UserCheckpoint,
                None,
            );
            self.state.history.push(HistoryRecord::Refreshed {
                origin: prepared.binding.origin,
                before,
                after,
            });
        }
        // These original current-state bytes are already owned and exactly
        // unchanged across opening. Only the authenticated token advances.
        self.state.origins[old].current.token = actual.opening[2].stop.token.clone();
        let before = copy_checkpoint(
            actual.opening[2],
            next_buffer(&mut prepared.buffers, &mut slot),
            StopPhase::UserCheckpoint,
            None,
        );
        let successor = copy_checkpoint(
            actual.step,
            next_buffer(&mut prepared.buffers, &mut slot),
            phase,
            signal.clone(),
        );
        let mut records = prepared.evidence.take().unwrap();
        records[0].trace = Some(actual.trace);
        self.state.history.push(HistoryRecord::Consumed {
            origin: prepared.binding.origin,
            evidence: OwnerConsumption {
                before,
                successor,
                evidence: Consumption::OwnedOrdinary(records),
            },
        });
        self.state.origins[old].active = false;
        let initial = copy_checkpoint(
            actual.step,
            next_buffer(&mut prepared.buffers, &mut slot),
            phase,
            signal.clone(),
        );
        let current = copy_checkpoint(
            actual.closing[2],
            next_buffer(&mut prepared.buffers, &mut slot),
            StopPhase::UserCheckpoint,
            None,
        );
        self.state.origins.push(StoredOrigin {
            row: OriginRow {
                id,
                kind: OriginKind::CurrentHeldPc,
                pc: initial.logical_pc,
                created_generation: self.state.generation,
                initial,
            },
            current,
            active: true,
            frame: None,
            runtime_kernel: None,
            ordinary_history: None,
        });
        for index in 0..PRIVATE_PER_SIDE {
            let before = if index == 0 {
                copy_checkpoint(
                    actual.step,
                    next_buffer(&mut prepared.buffers, &mut slot),
                    phase,
                    signal.clone(),
                )
            } else {
                copy_checkpoint(
                    actual.closing[index - 1],
                    next_buffer(&mut prepared.buffers, &mut slot),
                    StopPhase::UserCheckpoint,
                    None,
                )
            };
            let after = copy_checkpoint(
                actual.closing[index],
                next_buffer(&mut prepared.buffers, &mut slot),
                StopPhase::UserCheckpoint,
                None,
            );
            self.state.history.push(HistoryRecord::Refreshed {
                origin: id,
                before,
                after,
            });
        }
        self.state.next_serial = next;
        self.commit_debit(reservation, remaining, used);
        prepared.committed = true;
        Ok(OrdinaryCensusResult { current: id })
    }
}

#[cfg(test)]
fn next_buffer(buffers: &mut [Vec<u8>; NEW_STATES - 1], slot: &mut usize) -> Vec<u8> {
    let index = *slot;
    *slot += 1;
    std::mem::take(&mut buffers[index])
}
