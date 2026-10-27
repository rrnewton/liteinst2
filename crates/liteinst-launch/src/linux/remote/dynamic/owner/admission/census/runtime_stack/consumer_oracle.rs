//! Fixed, prepaid observations of actual committed seven-transition histories.
//! Supplied comparison inputs are descriptive and never become native seals.
use super::super::super::runtime::stack::RuntimeStackIdentity;
use super::super::super::runtime_stack::operand::StackOperation;
use super::*;
pub(in crate::linux::remote::dynamic::owner::admission::census) mod storage;
use storage::{
    BufferIdentity, CensusConsumerError, ConsumerBindingView, ConsumerProgress, checked_add,
    copy_state, require, state_bytes,
};

pub(in crate::linux::remote::dynamic::owner::admission::census) mod prefix_mirror;

#[cfg(test)]
mod tests;

pub(in crate::linux::remote::dynamic::owner::admission) struct StackConsumerInput<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) start: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) reservation: Reservation,
    pub(in crate::linux::remote::dynamic::owner::admission) identity: &'a RuntimeStackIdentity,
    pub(in crate::linux::remote::dynamic::owner::admission) logical_before: &'a ObservedStop,
    pub(in crate::linux::remote::dynamic::owner::admission) checkpoints: [NativeCheckpoint<'a>; 7],
    pub(in crate::linux::remote::dynamic::owner::admission) trace: NativeTrace,
    pub(in crate::linux::remote::dynamic::owner::admission) words: StackWordViews<'a>,
    pub(in crate::linux::remote::dynamic::owner::admission) call_id: Option<PotentialCallId>,
    pub(in crate::linux::remote::dynamic::owner::admission) sources: &'a PreparedInitialSources,
    pub(in crate::linux::remote::dynamic::owner::admission) current: OriginId,
    pub(in crate::linux::remote::dynamic::owner::admission) native_current: &'a AdmissionStop,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum RowKind {
    Refresh,
    Consumption,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct RowHeader {
    pub(in crate::linux::remote::dynamic::owner::admission) kind: RowKind,
    pub(in crate::linux::remote::dynamic::owner::admission) origin: OriginId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct OriginHeader {
    pub(in crate::linux::remote::dynamic::owner::admission) id: OriginId,
    pub(in crate::linux::remote::dynamic::owner::admission) kind: OriginKind,
    pub(in crate::linux::remote::dynamic::owner::admission) pc: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) generation: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) frame_absent: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) kernel:
        Option<(OriginId, Option<OriginId>)>,
}
impl OriginHeader {
    fn of(value: &StoredOrigin) -> Self {
        Self {
            id: value.row.id,
            kind: value.row.kind,
            pc: value.row.pc,
            generation: value.row.created_generation,
            frame_absent: value.frame.is_none(),
            kernel: value.runtime_kernel.map(|v| (v.returned, v.parent)),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct CensusHeader {
    pub(in crate::linux::remote::dynamic::owner::admission) identity: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) session: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) space: AddressSpaceId,
    pub(in crate::linux::remote::dynamic::owner::admission) limits: Limits,
    pub(in crate::linux::remote::dynamic::owner::admission) generation: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) next_serial: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) charged: BudgetCharge,
    pub(in crate::linux::remote::dynamic::owner::admission) used: BudgetCharge,
    pub(in crate::linux::remote::dynamic::owner::admission) reservation:
        Option<(Reservation, BudgetCharge)>,
    pub(in crate::linux::remote::dynamic::owner::admission) origins_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) origins_length: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) origins_capacity: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) history_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) history_length: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) history_capacity: usize,
}
impl CensusHeader {
    fn of(value: &ResumeCensus) -> Self {
        Self {
            identity: value.identity,
            session: value.session,
            space: value.space,
            limits: value.limits,
            generation: value.state.generation,
            next_serial: value.state.next_serial,
            charged: value.state.charged,
            used: value.state.used,
            reservation: value.state.reservation,
            origins_pointer: value.state.origins.as_ptr() as usize,
            origins_length: value.state.origins.len(),
            origins_capacity: value.state.origins.capacity(),
            history_pointer: value.state.history.as_ptr() as usize,
            history_length: value.state.history.len(),
            history_capacity: value.state.history.capacity(),
        }
    }
}
pub(in crate::linux::remote::dynamic::owner::admission) struct PreparedStackObservation {
    allocation: ConsumerProgress,
    capture: ConsumerProgress,
    payload: usize,
    census: Option<CensusHeader>,
    start: Option<usize>,
    rows: [Option<RowHeader>; 7],
    evidence: Option<StackEvidence>,
    evidence_allocation: Option<(usize, usize)>,
    old_origin: Option<OriginHeader>,
    new_origin: Option<OriginHeader>,
    old_current_allocation: Option<BufferIdentity>,
    states: [Option<ObservedStop>; STATES],
    buffers: [Vec<u8>; STATES],
    actual_allocations: [Option<BufferIdentity>; STATES],
    #[cfg(test)]
    allocation_fault: Option<tests::Fault>,
}
impl PreparedStackObservation {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            allocation: ConsumerProgress::default(),
            capture: ConsumerProgress::default(),
            payload: 0,
            census: None,
            start: None,
            rows: [None; 7],
            evidence: None,
            evidence_allocation: None,
            old_origin: None,
            new_origin: None,
            old_current_allocation: None,
            states: std::array::from_fn(|_| None),
            buffers: std::array::from_fn(|_| Vec::new()),
            actual_allocations: [None; STATES],
            #[cfg(test)]
            allocation_fault: None,
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn reservation_bytes()
    -> Result<usize, CensusConsumerError> {
        checked_add(
            size_of::<Self>(),
            STATES
                .checked_mul(MAX_XSTATE_BYTES)
                .ok_or(CensusConsumerError::Capacity)?,
        )
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocate_payloads(
        &mut self,
    ) -> Result<(), CensusConsumerError> {
        self.allocation.begin()?;
        let result = (|| {
            Self::reservation_bytes()?;
            for index in 0..STATES {
                require(self.states[index].is_none() && self.buffers[index].capacity() == 0)?;
                let next = checked_add(self.payload, MAX_XSTATE_BYTES)?;
                #[cfg(test)]
                tests::before(self.allocation_fault, index)?;
                self.buffers[index] = exact_storage::empty_bytes(MAX_XSTATE_BYTES)?;
                self.payload = next;
                self.allocation.filled = index + 1;
                #[cfg(test)]
                tests::after(self.allocation_fault, index);
            }
            self.allocation.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            self.allocation.fail(error);
        }
        result
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocated_bytes(
        &self,
    ) -> Result<usize, CensusConsumerError> {
        let mut payload = 0;
        for index in 0..STATES {
            payload = checked_add(
                payload,
                state_bytes(&self.states[index], &self.buffers[index])?,
            )?;
        }
        require(payload == self.payload)?;
        checked_add(size_of::<Self>(), payload)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        self.allocation.abort();
        self.capture.abort();
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn progress(
        &self,
    ) -> (&ConsumerProgress, &ConsumerProgress) {
        (&self.allocation, &self.capture)
    }
    fn copy(&mut self, index: usize, value: &ObservedStop) -> Result<(), CensusConsumerError> {
        self.actual_allocations[index] = Some(BufferIdentity::of(&value.xstate));
        copy_state(value, &mut self.states[index], &mut self.buffers[index])?;
        self.capture.filled += 1;
        Ok(())
    }
    fn matches(&self, index: usize, value: &ObservedStop) -> Result<(), CensusConsumerError> {
        require(
            self.states[index].as_ref() == Some(value)
                && self.actual_allocations[index] == Some(BufferIdentity::of(&value.xstate)),
        )
    }
}
type RowView<'a> = (
    RowHeader,
    &'a ObservedStop,
    &'a ObservedStop,
    Option<&'a [StackEvidence]>,
);
fn row(value: &HistoryRecord) -> Result<RowView<'_>, CensusConsumerError> {
    match value {
        HistoryRecord::Refreshed {
            origin,
            before,
            after,
        } => Ok((
            RowHeader {
                kind: RowKind::Refresh,
                origin: *origin,
            },
            before,
            after,
            None,
        )),
        HistoryRecord::Consumed { origin, evidence } => match &evidence.evidence {
            Consumption::OwnedStack(records) => Ok((
                RowHeader {
                    kind: RowKind::Consumption,
                    origin: *origin,
                },
                &evidence.before,
                &evidence.successor,
                Some(records),
            )),
            _ => Err(CensusConsumerError::Mismatch),
        },
        _ => Err(CensusConsumerError::Mismatch),
    }
}
fn origin(census: &ResumeCensus, id: OriginId) -> Result<&StoredOrigin, CensusConsumerError> {
    let mut matches = census
        .state
        .origins
        .iter()
        .filter(|value| value.row.id == id);
    let result = matches.next().ok_or(CensusConsumerError::Incomplete)?;
    require(matches.next().is_none())?;
    Ok(result)
}
fn monotone(old: BudgetCharge, new: BudgetCharge) -> bool {
    old.epochs <= new.epochs
        && old.source_fact_bytes <= new.source_fact_bytes
        && old.reports <= new.reports
        && old.origins <= new.origins
        && old.witnesses <= new.witnesses
        && old.plan_history <= new.plan_history
}
fn checkpoint(
    actual: &ObservedStop,
    native: NativeCheckpoint<'_>,
    before: &ObservedStop,
    phase: StopPhase,
    signal: Option<DynamicSignalInfo>,
) -> Result<(), CensusConsumerError> {
    require(
        actual.token == native.stop.token
            && actual.task == native.stop.identity
            && actual.token.session == before.token.session
            && actual.token.tid == before.token.tid
            && actual.token.task == before.token.task
            && actual.task == before.task
            && actual.task.generation == 0
            && actual.token.task == Some(actual.task.task)
            && actual.logical_pc == native.state.registers.rip
            && actual.registers == native.state.registers
            && actual.xstate == native.state.xstate
            && actual.signal_mask == native.state.mask
            && actual.phase == phase
            && actual.signal == signal
            && actual.xstate.capacity() == MAX_XSTATE_BYTES
            && (576..MAX_XSTATE_BYTES).contains(&actual.xstate.len()),
    )
}
fn require_words(
    input: &StackConsumerInput<'_>,
    binding: &Binding,
) -> Result<(), CensusConsumerError> {
    let words = &input.words;
    require(
        words.operand == &binding.operand && ProfileRecord::from(words.profile) == binding.profile,
    )?;
    super::validate::require_catalog_maps(input.sources, words)?;
    binding
        .fetch
        .verify_open(words.baseline_maps, words.opened_maps)
        .map_err(|_| CensusConsumerError::Mismatch)?;
    let associations = [
        StackCaptureAssociation::A {
            stop: input.identity.stop().clone(),
            source_id: input.identity.source_id(),
            until: input.identity.until(),
        },
        StackCaptureAssociation::B {
            stop: input.checkpoints[2].stop.clone(),
            until: input.identity.until(),
        },
        StackCaptureAssociation::C {
            original: input.checkpoints[2].stop.clone(),
            raw_wait: (input.trace.tid, input.trace.status),
            ordinal: 3,
            until: input.identity.until(),
        },
        StackCaptureAssociation::D {
            stop: input.checkpoints[6].stop.clone(),
            until: input.identity.until(),
        },
    ];
    for (index, view) in words.captures.iter().enumerate() {
        require(
            view.complete
                && view.first_failure.is_none()
                && view.association == Some(&associations[index]),
        )?;
        view.observation
            .require_ready()
            .map_err(|_| CensusConsumerError::Mismatch)?;
        let pkru = validate_state(&view.observation.state, binding.profile.layout)
            .map_err(|_| CensusConsumerError::Mismatch)?;
        require(pkru == binding.operand.pkru)?;
        view.pagemap_access
            .validate_for(&view.word.pagemap)
            .map_err(|_| CensusConsumerError::Mismatch)?;
        let value = view
            .word
            .validate(&binding.operand.geometry)
            .map_err(|_| CensusConsumerError::Mismatch)?;
        let maps = view
            .observation
            .maps_capture
            .bytes(&view.observation.maps)
            .map_err(|_| CensusConsumerError::Mismatch)?;
        let smaps = view
            .observation
            .smaps_capture
            .bytes(&view.observation.smaps)
            .map_err(|_| CensusConsumerError::Mismatch)?;
        let stack = binding
            .profile
            .stack
            .require_current(words.original_maps, maps)
            .map_err(|_| CensusConsumerError::Mismatch)?;
        require(
            validate_smaps(smaps, maps, stack).map_err(|_| CensusConsumerError::Mismatch)?
                == binding.profile.metadata,
        )?;
        require(
            maps == if index == 0 || index == 3 {
                words.baseline_maps
            } else {
                words.opened_maps
            },
        )?;
        let state = &view.observation.state.state;
        require(if index < 2 {
            value == binding.operand.value && same_architecture(input.logical_before, state)
        } else {
            state == input.checkpoints[3].state
        })?;
    }
    let [a, b, c, d] = words.captures;
    require(a.word.bytes == b.word.bytes && c.word.bytes == d.word.bytes)?;
    validate_effect(
        &a.observation.state.state,
        &c.observation.state.state,
        words.operand,
        &a.word.bytes,
        &c.word.bytes,
    )
    .map_err(|_| CensusConsumerError::Mismatch)
}
impl ResumeCensus {
    pub(in crate::linux::remote::dynamic::owner::admission) fn copy_stack_consumer_observation_into(
        &self,
        input: StackConsumerInput<'_>,
        out: &mut PreparedStackObservation,
    ) -> Result<(), CensusConsumerError> {
        out.capture.begin()?;
        let result = (|| {
            out.allocation.require_complete()?;
            require(out.allocated_bytes()? == PreparedStackObservation::reservation_bytes()?)?;
            out.census = Some(CensusHeader::of(self));
            out.start = Some(input.start);
            require(
                out.census
                    .as_ref()
                    .is_some_and(|header| header.reservation.is_none()),
            )?;
            let end = input
                .start
                .checked_add(7)
                .ok_or(CensusConsumerError::Capacity)?;
            require(self.state.history.len() == end && self.state.generation == 0)?;
            let history = self
                .state
                .history
                .get(input.start..end)
                .ok_or(CensusConsumerError::Incomplete)?;
            let original = input.logical_before;
            require(
                original.phase == StopPhase::UserCheckpoint
                    && original.signal.is_none()
                    && input.identity.stop().token == original.token
                    && input.identity.stop().identity == original.task,
            )?;
            let mut previous = original;
            for (index, record) in history.iter().enumerate() {
                let (header, before, after, evidence) = row(record)?;
                out.rows[index] = Some(header);
                out.copy(index * 2, before)?;
                out.copy(index * 2 + 1, after)?;
                require(
                    before == previous
                        && header.kind
                            == if index == 3 {
                                RowKind::Consumption
                            } else {
                                RowKind::Refresh
                            },
                )?;
                require(
                    header.origin
                        == if index < 4 {
                            input.identity.origin()
                        } else {
                            input.current
                        },
                )?;
                let native = input.checkpoints[index];
                require(
                    native.stop.token.sequence > before.token.sequence
                        && native.stop.signal.is_none()
                        && native.stop.phase
                            == if index == 3 {
                                AdmissionPhase::NativeCompleted
                            } else {
                                AdmissionPhase::Restored
                            },
                )?;
                let phase = if index == 3 {
                    StopPhase::OwnedStackComplete {
                        execution: input.identity.execution(),
                    }
                } else {
                    StopPhase::UserCheckpoint
                };
                checkpoint(
                    after,
                    native,
                    original,
                    phase,
                    if index == 3 {
                        Some(DynamicSignalInfo {
                            raw: input.trace.signal,
                        })
                    } else {
                        None
                    },
                )?;
                require(if index < 3 {
                    same_architecture(original, native.state)
                } else {
                    native.state == input.checkpoints[3].state
                })?;
                if let Some(evidence) = evidence {
                    require(index == 3 && evidence.len() == 1)?;
                    out.evidence_allocation = Some((evidence.as_ptr() as usize, evidence.len()));
                    out.evidence = Some(evidence[0].clone()); // fixed Binding and word arrays only
                }
                previous = after;
            }
            let evidence = out
                .evidence
                .as_ref()
                .ok_or(CensusConsumerError::Incomplete)?;
            let binding = evidence
                .binding
                .as_ref()
                .ok_or(CensusConsumerError::Incomplete)?;
            let identity = input.identity;
            require(
                evidence.trace == Some(input.trace)
                    && evidence.call == input.call_id
                    && evidence.words == Some(input.words.captures.map(|v| v.word.bytes)),
            )?;
            require(
                binding.census == self.identity
                    && binding.reservation == input.reservation
                    && binding.origin == identity.origin()
                    && binding.execution == identity.execution()
                    && binding.until == identity.until()
                    && binding.operand == *identity.operand_description()
                    && binding.operand.stop == *identity.stop()
                    && binding.profile.stack == identity.stack_descriptor()
                    && binding.profile.metadata == identity.stack_metadata()
                    && binding.profile.layout == identity.pku_layout()
                    && binding.profile.initial_rsp == identity.initial_rsp()
                    && binding.profile.restored == *identity.initial_stop()
                    && binding.source.id == identity.source_id(),
            )?;
            binding.require_source(input.sources)?;
            let signal = DynamicSignalInfo {
                raw: input.trace.signal,
            };
            require(
                input.trace.ordinal == 3
                    && input.trace.tid == original.token.tid
                    && libc::WIFSTOPPED(input.trace.status)
                    && libc::WSTOPSIG(input.trace.status) == libc::SIGTRAP
                    && input.trace.status >> 16 == 0
                    && input.trace.dr6 == TRACE_DR6
                    && signal.signal() == libc::SIGTRAP
                    && signal.errno() == 0
                    && signal.code() == libc::TRAP_TRACE
                    && u64::from_ne_bytes(
                        input.trace.signal[16..24]
                            .try_into()
                            .map_err(|_| CensusConsumerError::Mismatch)?,
                    ) == input.checkpoints[3].state.registers.rip,
            )?;
            require(match binding.operand.geometry.operation {
                StackOperation::DirectCall => input.call_id.is_some(),
                StackOperation::Return => input.call_id.is_none(),
            })?;
            require_words(&input, binding)?;
            let old = origin(self, identity.origin())?;
            let current = origin(self, input.current)?;
            require(
                !old.active
                    && old.frame.is_none()
                    && current.active
                    && self.state.origins.iter().filter(|v| v.active).count() == 1
                    && input.current.census == self.identity
                    && input.current.serial == binding.candidate_serial
                    && self.state.next_serial
                        == input
                            .current
                            .serial
                            .checked_add(1)
                            .ok_or(CensusConsumerError::Capacity)?
                    && current.row.kind == OriginKind::CurrentHeldPc
                    && current.row.created_generation == 0
                    && current.row.pc == input.checkpoints[3].state.registers.rip
                    && current.frame.is_none()
                    && current.runtime_kernel.is_none()
                    && old.current == *row(&history[3])?.1
                    && current.row.initial == *row(&history[3])?.2
                    && current.current == *previous
                    && input.native_current == input.checkpoints[6].stop
                    && current.current.token == input.native_current.token
                    && current.current.task == input.native_current.identity,
            )?;
            out.old_origin = Some(OriginHeader::of(old));
            out.new_origin = Some(OriginHeader::of(current));
            out.old_current_allocation = Some(BufferIdentity::of(&old.current.xstate));
            out.copy(14, &current.row.initial)?;
            out.copy(15, &current.current)?;
            out.capture.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            out.capture.fail(error);
        }
        result
    }
    /// Compare immutable historical ownership after later operations or cleanup.
    /// The copied final current remains historical; no stale-current assertion.
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_stack_consumer_observation(
        &self,
        out: &PreparedStackObservation,
        sources: &PreparedInitialSources,
    ) -> Result<(), CensusConsumerError> {
        out.allocation.require_complete()?;
        out.capture.require_complete()?;
        let header = out.census.ok_or(CensusConsumerError::Incomplete)?;
        let now = CensusHeader::of(self);
        require(
            header.identity == now.identity
                && header.session == now.session
                && header.space == now.space
                && header.limits == now.limits
                && header.generation == now.generation
                && header.next_serial <= now.next_serial
                && monotone(header.used, now.used)
                && monotone(header.charged, now.charged)
                && header.origins_pointer == now.origins_pointer
                && header.origins_capacity == now.origins_capacity
                && header.origins_length <= now.origins_length
                && header.history_pointer == now.history_pointer
                && header.history_capacity == now.history_capacity
                && header.history_length <= now.history_length,
        )?;
        let start = out.start.ok_or(CensusConsumerError::Incomplete)?;
        let end = start.checked_add(7).ok_or(CensusConsumerError::Capacity)?;
        let history = self
            .state
            .history
            .get(start..end)
            .ok_or(CensusConsumerError::Incomplete)?;
        for (index, record) in history.iter().enumerate() {
            let (header, before, after, evidence) = row(record)?;
            require(out.rows[index] == Some(header))?;
            out.matches(index * 2, before)?;
            out.matches(index * 2 + 1, after)?;
            if index == 3 {
                let records = evidence.ok_or(CensusConsumerError::Incomplete)?;
                require(
                    records.len() == 1
                        && out.evidence.as_ref() == records.first()
                        && out.evidence_allocation
                            == Some((records.as_ptr() as usize, records.len())),
                )?;
            } else {
                require(evidence.is_none())?;
            }
        }
        let old_header = out.old_origin.ok_or(CensusConsumerError::Incomplete)?;
        let new_header = out.new_origin.ok_or(CensusConsumerError::Incomplete)?;
        let old = origin(self, old_header.id)?;
        let new = origin(self, new_header.id)?;
        require(
            !old.active
                && OriginHeader::of(old) == old_header
                && OriginHeader::of(new) == new_header,
        )?;
        require(
            out.states[6].as_ref() == Some(&old.current)
                && out.old_current_allocation == Some(BufferIdentity::of(&old.current.xstate)),
        )?;
        out.matches(14, &new.row.initial)?;
        require(out.actual_allocations[15] == Some(BufferIdentity::of(&new.current.xstate)))?;
        // Slot15 was the complete actual current at capture; the immutable last
        // closing endpoint retains its value even after that origin advances.
        require(out.states[15].as_ref() == Some(row(&history[6])?.2))?;
        out.evidence
            .as_ref()
            .and_then(|v| v.binding.as_ref())
            .ok_or(CensusConsumerError::Incomplete)?
            .require_source(sources)?;
        require(out.allocated_bytes()? == PreparedStackObservation::reservation_bytes()?)
    }
}

/// Fixed managed comparison/copy peak, distinct from retained payload. Existing
/// pure parser/word checks are conservatively covered by the census validator
/// bound; no native acquisition is performed by this helper or the comparisons.
pub(in crate::linux::remote::dynamic::owner::admission) fn consumer_observation_temporary_bytes()
-> Result<usize, CensusConsumerError> {
    let mut total = super::stack_census_temporary_bytes()?;
    total = checked_add(
        total,
        super::super::stack_calls::consumer_oracle::temporary_bytes()?,
    )?;
    for size in [
        2 * size_of::<CensusHeader>(),
        4 * size_of::<OriginHeader>(),
        2 * size_of::<StackEvidence>(),
        2 * size_of::<Binding>(),
        size_of::<StackConsumerInput<'_>>(),
        4 * size_of::<RowView<'_>>(),
        size_of::<[StackCaptureAssociation; 4]>(),
        2 * size_of::<ObservedStop>(),
        4 * size_of::<BufferIdentity>(),
        4 * size_of::<ConsumerProgress>(),
        size_of::<StackPartialView<'_>>(),
        size_of::<StackEvidenceView<'_>>(),
        size_of::<ConsumerBindingView<'_>>(),
        8 * size_of::<Result<(), CensusConsumerError>>(),
        size_of::<[usize; 16]>(),
    ] {
        total = checked_add(total, size)?;
    }
    Ok(total)
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct StackEvidenceView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) binding:
        Option<ConsumerBindingView<'a>>,
    pub(in crate::linux::remote::dynamic::owner::admission) trace: Option<NativeTrace>,
    pub(in crate::linux::remote::dynamic::owner::admission) words: Option<&'a [[u8; 16]; 4]>,
    pub(in crate::linux::remote::dynamic::owner::admission) call: Option<PotentialCallId>,
}
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct StackPartialView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) address: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) copied_allocations:
        [Option<BufferIdentity>; STATES],
    pub(in crate::linux::remote::dynamic::owner::admission) buffer_allocations:
        [BufferIdentity; STATES],
    pub(in crate::linux::remote::dynamic::owner::admission) allocation: &'a ConsumerProgress,
    pub(in crate::linux::remote::dynamic::owner::admission) capture: &'a ConsumerProgress,
    pub(in crate::linux::remote::dynamic::owner::admission) payload: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) census: Option<&'a CensusHeader>,
    pub(in crate::linux::remote::dynamic::owner::admission) start: Option<usize>,
    pub(in crate::linux::remote::dynamic::owner::admission) rows: &'a [Option<RowHeader>; 7],
    pub(in crate::linux::remote::dynamic::owner::admission) evidence: Option<StackEvidenceView<'a>>,
    pub(in crate::linux::remote::dynamic::owner::admission) evidence_allocation:
        Option<(usize, usize)>,
    pub(in crate::linux::remote::dynamic::owner::admission) old_origin: Option<&'a OriginHeader>,
    pub(in crate::linux::remote::dynamic::owner::admission) new_origin: Option<&'a OriginHeader>,
    pub(in crate::linux::remote::dynamic::owner::admission) old_current_allocation:
        Option<BufferIdentity>,
    pub(in crate::linux::remote::dynamic::owner::admission) states:
        &'a [Option<ObservedStop>; STATES],
    pub(in crate::linux::remote::dynamic::owner::admission) buffers: &'a [Vec<u8>; STATES],
    pub(in crate::linux::remote::dynamic::owner::admission) actual_allocations:
        &'a [Option<BufferIdentity>; STATES],
}
impl PreparedStackObservation {
    pub(in crate::linux::remote::dynamic::owner::admission) fn partial_view(
        &self,
    ) -> StackPartialView<'_> {
        StackPartialView {
            address: std::ptr::from_ref(self) as usize,
            copied_allocations: std::array::from_fn(|i| {
                self.states[i]
                    .as_ref()
                    .map(|value| BufferIdentity::of(&value.xstate))
            }),
            buffer_allocations: std::array::from_fn(|i| BufferIdentity::of(&self.buffers[i])),
            allocation: &self.allocation,
            capture: &self.capture,
            payload: self.payload,
            census: self.census.as_ref(),
            start: self.start,
            rows: &self.rows,
            evidence: self.evidence.as_ref().map(|v| StackEvidenceView {
                binding: v.binding.as_ref().map(ConsumerBindingView::of),
                trace: v.trace,
                words: v.words.as_ref(),
                call: v.call,
            }),
            evidence_allocation: self.evidence_allocation,
            old_origin: self.old_origin.as_ref(),
            new_origin: self.new_origin.as_ref(),
            old_current_allocation: self.old_current_allocation,
            states: &self.states,
            buffers: &self.buffers,
            actual_allocations: &self.actual_allocations,
        }
    }
}
