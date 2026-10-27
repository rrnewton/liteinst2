//! Immutable descriptions. Passing these checks supplies no native permission.
use super::super::super::runtime_capture::WindowView;
use super::super::super::source_identity::InitialSourceVma;
use super::*;
use liteinst_admission::scan::{Boundary, Snapshot, WriteControl};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct ProfileRecord {
    pub(in crate::linux::remote::dynamic::owner::admission::census) stack: StackDescriptor,
    pub(in crate::linux::remote::dynamic::owner::admission::census) metadata: StackMetadata,
    pub(in crate::linux::remote::dynamic::owner::admission::census) layout: PkuLayout,
    pub(in crate::linux::remote::dynamic::owner::admission::census) initial_rsp: u64,
    pub(in crate::linux::remote::dynamic::owner::admission::census) island: std::ops::Range<u64>,
    pub(in crate::linux::remote::dynamic::owner::admission::census) restored: AdmissionStop,
}
impl From<&ProfileDescription> for ProfileRecord {
    fn from(value: &ProfileDescription) -> Self {
        Self {
            stack: value.stack,
            metadata: value.metadata,
            layout: value.layout,
            initial_rsp: value.initial_rsp,
            island: value.island.clone(),
            restored: value.restored.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct SourceRecord {
    pub(in crate::linux::remote::dynamic::owner::admission::census) id: SourceWindowId,
    pub(in crate::linux::remote::dynamic::owner::admission::census) initial: InitialSourceVma,
    pub(in crate::linux::remote::dynamic::owner::admission::census) range: AddressRange,
    pub(in crate::linux::remote::dynamic::owner::admission::census) target: AddressRange,
    before: Boundary,
    after: Boundary,
    writes: WriteControl,
    snapshot_address: usize,
    bytes_address: usize,
}
impl SourceRecord {
    #[cfg(feature = "dev-owned-stack-consumer-oracle")]
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn consumer_view(
        &self,
    ) -> super::consumer_oracle::storage::ConsumerSourceView {
        super::consumer_oracle::storage::ConsumerSourceView {
            id: self.id,
            initial: self.initial,
            range: self.range,
            target: self.target,
            before: self.before,
            after: self.after,
            writes: self.writes,
            snapshot_address: self.snapshot_address,
            bytes_address: self.bytes_address,
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn capture(
        window: &WindowView<'_>,
    ) -> Self {
        Self::from_parts(
            window.id,
            window.initial_source(),
            window.target,
            window.snapshot,
        )
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn from_parts(
        id: SourceWindowId,
        initial: InitialSourceVma,
        target: AddressRange,
        snapshot: &Snapshot,
    ) -> Self {
        Self {
            id,
            initial,
            range: snapshot.range(),
            target,
            before: snapshot.before,
            after: snapshot.after,
            writes: snapshot.writes,
            snapshot_address: std::ptr::from_ref(snapshot) as usize,
            bytes_address: snapshot.bytes().as_ptr() as usize,
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn require_snapshot(
        &self,
        actual: Self,
        snapshot: &Snapshot,
        geometry: &OperandGeometry,
        fetch: &FetchGeometry,
    ) -> Result<(), CensusError> {
        let identity = self.id.identity();
        let instruction = AddressRange::new(geometry.pc, geometry.next_pc)
            .ok_or(CensusError::InvalidConsumption)?;
        let offset = usize::try_from(
            geometry
                .pc
                .checked_sub(self.range.start())
                .ok_or(CensusError::InvalidConsumption)?,
        )
        .map_err(|_| CensusError::Capacity)?;
        let end = offset
            .checked_add(geometry.length)
            .ok_or(CensusError::Capacity)?;
        if *self != actual
            || identity.mapping == 0
            || identity.generation != 0
            || snapshot.mapping.0 != identity.mapping
            || snapshot.generation.0 != identity.generation
            || self.writes != WriteControl::Owned
            || !self.range.covers(instruction)
            || !self.target.contains(geometry.pc)
            || snapshot.bytes().get(offset..end) != Some(encoding(geometry)?)
            || FetchGeometry::for_initial_source(self.initial, instruction)
                .map_err(|_| CensusError::InvalidConsumption)?
                != *fetch
        {
            return Err(CensusError::IdentityMismatch);
        }
        // next_pc is an exclusive continuation: it may be on a never-opened
        // next page or outside this window. It is not promoted to a source head.
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct Binding {
    pub(in crate::linux::remote::dynamic::owner::admission::census) census: u64,
    pub(in crate::linux::remote::dynamic::owner::admission::census) reservation: Reservation,
    pub(in crate::linux::remote::dynamic::owner::admission::census) candidate_serial: u64,
    pub(in crate::linux::remote::dynamic::owner::admission::census) origin: OriginId,
    pub(in crate::linux::remote::dynamic::owner::admission::census) execution: ExecutionId,
    pub(in crate::linux::remote::dynamic::owner::admission::census) source: SourceRecord,
    pub(in crate::linux::remote::dynamic::owner::admission::census) fetch: FetchGeometry,
    pub(in crate::linux::remote::dynamic::owner::admission::census) operand: OperandDescription,
    pub(in crate::linux::remote::dynamic::owner::admission::census) profile: ProfileRecord,
    pub(in crate::linux::remote::dynamic::owner::admission::census) until: Instant,
}
pub(in crate::linux::remote::dynamic::owner::admission::census) fn encoding(
    geometry: &OperandGeometry,
) -> Result<&[u8], CensusError> {
    geometry
        .encoding
        .get(..geometry.length)
        .ok_or(CensusError::InvalidConsumption)
}
pub(in crate::linux::remote::dynamic::owner::admission::census) fn validate_operand(
    operand: &OperandDescription,
    profile: &ProfileRecord,
    before: &ObservedStop,
) -> Result<(), CensusError> {
    let geometry = &operand.geometry;
    let reproduced = OperandGeometry::derive(
        before.logical_pc,
        encoding(geometry)?,
        before.registers.rsp,
        &profile.stack.range(),
        &profile.island,
    )
    .map_err(|_| CensusError::InvalidConsumption)?;
    let restored = &profile.restored;
    if reproduced != *geometry
        || operand.target != geometry.call_target.unwrap_or(operand.value)
        || !(4096..(1_u64 << 47)).contains(&operand.target)
        || profile.island.contains(&operand.target)
        || operand.stop.token != before.token
        || operand.stop.identity != before.task
        || operand.stop.signal.is_some()
        || !matches!(
            operand.stop.phase,
            AdmissionPhase::EntryReady | AdmissionPhase::Restored
        )
        || restored.identity != before.task
        || restored.token.session != before.token.session
        || restored.token.tid != before.token.tid
        || restored.token.task != before.token.task
        || restored.token.sequence > before.token.sequence
        || restored.signal.is_some()
        || !matches!(
            restored.phase,
            AdmissionPhase::EntryReady | AdmissionPhase::Restored
        )
        || !profile.stack.range().contains(&profile.initial_rsp)
        || operand.pkru & 3 != 0
    {
        return Err(CensusError::InvalidConsumption);
    }
    Ok(())
}
impl Binding {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn from_actual(
        census: &ResumeCensus,
        reservation: Reservation,
        actual: &RuntimeStackBinding<'_, '_>,
    ) -> Result<Self, CensusError> {
        let before = census.current_observation(actual.origin())?;
        let window = actual.window();
        let candidate = actual.candidate();
        let source = SourceRecord::capture(window);
        let operand = actual.operand_description();
        if actual.before() != before
            || actual.stop() != &operand.stop
            || actual.source_id() != source.id
            || !std::ptr::eq(candidate.snapshot(), actual.window().snapshot)
            || candidate.registers() != &before.registers
            || candidate.bytes() != encoding(&operand.geometry)?
            || candidate.next_pc() != operand.geometry.next_pc
            || candidate.range().start() != before.logical_pc
            || !matches!(candidate.kind(), CandidateKind::Ordinary(_))
        {
            return Err(CensusError::StaleObservation);
        }
        source.require_snapshot(
            SourceRecord::capture(actual.window()),
            candidate.snapshot(),
            &operand.geometry,
            actual.geometry(),
        )?;
        let binding = Self {
            census: census.identity,
            reservation,
            candidate_serial: census.state.next_serial,
            origin: actual.origin(),
            execution: actual.execution(),
            source,
            fetch: *actual.geometry(),
            operand: operand.clone(),
            profile: ProfileRecord::from(actual.profile_description()),
            until: actual.until(),
        };
        binding.validate_current(census)?;
        Ok(binding)
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn require_actual(
        &self,
        actual: &RuntimeStackBinding<'_, '_>,
        before: &ObservedStop,
    ) -> Result<(), CensusError> {
        if actual.before() != before
            || actual.stop() != &self.operand.stop
            || actual.source_id() != self.source.id
            || actual.origin() != self.origin
            || actual.execution() != self.execution
            || actual.until() != self.until
            || actual.operand_description() != &self.operand
            || ProfileRecord::from(actual.profile_description()) != self.profile
            || actual.geometry() != &self.fetch
            || !std::ptr::eq(actual.candidate().snapshot(), actual.window().snapshot)
            || actual.candidate().registers() != &before.registers
            || actual.candidate().bytes() != encoding(&self.operand.geometry)?
            || actual.candidate().next_pc() != self.operand.geometry.next_pc
            || !matches!(actual.candidate().kind(), CandidateKind::Ordinary(_))
        {
            return Err(CensusError::IdentityMismatch);
        }
        self.source.require_snapshot(
            SourceRecord::capture(actual.window()),
            actual.candidate().snapshot(),
            &self.operand.geometry,
            &self.fetch,
        )?;
        validate_operand(&self.operand, &self.profile, before)
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn validate_current(
        &self,
        census: &ResumeCensus,
    ) -> Result<(), CensusError> {
        let before = census.current_observation(self.origin)?;
        census.remaining(self.reservation)?;
        if self.census != census.identity
            || self.candidate_serial != census.state.next_serial
            || self.execution.session != census.session
            || self.execution.serial == 0
            || self.source.id.identity().mapping == 0
            || self.source.id.identity().generation != census.state.generation
            || before.phase != StopPhase::UserCheckpoint
            || before.signal.is_some()
            || before.task.generation != 0
            || census.state.generation != 0
            || self.until != self.operand.until
            || Instant::now() >= self.until
            || !(576..MAX_XSTATE_BYTES).contains(&before.xstate.len())
        {
            return Err(CensusError::StaleObservation);
        }
        census.runtime_register_provenance(self.origin)?;
        validate_operand(&self.operand, &self.profile, before)?;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn require_source(
        &self,
        sources: &PreparedInitialSources,
    ) -> Result<(), CensusError> {
        let window = sources
            .window(self.source.id.index())
            .ok_or(CensusError::MissingImage)?;
        self.source.require_snapshot(
            SourceRecord::capture(&window),
            sources
                .window(self.source.id.index())
                .ok_or(CensusError::MissingImage)?
                .snapshot,
            &self.operand.geometry,
            &self.fetch,
        )
    }
}
