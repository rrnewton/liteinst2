//! Whole-source requests and fixed identities for the actual owned-stack path.
//! A context is descriptive. Only the separate native acquisition can supply A.
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime_capture::{
    RuntimeWindowProof, SourceWindowId, WindowView,
};
use crate::linux::remote::dynamic::owner::admission::runtime_instruction::{
    CandidateKind, InstructionCandidate,
};
use crate::linux::remote::dynamic::owner::admission::runtime_stack::{
    access::PkuLayout,
    metadata::{StackDescriptor, StackMetadata},
    operand::{OperandDescription, StackOperation},
    profile::ProfileDescription,
};
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native::acquire::{
    OriginalStackIdentity, OwnedStackOperand,
};
use iced_x86::Code;

const LOW_START: u64 = 4096;
const LOW_END: u64 = 1 << 47;

/// This cloneable fixed projection records identity, never execution authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct RuntimeStackIdentity {
    source: SourceWindowId,
    origin: OriginId,
    execution: ExecutionId,
    stop: AdmissionStop,
    initial_stop: AdmissionStop,
    stack: StackDescriptor,
    metadata: StackMetadata,
    layout: PkuLayout,
    initial_rsp: u64,
    operand: OperandDescription,
    until: Instant,
}

/// Descriptive immutable inputs; constructing this value grants no authority.
#[derive(Clone, Copy)]
pub(super) struct StackRequest<'s> {
    pub(super) original_maps: &'s [u8],
    pub(super) origin: OriginId,
    pub(super) serial: u64,
    pub(super) island: &'s TrustedIsland,
    pub(super) lineage: &'s ControlLineage,
}

pub(in crate::linux::remote::dynamic::owner::admission) struct StackBeforeContext<'s, 'v> {
    source: &'v RuntimeWindowProof<'s>,
    candidate: &'v InstructionCandidate<'s>,
    original_maps: &'s [u8],
    geometry: maps::FetchGeometry,
    origin: OriginId,
    execution: ExecutionId,
    island: &'s TrustedIsland,
    lineage: &'s ControlLineage,
}

pub(in crate::linux::remote::dynamic::owner::admission) struct RuntimeStackBinding<'s, 'o> {
    source: RuntimeWindowProof<'s>,
    candidate: InstructionCandidate<'s>,
    original_maps: &'s [u8],
    geometry: maps::FetchGeometry,
    island: &'s TrustedIsland,
    lineage: &'s ControlLineage,
    profile: OriginalStackIdentity<'o>,
    operand: OwnedStackOperand<'o>,
    identity: RuntimeStackIdentity,
}

fn original_pc(pc: u64, island: &std::ops::Range<u64>) -> Result<(), GateError> {
    if !(LOW_START..LOW_END).contains(&pc) || island.contains(&pc) {
        return Err(GateError::Refused(
            "runtime stack continuation is outside the original profile",
        ));
    }
    Ok(())
}

fn operation(
    candidate: &InstructionCandidate<'_>,
    island: &std::ops::Range<u64>,
) -> Result<StackOperation, GateError> {
    let CandidateKind::Ordinary(instruction) = candidate.kind() else {
        return Err(GateError::Refused(
            "runtime selected operation cannot enter the stack path",
        ));
    };
    let operation = match (candidate.bytes(), instruction.decoded().code()) {
        ([0xe8, _, _, _, _], Code::Call_rel32_64) => StackOperation::DirectCall,
        ([0xc3], Code::Retnq) => StackOperation::Return,
        _ => {
            return Err(GateError::Refused(
                "runtime stack encoding is not qualified",
            ));
        }
    };
    original_pc(candidate.range().start(), island)?;
    // A boundary return PC may be on a never-executed next page. It is a
    // conservative continuation fact, not permission to open that page.
    original_pc(candidate.next_pc(), island)?;
    if operation == StackOperation::DirectCall {
        let bytes = candidate.bytes();
        let displacement = i32::from_le_bytes(
            bytes[1..5]
                .try_into()
                .map_err(|_| GateError::Refused("runtime stack displacement differs"))?,
        );
        let target = candidate
            .next_pc()
            .checked_add_signed(i64::from(displacement))
            .ok_or(GateError::Refused("runtime stack target overflows"))?;
        original_pc(target, island)?;
        if instruction.direct_target() != Some(target)
            || instruction.decoded().near_branch_target() != target
        {
            return Err(GateError::Refused("runtime stack decoded target differs"));
        }
    }
    Ok(operation)
}

impl<'s, 'v> StackBeforeContext<'s, 'v> {
    pub(super) fn new(
        source: &'v RuntimeWindowProof<'s>,
        candidate: &'v InstructionCandidate<'s>,
        census: &ResumeCensus,
        request: StackRequest<'s>,
    ) -> Result<Self, GateError> {
        let StackRequest {
            original_maps,
            origin,
            serial,
            island,
            lineage,
        } = request;
        let before = source.observed();
        let stop = source.stop();
        if !std::ptr::eq(candidate.snapshot(), source.window().snapshot)
            || !std::ptr::eq(candidate.registers(), &before.registers)
            || candidate.range().start() != before.logical_pc
            || candidate.registers().rip != before.logical_pc
            || before.token != stop.token
            || before.task != stop.identity
            || before.phase != StopPhase::UserCheckpoint
            || before.signal.is_some()
            || stop.signal.is_some()
            || !matches!(
                stop.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
            || stop.identity.address_space != island.address_space
            || stop.identity.generation != 0
            || island.generation != 0
            || census.generation() != 0
            || island.page_size != 4096
            || island.range.start % 4096 != 0
            || island.range.end.checked_sub(island.range.start) != Some(4096)
            || original_maps.is_empty()
        {
            return Err(GateError::Refused(
                "runtime stack source/checkpoint binding differs",
            ));
        }
        census
            .check_current_origin(origin, before)
            .map_err(census_error)?;
        operation(candidate, &island.range)?;
        let geometry = maps::FetchGeometry::for_initial_source(
            source.window().initial_source(),
            candidate.range(),
        )?;
        if geometry.pages().start() < island.range.end
            && island.range.start < geometry.pages().end()
        {
            return Err(GateError::Refused(
                "runtime stack fetch overlaps the private island",
            ));
        }
        geometry.projected_rows(source.baseline_maps())?;
        let execution =
            ExecutionId::from_owner(stop.token.session, serial).map_err(census_error)?;
        Ok(Self {
            source,
            candidate,
            original_maps,
            geometry,
            origin,
            execution,
            island,
            lineage,
        })
    }
}

impl<'s, 'o> RuntimeStackBinding<'s, 'o> {
    pub(super) fn new(
        source: RuntimeWindowProof<'s>,
        candidate: InstructionCandidate<'s>,
        census: &ResumeCensus,
        request: StackRequest<'s>,
        profile: OriginalStackIdentity<'o>,
        operand: OwnedStackOperand<'o>,
    ) -> Result<Self, GateError> {
        let context = StackBeforeContext::new(&source, &candidate, census, request)?;
        let StackRequest {
            original_maps,
            origin,
            serial: _,
            island,
            lineage,
        } = request;
        operand.require_profile(&profile, original_maps)?;
        let description = operand.description();
        let actual = operand.before();
        let before = context.before();
        let expected_operation = operation(&candidate, &island.range)?;
        if operand.origin() != origin
            || operand.execution() != context.execution()
            || operand.source_id() != context.source_id()
            || operand.stop() != context.stop()
            || description.stop != *context.stop()
            || operand.until() != context.until()
            || description.until != context.until()
            || actual.registers != before.registers
            || actual.xstate != before.xstate
            || actual.mask != before.signal_mask
            || description.geometry.operation != expected_operation
            || description.geometry.pc != before.logical_pc
            || description.geometry.next_pc != candidate.next_pc()
            || description.geometry.original_rsp != before.registers.rsp
            || description.geometry.length != candidate.bytes().len()
            || description.geometry.encoding[..description.geometry.length] != *candidate.bytes()
            || description.geometry.stack != profile.description().stack.range()
            || description.geometry.island != island.range
        {
            return Err(GateError::Refused(
                "runtime stack actual operand binding differs",
            ));
        }
        original_pc(description.target, &island.range)?;
        let initial = profile.description();
        let geometry = context.geometry;
        let identity = RuntimeStackIdentity {
            source: context.source_id(),
            origin,
            execution: context.execution(),
            stop: context.stop().clone(),
            initial_stop: initial.restored.clone(),
            stack: initial.stack,
            metadata: initial.metadata,
            layout: initial.layout,
            initial_rsp: initial.initial_rsp,
            operand: description.clone(),
            until: context.until(),
        };
        Ok(Self {
            source,
            candidate,
            original_maps,
            geometry,
            island,
            lineage,
            profile,
            operand,
            identity,
        })
    }
}

impl RuntimeStackIdentity {
    pub(in crate::linux::remote::dynamic::owner::admission) fn source_id(&self) -> SourceWindowId {
        self.source
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn origin(&self) -> OriginId {
        self.origin
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn execution(&self) -> ExecutionId {
        self.execution
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn stop(&self) -> &AdmissionStop {
        &self.stop
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn initial_stop(
        &self,
    ) -> &AdmissionStop {
        &self.initial_stop
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn stack_descriptor(
        &self,
    ) -> StackDescriptor {
        self.stack
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn stack_metadata(
        &self,
    ) -> StackMetadata {
        self.metadata
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn pku_layout(&self) -> PkuLayout {
        self.layout
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn initial_rsp(&self) -> u64 {
        self.initial_rsp
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn operand_description(
        &self,
    ) -> &OperandDescription {
        &self.operand
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn until(&self) -> Instant {
        self.until
    }
}
impl<'s, 'v> StackBeforeContext<'s, 'v> {
    pub(in crate::linux::remote::dynamic::owner::admission) fn candidate(
        &self,
    ) -> &InstructionCandidate<'s> {
        self.candidate
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn source_id(&self) -> SourceWindowId {
        self.source.window().id
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn stop(&self) -> &'s AdmissionStop {
        self.source.stop()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn before(&self) -> &'s ObservedStop {
        self.source.observed()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn geometry(
        &self,
    ) -> &maps::FetchGeometry {
        &self.geometry
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn island(&self) -> &'s TrustedIsland {
        self.island
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn lineage(
        &self,
    ) -> &'s ControlLineage {
        self.lineage
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn baseline_maps(&self) -> &'s [u8] {
        self.source.baseline_maps()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn original_maps(&self) -> &'s [u8] {
        self.original_maps
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn until(&self) -> Instant {
        self.source.until()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn origin(&self) -> OriginId {
        self.origin
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn execution(&self) -> ExecutionId {
        self.execution
    }
}
impl<'s, 'o> RuntimeStackBinding<'s, 'o> {
    pub(in crate::linux::remote::dynamic::owner::admission) fn candidate(
        &self,
    ) -> &InstructionCandidate<'s> {
        &self.candidate
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn source_id(&self) -> SourceWindowId {
        self.source.window().id
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn stop(&self) -> &'s AdmissionStop {
        self.source.stop()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn before(&self) -> &'s ObservedStop {
        self.source.observed()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn geometry(
        &self,
    ) -> &maps::FetchGeometry {
        &self.geometry
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn island(&self) -> &'s TrustedIsland {
        self.island
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn lineage(
        &self,
    ) -> &'s ControlLineage {
        self.lineage
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn baseline_maps(&self) -> &'s [u8] {
        self.source.baseline_maps()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn original_maps(&self) -> &'s [u8] {
        self.original_maps
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn until(&self) -> Instant {
        self.source.until()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn origin(&self) -> OriginId {
        self.identity.origin
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn execution(&self) -> ExecutionId {
        self.identity.execution
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn identity(
        &self,
    ) -> &RuntimeStackIdentity {
        &self.identity
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn operand(
        &self,
    ) -> &OwnedStackOperand<'o> {
        &self.operand
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn operand_description(
        &self,
    ) -> &OperandDescription {
        self.operand.description()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn profile_description(
        &self,
    ) -> &ProfileDescription {
        self.profile.description()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn window(&self) -> &WindowView<'s> {
        self.source.window()
    }
}
