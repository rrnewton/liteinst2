//! Actual-PC ordinary instruction binding. This producer accepts only the
//! closed operand-free profile below. Native control state and single-step
//! completion remain the separate native transport's obligations.
use super::super::runtime_capture::{RuntimeWindowProof, SourceWindowId};
use super::super::runtime_instruction::{CandidateKind, InstructionCandidate, OrdinaryFamily};
use super::super::runtime_native::ControlLineage;
use super::maps::FetchGeometry;
use super::*;
use iced_x86::OpKind;

const VSYSCALL_START: u64 = 0xffff_ffff_ff60_0000;
const VSYSCALL_END: u64 = VSYSCALL_START + 4096;

/// Non-Clone, with a constructor confined to the runtime owner. Source reads
/// have ended before this object can be passed to the mutable native owner.
/// Their exact whole-window/checkpoint evidence remains borrowed here. This is
/// an invocation request, not a certificate that debug/rseq/CET controls pass.
pub(in crate::linux::remote::dynamic::owner::admission) struct RuntimeInstructionBinding<'a> {
    source: RuntimeWindowProof<'a>,
    candidate: InstructionCandidate<'a>,
    geometry: FetchGeometry,
    origin: OriginId,
    execution: ExecutionId,
    island: &'a TrustedIsland,
    lineage: &'a ControlLineage,
}

impl<'a> RuntimeInstructionBinding<'a> {
    pub(super) fn new(
        source: RuntimeWindowProof<'a>,
        candidate: InstructionCandidate<'a>,
        census: &ResumeCensus,
        origin: OriginId,
        serial: u64,
        island: &'a TrustedIsland,
        lineage: &'a ControlLineage,
    ) -> Result<Self, GateError> {
        let window = source.window();
        let before = source.observed();
        let stop = source.stop();
        if !std::ptr::eq(candidate.snapshot(), window.snapshot)
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
        {
            return Err(GateError::Refused(
                "runtime ordinary source/checkpoint binding differs",
            ));
        }
        census
            .check_current_origin(origin, before)
            .map_err(census_error)?;
        require_operand_free(&candidate, &island.range)?;
        let geometry =
            FetchGeometry::for_initial_source(window.initial_source(), candidate.range())?;
        if geometry.pages().start() < island.range.end
            && island.range.start < geometry.pages().end()
        {
            return Err(GateError::Refused(
                "runtime original fetch overlaps the private island",
            ));
        }
        geometry.projected_rows(source.baseline_maps())?;
        let execution =
            ExecutionId::from_owner(stop.token.session, serial).map_err(census_error)?;
        Ok(Self {
            source,
            candidate,
            geometry,
            origin,
            execution,
            island,
            lineage,
        })
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn source_id(&self) -> SourceWindowId {
        self.source.window().id
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn candidate(
        &self,
    ) -> &InstructionCandidate<'a> {
        &self.candidate
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn geometry(&self) -> &FetchGeometry {
        &self.geometry
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn origin(&self) -> OriginId {
        self.origin
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn execution(&self) -> ExecutionId {
        self.execution
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn stop(&self) -> &'a AdmissionStop {
        self.source.stop()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn before(&self) -> &'a ObservedStop {
        self.source.observed()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn island(&self) -> &'a TrustedIsland {
        self.island
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn until(&self) -> Instant {
        self.source.until()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn baseline_maps(&self) -> &'a [u8] {
        self.source.baseline_maps()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn lineage(
        &self,
    ) -> &'a ControlLineage {
        self.lineage
    }
}

/// The classifier describes a broader ordinary set. Native eligibility here
/// additionally excludes every explicit or implicit data access and indirect
/// transfer. LEA and architectural NOP memory encodings calculate/access no
/// application data; their acceptance is explicit, not inferred from OpKind.
fn require_operand_free(
    candidate: &InstructionCandidate<'_>,
    island: &std::ops::Range<u64>,
) -> Result<(), GateError> {
    let CandidateKind::Ordinary(ordinary) = candidate.kind() else {
        return Err(GateError::Refused(
            "runtime selected instruction needs its own completion",
        ));
    };
    let instruction = ordinary.decoded();
    match ordinary.family() {
        OrdinaryFamily::Move | OrdinaryFamily::Arithmetic | OrdinaryFamily::Compare => {
            for index in 0..instruction.op_count() {
                if !matches!(
                    instruction.op_kind(index),
                    OpKind::Register
                        | OpKind::Immediate8
                        | OpKind::Immediate8_2nd
                        | OpKind::Immediate16
                        | OpKind::Immediate32
                        | OpKind::Immediate64
                        | OpKind::Immediate8to16
                        | OpKind::Immediate8to32
                        | OpKind::Immediate8to64
                        | OpKind::Immediate32to64
                ) {
                    return Err(GateError::Refused(
                        "runtime ordinary data-access footprint is unqualified",
                    ));
                }
            }
        }
        OrdinaryFamily::Address | OrdinaryFamily::Nop => {}
        OrdinaryFamily::ConditionalBranch | OrdinaryFamily::Jump => {
            let target = ordinary.direct_target().ok_or(GateError::Refused(
                "runtime indirect-transfer footprint is unqualified",
            ))?;
            require_original_pc(target, island)?;
        }
        OrdinaryFamily::Push
        | OrdinaryFamily::Pop
        | OrdinaryFamily::Call
        | OrdinaryFamily::Return => {
            return Err(GateError::Refused(
                "runtime ordinary stack footprint is unqualified",
            ));
        }
    }
    require_original_pc(candidate.range().start(), island)?;
    // Keep the full fall-through obligation even at a source-window/page end.
    // No destination bytes or prior execution are inferred from this address.
    require_original_pc(candidate.next_pc(), island)
}

fn require_original_pc(pc: u64, island: &std::ops::Range<u64>) -> Result<(), GateError> {
    if island.contains(&pc) || (VSYSCALL_START..VSYSCALL_END).contains(&pc) {
        return Err(GateError::Refused(
            "runtime ordinary continuation enters private or fixed code",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
