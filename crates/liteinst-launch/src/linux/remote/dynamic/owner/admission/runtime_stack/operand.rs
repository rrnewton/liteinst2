//! Pure operand/effect validation. Descriptions never supply native fetch,
//! write, source-head, CALL-ledger, or completed-origin authority.
use super::access::{PagemapObservation, PkuLayoutEvidence, validate_state};
use super::metadata::validate_smaps;
use super::profile::ProfileDescription;
use super::storage::StackObservationStorage;
use super::*;
use iced_x86::{Code, Decoder, DecoderOptions};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum StackOperation {
    DirectCall,
    Return,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct OperandGeometry {
    pub(in crate::linux::remote::dynamic::owner::admission) operation: StackOperation,
    pub(in crate::linux::remote::dynamic::owner::admission) pc: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) next_pc: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) call_target: Option<u64>,
    pub(in crate::linux::remote::dynamic::owner::admission) original_rsp: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) stack: Range<u64>,
    pub(in crate::linux::remote::dynamic::owner::admission) island: Range<u64>,
    pub(in crate::linux::remote::dynamic::owner::admission) slot: Range<u64>,
    pub(in crate::linux::remote::dynamic::owner::admission) envelope: Range<u64>,
    pub(in crate::linux::remote::dynamic::owner::admission) encoding: [u8; 5],
    pub(in crate::linux::remote::dynamic::owner::admission) length: usize,
}
impl OperandGeometry {
    pub(in crate::linux::remote::dynamic::owner::admission) fn derive(
        pc: u64,
        bytes: &[u8],
        rsp: u64,
        stack: &Range<u64>,
        island: &Range<u64>,
    ) -> Result<Self, StackError> {
        if !interval(stack) || !interval(island) || !low(pc) || !low(rsp) || overlaps(stack, island)
        {
            return Err(StackError::Geometry);
        }
        let operation = match bytes {
            [0xe8, _, _, _, _] => StackOperation::DirectCall,
            [0xc3] => StackOperation::Return,
            _ => return Err(StackError::Encoding),
        };
        let next_pc = pc
            .checked_add(bytes.len() as u64)
            .filter(|pc| low(*pc))
            .ok_or(StackError::Geometry)?;
        if overlaps(&(pc..next_pc), island) {
            return Err(StackError::Geometry);
        }
        let mut decoder = Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let expected_code = match operation {
            StackOperation::DirectCall => Code::Call_rel32_64,
            StackOperation::Return => Code::Retnq,
        };
        if instruction.code() != expected_code
            || instruction.len() != bytes.len()
            || instruction.next_ip() != next_pc
            || decoder.can_decode()
        {
            return Err(StackError::Encoding);
        }
        let call_target = if operation == StackOperation::DirectCall {
            let displacement =
                i32::from_le_bytes(bytes[1..5].try_into().map_err(|_| StackError::Encoding)?);
            let target = next_pc
                .checked_add_signed(i64::from(displacement))
                .filter(|pc| low(*pc))
                .ok_or(StackError::Geometry)?;
            if instruction.near_branch_target() != target {
                return Err(StackError::Encoding);
            }
            Some(target)
        } else {
            None
        };
        for target in [Some(pc), Some(next_pc), call_target].into_iter().flatten() {
            if island.contains(&target) {
                return Err(StackError::Geometry);
            }
        }
        let slot_start = match operation {
            StackOperation::DirectCall => rsp.checked_sub(8),
            StackOperation::Return => Some(rsp),
        }
        .ok_or(StackError::Geometry)?;
        let slot_end = slot_start.checked_add(8).ok_or(StackError::Geometry)?;
        let envelope_start = slot_start & !7;
        let envelope_end = slot_end
            .checked_add(7)
            .map(|n| n & !7)
            .ok_or(StackError::Geometry)?;
        let slot = slot_start..slot_end;
        let envelope = envelope_start..envelope_end;
        if !interval(&slot)
            || !interval(&envelope)
            || stack.start > envelope.start
            || envelope.end > stack.end
            || overlaps(&envelope, island)
        {
            return Err(StackError::Geometry);
        }
        // RET's successor RSP is an independently checked exclusive endpoint.
        let successor_rsp = if operation == StackOperation::DirectCall {
            slot_start
        } else {
            slot_end
        };
        if !low(successor_rsp) {
            return Err(StackError::Geometry);
        }
        let mut encoding = [0; 5];
        encoding[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            operation,
            pc,
            next_pc,
            call_target,
            original_rsp: rsp,
            stack: stack.clone(),
            island: island.clone(),
            slot,
            envelope,
            encoding,
            length: bytes.len(),
        })
    }
    fn validate(&self) -> Result<(), StackError> {
        let bytes = self
            .encoding
            .get(..self.length)
            .ok_or(StackError::Geometry)?;
        if Self::derive(self.pc, bytes, self.original_rsp, &self.stack, &self.island)? != *self {
            return Err(StackError::Geometry);
        }
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn envelope_length(&self) -> usize {
        (self.envelope.end - self.envelope.start) as usize
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct PeekRecord {
    pub(in crate::linux::remote::dynamic::owner::admission) address: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) request: Request,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct WordObservation {
    pub(in crate::linux::remote::dynamic::owner::admission) bytes: [u8; 16],
    pub(in crate::linux::remote::dynamic::owner::admission) copied: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) peek: [Option<PeekRecord>; 2],
    pub(in crate::linux::remote::dynamic::owner::admission) complete: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) pagemap: PagemapObservation,
}
impl WordObservation {
    pub(in crate::linux::remote::dynamic::owner::admission) fn validate(
        &self,
        geometry: &OperandGeometry,
    ) -> Result<u64, StackError> {
        geometry.validate()?;
        let length = geometry.envelope_length();
        if !self.complete || !matches!(length, 8 | 16) || self.copied != length {
            return Err(StackError::Incomplete);
        }
        self.pagemap.validate(&geometry.envelope)?;
        for index in 0..2 {
            if index * 8 >= length {
                if self.peek[index].is_some() || self.bytes[index * 8..].iter().any(|b| *b != 0) {
                    return Err(StackError::Word);
                }
                continue;
            }
            let request = self.peek[index].ok_or(StackError::Incomplete)?;
            let bytes = &self.bytes[index * 8..index * 8 + 8];
            if request.address != geometry.envelope.start + (index * 8) as u64
                || request.request.errno.is_some()
                || request.request.result as u64
                    != u64::from_le_bytes(bytes.try_into().map_err(|_| StackError::Word)?)
            {
                return Err(StackError::Word);
            }
        }
        let offset = (geometry.slot.start - geometry.envelope.start) as usize;
        Ok(u64::from_le_bytes(
            self.bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| StackError::Word)?,
        ))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct OperandDescription {
    pub(in crate::linux::remote::dynamic::owner::admission) geometry: OperandGeometry,
    pub(in crate::linux::remote::dynamic::owner::admission) value: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) target: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) pkru: u32,
    pub(in crate::linux::remote::dynamic::owner::admission) stop: AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner::admission) until: std::time::Instant,
}
pub(in crate::linux::remote::dynamic::owner::admission) struct OperandInput<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) profile: &'a ProfileDescription,
    pub(in crate::linux::remote::dynamic::owner::admission) original_maps: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner::admission) expected_maps: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner::admission) current: &'a TaskStateSnapshot,
    pub(in crate::linux::remote::dynamic::owner::admission) current_stop: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner::admission) until: std::time::Instant,
    pub(in crate::linux::remote::dynamic::owner::admission) pc: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) encoding: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner::admission) island: &'a Range<u64>,
}
pub(in crate::linux::remote::dynamic::owner::admission) struct PreparedStackOperand {
    pub(in crate::linux::remote::dynamic::owner::admission) observation: StackObservationStorage,
    pub(in crate::linux::remote::dynamic::owner::admission) layout_evidence: PkuLayoutEvidence,
    pub(in crate::linux::remote::dynamic::owner::admission) word: WordObservation,
    attempted: bool,
    first_failure: Option<StackError>,
    description: Option<OperandDescription>,
}
impl PreparedStackOperand {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            observation: StackObservationStorage::empty(),
            layout_evidence: PkuLayoutEvidence::default(),
            word: WordObservation::default(),
            attempted: false,
            first_failure: None,
            description: None,
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn reservation_bytes()
    -> Result<usize, StackError> {
        add(size_of::<Self>(), 3 * BYTES)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocate_payloads(
        &mut self,
    ) -> Result<(), StackError> {
        self.observation.allocate_payloads()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocated_bytes(
        &self,
    ) -> Result<usize, StackError> {
        add(size_of::<Self>(), self.observation.payload_bytes()?)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        self.observation.mark_aborted();
        if self.first_failure().is_none() {
            self.first_failure = Some(StackError::Aborted);
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn first_failure(
        &self,
    ) -> Option<StackError> {
        self.first_failure
            .or(self.observation.allocation.first_failure)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn description(
        &self,
    ) -> Option<&OperandDescription> {
        if self.first_failure().is_none() {
            self.description.as_ref()
        } else {
            None
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn validate(
        &mut self,
        input: OperandInput<'_>,
    ) -> Result<&OperandDescription, StackError> {
        if self.attempted || self.first_failure().is_some() {
            return Err(StackError::Reused);
        }
        self.attempted = true;
        match self.validate_inner(input) {
            Ok(description) => {
                self.description = Some(description);
                Ok(self.description.as_ref().expect("installed description"))
            }
            Err(error) => {
                self.first_failure = Some(error);
                Err(error)
            }
        }
    }
    fn validate_inner(&self, input: OperandInput<'_>) -> Result<OperandDescription, StackError> {
        self.observation.require_ready()?;
        let initial_stop = &input.profile.restored;
        let current_stop = input.current_stop;
        if input.island != &input.profile.island
            || current_stop.identity != initial_stop.identity
            || current_stop.token.session != initial_stop.token.session
            || current_stop.token.tid != initial_stop.token.tid
            || current_stop.token.task != Some(current_stop.identity.task)
            || current_stop.token.sequence < initial_stop.token.sequence
            || current_stop.signal.is_some()
            || !matches!(
                current_stop.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
        {
            return Err(StackError::Provenance);
        }
        let layout = self.layout_evidence.validate()?;
        if layout != input.profile.layout {
            return Err(StackError::Layout);
        }
        let pkru = validate_state(&self.observation.state, layout)?;
        if self.observation.state.state != *input.current || input.current.registers.rip != input.pc
        {
            return Err(StackError::State);
        }
        let maps = self
            .observation
            .maps_capture
            .bytes(&self.observation.maps)?;
        if maps != input.expected_maps {
            return Err(StackError::Maps);
        }
        let index = input
            .profile
            .stack
            .require_current(input.original_maps, maps)?;
        let smaps = self
            .observation
            .smaps_capture
            .bytes(&self.observation.smaps)?;
        if validate_smaps(smaps, maps, index)? != input.profile.metadata {
            return Err(StackError::Metadata);
        }
        let geometry = OperandGeometry::derive(
            input.pc,
            input.encoding,
            input.current.registers.rsp,
            &input.profile.stack.range(),
            input.island,
        )?;
        let value = self.word.validate(&geometry)?;
        let target = geometry.call_target.unwrap_or(value);
        if !low(target) || input.island.contains(&target) {
            return Err(StackError::Geometry);
        }
        Ok(OperandDescription {
            geometry,
            value,
            target,
            pkru,
            stop: current_stop.clone(),
            until: input.until,
        })
    }
}
/// A pure comparison, never a completion seal. It is deliberately exact in all
/// registers/flags, XSTATE and mask except the specified RIP/RSP and genuine
/// post-original orig_rax=MAX relation. Native trap proof is a separate input
/// obligation of the future producer, not supplied by this function.
pub(in crate::linux::remote::dynamic::owner::admission) fn validate_effect(
    initial: &TaskStateSnapshot,
    actual: &TaskStateSnapshot,
    description: &OperandDescription,
    before: &[u8; 16],
    after: &[u8; 16],
) -> Result<(), StackError> {
    let geometry = &description.geometry;
    geometry.validate()?;
    if !low(description.target) || geometry.island.contains(&description.target) {
        return Err(StackError::Geometry);
    }
    let offset = usize::try_from(
        geometry
            .slot
            .start
            .checked_sub(geometry.envelope.start)
            .ok_or(StackError::Geometry)?,
    )
    .map_err(|_| StackError::Geometry)?;
    let bytes = before
        .get(offset..offset.checked_add(8).ok_or(StackError::Geometry)?)
        .ok_or(StackError::Geometry)?;
    let word = u64::from_le_bytes(bytes.try_into().map_err(|_| StackError::Word)?);
    if word != description.value || description.target != geometry.call_target.unwrap_or(word) {
        return Err(StackError::Word);
    }
    let mut registers = initial.registers;
    if registers.rip != geometry.pc || registers.rsp != geometry.original_rsp {
        return Err(StackError::State);
    }
    registers.rip = description.target;
    registers.rsp = match geometry.operation {
        StackOperation::DirectCall => geometry.slot.start,
        StackOperation::Return => geometry.slot.end,
    };
    registers.orig_rax = u64::MAX;
    if actual.registers != registers
        || actual.xstate != initial.xstate
        || actual.mask != initial.mask
    {
        return Err(StackError::State);
    }
    let mut expected = *before;
    if geometry.operation == StackOperation::DirectCall {
        let offset = (geometry.slot.start - geometry.envelope.start) as usize;
        expected[offset..offset + 8].copy_from_slice(&geometry.next_pc.to_le_bytes());
    }
    if *after != expected {
        return Err(StackError::Word);
    }
    Ok(())
}
