//! Pure interpretation of retained records. No CPUID, ptrace, or procfs call
//! occurs here. Uniform component-9 layout remains an explicit caller ABI
//! premise; matching descriptive records cannot establish that premise.
use super::*;

pub(in crate::linux::remote::dynamic::owner::admission) const CPUID_INPUTS: [(u32, u32); 5] =
    [(0, 0), (1, 0), (7, 0), (13, 0), (13, 9)];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct CpuidRecord {
    pub(in crate::linux::remote::dynamic::owner::admission) leaf: u32,
    pub(in crate::linux::remote::dynamic::owner::admission) subleaf: u32,
    /// EAX, EBX, ECX, EDX, retained without normalization.
    pub(in crate::linux::remote::dynamic::owner::admission) registers: [u32; 4],
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct PkuLayoutEvidence {
    pub(in crate::linux::remote::dynamic::owner::admission) records: [Option<CpuidRecord>; 5],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct PkuLayout {
    offset: usize,
    size: usize,
}
impl PkuLayoutEvidence {
    pub(in crate::linux::remote::dynamic::owner::admission) fn validate(
        &self,
    ) -> Result<PkuLayout, StackError> {
        let mut raw = [[0_u32; 4]; 5];
        for (index, expected) in CPUID_INPUTS.into_iter().enumerate() {
            let record = self.records[index].ok_or(StackError::Incomplete)?;
            if (record.leaf, record.subleaf) != expected {
                return Err(StackError::Layout);
            }
            raw[index] = record.registers;
        }
        let user_features = u64::from(raw[3][0]) | (u64::from(raw[3][3]) << 32);
        if raw[0][0] < 13
            || raw[1][2] & ((1 << 26) | (1 << 27)) != (1 << 26) | (1 << 27)
            || raw[2][2] & ((1 << 3) | (1 << 4)) != (1 << 3) | (1 << 4)
            || user_features & (1 << 9) == 0
            || raw[4][0] != 8
            || raw[4][2] & 1 != 0
        {
            return Err(StackError::Layout);
        }
        let offset = usize::try_from(raw[4][1]).map_err(|_| StackError::Layout)?;
        if offset < 576 || offset.checked_add(8).is_none_or(|end| end >= BYTES) {
            return Err(StackError::Layout);
        }
        // Every required boolean is positively established above. Only the
        // component size/offset can vary within the accepted projection.
        // All five unprojected records remain owned by the preparation.
        Ok(PkuLayout { offset, size: 8 })
    }
}
fn word(bytes: &[u8], offset: usize) -> Result<u64, StackError> {
    let end = offset.checked_add(8).ok_or(StackError::Xstate)?;
    let bytes = bytes.get(offset..end).ok_or(StackError::Xstate)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| StackError::Xstate)?,
    ))
}
fn successful(request: Option<Request>) -> bool {
    request
        == Some(Request {
            result: 0,
            errno: None,
        })
}
/// Requires genuine request outcomes as data, including the original requested
/// pointer. The caller still has to establish physical held-stop authority.
pub(in crate::linux::remote::dynamic::owner::admission) fn validate_state(
    slot: &StateSlot,
    layout: PkuLayout,
) -> Result<u32, StackError> {
    if !slot.complete
        || !successful(slot.registers_request)
        || !successful(slot.xstate_request)
        || !successful(slot.mask_request)
        || slot.state.xstate.capacity() != BYTES
        || slot.requested_pointer != slot.state.xstate.as_ptr() as usize
        || slot.returned_pointer != slot.requested_pointer
        || !(576..BYTES).contains(&slot.returned_length)
        || slot.returned_length % 8 != 0
        || slot.state.xstate.len() != slot.returned_length
    {
        return Err(StackError::Request);
    }
    let bytes = &slot.state.xstate;
    // Linux REGSET_XSTATE's exported XCR0 word is at offset464. This is not
    // the differently interpreted signal-frame FP_XSTATE_MAGIC layout.
    if word(bytes, 464)? & (1 << 9) == 0
        || word(bytes, 512)? & (1 << 9) == 0
        || word(bytes, 520)? != 0
        || bytes[528..576].iter().any(|byte| *byte != 0)
        || layout.size != 8
    {
        return Err(StackError::Xstate);
    }
    let component = word(bytes, layout.offset)?;
    if component >> 32 != 0 || component & 3 != 0 {
        return Err(StackError::Xstate);
    }
    let registers = &slot.state.registers;
    // Preserve the existing native64 TF/RF/mode predicates and add AC.
    if registers.cs != 0x33
        || registers.ss != 0x2b
        || registers.eflags & ((1 << 8) | (1 << 16) | (1 << 17) | (1 << 18)) != 0
    {
        return Err(StackError::Mode);
    }
    Ok(component as u32)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct PagemapObservation {
    pub(in crate::linux::remote::dynamic::owner::admission) fd: i32,
    pub(in crate::linux::remote::dynamic::owner::admission) offset: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) requested: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) copied: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) bytes: [u8; 16],
    pub(in crate::linux::remote::dynamic::owner::admission) request: Option<Request>,
}
impl PagemapObservation {
    pub(in crate::linux::remote::dynamic::owner::admission) fn validate(
        &self,
        envelope: &Range<u64>,
    ) -> Result<(), StackError> {
        if !interval(envelope) || !matches!(envelope.end - envelope.start, 8 | 16) {
            return Err(StackError::Geometry);
        }
        let first = envelope.start / PAGE;
        let last = (envelope.end - 1) / PAGE;
        let requested = usize::try_from(last - first + 1)
            .ok()
            .and_then(|n| n.checked_mul(8))
            .ok_or(StackError::Geometry)?;
        if !matches!(requested, 8 | 16)
            || self.fd < 0
            || self.offset != first.checked_mul(8).ok_or(StackError::Geometry)?
            || self.requested != requested
            || self.copied != requested
            || self.request
                != Some(Request {
                    result: requested as i64,
                    errno: None,
                })
        {
            return Err(StackError::Request);
        }
        for bytes in self.bytes[..requested].chunks_exact(8) {
            let value = u64::from_le_bytes(bytes.try_into().map_err(|_| StackError::Pagemap)?);
            const PRESENT: u64 = 1 << 63;
            const EXCLUSIVE: u64 = 1 << 56;
            const PFN: u64 = (1 << 55) - 1;
            const SOFT_DIRTY: u64 = 1 << 55;
            let allowed = PRESENT | EXCLUSIVE | SOFT_DIRTY | PFN;
            if value & (PRESENT | EXCLUSIVE) != PRESENT | EXCLUSIVE || value & !allowed != 0 {
                return Err(StackError::Pagemap);
            }
        }
        Ok(())
    }
}
