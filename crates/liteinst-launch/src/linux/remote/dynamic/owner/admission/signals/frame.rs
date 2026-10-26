//! Native x86-64 rt_sigframe layout from the pinned Linux UAPI, not libc's
//! larger userspace ucontext. This parser grants no execution authority.
use super::*;

#[cfg(test)]
mod tests;

pub(super) const HEADER_BYTES: usize = 440;
pub(super) const MAX_FRAME_BYTES: usize = MAX_XSTATE + 4096;
const CONTEXT: usize = 48;
const ERROR: usize = CONTEXT + 152;
const TRAPNO: usize = CONTEXT + 160;
const CR2: usize = CONTEXT + 176;
const FP_POINTER: usize = CONTEXT + 184;
const SIGMASK: usize = 304;
const INFO: usize = 312;
const RIP: usize = CONTEXT + 128;
const RAX: usize = CONTEXT + 104;
const FLAGS: usize = CONTEXT + 136;
const XMM0: usize = 160;
const FP_MAGIC1: u32 = 0x4650_5853;
const FP_MAGIC2: u32 = 0x4650_5845;

#[derive(Clone, Debug)]
pub(super) struct CapturedFrame {
    pub(super) raw: DynamicSignalFrame,
    pub(super) projected: DynamicSignalFrame,
    pub(super) final_image: Vec<u8>,
    edit_ranges: Vec<Range<usize>>,
}

pub(super) struct FrameStorage {
    projected: Vec<u8>,
    final_image: Vec<u8>,
    edit_ranges: Vec<Range<usize>>,
}

/// The two actual states that bound kernel frame construction, retained
/// separately from the original signal payload and layout/profile facts.
pub(super) struct DeliveryStates<'a> {
    pub(super) interrupted: &'a TaskStateSnapshot,
    pub(super) fetch: &'a TaskStateSnapshot,
}
impl FrameStorage {
    pub(super) fn new() -> Result<Self, GateError> {
        let allocate = || -> Result<Vec<u8>, GateError> {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(MAX_FRAME_BYTES)
                .map_err(|_| invalid("signal projection storage allocation failed"))?;
            bytes.resize(MAX_FRAME_BYTES, 0);
            Ok(bytes)
        };
        let mut edit_ranges = Vec::new();
        edit_ranges
            .try_reserve_exact(5)
            .map_err(|_| invalid("signal edit geometry allocation failed"))?;
        Ok(Self {
            projected: allocate()?,
            final_image: allocate()?,
            edit_ranges,
        })
    }
    pub(super) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.projected.len()
            + self.final_image.len()
            + self.edit_ranges.capacity() * std::mem::size_of::<Range<usize>>()
    }
}

fn invalid(message: &'static str) -> GateError {
    GateError::Refused(message)
}
fn word(bytes: &[u8], offset: usize) -> Result<u64, GateError> {
    let end = offset
        .checked_add(8)
        .ok_or(invalid("signal frame offset overflow"))?;
    let value: [u8; 8] = bytes
        .get(offset..end)
        .ok_or(invalid("signal frame word outside captured bytes"))?
        .try_into()
        .map_err(|_| invalid("signal frame word length differs"))?;
    Ok(u64::from_le_bytes(value))
}
fn half(bytes: &[u8], offset: usize) -> Result<u32, GateError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(invalid("signal FP header outside captured bytes"))?
        .try_into()
        .map_err(|_| invalid("signal FP header length differs"))?;
    Ok(u32::from_le_bytes(value))
}
fn put(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), GateError> {
    bytes
        .get_mut(offset..offset + 8)
        .ok_or(invalid("signal projection outside complete frame"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn within(range: &Range<u64>, start: u64, end: u64) -> bool {
    range.start <= start && start < end && end <= range.end
}

impl CapturedFrame {
    #[cfg(test)]
    pub(super) fn read(
        read: impl FnMut(u64, usize) -> Result<Vec<u8>, GateError>,
        id: SignalFrameId,
        profile: &DynamicSignalProfile,
        interrupted: &TaskStateSnapshot,
        fetch: &TaskStateSnapshot,
        signal: &DynamicSignalInfo,
        metadata: DynamicExceptionMetadata,
    ) -> Result<Self, GateError> {
        Self::read_with_storage(
            read,
            id,
            profile,
            DeliveryStates { interrupted, fetch },
            signal,
            metadata,
            FrameStorage::new()?,
        )
    }

    pub(super) fn read_with_storage(
        mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, GateError>,
        id: SignalFrameId,
        profile: &DynamicSignalProfile,
        states: DeliveryStates<'_>,
        signal: &DynamicSignalInfo,
        metadata: DynamicExceptionMetadata,
        storage: FrameStorage,
    ) -> Result<Self, GateError> {
        let DeliveryStates { interrupted, fetch } = states;
        let address = fetch.registers.rsp;
        let header_end = address
            .checked_add(HEADER_BYTES as u64)
            .ok_or(invalid("signal frame address overflow"))?;
        let stack = profile
            .alternate_stack
            .as_ref()
            .unwrap_or(&profile.normal_stack);
        if !within(stack, address, header_end)
            || address & 15 != 8
            || !interrupted
                .registers
                .rsp
                .checked_sub(1)
                .is_some_and(|bottom| {
                    within(&profile.normal_stack, bottom, interrupted.registers.rsp)
                })
            || fetch.registers.rip != profile.handler
            || fetch.registers.rdi != u64::from(profile.signal)
            || fetch.registers.rsi != address + INFO as u64
            || fetch.registers.rdx != address + 8
            || fetch.registers.rax != 0
            || fetch.registers.cs != 0x33
            || fetch.registers.ss != 0x2b
            || fetch.mask
                != (interrupted.mask | profile.action_mask | (1_u64 << (profile.signal - 1)))
            || interrupted.registers.cs != 0x33
            || interrupted.registers.ss != 0x2b
            || interrupted.registers.eflags & (0x100 | 0x10000) != 0
        {
            return Err(invalid("signal handler fetch/frame ABI differs"));
        }
        let header = read(address, HEADER_BYTES)?;
        if header.len() != HEADER_BYTES
            || word(&header, 0)? != profile.restorer
            || word(&header, 8)? != 7
            || word(&header, 16)? != 0
            || word(&header, SIGMASK)? != interrupted.mask
            || header.get(INFO..INFO + 128) != Some(signal.raw_bytes().as_slice())
        {
            return Err(invalid("signal frame context/siginfo/restorer differs"));
        }
        let (stack_pointer, stack_flags, stack_size) = profile
            .alternate_stack
            .as_ref()
            .map(|range| (range.start, 0_u32, range.end - range.start))
            .unwrap_or((0, libc::SS_DISABLE as u32, 0));
        if word(&header, 24)? != stack_pointer
            || half(&header, 32)? != stack_flags
            || word(&header, 40)? != stack_size
        {
            return Err(invalid("signal frame saved alternate stack differs"));
        }
        let r = &interrupted.registers;
        let general = [
            r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15, r.rdi, r.rsi, r.rbp, r.rbx,
            r.rdx, r.rax, r.rcx, r.rsp, r.rip, r.eflags,
        ];
        for (index, expected) in general.into_iter().enumerate() {
            if word(&header, CONTEXT + index * 8)? != expected {
                return Err(invalid("signal frame saved complete GPR/flags differs"));
            }
        }
        let segments = r.cs | (r.ss << 48);
        if word(&header, CONTEXT + 144)? != segments
            || word(&header, CONTEXT + 168)? != interrupted.mask
        {
            return Err(invalid("signal frame segment/mask words differ"));
        }
        let fpstate = word(&header, FP_POINTER)?;
        let minimum_fp_end = fpstate
            .checked_add(512)
            .ok_or(invalid("signal FP range overflows"))?;
        if fpstate < header_end || fpstate & 63 != 0 || !within(stack, fpstate, minimum_fp_end) {
            return Err(invalid("signal FP pointer lacks bounded native storage"));
        }
        let fp = read(fpstate, 512)?;
        if fp.len() != 512 || half(&fp, 464)? != FP_MAGIC1 {
            return Err(invalid("signal frame lacks exact extended-state magic"));
        }
        let extended = half(&fp, 468)? as usize;
        let xstate_size = half(&fp, 480)? as usize;
        if !(576..=MAX_XSTATE).contains(&xstate_size)
            || xstate_size.checked_add(4) != Some(extended)
        {
            return Err(invalid("signal extended-state size differs"));
        }
        let end = fpstate
            .checked_add(extended as u64)
            .ok_or(invalid("signal complete frame overflows"))?;
        let length = usize::try_from(
            end.checked_sub(address)
                .ok_or(invalid("signal FP state precedes frame"))?,
        )
        .map_err(|_| invalid("signal frame size overflows"))?;
        if length > MAX_FRAME_BYTES || !within(stack, address, end) {
            return Err(invalid("signal complete frame exceeds its reserved stack"));
        }
        let bytes = read(address, length)?;
        let fp_offset = usize::try_from(fpstate - address)
            .map_err(|_| invalid("signal FP offset overflows"))?;
        if bytes.len() != length
            || bytes[..HEADER_BYTES] != header
            || bytes.get(fp_offset..fp_offset + fp.len()) != Some(fp.as_slice())
            || half(&bytes, length - 4)? != FP_MAGIC2
        {
            return Err(invalid("signal frame changed or terminal FP magic differs"));
        }
        let raw = DynamicSignalFrame {
            id,
            version: 0,
            address,
            fpstate,
            bytes,
        };
        let FrameStorage {
            projected: mut projected_bytes,
            mut final_image,
            mut edit_ranges,
        } = storage;
        if projected_bytes.len() < length
            || final_image.len() < length
            || edit_ranges.capacity() < 5
        {
            return Err(invalid(
                "signal projection storage was not reserved before delivery",
            ));
        }
        projected_bytes[..length].copy_from_slice(&raw.bytes);
        projected_bytes.truncate(length);
        let mut projected = DynamicSignalFrame {
            id,
            version: 1,
            address,
            fpstate,
            bytes: projected_bytes,
        };
        put(&mut projected.bytes, TRAPNO, metadata.trapno)?;
        put(&mut projected.bytes, ERROR, metadata.error_code)?;
        put(&mut projected.bytes, CR2, metadata.cr2)?;
        final_image[..length].copy_from_slice(&projected.bytes);
        final_image.truncate(length);
        edit_ranges.clear();
        if let Some(edits) = &profile.frame_edits {
            let fp_offset = usize::try_from(fpstate - address)
                .map_err(|_| invalid("signal FP offset overflows"))?;
            put(&mut final_image, RIP, edits.landing_pc)?;
            put(&mut final_image, RAX, edits.rax)?;
            put(
                &mut final_image,
                FLAGS,
                r.eflags & if edits.clear_carry { !1 } else { u64::MAX },
            )?;
            put(&mut final_image, SIGMASK, edits.signal_mask)?;
            final_image
                .get_mut(fp_offset + XMM0..fp_offset + XMM0 + 16)
                .ok_or(invalid("signal XMM0 lies outside frame"))?
                .copy_from_slice(&edits.xmm0);
            edit_ranges.extend([
                RIP..RIP + 8,
                RAX..RAX + 8,
                FLAGS..FLAGS + 8,
                SIGMASK..SIGMASK + 8,
                fp_offset + XMM0..fp_offset + XMM0 + 16,
            ]);
        }
        Ok(Self {
            raw,
            projected,
            final_image,
            edit_ranges,
        })
    }

    /// Exact read-only check at every relying boundary. A planned edit is not
    /// evidence it occurred; return uses final_only and requires all final bytes.
    pub(super) fn validate_current(
        &self,
        current: Vec<u8>,
        final_only: bool,
    ) -> Result<Vec<u8>, GateError> {
        if current.len() != self.raw.bytes.len() {
            return Err(invalid("live signal frame became incomplete"));
        }
        if final_only {
            if current != self.final_image {
                return Err(invalid(
                    "signal return frame differs from exact final edits",
                ));
            }
            return Ok(current);
        }
        for range in &self.edit_ranges {
            let bytes = &current[range.clone()];
            if bytes != &self.projected.bytes[range.clone()]
                && bytes != &self.final_image[range.clone()]
            {
                return Err(invalid(
                    "live signal frame contains an undeclared field value",
                ));
            }
        }
        if current.iter().enumerate().any(|(index, byte)| {
            !self.edit_ranges.iter().any(|range| range.contains(&index))
                && *byte != self.projected.bytes[index]
        }) {
            return Err(invalid("live signal frame changed an undeclared byte"));
        }
        Ok(current)
    }

    pub(super) fn expected_return(
        &self,
        before: &TaskStateSnapshot,
        profile: &DynamicSignalProfile,
    ) -> Result<TaskStateSnapshot, GateError> {
        let mut state = before.clone();
        state.registers.orig_rax = u64::MAX;
        if let Some(edits) = &profile.frame_edits {
            state.registers.rip = edits.landing_pc;
            state.registers.rax = edits.rax;
            if edits.clear_carry {
                state.registers.eflags &= !1;
            }
            state.mask = edits.signal_mask;
            state
                .xstate
                .get_mut(XMM0..XMM0 + 16)
                .ok_or(invalid("saved original XMM0 is outside complete XSTATE"))?
                .copy_from_slice(&edits.xmm0);
        }
        Ok(state)
    }

    #[cfg(test)]
    pub(super) fn metadata(bytes: &[u8]) -> Result<DynamicExceptionMetadata, GateError> {
        Ok(DynamicExceptionMetadata {
            trapno: word(bytes, TRAPNO)?,
            error_code: word(bytes, ERROR)?,
            cr2: word(bytes, CR2)?,
        })
    }
}
