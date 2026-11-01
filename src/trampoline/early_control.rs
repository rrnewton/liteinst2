//! Ordinary point gate: one retained atomic byte, no application-register ABI.
use super::*;
use iced_x86::{Encoder, MemoryOperand, Register};

const GATE_INSTRUCTIONS: usize = 11;
const MAX_GATE_BYTES: u64 = 52;
const MAX_MAPPING_BYTES: usize = 8192;

pub(super) struct GateSpec {
    indices: [usize; GATE_INSTRUCTIONS],
    load_address: u64,
    disabled: u64,
    observer: u64,
    body: u64,
}

fn stencil(
    load_address: u64,
    disabled: u64,
    observer: u64,
    body: u64,
) -> Result<[Instruction; GATE_INSTRUCTIONS], TrampolineError> {
    let adjust = |delta| {
        Instruction::with2(
            Code::Lea_r64_m,
            Register::RSP,
            MemoryOperand::with_base_displ(Register::RSP, delta),
        )
        .map_err(encoding_error)
    };
    Ok([
        adjust(-128)?,
        Instruction::with1(Code::Push_r64, Register::RCX).map_err(encoding_error)?,
        Instruction::with2(Code::Mov_r64_imm64, Register::RCX, load_address)
            .map_err(encoding_error)?,
        // x86-64's byte MOV implements an acquire load of this retained
        // AtomicBool. Its only writers are the existing atomic release stores.
        // Zero extension makes JRCXZ depend on this byte alone; no flag changes.
        Instruction::with2(
            Code::Movzx_r32_rm8,
            Register::ECX,
            MemoryOperand::with_base_displ(Register::RCX, 0),
        )
        .map_err(encoding_error)?,
        Instruction::with_branch(Code::Jrcxz_rel8_64, disabled).map_err(encoding_error)?,
        Instruction::with1(Code::Pop_r64, Register::RCX).map_err(encoding_error)?,
        adjust(128)?,
        Instruction::with_branch(Code::Jmp_rel32_64, observer).map_err(encoding_error)?,
        Instruction::with1(Code::Pop_r64, Register::RCX).map_err(encoding_error)?,
        adjust(128)?,
        Instruction::with_branch(Code::Jmp_rel32_64, body).map_err(encoding_error)?,
    ])
}

pub(super) fn append(
    output: &mut Vec<Instruction>,
    control: &ProbeControl,
    observer: u64,
    body: u64,
    identity: &mut impl FnMut() -> Result<u64, TrampolineError>,
) -> Result<GateSpec, TrampolineError> {
    let disabled = identity()?;
    let load_address = control.enabled_load().address();
    let mut indices = [0; GATE_INSTRUCTIONS];
    for (ordinal, mut instruction) in stencil(load_address, disabled, observer, body)?
        .into_iter()
        .enumerate()
    {
        if ordinal == 8 {
            let mut marker = Instruction::with(Code::Zero_bytes);
            marker.set_ip(disabled);
            output.push(marker);
        }
        instruction.set_ip(identity()?);
        indices[ordinal] = output.len();
        output.push(instruction);
    }
    Ok(GateSpec {
        indices,
        load_address,
        disabled,
        observer,
        body,
    })
}

fn actual_address(
    index: usize,
    address: u64,
    encoded: &BlockEncoderResult,
) -> Result<u64, TrampolineError> {
    let offset = encoded
        .new_instruction_offsets
        .get(index)
        .copied()
        .filter(|value| *value != u32::MAX)
        .ok_or_else(|| encoding_error("early gate lost exact instruction offset"))?;
    address
        .checked_add(u64::from(offset))
        .ok_or_else(|| encoding_error("early gate address overflow"))
}

/// Verify the complete final stencil against its actual retained byte owner.
/// Only canonical direct JMP rel8/rel32 relaxation is admitted. The rel8 JRCXZ
/// crosses one local restoration arm, never the opaque observer helper.
pub(super) fn verify(
    spec: &GateSpec,
    original: &[Instruction],
    address: u64,
    encoded: &BlockEncoderResult,
    action: &ControlledAction,
    boundaries: (usize, usize, usize),
) -> Result<crate::controls::EarlyControlGateLayout, TrampolineError> {
    let (entry, observer, body) = boundaries;
    let disabled = spec.indices[8]
        .checked_sub(1)
        .ok_or_else(|| encoding_error("early gate disabled marker missing"))?;
    if spec.load_address != action.control.enabled_load().address()
        || spec.indices[0]
            != entry
                .checked_add(1)
                .ok_or_else(|| encoding_error("early gate index overflow"))?
        || spec.observer == spec.body
        || spec.disabled == spec.observer
        || spec.disabled == spec.body
        || !original
            .get(entry)
            .is_some_and(|i| i.code() == Code::Zero_bytes)
    {
        return Err(encoding_error("early gate owner/entry metadata differs"));
    }
    for (index, label) in [
        (disabled, spec.disabled),
        (observer, spec.observer),
        (body, spec.body),
    ] {
        if !original
            .get(index)
            .is_some_and(|i| i.code() == Code::Zero_bytes && i.ip() == label)
        {
            return Err(encoding_error("early gate local label differs"));
        }
    }
    let entry_pc = actual_address(entry, address, encoded)?;
    let disabled_pc = actual_address(disabled, address, encoded)?;
    let observer_pc = actual_address(observer, address, encoded)?;
    let body_pc = actual_address(body, address, encoded)?;
    if observer
        != spec.indices[10]
            .checked_add(1)
            .ok_or_else(|| encoding_error("early gate index overflow"))?
        || observer_pc <= entry_pc
        || observer_pc - entry_pc > MAX_GATE_BYTES
        || body_pc <= observer_pc
    {
        return Err(encoding_error("early gate extent/continuations differ"));
    }
    let expected = stencil(spec.load_address, disabled_pc, observer_pc, body_pc)?;
    let mut cursor = entry_pc;
    for (ordinal, mut expected) in expected.into_iter().enumerate() {
        let index = spec.indices[ordinal];
        let exact_index = spec.indices[0]
            .checked_add(ordinal + usize::from(ordinal >= 8))
            .ok_or_else(|| encoding_error("early gate index overflow"))?;
        if index != exact_index {
            return Err(encoding_error("early gate instruction population differs"));
        }
        let pc = actual_address(index, address, encoded)?;
        if pc != cursor || (ordinal == 8 && pc != disabled_pc) {
            return Err(encoding_error("early gate instruction extent differs"));
        }
        let offset = usize::try_from(pc - address).map_err(encoding_error)?;
        let bytes = encoded
            .code_buffer
            .get(offset..)
            .ok_or_else(|| encoding_error("early gate offset exceeds image"))?;
        let observed = Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE).decode();
        let jump = expected.code() == Code::Jmp_rel32_64
            && matches!(observed.code(), Code::Jmp_rel8_64 | Code::Jmp_rel32_64);
        if (!jump && observed.code() != expected.code()) || observed.rflags_modified() != 0 {
            return Err(encoding_error("early gate opcode/flags changed"));
        }
        if jump {
            expected.set_code(observed.code());
        }
        let mut encoder = Encoder::new(64);
        encoder.encode(&expected, pc).map_err(encoding_error)?;
        let canonical = encoder.take_buffer();
        if observed.len() != canonical.len()
            || bytes.get(..canonical.len()) != Some(canonical.as_slice())
            || (ordinal == 4
                && (canonical.len() != 2
                    || i8::try_from(i128::from(disabled_pc) - i128::from(observed.next_ip()))
                        .is_err()))
        {
            return Err(encoding_error("early gate bytes/operands/width changed"));
        }
        cursor = pc
            .checked_add(canonical.len() as u64)
            .ok_or_else(|| encoding_error("early gate end overflow"))?;
    }
    if cursor != observer_pc {
        return Err(encoding_error("early gate lost observer continuation"));
    }
    Ok(crate::controls::EarlyControlGateLayout {
        logical_pc: action.logical_pc,
        entry: entry_pc,
        post_load: actual_address(spec.indices[4], address, encoded)?,
        observing_entry: observer_pc,
        original_body: body_pc,
    })
}

pub(super) fn validate_image_extent(address: u64, len: usize) -> Result<(), TrampolineError> {
    let end = address
        .checked_add(len as u64)
        .and_then(|value| value.checked_add(4095))
        .ok_or_else(|| encoding_error("early point image extent overflow"))?
        & !4095;
    if len == 0 || end - (address & !4095) > MAX_MAPPING_BYTES as u64 {
        return Err(TrampolineError::CodeTooLarge {
            code_len: len,
            allocation_len: MAX_MAPPING_BYTES - (address & 4095) as usize,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
