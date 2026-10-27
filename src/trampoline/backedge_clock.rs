//! Real encoder instructions/labels; no emitted-image byte surgery.
use super::*;
use crate::backedge_clock::{BackedgeClockAction, ClockMode};
use iced_x86::{MemoryOperand, Register};

pub(super) struct GateSpec {
    indices: Vec<usize>,
}

pub(super) fn append(
    output: &mut Vec<Instruction>,
    action: &BackedgeClockAction,
    observer: u64,
    body: u64,
    identity: &mut impl FnMut() -> Result<u64, TrampolineError>,
) -> Result<GateSpec, TrampolineError> {
    let fast = identity()?;
    let slow = identity()?;
    let mut indices = Vec::new();
    let mut emit = |mut i: Instruction, label: Option<u64>| -> Result<(), TrampolineError> {
        i.set_ip(match label {
            Some(label) => label,
            None => identity()?,
        });
        indices.push(output.len());
        output.push(i);
        Ok(())
    };
    let rip = |offset: u64| {
        MemoryOperand::with_base_displ(Register::RIP, (action.clock.address() + offset) as i64)
    };
    let load = |offset| {
        Instruction::with2(Code::Mov_r64_rm64, Register::RCX, rip(offset)).map_err(encoding_error)
    };
    let store = |offset| {
        Instruction::with2(Code::Mov_rm64_r64, rip(offset), Register::RCX).map_err(encoding_error)
    };
    let lea = |delta| {
        Instruction::with2(
            Code::Lea_r64_m,
            Register::RCX,
            MemoryOperand::with_base_displ(Register::RCX, delta),
        )
        .map_err(encoding_error)
    };
    let branch = |code, target| Instruction::with_branch(code, target).map_err(encoding_error);
    emit(store(0)?, None)?;
    emit(load(8)?, None)?;
    emit(lea(1)?, None)?;
    emit(store(8)?, None)?;
    if let Some(cc) = action.condition {
        let inverse = match cc {
            5 => Code::Je_rel32_64,
            15 => Code::Jle_rel32_64,
            2 => Code::Jae_rel32_64,
            _ => return Err(encoding_error("unsupported clock condition")),
        };
        emit(branch(inverse, fast)?, None)?;
    }
    emit(load(16)?, None)?;
    emit(lea(1)?, None)?;
    emit(store(16)?, None)?;
    if action.mode == ClockMode::Stop {
        emit(load(24)?, None)?;
        emit(lea(-1)?, None)?;
        emit(store(24)?, None)?;
        emit(branch(Code::Jrcxz_rel8_64, slow)?, None)?;
    }
    emit(load(0)?, Some(fast))?;
    emit(branch(Code::Jmp_rel32_64, body)?, None)?;
    if action.mode == ClockMode::Stop {
        emit(load(0)?, Some(slow))?;
        emit(branch(Code::Jmp_rel32_64, observer)?, None)?;
    }
    Ok(GateSpec { indices })
}

/// Admit exact final forms and address/label correspondence after the real encoder.
/// JRCXZ expansion, address-size prefixes and absolute-memory fallback all refuse.
pub(super) fn verify(
    spec: &GateSpec,
    original: &[Instruction],
    address: u64,
    encoded: &BlockEncoderResult,
) -> Result<(), TrampolineError> {
    let actual_address = |index: usize| -> Result<u64, TrampolineError> {
        let offset = *encoded
            .new_instruction_offsets
            .get(index)
            .filter(|&&offset| offset != u32::MAX)
            .ok_or_else(|| encoding_error("inline gate lost exact instruction"))?;
        address
            .checked_add(u64::from(offset))
            .ok_or_else(|| encoding_error("inline gate address overflow"))
    };
    for &index in &spec.indices {
        let expected = &original[index];
        let pc = actual_address(index)?;
        let offset = usize::try_from(pc - address).map_err(encoding_error)?;
        let mut decoder =
            Decoder::with_ip(64, &encoded.code_buffer[offset..], pc, DecoderOptions::NONE);
        let observed = decoder.decode();
        if observed.code() != expected.code()
            || observed.op_count() != expected.op_count()
            || observed.rflags_modified() != 0
            || observed.has_lock_prefix()
            || observed.has_rep_prefix()
            || observed.has_repne_prefix()
            || observed.segment_prefix() != Register::None
        {
            return Err(encoding_error("inline gate opcode/flags/prefix changed"));
        }
        for operand in 0..expected.op_count() {
            if observed.op_kind(operand) != expected.op_kind(operand) {
                return Err(encoding_error("inline gate operand kind changed"));
            }
            match expected.op_kind(operand) {
                OpKind::Register
                    if observed.op_register(operand) != expected.op_register(operand) =>
                {
                    return Err(encoding_error("inline gate register changed"));
                }
                OpKind::NearBranch64 => {
                    let target_index = original
                        .iter()
                        .position(|i| i.ip() == expected.near_branch_target())
                        .ok_or_else(|| encoding_error("inline gate target lacks exact label"))?;
                    if observed.near_branch_target() != actual_address(target_index)? {
                        return Err(encoding_error("inline gate target changed"));
                    }
                }
                OpKind::Memory => {
                    if observed.memory_base() != expected.memory_base()
                        || observed.memory_index() != expected.memory_index()
                        || observed.memory_index_scale() != expected.memory_index_scale()
                        || observed.memory_displacement64() != expected.memory_displacement64()
                        || observed.memory_size() != expected.memory_size()
                    {
                        return Err(encoding_error("inline gate memory binding changed"));
                    }
                    if observed.is_ip_rel_memory_operand()
                        && i32::try_from(
                            i128::from(observed.ip_rel_memory_address())
                                - i128::from(observed.next_ip()),
                        )
                        .is_err()
                    {
                        return Err(encoding_error("inline clock word exceeds signed RIP reach"));
                    }
                }
                OpKind::Register => {}
                _ => return Err(encoding_error("inline gate unexpected operand")),
            }
        }
        if observed.code() == Code::Jrcxz_rel8_64 && observed.len() != 2 {
            return Err(encoding_error(
                "inline clock JRCXZ address-size/width changed",
            ));
        }
    }
    Ok(())
}
