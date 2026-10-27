//! Keep exact scanner-owned NOP encodings when no address field needs relocation.
use super::{Instruction, Mnemonic, OpKind, ScanResult, TrampolineError, encoding_error};

fn eligible(instruction: &Instruction) -> bool {
    instruction.mnemonic() == Mnemonic::Nop
        && instruction.flow_control() == iced_x86::FlowControl::Next
        && !instruction.is_ip_rel_memory_operand()
        // Keep every RIP/EIP/absolute/index-only operand on the old encoder
        // and artifact-field path. DeclareByte supplies no constant offsets.
        && !(instruction.op_kinds().any(|kind| kind == OpKind::Memory)
            && instruction.memory_base() == iced_x86::Register::None)
}

pub(super) fn capture(
    scan: &ScanResult,
    instructions: &[Instruction],
) -> Result<Vec<Option<Vec<u8>>>, TrampolineError> {
    instructions
        .iter()
        .map(|original| {
            if !eligible(original) {
                return Ok(None);
            }
            let scanned = scan
                .instructions()
                .iter()
                .find(|item| {
                    item.address() == original.ip()
                        && item.len() == original.len()
                        && item.instruction() == original
                })
                .ok_or_else(|| encoding_error("original NOP is absent from scanner snapshot"))?;
            let end = scanned
                .offset()
                .checked_add(scanned.len())
                .ok_or_else(|| encoding_error("original NOP extent overflow"))?;
            let bytes = scan
                .snapshot()
                .get(scanned.offset()..end)
                .ok_or_else(|| encoding_error("original NOP exceeds scanner snapshot"))?;
            Ok(Some(bytes.to_vec()))
        })
        .collect()
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn instruction(
    original: &Instruction,
    retained: Option<&[u8]>,
) -> Result<Instruction, TrampolineError> {
    if !eligible(original) {
        if retained.is_some() {
            return Err(encoding_error("unexpected retained NOP bytes"));
        }
        return Ok(*original);
    }
    let bytes = retained.ok_or_else(|| encoding_error("original NOP bytes were not retained"))?;
    let scan = super::InstructionScanner::default()
        .scan(bytes, original.ip())
        .map_err(encoding_error)?;
    if !(1..=15).contains(&bytes.len())
        || bytes.len() != original.len()
        || scan.instructions().len() != 1
        || scan.instructions()[0].instruction() != original
    {
        return Err(encoding_error(
            "retained NOP bytes differ from decoded original",
        ));
    }
    let mut directive = Instruction::with_declare_byte(bytes).map_err(encoding_error)?;
    directive.set_ip(original.ip());
    Ok(directive)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn verify(
    block: &super::BlockEncoderResult,
    index: usize,
    bytes: &[u8],
) -> Result<(), TrampolineError> {
    let start = block
        .new_instruction_offsets
        .get(index)
        .copied()
        .filter(|offset| *offset != u32::MAX)
        .ok_or_else(|| encoding_error("original NOP lost its encoder offset"))?
        as usize;
    let end = start
        .checked_add(bytes.len())
        .ok_or_else(|| encoding_error("emitted NOP extent overflow"))?;
    if block.code_buffer.get(start..end) != Some(bytes) {
        return Err(encoding_error("encoder changed original NOP bytes"));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
