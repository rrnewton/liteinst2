//! Byte/control-flow checks only; external entry and memory ownership are not decoded.
use super::ClockError;
use crate::scanner::InstructionScanner;
use iced_x86::{FlowControl, Mnemonic, OpKind, Register};

pub(super) fn admit(bytes: &[u8], base: u64, logical_pc: u64) -> Result<Option<u8>, ClockError> {
    if bytes.is_empty() || bytes.len() > 256 || base == 0 {
        return Err(ClockError::Source);
    }
    let scan = InstructionScanner::default()
        .scan(bytes, base)
        .map_err(|_| ClockError::Source)?;
    let items = scan.instructions();
    let mut successors = vec![Vec::new(); items.len()];
    let mut backedge = None;
    let mut returns = 0;
    for (index, item) in items.iter().enumerate() {
        let instruction = item.instruction();
        let raw = &bytes[item.offset()..item.offset() + item.len()];
        if instruction.has_lock_prefix()
            || instruction.has_rep_prefix()
            || instruction.has_repne_prefix()
            || instruction.segment_prefix() != Register::None
            || instruction.is_privileged()
        {
            return Err(ClockError::Source);
        }
        match instruction.flow_control() {
            FlowControl::Next => {
                if !matches!(
                    instruction.mnemonic(),
                    Mnemonic::Mov
                        | Mnemonic::Lea
                        | Mnemonic::Xor
                        | Mnemonic::Add
                        | Mnemonic::Sub
                        | Mnemonic::And
                        | Mnemonic::Or
                        | Mnemonic::Test
                        | Mnemonic::Cmp
                        | Mnemonic::Inc
                        | Mnemonic::Dec
                        | Mnemonic::Nop
                ) || (0..instruction.op_count()).any(|operand| {
                    instruction.op_kind(operand) == OpKind::Register
                        && (!instruction.op_register(operand).is_gpr()
                            || stack_pointer(instruction.op_register(operand)))
                }) || stack_pointer(instruction.memory_base())
                    || stack_pointer(instruction.memory_index())
                    || index + 1 == items.len()
                {
                    return Err(ClockError::Source);
                }
                successors[index].push(index + 1);
            }
            FlowControl::Return if raw == [0xc3] && index + 1 == items.len() => {
                returns += 1;
            }
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                // Admit only ordinary direct near Jcc/JMP encodings, not LOOP,
                // JRCXZ, far branches or prefixes with hidden size semantics.
                let direct = matches!(
                    raw,
                    [0x70..=0x7f, _]
                        | [0x0f, 0x80..=0x8f, _, _, _, _]
                        | [0xeb, _]
                        | [0xe9, _, _, _, _]
                );
                let target = instruction.near_branch_target();
                let destination = items
                    .iter()
                    .position(|i| i.address() == target)
                    .ok_or(ClockError::Source)?;
                if !direct || target == item.address() {
                    return Err(ClockError::Source);
                }
                if target < item.address() {
                    let condition = match raw {
                        [0x0f, 0x85, _, _, _, _] => Some(5),
                        [0x0f, 0x8f, _, _, _, _] => Some(15),
                        [0x0f, 0x82, _, _, _, _] => Some(2),
                        [0xe9, _, _, _, _] => None,
                        _ => return Err(ClockError::Source),
                    };
                    if item.address() != logical_pc || backedge.replace(condition).is_some() {
                        return Err(ClockError::Source);
                    }
                }
                successors[index].push(destination);
                if instruction.flow_control() == FlowControl::ConditionalBranch {
                    if index + 1 == items.len() {
                        return Err(ClockError::Source);
                    }
                    successors[index].push(index + 1);
                }
            }
            _ => return Err(ClockError::Source),
        }
    }
    if returns != 1 {
        return Err(ClockError::Source);
    }
    let condition = backedge.ok_or(ClockError::Source)?;
    let mut reached = vec![false; items.len()];
    let mut pending = vec![0];
    while let Some(index) = pending.pop() {
        if !reached[index] {
            reached[index] = true;
            pending.extend(successors[index].iter().copied());
        }
    }
    if reached.iter().any(|seen| !seen) {
        return Err(ClockError::Source);
    }
    Ok(condition)
}

fn stack_pointer(register: Register) -> bool {
    matches!(
        register,
        Register::RSP | Register::ESP | Register::SP | Register::SPL
    )
}
