//! Closed two-backedge scalar CFG; no live-source or external-entry authority.
use super::ClockError;
use crate::control_flow;
use crate::scanner::{InstructionScanner, ScanResult};
use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

pub(super) fn admit(
    bytes: &[u8],
    base: u64,
    sites: [u64; 2],
) -> Result<(ScanResult, [Option<u8>; 2]), ClockError> {
    if !(5..=80).contains(&bytes.len())
        || base == 0
        || base.checked_add(bytes.len() as u64).is_none()
        || sites[0] >= sites[1]
    {
        return Err(ClockError::Source);
    }
    let scan = InstructionScanner::default()
        .scan(bytes, base)
        .map_err(|_| ClockError::Source)?;
    let conditions = admit_scan(bytes, base, sites, &scan)?;
    Ok((scan, conditions))
}

pub(super) fn admit_scan(
    bytes: &[u8],
    base: u64,
    sites: [u64; 2],
    scan: &ScanResult,
) -> Result<[Option<u8>; 2], ClockError> {
    if !(5..=80).contains(&bytes.len())
        || base == 0
        || base.checked_add(bytes.len() as u64).is_none()
        || sites[0] >= sites[1]
        || scan.snapshot() != bytes
        || scan.instructions().first().map(|item| item.address()) != Some(base)
        || scan
            .instructions()
            .last()
            .map(|item| item.instruction().next_ip())
            != base.checked_add(bytes.len() as u64)
    {
        return Err(ClockError::Source);
    }
    let items = scan.instructions();
    let mut backedges = Vec::new();
    let mut returns = 0;
    let graph = control_flow::build(scan, |index, item, row| {
        let instruction = item.instruction();
        let raw = &bytes[item.offset()..item.offset() + item.len()];
        if instruction.has_lock_prefix()
            || instruction.has_rep_prefix()
            || instruction.has_repne_prefix()
            || instruction.segment_prefix() != Register::None
            || instruction.is_privileged()
            || !prefixes(raw)
        {
            return Err(ClockError::Source);
        }
        match instruction.flow_control() {
            FlowControl::Next => {
                if !scalar(instruction) || index + 1 == items.len() {
                    return Err(ClockError::Source);
                }
            }
            FlowControl::Return if raw == [0xc3] && index + 1 == items.len() => {
                returns += 1;
            }
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if !matches!(
                    raw,
                    [0x70..=0x7f, _]
                        | [0x0f, 0x80..=0x8f, _, _, _, _]
                        | [0xeb, _]
                        | [0xe9, _, _, _, _]
                ) || instruction.op_count() != 1
                    || instruction.op_kind(0) != OpKind::NearBranch64
                {
                    return Err(ClockError::Source);
                }
                let target = instruction.near_branch_target();
                row.branch_target()
                    .and_then(|target| target.head())
                    .ok_or(ClockError::Source)?;
                if target == item.address() {
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
                    if backedges.len() == 2 || item.address() != sites[backedges.len()] {
                        return Err(ClockError::Source);
                    }
                    backedges.push(condition);
                }
                if instruction.flow_control() == FlowControl::ConditionalBranch
                    && index + 1 == items.len()
                {
                    return Err(ClockError::Source);
                }
            }
            _ => return Err(ClockError::Source),
        }
        Ok(())
    })?;
    if returns != 1 || backedges.len() != 2 {
        return Err(ClockError::Source);
    }
    let indexed = graph.indexed().map_err(|_| ClockError::Source)?;
    let reached = indexed.reachable_from(0).map_err(|_| ClockError::Source)?;
    if reached.iter().any(|seen| !seen) {
        return Err(ClockError::Source);
    }
    // A structural exit from every head is necessary, but not a proof that a
    // particular input terminates or satisfies the caller's finite work bound.
    let can_return = indexed
        .can_reach_any(&[items.len() - 1])
        .map_err(|_| ClockError::Source)?;
    if can_return.iter().any(|exit| !exit) {
        return Err(ClockError::Source);
    }
    Ok([backedges[0], backedges[1]])
}

// The explicit v1 envelope permits one REX, not ignored/stacked prefixes or
// operand/address-size overrides. This is stricter than the old loop profile.
fn prefixes(raw: &[u8]) -> bool {
    let opcode = if matches!(raw.first(), Some(0x40..=0x4f)) {
        raw.get(1)
    } else {
        raw.first()
    };
    !matches!(
        opcode,
        None | Some(
            0x40..=0x4f
                | 0x26
                | 0x2e
                | 0x36
                | 0x3e
                | 0x64
                | 0x65
                | 0x66
                | 0x67
                | 0xf0
                | 0xf2
                | 0xf3
        )
    )
}

fn scalar(instruction: &Instruction) -> bool {
    if !matches!(
        instruction.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Movzx
            | Mnemonic::Xor
            | Mnemonic::Add
            | Mnemonic::Adc
            | Mnemonic::Sub
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Test
            | Mnemonic::Cmp
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Nop
    ) {
        return false;
    }
    (0..instruction.op_count()).all(|operand| match instruction.op_kind(operand) {
        OpKind::Register => {
            let register = instruction.op_register(operand);
            register.is_gpr()
                && matches!(
                    register.full_register(),
                    Register::RAX
                        | Register::RCX
                        | Register::RDX
                        | Register::RSI
                        | Register::RDI
                        | Register::R8
                        | Register::R9
                        | Register::R10
                        | Register::R11
                )
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => true,
        _ => false,
    })
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod cfg_shared_tests;
