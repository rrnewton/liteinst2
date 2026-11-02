//! Complete bounded byte/CFG checks. These do not discover external entries or
//! prove pointer provenance, the checksum result, or termination.
use super::{IntegerLeafCertificate, SetupRefusal};
use iced_x86::{FlowControl, Mnemonic, OpKind, Register};
use liteinst2::control_flow::{self, Coverage};
use liteinst2::scanner::InstructionScanner;

fn gpr(register: Register) -> bool {
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
fn address_register(register: Register) -> bool {
    register == Register::None || (register.is_gpr64() && gpr(register))
}
fn ordinary(i: &iced_x86::Instruction) -> bool {
    if !matches!(
        i.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Movzx
            | Mnemonic::Lea
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
    for n in 0..i.op_count() {
        match i.op_kind(n) {
            OpKind::Register if gpr(i.op_register(n)) => {}
            OpKind::Memory => {
                // Only read operands (or LEA/NOP's nonaccessing address form).
                // No store, RMW, absolute, RIP-relative, 32-bit address, stack
                // or callee-saved address component is admitted.
                if (n == 0
                    && !matches!(i.mnemonic(), Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Nop))
                    || i.memory_base() == Register::None
                    || !address_register(i.memory_base())
                    || !address_register(i.memory_index())
                {
                    return false;
                }
            }
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {}
            _ => return false,
        }
    }
    true
}

pub(super) fn admit(bytes: &[u8], base: u64) -> Result<IntegerLeafCertificate, SetupRefusal> {
    let refusal = SetupRefusal::EntryExit;
    if bytes.is_empty() || bytes.len() > 256 || base == 0 {
        return Err(refusal);
    }
    let end = base.checked_add(bytes.len() as u64).ok_or(refusal)?;
    let scan = InstructionScanner::default()
        .scan(bytes, base)
        .map_err(|_| refusal)?;
    let items = scan.instructions();
    let graph = control_flow::build(&scan, |n, item, row| {
        let i = item.instruction();
        let raw = &bytes[item.offset()..item.offset() + item.len()];
        if i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.segment_prefix() != Register::None
            || i.is_privileged()
        {
            return Err(refusal);
        }
        match i.flow_control() {
            FlowControl::Next => {
                if !ordinary(i) || n + 1 == items.len() {
                    return Err(refusal);
                }
            }
            FlowControl::Return if raw == [0xc3] => {}
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if !matches!(
                    raw,
                    [0x70..=0x7f, _]
                        | [0x0f, 0x80..=0x8f, _, _, _, _]
                        | [0xeb, _]
                        | [0xe9, _, _, _, _]
                ) || i.op_count() != 1
                    || i.op_kind(0) != OpKind::NearBranch64
                {
                    return Err(refusal);
                }
                let target = i.near_branch_target();
                row.branch_target()
                    .and_then(|target| target.head())
                    .ok_or(refusal)?;
                if target == item.address() {
                    return Err(refusal);
                }
                if i.flow_control() == FlowControl::ConditionalBranch && n + 1 == items.len() {
                    return Err(refusal);
                }
            }
            _ => return Err(refusal),
        }
        Ok(())
    })?;
    let indexed = graph.indexed().map_err(|_| refusal)?;
    let reached = indexed.reachable_from(0).map_err(|_| refusal)?;
    // Compilers can leave alignment NOPs between reachable blocks. No other
    // unreachable instruction/data is silently classified as code or skipped.
    if items
        .iter()
        .enumerate()
        .any(|(n, x)| !reached[n] && x.instruction().mnemonic() != Mnemonic::Nop)
    {
        return Err(refusal);
    }
    let returns: Vec<_> = items
        .iter()
        .enumerate()
        .filter(|(n, x)| reached[*n] && x.instruction().flow_control() == FlowControl::Return)
        .map(|(_, x)| x.address())
        .collect();
    if !(1..=4).contains(&returns.len()) {
        return Err(refusal);
    }
    // Every reachable node must have a CFG path to an ordinary RET. This is
    // structural exit coverage, not a proof that input-dependent loops terminate.
    let return_indices: Vec<_> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| returns.contains(&item.address()))
        .map(|(index, _)| index)
        .collect();
    let can_return = indexed
        .can_reach_any(&return_indices)
        .map_err(|_| refusal)?;
    if reached
        .iter()
        .zip(&can_return)
        .any(|(&r, &exit)| r && !exit)
    {
        return Err(refusal);
    }
    let blocks = indexed
        .blocks(Coverage::Reachable(&reached))
        .map_err(|_| refusal)?;
    if blocks.len() > 32 {
        return Err(refusal);
    }
    let mut edges = Vec::new();
    for (n, next) in indexed.successors().iter().enumerate() {
        if reached[n] {
            edges.extend(
                next.iter()
                    .map(|&to| (items[n].address(), items[to].address())),
            );
        }
    }
    Ok(IntegerLeafCertificate {
        entry: base,
        end,
        heads: items.iter().map(|x| x.address()).collect(),
        entries: graph
            .branch_entries()
            .iter()
            .copied()
            .filter(|&n| reached[n])
            .map(|n| items[n].address())
            .collect(),
        padding: items
            .iter()
            .enumerate()
            .filter(|(n, _)| !reached[*n])
            .map(|(_, x)| x.address())
            .collect(),
        returns,
        blocks,
        edges,
    })
}

#[cfg(test)]
#[path = "cfg_adc_tests.rs"]
mod adc_tests;

#[cfg(test)]
#[path = "cfg_shared_tests.rs"]
mod shared_tests;
