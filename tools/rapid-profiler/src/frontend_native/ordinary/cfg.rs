//! Complete bounded byte/CFG checks. These do not discover external entries or
//! prove pointer provenance, the checksum result, or termination.
use super::{IntegerLeafCertificate, SetupRefusal};
use iced_x86::{FlowControl, Mnemonic, OpKind, Register};
use liteinst2::scanner::InstructionScanner;
use std::collections::BTreeSet;

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
    let mut successors = vec![Vec::new(); items.len()];
    let mut leaders = BTreeSet::from([0]);
    for (n, item) in items.iter().enumerate() {
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
                successors[n].push(n + 1);
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
                let destination = items
                    .iter()
                    .position(|x| x.address() == target)
                    .ok_or(refusal)?;
                if target == item.address() {
                    return Err(refusal);
                }
                successors[n].push(destination);
                leaders.insert(destination);
                if i.flow_control() == FlowControl::ConditionalBranch {
                    if n + 1 == items.len() {
                        return Err(refusal);
                    }
                    successors[n].push(n + 1);
                    leaders.insert(n + 1);
                }
            }
            _ => return Err(refusal),
        }
    }
    let mut reached = vec![false; items.len()];
    let mut pending = vec![0];
    while let Some(n) = pending.pop() {
        if !reached[n] {
            reached[n] = true;
            pending.extend(successors[n].iter().copied());
        }
    }
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
    let mut can_return: Vec<_> = items
        .iter()
        .map(|x| returns.contains(&x.address()))
        .collect();
    for _ in 0..items.len() {
        for (n, next) in successors.iter().enumerate() {
            let reaches = next.iter().any(|&target| can_return[target]);
            can_return[n] |= reaches;
        }
    }
    if reached
        .iter()
        .zip(&can_return)
        .any(|(&r, &exit)| r && !exit)
    {
        return Err(refusal);
    }
    let mut blocks = Vec::new();
    let mut n = 0;
    while n < items.len() {
        if !reached[n] {
            n += 1;
            continue;
        }
        let first = n;
        loop {
            let terminal = items[n].instruction().flow_control() != FlowControl::Next
                || n + 1 == items.len()
                || !reached[n + 1]
                || leaders.contains(&(n + 1));
            n += 1;
            if terminal {
                break;
            }
        }
        blocks.push((items[first].address(), items[n - 1].instruction().next_ip()));
    }
    if blocks.len() > 32 {
        return Err(refusal);
    }
    let mut edges = Vec::new();
    for (n, next) in successors.iter().enumerate() {
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
        entries: leaders
            .into_iter()
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
