//! Closed, exact-width expression proof. Symbols P/H/T are never identified
//! merely because the observed getpid and gettid happen to have equal values.
use super::OracleError;
use super::artifact::{ArtifactPlan, PlannedInstruction, PlannedKind};
use crate::RegisterSnapshot;
use crate::linux::remote::dynamic::owner::trusted::TaskStateSnapshot;
use iced_x86::{Code, Instruction, Mnemonic, OpKind, Register};

#[cfg(test)]
mod tests;
fn bad() -> OracleError {
    OracleError::Invalid("artifact expression or full state differs")
}

/// Unknown is not zero and cannot satisfy any terminal/helper equation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Expression {
    Unknown,
    Affine {
        coefficients: [u64; 19],
        constant: u64,
    },
}
impl Expression {
    const fn constant(value: u64) -> Self {
        Self::Affine {
            coefficients: [0; 19],
            constant: value,
        }
    }
    const fn symbol(index: usize) -> Self {
        let mut coefficients = [0; 19];
        coefficients[index] = 1;
        Self::Affine {
            coefficients,
            constant: 0,
        }
    }
    fn add(self, other: Self, subtract: bool) -> Self {
        match (self, other) {
            (
                Self::Affine {
                    coefficients: a,
                    constant: x,
                },
                Self::Affine {
                    coefficients: b,
                    constant: y,
                },
            ) => {
                let mut coefficients = [0; 19];
                for (i, coefficient) in coefficients.iter_mut().enumerate() {
                    *coefficient = if subtract {
                        a[i].wrapping_sub(b[i])
                    } else {
                        a[i].wrapping_add(b[i])
                    };
                }
                Self::Affine {
                    coefficients,
                    constant: if subtract {
                        x.wrapping_sub(y)
                    } else {
                        x.wrapping_add(y)
                    },
                }
            }
            _ => Self::Unknown,
        }
    }
    fn scale(self, factor: u64) -> Self {
        match self {
            Self::Affine {
                mut coefficients,
                constant,
            } => {
                for value in &mut coefficients {
                    *value = value.wrapping_mul(factor);
                }
                Self::Affine {
                    coefficients,
                    constant: constant.wrapping_mul(factor),
                }
            }
            Self::Unknown => Self::Unknown,
        }
    }
    fn width(self, width: u32) -> Result<Self, OracleError> {
        if width == 64 {
            return Ok(self);
        }
        match self {
            Self::Affine {
                coefficients,
                constant,
            } if coefficients.iter().all(|c| *c == 0) => {
                Ok(Self::constant(u64::from(constant as u32)))
            }
            _ => Err(OracleError::Invalid("artifact narrows a symbolic identity")),
        }
    }
}

pub(super) fn temporary_bytes() -> Result<usize, OracleError> {
    // Two register expression banks, saved callee set, arithmetic/source copies,
    // complete register models and fixed iterator/index locals. No heap.
    ((2 * 16 + 6 + 8) * std::mem::size_of::<Expression>())
        .checked_add(
            4 * std::mem::size_of::<RegisterSnapshot>()
                + 2 * 16 * std::mem::size_of::<u64>()
                + 32 * std::mem::size_of::<usize>(),
        )
        .ok_or(OracleError::Invalid("artifact dataflow temporary overflow"))
}

pub(super) struct DataflowContract {
    pub(super) call: usize,
    pub(super) ret: usize,
    pub(super) syscalls: [usize; 3],
    pub(super) count: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FrameObservation {
    pub(super) initial_rsp: u64,
    pub(super) call_slot: u64,
    pub(super) return_pc: u64,
    pub(super) helper_pc: u64,
}
pub(super) fn require_frame(
    plan: &ArtifactPlan,
    initial: &TaskStateSnapshot,
) -> Result<FrameObservation, OracleError> {
    let s = initial.registers.rsp;
    if s == 0 || s % 16 != 0 || s >= 0x0000_8000_0000_0000 || initial.registers.rip != plan.entry {
        return Err(bad());
    }
    Ok(FrameObservation {
        initial_rsp: s,
        call_slot: s.checked_sub(8).ok_or_else(bad)?,
        return_pc: plan.instruction(plan.call)?.next_pc(),
        helper_pc: plan.helper.start,
    })
}
fn register(register: Register) -> Result<(usize, u32), OracleError> {
    use Register::*;
    let value = match register {
        RAX => (0, 64),
        RCX => (1, 64),
        RDX => (2, 64),
        RBX => (3, 64),
        RSP => (4, 64),
        RBP => (5, 64),
        RSI => (6, 64),
        RDI => (7, 64),
        R8 => (8, 64),
        R9 => (9, 64),
        R10 => (10, 64),
        R11 => (11, 64),
        R12 => (12, 64),
        R13 => (13, 64),
        R14 => (14, 64),
        R15 => (15, 64),
        EAX => (0, 32),
        ECX => (1, 32),
        EDX => (2, 32),
        EBX => (3, 32),
        ESP => (4, 32),
        EBP => (5, 32),
        ESI => (6, 32),
        EDI => (7, 32),
        R8D => (8, 32),
        R9D => (9, 32),
        R10D => (10, 32),
        R11D => (11, 32),
        R12D => (12, 32),
        R13D => (13, 32),
        R14D => (14, 32),
        R15D => (15, 32),
        _ => return Err(bad()),
    };
    Ok(value)
}
fn immediate(i: &Instruction) -> Result<u64, OracleError> {
    Ok(match i.op1_kind() {
        OpKind::Immediate32 => u64::from(i.immediate32()),
        OpKind::Immediate64 => i.immediate64(),
        OpKind::Immediate32to64 => i.immediate32to64() as u64,
        OpKind::Immediate8to64 => i.immediate8to64() as u64,
        OpKind::Immediate8to32 => u64::from(i.immediate8to32() as u32),
        _ => return Err(bad()),
    })
}
pub(super) fn require_ordinary(i: &Instruction, bytes: &[u8]) -> Result<(), OracleError> {
    if bytes.is_empty()
        || i.has_lock_prefix()
        || i.has_rep_prefix()
        || i.has_repne_prefix()
        || i.segment_prefix() != Register::None
    {
        return Err(bad());
    }
    let mut prefix = 0;
    if (0x40..=0x4f).contains(&bytes[0]) {
        prefix = 1;
    }
    if bytes.get(prefix).is_none_or(|b| {
        matches!(
            *b,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 | 0x40
                ..=0x4f
        )
    }) {
        return Err(bad());
    }
    if matches!(i.code(), Code::Nopd | Code::Nopq) && bytes == [0x90] {
        return Ok(());
    }
    let accepted = matches!(
        i.code(),
        Code::Mov_rm32_r32
            | Code::Mov_rm64_r64
            | Code::Mov_r32_rm32
            | Code::Mov_r64_rm64
            | Code::Mov_r32_imm32
            | Code::Mov_r64_imm64
            | Code::Mov_rm32_imm32
            | Code::Mov_rm64_imm32
            | Code::Lea_r64_m
            | Code::Add_rm32_r32
            | Code::Add_rm64_r64
            | Code::Add_r32_rm32
            | Code::Add_r64_rm64
            | Code::Add_EAX_imm32
            | Code::Add_RAX_imm32
            | Code::Add_rm32_imm32
            | Code::Add_rm64_imm32
            | Code::Add_rm32_imm8
            | Code::Add_rm64_imm8
            | Code::Sub_rm32_r32
            | Code::Sub_rm64_r64
            | Code::Sub_r32_rm32
            | Code::Sub_r64_rm64
            | Code::Sub_EAX_imm32
            | Code::Sub_RAX_imm32
            | Code::Sub_rm32_imm32
            | Code::Sub_rm64_imm32
            | Code::Sub_rm32_imm8
            | Code::Sub_rm64_imm8
    );
    if !accepted || i.op_count() != 2 || i.op0_kind() != OpKind::Register {
        return Err(bad());
    }
    let (destination, width) = register(i.op0_register())?;
    if destination == 4 {
        return Err(OracleError::Invalid("artifact writes an RSP alias"));
    }
    if i.mnemonic() == Mnemonic::Lea {
        if width != 64
            || i.op1_kind() != OpKind::Memory
            || !matches!(i.memory_index_scale(), 1 | 2 | 4 | 8)
        {
            return Err(bad());
        }
        for r in [i.memory_base(), i.memory_index()] {
            if !matches!(r, Register::None | Register::RIP) {
                let (_, w) = register(r)?;
                if w != 64 {
                    return Err(bad());
                }
            }
        }
    } else if i.op1_kind() == OpKind::Register {
        if register(i.op1_register())?.1 != width {
            return Err(bad());
        }
    } else {
        immediate(i)?;
    }
    Ok(())
}
fn source(i: &Instruction, registers: &[Expression; 16]) -> Result<Expression, OracleError> {
    if i.mnemonic() == Mnemonic::Lea {
        if i.memory_base() == Register::RIP {
            return Ok(Expression::constant(i.ip_rel_memory_address()));
        }
        let base = if i.memory_base() == Register::None {
            Expression::constant(0)
        } else {
            registers[register(i.memory_base())?.0]
        };
        let index = if i.memory_index() == Register::None {
            Expression::constant(0)
        } else {
            registers[register(i.memory_index())?.0].scale(u64::from(i.memory_index_scale()))
        };
        return Ok(base
            .add(index, false)
            .add(Expression::constant(i.memory_displacement64()), false));
    }
    if i.op1_kind() == OpKind::Register {
        let (r, width) = register(i.op1_register())?;
        registers[r].width(width)
    } else {
        Ok(Expression::constant(immediate(i)?))
    }
}
fn ordinary(i: &Instruction, registers: &mut [Expression; 16]) -> Result<(), OracleError> {
    if i.mnemonic() == Mnemonic::Nop {
        return Ok(());
    }
    let (destination, width) = register(i.op0_register())?;
    let rhs = source(i, registers)?;
    let value = match i.mnemonic() {
        Mnemonic::Mov | Mnemonic::Lea => rhs,
        Mnemonic::Add => registers[destination].width(width)?.add(rhs, false),
        Mnemonic::Sub => registers[destination].width(width)?.add(rhs, true),
        _ => return Err(bad()),
    };
    registers[destination] = value.width(width)?;
    Ok(())
}
pub(super) fn prove_dataflow(plan: &ArtifactPlan) -> Result<DataflowContract, OracleError> {
    let mut registers = std::array::from_fn(|index| Expression::symbol(3 + index));
    let mut preserved = None;
    for instruction in plan.instructions() {
        match instruction.kind() {
            PlannedKind::Ordinary => ordinary(instruction.decoded(), &mut registers)?,
            PlannedKind::Call => {
                if registers[7] != Expression::symbol(0) {
                    return Err(bad());
                }
                // E8 pushes the actual next PC before the helper executes.
                // RSP reads remain legal ordinary sources and must see S-8.
                registers[4] = registers[4].add(Expression::constant(8), true);
                preserved = Some([
                    registers[3],
                    registers[5],
                    registers[12],
                    registers[13],
                    registers[14],
                    registers[15],
                ]);
            }
            PlannedKind::Ret => {
                if registers[0] != Expression::symbol(0).add(Expression::constant(7), false)
                    || preserved
                        != Some([
                            registers[3],
                            registers[5],
                            registers[12],
                            registers[13],
                            registers[14],
                            registers[15],
                        ])
                {
                    return Err(bad());
                }
                // C3 consumes that word; caller-side RSP reads see S again.
                registers[4] = registers[4].add(Expression::constant(8), false);
                registers[0] = Expression::symbol(1);
            }
            PlannedKind::Syscall { number } => {
                if registers[0] != Expression::constant(number) {
                    return Err(bad());
                }
                match number {
                    39 => registers[0] = Expression::symbol(0),
                    186 => registers[0] = Expression::symbol(2),
                    231 => {
                        if registers[7] != Expression::symbol(1).add(Expression::symbol(2), true) {
                            return Err(OracleError::Invalid(
                                "terminal argument does not consume helper result minus gettid",
                            ));
                        }
                    }
                    _ => return Err(bad()),
                }
                registers[1] = Expression::Unknown;
                registers[11] = Expression::Unknown;
            }
        }
    }
    Ok(DataflowContract {
        call: plan.call,
        ret: plan.ret,
        syscalls: plan.syscalls,
        count: plan.len(),
    })
}
fn constant_value(value: Expression) -> Result<u64, OracleError> {
    match value {
        Expression::Affine {
            coefficients,
            constant,
        } if coefficients.iter().all(|c| *c == 0) => Ok(constant),
        _ => Err(bad()),
    }
}
fn values(r: &RegisterSnapshot) -> [u64; 16] {
    [
        r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12,
        r.r13, r.r14, r.r15,
    ]
}
fn set(r: &mut RegisterSnapshot, index: usize, value: u64) {
    match index {
        0 => r.rax = value,
        1 => r.rcx = value,
        2 => r.rdx = value,
        3 => r.rbx = value,
        4 => r.rsp = value,
        5 => r.rbp = value,
        6 => r.rsi = value,
        7 => r.rdi = value,
        8 => r.r8 = value,
        9 => r.r9 = value,
        10 => r.r10 = value,
        11 => r.r11 = value,
        12 => r.r12 = value,
        13 => r.r13 = value,
        14 => r.r14 = value,
        15 => r.r15 = value,
        _ => unreachable!(),
    }
}
fn flags(before: u64, left: u64, right: u64, result: u64, width: u32, subtract: bool) -> u64 {
    let mask = if width == 64 {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    };
    let sign = 1_u64 << (width - 1);
    let l = left & mask;
    let r = right & mask;
    let v = result & mask;
    let carry = if subtract {
        l < r
    } else {
        u128::from(l) + u128::from(r) > u128::from(mask)
    };
    let overflow = if subtract {
        (l ^ r) & (l ^ v) & sign != 0
    } else {
        (!(l ^ r)) & (l ^ v) & sign != 0
    };
    let produced = u64::from(carry)
        | (u64::from((v as u8).count_ones() % 2 == 0) << 2)
        | (u64::from((l ^ r ^ v) & 16 != 0) << 4)
        | (u64::from(v == 0) << 6)
        | (u64::from(v & sign != 0) << 7)
        | (u64::from(overflow) << 11);
    (before & !0x8d5) | produced
}
/// Complete own-lane equality for an admitted closed ordinary instruction.
pub(super) fn compare_ordinary(
    instruction: &PlannedInstruction,
    before: &TaskStateSnapshot,
    after: &TaskStateSnapshot,
) -> Result<(), OracleError> {
    if instruction.kind() != PlannedKind::Ordinary || before.registers.rip != instruction.pc() {
        return Err(bad());
    }
    let mut expected = before.registers;
    let i = instruction.decoded();
    if i.mnemonic() != Mnemonic::Nop {
        let mut model = values(&before.registers).map(Expression::constant);
        let (destination, width) = register(i.op0_register())?;
        let rhs = source(i, &model)?;
        let right = constant_value(rhs)?;
        let left = values(&before.registers)[destination];
        ordinary(i, &mut model)?;
        let value = constant_value(model[destination])?;
        set(&mut expected, destination, value);
        if matches!(i.mnemonic(), Mnemonic::Add | Mnemonic::Sub) {
            expected.eflags = flags(
                expected.eflags,
                left,
                right,
                value,
                width,
                i.mnemonic() == Mnemonic::Sub,
            );
        }
    }
    expected.rip = instruction.next_pc();
    expected.orig_rax = u64::MAX;
    if after.registers != expected || after.xstate != before.xstate || after.mask != before.mask {
        return Err(bad());
    }
    Ok(())
}
pub(super) fn compare_stack(
    plan: &ArtifactPlan,
    frame: FrameObservation,
    ordinal: usize,
    before: &TaskStateSnapshot,
    after: &TaskStateSnapshot,
) -> Result<(), OracleError> {
    let instruction = plan.instruction(ordinal)?;
    let mut expected = before.registers;
    match instruction.kind() {
        PlannedKind::Call => {
            if expected.rip != instruction.pc() || expected.rsp != frame.initial_rsp {
                return Err(bad());
            }
            expected.rip = frame.helper_pc;
            expected.rsp = frame.call_slot;
        }
        PlannedKind::Ret => {
            if expected.rip != instruction.pc() || expected.rsp != frame.call_slot {
                return Err(bad());
            }
            expected.rip = frame.return_pc;
            expected.rsp = frame.initial_rsp;
        }
        _ => return Err(bad()),
    }
    expected.orig_rax = u64::MAX;
    if after.registers != expected || after.xstate != before.xstate || after.mask != before.mask {
        return Err(bad());
    }
    Ok(())
}
/// Returning identity syscalls preserve every other own-lane component. The
/// caller must separately establish the real task/PID namespace association.
pub(super) fn compare_kernel_return(
    instruction: &PlannedInstruction,
    before: &TaskStateSnapshot,
    after: &TaskStateSnapshot,
    actual_pid: i32,
) -> Result<(), OracleError> {
    let PlannedKind::Syscall { number } = instruction.kind() else {
        return Err(bad());
    };
    if !matches!(number, 39 | 186)
        || actual_pid <= 0
        || before.registers.rip != instruction.pc()
        || before.registers.rax != number
    {
        return Err(bad());
    }
    let expected = RegisterSnapshot {
        rip: instruction.next_pc(),
        rcx: instruction.next_pc(),
        r11: before.registers.eflags & !0x10000,
        eflags: before.registers.eflags & !0x10000,
        orig_rax: number,
        rax: actual_pid as u64,
        ..before.registers
    };
    if after.registers != expected || after.xstate != before.xstate || after.mask != before.mask {
        return Err(bad());
    }
    Ok(())
}

/// Runtime counterpart to the symbolic proof: complete retained states remain
/// available; this only checks actual semantic values and ABI relationships.
pub(super) fn compare_value_flow<'a>(
    plan: &ArtifactPlan,
    contract: &DataflowContract,
    mut states: impl FnMut(
        usize,
    ) -> Result<
        (&'a TaskStateSnapshot, Option<&'a TaskStateSnapshot>),
        OracleError,
    >,
) -> Result<(), OracleError> {
    if (
        contract.call,
        contract.ret,
        contract.syscalls,
        contract.count,
    ) != (plan.call, plan.ret, plan.syscalls, plan.len())
    {
        return Err(bad());
    }
    let (_, pid) = states(plan.syscalls[0])?;
    let p = pid.ok_or_else(bad)?.registers.rax;
    let (call, _) = states(plan.call)?;
    let (ret, _) = states(plan.ret)?;
    let (_, tid) = states(plan.syscalls[1])?;
    let t = tid.ok_or_else(bad)?.registers.rax;
    if p == 0
        || p > i32::MAX as u64
        || t != p
        || call.registers.rdi != p
        || ret.registers.rax != p.checked_add(7).ok_or_else(bad)?
    {
        return Err(bad());
    }
    let a = values(&call.registers);
    let b = values(&ret.registers);
    if [3, 5, 12, 13, 14, 15].into_iter().any(|r| a[r] != b[r]) {
        return Err(bad());
    }
    let (terminal, after) = states(plan.syscalls[2])?;
    if after.is_some()
        || terminal.registers.rax != 231
        || terminal.registers.rdi != 7
        || terminal.registers.rdi != ret.registers.rax.wrapping_sub(t)
    {
        return Err(bad());
    }
    Ok(())
}
