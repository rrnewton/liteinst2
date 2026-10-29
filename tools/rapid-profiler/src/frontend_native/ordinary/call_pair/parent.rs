//! Complete bounded caller admission. No literal compiler output is authority.
use super::{NormalCallPairEdge, NormalCallPairParentCertificate, SetupRefusal};
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, SetupRefusal>;
const FRAME: i32 = 64;
const GPRS: [Register; 16] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RSP,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];
const SAVED: [Register; 6] = [
    Register::RBX,
    Register::RBP,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];
const VOLATILE: [Register; 9] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Origin {
    Initial(Register),
    Input,
    Length,
    Stack(i32),
    ChildResult,
    LengthHigh,
    Packed,
    Unknown,
}
#[derive(Clone, Copy)]
enum Operand {
    Register(Register),
    Memory(Register, i32),
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(SetupRefusal::EntryExit)
    }
}
fn index(r: Register) -> Result<usize> {
    GPRS.iter()
        .position(|&g| g == r)
        .ok_or(SetupRefusal::EntryExit)
}
struct State {
    regs: [Origin; 16],
    stack: BTreeMap<i32, Origin>,
    sp: i32,
    lowest: i32,
}
impl State {
    fn new() -> Self {
        let mut regs = GPRS.map(Origin::Initial);
        regs[4] = Origin::Stack(0);
        regs[6] = Origin::Length;
        regs[7] = Origin::Input;
        Self {
            regs,
            stack: BTreeMap::new(),
            sp: 0,
            lowest: 0,
        }
    }
    fn reg(&self, r: Register) -> Result<Origin> {
        Ok(self.regs[index(r)?])
    }
    fn move_sp(&mut self, next: i32) -> Result<()> {
        require((-FRAME..=0).contains(&next) && next % 8 == 0)?;
        self.stack.retain(|&at, _| at >= next);
        self.sp = next;
        self.lowest = self.lowest.min(next);
        self.regs[4] = Origin::Stack(next);
        Ok(())
    }
    fn write_reg(&mut self, r: Register, value: Origin) -> Result<()> {
        if r == Register::RSP {
            let Origin::Stack(next) = value else {
                return Err(SetupRefusal::EntryExit);
            };
            self.move_sp(next)
        } else {
            self.regs[index(r)?] = value;
            Ok(())
        }
    }
    fn address(&self, r: Register, offset: i32) -> Result<i32> {
        let Origin::Stack(base) = self.reg(r)? else {
            return Err(SetupRefusal::EntryExit);
        };
        let at = base.checked_add(offset).ok_or(SetupRefusal::EntryExit)?;
        require(
            at >= self.sp && at < 0 && at % 8 == 0 && at.checked_add(8).is_some_and(|end| end <= 0),
        )?;
        Ok(at)
    }
    fn read(&self, operand: Operand) -> Result<Origin> {
        match operand {
            Operand::Register(r) => self.reg(r),
            Operand::Memory(r, offset) => self
                .stack
                .get(&self.address(r, offset)?)
                .copied()
                .ok_or(SetupRefusal::EntryExit),
        }
    }
    fn write(&mut self, operand: Operand, value: Origin) -> Result<()> {
        match operand {
            Operand::Register(r) => self.write_reg(r, value),
            Operand::Memory(r, offset) => {
                self.stack.insert(self.address(r, offset)?, value);
                Ok(())
            }
        }
    }
}
fn operand(i: &Instruction, n: u32) -> Result<Operand> {
    match i.op_kind(n) {
        OpKind::Register => {
            let r = i.op_register(n);
            index(r)?;
            Ok(Operand::Register(r))
        }
        OpKind::Memory => {
            let r = i.memory_base();
            index(r)?;
            require(
                i.memory_index() == Register::None
                    && i.memory_index_scale() == 1
                    && !i.is_ip_rel_memory_operand(),
            )?;
            let offset = i32::try_from(i.memory_displacement64() as i64)
                .map_err(|_| SetupRefusal::EntryExit)?;
            require((-FRAME..=FRAME).contains(&offset))?;
            Ok(Operand::Memory(r, offset))
        }
        _ => Err(SetupRefusal::EntryExit),
    }
}
fn register(i: &Instruction, n: u32) -> Result<Register> {
    let Operand::Register(r) = operand(i, n)? else {
        return Err(SetupRefusal::EntryExit);
    };
    Ok(r)
}
pub(super) fn admit(bytes: &[u8], base: u64) -> Result<NormalCallPairParentCertificate> {
    require((5..=80).contains(&bytes.len()) && base != 0)?;
    let end = base
        .checked_add(bytes.len() as u64)
        .ok_or(SetupRefusal::EntryExit)?;
    let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut s = State::new();
    let mut heads = Vec::new();
    let mut edges = Vec::new();
    let mut call = None;
    let mut ret = None;
    let mut call_rsp = 0;
    let mut initialized = Vec::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        require(!i.is_invalid() && i.ip() >= base && i.next_ip() <= end && i.next_ip() > i.ip())?;
        let at = usize::try_from(i.ip() - base).map_err(|_| SetupRefusal::EntryExit)?;
        let next = usize::try_from(i.next_ip() - base).map_err(|_| SetupRefusal::EntryExit)?;
        let raw = bytes.get(at..next).ok_or(SetupRefusal::EntryExit)?;
        require(
            !raw.is_empty()
                && i.segment_prefix() == Register::None
                && !i.has_lock_prefix()
                && !i.has_rep_prefix()
                && !i.has_repne_prefix()
                && !i.is_privileged(),
        )?;
        // Zero or one REX only; legacy, duplicate and address-size prefixes refuse.
        let opcode = usize::from((0x40..=0x4f).contains(&raw[0]));
        let first = *raw.get(opcode).ok_or(SetupRefusal::EntryExit)?;
        require(!matches!(
            first,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 | 0x40
                ..=0x4f
        ))?;
        let expected_flow = match i.code() {
            Code::Call_rel32_64 => FlowControl::Call,
            Code::Retnq => FlowControl::Return,
            _ => FlowControl::Next,
        };
        require(i.flow_control() == expected_flow)?;
        match i.code() {
            Code::Push_r64 => {
                let r = register(&i, 0)?;
                require(r != Register::RSP)?;
                let value = s.reg(r)?;
                s.move_sp(s.sp.checked_sub(8).ok_or(SetupRefusal::EntryExit)?)?;
                s.stack.insert(s.sp, value);
            }
            Code::Pop_r64 => {
                let r = register(&i, 0)?;
                require(r != Register::RSP)?;
                let value = s.stack.get(&s.sp).copied().ok_or(SetupRefusal::EntryExit)?;
                s.write_reg(r, value)?;
                s.move_sp(s.sp.checked_add(8).ok_or(SetupRefusal::EntryExit)?)?;
            }
            Code::Mov_r64_rm64 | Code::Mov_rm64_r64 => {
                let source = s.read(operand(&i, 1)?)?;
                s.write(operand(&i, 0)?, source)?;
            }
            Code::Lea_r64_m => {
                let Operand::Memory(r, offset) = operand(&i, 1)? else {
                    return Err(SetupRefusal::EntryExit);
                };
                let Origin::Stack(base) = s.reg(r)? else {
                    return Err(SetupRefusal::EntryExit);
                };
                let next = base.checked_add(offset).ok_or(SetupRefusal::EntryExit)?;
                require((-FRAME..=0).contains(&next) && next % 8 == 0)?;
                s.write_reg(register(&i, 0)?, Origin::Stack(next))?;
            }
            Code::Add_rm64_imm8
            | Code::Add_rm64_imm32
            | Code::Sub_rm64_imm8
            | Code::Sub_rm64_imm32 => {
                require(register(&i, 0)? == Register::RSP)?;
                let amount = match i.op1_kind() {
                    OpKind::Immediate8to64 => i.immediate8to64(),
                    OpKind::Immediate32to64 => i.immediate32to64(),
                    _ => return Err(SetupRefusal::EntryExit),
                };
                require(amount > 0 && amount <= i64::from(FRAME) && amount % 8 == 0)?;
                let delta = amount as i32
                    * if matches!(i.code(), Code::Sub_rm64_imm8 | Code::Sub_rm64_imm32) {
                        -1
                    } else {
                        1
                    };
                s.move_sp(s.sp.checked_add(delta).ok_or(SetupRefusal::EntryExit)?)?;
            }
            Code::Shl_rm64_imm8 => {
                let r = register(&i, 0)?;
                require(
                    call.is_some()
                        && i.op1_kind() == OpKind::Immediate8
                        && i.immediate8() == 32
                        && s.reg(r)? == Origin::Length,
                )?;
                s.write_reg(r, Origin::LengthHigh)?;
            }
            Code::Or_rm64_r64 | Code::Or_r64_rm64 => {
                let a = register(&i, 0)?;
                let b = register(&i, 1)?;
                let x = s.reg(a)?;
                let y = s.reg(b)?;
                require(
                    call.is_some()
                        && matches!(
                            (x, y),
                            (Origin::ChildResult, Origin::LengthHigh)
                                | (Origin::LengthHigh, Origin::ChildResult)
                        ),
                )?;
                s.write_reg(a, Origin::Packed)?;
            }
            Code::Call_rel32_64 => {
                require(
                    raw.len() == 5
                        && raw[0] == 0xe8
                        && call.is_none()
                        && i.op0_kind() == OpKind::NearBranch64
                        && s.reg(Register::RDI)? == Origin::Input
                        && s.reg(Register::RSI)? == Origin::Length
                        && (8 + s.sp).rem_euclid(16) == 0
                        && s.stack.values().any(|&value| value == Origin::Length),
                )?;
                let displacement =
                    i32::from_le_bytes(raw[1..5].try_into().map_err(|_| SetupRefusal::EntryExit)?);
                let target = u64::try_from(i128::from(i.next_ip()) + i128::from(displacement))
                    .map_err(|_| SetupRefusal::EntryExit)?;
                require(
                    target != 0
                        && !(base..end).contains(&target)
                        && target == i.near_branch_target(),
                )?;
                call = Some(NormalCallPairEdge {
                    call_pc: i.ip(),
                    callee_entry: target,
                    continuation: i.next_ip(),
                });
                call_rsp = s.sp;
                initialized = s.stack.keys().copied().collect();
                for r in VOLATILE {
                    s.regs[index(r)?] = Origin::Unknown;
                }
                s.regs[0] = Origin::ChildResult;
            }
            Code::Retnq => {
                require(
                    raw == [0xc3]
                        && i.next_ip() == end
                        && call.is_some()
                        && ret.is_none()
                        && s.sp == 0
                        && s.reg(Register::RAX)? == Origin::Packed
                        && SAVED.iter().all(|&r| s.reg(r) == Ok(Origin::Initial(r))),
                )?;
                ret = Some(i.ip());
            }
            Code::Nopd if raw == [0x90] => {}
            _ => return Err(SetupRefusal::EntryExit),
        }
        heads.push(i.ip());
        if i.code() != Code::Retnq {
            require(i.next_ip() < end)?;
            edges.push((i.ip(), i.next_ip()));
        }
    }
    require(decoder.position() == bytes.len())?;
    let edge = call.ok_or(SetupRefusal::EntryExit)?;
    let ret = ret.ok_or(SetupRefusal::EntryExit)?;
    require(base < edge.call_pc && edge.continuation < end)?;
    Ok(NormalCallPairParentCertificate {
        entry: base,
        end,
        heads,
        entries: [base, edge.continuation],
        returns: [ret],
        blocks: [(base, edge.call_pc), (edge.continuation, end)],
        edges,
        edge,
        call_rsp,
        stack_allocation: (-s.lowest) as u64,
        initialized,
        child_stack_delta: (8 - call_rsp) as u64,
    })
}
