//! Closed copied-Rust-invoke admission; metadata is not native execution evidence.
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};
use std::collections::BTreeMap;
#[path = "native_rust_invoke/copy.rs"]
mod copy;
pub type CopiedInvoke = copy::CopiedInvoke;
#[cfg(test)]
#[path = "native_rust_invoke/tests.rs"]
mod tests;

pub const MAX_BYTES: usize = 256;
const FRAME: i32 = 256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Format,
    Symbol,
    Relocation,
    Instruction,
    Provenance,
    Stack,
    Source,
    Mapping,
    Io,
}
pub type Result<T> = std::result::Result<T, Error>;
fn require(ok: bool, error: Error) -> Result<()> {
    if ok { Ok(()) } else { Err(error) }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operand {
    Register(Register),
    Memory { base: Register, displacement: i32 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Push(Register),
    Pop(Register),
    Move {
        destination: Operand,
        source: Operand,
    },
    Lea {
        destination: Register,
        base: Register,
        displacement: i32,
    },
    AdjustStack {
        delta: i32,
    },
    Call {
        target: Register,
    },
    Return,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Step {
    pub offset: u64,
    pub length: u8,
    pub code: Code,
    pub operation: Operation,
    pub rsp_before: i32,
    pub rsp_after: i32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    bytes: Vec<u8>,
    heads: Vec<u64>,
    steps: Vec<Step>,
    calls: [u64; 1],
    continuations: [u64; 1],
    outer_ret: u64,
    subject_rsp_delta: u64,
    protected: u64,
}
impl Plan {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn heads(&self) -> &[u64] {
        &self.heads
    }
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }
    pub fn calls(&self) -> &[u64; 1] {
        &self.calls
    }
    pub fn continuations(&self) -> &[u64; 1] {
        &self.continuations
    }
    pub fn outer_ret(&self) -> u64 {
        self.outer_ret
    }
    pub fn subject_rsp_delta(&self) -> u64 {
        self.subject_rsp_delta
    }
    pub fn protected_stack_below(&self) -> u64 {
        self.protected
    }
}
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
fn index(r: Register) -> Result<usize> {
    GPRS.iter().position(|&v| v == r).ok_or(Error::Instruction)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Origin {
    Initial(Register),
    Target,
    Input,
    Length,
    Output,
    Stack(i32),
    Result,
    Unknown,
}
struct State {
    regs: [Origin; 16],
    stack: BTreeMap<i32, Origin>,
    sp: i32,
    lowest: i32,
}
impl State {
    fn new() -> Self {
        let mut s = Self {
            regs: GPRS.map(Origin::Initial),
            stack: BTreeMap::new(),
            sp: 0,
            lowest: 0,
        };
        for (r, v) in [
            (Register::RDI, Origin::Target),
            (Register::RSI, Origin::Input),
            (Register::RDX, Origin::Length),
            (Register::RCX, Origin::Output),
            (Register::RSP, Origin::Stack(0)),
        ] {
            s.regs[index(r).unwrap()] = v;
        }
        s
    }
    fn register(&self, r: Register) -> Result<Origin> {
        Ok(self.regs[index(r)?])
    }
    fn move_sp(&mut self, next: i32) -> Result<()> {
        require((-FRAME..=0).contains(&next) && next % 8 == 0, Error::Stack)?;
        self.stack.retain(|&slot, _| slot >= next);
        self.sp = next;
        self.lowest = self.lowest.min(next);
        self.regs[index(Register::RSP)?] = Origin::Stack(next);
        Ok(())
    }
    fn write_register(&mut self, r: Register, v: Origin) -> Result<()> {
        if r == Register::RSP {
            let Origin::Stack(next) = v else {
                return Err(Error::Stack);
            };
            self.move_sp(next)
        } else {
            self.regs[index(r)?] = v;
            Ok(())
        }
    }
    fn stack_address(&self, base: Register, displacement: i32) -> Result<i32> {
        let Origin::Stack(offset) = self.register(base)? else {
            return Err(Error::Provenance);
        };
        let at = offset.checked_add(displacement).ok_or(Error::Stack)?;
        require(
            at >= self.sp && at < 0 && at % 8 == 0 && at.checked_add(8).is_some_and(|end| end <= 0),
            Error::Stack,
        )?;
        Ok(at)
    }
    fn read(&self, operand: Operand) -> Result<Origin> {
        match operand {
            Operand::Register(r) => self.register(r),
            Operand::Memory { base, displacement } => {
                let at = self.stack_address(base, displacement)?;
                self.stack.get(&at).copied().ok_or(Error::Stack)
            }
        }
    }
    fn write(&mut self, operand: Operand, value: Origin) -> Result<()> {
        match operand {
            Operand::Register(r) => self.write_register(r, value),
            Operand::Memory { base, displacement } => {
                let at = self.stack_address(base, displacement)?;
                self.stack.insert(at, value);
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
            let base = i.memory_base();
            index(base)?;
            require(
                i.memory_index() == Register::None
                    && i.memory_index_scale() == 1
                    && !i.is_ip_rel_memory_operand(),
                Error::Instruction,
            )?;
            let displacement =
                i32::try_from(i.memory_displacement64() as i64).map_err(|_| Error::Instruction)?;
            require((-FRAME..=FRAME).contains(&displacement), Error::Stack)?;
            Ok(Operand::Memory { base, displacement })
        }
        _ => Err(Error::Instruction),
    }
}
fn register(i: &Instruction, n: u32) -> Result<Register> {
    let Operand::Register(r) = operand(i, n)? else {
        return Err(Error::Instruction);
    };
    Ok(r)
}
fn operation(i: &Instruction) -> Result<Operation> {
    use Code::*;
    match i.code() {
        Push_r64 => Ok(Operation::Push(register(i, 0)?)),
        Pop_r64 => Ok(Operation::Pop(register(i, 0)?)),
        Mov_r64_rm64 | Mov_rm64_r64 => Ok(Operation::Move {
            destination: operand(i, 0)?,
            source: operand(i, 1)?,
        }),
        Lea_r64_m => {
            let Operand::Memory { base, displacement } = operand(i, 1)? else {
                return Err(Error::Instruction);
            };
            Ok(Operation::Lea {
                destination: register(i, 0)?,
                base,
                displacement,
            })
        }
        Add_rm64_imm8 | Add_rm64_imm32 | Sub_rm64_imm8 | Sub_rm64_imm32 => {
            require(register(i, 0)? == Register::RSP, Error::Instruction)?;
            let value = match i.op1_kind() {
                OpKind::Immediate8to64 => i.immediate8to64(),
                OpKind::Immediate32to64 => i.immediate32to64(),
                _ => return Err(Error::Instruction),
            };
            require(
                value > 0 && value <= i64::from(FRAME) && value % 8 == 0,
                Error::Stack,
            )?;
            let delta = value as i32
                * if matches!(i.code(), Sub_rm64_imm8 | Sub_rm64_imm32) {
                    -1
                } else {
                    1
                };
            Ok(Operation::AdjustStack { delta })
        }
        Call_rm64 => Ok(Operation::Call {
            target: register(i, 0)?,
        }),
        Retnq => Ok(Operation::Return),
        _ => Err(Error::Instruction),
    }
}
/// Admit only the complete fixed four-origin machine profile, not arbitrary Rust ABI.
pub fn admit(bytes: &[u8]) -> Result<Plan> {
    require((1..=MAX_BYTES).contains(&bytes.len()), Error::Instruction)?;
    let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
    let mut s = State::new();
    let mut heads = Vec::new();
    let mut steps = Vec::new();
    let mut call = None;
    let mut continuation = None;
    let mut stored = false;
    let mut ret = None;
    let mut target_delta = 0;
    while decoder.can_decode() {
        let i = decoder.decode();
        require(!i.is_invalid(), Error::Instruction)?;
        let at = i.ip() as usize;
        let end = i.next_ip() as usize;
        let raw = bytes.get(at..end).ok_or(Error::Instruction)?;
        require(
            !raw.is_empty()
                && i.segment_prefix() == Register::None
                && !i.has_lock_prefix()
                && !i.has_rep_prefix()
                && !i.has_repne_prefix(),
            Error::Instruction,
        )?;
        // Exactly zero or one REX; all legacy/duplicate prefixes are outside this profile.
        let opcode = usize::from((0x40..=0x4f).contains(&raw[0]));
        let first = *raw.get(opcode).ok_or(Error::Instruction)?;
        require(
            !matches!(
                first,
                0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 | 0x40
                    ..=0x4f
            ),
            Error::Instruction,
        )?;
        let op = operation(&i)?;
        let before = s.sp;
        let expected_flow = match op {
            Operation::Call { .. } => FlowControl::IndirectCall,
            Operation::Return => FlowControl::Return,
            _ => FlowControl::Next,
        };
        require(i.flow_control() == expected_flow, Error::Instruction)?;
        let is_store = if let Operation::Move {
            destination:
                Operand::Memory {
                    base,
                    displacement: 0,
                },
            source: Operand::Register(Register::RAX),
        } = op
        {
            s.register(base)? == Origin::Output && s.register(Register::RAX)? == Origin::Result
        } else {
            false
        };
        if call.is_some() && !stored {
            require(continuation == Some(i.ip()) && is_store, Error::Provenance)?;
        }
        match op {
            Operation::Push(r) => {
                require(r != Register::RSP, Error::Instruction)?;
                let value = s.register(r)?;
                s.move_sp(s.sp.checked_sub(8).ok_or(Error::Stack)?)?;
                s.stack.insert(s.sp, value);
            }
            Operation::Pop(r) => {
                require(r != Register::RSP, Error::Instruction)?;
                let value = s.stack.get(&s.sp).copied().ok_or(Error::Stack)?;
                s.write_register(r, value)?;
                s.move_sp(s.sp.checked_add(8).ok_or(Error::Stack)?)?;
            }
            Operation::Move {
                destination,
                source,
            } => {
                if is_store {
                    require(!stored && call.is_some(), Error::Provenance)?;
                    stored = true;
                } else {
                    let value = s.read(source)?;
                    s.write(destination, value)?;
                }
            }
            Operation::Lea {
                destination,
                base,
                displacement,
            } => {
                let Origin::Stack(offset) = s.register(base)? else {
                    return Err(Error::Provenance);
                };
                let value = offset.checked_add(displacement).ok_or(Error::Stack)?;
                require(
                    (-FRAME..=0).contains(&value) && value % 8 == 0,
                    Error::Stack,
                )?;
                s.write_register(destination, Origin::Stack(value))?;
            }
            Operation::AdjustStack { delta } => {
                s.move_sp(s.sp.checked_add(delta).ok_or(Error::Stack)?)?
            }
            Operation::Call { target } => {
                require(
                    call.is_none()
                        && s.register(target)? == Origin::Target
                        && s.register(Register::RDI)? == Origin::Input
                        && s.register(Register::RSI)? == Origin::Length,
                    Error::Provenance,
                )?;
                require((8 + s.sp).rem_euclid(16) == 0, Error::Stack)?;
                call = Some(i.ip());
                continuation = Some(i.next_ip());
                target_delta = (8 - s.sp) as u64;
                for r in VOLATILE {
                    s.regs[index(r)?] = Origin::Unknown;
                }
                s.regs[index(Register::RAX)?] = Origin::Result;
            }
            Operation::Return => {
                require(
                    raw == [0xc3]
                        && end == bytes.len()
                        && call.is_some()
                        && stored
                        && ret.is_none(),
                    Error::Instruction,
                )?;
                require(
                    s.sp == 0
                        && SAVED
                            .iter()
                            .all(|&r| s.register(r) == Ok(Origin::Initial(r))),
                    Error::Stack,
                )?;
                ret = Some(i.ip());
            }
        }
        heads.push(i.ip());
        steps.push(Step {
            offset: i.ip(),
            length: i.len() as u8,
            code: i.code(),
            operation: op,
            rsp_before: before,
            rsp_after: s.sp,
        });
    }
    require(decoder.position() == bytes.len(), Error::Instruction)?;
    Ok(Plan {
        bytes: bytes.to_vec(),
        heads,
        steps,
        calls: [call.ok_or(Error::Instruction)?],
        continuations: [continuation.ok_or(Error::Instruction)?],
        outer_ret: ret.ok_or(Error::Instruction)?,
        subject_rsp_delta: target_delta,
        protected: (-s.lowest as u64).max(128 + target_delta).max(128),
    })
}
