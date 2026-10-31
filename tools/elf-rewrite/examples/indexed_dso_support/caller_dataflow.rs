//! Finite machine-dataflow checks for the two ordinary C caller fixtures.
//!
//! This is deliberately conditional byte evidence, not an ABI certificate. The
//! entry arguments/ranges, DF-clear SysV entry, support-call contracts, original
//! CFI and loaded identities remain independently owned. In particular, target
//! RSP/callee preservation is NEVER an input premise. A direct RIP-relative raw
//! capture can record those actual outcomes before any frame-pointer reload.
//! Only a completed run's independently compared raw RSP can discharge the
//! conditional frame-address interpretation used for later C exports. Retained
//! pointer spills also need a separate target/support no-alias proof.
//!
//! The prefix is the unique graph path that can reach the target; no branch
//! condition is assumed true and error exits are not labelled successful. The
//! first result stops before its comparison CALL. `prove_tail` separately binds
//! that helper's actual effects and checks every remaining local path. Support
//! calls still require explicit normal-return/write-footprint contracts.
#![forbid(unsafe_code)]

use super::{caller, observations};
use formats::ContentId;
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic,
    OpAccess, OpKind, Register,
};
use std::collections::BTreeMap;

const CALLEE: [Register; 6] = [
    Register::RBX,
    Register::RBP,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];
const ARGUMENTS: [Register; 6] = [
    Register::RDI,
    Register::RSI,
    Register::RDX,
    Register::RCX,
    Register::R8,
    Register::R9,
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
const OUT_BYTES: i64 = 344;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Work,
    Reference,
}
impl Kind {
    fn out(self) -> u8 {
        if self == Self::Work { 5 } else { 3 }
    }
    fn number(self) -> u64 {
        if self == Self::Work { 1 } else { 2 }
    }
}

/// Coordinate only. The caller must own the exact hidden, nonaliased writable
/// 64-byte cell and exclude concurrent/reentrant writes for the entire run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawCapture {
    pub address: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Identity,
    Bounds,
    Path,
    Instruction,
    Address,
    Target,
    Argument,
    GuardedBox,
    Observation,
    Capture,
}
type Result<T> = std::result::Result<T, Error>;

/// Offsets are relative to the actual function-entry RSP, not guessed addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Address {
    Frame(i64),
    Observation(i64),
    Control(i64),
    Raw(i64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Value {
    Unknown,
    Constant(u64),
    EntryArgument(u8),
    EntryRegister(Register),
    FramePointer(i64),
    RspSample {
        frame: i64,
        instruction: u64,
    },
    /// Fresh physical value at the actual normal return; never a canary constant.
    Returned(Register),
    /// Fresh value read from a guarded word after the target, never its initializer.
    ReturnedWord(i64),
    FailureWord(u64),
    NoFailureResult(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cell {
    pub address: Address,
    pub bytes: usize,
    pub value: Value,
    pub loaded_from: Option<Address>,
    pub source_register: Option<Register>,
    pub instruction: u64,
}

/// These are outstanding contracts, not automatically admitted semantics.
/// The six preserved registers and RSP refer ONLY to this support call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportCall {
    pub call: caller::CallSite,
    pub arguments: [Value; 6],
    pub preserved_cells: Vec<Cell>,
}

#[derive(Clone, Debug)]
pub struct Dataflow {
    identity: ContentId,
    base: u64,
    byte_len: usize,
    kind: Kind,
    target: caller::CallSite,
    frame: i64,
    guarded_box: i64,
    before: Vec<Cell>,
    after: Vec<Cell>,
    raw: Option<RawCapture>,
    raw_stores: Vec<u64>,
    supports: Vec<SupportCall>,
    target_protected: Vec<Cell>,
    tail: caller::CallSite,
    remaining_calls: Vec<caller::CallSite>,
    at_compare: Machine,
}
impl Dataflow {
    pub const fn identity(&self) -> ContentId {
        self.identity
    }
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    pub const fn target_call(&self) -> caller::CallSite {
        self.target
    }
    pub const fn pre_call_frame_offset(&self) -> i64 {
        self.frame
    }
    pub const fn guarded_box_offset(&self) -> i64 {
        self.guarded_box
    }
    pub fn before_cells(&self) -> &[Cell] {
        &self.before
    }
    /// Conditional on actual raw-RSP equality and retained pointer-spill ownership.
    pub fn conditional_after_cells(&self) -> &[Cell] {
        &self.after
    }
    pub const fn raw_capture(&self) -> Option<RawCapture> {
        self.raw
    }
    pub fn raw_store_instructions(&self) -> &[u64] {
        &self.raw_stores
    }
    pub fn prefix_support_calls(&self) -> &[SupportCall] {
        &self.supports
    }
    /// Excludes all five guarded words: their post-values are actual new reads.
    pub fn target_protected_cells(&self) -> &[Cell] {
        &self.target_protected
    }
    pub const fn unproved_tail_entry(&self) -> caller::CallSite {
        self.tail
    }
    pub fn remaining_support_calls(&self) -> &[caller::CallSite] {
        &self.remaining_calls
    }
    /// Bind the first tail CALL to independently decoded helper bytes. This
    /// closes its local clobber/write-footprint question, not the remaining
    /// caller tail, normal-return/valid-read premises or the finish callback.
    pub fn bind_compare(&self, effects: &CompareEffects) -> Result<BoundCompare> {
        if self.tail.direct_target != Some(effects.base) {
            return Err(Error::Target);
        }
        Ok(BoundCompare {
            call: self.tail,
            effects: effects.clone(),
        })
    }
    /// Prove local tail paths under the explicit support-call contracts. This
    /// does not discharge raw RSP, spill ownership, CFI or actual normal return.
    pub fn prove_tail(&self, bytes: &[u8], effects: &CompareEffects) -> Result<TailProof> {
        tail(self, bytes, effects)
    }
    pub const fn post_target_observation_ownership_complete(&self) -> bool {
        false
    }
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug)]
struct Operand {
    value: Value,
    loaded: Option<Address>,
}
impl Operand {
    fn new(value: Value) -> Self {
        Self {
            value,
            loaded: None,
        }
    }
}
#[derive(Clone, Copy, Debug)]
enum Vector {
    Unknown,
    Zero,
    Control(i64),
}

#[derive(Clone, Debug)]
struct Machine {
    kind: Kind,
    raw: Option<RawCapture>,
    registers: [Operand; 16],
    vectors: [Vector; 16],
    cells: BTreeMap<Address, Cell>,
    raw_zero: [bool; 64],
    supports: Vec<SupportCall>,
}

fn reg(register: Register) -> Result<usize> {
    Ok(match register.full_register() {
        Register::RAX => 0,
        Register::RCX => 1,
        Register::RDX => 2,
        Register::RBX => 3,
        Register::RSP => 4,
        Register::RBP => 5,
        Register::RSI => 6,
        Register::RDI => 7,
        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,
        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,
        _ => return Err(Error::Instruction),
    })
}
fn xmm(register: Register) -> Result<usize> {
    let n = register as usize;
    let start = Register::XMM0 as usize;
    if (start..start + 16).contains(&n) {
        Ok(n - start)
    } else {
        Err(Error::Instruction)
    }
}
fn offset(address: Address) -> i64 {
    match address {
        Address::Frame(n) | Address::Observation(n) | Address::Control(n) | Address::Raw(n) => n,
    }
}
fn same_region(a: Address, b: Address) -> bool {
    std::mem::discriminant(&a) == std::mem::discriminant(&b)
}
fn overlaps(a: Address, an: usize, b: Address, bn: usize) -> bool {
    same_region(a, b) && offset(a) < offset(b) + bn as i64 && offset(b) < offset(a) + an as i64
}
fn immediate(i: &Instruction, op: u32) -> Result<u64> {
    Ok(match i.op_kind(op) {
        OpKind::Immediate8 => u64::from(i.immediate8()),
        OpKind::Immediate32 => u64::from(i.immediate32()),
        OpKind::Immediate64 => i.immediate64(),
        OpKind::Immediate8to64 => i.immediate8to64() as u64,
        OpKind::Immediate8to32 => i.immediate8to32() as u32 as u64,
        OpKind::Immediate32to64 => i.immediate32to64() as u64,
        _ => return Err(Error::Instruction),
    })
}
impl Machine {
    fn new(kind: Kind, raw: Option<RawCapture>) -> Self {
        let mut state = Self {
            kind,
            raw,
            registers: [Operand::new(Value::Unknown); 16],
            vectors: [Vector::Unknown; 16],
            cells: BTreeMap::new(),
            raw_zero: [false; 64],
            supports: Vec::new(),
        };
        for (n, r) in ARGUMENTS.iter().enumerate() {
            state.registers[reg(*r).unwrap()] = Operand::new(Value::EntryArgument(n as u8));
        }
        for r in CALLEE {
            state.registers[reg(r).unwrap()] = Operand::new(Value::EntryRegister(r));
        }
        state.registers[4] = Operand::new(Value::FramePointer(0));
        state
    }
    fn value(&self, r: Register) -> Result<Operand> {
        let value = self.registers[reg(r)?];
        if r.is_gpr64() {
            Ok(value)
        } else if r.is_gpr32() {
            Ok(Operand::new(match value.value {
                Value::Constant(n) => Value::Constant(n & 0xffff_ffff),
                Value::FailureWord(version) => Value::FailureWord(version),
                Value::NoFailureResult(version) => Value::NoFailureResult(version),
                _ => Value::Unknown,
            }))
        } else {
            Err(Error::Instruction)
        }
    }
    fn assign(&mut self, r: Register, mut value: Operand) -> Result<()> {
        if r.is_gpr32() {
            value = Operand::new(match value.value {
                Value::Constant(n) => Value::Constant(n & 0xffff_ffff),
                Value::FailureWord(version) => Value::FailureWord(version),
                Value::NoFailureResult(version) => Value::NoFailureResult(version),
                _ => Value::Unknown,
            });
        } else if !r.is_gpr64() {
            return Err(Error::Instruction);
        }
        self.registers[reg(r)?] = value;
        Ok(())
    }
    fn frame(&self) -> Result<i64> {
        match self.value(Register::RSP)?.value {
            Value::FramePointer(n) => Ok(n),
            _ => Err(Error::Address),
        }
    }
    fn address(&self, i: &Instruction, bytes: usize) -> Result<Address> {
        if i.segment_prefix() != Register::None || i.memory_index() != Register::None {
            return Err(Error::Address);
        }
        let displacement = i.memory_displacement64() as i64;
        let address = if i.is_ip_rel_memory_operand() {
            if i.memory_base() != Register::RIP {
                return Err(Error::Address);
            }
            let raw = self.raw.ok_or(Error::Address)?;
            let n = i
                .ip_rel_memory_address()
                .checked_sub(raw.address)
                .ok_or(Error::Address)?;
            Address::Raw(i64::try_from(n).map_err(|_| Error::Address)?)
        } else {
            match self.value(i.memory_base())?.value {
                Value::FramePointer(n) => {
                    Address::Frame(n.checked_add(displacement).ok_or(Error::Address)?)
                }
                Value::EntryArgument(n) if n == self.kind.out() => {
                    Address::Observation(displacement)
                }
                Value::EntryArgument(0) => Address::Control(displacement),
                _ => return Err(Error::Address),
            }
        };
        let start = offset(address);
        let end = start.checked_add(bytes as i64).ok_or(Error::Address)?;
        let valid = match address {
            Address::Frame(_) => self.frame()? <= start && end <= 0,
            Address::Observation(_) => 0 <= start && end <= OUT_BYTES,
            Address::Control(_) => 0 <= start && end <= 208,
            Address::Raw(_) => 0 <= start && end <= 64,
        };
        if valid {
            Ok(address)
        } else {
            Err(Error::Address)
        }
    }
    fn load(&self, address: Address, bytes: usize) -> Operand {
        let value = self
            .cells
            .get(&address)
            .filter(|c| c.bytes == bytes)
            .map_or(Value::Unknown, |c| c.value);
        Operand {
            value,
            loaded: Some(address),
        }
    }
    fn write(
        &mut self,
        address: Address,
        bytes: usize,
        value: Operand,
        source: Option<Register>,
        ip: u64,
    ) -> Result<()> {
        if matches!(address, Address::Control(_)) {
            return Err(Error::Address);
        }
        self.cells
            .retain(|_, c| !overlaps(address, bytes, c.address, c.bytes));
        if let Address::Raw(n) = address {
            let start = usize::try_from(n).map_err(|_| Error::Address)?;
            let end = start
                .checked_add(bytes)
                .filter(|&end| end <= 64)
                .ok_or(Error::Address)?;
            self.raw_zero[start..end].fill(value.value == Value::Constant(0));
        }
        self.cells.insert(
            address,
            Cell {
                address,
                bytes,
                value: value.value,
                loaded_from: value.loaded,
                source_register: source,
                instruction: ip,
            },
        );
        Ok(())
    }
    fn operand(&self, i: &Instruction, op: u32) -> Result<Operand> {
        match i.op_kind(op) {
            OpKind::Register => self.value(i.op_register(op)),
            OpKind::Memory => {
                let n = i.memory_size().size();
                Ok(self.load(self.address(i, n)?, n))
            }
            _ => Ok(Operand::new(Value::Constant(immediate(i, op)?))),
        }
    }
    fn support(&mut self, i: &Instruction) -> Result<()> {
        if i.code() != Code::Call_rel32_64 || self.supports.len() == 2 {
            return Err(Error::Instruction);
        }
        let mut arguments = [Value::Unknown; 6];
        for (n, r) in ARGUMENTS.iter().enumerate() {
            arguments[n] = self.value(*r)?.value;
        }
        // These identify the actual arguments to the two separate contracts;
        // they do not turn those direct targets into trusted helper semantics.
        if arguments[0] != Value::EntryArgument(0)
            || (self.supports.is_empty() && arguments[1] != Value::EntryArgument(self.kind.out()))
            || (self.supports.len() == 1
                && (!matches!(arguments[1], Value::FramePointer(_))
                    || arguments[2] != Value::EntryArgument(self.kind.out())))
        {
            return Err(Error::Argument);
        }
        self.supports.push(SupportCall {
            call: caller::CallSite {
                address: i.ip(),
                return_pc: i.next_ip(),
                direct_target: Some(i.near_branch_target()),
            },
            arguments,
            preserved_cells: self
                .cells
                .values()
                .filter(|c| {
                    c.value != Value::Unknown
                        && match c.address {
                            Address::Frame(_) => true,
                            Address::Observation(n) => {
                                matches!(n, 0 | 8 | 16 | 208 | 316) || (48..176).contains(&n)
                            }
                            _ => false,
                        }
                })
                .copied()
                .collect(),
        });
        for r in VOLATILE {
            self.registers[reg(r)?] = Operand::new(Value::Unknown);
        }
        self.vectors.fill(Vector::Unknown);
        Ok(())
    }
    fn step(&mut self, i: &Instruction) -> Result<()> {
        if i.has_lock_prefix()
            || i.has_repne_prefix()
            || (i.has_rep_prefix() && i.mnemonic() != Mnemonic::Stosq)
        {
            return Err(Error::Instruction);
        }
        match i.mnemonic() {
            Mnemonic::Push if i.op0_kind() == OpKind::Register && i.op0_register().is_gpr64() => {
                let value = self.value(i.op0_register())?;
                let frame = self
                    .frame()?
                    .checked_sub(8)
                    .filter(|n| *n >= -(caller::BYTE_LIMIT as i64))
                    .ok_or(Error::Bounds)?;
                self.assign(Register::RSP, Operand::new(Value::FramePointer(frame)))?;
                self.write(
                    Address::Frame(frame),
                    8,
                    value,
                    Some(i.op0_register()),
                    i.ip(),
                )?;
            }
            Mnemonic::Sub
                if i.op0_kind() == OpKind::Register && i.op0_register() == Register::RSP =>
            {
                let amount = i64::try_from(immediate(i, 1)?).map_err(|_| Error::Bounds)?;
                let frame = self
                    .frame()?
                    .checked_sub(amount)
                    .filter(|n| amount > 0 && *n >= -(caller::BYTE_LIMIT as i64))
                    .ok_or(Error::Bounds)?;
                self.assign(Register::RSP, Operand::new(Value::FramePointer(frame)))?;
            }
            Mnemonic::Mov => {
                let mut value = self.operand(i, 1)?;
                if i.op1_kind() == OpKind::Register
                    && i.op1_register() == Register::RSP
                    && i.op0_kind() == OpKind::Register
                {
                    value = Operand::new(Value::RspSample {
                        frame: self.frame()?,
                        instruction: i.ip(),
                    });
                }
                if i.op0_kind() == OpKind::Register {
                    self.assign(i.op0_register(), value)?;
                } else if i.op0_kind() == OpKind::Memory {
                    let n = i.memory_size().size();
                    if !matches!(n, 4 | 8) {
                        return Err(Error::Instruction);
                    }
                    let source = (i.op1_kind() == OpKind::Register).then(|| i.op1_register());
                    self.write(self.address(i, n)?, n, value, source, i.ip())?;
                } else {
                    return Err(Error::Instruction);
                }
            }
            Mnemonic::Lea if i.op0_kind() == OpKind::Register && i.op0_register().is_gpr64() => {
                let Address::Frame(n) = self.address(i, 0)? else {
                    return Err(Error::Address);
                };
                self.assign(i.op0_register(), Operand::new(Value::FramePointer(n)))?;
            }
            Mnemonic::Xor
                if i.op0_kind() == OpKind::Register
                    && i.op1_kind() == OpKind::Register
                    && i.op0_register() == i.op1_register() =>
            {
                self.assign(i.op0_register(), Operand::new(Value::Constant(0)))?
            }
            Mnemonic::Pxor | Mnemonic::Xorps
                if i.op0_kind() == OpKind::Register
                    && i.op1_kind() == OpKind::Register
                    && i.op0_register() == i.op1_register() =>
            {
                self.vectors[xmm(i.op0_register())?] = Vector::Zero
            }
            Mnemonic::Movdqu | Mnemonic::Movdqa | Mnemonic::Movaps | Mnemonic::Movups => {
                if i.memory_size().size() != 16 {
                    return Err(Error::Instruction);
                }
                if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Memory {
                    let Address::Control(n) = self.address(i, 16)? else {
                        return Err(Error::Address);
                    };
                    self.vectors[xmm(i.op0_register())?] = Vector::Control(n);
                } else if i.op0_kind() == OpKind::Memory && i.op1_kind() == OpKind::Register {
                    let address = self.address(i, 16)?;
                    let value = match self.vectors[xmm(i.op1_register())?] {
                        Vector::Zero => Value::Constant(0),
                        Vector::Control(n)
                            if matches!(address, Address::Frame(_)) && (0..176).contains(&n) =>
                        {
                            Value::Unknown
                        }
                        _ => return Err(Error::Instruction),
                    };
                    // Unknown copied config bytes invalidate overlapping scalar
                    // facts. They never manufacture a known argument/spill.
                    self.write(address, 16, Operand::new(value), None, i.ip())?;
                } else {
                    return Err(Error::Instruction);
                }
            }
            Mnemonic::Stosq if i.has_rep_prefix() => {
                if i.op0_kind() != OpKind::MemoryESRDI
                    || self.value(Register::RDI)?.value != Value::EntryArgument(self.kind.out())
                    || self.value(Register::RCX)?.value != Value::Constant(43)
                    || self.value(Register::RAX)?.value != Value::Constant(0)
                {
                    return Err(Error::Instruction);
                }
                for n in (0..OUT_BYTES).step_by(8) {
                    self.write(
                        Address::Observation(n),
                        8,
                        Operand::new(Value::Constant(0)),
                        Some(Register::RAX),
                        i.ip(),
                    )?;
                }
                self.assign(Register::RDI, Operand::new(Value::Unknown))?;
                self.assign(Register::RCX, Operand::new(Value::Constant(0)))?;
            }
            Mnemonic::Cmp | Mnemonic::Test => {
                for op in 0..i.op_count() {
                    if i.op_kind(op) == OpKind::Memory {
                        self.address(i, i.memory_size().size())?;
                    }
                }
            }
            Mnemonic::Nop => (),
            Mnemonic::Call => self.support(i)?,
            _ if matches!(
                i.flow_control(),
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
            ) && i.op0_kind() == OpKind::NearBranch64
                && matches!(i.mnemonic(), Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jmp) => {}
            _ => return Err(Error::Instruction),
        }
        Ok(())
    }
}

fn decode(bytes: &[u8], proof: &caller::Proof) -> Result<Vec<Instruction>> {
    if bytes.len() != proof.byte_len() || ContentId::of(bytes) != proof.identity() {
        return Err(Error::Identity);
    }
    if bytes.is_empty() || bytes.len() > caller::BYTE_LIMIT {
        return Err(Error::Bounds);
    }
    let end = proof
        .base()
        .checked_add(bytes.len() as u64)
        .ok_or(Error::Bounds)?;
    let instructions: Vec<_> = Decoder::with_ip(64, bytes, proof.base(), DecoderOptions::NONE)
        .into_iter()
        .collect();
    if instructions.len() > caller::INSTRUCTION_LIMIT
        || instructions.iter().any(Instruction::is_invalid)
        || instructions.last().map(Instruction::next_ip) != Some(end)
        || !instructions
            .iter()
            .map(Instruction::ip)
            .eq(proof.heads().iter().copied())
    {
        return Err(Error::Identity);
    }
    Ok(instructions)
}

fn prefix(instructions: &[Instruction], target: u64) -> Result<Vec<usize>> {
    let heads: BTreeMap<_, _> = instructions
        .iter()
        .enumerate()
        .map(|(n, i)| (i.ip(), n))
        .collect();
    let head = |address| heads.get(&address).copied().ok_or(Error::Path);
    let target = head(target)?;
    let mut edges = vec![Vec::new(); instructions.len()];
    let mut reverse = edges.clone();
    for (n, i) in instructions.iter().enumerate() {
        match i.flow_control() {
            FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
                edges[n].push(head(i.next_ip())?)
            }
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                edges[n].push(head(i.near_branch_target())?);
                if i.flow_control() == FlowControl::ConditionalBranch {
                    let next = head(i.next_ip())?;
                    if !edges[n].contains(&next) {
                        edges[n].push(next);
                    }
                }
            }
            FlowControl::Return => (),
            _ => return Err(Error::Path),
        }
        for &to in &edges[n] {
            reverse[to].push(n);
        }
    }
    let mut can_reach = vec![false; instructions.len()];
    let mut todo = vec![target];
    while let Some(n) = todo.pop() {
        if !can_reach[n] {
            can_reach[n] = true;
            todo.extend(&reverse[n]);
        }
    }
    let mut path = Vec::new();
    let mut at = 0;
    while at != target {
        if !can_reach[at] || path.contains(&at) {
            return Err(Error::Path);
        }
        path.push(at);
        let mut choices = edges[at].iter().copied().filter(|&n| can_reach[n]);
        at = choices.next().ok_or(Error::Path)?;
        if choices.next().is_some() {
            return Err(Error::Path);
        }
    }
    Ok(path)
}

fn cell(state: &Machine, n: i64, bytes: usize) -> Result<Cell> {
    state
        .cells
        .get(&Address::Observation(n))
        .filter(|c| c.bytes == bytes)
        .copied()
        .ok_or(Error::Observation)
}

fn before(state: &Machine, proof: &caller::Proof) -> Result<(i64, Vec<Cell>)> {
    let frame = state.frame()?;
    let mut result = Vec::new();
    for (n, ip) in [
        (0, proof.labels().sample),
        (8, proof.labels().configured),
        (16, proof.labels().pre),
    ] {
        let c = cell(state, n, 8)?;
        if c.value
            != (Value::RspSample {
                frame,
                instruction: ip,
            })
        {
            return Err(Error::Observation);
        }
        result.push(c);
    }
    for (n, r) in CALLEE.iter().enumerate() {
        let c = cell(state, 48 + n as i64 * 8, 8)?;
        if c.value != Value::Constant(observations::CANARIES[n])
            || c.source_register != Some(*r)
            || c.instruction < proof.labels().canary_before
            || c.instruction >= proof.labels().pre
            || state.value(*r)?.value != c.value
        {
            return Err(Error::Observation);
        }
        result.push(c);
    }
    let initial = cell(state, 144, 8)?;
    let Some(Address::Frame(base)) = initial.loaded_from else {
        return Err(Error::GuardedBox);
    };
    let values = [
        observations::GUARDS[0],
        observations::GUARDS[1],
        observations::OUTPUT_POISON,
        observations::GUARDS[2],
        observations::GUARDS[3],
    ];
    for (n, out) in [144, 152, 208, 160, 168].into_iter().enumerate() {
        let c = cell(state, out, 8)?;
        let location = Address::Frame(base + n as i64 * 8);
        if c.value != Value::Constant(values[n])
            || c.loaded_from != Some(location)
            || state.cells.get(&location).map(|c| (c.bytes, c.value))
                != Some((8, Value::Constant(values[n])))
        {
            return Err(Error::GuardedBox);
        }
        result.push(c);
    }
    for (n, value) in [(316, state.kind.number()), (328, 1)] {
        let c = cell(state, n, 4)?;
        if c.value != Value::Constant(value) {
            return Err(Error::Observation);
        }
        result.push(c);
    }
    Ok((base, result))
}

fn capture(
    instructions: &[Instruction],
    proof: &caller::Proof,
    raw: RawCapture,
) -> Result<Vec<u64>> {
    let start = instructions
        .iter()
        .position(|i| i.ip() == proof.return_pc())
        .ok_or(Error::Capture)?;
    let block = instructions.get(start..start + 9).ok_or(Error::Capture)?;
    let sample = &block[0];
    if sample.ip() != proof.labels().post
        || sample.mnemonic() != Mnemonic::Mov
        || sample.op0_kind() != OpKind::Register
        || !sample.op0_register().is_gpr64()
        || sample.op1_kind() != OpKind::Register
        || sample.op1_register() != Register::RSP
        || sample.op0_register() == Register::RAX
        || sample.op0_register() == Register::RSP
        || CALLEE.contains(&sample.op0_register())
    {
        return Err(Error::Capture);
    }
    let mut stores = Vec::new();
    for (n, (i, source)) in block[1..]
        .iter()
        .zip([
            Register::RAX,
            Register::RSP,
            Register::RBX,
            Register::RBP,
            Register::R12,
            Register::R13,
            Register::R14,
            Register::R15,
        ])
        .enumerate()
    {
        if i.mnemonic() != Mnemonic::Mov
            || i.op0_kind() != OpKind::Memory
            || !i.is_ip_rel_memory_operand()
            || i.memory_base() != Register::RIP
            || i.memory_size().size() != 8
            || i.segment_prefix() != Register::None
            || i.op1_kind() != OpKind::Register
            || i.op1_register() != source
            || i.ip_rel_memory_address()
                != raw
                    .address
                    .checked_add(n as u64 * 8)
                    .ok_or(Error::Capture)?
            || i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.next_ip() > proof.labels().canary_after
        {
            return Err(Error::Capture);
        }
        stores.push(i.ip());
    }
    Ok(stores)
}

/// Conditional caller-local facts for a single authenticated complete body.
/// `None` retains the historical caller's independent-capture gap; it cannot
/// be promoted by passing only its later C-exported RSP/canary comparisons.
pub fn prove(
    bytes: &[u8],
    proof: &caller::Proof,
    kind: Kind,
    raw: Option<RawCapture>,
) -> Result<Dataflow> {
    let instructions = decode(bytes, proof)?;
    let path = prefix(&instructions, proof.target_call().address)?;
    let mut state = Machine::new(kind, raw);
    for index in path {
        state.step(&instructions[index])?;
    }
    if state.supports.len() != 2 {
        return Err(Error::Argument);
    }
    let (guarded_box, before) = before(&state, proof)?;
    let target = instructions
        .iter()
        .find(|i| i.ip() == proof.target_call().address)
        .ok_or(Error::Target)?;
    if target.code() != Code::Call_rm64
        || target.op0_kind() != OpKind::Register
        || state.value(target.op0_register())?.value != Value::EntryArgument(1)
    {
        return Err(Error::Target);
    }
    let expected = match kind {
        Kind::Work => vec![
            Value::EntryArgument(2),
            Value::EntryArgument(3),
            Value::EntryArgument(4),
            Value::FramePointer(guarded_box + 16),
        ],
        Kind::Reference => vec![Value::EntryArgument(2)],
    };
    for (&r, &value) in ARGUMENTS.iter().zip(&expected) {
        if state.value(r)?.value != value {
            return Err(Error::Argument);
        }
    }
    let raw_stores = if let Some(raw) = raw {
        if !state.raw_zero.iter().all(|zero| *zero) {
            return Err(Error::Capture);
        }
        capture(&instructions, proof, raw)?
    } else {
        Vec::new()
    };
    let frame = state.frame()?;
    let target_protected: Vec<_> = state
        .cells
        .values()
        .filter(|c| {
            !matches!(c.address, Address::Raw(_))
                && !overlaps(c.address, c.bytes, Address::Frame(guarded_box), 40)
                && c.value != Value::Unknown
        })
        .copied()
        .collect();
    // All physical return values are fresh. Retaining FramePointer here is ONLY
    // the explicit completed-run raw-RSP equality condition documented above.
    for r in VOLATILE {
        state.registers[reg(r)?] = Operand::new(Value::Unknown);
    }
    for r in CALLEE.into_iter().chain([Register::RAX]) {
        state.registers[reg(r)?] = Operand::new(Value::Returned(r));
    }
    state.vectors.fill(Vector::Unknown);
    for n in 0..5 {
        let address = guarded_box + n * 8;
        state.write(
            Address::Frame(address),
            8,
            Operand::new(Value::ReturnedWord(address)),
            None,
            target.ip(),
        )?;
    }
    let mut at = instructions
        .iter()
        .position(|i| i.ip() == proof.return_pc())
        .ok_or(Error::Path)?;
    while instructions[at].flow_control() == FlowControl::Next {
        state.step(&instructions[at])?;
        at += 1;
        if at == instructions.len() {
            return Err(Error::Path);
        }
    }
    let tail = &instructions[at];
    if tail.code() != Code::Call_rel32_64
        || tail.ip() < proof.labels().canary_after
        || state.value(Register::RDI)?.value != Value::EntryArgument(kind.out())
    {
        return Err(Error::Path);
    }
    let mut after = Vec::new();
    let post = cell(&state, 24, 8)?;
    if post.value
        != (Value::RspSample {
            frame,
            instruction: proof.labels().post,
        })
    {
        return Err(Error::Observation);
    }
    after.push(post);
    for (n, r) in CALLEE.iter().enumerate() {
        let c = cell(&state, 96 + n as i64 * 8, 8)?;
        if c.value != Value::Returned(*r)
            || c.source_register != Some(*r)
            || c.instruction < proof.labels().canary_after
        {
            return Err(Error::Observation);
        }
        after.push(c);
    }
    let returned = cell(&state, 224, 8)?;
    if returned.value != Value::Returned(Register::RAX) {
        return Err(Error::Observation);
    }
    after.push(returned);
    for (n, out) in [176, 184, 216, 192, 200].into_iter().enumerate() {
        let c = cell(&state, out, 8)?;
        let address = guarded_box + n as i64 * 8;
        if c.value != Value::ReturnedWord(address) || c.loaded_from != Some(Address::Frame(address))
        {
            return Err(Error::Observation);
        }
        after.push(c);
    }
    let returned_flag = cell(&state, 332, 4)?;
    if returned_flag.value != Value::Constant(1) {
        return Err(Error::Observation);
    }
    after.push(returned_flag);
    Ok(Dataflow {
        identity: proof.identity(),
        base: proof.base(),
        byte_len: bytes.len(),
        kind,
        target: proof.target_call(),
        frame,
        guarded_box,
        before,
        after,
        raw,
        raw_stores,
        supports: state.supports.clone(),
        target_protected,
        tail: caller::CallSite {
            address: tail.ip(),
            return_pc: tail.next_ip(),
            direct_target: Some(tail.near_branch_target()),
        },
        remaining_calls: proof
            .support_calls_requiring_preservation()
            .filter(|c| c.address >= tail.ip())
            .copied()
            .collect(),
        at_compare: state,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelperWrite {
    pub instruction: u64,
    pub base: Register,
    pub displacement: i64,
    pub bytes: usize,
}

/// Local effects only. All reads still need their actual owned addresses; no
/// termination or semantic comparison result is inferred from this footprint.
#[derive(Clone, Debug)]
pub struct CompareEffects {
    identity: ContentId,
    base: u64,
    bytes: usize,
    writes: Vec<HelperWrite>,
}
impl CompareEffects {
    pub const fn identity(&self) -> ContentId {
        self.identity
    }
    pub const fn base(&self) -> u64 {
        self.base
    }
    pub const fn byte_len(&self) -> usize {
        self.bytes
    }
    pub fn writes(&self) -> &[HelperWrite] {
        &self.writes
    }
    pub fn preserves(&self, register: Register) -> bool {
        register.is_gpr64()
            && !matches!(
                register,
                Register::RAX | Register::RCX | Register::RDX | Register::RSP
            )
    }
}
#[derive(Clone, Debug)]
pub struct BoundCompare {
    call: caller::CallSite,
    effects: CompareEffects,
}
impl BoundCompare {
    pub const fn call(&self) -> caller::CallSite {
        self.call
    }
    pub fn effects(&self) -> &CompareEffects {
        &self.effects
    }
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

/// Decode the complete independently owned static compare_observations body.
/// The bounded instruction set proves local preservation without relying on
/// GCC's interprocedural knowledge or generic SysV volatile-register rules.
pub fn compare_effects(bytes: &[u8], base: u64) -> Result<CompareEffects> {
    if bytes.is_empty() || bytes.len() > caller::BYTE_LIMIT {
        return Err(Error::Bounds);
    }
    let end = base.checked_add(bytes.len() as u64).ok_or(Error::Bounds)?;
    let instructions: Vec<_> = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE)
        .into_iter()
        .collect();
    if instructions.len() > caller::INSTRUCTION_LIMIT
        || instructions.last().map(Instruction::next_ip) != Some(end)
    {
        return Err(Error::Bounds);
    }
    let heads: Vec<_> = instructions.iter().map(Instruction::ip).collect();
    let mut factory = InstructionInfoFactory::new();
    let mut result = Vec::new();
    let mut returns = 0;
    for i in &instructions {
        if i.is_invalid()
            || i.is_privileged()
            || i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.segment_prefix() != Register::None
        {
            return Err(Error::Instruction);
        }
        match i.flow_control() {
            FlowControl::Return if i.code() == Code::Retnq => {
                returns += 1;
                continue;
            }
            FlowControl::Next
                if matches!(
                    i.mnemonic(),
                    Mnemonic::Mov
                        | Mnemonic::Lea
                        | Mnemonic::Cmp
                        | Mnemonic::Test
                        | Mnemonic::Add
                        | Mnemonic::Xor
                        | Mnemonic::Or
                        | Mnemonic::Nop
                ) =>
            {
                if heads.binary_search(&i.next_ip()).is_err() {
                    return Err(Error::Path);
                }
            }
            FlowControl::Next
                if i.mnemonic() == Mnemonic::Xchg
                    && i.op0_kind() == OpKind::Register
                    && i.op1_kind() == OpKind::Register
                    && i.op0_register() == Register::AX
                    && i.op1_register() == Register::AX =>
            {
                if heads.binary_search(&i.next_ip()).is_err() {
                    return Err(Error::Path);
                }
            }
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
                if i.op0_kind() == OpKind::NearBranch64 =>
            {
                if heads.binary_search(&i.near_branch_target()).is_err()
                    || (i.flow_control() == FlowControl::ConditionalBranch
                        && heads.binary_search(&i.next_ip()).is_err())
                {
                    return Err(Error::Path);
                }
            }
            _ => return Err(Error::Instruction),
        }
        let info = factory.info(i);
        for r in info.used_registers() {
            if writes(r.access())
                && !matches!(
                    r.register().full_register(),
                    Register::RAX | Register::RCX | Register::RDX
                )
            {
                return Err(Error::Instruction);
            }
        }
        for memory in info.used_memory() {
            if !writes(memory.access()) {
                continue;
            }
            let displacement = memory.displacement() as i64;
            let size = memory.memory_size().size();
            if memory.index() != Register::None {
                return Err(Error::Address);
            }
            let allowed = match memory.base() {
                Register::RSP => {
                    i.mnemonic() == Mnemonic::Mov
                        && size == 8
                        && (-48..=-16).contains(&displacement)
                        && displacement % 8 == 0
                }
                Register::RDI => {
                    i.mnemonic() == Mnemonic::Or
                        && size == 4
                        && displacement == 320
                        && matches!(immediate(i, 1)?, 8 | 16 | 32)
                }
                _ => false,
            };
            if !allowed {
                return Err(Error::Address);
            }
            result.push(HelperWrite {
                instruction: i.ip(),
                base: memory.base(),
                displacement,
                bytes: size,
            });
        }
    }
    if returns == 0 {
        return Err(Error::Path);
    }
    Ok(CompareEffects {
        identity: ContentId::of(bytes),
        base,
        bytes: bytes.len(),
        writes: result,
    })
}

/// All local continuations return the actual `failures == 0` value and restore
/// entry RSP/saved registers, conditional on the separately owned normal-return
/// slot and explicit preservation contracts. No target outcome is assumed.
#[derive(Clone, Debug)]
pub struct TailProof {
    identity: ContentId,
    compare: BoundCompare,
    finish_contracts: Vec<SupportCall>,
    return_instructions: Vec<u64>,
    paths: usize,
}
impl TailProof {
    pub const fn identity(&self) -> ContentId {
        self.identity
    }
    pub fn compare(&self) -> &BoundCompare {
        &self.compare
    }
    /// One actual finish call per path; identical alternative contracts merge.
    /// It may write status_after/end/final (264..312), failure (320..324), and
    /// end_attempted (336..340). It must preserve every listed cell, including
    /// the independently captured raw cells, RSP and all six physical registers.
    pub fn finish_contracts(&self) -> &[SupportCall] {
        &self.finish_contracts
    }
    pub fn return_instructions(&self) -> &[u64] {
        &self.return_instructions
    }
    pub const fn local_paths(&self) -> usize {
        self.paths
    }
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}

#[derive(Clone)]
struct TailState {
    at: usize,
    machine: Machine,
    failure_zero: Option<u64>,
    finished: bool,
    seen: Vec<usize>,
}

fn tail(data: &Dataflow, bytes: &[u8], effects: &CompareEffects) -> Result<TailProof> {
    if bytes.len() != data.byte_len || ContentId::of(bytes) != data.identity {
        return Err(Error::Identity);
    }
    let compare = data.bind_compare(effects)?;
    if data.remaining_calls.len() != 2 || data.remaining_calls[0] != data.tail {
        return Err(Error::Path);
    }
    let finish = data.remaining_calls[1];
    if finish.direct_target.is_none() {
        return Err(Error::Target);
    }
    let instructions: Vec<_> = Decoder::with_ip(64, bytes, data.base, DecoderOptions::NONE)
        .into_iter()
        .collect();
    let heads: BTreeMap<_, _> = instructions
        .iter()
        .enumerate()
        .map(|(n, i)| (i.ip(), n))
        .collect();
    let head = |address| heads.get(&address).copied().ok_or(Error::Path);
    let mut machine = data.at_compare.clone();
    for r in [Register::RAX, Register::RCX, Register::RDX] {
        machine.assign(r, Operand::new(Value::Unknown))?;
    }
    machine.write(
        Address::Observation(320),
        4,
        Operand::new(Value::FailureWord(data.tail.address)),
        None,
        data.tail.address,
    )?;
    let mut todo = vec![TailState {
        at: head(data.tail.return_pc)?,
        machine,
        failure_zero: None,
        finished: false,
        seen: Vec::new(),
    }];
    let mut steps = 0;
    let mut paths = 0;
    let mut returns = Vec::new();
    let mut finish_contracts = Vec::new();
    while let Some(mut state) = todo.pop() {
        loop {
            steps += 1;
            if steps > caller::INSTRUCTION_LIMIT || state.seen.contains(&state.at) {
                return Err(Error::Path);
            }
            state.seen.push(state.at);
            let i = &instructions[state.at];
            if i.has_lock_prefix()
                || i.has_rep_prefix()
                || i.has_repne_prefix()
                || i.segment_prefix() != Register::None
            {
                return Err(Error::Instruction);
            }
            match i.flow_control() {
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
                    if i.op0_kind() == OpKind::NearBranch64
                        && matches!(i.mnemonic(), Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jmp) =>
                {
                    if i.flow_control() == FlowControl::ConditionalBranch {
                        let mut alternative = state.clone();
                        alternative.at = head(i.next_ip())?;
                        todo.push(alternative);
                    }
                    state.at = head(i.near_branch_target())?;
                    continue;
                }
                FlowControl::Call if i.code() == Code::Call_rel32_64 => {
                    if state.finished
                        || i.ip() != finish.address
                        || i.next_ip() != finish.return_pc
                        || Some(i.near_branch_target()) != finish.direct_target
                    {
                        return Err(Error::Target);
                    }
                    let mut arguments = [Value::Unknown; 6];
                    for (n, r) in ARGUMENTS.iter().enumerate() {
                        arguments[n] = state.machine.value(*r)?.value;
                    }
                    if arguments[0] != Value::EntryArgument(0)
                        || arguments[1] != Value::EntryArgument(data.kind.out())
                    {
                        return Err(Error::Argument);
                    }
                    let contract = SupportCall {
                        call: finish,
                        arguments,
                        preserved_cells: state
                            .machine
                            .cells
                            .values()
                            .filter(|c| match c.address {
                                Address::Observation(n) => {
                                    !(264..312).contains(&n) && n != 320 && n != 336
                                }
                                _ => true,
                            })
                            .copied()
                            .collect(),
                    };
                    if !finish_contracts.contains(&contract) {
                        finish_contracts.push(contract);
                    }
                    // This is an explicit SysV/no-alias premise for FINISH,
                    // never an admission of target RSP/callee preservation.
                    for r in VOLATILE {
                        state.machine.assign(r, Operand::new(Value::Unknown))?;
                    }
                    state.machine.vectors.fill(Vector::Unknown);
                    state.machine.cells.retain(|address, _| !matches!(address, Address::Observation(n) if (264..312).contains(n) || *n == 336));
                    state.machine.write(
                        Address::Observation(320),
                        4,
                        Operand::new(Value::FailureWord(i.ip())),
                        None,
                        i.ip(),
                    )?;
                    state.failure_zero = None;
                    state.finished = true;
                }
                FlowControl::Return if i.code() == Code::Retnq => {
                    let Value::FailureWord(version) = cell(&state.machine, 320, 4)?.value else {
                        return Err(Error::Observation);
                    };
                    if !state.finished
                        || state.machine.frame()? != 0
                        || state.machine.value(Register::RAX)?.value
                            != Value::NoFailureResult(version)
                    {
                        return Err(Error::Observation);
                    }
                    for r in CALLEE {
                        if state.machine.value(r)?.value != Value::EntryRegister(r) {
                            return Err(Error::Observation);
                        }
                    }
                    paths += 1;
                    if !returns.contains(&i.ip()) {
                        returns.push(i.ip());
                    }
                    break;
                }
                FlowControl::Next => match i.mnemonic() {
                    Mnemonic::Mov => {
                        if i.op0_kind() == OpKind::Memory
                            && !matches!(
                                state.machine.address(i, i.memory_size().size())?,
                                Address::Frame(_)
                            )
                        {
                            return Err(Error::Observation);
                        }
                        state.machine.step(i)?;
                    }
                    Mnemonic::Cmp | Mnemonic::Test => {
                        state.machine.step(i)?;
                        let tested = i.mnemonic() == Mnemonic::Test
                            && i.op0_kind() == OpKind::Register
                            && i.op1_kind() == OpKind::Register
                            && i.op0_register() == i.op1_register();
                        state.failure_zero = if tested {
                            match state.machine.value(i.op0_register())?.value {
                                Value::FailureWord(version) => Some(version),
                                _ => None,
                            }
                        } else {
                            None
                        };
                    }
                    Mnemonic::Xor => {
                        state.machine.step(i)?;
                        state.failure_zero = None;
                    }
                    Mnemonic::Or if i.op0_kind() == OpKind::Memory => {
                        if state.machine.address(i, 4)? != Address::Observation(320)
                            || i.memory_size().size() != 4
                            || !matches!(immediate(i, 1)?, 8 | 16 | 32)
                        {
                            return Err(Error::Observation);
                        }
                        state.machine.write(
                            Address::Observation(320),
                            4,
                            Operand::new(Value::FailureWord(i.ip())),
                            None,
                            i.ip(),
                        )?;
                        state.failure_zero = None;
                    }
                    Mnemonic::Add
                        if i.op0_kind() == OpKind::Register
                            && i.op0_register() == Register::RSP =>
                    {
                        let amount = i64::try_from(immediate(i, 1)?).map_err(|_| Error::Bounds)?;
                        let frame = state
                            .machine
                            .frame()?
                            .checked_add(amount)
                            .filter(|n| amount > 0 && *n <= 0)
                            .ok_or(Error::Address)?;
                        state
                            .machine
                            .assign(Register::RSP, Operand::new(Value::FramePointer(frame)))?;
                        state.failure_zero = None;
                    }
                    Mnemonic::Pop
                        if i.op0_kind() == OpKind::Register
                            && CALLEE.contains(&i.op0_register()) =>
                    {
                        let frame = state.machine.frame()?;
                        let next = frame
                            .checked_add(8)
                            .filter(|n| *n <= 0)
                            .ok_or(Error::Address)?;
                        let value = state.machine.load(Address::Frame(frame), 8);
                        state.machine.assign(i.op0_register(), value)?;
                        state
                            .machine
                            .assign(Register::RSP, Operand::new(Value::FramePointer(next)))?;
                    }
                    Mnemonic::Sete
                        if i.op0_kind() == OpKind::Register && i.op0_register() == Register::AL =>
                    {
                        let version = state.failure_zero.ok_or(Error::Observation)?;
                        if state.machine.value(Register::RAX)?.value != Value::Constant(0) {
                            return Err(Error::Observation);
                        }
                        state
                            .machine
                            .assign(Register::RAX, Operand::new(Value::NoFailureResult(version)))?;
                    }
                    Mnemonic::Nop => (),
                    _ => return Err(Error::Instruction),
                },
                _ => return Err(Error::Instruction),
            }
            state.at = head(i.next_ip())?;
        }
    }
    if paths == 0 {
        return Err(Error::Path);
    }
    returns.sort_unstable();
    Ok(TailProof {
        identity: data.identity,
        compare,
        finish_contracts,
        return_instructions: returns,
        paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Retained complete function bytes from the closed compiled fixture
    // f9cc81653396f83b3f20fa6edcc5dcadc5ad87142f29d6dffb0fb40b67f3f60c.
    // These pure controls execute neither the instructions nor the C fixture.
    // compare_observations at 0x1300, 201 bytes, SHA256 757bc028b1b8bd23e69b8dbaa346851aae507171c5ac13b7882eaff43809acf2
    const COMPARE: &str = concat!(
        "48b8df9b5713e1ac682448bae1ac6824df9b571348894424d048b89397585326",
        "59413148894424d848b8459045281828182748894424e048b89911ee77cc33aa",
        "5548894424e848b8119977ee33cc55aa48894424f031c0eb1d0f1f8000000000",
        "4883c001838f40010000104883f806741f488b54c4c8483954c73075e3483954",
        "c76075dc4883c0014883f80675e36690488d8790000000488d97b0000000488b",
        "48204839087407838f40010000204883c0084839d075e7488b47104839471874",
        "07838f4001000008c3",
    );

    // li2_uw_call_reference at 0x1790, 943 bytes, SHA256 c2baf78b0ccd92f857ff9afa626c08b8878ea48b312111053a8ec090fbc57595
    const REFERENCE: &str = concat!(
        "415741564155415455534881ec08010000488914244885c974454989c84989f9",
        "b92b00000031c04c89c7f348ab41c7803c010000020000004885f60f84bf0100",
        "0048897424184c89cf4c89c64c894424104c894c2408e815f9ffff85c0751931",
        "c04881c4080100005b5d415c415d415e415fc30f1f44000048b8887766554433",
        "22114c8b4424104c8b4c2408488944242048b811223344556677884889442428",
        "48b8696996965a5ac3c3488944243048b8f0debc9a78563412488944243848b8",
        "1032547698badcfe4889442440488b44242049898090000000488b4424284989",
        "8098000000488b442430498980d0000000488b442438498980a0000000488b44",
        "2440498980a8000000f3410f6f09f3410f6f5110f3410f6f5920f3410f6f6130",
        "f3410f6f69400f294c2450f3410f6f7150f3410f6f79600f29542460f3410f6f",
        "41700f295c24700f29a424800000000f29ac24900000000f29b424a00000000f",
        "29bc24b00000000f298424c0000000f3410f6f8980000000f3410f6f91900000",
        "00f3410f6f99a00000000f298c24d00000000f299424e00000000f299c24f000",
        "00004889e0498900488d7424504c89c24c89cf4c894424104c894c2408e81ef8",
        "ffff85c00f8495feffff4889e04c8b4424104c8b4c24084c8b542418493b0049",
        "894008742b41838840010000084c89c64c89cfe8b8f8ffffe962feffff0f1f00",
        "41c7804001000001000000e951feffff418b884001000085c975d248bbe1ac68",
        "24df9b571348bddf9b5713e1ac682449bc939758532659413149bd4590452818",
        "28182749be9911ee77cc33aa5549bf119977ee33cc55aa49895830498968384d",
        "8960404d8968484d8970504d8978584889e049894010493b000f8566ffffff66",
        "0fefc04c894c2410488b3c240f2905fd25000041c78048010000010000000f29",
        "05fb2500004c894424080f2905ff2500000f29050826000041ffd24889e24889",
        "05cb250000488925cc25000048891dcd25000048892dce2500004c8925cf2500",
        "004c892dd02500004c8935d12500004c893dd22500004c8b4424084989501849",
        "8980e0000000488b4424204c89c749895860498980b0000000488b442428488b",
        "74243049896868498980b8000000488b4424384d896070498980c0000000488b",
        "4424404d8968784d89b0800000004d89b88800000041c7804c01000001000000",
        "4989b0d8000000498980c8000000e8fdf7ffff4939b0d00000004c8b4c241074",
        "0841838840010000204c89c64c89cf4c890424e818f7ffff4c8b042431c0418b",
        "904001000085d20f94c0e9b2fcffff",
    );

    // li2_uw_call_work at 0x13d0, 954 bytes, SHA256 e0e98fb1a7b5dbeb119d3b177f9b10bb4159a9ebc4f1722c4650bffa1b553bc5
    const WORK: &str = concat!(
        "415741564155415455534881ec180100004889142448894c24084c894424104d",
        "85c974454989fab92b00000031c04c89cff348ab41c7813c0100000100000048",
        "85f6743c48833c2400743548897424284c89d74c89ce4c894c24204c89542418",
        "e8cbfcffff85c0752731c04881c4180100005b5d415c415d415e415fc30f1f00",
        "41c781400100000100000031c0ebdc9048b888776655443322114c8b4c24204c",
        "8b542418488944243048b81122334455667788488944243848b8696996965a5a",
        "c3c3488944244048b8f0debc9a78563412488944244848b81032547698badcfe",
        "4889442450488b44243049898190000000488b44243849898198000000488b44",
        "2440498981d0000000488b442448498981a0000000488b442450498981a80000",
        "00f3410f6f0af3410f6f5210f3410f6f5a20f3410f6f6230f3410f6f6a400f29",
        "4c2460f3410f6f7250f3410f6f7a600f29542470f3410f6f42700f299c248000",
        "00000f29a424900000000f29ac24a00000000f29b424b00000000f29bc24c000",
        "00000f298424d0000000f3410f6f8a80000000f3410f6f9290000000f3410f6f",
        "9aa00000000f298c24e00000000f299424f00000000f299c24000100004889e0",
        "498901488d7424604c89ca4c89d74c894c24204c89542418e8c3fbffff85c00f",
        "8484feffff4889e04c8b4c24204c8b5424184c8b5c2428493b01498941087420",
        "41838940010000084c89ce4c89d7e85dfcffffe951feffff0f1f840000000000",
        "418b894001000085c975dd48bbe1ac6824df9b571348bddf9b5713e1ac682449",
        "bc939758532659413149bd459045281828182749be9911ee77cc33aa5549bf11",
        "9977ee33cc55aa49895930498969384d8961404d8969484d8971504d89795848",
        "89e049894110493b010f8571ffffff660fefc04c89542420488b542410488d4c",
        "24400f2905e7290000488b742408488b3c240f2905e729000041c78148010000",
        "010000000f2905e52900004c894c24180f2905e929000041ffd34889e2488905",
        "ac290000488925ad29000048891dae29000048892daf2900004c8925b0290000",
        "4c892db12900004c8935b22900004c893db32900004c8b4c2418498951184989",
        "81e0000000488b4424304c89cf4c89ce49895960498981b0000000488b442438",
        "49896968498981b8000000488b4424404d896170498981d8000000488b442448",
        "4d896978498981c0000000488b4424504d89b180000000498981c80000004d89",
        "b98800000041c7814c01000001000000e89bfbffff488b7c24204c890c24e8cd",
        "faffff4c8b0c2431c0418b914001000085d20f94c0e9b1fcffff",
    );

    fn bytes(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |b: u8| match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    _ => panic!("hex fixture"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }
    fn fixture(kind: Kind) -> (Vec<u8>, u64, caller::Labels, RawCapture) {
        match kind {
            Kind::Work => (
                bytes(WORK),
                0x13d0,
                caller::Labels {
                    sample: 0x158d,
                    configured: 0x15b5,
                    canary_before: 0x1637,
                    pre: 0x164f,
                    post: 0x16aa,
                    canary_after: 0x16ee,
                },
                RawCapture { address: 0x4060 },
            ),
            Kind::Reference => (
                bytes(REFERENCE),
                0x1790,
                caller::Labels {
                    sample: 0x1932,
                    configured: 0x195a,
                    canary_before: 0x19e7,
                    pre: 0x19ff,
                    post: 0x1a4b,
                    canary_after: 0x1a8f,
                },
                RawCapture { address: 0x4020 },
            ),
        }
    }
    fn check(kind: Kind, edit: impl FnOnce(&mut Vec<u8>, u64)) -> Result<Dataflow> {
        let (mut bytes, base, labels, raw) = fixture(kind);
        edit(&mut bytes, base);
        let graph = caller::prove(&bytes, base, labels)
            .expect("mutant keeps the original graph/register-window proof");
        prove(&bytes, &graph, kind, Some(raw))
    }
    fn change(bytes: &mut [u8], base: u64, at: u64, old: u8, new: u8) {
        let byte = &mut bytes[(at - base) as usize];
        assert_eq!(*byte, old, "exact mutant site");
        *byte = new;
    }

    #[test]
    fn compiled_work_and_reference_keep_all_argument_capture_and_export_facts() {
        for kind in [Kind::Work, Kind::Reference] {
            let result = check(kind, |_, _| {}).unwrap();
            assert_eq!(result.kind(), kind);
            assert_eq!(result.before_cells().len(), 16);
            assert_eq!(result.conditional_after_cells().len(), 14);
            assert_eq!(result.prefix_support_calls().len(), 2);
            assert_eq!(result.raw_store_instructions().len(), 8);
            assert_eq!(result.remaining_support_calls().len(), 2);
            assert_eq!(
                result.pre_call_frame_offset(),
                if kind == Kind::Work { -328 } else { -312 }
            );
            assert_eq!(result.guarded_box_offset(), -280);
            assert!(
                result
                    .target_protected_cells()
                    .iter()
                    .any(|cell| cell.value == Value::EntryArgument(kind.out()))
            );
            assert!(!result.post_target_observation_ownership_complete());
            assert!(!result.qualification_complete());
        }
    }

    #[test]
    fn every_changed_work_argument_and_the_indirect_target_are_refused() {
        for (at, old, new, error) in [
            (0x16a9, 0xd3, 0xd2, Error::Target),
            (0x1680, 0x3c, 0x34, Error::Argument), // input goes to RSI, not RDI
            (0x167d, 0x08, 0x00, Error::Argument), // length loads input spill
            (0x166c, 0x10, 0x08, Error::Argument), // seed loads length spill
            (0x1671, 0x40, 0x48, Error::Argument), // output names guard, not box[2]
        ] {
            assert_eq!(
                check(Kind::Work, |b, base| change(b, base, at, old, new)).unwrap_err(),
                error
            );
        }
    }

    #[test]
    fn reference_argument_and_partial_pointer_spills_are_refused() {
        assert_eq!(
            check(Kind::Reference, |b, base| change(
                b, base, 0x1a1a, 0x3c, 0x34
            ))
            .unwrap_err(),
            Error::Argument
        );
        // 32-bit spill cannot retain an entry function pointer, even if a
        // particular unqualified address happened to fit in 32 bits.
        assert_eq!(
            check(Kind::Work, |b, base| change(b, base, 0x141b, 0x48, 0x40)).unwrap_err(),
            Error::Target
        );
    }

    #[test]
    fn before_and_after_canaries_must_come_from_the_exact_physical_register() {
        for at in [0x1639, 0x1702] {
            assert_eq!(
                check(Kind::Work, |b, base| change(b, base, at, 0x59, 0x41)).unwrap_err(),
                Error::Observation
            );
        }
    }

    #[test]
    fn result_and_guard_exports_cannot_change_destination_or_memory_source() {
        assert_eq!(
            check(Kind::Work, |b, base| change(b, base, 0x16f1, 0xe0, 0xe8)).unwrap_err(),
            Error::Observation
        );
        assert_eq!(
            check(Kind::Work, |b, base| change(b, base, 0x16f9, 0x30, 0x38)).unwrap_err(),
            Error::Observation
        );
    }

    #[test]
    fn raw_capture_rejects_wrong_register_cell_and_sample_clobber() {
        for (at, old, new) in [
            (0x16af, 0x05, 0x0d),
            (0x16b0, 0xac, 0xad),
            (0x16ac, 0xe2, 0xe0),
        ] {
            assert_eq!(
                check(Kind::Work, |b, base| change(b, base, at, old, new)).unwrap_err(),
                Error::Capture
            );
        }
    }

    #[test]
    fn every_raw_reset_byte_is_required_before_the_target() {
        assert_eq!(
            check(Kind::Work, |b, base| {
                let at = (0x16a0 - base) as usize;
                assert_eq!(&b[at..at + 3], &[0x0f, 0x29, 0x05]);
                b[at..at + 7].fill(0x90);
            })
            .unwrap_err(),
            Error::Capture
        );
    }

    #[test]
    fn stack_only_exports_retain_the_missing_independent_capture_limitation() {
        let (mut b, base, labels, _) = fixture(Kind::Work);
        // Byte puzzle with the same old stack-export seam; this is explicitly
        // not a claim that the historical artifact contained these NOPs.
        let ranges: Vec<_> = Decoder::with_ip(64, &b, base, DecoderOptions::NONE)
            .into_iter()
            .filter(|i| i.is_ip_rel_memory_operand())
            .map(|i| ((i.ip() - base) as usize, i.len()))
            .collect();
        assert_eq!(ranges.len(), 12);
        for (at, len) in ranges {
            b[at..at + len].fill(0x90);
        }
        let graph = caller::prove(&b, base, labels).unwrap();
        let result = prove(&b, &graph, Kind::Work, None).unwrap();
        assert_eq!(result.raw_capture(), None);
        assert!(result.raw_store_instructions().is_empty());
        assert_eq!(result.conditional_after_cells().len(), 14);
        assert!(!result.post_target_observation_ownership_complete());
        assert!(!result.qualification_complete());
    }

    #[test]
    fn whole_body_identity_is_rechecked_before_dataflow() {
        let (mut b, base, labels, raw) = fixture(Kind::Work);
        let graph = caller::prove(&b, base, labels).unwrap();
        b[0] ^= 1;
        assert_eq!(
            prove(&b, &graph, Kind::Work, Some(raw)).unwrap_err(),
            Error::Identity
        );
    }

    #[test]
    fn compare_effects_bind_exact_call_and_preserve_required_volatile_registers() {
        let body = bytes(COMPARE);
        let effects = compare_effects(&body, 0x1300).unwrap();
        assert_eq!(effects.identity(), ContentId::of(&body));
        assert_eq!(effects.byte_len(), 201);
        assert_eq!(effects.writes().len(), 8);
        for r in [Register::RSI, Register::R8, Register::R9] {
            assert!(effects.preserves(r));
        }
        for r in [Register::RAX, Register::RCX, Register::RDX, Register::RSP] {
            assert!(!effects.preserves(r));
        }
        for kind in [Kind::Work, Kind::Reference] {
            let dataflow = check(kind, |_, _| {}).unwrap();
            assert_eq!(
                dataflow.bind_compare(&effects).unwrap().call,
                dataflow.unproved_tail_entry()
            );
            let shifted = compare_effects(&body, 0x1400).unwrap();
            assert_eq!(dataflow.bind_compare(&shifted).unwrap_err(), Error::Target);
        }
    }

    #[test]
    fn compare_effects_reject_volatile_clobbers_and_observation_or_stack_aliases() {
        for (at, old, new, error) in [
            (0x130b, 0xba, 0xbe, Error::Instruction), // RSI write
            (0x1318, 0xd0, 0x00, Error::Address),     // scratch store overwrites return slot
        ] {
            let mut body = bytes(COMPARE);
            change(&mut body, 0x1300, at, old, new);
            assert_eq!(compare_effects(&body, 0x1300).unwrap_err(), error);
        }
        let mut body = bytes(COMPARE);
        change(&mut body, 0x1300, 0x1366, 0x40, 0xd8);
        change(&mut body, 0x1300, 0x1367, 0x01, 0x00);
        assert_eq!(compare_effects(&body, 0x1300).unwrap_err(), Error::Address);
    }

    #[test]
    fn compare_effects_reject_calls_and_external_branch_heads() {
        let mut body = bytes(COMPARE);
        body[..5].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        assert_eq!(
            compare_effects(&body, 0x1300).unwrap_err(),
            Error::Instruction
        );
        let mut body = bytes(COMPARE);
        change(&mut body, 0x1300, 0x1358, 0x1d, 0x7f);
        assert_eq!(compare_effects(&body, 0x1300).unwrap_err(), Error::Path);
    }

    fn tail_check(kind: Kind, edit: impl FnOnce(&mut Vec<u8>, u64)) -> Result<TailProof> {
        let (mut b, base, labels, raw) = fixture(kind);
        edit(&mut b, base);
        let graph = caller::prove(&b, base, labels)
            .expect("tail mutant preserves existing CFG/window admission");
        let data = prove(&b, &graph, kind, Some(raw))?;
        data.prove_tail(&b, &compare_effects(&bytes(COMPARE), 0x1300)?)
    }

    #[test]
    fn both_compiled_tails_restore_entry_state_and_return_only_the_failure_predicate() {
        for kind in [Kind::Work, Kind::Reference] {
            let result = tail_check(kind, |_, _| {}).unwrap();
            assert_eq!(result.local_paths(), if kind == Kind::Work { 1 } else { 2 });
            assert_eq!(result.finish_contracts().len(), 1);
            assert_eq!(
                result.return_instructions(),
                if kind == Kind::Work {
                    &[0x144c]
                } else {
                    &[0x1802]
                }
            );
            assert!(
                result.finish_contracts()[0]
                    .preserved_cells
                    .iter()
                    .any(|c| c.address == Address::Raw(0))
            );
            assert!(!result.qualification_complete());
        }
    }

    #[test]
    fn tail_rejects_guard_rewrites_wrong_finish_arguments_and_missing_pointer_spill() {
        assert_eq!(
            tail_check(Kind::Reference, |b, base| {
                change(b, base, 0x1b14, 0x40, 0xb0);
                change(b, base, 0x1b15, 0x01, 0x00);
            })
            .unwrap_err(),
            Error::Observation
        );
        assert_eq!(
            tail_check(Kind::Work, |b, base| change(b, base, 0x1769, 0x20, 0x18)).unwrap_err(),
            Error::Argument
        );
        assert_eq!(
            tail_check(Kind::Work, |b, base| {
                let at = (0x176a - base) as usize;
                assert_eq!(&b[at..at + 4], &[0x4c, 0x89, 0x0c, 0x24]);
                b[at..at + 4].fill(0x90);
            })
            .unwrap_err(),
            Error::Address
        );
    }

    #[test]
    fn tail_rejects_wrong_epilogue_register_or_rsp_restoration_and_inverted_result() {
        for (at, old, new, expected) in [
            (0x1442, 0x5b, 0x5d, Error::Observation),
            (0x143e, 0x18, 0x10, Error::Observation),
            (0x1783, 0x94, 0x95, Error::Instruction),
            (0x177c, 0x40, 0x3c, Error::Observation),
        ] {
            assert_eq!(
                tail_check(Kind::Work, |b, base| change(b, base, at, old, new)).unwrap_err(),
                expected
            );
        }
        // A new failure after SETE must not leave a stale success predicate.
        // This byte puzzle extends only the final tail and retargets its JMP;
        // all labels, the real CALL and its actual return stay at the same IPs.
        assert_eq!(
            tail_check(Kind::Work, |b, base| {
                let at = (0x1785 - base) as usize;
                assert_eq!(b[at], 0xe9);
                let old = i32::from_le_bytes(b[at + 1..at + 5].try_into().unwrap());
                b.splice(at..at, [0x41, 0x83, 0x89, 0x40, 0x01, 0, 0, 0x10]);
                b[at + 9..at + 13].copy_from_slice(&(old - 8).to_le_bytes());
            })
            .unwrap_err(),
            Error::Observation
        );
    }

    #[test]
    fn tail_requires_the_same_complete_caller_and_actual_comparator_target() {
        let (mut b, _, _, _) = fixture(Kind::Work);
        let data = check(Kind::Work, |_, _| {}).unwrap();
        let effects = compare_effects(&bytes(COMPARE), 0x1300).unwrap();
        b[0] ^= 1;
        assert_eq!(data.prove_tail(&b, &effects).unwrap_err(), Error::Identity);
        let (b, _, _, _) = fixture(Kind::Work);
        let shifted = compare_effects(&bytes(COMPARE), 0x1400).unwrap();
        assert_eq!(data.prove_tail(&b, &shifted).unwrap_err(), Error::Target);
    }
}
