//! Separate finite scalar descriptor. No data reads, RX lease or STEP changes.
//! The exact Code/form gate precedes info(), whose retained vectors cannot grow
//! for this domain: at most 3 register rows and 1 memory row (see CONTRACT.md).

use crate::{abi, arena};
use core::{cell::UnsafeCell, mem::MaybeUninit};
use iced_x86::{
    Code, CodeSize, Decoder, DecoderOptions, Instruction, InstructionInfo, InstructionInfoFactory,
    MemorySize, OpAccess, OpKind, Register, RflagsBits,
};

const VERSION: u32 = 1;
const UNSUPPORTED: u32 = 1;
const INVALID: u32 = 2;
const TRUNCATED: u32 = 3;
const PREFIX: u32 = 4;
const OPERANDS: u32 = 5;
const EFFECTS: u32 = 6;
const ADDRESS: u32 = 7;
const NEXT: u32 = 0;
const JCC: u32 = 1;
const JMP: u32 = 2;
const NONE: u32 = 0;
const READ: u32 = 1;
const WRITE: u32 = 2;
const READ_WRITE: u32 = 3;
const REGISTER: u32 = 1;
const MEMORY: u32 = 2;
const IMMEDIATE: u32 = 3;
const BRANCH: u32 = 4;
const NO_REGISTER: u32 = 16;
const NO_CONDITION: u32 = 16;
const CF: u32 = 1;
const PF: u32 = 1 << 2;
const AF: u32 = 1 << 4;
const ZF: u32 = 1 << 6;
const SF: u32 = 1 << 7;
const OF: u32 = 1 << 11;

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Operand {
    pub immediate: u64,
    pub kind: u32,
    pub reg: u32,
    pub width_bits: u32,
    pub access: u32,
    pub encoding_bits: u32,
    pub reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct UsedRegister {
    pub reg: u32,
    pub width_bits: u32,
    pub access: u32,
    pub reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Memory {
    pub displacement: u64,
    pub base: u32,
    pub index: u32,
    pub scale: u32,
    pub width_bytes: u32,
    pub address_bits: u32,
    pub segment: u32,
    pub access: u32,
    pub reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Description {
    pub decoded: abi::Decoded,
    pub target: u64,
    pub operands: [Operand; 2],
    pub registers: [UsedRegister; 3],
    pub memory: Memory,
    pub version: u32,
    pub ready: u32,
    pub refusal: u32,
    pub flow: u32,
    pub condition: u32,
    pub operand_count: u32,
    pub register_count: u32,
    pub memory_count: u32,
    pub flags_read: u32,
    pub flags_written: u32,
    pub flags_set: u32,
    pub flags_cleared: u32,
    pub flags_undefined: u32,
    pub gpr_read: u32,
    pub gpr_write: u32,
    pub reserved: [u32; 3],
}
const _: () = {
    assert!(core::mem::size_of::<Operand>() == 32);
    assert!(core::mem::size_of::<UsedRegister>() == 16);
    assert!(core::mem::size_of::<Memory>() == 40);
    assert!(core::mem::size_of::<Description>() == 304);
    assert!(core::mem::align_of::<Description>() == 8);
    assert!(core::mem::offset_of!(Description, target) == 72);
    assert!(core::mem::offset_of!(Description, operands) == 80);
    assert!(core::mem::offset_of!(Description, registers) == 144);
    assert!(core::mem::offset_of!(Description, memory) == 192);
    assert!(core::mem::offset_of!(Description, version) == 232);
    assert!(core::mem::offset_of!(Description, flags_read) == 264);
    assert!(core::mem::offset_of!(Description, gpr_read) == 284);
    assert!(core::mem::offset_of!(Description, reserved) == 292);
};

struct Factory(UnsafeCell<MaybeUninit<InstructionInfoFactory>>);
// SAFETY: initialization has the original single-owner/no-entry contract;
// thereafter every access requires the unique arena::Call token. Never dropped.
unsafe impl Sync for Factory {}
static FACTORY: Factory = Factory(UnsafeCell::new(MaybeUninit::uninit()));

pub(crate) fn initialize() {
    // SAFETY: called once between successful arena::begin and arena::seal.
    // Construction allocates its two vectors while allocation is permitted.
    unsafe {
        (*FACTORY.0.get()).write(InstructionInfoFactory::new());
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    MovRmR,
    MovRRm,
    Movzx,
    And,
    Xor,
    Test,
    Cmp,
    Jcc,
    Jmp,
}
#[derive(Clone, Copy)]
struct Spec {
    form: Form,
    width: u32,
    condition: u32,
}

fn domain(code: Code) -> Option<Spec> {
    use Code::*;
    use Form::*;
    let (form, width, condition) = match code {
        Mov_rm32_r32 => (MovRmR, 32, NO_CONDITION),
        Mov_rm64_r64 => (MovRmR, 64, NO_CONDITION),
        Mov_r32_rm32 => (MovRRm, 32, NO_CONDITION),
        Mov_r64_rm64 => (MovRRm, 64, NO_CONDITION),
        Movzx_r32_rm8 => (Movzx, 32, NO_CONDITION),
        Movzx_r64_rm8 => (Movzx, 64, NO_CONDITION),
        And_rm32_imm8 => (And, 32, NO_CONDITION),
        And_rm64_imm8 => (And, 64, NO_CONDITION),
        Xor_rm32_r32 => (Xor, 32, NO_CONDITION),
        Xor_rm64_r64 => (Xor, 64, NO_CONDITION),
        Test_rm32_r32 => (Test, 32, NO_CONDITION),
        Test_rm64_r64 => (Test, 64, NO_CONDITION),
        Cmp_AL_imm8 => (Cmp, 8, NO_CONDITION),
        Jo_rel8_64 | Jo_rel32_64 => (Jcc, 64, 0),
        Jno_rel8_64 | Jno_rel32_64 => (Jcc, 64, 1),
        Jb_rel8_64 | Jb_rel32_64 => (Jcc, 64, 2),
        Jae_rel8_64 | Jae_rel32_64 => (Jcc, 64, 3),
        Je_rel8_64 | Je_rel32_64 => (Jcc, 64, 4),
        Jne_rel8_64 | Jne_rel32_64 => (Jcc, 64, 5),
        Jbe_rel8_64 | Jbe_rel32_64 => (Jcc, 64, 6),
        Ja_rel8_64 | Ja_rel32_64 => (Jcc, 64, 7),
        Js_rel8_64 | Js_rel32_64 => (Jcc, 64, 8),
        Jns_rel8_64 | Jns_rel32_64 => (Jcc, 64, 9),
        Jp_rel8_64 | Jp_rel32_64 => (Jcc, 64, 10),
        Jnp_rel8_64 | Jnp_rel32_64 => (Jcc, 64, 11),
        Jl_rel8_64 | Jl_rel32_64 => (Jcc, 64, 12),
        Jge_rel8_64 | Jge_rel32_64 => (Jcc, 64, 13),
        Jle_rel8_64 | Jle_rel32_64 => (Jcc, 64, 14),
        Jg_rel8_64 | Jg_rel32_64 => (Jcc, 64, 15),
        Jmp_rel8_64 | Jmp_rel32_64 => (Jmp, 64, NO_CONDITION),
        _ => return None,
    };
    Some(Spec {
        form,
        width,
        condition,
    })
}

fn canonical(pc: u64) -> bool {
    ((pc << 16) as i64 >> 16) as u64 == pc
}

fn register(reg: Register) -> Option<(u32, u32)> {
    use Register::*;
    Some(match reg {
        AL => (0, 8),
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
        _ => return Option::None,
    })
}
fn address_register(reg: Register) -> Option<u32> {
    if reg == Register::None {
        Some(NO_REGISTER)
    } else {
        register(reg).and_then(|(r, w)| if w == 64 { Some(r) } else { None })
    }
}
fn access(value: OpAccess) -> Option<u32> {
    match value {
        OpAccess::None => Some(NONE),
        OpAccess::Read => Some(READ),
        OpAccess::Write => Some(WRITE),
        OpAccess::ReadWrite => Some(READ_WRITE),
        _ => None,
    }
}
fn memory_width(value: MemorySize) -> Option<u32> {
    match value {
        MemorySize::UInt8 => Some(1),
        MemorySize::UInt32 => Some(4),
        MemorySize::UInt64 => Some(8),
        _ => None,
    }
}

// No legacy prefix, multiple REX, or branch/CMP REX enters this domain. Opcode,
// REX.W and the decoded Code/form must agree. The one optional REX may include
// ignored extension bits; iced's actual decoded registers/addresses are retained.
fn raw_form(spec: Spec, bytes: &[u8]) -> bool {
    if matches!(spec.form, Form::Jcc | Form::Jmp) {
        return true;
    } // exact below
    if spec.form == Form::Cmp {
        return bytes.len() == 2 && bytes[0] == 0x3c;
    }
    let (at, rex) = match bytes.first() {
        Some(value @ 0x40..=0x4f) => (1, *value),
        _ => (0, 0),
    };
    if (rex & 8 != 0) != (spec.width == 64) {
        return false;
    }
    let tail = &bytes[at..];
    let opcode = match spec.form {
        Form::MovRmR => 0x89,
        Form::MovRRm => 0x8b,
        Form::And => 0x83,
        Form::Xor => 0x31,
        Form::Test => 0x85,
        Form::Movzx => return tail.len() >= 3 && tail[..2] == [0x0f, 0xb6],
        _ => return false,
    };
    tail.len() >= 2 && tail[0] == opcode && (spec.form != Form::And || tail[1] & 0x38 == 0x20)
}

fn register_operand(ins: &Instruction, index: u32, width: u32, role: u32) -> Option<Operand> {
    if ins.op_kind(index) != OpKind::Register {
        return None;
    }
    let (reg, actual_width) = register(ins.op_register(index))?;
    if actual_width != width || (reg == 4 && role & WRITE != 0) {
        return None;
    }
    Some(Operand {
        kind: REGISTER,
        reg,
        width_bits: width,
        access: role,
        ..Operand::default()
    })
}
fn memory_operand(ins: &Instruction, width: u32) -> Option<(Operand, Memory)> {
    if ins.op1_kind() != OpKind::Memory
        || memory_width(ins.memory_size())? != width
        || ins.is_ip_rel_memory_operand()
        || ins.is_vsib()
    {
        return None;
    }
    let base = address_register(ins.memory_base())?;
    let index = address_register(ins.memory_index())?;
    let segment = match ins.memory_segment() {
        Register::DS => 1,
        Register::SS => 2,
        _ => return None,
    };
    let scale = ins.memory_index_scale();
    if !matches!(scale, 1 | 2 | 4 | 8) {
        return None;
    }
    Some((
        Operand {
            kind: MEMORY,
            width_bits: width * 8,
            access: READ,
            ..Operand::default()
        },
        Memory {
            displacement: ins.memory_displacement64(),
            base,
            index,
            scale,
            width_bytes: width,
            address_bits: 64,
            segment,
            access: READ,
            reserved: 0,
        },
    ))
}

fn branch(ins: &Instruction, spec: Spec, bytes: &[u8], row: &mut Description) -> Result<(), u32> {
    if ins.op_count() != 1 || ins.op0_kind() != OpKind::NearBranch64 {
        return Err(OPERANDS);
    }
    let (offset, count) = match (spec.form, bytes.len()) {
        (Form::Jcc, 2) if bytes[0] == 0x70 + spec.condition as u8 => (1, 1),
        (Form::Jcc, 6) if bytes[..2] == [0x0f, 0x80 + spec.condition as u8] => (2, 4),
        (Form::Jmp, 2) if bytes[0] == 0xeb => (1, 1),
        (Form::Jmp, 5) if bytes[0] == 0xe9 => (1, 4),
        _ => return Err(PREFIX),
    };
    let delta = if count == 1 {
        bytes[offset] as i8 as i64
    } else {
        i32::from_le_bytes(bytes[offset..offset + 4].try_into().map_err(|_| PREFIX)?) as i64
    };
    let target = (row.decoded.next_pc as i128) + (delta as i128);
    if target < 0 || target > u64::MAX as i128 {
        return Err(ADDRESS);
    }
    let target = target as u64;
    if !canonical(target) || target != ins.near_branch64() {
        return Err(ADDRESS);
    }
    row.target = target;
    row.flow = if spec.form == Form::Jcc { JCC } else { JMP };
    row.condition = spec.condition;
    row.operand_count = 1;
    row.operands[0] = Operand {
        immediate: target,
        kind: BRANCH,
        width_bits: 64,
        access: READ,
        encoding_bits: count as u32 * 8,
        ..Operand::default()
    };
    Ok(())
}

fn operands(ins: &Instruction, spec: Spec, bytes: &[u8], row: &mut Description) -> Result<(), u32> {
    if matches!(spec.form, Form::Jcc | Form::Jmp) {
        return branch(ins, spec, bytes, row);
    }
    if ins.op_count() != 2 {
        return Err(OPERANDS);
    }
    let equal_xor = spec.form == Form::Xor
        && ins.op0_kind() == OpKind::Register
        && ins.op1_kind() == OpKind::Register
        && ins.op0_register() == ins.op1_register();
    let first_role = match spec.form {
        Form::MovRmR | Form::MovRRm | Form::Movzx => WRITE,
        Form::And | Form::Xor if !equal_xor => READ_WRITE,
        Form::Xor => WRITE,
        Form::Test | Form::Cmp => READ,
        _ => return Err(OPERANDS),
    };
    row.operands[0] = register_operand(ins, 0, spec.width, first_role).ok_or(OPERANDS)?;
    row.operands[1] = match spec.form {
        Form::MovRmR | Form::Xor | Form::Test => {
            register_operand(ins, 1, spec.width, if equal_xor { NONE } else { READ })
                .ok_or(OPERANDS)?
        }
        Form::MovRRm if ins.op1_kind() == OpKind::Register => {
            register_operand(ins, 1, spec.width, READ).ok_or(OPERANDS)?
        }
        Form::MovRRm | Form::Movzx => {
            let width = if spec.form == Form::Movzx {
                1
            } else {
                spec.width / 8
            };
            let (operand, memory) = memory_operand(ins, width).ok_or(OPERANDS)?;
            row.memory = memory;
            row.memory_count = 1;
            operand
        }
        Form::And => {
            let raw = *bytes.last().ok_or(OPERANDS)?;
            let value = match (spec.width, ins.op1_kind()) {
                (32, OpKind::Immediate8to32) => (raw as i8 as i32 as u32) as u64,
                (64, OpKind::Immediate8to64) => raw as i8 as i64 as u64,
                _ => return Err(OPERANDS),
            };
            let actual = if spec.width == 32 {
                ins.immediate8to32() as u32 as u64
            } else {
                ins.immediate8to64() as u64
            };
            if value != actual {
                return Err(OPERANDS);
            }
            Operand {
                immediate: value,
                kind: IMMEDIATE,
                width_bits: spec.width,
                access: READ,
                encoding_bits: 8,
                ..Operand::default()
            }
        }
        Form::Cmp if ins.op1_kind() == OpKind::Immediate8 && ins.immediate8() == bytes[1] => {
            Operand {
                immediate: bytes[1] as u64,
                kind: IMMEDIATE,
                width_bits: 8,
                access: READ,
                encoding_bits: 8,
                ..Operand::default()
            }
        }
        _ => return Err(OPERANDS),
    };
    row.operand_count = 2;
    row.flow = NEXT;
    row.condition = NO_CONDITION;
    Ok(())
}

fn flags(value: u32) -> Option<u32> {
    let mut remaining = value;
    let mut result = 0;
    for (iced, hardware) in [
        (RflagsBits::CF, CF),
        (RflagsBits::PF, PF),
        (RflagsBits::AF, AF),
        (RflagsBits::ZF, ZF),
        (RflagsBits::SF, SF),
        (RflagsBits::OF, OF),
    ] {
        if remaining & iced != 0 {
            result |= hardware;
            remaining &= !iced;
        }
    }
    if remaining == 0 { Some(result) } else { None }
}
fn flag_effects(ins: &Instruction, spec: Spec, row: &mut Description) -> Result<(), u32> {
    let actual = [
        flags(ins.rflags_read()).ok_or(EFFECTS)?,
        flags(ins.rflags_written()).ok_or(EFFECTS)?,
        flags(ins.rflags_set()).ok_or(EFFECTS)?,
        flags(ins.rflags_cleared()).ok_or(EFFECTS)?,
        flags(ins.rflags_undefined()).ok_or(EFFECTS)?,
    ];
    let expected = match spec.form {
        Form::And | Form::Test => [0, SF | ZF | PF, 0, CF | OF, AF],
        Form::Xor if ins.op0_register() == ins.op1_register() => [0, 0, PF | ZF, CF | OF | SF, AF],
        Form::Xor => [0, SF | ZF | PF, 0, CF | OF, AF],
        Form::Cmp => [0, CF | PF | AF | ZF | SF | OF, 0, 0, 0],
        Form::Jcc => {
            let read = match spec.condition {
                0 | 1 => OF,
                2 | 3 => CF,
                4 | 5 => ZF,
                6 | 7 => CF | ZF,
                8 | 9 => SF,
                10 | 11 => PF,
                12 | 13 => SF | OF,
                14 | 15 => ZF | SF | OF,
                _ => return Err(EFFECTS),
            };
            [read, 0, 0, 0, 0]
        }
        _ => [0; 5],
    };
    if actual != expected {
        return Err(EFFECTS);
    }
    [
        row.flags_read,
        row.flags_written,
        row.flags_set,
        row.flags_cleared,
        row.flags_undefined,
    ] = actual;
    Ok(())
}

fn push_register(
    rows: &mut [UsedRegister; 3],
    count: &mut usize,
    reg: u32,
    width: u32,
    role: u32,
) -> Result<(), u32> {
    if *count >= rows.len() || reg >= 16 {
        return Err(EFFECTS);
    }
    rows[*count] = UsedRegister {
        reg,
        width_bits: width,
        access: role,
        reserved: 0,
    };
    *count += 1;
    Ok(())
}
fn expected_registers(row: &Description) -> Result<([UsedRegister; 3], usize), u32> {
    let mut rows = [UsedRegister::default(); 3];
    let mut count = 0;
    for operand in &row.operands[..row.operand_count as usize] {
        if operand.kind == REGISTER && operand.access != NONE {
            if operand.width_bits == 32 && operand.access == READ_WRITE {
                push_register(&mut rows, &mut count, operand.reg, 32, READ)?;
                push_register(&mut rows, &mut count, operand.reg, 64, WRITE)?;
            } else {
                let width = if operand.width_bits == 32 && operand.access == WRITE {
                    64
                } else {
                    operand.width_bits
                };
                push_register(&mut rows, &mut count, operand.reg, width, operand.access)?;
            }
        } else if operand.kind == MEMORY {
            for reg in [row.memory.base, row.memory.index] {
                if reg != NO_REGISTER {
                    push_register(&mut rows, &mut count, reg, 64, READ)?;
                }
            }
        }
    }
    Ok((rows, count))
}

fn information(
    ins: &Instruction,
    info: &InstructionInfo,
    row: &mut Description,
) -> Result<(), u32> {
    for index in 0..5 {
        let expected = if index < row.operand_count {
            row.operands[index as usize].access
        } else {
            NONE
        };
        if access(info.op_access(index)).ok_or(EFFECTS)? != expected {
            return Err(EFFECTS);
        }
    }
    let (expected, count) = expected_registers(row)?;
    if info.used_registers().len() != count || info.used_memory().len() != row.memory_count as usize
    {
        return Err(EFFECTS);
    }
    for (index, value) in info.used_registers().iter().enumerate() {
        let (reg, width_bits) = register(value.register()).ok_or(EFFECTS)?;
        let access = access(value.access()).ok_or(EFFECTS)?;
        let actual = UsedRegister {
            reg,
            width_bits,
            access,
            reserved: 0,
        };
        if actual != expected[index] {
            return Err(EFFECTS);
        }
        row.registers[index] = actual;
        if access & READ != 0 {
            row.gpr_read |= 1 << reg;
        }
        if access & WRITE != 0 {
            row.gpr_write |= 1 << reg;
        }
    }
    row.register_count = count as u32;
    if row.gpr_write & (1 << 4) != 0 {
        return Err(EFFECTS);
    }
    if row.memory_count == 1 {
        let memory = &info.used_memory()[0];
        let segment = match memory.segment() {
            Register::DS => 1,
            Register::SS => 2,
            _ => return Err(EFFECTS),
        };
        let actual = Memory {
            displacement: memory.displacement(),
            base: address_register(memory.base()).ok_or(EFFECTS)?,
            index: address_register(memory.index()).ok_or(EFFECTS)?,
            scale: memory.scale(),
            width_bytes: memory_width(memory.memory_size()).ok_or(EFFECTS)?,
            address_bits: 64,
            segment,
            access: access(memory.access()).ok_or(EFFECTS)?,
            reserved: 0,
        };
        if memory.address_size() != CodeSize::Code64
            || memory.vsib_size() != 0
            || actual != row.memory
        {
            return Err(EFFECTS);
        }
    }
    if ins.code_size() != CodeSize::Code64 || ins.has_op_mask() || ins.is_save_restore_instruction()
    {
        return Err(EFFECTS);
    }
    Ok(())
}

pub(crate) fn one(pc: u64, source: &[u8], _call: &arena::Call) -> Result<Description, u32> {
    // Preserve the old decoder's complete row, including its STEP refusal.
    let decoded = crate::decode::one(pc, source)?;
    let refused = |reason| Description {
        decoded,
        version: VERSION,
        refusal: reason,
        ..Description::default()
    };
    match decoded.decode_status {
        abi::INVALID => return Ok(refused(INVALID)),
        abi::TRUNCATED => return Ok(refused(TRUNCATED)),
        abi::VALID => {}
        _ => return Ok(refused(EFFECTS)),
    }
    if !canonical(pc) || !canonical(decoded.next_pc) {
        return Ok(refused(ADDRESS));
    }
    let mut decoder = Decoder::with_ip(64, source, pc, DecoderOptions::NONE);
    let ins = decoder.decode();
    if ins.is_invalid()
        || ins.code() as u32 != decoded.code
        || ins.len() as u32 != decoded.length
        || ins.next_ip() != decoded.next_pc
        || decoded.kind != abi::NONE
    {
        return Ok(refused(EFFECTS));
    }
    let Some(spec) = domain(ins.code()) else {
        return Ok(refused(UNSUPPORTED));
    };
    let bytes = &source[..ins.len()];
    if !raw_form(spec, bytes) {
        return Ok(refused(PREFIX));
    }
    let mut row = Description {
        decoded,
        version: VERSION,
        ..Description::default()
    };
    if let Err(reason) =
        operands(&ins, spec, bytes, &mut row).and_then(|_| flag_effects(&ins, spec, &mut row))
    {
        return Ok(refused(reason));
    }
    // Gate/prove the 3-register/1-memory bound BEFORE calling the Vec-based
    // factory. All accepted forms have no implied access except XOR's clearing
    // specialization (its transient maximum is also three rows).
    if expected_registers(&row).is_err() || row.memory_count > 1 {
        return Ok(refused(EFFECTS));
    }
    // SAFETY: initialize precedes seal; the borrowed Call proves exclusive
    // factory access. The retained factory is neither moved nor dropped.
    let info = unsafe { (&mut *FACTORY.0.get()).assume_init_mut().info(&ins) };
    if let Err(reason) = information(&ins, info, &mut row) {
        return Ok(refused(reason));
    }
    row.ready = 1;
    Ok(row)
}
