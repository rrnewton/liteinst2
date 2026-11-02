// Included only inside region::span under the additive scalar-read feature.
// No data read, allocator growth, source lease or execution authority.
use super::*;

const READ_VERSION: u32 = 2;

fn low_register(reg: Register) -> Option<(u32, u32)> {
    let byte = match reg {
        Register::AL => 0, Register::CL => 1, Register::DL => 2, Register::BL => 3,
        Register::SPL => 4, Register::BPL => 5, Register::SIL => 6, Register::DIL => 7,
        Register::R8L => 8, Register::R9L => 9, Register::R10L => 10, Register::R11L => 11,
        Register::R12L => 12, Register::R13L => 13, Register::R14L => 14, Register::R15L => 15,
        _ => return super::register(reg),
    };
    Some((byte, 8))
}

fn reg(ins: &Instruction, index: u32, width: u32, role: u32) -> Result<Operand, u32> {
    if ins.op_kind(index) != OpKind::Register { return Err(OPERANDS); }
    let (reg, actual) = low_register(ins.op_register(index)).ok_or(OPERANDS)?;
    if actual != width || (reg == 4 && role & WRITE != 0) { return Err(OPERANDS); }
    Ok(Operand { kind: REGISTER, reg, width_bits: width, access: role, ..Operand::default() })
}

fn nop(bytes: &[u8]) -> bool {
    matches!(bytes,
        [0x0f, 0x1f, 0x00] |
        [0x0f, 0x1f, 0x40, 0x00] |
        [0x0f, 0x1f, 0x44, 0x00, 0x00] |
        [0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00] |
        [0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00])
}

fn operands(ins: &Instruction, constants: &iced_x86::ConstantOffsets,
            bytes: &[u8], row: &mut Description) -> Result<(), u32> {
    let (at, rex) = match bytes.first() {
        Some(value @ 0x40..=0x4f) => (1, *value), _ => (0, 0),
    };
    let tail = &bytes[at..];
    row.condition = NO_CONDITION;
    match ins.code() {
        Code::Movsxd_r64_rm32 => {
            // REX.W is mandatory. X is unused in this register-only form.
            if rex & 8 == 0 || rex & 2 != 0 || tail.len() != 2
                || tail[0] != 0x63 || tail[1] & 0xc0 != 0xc0 { return Err(PREFIX); }
            if ins.op_count() != 2 { return Err(OPERANDS); }
            row.operands[0] = reg(ins, 0, 64, WRITE)?;
            row.operands[1] = reg(ins, 1, 32, READ)?;
            row.operand_count = 2;
        }
        Code::Test_rm8_r8 | Code::Cmp_rm8_r8 => {
            let opcode = if ins.code() == Code::Test_rm8_r8 { 0x84 } else { 0x38 };
            if rex & 0x0a != 0 || tail.len() != 2 || tail[0] != opcode
                || tail[1] & 0xc0 != 0xc0 { return Err(PREFIX); }
            if ins.op_count() != 2 { return Err(OPERANDS); }
            row.operands[0] = reg(ins, 0, 8, READ)?;
            row.operands[1] = reg(ins, 1, 8, READ)?;
            // A bare REX is necessary for SPL/BPL/SIL/DIL, not for AL..BL.
            if rex == 0x40 && row.operands.iter().all(|o| o.reg < 4) { return Err(PREFIX); }
            row.operand_count = 2;
        }
        Code::Cmp_rm8_imm8 => {
            // Only opcode80 /7 memory, one optional meaningful REX.B/X.
            if rex & 0x0c != 0 || rex == 0x40 || tail.len() < 3
                || tail[0] != 0x80 || tail[1] & 0x38 != 0x38
                || tail[1] & 0xc0 == 0xc0 { return Err(PREFIX); }
            if ins.op_count() != 2 || ins.op0_kind() != OpKind::Memory
                || ins.op1_kind() != OpKind::Immediate8 { return Err(OPERANDS); }
            let spec = Spec { family: Family::Cmp, encoding: Encoding::Group8,
                width: 8, opcode: 0x80, group: 7 };
            row.operands[0] = address_operand(ins, constants, bytes, spec, row)?;
            // Refuse ignored REX extensions (including RIP/no-base aliases).
            if rex & 1 != 0 && !(8..16).contains(&row.address.base)
                || rex & 2 != 0 && !(8..16).contains(&row.address.index) { return Err(PREFIX); }
            let pos = constants.immediate_offset();
            if constants.immediate_size() != 1 || pos + 1 != bytes.len()
                || bytes[pos] != ins.immediate8() { return Err(OPERANDS); }
            row.operands[1] = Operand { immediate: bytes[pos] as u64, kind: IMMEDIATE,
                width_bits: 8, access: READ, encoding_bits: 8, ..Operand::default() };
            row.operand_count = 2;
        }
        Code::Nop_rm32 => {
            if !nop(bytes) { return Err(PREFIX); }
            if ins.op_count() != 1 || ins.op0_kind() != OpKind::Memory { return Err(OPERANDS); }
            // The encoded addressing syntax is ignored by the CPU. It has no
            // architectural operand, GPR read, address calculation or memory read.
        }
        _ => return Err(UNSUPPORTED),
    }
    Ok(())
}

fn effect_flags(ins: &Instruction, row: &mut Description) -> Result<(), u32> {
    let actual = [flags(ins.rflags_read()).ok_or(EFFECTS)?, flags(ins.rflags_written()).ok_or(EFFECTS)?,
        flags(ins.rflags_set()).ok_or(EFFECTS)?, flags(ins.rflags_cleared()).ok_or(EFFECTS)?,
        flags(ins.rflags_undefined()).ok_or(EFFECTS)?];
    let expected = match ins.code() {
        Code::Cmp_rm8_imm8 | Code::Cmp_rm8_r8 => [0, CF | PF | AF | ZF | SF | OF, 0, 0, 0],
        Code::Test_rm8_r8 => [0, PF | ZF | SF, 0, CF | OF, AF],
        Code::Movsxd_r64_rm32 | Code::Nop_rm32 => [0; 5],
        _ => return Err(EFFECTS),
    };
    if actual != expected { return Err(EFFECTS); }
    [row.flags_read, row.flags_written, row.flags_set, row.flags_cleared, row.flags_undefined] = actual;
    Ok(())
}

fn information(ins: &Instruction, info: &InstructionInfo, row: &mut Description) -> Result<(), u32> {
    for i in 0..5 {
        let want = if i < row.operand_count { row.operands[i as usize].access } else { NONE };
        if access(info.op_access(i)) != Some(want) { return Err(EFFECTS); }
    }
    // No implied state in these five Codes. This independently joins the full
    // factory result, including ordered alias rows and exact memory effects.
    let spec = Spec { family: Family::Cmp, encoding: Encoding::RmReg, width: 8, opcode: 0, group: 0 };
    let (expected, count) = expected_registers(row, spec)?;
    if info.used_registers().len() != count || info.used_memory().len() != row.memory_count as usize {
        return Err(EFFECTS);
    }
    for (i, value) in info.used_registers().iter().enumerate() {
        let (reg, width_bits) = low_register(value.register()).ok_or(EFFECTS)?;
        let role = access(value.access()).ok_or(EFFECTS)?;
        let actual = UsedRegister { reg, width_bits, access: role, reserved: 0 };
        if actual != expected[i] { return Err(EFFECTS); }
        row.registers[i] = actual;
        if role & READ != 0 { row.gpr_read |= 1 << reg; }
        if role & WRITE != 0 { row.gpr_write |= 1 << reg; }
    }
    row.register_count = count as u32;
    if row.gpr_write & (1 << 4) != 0 { return Err(EFFECTS); }
    if row.memory_count == 1 {
        let memory = &info.used_memory()[0];
        let actual = Memory { displacement: memory.displacement(),
            base: address_register(memory.base()).ok_or(EFFECTS)?,
            index: address_register(memory.index()).ok_or(EFFECTS)?, scale: memory.scale(),
            width_bytes: memory_width(memory.memory_size()).ok_or(EFFECTS)?, address_bits: 64,
            segment: match memory.segment() { Register::DS => 1, Register::SS => 2, _ => return Err(EFFECTS) },
            access: access(memory.access()).ok_or(EFFECTS)?, reserved: 0 };
        if memory.address_size() != CodeSize::Code64 || memory.vsib_size() != 0 || actual != row.address {
            return Err(EFFECTS);
        }
    }
    if ins.code_size() != CodeSize::Code64 || ins.has_op_mask() || ins.is_save_restore_instruction() {
        return Err(EFFECTS);
    }
    Ok(())
}

fn one(pc: u64, source: &[u8], call: &arena::Call) -> Result<Description, u32> {
    let old = super::one(pc, source, call)?;
    if old.ready == 1 { return Ok(Description { version: READ_VERSION, ..old }); }
    let decoded = old.decoded;
    let refused = |reason| Description { decoded, version: READ_VERSION, refusal: reason, ..Description::default() };
    if decoded.decode_status != abi::VALID { return Ok(refused(old.refusal)); }
    if !canonical(pc) || !canonical(decoded.next_pc) { return Ok(refused(ADDRESS)); }
    let mut decoder = Decoder::with_ip(64, source, pc, DecoderOptions::NONE);
    let ins = decoder.decode();
    if ins.is_invalid() || ins.code() as u32 != decoded.code || ins.len() as u32 != decoded.length
        || ins.next_ip() != decoded.next_pc || decoded.kind != abi::NONE { return Ok(refused(EFFECTS)); }
    let bytes = &source[..ins.len()];
    let constants = decoder.get_constant_offsets(&ins);
    let mut row = Description { decoded, version: READ_VERSION, ..Description::default() };
    if let Err(reason) = operands(&ins, &constants, bytes, &mut row)
        .and_then(|_| effect_flags(&ins, &mut row)) { return Ok(refused(reason)); }
    // All added forms have <=2 used-register rows and <=1 memory row before
    // factory entry; neither NOP nor MOVSXD introduces implicit vector state.
    let spec = Spec { family: Family::Cmp, encoding: Encoding::RmReg, width: 8, opcode: 0, group: 0 };
    let count = match expected_registers(&row, spec) {
        Ok((_, count)) => count, Err(reason) => return Ok(refused(reason)),
    };
    if count > 2 || row.memory_count > 1 { return Ok(refused(EFFECTS)); }
    // SAFETY: same sealed factory and unique arena Call as the old API.
    let info = unsafe { (&mut *FACTORY.0.get()).assume_init_mut().info(&ins) };
    if let Err(reason) = information(&ins, info, &mut row) { return Ok(refused(reason)); }
    row.ready = 1;
    Ok(row)
}

/// # Safety
/// Same immutable owned source, aligned/disjoint output and sealed single-caller
/// arena contract as span_describe. This call grants no execution authority.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_scalar_read_describe(pc: u64, bytes: *const u8,
        length: usize, out: *mut Description) -> u32 {
    if out.is_null() { return abi::BAD_ARGUMENT; }
    // SAFETY: caller owns the complete output on every return.
    unsafe { out.write(Description::default()); }
    if bytes.is_null() || !(1..=15).contains(&length)
        || (bytes as usize).checked_add(length).is_none() { return abi::BAD_ARGUMENT; }
    let call = match arena::enter() { Ok(call) => call, Err(error) => return error };
    // SAFETY: caller retains the bounded immutable disjoint source.
    let source = unsafe { core::slice::from_raw_parts(bytes, length) };
    match one(pc, source, &call) {
        Ok(row) => { unsafe { out.write(row); } abi::OK }
        Err(error) => error,
    }
}

/// A separate no-write theorem; neither descriptor flags nor mnemonic alone
/// authorizes it. It also requires the unchanged actual TF admission facts.
/// # Safety
/// Same source/output/arena contract as scalar_read_describe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_scalar_read_none(pc: u64, bytes: *const u8,
        length: usize, out: *mut crate::WriteFootprint) -> u32 {
    if out.is_null() { return abi::BAD_ARGUMENT; }
    // SAFETY: caller owns the complete output on every return.
    unsafe { out.write(crate::WriteFootprint::default()); }
    if bytes.is_null() || !(1..=15).contains(&length)
        || (bytes as usize).checked_add(length).is_none() { return abi::BAD_ARGUMENT; }
    let call = match arena::enter() { Ok(call) => call, Err(error) => return error };
    // SAFETY: bounded immutable source remains disjoint from output and arena.
    let source = unsafe { core::slice::from_raw_parts(bytes, length) };
    let row = match one(pc, source, &call) { Ok(row) => row, Err(error) => return error };
    let mut instruction = Instruction::default();
    let tf = match crate::tf::one_with_instruction(pc, source, &mut instruction) {
        Ok(row) => row, Err(error) => return error,
    };
    let mut result = crate::WriteFootprint { pc: row.decoded.pc, next_pc: row.decoded.next_pc,
        abi_version: 1, code: row.decoded.code, length: row.decoded.length,
        ..crate::WriteFootprint::default() };
    if row.ready == 1 && row.refusal == 0 && row.version == READ_VERSION && tf.policy == 1
        && tf.pc == result.pc && tf.next_pc == result.next_pc && tf.code == result.code && tf.length == result.length
        && !instruction.is_invalid() && instruction.code() as u32 == result.code
        && instruction.len() as u32 == result.length && instruction.next_ip() == result.next_pc {
        use iced_x86::Mnemonic::*;
        let independent = match instruction.mnemonic() {
            // The old NONE theorem's arms are preserved literally.
            Lea | Cmp | Test | Movzx | Jmp | Jo | Jno | Jb | Jae | Je | Jne
            | Jbe | Ja | Js | Jns | Jp | Jnp | Jl | Jge | Jle | Jg => true,
            Mov | Add | Sub | And | Or | Xor | Shl | Shr | Sar =>
                instruction.op0_kind() == OpKind::Register,
            Movsxd => instruction.code() == Code::Movsxd_r64_rm32
                && instruction.op0_kind() == OpKind::Register && instruction.op1_kind() == OpKind::Register,
            Nop => instruction.code() == Code::Nop_rm32 && nop(&source[..instruction.len()]),
            _ => false,
        };
        if independent { result.policy = 1; }
    }
    // SAFETY: unsupported results retain the complete zero range.
    unsafe { out.write(result); }
    abi::OK
}

// Distinct version3 API; all scalar-read2 bodies stay unchanged.
#[cfg(feature = "loop-effects")]
mod loop_scalar {
    include!("loop_scalar.rs");
}
