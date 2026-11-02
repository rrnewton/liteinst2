// Included inside region::span::scalar_read only for loop-effects.
use super::*;

const LOOP_VERSION: u32 = 3;
const _: () = assert!(Code::Imul_r64_rm64 as u32 == 2072);

fn one(pc: u64, source: &[u8], call: &arena::Call) -> Result<Description, u32> {
    let old = super::one(pc, source, call)?;
    if old.ready == 1 { return Ok(Description { version: LOOP_VERSION, ..old }); }
    let decoded = old.decoded;
    let refused = |reason| Description { decoded, version: LOOP_VERSION, refusal: reason, ..Description::default() };
    if decoded.decode_status != abi::VALID { return Ok(refused(old.refusal)); }
    if !canonical(pc) || !canonical(decoded.next_pc) { return Ok(refused(ADDRESS)); }
    let mut decoder = Decoder::with_ip(64, source, pc, DecoderOptions::NONE);
    let ins = decoder.decode();
    if ins.is_invalid() || ins.code() as u32 != decoded.code || ins.len() as u32 != decoded.length
        || ins.next_ip() != decoded.next_pc || decoded.kind != abi::NONE { return Ok(refused(EFFECTS)); }
    if ins.code() != Code::Imul_r64_rm64 { return Ok(refused(old.refusal)); }
    let bytes = &source[..ins.len()];
    if bytes.len() != 4 || !matches!(bytes[0], 0x48..=0x4f) || bytes[0] & 2 != 0
        || bytes[1] != 0x0f || bytes[2] != 0xaf || bytes[3] & 0xc0 != 0xc0
        || ins.has_lock_prefix() || ins.has_rep_prefix() || ins.has_repne_prefix()
        || ins.segment_prefix() != Register::None { return Ok(refused(PREFIX)); }
    if ins.op_count() != 2 { return Ok(refused(OPERANDS)); }
    let mut row = Description { decoded, version: LOOP_VERSION, flow: NEXT,
        condition: NO_CONDITION, ..Description::default() };
    row.operands[0] = match super::reg(&ins, 0, 64, READ_WRITE) {
        Ok(value) => value, Err(reason) => return Ok(refused(reason)),
    };
    row.operands[1] = match super::reg(&ins, 1, 64, READ) {
        Ok(value) => value, Err(reason) => return Ok(refused(reason)),
    };
    row.operand_count = 2;
    let actual = match (flags(ins.rflags_read()), flags(ins.rflags_written()),
        flags(ins.rflags_set()), flags(ins.rflags_cleared()), flags(ins.rflags_undefined())) {
        (Some(a), Some(b), Some(c), Some(d), Some(e)) => [a,b,c,d,e],
        _ => return Ok(refused(EFFECTS)),
    };
    if actual != [0, CF | OF, 0, 0, SF | ZF | AF | PF] { return Ok(refused(EFFECTS)); }
    [row.flags_read, row.flags_written, row.flags_set, row.flags_cleared, row.flags_undefined] = actual;
    // Both operands are explicit64-bit registers. Reuse the complete factory
    // join, including ordered alias rows; no memory/implied state is invented.
    // SAFETY: the unchanged sealed factory is owned by this unique arena Call.
    let info = unsafe { (&mut *FACTORY.0.get()).assume_init_mut().info(&ins) };
    if let Err(reason) = super::information(&ins, info, &mut row) { return Ok(refused(reason)); }
    row.ready = 1;
    Ok(row)
}

/// # Safety
/// The same owned immutable/disjoint source, aligned output and sealed,
/// serialized arena requirements as scalar_read_describe apply.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_loop_scalar_describe(pc: u64, bytes: *const u8,
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

/// # Safety
/// Same source/output/arena contract as loop_scalar_describe. This is a
/// register-free no-write theorem, not permission to execute an instruction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_loop_scalar_none(pc: u64, bytes: *const u8,
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
    if row.ready == 1 && row.refusal == 0 && row.version == LOOP_VERSION && tf.policy == 1
        && tf.pc == result.pc && tf.next_pc == result.next_pc && tf.code == result.code && tf.length == result.length
        && !instruction.is_invalid() && instruction.code() as u32 == result.code
        && instruction.len() as u32 == result.length && instruction.next_ip() == result.next_pc {
        use iced_x86::Mnemonic::*;
        let independent = match instruction.mnemonic() {
            // Preserve every old scalar-read NONE arm; add only the exact
            // register-only IMUL Code independently of the descriptor's masks.
            Lea | Cmp | Test | Movzx | Jmp | Jo | Jno | Jb | Jae | Je | Jne
            | Jbe | Ja | Js | Jns | Jp | Jnp | Jl | Jge | Jle | Jg => true,
            Mov | Add | Sub | And | Or | Xor | Shl | Shr | Sar =>
                instruction.op0_kind() == OpKind::Register,
            Movsxd => instruction.code() == Code::Movsxd_r64_rm32
                && instruction.op0_kind() == OpKind::Register && instruction.op1_kind() == OpKind::Register,
            Nop => instruction.code() == Code::Nop_rm32 && nop(&source[..instruction.len()]),
            Imul => instruction.code() == Code::Imul_r64_rm64
                && instruction.op0_kind() == OpKind::Register && instruction.op1_kind() == OpKind::Register,
            _ => false,
        };
        if independent { result.policy = 1; }
    }
    // SAFETY: unsupported results retain the complete zero range.
    unsafe { out.write(result); }
    abi::OK
}
