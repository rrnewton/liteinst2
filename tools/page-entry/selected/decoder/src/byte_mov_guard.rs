// Included inside mov_guard only for the separate loop-effects feature.
use super::*;
const _: () = {
    assert!(Code::Mov_rm8_r8 as u32 == 279);
    assert!(Code::Mov_rm8_imm8 as u32 == 401);
};

fn low(r: Register) -> Option<u32> {
    use Register::*;
    Some(match r {
        AL => 0, CL => 1, DL => 2, BL => 3,
        SPL => 4, BPL => 5, SIL => 6, DIL => 7,
        R8L => 8, R9L => 9, R10L => 10, R11L => 11,
        R12L => 12, R13L => 13, R14L => 14, R15L => 15,
        _ => return Option::None,
    })
}

fn one(pc: u64, source: &[u8]) -> Result<Store, u32> {
    let mut instruction = iced_x86::Instruction::default();
    let qualified = tf::one_with_instruction(pc, source, &mut instruction)?;
    let mut out = Store { tf: qualified, version: 2, available: source.len() as u32,
        refusal: 1, ..Store::default() };
    out.bytes[..source.len()].copy_from_slice(source);
    if qualified.policy != 1 || instruction.is_invalid() || instruction.op_count() != 2
        || instruction.op0_kind() != OpKind::Memory { return Ok(out); }
    let immediate = match instruction.code() {
        Code::Mov_rm8_r8 => false, Code::Mov_rm8_imm8 => true, _ => return Ok(out),
    };
    if instruction.code() as u32 != qualified.code || instruction.len() as u32 != qualified.length
        || instruction.next_ip() != qualified.next_pc { return Ok(out); }
    let n = instruction.len(); let bytes = &source[..n];
    let op = usize::from(matches!(bytes[0], 0x40..=0x4f));
    if n < op+2 || bytes[op] != if immediate { 0xc6 } else { 0x88 }
        || bytes[op+1] & 0xc0 == 0xc0 { return Ok(out); }
    let rex = if op == 1 { bytes[0] } else { 0 };
    if rex & 8 != 0 || immediate && (bytes[op+1] & 0x38 != 0 || rex & 4 != 0)
        || instruction.has_lock_prefix() || instruction.has_rep_prefix() || instruction.has_repne_prefix()
        || !matches!(instruction.memory_segment(), Register::DS | Register::SS)
        || instruction.segment_prefix() != Register::None { return Ok(out); }
    let mut decoder = x86::decoder64(source, pc);
    let again = decoder.decode();
    if again != instruction { return Ok(out); }
    let constants = decoder.get_constant_offsets(&again);
    let d = constants.displacement_offset(); let dn = constants.displacement_size();
    let im = constants.immediate_offset(); let imn = constants.immediate_size();
    if !matches!(dn, 0 | 1 | 4) || d > n || dn > n-d
        || if immediate { imn != 1 || im+1 != n } else { imn != 0 } { return Ok(out); }
    let base = if instruction.is_ip_rel_memory_operand() {
        if instruction.memory_base() != Register::RIP || instruction.memory_index() != Register::None
            || dn != 4 { return Ok(out); }
        NO_REG
    } else { match address(instruction.memory_base()) { Some(x) => x, None => return Ok(out) } };
    let index = match address(instruction.memory_index()) { Some(x) => x, None => return Ok(out) };
    let scale = instruction.memory_index_scale();
    if !matches!(scale, 1 | 2 | 4 | 8)
        || rex & 1 != 0 && !(8..16).contains(&base)
        || rex & 2 != 0 && !(8..16).contains(&index) { return Ok(out); }
    let source_reg = if immediate { NO_REG } else {
        if instruction.op1_kind() != OpKind::Register { return Ok(out); }
        match low(instruction.op1_register()) { Some(x) => x, None => return Ok(out) }
    };
    if rex == 0x40 && !(4..8).contains(&source_reg) { return Ok(out); }
    let value = if immediate {
        if instruction.op1_kind() != OpKind::Immediate8 || instruction.immediate8() != bytes[im] { return Ok(out); }
        u64::from(bytes[im])
    } else { 0 };
    out.width_bytes=1;out.source_kind=if immediate {2}else{1};out.source_reg=source_reg;
    out.base=base;out.index=index;out.scale=scale;out.displacement=instruction.memory_displacement64();
    out.rip_relative=u32::from(instruction.is_ip_rel_memory_operand());
    if out.rip_relative!=0 { out.rip_target=instruction.ip_rel_memory_address(); }
    out.immediate=value;out.displacement_offset=d as u32;out.displacement_bytes=dn as u32;
    out.opcode_offset=op as u32;out.modrm_offset=(op+1)as u32;out.refusal=0;out.ready=1;
    Ok(out)
}

/// # Safety
/// Same initialized/sealed arena, serialized caller and owned disjoint readable
/// 1..15 source / aligned writable output contract as the existing decoder.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_byte_mov_store(pc:u64, bytes:*const u8, length:usize, out:*mut Store)->u32 {
    if out.is_null(){return abi::BAD_ARGUMENT;}
    // SAFETY: caller owns the whole output, including every refusal path.
    unsafe{out.write(Store::default());}
    if bytes.is_null() || !(1..=15).contains(&length) || (bytes as usize).checked_add(length).is_none(){return abi::BAD_ARGUMENT;}
    let _call=match arena::enter(){Ok(x)=>x,Err(e)=>return e};
    // SAFETY: caller retains immutable disjoint bytes for this serialized call.
    let source=unsafe{core::slice::from_raw_parts(bytes,length)};
    match one(pc,source){Ok(x)=>{unsafe{out.write(x);}abi::OK},Err(e)=>e}
}
