//! Four memory-store Codes only. Description is not a write/execution permit.
use crate::{abi, arena, tf};
use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Store {
    tf: tf::Classification,
    bytes: [u8; 16],
    displacement: u64,
    rip_target: u64,
    immediate: u64,
    version: u32, ready: u32, refusal: u32, available: u32,
    width_bytes: u32, source_kind: u32, source_reg: u32, base: u32,
    index: u32, scale: u32, rip_relative: u32, displacement_offset: u32,
    displacement_bytes: u32, modrm_offset: u32, opcode_offset: u32, reserved: u32,
}
const _: () = {
    assert!(core::mem::size_of::<Store>() == 144);
    assert!(core::mem::offset_of!(Store, displacement) == 56);
    assert!(core::mem::offset_of!(Store, version) == 80);
};
const NO_REG: u32 = 16;
fn gpr(r: Register, wide: bool) -> Option<u32> {
    let first = (if wide { Register::RAX } else { Register::EAX }) as u32;
    let value = r as u32;
    if value >= first && value - first < 16 { Some(value-first) } else { None }
}
fn address(r: Register) -> Option<u32> {
    if r == Register::None { Some(NO_REG) } else { gpr(r, true) }
}
fn one(pc: u64, source: &[u8]) -> Result<Store, u32> {
    let mut instruction = iced_x86::Instruction::default();
    let qualified = tf::one_with_instruction(pc, source, &mut instruction)?;
    let mut out = Store { tf: qualified, version: 1, available: source.len() as u32,
        refusal: 1, ..Store::default() };
    out.bytes[..source.len()].copy_from_slice(source);
    if qualified.policy != 1 || instruction.is_invalid() || instruction.op_count() != 2
        || instruction.op0_kind() != OpKind::Memory { return Ok(out); }
    let (width, immediate) = match instruction.code() {
        Code::Mov_rm32_r32 => (4, false), Code::Mov_rm64_r64 => (8, false),
        Code::Mov_rm32_imm32 => (4, true), Code::Mov_rm64_imm32 => (8, true),
        _ => return Ok(out),
    };
    if instruction.code() as u32 != qualified.code || instruction.len() as u32 != qualified.length
        || instruction.next_ip() != qualified.next_pc { return Ok(out); }
    let n = instruction.len(); let bytes = &source[..n];
    let op = usize::from(matches!(bytes[0], 0x40..=0x4f));
    if n < op+2 || bytes[op] != if immediate { 0xc7 } else { 0x89 }
        || bytes[op+1] & 0xc0 == 0xc0 { return Ok(out); }
    let rex = if op == 1 { bytes[0] } else { 0 };
    if (rex & 8 != 0) != (width == 8) || immediate && (bytes[op+1] & 0x38 != 0 || rex & 4 != 0)
        || instruction.has_lock_prefix() || instruction.has_rep_prefix() || instruction.has_repne_prefix()
        || !matches!(instruction.memory_segment(), Register::DS | Register::SS)
        || instruction.segment_prefix() != Register::None { return Ok(out); }
    // Re-decode supplies actual displacement/immediate positions; identity joins
    // prevent treating a hand-parsed operand as an independent iced result.
    let mut decoder = Decoder::with_ip(64, source, pc, DecoderOptions::NONE);
    let again = decoder.decode();
    if again != instruction { return Ok(out); }
    let constants = decoder.get_constant_offsets(&again);
    let d = constants.displacement_offset(); let dn = constants.displacement_size();
    let im = constants.immediate_offset(); let imn = constants.immediate_size();
    if !matches!(dn, 0 | 1 | 4) || d > n || dn > n-d
        || if immediate { imn != 4 || im+4 != n } else { imn != 0 } { return Ok(out); }
    let base = if instruction.is_ip_rel_memory_operand() {
        if instruction.memory_base() != Register::RIP || instruction.memory_index() != Register::None
            || dn != 4 { return Ok(out); }
        NO_REG
    } else { match address(instruction.memory_base()) { Some(x) => x, None => return Ok(out) } };
    let index = match address(instruction.memory_index()) { Some(x) => x, None => return Ok(out) };
    let scale = instruction.memory_index_scale();
    if !matches!(scale,1|2|4|8) { return Ok(out); }
    let source_reg = if immediate { NO_REG } else {
        if instruction.op1_kind() != OpKind::Register { return Ok(out); }
        match gpr(instruction.op1_register(), width==8) { Some(x) => x, None => return Ok(out) }
    };
    let value = if immediate {
        let raw = u32::from_le_bytes(bytes[im..im+4].try_into().map_err(|_| abi::BAD_ARGUMENT)?);
        if width==8 {
            if instruction.op1_kind()!=OpKind::Immediate32to64 { return Ok(out); }
            let v=raw as i32 as i64 as u64;
            if instruction.immediate32to64() as u64 != v { return Ok(out); } v
        } else {
            if instruction.op1_kind()!=OpKind::Immediate32 || instruction.immediate32()!=raw { return Ok(out); }
            raw as u64
        }
    } else { 0 };
    out.width_bytes=width; out.source_kind=if immediate {2}else{1};out.source_reg=source_reg;
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
pub unsafe extern "C" fn li2_decoder_mov_store(pc:u64, bytes:*const u8, length:usize, out:*mut Store)->u32 {
    if out.is_null(){return abi::BAD_ARGUMENT;}
    unsafe{out.write(Store::default());}
    if bytes.is_null() || !(1..=15).contains(&length) || (bytes as usize).checked_add(length).is_none(){return abi::BAD_ARGUMENT;}
    let _call=match arena::enter(){Ok(x)=>x,Err(e)=>return e};
    let source=unsafe{core::slice::from_raw_parts(bytes,length)};
    match one(pc,source){Ok(x)=>{unsafe{out.write(x);}abi::OK},Err(e)=>e}
}
