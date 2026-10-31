//! One 64-bit memory ADD Code. Description is not source/write/RX authority.
use crate::{abi, arena, tf};
use core::{cell::UnsafeCell, mem::MaybeUninit};
use iced_x86::{Code, CodeSize, Decoder, DecoderOptions, Instruction, InstructionInfoFactory, MemorySize, OpAccess, OpKind, Register, RflagsBits};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Descriptor {
    tf: tf::Classification,
    bytes: [u8; 16],
    displacement: u64,
    rip_target: u64,
    flags_written: u64,
    version: u32, ready: u32, refusal: u32, available: u32,
    width_bytes: u32, memory_access: u32, source_reg: u32, base: u32,
    index: u32, scale: u32, rip_relative: u32, displacement_offset: u32,
    displacement_bytes: u32, modrm_offset: u32, opcode_offset: u32, reserved: u32,
}
const _: () = {
    assert!(core::mem::size_of::<Descriptor>() == 144);
    assert!(core::mem::offset_of!(Descriptor, displacement) == 56);
    assert!(core::mem::offset_of!(Descriptor, version) == 80);
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
struct Factory(UnsafeCell<MaybeUninit<InstructionInfoFactory>>);
// SAFETY: initialization is single-owner; every later access requires the
// exclusive arena::Call. The factory remains live and is never dropped.
unsafe impl Sync for Factory {}
static FACTORY: Factory = Factory(UnsafeCell::new(MaybeUninit::uninit()));
pub(crate) fn initialize() {
    // SAFETY: the caller is between successful arena::begin and arena::seal.
    unsafe { (*FACTORY.0.get()).write(InstructionInfoFactory::new()); }
}
fn information(ins: &Instruction, _call: &arena::Call) -> bool {
    if ins.code() != Code::Add_rm64_r64 || ins.op_count() != 2
        || ins.op0_kind() != OpKind::Memory || ins.op1_kind() != OpKind::Register
        || ins.code_size()!=CodeSize::Code64 || ins.has_op_mask() || ins.is_save_restore_instruction()
        || ins.has_lock_prefix() || ins.has_rep_prefix() || ins.has_repne_prefix()
        || ins.segment_prefix() != Register::None || ins.is_vsib()
        || ins.memory_size() != MemorySize::UInt64 { return false; }
    let Some(source) = gpr(ins.op1_register(), true) else { return false; };
    let base = if ins.is_ip_rel_memory_operand() {
        if ins.memory_base() != Register::RIP || ins.memory_index() != Register::None { return false; }
        NO_REG
    } else { let Some(x) = address(ins.memory_base()) else { return false; }; x };
    let Some(index) = address(ins.memory_index()) else { return false; };
    if !matches!(ins.memory_segment(), Register::DS | Register::SS) { return false; }
    let scale = ins.memory_index_scale();
    if !matches!(scale, 1 | 2 | 4 | 8) { return false; }
    let actual = [ins.rflags_read(), ins.rflags_written(), ins.rflags_set(), ins.rflags_cleared(), ins.rflags_undefined()];
    let status = RflagsBits::CF | RflagsBits::PF | RflagsBits::AF | RflagsBits::ZF | RflagsBits::SF | RflagsBits::OF;
    if actual != [0, status, 0, 0, 0] { return false; }
    // Exact Code/form proves <=3 read-only GPR rows and one memory row BEFORE
    // factory access. Preserve repeated operands in the independent row join.
    let mut expected = [NO_REG;3];let mut count=0;
    for r in [base,index,source] { if r!=NO_REG { expected[count]=r;count+=1; } }
    // SAFETY: initialize/seal and this unique Call cover retained vector reuse.
    let info = unsafe { (&mut *FACTORY.0.get()).assume_init_mut().info(ins) };
    for i in 0..5 {
        let want = if i==0 { OpAccess::ReadWrite } else if i==1 { OpAccess::Read } else { OpAccess::None };
        if info.op_access(i)!=want { return false; }
    }
    if info.used_registers().len()!=count || info.used_memory().len()!=1 { return false; }
    for (i,r) in info.used_registers().iter().enumerate() {
        if gpr(r.register(),true)!=Some(expected[i]) || r.access()!=OpAccess::Read { return false; }
    }
    let m=&info.used_memory()[0];
    address(m.base())==Some(base) && address(m.index())==Some(index)
        && m.scale()==scale && m.displacement()==ins.memory_displacement64()
        && m.memory_size()==MemorySize::UInt64 && m.segment()==ins.memory_segment()
        && m.access()==OpAccess::ReadWrite && m.address_size()==CodeSize::Code64 && m.vsib_size()==0
}
fn one(pc: u64, source: &[u8], call: &arena::Call) -> Result<Descriptor, u32> {
    let mut instruction = iced_x86::Instruction::default();
    let qualified = tf::one_with_instruction(pc, source, &mut instruction)?;
    let mut out = Descriptor { tf: qualified, version: 1, available: source.len() as u32,
        refusal: 1, ..Descriptor::default() };
    out.bytes[..source.len()].copy_from_slice(source);
    if qualified.policy != 1 || qualified.flow != 1 || qualified.family != 1
        || instruction.is_invalid() || instruction.op_count() != 2
        || instruction.op0_kind() != OpKind::Memory { return Ok(out); }
    if instruction.code() != Code::Add_rm64_r64 { return Ok(out); }
    let width = 8;
    if instruction.code() as u32 != qualified.code || instruction.len() as u32 != qualified.length
        || instruction.next_ip() != qualified.next_pc { return Ok(out); }
    let n = instruction.len(); let bytes = &source[..n];
    let op = usize::from(matches!(bytes[0], 0x40..=0x4f));
    if n < op+2 || bytes[op] != 0x01
        || bytes[op+1] & 0xc0 == 0xc0 { return Ok(out); }
    let rex = if op == 1 { bytes[0] } else { 0 };
    if rex & 8 == 0
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
    let imn = constants.immediate_size();
    if !matches!(dn, 0 | 1 | 4) || d > n || dn > n-d
        || imn != 0 || constants.immediate_size2() != 0 { return Ok(out); }
    let base = if instruction.is_ip_rel_memory_operand() {
        if instruction.memory_base() != Register::RIP || instruction.memory_index() != Register::None
            || dn != 4 { return Ok(out); }
        NO_REG
    } else { match address(instruction.memory_base()) { Some(x) => x, None => return Ok(out) } };
    let index = match address(instruction.memory_index()) { Some(x) => x, None => return Ok(out) };
    let scale = instruction.memory_index_scale();
    if !matches!(scale,1|2|4|8) { return Ok(out); }
    if instruction.op1_kind() != OpKind::Register { return Ok(out); }
    let source_reg = match gpr(instruction.op1_register(), true) { Some(x) => x, None => return Ok(out) };
    // This profile's independent pre-seal factory is borrowed under this same exclusive
    // Call. Exact Code/form bounds its vectors to <=3 registers/one memory.
    // Its independent effects must be READ_WRITE64 + READ GPR64, no GPR
    // write, and exactly CF/PF/AF/ZF/SF/OF written (none read/undefined).
    if !information(&instruction, call) { return Ok(out); }
    out.width_bytes=width;out.memory_access=3;out.source_reg=source_reg;
    out.base=base;out.index=index;out.scale=scale;out.displacement=instruction.memory_displacement64();
    out.rip_relative=u32::from(instruction.is_ip_rel_memory_operand());
    if out.rip_relative!=0 { out.rip_target=instruction.ip_rel_memory_address(); }
    out.flags_written=0x8d5;out.displacement_offset=d as u32;out.displacement_bytes=dn as u32;
    out.opcode_offset=op as u32;out.modrm_offset=(op+1)as u32;out.refusal=0;out.ready=1;
    Ok(out)
}
/// # Safety
/// Same initialized/sealed arena, serialized caller and owned disjoint readable
/// 1..15 source / aligned writable output contract as the existing decoder.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn li2_decoder_add_rmw(pc:u64, bytes:*const u8, length:usize, out:*mut Descriptor)->u32 {
    if out.is_null(){return abi::BAD_ARGUMENT;}
    unsafe{out.write(Descriptor::default());}
    if bytes.is_null() || !(1..=15).contains(&length) || (bytes as usize).checked_add(length).is_none(){return abi::BAD_ARGUMENT;}
    let call=match arena::enter(){Ok(x)=>x,Err(e)=>return e};
    let source=unsafe{core::slice::from_raw_parts(bytes,length)};
    match one(pc,source,&call){Ok(x)=>{unsafe{out.write(x);}abi::OK},Err(e)=>e}
}
