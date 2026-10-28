//! Conservative writes for the closed original-address TF profile.
//! No allocator, instruction-info factory, memory access, or execution authority.
use iced_x86::{Code, Instruction, MemorySize, Mnemonic, OpKind, Register};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Registers {
    pub gpr: [u64; 16],
    pub fs_base: u64,
    pub gs_base: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Footprint {
    pub pc: u64,
    pub next_pc: u64,
    pub first: u64,
    pub end: u64,
    pub abi_version: u32,
    pub policy: u32,
    pub code: u32,
    pub length: u32,
}

const _: () = {
    assert!(core::mem::size_of::<Registers>() == 144);
    assert!(core::mem::align_of::<Registers>() == 8);
    assert!(core::mem::offset_of!(Registers, fs_base) == 128);
    assert!(core::mem::size_of::<Footprint>() == 48);
    assert!(core::mem::align_of::<Footprint>() == 8);
    assert!(core::mem::offset_of!(Footprint, abi_version) == 32);
    assert!(core::mem::offset_of!(Footprint, length) == 44);
};

const UNSUPPORTED: u32 = 0;
const NONE: u32 = 1;
const RANGE: u32 = 2;

fn no_write(mut out: Footprint) -> Footprint {
    out.policy = NONE;
    out
}

fn range(mut out: Footprint, first: u64, bytes: u64) -> Footprint {
    if let Some(end) = first.checked_add(bytes) {
        if end > first {
            out.first = first;
            out.end = end;
            out.policy = RANGE;
        }
    }
    out
}

// These are data sizes, independent of the instruction's read/write role.
// Unknown, variable, broadcast, far-pointer and larger forms remain closed.
fn width(size: MemorySize) -> Option<u64> {
    use MemorySize::*;
    match size {
        UInt8 | Int8 => Some(1),
        UInt16 | Int16 => Some(2),
        UInt32 | Int32 | Float32 => Some(4),
        UInt64 | Int64 | Float64 => Some(8),
        Packed128_UInt8 | Packed128_Int8 | Packed128_UInt16 | Packed128_Int16
        | Packed128_UInt32 | Packed128_Int32 | Packed128_UInt64 | Packed128_Int64
        | Packed128_Float32 | Packed128_Float64 => Some(16),
        _ => None,
    }
}

fn register_value(state: &Registers, register: Register) -> Option<u64> {
    use Register::*;
    let (index, low32) = match register {
        RAX => (0, false), RCX => (1, false), RDX => (2, false), RBX => (3, false),
        RSP => (4, false), RBP => (5, false), RSI => (6, false), RDI => (7, false),
        R8 => (8, false), R9 => (9, false), R10 => (10, false), R11 => (11, false),
        R12 => (12, false), R13 => (13, false), R14 => (14, false), R15 => (15, false),
        EAX => (0, true), ECX => (1, true), EDX => (2, true), EBX => (3, true),
        ESP => (4, true), EBP => (5, true), ESI => (6, true), EDI => (7, true),
        R8D => (8, true), R9D => (9, true), R10D => (10, true), R11D => (11, true),
        R12D => (12, true), R13D => (13, true), R14D => (14, true), R15D => (15, true),
        CS | DS | ES | SS => return Some(0),
        FS => return Some(state.fs_base),
        GS => return Some(state.gs_base),
        _ => return Option::None,
    };
    Some(if low32 { state.gpr[index] as u32 as u64 } else { state.gpr[index] })
}

pub(crate) fn one(pc: u64, source: &[u8], state: &Registers) -> Result<Footprint, u32> {
    let mut instruction = Instruction::default();
    let qualified = crate::tf::one_with_instruction(pc, source, &mut instruction)?;
    let out = Footprint {
        pc: qualified.pc, next_pc: qualified.next_pc, abi_version: 1,
        code: qualified.code, length: qualified.length, policy: UNSUPPORTED,
        ..Footprint::default()
    };
    if qualified.policy != 1 { return Ok(out); }
    if instruction.is_invalid() || instruction.code() as u32 != out.code
        || instruction.len() as u32 != out.length || instruction.next_ip() != out.next_pc
    { return Ok(out); }
    // Source memory of CALL/PUSH is read-only, but their implicit stack store
    // must be considered before inspecting the explicit operand roles.
    match instruction.code() {
        Code::Call_rel32_64 | Code::Call_rm64 | Code::Push_r64 | Code::Push_rm64
        | Code::Pushq_imm32 | Code::Pushq_imm8 => {
            return Ok(match state.gpr[4].checked_sub(8) {
                Some(first) => range(out, first, 8), None => out,
            });
        }
        Code::Pop_rm64 => {
            // POP memory uses post-pop RSP in its effective address. It is
            // deliberately unsupported until a separate oracle covers that.
            return Ok(if instruction.op0_kind() == OpKind::Register { no_write(out) } else { out });
        }
        Code::Pop_r64 | Code::Leaveq | Code::Retnq | Code::Retnq_imm16 => return Ok(no_write(out)),
        // This exact store/reverse-copy Code is separate from the load's
        // NONE arm. Every memory form potentially writes the complete16 bytes.
        Code::VEX_Vmovdqu_xmmm128_xmm => {
            if instruction.op0_kind() == OpKind::Register { return Ok(no_write(out)); }
            if instruction.op0_kind() != OpKind::Memory { return Ok(out); }
            let Some(first) = instruction.virtual_address(0, 0, |register, index, element_size| {
                if index != 0 || element_size != 0 { return None; }
                register_value(state, register)
            }) else { return Ok(out); };
            return Ok(range(out, first, 16));
        }
        // These exact Codes have register destinations. Do not put their
        // mnemonics in the no-write family: a future memory-store Code with
        // the same mnemonic must remain unsupported until explicitly reviewed.
        Code::EVEX_Vpbroadcastb_zmm_k1z_r32
        | Code::EVEX_Vmovdqu64_zmm_k1z_zmmm512
        | Code::VEX_Vmovdqu_xmm_xmmm128
        | Code::EVEX_Vptestnmb_kr_k1_zmm_zmmm512
        | Code::EVEX_Vptestmb_kr_k1_zmm_zmmm512
        | Code::VEX_Kmovq_r64_kr
        | Code::EVEX_Vpcmpeqb_kr_k1_zmm_zmmm512
        | Code::EVEX_Vpcmpb_kr_k1_zmm_zmmm512_imm8
        | Code::EVEX_Vpxorq_xmm_k1z_xmm_xmmm128b64
        | Code::VEX_Blsmsk_r64_rm64 => return Ok(no_write(out)),
        _ => {}
    }
    use Mnemonic::*;
    match instruction.mnemonic() {
        // Explicitly no application-memory writes, including memory-source
        // arithmetic and bit tests. Faults and control transfers remain owned
        // by the unchanged execution route, not this descriptive query.
        Endbr64 | Nop | Lea | Cmp | Test | Bt | Mul | Imul | Div | Idiv | Jmp
        | Jo | Jno | Jb | Jae | Je | Jne | Jbe | Ja | Js | Jns | Jp | Jnp
        | Jl | Jge | Jle | Jg | Jrcxz | Loop | Loope | Loopne
        | Clc | Stc | Cmc | Cld | Std | Cbw | Cwde | Cdqe | Cwd | Cdq | Cqo
        | Bswap | Bsf | Bsr | Movzx | Movsx | Movsxd
        | Cmovo | Cmovno | Cmovb | Cmovae | Cmove | Cmovne | Cmovbe | Cmova
        | Cmovs | Cmovns | Cmovp | Cmovnp | Cmovl | Cmovge | Cmovle | Cmovg
        | Pmovmskb | Xgetbv | Rdsspq
        => return Ok(no_write(out)),
        // A register bit-string operand does not write memory. A memory form
        // may address beyond the nominal word using its bit index: refuse it.
        Bts | Btr | Btc => return Ok(if instruction.op0_kind() == OpKind::Register {
            no_write(out)
        } else { out }),
        // In these closed mnemonic families all potential memory writes are
        // the explicit operand zero. Include the whole operand for conditional
        // CMPXCHG and zero-count shifts; never infer absence from flags/count.
        Mov | Add | Adc | Sub | Sbb | And | Or | Xor | Inc | Dec | Neg | Not
        | Shl | Shr | Sar | Rol | Ror | Rcl | Rcr | Shld | Shrd | Xchg | Xadd | Cmpxchg
        | Seto | Setno | Setb | Setae | Sete | Setne | Setbe | Seta
        | Sets | Setns | Setp | Setnp | Setl | Setge | Setle | Setg
        | Movups | Movaps | Movdqa | Movdqu | Pxor | Xorps | Xorpd | Pand | Pandn | Por
        | Paddb | Paddw | Paddd | Paddq | Psubb | Psubw | Psubd | Psubq
        | Pcmpeqb | Pcmpeqw | Pcmpeqd | Pcmpgtb | Pcmpgtw | Pcmpgtd
        | Pminub | Pmaxub | Pmaxud | Movlpd | Movhpd | Pslldq | Psrldq
        | Movd | Movq | Punpcklbw | Punpcklwd | Pshufd => {}
        _ => return Ok(out),
    }
    if instruction.op0_kind() == OpKind::Register { return Ok(no_write(out)); }
    if instruction.op0_kind() != OpKind::Memory { return Ok(out); }
    let Some(bytes) = width(instruction.memory_size()) else { return Ok(out); };
    let Some(first) = instruction.virtual_address(0, 0, |register, index, element_size| {
        if index != 0 || element_size != 0 { return None; }
        register_value(state, register)
    }) else { return Ok(out); };
    Ok(range(out, first, bytes))
}
