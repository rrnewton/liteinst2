//! Separate closed TF-transparent profile. Old decoding/step classification is unchanged.
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, OpKind};
use crate::abi;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Classification {
    pub pc: u64,
    pub next_pc: u64,
    pub abi_version: u32,
    pub policy: u32,
    pub code: u32,
    pub length: u32,
    pub flow: u32,
    pub family: u32,
}
const _: () = {
    assert!(core::mem::size_of::<Classification>() == 40);
    assert!(core::mem::align_of::<Classification>() == 8);
    assert!(core::mem::offset_of!(Classification, pc) == 0);
    assert!(core::mem::offset_of!(Classification, next_pc) == 8);
    assert!(core::mem::offset_of!(Classification, abi_version) == 16);
    assert!(core::mem::offset_of!(Classification, policy) == 20);
    assert!(core::mem::offset_of!(Classification, code) == 24);
    assert!(core::mem::offset_of!(Classification, length) == 28);
    assert!(core::mem::offset_of!(Classification, flow) == 32);
    assert!(core::mem::offset_of!(Classification, family) == 36);
};

fn prefixes(instruction: &Instruction, bytes: &[u8]) -> bool {
    let mut operand = false;
    let mut address = false;
    let mut segment = false;
    let mut mandatory = false;
    let mut rex = None;
    for &byte in bytes {
        match byte {
            0x66 if !operand && rex.is_none() => operand = true,
            0x67 if !address && rex.is_none() => address = true,
            0x64 | 0x65 if !segment && rex.is_none() => segment = true,
            // These exact SIMD codes use F3 as an opcode selector, not REP.
            0xf3 if !mandatory && rex.is_none() && matches!(instruction.code(),
                Code::Movdqu_xmm_xmmm128 | Code::Movdqu_xmmm128_xmm) => mandatory = true,
            0x40..=0x4f if rex.is_none() => rex = Some(byte),
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 |
            0xf0 | 0xf2 | 0xf3 | 0x40..=0x4f => return false,
            _ => break,
        }
    }
    // Avoid an ignored 66+REX.W combination in this first explicit profile.
    if operand && rex.is_some_and(|value| value & 8 != 0) { return false; }
    if (segment || address) && !(0..instruction.op_count())
        .any(|i| instruction.op_kind(i) == OpKind::Memory) { return false; }
    true
}

pub(crate) fn one(pc: u64, source: &[u8]) -> Result<Classification, u32> {
    let decoded = crate::decode::one(pc, source)?;
    let mut out = Classification { pc, next_pc: decoded.next_pc,
        abi_version: 1, code: decoded.code, length: decoded.length, ..Classification::default() };
    if decoded.decode_status != abi::VALID || decoded.kind != abi::NONE { return Ok(out); }
    let mut decoder = Decoder::with_ip(64, source, pc, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if !prefixes(&instruction, &source[..instruction.len()]) { return Ok(out); }
    // Exact Code enumeration, never a catch-all mnemonic/valid-decode permit.
    let (flow, family) = match instruction.code() {
        Code::Nopw | Code::Nopd | Code::Nopq
        | Code::Nop_rm16 | Code::Nop_rm32 | Code::Nop_rm64
        | Code::Mov_rm8_r8 | Code::Mov_rm16_r16 | Code::Mov_rm32_r32
        | Code::Mov_rm64_r64 | Code::Mov_r8_rm8 | Code::Mov_r16_rm16
        | Code::Mov_r32_rm32 | Code::Mov_r64_rm64 | Code::Mov_AL_moffs8
        | Code::Mov_AX_moffs16 | Code::Mov_EAX_moffs32 | Code::Mov_RAX_moffs64
        | Code::Mov_moffs8_AL | Code::Mov_moffs16_AX | Code::Mov_moffs32_EAX
        | Code::Mov_moffs64_RAX | Code::Mov_r8_imm8 | Code::Mov_r16_imm16
        | Code::Mov_r32_imm32 | Code::Mov_r64_imm64 | Code::Mov_rm8_imm8
        | Code::Mov_rm16_imm16 | Code::Mov_rm32_imm32 | Code::Mov_rm64_imm32
        | Code::Movzx_r16_rm8 | Code::Movzx_r32_rm8 | Code::Movzx_r64_rm8
        | Code::Movzx_r32_rm16 | Code::Movzx_r64_rm16 | Code::Movsx_r16_rm8
        | Code::Movsx_r32_rm8 | Code::Movsx_r64_rm8 | Code::Movsx_r32_rm16
        | Code::Movsx_r64_rm16 | Code::Movsxd_r64_rm32 | Code::Lea_r16_m
        | Code::Lea_r32_m | Code::Lea_r64_m | Code::Clc
        | Code::Stc | Code::Cmc | Code::Cld
        | Code::Std | Code::Add_rm8_r8 | Code::Add_rm16_r16
        | Code::Add_rm32_r32 | Code::Add_rm64_r64 | Code::Add_r8_rm8
        | Code::Add_r16_rm16 | Code::Add_r32_rm32 | Code::Add_r64_rm64
        | Code::Add_AL_imm8 | Code::Add_AX_imm16 | Code::Add_EAX_imm32
        | Code::Add_RAX_imm32 | Code::Add_rm8_imm8 | Code::Add_rm16_imm16
        | Code::Add_rm32_imm32 | Code::Add_rm64_imm32 | Code::Add_rm16_imm8
        | Code::Add_rm32_imm8 | Code::Add_rm64_imm8 | Code::Adc_rm8_r8
        | Code::Adc_rm16_r16 | Code::Adc_rm32_r32 | Code::Adc_rm64_r64
        | Code::Adc_r8_rm8 | Code::Adc_r16_rm16 | Code::Adc_r32_rm32
        | Code::Adc_r64_rm64 | Code::Adc_AL_imm8 | Code::Adc_AX_imm16
        | Code::Adc_EAX_imm32 | Code::Adc_RAX_imm32 | Code::Adc_rm8_imm8
        | Code::Adc_rm16_imm16 | Code::Adc_rm32_imm32 | Code::Adc_rm64_imm32
        | Code::Adc_rm16_imm8 | Code::Adc_rm32_imm8 | Code::Adc_rm64_imm8
        | Code::Sub_rm8_r8 | Code::Sub_rm16_r16 | Code::Sub_rm32_r32
        | Code::Sub_rm64_r64 | Code::Sub_r8_rm8 | Code::Sub_r16_rm16
        | Code::Sub_r32_rm32 | Code::Sub_r64_rm64 | Code::Sub_AL_imm8
        | Code::Sub_AX_imm16 | Code::Sub_EAX_imm32 | Code::Sub_RAX_imm32
        | Code::Sub_rm8_imm8 | Code::Sub_rm16_imm16 | Code::Sub_rm32_imm32
        | Code::Sub_rm64_imm32 | Code::Sub_rm16_imm8 | Code::Sub_rm32_imm8
        | Code::Sub_rm64_imm8 | Code::Sbb_rm8_r8 | Code::Sbb_rm16_r16
        | Code::Sbb_rm32_r32 | Code::Sbb_rm64_r64 | Code::Sbb_r8_rm8
        | Code::Sbb_r16_rm16 | Code::Sbb_r32_rm32 | Code::Sbb_r64_rm64
        | Code::Sbb_AL_imm8 | Code::Sbb_AX_imm16 | Code::Sbb_EAX_imm32
        | Code::Sbb_RAX_imm32 | Code::Sbb_rm8_imm8 | Code::Sbb_rm16_imm16
        | Code::Sbb_rm32_imm32 | Code::Sbb_rm64_imm32 | Code::Sbb_rm16_imm8
        | Code::Sbb_rm32_imm8 | Code::Sbb_rm64_imm8 | Code::And_rm8_r8
        | Code::And_rm16_r16 | Code::And_rm32_r32 | Code::And_rm64_r64
        | Code::And_r8_rm8 | Code::And_r16_rm16 | Code::And_r32_rm32
        | Code::And_r64_rm64 | Code::And_AL_imm8 | Code::And_AX_imm16
        | Code::And_EAX_imm32 | Code::And_RAX_imm32 | Code::And_rm8_imm8
        | Code::And_rm16_imm16 | Code::And_rm32_imm32 | Code::And_rm64_imm32
        | Code::And_rm16_imm8 | Code::And_rm32_imm8 | Code::And_rm64_imm8
        | Code::Or_rm8_r8 | Code::Or_rm16_r16 | Code::Or_rm32_r32
        | Code::Or_rm64_r64 | Code::Or_r8_rm8 | Code::Or_r16_rm16
        | Code::Or_r32_rm32 | Code::Or_r64_rm64 | Code::Or_AL_imm8
        | Code::Or_AX_imm16 | Code::Or_EAX_imm32 | Code::Or_RAX_imm32
        | Code::Or_rm8_imm8 | Code::Or_rm16_imm16 | Code::Or_rm32_imm32
        | Code::Or_rm64_imm32 | Code::Or_rm16_imm8 | Code::Or_rm32_imm8
        | Code::Or_rm64_imm8 | Code::Xor_rm8_r8 | Code::Xor_rm16_r16
        | Code::Xor_rm32_r32 | Code::Xor_rm64_r64 | Code::Xor_r8_rm8
        | Code::Xor_r16_rm16 | Code::Xor_r32_rm32 | Code::Xor_r64_rm64
        | Code::Xor_AL_imm8 | Code::Xor_AX_imm16 | Code::Xor_EAX_imm32
        | Code::Xor_RAX_imm32 | Code::Xor_rm8_imm8 | Code::Xor_rm16_imm16
        | Code::Xor_rm32_imm32 | Code::Xor_rm64_imm32 | Code::Xor_rm16_imm8
        | Code::Xor_rm32_imm8 | Code::Xor_rm64_imm8 | Code::Cmp_rm8_r8
        | Code::Cmp_rm16_r16 | Code::Cmp_rm32_r32 | Code::Cmp_rm64_r64
        | Code::Cmp_r8_rm8 | Code::Cmp_r16_rm16 | Code::Cmp_r32_rm32
        | Code::Cmp_r64_rm64 | Code::Cmp_AL_imm8 | Code::Cmp_AX_imm16
        | Code::Cmp_EAX_imm32 | Code::Cmp_RAX_imm32 | Code::Cmp_rm8_imm8
        | Code::Cmp_rm16_imm16 | Code::Cmp_rm32_imm32 | Code::Cmp_rm64_imm32
        | Code::Cmp_rm16_imm8 | Code::Cmp_rm32_imm8 | Code::Cmp_rm64_imm8
        | Code::Test_rm8_r8 | Code::Test_rm16_r16 | Code::Test_rm32_r32
        | Code::Test_rm64_r64 | Code::Test_AL_imm8 | Code::Test_AX_imm16
        | Code::Test_EAX_imm32 | Code::Test_RAX_imm32 | Code::Test_rm8_imm8
        | Code::Test_rm16_imm16 | Code::Test_rm32_imm32 | Code::Test_rm64_imm32
        | Code::Inc_rm8 | Code::Inc_rm16 | Code::Inc_rm32
        | Code::Inc_rm64 | Code::Dec_rm8 | Code::Dec_rm16
        | Code::Dec_rm32 | Code::Dec_rm64 | Code::Neg_rm8
        | Code::Neg_rm16 | Code::Neg_rm32 | Code::Neg_rm64
        | Code::Not_rm8 | Code::Not_rm16 | Code::Not_rm32
        | Code::Not_rm64 => (1, 1),
        Code::Push_r64 | Code::Push_rm64 | Code::Pushq_imm32
        | Code::Pushq_imm8 | Code::Pop_r64 | Code::Pop_rm64
        | Code::Leaveq => (1, 2),
        Code::Jmp_rel8_64 | Code::Jmp_rel32_64 | Code::Jmp_rm64
        | Code::Jrcxz_rel8_64 | Code::Loop_rel8_64_RCX | Code::Loope_rel8_64_RCX
        | Code::Loopne_rel8_64_RCX | Code::Jo_rel8_64 | Code::Jo_rel32_64
        | Code::Jno_rel8_64 | Code::Jno_rel32_64 | Code::Jb_rel8_64
        | Code::Jb_rel32_64 | Code::Jae_rel8_64 | Code::Jae_rel32_64
        | Code::Je_rel8_64 | Code::Je_rel32_64 | Code::Jne_rel8_64
        | Code::Jne_rel32_64 | Code::Jbe_rel8_64 | Code::Jbe_rel32_64
        | Code::Ja_rel8_64 | Code::Ja_rel32_64 | Code::Js_rel8_64
        | Code::Js_rel32_64 | Code::Jns_rel8_64 | Code::Jns_rel32_64
        | Code::Jp_rel8_64 | Code::Jp_rel32_64 | Code::Jnp_rel8_64
        | Code::Jnp_rel32_64 | Code::Jl_rel8_64 | Code::Jl_rel32_64
        | Code::Jge_rel8_64 | Code::Jge_rel32_64 | Code::Jle_rel8_64
        | Code::Jle_rel32_64 | Code::Jg_rel8_64 | Code::Jg_rel32_64 => (2, 3),
        Code::Call_rel32_64 | Code::Call_rm64 => (2, 4),
        Code::Retnq | Code::Retnq_imm16 => (2, 5),
        Code::Movups_xmm_xmmm128 | Code::Movups_xmmm128_xmm | Code::Movaps_xmm_xmmm128
        | Code::Movaps_xmmm128_xmm | Code::Movdqa_xmm_xmmm128 | Code::Movdqa_xmmm128_xmm
        | Code::Movdqu_xmm_xmmm128 | Code::Movdqu_xmmm128_xmm | Code::Pxor_xmm_xmmm128
        | Code::Xorps_xmm_xmmm128 | Code::Xorpd_xmm_xmmm128 | Code::Pand_xmm_xmmm128
        | Code::Pandn_xmm_xmmm128 | Code::Por_xmm_xmmm128 | Code::Paddb_xmm_xmmm128
        | Code::Paddw_xmm_xmmm128 | Code::Paddd_xmm_xmmm128 | Code::Paddq_xmm_xmmm128
        | Code::Psubb_xmm_xmmm128 | Code::Psubw_xmm_xmmm128 | Code::Psubd_xmm_xmmm128
        | Code::Psubq_xmm_xmmm128 => (1, 6),
        _ => return Ok(out),
    };
    out.policy = 1;
    out.flow = flow;
    out.family = family;
    Ok(out)
}
