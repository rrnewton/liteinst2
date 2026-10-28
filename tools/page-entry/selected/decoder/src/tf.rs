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

// Exact padding palette only. In particular, the CS-prefixed ten-byte form
// does not authorize segment overrides or repeated prefixes on other bytes.
fn canonical_padding_nop(instruction: &Instruction, bytes: &[u8]) -> bool {
    matches!((instruction.code(), bytes),
        (Code::Nopd, [0x90]) |
        (Code::Nopw, [0x66, 0x90]) |
        (Code::Nop_rm32, [0x0f, 0x1f, 0x00]) |
        (Code::Nop_rm32, [0x0f, 0x1f, 0x40, 0x00]) |
        (Code::Nop_rm32, [0x0f, 0x1f, 0x44, 0x00, 0x00]) |
        (Code::Nop_rm16, [0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00]) |
        (Code::Nop_rm32, [0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00]) |
        (Code::Nop_rm32, [0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]) |
        (Code::Nop_rm16, [0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]) |
        (Code::Nop_rm16, [0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]) |
        (Code::Nop_rm16, [0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]))
}

// Exact original-PC BND indirect JMP only. Actual XCR0 MPX-disabled state
// is observed again on the authenticated NX frame before source pages open.
fn canonical_bnd_jmp_rip(instruction: &Instruction, bytes: &[u8]) -> bool {
    instruction.code() == Code::Jmp_rm64
        && matches!(bytes, [0xf2, 0xff, 0x25, _, _, _, _])
}

// Exact near-register NOTRACK forms in the existing no-user-CET profile.
// RSP-source and memory forms remain outside this first native cohort. No
// ignored REX bits, other prefixes, far transfers or operand-size override.
fn canonical_notrack_register(instruction: &Instruction, bytes: &[u8]) -> bool {
    let modrm = match bytes {
        [0x3e, 0xff, byte] if (*byte & 7) != 4 => *byte,
        [0x3e, 0x41, 0xff, byte] => *byte,
        _ => return false,
    };
    matches!((instruction.code(), modrm & 0xf8),
        (Code::Call_rm64, 0xd0) | (Code::Jmp_rm64, 0xe0))
}

// Exactly the nine legacy REX.W MOVQ encodings qualified by the finite
// full-state cohort. This does not relax the general 66+REX.W prefix rule.
fn canonical_movq_integer(instruction: &Instruction, bytes: &[u8]) -> bool {
    matches!((instruction.code(), bytes),
        (Code::Movq_xmm_rm64, [0x66, 0x48 | 0x4d, 0x0f, 0x6e, 0xce | 0x0f]) |
        (Code::Movq_rm64_xmm, [0x66, 0x48 | 0x4d, 0x0f, 0x7e, 0xce | 0x0f]) |
        (Code::Movq_rm64_xmm, [0x66, 0x48, 0x0f, 0x7e, 0xc6]))
}

// Only this original-PC, memory-destination LOCK ADD encoding. The CPU
// performs the atomic RMW; this exception neither emulates it nor authorizes
// other LOCK/HLE prefixes, address sizes, operand sizes or ModRM forms.
fn canonical_lock_add_rip(instruction: &Instruction, bytes: &[u8]) -> bool {
    instruction.code() == Code::Add_rm32_imm8
        && matches!(bytes, [0xf0, 0x83, 0x05, _, _, _, _, _])
}

// Paired canonical memory SUB only; no general LOCK/prefix permission.
// The CPU performs the atomic RMW at the original RIP-relative address.
fn canonical_lock_sub_rip(instruction: &Instruction, bytes: &[u8]) -> bool {
    instruction.code() == Code::Sub_rm32_imm8
        && matches!(bytes, [0xf0, 0x83, 0x2d, _, _, _, _, _])
}

// Five exact legacy SSE4.1 PMAXUD forms qualified by the finite oracle.
// No ignored REX bits, other address modes, prefix aliases or VEX/EVEX.
// Memory alignment/faults remain CPU effects at the original source PC.
fn canonical_pmaxud(instruction: &Instruction, bytes: &[u8]) -> bool {
    instruction.code() == Code::Pmaxud_xmm_xmmm128
        && matches!(bytes,
            [0x66, 0x0f, 0x38, 0x3f, 0xc1 | 0xff | 0x06] |
            [0x66, 0x45, 0x0f, 0x38, 0x3f, 0xe1] |
            [0x66, 0x44, 0x0f, 0x38, 0x3f, 0x26])
}

pub(crate) fn one(pc: u64, source: &[u8]) -> Result<Classification, u32> {
    let decoded = crate::decode::one(pc, source)?;
    let mut out = Classification { pc, next_pc: decoded.next_pc,
        abi_version: 1, code: decoded.code, length: decoded.length, ..Classification::default() };
    if decoded.decode_status != abi::VALID || decoded.kind != abi::NONE { return Ok(out); }
    let mut decoder = Decoder::with_ip(64, source, pc, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.code() == Code::Endbr64 {
        // Existing no-CET profile only: one canonical instruction, no added
        // or ignored prefix. Other Code values retain the old prefix policy.
        if source[..instruction.len()] != [0xf3, 0x0f, 0x1e, 0xfa] { return Ok(out); }
    } else if instruction.code() == Code::Rdsspq_r64 {
        // Only canonical r64 encodings. Actual disabled-shadow-stack custody
        // is checked on the genuine NX frame before either source page opens.
        if !matches!(&source[..instruction.len()],
            [0xf3, 0x48 | 0x49, 0x0f, 0x1e, m] if (*m & 0xf8) == 0xc8) { return Ok(out); }
    } else if matches!(instruction.code(), Code::Movq_xmm_rm64 | Code::Movq_rm64_xmm) {
        if !canonical_movq_integer(&instruction, &source[..instruction.len()]) { return Ok(out); }
    } else if instruction.code() == Code::EVEX_Vpbroadcastb_zmm_k1z_r32 {
        // Only the observed unmasked EVEX.512 register form, ZMM16 <- RSI[7:0].
        // This exact gate grants no other EVEX, masking, width or register form.
        if source[..instruction.len()] != [0x62, 0xe2, 0x7d, 0x48, 0x7a, 0xc6] { return Ok(out); }
    } else if instruction.code() == Code::EVEX_Vmovdqu64_zmm_k1z_zmmm512 {
        // Exact observed unmasked EVEX.512 load, ZMM17 <- 64 bytes at [RDI].
        // No other EVEX, mask, width, register, address or added prefix is granted.
        if source[..instruction.len()] != [0x62, 0xe1, 0xfe, 0x48, 0x6f, 0x0f] { return Ok(out); }
    } else if instruction.code() == Code::Pmaxud_xmm_xmmm128 {
        if !canonical_pmaxud(&instruction, &source[..instruction.len()]) { return Ok(out); }
    } else if instruction.code() == Code::Xgetbv {
        // The actual ECX=0 restriction is enforced on the genuine NX frame
        // before either instruction page opens; decoding grants no RX permit.
        if source[..instruction.len()] != [0x0f, 0x01, 0xd0] { return Ok(out); }
    } else if !canonical_padding_nop(&instruction, &source[..instruction.len()])
        && !canonical_notrack_register(&instruction, &source[..instruction.len()])
        && !canonical_bnd_jmp_rip(&instruction, &source[..instruction.len()])
        && !canonical_lock_add_rip(&instruction, &source[..instruction.len()])
        && !canonical_lock_sub_rip(&instruction, &source[..instruction.len()])
        && !prefixes(&instruction, &source[..instruction.len()]) { return Ok(out); }
    // Exact Code enumeration, never a catch-all mnemonic/valid-decode permit.
    let (flow, family) = match instruction.code() {
        Code::Rdsspq_r64 | Code::Xgetbv | Code::Endbr64 | Code::Nopw | Code::Nopd | Code::Nopq
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
        | Code::Not_rm64
        // Shl — exact iced-x86 1.21.0 Code alternatives.
        | Code::Shl_rm8_imm8 | Code::Shl_rm16_imm8 | Code::Shl_rm32_imm8
        | Code::Shl_rm64_imm8 | Code::Shl_rm8_1 | Code::Shl_rm16_1
        | Code::Shl_rm32_1 | Code::Shl_rm64_1 | Code::Shl_rm8_CL
        | Code::Shl_rm16_CL | Code::Shl_rm32_CL | Code::Shl_rm64_CL
        // Shr — exact iced-x86 1.21.0 Code alternatives.
        | Code::Shr_rm8_imm8 | Code::Shr_rm16_imm8 | Code::Shr_rm32_imm8
        | Code::Shr_rm64_imm8 | Code::Shr_rm8_1 | Code::Shr_rm16_1
        | Code::Shr_rm32_1 | Code::Shr_rm64_1 | Code::Shr_rm8_CL
        | Code::Shr_rm16_CL | Code::Shr_rm32_CL | Code::Shr_rm64_CL
        // Sar — exact iced-x86 1.21.0 Code alternatives.
        | Code::Sar_rm8_imm8 | Code::Sar_rm16_imm8 | Code::Sar_rm32_imm8
        | Code::Sar_rm64_imm8 | Code::Sar_rm8_1 | Code::Sar_rm16_1
        | Code::Sar_rm32_1 | Code::Sar_rm64_1 | Code::Sar_rm8_CL
        | Code::Sar_rm16_CL | Code::Sar_rm32_CL | Code::Sar_rm64_CL
        // Rol — exact iced-x86 1.21.0 Code alternatives.
        | Code::Rol_rm8_imm8 | Code::Rol_rm16_imm8 | Code::Rol_rm32_imm8
        | Code::Rol_rm64_imm8 | Code::Rol_rm8_1 | Code::Rol_rm16_1
        | Code::Rol_rm32_1 | Code::Rol_rm64_1 | Code::Rol_rm8_CL
        | Code::Rol_rm16_CL | Code::Rol_rm32_CL | Code::Rol_rm64_CL
        // Ror — exact iced-x86 1.21.0 Code alternatives.
        | Code::Ror_rm8_imm8 | Code::Ror_rm16_imm8 | Code::Ror_rm32_imm8
        | Code::Ror_rm64_imm8 | Code::Ror_rm8_1 | Code::Ror_rm16_1
        | Code::Ror_rm32_1 | Code::Ror_rm64_1 | Code::Ror_rm8_CL
        | Code::Ror_rm16_CL | Code::Ror_rm32_CL | Code::Ror_rm64_CL
        // Rcl — exact iced-x86 1.21.0 Code alternatives.
        | Code::Rcl_rm8_imm8 | Code::Rcl_rm16_imm8 | Code::Rcl_rm32_imm8
        | Code::Rcl_rm64_imm8 | Code::Rcl_rm8_1 | Code::Rcl_rm16_1
        | Code::Rcl_rm32_1 | Code::Rcl_rm64_1 | Code::Rcl_rm8_CL
        | Code::Rcl_rm16_CL | Code::Rcl_rm32_CL | Code::Rcl_rm64_CL
        // Rcr — exact iced-x86 1.21.0 Code alternatives.
        | Code::Rcr_rm8_imm8 | Code::Rcr_rm16_imm8 | Code::Rcr_rm32_imm8
        | Code::Rcr_rm64_imm8 | Code::Rcr_rm8_1 | Code::Rcr_rm16_1
        | Code::Rcr_rm32_1 | Code::Rcr_rm64_1 | Code::Rcr_rm8_CL
        | Code::Rcr_rm16_CL | Code::Rcr_rm32_CL | Code::Rcr_rm64_CL
        // Shld — exact iced-x86 1.21.0 Code alternatives.
        | Code::Shld_rm16_r16_imm8 | Code::Shld_rm32_r32_imm8 | Code::Shld_rm64_r64_imm8
        | Code::Shld_rm16_r16_CL | Code::Shld_rm32_r32_CL | Code::Shld_rm64_r64_CL
        // Shrd — exact iced-x86 1.21.0 Code alternatives.
        | Code::Shrd_rm16_r16_imm8 | Code::Shrd_rm32_r32_imm8 | Code::Shrd_rm64_r64_imm8
        | Code::Shrd_rm16_r16_CL | Code::Shrd_rm32_r32_CL | Code::Shrd_rm64_r64_CL
        // Mul — exact iced-x86 1.21.0 Code alternatives.
        | Code::Mul_rm8 | Code::Mul_rm16 | Code::Mul_rm32
        | Code::Mul_rm64
        // Imul — exact iced-x86 1.21.0 Code alternatives.
        | Code::Imul_r16_rm16_imm16 | Code::Imul_r32_rm32_imm32 | Code::Imul_r64_rm64_imm32
        | Code::Imul_r16_rm16_imm8 | Code::Imul_r32_rm32_imm8 | Code::Imul_r64_rm64_imm8
        | Code::Imul_rm8 | Code::Imul_rm16 | Code::Imul_rm32
        | Code::Imul_rm64 | Code::Imul_r16_rm16 | Code::Imul_r32_rm32
        | Code::Imul_r64_rm64
        // Div — exact iced-x86 1.21.0 Code alternatives.
        | Code::Div_rm8 | Code::Div_rm16 | Code::Div_rm32
        | Code::Div_rm64
        // Idiv — exact iced-x86 1.21.0 Code alternatives.
        | Code::Idiv_rm8 | Code::Idiv_rm16 | Code::Idiv_rm32
        | Code::Idiv_rm64
        // Cbw — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cbw
        // Cwde — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cwde
        // Cdqe — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cdqe
        // Cwd — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cwd
        // Cdq — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cdq
        // Cqo — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cqo
        // Cmovo — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovo_r16_rm16 | Code::Cmovo_r32_rm32 | Code::Cmovo_r64_rm64
        // Cmovno — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovno_r16_rm16 | Code::Cmovno_r32_rm32 | Code::Cmovno_r64_rm64
        // Cmovb — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovb_r16_rm16 | Code::Cmovb_r32_rm32 | Code::Cmovb_r64_rm64
        // Cmovae — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovae_r16_rm16 | Code::Cmovae_r32_rm32 | Code::Cmovae_r64_rm64
        // Cmove — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmove_r16_rm16 | Code::Cmove_r32_rm32 | Code::Cmove_r64_rm64
        // Cmovne — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovne_r16_rm16 | Code::Cmovne_r32_rm32 | Code::Cmovne_r64_rm64
        // Cmovbe — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovbe_r16_rm16 | Code::Cmovbe_r32_rm32 | Code::Cmovbe_r64_rm64
        // Cmova — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmova_r16_rm16 | Code::Cmova_r32_rm32 | Code::Cmova_r64_rm64
        // Cmovs — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovs_r16_rm16 | Code::Cmovs_r32_rm32 | Code::Cmovs_r64_rm64
        // Cmovns — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovns_r16_rm16 | Code::Cmovns_r32_rm32 | Code::Cmovns_r64_rm64
        // Cmovp — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovp_r16_rm16 | Code::Cmovp_r32_rm32 | Code::Cmovp_r64_rm64
        // Cmovnp — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovnp_r16_rm16 | Code::Cmovnp_r32_rm32 | Code::Cmovnp_r64_rm64
        // Cmovl — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovl_r16_rm16 | Code::Cmovl_r32_rm32 | Code::Cmovl_r64_rm64
        // Cmovge — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovge_r16_rm16 | Code::Cmovge_r32_rm32 | Code::Cmovge_r64_rm64
        // Cmovle — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovle_r16_rm16 | Code::Cmovle_r32_rm32 | Code::Cmovle_r64_rm64
        // Cmovg — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmovg_r16_rm16 | Code::Cmovg_r32_rm32 | Code::Cmovg_r64_rm64
        // Seto — exact iced-x86 1.21.0 Code alternatives.
        | Code::Seto_rm8
        // Setno — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setno_rm8
        // Setb — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setb_rm8
        // Setae — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setae_rm8
        // Sete — exact iced-x86 1.21.0 Code alternatives.
        | Code::Sete_rm8
        // Setne — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setne_rm8
        // Setbe — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setbe_rm8
        // Seta — exact iced-x86 1.21.0 Code alternatives.
        | Code::Seta_rm8
        // Sets — exact iced-x86 1.21.0 Code alternatives.
        | Code::Sets_rm8
        // Setns — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setns_rm8
        // Setp — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setp_rm8
        // Setnp — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setnp_rm8
        // Setl — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setl_rm8
        // Setge — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setge_rm8
        // Setle — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setle_rm8
        // Setg — exact iced-x86 1.21.0 Code alternatives.
        | Code::Setg_rm8
        // BSF/BSR — exact scalar forms. CPU supplies all actual flags and
        // destination state, including zero-source architecture variations.
        | Code::Bsf_r16_rm16 | Code::Bsf_r32_rm32 | Code::Bsf_r64_rm64
        | Code::Bsr_r16_rm16 | Code::Bsr_r32_rm32 | Code::Bsr_r64_rm64
        // Bswap — exact iced-x86 1.21.0 Code alternatives.
        | Code::Bswap_r32 | Code::Bswap_r64
        // Bt — exact iced-x86 1.21.0 Code alternatives.
        | Code::Bt_rm16_r16 | Code::Bt_rm32_r32 | Code::Bt_rm64_r64
        | Code::Bt_rm16_imm8 | Code::Bt_rm32_imm8 | Code::Bt_rm64_imm8
        // Bts — exact iced-x86 1.21.0 Code alternatives.
        | Code::Bts_rm16_r16 | Code::Bts_rm32_r32 | Code::Bts_rm64_r64
        | Code::Bts_rm16_imm8 | Code::Bts_rm32_imm8 | Code::Bts_rm64_imm8
        // Btr — exact iced-x86 1.21.0 Code alternatives.
        | Code::Btr_rm16_r16 | Code::Btr_rm32_r32 | Code::Btr_rm64_r64
        | Code::Btr_rm16_imm8 | Code::Btr_rm32_imm8 | Code::Btr_rm64_imm8
        // Btc — exact iced-x86 1.21.0 Code alternatives.
        | Code::Btc_rm16_imm8 | Code::Btc_rm32_imm8 | Code::Btc_rm64_imm8
        | Code::Btc_rm16_r16 | Code::Btc_rm32_r32 | Code::Btc_rm64_r64
        // Xchg — exact iced-x86 1.21.0 Code alternatives.
        | Code::Xchg_rm8_r8 | Code::Xchg_rm16_r16 | Code::Xchg_rm32_r32
        | Code::Xchg_rm64_r64 | Code::Xchg_r16_AX | Code::Xchg_r32_EAX
        | Code::Xchg_r64_RAX
        // Xadd — exact iced-x86 1.21.0 Code alternatives.
        | Code::Xadd_rm8_r8 | Code::Xadd_rm16_r16 | Code::Xadd_rm32_r32
        | Code::Xadd_rm64_r64
        // Cmpxchg — exact iced-x86 1.21.0 Code alternatives.
        | Code::Cmpxchg_rm8_r8 | Code::Cmpxchg_rm16_r16 | Code::Cmpxchg_rm32_r32
        | Code::Cmpxchg_rm64_r64 => (1, 1),
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
        | Code::Psubq_xmm_xmmm128
        // Legacy SSE2 only; unchanged prefix policy excludes 66+REX.W.
        | Code::Pcmpeqb_xmm_xmmm128 | Code::Pcmpeqw_xmm_xmmm128 | Code::Pcmpeqd_xmm_xmmm128
        | Code::Pcmpgtb_xmm_xmmm128 | Code::Pcmpgtw_xmm_xmmm128 | Code::Pcmpgtd_xmm_xmmm128
        | Code::Pminub_xmm_xmmm128 | Code::Pmaxub_xmm_xmmm128
        // Exact SSE4.1 PMAXUD palette is checked before this Code arm.
        | Code::Pmaxud_xmm_xmmm128
        // Exact unmasked EVEX512 broadcast, checked before this Code arm.
        | Code::EVEX_Vpbroadcastb_zmm_k1z_r32
        | Code::EVEX_Vmovdqu64_zmm_k1z_zmmm512
        | Code::Pmovmskb_r32_xmm
        // Legacy m64 half moves only. Other XMM lanes and upper vectors survive.
        | Code::Movlpd_xmm_m64 | Code::Movlpd_m64_xmm
        | Code::Movhpd_xmm_m64 | Code::Movhpd_m64_xmm
        // Legacy byte-count shifts of one XMM register; upper vectors survive.
        | Code::Pslldq_xmm_imm8 | Code::Psrldq_xmm_imm8
        // Legacy MOVD r/m32 only; load clears XMM[127:32], r32 stores zero-extend.
        | Code::Movd_xmm_rm32 | Code::Movd_rm32_xmm
        // Legacy low-lane unpack/shuffle only; upper vectors and flags survive.
        | Code::Punpcklbw_xmm_xmmm128 | Code::Punpcklwd_xmm_xmmm128
        | Code::Pshufd_xmm_xmmm128_imm8
        // REX.W MOVQ uses only the independently guarded canonical palette.
        | Code::Movq_xmm_rm64 | Code::Movq_rm64_xmm => (1, 6),
        _ => return Ok(out),
    };
    out.policy = 1;
    out.flow = flow;
    out.family = family;
    Ok(out)
}
