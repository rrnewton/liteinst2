//! Positive encoding inventory. A new mnemonic or encoding is unsupported
//! until its native obligations and controls are reviewed; no wildcard accepts.
use super::OrdinaryFamily;
use iced_x86::Code;

pub(super) fn classify(code: Code) -> Option<OrdinaryFamily> {
    match code {
        Code::Mov_rm8_r8
        | Code::Mov_rm16_r16
        | Code::Mov_rm32_r32
        | Code::Mov_rm64_r64
        | Code::Mov_r8_rm8
        | Code::Mov_r16_rm16
        | Code::Mov_r32_rm32
        | Code::Mov_r64_rm64
        | Code::Mov_r8_imm8
        | Code::Mov_r16_imm16
        | Code::Mov_r32_imm32
        | Code::Mov_r64_imm64
        | Code::Mov_rm8_imm8
        | Code::Mov_rm16_imm16
        | Code::Mov_rm32_imm32
        | Code::Mov_rm64_imm32
        | Code::Mov_AL_moffs8
        | Code::Mov_AX_moffs16
        | Code::Mov_EAX_moffs32
        | Code::Mov_RAX_moffs64
        | Code::Mov_moffs8_AL
        | Code::Mov_moffs16_AX
        | Code::Mov_moffs32_EAX
        | Code::Mov_moffs64_RAX => Some(OrdinaryFamily::Move),
        Code::Lea_r16_m | Code::Lea_r32_m | Code::Lea_r64_m => Some(OrdinaryFamily::Address),
        Code::Add_rm8_r8
        | Code::Add_rm16_r16
        | Code::Add_rm32_r32
        | Code::Add_rm64_r64
        | Code::Add_r8_rm8
        | Code::Add_r16_rm16
        | Code::Add_r32_rm32
        | Code::Add_r64_rm64
        | Code::Add_AL_imm8
        | Code::Add_AX_imm16
        | Code::Add_EAX_imm32
        | Code::Add_RAX_imm32
        | Code::Add_rm8_imm8
        | Code::Add_rm16_imm16
        | Code::Add_rm32_imm32
        | Code::Add_rm64_imm32
        | Code::Add_rm16_imm8
        | Code::Add_rm32_imm8
        | Code::Add_rm64_imm8
        | Code::Adc_rm8_r8
        | Code::Adc_rm16_r16
        | Code::Adc_rm32_r32
        | Code::Adc_rm64_r64
        | Code::Adc_r8_rm8
        | Code::Adc_r16_rm16
        | Code::Adc_r32_rm32
        | Code::Adc_r64_rm64
        | Code::Adc_AL_imm8
        | Code::Adc_AX_imm16
        | Code::Adc_EAX_imm32
        | Code::Adc_RAX_imm32
        | Code::Adc_rm8_imm8
        | Code::Adc_rm16_imm16
        | Code::Adc_rm32_imm32
        | Code::Adc_rm64_imm32
        | Code::Adc_rm16_imm8
        | Code::Adc_rm32_imm8
        | Code::Adc_rm64_imm8
        | Code::Sub_rm8_r8
        | Code::Sub_rm16_r16
        | Code::Sub_rm32_r32
        | Code::Sub_rm64_r64
        | Code::Sub_r8_rm8
        | Code::Sub_r16_rm16
        | Code::Sub_r32_rm32
        | Code::Sub_r64_rm64
        | Code::Sub_AL_imm8
        | Code::Sub_AX_imm16
        | Code::Sub_EAX_imm32
        | Code::Sub_RAX_imm32
        | Code::Sub_rm8_imm8
        | Code::Sub_rm16_imm16
        | Code::Sub_rm32_imm32
        | Code::Sub_rm64_imm32
        | Code::Sub_rm16_imm8
        | Code::Sub_rm32_imm8
        | Code::Sub_rm64_imm8
        | Code::Sbb_rm8_r8
        | Code::Sbb_rm16_r16
        | Code::Sbb_rm32_r32
        | Code::Sbb_rm64_r64
        | Code::Sbb_r8_rm8
        | Code::Sbb_r16_rm16
        | Code::Sbb_r32_rm32
        | Code::Sbb_r64_rm64
        | Code::Sbb_AL_imm8
        | Code::Sbb_AX_imm16
        | Code::Sbb_EAX_imm32
        | Code::Sbb_RAX_imm32
        | Code::Sbb_rm8_imm8
        | Code::Sbb_rm16_imm16
        | Code::Sbb_rm32_imm32
        | Code::Sbb_rm64_imm32
        | Code::Sbb_rm16_imm8
        | Code::Sbb_rm32_imm8
        | Code::Sbb_rm64_imm8
        | Code::And_rm8_r8
        | Code::And_rm16_r16
        | Code::And_rm32_r32
        | Code::And_rm64_r64
        | Code::And_r8_rm8
        | Code::And_r16_rm16
        | Code::And_r32_rm32
        | Code::And_r64_rm64
        | Code::And_AL_imm8
        | Code::And_AX_imm16
        | Code::And_EAX_imm32
        | Code::And_RAX_imm32
        | Code::And_rm8_imm8
        | Code::And_rm16_imm16
        | Code::And_rm32_imm32
        | Code::And_rm64_imm32
        | Code::And_rm16_imm8
        | Code::And_rm32_imm8
        | Code::And_rm64_imm8
        | Code::Or_rm8_r8
        | Code::Or_rm16_r16
        | Code::Or_rm32_r32
        | Code::Or_rm64_r64
        | Code::Or_r8_rm8
        | Code::Or_r16_rm16
        | Code::Or_r32_rm32
        | Code::Or_r64_rm64
        | Code::Or_AL_imm8
        | Code::Or_AX_imm16
        | Code::Or_EAX_imm32
        | Code::Or_RAX_imm32
        | Code::Or_rm8_imm8
        | Code::Or_rm16_imm16
        | Code::Or_rm32_imm32
        | Code::Or_rm64_imm32
        | Code::Or_rm16_imm8
        | Code::Or_rm32_imm8
        | Code::Or_rm64_imm8
        | Code::Xor_rm8_r8
        | Code::Xor_rm16_r16
        | Code::Xor_rm32_r32
        | Code::Xor_rm64_r64
        | Code::Xor_r8_rm8
        | Code::Xor_r16_rm16
        | Code::Xor_r32_rm32
        | Code::Xor_r64_rm64
        | Code::Xor_AL_imm8
        | Code::Xor_AX_imm16
        | Code::Xor_EAX_imm32
        | Code::Xor_RAX_imm32
        | Code::Xor_rm8_imm8
        | Code::Xor_rm16_imm16
        | Code::Xor_rm32_imm32
        | Code::Xor_rm64_imm32
        | Code::Xor_rm16_imm8
        | Code::Xor_rm32_imm8
        | Code::Xor_rm64_imm8 => Some(OrdinaryFamily::Arithmetic),
        Code::Cmp_rm8_r8
        | Code::Cmp_rm16_r16
        | Code::Cmp_rm32_r32
        | Code::Cmp_rm64_r64
        | Code::Cmp_r8_rm8
        | Code::Cmp_r16_rm16
        | Code::Cmp_r32_rm32
        | Code::Cmp_r64_rm64
        | Code::Cmp_AL_imm8
        | Code::Cmp_AX_imm16
        | Code::Cmp_EAX_imm32
        | Code::Cmp_RAX_imm32
        | Code::Cmp_rm8_imm8
        | Code::Cmp_rm16_imm16
        | Code::Cmp_rm32_imm32
        | Code::Cmp_rm64_imm32
        | Code::Cmp_rm16_imm8
        | Code::Cmp_rm32_imm8
        | Code::Cmp_rm64_imm8
        | Code::Test_rm8_r8
        | Code::Test_rm16_r16
        | Code::Test_rm32_r32
        | Code::Test_rm64_r64
        | Code::Test_AL_imm8
        | Code::Test_AX_imm16
        | Code::Test_EAX_imm32
        | Code::Test_RAX_imm32
        | Code::Test_rm8_imm8
        | Code::Test_rm16_imm16
        | Code::Test_rm32_imm32
        | Code::Test_rm64_imm32 => Some(OrdinaryFamily::Compare),
        Code::Push_r64 => Some(OrdinaryFamily::Push),
        Code::Pop_r64 => Some(OrdinaryFamily::Pop),
        Code::Nopw | Code::Nopd | Code::Nopq | Code::Nop_rm16 | Code::Nop_rm32 | Code::Nop_rm64 => {
            Some(OrdinaryFamily::Nop)
        }
        Code::Jo_rel8_64
        | Code::Jno_rel8_64
        | Code::Jb_rel8_64
        | Code::Jae_rel8_64
        | Code::Je_rel8_64
        | Code::Jne_rel8_64
        | Code::Jbe_rel8_64
        | Code::Ja_rel8_64
        | Code::Js_rel8_64
        | Code::Jns_rel8_64
        | Code::Jp_rel8_64
        | Code::Jnp_rel8_64
        | Code::Jl_rel8_64
        | Code::Jge_rel8_64
        | Code::Jle_rel8_64
        | Code::Jg_rel8_64
        | Code::Jo_rel32_64
        | Code::Jno_rel32_64
        | Code::Jb_rel32_64
        | Code::Jae_rel32_64
        | Code::Je_rel32_64
        | Code::Jne_rel32_64
        | Code::Jbe_rel32_64
        | Code::Ja_rel32_64
        | Code::Js_rel32_64
        | Code::Jns_rel32_64
        | Code::Jp_rel32_64
        | Code::Jnp_rel32_64
        | Code::Jl_rel32_64
        | Code::Jge_rel32_64
        | Code::Jle_rel32_64
        | Code::Jg_rel32_64 => Some(OrdinaryFamily::ConditionalBranch),
        Code::Jmp_rel8_64 | Code::Jmp_rel32_64 | Code::Jmp_rm64 => Some(OrdinaryFamily::Jump),
        Code::Call_rel32_64 | Code::Call_rm64 => Some(OrdinaryFamily::Call),
        Code::Retnq => Some(OrdinaryFamily::Return),
        _ => None,
    }
}

// Only the explicitly accepted native near relative forms have a displacement.
// The caller checks addition instead of accepting iced's wrapping destination.
pub(super) fn relative_width(code: Code) -> Option<usize> {
    match code {
        Code::Jmp_rel8_64
        | Code::Jo_rel8_64
        | Code::Jno_rel8_64
        | Code::Jb_rel8_64
        | Code::Jae_rel8_64
        | Code::Je_rel8_64
        | Code::Jne_rel8_64
        | Code::Jbe_rel8_64
        | Code::Ja_rel8_64
        | Code::Js_rel8_64
        | Code::Jns_rel8_64
        | Code::Jp_rel8_64
        | Code::Jnp_rel8_64
        | Code::Jl_rel8_64
        | Code::Jge_rel8_64
        | Code::Jle_rel8_64
        | Code::Jg_rel8_64 => Some(1),
        Code::Jmp_rel32_64
        | Code::Call_rel32_64
        | Code::Jo_rel32_64
        | Code::Jno_rel32_64
        | Code::Jb_rel32_64
        | Code::Jae_rel32_64
        | Code::Je_rel32_64
        | Code::Jne_rel32_64
        | Code::Jbe_rel32_64
        | Code::Ja_rel32_64
        | Code::Js_rel32_64
        | Code::Jns_rel32_64
        | Code::Jp_rel32_64
        | Code::Jnp_rel32_64
        | Code::Jl_rel32_64
        | Code::Jge_rel32_64
        | Code::Jle_rel32_64
        | Code::Jg_rel32_64 => Some(4),
        _ => None,
    }
}
