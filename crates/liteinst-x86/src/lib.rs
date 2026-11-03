//! Shared descriptive x86 facts, never instruction-head or execution authority.
//!
//! Walkers choose their own linear/all-start policy, bounds and error mapping.
//! Selected families do not grant CPU support, an emitter ABI, entry ownership,
//! mapping freshness or a complete control-flow graph.
//!
//! The default feature selects iced's `std` support. A freestanding consumer
//! disables defaults and must select iced's `no_std` support in its independent
//! dependency graph. This crate adds no allocator or decoder-table policy.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use iced_x86::{Code, Mnemonic, Register};
pub use iced_x86::{Decoder, DecoderError, DecoderOptions, Instruction};

/// Creates the ordinary 64-bit decoder without changing sequential traversal.
pub fn decoder64(bytes: &[u8], pc: u64) -> Decoder<'_> {
    Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE)
}

/// Raw result of one decode, including invalid/truncated instruction metadata.
#[derive(Clone, Copy, Debug)]
pub struct Decoded {
    /// The original iced instruction, including its length and wrapping IPs.
    pub instruction: Instruction,
    /// The decoder's original error; callers retain their own error policy.
    pub error: DecoderError,
}

/// Decodes one instruction without imposing a source-length or overflow policy.
///
/// Empty input, a truncated encoding and a wrapping next IP remain descriptive
/// results. Callers must preserve their own prechecks and refusal order.
pub fn decode64(pc: u64, bytes: &[u8]) -> Decoded {
    let mut decoder = decoder64(bytes, pc);
    let instruction = decoder.decode();
    Decoded {
        instruction,
        error: decoder.last_error(),
    }
}

/// Architectural family, independent of any consumer's selection policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedClass {
    /// CPUID.
    Cpuid,
    /// RDRAND.
    Rdrand,
    /// RDSEED.
    Rdseed,
    /// RDPID.
    Rdpid,
    /// RDTSC.
    Rdtsc,
    /// RDTSCP.
    Rdtscp,
    /// SYSCALL.
    Syscall,
    /// SYSENTER; a fact does not establish its calling convention.
    Sysenter,
    /// INT 80h; a fact does not establish its calling convention.
    Int80,
}

/// Classifies the existing exact selected Code forms, including syscall aliases.
///
/// RDPID's 32-bit-mode encoding is deliberately absent from this exact-form
/// view. This function does not validate a constructed Instruction's operands.
pub fn selected_code(instruction: &Instruction) -> Option<SelectedClass> {
    Some(match instruction.code() {
        Code::Cpuid => SelectedClass::Cpuid,
        Code::Rdrand_r16 | Code::Rdrand_r32 | Code::Rdrand_r64 => SelectedClass::Rdrand,
        Code::Rdseed_r16 | Code::Rdseed_r32 | Code::Rdseed_r64 => SelectedClass::Rdseed,
        Code::Rdpid_r64 => SelectedClass::Rdpid,
        Code::Rdtsc => SelectedClass::Rdtsc,
        Code::Rdtscp => SelectedClass::Rdtscp,
        Code::Syscall => SelectedClass::Syscall,
        Code::Sysenter => SelectedClass::Sysenter,
        Code::Int_imm8 if instruction.immediate8() == 0x80 => SelectedClass::Int80,
        _ => return None,
    })
}

/// Preserves the admission scanner's broader mnemonic-family classification.
///
/// This view is distinct from exact encoding support, even when both coincide
/// for a particular valid 64-bit decode. Neither view filters CPU capabilities.
pub fn selected_mnemonic(instruction: &Instruction) -> Option<SelectedClass> {
    Some(match instruction.mnemonic() {
        Mnemonic::Cpuid => SelectedClass::Cpuid,
        Mnemonic::Rdrand => SelectedClass::Rdrand,
        Mnemonic::Rdseed => SelectedClass::Rdseed,
        Mnemonic::Rdpid => SelectedClass::Rdpid,
        Mnemonic::Rdtsc => SelectedClass::Rdtsc,
        Mnemonic::Rdtscp => SelectedClass::Rdtscp,
        Mnemonic::Syscall => SelectedClass::Syscall,
        Mnemonic::Sysenter => SelectedClass::Sysenter,
        Mnemonic::Int if instruction.immediate8() == 0x80 => SelectedClass::Int80,
        _ => return None,
    })
}

/// The existing `j*` mnemonic population, not all control transfers.
///
/// This includes unusual/far jump forms without granting relocation support.
/// CALL, RET, LOOP and XBEGIN are not members of this descriptive family.
pub fn is_jump_mnemonic(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Jcxz
            | Mnemonic::Je
            | Mnemonic::Jecxz
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jmp
            | Mnemonic::Jmpe
            | Mnemonic::Jne
            | Mnemonic::Jno
            | Mnemonic::Jnp
            | Mnemonic::Jns
            | Mnemonic::Jo
            | Mnemonic::Jp
            | Mnemonic::Jrcxz
            | Mnemonic::Js
            | Mnemonic::Jknzd
            | Mnemonic::Jkzd
    )
}

/// Descriptive members of the jumps plus exact register-stack union.
/// This does not establish helper-stack safety or an instruction's admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JumpStackClass {
    /// Any member of the existing `j*` mnemonic population.
    Jump,
    /// Exactly `Code::Push_r64`, including RSP.
    PushRegister64,
    /// Exactly `Code::Pop_r64`, including RSP.
    PopRegister64,
}

impl JumpStackClass {
    /// Canonical descriptive class label for the separately bound population.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Jump => "jump",
            Self::PushRegister64 => "push-r64",
            Self::PopRegister64 => "pop-r64",
        }
    }
}

/// Classifies the complete union without filtering prefixes or registers.
///
/// Other PUSH/POP encodings, including register operands encoded with r/m
/// opcodes, are excluded. Constructed operands and execution support remain
/// consumer obligations; the Code fact is not a new qualification rule.
pub fn jump_or_register_stack(instruction: &Instruction) -> Option<JumpStackClass> {
    match instruction.code() {
        Code::Push_r64 => Some(JumpStackClass::PushRegister64),
        Code::Pop_r64 => Some(JumpStackClass::PopRegister64),
        _ if is_jump_mnemonic(instruction.mnemonic()) => Some(JumpStackClass::Jump),
        _ => None,
    }
}

/// General-purpose register identity in architectural encoding order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Gpr {
    /// RAX.
    Rax,
    /// RCX.
    Rcx,
    /// RDX.
    Rdx,
    /// RBX.
    Rbx,
    /// RSP. Consumers may impose a separate callback-ABI refusal.
    Rsp,
    /// RBP.
    Rbp,
    /// RSI.
    Rsi,
    /// RDI.
    Rdi,
    /// R8.
    R8,
    /// R9.
    R9,
    /// R10.
    R10,
    /// R11.
    R11,
    /// R12.
    R12,
    /// R13.
    R13,
    /// R14.
    R14,
    /// R15.
    R15,
}

/// Width of a selected full-GPR operand; byte registers are not included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Width {
    /// Sixteen bits.
    Bits16 = 16,
    /// Thirty-two bits.
    Bits32 = 32,
    /// Sixty-four bits.
    Bits64 = 64,
}

/// Architectural full-GPR operand facts, without an emitter acceptance policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GprOperand {
    /// Register identity, including RSP.
    pub register: Gpr,
    /// Operand width as reported by the decoded register.
    pub width: Width,
}

/// Maps a 16/32/64-bit iced GPR to its architectural identity and width.
pub fn gpr(register: Register) -> Option<GprOperand> {
    macro_rules! registers {
        ($($name:ident => ($r16:ident, $r32:ident, $r64:ident)),+ $(,)?) => {
            match register {
                $(Register::$r16 => Some(GprOperand { register: Gpr::$name, width: Width::Bits16 }),
                  Register::$r32 => Some(GprOperand { register: Gpr::$name, width: Width::Bits32 }),
                  Register::$r64 => Some(GprOperand { register: Gpr::$name, width: Width::Bits64 }),)+
                _ => None,
            }
        };
    }
    registers! {
        Rax => (AX, EAX, RAX), Rcx => (CX, ECX, RCX), Rdx => (DX, EDX, RDX),
        Rbx => (BX, EBX, RBX), Rsp => (SP, ESP, RSP), Rbp => (BP, EBP, RBP),
        Rsi => (SI, ESI, RSI), Rdi => (DI, EDI, RDI), R8 => (R8W, R8D, R8),
        R9 => (R9W, R9D, R9), R10 => (R10W, R10D, R10), R11 => (R11W, R11D, R11),
        R12 => (R12W, R12D, R12), R13 => (R13W, R13D, R13),
        R14 => (R14W, R14D, R14), R15 => (R15W, R15D, R15),
    }
}

#[cfg(test)]
mod tests;
