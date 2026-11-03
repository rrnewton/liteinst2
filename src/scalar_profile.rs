//! Pure instruction-form policy shared by the closed scalar frontends.
//!
//! This describes their existing read-only, caller-saved-GPR operand subset.
//! It does not establish decoding validity, prefix or privilege legality,
//! CFG or entry ownership, memory validity, ABI or runtime qualification.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

fn gpr(register: Register) -> bool {
    register.is_gpr()
        && matches!(
            register.full_register(),
            Register::RAX
                | Register::RCX
                | Register::RDX
                | Register::RSI
                | Register::RDI
                | Register::R8
                | Register::R9
                | Register::R10
                | Register::R11
        )
}
fn address_register(register: Register) -> bool {
    register == Register::None || (register.is_gpr64() && gpr(register))
}

/// Matches the read-only, caller-saved scalar instruction-form policy.
///
/// This preserves the existing mnemonic and operand checks, including byte
/// aliases of RAX, RCX, RDX, RSI, RDI and R8..R11. Memory operands need an allowed
/// 64-bit base and optional allowed 64-bit index. Memory writes and
/// read-modify-write forms are excluded; LEA and NOP retain nonaccessing forms.
///
/// Callers retain their separate prefix, privilege, general qualification,
/// control-flow, entry, size and resource checks in their original order.
/// A true result alone is not an admission or safety certificate.
pub fn read_only_caller_saved(i: &Instruction) -> bool {
    if !matches!(
        i.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Movzx
            | Mnemonic::Lea
            | Mnemonic::Xor
            | Mnemonic::Add
            | Mnemonic::Adc
            | Mnemonic::Sub
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Test
            | Mnemonic::Cmp
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Nop
    ) {
        return false;
    }
    for n in 0..i.op_count() {
        match i.op_kind(n) {
            OpKind::Register if gpr(i.op_register(n)) => {}
            OpKind::Memory => {
                // Only read operands (or LEA/NOP's nonaccessing address form).
                // No store, RMW, absolute, RIP-relative, 32-bit address, stack
                // or callee-saved address component is admitted.
                if (n == 0
                    && !matches!(i.mnemonic(), Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Nop))
                    || i.memory_base() == Register::None
                    || !address_register(i.memory_base())
                    || !address_register(i.memory_index())
                {
                    return false;
                }
            }
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {}
            _ => return false,
        }
    }
    true
}
