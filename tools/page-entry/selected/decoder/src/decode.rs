//! Exact iced decode plus a deliberately small descriptive step inventory.

use crate::abi::*;
use iced_x86::{
    Code, Decoder, DecoderError, DecoderOptions, Instruction, Mnemonic, OpKind, Register,
};

pub(crate) fn warm_tables() {
    // Decoder construction initializes every enabled legacy/VEX/EVEX/XOP table
    // in one TABLES initializer. No table family is compiled out for speed.
    let mut decoder = Decoder::with_ip(64, &[0x90], 0, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() || instruction.len() != 1 {
        crate::arena::fatal(crate::arena::FATAL_PANIC);
    }
}

pub(crate) fn one(pc: u64, source: &[u8]) -> Result<Decoded, u32> {
    if source.is_empty() || source.len() > 15 {
        return Err(BAD_ARGUMENT);
    }
    // Also exclude wrapping metadata on invalid/truncated decoder results.
    pc.checked_add(source.len() as u64)
        .ok_or(ADDRESS_OVERFLOW)?;
    let mut row = Decoded {
        pc,
        abi_version: VERSION,
        destination: NO_REGISTER,
        available: source.len() as u32,
        step_disposition: STEP_INVALID,
        ..Decoded::default()
    };
    row.bytes[..source.len()].copy_from_slice(source);
    let mut decoder = Decoder::with_ip(64, source, pc, DecoderOptions::NONE);
    let instruction = decoder.decode();
    row.code = instruction.code() as u32;
    row.length = instruction.len() as u32;
    row.next_pc = pc
        .checked_add(instruction.len() as u64)
        .ok_or(ADDRESS_OVERFLOW)?;
    row.decode_status = match decoder.last_error() {
        DecoderError::None => VALID,
        DecoderError::NoMoreBytes => TRUNCATED,
        _ => INVALID,
    };
    if instruction.is_invalid() || row.decode_status != VALID {
        return Ok(row);
    }
    let (kind, operand) = match instruction.code() {
        Code::Cpuid => (CPUID, false),
        Code::Rdrand_r16 | Code::Rdrand_r32 | Code::Rdrand_r64 => (RDRAND, true),
        Code::Rdseed_r16 | Code::Rdseed_r32 | Code::Rdseed_r64 => (RDSEED, true),
        Code::Rdpid_r64 => (RDPID, true),
        Code::Rdtsc => (RDTSC, false),
        Code::Rdtscp => (RDTSCP, false),
        Code::Syscall => (SYSCALL, false),
        Code::Sysenter => (SYSENTER, false),
        Code::Int_imm8 if instruction.immediate8() == 0x80 => (INT80, false),
        _ => (NONE, false),
    };
    row.kind = kind;
    if operand {
        let (destination, width) = register(instruction.op0_register()).ok_or(BAD_ARGUMENT)?;
        // RSP stays in the facts. No emitter limitation deselects a candidate.
        row.destination = destination;
        row.width_bits = width;
    }
    row.step_disposition = step(&instruction, &source[..instruction.len()], kind);
    Ok(row)
}

fn register(register: Register) -> Option<(u32, u32)> {
    macro_rules! regs {
        ($($index:literal => ($small:ident, $medium:ident, $large:ident)),+ $(,)?) => {
            match register {
                $(Register::$small => Some(($index, 16)),
                  Register::$medium => Some(($index, 32)),
                  Register::$large => Some(($index, 64)),)+
                _ => None,
            }
        };
    }
    regs! {
        0 => (AX, EAX, RAX), 1 => (CX, ECX, RCX), 2 => (DX, EDX, RDX),
        3 => (BX, EBX, RBX), 4 => (SP, ESP, RSP), 5 => (BP, EBP, RBP),
        6 => (SI, ESI, RSI), 7 => (DI, EDI, RDI), 8 => (R8W, R8D, R8),
        9 => (R9W, R9D, R9), 10 => (R10W, R10D, R10), 11 => (R11W, R11D, R11),
        12 => (R12W, R12D, R12), 13 => (R13W, R13D, R13),
        14 => (R14W, R14D, R14), 15 => (R15W, R15D, R15),
    }
}

// Only the complete canonical register forms enter this new inventory. The
// independent owner must still authenticate the original bytes and mapping.
fn register_mov_step(instruction: &Instruction, bytes: &[u8]) -> u32 {
    if instruction.op0_kind() != OpKind::Register || instruction.op1_kind() != OpKind::Register {
        return STEP_UNSUPPORTED;
    }
    let Some((destination, width)) = register(instruction.op0_register()) else {
        return STEP_UNSUPPORTED;
    };
    let Some((source, source_width)) = register(instruction.op1_register()) else {
        return STEP_UNSUPPORTED;
    };
    if destination == 4 {
        return STEP_RSP_WRITE;
    }
    let mut at = 0;
    let small = bytes.first() == Some(&0x66);
    if small {
        at += 1;
    }
    let rex = match bytes.get(at) {
        Some(value @ 0x40..=0x4f) => {
            at += 1;
            *value
        }
        _ => 0,
    };
    // REX.X and a bare REX are ignored in mod=3. Redundant 66+REX.W,
    // repeated/out-of-order prefixes, segments, address, REP and LOCK refuse.
    if rex & 2 != 0 || rex == 0x40 || (small && rex & 8 != 0) || bytes.len() != at + 2 {
        return STEP_PREFIX_UNQUALIFIED;
    }
    let opcode = bytes[at];
    let modrm = bytes[at + 1];
    if !matches!(opcode, 0x89 | 0x8b) || modrm & 0xc0 != 0xc0 {
        return STEP_PREFIX_UNQUALIFIED;
    }
    let reg = ((modrm >> 3) & 7) as u32 + if rex & 4 != 0 { 8 } else { 0 };
    let rm = (modrm & 7) as u32 + if rex & 1 != 0 { 8 } else { 0 };
    let (expected_destination, expected_source) =
        if opcode == 0x89 { (rm, reg) } else { (reg, rm) };
    let expected_width = if rex & 8 != 0 {
        64
    } else if small {
        16
    } else {
        32
    };
    if (destination, source, width, source_width)
        != (
            expected_destination,
            expected_source,
            expected_width,
            expected_width,
        )
    {
        return STEP_UNSUPPORTED;
    }
    STEP_CANDIDATE
}

fn step(instruction: &Instruction, bytes: &[u8], kind: u32) -> u32 {
    if kind == SYSCALL || kind == SYSENTER || kind == INT80 {
        return STEP_KERNEL_TRANSFER;
    }
    if kind != NONE {
        return STEP_SELECTED;
    }
    if instruction.has_xacquire_prefix() || instruction.has_xrelease_prefix() {
        return STEP_TRANSACTION;
    }
    match instruction.mnemonic() {
        Mnemonic::Xbegin | Mnemonic::Xend | Mnemonic::Xabort | Mnemonic::Xtest => {
            return STEP_TRANSACTION;
        }
        Mnemonic::Encls
        | Mnemonic::Enclu
        | Mnemonic::Enclv
        | Mnemonic::Getsec
        | Mnemonic::Getsecq
        | Mnemonic::Xsetbv
        | Mnemonic::Wrpkru
        | Mnemonic::Wrfsbase
        | Mnemonic::Wrgsbase
        | Mnemonic::Swapgs
        | Mnemonic::Xrstor
        | Mnemonic::Xrstor64
        | Mnemonic::Xrstors
        | Mnemonic::Xrstors64
        | Mnemonic::Rstorssp
        | Mnemonic::Setssbsy
        | Mnemonic::Clrssbsy
        | Mnemonic::Incsspd
        | Mnemonic::Incsspq
        | Mnemonic::Vmcall
        | Mnemonic::Vmmcall
        | Mnemonic::Vmlaunch
        | Mnemonic::Vmresume
        | Mnemonic::Vmrun
        | Mnemonic::Vmxon
        | Mnemonic::Vmxoff
        | Mnemonic::Vmgexit
        | Mnemonic::Uiret
        | Mnemonic::Stui
        | Mnemonic::Clui
        | Mnemonic::Rdmsr
        | Mnemonic::Wrmsr
        | Mnemonic::Lgdt
        | Mnemonic::Lidt
        | Mnemonic::Lldt
        | Mnemonic::Ltr
        | Mnemonic::Hlt
        | Mnemonic::Rsm => {
            return STEP_CONTROL_STATE;
        }
        Mnemonic::Pushf | Mnemonic::Pushfd | Mnemonic::Pushfq => return STEP_FLAGS_OBSERVED,
        Mnemonic::Popf
        | Mnemonic::Popfd
        | Mnemonic::Popfq
        | Mnemonic::Iret
        | Mnemonic::Iretd
        | Mnemonic::Iretq => return STEP_FLAGS_RESTORED,
        Mnemonic::Lss | Mnemonic::Sti | Mnemonic::Cli => return STEP_DEBUG_INHIBITION,
        Mnemonic::Mov | Mnemonic::Pop if instruction.op0_register() == Register::SS => {
            return STEP_DEBUG_INHIBITION;
        }
        _ => {}
    }
    if matches!(
        instruction.code(),
        Code::Mov_rm16_r16
            | Code::Mov_rm32_r32
            | Code::Mov_rm64_r64
            | Code::Mov_r16_rm16
            | Code::Mov_r32_rm32
            | Code::Mov_r64_rm64
    ) {
        return register_mov_step(instruction, bytes);
    }
    // Closed initial inventory only; candidate is not native step permission.
    if !matches!(
        instruction.code(),
        Code::Mov_r16_imm16
            | Code::Mov_r32_imm32
            | Code::Mov_r64_imm64
            | Code::Nopw
            | Code::Nopd
            | Code::Nopq
    ) {
        return STEP_UNSUPPORTED;
    }
    if register(instruction.op0_register()).is_some_and(|(destination, _)| destination == 4) {
        return STEP_RSP_WRITE;
    }
    for byte in bytes {
        match byte {
            0x66 | 0x67 | 0x40..=0x4f => {}
            0xf0 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => {
                return STEP_PREFIX_UNQUALIFIED;
            }
            _ => break,
        }
    }
    STEP_CANDIDATE
}
