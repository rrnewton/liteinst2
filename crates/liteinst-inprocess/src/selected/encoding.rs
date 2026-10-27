//! Typed operand decoding. This is not an entry/head or CPU-capability proof.

use iced_x86::{Code, Decoder, DecoderOptions, Register};
use liteinst2::contracts::Refusal;

use super::SelectedKind;

/// Architectural destination, in x86 register-encoding order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SelectedDestination {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

/// Architectural width of a register result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedWidth {
    /// Preserve the upper 48 destination bits.
    Bits16,
    /// Clear the upper 32 destination bits.
    Bits32,
    /// Replace the complete register.
    Bits64,
}

/// Immutable exact instruction selected before planning or publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedInstruction {
    kind: SelectedKind,
    logical_pc: u64,
    next_pc: u64,
    bytes: [u8; 15],
    len: u8,
    destination: Option<SelectedDestination>,
    width: Option<SelectedWidth>,
}

impl SelectedInstruction {
    /// Exact selected class, independent of CPUID feature advertisements.
    pub const fn kind(&self) -> SelectedKind {
        self.kind
    }
    /// Original caller-certified instruction head.
    pub const fn logical_pc(&self) -> u64 {
        self.logical_pc
    }
    /// Original fallthrough, including every accepted prefix byte.
    pub const fn next_pc(&self) -> u64 {
        self.next_pc
    }
    /// Exact decoded instruction bytes, without the following tail.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
    /// Explicit register operand, or None for implicit-operand instructions.
    pub const fn destination(&self) -> Option<SelectedDestination> {
        self.destination
    }
    /// Explicit result width; RDPID uses a 64-bit zero-extended result.
    pub const fn width(&self) -> Option<SelectedWidth> {
        self.width
    }
}

fn refused(reason: &str) -> Refusal {
    Refusal::UnsupportedSemantics(reason.into())
}

/// Decode the first instruction under the core's 64-bit decoder rules.
///
/// The existing CPUID/RDTSC/SYSCALL profile remains its exact unprefixed
/// encoding. New classes accept decoder-valid ignored prefixes and effective
/// REX/operand widths; invalid LOCK, memory forms and overlength encodings
/// refuse. No CPUID feature check deselects a requested instruction. SP/ESP/RSP
/// destinations refuse because the current core callback ABI cannot restore RSP.
pub fn decode_selected(
    kind: SelectedKind,
    pc: u64,
    bytes: &[u8],
) -> Result<SelectedInstruction, Refusal> {
    let mut decoder = Decoder::with_ip(64, bytes, pc, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() || instruction.len() == 0 || instruction.len() > bytes.len() {
        return Err(refused("invalid selected instruction encoding"));
    }
    let len = instruction.len();
    let next_pc = pc.checked_add(len as u64).ok_or(Refusal::InvalidRange)?;
    let (actual, operand) = match instruction.code() {
        Code::Cpuid => (SelectedKind::Cpuid, None),
        Code::Rdtsc => (SelectedKind::Rdtsc, None),
        Code::Syscall => (SelectedKind::Syscall, None),
        Code::Rdtscp => (SelectedKind::Rdtscp, None),
        Code::Rdrand_r16 | Code::Rdrand_r32 | Code::Rdrand_r64 => (
            SelectedKind::Rdrand,
            Some(register(instruction.op0_register())?),
        ),
        Code::Rdseed_r16 | Code::Rdseed_r32 | Code::Rdseed_r64 => (
            SelectedKind::Rdseed,
            Some(register(instruction.op0_register())?),
        ),
        Code::Rdpid_r64 => (
            SelectedKind::Rdpid,
            Some(register(instruction.op0_register())?),
        ),
        _ => return Err(refused("instruction is not a supported selected class")),
    };
    if actual != kind {
        return Err(refused("selected class differs from actual instruction"));
    }
    if matches!(
        kind,
        SelectedKind::Cpuid | SelectedKind::Rdtsc | SelectedKind::Syscall
    ) && Some(&bytes[..len]) != kind.encoding()
    {
        return Err(refused(
            "existing selected class requires its exact unprefixed encoding",
        ));
    }
    if operand.is_some_and(|(destination, _)| destination == SelectedDestination::Rsp) {
        return Err(refused(
            "core callback RSP is metadata, not a writable result",
        ));
    }
    if kind == SelectedKind::Rdpid && operand.map(|(_, width)| width) != Some(SelectedWidth::Bits64)
    {
        return Err(refused("invalid long-mode RDPID result width"));
    }
    let mut original = [0; 15];
    original[..len].copy_from_slice(&bytes[..len]);
    Ok(SelectedInstruction {
        kind,
        logical_pc: pc,
        next_pc,
        bytes: original,
        len: len as u8,
        destination: operand.map(|(destination, _)| destination),
        width: operand.map(|(_, width)| width),
    })
}

fn register(register: Register) -> Result<(SelectedDestination, SelectedWidth), Refusal> {
    macro_rules! registers {
        ($($name:ident => ($r16:ident, $r32:ident, $r64:ident)),+ $(,)?) => {
            match register {
                $(Register::$r16 => Ok((SelectedDestination::$name, SelectedWidth::Bits16)),
                  Register::$r32 => Ok((SelectedDestination::$name, SelectedWidth::Bits32)),
                  Register::$r64 => Ok((SelectedDestination::$name, SelectedWidth::Bits64)),)+
                _ => Err(refused("selected operand is not an architectural GPR")),
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
