//! Typed operand decoding. This is not an entry/head or CPU-capability proof.

use iced_x86::Register;
use liteinst::contracts::Refusal;
use liteinst::x86::{self, SelectedClass};

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
    let instruction = x86::decode64(pc, bytes).instruction;
    if instruction.is_invalid() || instruction.len() == 0 || instruction.len() > bytes.len() {
        return Err(refused("invalid selected instruction encoding"));
    }
    let len = instruction.len();
    let next_pc = pc.checked_add(len as u64).ok_or(Refusal::InvalidRange)?;
    let (actual, operand) = match x86::selected_code(&instruction) {
        Some(SelectedClass::Cpuid) => (SelectedKind::Cpuid, None),
        Some(SelectedClass::Rdtsc) => (SelectedKind::Rdtsc, None),
        Some(SelectedClass::Syscall) => (SelectedKind::Syscall, None),
        Some(SelectedClass::Rdtscp) => (SelectedKind::Rdtscp, None),
        Some(SelectedClass::Rdrand) => (
            SelectedKind::Rdrand,
            Some(register(instruction.op0_register())?),
        ),
        Some(SelectedClass::Rdseed) => (
            SelectedKind::Rdseed,
            Some(register(instruction.op0_register())?),
        ),
        Some(SelectedClass::Rdpid) => (
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
    let operand = x86::gpr(register)
        .ok_or_else(|| refused("selected operand is not an architectural GPR"))?;
    let destination = match operand.register {
        x86::Gpr::Rax => SelectedDestination::Rax,
        x86::Gpr::Rcx => SelectedDestination::Rcx,
        x86::Gpr::Rdx => SelectedDestination::Rdx,
        x86::Gpr::Rbx => SelectedDestination::Rbx,
        x86::Gpr::Rsp => SelectedDestination::Rsp,
        x86::Gpr::Rbp => SelectedDestination::Rbp,
        x86::Gpr::Rsi => SelectedDestination::Rsi,
        x86::Gpr::Rdi => SelectedDestination::Rdi,
        x86::Gpr::R8 => SelectedDestination::R8,
        x86::Gpr::R9 => SelectedDestination::R9,
        x86::Gpr::R10 => SelectedDestination::R10,
        x86::Gpr::R11 => SelectedDestination::R11,
        x86::Gpr::R12 => SelectedDestination::R12,
        x86::Gpr::R13 => SelectedDestination::R13,
        x86::Gpr::R14 => SelectedDestination::R14,
        x86::Gpr::R15 => SelectedDestination::R15,
    };
    let width = match operand.width {
        x86::Width::Bits16 => SelectedWidth::Bits16,
        x86::Width::Bits32 => SelectedWidth::Bits32,
        x86::Width::Bits64 => SelectedWidth::Bits64,
    };
    Ok((destination, width))
}
