//! Pure actual-PC classification, without native execution authority.
//!
//! A candidate borrows the full original Snapshot and register input. Neither
//! that borrow nor an ordinary family proves a native single-instruction stop,
//! authenticated debug/control state, head completeness, or permission to run.
use iced_x86::{Code, Decoder, DecoderOptions, Instruction};
use liteinst_admission::AddressRange;
use liteinst_admission::scan::{Snapshot, WriteControl};

use crate::RegisterSnapshot;
use crate::selected::{self, DecodedSelected, SemanticsError, SyscallAliases};

mod families;
#[cfg(test)]
mod tests;

const MAX_INSTRUCTION: usize = 15;
const TF: u64 = 1 << 8;
const RF: u64 = 1 << 16;
// Arithmetic flags, fixed bit1, IF, DF, AC, ID. This is a descriptive ordinary
// profile, not proof that any privileged/debug/rseq/CET state is authenticated.
const ORDINARY_FLAGS: u64 = 1
    | 2
    | (1 << 2)
    | (1 << 4)
    | (1 << 6)
    | (1 << 7)
    | (1 << 9)
    | (1 << 10)
    | (1 << 11)
    | (1 << 18)
    | (1 << 21);

/// A caller's description, deliberately not a native debug-state certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DebugDisposition {
    Unknown,
    Present,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InstructionRefusal {
    UncontrolledWrites,
    ProgramCounterOutsideSnapshot,
    UnsupportedMode,
    AddressOverflow,
    Selected(SemanticsError),
    TrapFlag,
    ResumeFlag,
    UnsupportedFlags,
    DebugStateUnproven,
    UnsupportedPrefix,
    Unsupported(Code),
}

/// A closed family, not a claim that its execution is transparent or qualified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OrdinaryFamily {
    Move,
    Address,
    Arithmetic,
    Compare,
    Push,
    Pop,
    Nop,
    ConditionalBranch,
    Jump,
    Call,
    Return,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OrdinaryInstruction {
    decoded: Instruction,
    family: OrdinaryFamily,
    direct_target: Option<u64>,
}

impl OrdinaryInstruction {
    pub(super) fn decoded(&self) -> &Instruction {
        &self.decoded
    }
    pub(super) fn family(&self) -> OrdinaryFamily {
        self.family
    }
    /// None includes indirect transfers; it never means a proved fall-through.
    pub(super) fn direct_target(&self) -> Option<u64> {
        self.direct_target
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum CandidateKind {
    Selected(DecodedSelected),
    Ordinary(OrdinaryInstruction),
}

/// No constructor is exposed. Retained bytes/identity are never replaced by a
/// sliced Snapshot, and mutable live source must still be reauthenticated.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct InstructionCandidate<'a> {
    snapshot: &'a Snapshot,
    registers: &'a RegisterSnapshot,
    debug: DebugDisposition,
    range: AddressRange,
    bytes: &'a [u8],
    kind: CandidateKind,
}

impl<'a> InstructionCandidate<'a> {
    pub(super) fn snapshot(&self) -> &'a Snapshot {
        self.snapshot
    }
    pub(super) fn registers(&self) -> &'a RegisterSnapshot {
        self.registers
    }
    pub(super) fn debug(&self) -> DebugDisposition {
        self.debug
    }
    pub(super) fn range(&self) -> AddressRange {
        self.range
    }
    pub(super) fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub(super) fn next_pc(&self) -> u64 {
        self.range.end()
    }
    pub(super) fn kind(&self) -> &CandidateKind {
        &self.kind
    }
}

pub(super) fn classify<'a>(
    snapshot: &'a Snapshot,
    registers: &'a RegisterSnapshot,
    debug: DebugDisposition,
    aliases: &SyscallAliases,
) -> Result<InstructionCandidate<'a>, InstructionRefusal> {
    if snapshot.writes != WriteControl::Owned {
        return Err(InstructionRefusal::UncontrolledWrites);
    }
    if registers.cs != 0x33 {
        return Err(InstructionRefusal::UnsupportedMode);
    }
    let pc = registers.rip;
    if !snapshot.range().contains(pc) {
        return Err(InstructionRefusal::ProgramCounterOutsideSnapshot);
    }
    let offset = usize::try_from(
        pc.checked_sub(snapshot.range().start())
            .ok_or(InstructionRefusal::AddressOverflow)?,
    )
    .map_err(|_| InstructionRefusal::AddressOverflow)?;
    let remaining = snapshot
        .bytes()
        .get(offset..)
        .ok_or(InstructionRefusal::ProgramCounterOutsideSnapshot)?;

    // Only this exact error permits ordinary classification. In particular,
    // INT80/SYSENTER aliases and declarations on wrong opcodes cannot escape.
    let kind = match selected::decode(pc, remaining, aliases) {
        Ok(selected) => CandidateKind::Selected(selected),
        Err(SemanticsError::NotSelected) => {
            ordinary_state(registers, debug)?;
            let mut decoder = Decoder::with_ip(64, remaining, pc, DecoderOptions::NONE);
            let decoded = decoder.decode();
            if decoded.is_invalid()
                || decoded.len() == 0
                || decoded.len() > MAX_INSTRUCTION
                || decoded.len() > remaining.len()
            {
                return Err(InstructionRefusal::Selected(
                    SemanticsError::InvalidEncoding,
                ));
            }
            let bytes = &remaining[..decoded.len()];
            ordinary_prefixes(bytes, &decoded)?;
            let family = families::classify(decoded.code())
                .ok_or(InstructionRefusal::Unsupported(decoded.code()))?;
            let next = pc
                .checked_add(decoded.len() as u64)
                .ok_or(InstructionRefusal::AddressOverflow)?;
            let direct_target = relative_target(&decoded, bytes, next)?;
            CandidateKind::Ordinary(OrdinaryInstruction {
                decoded,
                family,
                direct_target,
            })
        }
        Err(error) => return Err(InstructionRefusal::Selected(error)),
    };
    let len = match &kind {
        CandidateKind::Selected(selected) => selected.bytes().len(),
        CandidateKind::Ordinary(ordinary) => ordinary.decoded.len(),
    };
    if len == 0 || len > MAX_INSTRUCTION || len > remaining.len() {
        return Err(InstructionRefusal::Selected(
            SemanticsError::InvalidEncoding,
        ));
    }
    let next = pc
        .checked_add(len as u64)
        .ok_or(InstructionRefusal::AddressOverflow)?;
    let range = AddressRange::new(pc, next).ok_or(InstructionRefusal::AddressOverflow)?;
    Ok(InstructionCandidate {
        snapshot,
        registers,
        debug,
        range,
        bytes: &remaining[..len],
        kind,
    })
}

fn ordinary_state(
    registers: &RegisterSnapshot,
    debug: DebugDisposition,
) -> Result<(), InstructionRefusal> {
    if registers.eflags & TF != 0 {
        return Err(InstructionRefusal::TrapFlag);
    }
    if registers.eflags & RF != 0 {
        return Err(InstructionRefusal::ResumeFlag);
    }
    if registers.eflags & 2 == 0 || registers.eflags & !ORDINARY_FLAGS != 0 {
        return Err(InstructionRefusal::UnsupportedFlags);
    }
    if debug != DebugDisposition::Absent {
        return Err(InstructionRefusal::DebugStateUnproven);
    }
    Ok(())
}

fn ordinary_prefixes(bytes: &[u8], instruction: &Instruction) -> Result<(), InstructionRefusal> {
    // Inspect the actual prefix train too: ignored/redundant prefixes must not
    // hide a transactional hint, NOTRACK, or an unqualified segment override.
    for byte in bytes {
        match byte {
            0xf0 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => {
                return Err(InstructionRefusal::UnsupportedPrefix);
            }
            0x66 | 0x67 | 0x40..=0x4f => {}
            _ => break,
        }
    }
    if instruction.has_lock_prefix()
        || instruction.has_rep_prefix()
        || instruction.has_repne_prefix()
        || instruction.has_xacquire_prefix()
        || instruction.has_xrelease_prefix()
        || instruction.has_segment_prefix()
    {
        return Err(InstructionRefusal::UnsupportedPrefix);
    }
    Ok(())
}

fn relative_target(
    instruction: &Instruction,
    bytes: &[u8],
    next: u64,
) -> Result<Option<u64>, InstructionRefusal> {
    let displacement = match families::relative_width(instruction.code()) {
        Some(1) => i64::from(*bytes.last().ok_or(InstructionRefusal::AddressOverflow)? as i8),
        Some(4) => {
            let start = bytes
                .len()
                .checked_sub(4)
                .ok_or(InstructionRefusal::AddressOverflow)?;
            let raw: [u8; 4] = bytes[start..]
                .try_into()
                .map_err(|_| InstructionRefusal::AddressOverflow)?;
            i64::from(i32::from_le_bytes(raw))
        }
        None => return Ok(None),
        Some(_) => return Err(InstructionRefusal::AddressOverflow),
    };
    let target = next
        .checked_add_signed(displacement)
        .ok_or(InstructionRefusal::AddressOverflow)?;
    if target != instruction.near_branch64() {
        return Err(InstructionRefusal::AddressOverflow);
    }
    Ok(Some(target))
}
