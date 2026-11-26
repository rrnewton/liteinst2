//! P1b.1: the pure resolver for indirect jumps and calls, shared by
//! both dispatchers (`P1B-DESIGN.md` §2, P1b.1).
//!
//! An INDIRECT exit reaches the dispatcher with the state before
//! the instruction. [`resolve`] decodes the transfer: the target
//! (a register, or 8 bytes read at the effective address), the
//! kind (jump or call) and the next IP a call pushes. It touches
//! no state and writes nothing; the dispatcher does the region
//! check, the translation of new roots, the push and the transfer,
//! in that order. Forms P1b.1 does not resolve (far transfers,
//! segment overrides, a 32-bit base or index) return
//! [`ResolveError::Unsupported`], which the dispatcher refuses by
//! name as `IndirectUnresolved`. A 32-bit absolute address
//! (`67 ff /4|/2` with `[disp32]`) returns
//! [`ResolveError::AddressSize32`], refused as
//! `IndirectAddressSize32`. (The decoder runs in Intel's decode mode,
//! `DecoderOptions::NONE`, where an operand-size prefix on a near
//! branch is ignored in 64-bit mode; AMD honours it. Decode refuses
//! every 66h-prefixed near branch and `ret` by name, so none reaches
//! this resolver.)

use std::collections::{BTreeMap, BTreeSet};

use liteinst_x86::{Code, Instruction, OpKind, Register};

use crate::state::GuestState;
use crate::types::RegionFacts;

/// The transfer an indirect instruction makes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndirectKind {
    /// `jmp r/m64`.
    Jump,
    /// `call r/m64`: pushes `next_ip`.
    Call,
}

/// A resolved indirect transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolved {
    pub kind: IndirectKind,
    /// The transfer target, read from the register or from memory.
    pub target: u64,
    /// The address of the next instruction (`pc + len`): what a
    /// call pushes, and the base of a RIP-relative operand.
    pub next_ip: u64,
}

/// Why [`resolve`] produced no target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveError {
    /// A form P1b.1 does not resolve; refused by name as
    /// `Refuse::IndirectUnresolved` at the instruction.
    Unsupported,
    /// The 8-byte read of the memory operand at `addr` failed: a
    /// guest fault at the instruction, which does not retire.
    ReadFault { addr: u64 },
    /// The memory operand has a 32-bit address size in absolute form
    /// (`67 ff /4|/2` with `[disp32]`); refused by name as
    /// `Refuse::IndirectAddressSize32` at the instruction.
    AddressSize32,
}

/// The 64-bit general register `reg` in `s`, or `None` for any
/// other register (a 32-bit or 16-bit name, a segment, RIP).
fn gpr64(s: &GuestState, reg: Register) -> Option<u64> {
    Some(match reg {
        Register::RAX => s.rax,
        Register::RBX => s.rbx,
        Register::RCX => s.rcx,
        Register::RDX => s.rdx,
        Register::RSI => s.rsi,
        Register::RDI => s.rdi,
        Register::RBP => s.rbp,
        Register::RSP => s.rsp,
        Register::R8 => s.r8,
        Register::R9 => s.r9,
        Register::R10 => s.r10,
        Register::R11 => s.r11,
        Register::R12 => s.r12,
        Register::R13 => s.r13,
        Register::R14 => s.r14,
        Register::R15 => s.r15,
        _ => return None,
    })
}

/// The effective address of `insn`'s memory operand, computed from
/// the state before the instruction: base + index x scale +
/// displacement, where a RIP-relative base is `next_ip`.
fn effective_address(insn: &Instruction, s: &GuestState, next_ip: u64) -> Option<u64> {
    let disp = insn.memory_displacement64();
    let (base_value, disp) = match insn.memory_base() {
        // iced reports a RIP-relative operand's displacement as the
        // absolute address it decoded; the encoded displacement is
        // that address minus the decoder's next IP.
        Register::RIP => (next_ip, disp.wrapping_sub(insn.next_ip())),
        Register::None => (0, disp),
        r => (gpr64(s, r)?, disp),
    };
    let index_value = match insn.memory_index() {
        Register::None => 0,
        r => {
            let scale = u64::from(insn.memory_index_scale());
            gpr64(s, r)?.wrapping_mul(scale)
        }
    };
    Some(base_value.wrapping_add(index_value).wrapping_add(disp))
}

/// Resolve the indirect transfer `insn` at `pc` (`len` bytes) from
/// the state before it. `read_u64` reads 8 guest bytes, `None` on a
/// fault. Nothing is written.
pub fn resolve(
    insn: &Instruction,
    pc: u64,
    len: usize,
    s: &GuestState,
    read_u64: &mut dyn FnMut(u64) -> Option<u64>,
) -> Result<Resolved, ResolveError> {
    let kind = match insn.code() {
        Code::Jmp_rm64 => IndirectKind::Jump,
        Code::Call_rm64 => IndirectKind::Call,
        _ => return Err(ResolveError::Unsupported),
    };
    if insn.op_count() != 1 || insn.segment_prefix() != Register::None {
        return Err(ResolveError::Unsupported);
    }
    let next_ip = pc.wrapping_add(len as u64);
    let target = match insn.op0_kind() {
        OpKind::Register => match gpr64(s, insn.op0_register()) {
            Some(v) => v,
            None => return Err(ResolveError::Unsupported),
        },
        OpKind::Memory => {
            // 67h with an absolute [disp32]: a 32-bit address. Iced
            // reports its displacement zero-extended with size 4 (a
            // 64-bit [disp32] reports size 8), so effective_address
            // would compute it; this resolver claims 64-bit addressing
            // only. Every other 67h form already fails in gpr64.
            if insn.memory_base() == Register::None
                && insn.memory_index() == Register::None
                && insn.memory_displ_size() == 4
            {
                return Err(ResolveError::AddressSize32);
            }
            let Some(ea) = effective_address(insn, s, next_ip) else {
                return Err(ResolveError::Unsupported);
            };
            match read_u64(ea) {
                Some(v) => v,
                None => return Err(ResolveError::ReadFault { addr: ea }),
            }
        }
        _ => return Err(ResolveError::Unsupported),
    };
    Ok(Resolved {
        kind,
        target,
        next_ip,
    })
}

/// The roots a resolved in-region transfer adds (P1b.1 §1.2 step 4):
/// the target, plus the next IP of a call whose next IP lies inside
/// the region (an out-of-region return site adds no root), minus
/// every address that is already a block start. Empty when nothing
/// needs translating.
pub fn new_roots(
    r: &Resolved,
    region: &RegionFacts,
    block_gen: &BTreeMap<u64, u64>,
) -> BTreeSet<u64> {
    let mut roots = BTreeSet::from([r.target]);
    if r.kind == IndirectKind::Call && region.contains(r.next_ip) {
        roots.insert(r.next_ip);
    }
    roots.retain(|pc| !block_gen.contains_key(pc));
    roots
}

/// Whether a call's 8-byte return-address slot `[rsp-8, rsp)` crosses
/// a 4 KiB page boundary, i.e. `(rsp - 8) & 0xfff > 0xff8`. The
/// dispatchers write the slot with one tracer or process write. When
/// the slot spans two pages and only the second is unwritable, that
/// write can store the first page's bytes before it fails, which a
/// native `call` (#PF before any store) never does. So both
/// dispatchers refuse such a call by name
/// (`Refuse::IndirectPushCrossesPage`) before any retranslation or
/// write. An 8-byte-aligned slot never crosses a page, so an
/// ABI-aligned stack never meets this refusal.
pub fn push_crosses_page(rsp: u64) -> bool {
    (rsp.wrapping_sub(8) & 0xfff) > 0xff8
}
