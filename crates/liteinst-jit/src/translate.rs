//! Block discovery (recursive descent over direct edges) and
//! out-of-place emission with folded counting.
//!
//! Emission invariants: copied instructions keep their source length
//! (RIP-relative operands are re-encoded and must not change length,
//! else refusal); every conditional branch routes both successors
//! through a flag-neutral count stub so the increment is credited
//! exactly once, after retirement; syscall-class, nondeterministic,
//! indirect, and return terminators emit an exit stub and never
//! execute in the cache.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use iced_x86::{ConditionCode, Encoder};

use crate::decode::{DecodedInsn, InsnClass, decode_one};
use crate::pcmap::{PcMap, PcMapEntry, Phase};
use crate::refuse::Refuse;
use crate::state::{
    OFF_BRANCH_COUNT, OFF_EXIT_KIND, OFF_EXIT_NEXT, OFF_EXIT_SRC, OFF_HOST_R12, OFF_HOST_R13,
    OFF_HOST_R14, OFF_HOST_R15, OFF_HOST_RBP, OFF_HOST_RBX, OFF_HOST_RSP, OFF_INSTRUCTION_COUNT,
    OFF_SCRATCH, OFF_SPILL_FLAGS, OFF_SPILL_RAX, OFF_STATE, ST_R8, ST_R9, ST_R10, ST_R11, ST_R12,
    ST_R13, ST_R14, ST_R15, ST_RAX, ST_RBP, ST_RBX, ST_RCX, ST_RDI, ST_RDX, ST_RFLAGS, ST_RSI,
    ST_RSP, exit_kind,
};
use crate::types::{CountProfile, RegionFacts};

pub const MAX_INSNS_PER_BLOCK: usize = 512;
pub const MAX_BLOCKS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminator {
    Cond {
        target: u64,
        fallthrough: u64,
        loop_like: bool,
    },
    Jump {
        target: u64,
    },
    Call {
        target: u64,
        return_pc: u64,
    },
    Fallthrough {
        next: u64,
    },
    Return,
    Indirect,
    SyscallExit {
        next: u64,
    },
    NondetExit {
        next: u64,
    },
}

/// One discovered basic block. `insns` holds ordinary copied
/// instructions only; the terminator instruction (branch, jump, call,
/// return, indirect, syscall, nondet) is kept separately in `term`.
#[derive(Clone, Debug)]
pub struct Block {
    pub start: u64,
    pub insns: Vec<DecodedInsn>,
    pub term: Option<DecodedInsn>,
    pub terminator: Terminator,
}

impl Block {
    pub fn term_pc(&self) -> Option<u64> {
        self.term.as_ref().map(|t| t.pc)
    }
    /// Whether the terminator instruction retires inside the cache.
    /// Syscall/nondet terminators exit before executing and do not.
    fn term_retires_in_cache(&self) -> bool {
        !matches!(
            self.terminator,
            Terminator::SyscallExit { .. }
                | Terminator::NondetExit { .. }
                | Terminator::Fallthrough { .. }
        )
    }
    /// Total source instructions retired by one full block execution.
    pub fn instruction_total(&self) -> u64 {
        self.insns.len() as u64 + u64::from(self.term.is_some() && self.term_retires_in_cache())
    }
    pub fn insn_pcs(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.insns.iter().map(|i| i.pc).collect();
        if self.term_retires_in_cache()
            && let Some(t) = &self.term
        {
            v.push(t.pc);
        }
        v
    }
}

/// A completed translation: emitted bytes plus recovery metadata.
#[derive(Debug)]
pub struct Translation {
    pub entry_src: u64,
    pub gen_base: u64,
    pub code: Vec<u8>,
    pub pcmap: PcMap,
    pub block_gen: BTreeMap<u64, u64>,
    pub blocks: BTreeMap<u64, Block>,
}

fn check_interior(decoded: &BTreeMap<u64, usize>, target: u64) -> Result<(), Refuse> {
    if let Some((&start, &len)) = decoded.range(..=target).next_back()
        && target != start
        && target < start.wrapping_add(len as u64)
    {
        return Err(Refuse::InteriorEntry { target });
    }
    Ok(())
}

/// Discover all blocks reachable from `entry` over direct edges.
pub fn discover(region: &RegionFacts, entry: u64) -> Result<BTreeMap<u64, Block>, Refuse> {
    if !region.immutable_private {
        return Err(Refuse::SelfModifyingOrWritableCode { src: region.base });
    }
    if !region.contains(entry) {
        return Err(Refuse::InteriorEntry { target: entry });
    }
    let mut blocks: BTreeMap<u64, Block> = BTreeMap::new();
    let mut starts: BTreeSet<u64> = BTreeSet::from([entry]);
    let mut work: Vec<u64> = vec![entry];
    let mut decoded: BTreeMap<u64, usize> = BTreeMap::new();
    while let Some(start) = work.pop() {
        if blocks.contains_key(&start) {
            continue;
        }
        // A later-discovered direct target can land inside a block
        // already built (classic back-edge): split that block at the
        // target so blocks never overlap in source space.
        if let Some((&bs, _)) = blocks.range(..start).next_back() {
            let hit = {
                let b = &blocks[&bs];
                b.insns
                    .iter()
                    .position(|i| i.pc == start)
                    .map(|i| (i, false))
                    .or_else(|| (b.term_pc() == Some(start)).then_some((b.insns.len(), true)))
            };
            if let Some((idx, _)) = hit {
                let b = blocks.get_mut(&bs).expect("block just found");
                b.insns.truncate(idx);
                b.term = None;
                b.terminator = Terminator::Fallthrough { next: start };
            }
        }
        if blocks.len() >= MAX_BLOCKS {
            return Err(Refuse::BudgetExceeded { what: "blocks" });
        }
        check_interior(&decoded, start)?;
        let mut insns: Vec<DecodedInsn> = Vec::new();
        let mut pc = start;
        let (term_pc, terminator, successors): (Option<u64>, Terminator, Vec<u64>) = loop {
            if insns.len() >= MAX_INSNS_PER_BLOCK {
                return Err(Refuse::BudgetExceeded {
                    what: "insns per block",
                });
            }
            if pc != start && starts.contains(&pc) {
                break (None, Terminator::Fallthrough { next: pc }, vec![pc]);
            }
            let Some(bytes) = region.slice_from(pc) else {
                return Err(Refuse::Decode { src_pc: pc });
            };
            let Some(d) = decode_one(bytes, pc) else {
                return Err(Refuse::Decode { src_pc: pc });
            };
            decoded.insert(pc, d.len);
            let next = pc.wrapping_add(d.len as u64);
            // A queued or built block start strictly inside this
            // instruction means two reachable streams disagree on
            // instruction boundaries: refuse, never pick one.
            if let Some(&s) = starts.range(pc.wrapping_add(1)..next).next() {
                return Err(Refuse::InteriorEntry { target: s });
            }
            if let Some((&s, _)) = blocks.range(pc.wrapping_add(1)..next).next() {
                return Err(Refuse::InteriorEntry { target: s });
            }
            match d.class {
                InsnClass::Ordinary => {
                    insns.push(d);
                    pc = next;
                }
                InsnClass::CondBranch { target, loop_like } => {
                    break (
                        Some(pc),
                        Terminator::Cond {
                            target,
                            fallthrough: next,
                            loop_like,
                        },
                        // The branch instruction itself is needed at
                        // emission time; keep it in `insns` via a
                        // sentinel handled by the caller below.
                        vec![target, next],
                    );
                }
                InsnClass::DirectJump { target } => {
                    break (Some(pc), Terminator::Jump { target }, vec![target]);
                }
                InsnClass::DirectCall { target } => {
                    break (
                        Some(pc),
                        Terminator::Call {
                            target,
                            return_pc: next,
                        },
                        vec![target, next],
                    );
                }
                InsnClass::Return => break (Some(pc), Terminator::Return, vec![]),
                InsnClass::Indirect => break (Some(pc), Terminator::Indirect, vec![]),
                InsnClass::Syscall => {
                    break (Some(pc), Terminator::SyscallExit { next }, vec![next]);
                }
                InsnClass::Nondet => {
                    break (Some(pc), Terminator::NondetExit { next }, vec![next]);
                }
            }
        };
        // Re-decode the terminator instruction for emission needs
        // (condition code, loop-like re-encode).
        let term = match term_pc {
            Some(tp) => Some(
                region
                    .slice_from(tp)
                    .and_then(|b| decode_one(b, tp))
                    .ok_or(Refuse::Decode { src_pc: tp })?,
            ),
            None => None,
        };
        blocks.insert(
            start,
            Block {
                start,
                insns,
                term,
                terminator,
            },
        );
        for s in successors {
            if region.contains(s) {
                check_interior(&decoded, s)?;
                if starts.insert(s) {
                    work.push(s);
                }
            } else if matches!(
                terminator,
                Terminator::Jump { .. } | Terminator::Call { .. }
            ) || matches!(terminator, Terminator::Cond { .. })
            {
                // Direct edge leaving the admitted region: P1a has no
                // external-target mechanism, refuse by name. (Return
                // and indirect edges exit to the dispatcher instead.)
                return Err(Refuse::IndirectUnresolved {
                    src_pc: term_pc.unwrap_or(start),
                });
            }
        }
    }
    Ok(blocks)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum FixTarget {
    Block(u64),
    CountStub { branch: u64, successor: u64 },
    CommonExit,
}

struct Emitter {
    buf: Vec<u8>,
    gen_base: u64,
    data_addr: u64,
    pcmap: PcMap,
    fixups: Vec<(usize, FixTarget)>,
    stubs: Vec<(u64, u64)>,
}

impl Emitter {
    fn pc(&self) -> u64 {
        self.gen_base.wrapping_add(self.buf.len() as u64)
    }
    fn field(&self, off: usize) -> u64 {
        self.data_addr.wrapping_add(off as u64)
    }
    /// RIP displacement for an instruction of total length `insn_len`
    /// starting at the current emit position.
    fn disp(&self, field_off: usize, insn_len: u64) -> Result<i32, Refuse> {
        let target = self.field(field_off);
        let next = self.pc().wrapping_add(insn_len);
        let d = target.wrapping_sub(next) as i64;
        i32::try_from(d).map_err(|_| Refuse::Unrelocatable {
            src_pc: 0,
            reason: "cache data out of rel32 reach",
        })
    }
    fn map(&mut self, start: u64, len: u64, src_pc: u64, phase: Phase) -> Result<(), Refuse> {
        self.pcmap.push(PcMapEntry {
            gen_start: start,
            gen_end: start.wrapping_add(len),
            src_pc,
            phase,
        })
    }
    fn mov_mem_rax(&mut self, off: usize) -> Result<(), Refuse> {
        let d = self.disp(off, 7)?;
        self.buf.extend_from_slice(&[0x48, 0x89, 0x05]);
        self.buf.extend_from_slice(&d.to_le_bytes());
        Ok(())
    }
    fn mov_rax_mem(&mut self, off: usize) -> Result<(), Refuse> {
        let d = self.disp(off, 7)?;
        self.buf.extend_from_slice(&[0x48, 0x8b, 0x05]);
        self.buf.extend_from_slice(&d.to_le_bytes());
        Ok(())
    }
    fn mov_mem_reg(&mut self, off: usize, reg: u8) -> Result<(), Refuse> {
        let d = self.disp(off, 7)?;
        let rex = 0x48 | if reg >= 8 { 0x04 } else { 0 };
        let modrm = 0x05 | ((reg & 7) << 3);
        self.buf.extend_from_slice(&[rex, 0x89, modrm]);
        self.buf.extend_from_slice(&d.to_le_bytes());
        Ok(())
    }
    fn mov_reg_mem(&mut self, off: usize, reg: u8) -> Result<(), Refuse> {
        let d = self.disp(off, 7)?;
        let rex = 0x48 | if reg >= 8 { 0x04 } else { 0 };
        let modrm = 0x05 | ((reg & 7) << 3);
        self.buf.extend_from_slice(&[rex, 0x8b, modrm]);
        self.buf.extend_from_slice(&d.to_le_bytes());
        Ok(())
    }
    fn jmp_fix(&mut self, target: FixTarget) {
        self.buf.push(0xe9);
        let at = self.buf.len();
        self.buf.extend_from_slice(&[0; 4]);
        self.fixups.push((at, target));
    }
    /// Save RAX + all status flags (via SETO/LAHF) into spill slots.
    /// Every instruction here is itself flag-neutral.
    fn save_rax_flags(&mut self) -> Result<(), Refuse> {
        self.mov_mem_rax(OFF_SPILL_RAX)?;
        self.buf.extend_from_slice(&[0x0f, 0x90, 0xc0]); // seto al
        self.buf.push(0x9f); // lahf
        self.mov_mem_rax(OFF_SPILL_FLAGS)
    }
    /// Restore flags then RAX. `add al,0x7f` re-derives OF from the
    /// saved OF byte; SAHF (which does not touch OF) restores the
    /// remaining status flags.
    fn restore_rax_flags(&mut self) -> Result<(), Refuse> {
        self.mov_rax_mem(OFF_SPILL_FLAGS)?;
        self.buf.extend_from_slice(&[0x04, 0x7f]); // add al,0x7f
        self.buf.push(0x9e); // sahf
        self.mov_rax_mem(OFF_SPILL_RAX)
    }
    fn count_stub_body(&mut self, branch: u64, successor: u64) -> Result<(), Refuse> {
        let start = self.pc();
        self.save_rax_flags()?;
        let d = self.disp(OFF_BRANCH_COUNT, 7)?;
        self.buf.extend_from_slice(&[0x48, 0xff, 0x05]); // inc qword [rip+d]
        self.buf.extend_from_slice(&d.to_le_bytes());
        self.restore_rax_flags()?;
        self.jmp_fix(FixTarget::Block(successor));
        let len = self.pc().wrapping_sub(start);
        self.map(start, len, branch, Phase::CountStub)
    }
    fn block_head_add(&mut self, src: u64, n: u64) -> Result<(), Refuse> {
        if n == 0 {
            return Ok(());
        }
        let start = self.pc();
        self.save_rax_flags()?;
        if let Ok(v) = i8::try_from(i64::try_from(n).unwrap_or(i64::MAX)) {
            let d = self.disp(OFF_INSTRUCTION_COUNT, 8)?;
            self.buf.extend_from_slice(&[0x48, 0x83, 0x05]);
            self.buf.extend_from_slice(&d.to_le_bytes());
            self.buf.push(v as u8);
        } else {
            let v = i32::try_from(n).map_err(|_| Refuse::BudgetExceeded {
                what: "block instruction count",
            })?;
            let d = self.disp(OFF_INSTRUCTION_COUNT, 11)?;
            self.buf.extend_from_slice(&[0x48, 0x81, 0x05]);
            self.buf.extend_from_slice(&d.to_le_bytes());
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
        self.restore_rax_flags()?;
        let len = self.pc().wrapping_sub(start);
        self.map(start, len, src, Phase::CountStub)
    }
    fn exit_stub(&mut self, kind: u64, src: u64, next: u64) -> Result<(), Refuse> {
        let start = self.pc();
        self.mov_mem_rax(OFF_SPILL_RAX)?;
        for (off, val) in [
            (OFF_EXIT_KIND, kind),
            (OFF_EXIT_SRC, src),
            (OFF_EXIT_NEXT, next),
        ] {
            self.buf.extend_from_slice(&[0x48, 0xb8]);
            self.buf.extend_from_slice(&val.to_le_bytes());
            self.mov_mem_rax(off)?;
        }
        self.mov_rax_mem(OFF_SPILL_RAX)?;
        self.jmp_fix(FixTarget::CommonExit);
        let len = self.pc().wrapping_sub(start);
        self.map(start, len, src, Phase::ExitSequence)
    }
    fn request_stub(&mut self, branch: u64, successor: u64) {
        if !self.stubs.contains(&(branch, successor)) {
            self.stubs.push((branch, successor));
        }
    }
}

fn cc_value(cc: ConditionCode) -> Option<u8> {
    Some(match cc {
        ConditionCode::o => 0,
        ConditionCode::no => 1,
        ConditionCode::b => 2,
        ConditionCode::ae => 3,
        ConditionCode::e => 4,
        ConditionCode::ne => 5,
        ConditionCode::be => 6,
        ConditionCode::a => 7,
        ConditionCode::s => 8,
        ConditionCode::ns => 9,
        ConditionCode::p => 10,
        ConditionCode::np => 11,
        ConditionCode::l => 12,
        ConditionCode::ge => 13,
        ConditionCode::le => 14,
        ConditionCode::g => 15,
        _ => return None,
    })
}

fn emit_common_exit(e: &mut Emitter) -> Result<u64, Refuse> {
    let at = e.pc();
    e.mov_mem_reg(OFF_STATE + ST_RSP, 4)?;
    // lea rsp, [rip + scratch_top]
    let target = e.field(OFF_SCRATCH).wrapping_add(256);
    let d = i32::try_from(target.wrapping_sub(e.pc().wrapping_add(7)) as i64).map_err(|_| {
        Refuse::Unrelocatable {
            src_pc: 0,
            reason: "scratch stack out of reach",
        }
    })?;
    e.buf.extend_from_slice(&[0x48, 0x8d, 0x25]);
    e.buf.extend_from_slice(&d.to_le_bytes());
    e.buf.push(0x9c); // pushfq (private scratch stack)
    let d = e.disp(OFF_STATE + ST_RFLAGS, 6)?;
    e.buf.extend_from_slice(&[0x8f, 0x05]); // pop qword [rip+d]
    e.buf.extend_from_slice(&d.to_le_bytes());
    for (off, reg) in [
        (ST_RAX, 0u8),
        (ST_RCX, 1),
        (ST_RDX, 2),
        (ST_RBX, 3),
        (ST_RBP, 5),
        (ST_RSI, 6),
        (ST_RDI, 7),
        (ST_R8, 8),
        (ST_R9, 9),
        (ST_R10, 10),
        (ST_R11, 11),
        (ST_R12, 12),
        (ST_R13, 13),
        (ST_R14, 14),
        (ST_R15, 15),
    ] {
        e.mov_mem_reg(OFF_STATE + off, reg)?;
    }
    e.mov_reg_mem(OFF_HOST_RSP, 4)?;
    e.mov_reg_mem(OFF_HOST_RBX, 3)?;
    e.mov_reg_mem(OFF_HOST_RBP, 5)?;
    e.mov_reg_mem(OFF_HOST_R12, 12)?;
    e.mov_reg_mem(OFF_HOST_R13, 13)?;
    e.mov_reg_mem(OFF_HOST_R14, 14)?;
    e.mov_reg_mem(OFF_HOST_R15, 15)?;
    e.buf.push(0xc3); // ret to dispatcher
    Ok(at)
}

/// Translate every block reachable from `entry`. `gen_base` is the
/// address the emitted bytes will execute at; `data_addr` is the
/// address of the allocation's `JitData`.
pub fn translate(
    region: &RegionFacts,
    entry: u64,
    profile: CountProfile,
    gen_base: u64,
    data_addr: u64,
) -> Result<Translation, Refuse> {
    let blocks = discover(region, entry)?;
    let mut e = Emitter {
        buf: Vec::new(),
        gen_base,
        data_addr,
        pcmap: PcMap::new(),
        fixups: Vec::new(),
        stubs: Vec::new(),
    };
    let mut block_gen: BTreeMap<u64, u64> = BTreeMap::new();
    let mut stub_gen: HashMap<(u64, u64), u64> = HashMap::new();
    for block in blocks.values() {
        block_gen.insert(block.start, e.pc());
        if profile == CountProfile::BranchesAndInstructions {
            e.block_head_add(block.start, block.instruction_total())?;
        }
        for insn in &block.insns {
            let start = e.pc();
            if insn.instruction.is_ip_rel_memory_operand() {
                let mut enc = Encoder::new(64);
                enc.encode(&insn.instruction, start)
                    .map_err(|_| Refuse::Unrelocatable {
                        src_pc: insn.pc,
                        reason: "rip-relative re-encode failed",
                    })?;
                let bytes = enc.take_buffer();
                if bytes.len() != insn.len {
                    return Err(Refuse::Unrelocatable {
                        src_pc: insn.pc,
                        reason: "rip-relative re-encode changed length",
                    });
                }
                e.buf.extend_from_slice(&bytes);
            } else {
                let src = region
                    .slice_from(insn.pc)
                    .ok_or(Refuse::Decode { src_pc: insn.pc })?;
                e.buf.extend_from_slice(&src[..insn.len]);
            }
            e.map(start, insn.len as u64, insn.pc, Phase::Copied)?;
        }
        let term_pc = block.term_pc().unwrap_or(block.start);
        match block.terminator {
            Terminator::Cond {
                target,
                fallthrough,
                loop_like,
            } => {
                e.request_stub(term_pc, target);
                e.request_stub(term_pc, fallthrough);
                let start = e.pc();
                if loop_like {
                    let term = block
                        .term
                        .as_ref()
                        .ok_or(Refuse::Decode { src_pc: term_pc })?;
                    let mut ins = term.instruction;
                    ins.set_near_branch64(start.wrapping_add(2 + 5));
                    let mut enc = Encoder::new(64);
                    let n = enc.encode(&ins, start).map_err(|_| Refuse::Unrelocatable {
                        src_pc: term_pc,
                        reason: "loop-like re-encode failed",
                    })?;
                    if n != 2 {
                        return Err(Refuse::Unrelocatable {
                            src_pc: term_pc,
                            reason: "loop-like re-encode not rel8",
                        });
                    }
                    e.buf.extend_from_slice(&enc.take_buffer());
                    e.jmp_fix(FixTarget::CountStub {
                        branch: term_pc,
                        successor: fallthrough,
                    });
                    e.jmp_fix(FixTarget::CountStub {
                        branch: term_pc,
                        successor: target,
                    });
                } else {
                    let term = block
                        .term
                        .as_ref()
                        .ok_or(Refuse::Decode { src_pc: term_pc })?;
                    let cc = cc_value(term.instruction.condition_code()).ok_or(
                        Refuse::Unrelocatable {
                            src_pc: term_pc,
                            reason: "unknown condition code",
                        },
                    )?;
                    e.buf.extend_from_slice(&[0x0f, 0x80 + cc]);
                    let at = e.buf.len();
                    e.buf.extend_from_slice(&[0; 4]);
                    e.fixups.push((
                        at,
                        FixTarget::CountStub {
                            branch: term_pc,
                            successor: target,
                        },
                    ));
                    e.jmp_fix(FixTarget::CountStub {
                        branch: term_pc,
                        successor: fallthrough,
                    });
                }
                let len = e.pc().wrapping_sub(start);
                e.map(start, len, term_pc, Phase::Copied)?;
            }
            Terminator::Jump { target } => {
                let start = e.pc();
                e.jmp_fix(FixTarget::Block(target));
                e.map(start, 5, term_pc, Phase::Copied)?;
            }
            Terminator::Call { target, return_pc } => {
                let start = e.pc();
                e.mov_mem_rax(OFF_SPILL_RAX)?;
                e.buf.extend_from_slice(&[0x48, 0xb8]);
                e.buf.extend_from_slice(&return_pc.to_le_bytes());
                e.buf.extend_from_slice(&[0x48, 0x8d, 0x64, 0x24, 0xf8]); // lea rsp,[rsp-8]
                e.buf.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]); // mov [rsp],rax
                e.mov_rax_mem(OFF_SPILL_RAX)?;
                e.jmp_fix(FixTarget::Block(target));
                let len = e.pc().wrapping_sub(start);
                e.map(start, len, term_pc, Phase::CallSequence)?;
            }
            Terminator::Fallthrough { next } => {
                e.jmp_fix(FixTarget::Block(next));
            }
            Terminator::Return => {
                e.exit_stub(exit_kind::RETURN, term_pc, 0)?;
            }
            Terminator::Indirect => {
                e.exit_stub(exit_kind::INDIRECT, term_pc, 0)?;
            }
            Terminator::SyscallExit { next } => {
                e.exit_stub(exit_kind::SYSCALL, term_pc, next)?;
            }
            Terminator::NondetExit { next } => {
                e.exit_stub(exit_kind::NONDET, term_pc, next)?;
            }
        }
    }
    let pending: Vec<(u64, u64)> = e.stubs.clone();
    for (branch, successor) in pending {
        stub_gen.insert((branch, successor), e.pc());
        e.count_stub_body(branch, successor)?;
    }
    let common_exit = emit_common_exit(&mut e)?;
    for (at, target) in std::mem::take(&mut e.fixups) {
        let dest = match target {
            FixTarget::Block(src) => *block_gen
                .get(&src)
                .ok_or(Refuse::InteriorEntry { target: src })?,
            FixTarget::CountStub { branch, successor } => *stub_gen
                .get(&(branch, successor))
                .ok_or(Refuse::InteriorEntry { target: successor })?,
            FixTarget::CommonExit => common_exit,
        };
        let next = gen_base.wrapping_add(at as u64).wrapping_add(4);
        let d =
            i32::try_from(dest.wrapping_sub(next) as i64).map_err(|_| Refuse::Unrelocatable {
                src_pc: 0,
                reason: "block target out of rel32 reach",
            })?;
        e.buf[at..at + 4].copy_from_slice(&d.to_le_bytes());
    }
    Ok(Translation {
        entry_src: entry,
        gen_base,
        code: e.buf,
        pcmap: e.pcmap,
        block_gen,
        blocks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Generation;

    fn region(bytes: Vec<u8>) -> RegionFacts {
        RegionFacts {
            base: 0x10_0000,
            bytes,
            generation: Generation(1),
            immutable_private: true,
        }
    }

    #[test]
    fn writable_region_refuses() {
        let mut r = region(vec![0xc3]);
        r.immutable_private = false;
        assert!(matches!(
            discover(&r, 0x10_0000),
            Err(Refuse::SelfModifyingOrWritableCode { .. })
        ));
    }

    #[test]
    fn discovery_splits_on_branch_targets() {
        // xor eax,eax; inc eax; cmp eax,3; jne -6 (to inc); ret
        let bytes = vec![0x31, 0xc0, 0xff, 0xc0, 0x83, 0xf8, 0x03, 0x75, 0xf9, 0xc3];
        let r = region(bytes);
        let blocks = discover(&r, 0x10_0000).unwrap();
        // entry block (xor) falls through to loop head (inc), loop
        // block ends at jne, exit block is ret.
        assert_eq!(blocks.len(), 3);
        assert!(blocks.contains_key(&0x10_0000));
        assert!(blocks.contains_key(&0x10_0002));
        assert!(blocks.contains_key(&0x10_0009));
    }

    #[test]
    fn interior_target_refuses() {
        // je into byte 1 of the fallthrough mov rax, imm64: both
        // reachable streams claim the same bytes with different
        // boundaries. (An unconditional jump into never-decoded
        // bytes would instead be a legitimate overlapping stream.)
        let bytes = vec![0x74, 0x01, 0x48, 0xb8, 1, 0, 0, 0, 0, 0, 0, 0, 0xc3];
        let r = region(bytes);
        assert!(matches!(
            discover(&r, 0x10_0000),
            Err(Refuse::InteriorEntry { .. })
        ));
    }

    #[test]
    fn translation_maps_every_block() {
        let bytes = vec![0x31, 0xc0, 0xff, 0xc0, 0x83, 0xf8, 0x03, 0x75, 0xf9, 0xc3];
        let r = region(bytes);
        let t = translate(&r, 0x10_0000, CountProfile::Branches, 0x80_0000, 0x81_0000).unwrap();
        assert_eq!(t.block_gen.len(), 3);
        for &g in t.block_gen.values() {
            assert!(t.pcmap.lookup(g).is_some(), "gen {g:#x} unmapped");
        }
    }
}
