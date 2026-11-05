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

use crate::decode::{DecodedInsn, InsnClass, decode_supported};
use crate::pcmap::{
    CallStage, CommonStage, ExitStage, PcMap, PcMapEntry, Phase, Recovery, StubStage,
};
use crate::refuse::Refuse;
use crate::state::SCRATCH_LEN;
use crate::state::{
    OFF_BRANCH_COUNT, OFF_EXIT_KIND, OFF_EXIT_NEXT, OFF_EXIT_SRC, OFF_HOST_R12, OFF_HOST_R13,
    OFF_HOST_R14, OFF_HOST_R15, OFF_HOST_RBP, OFF_HOST_RBX, OFF_HOST_RSP, OFF_INSTRUCTION_COUNT,
    OFF_POLL, OFF_SCRATCH, OFF_SPILL_FLAGS, OFF_SPILL_RAX, OFF_STATE, ST_R8, ST_R9, ST_R10, ST_R11,
    ST_R12, ST_R13, ST_R14, ST_R15, ST_RAX, ST_RBP, ST_RBX, ST_RCX, ST_RDI, ST_RDX, ST_RFLAGS,
    ST_RSI, ST_RSP, exit_kind,
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
    Return {
        pop_extra: u16,
    },
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
            let d = decode_supported(bytes, pc)?;
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
                InsnClass::Return => {
                    let pop_extra = if d.instruction.op_count() == 1 {
                        d.instruction.immediate16()
                    } else {
                        0
                    };
                    break (Some(pc), Terminator::Return { pop_extra }, vec![]);
                }
                InsnClass::Indirect => break (Some(pc), Terminator::Indirect, vec![]),
                InsnClass::Syscall => {
                    break (Some(pc), Terminator::SyscallExit { next }, vec![next]);
                }
                InsnClass::Nondet(_) => {
                    break (Some(pc), Terminator::NondetExit { next }, vec![next]);
                }
            }
        };
        // Re-decode the terminator instruction for emission needs
        // (condition code, loop-like re-encode).
        let term = match term_pc {
            Some(tp) => Some(decode_supported(
                region.slice_from(tp).ok_or(Refuse::Decode { src_pc: tp })?,
                tp,
            )?),
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
    PollExit(u64),
    CommonExit,
}

#[derive(Clone, Copy)]
enum StubKind {
    Branch { branch: u64, successor: u64 },
    Insn { block: u64 },
}

struct Emitter {
    buf: Vec<u8>,
    gen_base: u64,
    data_addr: u64,
    pcmap: PcMap,
    fixups: Vec<(usize, FixTarget)>,
    stubs: Vec<(u64, u64)>,
    poll_exits: Vec<u64>,
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
    fn map(
        &mut self,
        start: u64,
        len: u64,
        src_pc: u64,
        phase: Phase,
        recovery: Recovery,
    ) -> Result<(), Refuse> {
        self.pcmap.push(PcMapEntry {
            gen_start: start,
            gen_end: start.wrapping_add(len),
            src_pc,
            phase,
            recovery,
        })
    }
    /// Emit one machinery instruction and map exactly its bytes
    /// with the recovery recipe for a stop at its first byte.
    fn seg(
        &mut self,
        src_pc: u64,
        phase: Phase,
        recovery: Recovery,
        emit: impl FnOnce(&mut Self) -> Result<(), Refuse>,
    ) -> Result<(), Refuse> {
        let start = self.pc();
        emit(self)?;
        let len = self.pc().wrapping_sub(start);
        self.map(start, len, src_pc, phase, recovery)
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
    /// Flag-neutral spill/count stub, mapped per instruction.
    /// `branch` is Some for a branch-credit stub (successor jump
    /// appended), None for a block-head instruction-credit stub.
    fn credit_stub(
        &mut self,
        counter_off: usize,
        amount: u64,
        branch: Option<(u64, u64)>,
        block: u64,
    ) -> Result<(), Refuse> {
        let (src, mk) = match branch {
            Some((b, succ)) => (
                succ,
                StubKind::Branch {
                    branch: b,
                    successor: succ,
                },
            ),
            None => (block, StubKind::Insn { block }),
        };
        let rec = |stage: StubStage| match mk {
            StubKind::Branch { branch, successor } => Recovery::BranchStub {
                branch,
                successor,
                stage,
            },
            StubKind::Insn { block } => Recovery::InsnCountStub { block, stage },
        };
        use StubStage::*;
        self.seg(src, Phase::CountStub, rec(BeforeCreditPristine), |e| {
            e.mov_mem_rax(OFF_SPILL_RAX)
        })?;
        self.seg(src, Phase::CountStub, rec(BeforeCreditPristine), |e| {
            e.buf.extend_from_slice(&[0x0f, 0x90, 0xc0]); // seto al
            Ok(())
        })?;
        self.seg(src, Phase::CountStub, rec(BeforeCreditSpilled), |e| {
            e.buf.push(0x9f); // lahf
            Ok(())
        })?;
        self.seg(src, Phase::CountStub, rec(BeforeCreditSpilled), |e| {
            e.mov_mem_rax(OFF_SPILL_FLAGS)
        })?;
        self.seg(src, Phase::CountStub, rec(BeforeCreditSpilled), |e| {
            if amount == 1 {
                let d = e.disp(counter_off, 7)?;
                e.buf.extend_from_slice(&[0x48, 0xff, 0x05]);
                e.buf.extend_from_slice(&d.to_le_bytes());
            } else if let Ok(v) = i8::try_from(i64::try_from(amount).unwrap_or(i64::MAX)) {
                let d = e.disp(counter_off, 8)?;
                e.buf.extend_from_slice(&[0x48, 0x83, 0x05]);
                e.buf.extend_from_slice(&d.to_le_bytes());
                e.buf.push(v as u8);
            } else {
                let v = i32::try_from(amount).map_err(|_| Refuse::BudgetExceeded {
                    what: "block instruction count",
                })?;
                let d = e.disp(counter_off, 11)?;
                e.buf.extend_from_slice(&[0x48, 0x81, 0x05]);
                e.buf.extend_from_slice(&d.to_le_bytes());
                e.buf.extend_from_slice(&v.to_le_bytes());
            }
            Ok(())
        })?;
        self.seg(src, Phase::CountStub, rec(AfterCreditSpilled), |e| {
            e.mov_rax_mem(OFF_SPILL_FLAGS)
        })?;
        self.seg(src, Phase::CountStub, rec(AfterCreditSpilled), |e| {
            e.buf.extend_from_slice(&[0x04, 0x7f]); // add al,0x7f (OF)
            Ok(())
        })?;
        self.seg(src, Phase::CountStub, rec(AfterCreditSpilled), |e| {
            e.buf.push(0x9e); // sahf
            Ok(())
        })?;
        self.seg(src, Phase::CountStub, rec(AfterCreditFlagsRestored), |e| {
            e.mov_rax_mem(OFF_SPILL_RAX)
        })?;
        if let StubKind::Branch { successor, .. } = mk {
            self.seg(src, Phase::CountStub, rec(Committed), |e| {
                e.jmp_fix(FixTarget::Block(successor));
                Ok(())
            })?;
        }
        Ok(())
    }
    fn count_stub_body(&mut self, branch: u64, successor: u64) -> Result<(), Refuse> {
        self.credit_stub(OFF_BRANCH_COUNT, 1, Some((branch, successor)), 0)
    }
    fn block_head_add(&mut self, src: u64, n: u64) -> Result<(), Refuse> {
        if n == 0 {
            return Ok(());
        }
        self.credit_stub(OFF_INSTRUCTION_COUNT, n, None, src)
    }
    /// Block-head pending-signal poll: decrement the per-entry
    /// budget; on exhaustion exit to the dispatcher (which checks
    /// for pending asynchronous signals) instead of continuing.
    /// Flag-neutral and mapped per instruction like credit stubs.
    fn poll_stub(&mut self, block: u64) -> Result<(), Refuse> {
        use StubStage::*;
        let rec = |stage: StubStage| Recovery::PollStub { block, stage };
        if !self.poll_exits.contains(&block) {
            self.poll_exits.push(block);
        }
        self.seg(block, Phase::CountStub, rec(BeforeCreditPristine), |e| {
            e.mov_mem_rax(OFF_SPILL_RAX)
        })?;
        self.seg(block, Phase::CountStub, rec(BeforeCreditPristine), |e| {
            e.buf.extend_from_slice(&[0x0f, 0x90, 0xc0]);
            Ok(())
        })?;
        self.seg(block, Phase::CountStub, rec(BeforeCreditSpilled), |e| {
            e.buf.push(0x9f);
            Ok(())
        })?;
        self.seg(block, Phase::CountStub, rec(BeforeCreditSpilled), |e| {
            e.mov_mem_rax(OFF_SPILL_FLAGS)
        })?;
        self.seg(block, Phase::CountStub, rec(BeforeCreditSpilled), |e| {
            let d = e.disp(OFF_POLL, 7)?;
            e.buf.extend_from_slice(&[0x48, 0xff, 0x0d]); // dec qword [rip+d]
            e.buf.extend_from_slice(&d.to_le_bytes());
            Ok(())
        })?;
        // jnz continue_restore (disp covers restore-A + jmp = 22)
        self.seg(block, Phase::CountStub, rec(AfterCreditSpilled), |e| {
            e.buf.extend_from_slice(&[0x75, 22]);
            Ok(())
        })?;
        // Poll path: restore, then exit to the dispatcher poll.
        self.seg(block, Phase::CountStub, rec(AfterCreditSpilled), |e| {
            e.mov_rax_mem(OFF_SPILL_FLAGS)
        })?;
        self.seg(block, Phase::CountStub, rec(AfterCreditSpilled), |e| {
            e.buf.extend_from_slice(&[0x04, 0x7f]);
            Ok(())
        })?;
        self.seg(block, Phase::CountStub, rec(AfterCreditSpilled), |e| {
            e.buf.push(0x9e);
            Ok(())
        })?;
        self.seg(
            block,
            Phase::CountStub,
            rec(AfterCreditFlagsRestored),
            |e| e.mov_rax_mem(OFF_SPILL_RAX),
        )?;
        self.seg(block, Phase::CountStub, rec(Committed), |e| {
            e.jmp_fix(FixTarget::PollExit(block));
            Ok(())
        })?;
        // Continue path: restore and fall into the block body.
        self.seg(block, Phase::CountStub, rec(AfterCreditSpilled), |e| {
            e.mov_rax_mem(OFF_SPILL_FLAGS)
        })?;
        self.seg(block, Phase::CountStub, rec(AfterCreditSpilled), |e| {
            e.buf.extend_from_slice(&[0x04, 0x7f]);
            Ok(())
        })?;
        self.seg(block, Phase::CountStub, rec(AfterCreditSpilled), |e| {
            e.buf.push(0x9e);
            Ok(())
        })?;
        self.seg(
            block,
            Phase::CountStub,
            rec(AfterCreditFlagsRestored),
            |e| e.mov_rax_mem(OFF_SPILL_RAX),
        )
    }
    fn exit_stub(&mut self, kind: u64, src: u64, next: u64) -> Result<(), Refuse> {
        self.exit_stub_poll(kind, src, next, false)
    }
    fn exit_stub_poll(&mut self, kind: u64, src: u64, next: u64, poll: bool) -> Result<(), Refuse> {
        use ExitStage::*;
        self.seg(
            src,
            Phase::ExitSequence,
            if poll {
                Recovery::PollExitStub { stage: Pristine }
            } else {
                Recovery::ExitStub { stage: Pristine }
            },
            |e| e.mov_mem_rax(OFF_SPILL_RAX),
        )?;
        for (off, val) in [
            (OFF_EXIT_KIND, kind),
            (OFF_EXIT_SRC, src),
            (OFF_EXIT_NEXT, next),
        ] {
            self.seg(
                src,
                Phase::ExitSequence,
                if poll {
                    Recovery::PollExitStub { stage: Spilled }
                } else {
                    Recovery::ExitStub { stage: Spilled }
                },
                |e| {
                    e.buf.extend_from_slice(&[0x48, 0xb8]);
                    e.buf.extend_from_slice(&val.to_le_bytes());
                    Ok(())
                },
            )?;
            self.seg(
                src,
                Phase::ExitSequence,
                if poll {
                    Recovery::PollExitStub { stage: Spilled }
                } else {
                    Recovery::ExitStub { stage: Spilled }
                },
                |e| e.mov_mem_rax(off),
            )?;
        }
        self.seg(
            src,
            Phase::ExitSequence,
            if poll {
                Recovery::PollExitStub { stage: Spilled }
            } else {
                Recovery::ExitStub { stage: Spilled }
            },
            |e| e.mov_rax_mem(OFF_SPILL_RAX),
        )?;
        self.seg(
            src,
            Phase::ExitSequence,
            if poll {
                Recovery::PollExitStub { stage: Pristine }
            } else {
                Recovery::ExitStub { stage: Pristine }
            },
            |e| {
                e.jmp_fix(FixTarget::CommonExit);
                Ok(())
            },
        )
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
    use CommonStage::*;
    let at = e.pc();
    let rec = |stage: CommonStage| Recovery::CommonExit { stage };
    e.seg(0, Phase::CommonExit, rec(BeforeRspSave), |e| {
        e.mov_mem_reg(OFF_STATE + ST_RSP, 4)
    })?;
    e.seg(0, Phase::CommonExit, rec(RspSaved), |e| {
        // lea rsp, [rip + scratch_top]
        let target = e.field(OFF_SCRATCH).wrapping_add(SCRATCH_LEN as u64);
        let d =
            i32::try_from(target.wrapping_sub(e.pc().wrapping_add(7)) as i64).map_err(|_| {
                Refuse::Unrelocatable {
                    src_pc: 0,
                    reason: "scratch stack out of reach",
                }
            })?;
        e.buf.extend_from_slice(&[0x48, 0x8d, 0x25]);
        e.buf.extend_from_slice(&d.to_le_bytes());
        Ok(())
    })?;
    e.seg(0, Phase::CommonExit, rec(RspSaved), |e| {
        e.buf.push(0x9c); // pushfq (private scratch stack)
        Ok(())
    })?;
    e.seg(0, Phase::CommonExit, rec(RspSaved), |e| {
        let d = e.disp(OFF_STATE + ST_RFLAGS, 6)?;
        e.buf.extend_from_slice(&[0x8f, 0x05]); // pop qword [rip+d]
        e.buf.extend_from_slice(&d.to_le_bytes());
        Ok(())
    })?;
    // Guest flags are captured; host code after this point runs
    // under the SysV ABI, which requires DF clear. The guest DF
    // survives in state.rflags and is restored by iret on re-entry.
    e.seg(0, Phase::CommonExit, rec(CommonStage::FlagsSaved), |e| {
        e.buf.push(0xfc); // cld
        Ok(())
    })?;
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
        e.seg(0, Phase::CommonExit, rec(FlagsSaved), |e| {
            e.mov_mem_reg(OFF_STATE + off, reg)
        })?;
    }
    e.seg(0, Phase::CommonExit, rec(AllSaved), |e| {
        e.mov_reg_mem(OFF_HOST_RSP, 4)
    })?;
    e.seg(0, Phase::CommonExit, rec(AllSaved), |e| {
        e.mov_reg_mem(OFF_HOST_RBX, 3)
    })?;
    e.seg(0, Phase::CommonExit, rec(AllSaved), |e| {
        e.mov_reg_mem(OFF_HOST_RBP, 5)
    })?;
    e.seg(0, Phase::CommonExit, rec(AllSaved), |e| {
        e.mov_reg_mem(OFF_HOST_R12, 12)
    })?;
    e.seg(0, Phase::CommonExit, rec(AllSaved), |e| {
        e.mov_reg_mem(OFF_HOST_R13, 13)
    })?;
    e.seg(0, Phase::CommonExit, rec(AllSaved), |e| {
        e.mov_reg_mem(OFF_HOST_R14, 14)
    })?;
    e.seg(0, Phase::CommonExit, rec(AllSaved), |e| {
        e.mov_reg_mem(OFF_HOST_R15, 15)
    })?;
    e.seg(0, Phase::CommonExit, rec(AllSaved), |e| {
        e.buf.push(0xc3); // ret to dispatcher
        Ok(())
    })?;
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
        poll_exits: Vec::new(),
    };
    let mut block_gen: BTreeMap<u64, u64> = BTreeMap::new();
    let mut stub_gen: HashMap<(u64, u64), u64> = HashMap::new();
    for block in blocks.values() {
        block_gen.insert(block.start, e.pc());
        e.poll_stub(block.start)?;
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
            e.map(
                start,
                insn.len as u64,
                insn.pc,
                Phase::Copied,
                Recovery::Copied,
            )?;
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
                    e.map(start, 2, term_pc, Phase::Copied, Recovery::Copied)?;
                    let ft = e.pc();
                    e.jmp_fix(FixTarget::CountStub {
                        branch: term_pc,
                        successor: fallthrough,
                    });
                    e.map(
                        ft,
                        5,
                        fallthrough,
                        Phase::CountStub,
                        Recovery::BranchStub {
                            branch: term_pc,
                            successor: fallthrough,
                            stage: StubStage::BeforeCreditPristine,
                        },
                    )?;
                    let tk = e.pc();
                    e.jmp_fix(FixTarget::CountStub {
                        branch: term_pc,
                        successor: target,
                    });
                    e.map(
                        tk,
                        5,
                        target,
                        Phase::CountStub,
                        Recovery::BranchStub {
                            branch: term_pc,
                            successor: target,
                            stage: StubStage::BeforeCreditPristine,
                        },
                    )?;
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
                    e.map(start, 6, term_pc, Phase::Copied, Recovery::Copied)?;
                    let ft = e.pc();
                    e.jmp_fix(FixTarget::CountStub {
                        branch: term_pc,
                        successor: fallthrough,
                    });
                    e.map(
                        ft,
                        5,
                        fallthrough,
                        Phase::CountStub,
                        Recovery::BranchStub {
                            branch: term_pc,
                            successor: fallthrough,
                            stage: StubStage::BeforeCreditPristine,
                        },
                    )?;
                }
            }
            Terminator::Jump { target } => {
                let start = e.pc();
                e.jmp_fix(FixTarget::Block(target));
                e.map(start, 5, term_pc, Phase::Copied, Recovery::Copied)?;
            }
            Terminator::Call { target, return_pc } => {
                use CallStage::*;
                let rec = |stage: CallStage| Recovery::Call {
                    call_pc: term_pc,
                    target,
                    stage,
                };
                e.seg(term_pc, Phase::CallSequence, rec(Pristine), |e| {
                    e.mov_mem_rax(OFF_SPILL_RAX)
                })?;
                e.seg(term_pc, Phase::CallSequence, rec(Pristine), |e| {
                    e.buf.extend_from_slice(&[0x48, 0xb8]);
                    e.buf.extend_from_slice(&return_pc.to_le_bytes());
                    Ok(())
                })?;
                e.seg(term_pc, Phase::CallSequence, rec(RaxSpilled), |e| {
                    e.buf.extend_from_slice(&[0x48, 0x8d, 0x64, 0x24, 0xf8]);
                    Ok(())
                })?;
                e.seg(term_pc, Phase::CallSequence, rec(RspDecremented), |e| {
                    e.buf.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]);
                    Ok(())
                })?;
                e.seg(target, Phase::CallSequence, rec(CommittedSpilled), |e| {
                    e.mov_rax_mem(OFF_SPILL_RAX)
                })?;
                e.seg(target, Phase::CallSequence, rec(Committed), |e| {
                    e.jmp_fix(FixTarget::Block(target));
                    Ok(())
                })?;
            }
            Terminator::Fallthrough { next } => {
                e.seg(next, Phase::Copied, Recovery::Fallthrough { next }, |e| {
                    e.jmp_fix(FixTarget::Block(next));
                    Ok(())
                })?;
            }
            Terminator::Return { pop_extra } => {
                e.exit_stub(exit_kind::RETURN, term_pc, u64::from(pop_extra))?;
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
    let mut poll_gen: HashMap<u64, u64> = HashMap::new();
    let pending_polls: Vec<u64> = e.poll_exits.clone();
    for block in pending_polls {
        poll_gen.insert(block, e.pc());
        e.exit_stub_poll(exit_kind::POLL, block, block, true)?;
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
            FixTarget::PollExit(block) => *poll_gen
                .get(&block)
                .ok_or(Refuse::InteriorEntry { target: block })?,
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
    fn envelope_refuses_by_default() {
        // One representative per refused family; each must refuse
        // by name instead of being copied as Ordinary (F4).
        let cases: &[(&str, &[u8])] = &[
            ("wrfsbase", &[0xf3, 0x48, 0x0f, 0xae, 0xd8, 0xc3]),
            ("hlt", &[0xf4, 0xc3]),
            ("int3", &[0xcc, 0xc3]),
            ("rdpmc", &[0x0f, 0x33, 0xc3]),
            ("xbegin", &[0xc7, 0xf8, 0x00, 0x00, 0x00, 0x00, 0xc3]),
            ("fxsave", &[0x0f, 0xae, 0x00, 0xc3]),
            ("movaps-xmm", &[0x0f, 0x28, 0xc1, 0xc3]),
            ("popfq", &[0x9d, 0xc3]),
            ("swapgs", &[0x0f, 0x01, 0xf8, 0xc3]),
            ("fs-load", &[0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0xc3]),
            // R1 hidden-state families (decode-only; never executed).
            ("wrpkru", &[0x0f, 0x01, 0xef, 0xc3]),
            ("rdpkru", &[0x0f, 0x01, 0xee, 0xc3]),
            ("rdpru", &[0x0f, 0x01, 0xfd, 0xc3]),
            ("mwaitx", &[0x0f, 0x01, 0xfb, 0xc3]),
            ("monitorx", &[0x0f, 0x01, 0xfa, 0xc3]),
            ("ldmxcsr", &[0x0f, 0xae, 0x10, 0xc3]),
            ("fninit", &[0xdb, 0xe3, 0xc3]),
            ("fldcw", &[0xd9, 0x28, 0xc3]),
            ("fnstenv", &[0xd9, 0x30, 0xc3]),
            ("fxrstor64", &[0x48, 0x0f, 0xae, 0x08, 0xc3]),
            ("xrstor64", &[0x48, 0x0f, 0xae, 0x28, 0xc3]),
            ("xsavec", &[0x0f, 0xc7, 0x20, 0xc3]),
            ("umonitor", &[0xf3, 0x48, 0x0f, 0xae, 0xf0, 0xc3]),
            ("emms", &[0x0f, 0x77, 0xc3]),
            ("femms", &[0x0f, 0x0e, 0xc3]),
            // Round-3 alternate encodings of the same families.
            ("wrpkru-rerex", &[0x40, 0x40, 0x0f, 0x01, 0xef, 0xc3]),
            ("fninit-rerex", &[0x40, 0x40, 0xdb, 0xe3, 0xc3]),
            ("fninit-rex-legacy", &[0x40, 0x66, 0xdb, 0xe3, 0xc3]),
            ("vldmxcsr", &[0xc5, 0xf8, 0xae, 0x10, 0xc3]),
            ("vstmxcsr", &[0xc5, 0xf8, 0xae, 0x18, 0xc3]),
            ("sttilecfg", &[0xc4, 0xe2, 0x79, 0x49, 0x00, 0xc3]),
            ("senduipi", &[0xf3, 0x0f, 0xc7, 0xf0, 0xc3]),
        ];
        for (name, bytes) in cases {
            let r = region(bytes.to_vec());
            let out = discover(&r, 0x10_0000);
            assert!(
                matches!(out, Err(Refuse::Unrelocatable { .. })),
                "{name}: got {out:?}"
            );
        }
    }

    #[test]
    fn every_emitted_byte_is_mapped_contiguously() {
        // The exact Astra F1 counterexample shape, both profiles.
        let bytes = vec![0x31, 0xc0, 0xff, 0xc0, 0x83, 0xf8, 0x03, 0x75, 0xf9, 0xc3];
        for profile in [
            CountProfile::Branches,
            CountProfile::BranchesAndInstructions,
        ] {
            let r = region(bytes.clone());
            let t = translate(&r, 0x10_0000, profile, 0x80_0000, 0x81_0000).unwrap();
            let unmapped = (0..t.code.len() as u64)
                .filter(|&i| t.pcmap.lookup(0x80_0000 + i).is_none())
                .count();
            assert_eq!(unmapped, 0, "profile {profile:?}");
            let mut expect = 0x80_0000u64;
            for e in t.pcmap.entries() {
                assert_eq!(e.gen_start, expect, "gap before {e:?}");
                expect = e.gen_end;
            }
            assert_eq!(expect, 0x80_0000 + t.code.len() as u64);
        }
        // Machinery-heavy translation (calls, stubs, exits).
        let fix = crate::fixtures::by_name("call_helper");
        let r = region(fix.bytes);
        let t = translate(
            &r,
            0x10_0000,
            CountProfile::BranchesAndInstructions,
            0x80_0000,
            0x81_0000,
        )
        .unwrap();
        assert!(
            (0..t.code.len() as u64).all(|i| t.pcmap.lookup(0x80_0000 + i).is_some()),
            "call_helper has unmapped emitted bytes"
        );
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
