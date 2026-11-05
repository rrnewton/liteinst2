//! Generated-PC to source-state recovery map.
//!
//! Every emitted byte belongs to exactly one entry, and machinery
//! sequences are mapped per emitted instruction with a `Recovery`
//! recipe: given the raw interrupted registers plus the spill
//! slots, the recipe reconstructs the precise guest state (next
//! source PC, registers, flags) and whether the in-flight branch /
//! instruction credit is already committed in the counters or
//! still pending. A source-PC label alone is not recovery.

use crate::refuse::Refuse;

/// Which emitted machinery a generated range belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Copied guest instruction (including branch/jump encodings).
    Copied,
    /// Counter stub (branch credit or block instruction credit).
    CountStub,
    /// Direct-call return-address materialization sequence.
    CallSequence,
    /// Exit stub recording the exit kind for the dispatcher.
    ExitSequence,
    /// Common state-export / host-restore epilogue.
    CommonExit,
}

/// Position inside a flag-neutral spill/count stub, by the
/// instruction at this entry's start (not yet executed).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StubStage {
    /// Nothing clobbered yet; credit not stored.
    BeforeCreditPristine,
    /// RAX may hold SETO/LAHF scratch; flags still pristine;
    /// credit not stored. Guest RAX is in `spill_rax`.
    BeforeCreditSpilled,
    /// Credit stored; RAX/flags hold scratch. Guest RAX and flags
    /// reconstruct from `spill_rax`/`spill_flags`.
    AfterCreditSpilled,
    /// Flags restored (SAHF done); guest RAX is in `spill_rax`.
    AfterCreditFlagsRestored,
    /// Fully restored; only the successor jump remains.
    Committed,
}

/// Position inside the direct-call sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallStage {
    /// Nothing clobbered; the call has not retired.
    Pristine,
    /// RAX holds the return address; guest RAX is in `spill_rax`;
    /// RSP not yet decremented. Not retired.
    RaxSpilled,
    /// RSP decremented, store not completed. Undo both. Not retired.
    RspDecremented,
    /// Return address stored; guest RAX is in `spill_rax`. Retired.
    CommittedSpilled,
    /// Fully restored; only the successor jump remains. Retired.
    Committed,
}

/// Position inside an exit stub.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitStage {
    Pristine,
    /// RAX holds an exit field value; guest RAX is in `spill_rax`.
    Spilled,
}

/// Position inside the common exit epilogue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommonStage {
    /// Guest RSP not yet saved; registers are the guest's.
    BeforeRspSave,
    /// Guest RSP is in `state.rsp`; interrupted RSP is scratch.
    RspSaved,
    /// Guest RSP and RFLAGS are in `state`; interrupted flags may
    /// already have been host-cleared (CLD) and must not be used.
    FlagsSaved,
    /// Every guest register is in `state`; interrupted registers
    /// after this point may already hold host values.
    AllSaved,
}

/// How to reconstruct precise guest state when execution stops at
/// this entry's first byte (the entry's instruction not yet run).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recovery {
    /// Copied instruction: registers pristine, next PC is the
    /// instruction itself (not retired).
    Copied,
    /// Branch-credit stub for `branch`, heading to `successor`.
    BranchStub {
        branch: u64,
        successor: u64,
        stage: StubStage,
    },
    /// Block-head instruction-credit stub for `block`.
    InsnCountStub { block: u64, stage: StubStage },
    /// Block-head pending-signal poll stub for `block`; stages
    /// describe spill state only (no guest-visible credit).
    PollStub { block: u64, stage: StubStage },
    /// Direct-call sequence for the call at `call_pc`.
    Call {
        call_pc: u64,
        target: u64,
        stage: CallStage,
    },
    /// Exit stub for the terminator at the entry's source PC.
    ExitStub { stage: ExitStage },
    /// Common epilogue; the terminator source PC is `exit_src` in
    /// the data block, and a stop here is an executor error.
    CommonExit { stage: CommonStage },
    /// Plain jump to the next block (fallthrough split): the
    /// previous block fully retired, `next` not yet entered.
    Fallthrough { next: u64 },
}

/// One half-open generated range `[gen_start, gen_end)` recovering
/// to `src_pc` (plus offset within a `Copied` instruction only for
/// raw lookup; state recovery is defined at entry starts).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcMapEntry {
    pub gen_start: u64,
    pub gen_end: u64,
    pub src_pc: u64,
    pub phase: Phase,
    pub recovery: Recovery,
}

impl PcMapEntry {
    pub fn recover(&self, g: u64) -> u64 {
        match self.phase {
            Phase::Copied => self.src_pc.wrapping_add(g.wrapping_sub(self.gen_start)),
            _ => self.src_pc,
        }
    }
}

/// Sorted, non-overlapping PC map for one cache allocation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PcMap {
    entries: Vec<PcMapEntry>,
}

impl PcMap {
    pub fn new() -> PcMap {
        PcMap {
            entries: Vec::new(),
        }
    }

    pub fn push(&mut self, e: PcMapEntry) -> Result<(), Refuse> {
        if e.gen_end <= e.gen_start {
            return Err(Refuse::Unrelocatable {
                src_pc: e.src_pc,
                reason: "empty pc-map range",
            });
        }
        if let Some(last) = self.entries.last()
            && e.gen_start < last.gen_end
        {
            return Err(Refuse::Unrelocatable {
                src_pc: e.src_pc,
                reason: "overlapping pc-map range",
            });
        }
        self.entries.push(e);
        Ok(())
    }

    pub fn lookup(&self, gen_pc: u64) -> Option<&PcMapEntry> {
        let idx = self
            .entries
            .partition_point(|e| e.gen_start <= gen_pc)
            .checked_sub(1)?;
        let e = &self.entries[idx];
        (gen_pc < e.gen_end).then_some(e)
    }

    pub fn recover(&self, gen_pc: u64) -> Option<u64> {
        self.lookup(gen_pc).map(|e| e.recover(gen_pc))
    }

    pub fn entries(&self) -> &[PcMapEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PcMap {
        let mut m = PcMap::new();
        m.push(PcMapEntry {
            gen_start: 0x8000,
            gen_end: 0x8005,
            src_pc: 0x1000,
            phase: Phase::Copied,
            recovery: Recovery::Copied,
        })
        .unwrap();
        m.push(PcMapEntry {
            gen_start: 0x8005,
            gen_end: 0x8015,
            src_pc: 0x1005,
            phase: Phase::CountStub,
            recovery: Recovery::BranchStub {
                branch: 0x1000,
                successor: 0x1005,
                stage: StubStage::BeforeCreditPristine,
            },
        })
        .unwrap();
        m
    }

    #[test]
    fn copied_is_offset_preserving() {
        let m = sample();
        assert_eq!(m.recover(0x8000), Some(0x1000));
        assert_eq!(m.recover(0x8003), Some(0x1003));
        assert_eq!(m.recover(0x8004), Some(0x1004));
    }

    #[test]
    fn stub_recovers_successor_for_whole_range() {
        let m = sample();
        for g in 0x8005..0x8015 {
            assert_eq!(m.recover(g), Some(0x1005), "gen {g:#x}");
        }
    }

    #[test]
    fn gaps_and_bounds_miss() {
        let m = sample();
        assert_eq!(m.recover(0x7fff), None);
        assert_eq!(m.recover(0x8015), None);
    }

    #[test]
    fn overlap_and_empty_refuse() {
        let mut m = sample();
        assert!(
            m.push(PcMapEntry {
                gen_start: 0x8010,
                gen_end: 0x8020,
                src_pc: 0x1006,
                phase: Phase::Copied,
                recovery: Recovery::Copied,
            })
            .is_err()
        );
    }
}
