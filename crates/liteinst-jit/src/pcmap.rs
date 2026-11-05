//! Generated-PC to source-PC map, phased from the first commit.
//!
//! Every emitted byte range belongs to exactly one entry. `Copied`
//! ranges are offset-preserving: a fault at generated PC `g` inside a
//! copied instruction recovers source PC `src + (g - start)`. Stub
//! ranges name the source instruction whose retirement they complete,
//! so an interruption between a branch and its counter increment is
//! resolvable from the PC alone and is credited exactly once.

use crate::refuse::Refuse;

/// Which emitted machinery a generated range belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Verbatim (possibly displacement-fixed) guest instruction.
    Copied,
    /// Flag-neutral counter stub on a branch successor edge. Entering
    /// this range means the named branch has retired; the increment
    /// inside it is the credit.
    CountStub,
    /// Flag-neutral sequence pushing a source return address for a
    /// direct call.
    CallSequence,
    /// State-export / dispatcher exit sequence.
    ExitSequence,
}

/// One half-open generated range `[gen_start, gen_end)` recovering to
/// source PC `src_pc` (plus offset, for `Phase::Copied`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcMapEntry {
    pub gen_start: u64,
    pub gen_end: u64,
    pub src_pc: u64,
    pub phase: Phase,
}

impl PcMapEntry {
    /// Recover the precise source PC for generated PC `g`, which must
    /// lie inside this entry.
    pub fn recover(&self, g: u64) -> u64 {
        match self.phase {
            Phase::Copied => self.src_pc.wrapping_add(g.wrapping_sub(self.gen_start)),
            Phase::CountStub | Phase::CallSequence | Phase::ExitSequence => self.src_pc,
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

    /// Append an entry. Entries must be appended in increasing,
    /// non-overlapping order; anything else refuses.
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

    /// Precise source PC for any generated PC, if covered.
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
        })
        .unwrap();
        m.push(PcMapEntry {
            gen_start: 0x8005,
            gen_end: 0x8015,
            src_pc: 0x1005,
            phase: Phase::CountStub,
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
    fn stub_recovers_branch_pc_for_whole_range() {
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
        assert!(matches!(
            m.push(PcMapEntry {
                gen_start: 0x8010,
                gen_end: 0x8020,
                src_pc: 0x1006,
                phase: Phase::Copied,
            }),
            Err(Refuse::Unrelocatable { .. })
        ));
        assert!(matches!(
            m.push(PcMapEntry {
                gen_start: 0x8020,
                gen_end: 0x8020,
                src_pc: 0x1006,
                phase: Phase::Copied,
            }),
            Err(Refuse::Unrelocatable { .. })
        ));
    }
}
