//! Raw callback-positioned endpoints. No calibration or accuracy claim.
use super::{BridgeError, Cause, error};
use crate::frontend::{IntervalEntrySummary, Observation, UnsampledSummary};

/// Uncorrected RDTSCP observation, acquired after application-state save.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawTimestamp {
    pub ticks: u64,
    pub aux: u32,
}

/// Diagnostic ownership only; no receipt, ticket or epoch can be extracted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawIntervalOwner {
    Sampled { generation: u64, invocation: usize },
    InitialDisarmed,
    Removed { generation: u64 },
    FunctionClosed { generation: u64 },
}

/// One real entry/original-RET pair, including unsampled invocations.
/// Endpoints include callback/trampoline and descheduling costs. Ticks are not
/// nanoseconds, core cycles or overhead-corrected application work.
/// With concurrent activation, start precedes controller-lock waiting; ownership
/// is selected at reservation after that wait, not at the raw start timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawInterval {
    pub ordinal: u64,
    pub entry_pc: u64,
    pub return_pc: u64,
    pub owner: RawIntervalOwner,
    pub start: RawTimestamp,
    pub end: RawTimestamp,
}
impl RawInterval {
    /// Equal AUX and monotonic endpoints permit a raw difference only. They do
    /// not establish uninterrupted execution or calibrated timing accuracy.
    pub fn elapsed_ticks(&self) -> Option<u64> {
        (self.start.aux == self.end.aux)
            .then(|| self.end.ticks.checked_sub(self.start.ticks))
            .flatten()
    }
    pub(super) fn observation(&self) -> Observation {
        if self.start.aux != self.end.aux {
            Observation::Unavailable(1)
        } else if self.end.ticks < self.start.ticks {
            Observation::Unavailable(2)
        } else {
            Observation::Value(self.end.ticks)
        }
    }
}
pub(super) fn owner(summary: IntervalEntrySummary) -> RawIntervalOwner {
    match summary {
        IntervalEntrySummary::Admitted {
            generation,
            invocation,
            ..
        } => RawIntervalOwner::Sampled {
            generation: generation.get(),
            invocation,
        },
        IntervalEntrySummary::Unsampled { reason, .. } => match reason {
            UnsampledSummary::InitialDisarmed => RawIntervalOwner::InitialDisarmed,
            UnsampledSummary::Removed { generation } => RawIntervalOwner::Removed {
                generation: generation.get(),
            },
            UnsampledSummary::FunctionClosed { generation, .. } => {
                RawIntervalOwner::FunctionClosed {
                    generation: generation.get(),
                }
            }
        },
    }
}

pub(super) fn supported() -> bool {
    std::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_0001
        && std::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 27) != 0
}
/// # Safety
/// The separate ordinary factory checked RDTSCP before any publication.
pub(super) unsafe fn read() -> RawTimestamp {
    let (lo, hi, aux): (u32, u32, u32);
    // SAFETY: caller checked instruction support; no memory or flags change.
    // Deliberately no `nomem`: compiler memory motion must not cross this seam.
    unsafe {
        std::arch::asm!("lfence", "rdtscp", "lfence",
            out("eax") lo, out("edx") hi, out("ecx") aux,
            options(nostack, preserves_flags));
    }
    RawTimestamp {
        ticks: (u64::from(hi) << 32) | u64::from(lo),
        aux,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Rows {
    rows: [Option<RawInterval>; super::EVENTS / 2],
    len: usize,
}
impl Rows {
    pub(super) fn new() -> Self {
        Self {
            rows: [None; super::EVENTS / 2],
            len: 0,
        }
    }
    pub(super) fn reserve(&self, outstanding: usize) -> Result<(), BridgeError> {
        if self
            .len
            .checked_add(outstanding)
            .is_none_or(|n| n >= self.rows.len())
        {
            return Err(error(Cause::Capacity));
        }
        Ok(())
    }
    pub(super) fn push(&mut self, row: RawInterval) -> Result<(), BridgeError> {
        let slot = self.rows.get_mut(self.len).ok_or(error(Cause::Capacity))?;
        if slot.is_some() {
            return Err(error(Cause::Invariant));
        }
        *slot = Some(row);
        self.len += 1;
        Ok(())
    }
    // Optional facade: authenticate one append without exposing mutable rows.
    pub(super) fn one_after(&self, before: &Self) -> Option<RawInterval> {
        if before.len.checked_add(1) != Some(self.len)
            || self.len > self.rows.len()
            || self.rows[..before.len] != before.rows[..before.len]
            || before.rows[before.len..].iter().any(Option::is_some)
            || self.rows[self.len..].iter().any(Option::is_some)
        {
            return None;
        }
        self.rows[before.len]
    }
    pub(super) fn snapshot(&self) -> Vec<RawInterval> {
        self.rows[..self.len]
            .iter()
            .map(|x| x.expect("committed timing row"))
            .collect()
    }
    // No allocation and no mutation of this storage; the caller preallocates.
    pub(super) fn copy_committed(&self, output: &mut Vec<RawInterval>) -> Result<(), BridgeError> {
        if !output.is_empty()
            || self.len > self.rows.len()
            || self.rows[..self.len].iter().any(Option::is_none)
            || self.rows[self.len..].iter().any(Option::is_some)
        {
            return Err(error(Cause::Invariant));
        }
        if output.capacity() < self.rows.len() {
            return Err(error(Cause::Capacity));
        }
        output.extend(self.rows[..self.len].iter().flatten().copied());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(start: u64, end: u64, aux: u32) -> RawInterval {
        RawInterval {
            ordinal: 1,
            entry_pc: 0x1000,
            return_pc: 0x1020,
            owner: RawIntervalOwner::InitialDisarmed,
            start: RawTimestamp {
                ticks: start,
                aux: 7,
            },
            end: RawTimestamp { ticks: end, aux },
        }
    }
    #[test]
    fn raw_endpoints_preserve_clock_failures_without_a_fabricated_duration() {
        let valid = row(100, 130, 7);
        assert_eq!(valid.elapsed_ticks(), Some(30));
        assert_eq!(valid.observation(), Observation::Value(130));
        let changed = row(100, 130, 8);
        assert_eq!(changed.elapsed_ticks(), None);
        assert_eq!(changed.observation(), Observation::Unavailable(1));
        let backwards = row(100, 99, 7);
        assert_eq!(backwards.elapsed_ticks(), None);
        assert_eq!(backwards.observation(), Observation::Unavailable(2));
        assert_eq!(backwards.end.ticks, 99);
        assert_eq!(row(100, 100, 7).elapsed_ticks(), Some(0));
    }
    #[test]
    fn reserve_includes_pending_returns_before_admitting_another_entry() {
        let mut rows = Rows::new();
        assert!(rows.reserve(31).is_ok());
        assert_eq!(rows.reserve(32), Err(error(Cause::Capacity)));
        assert_eq!(rows.reserve(usize::MAX), Err(error(Cause::Capacity)));
        for n in 0..32 {
            assert!(rows.reserve(0).is_ok());
            let mut r = row(n, n + 10, 7);
            r.ordinal = n + 1;
            rows.push(r).unwrap();
        }
        let before = rows.snapshot();
        assert_eq!(rows.reserve(0), Err(error(Cause::Capacity)));
        assert_eq!(rows.push(row(0, 0, 7)), Err(error(Cause::Capacity)));
        assert_eq!(rows.snapshot(), before);
        assert_eq!(before.len(), 32);
    }
}

#[cfg(test)]
mod drain_tests;
