//! Bounded parent-only diagnostics; never a source of oracle decisions.
use std::io::Write;

const CAPACITY: usize = 20_000;

pub(super) struct PcCounts {
    completed: Vec<u64>,
    dropped: usize,
    unpaired: usize,
    first_observed: Option<usize>,
}
impl Default for PcCounts {
    fn default() -> Self {
        Self {
            completed: Vec::with_capacity(CAPACITY),
            dropped: 0,
            unpaired: 0,
            first_observed: None,
        }
    }
}
impl PcCounts {
    pub(super) fn transition(&mut self, prior: Option<(u64, usize)>, step: usize) {
        self.first_observed.get_or_insert(step);
        let Some((pc, before)) = prior else {
            return;
        };
        if before.checked_add(1) != Some(step) {
            self.unpaired = self.unpaired.saturating_add(1);
            return;
        }
        if self.completed.len() < CAPACITY {
            self.completed.push(pc);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    pub(super) fn write_failure(&mut self, stderr: &mut impl Write) {
        // The oracle has already failed. Sorting uses existing storage and
        // never touches the tracee or changes the original failure's verdict.
        self.completed.sort_unstable();
        let _ = writeln!(
            stderr,
            "early-entry code-pcs: capacity={} first_observed_step={:?} recorded_completed_steps={} dropped_completed_steps={} unpaired_observations={}",
            CAPACITY,
            self.first_observed,
            self.completed.len(),
            self.dropped,
            self.unpaired
        );
        let mut start = 0;
        while start < self.completed.len() {
            let pc = self.completed[start];
            let mut end = start + 1;
            while end < self.completed.len() && self.completed[end] == pc {
                end += 1;
            }
            let _ = writeln!(stderr, "early-entry pc: {pc:016x} {}", end - start);
            start = end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_completed_transitions_and_preserves_each_pc() {
        let mut counts = PcCounts::default();
        counts.transition(None, 10);
        counts.transition(Some((0x3000, 10)), 11);
        counts.transition(Some((0x2001, 11)), 12);
        counts.transition(Some((0x3000, 12)), 13);
        counts.transition(Some((0xdead, 13)), 15);
        counts.transition(Some((0xbeef, usize::MAX)), 0);
        let mut output = Vec::new();
        counts.write_failure(&mut output);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "early-entry code-pcs: capacity=20000 first_observed_step=Some(10) recorded_completed_steps=3 dropped_completed_steps=0 unpaired_observations=2\n\
             early-entry pc: 0000000000002001 1\n\
             early-entry pc: 0000000000003000 2\n"
        );
    }

    #[test]
    fn capacity_exhaustion_counts_drops_without_growing_or_losing_records() {
        let mut counts = PcCounts::default();
        let storage = counts.completed.as_ptr();
        for step in 1..=CAPACITY + 7 {
            counts.transition(Some((0x1234, step - 1)), step);
        }
        assert_eq!(counts.completed.len(), CAPACITY);
        assert_eq!(counts.completed.as_ptr(), storage);
        assert_eq!(counts.dropped, 7);
        assert_eq!(counts.unpaired, 0);
        let mut output = Vec::new();
        counts.write_failure(&mut output);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "early-entry code-pcs: capacity=20000 first_observed_step=Some(1) recorded_completed_steps=20000 dropped_completed_steps=7 unpaired_observations=0\n\
             early-entry pc: 0000000000001234 20000\n"
        );
    }
}
