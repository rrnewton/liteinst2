//! Common bounded result storage for the new matched native/SDK cohort.
//! The historical guarded-consumer cohort does not construct this collection.

pub const BLOCKS: usize = 64;
pub const CALLS: usize = 24;
pub const ROOTS: usize = BLOCKS * CALLS;

pub fn input_index(call: usize) -> usize {
    assert!(call < CALLS);
    usize::from(call >= 10) * 2 + call % 2
}

pub struct Results {
    values: Box<[u64; ROOTS]>,
    next: usize,
}
impl Results {
    pub fn new() -> Self {
        Self {
            values: Box::new([0; ROOTS]),
            next: 0,
        }
    }

    /// One indexed write per returned root. Values are checked after the loop;
    /// this operation proves collection order, not native execution by itself.
    pub fn record(&mut self, index: usize, value: u64) {
        assert_eq!(index, self.next, "exact next returned-root index");
        assert!(index < ROOTS, "bounded returned-root population");
        self.values[index] = value;
        self.next += 1;
    }

    pub fn complete(&self, expected: &[u64; 4], checksums: &[u64]) {
        assert_eq!(self.next, ROOTS, "all returned-root slots populated");
        assert_eq!(checksums.len(), BLOCKS, "all block checksums retained");
        let mut counts = [0_usize; 4];
        for (block, values) in self.values.chunks_exact(CALLS).enumerate() {
            let mut checksum = 0_u64;
            for (call, value) in values.iter().enumerate() {
                let index = input_index(call);
                assert_eq!(*value, expected[index], "every indexed scalar result");
                counts[index] += 1;
                checksum = checksum.wrapping_add(*value);
            }
            assert_eq!(checksums[block], checksum, "exact block checksum");
        }
        assert_eq!(counts, [320, 320, 448, 448]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALUES: [u64; 4] = [u64::MAX, 17, 23, 31];
    fn full() -> (Results, Vec<u64>) {
        let mut result = Results::new();
        let mut sums = Vec::new();
        for block in 0..BLOCKS {
            let mut sum = 0_u64;
            for call in 0..CALLS {
                let value = VALUES[input_index(call)];
                result.record(block * CALLS + call, value);
                sum = sum.wrapping_add(value);
            }
            sums.push(sum);
        }
        (result, sums)
    }
    #[test]
    fn complete_population_checks_every_value_and_wrapping_sum() {
        let (result, sums) = full();
        result.complete(&VALUES, &sums);
        assert_eq!(ROOTS * size_of::<u64>(), 12_288);
    }
    #[test]
    fn duplicate_missing_extra_and_reordered_results_refuse() {
        for index in [0, 2, ROOTS] {
            let mut result = Results::new();
            result.record(0, VALUES[0]);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    result.record(index, 0);
                }))
                .is_err()
            );
        }
        let (mut result, sums) = full();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                result.record(ROOTS, 0);
            }))
            .is_err()
        );
        result.next -= 1;
        assert!(std::panic::catch_unwind(|| result.complete(&VALUES, &sums)).is_err());
    }
    #[test]
    fn cancellation_cannot_hide_two_wrong_results() {
        let (mut result, sums) = full();
        result.values[10] += 1;
        result.values[11] -= 1;
        assert!(std::panic::catch_unwind(|| result.complete(&VALUES, &sums)).is_err());
    }
    #[test]
    fn wrong_or_incomplete_block_summaries_refuse() {
        let (result, mut sums) = full();
        sums[63] ^= 1;
        assert!(std::panic::catch_unwind(|| result.complete(&VALUES, &sums)).is_err());
        sums.pop();
        assert!(std::panic::catch_unwind(|| result.complete(&VALUES, &sums)).is_err());
    }
}
