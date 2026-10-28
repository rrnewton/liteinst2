//! Closed selected-checksum protocol and strict carried budget. No loader or
//! native execution authority is created by these metadata validators.
use super::{CHILD_BUDGET, Instant, MAX_STEPS, PairResult};
use std::collections::BTreeSet;

pub const LABEL: &str = "selected-checksum-v1";
pub const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
pub const HEADER: &str = "seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,value\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Arguments {
    pub elf_va: u64,
    pub length: usize,
}
impl Arguments {
    /// CLI values are ELF virtual-address metadata, never runtime pointers.
    /// This representation check does not prove independent metadata authority.
    pub fn parse(elf_va: &str, length: &str) -> Self {
        fn number(text: &str) -> u64 {
            assert!(!text.is_empty());
            assert!(text.bytes().all(|b| b.is_ascii_digit()));
            assert!(text == "0" || !text.starts_with('0'));
            text.parse().expect("canonical u64 metadata")
        }
        let elf_va = number(elf_va);
        let length = number(length);
        assert!((1..=256).contains(&length));
        elf_va.checked_add(length).expect("complete ELF extent");
        Self {
            elf_va,
            length: usize::try_from(length).unwrap(),
        }
    }
}

/// A fresh pair's immutable 15-second budget; neither child nor output gets a
/// renewal. The route creates this before allocation (and first-pair file setup).
#[derive(Clone, Copy)]
pub struct Deadline(Instant);
impl Deadline {
    pub fn start() -> Self {
        Self(Instant::now() + CHILD_BUDGET)
    }
    pub fn check(self) {
        self.check_at(Instant::now());
    }
    fn check_at(self, now: Instant) {
        assert!(now < self.0, "selected checksum absolute deadline");
    }
    pub(super) fn end(self) -> Instant {
        self.0
    }
    pub(super) fn request(self, reference: Option<(Instant, u64)>, native_noop: Option<u64>) {
        self.request_at(reference, native_noop, Instant::now());
    }
    fn request_at(self, reference: Option<(Instant, u64)>, native_noop: Option<u64>, now: Instant) {
        assert!(reference.is_none(), "selected checksum uses Legacy gate");
        assert!(native_noop.is_none(), "selected checksum uses Legacy gate");
        self.check_at(now);
    }
}

/// Parent-observed state summaries only. Full rows/Reports remain child checks,
/// and normal exit/reap custody remains the shared pair engine's obligation.
#[derive(Default)]
pub struct Population {
    next: usize,
    comparisons: usize,
    declared: Option<BTreeSet<u64>>,
    observed: BTreeSet<u64>,
}
impl Population {
    pub fn record(&mut self, seed: u64, length: usize, pair: &PairResult) {
        assert!(self.next < 4, "closed four-pair population");
        assert_eq!(seed, SEEDS[self.next / 2]);
        assert_eq!(length, [1, 64][self.next % 2]);
        assert!(pair.visits > 0 && pair.visits < pair.comparisons);
        assert!((pair.comparisons..=MAX_STEPS).contains(&pair.original_steps));
        assert!((pair.comparisons..=MAX_STEPS).contains(&pair.candidate_steps));
        let expected = (0..length)
            .map(|j| (((128 + j) as u64 * 37 + 11 + seed) as u8 ^ 0x5a) as u64)
            .sum::<u64>()
            ^ 0x9e37_79b9_7f4a_7c15;
        assert_eq!(
            pair.value, expected,
            "independent fixed input/scalar formula"
        );
        assert!((1..=4).contains(&pair.declared_returns.len()));
        assert_eq!(
            pair.returns.len(),
            1,
            "one actual subject RET per child pair"
        );
        assert!(pair.returns.is_subset(&pair.declared_returns));
        if let Some(declared) = &self.declared {
            assert_eq!(declared, &pair.declared_returns);
        } else {
            self.declared = Some(pair.declared_returns.clone());
        }
        self.observed.extend(&pair.returns);
        if self.next % 2 == 1 {
            assert_eq!(
                Some(&self.observed),
                self.declared.as_ref(),
                "actual RET union covers the complete certificate for this seed"
            );
            self.observed.clear();
            self.declared = None;
        }
        self.comparisons = self.comparisons.checked_add(pair.comparisons).unwrap();
        self.next += 1;
    }
    pub fn finish(self) -> usize {
        assert_eq!(self.next, 4, "complete selected population");
        assert!(self.declared.is_none() && self.observed.is_empty());
        self.comparisons
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    // Fabricated protocol metadata exercises actual validators, never native
    // returns, Ready ownership, source provenance or child completion credit.
    fn pair(seed: u64, length: usize, ret: u64) -> PairResult {
        let input: Vec<u8> = (128..128 + length)
            .map(|i| (i as u64 * 37 + 11 + seed) as u8)
            .collect();
        let value = input.iter().fold(0, |s, &b| s + u64::from(b ^ 0x5a)) ^ 0x9e37_79b9_7f4a_7c15;
        PairResult {
            comparisons: 12,
            original_steps: 15,
            candidate_steps: 50,
            visits: 2,
            returns: BTreeSet::from([ret]),
            declared_returns: BTreeSet::from([0x1000, 0x1005]),
            value,
        }
    }
    #[test]
    fn selected_arguments_require_canonical_complete_extent() {
        assert_eq!(
            Arguments::parse("4096", "256"),
            Arguments {
                elf_va: 4096,
                length: 256
            }
        );
        for (va, len) in [
            ("", "1"),
            ("+1", "1"),
            ("-1", "1"),
            ("01", "1"),
            (" 1", "1"),
            ("1\n", "1"),
            ("0x1000", "1"),
            ("١", "1"),
            ("1", "00"),
            ("1", "0"),
            ("1", "257"),
            ("1", "+1"),
            ("18446744073709551616", "1"),
            ("18446744073709551615", "1"),
        ] {
            assert!(
                catch_unwind(|| Arguments::parse(va, len)).is_err(),
                "{va:?}/{len:?}"
            );
        }
    }
    #[test]
    fn selected_population_requires_order_counts_and_scalar() {
        let mut population = Population::default();
        for seed in SEEDS {
            population.record(seed, 1, &pair(seed, 1, 0x1000));
            population.record(seed, 64, &pair(seed, 64, 0x1005));
        }
        assert!(
            catch_unwind(AssertUnwindSafe(|| population.record(
                SEEDS[0],
                1,
                &pair(SEEDS[0], 1, 0x1000)
            )))
            .is_err()
        );
        assert_eq!(population.finish(), 48);
        assert!(catch_unwind(|| Population::default().finish()).is_err());
        for mutation in 0..12 {
            let mut p = Population::default();
            let mut result = pair(SEEDS[0], 1, 0x1000);
            let mut seed = SEEDS[0];
            let mut length = 1;
            match mutation {
                0 => seed = SEEDS[1],
                1 => length = 64,
                2 => result.value ^= 1,
                3 => result.visits = 0,
                4 => result.visits = result.comparisons,
                5 => result.original_steps = result.comparisons - 1,
                6 => result.candidate_steps = MAX_STEPS + 1,
                7 => result.returns.clear(),
                8 => {
                    result.returns.insert(0x1005);
                }
                9 => {
                    result.declared_returns.remove(&0x1000);
                }
                10 => result.original_steps = MAX_STEPS + 1,
                _ => result.candidate_steps = result.comparisons - 1,
            }
            assert!(catch_unwind(AssertUnwindSafe(|| p.record(seed, length, &result))).is_err());
        }
        let mut p = Population::default();
        p.record(SEEDS[0], 1, &pair(SEEDS[0], 1, 0x1000));
        assert!(
            catch_unwind(AssertUnwindSafe(|| p.record(
                SEEDS[0],
                1,
                &pair(SEEDS[0], 1, 0x1000)
            )))
            .is_err()
        );
        assert!(catch_unwind(AssertUnwindSafe(|| p.finish())).is_err());
    }
    #[test]
    fn selected_ret_union_requires_all_declared_and_stable_ownership() {
        for changed in [false, true] {
            let mut p = Population::default();
            p.record(SEEDS[0], 1, &pair(SEEDS[0], 1, 0x1000));
            let mut last = pair(SEEDS[0], 64, if changed { 0x1005 } else { 0x1000 });
            if changed {
                last.declared_returns.insert(0x1010);
            }
            assert!(catch_unwind(AssertUnwindSafe(|| p.record(SEEDS[0], 64, &last))).is_err());
        }
    }
    #[test]
    fn selected_deadline_never_renews_or_accepts_other_profiles() {
        let start = Instant::now();
        let deadline = Deadline(start + CHILD_BUDGET);
        deadline.check_at(start);
        deadline.check_at(deadline.end() - std::time::Duration::from_nanos(1));
        assert!(catch_unwind(|| deadline.check_at(deadline.end())).is_err());
        assert!(
            catch_unwind(|| deadline.check_at(deadline.end() + std::time::Duration::from_nanos(1)))
                .is_err()
        );
        assert_eq!(deadline.end(), start + std::time::Duration::from_secs(15));
        deadline.request_at(None, None, start);
        assert!(catch_unwind(|| deadline.request_at(None, None, deadline.end())).is_err());
        assert!(
            catch_unwind(|| deadline.request_at(Some((deadline.end(), 1)), None, start)).is_err()
        );
        assert!(catch_unwind(|| deadline.request_at(None, Some(1), start)).is_err());
    }
}
