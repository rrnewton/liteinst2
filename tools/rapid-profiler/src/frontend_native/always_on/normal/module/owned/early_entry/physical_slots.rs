//! Exact occupancy of four physical slots; no cached validation of row contents.
#![forbid(unsafe_code)]

use super::EarlyEntryModulePhysicalRow;
use std::ops::Deref;

// Fields stay private to this module. There is no mutable Option, array or row
// view: changing a row's observed_ordinal must update its count through set().
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SeenSlots {
    values: [Option<u64>; 4],
    present: u8,
    count: u8,
}
impl SeenSlots {
    pub(super) const fn empty() -> Self {
        Self {
            values: [None; 4],
            present: 0,
            count: 0,
        }
    }

    pub(super) fn set(&mut self, index: usize, value: Option<u64>) {
        // Index checking precedes every write and bounds the shift. Copy values
        // run no destructor/callback between the related representation writes.
        let slot = &mut self.values[index];
        let bit = 1u8 << index;
        let count = self.count - u8::from(slot.is_some()) + u8::from(value.is_some());
        let present = if value.is_some() {
            self.present | bit
        } else {
            self.present & !bit
        };
        *slot = value;
        self.present = present;
        self.count = count;
    }

    pub(super) fn tail_is_empty(&self, start: usize) -> bool {
        start <= 4 && self.present & !(((1u16 << start) - 1) as u8) == 0
    }

    pub(super) fn count(&self) -> usize {
        usize::from(self.count)
    }
}
impl Deref for SeenSlots {
    type Target = [Option<u64>; 4];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RowSlots {
    values: [Option<EarlyEntryModulePhysicalRow>; 4],
    present: u8,
    observed: u8,
}
impl RowSlots {
    pub(super) const fn empty() -> Self {
        Self {
            values: [None; 4],
            present: 0,
            observed: 0,
        }
    }

    #[inline(always)]
    pub(super) fn set(&mut self, index: usize, value: Option<EarlyEntryModulePhysicalRow>) {
        let slot = &mut self.values[index];
        let bit = 1u8 << index;
        let old_observed = slot
            .as_ref()
            .is_some_and(|row| row.observed_ordinal.is_some());
        let new_observed = value
            .as_ref()
            .is_some_and(|row| row.observed_ordinal.is_some());
        let observed = self.observed - u8::from(old_observed) + u8::from(new_observed);
        let present = if value.is_some() {
            self.present | bit
        } else {
            self.present & !bit
        };
        *slot = value;
        self.present = present;
        self.observed = observed;
    }

    pub(super) fn is_prefix(&self, len: usize) -> bool {
        len <= 4 && self.present == ((1u16 << len) - 1) as u8
    }

    pub(super) fn observed_count(&self) -> usize {
        usize::from(self.observed)
    }
}
impl Deref for RowSlots {
    type Target = [Option<EarlyEntryModulePhysicalRow>; 4];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

#[cfg(test)]
mod tests {
    use super::super::FunctionId;
    use super::*;

    fn row(index: usize, observed: bool) -> EarlyEntryModulePhysicalRow {
        EarlyEntryModulePhysicalRow {
            batch: 7,
            position: index,
            function: FunctionId(11 + index as u64),
            observed_ordinal: observed.then_some(19 + index as u64),
            return_pc: 0x1010 + index as u64 * 16,
            entry_rsp: 0x8008,
            return_word: 0x9008 + index as u64 * 8,
        }
    }

    fn original_seen(slots: &SeenSlots, expected: [Option<u64>; 4]) {
        assert_eq!(**slots, expected);
        assert_eq!(slots.count(), expected.iter().flatten().count());
        for start in 0..=4 {
            assert_eq!(
                slots.tail_is_empty(start),
                !expected[start..].iter().any(Option::is_some)
            );
        }
        assert!(!slots.tail_is_empty(5));
        assert!(!slots.tail_is_empty(usize::MAX));
    }

    fn original_rows(slots: &RowSlots, expected: [Option<EarlyEntryModulePhysicalRow>; 4]) {
        assert_eq!(**slots, expected);
        assert_eq!(
            slots.observed_count(),
            expected
                .iter()
                .flatten()
                .filter(|r| r.observed_ordinal.is_some())
                .count()
        );
        for len in 0..=4 {
            assert_eq!(
                slots.is_prefix(len),
                !expected[..len].iter().any(Option::is_none)
                    && !expected[len..].iter().any(Option::is_some)
            );
        }
        assert!(!slots.is_prefix(5));
        assert!(!slots.is_prefix(usize::MAX));
    }

    #[test]
    fn all_occupancies_and_replacements_match_original_array_queries() {
        for mask in 0u8..16 {
            let mut seen = SeenSlots::empty();
            let mut expected = [None; 4];
            for (index, value) in expected.iter_mut().enumerate() {
                *value = (mask & (1 << index) != 0).then_some(index as u64 + 1);
                seen.set(index, *value);
            }
            original_seen(&seen, expected);
            for index in [0usize, 1, 2, 3] {
                let old = expected[index];
                for value in [None, Some(0), Some(u64::MAX), old] {
                    seen.set(index, value);
                    expected[index] = value;
                    original_seen(&seen, expected);
                }
            }
            for index in [0usize, 1, 2, 3] {
                seen.set(index, None);
                expected[index] = None;
                original_seen(&seen, expected);
            }
        }
        // Per slot: absent, present bypass, or present observed. Every mask and
        // observed subset is covered, including holes and stray tail rows.
        for pattern in 0..81 {
            let mut rows = RowSlots::empty();
            let mut expected = [None; 4];
            let mut digits = pattern;
            for (index, value) in expected.iter_mut().enumerate() {
                let digit = digits % 3;
                digits /= 3;
                *value = (digit != 0).then(|| row(index, digit == 2));
                rows.set(index, *value);
            }
            original_rows(&rows, expected);
            for index in [0usize, 1, 2, 3] {
                let old = expected[index];
                for value in [None, Some(row(index, false)), Some(row(index, true)), old] {
                    rows.set(index, value);
                    expected[index] = value;
                    original_rows(&rows, expected);
                }
            }
            for index in [0usize, 1, 2, 3] {
                rows.set(index, None);
                expected[index] = None;
                original_rows(&rows, expected);
            }
        }
    }

    #[test]
    fn out_of_range_replacements_preserve_all_values_masks_and_counts() {
        let mut seen = SeenSlots::empty();
        let mut rows = RowSlots::empty();
        seen.set(0, Some(9));
        seen.set(3, Some(17));
        rows.set(0, Some(row(0, false)));
        rows.set(3, Some(row(3, true)));
        for index in [4, usize::MAX] {
            for value in [None, Some(7)] {
                let before = seen;
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        seen.set(index, value);
                    }))
                    .is_err()
                );
                assert_eq!(seen, before);
                original_seen(&seen, *before);
            }
            for value in [None, Some(row(1, false)), Some(row(1, true))] {
                let before = rows;
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rows.set(index, value);
                    }))
                    .is_err()
                );
                assert_eq!(rows, before);
                original_rows(&rows, *before);
            }
        }
    }
}
