//! Exact occupancy and owner-bound immutable geometry; raw row checks stay fresh.
#![forbid(unsafe_code)]

use super::{
    Arc, Binding, BindingProfile, BridgeError, Cause, EarlyEntryModulePhysicalRow, NormalState,
    SelectedFunction, error,
};
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
struct GeometryKey {
    selected: SelectedFunction,
    entry: u64,
    return_pc: u64,
}

// The batch retains one immutable binding for every fact, never one per row.
// Production keeps this owner inside the active PhysicalState batch.
// Raw rows and facts share the same private mutation boundary.
#[cfg_attr(test, derive(Clone))]
pub(super) struct RowSlots {
    values: [Option<EarlyEntryModulePhysicalRow>; 4],
    present: u8,
    observed: u8,
    facts: [Option<GeometryKey>; 4],
    owner: Option<Arc<Binding>>,
}

// This non-Clone token owns the slot borrow until the unchanged RET transition
// succeeds. It exposes no NormalState/Session or mutable row/Option view.
pub(super) struct CheckedRow<'a> {
    slots: &'a mut RowSlots,
    fact: Option<GeometryKey>,
    canonical_entry: u64,
}
impl CheckedRow<'_> {
    pub(super) fn canonical_entry(&self) -> u64 {
        self.canonical_entry
    }
    #[inline(always)]
    pub(super) fn set(self, index: usize, row: EarlyEntryModulePhysicalRow) {
        // The original bounds-checked raw write runs first. A failed transition
        // drops this token without changing any row, fact, count or owner.
        self.slots.set(index, Some(row));
        self.slots.facts[index] = self.fact;
    }
}
impl RowSlots {
    pub(super) const fn empty() -> Self {
        Self {
            values: [None; 4],
            present: 0,
            observed: 0,
            facts: [None; 4],
            owner: None,
        }
    }

    pub(super) fn with_owner(owner: Arc<Binding>) -> Self {
        Self {
            owner: Some(owner),
            ..Self::empty()
        }
    }

    #[inline(always)]
    pub(super) fn checked_return(
        &mut self,
        state: &NormalState,
        selected: SelectedFunction,
        pc: u64,
    ) -> Result<CheckedRow<'_>, BridgeError> {
        // These are the original Module extraction, unchecked site indexing
        // and geometry call, at the old RET validation position.
        let BindingProfile::Module { site, .. } = &state.binding.profile else {
            return Err(error(Cause::Identity));
        };
        let entry = site.functions()[selected.index].entry();
        state.selected_geometry(selected, entry, Some(pc))?;
        let fact = self
            .owner
            .as_ref()
            .filter(|owner| Arc::ptr_eq(owner, &state.binding))
            .map(|_| GeometryKey {
                selected,
                entry,
                return_pc: pc,
            });
        Ok(CheckedRow {
            slots: self,
            fact,
            canonical_entry: entry,
        })
    }

    #[inline(always)]
    pub(super) fn geometry_matches(
        &self,
        index: usize,
        state: &NormalState,
        selected: SelectedFunction,
        entry: u64,
        return_pc: u64,
    ) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, &state.binding))
            && self.facts[index]
                == Some(GeometryKey {
                    selected,
                    entry,
                    return_pc,
                })
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
        // Even identical replacement/clear invalidates the old proof. The
        // checked token is the only path that can install a fresh fact.
        self.facts[index] = None;
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

// Preserve complete capsule equality in the existing test snapshots. Binding
// identity, every raw value, mask/count and fact are compared; not just occupancy.
#[cfg(test)]
impl std::fmt::Debug for RowSlots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RowSlots")
            .field("values", &self.values)
            .field("present", &self.present)
            .field("observed", &self.observed)
            .field("facts", &self.facts)
            .field("owner", &self.owner.as_ref().map(Arc::as_ptr))
            .finish()
    }
}
#[cfg(test)]
impl PartialEq for RowSlots {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
            && self.present == other.present
            && self.observed == other.observed
            && self.facts == other.facts
            && self.owner.as_ref().map(Arc::as_ptr) == other.owner.as_ref().map(Arc::as_ptr)
    }
}
#[cfg(test)]
impl Eq for RowSlots {}

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
                let before = rows.clone();
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
