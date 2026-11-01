//! Exact occupancy of the fixed record arrays, maintained by safe mutation.
#![forbid(unsafe_code)]

use super::CALLS;
use std::ops::Deref;

const _: () = assert!(CALLS == u32::BITS as usize);

/// Bit i is set exactly when values[i] is Some. Fields stay private to this
/// module; no mutable Option, slice, DerefMut or IndexMut can escape. The mask
/// proves occupancy only, never row contents, model state or a whole shape.
#[derive(Clone, Copy)]
pub(super) struct PresenceSlots<T: Copy> {
    values: [Option<T>; CALLS],
    present: u32,
}
impl<T: Copy> PresenceSlots<T> {
    pub(super) const fn empty() -> Self {
        Self {
            values: [None; CALLS],
            present: 0,
        }
    }

    pub(super) fn set(&mut self, index: usize, value: Option<T>) {
        // Bounds are checked before either field changes. The const capacity
        // proof makes the shift valid; Copy assignment runs no user destructor.
        // No fallible operation or callback occurs between the two writes.
        let slot = &mut self.values[index];
        let bit = 1u32 << index;
        *slot = value;
        if value.is_some() {
            self.present |= bit;
        } else {
            self.present &= !bit;
        }
    }

    pub(super) fn clear(&mut self) {
        self.values = [None; CALLS];
        self.present = 0;
    }

    pub(super) fn is_prefix(&self, len: usize) -> bool {
        // A u64 intermediate handles both the empty prefix and all 32 cells.
        len <= CALLS && self.present == ((1u64 << len) - 1) as u32
    }

    // Existing hostile-content controls may alter a row, but cannot change its
    // Option discriminant. Production writes use only set and clear above.
    #[cfg(test)]
    pub(super) fn value_mut(&mut self, index: usize) -> Option<&mut T> {
        self.values.get_mut(index).and_then(Option::as_mut)
    }
}
impl<T: Copy> Deref for PresenceSlots<T> {
    type Target = [Option<T>; CALLS];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compare_original_conditions(slots: &PresenceSlots<u64>) {
        for len in 0..=CALLS {
            let original = !slots[..len].iter().any(Option::is_none)
                && !slots[len..].iter().any(Option::is_some);
            assert_eq!(slots.is_prefix(len), original);
        }
        assert!(!slots.is_prefix(CALLS + 1));
        assert!(!slots.is_prefix(usize::MAX));
    }

    #[test]
    fn every_prefix_hole_tail_replacement_and_clear_matches_original_conditions() {
        for prefix in 0..=CALLS {
            let mut slots = PresenceSlots::empty();
            for index in 0..prefix {
                slots.set(index, Some(index as u64));
            }
            compare_original_conditions(&slots);
            for index in 0..CALLS {
                let original = slots[index];
                slots.set(index, None);
                compare_original_conditions(&slots);
                assert!(slots.value_mut(index).is_none());
                slots.set(index, Some(73));
                compare_original_conditions(&slots);
                *slots.value_mut(index).unwrap() = 91;
                compare_original_conditions(&slots);
                slots.set(index, Some(17));
                compare_original_conditions(&slots);
                slots.set(index, original);
                compare_original_conditions(&slots);
            }
            slots.clear();
            assert!(slots.iter().all(Option::is_none));
            compare_original_conditions(&slots);
        }
    }

    #[test]
    fn out_of_range_set_preserves_complete_array_and_presence() {
        let mut slots = PresenceSlots::empty();
        slots.set(0, Some(3u64));
        slots.set(CALLS - 1, Some(7));
        for index in [CALLS, usize::MAX] {
            for value in [None, Some(99)] {
                let before = slots;
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                        || slots.set(index, value)
                    ))
                    .is_err()
                );
                assert_eq!(slots.values, before.values);
                assert_eq!(slots.present, before.present);
                compare_original_conditions(&slots);
            }
        }
    }
}
