//! Atomic publication strategies for live instruction patches.
//!
//! This module currently classifies eight-byte WordPatch spans. The guarded
//! cross-line state machine will be implemented here so it cannot silently
//! fall back to a tearing store.

use crate::cache_line::CacheLineSize;

/// Number of bytes published by the generic x86-64 WordPatch operation.
pub const WORD_PATCH_BYTES: usize = 8;

/// Publication strategy required for an eight-byte patch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchStrategy {
    /// The complete word is contained in one cache line.
    AtomicWord,
    /// The word is split and requires guarded front/back publication.
    GuardedSplit {
        /// Bytes in the cache line containing the patch start.
        front_len: usize,
        /// Bytes in the following cache line.
        back_len: usize,
    },
}

/// Classifies the publication strategy for an eight-byte patch at `address`.
pub fn classify_word_patch(address: usize, cache_line: CacheLineSize) -> PatchStrategy {
    match cache_line.split_offset(address, WORD_PATCH_BYTES) {
        Some(front_len) => PatchStrategy::GuardedSplit {
            front_len,
            back_len: WORD_PATCH_BYTES - front_len,
        },
        None => PatchStrategy::AtomicWord,
    }
}

#[cfg(test)]
mod tests {
    use super::{PatchStrategy, classify_word_patch};
    use crate::cache_line::CacheLineSize;

    const LINE: CacheLineSize = CacheLineSize::new(64).unwrap();

    #[test]
    fn classifies_all_word_splits() {
        for front_len in 1..8 {
            let address = 64 - front_len;
            assert_eq!(
                classify_word_patch(address, LINE),
                PatchStrategy::GuardedSplit {
                    front_len,
                    back_len: 8 - front_len,
                }
            );
        }
    }

    #[test]
    fn word_ending_at_boundary_is_single_line() {
        assert_eq!(classify_word_patch(56, LINE), PatchStrategy::AtomicWord);
    }
}
