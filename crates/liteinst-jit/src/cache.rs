//! Cache index and invalidation bookkeeping (pure logic).
//!
//! Invalidation is generation-stamped and serialized against
//! insertion: a translation stamped with an older generation can
//! never be inserted after a newer invalidation. Eviction in P1a is
//! flush-whole-cache, the simplest correct policy; region-granular
//! eviction with incoming-link tracking is a later optimization.

use std::collections::HashMap;

use crate::refuse::Refuse;
use crate::types::{CacheKey, CountProfile, Generation};

/// Where one translation lives in generated and source space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheRecord {
    pub key: CacheKey,
    /// Source block covered, half-open.
    pub src_start: u64,
    pub src_end: u64,
    /// Generated entry PC.
    pub gen_entry: u64,
}

#[derive(Debug)]
pub struct CacheIndex {
    current: Generation,
    records: HashMap<CacheKey, CacheRecord>,
}

impl CacheIndex {
    pub fn new(generation: Generation) -> CacheIndex {
        CacheIndex {
            current: generation,
            records: HashMap::new(),
        }
    }

    pub fn generation(&self) -> Generation {
        self.current
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Insert a translation record. A record stamped with any
    /// generation other than the current one refuses: older stamps
    /// lose the insert-after-invalidate race by construction.
    pub fn insert(&mut self, rec: CacheRecord) -> Result<(), Refuse> {
        if rec.key.generation != self.current {
            return Err(Refuse::StaleGeneration {
                expected: self.current.0,
                found: rec.key.generation.0,
            });
        }
        self.records.insert(rec.key, rec);
        Ok(())
    }

    /// Find a translation by its full identity under the current
    /// generation.
    pub fn lookup(
        &self,
        src_pc: u64,
        byte_hash: u64,
        profile: CountProfile,
    ) -> Option<&CacheRecord> {
        let key = CacheKey {
            src_pc,
            byte_hash,
            generation: self.current,
            profile,
        };
        self.records.get(&key)
    }

    /// Invalidate every record overlapping `[src_start, src_end)` and
    /// advance to `new_generation`, which must be strictly newer.
    /// Returns the number of records dropped. Callers must unchain
    /// incoming links and quarantine the generated ranges before
    /// reusing their space; this index only owns identity.
    pub fn invalidate(
        &mut self,
        src_start: u64,
        src_end: u64,
        new_generation: Generation,
    ) -> Result<usize, Refuse> {
        if new_generation <= self.current {
            return Err(Refuse::StaleGeneration {
                expected: self.current.next().0,
                found: new_generation.0,
            });
        }
        let before = self.records.len();
        self.records
            .retain(|_, r| !(r.src_start < src_end && src_start < r.src_end));
        self.current = new_generation;
        Ok(before - self.records.len())
    }

    /// Drop everything (P1a eviction policy) without changing the
    /// generation. Returns the number of records dropped.
    pub fn flush(&mut self) -> usize {
        let n = self.records.len();
        self.records.clear();
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CountProfile::Branches;

    fn rec(src_pc: u64, generation: u64) -> CacheRecord {
        CacheRecord {
            key: CacheKey {
                src_pc,
                byte_hash: 0xabc,
                generation: Generation(generation),
                profile: Branches,
            },
            src_start: src_pc,
            src_end: src_pc + 0x10,
            gen_entry: 0x8000 + src_pc,
        }
    }

    #[test]
    fn insert_and_lookup() {
        let mut ix = CacheIndex::new(Generation(1));
        ix.insert(rec(0x1000, 1)).unwrap();
        assert_eq!(
            ix.lookup(0x1000, 0xabc, Branches).map(|r| r.gen_entry),
            Some(0x9000)
        );
        assert_eq!(ix.lookup(0x1000, 0xdef, Branches), None);
        assert_eq!(ix.lookup(0x2000, 0xabc, Branches), None);
    }

    #[test]
    fn stale_insert_refuses() {
        let mut ix = CacheIndex::new(Generation(2));
        assert!(matches!(
            ix.insert(rec(0x1000, 1)),
            Err(Refuse::StaleGeneration {
                expected: 2,
                found: 1
            })
        ));
        assert!(ix.is_empty());
    }

    #[test]
    fn invalidate_drops_overlap_and_advances() {
        let mut ix = CacheIndex::new(Generation(1));
        ix.insert(rec(0x1000, 1)).unwrap();
        ix.insert(rec(0x2000, 1)).unwrap();
        let dropped = ix.invalidate(0x1008, 0x1009, Generation(2)).unwrap();
        assert_eq!(dropped, 1);
        assert_eq!(ix.generation(), Generation(2));
        // The survivor is now stale too: lookups stamp generation 2.
        assert_eq!(ix.lookup(0x2000, 0xabc, Branches), None);
        assert_eq!(ix.len(), 1);
    }

    #[test]
    fn invalidate_requires_newer_generation() {
        let mut ix = CacheIndex::new(Generation(3));
        assert!(matches!(
            ix.invalidate(0, u64::MAX, Generation(3)),
            Err(Refuse::StaleGeneration { .. })
        ));
    }

    #[test]
    fn insert_after_invalidate_race_loses() {
        let mut ix = CacheIndex::new(Generation(1));
        ix.invalidate(0, u64::MAX, Generation(2)).unwrap();
        // A translation built under generation 1 arrives late.
        assert!(matches!(
            ix.insert(rec(0x1000, 1)),
            Err(Refuse::StaleGeneration { .. })
        ));
        ix.insert(rec(0x1000, 2)).unwrap();
        assert_eq!(ix.flush(), 1);
        assert!(ix.is_empty());
    }
}
