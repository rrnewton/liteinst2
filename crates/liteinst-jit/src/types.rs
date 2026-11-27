//! Identity types shared by translation, caching, and invalidation.

/// A mapping generation. It must advance on every byte, alias, entry,
/// or policy change to the source mapping; a cache entry is valid only
/// under the exact generation it was translated from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Generation(pub u64);

impl Generation {
    pub fn next(self) -> Generation {
        Generation(self.0.wrapping_add(1))
    }
}

/// What a translation counts. The primary count is always retired
/// conditional branches (RCBs), credited after retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CountProfile {
    /// Retired conditional branches only.
    Branches,
    /// Retired conditional branches plus retired instructions.
    BranchesAndInstructions,
}

/// Facts about a source code region, supplied and owned by the caller.
/// This crate never discovers write ownership on its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionFacts {
    /// Guest address of `bytes[0]`.
    pub base: u64,
    /// Snapshot of the source bytes.
    pub bytes: Vec<u8>,
    /// Generation of the source mapping when the snapshot was taken.
    pub generation: Generation,
    /// The caller's assertion that the mapping is private and
    /// non-writable for the cache lifetime; `false` refuses. Admission
    /// checks only this flag: this crate does not verify it against
    /// the mapping's protections
    /// (<https://github.com/rrnewton/liteinst2/issues/107>).
    pub immutable_private: bool,
}

impl RegionFacts {
    pub fn end(&self) -> u64 {
        self.base.wrapping_add(self.bytes.len() as u64)
    }
    pub fn contains(&self, pc: u64) -> bool {
        pc >= self.base && pc < self.end()
    }
    /// Bytes starting at guest address `pc`, if inside the region.
    pub fn slice_from(&self, pc: u64) -> Option<&[u8]> {
        let off = usize::try_from(pc.checked_sub(self.base)?).ok()?;
        self.bytes.get(off..)
    }
}

/// A change to guest memory reported by the caller, who owns the
/// system call semantics; this crate never classifies the call itself.
/// Every event advances the executable's generation, and the live
/// translation is rebuilt on the next transfer into the cache (one
/// global generation, flushed on any mapping event).
///
/// Events reported together are applied all or none. If any region
/// event in the batch is not strictly newer than the one before it
/// (a hole event counts as one step), no snapshot in the batch is
/// admitted, every range the batch names becomes a hole, and the batch
/// refuses `Refuse::StaleGeneration`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingEvent {
    /// Start of the changed range.
    pub start: u64,
    /// End of the changed range (exclusive).
    pub end: u64,
    /// `Some`: the admitted region is now this fresh snapshot, whose
    /// generation must be strictly newer than the executable's.
    /// `None`: `[start, end)` no longer holds admitted code; control
    /// that reaches it refuses `Refuse::UnmappedCode`.
    pub region: Option<RegionFacts>,
}

/// FNV-1a over source bytes. This is an identity check against the
/// snapshot the block was translated from, not a security hash.
pub fn byte_hash(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Identity of one cached translation: source PC, byte hash,
/// generation and count profile. `CacheIndex::lookup` compares the
/// whole key, but neither dispatcher calls it: both enter blocks by
/// address, so at dispatch today address equality alone selects an
/// entry (<https://github.com/rrnewton/liteinst2/issues/104>).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CacheKey {
    pub src_pc: u64,
    pub byte_hash: u64,
    pub generation: Generation,
    pub profile: CountProfile,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_advances() {
        assert_eq!(Generation(7).next(), Generation(8));
        assert!(Generation(8) > Generation(7));
    }

    #[test]
    fn hash_distinguishes_bytes() {
        assert_ne!(byte_hash(b"\x90"), byte_hash(b"\x91"));
        assert_eq!(byte_hash(b"abc"), byte_hash(b"abc"));
        assert_ne!(byte_hash(b"ab"), byte_hash(b"abc"));
    }

    #[test]
    fn region_bounds() {
        let r = RegionFacts {
            base: 0x1000,
            bytes: vec![0x90; 16],
            generation: Generation(1),
            immutable_private: true,
        };
        assert!(r.contains(0x1000));
        assert!(r.contains(0x100f));
        assert!(!r.contains(0x1010));
        assert_eq!(r.slice_from(0x1004).map(<[u8]>::len), Some(12));
        assert_eq!(r.slice_from(0x2000), None);
    }
}
