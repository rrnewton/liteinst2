//! Standalone admission facts for x86-64. See the crate README for the envelope.
//!
//! The B0 publication model never changes memory permissions or executable bytes.
//! Its tokens are deliberately not quiescence leases for the LiteInst core.
#![forbid(unsafe_code)]

pub mod entries;
pub mod model;
pub mod scan;

use std::ops::Range;

/// Identity of an owned mapping incarnation. Never reuse an id for another mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MappingId(pub u64);

/// Version of bytes, permissions, aliases and entry facts for one mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(pub u64);

/// Validated nonempty half-open virtual-address range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AddressRange {
    start: u64,
    end: u64,
}

impl AddressRange {
    pub fn new(start: u64, end: u64) -> Option<Self> {
        (start < end).then_some(Self { start, end })
    }

    pub fn from_len(start: u64, len: usize) -> Option<Self> {
        Self::new(start, start.checked_add(u64::try_from(len).ok()?)?)
    }

    pub fn start(self) -> u64 {
        self.start
    }

    pub fn end(self) -> u64 {
        self.end
    }

    pub fn contains(self, address: u64) -> bool {
        self.start <= address && address < self.end
    }

    pub fn covers(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    pub fn as_range(self) -> Range<u64> {
        self.start..self.end
    }
}

pub mod core_bridge;
