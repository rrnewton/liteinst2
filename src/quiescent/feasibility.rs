//! Shared, pure geometry for short instruction puns and rel32 byte constraints.
//!
//! These queries do not qualify instructions, authenticate current bytes, grant
//! allocation authority, or choose a candidate search schedule.

use crate::contracts::{AddressRange, Refusal};

/// Ordered single-byte opcodes architecturally invalid in 64-bit mode.
///
/// The order is part of the core's indexed candidate schedule. Do not add
/// D4/D5: newer ISAs may assign prefixes to historically illegal opcodes.
pub const ENTRY_BYTES: [u8; 14] = [
    0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x60, 0x61, 0xce,
];

/// Descriptive constraints, not evidence that any target or mapping exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rel32Constraints {
    /// Address after the redirect, used as the signed displacement origin.
    pub next: u64,
    /// Required little-endian displacement bytes; `None` leaves a byte free.
    pub fixed: [Option<u8>; 4],
    /// Bytes that must also be members of [`ENTRY_BYTES`].
    pub entries: [bool; 4],
}

impl Rel32Constraints {
    /// An unconstrained signed rel32 displacement from `next`.
    pub const fn plain(next: u64) -> Self {
        Self {
            next,
            fixed: [None; 4],
            entries: [false; 4],
        }
    }

    /// Checks one byte, returning `None` for an invalid digit index.
    pub fn allows(self, digit: usize, byte: u8) -> Option<bool> {
        let fixed = *self.fixed.get(digit)?;
        let entry = *self.entries.get(digit)?;
        Some(fixed.is_none_or(|value| value == byte) && (!entry || ENTRY_BYTES.contains(&byte)))
    }
}

/// Checked head geometry. Semantic and original-byte checks remain caller-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PunHead {
    source: AddressRange,
    displaced: AddressRange,
    consumed: AddressRange,
    len: usize,
    prefixes: usize,
}

/// Checks the head stage, before the caller's instruction/entry qualification.
///
/// Range construction precedes the short-window predicates. `NoPatchWindow`
/// identifies those predicates; malformed ranges retain `InvalidRange`.
pub fn pun_head(
    physical: u64,
    len: usize,
    prefixes: usize,
    source: AddressRange,
    block: AddressRange,
    max_displaced: usize,
) -> Result<PunHead, Refusal> {
    let displaced = AddressRange::new(physical, len)?;
    let consumed = AddressRange::new(
        physical,
        5_usize.checked_add(prefixes).ok_or(Refusal::InvalidRange)?,
    )?;
    if !(1..=4).contains(&len)
        || prefixes >= len
        || len > max_displaced
        || !block.covers(displaced)
        || !source.covers(consumed)
        || physical / 64 != (displaced.end() - 1) / 64
    {
        return Err(Refusal::NoPatchWindow);
    }
    Ok(PunHead {
        source,
        displaced,
        consumed,
        len,
        prefixes,
    })
}

impl PunHead {
    /// Whole original instruction, including every byte the caller must guard.
    pub const fn displaced(self) -> AddressRange {
        self.displaced
    }

    /// Redirect fetch extent, including unchanged successor bytes.
    pub const fn consumed(self) -> AddressRange {
        self.consumed
    }

    /// Checks store geometry at the caller's separate store-check stage.
    pub fn store_range(self) -> Result<AddressRange, Refusal> {
        let physical = self.displaced.start();
        let store_len = self.len.next_power_of_two();
        // x86 has no three-byte MOV. Preserve the successor byte, or the
        // preceding byte at offset 61, without crossing a cache line.
        let store_address = physical.min((physical | 63) - (store_len as u64 - 1));
        let store = AddressRange::new(store_address, store_len)?;
        if !self.source.covers(store) {
            return Err(Refusal::NoPatchWindow);
        }
        Ok(store)
    }

    /// Reads the supplied current suffix after the caller's original-byte guard.
    ///
    /// No clipping is performed: an unrepresentable signed low target returns
    /// `AllocationUnavailable`; overflowing window construction is `InvalidRange`.
    pub fn targets(self, current_code: &[u8]) -> Result<PunTargets, Refusal> {
        let offset = usize::try_from(self.displaced.start() - self.source.start())
            .map_err(|_| Refusal::InvalidRange)?;
        let start = offset.checked_add(self.len).ok_or(Refusal::InvalidRange)?;
        let end = offset
            .checked_add(5 + self.prefixes)
            .ok_or(Refusal::InvalidRange)?;
        let suffix = current_code.get(start..end).ok_or(Refusal::InvalidRange)?;
        let free = self.len - self.prefixes - 1;
        let mut fixed = [0_u8; 4];
        fixed[free..].copy_from_slice(suffix);
        let next = self.consumed.end();
        let low = u64::try_from(i128::from(next) + i128::from(i32::from_le_bytes(fixed)))
            .map_err(|_| Refusal::AllocationUnavailable)?;
        let window = AddressRange::new(low, 1_usize << (8 * free))?;
        Ok(PunTargets {
            window,
            offset,
            free,
            next,
            fixed,
        })
    }
}

/// Exact suffix-derived geometry, independent of any placement search policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PunTargets {
    window: AddressRange,
    offset: usize,
    free: usize,
    next: u64,
    fixed: [u8; 4],
}

impl PunTargets {
    /// Complete, untrimmed target interval.
    pub const fn window(self) -> AddressRange {
        self.window
    }

    /// Instruction offset in the current source byte slice.
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Low displacement bytes supplied by the rewritten instruction.
    pub const fn free_bytes(self) -> usize {
        self.free
    }

    /// Redirect's next instruction address.
    pub const fn next(self) -> u64 {
        self.next
    }

    /// Current fixed suffix with zeroes in the freely chosen low bytes.
    pub const fn raw_displacement(self) -> [u8; 4] {
        self.fixed
    }

    /// The same fixed suffix as descriptive rel32 byte constraints.
    pub fn constraints(self) -> Rel32Constraints {
        let mut result = Rel32Constraints::plain(self.next);
        for (slot, byte) in result.fixed.iter_mut().zip(self.fixed).skip(self.free) {
            *slot = Some(byte);
        }
        result
    }
}

#[cfg(test)]
mod tests;
