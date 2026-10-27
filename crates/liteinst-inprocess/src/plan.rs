use crate::GateError;

pub(crate) const PAGE: usize = 4096;
const MAX_PAGES: usize = 16_384;
const MAX_HEADS: usize = 262_144;
const MAX_BUNDLES: usize = 16_384;

/// One complete final instruction fetch, relative to the owned source mapping.
/// Entries are strictly ordered by offset. Overlapping streams are permitted
/// only under the caller's complete execution/publication proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstructionExtent {
    pub offset: usize,
    pub len: usize,
    pub bundle: usize,
}

/// A prequalified contiguous page dependency closure. It may include already
/// admitted pages; every page remains part of the immutable source contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageBundle {
    pub first_page: usize,
    pub page_count: usize,
}

pub(crate) struct Plan {
    pub(crate) instructions: Vec<InstructionExtent>,
    pub(crate) bundles: Vec<PageBundle>,
    pub(crate) pages: usize,
}

impl Plan {
    pub(crate) fn new(
        base: usize,
        len: usize,
        instructions: &[InstructionExtent],
        bundles: &[PageBundle],
    ) -> Result<Self, GateError> {
        if base == 0 || base % PAGE != 0 || len == 0 || len % PAGE != 0 {
            return Err(GateError::Invalid("source is not a nonempty page range"));
        }
        base.checked_add(len)
            .ok_or(GateError::Invalid("source end overflow"))?;
        if len / PAGE > MAX_PAGES
            || instructions.is_empty()
            || instructions.len() > MAX_HEADS
            || bundles.is_empty()
            || bundles.len() > MAX_BUNDLES
        {
            return Err(GateError::Invalid("source metadata bound"));
        }
        for bundle in bundles {
            let end = bundle
                .first_page
                .checked_add(bundle.page_count)
                .ok_or(GateError::Invalid("bundle end overflow"))?;
            if bundle.page_count == 0 || end > len / PAGE {
                return Err(GateError::Invalid("bundle outside source"));
            }
        }
        let mut previous = None;
        for instruction in instructions {
            if previous.is_some_and(|offset| offset >= instruction.offset) {
                return Err(GateError::Invalid("instruction heads not strictly ordered"));
            }
            previous = Some(instruction.offset);
            let end = instruction
                .offset
                .checked_add(instruction.len)
                .ok_or(GateError::Invalid("instruction end overflow"))?;
            if !(1..=15).contains(&instruction.len) || end > len {
                return Err(GateError::Invalid("invalid complete instruction extent"));
            }
            let bundle = bundles
                .get(instruction.bundle)
                .ok_or(GateError::Invalid("instruction bundle absent"))?;
            if instruction.offset / PAGE < bundle.first_page
                || (end - 1) / PAGE >= bundle.first_page + bundle.page_count
            {
                return Err(GateError::Invalid("bundle omits fetch page"));
            }
        }
        let mut owned_instructions = Vec::new();
        owned_instructions
            .try_reserve_exact(instructions.len())
            .map_err(|_| GateError::Invalid("instruction metadata allocation"))?;
        owned_instructions.extend_from_slice(instructions);
        let mut owned_bundles = Vec::new();
        owned_bundles
            .try_reserve_exact(bundles.len())
            .map_err(|_| GateError::Invalid("bundle metadata allocation"))?;
        owned_bundles.extend_from_slice(bundles);
        Ok(Self {
            instructions: owned_instructions,
            bundles: owned_bundles,
            pages: len / PAGE,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Fetch {
    pub(crate) signal: i32,
    pub(crate) code: i32,
    pub(crate) trap: u64,
    pub(crate) error: u64,
    pub(crate) pc: usize,
    pub(crate) address: usize,
}

/// Descriptive authentication only. Live pending-state and byte checks remain
/// separate, and this function cannot grant execute permission.
pub(crate) fn fetch_instruction(
    base: usize,
    len: usize,
    instructions: &[InstructionExtent],
    fetch: Fetch,
) -> Option<InstructionExtent> {
    if fetch.signal != libc::SIGSEGV
        || fetch.code != 2
        || fetch.trap != 14
        || fetch.error & (1 << 4) == 0
        || fetch.error & (1 << 1) != 0
        || fetch.error & (1 << 2) == 0
    {
        return None;
    }
    let offset = fetch.pc.checked_sub(base)?;
    let address = fetch.address.checked_sub(base)?;
    if offset >= len || address >= len {
        return None;
    }
    let index = instructions
        .binary_search_by_key(&offset, |entry| entry.offset)
        .ok()?;
    let instruction = *instructions.get(index)?;
    let end = offset.checked_add(instruction.len)?;
    if address < offset || address >= end {
        return None;
    }
    Some(instruction)
}

/// Reads exactly the supplied initialized buffers, with no libc memcmp call.
/// The caller retains two readable buffers of at least `len` bytes.
pub(crate) unsafe fn bytes_equal(actual: *const u8, expected: *const u8, len: usize) -> bool {
    for offset in 0..len {
        // SAFETY: forwarded checked readable-buffer extent.
        let (actual, expected) = unsafe {
            (
                core::ptr::read_volatile(actual.add(offset)),
                core::ptr::read_volatile(expected.add(offset)),
            )
        };
        if actual != expected {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests;
