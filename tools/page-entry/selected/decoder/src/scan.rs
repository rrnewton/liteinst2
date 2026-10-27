//! All-byte-start facts for one page and its authenticated contiguous halos.

use crate::abi::*;

pub(crate) const PAGE: usize = 4096;
pub(crate) const HALO: usize = 14;
pub(crate) const MAX_WINDOW: usize = PAGE + 2 * HALO;

// SAFETY: caller owns out_rows for capacity elements, disjoint from input/scan.
pub(crate) unsafe fn page(
    base: u64,
    bytes: &[u8],
    page: u64,
    before_nonexec: bool,
    after_nonexec: bool,
    out_rows: *mut Decoded,
    capacity: usize,
    out: &mut Scan,
) -> u32 {
    if page % PAGE as u64 != 0
        || bytes.is_empty()
        || bytes.len() > MAX_WINDOW
        || capacity > MAX_WINDOW
        || (capacity != 0 && out_rows.is_null())
    {
        return BAD_ARGUMENT;
    }
    let Some(window_end) = base.checked_add(bytes.len() as u64) else {
        return ADDRESS_OVERFLOW;
    };
    let Some(start) = page.checked_sub(base).and_then(|n| usize::try_from(n).ok()) else {
        return BAD_ARGUMENT;
    };
    let Some(end) = start.checked_add(PAGE).filter(|n| *n <= bytes.len()) else {
        return BAD_ARGUMENT;
    };
    if (start < HALO && !before_nonexec) || (bytes.len() - end < HALO && !after_nonexec) {
        return MISSING_BOUNDARY;
    }
    let first = start.saturating_sub(HALO);
    out.page = page;
    out.dependency_first = base + first as u64;
    out.dependency_end = window_end;
    for offset in first..end {
        let available = (bytes.len() - offset).min(15);
        let row = match crate::decode::one(base + offset as u64, &bytes[offset..offset + available])
        {
            Ok(row) => row,
            Err(error) => return error,
        };
        out.starts += 1;
        if row.decode_status != VALID {
            if row.decode_status == TRUNCATED {
                out.truncated_starts += 1;
            } else {
                out.invalid_starts += 1;
            }
            continue;
        }
        // Fixed full default policy, never CPUID-filtered. Every selected
        // decode intersecting the requested page is retained, including RSP.
        if !(CPUID..=SYSCALL).contains(&row.kind) || row.next_pc <= page {
            continue;
        }
        out.candidates += 1;
        out.by_class[(row.kind - 1) as usize] += 1;
        if (out.written as usize) < capacity {
            // SAFETY: prevalidated output allocation; index is below capacity.
            unsafe {
                out_rows.add(out.written as usize).write(row);
            }
            out.written += 1;
        }
    }
    if out.candidates != out.written {
        return OUTPUT_CAPACITY;
    }
    out.complete = 1;
    OK
}
