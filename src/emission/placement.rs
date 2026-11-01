//! One arithmetic placement preference, never an image-size certificate.
//!
//! This is used only by the explicit current-placement artifact entrypoint.
//! It changes no range or budget and does not call an encoder or planner.

use crate::contracts::{AddressRange, Refusal};
use crate::quiescent::{AllocationPolicy, candidate_target};

const PAGE: u64 = 4096;

pub(crate) fn validate(policy: &AllocationPolicy) -> Result<(), Refusal> {
    if policy.max_candidates != 1
        || policy.max_mappings != 1
        || policy.max_mapped_bytes != PAGE as usize
        || policy.ranges.is_empty()
        || policy.ranges.len() > 16
        || policy
            .ranges
            .iter()
            .any(|range| range.start() & (PAGE - 1) != 0 || range.end() & (PAGE - 1) != 0)
    {
        return Err(Refusal::InvalidRange);
    }
    Ok(())
}

// Work is proportional to the finite input intervals, never the arena's pages.
// Round every occupied byte outward: a partially occupied page is unavailable.
fn free_pages(
    policy: &AllocationPolicy,
    occupied: &[AddressRange],
    source: AddressRange,
) -> Result<Vec<AddressRange>, Refusal> {
    validate(policy)?;
    let mut held = Vec::with_capacity(occupied.len() + 1);
    for range in occupied.iter().chain(std::iter::once(&source)) {
        let start = range.start() & !(PAGE - 1);
        let end = range
            .end()
            .checked_add(PAGE - 1)
            .ok_or(Refusal::InvalidRange)?
            & !(PAGE - 1);
        held.push((start, end));
    }
    held.sort_unstable();
    let mut free = Vec::new();
    for range in &policy.ranges {
        let mut cursor = range.start();
        for &(start, end) in &held {
            if end <= cursor {
                continue;
            }
            if start >= range.end() {
                break;
            }
            if start > cursor {
                free.push(AddressRange::new(cursor, (start - cursor) as usize)?);
            }
            cursor = cursor.max(end).min(range.end());
            if cursor == range.end() {
                break;
            }
        }
        if cursor < range.end() {
            free.push(AddressRange::new(cursor, (range.end() - cursor) as usize)?);
        }
    }
    Ok(free)
}

fn available(target: u64, free: &[AddressRange]) -> bool {
    AddressRange::new(target & !(PAGE - 1), PAGE as usize)
        .is_ok_and(|page| free.iter().any(|range| range.covers(page)))
}

pub(crate) fn for_pun(
    policy: &AllocationPolicy,
    window: AddressRange,
    occupied: &[AddressRange],
    source: AddressRange,
) -> Result<AllocationPolicy, Refusal> {
    let free = free_pages(policy, occupied, source)?;
    if policy
        .preferred_address
        .is_some_and(|seed| window.contains(seed) && available(seed, &free))
    {
        return Ok(policy.clone());
    }
    let target = free
        .iter()
        .filter_map(|range| {
            let low = range.start().max(window.start());
            let high = range.end().min(window.end());
            if low >= high {
                return None;
            }
            // A boundary is the lowest attainable offset, otherwise use low.
            let boundary = low.checked_add(PAGE - 1)? & !(PAGE - 1);
            Some(if boundary < high { boundary } else { low })
        })
        .min_by_key(|target| (target % PAGE, *target))
        .ok_or(Refusal::AllocationUnavailable)?;
    let mut effective = policy.clone();
    effective.preferred_address = Some(target);
    Ok(effective)
}

pub(crate) fn for_relocation(
    policy: &AllocationPolicy,
    physical: u64,
    mask: [bool; 4],
    occupied: &[AddressRange],
    source: AddressRange,
) -> Result<AllocationPolicy, Refusal> {
    let free = free_pages(policy, occupied, source)?;
    // candidate_target evaluates this even when a preferred address is present.
    let next = physical.checked_add(5).ok_or(Refusal::InvalidRange)?;
    next.checked_add(0x1_0000).ok_or(Refusal::InvalidRange)?;
    if candidate_target(physical, mask, policy.preferred_address, 0)
        .is_some_and(|seed| available(seed, &free))
    {
        // Geometric availability says nothing about the eventual image length.
        return Ok(policy.clone());
    }
    let fixed_mask = mask.iter().enumerate().fold(0_u64, |bits, (i, set)| {
        bits | if *set { 0xff_u64 << (i * 8) } else { 0 }
    });
    // q = displacement - i32::MIN is monotone in target address. Its sign bit
    // is inverted relative to the encoded signed displacement.
    let fixed_value = (0x0606_0606_u64 ^ 0x8000_0000) & fixed_mask;
    let mut best: Option<u64> = None;
    for range in free {
        let low = (i128::from(range.start()) - i128::from(next)).max(i128::from(i32::MIN));
        let high = (i128::from(range.end() - 1) - i128::from(next)).min(i128::from(i32::MAX));
        if low > high {
            continue;
        }
        let qlow = (low - i128::from(i32::MIN)) as u64;
        let qhigh = (high - i128::from(i32::MIN)) as u64;
        if let Some(q) = low_offset(qlow, qhigh, fixed_mask, fixed_value, next % PAGE) {
            let target = u64::try_from(i128::from(next) + i128::from(i32::MIN) + i128::from(q))
                .map_err(|_| Refusal::InvalidRange)?;
            if best.is_none_or(|old| (target % PAGE, target) < (old % PAGE, old)) {
                best = Some(target);
            }
        }
    }
    let target = best.ok_or(Refusal::AllocationUnavailable)?;
    if candidate_target(physical, mask, Some(target), 0) != Some(target) {
        return Err(Refusal::InvalidPlan);
    }
    let mut effective = policy.clone();
    effective.preferred_address = Some(target);
    Ok(effective)
}

// Least fixed-bit integer in an inclusive interval. Each carry either finishes
// or moves the highest mismatch upward; at most 32 carries are possible.
fn first_fixed(low: u64, high: u64, mask: u64, value: u64) -> Option<u64> {
    if low > high || high > u64::from(u32::MAX) || mask > u64::from(u32::MAX) || value & !mask != 0
    {
        return None;
    }
    let mut candidate = low;
    for _ in 0..=u32::BITS {
        if candidate > high {
            return None;
        }
        let mismatch = (candidate ^ value) & mask;
        if mismatch == 0 {
            return Some(candidate);
        }
        let bit = 1_u64 << (63 - mismatch.leading_zeros());
        if value & bit != 0 {
            candidate = ((candidate | bit) & !(bit - 1)) | (value & (bit - 1));
        } else {
            let unit = bit.checked_mul(2)?;
            candidate =
                (candidate / unit).checked_add(1)?.checked_mul(unit)? | (value & (unit - 1));
        }
    }
    None
}

// Minimize the page offset of next + q; i32::MIN is page aligned. Split only
// the two partial q pages and one full-page interval, not every page/address.
fn low_offset(low: u64, high: u64, mask: u64, value: u64, next_low: u64) -> Option<u64> {
    let first = low / PAGE;
    let last = high / PAGE;
    let mut best: Option<u64> = None;
    let mut consider = |page: u64, left: u64, right: u64| {
        if page & (mask >> 12) != value >> 12 || left > right {
            return;
        }
        let turn = (PAGE - next_low) % PAGE;
        let tail = first_fixed(left.max(turn), right, mask & (PAGE - 1), value & (PAGE - 1));
        let head = if turn == 0 {
            None
        } else {
            first_fixed(
                left,
                right.min(turn - 1),
                mask & (PAGE - 1),
                value & (PAGE - 1),
            )
        };
        if let Some(part) = tail.or(head) {
            let q = page * PAGE + part;
            if best.is_none_or(|old| ((q + next_low) % PAGE, q) < ((old + next_low) % PAGE, old)) {
                best = Some(q);
            }
        }
    };
    consider(
        first,
        low % PAGE,
        if first == last { high % PAGE } else { PAGE - 1 },
    );
    if first < last {
        if let Some(page) = first_fixed(first + 1, last - 1, mask >> 12, value >> 12) {
            consider(page, 0, PAGE - 1);
        }
        consider(last, 0, high % PAGE);
    }
    best
}

#[cfg(test)]
mod tests;
