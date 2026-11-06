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
    let target = minimum_relocation_target(physical, mask, free, next)?;
    let mut effective = policy.clone();
    effective.preferred_address = Some(target);
    Ok(effective)
}

// Shared finite argmin; callers separately decide whether to preserve a seed.
fn minimum_relocation_target(
    physical: u64,
    mask: [bool; 4],
    free: Vec<AddressRange>,
    next: u64,
) -> Result<u64, Refusal> {
    let mut constraints = crate::quiescent::feasibility::Rel32Constraints::plain(next);
    for (fixed, constrained) in constraints.fixed.iter_mut().zip(mask) {
        if constrained {
            *fixed = Some(0x06);
        }
    }
    let target = digits::minimum_target(constraints, &free)?;
    if candidate_target(physical, mask, Some(target), 0) != Some(target) {
        return Err(Refusal::InvalidPlan);
    }
    Ok(target)
}

/// A certificate may conservatively refuse a genuinely fitting image; it never
/// licenses more than one page, one candidate or the caller's exact ranges.
fn certificate(bound: usize) -> Result<(), Refusal> {
    if bound == 0 || bound > PAGE as usize {
        return Err(Refusal::AllocationUnavailable);
    }
    Ok(())
}

fn certified(target: u64, bound: usize) -> bool {
    (target % PAGE)
        .checked_add(bound as u64)
        .is_some_and(|end| end <= PAGE)
}

pub(crate) fn fitting_for_pun(
    policy: &AllocationPolicy,
    window: AddressRange,
    occupied: &[AddressRange],
    source: AddressRange,
    bound: usize,
) -> Result<AllocationPolicy, Refusal> {
    certificate(bound)?;
    let free = free_pages(policy, occupied, source)?;
    if policy.preferred_address.is_some_and(|seed| {
        window.contains(seed) && available(seed, &free) && certified(seed, bound)
    }) {
        return Ok(policy.clone());
    }
    let mut without_seed = policy.clone();
    without_seed.preferred_address = None;
    let effective = for_pun(&without_seed, window, occupied, source)?;
    let target = effective
        .preferred_address
        .ok_or(Refusal::AllocationUnavailable)?;
    // for_pun returns the minimum page offset in the entire finite free/window
    // intersection. If that offset cannot be certified, no alternative is tried.
    if !certified(target, bound) {
        return Err(Refusal::AllocationUnavailable);
    }
    Ok(effective)
}

pub(crate) fn fitting_for_relocation(
    policy: &AllocationPolicy,
    physical: u64,
    mask: [bool; 4],
    occupied: &[AddressRange],
    source: AddressRange,
    bound: usize,
) -> Result<AllocationPolicy, Refusal> {
    certificate(bound)?;
    let free = free_pages(policy, occupied, source)?;
    let next = physical.checked_add(5).ok_or(Refusal::InvalidRange)?;
    next.checked_add(0x1_0000).ok_or(Refusal::InvalidRange)?;
    if candidate_target(physical, mask, policy.preferred_address, 0)
        .is_some_and(|seed| available(seed, &free) && certified(seed, bound))
    {
        return Ok(policy.clone());
    }
    let target = minimum_relocation_target(physical, mask, free, next)?;
    if !certified(target, bound) {
        return Err(Refusal::AllocationUnavailable);
    }
    let mut effective = policy.clone();
    effective.preferred_address = Some(target);
    Ok(effective)
}

mod digits;

// Keep the existing private arithmetic control entrypoints over the shared
// digit query; production relocation uses the same query through fixed-06.
#[cfg(test)]
use digits::{first_fixed, low_offset};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fitting_tests;

/// One short-T3 selected-entry envelope, computed before any body encode.
/// The caller first preserves an available direct fitting result, and supplies
/// the actual victim mapping among `occupied`. No policy bound is modified.
/// Refusal means this finite certificate failed, not universal impossibility.
pub(crate) fn entry_veneer_for_pun(
    policy: &AllocationPolicy,
    window: AddressRange,
    occupied: &[AddressRange],
    source: AddressRange,
    bound: usize,
) -> Result<crate::trampoline::EntryVeneerPlacement, Refusal> {
    use crate::trampoline::EntryVeneerPlacement;
    if bound == 0 || bound > PAGE as usize - 5 {
        return Err(Refusal::AllocationUnavailable);
    }
    let free = free_pages(policy, occupied, source)?;
    let layout = |entry: u64| EntryVeneerPlacement::new(entry & !(PAGE - 1), entry, bound);
    if let Some(seed) = policy.preferred_address
        && window.contains(seed)
        && available(seed, &free)
        && let Ok(placement) = layout(seed)
    {
        return Ok(placement);
    }
    let mut best: Option<u64> = None;
    for range in &free {
        let low = range.start().max(window.start());
        let high = range.end().min(window.end());
        if low >= high {
            continue;
        }
        let first = low & !(PAGE - 1);
        let last = (high - 1) & !(PAGE - 1);
        let mut consider = |page: u64| -> Result<(), Refusal> {
            // free pages are whole intervals; only the window clips this page.
            let entry = low.max(
                page.checked_add(bound as u64)
                    .ok_or(Refusal::InvalidRange)?,
            );
            let final_entry = page.checked_add(PAGE - 5).ok_or(Refusal::InvalidRange)?;
            if entry < high
                && entry <= final_entry
                && best.is_none_or(|old| (entry % PAGE, entry) < (old % PAGE, old))
            {
                best = Some(entry);
            }
            Ok(())
        };
        consider(first)?;
        if last != first {
            // The earliest complete page, when there is one, attains offset U.
            // Later complete pages cannot improve its (offset,address) pair.
            let next = first.checked_add(PAGE).ok_or(Refusal::InvalidRange)?;
            if next < last {
                consider(next)?;
            }
            consider(last)?;
        }
    }
    let entry = best.ok_or(Refusal::AllocationUnavailable)?;
    if !window.contains(entry) || !available(entry, &free) {
        return Err(Refusal::InvalidPlan);
    }
    layout(entry)
}

#[cfg(test)]
mod entry_veneer_tests;

// Explicit overlapping source relays; existing placement modes stay unchanged.
mod overlap;
pub(crate) use overlap::joint_overlapping_targets;

// Explicit artifact-only certified target; legacy wrappers above stay unchanged.
mod entry_alphabet;
pub(crate) use entry_alphabet::{RelocationPlacementFacts, entry_alphabet_fitting};
