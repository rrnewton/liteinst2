//! One arithmetic pair for E9 at V and E9 at V+1, before either body encode.
use super::{AllocationPolicy, PAGE, certificate, certified, free_pages};
use crate::contracts::{AddressRange, Refusal};

const CLASS: i128 = 1 << 24;
const SIGN: i128 = 1 << 32;

/// Returns (selected entry, victim entry), not image/allocation authority.
///
/// First preserve a feasible selected hint and its uniquely correlated victim;
/// otherwise preserve a feasible victim hint with the least selected address;
/// otherwise take the least selected address in the finite feasible pair set.
/// The two complete pages must be different. Hints never add permits.
///
/// The caller still qualifies the original victim and V+1 rel8, prepares each
/// role once, charges its one pair/image slot, emits each image once, and checks
/// actual extents, fields, canonical source bytes and complete composition.
pub(crate) fn joint_overlapping_targets(
    selected_policy: &AllocationPolicy,
    victim_policy: &AllocationPolicy,
    occupied: &[AddressRange],
    source: AddressRange,
    victim: u64,
    selected_bound: usize,
    victim_bound: usize,
) -> Result<(u64, u64), Refusal> {
    certificate(selected_bound)?;
    certificate(victim_bound)?;
    let space = PairSpace {
        selected: normalized_free(selected_policy, occupied, source)?,
        victim: normalized_free(victim_policy, occupied, source)?,
        selected_next: victim.checked_add(6).ok_or(Refusal::InvalidRange)?,
        victim_next: victim.checked_add(5).ok_or(Refusal::InvalidRange)?,
        selected_bound,
        victim_bound,
    };
    if let Some(seed) = selected_policy.preferred_address
        && let Ok(d) = i32::try_from(i128::from(seed) - i128::from(space.selected_next))
    {
        let d = i128::from(d);
        if let Some(pair) = space.targets(d.div_euclid(CLASS), d.rem_euclid(CLASS))
            && space.allowed(pair)
        {
            return Ok(pair);
        }
    }
    if let Some(seed) = victim_policy.preferred_address
        && let Ok(d) = i32::try_from(i128::from(seed) - i128::from(space.victim_next))
    {
        let encoded = d as u32;
        if encoded & 255 == 0xe9 {
            let r = i128::from(encoded >> 8);
            for k in -128..=127 {
                if let Some(pair) = space.targets(k, r)
                    && space.allowed(pair)
                {
                    return Ok(pair);
                }
            }
        }
    }
    // Each half is monotone in r. No free-page Cartesian product or page scan.
    let victim_halves = [space.victim_intervals(false), space.victim_intervals(true)];
    for k in -128..=127 {
        let selected = space.selected_intervals(k);
        for (negative, victim_ranges) in victim_halves.iter().enumerate() {
            let (mut a, mut b) = (0, 0);
            while a < selected.len() && b < victim_ranges.len() {
                let low = selected[a].0.max(victim_ranges[b].0);
                let high = selected[a].1.min(victim_ranges[b].1);
                if low <= high
                    && let Some(r) = space.first_distinct(low, high, k, negative != 0)
                {
                    let pair = space.targets(k, r).ok_or(Refusal::InvalidPlan)?;
                    if !space.allowed(pair) {
                        return Err(Refusal::InvalidPlan);
                    }
                    return Ok(pair);
                }
                if selected[a].1 <= victim_ranges[b].1 {
                    a += 1;
                } else {
                    b += 1;
                }
            }
        }
    }
    Err(Refusal::AllocationUnavailable)
}

fn normalized_free(
    policy: &AllocationPolicy,
    occupied: &[AddressRange],
    source: AddressRange,
) -> Result<Vec<(u64, u64)>, Refusal> {
    let mut ranges: Vec<_> = free_pages(policy, occupied, source)?
        .into_iter()
        .map(|range| (range.start(), range.end()))
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    Ok(merged)
}

struct PairSpace {
    selected: Vec<(u64, u64)>,
    victim: Vec<(u64, u64)>,
    selected_next: u64,
    victim_next: u64,
    selected_bound: usize,
    victim_bound: usize,
}

impl PairSpace {
    fn targets(&self, k: i128, r: i128) -> Option<(u64, u64)> {
        if !(-128..=127).contains(&k) || !(0..CLASS).contains(&r) {
            return None;
        }
        let selected = i128::from(self.selected_next) + k * CLASS + r;
        let victim =
            i128::from(self.victim_next) + 0xe9 + 256 * r - if r >= CLASS / 2 { SIGN } else { 0 };
        Some((u64::try_from(selected).ok()?, u64::try_from(victim).ok()?))
    }

    fn allowed(&self, (selected, victim): (u64, u64)) -> bool {
        let covered = |ranges: &[(u64, u64)], target: u64| {
            let page = target & !(PAGE - 1);
            page.checked_add(PAGE)
                .is_some_and(|end| ranges.iter().any(|&(a, b)| a <= page && end <= b))
        };
        selected / PAGE != victim / PAGE
            && certified(selected, self.selected_bound)
            && certified(victim, self.victim_bound)
            && covered(&self.selected, selected)
            && covered(&self.victim, victim)
    }

    fn selected_intervals(&self, k: i128) -> Vec<(i128, i128)> {
        let origin = i128::from(self.selected_next) + k * CLASS;
        self.selected
            .iter()
            .filter_map(|&(a, b)| {
                let low = (i128::from(a) - origin).max(0);
                let high = (i128::from(b) - 1 - origin).min(CLASS - 1);
                (low <= high).then_some((low, high))
            })
            .collect()
    }

    fn victim_intervals(&self, negative: bool) -> Vec<(i128, i128)> {
        let origin = i128::from(self.victim_next) + 0xe9 - if negative { SIGN } else { 0 };
        let (first, last) = if negative {
            (CLASS / 2, CLASS - 1)
        } else {
            (0, CLASS / 2 - 1)
        };
        self.victim
            .iter()
            .filter_map(|&(a, b)| {
                let low = ceil_div(i128::from(a) - origin, 256).max(first);
                let high = (i128::from(b) - 1 - origin).div_euclid(256).min(last);
                (low <= high).then_some((low, high))
            })
            .collect()
    }

    // Least r satisfying both page-offset certificates. The victim offset has
    // only sixteen residue classes; selected fit is one cyclic interval.
    fn first_fitting(&self, low: i128, high: i128) -> Option<i128> {
        if low > high {
            return None;
        }
        let page = i128::from(PAGE);
        let start = (-i128::from(self.selected_next)).rem_euclid(page);
        let end = start + page - self.selected_bound as i128;
        let windows = if end < page {
            vec![(start, end)]
        } else {
            vec![(0, end - page), (start, page - 1)]
        };
        let mut best: Option<i128> = None;
        for residue in 0..16 {
            let victim_offset =
                (i128::from(self.victim_next) + 0xe9 + 256 * residue).rem_euclid(page);
            if victim_offset + self.victim_bound as i128 > page {
                continue;
            }
            for &(a, b) in &windows {
                let first = a + (residue - a).rem_euclid(16);
                if first > b {
                    continue;
                }
                let cycle = low.div_euclid(page) * page;
                let within = a.max(low - cycle);
                let rounded = within + (residue - within).rem_euclid(16);
                let candidate = if rounded <= b {
                    cycle + rounded
                } else {
                    cycle + page + first
                };
                if candidate <= high && best.is_none_or(|old| candidate < old) {
                    best = Some(candidate);
                }
            }
        }
        best
    }

    fn first_distinct(&self, low: i128, high: i128, k: i128, negative: bool) -> Option<i128> {
        // T-S = 232 +255r -k*2^24 -sign*2^32. Equal pages require
        // abs(T-S)<=4095, an interval containing at most33 integer r values.
        let constant = 232 - k * CLASS - if negative { SIGN } else { 0 };
        let critical_low = ceil_div(-(i128::from(PAGE) - 1) - constant, 255).max(low);
        let critical_high = (i128::from(PAGE) - 1 - constant).div_euclid(255).min(high);
        if critical_low > critical_high {
            return self.first_fitting(low, high);
        }
        if let Some(r) = self.first_fitting(low, critical_low - 1) {
            return Some(r);
        }
        for r in critical_low..=critical_high {
            let (selected, victim) = self.targets(k, r)?;
            if selected / PAGE != victim / PAGE
                && certified(selected, self.selected_bound)
                && certified(victim, self.victim_bound)
            {
                return Some(r);
            }
        }
        self.first_fitting(critical_high + 1, high)
    }
}

fn ceil_div(value: i128, divisor: i128) -> i128 {
    -(-value).div_euclid(divisor)
}

#[cfg(test)]
mod tests;
