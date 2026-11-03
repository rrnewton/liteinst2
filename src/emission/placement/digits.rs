//! Pure bounded rel32 digit geometry, without mapping or image authority.
use crate::contracts::{AddressRange, Refusal};
use crate::quiescent::feasibility::Rel32Constraints;

const PAGE: u64 = 4096;

#[derive(Clone, Copy)]
struct ByteDomain([u64; 4]);

impl ByteDomain {
    fn from_allowed(mut allowed: impl FnMut(u8) -> bool) -> Self {
        let mut result = Self([0; 4]);
        for byte in 0..=u8::MAX {
            if allowed(byte) {
                result.0[usize::from(byte / 64)] |= 1_u64 << (byte % 64);
            }
        }
        result
    }

    fn one(byte: u8) -> Self {
        let mut result = Self([0; 4]);
        result.0[usize::from(byte / 64)] = 1_u64 << (byte % 64);
        result
    }

    fn contains(self, byte: u8) -> bool {
        self.0[usize::from(byte / 64)] & (1_u64 << (byte % 64)) != 0
    }
}

// q = signed displacement - i32::MIN. Only the top byte changes: XOR 0x80.
fn domains(constraints: Rel32Constraints) -> [ByteDomain; 4] {
    std::array::from_fn(|digit| {
        ByteDomain::from_allowed(|byte| {
            constraints.allows(digit, byte ^ if digit == 3 { 0x80 } else { 0 }) == Some(true)
        })
    })
}

struct DigitSearch<'a> {
    low: [u8; 4],
    high: [u8; 4],
    domains: &'a [ByteDomain; 4],
    // None is unvisited; Some(None) is a proved empty suffix. A suffix depends
    // only on depth and the two tight-bound flags, not on the chosen prefix.
    memo: [[Option<Option<u32>>; 4]; 4],
}

impl DigitSearch<'_> {
    fn suffix(&mut self, depth: usize, state: usize) -> Option<u32> {
        if depth == 4 {
            return Some(0);
        }
        if let Some(answer) = self.memo[depth][state] {
            return answer;
        }
        let digit = 3 - depth;
        let low = if state & 1 != 0 { self.low[digit] } else { 0 };
        let high = if state & 2 != 0 {
            self.high[digit]
        } else {
            u8::MAX
        };
        let mut answer = None;
        for byte in low..=high {
            if !self.domains[digit].contains(byte) {
                continue;
            }
            let next = usize::from(state & 1 != 0 && byte == self.low[digit])
                | (usize::from(state & 2 != 0 && byte == self.high[digit]) << 1);
            if let Some(tail) = self.suffix(depth + 1, next) {
                answer = Some((u32::from(byte) << (digit * 8)) | tail);
                break;
            }
        }
        self.memo[depth][state] = Some(answer);
        answer
    }
}

// At most four depths * four states * 256 digit transitions, with no address
// walk, allocation or exponential retry. The returned word is the least one.
fn first(low: u64, high: u64, domains: &[ByteDomain; 4]) -> Option<u64> {
    if low > high || high > u64::from(u32::MAX) {
        return None;
    }
    DigitSearch {
        low: (low as u32).to_le_bytes(),
        high: (high as u32).to_le_bytes(),
        domains,
        memo: [[None; 4]; 4],
    }
    .suffix(0, 3)
    .map(u64::from)
}

fn partial(
    page: u64,
    left: u64,
    right: u64,
    domains: &[ByteDomain; 4],
    next_low: u64,
) -> Option<u64> {
    if left > right
        || !domains[2].contains((page >> 4) as u8)
        || !domains[3].contains((page >> 12) as u8)
    {
        return None;
    }
    let high_nibble = ((page & 15) as u8) << 4;
    let low_domains = [
        domains[0],
        ByteDomain::from_allowed(|byte| byte < 16 && domains[1].contains(high_nibble | byte)),
        ByteDomain::one(0),
        ByteDomain::one(0),
    ];
    let turn = (PAGE - next_low) % PAGE;
    let part = first(left.max(turn), right, &low_domains).or_else(|| {
        if turn == 0 {
            None
        } else {
            first(left, right.min(turn - 1), &low_domains)
        }
    })?;
    Some(page * PAGE + part)
}

// Split two partial q pages and a full-page interval. The high nibble of byte1
// is the only coupling across bit12. For each of its 16 values, the lowest full
// page and its best low part independently minimize (target page offset, q).
fn minimum_offset(low: u64, high: u64, domains: &[ByteDomain; 4], next_low: u64) -> Option<u64> {
    if low > high || high > u64::from(u32::MAX) || next_low >= PAGE {
        return None;
    }
    let first_page = low / PAGE;
    let last_page = high / PAGE;
    let mut best = None;
    let mut consider = |page, left, right| {
        if let Some(q) = partial(page, left, right, domains, next_low) {
            if best.is_none_or(|old| ((q + next_low) % PAGE, q) < ((old + next_low) % PAGE, old)) {
                best = Some(q);
            }
        }
    };
    consider(
        first_page,
        low % PAGE,
        if first_page == last_page {
            high % PAGE
        } else {
            PAGE - 1
        },
    );
    if first_page < last_page {
        for high_nibble in 0_u8..16 {
            if !(0_u8..16).any(|low_nibble| domains[1].contains((high_nibble << 4) | low_nibble)) {
                continue;
            }
            // Low12 is fixed to zero only for this high-page query. The actual
            // byte1 low nibble is checked by partial, never treated as free.
            let high_domains = [
                ByteDomain::one(0),
                ByteDomain::one(high_nibble << 4),
                domains[2],
                domains[3],
            ];
            if let Some(q) = first((first_page + 1) * PAGE, last_page * PAGE - 1, &high_domains) {
                consider(q / PAGE, 0, PAGE - 1);
            }
        }
        consider(last_page, 0, high % PAGE);
    }
    best
}

/// Minimum (page offset, address) over the exact supplied intervals and byte
/// constraints. These are descriptive inputs, not free-page/source/entry or
/// size certificates. No encoder, allocation, search slot or planner is run.
pub(super) fn minimum_target(
    constraints: Rel32Constraints,
    intervals: &[AddressRange],
) -> Result<u64, Refusal> {
    let domains = domains(constraints);
    let mut best = None;
    for range in intervals {
        let low =
            (i128::from(range.start()) - i128::from(constraints.next)).max(i128::from(i32::MIN));
        let high =
            (i128::from(range.end() - 1) - i128::from(constraints.next)).min(i128::from(i32::MAX));
        if low > high {
            continue;
        }
        let low = (low - i128::from(i32::MIN)) as u64;
        let high = (high - i128::from(i32::MIN)) as u64;
        if let Some(q) = minimum_offset(low, high, &domains, constraints.next % PAGE) {
            let target =
                u64::try_from(i128::from(constraints.next) + i128::from(i32::MIN) + i128::from(q))
                    .map_err(|_| Refusal::InvalidRange)?;
            if best.is_none_or(|old| (target % PAGE, target) < (old % PAGE, old)) {
                best = Some(target);
            }
        }
    }
    best.ok_or(Refusal::AllocationUnavailable)
}

#[cfg(test)]
fn fixed_domains(mask: u64, value: u64) -> Option<[ByteDomain; 4]> {
    if mask > u64::from(u32::MAX) || value & !mask != 0 {
        return None;
    }
    Some(std::array::from_fn(|digit| {
        let mask = (mask >> (digit * 8)) as u8;
        let value = (value >> (digit * 8)) as u8;
        ByteDomain::from_allowed(|byte| byte & mask == value)
    }))
}

#[cfg(test)]
pub(super) fn first_fixed(low: u64, high: u64, mask: u64, value: u64) -> Option<u64> {
    first(low, high, &fixed_domains(mask, value)?)
}

#[cfg(test)]
pub(super) fn low_offset(low: u64, high: u64, mask: u64, value: u64, next_low: u64) -> Option<u64> {
    minimum_offset(low, high, &fixed_domains(mask, value)?, next_low)
}

#[cfg(test)]
mod tests;
