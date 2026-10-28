//! Finite lazy search of page-aligned starts in the captured reachable gaps.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NearGap {
    pub(super) next: usize,
    pub(super) last: usize,
    pub(super) descending: bool,
}
pub(super) struct NearCandidates {
    gaps: std::vec::IntoIter<NearGap>,
    current: Option<NearGap>,
    page_size: usize,
}
impl NearCandidates {
    pub(super) fn new(gaps: Vec<NearGap>, page_size: usize) -> Self {
        Self {
            gaps: gaps.into_iter(),
            current: None,
            page_size,
        }
    }
}
impl Iterator for NearCandidates {
    type Item = usize;
    fn next(&mut self) -> Option<usize> {
        let mut gap = self.current.take().or_else(|| self.gaps.next())?;
        let candidate = gap.next;
        if candidate != gap.last {
            gap.next = if gap.descending {
                candidate.checked_sub(self.page_size)?
            } else {
                candidate.checked_add(self.page_size)?
            };
            self.current = Some(gap);
        }
        Some(candidate)
    }
}
pub(super) fn near_start_bounds(
    next_ip: usize,
    len: usize,
    page_size: usize,
) -> Result<(usize, usize), TrampolineError> {
    if !page_size.is_power_of_two() || len == 0 || len % page_size != 0 {
        return Err(TrampolineError::InvalidPageSize);
    }
    let low = (next_ip as i128 + i32::MIN as i128).max(page_size as i128);
    // The final byte, not only the first slot, must satisfy can_reach().
    let high =
        (next_ip as i128 + i32::MAX as i128 - (len - 1) as i128).min((usize::MAX - len) as i128);
    if low > high {
        return Err(TrampolineError::NoReachableMapping);
    }
    Ok((low as usize, high as usize))
}
pub(super) fn claim_near_candidate(
    candidates: impl IntoIterator<Item = usize>,
    mut claim: impl FnMut(usize) -> Result<bool, TrampolineError>,
) -> Result<usize, TrampolineError> {
    for candidate in candidates {
        // false has exactly one production meaning: mmap returned EEXIST.
        // ENOMEM/EACCES/etc. stop immediately rather than amplifying syscalls.
        if claim(candidate)? {
            return Ok(candidate);
        }
    }
    Err(TrampolineError::NoReachableMapping)
}

#[cfg(test)]
mod tests;
