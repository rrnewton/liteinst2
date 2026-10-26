//! Exhaustive table walks; row-count equality is never a replacement for them.
use super::rows::PairRows;
use super::*;

fn island_row(row: MapEntry<'_>, island: &Range<u64>) -> bool {
    row.start == island.start && row.end == island.end
}

fn exact_clear(old: MapEntry<'_>, actual: MapEntry<'_>) -> bool {
    if !executable(old) || old.raw_line.len() != actual.raw_line.len() {
        return false;
    }
    let mut permissions = old.permissions.bytes();
    permissions[2] = b'-';
    if actual.permissions.bytes() != permissions {
        return false;
    }
    let Some(start) = old.raw_line.iter().position(|byte| *byte == b' ') else {
        return false;
    };
    let Some(skip) = old.raw_line[start..].iter().position(|byte| *byte != b' ') else {
        return false;
    };
    let column = start + skip + 2;
    old.raw_line
        .iter()
        .zip(actual.raw_line)
        .enumerate()
        .all(|(index, (a, b))| {
            if index == column {
                *a == b'x' && *b == b'-'
            } else {
                a == b
            }
        })
}

impl InitialMapPlan {
    pub(in crate::linux::remote::dynamic::owner) fn verify_snapshot(
        &self,
        original: &[u8],
        actual: &[u8],
        island: &Range<u64>,
        quarantined_executable_prefix: usize,
    ) -> Result<InitialMapProjection, LaunchError> {
        let old = self.require_original(original)?;
        let new = parse(actual)?;
        if quarantined_executable_prefix > self.executable_count
            || island.start == 0
            || island.start % PAGE != 0
            || island.end.checked_sub(island.start) != Some(PAGE)
            || island.end > USER_END
            || old
                .entries()
                .any(|row| row.start < island.end && island.start < row.end)
        {
            return Err(invalid());
        }
        let (island_index, observed_island) = new
            .entries()
            .enumerate()
            .find(|(_, row)| island_row(*row, island))
            .ok_or_else(invalid)?;
        if observed_island.permissions.bytes() != *b"r-xp"
            || observed_island.file_offset != 0
            || file(observed_island) != (0, 0, 0)
            || observed_island.pathname.is_some()
        {
            return Err(invalid());
        }
        // Full parsing already proves disjoint ordered rows, so the exact
        // island range occurs once. Every other actual row is consumed below.
        let mut current = new
            .entries()
            .enumerate()
            .filter(|(_, row)| !island_row(*row, island));
        let mut originals = old.entries().enumerate();
        let mut executable_ordinal = 0usize;
        let mut pair_projection = None;
        while let Some((index, prior)) = originals.next() {
            let (actual_index, row) = current.next().ok_or_else(invalid)?;
            if index == self.lower_index {
                let (upper_index, upper) = originals.next().ok_or_else(invalid)?;
                if upper_index != self.upper_index
                    || executable_ordinal != self.target_executable_ordinal
                {
                    return Err(invalid());
                }
                let pair = PairRows::new(prior, upper)?;
                let cleared = executable_ordinal < quarantined_executable_prefix;
                let (merged, rx_index, rx_row) =
                    if cleared && row.start == prior.start && row.end == upper.end {
                        pair.verify_union_nx(row)?;
                        (true, actual_index, row)
                    } else {
                        let (next_index, next) = current.next().ok_or_else(invalid)?;
                        if cleared {
                            pair.verify_separate_nx(row, next)?;
                        } else {
                            // A pair cannot merge before its original RX row is
                            // the actual target of a quarantine operation.
                            pair.verify_open_pair(row, next)?;
                        }
                        (false, next_index, next)
                    };
                pair_projection = Some((
                    merged,
                    actual_index,
                    rx_index,
                    span(actual, row),
                    span(actual, rx_row),
                ));
                executable_ordinal = executable_ordinal.checked_add(1).ok_or_else(invalid)?;
            } else if executable(prior) {
                let cleared = executable_ordinal < quarantined_executable_prefix;
                if (cleared && !exact_clear(prior, row))
                    || (!cleared && prior.raw_line != row.raw_line)
                {
                    return Err(invalid());
                }
                executable_ordinal = executable_ordinal.checked_add(1).ok_or_else(invalid)?;
            } else if prior.raw_line != row.raw_line {
                return Err(invalid());
            }
        }
        let (merged, lower_current_index, rx_current_index, lower_current_span, rx_current_span) =
            pair_projection.ok_or_else(invalid)?;
        let expected_rows = self
            .original_rows
            .checked_add(1)
            .and_then(|count| count.checked_sub(usize::from(merged)))
            .ok_or_else(invalid)?;
        if current.next().is_some()
            || executable_ordinal != self.executable_count
            || new.entries().len() != expected_rows
        {
            return Err(invalid());
        }
        Ok(InitialMapProjection {
            plan: *self,
            cleared_prefix: quarantined_executable_prefix,
            merged,
            current_rows: new.entries().len(),
            current_bytes: actual.len(),
            island: (island.start, island.end),
            island_index,
            island_span: span(actual, observed_island),
            lower_current_index,
            rx_current_index,
            lower_current_span,
            rx_current_span,
        })
    }

    pub(in crate::linux::remote::dynamic::owner) fn verify_transition(
        &self,
        original: &[u8],
        before: &[u8],
        after: &[u8],
        island: &Range<u64>,
    ) -> Result<InitialMapProjection, LaunchError> {
        let a = self.verify_snapshot(original, before, island, self.target_executable_ordinal)?;
        let b = self.verify_snapshot(
            original,
            after,
            island,
            self.target_executable_ordinal
                .checked_add(1)
                .ok_or_else(invalid)?,
        )?;
        let old_island = parse(before)?
            .entries()
            .nth(a.island_index)
            .ok_or_else(invalid)?;
        let new_island = parse(after)?
            .entries()
            .nth(b.island_index)
            .ok_or_else(invalid)?;
        if old_island.raw_line != new_island.raw_line {
            return Err(invalid());
        }
        // All non-island rows were independently matched to the same complete
        // original capture at the two exact prefixes. Only the pair's target
        // permission and its allowed optional collapse can differ.
        Ok(b)
    }
}

impl InitialMapProjection {
    pub(in crate::linux::remote::dynamic::owner) fn plan(&self) -> &InitialMapPlan {
        &self.plan
    }

    pub(in crate::linux::remote::dynamic::owner) fn cleared_prefix(&self) -> usize {
        self.cleared_prefix
    }

    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner) fn is_merged(&self) -> bool {
        self.merged
    }

    pub(in crate::linux::remote::dynamic::owner) fn view<'a>(
        &self,
        original: &'a [u8],
        actual: &'a [u8],
        island: &Range<u64>,
    ) -> Result<InitialMapView<'a>, LaunchError> {
        let actual_projection =
            self.plan
                .verify_snapshot(original, actual, island, self.cleared_prefix)?;
        if *self != actual_projection {
            return Err(invalid());
        }
        Ok(InitialMapView {
            original: parse(original)?,
            current: parse(actual)?,
            projection: *self,
        })
    }
}

impl<'a> InitialMapView<'a> {
    pub(in crate::linux::remote::dynamic::owner) fn originals(&self) -> ParsedMaps<'a> {
        self.original
    }

    pub(in crate::linux::remote::dynamic::owner) fn current(&self) -> ParsedMaps<'a> {
        self.current
    }

    /// The island has no original pool entry. A union uses only its original
    /// lower descriptor; the absorbed upper allocation remains owner-retained.
    pub(in crate::linux::remote::dynamic::owner) fn descriptor_pool_index(
        &self,
        current_index: usize,
    ) -> Result<Option<usize>, LaunchError> {
        if current_index >= self.projection.current_rows {
            return Err(invalid());
        }
        if current_index == self.projection.island_index {
            return Ok(None);
        }
        let mut original_index = current_index
            .checked_sub(usize::from(current_index > self.projection.island_index))
            .ok_or_else(invalid)?;
        if self.projection.merged && original_index > self.projection.plan.lower_index {
            original_index = original_index.checked_add(1).ok_or_else(invalid)?;
        }
        if original_index >= self.projection.plan.original_rows {
            return Err(invalid());
        }
        Ok(Some(original_index))
    }

    pub(in crate::linux::remote::dynamic::owner) fn source(
        &self,
        original_index: usize,
    ) -> Result<InitialSourceRow<'a>, LaunchError> {
        let original = self
            .original
            .entries()
            .nth(original_index)
            .ok_or_else(invalid)?;
        if !executable(original) || original.permissions.bytes() != *b"r-xp" {
            // In particular, neither the original R header nor the fixed
            // vsyscall row is a source merely because a container exists.
            return Err(invalid());
        }
        let plan = &self.projection.plan;
        let current_index = if original_index == plan.upper_index {
            self.projection.rx_current_index
        } else {
            let without_island = original_index
                .checked_sub(usize::from(
                    self.projection.merged && original_index > plan.upper_index,
                ))
                .ok_or_else(invalid)?;
            without_island
                .checked_add(usize::from(without_island >= self.projection.island_index))
                .ok_or_else(invalid)?
        };
        let current = self
            .current
            .entries()
            .nth(current_index)
            .ok_or_else(invalid)?;
        Ok(InitialSourceRow {
            original,
            current,
            original_index,
            current_index,
            original_span: span(self.original.raw(), original),
            current_span: span(self.current.raw(), current),
        })
    }
}
