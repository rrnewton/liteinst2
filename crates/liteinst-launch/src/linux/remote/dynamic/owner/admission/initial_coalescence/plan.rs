//! Selection is descriptive preflight; structural absence keeps the old path.
use super::rows::PairRows;
use super::*;

impl InitialMapPlan {
    pub(in crate::linux::remote::dynamic::owner) fn select(
        original: &[u8],
        entry: &EntryEvidence,
        executable: (u32, u32, u64),
    ) -> Result<Option<Self>, LaunchError> {
        // Even an unsupported image must not hide malformed suffix rows.
        let maps = parse(original)?;
        if entry.first_image != FirstImage::Executable
            || entry.interpreter.is_some()
            || entry.interpreter_base != 0
            || entry.initial_instruction != entry.executable_entry
        {
            return Ok(None);
        }
        select(maps, entry.executable_entry, executable)
    }

    pub(in crate::linux::remote::dynamic::owner) fn pair_range(&self) -> Range<u64> {
        self.pair_start..self.pair_end
    }

    pub(in crate::linux::remote::dynamic::owner) fn rx_range(&self) -> Range<u64> {
        self.rx_start..self.pair_end
    }

    pub(in crate::linux::remote::dynamic::owner) fn original_rows(&self) -> usize {
        self.original_rows
    }

    pub(in crate::linux::remote::dynamic::owner) fn executable_count(&self) -> usize {
        self.executable_count
    }

    pub(in crate::linux::remote::dynamic::owner) fn target_executable_ordinal(&self) -> usize {
        self.target_executable_ordinal
    }

    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner) fn pair_indices(&self) -> (usize, usize) {
        (self.lower_index, self.upper_index)
    }

    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner) fn pair_spans(
        &self,
    ) -> ((usize, usize), (usize, usize)) {
        (self.lower_span, self.upper_span)
    }

    pub(super) fn require_original<'a>(
        &self,
        original: &'a [u8],
    ) -> Result<ParsedMaps<'a>, LaunchError> {
        let parsed = parse(original)?;
        // Recompute every scalar, pair predicate, neighbour and visible alias.
        // Full unrelated raw identity is checked against each actual table;
        // only the native owner's immutable retained capture supplies custody.
        if select(parsed, self.entry, self.executable)? != Some(*self) {
            return Err(invalid());
        }
        Ok(parsed)
    }
}

fn select(
    maps: ParsedMaps<'_>,
    entry: u64,
    identity: (u32, u32, u64),
) -> Result<Option<InitialMapPlan>, LaunchError> {
    if identity.2 == 0 || entry == 0 || entry >= USER_END {
        return Ok(None);
    }
    let mut executables = 0usize;
    let mut previous = None;
    let mut candidate = None;
    for (index, row) in maps.entries().enumerate() {
        if row.pathname == Some(b"[vsyscall]".as_slice()) && !fixed_vsyscall(row) {
            return Err(invalid());
        }
        if executable(row) {
            let p = row.permissions.bytes();
            if p[1] == b'w' || p[3] != b'p' {
                return Ok(None);
            }
            executables = executables.checked_add(1).ok_or_else(invalid)?;
        }
        if let Some((lower_index, lower)) = previous
            && file(lower) == identity
            && file(row) == identity
            && let Ok(pair) = PairRows::new(lower, row)
        {
            if candidate.is_some() {
                return Ok(None);
            }
            candidate = Some((lower_index, index, pair));
        }
        previous = Some((index, row));
    }
    if executables == 0 || executables > 64 {
        return Ok(None);
    }
    let Some((lower_index, upper_index, pair)) = candidate else {
        return Ok(None);
    };
    let lower = pair.original_lower();
    let upper = pair.original_rx();
    if upper.end > USER_END || !(upper.start <= entry && entry < upper.end) {
        return Ok(None);
    }
    if lower_index
        .checked_sub(1)
        .and_then(|index| maps.entries().nth(index))
        .is_some_and(|row| pair.extends_run(row))
        || maps
            .entries()
            .nth(upper_index + 1)
            .is_some_and(|row| pair.extends_run(row))
    {
        return Ok(None);
    }
    // The extra lower-page byte capture must not acquire support for a visible
    // backing alias. Use the entire pair's original file interval here.
    let file_end = upper.file_offset.checked_add(PAGE).ok_or_else(invalid)?;
    let mut target_ordinal = 0usize;
    for (index, row) in maps.entries().enumerate() {
        if index < upper_index && executable(row) {
            target_ordinal = target_ordinal.checked_add(1).ok_or_else(invalid)?;
        }
        if index == lower_index || index == upper_index || file(row) != identity {
            continue;
        }
        let end = row
            .file_offset
            .checked_add(row.end - row.start)
            .ok_or_else(invalid)?;
        if lower.file_offset < end && row.file_offset < file_end {
            return Ok(None);
        }
    }
    Ok(Some(InitialMapPlan {
        original_rows: maps.entries().len(),
        original_bytes: maps.raw().len(),
        executable_count: executables,
        lower_index,
        upper_index,
        lower_span: span(maps.raw(), lower),
        upper_span: span(maps.raw(), upper),
        target_executable_ordinal: target_ordinal,
        pair_start: lower.start,
        pair_end: upper.end,
        rx_start: upper.start,
        lower_offset: lower.file_offset,
        executable: identity,
        entry,
    }))
}
