//! Bounded borrowed smaps interpretation using the unchanged maps grammar.
//! Original VMA identity and metadata eligibility are descriptive, not custody.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct StackDescriptor {
    pub(in crate::linux::remote::dynamic::owner::admission) start: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) end: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) original_index: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) original_span: (usize, usize),
    pub(in crate::linux::remote::dynamic::owner::admission) baseline_index: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) baseline_span: (usize, usize),
}
impl StackDescriptor {
    pub(in crate::linux::remote::dynamic::owner::admission) fn range(self) -> Range<u64> {
        self.start..self.end
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn validate(
        original: &[u8],
        baseline: &[u8],
        rsp: u64,
        island: &Range<u64>,
    ) -> Result<Self, StackError> {
        if !low(rsp) || !interval(island) {
            return Err(StackError::Geometry);
        }
        let originals = maps(original)?;
        let current = maps(baseline)?;
        let (original_index, old, original_span) = containing(originals, rsp)?;
        let (baseline_index, now, baseline_span) = containing(current, rsp)?;
        if old != now
            || old.permissions.bytes() != *b"rw-p"
            || old.file_offset != 0
            || old.device_major != 0
            || old.device_minor != 0
            || old.inode != 0
            || !interval(&(old.start..old.end))
            || overlaps(&(old.start..old.end), island)
        {
            return Err(StackError::Provenance);
        }
        for row in originals.entries() {
            if row.permissions.bytes()[2] == b'x'
                && overlaps(&(old.start..old.end), &(row.start..row.end))
            {
                return Err(StackError::Provenance);
            }
        }
        Ok(Self {
            start: old.start,
            end: old.end,
            original_index,
            original_span,
            baseline_index,
            baseline_span,
        })
    }
    /// Compare the original complete descriptor bytes, not only its endpoints
    /// or the [stack] label. Other-row projection remains root source authority.
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_current(
        self,
        original: &[u8],
        current: &[u8],
    ) -> Result<usize, StackError> {
        let old = maps(original)?
            .entries()
            .nth(self.original_index)
            .ok_or(StackError::Provenance)?;
        let span = original
            .get(self.original_span.0..self.original_span.1)
            .ok_or(StackError::Provenance)?;
        if old.start != self.start
            || old.end != self.end
            || old.raw_line != span
            || old.permissions.bytes() != *b"rw-p"
            || old.file_offset != 0
            || old.device_major != 0
            || old.device_minor != 0
            || old.inode != 0
            || !interval(&self.range())
        {
            return Err(StackError::Provenance);
        }
        let mut found = None;
        for (index, row) in maps(current)?.entries().enumerate() {
            if overlaps(&self.range(), &(row.start..row.end)) {
                if found.is_some() || row != old {
                    return Err(StackError::Provenance);
                }
                found = Some(index);
            }
        }
        found.ok_or(StackError::Provenance)
    }
}
fn containing(
    maps: ParsedMaps<'_>,
    address: u64,
) -> Result<(usize, MapEntry<'_>, (usize, usize)), StackError> {
    let mut offset = 0;
    for (index, row) in maps.entries().enumerate() {
        let end = add(offset, row.raw_line.len())?;
        if row.start <= address && address < row.end {
            return Ok((index, row, (offset, end)));
        }
        offset = add(end, 1)?;
    }
    Err(StackError::Provenance)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct StackMetadata {
    /// rd wr mr mw me gd ac, optionally sd nh. Raw text remains in smaps.
    flags: u16,
}
impl StackMetadata {
    // Descriptive bit projection used by the metadata controls.
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn flags(self) -> u16 {
        self.flags
    }
}
fn flags(bytes: &[u8]) -> Result<u16, StackError> {
    let mut found = 0_u16;
    for token in bytes
        .split(|b| b.is_ascii_whitespace())
        .filter(|s| !s.is_empty())
    {
        let bit = match token {
            b"rd" => 0,
            b"wr" => 1,
            b"mr" => 2,
            b"mw" => 3,
            b"me" => 4,
            b"gd" => 5,
            b"ac" => 6,
            b"sd" => 7,
            b"nh" => 8,
            _ => return Err(StackError::Flags),
        };
        if found & (1 << bit) != 0 {
            return Err(StackError::Flags);
        }
        found |= 1 << bit;
    }
    if found & 0x7f != 0x7f {
        return Err(StackError::Flags);
    }
    Ok(found)
}
/// Validate every smaps header against every complete maps row. No pathname
/// decoding, allocation, lower bound truncation, or independent maps parser.
pub(in crate::linux::remote::dynamic::owner::admission) fn validate_smaps(
    raw: &[u8],
    complete_maps: &[u8],
    stack_index: usize,
) -> Result<StackMetadata, StackError> {
    if raw.is_empty() || raw.len() > BYTES || !raw.ends_with(b"\n") || raw.contains(&0) {
        return Err(StackError::Framing);
    }
    let maps = maps(complete_maps)?;
    let mut expected = maps.entries();
    let mut rows = 0_usize;
    let mut current = None;
    let mut pkey = None;
    let mut vmflags = None;
    for line in raw[..raw.len() - 1].split(|b| *b == b'\n') {
        if line.is_empty() {
            return Err(StackError::Framing);
        }
        // Header fields have no colon before the first space. Metadata keys
        // do. A malformed header-like line therefore reaches the same strict
        // maps parser instead of silently becoming an ignored statistic.
        let first_end = line.iter().position(|b| *b == b' ').unwrap_or(line.len());
        if !line[..first_end].contains(&b':') {
            let actual = parse_header_line(line).map_err(|_| StackError::Maps)?;
            if rows == ROWS || Some(actual) != expected.next() {
                return Err(StackError::Maps);
            }
            current = Some(rows);
            rows += 1;
            continue;
        }
        let index = current.ok_or(StackError::Framing)?;
        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or(StackError::Metadata)?;
        let key = &line[..colon];
        if key.is_empty() || !key.iter().all(|b| b.is_ascii_alphabetic() || *b == b'_') {
            return Err(StackError::Metadata);
        }
        let value = &line[colon + 1..];
        if value.first().is_none_or(|b| !b.is_ascii_whitespace()) {
            return Err(StackError::Metadata);
        }
        if index == stack_index {
            match key {
                b"ProtectionKey" => {
                    if pkey.is_some() || value.trim_ascii() != b"0" {
                        return Err(StackError::Metadata);
                    }
                    pkey = Some(0);
                }
                b"VmFlags" => {
                    if vmflags.is_some() {
                        return Err(StackError::Flags);
                    }
                    vmflags = Some(flags(value)?);
                }
                _ => {}
            }
        }
    }
    if rows == 0 || stack_index >= rows || expected.next().is_some() || pkey != Some(0) {
        return Err(StackError::Metadata);
    }
    Ok(StackMetadata {
        flags: vmflags.ok_or(StackError::Metadata)?,
    })
}
