//! Lossless, bounded interpretation of an already retained `/proc/TID/maps`
//! capture. Parsing supplies no task, procfs, mapping, writer or alias authority.
//! The owner must authenticate those facts separately before using a capture.
//!
//! The view borrows the immutable capture and performs no allocation. In
//! particular, pathname bytes are not UTF-8 decoded or whitespace-normalized.
//! `raw_line` also preserves the exact separator/padding before a pathname.

#[cfg(test)]
mod tests;

/// Matches the existing bounded proc-metadata read ceiling. This is not an
/// allowance to increase a caller's smaller, pre-effect reserved byte bound.
pub(in super::super) const MAX_MAPS_BYTES: usize = 1024 * 1024;
const PAGE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum MapParseError {
    Empty,
    ByteLimit,
    RowLimit,
    Framing,
    Fields,
    Permissions,
    Number,
    Range,
    Order,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct MapPermissions([u8; 4]);

impl MapPermissions {
    pub(in super::super) fn bytes(self) -> [u8; 4] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct MapEntry<'a> {
    pub(in super::super) start: u64,
    pub(in super::super) end: u64,
    pub(in super::super) permissions: MapPermissions,
    pub(in super::super) file_offset: u64,
    pub(in super::super) device_major: u32,
    pub(in super::super) device_minor: u32,
    pub(in super::super) inode: u64,
    /// Descriptive bytes only. Absence does not prove anonymous provenance or
    /// the absence of aliases. Internal and trailing whitespace is retained.
    pub(in super::super) pathname: Option<&'a [u8]>,
    /// Complete original line, excluding only its terminating newline.
    pub(in super::super) raw_line: &'a [u8],
    /// Original bytes after the inode, including separator/alignment spaces.
    pub(in super::super) pathname_column: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct ParsedMaps<'a> {
    raw: &'a [u8],
    rows: usize,
}

impl<'a> ParsedMaps<'a> {
    /// `row_limit` is an already reserved caller bound. The complete capture is
    /// checked before a view is returned; malformed suffixes cannot disappear.
    pub(in super::super) fn parse(raw: &'a [u8], row_limit: usize) -> Result<Self, MapParseError> {
        if raw.is_empty() {
            return Err(MapParseError::Empty);
        }
        if raw.len() > MAX_MAPS_BYTES {
            return Err(MapParseError::ByteLimit);
        }
        if !raw.ends_with(b"\n") || raw.contains(&0) {
            return Err(MapParseError::Framing);
        }
        let mut rows = 0_usize;
        let mut previous_end = None;
        for line in raw[..raw.len() - 1].split(|byte| *byte == b'\n') {
            if rows == row_limit {
                return Err(MapParseError::RowLimit);
            }
            let entry = parse_line(line)?;
            if previous_end.is_some_and(|end| entry.start < end) {
                return Err(MapParseError::Order);
            }
            previous_end = Some(entry.end);
            rows = rows.checked_add(1).ok_or(MapParseError::RowLimit)?;
        }
        Ok(Self { raw, rows })
    }

    pub(in super::super) fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub(in super::super) fn len(self) -> usize {
        self.rows
    }

    pub(in super::super) fn entries(self) -> MapEntries<'a> {
        MapEntries {
            remaining: self.raw,
            rows: self.rows,
        }
    }
}

pub(in super::super) struct MapEntries<'a> {
    remaining: &'a [u8],
    rows: usize,
}

impl<'a> Iterator for MapEntries<'a> {
    type Item = MapEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rows == 0 {
            return None;
        }
        // Only ParsedMaps constructs this iterator. Its immutable borrowed
        // bytes were fully validated, including every terminating newline.
        let end = self
            .remaining
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("validated maps newline");
        let line = &self.remaining[..end];
        self.remaining = &self.remaining[end + 1..];
        self.rows -= 1;
        Some(parse_line(line).expect("validated immutable maps line"))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.rows, Some(self.rows))
    }
}

impl ExactSizeIterator for MapEntries<'_> {}

fn field<'a>(line: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], MapParseError> {
    let start = *cursor;
    while *cursor < line.len() && line[*cursor] != b' ' {
        *cursor += 1;
    }
    if start == *cursor {
        return Err(MapParseError::Fields);
    }
    Ok(&line[start..*cursor])
}

fn separator(line: &[u8], cursor: &mut usize) -> Result<(), MapParseError> {
    let start = *cursor;
    while *cursor < line.len() && line[*cursor] == b' ' {
        *cursor += 1;
    }
    if start == *cursor || *cursor == line.len() {
        return Err(MapParseError::Fields);
    }
    Ok(())
}

fn pair(bytes: &[u8], delimiter: u8) -> Result<(&[u8], &[u8]), MapParseError> {
    let index = bytes
        .iter()
        .position(|byte| *byte == delimiter)
        .ok_or(MapParseError::Fields)?;
    let left = &bytes[..index];
    let right = &bytes[index + 1..];
    if left.is_empty() || right.is_empty() || right.contains(&delimiter) {
        return Err(MapParseError::Fields);
    }
    Ok((left, right))
}

fn number(bytes: &[u8], radix: u64) -> Result<u64, MapParseError> {
    if bytes.is_empty() {
        return Err(MapParseError::Number);
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' if radix == 16 => u64::from(byte - b'a') + 10,
            _ => return Err(MapParseError::Number),
        };
        if digit >= radix {
            return Err(MapParseError::Number);
        }
        value
            .checked_mul(radix)
            .and_then(|value| value.checked_add(digit))
            .ok_or(MapParseError::Number)
    })
}

fn parse_line(line: &[u8]) -> Result<MapEntry<'_>, MapParseError> {
    let mut cursor = 0;
    let range = field(line, &mut cursor)?;
    separator(line, &mut cursor)?;
    let permissions = field(line, &mut cursor)?;
    separator(line, &mut cursor)?;
    let offset = field(line, &mut cursor)?;
    separator(line, &mut cursor)?;
    let device = field(line, &mut cursor)?;
    separator(line, &mut cursor)?;
    let inode = field(line, &mut cursor)?;
    let pathname_column = &line[cursor..];
    while cursor < line.len() && line[cursor] == b' ' {
        cursor += 1;
    }
    let pathname = (cursor != line.len()).then_some(&line[cursor..]);
    let (start, end) = pair(range, b'-')?;
    let start = number(start, 16)?;
    let end = number(end, 16)?;
    if start >= end || start % PAGE != 0 || end % PAGE != 0 {
        return Err(MapParseError::Range);
    }
    let permissions: [u8; 4] = permissions
        .try_into()
        .map_err(|_| MapParseError::Permissions)?;
    if !matches!(permissions[0], b'r' | b'-')
        || !matches!(permissions[1], b'w' | b'-')
        || !matches!(permissions[2], b'x' | b'-')
        || !matches!(permissions[3], b'p' | b's')
    {
        return Err(MapParseError::Permissions);
    }
    let (major, minor) = pair(device, b':')?;
    Ok(MapEntry {
        start,
        end,
        permissions: MapPermissions(permissions),
        file_offset: number(offset, 16)?,
        device_major: u32::try_from(number(major, 16)?).map_err(|_| MapParseError::Number)?,
        device_minor: u32::try_from(number(minor, 16)?).map_err(|_| MapParseError::Number)?,
        inode: number(inode, 10)?,
        pathname,
        raw_line: line,
        pathname_column,
    })
}
