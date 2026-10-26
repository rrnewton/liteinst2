//! Descriptive row projection for one complete R/RX file-page pair.
//!
//! These borrowed comparisons allocate nothing and grant no native authority.
//! Their caller must separately prove the complete inventory, original entry,
//! file object/alias custody, single eligible pair, actual held observations,
//! original RX source extent and exact whole-baseline closure.
use crate::LaunchError;
use crate::linux::remote::dynamic::owner::admission::mapping::maps::MapEntry;

const PAGE: u64 = 4096;

#[derive(Clone, Copy)]
pub(in crate::linux::remote::dynamic::owner) struct PairRows<'a> {
    lower: MapEntry<'a>,
    upper: MapEntry<'a>,
    lower_columns: Columns,
    upper_columns: Columns,
}

/// Offsets into an already completely parsed row. Retaining spelling avoids
/// admitting a numerically equal field with changed padding or separators.
#[derive(Clone, Copy)]
struct Columns {
    dash: usize,
    range_end: usize,
    permissions: usize,
    offset: usize,
    offset_end: usize,
    device: usize,
}

fn invalid() -> LaunchError {
    LaunchError::Invalid("initial coalescence pair row projection differs")
}

fn columns(row: MapEntry<'_>) -> Result<Columns, LaunchError> {
    let bytes = row.raw_line;
    let range_end = bytes
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or_else(invalid)?;
    let dash = bytes[..range_end]
        .iter()
        .position(|byte| *byte == b'-')
        .ok_or_else(invalid)?;
    let start_after = |end: usize| {
        bytes
            .get(end..)
            .and_then(|tail| tail.iter().position(|byte| *byte != b' '))
            .and_then(|at| end.checked_add(at))
            .ok_or_else(invalid)
    };
    let field_end = |start: usize| {
        bytes
            .get(start..)
            .and_then(|tail| tail.iter().position(|byte| *byte == b' '))
            .and_then(|at| start.checked_add(at))
            .ok_or_else(invalid)
    };
    let permissions = start_after(range_end)?;
    let permissions_end = field_end(permissions)?;
    if permissions_end - permissions != 4
        || bytes[permissions..permissions_end] != row.permissions.bytes()
    {
        return Err(invalid());
    }
    let offset = start_after(permissions_end)?;
    let offset_end = field_end(offset)?;
    let device = start_after(offset_end)?;
    if dash == 0 || dash + 1 == range_end {
        return Err(invalid());
    }
    Ok(Columns {
        dash,
        range_end,
        permissions,
        offset,
        offset_end,
        device,
    })
}

fn same_file(a: MapEntry<'_>, b: MapEntry<'_>) -> bool {
    a.device_major == b.device_major
        && a.device_minor == b.device_minor
        && a.inode == b.inode
        && a.pathname == b.pathname
}

fn same_backing(a: MapEntry<'_>, b: MapEntry<'_>) -> bool {
    same_file(a, b) && a.pathname_column == b.pathname_column
}

impl<'a> PairRows<'a> {
    pub(in crate::linux::remote::dynamic::owner) fn new(
        lower: MapEntry<'a>,
        upper: MapEntry<'a>,
    ) -> Result<Self, LaunchError> {
        if lower.start == 0
            || lower.start % PAGE != 0
            || lower.end.checked_sub(lower.start) != Some(PAGE)
            || upper.end.checked_sub(upper.start) != Some(PAGE)
            || lower.end != upper.start
            || lower.permissions.bytes() != *b"r--p"
            || upper.permissions.bytes() != *b"r-xp"
            || lower.file_offset % PAGE != 0
            || lower.file_offset.checked_add(PAGE) != Some(upper.file_offset)
            || upper.file_offset.checked_add(PAGE).is_none()
            || lower.inode == 0
            || lower
                .pathname
                .is_none_or(|name| name.is_empty() || name[0] == b'[')
            || !same_backing(lower, upper)
        {
            return Err(invalid());
        }
        let a = columns(lower)?;
        let b = columns(upper)?;
        // The finite projection retains the exact range widths and every
        // separator. The shared boundary must also have identical spelling.
        if a.dash != b.dash
            || a.range_end != b.range_end
            || a.permissions != b.permissions
            || a.offset != b.offset
            || a.offset_end != b.offset_end
            || a.device != b.device
            || lower.raw_line[a.dash + 1..a.range_end] != upper.raw_line[..b.dash]
            || lower.raw_line[a.range_end..a.permissions]
                != upper.raw_line[b.range_end..b.permissions]
            || lower.raw_line[a.permissions + 4..a.offset]
                != upper.raw_line[b.permissions + 4..b.offset]
            || lower.raw_line[a.offset_end..] != upper.raw_line[b.offset_end..]
        {
            return Err(invalid());
        }
        Ok(Self {
            lower,
            upper,
            lower_columns: a,
            upper_columns: b,
        })
    }

    pub(in crate::linux::remote::dynamic::owner) fn original_lower(self) -> MapEntry<'a> {
        self.lower
    }

    pub(in crate::linux::remote::dynamic::owner) fn original_rx(self) -> MapEntry<'a> {
        self.upper
    }

    /// Whether an adjacent third R/RX row could extend the same projected
    /// read-only file run. A true result makes this finite pair unsupported;
    /// it is never permission to absorb that row. Whole-inventory selection
    /// must call this for both actual original neighbours.
    pub(in crate::linux::remote::dynamic::owner) fn extends_run(self, other: MapEntry<'_>) -> bool {
        if !matches!(other.permissions.bytes(), [b'r', b'-', b'-' | b'x', b'p'])
            // This is a conservative exclusion, not accepted row identity.
            // Different numeric widths/separator padding cannot hide an
            // adjacent same-file run that the kernel might coalesce.
            || !same_file(self.lower, other)
        {
            return false;
        }
        (other.end == self.lower.start
            && other
                .end
                .checked_sub(other.start)
                .and_then(|length| other.file_offset.checked_add(length))
                == Some(self.lower.file_offset))
            || (self.upper.end == other.start
                && self.upper.file_offset.checked_add(PAGE) == Some(other.file_offset))
    }

    /// Exactly the two original rows, with only the upper X bit cleared.
    pub(in crate::linux::remote::dynamic::owner) fn verify_separate_nx(
        self,
        lower: MapEntry<'_>,
        upper: MapEntry<'_>,
    ) -> Result<(), LaunchError> {
        if lower.raw_line != self.lower.raw_line
            || upper.start != self.upper.start
            || upper.end != self.upper.end
            || upper.file_offset != self.upper.file_offset
            || upper.permissions.bytes() != *b"r--p"
            || !same_backing(self.upper, upper)
            || upper.raw_line.len() != self.upper.raw_line.len()
        {
            return Err(invalid());
        }
        let execute_column = self.upper_columns.permissions + 2;
        if !self
            .upper
            .raw_line
            .iter()
            .zip(upper.raw_line)
            .enumerate()
            .all(|(index, (original, actual))| {
                if index == execute_column {
                    *original == b'x' && *actual == b'-'
                } else {
                    original == actual
                }
            })
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Exactly the lower original row with its end replaced by the upper
    /// original end. Its start, R-only permissions, offset and raw suffix stay
    /// byte-identical. No normalization, equivalent split or larger union.
    pub(in crate::linux::remote::dynamic::owner) fn verify_union_nx(
        self,
        actual: MapEntry<'_>,
    ) -> Result<(), LaunchError> {
        let a = self.lower_columns;
        let b = self.upper_columns;
        if actual.start != self.lower.start
            || actual.end != self.upper.end
            || actual.file_offset != self.lower.file_offset
            || actual.permissions.bytes() != *b"r--p"
            || !same_backing(self.lower, actual)
            || actual.raw_line.len() != self.lower.raw_line.len()
            || actual.raw_line[..a.dash + 1] != self.lower.raw_line[..a.dash + 1]
            || actual.raw_line[a.dash + 1..a.range_end]
                != self.upper.raw_line[b.dash + 1..b.range_end]
            || actual.raw_line[a.range_end..] != self.lower.raw_line[a.range_end..]
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Opening just the original upper page reconstructs the two original
    /// R/RX rows exactly. This cannot admit X on any byte of the lower page.
    pub(in crate::linux::remote::dynamic::owner) fn verify_open_pair(
        self,
        lower: MapEntry<'_>,
        upper: MapEntry<'_>,
    ) -> Result<(), LaunchError> {
        if lower.raw_line != self.lower.raw_line || upper.raw_line != self.upper.raw_line {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
