//! Envelope inventory only. Original CFI programs are opaque preserved bytes;
//! this parser does not certify their caller-recovery semantics.

use super::{Error, IndexLimits, add, limit};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Record {
    pub address: u64,
    pub bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Fde {
    pub record: Record,
    pub cie: u64,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug)]
pub(super) struct Stream {
    pub cies: Vec<Record>,
    pub fdes: Vec<Fde>,
    /// Includes the complete four-byte zero terminator.
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Entry {
    pub start: u64,
    pub fde: u64,
}

#[derive(Clone, Debug)]
pub(super) struct Header {
    pub stream: u64,
    pub entries: Vec<Entry>,
}

pub(super) fn word(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let end = at.checked_add(4).ok_or(Error::Arithmetic)?;
    let bytes = bytes.get(at..end).ok_or(Error::MalformedRecord)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| Error::MalformedRecord)?,
    ))
}

fn relative(base: u64, value: u32) -> Result<u64, Error> {
    base.checked_add_signed(i64::from(value as i32))
        .ok_or(Error::Arithmetic)
}

pub(super) fn index_bytes(count: usize) -> Result<usize, Error> {
    count
        .checked_mul(8)
        .and_then(|size| size.checked_add(12))
        .ok_or(Error::Arithmetic)
}

pub(super) fn header(bytes: &[u8], address: u64, limits: IndexLimits) -> Result<Header, Error> {
    if address % 4 != 0 || bytes.get(..4) != Some(&[1, 0x1b, 3, 0x3b]) {
        return Err(Error::UnsupportedHeader);
    }
    let count = usize::try_from(word(bytes, 8)?).map_err(|_| Error::Arithmetic)?;
    limit("index bytes", bytes.len(), limits.index_bytes)?;
    if count == 0 || index_bytes(count)? != bytes.len() {
        return Err(Error::IndexMismatch);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    for pair in bytes[12..].chunks_exact(8) {
        let entry = Entry {
            start: relative(address, word(pair, 0)?)?,
            fde: relative(address, word(pair, 4)?)?,
        };
        // Never normalize a malformed original table by sorting it.
        if entries
            .last()
            .is_some_and(|old: &Entry| old.start >= entry.start)
        {
            return Err(Error::IndexMismatch);
        }
        entries.push(entry);
    }
    Ok(Header {
        stream: relative(add(address, 4)?, word(bytes, 4)?)?,
        entries,
    })
}

/// The complete original or generated stream, with independently bounded reads.
/// A zero-sized FDE is counted before refusing it; no scanned record is omitted.
pub(super) fn stream<'a>(
    mut read: impl FnMut(u64, usize) -> Result<&'a [u8], Error>,
    start: u64,
    limits: IndexLimits,
) -> Result<Stream, Error> {
    let mut result = Stream {
        cies: Vec::new(),
        fdes: Vec::new(),
        bytes: 0,
    };
    loop {
        let prefix_end = result.bytes.checked_add(4).ok_or(Error::Arithmetic)?;
        limit("stream bytes", prefix_end, limits.original_bytes)?;
        let address = add(start, result.bytes as u64)?;
        let length = word(read(address, 4)?, 0)?;
        if length == 0 {
            result.bytes = prefix_end;
            break;
        }
        if length == u32::MAX || length < 4 {
            return Err(Error::UnsupportedRecord);
        }
        let size = usize::try_from(length)
            .map_err(|_| Error::Arithmetic)?
            .checked_add(4)
            .ok_or(Error::Arithmetic)?;
        let next = result.bytes.checked_add(size).ok_or(Error::Arithmetic)?;
        limit("stream bytes", next, limits.original_bytes)?;
        let bytes = read(address, size)?;
        let cie_delta = word(bytes, 4)?;
        let record = Record {
            address,
            bytes: size,
        };
        if cie_delta == 0 {
            limit(
                "CIE records",
                result.cies.len().checked_add(1).ok_or(Error::Arithmetic)?,
                limits.original_cies,
            )?;
            // Canonical bounded CIE32 v1: zR, code-align1, data-align-8,
            // RA16, augmentation length1, pcrel/sdata4 locations. Its program
            // remains opaque; this does not broaden the semantic CFI parser.
            if bytes.get(8..17) != Some(&[1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b]) {
                return Err(Error::UnsupportedRecord);
            }
            result.cies.try_reserve(1).map_err(|_| Error::Allocation)?;
            result.cies.push(record);
        } else {
            limit(
                "FDE records",
                result.fdes.len().checked_add(1).ok_or(Error::Arithmetic)?,
                limits.original_fdes,
            )?;
            let cie = add(address, 4)?
                .checked_sub(u64::from(cie_delta))
                .ok_or(Error::MalformedRecord)?;
            if !result.cies.iter().any(|old| old.address == cie) {
                return Err(Error::MalformedRecord);
            }
            let begin = relative(add(address, 8)?, word(bytes, 8)?)?;
            // Range has only the signed format, not the initial-PC base.
            let range = word(bytes, 12)? as i32;
            if range <= 0 || bytes.get(16) != Some(&0) {
                return Err(Error::UnsupportedRecord);
            }
            result.fdes.try_reserve(1).map_err(|_| Error::Allocation)?;
            result.fdes.push(Fde {
                record,
                cie,
                start: begin,
                end: add(begin, range as u64)?,
            });
        }
        result.bytes = next;
    }
    if result.cies.is_empty() || result.fdes.is_empty() {
        return Err(Error::IndexMismatch);
    }
    Ok(result)
}

pub(super) fn ordered(fdes: &[Fde]) -> Result<Vec<Entry>, Error> {
    let mut sorted = Vec::new();
    sorted
        .try_reserve_exact(fdes.len())
        .map_err(|_| Error::Allocation)?;
    sorted.extend(fdes.iter());
    sorted.sort_by_key(|fde| fde.start);
    if sorted.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(Error::OverlappingFrames);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(sorted.len())
        .map_err(|_| Error::Allocation)?;
    entries.extend(sorted.into_iter().map(|fde| Entry {
        start: fde.start,
        fde: fde.record.address,
    }));
    Ok(entries)
}

pub(super) fn render(
    entries: &[Entry],
    stream: u64,
    address: u64,
    limits: IndexLimits,
) -> Result<Vec<u8>, Error> {
    let size = index_bytes(entries.len())?;
    limit("index bytes", size, limits.index_bytes)?;
    if entries.is_empty()
        || address % 4 != 0
        || entries
            .windows(2)
            .any(|pair| pair[0].start >= pair[1].start)
    {
        return Err(Error::IndexMismatch);
    }
    let delta = |target, base| {
        i32::try_from(i128::from(target) - i128::from(base)).map_err(|_| Error::RelativeRange)
    };
    let count = u32::try_from(entries.len()).map_err(|_| Error::Arithmetic)?;
    // Check every displacement before reserving output storage.
    delta(stream, add(address, 4)?)?;
    for entry in entries {
        delta(entry.start, address)?;
        delta(entry.fde, address)?;
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(size)
        .map_err(|_| Error::Allocation)?;
    output.extend_from_slice(&[1, 0x1b, 3, 0x3b]);
    output.extend_from_slice(&delta(stream, add(address, 4)?)?.to_le_bytes());
    output.extend_from_slice(&count.to_le_bytes());
    for entry in entries {
        output.extend_from_slice(&delta(entry.start, address)?.to_le_bytes());
        output.extend_from_slice(&delta(entry.fde, address)?.to_le_bytes());
    }
    Ok(output)
}
