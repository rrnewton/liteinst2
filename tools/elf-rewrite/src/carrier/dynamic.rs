//! Bounded loader-relocation ownership, without dynamic linking or symbol resolution.
//!
//! This deliberately rejects unknown dynamic tags, GNU/Android packed relocation
//! extensions, and metadata in executable loads. COPY is limited to checked
//! ET_EXEC/DT_RELA destination reservations derived from complete symbol metadata.
//! Complete bounded table/chain extents must remain in nonexecuting file owners.
//! Owners are then protected as whole original loads. This is ownership proof,
//! not symbol resolution, version matching, or dynamic-linking qualification.

use super::elf64::{self, Elf64, ElfVaddr, FileRange, SegmentType, Storage, VirtualRange};
use std::collections::BTreeMap;

#[path = "dynamic_metadata.rs"]
mod complete_metadata;

/// Prospective bounds on all table scans and RELR expansion.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub dynamic_entries: usize,
    pub relocation_records: usize,
    pub relocation_writes: usize,
    pub metadata_records: usize,
    pub metadata_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            dynamic_entries: 4096,
            relocation_records: 1_048_576,
            relocation_writes: 1_048_576,
            metadata_records: 1_048_576,
            metadata_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Elf(elf64::Error),
    MultipleDynamicSegments,
    InvalidDynamicSegment,
    MissingTerminator,
    DuplicateTag {
        tag: u64,
    },
    UnsupportedTag {
        tag: u64,
    },
    InvalidTags {
        tag: u64,
    },
    UnsupportedTextRelocations,
    MetadataInExecutableLoad {
        index: usize,
    },
    MetadataNotReadable,
    MetadataNotFileBacked,
    TableOverlap,
    UnsupportedRelocation {
        kind: u32,
    },
    InvalidRelocation {
        kind: u32,
    },
    InvalidRelr,
    InvalidMetadata {
        tag: u64,
    },
    DuplicateWrite {
        first: usize,
        second: usize,
    },
    SourceRelocation {
        dependency: usize,
        write: usize,
    },
    SourceMetadata {
        dependency: usize,
    },
    Arithmetic,
    Budget {
        resource: &'static str,
        limit: usize,
    },
}

impl From<elf64::Error> for Error {
    fn from(value: elf64::Error) -> Self {
        Self::Elf(value)
    }
}

/// Table provenance of an actual loader write; RELR uses its record index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableKind {
    Rela,
    Rel,
    JumpRela,
    JumpRel,
    Relr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelocationWrite {
    pub table: TableKind,
    pub record: usize,
    pub kind: u32,
    pub symbol: u32,
    /// Fixed-width kinds have their exact width, including TLS descriptors.
    /// COPY has the declared destination reservation (st_size), a conservative
    /// write footprint rather than an observed resolved-provider copy length.
    pub range: VirtualRange,
    /// None means a wholly zero-filled original target, never an absent owner.
    pub file: Option<FileRange>,
}

/// A symbol-field dependency, independent of whether a relocation writes bytes.
///
/// Every REL/RELA/JMPREL record is retained, including R_X86_64_NONE: loader
/// version/symbol accesses can precede the machine handler's no-write decision.
/// RELR has no symbol field and therefore contributes no record here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolReference {
    pub table: TableKind,
    pub record: usize,
    pub kind: u32,
    pub symbol: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Inventory {
    pub writes: Vec<RelocationWrite>,
    /// Bounded by the aggregate relocation-record limit, not the write limit.
    pub symbol_references: Vec<SymbolReference>,
    pub tables: Vec<FileRange>,
    /// Entire readable, nonexecutable original load owners of known metadata.
    pub protected: Vec<FileRange>,
    pub dynamic_entries: usize,
    pub relocation_records: usize,
}

impl Inventory {
    /// Check all semantic source dependencies, not just changed opcode bytes.
    /// Callers must supply consumed pun bytes, padding and relocated instructions.
    pub fn check_source_ranges(&self, dependencies: &[FileRange]) -> Result<(), Error> {
        for (dependency, range) in dependencies.iter().enumerate() {
            if self
                .protected
                .iter()
                .any(|other| intersects(*range, *other))
            {
                return Err(Error::SourceMetadata { dependency });
            }
            for (write, item) in self.writes.iter().enumerate() {
                if item.file.is_some_and(|other| intersects(*range, other)) {
                    return Err(Error::SourceRelocation { dependency, write });
                }
            }
        }
        Ok(())
    }
}

/// Inspect original dynamic tables before any appended mapping or source edit.
pub fn inspect(input: &Elf64<'_>, limits: Limits) -> Result<Inventory, Error> {
    let segments: Vec<_> = input.segments(SegmentType::Dynamic).collect();
    if segments.len() > 1 {
        return Err(Error::MultipleDynamicSegments);
    }
    let Some(segment) = segments.first() else {
        return Ok(Inventory::default());
    };
    if segment.file_size == 0
        || segment.file_size % 16 != 0
        || segment.file_size > segment.memory_size
    {
        return Err(Error::InvalidDynamicSegment);
    }
    let count = usize::try_from(segment.file_size / 16).map_err(|_| Error::Arithmetic)?;
    bound(count, limits.dynamic_entries, "dynamic entries")?;
    let mut out = Inventory::default();
    let dynamic_file = metadata(input, segment.vaddr.0, segment.file_size, &mut out)?;
    if dynamic_file != segment.file_range()? {
        return Err(Error::InvalidDynamicSegment);
    }
    out.tables.push(dynamic_file);
    let bytes = file_bytes(input, dynamic_file)?;
    let mut tags = BTreeMap::<u64, u64>::new();
    let mut strings = Vec::new();
    let mut terminated = false;
    for record in bytes.chunks_exact(16) {
        out.dynamic_entries += 1;
        let tag = u64_at(record, 0);
        let value = u64_at(record, 8);
        if tag == 0 {
            terminated = true;
            break;
        }
        if !known_tag(tag) {
            return Err(Error::UnsupportedTag { tag });
        }
        if matches!(tag, 1 | 14 | 15 | 29 | 0x7fff_fffd | 0x7fff_ffff) {
            strings.push(value);
        }
        if matches!(tag, 1 | 0x7fff_fffd | 0x7fff_ffff) {
            // Repeated NEEDED/AUXILIARY/FILTER strings are legal; their owner is
            // validated through STRTAB/STRSZ below, not inferred from this value.
            continue;
        }
        if tags.insert(tag, value).is_some() {
            return Err(Error::DuplicateTag { tag });
        }
    }
    if !terminated {
        return Err(Error::MissingTerminator);
    }
    if tags.contains_key(&22) || tags.get(&30).is_some_and(|flags| flags & 4 != 0) {
        return Err(Error::UnsupportedTextRelocations);
    }
    for (pointer, size) in [(5, 10), (25, 27), (26, 28), (32, 33)] {
        match (tags.get(&pointer), tags.get(&size)) {
            (None, None) => {}
            (Some(&address), Some(&length)) => {
                if pointer != 5 && length % 8 != 0 {
                    return Err(Error::InvalidTags { tag: size });
                }
                if length != 0 {
                    metadata(input, address, length, &mut out)?;
                }
            }
            _ => return Err(Error::InvalidTags { tag: pointer }),
        }
    }
    if !strings.is_empty() {
        let (&address, &length) = tags
            .get(&5)
            .zip(tags.get(&10))
            .ok_or(Error::InvalidTags { tag: 5 })?;
        if length == 0 {
            return Err(Error::InvalidTags { tag: 10 });
        }
        let range = metadata(input, address, length, &mut out)?;
        let table = file_bytes(input, range)?;
        bound(table.len(), limits.metadata_bytes, "metadata bytes")?;
        let last_nul = table.iter().rposition(|byte| *byte == 0);
        for offset in strings {
            if !last_nul.is_some_and(|last| offset <= last as u64) {
                return Err(Error::InvalidTags { tag: 5 });
            }
        }
    }
    match (tags.get(&6), tags.get(&11)) {
        (None, None) => {}
        (Some(&address), Some(&24)) => {
            metadata(input, address, 24, &mut out)?;
        }
        _ => return Err(Error::InvalidTags { tag: 6 }),
    }
    // Validate the first access cheaply. The complete metadata pass below must
    // prove all variable/symbol-sized extents before this inventory can return.
    for tag in [
        3,
        4,
        34,
        0x6fff_fef5,
        0x6fff_fef7,
        0x6fff_fff0,
        0x6fff_fffc,
        0x6fff_fffe,
    ] {
        if let Some(&address) = tags.get(&tag) {
            let bytes = match tag {
                3 => 24,
                0x6fff_fef7 => 8,
                _ => 1,
            };
            metadata(input, address, bytes, &mut out)?;
        }
    }
    for (pointer, count) in [(0x6fff_fffc, 0x6fff_fffd), (0x6fff_fffe, 0x6fff_ffff)] {
        if tags.contains_key(&pointer) != tags.contains_key(&count) {
            return Err(Error::InvalidTags { tag: pointer });
        }
    }
    for tag in [12, 13] {
        if let Some(&address) = tags.get(&tag) {
            if address != 0 {
                input.executable_bytes(ElfVaddr(address), 1)?;
            }
        }
    }
    let mut descriptors = Vec::new();
    if let Some(table) = relocation_table(&tags, 7, 8, 9, 24, TableKind::Rela)? {
        descriptors.push(table);
    }
    if let Some(table) = relocation_table(&tags, 17, 18, 19, 16, TableKind::Rel)? {
        descriptors.push(table);
    }
    if let Some(table) = relocation_table(&tags, 36, 35, 37, 8, TableKind::Relr)? {
        descriptors.push(table);
    }
    match (tags.get(&23), tags.get(&2), tags.get(&20)) {
        (None, None, None) => {}
        (Some(&address), Some(&length), Some(&kind)) if matches!(kind, 7 | 17) => {
            let (entry_size, table) = if kind == 7 {
                (24, TableKind::JumpRela)
            } else {
                (16, TableKind::JumpRel)
            };
            if length % entry_size != 0 {
                return Err(Error::InvalidTags { tag: 2 });
            }
            descriptors.push(Descriptor {
                address,
                length,
                entry_size,
                table,
            });
        }
        _ => return Err(Error::InvalidTags { tag: 23 }),
    }
    // Relative-count accelerators are semantic loader inputs: the prefix must
    // really contain symbol-free RELATIVE records, not merely fit the table.
    for (count_tag, table_kind) in [
        (0x6fff_fff9, TableKind::Rela),
        (0x6fff_fffa, TableKind::Rel),
    ] {
        if let Some(&count) = tags.get(&count_tag) {
            let table = descriptors
                .iter()
                .find(|table| table.table == table_kind)
                .ok_or(Error::InvalidTags { tag: count_tag })?;
            if count > table.length / table.entry_size {
                return Err(Error::InvalidTags { tag: count_tag });
            }
        }
    }
    let mut copies = Vec::new();
    for table in &descriptors {
        let count =
            usize::try_from(table.length / table.entry_size).map_err(|_| Error::Arithmetic)?;
        out.relocation_records = out
            .relocation_records
            .checked_add(count)
            .ok_or(Error::Arithmetic)?;
        bound(
            out.relocation_records,
            limits.relocation_records,
            "relocation records",
        )?;
        if table.length == 0 {
            continue;
        }
        let range = metadata(input, table.address, table.length, &mut out)?;
        if out.tables.iter().any(|old| intersects(*old, range)) {
            return Err(Error::TableOverlap);
        }
        out.tables.push(range);
        let records = file_bytes(input, range)?;
        if table.table == TableKind::Relr {
            inspect_relr(input, records, &mut out, limits)?;
            copy_write_budget(out.writes.len(), copies.len(), limits)?;
            continue;
        }
        for (record, bytes) in records.chunks_exact(table.entry_size as usize).enumerate() {
            let target = u64_at(bytes, 0);
            let info = u64_at(bytes, 8);
            let kind = info as u32;
            let symbol = (info >> 32) as u32;
            let relative_count = match table.table {
                TableKind::Rela => tags.get(&0x6fff_fff9),
                TableKind::Rel => tags.get(&0x6fff_fffa),
                _ => None,
            }
            .copied()
            .unwrap_or(0);
            if (record as u64) < relative_count && (kind != 8 || symbol != 0) {
                return Err(Error::InvalidRelocation { kind });
            }
            if matches!(kind, 8 | 37 | 38) && symbol != 0 {
                return Err(Error::InvalidRelocation { kind });
            }
            if symbol != 0 && !tags.contains_key(&6) {
                return Err(Error::InvalidTags { tag: 6 });
            }
            let width = if kind == 5 {
                if input.header().object_type != elf64::ObjectType::Executable
                    || table.table != TableKind::Rela
                    || symbol == 0
                {
                    return Err(Error::UnsupportedRelocation { kind });
                }
                if u64_at(bytes, 16) != 0 {
                    return Err(Error::InvalidRelocation { kind });
                }
                let pending = copies.len().checked_add(1).ok_or(Error::Arithmetic)?;
                copy_write_budget(out.writes.len(), pending, limits)?;
                copies.push((record, target, symbol));
                0 // Deferred until complete symbol/name/version ownership.
            } else {
                relocation_width(kind)?
            };
            out.symbol_references.push(SymbolReference {
                table: table.table,
                record,
                kind,
                symbol,
            });
            if width != 0 {
                copy_write_budget(
                    out.writes.len().checked_add(1).ok_or(Error::Arithmetic)?,
                    copies.len(),
                    limits,
                )?;
                push_write(
                    input,
                    &mut out,
                    limits,
                    RelocationWrite {
                        table: table.table,
                        record,
                        kind,
                        symbol,
                        range: VirtualRange::checked(ElfVaddr(target), width)?,
                        file: None,
                    },
                )?;
            }
        }
    }
    let symbols = complete_metadata::inspect(input, &tags, &mut out, limits)?;
    let has_copy = !copies.is_empty();
    for (record, target, symbol) in copies {
        let size = symbols.copy_size(symbol, target)?;
        let range = VirtualRange::checked(ElfVaddr(target), size)?;
        let owner = input.virtual_to_storage(range.start(), range.len())?;
        if !owner.flags.readable() || !owner.flags.writable() || owner.flags.executable() {
            return Err(Error::InvalidRelocation { kind: 5 });
        }
        push_write(
            input,
            &mut out,
            limits,
            RelocationWrite {
                table: TableKind::Rela,
                record,
                kind: 5,
                symbol,
                range,
                file: None,
            },
        )?;
    }
    if has_copy {
        // Restore descriptor/record order after resolving deferred COPY rows.
        // Stable sort preserves the existing per-record RELR expansion order.
        out.writes.sort_by_key(|write| {
            (
                match write.table {
                    TableKind::Rela => 0,
                    TableKind::Rel => 1,
                    TableKind::Relr => 2,
                    TableKind::JumpRela | TableKind::JumpRel => 3,
                },
                write.record,
            )
        });
    }
    let mut order: Vec<_> = out.writes.iter().enumerate().collect();
    order.sort_by_key(|(_, write)| write.range.start());
    for pair in order.windows(2) {
        if pair[1].1.range.start() < pair[0].1.range.end() {
            return Err(Error::DuplicateWrite {
                first: pair[0].0,
                second: pair[1].0,
            });
        }
    }
    out.protected.sort_by_key(|range| range.start());
    out.protected.dedup();
    Ok(out)
}

fn copy_write_budget(fixed: usize, pending: usize, limits: Limits) -> Result<(), Error> {
    bound(
        fixed.checked_add(pending).ok_or(Error::Arithmetic)?,
        limits.relocation_writes,
        "relocation writes",
    )
}

fn relocation_width(kind: u32) -> Result<u64, Error> {
    match kind {
        0 => Ok(0),
        1 | 6 | 7 | 8 | 16 | 17 | 18 | 37 | 38 => Ok(8),
        2 | 10 | 11 => Ok(4),
        36 => Ok(16),
        // COPY is handled separately after complete symbol-size/version ownership.
        // Static-only and unrecognized kinds are not guessed from their numbers.
        _ => Err(Error::UnsupportedRelocation { kind }),
    }
}

fn inspect_relr(
    input: &Elf64<'_>,
    records: &[u8],
    out: &mut Inventory,
    limits: Limits,
) -> Result<(), Error> {
    let mut cursor: Option<u64> = None;
    for (record, bytes) in records.chunks_exact(8).enumerate() {
        let word = u64_at(bytes, 0);
        if word & 1 == 0 {
            if word % 8 != 0 || cursor.is_some_and(|old| word < old) {
                return Err(Error::InvalidRelr);
            }
            push_write(
                input,
                out,
                limits,
                RelocationWrite {
                    table: TableKind::Relr,
                    record,
                    kind: 8,
                    symbol: 0,
                    range: VirtualRange::checked(ElfVaddr(word), 8)?,
                    file: None,
                },
            )?;
            cursor = Some(word.checked_add(8).ok_or(Error::Arithmetic)?);
        } else {
            let base = cursor.ok_or(Error::InvalidRelr)?;
            for bit in 1..64 {
                if word & (1_u64 << bit) != 0 {
                    let target = base.checked_add((bit - 1) * 8).ok_or(Error::Arithmetic)?;
                    push_write(
                        input,
                        out,
                        limits,
                        RelocationWrite {
                            table: TableKind::Relr,
                            record,
                            kind: 8,
                            symbol: 0,
                            range: VirtualRange::checked(ElfVaddr(target), 8)?,
                            file: None,
                        },
                    )?;
                }
            }
            cursor = Some(base.checked_add(63 * 8).ok_or(Error::Arithmetic)?);
        }
    }
    Ok(())
}

fn push_write(
    input: &Elf64<'_>,
    out: &mut Inventory,
    limits: Limits,
    mut write: RelocationWrite,
) -> Result<(), Error> {
    bound(
        out.writes.len().checked_add(1).ok_or(Error::Arithmetic)?,
        limits.relocation_writes,
        "relocation writes",
    )?;
    let mapping = input.virtual_to_storage(write.range.start(), write.range.len())?;
    write.file = match mapping.storage {
        Storage::FileBacked(file) => Some(file),
        Storage::ZeroFill => None,
    };
    out.writes.push(write);
    Ok(())
}

struct Descriptor {
    address: u64,
    length: u64,
    entry_size: u64,
    table: TableKind,
}

fn relocation_table(
    tags: &BTreeMap<u64, u64>,
    pointer: u64,
    size: u64,
    entry: u64,
    width: u64,
    table: TableKind,
) -> Result<Option<Descriptor>, Error> {
    match (tags.get(&pointer), tags.get(&size), tags.get(&entry)) {
        (None, None, None) => Ok(None),
        // REL[A]ENT may be shared with a JMPREL-only table.
        (None, None, Some(&actual)) if actual == width => Ok(None),
        (Some(&address), Some(&length), Some(&actual))
            if actual == width && length % width == 0 =>
        {
            Ok(Some(Descriptor {
                address,
                length,
                entry_size: width,
                table,
            }))
        }
        _ => Err(Error::InvalidTags { tag: pointer }),
    }
}

fn metadata(
    input: &Elf64<'_>,
    address: u64,
    length: u64,
    out: &mut Inventory,
) -> Result<FileRange, Error> {
    let mapping = input.virtual_to_storage(ElfVaddr(address), length)?;
    if mapping.flags.executable() {
        return Err(Error::MetadataInExecutableLoad {
            index: mapping.program_header,
        });
    }
    if !mapping.flags.readable() {
        return Err(Error::MetadataNotReadable);
    }
    let Storage::FileBacked(range) = mapping.storage else {
        return Err(Error::MetadataNotFileBacked);
    };
    out.protected
        .push(input.program_headers()[mapping.program_header].file_range()?);
    Ok(range)
}

fn file_bytes<'a>(input: &Elf64<'a>, range: FileRange) -> Result<&'a [u8], Error> {
    let start = usize::try_from(range.start().0).map_err(|_| Error::Arithmetic)?;
    let end = usize::try_from(range.end().0).map_err(|_| Error::Arithmetic)?;
    input.bytes().get(start..end).ok_or(Error::Arithmetic)
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn bound(required: usize, limit: usize, resource: &'static str) -> Result<(), Error> {
    if required > limit {
        Err(Error::Budget { resource, limit })
    } else {
        Ok(())
    }
}
fn intersects(a: FileRange, b: FileRange) -> bool {
    a.start() < b.end() && b.start() < a.end()
}
fn known_tag(tag: u64) -> bool {
    matches!(tag,
        1..=30 | 32..=37 |
        0x6fff_fef5 | 0x6fff_fef7 | 0x6fff_fff0 |
        0x6fff_fff9..=0x6fff_ffff | 0x7fff_fffd | 0x7fff_ffff)
}

#[cfg(test)]
#[path = "dynamic_copy_fixtures.rs"]
mod copy_fixtures;
