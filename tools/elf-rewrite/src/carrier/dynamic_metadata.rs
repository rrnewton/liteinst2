//! Complete bounded extents for variable loader-consumed dynamic metadata.
use super::*;
use std::collections::BTreeSet;

const HASH: u64 = 4;
const GNU_HASH: u64 = 0x6fff_fef5;
const VERSYM: u64 = 0x6fff_fff0;
const VERDEF: u64 = 0x6fff_fffc;
const VERNEED: u64 = 0x6fff_fffe;

struct Work {
    records: usize,
    bytes: usize,
    limits: Limits,
}
impl Work {
    fn charge(&mut self, records: u64, bytes: u64) -> Result<(), Error> {
        self.records = self
            .records
            .checked_add(usize::try_from(records).map_err(|_| Error::Arithmetic)?)
            .ok_or(Error::Arithmetic)?;
        self.bytes = self
            .bytes
            .checked_add(usize::try_from(bytes).map_err(|_| Error::Arithmetic)?)
            .ok_or(Error::Arithmetic)?;
        bound(
            self.records,
            self.limits.metadata_records,
            "metadata records",
        )?;
        bound(self.bytes, self.limits.metadata_bytes, "metadata bytes")
    }
}

/// Metadata borrows returned only after the complete bounded pass succeeds.
/// This authenticates input ownership, not the external provider's symbol value.
pub(super) struct Symbols<'a> {
    table: Option<&'a [u8]>,
    strings: Option<&'a [u8]>,
    versions: Option<&'a [u8]>,
    needed: BTreeMap<u16, Option<NeededVersion>>,
    defined: BTreeSet<u16>,
}

struct NeededVersion {
    index: u16,
    flags: u16,
    library: u32,
    name: u32,
}

impl Symbols<'_> {
    pub(super) fn copy_size(&self, symbol: u32, target: u64) -> Result<u64, Error> {
        let invalid = || Error::InvalidRelocation { kind: 5 };
        let index = usize::try_from(symbol).map_err(|_| Error::Arithmetic)?;
        let at = index.checked_mul(24).ok_or(Error::Arithmetic)?;
        let end = at.checked_add(24).ok_or(Error::Arithmetic)?;
        let row = self
            .table
            .and_then(|table| table.get(at..end))
            .ok_or_else(invalid)?;
        let section = u16_at(row, 6);
        let size = u64_at(row, 16);
        // Named, defined GLOBAL/OBJECT, default visibility, ordinary section.
        // The section number is not used as a storage owner or trusted extent.
        if symbol == 0
            || row[4] != 0x11
            || row[5] != 0
            || section == 0
            || section >= 0xff00
            || size == 0
            || u64_at(row, 8) != target
            || !self.nonempty_name(u32_at(row, 0))
        {
            return Err(invalid());
        }
        if let Some(versions) = self.versions {
            let at = index.checked_mul(2).ok_or(Error::Arithmetic)?;
            let end = at.checked_add(2).ok_or(Error::Arithmetic)?;
            let row = versions.get(at..end).ok_or_else(invalid)?;
            let version = u16_at(row, 0);
            if version == 0 || version & 0x8000 != 0 {
                return Err(invalid());
            }
            if version != 1 {
                if self.defined.contains(&version) {
                    return Err(invalid());
                }
                let need = self
                    .needed
                    .get(&version)
                    .and_then(Option::as_ref)
                    .ok_or_else(invalid)?;
                if need.index != version
                    || need.flags != 0
                    || !self.nonempty_name(need.library)
                    || !self.nonempty_name(need.name)
                {
                    return Err(invalid());
                }
            }
        }
        Ok(size)
    }

    fn nonempty_name(&self, offset: u32) -> bool {
        // The complete pass has already proved a terminating NUL after every
        // referenced offset. COPY additionally refuses an empty symbol/version.
        if offset == 0 {
            return false;
        }
        usize::try_from(offset)
            .ok()
            .and_then(|at| self.strings.and_then(|table| table.get(at)))
            .is_some_and(|byte| *byte != 0)
    }
}

pub(super) fn inspect<'a>(
    input: &Elf64<'a>,
    tags: &BTreeMap<u64, u64>,
    out: &mut Inventory,
    limits: Limits,
) -> Result<Symbols<'a>, Error> {
    let mut work = Work {
        records: 0,
        bytes: 0,
        limits,
    };
    let collect_copy = out
        .symbol_references
        .iter()
        .any(|reference| reference.kind == 5);
    let mut needed: BTreeMap<u16, Option<NeededVersion>> = BTreeMap::new();
    let mut defined = BTreeSet::new();
    let mut symbol_table = None;
    let mut versions = None;
    let mut authoritative: Option<u64> = None;
    if let Some(&address) = tags.get(&HASH) {
        let header = checked(input, address, 8, out, &mut work)?;
        let buckets = u64::from(u32_at(header, 0));
        let chains = u64::from(u32_at(header, 4));
        if buckets == 0 || chains == 0 {
            return Err(Error::InvalidMetadata { tag: HASH });
        }
        work.charge(buckets.checked_add(chains).ok_or(Error::Arithmetic)?, 0)?;
        let extent = plus(8, times(plus(buckets, chains)?, 4)?)?;
        let table = checked(input, address, extent, out, &mut work)?;
        for word in table[8..].chunks_exact(4) {
            if u64::from(u32_at(word, 0)) >= chains {
                return Err(Error::InvalidMetadata { tag: HASH });
            }
        }
        authoritative = Some(chains);
    }
    if let Some(&address) = tags.get(&GNU_HASH) {
        let header = checked(input, address, 16, out, &mut work)?;
        let buckets = u64::from(u32_at(header, 0));
        let first = u64::from(u32_at(header, 4));
        let bloom = u64::from(u32_at(header, 8));
        if buckets == 0 || !bloom.is_power_of_two() || u32_at(header, 12) >= 32 {
            return Err(Error::InvalidMetadata { tag: GNU_HASH });
        }
        work.charge(plus(buckets, bloom)?, 0)?;
        // Even an empty hash carries the un-hashed prefix of the symbol table.
        bound(
            usize::try_from(first).map_err(|_| Error::Arithmetic)?,
            limits.metadata_records,
            "metadata records",
        )?;
        let bucket_offset = plus(16, times(bloom, 8)?)?;
        let fixed = plus(bucket_offset, times(buckets, 4)?)?;
        let table = checked(input, address, fixed, out, &mut work)?;
        let mut symbols = first;
        for bucket in
            table[usize::try_from(bucket_offset).map_err(|_| Error::Arithmetic)?..].chunks_exact(4)
        {
            let mut symbol = u64::from(u32_at(bucket, 0));
            if symbol == 0 {
                continue;
            }
            if symbol < first {
                return Err(Error::InvalidMetadata { tag: GNU_HASH });
            }
            loop {
                work.charge(1, 0)?;
                bound(
                    usize::try_from(plus(symbol, 1)?).map_err(|_| Error::Arithmetic)?,
                    limits.metadata_records,
                    "metadata records",
                )?;
                let delta = times(symbol - first, 4)?;
                let chain = checked(
                    input,
                    plus(address, plus(fixed, delta)?)?,
                    4,
                    out,
                    &mut work,
                )?;
                symbols = symbols.max(plus(symbol, 1)?);
                if u32_at(chain, 0) & 1 != 0 {
                    break;
                }
                symbol = plus(symbol, 1)?;
            }
        }
        // Also prove the complete contiguous table range, not only each access.
        checked(
            input,
            address,
            plus(fixed, times(symbols - first, 4)?)?,
            out,
            &mut work,
        )?;
        if authoritative.is_some_and(|count| symbols > count) {
            return Err(Error::InvalidMetadata { tag: GNU_HASH });
        }
        authoritative = authoritative.or(Some(symbols));
    }
    let referenced = out
        .symbol_references
        .iter()
        .map(|reference| u64::from(reference.symbol))
        .max()
        .unwrap_or(0);
    if authoritative.is_some_and(|count| referenced >= count) {
        return Err(Error::InvalidMetadata { tag: 6 });
    }
    let symbols = authoritative.unwrap_or(plus(referenced, 1)?);
    let strings = if let (Some(&address), Some(&length)) = (tags.get(&5), tags.get(&10)) {
        if length == 0 {
            None
        } else {
            Some(checked(input, address, length, out, &mut work)?)
        }
    } else {
        None
    };
    let last_nul = strings.and_then(|bytes| bytes.iter().rposition(|byte| *byte == 0));
    if let Some(&address) = tags.get(&6) {
        work.charge(symbols, 0)?;
        let length = times(symbols, 24)?;
        let table = checked(input, address, length, out, &mut work)?;
        symbol_table = Some(table);
        for symbol in table.chunks_exact(24) {
            // An absent string table is acceptable only for unnamed records;
            // this does not validate symbol lookup or dynamic linking semantics.
            let name = u64::from(u32_at(symbol, 0));
            if name != 0 || strings.is_some() {
                string(name, last_nul, 6)?;
            }
        }
        // Retain the exact already-validated owner without charging/scanning
        // again or changing the old metadata pass's acceptance and limits.
        let owner = input.virtual_to_storage(ElfVaddr(address), length)?;
        let Storage::FileBacked(file) = owner.storage else {
            return Err(Error::MetadataNotFileBacked);
        };
        out.symbol_extent = Some(SymbolExtent {
            file,
            virtual_range: owner.virtual_range,
            count: symbols,
            hash_authoritative: authoritative.is_some(),
        });
    } else if authoritative.is_some()
        || referenced != 0
        || tags.contains_key(&VERSYM)
        || tags.contains_key(&34)
    {
        return Err(Error::InvalidMetadata { tag: 6 });
    }
    for (tag, width) in [(34, 4), (VERSYM, 2)] {
        if let Some(&address) = tags.get(&tag) {
            work.charge(symbols, 0)?;
            let table = checked(input, address, times(symbols, width)?, out, &mut work)?;
            if tag == VERSYM {
                versions = Some(table);
            }
        }
    }
    for (tag, count_tag, header_size, auxiliary_size) in
        [(VERDEF, 0x6fff_fffd, 20, 8), (VERNEED, 0x6fff_ffff, 16, 16)]
    {
        if let Some(&address) = tags.get(&tag) {
            let count = *tags.get(&count_tag).ok_or(Error::InvalidMetadata { tag })?;
            if count == 0 {
                return Err(Error::InvalidMetadata { tag });
            }
            work.charge(count, 0)?;
            let mut current = address;
            for record in 0..count {
                let header = checked(input, current, header_size, out, &mut work)?;
                if u16_at(header, 0) != 1 {
                    return Err(Error::InvalidMetadata { tag });
                }
                if collect_copy && tag == VERDEF {
                    defined.insert(u16_at(header, 4) & 0x7fff);
                }
                let (aux_count, auxiliary, next) = if tag == VERDEF {
                    (
                        u64::from(u16_at(header, 6)),
                        u64::from(u32_at(header, 12)),
                        u64::from(u32_at(header, 16)),
                    )
                } else {
                    string(u64::from(u32_at(header, 4)), last_nul, tag)?;
                    (
                        u64::from(u16_at(header, 2)),
                        u64::from(u32_at(header, 8)),
                        u64::from(u32_at(header, 12)),
                    )
                };
                if aux_count == 0 || auxiliary < header_size {
                    return Err(Error::InvalidMetadata { tag });
                }
                work.charge(aux_count, 0)?;
                let mut aux = plus(current, auxiliary)?;
                for index in 0..aux_count {
                    let record = checked(input, aux, auxiliary_size, out, &mut work)?;
                    let (name_at, next_at) = if tag == VERDEF { (0, 4) } else { (8, 12) };
                    string(u64::from(u32_at(record, name_at)), last_nul, tag)?;
                    if collect_copy && tag == VERNEED {
                        let value = NeededVersion {
                            index: u16_at(record, 6),
                            flags: u16_at(record, 4),
                            library: u32_at(header, 4),
                            name: u32_at(record, 8),
                        };
                        // All auxiliary records have already been charged to
                        // the unchanged metadata record/byte budgets. Duplicate
                        // indices remain ambiguous, never last-writer-wins.
                        needed
                            .entry(value.index & 0x7fff)
                            .and_modify(|owner| *owner = None)
                            .or_insert(Some(value));
                    }
                    let offset = u64::from(u32_at(record, next_at));
                    if index + 1 == aux_count {
                        if offset != 0 {
                            return Err(Error::InvalidMetadata { tag });
                        }
                    } else {
                        if offset < auxiliary_size {
                            return Err(Error::InvalidMetadata { tag });
                        }
                        aux = plus(aux, offset)?;
                    }
                }
                if record + 1 == count {
                    if next != 0 {
                        return Err(Error::InvalidMetadata { tag });
                    }
                } else {
                    if next < header_size {
                        return Err(Error::InvalidMetadata { tag });
                    }
                    current = plus(current, next)?;
                }
            }
        }
    }
    Ok(Symbols {
        table: symbol_table,
        strings,
        versions,
        needed,
        defined,
    })
}

fn checked<'a>(
    input: &Elf64<'a>,
    address: u64,
    length: u64,
    out: &mut Inventory,
    work: &mut Work,
) -> Result<&'a [u8], Error> {
    work.charge(0, length)?;
    let range = metadata(input, address, length, out)?;
    file_bytes(input, range)
}
fn string(offset: u64, last_nul: Option<usize>, tag: u64) -> Result<(), Error> {
    if last_nul.is_some_and(|last| offset <= last as u64) {
        Ok(())
    } else {
        Err(Error::InvalidMetadata { tag })
    }
}
fn plus(left: u64, right: u64) -> Result<u64, Error> {
    left.checked_add(right).ok_or(Error::Arithmetic)
}
fn times(left: u64, right: u64) -> Result<u64, Error> {
    left.checked_mul(right).ok_or(Error::Arithmetic)
}
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
