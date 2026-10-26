//! Complete bounded extents for variable loader-consumed dynamic metadata.
use super::*;

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

pub(super) fn inspect(
    input: &Elf64<'_>,
    tags: &BTreeMap<u64, u64>,
    out: &mut Inventory,
    limits: Limits,
) -> Result<(), Error> {
    let mut work = Work {
        records: 0,
        bytes: 0,
        limits,
    };
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
        let table = checked(input, address, times(symbols, 24)?, out, &mut work)?;
        for symbol in table.chunks_exact(24) {
            // An absent string table is acceptable only for unnamed records;
            // this does not validate symbol lookup or dynamic linking semantics.
            let name = u64::from(u32_at(symbol, 0));
            if name != 0 || strings.is_some() {
                string(name, last_nul, 6)?;
            }
        }
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
            checked(input, address, times(symbols, width)?, out, &mut work)?;
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
    Ok(())
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
