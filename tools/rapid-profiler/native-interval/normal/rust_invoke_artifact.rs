//! Private complete-ELF authority for an unchanged copied Rust invoke body.
use crate::oracle::native_ordinary::normal_caller::rust_invoke::{
    self, CopiedInvoke, Error, Plan, Result,
};
use object::{Object, ObjectSection, ObjectSymbol, SectionFlags, SymbolFlags, SymbolKind};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
#[cfg(test)]
#[path = "rust_invoke_artifact/tests.rs"]
mod tests;

const CAP: usize = 512 * 1024 * 1024;
const SYMBOL: &str = "liteinst_csv_call_and_store";
pub(super) fn require(ok: bool, error: Error) -> Result<()> {
    if ok { Ok(()) } else { Err(error) }
}
pub(super) fn slice(b: &[u8], at: u64, len: u64) -> Result<&[u8]> {
    let end = at.checked_add(len).ok_or(Error::Format)?;
    b.get(
        usize::try_from(at).map_err(|_| Error::Format)?
            ..usize::try_from(end).map_err(|_| Error::Format)?,
    )
    .ok_or(Error::Format)
}
pub(super) fn u16_at(b: &[u8], at: u64) -> Result<u16> {
    Ok(u16::from_le_bytes(slice(b, at, 2)?.try_into().unwrap()))
}
pub(super) fn u32_at(b: &[u8], at: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(slice(b, at, 4)?.try_into().unwrap()))
}
pub(super) fn u64_at(b: &[u8], at: u64) -> Result<u64> {
    Ok(u64::from_le_bytes(slice(b, at, 8)?.try_into().unwrap()))
}
pub(super) fn end(start: u64, size: u64) -> Result<u64> {
    start.checked_add(size).ok_or(Error::Format)
}
pub(super) fn overlaps(a: u64, an: u64, b: u64, bn: u64) -> Result<bool> {
    Ok(an != 0 && bn != 0 && a < end(b, bn)? && b < end(a, an)?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection {
    pub virtual_address: u64,
    pub file_offset: u64,
    pub section: usize,
    pub extent: usize,
}
#[derive(Clone, Copy)]
struct Section {
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    entry: u64,
}
#[derive(Clone, Copy)]
struct Load {
    flags: u32,
    offset: u64,
    address: u64,
    files: u64,
    memory: u64,
}

// Finite x86-64 ELF relocation widths. Unknown/variable-size forms refuse the
// artifact; NONE writes nothing. COPY and packed RELR are outside this profile.
fn relocation_width(kind: u32) -> Result<u64> {
    match kind {
        0 => Ok(0),
        1 | 6 | 7 | 8 | 16 | 17 | 18 | 24 | 25 | 27 | 28 | 29 | 30 | 31 | 33 | 37 | 38 => Ok(8),
        2 | 3 | 4 | 9 | 10 | 11 | 19 | 20 | 21 | 22 | 23 | 26 | 32 | 34 | 41 | 42 => Ok(4),
        12 | 13 => Ok(2),
        14 | 15 => Ok(1),
        36 => Ok(16),
        _ => Err(Error::Relocation),
    }
}
fn relocations(
    b: &[u8],
    sections: &[Section],
    dynamics: &[Load],
    loads: &[Load],
    selected: Selection,
) -> Result<()> {
    for s in sections {
        require(s.kind != 19 || s.size == 0, Error::Relocation)?; // SHT_RELR
        if !matches!(s.kind, 4 | 9) {
            continue;
        }
        let width = if s.kind == 4 { 24 } else { 16 };
        require(s.entry == width && s.size % width == 0, Error::Relocation)?;
        for row in slice(b, s.offset, s.size)?.chunks_exact(width as usize) {
            let address = u64_at(row, 0)?;
            let bytes = relocation_width(u64_at(row, 8)? as u32)?;
            if bytes != 0 {
                require(
                    !overlaps(
                        address,
                        bytes,
                        selected.virtual_address,
                        selected.extent as u64,
                    )?,
                    Error::Relocation,
                )?;
            }
        }
    }
    // Dynamic relocation pointers must refer to the same exhaustively checked
    // section tables, never a second hidden relocation source.
    let dynamic_sections: Vec<_> = sections.iter().filter(|s| s.kind == 6).collect();
    require(dynamic_sections.len() == dynamics.len(), Error::Relocation)?;
    for dynamic in dynamics {
        let (offset, size) = (dynamic.offset, dynamic.files);
        require(
            dynamic.memory == size && dynamic.flags & !7 == 0,
            Error::Relocation,
        )?;
        require(dynamic_sections.len() == 1, Error::Relocation)?;
        let section = dynamic_sections[0];
        require(
            section.address == dynamic.address
                && section.offset == offset
                && section.size == size
                && section.entry == 16
                && section.flags & 2 != 0,
            Error::Relocation,
        )?;
        unique_load_bytes(loads, dynamic.address, size, offset)?;
        require(size != 0 && size <= 65536 && size % 16 == 0, Error::Format)?;
        let mut tags = BTreeMap::new();
        let mut ended = false;
        for row in slice(b, offset, size)?.chunks_exact(16) {
            let (tag, value) = (u64_at(row, 0)?, u64_at(row, 8)?);
            require(!ended || (tag == 0 && value == 0), Error::Format)?;
            if tag == 0 {
                require(value == 0, Error::Format)?;
                ended = true;
                continue;
            }
            // Standard non-packed tags plus the known GNU hash/version/count
            // metadata only. Android packed forms and DT_RELR do not disappear
            // behind an otherwise accepted ordinary relocation table.
            require(
                matches!(tag,1..=30|32|33|0x6fff_fef5|0x6fff_fff0|0x6fff_fff9..=0x6fff_ffff),
                Error::Relocation,
            )?;
            if matches!(tag, 2 | 7 | 8 | 9 | 17 | 18 | 19 | 20 | 23) {
                require(tags.insert(tag, value).is_none(), Error::Relocation)?;
            }
        }
        require(ended, Error::Format)?;
        for (pointer, length, entry, kind, width) in [(7, 8, 9, 4, 24), (17, 18, 19, 9, 16)] {
            if ![pointer, length, entry]
                .iter()
                .any(|t| tags.contains_key(t))
            {
                continue;
            }
            let address = *tags.get(&pointer).ok_or(Error::Relocation)?;
            let length = *tags.get(&length).ok_or(Error::Relocation)?;
            require(tags.get(&entry) == Some(&width), Error::Relocation)?;
            relocation_table(sections, loads, address, length, kind, width)?;
        }
        if [2, 20, 23].iter().any(|t| tags.contains_key(t)) {
            let address = *tags.get(&23).ok_or(Error::Relocation)?;
            let length = *tags.get(&2).ok_or(Error::Relocation)?;
            let (kind, width) = match tags.get(&20) {
                Some(7) => (4, 24),
                Some(17) => (9, 16),
                _ => return Err(Error::Relocation),
            };
            relocation_table(sections, loads, address, length, kind, width)?;
        }
    }
    Ok(())
}
fn relocation_table(
    sections: &[Section],
    loads: &[Load],
    address: u64,
    size: u64,
    kind: u32,
    width: u64,
) -> Result<()> {
    require(size % width == 0, Error::Relocation)?;
    if size == 0 {
        return Ok(());
    }
    let matching: Vec<_> = sections
        .iter()
        .filter(|s| {
            s.kind == kind
                && s.address <= address
                && end(address, size).is_ok_and(|e| end(s.address, s.size).is_ok_and(|se| e <= se))
                && (address - s.address) % width == 0
        })
        .collect();
    require(matching.len() == 1, Error::Relocation)?;
    let s = matching[0];
    let expected = end(s.offset, address - s.address)?;
    unique_load_bytes(loads, address, size, expected)
}
// Every intersecting loader segment must agree and cover the whole source.
// Counting only agreeable segments would hide a second conflicting mapping.
fn unique_load_bytes(loads: &[Load], address: u64, size: u64, offset: u64) -> Result<()> {
    require(size != 0, Error::Relocation)?;
    let mut count = 0;
    for l in loads {
        if !overlaps(l.address, l.memory, address, size)? {
            continue;
        }
        require(
            l.address <= address
                && end(address, size)? <= end(l.address, l.files)?
                && end(l.offset, address - l.address)? == offset,
            Error::Relocation,
        )?;
        count += 1;
    }
    require(count == 1, Error::Relocation)
}

/// Extract the complete unique named FUNC; this proves syntax, not native fit.
pub fn extract(b: &[u8]) -> Result<(Selection, Plan)> {
    require(
        b.len() <= CAP
            && b.get(..7) == Some(b"\x7fELF\x02\x01\x01")
            && matches!(u16_at(b, 16)?, 2 | 3)
            && u16_at(b, 18)? == 62
            && u32_at(b, 20)? == 1
            && u32_at(b, 48)? == 0
            && u16_at(b, 52)? == 64
            && u16_at(b, 54)? == 56
            && u16_at(b, 58)? == 64,
        Error::Format,
    )?;
    let (phoff, shoff) = (u64_at(b, 32)?, u64_at(b, 40)?);
    let (pn, sn) = (u16_at(b, 56)?, u16_at(b, 60)?);
    require(
        (1..=4096).contains(&pn) && (1..=4096).contains(&sn) && u16_at(b, 62)? < sn,
        Error::Format,
    )?; // No extended section counts/indexes.
    slice(b, phoff, u64::from(pn) * 56)?;
    slice(b, shoff, u64::from(sn) * 64)?;
    let mut loads = Vec::new();
    let mut dynamics = Vec::new();
    for n in 0..pn {
        let p = phoff + u64::from(n) * 56;
        let kind = u32_at(b, p)?;
        let l = Load {
            flags: u32_at(b, p + 4)?,
            offset: u64_at(b, p + 8)?,
            address: u64_at(b, p + 16)?,
            files: u64_at(b, p + 32)?,
            memory: u64_at(b, p + 40)?,
        };
        slice(b, l.offset, l.files)?;
        end(l.address, l.memory)?;
        if kind == 1 {
            let align = u64_at(b, p + 48)?;
            require(
                l.files <= l.memory
                    && l.flags & !7 == 0
                    && (align <= 1
                        || (align.is_power_of_two() && l.offset % align == l.address % align)),
                Error::Format,
            )?;
            loads.push(l);
        }
        if kind == 2 {
            dynamics.push(l);
        }
    }
    require(!loads.is_empty() && dynamics.len() <= 1, Error::Format)?;
    let mut sections = Vec::new();
    for n in 0..sn {
        let p = shoff + u64::from(n) * 64;
        let s = Section {
            kind: u32_at(b, p + 4)?,
            flags: u64_at(b, p + 8)?,
            address: u64_at(b, p + 16)?,
            offset: u64_at(b, p + 24)?,
            size: u64_at(b, p + 32)?,
            entry: u64_at(b, p + 56)?,
        };
        end(s.address, s.size)?;
        if s.kind != 8 {
            slice(b, s.offset, s.size)?;
        }
        require(
            matches!(s.kind,0..=9|11|14..=17|19|0x6fff_fff5|0x6fff_fff6|0x6fff_fffd..=0x6fff_ffff)
                && s.flags & 0x800 == 0,
            Error::Format,
        )?; // No SHNDX, compression or unknown/packed section grammar.
        sections.push(s);
    }
    let file = object::File::parse(b).map_err(|_| Error::Format)?;
    let mut selected = None;
    let mut per_table = [false; 2];
    for (table, symbols) in [file.symbols(), file.dynamic_symbols()]
        .into_iter()
        .enumerate()
    {
        for s in symbols {
            if s.name().map_err(|_| Error::Symbol)? != SYMBOL {
                continue;
            }
            require(
                !per_table[table]
                    && s.is_definition()
                    && s.kind() == SymbolKind::Text
                    && matches!(
                        s.flags(),
                        SymbolFlags::Elf {
                            st_info: 0x12,
                            st_other: 0
                        }
                    )
                    && (1..=rust_invoke::MAX_BYTES as u64).contains(&s.size()),
                Error::Symbol,
            )?;
            per_table[table] = true;
            let section = s.section_index().ok_or(Error::Symbol)?;
            let raw = sections.get(section.0).ok_or(Error::Symbol)?;
            let section = file.section_by_index(section).map_err(|_| Error::Symbol)?;
            require(
                raw.kind == 1
                    && raw.flags & 7 == 6
                    && s.address() >= raw.address
                    && end(s.address(), s.size())? <= end(raw.address, raw.size)?
                    && matches!(section.flags(),SectionFlags::Elf{sh_flags} if sh_flags==raw.flags)
                    && section.file_range() == Some((raw.offset, raw.size)),
                Error::Symbol,
            )?;
            let selection = Selection {
                virtual_address: s.address(),
                file_offset: end(raw.offset, s.address() - raw.address)?,
                section: s.section_index().unwrap().0,
                extent: s.size() as usize,
            };
            require(selected.is_none_or(|old| old == selection), Error::Symbol)?;
            selected = Some(selection);
        }
    }
    let selected = selected.ok_or(Error::Symbol)?;
    let mut containing = 0;
    for l in &loads {
        if !overlaps(
            l.address,
            l.memory,
            selected.virtual_address,
            selected.extent as u64,
        )? {
            continue;
        }
        require(
            l.flags == 5
                && l.address <= selected.virtual_address
                && end(selected.virtual_address, selected.extent as u64)?
                    <= end(l.address, l.files)?
                && end(l.offset, selected.virtual_address - l.address)? == selected.file_offset,
            Error::Symbol,
        )?;
        containing += 1;
    }
    require(containing == 1, Error::Symbol)?;
    for s in file.symbols().chain(file.dynamic_symbols()) {
        if s.name().map_err(|_| Error::Symbol)? == SYMBOL
            || s.is_undefined()
            || matches!(s.kind(), SymbolKind::Section | SymbolKind::File)
        {
            continue;
        }
        let size = s.size();
        require(
            if size == 0 {
                !(selected.virtual_address <= s.address()
                    && s.address() < end(selected.virtual_address, selected.extent as u64)?)
            } else {
                !overlaps(
                    s.address(),
                    size,
                    selected.virtual_address,
                    selected.extent as u64,
                )?
            },
            Error::Symbol,
        )?;
    }
    relocations(b, &sections, &dynamics, &loads, selected)?;
    let plan = rust_invoke::admit(slice(b, selected.file_offset, selected.extent as u64)?)?;
    Ok((selected, plan))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Stamp {
    pub(super) dev: u64,
    pub(super) ino: u64,
    pub(super) len: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
pub(super) fn stamp(file: &File) -> Result<Stamp> {
    let m = file.metadata().map_err(|_| Error::Io)?;
    require(m.is_file() && m.len() <= CAP as u64, Error::Source)?;
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        mode: m.mode(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}
fn source_matches(
    original: Stamp,
    before: Stamp,
    after: Stamp,
    expected: &[u8],
    actual: &[u8],
) -> Result<()> {
    require(
        original == before
            && original == after
            && original.len == expected.len() as u64
            && !expected.is_empty()
            && expected.len() <= CAP
            && expected == actual,
        Error::Source,
    )
}
pub(super) fn verify_file(file: &File, original: Stamp, expected: &[u8]) -> Result<()> {
    let before = stamp(file)?;
    require(
        before == original && expected.len() as u64 == original.len && expected.len() <= CAP,
        Error::Source,
    )?;
    let mut actual = vec![0; expected.len()];
    let mut at = 0;
    while at < actual.len() {
        let n = file
            .read_at(&mut actual[at..], at as u64)
            .map_err(|_| Error::Io)?;
        require(n != 0, Error::Source)?;
        at += n;
    }
    let mut extra = [0];
    require(
        file.read_at(&mut extra, at as u64).map_err(|_| Error::Io)? == 0,
        Error::Source,
    )?;
    source_matches(original, before, stamp(file)?, expected, &actual)
}
pub struct Artifact {
    file: File,
    stamp: Stamp,
    bytes: Vec<u8>,
    selection: Selection,
    copy: CopiedInvoke,
}
impl Artifact {
    /// # Safety
    /// `trusted` is independently authenticated complete application ELF data.
    /// No source writer or alias mutation is permitted through final acceptance.
    /// The caller upholds CopiedInvoke's exclusive/fork/reap lifetime contract.
    pub unsafe fn open(path: &Path, trusted: &[u8]) -> Result<Self> {
        require(!trusted.is_empty() && trusted.len() <= CAP, Error::Source)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| Error::Io)?;
        let initial = stamp(&file)?;
        verify_file(&file, initial, trusted)?;
        let (selection, plan) = extract(trusted)?;
        let copy = unsafe { CopiedInvoke::new(plan) }?;
        let owner = Self {
            file,
            stamp: initial,
            bytes: trusted.to_vec(),
            selection,
            copy,
        };
        owner.verify()?;
        Ok(owner)
    }
    pub fn selection(&self) -> Selection {
        self.selection
    }
    pub fn plan(&self) -> &Plan {
        self.copy.plan()
    }
    pub fn entry(&self) -> u64 {
        self.copy.entry()
    }
    pub fn source(&self) -> (u64, &[u8]) {
        self.copy.source()
    }
    pub fn verify(&self) -> Result<()> {
        verify_file(&self.file, self.stamp, &self.bytes)?;
        self.copy.verify()
    }
}
