//! Immutable byte/symbol authority for the explicitly compiled DSO fixture.
//! No symbol, name, build ID or CFI byte copy certifies frame/hook semantics.
#![forbid(unsafe_code)]

use formats::ContentId;
use li2core::generated_unwind::artifact::OriginalArtifactCfi;
use liteinst_rewrite::carrier::{
    dynamic,
    elf64::{
        self, Elf64, ElfVaddr, FileRange, ObjectType, ParseLimits, SegmentType, Storage,
        VirtualRange,
    },
    unwind::{self, IndexLimits, OriginalIndex},
};
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

pub const BYTE_LIMIT: u64 = 16 * 1024 * 1024;
pub const SECTION_LIMIT: usize = 4096;
pub const SYMBOL_LIMIT: usize = 65536;
pub const PAGE: u64 = 4096;
const PROGRAM_LIMIT: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Io(std::io::ErrorKind),
    Elf(elf64::Error),
    Unwind(unwind::Error),
    Dynamic(dynamic::Error),
    Limit(&'static str),
    Format(&'static str),
    Missing(&'static str),
    Duplicate(&'static str),
    Symbol(&'static str),
    Ownership,
    Arithmetic,
    Allocation,
}
type Result<T> = std::result::Result<T, Error>;
impl From<elf64::Error> for Error {
    fn from(error: elf64::Error) -> Self {
        Self::Elf(error)
    }
}
impl From<unwind::Error> for Error {
    fn from(error: unwind::Error) -> Self {
        Self::Unwind(error)
    }
}
impl From<dynamic::Error> for Error {
    fn from(error: dynamic::Error) -> Self {
        Self::Dynamic(error)
    }
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

/// The observed linkage form is retained; LOCAL/DEFAULT is not STV_HIDDEN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Linkage {
    Exported,
    Hidden,
    Localized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Symbol {
    pub name: &'static str,
    pub address: u64,
    pub size: u64,
    pub section: usize,
    pub binding: u8,
    pub visibility: u8,
    pub linkage: Linkage,
}

#[derive(Clone, Debug)]
pub struct Symbols {
    pub work: Symbol,
    pub selected: Symbol,
    pub continuation: Symbol,
    pub hook: Symbol,
    pub reference: Symbol,
    pub collect_original: Symbol,
    pub configure: Symbol,
    pub capture_status: Symbol,
    pub capture_end: Symbol,
    pub consumer_addresses: Symbol,
    pub find_fde: Symbol,
}

/// Exact code bytes and a unique bidirectional nonwritable executable owner.
pub struct Code<'a> {
    pub bytes: &'a [u8],
    pub file: FileRange,
    pub program_header: usize,
}

/// Conservative reserved extents; the carrier must still validate actual output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Placements {
    pub carrier: VirtualRange,
    pub image: VirtualRange,
    pub output_file_upper_bound: u64,
    pub mapped_bytes: u64,
    pub virtual_span: u64,
}

pub struct Snapshot {
    bytes: Vec<u8>,
    identity: ContentId,
    symbols: Symbols,
    loads: Vec<VirtualRange>,
}
impl Snapshot {
    /// Bounded file capture, not proof of a fresh compiler build or immutable
    /// external inode. The caller separately owns that build/file provenance.
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        // Refuse a symlink at the final path component, and do not block opening
        // a FIFO before the descriptor's regular-file check. No stat/open race.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(Error::Format("regular input file"));
        }
        if metadata.len() > BYTE_LIMIT {
            return Err(Error::Limit("input file bytes"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(metadata.len() as usize)
            .map_err(|_| Error::Allocation)?;
        file.take(BYTE_LIMIT + 1).read_to_end(&mut bytes)?;
        Self::parse(bytes)
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() as u64 > BYTE_LIMIT {
            return Err(Error::Limit("input file bytes"));
        }
        let elf = parse_elf(&bytes)?;
        if elf.header().object_type != ObjectType::Dynamic || elf.header().entry.0 != 0 {
            return Err(Error::Format("ET_DYN with zero entry"));
        }
        elf.check_load_page_congruence(PAGE)?;
        let sections = sections(&elf)?;
        let (regular, dynamic) = symbol_tables(&bytes, &sections)?;
        let symbols = required(&elf, &sections, &regular, &dynamic)?;
        dynamic_symbols(&elf, &sections)?;
        let loads = load_ranges(&elf)?;
        Ok(Self {
            identity: ContentId::of(&bytes),
            bytes,
            symbols,
            loads,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub const fn identity(&self) -> ContentId {
        self.identity
    }
    pub fn elf(&self) -> Result<Elf64<'_>> {
        parse_elf(&self.bytes)
    }
    pub const fn symbols(&self) -> &Symbols {
        &self.symbols
    }
    pub fn occupied_loads(&self) -> &[VirtualRange] {
        &self.loads
    }

    /// A required function's full bytes. NOTYPE markers are coordinates only.
    pub fn code(&self, symbol: &Symbol) -> Result<Code<'_>> {
        let expected = self
            .required_symbol(symbol.name)
            .ok_or(Error::Symbol("foreign symbol"))?;
        if expected != symbol || symbol.size == 0 {
            return Err(Error::Symbol("function identity/size"));
        }
        owned_code(&self.elf()?, symbol.address, symbol.size)
    }

    /// Byte copies only; exact-point recovery semantics are independently owed.
    pub fn source_record(&self, point: u64) -> Result<OriginalArtifactCfi> {
        let elf = self.elf()?;
        Ok(
            OriginalIndex::inspect(&elf, IndexLimits::default(), dynamic::Limits::default())?
                .source_record(point)?,
        )
    }

    /// A separately selected fixture function, including a static collector
    /// helper. Its bytes and linkage are authenticated; semantics are not.
    pub fn named_function(&self, name: &'static str, exported: bool) -> Result<Symbol> {
        let input = self.elf()?;
        let sections = sections(&input)?;
        let (regular, dynamic) = symbol_tables(&self.bytes, &sections)?;
        required_symbol(&input, &sections, &regular, &dynamic, name, true, exported)
    }

    pub fn original_metadata(&self) -> Result<(u64, &[u8])> {
        original_metadata(&self.bytes)
    }

    /// Bind the collector's direct CALL to the actual standard GNU PLT entry
    /// and its exact `_Unwind_Backtrace` relocation. Runtime resolution of the
    /// returned GOT coordinate must still equal the qualified consumer address.
    pub fn backtrace_plt(&self) -> Result<(u64, u64)> {
        let input = self.elf()?;
        let sections = sections(&input)?;
        let (_, dynamic_symbols) = symbol_tables(&self.bytes, &sections)?;
        let mut named = dynamic_symbols
            .iter()
            .enumerate()
            .filter(|(_, s)| s.name == b"_Unwind_Backtrace");
        let (symbol_index, symbol) = named.next().ok_or(Error::Missing("_Unwind_Backtrace"))?;
        if named.next().is_some()
            || symbol.section != 0
            || symbol.binding != 1
            || symbol.visibility != 0
            || !matches!(symbol.kind, 0 | 2)
        {
            return Err(Error::Symbol("_Unwind_Backtrace"));
        }
        let inventory = dynamic::inspect(&input, dynamic::Limits::default())?;
        let mut slots = inventory.writes.iter().filter(|r| {
            r.symbol as usize == symbol_index
                && r.table == dynamic::TableKind::JumpRela
                && r.kind == 7
                && r.range.len() == 8
        });
        let slot = slots.next().ok_or(Error::Missing("Backtrace JUMP_SLOT"))?;
        if slots.next().is_some() {
            return Err(Error::Duplicate("Backtrace JUMP_SLOT"));
        }
        let got = slot.range.start().0;
        let mut plts = sections.iter().filter(|s| s.name == b".plt");
        let plt = plts.next().ok_or(Error::Missing(".plt"))?;
        if plts.next().is_some()
            || plt.kind != 1
            || plt.flags != 6
            || plt.size < 32
            || plt.size % 16 != 0
        {
            return Err(Error::Format("GNU PLT extent"));
        }
        let code = owned_code(&input, plt.address, plt.size)?;
        if code.file.start().0 != plt.offset {
            return Err(Error::Ownership);
        }
        let mut found = None;
        for (i, bytes) in code.bytes.chunks_exact(16).enumerate().skip(1) {
            if bytes[..2] != [0xff, 0x25] {
                return Err(Error::Format("GNU PLT indirect JMP"));
            }
            let address = add(plt.address, i as u64 * 16)?;
            let displacement = i32::from_le_bytes(bytes[2..6].try_into().unwrap());
            let resolved = i128::from(add(address, 6)?) + i128::from(displacement);
            if resolved == i128::from(got) && found.replace(address).is_some() {
                return Err(Error::Duplicate("Backtrace PLT entry"));
            }
        }
        Ok((found.ok_or(Error::Missing("Backtrace PLT entry"))?, got))
    }

    /// `carrier_bytes` includes its complete relocated program-header table,
    /// payload and CFI/index. These are reservations, not permission to overrun.
    /// Independent file, summed mapped-byte and span limits all remain 16 MiB.
    pub fn placements(&self, carrier_bytes: u64, image_bytes: u64) -> Result<Placements> {
        if carrier_bytes == 0 || image_bytes == 0 {
            return Err(Error::Format("nonempty new LOADs"));
        }
        let carrier_bytes = align(carrier_bytes)?;
        let image_bytes = align(image_bytes)?;
        let begin = self.loads.last().ok_or(Error::Ownership)?.end().0;
        let middle = add(begin, carrier_bytes)?;
        let end = add(middle, image_bytes)?;
        let mapped = self
            .loads
            .iter()
            .try_fold(0_u64, |sum, range| add(sum, range.len()))?;
        let mapped_bytes = add(add(mapped, carrier_bytes)?, image_bytes)?;
        let virtual_span = end - self.loads.first().ok_or(Error::Ownership)?.start().0;
        let output_file_upper_bound = add(
            add(align(self.bytes.len() as u64)?, carrier_bytes)?,
            image_bytes,
        )?;
        if mapped_bytes > BYTE_LIMIT {
            return Err(Error::Limit("complete mapped bytes"));
        }
        if virtual_span > BYTE_LIMIT {
            return Err(Error::Limit("complete virtual span"));
        }
        if output_file_upper_bound > BYTE_LIMIT {
            return Err(Error::Limit("complete file bytes"));
        }
        Ok(Placements {
            carrier: VirtualRange::checked(ElfVaddr(begin), carrier_bytes)?,
            image: VirtualRange::checked(ElfVaddr(middle), image_bytes)?,
            output_file_upper_bound,
            mapped_bytes,
            virtual_span,
        })
    }

    fn required_symbol(&self, name: &str) -> Option<&Symbol> {
        let s = &self.symbols;
        [
            &s.work,
            &s.selected,
            &s.continuation,
            &s.hook,
            &s.reference,
            &s.collect_original,
            &s.configure,
            &s.capture_status,
            &s.capture_end,
            &s.consumer_addresses,
            &s.find_fde,
        ]
        .into_iter()
        .find(|symbol| symbol.name == name)
    }
}

/// Unique immutable original .eh_frame bytes for exact CIE/FDE joins. This
/// proves storage coordinates, not the recovery semantics of its programs.
pub fn original_metadata(bytes: &[u8]) -> Result<(u64, &[u8])> {
    let input = parse_elf(bytes)?;
    let sections = sections(&input)?;
    let mut matches = sections.iter().filter(|s| s.name == b".eh_frame");
    let s = matches.next().ok_or(Error::Missing(".eh_frame"))?;
    if matches.next().is_some() {
        return Err(Error::Duplicate(".eh_frame"));
    }
    if s.kind != 1 || s.flags != 2 || s.size == 0 {
        return Err(Error::Format("original .eh_frame storage"));
    }
    let owner = input.virtual_to_storage(ElfVaddr(s.address), s.size)?;
    let inverse = input.file_to_virtual(elf64::FileOffset(s.offset), s.size)?;
    let expected = FileRange::checked(elf64::FileOffset(s.offset), s.size)?;
    if owner.flags.0 != 4
        || owner.storage != Storage::FileBacked(expected)
        || inverse.program_header != owner.program_header
        || inverse.virtual_range.start().0 != s.address
    {
        return Err(Error::Ownership);
    }
    Ok((s.address, slice(bytes, s.offset, s.size)?))
}

#[path = "caller_image.rs"]
pub mod caller_image;

fn load_ranges(elf: &Elf64<'_>) -> Result<Vec<VirtualRange>> {
    let mut loads = Vec::new();
    let mut mapped = 0_u64;
    for segment in elf
        .segments(SegmentType::Load)
        .filter(|segment| segment.memory_size != 0)
    {
        let begin = segment.vaddr.0 & !(PAGE - 1);
        let end = align(add(segment.vaddr.0, segment.memory_size)?)?;
        if loads
            .last()
            .is_some_and(|old: &VirtualRange| old.end().0 > begin)
        {
            return Err(Error::Format("overlapping original LOAD pages"));
        }
        mapped = add(mapped, end - begin)?;
        if mapped > BYTE_LIMIT {
            return Err(Error::Limit("original mapped bytes"));
        }
        loads.try_reserve(1).map_err(|_| Error::Allocation)?;
        loads.push(VirtualRange::checked(ElfVaddr(begin), end - begin)?);
    }
    let first = loads
        .first()
        .ok_or(Error::Format("nonempty original LOADs"))?;
    if loads.last().unwrap().end().0 - first.start().0 > BYTE_LIMIT {
        return Err(Error::Limit("original virtual span"));
    }
    Ok(loads)
}

fn parse_elf(bytes: &[u8]) -> Result<Elf64<'_>> {
    Ok(Elf64::parse(
        bytes,
        ParseLimits {
            max_program_headers: PROGRAM_LIMIT,
        },
    )?)
}
pub(super) fn owned_code<'a>(elf: &Elf64<'a>, address: u64, size: u64) -> Result<Code<'a>> {
    let mapping = elf.virtual_to_storage(ElfVaddr(address), size)?;
    let Storage::FileBacked(file) = mapping.storage else {
        return Err(Error::Ownership);
    };
    let reverse = elf.file_to_virtual(file.start(), file.len())?;
    if !mapping.flags.readable()
        || !mapping.flags.executable()
        || mapping.flags.writable()
        || reverse.program_header != mapping.program_header
        || reverse.virtual_range != mapping.virtual_range
    {
        return Err(Error::Ownership);
    }
    Ok(Code {
        bytes: elf.executable_bytes(ElfVaddr(address), size)?,
        file,
        program_header: mapping.program_header,
    })
}

/// Join the section inventory to the loader's actual dynamic table. This does
/// not prove runtime name resolution, symbol-version selection or interposition.
fn dynamic_symbols(elf: &Elf64<'_>, sections: &[Section<'_>]) -> Result<()> {
    let mut segments = elf.segments(SegmentType::Dynamic);
    let segment = segments.next().ok_or(Error::Missing("PT_DYNAMIC"))?;
    if segments.next().is_some() {
        return Err(Error::Duplicate("PT_DYNAMIC"));
    }
    if segment.file_size == 0
        || segment.file_size % 16 != 0
        || segment.file_size > segment.memory_size
    {
        return Err(Error::Format("PT_DYNAMIC extent"));
    }
    if segment.file_size / 16 > 4096 {
        return Err(Error::Limit("dynamic entries"));
    }
    let table = owned_metadata(elf, segment.vaddr.0, segment.file_size)?;
    if table != segment.file_range()? {
        return Err(Error::Ownership);
    }
    let bytes = slice(elf.bytes(), table.start().0, table.len())?;
    let mut values = [None; 4];
    let mut terminated = false;
    for row in bytes.chunks_exact(16) {
        let tag = u64_at(row, 0)?;
        if tag == 0 {
            terminated = true;
            break;
        }
        if let Some(index) = [6, 5, 11, 10].iter().position(|required| *required == tag) {
            if values[index].replace(u64_at(row, 8)?).is_some() {
                return Err(Error::Duplicate("dynamic symbol/string tag"));
            }
        }
    }
    if !terminated {
        return Err(Error::Format("dynamic terminator"));
    }
    let mut symbols = sections.iter().filter(|section| section.kind == 11);
    let symbols = symbols.next().ok_or(Error::Missing("SHT_DYNSYM"))?;
    let strings = sections
        .get(symbols.link)
        .ok_or(Error::Format("dynamic STRTAB link"))?;
    if values
        != [
            Some(symbols.address),
            Some(strings.address),
            Some(24),
            Some(strings.size),
        ]
        || symbols.entry_size != 24
        || symbols.flags & 2 == 0
        || strings.flags & 2 == 0
    {
        return Err(Error::Format("PT_DYNAMIC symbol/string section join"));
    }
    let symbol_file = owned_metadata(elf, symbols.address, symbols.size)?;
    let string_file = owned_metadata(elf, strings.address, strings.size)?;
    if symbol_file.start().0 != symbols.offset
        || symbol_file.len() != symbols.size
        || string_file.start().0 != strings.offset
        || string_file.len() != strings.size
    {
        return Err(Error::Ownership);
    }
    let dependencies = [
        (table, segment.vaddr.0),
        (symbol_file, symbols.address),
        (string_file, strings.address),
    ];
    for (i, (file, _)) in dependencies.iter().enumerate() {
        if dependencies[..i]
            .iter()
            .any(|(other, _)| intersects(*file, *other))
        {
            return Err(Error::Ownership);
        }
    }
    // Reuse complete bounded hash/version/relocation ownership validation; the
    // section join above does not replace this or invent loader lookup proof.
    let inventory = dynamic::inspect(
        elf,
        dynamic::Limits {
            dynamic_entries: 4096,
            relocation_records: SYMBOL_LIMIT,
            relocation_writes: SYMBOL_LIMIT,
            metadata_records: SYMBOL_LIMIT,
            metadata_bytes: BYTE_LIMIT as usize,
        },
    )?;
    let extent = inventory
        .symbol_extent
        .ok_or(Error::Missing("dynamic symbol extent"))?;
    if !extent.hash_authoritative
        || extent.count != symbols.size / 24
        || extent.file != symbol_file
        || extent.virtual_range.start().0 != symbols.address
        || extent.virtual_range.len() != symbols.size
    {
        return Err(Error::Format("hash-authoritative symbol extent"));
    }
    for (file, address) in dependencies {
        let end = add(address, file.len())?;
        if inventory.writes.iter().any(|write| {
            (write.range.start().0 < end && address < write.range.end().0)
                || write.file.is_some_and(|other| intersects(file, other))
        }) {
            return Err(Error::Ownership);
        }
    }
    Ok(())
}

fn owned_metadata(elf: &Elf64<'_>, address: u64, size: u64) -> Result<FileRange> {
    let mapping = elf.virtual_to_storage(ElfVaddr(address), size)?;
    let Storage::FileBacked(file) = mapping.storage else {
        return Err(Error::Ownership);
    };
    let reverse = elf.file_to_virtual(file.start(), file.len())?;
    if !mapping.flags.readable()
        || mapping.flags.executable()
        || reverse.program_header != mapping.program_header
        || reverse.virtual_range != mapping.virtual_range
    {
        return Err(Error::Ownership);
    }
    Ok(file)
}
fn intersects(a: FileRange, b: FileRange) -> bool {
    a.start() < b.end() && b.start() < a.end()
}

#[derive(Clone)]
struct Section<'a> {
    name: &'a [u8],
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: usize,
    info: usize,
    entry_size: u64,
}
fn sections<'a>(elf: &Elf64<'a>) -> Result<Vec<Section<'a>>> {
    let h = elf.header();
    let count = usize::from(h.section_count);
    if count > SECTION_LIMIT {
        return Err(Error::Limit("section count"));
    }
    if count == 0
        || h.section_entry_size != 64
        || h.section_name_index == 0
        || usize::from(h.section_name_index) >= count
        || h.section_offset.0 < 64
    {
        return Err(Error::Format("section table"));
    }
    let bytes = slice(elf.bytes(), h.section_offset.0, (count as u64) * 64)?;
    if bytes[..64].iter().any(|byte| *byte != 0) {
        return Err(Error::Format("null section"));
    }
    let names_header = &bytes[usize::from(h.section_name_index) * 64..][..64];
    if u32_at(names_header, 4)? != 3 {
        return Err(Error::Format("section-name STRTAB"));
    }
    let names = string_table(
        elf.bytes(),
        u64_at(names_header, 24)?,
        u64_at(names_header, 32)?,
    )?;
    let mut sections = Vec::new();
    sections
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    for (index, raw) in bytes.chunks_exact(64).enumerate() {
        let kind = u32_at(raw, 4)?;
        let offset = u64_at(raw, 24)?;
        let size = u64_at(raw, 32)?;
        let address = u64_at(raw, 16)?;
        let alignment = u64_at(raw, 48)?;
        if alignment > 1 && !alignment.is_power_of_two() {
            return Err(Error::Format("section alignment"));
        }
        add(address, size)?;
        if kind != 8 {
            slice(elf.bytes(), offset, size)?;
        }
        if index != 0 && kind == 0 {
            return Err(Error::Format("additional null section"));
        }
        sections.push(Section {
            name: string(names, u32_at(raw, 0)? as usize)?,
            kind,
            flags: u64_at(raw, 8)?,
            address,
            offset,
            size,
            link: u32_at(raw, 40)? as usize,
            info: u32_at(raw, 44)? as usize,
            entry_size: u64_at(raw, 56)?,
        });
    }
    Ok(sections)
}

#[derive(Clone, Copy)]
struct RawSymbol<'a> {
    name: &'a [u8],
    address: u64,
    size: u64,
    section: usize,
    binding: u8,
    kind: u8,
    visibility: u8,
}
type SymbolTables<'a> = (Vec<RawSymbol<'a>>, Vec<RawSymbol<'a>>);
fn symbol_tables<'a>(bytes: &'a [u8], sections: &[Section<'a>]) -> Result<SymbolTables<'a>> {
    let mut regular = None;
    let mut dynamic = None;
    let mut total = 0_usize;
    for table in sections
        .iter()
        .filter(|section| section.kind == 2 || section.kind == 11)
    {
        let regular_table = table.kind == 2;
        let expected = if regular_table {
            b".symtab".as_slice()
        } else {
            b".dynsym".as_slice()
        };
        if table.name != expected
            || table.entry_size != 24
            || table.size == 0
            || table.size % 24 != 0
        {
            return Err(Error::Format("symbol table shape/name"));
        }
        let count = usize::try_from(table.size / 24).map_err(|_| Error::Arithmetic)?;
        total = total.checked_add(count).ok_or(Error::Arithmetic)?;
        if total > SYMBOL_LIMIT {
            return Err(Error::Limit("total symbol rows"));
        }
        if table.info == 0 || table.info > count {
            return Err(Error::Format("symbol local boundary"));
        }
        let strings = sections
            .get(table.link)
            .ok_or(Error::Format("symbol string link"))?;
        let expected = if regular_table {
            b".strtab".as_slice()
        } else {
            b".dynstr".as_slice()
        };
        if strings.kind != 3 || strings.name != expected {
            return Err(Error::Format("symbol STRTAB"));
        }
        let names = string_table(bytes, strings.offset, strings.size)?;
        let raw = slice(bytes, table.offset, table.size)?;
        if raw[..24].iter().any(|byte| *byte != 0) {
            return Err(Error::Format("null symbol"));
        }
        let mut symbols = Vec::new();
        symbols
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        for (index, row) in raw.chunks_exact(24).enumerate() {
            let symbol = RawSymbol {
                name: string(names, u32_at(row, 0)? as usize)?,
                binding: row[4] >> 4,
                kind: row[4] & 15,
                visibility: row[5],
                section: u16::from_le_bytes([row[6], row[7]]) as usize,
                address: u64_at(row, 8)?,
                size: u64_at(row, 16)?,
            };
            if (symbol.binding == 0) != (index < table.info) || symbol.visibility > 3 {
                return Err(Error::Format("symbol binding/visibility"));
            }
            let end = add(symbol.address, symbol.size)?;
            match symbol.section {
                0 | 0xfff1 => (), // Undefined/absolute rows grant no code owner.
                section if section >= 0xff00 => {
                    return Err(Error::Format("reserved symbol section"));
                }
                section => {
                    let owner = sections
                        .get(section)
                        .ok_or(Error::Format("defined symbol section"))?;
                    if symbol.address < owner.address || end > add(owner.address, owner.size)? {
                        return Err(Error::Format("defined symbol extent"));
                    }
                }
            }
            symbols.push(symbol);
        }
        let slot = if regular_table {
            &mut regular
        } else {
            &mut dynamic
        };
        if slot.replace(symbols).is_some() {
            return Err(Error::Duplicate("symbol inventory"));
        }
    }
    Ok((
        regular.ok_or(Error::Missing("SHT_SYMTAB"))?,
        dynamic.ok_or(Error::Missing("SHT_DYNSYM"))?,
    ))
}

fn required_symbol(
    elf: &Elf64<'_>,
    sections: &[Section<'_>],
    regular: &[RawSymbol<'_>],
    dynamic: &[RawSymbol<'_>],
    name: &'static str,
    function: bool,
    exported: bool,
) -> Result<Symbol> {
    let mut found = regular
        .iter()
        .filter(|symbol| symbol.name == name.as_bytes());
    let symbol = found.next().ok_or(Error::Missing(name))?;
    if found.next().is_some() {
        return Err(Error::Duplicate(name));
    }
    if symbol.section == 0
        || symbol.section >= sections.len()
        || symbol.kind != if function { 2 } else { 0 }
        || (function && symbol.size == 0)
        || (!function && symbol.size != 0)
    {
        return Err(Error::Symbol(name));
    }
    let section = &sections[symbol.section];
    if section.kind != 1 || section.flags & 7 != 6 {
        return Err(Error::Symbol(name));
    }
    let mut named = dynamic.iter().filter(|row| row.name == name.as_bytes());
    let linkage = if exported {
        let other = named.next().ok_or(Error::Missing(name))?;
        if named.next().is_some()
            || symbol.binding != 1
            || symbol.visibility != 0
            || other.binding != 1
            || other.visibility != 0
            || other.kind != symbol.kind
            || (other.section, other.address, other.size)
                != (symbol.section, symbol.address, symbol.size)
        {
            return Err(Error::Symbol(name));
        }
        Linkage::Exported
    } else {
        if named.any(|row| row.section != 0) {
            return Err(Error::Symbol(name));
        }
        if symbol.visibility == 2 && symbol.binding <= 1 {
            Linkage::Hidden
        } else if symbol.binding == 0 && symbol.visibility == 0 {
            Linkage::Localized
        } else {
            return Err(Error::Symbol(name));
        }
    };
    let length = if function { symbol.size } else { 1 };
    if symbol.address == add(section.address, section.size)? {
        return Err(Error::Symbol(name));
    }
    let code = owned_code(elf, symbol.address, length)?;
    if code.file.start().0 != add(section.offset, symbol.address - section.address)? {
        return Err(Error::Ownership);
    }
    Ok(Symbol {
        name,
        address: symbol.address,
        size: symbol.size,
        section: symbol.section,
        binding: symbol.binding,
        visibility: symbol.visibility,
        linkage,
    })
}

fn required(
    elf: &Elf64<'_>,
    sections: &[Section<'_>],
    regular: &[RawSymbol<'_>],
    dynamic: &[RawSymbol<'_>],
) -> Result<Symbols> {
    let get = |name, function, exported| {
        required_symbol(elf, sections, regular, dynamic, name, function, exported)
    };
    let symbols = Symbols {
        work: get("li2_uw_work", true, true)?,
        selected: get("li2_uw_selected", false, false)?,
        continuation: get("li2_uw_continuation", false, false)?,
        hook: get("li2_uw_hook", true, false)?,
        reference: get("li2_uw_reference", true, true)?,
        collect_original: get("li2_uw_collect_original", true, false)?,
        configure: get("li2_uw_configure", true, true)?,
        capture_status: get("li2_uw_capture_status", true, true)?,
        capture_end: get("li2_uw_capture_end", true, true)?,
        consumer_addresses: get("li2_uw_consumer_addresses", true, true)?,
        find_fde: get("li2_uw_find_fde", true, true)?,
    };
    let end = add(symbols.work.address, symbols.work.size)?;
    if symbols.selected.section != symbols.work.section
        || symbols.continuation.section != symbols.work.section
        || symbols.selected.address < symbols.work.address
        || symbols.continuation.address >= end
        || add(symbols.selected.address, 5)? != symbols.continuation.address
    {
        return Err(Error::Symbol("selected/continuation extent"));
    }
    // Distinct required function names cannot alias/overlap one another.
    let mut functions = [
        symbols.work,
        symbols.hook,
        symbols.reference,
        symbols.collect_original,
        symbols.configure,
        symbols.capture_status,
        symbols.capture_end,
        symbols.consumer_addresses,
        symbols.find_fde,
    ];
    functions.sort_by_key(|symbol| symbol.address);
    for pair in functions.windows(2) {
        if add(pair[0].address, pair[0].size)? > pair[1].address {
            return Err(Error::Symbol("overlapping required functions"));
        }
    }
    Ok(symbols)
}

fn slice(bytes: &[u8], start: u64, length: u64) -> Result<&[u8]> {
    let end = usize::try_from(add(start, length)?).map_err(|_| Error::Arithmetic)?;
    let start = usize::try_from(start).map_err(|_| Error::Arithmetic)?;
    bytes.get(start..end).ok_or(Error::Format("file extent"))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        slice(bytes, at as u64, 4)?.try_into().unwrap(),
    ))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        slice(bytes, at as u64, 8)?.try_into().unwrap(),
    ))
}
fn string_table(bytes: &[u8], at: u64, size: u64) -> Result<&[u8]> {
    let table = slice(bytes, at, size)?;
    if table.first() != Some(&0) || table.last() != Some(&0) {
        return Err(Error::Format("terminated string table"));
    }
    Ok(table)
}
fn string(table: &[u8], offset: usize) -> Result<&[u8]> {
    let suffix = table.get(offset..).ok_or(Error::Format("string offset"))?;
    let end = suffix
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Format("string terminator"))?;
    Ok(&suffix[..end])
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(Error::Arithmetic)
}
fn align(value: u64) -> Result<u64> {
    Ok(add(value, PAGE - 1)? & !(PAGE - 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SH: usize = 0x2000;
    const SYM: usize = 0x2200;
    const STR: usize = 0x2400;
    const DYNAMIC: usize = 0x400;
    const DYN: usize = 0x600;
    const DSTR: usize = 0x800;
    const HASH: usize = 0xa00;
    const SHSTR: usize = 0x2a00;
    const NAMES: [&str; 11] = [
        "li2_uw_work",
        "li2_uw_selected",
        "li2_uw_continuation",
        "li2_uw_hook",
        "li2_uw_reference",
        "li2_uw_collect_original",
        "li2_uw_configure",
        "li2_uw_capture_status",
        "li2_uw_capture_end",
        "li2_uw_consumer_addresses",
        "li2_uw_find_fde",
    ];
    fn w16(b: &mut [u8], at: usize, n: u16) {
        b[at..at + 2].copy_from_slice(&n.to_le_bytes());
    }
    fn w32(b: &mut [u8], at: usize, n: u32) {
        b[at..at + 4].copy_from_slice(&n.to_le_bytes());
    }
    fn w64(b: &mut [u8], at: usize, n: u64) {
        b[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    fn fixture(localized: bool) -> Vec<u8> {
        let mut b = vec![0; 0x3000];
        b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        w16(&mut b, 16, 3);
        w16(&mut b, 18, 62);
        w32(&mut b, 20, 1);
        w64(&mut b, 32, 64);
        w64(&mut b, 40, SH as u64);
        for (at, n) in [(52, 64), (54, 56), (56, 3), (58, 64), (60, 7), (62, 6)] {
            w16(&mut b, at, n);
        }
        for (i, offset, flags) in [(0, 0, 4), (1, 4096, 5)] {
            let at = 64 + i * 56;
            w32(&mut b, at, 1);
            w32(&mut b, at + 4, flags);
            w64(&mut b, at + 8, offset);
            w64(&mut b, at + 16, offset);
            w64(&mut b, at + 32, 4096);
            w64(&mut b, at + 40, 4096);
            w64(&mut b, at + 48, 4096);
        }
        let mut names = vec![0];
        let mut offsets = Vec::new();
        for name in NAMES {
            offsets.push(names.len());
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        b[STR..STR + names.len()].copy_from_slice(&names);
        b[DSTR..DSTR + names.len()].copy_from_slice(&names);
        let hidden = |i| matches!(i, 1 | 2 | 3 | 5);
        let mut order: Vec<_> = (0..11).collect();
        if localized {
            order.sort_by_key(|i| !hidden(*i));
        }
        // Actual mapped PT_DYNAMIC plus complete SysV hash inventory. The
        // indexed symbols/strings below are the very same bytes the loader sees.
        let at = 64 + 2 * 56;
        w32(&mut b, at, 2);
        w32(&mut b, at + 4, 4);
        w64(&mut b, at + 8, DYNAMIC as u64);
        w64(&mut b, at + 16, DYNAMIC as u64);
        w64(&mut b, at + 32, 6 * 16);
        w64(&mut b, at + 40, 6 * 16);
        w64(&mut b, at + 48, 8);
        for (i, (tag, value)) in [
            (6, DYN as u64),
            (5, DSTR as u64),
            (11, 24),
            (10, names.len() as u64),
            (4, HASH as u64),
            (0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            w64(&mut b, DYNAMIC + i * 16, tag);
            w64(&mut b, DYNAMIC + i * 16 + 8, value);
        }
        let mut dynamic_count = 1;
        for (row, i) in order.into_iter().enumerate() {
            let at = SYM + (row + 1) * 24;
            let marker = matches!(i, 1 | 2);
            let address = match i {
                0 | 1 => 0x1100,
                2 => 0x1105,
                _ => 0x1100 + i as u64 * 16,
            };
            w32(&mut b, at, offsets[i] as u32);
            b[at + 4] = (if localized && hidden(i) { 0 } else { 16 }) | if marker { 0 } else { 2 };
            b[at + 5] = if hidden(i) && !localized { 2 } else { 0 };
            w16(&mut b, at + 6, 1);
            w64(&mut b, at + 8, address);
            w64(&mut b, at + 16, if marker { 0 } else { 16 });
            if !hidden(i) {
                let row = b[at..at + 24].to_vec();
                b[DYN + dynamic_count * 24..DYN + (dynamic_count + 1) * 24].copy_from_slice(&row);
                dynamic_count += 1;
            }
        }
        w32(&mut b, HASH, 1);
        w32(&mut b, HASH + 4, dynamic_count as u32);
        w32(&mut b, HASH + 8, 1);
        for i in 1..dynamic_count - 1 {
            w32(&mut b, HASH + 12 + i * 4, i as u32 + 1);
        }
        let section_names = b"\0.text\0.symtab\0.strtab\0.dynsym\0.dynstr\0.shstrtab\0";
        b[SHSTR..SHSTR + section_names.len()].copy_from_slice(section_names);
        for (i, name, kind, offset, size, link, info, entry) in [
            (1, 1, 1, 4096, 512, 0, 0, 0),
            (2, 7, 2, SYM, 12 * 24, 3, if localized { 5 } else { 1 }, 24),
            (3, 15, 3, STR, names.len(), 0, 0, 0),
            (4, 23, 11, DYN, dynamic_count * 24, 5, 1, 24),
            (5, 31, 3, DSTR, names.len(), 0, 0, 0),
            (6, 39, 3, SHSTR, section_names.len(), 0, 0, 0),
        ] {
            let at = SH + i * 64;
            w32(&mut b, at, name);
            w32(&mut b, at + 4, kind);
            if i == 1 {
                w64(&mut b, at + 8, 6);
                w64(&mut b, at + 16, 4096);
            }
            if i == 4 || i == 5 {
                w64(&mut b, at + 8, 2);
                w64(&mut b, at + 16, offset as u64);
            }
            w64(&mut b, at + 24, offset as u64);
            w64(&mut b, at + 32, size as u64);
            w32(&mut b, at + 40, link);
            w32(&mut b, at + 44, info);
            w64(&mut b, at + 48, 1);
            w64(&mut b, at + 56, entry);
        }
        b
    }
    fn refusal(bytes: Vec<u8>) -> Error {
        Snapshot::parse(bytes).err().expect("required refusal")
    }

    #[test]
    fn complete_symbol_snapshot_retains_hidden_and_localized_forms_and_exact_owners() {
        for localized in [false, true] {
            let bytes = fixture(localized);
            let identity = ContentId::of(&bytes);
            let snapshot = Snapshot::parse(bytes.clone()).unwrap();
            assert_eq!(snapshot.identity(), identity);
            assert_eq!(snapshot.bytes(), bytes);
            let s = snapshot.symbols();
            assert_eq!(
                (
                    s.work.address,
                    s.work.size,
                    s.selected.address,
                    s.continuation.address
                ),
                (0x1100, 16, 0x1100, 0x1105)
            );
            assert_eq!(
                s.hook.linkage,
                if localized {
                    Linkage::Localized
                } else {
                    Linkage::Hidden
                }
            );
            assert_eq!(s.work.linkage, Linkage::Exported);
            let code = snapshot.code(&s.work).unwrap();
            assert_eq!(
                (code.file.start().0, code.file.len(), code.program_header),
                (0x1100, 16, 1)
            );
            assert_eq!(code.bytes, &bytes[0x1100..0x1110]);
            assert_eq!(snapshot.occupied_loads().len(), 2);
            assert!(matches!(
                snapshot.source_record(s.selected.address),
                Err(Error::Unwind(unwind::Error::UnsupportedHeader))
            ));
        }
    }

    #[test]
    fn required_symbol_type_extent_binding_and_dynamic_identity_are_exact() {
        for case in 0..10 {
            let mut b = fixture(false);
            match case {
                0 => b[SYM + 24 + 4] = 17, // OBJECT is not FUNC.
                1 => w64(&mut b, SYM + 24 + 16, 0),
                2 => w16(&mut b, SYM + 24 + 6, 0),
                3 => b[SYM + 24 + 4] = 34, // WEAK is not the declared export.
                4 => w64(&mut b, DYN + 24 + 8, 0x1101),
                5 => w64(&mut b, SYM + 3 * 24 + 8, 0x1110), // continuation outside function.
                6 => b[SYM + 4 * 24 + 5] = 0, // Global/default hook is exported linkage.
                7 => w64(&mut b, SYM + 4 * 24 + 8, 0x1100), // Distinct function overlaps work.
                8 => {
                    // A second dynamic row cannot share the required name.
                    let name = u32_at(&b, SYM + 24).unwrap();
                    w32(&mut b, DYN + 2 * 24, name);
                }
                _ => {
                    // Hidden hook cannot also have a dynamic definition.
                    let name = u32_at(&b, SYM + 4 * 24).unwrap();
                    w32(&mut b, DYN + 2 * 24, name);
                }
            }
            assert!(matches!(refusal(b), Error::Symbol(_)));
        }
    }

    #[test]
    fn strings_null_rows_and_unique_required_names_are_not_normalized() {
        for case in 0..7 {
            let mut b = fixture(false);
            match case {
                0 => w32(&mut b, SYM + 24, u32::MAX),
                1 => b[STR] = b'x',
                2 => b[STR + NAMES[0].len() + 1] = b'x',
                3 => {
                    let name = u32_at(&b[SYM + 24..], 0).unwrap();
                    w32(&mut b, SYM + 2 * 24, name);
                }
                4 => b[SYM] = 1,
                5 => w32(&mut b, SH + 2 * 64 + 44, 2),
                _ => w32(&mut b, SH + 2 * 64 + 40, 1),
            }
            assert!(matches!(
                refusal(b),
                Error::Format(_) | Error::Missing(_) | Error::Duplicate(_)
            ));
        }
    }

    #[test]
    fn executable_ownership_includes_permissions_section_file_join_and_reverse_aliases() {
        let mut writable = fixture(false);
        w32(&mut writable, 64 + 56 + 4, 7);
        assert_eq!(refusal(writable), Error::Ownership);
        let mut section = fixture(false);
        w64(&mut section, SH + 64 + 24, 4097);
        assert_eq!(refusal(section), Error::Ownership);
        let mut extent = fixture(false);
        w64(&mut extent, SYM + 24 + 16, 0x1000);
        assert_eq!(refusal(extent), Error::Format("defined symbol extent"));
        let mut alias = fixture(false);
        w16(&mut alias, 56, 4);
        let segment = alias[64 + 56..64 + 112].to_vec();
        alias[64 + 168..64 + 224].copy_from_slice(&segment);
        w64(&mut alias, 64 + 168 + 16, 0x5000);
        assert!(matches!(
            refusal(alias),
            Error::Elf(elf64::Error::AmbiguousFile { .. })
        ));
    }

    #[test]
    fn byte_section_symbol_limits_and_unsupported_headers_refuse() {
        assert_eq!(
            refusal(vec![0; BYTE_LIMIT as usize + 1]),
            Error::Limit("input file bytes")
        );
        let mut b = fixture(false);
        w16(&mut b, 60, 4097);
        assert_eq!(refusal(b), Error::Limit("section count"));
        let mut b = fixture(false);
        w64(&mut b, SH + 2 * 64 + 32, (SYMBOL_LIMIT as u64 + 1) * 24);
        b.resize(2 * 1024 * 1024, 0);
        assert_eq!(refusal(b), Error::Limit("total symbol rows"));
        for (at, n) in [(16, 2), (58, 63), (60, 0), (62, 0xffff)] {
            let mut b = fixture(false);
            w16(&mut b, at, n);
            assert!(matches!(refusal(b), Error::Format(_)));
        }
        let mut b = fixture(false);
        w64(&mut b, 24, 0x1100);
        assert_eq!(refusal(b), Error::Format("ET_DYN with zero entry"));
    }

    #[test]
    fn placement_reservations_separate_actual_file_mapped_and_virtual_bounds() {
        let s = Snapshot::parse(fixture(false)).unwrap();
        let p = s.placements(4097, 1).unwrap();
        assert_eq!(
            (
                p.carrier.start().0,
                p.carrier.end().0,
                p.image.start().0,
                p.image.end().0
            ),
            (0x2000, 0x4000, 0x4000, 0x5000)
        );
        assert_eq!(
            (p.mapped_bytes, p.virtual_span, p.output_file_upper_bound),
            (0x5000, 0x5000, 0x6000)
        );
        assert_eq!(s.placements(0, 1), Err(Error::Format("nonempty new LOADs")));
        assert_eq!(s.placements(u64::MAX, 1), Err(Error::Arithmetic));
        let mut b = fixture(false);
        b.resize(BYTE_LIMIT as usize, 0);
        let s = Snapshot::parse(b).unwrap();
        assert_eq!(s.placements(1, 1), Err(Error::Limit("complete file bytes")));
        let mut b = fixture(false);
        w64(&mut b, 64 + 56 + 40, BYTE_LIMIT - PAGE);
        let s = Snapshot::parse(b).unwrap();
        assert_eq!(
            s.placements(1, 1),
            Err(Error::Limit("complete mapped bytes"))
        );
        let mut b = fixture(false);
        let shift = BYTE_LIMIT - 2 * PAGE;
        w64(&mut b, 64 + 56 + 16, 4096 + shift);
        w64(&mut b, SH + 64 + 16, 4096 + shift);
        for (table, count) in [(SYM, 12), (DYN, 8)] {
            for i in 1..count {
                let value = u64_at(&b, table + i * 24 + 8).unwrap();
                w64(&mut b, table + i * 24 + 8, value + shift);
            }
        }
        let s = Snapshot::parse(b).unwrap();
        assert_eq!(
            s.placements(1, 1),
            Err(Error::Limit("complete virtual span"))
        );
    }

    #[test]
    fn caller_cannot_turn_a_foreign_symbol_copy_into_owned_code() {
        let s = Snapshot::parse(fixture(false)).unwrap();
        let mut changed = s.symbols().work;
        changed.size += 1;
        assert!(matches!(
            s.code(&changed),
            Err(Error::Symbol("function identity/size"))
        ));
        assert!(matches!(
            s.code(&s.symbols().selected),
            Err(Error::Symbol("function identity/size"))
        ));
    }

    #[test]
    fn loader_dynamic_table_and_all_four_symbol_tags_must_join_sections() {
        let mut missing = fixture(false);
        w32(&mut missing, 64 + 2 * 56, 0);
        assert_eq!(refusal(missing), Error::Missing("PT_DYNAMIC"));
        let mut duplicate = fixture(false);
        w16(&mut duplicate, 56, 4);
        let header = duplicate[64 + 112..64 + 168].to_vec();
        duplicate[64 + 168..64 + 224].copy_from_slice(&header);
        assert_eq!(refusal(duplicate), Error::Duplicate("PT_DYNAMIC"));
        for (row, value) in [(0, DYN as u64 + 24), (1, DSTR as u64 + 1), (2, 23), (3, 1)] {
            let mut b = fixture(false);
            w64(&mut b, DYNAMIC + row * 16 + 8, value);
            assert_eq!(
                refusal(b),
                Error::Format("PT_DYNAMIC symbol/string section join")
            );
        }
        let mut missing = fixture(false);
        w64(&mut missing, DYNAMIC + 3 * 16, 21);
        assert_eq!(
            refusal(missing),
            Error::Format("PT_DYNAMIC symbol/string section join")
        );
        let mut duplicate = fixture(false);
        w64(&mut duplicate, DYNAMIC + 4 * 16, 11);
        assert_eq!(
            refusal(duplicate),
            Error::Duplicate("dynamic symbol/string tag")
        );
        let mut unterminated = fixture(false);
        w64(&mut unterminated, DYNAMIC + 5 * 16, 21);
        assert_eq!(refusal(unterminated), Error::Format("dynamic terminator"));
        let mut excessive = fixture(false);
        excessive.resize(0x11000, 0);
        w64(&mut excessive, 64 + 2 * 56 + 32, 4097 * 16);
        w64(&mut excessive, 64 + 2 * 56 + 40, 4097 * 16);
        assert_eq!(refusal(excessive), Error::Limit("dynamic entries"));
        let mut bad_hash = fixture(false);
        w32(&mut bad_hash, HASH + 8, 8);
        assert!(matches!(
            refusal(bad_hash),
            Error::Dynamic(dynamic::Error::InvalidMetadata { tag: 4 })
        ));
    }

    #[test]
    fn dynamic_metadata_requires_same_file_owner_and_no_loader_write() {
        let mut wrong_file = fixture(false);
        w64(&mut wrong_file, 64 + 2 * 56 + 8, DYNAMIC as u64 + 1);
        assert_eq!(refusal(wrong_file), Error::Ownership);
        let mut wrong_section = fixture(false);
        w64(&mut wrong_section, SH + 4 * 64 + 16, DYN as u64 + 1);
        w64(&mut wrong_section, DYNAMIC + 8, DYN as u64 + 1);
        assert_eq!(refusal(wrong_section), Error::Ownership);
        let mut alias = fixture(false);
        w16(&mut alias, 56, 4);
        let header = alias[64..64 + 56].to_vec();
        alias[64 + 168..64 + 224].copy_from_slice(&header);
        w64(&mut alias, 64 + 168 + 16, 0x5000);
        assert!(matches!(
            refusal(alias),
            Error::Elf(elf64::Error::AmbiguousFile { .. })
        ));
        for target in [DYNAMIC, DYN, DSTR] {
            let mut b = fixture(false);
            w64(&mut b, 64 + 2 * 56 + 32, 9 * 16);
            w64(&mut b, 64 + 2 * 56 + 40, 9 * 16);
            for (i, (tag, value)) in [(7, 0xb00), (8, 24), (9, 24), (0, 0)]
                .into_iter()
                .enumerate()
            {
                w64(&mut b, DYNAMIC + (5 + i) * 16, tag);
                w64(&mut b, DYNAMIC + (5 + i) * 16 + 8, value);
            }
            w64(&mut b, 0xb00, target as u64);
            w64(&mut b, 0xb08, 8); // R_X86_64_RELATIVE
            assert_eq!(refusal(b), Error::Ownership);
        }
    }

    #[test]
    fn hash_authority_must_cover_the_exact_complete_dynamic_symbol_extent() {
        let complete = fixture(false);
        let elf = parse_elf(&complete).unwrap();
        let extent = dynamic::inspect(&elf, dynamic::Limits::default())
            .unwrap()
            .symbol_extent
            .unwrap();
        assert!(extent.hash_authoritative);
        assert_eq!(
            (
                extent.count,
                extent.file.start().0,
                extent.file.len(),
                extent.virtual_range.start().0,
                extent.virtual_range.len()
            ),
            (8, DYN as u64, 8 * 24, DYN as u64, 8 * 24)
        );
        for (count, hash) in [(1, true), (9, true), (1, false)] {
            let mut bytes = fixture(false);
            if hash {
                w32(&mut bytes, HASH + 4, count);
                if count == 1 {
                    w32(&mut bytes, HASH + 8, 0);
                }
            } else {
                w64(&mut bytes, DYNAMIC + 4 * 16, 21); // DT_DEBUG, no hash count.
            }
            // Existing callers keep the original parser acceptance. Its typed
            // result exposes exactly what was validated, never the section tail.
            let elf = parse_elf(&bytes).unwrap();
            let extent = dynamic::inspect(&elf, dynamic::Limits::default())
                .unwrap()
                .symbol_extent
                .unwrap();
            assert_eq!(
                (extent.count, extent.hash_authoritative),
                (u64::from(count), hash)
            );
            assert_eq!(extent.file.len(), u64::from(count) * 24);
            assert_eq!(
                refusal(bytes),
                Error::Format("hash-authoritative symbol extent")
            );
        }
        // The same typed authority comes from the existing GNU hash scanner,
        // not a second hash parser in this fixture view.
        let mut gnu = fixture(false);
        w64(&mut gnu, DYNAMIC + 4 * 16, 0x6fff_fef5);
        gnu[HASH..HASH + 64].fill(0);
        w32(&mut gnu, HASH, 1);
        w32(&mut gnu, HASH + 4, 1);
        w32(&mut gnu, HASH + 8, 1);
        w32(&mut gnu, HASH + 12, 5);
        w64(&mut gnu, HASH + 16, u64::MAX);
        w32(&mut gnu, HASH + 24, 1);
        w32(&mut gnu, HASH + 28 + 6 * 4, 1);
        let elf = parse_elf(&gnu).unwrap();
        let extent = dynamic::inspect(&elf, dynamic::Limits::default())
            .unwrap()
            .symbol_extent
            .unwrap();
        assert_eq!(
            (extent.count, extent.hash_authoritative, extent.file.len()),
            (8, true, 8 * 24)
        );
        Snapshot::parse(gnu).unwrap();
    }

    #[test]
    fn descriptor_capture_refuses_symlinks_and_nonregular_files() {
        use std::{
            fs,
            sync::atomic::{AtomicU64, Ordering},
        };
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let directory = (0..32)
            .find_map(|_| {
                let path = std::env::temp_dir().join(format!(
                    "li2-indexed-snapshot-{}-{}",
                    std::process::id(),
                    SERIAL.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::create_dir(&path) {
                    Ok(()) => Some(Scratch(path)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => panic!("create owned snapshot fixture: {error}"),
                }
            })
            .expect("bounded unique snapshot fixture directory");
        let regular = directory.0.join("regular.elf");
        let link = directory.0.join("link.elf");
        let bytes = fixture(false);
        fs::write(&regular, &bytes).unwrap();
        assert_eq!(
            Snapshot::read(&regular).unwrap().identity(),
            ContentId::of(&bytes)
        );
        std::os::unix::fs::symlink(&regular, &link).unwrap();
        assert!(matches!(Snapshot::read(&link), Err(Error::Io(_))));
        assert!(matches!(
            Snapshot::read(&directory.0),
            Err(Error::Format("regular input file"))
        ));
    }
}
