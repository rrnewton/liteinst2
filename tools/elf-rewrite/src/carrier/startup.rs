//! Typed main-image startup metadata for separately named static ET_EXEC profiles.
//!
//! Paths come from an independently authenticated package policy. This writer
//! performs no filesystem lookup and does not qualify the interpreter, DSO,
//! dependency graph, constructor ordering, router, or native execution.

use super::elf64::{Elf64, ElfVaddr, FileOffset, FileRange, ObjectType, SegmentType, Storage};
use super::{Error as CarrierError, add, align_up, budget, host_index};

const DYNAMIC_BYTES: u64 = 7 * 16;
const ABSOLUTE_DYNAMIC_BYTES: u64 = 9 * 16;

/// Additional finite bounds; the existing image/layout limits still apply to
/// every added header, carrier page, image, file byte and the complete VA hull.
/// Runtime DSO/dependency resources require their own package budget.
#[derive(Clone, Copy, Debug)]
pub struct StartupLimits {
    /// Includes the final NUL.
    pub max_interpreter_bytes: u64,
    /// Aggregate DT_NEEDED pathname bytes, including each terminating NUL.
    pub max_needed_bytes: u64,
    /// Includes the leading empty string and all terminating pathname NULs.
    pub max_string_table_bytes: u64,
    pub max_dynamic_bytes: u64,
    /// Complete added metadata interval, including internal alignment padding.
    pub max_metadata_bytes: u64,
    pub max_input_sections: usize,
    pub max_input_symbols: usize,
    /// Aggregate original SHT_STRTAB bytes, including the section-name table.
    pub max_input_string_bytes: u64,
}

/// Frozen absolute pathnames for a separately authenticated package. Neither
/// path is searched or opened by the writer. There is exactly one DT_NEEDED.
#[derive(Clone, Copy, Debug)]
pub struct StaticExecStartup<'a> {
    pub interpreter: &'a str,
    pub bootstrap_dso: &'a str,
    pub limits: StartupLimits,
}

/// Separate three-needed class; all three terminated names share the needed budget.
#[derive(Clone, Copy, Debug)]
pub struct StaticExecAbsolutePrerequisites<'a> {
    pub interpreter: &'a str,
    pub libgcc: &'a str,
    pub libc: &'a str,
    pub bootstrap_dso: &'a str,
    pub limits: StartupLimits,
}
#[derive(Clone, Copy)]
pub(super) enum Request<'a> {
    Single(StaticExecStartup<'a>),
    Absolute(StaticExecAbsolutePrerequisites<'a>),
}
impl<'a> Request<'a> {
    fn interpreter(self) -> &'a str {
        match self {
            Self::Single(r) => r.interpreter,
            Self::Absolute(r) => r.interpreter,
        }
    }
    fn limits(self) -> StartupLimits {
        match self {
            Self::Single(r) => r.limits,
            Self::Absolute(r) => r.limits,
        }
    }
    fn needed(self) -> Vec<&'a str> {
        match self {
            Self::Single(r) => vec![r.bootstrap_dso],
            Self::Absolute(r) => vec![r.libgcc, r.libc, r.bootstrap_dso],
        }
    }
    fn strings(self) -> Result<u64, CarrierError> {
        self.needed().into_iter().try_fold(1, |sum, name| {
            add(sum, name.len() as u64 + 1, "startup strings")
        })
    }
    fn dynamic_bytes(self) -> u64 {
        match self {
            Self::Single(_) => DYNAMIC_BYTES,
            Self::Absolute(_) => ABSOLUTE_DYNAMIC_BYTES,
        }
    }
}

/// Exact new main-file metadata. Every range has the same unique R-only carrier
/// owner. The original ELF entry, code addresses and LOAD records are retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupLayout {
    pub metadata: FileRange,
    pub interpreter: FileRange,
    pub string_table: FileRange,
    pub symbol_table: FileRange,
    pub hash_table: FileRange,
    pub dynamic: FileRange,
    pub interpreter_vaddr: ElfVaddr,
    pub dynamic_vaddr: ElfVaddr,
    pub interpreter_index: usize,
    pub dynamic_index: usize,
    /// Existing nonexecutable GNU_STACK, or a synthesized RW, non-X record.
    pub stack_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPath { which: &'static str },
    InvalidAbsolutePrerequisites,
    UnsupportedInputSegment { index: usize, kind: SegmentType },
    InvalidLoadPermissions { index: usize },
    InvalidStack { index: usize },
    MultipleStacks,
    InvalidSection { index: usize },
    UnsupportedSection { index: usize, kind: u32 },
    StartupSection { index: usize },
    InvalidSymbol { section: usize, index: usize },
    ResolverSymbol { section: usize, index: usize },
    StartupSymbol { section: usize, index: usize },
}

pub(super) struct Prepared<'a> {
    pub request: Request<'a>,
    pub original_stack: Option<usize>,
    pub protected: Vec<FileRange>,
}

impl Prepared<'_> {
    pub fn extra_headers(&self) -> usize {
        2 + usize::from(self.original_stack.is_none())
    }
}

pub(super) fn scan_budget(
    prepared: &Prepared<'_>,
    limits: super::dynamic::Limits,
) -> Result<(), CarrierError> {
    budget(
        "startup dynamic entries",
        prepared.request.dynamic_bytes() / 16,
        limits.dynamic_entries as u64,
    )?;
    // The fixed grammar scans one bucket, one chain and one null symbol. Its
    // complete-metadata pass charges the hash header (8), full hash (16),
    // strings, and symbol (24). Check these before allocating output as well
    // as retaining the real dynamic inspector's post-write bounds.
    budget(
        "startup metadata scan records",
        3,
        limits.metadata_records as u64,
    )?;
    let strings = prepared.request.strings()?;
    budget(
        "startup metadata scan bytes",
        add(48, strings, "startup metadata scan")?,
        limits.metadata_bytes as u64,
    )?;
    Ok(())
}

pub(super) fn prepare<'a>(
    input: &Elf64<'_>,
    request: Request<'a>,
) -> Result<Prepared<'a>, CarrierError> {
    if input.header().object_type != ObjectType::Executable {
        return Err(CarrierError::UnsupportedObjectType);
    }
    let limits = request.limits();
    if let Request::Absolute(r) = request {
        if r.libgcc == r.libc
            || r.libgcc == r.bootstrap_dso
            || r.libc == r.bootstrap_dso
            || r.libgcc == r.interpreter
            || r.libc == r.interpreter
            || r.bootstrap_dso == r.interpreter
            || limits.max_dynamic_bytes != ABSOLUTE_DYNAMIC_BYTES
        {
            return Err(Error::InvalidAbsolutePrerequisites.into());
        }
        for value in [r.interpreter, r.libgcc, r.libc, r.bootstrap_dso] {
            if !value.is_ascii()
                || value
                    .bytes()
                    .any(|b| !(0x21..=0x7e).contains(&b) || b == b'$')
                || value
                    .split('/')
                    .skip(1)
                    .any(|p| p.is_empty() || p == "." || p == "..")
            {
                return Err(Error::InvalidPath {
                    which: "absolute prerequisites",
                }
                .into());
            }
        }
        for (required, ceiling) in [
            (limits.max_interpreter_bytes, 4096),
            (limits.max_needed_bytes, 4096),
            (limits.max_string_table_bytes, 4097),
            (limits.max_metadata_bytes, 16384),
            (limits.max_input_sections as u64, 4096),
            (limits.max_input_symbols as u64, 65536),
            (limits.max_input_string_bytes, 1048576),
        ] {
            budget("absolute startup ceiling", required, ceiling)?;
        }
    }
    path(
        request.interpreter(),
        "interpreter",
        limits.max_interpreter_bytes,
    )?;
    let mut needed = 0;
    for name in request.needed() {
        needed = add(
            needed,
            path(name, "needed", limits.max_needed_bytes)?,
            "needed pathname aggregate",
        )?;
    }
    budget("startup needed bytes", needed, limits.max_needed_bytes)?;
    budget(
        "startup string table bytes",
        add(needed, 1, "startup string table")?,
        limits.max_string_table_bytes,
    )?;
    budget(
        "startup dynamic bytes",
        request.dynamic_bytes(),
        limits.max_dynamic_bytes,
    )?;
    let mut original_stack = None;
    for item in input.program_headers() {
        if matches!(
            item.kind,
            SegmentType::Interpreter | SegmentType::Dynamic | SegmentType::Tls
        ) {
            return Err(Error::UnsupportedInputSegment {
                index: item.index,
                kind: item.kind,
            }
            .into());
        }
        if item.kind == SegmentType::Load
            && (!item.flags.readable()
                || item.flags.0 & !7 != 0
                || (item.flags.writable() && item.flags.executable()))
        {
            return Err(Error::InvalidLoadPermissions { index: item.index }.into());
        }
        if item.kind == SegmentType::GnuStack {
            if original_stack.replace(item.index).is_some() {
                return Err(Error::MultipleStacks.into());
            }
            if item.flags.0 != 6 || item.file_size != 0 || item.memory_size != 0 {
                return Err(Error::InvalidStack { index: item.index }.into());
            }
        }
    }
    let protected = sections(input, limits)?;
    Ok(Prepared {
        request,
        original_stack,
        protected,
    })
}

fn path(value: &str, which: &'static str, limit: u64) -> Result<u64, CarrierError> {
    if value.len() < 2 || !value.starts_with('/') || value.as_bytes().contains(&0) {
        return Err(Error::InvalidPath { which }.into());
    }
    let length = add(value.len() as u64, 1, "startup pathname")?;
    budget(
        if which == "interpreter" {
            "startup interpreter bytes"
        } else {
            "startup needed bytes"
        },
        length,
        limit,
    )?;
    Ok(length)
}

pub(super) fn layout(
    start: u64,
    carrier_offset: u64,
    carrier_vaddr: ElfVaddr,
    prepared: &Prepared<'_>,
) -> Result<StartupLayout, CarrierError> {
    let interpreter = FileRange::checked(
        FileOffset(start),
        prepared.request.interpreter().len() as u64 + 1,
    )?;
    let string_table = FileRange::checked(interpreter.end(), prepared.request.strings()?)?;
    let symbol_table = FileRange::checked(FileOffset(align_up(string_table.end().0, 8)?), 24)?;
    let hash_table = FileRange::checked(FileOffset(align_up(symbol_table.end().0, 4)?), 16)?;
    let dynamic = FileRange::checked(
        FileOffset(align_up(hash_table.end().0, 8)?),
        prepared.request.dynamic_bytes(),
    )?;
    let metadata = FileRange::checked(FileOffset(start), dynamic.end().0 - start)?;
    budget(
        "startup metadata bytes",
        metadata.len(),
        prepared.request.limits().max_metadata_bytes,
    )?;
    Ok(StartupLayout {
        metadata,
        interpreter,
        string_table,
        symbol_table,
        hash_table,
        dynamic,
        interpreter_vaddr: address(interpreter, carrier_offset, carrier_vaddr)?,
        dynamic_vaddr: address(dynamic, carrier_offset, carrier_vaddr)?,
        interpreter_index: usize::MAX,
        dynamic_index: usize::MAX,
        stack_index: usize::MAX,
    })
}

fn address(range: FileRange, offset: u64, vaddr: ElfVaddr) -> Result<ElfVaddr, CarrierError> {
    let relative = range
        .start()
        .0
        .checked_sub(offset)
        .ok_or(CarrierError::OutputInvariant)?;
    Ok(ElfVaddr(add(
        vaddr.0,
        relative,
        "startup metadata address",
    )?))
}

pub(super) enum Header {
    Interpreter,
    Dynamic,
    Stack,
}

pub(super) fn header(
    layout: &mut StartupLayout,
    kind: Header,
    index: usize,
) -> super::EncodedHeader {
    let (kind, flags, offset, vaddr, size, alignment) = match kind {
        Header::Interpreter => {
            layout.interpreter_index = index;
            (
                3,
                4,
                layout.interpreter.start().0,
                layout.interpreter_vaddr.0,
                layout.interpreter.len(),
                1,
            )
        }
        Header::Dynamic => {
            layout.dynamic_index = index;
            (
                2,
                4,
                layout.dynamic.start().0,
                layout.dynamic_vaddr.0,
                layout.dynamic.len(),
                8,
            )
        }
        Header::Stack => {
            layout.stack_index = index;
            (0x6474_e551, 6, 0, 0, 0, 16)
        }
    };
    super::EncodedHeader {
        kind,
        flags,
        offset,
        vaddr,
        file_size: size,
        memory_size: size,
        alignment,
    }
}

pub(super) fn render(
    bytes: &mut [u8],
    layout: &StartupLayout,
    prepared: &Prepared<'_>,
    carrier_offset: u64,
    carrier_vaddr: ElfVaddr,
) -> Result<(), CarrierError> {
    let at = host_index(layout.interpreter.start().0)?;
    let path = prepared.request.interpreter().as_bytes();
    bytes[at..at + path.len()].copy_from_slice(path);
    let mut at = host_index(layout.string_table.start().0)? + 1;
    let mut records = Vec::new();
    for path in prepared.request.needed() {
        records.push((
            1_u64,
            (at - host_index(layout.string_table.start().0)?) as u64,
        ));
        bytes[at..at + path.len()].copy_from_slice(path.as_bytes());
        at += path.len() + 1;
    }
    // New backing was zero-initialized. This leaves all terminating NULs, the
    // leading empty string, the complete null symbol and all padding literal.
    let at = host_index(layout.hash_table.start().0)?;
    bytes[at..at + 4].copy_from_slice(&1_u32.to_le_bytes());
    bytes[at + 4..at + 8].copy_from_slice(&1_u32.to_le_bytes());
    // One bucket, one chain, both zero: the main exports no dynamic symbol.
    records.extend([
        (
            5,
            address(layout.string_table, carrier_offset, carrier_vaddr)?.0,
        ),
        (10, layout.string_table.len()),
        (
            6,
            address(layout.symbol_table, carrier_offset, carrier_vaddr)?.0,
        ),
        (11, 24),
        (
            4,
            address(layout.hash_table, carrier_offset, carrier_vaddr)?.0,
        ),
        (0, 0),
    ]);
    let at = host_index(layout.dynamic.start().0)?;
    for (index, (tag, value)) in records.into_iter().enumerate() {
        bytes[at + index * 16..at + index * 16 + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[at + index * 16 + 8..at + index * 16 + 16].copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

/// Reinspect every synthesized metadata owner and the loader-readable dynamic
/// grammar after the final original edits have been applied. No DT_DEBUG slot,
/// relocation, dynamic symbol reference, or main startup function is emitted.
pub(super) fn verify(
    output: &Elf64<'_>,
    layout: &StartupLayout,
    prepared: &Prepared<'_>,
    carrier_index: usize,
    limits: super::dynamic::Limits,
) -> Result<(), CarrierError> {
    for range in [
        layout.metadata,
        layout.interpreter,
        layout.string_table,
        layout.symbol_table,
        layout.hash_table,
        layout.dynamic,
    ] {
        let owner = output.file_to_virtual(range.start(), range.len())?;
        if owner.program_header != carrier_index || owner.flags.0 != 4 {
            return Err(CarrierError::OutputInvariant);
        }
    }
    let interpreter = &output.program_headers()[layout.interpreter_index];
    let dynamic = &output.program_headers()[layout.dynamic_index];
    let stack = &output.program_headers()[layout.stack_index];
    if interpreter.kind != SegmentType::Interpreter
        || interpreter.file_range()? != layout.interpreter
        || interpreter.vaddr != layout.interpreter_vaddr
        || interpreter.flags.0 != 4
        || interpreter.memory_size != interpreter.file_size
        || interpreter.alignment != 1
        || dynamic.kind != SegmentType::Dynamic
        || dynamic.file_range()? != layout.dynamic
        || dynamic.vaddr != layout.dynamic_vaddr
        || dynamic.flags.0 != 4
        || dynamic.memory_size != dynamic.file_size
        || dynamic.alignment != 8
        || stack.kind != SegmentType::GnuStack
        || stack.flags.0 != 6
        || stack.file_size != 0
        || stack.memory_size != 0
    {
        return Err(CarrierError::OutputInvariant);
    }
    let file = |range: FileRange| -> Result<&[u8], CarrierError> {
        output
            .bytes()
            .get(host_index(range.start().0)?..host_index(range.end().0)?)
            .ok_or(CarrierError::OutputInvariant)
    };
    let interpreter_bytes = file(layout.interpreter)?;
    let strings = file(layout.string_table)?;
    let mut expected_strings = vec![0];
    let mut records = Vec::new();
    for name in prepared.request.needed() {
        records.push((1_u64, expected_strings.len() as u64));
        expected_strings.extend_from_slice(name.as_bytes());
        expected_strings.push(0);
    }
    if interpreter_bytes.strip_suffix(&[0]) != Some(prepared.request.interpreter().as_bytes())
        || strings != expected_strings
        || file(layout.symbol_table)? != [0; 24]
        || file(layout.hash_table)? != [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        || output.segments(SegmentType::Interpreter).count() != 1
        || output.segments(SegmentType::Dynamic).count() != 1
        || output.segments(SegmentType::GnuStack).count() != 1
    {
        return Err(CarrierError::OutputInvariant);
    }
    for (start, end) in [
        (layout.string_table.end(), layout.symbol_table.start()),
        (layout.symbol_table.end(), layout.hash_table.start()),
        (layout.hash_table.end(), layout.dynamic.start()),
    ] {
        let length = end
            .0
            .checked_sub(start.0)
            .ok_or(CarrierError::OutputInvariant)?;
        if file(FileRange::checked(start, length)?)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(CarrierError::OutputInvariant);
        }
    }
    let va = |range: FileRange| -> Result<u64, CarrierError> {
        Ok(output
            .file_to_virtual(range.start(), range.len())?
            .virtual_range
            .start()
            .0)
    };
    records.extend([
        (5, va(layout.string_table)?),
        (10, layout.string_table.len()),
        (6, va(layout.symbol_table)?),
        (11, 24),
        (4, va(layout.hash_table)?),
        (0, 0),
    ]);
    let table = file(layout.dynamic)?;
    if table.len() != prepared.request.dynamic_bytes() as usize
        || records.into_iter().enumerate().any(|(index, record)| {
            (u64_at(table, index * 16), u64_at(table, index * 16 + 8)) != record
        })
    {
        return Err(CarrierError::OutputInvariant);
    }
    let inventory = super::dynamic::inspect(output, limits)?;
    if inventory.dynamic_entries != prepared.request.dynamic_bytes() as usize / 16
        || inventory.relocation_records != 0
        || !inventory.writes.is_empty()
        || !inventory.symbol_references.is_empty()
    {
        return Err(CarrierError::OutputInvariant);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Section {
    name: u32,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,
}

fn section(input: &Elf64<'_>, index: usize) -> Result<Section, CarrierError> {
    if index >= usize::from(input.header().section_count) {
        return Err(Error::InvalidSection { index }.into());
    }
    let at = host_index(add(
        input.header().section_offset.0,
        index as u64 * 64,
        "startup section",
    )?)?;
    let b = input
        .bytes()
        .get(at..at + 64)
        .ok_or(Error::InvalidSection { index })?;
    Ok(Section {
        name: u32_at(b, 0),
        kind: u32_at(b, 4),
        flags: u64_at(b, 8),
        address: u64_at(b, 16),
        offset: u64_at(b, 24),
        size: u64_at(b, 32),
        link: u32_at(b, 40),
        info: u32_at(b, 44),
        alignment: u64_at(b, 48),
        entry_size: u64_at(b, 56),
    })
}

fn section_bytes<'a>(
    input: &Elf64<'a>,
    row: Section,
    index: usize,
) -> Result<&'a [u8], CarrierError> {
    let end = add(row.offset, row.size, "startup section file extent")?;
    input
        .bytes()
        .get(host_index(row.offset)?..host_index(end)?)
        .ok_or_else(|| Error::InvalidSection { index }.into())
}

fn string(table: &[u8], offset: u32, index: usize) -> Result<&[u8], CarrierError> {
    let tail = table
        .get(offset as usize..)
        .ok_or(Error::InvalidSection { index })?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::InvalidSection { index })?;
    Ok(&tail[..end])
}

fn startup_section(name: &[u8]) -> bool {
    [
        b".init".as_slice(),
        b".fini",
        b".preinit_array",
        b".init_array",
        b".fini_array",
        b".ctors",
        b".dtors",
    ]
    .iter()
    .any(|prefix| {
        name == *prefix
            || name
                .strip_prefix(*prefix)
                .is_some_and(|suffix| suffix.first() == Some(&b'.'))
    })
}

fn startup_symbol(name: &[u8]) -> bool {
    [
        b"_init".as_slice(),
        b"_fini",
        b"__libc_csu_init",
        b"__libc_csu_fini",
        b"__preinit_array_start",
        b"__preinit_array_end",
        b"__init_array_start",
        b"__init_array_end",
        b"__fini_array_start",
        b"__fini_array_end",
        b"__CTOR_LIST__",
        b"__CTOR_END__",
        b"__DTOR_LIST__",
        b"__DTOR_END__",
    ]
    .contains(&name)
}

fn sections(input: &Elf64<'_>, limits: StartupLimits) -> Result<Vec<FileRange>, CarrierError> {
    let Some(table) = super::section_table(input)? else {
        return Ok(Vec::new());
    };
    let count = usize::from(input.header().section_count);
    budget(
        "startup input sections",
        count as u64,
        limits.max_input_sections as u64,
    )?;
    let mut protected = Vec::new();
    protected
        .try_reserve_exact(count)
        .map_err(|_| CarrierError::Allocation)?;
    let null = &input.bytes()[host_index(table.start().0)?..host_index(table.start().0)? + 64];
    if null.iter().any(|byte| *byte != 0) {
        return Err(Error::InvalidSection { index: 0 }.into());
    }
    let mut string_bytes = 0_u64;
    let mut symbols = 0_u64;
    for index in 1..count {
        let row = section(input, index)?;
        if !matches!(row.kind, 1 | 2 | 3 | 7 | 8) {
            return Err(Error::UnsupportedSection {
                index,
                kind: row.kind,
            }
            .into());
        }
        if row.flags & 0x400 != 0 {
            return Err(Error::StartupSection { index }.into());
        }
        if row.alignment > 1 && !row.alignment.is_power_of_two() {
            return Err(Error::InvalidSection { index }.into());
        }
        add(row.address, row.size, "startup section memory extent")?;
        if row.kind != 8 {
            section_bytes(input, row, index)?;
            if row.size != 0 && row.flags & 4 == 0 {
                protected.push(FileRange::checked(FileOffset(row.offset), row.size)?);
            }
        }
        if row.flags & 2 != 0 && row.size != 0 {
            let owner = input.virtual_to_storage(ElfVaddr(row.address), row.size)?;
            if (row.flags & 1 != 0 && !owner.flags.writable())
                || (row.flags & 4 != 0 && !owner.flags.executable())
                || match owner.storage {
                    Storage::ZeroFill => row.kind != 8,
                    Storage::FileBacked(file) => row.kind == 8 || file.start().0 != row.offset,
                }
            {
                return Err(Error::InvalidSection { index }.into());
            }
        }
        if row.kind == 3 {
            string_bytes = add(string_bytes, row.size, "startup input strings")?;
            budget(
                "startup input string bytes",
                string_bytes,
                limits.max_input_string_bytes,
            )?;
            let bytes = section_bytes(input, row, index)?;
            if bytes.first() != Some(&0) || bytes.last() != Some(&0) || row.flags & 4 != 0 {
                return Err(Error::InvalidSection { index }.into());
            }
        }
        if row.kind == 2 {
            if row.entry_size != 24 || row.size == 0 || row.size % 24 != 0 || row.flags & 4 != 0 {
                return Err(Error::InvalidSection { index }.into());
            }
            symbols = add(symbols, row.size / 24, "startup input symbols")?;
            budget(
                "startup input symbols",
                symbols,
                limits.max_input_symbols as u64,
            )?;
        }
    }
    let names = if input.header().section_name_index == 0 {
        None
    } else {
        let index = usize::from(input.header().section_name_index);
        let row = section(input, index)?;
        if row.kind != 3 {
            return Err(Error::InvalidSection { index }.into());
        }
        Some(section_bytes(input, row, index)?)
    };
    for index in 1..count {
        let row = section(input, index)?;
        if let Some(names) = names {
            if startup_section(string(names, row.name, index)?) {
                return Err(Error::StartupSection { index }.into());
            }
        } else if row.name != 0 {
            return Err(Error::InvalidSection { index }.into());
        }
        if row.kind != 2 {
            continue;
        }
        let strings = section(input, row.link as usize)?;
        if strings.kind != 3 || u64::from(row.info) > row.size / 24 {
            return Err(Error::InvalidSection { index }.into());
        }
        let strings = section_bytes(input, strings, row.link as usize)?;
        let bytes = section_bytes(input, row, index)?;
        for (symbol, record) in bytes.chunks_exact(24).enumerate() {
            let bad = || Error::InvalidSymbol {
                section: index,
                index: symbol,
            };
            if symbol == 0 && record.iter().any(|byte| *byte != 0) {
                return Err(bad().into());
            }
            let section_index = u16::from_le_bytes([record[6], record[7]]);
            if section_index == 0xffff
                || (section_index < 0xff00 && usize::from(section_index) >= count)
            {
                return Err(bad().into());
            }
            if record[4] & 0xf == 10 {
                return Err(Error::ResolverSymbol {
                    section: index,
                    index: symbol,
                }
                .into());
            }
            let name = string(strings, u32_at(record, 0), index)?;
            if startup_symbol(name) {
                return Err(Error::StartupSymbol {
                    section: index,
                    index: symbol,
                }
                .into());
            }
        }
    }
    Ok(protected)
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
