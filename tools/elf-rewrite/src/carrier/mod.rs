//! Private A3 draft: append a read-only carrier and a new program-header table.
//!
//! This is a byte-layout writer, not instruction validation or loader approval.
//! The original freestanding API remains unchanged. The extended private API
//! inventories dynamic writes and adds RX images in one module-relative domain.

pub mod dynamic;
#[path = "elf64.rs"]
pub mod elf64;

use elf64::{Elf64, ElfVaddr, FileOffset, FileRange, ObjectType, ParseLimits, SegmentType};

/// Explicit target and allocation bounds; these are not inferred from this host.
#[derive(Clone, Copy, Debug)]
pub struct CarrierPolicy {
    /// Authenticated target page size, a nonzero power of two.
    pub page_size: u64,
    /// Exclusive bound of the target's permitted lower user-address interval.
    pub user_address_limit: u64,
    /// Maximum increase in file bytes, including append alignment padding.
    pub max_added_file_bytes: u64,
    /// Maximum complete output length before any output allocation occurs.
    pub max_output_file_bytes: u64,
    /// Maximum complete output program-header count.
    pub max_program_headers: usize,
    /// Maximum span from the lowest original load page to the new carrier end.
    pub max_virtual_span: u64,
}

/// PIC image bytes at an exact module-relative entry. No pointer/ABI proof is
/// inferred from this record; a separate emitter must supply that qualification.
#[derive(Clone, Debug)]
pub struct RxImage {
    pub entry: ElfVaddr,
    pub bytes: Vec<u8>,
}

/// Additive image/dynamic profile; original CarrierPolicy literals are unchanged.
#[derive(Clone, Copy, Debug)]
pub struct ImagePolicy {
    pub layout: CarrierPolicy,
    pub dynamic: dynamic::Limits,
    pub max_images: usize,
    pub max_new_load_pages: u64,
}

pub struct ImageRequest<'a> {
    pub carrier_vaddr: ElfVaddr,
    pub payload: &'a [u8],
    pub images: &'a [RxImage],
    /// Complete original-file dependencies of all emitted transformations,
    /// including unchanged successor, padding and relocated source bytes.
    pub source_dependencies: &'a [FileRange],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImagePlacement {
    pub entry: ElfVaddr,
    pub file: FileRange,
    pub program_header: usize,
}

/// An exact same-length original-file edit supplied by a separate semantic planner.
/// This writer authenticates bytes/ownership, not instruction or entry correctness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredEdit {
    /// Original file offset.
    pub offset: FileOffset,
    /// Exact original bytes expected at that offset.
    pub expected: Vec<u8>,
    /// Exact replacement bytes of the same nonzero length.
    pub replacement: Vec<u8>,
}

/// The purpose of an explicitly reported original-file change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    /// ELF e_phoff at file bytes 32..40.
    ProgramHeaderOffset,
    /// ELF e_phnum at file bytes 56..58.
    ProgramHeaderCount,
    /// A separately supplied source edit; semantics are not established here.
    DeclaredSource,
}

/// Every modified original-file interval is represented by exact before/after bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change {
    /// Purpose of the change.
    pub kind: ChangeKind,
    /// Byte-authenticated edit.
    pub edit: DeclaredEdit,
}

/// Successful byte layout, still requiring real loader/architectural qualification.
#[derive(Clone, Debug)]
pub struct CarrierOutput {
    bytes: Vec<u8>,
    changes: Vec<Change>,
    /// The complete appended interval, including zero alignment padding.
    pub appended: FileRange,
    /// Location of the new program-header table in the original-file domain.
    pub program_table: FileRange,
    /// ELF virtual address of that table and new read-only load start.
    pub program_table_vaddr: ElfVaddr,
    /// Appended payload interval, after the new table and 8-byte padding.
    pub payload: FileRange,
    /// Output index of each original record; original relative order is preserved.
    pub original_to_output_header: Vec<usize>,
    /// Output index of the unique PT_PHDR, either inserted or relocated.
    pub phdr_index: usize,
    /// Output index of the newly appended read-only PT_LOAD.
    pub carrier_index: usize,
    /// Exact image extents in caller order, with separate dedicated file backing.
    pub images: Vec<ImagePlacement>,
    /// Exact count of newly mapped pages; alias sharing is not claimed.
    pub new_load_pages: u64,
    /// Original dynamic ownership; never includes new image bytes or mappings.
    pub dynamic: dynamic::Inventory,
}

impl CarrierOutput {
    /// Fully constructed private bytes. No executable output inode has been created.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// All exact modifications to original-file bytes, in increasing offset order.
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }
}

/// Structured layout/profile refusals; none mean that the full A3 task is complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Checked parsing or ownership failed.
    Elf(elf64::Error),
    /// This staged writer does not implement PIE/DSO load-bias qualification.
    UnsupportedObjectType,
    /// Interpreter/dynamic/property qualification is deliberately unimplemented.
    UnsupportedSegment { index: usize, kind: SegmentType },
    /// Original dynamic tables or loader write ownership are not qualified.
    Dynamic(dynamic::Error),
    /// Interpreter record is duplicated, empty, late, or lacks a final path NUL.
    InvalidInterpreter,
    /// Image bytes are empty or image pages overlap original/new mappings.
    InvalidImage { index: usize },
    /// A declared source dependency has no unique executable file owner.
    InvalidDependency { index: usize },
    /// Every changed source interval must also appear in declared dependencies.
    MissingEditDependency { index: usize },
    /// No nonempty load can anchor the original image.
    NoLoadImage,
    /// Caller target limits cannot describe a supported page/address domain.
    InvalidTargetPolicy,
    /// An original or new load page interval exceeds the explicit address limit.
    AddressLimit { index: Option<usize> },
    /// Original load pages overlap; this slice does not reinterpret loader precedence.
    OverlappingLoadPages { before: usize, after: usize },
    /// Requested carrier placement is unaligned, not after all original loads, or overlapping.
    CarrierPlacement,
    /// The new load pages would occupy a declared non-load metadata memory extent.
    CarrierMetadataOverlap { index: usize },
    /// The image header or existing program table is not uniquely mapped readable data.
    HeaderMapping,
    /// Duplicate, late, or inconsistent original PT_PHDR metadata.
    InvalidProgramHeaderMapping,
    /// Section-table metadata is inconsistent or uses unsupported extended counts/indexes.
    UnsupportedSectionLayout,
    /// A configured byte/count/span budget would be exceeded.
    Budget {
        resource: &'static str,
        required: u64,
        limit: u64,
    },
    /// A checked arithmetic operation or host-size conversion failed.
    Arithmetic { operation: &'static str },
    /// The bounded private output allocation could not be reserved.
    Allocation,
    /// A declared source edit is empty or changes length.
    InvalidEditShape { index: usize },
    /// Expected original bytes disagree with the input.
    StaleEdit { index: usize },
    /// Two declared edits overlap, even if their replacement bytes happen to match.
    OverlappingEdits { before: usize, after: usize },
    /// A source edit intersects ELF/header/loader metadata protected by this writer.
    ProtectedMetadata { index: usize },
    /// A source edit is not uniquely owned original executable file data.
    NonExecutableEdit { index: usize },
    /// Internal output checks did not reproduce the declared source transformation.
    OutputInvariant,
}

impl From<elf64::Error> for Error {
    fn from(error: elf64::Error) -> Self {
        Self::Elf(error)
    }
}

impl From<dynamic::Error> for Error {
    fn from(error: dynamic::Error) -> Self {
        Self::Dynamic(error)
    }
}

/// Append payload plus a relocated program table in a new R-only PT_LOAD.
///
/// Input bytes, e_entry, old PT_LOAD records, dynamic hooks and PT_NOTE records
/// are never shifted or stolen. The only original-byte differences are the two
/// declared ELF-header fields and authenticated supplied source edits. Dynamic,
/// interpreter-bearing and GNU-property-bearing images are explicitly refused
/// until those target/profile dependencies have separate qualification.
pub fn append_read_only_carrier(
    input: &Elf64<'_>,
    carrier_vaddr: ElfVaddr,
    payload: &[u8],
    edits: &[DeclaredEdit],
    policy: CarrierPolicy,
) -> Result<CarrierOutput, Error> {
    append_internal(
        input,
        ImageRequest {
            carrier_vaddr,
            payload,
            images: &[],
            source_dependencies: &[],
        },
        edits,
        ImagePolicy {
            layout: policy,
            dynamic: dynamic::Limits::default(),
            max_images: 0,
            max_new_load_pages: u64::MAX,
        },
        false,
    )
}

/// Construct an ET_EXEC/ET_DYN carrier with separately backed immutable RX images.
///
/// This preserves original dynamic/interpreter hooks. It does not prove PIC,
/// hook readiness, CPU/CET compatibility, unwind, or actual loader behavior.
/// All new pages must follow the complete original load-page span. GNU_PROPERTY,
/// text relocations, COPY and unknown relocation formats remain typed refusals.
pub fn append_carrier_with_images(
    input: &Elf64<'_>,
    request: ImageRequest<'_>,
    edits: &[DeclaredEdit],
    policy: ImagePolicy,
) -> Result<CarrierOutput, Error> {
    append_internal(input, request, edits, policy, true)
}

fn append_internal(
    input: &Elf64<'_>,
    request: ImageRequest<'_>,
    edits: &[DeclaredEdit],
    image_policy: ImagePolicy,
    extended: bool,
) -> Result<CarrierOutput, Error> {
    let ImageRequest {
        carrier_vaddr,
        payload,
        images,
        source_dependencies,
    } = request;
    let policy = image_policy.layout;
    if !extended && input.header().object_type != ObjectType::Executable {
        return Err(Error::UnsupportedObjectType);
    }
    if !policy.page_size.is_power_of_two()
        || policy.user_address_limit == 0
        || policy.user_address_limit % policy.page_size != 0
    {
        return Err(Error::InvalidTargetPolicy);
    }
    input.check_load_page_congruence(policy.page_size)?;
    for item in input.program_headers() {
        if item.kind == SegmentType::GnuProperty
            || (!extended && matches!(item.kind, SegmentType::Interpreter | SegmentType::Dynamic))
        {
            return Err(Error::UnsupportedSegment {
                index: item.index,
                kind: item.kind,
            });
        }
    }
    let loads: Vec<_> = input
        .segments(SegmentType::Load)
        .filter(|item| item.memory_size != 0)
        .collect();
    if loads.is_empty() {
        return Err(Error::NoLoadImage);
    }
    let mut lowest_page = u64::MAX;
    let mut last_page_end = 0;
    let mut previous_index = None;
    for item in &loads {
        let start = align_down(item.vaddr.0, policy.page_size);
        let end = align_up(item.memory_range()?.end().0, policy.page_size)?;
        if end > policy.user_address_limit {
            return Err(Error::AddressLimit {
                index: Some(item.index),
            });
        }
        if let Some(before) = previous_index {
            if start < last_page_end {
                return Err(Error::OverlappingLoadPages {
                    before,
                    after: item.index,
                });
            }
        }
        lowest_page = lowest_page.min(start);
        last_page_end = end;
        previous_index = Some(item.index);
    }
    if carrier_vaddr.0 % policy.page_size != 0
        || carrier_vaddr.0 < last_page_end
        || input
            .segments(SegmentType::Load)
            .any(|item| item.vaddr > carrier_vaddr)
    {
        return Err(Error::CarrierPlacement);
    }
    let header_mapping = input.file_to_virtual(FileOffset(0), 64)?;
    if !header_mapping.flags.readable() {
        return Err(Error::HeaderMapping);
    }
    let old_table_len = u64::from(input.header().program_count) * 56;
    let old_table = FileRange::checked(input.header().program_offset, old_table_len)?;
    let old_table_mapping = input.file_to_virtual(old_table.start(), old_table.len())?;
    if !old_table_mapping.flags.readable() {
        return Err(Error::HeaderMapping);
    }
    // This verifies only that the original entry names an executable file byte;
    // it is not a decode, instruction-head, or complete-entry certification.
    if input.header().object_type != ObjectType::Dynamic || input.header().entry.0 != 0 {
        input.executable_bytes(input.header().entry, 1)?;
    }
    let old_phdrs: Vec<_> = input.segments(SegmentType::ProgramHeaders).collect();
    if old_phdrs.len() > 1 {
        return Err(Error::InvalidProgramHeaderMapping);
    }
    let first_load_index = input
        .segments(SegmentType::Load)
        .next()
        .ok_or(Error::NoLoadImage)?
        .index;
    if extended {
        validate_interpreter(input, first_load_index)?;
    }
    let dynamic = if extended {
        dynamic::inspect(input, image_policy.dynamic)?
    } else {
        dynamic::Inventory::default()
    };
    if let Some(item) = old_phdrs.first() {
        if item.index >= first_load_index
            || item.offset != old_table.start()
            || item.vaddr != old_table_mapping.virtual_range.start()
            || item.file_size != old_table.len()
            || item.memory_size != old_table.len()
            || !item.flags.readable()
        {
            return Err(Error::InvalidProgramHeaderMapping);
        }
    }
    let section_table = section_table(input)?;
    let mut protected = vec![FileRange::checked(FileOffset(0), 64)?, old_table];
    if let Some(section_table) = section_table {
        protected.push(section_table);
    }
    for item in input.program_headers() {
        if !matches!(item.kind, SegmentType::Load | SegmentType::Null) && item.file_size != 0 {
            protected.push(item.file_range()?);
        }
    }
    for (index, range) in source_dependencies.iter().enumerate() {
        if range.is_empty() {
            return Err(Error::InvalidDependency { index });
        }
        let mapping = input.file_to_virtual(range.start(), range.len())?;
        if !mapping.flags.executable() || protected.iter().any(|p| intersects(*p, *range)) {
            return Err(Error::InvalidDependency { index });
        }
        input.executable_bytes(mapping.virtual_range.start(), range.len())?;
    }
    dynamic.check_source_ranges(source_dependencies)?;
    let mut ordered: Vec<_> = edits.iter().enumerate().collect();
    ordered.sort_by_key(|(_, edit)| edit.offset);
    let mut preceding: Option<(usize, FileRange)> = None;
    for &(index, edit) in &ordered {
        if edit.expected.is_empty() || edit.expected.len() != edit.replacement.len() {
            return Err(Error::InvalidEditShape { index });
        }
        let range = FileRange::checked(edit.offset, edit.expected.len() as u64)?;
        if extended
            && !source_dependencies.iter().any(|dependency| {
                dependency.start() <= range.start() && dependency.end() >= range.end()
            })
        {
            return Err(Error::MissingEditDependency { index });
        }
        if let Some((before, previous)) = preceding {
            if range.start() < previous.end() {
                return Err(Error::OverlappingEdits {
                    before,
                    after: index,
                });
            }
        }
        preceding = Some((index, range));
        if protected.iter().any(|p| intersects(*p, range)) {
            return Err(Error::ProtectedMetadata { index });
        }
        let start = host_index(range.start().0)?;
        let end = host_index(range.end().0)?;
        if input.bytes().get(start..end) != Some(edit.expected.as_slice()) {
            return Err(Error::StaleEdit { index });
        }
        let mapping = input.file_to_virtual(range.start(), range.len())?;
        if !mapping.flags.executable() {
            return Err(Error::NonExecutableEdit { index });
        }
        input.executable_bytes(mapping.virtual_range.start(), range.len())?;
        dynamic.check_source_ranges(&[range])?;
    }
    let insert_phdr = old_phdrs.is_empty();
    let old_count = input.program_headers().len();
    budget(
        "images",
        images.len() as u64,
        image_policy.max_images as u64,
    )?;
    let new_count = old_count
        .checked_add(1 + usize::from(insert_phdr))
        .and_then(|count| count.checked_add(images.len()))
        .ok_or(Error::Arithmetic {
            operation: "program-header count",
        })?;
    budget(
        "program headers",
        new_count as u64,
        policy.max_program_headers.min(0xfffe) as u64,
    )?;
    let new_table_len = (new_count as u64)
        .checked_mul(56)
        .ok_or(Error::Arithmetic {
            operation: "program-header bytes",
        })?;
    let original_len = input.bytes().len() as u64;
    let carrier_offset = align_up(original_len, policy.page_size)?;
    let table_range = FileRange::checked(FileOffset(carrier_offset), new_table_len)?;
    let payload_offset = align_up(table_range.end().0, 8)?;
    let payload_range = FileRange::checked(FileOffset(payload_offset), payload.len() as u64)?;
    let mut output_len = payload_range.end().0;
    let carrier_size = output_len - carrier_offset;
    let carrier_end = add(carrier_vaddr.0, carrier_size, "carrier virtual extent")?;
    let carrier_page_end = align_up(carrier_end, policy.page_size)?;
    if carrier_page_end > policy.user_address_limit {
        return Err(Error::AddressLimit { index: None });
    }
    let mut added = vec![AddedLoad {
        offset: carrier_offset,
        vaddr: carrier_vaddr.0,
        size: carrier_size,
        page_end: carrier_page_end,
        flags: 4,
        image: None,
    }];
    let mut image_placements = Vec::with_capacity(images.len());
    for (index, image) in images.iter().enumerate() {
        let start = align_down(image.entry.0, policy.page_size);
        if image.bytes.is_empty()
            || start < last_page_end
            || input
                .segments(SegmentType::Load)
                .any(|old| old.vaddr.0 > start)
        {
            return Err(Error::InvalidImage { index });
        }
        let prefix = image.entry.0 - start;
        let size = add(prefix, image.bytes.len() as u64, "image file extent")?;
        let page_end = align_up(add(start, size, "image virtual extent")?, policy.page_size)?;
        if page_end > policy.user_address_limit {
            return Err(Error::AddressLimit { index: None });
        }
        let offset = align_up(output_len, policy.page_size)?;
        let file = FileRange::checked(
            FileOffset(add(offset, prefix, "image file entry")?),
            image.bytes.len() as u64,
        )?;
        output_len = file.end().0;
        image_placements.push(ImagePlacement {
            entry: image.entry,
            file,
            program_header: usize::MAX,
        });
        added.push(AddedLoad {
            offset,
            vaddr: start,
            size,
            page_end,
            flags: 5,
            image: Some(index),
        });
    }
    added.sort_by_key(|load| load.vaddr);
    for pair in added.windows(2) {
        if pair[1].vaddr < pair[0].page_end {
            return Err(Error::InvalidImage {
                index: pair[1]
                    .image
                    .or(pair[0].image)
                    .ok_or(Error::OutputInvariant)?,
            });
        }
    }
    let mut new_load_pages = 0_u64;
    for load in &added {
        new_load_pages = add(
            new_load_pages,
            (load.page_end - load.vaddr) / policy.page_size,
            "new load page count",
        )?;
        for item in input.program_headers() {
            if !matches!(item.kind, SegmentType::Load | SegmentType::Null) && item.memory_size != 0
            {
                let extent = item.memory_range()?;
                if extent.start().0 < load.page_end && load.vaddr < extent.end().0 {
                    return Err(Error::CarrierMetadataOverlap { index: item.index });
                }
            }
        }
    }
    budget(
        "new load pages",
        new_load_pages,
        image_policy.max_new_load_pages,
    )?;
    budget(
        "added file bytes",
        output_len - original_len,
        policy.max_added_file_bytes,
    )?;
    budget(
        "output file bytes",
        output_len,
        policy.max_output_file_bytes,
    )?;
    budget(
        "virtual span",
        added.last().ok_or(Error::OutputInvariant)?.page_end - lowest_page,
        policy.max_virtual_span,
    )?;
    let output_len = host_index(output_len)?;
    let phdr_index = old_phdrs.first().map_or(0, |item| item.index);
    let header_base = old_count + usize::from(insert_phdr);
    let carrier_index = header_base
        + added
            .iter()
            .position(|load| load.image.is_none())
            .ok_or(Error::OutputInvariant)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(output_len)
        .map_err(|_| Error::Allocation)?;
    bytes.extend_from_slice(input.bytes());
    bytes.resize(output_len, 0);
    let mut original_to_output_header = Vec::with_capacity(old_count);
    if insert_phdr {
        encode_phdr(
            &mut bytes,
            carrier_offset,
            table_header(carrier_offset, carrier_vaddr.0, new_table_len),
        )?;
    }
    for item in input.program_headers() {
        let new_index = item.index + usize::from(insert_phdr);
        original_to_output_header.push(new_index);
        let old_offset = add(
            old_table.start().0,
            item.index as u64 * 56,
            "old program-header offset",
        )?;
        let new_offset = add(
            carrier_offset,
            new_index as u64 * 56,
            "new program-header offset",
        )?;
        if item.kind == SegmentType::ProgramHeaders {
            encode_phdr(
                &mut bytes,
                new_offset,
                table_header(carrier_offset, carrier_vaddr.0, new_table_len),
            )?;
        } else {
            let source = &input.bytes()[host_index(old_offset)?..host_index(old_offset + 56)?];
            bytes[host_index(new_offset)?..host_index(new_offset + 56)?].copy_from_slice(source);
        }
    }
    for (position, load) in added.iter().enumerate() {
        let index = header_base + position;
        encode_phdr(
            &mut bytes,
            add(carrier_offset, index as u64 * 56, "appended load header")?,
            EncodedHeader {
                kind: 1,
                flags: load.flags,
                offset: load.offset,
                vaddr: load.vaddr,
                file_size: load.size,
                memory_size: load.size,
                alignment: policy.page_size,
            },
        )?;
        if let Some(image) = load.image {
            image_placements[image].program_header = index;
        }
    }
    bytes[host_index(payload_offset)?..host_index(payload_range.end().0)?].copy_from_slice(payload);
    for (image, placement) in images.iter().zip(&image_placements) {
        bytes[host_index(placement.file.start().0)?..host_index(placement.file.end().0)?]
            .copy_from_slice(&image.bytes);
    }
    let mut changes = vec![
        Change {
            kind: ChangeKind::ProgramHeaderOffset,
            edit: DeclaredEdit {
                offset: FileOffset(32),
                expected: input.bytes()[32..40].to_vec(),
                replacement: carrier_offset.to_le_bytes().to_vec(),
            },
        },
        Change {
            kind: ChangeKind::ProgramHeaderCount,
            edit: DeclaredEdit {
                offset: FileOffset(56),
                expected: input.bytes()[56..58].to_vec(),
                replacement: (new_count as u16).to_le_bytes().to_vec(),
            },
        },
    ];
    changes.extend(ordered.iter().map(|(_, edit)| Change {
        kind: ChangeKind::DeclaredSource,
        edit: (*edit).clone(),
    }));
    changes.sort_by_key(|change| change.edit.offset);
    for change in &changes {
        let start = host_index(change.edit.offset.0)?;
        bytes[start..start + change.edit.replacement.len()]
            .copy_from_slice(&change.edit.replacement);
    }
    verify_preservation(input.bytes(), &bytes, &changes)?;
    let reparsed = Elf64::parse(
        &bytes,
        ParseLimits {
            max_program_headers: policy.max_program_headers,
        },
    )?;
    reparsed.check_load_page_congruence(policy.page_size)?;
    let mapping = reparsed.file_to_virtual(FileOffset(carrier_offset), new_table_len)?;
    if mapping.program_header != carrier_index
        || mapping.virtual_range.start() != carrier_vaddr
        || reparsed.header().entry != input.header().entry
        || reparsed.program_headers()[carrier_index].flags.0 != 4
        || reparsed.program_headers()[phdr_index].kind != SegmentType::ProgramHeaders
    {
        return Err(Error::OutputInvariant);
    }
    for (image, placement) in images.iter().zip(&image_placements) {
        let mapping = reparsed.file_to_virtual(placement.file.start(), placement.file.len())?;
        if mapping.program_header != placement.program_header
            || mapping.virtual_range.start() != image.entry
            || mapping.flags.0 != 5
            || reparsed.executable_bytes(image.entry, image.bytes.len() as u64)? != image.bytes
        {
            return Err(Error::OutputInvariant);
        }
    }
    Ok(CarrierOutput {
        bytes,
        changes,
        appended: FileRange::checked(FileOffset(original_len), output_len as u64 - original_len)?,
        program_table: table_range,
        program_table_vaddr: carrier_vaddr,
        payload: payload_range,
        original_to_output_header,
        phdr_index,
        carrier_index,
        images: image_placements,
        new_load_pages,
        dynamic,
    })
}

struct AddedLoad {
    offset: u64,
    vaddr: u64,
    size: u64,
    page_end: u64,
    flags: u32,
    image: Option<usize>,
}

fn validate_interpreter(input: &Elf64<'_>, first_load_index: usize) -> Result<(), Error> {
    let items: Vec<_> = input.segments(SegmentType::Interpreter).collect();
    if items.len() > 1 {
        return Err(Error::InvalidInterpreter);
    }
    if let Some(item) = items.first() {
        if item.index >= first_load_index || item.file_size < 2 || item.file_size > item.memory_size
        {
            return Err(Error::InvalidInterpreter);
        }
        let range = item.file_range()?;
        let path = &input.bytes()[host_index(range.start().0)?..host_index(range.end().0)?];
        if path[0] != b'/' || path.last() != Some(&0) || path[..path.len() - 1].contains(&0) {
            return Err(Error::InvalidInterpreter);
        }
        let mapping = input.file_to_virtual(range.start(), range.len())?;
        if !mapping.flags.readable() || mapping.virtual_range.start() != item.vaddr {
            return Err(Error::InvalidInterpreter);
        }
    }
    Ok(())
}

fn section_table(input: &Elf64<'_>) -> Result<Option<FileRange>, Error> {
    let h = input.header();
    if h.section_offset.0 == 0 {
        if h.section_count != 0
            || h.section_name_index != 0
            || !matches!(h.section_entry_size, 0 | 64)
        {
            return Err(Error::UnsupportedSectionLayout);
        }
        return Ok(None);
    }
    if h.section_count == 0 || h.section_entry_size != 64 || h.section_name_index >= h.section_count
    {
        return Err(Error::UnsupportedSectionLayout);
    }
    let range = FileRange::checked(h.section_offset, u64::from(h.section_count) * 64)?;
    if range.end().0 > input.bytes().len() as u64 || range.start().0 < 64 {
        return Err(Error::UnsupportedSectionLayout);
    }
    Ok(Some(range))
}

fn add(start: u64, length: u64, operation: &'static str) -> Result<u64, Error> {
    start
        .checked_add(length)
        .ok_or(Error::Arithmetic { operation })
}
fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}
fn align_up(value: u64, alignment: u64) -> Result<u64, Error> {
    let remainder = value % alignment;
    if remainder == 0 {
        Ok(value)
    } else {
        add(value, alignment - remainder, "alignment rounding")
    }
}
fn host_index(value: u64) -> Result<usize, Error> {
    value.try_into().map_err(|_| Error::Arithmetic {
        operation: "host file-size conversion",
    })
}
fn budget(resource: &'static str, required: u64, limit: u64) -> Result<(), Error> {
    if required > limit {
        Err(Error::Budget {
            resource,
            required,
            limit,
        })
    } else {
        Ok(())
    }
}
fn intersects(a: FileRange, b: FileRange) -> bool {
    !a.is_empty() && !b.is_empty() && a.start() < b.end() && b.start() < a.end()
}
struct EncodedHeader {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}
fn table_header(offset: u64, vaddr: u64, length: u64) -> EncodedHeader {
    EncodedHeader {
        kind: 6,
        flags: 4,
        offset,
        vaddr,
        file_size: length,
        memory_size: length,
        alignment: 8,
    }
}
fn encode_phdr(bytes: &mut [u8], at: u64, header: EncodedHeader) -> Result<(), Error> {
    let at = host_index(at)?;
    let raw = bytes
        .get_mut(
            at..at.checked_add(56).ok_or(Error::Arithmetic {
                operation: "encoded program-header extent",
            })?,
        )
        .ok_or(Error::OutputInvariant)?;
    raw[0..4].copy_from_slice(&header.kind.to_le_bytes());
    raw[4..8].copy_from_slice(&header.flags.to_le_bytes());
    for (start, value) in [
        (8, header.offset),
        (16, header.vaddr),
        (24, header.vaddr),
        (32, header.file_size),
        (40, header.memory_size),
        (48, header.alignment),
    ] {
        raw[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}
fn verify_preservation(original: &[u8], output: &[u8], changes: &[Change]) -> Result<(), Error> {
    let mut cursor = 0;
    for change in changes {
        let start = host_index(change.edit.offset.0)?;
        let end = start
            .checked_add(change.edit.expected.len())
            .ok_or(Error::OutputInvariant)?;
        if start < cursor
            || original.get(start..end) != Some(change.edit.expected.as_slice())
            || output.get(start..end) != Some(change.edit.replacement.as_slice())
            || original.get(cursor..start) != output.get(cursor..start)
        {
            return Err(Error::OutputInvariant);
        }
        cursor = end;
    }
    if original.get(cursor..) != output.get(cursor..original.len()) {
        return Err(Error::OutputInvariant);
    }
    Ok(())
}

#[cfg(test)]
#[path = "carrier_fixtures.rs"]
mod fixtures;

#[cfg(test)]
#[path = "image_fixtures.rs"]
mod image_fixtures;
