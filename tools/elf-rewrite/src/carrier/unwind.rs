//! A bounded GNU indexed-unwind carrier, not runtime unwind qualification.
//!
//! The indexed consumer must support an aligned datarel/sdata4 table whose FDEs
//! may occupy separate blocks. Linear fallback still names the original stream;
//! it is not claimed to find generated records. No records are registered here.
//! The existing unsafe exact-point and hook certificates remain caller-owned.

mod parser;
#[cfg(test)]
mod tests;

use super::elf64::{
    self, Elf64, ElfVaddr, FileOffset, FileRange, ParseLimits, SegmentType, Storage,
};
use super::{CarrierOutput, DeclaredEdit, ImagePolicy, ImageRequest, dynamic};
use formats::ContentId;
use li2core::contracts::PatchPlan;
use li2core::emission::{ArtifactFrameTrace, ArtifactRequirement, SymbolicHook};
use li2core::frame_trace::FrameTraceRequirement;
use li2core::generated_unwind::artifact::{OriginalArtifactCfi, PreparedArtifactUnwind};
use parser::{Entry, Header, Stream};

// Keep the shared ELF enum unchanged: older startup profiles deliberately
// refuse this as Other, and this additive profile must not widen them.
const GNU_EH_FRAME: SegmentType = SegmentType::Other(0x6474_e550);

/// Separate bounds for inventory/indexing, never broader source-CFI semantics.
#[derive(Clone, Copy, Debug)]
pub struct IndexLimits {
    pub original_fdes: usize,
    pub original_cies: usize,
    /// Original header plus complete original stream, including its terminator.
    pub original_bytes: usize,
    /// Maximum original or combined header/table size.
    pub index_bytes: usize,
}
impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            original_fdes: 256,
            original_cies: 64,
            original_bytes: 1024 * 1024,
            index_bytes: 64 * 1024,
        }
    }
}

/// Refusals of this optional byte product. Ordinary carrier APIs are unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Carrier(super::Error),
    Elf(elf64::Error),
    UnsupportedHeader,
    UnsupportedRecord,
    MalformedRecord,
    IndexMismatch,
    OverlappingFrames,
    MetadataOwner,
    MetadataWrite,
    MetadataEdit,
    SourceBinding,
    ImageBinding,
    EditBinding,
    MissingPoint,
    MetadataAddress,
    RelativeRange,
    Arithmetic,
    Allocation,
    Limit {
        resource: &'static str,
        required: usize,
        limit: usize,
    },
    OutputInvariant,
}
impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Carrier(value)
    }
}
impl From<elf64::Error> for Error {
    fn from(value: elf64::Error) -> Self {
        Self::Elf(value)
    }
}
impl From<dynamic::Error> for Error {
    fn from(value: dynamic::Error) -> Self {
        Self::Carrier(super::Error::Dynamic(value))
    }
}

/// Authenticated byte inventory. A containing interval does not certify a point
/// as an instruction boundary or establish any caller-recovery rule there.
pub struct OriginalIndex<'elf, 'data> {
    input: &'elf Elf64<'data>,
    identity: ContentId,
    header_index: usize,
    header_address: u64,
    header: Header,
    stream: Stream,
    dependencies: [FileRange; 2],
    dynamic: dynamic::Inventory,
}
impl<'elf, 'data> OriginalIndex<'elf, 'data> {
    pub fn inspect(
        input: &'elf Elf64<'data>,
        limits: IndexLimits,
        dynamic_limits: dynamic::Limits,
    ) -> Result<Self, Error> {
        let mut headers = input.segments(GNU_EH_FRAME);
        let header = headers.next().ok_or(Error::UnsupportedHeader)?;
        if headers.next().is_some()
            || header.flags.0 != 4
            || header.file_size != header.memory_size
            || header.file_size < 12
            || header.vaddr.0 % 4 != 0
            || header.offset.0 % 4 != 0
        {
            return Err(Error::UnsupportedHeader);
        }
        let header_len = usize::try_from(header.file_size).map_err(|_| Error::Arithmetic)?;
        limit("index bytes", header_len, limits.index_bytes)?;
        limit("original metadata bytes", header_len, limits.original_bytes)?;
        let dynamic = dynamic::inspect(input, dynamic_limits)?;
        let prefix = metadata(input, &dynamic, header.vaddr.0, 12)?;
        let count = usize::try_from(parser::word(prefix, 8)?).map_err(|_| Error::Arithmetic)?;
        limit("FDE records", count, limits.original_fdes)?;
        if parser::index_bytes(count)? != header_len {
            return Err(Error::IndexMismatch);
        }
        let header_file = metadata_range(input, &dynamic, header.vaddr.0, header_len)?;
        if header_file != header.file_range()? {
            return Err(Error::MetadataOwner);
        }
        let parsed = parser::header(
            metadata(input, &dynamic, header.vaddr.0, header_len)?,
            header.vaddr.0,
            limits,
        )?;
        let stream = parser::stream(
            |at, size| metadata(input, &dynamic, at, size),
            parsed.stream,
            IndexLimits {
                original_bytes: limits.original_bytes - header_len,
                ..limits
            },
        )?;
        let stream_file = metadata_range(input, &dynamic, parsed.stream, stream.bytes)?;
        if super::intersects(header_file, stream_file) {
            return Err(Error::MetadataOwner);
        }
        if parser::ordered(&stream.fdes)? != parsed.entries {
            return Err(Error::IndexMismatch);
        }
        for fde in &stream.fdes {
            input.executable_bytes(ElfVaddr(fde.start), fde.end - fde.start)?;
        }
        Ok(Self {
            input,
            identity: ContentId::of(input.bytes()),
            header_index: header.index,
            header_address: header.vaddr.0,
            header: parsed,
            stream,
            dependencies: [header_file, stream_file],
            dynamic,
        })
    }

    /// Exact complete original content identity, not a build ID or path.
    pub const fn identity(&self) -> ContentId {
        self.identity
    }
    pub const fn header_address(&self) -> ElfVaddr {
        ElfVaddr(self.header_address)
    }
    pub const fn stream_address(&self) -> ElfVaddr {
        ElfVaddr(self.header.stream)
    }
    /// Complete original intervals and exact FDE coordinates, in stream order.
    pub fn intervals(&self) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
        self.stream
            .fdes
            .iter()
            .map(|fde| (fde.start, fde.end, fde.record.address))
    }
    /// Header/table and complete original record stream, including termination.
    pub fn dependencies(&self) -> &[FileRange] {
        &self.dependencies
    }
    pub const fn qualification_complete(&self) -> bool {
        false
    }

    /// Copy the containing original CIE/FDE. This does not certify exact-point
    /// frame semantics; the caller must independently discharge that contract.
    pub fn source_record(&self, point: u64) -> Result<OriginalArtifactCfi, Error> {
        let fde = self
            .stream
            .fdes
            .iter()
            .find(|fde| fde.start <= point && point < fde.end)
            .ok_or(Error::MissingPoint)?;
        let cie = self
            .stream
            .cies
            .iter()
            .find(|cie| cie.address == fde.cie)
            .ok_or(Error::IndexMismatch)?;
        Ok(OriginalArtifactCfi {
            cie_address: cie.address,
            cie: copy(metadata(self.input, &self.dynamic, cie.address, cie.bytes)?)?,
            fde_address: fde.record.address,
            fde: copy(metadata(
                self.input,
                &self.dynamic,
                fde.record.address,
                fde.record.bytes,
            )?)?,
        })
    }

    fn authenticate_source_records(&self, records: &[OriginalArtifactCfi]) -> Result<(), Error> {
        if records.is_empty() {
            return Err(Error::SourceBinding);
        }
        for record in records {
            let fde = self
                .stream
                .fdes
                .iter()
                .find(|fde| fde.record.address == record.fde_address)
                .ok_or(Error::SourceBinding)?;
            let cie = self
                .stream
                .cies
                .iter()
                .find(|cie| cie.address == record.cie_address)
                .ok_or(Error::SourceBinding)?;
            if fde.cie != cie.address
                || fde.record.bytes != record.fde.len()
                || cie.bytes != record.cie.len()
                || metadata(self.input, &self.dynamic, cie.address, cie.bytes)? != record.cie
                || metadata(
                    self.input,
                    &self.dynamic,
                    fde.record.address,
                    fde.record.bytes,
                )? != record.fde
            {
                return Err(Error::SourceBinding);
            }
        }
        Ok(())
    }
}

/// Inputs already bound by the producer and the caller's unsafe certificates.
pub struct IndexedUnwindRequest<'a> {
    pub trace: &'a ArtifactFrameTrace,
    pub records: &'a PreparedArtifactUnwind,
    pub limits: IndexLimits,
}

/// Structural placement plus unchanged outstanding source/runtime obligations.
#[derive(Clone, Debug)]
pub struct UnwindPlacement {
    pub header: FileRange,
    pub header_address: ElfVaddr,
    pub records: FileRange,
    pub records_address: ElfVaddr,
    pub program_header: usize,
    pub original_fdes: usize,
    pub generated_fdes: usize,
    pub source_step: PatchPlan,
    pub bias_domain: u64,
    pub symbolic_hook: SymbolicHook,
    pub artifact_requirements: Vec<ArtifactRequirement>,
    pub frame_requirements: Vec<FrameTraceRequirement>,
}
impl UnwindPlacement {
    /// Bytes and index lookup structure do not discharge consumer/lifetime work.
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}

/// Exact metadata coordinate after the ordinary payload, before preparing CFI.
/// No source/loader admission is implied; final construction repeats all checks.
pub fn metadata_address(
    input: &Elf64<'_>,
    request: &ImageRequest<'_>,
    policy: ImagePolicy,
) -> Result<ElfVaddr, Error> {
    let payload = payload_address(input, request, policy)?;
    Ok(ElfVaddr(super::align_up(
        add(payload, request.payload.len() as u64)?,
        8,
    )?))
}

fn payload_address(
    input: &Elf64<'_>,
    request: &ImageRequest<'_>,
    policy: ImagePolicy,
) -> Result<u64, Error> {
    if policy.layout.page_size < 8
        || !policy.layout.page_size.is_power_of_two()
        || request.carrier_vaddr.0 % policy.layout.page_size != 0
    {
        return Err(super::Error::InvalidTargetPolicy.into());
    }
    let phdrs = input.segments(SegmentType::ProgramHeaders).count();
    if phdrs > 1 || input.segments(GNU_EH_FRAME).count() != 1 {
        return Err(Error::UnsupportedHeader);
    }
    super::budget(
        "images",
        request.images.len() as u64,
        policy.max_images as u64,
    )?;
    let count = input
        .program_headers()
        .len()
        .checked_add(1 + usize::from(phdrs == 0))
        .and_then(|n| n.checked_add(request.images.len()))
        .ok_or(Error::Arithmetic)?;
    super::budget(
        "program headers",
        count as u64,
        policy.layout.max_program_headers.min(0xfffe) as u64,
    )?;
    let offset = super::align_up(input.bytes().len() as u64, policy.layout.page_size)?;
    let table = (count as u64).checked_mul(56).ok_or(Error::Arithmetic)?;
    let (_, payload) = super::table_and_payload(offset, table)?;
    add(request.carrier_vaddr.0, payload - offset)
}

/// Embed exact relative records and a complete combined GNU index. This is a
/// singleton NOP5 artifact route, not general CFI certification or registration.
/// Original metadata bytes and all original lookups remain present. The actual
/// indexed consumer, loaded identities and lifetimes still require qualification.
pub fn append_carrier_with_indexed_unwind(
    input: &Elf64<'_>,
    request: ImageRequest<'_>,
    edits: &[DeclaredEdit],
    policy: ImagePolicy,
    unwind: IndexedUnwindRequest<'_>,
) -> Result<CarrierOutput, Error> {
    let original = OriginalIndex::inspect(input, unwind.limits, policy.dynamic)?;
    authenticate_plan(input, &request, edits, &original, &unwind)?;
    let address = metadata_address(input, &request, policy)?.0;
    if unwind.records.address() != address {
        return Err(Error::MetadataAddress);
    }
    let generated = generated_stream(unwind.records)?;
    let count = original
        .stream
        .fdes
        .len()
        .checked_add(generated.fdes.len())
        .ok_or(Error::Arithmetic)?;
    limit(
        "index bytes",
        parser::index_bytes(count)?,
        unwind.limits.index_bytes,
    )?;
    let mut all = Vec::new();
    all.try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    all.extend_from_slice(&original.stream.fdes);
    all.extend_from_slice(&generated.fdes);
    let entries = parser::ordered(&all)?;
    let header_address = super::align_up(add(address, unwind.records.bytes().len() as u64)?, 8)?;
    let header = parser::render(
        &entries,
        original.header.stream,
        header_address,
        unwind.limits,
    )?;
    let payload_start = payload_address(input, &request, policy)?;
    let final_len = usize::try_from(add(header_address, header.len() as u64)? - payload_start)
        .map_err(|_| Error::Arithmetic)?;
    super::budget(
        "unwind payload bytes",
        final_len as u64,
        policy.layout.max_added_file_bytes,
    )?;
    super::budget(
        "unwind output bytes",
        add(input.bytes().len() as u64, final_len as u64)?,
        policy.layout.max_output_file_bytes,
    )?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(final_len)
        .map_err(|_| Error::Allocation)?;
    payload.extend_from_slice(request.payload);
    payload.resize(
        usize::try_from(address - payload_start).map_err(|_| Error::Arithmetic)?,
        0,
    );
    payload.extend_from_slice(unwind.records.bytes());
    payload.resize(
        usize::try_from(header_address - payload_start).map_err(|_| Error::Arithmetic)?,
        0,
    );
    payload.extend_from_slice(&header);
    let mut output = super::append_carrier_with_images(
        input,
        ImageRequest {
            payload: &payload,
            ..request
        },
        edits,
        policy,
    )?;
    let records_file = FileRange::checked(
        FileOffset(add(output.payload.start().0, address - payload_start)?),
        unwind.records.bytes().len() as u64,
    )?;
    let header_file = FileRange::checked(
        FileOffset(add(
            output.payload.start().0,
            header_address - payload_start,
        )?),
        header.len() as u64,
    )?;
    let index = *output
        .original_to_output_header
        .get(original.header_index)
        .ok_or(Error::OutputInvariant)?;
    let at = add(
        output.program_table.start().0,
        (index as u64).checked_mul(56).ok_or(Error::Arithmetic)?,
    )?;
    super::encode_phdr(
        &mut output.bytes,
        at,
        super::EncodedHeader {
            kind: 0x6474_e550,
            flags: 4,
            offset: header_file.start().0,
            vaddr: header_address,
            file_size: header.len() as u64,
            memory_size: header.len() as u64,
            alignment: 4,
        },
    )?;
    verify_output(
        input,
        &output,
        &original,
        &generated,
        RecordBytes {
            address: unwind.records.address(),
            bytes: unwind.records.bytes(),
        },
        policy,
        FinalIndex {
            entries: &entries,
            header: &header,
            header_file,
            header_address,
            records_file,
            limits: unwind.limits,
        },
    )?;
    output.unwind = Some(UnwindPlacement {
        header: header_file,
        header_address: ElfVaddr(header_address),
        records: records_file,
        records_address: ElfVaddr(address),
        program_header: index,
        original_fdes: original.stream.fdes.len(),
        generated_fdes: generated.fdes.len(),
        source_step: unwind.trace.source_step().clone(),
        bias_domain: unwind.trace.bias_domain(),
        symbolic_hook: unwind.trace.symbolic_hook(),
        artifact_requirements: unwind.trace.image().metadata().requirements().to_vec(),
        frame_requirements: unwind.trace.trace().requirements().to_vec(),
    });
    Ok(output)
}

fn authenticate_plan(
    input: &Elf64<'_>,
    request: &ImageRequest<'_>,
    edits: &[DeclaredEdit],
    original: &OriginalIndex<'_, '_>,
    unwind: &IndexedUnwindRequest<'_>,
) -> Result<(), Error> {
    if unwind.trace.identity().source.0 != original.identity.0
        || !unwind.records.matches_trace(unwind.trace)
    {
        return Err(Error::SourceBinding);
    }
    original.authenticate_source_records(unwind.records.source_records())?;
    let image = unwind.trace.image();
    if request.images.len() != 1
        || request.images[0].entry.0 != image.address()
        || request.images[0].bytes != image.bytes()
    {
        return Err(Error::ImageBinding);
    }
    let parts = unwind.trace.source_step().parts();
    for read in &parts.reads {
        if input.executable_bytes(ElfVaddr(read.address), read.bytes.len() as u64)? != read.bytes {
            return Err(Error::SourceBinding);
        }
    }
    for dependency in &parts.dependencies {
        let mapped = input.virtual_to_storage(ElfVaddr(dependency.start()), dependency.len())?;
        let Storage::FileBacked(file) = mapped.storage else {
            return Err(Error::SourceBinding);
        };
        if !mapped.flags.executable()
            || !request
                .source_dependencies
                .iter()
                .any(|held| held.start() <= file.start() && held.end() >= file.end())
        {
            return Err(Error::SourceBinding);
        }
        let reverse = input.file_to_virtual(file.start(), file.len())?;
        if reverse.program_header != mapped.program_header
            || reverse.virtual_range != mapped.virtual_range
        {
            return Err(Error::SourceBinding);
        }
    }
    if edits.len() != parts.writes.len() {
        return Err(Error::EditBinding);
    }
    for (write, edit) in parts.writes.iter().zip(edits) {
        let mapping = input.file_to_virtual(edit.offset, edit.expected.len() as u64)?;
        if mapping.virtual_range.start().0 != write.address
            || edit.replacement != write.bytes
            || edit.expected
                != input.executable_bytes(ElfVaddr(write.address), write.bytes.len() as u64)?
        {
            return Err(Error::EditBinding);
        }
    }
    // Code expectations are not CFI expectations. Protect the latter separately,
    // including when an original metadata owner is executable but not writable.
    let mut changes = Vec::new();
    changes
        .try_reserve_exact(edits.len() + 2)
        .map_err(|_| Error::Allocation)?;
    changes.push(FileRange::checked(FileOffset(32), 8)?);
    changes.push(FileRange::checked(FileOffset(56), 2)?);
    for edit in edits {
        changes.push(FileRange::checked(edit.offset, edit.expected.len() as u64)?);
    }
    if original.dependencies.iter().any(|data| {
        changes
            .iter()
            .any(|change| super::intersects(*data, *change))
    }) {
        return Err(Error::MetadataEdit);
    }
    Ok(())
}

fn generated_stream(records: &PreparedArtifactUnwind) -> Result<Stream, Error> {
    let bytes = records.bytes();
    let stream = parser::stream(
        |at, len| {
            let begin = usize::try_from(
                at.checked_sub(records.address())
                    .ok_or(Error::MetadataAddress)?,
            )
            .map_err(|_| Error::Arithmetic)?;
            bytes
                .get(begin..begin.checked_add(len).ok_or(Error::Arithmetic)?)
                .ok_or(Error::MalformedRecord)
        },
        records.address(),
        IndexLimits {
            original_fdes: records.fdes().len(),
            original_cies: 1,
            original_bytes: bytes.len(),
            index_bytes: 0,
        },
    )?;
    if stream.bytes != bytes.len() || stream.fdes.len() != records.fdes().len() {
        return Err(Error::IndexMismatch);
    }
    for (fde, &(start, end, offset)) in stream.fdes.iter().zip(records.fdes()) {
        if (fde.start, fde.end, fde.record.address)
            != (start, end, add(records.address(), offset as u64)?)
        {
            return Err(Error::IndexMismatch);
        }
    }
    Ok(stream)
}

struct FinalIndex<'a> {
    entries: &'a [Entry],
    header: &'a [u8],
    header_file: FileRange,
    header_address: u64,
    records_file: FileRange,
    limits: IndexLimits,
}

struct RecordBytes<'a> {
    address: u64,
    bytes: &'a [u8],
}

fn verify_output(
    input: &Elf64<'_>,
    output: &CarrierOutput,
    original: &OriginalIndex<'_, '_>,
    generated: &Stream,
    records: RecordBytes<'_>,
    policy: ImagePolicy,
    expected: FinalIndex<'_>,
) -> Result<(), Error> {
    let FinalIndex {
        entries,
        header,
        header_file,
        header_address,
        records_file,
        limits,
    } = expected;
    super::verify_preservation(input.bytes(), output.bytes(), output.changes())?;
    let parsed = Elf64::parse(
        output.bytes(),
        ParseLimits {
            max_program_headers: policy.layout.max_program_headers,
        },
    )?;
    parsed.check_load_page_congruence(policy.layout.page_size)?;
    let headers: Vec<_> = parsed.segments(GNU_EH_FRAME).collect();
    if headers.len() != 1
        || headers[0].file_range()? != header_file
        || headers[0].vaddr.0 != header_address
        || headers[0].flags.0 != 4
        || headers[0].memory_size != header_file.len()
        || headers[0].alignment != 4
    {
        return Err(Error::OutputInvariant);
    }
    let header_mapping = parsed.file_to_virtual(header_file.start(), header_file.len())?;
    if header_mapping.program_header != output.carrier_index
        || header_mapping.flags.0 != 4
        || header_mapping.virtual_range.start().0 != header_address
    {
        return Err(Error::OutputInvariant);
    }
    for old in input.program_headers() {
        if old.index == original.header_index || old.kind == SegmentType::ProgramHeaders {
            continue;
        }
        let new_index = *output
            .original_to_output_header
            .get(old.index)
            .ok_or(Error::OutputInvariant)?;
        let before = add(input.header().program_offset.0, old.index as u64 * 56)?;
        let after = add(output.program_table.start().0, new_index as u64 * 56)?;
        let before = super::host_index(before)?;
        let after = super::host_index(after)?;
        if input
            .bytes()
            .get(before..before.checked_add(56).ok_or(Error::Arithmetic)?)
            != output
                .bytes()
                .get(after..after.checked_add(56).ok_or(Error::Arithmetic)?)
        {
            return Err(Error::OutputInvariant);
        }
    }
    let read_header = metadata(&parsed, &output.dynamic, header_address, header.len())?;
    let index = parser::header(read_header, header_address, limits)?;
    if read_header != header || index.stream != original.header.stream || index.entries != entries {
        return Err(Error::OutputInvariant);
    }
    let image = parsed.file_to_virtual(records_file.start(), records_file.len())?;
    if image.program_header != output.carrier_index
        || image.virtual_range.start().0 != records.address
        || image.flags.0 != 4
        || metadata(
            &parsed,
            &output.dynamic,
            records.address,
            records.bytes.len(),
        )? != records.bytes
    {
        return Err(Error::OutputInvariant);
    }
    for range in original.dependencies {
        let begin = usize::try_from(range.start().0).map_err(|_| Error::Arithmetic)?;
        let end = usize::try_from(range.end().0).map_err(|_| Error::Arithmetic)?;
        if output.bytes().get(begin..end) != input.bytes().get(begin..end) {
            return Err(Error::OutputInvariant);
        }
    }
    for fde in original.stream.fdes.iter().chain(&generated.fdes) {
        let actual = metadata(
            &parsed,
            &output.dynamic,
            fde.record.address,
            fde.record.bytes,
        )?;
        if parser::word(actual, 8)? as i32 as i64
            != i64::try_from(i128::from(fde.start) - i128::from(add(fde.record.address, 8)?))
                .map_err(|_| Error::Arithmetic)?
            || parser::word(actual, 12)? as i32 as i64
                != i64::try_from(fde.end - fde.start).map_err(|_| Error::Arithmetic)?
        {
            return Err(Error::OutputInvariant);
        }
        parsed.executable_bytes(ElfVaddr(fde.start), fde.end - fde.start)?;
    }
    Ok(())
}

fn metadata_range(
    input: &Elf64<'_>,
    dynamic: &dynamic::Inventory,
    address: u64,
    len: usize,
) -> Result<FileRange, Error> {
    let mapping = input.virtual_to_storage(ElfVaddr(address), len as u64)?;
    let Storage::FileBacked(file) = mapping.storage else {
        return Err(Error::MetadataOwner);
    };
    let reverse = input.file_to_virtual(file.start(), file.len())?;
    if !mapping.flags.readable()
        || mapping.flags.writable()
        || reverse.program_header != mapping.program_header
        || reverse.virtual_range != mapping.virtual_range
    {
        return Err(Error::MetadataOwner);
    }
    if dynamic.writes.iter().any(|write| {
        write.range.start() < mapping.virtual_range.end()
            && mapping.virtual_range.start() < write.range.end()
            || write
                .file
                .is_some_and(|other| super::intersects(file, other))
    }) {
        return Err(Error::MetadataWrite);
    }
    Ok(file)
}

fn metadata<'a>(
    input: &Elf64<'a>,
    dynamic: &dynamic::Inventory,
    address: u64,
    len: usize,
) -> Result<&'a [u8], Error> {
    let file = metadata_range(input, dynamic, address, len)?;
    let start = usize::try_from(file.start().0).map_err(|_| Error::Arithmetic)?;
    let end = usize::try_from(file.end().0).map_err(|_| Error::Arithmetic)?;
    input.bytes().get(start..end).ok_or(Error::MetadataOwner)
}

fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::Arithmetic)
}
fn limit(resource: &'static str, required: usize, maximum: usize) -> Result<(), Error> {
    if required > maximum {
        Err(Error::Limit {
            resource,
            required,
            limit: maximum,
        })
    } else {
        Ok(())
    }
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Allocation)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
