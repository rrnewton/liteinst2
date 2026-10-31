//! Private producer for the fixed compiled-C witness, never a general DSO API.
//! Structural checks retain, rather than discharge, runtime admission duties.

use super::{elf, leaf};
use formats::ContentId;
use li2core::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet,
    Refusal, ResumeObligation, SourceIdentity,
};
use li2core::emission::{
    ArtifactEmission, ArtifactFrameTrace, ArtifactFrameTraceRefusal, ArtifactRequest, PlanningSite,
    SymbolicHook, TargetProfile,
};
use li2core::frame_trace::FrameTraceLimits;
use li2core::generated_unwind::artifact::{
    ArtifactFramePreservingHook, ArtifactSourceCertificate, PreparedArtifactUnwind,
};
use li2core::generated_unwind::{self, Limits};
use li2core::planner::HookSemantics;
use li2core::quiescent::{
    AllocationPolicy, PlanningFailure, SearchPolicy, TacticPolicy, plan_install_with_emission,
};
use li2core::trampoline::SavedExtendedStateLayout;
use liteinst_rewrite::carrier::elf64::{
    Elf64, ElfVaddr, FileRange, ParseLimits, SegmentType, Storage, VirtualRange,
};
use liteinst_rewrite::carrier::unwind::{self, IndexLimits, IndexedUnwindRequest, OriginalIndex};
use liteinst_rewrite::carrier::{
    CarrierOutput, CarrierPolicy, DeclaredEdit, ImagePolicy, ImageRequest, RxImage, dynamic,
};
use std::sync::Arc;

const DOMAIN: u64 = 1;
const PROGRAM_LIMIT: usize = 128;
const IMAGE_BYTES: u64 = 8192;
const PAYLOAD: &[u8] = b"li2-indexed-dso-normal-backtrace-v1\0";
const GNU_EH_FRAME: SegmentType = SegmentType::Other(0x6474_e550);

/// Exact fixed sources in subject/collector/header order. The build owner must
/// compile these bytes and close its input/tool/dependency record independently.
pub(super) fn fixture_sources() -> [&'static [u8]; 3] {
    [
        include_bytes!("../../../unwind-oracle/indexed_dso/subject.c"),
        include_bytes!("../../../unwind-oracle/indexed_dso/collector.c"),
        include_bytes!("../../../unwind-oracle/indexed_dso/witness.h"),
    ]
}

/// An assertion supplied by the owner of the real fixed build. These hashes
/// bind bytes; constructing/parsing this value proves NONE of the unsafe
/// semantic premises of `prepare_owned_fixture`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BuildAttestation {
    pub artifact: ContentId,
    pub sources: [ContentId; 3],
    /// Identity of the closed, retained build record (including tools, exact
    /// commands, objects, CRT and shared inputs). No receipt is read here.
    pub record: ContentId,
}

#[derive(Debug)]
pub(super) enum Error {
    Snapshot(elf::Error),
    Elf(liteinst_rewrite::carrier::elf64::Error),
    Leaf(leaf::Error),
    Core(Refusal),
    Planning(Box<PlanningFailure>),
    Trace(ArtifactFrameTraceRefusal),
    Cfi(generated_unwind::Refusal),
    Index(unwind::Error),
    BuildBinding,
    OutputBinding,
    Arithmetic,
}
type Result<T> = std::result::Result<T, Error>;

/// Kept together for the later loader/consumer witness. No execution, mapping,
/// registration, publication or qualification capability is exposed.
pub(super) struct Candidate {
    pub build: BuildAttestation,
    pub target_state: SavedExtendedStateLayout,
    pub placement: elf::Placements,
    pub output: CarrierOutput,
    pub trace: ArtifactFrameTrace,
    pub records: PreparedArtifactUnwind,
    /// Complete original denominator, including unselected original functions.
    pub original_fdes: Vec<(u64, u64, u64)>,
}

impl Candidate {
    pub const fn qualification_complete(&self) -> bool {
        false
    }

    /// Lookup-only negative: keep every code/CFI byte, but restore the original
    /// GNU row in the active copied PHDR table. Run in a fresh process, never
    /// execute instrumented work from this deliberately incomplete index.
    pub fn original_index_only(&self, original: &elf::Snapshot) -> Result<LookupNegative> {
        if original.identity() != self.build.artifact {
            return Err(Error::BuildBinding);
        }
        let input = original.elf().map_err(Error::Snapshot)?;
        let old = input
            .segments(GNU_EH_FRAME)
            .next()
            .ok_or(Error::OutputBinding)?;
        let unwind = self.output.unwind.as_ref().ok_or(Error::OutputBinding)?;
        let old_start = row_offset(input.header().program_offset.0, old.index)?;
        let new_start = row_offset(self.output.program_table.start().0, unwind.program_header)?;
        let old_row = original
            .bytes()
            .get(old_start..add_usize(old_start, 56)?)
            .ok_or(Error::OutputBinding)?;
        let bytes = replace_row(self.output.bytes(), new_start, old_row)?;
        let parsed = Elf64::parse(
            &bytes,
            ParseLimits {
                max_program_headers: PROGRAM_LIMIT,
            },
        )
        .map_err(Error::Elf)?;
        let restored = parsed
            .program_headers()
            .get(unwind.program_header)
            .ok_or(Error::OutputBinding)?;
        if restored.kind != GNU_EH_FRAME
            || restored.vaddr != old.vaddr
            || restored.offset != old.offset
            || restored.file_size != old.file_size
            || restored.memory_size != old.memory_size
            || restored.flags != old.flags
            || restored.alignment != old.alignment
        {
            return Err(Error::OutputBinding);
        }
        Ok(LookupNegative {
            bytes,
            changed_row: FileRange::checked(
                liteinst_rewrite::carrier::elf64::FileOffset(new_start as u64),
                56,
            )
            .map_err(Error::Elf)?,
        })
    }
}

/// Distinct from Candidate: this product cannot supply normal unwind evidence.
pub(super) struct LookupNegative {
    pub bytes: Vec<u8>,
    pub changed_row: FileRange,
}

/// Prepare only a freshly built instance of the exact fixture sources above.
///
/// # Safety
/// The caller owns the closed build named by `build.record`, including actual
/// compiler/linker commands and immutable tools, every object/CRT/shared input,
/// and this exact final artifact. It has independently established that the
/// hidden hook is the compiled reviewed collector, uses the SysV ABI, returns
/// normally, never changes HookContext or any original CFA/caller-memory
/// dependency, and cannot throw, cancel, longjmp, switch stacks or replace the
/// context. All direct/indirect dependencies must satisfy that contract. A
/// source-name/hash match, compiler flag, ELF symbol or parsed receipt alone is
/// NOT this proof. Runtime readiness and non-aliasing must be enforced before
/// any generated execution and throughout every walk.
///
/// The selected function is the compiled reviewed leaf, with no external
/// interior entry, saved resume, self-modification, code-as-data or escaping
/// alternate control flow. Its inputs/output do not alias its return word or
/// caller recovery memory, and ordinary RET uses the SysV entry return word.
/// The checks below independently prove the actual prefix and both exact CFI
/// rows; they do not infer those remaining source/build premises.
///
/// This does NOT qualify loading/execution. The later owner must authenticate
/// loaded code/metadata/PHDRs, the five-symbol indexed consumer and its immutable
/// dependencies, actual caller CALL.next_ip/RSP/canaries, CPU/XCR0/CET and stack
/// capacity; enforce configuration/buffer disjointness; and retain all modules,
/// handles and records until all generated frames and walks have ended. The
/// supplied state describes a target; no host probing or fallback occurs here.
pub(super) unsafe fn prepare_owned_fixture(
    original: &elf::Snapshot,
    build: BuildAttestation,
    state: SavedExtendedStateLayout,
) -> Result<Candidate> {
    check_build(original.identity(), &build)?;
    let input = original.elf().map_err(Error::Snapshot)?;
    let symbols = original.symbols();
    let code = original.code(&symbols.work).map_err(Error::Snapshot)?;
    let record = original
        .source_record(symbols.selected.address)
        .map_err(Error::Snapshot)?;
    let heads = leaf::prove(
        code.bytes,
        symbols.work.address,
        symbols.selected.address,
        &record,
    )
    .map_err(Error::Leaf)?;
    let placement = original
        .placements(carrier_reservation()?, IMAGE_BYTES)
        .map_err(Error::Snapshot)?;
    let identity = CodeIdentity {
        source: SourceIdentity(original.identity().0),
        mapping: DOMAIN,
        generation: 1,
    };
    let function = address_range(symbols.work.address, symbols.work.size)?;
    let entries = LegalEntrySet {
        identity,
        scope: function,
        provenance: EntryProvenance::Declared("fixed compiled-C DSO build attestation".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: heads
            .into_iter()
            .map(|address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    };
    let allocation = AllocationPolicy {
        ranges: vec![address_range(
            placement.image.start().0,
            placement.image.len(),
        )?],
        preferred_address: Some(placement.image.start().0),
        max_candidates: 256,
        max_mappings: 1,
        max_mapped_bytes: usize::try_from(IMAGE_BYTES).map_err(|_| Error::Arithmetic)?,
    };
    let mut occupied = original
        .occupied_loads()
        .iter()
        .map(|range| address_range(range.start().0, range.len()))
        .collect::<Result<Vec<_>>>()?;
    occupied.push(address_range(
        placement.carrier.start().0,
        placement.carrier.len(),
    )?);
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(state, DOMAIN).map_err(Error::Core)?,
        SymbolicHook {
            identity: 1,
            address: Some(symbols.hook.address),
        },
        occupied,
    );
    let trace = plan_install_with_emission(&ArtifactRequest {
        site: PlanningSite {
            identity,
            code: code.bytes,
            base_address: symbols.work.address,
            function,
            // The independent prefix proof is straight-line through NOP5.
            block: address_range(
                symbols.work.address,
                symbols.continuation.address - symbols.work.address,
            )?,
            logical_pc: symbols.selected.address,
            entries: &entries,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 0,
                max_sites: 1,
                ..SearchPolicy::default()
            },
        },
        emission: &emission,
    })
    .map_err(|error| Error::Planning(Box::new(error)))?
    .frame_trace_nop5(&emission, FrameTraceLimits::default())
    .map_err(Error::Trace)?;
    let images = vec![RxImage {
        entry: ElfVaddr(trace.image().address()),
        bytes: trace.image().bytes().to_vec(),
    }];
    let dependencies = trace
        .source_step()
        .parts()
        .dependencies
        .iter()
        .map(|range| file_range(&input, range.start(), range.len()))
        .collect::<Result<Vec<_>>>()?;
    let edits = trace
        .source_step()
        .parts()
        .writes
        .iter()
        .map(|write| {
            let file = file_range(&input, write.address, write.bytes.len() as u64)?;
            Ok(DeclaredEdit {
                offset: file.start(),
                expected: input
                    .executable_bytes(ElfVaddr(write.address), write.bytes.len() as u64)
                    .map_err(Error::Elf)?
                    .to_vec(),
                replacement: write.bytes.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let request = ImageRequest {
        carrier_vaddr: placement.carrier.start(),
        payload: PAYLOAD,
        images: &images,
        source_dependencies: &dependencies,
    };
    let policy = policy(original.bytes().len() as u64, &placement)?;
    let metadata = unwind::metadata_address(&input, &request, policy).map_err(Error::Index)?;
    // SAFETY: the whole-build/external-entry/return-word premises are supplied
    // by this function's unsafe caller. Snapshot proves immutable ownership;
    // leaf::prove independently establishes both exact heads and recovery rows.
    let source = Arc::new(
        unsafe {
            ArtifactSourceCertificate::certify(
                identity,
                DOMAIN,
                vec![record],
                vec![symbols.selected.address, symbols.continuation.address],
                Limits::default(),
            )
        }
        .map_err(Error::Cfi)?,
    );
    // SAFETY: this is precisely the source/build contract above, NOT a semantic
    // conclusion drawn from symbol lookup, ContentId or a JSON receipt.
    let hook =
        unsafe { ArtifactFramePreservingHook::certify(identity, DOMAIN, trace.symbolic_hook()) }
            .map_err(Error::Cfi)?;
    let records =
        PreparedArtifactUnwind::prepare(&trace, source, hook, metadata.0, Limits::default())
            .map_err(Error::Cfi)?;
    let index = OriginalIndex::inspect(&input, IndexLimits::default(), dynamic::Limits::default())
        .map_err(Error::Index)?;
    let original_fdes = index.intervals().collect();
    let output = unwind::append_carrier_with_indexed_unwind(
        &input,
        request,
        &edits,
        policy,
        IndexedUnwindRequest {
            trace: &trace,
            records: &records,
            limits: IndexLimits::default(),
        },
    )
    .map_err(Error::Index)?;
    check_output(&output, &placement)?;
    if records.qualification_complete() {
        return Err(Error::OutputBinding);
    }
    Ok(Candidate {
        build,
        target_state: state,
        placement,
        output,
        trace,
        records,
        original_fdes,
    })
}

fn check_build(artifact: ContentId, build: &BuildAttestation) -> Result<()> {
    if build.artifact != artifact || build.sources != fixture_sources().map(ContentId::of) {
        return Err(Error::BuildBinding);
    }
    Ok(())
}

fn carrier_reservation() -> Result<u64> {
    // Existing CFI/index bounds plus the full PHDR limit and two alignment
    // slacks. This is a conservative reservation, not a new larger CFI limit.
    (PROGRAM_LIMIT as u64)
        .checked_mul(56)
        .and_then(|n| n.checked_add(PAYLOAD.len() as u64))
        .and_then(|n| n.checked_add(Limits::default().metadata_bytes as u64))
        .and_then(|n| n.checked_add(IndexLimits::default().index_bytes as u64))
        .and_then(|n| n.checked_add(14))
        .ok_or(Error::Arithmetic)
}
fn policy(input_len: u64, placement: &elf::Placements) -> Result<ImagePolicy> {
    Ok(ImagePolicy {
        layout: CarrierPolicy {
            page_size: elf::PAGE,
            user_address_limit: 1 << 47,
            max_added_file_bytes: placement
                .output_file_upper_bound
                .checked_sub(input_len)
                .ok_or(Error::Arithmetic)?,
            max_output_file_bytes: placement.output_file_upper_bound,
            max_program_headers: PROGRAM_LIMIT,
            max_virtual_span: elf::BYTE_LIMIT,
        },
        dynamic: dynamic::Limits::default(),
        max_images: 1,
        max_new_load_pages: placement
            .carrier
            .len()
            .checked_add(placement.image.len())
            .ok_or(Error::Arithmetic)?
            / elf::PAGE,
    })
}
fn check_output(output: &CarrierOutput, placement: &elf::Placements) -> Result<()> {
    let parsed = Elf64::parse(
        output.bytes(),
        ParseLimits {
            max_program_headers: PROGRAM_LIMIT,
        },
    )
    .map_err(Error::Elf)?;
    let carrier = parsed
        .program_headers()
        .get(output.carrier_index)
        .ok_or(Error::OutputBinding)?;
    let [image] = output.images.as_slice() else {
        return Err(Error::OutputBinding);
    };
    let rx = parsed
        .program_headers()
        .get(image.program_header)
        .ok_or(Error::OutputBinding)?;
    let unwind = output.unwind.as_ref().ok_or(Error::OutputBinding)?;
    if output.bytes().len() as u64 > placement.output_file_upper_bound
        || carrier.kind != SegmentType::Load
        || carrier.flags.0 != 4
        || rx.kind != SegmentType::Load
        || rx.flags.0 != 5
        || carrier.vaddr != placement.carrier.start()
        || rx.vaddr != placement.image.start()
        || !contains(
            placement.carrier,
            carrier.memory_range().map_err(Error::Elf)?,
        )
        || !contains(placement.image, rx.memory_range().map_err(Error::Elf)?)
        || unwind.qualification_complete()
        || unwind.artifact_requirements.is_empty()
        || unwind.frame_requirements.is_empty()
    {
        return Err(Error::OutputBinding);
    }
    Ok(())
}
fn contains(outer: VirtualRange, inner: VirtualRange) -> bool {
    outer.start().0 <= inner.start().0 && inner.end().0 <= outer.end().0
}
fn address_range(start: u64, size: u64) -> Result<AddressRange> {
    AddressRange::new(start, usize::try_from(size).map_err(|_| Error::Arithmetic)?)
        .map_err(Error::Core)
}
fn file_range(input: &Elf64<'_>, start: u64, size: u64) -> Result<FileRange> {
    let mapped = input
        .virtual_to_storage(ElfVaddr(start), size)
        .map_err(Error::Elf)?;
    let Storage::FileBacked(file) = mapped.storage else {
        return Err(Error::OutputBinding);
    };
    Ok(file)
}
fn add_usize(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Arithmetic)
}
fn row_offset(table: u64, row: usize) -> Result<usize> {
    let value = (row as u64)
        .checked_mul(56)
        .and_then(|n| table.checked_add(n))
        .ok_or(Error::Arithmetic)?;
    usize::try_from(value).map_err(|_| Error::Arithmetic)
}
fn replace_row(positive: &[u8], start: usize, old_row: &[u8]) -> Result<Vec<u8>> {
    let end = add_usize(start, 56)?;
    if old_row.len() != 56 || positive.get(start..end).is_none_or(|row| row == old_row) {
        return Err(Error::OutputBinding);
    }
    let mut bytes = positive.to_vec();
    bytes[start..end].copy_from_slice(old_row);
    if bytes[..start] != positive[..start] || bytes[end..] != positive[end..] {
        return Err(Error::OutputBinding);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_checks_every_source_and_whole_artifact_without_claiming_semantics() {
        let artifact = ContentId::of(b"only a binding control, no compiled artifact");
        let binding = BuildAttestation {
            artifact,
            sources: fixture_sources().map(ContentId::of),
            record: ContentId::of(b"not a semantic certificate"),
        };
        assert!(check_build(artifact, &binding).is_ok());
        let mut bad = binding;
        bad.artifact = ContentId::of(b"different artifact");
        assert!(matches!(
            check_build(artifact, &bad),
            Err(Error::BuildBinding)
        ));
        for i in 0..3 {
            let mut bad = binding;
            bad.sources[i] = ContentId::of(b"different source");
            assert!(matches!(
                check_build(artifact, &bad),
                Err(Error::BuildBinding)
            ));
        }
    }

    #[test]
    fn negative_changes_exactly_one_row_and_refuses_vacuous_or_truncated_edits() {
        let positive: Vec<u8> = (0..224).map(|n| n as u8).collect();
        let row = [0xff; 56];
        let result = replace_row(&positive, 56, &row).unwrap();
        assert_eq!(result.len(), positive.len());
        assert_eq!(&result[..56], &positive[..56]);
        assert_eq!(&result[56..112], &row);
        assert_eq!(&result[112..], &positive[112..]);
        assert!(replace_row(&positive, 56, &positive[56..112]).is_err());
        assert!(replace_row(&positive, 56, &row[..55]).is_err());
        assert!(replace_row(&positive, 169, &row).is_err());
        assert!(replace_row(&positive, usize::MAX, &row).is_err());
    }
}
