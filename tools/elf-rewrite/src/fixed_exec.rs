//! The explicit fixed-ET_EXEC adapter. No live mapping/loader proof is created.
use crate::*;

pub const BINDING_PROFILE: &str = "fixed-exec-zero-bias-indexed-jump32-v1";
pub const METADATA: &str = "planner_profile\twhole-program-packed-overlapping-neighbors-4096\naddress_binding\tfixed-exec-zero-bias-indexed-jump32-v1\nrequired_object_type\tET_EXEC\nrequired_load_bias\t0\nfixed_binding_qualification\tunresolved-runtime-loader-obligation\n";

/// Canonical relocation/load-bias policy bytes for the portable compatibility
/// digest. These bytes bind the complete selection as well as the fixed source,
/// domain, generation and zero-bias obligation; they do not prove a live loader.
pub fn binding_policy(binding: FixedImageBinding, selection: ContentId) -> Vec<u8> {
    let identity = binding.identity();
    format!(
        "LI2FIXED-EXEC-BINDING\t1\n{METADATA}selection_sha256\t{}\nsource_sha256\t{}\nmapping\t{}\ngeneration\t{}\ndomain\t{}\nfield_encoding\toriginal-indexed-jump-signed32-v1\n",
        ledger::hex(&selection.0), ledger::hex(&identity.source.0),
        identity.mapping, identity.generation, binding.domain(),
    ).into_bytes()
}

// Common constructor for singleton and paired frontends. This is not a second
// encoder; the ordinary constructor remains the exact no-binding route.
pub(crate) fn emission(
    selection: &Selection,
    hook: &model::Hook,
    occupied: Vec<AddressRange>,
    binding: Option<FixedImageBinding>,
) -> Result<ArtifactEmission, Error> {
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(selection.target, selection.bias_domain)
            .map_err(|error| Error::new("target", error))?,
        SymbolicHook {
            identity: hook.id,
            address: Some(hook.pc),
        },
        occupied,
    );
    match binding {
        None => Ok(emission),
        Some(binding) => emission
            .with_fixed_image(binding)
            .map_err(|error| Error::new("fixed-binding", error)),
    }
}

pub(crate) fn bind(
    elf: &Elf64<'_>,
    identity: CodeIdentity,
    domain: u64,
) -> Result<FixedImageBinding, Error> {
    if elf.header().object_type != carrier::elf64::ObjectType::Executable {
        return Err(Error::new("fixed-exec-binding", "requires ET_EXEC"));
    }
    if identity.source.0 != ContentId::of(elf.bytes()).0 {
        return Err(Error::new("fixed-exec-binding", "original digest mismatch"));
    }
    FixedImageBinding::zero_bias(identity, domain)
        .map_err(|error| Error::new("fixed-exec-binding", error))
}

// The existing writer has already checked edits/relocations/ownership/bounds.
// This independent fixed-profile readback happens before candidate publication.
// It cannot turn an earlier producer or carrier refusal into a partial success.
pub(crate) struct OutputReadback<'a> {
    pub bytes: &'a [u8],
    pub original_to_output_header: &'a [usize],
    pub max_program_headers: usize,
}

pub(crate) fn validate_output(
    original: &Elf64<'_>,
    binding: FixedImageBinding,
    plans: &[(u64, ArtifactPlan)],
    output: OutputReadback<'_>,
    dynamic: &carrier::dynamic::Inventory,
    dependencies: &[FileRange],
) -> Result<(), carrier::Error> {
    let views: Vec<_> = plans.iter().map(|(id, plan)| (*id, plan)).collect();
    validate_output_views(original, binding, &views, output, dynamic, dependencies)
}
pub(crate) fn validate_output_views(
    original: &Elf64<'_>,
    binding: FixedImageBinding,
    plans: &[(u64, &ArtifactPlan)],
    output: OutputReadback<'_>,
    dynamic: &carrier::dynamic::Inventory,
    dependencies: &[FileRange],
) -> Result<(), carrier::Error> {
    let rebound = bind(original, binding.identity(), binding.domain())
        .map_err(|_| carrier::Error::OutputInvariant)?;
    if rebound != binding {
        return Err(carrier::Error::OutputInvariant);
    }
    let written = Elf64::parse(
        output.bytes,
        ParseLimits {
            max_program_headers: output.max_program_headers,
        },
    )?;
    if written.header().object_type != carrier::elf64::ObjectType::Executable
        || written.header().entry != original.header().entry
    {
        return Err(carrier::Error::OutputInvariant);
    }
    // The carrier inserts/interleaves headers, so table indices are locations,
    // not LOAD identities. Join its complete, ordered header map, then compare
    // every original LOAD field at the actual output location. No virtual/file
    // address, physical address, extent, permission or alignment may change.
    let headers = output.original_to_output_header;
    if headers.len() != original.program_headers().len()
        || headers.windows(2).any(|pair| pair[0] >= pair[1])
        || headers
            .iter()
            .any(|index| *index >= written.program_headers().len())
    {
        return Err(carrier::Error::OutputInvariant);
    }
    for load in original.segments(SegmentType::Load) {
        let mut expected = load.clone();
        expected.index = headers[load.index];
        if written.program_headers().get(expected.index) != Some(&expected) {
            return Err(carrier::Error::OutputInvariant);
        }
    }
    for image in plans.iter().flat_map(|(_, plan)| plan.images()) {
        if image.metadata().fixed_image() != Some(binding) {
            return Err(carrier::Error::OutputInvariant);
        }
        let bytes =
            written.executable_bytes(ElfVaddr(image.address()), image.bytes().len() as u64)?;
        if bytes != image.bytes() {
            return Err(carrier::Error::OutputInvariant);
        }
        for field in image.metadata().fields() {
            if field.encoding != ArtifactFieldEncoding::FixedSigned32 {
                continue;
            }
            let source = field.fixed_source.ok_or(carrier::Error::OutputInvariant)?;
            let instruction = source.instruction();
            let old =
                original.executable_bytes(ElfVaddr(instruction.start()), instruction.len())?;
            let mut decoder = li2core::x86::decoder64(old, instruction.start());
            let decoded = decoder.decode();
            let constants = decoder.get_constant_offsets(&decoded);
            if decoded.code() != iced_x86::Code::Jmp_rm64
                || decoded.len() as u64 != instruction.len()
                || decoder.can_decode()
                || decoded.op0_kind() != iced_x86::OpKind::Memory
                || decoded.memory_base() != iced_x86::Register::None
                || !decoded.memory_index().is_gpr64()
                || decoded.memory_index_scale() != 8
                || decoded.segment_prefix() != iced_x86::Register::None
                || decoded.has_lock_prefix()
                || decoded.has_rep_prefix()
                || decoded.has_repne_prefix()
                || constants.displacement_size() != 4
                || instruction
                    .start()
                    .checked_add(constants.displacement_offset() as u64)
                    != Some(source.displacement().start())
                || i128::from(decoded.memory_displacement64() as i64) != field.target
            {
                return Err(carrier::Error::OutputInvariant);
            }
            let generated_start = field
                .offset
                .checked_sub(constants.displacement_offset() as u64)
                .ok_or(carrier::Error::OutputInvariant)?;
            let start =
                usize::try_from(generated_start).map_err(|_| carrier::Error::OutputInvariant)?;
            let tail = bytes.get(start..).ok_or(carrier::Error::OutputInvariant)?;
            let pc = image
                .address()
                .checked_add(generated_start)
                .ok_or(carrier::Error::OutputInvariant)?;
            let mut generated_decoder = li2core::x86::decoder64(tail, pc);
            let generated = generated_decoder.decode();
            let emitted_constants = generated_decoder.get_constant_offsets(&generated);
            if generated.code() != decoded.code()
                || generated.len() != decoded.len()
                || generated.op0_kind() != decoded.op0_kind()
                || generated.memory_base() != decoded.memory_base()
                || generated.memory_index() != decoded.memory_index()
                || generated.memory_index_scale() != decoded.memory_index_scale()
                || generated.memory_displ_size() != decoded.memory_displ_size()
                || generated.memory_displacement64() != decoded.memory_displacement64()
                || generated.segment_prefix() != decoded.segment_prefix()
                || generated.has_lock_prefix() != decoded.has_lock_prefix()
                || generated.has_rep_prefix() != decoded.has_rep_prefix()
                || generated.has_repne_prefix() != decoded.has_repne_prefix()
                || emitted_constants.displacement_offset() != constants.displacement_offset()
                || emitted_constants.displacement_size() != 4
            {
                return Err(carrier::Error::OutputInvariant);
            }
            let file = crate::translate(original, source.displacement().start(), 4)
                .map_err(|_| carrier::Error::OutputInvariant)?;
            if !dependencies
                .iter()
                .any(|range| range.start().0 <= file.start().0 && range.end().0 >= file.end().0)
            {
                return Err(carrier::Error::OutputInvariant);
            }
            dynamic.check_source_ranges(&[file])?;
        }
        image
            .metadata()
            .validate_fixed_image(
                binding.identity(),
                binding.domain(),
                0,
                image.address(),
                bytes,
            )
            .map_err(|_| carrier::Error::OutputInvariant)?;
    }
    Ok(())
}

// Only the named group route uses this identity. Both portable and embedded
// metadata bind the immutable complete partition and its explicit group tactic.
pub(crate) fn grouped_binding_policy(
    binding: FixedImageBinding,
    selection: ContentId,
    grouping: ContentId,
) -> Vec<u8> {
    let old = binding_policy(binding, selection);
    let text = std::str::from_utf8(&old).expect("fixed binding is ASCII");
    let mut bytes = text.replacen(
        "planner_profile\twhole-program-packed-overlapping-neighbors-4096\n",
        &format!("planner_profile\t{}\nsingleton_planner_profile\twhole-program-packed-overlapping-neighbors-4096\n", crate::grouped_artifact_frontend::GROUPED_PROFILE), 1,
    ).into_bytes();
    bytes.extend_from_slice(
        format!(
            "grouped_profile\t{}\ngrouping_policy_sha256\t{}\n",
            crate::grouped_artifact_frontend::GROUPED_PROFILE,
            ledger::hex(&grouping.0),
        )
        .as_bytes(),
    );
    bytes
}
