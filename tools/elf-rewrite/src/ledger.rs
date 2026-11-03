//! Versioned inspectable records. Free-form producer roles/diagnostics are hex.
use crate::carrier::{self, elf64::FileRange};
use crate::model::{self, Error, Selection, SiteReport};
use formats::ContentId;
use li2core::composition::Composition;
use li2core::contracts::{EntryObligation, PlanKind};
use li2core::emission::{ArtifactPlan, ArtifactRequirement};
use li2core::trampoline::SavedExtendedStateFormat;
use std::collections::BTreeMap;
use std::fmt::Write as _;

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn target(s: &Selection) -> Vec<u8> {
    let state = s.target;
    let kind = if state.format() == SavedExtendedStateFormat::FXSAVE64 {
        "fxsave64"
    } else {
        "xsave64-standard"
    };
    let mut out = format!(
        "LI2TARGET\t1\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\npage_bytes\t4096\nbias_domain\t{}\nformat\t{}\nallocation_bytes\t{}\nimage_bytes\t{}\nxcr0_mask\t{}\nqualification_complete\tfalse\n",
        s.bias_domain,
        kind,
        state.len(),
        state.image_len(),
        state.mask()
    );
    for c in state.components() {
        writeln!(
            &mut out,
            "component\t{}\t{}\t{}",
            c.xfeature(),
            c.offset(),
            c.size()
        )
        .unwrap();
    }
    out.into_bytes()
}
pub(crate) fn plans(
    s: &Selection,
    plans: &[(u64, ArtifactPlan)],
    composition: &Composition,
    deps: &[FileRange],
) -> Result<Vec<u8>, Error> {
    let views: Vec<_> = plans.iter().map(|(id, plan)| (*id, plan)).collect();
    plans_view(s, &views, composition, deps)
}
pub(crate) fn plans_view(
    s: &Selection,
    plans: &[(u64, &ArtifactPlan)],
    composition: &Composition,
    deps: &[FileRange],
) -> Result<Vec<u8>, Error> {
    Ok(plans_view_encoded(s, plans, composition, deps, None)?.ledger)
}
pub(crate) fn plans_view_encoded(
    s: &Selection,
    plans: &[(u64, &ArtifactPlan)],
    composition: &Composition,
    deps: &[FileRange],
    limits: Option<crate::ledger_codec::Limits>,
) -> Result<crate::ledger_codec::EncodedPlan, Error> {
    let mut out = crate::ledger_codec::PlanWriter::new(
        format!(
            "LI2LEDGER\t1\noriginal_sha256\t{}\nselection_sha256\t{}\nbias_policy\tcommon-additive-module-relative-v1\nbias_domain\t{}\nqualification_complete\tfalse\nexecution_authority\tnone\ngrouping\tseparate-backing-only\nrequirement\t0\t101\tdeclared-entry-completeness-not-proven\nunresolved\tloader-abi-cpu-unwind-cet\n",
            hex(&s.original.0),
            hex(&ContentId::of(&s.manifest).0),
            s.bias_domain
        ),
        limits,
    );
    for hook in &s.hooks {
        writeln!(
            &mut out,
            "hook\t{}\t{}\t{}\t{}",
            hook.id,
            hook.pc,
            hook.length,
            hex(&hook.expected.0)
        )
        .unwrap();
    }
    let mut image_id = 0;
    for (site, plan) in plans {
        for (step_id, step) in plan.source_steps().iter().enumerate() {
            let p = step.parts();
            let kind = match &p.kind {
                PlanKind::Relocation => "relocation",
                PlanKind::GeneralizedPun(_) => "generalized-pun",
                PlanKind::PrefixedPun(_) => "prefixed-pun",
            };
            writeln!(
                &mut out,
                "step\t{site}\t{step_id}\t{kind}\t{}\t{}\t{}\t{}",
                p.logical_pc,
                p.physical_pc,
                p.displaced.start(),
                p.displaced.end()
            )
            .unwrap();
            writeln!(
                &mut out,
                "live-prerequisites-not-receipts\t{site}\t{step_id}\t{}\t{}\t{}",
                p.requirements.quiescent, p.requirements.sync_core, p.requirements.sigill_router
            )
            .unwrap();
            out.reads(*site, step_id, &p.reads);
            for write in &p.writes {
                writeln!(
                    &mut out,
                    "semantic-write\t{site}\t{step_id}\t{}\t{}",
                    write.address,
                    hex(&write.bytes)
                )
                .unwrap();
            }
            let store = match &p.kind {
                PlanKind::GeneralizedPun(p) => Some(&p.store),
                PlanKind::PrefixedPun(p) => Some(&p.store),
                _ => None,
            };
            if let Some(store) = store {
                writeln!(
                    &mut out,
                    "live-store-span\t{site}\t{step_id}\t{}\t{}",
                    store.address,
                    hex(&store.bytes)
                )
                .unwrap();
            }
            for obligation in &p.obligations {
                match obligation {
                    EntryObligation::Preserved(pc) => {
                        writeln!(&mut out, "entry-preserved\t{site}\t{step_id}\t{pc}")
                    }
                    EntryObligation::Routed(r) => writeln!(
                        &mut out,
                        "entry-router-required\t{site}\t{step_id}\t{}\t{}",
                        r.original, r.generated
                    ),
                    EntryObligation::Unresolved { .. } => {
                        return Err(Error::new("ledger", "core returned unresolved entry"));
                    }
                }
                .unwrap();
            }
            for a in &p.allocations {
                writeln!(
                    &mut out,
                    "allocation\t{site}\t{step_id}\t{}\t{}\t{}",
                    a.range.start(),
                    a.range.end(),
                    a.alignment
                )
                .unwrap();
            }
        }
        if let li2core::emission::ArtifactMetrics::Engine(
            _,
            li2core::engine::SelectedMetrics::Neighbor(g, _),
            _,
        ) = plan.metrics()
        {
            // Geometry is generation-bound plan evidence, never global PC authority.
            writeln!(
                &mut out,
                "source-relay-geometry-hex\t{site}\t{}",
                hex(format!("{g:?}").as_bytes())
            )
            .unwrap();
        }
        for image in plan.images() {
            if image.metadata().qualification_complete() {
                return Err(Error::new("ledger", "unexpected image readiness"));
            }
            writeln!(
                &mut out,
                "image\t{image_id}\t{site}\t{}\t{}\t{}\timage-{image_id:04}.bin",
                image.address(),
                image.bytes().len(),
                hex(&ContentId::of(image.bytes()).0)
            )
            .unwrap();
            for &(original, generated) in image.entry_routes() {
                writeln!(&mut out, "route\t{image_id}\t{original}\t{generated}").unwrap();
            }
            for &(original, generated) in image.instruction_boundaries() {
                writeln!(
                    &mut out,
                    "restored-boundary\t{image_id}\t{original}\t{generated}"
                )
                .unwrap();
            }
            for pc in image.program_counter_mappings() {
                writeln!(
                    &mut out,
                    "pc-range\t{image_id}\t{}\t{}\t{}",
                    pc.generated_start(),
                    pc.generated_end(),
                    pc.logical_address()
                )
                .unwrap();
            }
            if let Some(binding) = image.metadata().fixed_image() {
                image
                    .metadata()
                    .validate_fixed_image(
                        li2core::contracts::CodeIdentity {
                            source: li2core::contracts::SourceIdentity(s.original.0),
                            mapping: s.bias_domain,
                            generation: 1,
                        },
                        s.bias_domain,
                        0,
                        image.address(),
                        image.bytes(),
                    )
                    .map_err(|error| Error::new("fixed-field", error))?;
                writeln!(
                    &mut out,
                    "unmet-fixed-image-binding\t{image_id}\t{}\t{}\t{}\t{}\t{}",
                    hex(&binding.identity().source.0),
                    binding.identity().mapping,
                    binding.identity().generation,
                    binding.domain(),
                    binding.required_load_bias()
                )
                .unwrap();
            }
            for f in image.metadata().fields() {
                if let Some(source) = f.fixed_source {
                    writeln!(&mut out, "original-fixed-field\t{image_id}\t{}\t{}\t{}\tsigned32\tloader-ownership-required",
                        source.instruction().start(), source.instruction().len(), source.displacement().start()).unwrap();
                }
                let at = usize::try_from(f.offset).map_err(|e| Error::new("field", e))?;
                let end = at
                    .checked_add(f.width)
                    .ok_or_else(|| Error::new("field", "overflow"))?;
                let bytes = image
                    .bytes()
                    .get(at..end)
                    .ok_or_else(|| Error::new("field", "out of bounds"))?;
                let value = match bytes.len() {
                    1 => i128::from(i8::from_le_bytes(bytes.try_into().unwrap())),
                    4 => i128::from(i32::from_le_bytes(bytes.try_into().unwrap())),
                    8 => i128::from(i64::from_le_bytes(bytes.try_into().unwrap())),
                    _ => return Err(Error::new("field", "unsupported producer width")),
                };
                if f.bias_domain != s.bias_domain
                    || f.origin > image.bytes().len() as u64
                    || value
                        != if f.encoding == li2core::emission::ArtifactFieldEncoding::FixedSigned32
                        {
                            if image.metadata().fixed_image().is_none()
                                || f.origin != 0
                                || f.width != 4
                            {
                                return Err(Error::new(
                                    "field",
                                    "fixed field lacks binding/width/origin",
                                ));
                            }
                            f.target
                        } else {
                            f.target - i128::from(image.address()) - i128::from(f.origin)
                        }
                {
                    return Err(Error::new("field", "producer arithmetic/domain mismatch"));
                }
                writeln!(
                    &mut out,
                    "field\t{image_id}\t{}\t{}\t{:?}\t{}\t{}\t{}\t{}\t{}",
                    f.offset,
                    f.width,
                    f.encoding,
                    f.origin,
                    f.target,
                    f.bias_domain,
                    hex(f.role.as_bytes()),
                    hex(bytes)
                )
                .unwrap();
            }
            for r in image.metadata().requirements() {
                let (code, hook) = match r {
                    ArtifactRequirement::ArtifactIdentityAndAddressBinding => (1, 0),
                    ArtifactRequirement::TargetCpuAndStateAtEntry => (2, 0),
                    ArtifactRequirement::OriginalDynamicRelocationOwnership => (3, 0),
                    ArtifactRequirement::OriginalImmediatePointerProvenance => (4, 0),
                    ArtifactRequirement::HookAbiAndReadiness(h) => (5, *h),
                    ArtifactRequirement::EntryRouterBootstrap => (6, 0),
                    ArtifactRequirement::GeneratedUnwindInformation => (7, 0),
                    ArtifactRequirement::OriginalCodeAsDataContract => (8, 0),
                };
                writeln!(&mut out, "unmet-requirement\t{image_id}\t{code}\t{hook}").unwrap();
            }
            image_id += 1;
        }
    }
    for range in composition.locks() {
        writeln!(&mut out, "byte-lock\t{}\t{}", range.start(), range.end()).unwrap();
    }
    for range in deps {
        writeln!(
            &mut out,
            "original-file-dependency\t{}\t{}",
            range.start().0,
            range.end().0
        )
        .unwrap();
    }
    out.finish()
}
pub(crate) fn carrier(ledger: &mut Vec<u8>, output: &carrier::CarrierOutput) {
    let mut out = String::from("CARRIER-EXTENSION\t1\n");
    writeln!(
        &mut out,
        "candidate_sha256\t{}",
        hex(&ContentId::of(output.bytes()).0)
    )
    .unwrap();
    writeln!(
        &mut out,
        "new_load_pages\t{}\nphdr_file\t{}\t{}\nphdr_vaddr\t{}",
        output.new_load_pages,
        output.program_table.start().0,
        output.program_table.len(),
        output.program_table_vaddr.0
    )
    .unwrap();
    for (id, image) in output.images.iter().enumerate() {
        writeln!(
            &mut out,
            "elf-image\t{id}\t{}\t{}\t{}\t{}",
            image.entry.0,
            image.file.start().0,
            image.file.len(),
            image.program_header
        )
        .unwrap();
    }
    for change in output.changes() {
        let e = &change.edit;
        writeln!(
            &mut out,
            "elf-change\t{:?}\t{}\t{}\t{}",
            change.kind,
            e.offset.0,
            hex(&e.expected),
            hex(&e.replacement)
        )
        .unwrap();
    }
    for r in &output.dynamic.writes {
        writeln!(
            &mut out,
            "original-loader-write\t{:?}\t{}\t{}\t{}\t{}\t{}",
            r.table,
            r.record,
            r.kind,
            r.symbol,
            r.range.start().0,
            r.range.len()
        )
        .unwrap();
    }
    for r in &output.dynamic.symbol_references {
        writeln!(
            &mut out,
            "original-symbol-reference\t{:?}\t{}\t{}\t{}",
            r.table, r.record, r.kind, r.symbol
        )
        .unwrap();
    }
    for r in &output.dynamic.tables {
        writeln!(
            &mut out,
            "original-loader-table\t{}\t{}",
            r.start().0,
            r.len()
        )
        .unwrap();
    }
    for r in &output.dynamic.protected {
        writeln!(
            &mut out,
            "original-loader-protected\t{}\t{}",
            r.start().0,
            r.len()
        )
        .unwrap();
    }
    ledger.extend_from_slice(out.as_bytes());
}
// Additive serialization records. Existing image/elf-image rows retain caller
// order and identity; only a generated RX header may be shared by its members.
pub(crate) fn packed_rx_runs(
    ledger: &mut Vec<u8>,
    output: &carrier::CarrierOutput,
) -> Result<(), Error> {
    use carrier::elf64::{Elf64, ParseLimits, SegmentType};
    let elf = Elf64::parse(
        output.bytes(),
        ParseLimits {
            max_program_headers: 1170,
        },
    )
    .map_err(|e| Error::new("rx-run-ledger", e))?;
    let mut groups = BTreeMap::<usize, Vec<usize>>::new();
    for (id, image) in output.images.iter().enumerate() {
        groups.entry(image.program_header).or_default().push(id);
    }
    let mut out = format!(
        "RX-RUN-EXTENSION\t1\ncarrier_layout\tlinux-adjacent-generated-rx-runs-v1\nrx_run_count\t{}\nrx_run_image_count\t{}\n",
        groups.len(),
        output.images.len(),
    );
    for (run, (header, members)) in groups.iter().enumerate() {
        let ph = elf
            .program_headers()
            .get(*header)
            .ok_or_else(|| Error::new("rx-run-ledger", "missing generated header"))?;
        if output.original_to_output_header.contains(header)
            || *header == output.carrier_index
            || ph.kind != SegmentType::Load
            || ph.flags.0 != 5
            || ph.alignment != 4096
            || ph.vaddr.0 & 4095 != 0
            || ph.offset.0 & 4095 != 0
            || ph.file_size != ph.memory_size
        {
            return Err(Error::new("rx-run-ledger", "not a generated RX run"));
        }
        writeln!(
            &mut out,
            "rx-run\t{run}\t{header}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            ph.offset.0,
            ph.file_size,
            ph.vaddr.0,
            ph.memory_size,
            ph.flags.0,
            ph.alignment,
            members.len()
        )
        .unwrap();
        for &id in members {
            let image = &output.images[id];
            let mapping = elf
                .file_to_virtual(image.file.start(), image.file.len())
                .map_err(|e| Error::new("rx-run-ledger", e))?;
            if mapping.program_header != *header || mapping.virtual_range.start() != image.entry {
                return Err(Error::new("rx-run-ledger", "image/header mapping mismatch"));
            }
            writeln!(
                &mut out,
                "rx-run-member\t{id}\t{run}\t{header}\t{}\t{}\t{}",
                image.entry.0,
                image.file.start().0,
                image.file.len()
            )
            .unwrap();
        }
    }
    ledger.extend_from_slice(out.as_bytes());
    Ok(())
}
pub(crate) fn report(s: &Selection, reports: &[SiteReport], complete: bool) -> Vec<u8> {
    let mut out = format!(
        "LI2REPORT\t1\noriginal_sha256\t{}\nselection_sha256\t{}\ncandidate_complete\t{complete}\nqualification_complete\tfalse\nsite\tpc\tfile_offset\tlength\tcore_tactic\tcandidate_emitted\trefusal_code\tstage\tdetail_hex\n",
        hex(&s.original.0),
        hex(&ContentId::of(&s.manifest).0)
    );
    for r in reports {
        writeln!(
            &mut out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            r.id,
            r.pc,
            r.file_offset,
            r.length,
            r.core_tactic.map(model::tactic_name).unwrap_or("none"),
            r.candidate_emitted,
            r.refusal_code
                .map(|n| n.to_string())
                .unwrap_or_else(|| "none".into()),
            r.refusal.as_ref().map(|e| e.stage).unwrap_or("none"),
            r.refusal
                .as_ref()
                .map(|e| hex(e.detail.as_bytes()))
                .unwrap_or_default()
        )
        .unwrap();
    }
    out.into_bytes()
}
pub(crate) fn index(original: ContentId, files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut out = format!(
        "LI2BUNDLE\t1\noriginal_sha256\t{}\nqualification_complete\tfalse\nconsumer_action\tRuntimeScan-while-gated-until-qualified\n",
        hex(&original.0)
    );
    for (name, bytes) in files {
        writeln!(
            &mut out,
            "file\t{name}\t{}\t{}",
            bytes.len(),
            hex(&ContentId::of(bytes).0)
        )
        .unwrap();
    }
    out.into_bytes()
}

// The legacy ledger stays literal. Only the new frontend calls this extension;
// a direct-only plan keeps the exact old ledger, while a wrapper exposes E
// separately from storage B. Empty padding is represented by equal endpoints.
pub(crate) fn plans_with_entry_veneers(
    s: &Selection,
    accepted: &[(u64, ArtifactPlan)],
    composition: &Composition,
    deps: &[FileRange],
) -> Result<Vec<u8>, Error> {
    let views: Vec<_> = accepted.iter().map(|(id, plan)| (*id, plan)).collect();
    plans_with_entry_veneers_view(s, &views, composition, deps)
}
pub(crate) fn plans_with_entry_veneers_view(
    s: &Selection,
    accepted: &[(u64, &ArtifactPlan)],
    composition: &Composition,
    deps: &[FileRange],
) -> Result<Vec<u8>, Error> {
    let mut out = plans_view(s, accepted, composition, deps)?;
    append_entry_veneers(&mut out, accepted)?;
    Ok(out)
}
pub(crate) fn append_entry_veneers(
    out: &mut Vec<u8>,
    accepted: &[(u64, &ArtifactPlan)],
) -> Result<(), Error> {
    let mut extension = String::new();
    let mut image_id = 0;
    for (site, plan) in accepted {
        for image in plan.images() {
            if let Some(layout) = image.entry_veneer() {
                let storage = layout.storage_address();
                let entry = layout.entry_address();
                let body_len = layout.body_len();
                let bound = layout.size_bound();
                let offset = entry
                    .checked_sub(storage)
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or_else(|| Error::new("entry-veneer-ledger", "entry offset"))?;
                let body_end = storage
                    .checked_add(body_len as u64)
                    .ok_or_else(|| Error::new("entry-veneer-ledger", "body end"))?;
                let end = entry
                    .checked_add(5)
                    .ok_or_else(|| Error::new("entry-veneer-ledger", "veneer end"))?;
                if storage != image.address()
                    || entry != image.entry_address()
                    || storage % 4096 != 0
                    || offset > 4091
                    || body_len == 0
                    || body_len > bound
                    || bound > offset
                    || image.bytes().len() != offset + 5
                    || layout.padding_range() != (body_end, entry)
                    || layout.veneer_range() != (entry, end)
                    || image.bytes()[body_len..offset]
                        .iter()
                        .any(|&byte| byte != 0xcc)
                    || image.bytes()[offset] != 0xe9
                {
                    return Err(Error::new("entry-veneer-ledger", "storage partition"));
                }
                let displacement =
                    i32::from_le_bytes(image.bytes()[offset + 1..offset + 5].try_into().unwrap());
                if i128::from(end) + i128::from(displacement) != i128::from(storage) {
                    return Err(Error::new("entry-veneer-ledger", "entry transfer"));
                }
                if extension.is_empty() {
                    extension.push_str("ENTRY-VENEER-EXTENSION\t1\n");
                }
                writeln!(
                    extension,
                    "entry-veneer\t{image_id}\t{site}\t{storage}\t{entry}\t{body_len}\t{bound}\t{}\t{}\t{body_end}\t{entry}\tcc\t{entry}\t{end}\t{storage}",
                    image.bytes().len(), hex(&ContentId::of(image.bytes()).0),
                ).unwrap();
            } else if image.entry_address() != image.address() {
                return Err(Error::new("entry-veneer-ledger", "direct image entry"));
            }
            image_id += 1;
        }
    }
    out.extend_from_slice(extension.as_bytes());
    Ok(())
}

pub(crate) fn fixed_binding(ledger: &mut Vec<u8>, binding: li2core::emission::FixedImageBinding) {
    let text = std::str::from_utf8(ledger).expect("producer ledger is ASCII");
    let old = "bias_policy\tcommon-additive-module-relative-v1\n";
    assert_eq!(text.matches(old).count(), 1);
    *ledger = text
        .replacen(
            old,
            "bias_policy\tfixed-exec-zero-bias-indexed-jump32-v1\n",
            1,
        )
        .into_bytes();
    ledger.extend_from_slice(
        format!(
            "required-fixed-source\t{}\t{}\t{}\t{}\t0\n",
            hex(&binding.identity().source.0),
            binding.identity().mapping,
            binding.identity().generation,
            binding.domain()
        )
        .as_bytes(),
    );
}

// A distinct top-level grammar prevents old single-site readers from silently
// treating the primary logical_pc as the complete group population.
pub(crate) fn grouped_plans(
    s: &Selection,
    accepted: &[(u64, &ArtifactPlan)],
    composition: &Composition,
    deps: &[FileRange],
    associations: &[u8],
) -> Result<Vec<u8>, Error> {
    let bytes = plans_with_entry_veneers_view(s, accepted, composition, deps)?;
    apply_grouped_associations(bytes, associations, 1)
}
pub(crate) fn apply_grouped_associations(
    bytes: Vec<u8>,
    associations: &[u8],
    version: u8,
) -> Result<Vec<u8>, Error> {
    let (old_header, new_header) = match version {
        1 => ("LI2LEDGER\t1\n", "LI2GROUPED-LEDGER\t1\n"),
        2 => ("LI2LEDGER\t2\n", "LI2GROUPED-LEDGER\t2\n"),
        _ => return Err(Error::new("grouped-ledger", "unsupported storage version")),
    };
    let text = std::str::from_utf8(&bytes).map_err(|e| Error::new("grouped-ledger", e))?;
    if !text.starts_with(old_header)
        || text.matches("grouping\tseparate-backing-only\n").count() != 1
    {
        return Err(Error::new("grouped-ledger", "legacy grammar mismatch"));
    }
    let mut out = text
        .replacen(old_header, new_header, 1)
        .replacen(
            "grouping\tseparate-backing-only\n",
            "grouping\tcomplete-selected-block-units-v1\n",
            1,
        )
        .into_bytes();
    out.extend_from_slice(associations);
    Ok(out)
}
