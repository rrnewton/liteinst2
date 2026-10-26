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
    let mut out = format!(
        "LI2LEDGER\t1\noriginal_sha256\t{}\nselection_sha256\t{}\nbias_policy\tcommon-additive-module-relative-v1\nbias_domain\t{}\nqualification_complete\tfalse\nexecution_authority\tnone\ngrouping\tseparate-backing-only\nrequirement\t0\t101\tdeclared-entry-completeness-not-proven\nunresolved\tloader-abi-cpu-unwind-cet\n",
        hex(&s.original.0),
        hex(&ContentId::of(&s.manifest).0),
        s.bias_domain
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
            for read in &p.reads {
                writeln!(
                    &mut out,
                    "step-read\t{site}\t{step_id}\t{}\t{}",
                    read.address,
                    hex(&read.bytes)
                )
                .unwrap();
            }
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
            for f in image.metadata().fields() {
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
                    || value != f.target - i128::from(image.address()) - i128::from(f.origin)
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
    Ok(out.into_bytes())
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
