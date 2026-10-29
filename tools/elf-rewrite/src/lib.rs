//! Offline ELF candidate construction. Runtime qualification remains separate.
//! No live callback pointer, executable mapping, publication receipt, or admission.
#![forbid(unsafe_code)]
pub mod carrier;
pub mod disassembly;
mod ledger;
pub mod model;
mod neighbor_catalogue;
pub mod selection;

use carrier::elf64::{Elf64, ElfVaddr, FileRange, ParseLimits, SegmentType, Storage};
use formats::{Compatibility, ContentId, Metadata, Outcome, Site};
use li2core::composition::Composition;
use li2core::contracts::*;
use li2core::emission::*;
use li2core::engine::{self, EnginePolicy};
use li2core::neighbor::NeighborSearch;
use li2core::quiescent::TacticPolicy;
use li2core::scanner::InstructionScanner;
pub use model::{Error, SiteReport};
use model::{SelectedSite, Selection};
use std::collections::BTreeMap;

/// Complete output file set. Candidate bytes are never executable authority.
#[derive(Clone, Debug)]
pub struct Product {
    files: BTreeMap<String, Vec<u8>>,
    reports: Vec<SiteReport>,
    complete: bool,
}
impl Product {
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }
    pub fn reports(&self) -> &[SiteReport] {
        &self.reports
    }
    pub fn candidate_complete(&self) -> bool {
        self.complete
    }
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}

/// Produces metadata and an exact full-selection report. Only a complete source,
/// placement and carrier result also produces candidate ELF/sparse/image files.
/// All inputs remain borrowed immutable bytes. Caller must keep output gated.
pub fn prepare(original: &[u8], manifest: &[u8]) -> Result<Product, Error> {
    prepare_mode(original, manifest, false)
}

/// Opt-in structural preparation with separately declared foreign T3 owners.
/// The input selection must provide agreeing complete function/head/resume
/// declarations and finite direct-control-flow blocks. Foreign victims remain
/// auxiliary operations, never additional requested hooks. The same engine,
/// original budgets and final all-sites carrier transaction remain mandatory.
/// Qualification is still incomplete: this does not authorize execution.
pub fn prepare_with_owned_neighbors(original: &[u8], manifest: &[u8]) -> Result<Product, Error> {
    prepare_mode(original, manifest, true)
}

/// Artifact-only code-region preparation, distinct from recovered functions.
/// The sealed importer supplies all verified heads and private-image resumes;
/// owned-neighbor/function catalogue planning is deliberately unavailable here.
/// Every requested jump shares the existing all-or-nothing source/carrier pass.
pub fn prepare_disassembly(
    original: &[u8],
    selected: &disassembly::DisassemblySelection,
) -> Result<Product, Error> {
    let mut product = prepare_selection_mode(original, selected.selection.clone(), false)?;
    product.files.remove("bundle-index.tsv");
    product.files.extend(selected.files.clone());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.selection.original, &product.files),
    );
    Ok(product)
}

fn prepare_mode(original: &[u8], manifest: &[u8], owned_neighbors: bool) -> Result<Product, Error> {
    let selection = selection::parse(manifest)?;
    prepare_selection_mode(original, selection, owned_neighbors)
}

fn prepare_selection_mode(
    original: &[u8],
    selection: Selection,
    owned_neighbors: bool,
) -> Result<Product, Error> {
    let s = &selection;
    if original.len() > s.limits.input_bytes {
        return Err(Error::new("input-limit", original.len()));
    }
    if ContentId::of(original) != s.original {
        return Err(Error::new("original-identity", "SHA-256 mismatch"));
    }
    let elf = Elf64::parse(
        original,
        ParseLimits {
            max_program_headers: s.limits.program_headers,
        },
    )
    .map_err(|e| Error::new("elf", e))?;
    elf.check_load_page_congruence(4096)
        .map_err(|e| Error::new("elf-page", e))?;
    let dynamic = carrier::dynamic::inspect(&elf, carrier::dynamic::Limits::default())
        .map_err(|e| Error::new("dynamic", e))?;
    let identity = CodeIdentity {
        source: SourceIdentity(s.original.0),
        mapping: s.bias_domain,
        generation: 1,
    };
    let mut occupied = Vec::new();
    for load in elf.segments(SegmentType::Load) {
        if load.memory_size == 0 {
            continue;
        }
        let end = round_page(
            load.vaddr
                .0
                .checked_add(load.memory_size)
                .ok_or_else(|| Error::new("elf-range", "overflow"))?,
        )?;
        occupied.push(addr(load.vaddr.0 & !4095, end - (load.vaddr.0 & !4095))?);
    }
    // Prospective PHDR cap bounds the R-only carrier payload/table reservation.
    let carrier_reserve = round_page(
        (s.limits.program_headers as u64)
            .checked_mul(56)
            .and_then(|v| v.checked_add(128))
            .ok_or_else(|| Error::new("carrier-reservation", "overflow"))?,
    )?;
    occupied.push(addr(s.carrier_pc, carrier_reserve)?);
    let mut dependencies = Vec::new();
    for hook in &s.hooks {
        let file = translate(&elf, hook.pc, hook.length as u64)?;
        let bytes = elf
            .executable_bytes(ElfVaddr(hook.pc), hook.length as u64)
            .map_err(|e| Error::new("hook-owner", e))?;
        if ContentId::of(bytes) != hook.expected {
            return Err(Error::new("hook-identity", hook.id));
        }
        dynamic
            .check_source_ranges(&[file])
            .map_err(|e| Error::new("hook-relocation", e))?;
        dependencies.push(file);
    }
    let snapshots = original_snapshots(&elf, &s.sites)?;
    let mut composition =
        Composition::new(identity, snapshots).map_err(|e| Error::new("composition-original", e))?;
    let mut reports: Vec<_> = s
        .sites
        .iter()
        .map(|site| SiteReport {
            id: site.id,
            pc: site.pc,
            file_offset: site.file_offset,
            length: site.length,
            core_tactic: None,
            candidate_emitted: false,
            refusal: None,
            refusal_code: None,
            diagnostics: String::new(),
        })
        .collect();
    let mut ordered: Vec<_> = (0..s.sites.len()).collect();
    ordered.sort_by_key(|&i| std::cmp::Reverse(s.sites[i].pc));
    let mut accepted = Vec::<(u64, ArtifactPlan)>::new();
    let mut image_count = 0_usize;
    let mut image_bytes = 0_usize;
    let mut allocation_pages = 0_u64;
    for index in ordered {
        let site = &s.sites[index];
        let report = &mut reports[index];
        let prepared = (|| {
            validate_site(&elf, site)?;
            let code = elf
                .executable_bytes(ElfVaddr(site.snapshot.start()), site.snapshot.len())
                .map_err(|e| Error::new("snapshot", e))?;
            let entries = LegalEntrySet {
                identity,
                scope: site.function,
                provenance: EntryProvenance::Declared(format!(
                    "selection provenance SHA-256 {}",
                    ledger::hex(&site.provenance.0)
                )),
                completeness: site.completeness,
                entries: site.heads.clone(),
                resumes: site.resumes.clone(),
            };
            let hook = s
                .hooks
                .iter()
                .find(|h| h.id == site.hook)
                .ok_or_else(|| Error::new("hook", "missing"))?;
            let emission = ArtifactEmission::new(
                TargetProfile::linux_x86_64_legacy_evex(s.target, s.bias_domain)
                    .map_err(|e| Error::new("target", e))?,
                SymbolicHook {
                    identity: hook.id,
                    address: Some(hook.pc),
                },
                occupied.clone(),
            );
            let request = ArtifactRequest {
                site: PlanningSite {
                    identity,
                    code,
                    base_address: site.snapshot.start(),
                    function: site.function,
                    block: site.block,
                    logical_pc: site.pc,
                    entries: &entries,
                    semantics: site.semantics,
                    allocation: &site.selected_allocation,
                    search: site.search,
                },
                emission: &emission,
            };
            let policy = EnginePolicy {
                forced: site.forced,
                successor_puns: TacticPolicy::PreferGeneralizedPun,
                neighbor: NeighborSearch {
                    forced_victim: site.forced_victim,
                    max_victims: site.max_victims,
                    max_pairs: site.max_pairs,
                },
                bundle: li2core::bundle::BundleBudget {
                    max_steps: 2,
                    max_mappings: s.limits.images,
                    max_virtual_bytes: s.limits.new_load_pages.saturating_mul(4096),
                    max_backing_bytes: s.limits.new_load_pages.saturating_mul(4096),
                    max_virtual_span: s.limits.virtual_span,
                },
            };
            let result = if owned_neighbors {
                let owners = neighbor_catalogue::collect(&elf, s, identity, site)?;
                let foreign: Vec<_> = owners.iter().map(|owner| owner.site(site)).collect();
                engine::plan_with_emission_after_with_foreign(
                    &request,
                    &composition,
                    &site.victim_allocation,
                    policy,
                    &foreign,
                )
            } else {
                engine::plan_with_emission_after(
                    &request,
                    &composition,
                    &site.victim_allocation,
                    policy,
                )
            };
            let plan = match result {
                Ok(plan) => plan,
                Err(failure) => {
                    report.refusal_code = Some(model::core_code(&failure.reason));
                    report.diagnostics = format!("{failure:#?}");
                    return Err(Error::new("core", failure.reason));
                }
            };
            report.diagnostics = format!("{:#?}", plan.metrics());
            let ArtifactMetrics::Engine(tactic, _, _) = plan.metrics() else {
                return Err(Error::new("core-invariant", "engine metric missing"));
            };
            report.core_tactic = Some(*tactic);
            if plan.qualification_complete() {
                return Err(Error::new(
                    "readiness-invariant",
                    "unexpected qualification",
                ));
            }
            let new_images = plan.images().count();
            let new_bytes = plan
                .images()
                .try_fold(0_usize, |n, i| n.checked_add(i.bytes().len()))
                .ok_or_else(|| Error::new("image-budget", "overflow"))?;
            let mut new_pages = 0_u64;
            let mut new_dependencies = Vec::new();
            let mut next = composition.clone();
            for step in plan.source_steps() {
                // T2/T3 steps intentionally read their preceding internal overlay.
                next.append(step)
                    .map_err(|e| Error::new("composition", e))?;
                for dependency in &step.parts().dependencies {
                    let file = translate(&elf, dependency.start(), dependency.len())?;
                    dynamic
                        .check_source_ranges(&[file])
                        .map_err(|e| Error::new("source-relocation", e))?;
                    new_dependencies.push(file);
                }
                for allocation in &step.parts().allocations {
                    new_pages = new_pages
                        .checked_add(allocation.range.len() / 4096)
                        .ok_or_else(|| Error::new("allocation-budget", "overflow"))?;
                }
            }
            if image_count
                .checked_add(new_images)
                .is_none_or(|v| v > s.limits.images)
                || image_bytes
                    .checked_add(new_bytes)
                    .is_none_or(|v| v > s.limits.image_bytes)
                || allocation_pages
                    .checked_add(new_pages)
                    .is_none_or(|v| v > s.limits.new_load_pages)
            {
                return Err(Error::new(
                    "aggregate-budget",
                    "complete selected set exceeds declared resources",
                ));
            }
            // Same-module hook contents are immutable dependencies too.
            for hook in &s.hooks {
                for bytes in next.final_bytes() {
                    let left = bytes.address.max(hook.pc);
                    let right = (bytes.address + bytes.bytes.len() as u64)
                        .min(hook.pc + hook.length as u64);
                    if left < right {
                        let actual = &bytes.bytes
                            [(left - bytes.address) as usize..(right - bytes.address) as usize];
                        if actual
                            != elf
                                .executable_bytes(ElfVaddr(left), right - left)
                                .map_err(|e| Error::new("hook-owner", e))?
                        {
                            return Err(Error::new(
                                "hook-ownership",
                                "source transformation changes hook",
                            ));
                        }
                    }
                }
            }
            for step in plan.source_steps() {
                occupied.extend(step.parts().allocations.iter().map(|a| a.range));
            }
            dependencies.extend(new_dependencies);
            image_count += new_images;
            image_bytes += new_bytes;
            allocation_pages += new_pages;
            composition = next;
            Ok(plan)
        })();
        match prepared {
            Ok(plan) => accepted.push((site.id, plan)),
            Err(error) => {
                report.refusal = Some(error);
                if report.refusal_code.is_none() {
                    report.refusal_code = Some(10_001);
                }
            }
        }
    }
    let mut files = BTreeMap::new();
    if owned_neighbors {
        files.insert(
            "planning-profile.tsv".into(),
            b"LI2PLANNING\t1\nprofile\towned-foreign-neighbors-v1\nqualification_complete\tfalse\n"
                .to_vec(),
        );
    }
    let profile = ledger::target(s);
    files.insert("target.tsv".into(), profile.clone());
    files.insert("selection.txt".into(), s.manifest.clone());
    let mut ledger = ledger::plans(s, &accepted, &composition, &dependencies)?;
    files.insert("plan-ledger.tsv".into(), ledger.clone());
    for (index, image) in accepted.iter().flat_map(|(_, p)| p.images()).enumerate() {
        // Planned bytes remain inspectable even if another site refuses. They
        // are not an executable carrier or an applicable sparse transaction.
        files.insert(format!("image-{index:04}.bin"), image.bytes().to_vec());
    }
    let edits = final_edits(&elf, &composition)?;
    let mut candidate = None;
    let mut sparse = None;
    if reports.iter().all(|r| r.refusal.is_none()) {
        let initial_meta = make_metadata(original, s, &reports, true, &profile)?
            .encode(formats::Limits::default())
            .map_err(|e| Error::new("metadata", e))?;
        let mut payload = b"LI2TOOL-CANDIDATE-UNREADY-V1\0".to_vec();
        payload.extend_from_slice(&ContentId::of(&initial_meta).0);
        payload.extend_from_slice(&ContentId::of(&ledger).0);
        let images: Vec<_> = accepted
            .iter()
            .flat_map(|(_, p)| p.images())
            .map(|i| carrier::RxImage {
                entry: ElfVaddr(i.address()),
                bytes: i.bytes().to_vec(),
            })
            .collect();
        let write_carrier = if owned_neighbors
            && elf.header().object_type == carrier::elf64::ObjectType::Executable
        {
            carrier::append_exec_carrier_with_interleaved_images
        } else {
            carrier::append_carrier_with_images
        };
        let result = write_carrier(
            &elf,
            carrier::ImageRequest {
                carrier_vaddr: ElfVaddr(s.carrier_pc),
                payload: &payload,
                images: &images,
                source_dependencies: &dependencies,
            },
            &edits,
            carrier::ImagePolicy {
                layout: carrier::CarrierPolicy {
                    page_size: 4096,
                    user_address_limit: 1 << 47,
                    max_added_file_bytes: s.limits.added_file_bytes,
                    max_output_file_bytes: s.limits.output_bytes,
                    max_program_headers: s.limits.program_headers,
                    max_virtual_span: s.limits.virtual_span,
                },
                dynamic: carrier::dynamic::Limits::default(),
                max_images: s.limits.images,
                max_new_load_pages: s.limits.new_load_pages,
            },
        );
        match result {
            Ok(output) => {
                // Same authenticated original-relative edits back the sparse output;
                // ELF header/appended bytes stay carrier-only, explicitly recorded.
                let pages = formats::sparse::SparsePages::build(
                    original,
                    edits
                        .iter()
                        .map(|e| formats::sparse::FileEdit {
                            offset: e.offset.0,
                            expected: e.expected.clone(),
                            replacement: e.replacement.clone(),
                        })
                        .collect(),
                    sparse_limits(s),
                )
                .map_err(|e| Error::new("sparse", e))?;
                sparse = Some(
                    formats::sparse_wire::encode(
                        &pages,
                        formats::sparse_wire::Limits {
                            bytes: s.limits.output_bytes as usize,
                            content: sparse_limits(s),
                        },
                    )
                    .map_err(|e| Error::new("sparse-wire", e))?,
                );
                ledger::carrier(&mut ledger, &output);
                candidate = Some(output.bytes().to_vec());
                for report in &mut reports {
                    report.candidate_emitted = true;
                }
            }
            Err(error) => {
                for report in &mut reports {
                    report.refusal = Some(Error::new("carrier", &error));
                    report.refusal_code = Some(10_002);
                }
            }
        }
    }
    let complete = candidate.is_some();
    if !complete {
        for report in &mut reports {
            if report.refusal.is_none() {
                report.refusal = Some(Error::new(
                    "atomic-selection",
                    "another requested site or carrier failed; no partial candidate",
                ));
                report.refusal_code = Some(10_003);
            }
        }
    }
    let metadata = make_metadata(original, s, &reports, false, &profile)?;
    files.insert(
        "metadata.li2meta".into(),
        metadata
            .encode(formats::Limits::default())
            .map_err(|e| Error::new("metadata", e))?,
    );
    files.insert("ledger.tsv".into(), ledger);
    files.insert("report.tsv".into(), ledger::report(s, &reports, complete));
    for report in &reports {
        files.insert(
            format!("site-{}.diagnostics.txt", report.id),
            report.diagnostics.as_bytes().to_vec(),
        );
    }
    if let Some(bytes) = candidate {
        files.insert("candidate.elf".into(), bytes);
    }
    if let Some(bytes) = sparse {
        files.insert("source.li2sparse".into(), bytes);
    }
    files.insert("bundle-index.tsv".into(), ledger::index(s.original, &files));
    Ok(Product {
        files,
        reports,
        complete,
    })
}

fn validate_site(elf: &Elf64<'_>, s: &SelectedSite) -> Result<(), Error> {
    if !s.snapshot.covers(s.function) || !s.function.covers(s.block) || !s.block.contains(s.pc) {
        return Err(Error::new("site-geometry", s.id));
    }
    let file = translate(elf, s.pc, u64::from(s.length))?;
    if file.start().0 != s.file_offset {
        return Err(Error::new("site-file-offset", s.id));
    }
    let bytes = elf
        .executable_bytes(ElfVaddr(s.snapshot.start()), s.snapshot.len())
        .map_err(|e| Error::new("snapshot", e))?;
    let scan = InstructionScanner::default()
        .scan(bytes, s.snapshot.start())
        .map_err(|e| Error::new("decode", e))?;
    if !scan
        .instructions()
        .iter()
        .any(|i| i.address() == s.pc && i.len() == usize::from(s.length))
    {
        return Err(Error::new(
            "selected-instruction",
            "manifest PC/length differs from original decode",
        ));
    }
    Ok(())
}
fn original_snapshots(
    elf: &Elf64<'_>,
    sites: &[SelectedSite],
) -> Result<Vec<ExpectedBytes>, Error> {
    let mut ranges: Vec<_> = sites
        .iter()
        .map(|s| (s.snapshot.start(), s.snapshot.end()))
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start < last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
        .into_iter()
        .map(|(start, end)| {
            Ok(ExpectedBytes {
                address: start,
                bytes: elf
                    .executable_bytes(ElfVaddr(start), end - start)
                    .map_err(|e| Error::new("snapshot-owner", e))?
                    .to_vec(),
            })
        })
        .collect()
}
fn translate(elf: &Elf64<'_>, pc: u64, len: u64) -> Result<FileRange, Error> {
    let mapped = elf
        .virtual_to_storage(ElfVaddr(pc), len)
        .map_err(|e| Error::new("source-translation", e))?;
    let Storage::FileBacked(file) = mapped.storage else {
        return Err(Error::new("source-translation", "zero fill"));
    };
    if !mapped.flags.readable() || !mapped.flags.executable() || mapped.flags.writable() {
        return Err(Error {
            stage: "source-protection",
            detail: "requires original RX".into(),
        });
    }
    let inverse = elf
        .file_to_virtual(file.start(), file.len())
        .map_err(|e| Error::new("inverse-translation", e))?;
    if inverse.virtual_range.start().0 != pc {
        return Err(Error::new("inverse-translation", "different owner"));
    }
    Ok(file)
}
fn final_edits(
    elf: &Elf64<'_>,
    composition: &Composition,
) -> Result<Vec<carrier::DeclaredEdit>, Error> {
    let mut result = Vec::new();
    for (before, after) in composition
        .originals()
        .iter()
        .zip(composition.final_bytes())
    {
        let mut at = 0;
        while at < before.bytes.len() {
            if before.bytes[at] == after.bytes[at] {
                at += 1;
                continue;
            }
            let start = at;
            while at < before.bytes.len() && before.bytes[at] != after.bytes[at] {
                at += 1;
            }
            let file = translate(elf, before.address + start as u64, (at - start) as u64)?;
            result.push(carrier::DeclaredEdit {
                offset: file.start(),
                expected: before.bytes[start..at].to_vec(),
                replacement: after.bytes[start..at].to_vec(),
            });
        }
    }
    result.sort_by_key(|e| e.offset);
    Ok(result)
}
fn make_metadata(
    original: &[u8],
    s: &Selection,
    reports: &[SiteReport],
    pretend_emitted: bool,
    profile: &[u8],
) -> Result<Metadata, Error> {
    let records = reports
        .iter()
        .map(|r| Site {
            id: r.id,
            original_pc: r.pc,
            file_offset: r.file_offset,
            length: r.length,
            outcome: if (r.candidate_emitted || pretend_emitted) && r.refusal.is_none() {
                Outcome::Rewritten(model::format_tactic(
                    r.core_tactic.expect("successful core tactic"),
                ))
            } else {
                Outcome::Refused(r.refusal_code.unwrap_or(10_003))
            },
        })
        .collect();
    let metadata = Metadata::new(
        original,
        ContentId::of(&s.manifest),
        Compatibility {
            planner: CONTRACT_VERSION,
            encoder: 1,
            hook_abi: 1,
            arena: 1,
            target: ContentId::of(profile),
            binding: ContentId::of(&s.manifest),
        },
        records,
    )
    .map_err(|e| Error::new("metadata", e))?;
    metadata
        .verify_selection(
            ContentId::of(&s.manifest),
            &s.sites.iter().map(|s| s.id).collect::<Vec<_>>(),
        )
        .map_err(|e| Error::new("metadata-selection", e))?;
    Ok(metadata)
}
fn sparse_limits(s: &Selection) -> formats::sparse::Limits {
    formats::sparse::Limits {
        edits: s.limits.input_bytes,
        edited_bytes: s.limits.input_bytes,
        pages: s.limits.input_bytes.div_ceil(4096),
    }
}
fn addr(start: u64, len: u64) -> Result<AddressRange, Error> {
    AddressRange::new(
        start,
        usize::try_from(len).map_err(|e| Error::new("range", e))?,
    )
    .map_err(|e| Error::new("range", e))
}
fn round_page(n: u64) -> Result<u64, Error> {
    n.checked_add(4095)
        .map(|v| v & !4095)
        .ok_or_else(|| Error::new("round-page", "overflow"))
}
