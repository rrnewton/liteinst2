//! Offline ELF candidate construction. Runtime qualification remains separate.
//! No live callback pointer, executable mapping, publication receipt, or admission.
#![forbid(unsafe_code)]
mod adjacent_b2_frontend;
pub mod carrier;
pub mod disassembly;
#[cfg(feature = "offline-router")]
pub mod offline_router;
pub use adjacent_b2_frontend::prepare_disassembly_adjacent_b2;
pub use adjacent_b2_frontend::routed_jmp::prepare_disassembly_adjacent_routed_jmp;
mod fixed_exec;
mod grouped_artifact_frontend;
pub use grouped_artifact_frontend::{
    GROUPED_PROFILE, GROUPED_UPSTREAM_PROFILE, grouped_fixed_exec_binding_policy,
    grouped_fixed_exec_metadata, grouped_upstream_fixed_exec_binding_policy,
    grouped_upstream_fixed_exec_metadata, prepare_disassembly_jump_stack_grouped_fixed_exec,
    prepare_disassembly_jump_stack_grouped_upstream_fixed_exec,
};
mod ledger;
pub use fixed_exec::{
    BINDING_PROFILE as FIXED_EXEC_BINDING_PROFILE, METADATA as FIXED_EXEC_METADATA,
    binding_policy as fixed_exec_binding_policy,
};
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
    fixed_binding: Option<FixedImageBinding>,
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
    /// Exact source declaration, independently checked again by the fixed writer.
    pub const fn fixed_image_binding(&self) -> Option<FixedImageBinding> {
        self.fixed_binding
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
    let mut product =
        prepare_selection_with_mode(original, selected.selection.clone(), false, selected.mode)?;
    product.files.remove("bundle-index.tsv");
    product.files.extend(selected.files.clone());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.selection.original, &product.files),
    );
    Ok(product)
}

/// Explicit whole-program shared-head selection, same complete transaction and
/// long-only victims with inherited T3 pair admission. The first four tactics
/// retain local selection; final composition and every original budget remain.
/// No PIE startup, runtime or memory-fit admission.
pub fn prepare_disassembly_whole(
    original: &[u8],
    selected: &disassembly::whole::WholeProgramSelection,
) -> Result<Product, Error> {
    let mut product = prepare_selection_with_mode(
        original,
        selected.selection.clone(),
        false,
        disassembly::NeighborMode::WholeLongT3Ownership,
    )?;
    product.files.remove("bundle-index.tsv");
    product.files.extend(selected.files.clone());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.selection.original, &product.files),
    );
    Ok(product)
}

/// Opt-in B1/B2/T1 placement from current composition and declared ranges.
///
/// Uses the same typed complete selection and exact policy bytes. Selected
/// allocation must declare one candidate, one mapping, 4096 bytes and 1..=16
/// page-aligned ranges. Original LOAD pages, the reserved carrier and committed
/// image allocations are supplied through the existing ArtifactEmission occupancy.
/// A geometrically available seed is retained; actual image-fit failure does
/// not trigger a second emission. T2/T3 retain their policies and inherited
/// long-T3 pair admission. Final atomic composition and every cap still apply.
/// This is artifact construction only, with no qualification or runtime claim.
pub fn prepare_disassembly_whole_current_placement(
    original: &[u8],
    selected: &disassembly::whole::WholeProgramSelection,
) -> Result<Product, Error> {
    let mut product = prepare_selection_with_mode(
        original,
        selected.selection.clone(),
        false,
        disassembly::NeighborMode::WholeCurrentPlacement,
    )?;
    product.files.remove("bundle-index.tsv");
    product.files.extend(selected.files.clone());
    product
        .files
        .get_mut("planning-profile.tsv")
        .expect("typed whole-program selection retains its profile")
        .extend_from_slice(disassembly::whole::CURRENT_PLACEMENT_METADATA.as_bytes());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.selection.original, &product.files),
    );
    Ok(product)
}

/// Explicit mixed 6..=15-byte T3 with complete pending selected ownership.
///
/// B1/B2/T1 retain current-composition placement and T2 retains its existing
/// policy. Mixed T3 uses one shared victim/pair budget and admits each complete
/// pair against inherited ownership and every other outstanding instruction.
/// The full pending set is built once; only successful atomic commits remove
/// entries. A first-four local success can still refuse the final pending check
/// without restarting search. All source, dependency, hook and resource checks
/// remain mandatory. No candidate bytes are executed or qualified here.
pub fn prepare_disassembly_whole_current_placement_mixed_neighbors(
    original: &[u8],
    selected: &disassembly::whole::WholeProgramSelection,
) -> Result<Product, Error> {
    let mut product = prepare_selection_with_mode(
        original,
        selected.selection.clone(),
        false,
        disassembly::NeighborMode::WholeCurrentPlacementMixedPending,
    )?;
    product.files.remove("bundle-index.tsv");
    product.files.extend(selected.mixed_pending_files());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.selection.original, &product.files),
    );
    Ok(product)
}

/// Opt-in certified single-candidate placement with complete pending ownership.
///
/// B1/B2/T1 and both mixed-T3 roles use conservative artifact capacity bounds
/// before their one real emission. T2 keeps its legacy placement policy. Every
/// completed first-four bundle is admitted against inherited composition and
/// pending instructions before tactic success; refusal consumes that attempt
/// and advances only to the next declared tactic, while forced stays forced.
/// All final append, dependency, hook, entry, aggregate and atomic-selection
/// checks remain required. A capacity certificate is not execution authority.
pub fn prepare_disassembly_whole_fitting_mixed_neighbors(
    original: &[u8],
    selected: &disassembly::whole::WholeProgramSelection,
) -> Result<Product, Error> {
    let mut product = prepare_selection_with_mode(
        original,
        selected.selection.clone(),
        false,
        disassembly::NeighborMode::WholeFittingMixedPending,
    )?;
    product.files.remove("bundle-index.tsv");
    product.files.extend(selected.fitting_mixed_files());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.selection.original, &product.files),
    );
    Ok(product)
}

/// Explicit short-T3 selected entry veneers within the same owned image page.
/// Body storage and source entry remain distinct; this grants no execution or
/// loader qualification. Complete pending ownership and final commit checks
/// are identical to the fitting whole-program route.
pub fn prepare_disassembly_whole_entry_veneer_mixed_neighbors(
    original: &[u8],
    selected: &disassembly::whole::WholeProgramSelection,
) -> Result<Product, Error> {
    let mut product = prepare_selection_with_mode(
        original,
        selected.selection.clone(),
        false,
        disassembly::NeighborMode::WholeEntryVeneerMixedPending,
    )?;
    product.files.remove("bundle-index.tsv");
    product.files.extend(selected.entry_veneer_mixed_files());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.selection.original, &product.files),
    );
    Ok(product)
}

fn prepare_mode(original: &[u8], manifest: &[u8], owned_neighbors: bool) -> Result<Product, Error> {
    let selection = selection::parse(manifest)?;
    prepare_selection_mode(original, selection, owned_neighbors, false)
}

fn prepare_selection_mode(
    original: &[u8],
    selection: Selection,
    owned_neighbors: bool,
    short_only: bool,
) -> Result<Product, Error> {
    prepare_selection_with_mode(
        original,
        selection,
        owned_neighbors,
        if short_only {
            disassembly::NeighborMode::ShortOnly
        } else {
            disassembly::NeighborMode::LongOnly
        },
    )
}

/// Opt-in Linux PHDR-count-bounded serialization of the existing entry-veneer
/// whole-program plan. Only adjacent already-owned generated RX pages share a
/// LOAD header; addresses, bytes, planning limits and qualification are unchanged.
pub fn prepare_disassembly_whole_packed_entry_veneer_mixed_neighbors(
    original: &[u8],
    selected: &disassembly::whole::WholeProgramSelection,
) -> Result<Product, Error> {
    let mut product = prepare_selection_with_carrier_layout(
        original,
        selected.selection.clone(),
        false,
        disassembly::NeighborMode::WholeEntryVeneerMixedPending,
        None,
        adjacent_b2_frontend::PairProfile::ForwardJcc,
        CarrierTransaction {
            hooks: TransactionHooks {
                addon: None,
                gate: |_| Ok(()),
            },
            packed_rx_runs: true,
            fixed_exec: false,
            grouped_classes: None,
        },
    )?;
    product.files.remove("bundle-index.tsv");
    product
        .files
        .extend(selected.packed_entry_veneer_mixed_files());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.selection.original, &product.files),
    );
    Ok(product)
}

/// Explicit artifact-only overlapping-neighbor route with packed generated RX runs.
/// T3 uses two E9 entries at V/V+1 inside one original 6..=15-byte victim,
/// with one jointly certified candidate per image and direct body entries.
/// B1/B2/T1/T2, complete pending ownership, final atomic admission, all budgets
/// and carrier readback remain mandatory. This is no runtime qualification.
pub fn prepare_disassembly_whole_packed_overlapping_neighbors(
    original: &[u8],
    selected: &disassembly::whole::WholeProgramSelection,
) -> Result<Product, Error> {
    let mut product = prepare_selection_with_carrier_layout(
        original,
        selected.selection.clone(),
        false,
        disassembly::NeighborMode::WholeOverlappingPending,
        None,
        adjacent_b2_frontend::PairProfile::ForwardJcc,
        CarrierTransaction {
            hooks: TransactionHooks {
                addon: None,
                gate: |_| Ok(()),
            },
            packed_rx_runs: true,
            fixed_exec: false,
            grouped_classes: None,
        },
    )?;
    product.files.remove("bundle-index.tsv");
    product.files.extend(selected.packed_overlapping_files());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.selection.original, &product.files),
    );
    Ok(product)
}

/// Explicit fixed-address ET_EXEC profile. Uses the existing packed overlapping
/// planner and unchanged policy/budgets. No fallback to a common-bias profile,
/// partial candidate, loader admission or page-exemption authority is provided.
pub fn prepare_disassembly_whole_fixed_exec_packed_overlapping_neighbors(
    original: &[u8],
    selected: &disassembly::whole::WholeProgramSelection,
) -> Result<Product, Error> {
    prepare_whole_fixed_exec(original, &selected.selection, || {
        selected.packed_overlapping_files()
    })
}

/// Complete jump/register-stack union under the explicit fixed-address ET_EXEC
/// contract. Uses the same qualification, pending ownership, planner, encoder,
/// carrier and all-or-none transaction; no runtime/stack-fault guarantee follows.
pub fn prepare_disassembly_jump_stack_fixed_exec_packed_overlapping_neighbors(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
) -> Result<Product, Error> {
    prepare_whole_fixed_exec(original, &selected.selection, || {
        selected.packed_overlapping_files()
    })
}

fn prepare_whole_fixed_exec(
    original: &[u8],
    selected: &Selection,
    profile_files: impl FnOnce() -> BTreeMap<String, Vec<u8>>,
) -> Result<Product, Error> {
    let mut product = prepare_selection_with_carrier_layout(
        original,
        selected.clone(),
        false,
        disassembly::NeighborMode::WholeOverlappingPending,
        None,
        adjacent_b2_frontend::PairProfile::ForwardJcc,
        CarrierTransaction {
            hooks: TransactionHooks {
                addon: None,
                gate: |_| Ok(()),
            },
            packed_rx_runs: true,
            fixed_exec: true,
            grouped_classes: None,
        },
    )?;
    product.files.remove("bundle-index.tsv");
    let mut files = profile_files();
    files
        .get_mut("planning-profile.tsv")
        .expect("typed whole-program selection retains its profile")
        .extend_from_slice(FIXED_EXEC_METADATA.as_bytes());
    product.files.extend(files);
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.original, &product.files),
    );
    Ok(product)
}

fn prepare_selection_with_mode(
    original: &[u8],
    selection: Selection,
    owned_neighbors: bool,
    mode: disassembly::NeighborMode,
) -> Result<Product, Error> {
    prepare_selection_with_adjacent(original, selection, owned_neighbors, mode, None)
}

fn prepare_selection_with_adjacent(
    original: &[u8],
    selection: Selection,
    owned_neighbors: bool,
    mode: disassembly::NeighborMode,
    adjacent: Option<disassembly::adjacent_b2::AdjacentB2Limits>,
) -> Result<Product, Error> {
    prepare_selection_with_adjacent_gate(
        original,
        selection,
        owned_neighbors,
        mode,
        adjacent,
        |_| Ok(()),
    )
}

// Private fault seam observes only complete construction boundaries. Production
// supplies an infallible callback; it cannot supply plans or relax any guard.
fn prepare_selection_with_adjacent_gate(
    original: &[u8],
    selection: Selection,
    owned_neighbors: bool,
    mode: disassembly::NeighborMode,
    adjacent: Option<disassembly::adjacent_b2::AdjacentB2Limits>,
    gate: impl FnMut(&'static str) -> Result<(), Error>,
) -> Result<Product, Error> {
    prepare_selection_with_pair_gate(
        original,
        selection,
        owned_neighbors,
        mode,
        adjacent,
        adjacent_b2_frontend::PairProfile::ForwardJcc,
        gate,
    )
}

fn prepare_selection_with_pair_gate(
    original: &[u8],
    selection: Selection,
    owned_neighbors: bool,
    mode: disassembly::NeighborMode,
    adjacent: Option<disassembly::adjacent_b2::AdjacentB2Limits>,
    pair_profile: adjacent_b2_frontend::PairProfile,
    gate: impl FnMut(&'static str) -> Result<(), Error>,
) -> Result<Product, Error> {
    prepare_selection_transaction(
        original,
        selection,
        owned_neighbors,
        mode,
        adjacent,
        pair_profile,
        TransactionHooks { addon: None, gate },
    )
}

// Private extension of the final all-selected transaction. Legacy entry points
// always pass None and retain their original writer and complete bytes.
trait CandidateAddon {
    fn reservation(&self, legacy_bytes: u64) -> Result<u64, Error>;
    fn carrier(
        &self,
        elf: &Elf64<'_>,
        request: carrier::ImageRequest<'_>,
        edits: &[carrier::DeclaredEdit],
        policy: carrier::ImagePolicy,
    ) -> Result<carrier::CarrierOutput, carrier::Error>;
    fn finish(
        &self,
        original: &[u8],
        selection: &Selection,
        accepted: &[(u64, ArtifactPlan)],
        files: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<(), Error>;
}

struct TransactionHooks<'a, F> {
    addon: Option<&'a dyn CandidateAddon>,
    gate: F,
}

fn prepare_selection_transaction(
    original: &[u8],
    selection: Selection,
    owned_neighbors: bool,
    mode: disassembly::NeighborMode,
    adjacent: Option<disassembly::adjacent_b2::AdjacentB2Limits>,
    pair_profile: adjacent_b2_frontend::PairProfile,
    hooks: TransactionHooks<'_, impl FnMut(&'static str) -> Result<(), Error>>,
) -> Result<Product, Error> {
    prepare_selection_with_carrier_layout(
        original,
        selection,
        owned_neighbors,
        mode,
        adjacent,
        pair_profile,
        CarrierTransaction {
            hooks,
            packed_rx_runs: false,
            fixed_exec: false,
            grouped_classes: None,
        },
    )
}

// The planner mode is deliberately unchanged. Only this final serialization
// choice differs; every legacy caller takes the original carrier branch.
struct CarrierTransaction<'a, F> {
    hooks: TransactionHooks<'a, F>,
    packed_rx_runs: bool,
    fixed_exec: bool,
    grouped_classes: Option<(
        &'a [li2core::x86::JumpStackClass],
        grouped_artifact_frontend::GroupProfile,
    )>,
}

fn prepare_selection_with_carrier_layout(
    original: &[u8],
    selection: Selection,
    owned_neighbors: bool,
    mode: disassembly::NeighborMode,
    adjacent: Option<disassembly::adjacent_b2::AdjacentB2Limits>,
    pair_profile: adjacent_b2_frontend::PairProfile,
    transaction: CarrierTransaction<'_, impl FnMut(&'static str) -> Result<(), Error>>,
) -> Result<Product, Error> {
    let CarrierTransaction {
        hooks,
        packed_rx_runs,
        fixed_exec,
        grouped_classes,
    } = transaction;
    let TransactionHooks { addon, mut gate } = hooks;
    if packed_rx_runs
        && (owned_neighbors
            || adjacent.is_some()
            || addon.is_some()
            || (mode != disassembly::NeighborMode::WholeEntryVeneerMixedPending
                && mode != disassembly::NeighborMode::WholeOverlappingPending))
    {
        return Err(Error::new(
            "carrier-layout",
            "packed RX runs require the whole entry-veneer route",
        ));
    }
    if fixed_exec && (!packed_rx_runs || mode != disassembly::NeighborMode::WholeOverlappingPending)
    {
        return Err(Error::new(
            "fixed-exec-profile",
            "requires explicit packed overlapping route",
        ));
    }
    if grouped_classes.is_some()
        && (!fixed_exec
            || !packed_rx_runs
            || owned_neighbors
            || adjacent.is_some()
            || addon.is_some())
    {
        return Err(Error::new(
            "grouped-profile",
            "requires the fixed packed transaction without addons or adjacent planning",
        ));
    }
    if owned_neighbors && mode != disassembly::NeighborMode::LongOnly {
        return Err(Error::new(
            "neighbor-mode",
            "short-only has no foreign owner route",
        ));
    }
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
    let fixed_binding = if fixed_exec {
        Some(fixed_exec::bind(&elf, identity, s.bias_domain)?)
    } else {
        None
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
    let carrier_reserve = carrier_table_reservation(s.limits.program_headers)?;
    let carrier_reserve = match addon {
        Some(addon) => addon.reservation(carrier_reserve)?,
        None => carrier_reserve,
    };
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
    let composition =
        Composition::new(identity, snapshots).map_err(|e| Error::new("composition-original", e))?;
    // Only explicit pending modes supply the complete original instruction set.
    // Keep failed sites in this table; a successful commit alone discharges one.
    let mut pending = if matches!(
        mode,
        disassembly::NeighborMode::ShortT3Pending
            | disassembly::NeighborMode::WholeCurrentPlacementMixedPending
            | disassembly::NeighborMode::WholeFittingMixedPending
            | disassembly::NeighborMode::WholeEntryVeneerMixedPending
            | disassembly::NeighborMode::WholeOverlappingPending
    ) {
        s.sites
            .iter()
            .enumerate()
            .map(|(index, site)| addr(site.pc, u64::from(site.length)).map(|r| (index, r)))
            .collect::<Result<Vec<_>, Error>>()?
    } else {
        Vec::new()
    };
    pending.sort_by_key(|(_, range)| range.start());
    if matches!(
        mode,
        disassembly::NeighborMode::ShortT3Pending
            | disassembly::NeighborMode::WholeCurrentPlacementMixedPending
            | disassembly::NeighborMode::WholeFittingMixedPending
            | disassembly::NeighborMode::WholeEntryVeneerMixedPending
            | disassembly::NeighborMode::WholeOverlappingPending
    ) {
        composition
            .require_unclaimed_ranges(&pending.iter().map(|(_, range)| *range).collect::<Vec<_>>())
            .map_err(|e| Error::new("pending-selected", e))?;
    }
    // Freeze all units from original, sealed selection before any plan mutates the overlay.
    let grouped_schedule = grouped_classes
        .map(|(classes, profile)| match profile {
            grouped_artifact_frontend::GroupProfile::Exact => {
                grouped_artifact_frontend::Schedule::freeze(&elf, s, classes)
            }
            grouped_artifact_frontend::GroupProfile::Upstream => {
                grouped_artifact_frontend::Schedule::freeze_upstream(&elf, s, classes)
            }
        })
        .transpose()?;
    let mut grouped_accepted = Vec::new();
    let mut grouped_evidence = Vec::new();
    let reports: Vec<_> = s
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
    let accepted = Vec::<(u64, ArtifactPlan)>::new();
    let image_count = 0_usize;
    let image_bytes = 0_usize;
    let allocation_pages = 0_u64;
    let mut draft = adjacent_b2_frontend::SelectionDraft {
        composition,
        pending,
        reports,
        accepted,
        occupied,
        dependencies,
        image_count,
        image_bytes,
        allocation_pages,
        baseline: Vec::new(),
        work: Vec::new(),
        edges: Vec::new(),
        totals: Default::default(),
        blocked_groups: Vec::new(),
        routed: Default::default(),
    };
    if let Some(schedule) = &grouped_schedule {
        grouped_evidence = grouped_artifact_frontend::plan(
            SingletonContext {
                elf: &elf,
                dynamic: &dynamic,
                s,
                identity,
                fixed_binding,
                owned_neighbors: false,
                mode,
                record_baseline: false,
            },
            schedule,
            &mut draft,
            &mut grouped_accepted,
        );
    } else if let Some(limits) = adjacent {
        match pair_profile {
            adjacent_b2_frontend::PairProfile::ForwardJcc => adjacent_b2_frontend::plan(
                &elf, &dynamic, s, identity, limits, &ordered, &mut draft,
            )?,
            adjacent_b2_frontend::PairProfile::RoutedJmpUnion => {
                adjacent_b2_frontend::plan_profile(
                    &elf,
                    &dynamic,
                    s,
                    identity,
                    adjacent_b2_frontend::PairPolicy {
                        limits,
                        profile: pair_profile,
                    },
                    &ordered,
                    &mut draft,
                )?
            }
        }
    } else {
        for index in ordered {
            attempt_singleton(
                SingletonContext {
                    elf: &elf,
                    dynamic: &dynamic,
                    s,
                    identity,
                    fixed_binding,
                    owned_neighbors,
                    mode,
                    record_baseline: false,
                },
                &mut draft,
                index,
            );
        }
    }
    let adjacent_evidence = if adjacent.is_some() {
        gate("evidence-serialization")?;
        Some(match pair_profile {
            adjacent_b2_frontend::PairProfile::ForwardJcc => {
                adjacent_b2_frontend::evidence(s, &draft)?
            }
            adjacent_b2_frontend::PairProfile::RoutedJmpUnion => {
                adjacent_b2_frontend::routed_jmp::evidence(s, &draft)?
            }
        })
    } else {
        None
    };
    // Local legacy successes stay untouched in saved evidence. A separately
    // refused new-profile whole group cannot authorize a complete candidate.
    if let Some(error) = draft.blocked_groups.first() {
        for report in &mut draft.reports {
            if report.refusal.is_none() {
                report.refusal = Some(Error::new("adjacent-group-admission", error));
                report.refusal_code = Some(10_001);
            }
        }
    }
    let adjacent_b2_frontend::SelectionDraft {
        composition,
        pending: _,
        mut reports,
        accepted,
        occupied: _,
        dependencies,
        image_count: _,
        image_bytes: _,
        allocation_pages: _,
        baseline: _,
        work: _,
        edges: _,
        totals: _,
        blocked_groups: _,
        routed: _,
    } = draft;
    let plan_views: Vec<_> = grouped_accepted
        .iter()
        .map(|unit: &grouped_artifact_frontend::AcceptedGroup| {
            (unit.primary(s), unit.plan.artifact())
        })
        .chain(accepted.iter().map(|(id, plan)| (*id, plan)))
        .collect();
    let grouped_associations = grouped_schedule
        .as_ref()
        .map(|schedule| schedule.associations(s, &grouped_accepted, &accepted, &reports))
        .transpose()?;
    let mut files = BTreeMap::new();
    for (unit, evidence) in grouped_evidence {
        files.insert(
            format!("group-{unit}.diagnostics.txt"),
            evidence.into_bytes(),
        );
    }
    if let Some(schedule) = &grouped_schedule {
        files.insert("grouping-policy.tsv".into(), schedule.policy.clone());
    }
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
    let compatibility_binding = if let Some(binding) = fixed_binding {
        let policy = match &grouped_schedule {
            Some(schedule) => schedule.profile.binding_policy(
                binding,
                ContentId::of(&s.manifest),
                ContentId::of(&schedule.policy),
            ),
            None => fixed_exec::binding_policy(binding, ContentId::of(&s.manifest)),
        };
        let identity = ContentId::of(&policy);
        files.insert("binding-policy.tsv".into(), policy);
        identity
    } else {
        ContentId::of(&s.manifest)
    };
    let mut ledger = if let Some(associations) = &grouped_associations {
        ledger::grouped_plans(s, &plan_views, &composition, &dependencies, associations)?
    } else if mode == disassembly::NeighborMode::WholeEntryVeneerMixedPending
        || mode == disassembly::NeighborMode::WholeOverlappingPending
    {
        ledger::plans_with_entry_veneers(s, &accepted, &composition, &dependencies)?
    } else {
        ledger::plans(s, &accepted, &composition, &dependencies)?
    };
    if let Some(binding) = fixed_binding {
        ledger::fixed_binding(&mut ledger, binding);
    }
    files.insert("plan-ledger.tsv".into(), ledger.clone());
    for (index, image) in plan_views.iter().flat_map(|(_, p)| p.images()).enumerate() {
        // Planned bytes remain inspectable even if another site refuses. They
        // are not an executable carrier or an applicable sparse transaction.
        files.insert(format!("image-{index:04}.bin"), image.bytes().to_vec());
    }
    let edits = final_edits(&elf, &composition)?;
    let mut candidate = None;
    let mut sparse = None;
    if reports.iter().all(|r| r.refusal.is_none()) {
        let initial_meta =
            make_metadata(original, s, &reports, true, &profile, compatibility_binding)?
                .encode(formats::Limits::default())
                .map_err(|e| Error::new("metadata", e))?;
        let mut payload = b"LI2TOOL-CANDIDATE-UNREADY-V1\0".to_vec();
        payload.extend_from_slice(&ContentId::of(&initial_meta).0);
        payload.extend_from_slice(&ContentId::of(&ledger).0);
        let images: Vec<_> = plan_views
            .iter()
            .flat_map(|(_, p)| p.images())
            .map(|i| carrier::RxImage {
                entry: ElfVaddr(i.address()),
                bytes: i.bytes().to_vec(),
            })
            .collect();
        let write_carrier = if packed_rx_runs {
            carrier::append_carrier_with_linux_rx_runs
        } else if (owned_neighbors || adjacent.is_some())
            && elf.header().object_type == carrier::elf64::ObjectType::Executable
        {
            if pair_profile == adjacent_b2_frontend::PairProfile::RoutedJmpUnion {
                carrier::append_exec_carrier_with_interleaved_loads
            } else {
                carrier::append_exec_carrier_with_interleaved_images
            }
        } else {
            carrier::append_carrier_with_images
        };
        if adjacent.is_some() {
            gate("carrier-construction")?;
        }
        let request = carrier::ImageRequest {
            carrier_vaddr: ElfVaddr(s.carrier_pc),
            payload: &payload,
            images: &images,
            source_dependencies: &dependencies,
        };
        let policy = carrier::ImagePolicy {
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
        };
        let result = match addon {
            Some(addon) => addon.carrier(&elf, request, &edits, policy),
            None => write_carrier(&elf, request, &edits, policy),
        };
        let result = result.and_then(|output| {
            if let Some(binding) = fixed_binding {
                let readback = fixed_exec::OutputReadback {
                    bytes: output.bytes(),
                    original_to_output_header: &output.original_to_output_header,
                    max_program_headers: s.limits.program_headers,
                };
                if grouped_schedule.is_some() {
                    fixed_exec::validate_output_views(
                        &elf,
                        binding,
                        &plan_views,
                        readback,
                        &dynamic,
                        &dependencies,
                    )?;
                } else {
                    fixed_exec::validate_output(
                        &elf,
                        binding,
                        &accepted,
                        readback,
                        &dynamic,
                        &dependencies,
                    )?;
                }
            }
            Ok(output)
        });
        match result {
            Ok(output) => {
                if adjacent.is_some() {
                    gate("sparse-serialization")?;
                }
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
                if fixed_binding.is_some() {
                    ledger.extend_from_slice(b"fixed-original-field-ownership\tchecked-original-dependencies-and-loader-writes\nfixed-output-readback\tchecked\n");
                }
                if packed_rx_runs {
                    ledger::packed_rx_runs(&mut ledger, &output)?;
                }
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
    if adjacent.is_some() && !complete {
        // A failed whole selection has evidence, never orphan candidate plans.
        files.retain(|name, _| !name.starts_with("image-") && name != "plan-ledger.tsv");
        ledger = format!(
            "LI2ADJACENT-NO-CANDIDATE\t1\nselection_sha256\t{}\nqualification_complete\tfalse\n",
            ledger::hex(&ContentId::of(&s.manifest).0)
        )
        .into_bytes();
    }
    if let Some(bytes) = adjacent_evidence {
        let name = match pair_profile {
            adjacent_b2_frontend::PairProfile::ForwardJcc => "adjacent-b2-evidence.txt",
            adjacent_b2_frontend::PairProfile::RoutedJmpUnion => "adjacent-routed-jmp-evidence.txt",
        };
        files.insert(name.into(), bytes);
    }
    let metadata = make_metadata(
        original,
        s,
        &reports,
        false,
        &profile,
        compatibility_binding,
    )?;
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
    if adjacent.is_some() {
        gate("complete-output-serialization")?;
    }
    if complete {
        if let Some(addon) = addon {
            gate("startup-catalog")?;
            addon.finish(original, s, &accepted, &mut files)?;
        }
    }
    files.insert("bundle-index.tsv".into(), ledger::index(s.original, &files));
    Ok(Product {
        files,
        reports,
        complete,
        fixed_binding,
    })
}

struct SingletonContext<'a, 'code> {
    elf: &'a Elf64<'code>,
    dynamic: &'a carrier::dynamic::Inventory,
    s: &'a Selection,
    identity: CodeIdentity,
    fixed_binding: Option<FixedImageBinding>,
    owned_neighbors: bool,
    mode: disassembly::NeighborMode,
    record_baseline: bool,
}
fn attempt_singleton(
    context: SingletonContext<'_, '_>,
    draft: &mut adjacent_b2_frontend::SelectionDraft,
    index: usize,
) {
    let SingletonContext {
        elf,
        dynamic,
        s,
        identity,
        fixed_binding,
        owned_neighbors,
        mode,
        record_baseline,
    } = context;
    let adjacent_b2_frontend::SelectionDraft {
        composition,
        pending,
        reports,
        accepted,
        occupied,
        dependencies,
        image_count,
        image_bytes,
        allocation_pages,
        baseline,
        ..
    } = draft;
    let site = &s.sites[index];
    let report = &mut reports[index];
    let pending_ranges: Vec<_> = pending
        .iter()
        .filter_map(|(other, range)| (*other != index).then_some(*range))
        .collect();
    let prepared = (|| {
        validate_site(elf, site)?;
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
            entries: site.heads.as_ref().clone(),
            resumes: site.resumes.clone(),
        };
        let hook = s
            .hooks
            .iter()
            .find(|h| h.id == site.hook)
            .ok_or_else(|| Error::new("hook", "missing"))?;
        let emission = fixed_exec::emission(s, hook, occupied.clone(), fixed_binding)?;
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
        let result = if mode == disassembly::NeighborMode::WholeOverlappingPending {
            engine::plan_with_emission_after_and_overlapping_t3_pending(
                &request,
                composition,
                &pending_ranges,
                &site.victim_allocation,
                policy,
            )
        } else if mode == disassembly::NeighborMode::WholeEntryVeneerMixedPending {
            engine::plan_with_emission_after_and_entry_veneer_mixed_t3_pending(
                &request,
                composition,
                &pending_ranges,
                &site.victim_allocation,
                policy,
            )
        } else if mode == disassembly::NeighborMode::WholeFittingMixedPending {
            engine::plan_with_emission_after_and_fitting_mixed_t3_pending(
                &request,
                composition,
                &pending_ranges,
                &site.victim_allocation,
                policy,
            )
        } else if mode == disassembly::NeighborMode::WholeCurrentPlacementMixedPending {
            engine::plan_with_emission_after_and_current_placement_mixed_t3_pending(
                &request,
                composition,
                &pending_ranges,
                &site.victim_allocation,
                policy,
            )
        } else if mode == disassembly::NeighborMode::WholeCurrentPlacement {
            engine::plan_with_emission_after_and_current_placement(
                &request,
                composition,
                &site.victim_allocation,
                policy,
            )
        } else if mode == disassembly::NeighborMode::WholeLongT3Ownership {
            engine::plan_with_emission_after_and_long_t3_ownership(
                &request,
                composition,
                &site.victim_allocation,
                policy,
            )
        } else if mode == disassembly::NeighborMode::ShortT3Pending {
            engine::plan_with_emission_after_and_short_t3_pending(
                &request,
                composition,
                &pending_ranges,
                &site.victim_allocation,
                policy,
            )
        } else if owned_neighbors {
            let owners = neighbor_catalogue::collect(elf, s, identity, site)?;
            let foreign: Vec<_> = owners.iter().map(|owner| owner.site(site)).collect();
            engine::plan_with_emission_after_with_foreign(
                &request,
                composition,
                &site.victim_allocation,
                policy,
                &foreign,
            )
        } else if mode == disassembly::NeighborMode::ShortT3Ownership {
            engine::plan_with_emission_after_and_short_t3_ownership(
                &request,
                composition,
                &site.victim_allocation,
                policy,
            )
        } else if mode == disassembly::NeighborMode::ShortOnly {
            engine::plan_with_emission_after_and_short_neighbors(
                &request,
                composition,
                &site.victim_allocation,
                policy,
            )
        } else {
            engine::plan_with_emission_after(&request, composition, &site.victim_allocation, policy)
        };
        if record_baseline {
            baseline.push(adjacent_b2_frontend::Baseline {
                id: site.id,
                result: result.clone(),
            });
        }
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
        admit_artifact(
            AdmissionContext {
                elf,
                dynamic,
                s,
                mode,
            },
            AdmissionState {
                composition,
                occupied,
                dependencies,
                image_count,
                image_bytes,
                allocation_pages,
            },
            &plan,
            &pending_ranges,
        )?;
        Ok(plan)
    })();
    match prepared {
        Ok(plan) => {
            accepted.push((site.id, plan));
            pending.retain(|(other, _)| *other != index);
        }
        Err(error) => {
            report.refusal = Some(error);
            if report.refusal_code.is_none() {
                report.refusal_code = Some(10_001);
            }
        }
    }
}

struct AdmissionContext<'a, 'code> {
    elf: &'a Elf64<'code>,
    dynamic: &'a carrier::dynamic::Inventory,
    s: &'a Selection,
    mode: disassembly::NeighborMode,
}
struct AdmissionState<'a> {
    composition: &'a mut Composition,
    occupied: &'a mut Vec<AddressRange>,
    dependencies: &'a mut Vec<FileRange>,
    image_count: &'a mut usize,
    image_bytes: &'a mut usize,
    allocation_pages: &'a mut u64,
}
// One shared post-plan admission, preserving legacy error/commit order. A group
// supplies its one plan and exact outside-group pending intervals, not N clones.
fn admit_artifact(
    context: AdmissionContext<'_, '_>,
    state: AdmissionState<'_>,
    plan: &ArtifactPlan,
    pending_ranges: &[AddressRange],
) -> Result<(), Error> {
    let AdmissionContext {
        elf,
        dynamic,
        s,
        mode,
    } = context;
    let AdmissionState {
        composition,
        occupied,
        dependencies,
        image_count,
        image_bytes,
        allocation_pages,
    } = state;
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
            let file = translate(elf, dependency.start(), dependency.len())?;
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
            let right =
                (bytes.address + bytes.bytes.len() as u64).min(hook.pc + hook.length as u64);
            if left < right {
                let actual =
                    &bytes.bytes[(left - bytes.address) as usize..(right - bytes.address) as usize];
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
    // Preserve every existing append/dependency/resource/hook failure first.
    // First-four local success may refuse here; this never restarts search.
    if matches!(
        mode,
        disassembly::NeighborMode::ShortT3Pending
            | disassembly::NeighborMode::WholeCurrentPlacementMixedPending
            | disassembly::NeighborMode::WholeFittingMixedPending
            | disassembly::NeighborMode::WholeEntryVeneerMixedPending
            | disassembly::NeighborMode::WholeOverlappingPending
    ) {
        next.require_unclaimed_ranges(pending_ranges)
            .map_err(|e| Error::new("pending-selected", e))?;
    }
    for step in plan.source_steps() {
        occupied.extend(step.parts().allocations.iter().map(|a| a.range));
    }
    dependencies.extend(new_dependencies);
    *image_count += new_images;
    *image_bytes += new_bytes;
    *allocation_pages += new_pages;
    *composition = next;
    Ok(())
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
    binding: ContentId,
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
            binding,
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

/// Checked page reservation for the existing prospective PHDR table/payload.
/// This is geometry only, not carrier placement or executable admission.
pub fn carrier_table_reservation(program_headers: usize) -> Result<u64, Error> {
    round_page(
        (program_headers as u64)
            .checked_mul(56)
            .and_then(|v| v.checked_add(128))
            .ok_or_else(|| Error::new("carrier-reservation", "overflow"))?,
    )
}
