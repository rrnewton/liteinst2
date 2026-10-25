//! Original-instruction eviction composed with a short selected-site pun.
//!
//! Instruction identities and legal entries come from one authenticated original
//! decode. Later source encodings use the preceding byte overlay. Unreachable
//! tails of evicted instructions never become new original instructions.

use crate::bundle::{BundleBudget, PlannedBundle};
use crate::contracts::*;
use crate::quiescent::{
    self, AllocationPolicy, InstallRequest, PatchTactic, PlanMetrics, PlannedInstall, TacticPolicy,
};
use crate::scanner::{ScanResult, ScannedInstruction};
use crate::search::{RefusalClass, SearchDomain, SearchEvidence, SearchScope};
use crate::trampoline::{TrampolineImage, TrampolinePlan};

/// Explicit composition tactic; a successful simpler plan is not an eviction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvictionKind {
    /// T2: preserve the original successor through its own callback-free redirect.
    Successor {
        /// Original successor instruction address, never a generated address.
        victim: u64,
    },
}

/// One bounded combination considered by the successor planner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvictionAttempt {
    /// Original instruction receiving the auxiliary redirect.
    pub victim: u64,
    /// Candidate address of its callback-free generated image.
    pub victim_target: u64,
    /// Selected-site prefix count, or None when victim placement failed before
    /// a selected pun was tried. Some(0) means an ordinary generalized pun.
    pub prefix_count: Option<u8>,
    /// None only for the selected, completely composed transaction.
    pub refusal: Option<Refusal>,
}

/// Geometry and bounded search accounting, without timing estimates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvictionMetrics {
    /// Explicit bounded-search evidence; incomplete proofs remain marked.
    pub search: SearchEvidence,
    /// Whole original bytes evicted from the successor.
    pub victim_bytes: usize,
    /// Number of successor image placement candidates examined.
    pub victim_candidates: usize,
    /// Extra redirect instructions on an entry that falls through the victim.
    /// The entry redirect and generated continuation are both charged; an
    /// original taken branch or return may bypass the continuation redirect.
    pub victim_fallthrough_redirects: usize,
    /// Ordered candidate/prefix outcomes, including refusals.
    pub attempts: Vec<EvictionAttempt>,
}

/// A trusted, inspectable all-or-keep-gated eviction transaction.
#[derive(Clone, Debug)]
pub struct PlannedEviction {
    bundle: PlannedBundle,
    kind: EvictionKind,
    metrics: EvictionMetrics,
}

impl PlannedEviction {
    /// The complete source, image, lease and publication transaction.
    pub const fn bundle(&self) -> &PlannedBundle {
        &self.bundle
    }

    /// Forced tactic and its original victim address.
    pub const fn kind(&self) -> EvictionKind {
        self.kind
    }

    /// Search inventory and auxiliary execution cost.
    pub const fn metrics(&self) -> &EvictionMetrics {
        &self.metrics
    }
}

/// A failed successor search, retaining attempted placement/prefix evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvictionFailure {
    /// Explicit bounded-search evidence; incomplete proofs remain marked.
    pub search: SearchEvidence,
    /// Final fail-closed reason, not successful coverage.
    pub reason: Refusal,
    /// Every attempted joint placement after original validation.
    pub attempts: Vec<EvictionAttempt>,
}

/// Forces T2: evict one whole successor, then pun the selected instruction.
///
/// The successor must be a 5..=15-byte original instruction inside the certified
/// function and entry scope. It may be outside the selected basic block. Its
/// entry receives E9; its remaining original tail is unchanged and locked.
/// The original instruction executes in a callback-free image and rejoins at
/// its original successor. Its redirect and image add no selected hook; an
/// original branch back to the selected instruction still invokes that hook.
///
/// `request.allocation` bounds the selected hook image; `victim_allocation`
/// separately bounds the successor image. Aggregate bundle limits apply to
/// both. No source writes or executable reservations occur during planning.
/// `GeneralizedPunOnly` and `PrefixPunOnly` force the selected pun kind;
/// `PreferGeneralizedPun` tries B2 then T1 for each victim placement. Ordinary
/// relocation is not substituted for this forced eviction tactic.
pub fn plan_successor(
    request: &InstallRequest<'_>,
    victim_allocation: &AllocationPolicy,
    budget: BundleBudget,
) -> Result<PlannedEviction, Refusal> {
    plan_successor_detailed(request, victim_allocation, budget).map_err(|failure| failure.reason)
}

/// Successor planner retaining the bounded candidate inventory on failure.
pub fn plan_successor_detailed(
    request: &InstallRequest<'_>,
    victim_allocation: &AllocationPolicy,
    budget: BundleBudget,
) -> Result<PlannedEviction, EvictionFailure> {
    let mut attempts = Vec::new();
    let mut search_evidence = SearchEvidence::default();
    let result = (|| {
        let (source, scan) = quiescent::validated_source(request)
            .inspect_err(|reason| search_evidence.qualification(SearchScope::default(), reason))?;
        if request.search.max_sites == 0 {
            return Err(Refusal::NoPatchWindow);
        }
        if request.search.tactics == TacticPolicy::RelocationOnly {
            return Err(Refusal::UnsupportedSemantics(
                "successor eviction requires a selected generalized or prefixed pun".into(),
            ));
        }
        let selected = scan
            .instructions()
            .iter()
            .find(|item| item.address() == request.logical_pc)
            .ok_or(Refusal::NotInstructionHead)?;
        let len = selected.len();
        if !(1..=4).contains(&len)
            || (request.search.tactics == TacticPolicy::PrefixPunOnly && len == 1)
        {
            return Err(Refusal::NoPatchWindow);
        }
        let victim_pc = selected.address() + len as u64;
        let victim = scan
            .instructions()
            .iter()
            .find(|item| item.address() == victim_pc)
            .ok_or(Refusal::NoPatchWindow)?;
        let scope = SearchScope {
            physical_pc: Some(victim_pc),
            ..SearchScope::default()
        };
        let displaced = qualify_victim(request, &scan, victim, 5)
            .inspect_err(|reason| search_evidence.qualification(scope, reason))?;
        if budget.max_steps < 2
            || budget.max_mappings < 2
            || budget.max_virtual_bytes < 8192
            || budget.max_backing_bytes < 8192
            || victim_allocation.max_mappings == 0
            || victim_allocation.max_mapped_bytes < 4096
        {
            search_evidence.refusal(
                scope,
                RefusalClass::ResourceCapacity,
                &Refusal::AllocationUnavailable,
            );
            return Err(Refusal::AllocationUnavailable);
        }
        let occupied = quiescent::occupied_ranges()?;
        let trampoline = TrampolinePlan::from_instruction(&scan, victim_pc)
            .map_err(|error| Refusal::Backend(error.to_string()))?;
        let mut seen = std::collections::BTreeSet::new();
        let mut last_error = Refusal::AllocationUnavailable;
        // A valid victim placement can expose a more specific selected-site
        // refusal. Later unavailable victim addresses must not erase it.
        let mut selected_error = None;
        let image_search = search_evidence.begin(
            SearchDomain::VictimImages,
            scope,
            victim_allocation.max_candidates,
            None,
        );
        for candidate in 0..victim_allocation.max_candidates {
            search_evidence.visit(image_search);
            let Some(target) = quiescent::candidate_target(
                victim_pc,
                [false; 4],
                victim_allocation.preferred_address,
                candidate,
            ) else {
                continue;
            };
            if !seen.insert(target) {
                continue;
            }
            let image = match trampoline.emit_at(target) {
                Ok(image) => image,
                Err(error) => {
                    last_error = Refusal::Backend(error.to_string());
                    attempts.push(EvictionAttempt {
                        victim: victim_pc,
                        victim_target: target,
                        prefix_count: None,
                        refusal: Some(last_error.clone()),
                    });
                    continue;
                }
            };
            let allocation = image_allocation(&image)?;
            if allocation.len() > victim_allocation.max_mapped_bytes as u64
                || !victim_allocation
                    .ranges
                    .iter()
                    .any(|range| range.covers(allocation))
                || source.overlaps(allocation)
                || occupied.iter().any(|range| range.overlaps(allocation))
            {
                last_error = Refusal::AllocationUnavailable;
                attempts.push(EvictionAttempt {
                    victim: victim_pc,
                    victim_target: target,
                    prefix_count: None,
                    refusal: Some(last_error.clone()),
                });
                continue;
            }
            let patch = near_redirect(victim_pc, target)?;
            let evicted = instruction_member(
                request, source, displaced, image, allocation, patch, candidate,
            )?;
            let mut overlay = request.code.to_vec();
            for edit in &evicted.plan().parts().writes {
                let offset = (edit.address - source.start()) as usize;
                overlay[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
            }
            // Instruction identity is still the authenticated ORIGINAL decode.
            // The selected instruction is unchanged; only consumed successor
            // displacement bytes are read from this validated preceding overlay.
            let overlaid = InstallRequest {
                code: &overlay,
                ..*request
            };
            let mut held_allocations = occupied.clone();
            held_allocations.push(allocation);
            let prefixes: Vec<_> = match request.search.tactics {
                TacticPolicy::GeneralizedPunOnly => vec![0],
                TacticPolicy::PrefixPunOnly => (1..len).collect(),
                TacticPolicy::PreferGeneralizedPun => (0..len).collect(),
                TacticPolicy::RelocationOnly => unreachable!("refused above"),
            };
            for prefix_count in prefixes {
                let selected_plan = quiescent::plan_pun(
                    &overlaid,
                    &scan,
                    source,
                    &held_allocations,
                    prefix_count,
                    &mut search_evidence,
                    SearchScope {
                        victim_target: Some(target),
                        ..SearchScope::default()
                    },
                );
                let composed = selected_plan.and_then(|mut selected_plan| {
                    selected_plan.metrics.attempts.push(quiescent::SiteAttempt {
                        tactic: if prefix_count == 0 {
                            PatchTactic::GeneralizedPun
                        } else {
                            PatchTactic::PrefixPun
                        },
                        physical_pc: request.logical_pc,
                        refusal: None,
                    });
                    PlannedBundle::compose(
                        vec![ExpectedBytes {
                            address: source.start(),
                            bytes: request.code.to_vec(),
                        }],
                        vec![evicted.clone(), selected_plan],
                        budget,
                    )
                });
                attempts.push(EvictionAttempt {
                    victim: victim_pc,
                    victim_target: target,
                    prefix_count: Some(prefix_count as u8),
                    refusal: composed.as_ref().err().cloned(),
                });
                match composed {
                    Ok(bundle) => {
                        search_evidence.accept(image_search);
                        return Ok(PlannedEviction {
                            bundle,
                            kind: EvictionKind::Successor { victim: victim_pc },
                            metrics: EvictionMetrics {
                                search: SearchEvidence::default(),
                                victim_bytes: displaced.len() as usize,
                                victim_candidates: candidate + 1,
                                victim_fallthrough_redirects: 2,
                                attempts: attempts.clone(),
                            },
                        });
                    }
                    Err(error) => selected_error = Some(error),
                }
            }
        }
        search_evidence.finish_candidates(
            image_search,
            quiescent::candidate_target_proof(
                victim_pc,
                [false; 4],
                victim_allocation.preferred_address,
                victim_allocation.max_candidates,
            ),
        );
        Err(selected_error.unwrap_or(last_error))
    })();
    match result {
        Ok(mut plan) => {
            search_evidence.accepted = true;
            plan.metrics.search = search_evidence;
            Ok(plan)
        }
        Err(reason) => Err(EvictionFailure {
            reason,
            attempts,
            search: search_evidence,
        }),
    }
}

pub(crate) fn qualify_victim(
    request: &InstallRequest<'_>,
    scan: &ScanResult,
    victim: &ScannedInstruction,
    minimum: usize,
) -> Result<AddressRange, Refusal> {
    let displaced = AddressRange::new(victim.address(), victim.len())?;
    if victim.len() < minimum
        || !request.function.covers(displaced)
        || victim.len() > request.search.max_displaced_bytes
    {
        return Err(Refusal::NoPatchWindow);
    }
    if !request.entries.scope.covers(displaced) {
        return Err(Refusal::UnresolvedEntry);
    }
    if request
        .entries
        .entries
        .iter()
        .any(|entry| displaced.contains(entry.address) && entry.requires_endbr)
    {
        return Err(Refusal::UnsupportedSemantics(
            "CET IBT landing pad in evicted instruction".into(),
        ));
    }
    for item in scan.instructions() {
        if matches!(
            item.instruction().op0_kind(),
            iced_x86::OpKind::NearBranch16
                | iced_x86::OpKind::NearBranch32
                | iced_x86::OpKind::NearBranch64
        ) {
            let target = item.instruction().near_branch_target();
            if displaced.contains(target) && target != displaced.start() {
                return Err(Refusal::NotInstructionHead);
            }
        }
    }
    quiescent::qualify_instruction(victim.instruction())?;
    Ok(displaced)
}

pub(crate) fn image_allocation(image: &TrampolineImage) -> Result<AddressRange, Refusal> {
    let start = image.address() & !4095;
    let end = image
        .address()
        .checked_add(image.bytes().len() as u64)
        .and_then(|end| end.checked_add(4095))
        .map(|end| end & !4095)
        .ok_or(Refusal::InvalidRange)?;
    AddressRange::new(start, (end - start) as usize)
}

pub(crate) fn near_redirect(source: u64, target: u64) -> Result<Vec<u8>, Refusal> {
    let displacement = i32::try_from(i128::from(target) - i128::from(source) - 5)
        .map_err(|_| Refusal::AllocationUnavailable)?;
    let mut bytes = vec![0xe9];
    bytes.extend_from_slice(&displacement.to_le_bytes());
    Ok(bytes)
}

pub(crate) fn instruction_member(
    request: &InstallRequest<'_>,
    source: AddressRange,
    displaced: AddressRange,
    image: TrampolineImage,
    allocation: AddressRange,
    patch: Vec<u8>,
    candidate: usize,
) -> Result<PlannedInstall, Refusal> {
    let plan = PatchPlan::checked(PlanParts {
        identity: request.identity,
        profile: ApplicationProfile::InstallOnce,
        kind: PlanKind::Relocation,
        logical_pc: displaced.start(),
        physical_pc: displaced.start(),
        displaced,
        reads: vec![ExpectedBytes {
            address: source.start(),
            bytes: request.code.to_vec(),
        }],
        writes: vec![ByteEdit {
            address: displaced.start(),
            bytes: patch,
        }],
        dependencies: vec![source],
        entries: request.entries.clone(),
        obligations: vec![EntryObligation::Preserved(displaced.start())],
        allocations: vec![AllocationRequest {
            range: allocation,
            alignment: 4096,
        }],
        generated: vec![GeneratedCode {
            address: image.address(),
            bytes: image.bytes().to_vec(),
            program_counters: image.program_counter_mappings().to_vec(),
        }],
        requirements: PublicationRequirements {
            quiescent: true,
            sync_core: true,
            sigill_router: false,
        },
    })?;
    Ok(PlannedInstall {
        plan,
        image,
        metrics: PlanMetrics {
            search: SearchEvidence::default(),
            upstream_bytes: 0,
            displaced_bytes: displaced.len() as usize,
            prefix_instructions: 0,
            allocation_attempts: candidate + 1,
            attempts: vec![],
        },
    })
}
