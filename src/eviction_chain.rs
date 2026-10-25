//! Bounded recursive successor eviction, separate from the five-tactic engine.
//!
//! The selected short instruction is followed by one or more original short
//! successors and then a whole 5..=15-byte anchor. The anchor is redirected
//! first. Each preceding short instruction is punned against that new overlay,
//! in reverse original address order. Every auxiliary image is callback-free.
//! This module never decodes rewritten bytes or manufactures a live receipt.

use crate::bundle::{BundleBudget, PlannedBundle};
use crate::contracts::{AddressRange, ExpectedBytes, Refusal};
use crate::eviction::{image_allocation, instruction_member, near_redirect, qualify_victim};
use crate::planner::HookSemantics;
use crate::quiescent::{self, AllocationPolicy, InstallRequest, PlannedInstall, TacticPolicy};
use crate::scanner::ScanResult;
use crate::search::{CandidateProof, SearchDomain, SearchEvidence, SearchScope, SearchStop};
use crate::trampoline::TrampolinePlan;

/// Hard stack bound for this explicit chain API, excluding the selected site.
/// A larger request is refused; it is never silently truncated to this value.
pub const MAX_SHORT_SUCCESSORS: usize = 8;

/// Explicit recursion, prefix and total placement-work policy.
#[derive(Clone, Copy, Debug)]
pub struct ChainSearch<'a> {
    /// Optional exact increasing list of every successor, including the anchor.
    /// Repeated/backward/skipped heads refuse; a forced list is never replaced.
    pub forced_successors: Option<&'a [u64]>,
    /// Maximum original 1..=4-byte successors before the terminal anchor.
    pub max_short_successors: usize,
    /// Total candidate trials across all nodes, prefixes and backtracking.
    /// Anchor generator slots that return None or duplicate a target also count.
    pub max_candidate_trials: usize,
    /// B2/T1 order for callback-free short successors. The selected site retains
    /// request.search.tactics. RelocationOnly is unsupported at either level.
    pub auxiliary_puns: TacticPolicy,
}
impl Default for ChainSearch<'_> {
    fn default() -> Self {
        Self {
            forced_successors: None,
            max_short_successors: 4,
            max_candidate_trials: 256,
            auxiliary_puns: TacticPolicy::PreferGeneralizedPun,
        }
    }
}

/// Immutable original instruction plus its selected image and prefix geometry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainNode {
    /// Original head, in increasing original order in PlannedChain::nodes().
    pub original: u64,
    /// One whole original instruction; never a patched decode length.
    pub original_len: usize,
    /// Entry of this node's separate generated image.
    pub target: u64,
    /// None for the final ordinary-E9 anchor; Some(0) for B2; Some(P) for T1.
    pub prefix_count: Option<u8>,
    /// Exactly the selected node (index zero) has a callback.
    pub has_selected_hook: bool,
}

/// One local search invocation, including the complete already-placed suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainRun {
    /// Original head whose image is being placed.
    pub original: u64,
    /// None for the anchor; Some(0) for B2; Some(P) for T1.
    pub prefix_count: Option<u8>,
    /// Descending source order, same as the transaction steps placed so far.
    pub suffix_targets: Vec<(u64, u64)>,
    /// Per-node/per-prefix address-domain cap. Re-entering a node after changing
    /// its suffix starts a new local run; every re-entry still pays global work.
    pub local_limit: usize,
    /// Remaining total trial allowance when this local invocation began.
    pub global_remaining_at_entry: usize,
    /// Number of candidate slots or distinct pun targets entered locally.
    pub examined: usize,
    /// A local-domain outcome. It never certifies whole-site impossibility.
    pub stop: SearchStop,
    /// Local generator evidence after this run ended without acceptance.
    pub proof: Option<CandidateProof>,
}

/// Concrete outcome at a placement or composition stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainAttempt {
    /// Original head whose placement or composition was attempted.
    pub original: u64,
    /// Exact candidate, or None before a valid candidate exists.
    pub target: Option<u64>,
    /// None for the anchor or pre-placement resource refusal.
    pub prefix_count: Option<u8>,
    /// None means this member composed. It does not mean the whole chain won.
    pub refusal: Option<Refusal>,
    /// Only the final successful leaf sets this bit.
    pub complete_chain: bool,
    /// The exact-target pun's ordinary validator evidence, if it was invoked.
    pub leaf_search: SearchEvidence,
}

/// Deterministic original-head discovery, separate from image placement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainDiscovery {
    /// Includes the first omitted short head when the depth bound is reached.
    pub short_successors: Vec<u64>,
    /// Set only after qualifying the terminal whole instruction.
    pub anchor: Option<u64>,
    /// DomainComplete means this one immediate-successor path reached its anchor.
    /// It is not a proof about every site, tactic, or address schedule.
    pub stop: SearchStop,
}

/// Exact work and image geometry, without runtime-performance estimates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainMetrics {
    /// Original dependency path and its separately scoped termination.
    pub discovery: ChainDiscovery,
    /// All entered image-placement trials, including failed suffixes.
    pub candidate_trials: usize,
    /// Caller-supplied total placement-trial cap.
    pub global_limit: usize,
    /// True only after observing a next slot which the global cap forbids.
    /// Merely consuming exactly the cap does not set this flag.
    pub global_cutoff: bool,
    /// Ordered local searches; failed suffix searches survive success.
    pub runs: Vec<ChainRun>,
    /// Ordered raw placement and composition outcomes.
    pub attempts: Vec<ChainAttempt>,
    /// Remains false: a finished page-boundary schedule is not a proof over
    /// every byte address, allocator layout, tactic or supported application.
    pub classification_complete: bool,
    /// Two redirects per auxiliary fallthrough: source E9 and image rejoin.
    /// A taken original branch/RET can bypass its generated rejoin.
    pub auxiliary_fallthrough_redirects: usize,
}

/// Opaque, checked multi-member plan for one selected successor chain.
#[derive(Clone, Debug)]
pub struct PlannedChain {
    bundle: PlannedBundle,
    nodes: Vec<ChainNode>,
    metrics: ChainMetrics,
}
impl PlannedChain {
    /// Existing transactional publication and retirement plan.
    pub const fn bundle(&self) -> &PlannedBundle {
        &self.bundle
    }
    /// Original nodes in increasing address order, selected first.
    pub fn nodes(&self) -> &[ChainNode] {
        &self.nodes
    }
    /// Complete retained local attempts and bounded-work evidence.
    pub const fn metrics(&self) -> &ChainMetrics {
        &self.metrics
    }
}

/// Refused chain with its raw reason and every recorded local attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainFailure {
    /// Raw refusal is preserved separately from local cutoff evidence.
    pub reason: Refusal,
    /// Work completed before the refusal, including any observed cutoff.
    pub metrics: Box<ChainMetrics>,
}

/// Plans a genuine successor dependency chain without changing the engine API.
///
/// This API requires at least one short successor; a direct long successor uses
/// the existing `eviction::plan_successor` API. Discovery terminates at the first
/// long successor; no other anchor or dependency path is substituted. Taken
/// original branches may revisit selected code and therefore execute its hook;
/// auxiliary entry alone does not add a hook.
///
/// `successor_allocations` has exactly one policy for each original successor,
/// including the final anchor, in increasing original address order. Selected
/// placement uses request.allocation. Each policy's candidate/mapping/byte cap
/// remains in force; all nodes additionally pay the global trial/bundle bounds.
/// Local address caps apply separately to each prefix and each suffix placement;
/// all entered anchor slots (including invalid/duplicate slots) and distinct pun
/// targets pay the single global cap. A global omitted-slot witness takes final
/// refusal precedence as AllocationUnavailable; prior raw reasons stay recorded.
/// No source or generated mapping is mutated or reserved by this operation.
/// The bundle uses existing all-preflight/keep-gated publication and retirement.
/// The forced chain may cross the selected block boundary, but every auxiliary
/// instruction must be inside the owned function and complete entry scope.
/// No basic block spanning an original branch is invented.
pub fn plan_successor_chain(
    request: &InstallRequest<'_>,
    successor_allocations: &[AllocationPolicy],
    search: ChainSearch<'_>,
    budget: BundleBudget,
) -> Result<PlannedChain, Refusal> {
    plan_successor_chain_detailed(request, successor_allocations, search, budget)
        .map_err(|failure| failure.reason)
}

/// Detailed chain planner; all refused branches and local cutoffs are retained.
pub fn plan_successor_chain_detailed(
    request: &InstallRequest<'_>,
    successor_allocations: &[AllocationPolicy],
    search: ChainSearch<'_>,
    budget: BundleBudget,
) -> Result<PlannedChain, ChainFailure> {
    let mut metrics = ChainMetrics {
        discovery: ChainDiscovery {
            short_successors: Vec::new(),
            anchor: None,
            stop: SearchStop::Interrupted,
        },
        candidate_trials: 0,
        global_limit: search.max_candidate_trials,
        global_cutoff: false,
        runs: Vec::new(),
        attempts: Vec::new(),
        classification_complete: false,
        auxiliary_fallthrough_redirects: 0,
    };
    let result = (|| {
        let (source, scan) = quiescent::validated_source(request)?;
        let nodes = original_chain(request, &scan, search, &mut metrics.discovery)?;
        if successor_allocations.len() != nodes.len() - 1 {
            return Err(Refusal::InvalidPlan);
        }
        if budget.max_steps < nodes.len()
            || budget.max_mappings < nodes.len()
            || budget.max_virtual_bytes < nodes.len() as u64 * 4096
            || budget.max_backing_bytes < nodes.len() as u64 * 4096
        {
            return Err(Refusal::AllocationUnavailable);
        }
        let mut occupied = quiescent::occupied_ranges()?;
        occupied.push(source);
        metrics.auxiliary_fallthrough_redirects = 2 * (nodes.len() - 1);
        let mut planner = ChainPlanner {
            request,
            policies: successor_allocations,
            search,
            budget,
            source,
            scan,
            nodes,
            occupied,
            metrics: &mut metrics,
            last_error: Refusal::AllocationUnavailable,
        };
        let end = planner.nodes.len() - 1;
        let bundle = planner
            .descend(end, Vec::new(), request.code.to_vec())?
            .ok_or_else(|| planner.last_error.clone())?;
        let nodes = bundle
            .plan()
            .steps()
            .iter()
            .rev()
            .zip(bundle.images().iter().rev())
            .enumerate()
            .map(|(index, (step, image))| {
                let parts = step.parts();
                ChainNode {
                    original: parts.physical_pc,
                    original_len: parts.displaced.len() as usize,
                    target: image.address(),
                    prefix_count: match &parts.kind {
                        crate::contracts::PlanKind::Relocation => None,
                        crate::contracts::PlanKind::GeneralizedPun(_) => Some(0),
                        crate::contracts::PlanKind::PrefixedPun(pun) => Some(pun.prefix_count),
                    },
                    has_selected_hook: index == 0,
                }
            })
            .collect();
        Ok((bundle, nodes))
    })();
    match result {
        Ok((bundle, nodes)) => Ok(PlannedChain {
            bundle,
            nodes,
            metrics,
        }),
        Err(reason) => Err(ChainFailure {
            reason,
            metrics: Box::new(metrics),
        }),
    }
}

#[derive(Clone, Copy)]
struct OriginalNode {
    pc: u64,
    len: usize,
}

fn original_chain(
    request: &InstallRequest<'_>,
    scan: &ScanResult,
    search: ChainSearch<'_>,
    discovery: &mut ChainDiscovery,
) -> Result<Vec<OriginalNode>, Refusal> {
    if search.max_short_successors > MAX_SHORT_SUCCESSORS {
        return Err(Refusal::UnsupportedSemantics(
            "chain recursion bound exceeds hard limit".into(),
        ));
    }
    if request.search.max_sites == 0 {
        return Err(Refusal::NoPatchWindow);
    }
    if matches!(request.search.tactics, TacticPolicy::RelocationOnly)
        || matches!(search.auxiliary_puns, TacticPolicy::RelocationOnly)
    {
        return Err(Refusal::UnsupportedSemantics(
            "successor chains require B2/T1 puns".into(),
        ));
    }
    if let Some(forced) = search.forced_successors {
        // This is a dependency-path check, not a ban on executable backedges.
        if forced.is_empty()
            || forced.len() > MAX_SHORT_SUCCESSORS + 1
            || forced.windows(2).any(|pair| pair[0] >= pair[1])
            || forced[0] <= request.logical_pc
        {
            return Err(Refusal::InvalidPlan);
        }
    }
    let selected = scan
        .instructions()
        .iter()
        .find(|item| item.address() == request.logical_pc)
        .ok_or(Refusal::NotInstructionHead)?;
    if !(1..=4).contains(&selected.len())
        || selected.len() > request.search.max_displaced_bytes
        || !request
            .block
            .covers(AddressRange::new(selected.address(), selected.len())?)
    {
        return Err(Refusal::NoPatchWindow);
    }
    // Replacement keeps the existing selected-instruction qualification rule.
    if request.semantics != HookSemantics::ReplaceFirst {
        quiescent::qualify_instruction(selected.instruction())?;
    }
    let mut nodes = vec![OriginalNode {
        pc: selected.address(),
        len: selected.len(),
    }];
    let mut short_count = 0;
    loop {
        let previous = nodes.last().unwrap();
        let pc = previous
            .pc
            .checked_add(previous.len as u64)
            .ok_or(Refusal::InvalidRange)?;
        if let Some(forced) = search.forced_successors {
            if forced.get(nodes.len() - 1).copied() != Some(pc) {
                return Err(Refusal::InvalidPlan);
            }
        }
        let item = scan
            .instructions()
            .iter()
            .find(|item| item.address() == pc)
            .ok_or(Refusal::NoPatchWindow)?;
        qualify_victim(request, scan, item, 1)?;
        nodes.push(OriginalNode {
            pc,
            len: item.len(),
        });
        if item.len() >= 5 {
            if short_count == 0 {
                return Err(Refusal::NoPatchWindow);
            }
            if search
                .forced_successors
                .is_some_and(|forced| forced.len() != nodes.len() - 1)
            {
                return Err(Refusal::InvalidPlan);
            }
            discovery.anchor = Some(pc);
            discovery.stop = SearchStop::DomainComplete;
            return Ok(nodes);
        }
        short_count += 1;
        discovery.short_successors.push(pc);
        if short_count > search.max_short_successors {
            discovery.stop = SearchStop::BudgetLimited {
                remaining_at_least: 1,
            };
            return Err(Refusal::AllocationUnavailable);
        }
    }
}

struct ChainPlanner<'r, 'a, 'p, 'm> {
    request: &'r InstallRequest<'a>,
    policies: &'p [AllocationPolicy],
    search: ChainSearch<'p>,
    budget: BundleBudget,
    source: AddressRange,
    scan: ScanResult,
    nodes: Vec<OriginalNode>,
    occupied: Vec<AddressRange>,
    metrics: &'m mut ChainMetrics,
    last_error: Refusal,
}

impl ChainPlanner<'_, '_, '_, '_> {
    fn descend(
        &mut self,
        index: usize,
        members: Vec<PlannedInstall>,
        overlay: Vec<u8>,
    ) -> Result<Option<PlannedBundle>, Refusal> {
        let node = self.nodes[index];
        let anchor = index == self.nodes.len() - 1;
        let policy = if index == 0 {
            self.request.allocation
        } else {
            &self.policies[index - 1]
        };
        let policy = policy.clone();
        if policy.max_mappings == 0 || policy.max_mapped_bytes < 4096 {
            self.record(
                node.pc,
                None,
                None,
                Some(Refusal::AllocationUnavailable),
                false,
                SearchEvidence::default(),
            );
            return Ok(None);
        }
        let prefixes = if anchor {
            vec![None]
        } else {
            prefix_choices(
                if index == 0 {
                    self.request.search.tactics
                } else {
                    self.search.auxiliary_puns
                },
                node.len,
            )?
            .into_iter()
            .map(Some)
            .collect()
        };
        for prefix in prefixes {
            let remaining = self
                .search
                .max_candidate_trials
                .saturating_sub(self.metrics.candidate_trials);
            let run = self.metrics.runs.len();
            self.metrics.runs.push(ChainRun {
                original: node.pc,
                prefix_count: prefix.map(|p| p as u8),
                suffix_targets: members
                    .iter()
                    .map(|m| (m.plan().parts().physical_pc, m.image().address()))
                    .collect(),
                local_limit: policy.max_candidates,
                global_remaining_at_entry: remaining,
                examined: 0,
                stop: SearchStop::Interrupted,
                proof: None,
            });
            let mut occupied = self.occupied.clone();
            occupied.extend(
                members
                    .iter()
                    .flat_map(|member| member.plan().parts().allocations.iter().map(|a| a.range)),
            );
            let mut seen = std::collections::BTreeSet::new();
            let (targets, proof) = if anchor {
                // One extra bounded slot witnesses a global cutoff. No omitted
                // earlier invalid slot is skipped or charged as a success.
                let n = policy.max_candidates.min(remaining.saturating_add(1));
                (
                    (0..n)
                        .map(|slot| {
                            quiescent::candidate_target(
                                node.pc,
                                [false; 4],
                                policy.preferred_address,
                                slot,
                            )
                        })
                        .collect::<Vec<_>>(),
                    None,
                )
            } else {
                let window = match pun_window(self.source, &overlay, node, prefix.unwrap()) {
                    Ok(window) => window,
                    Err(reason) => {
                        self.record(
                            node.pc,
                            None,
                            prefix,
                            Some(reason),
                            false,
                            SearchEvidence::default(),
                        );
                        continue;
                    }
                };
                let mut bounded_policy = policy.clone();
                bounded_policy.max_candidates =
                    policy.max_candidates.min(remaining.saturating_add(1));
                let candidates = quiescent::pun_candidates(window, &bounded_policy);
                (
                    candidates
                        .addresses
                        .into_iter()
                        .map(Some)
                        .collect::<Vec<_>>(),
                    Some(candidates.proof),
                )
            };
            for (slot, target) in targets.into_iter().enumerate() {
                if self.metrics.candidate_trials == self.search.max_candidate_trials {
                    self.metrics.global_cutoff = true;
                    self.metrics.runs[run].stop = SearchStop::BudgetLimited {
                        remaining_at_least: 1,
                    };
                    return Err(Refusal::AllocationUnavailable);
                }
                self.metrics.candidate_trials += 1;
                self.metrics.runs[run].examined += 1;
                let Some(target) = target else {
                    self.record(
                        node.pc,
                        None,
                        prefix,
                        Some(Refusal::AllocationUnavailable),
                        false,
                        SearchEvidence::default(),
                    );
                    continue;
                };
                if !seen.insert(target) {
                    self.record(
                        node.pc,
                        Some(target),
                        prefix,
                        Some(Refusal::AllocationUnavailable),
                        false,
                        SearchEvidence::default(),
                    );
                    continue;
                }
                let request = InstallRequest {
                    code: &overlay,
                    logical_pc: node.pc,
                    allocation: &policy,
                    block: if index == 0 {
                        self.request.block
                    } else {
                        AddressRange::new(node.pc, node.len)?
                    },
                    semantics: if index == 0 {
                        self.request.semantics
                    } else {
                        HookSemantics::Observe
                    },
                    ..*self.request
                };
                let mut leaf_search = SearchEvidence::default();
                let member = if anchor {
                    anchor_member(&request, &self.scan, self.source, &occupied, target, slot)
                } else {
                    quiescent::plan_pun_with_context(
                        &request,
                        &self.scan,
                        self.source,
                        &occupied,
                        prefix.unwrap(),
                        &mut leaf_search,
                        quiescent::PunContext {
                            scope: SearchScope {
                                physical_pc: Some(node.pc),
                                ..SearchScope::default()
                            },
                            callback_free: index != 0,
                            exact_target: Some(target),
                        },
                    )
                };
                let member = match member {
                    Ok(member) => {
                        if !anchor {
                            // This exact-target leaf returned a checked plan.
                            // Outer composition or preceding nodes can still fail.
                            leaf_search.accepted = true;
                        }
                        member
                    }
                    Err(reason) => {
                        self.record(
                            node.pc,
                            Some(target),
                            prefix,
                            Some(reason),
                            false,
                            leaf_search,
                        );
                        continue;
                    }
                };
                let mut next_members = members.clone();
                next_members.push(member);
                let composed = PlannedBundle::compose(
                    vec![ExpectedBytes {
                        address: self.source.start(),
                        bytes: self.request.code.to_vec(),
                    }],
                    next_members.clone(),
                    self.budget,
                );
                let composed = match composed {
                    Ok(bundle) => bundle,
                    Err(reason) => {
                        self.record(
                            node.pc,
                            Some(target),
                            prefix,
                            Some(reason),
                            false,
                            leaf_search,
                        );
                        continue;
                    }
                };
                self.record(node.pc, Some(target), prefix, None, index == 0, leaf_search);
                if index == 0 {
                    self.metrics.runs[run].stop = SearchStop::Accepted;
                    return Ok(Some(composed));
                }
                let next_overlay = composed.plan().final_bytes()[0].bytes.clone();
                if let Some(bundle) = self.descend(index - 1, next_members, next_overlay)? {
                    self.metrics.runs[run].stop = SearchStop::Accepted;
                    return Ok(Some(bundle));
                }
            }
            let proof = proof.unwrap_or_else(|| {
                quiescent::candidate_target_proof(
                    node.pc,
                    [false; 4],
                    policy.preferred_address,
                    self.metrics.runs[run].examined,
                )
            });
            let mut evidence = SearchEvidence::default();
            let proof_run = evidence.begin(
                SearchDomain::VictimImages,
                SearchScope::default(),
                policy.max_candidates,
                None,
            );
            for _ in 0..self.metrics.runs[run].examined {
                evidence.visit(proof_run);
            }
            evidence.finish_candidates(proof_run, proof.clone());
            self.metrics.runs[run].stop = evidence.runs[proof_run].stop;
            self.metrics.runs[run].proof = Some(proof);
        }
        Ok(None)
    }

    fn record(
        &mut self,
        original: u64,
        target: Option<u64>,
        prefix: Option<usize>,
        refusal: Option<Refusal>,
        complete_chain: bool,
        leaf_search: SearchEvidence,
    ) {
        if let Some(reason) = &refusal {
            // Do not hide a selected/structural refusal behind a later generic
            // unavailable address. Every raw reason is still in attempts.
            if self.last_error == Refusal::AllocationUnavailable
                || *reason != Refusal::AllocationUnavailable
            {
                self.last_error = reason.clone();
            }
        }
        self.metrics.attempts.push(ChainAttempt {
            original,
            target,
            prefix_count: prefix.map(|p| p as u8),
            refusal,
            complete_chain,
            leaf_search,
        });
    }
}

fn prefix_choices(policy: TacticPolicy, len: usize) -> Result<Vec<usize>, Refusal> {
    match policy {
        TacticPolicy::GeneralizedPunOnly => Ok(vec![0]),
        TacticPolicy::PrefixPunOnly if len > 1 => Ok((1..len).collect()),
        TacticPolicy::PreferGeneralizedPun => Ok((0..len).collect()),
        TacticPolicy::PrefixPunOnly => Err(Refusal::NoPatchWindow),
        TacticPolicy::RelocationOnly => {
            Err(Refusal::UnsupportedSemantics("chain requires pun".into()))
        }
    }
}

fn pun_window(
    source: AddressRange,
    overlay: &[u8],
    node: OriginalNode,
    prefixes: usize,
) -> Result<AddressRange, Refusal> {
    if prefixes >= node.len || !(1..=4).contains(&node.len) {
        return Err(Refusal::NoPatchWindow);
    }
    if !source.covers(AddressRange::new(node.pc, 5 + prefixes)?) {
        return Err(Refusal::NoPatchWindow);
    }
    let offset = (node.pc - source.start()) as usize;
    let free = node.len - prefixes - 1;
    let mut bytes = [0; 4];
    bytes[free..].copy_from_slice(&overlay[offset + node.len..offset + 5 + prefixes]);
    let next = node
        .pc
        .checked_add(5 + prefixes as u64)
        .ok_or(Refusal::InvalidRange)?;
    let low = u64::try_from(i128::from(next) + i128::from(i32::from_le_bytes(bytes)))
        .map_err(|_| Refusal::AllocationUnavailable)?;
    AddressRange::new(low, 1_usize << (free * 8))
}

fn anchor_member(
    request: &InstallRequest<'_>,
    scan: &ScanResult,
    source: AddressRange,
    occupied: &[AddressRange],
    target: u64,
    slot: usize,
) -> Result<PlannedInstall, Refusal> {
    let original = scan
        .instructions()
        .iter()
        .find(|item| item.address() == request.logical_pc)
        .ok_or(Refusal::NotInstructionHead)?;
    let displaced = qualify_victim(request, scan, original, 5)?;
    let image = TrampolinePlan::from_instruction(scan, request.logical_pc)
        .and_then(|plan| plan.emit_at(target))
        .map_err(|error| Refusal::Backend(error.to_string()))?;
    let allocation = image_allocation(&image)?;
    if allocation.len() > request.allocation.max_mapped_bytes as u64
        || !request
            .allocation
            .ranges
            .iter()
            .any(|range| range.covers(allocation))
        || occupied.iter().any(|range| range.overlaps(allocation))
    {
        return Err(Refusal::AllocationUnavailable);
    }
    let patch = near_redirect(request.logical_pc, target)?;
    instruction_member(request, source, displaced, image, allocation, patch, slot)
}
