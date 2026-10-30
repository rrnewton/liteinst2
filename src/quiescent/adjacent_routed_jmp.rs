//! Explicit artifact-only upper routed JMP/MOV relocation followed by lower B2.
//! This initial profile is JBE rel8 backward, JMP rel8 forward and MOV R12->RDI.
//! The register restriction scopes the first proof; it is not an ISA restriction.

use super::*;
use crate::bundle::{BundleBudget, BundleMemory, PlannedBundle};
use crate::composition::Composition;
use crate::emission::{
    ArtifactEmission, ArtifactFieldEncoding, ArtifactPlan, EmissionContext, PlanningSite,
};
use crate::search::{CandidateProof, SearchEvidence};
use crate::trampoline::{ObservationStackProfile, TrampolineImage, TrampolineLayout};

/// Independent mixed-pair allowances; legacy allocation policies are unchanged.
#[derive(Clone, Copy, Debug)]
pub struct RoutedJmpBudget {
    /// Maximum admitted-upper lower scopes, including empty lower schedules.
    pub max_continuations: usize,
    /// Limits for the two NEW steps only; caller must account for the predecessor.
    pub bundle: BundleBudget,
}

/// Actual stage; local acceptance never means the entire pair accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutedJmpStage {
    /// Original identity, narrow domain and initial pending ownership.
    Preflight,
    /// One exact upper relocation image call.
    UpperImage,
    /// Verification of the emitted upper entries, effects and source route.
    UpperProof,
    /// Upper append to a private predecessor clone.
    UpperAppend,
    /// Lower and external outstanding instructions remain unclaimed.
    UpperPending,
    /// Charged upper-conditioned lower schedule.
    LowerSchedule,
    /// One exact lower B2 image call.
    LowerImage,
    /// Actual lower branch, hook and continuation verification.
    LowerProof,
    /// Lower append to the private upper composition.
    LowerAppend,
    /// External outstanding instructions remain unclaimed.
    LowerPending,
    /// Complete two-new-member bundle accounting.
    Aggregate,
}

/// Terminal reason class, independent of the retained raw core refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutedJmpStop {
    /// A named original-domain or authentication guard failed.
    Eligibility(&'static str),
    /// Another upper image slot was outside the declared allowance.
    UpperBudget,
    /// Cumulative lower images exhausted the declared allowance.
    LowerBudget,
    /// Admitted-upper lower scopes exhausted the declared allowance.
    JointBudget,
    /// J exceeds U or finite bookkeeping arithmetic overflows.
    InvalidBudget,
    /// The declared schedules ended without acceptance.
    Exhausted,
    /// A structural invariant failed; there is no candidate retry.
    Invariant,
}

/// One actual decision, with original ordinals and cumulative debits.
#[derive(Clone, Debug)]
pub struct RoutedJmpEvent {
    /// Decision reached.
    pub stage: RoutedJmpStage,
    /// None is a local acceptance; Some is the actual refusal.
    pub refusal: Option<Refusal>,
    /// Counts before this stage.
    pub before: PairCounts,
    /// Counts after this stage.
    pub after: PairCounts,
    /// Original upper indexed slot and target.
    pub upper: Option<(usize, u64)>,
    /// Original current-scope lower slot and target.
    pub lower: Option<(usize, u64)>,
    /// Actual kernel search diagnostics, absent for non-kernel stages.
    pub search: Option<SearchEvidence>,
}

/// Complete mixed search inventory; no global impossibility claim.
#[derive(Clone, Debug)]
pub struct RoutedJmpEvidence {
    /// Original PCs in lower, upper order.
    pub selected: [u64; 2],
    /// Original suffix entry, when original qualification succeeded.
    pub suffix: Option<u64>,
    /// Final cumulative U/L/J work.
    pub counts: PairCounts,
    /// Actual entered upper slots; None targets consumed no image call.
    pub upper_slots: Vec<(usize, Option<u64>)>,
    /// Certificate for the original indexed upper policy prefix.
    pub upper_proof: Option<CandidateProof>,
    /// Original lower policies applied to actual upper overlays, including empty schedules.
    pub lower_schedules: Vec<PairSchedule>,
    /// Chronological decisions.
    pub events: Vec<RoutedJmpEvent>,
    /// This bounded profile never proves global classification completeness.
    pub classification_complete: bool,
    /// True only after both members and pair accounting accepted.
    pub accepted: bool,
}

/// A refusal retains every attempted stage and never a partial plan.
#[derive(Clone, Debug)]
pub struct RoutedJmpFailure {
    /// Original core reason.
    pub reason: Refusal,
    /// Independent stopping class.
    pub stop: RoutedJmpStop,
    /// Decision location.
    pub stage: RoutedJmpStage,
    /// All actual bounded work.
    pub evidence: Box<RoutedJmpEvidence>,
    /// Next returned or proven omitted target, not an executed image.
    pub unvisited_target: Option<u64>,
}

/// Opaque two-member artifact, with distinct mixed-tactic attribution.
#[derive(Clone, Debug)]
pub struct RoutedJmpArtifactPlan {
    members: [ArtifactPlan; 2],
    evidence: RoutedJmpEvidence,
    memory: BundleMemory,
}
impl RoutedJmpArtifactPlan {
    /// Actual append order: upper Relocation, lower GeneralizedPun.
    pub const fn members(&self) -> &[ArtifactPlan; 2] {
        &self.members
    }
    /// Exact original selected PCs in append order.
    pub fn logical_pcs(&self) -> [u64; 2] {
        [self.evidence.selected[1], self.evidence.selected[0]]
    }
    /// Actual mixed search inventory.
    pub const fn evidence(&self) -> &RoutedJmpEvidence {
        &self.evidence
    }
    /// New-pair mapping accounting, excluding predecessor resources.
    pub const fn memory(&self) -> BundleMemory {
        self.memory
    }
    /// No native, router, loader, CPU or callback admission is supplied.
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}

struct Stop {
    reason: Refusal,
    stop: RoutedJmpStop,
    stage: RoutedJmpStage,
    target: Option<u64>,
}
fn refused(name: &'static str, reason: Refusal) -> Stop {
    Stop {
        reason,
        stop: RoutedJmpStop::Eligibility(name),
        stage: RoutedJmpStage::Preflight,
        target: None,
    }
}
fn domain(name: &'static str) -> Stop {
    refused(name, Refusal::UnsupportedSemantics(name.into()))
}
fn budget(stop: RoutedJmpStop, stage: RoutedJmpStage, target: Option<u64>) -> Stop {
    Stop {
        reason: Refusal::AllocationUnavailable,
        stop,
        stage,
        target,
    }
}
struct Work {
    evidence: RoutedJmpEvidence,
    upper: Option<(usize, u64)>,
    lower: Option<(usize, u64)>,
    last: Option<(RoutedJmpStage, Refusal)>,
}
impl Work {
    fn record(
        &mut self,
        stage: RoutedJmpStage,
        reason: Option<Refusal>,
        before: PairCounts,
        search: Option<SearchEvidence>,
    ) -> Result<(), Stop> {
        self.evidence.events.push(RoutedJmpEvent {
            stage,
            refusal: reason.clone(),
            before,
            after: self.evidence.counts,
            upper: self.upper,
            lower: self.lower,
            search,
        });
        if let Some(reason) = reason {
            self.last = Some((stage, reason.clone()));
            if matches!(reason, Refusal::InvalidRange | Refusal::InvalidPlan) {
                return Err(Stop {
                    reason,
                    stop: RoutedJmpStop::Invariant,
                    stage,
                    target: None,
                });
            }
        }
        Ok(())
    }
}

/// Sealed authority for exactly one original JMP and its unselected MOV entry.
/// Only this module constructs it after authenticating the full original view.
pub(crate) struct VerifiedRoutedJmpSuffix {
    lower: u64,
    upper: u64,
    suffix: u64,
    end: u64,
    backward: u64,
    forward: u64,
    original: [u8; 7],
    identity: CodeIdentity,
    source: AddressRange,
    original_source: Vec<u8>,
    entries: LegalEntrySet,
}
impl VerifiedRoutedJmpSuffix {
    pub(crate) fn upper(&self) -> u64 {
        self.upper
    }
    pub(crate) fn end(&self) -> u64 {
        self.end
    }
    pub(crate) fn source(&self) -> AddressRange {
        self.source
    }
    pub(crate) fn matches_scan(&self, scan: &ScanResult) -> bool {
        let Some(first) = scan.instructions().first() else {
            return false;
        };
        let Some(offset) = self
            .lower
            .checked_sub(first.address())
            .and_then(|n| usize::try_from(n).ok())
        else {
            return false;
        };
        first.address() == self.source.start()
            && scan.snapshot() == self.original_source
            && scan.snapshot().get(offset..offset + 7) == Some(self.original.as_slice())
            && scan
                .instructions()
                .iter()
                .any(|i| i.address() == self.upper && i.len() == 2)
            && scan
                .instructions()
                .iter()
                .any(|i| i.address() == self.suffix && i.len() == 3)
    }
    pub(crate) fn matches_request(&self, request: &PlanningRequest<'_>, scan: &ScanResult) -> bool {
        self.matches_scan(scan)
            && request.identity == self.identity
            && request.original_code == self.original_source
            && request.base_address == self.source.start()
            && request.function == self.source
            && request.logical_pc == self.upper
            && request.block.start() == self.upper
            && request.block.len() == 2
            && request.semantics == HookSemantics::Observe
            && request.entries == &self.entries
    }
    fn verify_member(
        &self,
        member: &PlannedInstall,
        input: &ArtifactEmission,
        upper: bool,
    ) -> Result<(), Refusal> {
        let pc = if upper { self.upper } else { self.lower };
        let target = if upper { self.forward } else { self.backward };
        let continuation = if upper { self.end } else { self.upper };
        let suffix = upper.then_some((self.suffix, &self.original[4..]));
        verify_view(
            ImageView::from(member.image()),
            input,
            pc,
            target,
            continuation,
            suffix,
        )?;
        let p = member.plan().parts();
        if p.logical_pc != pc
            || p.physical_pc != pc
            || p.writes.len() != 1
            || p.writes[0].address != pc
            || p.generated.len() != 1
            || p.generated[0].address != member.image().address()
            || p.generated[0].bytes != member.image().bytes()
            || p.generated[0].program_counters != member.image().program_counter_mappings()
            || p.identity != self.identity
            || p.entries != self.entries
            || !p.requirements.quiescent
            || !p.requirements.sync_core
        {
            return Err(Refusal::InvalidPlan);
        }
        if upper {
            let entry = member.image().entry_routes()[1].1;
            let expected = vec![
                EntryObligation::Preserved(self.upper),
                EntryObligation::Routed(EntryRoute {
                    original: self.suffix,
                    generated: entry,
                }),
            ];
            let patch = &p.writes[0].bytes;
            if p.kind != PlanKind::Relocation
                || p.displaced != AddressRange::new(self.upper, 5)?
                || p.obligations != expected
                || !p.requirements.sigill_router
                || patch.len() != 5
                || patch[0] != 0xe9
                || !ILLEGAL.contains(&patch[2])
                || i128::from(self.upper)
                    + 5
                    + i128::from(i32::from_le_bytes(patch[1..5].try_into().unwrap()))
                    != i128::from(member.image().address())
            {
                return Err(Refusal::InvalidPlan);
            }
        } else {
            let PlanKind::GeneralizedPun(pun) = &p.kind else {
                return Err(Refusal::InvalidPlan);
            };
            if p.displaced != AddressRange::new(self.lower, 2)?
                || p.requirements.sigill_router
                || p.writes[0].bytes.len() != 2
                || p.writes[0].bytes[0] != 0xe9
                || pun.instruction_len != 2
                || pun.consumed != AddressRange::new(self.lower, 5)?
                || pun.store.address != self.lower
                || pun.store.bytes != p.writes[0].bytes
                || p.obligations
                    != vec![
                        EntryObligation::Preserved(self.lower),
                        EntryObligation::Preserved(self.upper),
                        EntryObligation::Preserved(self.suffix),
                    ]
            {
                return Err(Refusal::InvalidPlan);
            }
        }
        Ok(())
    }

    fn verify_composed(
        &self,
        pair: &Composition,
        upper: &PlannedInstall,
        lower: &PlannedInstall,
    ) -> Result<(), Refusal> {
        let current =
            pair.planning_overlay(self.identity, self.source.start(), &self.original_source)?;
        let offset = (self.lower - self.source.start()) as usize;
        let bytes = current
            .get(offset..offset + 7)
            .ok_or(Refusal::InvalidPlan)?;
        if bytes[..2] != lower.plan().parts().writes[0].bytes
            || bytes[2..] != upper.plan().parts().writes[0].bytes
            || bytes[0] != 0xe9
            || bytes[2] != 0xe9
            || !ILLEGAL.contains(&bytes[4])
            || i128::from(self.lower)
                + 5
                + i128::from(i32::from_le_bytes(bytes[1..5].try_into().unwrap()))
                != i128::from(lower.image().address())
            || i128::from(self.upper)
                + 5
                + i128::from(i32::from_le_bytes(bytes[3..7].try_into().unwrap()))
                != i128::from(upper.image().address())
        {
            return Err(Refusal::InvalidPlan);
        }
        // The lower member's local Preserved(F) means current source bytes, not
        // original MOV bytes. The returned upper member retains the sole route.
        if !upper
            .plan()
            .parts()
            .obligations
            .contains(&EntryObligation::Routed(EntryRoute {
                original: self.suffix,
                generated: upper.image().entry_routes()[1].1,
            }))
        {
            return Err(Refusal::InvalidPlan);
        }
        Ok(())
    }
}

struct ImageView<'a> {
    address: u64,
    bytes: &'a [u8],
    layout: TrampolineLayout,
    entries: &'a [(u64, u64)],
    bodies: &'a [(u64, u64)],
    maps: &'a [crate::trampoline::ProgramCounterMapping],
    metadata: Option<&'a crate::emission::ArtifactImageMetadata>,
    plain: bool,
}
impl<'a> From<&'a TrampolineImage> for ImageView<'a> {
    fn from(image: &'a TrampolineImage) -> Self {
        Self {
            address: image.address(),
            bytes: image.bytes(),
            layout: image.layout(),
            entries: image.entry_routes(),
            bodies: image.instruction_boundaries(),
            maps: image.program_counter_mappings(),
            metadata: image.artifact_metadata(),
            plain: image.controls().is_empty()
                && image.clock().is_none()
                && image.precontext_selector().is_none(),
        }
    }
}
fn verify_view(
    v: ImageView<'_>,
    input: &ArtifactEmission,
    pc: u64,
    target: u64,
    continuation: u64,
    suffix: Option<(u64, &[u8])>,
) -> Result<(), Refusal> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
    let bad = || Refusal::InvalidPlan;
    let count = if suffix.is_some() { 2 } else { 1 };
    let l = v.layout;
    let hook_end = l
        .instrumentation_len
        .checked_add(l.restore_len)
        .ok_or_else(bad)?;
    let tail = v.bytes.len().checked_sub(5).ok_or_else(bad)?;
    let at = |off: usize| v.address.checked_add(off as u64).ok_or_else(bad);
    if !v.plain
        || l.observation_stack_profile != ObservationStackProfile::Legacy128
        || l.saved_extended_state != input.profile().saved_state()
        || l.total_len() != Some(v.bytes.len())
        || l.relocated_prefix_len != 0
        || l.entry_stop_len != 0
        || l.completion_stop_len != 0
        || l.return_len != 5
        || l.instrumentation_len == 0
        || l.restore_len == 0
        || hook_end >= tail
        || v.entries.len() != count
        || v.bodies.len() != count
        || v.maps.len() != count + 1
        || v.entries[0] != (pc, v.address)
        || v.bodies[0] != (pc, at(hook_end)?)
    {
        return Err(bad());
    }
    let mut decoder = Decoder::with_ip(
        64,
        &v.bytes[hook_end..tail],
        at(hook_end)?,
        DecoderOptions::NONE,
    );
    let branch = decoder.decode();
    if branch.is_invalid()
        || branch.op0_kind() != OpKind::NearBranch64
        || branch.near_branch_target() != target
        || branch.mnemonic()
            != if suffix.is_some() {
                Mnemonic::Jmp
            } else {
                Mnemonic::Jbe
            }
        || branch.flow_control()
            != if suffix.is_some() {
                FlowControl::UnconditionalBranch
            } else {
                FlowControl::ConditionalBranch
            }
    {
        return Err(bad());
    }
    let branch_end = hook_end.checked_add(branch.len()).ok_or_else(bad)?;
    let width = if suffix.is_some() {
        match v.bytes.get(hook_end..branch_end) {
            Some([0xeb, _]) => 1,
            Some([0xe9, _, _, _, _]) => 4,
            _ => return Err(bad()),
        }
    } else {
        match v.bytes.get(hook_end..branch_end) {
            Some([0x76, _]) => 1,
            Some([0x0f, 0x86, _, _, _, _]) => 4,
            _ => return Err(bad()),
        }
    };
    if let Some((source, bytes)) = suffix {
        if v.entries[1] != (source, at(branch_end)?)
            || v.bodies[1] != v.entries[1]
            || v.bytes.get(branch_end..tail) != Some(bytes)
        {
            return Err(bad());
        }
    } else if branch_end != tail {
        return Err(bad());
    }
    for i in 0..count {
        let end = if i + 1 < count {
            v.entries[i + 1].1
        } else {
            at(tail)?
        };
        if v.maps[i].generated_start() != v.entries[i].1
            || v.maps[i].generated_end() != end
            || v.maps[i].logical_address() != v.entries[i].0
        {
            return Err(bad());
        }
    }
    if v.maps[count].generated_start() != at(tail)?
        || v.maps[count].generated_end() != at(v.bytes.len())?
        || v.maps[count].logical_address() != continuation
        || v.bytes[tail] != 0xe9
        || i128::from(at(v.bytes.len())?)
            + i128::from(i32::from_le_bytes(v.bytes[tail + 1..].try_into().unwrap()))
            != i128::from(continuation)
    {
        return Err(bad());
    }
    // All instrumentation/restore bytes are real instructions; no byte-pattern
    // search can mistake an immediate for an extra hook.
    let mut helpers = Decoder::with_ip(64, &v.bytes[..hook_end], v.address, DecoderOptions::NONE);
    let mut calls = 0;
    let mut call_field = None;
    let mut helper_heads = Vec::new();
    while helpers.can_decode() {
        let i = helpers.decode();
        helper_heads.push(i.ip() - v.address);
        if i.is_invalid() || !matches!(i.flow_control(), FlowControl::Next | FlowControl::Call) {
            return Err(bad());
        }
        if matches!(
            i.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) {
            if i.flow_control() != FlowControl::Call
                || i.op0_kind() != OpKind::NearBranch64
                || Some(i.near_branch_target()) != input.hook().address
            {
                return Err(bad());
            }
            calls += 1;
            if i.len() != 5 || v.bytes[(i.ip() - v.address) as usize] != 0xe8 {
                return Err(bad());
            }
            call_field = Some((i.ip() - v.address + 1, i.next_ip() - v.address));
        }
    }
    if calls != 1 {
        return Err(bad());
    }
    let m = v.metadata.ok_or_else(bad)?;
    if m.qualification_complete() || m.fields().len() != 4 {
        return Err(bad());
    }
    let roles = [
        ("LogicalPc".to_string(), pc),
        (
            "HookCall".to_string(),
            input.hook().address.ok_or_else(bad)?,
        ),
        (format!("OriginalBranch {{ original_pc: {pc} }}"), target),
        ("Return".to_string(), continuation),
    ];
    for (role, expected) in roles {
        let found: Vec<_> = m.fields().iter().filter(|f| f.role == role).collect();
        if found.len() != 1 {
            return Err(bad());
        }
        let f = found[0];
        let off = usize::try_from(f.offset).map_err(|_| bad())?;
        let end = off.checked_add(f.width).ok_or_else(bad)?;
        let bytes = v.bytes.get(off..end).ok_or_else(bad)?;
        if f.target != i128::from(expected)
            || f.bias_domain != input.profile().bias_domain()
            || f.origin > v.bytes.len() as u64
        {
            return Err(bad());
        }
        let displacement = match (f.encoding, f.width) {
            (ArtifactFieldEncoding::Delta, 8) if role == "LogicalPc" => {
                if off < 9
                    || f.origin != f.offset - 2
                    || end + 4 > l.instrumentation_len
                    || v.bytes[off - 9..off] != [0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x48, 0xba]
                    || v.bytes[end..end + 4] != [0x48, 0x01, 0xd0, 0x50]
                    || [off - 9, off - 2, end, end + 3]
                        .iter()
                        .any(|at| !helper_heads.contains(&(*at as u64)))
                {
                    return Err(bad());
                }
                i128::from(i64::from_le_bytes(bytes.try_into().unwrap()))
            }
            (ArtifactFieldEncoding::Relative, 4) if role == "HookCall" => {
                if off == 0
                    || v.bytes[off - 1] != 0xe8
                    || f.origin != end as u64
                    || end > l.instrumentation_len
                    || call_field != Some((f.offset, f.origin))
                {
                    return Err(bad());
                }
                i128::from(i32::from_le_bytes(bytes.try_into().unwrap()))
            }
            (ArtifactFieldEncoding::Relative, 4) if role == "Return" => {
                if off != tail + 1 || f.origin != v.bytes.len() as u64 {
                    return Err(bad());
                }
                i128::from(i32::from_le_bytes(bytes.try_into().unwrap()))
            }
            (ArtifactFieldEncoding::Relative, 1 | 4) if role.starts_with("OriginalBranch ") => {
                if end != branch_end || f.origin != branch_end as u64 || f.width != width {
                    return Err(bad());
                }
                if f.width == 1 {
                    i128::from(bytes[0] as i8)
                } else {
                    i128::from(i32::from_le_bytes(bytes.try_into().unwrap()))
                }
            }
            _ => return Err(bad()),
        };
        if i128::from(v.address) + i128::from(f.origin) + displacement != i128::from(expected) {
            return Err(bad());
        }
    }
    Ok(())
}

struct Prepared {
    current: Vec<u8>,
    source: AddressRange,
    scan: ScanResult,
    proof: VerifiedRoutedJmpSuffix,
    lower_pending: Vec<AddressRange>,
}
fn preflight(
    requests: &[PlanningRequest<'_>; 2],
    input: &ArtifactEmission,
    predecessor: &Composition,
    pending: &[AddressRange],
    limits: RoutedJmpBudget,
) -> Result<Prepared, Stop> {
    let [lower, upper] = requests;
    let current = predecessor
        .planning_overlay(lower.identity, lower.base_address, lower.original_code)
        .map_err(|e| refused("original-authentication", e))?;
    if lower.identity != upper.identity {
        return Err(refused("identity", Refusal::StaleGeneration));
    }
    if lower.base_address != upper.base_address
        || lower.original_code != upper.original_code
        || lower.function != upper.function
        || lower.entries != upper.entries
    {
        return Err(domain("original-view"));
    }
    let (source, scan) = validated_source_core(lower).map_err(|e| refused("original", e))?;
    validated_source_core(upper).map_err(|e| refused("original", e))?;
    let l = lower.logical_pc;
    let u = l.checked_add(2).ok_or_else(|| domain("geometry"))?;
    let f = u.checked_add(2).ok_or_else(|| domain("geometry"))?;
    let end = u.checked_add(5).ok_or_else(|| domain("geometry"))?;
    if upper.logical_pc != u
        || !source.contains(end)
        || lower.function != source
        || lower.entries.scope != source
        || lower.block != AddressRange::new(l, 2).map_err(|e| refused("geometry", e))?
        || upper.block != AddressRange::new(u, 2).map_err(|e| refused("geometry", e))?
        || l / 64 != (u - 1) / 64
    {
        return Err(domain("geometry"));
    }
    let entries = lower.entries;
    if entries.completeness != EntryCompleteness::AllInstructionHeads
        || entries.entries.len() != scan.instructions().len()
        || entries
            .entries
            .iter()
            .zip(scan.instructions())
            .any(|(a, b)| a.address != b.address() || a.requires_endbr)
    {
        return Err(domain("all-heads-no-cet"));
    }
    if let ResumeObligation::Enumerated(pcs) = &entries.resumes {
        if pcs.windows(2).any(|p| p[0] >= p[1]) {
            return Err(domain("resumes"));
        }
    }
    for (index, request) in requests.iter().enumerate() {
        if request.semantics != HookSemantics::Observe
            || request.search.max_upstream_bytes != 0
            || request.search.max_sites != 1
            || request.search.max_displaced_bytes != if index == 0 { 2 } else { 5 }
            || request.search.tactics
                != if index == 0 {
                    TacticPolicy::GeneralizedPunOnly
                } else {
                    TacticPolicy::RelocationOnly
                }
        {
            return Err(domain("exact-search-observe"));
        }
        if request.allocation.max_mappings == 0 || request.allocation.max_mapped_bytes < 4096 {
            return Err(refused("site-resource", Refusal::AllocationUnavailable));
        }
    }
    if input.hook().address.is_none() {
        return Err(domain("resolved-hook"));
    }
    let offset = usize::try_from(l - source.start()).map_err(|_| domain("geometry"))?;
    let original: [u8; 7] = lower
        .original_code
        .get(offset..offset + 7)
        .ok_or_else(|| domain("geometry"))?
        .try_into()
        .map_err(|_| domain("geometry"))?;
    if original[0] != 0x76
        || original[2] != 0xeb
        || !matches!(&original[4..], [0x4c, 0x89, 0xe7] | [0x49, 0x8b, 0xfc])
    {
        return Err(domain("branch-suffix-domain"));
    }
    let item = |pc| {
        scan.instructions()
            .iter()
            .find(|i| i.address() == pc)
            .ok_or_else(|| domain("head"))
    };
    let a = item(l)?.instruction();
    let b = item(u)?.instruction();
    let s = item(f)?.instruction();
    if a.len() != 2
        || a.mnemonic() != Mnemonic::Jbe
        || a.op0_kind() != iced_x86::OpKind::NearBranch64
        || b.len() != 2
        || b.mnemonic() != Mnemonic::Jmp
        || b.op0_kind() != iced_x86::OpKind::NearBranch64
        || s.len() != 3
        || s.mnemonic() != Mnemonic::Mov
        || s.flow_control() != iced_x86::FlowControl::Next
        || s.op_count() != 2
        || s.op0_register() != iced_x86::Register::RDI
        || s.op1_register() != iced_x86::Register::R12
        || s.is_ip_rel_memory_operand()
    {
        return Err(domain("decoded-domain"));
    }
    let (backward, forward) = (a.near_branch_target(), b.near_branch_target());
    if backward >= l
        || forward < end
        || !source.contains(backward)
        || !source.contains(forward)
        || scan.site(backward).is_none()
        || scan.site(forward).is_none()
        || scan.site(end).is_none()
    {
        return Err(domain("external-original-target"));
    }
    let lower_range = AddressRange::new(l, 2).map_err(|e| refused("geometry", e))?;
    let upper_range = AddressRange::new(u, 5).map_err(|e| refused("geometry", e))?;
    if pending.windows(2).any(|p| p[0].end() > p[1].start())
        || pending
            .iter()
            .any(|r| r.overlaps(lower_range) || r.overlaps(upper_range))
    {
        return Err(refused(
            "pending-shape-or-selected-suffix",
            Refusal::InvalidRange,
        ));
    }
    let mut initial = pending.to_vec();
    initial.extend([lower_range, upper_range]);
    initial.sort_unstable_by_key(|r| r.start());
    predecessor
        .require_unclaimed_ranges(&initial)
        .map_err(|e| refused("initial-pending", e))?;
    let (u_cap, l_cap, j_cap) = (
        upper.allocation.max_candidates,
        lower.allocation.max_candidates,
        limits.max_continuations,
    );
    let shape = || -> Option<()> {
        u_cap.checked_mul(std::mem::size_of::<(usize, Option<u64>)>())?;
        u_cap
            .checked_mul(4)?
            .checked_add(l_cap.checked_mul(5)?)?
            .checked_add(j_cap)?
            .checked_add(1)?
            .checked_mul(std::mem::size_of::<RoutedJmpEvent>())?;
        j_cap
            .checked_mul(l_cap)?
            .checked_mul(std::mem::size_of::<u64>())?;
        j_cap
            .checked_mul(lower.allocation.ranges.len())?
            .checked_mul(l_cap)?;
        Some(())
    };
    if j_cap > u_cap || shape().is_none() {
        return Err(budget(
            RoutedJmpStop::InvalidBudget,
            RoutedJmpStage::Preflight,
            None,
        ));
    }
    for (cap, stop) in [
        (u_cap, RoutedJmpStop::UpperBudget),
        (l_cap, RoutedJmpStop::LowerBudget),
        (j_cap, RoutedJmpStop::JointBudget),
    ] {
        if cap == 0 {
            return Err(budget(stop, RoutedJmpStage::Preflight, None));
        }
    }
    let mut lower_pending = pending.to_vec();
    lower_pending.push(lower_range);
    lower_pending.sort_unstable_by_key(|r| r.start());
    Ok(Prepared {
        current,
        source,
        scan,
        proof: VerifiedRoutedJmpSuffix {
            lower: l,
            upper: u,
            suffix: f,
            end,
            backward,
            forward,
            original,
            identity: lower.identity,
            source,
            original_source: lower.original_code.to_vec(),
            entries: entries.clone(),
        },
        lower_pending,
    })
}

/// Plans an atomic artifact pair in the narrow JBE/EB/MOV R12->RDI domain.
///
/// Supply lower then upper with identical complete original all-head facts.
/// Original blocks are exactly the two original branches (two bytes each);
/// the upper proof, not a widened basic block, authorizes its unselected MOV.
/// The lower search is B2/0-upstream/2-displaced/1-site; upper is
/// RelocationOnly/0-upstream/5-displaced/1-site. External pending ranges must
/// cover every other selected body, including the MOV if it is selected.
///
/// U and L are the independent allocation max_candidates; J is independent
/// and cumulative. No predecessor mutation or live publication occurs. Pair
/// limits exclude predecessor resources; callers must enforce full-selection
/// budgets and stage both selected associations atomically before publication.
/// All original code/entry/occupancy, router, hook and target authority remains
/// owed; this result cannot be converted to a live publisher.
pub fn plan_adjacent_routed_jmp_with_emission_after(
    sites: [PlanningSite<'_>; 2],
    input: &ArtifactEmission,
    predecessor: &Composition,
    external_pending: &[AddressRange],
    limits: RoutedJmpBudget,
) -> Result<RoutedJmpArtifactPlan, RoutedJmpFailure> {
    let requests = sites.map(|site| PlanningRequest {
        original_code: site.code,
        site,
        emission: EmissionContext::Artifact(input),
    });
    let mut work = Work {
        evidence: RoutedJmpEvidence {
            selected: sites.map(|s| s.logical_pc),
            suffix: None,
            counts: PairCounts::default(),
            upper_slots: Vec::new(),
            upper_proof: None,
            lower_schedules: Vec::new(),
            events: Vec::new(),
            classification_complete: false,
            accepted: false,
        },
        upper: None,
        lower: None,
        last: None,
    };
    let result = (|| -> Result<([ArtifactPlan; 2], BundleMemory), Stop> {
        let p = match preflight(&requests, input, predecessor, external_pending, limits) {
            Ok(p) => p,
            Err(e) => {
                let _ = work.record(
                    RoutedJmpStage::Preflight,
                    Some(e.reason.clone()),
                    work.evidence.counts,
                    None,
                );
                return Err(e);
            }
        };
        work.evidence.suffix = Some(p.proof.suffix);
        work.record(RoutedJmpStage::Preflight, None, work.evidence.counts, None)?;
        let upper = &requests[1];
        let lower = &requests[0];
        let mask = [false, true, false, false];
        let upper_proof = candidate_target_proof(
            upper.logical_pc,
            mask,
            upper.allocation.preferred_address,
            upper.allocation.max_candidates,
        );
        work.evidence.upper_proof = Some(upper_proof.clone());
        for ordinal in 0..upper.allocation.max_candidates {
            let target = candidate_target(
                upper.logical_pc,
                mask,
                upper.allocation.preferred_address,
                ordinal,
            );
            if work.evidence.counts.joint == limits.max_continuations {
                return Err(budget(
                    RoutedJmpStop::JointBudget,
                    RoutedJmpStage::UpperImage,
                    target,
                ));
            }
            if work.evidence.counts.lower == lower.allocation.max_candidates {
                return Err(budget(
                    RoutedJmpStop::LowerBudget,
                    RoutedJmpStage::UpperImage,
                    target,
                ));
            }
            work.evidence.upper_slots.push((ordinal, target));
            let Some(target) = target else {
                continue;
            };
            work.upper = Some((ordinal, target));
            work.lower = None;
            let before = work.evidence.counts;
            work.evidence.counts.upper += 1;
            let mut search = SearchEvidence::default();
            let request = upper.with_code(&p.current);
            let instructions = p
                .scan
                .instructions()
                .iter()
                .filter(|i| p.proof.upper <= i.address() && i.address() < p.proof.end)
                .collect();
            let member = emit_relocation_window(
                &request,
                &p.scan,
                p.source,
                input.occupied(),
                (None, None),
                RelocationWindow {
                    physical: p.proof.upper,
                    end: p.proof.end,
                    displaced: AddressRange::new(p.proof.upper, 5)
                        .map_err(|e| refused("geometry", e))?,
                    instructions,
                    authority: RelocationAuthority::RoutedJmp {
                        proof: &p.proof,
                        ordinal,
                        target,
                    },
                },
                &mut search,
            );
            let mut upper_member = match member {
                Ok(m) => {
                    search.accepted = true;
                    work.record(
                        RoutedJmpStage::UpperImage,
                        None,
                        before,
                        Some(search.clone()),
                    )?;
                    m
                }
                Err(e) => {
                    work.record(RoutedJmpStage::UpperImage, Some(e), before, Some(search))?;
                    continue;
                }
            };
            search.accepted = true;
            upper_member.metrics.search = search;
            p.proof
                .verify_member(&upper_member, input, true)
                .map_err(|reason| Stop {
                    reason,
                    stop: RoutedJmpStop::Invariant,
                    stage: RoutedJmpStage::UpperProof,
                    target: None,
                })
                .inspect_err(|e| {
                    let _ =
                        work.record(e.stage, Some(e.reason.clone()), work.evidence.counts, None);
                })?;
            work.record(RoutedJmpStage::UpperProof, None, work.evidence.counts, None)?;
            let mut after_upper = predecessor.clone();
            if let Err(e) = after_upper.append(upper_member.plan()) {
                work.record(
                    RoutedJmpStage::UpperAppend,
                    Some(e),
                    work.evidence.counts,
                    None,
                )?;
                continue;
            }
            work.record(
                RoutedJmpStage::UpperAppend,
                None,
                work.evidence.counts,
                None,
            )?;
            if let Err(e) = after_upper.require_unclaimed_ranges(&p.lower_pending) {
                work.record(
                    RoutedJmpStage::UpperPending,
                    Some(e),
                    work.evidence.counts,
                    None,
                )?;
                continue;
            }
            work.record(
                RoutedJmpStage::UpperPending,
                None,
                work.evidence.counts,
                None,
            )?;
            let before = work.evidence.counts;
            work.evidence.counts.joint += 1;
            let current = match after_upper.planning_overlay(
                lower.identity,
                lower.base_address,
                lower.original_code,
            ) {
                Ok(current) => current,
                Err(reason) => {
                    let _ = work.record(
                        RoutedJmpStage::LowerSchedule,
                        Some(reason.clone()),
                        before,
                        None,
                    );
                    return Err(Stop {
                        reason,
                        stop: RoutedJmpStop::Invariant,
                        stage: RoutedJmpStage::LowerSchedule,
                        target: None,
                    });
                }
            };
            let offset = (lower.logical_pc - p.source.start()) as usize;
            let fixed = i32::from_le_bytes([
                0,
                current[offset + 2],
                current[offset + 3],
                current[offset + 4],
            ]);
            let low = match u64::try_from(i128::from(lower.logical_pc) + 5 + i128::from(fixed)) {
                Ok(low) => low,
                Err(_) => {
                    work.record(
                        RoutedJmpStage::LowerSchedule,
                        Some(Refusal::AllocationUnavailable),
                        before,
                        None,
                    )?;
                    continue;
                }
            };
            let window = match AddressRange::new(low, 256) {
                Ok(window) => window,
                Err(reason) => {
                    let _ = work.record(
                        RoutedJmpStage::LowerSchedule,
                        Some(reason.clone()),
                        before,
                        None,
                    );
                    return Err(Stop {
                        reason,
                        stop: RoutedJmpStop::Invariant,
                        stage: RoutedJmpStage::LowerSchedule,
                        target: None,
                    });
                }
            };
            let candidates = pun_candidates(window, lower.allocation);
            work.evidence.lower_schedules.push(PairSchedule {
                upper_ordinal: Some(ordinal),
                upper_target: Some(target),
                window,
                targets: candidates.addresses.clone(),
                proof: candidates.proof.clone(),
            });
            work.record(
                RoutedJmpStage::LowerSchedule,
                candidates
                    .addresses
                    .is_empty()
                    .then_some(Refusal::AllocationUnavailable),
                before,
                None,
            )?;
            for (li, lt) in candidates.addresses.into_iter().enumerate() {
                if work.evidence.counts.lower == lower.allocation.max_candidates {
                    return Err(budget(
                        RoutedJmpStop::LowerBudget,
                        RoutedJmpStage::LowerImage,
                        Some(lt),
                    ));
                }
                work.lower = Some((li, lt));
                let before = work.evidence.counts;
                work.evidence.counts.lower += 1;
                let mut search = SearchEvidence::default();
                let member = plan_pun_with_context_core(
                    &lower.with_code(&current),
                    &p.scan,
                    p.source,
                    input.occupied(),
                    0,
                    &mut search,
                    PunContext {
                        scope: SearchScope::default(),
                        callback_free: false,
                        exact_target: Some(lt),
                    },
                );
                let mut lower_member = match member {
                    Ok(m) => {
                        search.accepted = true;
                        work.record(
                            RoutedJmpStage::LowerImage,
                            None,
                            before,
                            Some(search.clone()),
                        )?;
                        m
                    }
                    Err(e) => {
                        work.record(RoutedJmpStage::LowerImage, Some(e), before, Some(search))?;
                        continue;
                    }
                };
                search.accepted = true;
                lower_member.metrics.search = search;
                if let Err(reason) = p.proof.verify_member(&lower_member, input, false) {
                    let _ = work.record(
                        RoutedJmpStage::LowerProof,
                        Some(reason.clone()),
                        work.evidence.counts,
                        None,
                    );
                    return Err(Stop {
                        reason,
                        stop: RoutedJmpStop::Invariant,
                        stage: RoutedJmpStage::LowerProof,
                        target: None,
                    });
                }
                work.record(RoutedJmpStage::LowerProof, None, work.evidence.counts, None)?;
                let mut pair = after_upper.clone();
                if let Err(e) = pair.append(lower_member.plan()) {
                    work.record(
                        RoutedJmpStage::LowerAppend,
                        Some(e),
                        work.evidence.counts,
                        None,
                    )?;
                    continue;
                }
                if let Err(e) = p.proof.verify_composed(&pair, &upper_member, &lower_member) {
                    work.record(
                        RoutedJmpStage::LowerAppend,
                        Some(e),
                        work.evidence.counts,
                        None,
                    )?;
                    return Err(Stop {
                        reason: Refusal::InvalidPlan,
                        stop: RoutedJmpStop::Invariant,
                        stage: RoutedJmpStage::LowerAppend,
                        target: None,
                    });
                }
                work.record(
                    RoutedJmpStage::LowerAppend,
                    None,
                    work.evidence.counts,
                    None,
                )?;
                if let Err(e) = pair.require_unclaimed_ranges(external_pending) {
                    work.record(
                        RoutedJmpStage::LowerPending,
                        Some(e),
                        work.evidence.counts,
                        None,
                    )?;
                    continue;
                }
                work.record(
                    RoutedJmpStage::LowerPending,
                    None,
                    work.evidence.counts,
                    None,
                )?;
                let bundle = match PlannedBundle::compose(
                    predecessor.final_bytes().to_vec(),
                    vec![upper_member.clone(), lower_member.clone()],
                    limits.bundle,
                ) {
                    Ok(b) => b,
                    Err(e) => {
                        work.record(
                            RoutedJmpStage::Aggregate,
                            Some(e),
                            work.evidence.counts,
                            None,
                        )?;
                        continue;
                    }
                };
                work.record(RoutedJmpStage::Aggregate, None, work.evidence.counts, None)?;
                work.evidence.accepted = true;
                return Ok((
                    [
                        ArtifactPlan::single(upper_member),
                        ArtifactPlan::single(lower_member),
                    ],
                    bundle.plan().memory(),
                ));
            }
            if let Some(t) = omitted(&candidates.proof) {
                return Err(budget(
                    RoutedJmpStop::LowerBudget,
                    RoutedJmpStage::LowerSchedule,
                    Some(t),
                ));
            }
        }
        if let Some(t) = omitted(&upper_proof) {
            return Err(budget(
                RoutedJmpStop::UpperBudget,
                RoutedJmpStage::UpperImage,
                Some(t),
            ));
        }
        let (stage, reason) = work
            .last
            .clone()
            .unwrap_or((RoutedJmpStage::UpperImage, Refusal::AllocationUnavailable));
        Err(Stop {
            reason,
            stop: RoutedJmpStop::Exhausted,
            stage,
            target: None,
        })
    })();
    match result {
        Ok((members, memory)) => Ok(RoutedJmpArtifactPlan {
            members,
            memory,
            evidence: work.evidence,
        }),
        Err(e) => Err(RoutedJmpFailure {
            reason: e.reason,
            stop: e.stop,
            stage: e.stage,
            evidence: Box::new(work.evidence),
            unvisited_target: e.target,
        }),
    }
}
fn omitted(proof: &CandidateProof) -> Option<u64> {
    match proof {
        CandidateProof::PageBoundary { omitted, .. } => *omitted,
        CandidateProof::Indexed { omitted, .. } => omitted.map(|w| w.target),
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
