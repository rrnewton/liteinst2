//! Transactional adapter for one explicitly declared adjacent-B2 profile.
use crate::*;
use disassembly::adjacent_b2::{AdjacentB2DisassemblySelection, AdjacentB2Limits};
use li2core::bundle::BundleBudget;
use li2core::engine::Tactic;
use li2core::planner::HookSemantics;
use li2core::quiescent::{
    AdjacentB2ArtifactPlan, AdjacentB2Budget, AdjacentB2Failure, PairCounts, PairStop,
    SearchPolicy, plan_adjacent_b2_with_emission_after,
};

/// Same immutable bytes and full selected roster as the sealed importer.
pub fn prepare_disassembly_adjacent_b2(
    original: &[u8],
    selected: &AdjacentB2DisassemblySelection,
) -> Result<Product, Error> {
    let mut product = prepare_selection_with_adjacent(
        original,
        selected.base.selection.clone(),
        false,
        disassembly::NeighborMode::ShortT3Pending,
        Some(selected.limits),
    )?;
    product.files.remove("bundle-index.tsv");
    product.files.extend(selected.base.files.clone());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.base.selection.original, &product.files),
    );
    Ok(product)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Resources {
    steps: usize,
    mappings: usize,
    virtual_bytes: u64,
    backing_bytes: u64,
    first: Option<u64>,
    end: u64,
}
#[derive(Clone, Copy, Debug)]
struct Capacities {
    steps: usize,
    mappings: usize,
    virtual_bytes: u64,
    backing_bytes: u64,
    span: u64,
}
impl Capacities {
    fn from_selection(s: &Selection) -> Result<Self, Error> {
        let bytes = s
            .limits
            .new_load_pages
            .checked_mul(4096)
            .ok_or_else(|| Error::new("whole-budget", "page byte overflow"))?;
        Ok(Self {
            steps: s
                .sites
                .len()
                .checked_mul(2)
                .ok_or_else(|| Error::new("whole-budget", "step overflow"))?,
            mappings: s.limits.images,
            virtual_bytes: bytes,
            backing_bytes: bytes,
            span: s.limits.virtual_span,
        })
    }
}
impl Resources {
    fn collect(accepted: &[(u64, ArtifactPlan)]) -> Result<Self, Error> {
        let mut out = Self::default();
        for (_, plan) in accepted {
            out.steps = out
                .steps
                .checked_add(plan.source_steps().len())
                .ok_or_else(|| Error::new("whole-budget", "step overflow"))?;
            for step in plan.source_steps() {
                for allocation in &step.parts().allocations {
                    let r = allocation.range;
                    if r.start() % 4096 != 0 || r.len() % 4096 != 0 || r.is_empty() {
                        return Err(Error::new("whole-budget", "non-page allocation"));
                    }
                    out.mappings = out
                        .mappings
                        .checked_add(1)
                        .ok_or_else(|| Error::new("whole-budget", "mapping overflow"))?;
                    out.virtual_bytes = out
                        .virtual_bytes
                        .checked_add(r.len())
                        .ok_or_else(|| Error::new("whole-budget", "virtual overflow"))?;
                    out.backing_bytes = out
                        .backing_bytes
                        .checked_add(r.len())
                        .ok_or_else(|| Error::new("whole-budget", "backing overflow"))?;
                    out.first = Some(out.first.map_or(r.start(), |v| v.min(r.start())));
                    out.end = out.end.max(r.end());
                }
            }
        }
        Ok(out)
    }
    fn check(&self, cap: Capacities) -> Result<(), Error> {
        let span = match self.first {
            Some(first) => self
                .end
                .checked_sub(first)
                .ok_or_else(|| Error::new("whole-budget", "hull underflow"))?,
            None if self.end == 0 => 0,
            None => return Err(Error::new("whole-budget", "hull missing")),
        };
        for (name, exceeded) in [
            ("steps", self.steps > cap.steps),
            ("mappings", self.mappings > cap.mappings),
            ("virtual-bytes", self.virtual_bytes > cap.virtual_bytes),
            ("backing-bytes", self.backing_bytes > cap.backing_bytes),
            ("generated-hull", span > cap.span),
        ] {
            if exceeded {
                return Err(Error::new("whole-budget", name));
            }
        }
        Ok(())
    }
    fn pair_budget(&self, cap: Capacities, joint: usize) -> Result<AdjacentB2Budget, Error> {
        self.check(cap)?;
        let underflow = || Error::new("whole-budget", "residual underflow");
        Ok(AdjacentB2Budget {
            max_continuations: joint,
            bundle: BundleBudget {
                max_steps: 2,
                max_mappings: cap
                    .mappings
                    .checked_sub(self.mappings)
                    .ok_or_else(underflow)?,
                max_virtual_bytes: cap
                    .virtual_bytes
                    .checked_sub(self.virtual_bytes)
                    .ok_or_else(underflow)?,
                max_backing_bytes: cap
                    .backing_bytes
                    .checked_sub(self.backing_bytes)
                    .ok_or_else(underflow)?,
                max_virtual_span: cap.span,
            },
        })
    }
}

#[derive(Clone)]
pub(crate) struct Baseline {
    pub id: u64,
    pub result: Result<ArtifactPlan, engine::EngineFailure>,
}
#[derive(Clone)]
pub(crate) struct Edge {
    lower: u64,
    upper: u64,
    exclusion: Option<&'static str>,
    visited_group: bool,
}
#[derive(Clone)]
pub(crate) struct Work {
    lower: u64,
    upper: u64,
    baseline_reports: Vec<SiteReport>,
    result: Result<AdjacentB2ArtifactPlan, AdjacentB2Failure>,
    frontend_refusal: Option<Error>,
    group_admission_refusal: Option<Error>,
    committed: bool,
}
// These inventories are serialized into the evidence document. Explicit Debug
// implementations retain the derived field order while reading every field.
impl std::fmt::Debug for Baseline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Baseline")
            .field("id", &self.id)
            .field("result", &self.result)
            .finish()
    }
}
impl std::fmt::Debug for Edge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Edge")
            .field("lower", &self.lower)
            .field("upper", &self.upper)
            .field("exclusion", &self.exclusion)
            .field("visited_group", &self.visited_group)
            .finish()
    }
}
impl std::fmt::Debug for Work {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Work")
            .field("lower", &self.lower)
            .field("upper", &self.upper)
            .field("baseline_reports", &self.baseline_reports)
            .field("result", &self.result)
            .field("frontend_refusal", &self.frontend_refusal)
            .field("group_admission_refusal", &self.group_admission_refusal)
            .field("committed", &self.committed)
            .finish()
    }
}
/// Every mutable planning association is cloned together. Candidate buffers are
/// created only after this draft has been checked for complete selected coverage.
#[derive(Clone, Debug)]
pub(crate) struct SelectionDraft {
    pub composition: Composition,
    pub pending: Vec<(usize, AddressRange)>,
    pub reports: Vec<SiteReport>,
    pub accepted: Vec<(u64, ArtifactPlan)>,
    pub occupied: Vec<AddressRange>,
    pub dependencies: Vec<FileRange>,
    pub image_count: usize,
    pub image_bytes: usize,
    pub allocation_pages: u64,
    pub baseline: Vec<Baseline>,
    pub work: Vec<Work>,
    pub edges: Vec<Edge>,
    pub totals: Resources,
    pub blocked_groups: Vec<Error>,
}

fn entries(s: &SelectedSite, identity: CodeIdentity) -> LegalEntrySet {
    LegalEntrySet {
        identity,
        scope: s.function,
        provenance: EntryProvenance::Declared(format!(
            "selection provenance SHA-256 {}",
            ledger::hex(&s.provenance.0)
        )),
        completeness: s.completeness,
        entries: s.heads.clone(),
        resumes: s.resumes.clone(),
    }
}
fn exclusion(elf: &Elf64<'_>, lower: &SelectedSite, upper: &SelectedSite) -> Option<&'static str> {
    if lower.pc.checked_add(2) != Some(upper.pc) || lower.length != 2 || upper.length != 2 {
        return Some("pair-geometry");
    }
    if lower.snapshot != upper.snapshot
        || lower.function != lower.snapshot
        || upper.function != upper.snapshot
        || lower.heads != upper.heads
        || lower.completeness != EntryCompleteness::AllInstructionHeads
        || upper.completeness != EntryCompleteness::AllInstructionHeads
        || lower.resumes != upper.resumes
        || lower.provenance != upper.provenance
        || lower.hook != upper.hook
    {
        return Some("original-view");
    }
    if lower.heads.iter().any(|e| e.requires_endbr) {
        return Some("cet-domain");
    }
    for site in [lower, upper] {
        if site.forced.is_some_and(|t| t != Tactic::GeneralizedPun) {
            return Some("forced-tactic");
        }
        if site.search.max_sites == 0 {
            return Some("singleton-zero-sites");
        }
        if site.semantics != HookSemantics::Observe {
            return Some("observing-domain");
        }
        if let ResumeObligation::Enumerated(pcs) = &site.resumes {
            if pcs.windows(2).any(|w| w[0] >= w[1]) {
                return Some("resume-shape");
            }
        }
        if site
            .pc
            .checked_add(5)
            .is_none_or(|end| end > site.snapshot.end())
            || site.pc / 64 != (site.pc + 1) / 64
        {
            return Some("fetch-store-domain");
        }
        let Ok(bytes) = elf.executable_bytes(ElfVaddr(site.pc), 2) else {
            return Some("original-owner");
        };
        if !(0x70..=0x7f).contains(&bytes[0]) {
            return Some("branch-domain");
        }
        let target = i128::from(site.pc) + 2 + i128::from(bytes[1] as i8);
        if target < i128::from(upper.pc) + 2
            || target > i128::from(u64::MAX)
            || !site.snapshot.contains(target as u64)
            || !site.heads.iter().any(|h| h.address == target as u64)
        {
            return Some("branch-target");
        }
    }
    None
}
fn fatal(report: &SiteReport) -> bool {
    report.refusal.as_ref().is_some_and(|e| {
        matches!(
            e.stage,
            "core-invariant"
                | "readiness-invariant"
                | "original-identity"
                | "snapshot"
                | "site-file-offset"
                | "site-geometry"
        )
    }) || report.refusal_code.is_some_and(|c| (1..=6).contains(&c))
}
fn baseline(
    elf: &Elf64<'_>,
    dynamic: &carrier::dynamic::Inventory,
    s: &Selection,
    identity: CodeIdentity,
    draft: &mut SelectionDraft,
    index: usize,
) -> Result<(), Error> {
    attempt_singleton(
        SingletonContext {
            elf,
            dynamic,
            s,
            identity,
            owned_neighbors: false,
            mode: disassembly::NeighborMode::ShortT3Pending,
            record_baseline: true,
        },
        draft,
        index,
    );
    draft.totals = Resources::collect(&draft.accepted)?;
    if fatal(&draft.reports[index]) {
        return Err(draft.reports[index]
            .refusal
            .clone()
            .unwrap_or_else(|| Error::new("core-invariant", "terminal core authentication")));
    }
    Ok(())
}
fn call_pair(
    elf: &Elf64<'_>,
    s: &Selection,
    identity: CodeIdentity,
    limits: AdjacentB2Limits,
    draft: &SelectionDraft,
    lower: usize,
    upper: usize,
) -> Result<Result<AdjacentB2ArtifactPlan, AdjacentB2Failure>, Error> {
    let a = &s.sites[lower];
    let b = &s.sites[upper];
    validate_site(elf, a)?;
    validate_site(elf, b)?;
    let code = elf
        .executable_bytes(ElfVaddr(a.snapshot.start()), a.snapshot.len())
        .map_err(|e| Error::new("snapshot", e))?;
    let entries = entries(a, identity);
    let mut lower_allocation = a.selected_allocation.clone();
    let mut upper_allocation = b.selected_allocation.clone();
    lower_allocation.max_candidates = limits.lower;
    upper_allocation.max_candidates = limits.upper;
    let hook = s
        .hooks
        .iter()
        .find(|h| h.id == a.hook)
        .ok_or_else(|| Error::new("hook", "missing"))?;
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(s.target, s.bias_domain)
            .map_err(|e| Error::new("target", e))?,
        SymbolicHook {
            identity: hook.id,
            address: Some(hook.pc),
        },
        draft.occupied.clone(),
    );
    let lower_site = PlanningSite {
        identity,
        code,
        base_address: a.snapshot.start(),
        function: a.function,
        block: addr(a.pc, 2)?,
        logical_pc: a.pc,
        entries: &entries,
        semantics: a.semantics,
        allocation: &lower_allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::GeneralizedPunOnly,
            max_upstream_bytes: 0,
            max_displaced_bytes: 2,
            max_sites: 1,
        },
    };
    let upper_site = PlanningSite {
        block: addr(b.pc, 2)?,
        logical_pc: b.pc,
        semantics: b.semantics,
        allocation: &upper_allocation,
        ..lower_site
    };
    let pending: Vec<_> = draft
        .pending
        .iter()
        .filter_map(|(i, r)| (*i != lower && *i != upper).then_some(*r))
        .collect();
    let budget = draft
        .totals
        .pair_budget(Capacities::from_selection(s)?, limits.joint)?;
    Ok(plan_adjacent_b2_with_emission_after(
        [lower_site, upper_site],
        &emission,
        &draft.composition,
        &pending,
        budget,
    ))
}

/// Fault callbacks are private transactional test seams; production always uses
/// the infallible callback. They never construct or amend a core plan.
struct PairAssociation {
    lower: usize,
    upper: usize,
    attempt: usize,
}
fn stage_pair(
    elf: &Elf64<'_>,
    dynamic: &carrier::dynamic::Inventory,
    s: &Selection,
    before: &SelectionDraft,
    association: PairAssociation,
    pair: &AdjacentB2ArtifactPlan,
    mut checkpoint: impl FnMut(&'static str, &SelectionDraft) -> Result<(), Error>,
) -> Result<SelectionDraft, Error> {
    let PairAssociation {
        lower,
        upper,
        attempt,
    } = association;
    if pair.logical_pcs() != [s.sites[upper].pc, s.sites[lower].pc]
        || pair.qualification_complete()
        || !pair.evidence().accepted
    {
        return Err(Error::new("pair-invariant", "member binding"));
    }
    let mut next = before.clone();
    let external: Vec<_> = before
        .pending
        .iter()
        .filter_map(|(i, r)| (*i != lower && *i != upper).then_some(*r))
        .collect();
    for (ordinal, (index, member)) in [upper, lower].into_iter().zip(pair.members()).enumerate() {
        if !matches!(member.metrics(), ArtifactMetrics::Single(_))
            || member.qualification_complete()
        {
            return Err(Error::new("pair-invariant", "member authority or metrics"));
        }
        for step in member.source_steps() {
            next.composition
                .append(step)
                .map_err(|e| Error::new("composition", e))?;
            for dependency in &step.parts().dependencies {
                let file = translate(elf, dependency.start(), dependency.len())?;
                dynamic
                    .check_source_ranges(&[file])
                    .map_err(|e| Error::new("source-relocation", e))?;
                next.dependencies.push(file);
            }
            for allocation in &step.parts().allocations {
                next.allocation_pages = next
                    .allocation_pages
                    .checked_add(allocation.range.len() / 4096)
                    .ok_or_else(|| Error::new("allocation-budget", "overflow"))?;
                next.occupied.push(allocation.range);
            }
        }
        next.image_count = next
            .image_count
            .checked_add(member.images().count())
            .ok_or_else(|| Error::new("image-budget", "overflow"))?;
        for image in member.images() {
            next.image_bytes = next
                .image_bytes
                .checked_add(image.bytes().len())
                .ok_or_else(|| Error::new("image-budget", "overflow"))?;
        }
        if next.image_count > s.limits.images
            || next.image_bytes > s.limits.image_bytes
            || next.allocation_pages > s.limits.new_load_pages
        {
            return Err(Error::new(
                "aggregate-budget",
                "complete selected set exceeds declared resources",
            ));
        }
        for hook in &s.hooks {
            for bytes in next.composition.final_bytes() {
                let left = bytes.address.max(hook.pc);
                let right =
                    (bytes.address + bytes.bytes.len() as u64).min(hook.pc + hook.length as u64);
                if left < right
                    && bytes.bytes
                        [(left - bytes.address) as usize..(right - bytes.address) as usize]
                        != *elf
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
        let mut outstanding = external.clone();
        if ordinal == 0 {
            outstanding.push(addr(s.sites[lower].pc, u64::from(s.sites[lower].length))?);
        }
        outstanding.sort_by_key(|r| r.start());
        next.composition
            .require_unclaimed_ranges(&outstanding)
            .map_err(|e| Error::new("pending-selected", e))?;
        checkpoint(
            if ordinal == 0 {
                "upper-appended"
            } else {
                "both-appended"
            },
            &next,
        )?;
        let image_index = next
            .accepted
            .iter()
            .map(|(_, p)| p.images().count())
            .sum::<usize>();
        let step_index = next
            .accepted
            .iter()
            .map(|(_, p)| p.source_steps().len())
            .sum::<usize>();
        next.accepted.push((s.sites[index].id, member.clone()));
        next.pending.retain(|(i, _)| *i != index);
        next.reports[index].core_tactic = Some(Tactic::GeneralizedPun);
        next.reports[index].refusal = None;
        next.reports[index].refusal_code = None;
        next.reports[index].candidate_emitted = false;
        next.reports[index].diagnostics = format!(
            "adjacent_attempt={attempt} member={ordinal} role={} selected_id={} image_start={image_index} image_count={} step_start={step_index} step_count={}\n{:#?}",
            if ordinal == 0 { "upper" } else { "lower" },
            s.sites[index].id,
            member.images().count(),
            member.source_steps().len(),
            member.metrics()
        );
    }
    next.totals = Resources::collect(&next.accepted)?;
    next.totals.check(Capacities::from_selection(s)?)?;
    if next.totals.virtual_bytes
        != next
            .allocation_pages
            .checked_mul(4096)
            .ok_or_else(|| Error::new("whole-budget", "page overflow"))?
        || next.totals.backing_bytes != next.totals.virtual_bytes
    {
        return Err(Error::new("pair-invariant", "unshared allocation totals"));
    }
    checkpoint("associations-built", &next)?;
    Ok(next)
}

pub(crate) fn plan(
    elf: &Elf64<'_>,
    dynamic: &carrier::dynamic::Inventory,
    s: &Selection,
    identity: CodeIdentity,
    limits: AdjacentB2Limits,
    ordered: &[usize],
    draft: &mut SelectionDraft,
) -> Result<(), Error> {
    // Freeze every original edge and greedy group before any planning outcome.
    for w in ordered.windows(2) {
        let (a, b) = (&s.sites[w[1]], &s.sites[w[0]]);
        if a.pc.checked_add(u64::from(a.length)) == Some(b.pc) {
            draft.edges.push(Edge {
                lower: a.id,
                upper: b.id,
                exclusion: exclusion(elf, a, b),
                visited_group: false,
            });
        }
    }
    let mut groups = Vec::new();
    let mut at = 0;
    while at < ordered.len() {
        let upper = ordered[at];
        let lower = ordered
            .get(at + 1)
            .copied()
            .filter(|&i| exclusion(elf, &s.sites[i], &s.sites[upper]).is_none());
        groups.push((upper, lower));
        at += if lower.is_some() { 2 } else { 1 };
    }
    for (upper, lower) in groups {
        let Some(lower) = lower else {
            baseline(elf, dynamic, s, identity, draft, upper)?;
            if let Err(error) = draft.totals.check(Capacities::from_selection(s)?) {
                draft.blocked_groups.push(error);
            }
            continue;
        };
        for edge in &mut draft.edges {
            if edge.lower == s.sites[lower].id && edge.upper == s.sites[upper].id {
                edge.visited_group = true;
            }
        }
        let before = draft.clone();
        let mut trial = before.clone();
        baseline(elf, dynamic, s, identity, &mut trial, upper)?;
        baseline(elf, dynamic, s, identity, &mut trial, lower)?;
        // Preserve the literal legacy trial before this new-profile admission
        // guard. Two local successes remain successes in baseline evidence.
        let group_admission_refusal = trial.totals.check(Capacities::from_selection(s)?).err();
        if trial.reports[upper].refusal.is_none()
            && trial.reports[lower].refusal.is_none()
            && group_admission_refusal.is_none()
        {
            *draft = trial;
            continue;
        }
        if before.totals.check(Capacities::from_selection(s)?).is_err() {
            if let Some(error) = group_admission_refusal {
                trial.blocked_groups.push(error);
            }
            *draft = trial;
            continue;
        }
        let baseline_reports = vec![trial.reports[upper].clone(), trial.reports[lower].clone()];
        let result = call_pair(elf, s, identity, limits, &before, lower, upper)?;
        if let Err(failure) = &result {
            if matches!(failure.stop, PairStop::TerminalInvariant)
                || matches!(
                    failure.reason,
                    Refusal::InvalidPlan
                        | Refusal::InvalidRange
                        | Refusal::StaleGeneration
                        | Refusal::ExpectedBytesChanged
                )
            {
                return Err(Error::new("pair-invariant", failure));
            }
        }
        let attempt = before.work.len();
        let staged = match &result {
            Ok(pair) => Some(stage_pair(
                elf,
                dynamic,
                s,
                &before,
                PairAssociation {
                    lower,
                    upper,
                    attempt,
                },
                pair,
                |_, _| Ok(()),
            )),
            Err(_) => None,
        };
        let frontend_refusal = staged.as_ref().and_then(|r| r.as_ref().err()).cloned();
        if frontend_refusal
            .as_ref()
            .is_some_and(|e| e.stage == "pair-invariant")
        {
            return Err(frontend_refusal.unwrap());
        }
        let committed = staged.as_ref().is_some_and(Result::is_ok);
        let mut chosen = match staged {
            Some(Ok(mut pair)) => {
                pair.baseline = trial.baseline.clone();
                pair
            }
            _ => trial,
        };
        if !committed {
            if let Some(error) = &group_admission_refusal {
                chosen.blocked_groups.push(error.clone());
            }
        }
        chosen.work.push(Work {
            lower: s.sites[lower].id,
            upper: s.sites[upper].id,
            baseline_reports,
            result,
            frontend_refusal,
            group_admission_refusal,
            committed,
        });
        *draft = chosen;
    }
    // Exact one-to-one association, never a subset candidate.
    let admitted: std::collections::BTreeSet<_> =
        draft.accepted.iter().map(|(id, _)| *id).collect();
    if admitted.len() != draft.accepted.len()
        || draft
            .reports
            .iter()
            .any(|r| r.refusal.is_none() != admitted.contains(&r.id))
    {
        return Err(Error::new(
            "association-invariant",
            "report/accepted identity",
        ));
    }
    let mut expected_pending = s
        .sites
        .iter()
        .enumerate()
        .filter(|(_, site)| !admitted.contains(&site.id))
        .map(|(index, site)| addr(site.pc, u64::from(site.length)).map(|range| (index, range)))
        .collect::<Result<Vec<_>, Error>>()?;
    expected_pending.sort_by_key(|(_, range)| range.start());
    if draft.pending != expected_pending {
        return Err(Error::new(
            "association-invariant",
            "complete full-interval pending roster",
        ));
    }
    let mut images = 0usize;
    let mut bytes = 0usize;
    for (_, plan) in &draft.accepted {
        for image in plan.images() {
            images = images
                .checked_add(1)
                .ok_or_else(|| Error::new("association-invariant", "image overflow"))?;
            bytes = bytes
                .checked_add(image.bytes().len())
                .ok_or_else(|| Error::new("association-invariant", "payload overflow"))?;
        }
    }
    if Resources::collect(&draft.accepted)? != draft.totals
        || images != draft.image_count
        || bytes != draft.image_bytes
        || draft.totals.virtual_bytes
            != draft
                .allocation_pages
                .checked_mul(4096)
                .ok_or_else(|| Error::new("association-invariant", "page overflow"))?
        || draft.totals.backing_bytes != draft.totals.virtual_bytes
    {
        return Err(Error::new(
            "association-invariant",
            "whole draft resource totals",
        ));
    }
    Ok(())
}

pub(crate) fn evidence(s: &Selection, draft: &SelectionDraft) -> Result<Vec<u8>, Error> {
    let mut counts = PairCounts::default();
    for work in &draft.work {
        let c = match &work.result {
            Ok(p) => p.evidence().counts,
            Err(e) => e.evidence.counts,
        };
        counts.upper = counts
            .upper
            .checked_add(c.upper)
            .ok_or_else(|| Error::new("evidence", "upper overflow"))?;
        counts.lower = counts
            .lower
            .checked_add(c.lower)
            .ok_or_else(|| Error::new("evidence", "lower overflow"))?;
        counts.joint = counts
            .joint
            .checked_add(c.joint)
            .ok_or_else(|| Error::new("evidence", "joint overflow"))?;
    }
    let mut legacy_slots = 0usize;
    for baseline in &draft.baseline {
        let attempts = match &baseline.result {
            Ok(plan) => match plan.metrics() {
                ArtifactMetrics::Engine(_, _, attempts) => attempts,
                _ => return Err(Error::new("evidence", "baseline engine metrics")),
            },
            Err(failure) => &failure.attempts,
        };
        for attempt in attempts {
            for run in &attempt.search.runs {
                if matches!(
                    run.domain,
                    li2core::search::SearchDomain::SelectedImages
                        | li2core::search::SearchDomain::VictimImages
                ) {
                    legacy_slots = legacy_slots
                        .checked_add(run.examined)
                        .ok_or_else(|| Error::new("evidence", "legacy image-slot overflow"))?;
                }
            }
        }
    }
    let combined = legacy_slots
        .checked_add(counts.upper)
        .and_then(|n| n.checked_add(counts.lower))
        .ok_or_else(|| Error::new("evidence", "combined work overflow"))?;
    // Full typed Debug inventories are retained, including all CandidateProof
    // values, actual unvisited targets and unchanged legacy refusal evidence.
    Ok(format!(
        "LI2ADJACENT-EVIDENCE\t1\nselection_sha256\t{}\nselected_count\t{}\nbaseline_calls\t{}\npair_calls\t{}\nadjacent_counts\t{}\t{}\t{}\nqualification_complete\tfalse\nclassification_complete\tfalse\nlegacy_image_slots\t{legacy_slots}\ncombined_image_work_upper_bound\t{combined}\nresources\t{:#?}\nedges\t{:#?}\nbaseline\t{:#?}\npairs\t{:#?}\n",
        ledger::hex(&ContentId::of(&s.manifest).0), s.sites.len(), draft.baseline.len(),
        draft.work.len(), counts.upper, counts.lower, counts.joint, draft.totals,
        draft.edges, draft.baseline, draft.work).into_bytes())
}

#[cfg(test)]
mod tests;
