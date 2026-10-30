//! Narrow v6 union adapter. The sealed core owns the multi-entry proof.
use super::*;
use crate::disassembly::adjacent_routed_jmp::AdjacentRoutedJmpDisassemblySelection;
use li2core::quiescent::{
    RoutedJmpArtifactPlan, RoutedJmpBudget, RoutedJmpFailure, RoutedJmpStop,
    plan_adjacent_routed_jmp_with_emission_after,
};

pub fn prepare_disassembly_adjacent_routed_jmp(
    original: &[u8],
    selected: &AdjacentRoutedJmpDisassemblySelection,
) -> Result<Product, Error> {
    let limits = AdjacentB2Limits {
        upper: selected.limits.upper,
        lower: selected.limits.lower,
        joint: selected.limits.joint,
    };
    let mut product = prepare_selection_with_pair_gate(
        original,
        selected.base.selection.clone(),
        false,
        disassembly::NeighborMode::ShortT3Pending,
        Some(limits),
        PairProfile::RoutedJmpUnion,
        |_| Ok(()),
    )?;
    product.files.remove("bundle-index.tsv");
    product.files.extend(selected.base.files.clone());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.base.selection.original, &product.files),
    );
    Ok(product)
}

#[derive(Clone)]
pub(super) struct Edge {
    pub lower: u64,
    pub upper: u64,
    pub family: Option<PairKind>,
    pub exclusion: Option<&'static str>,
}
#[derive(Clone)]
pub(super) struct Dispatch {
    pub attempt: usize,
    pub lower: u64,
    pub upper: u64,
    pub family: PairKind,
}
#[derive(Clone)]
pub(super) struct Work {
    pub attempt: usize,
    pub lower: u64,
    pub upper: u64,
    pub baseline_reports: Vec<SiteReport>,
    pub result: Result<RoutedJmpArtifactPlan, RoutedJmpFailure>,
    pub frontend_refusal: Option<Error>,
    pub group_admission_refusal: Option<Error>,
    pub committed: bool,
}
/// Empty on every legacy profile; no legacy evidence serializer reads this state.
#[derive(Clone, Debug, Default)]
pub(crate) struct State {
    pub(super) edges: Vec<Edge>,
    pub(super) calls: Vec<Dispatch>,
    pub(super) work: Vec<Work>,
}

pub(super) fn eligibility(
    elf: &Elf64<'_>,
    selection: &Selection,
    lower: &SelectedSite,
    upper: &SelectedSite,
) -> Result<(), &'static str> {
    if lower.length != 2 || upper.length != 2 || lower.pc.checked_add(2) != Some(upper.pc) {
        return Err("mixed-pair-geometry");
    }
    let f = upper.pc.checked_add(2).ok_or("mixed-pair-geometry")?;
    let end = upper.pc.checked_add(5).ok_or("mixed-pair-geometry")?;
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
        return Err("mixed-original-view");
    }
    if lower.heads.iter().any(|e| e.requires_endbr) {
        return Err("mixed-cet-domain");
    }
    if lower.semantics != HookSemantics::Observe
        || upper.semantics != HookSemantics::Observe
        || lower.search.max_sites == 0
        || upper.search.max_sites == 0
    {
        return Err("mixed-observing-search");
    }
    if lower.forced.is_some_and(|t| t != Tactic::GeneralizedPun)
        || upper.forced.is_some_and(|t| t != Tactic::Relocation)
    {
        return Err("mixed-forced-tactic");
    }
    match &lower.resumes {
        ResumeObligation::Unresolved => return Err("mixed-resumes"),
        ResumeObligation::Enumerated(pcs) if pcs.windows(2).any(|w| w[0] >= w[1]) => {
            return Err("mixed-resumes");
        }
        _ => {}
    }
    if !lower.snapshot.contains(end) || lower.pc / 64 != (upper.pc - 1) / 64 {
        return Err("mixed-fetch-source-domain");
    }
    let bytes = elf
        .executable_bytes(ElfVaddr(lower.pc), 7)
        .map_err(|_| "mixed-original-owner")?;
    if bytes[0] != 0x76
        || bytes[2] != 0xeb
        || !matches!(&bytes[4..], [0x4c, 0x89, 0xe7] | [0x49, 0x8b, 0xfc])
    {
        return Err("mixed-branch-suffix-domain");
    }
    let backward = i128::from(lower.pc) + 2 + i128::from(bytes[1] as i8);
    let forward = i128::from(upper.pc) + 2 + i128::from(bytes[3] as i8);
    if backward < 0
        || backward >= i128::from(lower.pc)
        || forward < i128::from(end)
        || forward > i128::from(u64::MAX)
        || !lower.snapshot.contains(backward as u64)
        || !lower.snapshot.contains(forward as u64)
        || [backward as u64, forward as u64, f, end]
            .iter()
            .any(|pc| !lower.heads.iter().any(|h| h.address == *pc))
    {
        return Err("mixed-original-target");
    }
    if selection.sites.iter().any(|site| {
        site.pc
            .checked_add(u64::from(site.length))
            .is_none_or(|site_end| site.pc < end && f < site_end)
    }) {
        return Err("mixed-selected-suffix");
    }
    Ok(())
}

pub(super) fn call(
    elf: &Elf64<'_>,
    s: &Selection,
    identity: CodeIdentity,
    limits: AdjacentB2Limits,
    before: &SelectionDraft,
    lower: usize,
    upper: usize,
) -> Result<Result<RoutedJmpArtifactPlan, RoutedJmpFailure>, Error> {
    call_with_sites(
        PairRequest {
            elf,
            s,
            identity,
            limits,
            draft: before,
            lower,
            upper,
        },
        TacticPolicy::RelocationOnly,
        5,
        |sites, emission, pending, bundle| {
            plan_adjacent_routed_jmp_with_emission_after(
                sites,
                emission,
                &before.composition,
                pending,
                RoutedJmpBudget {
                    max_continuations: limits.joint,
                    bundle,
                },
            )
        },
    )
}

pub(super) fn view(pair: &RoutedJmpArtifactPlan) -> PairView<'_> {
    PairView {
        pcs: pair.logical_pcs(),
        members: pair.members(),
        accepted: pair.evidence().accepted,
        qualified: pair.qualification_complete(),
        tactics: [Tactic::Relocation, Tactic::GeneralizedPun],
        family: Some(PairKind::RoutedJmp.name()),
    }
}

pub(super) struct Recovery<'a, 'elf> {
    pub elf: &'a Elf64<'elf>,
    pub dynamic: &'a carrier::dynamic::Inventory,
    pub s: &'a Selection,
    pub identity: CodeIdentity,
    pub limits: AdjacentB2Limits,
    pub lower: usize,
    pub upper: usize,
}
pub(super) fn recover(
    context: Recovery<'_, '_>,
    before: SelectionDraft,
    trial: SelectionDraft,
    group_admission_refusal: Option<Error>,
) -> Result<SelectionDraft, Error> {
    let Recovery {
        elf,
        dynamic,
        s,
        identity,
        limits,
        lower,
        upper,
    } = context;
    let baseline_reports = vec![trial.reports[upper].clone(), trial.reports[lower].clone()];
    let result = call(elf, s, identity, limits, &before, lower, upper)?;
    if let Err(failure) = &result {
        if matches!(failure.stop, RoutedJmpStop::Invariant)
            || matches!(
                failure.reason,
                Refusal::InvalidPlan
                    | Refusal::InvalidRange
                    | Refusal::StaleGeneration
                    | Refusal::ExpectedBytesChanged
            )
        {
            return Err(Error::new("pair-invariant", format!("{failure:#?}")));
        }
    }
    let attempt = before.work.len() + before.routed.work.len();
    let staged = match &result {
        Ok(pair) => {
            if pair.evidence().selected != [s.sites[lower].pc, s.sites[upper].pc]
                || pair.evidence().suffix != s.sites[upper].pc.checked_add(2)
            {
                return Err(Error::new(
                    "pair-invariant",
                    "mixed suffix/selected identity",
                ));
            }
            Some(stage_members(
                elf,
                dynamic,
                s,
                &before,
                PairAssociation {
                    lower,
                    upper,
                    attempt,
                },
                view(pair),
                |_, _| Ok(()),
            ))
        }
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
        Some(Ok(mut next)) => {
            next.baseline = trial.baseline.clone();
            next
        }
        _ => trial,
    };
    if !committed {
        if let Some(error) = &group_admission_refusal {
            chosen.blocked_groups.push(error.clone());
        }
    }
    chosen.routed.calls.push(Dispatch {
        attempt,
        lower: s.sites[lower].id,
        upper: s.sites[upper].id,
        family: PairKind::RoutedJmp,
    });
    chosen.routed.work.push(Work {
        attempt,
        lower: s.sites[lower].id,
        upper: s.sites[upper].id,
        baseline_reports,
        result,
        frontend_refusal,
        group_admission_refusal,
        committed,
    });
    Ok(chosen)
}

fn add_counts(total: &mut PairCounts, c: PairCounts) -> Result<(), Error> {
    total.upper = total
        .upper
        .checked_add(c.upper)
        .ok_or_else(|| Error::new("evidence", "upper overflow"))?;
    total.lower = total
        .lower
        .checked_add(c.lower)
        .ok_or_else(|| Error::new("evidence", "lower overflow"))?;
    total.joint = total
        .joint
        .checked_add(c.joint)
        .ok_or_else(|| Error::new("evidence", "joint overflow"))?;
    Ok(())
}
pub(crate) fn evidence(s: &Selection, draft: &SelectionDraft) -> Result<Vec<u8>, Error> {
    let mut jcc = PairCounts::default();
    for work in &draft.work {
        add_counts(
            &mut jcc,
            match &work.result {
                Ok(p) => p.evidence().counts,
                Err(e) => e.evidence.counts,
            },
        )?;
    }
    let mut mixed = PairCounts::default();
    for work in &draft.routed.work {
        add_counts(
            &mut mixed,
            match &work.result {
                Ok(p) => p.evidence().counts,
                Err(e) => e.evidence.counts,
            },
        )?;
    }
    let mut total = jcc;
    add_counts(&mut total, mixed)?;
    let mut legacy = 0usize;
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
                    legacy = legacy
                        .checked_add(run.examined)
                        .ok_or_else(|| Error::new("evidence", "legacy image-slot overflow"))?;
                }
            }
        }
    }
    let calls = draft
        .work
        .len()
        .checked_add(draft.routed.work.len())
        .ok_or_else(|| Error::new("evidence", "call overflow"))?;
    if calls != draft.routed.calls.len()
        || draft
            .routed
            .calls
            .iter()
            .enumerate()
            .any(|(i, c)| c.attempt != i)
    {
        return Err(Error::new("evidence", "mixed dispatch sequence"));
    }
    let combined = legacy
        .checked_add(total.upper)
        .and_then(|n| n.checked_add(total.lower))
        .ok_or_else(|| Error::new("evidence", "combined work overflow"))?;
    Ok(format!(
        "LI2ADJACENT-ROUTED-JMP-EVIDENCE\t1\nselection_sha256\t{}\nselected_count\t{}\nbaseline_calls\t{}\npair_calls\t{calls}\nadjacent_counts\t{}\t{}\t{}\nforward_jcc_calls\t{}\nforward_jcc_counts\t{}\t{}\t{}\nrouted_jmp_calls\t{}\nrouted_jmp_counts\t{}\t{}\t{}\nqualification_complete\tfalse\nclassification_complete\tfalse\nlegacy_image_slots\t{legacy}\ncombined_image_work_upper_bound\t{combined}\nresources\t{:#?}\nedges\t{:#?}\nbaseline\t{:#?}\nforward_pairs\t{:#?}\nrouted_pairs\t{:#?}\n",
        ledger::hex(&ContentId::of(&s.manifest).0), s.sites.len(), draft.baseline.len(),
        total.upper, total.lower, total.joint, draft.work.len(), jcc.upper, jcc.lower, jcc.joint,
        draft.routed.work.len(), mixed.upper, mixed.lower, mixed.joint, draft.totals,
        (&draft.edges, &draft.routed.edges, &draft.routed.calls), draft.baseline,
        draft.work, draft.routed.work).into_bytes())
}

impl std::fmt::Debug for Edge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Edge")
            .field("lower", &self.lower)
            .field("upper", &self.upper)
            .field("family", &self.family)
            .field("exclusion", &self.exclusion)
            .finish()
    }
}

impl std::fmt::Debug for Dispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatch")
            .field("attempt", &self.attempt)
            .field("lower", &self.lower)
            .field("upper", &self.upper)
            .field("family", &self.family)
            .finish()
    }
}

impl std::fmt::Debug for Work {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Work")
            .field("attempt", &self.attempt)
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
