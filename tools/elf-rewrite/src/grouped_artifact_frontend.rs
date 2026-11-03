//! Complete selected-block units, using the shared artifact planner/transaction.
//! The opaque core window is not a completeness, loader or execution authority.
use crate::*;
use li2core::planner::HookSemantics;
use li2core::quiescent::{
    AllocationPolicy, ArtifactObservationPlan, ArtifactObservationRequest,
    plan_artifact_observation_window_after,
};
use li2core::x86::JumpStackClass;
use std::collections::BTreeSet;
use std::fmt::Write as _;

pub const GROUPED_PROFILE: &str = "jumps-gpr-stack64-block-observation-v1";
const POLICY: &str = "LI2GROUPING-POLICY\t1\nprofile\tjumps-gpr-stack64-block-observation-v1\nschedule\tall-multisite-blocks-descending-then-singletons-descending-v1\nwindow\tfirst-selected-head-through-last-selected-instruction\ngroup_tactic\tRelocationOnly\ngroup_attempts\t1\ngroup_fallback\tnone\nmember_budgets\tshared-not-summed\nentry_completeness\tAllInstructionHeads\nsingleton_profile\twhole-program-packed-overlapping-neighbors-4096\nqualification_complete\tfalse\n";

/// Separate typed profile; the input is still the sealed FULL jump/stack union.
/// Each multisite original block becomes one immutable work unit before any
/// planning. A refused group is never retried as singletons. Other blocks keep
/// the old singleton engine. The explicit CLI names this profile and preserves
/// its full census; neither API nor CLI grants loader admission or execution.
pub fn prepare_disassembly_jump_stack_grouped_fixed_exec(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
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
            fixed_exec: true,
            grouped_classes: Some(&selected.classes),
        },
    )?;
    product.files.remove("bundle-index.tsv");
    let mut files = selected.packed_overlapping_files();
    let profile = files
        .get_mut("planning-profile.tsv")
        .expect("sealed union has a planning profile");
    profile.extend_from_slice(grouped_fixed_exec_metadata().as_bytes());
    product.files.extend(files);
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.selection.original, &product.files),
    );
    Ok(product)
}

/// Canonical group-profile labels shared by the artifact and explicit CLI.
/// These declarations preserve all loader/readiness obligations.
pub fn grouped_fixed_exec_metadata() -> String {
    let mut out = FIXED_EXEC_METADATA.replacen(
        "planner_profile\twhole-program-packed-overlapping-neighbors-4096\n",
        &format!("planner_profile\t{GROUPED_PROFILE}\nsingleton_planner_profile\twhole-program-packed-overlapping-neighbors-4096\n"), 1,
    );
    out.push_str(&format!("grouped_profile\t{GROUPED_PROFILE}\ngrouping_policy\tgrouping-policy.tsv\ngrouping_ledger\tLI2GROUPED-LEDGER-1\n"));
    out
}

/// The same canonical bytes used by initial embedded and final portable metadata.
/// Authentication of the full grouping policy remains the caller's obligation.
pub fn grouped_fixed_exec_binding_policy(
    binding: FixedImageBinding,
    selection: ContentId,
    grouping: ContentId,
) -> Vec<u8> {
    fixed_exec::grouped_binding_policy(binding, selection, grouping)
}

#[derive(Clone, Debug)]
pub(crate) struct Group {
    // Indices into the immutable complete selected roster, in original PC order.
    members: Vec<usize>,
    window: AddressRange,
}
#[derive(Clone, Debug)]
pub(crate) struct Schedule {
    groups: Vec<Group>,
    singletons: Vec<usize>,
    classes: Vec<JumpStackClass>,
    pub(crate) policy: Vec<u8>,
}
pub(crate) struct AcceptedGroup {
    group: usize,
    members: Vec<usize>,
    pub(crate) plan: ArtifactObservationPlan,
}
impl AcceptedGroup {
    pub(crate) fn primary(&self, s: &Selection) -> u64 {
        s.sites[self.members[0]].id
    }
}

impl Schedule {
    pub(crate) fn freeze(
        elf: &Elf64<'_>,
        s: &Selection,
        classes: &[JumpStackClass],
    ) -> Result<Self, Error> {
        if classes.len() != s.sites.len() || s.sites.is_empty() {
            return Err(Error::new("grouped-population", "complete class count"));
        }
        let mut ids = BTreeSet::new();
        let mut previous_end = None;
        let mut ordered: Vec<_> = (0..s.sites.len()).collect();
        ordered.sort_by_key(|&i| s.sites[i].pc);
        let mut blocks = BTreeMap::<(u64, u64), Vec<usize>>::new();
        for i in ordered {
            let site = &s.sites[i];
            let range = addr(site.pc, u64::from(site.length))?;
            if !ids.insert(site.id) || previous_end.is_some_and(|end| end > site.pc) {
                return Err(Error::new(
                    "grouped-population",
                    "duplicate or overlapping selected rows",
                ));
            }
            previous_end = Some(range.end());
            let bytes = elf
                .executable_bytes(ElfVaddr(site.pc), u64::from(site.length))
                .map_err(|e| Error::new("grouped-source", e))?;
            let decoded = li2core::x86::decode64(site.pc, bytes);
            if decoded.instruction.len() != usize::from(site.length)
                || li2core::x86::jump_or_register_stack(&decoded.instruction) != Some(classes[i])
            {
                return Err(Error::new(
                    "grouped-population",
                    "sealed class differs from original",
                ));
            }
            blocks
                .entry((site.block.start(), site.block.end()))
                .or_default()
                .push(i);
        }
        let mut groups = Vec::new();
        let mut singletons = Vec::new();
        for members in blocks.into_values() {
            if members.len() == 1 {
                singletons.push(members[0]);
            } else {
                let first = &s.sites[members[0]];
                let last = &s.sites[*members.last().expect("nonempty block")];
                let end = last
                    .pc
                    .checked_add(u64::from(last.length))
                    .ok_or_else(|| Error::new("grouped-range", "overflow"))?;
                // No size/qualifier/policy failure removes a frozen group.
                groups.push(Group {
                    members,
                    window: addr(first.pc, end - first.pc)?,
                });
            }
        }
        groups.sort_by_key(|group| std::cmp::Reverse(group.window.start()));
        singletons.sort_by_key(|&i| std::cmp::Reverse(s.sites[i].pc));
        let mut out = Self {
            groups,
            singletons,
            classes: classes.to_vec(),
            policy: Vec::new(),
        };
        out.policy = out.policy_bytes(s);
        Ok(out)
    }
    fn policy_bytes(&self, s: &Selection) -> Vec<u8> {
        let mut text = format!(
            "{POLICY}original_sha256\t{}\nselection_sha256\t{}\ncomplete_site_count\t{}\n",
            ledger::hex(&s.original.0),
            ledger::hex(&ContentId::of(&s.manifest).0),
            s.sites.len()
        );
        for (unit, group) in self.groups.iter().enumerate() {
            writeln!(
                text,
                "unit\t{unit}\tgroup\t{}\t{}\t{}",
                group.window.start(),
                group.window.end(),
                group.members.len()
            )
            .unwrap();
            for &i in &group.members {
                self.member(&mut text, s, unit, i);
            }
        }
        for (at, &i) in self.singletons.iter().enumerate() {
            let unit = self.groups.len() + at;
            let site = &s.sites[i];
            writeln!(
                text,
                "unit\t{unit}\tsingleton\t{}\t{}\t1",
                site.pc,
                site.pc + u64::from(site.length)
            )
            .unwrap();
            self.member(&mut text, s, unit, i);
        }
        text.into_bytes()
    }
    fn member(&self, text: &mut String, s: &Selection, unit: usize, i: usize) {
        let site = &s.sites[i];
        writeln!(
            text,
            "member\t{unit}\t{}\t{}\t{}\t{}",
            site.id,
            site.pc,
            site.length,
            self.classes[i].name()
        )
        .unwrap();
    }
    fn validate_group(&self, s: &Selection, group: &Group) -> Result<(), Error> {
        let first = &s.sites[group.members[0]];
        let mut intersection = Vec::new();
        for (i, site) in s.sites.iter().enumerate() {
            let range = addr(site.pc, u64::from(site.length))?;
            if range.start() < group.window.end() && group.window.start() < range.end() {
                if !group.window.covers(range) {
                    return Err(Error::new(
                        "grouped-membership",
                        "selected instruction straddles window",
                    ));
                }
                intersection.push(i);
            }
        }
        intersection.sort_by_key(|&i| s.sites[i].pc);
        if intersection != group.members || group.members.len() < 2 {
            return Err(Error::new(
                "grouped-membership",
                "window must contain its exact full selected intersection",
            ));
        }
        if first.completeness != EntryCompleteness::AllInstructionHeads
            || first.semantics != HookSemantics::Observe
            || first.forced.is_some()
            || !matches!(
                first.search.tactics,
                TacticPolicy::PreferGeneralizedPun | TacticPolicy::RelocationOnly
            )
        {
            return Err(Error::new(
                "grouped-policy",
                "explicit observing all-head non-forced group policy required",
            ));
        }
        for &i in &group.members {
            let site = &s.sites[i];
            if !site.block.covers(group.window) || !compatible(first, site) {
                return Err(Error::new(
                    "grouped-policy",
                    "incompatible member source, entries, hook or policy",
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn associations(
        &self,
        s: &Selection,
        groups: &[AcceptedGroup],
        singles: &[(u64, ArtifactPlan)],
        reports: &[SiteReport],
    ) -> Result<Vec<u8>, Error> {
        let mut seen = BTreeSet::new();
        let mut text = format!(
            "GROUP-ASSOCIATIONS\t1\npolicy_sha256\t{}\n",
            ledger::hex(&ContentId::of(&self.policy).0)
        );
        for accepted in groups {
            let expected = self
                .groups
                .get(accepted.group)
                .ok_or_else(|| Error::new("grouped-association", "unknown unit"))?;
            if accepted.members != expected.members
                || accepted.plan.observation_pcs()
                    != expected
                        .members
                        .iter()
                        .map(|&i| s.sites[i].pc)
                        .collect::<Vec<_>>()
                || accepted
                    .plan
                    .artifact()
                    .source_steps()
                    .first()
                    .is_none_or(|step| step.parts().logical_pc != expected.window.start())
            {
                return Err(Error::new(
                    "grouped-association",
                    "opaque plan membership mismatch",
                ));
            }
            self.validate_group(s, expected)?;
            writeln!(
                text,
                "accepted-unit\t{}\t{}\tgroup\t{}",
                accepted.group,
                accepted.primary(s),
                expected.members.len()
            )
            .unwrap();
            for &i in &expected.members {
                if !seen.insert(s.sites[i].id) {
                    return Err(Error::new(
                        "grouped-association",
                        "duplicate accepted member",
                    ));
                }
                self.member(&mut text, s, accepted.group, i);
            }
        }
        for (id, _) in singles {
            let at = self
                .singletons
                .iter()
                .position(|&i| s.sites[i].id == *id)
                .ok_or_else(|| {
                    Error::new(
                        "grouped-association",
                        "singleton is not a frozen singleton unit",
                    )
                })?;
            if !seen.insert(*id) {
                return Err(Error::new(
                    "grouped-association",
                    "duplicate accepted singleton",
                ));
            }
            let unit = self.groups.len() + at;
            writeln!(text, "accepted-unit\t{unit}\t{id}\tsingleton\t1").unwrap();
            self.member(&mut text, s, unit, self.singletons[at]);
        }
        let locally_accepted: BTreeSet<_> = reports
            .iter()
            .filter(|r| r.refusal.is_none())
            .map(|r| r.id)
            .collect();
        if reports.len() != s.sites.len() || seen != locally_accepted {
            return Err(Error::new(
                "grouped-association",
                "accepted members and full local outcome roster differ",
            ));
        }
        // Full immutable policy retains refused units too. Only the units above
        // own plans; successful local admission is not candidate emission.
        writeln!(
            text,
            "accepted_member_count\t{}\ncomplete_site_count\t{}",
            seen.len(),
            s.sites.len()
        )
        .unwrap();
        Ok(text.into_bytes())
    }
}

fn allocation_equal(a: &AllocationPolicy, b: &AllocationPolicy) -> bool {
    a.ranges == b.ranges
        && a.preferred_address == b.preferred_address
        && a.max_candidates == b.max_candidates
        && a.max_mappings == b.max_mappings
        && a.max_mapped_bytes == b.max_mapped_bytes
}
fn compatible(a: &SelectedSite, b: &SelectedSite) -> bool {
    a.snapshot == b.snapshot
        && a.function == b.function
        && a.block == b.block
        && a.hook == b.hook
        && a.semantics == b.semantics
        && a.forced == b.forced
        && a.completeness == b.completeness
        && a.heads == b.heads
        && a.resumes == b.resumes
        && a.provenance == b.provenance
        && a.search.tactics == b.search.tactics
        && a.search.max_upstream_bytes == b.search.max_upstream_bytes
        && a.search.max_displaced_bytes == b.search.max_displaced_bytes
        && a.search.max_sites == b.search.max_sites
        && a.forced_victim == b.forced_victim
        && a.max_victims == b.max_victims
        && a.max_pairs == b.max_pairs
        && allocation_equal(&a.selected_allocation, &b.selected_allocation)
        && allocation_equal(&a.victim_allocation, &b.victim_allocation)
}

pub(crate) fn plan(
    context: SingletonContext<'_, '_>,
    schedule: &Schedule,
    draft: &mut adjacent_b2_frontend::SelectionDraft,
    accepted: &mut Vec<AcceptedGroup>,
) -> Vec<(usize, String)> {
    let mut evidence = Vec::new();
    for (unit, group) in schedule.groups.iter().enumerate() {
        evidence.push((
            unit,
            attempt_group(&context, schedule, unit, group, draft, accepted),
        ));
    }
    for &index in &schedule.singletons {
        attempt_singleton(
            SingletonContext {
                elf: context.elf,
                dynamic: context.dynamic,
                s: context.s,
                identity: context.identity,
                fixed_binding: context.fixed_binding,
                owned_neighbors: false,
                mode: disassembly::NeighborMode::WholeOverlappingPending,
                record_baseline: false,
            },
            draft,
            index,
        );
    }
    evidence
}

fn attempt_group(
    context: &SingletonContext<'_, '_>,
    schedule: &Schedule,
    unit: usize,
    group: &Group,
    draft: &mut adjacent_b2_frontend::SelectionDraft,
    accepted: &mut Vec<AcceptedGroup>,
) -> String {
    let elf = context.elf;
    let dynamic = context.dynamic;
    let s = context.s;
    let identity = context.identity;
    let binding = context.fixed_binding;
    let outside: Vec<_> = draft
        .pending
        .iter()
        .filter_map(|(i, range)| (!group.members.contains(i)).then_some(*range))
        .collect();
    let mut code = None;
    let mut diagnostics = format!(
        "group_unit={unit}; policy_sha256={}; members={:?}; no_fallback=true\n",
        ledger::hex(&ContentId::of(&schedule.policy).0),
        group
            .members
            .iter()
            .map(|&i| s.sites[i].id)
            .collect::<Vec<_>>()
    );
    let mut locally_planned = false;
    let result = (|| {
        schedule.validate_group(s, group)?;
        for &i in &group.members {
            validate_site(elf, &s.sites[i])?;
        }
        // Exclusion is precisely the complete group; missing outstanding rows
        // cannot masquerade as already committed group members.
        if group
            .members
            .iter()
            .any(|i| !draft.pending.iter().any(|(other, _)| other == i))
        {
            return Err(Error::new("grouped-pending", "member was already consumed"));
        }
        let first = &s.sites[group.members[0]];
        let bytes = elf
            .executable_bytes(ElfVaddr(first.snapshot.start()), first.snapshot.len())
            .map_err(|e| Error::new("snapshot", e))?;
        let entries = LegalEntrySet {
            identity,
            scope: first.function,
            provenance: EntryProvenance::Declared(format!(
                "selection provenance SHA-256 {}",
                ledger::hex(&first.provenance.0)
            )),
            completeness: first.completeness,
            entries: first.heads.as_ref().clone(),
            resumes: first.resumes.clone(),
        };
        let hook = s
            .hooks
            .iter()
            .find(|h| h.id == first.hook)
            .ok_or_else(|| Error::new("hook", "missing"))?;
        let emission = fixed_exec::emission(s, hook, draft.occupied.clone(), binding)?;
        let mut search = first.search;
        // This is the explicitly named group policy, authenticated before planning.
        // Numeric budgets come from ONE compatible member, never their sum.
        search.tactics = TacticPolicy::RelocationOnly;
        let pcs: Vec<_> = group.members.iter().map(|&i| s.sites[i].pc).collect();
        let request = ArtifactObservationRequest {
            artifact: ArtifactRequest {
                site: PlanningSite {
                    identity,
                    code: bytes,
                    base_address: first.snapshot.start(),
                    function: first.function,
                    block: first.block,
                    logical_pc: first.pc,
                    entries: &entries,
                    semantics: first.semantics,
                    allocation: &first.selected_allocation,
                    search,
                },
                emission: &emission,
            },
            physical_pc: group.window.start(),
            end: group.window.end(),
            observation_pcs: &pcs,
        };
        let planned =
            match plan_artifact_observation_window_after(&request, &draft.composition, &outside) {
                Ok(plan) => plan,
                Err(failure) => {
                    code = Some(model::core_code(&failure.reason));
                    writeln!(diagnostics, "{failure:#?}").unwrap();
                    return Err(Error::new("core", failure.reason));
                }
            };
        locally_planned = true;
        let li2core::emission::ArtifactMetrics::Single(metrics) = planned.artifact().metrics()
        else {
            return Err(Error::new(
                "grouped-invariant",
                "opaque result is not single-window metrics",
            ));
        };
        if &metrics.search != planned.search() {
            return Err(Error::new(
                "grouped-invariant",
                "opaque search differs from single-window metrics",
            ));
        }
        writeln!(diagnostics, "{:?}", planned.artifact().metrics()).unwrap();
        if planned.observation_pcs() != pcs || planned.artifact().source_steps().len() != 1 {
            return Err(Error::new(
                "grouped-invariant",
                "opaque result population or source-step count",
            ));
        }
        admit_artifact(
            AdmissionContext {
                elf,
                dynamic,
                s,
                mode: disassembly::NeighborMode::WholeOverlappingPending,
            },
            AdmissionState {
                composition: &mut draft.composition,
                occupied: &mut draft.occupied,
                dependencies: &mut draft.dependencies,
                image_count: &mut draft.image_count,
                image_bytes: &mut draft.image_bytes,
                allocation_pages: &mut draft.allocation_pages,
            },
            planned.artifact(),
            &outside,
        )?;
        Ok(planned)
    })();
    for &i in &group.members {
        let report = &mut draft.reports[i];
        report.diagnostics = format!(
            "group_unit={unit}; member={}; evidence=group-{unit}.diagnostics.txt; shared_search_once=true",
            report.id
        );
        if locally_planned {
            report.core_tactic = Some(li2core::engine::Tactic::Relocation);
        }
        if let Err(error) = &result {
            report.refusal = Some(error.clone());
            report.refusal_code = Some(code.unwrap_or(10_001));
        }
    }
    if let Err(error) = &result {
        writeln!(diagnostics, "refusal={error:?}").unwrap();
    }
    if let Ok(plan) = result {
        draft.pending.retain(|(i, _)| !group.members.contains(i));
        accepted.push(AcceptedGroup {
            group: unit,
            members: group.members.clone(),
            plan,
        });
    }
    diagnostics
}

#[cfg(test)]
mod tests;
