//! Complete selected-block units, using the shared artifact planner/transaction.
//! The opaque core window is not a completeness, loader or execution authority.
use crate::*;
use li2core::planner::HookSemantics;
use li2core::quiescent::{
    AllocationPolicy, ArtifactObservationPlan, ArtifactObservationRequest,
    ArtifactObservationSearchRequest, ArtifactObservationWindowSeal, ArtifactRelocationPlacement,
    PlanningFailure, plan_artifact_observation_window_after,
    plan_artifact_observation_window_upstream_after,
    plan_artifact_observation_window_upstream_after_with_placement,
    seal_artifact_observation_window_min5,
};
use li2core::x86::JumpStackClass;
use std::collections::BTreeSet;
use std::fmt::Write as _;
mod physical;
use li2core::quiescent::{
    ArtifactPhysicalWindowSchedule, plan_artifact_observation_windows_upstream_after_with_placement,
};
pub use physical::{
    GROUPED_PHYSICAL_MIN5_ALPHABET_UPSTREAM_PROFILE,
    grouped_physical_min5_alphabet_upstream_fixed_exec_binding_policy,
    grouped_physical_min5_alphabet_upstream_fixed_exec_metadata,
    prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_upstream_fixed_exec,
    prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_upstream_with_ledger_storage,
};

pub const GROUPED_PROFILE: &str = "jumps-gpr-stack64-block-observation-v1";
pub const GROUPED_UPSTREAM_PROFILE: &str = "jumps-gpr-stack64-block-upstream-v1";
pub const GROUPED_MIN5_UPSTREAM_PROFILE: &str = "jumps-gpr-stack64-block-min5-upstream-v1";
pub const GROUPED_MIN5_ALPHABET_UPSTREAM_PROFILE: &str =
    "jumps-gpr-stack64-block-min5-alphabet-upstream-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GroupProfile {
    Exact,
    Upstream,
    Min5Upstream,
    Min5AlphabetUpstream,
    PhysicalMin5AlphabetUpstream,
}
impl GroupProfile {
    fn name(self) -> &'static str {
        match self {
            Self::Exact => GROUPED_PROFILE,
            Self::Upstream => GROUPED_UPSTREAM_PROFILE,
            Self::Min5Upstream => GROUPED_MIN5_UPSTREAM_PROFILE,
            Self::Min5AlphabetUpstream => GROUPED_MIN5_ALPHABET_UPSTREAM_PROFILE,
            Self::PhysicalMin5AlphabetUpstream => GROUPED_PHYSICAL_MIN5_ALPHABET_UPSTREAM_PROFILE,
        }
    }
    fn min5(self) -> bool {
        matches!(self, Self::Min5Upstream | Self::Min5AlphabetUpstream)
    }
    fn physical(self) -> bool {
        self == Self::PhysicalMin5AlphabetUpstream
    }
    fn policy_version(self) -> u8 {
        match self {
            Self::PhysicalMin5AlphabetUpstream => 4,
            Self::Min5AlphabetUpstream => 3,
            Self::Min5Upstream => 2,
            Self::Exact | Self::Upstream => 1,
        }
    }
    fn placement(self) -> ArtifactRelocationPlacement {
        match self {
            Self::Min5AlphabetUpstream | Self::PhysicalMin5AlphabetUpstream => {
                ArtifactRelocationPlacement::EntryAlphabetV1
            }
            _ => ArtifactRelocationPlacement::Fixed06,
        }
    }
    fn policy(self) -> String {
        if self.physical() {
            return Self::Min5AlphabetUpstream.policy()
                .replace("LI2GROUPING-POLICY\t3\n", "LI2GROUPING-POLICY\t4\n")
                .replace(GROUPED_MIN5_ALPHABET_UPSTREAM_PROFILE, self.name())
                .replace("window\tminimum-whole-instruction-through-last-selected-min5-v1\n",
                    "window\tper-physical-minimum-whole-instruction-v1\n")
                .replace("group_relocation_placement\tentry-alphabet-v1\n",
                    "group_relocation_placement\tentry-alphabet-v1\nsource_dependency\tcollector-examined-instruction-envelope-v1\n");
        }
        if self == Self::Exact {
            return POLICY.into();
        }
        let upstream = POLICY.replace(GROUPED_PROFILE, self.name()).replace(
            "group_attempts\t1\n",
            "physical_schedule\tsame-site-then-single-cache-line-then-nearest-upstream-v1\nmax_physical_sites\t64\nmax_upstream_bytes\t64\nmax_displaced_bytes\t256\nimage_candidates_per_physical\t1\nimage_mappings_per_physical\t1\nimage_bytes_per_physical\t4096\nphysical_domain\tsame-block-heads-through-first-member\nmembership\tfull-manifest-maximum-prefix-and-actual-window\n",
        );
        if self.min5() {
            let policy = upstream.replace("LI2GROUPING-POLICY\t1\n", &format!("LI2GROUPING-POLICY\t{}\n", self.policy_version()))
                .replace("window\tfirst-selected-head-through-last-selected-instruction\n",
                    "window\tminimum-whole-instruction-through-last-selected-min5-v1\nseal_source\timmutable-original\nseal_stage\tbefore-overlay-mutation\n");
            if self.placement() == ArtifactRelocationPlacement::EntryAlphabetV1 {
                policy.replace("seal_stage\tbefore-overlay-mutation\n",
                    "seal_stage\tbefore-overlay-mutation\ngroup_relocation_placement\tentry-alphabet-v1\n")
            } else {
                policy
            }
        } else {
            upstream
        }
    }
    pub(crate) fn binding_policy(
        self,
        binding: FixedImageBinding,
        selection: ContentId,
        grouping: ContentId,
    ) -> Vec<u8> {
        let bytes = fixed_exec::grouped_binding_policy(binding, selection, grouping);
        if self == Self::Exact {
            return bytes;
        }
        // Reuse the sole canonical formatter. Only its two source-controlled
        // profile labels differ; identities and every obligation stay literal.
        String::from_utf8(bytes)
            .expect("canonical ASCII binding policy")
            .replace(GROUPED_PROFILE, self.name())
            .into_bytes()
    }
}
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
    prepare_grouped(original, selected, GroupProfile::Exact)
}

/// Separately named bounded physical search; partition, selected spans, source
/// policies and final atomic admission are identical to the exact profile.
pub fn prepare_disassembly_jump_stack_grouped_upstream_fixed_exec(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
) -> Result<Product, Error> {
    prepare_grouped(original, selected, GroupProfile::Upstream)
}

/// Separate minimum-window endpoint policy, frozen before any overlay mutation.
/// The supplied selection is unchanged; final native/loader obligations remain.
pub fn prepare_disassembly_jump_stack_grouped_min5_upstream_fixed_exec(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
) -> Result<Product, Error> {
    prepare_grouped(original, selected, GroupProfile::Min5Upstream)
}

/// The same minimum-window policy with the existing independent ledger codec.
pub fn prepare_disassembly_jump_stack_grouped_min5_upstream_with_ledger_storage(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
    storage: LedgerStorage,
) -> Result<Product, Error> {
    prepare_grouped_with_storage(original, selected, GroupProfile::Min5Upstream, storage)
}

/// Minimum-window geometry with the explicit artifact entry-alphabet placement.
/// Singletons retain their existing planner; this grants no execution authority.
pub fn prepare_disassembly_jump_stack_grouped_min5_alphabet_upstream_fixed_exec(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
) -> Result<Product, Error> {
    prepare_grouped(original, selected, GroupProfile::Min5AlphabetUpstream)
}
pub fn prepare_disassembly_jump_stack_grouped_min5_alphabet_upstream_with_ledger_storage(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
    storage: LedgerStorage,
) -> Result<Product, Error> {
    prepare_grouped_with_storage(
        original,
        selected,
        GroupProfile::Min5AlphabetUpstream,
        storage,
    )
}

fn prepare_grouped(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
    profile: GroupProfile,
) -> Result<Product, Error> {
    prepare_grouped_with_storage(original, selected, profile, LedgerStorage::Inline)
}

/// Independent physical storage option. All grouping/planning policies stay fixed.
pub fn prepare_disassembly_jump_stack_grouped_with_ledger_storage(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
    upstream: bool,
    storage: LedgerStorage,
) -> Result<Product, Error> {
    prepare_grouped_with_storage(
        original,
        selected,
        if upstream {
            GroupProfile::Upstream
        } else {
            GroupProfile::Exact
        },
        storage,
    )
}
fn prepare_grouped_with_storage(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
    profile: GroupProfile,
    storage: LedgerStorage,
) -> Result<Product, Error> {
    let mut product = prepare_selection_with_storage(
        original,
        selected.selection.clone(),
        false,
        disassembly::NeighborMode::WholeOverlappingPending,
        None,
        adjacent_b2_frontend::PairProfile::ForwardJcc,
        (
            CarrierTransaction {
                hooks: TransactionHooks {
                    addon: None,
                    gate: |_| Ok(()),
                },
                packed_rx_runs: true,
                fixed_exec: true,
                grouped_classes: Some((&selected.classes, profile)),
            },
            storage,
        ),
    )?;
    product.files.remove("bundle-index.tsv");
    let mut files = selected.packed_overlapping_files();
    let planning = files
        .get_mut("planning-profile.tsv")
        .expect("sealed union has a planning profile");
    let metadata = if storage == LedgerStorage::ReadChunks256 {
        grouped_metadata(profile).replace(
            "grouping_ledger\tLI2GROUPED-LEDGER-1\n",
            "grouping_ledger\tLI2GROUPED-LEDGER-2\n",
        )
    } else {
        grouped_metadata(profile)
    };
    planning.extend_from_slice(metadata.as_bytes());
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
    grouped_metadata(GroupProfile::Exact)
}
pub fn grouped_upstream_fixed_exec_metadata() -> String {
    grouped_metadata(GroupProfile::Upstream)
}
pub fn grouped_min5_upstream_fixed_exec_metadata() -> String {
    grouped_metadata(GroupProfile::Min5Upstream)
}
pub fn grouped_min5_alphabet_upstream_fixed_exec_metadata() -> String {
    grouped_metadata(GroupProfile::Min5AlphabetUpstream)
}
fn grouped_metadata(profile: GroupProfile) -> String {
    let physical = profile.physical();
    let min5 = profile.min5();
    let version = profile.policy_version();
    let placement = profile.placement();
    let profile = profile.name();
    let mut out = FIXED_EXEC_METADATA.replacen(
        "planner_profile\twhole-program-packed-overlapping-neighbors-4096\n",
        &format!("planner_profile\t{profile}\nsingleton_planner_profile\twhole-program-packed-overlapping-neighbors-4096\n"), 1,
    );
    out.push_str(&format!("grouped_profile\t{profile}\ngrouping_policy\tgrouping-policy.tsv\ngrouping_ledger\tLI2GROUPED-LEDGER-1\n"));
    if min5 {
        out.push_str(&format!(
            "grouping_policy_version\t{version}\nwindow_sealing\tminimum-whole-instruction-v1\n"
        ));
    }
    if physical {
        out.push_str(
            "grouping_policy_version\t4\nwindow_sealing\tphysical-minimum-whole-instruction-v1\n",
        );
    }
    if placement == ArtifactRelocationPlacement::EntryAlphabetV1 {
        out.push_str("group_relocation_placement\tentry-alphabet-v1\n");
    }
    out
}

/// The same canonical bytes used by initial embedded and final portable metadata.
/// Authentication of the full grouping policy remains the caller's obligation.
pub fn grouped_fixed_exec_binding_policy(
    binding: FixedImageBinding,
    selection: ContentId,
    grouping: ContentId,
) -> Vec<u8> {
    GroupProfile::Exact.binding_policy(binding, selection, grouping)
}
pub fn grouped_upstream_fixed_exec_binding_policy(
    binding: FixedImageBinding,
    selection: ContentId,
    grouping: ContentId,
) -> Vec<u8> {
    GroupProfile::Upstream.binding_policy(binding, selection, grouping)
}

pub fn grouped_min5_upstream_fixed_exec_binding_policy(
    binding: FixedImageBinding,
    selection: ContentId,
    grouping: ContentId,
) -> Vec<u8> {
    GroupProfile::Min5Upstream.binding_policy(binding, selection, grouping)
}

pub fn grouped_min5_alphabet_upstream_fixed_exec_binding_policy(
    binding: FixedImageBinding,
    selection: ContentId,
    grouping: ContentId,
) -> Vec<u8> {
    GroupProfile::Min5AlphabetUpstream.binding_policy(binding, selection, grouping)
}

#[derive(Clone, Debug)]
struct SealFailure {
    error: Error,
    code: u32,
    core: Option<Box<PlanningFailure>>,
}
impl SealFailure {
    fn adapter(error: Error) -> Self {
        Self {
            error,
            code: 10_001,
            core: None,
        }
    }
    fn core(failure: PlanningFailure) -> Self {
        Self {
            error: Error::new("core", &failure.reason),
            code: model::core_code(&failure.reason),
            core: Some(Box::new(failure)),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Group {
    // Indices into the immutable complete selected roster, in original PC order.
    members: Vec<usize>,
    // Original selected span remains independent of the sealed retained end.
    window: AddressRange,
    seal: Option<Result<ArtifactObservationWindowSeal, SealFailure>>,
    physical: Option<Result<ArtifactPhysicalWindowSchedule, SealFailure>>,
}
impl Group {
    fn retained_window(&self) -> AddressRange {
        match &self.seal {
            Some(Ok(seal)) => seal.retained_span(),
            _ => self.window,
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Schedule {
    pub(crate) profile: GroupProfile,
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
        Self::freeze_profile(elf, s, classes, GroupProfile::Exact)
    }
    pub(crate) fn freeze_upstream(
        elf: &Elf64<'_>,
        s: &Selection,
        classes: &[JumpStackClass],
    ) -> Result<Self, Error> {
        Self::freeze_profile(elf, s, classes, GroupProfile::Upstream)
    }
    pub(crate) fn freeze_min5_upstream(
        elf: &Elf64<'_>,
        s: &Selection,
        classes: &[JumpStackClass],
        identity: CodeIdentity,
        binding: Option<FixedImageBinding>,
        occupied: &[AddressRange],
    ) -> Result<Self, Error> {
        Self::freeze_min5_profile(
            elf,
            s,
            classes,
            identity,
            binding,
            occupied,
            GroupProfile::Min5Upstream,
        )
    }
    pub(crate) fn freeze_min5_profile(
        elf: &Elf64<'_>,
        s: &Selection,
        classes: &[JumpStackClass],
        identity: CodeIdentity,
        binding: Option<FixedImageBinding>,
        occupied: &[AddressRange],
        profile: GroupProfile,
    ) -> Result<Self, Error> {
        debug_assert!(profile.min5());
        let mut out = Self::freeze_profile(elf, s, classes, profile)?;
        for unit in 0..out.groups.len() {
            let result = (|| {
                let group = &out.groups[unit];
                out.validate_group(s, group).map_err(SealFailure::adapter)?;
                out.validate_upstream(s, group)
                    .map_err(SealFailure::adapter)?;
                for &i in &group.members {
                    validate_site(elf, &s.sites[i]).map_err(SealFailure::adapter)?;
                }
                let request = GroupRequest::new(elf, s, identity, binding, group, occupied)
                    .map_err(SealFailure::adapter)?;
                let seal = seal_artifact_observation_window_min5(&request.artifact(), &request.pcs)
                    .map_err(SealFailure::core)?;
                if seal.selected_span() != group.window {
                    return Err(SealFailure::adapter(Error::new(
                        "grouped-seal",
                        "selected span differs",
                    )));
                }
                out.validate_intersection(s, group, seal.retained_span())
                    .map_err(SealFailure::adapter)?;
                let floor = s.sites[group.members[0]]
                    .block
                    .start()
                    .max(group.window.start().saturating_sub(64));
                out.validate_intersection(
                    s,
                    group,
                    addr(floor, seal.retained_span().end() - floor)
                        .map_err(SealFailure::adapter)?,
                )
                .map_err(SealFailure::adapter)?;
                Ok(seal)
            })();
            // A refused seal remains one whole unit. No overlay has changed.
            out.groups[unit].seal = Some(result);
        }
        out.policy = out.policy_bytes(s);
        Ok(out)
    }
    fn freeze_profile(
        elf: &Elf64<'_>,
        s: &Selection,
        classes: &[JumpStackClass],
        profile: GroupProfile,
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
                    seal: None,
                    physical: None,
                });
            }
        }
        groups.sort_by_key(|group| std::cmp::Reverse(group.window.start()));
        singletons.sort_by_key(|&i| std::cmp::Reverse(s.sites[i].pc));
        let mut out = Self {
            profile,
            groups,
            singletons,
            classes: classes.to_vec(),
            policy: Vec::new(),
        };
        if !profile.min5() && !profile.physical() {
            out.policy = out.policy_bytes(s);
        }
        Ok(out)
    }
    fn policy_bytes(&self, s: &Selection) -> Vec<u8> {
        let policy = self.profile.policy();
        let mut text = format!(
            "{policy}original_sha256\t{}\nselection_sha256\t{}\ncomplete_site_count\t{}\n",
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
            if self.profile.physical() {
                self.physical_policy(&mut text, unit, group);
            }
            if self.profile.min5() {
                match group
                    .seal
                    .as_ref()
                    .expect("minimum-window schedule sealed before serialization")
                {
                    Ok(seal) => writeln!(
                        text,
                        "window-seal\t{unit}\tready\t{}\t-\t-\t-",
                        seal.retained_span().end()
                    )
                    .unwrap(),
                    Err(failure) => writeln!(
                        text,
                        "window-seal\t{unit}\trefused\t-\t{}\t{}\t{}",
                        failure.code,
                        failure.error.stage,
                        ledger::hex(failure.error.detail.as_bytes())
                    )
                    .unwrap(),
                }
            }
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
        self.validate_intersection(s, group, group.window)?;
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
    fn validate_intersection(
        &self,
        s: &Selection,
        group: &Group,
        window: AddressRange,
    ) -> Result<(), Error> {
        let mut intersection = Vec::new();
        for (i, site) in s.sites.iter().enumerate() {
            let range = addr(site.pc, u64::from(site.length))?;
            if range.start() < window.end() && window.start() < range.end() {
                if !window.covers(range) {
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
        Ok(())
    }
    fn upstream_envelope(&self, s: &Selection, group: &Group) -> Result<AddressRange, Error> {
        let first = &s.sites[group.members[0]];
        let floor = first.block.start().max(first.pc.saturating_sub(64));
        let end = if self.profile.physical() {
            group
                .physical
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .map_or(group.window.end(), |schedule| {
                    schedule
                        .rows()
                        .iter()
                        .filter_map(|row| row.outcome().ok())
                        .fold(group.window.end(), u64::max)
                })
        } else {
            group.retained_window().end()
        };
        addr(floor, end - floor)
    }
    fn validate_upstream(&self, s: &Selection, group: &Group) -> Result<(), Error> {
        let first = &s.sites[group.members[0]];
        if first.search.max_sites != 64
            || first.search.max_upstream_bytes != 64
            || first.search.max_displaced_bytes != 256
            || [&first.selected_allocation, &first.victim_allocation]
                .iter()
                .any(|a| a.max_candidates != 1 || a.max_mappings != 1 || a.max_mapped_bytes != 4096)
        {
            return Err(Error::new(
                "grouped-upstream-policy",
                "unchanged bounded search and image tuple required",
            ));
        }
        // This uses the FULL immutable selection, including already accepted
        // and straddling intervals. Pending is not a completeness substitute.
        self.validate_intersection(s, group, self.upstream_envelope(s, group)?)
    }
    fn validate_actual_window(
        &self,
        s: &Selection,
        group: &Group,
        plan: &ArtifactPlan,
    ) -> Result<(), Error> {
        if self.profile.physical() {
            return self.actual_physical_ordinal(s, group, plan).map(|_| ());
        }
        if self.profile == GroupProfile::Exact {
            return Ok(());
        }
        if self.profile.min5() {
            match &group.seal {
                Some(Ok(seal)) if seal.selected_span() == group.window => {
                    self.validate_intersection(s, group, seal.retained_span())?;
                }
                _ => {
                    return Err(Error::new(
                        "grouped-seal",
                        "accepted unit lacks its frozen seal",
                    ));
                }
            }
        }
        self.validate_upstream(s, group)?;
        let first = &s.sites[group.members[0]];
        let [step] = plan.source_steps() else {
            return Err(Error::new(
                "grouped-association",
                "one actual physical window required",
            ));
        };
        let parts = step.parts();
        let envelope = self.upstream_envelope(s, group)?;
        if parts.logical_pc != first.pc
            || parts.physical_pc > first.pc
            || parts.physical_pc != parts.displaced.start()
            || parts.displaced.end() != group.retained_window().end()
            || parts.displaced.len() > 256
            || !envelope.covers(parts.displaced)
            || !first.block.covers(parts.displaced)
            || !first
                .heads
                .iter()
                .any(|head| head.address == parts.physical_pc)
        {
            return Err(Error::new(
                "grouped-association",
                "actual upstream head/window outside frozen domain",
            ));
        }
        self.validate_intersection(s, group, parts.displaced)
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
            self.validate_actual_window(s, expected, accepted.plan.artifact())?;
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

// Own temporary entry/emission data; the core seal owns only bounded geometry.
// Both immutable preflight and actual attempt use this one request construction.
struct GroupRequest<'a> {
    first: &'a SelectedSite,
    bytes: &'a [u8],
    identity: CodeIdentity,
    entries: LegalEntrySet,
    emission: li2core::emission::ArtifactEmission,
    search: li2core::quiescent::SearchPolicy,
    pcs: Vec<u64>,
}
impl<'a> GroupRequest<'a> {
    fn new(
        elf: &'a Elf64<'_>,
        s: &'a Selection,
        identity: CodeIdentity,
        binding: Option<FixedImageBinding>,
        group: &Group,
        occupied: &[AddressRange],
    ) -> Result<Self, Error> {
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
        let emission = fixed_exec::emission(s, hook, occupied.to_vec(), binding)?;
        let mut search = first.search;
        // This is the explicitly named group policy, authenticated before planning.
        // Numeric budgets come from ONE compatible member, never their sum.
        search.tactics = TacticPolicy::RelocationOnly;
        let pcs: Vec<_> = group.members.iter().map(|&i| s.sites[i].pc).collect();
        Ok(Self {
            first,
            bytes,
            identity,
            entries,
            emission,
            search,
            pcs,
        })
    }
    fn artifact(&self) -> ArtifactRequest<'_> {
        ArtifactRequest {
            site: PlanningSite {
                identity: self.identity,
                code: self.bytes,
                base_address: self.first.snapshot.start(),
                function: self.first.function,
                block: self.first.block,
                logical_pc: self.first.pc,
                entries: &self.entries,
                semantics: self.first.semantics,
                allocation: &self.first.selected_allocation,
                search: self.search,
            },
            emission: &self.emission,
        }
    }
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
        if schedule.profile.physical() {
            match &group.physical {
                Some(Ok(_)) => {}
                Some(Err(failure)) => {
                    code = Some(failure.code);
                    if let Some(core) = &failure.core {
                        writeln!(diagnostics, "{core:#?}").unwrap();
                    }
                    return Err(failure.error.clone());
                }
                None => {
                    return Err(Error::new(
                        "grouped-physical-seal",
                        "missing immutable preflight",
                    ));
                }
            }
        }
        if schedule.profile.min5() {
            match &group.seal {
                Some(Ok(_)) => {}
                Some(Err(failure)) => {
                    code = Some(failure.code);
                    if let Some(core) = &failure.core {
                        writeln!(diagnostics, "{core:#?}").unwrap();
                    }
                    return Err(failure.error.clone());
                }
                None => return Err(Error::new("grouped-seal", "missing immutable preflight")),
            }
        }
        schedule.validate_group(s, group)?;
        if schedule.profile != GroupProfile::Exact {
            schedule.validate_upstream(s, group)?;
        }
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
        let request = GroupRequest::new(elf, s, identity, binding, group, &draft.occupied)?;
        let pcs = &request.pcs;
        let artifact = request.artifact();
        if schedule.profile.physical() {
            let Some(Ok(seal)) = &group.physical else {
                return Err(Error::new(
                    "grouped-physical-seal",
                    "missing successful preflight",
                ));
            };
            seal.matches_request(&artifact, pcs)
                .map_err(|e| Error::new("grouped-physical-seal", e))?;
            schedule.validate_physical_membership(s, group, seal)?;
        }
        if schedule.profile.min5() {
            let Some(Ok(seal)) = &group.seal else {
                return Err(Error::new("grouped-seal", "missing successful preflight"));
            };
            seal.matches_request(&artifact, pcs)
                .map_err(|e| Error::new("grouped-seal", e))?;
            schedule.validate_intersection(s, group, seal.retained_span())?;
        }
        let result = match schedule.profile {
            GroupProfile::PhysicalMin5AlphabetUpstream => {
                let Some(Ok(seal)) = &group.physical else {
                    unreachable!("preflight checked")
                };
                plan_artifact_observation_windows_upstream_after_with_placement(
                    &artifact,
                    seal,
                    &draft.composition,
                    &outside,
                    schedule.profile.placement(),
                )
            }
            GroupProfile::Exact => plan_artifact_observation_window_after(
                &ArtifactObservationRequest {
                    artifact,
                    physical_pc: group.window.start(),
                    end: group.window.end(),
                    observation_pcs: pcs,
                },
                &draft.composition,
                &outside,
            ),
            GroupProfile::Upstream
            | GroupProfile::Min5Upstream
            | GroupProfile::Min5AlphabetUpstream => {
                let request = ArtifactObservationSearchRequest {
                    artifact,
                    end: group.retained_window().end(),
                    observation_pcs: pcs,
                };
                match schedule.profile.placement() {
                    ArtifactRelocationPlacement::Fixed06 => {
                        plan_artifact_observation_window_upstream_after(
                            &request,
                            &draft.composition,
                            &outside,
                        )
                    }
                    placement => plan_artifact_observation_window_upstream_after_with_placement(
                        &request,
                        &draft.composition,
                        &outside,
                        placement,
                    ),
                }
            }
        };
        let planned = match result {
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
        if planned.observation_pcs() != pcs.as_slice()
            || planned.artifact().source_steps().len() != 1
        {
            return Err(Error::new(
                "grouped-invariant",
                "opaque result population or source-step count",
            ));
        }
        schedule.validate_actual_window(s, group, planned.artifact())?;
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

#[cfg(test)]
mod upstream_tests;

#[cfg(test)]
mod min5_tests;

#[cfg(test)]
mod alphabet_tests;
