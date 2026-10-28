//! Exact fixed-grammar factories; callers cannot substitute a role/action list.
use super::{entry_callback, exit_callback};
pub mod ordinary;
use crate::frontend_native::{LoadedBranchLeaf, LoadedLeaf, SetupRefusal};
use liteinst2::bundle::{BundleBudget, BundlePlan, BundleReceipt, InstalledBundle, PlannedBundle};
use liteinst2::contracts::*;
use liteinst2::controls::{ControlIdentity, ControlledAction, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, InstalledOnce, PlannedInstall, PlanningFailure, SearchPolicy,
    TacticPolicy, plan_coalesced_detailed,
};
use liteinst2::trampoline::{ExecutableTrampoline, HookContext, TrampolineImage};
use std::sync::Arc;

#[derive(Debug)]
/// A source/planning/publication correspondence refusal, with no installed authority.
pub enum SiteError {
    /// The separate raw timestamp profile requires RDTSCP.
    ClockUnsupported,
    /// Exact library CALL/RET gate refusal.
    Gate(super::gate::GateError),
    /// Original complete loader/source qualification failed.
    Source(SetupRefusal),
    /// Full bounded candidate failure, including its attempts, remains available.
    Planning(PlanningFailure),
    /// Existing composition/range validator refused.
    Core(Refusal),
    /// Exact fixed grammar, roles, plan, receipt or current bytes disagree.
    Correspondence,
}
impl From<Refusal> for SiteError {
    fn from(e: Refusal) -> Self {
        Self::Core(e)
    }
}
struct Role {
    pc: u64,
    control: ProbeControl,
}
pub(super) struct Site {
    roles: Vec<Role>,
    pub(super) terminal: u64,
    pub(super) gate: Option<Arc<super::gate::CallGate>>,
}
impl Site {
    pub(super) fn matches(&self, pc: u64, control: ControlIdentity<'_>, entry: bool) -> bool {
        self.roles
            .iter()
            .enumerate()
            .any(|(i, r)| (i == 0) == entry && r.pc == pc && r.control.has_identity(control))
    }
}
enum Owner {
    Single(&'static mut LoadedLeaf),
    Branch(&'static mut LoadedBranchLeaf),
}
impl Owner {
    fn entry(&self) -> u64 {
        match self {
            Self::Single(x) => x.entry(),
            Self::Branch(x) => x.entry(),
        }
    }
    fn terminal(&self) -> u64 {
        match self {
            Self::Single(x) => x.terminal(),
            Self::Branch(x) => x.terminal(),
        }
    }
    fn code(&self) -> &[u8] {
        match self {
            Self::Single(x) => x.code(),
            Self::Branch(x) => x.code(),
        }
    }
    fn original_page(&self) -> &[u8] {
        match self {
            Self::Single(x) => x.original_page(),
            Self::Branch(x) => x.original_page(),
        }
    }
    fn page(&self) -> u64 {
        match self {
            Self::Single(x) => x.page(),
            Self::Branch(x) => x.page(),
        }
    }
    fn verify(&mut self, patched: bool) -> Result<(), SiteError> {
        match self {
            Self::Single(x) => x.verify(patched),
            Self::Branch(x) => x.verify(patched),
        }
        .map_err(SiteError::Source)
    }
}
enum Planned {
    Single(Box<PlannedInstall>),
    Branch(Box<PlannedBundle>),
}
/// Owns the exact loader and factory plan. Only immutable plan inspection is exposed.
/// Publication still requires the existing unsafe publisher and complete lease.
pub struct IntervalSitePreparation {
    owner: Owner,
    planned: Planned,
    site: Arc<Site>,
}
/// Process-lived sealed source/publication authority. No owner/retire handle escapes.
pub struct InstalledIntervalSite {
    pub(super) site: Arc<Site>,
}
unsafe extern "C" fn impossible_ordinary_dispatch(_: *mut HookContext) {
    // SAFETY: the exact factory must emit managed actions, never this fallback.
    unsafe { libc::_exit(123) }
}
fn roles(entry: u64, offsets: &[u64]) -> Vec<Role> {
    offsets
        .iter()
        .enumerate()
        .map(|(i, offset)| {
            let (control, writer) = ProbeControl::new_managed_bound(
                if i == 0 {
                    entry_callback
                } else {
                    exit_callback
                },
                true,
            );
            drop(writer); // No public or private operation can disable mandatory bookkeeping.
            Role {
                pc: entry + offset,
                control,
            }
        })
        .collect()
}
fn entries(identity: CodeIdentity, scope: AddressRange, offsets: &[u64]) -> LegalEntrySet {
    LegalEntrySet { identity, scope, provenance: EntryProvenance::Declared(
        "complete authored fixed interval grammar; sealing retains the publisher's full entry/resume contract".into()),
        completeness: EntryCompleteness::Complete,
        entries: offsets.iter().map(|&n| LegalEntry { address: scope.start() + n, requires_endbr: false }).collect(),
        resumes: ResumeObligation::NoneExist }
}
fn base_allocation(entry: u64) -> Result<AllocationPolicy, SiteError> {
    let allocation = AllocationPolicy::near(entry)?;
    if (
        allocation.max_candidates,
        allocation.max_mappings,
        allocation.max_mapped_bytes,
    ) != (256, 1, 8192)
    {
        return Err(SiteError::Correspondence);
    }
    Ok(allocation)
}
impl IntervalSitePreparation {
    /// Construct exactly the whole 19-byte plan, with entry and original RET actions.
    /// No installation or physical publication occurs here.
    pub fn leaf(owner: &'static mut LoadedLeaf, identity: CodeIdentity) -> Result<Self, SiteError> {
        owner.verify(false).map_err(SiteError::Source)?;
        let entry = owner.entry();
        if identity.mapping != entry || identity.generation == 0 {
            return Err(SiteError::Correspondence);
        }
        let scope = AddressRange::new(entry, 19)?;
        let roles = roles(entry, &[0, 18]);
        let actions: Vec<_> = roles
            .iter()
            .map(|r| ControlledAction {
                logical_pc: r.pc,
                control: r.control.clone(),
            })
            .collect();
        let entries = entries(identity, scope, &[0]);
        let allocation = base_allocation(entry)?;
        let plan = plan_coalesced_detailed(
            &InstallRequest {
                identity,
                code: owner.code(),
                base_address: entry,
                function: scope,
                block: scope,
                logical_pc: entry,
                entries: &entries,
                hook: impossible_ordinary_dispatch,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_displaced_bytes: 80,
                    max_sites: 1,
                },
            },
            &actions,
        )
        .map_err(SiteError::Planning)?;
        let p = plan.plan().parts();
        if p.kind != PlanKind::Relocation
            || p.displaced != scope
            || p.physical_pc != entry
            || p.writes.len() != 1
            || p.writes[0].address != entry
            || p.writes[0].bytes.len() != 19
            || plan.metrics().displaced_bytes != 19
            || plan
                .image()
                .instruction_boundaries()
                .iter()
                .map(|&(pc, _)| pc - entry)
                .collect::<Vec<_>>()
                != [0, 5, 12, 15, 18]
            || plan.image().controls()
                != actions
                    .iter()
                    .map(|a| a.control.clone())
                    .collect::<Vec<_>>()
        {
            return Err(SiteError::Correspondence);
        }
        let terminal = owner.terminal();
        Ok(Self {
            owner: Owner::Single(owner),
            planned: Planned::Single(Box::new(plan)),
            site: Arc::new(Site {
                roles,
                terminal,
                gate: None,
            }),
        })
    }
    /// Construct the unchanged three-member block-local branch grammar: entry,
    /// nonzero RET block, zero RET block. This is not a coalesced multi-member plan.
    pub fn branch(
        owner: &'static mut LoadedBranchLeaf,
        identity: CodeIdentity,
    ) -> Result<Self, SiteError> {
        owner.verify(false).map_err(SiteError::Source)?;
        let entry = owner.entry();
        if identity.mapping != entry || identity.generation == 0 {
            return Err(SiteError::Correspondence);
        }
        let scope = AddressRange::new(entry, 36)?;
        let roles = roles(entry, &[0, 27, 35]);
        let entries = entries(identity, scope, &[0, 21, 28]);
        let mut overlay = owner.code().to_vec();
        let mut reserved: Vec<AddressRange> = Vec::new();
        let mut members = Vec::new();
        for (index, (logical, start, len, displaced, role)) in
            [(0, 0, 21, 5, 0), (35, 28, 8, 8, 2), (27, 21, 7, 7, 1)]
                .into_iter()
                .enumerate()
        {
            let mut allocation = base_allocation(entry)?;
            allocation.preferred_address = Some(
                (entry & !4095)
                    .checked_add(0x10_0000 + index as u64 * 0x1_0000)
                    .ok_or(Refusal::InvalidRange)?,
            );
            for &prior in &reserved {
                let mut remaining = Vec::new();
                for &range in &allocation.ranges {
                    if !range.overlaps(prior) {
                        remaining.push(range);
                    } else {
                        if range.start() < prior.start() {
                            remaining.push(AddressRange::new(
                                range.start(),
                                (prior.start() - range.start()) as usize,
                            )?);
                        }
                        if prior.end() < range.end() {
                            remaining.push(AddressRange::new(
                                prior.end(),
                                (range.end() - prior.end()) as usize,
                            )?);
                        }
                    }
                }
                allocation.ranges = remaining;
            }
            let member = plan_coalesced_detailed(
                &InstallRequest {
                    identity,
                    code: &overlay,
                    base_address: entry,
                    function: scope,
                    block: AddressRange::new(entry + start, len)?,
                    logical_pc: entry + logical,
                    entries: &entries,
                    hook: impossible_ordinary_dispatch,
                    semantics: HookSemantics::Observe,
                    allocation: &allocation,
                    search: SearchPolicy {
                        tactics: TacticPolicy::RelocationOnly,
                        max_upstream_bytes: if index == 0 { 0 } else { 7 },
                        max_displaced_bytes: if index == 0 { 5 } else { 8 },
                        max_sites: if index == 0 { 1 } else { 3 },
                    },
                },
                &[ControlledAction {
                    logical_pc: roles[role].pc,
                    control: roles[role].control.clone(),
                }],
            )
            .map_err(SiteError::Planning)?;
            let p = member.plan().parts();
            if p.kind != PlanKind::Relocation
                || p.physical_pc != entry + start
                || p.displaced != AddressRange::new(entry + start, displaced)?
                || member.metrics().displaced_bytes != displaced
                || p.writes.len() != 1
                || member.image().controls() != [roles[role].control.clone()]
            {
                return Err(SiteError::Correspondence);
            }
            for request in &p.allocations {
                if reserved.iter().any(|r| r.overlaps(request.range)) {
                    return Err(SiteError::Correspondence);
                }
                reserved.push(request.range);
            }
            for edit in &p.writes {
                let offset = usize::try_from(
                    edit.address
                        .checked_sub(entry)
                        .ok_or(Refusal::InvalidRange)?,
                )
                .map_err(|_| Refusal::InvalidRange)?;
                let end = offset
                    .checked_add(edit.bytes.len())
                    .ok_or(Refusal::InvalidRange)?;
                overlay
                    .get_mut(offset..end)
                    .ok_or(Refusal::InvalidRange)?
                    .copy_from_slice(&edit.bytes);
            }
            members.push(member);
        }
        let plan = PlannedBundle::compose(
            vec![ExpectedBytes {
                address: entry,
                bytes: owner.code().to_vec(),
            }],
            members,
            BundleBudget {
                max_steps: 3,
                max_mappings: 3,
                max_virtual_bytes: 24576,
                max_backing_bytes: 24576,
                max_virtual_span: 1 << 32,
            },
        )?;
        if plan.images().len() != 3
            || plan.plan().final_bytes()
                != [ExpectedBytes {
                    address: entry,
                    bytes: overlay,
                }]
        {
            return Err(SiteError::Correspondence);
        }
        let terminal = owner.terminal();
        Ok(Self {
            owner: Owner::Branch(owner),
            planned: Planned::Branch(Box::new(plan)),
            site: Arc::new(Site {
                roles,
                terminal,
                gate: None,
            }),
        })
    }
    /// Exact factory plan for the existing unsafe publisher and complete lease.
    pub fn single_plan(&self) -> Option<&PlannedInstall> {
        match &self.planned {
            Planned::Single(p) => Some(p.as_ref()),
            Planned::Branch(_) => None,
        }
    }
    /// Exact factory bundle for the existing unsafe publisher and complete lease.
    pub fn branch_plan(&self) -> Option<&PlannedBundle> {
        match &self.planned {
            Planned::Branch(p) => Some(p.as_ref()),
            Planned::Single(_) => None,
        }
    }
    /// Consume and retain exact installed single-plan authority, including on refusal.
    ///
    /// # Safety
    /// The complete original publisher contract still holds: real (not mock)
    /// publication/receipt, exact quiescence, final RX source and generated bytes,
    /// full legal-entry and NoneExist-resume proof, no CET, signals, external entry,
    /// unload, alias mutation or concurrent writer. All source/image addresses may
    /// be read. No callback executes until this succeeds and an attachment exists.
    pub unsafe fn seal_single(
        self,
        installed: InstalledOnce,
        receipt: PublicationReceipt,
    ) -> Result<InstalledIntervalSite, SiteError> {
        // Intentionally process-lived, non-Send owner/handle. No retire-capable
        // handle is extracted or placed in the shared immutable site descriptor.
        let retained = Box::leak(Box::new((self, installed, receipt)));
        let (prep, installed, receipt) = retained;
        let Planned::Single(plan) = &prep.planned else {
            return Err(SiteError::Correspondence);
        };
        if installed.is_retired()
            || installed.plan() != plan.plan()
            || receipt.plan() != plan.plan()
        {
            return Err(SiteError::Correspondence);
        }
        // SAFETY: caller's exact live publication and readable owner contract.
        unsafe {
            check_image(plan.image(), installed.trampoline())?;
        }
        let mut expected = prep.owner.code().to_vec();
        for edit in &plan.plan().parts().writes {
            let n = usize::try_from(
                edit.address
                    .checked_sub(prep.owner.entry())
                    .ok_or(Refusal::InvalidRange)?,
            )
            .map_err(|_| Refusal::InvalidRange)?;
            let end = n
                .checked_add(edit.bytes.len())
                .ok_or(Refusal::InvalidRange)?;
            expected
                .get_mut(n..end)
                .ok_or(Refusal::InvalidRange)?
                .copy_from_slice(&edit.bytes);
        }
        // SAFETY: same complete source owner.
        unsafe {
            check_source(&mut prep.owner, &expected)?;
        }
        Ok(InstalledIntervalSite {
            site: Arc::clone(&prep.site),
        })
    }
    /// Consume/retain every branch owner and member as one exact transaction.
    ///
    /// # Safety
    /// seal_single's complete contract applies to all three source blocks and
    /// images, including both declared alternate entries and both original RETs.
    pub unsafe fn seal_branch(
        self,
        installed: InstalledBundle,
        receipt: BundleReceipt,
    ) -> Result<InstalledIntervalSite, SiteError> {
        let retained = Box::leak(Box::new((self, installed, receipt)));
        let (prep, installed, receipt) = retained;
        let Planned::Branch(plan) = &prep.planned else {
            return Err(SiteError::Correspondence);
        };
        if installed.is_retired()
            || !same_bundle(installed.plan(), plan.plan())
            || !same_bundle(receipt.plan(), plan.plan())
            || installed.trampolines().len() != plan.images().len()
        {
            return Err(SiteError::Correspondence);
        }
        for (image, executable) in plan.images().iter().zip(installed.trampolines()) {
            // SAFETY: whole bundle read authority above.
            unsafe {
                check_image(image, executable)?;
            }
        }
        let finals = plan.plan().final_bytes();
        if finals.len() != 1 || finals[0].address != prep.owner.entry() {
            return Err(SiteError::Correspondence);
        }
        // SAFETY: exact published full owner snapshot.
        unsafe {
            check_source(&mut prep.owner, &finals[0].bytes)?;
        }
        Ok(InstalledIntervalSite {
            site: Arc::clone(&prep.site),
        })
    }
}
fn same_bundle(a: &BundlePlan, b: &BundlePlan) -> bool {
    a.identity() == b.identity()
        && a.originals() == b.originals()
        && a.final_bytes() == b.final_bytes()
        && a.steps() == b.steps()
        && a.locks() == b.locks()
        && a.memory() == b.memory()
}
unsafe fn check_image(
    image: &TrampolineImage,
    executable: &ExecutableTrampoline,
) -> Result<(), SiteError> {
    if executable.address() != image.address()
        || executable.code_len() != image.bytes().len()
        || executable.layout() != image.layout()
        || executable.program_counter_mappings() != image.program_counter_mappings()
    {
        return Err(SiteError::Correspondence);
    }
    // SAFETY: sealed live image and readable complete range supplied by caller.
    if unsafe {
        std::slice::from_raw_parts(image.address() as usize as *const u8, image.bytes().len())
    } != image.bytes()
    {
        return Err(SiteError::Correspondence);
    }
    Ok(())
}
unsafe fn check_source(owner: &mut Owner, expected: &[u8]) -> Result<(), SiteError> {
    owner.verify(true)?;
    if expected.len() != owner.code().len() || owner.terminal() == 0 {
        return Err(SiteError::Correspondence);
    }
    let mut page = owner.original_page().to_vec();
    let offset = usize::try_from(
        owner
            .entry()
            .checked_sub(owner.page())
            .ok_or(Refusal::InvalidRange)?,
    )
    .map_err(|_| Refusal::InvalidRange)?;
    let end = offset
        .checked_add(expected.len())
        .ok_or(Refusal::InvalidRange)?;
    page.get_mut(offset..end)
        .ok_or(Refusal::InvalidRange)?
        .copy_from_slice(expected);
    // SAFETY: full original source-page read authority, including untouched bytes.
    if unsafe { std::slice::from_raw_parts(owner.page() as usize as *const u8, page.len()) } != page
    {
        return Err(SiteError::Correspondence);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn synthetic_site() -> InstalledIntervalSite {
    // Pure state tests only: never a loader/publication or native execution authority.
    InstalledIntervalSite {
        site: Arc::new(Site {
            roles: roles(0x1000, &[0, 18]),
            terminal: 0x2005,
            gate: None,
        }),
    }
}
