//! Original-CALL-safe preparation for the distinct normal call-pair runtime.
use super::super::{SiteError, base_allocation, impossible_ordinary_dispatch};
use super::normal_module::{check_publication, module_budget, projection, replace_projection};
use super::{exclude, groups};
use crate::frontend_native::{
    IntegerLeafCertificate, LoadedNormalCallPair, NormalCallPairEdge,
    NormalCallPairParentCertificate,
};
use liteinst2::bundle::{BundleReceipt, InstalledBundle, PlannedBundle};
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::controls::{ControlIdentity, ControlledAction, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    InstallRequest, SearchPolicy, TacticPolicy, plan_coalesced_detailed_after_with_stack_profile,
};
use liteinst2::trampoline::{ObservationStackProfile, SavedExtendedStateLayout};
use std::sync::Arc;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalCallPairRoleKind {
    ParentEntry,
    ChildEntry,
    ChildRet,
    ChildAck,
    ParentRet,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalCallPairRole {
    pub kind: NormalCallPairRoleKind,
    pub pc: u64,
}
pub struct NormalCallPairFunctionSite {
    entry: u64,
    end: u64,
    returns: Vec<u64>,
}
impl NormalCallPairFunctionSite {
    pub fn entry(&self) -> u64 {
        self.entry
    }
    pub fn range(&self) -> (u64, u64) {
        (self.entry, self.end)
    }
    pub fn returns(&self) -> &[u64] {
        &self.returns
    }
}
struct Role {
    metadata: NormalCallPairRole,
    control: ProbeControl,
}
pub(in crate::frontend_native::always_on) struct CallPairSite {
    identity: CodeIdentity,
    functions: [NormalCallPairFunctionSite; 2],
    edge: NormalCallPairEdge,
    child_delta: u64,
    call_rsp: i32,
    roles: Vec<Role>,
    layout: SavedExtendedStateLayout,
    stack_profile: ObservationStackProfile,
}
impl CallPairSite {
    pub(in crate::frontend_native::always_on) fn identity(&self) -> CodeIdentity {
        self.identity
    }
    pub(in crate::frontend_native::always_on) fn functions(
        &self,
    ) -> &[NormalCallPairFunctionSite; 2] {
        &self.functions
    }
    pub(in crate::frontend_native::always_on) fn edge(&self) -> NormalCallPairEdge {
        self.edge
    }
    // Private sealed metadata/identity seam for the distinct CallPair runtime.
    // Metadata controls do not fabricate an opaque callback token or attachment.
    pub(in crate::frontend_native::always_on) fn child_stack_delta(&self) -> u64 {
        self.child_delta
    }
    pub(in crate::frontend_native::always_on) fn call_rsp_offset(&self) -> i32 {
        self.call_rsp
    }
    pub(in crate::frontend_native::always_on) fn resolve(
        &self,
        pc: u64,
        control: ControlIdentity<'_>,
        kind: NormalCallPairRoleKind,
    ) -> bool {
        self.role_at(pc, kind)
            .is_some_and(|r| r.control.has_identity(control))
    }
    pub(in crate::frontend_native::always_on) fn layout(&self) -> SavedExtendedStateLayout {
        self.layout
    }
    pub(in crate::frontend_native::always_on) fn stack_profile(&self) -> ObservationStackProfile {
        self.stack_profile
    }
    fn role_at(&self, pc: u64, kind: NormalCallPairRoleKind) -> Option<&Role> {
        self.roles
            .iter()
            .find(|r| r.metadata.pc == pc && r.metadata.kind == kind)
    }
    fn roles(&self) -> impl ExactSizeIterator<Item = NormalCallPairRole> + '_ {
        self.roles.iter().map(|r| r.metadata)
    }
}
// Original planner controls retain their inert callback without exposing a runtime route.
#[cfg(test)]
unsafe extern "C" fn unavailable<'a>(
    _: *mut liteinst2::trampoline::HookContext,
    _: ControlIdentity<'a>,
) {
    unsafe { libc::_exit(123) }
}
pub struct NormalCallPairSitePreparation {
    owner: &'static mut LoadedNormalCallPair,
    planned: PlannedBundle,
    site: Arc<CallPairSite>,
}
pub struct InstalledNormalCallPairSite {
    pub(in crate::frontend_native::always_on) site: Arc<CallPairSite>,
}
impl InstalledNormalCallPairSite {
    pub fn identity(&self) -> CodeIdentity {
        self.site.identity()
    }
    pub fn functions(&self) -> &[NormalCallPairFunctionSite; 2] {
        self.site.functions()
    }
    pub fn edge(&self) -> NormalCallPairEdge {
        self.site.edge()
    }
    pub fn roles(&self) -> impl ExactSizeIterator<Item = NormalCallPairRole> + '_ {
        self.site.roles()
    }
}
impl NormalCallPairSitePreparation {
    /// Plan complete parent-before/after-CALL regions and child certified blocks.
    /// Planning grants no attachment, physical fit or native-state authority.
    pub fn new(
        owner: &'static mut LoadedNormalCallPair,
        identity: CodeIdentity,
    ) -> Result<Self, SiteError> {
        if !super::super::super::timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        owner.verify_original().map_err(SiteError::Source)?;
        let (planned, site) = prepare(
            owner.parent().code(),
            owner.parent().certificate(),
            owner.child().code(),
            owner.child().certificate(),
            owner.source_pages(),
            identity,
        )?;
        owner.verify_original().map_err(SiteError::Source)?;
        Ok(Self {
            owner,
            planned,
            site,
        })
    }
    pub fn plan(&self) -> &PlannedBundle {
        &self.planned
    }
    pub fn identity(&self) -> CodeIdentity {
        self.site.identity()
    }
    pub fn functions(&self) -> &[NormalCallPairFunctionSite; 2] {
        self.site.functions()
    }
    pub fn edge(&self) -> NormalCallPairEdge {
        self.site.edge()
    }
    pub fn roles(&self) -> impl ExactSizeIterator<Item = NormalCallPairRole> + '_ {
        self.site.roles()
    }
    /// Retain all actual publication owners before any fallible correspondence check.
    ///
    /// # Safety
    /// The complete real successful bundle/receipt, full source and generated RX
    /// leases, quiescence, no-fork/no-writer/no-unload and no-CET contracts hold.
    /// The original CALL and its saved continuation remain at their admitted PCs.
    /// CallPair240 reserves 240 bytes with context prefix 416; it is storage
    /// geometry, not writable callback/XSAVE or state-preservation evidence.
    /// No entry/resume may execute without the distinct unsafe CallPair
    /// attachment and its full writable callback/XSAVE stack contract.
    /// Metadata drain never grants code drain.
    pub unsafe fn seal(
        self,
        installed: InstalledBundle,
        receipt: BundleReceipt,
    ) -> Result<InstalledNormalCallPairSite, SiteError> {
        let (prep, installed, receipt) = Box::leak(Box::new((self, installed, receipt)));
        // SAFETY: all genuine owners remain retained even if a check refuses.
        unsafe {
            check_publication(&prep.planned, installed, receipt, prep.site.identity)?;
        }
        if prep.planned.images().iter().any(|image| {
            image.layout().observation_stack_profile != ObservationStackProfile::CallPair240
                || image.layout().observation_stack_profile != prep.site.stack_profile
                || image.layout().saved_extended_state != prep.site.layout
        }) {
            return Err(SiteError::Correspondence);
        }
        prep.owner
            .verify_expected_pages(prep.planned.plan().final_bytes())
            .map_err(SiteError::Source)?;
        Ok(InstalledNormalCallPairSite {
            site: Arc::clone(&prep.site),
        })
    }
}
fn call_excluded(
    call: AddressRange,
    p: &PlanParts,
    locks: &[AddressRange],
) -> Result<(), SiteError> {
    if p.displaced.overlaps(call) || locks.iter().any(|r| r.overlaps(call)) {
        return Err(SiteError::Correspondence);
    }
    for edit in &p.writes {
        if AddressRange::new(edit.address, edit.bytes.len())?.overlaps(call) {
            return Err(SiteError::Correspondence);
        }
    }
    Ok(())
}
struct Region {
    function: usize,
    block: AddressRange,
    roles: Vec<usize>,
}
fn regions(
    parent: &NormalCallPairParentCertificate,
    child: &IntegerLeafCertificate,
) -> Result<Vec<Region>, SiteError> {
    let call = parent.call();
    let before = AddressRange::new(
        parent.entry(),
        usize::try_from(
            call.call_pc()
                .checked_sub(parent.entry())
                .ok_or(Refusal::InvalidRange)?,
        )
        .map_err(|_| Refusal::InvalidRange)?,
    )?;
    let after = AddressRange::new(
        call.continuation(),
        usize::try_from(
            parent
                .range()
                .1
                .checked_sub(call.continuation())
                .ok_or(Refusal::InvalidRange)?,
        )
        .map_err(|_| Refusal::InvalidRange)?,
    )?;
    if before.len() < 5 || after.len() < 5 {
        return Err(SiteError::Core(Refusal::NoPatchWindow));
    }
    if parent.blocks() != [(before.start(), before.end()), (after.start(), after.end())]
        || parent.returns() != [after.end() - 1]
        || !parent.heads().contains(&call.continuation())
    {
        return Err(SiteError::Correspondence);
    }
    let ack = 2 + child.returns().len();
    let mut result = vec![
        Region {
            function: 0,
            block: before,
            roles: vec![0],
        },
        Region {
            function: 0,
            block: after,
            roles: vec![ack, ack + 1],
        },
    ];
    for group in groups(
        child.entry(),
        child.returns(),
        child.blocks(),
        child.edges(),
    )? {
        result.push(Region {
            function: 1,
            block: group.block,
            roles: group.roles.iter().map(|i| i + 1).collect(),
        });
    }
    Ok(result)
}
fn source_pages(originals: &[ExpectedBytes], scopes: &[AddressRange; 2]) -> Result<(), SiteError> {
    let mut wanted = Vec::new();
    for scope in scopes {
        let mut page = scope.start() & !4095;
        loop {
            let end = page.checked_add(4096).ok_or(Refusal::InvalidRange)?;
            if !wanted.contains(&page) {
                wanted.push(page);
            }
            if end >= scope.end() {
                break;
            }
            page = end;
        }
    }
    wanted.sort_unstable();
    if !(1..=2).contains(&wanted.len())
        || originals.len() != wanted.len()
        || originals
            .iter()
            .zip(wanted)
            .any(|(page, at)| page.address != at || page.bytes.len() != 4096)
    {
        return Err(SiteError::Correspondence);
    }
    Ok(())
}
fn prepare(
    pcode: &[u8],
    parent: &NormalCallPairParentCertificate,
    ccode: &[u8],
    child: &IntegerLeafCertificate,
    originals: &[ExpectedBytes],
    identity: CodeIdentity,
) -> Result<(PlannedBundle, Arc<CallPairSite>), SiteError> {
    let scopes = [
        AddressRange::new(parent.entry(), pcode.len())?,
        AddressRange::new(child.entry(), ccode.len())?,
    ];
    let edge = parent.call();
    let call = AddressRange::new(edge.call_pc(), 5)?;
    if identity.mapping != parent.entry()
        || identity.generation == 0
        || scopes[0].overlaps(scopes[1])
        || !(5..=80).contains(&pcode.len())
        || !(1..=256).contains(&ccode.len())
        || parent.range() != (scopes[0].start(), scopes[0].end())
        || child.range() != (scopes[1].start(), scopes[1].end())
        || edge.callee_entry() != child.entry()
        || call.end() != edge.continuation()
        || !scopes[0].covers(call)
    {
        return Err(SiteError::Correspondence);
    }
    source_pages(originals, &scopes)?;
    if projection(originals, parent.entry(), pcode.len())? != pcode
        || projection(originals, child.entry(), ccode.len())? != ccode
    {
        return Err(SiteError::Correspondence);
    }
    let group_list = regions(parent, child)?;
    use NormalCallPairRoleKind::*;
    let metadata: Vec<_> = std::iter::once((ParentEntry, parent.entry()))
        .chain(std::iter::once((ChildEntry, child.entry())))
        .chain(child.returns().iter().map(|&pc| (ChildRet, pc)))
        .chain([
            (ChildAck, edge.continuation()),
            (ParentRet, parent.returns()[0]),
        ])
        .map(|(kind, pc)| NormalCallPairRole { kind, pc })
        .collect();
    let roles: Vec<_> = metadata
        .iter()
        .map(|&metadata| {
            let (control, writer) = ProbeControl::new_managed_bound(
                super::super::super::normal::call_pair::callback_for(metadata.kind),
                true,
            );
            drop(writer); // No operation can disable a mandatory role.
            Role { metadata, control }
        })
        .collect();
    let mut seen = vec![0usize; roles.len()];
    let mut predecessor = Composition::new(identity, originals.to_vec())?;
    let mut union = originals.to_vec();
    let mut overlays = [pcode.to_vec(), ccode.to_vec()];
    let mut reserved = originals
        .iter()
        .map(|p| AddressRange::new(p.address, p.bytes.len()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut members = Vec::new();
    let mut ordered_controls = Vec::new();
    for (ordinal, group) in group_list.iter().enumerate() {
        let f = group.function;
        let (code, heads, legal) = if f == 0 {
            (pcode, parent.heads(), parent.entries())
        } else {
            (ccode, child.heads(), child.entries())
        };
        let scope = scopes[f];
        let actions = group
            .roles
            .iter()
            .map(|&i| {
                let role = roles.get(i).ok_or(SiteError::Correspondence)?;
                seen[i] += 1;
                if !heads.contains(&role.metadata.pc) || !group.block.contains(role.metadata.pc) {
                    return Err(SiteError::Correspondence);
                }
                Ok(ControlledAction {
                    logical_pc: role.metadata.pc,
                    control: role.control.clone(),
                })
            })
            .collect::<Result<Vec<_>, SiteError>>()?;
        let logical = actions.first().ok_or(SiteError::Correspondence)?.logical_pc;
        let entries = LegalEntrySet {
            identity, scope, provenance: EntryProvenance::Declared("complete selected normal parent/child; sole external parent and exact original E8 continuation".into()),
            completeness: EntryCompleteness::Complete,
            entries: legal.iter().map(|&address| LegalEntry { address, requires_endbr: false }).collect(),
            resumes: if f == 0 { ResumeObligation::Enumerated(vec![edge.continuation()]) } else { ResumeObligation::NoneExist },
        };
        let mut allocation = base_allocation(scope.start())?;
        allocation.preferred_address = Some(
            (scope.start() & !4095)
                .checked_add(0x10_0000 + ordinal as u64 * 0x1_0000)
                .ok_or(Refusal::InvalidRange)?,
        );
        for &range in &reserved {
            exclude(&mut allocation.ranges, range)?;
        }
        let member = plan_coalesced_detailed_after_with_stack_profile(
            &InstallRequest {
                identity,
                code,
                base_address: scope.start(),
                function: scope,
                block: group.block,
                logical_pc: logical,
                entries: &entries,
                hook: impossible_ordinary_dispatch,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: if logical == group.block.start() {
                        0
                    } else {
                        64
                    },
                    max_displaced_bytes: 80,
                    max_sites: if logical == group.block.start() {
                        1
                    } else {
                        65
                    },
                },
            },
            &actions,
            &predecessor,
            ObservationStackProfile::CallPair240,
        )
        .map_err(SiteError::Planning)?;
        let p = member.plan().parts();
        if p.kind != PlanKind::Relocation
            || p.profile != ApplicationProfile::InstallOnce
            || p.identity != identity
            || p.entries != entries
            || p.logical_pc != logical
            || !group.block.covers(p.displaced)
            || p.physical_pc != p.displaced.start()
            || p.writes.len() != 1
            || p.writes[0].address != p.physical_pc
            || p.writes[0].bytes.len() as u64 != p.displaced.len()
            || p.reads
                != [ExpectedBytes {
                    address: scope.start(),
                    bytes: overlays[f].clone(),
                }]
            || member.image().layout().observation_stack_profile
                != ObservationStackProfile::CallPair240
            || member.image().controls()
                != actions
                    .iter()
                    .map(|a| a.control.clone())
                    .collect::<Vec<_>>()
            || member
                .image()
                .instruction_boundaries()
                .iter()
                .map(|&(pc, _)| pc)
                .collect::<Vec<_>>()
                != heads
                    .iter()
                    .copied()
                    .filter(|&pc| p.displaced.contains(pc))
                    .collect::<Vec<_>>()
            || actions.iter().any(|a| !p.displaced.contains(a.logical_pc))
        {
            return Err(SiteError::Correspondence);
        }
        call_excluded(call, p, &[])?;
        predecessor.append(member.plan())?;
        call_excluded(call, p, predecessor.locks())?;
        for allocation in &p.allocations {
            if reserved.iter().any(|r| r.overlaps(allocation.range)) {
                return Err(SiteError::Correspondence);
            }
            reserved.push(allocation.range);
        }
        for edit in &p.writes {
            let at = usize::try_from(
                edit.address
                    .checked_sub(scope.start())
                    .ok_or(Refusal::InvalidRange)?,
            )
            .map_err(|_| Refusal::InvalidRange)?;
            let end = at
                .checked_add(edit.bytes.len())
                .ok_or(Refusal::InvalidRange)?;
            if overlays[f].get(at..end) != code.get(at..end) {
                return Err(SiteError::Correspondence);
            }
            overlays[f]
                .get_mut(at..end)
                .ok_or(Refusal::InvalidRange)?
                .copy_from_slice(&edit.bytes);
            replace_projection(&mut union, edit.address, &edit.bytes)?;
        }
        ordered_controls.extend(actions.into_iter().map(|a| a.control));
        members.push(member);
    }
    let planned = PlannedBundle::compose(originals.to_vec(), members, module_budget())?;
    if seen.iter().any(|&n| n != 1)
        || planned.images().len() != group_list.len()
        || planned.plan().final_bytes() != predecessor.final_bytes()
        || planned.plan().final_bytes() != union
        || planned
            .images()
            .iter()
            .flat_map(|i| i.controls())
            .collect::<Vec<_>>()
            != ordered_controls.iter().collect::<Vec<_>>()
        || projection(&union, edge.call_pc(), 5)? != projection(originals, edge.call_pc(), 5)?
    {
        return Err(SiteError::Correspondence);
    }
    let image_layout = planned
        .images()
        .first()
        .ok_or(SiteError::Correspondence)?
        .layout();
    let layout = image_layout.saved_extended_state;
    let stack_profile = image_layout.observation_stack_profile;
    if layout.is_empty()
        || stack_profile != ObservationStackProfile::CallPair240
        || planned.images().iter().any(|image| {
            image.layout().saved_extended_state != layout
                || image.layout().observation_stack_profile != stack_profile
        })
    {
        return Err(SiteError::Correspondence);
    }
    let functions = [
        NormalCallPairFunctionSite {
            entry: parent.entry(),
            end: parent.range().1,
            returns: parent.returns().to_vec(),
        },
        NormalCallPairFunctionSite {
            entry: child.entry(),
            end: child.range().1,
            returns: child.returns().to_vec(),
        },
    ];
    Ok((
        planned,
        Arc::new(CallPairSite {
            identity,
            functions,
            edge,
            child_delta: parent.child_stack_delta(),
            call_rsp: parent.call_rsp_offset(),
            roles,
            layout,
            stack_profile,
        }),
    ))
}

#[cfg(test)]
impl CallPairSite {
    pub(in crate::frontend_native::always_on) fn synthetic(
        parent: NormalCallPairParentCertificate,
        child: IntegerLeafCertificate,
        identity: CodeIdentity,
        layout: SavedExtendedStateLayout,
    ) -> Arc<Self> {
        use NormalCallPairRoleKind::*;
        let metadata = std::iter::once((ParentEntry, parent.entry()))
            .chain(std::iter::once((ChildEntry, child.entry())))
            .chain(child.returns().iter().map(|&pc| (ChildRet, pc)))
            .chain([
                (ChildAck, parent.call().continuation()),
                (ParentRet, parent.returns()[0]),
            ]);
        let roles = metadata
            .map(|(kind, pc)| {
                let (control, writer) = ProbeControl::new_managed_bound(
                    super::super::super::normal::call_pair::callback_for(kind),
                    true,
                );
                drop(writer);
                Role {
                    metadata: NormalCallPairRole { kind, pc },
                    control,
                }
            })
            .collect();
        Arc::new(Self {
            identity,
            functions: [
                NormalCallPairFunctionSite {
                    entry: parent.entry(),
                    end: parent.range().1,
                    returns: parent.returns().to_vec(),
                },
                NormalCallPairFunctionSite {
                    entry: child.entry(),
                    end: child.range().1,
                    returns: child.returns().to_vec(),
                },
            ],
            edge: parent.call(),
            child_delta: parent.child_stack_delta(),
            call_rsp: parent.call_rsp_offset(),
            roles,
            layout,
            stack_profile: ObservationStackProfile::CallPair240,
        })
    }
    pub(in crate::frontend_native::always_on) fn control_for(
        &self,
        pc: u64,
        kind: NormalCallPairRoleKind,
    ) -> Option<&ProbeControl> {
        self.role_at(pc, kind).map(|r| &r.control)
    }
    // Exact role lookup reused, but ProbeControl equality is metadata only. This
    // does not mint or exercise the dispatcher's opaque ControlIdentity token.
    pub(in crate::frontend_native::always_on) fn resolve_control(
        &self,
        pc: u64,
        kind: NormalCallPairRoleKind,
        control: &ProbeControl,
    ) -> bool {
        self.role_at(pc, kind)
            .is_some_and(|r| &r.control == control)
    }
}
