//! One retained loader and complete page bundle for the fixed five-role tree.
use super::super::site::ordinary::exclude;
use super::super::site::{base_allocation, check_image, impossible_ordinary_dispatch, same_bundle};
use super::*;
use crate::frontend_native::LoadedCallTree;
use liteinst2::bundle::{BundleBudget, BundleReceipt, InstalledBundle, PlannedBundle};
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    InstallRequest, SearchPolicy, TacticPolicy, plan_coalesced_detailed_after_with_stack_profile,
};
use liteinst2::trampoline::ObservationStackProfile;

pub(super) struct Role {
    pub pc: u64,
    pub control: ProbeControl,
}
pub(super) struct Site {
    pub roles: [Role; 5],
    pub gate: Arc<TreeCallGate>,
    pub root: u64,
    pub child: u64,
}
impl Site {
    pub(super) fn matches(&self, role: RoleKind, pc: u64, control: ControlIdentity<'_>) -> bool {
        let r = &self.roles[role as usize];
        r.pc == pc && r.control.has_identity(control)
    }
}
/// Exact plan and its unique ordinary loader; neither exposes a callable pointer.
pub struct TreeSitePreparation {
    owner: &'static mut LoadedCallTree,
    planned: PlannedBundle,
    site: Arc<Site>,
    _local: PhantomData<Rc<()>>,
}
/// Process-lived executable retention plus one exclusive caller-thread verifier.
pub struct InstalledTreeSite {
    pub(super) site: Arc<Site>,
    pub(super) live: &'static mut Live,
}
pub(super) struct Live {
    prep: TreeSitePreparation,
    installed: InstalledBundle,
    receipt: BundleReceipt,
}
impl Live {
    pub(super) fn verify(&mut self) -> Result<(), SiteError> {
        let prep = &mut self.prep;
        if !prep.site.gate.process_matches()
            || self.installed.is_retired()
            || !same_bundle(self.installed.plan(), prep.planned.plan())
            || !same_bundle(self.receipt.plan(), prep.planned.plan())
            || self.installed.trampolines().len() != 4
            || prep.planned.images().len() != 4
        {
            return Err(SiteError::Correspondence);
        }
        for (image, executable) in prep
            .planned
            .images()
            .iter()
            .zip(self.installed.trampolines())
        {
            if image.layout().observation_stack_profile != ObservationStackProfile::Tree144 {
                return Err(SiteError::Correspondence);
            }
            // SAFETY: private process-lived installed owner and complete seal contract.
            unsafe {
                check_image(image, executable)?;
            }
        }
        let finals = prep.planned.plan().final_bytes();
        let (start, end) = prep.owner.source_range();
        if finals.len() != 1
            || finals[0].address != start
            || finals[0].bytes.len() as u64 != end - start
        {
            return Err(SiteError::Correspondence);
        }
        let offset = |address: u64| {
            usize::try_from(address.checked_sub(start).ok_or(Refusal::InvalidRange)?)
                .map_err(|_| Refusal::InvalidRange)
        };
        let root = offset(prep.site.root)?;
        let child = offset(prep.site.child)?;
        let root_bytes = finals[0]
            .bytes
            .get(root..root.checked_add(23).ok_or(Refusal::InvalidRange)?)
            .ok_or(Refusal::InvalidRange)?;
        let child_bytes = finals[0]
            .bytes
            .get(child..child.checked_add(39).ok_or(Refusal::InvalidRange)?)
            .ok_or(Refusal::InvalidRange)?;
        prep.owner
            .verify_expected_patch(root_bytes, child_bytes)
            .map_err(SiteError::Source)
    }
}

impl TreeSitePreparation {
    pub fn new(
        owner: &'static mut LoadedCallTree,
        gate: Arc<TreeCallGate>,
        identity: CodeIdentity,
    ) -> Result<Self, SiteError> {
        if !timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        owner.verify_original().map_err(SiteError::Source)?;
        let certificate = owner.certificate();
        let root = certificate.root().entry();
        let child = certificate.callee().entry();
        let (source_start, source_end) = owner.source_range();
        let source = AddressRange::new(source_start, owner.original_source().len())?;
        let call = AddressRange::new(root.checked_add(9).ok_or(Refusal::InvalidRange)?, 5)?;
        if identity.mapping != root
            || identity.generation == 0
            || source.len() != 4096
            || source.end() != source_end
            || child != root.checked_add(32).ok_or(Refusal::InvalidRange)?
            || owner.root_code().len() != 23
            || owner.callee_code().len() != 39
            || !source.covers(AddressRange::new(root, 23)?)
            || !source.covers(AddressRange::new(child, 39)?)
            || !gate.process_matches()
            || gate.target() != root
            || gate.declared_returns() != [root + 22]
            || source.contains(gate.continuation())
            || gate.continuation() == 0
        {
            return Err(SiteError::Correspondence);
        }
        let pcs = [root, child, child + 38, root + 14, root + 22];
        let roles = std::array::from_fn(|index| {
            let (control, writer) = ProbeControl::new_managed_bound(CALLBACKS[index], true);
            drop(writer);
            Role {
                pc: pcs[index],
                control,
            }
        });
        let mut predecessor = Composition::new(
            identity,
            vec![ExpectedBytes {
                address: source_start,
                bytes: owner.original_source().to_vec(),
            }],
        )?;
        let mut overlays = [owner.root_code().to_vec(), owner.callee_code().to_vec()];
        let mut full_overlay = owner.original_source().to_vec();
        let mut reserved = vec![source];
        let mut members = Vec::new();
        let groups: [(usize, u64, usize, &[usize]); 4] = [
            (0, root, 9, &[0]),
            (0, root + 14, 9, &[3, 4]),
            (1, child, 8, &[1]),
            (1, child + 25, 14, &[2]),
        ];
        for (index, (function, start, length, role_indices)) in groups.into_iter().enumerate() {
            let (entry, code, heads, legal) = if function == 0 {
                (
                    root,
                    owner.root_code(),
                    certificate.root().heads(),
                    certificate.root().entries(),
                )
            } else {
                (
                    child,
                    owner.callee_code(),
                    certificate.callee().heads(),
                    certificate.callee().entries(),
                )
            };
            let scope = AddressRange::new(entry, code.len())?;
            let block = AddressRange::new(start, length)?;
            let actions: Vec<_> = role_indices
                .iter()
                .map(|&i| ControlledAction {
                    logical_pc: roles[i].pc,
                    control: roles[i].control.clone(),
                })
                .collect();
            let logical = actions[0].logical_pc;
            let entries = LegalEntrySet {
                identity, scope, provenance: EntryProvenance::Declared("fixed two-function tree; original CALL and root+14 saved resume; sole external root entry".into()),
                completeness: EntryCompleteness::Complete,
                entries: legal.iter().map(|&address| LegalEntry { address, requires_endbr: false }).collect(),
                resumes: if function == 0 { ResumeObligation::Enumerated(vec![root + 14]) } else { ResumeObligation::NoneExist },
            };
            let mut allocation = base_allocation(root)?;
            allocation.preferred_address = Some(
                (root & !4095)
                    .checked_add(0x10_0000 + index as u64 * 0x1_0000)
                    .ok_or(Refusal::InvalidRange)?,
            );
            for &prior in &reserved {
                exclude(&mut allocation.ranges, prior)?;
            }
            let member = plan_coalesced_detailed_after_with_stack_profile(
                &InstallRequest {
                    identity,
                    code,
                    base_address: entry,
                    function: scope,
                    block,
                    logical_pc: logical,
                    entries: &entries,
                    hook: impossible_ordinary_dispatch,
                    semantics: HookSemantics::Observe,
                    allocation: &allocation,
                    search: SearchPolicy {
                        tactics: TacticPolicy::RelocationOnly,
                        max_upstream_bytes: if logical == start { 0 } else { 64 },
                        max_displaced_bytes: 80,
                        max_sites: if logical == start { 1 } else { 65 },
                    },
                },
                &actions,
                &predecessor,
                ObservationStackProfile::Tree144,
            )
            .map_err(SiteError::Planning)?;
            let p = member.plan().parts();
            let displaced_end = [root + 9, root + 23, child + 6, child + 39][index];
            if p.kind != PlanKind::Relocation
                || p.profile != ApplicationProfile::InstallOnce
                || p.identity != identity
                || p.entries != entries
                || p.logical_pc != logical
                || p.physical_pc != start
                || p.displaced.end() != displaced_end
                || !block.covers(p.displaced)
                || p.displaced.overlaps(call)
                || p.writes.len() != 1
                || p.writes[0].address != start
                || p.writes[0].bytes.len() as u64 != p.displaced.len()
                || p.reads
                    != [ExpectedBytes {
                        address: entry,
                        bytes: overlays[function].clone(),
                    }]
                || member.image().layout().observation_stack_profile
                    != ObservationStackProfile::Tree144
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
            // Full original-body reads/dependencies deliberately include E8.
            // Only exclusive ownership (displaced, writes, locks) excludes CALL.
            predecessor.append(member.plan())?;
            if predecessor.locks().iter().any(|r| r.overlaps(call)) {
                return Err(SiteError::Correspondence);
            }
            for request in &p.allocations {
                if reserved.iter().any(|r| r.overlaps(request.range)) {
                    return Err(SiteError::Correspondence);
                }
                reserved.push(request.range);
            }
            for edit in &p.writes {
                if AddressRange::new(edit.address, edit.bytes.len())?.overlaps(call) {
                    return Err(SiteError::Correspondence);
                }
                let at = usize::try_from(
                    edit.address
                        .checked_sub(entry)
                        .ok_or(Refusal::InvalidRange)?,
                )
                .map_err(|_| Refusal::InvalidRange)?;
                let end = at
                    .checked_add(edit.bytes.len())
                    .ok_or(Refusal::InvalidRange)?;
                if overlays[function].get(at..end) != code.get(at..end) {
                    return Err(SiteError::Correspondence);
                }
                overlays[function]
                    .get_mut(at..end)
                    .ok_or(Refusal::InvalidRange)?
                    .copy_from_slice(&edit.bytes);
                let at = usize::try_from(
                    edit.address
                        .checked_sub(source_start)
                        .ok_or(Refusal::InvalidRange)?,
                )
                .map_err(|_| Refusal::InvalidRange)?;
                let end = at
                    .checked_add(edit.bytes.len())
                    .ok_or(Refusal::InvalidRange)?;
                full_overlay
                    .get_mut(at..end)
                    .ok_or(Refusal::InvalidRange)?
                    .copy_from_slice(&edit.bytes);
            }
            members.push(member);
        }
        let planned = PlannedBundle::compose(
            vec![ExpectedBytes {
                address: source_start,
                bytes: owner.original_source().to_vec(),
            }],
            members,
            BundleBudget {
                max_steps: 4,
                max_mappings: 4,
                max_virtual_bytes: 4 * 8192,
                max_backing_bytes: 4 * 8192,
                max_virtual_span: 1 << 32,
            },
        )?;
        if planned.images().len() != 4
            || planned.plan().final_bytes() != predecessor.final_bytes()
            || planned.plan().final_bytes()
                != [ExpectedBytes {
                    address: source_start,
                    bytes: full_overlay,
                }]
            || planned
                .images()
                .iter()
                .map(|i| i.controls().len())
                .sum::<usize>()
                != 5
            || overlays[0][9..14] != owner.root_code()[9..14]
        {
            return Err(SiteError::Correspondence);
        }
        owner.verify_original().map_err(SiteError::Source)?;
        Ok(Self {
            owner,
            planned,
            site: Arc::new(Site {
                roles,
                gate,
                root,
                child,
            }),
            _local: PhantomData,
        })
    }
    pub fn plan(&self) -> &PlannedBundle {
        &self.planned
    }
    pub fn role_pcs(&self) -> impl ExactSizeIterator<Item = u64> + '_ {
        self.site.roles.iter().map(|r| r.pc)
    }
    pub fn gate(&self) -> &Arc<TreeCallGate> {
        &self.site.gate
    }
    /// # Safety
    /// Complete original source is unpublished and quiescent until this exclusive
    /// actual-thread guard is invoked/dropped; no fork, alias writer or reentry.
    pub unsafe fn prepare_original_call(
        &mut self,
    ) -> Result<PreparedOriginalTreeCall<'_>, SiteError> {
        let _scope = ControllerScope::enter().map_err(|_| SiteError::Correspondence)?;
        self.owner.verify_original().map_err(SiteError::Source)?;
        let actual = tid();
        if actual == 0 || actual > i32::MAX as u64 {
            return Err(SiteError::Gate(GateError::Identity));
        }
        Ok(PreparedOriginalTreeCall {
            prep: self,
            pid: std::process::id(),
            tid: actual,
            _local: PhantomData,
        })
    }
    /// # Safety
    /// Actual bundle receipt, complete source/generated leases and quiescence,
    /// five mandatory Tree144 roles, original E8/+14, no foreign entry/signal/CET/
    /// fork/unload/nonlocal exit and full writable callback stack remain valid.
    pub unsafe fn seal(
        self,
        installed: InstalledBundle,
        receipt: BundleReceipt,
    ) -> Result<InstalledTreeSite, SiteError> {
        let live = Box::leak(Box::new(Live {
            prep: self,
            installed,
            receipt,
        }));
        live.verify()?;
        Ok(InstalledTreeSite {
            site: Arc::clone(&live.prep.site),
            live,
        })
    }
}
/// Exclusive !Send/!Sync original-only guard; no second invocation or publication.
pub struct PreparedOriginalTreeCall<'a> {
    prep: &'a mut TreeSitePreparation,
    pid: u32,
    tid: u64,
    _local: PhantomData<Rc<()>>,
}
impl PreparedOriginalTreeCall<'_> {
    /// # Safety
    /// Same actual thread, admitted valid immutable1024-byte offset-linked input,
    /// writable bounded stack and normal CALL/RET; all preparation contracts hold.
    pub unsafe fn invoke(
        self,
        bytes: &[u8],
        stack: &ReadableStack,
    ) -> Result<OriginalTreeCallResult, SiteError> {
        let before = input_copy(bytes).map_err(|_| SiteError::Gate(GateError::Descriptor))?;
        let pending = if self.pid != std::process::id() || self.tid != tid() {
            Err(GateError::Identity)
        } else {
            unsafe { self.prep.site.gate.invoke_original(bytes, stack) }
        };
        // Keep the original scope alive through validation and commit. A scope
        // refusal still permits the safe input check and cannot replace a gate error.
        let scope = ControllerScope::enter();
        let pending = postflight::check(
            pending.map_err(SiteError::Gate),
            || {
                let _scope = scope.as_ref().map_err(|_| SiteError::Correspondence)?;
                self.prep.owner.verify_original().map_err(SiteError::Source)
            },
            || {
                if bytes == before {
                    Ok(())
                } else {
                    Err(SiteError::Correspondence)
                }
            },
        )?;
        Ok(pending.validate().map_err(SiteError::Gate)?.commit())
    }
}
