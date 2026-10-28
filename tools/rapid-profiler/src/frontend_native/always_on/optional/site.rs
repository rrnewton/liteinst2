//! Complete ordinary source/publication factory; no mutable callback controls escape.
use super::super::site::ordinary::{exclude, groups};
use super::super::site::{
    SiteError, base_allocation, check_image, impossible_ordinary_dispatch, same_bundle,
};
use super::super::{GateError, OriginalCallResult, ReadableStack, timing};
use super::{OptionalCallGate, entry_callback, exit_callback};
use crate::frontend_native::LoadedIntegerLeaf;
use liteinst2::bundle::{BundleBudget, BundleReceipt, InstalledBundle, PlannedBundle};
use liteinst2::composition::Composition;
use liteinst2::contracts::*;
use liteinst2::controls::ControlIdentity;
use liteinst2::planner::HookSemantics;
use liteinst2::precontext::{
    PreContextAction, PreContextRole, PreContextSelector, PreContextWriter,
};
use liteinst2::quiescent::{
    InstallRequest, SearchPolicy, TacticPolicy, plan_precontext_coalesced_detailed_after,
};
use liteinst2::trampoline::TrampolineImage;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;

pub(super) struct Site {
    pub(super) roles: Vec<PreContextAction>,
    pub(super) gate: Arc<OptionalCallGate>,
    pub(super) selector: PreContextSelector,
}
impl Site {
    pub(super) fn matches(&self, pc: u64, id: ControlIdentity<'_>, entry: bool) -> bool {
        self.roles.iter().any(|a| {
            a.logical_pc() == pc
                && a.control().has_identity(id)
                && a.role()
                    == if entry {
                        PreContextRole::Entry
                    } else {
                        PreContextRole::Return
                    }
        })
    }
}
/// Consuming authority, not a Clone selector writer or a retire/unload handle.
pub struct InstalledOptionalSite {
    pub(super) site: Arc<Site>,
    pub(super) writer: PreContextWriter,
}
pub struct OptionalSitePreparation {
    owner: &'static mut LoadedIntegerLeaf,
    planned: PlannedBundle,
    site: Arc<Site>,
    writer: Option<PreContextWriter>,
}
/// One-shot exclusive original call; dropping it neither invokes nor arms anything.
/// The preparation stays exclusively borrowed until this guard is consumed/dropped:
/// ```compile_fail,E0502
/// use rapid_profiler::frontend_native::OptionalSitePreparation;
/// fn inspect(prep: &mut OptionalSitePreparation) {
///     let call = unsafe { prep.prepare_original_call() }.unwrap();
///     let _ = prep.plan();
///     drop(call);
/// }
/// ```
pub struct PreparedOptionalOriginalCall<'a> {
    preparation: &'a mut OptionalSitePreparation,
    pid: u32,
    tid: libc::c_long,
    _local: PhantomData<Rc<()>>,
}
impl PreparedOptionalOriginalCall<'_> {
    /// # Safety
    /// Same thread; complete no-writer/no-fork/no-reentry/source lifetime contract
    /// has held since preparation. Input, stack, normal-return and no-CET obligations
    /// hold through the real original CALL. No callback or publication is installed.
    pub unsafe fn invoke(
        self,
        data: *const u8,
        len: usize,
        stack: &ReadableStack,
    ) -> Result<OriginalCallResult, SiteError> {
        let result = if self.pid != std::process::id() {
            Err(GateError::Process)
        } else if self.tid != unsafe { libc::syscall(libc::SYS_gettid) } {
            Err(GateError::Identity)
        } else {
            unsafe { self.preparation.site.gate.invoke_original(data, len, stack) }
        };
        self.preparation
            .owner
            .verify_original()
            .map_err(SiteError::Source)?;
        result.map_err(SiteError::Gate)
    }
}
fn image_roles(
    image: &TrampolineImage,
    actions: &[PreContextAction],
    selector: &PreContextSelector,
) -> bool {
    image.precontext_selector() == Some(selector)
        && image.controls()
            == actions
                .iter()
                .map(|a| a.control().clone())
                .collect::<Vec<_>>()
        && image
            .precontext_gates()
            .iter()
            .map(|g| (g.logical_pc, g.role))
            .collect::<Vec<_>>()
            == actions
                .iter()
                .map(|a| (a.logical_pc(), a.role()))
                .collect::<Vec<_>>()
}
impl OptionalSitePreparation {
    /// Full certified scalar symbol, entry and every C3; same bounded relocation
    /// windows/allocation policy as mandatory ordinary planning. No mixed actions.
    pub fn new(
        owner: &'static mut LoadedIntegerLeaf,
        identity: CodeIdentity,
    ) -> Result<Self, SiteError> {
        if !timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        owner.verify_original().map_err(SiteError::Source)?;
        let gate = OptionalCallGate::new(owner.certificate()).map_err(SiteError::Gate)?;
        let entry = owner.entry();
        let certificate = owner.certificate();
        let scope = AddressRange::new(entry, owner.code().len())?;
        let (source_start, source_end) = owner.source_range();
        let source = AddressRange::new(source_start, owner.original_source().len())?;
        if identity.mapping != entry
            || identity.generation == 0
            || certificate.entry() != entry
            || certificate.range() != (entry, scope.end())
            || !(1..=256).contains(&owner.code().len())
            || source.end() != source_end
            || !source.covers(scope)
            || !matches!(source.len(), 4096 | 8192)
            || !gate.process_matches()
            || gate.target() != entry
            || gate.returns() != certificate.returns()
            || gate.continuation() == 0
            || source.contains(gate.continuation())
        {
            return Err(SiteError::Correspondence);
        }
        let groups = groups(
            entry,
            certificate.returns(),
            certificate.blocks(),
            certificate.edges(),
        )?;
        let pcs: Vec<_> = std::iter::once(entry)
            .chain(certificate.returns().iter().copied())
            .collect();
        if pcs
            .iter()
            .any(|pc| !certificate.heads().contains(pc) || certificate.padding_heads().contains(pc))
            || certificate
                .blocks()
                .iter()
                .any(|&(a, b)| a < scope.start() || b > scope.end())
        {
            return Err(SiteError::Correspondence);
        }
        let (selector, writer) = PreContextSelector::new(false);
        let roles: Vec<_> = pcs
            .iter()
            .enumerate()
            .map(|(i, &pc)| {
                PreContextAction::new(
                    pc,
                    if i == 0 {
                        PreContextRole::Entry
                    } else {
                        PreContextRole::Return
                    },
                    &selector,
                    if i == 0 {
                        entry_callback
                    } else {
                        exit_callback
                    },
                )
            })
            .collect();
        let entries=LegalEntrySet{identity,scope,provenance:EntryProvenance::Declared(
            "complete scalar CFG and unsafe sole external entry/no saved resume; private scratch gate and preserving callbacks".into()),
            completeness:EntryCompleteness::Complete,
            entries:certificate.entries().iter().map(|&address|LegalEntry{address,requires_endbr:false}).collect(),resumes:ResumeObligation::NoneExist};
        let mut predecessor = Composition::new(
            identity,
            vec![ExpectedBytes {
                address: source_start,
                bytes: owner.original_source().to_vec(),
            }],
        )?;
        let mut overlay = owner.code().to_vec();
        let mut full_overlay = owner.original_source().to_vec();
        let mut reserved = vec![source];
        let mut members = Vec::new();
        for (index, group) in groups.iter().enumerate() {
            let actions: Vec<_> = group.roles.iter().map(|&i| roles[i].clone()).collect();
            let logical = actions[0].logical_pc();
            let mut allocation = base_allocation(entry)?;
            allocation.preferred_address = Some(
                (entry & !4095)
                    .checked_add(0x10_0000 + index as u64 * 0x1_0000)
                    .ok_or(Refusal::InvalidRange)?,
            );
            for &range in &reserved {
                exclude(&mut allocation.ranges, range)?;
            }
            // SAFETY: complete RBX-free ordinary certificate, sole external entry,
            // all RET roles, private scratch-first CALL frame and these preserving
            // callbacks form this separate profile. Execution obligations remain unsafe.
            let member = unsafe {
                plan_precontext_coalesced_detailed_after(
                    &InstallRequest {
                        identity,
                        code: owner.code(),
                        base_address: entry,
                        function: scope,
                        block: group.block,
                        logical_pc: logical,
                        entries: &entries,
                        hook: impossible_ordinary_dispatch,
                        semantics: HookSemantics::Observe,
                        allocation: &allocation,
                        search: SearchPolicy {
                            tactics: TacticPolicy::RelocationOnly,
                            max_upstream_bytes: if logical == entry { 0 } else { 64 },
                            max_displaced_bytes: 80,
                            max_sites: if logical == entry { 1 } else { 65 },
                        },
                    },
                    &actions,
                    &predecessor,
                )
            }
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
                        address: entry,
                        bytes: overlay.clone(),
                    }]
                || !image_roles(member.image(), &actions, &selector)
                || member
                    .image()
                    .instruction_boundaries()
                    .iter()
                    .map(|&(pc, _)| pc)
                    .collect::<Vec<_>>()
                    != certificate
                        .heads()
                        .iter()
                        .copied()
                        .filter(|&pc| p.displaced.contains(pc))
                        .collect::<Vec<_>>()
                || actions
                    .iter()
                    .any(|a| !p.displaced.contains(a.logical_pc()))
            {
                return Err(SiteError::Correspondence);
            }
            predecessor.append(member.plan())?;
            for request in &p.allocations {
                if reserved.iter().any(|r| r.overlaps(request.range)) {
                    return Err(SiteError::Correspondence);
                }
                reserved.push(request.range);
            }
            for edit in &p.writes {
                let at = usize::try_from(
                    edit.address
                        .checked_sub(entry)
                        .ok_or(Refusal::InvalidRange)?,
                )
                .map_err(|_| Refusal::InvalidRange)?;
                let end = at
                    .checked_add(edit.bytes.len())
                    .ok_or(Refusal::InvalidRange)?;
                if overlay.get(at..end) != owner.code().get(at..end) {
                    return Err(SiteError::Correspondence);
                }
                overlay
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
                max_steps: 5,
                max_mappings: 5,
                max_virtual_bytes: 5 * 8192,
                max_backing_bytes: 5 * 8192,
                max_virtual_span: 1 << 32,
            },
        )?;
        if planned.images().len() != groups.len()
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
                != roles.len()
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
                selector,
            }),
            writer: Some(writer),
        })
    }
    pub fn plan(&self) -> &PlannedBundle {
        &self.planned
    }
    pub fn gate(&self) -> &Arc<OptionalCallGate> {
        &self.site.gate
    }
    pub fn role_pcs(&self) -> impl ExactSizeIterator<Item = u64> + '_ {
        self.site.roles.iter().map(PreContextAction::logical_pc)
    }
    /// # Safety
    /// Complete original source/sole caller contract; no publication, fork, alias
    /// writer, unload, asynchronous handler/nonlocal exit or reentry until invoke/drop.
    /// A tracer-owned stop without a handler or source mutation is allowed. Actual
    /// invocation still forbids signals and requires valid ABI/input/stack/return.
    pub unsafe fn prepare_original_call(
        &mut self,
    ) -> Result<PreparedOptionalOriginalCall<'_>, SiteError> {
        self.owner.verify_original().map_err(SiteError::Source)?;
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        if tid <= 0 || tid > libc::c_long::from(i32::MAX) {
            return Err(SiteError::Gate(GateError::Identity));
        }
        Ok(PreparedOptionalOriginalCall {
            preparation: self,
            pid: std::process::id(),
            tid,
            _local: PhantomData,
        })
    }
    /// # Safety
    /// Same whole contract as prepare_original_call and its one-shot invoke.
    pub unsafe fn invoke_original(
        &mut self,
        data: *const u8,
        len: usize,
        stack: &ReadableStack,
    ) -> Result<OriginalCallResult, SiteError> {
        unsafe { self.prepare_original_call()?.invoke(data, len, stack) }
    }
    /// # Safety
    /// Genuine full bundle publication/receipt, complete readable source/images,
    /// entry/resume closure, no CET/signal/fork/unload/alias mutation or active call.
    /// Retain input and writable callback stack through actual return. Only this
    /// optional gate and attached preserving callbacks may execute the installation.
    pub unsafe fn seal(
        self,
        installed: InstalledBundle,
        receipt: BundleReceipt,
    ) -> Result<InstalledOptionalSite, SiteError> {
        // Process-lived retention applies even when a correspondence check refuses.
        let (p, installed, receipt) = Box::leak(Box::new((self, installed, receipt)));
        if !timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        if !p.site.gate.process_matches()
            || p.site.gate.target() != p.owner.entry()
            || p.site.gate.returns() != p.owner.certificate().returns()
            || p.site.selector.is_enabled()
            || installed.is_retired()
            || !same_bundle(installed.plan(), p.planned.plan())
            || !same_bundle(receipt.plan(), p.planned.plan())
            || installed.trampolines().len() != p.planned.images().len()
        {
            return Err(SiteError::Correspondence);
        }
        for (image, executable) in p.planned.images().iter().zip(installed.trampolines()) {
            if image.precontext_selector() != Some(&p.site.selector) {
                return Err(SiteError::Correspondence);
            }
            unsafe {
                check_image(image, executable)?;
            }
        }
        let finals = p.planned.plan().final_bytes();
        let (start, end) = p.owner.source_range();
        if finals.len() != 1
            || finals[0].address != start
            || finals[0].bytes.len() as u64 != end - start
        {
            return Err(SiteError::Correspondence);
        }
        let at = usize::try_from(
            p.owner
                .entry()
                .checked_sub(start)
                .ok_or(Refusal::InvalidRange)?,
        )
        .map_err(|_| Refusal::InvalidRange)?;
        let end = at
            .checked_add(p.owner.code().len())
            .ok_or(Refusal::InvalidRange)?;
        p.owner
            .verify_expected_patch(finals[0].bytes.get(at..end).ok_or(Refusal::InvalidRange)?)
            .map_err(SiteError::Source)?;
        Ok(InstalledOptionalSite {
            site: p.site.clone(),
            writer: p.writer.take().ok_or(SiteError::Correspondence)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use liteinst2::{scanner::InstructionScanner, trampoline::TrampolinePlan};
    #[test]
    fn image_join_requires_exact_selector_controls_complete_roles_and_order() {
        let pc = 0x0100_0000;
        let scan = InstructionScanner::default()
            .scan(&[0x31, 0xc0, 0x31, 0xc9, 0x90, 0xc3], pc)
            .unwrap();
        let (selector, writer) = PreContextSelector::new(false);
        let actions = [
            PreContextAction::new(pc, PreContextRole::Entry, &selector, entry_callback),
            PreContextAction::new(pc + 5, PreContextRole::Return, &selector, exit_callback),
        ];
        // Only construction/encoding; neither this leaf nor these callbacks run.
        let plan = unsafe { TrampolinePlan::from_precontext_actions(&scan, pc, pc + 6, &actions) }
            .unwrap();
        let image = plan.emit_at(0x0200_0000).unwrap();
        assert!(image_roles(&image, &actions, &selector));
        let (other, _) = PreContextSelector::new(false);
        assert!(!image_roles(&image, &actions, &other));
        assert!(!image_roles(&image, &actions[..1], &selector));
        assert!(!image_roles(
            &image,
            &[actions[1].clone(), actions[0].clone()],
            &selector
        ));
        let replacement =
            PreContextAction::new(pc + 5, PreContextRole::Return, &selector, exit_callback);
        assert!(!image_roles(
            &image,
            &[actions[0].clone(), replacement],
            &selector
        ));
        for action in actions {
            assert!(action.control().is_enabled());
            assert!(action.control().try_set_enabled(false).is_err());
        }
        drop(writer);
        assert_eq!(image.controls().len(), 2);
        assert_eq!(image.precontext_gates().len(), 2);
    }
    #[test]
    fn complete_role_groups_keep_short_ret_and_internal_entry_refusals() {
        let groups_ = groups(
            0x1000,
            &[0x100f, 0x101f],
            &[(0x1000, 0x1010), (0x1010, 0x1020)],
            &[],
        )
        .unwrap();
        assert_eq!(groups_.len(), 2);
        assert_eq!(groups_[0].roles, [0, 1]);
        assert_eq!(groups_[1].roles, [2]);
        assert!(groups(0x1000, &[0x100f, 0x101f], &[(0x1000, 0x1010)], &[]).is_err());
        assert!(matches!(
            groups(
                0x1000,
                &[0x100f],
                &[(0x1000, 0x100f), (0x100f, 0x1010)],
                &[]
            ),
            Err(SiteError::Core(Refusal::NoPatchWindow))
        ));
        assert!(groups(0x1000, &[0x100f], &[(0x1000, 0x1010)], &[(0x1005, 0x1000)]).is_err());
    }
}
