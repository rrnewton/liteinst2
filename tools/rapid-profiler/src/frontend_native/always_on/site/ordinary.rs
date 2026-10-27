//! Ordinary scalar-symbol factory. Admission is separate from publication and timing.
use super::super::{
    ReadableStack,
    gate::{CallGate, OriginalCallResult},
    timed_entry_callback, timed_exit_callback, timing,
};
use super::{
    InstalledIntervalSite, Role, Site, SiteError, base_allocation, check_image,
    impossible_ordinary_dispatch, same_bundle,
};
use crate::frontend_native::LoadedIntegerLeaf;
use liteinst2::bundle::{BundleBudget, BundleReceipt, InstalledBundle, PlannedBundle};
use liteinst2::contracts::*;
use liteinst2::controls::{ControlledAction, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{InstallRequest, SearchPolicy, TacticPolicy, plan_coalesced_detailed};
use std::sync::Arc;

/// Owns one admitted DSO and all mandatory entry/RET plans. No publication occurs
/// here. A single unpatchable RET refuses the complete preparation.
pub struct OrdinarySitePreparation {
    owner: &'static mut LoadedIntegerLeaf,
    planned: PlannedBundle,
    site: Arc<Site>,
    gate: Arc<CallGate>,
}

struct BlockActions {
    block: AddressRange,
    roles: Vec<usize>,
}

fn groups(
    entry: u64,
    returns: &[u64],
    blocks: &[(u64, u64)],
    edges: &[(u64, u64)],
) -> Result<Vec<BlockActions>, SiteError> {
    if !(1..=4).contains(&returns.len()) || blocks.is_empty() || blocks.len() > 32
        || returns.iter().any(|&pc| pc <= entry)
        || returns.windows(2).any(|w| w[0] >= w[1])
        // An internal entry-edge would repeat entry bookkeeping in one call.
        || edges.iter().any(|&(_, to)| to == entry)
    {
        return Err(SiteError::Correspondence);
    }
    let pcs: Vec<_> = std::iter::once(entry)
        .chain(returns.iter().copied())
        .collect();
    let mut found = vec![false; pcs.len()];
    let mut result = Vec::new();
    let mut previous_end = 0;
    for &(start, end) in blocks {
        let length = usize::try_from(end.checked_sub(start).ok_or(Refusal::InvalidRange)?)
            .map_err(|_| Refusal::InvalidRange)?;
        let block = AddressRange::new(start, length)?;
        if start < previous_end {
            return Err(SiteError::Correspondence);
        }
        previous_end = end;
        let roles: Vec<_> = pcs
            .iter()
            .enumerate()
            .filter_map(|(i, &pc)| block.contains(pc).then_some(i))
            .collect();
        if roles.is_empty() {
            continue;
        }
        if block.len() < 5 {
            return Err(SiteError::Core(Refusal::NoPatchWindow));
        }
        for &i in &roles {
            if found[i]
                || (i == 0 && block.start() != entry)
                || (i != 0 && pcs[i].checked_add(1) != Some(end))
            {
                return Err(SiteError::Correspondence);
            }
            found[i] = true;
        }
        result.push(BlockActions { block, roles });
    }
    if found.iter().any(|&yes| !yes) || result.is_empty() || result.len() > 5 {
        return Err(SiteError::Correspondence);
    }
    Ok(result)
}

// Subtract complete already-owned ranges; never truncate a generated mapping.
fn exclude(ranges: &mut Vec<AddressRange>, owned: AddressRange) -> Result<(), SiteError> {
    let mut remaining = Vec::new();
    for &range in ranges.iter() {
        if !range.overlaps(owned) {
            remaining.push(range);
            continue;
        }
        if range.start() < owned.start() {
            remaining.push(AddressRange::new(
                range.start(),
                usize::try_from(owned.start() - range.start())
                    .map_err(|_| Refusal::InvalidRange)?,
            )?);
        }
        if owned.end() < range.end() {
            remaining.push(AddressRange::new(
                owned.end(),
                usize::try_from(range.end() - owned.end()).map_err(|_| Refusal::InvalidRange)?,
            )?);
        }
    }
    *ranges = remaining;
    Ok(())
}

impl OrdinarySitePreparation {
    /// Build entry and every original ordinary RET action within certified blocks.
    ///
    /// The first profile refuses local edges into the external symbol entry.
    /// It retains the existing 64-byte upstream/80-byte displacement/65-site caps;
    /// no padding, omitted RET, cross-block window or fallback callback is added.
    pub fn new(
        owner: &'static mut LoadedIntegerLeaf,
        gate: Arc<CallGate>,
        identity: CodeIdentity,
    ) -> Result<Self, SiteError> {
        if !timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        owner.verify_original().map_err(SiteError::Source)?;
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
            || gate.declared_returns() != certificate.returns()
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
        let roles: Vec<_> = pcs
            .iter()
            .enumerate()
            .map(|(i, &pc)| {
                let (control, writer) = ProbeControl::new_managed_bound(
                    if i == 0 {
                        timed_entry_callback
                    } else {
                        timed_exit_callback
                    },
                    true,
                );
                drop(writer); // Mandatory pairing can never be disabled.
                Role { pc, control }
            })
            .collect();
        let entries = LegalEntrySet {
            identity,
            scope,
            provenance: EntryProvenance::Declared(
                "admitted complete local CFG plus unsafe sole external entry/no saved-resume contract".into(),
            ),
            completeness: EntryCompleteness::Complete,
            entries: certificate.entries().iter().map(|&address| LegalEntry { address, requires_endbr: false }).collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let mut overlay = owner.code().to_vec();
        let mut full_overlay = owner.original_source().to_vec();
        let mut reserved = vec![source];
        let mut members = Vec::new();
        for (index, group) in groups.iter().enumerate() {
            let actions: Vec<_> = group
                .roles
                .iter()
                .map(|&i| ControlledAction {
                    logical_pc: roles[i].pc,
                    control: roles[i].control.clone(),
                })
                .collect();
            let logical = actions[0].logical_pc;
            let mut allocation = base_allocation(entry)?;
            allocation.preferred_address = Some(
                (entry & !4095)
                    .checked_add(0x10_0000 + index as u64 * 0x1_0000)
                    .ok_or(Refusal::InvalidRange)?,
            );
            for &prior in &reserved {
                exclude(&mut allocation.ranges, prior)?;
            }
            let member = plan_coalesced_detailed(
                &InstallRequest {
                    identity,
                    code: &overlay,
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
                        address: entry,
                        bytes: overlay.clone(),
                    }]
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
                    != certificate
                        .heads()
                        .iter()
                        .copied()
                        .filter(|&pc| p.displaced.contains(pc))
                        .collect::<Vec<_>>()
                || actions.iter().any(|a| !p.displaced.contains(a.logical_pc))
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
        let site = Arc::new(Site {
            roles,
            terminal: gate.continuation(),
            gate: Some(Arc::clone(&gate)),
        });
        Ok(Self {
            owner,
            planned,
            site,
            gate,
        })
    }

    /// Call the unchanged original through the same library gate before publication.
    /// This returns a value and CALL/RSP observations, never interval/RET coverage.
    ///
    /// # Safety
    /// No publication or callback attachment has occurred. The loader's full
    /// ABI, input-memory, normal-return, signal/reentry, no-CET and termination
    /// contract holds; `stack` covers the live CALL return word and remains
    /// readable. Only this thread may invoke the gate; no source/alias writer,
    /// fork or unload may race either complete source check or the call.
    pub unsafe fn invoke_original(
        &mut self,
        data: *const u8,
        len: usize,
        stack: &ReadableStack,
    ) -> Result<OriginalCallResult, SiteError> {
        self.owner.verify_original().map_err(SiteError::Source)?;
        // SAFETY: caller supplies the original-only gate and memory contract.
        let result = unsafe { self.gate.invoke_original(data, len, stack) };
        // A gate refusal also preserves the required after-observation.
        self.owner.verify_original().map_err(SiteError::Source)?;
        result.map_err(SiteError::Gate)
    }

    /// Full bundle, including every image, original source page and final overlay.
    pub fn plan(&self) -> &PlannedBundle {
        &self.planned
    }
    /// Entry first, then every original RET in ascending source order.
    pub fn role_pcs(&self) -> impl ExactSizeIterator<Item = u64> + '_ {
        self.site.roles.iter().map(|r| r.pc)
    }
    /// Immutable library call identity, without any admission/receipt extraction.
    pub fn gate(&self) -> &Arc<CallGate> {
        &self.gate
    }

    /// Consume/retain the complete installation, including on correspondence refusal.
    ///
    /// # Safety
    /// All existing bundle publication requirements hold: real publication and
    /// receipt, full source-page/generated leases and quiescence, final RX bytes,
    /// complete local/external entry and NoneExist-resume proof, no CET, signals,
    /// code-as-data, unload, fork, alias mutation, active callback or concurrent
    /// writer. All source/image ranges are readable. Callback execution starts
    /// only after this seal and a matching thread/gate attachment. The admitted
    /// SysV input memory, writable callback/XSAVE stack, ordinary return and
    /// termination obligations remain explicit; barrier completion is not drain.
    pub unsafe fn seal(
        self,
        installed: InstalledBundle,
        receipt: BundleReceipt,
    ) -> Result<InstalledIntervalSite, SiteError> {
        let (prep, installed, receipt) = Box::leak(Box::new((self, installed, receipt)));
        if !timing::supported() {
            return Err(SiteError::ClockUnsupported);
        }
        if !prep.gate.process_matches()
            || prep.gate.target() != prep.owner.entry()
            || prep.gate.declared_returns() != prep.owner.certificate().returns()
            || prep.site.terminal != prep.gate.continuation()
            || prep
                .site
                .gate
                .as_ref()
                .is_none_or(|g| !Arc::ptr_eq(g, &prep.gate))
            || installed.is_retired()
            || !same_bundle(installed.plan(), prep.planned.plan())
            || !same_bundle(receipt.plan(), prep.planned.plan())
            || installed.trampolines().len() != prep.planned.images().len()
        {
            return Err(SiteError::Correspondence);
        }
        for (image, executable) in prep.planned.images().iter().zip(installed.trampolines()) {
            // SAFETY: complete real published owner/readability contract above.
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
        let at = usize::try_from(
            prep.owner
                .entry()
                .checked_sub(start)
                .ok_or(Refusal::InvalidRange)?,
        )
        .map_err(|_| Refusal::InvalidRange)?;
        let end = at
            .checked_add(prep.owner.code().len())
            .ok_or(Refusal::InvalidRange)?;
        let expected = finals[0].bytes.get(at..end).ok_or(Refusal::InvalidRange)?;
        prep.owner
            .verify_expected_patch(expected)
            .map_err(SiteError::Source)?;
        Ok(InstalledIntervalSite {
            site: Arc::clone(&prep.site),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Geometry tests only: no loader, live planner, executable maps or publication.
    #[test]
    fn every_ret_is_grouped_and_same_block_entry_ret_is_coalesced() {
        let g = groups(0x1000, &[0x1007], &[(0x1000, 0x1008)], &[]).unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].roles, [0, 1]);
        let g = groups(
            0x1000,
            &[0x1017, 0x1027],
            &[(0x1000, 0x1005), (0x1010, 0x1018), (0x1020, 0x1028)],
            &[(0x1003, 0x1020)],
        )
        .unwrap();
        assert_eq!(
            g.iter().map(|g| g.roles.clone()).collect::<Vec<_>>(),
            [vec![0], vec![1], vec![2]]
        );
    }
    #[test]
    fn short_or_missing_ret_block_refuses_without_padding_or_omission() {
        assert!(matches!(
            groups(
                0x1000,
                &[0x1012],
                &[(0x1000, 0x1005), (0x1010, 0x1013)],
                &[]
            ),
            Err(SiteError::Core(Refusal::NoPatchWindow))
        ));
        assert!(
            groups(
                0x1000,
                &[0x1017, 0x1027],
                &[(0x1000, 0x1005), (0x1010, 0x1018)],
                &[]
            )
            .is_err()
        );
        assert!(groups(0x1000, &[0x1017, 0x1017], &[(0x1000, 0x1018)], &[]).is_err());
    }
    #[test]
    fn internal_entry_backedge_and_overlapping_blocks_refuse() {
        assert!(
            groups(
                0x1000,
                &[0x1017],
                &[(0x1000, 0x1005), (0x1010, 0x1018)],
                &[(0x1010, 0x1000)]
            )
            .is_err()
        );
        assert!(
            groups(
                0x1000,
                &[0x1017],
                &[(0x1000, 0x1012), (0x1010, 0x1018)],
                &[]
            )
            .is_err()
        );
    }
    #[test]
    fn source_and_prior_mapping_exclusion_preserves_every_other_byte() {
        let mut ranges = vec![AddressRange::new(0x1000, 0x6000).unwrap()];
        exclude(&mut ranges, AddressRange::new(0x3000, 0x2000).unwrap()).unwrap();
        exclude(&mut ranges, AddressRange::new(0x1000, 0x1000).unwrap()).unwrap();
        assert_eq!(
            ranges,
            [
                AddressRange::new(0x2000, 0x1000).unwrap(),
                AddressRange::new(0x5000, 0x2000).unwrap()
            ]
        );
        assert!(
            ranges
                .iter()
                .all(|r| !r.overlaps(AddressRange::new(0x3000, 0x2000).unwrap()))
        );
    }
}
