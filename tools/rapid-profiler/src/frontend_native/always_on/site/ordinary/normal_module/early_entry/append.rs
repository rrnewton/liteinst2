use super::*;

impl FunctionPlanning<'_> {
    fn append_entry_admission(
        self,
        typed: &[EntryAdmissionAction],
        predecessor: &mut Composition,
        reserved: &mut Vec<AddressRange>,
        members: &mut Vec<liteinst2::quiescent::PlannedInstall>,
        overlay: &mut [u8],
        full_overlay: &mut [u8],
    ) -> Result<(), SiteError> {
        if typed.len() != self.roles.len()
            || typed.iter().zip(self.roles).any(|(a, r)| {
                a.logical_pc() != r.pc
                    || a.control() != &r.control
                    || a.function_entry() != self.certificate.entry()
            })
            || self
                .groups
                .iter()
                .any(|g| g.roles.is_empty() || g.roles.iter().any(|&i| i >= typed.len()))
        {
            return Err(SiteError::Correspondence);
        }
        let Self {
            code,
            certificate,
            policy,
            identity,
            scope,
            groups,
            roles: _,
            entries,
            source_start,
        } = self;
        let entry = certificate.entry();
        for (index, group) in groups.iter().enumerate() {
            let actions: Vec<_> = group.roles.iter().map(|&i| typed[i].clone()).collect();
            let logical = actions[0].logical_pc();
            let mut allocation = base_allocation(entry)?;
            allocation.preferred_address = Some(
                (entry & !4095)
                    .checked_add(0x10_0000 + index as u64 * 0x1_0000)
                    .ok_or(Refusal::InvalidRange)?,
            );
            for &prior in reserved.iter() {
                exclude(&mut allocation.ranges, prior)?;
            }
            let member = match policy {
                PreparationPolicy::CertifiedBlocks => unsafe {
                    plan_entry_admission_detailed_after(
                        &InstallRequest {
                            identity,
                            code,
                            base_address: entry,
                            function: scope,
                            block: group.block,
                            logical_pc: logical,
                            entries,
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
                        predecessor,
                    )
                },
                PreparationPolicy::WholeFunction => {
                    // SAFETY: the exclusive admitted owner authenticates the
                    // exact complete scalar CFG, sole external entry, no saved
                    // resumes/foreign transfers and continuous source lifetime.
                    // The permanent distinct controls above are our managed
                    // non-unwinding state-preserving entry/RET observers. The
                    // core independently checks complete leaders, every C3 and
                    // exact whole extent, using this original source and the
                    // authenticated predecessor overlay. Publication/execution
                    // still require the unchanged explicit unsafe contracts.
                    unsafe {
                        plan_whole_function_entry_admission_detailed_after(
                            &WholeFunctionRequest {
                                identity,
                                code,
                                base_address: entry,
                                entries,
                                allocation: &allocation,
                            },
                            &actions,
                            predecessor,
                        )
                    }
                }
            }
            .map_err(SiteError::Planning)?;
            let p = member.plan().parts();
            if p.kind != PlanKind::Relocation
                || p.profile != ApplicationProfile::InstallOnce
                || p.identity != identity
                || p.entries != *entries
                || p.logical_pc != logical
                || !group.block.covers(p.displaced)
                || p.physical_pc != p.displaced.start()
                || p.writes.len() != 1
                || p.writes[0].address != p.physical_pc
                || p.writes[0].bytes.len() as u64 != p.displaced.len()
                || p.reads
                    != [ExpectedBytes {
                        address: entry,
                        bytes: overlay.to_vec(),
                    }]
                || member.image().controls()
                    != actions
                        .iter()
                        .map(|a| a.control().clone())
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
                || actions
                    .iter()
                    .any(|a| !p.displaced.contains(a.logical_pc()))
            {
                return Err(SiteError::Correspondence);
            }
            if policy == PreparationPolicy::WholeFunction {
                if groups.len() != 1 || index != 0 || group.block != scope {
                    return Err(SiteError::Correspondence);
                }
                whole::check_plan(scope, certificate.heads(), &member)?;
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
                if overlay.get(at..end) != code.get(at..end) {
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
        Ok(())
    }
}
