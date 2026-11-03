//! Policy4 consumes opaque core schedules; it never collects or decodes windows.
use super::*;
use li2core::quiescent::seal_artifact_observation_windows_upstream_min5;

pub const GROUPED_PHYSICAL_MIN5_ALPHABET_UPSTREAM_PROFILE: &str =
    "jumps-gpr-stack64-block-physical-min5-alphabet-upstream-v1";

/// Per-physical minimum windows sealed against the original complete selection.
/// This is offline candidate construction, with no native qualification credit.
pub fn prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_upstream_fixed_exec(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
) -> Result<Product, Error> {
    prepare_grouped(
        original,
        selected,
        GroupProfile::PhysicalMin5AlphabetUpstream,
    )
}
pub fn prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_upstream_with_ledger_storage(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
    storage: LedgerStorage,
) -> Result<Product, Error> {
    prepare_grouped_with_storage(
        original,
        selected,
        GroupProfile::PhysicalMin5AlphabetUpstream,
        storage,
    )
}
pub fn grouped_physical_min5_alphabet_upstream_fixed_exec_metadata() -> String {
    grouped_metadata(GroupProfile::PhysicalMin5AlphabetUpstream)
}
pub fn grouped_physical_min5_alphabet_upstream_fixed_exec_binding_policy(
    binding: FixedImageBinding,
    selection: ContentId,
    grouping: ContentId,
) -> Vec<u8> {
    GroupProfile::PhysicalMin5AlphabetUpstream.binding_policy(binding, selection, grouping)
}

impl Schedule {
    pub(crate) fn freeze_physical(
        elf: &Elf64<'_>,
        s: &Selection,
        classes: &[JumpStackClass],
        identity: CodeIdentity,
        binding: Option<FixedImageBinding>,
        occupied: &[AddressRange],
    ) -> Result<Self, Error> {
        let mut out =
            Self::freeze_profile(elf, s, classes, GroupProfile::PhysicalMin5AlphabetUpstream)?;
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
                let seal = seal_artifact_observation_windows_upstream_min5(
                    &request.artifact(),
                    &request.pcs,
                )
                .map_err(SealFailure::core)?;
                out.validate_physical_membership(s, group, &seal)
                    .map_err(SealFailure::adapter)?;
                Ok(seal)
            })();
            // Keep the entire unit, including a global preflight failure. All
            // groups are frozen here, before the shared transaction mutates.
            out.groups[unit].physical = Some(result);
        }
        out.policy = out.policy_bytes(s);
        Ok(out)
    }

    pub(super) fn validate_physical_membership(
        &self,
        s: &Selection,
        group: &Group,
        seal: &ArtifactPhysicalWindowSchedule,
    ) -> Result<(), Error> {
        let pcs: Vec<_> = group.members.iter().map(|&i| s.sites[i].pc).collect();
        if seal.selected_span() != group.window || seal.observation_pcs() != pcs {
            return Err(Error::new(
                "grouped-physical-seal",
                "selected span or complete members differ",
            ));
        }
        let mut end = group.window.end();
        for row in seal.rows() {
            if let Ok(ready_end) = row.outcome() {
                let range = addr(
                    row.physical_pc(),
                    ready_end.checked_sub(row.physical_pc()).ok_or_else(|| {
                        Error::new("grouped-physical-seal", "reversed ready window")
                    })?,
                )?;
                self.validate_intersection(s, group, range)?;
                end = end.max(ready_end);
            }
        }
        let floor = s.sites[group.members[0]]
            .block
            .start()
            .max(group.window.start().saturating_sub(64));
        // This includes the omitted-head prefix and already consumed members.
        // Refused-row source dependencies are deliberately NOT membership windows.
        self.validate_intersection(s, group, addr(floor, end - floor)?)
    }

    pub(super) fn physical_policy(&self, text: &mut String, unit: usize, group: &Group) {
        match group
            .physical
            .as_ref()
            .expect("physical schedule frozen before serialization")
        {
            Err(failure) => writeln!(
                text,
                "unit-preflight\t{unit}\trefused\t{}\t{}\t{}",
                failure.code,
                failure.error.stage,
                ledger::hex(failure.error.detail.as_bytes())
            )
            .unwrap(),
            Ok(seal) => {
                let total = seal.physical_domain().len();
                let sealed = seal.rows().len();
                assert!((1..=65).contains(&total) && sealed == total.min(64));
                writeln!(
                    text,
                    "window-domain\t{unit}\t{total}\t{sealed}\t{}",
                    total - sealed
                )
                .unwrap();
                let (source, bytes) = seal.source_dependency().expect("positive named row budget");
                assert!(source.len() <= 335 && source.len() == bytes.len() as u64);
                writeln!(
                    text,
                    "window-source\t{unit}\t{}\t{}\t{}",
                    source.start(),
                    source.end(),
                    ledger::hex(&ContentId::of(bytes).0)
                )
                .unwrap();
                for (ordinal, row) in seal.rows().iter().enumerate() {
                    assert_eq!(row.ordinal(), ordinal);
                    assert_eq!(row.physical_pc(), seal.physical_domain()[ordinal]);
                    match row.outcome() {
                        Ok(end) => writeln!(
                            text,
                            "physical-window\t{unit}\t{ordinal}\t{}\tready\t{end}\t-\t-\t-",
                            row.physical_pc()
                        )
                        .unwrap(),
                        Err(reason) => writeln!(
                            text,
                            "physical-window\t{unit}\t{ordinal}\t{}\trefused\t-\t{}\tcore\t{}",
                            row.physical_pc(),
                            model::core_code(reason),
                            ledger::hex(Error::new("core", reason).detail.as_bytes())
                        )
                        .unwrap(),
                    }
                }
            }
        }
    }

    pub(super) fn actual_physical_ordinal(
        &self,
        s: &Selection,
        group: &Group,
        plan: &ArtifactPlan,
    ) -> Result<usize, Error> {
        let Some(Ok(seal)) = &group.physical else {
            return Err(Error::new(
                "grouped-physical-seal",
                "accepted unit lacks complete schedule",
            ));
        };
        self.validate_physical_membership(s, group, seal)?;
        self.validate_upstream(s, group)?;
        let [step] = plan.source_steps() else {
            return Err(Error::new(
                "grouped-association",
                "one actual physical window required",
            ));
        };
        let parts = step.parts();
        let first = &s.sites[group.members[0]];
        if parts.logical_pc != first.pc
            || parts.displaced.start() != parts.physical_pc
            || !(5..=256).contains(&parts.displaced.len())
            || !first.block.covers(parts.displaced)
            || !self.upstream_envelope(s, group)?.covers(parts.displaced)
        {
            return Err(Error::new(
                "grouped-association",
                "actual physical window outside policy",
            ));
        }
        let ordinal = accepted_ordinal(seal, parts.physical_pc, parts.displaced.end())?;
        self.validate_intersection(s, group, parts.displaced)?;
        Ok(ordinal)
    }
}

fn accepted_ordinal(
    seal: &ArtifactPhysicalWindowSchedule,
    physical: u64,
    end: u64,
) -> Result<usize, Error> {
    let mut matches = seal
        .rows()
        .iter()
        .filter(|row| row.physical_pc() == physical && row.outcome() == Ok(end));
    let first = matches
        .next()
        .ok_or_else(|| Error::new("grouped-association", "actual step has no ready sealed row"))?;
    if matches.next().is_some() {
        return Err(Error::new(
            "grouped-association",
            "actual step matches multiple rows",
        ));
    }
    Ok(first.ordinal())
}

#[cfg(test)]
mod tests;
