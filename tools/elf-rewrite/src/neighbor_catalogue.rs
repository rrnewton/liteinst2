//! Explicit function owners for the opt-in cross-function T3 preparation mode.
//! Linear decoding checks the supplied declarations; it cannot discover entries.
use super::*;
use iced_x86::{Code, FlowControl, OpKind};
use li2core::scanner::ScanResult;
use std::collections::BTreeSet;

/// Owns the entry declaration so a borrowed PlanningSite cannot outlive it.
pub(crate) struct OwnedNeighbor<'a> {
    source: &'a SelectedSite,
    code: &'a [u8],
    pc: u64,
    block: AddressRange,
    entries: LegalEntrySet,
}

impl OwnedNeighbor<'_> {
    pub(crate) fn site<'a>(&'a self, selected: &'a SelectedSite) -> PlanningSite<'a> {
        PlanningSite {
            identity: self.entries.identity,
            code: self.code,
            base_address: self.source.snapshot.start(),
            function: self.source.function,
            block: self.block,
            logical_pc: self.pc,
            entries: &self.entries,
            semantics: li2core::planner::HookSemantics::Observe,
            allocation: &selected.victim_allocation,
            search: selected.search,
        }
    }
}

/// Candidates come only from other complete, explicitly declared functions in
/// this same selection. Duplicate owner declarations must agree exactly. No
/// inter-function bytes, inferred symbol extent, or function fusion is allowed.
/// This opt-in profile requires all decoded heads to be declared legal entries
/// and a finite direct-control-flow block partition. Calls split the current
/// block; this partition does not infer ownership or entries in their callees.
pub(crate) fn collect<'a>(
    elf: &'a Elf64<'_>,
    selection: &'a Selection,
    identity: CodeIdentity,
    selected: &SelectedSite,
) -> Result<Vec<OwnedNeighbor<'a>>, Error> {
    let mut owners: BTreeMap<(u64, u64), &SelectedSite> = BTreeMap::new();
    for site in &selection.sites {
        validate_site(elf, site)?;
        let key = (site.function.start(), site.function.end());
        if let Some(previous) = owners.get(&key) {
            if previous.snapshot != site.snapshot
                || previous.heads != site.heads
                || previous.completeness != site.completeness
                || previous.resumes != site.resumes
                || previous.provenance != site.provenance
            {
                return Err(Error::new("neighbor-owner-conflict", site.id));
            }
        } else {
            owners.insert(key, site);
        }
    }
    let ordered: Vec<_> = owners.values().copied().collect();
    if ordered
        .windows(2)
        .any(|pair| pair[0].function.overlaps(pair[1].function))
    {
        return Err(Error::new(
            "neighbor-owner-overlap",
            "distinct functions overlap",
        ));
    }
    let mut out = Vec::new();
    for owner in ordered {
        if owner.function == selected.function {
            continue;
        }
        if !matches!(
            owner.completeness,
            EntryCompleteness::Complete | EntryCompleteness::AllInstructionHeads
        ) || matches!(owner.resumes, ResumeObligation::Unresolved)
        {
            return Err(Error::new("neighbor-owner-entries", owner.id));
        }
        let code = elf
            .executable_bytes(ElfVaddr(owner.snapshot.start()), owner.snapshot.len())
            .map_err(|e| Error::new("neighbor-snapshot", e))?;
        let function_bytes = elf
            .executable_bytes(ElfVaddr(owner.function.start()), owner.function.len())
            .map_err(|e| Error::new("neighbor-function", e))?;
        let scan = InstructionScanner::default()
            .scan(function_bytes, owner.function.start())
            .map_err(|e| Error::new("neighbor-decode", e))?;
        if !scan
            .instructions()
            .iter()
            .map(|i| i.address())
            .eq(owner.heads.iter().map(|h| h.address))
        {
            return Err(Error::new("neighbor-all-heads", owner.id));
        }
        let blocks = derive_blocks(owner.function, &scan)?;
        for site in selection
            .sites
            .iter()
            .filter(|s| s.function == owner.function)
        {
            if blocks.iter().find(|b| b.contains(site.pc)).copied() != Some(site.block) {
                return Err(Error::new("neighbor-declared-block", site.id));
            }
        }
        let entries = LegalEntrySet {
            identity,
            scope: owner.function,
            provenance: EntryProvenance::Declared(format!(
                "selection provenance SHA-256 {}",
                ledger::hex(&owner.provenance.0),
            )),
            completeness: owner.completeness,
            entries: owner.heads.clone(),
            resumes: owner.resumes.clone(),
        };
        for instruction in scan.instructions() {
            let pc = instruction.address();
            let displacement = i128::from(pc) + 5 - (i128::from(selected.pc) + 2);
            if !(10..=15).contains(&instruction.len()) || i8::try_from(displacement).is_err() {
                continue;
            }
            let block = *blocks
                .iter()
                .find(|b| b.contains(pc))
                .ok_or_else(|| Error::new("neighbor-block", pc))?;
            out.push(OwnedNeighbor {
                source: owner,
                code,
                pc,
                block,
                entries: entries.clone(),
            });
        }
    }
    out.sort_by_key(|candidate| std::cmp::Reverse(candidate.pc));
    Ok(out)
}

fn derive_blocks(function: AddressRange, scan: &ScanResult) -> Result<Vec<AddressRange>, Error> {
    let heads: BTreeSet<_> = scan.instructions().iter().map(|i| i.address()).collect();
    let mut boundaries = BTreeSet::from([function.start(), function.end()]);
    for item in scan.instructions() {
        let instruction = item.instruction();
        let next = instruction.next_ip();
        let flow = instruction.flow_control();
        if flow != FlowControl::Next && next < function.end() {
            boundaries.insert(next);
        }
        let mut successors = Vec::new();
        match flow {
            FlowControl::Next => successors.push(next),
            FlowControl::Call if instruction.code() == Code::Call_rel32_64 => {
                // The unchanged call target is not an inferred victim owner.
                // Only its local continuation contributes to this partition.
                successors.push(next);
            }
            FlowControl::Return if instruction.code() == Code::Retnq => {}
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if !matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ) {
                    return Err(Error::new("neighbor-non-near-branch", item.address()));
                }
                let target = instruction.near_branch_target();
                boundaries.insert(target);
                successors.push(target);
                if flow == FlowControl::ConditionalBranch {
                    successors.push(next);
                }
            }
            _ => return Err(Error::new("neighbor-control-flow", item.address())),
        }
        if successors.iter().any(|pc| !heads.contains(pc)) {
            return Err(Error::new("neighbor-target-not-head", item.address()));
        }
    }
    let boundaries: Vec<_> = boundaries.into_iter().collect();
    boundaries
        .windows(2)
        .map(|pair| addr(pair[0], pair[1] - pair[0]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(bytes: &[u8]) -> Result<Vec<AddressRange>, Error> {
        let function = AddressRange::new(0x1000, bytes.len()).unwrap();
        let scan = InstructionScanner::default().scan(bytes, 0x1000).unwrap();
        derive_blocks(function, &scan)
    }

    #[test]
    fn conditional_targets_and_fallthrough_bound_the_actual_blocks() {
        // JE +1; NOP; RET. Every successor is an original decoded head.
        let actual = blocks(&[0x74, 1, 0x90, 0xc3]).unwrap();
        assert_eq!(
            actual,
            vec![
                addr(0x1000, 2).unwrap(),
                addr(0x1002, 1).unwrap(),
                addr(0x1003, 1).unwrap()
            ]
        );
    }

    #[test]
    fn foreign_interior_and_unowned_successors_are_refused() {
        for code in [&[0xeb, 0x7f][..], &[0xeb, 0xff][..], &[0x90][..]] {
            assert_eq!(blocks(code).unwrap_err().stage, "neighbor-target-not-head");
        }
        assert_eq!(
            blocks(&[0xff, 0xe0]).unwrap_err().stage,
            "neighbor-control-flow"
        );
    }

    #[test]
    fn direct_calls_split_blocks_without_granting_callee_ownership() {
        let bytes = [0xe8, 0xfb, 0x0f, 0, 0, 0xc3];
        assert_eq!(
            blocks(&bytes).unwrap(),
            vec![addr(0x1000, 5).unwrap(), addr(0x1005, 1).unwrap()]
        );
        assert_eq!(
            blocks(&bytes[..5]).unwrap_err().stage,
            "neighbor-target-not-head"
        );
    }
}
