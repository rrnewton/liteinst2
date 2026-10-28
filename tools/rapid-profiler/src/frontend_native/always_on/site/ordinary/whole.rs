//! Closed frontend whole-function geometry; no loader or publication authority.
use super::{BlockActions, SiteError};
use liteinst2::contracts::{AddressRange, Refusal};
use liteinst2::quiescent::PlannedInstall;
use liteinst2::trampoline::ObservationStackProfile;

pub(super) fn groups(
    scope: AddressRange,
    returns: &[u64],
    blocks: &[(u64, u64)],
    edges: &[(u64, u64)],
) -> Result<Vec<BlockActions>, SiteError> {
    if !(5..=80).contains(&scope.len()) {
        return Err(SiteError::Core(Refusal::NoPatchWindow));
    }
    let entry = scope.start();
    if !(1..=4).contains(&returns.len())
        || blocks.is_empty()
        || blocks.len() > 32
        || returns.iter().any(|&pc| pc <= entry || !scope.contains(pc))
        || returns.windows(2).any(|w| w[0] >= w[1])
        || edges
            .iter()
            .any(|&(from, to)| !scope.contains(from) || !scope.contains(to) || to == entry)
    {
        return Err(SiteError::Correspondence);
    }
    let pcs: Vec<_> = std::iter::once(entry)
        .chain(returns.iter().copied())
        .collect();
    let mut found = vec![false; pcs.len()];
    let mut previous_end = entry;
    for &(start, end) in blocks {
        let length = usize::try_from(end.checked_sub(start).ok_or(Refusal::InvalidRange)?)
            .map_err(|_| Refusal::InvalidRange)?;
        let block = AddressRange::new(start, length)?;
        if !scope.covers(block) || start < previous_end {
            return Err(SiteError::Correspondence);
        }
        previous_end = end;
        for (i, &pc) in pcs
            .iter()
            .enumerate()
            .filter(|(_, pc)| block.contains(**pc))
        {
            if found[i]
                || (i == 0 && block.start() != entry)
                || (i != 0 && pc.checked_add(1) != Some(end))
            {
                return Err(SiteError::Correspondence);
            }
            found[i] = true;
        }
    }
    if found.iter().any(|&yes| !yes) {
        return Err(SiteError::Correspondence);
    }
    Ok(vec![BlockActions {
        block: scope,
        roles: (0..pcs.len()).collect(),
    }])
}

// Additional whole-profile correspondence. The shared constructor still checks
// all controls, read/write overlays, identity/entry facts and bundle ownership.
pub(super) fn check_plan(
    scope: AddressRange,
    heads: &[u64],
    member: &PlannedInstall,
) -> Result<(), SiteError> {
    let p = member.plan().parts();
    let image = member.image();
    let image_range = AddressRange::new(image.address(), image.bytes().len())?;
    if p.displaced != scope
        || p.physical_pc != scope.start()
        || p.logical_pc != scope.start()
        || member.metrics().displaced_bytes as u64 != scope.len()
        || image.layout().observation_stack_profile != ObservationStackProfile::Legacy128
        || p.allocations.len() != 1
        || p.allocations[0].range.len() > 8192
        || !p.allocations[0].range.covers(image_range)
        || p.generated.len() != 1
        || p.generated[0].address != image.address()
        || p.generated[0].bytes.as_slice() != image.bytes()
        || p.generated[0].program_counters.as_slice() != image.program_counter_mappings()
        || image
            .entry_routes()
            .iter()
            .map(|&(pc, _)| pc)
            .collect::<Vec<_>>()
            .as_slice()
            != heads
        || image
            .instruction_boundaries()
            .iter()
            .map(|&(pc, _)| pc)
            .collect::<Vec<_>>()
            .as_slice()
            != heads
    {
        return Err(SiteError::Correspondence);
    }
    for &(pc, generated) in image
        .entry_routes()
        .iter()
        .chain(image.instruction_boundaries())
    {
        if !image
            .program_counter_mappings()
            .iter()
            .any(|map| map.translate(generated) == Some(pc))
        {
            return Err(SiteError::Correspondence);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const ENTRY: u64 = 0x1000;

    fn scope(len: usize) -> AddressRange {
        AddressRange::new(ENTRY, len).unwrap()
    }

    #[test]
    fn whole_group_keeps_entry_and_two_one_byte_return_roles_once() {
        let blocks = [
            (ENTRY, ENTRY + 7),
            (ENTRY + 7, ENTRY + 8),
            (ENTRY + 8, ENTRY + 11),
            (ENTRY + 11, ENTRY + 12),
        ];
        let returns = [ENTRY + 7, ENTRY + 11];
        let edges = [
            (ENTRY, ENTRY + 7),
            (ENTRY, ENTRY + 8),
            (ENTRY + 8, ENTRY + 11),
        ];
        let found = groups(scope(12), &returns, &blocks, &edges).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].block, scope(12));
        assert_eq!(found[0].roles, [0, 1, 2]);
        // The opt-in policy does not reinterpret the old certified-block path.
        assert!(matches!(
            super::super::groups(ENTRY, &returns, &blocks, &edges),
            Err(SiteError::Core(Refusal::NoPatchWindow))
        ));
    }

    #[test]
    fn whole_extent_includes_padding_and_branch_after_last_action() {
        let blocks = [
            (ENTRY, ENTRY + 5),
            (ENTRY + 5, ENTRY + 6),
            (ENTRY + 8, ENTRY + 16),
        ];
        let found = groups(
            scope(16),
            &[ENTRY + 5],
            &blocks,
            &[(ENTRY, ENTRY + 8), (ENTRY + 8, ENTRY + 5)],
        )
        .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].block.end(), ENTRY + 16);
        assert_eq!(found[0].roles, [0, 1]);
    }

    #[test]
    fn whole_extent_keeps_exact_five_through_eighty_bound() {
        for len in [5, 80] {
            let end = ENTRY + len as u64;
            let found = groups(scope(len), &[end - 1], &[(ENTRY, end)], &[]).unwrap();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].block, scope(len));
            assert_eq!(found[0].roles, [0, 1]);
        }
        for len in [1, 2, 3, 4, 81, 256] {
            let end = ENTRY + len as u64;
            assert!(matches!(
                groups(scope(len), &[end - 1], &[(ENTRY, end)], &[]),
                Err(SiteError::Core(Refusal::NoPatchWindow))
            ));
        }
    }

    #[test]
    fn whole_missing_duplicate_unsorted_and_outside_roles_refuse() {
        let blocks = [
            (ENTRY, ENTRY + 7),
            (ENTRY + 7, ENTRY + 8),
            (ENTRY + 8, ENTRY + 11),
            (ENTRY + 11, ENTRY + 12),
        ];
        for returns in [
            vec![],
            vec![ENTRY],
            vec![ENTRY + 12],
            vec![ENTRY + 7, ENTRY + 7],
            vec![ENTRY + 11, ENTRY + 7],
            vec![ENTRY + 3],
            vec![ENTRY + 1, ENTRY + 2, ENTRY + 3, ENTRY + 4, ENTRY + 5],
        ] {
            assert!(groups(scope(12), &returns, &blocks, &[]).is_err());
        }
        assert!(groups(scope(12), &[ENTRY + 7, ENTRY + 11], &blocks[..2], &[]).is_err());
    }

    #[test]
    fn whole_entry_backedge_escape_and_bad_block_geometry_refuse() {
        let valid = [(ENTRY, ENTRY + 12)];
        for edges in [
            vec![(ENTRY + 5, ENTRY)],
            vec![(ENTRY, ENTRY + 12)],
            vec![(ENTRY - 1, ENTRY + 5)],
        ] {
            assert!(groups(scope(12), &[ENTRY + 11], &valid, &edges).is_err());
        }
        for blocks in [
            vec![],
            vec![(ENTRY + 1, ENTRY + 12)],
            vec![(ENTRY - 1, ENTRY + 12)],
            vec![(ENTRY, ENTRY + 13)],
            vec![(ENTRY, ENTRY + 8), (ENTRY + 7, ENTRY + 12)],
            vec![(ENTRY, ENTRY)],
            vec![(ENTRY + 2, ENTRY + 1)],
        ] {
            assert!(groups(scope(12), &[ENTRY + 11], &blocks, &[]).is_err());
        }
    }

    #[test]
    fn whole_support_does_not_change_old_valid_groups_or_old_short_refusal() {
        let old = super::super::groups(ENTRY, &[ENTRY + 7], &[(ENTRY, ENTRY + 8)], &[]).unwrap();
        let new = groups(scope(8), &[ENTRY + 7], &[(ENTRY, ENTRY + 8)], &[]).unwrap();
        assert_eq!(old.len(), new.len());
        assert_eq!(old[0].block, new[0].block);
        assert_eq!(old[0].roles, new[0].roles);
        assert!(matches!(
            super::super::groups(
                ENTRY,
                &[ENTRY + 5],
                &[(ENTRY, ENTRY + 5), (ENTRY + 5, ENTRY + 6)],
                &[]
            ),
            Err(SiteError::Core(Refusal::NoPatchWindow))
        ));
        assert_eq!(
            groups(
                scope(6),
                &[ENTRY + 5],
                &[(ENTRY, ENTRY + 5), (ENTRY + 5, ENTRY + 6)],
                &[]
            )
            .unwrap()[0]
                .roles,
            [0, 1]
        );
    }
}
