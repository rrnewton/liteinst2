use super::*;

const PHYSICAL: u64 = 0x0040_08f5;
const TARGET: u64 = 0x0640_1000;

fn policy() -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![AddressRange::new(0x0640_0000, 8192).unwrap()],
        preferred_address: None,
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    }
}
fn facts(policy: &AllocationPolicy) -> RelocationPlacementFacts<'_> {
    RelocationPlacementFacts {
        physical: PHYSICAL,
        mask: [true, true, false, true],
        policy,
        occupied: &[],
        source: AddressRange::new(PHYSICAL, 5).unwrap(),
        // Pure target-validation control; actual prepared bounds are tested by
        // artifact_window::placement_tests through the real encoder.
        prepared_bound: 512,
    }
}

#[test]
fn checked_target_preserves_seed_or_selects_one_alphabet_target() {
    let mut p = policy();
    let f = facts(&p);
    assert!(matches!(
        fitting_for_relocation(&p, f.physical, f.mask, &[], f.source, 512),
        Err(Refusal::AllocationUnavailable)
    ));
    let target = entry_alphabet_fitting(&f).unwrap();
    assert_eq!(target.target, TARGET);
    assert_eq!(target.displacement.to_le_bytes(), [0x06, 0x07, 0, 0x06]);
    assert_eq!(target.into_target(&f), Ok(TARGET));
    assert_eq!(
        candidate_target(PHYSICAL, f.mask, Some(TARGET), 0),
        Some(0x0640_0f00)
    );
    // A certified legacy seed remains first, even when a lower offset exists.
    p.preferred_address = Some(0x0640_0f00);
    let mut f = facts(&p);
    f.prepared_bound = 256;
    assert_eq!(
        entry_alphabet_fitting(&f).unwrap().into_target(&f),
        Ok(0x0640_0f00)
    );
}

#[test]
fn checked_target_rejoins_every_field_and_rejects_coherent_non_alphabet_bytes() {
    let p = policy();
    let f = facts(&p);
    for field in 0..8 {
        let mut target = entry_alphabet_fitting(&f).unwrap();
        match field {
            0 => target.physical += 1,
            1 => target.next += 1,
            2 => target.mask[0] = false,
            3 => target.target += 1,
            4 => target.displacement += 1,
            5 => target.page = AddressRange::new(TARGET - 4096, 4096).unwrap(),
            6 => target.source = AddressRange::new(PHYSICAL, 6).unwrap(),
            7 => target.prepared_bound += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            target.into_target(&f),
            Err(Refusal::InvalidPlan),
            "field {field}"
        );
    }
    // Rejoin all numerical fields, so only the indispensable producer alphabet
    // check can reject these coherent targets. D4/D5 are deliberately excluded.
    for byte in [0x08, 0x90, 0xd4, 0xd5] {
        let mut target = entry_alphabet_fitting(&f).unwrap();
        target.displacement = i32::from_le_bytes([byte, 0x07, 0, 0x06]);
        target.target = (i128::from(target.next) + i128::from(target.displacement)) as u64;
        target.page = AddressRange::new(target.target & !4095, 4096).unwrap();
        assert_eq!(target.into_target(&f), Err(Refusal::InvalidPlan));
    }
    for field in 0..4 {
        let target = entry_alphabet_fitting(&f).unwrap();
        let mut changed = facts(&p);
        match field {
            0 => changed.physical += 1,
            1 => changed.mask[0] = false,
            2 => changed.source = AddressRange::new(PHYSICAL, 6).unwrap(),
            3 => changed.prepared_bound = 0,
            _ => unreachable!(),
        }
        assert_eq!(target.into_target(&changed), Err(Refusal::InvalidPlan));
    }
}

#[test]
fn consumption_rechecks_permits_occupancy_and_unchanged_one_page_policy() {
    let p = policy();
    let f = facts(&p);
    let occupied = [AddressRange::new(TARGET + 4095, 1).unwrap()];
    let mut changed = facts(&p);
    changed.occupied = &occupied;
    assert_eq!(
        entry_alphabet_fitting(&f).unwrap().into_target(&changed),
        Err(Refusal::AllocationUnavailable)
    );
    let mut narrow = policy();
    narrow.ranges = vec![AddressRange::new(TARGET - 4096, 4096).unwrap()];
    assert_eq!(
        entry_alphabet_fitting(&f)
            .unwrap()
            .into_target(&facts(&narrow)),
        Err(Refusal::AllocationUnavailable)
    );
    for field in 0..3 {
        let mut bad = policy();
        match field {
            0 => bad.max_candidates = 2,
            1 => bad.max_mappings = 2,
            2 => bad.max_mapped_bytes = 8192,
            _ => unreachable!(),
        }
        assert_eq!(
            entry_alphabet_fitting(&f)
                .unwrap()
                .into_target(&facts(&bad)),
            Err(Refusal::InvalidRange)
        );
        for bound in [0, 4097] {
            let mut bad_facts = facts(&bad);
            bad_facts.prepared_bound = bound;
            assert!(matches!(
                entry_alphabet_fitting(&bad_facts),
                Err(Refusal::AllocationUnavailable)
            ));
        }
    }
    let mut overflow = facts(&p);
    overflow.physical = u64::MAX - 4;
    assert!(matches!(
        entry_alphabet_fitting(&overflow),
        Err(Refusal::InvalidRange)
    ));
    overflow.physical = u64::MAX - 5;
    assert!(matches!(
        entry_alphabet_fitting(&overflow),
        Err(Refusal::InvalidRange)
    ));
    let mut held_source = facts(&p);
    held_source.source = AddressRange::new(TARGET, 1).unwrap();
    assert!(matches!(
        entry_alphabet_fitting(&held_source),
        Err(Refusal::AllocationUnavailable)
    ));
}
