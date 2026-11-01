use super::*;

fn arena(seed: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![AddressRange::new(0x500000, 3 * 4096).unwrap()],
        preferred_address: Some(seed),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    }
}

fn same_limits(before: &AllocationPolicy, after: &AllocationPolicy) {
    assert_eq!(before.ranges, after.ranges);
    assert_eq!(after.max_candidates, 1);
    assert_eq!(after.max_mappings, 1);
    assert_eq!(after.max_mapped_bytes, 4096);
}

#[test]
fn fitting_preserves_certified_seed_and_replaces_only_nonfitting_seed() {
    let source = AddressRange::new(0x1000, 64).unwrap();
    let physical = source.start();
    let seed = arena(0x501100);
    let window = AddressRange::new(0x500000, 3 * 4096).unwrap();
    for effective in [
        fitting_for_pun(&seed, window, &[], source, 512).unwrap(),
        fitting_for_relocation(&seed, physical, [false; 4], &[], source, 512).unwrap(),
    ] {
        same_limits(&seed, &effective);
        assert_eq!(effective.preferred_address, seed.preferred_address);
    }
    let late = arena(0x501ff0);
    assert_eq!(
        for_relocation(&late, physical, [false; 4], &[], source)
            .unwrap()
            .preferred_address,
        late.preferred_address
    );
    let effective = fitting_for_relocation(&late, physical, [false; 4], &[], source, 512).unwrap();
    same_limits(&late, &effective);
    assert_eq!(effective.preferred_address, Some(0x500000));
    assert_eq!(
        candidate_target(physical, [false; 4], effective.preferred_address, 0),
        Some(0x500000)
    );
    let crossing = AddressRange::new(0x501f00, 512).unwrap();
    let effective = fitting_for_pun(&late, crossing, &[], source, 512).unwrap();
    assert_eq!(effective.preferred_address, Some(0x502000));
    same_limits(&late, &effective);
}

#[test]
fn fitting_masks_and_narrow_windows_refuse_without_larger_ranges_or_second_slot() {
    let source = AddressRange::new(11216, 64).unwrap();
    let policy = AllocationPolicy {
        ranges: vec![AddressRange::new(262144, 2147483648 - 262144).unwrap()],
        preferred_address: Some(12333056),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let mask = [true, false, false, true];
    assert_eq!(
        candidate_target(11216, mask, policy.preferred_address, 0),
        Some(112996315)
    );
    let effective = fitting_for_relocation(&policy, 11216, mask, &[], source, 512).unwrap();
    let target = effective.preferred_address.unwrap();
    assert_eq!(target % PAGE, 219);
    assert_eq!(candidate_target(11216, mask, Some(target), 0), Some(target));
    same_limits(&policy, &effective);
    assert!(matches!(
        fitting_for_relocation(&policy, 11216, mask, &[], source, 4096),
        Err(Refusal::AllocationUnavailable)
    ));
    // Exact prior B2 window: even its minimum offset leaves only 297 bytes.
    let window = AddressRange::new(1075838679, 256).unwrap();
    let accepted = fitting_for_pun(&policy, window, &[], source, 297).unwrap();
    assert_eq!(accepted.preferred_address.unwrap() % PAGE, 3799);
    assert!(matches!(
        fitting_for_pun(&policy, window, &[], source, 298),
        Err(Refusal::AllocationUnavailable)
    ));
}

#[test]
fn fitting_excludes_partial_pages_and_rejects_bounds_policy_and_overflow() {
    let source = AddressRange::new(0x1000, 64).unwrap();
    let policy = arena(0x501ff0);
    let occupied = [
        AddressRange::new(0x500001, 1).unwrap(),
        AddressRange::new(0x501a00, 1).unwrap(),
    ];
    let effective =
        fitting_for_relocation(&policy, 0x1000, [false; 4], &occupied, source, 512).unwrap();
    assert_eq!(effective.preferred_address, Some(0x502000));
    same_limits(&policy, &effective);
    for bound in [0, 4097, usize::MAX] {
        assert!(matches!(
            fitting_for_relocation(&policy, 0x1000, [false; 4], &[], source, bound),
            Err(Refusal::AllocationUnavailable)
        ));
        assert!(matches!(
            fitting_for_pun(&policy, policy.ranges[0], &[], source, bound),
            Err(Refusal::AllocationUnavailable)
        ));
    }
    let mut invalid = policy.clone();
    invalid.max_candidates = 2;
    assert!(matches!(
        fitting_for_relocation(&invalid, 0x1000, [false; 4], &[], source, 512),
        Err(Refusal::InvalidRange)
    ));
    assert!(matches!(
        fitting_for_relocation(&policy, u64::MAX, [false; 4], &[], source, 512),
        Err(Refusal::InvalidRange)
    ));
    let edge = AddressRange::new(u64::MAX - 4095, 4095).unwrap();
    assert!(matches!(
        fitting_for_pun(&policy, policy.ranges[0], &[], edge, 512),
        Err(Refusal::InvalidRange)
    ));
    assert!(matches!(
        fitting_for_pun(&policy, policy.ranges[0], &policy.ranges, source, 512),
        Err(Refusal::AllocationUnavailable)
    ));
}
