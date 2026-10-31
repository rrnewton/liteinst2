use super::*;

fn policy(seed: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![AddressRange::new(262144, 2147483648 - 262144).unwrap()],
        preferred_address: Some(seed),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    }
}

#[test]
fn fixed_bit_carry_matches_independent_finite_enumeration() {
    for mask in [0, 1, 15, 85, 128, 170, 255] {
        for value in [0, mask & 0xa6, mask] {
            for low in 0..=255 {
                let high = (low + 23).min(255);
                let expected = (low..=high).find(|x| x & mask == value);
                assert_eq!(first_fixed(low, high, mask, value), expected);
            }
        }
    }
    assert_eq!(first_fixed(3, 2, 0, 0), None);
    assert_eq!(first_fixed(u32::MAX as u64, u32::MAX as u64, 1, 0), None);
}

#[test]
fn low_offset_matches_independent_page_crossing_enumeration() {
    for (low, high) in [
        (0, 8191),
        (4000, 9000),
        (0x7fff_f800, 0x8000_1020),
        (0xffff_e000, 0xffff_ffff),
        (0x8605_f800, 0x8606_1020),
        (0x86ff_f800, 0x8700_1020),
    ] {
        for pattern in 0..16 {
            let mask = (0..4).fold(0_u64, |bits, byte| {
                bits | if pattern & (1 << byte) != 0 {
                    0xff << (8 * byte)
                } else {
                    0
                }
            });
            let value = (0x0606_0606 ^ 0x8000_0000) & mask;
            for next in [0, 219, 3029, 4095] {
                let expected = (low..=high)
                    .filter(|q| q & mask == value)
                    .min_by_key(|q| ((q + next) % PAGE, *q));
                assert_eq!(low_offset(low, high, mask, value, next), expected);
            }
        }
    }
}

#[test]
fn site_215_seed_geometry_is_not_an_image_capacity_certificate() {
    let source = AddressRange::new(11216, 64).unwrap();
    let mask = [true, false, false, true];
    for (seed, target, offset) in [(1905890, 102569179, 1243), (12333056, 112996315, 4059)] {
        let original = policy(seed);
        let effective = for_relocation(&original, 11216, mask, &[], source).unwrap();
        assert_eq!(effective.preferred_address, Some(seed));
        assert_eq!(effective.ranges, original.ranges);
        assert_eq!(
            candidate_target(11216, mask, effective.preferred_address, 0),
            Some(target)
        );
        assert_eq!(target % PAGE, offset);
    }
    let original = policy(12333056);
    let occupied = [AddressRange::new(112996315 & !4095, 4096).unwrap()];
    let effective = for_relocation(&original, 11216, mask, &occupied, source).unwrap();
    let target = effective.preferred_address.unwrap();
    assert_eq!(target % PAGE, 219);
    assert_eq!(candidate_target(11216, mask, Some(target), 0), Some(target));
    assert!(!occupied[0].contains(target));
    assert_eq!(effective.ranges, original.ranges);
    assert_eq!(effective.max_candidates, 1);
    assert_eq!(effective.max_mappings, 1);
    assert_eq!(effective.max_mapped_bytes, 4096);
}

#[test]
fn pun_preference_uses_exact_window_and_entire_free_pages() {
    let source = AddressRange::new(0x1000, 64).unwrap();
    let original = policy(0x700000);
    let window = AddressRange::new(0x401ff0, 256).unwrap();
    let effective = for_pun(&original, window, &[], source).unwrap();
    assert_eq!(effective.preferred_address, Some(0x402000));
    // A single occupied byte excludes its whole page, not merely that byte.
    let occupied = [AddressRange::new(0x402100, 1).unwrap()];
    let effective = for_pun(&original, window, &occupied, source).unwrap();
    assert_eq!(effective.preferred_address, Some(0x401ff0));
    let singleton = AddressRange::new(585710856, 1).unwrap();
    assert_eq!(
        for_pun(&original, singleton, &[], source)
            .unwrap()
            .preferred_address,
        Some(585710856)
    );
    assert_eq!(effective.ranges, original.ranges);
    let mut near_source = original;
    near_source.ranges = vec![AddressRange::new(0x1000, 8192).unwrap()];
    near_source.preferred_address = Some(0x1000);
    let window = AddressRange::new(0x1000, 8192).unwrap();
    assert_eq!(
        for_pun(&near_source, window, &[], source)
            .unwrap()
            .preferred_address,
        Some(0x2000)
    );
}

#[test]
fn unavailable_pages_and_checked_overflow_do_not_expand_policy() {
    let source = AddressRange::new(11216, 64).unwrap();
    let original = policy(1905890);
    assert!(matches!(
        for_relocation(
            &original,
            11216,
            [true, false, false, true],
            &original.ranges,
            source
        ),
        Err(Refusal::AllocationUnavailable)
    ));
    assert!(matches!(
        for_relocation(&original, u64::MAX - 5, [false; 4], &[], source),
        Err(Refusal::InvalidRange)
    ));
    let high = [AddressRange::new(u64::MAX - 8, 8).unwrap()];
    assert!(matches!(
        for_relocation(&original, 11216, [false; 4], &high, source),
        Err(Refusal::InvalidRange)
    ));
    for count in [0, 2] {
        let mut invalid = original.clone();
        invalid.max_candidates = count;
        assert!(matches!(validate(&invalid), Err(Refusal::InvalidRange)));
    }
    let mut invalid = original.clone();
    invalid.ranges = vec![AddressRange::new(262145, 4096).unwrap()];
    assert!(matches!(validate(&invalid), Err(Refusal::InvalidRange)));
    let mut narrow = original;
    narrow.ranges = vec![AddressRange::new(262144, 4096).unwrap()];
    assert!(matches!(
        for_relocation(&narrow, 11216, [true; 4], &[], source),
        Err(Refusal::AllocationUnavailable)
    ));
}
