use super::*;
use crate::quiescent::feasibility::ENTRY_BYTES;

// A finite byte-address oracle, deliberately unlike the digit/page algorithm.
fn oracle(constraints: Rel32Constraints, ranges: &[AddressRange]) -> Option<u64> {
    ranges
        .iter()
        .flat_map(|range| range.start()..range.end())
        .filter(|target| {
            let Ok(displacement) =
                i32::try_from(i128::from(*target) - i128::from(constraints.next))
            else {
                return false;
            };
            displacement
                .to_le_bytes()
                .into_iter()
                .enumerate()
                .all(|(digit, byte)| {
                    constraints.fixed[digit].is_none_or(|fixed| fixed == byte)
                        && (!constraints.entries[digit] || ENTRY_BYTES.contains(&byte))
                })
        })
        .min_by_key(|target| (target % PAGE, *target))
}

fn interval(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}

fn checked_result(constraints: Rel32Constraints, ranges: &[AddressRange]) {
    let actual = minimum_target(constraints, ranges);
    match oracle(constraints, ranges) {
        Some(target) => assert_eq!(actual.unwrap(), target),
        None => assert_eq!(actual.unwrap_err(), Refusal::AllocationUnavailable),
    }
}

#[test]
fn all_entry_bytes_and_fixed_conflicts_are_exact_in_each_digit() {
    assert_eq!(
        ENTRY_BYTES,
        [
            0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x60, 0x61, 0xce
        ]
    );
    let next = 0x9000_0000;
    for digit in 0..4 {
        for byte in ENTRY_BYTES
            .into_iter()
            .chain([0x00, 0x62, 0x90, 0xd4, 0xd5, 0xff])
        {
            let mut bytes = [0_u8; 4];
            bytes[digit] = byte;
            let target =
                u64::try_from(i128::from(next) + i128::from(i32::from_le_bytes(bytes))).unwrap();
            let mut constraints = Rel32Constraints::plain(next);
            constraints.entries[digit] = true;
            let ranges = [interval(target, 1)];
            checked_result(constraints, &ranges);
            constraints.fixed[digit] = Some(byte);
            checked_result(constraints, &ranges);
            constraints.fixed[digit] = Some(byte ^ 1);
            assert_eq!(
                minimum_target(constraints, &ranges).unwrap_err(),
                Refusal::AllocationUnavailable
            );
        }
    }
}

#[test]
fn digit_minimum_matches_finite_enumeration_across_carries() {
    for pattern in 0..16 {
        let mut constraints = Rel32Constraints::plain(0);
        constraints.entries = std::array::from_fn(|digit| pattern & (1 << digit) != 0);
        let domains = domains(constraints);
        for (low, high) in [
            (0, 255),
            (0xff0, 0x1020),
            (0xfff0, 0x10020),
            (0x7fff_fff0, 0x8000_0020),
            (0x8606_fff0, 0x8607_0020),
            (0xffff_fff0, 0xffff_ffff),
        ] {
            let expected = (low..=high).find(|q| {
                ((*q as u32) ^ 0x8000_0000)
                    .to_le_bytes()
                    .into_iter()
                    .enumerate()
                    .all(|(digit, byte)| !constraints.entries[digit] || ENTRY_BYTES.contains(&byte))
            });
            assert_eq!(first(low, high, &domains), expected);
        }
    }
    let all = [ByteDomain::from_allowed(|_| true); 4];
    assert_eq!(first(9, 8, &all), None);
    assert_eq!(first(0, u64::from(u32::MAX) + 1, &all), None);
    assert_eq!(minimum_offset(0, 1, &all, PAGE), None);
}

#[test]
fn all_masks_match_small_signed_partial_and_full_page_oracle() {
    // Each interval is at most 0x3021 bytes; this never scans an arena.
    for next in [0x9000_0000_u64, 0x9000_08fa, 0x9000_0fff] {
        for pattern in 0..16 {
            let mut constraints = Rel32Constraints::plain(next);
            constraints.entries = std::array::from_fn(|digit| pattern & (1 << digit) != 0);
            for (qlow, qhigh) in [
                (0_u64, 0x3020),
                (0x4eff_f7f0, 0x4f00_0810),
                (0x7fff_fff0, 0x8000_0020),
                (0x8605_f7f0, 0x8606_0810),
                (0x8606_0000, 0x8606_3020),
                (0x8606_fff0, 0x8607_0020),
                (0xffff_f7f0, 0xffff_ffff),
            ] {
                let low = u64::try_from(i128::from(next) + i128::from(i32::MIN) + i128::from(qlow))
                    .unwrap();
                let ranges = [interval(low, usize::try_from(qhigh - qlow + 1).unwrap())];
                checked_result(constraints, &ranges);
                constraints.fixed[2] = Some(0x06);
                checked_result(constraints, &ranges);
                constraints.fixed[2] = None;
            }
        }
    }
}

#[test]
fn fixed06_wrapper_matches_independent_argmin_for_every_mask() {
    let physical = 0x4008f5;
    let next = physical + 5;
    let ranges = [interval(0x0640_0000, 8192), interval(0x0641_0f00, 512)];
    for pattern in 0..16 {
        let mask = std::array::from_fn(|digit| pattern & (1 << digit) != 0);
        let mut constraints = Rel32Constraints::plain(next);
        for (fixed, constrained) in constraints.fixed.iter_mut().zip(mask) {
            *fixed = constrained.then_some(0x06);
        }
        let actual = super::super::minimum_relocation_target(physical, mask, ranges.to_vec(), next);
        match oracle(constraints, &ranges) {
            Some(target) => {
                assert_eq!(actual.unwrap(), target);
                assert_eq!(
                    crate::quiescent::candidate_target(physical, mask, Some(target), 0),
                    Some(target)
                );
            }
            None => assert_eq!(actual.unwrap_err(), Refusal::AllocationUnavailable),
        }
    }
}

#[test]
fn alphabet_geometry_does_not_change_fixed_profile_or_indexed_attempt_zero() {
    let physical = 0x4008f5;
    let next = physical + 5;
    let mask = [true, true, false, true];
    let ranges = [interval(0x0640_0000, 8192)];
    let policy = super::super::AllocationPolicy {
        ranges: ranges.to_vec(),
        preferred_address: None,
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    };
    let source = interval(physical, 64);
    let old =
        super::super::minimum_relocation_target(physical, mask, ranges.to_vec(), next).unwrap();
    assert_eq!(old, 0x0640_0f00);
    assert_eq!(PAGE - old % PAGE, 256);
    assert_eq!(
        super::super::fitting_for_relocation(&policy, physical, mask, &[], source, 512)
            .unwrap_err(),
        Refusal::AllocationUnavailable
    );
    let mut constraints = Rel32Constraints::plain(next);
    constraints.entries = mask;
    let target = minimum_target(constraints, &ranges).unwrap();
    assert_eq!(target, 0x0640_1000);
    assert_eq!(
        i32::try_from(i128::from(target) - i128::from(next))
            .unwrap()
            .to_le_bytes(),
        [0x06, 0x07, 0x00, 0x06]
    );
    assert_eq!(target % PAGE, 0);
    assert_eq!(
        crate::quiescent::candidate_target(physical, mask, Some(target), 0),
        Some(old)
    );
    assert_eq!(
        (
            policy.max_candidates,
            policy.max_mappings,
            policy.max_mapped_bytes
        ),
        (1, 1, 4096)
    );
    assert_eq!(policy.ranges, ranges);
    // A new arithmetic answer has not granted an image, extra slot or profile.
    assert_eq!(
        super::super::fitting_for_relocation(&policy, physical, mask, &[], source, 4097)
            .unwrap_err(),
        Refusal::AllocationUnavailable
    );
}

#[test]
fn clipped_signed_edges_empty_sets_and_interval_order_are_exact() {
    for next in [0, u64::MAX] {
        let constraints = Rel32Constraints::plain(next);
        checked_result(constraints, &[interval(0, 17), interval(u64::MAX - 17, 17)]);
    }
    let constraints = Rel32Constraints::plain(0);
    assert_eq!(
        minimum_target(constraints, &[interval(0x8000_0000, 17)]).unwrap_err(),
        Refusal::AllocationUnavailable
    );
    assert_eq!(
        minimum_target(constraints, &[]).unwrap_err(),
        Refusal::AllocationUnavailable
    );
    let mut impossible = Rel32Constraints::plain(0x9000_0000);
    impossible.entries[0] = true;
    impossible.fixed[0] = Some(0x62);
    assert_eq!(
        minimum_target(impossible, &[interval(0x9000_0000, 33)]).unwrap_err(),
        Refusal::AllocationUnavailable
    );
    let mut constraints = Rel32Constraints::plain(0x4008fa);
    constraints.entries = [true, true, false, true];
    let a = interval(0x0640_0000, 8192);
    let b = interval(0x0641_0000, 8192);
    for ranges in [[a, b, a], [b, a, b]] {
        checked_result(constraints, &ranges);
        assert_eq!(minimum_target(constraints, &ranges).unwrap(), 0x0640_1000);
    }
}
