use super::*;

fn policy(ranges: &[(u64, usize)], hint: Option<u64>) -> AllocationPolicy {
    AllocationPolicy {
        ranges: ranges
            .iter()
            .map(|&(a, n)| AddressRange::new(a, n).unwrap())
            .collect(),
        preferred_address: hint,
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    }
}

// Independent decoder arithmetic: construct the two actual overlapping rel32
// encodings, without using PairSpace, interval transforms or residue helpers.
fn encoded_pair(v: u64, selected: u64) -> Option<(u64, [u8; 6])> {
    let d = i32::try_from(i128::from(selected) - i128::from(v) - 6).ok()?;
    let d = d.to_le_bytes();
    let bytes = [0xe9, 0xe9, d[0], d[1], d[2], d[3]];
    let vd = i32::from_le_bytes(bytes[1..5].try_into().unwrap());
    let target = u64::try_from(i128::from(v) + 5 + i128::from(vd)).ok()?;
    assert_eq!(
        i128::from(v) + 6 + i128::from(i32::from_le_bytes(d)),
        i128::from(selected)
    );
    Some((target, bytes))
}

fn brute(
    selected: &AllocationPolicy,
    victim: &AllocationPolicy,
    occupied: &[AddressRange],
    source: AddressRange,
    v: u64,
    bounds: (usize, usize),
) -> Option<(u64, u64)> {
    let fits = |p: &AllocationPolicy, target: u64, bound: usize| {
        let page = AddressRange::new(target & !4095, 4096).unwrap();
        target % 4096 + bound as u64 <= 4096
            && p.ranges.iter().any(|r| r.covers(page))
            && !source.overlaps(page)
            && !occupied.iter().any(|r| r.overlaps(page))
    };
    selected
        .ranges
        .iter()
        .flat_map(|r| r.start()..r.end())
        .filter_map(|s| {
            let (t, _) = encoded_pair(v, s)?;
            (s / 4096 != t / 4096 && fits(selected, s, bounds.0) && fits(victim, t, bounds.1))
                .then_some((s, t))
        })
        .min()
}

#[test]
fn overlapping_targets_preserve_correlated_hints_with_exact_source_bytes() {
    let source = AddressRange::new(8192, 60000).unwrap();
    let broad = [(262144, 536870912 - 262144)];
    let selected = policy(&broad, Some(1048584));
    let victim = policy(&broad, Some(253706642));
    let pair = joint_overlapping_targets(&selected, &victim, &[], source, 57764, 321, 20).unwrap();
    assert_eq!(pair, (1048584, 253706386));
    assert_eq!(
        encoded_pair(57764, pair.0),
        Some((pair.1, [0xe9, 0xe9, 0x5e, 0x1e, 0x0f, 0]))
    );
    let no_selected_hint = policy(&broad, None);
    let victim_hint = policy(&broad, Some(253706386));
    assert_eq!(
        joint_overlapping_targets(&no_selected_hint, &victim_hint, &[], source, 57764, 321, 20),
        Ok(pair)
    );
    assert_eq!(selected.preferred_address, Some(1048584));
    assert_eq!(victim.preferred_address, Some(253706642));
    assert_eq!((selected.max_candidates, victim.max_candidates), (1, 1));
    assert_eq!((selected.max_mappings, victim.max_mappings), (1, 1));
    assert_eq!(
        (selected.max_mapped_bytes, victim.max_mapped_bytes),
        (4096, 4096)
    );
}

#[test]
fn overlapping_targets_match_independent_enumeration_across_signed_classes() {
    let v = 0x9000_0712_u64;
    let source = AddressRange::new(v & !4095, 4096).unwrap();
    for (k, r) in [
        (-128, 0),
        (-1, 0x7ffff0),
        (-1, 0x800000),
        (0, 0),
        (0, 0x7ffff0),
        (0, 0x800000),
        (1, 2280),
        (127, 0xffffff),
    ] {
        let s = u64::try_from(i128::from(v) + 6 + k * (1 << 24) + r).unwrap();
        let t = encoded_pair(v, s).unwrap().0;
        let selected = policy(&[(s & !4095, 8192)], None);
        let victim = policy(&[(t & !4095, 8192)], None);
        for bounds in [(1, 1), (321, 20), (4096, 4096)] {
            let expected = brute(&selected, &victim, &[], source, v, bounds);
            assert_eq!(
                joint_overlapping_targets(&selected, &victim, &[], source, v, bounds.0, bounds.1)
                    .ok(),
                expected,
                "k={k}, r={r}, bounds={bounds:?}"
            );
        }
    }
}

#[test]
fn overlapping_residue_and_same_page_solver_matches_literal_enumeration() {
    for v in [
        0x1_0000_0000_u64,
        0x1_0000_0012,
        0x1_0000_0712,
        0x1_0000_0fff,
    ] {
        for bounds in [(1, 1), (321, 20), (4088, 3950), (4096, 4096)] {
            let space = PairSpace {
                selected: vec![],
                victim: vec![],
                selected_next: v + 6,
                victim_next: v + 5,
                selected_bound: bounds.0,
                victim_bound: bounds.1,
            };
            for (k, low, high) in [
                (-128, 0, 255),
                (-1, 0xffff00, 0xffffff),
                (0, 0, 255),
                (0, 4000, 4300),
                (1, 65000, 66000),
                (127, 0x7fff00, 0x7fffff),
                (127, 0x800000, 0x800100),
            ] {
                let expected = (low..=high).find(|&r| {
                    let s = u64::try_from(i128::from(v) + 6 + k * (1 << 24) + r).unwrap();
                    let t = encoded_pair(v, s).unwrap().0;
                    s / 4096 != t / 4096
                        && s % 4096 + bounds.0 as u64 <= 4096
                        && t % 4096 + bounds.1 as u64 <= 4096
                });
                assert_eq!(
                    space.first_distinct(low, high, k, low >= 1 << 23),
                    expected,
                    "V={v}, bounds={bounds:?}, k={k}, interval={low}..={high}"
                );
            }
        }
    }
}

#[test]
fn overlapping_targets_own_complete_distinct_pages_and_refuse_partial_occupancy() {
    let source = AddressRange::new(8192, 60000).unwrap();
    let selected = policy(&[(1048576, 4096)], Some(1048584));
    let victim = policy(&[(253706240, 4096)], Some(253706386));
    assert_eq!(
        joint_overlapping_targets(&selected, &victim, &[], source, 57764, 321, 20),
        Ok((1048584, 253706386))
    );
    for byte in [1048576, 1048576 + 4095, 253706240, 253706240 + 4095] {
        let occupied = [AddressRange::new(byte, 1).unwrap()];
        assert_eq!(
            joint_overlapping_targets(&selected, &victim, &occupied, source, 57764, 321, 20),
            Err(Refusal::AllocationUnavailable)
        );
    }
    let same = policy(&[(0x100000, 4096)], None);
    assert_eq!(
        joint_overlapping_targets(
            &same,
            &same,
            &[],
            AddressRange::new(0x80000, 16).unwrap(),
            0x100000,
            1,
            1
        ),
        Err(Refusal::AllocationUnavailable)
    );
    assert_eq!(
        joint_overlapping_targets(
            &selected,
            &victim,
            &[],
            AddressRange::new(1048584, 1).unwrap(),
            57764,
            321,
            20
        ),
        Err(Refusal::AllocationUnavailable)
    );
}

#[test]
fn overlapping_targets_normalize_permits_without_adding_authority_or_skipping_a_page() {
    let v = 57764;
    let source = AddressRange::new(8192, 60000).unwrap();
    let selected = policy(
        &[
            (1064960, 4096),
            (1052672, 4096),
            (1048576, 8192),
            (1048576, 4096),
        ],
        Some(u64::MAX),
    );
    let victim = policy(&[(253706240, 8192), (253706240, 4096)], Some(1));
    let occupied = [AddressRange::new(1052672, 1).unwrap()];
    let expected = brute(&selected, &victim, &occupied, source, v, (321, 20));
    let actual =
        joint_overlapping_targets(&selected, &victim, &occupied, source, v, 321, 20).unwrap();
    assert_eq!(Some(actual), expected);
    assert_eq!(selected.ranges.len(), 4);
    assert_eq!(victim.ranges.len(), 2);
    for (entry, p) in [(actual.0, &selected), (actual.1, &victim)] {
        assert!(
            p.ranges
                .iter()
                .any(|r| r.covers(AddressRange::new(entry & !4095, 4096).unwrap()))
        );
    }
}

#[test]
fn overlapping_targets_enforce_bound_endpoints_policy_shape_and_checked_origins() {
    let source = AddressRange::new(8192, 4096).unwrap();
    let p = policy(&[(262144, 536870912 - 262144)], None);
    for bound in [0, 4097] {
        assert_eq!(
            joint_overlapping_targets(&p, &p, &[], source, 57764, bound, 20),
            Err(Refusal::AllocationUnavailable)
        );
        assert_eq!(
            joint_overlapping_targets(&p, &p, &[], source, 57764, 321, bound),
            Err(Refusal::AllocationUnavailable)
        );
    }
    let mut malformed = p.clone();
    malformed.max_candidates = 2;
    assert_eq!(
        joint_overlapping_targets(&malformed, &p, &[], source, 57764, 321, 20),
        Err(Refusal::InvalidRange)
    );
    malformed = p.clone();
    malformed.ranges.clear();
    assert_eq!(
        joint_overlapping_targets(&p, &malformed, &[], source, 57764, 321, 20),
        Err(Refusal::InvalidRange)
    );
    malformed = policy(&[(262145, 4096)], None);
    assert_eq!(
        joint_overlapping_targets(&malformed, &p, &[], source, 57764, 321, 20),
        Err(Refusal::InvalidRange)
    );
    malformed = p.clone();
    malformed.ranges = vec![AddressRange::new(262144, 4096).unwrap(); 17];
    assert_eq!(
        joint_overlapping_targets(&p, &malformed, &[], source, 57764, 321, 20),
        Err(Refusal::InvalidRange)
    );
    assert_eq!(
        joint_overlapping_targets(&p, &p, &[], source, u64::MAX - 5, 321, 20),
        Err(Refusal::InvalidRange)
    );
    let wrapping_page = [AddressRange::new(u64::MAX - 4, 1).unwrap()];
    assert_eq!(
        joint_overlapping_targets(&p, &p, &wrapping_page, source, 57764, 321, 20),
        Err(Refusal::InvalidRange)
    );
    let far = policy(&[(1_u64 << 33, 4096)], None);
    assert_eq!(
        joint_overlapping_targets(&far, &p, &[], source, 57764, 321, 20),
        Err(Refusal::AllocationUnavailable)
    );
    let v = 0x9000_0712;
    let s = v + 6 + (1 << 24) + 2280;
    let t = encoded_pair(v, s).unwrap().0;
    assert_eq!((s % 4096, t % 4096), (0, 0));
    let selected = policy(&[(s, 4096)], Some(s));
    let victim = policy(&[(t, 4096)], Some(t));
    assert_eq!(
        joint_overlapping_targets(&selected, &victim, &[], source, v, 4096, 4096),
        Ok((s, t))
    );
}

#[test]
fn overlapping_targets_reconstruct_residual_source_puzzles_without_emission_claim() {
    let arena = [(262144, 536870912 - 262144)];
    let source = AddressRange::new(8192, 60000).unwrap();
    for (logical, v, selected, victim, expected, rel8) in [
        (
            57842_u64,
            57764_u64,
            1048584_u64,
            253706386_u64,
            [0xe9, 0xe9, 0x5e, 0x1e, 0x0f, 0],
            -79_i8,
        ),
        (
            15139,
            15204,
            1048590,
            264560722,
            [0xe9, 0xe9, 0xa4, 0xc4, 0x0f, 0],
            64,
        ),
    ] {
        let p = policy(&arena, Some(selected));
        let q = policy(&arena, None);
        assert_eq!(
            joint_overlapping_targets(&p, &q, &[], source, v, 321, 20),
            Ok((selected, victim))
        );
        assert_eq!(encoded_pair(v, selected), Some((victim, expected)));
        assert_eq!(
            i8::try_from(i128::from(v) + 1 - i128::from(logical) - 2).unwrap(),
            rel8
        );
        assert_eq!(victim % 256, (v + 238) % 256);
    }
}
