use super::*;
use crate::trampoline::EntryVeneerPlacement;

fn policy(seed: Option<u64>) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![AddressRange::new(0x500000, 4 * 4096).unwrap()],
        preferred_address: seed,
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 4096,
    }
}

#[test]
fn entry_veneer_preserves_seed_and_solves_only_the_same_page_window() {
    let source = AddressRange::new(57842, 2).unwrap();
    for entry in [55_144_261, 55_144_309] {
        let arena = AllocationPolicy {
            ranges: vec![AddressRange::new(55_140_352, 4096).unwrap()],
            preferred_address: Some(entry),
            ..policy(None)
        };
        let before = arena.clone();
        let window = AddressRange::new(entry, 1).unwrap();
        assert!(matches!(
            fitting_for_pun(&arena, window, &[], source, 978),
            Err(Refusal::AllocationUnavailable)
        ));
        let selected = entry_veneer_for_pun(&arena, window, &[], source, 978).unwrap();
        assert_eq!(selected.entry_address(), entry);
        assert_eq!(selected.storage_address(), 55_140_352);
        assert_eq!(selected.mapping(), arena.ranges[0]);
        assert_eq!(selected.size_bound(), 978);
        assert_eq!(selected.storage_len(), (entry - 55_140_352) as usize + 5);
        assert_eq!(arena.ranges, before.ranges);
        assert_eq!(arena.preferred_address, before.preferred_address);
        assert_eq!(
            (
                arena.max_candidates,
                arena.max_mappings,
                arena.max_mapped_bytes
            ),
            (1, 1, 4096)
        );
    }
    // An available seed remains preferred even when an earlier entry exists.
    let arena = policy(Some(0x502f00));
    let selected = entry_veneer_for_pun(&arena, arena.ranges[0], &[], source, 512).unwrap();
    assert_eq!(selected.entry_address(), 0x502f00);
    let unavailable_seed = policy(Some(0x502100));
    let selected =
        entry_veneer_for_pun(&unavailable_seed, arena.ranges[0], &[], source, 512).unwrap();
    assert_eq!(selected.entry_address(), 0x500200);
    // Existing direct fitting semantics are unchanged and remain the caller's
    // first choice; this helper does not replace that direct policy operation.
    let direct = fitting_for_pun(&unavailable_seed, arena.ranges[0], &[], source, 512).unwrap();
    assert_eq!(direct.preferred_address, unavailable_seed.preferred_address);
}

#[test]
fn entry_veneer_interval_argmin_matches_finite_independent_enumeration() {
    let source = AddressRange::new(0x1000, 2).unwrap();
    let arena = policy(None);
    let windows = [
        (0, 1),
        (1, 8191),
        (3909, 1),
        (3957, 1),
        (4090, 4102),
        (4092, 8192),
        (8189, 4099),
    ];
    for bound in [1, 5, 512, 978, 3909, 4091] {
        for &(start, len) in &windows {
            let window = AddressRange::new(0x500000 + start, len).unwrap();
            for held in [vec![], vec![AddressRange::new(0x501001, 1).unwrap()]] {
                // Enumerate candidate byte addresses only in these small test
                // windows. This is independent of free_pages/argmin helpers.
                let expected = (window.start()..window.end())
                    .filter(|&entry| {
                        let base = entry & !4095;
                        let end = base + 4096;
                        arena
                            .ranges
                            .iter()
                            .any(|r| r.start() <= base && end <= r.end())
                            && !held
                                .iter()
                                .chain(std::iter::once(&source))
                                .any(|r| r.start() < end && base < r.end())
                            && entry - base >= bound as u64
                            && entry - base <= 4091
                    })
                    .min_by_key(|entry| (entry % 4096, *entry));
                let actual = entry_veneer_for_pun(&arena, window, &held, source, bound);
                match expected {
                    Some(entry) => {
                        let actual = actual.unwrap();
                        assert_eq!(actual.entry_address(), entry);
                        assert_eq!(actual.storage_address(), entry & !4095);
                    }
                    None => assert!(matches!(actual, Err(Refusal::AllocationUnavailable))),
                }
            }
        }
    }
}

#[test]
fn entry_veneer_owns_whole_pages_and_refuses_overflow_caps_and_nonfit() {
    let source = AddressRange::new(0x1000, 2).unwrap();
    let arena = policy(None);
    let held = [
        AddressRange::new(0x500001, 1).unwrap(),
        AddressRange::new(0x501fff, 2).unwrap(),
    ];
    let selected = entry_veneer_for_pun(&arena, arena.ranges[0], &held, source, 512).unwrap();
    assert_eq!(selected.entry_address(), 0x503200);
    let source_in_page = AddressRange::new(0x503ffe, 2).unwrap();
    assert!(matches!(
        entry_veneer_for_pun(&arena, arena.ranges[0], &held, source_in_page, 512),
        Err(Refusal::AllocationUnavailable)
    ));
    for bound in [0, 4092, 4096, usize::MAX] {
        assert!(matches!(
            entry_veneer_for_pun(&arena, arena.ranges[0], &[], source, bound),
            Err(Refusal::AllocationUnavailable)
        ));
    }
    let at_end = AddressRange::new(0x500ffb, 1).unwrap();
    assert_eq!(
        entry_veneer_for_pun(&arena, at_end, &[], source, 4091)
            .unwrap()
            .storage_len(),
        4096
    );
    assert!(matches!(
        entry_veneer_for_pun(
            &arena,
            AddressRange::new(0x500ffc, 4).unwrap(),
            &[],
            source,
            1
        ),
        Err(Refusal::AllocationUnavailable)
    ));
    assert!(matches!(
        entry_veneer_for_pun(
            &arena,
            AddressRange::new(0x500200, 1).unwrap(),
            &[],
            source,
            513
        ),
        Err(Refusal::AllocationUnavailable)
    ));
    for change in 0..5 {
        let mut invalid = arena.clone();
        match change {
            0 => invalid.max_candidates = 2,
            1 => invalid.max_mappings = 2,
            2 => invalid.max_mapped_bytes = 8192,
            3 => invalid.ranges = vec![AddressRange::new(0x500001, 4096).unwrap()],
            _ => invalid.ranges = vec![arena.ranges[0]; 17],
        }
        assert!(matches!(
            entry_veneer_for_pun(&invalid, arena.ranges[0], &[], source, 1),
            Err(Refusal::InvalidRange)
        ));
    }
    let edge = AddressRange::new(u64::MAX - 4095, 4095).unwrap();
    assert!(matches!(
        entry_veneer_for_pun(&arena, arena.ranges[0], &[], edge, 512),
        Err(Refusal::InvalidRange)
    ));
    assert!(matches!(
        EntryVeneerPlacement::new(u64::MAX - 4095, u64::MAX - 4, 1),
        Err(Refusal::InvalidRange)
    ));
    assert!(matches!(
        EntryVeneerPlacement::new(0x500001, 0x500f00, 1),
        Err(Refusal::InvalidRange)
    ));
    assert!(matches!(
        EntryVeneerPlacement::new(0x500000, 0x4fffff, 1),
        Err(Refusal::InvalidRange)
    ));
}
