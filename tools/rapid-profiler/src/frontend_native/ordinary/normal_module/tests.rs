use super::*;

#[test]
fn pair_selection_requires_same_final_bytes_and_canonical_disjoint_extents() {
    let bytes = [0u8; 32];
    let equal = bytes;
    let a = TrustedFunctionSelection::new(&bytes, 0x1000, 16, "a").unwrap();
    let b = TrustedFunctionSelection::new(&equal, 0x1010, 16, "b").unwrap();
    assert_eq!(check_selections([&a, &b]), Ok(()));
    assert_eq!(check_selections([&b, &a]), Err(SetupRefusal::EntryExit));
    assert_eq!(check_selections([&a, &a]), Err(SetupRefusal::EntryExit));
    let overlap = TrustedFunctionSelection::new(&bytes, 0x100f, 16, "overlap").unwrap();
    assert_eq!(
        check_selections([&a, &overlap]),
        Err(SetupRefusal::EntryExit)
    );
    let other = TrustedFunctionSelection::new(&[1; 32], 0x1010, 16, "b").unwrap();
    assert_eq!(
        check_selections([&a, &other]),
        Err(SetupRefusal::SourceBytes)
    );
    let valid = NormalModuleContract {
        single_external_entry_per_function: true,
        sequential_call_ret_only: true,
        no_active_cet: true,
    };
    assert_eq!(valid.check(), Ok(()));
    assert_eq!(
        NormalModuleContract {
            single_external_entry_per_function: false,
            ..valid
        }
        .check(),
        Err(SetupRefusal::EntryExit)
    );
    assert_eq!(
        NormalModuleContract {
            sequential_call_ret_only: false,
            ..valid
        }
        .check(),
        Err(SetupRefusal::ExitSemantics)
    );
    assert_eq!(
        NormalModuleContract {
            no_active_cet: false,
            ..valid
        }
        .check(),
        Err(SetupRefusal::Cet)
    );
}

#[test]
fn canonical_union_deduplicates_exact_pages_and_refuses_conflict_or_third_page() {
    let first = vec![1; 4096];
    let second = vec![2; 4096];
    let both = [first.clone(), second.clone()].concat();
    let pages = canonical_pages([(0x1000, &both), (0x2000, &second)]).unwrap();
    assert_eq!(
        pages,
        [
            ExpectedBytes {
                address: 0x1000,
                bytes: first.clone()
            },
            ExpectedBytes {
                address: 0x2000,
                bytes: second.clone()
            }
        ]
    );
    assert_eq!(
        canonical_pages([(0x1000, &first), (0x1000, &first)])
            .unwrap()
            .len(),
        1
    );
    let mut bad = second.clone();
    bad[4095] ^= 1;
    assert_eq!(
        canonical_pages([(0x1000, &both), (0x2000, &bad)]),
        Err(SetupRefusal::SourceBytes)
    );
    assert_eq!(
        canonical_pages([(0x1000, &both), (0x3000, &second)]),
        Err(SetupRefusal::Format)
    );
    let sparse = canonical_pages([(0x5000, &second), (0x1000, &first)]).unwrap();
    assert_eq!(
        sparse.iter().map(|p| p.address).collect::<Vec<_>>(),
        [0x1000, 0x5000]
    );
    assert_eq!(sparse.iter().map(|p| p.bytes.len()).sum::<usize>(), 8192);
    assert_eq!(
        canonical_pages([(0x1001, &first), (0x5000, &second)]),
        Err(SetupRefusal::Format)
    );
    assert_eq!(
        canonical_pages([(!4095_u64, &first), (0x5000, &second)]),
        Err(SetupRefusal::Format)
    );
    assert_eq!(
        canonical_pages([(0x1000, &first[..4095]), (0x5000, &second)]),
        Err(SetupRefusal::Format)
    );
}

#[test]
fn final_union_checks_both_body_overlays_and_every_untouched_byte() {
    let first = vec![0xa5; 4096];
    let second = vec![0x5a; 4096];
    let originals = canonical_pages([(0x1000, &first), (0x2000, &second)]).unwrap();
    let bodies = [(0x1010, 0x1020), (0x2010, 0x2020)];
    let mut expected = originals.clone();
    expected[0].bytes[16..32].fill(0xcc);
    expected[1].bytes[16..32].fill(0xdd);
    assert_eq!(check_overlay(&originals, &expected, bodies), Ok(()));
    for (page, offset) in [(0, 15), (0, 32), (1, 0), (1, 4095)] {
        let mut bad = expected.clone();
        bad[page].bytes[offset] ^= 1;
        assert_eq!(
            check_overlay(&originals, &bad, bodies),
            Err(SetupRefusal::SourceBytes)
        );
    }
    assert_eq!(
        check_overlay(&originals, &expected[..1], bodies),
        Err(SetupRefusal::SourceBytes)
    );
    let mut shifted = expected.clone();
    shifted[1].address += 4096;
    assert_eq!(
        check_overlay(&originals, &shifted, bodies),
        Err(SetupRefusal::SourceBytes)
    );
    let mut short = expected;
    short[1].bytes.pop();
    assert_eq!(
        check_overlay(&originals, &short, bodies),
        Err(SetupRefusal::SourceBytes)
    );
}
