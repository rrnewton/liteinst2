//! Supplied-data tests only: no arm, permission changes, signals, or native code.
use super::*;

fn fetch(pc: usize, address: usize) -> Fetch {
    Fetch {
        signal: libc::SIGSEGV,
        code: 2,
        trap: 14,
        error: 0b1_0100,
        pc,
        address,
    }
}

#[test]
fn complete_cross_page_fetch_requires_both_pages() {
    let head = InstructionExtent {
        offset: PAGE - 2,
        len: 5,
        bundle: 0,
    };
    let complete = [PageBundle {
        first_page: 0,
        page_count: 2,
    }];
    let plan = Plan::new(0x100000, 2 * PAGE, &[head], &complete).unwrap();
    assert_eq!(plan.instructions, [head]);
    assert_eq!(plan.bundles, complete);
    assert_eq!(plan.pages, 2);
    for bundle in [
        PageBundle {
            first_page: 0,
            page_count: 1,
        },
        PageBundle {
            first_page: 1,
            page_count: 1,
        },
    ] {
        assert!(Plan::new(0x100000, 2 * PAGE, &[head], &[bundle]).is_err());
    }
}

#[test]
fn boundary_call_fetch_does_not_require_return_page() {
    // Descriptive final E8 extent: ends exactly at the first page boundary.
    // No synthetic CALL is executed and no native completion is constructed.
    let call = InstructionExtent {
        offset: PAGE - 5,
        len: 5,
        bundle: 0,
    };
    let next = InstructionExtent {
        offset: PAGE,
        len: 1,
        bundle: 1,
    };
    let bundles = [
        PageBundle {
            first_page: 0,
            page_count: 1,
        },
        PageBundle {
            first_page: 1,
            page_count: 1,
        },
    ];
    let plan = Plan::new(0x100000, 2 * PAGE, &[call, next], &bundles).unwrap();
    let selected = fetch_instruction(
        0x100000,
        2 * PAGE,
        &plan.instructions,
        fetch(0x100000 + PAGE - 5, 0x100000 + PAGE - 1),
    )
    .unwrap();
    assert_eq!(selected, call);
    assert_eq!(plan.bundles[selected.bundle].page_count, 1);
    assert!(
        fetch_instruction(
            0x100000,
            2 * PAGE,
            &plan.instructions,
            fetch(0x100000 + PAGE - 5, 0x100000 + PAGE)
        )
        .is_none()
    );
}

#[test]
fn metadata_refuses_unbounded_or_incomplete_extents() {
    let head = InstructionExtent {
        offset: 0,
        len: 1,
        bundle: 0,
    };
    let bundle = PageBundle {
        first_page: 0,
        page_count: 1,
    };
    for (base, len) in [
        (0, PAGE),
        (1, PAGE),
        (0x100000, 0),
        (0x100000, PAGE - 1),
        (usize::MAX - PAGE + 1, 2 * PAGE),
    ] {
        assert!(Plan::new(base, len, &[head], &[bundle]).is_err());
    }
    for bad in [
        InstructionExtent { len: 0, ..head },
        InstructionExtent { len: 16, ..head },
        InstructionExtent {
            offset: PAGE,
            ..head
        },
        InstructionExtent { bundle: 1, ..head },
        InstructionExtent {
            offset: usize::MAX,
            len: 2,
            ..head
        },
    ] {
        assert!(Plan::new(0x100000, PAGE, &[bad], &[bundle]).is_err());
    }
    for bad in [
        PageBundle {
            first_page: 0,
            page_count: 0,
        },
        PageBundle {
            first_page: 0,
            page_count: 2,
        },
        PageBundle {
            first_page: usize::MAX,
            page_count: 2,
        },
    ] {
        assert!(Plan::new(0x100000, PAGE, &[head], &[bad]).is_err());
    }
    assert!(Plan::new(0x100000, PAGE, &[], &[bundle]).is_err());
    assert!(Plan::new(0x100000, PAGE, &[head], &[]).is_err());
    assert!(Plan::new(0x100000, PAGE, &[head, head], &[bundle]).is_err());
    assert!(
        Plan::new(
            0x100000,
            PAGE,
            &[InstructionExtent { offset: 1, ..head }, head],
            &[bundle]
        )
        .is_err()
    );
}

#[test]
fn cross_page_fault_authenticates_saved_head_and_fault_extent() {
    let base = 0x100000;
    let head = InstructionExtent {
        offset: PAGE - 2,
        len: 5,
        bundle: 0,
    };
    for address in base + PAGE - 2..base + PAGE + 3 {
        assert_eq!(
            fetch_instruction(base, 2 * PAGE, &[head], fetch(base + PAGE - 2, address)),
            Some(head)
        );
    }
    for pc in [base, base + PAGE - 1, base + PAGE, base + 2 * PAGE] {
        assert!(fetch_instruction(base, 2 * PAGE, &[head], fetch(pc, base + PAGE)).is_none());
    }
    for address in [base - 1, base + PAGE - 3, base + PAGE + 3, base + 2 * PAGE] {
        assert!(
            fetch_instruction(base, 2 * PAGE, &[head], fetch(base + PAGE - 2, address)).is_none()
        );
    }
}

#[test]
fn data_foreign_and_non_native_faults_never_authenticate() {
    let head = InstructionExtent {
        offset: 0,
        len: 1,
        bundle: 0,
    };
    let good = fetch(0x100000, 0x100000);
    assert_eq!(fetch_instruction(0x100000, PAGE, &[head], good), Some(head));
    for bad in [
        Fetch {
            signal: libc::SIGBUS,
            ..good
        },
        Fetch { code: 1, ..good },
        Fetch { code: -6, ..good },
        Fetch { trap: 13, ..good },
        Fetch {
            error: 0b0100,
            ..good
        },
        Fetch {
            error: 0b1_0110,
            ..good
        },
        Fetch {
            error: 0b1_0000,
            ..good
        },
    ] {
        assert!(fetch_instruction(0x100000, PAGE, &[head], bad).is_none());
    }
}

#[test]
fn complete_byte_comparison_rejects_every_changed_position() {
    let expected = [0x90_u8; 2 * PAGE];
    let mut actual = expected;
    assert!(unsafe { bytes_equal(actual.as_ptr(), expected.as_ptr(), expected.len()) });
    for index in 0..actual.len() {
        actual[index] ^= 1;
        assert!(!unsafe { bytes_equal(actual.as_ptr(), expected.as_ptr(), expected.len()) });
        actual[index] ^= 1;
    }
    assert!(unsafe { bytes_equal(actual.as_ptr(), expected.as_ptr(), expected.len()) });
}
