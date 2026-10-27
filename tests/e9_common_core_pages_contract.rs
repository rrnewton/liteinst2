//! Pure page-view controls execute once, outside shared native oracle consumers.
//! These fixtures are byte arrays, not ELF admission or native replay results.
#[path = "support/e9_common_core_pages.rs"]
mod pages;

use pages::{IMAGE_END, IMAGE_START, LOADS, PAGE, Page, materialize_load_pages};

type Load = (u64, u64, u64, u64, u32);

fn fixture() -> Vec<u8> {
    (0..0x30000_usize)
        .map(|i| (i.wrapping_mul(17) ^ (i >> 8)) as u8)
        .collect()
}

fn loads(extra: &[Load]) -> Vec<Load> {
    let mut all = LOADS.to_vec();
    all.extend_from_slice(extra);
    all
}

fn original(elf: &[u8], base: &[u8]) {
    // Independent byte oracle for the four fixed tuples, including full file
    // page prefixes/suffixes and the last LOAD's BSS through its rounded end.
    assert_eq!(
        LOADS,
        [
            (0, 0x400000, 0x8b0, 0x8b0, 4),
            (0x1000, 0x401000, 0xa51, 0xa51, 5),
            (0x2000, 0x402000, 0xe1c, 0xe1c, 4),
            (0x3e00, 0x403e00, 0x20358, 0x20390, 6),
        ]
    );
    assert_eq!((IMAGE_START, IMAGE_END), (0x400000, 0x425000));
    assert_eq!(base.len(), 37 * PAGE);
    let mut expected = vec![0; 37 * PAGE];
    expected[..0x24158].copy_from_slice(&elf[..0x24158]);
    assert_eq!(base, expected);
}

fn view(actual: &Page, address: u64, flags: u32, expected: &[u8]) {
    assert_eq!((actual.address, actual.flags), (address, flags));
    assert_eq!(actual.bytes.len(), PAGE);
    assert_eq!(actual.bytes, expected);
}

fn refuses(elf: &[u8], all: Vec<Load>, expected: &str) {
    let failure = std::panic::catch_unwind(|| materialize_load_pages(elf, all))
        .err()
        .expect("invalid complete page view was accepted");
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .expect("page refusal must carry its original assertion or checked-bound panic");
    assert!(
        message.contains(expected),
        "wrong refusal: {message:?}; expected {expected:?}"
    );
}

#[test]
fn mixed_load_order_retains_full_original_pages_and_generated_zero_tail() {
    let elf = fixture();
    let (base, extra) = materialize_load_pages(
        &elf,
        loads(&[
            (0x26000, 0x440000, 0x1000, 0x1000, 4),
            (0x27000, 0x3fe000, 0x1010, 0x1080, 5),
        ]),
    );
    original(&elf, &base);
    assert_eq!(extra.len(), 3);
    // PT_LOAD order is intentionally neither ascending nor descending by VA.
    view(&extra[0], 0x440000, 4, &elf[0x26000..0x27000]);
    view(&extra[1], 0x3fe000, 5, &elf[0x27000..0x28000]);
    let mut tail = vec![0; PAGE];
    tail[..16].copy_from_slice(&elf[0x28000..0x28010]);
    view(&extra[2], 0x3ff000, 5, &tail);
}

#[test]
fn half_open_original_window_preserves_high_only_and_both_adjacent_pages() {
    let elf = fixture();
    let (base, extra) = materialize_load_pages(&elf, LOADS.to_vec());
    original(&elf, &base);
    assert!(extra.is_empty());
    let (base, high) =
        materialize_load_pages(&elf, loads(&[(0x26000, 0x425000, 0x1000, 0x1000, 5)]));
    original(&elf, &base);
    assert_eq!(high.len(), 1);
    view(&high[0], 0x425000, 5, &elf[0x26000..0x27000]);
    let (base, both) = materialize_load_pages(
        &elf,
        loads(&[
            (0x26000, 0x425000, 0x1000, 0x1000, 5),
            (0x27000, 0x3ff000, 0x1000, 0x1000, 4),
        ]),
    );
    original(&elf, &base);
    assert_eq!(both.len(), 2);
    view(&both[0], 0x425000, 5, &high[0].bytes);
    view(&both[1], 0x3ff000, 4, &elf[0x27000..0x28000]);
    // Exact last file byte suffices; all remaining original BSS is zero.
    let (base, extra) = materialize_load_pages(&elf[..0x24158], LOADS.to_vec());
    original(&elf, &base);
    assert!(extra.is_empty());
}

#[test]
fn missing_changed_reordered_or_extra_original_owners_refuse() {
    let elf = fixture();
    refuses(&elf, LOADS[..3].to_vec(), "loads.len() >= LOADS.len()");
    let mut swapped = LOADS.to_vec();
    swapped.swap(0, 1);
    refuses(&elf, swapped, "assertion `left == right` failed");
    for i in 0..4 {
        for field in 0..5 {
            let mut changed = LOADS.to_vec();
            let row = &mut changed[i];
            match field {
                0 => row.0 += 4096,
                1 => row.1 += 4096,
                2 => row.2 += 1,
                3 => row.3 += 1,
                4 => row.4 ^= 1,
                _ => unreachable!(),
            }
            refuses(&elf, changed, "assertion `left == right` failed");
        }
    }
    refuses(
        &elf[..0x24157],
        LOADS.to_vec(),
        "offset.checked_add(fs).unwrap() <= elf.len() as u64",
    );
    refuses(&elf, loads(&[LOADS[3]]), "seen.insert(page)");
}

#[test]
fn original_overlap_and_lower_straddle_refuse() {
    let elf = fixture();
    for row in [
        (0x26000, 0x400000, 0x1000, 0x1000, 5),
        (0x26000, 0x424000, 0x1000, 0x1000, 4),
        (0x26800, 0x3ff800, 0x801, 0x801, 5),
    ] {
        refuses(&elf, loads(&[row]), "seen.insert(page)");
    }
}

#[test]
fn generated_exact_and_rounded_overlap_refuse() {
    let elf = fixture();
    for pair in [
        [
            (0x26000, 0x3fe000, 0x100, 0x100, 5),
            (0x27000, 0x3fe000, 0x100, 0x100, 4),
        ],
        [
            (0x26100, 0x3fe100, 0x100, 0x100, 5),
            (0x27300, 0x3fe300, 0x100, 0x100, 4),
        ],
    ] {
        refuses(&elf, loads(&pair), "seen.insert(page)");
    }
}

#[test]
fn generated_permissions_remain_read_or_read_execute() {
    let elf = fixture();
    for flags in [4, 5] {
        let (base, extra) =
            materialize_load_pages(&elf, loads(&[(0x26100, 0x3fe100, 0x80, 0x80, flags)]));
        original(&elf, &base);
        assert_eq!(extra.len(), 1);
        // Whole file-page prefix/suffix are kept even outside the byte interval.
        view(&extra[0], 0x3fe000, flags, &elf[0x26000..0x27000]);
    }
    for address in [0x3fe000, 0x440000] {
        refuses(&elf, loads(&[(0x26000, address, 1, 1, 6)]), "flags != 6");
    }
    for flags in [0, 7] {
        refuses(
            &elf,
            loads(&[(0x26000, 0x3fe000, 1, 1, flags)]),
            "matches!(flags, 4..=6)",
        );
    }
}

#[test]
fn generated_page_and_load_count_limits_remain_exact() {
    let elf = fixture();
    let (base, extra) = materialize_load_pages(
        &elf,
        loads(&[
            (0x26000, 0x10000, 1, 1, 5),
            (0x27000, 0x800000, 0, 2047 * 4096, 4),
        ]),
    );
    original(&elf, &base);
    assert_eq!(extra.len(), 2048);
    view(&extra[0], 0x10000, 5, &elf[0x26000..0x27000]);
    for (i, page) in extra[1..].iter().enumerate() {
        assert_eq!((page.address, page.flags), (0x800000 + i as u64 * 4096, 4));
        assert_eq!(page.bytes, vec![0; PAGE]);
    }
    drop(extra);
    refuses(
        &elf,
        loads(&[
            (0x26000, 0x10000, 1, 1, 5),
            (0x27000, 0x800000, 0, 2048 * 4096, 4),
        ]),
        "pages.len() <= 2048",
    );
    let mut all = LOADS.to_vec();
    for i in 0..257 {
        all.push((0x26000, 0x1000000 + i * 4096, 1, 1, 4));
    }
    let (base, extra) = materialize_load_pages(&elf, all.clone());
    original(&elf, &base);
    assert_eq!(all.len(), 261);
    assert_eq!(extra.len(), 257);
    all.push((0x26000, 0x1000000 + 257 * 4096, 1, 1, 4));
    refuses(&elf, all, "loads.len() <= 261");
}

#[test]
fn whole_union_span_includes_lower_pages_and_keeps_exact_limit() {
    let elf = fixture();
    let (base, extra) = materialize_load_pages(
        &elf,
        loads(&[(0x26000, 0x10000, 1, 1, 4), (0x27000, 0x4000f000, 1, 1, 5)]),
    );
    original(&elf, &base);
    assert_eq!(extra.len(), 2);
    view(&extra[0], 0x10000, 4, &elf[0x26000..0x27000]);
    view(&extra[1], 0x4000f000, 5, &elf[0x27000..0x28000]);
    assert_eq!(extra[1].address + 4096 - extra[0].address, 1_073_741_824);
    refuses(
        &elf,
        loads(&[(0x26000, 0x10000, 1, 1, 4), (0x27000, 0x40010000, 1, 1, 5)]),
        "seen.last().unwrap() + 4096 - seen.first().unwrap() <= 1_073_741_824",
    );
}

#[test]
fn file_geometry_and_address_endpoint_refusals_remain() {
    let elf = fixture();
    for row in [
        (0x26000, 0x3fe000, 2, 1, 5),
        (elf.len() as u64, 0x3fe000, 1, 1, 5),
    ] {
        refuses(&elf, loads(&[row]), "matches!(flags, 4..=6)");
    }
    refuses(
        &elf,
        loads(&[(0x26001, 0x3fe000, 1, 1, 5)]),
        "assertion `left == right` failed",
    );
    for row in [
        (u64::MAX, 0x3fefff, 2, 2, 5),
        (0x26000, u64::MAX - 4095, 0, 4096, 5),
        (0x26fff, u64::MAX, 0, 0, 5),
    ] {
        refuses(
            &elf,
            loads(&[row]),
            "called `Option::unwrap()` on a `None` value",
        );
    }
    refuses(&elf, loads(&[(0x26000, 1 << 47, 1, 1, 5)]), "hi <= 1 << 47");
}

#[test]
fn interleaved_original_owners_keep_full_bytes_bss_and_generated_order() {
    let elf = fixture();
    let low = (0x26000, 0x10000, 0x1000, 0x1000, 5);
    let high = (0x27000, 0x440000, 0x1010, 0x1080, 4);
    for all in [
        vec![low, LOADS[0], LOADS[1], high, LOADS[2], LOADS[3]],
        vec![LOADS[0], high, LOADS[1], LOADS[2], low, LOADS[3]],
        vec![high, low, LOADS[0], LOADS[1], LOADS[2], LOADS[3]],
    ] {
        let expected_order: Vec<_> = all
            .iter()
            .filter(|row| row.1 == low.1 || row.1 == high.1)
            .map(|row| row.1)
            .collect();
        let (base, extra) = materialize_load_pages(&elf, all);
        original(&elf, &base);
        assert_eq!(extra.len(), 3);
        let mut i = 0;
        for address in expected_order {
            if address == low.1 {
                view(&extra[i], low.1, 5, &elf[0x26000..0x27000]);
                i += 1;
            } else {
                view(&extra[i], high.1, 4, &elf[0x27000..0x28000]);
                let mut tail = vec![0; PAGE];
                tail[..16].copy_from_slice(&elf[0x28000..0x28010]);
                view(&extra[i + 1], high.1 + 4096, 4, &tail);
                i += 2;
            }
        }
        assert_eq!(i, extra.len());
    }
}

#[test]
fn interleaved_missing_changed_reordered_duplicate_originals_refuse() {
    let elf = fixture();
    let all = vec![
        (0x26000, 0x10000, 1, 1, 5),
        LOADS[0],
        LOADS[1],
        LOADS[2],
        LOADS[3],
    ];
    for i in 1..5 {
        let mut missing = all.clone();
        missing.remove(i);
        refuses(&elf, missing, "assertion `left == right` failed");
        for field in 0..5 {
            let mut changed = all.clone();
            let row = &mut changed[i];
            match field {
                0 => row.0 += 4096,
                1 => row.1 += 4096,
                2 => row.2 += 1,
                3 => row.3 += 1,
                4 => row.4 ^= 1,
                _ => unreachable!(),
            }
            refuses(&elf, changed, "assertion `left == right` failed");
        }
    }
    let mut swapped = all.clone();
    swapped.swap(1, 2);
    refuses(&elf, swapped, "assertion `left == right` failed");
    let mut duplicate = all.clone();
    duplicate.push(LOADS[3]);
    refuses(&elf, duplicate, "seen.insert(page)");
    let mut empty_duplicate = all;
    empty_duplicate.push((0, LOADS[0].1, 0, 0, 4));
    refuses(&elf, empty_duplicate, "assertion `left == right` failed");
}

#[test]
fn interleaved_old_bss_generated_overlap_and_writable_pages_refuse() {
    let elf = fixture();
    let low = (0x26000, 0x10000, 1, 1, 5);
    for extra in [
        (0x27000, 0x424000, 0x1000, 0x1000, 4),
        (0x27800, 0x3ff800, 0x801, 0x801, 5),
        (0x27000, 0x10000, 1, 1, 4),
    ] {
        refuses(
            &elf,
            vec![low, LOADS[0], LOADS[1], extra, LOADS[2], LOADS[3]],
            "seen.insert(page)",
        );
    }
    refuses(
        &elf,
        vec![
            (0x26000, 0x10000, 1, 1, 6),
            LOADS[0],
            LOADS[1],
            LOADS[2],
            LOADS[3],
        ],
        "flags != 6",
    );
}
