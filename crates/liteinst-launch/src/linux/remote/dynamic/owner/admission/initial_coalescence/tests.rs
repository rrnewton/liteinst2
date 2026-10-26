//! Supplied-data controls only; no completed native producer is constructed.
use super::*;

const OTHER: &str = "00300000-00301000 r-xp 00000000 09:01 30   /other\n";
const OTHER_NX: &str = "00300000-00301000 r--p 00000000 09:01 30   /other\n";
const LOWER: &str = "00400000-00401000 r--p 00000000 08:02 17    /main a  \n";
const UPPER: &str = "00401000-00402000 r-xp 00001000 08:02 17    /main a  \n";
const UPPER_NX: &str = "00401000-00402000 r--p 00001000 08:02 17    /main a  \n";
const UNION: &str = "00400000-00402000 r--p 00000000 08:02 17    /main a  \n";
const DATA: &str = "00500000-00501000 rw-p 00000000 00:00 0\n";
const ISLAND: &str = "00600000-00601000 r-xp 00000000 00:00 0\n";
const VDSO: &str = "00700000-00701000 r-xp 00000000 00:00 0  [vdso]\n";
const VDSO_NX: &str = "00700000-00701000 r--p 00000000 00:00 0  [vdso]\n";
const VSYSCALL: &str = "ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]\n";
const FILE: (u32, u32, u64) = (8, 2, 17);

fn entry() -> EntryEvidence {
    EntryEvidence {
        first_image: FirstImage::Executable,
        executable_entry: 0x401000,
        interpreter_base: 0,
        initial_instruction: 0x401000,
        interpreter: None,
    }
}

fn original() -> Vec<u8> {
    [OTHER, LOWER, UPPER, DATA, VDSO, VSYSCALL]
        .concat()
        .into_bytes()
}

fn island() -> Range<u64> {
    0x600000..0x601000
}

fn plan(raw: &[u8]) -> InitialMapPlan {
    InitialMapPlan::select(raw, &entry(), FILE)
        .unwrap()
        .unwrap()
}

fn snapshot(prefix: usize, merged: bool) -> Vec<u8> {
    assert!(prefix <= 3);
    let mut lines = vec![if prefix > 0 { OTHER_NX } else { OTHER }];
    if merged {
        lines.push(UNION);
    } else {
        lines.push(LOWER);
        lines.push(if prefix > 1 { UPPER_NX } else { UPPER });
    }
    lines.extend([
        DATA,
        ISLAND,
        if prefix > 2 { VDSO_NX } else { VDSO },
        VSYSCALL,
    ]);
    lines.concat().into_bytes()
}

fn changed(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).unwrap();
    assert_eq!(text.matches(from).count(), 1);
    text.replace(from, to).into_bytes()
}

#[test]
fn initial_pair_plan_preserves_original_extent_spans_and_executable_order() {
    let raw = original();
    let p = plan(&raw);
    assert_eq!(p.original_rows(), 6);
    assert_eq!(p.executable_count(), 3);
    assert_eq!(p.target_executable_ordinal(), 1);
    assert_eq!(p.pair_indices(), (1, 2));
    assert_eq!(p.pair_range(), 0x400000..0x402000);
    assert_eq!(p.rx_range(), 0x401000..0x402000);
    for (span, line) in [(p.pair_spans().0, LOWER), (p.pair_spans().1, UPPER)] {
        assert_eq!(
            &raw[span.0..span.0 + span.1],
            &line.as_bytes()[..line.len() - 1]
        );
    }
}

#[test]
fn initial_pair_inventory_requires_exact_quarantine_prefix_and_target_stage() {
    let raw = original();
    let p = plan(&raw);
    for prefix in 0..=3 {
        let separate = snapshot(prefix, false);
        let proof = p
            .verify_snapshot(&raw, &separate, &island(), prefix)
            .unwrap();
        assert!(!proof.is_merged());
        assert_eq!(proof.cleared_prefix(), prefix);
        assert_eq!(proof.plan(), &p);
        for wrong in 0..=3 {
            if wrong != prefix {
                assert!(
                    p.verify_snapshot(&raw, &separate, &island(), wrong)
                        .is_err()
                );
            }
        }
        let merged = snapshot(prefix, true);
        if prefix > 1 {
            assert!(
                p.verify_snapshot(&raw, &merged, &island(), prefix)
                    .unwrap()
                    .is_merged()
            );
        } else {
            assert!(p.verify_snapshot(&raw, &merged, &island(), prefix).is_err());
        }
    }
    assert!(
        p.verify_snapshot(&raw, &snapshot(3, true), &island(), 4)
            .is_err()
    );
}

#[test]
fn initial_pair_inventory_consumes_every_row_without_count_only_acceptance() {
    let raw = original();
    let p = plan(&raw);
    let final_maps = snapshot(3, true);
    for actual in [
        changed(&final_maps, DATA, ""),
        changed(
            &final_maps,
            DATA,
            "00500000-00501000 r--p 00000000 00:00 0\n",
        ),
        changed(
            &final_maps,
            DATA,
            "00501000-00502000 rw-p 00000000 00:00 0\n",
        ),
        changed(
            &final_maps,
            DATA,
            "00500000-00502000 rw-p 00000000 00:00 0\n",
        ),
        changed(
            &final_maps,
            DATA,
            "00500000-00501000 rw-p 00000000 00:00 0\n00502000-00503000 r--p 00000000 00:00 0\n",
        ),
        changed(
            &final_maps,
            UNION,
            "00400000-00401000 r--p 00000000 08:02 17    /main a  \n00401000-00401800 r--p 00001000 08:02 17    /main a  \n",
        ),
        changed(
            &final_maps,
            UNION,
            "00400000-00403000 r--p 00000000 08:02 17    /main a  \n",
        ),
        changed(&final_maps, OTHER_NX, ""),
        changed(&final_maps, VSYSCALL, ""),
    ] {
        assert!(p.verify_snapshot(&raw, &actual, &island(), 3).is_err());
    }
    let mut truncated = final_maps.clone();
    truncated.pop();
    assert!(p.verify_snapshot(&raw, &truncated, &island(), 3).is_err());
    let mut bad_suffix = final_maps.clone();
    bad_suffix.extend_from_slice(b"broken\n");
    assert!(p.verify_snapshot(&raw, &bad_suffix, &island(), 3).is_err());
}

#[test]
fn initial_pair_inventory_keeps_unrelated_rows_and_all_raw_spelling_exact() {
    let raw = original();
    let p = plan(&raw);
    let final_maps = snapshot(3, true);
    for (from, to) in [
        ("00300000", "002ff000"),
        ("09:01", "9:01"),
        (" 30 ", " 030 "),
        ("30   /", "30    /"),
        ("/other", "/other2"),
        ("[vdso]", "[vvar]"),
        ("17    /", "17   /"),
        ("/main a  ", "/main a "),
        ("08:02", "08:03"),
        (" 17 ", " 18 "),
    ] {
        assert!(
            p.verify_snapshot(&raw, &changed(&final_maps, from, to), &island(), 3)
                .is_err()
        );
    }
    assert!(
        p.verify_snapshot(&raw, &changed(&final_maps, VDSO_NX, VDSO), &island(), 3)
            .is_err()
    );
    assert!(
        p.verify_snapshot(
            &raw,
            &changed(
                &final_maps,
                VSYSCALL,
                "ffffffffff600000-ffffffffff601000 ---p 00000000 00:00 0 [vsyscall]\n"
            ),
            &island(),
            3
        )
        .is_err()
    );
}

#[test]
fn initial_pair_inventory_requires_exact_disjoint_island_identity() {
    let raw = original();
    let p = plan(&raw);
    let final_maps = snapshot(3, true);
    for replacement in [
        "",
        "00600000-00601000 rwxp 00000000 00:00 0\n",
        "00600000-00601000 r--p 00000000 00:00 0\n",
        "00600000-00601000 r-xs 00000000 00:00 0\n",
        "00600000-00601000 r-xp 00001000 00:00 0\n",
        "00600000-00601000 r-xp 00000000 00:01 0\n",
        "00600000-00601000 r-xp 00000000 00:00 1\n",
        "00600000-00601000 r-xp 00000000 00:00 0 [named]\n",
        "00600000-00602000 r-xp 00000000 00:00 0\n",
    ] {
        assert!(
            p.verify_snapshot(
                &raw,
                &changed(&final_maps, ISLAND, replacement),
                &island(),
                3
            )
            .is_err()
        );
    }
    for wrong in [
        0..PAGE,
        0x400000..0x401000,
        0x600001..0x601001,
        0x600000..0x602000,
        USER_END..USER_END + PAGE,
    ] {
        assert!(p.verify_snapshot(&raw, &final_maps, &wrong, 3).is_err());
    }
}

#[test]
fn initial_pair_transition_checks_both_tables_and_unchanged_island_row() {
    let raw = original();
    let p = plan(&raw);
    let before = snapshot(1, false);
    for merged in [false, true] {
        let after = snapshot(2, merged);
        assert_eq!(
            p.verify_transition(&raw, &before, &after, &island())
                .unwrap()
                .is_merged(),
            merged
        );
        for wrong_before in [snapshot(0, false), snapshot(2, false), snapshot(1, true)] {
            assert!(
                p.verify_transition(&raw, &wrong_before, &after, &island())
                    .is_err()
            );
        }
        assert!(
            p.verify_transition(&raw, &before, &snapshot(3, merged), &island())
                .is_err()
        );
        let changed_island = changed(&after, ISLAND, "00600000-00601000 r-xp 00000000 00:00 00\n");
        // Each row is a descriptive anonymous island, but the actual private
        // call cannot change its spelling or any other unrelated raw byte.
        assert!(
            p.verify_snapshot(&raw, &changed_island, &island(), 2)
                .is_ok()
        );
        assert!(
            p.verify_transition(&raw, &before, &changed_island, &island())
                .is_err()
        );
    }
}

#[test]
fn initial_pair_selection_keeps_unsupported_profiles_on_the_strict_path() {
    let raw = original();
    for bad in [
        changed(&raw, LOWER, ""),
        changed(
            &raw,
            LOWER,
            "00400000-00401000 rw-p 00000000 08:02 17    /main a  \n",
        ),
        changed(
            &raw,
            UPPER,
            "00401000-00402000 r-xs 00001000 08:02 17    /main a  \n",
        ),
        changed(
            &raw,
            LOWER,
            "003ff000-00401000 r--p 00000000 08:02 17    /main a  \n",
        ),
        changed(
            &raw,
            UPPER,
            "00401000-00403000 r-xp 00001000 08:02 17    /main a  \n",
        ),
        changed(
            &raw,
            UPPER,
            "00401000-00402000 r-xp 00002000 08:02 17    /main a  \n",
        ),
    ] {
        assert!(
            InitialMapPlan::select(&bad, &entry(), FILE)
                .unwrap()
                .is_none()
        );
    }
    for identity in [(8, 3, 17), (9, 2, 17), (8, 2, 18), (8, 2, 0)] {
        assert!(
            InitialMapPlan::select(&raw, &entry(), identity)
                .unwrap()
                .is_none()
        );
    }
    for field in 0..5 {
        let mut e = entry();
        match field {
            0 => e.first_image = FirstImage::Interpreter,
            1 => e.interpreter = Some("/loader".into()),
            2 => e.interpreter_base = 0x300000,
            3 => e.initial_instruction += 1,
            _ => {
                e.executable_entry = 0x400000;
                e.initial_instruction = 0x400000;
            }
        }
        assert!(InitialMapPlan::select(&raw, &e, FILE).unwrap().is_none());
    }
}

#[test]
fn initial_pair_selection_refuses_multiple_pairs_third_rows_and_visible_aliases() {
    let raw = original();
    let second = "00500000-00501000 r--p 00003000 08:02 17    /main a  \n00501000-00502000 r-xp 00004000 08:02 17    /main a  \n";
    assert!(
        InitialMapPlan::select(&changed(&raw, DATA, second), &entry(), FILE)
            .unwrap()
            .is_none()
    );
    let right = "00402000-00403000 r--p 00002000 8:2 017        /main a  \n";
    let with_right = changed(&raw, DATA, &format!("{right}{DATA}"));
    assert!(
        InitialMapPlan::select(&with_right, &entry(), FILE)
            .unwrap()
            .is_none()
    );
    let shifted = changed(
        &changed(
            &raw,
            LOWER,
            "00400000-00401000 r--p 00001000 08:02 17    /main a  \n",
        ),
        UPPER,
        "00401000-00402000 r-xp 00002000 08:02 17    /main a  \n",
    );
    let left = "003ff000-00400000 r--p 00000000 8:2 017        /main a  \n";
    let with_left = changed(&shifted, OTHER, &format!("{OTHER}{left}"));
    assert!(
        InitialMapPlan::select(&with_left, &entry(), FILE)
            .unwrap()
            .is_none()
    );
    for offset in ["00000000", "00001000"] {
        let alias = format!("00500000-00501000 r--p {offset} 08:02 17 /different-hardlink\n");
        assert!(
            InitialMapPlan::select(&changed(&raw, DATA, &alias), &entry(), FILE)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn initial_pair_projection_preserves_source_scope_and_descriptor_pool_ownership() {
    let raw = original();
    let p = plan(&raw);
    for merged in [false, true] {
        let actual = snapshot(3, merged);
        let projection = p.verify_snapshot(&raw, &actual, &island(), 3).unwrap();
        let view = projection.view(&raw, &actual, &island()).unwrap();
        assert_eq!(view.originals().raw(), raw);
        assert_eq!(view.current().raw(), actual);
        let source = view.source(2).unwrap();
        assert_eq!(source.original.start, 0x401000);
        assert_eq!(source.original.end, 0x402000);
        assert_eq!(source.original.file_offset, 0x1000);
        assert_eq!(
            source.current.start,
            if merged { 0x400000 } else { 0x401000 }
        );
        assert_eq!(source.current.end, 0x402000);
        assert_eq!(source.current.file_offset, if merged { 0 } else { 0x1000 });
        assert_eq!(source.original_index, 2);
        assert_eq!(source.current_index, if merged { 1 } else { 2 });
        assert_eq!(
            &raw[source.original_span.0..source.original_span.0 + source.original_span.1],
            source.original.raw_line
        );
        assert_eq!(
            &actual[source.current_span.0..source.current_span.0 + source.current_span.1],
            source.current.raw_line
        );
        assert!(view.source(1).is_err()); // R header never becomes source.
        assert!(view.source(3).is_err());
        assert!(view.source(5).is_err()); // fixed vsyscall is not quarantined.
        assert!(view.source(6).is_err());
        assert_eq!(view.source(0).unwrap().current_index, 0);
        assert_eq!(
            view.source(4).unwrap().current_index,
            if merged { 4 } else { 5 }
        );
        let expected = if merged {
            vec![Some(0), Some(1), Some(3), None, Some(4), Some(5)]
        } else {
            vec![Some(0), Some(1), Some(2), Some(3), None, Some(4), Some(5)]
        };
        for (index, old) in expected.iter().enumerate() {
            assert_eq!(view.descriptor_pool_index(index).unwrap(), *old);
        }
        assert!(view.descriptor_pool_index(expected.len()).is_err());
    }
}

#[test]
fn initial_pair_projection_revalidation_refuses_forged_derived_metadata() {
    let raw = original();
    let actual = snapshot(3, true);
    let p = plan(&raw)
        .verify_snapshot(&raw, &actual, &island(), 3)
        .unwrap();
    for mutation in 0..29 {
        let mut bad = p;
        match mutation {
            0 => bad.current_rows += 1,
            1 => bad.current_bytes += 1,
            2 => bad.island_index += 1,
            3 => bad.island_span.0 += 1,
            4 => bad.island_span.1 -= 1,
            5 => bad.island.0 += PAGE,
            6 => bad.lower_current_index += 1,
            7 => bad.rx_current_index += 1,
            8 => bad.lower_current_span.0 += 1,
            9 => bad.rx_current_span.1 -= 1,
            10 => bad.merged = false,
            11 => bad.plan.original_rows += 1,
            12 => bad.plan.lower_index += 1,
            13 => bad.plan.upper_span.1 -= 1,
            14 => bad.plan.pair_start -= PAGE,
            15 => bad.plan.lower_offset += PAGE,
            16 => bad.plan.target_executable_ordinal += 1,
            17 => bad.plan.original_bytes += 1,
            18 => bad.plan.executable_count += 1,
            19 => bad.plan.upper_index += 1,
            20 => bad.plan.lower_span.0 += 1,
            21 => bad.plan.upper_span.0 += 1,
            22 => bad.plan.rx_start -= PAGE,
            23 => bad.plan.pair_end += PAGE,
            24 => bad.plan.executable.0 += 1,
            25 => bad.plan.executable.1 += 1,
            26 => bad.plan.executable.2 += 1,
            27 => bad.cleared_prefix -= 1,
            _ => bad.island.1 += PAGE,
        }
        assert!(
            bad.view(&raw, &actual, &island()).is_err(),
            "mutation {mutation}"
        );
    }
    assert!(p.view(&raw, &snapshot(3, false), &island()).is_err());
    assert!(p.view(&raw, &actual, &(0x800000..0x801000)).is_err());
    assert!(
        p.view(&changed(&raw, UPPER, UPPER_NX), &actual, &island())
            .is_err()
    );
}

#[test]
fn initial_pair_inventory_handles_island_before_pair_without_index_aliasing() {
    let raw = original();
    let actual = snapshot(3, true);
    let without = changed(&actual, ISLAND, "");
    let early = b"00200000-00201000 r-xp 00000000 00:00 0\n";
    let actual = [early.as_slice(), &without].concat();
    let p = plan(&raw)
        .verify_snapshot(&raw, &actual, &(0x200000..0x201000), 3)
        .unwrap();
    let view = p.view(&raw, &actual, &(0x200000..0x201000)).unwrap();
    assert_eq!(view.descriptor_pool_index(0).unwrap(), None);
    assert_eq!(view.descriptor_pool_index(1).unwrap(), Some(0));
    assert_eq!(view.descriptor_pool_index(2).unwrap(), Some(1));
    assert_eq!(view.source(0).unwrap().current_index, 1);
    assert_eq!(view.source(2).unwrap().current_index, 2);
    assert_eq!(view.source(4).unwrap().current_index, 4);
}

#[test]
fn initial_pair_plan_rejects_malformed_excessive_and_overflowing_descriptions() {
    let raw = original();
    assert!(InitialMapPlan::select(&raw[..raw.len() - 1], &entry(), FILE).is_err());
    let bad_vsyscall = changed(&raw, "ffffffffff600000", "ffffffffff5ff000");
    assert!(InitialMapPlan::select(&bad_vsyscall, &entry(), FILE).is_err());
    let excessive = vec![b'x'; MAP_BYTES + 1];
    assert!(InitialMapPlan::select(&excessive, &entry(), FILE).is_err());
    let too_many_rows: String = (0..=MAP_ROWS)
        .map(|index| {
            let start = 0x100000_usize + index * 4096;
            format!("{start:08x}-{:08x} r--p 00000000 00:00 0\n", start + 4096)
        })
        .collect();
    assert!(too_many_rows.len() < MAP_BYTES);
    assert!(InitialMapPlan::select(too_many_rows.as_bytes(), &entry(), FILE).is_err());
    let overflow_alias = changed(
        &raw,
        DATA,
        "00500000-00502000 r--p fffffffffffff000 08:02 17 /alias\n",
    );
    assert!(InitialMapPlan::select(&overflow_alias, &entry(), FILE).is_err());
    let high = [
        "0100000000000000-0100000000001000 r--p 00000000 08:02 17 /main\n",
        "0100000000001000-0100000000002000 r-xp 00001000 08:02 17 /main\n",
    ]
    .concat();
    let mut e = entry();
    e.executable_entry = USER_END + PAGE;
    e.initial_instruction = e.executable_entry;
    assert!(
        InitialMapPlan::select(high.as_bytes(), &e, FILE)
            .unwrap()
            .is_none()
    );
}
