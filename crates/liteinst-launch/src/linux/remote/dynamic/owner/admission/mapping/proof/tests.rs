//! Synthetic map captures and epoch models only. These controls authenticate
//! neither a procfs file/task nor actual mprotect, backing, exclusion or cleanup.
use super::*;

const LOGICAL: &[u8] = b"1000-5000 r-xp 00002000 08:01 7 /fixture  name (deleted) \n9000-b000 rw-p 00000000 00:00 0\n10000-11000 --xp 00000000 00:00 0 [fixed-model]\n";
const CLOSED: &[u8] = b"1000-5000 r--p 00002000 08:01 7 /fixture  name (deleted) \n9000-b000 rw-p 00000000 00:00 0\n10000-11000 --xp 00000000 00:00 0 [fixed-model]\n";
fn parsed(raw: &[u8]) -> ParsedMaps<'_> {
    ParsedMaps::parse(raw, 32).unwrap()
}
fn image(start: u64, end: u64) -> MemoryMapping {
    MemoryMapping {
        start,
        end,
        permissions: "r-xp".into(),
        file_offset: 0x2000 + start - 0x1000,
        pathname: Some("/fixture  name (deleted) ".into()),
    }
}
fn inventory() -> Vec<MemoryMapping> {
    vec![image(0x1000, 0x5000)]
}
fn fail(result: Result<(), GateError>, expected: &'static str) {
    assert!(matches!(result, Err(GateError::Refused(actual)) if actual == expected));
}
fn replace(raw: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    let index = raw.windows(old.len()).position(|part| part == old).unwrap();
    let mut result = raw[..index].to_vec();
    result.extend_from_slice(new);
    result.extend_from_slice(&raw[index + old.len()..]);
    result
}
fn page_rows(mask: u8) -> Vec<u8> {
    let mut raw = Vec::new();
    for page in 0..4 {
        let start = 0x1000_u64 + page * PAGE;
        let mode = if mask & (1 << page) != 0 {
            "r-xp"
        } else {
            "r--p"
        };
        raw.extend_from_slice(
            format!(
                "{start:x}-{:x} {mode} {:08x} 08:01 7 /fixture  name (deleted) \n",
                start + PAGE,
                0x2000 + page * PAGE
            )
            .as_bytes(),
        );
    }
    raw.extend_from_slice(
        b"9000-b000 rw-p 00000000 00:00 0\n10000-11000 --xp 00000000 00:00 0 [fixed-model]\n",
    );
    raw
}

#[test]
fn exact_file_and_anonymous_permission_projection_accepts_real_split_coalesced_geometry() {
    let split = b"1000-2000 r--p 00002000 08:01 7 /fixture  name (deleted) \n2000-4000 r--p 00003000 08:01 7 /fixture  name (deleted) \n4000-5000 r--p 00005000 08:01 7 /fixture  name (deleted) \n9000-b000 rw-p 00000000 00:00 0\n10000-11000 --xp 00000000 00:00 0 [fixed-model]\n";
    check_permission_projection(parsed(split), parsed(LOGICAL), &inventory()).unwrap();
    check_permission_projection(parsed(CLOSED), parsed(&page_rows(15)), &inventory()).unwrap();
    // A retained VMA can become a subrange of a coalesced logical row. Only
    // its exact pages lose X; neither adjacent page is silently included.
    let middle = vec![image(0x2000, 0x4000)];
    check_permission_projection(parsed(&page_rows(9)), parsed(LOGICAL), &middle).unwrap();
    // Anonymous offsets stay exact zero across the kernel's row split. No
    // invented file progression is applied to a no-file mapping.
    let anon_logical = b"20000-24000 r-xp 00000000 00:00 0\n";
    let anon_split = b"20000-22000 r--p 00000000 00:00 0\n22000-24000 r--p 00000000 00:00 0\n";
    let anon = MemoryMapping {
        start: 0x20000,
        end: 0x24000,
        permissions: "r-xp".into(),
        file_offset: 0,
        pathname: None,
    };
    check_permission_projection(parsed(anon_split), parsed(anon_logical), &[anon]).unwrap();
    // Non-UTF8 and internal/trailing pathname bytes remain exactly comparable;
    // parser whitespace before the pathname is only its formatting separator.
    let logical = replace(
        LOGICAL,
        b"/fixture  name (deleted) ",
        b"/fixture\xff  suffix ",
    );
    let closed = replace(
        CLOSED,
        b"/fixture  name (deleted) ",
        b"/fixture\xff  suffix ",
    );
    check_permission_projection(parsed(&closed), parsed(&logical), &inventory()).unwrap();
}

#[test]
fn every_backing_permission_and_path_mutation_is_an_exact_refusal() {
    for (old, new) in [
        (&b"r--p"[..], &b"r-xp"[..]),
        (&b"r--p"[..], &b"rw-p"[..]),
        (&b"r--p"[..], &b"---p"[..]),
        (&b"r--p"[..], &b"r--s"[..]),
        (&b"08:01"[..], &b"09:01"[..]),
        (&b"08:01"[..], &b"08:02"[..]),
        (&b"08:01 7"[..], &b"08:01 8"[..]),
        (&b"00002000"[..], &b"00003000"[..]),
        (&b"/fixture  name"[..], &b"/fixture name"[..]),
        (&b"(deleted) "[..], &b"(deleted)"[..]),
        (&b"/fixture  name (deleted) "[..], &b"/different"[..]),
        (&b"rw-p"[..], &b"rwxp"[..]),
        (&b"--xp"[..], &b"---p"[..]),
    ] {
        let changed = replace(CLOSED, old, new);
        fail(
            check_permission_projection(parsed(&changed), parsed(LOGICAL), &inventory()),
            "quarantine changed a permission, backing or pathname fact",
        );
    }
    // In a split file-backed map the second row must carry the progressed
    // offset. Merely keeping every row's initial offset would change backing.
    let wrong_split = b"1000-3000 r--p 00002000 08:01 7 /fixture  name (deleted) \n3000-5000 r--p 00002000 08:01 7 /fixture  name (deleted) \n9000-b000 rw-p 00000000 00:00 0\n10000-11000 --xp 00000000 00:00 0 [fixed-model]\n";
    fail(
        check_permission_projection(parsed(wrong_split), parsed(LOGICAL), &inventory()),
        "quarantine changed a permission, backing or pathname fact",
    );
    let logical = b"1000-3000 r-xp fffffffffffff000 08:01 7 /overflow\n";
    let closed = b"1000-3000 r--p fffffffffffff000 08:01 7 /overflow\n";
    fail(
        check_permission_projection(parsed(closed), parsed(logical), &[image(0x1000, 0x3000)]),
        "quarantine changed a permission, backing or pathname fact",
    );
}

#[test]
fn full_topology_rejects_missing_extra_shifted_and_interior_hole_intervals() {
    let missing = b"1000-5000 r--p 00002000 08:01 7 /fixture  name (deleted) \n9000-b000 rw-p 00000000 00:00 0\n";
    fail(
        check_permission_projection(parsed(missing), parsed(LOGICAL), &inventory()),
        "quarantine changed mapping topology",
    );
    let extra = [CLOSED, b"20000-21000 r--p 00000000 00:00 0\n"].concat();
    fail(
        check_permission_projection(parsed(&extra), parsed(LOGICAL), &inventory()),
        "quarantine changed mapping topology",
    );
    let shifted = replace(CLOSED, b"1000-5000", b"2000-5000");
    fail(
        check_permission_projection(parsed(&shifted), parsed(LOGICAL), &inventory()),
        "quarantine changed mapping start",
    );
    let hole = b"1000-2000 r--p 00002000 08:01 7 /fixture  name (deleted) \n3000-5000 r--p 00004000 08:01 7 /fixture  name (deleted) \n9000-b000 rw-p 00000000 00:00 0\n10000-11000 --xp 00000000 00:00 0 [fixed-model]\n";
    fail(
        check_permission_projection(parsed(hole), parsed(LOGICAL), &inventory()),
        "quarantine introduced a mapping gap",
    );
    let filled_gap = replace(CLOSED, b"9000-b000", b"5000-b000");
    fail(
        check_permission_projection(parsed(&filled_gap), parsed(LOGICAL), &inventory()),
        "quarantine changed mapping start",
    );
}

#[test]
fn opening_restores_exactly_every_possible_old_executable_page_subset() {
    for mask in 0_u8..16 {
        let old_pages = (0..4)
            .filter(|page| mask & (1 << page) != 0)
            .map(|page| 0x1000 + page * PAGE)
            .collect::<BTreeSet<_>>();
        let before = page_rows(mask);
        compare_projection(
            parsed(&before),
            parsed(LOGICAL),
            &inventory(),
            Some(&old_pages),
        )
        .unwrap();
        // Each single changed page is independently rejected, in both extra-X
        // and missing-X directions. No subset is skipped or called equivalent.
        for page in 0..4 {
            let corrupted = page_rows(mask ^ (1 << page));
            fail(
                compare_projection(
                    parsed(&corrupted),
                    parsed(LOGICAL),
                    &inventory(),
                    Some(&old_pages),
                ),
                "quarantine changed a permission, backing or pathname fact",
            );
        }
    }
    for pages in [
        BTreeSet::from([0x1001]),
        BTreeSet::from([0x5000]),
        BTreeSet::from([0x9000]),
    ] {
        fail(
            compare_projection(parsed(CLOSED), parsed(LOGICAL), &inventory(), Some(&pages)),
            "mapping projection retired page is outside its logical inventory",
        );
    }
}

#[test]
fn absent_malformed_inventory_and_stale_opening_epoch_never_certify_projection() {
    for mut inventory in [
        vec![image(0, 0x5000)],
        vec![image(0x1001, 0x5000)],
        vec![image(0x1000, 0x5001)],
        vec![image(0x5000, 0x5000)],
        vec![image(0x3000, 0x5000), image(0x1000, 0x3000)],
        vec![image(0x1000, 0x4000), image(0x3000, 0x5000)],
        vec![image(0x1000, 0x5000)],
    ] {
        if inventory.len() == 1 && inventory[0].start == 0x1000 && inventory[0].end == 0x5000 {
            inventory[0].permissions = "r--p".into();
        }
        fail(
            check_permission_projection(parsed(CLOSED), parsed(LOGICAL), &inventory),
            "mapping projection inventory is not disjoint logical RX",
        );
    }
    fail(
        check_permission_projection(parsed(CLOSED), parsed(LOGICAL), &[image(0x20000, 0x21000)]),
        "mapping projection logical inventory is absent",
    );
    let nx_logical = replace(LOGICAL, b"r-xp", b"r--p");
    fail(
        check_permission_projection(parsed(CLOSED), parsed(&nx_logical), &inventory()),
        "mapping projection lacks complete logical RX coverage",
    );
    let hole_logical = b"1000-2000 r-xp 00002000 08:01 7 /fixture  name (deleted) \n3000-5000 r-xp 00004000 08:01 7 /fixture  name (deleted) \n9000-b000 rw-p 00000000 00:00 0\n10000-11000 --xp 00000000 00:00 0 [fixed-model]\n";
    fail(
        check_permission_projection(parsed(CLOSED), parsed(hole_logical), &inventory()),
        "mapping projection lacks complete logical RX coverage",
    );
    fn domain() -> Domain {
        let bytes = vec![0x90; 4 * PAGE as usize];
        Domain::new(
            vec![ImageFacts {
                start: 0x1000,
                bytes: bytes.clone(),
                heads: BTreeSet::from([0x1000]),
            }],
            inventory(),
            &DynamicAdmissionOptions::default(),
            Instant::now() + Duration::from_secs(3),
            |pc, len| {
                assert_eq!((pc, len), (0x1000, bytes.len()));
                Ok(bytes.clone())
            },
        )
        .unwrap()
    }
    let mut model = domain();
    assert!(matches!(
        opening_pages(&model),
        Err(GateError::Refused(
            "mapping opening lacks its retained epoch"
        ))
    ));
    let binding = model.source_binding;
    model
        .generations
        .push(super::super::super::domain::RetiredGeneration {
            generation: 0,
            entry_version: 0,
            source_binding: binding,
            executable_pages: BTreeSet::from([0x2000, 0x4000]),
            guards: BTreeMap::new(),
            sites: BTreeMap::new(),
        });
    assert_eq!(
        opening_pages(&model).unwrap(),
        &BTreeSet::from([0x2000, 0x4000])
    );
    let foreign = domain().source_binding;
    for field in 0..3 {
        let old = &mut model.generations[0];
        match field {
            0 => old.generation = 1,
            1 => old.entry_version = 1,
            2 => old.source_binding = foreign,
            _ => unreachable!(),
        }
        assert!(matches!(
            opening_pages(&model),
            Err(GateError::Refused("mapping opening retained epoch differs"))
        ));
        let old = &mut model.generations[0];
        old.generation = 0;
        old.entry_version = 0;
        old.source_binding = binding;
    }
    assert_eq!(
        opening_pages(&model).unwrap(),
        &BTreeSet::from([0x2000, 0x4000])
    );
}
