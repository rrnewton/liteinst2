//! Fabricated original bytes, importer, parser and offline planner only.
use super::*;

const BASE: u64 = 0x400000;
const PC: u64 = BASE + 0x1100;
const HOOK: u64 = BASE + 0x11f00;
fn put(b: &mut [u8], at: usize, width: usize, value: u64) {
    b[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn digest(bytes: &[u8]) -> String {
    ledger::hex(&ContentId::of(bytes).0)
}
fn fixture(jumps: usize, nops: usize) -> (Vec<u8>, String) {
    let mut original = vec![0; 0x12000];
    original[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at, width, value) in [
        (16, 2, 2),
        (18, 2, 62),
        (20, 4, 1),
        (24, 8, PC),
        (32, 8, 64),
        (52, 2, 64),
        (54, 2, 56),
        (56, 2, 2),
    ] {
        put(&mut original, at, width, value);
    }
    for (i, (offset, size, flags)) in [(0, 4096, 4), (4096, 0x11000, 5)].into_iter().enumerate() {
        for (field, width, value) in [
            (0, 4, 1),
            (4, 4, flags),
            (8, 8, offset),
            (16, 8, BASE + offset),
            (24, 8, BASE + offset),
            (32, 8, size),
            (40, 8, size),
            (48, 8, 4096),
        ] {
            put(&mut original, 64 + 56 * i + field, width, value);
        }
    }
    let mut chunks = vec![vec![0xf3, 0x0f, 0x1e, 0xfa]];
    chunks.extend((0..nops).map(|_| vec![0x90]));
    chunks.extend((0..jumps).map(|_| vec![0x75, 0]));
    chunks.push(vec![0xc3]);
    let code: Vec<_> = chunks.iter().flatten().copied().collect();
    assert!(code.len() < (HOOK - PC) as usize);
    original[0x1100..0x1100 + code.len()].copy_from_slice(&code);
    original[0x11f00] = 0xc3;
    let mut text = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {PC} 4352 {}\n",
        digest(&original),
        code.len()
    );
    let mut pc = PC;
    for chunk in chunks {
        writeln!(text, "head {pc} {}", ledger::hex(&chunk)).unwrap();
        pc += chunk.len() as u64;
    }
    writeln!(text, "region {HOOK} 73472 1\nhead {HOOK} c3").unwrap();
    (original, text)
}
fn imported(original: &[u8], text: &str) -> Disassembly {
    import(original, text.as_bytes(), ContentId::of(text.as_bytes())).unwrap()
}
fn policy(original: &[u8], text: &str, count: usize) -> String {
    let mut out = format!(
        "{POLICY_HEADER}\noriginal {}\nledger {}\ntarget fxsave64\ndomain 1\ncarrier {}\nlimits 1048576 4096 4096 65536 64 1048576 262144 64 4294967296\nnull-hook {HOOK}\n",
        digest(original),
        digest(text.as_bytes()),
        BASE + 0x20000
    );
    for id in 1..=count {
        let selected = BASE + 0x4000000 + id as u64 * 0x4000;
        let victim = BASE + 0x6000000 + id as u64 * 0x4000;
        writeln!(out, "search {id} B1 0 80 1 none 64 256\nallocation {id} selected {selected} 256 8192 {selected}:8192\nallocation {id} victim {victim} 256 8192 {victim}:8192").unwrap();
    }
    out
}
fn bind(original: &[u8], text: &str, p: &str) -> Result<WholeProgramSelection, Error> {
    imported(original, text).bind_whole_program(p.as_bytes(), ContentId::of(p.as_bytes()))
}
fn parse(text: &[u8], imported: &Disassembly) -> Result<Selection, Error> {
    let regions = imported.shared_regions()?;
    selection::parse_shared_projection(
        text,
        &selection::SharedEntries {
            original: imported.original,
            ledger: ContentId::of(&imported.ledger),
            regions: &regions,
            sites: &imported.jumps,
            null_hook: HOOK,
        },
    )
}

#[test]
fn whole_shared_roundtrip_keeps_complete_heads_and_actual_prepare_path() {
    let (original, text) = fixture(2, 3);
    let p = policy(&original, &text, 2);
    let checked = imported(&original, &text);
    let selected = bind(&original, &text, &p).unwrap();
    assert_eq!(selected.profile(), PROFILE);
    let reparsed = parse(selected.manifest(), &checked).unwrap();
    assert_eq!(reparsed.manifest, selected.manifest());
    assert_eq!(reparsed.sites.len(), 2);
    assert!(Arc::ptr_eq(
        &reparsed.sites[0].heads,
        &reparsed.sites[1].heads
    ));
    assert_eq!(reparsed.sites[0].heads.len(), 7);
    assert!(reparsed.sites[0].heads[0].requires_endbr);
    for (site, decoded) in reparsed.sites.iter().zip(checked.jumps()) {
        assert_eq!(
            (site.id, site.pc, site.length as usize, site.file_offset),
            (decoded.id, decoded.pc, decoded.length, decoded.file_offset)
        );
        assert_eq!(site.completeness, EntryCompleteness::AllInstructionHeads);
        assert_eq!(site.provenance, ContentId::of(text.as_bytes()));
        assert_eq!(
            site.resumes,
            li2core::contracts::ResumeObligation::NoneExist
        );
    }
    let manifest = std::str::from_utf8(selected.manifest()).unwrap();
    assert_eq!(
        manifest
            .lines()
            .filter(|l| l.starts_with("region-entries "))
            .count(),
        2
    );
    assert_eq!(
        manifest
            .lines()
            .filter(|l| l.starts_with("entries-ref "))
            .count(),
        2
    );
    assert!(!manifest.lines().any(|l| l.starts_with("entries ")));
    assert!(selection::parse(selected.manifest()).is_err());
    assert!(
        imported(&original, &text)
            .bind(p.as_bytes(), ContentId::of(p.as_bytes()))
            .is_err()
    );
    assert!(
        bind(
            &original,
            &text,
            &p.replace(POLICY_HEADER, "LI2DISASM-POLICY 1")
        )
        .is_err()
    );
    let product = crate::prepare_disassembly_whole(&original, &selected).unwrap();
    assert_eq!(product.reports().len(), 2);
    assert!(!product.qualification_complete());
    assert_eq!(
        product.files()["planning-profile.tsv"],
        selected.files["planning-profile.tsv"]
    );
    let mut changed = original.clone();
    changed[0x200] ^= 1;
    assert!(crate::prepare_disassembly_whole(&changed, &selected).is_err());
}

#[test]
fn whole_shared_projection_refuses_head_reference_order_and_provenance_changes() {
    let (original, text) = fixture(2, 3);
    let checked = imported(&original, &text);
    let selected = bind(&original, &text, &policy(&original, &text, 2)).unwrap();
    let manifest = std::str::from_utf8(selected.manifest()).unwrap();
    let region = manifest
        .lines()
        .find(|l| l.starts_with("region-entries 1 "))
        .unwrap();
    let hook_region = manifest
        .lines()
        .find(|l| l.starts_with("region-entries 2 "))
        .unwrap();
    let first_site = manifest.lines().find(|l| l.starts_with("site 1 ")).unwrap();
    let second_site = manifest.lines().find(|l| l.starts_with("site 2 ")).unwrap();
    let h0 = format!("{PC}:1");
    let h1 = format!("{}:0", PC + 4);
    let wrong_hash = "0".repeat(64);
    let mutations = [
        manifest.replace(&h0, &format!("{PC}:0")),
        manifest.replace(&format!(" {h0}"), ""),
        manifest.replace(&h0, &format!("{h0} {h0}")),
        manifest.replace(&format!("{h0} {h1}"), &format!("{h1} {h0}")),
        manifest.replace(&h1, &format!("{}:0", PC + 5)),
        manifest.replace(&format!("{hook_region}\n"), ""),
        manifest.replace(region, &format!("{region}\n{region}")),
        manifest.replace(region, "region-entries 1"),
        manifest.replace(
            &format!("{region}\n{hook_region}"),
            &format!("{hook_region}\n{region}"),
        ),
        manifest.replace("entries-ref 1 1", "entries-ref 1 2"),
        manifest.replace("entries-ref 1 1", "entries-ref 1 0"),
        manifest.replace("entries-ref 1 1", "entries-ref 1 3"),
        manifest.replace("entries-ref 1 1\n", ""),
        manifest.replace("entries-ref 1 1", "entries-ref 1 1\nentries-ref 1 1"),
        manifest.replace(&format!("{second_site}\n"), ""),
        manifest.replace(
            first_site,
            &first_site.replacen(" observe ", " replace ", 1),
        ),
        manifest.replace(&digest(text.as_bytes()), &wrong_hash),
        manifest.replace(&digest(&original), &wrong_hash),
        manifest.replace(&format!("hook 1 {HOOK} 1 "), &format!("hook 1 {PC} 1 ")),
        manifest.replace("resumes 1 none", "resumes 1 unknown"),
        manifest.replace("entries-ref 1 1", "entries 1 complete 00 1:0"),
        manifest.replace("\noriginal ", "\n\noriginal "),
        manifest.replace("\noriginal ", "\noriginal  "),
        manifest.replace('\n', "\r\n"),
        manifest.trim_end().to_owned(),
    ];
    for bad in mutations {
        assert_ne!(bad, manifest);
        assert!(parse(bad.as_bytes(), &checked).is_err(), "accepted {bad}");
    }
    let mut lines: Vec<_> = manifest.lines().collect();
    let a = lines.iter().position(|l| l.starts_with("site 1 ")).unwrap();
    let b = lines.iter().position(|l| l.starts_with("site 2 ")).unwrap();
    lines.swap(a, b);
    assert!(parse((lines.join("\n") + "\n").as_bytes(), &checked).is_err());
    let mut lines: Vec<_> = manifest.lines().collect();
    let a = lines
        .iter()
        .position(|l| l.starts_with("entries-ref 1 "))
        .unwrap();
    let b = lines
        .iter()
        .position(|l| l.starts_with("entries-ref 2 "))
        .unwrap();
    lines.swap(a, b);
    assert!(parse((lines.join("\n") + "\n").as_bytes(), &checked).is_err());
}

#[test]
fn whole_shared_complete_population_caps_and_policy_guards_are_not_subsets() {
    let (original, text) = fixture(2053, 0);
    let p = policy(&original, &text, 2053);
    let selected = bind(&original, &text, &p).unwrap();
    assert_eq!(selected.selection.sites.len(), 2053);
    assert!(
        selected
            .selection
            .sites
            .iter()
            .all(|s| Arc::ptr_eq(&selected.selection.sites[0].heads, &s.heads))
    );
    assert_eq!(selected.selection.sites[0].heads.len(), 2055);
    assert!(selected.manifest().len() < SELECTION_LIMIT);
    assert!(
        imported(&original, &text)
            .bind(
                p.replace(POLICY_HEADER, "LI2DISASM-POLICY 1").as_bytes(),
                ContentId::of(p.replace(POLICY_HEADER, "LI2DISASM-POLICY 1").as_bytes())
            )
            .is_err()
    );
    for count in [SITE_LIMIT, SITE_LIMIT + 1] {
        let (o, l) = fixture(count, 0);
        let p = policy(&o, &l, if count == SITE_LIMIT { count } else { 0 });
        assert_eq!(bind(&o, &l, &p).is_ok(), count == SITE_LIMIT);
    }
    for count in [HEAD_LIMIT, HEAD_LIMIT + 1] {
        let (o, l) = fixture(1, count - 4);
        assert_eq!(
            imported(&o, &l)
                .regions
                .iter()
                .map(|r| r.instructions.len())
                .sum::<usize>(),
            count
        );
        let p = policy(&o, &l, 1);
        assert_eq!(bind(&o, &l, &p).is_ok(), count == HEAD_LIMIT);
    }
    let (o, l) = fixture(2, 0);
    let p = policy(&o, &l, 2);
    for bad in [
        p.replace("search 2 B1 0 80 1 none 64 256\n", ""),
        p.replace("limits 1048576 4096", "limits 1048576 4097"),
        p.replace("null-hook ", "hook "),
        p.clone() + "search 3 B1 0 80 1 none 64 256\n",
        p.replace("B1 0 80 1 none 64 256", "B1 0 80 1 none 64 1048577"),
        p.replace(" 256 8192 ", " 65537 8192 "),
    ] {
        assert!(bind(&o, &l, &bad).is_err());
    }
    assert!(
        imported(&o, &l)
            .bind_whole_program(p.as_bytes(), ContentId([0; 32]))
            .is_err()
    );
    assert!(
        imported(&o, &l)
            .bind_whole_program(&vec![b'x'; TEXT_LIMIT + 1], ContentId([0; 32]))
            .is_err()
    );
    let mut edge = "x".repeat(SELECTION_LIMIT - 1);
    append(&mut edge, "x").unwrap();
    assert!(append(&mut edge, "x").is_err());
    assert_eq!(edge.len(), SELECTION_LIMIT);
    assert!(parse(&vec![b'x'; SELECTION_LIMIT + 1], &imported(&o, &l)).is_err());
}

fn long_ownership_fixture() -> (Vec<u8>, String, String) {
    let (mut original, _) = fixture(2, 0);
    let mut chunks = vec![vec![0x75, 0], vec![0xc3]];
    chunks.extend((3..16).map(|_| vec![0x90]));
    chunks.push(vec![
        0x48, 0xb8, 0x37, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97,
    ]);
    chunks.extend((26..30).map(|_| vec![0x90]));
    chunks.push(vec![0x75, 0]);
    chunks.push(vec![
        0x48, 0xb8, 0x27, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97,
    ]);
    chunks.push(vec![0xc3]);
    chunks.extend((43..48).map(|_| vec![0x90]));
    let code: Vec<_> = chunks.iter().flatten().copied().collect();
    assert_eq!(code.len(), 48);
    original[0x1100..0x1130].copy_from_slice(&code);
    let mut text = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {PC} 4352 48\n",
        digest(&original)
    );
    let mut pc = PC;
    for bytes in chunks {
        writeln!(text, "head {pc} {}", ledger::hex(&bytes)).unwrap();
        pc += bytes.len() as u64;
    }
    writeln!(text, "region {HOOK} 73472 1\nhead {HOOK} c3").unwrap();
    let mut p = policy(&original, &text, 0);
    let selected = PC + 0x0100_0080;
    let victim = PC + 0x0600_0080;
    let prior = PC + 35 + 0x27b8_4800;
    writeln!(p, "search 1 T3 0 15 1 none 2 2\nallocation 1 selected {selected} 1 8192 {}:8192\nallocation 1 victim {victim} 1 8192 {}:8192\nsearch 2 B2 0 15 1 none 2 2\nallocation 2 selected {prior} 1 8192 {}:8192\nallocation 2 victim {victim} 1 8192 {}:8192", selected & !4095, victim & !4095, prior & !4095, victim & !4095).unwrap();
    (original, text, p)
}

#[test]
fn whole_long_t3_ownership_keeps_denominator_and_finds_alternate_victim() {
    let (original, text, p) = long_ownership_fixture();
    let selected = bind(&original, &text, &p).unwrap();
    assert_eq!(
        selected
            .selection
            .sites
            .iter()
            .map(|s| s.pc)
            .collect::<Vec<_>>(),
        [PC, PC + 30]
    );
    let legacy = crate::prepare_selection_with_mode(
        &original,
        selected.selection.clone(),
        false,
        NeighborMode::LongOnly,
    )
    .unwrap();
    assert!(!legacy.candidate_complete());
    assert_eq!(
        legacy.reports()[0].refusal.as_ref().unwrap().stage,
        "composition"
    );
    assert_eq!(
        legacy.reports()[0].refusal.as_ref().unwrap().detail,
        "OwnershipConflict"
    );
    assert!(!legacy.files().contains_key("candidate.elf"));
    let product = crate::prepare_disassembly_whole(&original, &selected).unwrap();
    assert!(product.candidate_complete());
    assert!(!product.qualification_complete());
    assert_eq!(
        product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(
        product
            .reports()
            .iter()
            .all(|r| r.refusal.is_none() && r.candidate_emitted)
    );
    assert_eq!(
        product.reports()[0].core_tactic,
        Some(li2core::engine::Tactic::NeighborEviction)
    );
    assert_eq!(
        product.reports()[1].core_tactic,
        Some(li2core::engine::Tactic::GeneralizedPun)
    );
    let d = &product.reports()[0].diagnostics;
    assert!(d.contains("OwnershipConflict") && d.contains("stage: Composition"));
    assert!(d.contains("victims_examined: 2") && d.contains("pairs_examined: 2"));
    let mut expected = original[0x1100..0x1130].to_vec();
    expected[..2].copy_from_slice(&[0xeb, 19]);
    let victim = PC + 0x0600_0080;
    let selected_target = PC + 0x0100_0080;
    expected[16] = 0xe9;
    expected[17..21].copy_from_slice(&i32::try_from(victim - (PC + 21)).unwrap().to_le_bytes());
    expected[21] = 0xe9;
    expected[22..26].copy_from_slice(
        &i32::try_from(selected_target - (PC + 26))
            .unwrap()
            .to_le_bytes(),
    );
    expected[30..32].copy_from_slice(&[0xe9, 0]);
    assert_eq!(&product.files()["candidate.elf"][0x1100..0x1130], &expected);
    assert_eq!(product.files()["candidate.elf"][0x11f00], 0xc3);
    let profile = std::str::from_utf8(&product.files()["planning-profile.tsv"]).unwrap();
    assert!(profile.contains(NEIGHBOR_METADATA));
    assert_eq!(
        selected.profile(),
        "elf-disassembly-null-jumps-shared-4096-v1"
    );
    let capped = p.replace("search 1 T3 0 15 1 none 2 2", "search 1 T3 0 15 1 none 2 1");
    let refused =
        crate::prepare_disassembly_whole(&original, &bind(&original, &text, &capped).unwrap())
            .unwrap();
    assert!(!refused.candidate_complete());
    assert_eq!(
        refused.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(
        refused
            .reports()
            .iter()
            .all(|r| r.refusal.is_some() && !r.candidate_emitted)
    );
    assert!(!refused.files().contains_key("candidate.elf"));
    assert!(
        refused.reports()[0]
            .diagnostics
            .contains("OwnershipConflict")
    );
}

// Two independent near JMPs, one shared original snapshot and one declared
// two-page arena. No bytes are mapped or executed by these artifact controls.
fn current_placement_fixture(pages: usize) -> (Vec<u8>, String, String) {
    let (mut original, _) = fixture(2, 0);
    let chunks: [&[u8]; 5] = [
        &[0xf3, 0x0f, 0x1e, 0xfa],
        &[0xe9, 0, 0, 0, 0],
        &[0xc3],
        &[0xe9, 0, 0, 0, 0],
        &[0xc3],
    ];
    let code: Vec<_> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    original[0x1100..0x1100 + code.len()].copy_from_slice(&code);
    let mut text = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {PC} 4352 {}\n",
        digest(&original),
        code.len()
    );
    let mut pc = PC;
    for chunk in chunks {
        writeln!(text, "head {pc} {}", ledger::hex(chunk)).unwrap();
        pc += chunk.len() as u64;
    }
    writeln!(text, "region {HOOK} 73472 1\nhead {HOOK} c3").unwrap();
    let mut p = policy(&original, &text, 0);
    let seed = PC & !4095;
    let free = BASE + 0x40000;
    for id in 1..=2 {
        writeln!(p, "search {id} B1 0 80 1 none 64 256\nallocation {id} selected {seed} 1 4096 {seed}:4096 {free}:{}\nallocation {id} victim {free} 1 4096 {free}:{}", pages * 4096, pages * 4096).unwrap();
    }
    (original, text, p)
}

#[test]
fn whole_current_placement_uses_declared_arena_and_committed_image_occupancy() {
    let (original, text, p) = current_placement_fixture(2);
    let selected = bind(&original, &text, &p).unwrap();
    let manifest = selected.manifest().to_vec();
    let prior = crate::prepare_disassembly_whole(&original, &selected).unwrap();
    assert!(!prior.candidate_complete());
    assert!(!prior.files().contains_key("candidate.elf"));
    let product = crate::prepare_disassembly_whole_current_placement(&original, &selected).unwrap();
    assert!(product.candidate_complete());
    assert!(!product.qualification_complete());
    assert_eq!(
        product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(
        product
            .reports()
            .iter()
            .all(|r| r.refusal.is_none() && r.candidate_emitted)
    );
    assert!(
        product
            .reports()
            .iter()
            .all(|r| r.core_tactic == Some(li2core::engine::Tactic::Relocation))
    );
    let plan = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    let allocations: Vec<_> = plan
        .lines()
        .filter(|l| l.starts_with("allocation\t"))
        .collect();
    let free = BASE + 0x40000;
    assert_eq!(
        allocations,
        [
            format!("allocation\t2\t0\t{free}\t{}\t4096", free + 4096),
            format!("allocation\t1\t0\t{}\t{}\t4096", free + 4096, free + 8192),
        ]
    );
    assert_eq!(selected.manifest(), manifest);
    assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
    assert_eq!(
        product.files()["disassembly-inventory.tsv"],
        selected.files["disassembly-inventory.tsv"]
    );
    let profile = &product.files()["planning-profile.tsv"];
    assert!(profile.starts_with(&selected.files["planning-profile.tsv"]));
    assert!(profile.ends_with(CURRENT_PLACEMENT_METADATA.as_bytes()));
    assert!(
        std::str::from_utf8(profile)
            .unwrap()
            .contains(NEIGHBOR_METADATA)
    );
    assert_eq!(&product.files()["candidate.elf"][0x11f00..0x11f01], &[0xc3]);
}

#[test]
fn whole_current_placement_exhaustion_keeps_full_atomic_refusal_and_one_candidate_cap() {
    let (original, text, p) = current_placement_fixture(1);
    let selected = bind(&original, &text, &p).unwrap();
    let product = crate::prepare_disassembly_whole_current_placement(&original, &selected).unwrap();
    assert!(!product.candidate_complete());
    assert!(!product.qualification_complete());
    assert!(!product.files().contains_key("candidate.elf"));
    assert_eq!(
        product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(
        product
            .reports()
            .iter()
            .all(|r| r.refusal.is_some() && !r.candidate_emitted)
    );
    assert!(product.reports().iter().any(|r| r.refusal_code == Some(11)));
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|n| n.starts_with("image-"))
            .count(),
        1
    );
    assert_eq!(
        product.files()["disassembly-inventory.tsv"],
        selected.files["disassembly-inventory.tsv"]
    );
    assert!(
        product.files()["planning-profile.tsv"].ends_with(CURRENT_PLACEMENT_METADATA.as_bytes())
    );
    let widened = p.replace(" 1 4096 ", " 2 4096 ");
    let invalid = bind(&original, &text, &widened).unwrap();
    let refused = crate::prepare_disassembly_whole_current_placement(&original, &invalid).unwrap();
    assert_eq!(refused.reports().len(), 2);
    assert!(refused.reports().iter().all(|r| r.refusal_code == Some(1)));
    assert!(!refused.files().contains_key("candidate.elf"));
    assert!(!refused.files().keys().any(|n| n.starts_with("image-")));
}

// Two selected branches share a complete original region. The closest T3
// victim is itself still selected; the next victim is either short or long.
// In the all-selected case both victims remain protected. No bytes execute.
fn mixed_pending_fixture(
    long: bool,
    all_selected: bool,
    pairs: usize,
) -> (Vec<u8>, String, String) {
    assert!(!long || !all_selected);
    let mut code = vec![
        0x2e, 0xb8, 0x37, 0x31, 0x42, 0x53, 0xb8, 1, 1, 1, 1, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x0f,
        0x85, 10, 0, 0, 0, 0xb8, 1, 1, 1, 1, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x75, 0, 0xc3,
    ];
    let heads = if long {
        code[..10].copy_from_slice(&[0x48, 0xb8, 0x37, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97]);
        code[10] = 0xc3;
        code[11] = 0x90;
        vec![
            0, 10, 11, 12, 13, 14, 15, 16, 22, 27, 28, 29, 30, 31, 32, 34,
        ]
    } else {
        if all_selected {
            code[..6].copy_from_slice(&[0x0f, 0x85, 10, 0, 0, 0]);
        }
        vec![0, 6, 11, 12, 13, 14, 15, 16, 22, 27, 28, 29, 30, 31, 32, 34]
    };
    let (mut original, _) = fixture(2, 0);
    original[0x1100..0x1100 + code.len()].copy_from_slice(&code);
    let mut text = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {PC} 4352 {}\n",
        digest(&original),
        code.len()
    );
    for (index, &offset) in heads.iter().enumerate() {
        let end = heads.get(index + 1).copied().unwrap_or(code.len());
        writeln!(
            text,
            "head {} {}",
            PC + offset as u64,
            ledger::hex(&code[offset..end])
        )
        .unwrap();
    }
    writeln!(text, "region {HOOK} 73472 1\nhead {HOOK} c3").unwrap();
    let mut p = policy(&original, &text, 0);
    let selected = PC + 0x0101_01d2;
    let victim = PC + 0x0600_0080;
    let mut rows = Vec::new();
    if all_selected {
        rows.push(("B1", PC + 0x0500_0080));
    }
    rows.extend([("B1", PC + 0x0400_0080), ("T3", selected)]);
    for (index, (tactic, target)) in rows.into_iter().enumerate() {
        let id = index + 1;
        writeln!(p, "search {id} {tactic} 0 80 1 none 2 {pairs}\nallocation {id} selected {target} 1 4096 {}:4096\nallocation {id} victim {victim} 1 4096 {}:4096", target & !4095, victim & !4095).unwrap();
    }
    (original, text, p)
}

fn mixed_pending_attempts(report: &crate::SiteReport, second: Option<(u64, bool)>) {
    use li2core::contracts::Refusal;
    use li2core::neighbor::{NeighborAttempt, NeighborAttemptStage};
    let row = |victim: u64, target: u64, conflict: bool| NeighborAttempt {
        victim,
        stage: NeighborAttemptStage::Composition,
        victim_target: Some(PC + 0x0600_0080),
        selected_target: Some(target),
        refusal: conflict.then_some(Refusal::OwnershipConflict),
    };
    let mut expected = vec![row(PC + 16, PC + 0x0101_01d2, true)];
    if let Some((target, conflict)) = second {
        expected.push(row(PC, target, conflict));
    }
    let actual: String = report.diagnostics.split_whitespace().collect();
    let expected: String = format!("candidates:Neighbor({expected:#?},)")
        .split_whitespace()
        .collect();
    assert!(actual.contains(&expected));
    assert_eq!(actual.matches("candidates:Neighbor(").count(), 1);
}

#[test]
fn whole_mixed_pending_uses_short_and_long_alternates_without_claiming_selected_victims() {
    use li2core::engine::Tactic;
    for long in [false, true] {
        let (original, text, p) = mixed_pending_fixture(long, false, 2);
        let saved = original.clone();
        let selected = bind(&original, &text, &p).unwrap();
        let saved_files = selected.files.clone();
        assert_eq!(
            selected
                .selection
                .sites
                .iter()
                .map(|s| (s.id, s.pc, s.length))
                .collect::<Vec<_>>(),
            [(1, PC + 16, 6), (2, PC + 32, 2)]
        );
        assert!(selected.selection.sites.iter().all(|s| {
            s.heads.len() == 16 && s.completeness == EntryCompleteness::AllInstructionHeads
        }));
        if !long {
            let old =
                crate::prepare_disassembly_whole_current_placement(&original, &selected).unwrap();
            assert!(!old.candidate_complete());
            assert!(!old.files().contains_key("candidate.elf"));
            assert!(
                old.files()["planning-profile.tsv"]
                    .ends_with(CURRENT_PLACEMENT_METADATA.as_bytes())
            );
        }
        let product = crate::prepare_disassembly_whole_current_placement_mixed_neighbors(
            &original, &selected,
        )
        .unwrap();
        assert!(product.candidate_complete());
        assert!(!product.qualification_complete());
        assert_eq!(
            product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(
            product
                .reports()
                .iter()
                .all(|r| r.refusal.is_none() && r.candidate_emitted)
        );
        assert_eq!(product.reports()[0].core_tactic, Some(Tactic::Relocation));
        assert_eq!(
            product.reports()[1].core_tactic,
            Some(Tactic::NeighborEviction)
        );
        let evidence = &product.reports()[1].diagnostics;
        assert!(evidence.contains("OwnershipConflict") && evidence.contains("stage: Composition"));
        assert!(evidence.contains("victims_examined: 2") && evidence.contains("pairs_examined: 2"));
        mixed_pending_attempts(
            &product.reports()[1],
            Some((PC + if long { 0x0101_01d2 } else { 0x0101_01c2 }, false)),
        );
        let mut expected = original[0x1100..0x1123].to_vec();
        expected[..5].copy_from_slice(&[0xe9, 0x7b, 0, 0, 6]);
        expected[5..10].copy_from_slice(if long {
            &[0xe9, 0xc8, 1, 1, 1]
        } else {
            &[0xe9, 0xb8, 1, 1, 1]
        });
        expected[16..21].copy_from_slice(&[0xe9, 0x6b, 0, 0, 4]);
        expected[32..34].copy_from_slice(&[0xeb, 0xe3]);
        assert_eq!(&product.files()["candidate.elf"][0x1100..0x1123], &expected);
        assert_eq!(product.files()["candidate.elf"][0x11f00], 0xc3);
        assert_eq!(
            product
                .files()
                .keys()
                .filter(|n| n.starts_with("image-"))
                .count(),
            3
        );
        assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
        assert_eq!(
            product.files()["disassembly-inventory.tsv"],
            saved_files["disassembly-inventory.tsv"]
        );
        let profile = std::str::from_utf8(&product.files()["planning-profile.tsv"]).unwrap();
        assert!(profile.contains(MIXED_PENDING_METADATA));
        assert!(!profile.contains("neighbor_victims\tlong-only\n"));
        assert!(
            std::str::from_utf8(&selected.files["planning-profile.tsv"])
                .unwrap()
                .contains(NEIGHBOR_METADATA)
        );
        assert_eq!(selected.files, saved_files);
        assert_eq!(original, saved);
    }
}

#[test]
fn whole_mixed_pending_pair_cap_and_all_selected_victims_keep_exact_atomic_refusals() {
    for (all_selected, pairs, ids) in [(false, 1, vec![1, 2]), (true, 2, vec![1, 2, 3])] {
        let (original, text, p) = mixed_pending_fixture(false, all_selected, pairs);
        let selected = bind(&original, &text, &p).unwrap();
        let product = crate::prepare_disassembly_whole_current_placement_mixed_neighbors(
            &original, &selected,
        )
        .unwrap();
        assert_eq!(
            product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
            ids
        );
        assert!(!product.candidate_complete());
        assert!(!product.qualification_complete());
        assert!(!product.files().contains_key("candidate.elf"));
        assert!(!product.files().contains_key("source.li2sparse"));
        assert!(
            product
                .reports()
                .iter()
                .all(|r| r.refusal.is_some() && !r.candidate_emitted)
        );
        let high = product.reports().last().unwrap();
        assert_eq!(high.core_tactic, None);
        assert_eq!(high.refusal_code, Some(12));
        assert_eq!(high.refusal.as_ref().unwrap().stage, "core");
        assert_eq!(high.refusal.as_ref().unwrap().detail, "OwnershipConflict");
        mixed_pending_attempts(high, all_selected.then_some((PC + 0x0101_01c2, true)));
        assert_eq!(high.diagnostics.matches("NeighborAttempt {").count(), pairs);
        let runs: Vec<_> = high.diagnostics.split("SearchRun {").skip(1).collect();
        let joint = runs
            .iter()
            .find(|r| r.contains("domain: JointPairs,"))
            .unwrap();
        assert!(joint.contains(&format!("examined: {pairs},")));
        assert!(joint.contains(if all_selected {
            "stop: UnclassifiedBoundedStop"
        } else {
            "stop: BudgetLimited"
        }));
        assert!(!high.diagnostics.contains("stop: Accepted"));
        for low in &product.reports()[..ids.len() - 1] {
            assert_eq!(low.core_tactic, Some(li2core::engine::Tactic::Relocation));
            assert_eq!(low.refusal_code, Some(10_003));
            assert_eq!(low.refusal.as_ref().unwrap().stage, "atomic-selection");
        }
        assert_eq!(
            product
                .files()
                .keys()
                .filter(|n| n.starts_with("image-"))
                .count(),
            ids.len() - 1
        );
        assert_eq!(
            product.files()["disassembly-inventory.tsv"],
            selected.files["disassembly-inventory.tsv"]
        );
        assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
        assert!(
            std::str::from_utf8(&product.files()["planning-profile.tsv"])
                .unwrap()
                .contains(MIXED_PENDING_METADATA)
        );
    }
}

// The seed is legal but leaves one byte. The fitting mode must choose once
// before emission; it must not turn an emitted failure into a retry.
#[test]
fn whole_fitting_places_once_and_keeps_complete_pending_t3_alternates() {
    use li2core::engine::Tactic;
    let (original, text, p) = current_placement_fixture(2);
    let source_page = PC & !4095;
    let free = BASE + 0x40000;
    let p = p.replace(
        &format!("selected {source_page} 1 4096"),
        &format!("selected {} 1 4096", free + 4095),
    );
    let selected = bind(&original, &text, &p).unwrap();
    let old =
        crate::prepare_disassembly_whole_current_placement_mixed_neighbors(&original, &selected)
            .unwrap();
    assert!(!old.candidate_complete());
    assert!(old.reports().iter().all(|r| r.refusal_code == Some(11)));
    assert!(!old.files().keys().any(|n| n.starts_with("image-")));
    let product =
        crate::prepare_disassembly_whole_fitting_mixed_neighbors(&original, &selected).unwrap();
    assert!(product.candidate_complete());
    assert!(!product.qualification_complete());
    assert_eq!(
        product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(product.reports().iter().all(|r| {
        r.core_tactic == Some(Tactic::Relocation) && r.refusal.is_none() && r.candidate_emitted
    }));
    let plan = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    assert_eq!(
        plan.lines()
            .filter(|l| l.starts_with("allocation\t"))
            .collect::<Vec<_>>(),
        [
            format!("allocation\t2\t0\t{free}\t{}\t4096", free + 4096),
            format!("allocation\t1\t0\t{}\t{}\t4096", free + 4096, free + 8192),
        ]
    );
    assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
    assert_eq!(
        product.files()["disassembly-inventory.tsv"],
        selected.files["disassembly-inventory.tsv"]
    );
    assert!(
        std::str::from_utf8(&product.files()["planning-profile.tsv"])
            .unwrap()
            .contains(FITTING_MIXED_METADATA)
    );
    assert_eq!(product.files()["candidate.elf"][0x11f00], 0xc3);

    for long in [false, true] {
        let (original, text, p) = mixed_pending_fixture(long, false, 2);
        let saved = original.clone();
        let selected = bind(&original, &text, &p).unwrap();
        let files = selected.files.clone();
        let old = crate::prepare_disassembly_whole_current_placement_mixed_neighbors(
            &original, &selected,
        )
        .unwrap();
        let product =
            crate::prepare_disassembly_whole_fitting_mixed_neighbors(&original, &selected).unwrap();
        assert!(old.candidate_complete() && product.candidate_complete());
        assert!(!product.qualification_complete());
        assert_eq!(
            product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(
            product
                .reports()
                .iter()
                .all(|r| r.candidate_emitted && r.refusal.is_none())
        );
        assert_eq!(product.reports()[0].core_tactic, Some(Tactic::Relocation));
        assert_eq!(
            product.reports()[1].core_tactic,
            Some(Tactic::NeighborEviction)
        );
        mixed_pending_attempts(
            &product.reports()[1],
            Some((PC + if long { 0x0101_01d2 } else { 0x0101_01c2 }, false)),
        );
        assert!(
            product.reports()[1]
                .diagnostics
                .contains("victims_examined: 2")
        );
        assert!(
            product.reports()[1]
                .diagnostics
                .contains("pairs_examined: 2")
        );
        assert_eq!(
            product.files()["candidate.elf"],
            old.files()["candidate.elf"]
        );
        assert_eq!(
            product.files()["plan-ledger.tsv"],
            old.files()["plan-ledger.tsv"]
        );
        assert!(
            std::str::from_utf8(&product.files()["planning-profile.tsv"])
                .unwrap()
                .contains(FITTING_MIXED_METADATA)
        );
        assert_eq!(
            product.files()["disassembly-inventory.tsv"],
            files["disassembly-inventory.tsv"]
        );
        assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
        assert_eq!(selected.files, files);
        assert_eq!(original, saved);
    }
}

// The high two-byte branch must refuse forced B1 and remain pending. The low
// B2 then owns its unchanged suffix; B1 can instead displace only CMP + low Jcc.
// Overall publication must still refuse because the high branch remains failed.
fn fitting_admission_fixture(forced: bool) -> (Vec<u8>, String, String) {
    let (mut original, _) = fixture(0, 0);
    original[0x1100..0x1105].fill(0);
    let start = BASE + 0x14f8;
    put(&mut original, 24, 8, start);
    let chunks: [&[u8]; 5] = [
        &[0x83, 0xf8, 0],
        &[0x75, 0],
        &[0xeb, 0],
        &[0x0f, 0x1f, 0x40, 0],
        &[0xc3],
    ];
    let code: Vec<_> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    original[0x14f8..0x14f8 + code.len()].copy_from_slice(&code);
    let mut text = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {start} 5368 {}\n",
        digest(&original),
        code.len()
    );
    let mut pc = start;
    for chunk in chunks {
        writeln!(text, "head {pc} {}", ledger::hex(chunk)).unwrap();
        pc += chunk.len() as u64;
    }
    writeln!(text, "region {HOOK} 73472 1\nhead {HOOK} c3").unwrap();
    let mut p = policy(&original, &text, 0);
    let arena = BASE + 0x40000;
    let low = if forced { "B2" } else { "preferred" };
    for (id, tactic) in [(1, low), (2, "B1")] {
        writeln!(p, "search {id} {tactic} 64 80 2 none 64 256\nallocation {id} selected {arena} 1 4096 {arena}:536870912\nallocation {id} victim {arena} 1 4096 {arena}:536870912").unwrap();
    }
    (original, text, p)
}

#[test]
fn whole_fitting_admits_alternate_tactic_but_retains_full_atomic_refusal() {
    use li2core::engine::Tactic;
    for forced in [false, true] {
        let (original, text, p) = fitting_admission_fixture(forced);
        let saved = original.clone();
        let selected = bind(&original, &text, &p).unwrap();
        let source = BASE + 0x14f8;
        assert_eq!(
            selected
                .selection
                .sites
                .iter()
                .map(|s| (s.id, s.pc, s.length))
                .collect::<Vec<_>>(),
            [(1, source + 3, 2), (2, source + 5, 2)]
        );
        assert!(selected.selection.sites.iter().all(|s| s.heads.len() == 5));
        let old = crate::prepare_disassembly_whole_current_placement_mixed_neighbors(
            &original, &selected,
        )
        .unwrap();
        assert_eq!(old.reports()[0].core_tactic, Some(Tactic::GeneralizedPun));
        assert_eq!(old.reports()[0].refusal_code, Some(10_001));
        assert_eq!(
            old.reports()[0].refusal.as_ref().unwrap().stage,
            "pending-selected"
        );
        assert_eq!(
            old.reports()[0].refusal.as_ref().unwrap().detail,
            "OwnershipConflict"
        );
        let product =
            crate::prepare_disassembly_whole_fitting_mixed_neighbors(&original, &selected).unwrap();
        assert_eq!(
            product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(!product.candidate_complete());
        assert!(!product.qualification_complete());
        assert!(!product.files().contains_key("candidate.elf"));
        assert!(!product.files().contains_key("source.li2sparse"));
        assert!(
            product
                .reports()
                .iter()
                .all(|r| r.refusal.is_some() && !r.candidate_emitted)
        );
        let high = &product.reports()[1];
        assert_eq!(high.core_tactic, None);
        assert_eq!(high.refusal_code, Some(9));
        assert_eq!(high.refusal.as_ref().unwrap().stage, "core");
        assert_eq!(high.refusal.as_ref().unwrap().detail, "NoPatchWindow");
        assert_eq!(high.diagnostics.matches("EngineAttempt {").count(), 1);
        let low = &product.reports()[0];
        assert!(low.diagnostics.contains("OwnershipConflict"));
        assert_eq!(
            low.diagnostics.matches("EngineAttempt {").count(),
            if forced { 1 } else { 2 }
        );
        if forced {
            assert_eq!(low.core_tactic, None);
            assert_eq!(low.refusal_code, Some(12));
            assert_eq!(low.refusal.as_ref().unwrap().stage, "core");
            assert_eq!(low.refusal.as_ref().unwrap().detail, "OwnershipConflict");
            assert!(!product.files().keys().any(|n| n.starts_with("image-")));
        } else {
            assert_eq!(low.core_tactic, Some(Tactic::Relocation));
            assert_eq!(low.refusal_code, Some(10_003));
            assert_eq!(low.refusal.as_ref().unwrap().stage, "atomic-selection");
            let evidence = &low.diagnostics;
            // Winning leaf metrics precede the ordered engine attempts and also
            // contain tactic fields. Compare only the two EngineAttempt records.
            let attempted_tactics = evidence
                .split("EngineAttempt {")
                .skip(1)
                .map(|attempt| {
                    attempt
                        .lines()
                        .map(str::trim)
                        .find(|line| line.starts_with("tactic: "))
                        .expect("EngineAttempt retains its tactic field")
                })
                .collect::<Vec<_>>();
            assert_eq!(
                attempted_tactics,
                ["tactic: GeneralizedPun,", "tactic: Relocation,"]
            );
            assert_eq!(
                product
                    .files()
                    .keys()
                    .filter(|n| n.starts_with("image-"))
                    .count(),
                1
            );
            let ledger = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
            assert!(ledger.contains(&format!(
                "step\t1\t0\trelocation\t{}\t{source}\t{source}\t{}\n",
                source + 3,
                source + 5
            )));
            assert!(!ledger.lines().any(|l| l.starts_with("step\t2\t")));
        }
        assert_eq!(
            product.files()["disassembly-inventory.tsv"],
            selected.files["disassembly-inventory.tsv"]
        );
        assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
        assert!(
            std::str::from_utf8(&product.files()["planning-profile.tsv"])
                .unwrap()
                .contains(FITTING_MIXED_METADATA)
        );
        assert_eq!(original, saved);
    }
}

// A complete original region with one six-byte victim, one four-byte suffix,
// and the sole selected two-byte branch. The preserved suffix fixes E late in
// its page; no source/importer shortcut or test-only image constructor is used.
fn entry_veneer_fixture(victim_offset: u64) -> (Vec<u8>, String, String) {
    let (mut original, _) = fixture(0, 0);
    original[0x1100..0x1105].fill(0);
    let victim = BASE + victim_offset;
    put(&mut original, 24, 8, victim);
    let code = [
        0x2e, 0xb8, 0x37, 0x31, 0x42, 0x53, 0x44, 0x8d, 0x48, 3, 0x75, 0, 0xc3,
    ];
    let offset = victim_offset as usize;
    original[offset..offset + code.len()].copy_from_slice(&code);
    let mut text = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {victim} {victim_offset} {}\n",
        digest(&original),
        code.len(),
    );
    for (start, end) in [(0, 6), (6, 10), (10, 12), (12, 13)] {
        writeln!(
            text,
            "head {} {}",
            victim + start as u64,
            ledger::hex(&code[start..end])
        )
        .unwrap();
    }
    writeln!(text, "region {HOOK} 73472 1\nhead {HOOK} c3").unwrap();
    let entry = victim + 10 + 0x0348_8d44;
    let victim_image = victim + 0x0600_0080;
    let mut p = policy(&original, &text, 0);
    writeln!(p, "search 1 T3 0 80 1 {victim} 1 1\nallocation 1 selected {entry} 1 4096 {}:4096\nallocation 1 victim {victim_image} 1 4096 {}:4096", entry & !4095, victim_image & !4095).unwrap();
    (original, text, p)
}

#[test]
fn whole_entry_veneer_keeps_storage_entry_fields_and_carrier_distinct() {
    use iced_x86::{Decoder, DecoderOptions};
    use li2core::engine::Tactic;
    for (offset, entry_offset) in [(0x11f7, 3909), (0x1227, 3957)] {
        let (original, text, p) = entry_veneer_fixture(offset);
        let saved = original.clone();
        let selected = bind(&original, &text, &p).unwrap();
        let saved_files = selected.files.clone();
        let victim = BASE + offset;
        let pc = victim + 10;
        let entry = victim + 10 + 0x0348_8d44;
        let storage = entry & !4095;
        assert_eq!(entry - storage, entry_offset);
        assert_eq!(selected.selection.sites.len(), 1);
        assert_eq!(selected.selection.sites[0].pc, pc);
        assert_eq!(selected.selection.sites[0].length, 2);
        assert_eq!(selected.selection.sites[0].heads.len(), 4);
        assert_eq!(selected.selection.sites[0].max_victims, 1);
        assert_eq!(selected.selection.sites[0].max_pairs, 1);
        let old =
            crate::prepare_disassembly_whole_fitting_mixed_neighbors(&original, &selected).unwrap();
        assert!(!old.candidate_complete());
        assert_eq!(old.reports().len(), 1);
        assert_eq!(old.reports()[0].refusal_code, Some(11));
        assert!(!old.files().contains_key("candidate.elf"));
        let product =
            crate::prepare_disassembly_whole_entry_veneer_mixed_neighbors(&original, &selected)
                .unwrap();
        assert!(product.candidate_complete());
        assert!(!product.qualification_complete());
        assert_eq!(product.reports().len(), 1);
        let report = &product.reports()[0];
        assert_eq!((report.id, report.pc, report.length), (1, pc, 2));
        assert_eq!(report.core_tactic, Some(Tactic::NeighborEviction));
        assert!(report.refusal.is_none() && report.candidate_emitted);
        assert_eq!(report.diagnostics.matches("EngineAttempt {").count(), 1);
        // Metrics and engine evidence print the same rows; inspect the sole
        // EngineAttempt, retaining both decisions for its one charged pair.
        let (metrics, attempt) = report.diagnostics.split_once("EngineAttempt {").unwrap();
        assert_eq!(attempt.matches("NeighborAttempt {").count(), 2);
        let expected = li2core::engine::CandidateEvidence::Neighbor(vec![
            li2core::neighbor::NeighborAttempt {
                victim,
                stage: li2core::neighbor::NeighborAttemptStage::EntryVeneerCertificate,
                victim_target: Some(victim + 0x0600_0080),
                selected_target: None,
                refusal: Some(li2core::contracts::Refusal::AllocationUnavailable),
            },
            li2core::neighbor::NeighborAttempt {
                victim,
                stage: li2core::neighbor::NeighborAttemptStage::Composition,
                victim_target: Some(victim + 0x0600_0080),
                selected_target: Some(entry),
                refusal: None,
            },
        ]);
        let actual: String = attempt.split_whitespace().collect();
        let expected: String = format!("candidates:{expected:#?}")
            .split_whitespace()
            .collect();
        assert_eq!(actual.matches("candidates:Neighbor(").count(), 1);
        assert!(actual.contains(&expected));
        let metrics: String = metrics.split_whitespace().collect();
        assert_eq!(metrics.matches("victims_examined:").count(), 1);
        assert_eq!(metrics.matches("pairs_examined:").count(), 1);
        assert!(metrics.contains("victims_examined:1,"));
        assert!(metrics.contains("pairs_examined:1,"));
        assert!(report.diagnostics.contains("victims_examined: 1"));
        assert!(report.diagnostics.contains("pairs_examined: 1"));
        let ledger = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
        let rows: Vec<Vec<&str>> = ledger
            .lines()
            .map(|line| line.split('\t').collect())
            .collect();
        let veneers: Vec<_> = rows.iter().filter(|r| r[0] == "entry-veneer").collect();
        assert_eq!(veneers.len(), 1);
        assert_eq!(ledger.matches("ENTRY-VENEER-EXTENSION\t1\n").count(), 1);
        let v = veneers[0];
        assert_eq!(v.len(), 15);
        let number = |i: usize| v[i].parse::<u64>().unwrap();
        let id = number(1);
        let body_len = number(5) as usize;
        let bound = number(6) as usize;
        let full_len = number(7) as usize;
        assert_eq!((number(2), number(3), number(4)), (1, storage, entry));
        assert!(body_len > 0 && body_len <= bound && bound <= entry_offset as usize);
        assert_eq!(full_len, entry_offset as usize + 5);
        assert_eq!(
            (number(9), number(10), v[11]),
            (storage + body_len as u64, entry, "cc")
        );
        assert_eq!(
            (number(12), number(13), number(14)),
            (entry, entry + 5, storage)
        );
        let bytes = &product.files()[&format!("image-{id:04}.bin")];
        assert_eq!(bytes.len(), full_len);
        assert_eq!(digest(bytes), v[8]);
        assert!(
            bytes[body_len..entry_offset as usize]
                .iter()
                .all(|&b| b == 0xcc)
        );
        let mut decoder = Decoder::with_ip(
            64,
            &bytes[entry_offset as usize..],
            entry,
            DecoderOptions::NONE,
        );
        let jump = decoder.decode();
        assert_eq!(jump.code(), Code::Jmp_rel32_64);
        assert_eq!(jump.len(), 5);
        assert_eq!(jump.near_branch_target(), storage);
        assert!(!decoder.can_decode());
        let image_row = rows
            .iter()
            .find(|r| r[0] == "image" && r[1] == id.to_string())
            .unwrap();
        assert_eq!(image_row[3].parse::<u64>().unwrap(), storage);
        assert_eq!(image_row[4].parse::<usize>().unwrap(), full_len);
        assert_eq!(image_row[5], v[8]);
        assert!(ledger.contains(&format!("route\t{id}\t{pc}\t{storage}\n")));
        let boundaries: Vec<_> = rows
            .iter()
            .filter(|r| r[0] == "restored-boundary" && r[1] == id.to_string())
            .collect();
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0][2].parse::<u64>().unwrap(), pc);
        assert!(boundaries[0][3].parse::<u64>().unwrap() < storage + body_len as u64);
        assert!(ledger.contains(&format!("pc-range\t{id}\t{entry}\t{}\t{pc}\n", entry + 5)));
        for r in rows
            .iter()
            .filter(|r| r[0] == "pc-range" && r[1] == id.to_string())
        {
            let start = r[2].parse::<u64>().unwrap();
            let end = r[3].parse::<u64>().unwrap();
            assert!(end <= storage + body_len as u64 || start >= entry);
        }
        let veneer_fields: Vec<_> = rows
            .iter()
            .filter(|r| {
                r[0] == "field"
                    && r[1] == id.to_string()
                    && r[2].parse::<u64>().unwrap() == entry_offset + 1
            })
            .collect();
        assert_eq!(veneer_fields.len(), 1);
        let f = veneer_fields[0];
        assert_eq!((f[3], f[4]), ("4", "Relative"));
        assert_eq!(f[5].parse::<u64>().unwrap(), entry_offset + 5);
        assert_eq!(f[6].parse::<u64>().unwrap(), storage);
        assert_eq!(f[7], "1");
        assert_eq!(
            f[8],
            ledger::hex(format!("EntryVeneer {{ original_pc: {pc} }}").as_bytes())
        );
        assert_eq!(f[9], ledger::hex(&bytes[entry_offset as usize + 1..]));
        for code in [1, 2, 3, 4, 7, 8] {
            assert!(ledger.contains(&format!("unmet-requirement\t{id}\t{code}\t0\n")));
        }
        assert!(ledger.contains(&format!("unmet-requirement\t{id}\t5\t1\n")));
        let allocations: Vec<_> = rows.iter().filter(|r| r[0] == "allocation").collect();
        assert_eq!(allocations.len(), 2);
        assert!(allocations.iter().all(|r| {
            r[5] == "4096" && r[4].parse::<u64>().unwrap() - r[3].parse::<u64>().unwrap() == 4096
        }));
        assert_eq!(rows.iter().filter(|r| r[0] == "image").count(), 2);
        let candidate = &product.files()["candidate.elf"];
        let elf = Elf64::parse(
            candidate,
            ParseLimits {
                max_program_headers: 64,
            },
        )
        .unwrap();
        assert_eq!(elf.header().entry, ElfVaddr(victim));
        assert_eq!(
            elf.executable_bytes(ElfVaddr(storage), full_len as u64)
                .unwrap(),
            bytes
        );
        let load: Vec<_> = elf
            .segments(SegmentType::Load)
            .filter(|p| p.vaddr == ElfVaddr(storage))
            .collect();
        assert_eq!(load.len(), 1);
        assert!(
            load[0].flags.readable() && load[0].flags.executable() && !load[0].flags.writable()
        );
        assert_eq!(load[0].file_size, full_len as u64);
        assert_eq!(load[0].memory_size, full_len as u64);
        assert_eq!(
            &candidate[offset as usize + 6..offset as usize + 10],
            &original[offset as usize + 6..offset as usize + 10]
        );
        assert_eq!(
            &candidate[offset as usize + 10..offset as usize + 12],
            &[0xeb, 0xf9]
        );
        let mut relay = Decoder::with_ip(
            64,
            &candidate[offset as usize + 5..offset as usize + 10],
            victim + 5,
            DecoderOptions::NONE,
        );
        let relay_jump = relay.decode();
        assert_eq!(relay_jump.code(), Code::Jmp_rel32_64);
        assert_eq!(relay_jump.near_branch_target(), entry);
        assert!(!relay.can_decode());
        assert_eq!(candidate[0x11f00], 0xc3);
        assert_eq!(
            product.files()["disassembly-inventory.tsv"],
            saved_files["disassembly-inventory.tsv"]
        );
        assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
        assert!(
            std::str::from_utf8(&product.files()["planning-profile.tsv"])
                .unwrap()
                .contains(ENTRY_VENEER_MIXED_METADATA)
        );
        assert_eq!(selected.files, saved_files);
        assert_eq!(original, saved);
    }
}

#[test]
fn whole_entry_veneer_preserves_direct_plans_and_full_pending_atomic_refusal() {
    // Direct success remains byte-identical even through the new mode.
    for long in [false, true] {
        let (original, text, p) = mixed_pending_fixture(long, false, 2);
        let selected = bind(&original, &text, &p).unwrap();
        let old =
            crate::prepare_disassembly_whole_fitting_mixed_neighbors(&original, &selected).unwrap();
        let product =
            crate::prepare_disassembly_whole_entry_veneer_mixed_neighbors(&original, &selected)
                .unwrap();
        assert!(old.candidate_complete() && product.candidate_complete());
        assert_eq!(product.reports().len(), 2);
        assert_eq!(
            product.files()["candidate.elf"],
            old.files()["candidate.elf"]
        );
        assert_eq!(
            product.files()["plan-ledger.tsv"],
            old.files()["plan-ledger.tsv"]
        );
        assert!(
            !std::str::from_utf8(&product.files()["plan-ledger.tsv"])
                .unwrap()
                .contains("ENTRY-VENEER-EXTENSION")
        );
        mixed_pending_attempts(
            &product.reports()[1],
            Some((PC + if long { 0x0101_01d2 } else { 0x0101_01c2 }, false)),
        );
        assert!(
            std::str::from_utf8(&product.files()["planning-profile.tsv"])
                .unwrap()
                .contains(ENTRY_VENEER_MIXED_METADATA)
        );
    }
    // Failed selected originals stay in the complete table; a veneer cannot
    // grant ownership of either one or reset the shared pair budget.
    for (all_selected, pairs, count) in [(false, 1, 2), (true, 2, 3)] {
        let (original, text, p) = mixed_pending_fixture(false, all_selected, pairs);
        let saved = original.clone();
        let selected = bind(&original, &text, &p).unwrap();
        let old =
            crate::prepare_disassembly_whole_fitting_mixed_neighbors(&original, &selected).unwrap();
        let product =
            crate::prepare_disassembly_whole_entry_veneer_mixed_neighbors(&original, &selected)
                .unwrap();
        assert_eq!(
            product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
            (1..=count).collect::<Vec<_>>()
        );
        assert!(!product.candidate_complete());
        assert!(!product.qualification_complete());
        assert!(!product.files().contains_key("candidate.elf"));
        assert!(!product.files().contains_key("source.li2sparse"));
        assert!(
            product
                .reports()
                .iter()
                .all(|r| r.refusal.is_some() && !r.candidate_emitted)
        );
        let high = product.reports().last().unwrap();
        assert_eq!(high.core_tactic, None);
        assert_eq!(high.refusal_code, Some(12));
        assert_eq!(high.refusal.as_ref().unwrap().stage, "core");
        assert_eq!(high.refusal.as_ref().unwrap().detail, "OwnershipConflict");
        assert_eq!(high.diagnostics, old.reports().last().unwrap().diagnostics);
        assert_eq!(high.diagnostics.matches("NeighborAttempt {").count(), pairs);
        mixed_pending_attempts(high, all_selected.then_some((PC + 0x0101_01c2, true)));
        for low in &product.reports()[..count as usize - 1] {
            assert_eq!(low.core_tactic, Some(li2core::engine::Tactic::Relocation));
            assert_eq!(low.refusal_code, Some(10_003));
            assert_eq!(low.refusal.as_ref().unwrap().stage, "atomic-selection");
        }
        assert_eq!(
            product.files()["disassembly-inventory.tsv"],
            selected.files["disassembly-inventory.tsv"]
        );
        assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
        assert!(
            std::str::from_utf8(&product.files()["planning-profile.tsv"])
                .unwrap()
                .contains(ENTRY_VENEER_MIXED_METADATA)
        );
        assert_eq!(original, saved);
    }
}

// Force caller order opposite virtual order, without changing either selected
// source or the original one-candidate/one-page planning policy.
fn packed_rx_fixture() -> (Vec<u8>, String, String) {
    let (original, text, mut p) = current_placement_fixture(2);
    let source = PC & !4095;
    let free = BASE + 0x40000;
    for id in 1..=2 {
        let seed = free + (id - 1) * 4096;
        p = p.replace(
            &format!("allocation {id} selected {source} 1 4096 "),
            &format!("allocation {id} selected {seed} 1 4096 "),
        );
    }
    (original, text, p)
}

#[test]
fn whole_packed_rx_runs_share_headers_keep_caller_order_and_legacy_bytes() {
    use crate::carrier::elf64::{Elf64, ElfVaddr, FileOffset, ParseLimits, SegmentType};
    let (original, text, p) = packed_rx_fixture();
    let saved = original.clone();
    let selected = bind(&original, &text, &p).unwrap();
    let saved_files = selected.files.clone();
    let old = crate::prepare_disassembly_whole_entry_veneer_mixed_neighbors(&original, &selected)
        .unwrap();
    let packed =
        crate::prepare_disassembly_whole_packed_entry_veneer_mixed_neighbors(&original, &selected)
            .unwrap();
    assert!(old.candidate_complete() && packed.candidate_complete());
    assert!(!packed.qualification_complete());
    assert_eq!(
        packed.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(packed.reports().iter().all(|r| r.core_tactic
        == Some(li2core::engine::Tactic::Relocation)
        && r.refusal.is_none()
        && r.candidate_emitted));
    assert_eq!(
        packed.files().keys().collect::<Vec<_>>(),
        old.files().keys().collect::<Vec<_>>()
    );
    for (name, bytes) in old.files() {
        if !matches!(
            name.as_str(),
            "candidate.elf" | "ledger.tsv" | "planning-profile.tsv" | "bundle-index.tsv"
        ) {
            assert_eq!(
                &packed.files()[name],
                bytes,
                "unchanged plan/input/report: {name}"
            );
        }
    }
    let before = Elf64::parse(
        &old.files()["candidate.elf"],
        ParseLimits {
            max_program_headers: 64,
        },
    )
    .unwrap();
    let after = Elf64::parse(
        &packed.files()["candidate.elf"],
        ParseLimits {
            max_program_headers: 64,
        },
    )
    .unwrap();
    assert_eq!(before.program_headers().len(), 6);
    assert_eq!(after.program_headers().len(), 5);
    assert_eq!(after.header().entry, before.header().entry);
    // Original LOADs and all per-image bytes stay exact; generated addresses
    // and their caller identities are unchanged despite reversed file backing.
    let original_elf = Elf64::parse(
        &original,
        ParseLimits {
            max_program_headers: 64,
        },
    )
    .unwrap();
    for ph in original_elf.segments(SegmentType::Load) {
        let old_load = before
            .segments(SegmentType::Load)
            .find(|p| p.vaddr == ph.vaddr)
            .unwrap();
        let new_load = after
            .segments(SegmentType::Load)
            .find(|p| p.vaddr == ph.vaddr)
            .unwrap();
        let mut expected = ph.clone();
        expected.index = old_load.index;
        assert_eq!(old_load, &expected);
        expected.index = new_load.index;
        assert_eq!(new_load, &expected);
    }
    let ledger = std::str::from_utf8(&packed.files()["ledger.tsv"]).unwrap();
    let rows: Vec<Vec<&str>> = ledger.lines().map(|l| l.split('\t').collect()).collect();
    let runs: Vec<_> = rows.iter().filter(|r| r[0] == "rx-run").collect();
    let members: Vec<_> = rows.iter().filter(|r| r[0] == "rx-run-member").collect();
    let images: Vec<_> = rows.iter().filter(|r| r[0] == "elf-image").collect();
    assert_eq!((runs.len(), members.len(), images.len()), (1, 2, 2));
    assert_eq!(runs[0].len(), 10);
    assert_eq!(&runs[0][7..], &["5", "4096", "2"]);
    assert_eq!(ledger.matches("RX-RUN-EXTENSION\t1\n").count(), 1);
    assert!(ledger.contains("rx_run_count\t1\nrx_run_image_count\t2\n"));
    let free = BASE + 0x40000;
    let mut files = Vec::new();
    for id in 0..2 {
        let image = images[id];
        let member = members[id];
        assert_eq!((image.len(), member.len()), (6, 7));
        assert_eq!(image[1], id.to_string());
        assert_eq!(member[1], image[1]);
        assert_eq!(member[2], runs[0][1]);
        assert_eq!(member[3], runs[0][2]);
        assert_eq!(member[3], image[5]);
        assert_eq!(&member[4..], &image[2..5]);
        let address = image[2].parse::<u64>().unwrap();
        let offset = image[3].parse::<u64>().unwrap();
        let bytes = &packed.files()[&format!("image-{id:04}.bin")];
        assert_eq!(address, free + (1 - id as u64) * 4096);
        assert_eq!(image[4].parse::<usize>().unwrap(), bytes.len());
        assert_eq!(
            after
                .executable_bytes(ElfVaddr(address), bytes.len() as u64)
                .unwrap(),
            bytes
        );
        assert_eq!(
            before
                .executable_bytes(ElfVaddr(address), bytes.len() as u64)
                .unwrap(),
            bytes
        );
        assert_eq!(
            after
                .file_to_virtual(FileOffset(offset), bytes.len() as u64)
                .unwrap()
                .program_header,
            image[5].parse::<usize>().unwrap()
        );
        files.push(offset);
    }
    assert_eq!(files[0] - files[1], 4096);
    let profile = std::str::from_utf8(&packed.files()["planning-profile.tsv"]).unwrap();
    assert!(profile.contains(PACKED_ENTRY_VENEER_MIXED_METADATA));
    assert_eq!(
        PACKED_ENTRY_VENEER_MIXED_METADATA,
        format!("{ENTRY_VENEER_MIXED_METADATA}{PACKED_RX_RUNS_METADATA}")
    );
    assert!(
        !std::str::from_utf8(&old.files()["ledger.tsv"])
            .unwrap()
            .contains("RX-RUN-EXTENSION")
    );
    assert!(
        !std::str::from_utf8(&old.files()["planning-profile.tsv"])
            .unwrap()
            .contains("carrier_layout")
    );
    // Calling the new mode cannot alter the old selection or its whole output.
    let again = crate::prepare_disassembly_whole_entry_veneer_mixed_neighbors(&original, &selected)
        .unwrap();
    assert_eq!(again.files(), old.files());
    assert_eq!(selected.files, saved_files);
    assert_eq!(original, saved);
}

#[test]
fn whole_packed_rx_runs_retain_actual_veneer_storage_entry_and_image_bytes() {
    use crate::carrier::elf64::{Elf64, ElfVaddr, ParseLimits};
    let (original, text, p) = entry_veneer_fixture(0x11f7);
    let selected = bind(&original, &text, &p).unwrap();
    let old = crate::prepare_disassembly_whole_entry_veneer_mixed_neighbors(&original, &selected)
        .unwrap();
    let packed =
        crate::prepare_disassembly_whole_packed_entry_veneer_mixed_neighbors(&original, &selected)
            .unwrap();
    assert!(old.candidate_complete() && packed.candidate_complete());
    assert!(!packed.qualification_complete());
    assert_eq!(packed.reports().len(), 1);
    assert_eq!(
        packed.reports()[0].core_tactic,
        Some(li2core::engine::Tactic::NeighborEviction)
    );
    assert_eq!(
        packed.reports()[0].diagnostics,
        old.reports()[0].diagnostics
    );
    assert_eq!(
        packed.files()["plan-ledger.tsv"],
        old.files()["plan-ledger.tsv"]
    );
    assert_eq!(
        packed.files()["source.li2sparse"],
        old.files()["source.li2sparse"]
    );
    let plan = std::str::from_utf8(&packed.files()["plan-ledger.tsv"]).unwrap();
    let veneer: Vec<_> = plan
        .lines()
        .filter(|l| l.starts_with("entry-veneer\t"))
        .collect();
    assert_eq!(veneer.len(), 1);
    let v: Vec<_> = veneer[0].split('\t').collect();
    let storage = v[3].parse::<u64>().unwrap();
    let entry = v[4].parse::<u64>().unwrap();
    assert_eq!(entry - storage, 3909);
    let elf = Elf64::parse(
        &packed.files()["candidate.elf"],
        ParseLimits {
            max_program_headers: 64,
        },
    )
    .unwrap();
    let mut count = 0;
    for line in plan.lines().filter(|l| l.starts_with("image\t")) {
        let row: Vec<_> = line.split('\t').collect();
        let address = row[3].parse::<u64>().unwrap();
        let bytes = &packed.files()[row[6]];
        assert_eq!(bytes, &old.files()[row[6]]);
        assert_eq!(
            elf.executable_bytes(ElfVaddr(address), bytes.len() as u64)
                .unwrap(),
            bytes
        );
        count += 1;
    }
    assert_eq!(count, 2);
    assert_eq!(elf.executable_bytes(ElfVaddr(entry), 1).unwrap(), &[0xe9]);
    assert!(
        std::str::from_utf8(&packed.files()["ledger.tsv"])
            .unwrap()
            .contains(veneer[0])
    );
}

#[test]
fn whole_packed_rx_runs_preserve_pending_and_carrier_refusal_denominators() {
    for (all_selected, pairs, count) in [(false, 1, 2), (true, 2, 3)] {
        let (original, text, p) = mixed_pending_fixture(false, all_selected, pairs);
        let selected = bind(&original, &text, &p).unwrap();
        let old =
            crate::prepare_disassembly_whole_entry_veneer_mixed_neighbors(&original, &selected)
                .unwrap();
        let packed = crate::prepare_disassembly_whole_packed_entry_veneer_mixed_neighbors(
            &original, &selected,
        )
        .unwrap();
        assert_eq!(
            packed.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
            (1..=count).collect::<Vec<_>>()
        );
        assert!(!packed.candidate_complete() && !packed.qualification_complete());
        for name in [
            "report.tsv",
            "plan-ledger.tsv",
            "ledger.tsv",
            "metadata.li2meta",
            "disassembly-inventory.tsv",
            "disassembly-policy.txt",
        ] {
            assert_eq!(
                packed.files()[name],
                old.files()[name],
                "unchanged refusal evidence: {name}"
            );
        }
        assert!(!packed.files().contains_key("candidate.elf"));
        assert!(!packed.files().contains_key("source.li2sparse"));
        assert_eq!(packed.reports().last().unwrap().refusal_code, Some(12));
        for low in &packed.reports()[..count as usize - 1] {
            assert_eq!(low.refusal_code, Some(10_003));
        }
        assert!(
            std::str::from_utf8(&packed.files()["planning-profile.tsv"])
                .unwrap()
                .contains(PACKED_ENTRY_VENEER_MIXED_METADATA)
        );
    }
    // The new layout cannot waive the caller's stricter complete PHDR budget.
    let (original, text, p) = packed_rx_fixture();
    let p = p.replace("262144 64 4294967296", "262144 4 4294967296");
    let selected = bind(&original, &text, &p).unwrap();
    assert_eq!(selected.selection.limits.program_headers, 4);
    let packed =
        crate::prepare_disassembly_whole_packed_entry_veneer_mixed_neighbors(&original, &selected)
            .unwrap();
    assert_eq!(
        packed.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(!packed.candidate_complete() && !packed.qualification_complete());
    assert!(packed.reports().iter().all(|r| r.core_tactic
        == Some(li2core::engine::Tactic::Relocation)
        && r.refusal_code == Some(10_002)
        && r.refusal.as_ref().unwrap().stage == "carrier"
        && !r.candidate_emitted));
    assert!(!packed.files().contains_key("candidate.elf"));
    assert!(!packed.files().contains_key("source.li2sparse"));
    assert_eq!(
        packed.files()["disassembly-inventory.tsv"],
        selected.files["disassembly-inventory.tsv"]
    );
    assert_eq!(packed.files()["disassembly-policy.txt"], p.as_bytes());
    assert!(
        std::str::from_utf8(&packed.files()["planning-profile.tsv"])
            .unwrap()
            .contains(PACKED_ENTRY_VENEER_MIXED_METADATA)
    );
}

// Complete original/importer/policy puzzle: the overlapping E9 displacement
// identity is independent of the four-byte successor at V+6. Never executed.
fn overlapping_fixture(pending_victim: bool) -> (Vec<u8>, String, String) {
    let (mut original, _) = fixture(0, 0);
    let mut code = [
        0x2e, 0xb8, 0x37, 0x31, 0x42, 0x53, 0x44, 0x8d, 0x48, 3, 0x75, 0, 0xc3,
    ];
    if pending_victim {
        code[..6].copy_from_slice(&[0x0f, 0x85, 4, 0, 0, 0]);
    }
    original[0x1100..0x1100 + code.len()].copy_from_slice(&code);
    let mut text = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {PC} 4352 {}\n",
        digest(&original),
        code.len(),
    );
    for (start, end) in [(0, 6), (6, 10), (10, 12), (12, 13)] {
        writeln!(
            text,
            "head {} {}",
            PC + start as u64,
            ledger::hex(&code[start..end])
        )
        .unwrap();
    }
    writeln!(text, "region {HOOK} 73472 1\nhead {HOOK} c3").unwrap();
    let selected = PC + 6 + 0x0002_0000;
    let victim = PC + 5 + 0x0200_00e9;
    let mut p = policy(&original, &text, 0);
    if pending_victim {
        let low = BASE + 0x30000;
        writeln!(p, "search 1 B1 0 80 1 none 1 1\nallocation 1 selected {low} 1 4096 {low}:4096\nallocation 1 victim {victim} 1 4096 {}:4096", victim & !4095).unwrap();
    }
    let id = if pending_victim { 2 } else { 1 };
    writeln!(p, "search {id} T3 0 80 1 {PC} 1 1\nallocation {id} selected {selected} 1 4096 {}:4096\nallocation {id} victim {victim} 1 4096 {}:4096", selected & !4095, victim & !4095).unwrap();
    (original, text, p)
}

#[test]
fn whole_packed_overlapping_emits_exact_relay_and_both_owned_images() {
    use iced_x86::{Decoder, DecoderOptions};
    use li2core::engine::Tactic;
    let (original, text, p) = overlapping_fixture(false);
    let saved = original.clone();
    let selected = bind(&original, &text, &p).unwrap();
    let saved_files = selected.files.clone();
    assert_eq!(selected.selection.sites.len(), 1);
    assert_eq!(selected.selection.sites[0].heads.len(), 4);
    assert_eq!(
        (
            selected.selection.sites[0].pc,
            selected.selection.sites[0].length
        ),
        (PC + 10, 2)
    );
    let old =
        crate::prepare_disassembly_whole_packed_entry_veneer_mixed_neighbors(&original, &selected)
            .unwrap();
    assert!(!old.candidate_complete());
    assert_eq!(old.reports()[0].refusal_code, Some(11));
    let product =
        crate::prepare_disassembly_whole_packed_overlapping_neighbors(&original, &selected)
            .unwrap();
    assert!(product.candidate_complete());
    assert!(!product.qualification_complete());
    assert_eq!(product.reports().len(), 1);
    let report = &product.reports()[0];
    assert_eq!((report.id, report.pc, report.length), (1, PC + 10, 2));
    assert_eq!(report.core_tactic, Some(Tactic::NeighborEviction));
    assert!(report.refusal.is_none() && report.candidate_emitted);
    assert_eq!(report.diagnostics.matches("EngineAttempt {").count(), 1);
    let (metrics, attempt) = report.diagnostics.split_once("EngineAttempt {").unwrap();
    assert_eq!(attempt.matches("NeighborAttempt {").count(), 1);
    let selected_target = PC + 6 + 0x0002_0000;
    let victim_target = PC + 5 + 0x0200_00e9;
    let expected =
        li2core::engine::CandidateEvidence::Neighbor(vec![li2core::neighbor::NeighborAttempt {
            victim: PC,
            stage: li2core::neighbor::NeighborAttemptStage::Composition,
            victim_target: Some(victim_target),
            selected_target: Some(selected_target),
            refusal: None,
        }]);
    let actual: String = attempt.split_whitespace().collect();
    let expected: String = format!("candidates:{expected:#?}")
        .split_whitespace()
        .collect();
    assert!(actual.contains(&expected));
    assert!(metrics.contains("victims_examined: 1") && metrics.contains("pairs_examined: 1"));
    let candidate = &product.files()["candidate.elf"];
    let mut expected_code = original[0x1100..0x110d].to_vec();
    expected_code[..6].copy_from_slice(&[0xe9, 0xe9, 0, 0, 2, 0]);
    expected_code[10..12].copy_from_slice(&[0xeb, 0xf5]);
    assert_eq!(&candidate[0x1100..0x110d], expected_code);
    for (start, end, pc, target, len) in [
        (0x1100, 0x1105, PC, victim_target, 5),
        (0x1101, 0x1106, PC + 1, selected_target, 5),
        (0x110a, 0x110c, PC + 10, PC + 1, 2),
    ] {
        let mut decoder = Decoder::with_ip(64, &candidate[start..end], pc, DecoderOptions::NONE);
        let jump = decoder.decode();
        assert_eq!(
            jump.code(),
            if len == 5 {
                Code::Jmp_rel32_64
            } else {
                Code::Jmp_rel8_64
            }
        );
        assert_eq!(jump.len(), len);
        assert_eq!(jump.near_branch_target(), target);
        assert!(!decoder.can_decode());
    }
    assert_eq!(&candidate[0x1106..0x110a], &original[0x1106..0x110a]);
    assert_eq!(candidate[0x11f00], original[0x11f00]);
    let elf = Elf64::parse(
        candidate,
        ParseLimits {
            max_program_headers: 64,
        },
    )
    .unwrap();
    let plan = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    let rows: Vec<Vec<&str>> = plan.lines().map(|l| l.split('\t').collect()).collect();
    let images: Vec<_> = rows.iter().filter(|r| r[0] == "image").collect();
    let allocations: Vec<_> = rows.iter().filter(|r| r[0] == "allocation").collect();
    assert_eq!((images.len(), allocations.len()), (2, 2));
    for (image, address, original_pc) in [
        (images[0], selected_target, PC + 10),
        (images[1], victim_target, PC),
    ] {
        assert_eq!(image[3].parse::<u64>().unwrap(), address);
        let bytes = &product.files()[image[6]];
        assert_eq!(image[4].parse::<usize>().unwrap(), bytes.len());
        assert_eq!(image[5], digest(bytes));
        assert_eq!(
            elf.executable_bytes(ElfVaddr(address), bytes.len() as u64)
                .unwrap(),
            bytes
        );
        assert!(plan.contains(&format!("route\t{}\t{original_pc}\t{address}\n", image[1])));
        assert!(
            allocations
                .iter()
                .any(|r| r[3].parse::<u64>().unwrap() == (address & !4095)
                    && r[4].parse::<u64>().unwrap() == (address & !4095) + 4096
                    && r[5] == "4096")
        );
    }
    let geometry = li2core::neighbor::NeighborGeometry {
        selected: PC + 10,
        selected_len: 2,
        victim: PC,
        victim_len: 6,
        relay: PC + 1,
        rel8: -11,
        selected_target,
        victim_target,
    };
    assert!(plan.contains(&format!(
        "source-relay-geometry-hex\t1\t{}\n",
        ledger::hex(format!("{geometry:?}").as_bytes())
    )));
    assert!(!plan.contains("ENTRY-VENEER-EXTENSION"));
    let ledger = std::str::from_utf8(&product.files()["ledger.tsv"]).unwrap();
    assert!(ledger.contains("RX-RUN-EXTENSION\t1\ncarrier_layout\tlinux-adjacent-generated-rx-runs-v1\nrx_run_count\t2\nrx_run_image_count\t2\n"));
    assert_eq!(
        ledger
            .lines()
            .filter(|l| l.starts_with("rx-run-member\t"))
            .count(),
        2
    );
    assert_eq!(
        product.files()["disassembly-inventory.tsv"],
        saved_files["disassembly-inventory.tsv"]
    );
    assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
    assert!(
        std::str::from_utf8(&product.files()["planning-profile.tsv"])
            .unwrap()
            .contains(PACKED_OVERLAPPING_METADATA)
    );
    assert_eq!(selected.files, saved_files);
    assert_eq!(original, saved);
    assert_eq!(
        crate::prepare_disassembly_whole_packed_entry_veneer_mixed_neighbors(&original, &selected)
            .unwrap()
            .files(),
        old.files()
    );
}

#[test]
fn whole_packed_overlapping_retains_pending_original_and_atomic_denominator() {
    let (original, text, p) = overlapping_fixture(true);
    let saved = original.clone();
    let selected = bind(&original, &text, &p).unwrap();
    assert_eq!(
        selected
            .selection
            .sites
            .iter()
            .map(|s| (s.id, s.pc, s.length))
            .collect::<Vec<_>>(),
        [(1, PC, 6), (2, PC + 10, 2)]
    );
    let product =
        crate::prepare_disassembly_whole_packed_overlapping_neighbors(&original, &selected)
            .unwrap();
    assert!(!product.candidate_complete() && !product.qualification_complete());
    assert_eq!(
        product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(!product.files().contains_key("candidate.elf"));
    assert!(!product.files().contains_key("source.li2sparse"));
    assert!(product.reports().iter().all(|r| !r.candidate_emitted));
    let high = &product.reports()[1];
    assert_eq!(high.core_tactic, None);
    assert_eq!(high.refusal_code, Some(12));
    assert_eq!(high.refusal.as_ref().unwrap().stage, "core");
    assert_eq!(high.refusal.as_ref().unwrap().detail, "OwnershipConflict");
    assert_eq!(high.diagnostics.matches("EngineAttempt {").count(), 1);
    let (_, attempt) = high.diagnostics.split_once("EngineAttempt {").unwrap();
    assert_eq!(attempt.matches("NeighborAttempt {").count(), 1);
    let expected =
        li2core::engine::CandidateEvidence::Neighbor(vec![li2core::neighbor::NeighborAttempt {
            victim: PC,
            stage: li2core::neighbor::NeighborAttemptStage::Composition,
            victim_target: Some(PC + 5 + 0x0200_00e9),
            selected_target: Some(PC + 6 + 0x0002_0000),
            refusal: Some(li2core::contracts::Refusal::OwnershipConflict),
        }]);
    let actual: String = attempt.split_whitespace().collect();
    let expected: String = format!("candidates:{expected:#?}")
        .split_whitespace()
        .collect();
    assert!(actual.contains(&expected));
    let low = &product.reports()[0];
    assert_eq!(low.core_tactic, Some(li2core::engine::Tactic::Relocation));
    assert_eq!(low.refusal_code, Some(10_003));
    assert_eq!(low.refusal.as_ref().unwrap().stage, "atomic-selection");
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|n| n.starts_with("image-"))
            .count(),
        1
    );
    assert_eq!(
        product.files()["disassembly-inventory.tsv"],
        selected.files["disassembly-inventory.tsv"]
    );
    assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
    assert!(
        std::str::from_utf8(&product.files()["planning-profile.tsv"])
            .unwrap()
            .contains(PACKED_OVERLAPPING_METADATA)
    );
    assert_eq!(original, saved);
}

#[test]
fn whole_packed_overlapping_preserves_direct_outputs_and_carrier_limits() {
    let (original, text, p) = packed_rx_fixture();
    let selected = bind(&original, &text, &p).unwrap();
    let old =
        crate::prepare_disassembly_whole_packed_entry_veneer_mixed_neighbors(&original, &selected)
            .unwrap();
    let product =
        crate::prepare_disassembly_whole_packed_overlapping_neighbors(&original, &selected)
            .unwrap();
    assert!(old.candidate_complete() && product.candidate_complete());
    assert!(!product.qualification_complete());
    assert_eq!(
        old.files().keys().collect::<Vec<_>>(),
        product.files().keys().collect::<Vec<_>>()
    );
    for (name, bytes) in old.files() {
        if !matches!(name.as_str(), "planning-profile.tsv" | "bundle-index.tsv") {
            assert_eq!(
                &product.files()[name],
                bytes,
                "unchanged direct output: {name}"
            );
        }
    }
    assert!(product.reports().iter().all(|r| r.core_tactic
        == Some(li2core::engine::Tactic::Relocation)
        && r.candidate_emitted));
    let p = p.replace("262144 64 4294967296", "262144 4 4294967296");
    let selected = bind(&original, &text, &p).unwrap();
    assert_eq!(selected.selection.limits.program_headers, 4);
    let refused =
        crate::prepare_disassembly_whole_packed_overlapping_neighbors(&original, &selected)
            .unwrap();
    assert!(!refused.candidate_complete() && !refused.qualification_complete());
    assert_eq!(
        refused.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(refused.reports().iter().all(|r| r.core_tactic
        == Some(li2core::engine::Tactic::Relocation)
        && r.refusal_code == Some(10_002)
        && r.refusal.as_ref().unwrap().stage == "carrier"
        && !r.candidate_emitted));
    assert!(!refused.files().contains_key("candidate.elf"));
    assert!(!refused.files().contains_key("source.li2sparse"));
    assert_eq!(
        refused.files()["disassembly-inventory.tsv"],
        selected.files["disassembly-inventory.tsv"]
    );
    assert!(
        std::str::from_utf8(&refused.files()["planning-profile.tsv"])
            .unwrap()
            .contains(PACKED_OVERLAPPING_METADATA)
    );
}
