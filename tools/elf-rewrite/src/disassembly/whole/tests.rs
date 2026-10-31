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
