//! Fabricated original bytes only. No emitted image is mapped or executed.
use super::*;
use crate::prepare_disassembly;

const BASE: u64 = 0x400000;
const PC: u64 = BASE + 0x1100;
const HOOK: u64 = BASE + 0x1f00;
fn put16(b: &mut [u8], at: usize, value: u16) {
    b[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn digest(b: &[u8]) -> String {
    ledger::hex(&ContentId::of(b).0)
}

fn fixture(chunks: &[&[u8]]) -> (Vec<u8>, String) {
    let mut original = vec![0; 8192];
    original[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut original, 16, 2);
    put16(&mut original, 18, 62);
    put32(&mut original, 20, 1);
    put64(&mut original, 24, PC);
    put64(&mut original, 32, 64);
    put16(&mut original, 52, 64);
    put16(&mut original, 54, 56);
    put16(&mut original, 56, 2);
    for (n, (offset, flags)) in [(0, 4), (4096, 5)].into_iter().enumerate() {
        let at = 64 + n * 56;
        put32(&mut original, at, 1);
        put32(&mut original, at + 4, flags);
        put64(&mut original, at + 8, offset);
        put64(&mut original, at + 16, BASE + offset);
        put64(&mut original, at + 24, BASE + offset);
        put64(&mut original, at + 32, 4096);
        put64(&mut original, at + 40, 4096);
        put64(&mut original, at + 48, 4096);
    }
    let code: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    assert!(code.len() < (HOOK - PC) as usize);
    original[0x1100..0x1100 + code.len()].copy_from_slice(&code);
    original[0x1f00] = 0xc3;
    let mut ledger = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {PC} 4352 {}\n",
        digest(&original),
        code.len()
    );
    let mut pc = PC;
    for chunk in chunks {
        writeln!(ledger, "head {pc} {}", ledger::hex(chunk)).unwrap();
        pc += chunk.len() as u64;
    }
    writeln!(ledger, "region {HOOK} 7936 1\nhead {HOOK} c3").unwrap();
    (original, ledger)
}
fn checked(original: &[u8], ledger: &str) -> Result<Disassembly, Error> {
    import(
        original,
        ledger.as_bytes(),
        ContentId::of(ledger.as_bytes()),
    )
}
fn policy(original: &[u8], ledger: &str, count: usize) -> String {
    let mut out = format!(
        "LI2DISASM-POLICY 1\noriginal {}\nledger {}\ntarget fxsave64\ndomain 1\ncarrier {}\nlimits 1048576 16 16 65536 64 1048576 262144 64 4294967296\nnull-hook {HOOK}\n",
        digest(original),
        digest(ledger.as_bytes()),
        BASE + 0x8000
    );
    for id in 1..=count {
        let selected = BASE + 0x4000000 + id as u64 * 0x4000;
        let victim = BASE + 0x6000000 + id as u64 * 0x4000;
        writeln!(out, "search {id} B1 0 80 1 none 64 256").unwrap();
        writeln!(
            out,
            "allocation {id} selected {selected} 256 8192 {selected}:8192"
        )
        .unwrap();
        writeln!(
            out,
            "allocation {id} victim {victim} 256 8192 {victim}:8192"
        )
        .unwrap();
    }
    out
}
fn bind(original: &[u8], ledger: &str, policy: &str) -> Result<DisassemblySelection, Error> {
    checked(original, ledger)?.bind(policy.as_bytes(), ContentId::of(policy.as_bytes()))
}
fn complex() -> (Vec<u8>, String) {
    fixture(&[
        &[0x75, 0],
        &[0xeb, 0],
        &[0xe3, 0],
        &[0xff, 0xe0],
        &[0xe8, 0xf3, 0xff, 0xff, 0xff],
        &[0xe2, 0xfe],
        &[0xc3],
    ])
}

#[test]
fn complete_jump_denominator_ignores_names_reachability_and_call_cycles() {
    let (original, ledger) = complex();
    let imported = checked(&original, &ledger).unwrap();
    assert_eq!(
        imported.jumps.iter().map(|s| s.pc).collect::<Vec<_>>(),
        [PC, PC + 2, PC + 4, PC + 6]
    );
    assert_eq!(imported.regions.len(), 2);
    assert_eq!(imported.regions[0].instructions.len(), 7);
    assert_eq!(imported.regions[0].instructions[4].near_branch_target(), PC);
    for s in &imported.jumps {
        assert_eq!(s.block, addr(s.pc, 2).unwrap());
        assert_eq!(s.file_offset, 4352 + s.pc - PC);
    }
    // Unresolved external/indirect calls and an unbalanced function-like RSP
    // sequence do not fabricate a whole-function/CFG requirement at import.
    let (external, locations) = fixture(&[
        &[0x48, 0x83, 0xec, 0x20],
        &[0xff, 0xd0],
        &[0xe8, 0, 0, 0x10, 0],
        &[0xeb, 0],
        &[0xc3],
    ]);
    assert_eq!(checked(&external, &locations).unwrap().jumps().len(), 1);
    let selection = imported
        .bind(
            policy(&original, &ledger, 4).as_bytes(),
            ContentId::of(policy(&original, &ledger, 4).as_bytes()),
        )
        .unwrap();
    for s in &selection.selection.sites {
        assert_eq!(s.completeness, EntryCompleteness::AllInstructionHeads);
        assert_eq!(s.function, addr(PC, 16).unwrap());
        assert_eq!(
            s.heads.iter().map(|h| h.address).collect::<Vec<_>>(),
            [PC, PC + 2, PC + 4, PC + 6, PC + 8, PC + 13, PC + 15]
        );
        assert_eq!(s.resumes, li2core::contracts::ResumeObligation::NoneExist);
    }
}

#[test]
fn whole_hash_and_each_head_byte_length_and_location_are_independent_gates() {
    let (original, ledger) = complex();
    let first = format!("head {PC} 7500\n");
    for wrong in [
        ledger.replace(&first, ""),
        ledger.replace(&first, &format!("{first}{first}")),
        ledger.replace(&first, &format!("head {} 7500\n", PC + 1)),
        ledger.replace(&first, &format!("head {PC} 7501\n")),
        ledger
            .replace(&format!("head {} eb00\n", PC + 2), "")
            .replace(&first, &format!("head {PC} 7500eb00\n")),
        ledger.replace("complete-code", "partial-code"),
        ledger.replace("\nregion", "\r\nregion"),
    ] {
        assert!(checked(&original, &wrong).is_err());
    }
    assert!(import(&original, ledger.as_bytes(), ContentId([0; 32])).is_err());
    let mut changed = original.clone();
    changed[0x300] ^= 1; // not code: still covered by the whole-file identity
    assert!(checked(&changed, &ledger).is_err());
    let (truncated, truncated_ledger) = fixture(&[&[0x0f]]);
    assert!(checked(&truncated, &truncated_ledger).is_err());
}

#[test]
fn complete_ledger_checks_rx_inverse_owner_and_known_entry_contradictions() {
    let (original, ledger) = complex();
    for wrong in [
        ledger.replace("4352 16", "4353 16"),
        ledger.replace(&format!("region {HOOK}"), &format!("region {PC}")),
    ] {
        assert!(checked(&original, &wrong).is_err());
    }
    for (at, value) in [(64 + 56 + 4, 1_u32), (64 + 56 + 4, 7)] {
        let mut changed = original.clone();
        put32(&mut changed, at, value);
        let rebound = ledger.replace(&digest(&original), &digest(&changed));
        assert!(checked(&changed, &rebound).is_err());
    }
    let mut changed = original.clone();
    put64(&mut changed, 24, PC + 1);
    let rebound = ledger.replace(&digest(&original), &digest(&changed));
    assert!(checked(&changed, &rebound).is_err());
    for target in [255_u8, 32] {
        // instruction interior, then undeclared RX gap
        let (o, l) = fixture(&[&[0xeb, target], &[0xc3]]);
        assert!(checked(&o, &l).is_err());
    }
    // Aliased file ownership is not cured by disjoint virtual addresses.
    let mut changed = original.clone();
    put16(&mut changed, 56, 3);
    let copy = original[120..176].to_vec();
    changed[176..232].copy_from_slice(&copy);
    put64(&mut changed, 176 + 16, BASE + 0x10000);
    let rebound = ledger.replace(&digest(&original), &digest(&changed));
    assert!(checked(&changed, &rebound).is_err());
}

#[test]
fn policy_cannot_omit_add_select_replace_or_increase_existing_caps() {
    let (original, ledger) = complex();
    let p = policy(&original, &ledger, 4);
    let missing = p
        .lines()
        .filter(|l| !l.starts_with("search 4 "))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    for bad in [
        missing,
        p.clone() + "search 5 B1 0 80 1 none 64 256\n",
        p.clone() + "site 99 0 1 0 0 1 0 1 0 1 1 replace original-decode\n",
        p.replace("1048576 16 16", "1048576 1 16"),
        p.replace("1048576 16 16", "1048576 1025 16"),
        p.replace("B1 0 80", "B1 0 65537"),
        p.replace(
            &format!("ledger {}", digest(ledger.as_bytes())),
            &format!("ledger {}", "0".repeat(64)),
        ),
    ] {
        assert!(bind(&original, &ledger, &bad).is_err());
    }
    assert!(
        checked(&original, &ledger)
            .unwrap()
            .bind(p.as_bytes(), ContentId([0; 32]))
            .is_err()
    );
    let (o, l) = fixture(&[&[0xc3]]);
    assert!(checked(&o, &l).unwrap().jumps().is_empty());
    assert!(bind(&o, &l, &policy(&o, &l, 0)).is_err()); // no vacuous success
}

#[test]
fn null_hook_must_be_original_single_c3_and_endbr_heads_stay_marked() {
    let (original, ledger) = fixture(&[&[0xf3, 0x0f, 0x1e, 0xfa], &[0xe9, 0, 0, 0, 0], &[0xc3]]);
    let p = policy(&original, &ledger, 1);
    let selected = bind(&original, &ledger, &p).unwrap();
    assert!(selected.selection.sites[0].heads[0].requires_endbr);
    assert_eq!(selected.selection.hooks[0].expected, ContentId::of(&[0xc3]));
    for hook in [PC, PC + 4, HOOK + 1] {
        assert!(
            bind(
                &original,
                &ledger,
                &p.replace(&format!("null-hook {HOOK}"), &format!("null-hook {hook}"))
            )
            .is_err()
        );
    }
    let mut changed = original.clone();
    changed[0x1f00] = 0x90;
    let rebound = ledger
        .replace(&digest(&original), &digest(&changed))
        .replace(&format!("head {HOOK} c3"), &format!("head {HOOK} 90"));
    assert!(bind(&changed, &rebound, &policy(&changed, &rebound, 1)).is_err());
}

#[test]
fn shared_prepare_retains_every_refusal_and_never_emits_partial_candidate() {
    let (original, ledger) = complex();
    let p = policy(&original, &ledger, 4);
    let selected = bind(&original, &ledger, &p).unwrap();
    let product = prepare_disassembly(&original, &selected).unwrap();
    assert_eq!(
        product.reports().iter().map(|s| s.id).collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert!(
        product
            .reports()
            .iter()
            .all(|s| s.refusal.is_some() && !s.candidate_emitted)
    );
    assert!(!product.candidate_complete() && !product.qualification_complete());
    assert!(!product.files().contains_key("candidate.elf"));
    assert!(!product.files().contains_key("source.li2sparse"));
    assert_eq!(product.files()["disassembly.txt"], ledger.as_bytes());
    assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
    assert_eq!(product.files()["selection.txt"], selected.manifest());
    let mut indexed = product.files().clone();
    indexed.remove("bundle-index.tsv");
    assert_eq!(
        product.files()["bundle-index.tsv"],
        crate::ledger::index(ContentId::of(&original), &indexed)
    );
    let mut changed = original.clone();
    changed[0x300] ^= 1;
    assert_eq!(
        prepare_disassembly(&changed, &selected).unwrap_err().stage,
        "original-identity"
    );
}

#[test]
fn one_original_jump_uses_shared_carrier_and_hook_guard_without_live_authority() {
    let (original, ledger) = fixture(&[&[0xe9, 0, 0, 0, 0], &[0xc3]]);
    let selected = bind(&original, &ledger, &policy(&original, &ledger, 1)).unwrap();
    let before = original.clone();
    let product = prepare_disassembly(&original, &selected).unwrap();
    assert!(product.candidate_complete(), "{:?}", product.reports());
    assert!(!product.qualification_complete());
    assert_eq!(original, before);
    let candidate = &product.files()["candidate.elf"];
    assert_eq!(candidate[0x1f00], 0xc3);
    assert_eq!(&candidate[0x300..0x1000], &original[0x300..0x1000]);
    assert_eq!(&candidate[24..32], &original[24..32]);
    assert_eq!(product.reports().len(), 1);
    assert!(product.reports()[0].candidate_emitted && product.reports()[0].refusal.is_none());
}

#[test]
fn bounded_text_and_whole_program_projection_refuse_without_splitting() {
    let (original, ledger) = complex();
    assert!(checked(&original, &ledger.repeat(TEXT_LIMIT / ledger.len() + 1)).is_err());
    assert!(checked(&original, ledger.trim_end()).is_err());
    let chunks: Vec<&[u8]> = std::iter::repeat_n(&[0xeb, 0][..], 1025)
        .chain([&[0xc3][..]])
        .collect();
    let (original, ledger) = fixture(&chunks);
    let imported = checked(&original, &ledger).unwrap();
    assert_eq!(imported.jumps().len(), 1025);
    assert!(
        String::from_utf8(imported.inventory())
            .unwrap()
            .contains("complete_jump_count\t1025\n")
    );
    let p = policy(&original, &ledger, 1025).replace("1048576 16 16", "1048576 1024 16");
    assert!(
        imported
            .bind(p.as_bytes(), ContentId::of(p.as_bytes()))
            .is_err()
    );
}

// Each positive uses a literal whole victim and literal successor instructions.
// Targets are derived before planning from their fixed E9 suffix bytes; no
// planning outcome chooses a fixture, a permit, or a replacement population.
fn short_fixture(length: usize, extra_refusal: bool) -> (Vec<u8>, String, String) {
    assert!((6..=9).contains(&length));
    let mut victim = vec![0x2e; length - 5];
    victim.extend_from_slice(&[0xb8, 0x27, 0x31, 0x42, 0x53]);
    let mut chunks = vec![victim];
    if length == 9 {
        chunks.extend([vec![0x6a, 1], vec![0x58]]); // PUSH 1; POP RAX
    } else {
        chunks.push(vec![0xb8, 1, 1, 1, 1]); // MOV EAX,0x01010101
    }
    while chunks.iter().map(Vec::len).sum::<usize>() < 32 {
        chunks.push(vec![0x90]);
    }
    assert_eq!(chunks.iter().map(Vec::len).sum::<usize>(), 32);
    chunks.extend([vec![0x75, 0], vec![0xc3]]);
    if extra_refusal {
        chunks.extend([vec![0xe9, 0, 0, 0, 0], vec![0xc3]]);
    }
    let refs: Vec<_> = chunks.iter().map(Vec::as_slice).collect();
    let (original, ledger) = fixture(&refs);
    let mut displacement = [0_u8; 4];
    displacement[length - 6..].copy_from_slice(&original[0x1100 + length..0x1100 + 10]);
    let selected =
        u64::try_from(i128::from(PC + 10) + i128::from(i32::from_le_bytes(displacement))).unwrap();
    let victim_target = BASE + 0x6000080;
    // Original LOAD end BASE+0x2000 < carrier BASE+0x8000 < both
    // complete two-page permits. The two permits do not overlap each other.
    let selected_page = selected & !4095;
    let victim_page = victim_target & !4095;
    assert!(selected_page > BASE + 0x9000 && victim_page > BASE + 0x9000);
    assert!(selected_page + 8192 <= victim_page || victim_page + 8192 <= selected_page);
    assert!(selected_page.max(victim_page) + 8192 - BASE < 4294967296);
    let count = if extra_refusal { 2 } else { 1 };
    let p = policy(&original, &ledger, count);
    let mut rows: Vec<String> = p.lines().take(8).map(str::to_owned).collect();
    rows[0] = "LI2DISASM-POLICY 2".into();
    rows.insert(3, "neighbor-victims short-only".into());
    for id in 1..=count {
        rows.push(format!("search {id} T3 0 80 1 {PC} 1 1"));
        rows.push(format!(
            "allocation {id} selected {selected} 1 8192 {selected_page}:8192"
        ));
        rows.push(format!(
            "allocation {id} victim {victim_target} 1 8192 {victim_page}:8192"
        ));
    }
    (original, ledger, rows.join("\n") + "\n")
}
fn short_bind(original: &[u8], ledger: &str, p: &str) -> Result<DisassemblySelection, Error> {
    checked(original, ledger)?.bind_short_neighbors(p.as_bytes(), ContentId::of(p.as_bytes()))
}

#[test]
fn short_only_policy_is_explicit_digest_bound_and_not_legacy() {
    let (o, l, p) = short_fixture(6, false);
    let selected = short_bind(&o, &l, &p).unwrap();
    assert_eq!(selected.profile(), SHORT_ONLY_PROFILE);
    assert_eq!(selected.selection.manifest, selected.manifest());
    let manifest = std::str::from_utf8(selected.manifest()).unwrap();
    assert_eq!(
        manifest.lines().take(3).collect::<Vec<_>>(),
        [
            "LI2TOOL 1",
            &format!("original {}", digest(&o)),
            "neighbor-victims short-only"
        ]
    );
    assert!(selection::parse(selected.manifest()).is_err());
    assert!(crate::prepare(&o, selected.manifest()).is_err());
    assert!(bind(&o, &l, &p).is_err());
    let old_policy = policy(&o, &l, 1);
    assert!(short_bind(&o, &l, &old_policy).is_err());
    assert_eq!(bind(&o, &l, &old_policy).unwrap().profile(), PROFILE);
    let family = "neighbor-victims short-only\n";
    for wrong in [
        p.replace(family, ""),
        p.replace(family, &format!("{family}{family}")),
        p.replace(family, "neighbor-victims long-only\n"),
        p.replace(family, "")
            .replace("target fxsave64\n", &format!("target fxsave64\n{family}")),
        p.replace("LI2DISASM-POLICY 2", "LI2DISASM-POLICY 1"),
    ] {
        assert!(short_bind(&o, &l, &wrong).is_err());
    }
    assert!(
        checked(&o, &l)
            .unwrap()
            .bind_short_neighbors(p.as_bytes(), ContentId([0; 32]))
            .is_err()
    );
    for wrong in [
        manifest.replace(family, ""),
        manifest.replace(family, &format!("{family}{family}")),
        manifest.replace(family, "neighbor-victims long-only\n"),
        manifest.replace(family, "") + family,
    ] {
        assert!(selection::parse_short_neighbor_projection(wrong.as_bytes()).is_err());
    }
    let profile = std::str::from_utf8(&selected.files["planning-profile.tsv"]).unwrap();
    assert!(profile.starts_with(&format!(
        "LI2PLANNING\t1\nprofile\t{SHORT_ONLY_PROFILE}\nneighbor_victims\tshort-only\n"
    )));
    assert!(profile.contains(&format!(
        "selection_sha256\t{}\n",
        digest(selected.manifest())
    )));
    assert!(profile.contains(&format!("policy_sha256\t{}\n", digest(p.as_bytes()))));
    assert_ne!(
        ContentId::of(selected.manifest()),
        ContentId::of(manifest.replace(family, "").as_bytes())
    );
}

#[test]
fn short_only_disassembly_forced_t3_preserves_all_heads_and_bytes() {
    for length in 6..=9 {
        let (o, l, p) = short_fixture(length, false);
        let imported = checked(&o, &l).unwrap();
        let expected_heads: Vec<_> = imported.regions[0]
            .instructions
            .iter()
            .map(|i| (i.ip(), i.len()))
            .collect();
        let selected = short_bind(&o, &l, &p).unwrap();
        assert_eq!(selected.selection.sites.len(), 1);
        assert_eq!(
            selected.selection.sites[0].completeness,
            EntryCompleteness::AllInstructionHeads
        );
        assert_eq!(
            selected.selection.sites[0]
                .heads
                .iter()
                .map(|h| h.address)
                .collect::<Vec<_>>(),
            expected_heads.iter().map(|(pc, _)| *pc).collect::<Vec<_>>()
        );
        let product = prepare_disassembly(&o, &selected).unwrap();
        assert!(product.candidate_complete(), "{:?}", product.reports());
        assert!(!product.qualification_complete());
        assert_eq!(product.reports().len(), 1);
        assert_eq!(
            product.reports()[0].core_tactic,
            Some(li2core::engine::Tactic::NeighborEviction)
        );
        assert!(product.reports()[0].candidate_emitted && product.reports()[0].refusal.is_none());
        let candidate = &product.files()["candidate.elf"];
        assert_eq!(&candidate[0x1120..0x1122], &[0xeb, (-29_i8) as u8]);
        assert_eq!(candidate[0x1100], 0xe9);
        assert_eq!(candidate[0x1105], 0xe9);
        for (pc, width) in expected_heads {
            if pc == PC || pc == PC + 32 {
                continue;
            }
            let offset = (pc - BASE) as usize;
            assert_eq!(
                &candidate[offset..offset + width],
                &o[offset..offset + width]
            );
        }
        assert_eq!(
            &candidate[0x1100 + length..0x110a],
            &o[0x1100 + length..0x110a]
        );
        assert_eq!(candidate[0x1f00], 0xc3);
        assert_eq!(product.files()["selection.txt"], selected.manifest());
        assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
        assert!(product.files().contains_key("source.li2sparse"));
        assert!(
            std::str::from_utf8(&product.files()["disassembly-inventory.tsv"])
                .unwrap()
                .contains(&format!(
                    "profile\t{SHORT_ONLY_PROFILE}\nneighbor_victims\tshort-only\n"
                ))
        );
        let mut wrong = o.clone();
        wrong[0x300] ^= 1;
        assert_eq!(
            prepare_disassembly(&wrong, &selected).unwrap_err().stage,
            "original-identity"
        );
    }
}

#[test]
fn short_only_disassembly_refusal_retains_the_complete_denominator() {
    let (o, l, p) = short_fixture(8, true);
    let selected = short_bind(&o, &l, &p).unwrap();
    assert_eq!(
        selected
            .selection
            .sites
            .iter()
            .map(|s| s.id)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    let product = prepare_disassembly(&o, &selected).unwrap();
    assert_eq!(
        product.reports().iter().map(|s| s.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        product.reports()[0].core_tactic,
        Some(li2core::engine::Tactic::NeighborEviction)
    );
    assert!(!product.reports()[0].diagnostics.is_empty());
    assert_eq!(product.reports()[1].core_tactic, None); // original five-byte E9
    assert!(
        product
            .reports()
            .iter()
            .all(|r| r.refusal.is_some() && !r.candidate_emitted)
    );
    assert!(!product.candidate_complete() && !product.qualification_complete());
    assert!(!product.files().contains_key("candidate.elf"));
    assert!(!product.files().contains_key("source.li2sparse"));
    assert!(product.files().contains_key("image-0000.bin"));
    assert!(product.files().contains_key("image-0001.bin"));
    assert_eq!(product.files()["disassembly.txt"], l.as_bytes());
    assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
}

#[test]
fn short_only_projection_and_search_caps_are_not_widened() {
    let (o, l, p) = short_fixture(7, false);
    let selected = short_bind(&o, &l, &p).unwrap();
    let mut exact = selected.manifest().to_vec();
    exact.resize(TEXT_LIMIT, b'\n');
    assert_eq!(
        selection::parse_short_neighbor_projection(&exact)
            .unwrap()
            .manifest,
        exact
    );
    exact.push(b'\n');
    assert!(selection::parse_short_neighbor_projection(&exact).is_err());
    let stripped = std::str::from_utf8(&exact)
        .unwrap()
        .replace("neighbor-victims short-only\n", "");
    assert!(selection::parse(stripped.as_bytes()).is_ok()); // bound is BEFORE stripping
    let search = format!("search 1 T3 0 80 1 {PC} 1 1\n");
    for wrong in [
        p.replace(&search, ""),
        p.clone() + &search,
        p.clone() + "search 2 T3 0 80 1 none 1 1\n",
        p.replace("1048576 16 16", "1048576 0 16"),
        p.replace("1048576 16 16", "1048576 1025 16"),
        p.replace("T3 0 80", "T3 0 65537"),
        p.replace(
            &format!("ledger {}", digest(l.as_bytes())),
            &format!("ledger {}", "0".repeat(64)),
        ),
    ] {
        assert!(short_bind(&o, &l, &wrong).is_err());
    }
    for wrong in [
        p.replace(&search, &format!("search 1 T3 0 80 1 {PC} 0 1\n")),
        p.replace(&search, &format!("search 1 T3 0 80 1 {PC} 1 0\n")),
        p.replace("1048576 16 16", "1048576 16 1"),
    ] {
        let selected = short_bind(&o, &l, &wrong).unwrap();
        let product = prepare_disassembly(&o, &selected).unwrap();
        assert_eq!(product.reports().len(), 1);
        assert!(!product.candidate_complete());
        assert!(product.reports()[0].refusal.is_some());
        assert!(!product.files().contains_key("candidate.elf"));
    }
    let malformed = l.replace(&format!("head {PC} "), &format!("head {} ", PC + 1));
    assert!(checked(&o, &malformed).is_err());
    assert!(short_bind(&o, &l, &(p.clone() + &"x".repeat(TEXT_LIMIT))).is_err());
}

fn owned_fixture(all_conflict: bool) -> (Vec<u8>, String, String) {
    let mut code = [0x90; 48];
    code[..3].copy_from_slice(&[0x75, 0, 0xc3]);
    code[14..16].copy_from_slice(if all_conflict {
        &[0x75, 0]
    } else {
        &[0xff, 0xc0]
    });
    code[16..22].copy_from_slice(&[0x2e, 0xb8, 0x37, 0x31, 0x42, 0x53]);
    code[22..28].copy_from_slice(&[0xb8, 1, 1, 1, 1, 0xc3]);
    code[30..32].copy_from_slice(&[0x75, 0]);
    code[32..38].copy_from_slice(&[0x2e, 0xb8, 0x27, 0x31, 0x42, 0x53]);
    code[38..44].copy_from_slice(&[0xb8, 1, 1, 1, 1, 0xc3]);
    let heads: [usize; 27] = [
        0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 22, 27, 28, 29, 30, 32, 38, 43, 44, 45,
        46, 47,
    ];
    let chunks: Vec<_> = heads
        .iter()
        .enumerate()
        .map(|(i, &start)| &code[start..heads.get(i + 1).copied().unwrap_or(code.len())])
        .collect();
    let (original, ledger) = fixture(&chunks);
    let count = if all_conflict { 3 } else { 2 };
    let base = policy(&original, &ledger, count);
    let mut rows: Vec<String> = base.lines().take(8).map(str::to_owned).collect();
    rows[0] = "LI2DISASM-POLICY 3".into();
    rows[6] = rows[6].replace("4294967296", "2147483648");
    rows.insert(3, "neighbor-victims short-only".into());
    rows.insert(4, "neighbor-ownership inherited-t3".into());
    let selected_u = PC + 26 + 0x010101b8;
    let selected_v = PC + 42 + 0x010101b8;
    let victim = PC + 0x06000080;
    let high_gp = PC + 35 + 0x27b82e00;
    let low_gp = PC + 19 + 0x37b82e00;
    assert_eq!(selected_u & !4095, selected_v & !4095);
    let pages = [
        selected_u & !4095,
        victim & !4095,
        high_gp & !4095,
        low_gp & !4095,
    ];
    for (i, &a) in pages.iter().enumerate() {
        assert!(a >= BASE + 0x9000 && a + 8192 - BASE < 2147483648);
        for &b in &pages[i + 1..] {
            assert!(a + 8192 <= b || b + 8192 <= a);
        }
    }
    for id in 1..=count {
        let target = if id == 1 {
            selected_v
        } else if all_conflict && id == 2 {
            low_gp
        } else {
            high_gp
        };
        let tactic = if id == 1 { "T3" } else { "B2" };
        rows.push(format!("search {id} {tactic} 0 80 1 none 2 2"));
        rows.push(format!(
            "allocation {id} selected {target} 1 8192 {}:8192",
            target & !4095
        ));
        rows.push(format!(
            "allocation {id} victim {victim} 1 8192 {}:8192",
            victim & !4095
        ));
    }
    (original, ledger, rows.join("\n") + "\n")
}

fn owned_bind(original: &[u8], ledger: &str, p: &str) -> Result<DisassemblySelection, Error> {
    checked(original, ledger)?.bind_short_t3_ownership(p.as_bytes(), ContentId::of(p.as_bytes()))
}

#[test]
fn short_t3_ownership_policy_and_projection_bind_both_modes() {
    let (o, l, p) = owned_fixture(false);
    let selected = owned_bind(&o, &l, &p).unwrap();
    assert_eq!(selected.profile(), SHORT_T3_OWNERSHIP_PROFILE);
    let manifest = std::str::from_utf8(selected.manifest()).unwrap();
    let family = "neighbor-victims short-only\n";
    let ownership = "neighbor-ownership inherited-t3\n";
    let mode = format!("{family}{ownership}");
    assert_eq!(
        manifest.lines().take(4).collect::<Vec<_>>(),
        [
            "LI2TOOL 1",
            &format!("original {}", digest(&o)),
            "neighbor-victims short-only",
            "neighbor-ownership inherited-t3",
        ]
    );
    assert!(selection::parse(selected.manifest()).is_err());
    assert!(selection::parse_short_neighbor_projection(selected.manifest()).is_err());
    assert!(crate::prepare(&o, selected.manifest()).is_err());
    assert!(bind(&o, &l, &p).is_err());
    assert!(short_bind(&o, &l, &p).is_err());
    let old = p
        .replace("LI2DISASM-POLICY 3", "LI2DISASM-POLICY 2")
        .replace(ownership, "");
    assert!(owned_bind(&o, &l, &old).is_err());
    assert!(owned_bind(&o, &l, &policy(&o, &l, 2)).is_err());
    assert!(
        checked(&o, &l)
            .unwrap()
            .bind_short_t3_ownership(p.as_bytes(), ContentId([0; 32]))
            .is_err()
    );
    for wrong in [
        p.replace(family, ""),
        p.replace(ownership, ""),
        p.replace(family, "neighbor-victims long-only\n"),
        p.replace(ownership, "neighbor-ownership local-only\n"),
        p.replace(ownership, &format!("{ownership}{ownership}")),
        p.replace(family, &format!("{family}{family}")),
        p.replace(&mode, &format!("{ownership}{family}")),
        p.replace(ownership, "") + ownership,
        p.replace("LI2DISASM-POLICY 3", "LI2DISASM-POLICY 2"),
    ] {
        assert!(owned_bind(&o, &l, &wrong).is_err()); // each receives its recomputed digest
    }
    for wrong in [
        manifest.replace(family, ""),
        manifest.replace(ownership, ""),
        manifest.replace(ownership, &format!("{ownership}{ownership}")),
        manifest.replace(&mode, &format!("{ownership}{family}")),
        manifest.replace(ownership, "") + ownership,
        manifest.replace(ownership, "neighbor-ownership local-only\n"),
    ] {
        assert!(selection::parse_short_t3_ownership_projection(wrong.as_bytes()).is_err());
    }
    let profile = std::str::from_utf8(&selected.files["planning-profile.tsv"]).unwrap();
    assert!(profile.starts_with(&format!("LI2PLANNING\t1\nprofile\t{SHORT_T3_OWNERSHIP_PROFILE}\nneighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\n")));
    assert!(profile.contains(&format!(
        "selection_sha256\t{}\n",
        digest(selected.manifest())
    )));
    assert!(profile.contains(&format!("policy_sha256\t{}\n", digest(p.as_bytes()))));
    assert_ne!(
        ContentId::of(selected.manifest()),
        ContentId::of(manifest.replace(&mode, "").as_bytes())
    );
    assert_eq!(
        selected.files["disassembly-inventory.tsv"],
        checked(&o, &l).unwrap().inventory_short_t3_ownership()
    );
}

#[test]
fn short_t3_ownership_actual_preceding_jump_admits_second_victim() {
    let (o, l, p) = owned_fixture(false);
    assert_eq!(l.lines().filter(|r| r.starts_with("head ")).count(), 28);
    let selected = owned_bind(&o, &l, &p).unwrap();
    assert_eq!(
        selected
            .selection
            .sites
            .iter()
            .map(|s| s.pc)
            .collect::<Vec<_>>(),
        [PC, PC + 30]
    );
    assert!(selected.selection.sites.iter().all(|s| s.heads.len() == 27));
    let product = prepare_disassembly(&o, &selected).unwrap();
    assert!(product.candidate_complete()); // refusal cannot satisfy this positive
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
    let evidence = &product.reports()[0].diagnostics;
    assert!(evidence.contains("OwnershipConflict") && evidence.contains("stage: Composition"));
    assert!(evidence.contains("pairs_examined: 2") && evidence.contains("victims_examined: 2"));
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|n| n.starts_with("image-") && n.ends_with(".bin"))
            .count(),
        3
    );
    let mut expected = o[0x1100..0x1130].to_vec();
    expected[..2].copy_from_slice(&[0xeb, 19]); // S -> U+5
    expected[16..21].copy_from_slice(&[0xe9, 0x6b, 0, 0, 6]); // U -> fixed victim image
    expected[21..26].copy_from_slice(&[0xe9, 0xb8, 1, 1, 1]); // fixed suffix -> selected U image
    expected[30..35].copy_from_slice(&[0xe9, 0, 0x2e, 0xb8, 0x27]); // actual prior selected GP
    let candidate = &product.files()["candidate.elf"];
    assert_eq!(&candidate[0x1100..0x1130], expected.as_slice());
    assert_eq!(&candidate[0x1120..0x1126], &o[0x1120..0x1126]); // rejected V stays original
    assert_eq!(candidate[0x1f00], 0xc3);
    let old = p
        .replace("LI2DISASM-POLICY 3", "LI2DISASM-POLICY 2")
        .replace("neighbor-ownership inherited-t3\n", "");
    let legacy = prepare_disassembly(&o, &short_bind(&o, &l, &old).unwrap()).unwrap();
    assert!(!legacy.candidate_complete());
    assert_eq!(
        legacy.reports()[0].core_tactic,
        Some(li2core::engine::Tactic::NeighborEviction)
    );
    assert!(
        legacy
            .reports()
            .iter()
            .all(|r| r.refusal.is_some() && !r.candidate_emitted)
    );
    assert!(!legacy.files().contains_key("candidate.elf"));
}

#[test]
fn short_t3_ownership_conflicts_and_pair_cap_keep_every_report() {
    for all_conflict in [false, true] {
        let (o, l, mut p) = owned_fixture(all_conflict);
        if !all_conflict {
            p = p.replace(
                "search 1 T3 0 80 1 none 2 2\n",
                "search 1 T3 0 80 1 none 2 1\n",
            );
        }
        let selected = owned_bind(&o, &l, &p).unwrap();
        let product = prepare_disassembly(&o, &selected).unwrap();
        let count = if all_conflict { 3 } else { 2 };
        assert_eq!(
            product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
            (1..=count).collect::<Vec<_>>()
        );
        assert!(
            product
                .reports()
                .iter()
                .all(|r| r.refusal.is_some() && !r.candidate_emitted)
        );
        assert!(
            product.reports()[0]
                .diagnostics
                .contains("OwnershipConflict")
        );
        assert!(
            product.reports()[0]
                .diagnostics
                .contains("stage: Composition")
        );
        // Atomic selection must not mask a failed predecessor or a successful T3.
        for report in &product.reports()[1..] {
            assert_eq!(
                report.core_tactic,
                Some(li2core::engine::Tactic::GeneralizedPun)
            );
            assert_eq!(report.refusal.as_ref().unwrap().stage, "atomic-selection");
            assert_eq!(report.refusal_code, Some(10_003));
        }
        let report = &product.reports()[0];
        assert_eq!(report.core_tactic, None);
        assert_eq!(report.refusal.as_ref().unwrap().stage, "core");
        assert_eq!(report.refusal.as_ref().unwrap().detail, "OwnershipConflict");
        assert_eq!(report.refusal_code, Some(12));
        let evidence: String = report.diagnostics.split_whitespace().collect();
        assert!(evidence.starts_with("EngineFailure{reason:OwnershipConflict,"));
        assert_eq!(evidence.matches("EngineAttempt{").count(), 1);
        assert_eq!(evidence.matches("accepted:false").count(), 1);
        assert!(!evidence.contains("accepted:true"));
        assert!(!evidence.contains("stop:Accepted"));
        let expected_pairs = if all_conflict {
            vec![
                (PC + 32, PC + 42 + 0x010101b8),
                (PC + 16, PC + 26 + 0x010101b8),
            ]
        } else {
            vec![(PC + 32, PC + 42 + 0x010101b8)]
        };
        let expected_attempts: Vec<_> = expected_pairs
            .into_iter()
            .map(
                |(victim, selected_target)| li2core::neighbor::NeighborAttempt {
                    victim,
                    stage: li2core::neighbor::NeighborAttemptStage::Composition,
                    victim_target: Some(PC + 0x06000080),
                    selected_target: Some(selected_target),
                    refusal: Some(li2core::contracts::Refusal::OwnershipConflict),
                },
            )
            .collect();
        let expected_evidence: String = format!("candidates:Neighbor({expected_attempts:#?},)")
            .split_whitespace()
            .collect();
        assert!(evidence.contains(&expected_evidence));
        assert_eq!(evidence.matches("candidates:Neighbor(").count(), 1);
        assert_eq!(
            evidence.matches("NeighborAttempt{").count(),
            if all_conflict { 2 } else { 1 }
        );
        assert_eq!(
            product
                .files()
                .keys()
                .filter(|n| n.starts_with("image-") && n.ends_with(".bin"))
                .count(),
            if all_conflict { 2 } else { 1 }
        );
        if !all_conflict {
            let evidence = &product.reports()[0].diagnostics;
            let runs: Vec<_> = evidence.split("SearchRun {").skip(1).collect();
            assert_eq!(runs.len(), 6);
            for (run, (domain, examined, stop)) in runs.iter().zip([
                ("Victims", 2, "Interrupted"),
                ("JointPairs", 1, "BudgetLimited"),
                ("VictimImages", 1, "BudgetLimited"),
                ("SelectedImages", 1, "DomainComplete"),
                ("VictimImages", 1, "Interrupted"),
                ("SelectedImages", 0, "Interrupted"),
            ]) {
                assert!(run.contains(&format!("domain: {domain},")));
                assert!(run.contains(&format!("examined: {examined},")));
                assert!(run.contains(&format!("stop: {stop}")));
            }
            assert!(runs[1].contains("remaining_at_least: 1"));
        }
        assert!(!product.candidate_complete() && !product.qualification_complete());
        assert!(!product.files().contains_key("candidate.elf"));
        assert!(!product.files().contains_key("source.li2sparse"));
        assert_eq!(product.files()["disassembly.txt"], l.as_bytes());
        assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
    }
}

#[test]
fn short_t3_ownership_full_projection_bound_and_resource_refusals() {
    let (o, l, p) = owned_fixture(false);
    let selected = owned_bind(&o, &l, &p).unwrap();
    let mut exact = selected.manifest().to_vec();
    exact.resize(TEXT_LIMIT, b'\n');
    assert_eq!(
        selection::parse_short_t3_ownership_projection(&exact)
            .unwrap()
            .manifest,
        exact
    );
    exact.push(b'\n');
    assert!(selection::parse_short_t3_ownership_projection(&exact).is_err());
    let stripped = std::str::from_utf8(&exact)
        .unwrap()
        .replace("neighbor-victims short-only\n", "")
        .replace("neighbor-ownership inherited-t3\n", "");
    assert!(selection::parse(stripped.as_bytes()).is_ok());
    let search = "search 1 T3 0 80 1 none 2 2\n";
    for wrong in [
        p.replace(search, ""),
        p.clone() + search,
        p.clone() + "search 3 T3 0 80 1 none 2 2\n",
        p.replace("1048576 16 16", "1048576 1025 16"),
        p.replace("T3 0 80", "T3 0 65537"),
        p.clone() + &"x".repeat(TEXT_LIMIT),
    ] {
        assert!(owned_bind(&o, &l, &wrong).is_err());
    }
    for wrong in [
        p.replace(search, "search 1 T3 0 80 1 none 0 2\n"),
        p.replace(search, "search 1 T3 0 80 1 none 2 0\n"),
        p.replace("1048576 16 16", "1048576 16 2"), // prior image plus locally valid two-image T3
    ] {
        let selected = owned_bind(&o, &l, &wrong).unwrap();
        let product = prepare_disassembly(&o, &selected).unwrap();
        assert_eq!(product.reports().len(), 2);
        assert!(product.reports().iter().all(|r| r.refusal.is_some()));
        assert!(!product.candidate_complete() && !product.files().contains_key("candidate.elf"));
    }
    let malformed = l.replace(&format!("head {PC} "), &format!("head {} ", PC + 1));
    assert!(checked(&o, &malformed).is_err());
}

// Frozen whole-selection puzzles. No emitted image is executed or mapped.
fn pending_fixture(suffix: bool) -> (Vec<u8>, String, String) {
    let code: Vec<u8> = if suffix {
        vec![
            0x2e, 0x2e, 0x2e, 0x2e, 0xb8, 0x37, 0x31, 0x42, 0x53, 0x01, 0xc0, 0xc3, 0x90, 0x90,
            0x90, 0x90, 0x2e, 0xb8, 0x27, 0x31, 0x42, 0x53, 0x75, 0, 0x6a, 1, 0x58, 0xc3, 0x90,
            0x90, 0x90, 0x90, 0x75, 0, 0xc3,
        ]
    } else {
        vec![
            0x2e, 0xb8, 0x37, 0x31, 0x42, 0x53, 0xb8, 1, 1, 1, 1, 0xc3, 0x90, 0x90, 0x90, 0x90,
            0x0f, 0x85, 10, 0, 0, 0, 0xb8, 1, 1, 1, 1, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x75, 0, 0xc3,
        ]
    };
    let heads: &[usize] = if suffix {
        &[
            0, 9, 11, 12, 13, 14, 15, 16, 22, 24, 26, 27, 28, 29, 30, 31, 32, 34,
        ]
    } else {
        &[0, 6, 11, 12, 13, 14, 15, 16, 22, 27, 28, 29, 30, 31, 32, 34]
    };
    assert_eq!(code.len(), 35);
    let chunks: Vec<_> = heads
        .iter()
        .enumerate()
        .map(|(i, &at)| &code[at..heads.get(i + 1).copied().unwrap_or(code.len())])
        .collect();
    let (o, l) = fixture(&chunks);
    let base = policy(&o, &l, 2);
    let mut rows: Vec<String> = base.lines().take(8).map(str::to_owned).collect();
    rows[0] = "LI2DISASM-POLICY 4".into();
    rows.insert(3, "neighbor-victims short-only".into());
    rows.insert(4, "neighbor-ownership inherited-t3".into());
    rows.insert(5, "pending-selected full-instruction-ownership".into());
    let later = PC + if suffix { 0x5801_6a1b } else { 0x0400_0080 };
    let selected = PC + if suffix { 0x016a_008f } else { 0x0101_01d2 };
    let victim = PC + 0x0600_0080;
    for (id, tactic, target) in [
        (1, if suffix { "B2" } else { "B1" }, later),
        (2, "T3", selected),
    ] {
        rows.push(format!("search {id} {tactic} 0 80 1 none 2 2"));
        rows.push(format!(
            "allocation {id} selected {target} 1 8192 {}:8192",
            target & !4095
        ));
        rows.push(format!(
            "allocation {id} victim {victim} 1 8192 {}:8192",
            victim & !4095
        ));
    }
    (o, l, rows.join("\n") + "\n")
}
fn pending_bind(o: &[u8], l: &str, p: &str) -> Result<DisassemblySelection, Error> {
    checked(o, l)?.bind_short_t3_pending(p.as_bytes(), ContentId::of(p.as_bytes()))
}
fn pending_old_policy(p: &str) -> String {
    p.replace("LI2DISASM-POLICY 4", "LI2DISASM-POLICY 3")
        .replace("pending-selected full-instruction-ownership\n", "")
}
fn pending_no_candidate(product: &crate::Product, ids: &[u64]) {
    assert_eq!(
        product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        ids
    );
    assert!(
        product
            .reports()
            .iter()
            .all(|r| r.refusal.is_some() && !r.candidate_emitted)
    );
    assert!(!product.candidate_complete() && !product.qualification_complete());
    assert!(!product.files().contains_key("candidate.elf"));
    assert!(!product.files().contains_key("source.li2sparse"));
}
fn pending_attempts(report: &crate::SiteReport, rows: &[li2core::neighbor::NeighborAttempt]) {
    let actual: String = report.diagnostics.split_whitespace().collect();
    let expected: String = format!("candidates:Neighbor({rows:#?},)")
        .split_whitespace()
        .collect();
    assert!(actual.contains(&expected));
    assert_eq!(actual.matches("candidates:Neighbor(").count(), 1);
}
fn pending_row(
    victim: u64,
    target: u64,
    stage: li2core::neighbor::NeighborAttemptStage,
    refusal: Option<li2core::contracts::Refusal>,
) -> li2core::neighbor::NeighborAttempt {
    li2core::neighbor::NeighborAttempt {
        victim,
        stage,
        victim_target: Some(PC + 0x0600_0080),
        selected_target: Some(target),
        refusal,
    }
}
fn pending_high_plan(
    o: &[u8],
    selected: &DisassemblySelection,
) -> (
    li2core::composition::Composition,
    li2core::emission::ArtifactPlan,
) {
    use li2core::contracts::*;
    use li2core::emission::*;
    let s = &selected.selection;
    let site = s.sites.last().unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity(s.original.0),
        mapping: s.bias_domain,
        generation: 1,
    };
    let code = &o[(site.snapshot.start() - BASE) as usize..(site.snapshot.end() - BASE) as usize];
    let entries = LegalEntrySet {
        identity,
        scope: site.function,
        provenance: EntryProvenance::Declared("pending fixture".into()),
        completeness: site.completeness,
        entries: site.heads.clone(),
        resumes: site.resumes.clone(),
    };
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(s.target, s.bias_domain).unwrap(),
        SymbolicHook {
            identity: 1,
            address: Some(HOOK),
        },
        vec![
            addr(BASE, 8192).unwrap(),
            addr(BASE + 0x8000, 4096).unwrap(),
        ],
    );
    let request = ArtifactRequest {
        site: PlanningSite {
            identity,
            code,
            base_address: site.snapshot.start(),
            function: site.function,
            block: site.block,
            logical_pc: site.pc,
            entries: &entries,
            semantics: site.semantics,
            allocation: &site.selected_allocation,
            search: site.search,
        },
        emission: &emission,
    };
    let mut composition = li2core::composition::Composition::new(
        identity,
        vec![ExpectedBytes {
            address: site.snapshot.start(),
            bytes: code.to_vec(),
        }],
    )
    .unwrap();
    let plan = li2core::engine::plan_with_emission_after_and_short_t3_ownership(
        &request,
        &composition,
        &site.victim_allocation,
        li2core::engine::EnginePolicy {
            forced: site.forced,
            neighbor: li2core::neighbor::NeighborSearch {
                forced_victim: site.forced_victim,
                max_victims: site.max_victims,
                max_pairs: site.max_pairs,
            },
            bundle: li2core::bundle::BundleBudget {
                max_steps: 2,
                max_mappings: s.limits.images,
                max_virtual_bytes: s.limits.new_load_pages * 4096,
                max_backing_bytes: s.limits.new_load_pages * 4096,
                max_virtual_span: s.limits.virtual_span,
            },
            ..Default::default()
        },
    )
    .unwrap();
    for step in plan.source_steps() {
        composition.append(step).unwrap();
    }
    (composition, plan)
}
fn pending_complete(suffix: bool) {
    use li2core::contracts::Refusal;
    use li2core::engine::Tactic;
    use li2core::neighbor::NeighborAttemptStage::Composition;
    let (o, l, p) = pending_fixture(suffix);
    let saved = o.clone();
    let selected = pending_bind(&o, &l, &p).unwrap();
    let lower = PC + if suffix { 22 } else { 16 };
    let heads: Vec<_> = if suffix {
        vec![
            0, 9, 11, 12, 13, 14, 15, 16, 22, 24, 26, 27, 28, 29, 30, 31, 32, 34,
        ]
    } else {
        vec![0, 6, 11, 12, 13, 14, 15, 16, 22, 27, 28, 29, 30, 31, 32, 34]
    }
    .into_iter()
    .map(|offset| PC + offset)
    .collect();
    assert_eq!(
        selected
            .selection
            .sites
            .iter()
            .map(|s| (s.id, s.pc, s.length))
            .collect::<Vec<_>>(),
        [(1, lower, if suffix { 2 } else { 6 }), (2, PC + 32, 2)]
    );
    for site in &selected.selection.sites {
        assert_eq!(
            site.heads.iter().map(|h| h.address).collect::<Vec<_>>(),
            heads
        );
        assert_eq!(site.completeness, EntryCompleteness::AllInstructionHeads);
    }
    assert_eq!(
        l.lines().filter(|r| r.starts_with("head ")).count(),
        heads.len() + 1
    );
    let (claimed, high) = pending_high_plan(&o, &selected);
    let li2core::emission::ArtifactMetrics::Engine(
        Tactic::NeighborEviction,
        li2core::engine::SelectedMetrics::Neighbor(g, m),
        _,
    ) = high.metrics()
    else {
        panic!("actual old T3")
    };
    assert_eq!(
        (g.victim, m.victims_examined, m.pairs_examined),
        (PC + 16, 1, 1)
    );
    let protected = addr(lower, if suffix { 2 } else { 6 }).unwrap();
    assert_eq!(
        claimed.require_unclaimed_ranges(&[protected]),
        Err(Refusal::OwnershipConflict)
    );
    if suffix {
        assert_eq!(&claimed.final_bytes()[0].bytes[22..24], &o[0x1116..0x1118]);
    } else {
        assert_ne!(&claimed.final_bytes()[0].bytes[16..22], &o[0x1110..0x1116]);
    }
    let old =
        prepare_disassembly(&o, &owned_bind(&o, &l, &pending_old_policy(&p)).unwrap()).unwrap();
    pending_no_candidate(&old, &[1, 2]);
    assert_eq!(old.reports()[1].core_tactic, Some(Tactic::NeighborEviction));
    assert_eq!(
        old.reports()[1].refusal.as_ref().unwrap().stage,
        "atomic-selection"
    );
    assert_eq!(old.reports()[1].refusal_code, Some(10_003));
    assert!(old.reports()[1].diagnostics.contains("pairs_examined: 1"));
    if suffix {
        assert_eq!(old.reports()[0].core_tactic, Some(Tactic::GeneralizedPun));
        assert_eq!(
            old.reports()[0].refusal.as_ref().unwrap().stage,
            "composition"
        );
        assert_eq!(
            old.reports()[0].refusal.as_ref().unwrap().detail,
            "OwnershipConflict"
        );
        assert_eq!(old.reports()[0].refusal_code, Some(10_001));
    } else {
        assert_eq!(old.reports()[0].core_tactic, None);
        assert_eq!(old.reports()[0].refusal.as_ref().unwrap().stage, "core");
        assert_eq!(
            old.reports()[0].refusal.as_ref().unwrap().detail,
            "ExpectedBytesChanged"
        );
        assert_eq!(old.reports()[0].refusal_code, Some(4));
    }
    let product = prepare_disassembly(&o, &selected).unwrap();
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
        Some(if suffix {
            Tactic::GeneralizedPun
        } else {
            Tactic::Relocation
        })
    );
    assert_eq!(
        product.reports()[1].core_tactic,
        Some(Tactic::NeighborEviction)
    );
    let first_target = PC + if suffix { 0x016a_008f } else { 0x0101_01d2 };
    let second_target = PC + if suffix { 0x016a_008f } else { 0x0101_01c2 };
    pending_attempts(
        &product.reports()[1],
        &[
            pending_row(
                PC + 16,
                first_target,
                Composition,
                Some(Refusal::OwnershipConflict),
            ),
            pending_row(PC, second_target, Composition, None),
        ],
    );
    let evidence = &product.reports()[1].diagnostics;
    assert!(evidence.contains("pairs_examined: 2") && evidence.contains("victims_examined: 2"));
    let mut expected = o[0x1100..0x1123].to_vec();
    expected[..5].copy_from_slice(&[0xe9, 0x7b, 0, 0, 6]);
    expected[5..10].copy_from_slice(if suffix {
        &[0xe9, 0x85, 0, 0x6a, 1]
    } else {
        &[0xe9, 0xb8, 1, 1, 1]
    });
    expected[32..34].copy_from_slice(&[0xeb, 0xe3]);
    if suffix {
        expected[22..27].copy_from_slice(&[0xe9, 0, 0x6a, 1, 0x58]);
    } else {
        expected[16..21].copy_from_slice(&[0xe9, 0x6b, 0, 0, 4]);
    }
    assert_eq!(
        &product.files()["candidate.elf"][0x1100..0x1123],
        expected.as_slice()
    );
    assert_eq!(product.files()["candidate.elf"][0x1f00], 0xc3);
    assert!(product.files().contains_key("source.li2sparse"));
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|n| n.starts_with("image-") && n.ends_with(".bin"))
            .count(),
        3
    );
    let ledger = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    let image_rows: Vec<Vec<_>> = ledger
        .lines()
        .filter(|r| r.starts_with("image\t"))
        .map(|r| r.split('\t').collect())
        .collect();
    let mut targets: Vec<u64> = image_rows.iter().map(|r| r[3].parse().unwrap()).collect();
    targets.sort_unstable();
    let later = PC + if suffix { 0x5801_6a1b } else { 0x0400_0080 };
    let mut expected_targets = vec![second_target, PC + 0x0600_0080, later];
    expected_targets.sort_unstable();
    assert_eq!(targets, expected_targets);
    let allocations: Vec<_> = ledger
        .lines()
        .filter(|r| r.starts_with("allocation\t"))
        .map(|r| {
            let fields: Vec<_> = r.split('\t').collect();
            (
                fields[3].parse::<u64>().unwrap(),
                fields[4].parse::<u64>().unwrap(),
            )
        })
        .collect();
    assert_eq!(allocations.len(), 3);
    for target in targets {
        assert_eq!(
            allocations
                .iter()
                .filter(|&&(a, b)| a == (target & !4095) && target < b && b - a <= 8192)
                .count(),
            1
        );
    }
    for (i, &(a, b)) in allocations.iter().enumerate() {
        assert!(a < b);
        for &(c, d) in &allocations[i + 1..] {
            assert!(b <= c || d <= a);
        }
    }
    assert_eq!(product.files()["disassembly.txt"], l.as_bytes());
    assert_eq!(product.files()["disassembly-policy.txt"], p.as_bytes());
    assert_eq!(o, saved);
}

#[test]
fn pending_selected_victim_is_preserved_for_its_later_hook() {
    pending_complete(false);
}
#[test]
fn pending_selected_unchanged_suffix_is_not_available_for_borrowing() {
    pending_complete(true);
}

#[test]
fn pending_selected_budget_and_forced_refusals_are_exact() {
    use li2core::contracts::Refusal;
    use li2core::engine::Tactic;
    use li2core::neighbor::NeighborAttemptStage::{Composition, SelectedPlacement};
    let (o, l, p) = pending_fixture(false);
    assert!(
        prepare_disassembly(&o, &pending_bind(&o, &l, &p).unwrap())
            .unwrap()
            .candidate_complete()
    );
    let search = "search 2 T3 0 80 1 none 2 2\n";
    for (variant, expected_pairs) in [
        (
            p.replace(search, &format!("search 2 T3 0 80 1 {} 2 2\n", PC + 16)),
            1,
        ),
        (p.replace(search, "search 2 T3 0 80 1 none 1 2\n"), 1),
        (p.replace(search, "search 2 T3 0 80 1 none 2 1\n"), 1),
    ] {
        let product = prepare_disassembly(&o, &pending_bind(&o, &l, &variant).unwrap()).unwrap();
        pending_no_candidate(&product, &[1, 2]);
        let low = &product.reports()[0];
        assert_eq!(low.core_tactic, Some(Tactic::Relocation));
        assert_eq!(low.refusal.as_ref().unwrap().stage, "atomic-selection");
        assert_eq!(low.refusal_code, Some(10_003));
        let high = &product.reports()[1];
        assert_eq!(high.core_tactic, None);
        assert_eq!(high.refusal.as_ref().unwrap().stage, "core");
        assert_eq!(high.refusal.as_ref().unwrap().detail, "OwnershipConflict");
        assert_eq!(high.refusal_code, Some(12));
        pending_attempts(
            high,
            &[pending_row(
                PC + 16,
                PC + 0x0101_01d2,
                Composition,
                Some(Refusal::OwnershipConflict),
            )],
        );
        assert_eq!(
            high.diagnostics.matches("NeighborAttempt {").count(),
            expected_pairs
        );
        assert!(
            !high.diagnostics.contains("accepted: true")
                && !high.diagnostics.contains("stop: Accepted")
        );
        if variant.contains("search 2 T3 0 80 1 none 2 1\n") {
            let runs: Vec<_> = high.diagnostics.split("SearchRun {").skip(1).collect();
            assert_eq!(runs.len(), 6);
            for (run, (domain, examined, stop)) in runs.iter().zip([
                ("Victims", 2, "Interrupted"),
                ("JointPairs", 1, "BudgetLimited"),
                ("VictimImages", 1, "BudgetLimited"),
                ("SelectedImages", 1, "DomainComplete"),
                ("VictimImages", 1, "Interrupted"),
                ("SelectedImages", 0, "Interrupted"),
            ]) {
                assert!(run.contains(&format!("domain: {domain},")));
                assert!(run.contains(&format!("examined: {examined},")));
                assert!(run.contains(&format!("stop: {stop}")));
            }
            assert!(runs[1].contains("remaining_at_least: 1"));
        } else {
            let runs: Vec<_> = high.diagnostics.split("SearchRun {").skip(1).collect();
            assert_eq!(runs.len(), 4);
            assert!(runs[0].contains("domain: Victims,") && runs[0].contains("examined: 1,"));
            assert!(runs[1].contains("domain: JointPairs,") && runs[1].contains("examined: 1,"));
            assert!(runs[0].contains(if variant.contains("none 1 2") {
                "stop: BudgetLimited"
            } else {
                "stop: DomainComplete"
            }));
        }
        assert_eq!(
            product
                .files()
                .keys()
                .filter(|n| n.starts_with("image-") && n.ends_with(".bin"))
                .count(),
            1
        );
    }
    let target = PC + 0x0101_01d2;
    let no_image = p.replace(
        &format!("allocation 2 selected {target} 1 8192"),
        &format!("allocation 2 selected {target} 1 1"),
    );
    let product = prepare_disassembly(&o, &pending_bind(&o, &l, &no_image).unwrap()).unwrap();
    pending_no_candidate(&product, &[1, 2]);
    assert_eq!(product.reports()[1].refusal_code, Some(11));
    assert_eq!(product.reports()[1].core_tactic, None);
    assert_eq!(product.reports()[1].refusal.as_ref().unwrap().stage, "core");
    assert_eq!(
        product.reports()[1].refusal.as_ref().unwrap().detail,
        "AllocationUnavailable"
    );
    // Below one page is a capacity preflight, before any candidate or search run.
    pending_attempts(&product.reports()[1], &[]);
    let early = &product.reports()[1].diagnostics;
    assert_eq!(early.matches("EngineAttempt {").count(), 1);
    assert_eq!(early.matches("NeighborAttempt {").count(), 0);
    assert_eq!(early.matches("SearchRun {").count(), 0);
    assert_eq!(early.matches("RefusalEvidence {").count(), 1);
    assert!(early.contains("class: ResourceCapacity"));
    assert!(!early.contains("accepted: true") && !early.contains("stop: Accepted"));
    assert_eq!(product.reports()[0].core_tactic, Some(Tactic::Relocation));
    assert_eq!(
        product.reports()[0].refusal.as_ref().unwrap().stage,
        "atomic-selection"
    );
    assert_eq!(product.reports()[0].refusal_code, Some(10_003));
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|n| n.starts_with("image-") && n.ends_with(".bin"))
            .count(),
        1
    );
    // Keep a valid capacity policy, but authorize only part of the shared page.
    // Both exact relay targets are enumerated; neither full image mapping fits.
    let page = target & !4095;
    let permit_bytes = target - page + 1;
    assert_eq!((PC + 0x0101_01c2) & !4095, page);
    assert!(page <= PC + 0x0101_01c2 && PC + 0x0101_01c2 < target + 1);
    assert!(permit_bytes < 4096);
    let full = format!("allocation 2 selected {target} 1 8192 {page}:8192\n");
    let partial = format!("allocation 2 selected {target} 1 8192 {page}:{permit_bytes}\n");
    assert_eq!(p.matches(&full).count(), 1);
    let no_mapping = p.replace(&full, &partial);
    let selected = pending_bind(&o, &l, &no_mapping).unwrap();
    assert_eq!(
        selected.selection.sites[1]
            .selected_allocation
            .max_mapped_bytes,
        8192
    );
    assert_eq!(
        selected.selection.sites[1]
            .selected_allocation
            .max_candidates,
        1
    );
    assert_eq!(
        selected.selection.sites[1].selected_allocation.ranges,
        [addr(page, permit_bytes).unwrap()]
    );
    let product = prepare_disassembly(&o, &selected).unwrap();
    pending_no_candidate(&product, &[1, 2]);
    assert_eq!(product.reports()[1].refusal_code, Some(11));
    assert_eq!(product.reports()[1].core_tactic, None);
    assert_eq!(product.reports()[1].refusal.as_ref().unwrap().stage, "core");
    assert_eq!(
        product.reports()[1].refusal.as_ref().unwrap().detail,
        "AllocationUnavailable"
    );
    assert_eq!(
        product.reports()[1]
            .diagnostics
            .matches("NeighborAttempt {")
            .count(),
        2
    );
    assert!(!product.reports()[1].diagnostics.contains("accepted: true"));
    pending_attempts(
        &product.reports()[1],
        &[
            pending_row(
                PC + 16,
                PC + 0x0101_01d2,
                SelectedPlacement,
                Some(Refusal::AllocationUnavailable),
            ),
            pending_row(
                PC,
                PC + 0x0101_01c2,
                SelectedPlacement,
                Some(Refusal::AllocationUnavailable),
            ),
        ],
    );
    let runs: Vec<_> = product.reports()[1]
        .diagnostics
        .split("SearchRun {")
        .skip(1)
        .collect();
    assert_eq!(runs.len(), 6);
    for (run, examined) in runs.iter().zip([2, 2, 1, 1, 1, 1]) {
        assert!(run.contains(&format!("examined: {examined},")));
    }
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|n| n.starts_with("image-") && n.ends_with(".bin"))
            .count(),
        1
    );
    let low = &product.reports()[0];
    assert_eq!(low.core_tactic, Some(Tactic::Relocation));
    assert_eq!(low.refusal.as_ref().unwrap().stage, "atomic-selection");
    let budget = p.replace("1048576 16 16", "1048576 16 2");
    let product = prepare_disassembly(&o, &pending_bind(&o, &l, &budget).unwrap()).unwrap();
    pending_no_candidate(&product, &[1, 2]);
    assert_eq!(
        product.reports()[1].core_tactic,
        Some(Tactic::NeighborEviction)
    );
    assert_eq!(
        product.reports()[1].refusal.as_ref().unwrap().stage,
        "atomic-selection"
    );
    assert_eq!(product.reports()[0].core_tactic, Some(Tactic::Relocation));
    assert_eq!(
        product.reports()[0].refusal.as_ref().unwrap().stage,
        "aggregate-budget"
    );
    assert_eq!(product.reports()[0].refusal_code, Some(10_001));
    pending_attempts(
        &product.reports()[1],
        &[
            pending_row(
                PC + 16,
                PC + 0x0101_01d2,
                Composition,
                Some(Refusal::OwnershipConflict),
            ),
            pending_row(PC, PC + 0x0101_01c2, Composition, None),
        ],
    );
}

#[test]
fn pending_selected_all_conflicts_keep_both_rows_and_complete_reports() {
    use li2core::contracts::Refusal;
    use li2core::engine::Tactic;
    use li2core::neighbor::NeighborAttemptStage::Composition;
    let (mut o, l, p) = pending_fixture(false);
    let old_digest = digest(&o);
    o[0x1100..0x1106].copy_from_slice(&[0x0f, 0x85, 10, 0, 0, 0]);
    let l = l.replace(&old_digest, &digest(&o)).replace(
        &format!("head {PC} 2eb837314253"),
        &format!("head {PC} 0f850a000000"),
    );
    let mut rows: Vec<String> = p.lines().take(11).map(str::to_owned).collect();
    rows[1] = format!("original {}", digest(&o));
    rows[2] = format!("ledger {}", digest(l.as_bytes()));
    let victim = PC + 0x0600_0080;
    for (id, tactic, target) in [
        (1, "B1", PC + 0x0500_0080),
        (2, "B1", PC + 0x0400_0080),
        (3, "T3", PC + 0x0101_01d2),
    ] {
        rows.push(format!("search {id} {tactic} 0 80 1 none 2 2"));
        rows.push(format!(
            "allocation {id} selected {target} 1 8192 {}:8192",
            target & !4095
        ));
        rows.push(format!(
            "allocation {id} victim {victim} 1 8192 {}:8192",
            victim & !4095
        ));
    }
    let p = rows.join("\n") + "\n";
    let selected = pending_bind(&o, &l, &p).unwrap();
    assert_eq!(
        selected
            .selection
            .sites
            .iter()
            .map(|s| s.pc)
            .collect::<Vec<_>>(),
        [PC, PC + 16, PC + 32]
    );
    let product = prepare_disassembly(&o, &selected).unwrap();
    pending_no_candidate(&product, &[1, 2, 3]);
    let high = &product.reports()[2];
    assert_eq!(high.core_tactic, None);
    assert_eq!(high.refusal.as_ref().unwrap().stage, "core");
    assert_eq!(high.refusal.as_ref().unwrap().detail, "OwnershipConflict");
    assert_eq!(high.refusal_code, Some(12));
    pending_attempts(
        high,
        &[
            pending_row(
                PC + 16,
                PC + 0x0101_01d2,
                Composition,
                Some(Refusal::OwnershipConflict),
            ),
            pending_row(
                PC,
                PC + 0x0101_01c2,
                Composition,
                Some(Refusal::OwnershipConflict),
            ),
        ],
    );
    assert_eq!(high.diagnostics.matches("NeighborAttempt {").count(), 2);
    assert!(
        !high.diagnostics.contains("accepted: true")
            && !high.diagnostics.contains("stop: Accepted")
    );
    let runs: Vec<_> = high.diagnostics.split("SearchRun {").skip(1).collect();
    assert_eq!(runs.len(), 6);
    for (run, examined) in runs.iter().zip([2, 2, 1, 1, 1, 1]) {
        assert!(run.contains(&format!("examined: {examined},")));
    }
    assert!(runs[0].contains("stop: DomainComplete"));
    assert!(runs[1].contains("stop: UnclassifiedBoundedStop"));
    for report in &product.reports()[..2] {
        assert_eq!(report.core_tactic, Some(Tactic::Relocation));
        assert_eq!(report.refusal.as_ref().unwrap().stage, "atomic-selection");
        assert_eq!(report.refusal_code, Some(10_003));
    }
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|n| n.starts_with("image-") && n.ends_with(".bin"))
            .count(),
        2
    );
}

#[test]
fn pending_selected_guard_reads_actual_transactional_coverage_and_locks() {
    use li2core::composition::Composition;
    use li2core::contracts::*;
    use li2core::emission::*;
    let (o, l, p) = pending_fixture(true);
    let selected = pending_bind(&o, &l, &p).unwrap();
    let (claimed, _) = pending_high_plan(&o, &selected);
    let saved = claimed.clone();
    assert_eq!(claimed.require_unclaimed_ranges(&[]), Ok(()));
    assert_eq!(
        claimed.require_unclaimed_ranges(&[addr(PC, 16).unwrap(), addr(PC + 26, 6).unwrap()]),
        Ok(())
    );
    assert_eq!(
        claimed.require_unclaimed_ranges(&[addr(PC + 25, 1).unwrap()]),
        Err(Refusal::OwnershipConflict)
    );
    assert_eq!(&claimed.final_bytes()[0].bytes[22..26], &o[0x1116..0x111a]);
    assert_eq!(
        claimed.require_unclaimed_ranges(&[addr(PC + 22, 2).unwrap(), addr(PC + 35, 1).unwrap()]),
        Err(Refusal::DependencyNotHeld)
    );
    assert_eq!(
        claimed.require_unclaimed_ranges(&[addr(PC + 26, 1).unwrap(), addr(PC + 25, 1).unwrap()]),
        Err(Refusal::InvalidRange)
    );
    let gap = Composition::new(
        claimed.identity(),
        vec![
            ExpectedBytes {
                address: PC,
                bytes: o[0x1100..0x1108].to_vec(),
            },
            ExpectedBytes {
                address: PC + 9,
                bytes: o[0x1109..0x1123].to_vec(),
            },
        ],
    )
    .unwrap();
    assert_eq!(
        gap.require_unclaimed_ranges(&[addr(PC, 35).unwrap()]),
        Err(Refusal::DependencyNotHeld)
    );
    assert_eq!(AddressRange::new(u64::MAX, 2), Err(Refusal::InvalidRange));
    assert_eq!(AddressRange::new(PC, 0), Err(Refusal::InvalidRange));
    // Source/identity authentication belongs to the actual engine boundary.
    let site = &selected.selection.sites[1];
    let entries = LegalEntrySet {
        identity: claimed.identity(),
        scope: site.function,
        provenance: EntryProvenance::Declared("pending preflight fixture".into()),
        completeness: site.completeness,
        entries: site.heads.clone(),
        resumes: site.resumes.clone(),
    };
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(
            selected.selection.target,
            selected.selection.bias_domain,
        )
        .unwrap(),
        SymbolicHook {
            identity: 1,
            address: Some(HOOK),
        },
        vec![addr(BASE, 8192).unwrap()],
    );
    let mut changed = o[0x1100..0x1123].to_vec();
    changed[0] ^= 1;
    let malformed = [addr(PC + 8, 1).unwrap(), addr(PC, 1).unwrap()];
    for stale in [true, false] {
        let mut identity = claimed.identity();
        if stale {
            identity.generation += 1;
        }
        let request = ArtifactRequest {
            site: PlanningSite {
                identity,
                code: &changed,
                base_address: PC,
                function: site.function,
                block: site.block,
                logical_pc: site.pc,
                entries: &entries,
                semantics: site.semantics,
                allocation: &site.selected_allocation,
                search: site.search,
            },
            emission: &emission,
        };
        let error = li2core::engine::plan_with_emission_after_and_short_t3_pending(
            &request,
            &claimed,
            &malformed,
            &site.victim_allocation,
            Default::default(),
        )
        .unwrap_err();
        assert_eq!(
            error.reason,
            if stale {
                Refusal::StaleGeneration
            } else {
                Refusal::ExpectedBytesChanged
            }
        );
        assert!(error.attempts.is_empty());
    }
    assert_eq!(claimed.identity(), saved.identity());
    assert_eq!(claimed.originals(), saved.originals());
    assert_eq!(claimed.final_bytes(), saved.final_bytes());
    assert_eq!(claimed.locks(), saved.locks());
    assert_eq!(claimed, saved);
}

fn pending_gp_fixture(fail_high: bool) -> (Vec<u8>, String, String) {
    let (o, l) = if fail_high {
        fixture(&[&[0x75, 0], &[0x75, 0], &[0x6a, 1], &[0x58], &[0xc3]])
    } else {
        fixture(&[
            &[0x75, 0],
            &[0x6a, 1],
            &[0x58],
            &[0xc3],
            &[0x90],
            &[0x90],
            &[0x75, 0],
            &[0x6a, 2],
            &[0x58],
            &[0xc3],
        ])
    };
    let base = policy(&o, &l, 2);
    let mut rows: Vec<String> = base.lines().take(8).map(str::to_owned).collect();
    rows[0] = "LI2DISASM-POLICY 4".into();
    rows.insert(3, "neighbor-victims short-only".into());
    rows.insert(4, "neighbor-ownership inherited-t3".into());
    rows.insert(5, "pending-selected full-instruction-ownership".into());
    let low = PC + 5 + if fail_high { 0x6a00_7500 } else { 0x5801_6a00 };
    let high = PC
        + if fail_high {
            0x0400_0080
        } else {
            13 + 0x5802_6a00
        };
    for (id, target) in [(1, low), (2, high)] {
        let tactic = if fail_high && id == 2 { "B1" } else { "B2" };
        let sites = if fail_high && id == 2 { 0 } else { 1 };
        rows.push(format!("search {id} {tactic} 0 80 {sites} none 2 2"));
        rows.push(format!(
            "allocation {id} selected {target} 1 8192 {}:8192",
            target & !4095
        ));
        let victim = PC + 0x0600_0080;
        rows.push(format!(
            "allocation {id} victim {victim} 1 8192 {}:8192",
            victim & !4095
        ));
    }
    (o, l, rows.join("\n") + "\n")
}

#[test]
fn pending_selected_failed_site_stays_pending_and_first_four_do_not_restart() {
    use li2core::engine::Tactic;
    let (o, l, p) = pending_gp_fixture(false);
    let selected = pending_bind(&o, &l, &p).unwrap();
    assert_eq!(
        selected
            .selection
            .sites
            .iter()
            .map(|s| s.pc)
            .collect::<Vec<_>>(),
        [PC, PC + 8]
    );
    let good = prepare_disassembly(&o, &selected).unwrap();
    assert!(good.candidate_complete());
    assert!(good.reports().iter().all(|r| r.refusal.is_none()
        && r.candidate_emitted
        && r.core_tactic == Some(Tactic::GeneralizedPun)));
    for report in good.reports() {
        assert_eq!(report.diagnostics.matches("EngineAttempt {").count(), 1);
        assert!(!report.diagnostics.contains("NeighborEviction"));
    }
    let (o, l, p) = pending_gp_fixture(true);
    let selected = pending_bind(&o, &l, &p).unwrap();
    assert_eq!(
        selected
            .selection
            .sites
            .iter()
            .map(|s| s.pc)
            .collect::<Vec<_>>(),
        [PC, PC + 2]
    );
    let old =
        prepare_disassembly(&o, &owned_bind(&o, &l, &pending_old_policy(&p)).unwrap()).unwrap();
    pending_no_candidate(&old, &[1, 2]);
    assert_eq!(old.reports()[0].core_tactic, Some(Tactic::GeneralizedPun));
    assert_eq!(
        old.reports()[0].refusal.as_ref().unwrap().stage,
        "atomic-selection"
    );
    assert_eq!(old.reports()[0].refusal_code, Some(10_003));
    let product = prepare_disassembly(&o, &selected).unwrap();
    pending_no_candidate(&product, &[1, 2]);
    let high = &product.reports()[1];
    assert_eq!(high.core_tactic, None);
    assert_eq!(high.refusal.as_ref().unwrap().stage, "core");
    assert_eq!(high.refusal.as_ref().unwrap().detail, "NoPatchWindow");
    assert_eq!(high.refusal_code, Some(9));
    let low = &product.reports()[0];
    assert_eq!(low.core_tactic, Some(Tactic::GeneralizedPun));
    assert_eq!(low.refusal.as_ref().unwrap().stage, "pending-selected");
    assert_eq!(low.refusal.as_ref().unwrap().detail, "OwnershipConflict");
    assert_eq!(low.refusal_code, Some(10_001));
    assert_eq!(low.diagnostics.matches("EngineAttempt {").count(), 1);
    assert!(!low.diagnostics.contains("NeighborEviction"));
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|n| n.starts_with("image-") && n.ends_with(".bin"))
            .count(),
        0
    );
    let ledger = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    assert!(!ledger.lines().any(|r| r.starts_with("step\t")
        || r.starts_with("allocation\t")
        || r.starts_with("byte-lock\t")));
    // Existing aggregate failure retains priority over the later pending guard.
    let scarce = p.replace("1048576 16 16 65536", "1048576 16 16 1");
    let product = prepare_disassembly(&o, &pending_bind(&o, &l, &scarce).unwrap()).unwrap();
    pending_no_candidate(&product, &[1, 2]);
    assert_eq!(
        product.reports()[0].core_tactic,
        Some(Tactic::GeneralizedPun)
    );
    assert_eq!(
        product.reports()[0].refusal.as_ref().unwrap().stage,
        "aggregate-budget"
    );
}

#[test]
fn pending_selected_mode_identity_and_complete_denominator_are_explicit() {
    let (o, l, p) = pending_fixture(false);
    let selected = pending_bind(&o, &l, &p).unwrap();
    assert_eq!(selected.profile(), SHORT_T3_PENDING_PROFILE);
    let family = "neighbor-victims short-only\n";
    let ownership = "neighbor-ownership inherited-t3\n";
    let pending = "pending-selected full-instruction-ownership\n";
    let mode = format!("{family}{ownership}{pending}");
    let manifest = std::str::from_utf8(selected.manifest()).unwrap();
    assert_eq!(
        manifest.lines().take(5).collect::<Vec<_>>(),
        [
            "LI2TOOL 1",
            &format!("original {}", digest(&o)),
            "neighbor-victims short-only",
            "neighbor-ownership inherited-t3",
            "pending-selected full-instruction-ownership",
        ]
    );
    assert!(bind(&o, &l, &p).is_err());
    assert!(short_bind(&o, &l, &p).is_err());
    assert!(owned_bind(&o, &l, &p).is_err());
    assert!(pending_bind(&o, &l, &pending_old_policy(&p)).is_err());
    assert!(pending_bind(&o, &l, &policy(&o, &l, 2)).is_err());
    assert!(selection::parse(selected.manifest()).is_err());
    assert!(selection::parse_short_neighbor_projection(selected.manifest()).is_err());
    assert!(selection::parse_short_t3_ownership_projection(selected.manifest()).is_err());
    assert!(crate::prepare(&o, selected.manifest()).is_err());
    let old = owned_bind(&o, &l, &pending_old_policy(&p)).unwrap();
    assert!(selection::parse_short_t3_pending_projection(old.manifest()).is_err());
    for wrong in [
        p.replace(pending, ""),
        p.replace(pending, &format!("{pending}{pending}")),
        p.replace(pending, "pending-selected heads-only\n"),
        p.replace(&mode, &format!("{family}{pending}{ownership}")),
        p.replace(pending, "") + pending,
        p.replace(family, ""),
        p.replace(ownership, ""),
        p.replace("LI2DISASM-POLICY 4", "LI2DISASM-POLICY 3"),
        p.replace(
            &format!("original {}", digest(&o)),
            &format!("original {}", "0".repeat(64)),
        ),
        p.replace(
            &format!("ledger {}", digest(l.as_bytes())),
            &format!("ledger {}", "0".repeat(64)),
        ),
        p.replace("search 2 T3 0 80 1 none 2 2\n", ""),
        p.clone() + "search 3 T3 0 80 1 none 2 2\n",
    ] {
        assert!(pending_bind(&o, &l, &wrong).is_err());
    }
    for wrong in [
        manifest.replace(pending, ""),
        manifest.replace(pending, &format!("{pending}{pending}")),
        manifest.replace(pending, "pending-selected heads-only\n"),
        manifest.replace(&mode, &format!("{family}{pending}{ownership}")),
        manifest.replace(pending, "") + pending,
        manifest.replace(family, &format!("{family}{family}")),
        manifest.replace(ownership, &format!("{ownership}{ownership}")),
    ] {
        assert!(selection::parse_short_t3_pending_projection(wrong.as_bytes()).is_err());
    }
    assert!(
        checked(&o, &l)
            .unwrap()
            .bind_short_t3_pending(p.as_bytes(), ContentId([0; 32]))
            .is_err()
    );
    assert!(import(&o, l.as_bytes(), ContentId([0; 32])).is_err());
    let omitted = l.replace(&format!("head {} 7500\n", PC + 32), "");
    assert!(checked(&o, &omitted).is_err());
    let mut changed = o.clone();
    changed[0x300] ^= 1;
    assert!(pending_bind(&changed, &l, &p).is_err());
    assert!(prepare_disassembly(&changed, &selected).is_err());
    assert_eq!(
        selected.files["disassembly-inventory.tsv"],
        checked(&o, &l).unwrap().inventory_short_t3_pending()
    );
    let profile = std::str::from_utf8(&selected.files["planning-profile.tsv"]).unwrap();
    assert!(profile.starts_with(&format!("LI2PLANNING\t1\nprofile\t{SHORT_T3_PENDING_PROFILE}\nneighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\n")));
    assert!(profile.contains(&format!("policy_sha256\t{}\n", digest(p.as_bytes()))));
    assert!(profile.contains(&format!(
        "selection_sha256\t{}\n",
        digest(selected.manifest())
    )));
    assert!(profile.contains("complete_jump_count\t2\n"));
    assert_ne!(
        ContentId::of(selected.manifest()),
        ContentId::of(manifest.replace(&mode, "").as_bytes())
    );
    let failed = p.replace(
        "search 2 T3 0 80 1 none 2 2\n",
        "search 2 T3 0 80 1 none 2 1\n",
    );
    let failed = pending_bind(&o, &l, &failed).unwrap();
    let product = prepare_disassembly(&o, &failed).unwrap();
    pending_no_candidate(&product, &[1, 2]);
    assert_eq!(
        product.files()["planning-profile.tsv"],
        failed.files["planning-profile.tsv"]
    );
    assert_eq!(
        product.files()["disassembly-inventory.tsv"],
        failed.files["disassembly-inventory.tsv"]
    );
}

#[test]
fn pending_selected_full_mode_bytes_count_toward_bounds_and_old_caps() {
    let (o, l, p) = pending_fixture(false);
    let selected = pending_bind(&o, &l, &p).unwrap();
    let mut exact = selected.manifest().to_vec();
    exact.resize(TEXT_LIMIT, b'\n');
    assert_eq!(
        selection::parse_short_t3_pending_projection(&exact)
            .unwrap()
            .manifest,
        exact
    );
    exact.push(b'\n');
    assert!(selection::parse_short_t3_pending_projection(&exact).is_err());
    let stripped = std::str::from_utf8(&exact)
        .unwrap()
        .replace("neighbor-victims short-only\n", "")
        .replace("neighbor-ownership inherited-t3\n", "")
        .replace("pending-selected full-instruction-ownership\n", "");
    assert!(selection::parse(stripped.as_bytes()).is_ok());
    for wrong in [
        p.clone() + &"x".repeat(TEXT_LIMIT),
        p.replace("1048576 16 16", "1048576 1025 16"),
        p.replace("1048576 16 16", "1048576 1 16"),
        p.replace("T3 0 80", "T3 0 65537"),
        p.replace("none 2 2", "none 2 1048577"),
    ] {
        assert!(pending_bind(&o, &l, &wrong).is_err());
    }
}
