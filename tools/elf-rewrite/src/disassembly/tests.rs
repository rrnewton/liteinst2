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
