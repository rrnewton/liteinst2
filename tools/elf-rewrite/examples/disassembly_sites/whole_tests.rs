//! Nonexecuting CLI and the real shared importer/binder/planner route.
use super::*;
use std::fmt::Write as _;

fn args() -> Vec<String> {
    [
        "program",
        "original",
        "ledger",
        "ledger-sha",
        "policy",
        "policy-sha",
        "output",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[test]
fn whole_cli_preserves_legacy_positional_paths_and_selects_only_complete_leading_form() {
    let base = args();
    let flags = [
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
        "--whole-program-4096",
    ];
    for flag in flags {
        for position in 1..base.len() {
            let mut positional = base.clone();
            positional[position] = flag.into();
            assert_eq!(
                arguments_with_whole(&positional),
                arguments_with_pending(&positional)
            );
            assert_eq!(
                arguments_with_whole(&positional).unwrap(),
                (&positional[1..], Mode::LongOnly)
            );
        }
    }
    // An old profile with the new spelling as a positional filename is still
    // the old profile, with exactly its old duplicate/mixed-token behavior.
    for old in &flags[..3] {
        for position in 2..8 {
            let mut input = base.clone();
            input.insert(1, (*old).into());
            input[position] = flags[3].into();
            assert_eq!(arguments_with_whole(&input), arguments_with_pending(&input));
        }
    }
    let mut whole = base.clone();
    whole.insert(1, flags[3].into());
    assert_eq!(
        arguments_with_whole(&whole).unwrap(),
        (&base[1..], Mode::Whole4096)
    );
    assert_eq!(
        labels_with_ownership(Mode::Whole4096),
        (disassembly::whole::PROFILE, "", "")
    );
    assert!(disassembly::import(&[], &[], ContentId::of(&[])).is_err());
    assert_eq!(
        labels_with_ownership(Mode::Whole4096),
        (disassembly::whole::PROFILE, "", "")
    );
    for position in 2..8 {
        for flag in flags {
            let mut mixed = whole.clone();
            mixed[position] = flag.into();
            assert!(arguments_with_whole(&mixed).is_err());
        }
    }
    assert_eq!(
        arguments_with_whole(&whole[..7]).unwrap(),
        (&whole[1..7], Mode::LongOnly)
    );
    assert_eq!(
        arguments_with_whole(&whole[..7]),
        arguments_with_pending(&whole[..7])
    );
    for count in 0..7 {
        assert!(arguments_with_whole(&whole[..count]).is_err());
    }
    let mut extra = whole.clone();
    extra.push("extra".into());
    assert!(arguments_with_whole(&extra).is_err());
    let mut misplaced = whole.clone();
    misplaced.swap(1, 2);
    assert!(arguments_with_whole(&misplaced).is_err());
    let mut unknown = whole;
    unknown[1] = "--unknown".into();
    assert_eq!(
        arguments_with_whole(&unknown),
        arguments_with_pending(&unknown)
    );
    assert!(arguments_with_whole(&unknown).is_err());
}

// Same small synthetic ELF shape as the independently reviewed shared-profile
// control. These bytes are never loaded, mapped or executed.
fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    const BASE: u64 = 0x400000;
    const PC: u64 = BASE + 0x1100;
    const HOOK: u64 = BASE + 0x11f00;
    fn put(bytes: &mut [u8], at: usize, width: usize, value: u64) {
        bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }
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
            put(&mut original, 64 + i * 56 + field, width, value);
        }
    }
    let chunks: [&[u8]; 7] = [
        &[0xf3, 0x0f, 0x1e, 0xfa],
        &[0x90],
        &[0x90],
        &[0x90],
        &[0x75, 0],
        &[0x75, 0],
        &[0xc3],
    ];
    let code: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    original[0x1100..0x1100 + code.len()].copy_from_slice(&code);
    original[0x11f00] = 0xc3;
    let mut ledger = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\nregion {PC} 4352 {}\n",
        digest(&original),
        code.len()
    );
    let mut pc = PC;
    for chunk in chunks {
        let bytes: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(ledger, "head {pc} {bytes}").unwrap();
        pc += chunk.len() as u64;
    }
    writeln!(ledger, "region {HOOK} 73472 1\nhead {HOOK} c3").unwrap();
    let mut policy = format!(
        "LI2DISASM-WHOLE-POLICY 1\noriginal {}\nledger {}\ntarget fxsave64\ndomain 1\ncarrier {}\nlimits 1048576 4096 4096 65536 64 1048576 262144 64 4294967296\nnull-hook {HOOK}\n",
        digest(&original),
        digest(ledger.as_bytes()),
        BASE + 0x20000
    );
    for id in 1..=2 {
        let selected = BASE + 0x4000000 + id * 0x4000;
        let victim = BASE + 0x6000000 + id * 0x4000;
        writeln!(policy, "search {id} B1 0 80 1 none 64 256\nallocation {id} selected {selected} 256 8192 {selected}:8192\nallocation {id} victim {victim} 256 8192 {victim}:8192").unwrap();
    }
    (original, ledger.into_bytes(), policy.into_bytes())
}

#[test]
fn whole_cli_uses_shared_prepare_and_keeps_full_inventory_on_policy_refusal() {
    let (original, ledger, policy) = fixture();
    let imported = disassembly::import(&original, &ledger, ContentId::of(&ledger)).unwrap();
    let inventory = imported.inventory_whole_program();
    assert_eq!(imported.jumps().len(), 2);
    let mut files = BTreeMap::new();
    let product = prepare_inputs(
        &original,
        &ledger,
        ContentId::of(&ledger),
        &policy,
        ContentId::of(&policy),
        Mode::Whole4096,
        &mut files,
    )
    .unwrap();
    assert_eq!(product.reports().len(), 2);
    assert!(!product.qualification_complete());
    assert_eq!(files["disassembly-inventory.tsv"], inventory);
    assert_eq!(product.files()["disassembly-inventory.tsv"], inventory);
    assert!(files["selection.txt"].starts_with(b"LI2TOOL-SHARED-REGIONS 1\n"));
    assert!(selection::parse(&files["selection.txt"]).is_err());
    assert!(
        std::str::from_utf8(&product.files()["planning-profile.tsv"])
            .unwrap()
            .contains(&format!("profile\t{}\n", disassembly::whole::PROFILE))
    );
    for (attempt, pin) in [
        (policy.clone(), ContentId([0; 32])),
        (
            policy[..policy.len() - 1].to_vec(),
            ContentId::of(&policy[..policy.len() - 1]),
        ),
        {
            let p = String::from_utf8(policy.clone())
                .unwrap()
                .replace("LI2DISASM-WHOLE-POLICY 1", "LI2DISASM-POLICY 1")
                .into_bytes();
            let pin = ContentId::of(&p);
            (p, pin)
        },
    ] {
        let mut retained = BTreeMap::new();
        assert!(
            prepare_inputs(
                &original,
                &ledger,
                ContentId::of(&ledger),
                &attempt,
                pin,
                Mode::Whole4096,
                &mut retained
            )
            .is_err()
        );
        assert_eq!(retained.len(), 1);
        assert_eq!(retained["disassembly-inventory.tsv"], inventory);
        assert!(!retained.contains_key("selection.txt"));
    }
    let mut invalid = BTreeMap::new();
    assert!(
        prepare_inputs(
            &original,
            &ledger,
            ContentId([0; 32]),
            &policy,
            ContentId::of(&policy),
            Mode::Whole4096,
            &mut invalid
        )
        .is_err()
    );
    assert!(invalid.is_empty());
    let mut legacy = BTreeMap::new();
    assert!(
        prepare_inputs(
            &original,
            &ledger,
            ContentId::of(&ledger),
            &policy,
            ContentId::of(&policy),
            Mode::LongOnly,
            &mut legacy
        )
        .is_err()
    );
    assert_eq!(legacy["disassembly-inventory.tsv"], imported.inventory());
    assert!(!legacy.contains_key("selection.txt"));
}

#[test]
fn whole_current_placement_cli_is_explicit_and_preserves_every_legacy_form() {
    let base = args();
    let flag = "--whole-program-current-placement-4096";
    for position in 1..base.len() {
        let mut positional = base.clone();
        positional[position] = flag.into();
        assert_eq!(
            arguments_with_current_placement(&positional),
            arguments_with_whole(&positional)
        );
    }
    for old in [
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
        "--whole-program-4096",
    ] {
        let mut input = base.clone();
        input.insert(1, old.into());
        for position in 2..input.len() {
            let mut positional = input.clone();
            positional[position] = flag.into();
            assert_eq!(
                arguments_with_current_placement(&positional),
                arguments_with_whole(&positional)
            );
        }
    }
    let mut new = base.clone();
    new.insert(1, flag.into());
    assert_eq!(
        arguments_with_current_placement(&new).unwrap(),
        (&base[1..], Mode::WholeCurrentPlacement4096)
    );
    let (profile, family, stdout) = labels_with_ownership(Mode::WholeCurrentPlacement4096);
    assert_eq!(profile, disassembly::whole::PROFILE);
    assert_eq!(family, disassembly::whole::CURRENT_PLACEMENT_METADATA);
    assert!(stdout.contains("artifact_placement=current-composition-single-candidate-v1"));
    assert!(stdout.contains("paired_ownership=inherited-long-T3"));
    for mixed in [
        flag,
        "--whole-program-4096",
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
    ] {
        for position in 2..new.len() {
            let mut bad = new.clone();
            bad[position] = mixed.into();
            assert!(arguments_with_current_placement(&bad).is_err());
        }
    }
    assert_eq!(
        arguments_with_current_placement(&new[..7]),
        arguments_with_whole(&new[..7])
    );
    let mut extra = new;
    extra.push("extra".into());
    assert!(arguments_with_current_placement(&extra).is_err());
}

#[test]
fn whole_current_placement_cli_retains_mode_and_denominator_on_refusal() {
    let (original, ledger, policy) = fixture();
    let inventory = disassembly::import(&original, &ledger, ContentId::of(&ledger))
        .unwrap()
        .inventory_whole_program();
    let mut files = BTreeMap::new();
    // This original fixture explicitly requests 256 candidates/8192 bytes. The
    // opt-in mode must refuse it, not silently narrow or expand either policy.
    let product = prepare_inputs(
        &original,
        &ledger,
        ContentId::of(&ledger),
        &policy,
        ContentId::of(&policy),
        Mode::WholeCurrentPlacement4096,
        &mut files,
    )
    .unwrap();
    assert_eq!(product.reports().len(), 2);
    assert!(product.reports().iter().all(|r| r.refusal_code == Some(1)));
    assert!(!product.candidate_complete());
    assert!(!product.qualification_complete());
    assert!(!product.files().contains_key("candidate.elf"));
    assert_eq!(files["disassembly-inventory.tsv"], inventory);
    assert_eq!(product.files()["disassembly-inventory.tsv"], inventory);
    assert_eq!(product.files()["disassembly-policy.txt"], policy);
    assert!(
        product.files()["planning-profile.tsv"]
            .ends_with(disassembly::whole::CURRENT_PLACEMENT_METADATA.as_bytes())
    );
    let mut failed = BTreeMap::new();
    assert!(
        prepare_inputs(
            &original,
            &ledger,
            ContentId::of(&ledger),
            &policy,
            ContentId([0; 32]),
            Mode::WholeCurrentPlacement4096,
            &mut failed,
        )
        .is_err()
    );
    assert_eq!(failed.len(), 1);
    assert_eq!(failed["disassembly-inventory.tsv"], inventory);
    let (_, family, _) = labels_with_ownership(Mode::WholeCurrentPlacement4096);
    assert_eq!(family, disassembly::whole::CURRENT_PLACEMENT_METADATA);
}

#[test]
fn whole_mixed_pending_cli_is_explicit_and_preserves_every_legacy_form() {
    let base = args();
    let flag = "--whole-program-current-placement-mixed-neighbors-4096";
    for position in 1..base.len() {
        let mut positional = base.clone();
        positional[position] = flag.into();
        assert_eq!(
            arguments_with_mixed_pending(&positional),
            arguments_with_current_placement(&positional)
        );
    }
    for old in [
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
        "--whole-program-4096",
        "--whole-program-current-placement-4096",
    ] {
        let mut input = base.clone();
        input.insert(1, old.into());
        assert_eq!(
            arguments_with_mixed_pending(&input),
            arguments_with_current_placement(&input)
        );
        for position in 2..input.len() {
            let mut positional = input.clone();
            positional[position] = flag.into();
            assert_eq!(
                arguments_with_mixed_pending(&positional),
                arguments_with_current_placement(&positional)
            );
        }
    }
    let mut new = base.clone();
    new.insert(1, flag.into());
    assert_eq!(
        arguments_with_mixed_pending(&new).unwrap(),
        (&base[1..], Mode::WholeCurrentPlacementMixedPending4096)
    );
    let (profile, family, stdout) =
        labels_with_ownership(Mode::WholeCurrentPlacementMixedPending4096);
    assert_eq!(profile, disassembly::whole::PROFILE);
    assert_eq!(family, disassembly::whole::MIXED_PENDING_METADATA);
    assert!(stdout.contains("neighbor_victims=mixed-short-and-long"));
    assert!(stdout.contains("pending_selected=full-instruction-ownership"));
    assert!(stdout.contains("selected_placement_tactics=B1,B2,T1"));
    assert!(stdout.contains("paired_placement_tactics=legacy-T2,mixed-T3"));
    assert!(stdout.contains("paired_ownership=inherited-mixed-T3"));
    for mixed in [
        flag,
        "--whole-program-current-placement-4096",
        "--whole-program-4096",
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
    ] {
        for position in 2..new.len() {
            let mut bad = new.clone();
            bad[position] = mixed.into();
            assert!(arguments_with_mixed_pending(&bad).is_err());
        }
    }
    assert_eq!(
        arguments_with_mixed_pending(&new[..7]),
        arguments_with_current_placement(&new[..7])
    );
    let mut extra = new.clone();
    extra.push("extra".into());
    assert!(arguments_with_mixed_pending(&extra).is_err());
    new.swap(1, 2);
    assert!(arguments_with_mixed_pending(&new).is_err());
}

#[test]
fn whole_mixed_pending_cli_retains_mode_and_denominator_on_refusal() {
    let (original, ledger, policy) = fixture();
    let inventory = disassembly::import(&original, &ledger, ContentId::of(&ledger))
        .unwrap()
        .inventory_whole_program();
    let mut files = BTreeMap::new();
    // This input asks for 256 candidates/8192 bytes: the new mode must refuse
    // the incompatible request, retaining both rows and the exact old policy.
    let product = prepare_inputs(
        &original,
        &ledger,
        ContentId::of(&ledger),
        &policy,
        ContentId::of(&policy),
        Mode::WholeCurrentPlacementMixedPending4096,
        &mut files,
    )
    .unwrap();
    assert_eq!(
        product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(
        product
            .reports()
            .iter()
            .all(|r| r.refusal_code == Some(1) && !r.candidate_emitted)
    );
    assert!(!product.candidate_complete());
    assert!(!product.qualification_complete());
    assert!(!product.files().contains_key("candidate.elf"));
    assert!(!product.files().keys().any(|n| n.starts_with("image-")));
    assert_eq!(files["disassembly-inventory.tsv"], inventory);
    assert_eq!(product.files()["disassembly-inventory.tsv"], inventory);
    assert_eq!(product.files()["disassembly-policy.txt"], policy);
    let profile = std::str::from_utf8(&product.files()["planning-profile.tsv"]).unwrap();
    assert!(profile.contains(disassembly::whole::MIXED_PENDING_METADATA));
    assert!(!profile.contains("neighbor_victims\tlong-only\n"));
    let mut failed = BTreeMap::new();
    assert!(
        prepare_inputs(
            &original,
            &ledger,
            ContentId::of(&ledger),
            &policy,
            ContentId([0; 32]),
            Mode::WholeCurrentPlacementMixedPending4096,
            &mut failed,
        )
        .is_err()
    );
    assert_eq!(failed.len(), 1);
    assert_eq!(failed["disassembly-inventory.tsv"], inventory);
    let (_, family, _) = labels_with_ownership(Mode::WholeCurrentPlacementMixedPending4096);
    assert_eq!(family, disassembly::whole::MIXED_PENDING_METADATA);
}
