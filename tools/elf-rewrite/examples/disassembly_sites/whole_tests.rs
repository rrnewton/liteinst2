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

#[test]
fn whole_fitting_cli_is_explicit_and_preserves_every_legacy_form() {
    let base = args();
    let flag = "--whole-program-fitting-mixed-neighbors-4096";
    for position in 1..base.len() {
        let mut positional = base.clone();
        positional[position] = flag.into();
        assert_eq!(
            arguments_with_fitting_mixed(&positional),
            arguments_with_mixed_pending(&positional)
        );
    }
    for old in [
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
        "--whole-program-4096",
        "--whole-program-current-placement-4096",
        "--whole-program-current-placement-mixed-neighbors-4096",
    ] {
        let mut input = base.clone();
        input.insert(1, old.into());
        assert_eq!(
            arguments_with_fitting_mixed(&input),
            arguments_with_mixed_pending(&input)
        );
        for position in 2..input.len() {
            let mut positional = input.clone();
            positional[position] = flag.into();
            assert_eq!(
                arguments_with_fitting_mixed(&positional),
                arguments_with_mixed_pending(&positional)
            );
        }
    }
    let mut new = base.clone();
    new.insert(1, flag.into());
    assert_eq!(
        arguments_with_fitting_mixed(&new).unwrap(),
        (&base[1..], Mode::WholeFittingMixedPending4096)
    );
    let (profile, family, stdout) = labels_with_ownership(Mode::WholeFittingMixedPending4096);
    assert_eq!(profile, disassembly::whole::PROFILE);
    assert_eq!(family, disassembly::whole::FITTING_MIXED_METADATA);
    assert!(stdout.contains("neighbor_victims=mixed-short-and-long"));
    assert!(stdout.contains("pending_selected=full-instruction-ownership"));
    assert!(stdout.contains("selected_placement_tactics=B1,B2,T1"));
    assert!(stdout.contains("paired_placement_tactics=legacy-T2,fitting-mixed-T3"));
    assert!(stdout.contains("paired_ownership=inherited-mixed-T3"));
    assert!(stdout.contains("artifact_placement=current-composition-certified-fit-v1"));
    assert!(stdout.contains("local_plan_admission=inherited-and-pending-before-tactic-success"));
    for mixed in [
        flag,
        "--whole-program-current-placement-4096",
        "--whole-program-current-placement-mixed-neighbors-4096",
        "--whole-program-4096",
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
    ] {
        for position in 2..new.len() {
            let mut bad = new.clone();
            bad[position] = mixed.into();
            assert!(arguments_with_fitting_mixed(&bad).is_err());
        }
    }
    assert_eq!(
        arguments_with_fitting_mixed(&new[..7]),
        arguments_with_mixed_pending(&new[..7])
    );
    let mut extra = new.clone();
    extra.push("extra".into());
    assert!(arguments_with_fitting_mixed(&extra).is_err());
    new.swap(1, 2);
    assert!(arguments_with_fitting_mixed(&new).is_err());
}

#[test]
fn whole_fitting_cli_retains_mode_and_denominator_on_refusal() {
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
        Mode::WholeFittingMixedPending4096,
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
    assert!(profile.contains(disassembly::whole::FITTING_MIXED_METADATA));
    assert!(!profile.contains("neighbor_victims\tlong-only\n"));
    let mut failed = BTreeMap::new();
    assert!(
        prepare_inputs(
            &original,
            &ledger,
            ContentId::of(&ledger),
            &policy,
            ContentId([0; 32]),
            Mode::WholeFittingMixedPending4096,
            &mut failed,
        )
        .is_err()
    );
    assert_eq!(failed.len(), 1);
    assert_eq!(failed["disassembly-inventory.tsv"], inventory);
    let (_, family, _) = labels_with_ownership(Mode::WholeFittingMixedPending4096);
    assert_eq!(family, disassembly::whole::FITTING_MIXED_METADATA);
}

#[test]
fn whole_entry_veneer_cli_is_explicit_and_preserves_every_legacy_form() {
    let base = args();
    let flag = "--whole-program-entry-veneer-mixed-neighbors-4096";
    for position in 1..base.len() {
        let mut positional = base.clone();
        positional[position] = flag.into();
        assert_eq!(
            arguments_with_entry_veneer(&positional),
            arguments_with_fitting_mixed(&positional)
        );
    }
    for old in [
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
        "--whole-program-4096",
        "--whole-program-current-placement-4096",
        "--whole-program-current-placement-mixed-neighbors-4096",
        "--whole-program-fitting-mixed-neighbors-4096",
    ] {
        let mut input = base.clone();
        input.insert(1, old.into());
        assert_eq!(
            arguments_with_entry_veneer(&input),
            arguments_with_fitting_mixed(&input)
        );
        for position in 2..input.len() {
            let mut positional = input.clone();
            positional[position] = flag.into();
            assert_eq!(
                arguments_with_entry_veneer(&positional),
                arguments_with_fitting_mixed(&positional)
            );
        }
    }
    let mut new = base.clone();
    new.insert(1, flag.into());
    assert_eq!(
        arguments_with_entry_veneer(&new).unwrap(),
        (&base[1..], Mode::WholeEntryVeneerMixedPending4096)
    );
    let (profile, family, stdout) = labels_with_ownership(Mode::WholeEntryVeneerMixedPending4096);
    assert_eq!(profile, disassembly::whole::PROFILE);
    assert_eq!(family, disassembly::whole::ENTRY_VENEER_MIXED_METADATA);
    assert!(stdout.contains("neighbor_victims=mixed-short-and-long"));
    assert!(stdout.contains("pending_selected=full-instruction-ownership"));
    assert!(stdout.contains("selected_placement_tactics=B1,B2,T1"));
    assert!(stdout.contains(
        "paired_placement_tactics=legacy-T2,fitting-mixed-T3-short-selected-entry-veneer"
    ));
    assert!(stdout.contains("artifact_entry_layout=short-T3-selected-same-page-e9-v1"));
    assert!(stdout.contains("paired_ownership=inherited-mixed-T3"));
    assert!(stdout.contains("artifact_placement=current-composition-certified-fit-v1"));
    assert!(stdout.contains("local_plan_admission=inherited-and-pending-before-tactic-success"));
    for mixed in [
        flag,
        "--whole-program-current-placement-4096",
        "--whole-program-current-placement-mixed-neighbors-4096",
        "--whole-program-fitting-mixed-neighbors-4096",
        "--whole-program-4096",
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
    ] {
        for position in 2..new.len() {
            let mut bad = new.clone();
            bad[position] = mixed.into();
            assert!(arguments_with_entry_veneer(&bad).is_err());
        }
    }
    assert_eq!(
        arguments_with_entry_veneer(&new[..7]),
        arguments_with_fitting_mixed(&new[..7])
    );
    let mut extra = new.clone();
    extra.push("extra".into());
    assert!(arguments_with_entry_veneer(&extra).is_err());
    new.swap(1, 2);
    assert!(arguments_with_entry_veneer(&new).is_err());
}

#[test]
fn whole_entry_veneer_cli_retains_mode_and_denominator_on_refusal() {
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
        Mode::WholeEntryVeneerMixedPending4096,
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
    assert!(profile.contains(disassembly::whole::ENTRY_VENEER_MIXED_METADATA));
    assert!(!profile.contains("neighbor_victims\tlong-only\n"));
    let mut failed = BTreeMap::new();
    assert!(
        prepare_inputs(
            &original,
            &ledger,
            ContentId::of(&ledger),
            &policy,
            ContentId([0; 32]),
            Mode::WholeEntryVeneerMixedPending4096,
            &mut failed,
        )
        .is_err()
    );
    assert_eq!(failed.len(), 1);
    assert_eq!(failed["disassembly-inventory.tsv"], inventory);
    let (_, family, _) = labels_with_ownership(Mode::WholeEntryVeneerMixedPending4096);
    assert_eq!(family, disassembly::whole::ENTRY_VENEER_MIXED_METADATA);
}

#[test]
fn whole_packed_rx_runs_cli_is_explicit_and_preserves_every_legacy_form() {
    let base = args();
    let flag = "--whole-program-packed-entry-veneer-mixed-neighbors-4096";
    for position in 1..base.len() {
        let mut positional = base.clone();
        positional[position] = flag.into();
        assert_eq!(
            arguments_with_packed_entry_veneer(&positional),
            arguments_with_entry_veneer(&positional)
        );
    }
    for old in [
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
        "--whole-program-4096",
        "--whole-program-current-placement-4096",
        "--whole-program-current-placement-mixed-neighbors-4096",
        "--whole-program-fitting-mixed-neighbors-4096",
        "--whole-program-entry-veneer-mixed-neighbors-4096",
    ] {
        let mut input = base.clone();
        input.insert(1, old.into());
        assert_eq!(
            arguments_with_packed_entry_veneer(&input),
            arguments_with_entry_veneer(&input)
        );
        for position in 2..input.len() {
            let mut positional = input.clone();
            positional[position] = flag.into();
            assert_eq!(
                arguments_with_packed_entry_veneer(&positional),
                arguments_with_entry_veneer(&positional)
            );
        }
    }
    let mut new = base.clone();
    new.insert(1, flag.into());
    assert_eq!(
        arguments_with_packed_entry_veneer(&new).unwrap(),
        (&base[1..], Mode::WholePackedEntryVeneerMixedPending4096)
    );
    let (profile, family, stdout) =
        labels_with_ownership(Mode::WholePackedEntryVeneerMixedPending4096);
    assert_eq!(profile, disassembly::whole::PROFILE);
    assert_eq!(
        family,
        disassembly::whole::PACKED_ENTRY_VENEER_MIXED_METADATA
    );
    assert!(stdout.contains("neighbor_victims=mixed-short-and-long"));
    assert!(stdout.contains("pending_selected=full-instruction-ownership"));
    assert!(stdout.contains("selected_placement_tactics=B1,B2,T1"));
    assert!(stdout.contains(
        "paired_placement_tactics=legacy-T2,fitting-mixed-T3-short-selected-entry-veneer"
    ));
    assert!(stdout.contains("artifact_entry_layout=short-T3-selected-same-page-e9-v1"));
    assert!(stdout.contains("carrier_layout=linux-adjacent-generated-rx-runs-v1"));
    assert!(stdout.contains("carrier_page_bytes=4096"));
    assert!(stdout.contains("carrier_program_header_limit=1170"));
    assert!(stdout.contains("paired_ownership=inherited-mixed-T3"));
    assert!(stdout.contains("artifact_placement=current-composition-certified-fit-v1"));
    assert!(stdout.contains("local_plan_admission=inherited-and-pending-before-tactic-success"));
    for mixed in [
        flag,
        "--whole-program-current-placement-4096",
        "--whole-program-current-placement-mixed-neighbors-4096",
        "--whole-program-fitting-mixed-neighbors-4096",
        "--whole-program-entry-veneer-mixed-neighbors-4096",
        "--whole-program-4096",
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
    ] {
        for position in 2..new.len() {
            let mut bad = new.clone();
            bad[position] = mixed.into();
            assert!(arguments_with_packed_entry_veneer(&bad).is_err());
        }
    }
    assert_eq!(
        arguments_with_packed_entry_veneer(&new[..7]),
        arguments_with_entry_veneer(&new[..7])
    );
    let mut extra = new.clone();
    extra.push("extra".into());
    assert!(arguments_with_packed_entry_veneer(&extra).is_err());
    new.swap(1, 2);
    assert!(arguments_with_packed_entry_veneer(&new).is_err());
}

#[test]
fn whole_packed_rx_runs_cli_retains_mode_and_denominator_on_refusal() {
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
        Mode::WholePackedEntryVeneerMixedPending4096,
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
    assert!(profile.contains(disassembly::whole::PACKED_ENTRY_VENEER_MIXED_METADATA));
    assert!(!profile.contains("neighbor_victims\tlong-only\n"));
    let mut failed = BTreeMap::new();
    assert!(
        prepare_inputs(
            &original,
            &ledger,
            ContentId::of(&ledger),
            &policy,
            ContentId([0; 32]),
            Mode::WholePackedEntryVeneerMixedPending4096,
            &mut failed,
        )
        .is_err()
    );
    assert_eq!(failed.len(), 1);
    assert_eq!(failed["disassembly-inventory.tsv"], inventory);
    let (_, family, _) = labels_with_ownership(Mode::WholePackedEntryVeneerMixedPending4096);
    assert_eq!(
        family,
        disassembly::whole::PACKED_ENTRY_VENEER_MIXED_METADATA
    );
}

#[test]
fn whole_packed_overlapping_cli_is_explicit_and_preserves_every_legacy_form() {
    let base = args();
    let flag = "--whole-program-packed-overlapping-neighbors-4096";
    for position in 1..base.len() {
        let mut positional = base.clone();
        positional[position] = flag.into();
        assert_eq!(
            arguments_with_packed_overlapping(&positional),
            arguments_with_packed_entry_veneer(&positional)
        );
    }
    for old in [
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
        "--whole-program-4096",
        "--whole-program-current-placement-4096",
        "--whole-program-current-placement-mixed-neighbors-4096",
        "--whole-program-fitting-mixed-neighbors-4096",
        "--whole-program-entry-veneer-mixed-neighbors-4096",
        "--whole-program-packed-entry-veneer-mixed-neighbors-4096",
    ] {
        let mut input = base.clone();
        input.insert(1, old.into());
        assert_eq!(
            arguments_with_packed_overlapping(&input),
            arguments_with_packed_entry_veneer(&input)
        );
        for position in 2..input.len() {
            let mut positional = input.clone();
            positional[position] = flag.into();
            assert_eq!(
                arguments_with_packed_overlapping(&positional),
                arguments_with_packed_entry_veneer(&positional)
            );
        }
    }
    let mut new = base.clone();
    new.insert(1, flag.into());
    assert_eq!(
        arguments_with_packed_overlapping(&new).unwrap(),
        (&base[1..], Mode::WholePackedOverlapping4096)
    );
    let (profile, family, stdout) = labels_with_ownership(Mode::WholePackedOverlapping4096);
    assert_eq!(profile, disassembly::whole::PROFILE);
    assert_eq!(family, disassembly::whole::PACKED_OVERLAPPING_METADATA);
    assert!(stdout.contains("neighbor_victims=original-6-to-15"));
    assert!(stdout.contains("pending_selected=full-instruction-ownership"));
    assert!(stdout.contains("selected_placement_tactics=B1,B2,T1"));
    assert!(stdout.contains("paired_placement_tactics=legacy-T2,joint-overlapping-T3"));
    assert!(stdout.contains("artifact_entry_layout=direct-body-entry"));
    assert!(stdout.contains("neighbor_relay=overlapping-e9-v-v+1-six-bytes-v1"));
    assert!(stdout.contains("carrier_layout=linux-adjacent-generated-rx-runs-v1"));
    assert!(stdout.contains("carrier_page_bytes=4096"));
    assert!(stdout.contains("carrier_program_header_limit=1170"));
    assert!(stdout.contains("paired_ownership=inherited-overlapping-T3"));
    assert!(stdout.contains("artifact_placement=current-composition-certified-fit-v1"));
    assert!(stdout.contains("local_plan_admission=inherited-and-pending-before-tactic-success"));
    for mixed in [
        flag,
        "--whole-program-current-placement-4096",
        "--whole-program-current-placement-mixed-neighbors-4096",
        "--whole-program-fitting-mixed-neighbors-4096",
        "--whole-program-entry-veneer-mixed-neighbors-4096",
        "--whole-program-packed-entry-veneer-mixed-neighbors-4096",
        "--whole-program-4096",
        "--short-neighbors-only",
        "--short-neighbors-owned",
        "--short-neighbors-pending",
    ] {
        for position in 2..new.len() {
            let mut bad = new.clone();
            bad[position] = mixed.into();
            assert!(arguments_with_packed_overlapping(&bad).is_err());
        }
    }
    assert_eq!(
        arguments_with_packed_overlapping(&new[..7]),
        arguments_with_packed_entry_veneer(&new[..7])
    );
    let mut extra = new.clone();
    extra.push("extra".into());
    assert!(arguments_with_packed_overlapping(&extra).is_err());
    new.swap(1, 2);
    assert!(arguments_with_packed_overlapping(&new).is_err());
}

#[test]
fn whole_packed_overlapping_cli_retains_mode_and_denominator_on_refusal() {
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
        Mode::WholePackedOverlapping4096,
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
    assert!(profile.contains(disassembly::whole::PACKED_OVERLAPPING_METADATA));
    assert!(!profile.contains("neighbor_victims\tlong-only\n"));
    let mut failed = BTreeMap::new();
    assert!(
        prepare_inputs(
            &original,
            &ledger,
            ContentId::of(&ledger),
            &policy,
            ContentId([0; 32]),
            Mode::WholePackedOverlapping4096,
            &mut failed,
        )
        .is_err()
    );
    assert_eq!(failed.len(), 1);
    assert_eq!(failed["disassembly-inventory.tsv"], inventory);
    let (_, family, _) = labels_with_ownership(Mode::WholePackedOverlapping4096);
    assert_eq!(family, disassembly::whole::PACKED_OVERLAPPING_METADATA);
}

#[test]
fn jump_stack_rewrite_selector_preserves_old_routes_and_rejects_mixing() {
    let base = args();
    for flag in [
        "--whole-program-fixed-exec-packed-overlapping-neighbors-4096",
        "--whole-program-packed-overlapping-neighbors-4096",
        "--whole-program-4096",
        "--short-neighbors-only",
    ] {
        let mut old = base.clone();
        old.insert(1, flag.into());
        assert_eq!(
            arguments_with_jump_stack(&old),
            arguments_with_fixed_exec(&old).map(|(a, m)| (a, PopulationMode::Existing(m)))
        );
    }
    let mut input = base.clone();
    input.insert(1, JUMP_STACK_FLAG.into());
    assert_eq!(
        arguments_with_jump_stack(&input).unwrap(),
        (&base[1..], PopulationMode::JumpStack)
    );
    let (profile, metadata, _) = labels_with_population(PopulationMode::JumpStack);
    assert_eq!(profile, disassembly::jump_stack::PROFILE);
    assert_eq!(metadata, liteinst_rewrite::FIXED_EXEC_METADATA);
    assert!(metadata.contains("required_load_bias\t0\n"));
    for flag in [
        JUMP_STACK_FLAG,
        "--whole-program-4096",
        "--short-neighbors-only",
        "--input-profile",
        "--policy-profile",
    ] {
        for position in 2..8 {
            let mut mixed = input.clone();
            mixed[position] = flag.into();
            assert!(arguments_with_jump_stack(&mixed).is_err());
        }
    }
    // Existing seven positional filenames retain their old interpretation.
    assert_eq!(
        arguments_with_jump_stack(&input[..7]),
        arguments_with_fixed_exec(&input[..7]).map(|(a, m)| (a, PopulationMode::Existing(m)))
    );
    input.push("extra".into());
    assert!(arguments_with_jump_stack(&input).is_err());
    assert_eq!(
        jump_stack_fields(None),
        "selection_profile\tjumps-gpr-stack64-v1\ncomplete_site_count\tunavailable\njump_count\tunavailable\npush_r64_count\tunavailable\npop_r64_count\tunavailable\n"
    );
}

#[test]
fn jump_stack_rewrite_uses_typed_prepare_and_retains_every_imported_row_on_refusal() {
    use li2core::contracts::AddressRange;
    use liteinst_rewrite::disassembly::whole::policy::{self, Carrier, NullHook, PolicyOptions};
    let (mut original, ledger, _) = fixture();
    let old_digest = digest(&original);
    original[0x1107..0x1109].copy_from_slice(&[0x54, 0x5c]);
    let ledger = String::from_utf8(ledger)
        .unwrap()
        .replace(&old_digest, &digest(&original))
        .replace("head 4198663 7500\n", "head 4198663 54\nhead 4198664 5c\n")
        .into_bytes();
    let imported =
        disassembly::jump_stack::import(&original, &ledger, ContentId::of(&ledger)).unwrap();
    assert_eq!(imported.sites().len(), 3);
    let expected: Vec<_> = imported
        .sites()
        .iter()
        .map(|s| {
            let g = s.geometry();
            (g.id, g.pc, g.length as u8, g.file_offset)
        })
        .collect();
    assert_eq!(
        expected,
        [
            (1, 4198663, 1, 4359),
            (2, 4198664, 1, 4360),
            (3, 4198665, 2, 4361)
        ]
    );
    let options = PolicyOptions {
        domain: 7,
        hook: NullHook::LowestOriginalRet,
        carrier: Carrier::AfterLoads,
        arena: AddressRange::new(0x01000000, 0x1f000000).unwrap(),
    };
    let mut rows = String::new();
    for id in 1..=3 {
        writeln!(rows, "search {id} preferred 64 256 64 none 256 4096").unwrap();
        for role in ["selected", "victim"] {
            writeln!(
                rows,
                "allocation {id} {role} none 1 4096 16777216:520093696"
            )
            .unwrap();
        }
    }
    let spec = policy::spec_from_jump_stack_records(
        &imported,
        &original,
        options,
        b"target fxsave64\n",
        rows.as_bytes(),
    )
    .unwrap();
    let policy = policy::build_jump_stack_policy(&imported, &original, &spec).unwrap();
    let mut files = BTreeMap::new();
    let mut classes = None;
    let product = prepare_population_inputs(
        &original,
        &ledger,
        ContentId::of(&ledger),
        &policy,
        ContentId::of(&policy),
        PopulationMode::JumpStack,
        (&mut files, &mut classes),
    )
    .unwrap();
    assert_eq!(classes, Some([1, 1, 1]));
    assert_eq!(
        product
            .reports()
            .iter()
            .map(|r| (r.id, r.pc, r.length, r.file_offset))
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(files["disassembly-inventory.tsv"], imported.inventory());
    assert_eq!(
        product.files()["disassembly-inventory.tsv"],
        imported.inventory()
    );
    assert_eq!(
        product.fixed_image_binding().unwrap().identity().source.0,
        ContentId::of(&original).0
    );
    assert!(!product.qualification_complete());
    assert!(
        std::str::from_utf8(&files["selection.txt"])
            .unwrap()
            .contains("profile jumps-gpr-stack64-v1\n")
    );
    for (bytes, pin) in [(policy.clone(), ContentId([0; 32])), {
        let old = String::from_utf8(policy.clone())
            .unwrap()
            .replace(
                "LI2DISASM-JUMP-STACK-WHOLE-POLICY 1",
                "LI2DISASM-WHOLE-POLICY 1",
            )
            .into_bytes();
        let pin = ContentId::of(&old);
        (old, pin)
    }] {
        let mut retained = BTreeMap::new();
        let mut counts = None;
        assert!(
            prepare_population_inputs(
                &original,
                &ledger,
                ContentId::of(&ledger),
                &bytes,
                pin,
                PopulationMode::JumpStack,
                (&mut retained, &mut counts)
            )
            .is_err()
        );
        assert_eq!(counts, Some([1, 1, 1]));
        assert_eq!(retained["disassembly-inventory.tsv"], imported.inventory());
        assert!(!retained.contains_key("selection.txt"));
    }
    let mut retained = BTreeMap::new();
    let mut counts = None;
    assert!(
        prepare_population_inputs(
            &original,
            &ledger,
            ContentId([0; 32]),
            &policy,
            ContentId::of(&policy),
            PopulationMode::JumpStack,
            (&mut retained, &mut counts)
        )
        .is_err()
    );
    assert!(retained.is_empty());
    assert_eq!(counts, None);
}
