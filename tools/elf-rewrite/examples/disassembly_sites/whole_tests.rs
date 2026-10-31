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
