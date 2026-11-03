//! Real artifact transactions; no generated instruction is executed here.
use super::tests::{UPSTREAM_PC as PC, upstream_source as source};
use super::*;

fn short() -> (Vec<u8>, disassembly::whole::JumpStackWholeSelection) {
    source(&[&[0x5b], &[0x5d], &[0x41, 0x5c], &[0xc3]])
}
fn prepare(original: &[u8], selected: &disassembly::whole::JumpStackWholeSelection) -> Product {
    prepare_disassembly_jump_stack_grouped_min5_alphabet_upstream_fixed_exec(original, selected)
        .unwrap()
}

#[test]
fn alphabet_group_keeps_every_observation_and_retained_entry_in_one_plan() {
    let (original, selected) = short();
    let product = prepare(&original, &selected);
    assert!(product.candidate_complete(), "{:?}", product.reports());
    assert!(!product.qualification_complete());
    assert_eq!(product.reports().len(), 3);
    assert!(product.reports().iter().all(|r| r.candidate_emitted
        && r.refusal.is_none()
        && r.core_tactic == Some(li2core::engine::Tactic::Relocation)));
    let policy = std::str::from_utf8(&product.files()["grouping-policy.tsv"]).unwrap();
    assert!(policy.starts_with("LI2GROUPING-POLICY\t3\n"));
    assert_eq!(
        policy
            .matches("group_relocation_placement\tentry-alphabet-v1\n")
            .count(),
        1
    );
    assert!(policy.contains(&format!(
        "unit\t0\tgroup\t{PC}\t{}\t3\nwindow-seal\t0\tready\t{}\t-\t-\t-\n",
        PC + 4,
        PC + 5
    )));
    let text = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    assert_eq!(text.lines().filter(|r| r.starts_with("image\t")).count(), 1);
    assert_eq!(
        text.lines()
            .filter(|r| r.starts_with("accepted-unit\t"))
            .count(),
        1
    );
    for tag in ["route", "restored-boundary"] {
        let heads: Vec<u64> = text
            .lines()
            .filter(|r| r.starts_with(&format!("{tag}\t")))
            .map(|r| r.split('\t').nth(2).unwrap().parse().unwrap())
            .collect();
        assert_eq!(heads, [PC, PC + 1, PC + 2, PC + 4]);
    }
    for (kind, expected) in [
        ("LogicalPc", vec![PC, PC + 1, PC + 2]),
        ("HookCall", vec![0x411f00; 3]),
    ] {
        let values: Vec<u64> = text
            .lines()
            .filter(|r| r.starts_with("field\t"))
            .map(|r| r.split('\t').collect::<Vec<_>>())
            .filter(|r| r[8] == ledger::hex(kind.as_bytes()))
            .map(|r| r[6].parse().unwrap())
            .collect();
        assert_eq!(values, expected);
    }
    assert!(
        std::str::from_utf8(&product.files()["ledger.tsv"])
            .unwrap()
            .contains("fixed-output-readback\tchecked\n")
    );
}

#[test]
fn alphabet_policy_and_binding_are_distinct_while_min5_geometry_and_caps_stay_exact() {
    let (original, selected) = short();
    let old = prepare_disassembly_jump_stack_grouped_min5_upstream_fixed_exec(&original, &selected)
        .unwrap();
    let new = prepare(&original, &selected);
    assert!(old.candidate_complete() && new.candidate_complete());
    let new_policy = std::str::from_utf8(&new.files()["grouping-policy.tsv"]).unwrap();
    let inverse = new_policy
        .replace("LI2GROUPING-POLICY\t3\n", "LI2GROUPING-POLICY\t2\n")
        .replace(
            GROUPED_MIN5_ALPHABET_UPSTREAM_PROFILE,
            GROUPED_MIN5_UPSTREAM_PROFILE,
        )
        .replace("group_relocation_placement\tentry-alphabet-v1\n", "");
    assert_eq!(inverse.as_bytes(), old.files()["grouping-policy.tsv"]);
    for name in [
        "selection.txt",
        "disassembly-policy.txt",
        "disassembly-inventory.tsv",
    ] {
        assert_eq!(new.files()[name], old.files()[name]);
    }
    assert_ne!(
        new.files()["binding-policy.tsv"],
        old.files()["binding-policy.tsv"]
    );
    let binding = new.fixed_image_binding().unwrap();
    let selection = ContentId::of(&new.files()["selection.txt"]);
    let grouping = ContentId::of(&new.files()["grouping-policy.tsv"]);
    assert_eq!(
        new.files()["binding-policy.tsv"],
        grouped_min5_alphabet_upstream_fixed_exec_binding_policy(binding, selection, grouping)
    );
    assert_ne!(
        new.files()["binding-policy.tsv"],
        grouped_min5_upstream_fixed_exec_binding_policy(binding, selection, grouping)
    );
    let metadata = grouped_min5_alphabet_upstream_fixed_exec_metadata();
    assert!(metadata.contains("grouping_policy_version\t3\n"));
    assert!(metadata.contains("group_relocation_placement\tentry-alphabet-v1\n"));
    assert!(!grouped_min5_upstream_fixed_exec_metadata().contains("group_relocation_placement"));
    for change in 0..3 {
        let mut selected = selected.clone();
        for site in &mut selected.selection.sites {
            match change {
                0 => site.search.max_sites = 65,
                1 => site.search.max_upstream_bytes = 65,
                _ => site.selected_allocation.max_mapped_bytes = 4097,
            }
        }
        let refused = prepare(&original, &selected);
        assert!(!refused.candidate_complete());
        assert_eq!(refused.reports().len(), 3);
        assert!(refused.reports().iter().all(|r| !r.candidate_emitted
            && r.core_tactic.is_none()
            && r.refusal.as_ref().unwrap().stage == "grouped-upstream-policy"));
        assert!(!refused.files().contains_key("candidate.elf"));
    }
}

#[test]
fn alphabet_does_not_repair_short_min5_seals_or_split_atomically_withheld_groups() {
    let (original, selected) = source(&[
        &[0x5b],
        &[0x5d],
        &[0x41, 0x5c],
        &[0xc3],
        &[0x5b],
        &[0x5d],
        &[0xc3],
    ]);
    let product = prepare(&original, &selected);
    let old = prepare_disassembly_jump_stack_grouped_min5_upstream_fixed_exec(&original, &selected)
        .unwrap();
    assert!(!product.candidate_complete());
    assert_eq!(product.reports().len(), 5);
    let outcomes = |p: &Product| {
        p.reports()
            .iter()
            .map(|r| {
                (
                    r.id,
                    r.core_tactic,
                    r.candidate_emitted,
                    r.refusal_code,
                    r.refusal.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(outcomes(&product), outcomes(&old));
    assert!(
        product.reports()[..3]
            .iter()
            .all(|r| r.refusal_code == Some(10_003)
                && r.core_tactic == Some(li2core::engine::Tactic::Relocation))
    );
    assert!(
        product.reports()[3..]
            .iter()
            .all(|r| r.refusal_code == Some(9)
                && r.core_tactic.is_none()
                && r.refusal.as_ref().unwrap().stage == "core")
    );
    assert!(product.reports().iter().all(|r| !r.candidate_emitted));
    assert!(
        !product.files().contains_key("candidate.elf")
            && !product.files().contains_key("source.li2sparse")
    );
    let plan = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    assert!(!plan.contains("accepted-unit\t0\t"));
    assert!(plan.contains("accepted_member_count\t3\ncomplete_site_count\t5\n"));
    let policy = std::str::from_utf8(&product.files()["grouping-policy.tsv"]).unwrap();
    assert_eq!(
        policy.lines().filter(|r| r.starts_with("member\t")).count(),
        5
    );
    assert_eq!(
        policy
            .lines()
            .filter(|r| r.starts_with("window-seal\t"))
            .count(),
        2
    );
}

#[test]
fn alphabet_storage_is_independent_and_singletons_keep_the_legacy_engine() {
    let (original, selected) = short();
    let inline = prepare(&original, &selected);
    let compact =
        prepare_disassembly_jump_stack_grouped_min5_alphabet_upstream_with_ledger_storage(
            &original,
            &selected,
            LedgerStorage::ReadChunks256,
        )
        .unwrap();
    assert!(inline.candidate_complete() && compact.candidate_complete());
    ledger_storage::verify_jump_stack(&original, &selected, compact.files()).unwrap();
    for name in [
        "grouping-policy.tsv",
        "binding-policy.tsv",
        "selection.txt",
        "report.tsv",
        "disassembly-inventory.tsv",
        "source.li2sparse",
        "image-0000.bin",
    ] {
        assert_eq!(inline.files()[name], compact.files()[name], "{name}");
    }
    let (original, selected) = source(&[
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x54],
        &[0xc3],
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x5c],
        &[0xc3],
    ]);
    let new = prepare(&original, &selected);
    assert!(new.candidate_complete());
    assert!(
        !std::str::from_utf8(&new.files()["grouping-policy.tsv"])
            .unwrap()
            .contains("window-seal\t")
    );
    for profile in [
        GroupProfile::Exact,
        GroupProfile::Upstream,
        GroupProfile::Min5Upstream,
    ] {
        let old = prepare_grouped(&original, &selected, profile).unwrap();
        assert!(old.candidate_complete());
        for name in [
            "selection.txt",
            "report.tsv",
            "disassembly-inventory.tsv",
            "source.li2sparse",
            "image-0000.bin",
            "image-0001.bin",
        ] {
            assert_eq!(old.files()[name], new.files()[name], "{profile:?} {name}");
        }
    }
}
