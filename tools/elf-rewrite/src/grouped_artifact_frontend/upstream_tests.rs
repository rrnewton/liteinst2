//! Source-only additive controls for the explicit upstream profile.
use super::tests::{
    UPSTREAM_BASE as BASE, UPSTREAM_PC as PC, upstream_draft as draft, upstream_elf as elf,
    upstream_run_group as run_group, upstream_source as source,
};
use super::*;

fn short() -> (Vec<u8>, disassembly::whole::JumpStackWholeSelection) {
    source(&[&[0x0f, 0x1f, 0x44, 0, 0], &[0x5b], &[0x5d], &[0xc3]])
}

#[test]
fn upstream_short_group_keeps_members_and_routes_unselected_prefix_once() {
    let (original, selected) = short();
    let exact = prepare_disassembly_jump_stack_grouped_fixed_exec(&original, &selected).unwrap();
    assert!(!exact.candidate_complete());
    assert_eq!(exact.reports().len(), 2);
    assert!(
        exact
            .reports()
            .iter()
            .all(|r| r.refusal_code == Some(9) && !r.candidate_emitted)
    );
    let product =
        prepare_disassembly_jump_stack_grouped_upstream_fixed_exec(&original, &selected).unwrap();
    assert!(product.candidate_complete(), "{:?}", product.reports());
    assert!(!product.qualification_complete());
    assert_eq!(product.reports().len(), 2);
    assert!(product.reports().iter().all(|r| r.candidate_emitted
        && r.refusal.is_none()
        && r.core_tactic == Some(li2core::engine::Tactic::Relocation)));
    let text = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    assert_eq!(
        text.lines()
            .filter(|r| r.starts_with("step\t"))
            .collect::<Vec<_>>(),
        [format!(
            "step\t1\t0\trelocation\t{}\t{PC}\t{PC}\t{}",
            PC + 5,
            PC + 7
        )]
    );
    assert_eq!(text.lines().filter(|r| r.starts_with("image\t")).count(), 1);
    assert_eq!(
        text.lines()
            .filter(|r| r.starts_with("allocation\t"))
            .count(),
        1
    );
    for tag in ["route", "restored-boundary"] {
        let heads: Vec<u64> = text
            .lines()
            .filter(|r| r.starts_with(&format!("{tag}\t")))
            .map(|r| r.split('\t').nth(2).unwrap().parse().unwrap())
            .collect();
        assert_eq!(heads, [PC, PC + 5, PC + 6]);
    }
    let logical: Vec<u64> = text
        .lines()
        .filter(|r| r.starts_with("field\t"))
        .map(|r| r.split('\t').collect::<Vec<_>>())
        .filter(|r| r[8] == ledger::hex(b"LogicalPc"))
        .map(|r| r[6].parse().unwrap())
        .collect();
    assert_eq!(logical, [PC + 5, PC + 6]);
    let policy = std::str::from_utf8(&product.files()["grouping-policy.tsv"]).unwrap();
    assert!(policy.contains(&format!("unit\t0\tgroup\t{}\t{}\t2\n", PC + 5, PC + 7)));
    assert!(
        policy
            .contains("max_physical_sites\t64\nmax_upstream_bytes\t64\nmax_displaced_bytes\t256\n")
    );
    assert!(!policy.contains("group_attempts\t1\n"));
    assert_eq!(
        product.files()["selection.txt"],
        exact.files()["selection.txt"]
    );
    assert_eq!(
        product.files()["disassembly-inventory.tsv"],
        exact.files()["disassembly-inventory.tsv"]
    );
    assert!(
        std::str::from_utf8(&product.files()["binding-policy.tsv"])
            .unwrap()
            .contains(GROUPED_UPSTREAM_PROFILE)
    );
    assert!(
        std::str::from_utf8(&exact.files()["binding-policy.tsv"])
            .unwrap()
            .contains(GROUPED_PROFILE)
    );
}

#[test]
fn upstream_full_manifest_rejects_consumed_and_straddling_prefix_members() {
    let (original, selected) = source(&[
        &[0x0f, 0x1f, 0x44, 0, 0],
        &[0x5b],
        &[0x5d],
        &[0x5e],
        &[0xc3],
    ]);
    for straddles in [false, true] {
        let mut selected = selected.clone();
        let mut schedule =
            Schedule::freeze_upstream(&elf(&original), &selected.selection, &selected.classes)
                .unwrap();
        // A hostile partition omits the earlier selected POP from the
        // remaining selected span. Pending-only validation would miss it.
        schedule.groups[0].members.remove(0);
        schedule.groups[0].window = addr(PC + 6, 2).unwrap();
        if straddles {
            // Defensive interval case: outside member crosses the block
            // prefix floor but ends before the group's selected span.
            selected.selection.sites[0].pc = PC - 1;
            selected.selection.sites[0].length = 2;
        }
        schedule
            .validate_group(&selected.selection, &schedule.groups[0])
            .unwrap();
        let mut state = draft(&original, &selected);
        state.pending.retain(|(index, _)| *index != 0); // already consumed
        let before = state.composition.clone();
        let pending = state.pending.clone();
        let accepted = run_group(&original, &selected, &schedule, &mut state);
        assert!(accepted.is_empty() && state.accepted.is_empty());
        assert_eq!(state.composition, before);
        assert_eq!(state.pending, pending);
        assert_eq!(
            (state.image_count, state.image_bytes, state.allocation_pages),
            (0, 0, 0)
        );
        for report in &state.reports[1..] {
            assert_eq!(report.refusal.as_ref().unwrap().stage, "grouped-membership");
            assert!(report.core_tactic.is_none() && !report.candidate_emitted);
        }
    }
}

#[test]
fn upstream_named_bounds_and_final_carrier_failure_remain_atomic() {
    let (original, selected) = short();
    for mutation in 0..6 {
        let mut wrong = selected.clone();
        for site in &mut wrong.selection.sites {
            match mutation {
                0 => site.search.max_sites = 65,
                1 => site.search.max_upstream_bytes = 65,
                2 => site.search.max_displaced_bytes = 257,
                3 => site.selected_allocation.max_candidates = 2,
                4 => site.selected_allocation.max_mappings = 2,
                _ => site.selected_allocation.max_mapped_bytes = 4097,
            }
        }
        let refused =
            prepare_disassembly_jump_stack_grouped_upstream_fixed_exec(&original, &wrong).unwrap();
        assert!(!refused.candidate_complete());
        assert_eq!(refused.reports().len(), 2);
        assert!(
            refused
                .reports()
                .iter()
                .all(
                    |r| r.refusal.as_ref().unwrap().stage == "grouped-upstream-policy"
                        && r.core_tactic.is_none()
                        && !r.candidate_emitted
                )
        );
        assert!(
            !refused
                .files()
                .keys()
                .any(|n| n.starts_with("image-") || n == "candidate.elf")
        );
    }
    let mut collision = selected.clone();
    collision.selection.carrier_pc = BASE;
    let refused =
        prepare_disassembly_jump_stack_grouped_upstream_fixed_exec(&original, &collision).unwrap();
    assert!(!refused.candidate_complete());
    assert_eq!(refused.reports().len(), 2);
    assert!(
        refused
            .reports()
            .iter()
            .all(|r| r.refusal_code == Some(10_002)
                && !r.candidate_emitted
                && r.core_tactic == Some(li2core::engine::Tactic::Relocation))
    );
    assert!(
        !refused.files().contains_key("candidate.elf")
            && !refused.files().contains_key("source.li2sparse")
    );
    assert!(
        std::str::from_utf8(&refused.files()["plan-ledger.tsv"])
            .unwrap()
            .contains("accepted_member_count\t2\ncomplete_site_count\t2\n")
    );
}

#[test]
fn upstream_nongroup_engine_matches_exact_images_and_outcomes() {
    let (original, selected) = source(&[
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x54],
        &[0xc3],
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x5c],
        &[0xc3],
    ]);
    let exact = prepare_disassembly_jump_stack_grouped_fixed_exec(&original, &selected).unwrap();
    let upstream =
        prepare_disassembly_jump_stack_grouped_upstream_fixed_exec(&original, &selected).unwrap();
    assert!(exact.candidate_complete() && upstream.candidate_complete());
    for name in [
        "selection.txt",
        "target.tsv",
        "disassembly-inventory.tsv",
        "disassembly-policy.txt",
        "report.tsv",
        "source.li2sparse",
        "image-0000.bin",
        "image-0001.bin",
    ] {
        assert_eq!(exact.files()[name], upstream.files()[name], "{name}");
    }
    assert!(
        Schedule::freeze_upstream(&elf(&original), &selected.selection, &selected.classes)
            .unwrap()
            .groups
            .is_empty()
    );
}
