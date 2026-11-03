//! Actual sealed import/core/carrier controls; authored RET, no native execution.
use super::tests::{
    UPSTREAM_BASE as BASE, UPSTREAM_PC as PC, upstream_draft as draft, upstream_elf as elf,
    upstream_run_group as run_group, upstream_source as source,
};
use super::*;

fn short() -> (Vec<u8>, disassembly::whole::JumpStackWholeSelection) {
    source(&[&[0x5b], &[0x5d], &[0x41, 0x5c], &[0xc3]])
}
fn freeze(original: &[u8], selected: &disassembly::whole::JumpStackWholeSelection) -> Schedule {
    let identity = CodeIdentity {
        source: SourceIdentity(selected.selection.original.0),
        mapping: 7,
        generation: 1,
    };
    let object = elf(original);
    let binding = fixed_exec::bind(&object, identity, 7).unwrap();
    Schedule::freeze_min5_upstream(
        &object,
        &selected.selection,
        &selected.classes,
        identity,
        Some(binding),
        &[],
    )
    .unwrap()
}

#[test]
fn min5_retained_ret_reaches_actual_carrier_without_changing_selected_population() {
    let (original, selected) = short();
    let old =
        prepare_disassembly_jump_stack_grouped_upstream_fixed_exec(&original, &selected).unwrap();
    assert!(!old.candidate_complete());
    assert_eq!(old.reports().len(), 3);
    assert!(
        old.reports()
            .iter()
            .all(|r| r.refusal_code == Some(9) && !r.candidate_emitted)
    );
    let product =
        prepare_disassembly_jump_stack_grouped_min5_upstream_fixed_exec(&original, &selected)
            .unwrap();
    assert!(product.candidate_complete(), "{:?}", product.reports());
    assert!(!product.qualification_complete());
    assert_eq!(product.reports().len(), 3);
    assert!(product.reports().iter().all(|r| r.candidate_emitted
        && r.refusal.is_none()
        && r.core_tactic == Some(li2core::engine::Tactic::Relocation)));
    for name in [
        "selection.txt",
        "disassembly-inventory.tsv",
        "disassembly-policy.txt",
    ] {
        assert_eq!(product.files()[name], old.files()[name]);
    }
    let policy = std::str::from_utf8(&product.files()["grouping-policy.tsv"]).unwrap();
    assert!(policy.starts_with("LI2GROUPING-POLICY\t2\n"));
    assert!(policy.contains(&format!("unit\t0\tgroup\t{PC}\t{}\t3\nwindow-seal\t0\tready\t{}\t-\t-\t-\nmember\t0\t1\t{PC}\t1\tpop-r64\n", PC + 4, PC + 5)));
    let text = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    assert!(text.contains(&format!(
        "step\t1\t0\trelocation\t{PC}\t{PC}\t{PC}\t{}\n",
        PC + 5
    )));
    for tag in ["route", "restored-boundary"] {
        let heads: Vec<u64> = text
            .lines()
            .filter(|row| row.starts_with(&format!("{tag}\t")))
            .map(|row| row.split('\t').nth(2).unwrap().parse().unwrap())
            .collect();
        assert_eq!(heads, [PC, PC + 1, PC + 2, PC + 4]);
    }
    let observed: Vec<u64> = text
        .lines()
        .filter(|r| r.starts_with("field\t"))
        .map(|r| r.split('\t').collect::<Vec<_>>())
        .filter(|r| r[8] == ledger::hex(b"LogicalPc"))
        .map(|r| r[6].parse().unwrap())
        .collect();
    assert_eq!(observed, [PC, PC + 1, PC + 2]);
    assert_eq!(text.lines().filter(|r| r.starts_with("image\t")).count(), 1);
    assert!(
        std::str::from_utf8(&product.files()["ledger.tsv"])
            .unwrap()
            .contains("fixed-output-readback\tchecked\n")
    );
    assert!(product.files().contains_key("candidate.elf"));
    assert_ne!(
        product.files()["binding-policy.tsv"],
        old.files()["binding-policy.tsv"]
    );
}

#[test]
fn min5_preflight_failure_keeps_all_units_and_exact_member_refusals_atomic() {
    let (original, selected) = source(&[
        &[0x5b],
        &[0x5d],
        &[0x41, 0x5c],
        &[0xc3],
        &[0x5b],
        &[0x5d],
        &[0xc3],
    ]);
    let schedule = freeze(&original, &selected);
    assert_eq!(schedule.groups.len(), 2);
    assert!(matches!(schedule.groups[0].seal.as_ref(), Some(Err(_))));
    assert!(matches!(schedule.groups[1].seal.as_ref(), Some(Ok(_))));
    let product =
        prepare_disassembly_jump_stack_grouped_min5_upstream_fixed_exec(&original, &selected)
            .unwrap();
    assert!(!product.candidate_complete());
    assert_eq!(product.reports().len(), 5);
    assert!(product.reports().iter().all(|r| !r.candidate_emitted));
    assert!(
        !product.files().contains_key("candidate.elf")
            && !product.files().contains_key("source.li2sparse")
    );
    for report in &product.reports()[..3] {
        assert_eq!(report.refusal_code, Some(10_003));
        assert_eq!(
            report.core_tactic,
            Some(li2core::engine::Tactic::Relocation)
        );
    }
    let Some(Err(failure)) = &schedule.groups[0].seal else {
        panic!("short block preflight refusal")
    };
    let core = failure.core.as_ref().unwrap();
    assert_eq!(core.reason, Refusal::NoPatchWindow);
    assert!(core.attempts.is_empty() && core.search.runs.is_empty() && !core.search.accepted);
    for report in &product.reports()[3..] {
        assert_eq!(report.refusal_code, Some(failure.code));
        assert_eq!(report.refusal.as_ref(), Some(&failure.error));
        assert!(report.core_tactic.is_none());
    }
    let policy = std::str::from_utf8(&product.files()["grouping-policy.tsv"]).unwrap();
    assert!(policy.contains(&format!(
        "window-seal\t0\trefused\t-\t9\tcore\t{}\n",
        ledger::hex(failure.error.detail.as_bytes())
    )));
    let plan = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    assert!(!plan.contains("accepted-unit\t0\t"));
    assert!(plan.contains("accepted_member_count\t3\ncomplete_site_count\t5\n"));
}

#[test]
fn min5_full_manifest_and_frozen_source_join_reject_consumed_straddling_or_changed_input() {
    let (original, selected) = short();
    for straddles in [false, true] {
        let mut selected = selected.clone();
        let mut schedule = freeze(&original, &selected);
        schedule.groups[0].members.remove(0);
        schedule.groups[0].window = addr(PC + 1, 3).unwrap();
        if straddles {
            selected.selection.sites[0].pc = PC - 1;
            selected.selection.sites[0].length = 2;
        }
        let mut state = draft(&original, &selected);
        state.pending.retain(|(i, _)| *i != 0);
        let before = state.composition.clone();
        assert!(run_group(&original, &selected, &schedule, &mut state).is_empty());
        assert_eq!(state.composition, before);
        for report in &state.reports[1..] {
            assert_eq!(report.refusal.as_ref().unwrap().stage, "grouped-membership");
            assert!(report.core_tactic.is_none() && !report.candidate_emitted);
        }
    }
    let schedule = freeze(&original, &selected);
    // The complete manifest, not pending alone, owns even the retained suffix.
    // This internal malformed-roster mutation must fail before qualification.
    let mut extra = selected.clone();
    let mut foreign = extra.selection.sites[2].clone();
    foreign.id = 4;
    foreign.pc = PC + 4;
    foreign.file_offset = 0x1104;
    foreign.length = 1;
    extra.selection.sites.push(foreign);
    let mut state = draft(&original, &extra);
    state.pending.retain(|(i, _)| *i != 3);
    let before = state.composition.clone();
    assert!(run_group(&original, &extra, &schedule, &mut state).is_empty());
    assert_eq!(state.composition, before);
    assert!(
        state.reports[..3]
            .iter()
            .all(
                |r| r.refusal.as_ref().unwrap().stage == "grouped-membership"
                    && r.core_tactic.is_none()
                    && !r.candidate_emitted
            )
    );
    let mut changed = original.clone();
    changed[0x1104] = 0x90;
    let mut state = draft(&changed, &selected);
    let before = state.composition.clone();
    let identity = state.composition.identity();
    let original_elf = elf(&original);
    let binding =
        fixed_exec::bind(&original_elf, identity, selected.selection.bias_domain).unwrap();
    let changed_elf = elf(&changed);
    // Public admission must reject the changed digest before group planning.
    let error =
        fixed_exec::bind(&changed_elf, identity, selected.selection.bias_domain).unwrap_err();
    assert_eq!(error.stage, "fixed-exec-binding");
    assert_eq!(error.detail, "\"original digest mismatch\"");
    // Independently challenge the frozen seal using the previously bound input.
    // This deliberately stale internal context is not a new public admission.
    let dynamic =
        carrier::dynamic::inspect(&changed_elf, carrier::dynamic::Limits::default()).unwrap();
    let mut accepted = Vec::new();
    let evidence = plan(
        SingletonContext {
            elf: &changed_elf,
            dynamic: &dynamic,
            s: &selected.selection,
            identity,
            fixed_binding: Some(binding),
            owned_neighbors: false,
            mode: disassembly::NeighborMode::WholeOverlappingPending,
            record_baseline: false,
        },
        &schedule,
        &mut state,
        &mut accepted,
    );
    assert_eq!(evidence.len(), schedule.groups.len());
    assert!(accepted.is_empty());
    assert_eq!(state.composition, before);
    assert!(
        state
            .reports
            .iter()
            .all(|r| r.refusal.as_ref().unwrap().stage == "grouped-seal"
                && r.refusal.as_ref().unwrap().detail == "ExpectedBytesChanged")
    );
}

#[test]
fn min5_named_bounds_and_final_carrier_refusal_never_relax_atomicity() {
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
            prepare_disassembly_jump_stack_grouped_min5_upstream_fixed_exec(&original, &wrong)
                .unwrap();
        assert!(!refused.candidate_complete());
        assert_eq!(refused.reports().len(), 3);
        assert!(
            refused
                .reports()
                .iter()
                .all(
                    |r| r.refusal.as_ref().unwrap().stage == "grouped-upstream-policy"
                        && r.refusal_code == Some(10_001)
                        && r.core_tactic.is_none()
                        && !r.candidate_emitted
                )
        );
        assert!(
            std::str::from_utf8(&refused.files()["grouping-policy.tsv"])
                .unwrap()
                .contains("window-seal\t0\trefused\t-\t10001\tgrouped-upstream-policy\t")
        );
    }
    let mut collision = selected.clone();
    collision.selection.carrier_pc = BASE;
    let refused =
        prepare_disassembly_jump_stack_grouped_min5_upstream_fixed_exec(&original, &collision)
            .unwrap();
    assert!(!refused.candidate_complete());
    assert_eq!(refused.reports().len(), 3);
    assert!(
        refused
            .reports()
            .iter()
            .all(|r| r.refusal_code == Some(10_002)
                && !r.candidate_emitted
                && r.core_tactic == Some(li2core::engine::Tactic::Relocation))
    );
    assert!(!refused.files().contains_key("candidate.elf"));
}

#[test]
fn min5_reuses_compact_codec_and_unchanged_singleton_engine() {
    let (original, selected) = short();
    let inline =
        prepare_disassembly_jump_stack_grouped_min5_upstream_fixed_exec(&original, &selected)
            .unwrap();
    let compact = prepare_disassembly_jump_stack_grouped_min5_upstream_with_ledger_storage(
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
    assert!(
        std::str::from_utf8(&compact.files()["plan-ledger.tsv"])
            .unwrap()
            .starts_with("LI2GROUPED-LEDGER\t2\n")
    );
    let (original, selected) = source(&[
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x54],
        &[0xc3],
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x5c],
        &[0xc3],
    ]);
    let old =
        prepare_disassembly_jump_stack_grouped_upstream_fixed_exec(&original, &selected).unwrap();
    let new = prepare_disassembly_jump_stack_grouped_min5_upstream_fixed_exec(&original, &selected)
        .unwrap();
    assert!(old.candidate_complete() && new.candidate_complete());
    assert!(
        !std::str::from_utf8(&new.files()["grouping-policy.tsv"])
            .unwrap()
            .contains("window-seal\t")
    );
    for name in [
        "selection.txt",
        "report.tsv",
        "disassembly-inventory.tsv",
        "source.li2sparse",
        "image-0000.bin",
        "image-0001.bin",
    ] {
        assert_eq!(old.files()[name], new.files()[name]);
    }
}
