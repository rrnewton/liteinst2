//! In-memory artifact controls; none execute generated code.
use super::super::tests::{
    UPSTREAM_BASE as BASE, UPSTREAM_PC as PC, upstream_draft as draft, upstream_elf as elf,
    upstream_run_group as run_group, upstream_source as source,
};
use super::*;

fn short() -> (Vec<u8>, disassembly::whole::JumpStackWholeSelection) {
    source(&[&[0x66, 0x90], &[0x5b], &[0x5d], &[0xc3]])
}
fn freeze(original: &[u8], selected: &disassembly::whole::JumpStackWholeSelection) -> Schedule {
    let object = elf(original);
    let identity = CodeIdentity {
        source: SourceIdentity(selected.selection.original.0),
        mapping: 7,
        generation: 1,
    };
    let binding = fixed_exec::bind(&object, identity, 7).unwrap();
    Schedule::freeze_physical(
        &object,
        &selected.selection,
        &selected.classes,
        identity,
        Some(binding),
        &[],
    )
    .unwrap()
}
fn prepare(original: &[u8], selected: &disassembly::whole::JumpStackWholeSelection) -> Product {
    prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_upstream_fixed_exec(
        original, selected,
    )
    .unwrap()
}

#[test]
fn physical_min5_refused_same_site_keeps_earlier_minimum_and_actual_ordinal() {
    let (original, selected) = short();
    let old = prepare_disassembly_jump_stack_grouped_min5_alphabet_upstream_fixed_exec(
        &original, &selected,
    )
    .unwrap();
    assert!(!old.candidate_complete());
    assert!(
        old.reports()
            .iter()
            .all(|r| r.refusal_code == Some(9) && !r.candidate_emitted)
    );
    let schedule = freeze(&original, &selected);
    let seal = schedule.groups[0]
        .physical
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap();
    assert_eq!(seal.physical_domain(), [PC + 2, PC]);
    assert_eq!(seal.rows()[0].outcome(), Err(&Refusal::NoPatchWindow));
    assert_eq!(seal.rows()[1].outcome(), Ok(PC + 5));
    assert_eq!(accepted_ordinal(seal, PC, PC + 5).unwrap(), 1);
    for (pc, end) in [(PC + 2, PC + 5), (PC, PC + 4), (PC, PC + 6)] {
        assert!(accepted_ordinal(seal, pc, end).is_err());
    }
    let mut state = draft(&original, &selected);
    let accepted = run_group(&original, &selected, &schedule, &mut state);
    assert_eq!(accepted.len(), 1);
    assert_eq!(
        schedule
            .actual_physical_ordinal(
                &selected.selection,
                &schedule.groups[0],
                accepted[0].plan.artifact()
            )
            .unwrap(),
        1
    );
    let product = prepare(&original, &selected);
    assert!(product.candidate_complete(), "{:?}", product.reports());
    assert_eq!(product.reports().len(), 2);
    assert!(!product.qualification_complete());
    let policy = std::str::from_utf8(&product.files()["grouping-policy.tsv"]).unwrap();
    assert!(policy.starts_with("LI2GROUPING-POLICY\t4\n"));
    assert!(policy.contains(&format!(
        "physical-window\t0\t0\t{}\trefused\t-\t9\tcore\t",
        PC + 2
    )));
    assert!(policy.contains(&format!(
        "physical-window\t0\t1\t{PC}\tready\t{}\t-\t-\t-\n",
        PC + 5
    )));
    let plan = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    for tag in ["route", "restored-boundary"] {
        let heads: Vec<u64> = plan
            .lines()
            .filter(|r| r.starts_with(&format!("{tag}\t")))
            .map(|r| r.split('\t').nth(2).unwrap().parse().unwrap())
            .collect();
        assert_eq!(heads, [PC, PC + 2, PC + 3, PC + 4]);
    }
    assert_eq!(plan.lines().filter(|r| r.starts_with("image\t")).count(), 1);
    assert_eq!(
        plan.lines()
            .filter(|r| r.starts_with("accepted-unit\t"))
            .count(),
        1
    );
    assert!(plan.contains("accepted_member_count\t2\ncomplete_site_count\t2\n"));
}

#[test]
fn physical_min5_refused_suffix_immediate_is_still_a_source_dependency() {
    let (original, selected) = source(&[
        &[0x48, 0x8d, 0x00],
        &[0x5b],
        &[0x5d],
        &[0xe8, 0, 0, 0, 0],
        &[0xc3],
    ]);
    let schedule = freeze(&original, &selected);
    let group = &schedule.groups[0];
    let seal = group.physical.as_ref().unwrap().as_ref().unwrap();
    assert!(seal.rows()[0].outcome().is_err());
    assert_eq!(seal.rows()[1].outcome(), Ok(PC + 5));
    assert_eq!(seal.source_dependency().unwrap().0, addr(PC, 10).unwrap());
    let mut changed = original.clone();
    changed[0x1106] = 1; // Same CALL length and same typed collector refusal.
    let object = elf(&changed);
    let identity = CodeIdentity {
        source: SourceIdentity(selected.selection.original.0),
        mapping: 7,
        generation: 1,
    };
    let original_object = elf(&original);
    let binding = fixed_exec::bind(&original_object, identity, 7).unwrap();
    let request = GroupRequest::new(
        &object,
        &selected.selection,
        identity,
        Some(binding),
        group,
        &[],
    )
    .unwrap();
    assert_eq!(
        seal.matches_request(&request.artifact(), &request.pcs),
        Err(Refusal::ExpectedBytesChanged)
    );
    let object = elf(&original);
    let request = GroupRequest::new(
        &object,
        &selected.selection,
        identity,
        Some(binding),
        group,
        &[],
    )
    .unwrap();
    seal.matches_request(&request.artifact(), &request.pcs)
        .unwrap();
    assert!(
        seal.matches_request(&request.artifact(), &request.pcs[..1])
            .is_err()
    );
    let mut request = request;
    request.search.max_sites = 63;
    assert!(
        seal.matches_request(&request.artifact(), &request.pcs)
            .is_err()
    );
    request.search.max_sites = 64;
    request.identity.generation += 1;
    assert!(
        seal.matches_request(&request.artifact(), &request.pcs)
            .is_err()
    );
}

#[test]
fn physical_min5_complete_manifest_rejects_consumed_and_straddling_foreign_members() {
    let (original, selected) = short();
    let schedule = freeze(&original, &selected);
    for (pc, length) in [(PC, 2), (PC - 1, 2)] {
        let mut selected = selected.clone();
        let mut foreign = selected.selection.sites[0].clone();
        foreign.id = 3;
        foreign.pc = pc;
        foreign.length = length;
        selected.selection.sites.push(foreign);
        let mut state = draft(&original, &selected);
        state.pending.retain(|(i, _)| *i != 2); // It is absent from pending, not from the manifest.
        let before = state.composition.clone();
        assert!(run_group(&original, &selected, &schedule, &mut state).is_empty());
        assert_eq!(state.composition, before);
        assert!(
            state.reports[..2]
                .iter()
                .all(
                    |r| r.refusal.as_ref().unwrap().stage == "grouped-membership"
                        && r.core_tactic.is_none()
                        && !r.candidate_emitted
                )
        );
    }
}

#[test]
fn physical_min5_serializes_first_sixty_four_rows_without_losing_omitted_prefix_membership() {
    let mut chunks: Vec<&[u8]> = vec![&[0x90]; 64];
    chunks.extend([&[0x5b][..], &[0x5d][..], &[0xc3][..]]);
    let (original, selected) = source(&chunks);
    let schedule = freeze(&original, &selected);
    let group = &schedule.groups[0];
    let seal = group.physical.as_ref().unwrap().as_ref().unwrap();
    assert_eq!((seal.physical_domain().len(), seal.rows().len()), (65, 64));
    let omitted = seal.physical_domain()[64];
    assert_eq!(omitted, PC + 57);
    assert!(seal.rows().iter().all(|row| row.physical_pc() != omitted));
    assert!(
        std::str::from_utf8(&schedule.policy)
            .unwrap()
            .contains("window-domain\t0\t65\t64\t1\n")
    );
    let mut changed = selected.clone();
    let mut foreign = changed.selection.sites[0].clone();
    foreign.id = 3;
    foreign.pc = omitted;
    foreign.length = 1;
    changed.selection.sites.push(foreign);
    assert_eq!(
        schedule
            .validate_physical_membership(&changed.selection, group, seal)
            .unwrap_err()
            .stage,
        "grouped-membership"
    );
}

#[test]
fn physical_min5_policy_refusal_has_no_invented_domain_and_atomic_failure_keeps_all_sites() {
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
        let refused = prepare(&original, &wrong);
        assert!(!refused.candidate_complete());
        assert_eq!(refused.reports().len(), 2);
        assert!(
            refused
                .reports()
                .iter()
                .all(|r| r.refusal_code == Some(10_001)
                    && r.refusal.as_ref().unwrap().stage == "grouped-upstream-policy"
                    && r.core_tactic.is_none())
        );
        let policy = std::str::from_utf8(&refused.files()["grouping-policy.tsv"]).unwrap();
        assert!(policy.contains("unit-preflight\t0\trefused\t10001\tgrouped-upstream-policy\t"));
        assert!(!policy.contains("window-domain\t") && !policy.contains("physical-window\t"));
    }
    let (original, selected) = source(&[
        &[0x66, 0x90],
        &[0x5b],
        &[0x5d],
        &[0xc3],
        &[0x5b],
        &[0x5d],
        &[0xc3],
    ]);
    let product = prepare(&original, &selected);
    assert_eq!(product.reports().len(), 4);
    assert!(!product.candidate_complete());
    assert!(
        product.reports()[..2]
            .iter()
            .all(|r| r.refusal_code == Some(10_003) && r.core_tactic.is_some())
    );
    assert!(
        product.reports()[2..]
            .iter()
            .all(|r| r.refusal_code == Some(9) && r.core_tactic.is_none())
    );
    assert!(product.reports().iter().all(|r| !r.candidate_emitted));
    assert!(
        !product.files().contains_key("candidate.elf")
            && !product.files().contains_key("source.li2sparse")
    );
}

#[test]
fn physical_min5_storage_is_independent_and_carrier_refusal_cannot_promote_a_plan() {
    let (original, selected) = short();
    let inline = prepare(&original, &selected);
    let compact =
        prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_upstream_with_ledger_storage(
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
        "report.tsv",
        "source.li2sparse",
        "image-0000.bin",
    ] {
        assert_eq!(inline.files()[name], compact.files()[name]);
    }
    let mut collision = selected.clone();
    collision.selection.carrier_pc = BASE;
    let refused = prepare(&original, &collision);
    assert!(
        refused
            .reports()
            .iter()
            .all(|r| r.refusal_code == Some(10_002)
                && r.core_tactic.is_some()
                && !r.candidate_emitted)
    );
    assert!(!refused.files().contains_key("candidate.elf"));
    let metadata = grouped_physical_min5_alphabet_upstream_fixed_exec_metadata();
    assert!(metadata.contains(
        "grouping_policy_version\t4\nwindow_sealing\tphysical-minimum-whole-instruction-v1\n"
    ));
    assert_ne!(
        inline.files()["binding-policy.tsv"],
        grouped_min5_alphabet_upstream_fixed_exec_binding_policy(
            inline.fixed_image_binding().unwrap(),
            ContentId::of(&inline.files()["selection.txt"]),
            ContentId::of(&inline.files()["grouping-policy.tsv"])
        )
    );
}
