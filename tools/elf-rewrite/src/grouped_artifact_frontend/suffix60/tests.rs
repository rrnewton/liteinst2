//! Shared planner and carrier controls, without generated execution.
use super::super::tests::{
    UPSTREAM_PC as PC, upstream_draft as draft, upstream_elf as elf,
    upstream_run_group as run_group, upstream_source as source,
};
use super::*;

fn prepare(original: &[u8], selected: &disassembly::whole::JumpStackWholeSelection) -> Product {
    prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_suffix60_upstream_fixed_exec(
        original, selected,
    )
    .unwrap()
}
fn freeze(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
    profile: GroupProfile,
) -> Schedule {
    let object = elf(original);
    let identity = CodeIdentity {
        source: SourceIdentity(selected.selection.original.0),
        mapping: 7,
        generation: 1,
    };
    let binding = fixed_exec::bind(&object, identity, 7).unwrap();
    Schedule::freeze_physical_profile(
        &object,
        &selected.selection,
        &selected.classes,
        identity,
        Some(binding),
        &[],
        profile,
    )
    .unwrap()
}
fn short() -> (Vec<u8>, disassembly::whole::JumpStackWholeSelection) {
    source(&[&[0x66, 0x90], &[0x5b], &[0x5d], &[0xc3]])
}

#[test]
fn suffix60_group_mode_changes_only_the_actual_suffix_store() {
    let mut chunks: Vec<&[u8]> = vec![&[0x5b], &[0x5d], &[0x90], &[0x90], &[0x90], &[0x5b]];
    chunks.extend([&[0x90][..]; 14]);
    chunks.push(&[0xc3]);
    let (original, selected) = source(&chunks);
    assert_eq!(selected.selection.sites.len(), 3);
    let mut old_state = draft(&original, &selected);
    let mut new_state = old_state.clone();
    let old_schedule = freeze(
        &original,
        &selected,
        GroupProfile::PhysicalMin5AlphabetUpstream,
    );
    let new_schedule = freeze(
        &original,
        &selected,
        GroupProfile::PhysicalMin5AlphabetSuffix60Upstream,
    );
    let old = run_group(&original, &selected, &old_schedule, &mut old_state);
    let new = run_group(&original, &selected, &new_schedule, &mut new_state);
    assert_eq!((old.len(), new.len()), (1, 1));
    let old = old[0].plan.artifact();
    let new = new[0].plan.artifact();
    assert_eq!((old.source_steps().len(), new.source_steps().len()), (1, 1));
    let old_parts = old.source_steps()[0].parts();
    assert_eq!(old_parts.physical_pc, PC);
    assert_eq!(old_parts.displaced, addr(PC, 6).unwrap());
    assert_eq!(old_parts.writes.len(), 1);
    assert_eq!(old_parts.writes[0].bytes.len(), 6);
    assert_eq!(old_parts.writes[0].bytes[5], 0x62);
    let mut expected = old_parts.clone();
    expected.writes[0].bytes[5] = 0x60;
    assert_eq!(new.source_steps()[0].parts(), &expected);
    assert_eq!(old.images().count(), 1);
    assert_eq!(new.images().count(), 1);
    let old_image = old.images().next().unwrap();
    let new_image = new.images().next().unwrap();
    assert_eq!(old_image.address(), new_image.address());
    assert_eq!(old_image.bytes(), new_image.bytes());
    assert_eq!(old_image.entry_routes(), new_image.entry_routes());
    assert_eq!(old_image.metadata(), new_image.metadata());
    assert_eq!(old_state.pending, new_state.pending);
    assert!(new_state.pending.is_empty());
    assert!(!old.qualification_complete() && !new.qualification_complete());
}

#[test]
fn suffix60_policy_and_portable_binding_are_explicit_with_all_old_bounds() {
    let (original, selected) = short();
    let old = prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_upstream_fixed_exec(
        &original, &selected,
    )
    .unwrap();
    let new = prepare(&original, &selected);
    assert!(old.candidate_complete() && new.candidate_complete());
    let policy = std::str::from_utf8(&new.files()["grouping-policy.tsv"]).unwrap();
    let inverse = policy
        .replace("LI2GROUPING-POLICY\t5\n", "LI2GROUPING-POLICY\t4\n")
        .replace(
            GROUPED_PHYSICAL_MIN5_ALPHABET_SUFFIX60_UPSTREAM_PROFILE,
            GROUPED_PHYSICAL_MIN5_ALPHABET_UPSTREAM_PROFILE,
        )
        .replace("group_routed_suffix\tsingle-byte60-v1\n", "");
    assert_eq!(inverse.as_bytes(), old.files()["grouping-policy.tsv"]);
    assert_eq!(
        policy
            .matches("group_routed_suffix\tsingle-byte60-v1\n")
            .count(),
        1
    );
    assert_eq!(
        GroupProfile::PhysicalMin5AlphabetUpstream.suffix(),
        ArtifactRoutedSuffix::Qualified62
    );
    assert_eq!(
        GroupProfile::PhysicalMin5AlphabetSuffix60Upstream.suffix(),
        ArtifactRoutedSuffix::SingleByte60
    );
    for name in [
        "selection.txt",
        "disassembly-policy.txt",
        "disassembly-inventory.tsv",
        "image-0000.bin",
        "source.li2sparse",
    ] {
        assert_eq!(new.files()[name], old.files()[name]);
    }
    let metadata = grouped_physical_min5_alphabet_suffix60_upstream_fixed_exec_metadata();
    assert!(metadata.contains(
        "grouping_policy_version\t5\nwindow_sealing\tphysical-minimum-whole-instruction-v1\n"
    ));
    assert!(metadata.ends_with("group_routed_suffix\tsingle-byte60-v1\n"));
    assert!(
        !grouped_physical_min5_alphabet_upstream_fixed_exec_metadata()
            .contains("group_routed_suffix")
    );
    let binding = new.fixed_image_binding().unwrap();
    let selection = ContentId::of(&new.files()["selection.txt"]);
    let grouping = ContentId::of(&new.files()["grouping-policy.tsv"]);
    assert_eq!(
        new.files()["binding-policy.tsv"],
        grouped_physical_min5_alphabet_suffix60_upstream_fixed_exec_binding_policy(
            binding, selection, grouping
        )
    );
    assert_ne!(
        new.files()["binding-policy.tsv"],
        grouped_physical_min5_alphabet_upstream_fixed_exec_binding_policy(
            binding, selection, grouping
        )
    );
    assert!(
        new.files()["binding-policy.tsv"].ends_with(b"group_routed_suffix\tsingle-byte60-v1\n")
    );
    for change in 0..6 {
        let mut wrong = selected.clone();
        for site in &mut wrong.selection.sites {
            match change {
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
                    && r.core_tactic.is_none()
                    && !r.candidate_emitted)
        );
        assert!(!refused.files().contains_key("candidate.elf"));
    }
}

#[test]
fn suffix60_group_profile_keeps_singleton_artifacts_and_storage_unchanged() {
    let (original, selected) = source(&[
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x54],
        &[0xc3],
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x5c],
        &[0xc3],
    ]);
    assert_eq!(selected.selection.sites.len(), 2);
    let old = prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_upstream_fixed_exec(
        &original, &selected,
    )
    .unwrap();
    let new = prepare(&original, &selected);
    assert!(old.candidate_complete() && new.candidate_complete());
    for name in [
        "selection.txt",
        "report.tsv",
        "image-0000.bin",
        "image-0001.bin",
        "source.li2sparse",
    ] {
        assert_eq!(new.files()[name], old.files()[name]);
    }
    let (original, selected) = short();
    let inline = prepare(&original, &selected);
    let compact = prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_suffix60_upstream_with_ledger_storage(
        &original, &selected, LedgerStorage::ReadChunks256,
    ).unwrap();
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
}

#[test]
fn suffix60_later_refusal_and_carrier_failure_atomically_withhold_every_member() {
    let (original, selected) = source(&[
        &[0x5b],
        &[0x5d],
        &[0xc3],
        &[0x66, 0x90],
        &[0x5b],
        &[0x5d],
        &[0xc3],
    ]);
    let product = prepare(&original, &selected);
    assert_eq!(product.reports().len(), 4);
    assert!(!product.candidate_complete());
    // The descending schedule accepts the upper group before the lower refusal.
    assert!(
        product.reports()[2..]
            .iter()
            .all(|r| r.refusal_code == Some(10_003)
                && r.refusal.as_ref().unwrap().stage == "atomic-selection"
                && r.core_tactic == Some(li2core::engine::Tactic::Relocation))
    );
    assert!(
        product.reports()[..2]
            .iter()
            .all(|r| r.refusal_code == Some(9)
                && r.refusal.as_ref().unwrap().stage == "core"
                && r.core_tactic.is_none())
    );
    assert!(product.reports().iter().all(|r| !r.candidate_emitted));
    assert!(
        !product.files().contains_key("candidate.elf")
            && !product.files().contains_key("source.li2sparse")
    );
    let (original, mut selected) = short();
    selected.selection.carrier_pc = super::super::tests::UPSTREAM_BASE;
    let refused = prepare(&original, &selected);
    assert!(!refused.candidate_complete());
    assert_eq!(refused.reports().len(), 2);
    assert!(
        refused
            .reports()
            .iter()
            .all(|r| r.refusal_code == Some(10_002)
                && r.refusal.as_ref().unwrap().stage == "carrier"
                && r.core_tactic == Some(li2core::engine::Tactic::Relocation)
                && !r.candidate_emitted)
    );
    assert!(!refused.files().contains_key("candidate.elf"));
}
