//! Source-only additive controls for the explicit upstream profile.
use super::grouped_tests::{upstream_fixture as fixture, upstream_run as run};
use super::*;

fn short() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    fixture(&[&[0x0f, 0x1f, 0x44, 0, 0], &[0x5b], &[0x5d], &[0xc3]])
}
#[test]
fn upstream_cli_selector_is_distinct_and_legacy_arguments_are_literal() {
    let base: Vec<String> = [
        "producer",
        "original",
        "ledger",
        "ledger-sha",
        "policy",
        "policy-sha",
        "out",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(
        arguments_with_grouped_upstream(&base),
        arguments_with_jump_stack(&base)
    );
    for old in [JUMP_STACK_FLAG, GROUPED_FLAG] {
        let mut args = base.clone();
        args.insert(1, old.into());
        assert_eq!(
            arguments_with_grouped_upstream(&args),
            arguments_with_jump_stack(&args)
        );
    }
    let mut args = base.clone();
    args.insert(1, GROUPED_UPSTREAM_FLAG.into());
    assert_eq!(
        arguments_with_grouped_upstream(&args).unwrap(),
        (&args[2..], PopulationMode::JumpStackGroupedUpstream)
    );
    assert_eq!(
        labels_with_population(PopulationMode::JumpStackGroupedUpstream).0,
        liteinst_rewrite::GROUPED_UPSTREAM_PROFILE
    );
    for index in 2..8 {
        let mut wrong = args.clone();
        wrong[index] = GROUPED_FLAG.into();
        assert!(arguments_with_grouped_upstream(&wrong).is_err());
    }
    assert!(arguments_with_grouped_upstream(&args[..7]).is_err());
    args.push("extra".into());
    assert!(arguments_with_grouped_upstream(&args).is_err());
}
#[test]
fn upstream_cli_short_group_uses_full_union_and_keeps_block_refusal() {
    let source = short();
    let (exact, old_capture, old_counts) = run(&source, PopulationMode::JumpStackGrouped);
    let (upstream, capture, counts) = run(&source, PopulationMode::JumpStackGroupedUpstream);
    assert!(!exact.candidate_complete());
    assert!(exact.reports().iter().all(|r| r.refusal_code == Some(9)));
    assert!(upstream.candidate_complete(), "{:?}", upstream.reports());
    assert_eq!(counts, Some([0, 0, 2]));
    assert_eq!(old_counts, counts);
    assert_eq!(old_capture, capture);
    assert_eq!(upstream.reports().len(), 2);
    assert!(
        upstream
            .reports()
            .iter()
            .all(|r| r.candidate_emitted && r.refusal.is_none())
    );
    assert_eq!(
        exact.files()["selection.txt"],
        upstream.files()["selection.txt"]
    );
    assert_eq!(
        exact.files()["disassembly-inventory.tsv"],
        upstream.files()["disassembly-inventory.tsv"]
    );
    // No earlier head in this declared block: the new profile cannot invent one.
    let blocked = fixture(&[&[0x5b], &[0x5d], &[0xc3]]);
    let (refused, _, counts) = run(&blocked, PopulationMode::JumpStackGroupedUpstream);
    assert_eq!(counts, Some([0, 0, 2]));
    assert_eq!(refused.reports().len(), 2);
    assert!(!refused.candidate_complete());
    assert!(
        refused
            .reports()
            .iter()
            .all(|r| !r.candidate_emitted && r.refusal_code == Some(9))
    );
    assert!(!refused.files().contains_key("candidate.elf"));
}
#[test]
fn upstream_cli_metadata_requires_new_policy_identity_and_exact_product() {
    let source = short();
    let (product, _, _) = run(&source, PopulationMode::JumpStackGroupedUpstream);
    assert!(product.candidate_complete());
    let imported =
        disassembly::jump_stack::import(&source.0, &source.1, ContentId::of(&source.1)).unwrap();
    let geometry: Vec<_> = imported
        .sites()
        .iter()
        .map(|s| s.geometry().clone())
        .collect();
    let selected = imported
        .bind_whole_program(&source.2, ContentId::of(&source.2))
        .unwrap();
    verify_grouped_metadata_for_profile(
        &source.0,
        &geometry,
        selected.manifest(),
        &product,
        product.files(),
        true,
    )
    .unwrap();
    assert_eq!(
        verify_grouped_metadata(
            &source.0,
            &geometry,
            selected.manifest(),
            &product,
            product.files()
        )
        .unwrap_err()
        .stage,
        "grouped-cli-metadata"
    );
    for name in [
        "grouping-policy.tsv",
        "binding-policy.tsv",
        "metadata.li2meta",
        "plan-ledger.tsv",
    ] {
        let mut files = product.files().clone();
        let before = files[name].clone();
        files.get_mut(name).unwrap().push(b'!');
        assert_ne!(files[name], before);
        assert_eq!(
            verify_grouped_metadata_for_profile(
                &source.0,
                &geometry,
                selected.manifest(),
                &product,
                &files,
                true
            )
            .unwrap_err()
            .stage,
            "grouped-cli-metadata"
        );
    }
    let (exact, _, _) = run(&source, PopulationMode::JumpStackGrouped);
    verify_grouped_metadata(
        &source.0,
        &geometry,
        selected.manifest(),
        &exact,
        exact.files(),
    )
    .unwrap();
    assert_eq!(
        verify_grouped_metadata_for_profile(
            &source.0,
            &geometry,
            selected.manifest(),
            &exact,
            exact.files(),
            true
        )
        .unwrap_err()
        .stage,
        "grouped-cli-metadata"
    );
}
