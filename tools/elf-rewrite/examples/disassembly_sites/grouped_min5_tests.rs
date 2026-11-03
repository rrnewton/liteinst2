//! Actual typed min5 import/carrier and compatibility controls; no execution.
use super::grouped_tests::{upstream_fixture as fixture, upstream_run as run};
use super::*;

fn short() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    fixture(&[&[0x5b], &[0x5d], &[0x41, 0x5c], &[0xc3]])
}

#[test]
fn min5_cli_selector_is_explicit_and_keeps_legacy_and_storage_routes() {
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
        arguments_with_grouped_min5_upstream(&base),
        arguments_with_grouped_upstream(&base)
    );
    for flag in [JUMP_STACK_FLAG, GROUPED_FLAG, GROUPED_UPSTREAM_FLAG] {
        let mut old = base.clone();
        old.insert(1, flag.into());
        assert_eq!(
            arguments_with_grouped_min5_upstream(&old),
            arguments_with_grouped_upstream(&old)
        );
    }
    let mut args = base;
    args.insert(1, GROUPED_MIN5_UPSTREAM_FLAG.into());
    assert_eq!(
        arguments_with_grouped_min5_upstream(&args).unwrap(),
        (&args[2..], PopulationMode::JumpStackGroupedMin5Upstream)
    );
    assert_eq!(
        labels_with_population(PopulationMode::JumpStackGroupedMin5Upstream).0,
        liteinst_rewrite::GROUPED_MIN5_UPSTREAM_PROFILE
    );
    for flag in [
        GROUPED_MIN5_UPSTREAM_FLAG,
        GROUPED_UPSTREAM_FLAG,
        GROUPED_FLAG,
        "--input-profile",
        "--policy-profile",
        "--trusted-complete-code",
    ] {
        let mut wrong = args.clone();
        wrong[3] = flag.into();
        assert!(arguments_with_grouped_min5_upstream(&wrong).is_err());
    }
    assert!(arguments_with_grouped_min5_upstream(&args[..7]).is_err());
    let mut extra = args.clone();
    extra.push("extra".into());
    assert!(arguments_with_grouped_min5_upstream(&extra).is_err());
    for (name, storage) in [
        ("inline", liteinst_rewrite::LedgerStorage::Inline),
        (
            "read-chunks256-v1",
            liteinst_rewrite::LedgerStorage::ReadChunks256,
        ),
    ] {
        let mut stored = args.clone();
        stored.splice(1..1, ["--ledger-storage".into(), name.into()]);
        assert_eq!(
            arguments_with_storage(&stored).unwrap(),
            (
                &stored[4..],
                PopulationMode::JumpStackGroupedMin5Upstream,
                storage
            )
        );
        stored[4] = "--ledger-storage".into();
        assert!(arguments_with_storage(&stored).is_err());
    }
}

#[test]
fn min5_cli_keeps_complete_population_for_retained_ret_and_preflight_refusal() {
    let source = short();
    let (old, old_capture, old_counts) = run(&source, PopulationMode::JumpStackGroupedUpstream);
    let (product, capture, counts) = run(&source, PopulationMode::JumpStackGroupedMin5Upstream);
    assert!(!old.candidate_complete());
    assert!(
        old.reports()
            .iter()
            .all(|r| r.refusal_code == Some(9) && !r.candidate_emitted)
    );
    assert!(product.candidate_complete(), "{:?}", product.reports());
    assert!(!product.qualification_complete());
    assert_eq!(counts, Some([0, 0, 3]));
    assert_eq!(old_counts, counts);
    assert_eq!(old_capture, capture);
    assert_eq!(product.reports().len(), 3);
    assert!(
        product
            .reports()
            .iter()
            .all(|r| r.candidate_emitted && r.refusal.is_none())
    );
    assert_eq!(
        product.files()["selection.txt"],
        old.files()["selection.txt"]
    );
    assert_eq!(
        product.files()["disassembly-inventory.tsv"],
        old.files()["disassembly-inventory.tsv"]
    );
    let metadata = liteinst_rewrite::grouped_min5_upstream_fixed_exec_metadata();
    assert!(metadata.contains("planner_profile\tjumps-gpr-stack64-block-min5-upstream-v1\n"));
    assert!(
        metadata
            .contains("grouping_policy_version\t2\nwindow_sealing\tminimum-whole-instruction-v1\n")
    );
    assert_eq!(
        jump_stack_fields(counts),
        "selection_profile\tjumps-gpr-stack64-v1\ncomplete_site_count\t3\njump_count\t0\npush_r64_count\t0\npop_r64_count\t3\n"
    );
    let mut compact_capture = BTreeMap::new();
    let mut compact_counts = None;
    let compact = prepare_population_inputs_with_storage(
        &source.0,
        &source.1,
        ContentId::of(&source.1),
        &source.2,
        ContentId::of(&source.2),
        (
            PopulationMode::JumpStackGroupedMin5Upstream,
            liteinst_rewrite::LedgerStorage::ReadChunks256,
        ),
        (&mut compact_capture, &mut compact_counts),
    )
    .unwrap();
    assert!(compact.candidate_complete());
    assert_eq!(compact_counts, counts);
    assert_eq!(compact_capture, capture);
    assert_eq!(
        compact.files()["grouping-policy.tsv"],
        product.files()["grouping-policy.tsv"]
    );
    assert_eq!(compact.files()["report.tsv"], product.files()["report.tsv"]);
    assert!(compact.files().contains_key("ledger-verification.tsv"));
    let blocked = fixture(&[&[0x5b], &[0x5d], &[0xc3]]);
    let (refused, capture, counts) = run(&blocked, PopulationMode::JumpStackGroupedMin5Upstream);
    assert!(!refused.candidate_complete());
    assert_eq!(counts, Some([0, 0, 2]));
    assert_eq!(refused.reports().len(), 2);
    assert!(refused.reports().iter().all(|r| r.refusal_code == Some(9)
        && r.refusal.as_ref().unwrap().stage == "core"
        && r.core_tactic.is_none()
        && !r.candidate_emitted));
    assert!(
        std::str::from_utf8(&refused.files()["grouping-policy.tsv"])
            .unwrap()
            .contains("window-seal\t0\trefused\t-\t9\tcore\t")
    );
    assert_eq!(
        refused.files()["disassembly-inventory.tsv"],
        capture["disassembly-inventory.tsv"]
    );
    assert!(!refused.files().contains_key("candidate.elf"));
}

#[test]
fn min5_cli_binding_rejects_old_profile_replay_and_mutated_policy_or_carrier() {
    let source = short();
    let (product, _, _) = run(&source, PopulationMode::JumpStackGroupedMin5Upstream);
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
    let verify = |product: &liteinst_rewrite::Product, files: &BTreeMap<String, Vec<u8>>| {
        verify_grouped_metadata_with_binding(
            &source.0,
            &geometry,
            selected.manifest(),
            product,
            files,
            liteinst_rewrite::grouped_min5_upstream_fixed_exec_binding_policy,
        )
    };
    verify(&product, product.files()).unwrap();
    for upstream in [false, true] {
        assert_eq!(
            verify_grouped_metadata_for_profile(
                &source.0,
                &geometry,
                selected.manifest(),
                &product,
                product.files(),
                upstream
            )
            .unwrap_err()
            .stage,
            "grouped-cli-metadata"
        );
        let (old, _, _) = run(
            &source,
            if upstream {
                PopulationMode::JumpStackGroupedUpstream
            } else {
                PopulationMode::JumpStackGrouped
            },
        );
        verify_grouped_metadata_for_profile(
            &source.0,
            &geometry,
            selected.manifest(),
            &old,
            old.files(),
            upstream,
        )
        .unwrap();
        assert_eq!(
            verify(&old, old.files()).unwrap_err().stage,
            "grouped-cli-metadata"
        );
    }
    for name in [
        "grouping-policy.tsv",
        "binding-policy.tsv",
        "metadata.li2meta",
        "plan-ledger.tsv",
    ] {
        let mut files = product.files().clone();
        files.get_mut(name).unwrap().push(b'!');
        assert_eq!(
            verify(&product, &files).unwrap_err().stage,
            "grouped-cli-metadata",
            "{name}"
        );
    }
    let mut files = product.files().clone();
    let candidate = files.get_mut("candidate.elf").unwrap();
    let marker = b"LI2TOOL-CANDIDATE-UNREADY-V1\0";
    let at = candidate
        .windows(marker.len())
        .rposition(|bytes| bytes == marker)
        .unwrap()
        + marker.len();
    candidate[at] ^= 1;
    let error = verify(&product, &files).unwrap_err();
    assert_eq!(error.stage, "grouped-cli-metadata");
    assert_eq!(error.detail, "embedded metadata/plan identity");
}
