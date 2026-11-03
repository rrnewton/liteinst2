//! Actual typed alphabet selector, full inventory and metadata compatibility.
use super::grouped_tests::{upstream_fixture as fixture, upstream_run as run};
use super::*;

fn short() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    fixture(&[&[0x5b], &[0x5d], &[0x41, 0x5c], &[0xc3]])
}

#[test]
fn alphabet_cli_selector_is_distinct_and_preserves_old_routes_and_storage() {
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
        arguments_with_grouped_min5_alphabet_upstream(&base),
        arguments_with_grouped_min5_upstream(&base)
    );
    for flag in [
        JUMP_STACK_FLAG,
        GROUPED_FLAG,
        GROUPED_UPSTREAM_FLAG,
        GROUPED_MIN5_UPSTREAM_FLAG,
    ] {
        let mut args = base.clone();
        args.insert(1, flag.into());
        assert_eq!(
            arguments_with_grouped_min5_alphabet_upstream(&args),
            arguments_with_grouped_min5_upstream(&args)
        );
    }
    let mut args = base;
    args.insert(1, GROUPED_MIN5_ALPHABET_UPSTREAM_FLAG.into());
    assert_eq!(
        arguments_with_grouped_min5_alphabet_upstream(&args).unwrap(),
        (
            &args[2..],
            PopulationMode::JumpStackGroupedMin5AlphabetUpstream
        )
    );
    assert_eq!(
        labels_with_population(PopulationMode::JumpStackGroupedMin5AlphabetUpstream).0,
        liteinst_rewrite::GROUPED_MIN5_ALPHABET_UPSTREAM_PROFILE
    );
    for flag in [
        GROUPED_MIN5_ALPHABET_UPSTREAM_FLAG,
        GROUPED_MIN5_UPSTREAM_FLAG,
        GROUPED_UPSTREAM_FLAG,
        GROUPED_FLAG,
        "--input-profile",
        "--policy-profile",
        "--trusted-complete-code",
    ] {
        let mut wrong = args.clone();
        wrong[3] = flag.into();
        assert!(arguments_with_grouped_min5_alphabet_upstream(&wrong).is_err());
    }
    assert!(arguments_with_grouped_min5_alphabet_upstream(&args[..7]).is_err());
    let mut extra = args.clone();
    extra.push("extra".into());
    assert!(arguments_with_grouped_min5_alphabet_upstream(&extra).is_err());
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
                PopulationMode::JumpStackGroupedMin5AlphabetUpstream,
                storage
            )
        );
        stored[4] = "--ledger-storage".into();
        assert!(arguments_with_storage(&stored).is_err());
    }
}

#[test]
fn alphabet_cli_keeps_complete_union_and_whole_unit_refusals_in_both_storage_modes() {
    let source = short();
    let (old, old_capture, old_counts) = run(&source, PopulationMode::JumpStackGroupedMin5Upstream);
    let (product, capture, counts) = run(
        &source,
        PopulationMode::JumpStackGroupedMin5AlphabetUpstream,
    );
    assert!(old.candidate_complete() && product.candidate_complete());
    assert!(!product.qualification_complete());
    assert_eq!(counts, Some([0, 0, 3]));
    assert_eq!(counts, old_counts);
    assert_eq!(capture, old_capture);
    assert_eq!(product.reports().len(), 3);
    assert!(
        product
            .reports()
            .iter()
            .all(|r| r.candidate_emitted && r.refusal.is_none())
    );
    for name in [
        "selection.txt",
        "disassembly-policy.txt",
        "disassembly-inventory.tsv",
    ] {
        assert_eq!(product.files()[name], old.files()[name]);
    }
    let metadata = liteinst_rewrite::grouped_min5_alphabet_upstream_fixed_exec_metadata();
    assert!(
        metadata
            .contains("grouping_policy_version\t3\nwindow_sealing\tminimum-whole-instruction-v1\n")
    );
    assert!(metadata.contains("group_relocation_placement\tentry-alphabet-v1\n"));
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
            PopulationMode::JumpStackGroupedMin5AlphabetUpstream,
            liteinst_rewrite::LedgerStorage::ReadChunks256,
        ),
        (&mut compact_capture, &mut compact_counts),
    )
    .unwrap();
    assert!(compact.candidate_complete());
    assert_eq!(compact_capture, capture);
    assert_eq!(compact_counts, counts);
    for name in [
        "grouping-policy.tsv",
        "binding-policy.tsv",
        "report.tsv",
        "source.li2sparse",
        "image-0000.bin",
    ] {
        assert_eq!(compact.files()[name], product.files()[name]);
    }
    assert!(compact.files().contains_key("ledger-verification.tsv"));
    let blocked = fixture(&[&[0x5b], &[0x5d], &[0xc3]]);
    let (refused, _, counts) = run(
        &blocked,
        PopulationMode::JumpStackGroupedMin5AlphabetUpstream,
    );
    assert_eq!(counts, Some([0, 0, 2]));
    assert_eq!(refused.reports().len(), 2);
    assert!(!refused.candidate_complete());
    assert!(refused.reports().iter().all(|r| r.refusal_code == Some(9)
        && r.refusal.as_ref().unwrap().stage == "core"
        && r.core_tactic.is_none()
        && !r.candidate_emitted));
    assert!(!refused.files().contains_key("candidate.elf"));
    assert!(
        std::str::from_utf8(&refused.files()["grouping-policy.tsv"])
            .unwrap()
            .contains("window-seal\t0\trefused\t-\t9\tcore\t")
    );
}

#[test]
fn alphabet_cli_rejects_old_profile_and_repinned_placement_or_embedded_metadata() {
    let source = short();
    let (product, _, _) = run(
        &source,
        PopulationMode::JumpStackGroupedMin5AlphabetUpstream,
    );
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
            liteinst_rewrite::grouped_min5_alphabet_upstream_fixed_exec_binding_policy,
        )
    };
    verify(&product, product.files()).unwrap();
    let (old, _, _) = run(&source, PopulationMode::JumpStackGroupedMin5Upstream);
    verify_grouped_metadata_with_binding(
        &source.0,
        &geometry,
        selected.manifest(),
        &old,
        old.files(),
        liteinst_rewrite::grouped_min5_upstream_fixed_exec_binding_policy,
    )
    .unwrap();
    assert_eq!(
        verify(&old, old.files()).unwrap_err().stage,
        "grouped-cli-metadata"
    );
    assert_eq!(
        verify_grouped_metadata_with_binding(
            &source.0,
            &geometry,
            selected.manifest(),
            &product,
            product.files(),
            liteinst_rewrite::grouped_min5_upstream_fixed_exec_binding_policy
        )
        .unwrap_err()
        .stage,
        "grouped-cli-metadata"
    );
    // Recompute the outer policy binding: the portable compatibility must still
    // reject the altered mode, even though these two text members now agree.
    let mut files = product.files().clone();
    let changed = std::str::from_utf8(&files["grouping-policy.tsv"])
        .unwrap()
        .replace(
            "group_relocation_placement\tentry-alphabet-v1\n",
            "group_relocation_placement\tfixed06\n",
        )
        .into_bytes();
    assert_ne!(changed, files["grouping-policy.tsv"]);
    files.insert("grouping-policy.tsv".into(), changed);
    let binding = liteinst_rewrite::grouped_min5_alphabet_upstream_fixed_exec_binding_policy(
        product.fixed_image_binding().unwrap(),
        ContentId::of(selected.manifest()),
        ContentId::of(&files["grouping-policy.tsv"]),
    );
    files.insert("binding-policy.tsv".into(), binding);
    let error = verify(&product, &files).unwrap_err();
    assert_eq!(error.stage, "grouped-cli-metadata");
    assert_eq!(error.detail, "portable compatibility or metadata integrity");
    for name in ["metadata.li2meta", "plan-ledger.tsv"] {
        let mut files = product.files().clone();
        files.get_mut(name).unwrap().push(b'!');
        assert_eq!(
            verify(&product, &files).unwrap_err().stage,
            "grouped-cli-metadata"
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
