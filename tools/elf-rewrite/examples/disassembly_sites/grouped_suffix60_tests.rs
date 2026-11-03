//! The explicit group suffix mode reuses the old selector and binding checks.
use super::grouped_tests::{upstream_fixture as fixture, upstream_run as run};
use super::*;

#[test]
fn suffix60_cli_has_an_exact_separate_selector_and_storage_arity() {
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
    for flag in [
        None,
        Some(JUMP_STACK_FLAG),
        Some(GROUPED_FLAG),
        Some(GROUPED_UPSTREAM_FLAG),
        Some(GROUPED_MIN5_UPSTREAM_FLAG),
        Some(GROUPED_MIN5_ALPHABET_UPSTREAM_FLAG),
        Some(GROUPED_PHYSICAL_MIN5_ALPHABET_UPSTREAM_FLAG),
    ] {
        let mut args = base.clone();
        if let Some(flag) = flag {
            args.insert(1, flag.into());
        }
        assert_eq!(
            arguments_with_grouped_physical_min5_alphabet_suffix60_upstream(&args),
            arguments_with_grouped_physical_min5_alphabet_upstream(&args)
        );
    }
    let mut args = base;
    args.insert(
        1,
        GROUPED_PHYSICAL_MIN5_ALPHABET_SUFFIX60_UPSTREAM_FLAG.into(),
    );
    assert_eq!(
        arguments_with_storage(&args).unwrap().1,
        PopulationMode::JumpStackGroupedPhysicalMin5AlphabetSuffix60Upstream
    );
    for flag in [
        GROUPED_PHYSICAL_MIN5_ALPHABET_SUFFIX60_UPSTREAM_FLAG,
        GROUPED_PHYSICAL_MIN5_ALPHABET_UPSTREAM_FLAG,
        GROUPED_MIN5_ALPHABET_UPSTREAM_FLAG,
        "--input-profile",
        "--trusted-complete-code",
    ] {
        let mut wrong = args.clone();
        wrong[3] = flag.into();
        assert!(arguments_with_storage(&wrong).is_err());
    }
    assert!(arguments_with_storage(&args[..7]).is_err());
    let mut extra = args.clone();
    extra.push("extra".into());
    assert!(arguments_with_storage(&extra).is_err());
    for (name, storage) in [
        ("inline", liteinst_rewrite::LedgerStorage::Inline),
        (
            "read-chunks256-v1",
            liteinst_rewrite::LedgerStorage::ReadChunks256,
        ),
    ] {
        let mut args = args.clone();
        args.splice(1..1, ["--ledger-storage".into(), name.into()]);
        assert_eq!(
            arguments_with_storage(&args).unwrap(),
            (
                &args[4..],
                PopulationMode::JumpStackGroupedPhysicalMin5AlphabetSuffix60Upstream,
                storage
            )
        );
    }
    let (profile, family, stdout) = labels_with_population(
        PopulationMode::JumpStackGroupedPhysicalMin5AlphabetSuffix60Upstream,
    );
    assert_eq!(
        profile,
        liteinst_rewrite::GROUPED_PHYSICAL_MIN5_ALPHABET_SUFFIX60_UPSTREAM_PROFILE
    );
    assert_eq!(family, "");
    assert!(stdout.contains(" group_routed_suffix=single-byte60-v1 "));
    assert!(
        !labels_with_population(PopulationMode::JumpStackGroupedPhysicalMin5AlphabetUpstream)
            .2
            .contains("group_routed_suffix")
    );
}

#[test]
fn suffix60_cli_authenticates_new_mode_in_portable_and_embedded_metadata() {
    let source = fixture(&[&[0x66, 0x90], &[0x5b], &[0x5d], &[0xc3]]);
    let (product, capture, counts) = run(
        &source,
        PopulationMode::JumpStackGroupedPhysicalMin5AlphabetSuffix60Upstream,
    );
    let (old, old_capture, old_counts) = run(
        &source,
        PopulationMode::JumpStackGroupedPhysicalMin5AlphabetUpstream,
    );
    assert!(product.candidate_complete() && old.candidate_complete());
    assert_eq!(counts, Some([0, 0, 2]));
    assert_eq!(counts, old_counts);
    assert_eq!(capture, old_capture);
    assert_eq!(product.reports().len(), 2);
    assert!(!product.qualification_complete());
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
    let verify = |files: &BTreeMap<String, Vec<u8>>| {
        verify_grouped_metadata_with_binding(
        &source.0, &geometry, selected.manifest(), &product, files,
        liteinst_rewrite::grouped_physical_min5_alphabet_suffix60_upstream_fixed_exec_binding_policy,
    )
    };
    verify(product.files()).unwrap();
    assert!(
        verify_grouped_metadata_with_binding(
            &source.0,
            &geometry,
            selected.manifest(),
            &product,
            product.files(),
            liteinst_rewrite::grouped_physical_min5_alphabet_upstream_fixed_exec_binding_policy
        )
        .is_err()
    );
    let mut stale = product.files().clone();
    stale.insert(
        "binding-policy.tsv".into(),
        old.files()["binding-policy.tsv"].clone(),
    );
    assert_eq!(verify(&stale).unwrap_err().stage, "grouped-cli-metadata");
    for changed in [
        b"group_routed_suffix\tqualified62-v1\n".as_slice(),
        b"".as_slice(),
    ] {
        let mut files = product.files().clone();
        let policy = std::str::from_utf8(&files["grouping-policy.tsv"])
            .unwrap()
            .replace(
                "group_routed_suffix\tsingle-byte60-v1\n",
                std::str::from_utf8(changed).unwrap(),
            )
            .into_bytes();
        files.insert("grouping-policy.tsv".into(), policy);
        files.insert("binding-policy.tsv".into(),
            liteinst_rewrite::grouped_physical_min5_alphabet_suffix60_upstream_fixed_exec_binding_policy(
                product.fixed_image_binding().unwrap(), ContentId::of(selected.manifest()),
                ContentId::of(&files["grouping-policy.tsv"])));
        assert_eq!(verify(&files).unwrap_err().stage, "grouped-cli-metadata");
    }
    for name in ["plan-ledger.tsv", "metadata.li2meta"] {
        let mut files = product.files().clone();
        files.get_mut(name).unwrap().push(b'!');
        assert_eq!(verify(&files).unwrap_err().stage, "grouped-cli-metadata");
    }
}
