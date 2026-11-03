//! Actual typed producer/codec/CLI boundaries; no candidate execution.
use super::*;
use liteinst_rewrite::{
    LedgerStorage,
    ledger_codec::{LedgerView, Limits, ReadContract},
    ledger_storage,
};

fn produce(
    source: &(Vec<u8>, Vec<u8>, Vec<u8>),
    mode: PopulationMode,
    storage: LedgerStorage,
) -> liteinst_rewrite::Product {
    prepare_population_inputs_with_storage(
        &source.0,
        &source.1,
        ContentId::of(&source.1),
        &source.2,
        ContentId::of(&source.2),
        (mode, storage),
        (&mut BTreeMap::new(), &mut None),
    )
    .unwrap()
}
fn selected(source: &(Vec<u8>, Vec<u8>, Vec<u8>)) -> disassembly::whole::JumpStackWholeSelection {
    disassembly::jump_stack::import(&source.0, &source.1, ContentId::of(&source.1))
        .unwrap()
        .bind_whole_program(&source.2, ContentId::of(&source.2))
        .unwrap()
}
fn view_limits(source: &[u8]) -> Limits {
    Limits::new(
        ReadContract {
            max_steps: 8192,
            max_reads_per_step: 1,
            max_read_bytes: source.len(),
        },
        128 * 1024 * 1024,
        0,
    )
    .unwrap()
}

#[test]
fn chunk_storage_selector_is_independent_and_legacy_parse_remains_exact() {
    let base: Vec<String> = [
        "producer",
        GROUPED_FLAG,
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
    let old = arguments_with_grouped_upstream(&base).unwrap();
    let ordinary = arguments_with_storage(&base).unwrap();
    assert_eq!((ordinary.0, ordinary.1), old);
    assert_eq!(ordinary.2, LedgerStorage::Inline);
    for flag in [GROUPED_FLAG, GROUPED_UPSTREAM_FLAG] {
        let mut args = base.clone();
        args[1] = flag.into();
        args.splice(
            1..1,
            ["--ledger-storage".into(), "read-chunks256-v1".into()],
        );
        assert_eq!(
            arguments_with_storage(&args).unwrap().2,
            LedgerStorage::ReadChunks256
        );
        let mut unknown = args.clone();
        unknown[2] = "read-chunks512-v1".into();
        assert!(arguments_with_storage(&unknown).is_err());
        let mut unsupported = args.clone();
        unsupported[3] = JUMP_STACK_FLAG.into();
        assert!(arguments_with_storage(&unsupported).is_err());
        let mut repeated = args.clone();
        repeated[4] = "--ledger-storage".into();
        assert!(arguments_with_storage(&repeated).is_err());
    }
    ledger_storage::require_inline_bootstrap(LedgerStorage::Inline).unwrap();
    assert_eq!(
        ledger_storage::require_inline_bootstrap(LedgerStorage::ReadChunks256)
            .unwrap_err()
            .stage,
        "ledger-storage"
    );
}

#[test]
fn chunk_storage_actual_group_preserves_inline_plans_images_outcomes_and_bindings() {
    let source = grouped_tests::storage_fixture();
    for mode in [
        PopulationMode::JumpStackGrouped,
        PopulationMode::JumpStackGroupedUpstream,
    ] {
        let inline = produce(&source, mode, LedgerStorage::Inline);
        let compact = produce(&source, mode, LedgerStorage::ReadChunks256);
        assert!(inline.candidate_complete() && compact.candidate_complete());
        assert_eq!(compact.reports().len(), 6);
        for name in [
            "selection.txt",
            "grouping-policy.tsv",
            "binding-policy.tsv",
            "metadata.li2meta",
            "report.tsv",
            "source.li2sparse",
            "image-0000.bin",
        ] {
            assert_eq!(compact.files()[name], inline.files()[name], "{name}");
        }
        let files = compact.files();
        let view = LedgerView::new(
            &files["plan-ledger.tsv"],
            &files["plan-ledger.tsv"],
            &files[ledger_storage::TABLE],
            view_limits(&source.0),
        )
        .unwrap();
        let mut expanded = Vec::new();
        let summary = view.write_inline(&mut expanded).unwrap();
        assert_eq!(expanded, inline.files()["plan-ledger.tsv"]);
        assert_eq!(summary.bytes, expanded.len());
        assert_eq!(summary.sha256, ContentId::of(&expanded));
        assert!(files["ledger.tsv"].starts_with(&files["plan-ledger.tsv"]));
        ledger_storage::verify_jump_stack(&source.0, &selected(&source), files).unwrap();
        assert!(!inline.files().contains_key(ledger_storage::TABLE));
        assert_ne!(files["candidate.elf"], inline.files()["candidate.elf"]);
        assert!(
            std::str::from_utf8(&files["bundle-index.tsv"])
                .unwrap()
                .contains("file\tread-chunks.tsv\t")
        );
    }
}

#[test]
fn chunk_storage_table_proof_and_physical_embedded_plan_mutations_refuse() {
    let source = grouped_tests::storage_fixture();
    let selected = selected(&source);
    let product = produce(
        &source,
        PopulationMode::JumpStackGrouped,
        LedgerStorage::ReadChunks256,
    );
    let mut bad = product.files().clone();
    bad.get_mut(ledger_storage::TABLE).unwrap()[0] = b'X';
    let error = ledger_storage::verify_jump_stack(&source.0, &selected, &bad).unwrap_err();
    assert_eq!(error.stage, "ledger-codec");
    assert!(error.detail.contains("table identity"));
    let mut bad = product.files().clone();
    bad.get_mut(ledger_storage::VERIFICATION)
        .unwrap()
        .push(b'x');
    assert!(
        ledger_storage::verify_jump_stack(&source.0, &selected, &bad)
            .unwrap_err()
            .detail
            .contains("verification/member mismatch")
    );
    let imported =
        disassembly::jump_stack::import(&source.0, &source.1, ContentId::of(&source.1)).unwrap();
    let geometry: Vec<_> = imported
        .sites()
        .iter()
        .map(|s| s.geometry().clone())
        .collect();
    let mut bad = product.files().clone();
    bad.get_mut("plan-ledger.tsv").unwrap().push(b'\n');
    let error = verify_grouped_metadata(&source.0, &geometry, selected.manifest(), &product, &bad)
        .unwrap_err();
    assert_eq!(error.stage, "grouped-cli-metadata");
    assert!(error.detail.contains("embedded metadata/plan identity"));
    let limits = view_limits(&source.0);
    assert!(
        limits
            .check_storage_lengths(64 * 1024 * 1024, 64 * 1024 * 1024, 1)
            .is_err()
    );
    assert_eq!(
        ledger_storage::legacy_record_width("entry-router-required", false),
        None
    );
    assert_eq!(
        ledger_storage::legacy_record_width("entry-router-required", true),
        Some(5)
    );
    assert_eq!(
        ledger_storage::legacy_record_width("LI2GROUPED-LEDGER", false),
        None
    );
    // Re-pin the plan/final prefix around a codec-valid ordinary row. Semantic
    // shape must refuse the extra fields, without collecting an input-sized Vec.
    let mut bad = product.files().clone();
    let mut plan = bad["plan-ledger.tsv"].clone();
    plan.extend_from_slice(format!("byte-lock\t0\t1{}\n", "\t0".repeat(32)).as_bytes());
    let tail = &product.files()["ledger.tsv"][product.files()["plan-ledger.tsv"].len()..];
    let mut final_ledger = plan.clone();
    final_ledger.extend_from_slice(tail);
    bad.insert("plan-ledger.tsv".into(), plan);
    bad.insert("ledger.tsv".into(), final_ledger);
    LedgerView::new(
        &bad["plan-ledger.tsv"],
        &bad["ledger.tsv"],
        &bad[ledger_storage::TABLE],
        limits,
    )
    .unwrap();
    let error = ledger_storage::verify_jump_stack(&source.0, &selected, &bad).unwrap_err();
    assert_eq!(error.stage, "ledger-storage");
    assert_eq!(error.detail, "unknown or malformed semantic record");
}

#[test]
fn chunk_storage_replays_evolving_reads_and_retains_atomic_refusals() {
    let source = grouped_tests::storage_fixture_chunks(&[
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x50],
        &[0xc3],
        &[0x2e, 0x2e, 0x2e, 0x2e, 0x58],
        &[0xc3],
    ]);
    let product = produce(
        &source,
        PopulationMode::JumpStackGrouped,
        LedgerStorage::ReadChunks256,
    );
    assert!(product.candidate_complete());
    let files = product.files();
    let mut rows: Vec<_> = std::str::from_utf8(&files["plan-ledger.tsv"])
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        rows.iter()
            .filter(|line| line.starts_with("step\t"))
            .count(),
        2
    );
    let write = rows
        .iter_mut()
        .find(|line| line.starts_with("semantic-write\t"))
        .unwrap();
    let mut fields: Vec<_> = write.split('\t').map(str::to_owned).collect();
    let old = fields[4].clone();
    fields[4].replace_range(..2, if old.starts_with("00") { "01" } else { "00" });
    assert_ne!(fields[4], old);
    *write = fields.join("\t");
    let changed = (rows.join("\n") + "\n").into_bytes();
    let mut bad = files.clone();
    let tail = &files["ledger.tsv"][files["plan-ledger.tsv"].len()..];
    let mut final_ledger = changed.clone();
    final_ledger.extend_from_slice(tail);
    bad.insert("plan-ledger.tsv".into(), changed);
    bad.insert("ledger.tsv".into(), final_ledger);
    // Table/ref hashes and complete prefix still agree. Only replay of step2
    // against step1's modified current bytes must refuse, before proof matching.
    LedgerView::new(
        &bad["plan-ledger.tsv"],
        &bad["ledger.tsv"],
        &bad[ledger_storage::TABLE],
        view_limits(&source.0),
    )
    .unwrap();
    assert_eq!(
        ledger_storage::verify_jump_stack(&source.0, &selected(&source), &bad)
            .unwrap_err()
            .stage,
        "ledger-current-read"
    );
    let short = grouped_tests::storage_fixture_chunks(&[&[0x50], &[0x58], &[0xc3]]);
    let inline = produce(
        &short,
        PopulationMode::JumpStackGrouped,
        LedgerStorage::Inline,
    );
    let compact = produce(
        &short,
        PopulationMode::JumpStackGrouped,
        LedgerStorage::ReadChunks256,
    );
    assert!(!compact.candidate_complete());
    assert_eq!(compact.reports().len(), 2);
    assert_eq!(compact.files()["report.tsv"], inline.files()["report.tsv"]);
    assert!(
        compact
            .reports()
            .iter()
            .all(|r| !r.candidate_emitted && r.refusal_code == Some(9))
    );
    assert!(!compact.files().contains_key("candidate.elf"));
    ledger_storage::verify_jump_stack(&short.0, &selected(&short), compact.files()).unwrap();
}
