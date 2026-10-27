//! Prospective pure integration checks. No emitted image is executed here.
use formats::{Compatibility, ContentId, Metadata, Outcome};
use li2core::contracts::CONTRACT_VERSION;
use liteinst_rewrite::{prepare, selection};

const BASE: u64 = 0x400000;
const S: u64 = BASE + 0x1100;
const HOOK: u64 = BASE + 0x1800;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Original engine contract byte geometries; filler after RET has no declared
/// external entry. This fixture does not claim all decoded filler heads legal.
fn input(kind: u16, tactic: &str) -> (Vec<u8>, String) {
    let (mut body, block, heads) = match tactic {
        "B1" => (vec![0xb8, 42, 0, 0, 0, 0xc3], 6, vec![0, 5]),
        "B2" => (
            vec![0x0f, 0x1f, 0, 0xb8, 42, 0, 0, 0, 0xc3],
            9,
            vec![0, 3, 8],
        ),
        "T1" => (vec![0x89, 0xc0, 0xb8, 42, 0, 0, 0, 0xc3], 8, vec![0, 2, 7]),
        "T2" => (
            vec![
                0x0f, 0x1f, 0, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0xb8, 42, 0, 0, 0, 0xc3,
            ],
            17,
            vec![0, 3, 11, 16, 64, 74],
        ),
        "T3" => (vec![0x75, 1, 0x90, 0xc3], 2, vec![0, 2, 3, 64, 74]),
        _ => panic!("unknown prospective tactic"),
    };
    if matches!(tactic, "T2" | "T3") {
        body.resize(64, 0x90);
        body.extend_from_slice(&[0x48, 0xb8]);
        body.extend_from_slice(&42_u64.to_le_bytes());
        body.push(0xc3);
    }
    let mut bytes = vec![0; 8192];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut bytes, 16, kind);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, if kind == 2 { S } else { 0 });
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 2);
    for (i, (offset, flags)) in [(0, 4), (4096, 5)].into_iter().enumerate() {
        let at = 64 + i * 56;
        put32(&mut bytes, at, 1);
        put32(&mut bytes, at + 4, flags);
        put64(&mut bytes, at + 8, offset);
        put64(&mut bytes, at + 16, BASE + offset);
        put64(&mut bytes, at + 24, BASE + offset);
        put64(&mut bytes, at + 32, 4096);
        put64(&mut bytes, at + 40, 4096);
        put64(&mut bytes, at + 48, 4096);
    }
    bytes[0x10f0..0x1100].fill(0x90);
    bytes[0x1100..0x1100 + body.len()].copy_from_slice(&body);
    bytes[0x1800] = 0xc3;
    let selected = match tactic {
        "B1" | "T3" => S + 0x4000000,
        "B2" => S + 5 + 0x2ab80000 + 0x8000,
        "T1" => S + 6 + 0x2ab8,
        "T2" => S + 5 + 0x56e90000 + 0x8000,
        _ => unreachable!(),
    };
    let victim = if tactic == "T2" {
        S + 8 + 0x00123456
    } else {
        S + 0x6000000
    };
    let len = match tactic {
        "B1" => 5,
        "B2" | "T2" => 3,
        _ => 2,
    };
    let heads = heads
        .iter()
        .map(|h| format!("{}:0", S + h))
        .collect::<Vec<_>>()
        .join(" ");
    let manifest = format!(
        "LI2TOOL 1\noriginal {}\ntarget fxsave64\ndomain 1\ncarrier {}\nlimits 1048576 16 16 65536 64 1048576 262144 64 4294967296\nhook 7 {HOOK} 1 {}\nsite 1 {S} {len} 4352 {} {} {S} {} {S} {block} 7 observe original-decode\nentries 1 complete {} {heads}\nresumes 1 none\nsearch 1 {tactic} 0 80 1 {} 64 256\nallocation 1 selected {selected} 256 8192 {}:8192\nallocation 1 victim {victim} 256 8192 {}:8192\n",
        hex(&ContentId::of(&bytes).0),
        BASE + 0x8000,
        hex(&ContentId::of(&[0xc3]).0),
        S - 16,
        body.len() + 16,
        body.len(),
        hex(&ContentId::of(b"declared original engine puzzle; no external filler entries").0),
        S + 64,
        selected & !4095,
        victim & !4095
    );
    (bytes, manifest)
}
fn metadata(product: &liteinst_rewrite::Product, manifest: &str) -> Metadata {
    let files = product.files();
    let policy = Compatibility {
        planner: CONTRACT_VERSION,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&files["target.tsv"]),
        binding: ContentId::of(manifest.as_bytes()),
    };
    Metadata::decode(
        &files["metadata.li2meta"],
        &policy,
        formats::Limits::default(),
    )
    .unwrap()
}

#[test]
fn every_forced_tactic_builds_both_exec_and_dyn_candidate_via_one_core() {
    let mut total = 0;
    for kind in [2, 3] {
        for tactic in ["B1", "B2", "T1", "T2", "T3"] {
            let (original, manifest) = input(kind, tactic);
            let before = original.clone();
            let result = prepare(&original, manifest.as_bytes()).unwrap();
            assert!(
                result.candidate_complete(),
                "{kind}/{tactic}: {:?}",
                result.reports()
            );
            assert!(!result.qualification_complete());
            assert_eq!(original, before);
            let report = &result.reports()[0];
            assert!(report.candidate_emitted && report.refusal.is_none());
            assert_eq!(
                format!("{:?}", report.core_tactic.unwrap()),
                match tactic {
                    "B1" => "Relocation",
                    "B2" => "GeneralizedPun",
                    "T1" => "PrefixedPun",
                    "T2" => "SuccessorEviction",
                    "T3" => "NeighborEviction",
                    _ => unreachable!(),
                }
            );
            let expected = if matches!(tactic, "T2" | "T3") { 2 } else { 1 };
            assert_eq!(
                result
                    .files()
                    .keys()
                    .filter(|n| n.starts_with("image-"))
                    .count(),
                expected
            );
            let out = &result.files()["candidate.elf"];
            assert_eq!(&out[16..18], &kind.to_le_bytes());
            assert_eq!(&out[24..32], &original[24..32]);
            let elf =
                liteinst_rewrite::carrier::elf64::Elf64::parse(out, Default::default()).unwrap();
            let ledger = std::str::from_utf8(&result.files()["ledger.tsv"]).unwrap();
            for row in ledger.lines().filter(|r| r.starts_with("elf-image\t")) {
                let f: Vec<_> = row.split('\t').collect();
                let id: usize = f[1].parse().unwrap();
                let pc: u64 = f[2].parse().unwrap();
                let len: u64 = f[4].parse().unwrap();
                assert_eq!(
                    elf.executable_bytes(liteinst_rewrite::carrier::elf64::ElfVaddr(pc), len)
                        .unwrap(),
                    result.files()[&format!("image-{id:04}.bin")]
                );
            }
            assert!(ledger.contains("unmet-requirement\t0\t2\t0"));
            assert!(ledger.contains("unmet-requirement\t0\t7\t0"));
            assert_eq!(metadata(&result, &manifest).sites().len(), 1);
            total += 1;
        }
    }
    assert_eq!(total, 10);
}

#[test]
fn sparse_bytes_are_exact_original_relative_changes_and_requirements_persist() {
    let (original, manifest) = input(2, "B1");
    let product = prepare(&original, manifest.as_bytes()).unwrap();
    assert!(product.candidate_complete());
    let sparse = formats::sparse_wire::decode(
        &product.files()["source.li2sparse"],
        &original,
        formats::sparse_wire::Limits {
            bytes: 1048576,
            content: formats::sparse::Limits {
                edits: 1048576,
                edited_bytes: 1048576,
                pages: 256,
            },
        },
    )
    .unwrap();
    let candidate = &product.files()["candidate.elf"];
    for edit in sparse.edits() {
        let start = edit.offset as usize;
        assert_eq!(&original[start..start + edit.expected.len()], edit.expected);
        assert_eq!(
            &candidate[start..start + edit.replacement.len()],
            edit.replacement
        );
    }
    for page in sparse.pages() {
        let start = page.offset as usize;
        assert_eq!(page.bytes, candidate[start..start + page.bytes.len()]);
    }
    let meta = metadata(&product, &manifest);
    meta.verify_original(&original).unwrap();
    meta.verify_selection(ContentId::of(manifest.as_bytes()), &[1])
        .unwrap();
    assert!(matches!(meta.sites()[0].outcome, Outcome::Rewritten(_)));
    for name in ["report.tsv", "ledger.tsv", "target.tsv", "bundle-index.tsv"] {
        assert!(
            std::str::from_utf8(&product.files()[name])
                .unwrap()
                .contains("qualification_complete\tfalse")
        );
    }
}

#[test]
fn original_digest_and_hook_digest_are_both_mandatory() {
    let (mut original, manifest) = input(2, "B1");
    original[0x1800] ^= 1;
    assert_eq!(
        prepare(&original, manifest.as_bytes()).unwrap_err().stage,
        "original-identity"
    );
    let old = selection::parse(manifest.as_bytes()).unwrap().original;
    let manifest = manifest.replace(&hex(&old.0), &hex(&ContentId::of(&original).0));
    assert_eq!(
        prepare(&original, manifest.as_bytes()).unwrap_err().stage,
        "hook-identity"
    );
}

#[test]
fn unknown_entries_refuse_without_a_partial_candidate() {
    let (original, manifest) = input(2, "B1");
    let manifest = manifest.replace("entries 1 complete", "entries 1 unknown");
    let product = prepare(&original, manifest.as_bytes()).unwrap();
    assert!(!product.candidate_complete());
    assert_eq!(product.reports()[0].refusal_code, Some(7));
    assert!(!product.files().contains_key("candidate.elf"));
    assert!(!product.files().contains_key("source.li2sparse"));
    assert!(matches!(
        metadata(&product, &manifest).sites()[0].outcome,
        Outcome::Refused(7)
    ));
}

#[test]
fn forced_b1_refusal_never_substitutes_neighbor() {
    let (original, manifest) = input(2, "T3");
    let manifest = manifest.replace("search 1 T3", "search 1 B1");
    let product = prepare(&original, manifest.as_bytes()).unwrap();
    assert!(!product.candidate_complete());
    assert_eq!(product.reports()[0].refusal_code, Some(9));
    assert!(product.reports()[0].core_tactic.is_none());
}

#[test]
fn carrier_budget_failure_retains_successful_leaf_and_exact_selection_outcome() {
    let (original, manifest) = input(2, "B1");
    let manifest = manifest.replace("65536 64 1048576 262144", "65536 64 1048576 0");
    let product = prepare(&original, manifest.as_bytes()).unwrap();
    assert!(!product.candidate_complete());
    assert_eq!(
        product.reports()[0].refusal.as_ref().unwrap().stage,
        "carrier"
    );
    assert!(product.reports()[0].core_tactic.is_some());
    assert_eq!(product.reports()[0].refusal_code, Some(10002));
    assert!(!product.files().contains_key("candidate.elf"));
    assert!(!product.files().contains_key("source.li2sparse"));
}

#[test]
fn prospective_image_limit_does_not_relabel_compound_tactic() {
    let (original, manifest) = input(2, "T3");
    let manifest = manifest.replace("1048576 16 16 65536", "1048576 16 1 65536");
    let product = prepare(&original, manifest.as_bytes()).unwrap();
    assert!(!product.candidate_complete());
    assert!(!product.files().contains_key("candidate.elf"));
    assert_eq!(product.reports().len(), 1);
    assert_eq!(product.reports()[0].refusal_code, Some(11));
}

#[test]
fn strict_manifest_rejects_duplicate_unknown_and_orphan_records() {
    let (_, manifest) = input(2, "B1");
    for extra in [
        "domain 1\n",
        "admit true\n",
        "resumes 99 none\n",
        "allocation 1 mystery none 1 4096 4194304:4096\n",
    ] {
        assert!(
            selection::parse(format!("{manifest}{extra}").as_bytes()).is_err(),
            "{extra}"
        );
    }
}

#[test]
fn target_description_is_checked_without_host_detection() {
    let (_, manifest) = input(2, "B1");
    let avx = manifest.replace("target fxsave64", "target xsave64 7 4:576:256");
    assert_eq!(selection::parse(avx.as_bytes()).unwrap().target.mask(), 7);
    let missing = manifest.replace("target fxsave64", "target xsave64 7");
    assert!(selection::parse(missing.as_bytes()).is_err());
}

#[test]
fn conflicting_second_logical_probe_is_reported_not_silently_dropped() {
    let (original, mut manifest) = input(2, "B1");
    let rows = manifest
        .lines()
        .filter(|l| {
            ["site ", "entries ", "resumes ", "search ", "allocation "]
                .iter()
                .any(|p| l.starts_with(p))
        })
        .map(|line| line.replacen(" 1 ", " 2 ", 1))
        .collect::<Vec<_>>()
        .join("\n");
    manifest.push_str(&rows);
    manifest.push('\n');
    let product = prepare(&original, manifest.as_bytes()).unwrap();
    assert_eq!(product.reports().len(), 2);
    assert!(!product.candidate_complete());
    assert!(
        product
            .reports()
            .iter()
            .all(|r| !r.candidate_emitted && r.refusal.is_some())
    );
    assert!(!product.files().contains_key("candidate.elf"));
    assert_eq!(metadata(&product, &manifest).sites().len(), 2);
}

#[test]
fn original_rx_is_required_independently_for_source_and_hook() {
    // Keep every previous fixture and its ten forced successes unchanged. This
    // new geometry gives source and hook independent original load owners.
    let separate = |source_flags: u32, hook_flags: u32| {
        let (mut original, manifest) = input(2, "B1");
        let old_identity = hex(&ContentId::of(&original).0);
        original.resize(3 * 4096, 0);
        put16(&mut original, 56, 3);
        put32(&mut original, 64 + 56 + 4, source_flags);
        let at = 64 + 2 * 56;
        put32(&mut original, at, 1);
        put32(&mut original, at + 4, hook_flags);
        put64(&mut original, at + 8, 8192);
        put64(&mut original, at + 16, BASE + 8192);
        put64(&mut original, at + 24, BASE + 8192);
        put64(&mut original, at + 32, 4096);
        put64(&mut original, at + 40, 4096);
        put64(&mut original, at + 48, 4096);
        original[0x2800] = 0xc3;
        let manifest = manifest
            .replacen(
                &format!("original {old_identity}"),
                &format!("original {}", hex(&ContentId::of(&original).0)),
                1,
            )
            .replacen(
                &format!("hook 7 {HOOK} 1"),
                &format!("hook 7 {} 1", BASE + 0x2800),
                1,
            );
        (original, manifest)
    };
    let (original, manifest) = separate(5, 5);
    let positive = prepare(&original, manifest.as_bytes()).unwrap();
    assert!(positive.candidate_complete());
    assert!(positive.reports()[0].candidate_emitted);
    assert!(positive.reports()[0].refusal.is_none());
    assert!(!positive.qualification_complete());

    let (original, manifest) = separate(1, 5);
    let before = original.clone();
    let refused = prepare(&original, manifest.as_bytes()).unwrap();
    assert_eq!(original, before);
    assert!(!refused.candidate_complete());
    assert!(!refused.reports()[0].candidate_emitted);
    assert_eq!(
        refused.reports()[0].refusal.as_ref().unwrap().stage,
        "source-protection"
    );
    assert_eq!(
        refused.reports()[0].refusal.as_ref().unwrap().detail,
        "requires original RX"
    );
    assert!(!refused.files().contains_key("candidate.elf"));
    assert!(!refused.files().contains_key("source.li2sparse"));

    let (original, manifest) = separate(5, 1);
    let before = original.clone();
    let refused = prepare(&original, manifest.as_bytes()).unwrap_err();
    assert_eq!(original, before);
    assert_eq!(refused.stage, "source-protection");
    assert_eq!(refused.detail, "requires original RX");
}

#[path = "support/composition_overlay.rs"]
mod composition_overlay;

#[path = "support/owned_neighbors.rs"]
mod owned_neighbors;
