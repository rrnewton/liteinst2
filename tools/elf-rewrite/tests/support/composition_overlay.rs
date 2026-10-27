//! Full-selection artifact composition; no generated code is executed.
use super::*;
use li2core::composition::Composition;
use li2core::contracts::{
    CodeIdentity, EntryProvenance, ExpectedBytes, LegalEntrySet, Refusal, SourceIdentity,
};
use li2core::emission::{
    ArtifactEmission, ArtifactRequest, PlanningSite, SymbolicHook, TargetProfile,
};
use li2core::engine::{self, EnginePolicy, Tactic};

const SECOND_HOOK: u64 = HOOK + 16;
const LOW_IMAGE: u64 = S + 0x4000000;
const HIGH_IMAGE: u64 = S + 0x6000000;

fn two_probes(overlap: bool) -> (Vec<u8>, String) {
    let (mut original, _) = input(2, "B1");
    let (body, head_offsets, first_len, second_offset, tactic): (&[u8], &[u64], u8, u64, &str) =
        if overlap {
            (
                &[0x0f, 0x1f, 0x00, 0xb8, 42, 0, 0, 0, 0xc3],
                &[0, 3, 8],
                3,
                3,
                "B1",
            )
        } else {
            (
                &[0xb8, 42, 0, 0, 0, 0xbb, 7, 0, 0, 0, 0xc3],
                &[0, 5, 10],
                5,
                5,
                "preferred",
            )
        };
    original[0x1100..0x1100 + body.len()].copy_from_slice(body);
    original[0x1810] = 0xc3;
    let entries = head_offsets
        .iter()
        .map(|offset| format!("{}:0", S + offset))
        .collect::<Vec<_>>()
        .join(" ");
    let provenance = hex(&ContentId::of(b"two complete original MOV/NOP fixture entries").0);
    let mut manifest = format!(
        "LI2TOOL 1\noriginal {}\ntarget fxsave64\ndomain 1\ncarrier {}\nlimits 1048576 16 16 65536 64 1048576 262144 64 4294967296\nhook 7 {HOOK} 1 {}\nhook 8 {SECOND_HOOK} 1 {}\n",
        hex(&ContentId::of(&original).0),
        BASE + 0x8000,
        hex(&ContentId::of(&[0xc3]).0),
        hex(&ContentId::of(&[0xc3]).0)
    );
    for (id, offset, len, hook, image) in [
        (1, 0, first_len, 7, LOW_IMAGE),
        (2, second_offset, 5, 8, HIGH_IMAGE),
    ] {
        let pc = S + offset;
        manifest.push_str(&format!(
            "site {id} {pc} {len} {} {} {} {S} {} {S} {} {hook} observe original-decode\nentries {id} complete {provenance} {entries}\nresumes {id} none\nsearch {id} {tactic} 0 80 1 none 64 256\nallocation {id} selected {image} 256 8192 {}:8192\nallocation {id} victim {} 256 8192 {}:8192\n",
            0x1100 + offset, S - 16, body.len() + 16, body.len(), body.len(),
            image & !4095, image + 0x2000000, (image + 0x2000000) & !4095
        ));
    }
    (original, manifest)
}

fn rows<'a>(ledger: &'a str, tag: &str) -> Vec<Vec<&'a str>> {
    ledger
        .lines()
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .filter(|row| row[0] == tag)
        .collect()
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn jump(pc: u64, target: u64) -> Vec<u8> {
    let mut bytes = vec![0xe9];
    bytes.extend_from_slice(
        &i32::try_from(i128::from(target) - i128::from(pc + 5))
            .unwrap()
            .to_le_bytes(),
    );
    bytes
}

#[test]
fn independent_original_mov_probes_compose_current_full_reads_and_original_sparse_edits() {
    let (original, manifest) = two_probes(false);
    let before = original.clone();
    let selected = selection::parse(manifest.as_bytes()).unwrap();
    assert_eq!(selected.sites.len(), 2);
    for site in &selected.sites {
        assert!(site.forced.is_none());
        assert_eq!(
            site.heads
                .iter()
                .map(|entry| entry.address)
                .collect::<Vec<_>>(),
            [S, S + 5, S + 10]
        );
    }
    let product = prepare(&original, manifest.as_bytes()).unwrap();
    assert!(product.candidate_complete(), "{:?}", product.reports());
    assert!(!product.qualification_complete());
    assert_eq!(original, before);
    assert_eq!(
        product.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    for report in product.reports() {
        assert_eq!(report.core_tactic, Some(Tactic::Relocation));
        assert!(
            report.candidate_emitted && report.refusal.is_none() && report.refusal_code.is_none()
        );
    }
    let meta = metadata(&product, &manifest);
    meta.verify_original(&original).unwrap();
    meta.verify_selection(ContentId::of(manifest.as_bytes()), &[1, 2])
        .unwrap();
    for (site, (id, pc)) in meta.sites().iter().zip([(1, S), (2, S + 5)]) {
        assert_eq!(
            (site.id, site.original_pc, site.file_offset, site.length),
            (id, pc, pc - BASE, 5)
        );
        assert_eq!(
            site.outcome,
            Outcome::Rewritten(formats::Tactic::Relocation)
        );
    }

    let ledger = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    let steps = rows(ledger, "step");
    assert_eq!(steps.len(), 2);
    for (step, (id, pc)) in steps.iter().zip([(2_u64, S + 5), (1, S)]) {
        assert_eq!(
            (step[0], step[1].parse::<u64>().unwrap(), step[2], step[3]),
            ("step", id, "0", "relocation")
        );
        assert_eq!(
            step[4..]
                .iter()
                .map(|value| value.parse::<u64>().unwrap())
                .collect::<Vec<_>>(),
            [pc, pc, pc, pc + 5]
        );
    }
    let high_jump = jump(S + 5, HIGH_IMAGE);
    let low_jump = jump(S, LOW_IMAGE);
    let reads = rows(ledger, "step-read");
    assert_eq!(reads.len(), 2);
    assert_eq!(
        (&reads[0][..3], reads[0][3].parse::<u64>().unwrap()),
        (&["step-read", "2", "0"][..], S - 16)
    );
    assert_eq!(unhex(reads[0][4]), original[0x10f0..0x110b]);
    let mut inherited = original[0x10f0..0x110b].to_vec();
    inherited[21..26].copy_from_slice(&high_jump);
    assert_eq!(
        (&reads[1][..3], reads[1][3].parse::<u64>().unwrap()),
        (&["step-read", "1", "0"][..], S - 16)
    );
    assert_eq!(unhex(reads[1][4]), inherited);
    let writes = rows(ledger, "semantic-write");
    assert_eq!(writes.len(), 2);
    assert_eq!(
        (
            writes[0][1],
            writes[0][3].parse::<u64>().unwrap(),
            unhex(writes[0][4])
        ),
        ("2", S + 5, high_jump.clone())
    );
    assert_eq!(
        (
            writes[1][1],
            writes[1][3].parse::<u64>().unwrap(),
            unhex(writes[1][4])
        ),
        ("1", S, low_jump.clone())
    );

    let candidate = &product.files()["candidate.elf"];
    let elf =
        liteinst_rewrite::carrier::elf64::Elf64::parse(candidate, Default::default()).unwrap();
    let images = rows(ledger, "image");
    assert_eq!(images.len(), 2);
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|name| name.starts_with("image-"))
            .count(),
        2
    );
    for (image, (id, site, pc, target, hook)) in images.iter().zip([
        (0, 2, S + 5, HIGH_IMAGE, SECOND_HOOK),
        (1, 1, S, LOW_IMAGE, HOOK),
    ]) {
        assert_eq!(
            (
                image[1].parse::<usize>().unwrap(),
                image[2].parse::<u64>().unwrap(),
                image[3].parse::<u64>().unwrap()
            ),
            (id, site, target)
        );
        let bytes = &product.files()[image[6]];
        assert_eq!(image[4].parse::<usize>().unwrap(), bytes.len());
        assert_eq!(image[5], hex(&ContentId::of(bytes).0));
        assert_eq!(
            elf.executable_bytes(
                liteinst_rewrite::carrier::elf64::ElfVaddr(target),
                bytes.len() as u64
            )
            .unwrap(),
            bytes
        );
        let routes = rows(ledger, "route")
            .into_iter()
            .filter(|r| r[1].parse::<usize>().unwrap() == id)
            .collect::<Vec<_>>();
        assert_eq!(routes.len(), 1);
        assert_eq!(
            (
                routes[0][2].parse::<u64>().unwrap(),
                routes[0][3].parse::<u64>().unwrap()
            ),
            (pc, target)
        );
        let boundaries = rows(ledger, "restored-boundary")
            .into_iter()
            .filter(|r| r[1].parse::<usize>().unwrap() == id)
            .collect::<Vec<_>>();
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0][2].parse::<u64>().unwrap(), pc);
        let offset = (boundaries[0][3].parse::<u64>().unwrap() - target) as usize;
        assert_eq!(
            &bytes[offset..offset + 5],
            &original[(pc - BASE) as usize..(pc - BASE) as usize + 5]
        );
        for (role, expected_target) in [("HookCall", hook), ("Return", pc + 5)] {
            let fields = rows(ledger, "field")
                .into_iter()
                .filter(|r| r[1].parse::<usize>().unwrap() == id && unhex(r[8]) == role.as_bytes())
                .collect::<Vec<_>>();
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0][6].parse::<u64>().unwrap(), expected_target);
            let at = fields[0][2].parse::<usize>().unwrap();
            let width = fields[0][3].parse::<usize>().unwrap();
            assert_eq!(&bytes[at..at + width], unhex(fields[0][9]));
        }
        assert!(
            rows(ledger, "unmet-requirement")
                .iter()
                .any(|r| r[1].parse::<usize>().unwrap() == id
                    && r[2] == "5"
                    && r[3].parse::<u64>().unwrap() == if site == 2 { 8 } else { 7 })
        );
    }
    let mut expected = original.clone();
    expected[0x1100..0x1105].copy_from_slice(&low_jump);
    expected[0x1105..0x110a].copy_from_slice(&high_jump);
    assert_eq!(&candidate[4096..8192], &expected[4096..8192]);
    assert_eq!(candidate[0x1800], original[0x1800]);
    assert_eq!(candidate[0x1810], original[0x1810]);
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
    let mut reconstructed = original.clone();
    for edit in sparse.edits() {
        let start = edit.offset as usize;
        assert!((0x1100..0x110a).contains(&start) && start + edit.expected.len() <= 0x110a);
        assert_eq!(&original[start..start + edit.expected.len()], edit.expected);
        reconstructed[start..start + edit.replacement.len()].copy_from_slice(&edit.replacement);
    }
    assert_eq!(reconstructed, expected);
    assert_eq!(sparse.pages().len(), 1);
    assert_eq!(sparse.pages()[0].offset, 4096);
    assert_eq!(sparse.pages()[0].bytes, expected[4096..8192]);
}

#[test]
fn overlapping_later_original_window_refuses_complete_selection_and_keeps_first_step() {
    let (original, manifest) = two_probes(true);
    let before = original.clone();
    let product = prepare(&original, manifest.as_bytes()).unwrap();
    assert_eq!(original, before);
    assert!(!product.candidate_complete() && !product.qualification_complete());
    assert_eq!(product.reports().len(), 2);
    let lower = &product.reports()[0];
    assert_eq!(
        (lower.id, lower.pc, lower.refusal_code, lower.core_tactic),
        (1, S, Some(4), None)
    );
    assert_eq!(lower.refusal.as_ref().unwrap().stage, "core");
    assert_eq!(
        lower.refusal.as_ref().unwrap().detail,
        "ExpectedBytesChanged"
    );
    assert!(lower.diagnostics.contains("ExpectedBytesChanged"));
    let first = &product.reports()[1];
    assert_eq!(
        (first.id, first.pc, first.refusal_code, first.core_tactic),
        (2, S + 3, Some(10003), Some(Tactic::Relocation))
    );
    assert_eq!(first.refusal.as_ref().unwrap().stage, "atomic-selection");
    assert!(product.reports().iter().all(|r| !r.candidate_emitted));
    assert!(!product.files().contains_key("candidate.elf"));
    assert!(!product.files().contains_key("source.li2sparse"));
    let meta = metadata(&product, &manifest);
    meta.verify_original(&original).unwrap();
    meta.verify_selection(ContentId::of(manifest.as_bytes()), &[1, 2])
        .unwrap();
    assert_eq!(
        meta.sites()
            .iter()
            .map(|s| (s.id, s.outcome))
            .collect::<Vec<_>>(),
        [(1, Outcome::Refused(4)), (2, Outcome::Refused(10003))]
    );
    let ledger = std::str::from_utf8(&product.files()["plan-ledger.tsv"]).unwrap();
    assert_eq!(rows(ledger, "step").len(), 1);
    assert_eq!(rows(ledger, "step")[0][1], "2");
    assert_eq!(rows(ledger, "step-read").len(), 1);
    assert_eq!(
        unhex(rows(ledger, "step-read")[0][4]),
        original[0x10f0..0x1109]
    );
    assert_eq!(rows(ledger, "image").len(), 1);
    assert_eq!(
        product
            .files()
            .keys()
            .filter(|n| n.starts_with("image-"))
            .count(),
        1
    );
    // This separate control exposes the first plan for exact comparison; the
    // requested two-site product above remains refused, with both report rows.
    let first_only = manifest
        .lines()
        .filter(|line| {
            ![
                "site 1 ",
                "entries 1 ",
                "resumes 1 ",
                "search 1 ",
                "allocation 1 ",
            ]
            .iter()
            .any(|prefix| line.starts_with(prefix))
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let standalone = prepare(&original, first_only.as_bytes()).unwrap();
    assert!(standalone.candidate_complete());
    assert_eq!(
        product.files()["image-0000.bin"],
        standalone.files()["image-0000.bin"]
    );
    let prior_ledger = std::str::from_utf8(&standalone.files()["plan-ledger.tsv"]).unwrap();
    let without_selection = |text: &str| {
        text.lines()
            .filter(|line| !line.starts_with("selection_sha256\t"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(without_selection(ledger), without_selection(prior_ledger));
}

#[test]
fn predecessor_authentication_requires_exact_identity_originals_and_complete_coverage() {
    let (original, manifest) = two_probes(false);
    let selected = selection::parse(manifest.as_bytes()).unwrap();
    let site = &selected.sites[0];
    let identity = CodeIdentity {
        source: SourceIdentity(selected.original.0),
        mapping: selected.bias_domain,
        generation: 1,
    };
    let code = &original[0x10f0..0x110b];
    let entries = LegalEntrySet {
        identity,
        scope: site.function,
        provenance: EntryProvenance::Declared("full fixture entries".into()),
        completeness: site.completeness,
        entries: site.heads.clone(),
        resumes: site.resumes.clone(),
    };
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(selected.target, selected.bias_domain).unwrap(),
        SymbolicHook {
            identity: 7,
            address: Some(HOOK),
        },
        vec![li2core::contracts::AddressRange::new(BASE, 8192).unwrap()],
    );
    let request = ArtifactRequest {
        site: PlanningSite {
            identity,
            code,
            base_address: S - 16,
            function: site.function,
            block: site.block,
            logical_pc: site.pc,
            entries: &entries,
            semantics: site.semantics,
            allocation: &site.selected_allocation,
            search: site.search,
        },
        emission: &emission,
    };
    let snapshot = ExpectedBytes {
        address: S - 16,
        bytes: code.to_vec(),
    };
    let mut changed = snapshot.clone();
    changed.bytes[0] ^= 1;
    let mut wrong_source = identity;
    wrong_source.source.0[0] ^= 1;
    let bad = [
        (
            Composition::new(wrong_source, vec![snapshot.clone()]).unwrap(),
            Refusal::StaleGeneration,
        ),
        (
            Composition::new(
                CodeIdentity {
                    mapping: identity.mapping + 1,
                    ..identity
                },
                vec![snapshot.clone()],
            )
            .unwrap(),
            Refusal::StaleGeneration,
        ),
        (
            Composition::new(
                CodeIdentity {
                    generation: 2,
                    ..identity
                },
                vec![snapshot.clone()],
            )
            .unwrap(),
            Refusal::StaleGeneration,
        ),
        (
            Composition::new(identity, vec![changed]).unwrap(),
            Refusal::ExpectedBytesChanged,
        ),
        (
            Composition::new(
                identity,
                vec![ExpectedBytes {
                    address: S - 15,
                    bytes: code.to_vec(),
                }],
            )
            .unwrap(),
            Refusal::DependencyNotHeld,
        ),
        (
            Composition::new(
                identity,
                vec![
                    ExpectedBytes {
                        address: S - 16,
                        bytes: code[..16].to_vec(),
                    },
                    ExpectedBytes {
                        address: S + 1,
                        bytes: code[17..].to_vec(),
                    },
                ],
            )
            .unwrap(),
            Refusal::DependencyNotHeld,
        ),
    ];
    for (predecessor, reason) in bad {
        let before = predecessor.clone();
        let error = engine::plan_with_emission_after(
            &request,
            &predecessor,
            &site.victim_allocation,
            EnginePolicy::default(),
        )
        .unwrap_err();
        assert_eq!(error.reason, reason);
        assert!(error.attempts.is_empty());
        assert_eq!(predecessor, before);
    }
    let mut adjacent = Composition::new(
        identity,
        vec![
            ExpectedBytes {
                address: S - 16,
                bytes: code[..16].to_vec(),
            },
            ExpectedBytes {
                address: S,
                bytes: code[16..].to_vec(),
            },
        ],
    )
    .unwrap();
    let before = adjacent.clone();
    let plan = engine::plan_with_emission_after(
        &request,
        &adjacent,
        &site.victim_allocation,
        EnginePolicy::default(),
    )
    .unwrap();
    assert_eq!(adjacent, before);
    assert_eq!(plan.source_steps().len(), 1);
    assert_eq!(plan.source_steps()[0].parts().reads, [snapshot]);
    assert!(!plan.qualification_complete());
    for step in plan.source_steps() {
        adjacent.append(step).unwrap();
    }
    assert_eq!(adjacent.originals()[0].bytes, code[..16]);
    assert_eq!(adjacent.originals()[1].bytes, code[16..]);
    assert_eq!(adjacent.final_bytes()[1].bytes[..5], jump(S, LOW_IMAGE));
}
