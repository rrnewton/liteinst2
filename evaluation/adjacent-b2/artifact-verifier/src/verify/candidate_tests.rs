use super::*;
use crate::verify::tests::{fixture, original};

#[test]
fn v04_complete_direct_positive_and_every_byte_class_mutant() {
    let f = fixture("checksum", true);
    let facts = f.expected.facts(&f.original, &f.product).unwrap();
    let records = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
    let plan = &f.product.0["plan-ledger.tsv"];
    let joined = ledger::join(&f.original, &facts, &records, plan, &f.product).unwrap();
    let payload = payload(&f.product.0["metadata.li2meta"], plan);
    let valid = &f.product.0["candidate.elf"];
    let layout = direct(&f.original, &joined, &payload, valid).unwrap();
    assert!(verify(&f.expected.program, &f.original, &f.expected, &f.product).is_ok());
    let mut offsets = vec![
        0,
        16,
        18,
        24,
        32,
        40,
        48,
        52,
        54,
        56,
        58,
        60,
        62,
        64,
        72,
        80,
        88,
        96,
        104,
        112,
        512,
        1023,
        0x3000,
        0x4000,
        f.original.len() - 1,
        host(layout.payload.start().0).unwrap(),
        host(layout.payload.start().0).unwrap() + payload.len() - 64,
        host(layout.payload.end().0).unwrap() - 1,
    ];
    for i in 0..layout.table.len() / 56 {
        for field in [0, 4, 8, 16, 24, 32, 40, 48] {
            offsets.push(host(layout.table.start().0 + i * 56 + field).unwrap());
        }
    }
    for p in &layout.images {
        offsets.push(host(p.file.start().0).unwrap());
        if p.file.start().0 % 4096 != 0 {
            offsets.push(host(p.file.start().0 - 1).unwrap());
        }
    }
    let after = host(layout.payload.end().0).unwrap();
    if after < host(layout.images[0].file.start().0).unwrap() {
        offsets.push(after);
    }
    for e in &joined.edits {
        offsets.push(host(e.offset.0).unwrap());
    }
    offsets.sort_unstable();
    offsets.dedup();
    for offset in offsets {
        let mut bad = valid.clone();
        bad[offset] ^= 1;
        let fake_writer_agreement = bad.clone();
        assert_eq!(fake_writer_agreement, bad);
        assert!(
            direct(&f.original, &joined, &payload, &bad).is_err(),
            "direct proof byte {offset}"
        );
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(direct(&f.original, &joined, &payload, &trailing).is_err());
}

fn layout_case(entry: u64, span: u64) -> (Vec<u8>, ledger::Joined, Vec<u8>) {
    let original = original();
    let elf = Elf64::parse(&original, ParseLimits::default()).unwrap();
    let joined = ledger::Joined {
        plans: Vec::new(),
        associations: Default::default(),
        images: vec![carrier::RxImage {
            entry: ElfVaddr(entry),
            bytes: vec![0x90],
        }],
        edits: Vec::new(),
        dependencies: vec![FileRange::checked(FileOffset(0x3000), 1).unwrap()],
    };
    let output = carrier::append_exec_carrier_with_interleaved_loads(
        &elf,
        carrier::ImageRequest {
            carrier_vaddr: ElfVaddr(0x480000),
            payload: b"fixed",
            images: &joined.images,
            source_dependencies: &joined.dependencies,
        },
        &[],
        carrier::ImagePolicy {
            layout: carrier::CarrierPolicy {
                page_size: 4096,
                user_address_limit: 1 << 47,
                max_added_file_bytes: TEXT as u64,
                max_output_file_bytes: OUTPUT as u64,
                max_program_headers: 128,
                max_virtual_span: span,
            },
            dynamic: Default::default(),
            max_images: 32,
            max_new_load_pages: 128,
        },
    )
    .unwrap();
    (original, joined, output.bytes().to_vec())
}
#[test]
fn v04_full_original_carrier_hull_equal_cap_and_next_page() {
    let (original, joined, candidate) = layout_case(0x803ff000, 2147483648);
    assert!(direct(&original, &joined, b"fixed", &candidate).is_ok());
    // The fixture builder's larger bound constructs the negative only; the
    // production direct checker still uses the unchanged exact 2 GiB ceiling.
    let (original, joined, candidate) = layout_case(0x80400000, 2147487744);
    assert!(direct(&original, &joined, b"fixed", &candidate).is_err());
}

#[test]
fn c04_direct_refusals_survive_repaired_candidate_extension_and_both_indices() {
    let mut f = crate::verify::tests::routed_fixture("checksum");
    let facts = f.expected.facts(&f.original, &f.product).unwrap();
    let records = report_records(&f.original, &facts, &f.product.0["report.tsv"]).unwrap();
    let plan = f.product.0["plan-ledger.tsv"].clone();
    let joined = ledger::join(&f.original, &facts, &records, &plan, &f.product).unwrap();
    let payload = payload(&f.product.0["metadata.li2meta"], &plan);
    let valid = f.product.clone();
    let layout = direct(&f.original, &joined, &payload, &valid.0["candidate.elf"]).unwrap();
    for at in [
        32,
        56,
        512,
        f.original.len() - 1,
        host(layout.table.start().0 + 24).unwrap(),
        host(layout.payload.start().0).unwrap(),
        host(layout.payload.end().0 - 1).unwrap(),
        host(layout.images[0].file.start().0).unwrap(),
    ] {
        f.product = valid.clone();
        let candidate = f.product.0.get_mut("candidate.elf").unwrap();
        candidate[at] ^= 1;
        let changed = digest(candidate);
        let full = String::from_utf8(f.product.0["ledger.tsv"].clone())
            .unwrap()
            .replace(&digest(&valid.0["candidate.elf"]), &changed);
        f.product.0.insert("ledger.tsv".into(), full.into_bytes());
        crate::verify::tests::reseal(&f.original, &mut f.product);
        crate::indices(&f.original, &f.product).unwrap();
        let refusal = direct(
            &f.original,
            &joined,
            &payload,
            &f.product.0["candidate.elf"],
        )
        .expect_err("independent direct check");
        assert_eq!(
            verify("checksum", &f.original, &f.expected, &f.product).err(),
            Some(refusal),
            "byte {at}"
        );
    }
}
