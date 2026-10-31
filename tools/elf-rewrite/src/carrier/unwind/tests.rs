//! Pure byte/ownership controls. Full opaque-certificate API controls are in
//! the separately owned fixture integration test; no unsafe constructor here.
use super::super::{CarrierPolicy, RxImage};
use super::*;
use elf64::VirtualRange;

const HEADER: usize = 0x400;
const STREAM: usize = 0x500;
const SOURCE: u64 = 0x1000;
const HOOK: u64 = 0x1100;

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn delta(bytes: &mut [u8], at: usize, target: u64, base: u64) {
    bytes[at..at + 4].copy_from_slice(
        &i32::try_from(i128::from(target) - i128::from(base))
            .unwrap()
            .to_le_bytes(),
    );
}
fn record(body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 4 + body.len().div_ceil(4) * 4];
    let len = bytes.len();
    put32(&mut bytes, 0, (len - 4) as u32);
    bytes[4..4 + body.len()].copy_from_slice(body);
    bytes
}
fn cfi(address: u64, functions: &[(u64, u64)]) -> (Vec<u8>, Vec<(u64, u64, u64)>) {
    // The unselected CFA-expression bytes are deliberately not in the core's
    // admitted source-recovery grammar. Inventory must preserve, not bless, it.
    let mut output = record(&[
        0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b, 0x0f, 2, 0x77, 8,
    ]);
    let mut rows = Vec::new();
    for &(start, end) in functions {
        let at = address + output.len() as u64;
        let mut body = vec![0; 13];
        put32(&mut body, 0, u32::try_from(at + 4 - address).unwrap());
        delta(&mut body, 4, start, at + 8);
        put32(&mut body, 8, u32::try_from(end - start).unwrap());
        body.extend_from_slice(&[0x0a, 0x0b]); // opaque balanced remember/restore
        output.extend(record(&body));
        rows.push((start, end, at));
    }
    output.extend_from_slice(&[0; 4]);
    (output, rows)
}

struct Fixture {
    bytes: Vec<u8>,
    rows: Vec<(u64, u64, u64)>,
    stream_len: usize,
}
fn fixture(bias: u64) -> Fixture {
    let mut bytes = vec![0; 8192];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut bytes, 16, 3);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 3);
    for (index, offset, flags) in [(0, 0, 4), (1, 4096, 5)] {
        super::super::encode_phdr(
            &mut bytes,
            64 + index * 56,
            super::super::EncodedHeader {
                kind: 1,
                flags,
                offset,
                vaddr: bias + offset,
                file_size: 4096,
                memory_size: 4096,
                alignment: 4096,
            },
        )
        .unwrap();
    }
    let (stream, rows) = cfi(
        bias + STREAM as u64,
        &[
            (bias + SOURCE, bias + SOURCE + 6),
            (bias + HOOK, bias + HOOK + 1),
        ],
    );
    bytes[STREAM..STREAM + stream.len()].copy_from_slice(&stream);
    let header_len = 12 + rows.len() * 8;
    super::super::encode_phdr(
        &mut bytes,
        64 + 2 * 56,
        super::super::EncodedHeader {
            kind: 0x6474_e550,
            flags: 4,
            offset: HEADER as u64,
            vaddr: bias + HEADER as u64,
            file_size: header_len as u64,
            memory_size: header_len as u64,
            alignment: 4,
        },
    )
    .unwrap();
    bytes[HEADER..HEADER + 4].copy_from_slice(&[1, 0x1b, 3, 0x3b]);
    delta(
        &mut bytes,
        HEADER + 4,
        bias + STREAM as u64,
        bias + HEADER as u64 + 4,
    );
    put32(&mut bytes, HEADER + 8, rows.len() as u32);
    for (i, &(start, _, fde)) in rows.iter().enumerate() {
        delta(&mut bytes, HEADER + 12 + i * 8, start, bias + HEADER as u64);
        delta(&mut bytes, HEADER + 16 + i * 8, fde, bias + HEADER as u64);
    }
    bytes[SOURCE as usize..SOURCE as usize + 6].copy_from_slice(&[0x0f, 0x1f, 0x44, 0, 0, 0xc3]);
    bytes[HOOK as usize] = 0xc3;
    Fixture {
        bytes,
        rows,
        stream_len: stream.len(),
    }
}
fn elf(bytes: &[u8]) -> Elf64<'_> {
    Elf64::parse(
        bytes,
        ParseLimits {
            max_program_headers: 32,
        },
    )
    .unwrap()
}
fn index_error(bytes: &[u8], limits: IndexLimits) -> Error {
    let parsed = elf(bytes);
    OriginalIndex::inspect(&parsed, limits, dynamic::Limits::default())
        .err()
        .expect("required refusal")
}
fn policy() -> ImagePolicy {
    ImagePolicy {
        layout: CarrierPolicy {
            page_size: 4096,
            user_address_limit: 1 << 32,
            max_added_file_bytes: 65536,
            max_output_file_bytes: 131072,
            max_program_headers: 16,
            max_virtual_span: 262144,
        },
        dynamic: dynamic::Limits::default(),
        max_images: 1,
        max_new_load_pages: 16,
    }
}

#[test]
fn complete_original_inventory_preserves_opaque_programs_at_two_biases() {
    for bias in [0, 0x400000] {
        let fixture = fixture(bias);
        let parsed = elf(&fixture.bytes);
        let inventory =
            OriginalIndex::inspect(&parsed, IndexLimits::default(), dynamic::Limits::default())
                .unwrap();
        assert_eq!(inventory.identity(), ContentId::of(&fixture.bytes));
        assert_eq!(inventory.header_address(), ElfVaddr(bias + HEADER as u64));
        assert_eq!(inventory.stream_address(), ElfVaddr(bias + STREAM as u64));
        assert_eq!(inventory.intervals().collect::<Vec<_>>(), fixture.rows);
        assert_eq!(inventory.dependencies()[1].len(), fixture.stream_len as u64);
        assert!(!inventory.qualification_complete());
        for &(start, end, address) in &fixture.rows {
            for point in [start, end - 1] {
                let record = inventory.source_record(point).unwrap();
                assert_eq!(
                    (record.cie_address, record.fde_address),
                    (bias + STREAM as u64, address)
                );
                assert_eq!(record.cie, fixture.bytes[STREAM..STREAM + 24]);
                let at = (address - bias) as usize;
                assert_eq!(record.fde, fixture.bytes[at..at + 20]);
                inventory.authenticate_source_records(&[record]).unwrap();
            }
        }
        assert_eq!(
            inventory.source_record(bias + SOURCE + 6).err(),
            Some(Error::MissingPoint)
        );
    }
}

#[test]
fn original_index_refuses_missing_duplicate_unordered_and_false_start_entries() {
    for (offset, value) in [
        (HEADER + 8, 1),
        (HEADER + 12, 0x222),
        (HEADER + 20, SOURCE as u32 - HEADER as u32),
        (HEADER + 24, (STREAM + 24 - HEADER) as u32),
    ] {
        let mut f = fixture(0);
        put32(&mut f.bytes, offset, value);
        assert_eq!(
            index_error(&f.bytes, IndexLimits::default()),
            Error::IndexMismatch
        );
    }
    let mut f = fixture(0);
    let first = f.bytes[HEADER + 12..HEADER + 20].to_vec();
    let second = f.bytes[HEADER + 20..HEADER + 28].to_vec();
    f.bytes[HEADER + 12..HEADER + 20].copy_from_slice(&second);
    f.bytes[HEADER + 20..HEADER + 28].copy_from_slice(&first);
    assert_eq!(
        index_error(&f.bytes, IndexLimits::default()),
        Error::IndexMismatch
    );
}

#[test]
fn unsupported_header_encodings_alignment_and_presence_refuse() {
    for offset in HEADER..HEADER + 4 {
        let mut f = fixture(0);
        f.bytes[offset] ^= 1;
        assert_eq!(
            index_error(&f.bytes, IndexLimits::default()),
            Error::UnsupportedHeader
        );
    }
    let mut f = fixture(0);
    put32(&mut f.bytes, 64 + 2 * 56, 0);
    assert_eq!(
        index_error(&f.bytes, IndexLimits::default()),
        Error::UnsupportedHeader
    );
    let mut f = fixture(0);
    put16(&mut f.bytes, 56, 4);
    let header = f.bytes[64 + 112..64 + 168].to_vec();
    f.bytes[64 + 168..64 + 224].copy_from_slice(&header);
    assert_eq!(
        index_error(&f.bytes, IndexLimits::default()),
        Error::UnsupportedHeader
    );
    let mut f = fixture(0);
    put64(&mut f.bytes, 64 + 112 + 16, HEADER as u64 + 1);
    assert_eq!(
        index_error(&f.bytes, IndexLimits::default()),
        Error::UnsupportedHeader
    );
}

#[test]
fn record_envelope_and_original_interval_mutants_are_not_omitted() {
    let first = STREAM + 24;
    for (offset, value, expected) in [
        (STREAM, u32::MAX, Error::UnsupportedRecord),
        (first + 4, 1, Error::MalformedRecord),
        (first + 12, 0, Error::UnsupportedRecord),
        (first + 12, u32::MAX, Error::UnsupportedRecord),
        (first + 12, 0x200, Error::OverlappingFrames),
    ] {
        let mut f = fixture(0);
        put32(&mut f.bytes, offset, value);
        assert_eq!(index_error(&f.bytes, IndexLimits::default()), expected);
    }
    for offset in [
        STREAM + 8,
        STREAM + 9,
        STREAM + 12,
        STREAM + 13,
        STREAM + 14,
        STREAM + 15,
        STREAM + 16,
        first + 16,
    ] {
        let mut f = fixture(0);
        f.bytes[offset] ^= 1;
        assert_eq!(
            index_error(&f.bytes, IndexLimits::default()),
            Error::UnsupportedRecord
        );
    }
}

#[test]
fn every_original_record_and_terminator_byte_charges_its_original_limit() {
    let f = fixture(0);
    for limits in [
        IndexLimits {
            original_fdes: 1,
            ..IndexLimits::default()
        },
        IndexLimits {
            original_cies: 0,
            ..IndexLimits::default()
        },
        IndexLimits {
            original_bytes: 28 + f.stream_len - 1,
            ..IndexLimits::default()
        },
        IndexLimits {
            index_bytes: 27,
            ..IndexLimits::default()
        },
    ] {
        assert!(matches!(index_error(&f.bytes, limits), Error::Limit { .. }));
    }
    let parsed = elf(&f.bytes);
    OriginalIndex::inspect(
        &parsed,
        IndexLimits {
            original_fdes: 2,
            original_cies: 1,
            original_bytes: 28 + f.stream_len,
            index_bytes: 28,
        },
        dynamic::Limits::default(),
    )
    .unwrap();
    let mut bad = f.bytes.clone();
    put32(&mut bad, STREAM + f.stream_len - 4, 4);
    assert!(matches!(
        index_error(
            &bad,
            IndexLimits {
                original_bytes: 28 + f.stream_len,
                ..IndexLimits::default()
            }
        ),
        Error::Limit {
            resource: "stream bytes",
            ..
        }
    ));
    let (mut bytes, _) = cfi(0x500, &[(0x1000, 0x1001)]);
    put32(&mut bytes, 24 + 12, 0);
    let error = parser::stream(
        |at, size| {
            bytes
                .get((at - 0x500) as usize..(at - 0x500) as usize + size)
                .ok_or(Error::MalformedRecord)
        },
        0x500,
        IndexLimits {
            original_fdes: 0,
            ..IndexLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(
        error,
        Error::Limit {
            resource: "FDE records",
            required: 1,
            limit: 0
        }
    );
}

#[test]
fn metadata_requires_bidirectional_unique_readonly_file_ownership() {
    let mut f = fixture(0);
    put32(&mut f.bytes, 64 + 4, 6);
    assert_eq!(
        index_error(&f.bytes, IndexLimits::default()),
        Error::MetadataOwner
    );
    let mut f = fixture(0);
    put64(&mut f.bytes, 64 + 32, HEADER as u64);
    assert_eq!(
        index_error(&f.bytes, IndexLimits::default()),
        Error::MetadataOwner
    );
    let mut f = fixture(0);
    put16(&mut f.bytes, 56, 4);
    super::super::encode_phdr(
        &mut f.bytes,
        64 + 3 * 56,
        super::super::EncodedHeader {
            kind: 1,
            flags: 4,
            offset: 0,
            vaddr: 0x3000,
            file_size: 4096,
            memory_size: 4096,
            alignment: 4096,
        },
    )
    .unwrap();
    assert!(matches!(
        index_error(&f.bytes, IndexLimits::default()),
        Error::Elf(elf64::Error::AmbiguousFile { .. })
    ));
    let f = fixture(0);
    let parsed = elf(&f.bytes);
    for (virtual_start, file) in [
        (STREAM as u64, None),
        (
            0x9000,
            Some(FileRange::checked(FileOffset(STREAM as u64), 8).unwrap()),
        ),
    ] {
        let mut inventory = dynamic::Inventory::default();
        inventory.writes.push(dynamic::RelocationWrite {
            table: dynamic::TableKind::Rela,
            record: 0,
            kind: 8,
            symbol: 0,
            range: VirtualRange::checked(ElfVaddr(virtual_start), 8).unwrap(),
            file,
        });
        assert_eq!(
            metadata_range(&parsed, &inventory, STREAM as u64, f.stream_len).err(),
            Some(Error::MetadataWrite)
        );
    }
}

#[test]
fn copied_source_cfi_must_match_both_exact_catalogue_records() {
    let f = fixture(0);
    let parsed = elf(&f.bytes);
    let inventory =
        OriginalIndex::inspect(&parsed, IndexLimits::default(), dynamic::Limits::default())
            .unwrap();
    let record = inventory.source_record(SOURCE).unwrap();
    for which in 0..4 {
        let mut changed = record.clone();
        match which {
            0 => changed.cie_address += 1,
            1 => changed.fde_address += 1,
            2 => *changed.cie.last_mut().unwrap() ^= 1,
            _ => *changed.fde.last_mut().unwrap() ^= 1,
        }
        assert_eq!(
            inventory.authenticate_source_records(&[changed]),
            Err(Error::SourceBinding)
        );
    }
    assert_eq!(
        inventory.authenticate_source_records(&[]),
        Err(Error::SourceBinding)
    );
}

#[test]
fn combined_index_preserves_every_tuple_and_refuses_overlap_and_range_overflow() {
    let f = fixture(0);
    let parsed = elf(&f.bytes);
    let inventory =
        OriginalIndex::inspect(&parsed, IndexLimits::default(), dynamic::Limits::default())
            .unwrap();
    let (bytes, _) = cfi(0x8000, &[(0x10000, 0x10020)]);
    let generated = parser::stream(
        |at, len| {
            bytes
                .get((at - 0x8000) as usize..(at - 0x8000) as usize + len)
                .ok_or(Error::MalformedRecord)
        },
        0x8000,
        IndexLimits::default(),
    )
    .unwrap();
    let mut all = inventory.stream.fdes.clone();
    all.extend(generated.fdes.clone());
    let entries = parser::ordered(&all).unwrap();
    let encoded = parser::render(&entries, STREAM as u64, 0x9000, IndexLimits::default()).unwrap();
    let decoded = parser::header(&encoded, 0x9000, IndexLimits::default()).unwrap();
    assert_eq!(decoded.stream, STREAM as u64);
    assert_eq!(decoded.entries, entries);
    assert_eq!(&entries[..2], &inventory.header.entries);
    assert_eq!(
        entries[2],
        Entry {
            start: 0x10000,
            fde: 0x8000 + 24
        }
    );
    all[2].start = SOURCE + 1;
    assert_eq!(parser::ordered(&all), Err(Error::OverlappingFrames));
    let address = 0x80000008;
    let extremes = [
        Entry { start: 8, fde: 8 },
        Entry {
            start: 0x100000007,
            fde: 0x100000007,
        },
    ];
    let encoded = parser::render(&extremes, address, address, IndexLimits::default()).unwrap();
    assert_eq!(
        parser::header(&encoded, address, IndexLimits::default())
            .unwrap()
            .entries,
        extremes
    );
    for target in [7, 0x100000008] {
        assert_eq!(
            parser::render(
                &[Entry {
                    start: target,
                    fde: address
                }],
                address,
                address,
                IndexLimits::default()
            ),
            Err(Error::RelativeRange)
        );
    }
}

#[test]
fn metadata_coordinate_shares_existing_carrier_layout_without_changing_it() {
    let f = fixture(0);
    let parsed = elf(&f.bytes);
    let images = [RxImage {
        entry: ElfVaddr(0x10000),
        bytes: vec![0xc3],
    }];
    for size in [0, 1, 7, 8, 9, 1024] {
        let payload = vec![0x69; size];
        let request = ImageRequest {
            carrier_vaddr: ElfVaddr(0x8000),
            payload: &payload,
            images: &images,
            source_dependencies: &[],
        };
        let address = metadata_address(&parsed, &request, policy()).unwrap();
        let plain =
            super::super::append_carrier_with_images(&parsed, request, &[], policy()).unwrap();
        assert!(plain.unwind.is_none());
        let out = elf(plain.bytes());
        let payload_start =
            plain.program_table_vaddr.0 + plain.payload.start().0 - plain.program_table.start().0;
        assert_eq!(address.0, (payload_start + size as u64 + 7) & !7);
        let original_header = out.segments(GNU_EH_FRAME).next().unwrap();
        assert_eq!(
            (original_header.offset.0, original_header.vaddr.0),
            (HEADER as u64, HEADER as u64)
        );
    }
}

#[test]
fn final_reread_rejects_changed_original_records_generated_bytes_and_active_headers() {
    let f = fixture(0);
    let parsed = elf(&f.bytes);
    let original =
        OriginalIndex::inspect(&parsed, IndexLimits::default(), dynamic::Limits::default())
            .unwrap();
    let images = [RxImage {
        entry: ElfVaddr(0x10000),
        bytes: vec![0xc3],
    }];
    let request = ImageRequest {
        carrier_vaddr: ElfVaddr(0x8000),
        payload: &[],
        images: &images,
        source_dependencies: &[],
    };
    let address = metadata_address(&parsed, &request, policy()).unwrap().0;
    let (bytes, _) = cfi(address, &[(0x10000, 0x10001)]);
    let generated = parser::stream(
        |at, len| {
            bytes
                .get((at - address) as usize..(at - address) as usize + len)
                .ok_or(Error::MalformedRecord)
        },
        address,
        IndexLimits::default(),
    )
    .unwrap();
    let mut all = original.stream.fdes.clone();
    all.extend(generated.fdes.clone());
    let entries = parser::ordered(&all).unwrap();
    let header_address = (address + bytes.len() as u64 + 7) & !7;
    let header = parser::render(
        &entries,
        STREAM as u64,
        header_address,
        IndexLimits::default(),
    )
    .unwrap();
    let mut payload = bytes.clone();
    payload.resize((header_address - address) as usize, 0);
    payload.extend_from_slice(&header);
    let mut output = super::super::append_carrier_with_images(
        &parsed,
        ImageRequest {
            payload: &payload,
            ..request
        },
        &[],
        policy(),
    )
    .unwrap();
    let records_file = FileRange::checked(output.payload.start(), bytes.len() as u64).unwrap();
    let header_file = FileRange::checked(
        FileOffset(output.payload.start().0 + header_address - address),
        header.len() as u64,
    )
    .unwrap();
    let index = output.original_to_output_header[original.header_index];
    let slot = output.program_table.start().0 + index as u64 * 56;
    super::super::encode_phdr(
        &mut output.bytes,
        slot,
        super::super::EncodedHeader {
            kind: 0x6474_e550,
            flags: 4,
            offset: header_file.start().0,
            vaddr: header_address,
            file_size: header.len() as u64,
            memory_size: header.len() as u64,
            alignment: 4,
        },
    )
    .unwrap();
    let verify = |candidate: &CarrierOutput| {
        verify_output(
            &parsed,
            candidate,
            &original,
            &generated,
            RecordBytes {
                address,
                bytes: &bytes,
            },
            policy(),
            FinalIndex {
                entries: &entries,
                header: &header,
                header_file,
                header_address,
                records_file,
                limits: IndexLimits::default(),
            },
        )
    };
    assert_eq!(verify(&output), Ok(()));
    for offset in [
        header_file.start().0 + 12,
        records_file.start().0 + 20,
        slot + 16,
        output.program_table.start().0 + output.original_to_output_header[0] as u64 * 56 + 4,
    ] {
        let mut changed = output.clone();
        changed.bytes[offset as usize] ^= 1;
        assert_eq!(verify(&changed), Err(Error::OutputInvariant));
    }
    for offset in [STREAM + 20, HEADER + 12, STREAM + f.stream_len - 1] {
        let mut changed = output.clone();
        changed.bytes[offset] ^= 1;
        assert_eq!(
            verify(&changed),
            Err(Error::Carrier(super::super::Error::OutputInvariant))
        );
    }
}
