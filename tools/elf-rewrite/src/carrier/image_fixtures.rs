//! Additive structural fixtures; these bytes are not a native loader qualification.
use super::*;

#[path = "property_fixtures.rs"]
mod property_fixtures;

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn parse(bytes: &[u8]) -> Elf64<'_> {
    Elf64::parse(bytes, ParseLimits::default()).unwrap()
}

fn fixture(kind: u16, base: u64, interpreter: bool, tags: &[(u64, u64)]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x3000];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut bytes, 16, kind);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(
        &mut bytes,
        24,
        if kind == 3 && !interpreter {
            0
        } else {
            base + 0x1100
        },
    );
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    let count = 6 + usize::from(interpreter);
    put16(&mut bytes, 56, count as u16);
    let mut records = vec![table_header(64, base + 64, count as u64 * 56)];
    if interpreter {
        records.push(EncodedHeader {
            kind: 3,
            flags: 4,
            offset: 0x600,
            vaddr: base + 0x600,
            file_size: 7,
            memory_size: 7,
            alignment: 1,
        });
        bytes[0x600..0x607].copy_from_slice(b"/ld.so\0");
    }
    for (offset, flags, memory_size) in [(0, 4, 0x1000), (0x1000, 5, 0x1000), (0x2000, 6, 0x2000)] {
        records.push(EncodedHeader {
            kind: 1,
            flags,
            offset,
            vaddr: base + offset,
            file_size: 0x1000,
            memory_size,
            alignment: 0x1000,
        });
    }
    records.push(EncodedHeader {
        kind: 2,
        flags: 6,
        offset: 0x2200,
        vaddr: base + 0x2200,
        file_size: (tags.len() as u64 + 1) * 16,
        memory_size: (tags.len() as u64 + 1) * 16,
        alignment: 8,
    });
    records.push(EncodedHeader {
        kind: 0x6474_e551,
        flags: 6,
        offset: 0,
        vaddr: 0,
        file_size: 0,
        memory_size: 0,
        alignment: 16,
    });
    for (index, record) in records.into_iter().enumerate() {
        encode_phdr(&mut bytes, 64 + index as u64 * 56, record).unwrap();
    }
    for (index, &(tag, value)) in tags.iter().enumerate() {
        put64(&mut bytes, 0x2200 + index * 16, tag);
        put64(&mut bytes, 0x2208 + index * 16, value);
    }
    bytes[0x1100..0x1108].copy_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3]);
    bytes
}

fn policy() -> ImagePolicy {
    ImagePolicy {
        layout: CarrierPolicy {
            page_size: 4096,
            user_address_limit: 1 << 47,
            max_added_file_bytes: 0x10000,
            max_output_file_bytes: 0x20000,
            max_program_headers: 32,
            max_virtual_span: 0x20000,
        },
        dynamic: dynamic::Limits::default(),
        max_images: 4,
        max_new_load_pages: 8,
    }
}
fn dependency() -> FileRange {
    FileRange::checked(FileOffset(0x1100), 8).unwrap()
}
fn edit(bytes: &[u8]) -> DeclaredEdit {
    DeclaredEdit {
        offset: FileOffset(0x1100),
        expected: bytes[0x1100..0x1105].to_vec(),
        replacement: vec![0xe9, 0, 0, 0, 0],
    }
}
fn images(base: u64) -> Vec<RxImage> {
    vec![
        RxImage {
            entry: ElfVaddr(base + 0x9005),
            bytes: vec![0x90, 0xc3],
        },
        RxImage {
            entry: ElfVaddr(base + 0x5003),
            bytes: vec![0xb8, 42, 0, 0, 0, 0xc3],
        },
    ]
}
fn append(
    bytes: &[u8],
    base: u64,
    images: &[RxImage],
    edits: &[DeclaredEdit],
    deps: &[FileRange],
    policy: ImagePolicy,
) -> Result<CarrierOutput, Error> {
    append_carrier_with_images(
        &parse(bytes),
        ImageRequest {
            carrier_vaddr: ElfVaddr(base + 0x6000),
            payload: b"metadata",
            images,
            source_dependencies: deps,
        },
        edits,
        policy,
    )
}
fn rela(bytes: &mut [u8], at: usize, target: u64, kind: u32, symbol: u32) {
    put64(bytes, at, target);
    put64(bytes, at + 8, (u64::from(symbol) << 32) | u64::from(kind));
    put64(bytes, at + 16, 0x1234);
}
fn inspect(bytes: &[u8]) -> Result<dynamic::Inventory, dynamic::Error> {
    dynamic::inspect(&parse(bytes), dynamic::Limits::default())
}
fn rela_fixture(kind: u32, target: u64) -> Vec<u8> {
    let mut bytes = fixture(3, 0, false, &[(7, 0x800), (8, 24), (9, 24)]);
    rela(&mut bytes, 0x800, target, kind, 0);
    bytes
}

#[test]
fn additive_exec_pie_and_dso_profiles_preserve_old_records_and_exact_rx_images() {
    for (kind, base, interpreter) in [(2, 0x400000, true), (3, 0, true), (3, 0, false)] {
        let original = fixture(kind, base, interpreter, &[]);
        let saved = original.clone();
        let images = images(base);
        let output = append(
            &original,
            base,
            &images,
            &[edit(&original)],
            &[dependency()],
            policy(),
        )
        .unwrap();
        let elf = parse(output.bytes());
        assert_eq!(original, saved);
        assert_eq!(elf.header().entry, parse(&original).header().entry);
        assert_eq!(
            elf.header().object_type,
            parse(&original).header().object_type
        );
        let mut expected = original.clone();
        assert_eq!(output.changes().len(), 3);
        for change in output.changes() {
            let start = change.edit.offset.0 as usize;
            assert_eq!(
                &original[start..start + change.edit.expected.len()],
                &change.edit.expected
            );
            expected[start..start + change.edit.replacement.len()]
                .copy_from_slice(&change.edit.replacement);
        }
        assert_eq!(&output.bytes()[..original.len()], &expected);
        for item in parse(&original).program_headers() {
            if item.kind != SegmentType::ProgramHeaders {
                let old = 64 + item.index * 56;
                let new = output.program_table.start().0 as usize
                    + output.original_to_output_header[item.index] * 56;
                assert_eq!(&original[old..old + 56], &output.bytes()[new..new + 56]);
            }
        }
        assert_eq!(output.images.len(), 2);
        assert_eq!(output.new_load_pages, 3);
        assert_eq!(output.bytes().len(), 0x5009);
        assert_eq!(
            output.images[0].file,
            FileRange::checked(FileOffset(0x4005), 2).unwrap()
        );
        assert_eq!(
            output.images[1].file,
            FileRange::checked(FileOffset(0x5003), 6).unwrap()
        );
        assert!(output.images[1].program_header < output.carrier_index);
        assert!(output.carrier_index < output.images[0].program_header);
        for (image, placement) in images.iter().zip(&output.images) {
            assert_eq!(
                elf.executable_bytes(image.entry, image.bytes.len() as u64)
                    .unwrap(),
                image.bytes
            );
            let load = &elf.program_headers()[placement.program_header];
            assert_eq!(load.flags.0, 5);
            assert_eq!(load.vaddr.0 % 4096, 0);
            assert_eq!(load.offset.0 % 4096, 0);
            assert_eq!(load.file_size, load.memory_size);
            let prefix = (image.entry.0 % 4096) as usize;
            assert!(
                output.bytes()[load.offset.0 as usize..load.offset.0 as usize + prefix]
                    .iter()
                    .all(|b| *b == 0)
            );
        }
    }
}

#[test]
fn rela_rel_relr_and_jmprel_have_exact_widths_counts_and_zero_fill_ownership() {
    let tags = [
        (7, 0x800),
        (8, 5 * 24),
        (9, 24),
        (17, 0x900),
        (18, 16),
        (19, 16),
        (36, 0xa00),
        (35, 16),
        (37, 8),
        (23, 0xb00),
        (2, 24),
        (20, 7),
        (6, 0xc00),
        (11, 24),
        (0x6fff_fff9, 1),
    ];
    let mut bytes = fixture(3, 0, false, &tags);
    for (index, (target, kind, symbol)) in [
        (0x2800, 8, 0),
        (0x2808, 6, 1),
        (0x2810, 36, 1),
        (0x2870, 37, 0),
        (0x3008, 8, 0),
    ]
    .into_iter()
    .enumerate()
    {
        rela(&mut bytes, 0x800 + index * 24, target, kind, symbol);
    }
    put64(&mut bytes, 0x900, 0x2830);
    put64(&mut bytes, 0x908, 2);
    put64(&mut bytes, 0xa00, 0x2840);
    put64(&mut bytes, 0xa08, 0b1011);
    rela(&mut bytes, 0xb00, 0x2868, 7, 1);
    let inventory = inspect(&bytes).unwrap();
    assert_eq!(inventory.relocation_records, 9);
    assert_eq!(inventory.writes.len(), 10);
    let actual: Vec<_> = inventory
        .writes
        .iter()
        .map(|write| {
            (
                write.range.start().0,
                write.range.len(),
                write.file.map(|file| file.start().0),
            )
        })
        .collect();
    assert_eq!(
        actual,
        vec![
            (0x2800, 8, Some(0x2800)),
            (0x2808, 8, Some(0x2808)),
            (0x2810, 16, Some(0x2810)),
            (0x2870, 8, Some(0x2870)),
            (0x3008, 8, None),
            (0x2830, 4, Some(0x2830)),
            (0x2840, 8, Some(0x2840)),
            (0x2848, 8, Some(0x2848)),
            (0x2858, 8, Some(0x2858)),
            (0x2868, 8, Some(0x2868))
        ]
    );
    inventory.check_source_ranges(&[dependency()]).unwrap();
    let output = append(
        &bytes,
        0,
        &images(0),
        &[edit(&bytes)],
        &[dependency()],
        policy(),
    )
    .unwrap();
    assert_eq!(output.dynamic.writes, inventory.writes);
}

#[test]
fn every_supported_loader_write_width_is_exact_and_copy_is_not_guessed() {
    for (kind, width) in [
        (1, 8),
        (2, 4),
        (6, 8),
        (7, 8),
        (8, 8),
        (10, 4),
        (11, 4),
        (16, 8),
        (17, 8),
        (18, 8),
        (36, 16),
        (37, 8),
        (38, 8),
    ] {
        let inventory = inspect(&rela_fixture(kind, 0x2800)).unwrap();
        assert_eq!(inventory.writes.len(), 1);
        assert_eq!(inventory.writes[0].range.len(), width);
    }
    assert!(
        inspect(&rela_fixture(0, u64::MAX))
            .unwrap()
            .writes
            .is_empty()
    );
    for kind in [5, 35, 43, u32::MAX] {
        assert!(
            matches!(inspect(&rela_fixture(kind, 0x2800)), Err(dynamic::Error::UnsupportedRelocation { kind: got }) if got == kind)
        );
    }
}

#[test]
fn relocation_in_unchanged_successor_or_padding_is_a_dependency_refusal() {
    let bytes = rela_fixture(8, 0x1104);
    // Only byte zero changes, but the consumed/relocated original footprint is
    // eight bytes. The loader's field intersects unchanged successor bytes.
    let item = DeclaredEdit {
        offset: FileOffset(0x1100),
        expected: vec![0x90],
        replacement: vec![0xe9],
    };
    assert!(matches!(
        append(&bytes, 0, &images(0), &[item], &[dependency()], policy()),
        Err(Error::Dynamic(dynamic::Error::SourceRelocation {
            dependency: 0,
            write: 0
        }))
    ));
    assert!(matches!(
        append(&bytes, 0, &images(0), &[], &[dependency()], policy()),
        Err(Error::Dynamic(dynamic::Error::SourceRelocation { .. }))
    ));
    let clean = fixture(3, 0, false, &[]);
    assert!(matches!(
        append(&clean, 0, &images(0), &[edit(&clean)], &[], policy()),
        Err(Error::MissingEditDependency { index: 0 })
    ));
}

#[test]
fn duplicate_or_partially_overlapping_loader_writes_refuse() {
    for second in [0x2800, 0x2804] {
        let mut bytes = fixture(3, 0, false, &[(7, 0x800), (8, 48), (9, 24)]);
        rela(&mut bytes, 0x800, 0x2800, 8, 0);
        rela(&mut bytes, 0x818, second, 8, 0);
        assert!(matches!(
            inspect(&bytes),
            Err(dynamic::Error::DuplicateWrite {
                first: 0,
                second: 1
            })
        ));
    }
    let mut bytes = fixture(
        3,
        0,
        false,
        &[(7, 0x800), (8, 24), (9, 24), (23, 0x800), (2, 24), (20, 7)],
    );
    rela(&mut bytes, 0x800, 0x2800, 7, 0);
    assert!(matches!(inspect(&bytes), Err(dynamic::Error::TableOverlap)));
}

#[test]
fn unmapped_cross_boundary_and_overflowing_loader_fields_refuse() {
    for target in [0x4000, 0x2ffc, 0x3ffc, u64::MAX - 3] {
        assert!(matches!(
            inspect(&rela_fixture(8, target)),
            Err(dynamic::Error::Elf(_))
        ));
    }
    let mut bytes = rela_fixture(8, 0x2800);
    put64(&mut bytes, 0x808, (1_u64 << 32) | 8);
    assert!(matches!(
        inspect(&bytes),
        Err(dynamic::Error::InvalidRelocation { kind: 8 })
    ));
    let mut bytes = fixture(
        3,
        0,
        false,
        &[(7, 0x800), (8, 24), (9, 24), (0x6fff_fff9, 1)],
    );
    rela(&mut bytes, 0x800, 0x2800, 6, 0);
    assert!(matches!(
        inspect(&bytes),
        Err(dynamic::Error::InvalidRelocation { kind: 6 })
    ));
}

#[test]
fn relr_bitmap_anchor_alignment_order_overflow_and_expansion_are_checked() {
    for words in [vec![3], vec![0x2802], vec![0x2800, 0x27f8]] {
        let mut bytes = fixture(
            3,
            0,
            false,
            &[(36, 0xa00), (35, words.len() as u64 * 8), (37, 8)],
        );
        for (index, word) in words.into_iter().enumerate() {
            put64(&mut bytes, 0xa00 + index * 8, word);
        }
        assert!(matches!(inspect(&bytes), Err(dynamic::Error::InvalidRelr)));
    }
    let mut bytes = fixture(3, 0, false, &[(36, 0xa00), (35, 16), (37, 8)]);
    put64(&mut bytes, 0xa00, 0x2800);
    put64(&mut bytes, 0xa08, u64::MAX);
    assert_eq!(inspect(&bytes).unwrap().writes.len(), 64);
    assert!(matches!(
        dynamic::inspect(
            &parse(&bytes),
            dynamic::Limits {
                relocation_writes: 63,
                ..dynamic::Limits::default()
            }
        ),
        Err(dynamic::Error::Budget {
            resource: "relocation writes",
            limit: 63
        })
    ));
    let high = u64::MAX - 4095;
    for (field, value) in [(16, high), (24, high), (32, 4095), (40, 4095)] {
        put64(&mut bytes, 64 + 3 * 56 + field, value);
    }
    for field in [16, 24] {
        put64(&mut bytes, 64 + 4 * 56 + field, high + 0x200);
    }
    put64(&mut bytes, 0xa00, u64::MAX - 15);
    put64(&mut bytes, 0xa08, 1);
    assert!(matches!(inspect(&bytes), Err(dynamic::Error::Arithmetic)));
}

#[test]
fn dynamic_tag_shapes_termination_and_unknown_formats_fail_closed() {
    for (tags, expected) in [
        (vec![(7, 0x800)], dynamic::Error::InvalidTags { tag: 7 }),
        (
            vec![(7, 0x800), (8, 24), (9, 16)],
            dynamic::Error::InvalidTags { tag: 7 },
        ),
        (
            vec![(7, 0x800), (8, 25), (9, 24)],
            dynamic::Error::InvalidTags { tag: 7 },
        ),
        (
            vec![(7, 0x800), (7, 0x800)],
            dynamic::Error::DuplicateTag { tag: 7 },
        ),
        (
            vec![(0x6000_000f, 0x800)],
            dynamic::Error::UnsupportedTag { tag: 0x6000_000f },
        ),
        (vec![(22, 0)], dynamic::Error::UnsupportedTextRelocations),
        (vec![(30, 4)], dynamic::Error::UnsupportedTextRelocations),
        (
            vec![(23, 0xb00), (2, 16), (20, 99)],
            dynamic::Error::InvalidTags { tag: 23 },
        ),
    ] {
        assert!(matches!(inspect(&fixture(3, 0, false, &tags)), Err(error) if error == expected));
    }
    let mut bytes = fixture(3, 0, false, &[]);
    put64(&mut bytes, 0x2200, 24);
    assert!(matches!(
        inspect(&bytes),
        Err(dynamic::Error::MissingTerminator)
    ));
    let mut bytes = fixture(3, 0, false, &[]);
    put32(&mut bytes, 64 + 5 * 56, 2);
    assert!(matches!(
        inspect(&bytes),
        Err(dynamic::Error::MultipleDynamicSegments)
    ));
}

#[test]
fn dynamic_metadata_cannot_hide_in_executable_or_zero_fill_storage() {
    assert!(matches!(
        inspect(&fixture(3, 0, false, &[(5, 0x1100), (10, 8)])),
        Err(dynamic::Error::MetadataInExecutableLoad { index: 2 })
    ));
    assert!(matches!(
        inspect(&fixture(3, 0, false, &[(5, 0x3000), (10, 8)])),
        Err(dynamic::Error::MetadataNotFileBacked)
    ));
    let mut bytes = fixture(
        3,
        0,
        false,
        &[
            (5, 0xd00),
            (10, 8),
            (6, 0xc00),
            (11, 24),
            (4, 0xe00),
            (0x6fff_fef5, 0xe20),
            (0x6fff_fff0, 0xe40),
        ],
    );
    // The original ownership-only fixture used zero placeholder hash headers.
    // Give the retained positive valid bounded empty inventories for the new
    // complete-extent proof: one undefined symbol, no named hash buckets.
    put32(&mut bytes, 0xe00, 1);
    put32(&mut bytes, 0xe04, 1);
    put32(&mut bytes, 0xe20, 1);
    put32(&mut bytes, 0xe24, 1);
    put32(&mut bytes, 0xe28, 1);
    put32(&mut bytes, 0xe2c, 5);
    let inventory = inspect(&bytes).unwrap();
    assert_eq!(
        inventory.protected,
        vec![
            FileRange::checked(FileOffset(0), 0x1000).unwrap(),
            FileRange::checked(FileOffset(0x2000), 0x1000).unwrap()
        ]
    );
    assert!(matches!(
        inventory.check_source_ranges(&[FileRange::checked(FileOffset(0xef0), 1).unwrap()]),
        Err(dynamic::Error::SourceMetadata { dependency: 0 })
    ));
}

#[test]
fn dynamic_entry_and_record_limits_are_prospective() {
    let bytes = rela_fixture(8, 0x2800);
    for (limits, resource, limit) in [
        (
            dynamic::Limits {
                dynamic_entries: 3,
                ..dynamic::Limits::default()
            },
            "dynamic entries",
            3,
        ),
        (
            dynamic::Limits {
                relocation_records: 0,
                ..dynamic::Limits::default()
            },
            "relocation records",
            0,
        ),
        (
            dynamic::Limits {
                relocation_writes: 0,
                ..dynamic::Limits::default()
            },
            "relocation writes",
            0,
        ),
    ] {
        assert!(
            matches!(dynamic::inspect(&parse(&bytes), limits), Err(dynamic::Error::Budget { resource: got, limit: got_limit }) if got == resource && got_limit == limit)
        );
    }
}

#[test]
fn images_cannot_overlap_original_bss_other_images_or_ro_carrier() {
    let bytes = fixture(3, 0, false, &[]);
    for entry in [0x1000, 0x3000, 0x6001] {
        assert!(matches!(
            append(
                &bytes,
                0,
                &[RxImage {
                    entry: ElfVaddr(entry),
                    bytes: vec![0xc3]
                }],
                &[],
                &[],
                policy()
            ),
            Err(Error::InvalidImage { .. })
        ));
    }
    let mut items = images(0);
    items[1].entry = ElfVaddr(0x9008);
    assert!(matches!(
        append(&bytes, 0, &items, &[], &[], policy()),
        Err(Error::InvalidImage { .. })
    ));
    items = images(0);
    items[0].bytes.clear();
    assert!(matches!(
        append(&bytes, 0, &items, &[], &[], policy()),
        Err(Error::InvalidImage { index: 0 })
    ));
    assert!(
        append(
            &bytes,
            0,
            &[RxImage {
                entry: ElfVaddr(u64::MAX),
                bytes: vec![1, 2]
            }],
            &[],
            &[],
            policy()
        )
        .is_err()
    );
}

#[test]
fn image_page_count_and_file_span_budgets_are_exact() {
    let bytes = fixture(3, 0, false, &[]);
    let items = images(0);
    let exact = ImagePolicy {
        max_images: 2,
        max_new_load_pages: 3,
        layout: CarrierPolicy {
            max_output_file_bytes: 0x5009,
            max_added_file_bytes: 0x2009,
            max_virtual_span: 0xa000,
            ..policy().layout
        },
        ..policy()
    };
    let output = append(&bytes, 0, &items, &[], &[], exact).unwrap();
    assert_eq!(output.new_load_pages, 3);
    assert_eq!(output.bytes().len(), 0x5009);
    for modified in [
        ImagePolicy {
            max_images: 1,
            ..exact
        },
        ImagePolicy {
            max_new_load_pages: 2,
            ..exact
        },
        ImagePolicy {
            layout: CarrierPolicy {
                max_output_file_bytes: 0x5008,
                ..exact.layout
            },
            ..exact
        },
        ImagePolicy {
            layout: CarrierPolicy {
                max_virtual_span: 0x9fff,
                ..exact.layout
            },
            ..exact
        },
    ] {
        assert!(matches!(
            append(&bytes, 0, &items, &[], &[], modified),
            Err(Error::Budget { .. })
        ));
    }
}

#[test]
fn interpreter_shape_order_and_gnu_property_remain_explicit_requirements() {
    let mut bytes = fixture(3, 0, true, &[]);
    bytes[0x606] = b'x';
    assert!(matches!(
        append(&bytes, 0, &[], &[], &[], policy()),
        Err(Error::InvalidInterpreter)
    ));
    let mut bytes = fixture(3, 0, true, &[]);
    let interp = bytes[120..176].to_vec();
    let late = 64 + 6 * 56;
    let stack = bytes[late..late + 56].to_vec();
    bytes[120..176].copy_from_slice(&stack);
    bytes[late..late + 56].copy_from_slice(&interp);
    assert!(matches!(
        append(&bytes, 0, &[], &[], &[], policy()),
        Err(Error::InvalidInterpreter)
    ));
    let mut bytes = fixture(3, 0, false, &[]);
    put32(&mut bytes, 64 + 5 * 56, 0x6474_e553);
    assert!(matches!(
        append(&bytes, 0, &[], &[], &[], policy()),
        Err(Error::UnsupportedSegment {
            kind: SegmentType::GnuProperty,
            ..
        })
    ));
}

#[test]
fn appended_image_pages_cannot_cover_original_declared_metadata_memory() {
    let mut bytes = fixture(3, 0, false, &[]);
    encode_phdr(
        &mut bytes,
        64 + 5 * 56,
        EncodedHeader {
            kind: 4,
            flags: 4,
            offset: 0x600,
            vaddr: 0x9000,
            file_size: 16,
            memory_size: 16,
            alignment: 8,
        },
    )
    .unwrap();
    assert!(matches!(
        append(&bytes, 0, &images(0), &[], &[], policy()),
        Err(Error::CarrierMetadataOverlap { index: 5 })
    ));
    assert!(matches!(
        append(
            &fixture(3, 0, false, &[]),
            0,
            &images(0),
            &[],
            &[FileRange::checked(FileOffset(0x2800), 8).unwrap()],
            policy()
        ),
        Err(Error::InvalidDependency { index: 0 })
    ));
}

#[test]
fn dynamic_string_and_symbol_metadata_is_explicit_and_bounded() {
    assert!(matches!(
        inspect(&fixture(3, 0, false, &[(1, 0)])),
        Err(dynamic::Error::InvalidTags { tag: 5 })
    ));
    let mut bytes = fixture(3, 0, false, &[(1, 0), (1, 4), (5, 0xd00), (10, 8)]);
    bytes[0xd00..0xd08].copy_from_slice(b"one\0two\0");
    assert!(inspect(&bytes).is_ok());
    bytes[0xd07] = b'x';
    assert!(matches!(
        inspect(&bytes),
        Err(dynamic::Error::InvalidTags { tag: 5 })
    ));
    let mut bytes = rela_fixture(6, 0x2800);
    put64(&mut bytes, 0x808, (1_u64 << 32) | 6);
    assert!(matches!(
        inspect(&bytes),
        Err(dynamic::Error::InvalidTags { tag: 6 })
    ));
}

// Prospective additive test for carrier image_fixtures.rs's existing helpers.
// Required result is refusal. At reviewed dynamic.rs 960a0f16, source inspection
// finds the SYMTAB check authenticates only entry zero; no Rust run is claimed.
#[test]
fn loader_symbol_record_cannot_hide_across_ro_rx_owner_boundary() {
    let mut bytes = fixture(
        3,
        0,
        false,
        &[
            (5, 0xd00),
            (10, 3),
            (6, 0xfe8),
            (11, 24),
            (7, 0x800),
            (8, 24),
            (9, 24),
        ],
    );
    bytes[0xd00..0xd03].copy_from_slice(b"\0x\0");
    // Entry zero [0xfe8,0x1000) is wholly readable non-executable metadata.
    // Referenced entry one [0x1000,0x1018) belongs to the next executable LOAD.
    put32(&mut bytes, 0x1000, 1); // st_name = "x"
    bytes[0x1004] = 0x10; // GLOBAL, NOTYPE, undefined reference
    rela(&mut bytes, 0x800, 0x2800, 6, 1); // GLOB_DAT, symbol 1
    let original = bytes.clone();
    let dependency = FileRange::checked(FileOffset(0x1000), 24).unwrap();
    let edit = DeclaredEdit {
        offset: FileOffset(0x1000),
        expected: bytes[0x1000..0x1005].to_vec(),
        replacement: vec![0x90; 5],
    };
    // A complete ownership proof may refuse during table inspection or when
    // checking dependencies; no acceptance/suppressed edit is a valid outcome.
    assert!(append(&bytes, 0, &images(0), &[edit], &[dependency], policy()).is_err());
    assert_eq!(bytes, original);
}

fn boundary_refuses_without_source_change(bytes: &[u8], length: u64) {
    let saved = bytes.to_vec();
    let dependency = FileRange::checked(FileOffset(0x1000), length).unwrap();
    let edit = DeclaredEdit {
        offset: FileOffset(0x1000),
        expected: bytes[0x1000..0x1001].to_vec(),
        replacement: vec![0x90],
    };
    assert!(append(bytes, 0, &images(0), &[edit], &[dependency], policy()).is_err());
    assert_eq!(bytes, saved);
}

#[test]
fn sysv_hash_buckets_and_chains_cannot_cross_into_executable_source() {
    let mut bytes = fixture(3, 0, false, &[(4, 0xff8), (6, 0xc00), (11, 24)]);
    put32(&mut bytes, 0xff8, 1);
    put32(&mut bytes, 0xffc, 2);
    assert!(matches!(inspect(&bytes), Err(dynamic::Error::Elf(_))));
    boundary_refuses_without_source_change(&bytes, 12);
}

#[test]
fn gnu_hash_bloom_buckets_and_chains_cannot_cross_into_executable_source() {
    let mut bytes = fixture(3, 0, false, &[(0x6fff_fef5, 0xff0), (6, 0xc00), (11, 24)]);
    for (offset, value) in [
        (0xff0, 1),
        (0xff4, 1),
        (0xff8, 1),
        (0xffc, 5),
        (0x1008, 1),
        (0x100c, 1),
    ] {
        put32(&mut bytes, offset, value);
    }
    assert!(matches!(inspect(&bytes), Err(dynamic::Error::Elf(_))));
    boundary_refuses_without_source_change(&bytes, 16);
    // A second geometry keeps the fixed header/bloom/bucket entirely in R;
    // the nonterminating first chain word leads to a second word in RX.
    let mut bytes = fixture(3, 0, false, &[(0x6fff_fef5, 0xfe0), (6, 0xc00), (11, 24)]);
    for (offset, value) in [
        (0xfe0, 1),
        (0xfe4, 1),
        (0xfe8, 1),
        (0xfec, 5),
        (0xff8, 1),
        (0x1000, 1),
    ] {
        put32(&mut bytes, offset, value);
    }
    assert!(matches!(
        inspect(&bytes),
        Err(dynamic::Error::MetadataInExecutableLoad { index: 2 })
    ));
    boundary_refuses_without_source_change(&bytes, 4);
}

#[test]
fn versym_full_symbol_inventory_cannot_cross_into_executable_source() {
    let mut bytes = fixture(
        3,
        0,
        false,
        &[(4, 0xe00), (6, 0xc00), (11, 24), (0x6fff_fff0, 0xffe)],
    );
    put32(&mut bytes, 0xe00, 1);
    put32(&mut bytes, 0xe04, 2);
    assert!(matches!(inspect(&bytes), Err(dynamic::Error::Elf(_))));
    boundary_refuses_without_source_change(&bytes, 2);
    let mut bytes = fixture(
        3,
        0,
        false,
        &[(4, 0xe00), (6, 0xc00), (11, 24), (34, 0xffc)],
    );
    put32(&mut bytes, 0xe00, 1);
    put32(&mut bytes, 0xe04, 2);
    assert!(matches!(inspect(&bytes), Err(dynamic::Error::Elf(_))));
    boundary_refuses_without_source_change(&bytes, 4);
}

#[test]
fn verdef_auxiliary_chain_cannot_hide_in_executable_source() {
    let mut bytes = fixture(
        3,
        0,
        false,
        &[(5, 0xd00), (10, 3), (0x6fff_fffc, 0xfec), (0x6fff_fffd, 1)],
    );
    bytes[0xd00..0xd03].copy_from_slice(b"\0x\0");
    put16(&mut bytes, 0xfec, 1);
    put16(&mut bytes, 0xff2, 1);
    put32(&mut bytes, 0xff8, 20);
    put32(&mut bytes, 0x1000, 1);
    put32(&mut bytes, 0x1004, 0);
    assert!(matches!(
        inspect(&bytes),
        Err(dynamic::Error::MetadataInExecutableLoad { index: 2 })
    ));
    boundary_refuses_without_source_change(&bytes, 8);
}

#[test]
fn verneed_auxiliary_chain_cannot_hide_in_executable_source() {
    let mut bytes = fixture(
        3,
        0,
        false,
        &[(5, 0xd00), (10, 3), (0x6fff_fffe, 0xff0), (0x6fff_ffff, 1)],
    );
    bytes[0xd00..0xd03].copy_from_slice(b"\0x\0");
    put16(&mut bytes, 0xff0, 1);
    put16(&mut bytes, 0xff2, 1);
    put32(&mut bytes, 0xff4, 1);
    put32(&mut bytes, 0xff8, 16);
    put32(&mut bytes, 0x1008, 1);
    put32(&mut bytes, 0x100c, 0);
    assert!(matches!(
        inspect(&bytes),
        Err(dynamic::Error::MetadataInExecutableLoad { index: 2 })
    ));
    boundary_refuses_without_source_change(&bytes, 16);
}

#[test]
fn complete_hash_symbol_and_version_extents_retain_a_real_positive() {
    let tags = [
        (7, 0x800),
        (8, 24),
        (9, 24),
        (4, 0xe00),
        (0x6fff_fef5, 0xe20),
        (6, 0xc00),
        (11, 24),
        (5, 0xd00),
        (10, 8),
        (34, 0xe60),
        (0x6fff_fff0, 0xe50),
        (0x6fff_fffc, 0xe80),
        (0x6fff_fffd, 1),
        (0x6fff_fffe, 0xec0),
        (0x6fff_ffff, 1),
    ];
    let mut bytes = fixture(3, 0, false, &tags);
    bytes[0xd00..0xd08].copy_from_slice(b"\0x\0v\0f\0\0");
    put32(&mut bytes, 0xc18, 1);
    put32(&mut bytes, 0xc30, 3);
    for (at, value) in [
        (0xe00, 1),
        (0xe04, 3),
        (0xe08, 1),
        (0xe10, 2),
        (0xe20, 1),
        (0xe24, 1),
        (0xe28, 1),
        (0xe2c, 5),
        (0xe38, 1),
        (0xe40, 1),
    ] {
        put32(&mut bytes, at, value);
    }
    put16(&mut bytes, 0xe80, 1);
    put16(&mut bytes, 0xe84, 2);
    put16(&mut bytes, 0xe86, 1);
    put32(&mut bytes, 0xe8c, 20);
    put32(&mut bytes, 0xe94, 3);
    put16(&mut bytes, 0xec0, 1);
    put16(&mut bytes, 0xec2, 1);
    put32(&mut bytes, 0xec4, 5);
    put32(&mut bytes, 0xec8, 16);
    put16(&mut bytes, 0xed6, 3);
    put32(&mut bytes, 0xed8, 3);
    rela(&mut bytes, 0x800, 0x2800, 6, 2);
    let output = append(
        &bytes,
        0,
        &images(0),
        &[edit(&bytes)],
        &[dependency()],
        policy(),
    )
    .unwrap();
    assert_eq!(output.images.len(), 2);
    assert_eq!(output.dynamic.writes.len(), 1);
    assert_eq!(
        output.dynamic.protected,
        vec![
            FileRange::checked(FileOffset(0), 0x1000).unwrap(),
            FileRange::checked(FileOffset(0x2000), 0x1000).unwrap()
        ]
    );
    let mut bad = bytes.clone();
    put64(&mut bad, 0x808, (3_u64 << 32) | 6);
    assert!(matches!(
        inspect(&bad),
        Err(dynamic::Error::InvalidMetadata { tag: 6 })
    ));
    let mut bad = bytes.clone();
    put32(&mut bad, 0xc30, 8);
    assert!(matches!(
        inspect(&bad),
        Err(dynamic::Error::InvalidMetadata { tag: 6 })
    ));
    let mut bad = bytes.clone();
    put32(&mut bad, 0xe98, 8);
    assert!(matches!(
        inspect(&bad),
        Err(dynamic::Error::InvalidMetadata { tag: 0x6fff_fffc })
    ));
}

#[test]
fn metadata_work_is_aggregate_across_repeated_hash_bucket_walks() {
    let mut bytes = fixture(3, 0, false, &[(0x6fff_fef5, 0xe20), (6, 0xc00), (11, 24)]);
    for (at, value) in [
        (0xe20, 3),
        (0xe24, 1),
        (0xe28, 1),
        (0xe2c, 5),
        (0xe38, 1),
        (0xe3c, 1),
        (0xe40, 1),
        (0xe48, 1),
    ] {
        put32(&mut bytes, at, value);
    }
    assert!(inspect(&bytes).is_ok());
    assert!(matches!(
        dynamic::inspect(
            &parse(&bytes),
            dynamic::Limits {
                metadata_records: 8,
                ..dynamic::Limits::default()
            }
        ),
        Err(dynamic::Error::Budget {
            resource: "metadata records",
            limit: 8
        })
    ));
    assert!(matches!(
        dynamic::inspect(
            &parse(&bytes),
            dynamic::Limits {
                metadata_bytes: 80,
                ..dynamic::Limits::default()
            }
        ),
        Err(dynamic::Error::Budget {
            resource: "metadata bytes",
            limit: 80
        })
    ));
    put32(&mut bytes, 0xe48, 0);
    assert!(matches!(
        dynamic::inspect(
            &parse(&bytes),
            dynamic::Limits {
                metadata_records: 8,
                ..dynamic::Limits::default()
            }
        ),
        Err(dynamic::Error::Budget {
            resource: "metadata records",
            limit: 8
        })
    ));
}

// Additive to image_fixtures.rs. A zero-width relocation can still select
// dynamic metadata before machine-specific no-op handling. No native execution
// is claimed by this source-review fixture.
#[test]
fn zero_write_relocation_cannot_hide_version_read_in_executable_source() {
    let mut bytes = fixture(
        3,
        0,
        false,
        &[
            (6, 0xc00),
            (11, 24),
            (0x6fff_fff0, 0xffe),
            (7, 0x800),
            (8, 24),
            (9, 24),
        ],
    );
    // R_X86_64_NONE does not write r_offset, but the generic glibc versioned
    // relocation loop selects VERSYM[R_SYM] before architecture dispatch.
    // Both symbols fit in R; VERSYM[0] fits at 0xffe, VERSYM[1] is in RX.
    rela(&mut bytes, 0x800, 0x2800, 0, 1);
    let original = bytes.clone();
    let dependency = FileRange::checked(FileOffset(0x1000), 2).unwrap();
    let edit = DeclaredEdit {
        offset: FileOffset(0x1000),
        expected: bytes[0x1000..0x1002].to_vec(),
        replacement: vec![0x90, 0x90],
    };
    assert!(append(&bytes, 0, &images(0), &[edit], &[dependency], policy()).is_err());
    assert_eq!(bytes, original);
}

#[test]
fn zero_write_all_formats_preserve_bounded_symbol_references_and_valid_ownership() {
    for (table, descriptor) in [
        (dynamic::TableKind::Rela, vec![(7, 0x800), (8, 24), (9, 24)]),
        (
            dynamic::TableKind::Rel,
            vec![(17, 0x800), (18, 16), (19, 16)],
        ),
        (
            dynamic::TableKind::JumpRela,
            vec![(23, 0x800), (2, 24), (20, 7)],
        ),
        (
            dynamic::TableKind::JumpRel,
            vec![(23, 0x800), (2, 16), (20, 17)],
        ),
    ] {
        let mut tags = vec![(6, 0xc00), (11, 24), (0x6fff_fff0, 0xe00)];
        tags.extend_from_slice(&descriptor);
        let mut bytes = fixture(3, 0, false, &tags);
        // The no-write target is deliberately invalid; it must not be invented
        // as a loader write. Symbol 1 still requires both complete metadata rows.
        rela(&mut bytes, 0x800, u64::MAX, 0, 1);
        let limits = dynamic::Limits {
            relocation_writes: 0,
            ..dynamic::Limits::default()
        };
        let inventory = dynamic::inspect(&parse(&bytes), limits).unwrap();
        assert_eq!(inventory.relocation_records, 1);
        assert!(inventory.writes.is_empty());
        assert_eq!(
            inventory.symbol_references,
            vec![dynamic::SymbolReference {
                table,
                record: 0,
                kind: 0,
                symbol: 1
            }]
        );
        assert!(
            inventory
                .protected
                .iter()
                .any(|owner| owner.start().0 <= 0xc00 && owner.end().0 >= 0xc30)
        );
        assert!(
            inventory
                .protected
                .iter()
                .any(|owner| owner.start().0 <= 0xe00 && owner.end().0 >= 0xe04)
        );
        let output = append(
            &bytes,
            0,
            &images(0),
            &[edit(&bytes)],
            &[dependency()],
            policy(),
        )
        .unwrap();
        assert!(output.dynamic.writes.is_empty());
        assert_eq!(
            output.dynamic.symbol_references,
            inventory.symbol_references
        );
        let original = bytes.clone();
        // Mutate only DT_SYMTAB's pointer; symbol zero remains in R, but the
        // required second symbol would enter RX. This catches prefix undercount.
        let mut crossing = bytes.clone();
        put64(&mut crossing, 0x2208, 0xfe8);
        assert!(inspect(&crossing).is_err());
        let mut bounded = limits;
        bounded.relocation_records = 0;
        assert!(matches!(
            dynamic::inspect(&parse(&bytes), bounded),
            Err(dynamic::Error::Budget {
                resource: "relocation records",
                limit: 0
            })
        ));
        assert_eq!(bytes, original);
    }
}

#[test]
fn zero_write_symbol_indices_cannot_expand_complete_hash_or_evade_metadata_budget() {
    let mut bytes = fixture(
        3,
        0,
        false,
        &[
            (6, 0xc00),
            (11, 24),
            (0x6fff_fff0, 0xe00),
            (4, 0xd00),
            (7, 0x800),
            (8, 24),
            (9, 24),
        ],
    );
    rela(&mut bytes, 0x800, u64::MAX, 0, 1);
    put32(&mut bytes, 0xd00, 1);
    put32(&mut bytes, 0xd04, 1);
    assert!(matches!(
        inspect(&bytes),
        Err(dynamic::Error::InvalidMetadata { tag: 6 })
    ));
    put32(&mut bytes, 0xd04, 2);
    let inventory = inspect(&bytes).unwrap();
    assert_eq!(inventory.symbol_references[0].symbol, 1);
    assert!(inventory.writes.is_empty());
    let bounded = dynamic::Limits {
        metadata_records: 1,
        ..dynamic::Limits::default()
    };
    assert!(matches!(
        dynamic::inspect(&parse(&bytes), bounded),
        Err(dynamic::Error::Budget {
            resource: "metadata records",
            limit: 1
        })
    ));
    let mut missing = fixture(3, 0, false, &[(7, 0x800), (8, 24), (9, 24)]);
    rela(&mut missing, 0x800, u64::MAX, 0, 1);
    assert!(matches!(
        inspect(&missing),
        Err(dynamic::Error::InvalidTags { tag: 6 })
    ));
}

#[test]
fn mixed_relocation_reference_inventory_is_ordered_and_distinct_from_writes() {
    let mut bytes = fixture(
        3,
        0,
        false,
        &[
            (6, 0xc00),
            (11, 24),
            (0x6fff_fff0, 0xe00),
            (7, 0x800),
            (8, 48),
            (9, 24),
            (17, 0x900),
            (18, 16),
            (19, 16),
            (36, 0xa00),
            (35, 8),
            (37, 8),
            (23, 0xb00),
            (2, 24),
            (20, 7),
        ],
    );
    rela(&mut bytes, 0x800, u64::MAX, 0, 2);
    rela(&mut bytes, 0x818, 0x2800, 6, 1);
    rela(&mut bytes, 0x900, u64::MAX, 0, 3);
    put64(&mut bytes, 0xa00, 0x2900);
    rela(&mut bytes, 0xb00, u64::MAX, 0, 4);
    let inventory = inspect(&bytes).unwrap();
    assert_eq!(inventory.relocation_records, 5);
    assert_eq!(inventory.writes.len(), 2);
    assert_eq!(
        inventory.symbol_references,
        vec![
            dynamic::SymbolReference {
                table: dynamic::TableKind::Rela,
                record: 0,
                kind: 0,
                symbol: 2
            },
            dynamic::SymbolReference {
                table: dynamic::TableKind::Rela,
                record: 1,
                kind: 6,
                symbol: 1
            },
            dynamic::SymbolReference {
                table: dynamic::TableKind::Rel,
                record: 0,
                kind: 0,
                symbol: 3
            },
            dynamic::SymbolReference {
                table: dynamic::TableKind::JumpRela,
                record: 0,
                kind: 0,
                symbol: 4
            },
        ]
    );
    assert_eq!(inventory.writes[0].table, dynamic::TableKind::Rela);
    assert_eq!(inventory.writes[1].table, dynamic::TableKind::Relr);
    assert!(
        inventory
            .protected
            .iter()
            .any(|owner| owner.start().0 <= 0xc00 && owner.end().0 >= 0xc78)
    );
}
