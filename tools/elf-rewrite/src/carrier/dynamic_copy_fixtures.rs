//! Pure byte fixtures for the bounded COPY destination profile; no loader run.
use super::super::{
    CarrierPolicy, DeclaredEdit, ImagePolicy, ImageRequest, RxImage, append_carrier_with_images,
};
use super::*;
use elf64::{FileOffset, ParseLimits};

const BASE: u64 = 0x400000;
const RELOC: usize = 0x800;
const SYMBOL: usize = 0xc00;
const VERSION: usize = 0xd00;
const HASH: usize = 0xd40;
const STRINGS: usize = 0xe00;
const NEED: usize = 0xe80;
const DYNAMIC: usize = 0x2200;

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn header(
    bytes: &mut [u8],
    index: usize,
    kind: u32,
    flags: u32,
    offset: u64,
    size: u64,
    memory: u64,
) {
    let at = 64 + index * 56;
    put32(bytes, at, kind);
    put32(bytes, at + 4, flags);
    put64(bytes, at + 8, offset);
    put64(bytes, at + 16, BASE + offset);
    put64(bytes, at + 24, BASE + offset);
    put64(bytes, at + 32, size);
    put64(bytes, at + 40, memory);
    put64(bytes, at + 48, if kind == 1 { 4096 } else { 8 });
}
fn tag(bytes: &mut [u8], index: usize, kind: u64, value: u64) {
    put64(bytes, DYNAMIC + index * 16, kind);
    put64(bytes, DYNAMIC + index * 16 + 8, value);
}
fn fixture(destinations: &[(u64, u64)]) -> Vec<u8> {
    assert!(!destinations.is_empty() && destinations.len() <= 3);
    let mut bytes = vec![0; 0x3000];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, BASE + 0x1100);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 4);
    header(&mut bytes, 0, 1, 4, 0, 0x1000, 0x1000);
    header(&mut bytes, 1, 1, 5, 0x1000, 0x1000, 0x1000);
    header(&mut bytes, 2, 1, 6, 0x2000, 0x1000, 0x2000);
    header(&mut bytes, 3, 2, 6, DYNAMIC as u64, 12 * 16, 12 * 16);
    let strings = b"\0copy_a\0copy_b\0libfixture.so\0COPY_1\0";
    bytes[STRINGS..STRINGS + strings.len()].copy_from_slice(strings);
    let tags = [
        (6, BASE + SYMBOL as u64),
        (11, 24),
        (5, BASE + STRINGS as u64),
        (10, strings.len() as u64),
        (4, BASE + HASH as u64),
        (0x6fff_fff0, BASE + VERSION as u64),
        (0x6fff_fffe, BASE + NEED as u64),
        (0x6fff_ffff, 1),
        (7, BASE + RELOC as u64),
        (8, destinations.len() as u64 * 24),
        (9, 24),
    ];
    for (index, &(kind, value)) in tags.iter().enumerate() {
        tag(&mut bytes, index, kind, value);
    }
    put32(&mut bytes, HASH, 1);
    put32(&mut bytes, HASH + 4, destinations.len() as u32 + 1);
    put16(&mut bytes, NEED, 1);
    put16(&mut bytes, NEED + 2, 1);
    put32(&mut bytes, NEED + 4, 15);
    put32(&mut bytes, NEED + 8, 16);
    put16(&mut bytes, NEED + 16 + 6, 3);
    put32(&mut bytes, NEED + 16 + 8, 29);
    for (index, &(target, size)) in destinations.iter().enumerate() {
        let symbol = index + 1;
        let at = SYMBOL + symbol * 24;
        put32(&mut bytes, at, if index == 0 { 1 } else { 8 });
        bytes[at + 4] = 0x11;
        put16(&mut bytes, at + 6, 1); // No section table is required or trusted.
        put64(&mut bytes, at + 8, BASE + target);
        put64(&mut bytes, at + 16, size);
        put16(&mut bytes, VERSION + symbol * 2, 3);
        put64(&mut bytes, RELOC + index * 24, BASE + target);
        put64(
            &mut bytes,
            RELOC + index * 24 + 8,
            ((symbol as u64) << 32) | 5,
        );
    }
    bytes[0x1100..0x1108].copy_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3]);
    bytes
}
fn parse(bytes: &[u8]) -> Elf64<'_> {
    Elf64::parse(bytes, ParseLimits::default()).unwrap()
}
fn inspect(bytes: &[u8]) -> Result<Inventory, Error> {
    super::inspect(&parse(bytes), Limits::default())
}

#[test]
fn copy_size_comes_from_complete_symbol_and_unique_file_or_zero_owner() {
    for size in [1, 8, 24] {
        for target in [0x2800, 0x3008] {
            let original = fixture(&[(target, size)]);
            let saved = original.clone();
            let out = inspect(&original).unwrap();
            assert_eq!(original, saved);
            assert_eq!(out.relocation_records, 1);
            assert_eq!(
                out.symbol_references,
                vec![SymbolReference {
                    table: TableKind::Rela,
                    record: 0,
                    kind: 5,
                    symbol: 1,
                }]
            );
            assert_eq!(
                out.writes,
                vec![RelocationWrite {
                    table: TableKind::Rela,
                    record: 0,
                    kind: 5,
                    symbol: 1,
                    range: VirtualRange::checked(ElfVaddr(BASE + target), size).unwrap(),
                    file: if target == 0x2800 {
                        Some(FileRange::checked(FileOffset(target), size).unwrap())
                    } else {
                        None
                    },
                }]
            );
        }
    }
    let last_byte = fixture(&[(0x3fff, 1)]);
    assert_eq!(
        inspect(&last_byte).unwrap().writes[0].range.end().0,
        BASE + 0x4000
    );
}

#[test]
fn copy_global_and_absent_version_are_explicit_and_unknown_versions_refuse() {
    let original = fixture(&[(0x3008, 8)]);
    let mut global = original.clone();
    put16(&mut global, VERSION + 2, 1);
    assert!(inspect(&global).is_ok());
    let mut unversioned = original.clone();
    // Replace DT_VERSYM with an otherwise valid singleton DT_BIND_NOW tag.
    tag(&mut unversioned, 5, 24, 0);
    assert!(inspect(&unversioned).is_ok());
    for version in [0, 2, 4, 0x8003] {
        let mut bad = original.clone();
        put16(&mut bad, VERSION + 2, version);
        assert!(matches!(
            inspect(&bad),
            Err(Error::InvalidRelocation { kind: 5 })
        ));
    }
    for offset in [NEED + 16 + 4, NEED + 16 + 6] {
        let mut bad = original.clone();
        put16(
            &mut bad,
            offset,
            if offset == NEED + 20 { 2 } else { 0x8003 },
        );
        assert!(matches!(
            inspect(&bad),
            Err(Error::InvalidRelocation { kind: 5 })
        ));
    }
    let mut duplicate = original.clone();
    put16(&mut duplicate, NEED + 2, 2);
    put32(&mut duplicate, NEED + 16 + 12, 16);
    let second = duplicate[NEED + 16..NEED + 32].to_vec();
    duplicate[NEED + 32..NEED + 48].copy_from_slice(&second);
    put32(&mut duplicate, NEED + 32 + 12, 0);
    assert!(matches!(
        inspect(&duplicate),
        Err(Error::InvalidRelocation { kind: 5 })
    ));
    let mut also_defined = original.clone();
    // A selected index cannot name both a definition and a needed version.
    tag(&mut also_defined, 11, 0x6fff_fffc, BASE + 0xec0);
    tag(&mut also_defined, 12, 0x6fff_fffd, 1);
    header(&mut also_defined, 3, 2, 6, DYNAMIC as u64, 14 * 16, 14 * 16);
    put16(&mut also_defined, 0xec0, 1);
    put16(&mut also_defined, 0xec0 + 4, 3);
    put16(&mut also_defined, 0xec0 + 6, 1);
    put32(&mut also_defined, 0xec0 + 12, 20);
    put32(&mut also_defined, 0xec0 + 20, 29);
    assert!(matches!(
        inspect(&also_defined),
        Err(Error::InvalidRelocation { kind: 5 })
    ));
}

#[test]
fn copy_symbol_profile_size_name_and_target_are_not_guessed() {
    let original = fixture(&[(0x3008, 8)]);
    for mutation in 0..12 {
        let mut bad = original.clone();
        let at = SYMBOL + 24;
        match mutation {
            0 => put64(&mut bad, at + 16, 0),
            1 => put64(&mut bad, at + 8, BASE + 0x3010),
            2 => bad[at + 4] = 0x12, // Function, not OBJECT.
            3 => bad[at + 4] = 0x21, // WEAK is not this supported profile.
            4 => bad[at + 5] = 2,    // Hidden.
            5 => put16(&mut bad, at + 6, 0),
            6 => put16(&mut bad, at + 6, 0xfff1),
            7 => put16(&mut bad, at + 6, 0xfff2),
            8 => put16(&mut bad, at + 6, 0xffff),
            9 => put32(&mut bad, at, 0),
            10 => put32(&mut bad, at, 7), // Empty string between names.
            11 => put64(&mut bad, at + 16, u64::MAX),
            _ => unreachable!(),
        }
        assert!(inspect(&bad).is_err(), "symbol mutation {mutation}");
    }
    let mut nonzero_string_zero = original.clone();
    nonzero_string_zero[STRINGS] = b'x';
    put32(&mut nonzero_string_zero, SYMBOL + 24, 0);
    assert!(matches!(
        inspect(&nonzero_string_zero),
        Err(Error::InvalidRelocation { kind: 5 })
    ));
    let mut addend = original.clone();
    put64(&mut addend, RELOC + 16, 1);
    assert!(matches!(
        inspect(&addend),
        Err(Error::InvalidRelocation { kind: 5 })
    ));
    let mut dynamic_object = original.clone();
    put16(&mut dynamic_object, 16, 3);
    assert!(matches!(
        inspect(&dynamic_object),
        Err(Error::UnsupportedRelocation { kind: 5 })
    ));
    let mut old_invalid = original.clone();
    put16(&mut old_invalid, 16, 3);
    put64(&mut old_invalid, RELOC + 8, 5);
    assert!(matches!(
        inspect(&old_invalid),
        Err(Error::UnsupportedRelocation { kind: 5 })
    ));
    let mut zero_symbol = original.clone();
    put64(&mut zero_symbol, RELOC + 8, 5);
    assert!(matches!(
        inspect(&zero_symbol),
        Err(Error::UnsupportedRelocation { kind: 5 })
    ));
}

#[test]
fn copy_does_not_accept_rel_or_jump_table_profiles() {
    let original = fixture(&[(0x3008, 8)]);
    let mut rel = original.clone();
    tag(&mut rel, 8, 17, BASE + RELOC as u64);
    tag(&mut rel, 9, 18, 16);
    tag(&mut rel, 10, 19, 16);
    assert!(matches!(
        inspect(&rel),
        Err(Error::UnsupportedRelocation { kind: 5 })
    ));
    let mut jump = original.clone();
    tag(&mut jump, 8, 23, BASE + RELOC as u64);
    tag(&mut jump, 9, 2, 24);
    tag(&mut jump, 10, 20, 7);
    assert!(matches!(
        inspect(&jump),
        Err(Error::UnsupportedRelocation { kind: 5 })
    ));
}

#[test]
fn copy_destination_rejects_permissions_crossings_ambiguity_and_overflow() {
    for (target, size) in [(0x2ffc, 8), (0x3ffc, 8), (0x5000, 8), (0x1ffc, 8)] {
        assert!(inspect(&fixture(&[(target, size)])).is_err());
    }
    for flags in [4, 5, 7] {
        let mut bad = fixture(&[(0x3008, 8)]);
        put32(&mut bad, 64 + 2 * 56 + 4, flags);
        assert!(inspect(&bad).is_err());
    }
    let mut ambiguous = fixture(&[(0x2800, 8)]);
    put16(&mut ambiguous, 56, 5);
    header(&mut ambiguous, 4, 1, 6, 0x2800, 8, 8);
    assert!(matches!(
        inspect(&ambiguous),
        Err(Error::Elf(elf64::Error::AmbiguousVirtual { .. }))
    ));
    let mut overflow = fixture(&[(0x3008, 8)]);
    put64(&mut overflow, RELOC, u64::MAX - 3);
    put64(&mut overflow, SYMBOL + 24 + 8, u64::MAX - 3);
    assert!(matches!(inspect(&overflow), Err(Error::Elf(_))));
}

#[test]
fn copy_requires_complete_hash_symbol_string_and_version_metadata() {
    let original = fixture(&[(0x3008, 8)]);
    for mutation in 0..6 {
        let mut bad = original.clone();
        match mutation {
            0 => put32(&mut bad, HASH + 4, 1), // Selected index outside nchain.
            1 => tag(&mut bad, 0, 6, BASE + 0xfe8), // Complete symbols enter RX.
            2 => tag(&mut bad, 5, 0x6fff_fff0, BASE + 0xffe), // VERSYM[1] enters RX.
            3 => tag(&mut bad, 5, 0x6fff_fff0, BASE + 0x3008), // Metadata in BSS.
            4 => tag(&mut bad, 3, 10, 4),      // Selected names have no terminating NUL.
            5 => put32(&mut bad, NEED + 8, 0), // Invalid version auxiliary chain.
            _ => unreachable!(),
        }
        assert!(inspect(&bad).is_err(), "metadata mutation {mutation}");
    }
    let mut empty_version = original.clone();
    put32(&mut empty_version, NEED + 16 + 8, 7);
    assert!(matches!(
        inspect(&empty_version),
        Err(Error::InvalidRelocation { kind: 5 })
    ));
    let mut empty_provider = original.clone();
    put32(&mut empty_provider, NEED + 4, 7);
    assert!(matches!(
        inspect(&empty_provider),
        Err(Error::InvalidRelocation { kind: 5 })
    ));
}

#[test]
fn copy_shares_all_write_overlap_source_and_budget_checks() {
    let original = fixture(&[(0x2800, 24), (0x3008, 8), (0x2840, 8)]);
    let mut mixed = original.clone();
    put64(&mut mixed, RELOC + 2 * 24 + 8, (3_u64 << 32) | 6);
    let inventory = inspect(&mixed).unwrap();
    assert_eq!(
        inventory
            .writes
            .iter()
            .map(|r| (r.record, r.kind))
            .collect::<Vec<_>>(),
        vec![(0, 5), (1, 5), (2, 6)]
    );
    assert_eq!(inventory.writes[0].range.len(), 24);
    assert!(
        inventory
            .check_source_ranges(&[FileRange::checked(FileOffset(0x2810), 1).unwrap()])
            .is_err()
    );
    // Put all metadata in the R-only load to isolate the COPY write check.
    let mut metadata_readonly = mixed.clone();
    metadata_readonly.copy_within(DYNAMIC..DYNAMIC + 12 * 16, 0x400);
    header(&mut metadata_readonly, 3, 2, 4, 0x400, 12 * 16, 12 * 16);
    assert!(matches!(
        inspect(&metadata_readonly)
            .unwrap()
            .check_source_ranges(&[FileRange::checked(FileOffset(0x2810), 1).unwrap()]),
        Err(Error::SourceRelocation {
            dependency: 0,
            write: 0
        })
    ));
    // Deferred COPY rows retain descriptor order before RELR expansion.
    let mut with_relr = mixed.clone();
    tag(&mut with_relr, 11, 36, BASE + 0xa00);
    tag(&mut with_relr, 12, 35, 16);
    tag(&mut with_relr, 13, 37, 8);
    header(&mut with_relr, 3, 2, 6, DYNAMIC as u64, 15 * 16, 15 * 16);
    put64(&mut with_relr, 0xa00, BASE + 0x2900);
    put64(&mut with_relr, 0xa08, 3);
    assert_eq!(
        inspect(&with_relr)
            .unwrap()
            .writes
            .iter()
            .map(|r| (r.table, r.record, r.kind))
            .collect::<Vec<_>>(),
        vec![
            (TableKind::Rela, 0, 5),
            (TableKind::Rela, 1, 5),
            (TableKind::Rela, 2, 6),
            (TableKind::Relr, 0, 8),
            (TableKind::Relr, 1, 8)
        ]
    );
    assert!(matches!(
        super::inspect(
            &parse(&with_relr),
            Limits {
                relocation_writes: 4,
                ..Limits::default()
            }
        ),
        Err(Error::Budget {
            resource: "relocation writes",
            limit: 4
        })
    ));
    for second in [0x2800, 0x2808, 0x2817] {
        let overlap = fixture(&[(0x2800, 24), (second, 8)]);
        assert!(matches!(
            inspect(&overlap),
            Err(Error::DuplicateWrite {
                first: 0,
                second: 1
            })
        ));
    }
    let mut fixed_overlap = fixture(&[(0x2800, 24), (0x2810, 8)]);
    put64(&mut fixed_overlap, RELOC + 24 + 8, (2_u64 << 32) | 6);
    assert!(matches!(
        inspect(&fixed_overlap),
        Err(Error::DuplicateWrite {
            first: 0,
            second: 1
        })
    ));
    for limits in [
        Limits {
            relocation_records: 2,
            ..Limits::default()
        },
        Limits {
            relocation_writes: 2,
            ..Limits::default()
        },
        Limits {
            metadata_records: 1,
            ..Limits::default()
        },
        Limits {
            metadata_bytes: 16,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            super::inspect(&parse(&mixed), limits),
            Err(Error::Budget { .. })
        ));
    }
}

#[test]
fn copy_carrier_preserves_original_metadata_loads_and_destination_reservations() {
    let original = fixture(&[(0x2800, 24), (0x3008, 8)]);
    let saved = original.clone();
    let dependency = FileRange::checked(FileOffset(0x1100), 8).unwrap();
    let edit = DeclaredEdit {
        offset: FileOffset(0x1100),
        expected: original[0x1100..0x1105].to_vec(),
        replacement: vec![0xe9, 0, 0, 0, 0],
    };
    let images = [RxImage {
        entry: ElfVaddr(BASE + 0x5000),
        bytes: vec![0x90, 0xc3],
    }];
    let output = append_carrier_with_images(
        &parse(&original),
        ImageRequest {
            carrier_vaddr: ElfVaddr(BASE + 0x6000),
            payload: b"copy-owner",
            images: &images,
            source_dependencies: &[dependency],
        },
        &[edit],
        ImagePolicy {
            layout: CarrierPolicy {
                page_size: 4096,
                user_address_limit: 1 << 47,
                max_added_file_bytes: 0x10000,
                max_output_file_bytes: 0x20000,
                max_program_headers: 32,
                max_virtual_span: 0x20000,
            },
            dynamic: Limits::default(),
            max_images: 4,
            max_new_load_pages: 8,
        },
    )
    .unwrap();
    assert_eq!(original, saved);
    let mut expected = original.clone();
    for change in output.changes() {
        let at = change.edit.offset.0 as usize;
        assert_eq!(
            &original[at..at + change.edit.expected.len()],
            &change.edit.expected
        );
        expected[at..at + change.edit.replacement.len()].copy_from_slice(&change.edit.replacement);
    }
    assert_eq!(&output.bytes()[..original.len()], &expected);
    for item in parse(&original).program_headers() {
        let old = 64 + item.index * 56;
        let new = output.program_table.start().0 as usize
            + output.original_to_output_header[item.index] * 56;
        assert_eq!(&original[old..old + 56], &output.bytes()[new..new + 56]);
    }
    let before = inspect(&original).unwrap();
    let after = inspect(output.bytes()).unwrap();
    assert_eq!(before.writes, after.writes);
    assert_eq!(before.symbol_references, after.symbol_references);
    assert_eq!(before.protected, after.protected);
    assert_eq!(
        parse(output.bytes()).header().entry,
        parse(&original).header().entry
    );
}
