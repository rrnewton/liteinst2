//! Prospective fixtures for the private parser. No emitted artifact is executed.

use super::*;

#[derive(Clone, Copy)]
struct Ph {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

fn load(offset: u64, vaddr: u64, file_size: u64, memory_size: u64) -> Ph {
    Ph {
        kind: 1,
        flags: 5,
        offset,
        vaddr,
        file_size,
        memory_size,
        alignment: 1,
    }
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn image(object_type: u16, headers: &[Ph], file_size: usize) -> Vec<u8> {
    assert!(file_size >= 64 + headers.len() * 56);
    let mut bytes = vec![0; file_size];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut bytes, 16, object_type);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, if object_type == 2 { 0x400300 } else { 0 });
    put64(&mut bytes, 32, if headers.is_empty() { 0 } else { 64 });
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, if headers.is_empty() { 0 } else { 56 });
    put16(&mut bytes, 56, headers.len().try_into().unwrap());
    for (index, item) in headers.iter().enumerate() {
        let base = 64 + index * 56;
        put32(&mut bytes, base, item.kind);
        put32(&mut bytes, base + 4, item.flags);
        put64(&mut bytes, base + 8, item.offset);
        put64(&mut bytes, base + 16, item.vaddr);
        put64(&mut bytes, base + 24, 0x1122_3344_5566_7788);
        put64(&mut bytes, base + 32, item.file_size);
        put64(&mut bytes, base + 40, item.memory_size);
        put64(&mut bytes, base + 48, item.alignment);
    }
    bytes
}

fn parse(bytes: &[u8]) -> Result<Elf64<'_>, Error> {
    Elf64::parse(bytes, ParseLimits::default())
}

#[test]
fn exec_inventory_preserves_every_header_and_unknown_fields() {
    let mut headers = vec![load(0, 0x400000, 0x700, 0x800)];
    headers[0].alignment = 4096;
    for kind in [
        3,
        2,
        6,
        7,
        4,
        0x6474_e551,
        0x6474_e552,
        0x6474_e553,
        0x7000_0042,
    ] {
        headers.push(Ph {
            kind,
            flags: 0x8000_0004,
            offset: 0x600,
            vaddr: 0x400600,
            file_size: 16,
            memory_size: 16,
            alignment: 8,
        });
    }
    let mut bytes = image(2, &headers, 0x800);
    bytes[7] = 3;
    bytes[8] = 7;
    put32(&mut bytes, 48, 0x1234);
    let elf = parse(&bytes).unwrap();
    assert_eq!(elf.bytes(), bytes);
    assert_eq!(elf.header().object_type, ObjectType::Executable);
    assert_eq!(elf.header().entry, ElfVaddr(0x400300));
    assert_eq!(elf.header().ident[7..9], [3, 7]);
    assert_eq!(elf.header().flags, 0x1234);
    assert_eq!(elf.program_headers().len(), headers.len());
    let kinds = [
        SegmentType::Load,
        SegmentType::Interpreter,
        SegmentType::Dynamic,
        SegmentType::ProgramHeaders,
        SegmentType::Tls,
        SegmentType::Note,
        SegmentType::GnuStack,
        SegmentType::GnuRelro,
        SegmentType::GnuProperty,
        SegmentType::Other(0x7000_0042),
    ];
    for (index, kind) in kinds.into_iter().enumerate() {
        let records: Vec<_> = elf.segments(kind).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].index, index);
        assert_eq!(records[0].raw_type, headers[index].kind);
        assert_eq!(records[0].physical_address, 0x1122_3344_5566_7788);
        assert_eq!(records[0].flags.0, headers[index].flags);
    }
}

#[test]
fn sectionless_dyn_zero_entry_needs_no_sections_or_symbols() {
    let bytes = image(3, &[load(0, 0, 0x400, 0x500)], 0x400);
    let elf = parse(&bytes).unwrap();
    assert_eq!(elf.header().object_type, ObjectType::Dynamic);
    assert_eq!(elf.header().entry, ElfVaddr(0));
    assert_eq!(elf.header().section_offset, FileOffset(0));
    assert_eq!(elf.header().section_count, 0);
    assert_eq!(
        elf.executable_bytes(ElfVaddr(0x300), 16).unwrap(),
        &bytes[0x300..0x310]
    );
}

#[test]
fn program_table_is_read_as_bytes_without_host_alignment_assumptions() {
    let mut bytes = image(3, &[load(0, 0, 0x400, 0x400)], 0x400);
    bytes.copy_within(64..120, 65);
    put64(&mut bytes, 32, 65);
    let elf = parse(&bytes).unwrap();
    assert_eq!(elf.header().program_offset, FileOffset(65));
    assert_eq!(elf.program_headers()[0].vaddr, ElfVaddr(0));
    assert_eq!(
        elf.executable_bytes(ElfVaddr(0x300), 8).unwrap(),
        &bytes[0x300..0x308]
    );
}

#[test]
fn exact_bidirectional_translation_and_permissions() {
    let mut bytes = image(2, &[load(0, 0x400000, 0x400, 0x500)], 0x400);
    bytes[0x300..0x310].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let original = bytes.clone();
    let elf = parse(&bytes).unwrap();
    let forward = elf.virtual_to_storage(ElfVaddr(0x400300), 16).unwrap();
    assert_eq!(forward.program_header, 0);
    assert_eq!(
        forward.storage,
        Storage::FileBacked(FileRange::checked(FileOffset(0x300), 16).unwrap())
    );
    let inverse = elf.file_to_virtual(FileOffset(0x300), 16).unwrap();
    assert_eq!(inverse.virtual_range, forward.virtual_range);
    assert_eq!(inverse.flags, SegmentFlags(5));
    assert!(inverse.flags.readable() && inverse.flags.executable() && !inverse.flags.writable());
    assert_eq!(
        elf.executable_bytes(ElfVaddr(0x400300), 16).unwrap(),
        &original[0x300..0x310]
    );
    assert_eq!(bytes, original);
}

#[test]
fn zero_fill_and_file_boundary_are_not_original_file_bytes() {
    let bytes = image(2, &[load(0, 0x400000, 0x400, 0x500)], 0x400);
    let elf = parse(&bytes).unwrap();
    assert_eq!(
        elf.virtual_to_storage(ElfVaddr(0x400400), 16)
            .unwrap()
            .storage,
        Storage::ZeroFill
    );
    assert!(matches!(
        elf.executable_bytes(ElfVaddr(0x400400), 16),
        Err(Error::NotFileBacked { index: 0, .. })
    ));
    assert!(matches!(
        elf.virtual_to_storage(ElfVaddr(0x4003ff), 2),
        Err(Error::CrossesFileZeroBoundary {
            index: 0,
            boundary: ElfVaddr(0x400400),
            ..
        })
    ));
    assert!(matches!(
        elf.virtual_to_storage(ElfVaddr(0x4004ff), 2),
        Err(Error::CrossesLoadBoundary { .. })
    ));
    assert!(matches!(
        elf.virtual_to_storage(ElfVaddr(0x400500), 1),
        Err(Error::UnmappedVirtual { .. })
    ));
}

#[test]
fn empty_file_load_can_have_an_anchor_beyond_eof() {
    let mut only_bss = load(0x2000, 0x602000, 0, 0x1000);
    only_bss.alignment = 0x1000;
    let bytes = image(3, &[only_bss], 0x200);
    let elf = parse(&bytes).unwrap();
    assert_eq!(
        elf.virtual_to_storage(ElfVaddr(0x602123), 4)
            .unwrap()
            .storage,
        Storage::ZeroFill
    );
    assert_eq!(elf.program_headers()[0].file_range().unwrap().len(), 0);
    assert!(matches!(
        elf.file_to_virtual(FileOffset(0x2000), 1),
        Err(Error::UnmappedFile { .. })
    ));
}

#[test]
fn nonexecuting_owner_is_not_filtered_out_of_ambiguity_checks() {
    let rx = load(0, 0x400000, 0x400, 0x400);
    let mut read_only = load(0x200, 0x400200, 0x100, 0x100);
    read_only.flags = 4;
    let bytes = image(2, &[rx, read_only], 0x400);
    let elf = parse(&bytes).unwrap();
    assert!(matches!(elf.executable_bytes(ElfVaddr(0x400250), 1),
        Err(Error::AmbiguousVirtual { owners, .. }) if owners == vec![0, 1]));
    let bytes = image(2, &[read_only], 0x400);
    assert_eq!(
        parse(&bytes)
            .unwrap()
            .executable_bytes(ElfVaddr(0x400250), 1),
        Err(Error::NotExecutable { index: 0 })
    );
}

#[test]
fn disjoint_virtual_aliases_remain_inventory_but_inverse_is_ambiguous() {
    let bytes = image(
        3,
        &[load(0, 0x1000, 0x400, 0x400), load(0, 0x3000, 0x400, 0x400)],
        0x400,
    );
    let elf = parse(&bytes).unwrap();
    assert_eq!(elf.segments(SegmentType::Load).count(), 2);
    assert_eq!(
        elf.executable_bytes(ElfVaddr(0x1100), 8).unwrap(),
        elf.executable_bytes(ElfVaddr(0x3100), 8).unwrap()
    );
    assert!(matches!(elf.file_to_virtual(FileOffset(0x100), 8),
        Err(Error::AmbiguousFile { owners, .. }) if owners == vec![0, 1]));
}

#[test]
fn disjoint_segments_crossing_is_distinct_from_overlapping_ownership() {
    let bytes = image(
        2,
        &[
            load(0, 0x400000, 0x200, 0x200),
            load(0x200, 0x400200, 0x200, 0x200),
        ],
        0x400,
    );
    let elf = parse(&bytes).unwrap();
    assert!(matches!(elf.virtual_to_storage(ElfVaddr(0x4001ff), 2),
        Err(Error::CrossesLoadBoundary { owners, .. }) if owners == vec![0, 1]));
    assert!(matches!(elf.file_to_virtual(FileOffset(0x1ff), 2),
        Err(Error::CrossesFileLoadBoundary { owners, .. }) if owners == vec![0, 1]));
    assert!(matches!(
        elf.virtual_to_storage(ElfVaddr(0x3fffff), 2),
        Err(Error::CrossesLoadBoundary { .. })
    ));
    assert!(matches!(
        elf.file_to_virtual(FileOffset(0x3ff), 2),
        Err(Error::CrossesFileLoadBoundary { .. })
    ));
}

#[test]
fn table_and_segment_file_bounds_are_checked_before_indexing() {
    let mut bytes = image(2, &[load(0, 0x400000, 0x400, 0x400)], 0x400);
    assert!(matches!(
        parse(&bytes[..63]),
        Err(Error::Truncated {
            region: FileRegion::Header,
            ..
        })
    ));
    assert!(matches!(
        parse(&bytes[..100]),
        Err(Error::Truncated {
            region: FileRegion::ProgramHeaderTable,
            ..
        })
    ));
    assert!(matches!(
        parse(&bytes[..0x3ff]),
        Err(Error::Truncated {
            region: FileRegion::Segment(0),
            ..
        })
    ));
    put64(&mut bytes, 32, u64::MAX - 7);
    assert!(matches!(
        parse(&bytes),
        Err(Error::Overflow {
            domain: AddressDomain::File,
            ..
        })
    ));
    put64(&mut bytes, 32, 32);
    assert_eq!(
        parse(&bytes).unwrap_err(),
        Error::ProgramTableOverlapsHeader {
            offset: FileOffset(32)
        }
    );
}

#[test]
fn all_address_arithmetic_rejects_unsigned_wraparound() {
    let bytes = image(2, &[load(0, 0x400000, 0x400, 0x400)], 0x400);
    let elf = parse(&bytes).unwrap();
    assert!(matches!(
        elf.virtual_to_storage(ElfVaddr(u64::MAX), 1),
        Err(Error::Overflow {
            domain: AddressDomain::Virtual,
            ..
        })
    ));
    assert!(matches!(
        elf.file_to_virtual(FileOffset(u64::MAX), 1),
        Err(Error::Overflow {
            domain: AddressDomain::File,
            ..
        })
    ));
    let bytes = image(2, &[load(u64::MAX - 3, 0x400000, 8, 8)], 0x400);
    assert!(matches!(
        parse(&bytes),
        Err(Error::Overflow {
            domain: AddressDomain::File,
            ..
        })
    ));
    let bytes = image(2, &[load(0, u64::MAX - 3, 8, 8)], 0x400);
    assert!(matches!(
        parse(&bytes),
        Err(Error::Overflow {
            domain: AddressDomain::Virtual,
            ..
        })
    ));
}

#[test]
fn alignment_size_and_load_order_refusals_are_precise() {
    let mut bad = load(0, 0x400000, 0x400, 0x400);
    bad.alignment = 3;
    assert_eq!(
        parse(&image(2, &[bad], 0x400)).unwrap_err(),
        Error::InvalidAlignment {
            index: 0,
            alignment: 3
        }
    );
    bad.alignment = 4096;
    bad.vaddr += 1;
    assert!(matches!(
        parse(&image(2, &[bad], 0x400)),
        Err(Error::IncongruentLoad { index: 0, .. })
    ));
    let bad = load(0, 0x400000, 0x400, 0x3ff);
    assert_eq!(
        parse(&image(2, &[bad], 0x400)).unwrap_err(),
        Error::FileSizeExceedsMemory {
            index: 0,
            file_size: 0x400,
            memory_size: 0x3ff
        }
    );
    let mut tls = bad;
    tls.kind = 7;
    assert!(matches!(
        parse(&image(2, &[tls], 0x400)),
        Err(Error::FileSizeExceedsMemory { index: 0, .. })
    ));
    let mut note = bad;
    note.kind = 4; // Notes need not describe a larger loadable memory image.
    assert!(parse(&image(2, &[note], 0x400)).is_ok());
    let bytes = image(
        2,
        &[
            load(0, 0x500000, 0x200, 0x200),
            load(0x200, 0x400000, 0x200, 0x200),
        ],
        0x400,
    );
    assert_eq!(
        parse(&bytes).unwrap_err(),
        Error::InvalidLoadOrder {
            before: 0,
            after: 1
        }
    );
}

#[test]
fn alignment_zero_one_and_large_powers_are_supported() {
    for alignment in [0, 1, 8, 4096, 1 << 21, 1 << 63] {
        let mut header = load(0, 0, 0x400, 0x400);
        header.alignment = alignment;
        assert!(
            parse(&image(3, &[header], 0x400)).is_ok(),
            "alignment {alignment}"
        );
    }
}

#[test]
fn target_page_congruence_is_explicit_even_when_declared_alignment_is_one() {
    let good = image(3, &[load(0, 0x400000, 0x400, 0x400)], 0x400);
    let elf = parse(&good).unwrap();
    assert_eq!(elf.check_load_page_congruence(4096), Ok(()));
    assert_eq!(
        elf.check_load_page_congruence(0),
        Err(Error::InvalidPageSize { page_size: 0 })
    );
    assert_eq!(
        elf.check_load_page_congruence(3072),
        Err(Error::InvalidPageSize { page_size: 3072 })
    );
    let mismatched = image(3, &[load(0, 0x400001, 0x400, 0x400)], 0x400);
    let elf = parse(&mismatched).unwrap();
    assert_eq!(elf.program_headers()[0].alignment, 1);
    assert_eq!(
        elf.check_load_page_congruence(4096),
        Err(Error::IncongruentLoadPage {
            index: 0,
            offset: FileOffset(0),
            vaddr: ElfVaddr(0x400001),
            page_size: 4096,
        })
    );
}

#[test]
fn unsupported_ident_and_fixed_header_fields_are_not_guessed() {
    let original = image(2, &[load(0, 0x400000, 0x400, 0x400)], 0x400);
    for (offset, value, field) in [(4, 1, HeaderField::Class), (5, 2, HeaderField::ByteOrder)] {
        let mut bytes = original.clone();
        bytes[offset] = value;
        assert_eq!(
            parse(&bytes).unwrap_err(),
            Error::Unsupported {
                field,
                value: u64::from(value)
            }
        );
    }
    let mut bytes = original.clone();
    put16(&mut bytes, 18, 3);
    assert_eq!(
        parse(&bytes).unwrap_err(),
        Error::Unsupported {
            field: HeaderField::Machine,
            value: 3
        }
    );
    put16(&mut bytes, 18, 62);
    put16(&mut bytes, 16, 1);
    assert_eq!(
        parse(&bytes).unwrap_err(),
        Error::Unsupported {
            field: HeaderField::ObjectType,
            value: 1
        }
    );
    for (offset, value, field, required) in [
        (52, 63, HeaderField::HeaderSize, 64),
        (54, 55, HeaderField::ProgramHeaderSize, 56),
    ] {
        let mut bytes = original.clone();
        put16(&mut bytes, offset, value);
        assert_eq!(
            parse(&bytes).unwrap_err(),
            Error::InvalidHeader {
                field,
                value: u64::from(value),
                required
            }
        );
    }
    let mut bytes = original.clone();
    bytes[0] = 0;
    assert!(matches!(
        parse(&bytes),
        Err(Error::InvalidHeader {
            field: HeaderField::Magic,
            ..
        })
    ));
    bytes = original.clone();
    bytes[6] = 2;
    assert!(matches!(
        parse(&bytes),
        Err(Error::InvalidHeader {
            field: HeaderField::IdentVersion,
            ..
        })
    ));
    bytes = original;
    put32(&mut bytes, 20, 2);
    assert!(matches!(
        parse(&bytes),
        Err(Error::InvalidHeader {
            field: HeaderField::Version,
            ..
        })
    ));
}

#[test]
fn extended_count_refusal_and_resource_cutoff_are_distinct() {
    let mut bytes = image(
        3,
        &[load(0, 0, 0x200, 0x200), load(0x200, 0x2000, 0x200, 0x200)],
        0x400,
    );
    assert_eq!(
        Elf64::parse(
            &bytes,
            ParseLimits {
                max_program_headers: 1
            }
        )
        .unwrap_err(),
        Error::ProgramHeaderLimit {
            required: 2,
            limit: 1
        }
    );
    assert_eq!(
        Elf64::parse(
            &bytes,
            ParseLimits {
                max_program_headers: 2
            }
        )
        .unwrap()
        .program_headers()
        .len(),
        2
    );
    put16(&mut bytes, 56, 0xffff);
    assert_eq!(
        parse(&bytes).unwrap_err(),
        Error::Unsupported {
            field: HeaderField::ProgramHeaderCount,
            value: 0xffff
        }
    );
}

#[test]
fn null_fields_are_unused_while_real_header_records_are_retained() {
    let null = Ph {
        kind: 0,
        flags: u32::MAX,
        offset: u64::MAX,
        vaddr: u64::MAX,
        file_size: u64::MAX,
        memory_size: u64::MAX,
        alignment: 3,
    };
    let bytes = image(3, &[null, load(0, 0, 0x400, 0x400)], 0x400);
    let elf = parse(&bytes).unwrap();
    assert_eq!(elf.program_headers().len(), 2);
    assert_eq!(elf.program_headers()[0].offset, FileOffset(u64::MAX));
    assert_eq!(
        elf.virtual_to_storage(ElfVaddr(0x100), 1)
            .unwrap()
            .program_header,
        1
    );
    assert!(elf.program_headers()[0].file_range().is_err());
}

#[test]
fn no_program_table_is_inventory_only_and_queries_remain_explicit() {
    let bytes = image(3, &[], 64);
    let elf = Elf64::parse(
        &bytes,
        ParseLimits {
            max_program_headers: 0,
        },
    )
    .unwrap();
    assert!(elf.program_headers().is_empty());
    assert!(matches!(
        elf.virtual_to_storage(ElfVaddr(0), 1),
        Err(Error::UnmappedVirtual { .. })
    ));
    assert!(matches!(
        elf.file_to_virtual(FileOffset(0), 1),
        Err(Error::UnmappedFile { .. })
    ));
    assert_eq!(
        elf.virtual_to_storage(ElfVaddr(0), 0),
        Err(Error::EmptyRange)
    );
    assert_eq!(
        elf.file_to_virtual(FileOffset(0), 0),
        Err(Error::EmptyRange)
    );
    let mut malformed = bytes;
    put64(&mut malformed, 32, 64);
    assert_eq!(
        parse(&malformed).unwrap_err(),
        Error::InvalidHeader {
            field: HeaderField::ProgramHeaderOffset,
            value: 64,
            required: 0
        }
    );
}
