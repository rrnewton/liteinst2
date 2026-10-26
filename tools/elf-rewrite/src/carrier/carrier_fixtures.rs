//! Prospective byte-layout fixtures, not executable output qualification.
use super::*;

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn fixture(with_phdr: bool, extra: &[u32]) -> Vec<u8> {
    let mut kinds = if with_phdr { vec![6, 1] } else { vec![1] };
    kinds.extend_from_slice(extra);
    let mut bytes = vec![0; 0x800];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, 0x400700);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, kinds.len() as u16);
    for (index, kind) in kinds.iter().copied().enumerate() {
        let at = 64 + index * 56;
        put32(&mut bytes, at, kind);
        let (flags, offset, vaddr, length, align) = match kind {
            1 => (5, 0, 0x400000, 0x800, 4096),
            6 => (4, 64, 0x400040, kinds.len() as u64 * 56, 8),
            0x6474_e551 => (6, 0, 0, 0, 16),
            _ => (4, 0x600, 0x400600, 16, 8),
        };
        put32(&mut bytes, at + 4, flags);
        for (field, value) in [
            (8, offset),
            (16, vaddr),
            (24, vaddr),
            (32, length),
            (40, length),
            (48, align),
        ] {
            put64(&mut bytes, at + field, value);
        }
    }
    bytes[0x600..0x610].copy_from_slice(b"opaque-note-data");
    bytes[0x700..0x704].copy_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
    bytes
}

fn policy() -> CarrierPolicy {
    CarrierPolicy {
        page_size: 4096,
        user_address_limit: 1 << 47,
        max_added_file_bytes: 0x10000,
        max_output_file_bytes: 0x20000,
        max_program_headers: 32,
        max_virtual_span: 0x10000,
    }
}

fn parse(bytes: &[u8]) -> Elf64<'_> {
    Elf64::parse(bytes, ParseLimits::default()).unwrap()
}

fn append(bytes: &[u8], edits: &[DeclaredEdit]) -> Result<CarrierOutput, Error> {
    append_read_only_carrier(
        &parse(bytes),
        ElfVaddr(0x401000),
        b"carrier-data",
        edits,
        policy(),
    )
}

fn assert_original_preserved(original: &[u8], output: &CarrierOutput) {
    let mut expected = original.to_vec();
    for change in output.changes() {
        let at = change.edit.offset.0 as usize;
        assert_eq!(
            &original[at..at + change.edit.expected.len()],
            &change.edit.expected
        );
        expected[at..at + change.edit.replacement.len()].copy_from_slice(&change.edit.replacement);
    }
    assert_eq!(&output.bytes()[..original.len()], expected);
    assert_eq!(
        &output.bytes()[24..32],
        &original[24..32],
        "original entry must remain exact"
    );
    assert_eq!(
        &output.bytes()[40..56],
        &original[40..56],
        "section and fixed header fields must remain exact"
    );
    assert_eq!(&output.bytes()[58..64], &original[58..64]);
}

#[test]
fn appended_ro_carrier_has_exact_new_phdr_mapping_without_old_header_space() {
    let original = fixture(false, &[]);
    let saved = original.clone();
    let output = append(&original, &[]).unwrap();
    let elf = parse(output.bytes());
    assert_eq!(original, saved);
    assert_original_preserved(&original, &output);
    assert_eq!(output.changes().len(), 2);
    assert_eq!(output.program_table.start(), FileOffset(0x1000));
    assert_eq!(output.program_table.len(), 3 * 56);
    assert_eq!(elf.header().program_count, 3);
    assert_eq!(output.phdr_index, 0);
    assert_eq!(output.carrier_index, 2);
    assert_eq!(output.original_to_output_header, vec![1]);
    assert_eq!(&output.bytes()[0x1038..0x1070], &original[64..120]);
    assert!(output.bytes()[0x800..0x1000].iter().all(|byte| *byte == 0));
    assert_eq!(output.payload.start(), FileOffset(0x1000 + 3 * 56));
    assert_eq!(
        &output.bytes()[output.payload.start().0 as usize..],
        b"carrier-data"
    );
    let phdr = &elf.program_headers()[0];
    let carrier = &elf.program_headers()[2];
    assert_eq!(phdr.offset, FileOffset(0x1000));
    assert_eq!(phdr.vaddr, ElfVaddr(0x401000));
    assert_eq!(phdr.file_size, 168);
    assert_eq!(phdr.memory_size, 168);
    assert_eq!(phdr.flags.0, 4);
    assert_eq!(carrier.offset, FileOffset(0x1000));
    assert_eq!(carrier.vaddr, ElfVaddr(0x401000));
    assert_eq!(carrier.file_size, 168 + 12);
    assert_eq!(carrier.memory_size, 168 + 12);
    assert_eq!(carrier.flags.0, 4);
    assert_eq!(carrier.alignment, 4096);
    let mapped = elf.file_to_virtual(FileOffset(0x1000), 168).unwrap();
    assert_eq!(mapped.program_header, 2);
    assert_eq!(mapped.virtual_range.start(), phdr.vaddr);
}

#[test]
fn multipage_payload_keeps_exact_file_length_and_bounded_page_span() {
    let original = fixture(false, &[]);
    let payload: Vec<u8> = (0..4101).map(|index| (index % 251) as u8).collect();
    let exact_end = 0x1000 + 168 + payload.len() as u64;
    let exact = CarrierPolicy {
        max_virtual_span: 0x3000,
        max_output_file_bytes: exact_end,
        max_added_file_bytes: exact_end - 0x800,
        ..policy()
    };
    let output =
        append_read_only_carrier(&parse(&original), ElfVaddr(0x401000), &payload, &[], exact)
            .unwrap();
    assert_original_preserved(&original, &output);
    assert_eq!(output.bytes().len() as u64, exact_end);
    assert_eq!(&output.bytes()[0x10a8..], payload);
    let elf = parse(output.bytes());
    assert_eq!(elf.program_headers()[2].file_size, 168 + 4101);
    assert_eq!(elf.program_headers()[2].memory_size, 168 + 4101);
    let too_small = CarrierPolicy {
        max_virtual_span: 0x2fff,
        ..exact
    };
    assert_eq!(
        append_read_only_carrier(
            &parse(&original),
            ElfVaddr(0x401000),
            &payload,
            &[],
            too_small
        )
        .unwrap_err(),
        Error::Budget {
            resource: "virtual span",
            required: 0x3000,
            limit: 0x2fff
        }
    );
}

#[test]
fn existing_phdr_moves_in_new_table_without_stealing_notes_or_stack_records() {
    let original = fixture(true, &[4, 0x6474_e551]);
    let output = append(&original, &[]).unwrap();
    let elf = parse(output.bytes());
    assert_original_preserved(&original, &output);
    assert_eq!(elf.header().program_count, 5);
    assert_eq!(output.original_to_output_header, vec![0, 1, 2, 3]);
    assert_eq!(elf.segments(SegmentType::Note).count(), 1);
    assert_eq!(elf.segments(SegmentType::GnuStack).count(), 1);
    assert_eq!(elf.segments(SegmentType::ProgramHeaders).count(), 1);
    for index in 1..4 {
        assert_eq!(
            &output.bytes()[0x1000 + index * 56..0x1000 + (index + 1) * 56],
            &original[64 + index * 56..64 + (index + 1) * 56]
        );
    }
    assert_eq!(&output.bytes()[64..64 + 4 * 56], &original[64..64 + 4 * 56]);
    assert_eq!(&output.bytes()[0x600..0x610], b"opaque-note-data");
    assert_eq!(elf.program_headers()[0].file_size, 5 * 56);
}

#[test]
fn declared_edits_are_authenticated_sorted_and_exhaustively_reported() {
    let original = fixture(false, &[]);
    let edits = [
        DeclaredEdit {
            offset: FileOffset(0x703),
            expected: vec![0xc3],
            replacement: vec![0xc3],
        },
        DeclaredEdit {
            offset: FileOffset(0x700),
            expected: vec![0x90, 0x90],
            replacement: vec![0x66, 0x90],
        },
    ];
    let output = append(&original, &edits).unwrap();
    assert_original_preserved(&original, &output);
    assert_eq!(
        output
            .changes()
            .iter()
            .map(|c| c.edit.offset.0)
            .collect::<Vec<_>>(),
        vec![32, 56, 0x700, 0x703]
    );
    assert_eq!(&output.bytes()[0x700..0x704], &[0x66, 0x90, 0x90, 0xc3]);
    assert_eq!(
        output
            .changes()
            .iter()
            .filter(|c| c.kind == ChangeKind::DeclaredSource)
            .count(),
        2
    );
}

#[test]
fn dynamic_load_bias_interpreter_and_property_requirements_are_not_ignored() {
    let mut pie = fixture(false, &[]);
    put16(&mut pie, 16, 3);
    assert_eq!(append(&pie, &[]).unwrap_err(), Error::UnsupportedObjectType);
    for (kind, expected) in [
        (2, SegmentType::Dynamic),
        (3, SegmentType::Interpreter),
        (0x6474_e553, SegmentType::GnuProperty),
    ] {
        let original = fixture(false, &[kind]);
        let saved = original.clone();
        assert_eq!(
            append(&original, &[]).unwrap_err(),
            Error::UnsupportedSegment {
                index: 1,
                kind: expected
            }
        );
        assert_eq!(original, saved);
    }
}

#[test]
fn edit_shape_staleness_and_overlap_refuse_without_input_mutation() {
    let original = fixture(false, &[]);
    let saved = original.clone();
    for edit in [
        DeclaredEdit {
            offset: FileOffset(0x700),
            expected: vec![],
            replacement: vec![],
        },
        DeclaredEdit {
            offset: FileOffset(0x700),
            expected: vec![0x90],
            replacement: vec![0x66, 0x90],
        },
    ] {
        assert_eq!(
            append(&original, &[edit]).unwrap_err(),
            Error::InvalidEditShape { index: 0 }
        );
    }
    let stale = DeclaredEdit {
        offset: FileOffset(0x700),
        expected: vec![0xcc],
        replacement: vec![0x90],
    };
    assert_eq!(
        append(&original, &[stale]).unwrap_err(),
        Error::StaleEdit { index: 0 }
    );
    let overlap = [
        DeclaredEdit {
            offset: FileOffset(0x700),
            expected: vec![0x90, 0x90],
            replacement: vec![0x90, 0x90],
        },
        DeclaredEdit {
            offset: FileOffset(0x701),
            expected: vec![0x90],
            replacement: vec![0x90],
        },
    ];
    assert_eq!(
        append(&original, &overlap).unwrap_err(),
        Error::OverlappingEdits {
            before: 0,
            after: 1
        }
    );
    assert_eq!(original, saved);
}

#[test]
fn header_old_phdr_note_and_section_table_are_protected_source_ranges() {
    let mut original = fixture(true, &[4]);
    put64(&mut original, 40, 0x780);
    put16(&mut original, 58, 64);
    put16(&mut original, 60, 1);
    for offset in [24, 32, 56, 64, 0x600, 0x780] {
        let edit = DeclaredEdit {
            offset: FileOffset(offset),
            expected: vec![original[offset as usize]],
            replacement: vec![0x90],
        };
        assert_eq!(
            append(&original, &[edit]).unwrap_err(),
            Error::ProtectedMetadata { index: 0 },
            "offset {offset}"
        );
    }
    let output = append(&original, &[]).unwrap();
    assert_original_preserved(&original, &output);
    assert_eq!(&output.bytes()[0x780..0x7c0], &original[0x780..0x7c0]);
}

#[test]
fn nonexecutable_data_edits_are_not_relabelled_as_source_code() {
    let mut original = fixture(false, &[]);
    original.resize(0x1800, 0);
    put16(&mut original, 56, 2);
    let at = 120;
    put32(&mut original, at, 1);
    put32(&mut original, at + 4, 6);
    for (field, value) in [
        (8, 0x1000),
        (16, 0x402000),
        (24, 0x402000),
        (32, 0x800),
        (40, 0x800),
        (48, 4096),
    ] {
        put64(&mut original, at + field, value);
    }
    let edit = DeclaredEdit {
        offset: FileOffset(0x1000),
        expected: vec![0],
        replacement: vec![1],
    };
    assert_eq!(
        append_read_only_carrier(
            &parse(&original),
            ElfVaddr(0x403000),
            b"x",
            &[edit],
            policy()
        )
        .unwrap_err(),
        Error::NonExecutableEdit { index: 0 }
    );
}

#[test]
fn placement_and_explicit_address_bounds_are_checked_before_allocation() {
    let original = fixture(false, &[]);
    let elf = parse(&original);
    for address in [0x400000, 0x400fff, 0x401001] {
        assert_eq!(
            append_read_only_carrier(&elf, ElfVaddr(address), b"x", &[], policy()).unwrap_err(),
            Error::CarrierPlacement
        );
    }
    assert_eq!(
        append_read_only_carrier(&elf, ElfVaddr(1 << 47), b"x", &[], policy()).unwrap_err(),
        Error::AddressLimit { index: None }
    );
    assert!(matches!(
        append_read_only_carrier(&elf, ElfVaddr(!4095_u64), b"x", &[], policy()),
        Err(Error::Arithmetic { .. })
    ));
    for page_size in [0, 3] {
        let mut policy = policy();
        policy.page_size = page_size;
        assert_eq!(
            append_read_only_carrier(&elf, ElfVaddr(0x401000), b"x", &[], policy).unwrap_err(),
            Error::InvalidTargetPolicy
        );
    }
}

#[test]
fn count_added_bytes_total_bytes_and_virtual_span_budgets_are_exact() {
    let original = fixture(false, &[]);
    let elf = parse(&original);
    let expected_end = 0x1000 + 3 * 56 + 12;
    let expected_added = expected_end - original.len() as u64;
    let baseline = policy();
    for (resource, required, limit, policy) in [
        (
            "program headers",
            3,
            2,
            CarrierPolicy {
                max_program_headers: 2,
                ..baseline
            },
        ),
        (
            "added file bytes",
            expected_added,
            expected_added - 1,
            CarrierPolicy {
                max_added_file_bytes: expected_added - 1,
                ..baseline
            },
        ),
        (
            "output file bytes",
            expected_end,
            expected_end - 1,
            CarrierPolicy {
                max_output_file_bytes: expected_end - 1,
                ..baseline
            },
        ),
        (
            "virtual span",
            0x2000,
            0x1fff,
            CarrierPolicy {
                max_virtual_span: 0x1fff,
                ..baseline
            },
        ),
    ] {
        assert_eq!(
            append_read_only_carrier(&elf, ElfVaddr(0x401000), b"carrier-data", &[], policy)
                .unwrap_err(),
            Error::Budget {
                resource,
                required,
                limit
            }
        );
    }
    let exact = CarrierPolicy {
        max_program_headers: 3,
        max_added_file_bytes: expected_added,
        max_output_file_bytes: expected_end,
        max_virtual_span: 0x2000,
        ..baseline
    };
    let output =
        append_read_only_carrier(&elf, ElfVaddr(0x401000), b"carrier-data", &[], exact).unwrap();
    assert_eq!(output.bytes().len() as u64, expected_end);
}

#[test]
fn original_page_overlaps_are_refused_instead_of_guessing_loader_precedence() {
    let mut original = fixture(false, &[1]);
    put64(&mut original, 64 + 32, 0x400);
    put64(&mut original, 64 + 40, 0x400);
    put64(&mut original, 120 + 8, 0x400);
    put64(&mut original, 120 + 16, 0x400400);
    put64(&mut original, 120 + 32, 0x400);
    put64(&mut original, 120 + 40, 0x400);
    put64(&mut original, 120 + 48, 1);
    assert_eq!(
        append(&original, &[]).unwrap_err(),
        Error::OverlappingLoadPages {
            before: 0,
            after: 1
        }
    );
}

#[test]
fn existing_phdr_must_be_unique_early_and_match_its_original_load_translation() {
    for (field, value) in [(8, 65), (16, 0x400041), (32, 1), (40, 1)] {
        let mut original = fixture(true, &[]);
        put64(&mut original, 64 + field, value);
        assert_eq!(
            append(&original, &[]).unwrap_err(),
            Error::InvalidProgramHeaderMapping
        );
    }
    assert_eq!(
        append(&fixture(true, &[6]), &[]).unwrap_err(),
        Error::InvalidProgramHeaderMapping
    );
    assert_eq!(
        append(&fixture(false, &[6]), &[]).unwrap_err(),
        Error::InvalidProgramHeaderMapping
    );
    // A zero-sized PT_LOAD still precedes PT_PHDR in the original table order.
    let mut original = fixture(false, &[6, 1]);
    for field in [8, 16, 24, 32, 40] {
        put64(&mut original, 64 + field, 0);
    }
    put64(&mut original, 64 + 48, 1);
    assert_eq!(
        append(&original, &[]).unwrap_err(),
        Error::InvalidProgramHeaderMapping
    );
}

#[test]
fn original_program_table_and_entry_require_actual_load_byte_ownership() {
    let mut original = fixture(false, &[]);
    put64(&mut original, 64 + 32, 64);
    put64(&mut original, 64 + 40, 64);
    assert!(matches!(
        append(&original, &[]),
        Err(Error::Elf(elf64::Error::UnmappedFile { .. }))
    ));
    let mut original = fixture(false, &[]);
    put64(&mut original, 24, 0x400800);
    assert!(matches!(
        append(&original, &[]),
        Err(Error::Elf(elf64::Error::UnmappedVirtual { .. }))
    ));
}

#[test]
fn section_layout_unsupported_cases_are_explicit_and_do_not_change_input() {
    for (offset, count, size, names) in [
        (0x780, 0, 64, 0),
        (0x780, 1, 63, 0),
        (0x7f0, 1, 64, 0),
        (0x780, 1, 64, 0xffff),
        (0, 1, 64, 0),
    ] {
        let mut original = fixture(false, &[]);
        put64(&mut original, 40, offset);
        put16(&mut original, 58, size);
        put16(&mut original, 60, count);
        put16(&mut original, 62, names);
        let saved = original.clone();
        assert_eq!(
            append(&original, &[]).unwrap_err(),
            Error::UnsupportedSectionLayout
        );
        assert_eq!(original, saved);
    }
}

#[test]
fn unknown_metadata_records_are_preserved_and_their_bytes_are_not_editable() {
    let original = fixture(false, &[0x7000_0042]);
    let output = append(&original, &[]).unwrap();
    let elf = parse(output.bytes());
    assert_eq!(elf.segments(SegmentType::Other(0x7000_0042)).count(), 1);
    assert_eq!(
        &output.bytes()[0x1000 + 2 * 56..0x1000 + 3 * 56],
        &original[120..176]
    );
    let edit = DeclaredEdit {
        offset: FileOffset(0x600),
        expected: vec![b'o'],
        replacement: vec![b'x'],
    };
    assert_eq!(
        append(&original, &[edit]).unwrap_err(),
        Error::ProtectedMetadata { index: 0 }
    );
}

#[test]
fn carrier_cannot_occupy_a_declared_note_or_unknown_metadata_memory_extent() {
    for kind in [4, 0x7000_0042] {
        let mut original = fixture(false, &[kind]);
        put64(&mut original, 120 + 16, 0x401000);
        assert_eq!(
            append(&original, &[]).unwrap_err(),
            Error::CarrierMetadataOverlap { index: 1 }
        );
    }
}

#[test]
fn preservation_check_rejects_an_unreported_original_byte_change() {
    let original = fixture(false, &[]);
    let output = append(&original, &[]).unwrap();
    let mut corrupted = output.bytes().to_vec();
    corrupted[0x650] ^= 1;
    assert_eq!(
        verify_preservation(&original, &corrupted, output.changes()),
        Err(Error::OutputInvariant)
    );
    assert_eq!(
        verify_preservation(&original, output.bytes(), output.changes()),
        Ok(())
    );
}
