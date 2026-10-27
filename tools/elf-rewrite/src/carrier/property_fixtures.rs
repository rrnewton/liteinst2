//! Structural GNU-property preservation; no CET or native-loader qualification.
use super::*;

const NOTE: usize = 0x700;
const PROPERTY_HEADER: usize = 64 + 5 * 56;
const ISA_NEEDED: u32 = 0xc000_8002;
const FEATURES: u32 = 0xc000_0002;

fn property_fixture(base: u64, properties: &[(u32, u32)]) -> Vec<u8> {
    let mut bytes = fixture(2, base, false, &[]);
    let length = 16 + 16 * properties.len();
    put32(&mut bytes, NOTE, 4);
    put32(&mut bytes, NOTE + 4, (length - 16) as u32);
    put32(&mut bytes, NOTE + 8, 5);
    bytes[NOTE + 12..NOTE + 16].copy_from_slice(b"GNU\0");
    for (index, &(kind, value)) in properties.iter().enumerate() {
        let at = NOTE + 16 + 16 * index;
        put32(&mut bytes, at, kind);
        put32(&mut bytes, at + 4, 4);
        put32(&mut bytes, at + 8, value);
    }
    encode_phdr(
        &mut bytes,
        PROPERTY_HEADER as u64,
        EncodedHeader {
            kind: 0x6474_e553,
            flags: 4,
            offset: NOTE as u64,
            vaddr: base + NOTE as u64,
            file_size: length as u64,
            memory_size: length as u64,
            alignment: 8,
        },
    )
    .unwrap();
    bytes
}

#[test]
fn isa_requirements_and_empty_feature_records_keep_exact_bytes_and_owners() {
    for base in [0, 0x400000] {
        for properties in [
            vec![(ISA_NEEDED, 1)],
            vec![(ISA_NEEDED, 3)], // baseline | v2, as emitted by current crt objects
            vec![(ISA_NEEDED, 0xf)],
            vec![(FEATURES, 0)],
            vec![(FEATURES, 0), (ISA_NEEDED, 3)],
        ] {
            let bytes = property_fixture(base, &properties);
            let original = parse(&bytes);
            let property = original.segments(SegmentType::GnuProperty).next().unwrap();
            let output = append(&bytes, base, &images(base), &[], &[], policy()).unwrap();
            let parsed = parse(output.bytes());
            let after = parsed.segments(SegmentType::GnuProperty).next().unwrap();
            assert_eq!(parsed.segments(SegmentType::GnuProperty).count(), 1);
            assert_eq!(after.offset, property.offset);
            assert_eq!(after.vaddr, property.vaddr);
            assert_eq!(after.file_size, property.file_size);
            assert_eq!(after.memory_size, property.memory_size);
            assert_eq!(after.flags, property.flags);
            assert_eq!(after.alignment, property.alignment);
            assert_eq!(
                &output.bytes()[NOTE..NOTE + property.file_size as usize],
                &bytes[NOTE..NOTE + property.file_size as usize]
            );
            assert!(output.changes().iter().all(|change| matches!(
                change.kind,
                ChangeKind::ProgramHeaderOffset | ChangeKind::ProgramHeaderCount
            )));
            let mapping = parsed
                .file_to_virtual(after.offset, after.file_size)
                .unwrap();
            assert_eq!(mapping.virtual_range.start(), property.vaddr);
            assert_eq!(mapping.flags.0, 4);
        }
    }
}

#[test]
fn cet_unknown_and_duplicate_properties_stay_refused() {
    for properties in [
        vec![(FEATURES, 1)],
        vec![(FEATURES, 2)],
        vec![(FEATURES, 3)],
        vec![(FEATURES, 4)],
        vec![(ISA_NEEDED, 0x10)],
        vec![(0xc001_0002, 3)], // ISA_USED is not in this profile
        vec![(0xdead_beef, 0)],
        vec![(ISA_NEEDED, 1), (ISA_NEEDED, 1)],
        vec![(ISA_NEEDED, 1), (FEATURES, 0)], // not sorted by property type
        vec![(FEATURES, 0), (ISA_NEEDED, 1), (ISA_NEEDED, 1)],
    ] {
        let bytes = property_fixture(0, &properties);
        assert!(matches!(
            append(&bytes, 0, &[], &[], &[], policy()),
            Err(Error::UnsupportedSegment {
                kind: SegmentType::GnuProperty,
                ..
            })
        ));
    }
}

#[test]
fn malformed_note_lengths_name_types_and_padding_are_not_ignored() {
    for (offset, value) in [
        (NOTE, 5),
        (NOTE + 4, 0),
        (NOTE + 4, 15),
        (NOTE + 4, 32),
        (NOTE + 8, 4),
        (NOTE + 12, 0),
        (NOTE + 20, 8),
        (NOTE + 28, 1),
    ] {
        let mut bytes = property_fixture(0, &[(ISA_NEEDED, 3)]);
        put32(&mut bytes, offset, value);
        assert!(matches!(
            append(&bytes, 0, &[], &[], &[], policy()),
            Err(Error::UnsupportedSegment {
                kind: SegmentType::GnuProperty,
                ..
            })
        ));
    }
}

#[test]
fn property_header_and_unique_read_only_mapping_must_agree() {
    for (offset, value) in [
        (PROPERTY_HEADER + 8, 0x708), // file and virtual ownership differ
        (PROPERTY_HEADER + 16, 0x708),
        (PROPERTY_HEADER + 32, 16),
        (PROPERTY_HEADER + 40, 48),
        (PROPERTY_HEADER + 48, 4),
    ] {
        let mut bytes = property_fixture(0, &[(ISA_NEEDED, 3)]);
        put64(&mut bytes, offset, value);
        assert!(append(&bytes, 0, &[], &[], &[], policy()).is_err());
    }
    for header in [PROPERTY_HEADER, 64 + 56] {
        for flags in [0, 5, 6] {
            let mut bytes = property_fixture(0, &[(ISA_NEEDED, 3)]);
            put32(&mut bytes, header + 4, flags);
            assert!(matches!(
                append(&bytes, 0, &[], &[], &[], policy()),
                Err(Error::UnsupportedSegment {
                    kind: SegmentType::GnuProperty,
                    ..
                })
            ));
        }
    }
    let mut duplicate = property_fixture(0, &[(ISA_NEEDED, 3)]);
    let property = duplicate[PROPERTY_HEADER..PROPERTY_HEADER + 56].to_vec();
    duplicate[64 + 4 * 56..64 + 5 * 56].copy_from_slice(&property);
    assert!(matches!(
        append(&duplicate, 0, &[], &[], &[], policy()),
        Err(Error::UnsupportedSegment {
            kind: SegmentType::GnuProperty,
            ..
        })
    ));
}

#[test]
fn property_bytes_cannot_be_declared_as_executable_dependencies() {
    let bytes = property_fixture(0, &[(ISA_NEEDED, 3)]);
    let dep = FileRange::checked(FileOffset(NOTE as u64), 32).unwrap();
    assert!(matches!(
        append(&bytes, 0, &[], &[], &[dep], policy()),
        Err(Error::InvalidDependency { index: 0 })
    ));
}

#[test]
fn freestanding_profile_still_refuses_a_valid_property_note() {
    let mut bytes = property_fixture(0, &[(ISA_NEEDED, 3)]);
    put32(&mut bytes, 64 + 4 * 56, 0); // Remove the independent PT_DYNAMIC refusal.
    assert!(matches!(
        append_read_only_carrier(
            &parse(&bytes),
            ElfVaddr(0x6000),
            b"metadata",
            &[],
            policy().layout
        ),
        Err(Error::UnsupportedSegment {
            kind: SegmentType::GnuProperty,
            ..
        })
    ));
}
