//! Pure admission controls. The file is parsed, never mapped or executed.
use super::*;

const SUBJECT: &[u8] = include_bytes!(env!("NATIVE_INTERVAL_DSO"));

fn changed_dynamic(change: impl FnOnce(&mut Vec<(u64, u64)>)) -> Vec<u8> {
    let file = object::File::parse(SUBJECT).unwrap();
    let (offset, length) = file
        .section_by_name(".dynamic")
        .unwrap()
        .file_range()
        .unwrap();
    let offset = usize::try_from(offset).unwrap();
    let length = usize::try_from(length).unwrap();
    let mut rows: Vec<_> = SUBJECT[offset..offset + length]
        .chunks_exact(16)
        .map(|row| (u64_at(row, 0).unwrap(), u64_at(row, 8).unwrap()))
        .take_while(|row| row.0 != 0)
        .collect();
    change(&mut rows);
    assert!(
        rows.len() < length / 16,
        "retain a complete terminating NULL row"
    );
    rows.resize(length / 16, (0, 0));
    let mut bytes = SUBJECT.to_vec();
    for (index, (tag, value)) in rows.into_iter().enumerate() {
        let at = offset + index * 16;
        bytes[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn refuses(bytes: &[u8]) {
    assert_eq!(parse(bytes).err(), Some(SetupRefusal::Format));
}

#[test]
fn parser_accepts_actual_subject_complete_grammar() {
    let elf = parse(SUBJECT).expect("actual admitted subject grammar");
    assert_eq!(elf.loads.len(), 4);
    assert_eq!(
        (elf.entry, elf.invoke, elf.terminal),
        (0x1010, 0x1030, 0x1035)
    );
    assert_eq!((elf.pointer, elf.bias_value), (0x3ee8, 0x2000));
    assert_eq!((elf.relro.start, elf.relro.end), (0x3000, 0x4000));
    assert_eq!(
        &elf.code[..8],
        &[0x48, 0x8d, 0x44, 0x7f, 0x07, 0x4c, 0x8b, 0x15]
    );
    assert_eq!(&elf.code[12..], &[0x49, 0x03, 0x02, 0x48, 0x89, 0x06, 0xc3]);
}

#[test]
fn parser_accepts_each_single_eager_binding_indicator() {
    for indicator in [24, 30, 0x6fff_fffb] {
        let bytes = changed_dynamic(|rows| {
            rows.retain(|row| !matches!(row.0, 24 | 30 | 0x6fff_fffb));
            rows.push((
                indicator,
                match indicator {
                    24 => 0,
                    30 => 8,
                    _ => 1,
                },
            ));
        });
        assert!(parse(&bytes).is_ok(), "required NOW form {indicator:#x}");
    }
}

#[test]
fn parser_rejects_nonzero_bind_now_payload() {
    refuses(&changed_dynamic(|rows| {
        rows.iter_mut().find(|r| r.0 == 24).unwrap().1 = 1
    }));
}

#[test]
fn parser_rejects_duplicate_bind_now() {
    refuses(&changed_dynamic(|rows| rows.push((24, 0))));
}

#[test]
fn parser_rejects_needed_dependency() {
    refuses(&changed_dynamic(|rows| rows.push((1, 1))));
}

#[test]
fn parser_rejects_init_constructor() {
    refuses(&changed_dynamic(|rows| rows.push((12, 0x1010))));
}

#[test]
fn parser_rejects_fini_destructor() {
    refuses(&changed_dynamic(|rows| rows.push((13, 0x1010))));
}

#[test]
fn parser_rejects_init_array_constructor() {
    refuses(&changed_dynamic(|rows| rows.push((25, 0x3ee8))));
}

#[test]
fn parser_rejects_invalid_flags_bits() {
    refuses(&changed_dynamic(|rows| {
        rows.retain(|r| r.0 != 30);
        rows.push((30, 4));
    }));
}

#[test]
fn parser_rejects_invalid_flags1_bits() {
    refuses(&changed_dynamic(|rows| {
        rows.iter_mut().find(|r| r.0 == 0x6fff_fffb).unwrap().1 = 2
    }));
}

#[test]
fn parser_rejects_missing_eager_binding() {
    refuses(&changed_dynamic(|rows| {
        rows.retain(|r| r.0 != 24);
        for (tag, value) in rows {
            if *tag == 30 {
                *value &= !8;
            }
            if *tag == 0x6fff_fffb {
                *value &= !1;
            }
        }
    }));
}

#[test]
fn parser_rejects_unknown_dynamic_tag() {
    refuses(&changed_dynamic(|rows| rows.push((0x4242, 0))));
}

#[test]
fn parser_rejects_nonnull_after_terminator() {
    refuses(&changed_dynamic(|rows| {
        rows.retain(|r| r.0 != 24);
        rows.push((0, 0));
        rows.push((24, 0));
    }));
}

#[test]
fn parser_rejects_textrel_tag() {
    refuses(&changed_dynamic(|rows| rows.push((22, 0))));
}
