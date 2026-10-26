use super::super::super::source_identity::{FileIdentity, ImageRole};
use super::*;

const BASELINE: &[u8] = b"00100000-00101000 rw-p 00000000 00:00 0\n00400000-00404000 r--p 00000000 08:01 7 /fixture\n00800000-00801000 r-xp 00000000 00:00 0\n";
const TWO_PAGES: &[u8] = b"00100000-00101000 rw-p 00000000 00:00 0\n00400000-00401000 r--p 00000000 08:01 7 /fixture\n00401000-00403000 r-xp 00001000 08:01 7 /fixture\n00403000-00404000 r--p 00003000 08:01 7 /fixture\n00800000-00801000 r-xp 00000000 00:00 0\n";

fn source() -> SourceVma {
    let start = BASELINE.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let length = BASELINE[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap();
    SourceVma {
        original_index: 1,
        current_index: 1,
        original_span: (start, length),
        current_span: (start, length),
        start: 0x400000,
        end: 0x404000,
        offset: 0,
        file: FileIdentity {
            major: 8,
            minor: 1,
            inode: 7,
        },
        role: ImageRole::Executable,
    }
}
fn crossing() -> FetchGeometry {
    FetchGeometry::for_instruction(source(), AddressRange::new(0x401fff, 0x402001).unwrap())
        .unwrap()
}
fn replace(bytes: &[u8], before: &str, after: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).unwrap();
    assert!(text.contains(before));
    text.replacen(before, after, 1).into_bytes()
}

#[test]
fn two_fetch_pages_preserve_full_vma_and_exact_split_identity() {
    let geometry = crossing();
    assert_eq!(geometry.source(), &source());
    assert_eq!(
        geometry.instruction(),
        AddressRange::new(0x401fff, 0x402001).unwrap()
    );
    assert_eq!(
        geometry.pages(),
        AddressRange::new(0x401000, 0x403000).unwrap()
    );
    assert_eq!(geometry.projected_rows(BASELINE).unwrap(), 5);
    geometry.verify_open(BASELINE, TWO_PAGES).unwrap();
    verify_closed(BASELINE, BASELINE).unwrap();
    assert_eq!(geometry.source().start, 0x400000);
    assert_eq!(geometry.source().end, 0x404000);
}

#[test]
fn exact_page_ending_does_not_open_the_never_executed_next_page() {
    let geometry =
        FetchGeometry::for_instruction(source(), AddressRange::new(0x400ffb, 0x401000).unwrap())
            .unwrap();
    assert_eq!(
        geometry.pages(),
        AddressRange::new(0x400000, 0x401000).unwrap()
    );
    assert_eq!(geometry.projected_rows(BASELINE).unwrap(), 4);
    let open = b"00100000-00101000 rw-p 00000000 00:00 0\n00400000-00401000 r-xp 00000000 08:01 7 /fixture\n00401000-00404000 r--p 00001000 08:01 7 /fixture\n00800000-00801000 r-xp 00000000 00:00 0\n";
    geometry.verify_open(BASELINE, open).unwrap();
    // Opening the return's next page would be a different, refused projection.
    let extra = replace(open, "00400000-00401000", "00400000-00402000");
    assert!(geometry.verify_open(BASELINE, &extra).is_err());
    let valid_extra = b"00100000-00101000 rw-p 00000000 00:00 0\n00400000-00402000 r-xp 00000000 08:01 7 /fixture\n00402000-00404000 r--p 00002000 08:01 7 /fixture\n00800000-00801000 r-xp 00000000 00:00 0\n";
    assert_eq!(parse(valid_extra).unwrap().entries().count(), 4);
    assert!(matches!(
        geometry.verify_open(BASELINE, valid_extra),
        Err(GateError::Refused(
            "runtime temporary source projection differs"
        ))
    ));
}

#[test]
fn full_one_page_source_does_not_create_a_fictitious_split() {
    let mut one = source();
    one.end = 0x401000;
    let baseline = replace(BASELINE, "00400000-00404000", "00400000-00401000");
    let open = replace(
        &baseline,
        "00400000-00401000 r--p",
        "00400000-00401000 r-xp",
    );
    let geometry =
        FetchGeometry::for_instruction(one, AddressRange::new(0x400001, 0x400003).unwrap())
            .unwrap();
    assert_eq!(geometry.projected_rows(&baseline).unwrap(), 3);
    geometry.verify_open(&baseline, &open).unwrap();
}

#[test]
fn foreign_or_incomplete_source_geometry_cannot_describe_fetch_permission() {
    for (start, end) in [
        (0x3fffff, 0x400001),
        (0x403fff, 0x404001),
        (0x401000, 0x401010),
    ] {
        assert!(
            FetchGeometry::for_instruction(source(), AddressRange::new(start, end).unwrap())
                .is_err()
        );
    }
    let instruction = AddressRange::new(0x401001, 0x401003).unwrap();
    let mut unaligned = source();
    unaligned.start += 1;
    assert!(FetchGeometry::for_instruction(unaligned, instruction).is_err());
    let mut overflow = source();
    overflow.start = u64::MAX - 8191;
    overflow.end = u64::MAX;
    assert!(
        FetchGeometry::for_instruction(
            overflow,
            AddressRange::new(u64::MAX - 4, u64::MAX - 1).unwrap()
        )
        .is_err()
    );
    for mutation in 0..6 {
        let mut changed = source();
        match mutation {
            0 => changed.current_index = 0,
            1 => changed.offset = 4096,
            2 => changed.file.major = 9,
            3 => changed.file.minor = 2,
            4 => changed.file.inode = 8,
            5 => changed.end -= 4096,
            _ => unreachable!(),
        }
        let geometry = FetchGeometry::for_instruction(changed, instruction).unwrap();
        assert!(
            geometry.projected_rows(BASELINE).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn each_temporary_source_piece_keeps_exact_backing_offsets_paths_and_permissions() {
    let geometry = crossing();
    for (before, after) in [
        ("00401000-00403000", "00401000-00402000"),
        ("00401000-00403000 r-xp", "00401000-00403000 rwxp"),
        ("00401000-00403000 r-xp", "00401000-00403000 r-xs"),
        (
            "r-xp 00001000 08:01 7 /fixture",
            "r-xp 00000000 08:01 7 /fixture",
        ),
        (
            "r-xp 00001000 08:01 7 /fixture",
            "r-xp 00001000 08:02 7 /fixture",
        ),
        (
            "r-xp 00001000 08:01 7 /fixture",
            "r-xp 00001000 08:01 8 /fixture",
        ),
        (
            "r-xp 00001000 08:01 7 /fixture",
            "r-xp 00001000 08:01 7 /different",
        ),
        (
            "r-xp 00001000 08:01 7 /fixture",
            "r-xp 00001000 08:01 7  /fixture",
        ),
        ("00400000-00401000 r--p", "00400000-00401000 r-xp"),
        ("00403000-00404000 r--p", "00403000-00404000 r-xp"),
        ("r--p 00003000", "r--p 00002000"),
    ] {
        assert!(
            geometry
                .verify_open(BASELINE, &replace(TWO_PAGES, before, after))
                .is_err(),
            "{before} -> {after}"
        );
    }
}

#[test]
fn unrelated_rows_and_extra_or_missing_rows_are_not_permissions_to_mutate() {
    let geometry = crossing();
    for (before, after) in [
        ("00100000-00101000 rw-p", "00100000-00101000 r--p"),
        ("00800000-00801000 r-xp", "00800000-00801000 r--p"),
        ("00100000-00101000 rw-p 00000000 00:00 0\n", ""),
        ("00800000-00801000 r-xp 00000000 00:00 0\n", ""),
        ("00100000-00101000 rw-p", "00100000-00101000  rw-p"),
    ] {
        assert!(
            geometry
                .verify_open(BASELINE, &replace(TWO_PAGES, before, after))
                .is_err()
        );
    }
    let mut extra = TWO_PAGES.to_vec();
    extra.extend_from_slice(b"00900000-00901000 r--p 00000000 00:00 0\n");
    assert!(geometry.verify_open(BASELINE, &extra).is_err());
}

#[test]
fn closed_permission_requires_the_complete_original_raw_inventory() {
    assert!(verify_closed(BASELINE, TWO_PAGES).is_err());
    for (before, after) in [
        ("00400000-00404000 r--p", "00400000-00404000 r-xp"),
        (" 08:01 7 /fixture", " 08:01 8 /fixture"),
        (" /fixture", "  /fixture"),
        ("00100000-00101000 rw-p", "00100000-00101000  rw-p"),
    ] {
        assert!(verify_closed(BASELINE, &replace(BASELINE, before, after)).is_err());
    }
    assert!(verify_closed(b"", b"").is_err());
    let mut zero_suffix = BASELINE.to_vec();
    zero_suffix.push(0);
    assert!(verify_closed(BASELINE, &zero_suffix).is_err());
    assert!(verify_closed(&zero_suffix, &zero_suffix).is_err());
}

#[test]
fn prospective_split_row_ceiling_is_checked_before_any_native_effect() {
    let mut bytes = BASELINE.to_vec();
    // 3 original rows + 507 additional rows + 2 split edges = exactly 512.
    for i in 0..507_u64 {
        let start = 0x1000000 + i * PAGE;
        bytes.extend_from_slice(
            format!("{start:08x}-{:08x} r--p 00000000 00:00 0\n", start + PAGE).as_bytes(),
        );
    }
    assert_eq!(crossing().projected_rows(&bytes).unwrap(), 512);
    bytes.extend_from_slice(b"02000000-02001000 r--p 00000000 00:00 0\n");
    assert!(matches!(
        crossing().projected_rows(&bytes),
        Err(GateError::Refused(
            "runtime temporary map projection exceeds its bound"
        ))
    ));
    let mut over = vec![b' '; 64 * 1024 + 1];
    over[0] = b'0';
    assert!(crossing().projected_rows(&over).is_err());
}
