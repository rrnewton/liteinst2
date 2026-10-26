//! Pure supplied-row controls, with no native execution or ownership credit.
use super::*;
use crate::linux::remote::dynamic::owner::admission::mapping::maps::ParsedMaps;

const LOWER: &[u8] = b"00400000-00401000 r--p 00001000 08:02 17    /fixture/a  b  \n";
const UPPER: &[u8] = b"00401000-00402000 r-xp 00002000 08:02 17    /fixture/a  b  \n";
const UPPER_NX: &[u8] = b"00401000-00402000 r--p 00002000 08:02 17    /fixture/a  b  \n";
const UNION: &[u8] = b"00400000-00402000 r--p 00001000 08:02 17    /fixture/a  b  \n";

fn row(bytes: &[u8]) -> MapEntry<'_> {
    let parsed = ParsedMaps::parse(bytes, 1).unwrap();
    let mut rows = parsed.entries();
    let row = rows.next().unwrap();
    assert!(rows.next().is_none());
    row
}

fn changed(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).unwrap();
    assert_eq!(text.matches(from).count(), 1);
    text.replace(from, to).into_bytes()
}

fn pair() -> PairRows<'static> {
    PairRows::new(row(LOWER), row(UPPER)).unwrap()
}

#[test]
fn pair_rows_accept_exact_separate_union_and_original_opening() {
    let pair = pair();
    assert_eq!(pair.original_lower().raw_line, row(LOWER).raw_line);
    assert_eq!(pair.original_rx().raw_line, row(UPPER).raw_line);
    assert_eq!(pair.original_rx().start, 0x401000);
    assert_eq!(pair.original_rx().end, 0x402000);
    assert_eq!(pair.original_rx().file_offset, 0x2000);
    pair.verify_separate_nx(row(LOWER), row(UPPER_NX)).unwrap();
    pair.verify_union_nx(row(UNION)).unwrap();
    pair.verify_open_pair(row(LOWER), row(UPPER)).unwrap();

    // The compiler candidate's zero-based file geometry is also descriptive
    // input here. It is not a replay of an actual compiler/native observation.
    let lower = changed(LOWER, "00001000", "00000000");
    let upper = changed(UPPER, "00002000", "00001000");
    let union = changed(UNION, "00001000", "00000000");
    PairRows::new(row(&lower), row(&upper))
        .unwrap()
        .verify_union_nx(row(&union))
        .unwrap();
}

#[test]
fn pair_rows_refuse_each_member_profile_and_identity_change() {
    for (from, to) in [
        ("r--p", "rw-p"),
        ("r--p", "r-xp"),
        ("r--p", "r--s"),
        ("00400000", "003ff000"),
        ("00001000", "00000000"),
        ("08:02", "09:02"),
        ("08:02", "08:03"),
        (" 17 ", " 0 "),
        ("/fixture/a", "/fixture/b"),
        ("17    /", "17   /"),
        ("a  b  ", "a b   "),
    ] {
        let lower = changed(LOWER, from, to);
        assert!(
            PairRows::new(row(&lower), row(UPPER)).is_err(),
            "{from} -> {to}"
        );
    }
    for (from, to) in [
        ("r-xp", "rw-p"),
        ("r-xp", "r--p"),
        ("r-xp", "r-xs"),
        ("00402000", "00403000"),
        ("00002000", "00003000"),
        ("08:02", "09:02"),
        ("08:02", "08:03"),
        (" 17 ", " 18 "),
        ("/fixture/a", "/fixture/b"),
        ("17    /", "17   /"),
        ("a  b  ", "a b   "),
    ] {
        let upper = changed(UPPER, from, to);
        assert!(
            PairRows::new(row(LOWER), row(&upper)).is_err(),
            "{from} -> {to}"
        );
    }
    let lower = changed(LOWER, "/fixture/a  b  ", "[special]");
    let upper = changed(UPPER, "/fixture/a  b  ", "[special]");
    assert!(PairRows::new(row(&lower), row(&upper)).is_err());
    let lower = changed(LOWER, "    /fixture/a  b  ", "");
    let upper = changed(UPPER, "    /fixture/a  b  ", "");
    assert!(PairRows::new(row(&lower), row(&upper)).is_err());
}

#[test]
fn pair_rows_refuse_union_corruption_in_each_retained_column() {
    for (from, to) in [
        ("00400000", "003ff000"),
        ("00402000", "00401000"),
        ("00402000", "00403000"),
        ("r--p", "r-xp"),
        ("r--p", "rw-p"),
        ("r--p", "r--s"),
        ("00001000", "00002000"),
        ("08:02", "09:02"),
        ("08:02", "08:03"),
        (" 17 ", " 18 "),
        ("/fixture/a", "/fixture/b"),
        ("17    /", "17   /"),
        ("a  b  ", "a b   "),
        // Equal numeric fields still require their original exact spelling.
        ("00001000", "000001000"),
        ("08:02", "8:02"),
        (" 17 ", " 017 "),
        ("00400000", "000400000"),
        ("00402000", "000402000"),
        ("r--p ", "r--p  "),
    ] {
        let actual = changed(UNION, from, to);
        assert!(
            pair().verify_union_nx(row(&actual)).is_err(),
            "{from} -> {to}"
        );
    }
}

#[test]
fn pair_rows_refuse_separate_changes_except_the_one_x_bit() {
    assert!(pair().verify_separate_nx(row(LOWER), row(UPPER)).is_err());
    for (from, to) in [
        ("r--p", "r-xp"),
        ("00001000", "00000000"),
        ("/fixture/a", "/fixture/b"),
        ("17    /", "17   /"),
    ] {
        let lower = changed(LOWER, from, to);
        assert!(
            pair()
                .verify_separate_nx(row(&lower), row(UPPER_NX))
                .is_err()
        );
    }
    for (from, to) in [
        ("00402000", "00403000"),
        ("00002000", "00003000"),
        ("r--p", "rw-p"),
        ("08:02", "08:03"),
        ("/fixture/a", "/fixture/b"),
        ("17    /", "17   /"),
        ("00002000", "000002000"),
    ] {
        let upper = changed(UPPER_NX, from, to);
        assert!(pair().verify_separate_nx(row(LOWER), row(&upper)).is_err());
    }
}

#[test]
fn pair_rows_opening_refuses_header_x_and_every_changed_source_row() {
    let header_x = changed(LOWER, "r--p", "r-xp");
    assert!(pair().verify_open_pair(row(&header_x), row(UPPER)).is_err());
    assert!(pair().verify_open_pair(row(LOWER), row(UPPER_NX)).is_err());
    for (from, to) in [
        ("00002000", "00001000"),
        ("00402000", "00403000"),
        ("r-xp", "rwxp"),
        ("/fixture/a", "/fixture/b"),
        ("17    /", "17   /"),
    ] {
        let upper = changed(UPPER, from, to);
        assert!(pair().verify_open_pair(row(LOWER), row(&upper)).is_err());
    }
}

#[test]
fn pair_rows_detect_both_third_row_extensions_without_absorbing_them() {
    let left = b"003ff000-00400000 r--p 00000000 08:02 17    /fixture/a  b  \n";
    let right = b"00402000-00403000 r--p 00003000 08:02 17    /fixture/a  b  \n";
    for original in [left.as_slice(), right.as_slice()] {
        assert!(pair().extends_run(row(original)));
        let executable = changed(original, "r--p", "r-xp");
        assert!(pair().extends_run(row(&executable)));
        let padding = changed(original, "17    /", "17           /");
        assert!(pair().extends_run(row(&padding)));
        let inode_width = changed(original, " 17 ", " 017 ");
        assert!(pair().extends_run(row(&inode_width)));
        let device_width = changed(original, "08:02", "8:2");
        assert!(pair().extends_run(row(&device_width)));
        let different_path = changed(original, "/fixture/a", "/fixture/b");
        assert!(!pair().extends_run(row(&different_path)));
        let writable = changed(original, "r--p", "rw-p");
        assert!(!pair().extends_run(row(&writable)));
        let different = changed(original, "08:02", "08:03");
        assert!(!pair().extends_run(row(&different)));
    }
    let discontinuous = changed(right, "00003000", "00004000");
    assert!(!pair().extends_run(row(&discontinuous)));
    let gap = b"00403000-00404000 r--p 00003000 08:02 17    /fixture/a  b  \n";
    assert!(!pair().extends_run(row(gap)));
    // Crossing the kernel's minimum eight-digit offset width changes the
    // pathname-column padding without changing same-file adjacency.
    let lower = changed(LOWER, "00001000", "ffffe000");
    let upper = changed(UPPER, "00002000", "fffff000");
    let wide_right = b"00402000-00403000 r--p 100000000 08:02 17   /fixture/a  b  \n";
    assert!(
        PairRows::new(row(&lower), row(&upper))
            .unwrap()
            .extends_run(row(wide_right))
    );
    let wide_lower = b"00400000-00401000 r--p 100000000 08:02 17   /fixture/a  b  \n";
    let wide_upper = b"00401000-00402000 r-xp 100001000 08:02 17   /fixture/a  b  \n";
    let narrow_left = b"003ff000-00400000 r--p fffff000 08:02 17    /fixture/a  b  \n";
    assert!(
        PairRows::new(row(wide_lower), row(wide_upper))
            .unwrap()
            .extends_run(row(narrow_left))
    );
    // A larger actual union remains forbidden, even when the third row is
    // compatible; callers must refuse, not absorb it or enlarge source scope.
    let larger = changed(UNION, "00402000", "00403000");
    assert!(pair().verify_union_nx(row(&larger)).is_err());
}

#[test]
fn pair_rows_reject_file_end_overflow_and_unaligned_offsets() {
    let lower = changed(LOWER, "00001000", "ffffffffffffe000");
    let upper = changed(UPPER, "00002000", "fffffffffffff000");
    assert!(PairRows::new(row(&lower), row(&upper)).is_err());
    let lower = changed(LOWER, "00001000", "00001001");
    let upper = changed(UPPER, "00002000", "00002001");
    assert!(PairRows::new(row(&lower), row(&upper)).is_err());
}

#[test]
fn pair_rows_refuse_new_pair_field_width_and_separator_spelling() {
    for (from, to) in [
        ("00401000", "000401000"),
        ("00402000", "000402000"),
        ("00002000", "000002000"),
        ("08:02", "8:02"),
        (" 17 ", " 017 "),
        ("r-xp ", "r-xp  "),
        ("00402000 ", "00402000  "),
    ] {
        let upper = changed(UPPER, from, to);
        assert!(
            PairRows::new(row(LOWER), row(&upper)).is_err(),
            "{from} -> {to}"
        );
    }
}
