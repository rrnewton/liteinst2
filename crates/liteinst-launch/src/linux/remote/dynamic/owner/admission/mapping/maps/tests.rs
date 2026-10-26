//! Synthetic proc-map bytes only: these controls provide no native identity,
//! anonymous provenance, alias certificate, held-task or publication evidence.
use super::*;

const ONE: &[u8] = b"00400000-00401000 r-xp 00001000 08:02 17    /fixture/a  b  \n";

fn refused(raw: &[u8], limit: usize, expected: MapParseError) {
    assert_eq!(ParsedMaps::parse(raw, limit), Err(expected));
}

#[test]
fn retains_every_identity_field_and_exact_pathname_bytes() {
    let raw = b"00400000-00401000 r-xp ffffffffffffffff ffffffff:abcdef01 18446744073709551615    /fixture/a  b\t\xff (deleted)  \n00402000-00403000 rw-s 00000000 00:00 0\n";
    let view = ParsedMaps::parse(raw, 2).unwrap();
    assert_eq!(view.raw(), raw);
    assert_eq!(view.len(), 2);
    let mut rows = view.entries();
    assert_eq!(rows.len(), 2);
    let first = rows.next().unwrap();
    assert_eq!((first.start, first.end), (0x400000, 0x401000));
    assert_eq!(first.permissions.bytes(), *b"r-xp");
    assert_eq!(first.file_offset, u64::MAX);
    assert_eq!(
        (first.device_major, first.device_minor),
        (u32::MAX, 0xabcdef01)
    );
    assert_eq!(first.inode, u64::MAX);
    assert_eq!(
        first.pathname,
        Some(&b"/fixture/a  b\t\xff (deleted)  "[..])
    );
    assert_eq!(
        first.pathname_column,
        b"    /fixture/a  b\t\xff (deleted)  "
    );
    assert_eq!(
        first.raw_line,
        &raw[..raw.iter().position(|byte| *byte == b'\n').unwrap()]
    );
    let second = rows.next().unwrap();
    assert_eq!(second.permissions.bytes(), *b"rw-s");
    assert_eq!(
        (
            second.file_offset,
            second.device_major,
            second.device_minor,
            second.inode
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(second.pathname, None);
    assert_eq!(second.pathname_column, b"");
    assert_eq!(rows.len(), 0);
    assert!(rows.next().is_none());
}

#[test]
fn whitespace_and_backing_identity_changes_cannot_alias() {
    let original = ParsedMaps::parse(ONE, 1).unwrap().entries().next().unwrap();
    for raw in [
        &b"00400000-00401000 r-xp 00001000 08:02 17    /fixture/a b\n"[..],
        &b"00400000-00401000 r-xp 00001000 08:03 17    /fixture/a  b  \n"[..],
        &b"00400000-00401000 r-xp 00001000 08:02 18    /fixture/a  b  \n"[..],
        &b"00400000-00401000 r-xp 00002000 08:02 17    /fixture/a  b  \n"[..],
    ] {
        let changed = ParsedMaps::parse(raw, 1).unwrap().entries().next().unwrap();
        assert_ne!(changed, original);
    }
    let spacing = b"00400000-00401000 r-xp 00001000 08:02 17 /fixture/a  b  \n";
    let changed = ParsedMaps::parse(spacing, 1)
        .unwrap()
        .entries()
        .next()
        .unwrap();
    assert_eq!(changed.pathname, original.pathname);
    assert_ne!(changed.raw_line, original.raw_line);
    assert_ne!(changed.pathname_column, original.pathname_column);
}

#[test]
fn rejects_incomplete_framing_and_exact_byte_or_row_limit_excess() {
    refused(b"", 1, MapParseError::Empty);
    refused(&ONE[..ONE.len() - 1], 1, MapParseError::Framing);
    refused(
        b"00400000-00401000 r-xp 0 00:00 0 /a\0b\n",
        1,
        MapParseError::Framing,
    );
    refused(ONE, 0, MapParseError::RowLimit);
    let two = b"00400000-00401000 r-xp 0 00:00 0\n00401000-00402000 r--p 0 00:00 0\n";
    assert_eq!(ParsedMaps::parse(two, 2).unwrap().len(), 2);
    refused(two, 1, MapParseError::RowLimit);
    let prefix = b"00400000-00401000 r-xp 0 00:00 0 /";
    let mut boundary = prefix.to_vec();
    boundary.resize(MAX_MAPS_BYTES - 1, b'a');
    boundary.push(b'\n');
    assert_eq!(
        ParsedMaps::parse(&boundary, 1).unwrap().raw().len(),
        MAX_MAPS_BYTES
    );
    boundary.insert(boundary.len() - 1, b'a');
    refused(&boundary, 1, MapParseError::ByteLimit);
}

#[test]
fn rejects_malformed_suffix_instead_of_accepting_valid_prefix() {
    for suffix in [
        &b"\n"[..],
        &b"garbage\n"[..],
        &b"00402000-00403000 rw-p 0 00:00\n"[..],
        &b"00402000-00403000 rw-p 0 00:00 0\n\n"[..],
    ] {
        let mut raw = ONE.to_vec();
        raw.extend_from_slice(suffix);
        refused(&raw, 4, MapParseError::Fields);
    }
}

#[test]
fn rejects_numeric_overflow_signs_prefixes_and_nondecimal_inodes() {
    for raw in [
        &b"10000000000000000-10000000000001000 r--p 0 00:00 0\n"[..],
        &b"00400000-00401000 r--p 10000000000000000 00:00 0\n"[..],
        &b"00400000-00401000 r--p 0 100000000:00 0\n"[..],
        &b"00400000-00401000 r--p 0 00:100000000 0\n"[..],
        &b"00400000-00401000 r--p 0 00:00 18446744073709551616\n"[..],
        &b"00400000-00401000 r--p +0 00:00 0\n"[..],
        &b"00400000-00401000 r--p 0x0 00:00 0\n"[..],
        &b"00400000-00401000 r--p A 00:00 0\n"[..],
        &b"00400000-00401000 r--p 0 00:00 0x10\n"[..],
        &b"00400000-00401000 r--p 0 00:00 -1\n"[..],
    ] {
        refused(raw, 1, MapParseError::Number);
    }
}

#[test]
fn rejects_noncanonical_permissions_and_header_separators() {
    for permissions in ["x--p", "rr-p", "rw-px", "rw-q", "rw-", "rWxp", "rwtp"] {
        let raw = format!("00400000-00401000 {permissions} 0 00:00 0\n");
        refused(raw.as_bytes(), 1, MapParseError::Permissions);
    }
    refused(
        b" 00400000-00401000 rw-p 0 00:00 0\n",
        1,
        MapParseError::Fields,
    );
    refused(
        b"00400000-00401000\trw-p 0 00:00 0\n",
        1,
        MapParseError::Fields,
    );
    refused(
        b"00400000-00401000 rw-p 0 00:00:01 0\n",
        1,
        MapParseError::Fields,
    );
}

#[test]
fn rejects_overlap_reversal_duplicate_and_nonpage_ranges() {
    for raw in [
        &b"00400000-00402000 r--p 0 00:00 0\n00401000-00403000 rw-p 0 00:00 0\n"[..],
        &b"00402000-00403000 r--p 0 00:00 0\n00400000-00401000 rw-p 0 00:00 0\n"[..],
        &b"00400000-00401000 r--p 0 00:00 0\n00400000-00401000 rw-p 0 00:00 0\n"[..],
    ] {
        refused(raw, 2, MapParseError::Order);
    }
    for raw in [
        &b"00400000-00400000 r--p 0 00:00 0\n"[..],
        &b"00401000-00400000 r--p 0 00:00 0\n"[..],
        &b"00400001-00401000 r--p 0 00:00 0\n"[..],
        &b"00400000-00401001 r--p 0 00:00 0\n"[..],
    ] {
        refused(raw, 1, MapParseError::Range);
    }
}

#[test]
fn absent_pathname_is_only_an_observed_field_not_an_alias_certificate() {
    let raw = b"00400000-00401000 rw-p 0 00:00 0    \n00402000-00403000 rw-p 0 00:00 0 [anon:owned  name]\n00404000-00405000 rw-p 0 08:01 7\n";
    let rows: Vec<_> = ParsedMaps::parse(raw, 3).unwrap().entries().collect();
    assert_eq!(rows[0].pathname, None);
    assert_eq!(rows[0].pathname_column, b"    ");
    assert_eq!(rows[1].pathname, Some(&b"[anon:owned  name]"[..]));
    assert_eq!(rows[2].pathname, None);
    assert_eq!(
        (rows[2].device_major, rows[2].device_minor, rows[2].inode),
        (8, 1, 7)
    );
    assert_ne!(rows[0], rows[2]);
}
