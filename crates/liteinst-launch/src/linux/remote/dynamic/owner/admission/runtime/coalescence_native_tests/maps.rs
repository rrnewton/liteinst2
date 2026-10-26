//! Independent literal-fixture map oracle. No production projection or parser
//! computes the expected merge/opening. Every unaffected raw row stays exact.
use super::*;

const LOWER: &[u8] = b"00400000-00401000 r--p 00000000 ";
const UPPER: &[u8] = b"00401000-00402000 r-xp 00001000 ";
const UNION: &[u8] = b"00400000-00402000 r--p 00000000 ";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Pair {
    pub(super) lower: NativeMap,
    pub(super) upper: NativeMap,
    pub(super) device: Vec<u8>,
    pub(super) inode: u64,
    pub(super) pathname: Vec<u8>,
}

pub(super) fn original(raw: &[u8]) -> Pair {
    let all = rows(raw);
    let pair = all
        .iter()
        .filter(|row| row.start < END && BASE < row.end)
        .collect::<Vec<_>>();
    assert_eq!(pair.len(), 2);
    assert_eq!(
        (pair[0].start, pair[0].end, pair[0].permissions),
        (BASE, ENTRY, *b"r--p")
    );
    assert_eq!(
        (pair[1].start, pair[1].end, pair[1].permissions),
        (ENTRY, END, *b"r-xp")
    );
    let suffix = pair[0].raw.strip_prefix(LOWER).unwrap();
    assert_eq!(pair[1].raw.strip_prefix(UPPER).unwrap(), suffix);
    let mut fields = suffix.splitn(3, |byte| *byte == b' ');
    let device = fields.next().unwrap().to_vec();
    let inode = std::str::from_utf8(fields.next().unwrap())
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let pathname = fields.next().unwrap();
    let pathname = pathname.trim_ascii_start().to_vec();
    assert!(device.contains(&b':') && device != b"00:00");
    assert!(inode != 0 && pathname.starts_with(b"/") && pathname.ends_with(b"/fixture"));
    Pair {
        lower: pair[0].clone(),
        upper: pair[1].clone(),
        device,
        inode,
        pathname,
    }
}

fn fixed(row: &NativeMap) -> bool {
    row.start == 0xffff_ffff_ff60_0000
        && row.end == 0xffff_ffff_ff60_1000
        && row.raw.ends_with(b"[vsyscall]")
}
fn put(output: &mut Vec<u8>, row: &[u8]) {
    output.extend_from_slice(row);
    output.push(b'\n');
}
fn merged(pair: &Pair) -> Vec<u8> {
    let mut result = UNION.to_vec();
    result.extend_from_slice(pair.lower.raw.strip_prefix(LOWER).unwrap());
    result
}

pub(super) fn island(raw: &[u8], range: &std::ops::Range<u64>) -> NativeMap {
    let all = rows(raw);
    let exact = all
        .iter()
        .filter(|row| row.start == range.start && row.end == range.end)
        .collect::<Vec<_>>();
    assert_eq!(exact.len(), 1);
    let row = exact[0];
    assert_eq!(range.end - range.start, 4096);
    assert_eq!(row.permissions, *b"r-xp");
    let fields = row
        .raw
        .split(|byte| *byte == b' ')
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), 5);
    assert_eq!(
        u64::from_str_radix(std::str::from_utf8(fields[2]).unwrap(), 16).unwrap(),
        0
    );
    assert_eq!(fields[3], b"00:00");
    assert_eq!(fields[4], b"0");
    row.clone()
}

/// Entire original inventory, plus exactly one independently checked island.
/// Prefix is the count of original executable rows already quarantined.
pub(super) fn expected(
    original: &[u8],
    pair: &Pair,
    island: &NativeMap,
    prefix: usize,
    merge: bool,
) -> Vec<u8> {
    let all = rows(original);
    assert!(
        all.iter()
            .all(|row| row.end <= island.start || island.end <= row.start)
    );
    let mut result = Vec::new();
    let mut inserted = false;
    let mut ordinal = 0;
    let mut replaced = 0;
    for row in all {
        if !inserted && island.start < row.start {
            put(&mut result, &island.raw);
            inserted = true;
        }
        let executable = row.permissions[2] == b'x' && !fixed(&row);
        if merge && row.start == BASE {
            assert_eq!(row, pair.lower);
            put(&mut result, &merged(pair));
            replaced += 1;
        } else if merge && row.start == ENTRY {
            assert_eq!(row, pair.upper);
            assert!(ordinal < prefix, "RX source was not actually quarantined");
        } else {
            let mut raw = row.raw.clone();
            if executable && ordinal < prefix {
                raw[row.x_column] = b'-';
            }
            put(&mut result, &raw);
        }
        if executable {
            ordinal += 1;
        }
    }
    if !inserted {
        put(&mut result, &island.raw);
    }
    assert!(prefix <= ordinal);
    assert_eq!(replaced, usize::from(merge));
    result
}

pub(super) fn counts(original: &[u8]) -> (usize, usize) {
    let mut count = 0;
    let mut target = None;
    for row in rows(original) {
        if row.permissions[2] == b'x' && !fixed(&row) {
            if row.start == ENTRY {
                assert!(target.replace(count).is_none());
            }
            count += 1;
        }
    }
    (count, target.unwrap())
}

pub(super) fn opened(baseline: &[u8], actual: &[u8], pair: &Pair) {
    let mut expected = Vec::new();
    let mut count = 0;
    for row in rows(baseline) {
        if row.start == BASE && row.end == END {
            assert_eq!(row.raw, merged(pair));
            count += 1;
            put(&mut expected, &pair.lower.raw);
            put(&mut expected, &pair.upper.raw);
        } else {
            put(&mut expected, &row.raw);
        }
    }
    assert_eq!(count, 1, "actual NX union is mandatory");
    assert_eq!(actual, expected);
    let actual = rows(actual);
    assert!(actual.iter().any(|row| row.raw == pair.lower.raw));
    assert!(actual.iter().any(|row| row.raw == pair.upper.raw));
}

/// Independent projection of the complete public descriptor fields. Preserve
/// the entire pathname suffix, including internal/trailing spaces; only the
/// kernel's formatting spaces before the pathname are skipped.
pub(super) fn descriptor(row: &NativeMap) -> crate::MemoryMapping {
    let mut cursor = 0;
    let mut fields = Vec::new();
    for _ in 0..5 {
        while row.raw.get(cursor) == Some(&b' ') {
            cursor += 1;
        }
        let start = cursor;
        while row.raw.get(cursor).is_some_and(|byte| *byte != b' ') {
            cursor += 1;
        }
        assert!(start < cursor);
        fields.push(&row.raw[start..cursor]);
    }
    assert_eq!(fields[1], row.permissions);
    let file_offset = u64::from_str_radix(std::str::from_utf8(fields[2]).unwrap(), 16).unwrap();
    while row.raw.get(cursor) == Some(&b' ') {
        cursor += 1;
    }
    let pathname = (cursor < row.raw.len())
        .then(|| std::str::from_utf8(&row.raw[cursor..]).unwrap().to_owned());
    crate::MemoryMapping {
        start: row.start,
        end: row.end,
        permissions: std::str::from_utf8(&row.permissions).unwrap().to_owned(),
        file_offset,
        pathname,
    }
}

pub(super) fn original_executables(raw: &[u8]) -> Vec<crate::MemoryMapping> {
    rows(raw)
        .iter()
        .filter(|row| row.permissions[2] == b'x' && !fixed(row))
        .map(descriptor)
        .collect()
}
