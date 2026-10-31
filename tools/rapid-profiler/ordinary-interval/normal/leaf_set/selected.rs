//! Frozen application results for the separately named selected session.
//!
//! These bytes describe expected scalar results, not authority to invoke native
//! code. Complete-function, ABI, readable-input and lifetime premises remain the
//! caller's independent obligation under the unchanged module contract.
use super::{FunctionId, Policy, Preparation, Selection, failure, input, number, record_cap};
use std::ffi::{OsStr, OsString};
use std::fs::{Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;

const TABLE_BYTES: usize = 1024 * 1024;
const LABEL_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Label {
    bytes: [u8; LABEL_BYTES],
    length: u8,
}
impl Label {
    pub(super) fn new(value: &str) -> Result<Self, String> {
        let raw = value.as_bytes();
        if raw.is_empty()
            || raw.len() > LABEL_BYTES
            || !raw[0].is_ascii_alphabetic()
            || !raw.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            return Err("selected label must be 1..24 ASCII identifier bytes".into());
        }
        let mut bytes = [0; LABEL_BYTES];
        bytes[..raw.len()].copy_from_slice(raw);
        Ok(Self {
            bytes,
            length: raw.len() as u8,
        })
    }
    pub(super) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..usize::from(self.length)]).expect("immutable ASCII label")
    }
}

#[derive(Debug)]
pub(super) struct Row {
    record: input::Record,
    dimension: usize,
    values: Box<[u64]>,
}
impl Row {
    pub(super) fn expected(&self, record: &input::Record, column: usize) -> u64 {
        self.record.check();
        record.check();
        assert!((1..=4).contains(&self.dimension));
        assert_eq!(self.values.len(), self.dimension);
        assert!(column < self.dimension);
        assert_eq!(&self.record, record, "frozen selected input identity");
        self.values[column]
    }
}

#[derive(Debug)]
pub(super) struct Table {
    functions: Box<[FunctionId]>,
    rows: Box<[Arc<Row>]>,
}
impl Table {
    pub(super) fn parse(raw: &[u8], functions: &[FunctionId]) -> Result<Self, String> {
        if !(1..=4).contains(&functions.len())
            || functions
                .iter()
                .enumerate()
                .any(|(i, id)| functions[..i].contains(id))
        {
            return Err("complete unique selected function table required".into());
        }
        if raw.is_empty()
            || raw.len() > TABLE_BYTES
            || raw.last() != Some(&b'\n')
            || raw
                .iter()
                .any(|b| *b != b'\n' && !(0x20..=0x7e).contains(b))
        {
            return Err("bounded ASCII LF-terminated selected table required".into());
        }
        let text = std::str::from_utf8(raw).map_err(failure)?;
        // Strip exactly the required final LF, so extra/trailing lines survive
        // and cannot be silently discarded by a whitespace-oriented parser.
        let mut lines = text[..text.len() - 1].split('\n');
        let header = fields(lines.next().ok_or("selected header missing")?)?;
        if header.len() != 4 || header[0] != "LI2SELECTED" || header[1] != "1" {
            return Err("selected table version or header shape".into());
        }
        let n = usize::try_from(decimal(header[2])?).map_err(failure)?;
        let m = usize::try_from(decimal(header[3])?).map_err(failure)?;
        if n != functions.len() || !(1..=record_cap(n)).contains(&m) {
            return Err("selected table dimensions exceed the fixed session profile".into());
        }
        let ids = fields(lines.next().ok_or("selected functions missing")?)?;
        if ids.len() != n + 1 || ids[0] != "functions" {
            return Err("selected function row shape".into());
        }
        for (token, expected) in ids[1..].iter().zip(functions) {
            if FunctionId(decimal(token)?) != *expected {
                return Err("selected functions differ from the exact selection order".into());
            }
        }
        let mut rows = Vec::with_capacity(m);
        for ordinal in 1..=m {
            let row = fields(lines.next().ok_or("selected record missing")?)?;
            if row.len() != n + 3 || row[0] != "record" || decimal(row[1])? != ordinal as u64 {
                return Err("complete consecutive selected record row required".into());
            }
            let bytes = payload(row[2])?;
            let record = input::Record::new(ordinal as u64, &bytes)
                .map_err(|why| format!("selected record refused: {}", why.label()))?;
            let values = row[3..]
                .iter()
                .map(|token| decimal(token))
                .collect::<Result<Vec<_>, _>>()?;
            rows.push(Arc::new(Row {
                record,
                dimension: n,
                values: values.into_boxed_slice(),
            }));
        }
        if lines.next() != Some("END") || lines.next().is_some() {
            return Err("selected table must end immediately after all declared records".into());
        }
        Ok(Self {
            functions: functions.into(),
            rows: rows.into_boxed_slice(),
        })
    }
    pub(super) fn row(&self, record: &input::Record) -> Result<Arc<Row>, String> {
        record.check();
        let index = usize::try_from(record.id - 1).map_err(failure)?;
        let row = self
            .rows
            .get(index)
            .ok_or("input has no frozen selected row")?;
        row.record.check();
        if &row.record != record {
            return Err("input differs from its exact frozen selected row".into());
        }
        if row.dimension != self.functions.len() || row.values.len() != row.dimension {
            return Err("selected row dimension differs from the function table".into());
        }
        Ok(Arc::clone(row))
    }
    pub(super) fn count(&self) -> usize {
        self.rows.len()
    }
    pub(super) fn functions(&self) -> &[FunctionId] {
        &self.functions
    }
    pub(super) fn complete(&self, accepted: usize) -> Result<(), String> {
        if accepted != self.count() {
            return Err("selected input must consume every frozen row exactly once".into());
        }
        Ok(())
    }
}

fn fields(line: &str) -> Result<Vec<&str>, String> {
    let fields: Vec<_> = line.split(' ').collect();
    if fields.iter().any(|field| field.is_empty()) {
        return Err("selected table requires canonical single-space framing".into());
    }
    Ok(fields)
}
fn decimal(token: &str) -> Result<u64, String> {
    number(OsStr::new(token))
}
fn payload(token: &str) -> Result<Vec<u8>, String> {
    if token == "-" {
        return Ok(Vec::new());
    }
    let raw = token.as_bytes();
    if raw.is_empty()
        || raw.len() > input::PAYLOAD * 2
        || raw.len() % 2 != 0
        || !raw
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err("selected payload must be bounded lowercase hex or dash".into());
    }
    let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(raw
        .chunks_exact(2)
        .map(|b| nibble(b[0]) * 16 + nibble(b[1]))
        .collect())
}

type ParsedArguments = (usize, u32, Vec<Selection>, Arc<Table>);

pub(super) fn arguments(args: &[OsString]) -> Result<ParsedArguments, String> {
    arguments_with(args, read_table)
}
fn arguments_with(
    args: &[OsString],
    load: impl FnOnce(&Path, &[FunctionId]) -> Result<Table, String>,
) -> Result<ParsedArguments, String> {
    if args.len() < 6 {
        return Err("normal-selected-session CANDIDATE TRUSTED_FINAL TABLE K EPOCHS N (ID LABEL ELF_VA EXTENT POLICY){N}".into());
    }
    let k = usize::try_from(number(&args[3])?).map_err(failure)?;
    let epochs = u32::try_from(number(&args[4])?).map_err(failure)?;
    let n = usize::try_from(number(&args[5])?).map_err(failure)?;
    if !matches!(k, 10 | 1000)
        || !(1..=520).contains(&epochs)
        || !(1..=4).contains(&n)
        || args.len() != 6 + 5 * n
    {
        return Err("closed selected session profile".into());
    }
    let (selections, table) = selection_table(&args[6..], &args[2], n, load)?;
    Ok((k, epochs, selections, table))
}

type AccuracyArguments = (Policy, Vec<Selection>, Arc<Table>);
pub(super) fn accuracy_arguments(args: &[OsString]) -> Result<AccuracyArguments, String> {
    accuracy_arguments_with(args, read_table)
}
fn accuracy_arguments_with(
    args: &[OsString],
    load: impl FnOnce(&Path, &[FunctionId]) -> Result<Table, String>,
) -> Result<AccuracyArguments, String> {
    if args.len() < 7 {
        return Err("normal-selected-accuracy-session CANDIDATE TRUSTED_FINAL TABLE K EPOCH_MS EPOCHS N (ID LABEL ELF_VA EXTENT POLICY){N}".into());
    }
    let k = usize::try_from(number(&args[3])?).map_err(failure)?;
    let epoch_ms = u32::try_from(number(&args[4])?).map_err(failure)?;
    let epochs = u32::try_from(number(&args[5])?).map_err(failure)?;
    let n = usize::try_from(number(&args[6])?).map_err(failure)?;
    if !(1..=520).contains(&epochs) || !(1..=4).contains(&n) || args.len() != 7 + 5 * n {
        return Err("closed selected accuracy session profile".into());
    }
    let policy = Policy::accuracy(k, epoch_ms, epochs, 4096).map_err(failure)?;
    let (selections, table) = selection_table(&args[7..], &args[2], n, load)?;
    Ok((policy, selections, table))
}
fn selection_table(
    rows: &[OsString],
    path: &std::ffi::OsStr,
    n: usize,
    load: impl FnOnce(&Path, &[FunctionId]) -> Result<Table, String>,
) -> Result<(Vec<Selection>, Arc<Table>), String> {
    let mut selections: Vec<Selection> = Vec::with_capacity(n);
    for row in rows.chunks_exact(5) {
        let selection = Selection {
            function: FunctionId(number(&row[0])?),
            label: Label::new(row[1].to_str().ok_or("ASCII selected label required")?)?,
            va: number(&row[2])?,
            extent: usize::try_from(number(&row[3])?).map_err(failure)?,
            policy: Preparation::parse(row[4].to_str().ok_or("ASCII policy required")?)?,
        };
        let range = match selection.policy {
            Preparation::Certified => 1..=256,
            Preparation::Whole => 5..=80,
        };
        if selection.va == 0
            || !range.contains(&selection.extent)
            || selection.va.checked_add(selection.extent as u64).is_none()
            || selections
                .iter()
                .any(|p| p.function == selection.function || p.label == selection.label)
            || selections.last().is_some_and(|p| {
                p.va >= selection.va || p.va.checked_add(p.extent as u64).unwrap() > selection.va
            })
        {
            return Err("complete canonical selected function table required".into());
        }
        selections.push(selection);
    }
    let functions: Vec<_> = selections.iter().map(|s| s.function).collect();
    let table = load(Path::new(path), &functions)?;
    Ok((selections, Arc::new(table)))
}

#[derive(Debug, Eq, PartialEq)]
struct Stamp {
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u64,
    uid: u32,
    gid: u32,
    rdev: u64,
    len: u64,
    blksize: u64,
    blocks: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl From<&Metadata> for Stamp {
    fn from(m: &Metadata) -> Self {
        // Access time is deliberately excluded: reading the owned snapshot may
        // update it. Identity, ownership, layout and mutation stamps are exact.
        Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            nlink: m.nlink(),
            uid: m.uid(),
            gid: m.gid(),
            rdev: m.rdev(),
            len: m.len(),
            blksize: m.blksize(),
            blocks: m.blocks(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}
fn same_named_file(path: &Path, expected: &Stamp) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(failure)?;
    if !metadata.is_file() || Stamp::from(&metadata) != *expected {
        return Err("selected table path identity changed".into());
    }
    Ok(())
}
fn read_table(path: &Path, functions: &[FunctionId]) -> Result<Table, String> {
    // NONBLOCK prevents opening a substituted FIFO from waiting before the
    // regular-file check. NOFOLLOW applies to the supplied final component.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(failure)?;
    let metadata = file.metadata().map_err(failure)?;
    if !metadata.is_file() || !(1..=TABLE_BYTES as u64).contains(&metadata.len()) {
        return Err("selected table must be a bounded nonempty regular file".into());
    }
    let before = Stamp::from(&metadata);
    let canonical = std::fs::canonicalize(path).map_err(failure)?;
    same_named_file(path, &before)?;
    same_named_file(&canonical, &before)?;
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(TABLE_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(failure)?;
    if raw.len() as u64 != before.len
        || raw.len() > TABLE_BYTES
        || Stamp::from(&file.metadata().map_err(failure)?) != before
        || std::fs::canonicalize(path).map_err(failure)? != canonical
    {
        return Err("selected table changed during bounded snapshot".into());
    }
    same_named_file(path, &before)?;
    same_named_file(&canonical, &before)?;
    Table::parse(&raw, functions)
}

// A separate literal grammar. The old selected/accuracy entrypoints above do
// not accept PHASE/DELAY_NS or inherit this initial one-function restriction.
type PhaseArguments = (super::phase::Request, Vec<Selection>, Arc<Table>);
pub(super) fn phase_arguments(args: &[OsString]) -> Result<PhaseArguments, String> {
    phase_arguments_with(args, read_table)
}
fn phase_arguments_with(
    args: &[OsString],
    load: impl FnOnce(&Path, &[FunctionId]) -> Result<Table, String>,
) -> Result<PhaseArguments, String> {
    if args.len() != 14 {
        return Err("normal-selected-accuracy-phase-session CANDIDATE TRUSTED_FINAL TABLE K EPOCH_MS EPOCHS PHASE DELAY_NS 1 41 exact_work_nonempty ELF_VA 37 whole".into());
    }
    let k = usize::try_from(number(&args[3])?).map_err(failure)?;
    let ms = u32::try_from(number(&args[4])?).map_err(failure)?;
    let epochs = u32::try_from(number(&args[5])?).map_err(failure)?;
    if !(1..=520).contains(&epochs)
        || number(&args[8])? != 1
        || number(&args[9])? != super::phase::FUNCTION
        || args[10].to_str() != Some("exact_work_nonempty")
        || number(&args[12])? != 37
        || args[13].to_str() != Some("whole")
    {
        return Err("phase requires exactly the whole nonempty Exact37 selection".into());
    }
    let policy = Policy::accuracy(k, ms, epochs, 4096).map_err(failure)?;
    let request = super::phase::Request::new(
        args[6].to_str().ok_or("ASCII phase required")?,
        number(&args[7])?,
        policy,
    )
    .map_err(failure)?;
    let (leaves, table) = selection_table(&args[9..], &args[2], 1, load)?;
    if table.count() != super::phase::CALLS
        || table
            .rows
            .iter()
            .any(|row| !(1..=64).contains(&row.record.length))
    {
        return Err("phase requires all2048 nonempty 1..64-byte frozen inputs".into());
    }
    Ok((request, leaves, table))
}

#[cfg(test)]
#[path = "selected_tests.rs"]
pub(in crate::normal) mod controls;

#[cfg(test)]
mod accuracy_tests;

#[cfg(test)]
mod phase_tests {
    use super::*;
    fn args() -> Vec<OsString> {
        [
            "candidate",
            "trusted",
            "table",
            "10",
            "10",
            "520",
            "locked",
            "0",
            "1",
            "41",
            "exact_work_nonempty",
            "4096",
            "37",
            "whole",
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }
    fn table(functions: &[FunctionId], count: usize, first: &str) -> Result<Table, String> {
        let mut raw = format!("LI2SELECTED 1 1 {count}\nfunctions 41\n");
        for id in 1..=count {
            raw.push_str(&format!(
                "record {id} {} 0\n",
                if id == 1 { first } else { "41" }
            ));
        }
        raw.push_str("END\n");
        Table::parse(raw.as_bytes(), functions)
    }
    #[test]
    fn phase_cli_is_explicit_and_mutually_refuses_legacy_grammars() {
        let original = args();
        let (request, leaves, values) =
            phase_arguments_with(&original, |_, f| table(f, 2048, "41")).unwrap();
        assert_eq!(
            request.policy(),
            Policy::accuracy(10, 10, 520, 4096).unwrap()
        );
        assert_eq!(leaves.len(), 1);
        assert_eq!(values.count(), 2048);
        assert!(
            arguments_with(&original, |_, _| panic!("legacy must refuse before load")).is_err()
        );
        assert!(
            accuracy_arguments_with(&original, |_, _| panic!("legacy must refuse before load"))
                .is_err()
        );
        let mut old = original.clone();
        old.drain(6..8);
        assert!(accuracy_arguments_with(&old, |_, f| table(f, 2048, "41")).is_ok());
        assert!(
            phase_arguments_with(&old, |_, _| panic!("phase must refuse legacy grammar")).is_err()
        );
        for (column, value) in [
            (3, "2"),
            (4, "2"),
            (5, "0"),
            (5, "521"),
            (6, "other"),
            (7, "1"),
            (7, "-1"),
            (7, "00"),
            (8, "2"),
            (9, "42"),
            (10, "other"),
            (11, "0"),
            (12, "36"),
            (13, "certified"),
        ] {
            let mut changed = original.clone();
            changed[column] = value.into();
            assert!(phase_arguments_with(&changed, |_, f| table(f, 2048, "41")).is_err());
        }
        let mut extra = original.clone();
        extra.push("extra".into());
        assert!(phase_arguments_with(&extra, |_, _| panic!("extra CLI field")).is_err());
        let mut random = original.clone();
        random[6] = "random".into();
        for delay in [0, 9_999_999] {
            random[7] = delay.to_string().into();
            assert!(phase_arguments_with(&random, |_, f| table(f, 2048, "41")).is_ok());
        }
        random[7] = "10000000".into();
        assert!(phase_arguments_with(&random, |_, f| table(f, 2048, "41")).is_err());
    }
    #[test]
    fn phase_parser_requires_every_nonempty_frozen_input_without_changing_old_table() {
        for count in [1, 2047] {
            assert!(phase_arguments_with(&args(), |_, f| table(f, count, "41")).is_err());
        }
        // Empty input is legal in the old selected table, never in Exact37.
        assert!(table(&[FunctionId(41)], 2048, "-").is_ok());
        assert!(phase_arguments_with(&args(), |_, f| table(f, 2048, "-")).is_err());
        assert!(phase_arguments_with(&args(), |_, f| table(f, 2048, &"41".repeat(64))).is_ok());
        assert!(phase_arguments_with(&args(), |_, f| table(f, 2048, &"41".repeat(65))).is_err());
    }
}
