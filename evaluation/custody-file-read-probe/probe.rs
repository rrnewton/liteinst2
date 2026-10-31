//! Unexecuted, fixed diagnostic probe; no profiler or performance qualification.
//! The Take<File> stays alive only to split read completion from its ordinary
//! statement-end drop. Drop's close result and syscall counts are unobserved.
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

// The owner hashes this input before compilation: SHA256
// ec282b162def940f84a37e8945adfb745a96991bd0c1458a3f782d6308d57b20.
const EXPECTED: &[u8; 13_360] = include_bytes!(env!("CUSTODY_PROBE_EXPECTED"));
const LIMIT: u64 = 1024 * 1024 + 1;
const REPETITIONS: u32 = 5;
const WARMUP_PAIRS: u32 = 64;
const MEASURED_PAIRS: u32 = 256;
const ROWS: usize = ((WARMUP_PAIRS + MEASURED_PAIRS) * 2) as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    dev: u64,
    ino: u64,
    mode: u32,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

impl Stamp {
    fn read(path: &Path) -> io::Result<Self> {
        let m = fs::metadata(path)?;
        if !m.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not regular"));
        }
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            len: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        })
    }
}

// Expected stamps come from the owner's independent preflight. No measured
// read, pathname lookup or input argument derives a replacement expectation.
struct Inputs {
    repetition: u32,
    paths: [PathBuf; 2],
    stamps: [Stamp; 2],
}

fn parse_stamp(text: &str) -> Option<Stamp> {
    let fields: Vec<_> = text.split(',').collect();
    if fields.len() != 8 {
        return None;
    }
    Some(Stamp {
        dev: fields[0].parse().ok()?,
        ino: fields[1].parse().ok()?,
        mode: fields[2].parse().ok()?,
        len: fields[3].parse().ok()?,
        mtime: fields[4].parse().ok()?,
        mtime_ns: fields[5].parse().ok()?,
        ctime: fields[6].parse().ok()?,
        ctime_ns: fields[7].parse().ok()?,
    })
}

fn arguments(args: &[String]) -> Option<Inputs> {
    if args.len() != 6 {
        return None;
    }
    let repetition: u32 = args[1].parse().ok()?;
    let paths = [PathBuf::from(&args[2]), PathBuf::from(&args[3])];
    let stamps = [parse_stamp(&args[4])?, parse_stamp(&args[5])?];
    if !(1..=REPETITIONS).contains(&repetition)
        || paths.iter().any(|p| !p.is_absolute())
        || paths[0] == paths[1]
        || (stamps[0].dev, stamps[0].ino) == (stamps[1].dev, stamps[1].ino)
        || stamps.iter().any(|s| {
            s.len != EXPECTED.len() as u64
                || s.mode & 0o170000 != 0o100000
                || !(0..1_000_000_000).contains(&s.mtime_ns)
                || !(0..1_000_000_000).contains(&s.ctime_ns)
        })
    {
        return None;
    }
    Some(Inputs {
        repetition,
        paths,
        stamps,
    })
}

// Numeric CSV statuses: 0=unrun, 1=OK, 2=before-stat I/O/nonregular,
// 3=before-stamp mismatch, 4=open error, 5=read error, 6=byte mismatch,
// 7=after-stat I/O/nonregular, 8=after-stamp mismatch, 9=clock regression.
// Missing durations/counts/errno use -1, never an invented zero.
#[derive(Default)]
struct Row {
    status: u8,
    open_ns: Option<u128>,
    read_ns: Option<u128>,
    drop_ns: Option<u128>,
    total_ns: Option<u128>,
    read_result: Option<usize>,
    observed_bytes: Option<usize>,
    remaining: Option<u64>,
    capacity_before: Option<usize>,
    capacity_after: Option<usize>,
    os_error: Option<i32>,
}

fn elapsed(a: Instant, b: Instant) -> Option<u128> {
    b.checked_duration_since(a).map(|d| d.as_nanos())
}

fn one(path: &Path, expected_stamp: Stamp, actual: &mut Vec<u8>) -> Row {
    let mut row = Row::default();
    match Stamp::read(path) {
        Ok(s) if s == expected_stamp => {}
        Ok(_) => {
            row.status = 3;
            return row;
        }
        Err(e) => {
            row.status = 2;
            row.os_error = e.raw_os_error();
            return row;
        }
    }
    // Original order: pathname stamp, clear, fresh open/bounded read/drop,
    // exact byte comparison, pathname stamp. No descriptor or answer is reused.
    actual.clear();
    row.capacity_before = Some(actual.capacity());
    let t0 = Instant::now();
    let opened = File::open(path);
    let t1 = Instant::now();
    let file = match opened {
        Ok(file) => file,
        Err(e) => {
            row.open_ns = elapsed(t0, t1);
            row.status = 4;
            row.os_error = e.raw_os_error();
            return row;
        }
    };
    let mut bounded = file.take(LIMIT);
    let result = bounded.read_to_end(actual);
    let remaining = bounded.limit();
    let t2 = Instant::now();
    drop(bounded);
    let t3 = Instant::now();
    row.open_ns = elapsed(t0, t1);
    row.read_ns = elapsed(t1, t2);
    row.drop_ns = elapsed(t2, t3);
    row.total_ns = elapsed(t0, t3);
    row.observed_bytes = Some(actual.len());
    row.remaining = Some(remaining);
    row.capacity_after = Some(actual.capacity());
    match result {
        Ok(n) => row.read_result = Some(n),
        Err(e) => {
            row.status = 5;
            row.os_error = e.raw_os_error();
            return row;
        }
    }
    // As in the production statement, close precedes this byte comparison.
    if actual.as_slice() != EXPECTED {
        row.status = 6;
        return row;
    }
    match Stamp::read(path) {
        Ok(s) if s == expected_stamp => {}
        Ok(_) => {
            row.status = 8;
            return row;
        }
        Err(e) => {
            row.status = 7;
            row.os_error = e.raw_os_error();
            return row;
        }
    }
    row.status = if [row.open_ns, row.read_ns, row.drop_ns, row.total_ns]
        .iter()
        .all(Option::is_some)
    {
        1
    } else {
        9
    };
    row
}

fn number<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "-1".into(), |v| v.to_string())
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().collect();
    let Some(inputs) = arguments(&args) else {
        eprintln!(
            "probe refused: repetition 1..5, two distinct absolute paths, and two independently pinned eight-field stamps required"
        );
        return ExitCode::FAILURE;
    };
    let repetition = inputs.repetition;
    // Allocate fixed reporting storage before measurement. Nothing is formatted
    // or written in the measured loop; no warmup or outlier rows are discarded.
    let mut rows: Vec<Row> = (0..ROWS).map(|_| Row::default()).collect();
    let mut actual = Vec::new();
    let mut completed = 0;
    'pairs: for pair in 0..WARMUP_PAIRS + MEASURED_PAIRS {
        actual.clear();
        actual.reserve(EXPECTED.len().min(LIMIT as usize));
        for file in 0..2 {
            let index = pair as usize * 2 + file;
            rows[index] = one(&inputs.paths[file], inputs.stamps[file], &mut actual);
            if rows[index].status != 1 {
                break 'pairs;
            }
            completed += 1;
        }
        actual.clear();
    }
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let result = (|| -> io::Result<()> {
        writeln!(
            out,
            "repetition,phase,pair,file,status,open_ns,read_ns,drop_ns,total_ns,read_result_bytes,observed_bytes,take_remaining,capacity_before,capacity_after,os_error"
        )?;
        for (index, row) in rows.iter().enumerate() {
            let pair = index as u32 / 2;
            let phase = u8::from(pair >= WARMUP_PAIRS);
            let phase_pair = if phase == 0 {
                pair
            } else {
                pair - WARMUP_PAIRS
            };
            writeln!(
                out,
                "{repetition},{phase},{phase_pair},{},{},{},{},{},{},{},{},{},{},{},{}",
                index % 2,
                row.status,
                number(row.open_ns),
                number(row.read_ns),
                number(row.drop_ns),
                number(row.total_ns),
                number(row.read_result),
                number(row.observed_bytes),
                number(row.remaining),
                number(row.capacity_before),
                number(row.capacity_after),
                number(row.os_error)
            )?;
        }
        out.flush()
    })();
    if result.is_err() {
        eprintln!("probe failed: raw CSV output incomplete");
        return ExitCode::FAILURE;
    }
    eprintln!(
        "probe repetition={repetition} completed={completed} planned={ROWS} qualification=false"
    );
    if completed == ROWS {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::path::PathBuf;

    // Future controls write only fresh private files beside the standalone
    // target/evaluation binary; this source file does not create that directory.
    struct TestFile(PathBuf);
    impl TestFile {
        fn new(name: &str, bytes: &[u8]) -> Self {
            let path = Path::new("target/evaluation/custody-file-read-probe-v1")
                .join(format!("control-{name}.bin"));
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            f.write_all(bytes).unwrap();
            drop(f);
            Self(path)
        }
    }
    impl Drop for TestFile {
        fn drop(&mut self) {
            fs::remove_file(&self.0).unwrap();
        }
    }
    fn check(name: &str, bytes: &[u8], status: u8) {
        let f = TestFile::new(name, bytes);
        let stamp = Stamp::read(&f.0).unwrap();
        let mut actual = vec![0xff; EXPECTED.len()];
        actual.clear();
        actual.reserve(EXPECTED.len().min(LIMIT as usize));
        let row = one(&f.0, stamp, &mut actual);
        let n = bytes.len().min(LIMIT as usize);
        assert_eq!(row.status, status);
        assert_eq!(row.read_result, Some(n));
        assert_eq!(row.observed_bytes, Some(n));
        assert_eq!(row.remaining, Some(LIMIT - n as u64));
        assert_eq!(actual, bytes[..n]);
        assert_eq!(
            row.open_ns.unwrap() + row.read_ns.unwrap() + row.drop_ns.unwrap(),
            row.total_ns.unwrap()
        );
    }
    #[test]
    fn exact_bytes() {
        check("exact", EXPECTED, 1);
    }
    #[test]
    fn empty_refuses() {
        check("empty", &[], 6);
    }
    #[test]
    fn truncated_refuses() {
        check("truncated", &EXPECTED[..EXPECTED.len() - 1], 6);
    }
    #[test]
    fn changed_refuses() {
        let mut bytes = EXPECTED.to_vec();
        bytes[701] ^= 1;
        check("changed", &bytes, 6);
    }
    #[test]
    fn appended_refuses() {
        let mut bytes = EXPECTED.to_vec();
        bytes.push(0);
        check("appended", &bytes, 6);
    }
    #[test]
    fn cap_plus_one_refuses() {
        let mut bytes = EXPECTED.to_vec();
        bytes.resize(LIMIT as usize, 0);
        check("cap-plus-one", &bytes, 6);
    }
    #[test]
    fn beyond_cap_refuses_without_reading_trailing_byte() {
        let mut bytes = EXPECTED.to_vec();
        bytes.resize(LIMIT as usize + 1, 0);
        check("beyond-cap", &bytes, 6);
    }
    #[test]
    fn changed_stamp_refuses_before_open() {
        let f = TestFile::new("stamp", EXPECTED);
        let mut stamp = Stamp::read(&f.0).unwrap();
        stamp.len += 1;
        let mut actual = vec![0x42];
        let row = one(&f.0, stamp, &mut actual);
        assert_eq!(row.status, 3);
        assert_eq!(row.open_ns, None);
        assert_eq!(row.read_ns, None);
        assert_eq!(row.drop_ns, None);
        assert_eq!(row.observed_bytes, None);
        assert_eq!(actual, [0x42]);
    }
    #[test]
    fn argument_contract_refusals() {
        let args: Vec<String> = [
            "probe",
            "1",
            "/example/candidate.so",
            "/example/trusted.so",
            "7,11,33152,13360,0,0,0,0",
            "7,12,33152,13360,0,0,0,0",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let accepted = arguments(&args).unwrap();
        assert_eq!(accepted.repetition, 1);
        assert_eq!(accepted.stamps[0].ino, 11);
        assert_eq!(accepted.stamps[1].ino, 12);
        assert!(arguments(&args[..5]).is_none());
        let mut extra = args.clone();
        extra.push("extra".into());
        assert!(arguments(&extra).is_none());
        for (index, value) in [
            (1, "0"),
            (1, "6"),
            (1, "not-a-number"),
            (2, "relative/candidate.so"),
            (3, "/example/candidate.so"),
            (4, "7,11,33152,13360,0,0,0"),
            (4, "7,11,33152,13360,0,0,0,0,0"),
            (4, "bad,11,33152,13360,0,0,0,0"),
            (4, "7,11,33152,13361,0,0,0,0"),
            (4, "7,11,16832,13360,0,0,0,0"),
            (4, "7,11,33152,13360,0,1000000000,0,0"),
            (5, "7,11,33152,13360,0,0,0,0"),
        ] {
            let mut changed = args.clone();
            changed[index] = value.into();
            assert!(arguments(&changed).is_none(), "index={index} value={value}");
        }
    }
}
