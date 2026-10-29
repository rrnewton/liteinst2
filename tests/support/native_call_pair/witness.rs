//! Bounded value copies, never an SDK owner, Report, timestamp truth or reap.
pub const WORDS: usize = 384;
pub const BYTES: usize = WORDS * 8;
pub const MAGIC: u64 = 0x6370_6174_6672_6d31;
pub type Row = [u64; 48];
pub type Report = [u64; 46];
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Witness {
    pub header: [u64; 16],
    pub batch: [u64; 20],
    pub stream: [u64; 16],
    pub rows: [Row; 2],
    pub report_count: u64,
    pub reports: [Report; 2],
    pub history: [u64; 50],
}
fn zero(b: &[u64]) {
    assert!(b.iter().all(|&v| v == 0), "inactive witness data");
}
fn optional(b: &[u64]) -> bool {
    assert!(b[0] <= 1, "canonical presence");
    if b[0] == 0 {
        zero(&b[1..]);
        false
    } else {
        true
    }
}
fn admission(b: &[u64]) {
    assert_eq!(b.len(), 4);
    assert!(b[0] != 0 && b[2] != 0);
    usize::try_from(b[1]).unwrap();
}
fn disposition(b: &[u64]) {
    assert!(matches!(b[0], 1 | 2));
    if b[0] == 2 {
        assert_eq!(b[1], 0);
    }
    usize::try_from(b[1]).unwrap();
}
fn completion(b: &[u64]) {
    assert_eq!(b.len(), 12);
    if optional(b) {
        admission(&b[1..5]);
        disposition(&b[5..7]);
        if optional(&b[7..10]) {
            assert!(b[8] != 0 && b[9] != 0);
        }
        if optional(&b[10..12]) {
            usize::try_from(b[11]).unwrap();
        }
    }
}
fn payload(b: &[u64]) {
    assert_eq!(b.len(), 12);
    if optional(b) {
        admission(&b[1..5]);
        assert!(b[5] != 0);
        match b[7] {
            1 => {
                assert!(matches!(b[8], 1 | 2));
                assert_eq!(b[11], 0);
            }
            2 => {
                zero(&b[8..11]);
                assert!(matches!(b[11], 1 | 2));
            }
            _ => panic!("payload tag"),
        }
    }
}
fn observation(b: &[u64]) {
    assert_eq!(b.len(), 22);
    admission(&b[..4]);
    if optional(&b[4..10]) {
        match b[5] {
            1 => {
                disposition(&b[7..9]);
                assert_eq!(b[9], 0);
            }
            2 => {
                zero(&b[6..9]);
                assert!(matches!(b[9], 1 | 2));
            }
            _ => panic!("terminal tag"),
        }
    }
    payload(&b[10..]);
}
fn binding(b: &[u64]) {
    match b[0] {
        0 => zero(&b[1..]),
        1 | 2 => assert!(b[2] != 0),
        _ => panic!("history binding tag"),
    }
}
impl Witness {
    fn canonical(&self) {
        assert_eq!(&self.header[..3], &[MAGIC, 1, WORDS as u64]);
        assert!(self.header[3] < 192);
        assert!(matches!(self.header[5], 10 | 1000));
        assert!(self.header[6] < 16 && (1..=3).contains(&self.header[7]));
        assert!(u32::try_from(self.header[8]).unwrap() != 0);
        assert_eq!(self.header[15], 0);
        for row in &self.rows {
            match row[6] {
                1 => {
                    assert!(row[7] != 0);
                    usize::try_from(row[8]).unwrap();
                }
                2 => zero(&row[7..9]),
                3 | 4 => {
                    assert!(row[7] != 0);
                    assert_eq!(row[8], 0);
                }
                _ => panic!("owner tag"),
            }
            u32::try_from(row[10]).unwrap();
            u32::try_from(row[12]).unwrap();
            assert!(matches!(row[18], 1 | 2));
            optional(&row[22..24]);
            completion(&row[24..36]);
            payload(&row[36..48]);
        }
        assert!((1..=2).contains(&self.report_count));
        let mut total = 0;
        for (i, report) in self.reports.iter().enumerate() {
            if i >= self.report_count as usize {
                zero(report);
                continue;
            }
            assert!(report[0] != 0 && (1..=2).contains(&report[1]));
            total += report[1];
            for (n, record) in report[2..].chunks_exact(22).enumerate() {
                if n < report[1] as usize {
                    observation(record);
                } else {
                    zero(record);
                }
            }
        }
        assert!((1..=2).contains(&total));
        binding(&self.history[19..22]);
        binding(&self.history[22..25]);
        assert!((2..=3).contains(&self.history[25]));
        assert_eq!(
            self.history[18].checked_sub(self.history[17]).unwrap(),
            self.history[25]
        );
        for (i, action) in self.history[26..].chunks_exact(8).enumerate() {
            if i < self.history[25] as usize {
                assert!((1..=7).contains(&action[0]) && action[1] != 0);
                optional(&action[2..4]);
                optional(&action[4..6]);
                optional(&action[6..8]);
            } else {
                zero(action);
            }
        }
    }
}
pub fn encode(value: &Witness) -> [u8; BYTES] {
    value.canonical();
    let count = [value.report_count];
    let mut out = [0; BYTES];
    let mut n = 0;
    for part in [
        &value.header[..],
        &value.batch,
        &value.stream,
        &value.rows[0],
        &value.rows[1],
        &count,
        &value.reports[0],
        &value.reports[1],
        &value.history,
    ] {
        for word in part {
            out[n * 8..n * 8 + 8].copy_from_slice(&word.to_le_bytes());
            n += 1;
        }
    }
    assert_eq!(n, 291);
    out
}
pub fn decode(bytes: &[u8]) -> Witness {
    assert_eq!(bytes.len(), BYTES, "complete single postflight packet");
    let mut words = bytes
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    fn take<const N: usize>(words: &mut impl Iterator<Item = u64>) -> [u64; N] {
        std::array::from_fn(|_| words.next().unwrap())
    }
    let value = Witness {
        header: take(&mut words),
        batch: take(&mut words),
        stream: take(&mut words),
        rows: [take(&mut words), take(&mut words)],
        report_count: words.next().unwrap(),
        reports: [take(&mut words), take(&mut words)],
        history: take(&mut words),
    };
    assert!(words.all(|v| v == 0), "reserved witness tail");
    value.canonical();
    value
}
