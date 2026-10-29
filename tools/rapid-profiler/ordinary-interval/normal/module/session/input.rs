//! Strict one-record CSV grammar. Exact bytes, not a digest, own acceptance.
use super::*;
use shared::io::{Frame, Io};
pub(in crate::normal) const RECORDS: usize = 2048;
pub(in crate::normal) const PAYLOAD: usize = 64;
const GUARD: u8 = 0xa7;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::normal) enum Refusal {
    Syntax,
    Overlong,
    Unterminated,
    RecordLimit,
}
impl Refusal {
    pub(in crate::normal) fn label(self) -> &'static str {
        match self {
            Self::Syntax => "syntax",
            Self::Overlong => "overlong",
            Self::Unterminated => "unterminated",
            Self::RecordLimit => "record_limit",
        }
    }
}
/// A typed input outcome selected only after complete drain and final Schedule acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::normal) enum InputCompletion {
    Refused(Refusal),
    Incomplete,
}
impl InputCompletion {
    pub(super) fn stderr(self) -> &'static str {
        match self {
            Self::Refused(Refusal::Syntax) => "normal-module-session INPUT_REFUSED: syntax\n",
            Self::Refused(Refusal::Overlong) => "normal-module-session INPUT_REFUSED: overlong\n",
            Self::Refused(Refusal::Unterminated) => {
                "normal-module-session INPUT_REFUSED: unterminated\n"
            }
            Self::Refused(Refusal::RecordLimit) => {
                "normal-module-session INPUT_REFUSED: record_limit\n"
            }
            Self::Incomplete => "normal-module-session INPUT_INCOMPLETE\n",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::normal) struct Record {
    pub id: u64,
    pub length: usize,
    pub fields: u64,
    storage: [u8; 96],
    // Independent accepted-byte snapshot; this array is never passed to either target.
    accepted: [u8; PAYLOAD],
    accepted_length: usize,
}
impl Record {
    pub(in crate::normal) fn new(id: u64, bytes: &[u8]) -> Result<Self, Refusal> {
        let fields = fields(bytes)?;
        assert!((1..=RECORDS as u64).contains(&id));
        let mut storage = [GUARD; 96];
        storage[16..16 + bytes.len()].copy_from_slice(bytes);
        let mut accepted = [0; PAYLOAD];
        accepted[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            id,
            length: bytes.len(),
            fields,
            storage,
            accepted,
            accepted_length: bytes.len(),
        })
    }
    pub(in crate::normal) fn bytes(&self) -> &[u8] {
        &self.storage[16..16 + self.length]
    }
    pub(in crate::normal) fn check(&self) {
        assert!((1..=RECORDS as u64).contains(&self.id) && self.length <= PAYLOAD);
        assert_eq!(self.length, self.accepted_length);
        assert_eq!(&self.storage[..16], &[GUARD; 16]);
        assert!(self.storage[16 + self.length..].iter().all(|&b| b == GUARD));
        assert_eq!(self.bytes(), &self.accepted[..self.accepted_length]);
        assert_eq!(fields(self.bytes()), Ok(self.fields));
    }
    pub(in crate::normal) fn checksum(&self) -> u64 {
        self.bytes().iter().fold(0xcbf29ce484222325, |h, &b| {
            (h ^ u64::from(b)).wrapping_mul(0x100000001b3)
        })
    }
}
// This recognizer does not call or translate the selected C scanner.
pub(super) fn fields(bytes: &[u8]) -> Result<u64, Refusal> {
    if bytes.len() > PAYLOAD {
        return Err(Refusal::Overlong);
    }
    if bytes.iter().any(|b| !(0x20..=0x7e).contains(b)) {
        return Err(Refusal::Syntax);
    }
    #[derive(Clone, Copy)]
    enum State {
        Start,
        Plain,
        Quoted,
        Quote,
    }
    let mut state = State::Start;
    let mut n = 1;
    for &b in bytes {
        state = match (state, b) {
            (State::Start, b'"') => State::Quoted,
            (State::Start | State::Plain, b',') => {
                n += 1;
                State::Start
            }
            (State::Plain, b'"') => return Err(Refusal::Syntax),
            (State::Start | State::Plain, _) => State::Plain,
            (State::Quoted, b'"') => State::Quote,
            (State::Quoted, _) => State::Quoted,
            (State::Quote, b'"') => State::Quoted,
            (State::Quote, b',') => {
                n += 1;
                State::Start
            }
            (State::Quote, _) => return Err(Refusal::Syntax),
        };
    }
    if matches!(state, State::Quoted) {
        return Err(Refusal::Syntax);
    }
    Ok(n)
}
#[derive(Clone, Debug)]
pub(in crate::normal) enum Command {
    Record(Arc<Record>),
    Stop,
}
impl shared::worker::Work for Command {
    fn kind(&self) -> u8 {
        match self {
            Self::Record(_) => 1,
            Self::Stop => 3,
        }
    }
    fn flush_id(&self) -> Option<u64> {
        None
    }
    fn stop() -> Self {
        Self::Stop
    }
}
#[derive(Default)]
pub(in crate::normal) struct Input {
    pub eof: bool,
    pub error: Option<Refusal>,
}
impl Input {
    pub(super) fn poll(&mut self, io: &mut Io, accepted: usize) -> Result<Option<Command>, String> {
        self.poll_with_limit(io, accepted, RECORDS)
    }
    pub(in crate::normal) fn poll_with_limit(
        &mut self,
        io: &mut Io,
        accepted: usize,
        limit: usize,
    ) -> Result<Option<Command>, String> {
        assert!((1..=RECORDS).contains(&limit));
        assert!(accepted <= limit && self.error.is_none() && !self.eof);
        self.frame_with_limit(io.csv_frame(accepted == limit)?, accepted, limit)
    }
    fn frame_with_limit(
        &mut self,
        frame: Frame,
        accepted: usize,
        limit: usize,
    ) -> Result<Option<Command>, String> {
        assert!((1..=RECORDS).contains(&limit) && accepted <= limit);
        assert!(!matches!(&frame, Frame::Line { .. }) || accepted < limit);
        self.frame(frame, accepted)
    }
    fn frame(&mut self, frame: Frame, accepted: usize) -> Result<Option<Command>, String> {
        let result = match frame {
            Frame::Pending => return Ok(None),
            Frame::Eof => {
                self.eof = true;
                return Ok(Some(Command::Stop));
            }
            Frame::Line { bytes, length } => Record::new(accepted as u64 + 1, &bytes[..length]),
            Frame::Overlong => Err(Refusal::Overlong),
            Frame::Unterminated => {
                self.eof = true;
                Err(Refusal::Unterminated)
            }
            Frame::ExtraByte => Err(Refusal::RecordLimit),
        };
        Ok(Some(match result {
            Ok(record) => Command::Record(Arc::new(record)),
            Err(error) => {
                assert!(self.error.replace(error).is_none());
                Command::Stop
            }
        }))
    }
    pub(in crate::normal) fn status(&self) -> &'static str {
        if self.error.is_some() {
            "INPUT_REFUSED"
        } else if self.eof {
            "COMPLETE"
        } else {
            "INPUT_INCOMPLETE"
        }
    }
    pub(in crate::normal) fn completion(&self) -> Result<(), InputCompletion> {
        match self.error {
            Some(error) => Err(InputCompletion::Refused(error)),
            None if self.eof => Ok(()),
            None => Err(InputCompletion::Incomplete),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grammar_preserves_literals_empty_fields_quotes_and_limits() {
        for (bytes, expected) in csv::CASES {
            assert_eq!(fields(bytes), Ok(expected));
        }
        assert_eq!(fields(&[b','; 64]), Ok(65));
        assert_eq!(fields(&[b'a'; 64]), Ok(1));
        assert_eq!(fields(&[b'a'; 65]), Err(Refusal::Overlong));
        for bytes in [
            b"a\"b".as_slice(),
            b"\"a\"x",
            b"\"a",
            b"a\0",
            b"a\r",
            b"a\n",
            b"a\x7f",
            b"a\x80",
        ] {
            assert_eq!(fields(bytes), Err(Refusal::Syntax));
        }
    }
    #[test]
    fn actual_frame_acceptance_distinguishes_eof_refusal_and_incomplete() {
        let mut input = Input::default();
        assert_eq!(input.status(), "INPUT_INCOMPLETE");
        assert!(input.completion().is_err());
        assert!(input.frame(Frame::Pending, 0).unwrap().is_none());
        let Some(Command::Record(r)) = input
            .frame(
                Frame::Line {
                    bytes: [0; 64],
                    length: 0,
                },
                0,
            )
            .unwrap()
        else {
            panic!()
        };
        assert_eq!((r.id, r.length, r.fields), (1, 0, 1));
        r.check();
        assert!(matches!(
            input.frame(Frame::Eof, 1).unwrap(),
            Some(Command::Stop)
        ));
        assert_eq!(input.status(), "COMPLETE");
        assert!(input.completion().is_ok());
        for (frame, why) in [
            (Frame::Overlong, Refusal::Overlong),
            (Frame::Unterminated, Refusal::Unterminated),
            (Frame::ExtraByte, Refusal::RecordLimit),
        ] {
            let mut input = Input::default();
            assert!(matches!(
                input.frame(frame, 3).unwrap(),
                Some(Command::Stop)
            ));
            assert_eq!(input.error, Some(why));
            assert_eq!(input.eof, why == Refusal::Unterminated);
            assert_eq!(input.status(), "INPUT_REFUSED");
            assert!(input.completion().is_err());
        }
    }
    #[test]
    fn owned_record_checks_entire_guard_and_exact_input() {
        let record = Record::new(2048, b"a,\"b,c\"").unwrap();
        record.check();
        assert_eq!(
            (record.bytes(), record.fields),
            (b"a,\"b,c\"".as_slice(), 2)
        );
        for at in [0, 15, 16 + record.length, 95] {
            let mut changed = record.clone();
            changed.storage[at] ^= 1;
            assert!(std::panic::catch_unwind(|| changed.check()).is_err());
        }
        let mut changed = record;
        changed.fields = 3;
        assert!(std::panic::catch_unwind(|| changed.check()).is_err());
    }
    #[test]
    fn accepted_snapshot_refuses_same_shape_in_range_payload_change() {
        let record = Record::new(1, b"a,b").unwrap();
        record.check();
        let mut changed = record.clone();
        changed.storage[16] = b'z';
        assert_eq!(changed.bytes(), b"z,b");
        assert_eq!(
            (changed.length, changed.fields),
            (record.length, record.fields)
        );
        assert_eq!(fields(changed.bytes()), Ok(record.fields));
        assert_eq!(changed.accepted, record.accepted);
        assert_eq!(&changed.storage[..16], &record.storage[..16]);
        assert_eq!(&changed.storage[19..], &record.storage[19..]);
        assert!(std::panic::catch_unwind(|| changed.check()).is_err());
        let mut changed = record;
        changed.length = 2;
        assert!(std::panic::catch_unwind(|| changed.check()).is_err());
    }
    #[test]
    fn typed_completion_keeps_all_refusals_incomplete_and_exact_stderr() {
        let incomplete = Input::default();
        assert_eq!(incomplete.completion(), Err(InputCompletion::Incomplete));
        assert_eq!(
            incomplete.completion().unwrap_err().stderr(),
            "normal-module-session INPUT_INCOMPLETE\n"
        );
        assert_eq!(
            Input {
                eof: true,
                error: None
            }
            .completion(),
            Ok(())
        );
        for (error, label) in [
            (Refusal::Syntax, "syntax"),
            (Refusal::Overlong, "overlong"),
            (Refusal::Unterminated, "unterminated"),
            (Refusal::RecordLimit, "record_limit"),
        ] {
            for eof in [false, true] {
                let input = Input {
                    eof,
                    error: Some(error),
                };
                assert_eq!(input.status(), "INPUT_REFUSED");
                assert_eq!(input.completion(), Err(InputCompletion::Refused(error)));
                assert_eq!(
                    input.completion().unwrap_err().stderr(),
                    format!("normal-module-session INPUT_REFUSED: {label}\n")
                );
            }
        }
    }
}

#[cfg(test)]
mod leaf_set_tests {
    use super::*;
    #[test]
    fn bounded_frame_limit_preserves_extra_byte_eof_and_accepted_snapshot() {
        for limit in [1024, 1365, 2048] {
            let mut input = Input::default();
            let mut bytes = [0; 64];
            bytes[..3].copy_from_slice(b"a,b");
            let Some(Command::Record(record)) = input
                .frame_with_limit(Frame::Line { bytes, length: 3 }, limit - 1, limit)
                .unwrap()
            else {
                panic!()
            };
            assert_eq!(record.id, limit as u64);
            record.check();
            assert!(matches!(
                input
                    .frame_with_limit(Frame::ExtraByte, limit, limit)
                    .unwrap(),
                Some(Command::Stop)
            ));
            assert_eq!(input.error, Some(Refusal::RecordLimit));
            assert!(!input.eof);
            assert_eq!(record.bytes(), b"a,b");
            let mut changed = record.as_ref().clone();
            changed.storage[16] = b'z';
            assert_eq!(fields(changed.bytes()), Ok(record.fields));
            assert!(std::panic::catch_unwind(|| changed.check()).is_err());
            let mut eof = Input::default();
            assert!(matches!(
                eof.frame_with_limit(Frame::Eof, limit, limit).unwrap(),
                Some(Command::Stop)
            ));
            assert!(eof.eof && eof.error.is_none());
            let mut partial = Input::default();
            assert!(matches!(
                partial
                    .frame_with_limit(Frame::Unterminated, 0, limit)
                    .unwrap(),
                Some(Command::Stop)
            ));
            assert!(partial.eof);
            assert_eq!(partial.error, Some(Refusal::Unterminated));
        }
        for limit in [0, 2049] {
            assert!(
                std::panic::catch_unwind(|| {
                    Input::default()
                        .frame_with_limit(Frame::Pending, 0, limit)
                        .unwrap();
                })
                .is_err()
            );
        }
        assert!(
            std::panic::catch_unwind(|| {
                Input::default()
                    .frame_with_limit(
                        Frame::Line {
                            bytes: [0; 64],
                            length: 0,
                        },
                        1024,
                        1024,
                    )
                    .unwrap();
            })
            .is_err()
        );
    }
}
