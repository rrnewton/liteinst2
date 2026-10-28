//! Bounded external requests. IDs belong to the application, never to the SDK.
use std::collections::BTreeSet;

pub(super) const INPUT: usize = 4096;
pub(super) const COMMANDS: usize = 4096;
pub(super) const LINE: usize = INPUT * 2 + 64;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Command {
    Call {
        id: u64,
        bound: usize,
        bytes: Vec<u8>,
    },
    Flush {
        id: u64,
    },
    Stop,
}
impl Command {
    pub(super) fn id(&self) -> Option<u64> {
        match self {
            Self::Call { id, .. } | Self::Flush { id } => Some(*id),
            Self::Stop => None,
        }
    }
}

fn number(s: &str) -> Result<u64, &'static str> {
    if s.is_empty()
        || s.len() > 20
        || !s.bytes().all(|b| b.is_ascii_digit())
        || (s.len() != 1 && s.starts_with('0'))
    {
        return Err("noncanonical unsigned integer");
    }
    s.parse().map_err(|_| "integer overflow")
}
fn nibble(b: u8) -> Result<u8, &'static str> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err("lowercase hexadecimal input required"),
    }
}
pub(super) fn parse(line: &[u8]) -> Result<Command, &'static str> {
    if line.len() > LINE || !line.is_ascii() {
        return Err("request line bound/encoding");
    }
    let words: Vec<_> = std::str::from_utf8(line)
        .map_err(|_| "request encoding")?
        .split(' ')
        .collect();
    match words.as_slice() {
        ["STOP"] => Ok(Command::Stop),
        ["FLUSH", id] => Ok(Command::Flush { id: number(id)? }),
        ["CALL", id, bound, input] => {
            let id = number(id)?;
            let bound = usize::try_from(number(bound)?).map_err(|_| "bound overflow")?;
            let mut bytes = Vec::new();
            if *input != "-" {
                if input.is_empty() || input.len() % 2 != 0 || input.len() > INPUT * 2 {
                    return Err("input length bound");
                }
                for pair in input.as_bytes().chunks_exact(2) {
                    bytes.push(nibble(pair[0])? * 16 + nibble(pair[1])?);
                }
            }
            if bound > bytes.len() {
                return Err("bound exceeds owned input");
            }
            Ok(Command::Call { id, bound, bytes })
        }
        _ => Err("expected CALL id bound hex, FLUSH id, or STOP"),
    }
}

#[derive(Default)]
pub(super) struct Ids(BTreeSet<u64>);
impl Ids {
    pub(super) fn accept(&mut self, command: &Command) -> Result<(), &'static str> {
        if let Some(id) = command.id() {
            if self.0.len() == COMMANDS {
                return Err("session command capacity");
            }
            if !self.0.insert(id) {
                return Err("duplicate request ID");
            }
        }
        Ok(())
    }
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_requests_include_empty_nul_and_arbitrary_external_ids() {
        assert_eq!(
            parse(b"CALL 18446744073709551615 0 -").unwrap(),
            Command::Call {
                id: u64::MAX,
                bound: 0,
                bytes: vec![]
            }
        );
        assert_eq!(
            parse(b"CALL 7 3 610062ff").unwrap(),
            Command::Call {
                id: 7,
                bound: 3,
                bytes: vec![97, 0, 98, 255]
            }
        );
        assert_eq!(parse(b"FLUSH 0").unwrap(), Command::Flush { id: 0 });
        assert_eq!(parse(b"STOP").unwrap(), Command::Stop);
    }
    #[test]
    fn malformed_requests_never_enter_the_population() {
        for text in [
            "",
            " STOP",
            "STOP ",
            "CALL 01 0 -",
            "CALL +1 0 -",
            "CALL 1 1 -",
            "CALL 1 0 ",
            "CALL 1 1 f",
            "CALL 1 1 FF",
            "CALL 1 1 gg",
            "CALL 1 2 00",
            "CALL 18446744073709551616 0 -",
            "CALL 1  0 -",
            "FLUSH -1",
            "FLUSH 1\r",
        ] {
            assert!(parse(text.as_bytes()).is_err(), "{text}");
        }
        assert!(parse(&[b'x'; LINE + 1]).is_err());
        assert!(parse(b"CALL 1 0 \xff").is_err());
    }
    #[test]
    fn duplicate_ids_and_finite_capacity_are_shared_by_calls_and_barriers() {
        let mut ids = Ids::default();
        ids.accept(&parse(b"CALL 8 0 -").unwrap()).unwrap();
        assert!(ids.accept(&parse(b"FLUSH 8").unwrap()).is_err());
        for id in 9..(8 + COMMANDS as u64) {
            ids.accept(&Command::Flush { id }).unwrap();
        }
        assert_eq!(ids.len(), COMMANDS);
        assert!(ids.accept(&Command::Flush { id: 0 }).is_err());
        ids.accept(&Command::Stop).unwrap();
    }
}
