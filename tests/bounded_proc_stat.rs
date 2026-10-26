//! Deterministic read-outcome checks for the bounded process-stat helper.
#![deny(warnings)]
#![forbid(unsafe_code)]

#[path = "support/bounded_proc_stat.rs"]
mod bounded_proc_stat;

use bounded_proc_stat::read_bounded_stat;
use std::collections::VecDeque;
use std::io::{self, Read};

#[derive(Debug)]
enum Step {
    Bytes(Vec<u8>),
    OsError(i32),
    SyntheticError(io::ErrorKind),
    End,
}

struct ScriptedReader {
    steps: VecDeque<Step>,
    calls: usize,
    bytes_read: usize,
}

impl ScriptedReader {
    fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: steps.into(),
            calls: 0,
            bytes_read: 0,
        }
    }
}

impl Read for ScriptedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        assert!(!output.is_empty(), "unexpected zero-length underlying read");
        match self.steps.pop_front().expect("unexpected extra read") {
            Step::Bytes(bytes) => {
                let count = output.len().min(bytes.len());
                output[..count].copy_from_slice(&bytes[..count]);
                self.bytes_read += count;
                if count < bytes.len() {
                    self.steps.push_front(Step::Bytes(bytes[count..].to_vec()));
                }
                Ok(count)
            }
            Step::OsError(errno) => Err(io::Error::from_raw_os_error(errno)),
            Step::SyntheticError(kind) => Err(io::Error::new(kind, "fixed synthetic read error")),
            Step::End => Ok(0),
        }
    }
}

#[test]
fn zero_byte_enoent_and_esrch_are_disappearance() {
    for errno in [libc::ENOENT, libc::ESRCH] {
        let mut reader = ScriptedReader::new(vec![Step::OsError(errno)]);
        assert_eq!(read_bounded_stat(&mut reader).unwrap(), None);
        assert_eq!((reader.calls, reader.bytes_read), (1, 0));
        assert!(reader.steps.is_empty());
    }
}

#[test]
fn partial_enoent_and_esrch_remain_errors() {
    for errno in [libc::ENOENT, libc::ESRCH] {
        let mut reader =
            ScriptedReader::new(vec![Step::Bytes(vec![0, 0xff, b'(']), Step::OsError(errno)]);
        let error = read_bounded_stat(&mut reader).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(errno));
        assert_eq!(
            error.to_string(),
            io::Error::from_raw_os_error(errno).to_string()
        );
        assert_eq!((reader.calls, reader.bytes_read), (2, 3));
        assert!(reader.steps.is_empty());
    }
}

#[test]
fn all_other_errors_propagate_before_and_after_bytes() {
    for partial in [false, true] {
        for errno in [libc::EACCES, libc::EPERM, libc::EIO, libc::EINTR] {
            let mut steps = Vec::new();
            if partial {
                steps.push(Step::Bytes(vec![0x80, 0]));
            }
            steps.push(Step::OsError(errno));
            let mut reader = ScriptedReader::new(steps);
            let error = read_bounded_stat(&mut reader).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
            assert_eq!(
                error.to_string(),
                io::Error::from_raw_os_error(errno).to_string()
            );
            assert_eq!(reader.calls, if partial { 2 } else { 1 });
            assert_eq!(reader.bytes_read, if partial { 2 } else { 0 });
            assert!(reader.steps.is_empty());
        }
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::Other] {
            let mut steps = Vec::new();
            if partial {
                steps.push(Step::Bytes(vec![0x80, 0]));
            }
            steps.push(Step::SyntheticError(kind));
            let mut reader = ScriptedReader::new(steps);
            let error = read_bounded_stat(&mut reader).unwrap_err();
            assert_eq!(error.raw_os_error(), None);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), "fixed synthetic read error");
            assert_eq!(reader.calls, if partial { 2 } else { 1 });
            assert_eq!(reader.bytes_read, if partial { 2 } else { 0 });
            assert!(reader.steps.is_empty());
        }
    }
}

#[test]
fn empty_eof_is_present_empty_data() {
    let mut reader = ScriptedReader::new(vec![Step::End]);
    assert_eq!(read_bounded_stat(&mut reader).unwrap(), Some(Vec::new()));
    assert_eq!((reader.calls, reader.bytes_read), (1, 0));
    assert!(reader.steps.is_empty());
}

#[test]
fn short_reads_preserve_all_bytes_without_text_conversion() {
    let mut reader = ScriptedReader::new(vec![
        Step::Bytes(vec![0, 0xff, b'(']),
        Step::Bytes(vec![b')', b' ', 0x80, b'\n']),
        Step::End,
    ]);
    assert_eq!(
        read_bounded_stat(&mut reader).unwrap(),
        Some(vec![0, 0xff, b'(', b')', b' ', 0x80, b'\n'])
    );
    assert_eq!((reader.calls, reader.bytes_read), (3, 7));
    assert!(reader.steps.is_empty());
}

#[test]
fn exactly_4096_bytes_remain_exact() {
    let expected = vec![0xa5; 4096];
    let mut reader = io::Cursor::new(expected.clone());
    assert_eq!(read_bounded_stat(&mut reader).unwrap(), Some(expected));
    assert_eq!(reader.position(), 4096);
}

#[test]
fn oversize_sentinel_stops_at_4097_without_another_read() {
    let mut reader = ScriptedReader::new(vec![
        Step::Bytes(vec![0x5a; 4098]),
        Step::OsError(libc::EIO),
    ]);
    let bytes = read_bounded_stat(&mut reader).unwrap().unwrap();
    assert_eq!(bytes, vec![0x5a; 4097]);
    assert!(
        bytes.len() > 4096,
        "existing caller must reject the sentinel"
    );
    assert_eq!((reader.calls, reader.bytes_read), (1, 4097));
    assert_eq!(reader.steps.len(), 2);
    match reader.steps.pop_front().unwrap() {
        Step::Bytes(remaining) => assert_eq!(remaining, vec![0x5a]),
        step => panic!("unexpected unconsumed step: {step:?}"),
    }
    assert!(matches!(
        reader.steps.pop_front(),
        Some(Step::OsError(libc::EIO))
    ));
}
