//! Single controller-thread nonblocking transport. No blocked reader to abandon.
use super::protocol::{self, Command};

pub(in crate::normal) enum Frame {
    Pending,
    Eof,
    Line { bytes: [u8; 64], length: usize },
    Overlong,
    Unterminated,
    ExtraByte,
}
const OUTPUT: usize = 4 * 1024 * 1024;
// Accuracy alone adds two lossless PMU rows/call, 520 arm rows and 10
// acquisition/close rows. Worst complete roster: 20,018 rows *350 =7,006,300.
const ACCURACY_OUTPUT: usize = 8 * 1024 * 1024;
pub(in crate::normal) struct Io {
    fds: [i32; 2],
    flags: [i32; 2],
    input: Vec<u8>,
    eof: bool,
    output: Vec<u8>,
    output_limit: usize,
    written: usize,
    write_blocked: u64,
}
impl Io {
    pub(in crate::normal) fn new() -> Result<Self, String> {
        Self::open([0, 1])
    }
    pub(in crate::normal) fn new_accuracy() -> Result<Self, String> {
        Self::open_with_limit([0, 1], ACCURACY_OUTPUT)
    }
    // Descriptor owners outlive this flag-restoring transport. Tests use
    // independent sockets without replacing the harness's standard descriptors.
    fn open(fds: [i32; 2]) -> Result<Self, String> {
        Self::open_with_limit(fds, OUTPUT)
    }
    fn open_with_limit(fds: [i32; 2], output_limit: usize) -> Result<Self, String> {
        assert!(matches!(output_limit, OUTPUT | ACCURACY_OUTPUT));
        let mut flags = [0; 2];
        for (i, &fd) in fds.iter().enumerate() {
            // SAFETY: standalone process standard descriptors; no concurrent I/O.
            let original = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if original < 0 {
                return Err("stdio flags unavailable".into());
            }
            flags[i] = original;
        }
        let result = Self {
            fds,
            flags,
            input: Vec::with_capacity(protocol::LINE + 1),
            eof: false,
            output: Vec::with_capacity(output_limit),
            output_limit,
            written: 0,
            write_blocked: 0,
        };
        for (i, &fd) in fds.iter().enumerate() {
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags[i] | libc::O_NONBLOCK) } < 0 {
                return Err("nonblocking stdio unavailable".into());
            }
        }
        Ok(result)
    }
    /// At most one bounded read and one command per controller iteration.
    pub(super) fn command(&mut self) -> Result<Option<Command>, String> {
        if !self.eof && !self.input.contains(&b'\n') {
            let mut bytes = [0_u8; 4096];
            let room = (protocol::LINE + 1 - self.input.len()).min(bytes.len());
            if room == 0 {
                return Err("request line capacity".into());
            }
            // SAFETY: valid live writable buffer, nonblocking descriptor.
            let n = unsafe { libc::read(self.fds[0], bytes.as_mut_ptr().cast(), room) };
            if n > 0 {
                self.input.extend_from_slice(&bytes[..n as usize]);
            } else if n == 0 {
                self.eof = true;
            } else {
                transient()?;
            }
        }
        if let Some(end) = self.input.iter().position(|&b| b == b'\n') {
            let command = protocol::parse(&self.input[..end]).map_err(str::to_string)?;
            self.input.drain(..=end);
            return Ok(Some(command));
        }
        if self.input.len() > protocol::LINE || (self.eof && !self.input.is_empty()) {
            return Err("overlong or unterminated request".into());
        }
        Ok(None)
    }
    /// Separate bounded CSV framing. Existing command() remains unchanged.
    /// At the record cap even one extra byte refuses; EOF requires read(0).
    pub(in crate::normal) fn csv_frame(&mut self, exhausted: bool) -> Result<Frame, String> {
        if !self.eof
            && !self.input.contains(&b'\n')
            && self.input.len() <= 64
            && !(exhausted && !self.input.is_empty())
        {
            let mut bytes = [0_u8; 65];
            let room = if exhausted { 1 } else { 65 - self.input.len() };
            let n = unsafe { libc::read(self.fds[0], bytes.as_mut_ptr().cast(), room) };
            if n > 0 {
                self.input.extend_from_slice(&bytes[..n as usize]);
            } else if n == 0 {
                self.eof = true;
            } else {
                transient()?;
            }
        }
        if exhausted && !self.input.is_empty() {
            return Ok(Frame::ExtraByte);
        }
        if let Some(end) = self.input.iter().position(|&b| b == b'\n') {
            if end > 64 {
                return Ok(Frame::Overlong);
            }
            let mut bytes = [0; 64];
            bytes[..end].copy_from_slice(&self.input[..end]);
            self.input.drain(..=end);
            return Ok(Frame::Line { bytes, length: end });
        }
        if self.input.len() > 64 {
            return Ok(Frame::Overlong);
        }
        if self.eof {
            return Ok(if self.input.is_empty() {
                Frame::Eof
            } else {
                Frame::Unterminated
            });
        }
        Ok(Frame::Pending)
    }
    pub(in crate::normal) fn eof(&self) -> bool {
        self.eof && self.input.is_empty()
    }
    pub(in crate::normal) fn emit(&mut self, line: String) -> Result<(), String> {
        self.emit_bytes(line.as_bytes())
    }
    /// Format only the existing HISTORY row into bounded temporary stack storage.
    /// Transfer retention precedes this call; append still precedes arm completion.
    pub(in crate::normal) fn emit_history(
        &mut self,
        number: u64,
        action_index: u64,
        kind: &str,
        generation: u64,
    ) -> Result<(), String> {
        use std::io::Write as _;
        let mut bytes = [0_u8; 350];
        let mut line = std::io::Cursor::new(&mut bytes[..]);
        writeln!(line, "HISTORY,{number},{action_index},{kind},{generation}")
            .map_err(|_| "session row shape")?;
        let length = line.position() as usize; // Cursor is bounded by the 350-byte slice.
        self.emit_bytes(&bytes[..length])
    }
    fn emit_bytes(&mut self, line: &[u8]) -> Result<(), String> {
        // Every fixed-format row is <=350 bytes even at maximum u64 values.
        // At most4096 RESULT-or-FLUSHED,4096 SAMPLE,4097 HISTORY,4096 REPORT,
        // plus READY/IO/DONE. The tighter per-kind layouts keep the sum below4MiB;
        // the total guard remains authoritative and never discards a row.
        if line.len() > 350
            || line.iter().filter(|&&b| b == b'\n').count() != 1
            || !line.ends_with(b"\n")
        {
            return Err("session row shape".into());
        }
        if self
            .output
            .len()
            .checked_add(line.len())
            .is_none_or(|n| n > self.output_limit)
        {
            return Err("session output capacity".into());
        }
        self.output.extend_from_slice(line);
        Ok(())
    }
    /// At most one 8 KiB write. All unsent bytes remain owned on backpressure.
    pub(in crate::normal) fn write(&mut self) -> Result<(), String> {
        let count = (self.output.len() - self.written).min(8192);
        if count == 0 {
            return Ok(());
        }
        let bytes = &self.output[self.written..self.written + count];
        // SAFETY: valid immutable slice, nonblocking descriptor, sole writer.
        let n = unsafe { libc::write(self.fds[1], bytes.as_ptr().cast(), bytes.len()) };
        if n > 0 {
            self.written += n as usize;
        } else if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                self.write_blocked = self
                    .write_blocked
                    .checked_add(1)
                    .ok_or("stdout pressure counter overflow")?;
            } else if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(format!("session I/O: {e}"));
            }
        } else {
            return Err("stdout made no progress".into());
        }
        Ok(())
    }
    pub(in crate::normal) fn output_len(&self) -> usize {
        self.output.len()
    }
    pub(in crate::normal) fn drained(&self) -> bool {
        self.written == self.output.len()
    }
    pub(in crate::normal) fn write_blocked(&self) -> u64 {
        self.write_blocked
    }
}
fn transient() -> Result<(), String> {
    let e = std::io::Error::last_os_error();
    if matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    ) {
        Ok(())
    } else {
        Err(format!("session I/O: {e}"))
    }
}
impl Drop for Io {
    fn drop(&mut self) {
        for (i, &fd) in self.fds.iter().enumerate() {
            // SAFETY: restore only descriptors this standalone session owns.
            unsafe {
                libc::fcntl(fd, libc::F_SETFL, self.flags[i]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::{fd::AsRawFd, unix::net::UnixStream};
    #[test]
    fn partial_input_eof_and_multiple_lines_preserve_exact_frames() {
        let (local, mut peer) = UnixStream::pair().unwrap();
        let mut io = Io::open([local.as_raw_fd(); 2]).unwrap();
        assert!(io.command().unwrap().is_none());
        peer.write_all(b"CALL 42 3 61").unwrap();
        assert!(io.command().unwrap().is_none());
        peer.write_all(b"0062\nFLUSH 9\n").unwrap();
        assert_eq!(
            io.command().unwrap(),
            Some(Command::Call {
                id: 42,
                bound: 3,
                bytes: b"a\0b".to_vec()
            })
        );
        assert_eq!(io.command().unwrap(), Some(Command::Flush { id: 9 }));
        assert!(io.command().unwrap().is_none());
        peer.write_all(b"CALL 5 0 -").unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        assert!(io.command().unwrap().is_none());
        assert!(io.command().is_err());
        assert_eq!(io.input, b"CALL 5 0 -");
    }
    #[test]
    fn full_output_retains_exact_unsent_bytes_then_drains_without_duplication() {
        let (local, mut peer) = UnixStream::pair().unwrap();
        let mut io = Io::open([local.as_raw_fd(); 2]).unwrap();
        let line = "x".repeat(349) + "\n";
        for _ in 0..4096 {
            io.emit(line.clone()).unwrap();
        }
        for _ in 0..400 {
            io.write().unwrap();
        }
        assert!(io.written > 0 && !io.drained());
        let stopped = io.written;
        io.write().unwrap();
        assert_eq!(io.written, stopped, "actual nonblocking output pressure");
        assert!(io.write_blocked() > 0);
        peer.set_nonblocking(true).unwrap();
        let mut received = Vec::new();
        for _ in 0..4096 {
            let mut bytes = [0; 8192];
            match peer.read(&mut bytes) {
                Ok(n) => received.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => panic!("{e}"),
            }
            io.write().unwrap();
            if received.len() == io.output.len() {
                break;
            }
        }
        assert!(io.drained());
        assert_eq!(received, io.output);
        let before = io.output.len();
        assert!(io.emit("x".repeat(350) + "\n").is_err());
        assert_eq!(io.output.len(), before);
        while io.output.len() + line.len() <= OUTPUT {
            io.emit(line.clone()).unwrap();
        }
        let remaining = OUTPUT - io.output.len();
        if remaining != 0 {
            io.emit("x".repeat(remaining - 1) + "\n").unwrap();
        }
        assert_eq!(io.output.len(), OUTPUT);
        assert!(io.emit("x\n".into()).is_err());
        assert_eq!(io.output.len(), OUTPUT);
    }
}

#[cfg(test)]
mod csv_tests {
    use super::*;
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::{fd::AsRawFd, unix::net::UnixStream};
    #[test]
    fn csv_frames_keep_partial_bytes_empty_record_and_observed_eof_distinct() {
        let (local, mut peer) = UnixStream::pair().unwrap();
        let mut io = Io::open([local.as_raw_fd(); 2]).unwrap();
        assert!(matches!(io.csv_frame(false).unwrap(), Frame::Pending));
        peer.write_all(b"a,").unwrap();
        assert!(matches!(io.csv_frame(false).unwrap(), Frame::Pending));
        peer.write_all(b"b\n\n").unwrap();
        let Frame::Line { bytes, length } = io.csv_frame(false).unwrap() else {
            panic!()
        };
        assert_eq!(&bytes[..length], b"a,b");
        assert!(matches!(
            io.csv_frame(false).unwrap(),
            Frame::Line { length: 0, .. }
        ));
        assert!(matches!(io.csv_frame(false).unwrap(), Frame::Pending));
        peer.shutdown(Shutdown::Write).unwrap();
        assert!(matches!(io.csv_frame(false).unwrap(), Frame::Eof));
    }
    #[test]
    fn csv_transport_refuses_extra_cap_byte_overlong_and_unterminated_without_discard() {
        for (data, exhausted, why) in [
            (&b"x"[..], true, 0),
            (&[b'x'; 65][..], false, 1),
            (&b"x"[..], false, 2),
        ] {
            let (local, mut peer) = UnixStream::pair().unwrap();
            let mut io = Io::open([local.as_raw_fd(); 2]).unwrap();
            peer.write_all(data).unwrap();
            if why == 2 {
                peer.shutdown(Shutdown::Write).unwrap();
                assert!(matches!(io.csv_frame(false).unwrap(), Frame::Pending));
            }
            let frame = io.csv_frame(exhausted).unwrap();
            assert!(matches!(
                (why, frame),
                (0, Frame::ExtraByte) | (1, Frame::Overlong) | (2, Frame::Unterminated)
            ));
            assert_eq!(io.input, data);
        }
        let (local, mut peer) = UnixStream::pair().unwrap();
        let mut io = Io::open([local.as_raw_fd(); 2]).unwrap();
        peer.write_all(&[b','; 64]).unwrap();
        peer.write_all(b"\n").unwrap();
        assert!(matches!(
            io.csv_frame(false).unwrap(),
            Frame::Line { length: 64, .. }
        ));
    }
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use std::os::{fd::AsRawFd, unix::net::UnixStream};

    #[test]
    fn history_stack_preserves_exact_legacy_bytes_at_numeric_extremes() {
        let (local, _peer) = UnixStream::pair().unwrap();
        let mut io = Io::open([local.as_raw_fd(); 2]).unwrap();
        for (number, index, generation) in [
            (0, 0, 0),
            (1, 10, 100),
            (u64::MAX, 0, 1),
            (0, u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX, u64::MAX),
        ] {
            for kind in ["published", "removed"] {
                io.output.clear();
                io.emit(format!("HISTORY,{number},{index},{kind},{generation}\n"))
                    .unwrap();
                let expected = io.output.clone();
                io.output.clear();
                io.emit_history(number, index, kind, generation).unwrap();
                assert_eq!(io.output, expected);
            }
        }
        io.output.clear();
        io.emit_history(0, 0, "published", 0).unwrap();
        assert_eq!(io.output, b"HISTORY,0,0,published,0\n");
        io.output.clear();
        io.emit_history(u64::MAX, u64::MAX, "published", u64::MAX)
            .unwrap();
        assert_eq!(
            io.output,
            b"HISTORY,18446744073709551615,18446744073709551615,published,18446744073709551615\n"
        );
        assert_eq!(io.output.len(), 81);
    }

    #[test]
    fn history_stack_and_borrowed_rows_refuse_without_output_mutation() {
        let (local, _peer) = UnixStream::pair().unwrap();
        let mut io = Io::open([local.as_raw_fd(); 2]).unwrap();
        io.emit("prefix\n".into()).unwrap();
        io.written = 2;
        io.write_blocked = 7;
        let before = io.output.clone();
        for line in [
            String::new(),
            "missing LF".into(),
            "first\nsecond\n".into(),
            "LF\nthen tail".into(),
            "x".repeat(350) + "\n",
        ] {
            assert_eq!(io.emit(line.clone()), Err("session row shape".into()));
            assert_eq!(io.output, before);
            assert_eq!(
                io.emit_bytes(line.as_bytes()),
                Err("session row shape".into())
            );
            assert_eq!(io.output, before);
            assert_eq!((io.written, io.write_blocked), (2, 7));
        }
        for kind in ["published\n".to_string(), "x".repeat(336)] {
            assert_eq!(
                io.emit_history(1, 1, &kind, 1),
                Err("session row shape".into())
            );
            assert_eq!(io.output, before);
            assert_eq!((io.written, io.write_blocked), (2, 7));
        }
        // A complete 350-byte row still fits; the formatter may not lower the bound.
        let kind = "x".repeat(335);
        let expected = format!("HISTORY,1,1,{kind},1\n");
        assert_eq!(expected.len(), 350);
        io.emit_history(1, 1, &kind, 1).unwrap();
        assert_eq!(&io.output[..before.len()], before);
        assert_eq!(&io.output[before.len()..], expected.as_bytes());
        assert_eq!((io.written, io.write_blocked), (2, 7));
    }

    #[test]
    fn history_stack_keeps_exact_output_cap_and_refusal_state() {
        let (local, _peer) = UnixStream::pair().unwrap();
        let mut io = Io::open([local.as_raw_fd(); 2]).unwrap();
        let expected = b"HISTORY,1,2,removed,3\n";
        io.output.resize(OUTPUT - expected.len() + 1, b'x');
        io.written = 13;
        io.write_blocked = 9;
        let before = io.output.clone();
        assert_eq!(
            io.emit_history(1, 2, "removed", 3),
            Err("session output capacity".into())
        );
        assert_eq!(io.output, before);
        assert_eq!((io.written, io.write_blocked), (13, 9));
        io.output.truncate(OUTPUT - expected.len());
        io.emit_history(1, 2, "removed", 3).unwrap();
        assert_eq!(io.output.len(), OUTPUT);
        assert_eq!(&io.output[OUTPUT - expected.len()..], expected);
        assert!(
            io.output[..OUTPUT - expected.len()]
                .iter()
                .all(|&b| b == b'x')
        );
        let full = io.output.clone();
        for borrowed in [false, true] {
            let result = if borrowed {
                io.emit_bytes(b"x\n")
            } else {
                io.emit("x\n".into())
            };
            assert_eq!(result, Err("session output capacity".into()));
            assert_eq!(io.output, full);
        }
        assert_eq!(
            io.emit_history(0, 0, "published", 0),
            Err("session output capacity".into())
        );
        // Shape refusal remains earlier than capacity refusal, even at a full output.
        assert_eq!(
            io.emit("missing LF".into()),
            Err("session row shape".into())
        );
        assert_eq!(io.output, full);
        assert_eq!((io.written, io.write_blocked), (13, 9));
    }
}

#[cfg(test)]
mod accuracy_tests;

#[cfg(test)]
mod prepared_input_tests {
    use super::*;
    use crate::normal::module::session::input::{Command, Input};
    use crate::normal::session::{ArmObservation, phase};
    use rapid_profiler::frontend_native::backoff::Policy;
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::{fd::AsRawFd, unix::net::UnixStream};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    #[test]
    fn prepared_pause_does_not_accept_prefetched_rows_or_promise_early_eof() {
        let (local, mut peer) = UnixStream::pair().unwrap();
        let mut io = Io::open([local.as_raw_fd(); 2]).unwrap();
        peer.write_all(b"A\nB\n").unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        let mut input = Input::default();
        assert!(
            matches!(input.poll_with_limit(&mut io,0,2048).unwrap(),Some(Command::Record(r)) if r.id==1)
        );
        let p = Policy::accuracy(10, 10, 3, 4096).unwrap();
        let old = phase::Request::new("locked", 0, p).unwrap();
        let shared = phase::Shared::new(old);
        let gate = phase::prepared::Shared::new(
            phase::prepared::Request::new(old, 1).unwrap(),
            Arc::clone(&shared),
        );
        let mut worker = phase::Worker::new(Arc::clone(&shared));
        let t = Instant::now();
        gate.prepared(t).unwrap();
        gate.start(t, p).unwrap();
        shared.first_arm(Duration::ZERO).unwrap();
        // Same predicate used by Application::input_enabled: do not poll even
        // when the pipe already contains another record and a writer EOF.
        assert!(gate.hold_input());
        assert!(!input.eof);
        gate.target_arm(ArmObservation {
            number: 2,
            generation: 71,
            due: p.period(),
            started: p.period(),
            completed: p.period(),
            accepted: true,
        })
        .unwrap();
        assert!(gate.poll_at_for_test(&mut worker, t + p.period()).unwrap());
        assert!(gate.begin_at_for_test(&mut worker, t + p.period()).unwrap());
        assert!(gate.hold_input());
        assert!(!input.eof);
        gate.returned().unwrap();
        assert!(!gate.hold_input());
        assert!(
            matches!(input.poll_with_limit(&mut io,1,2048).unwrap(),Some(Command::Record(r)) if r.id==2)
        );
        assert!(matches!(
            input.poll_with_limit(&mut io, 2, 2048).unwrap(),
            Some(Command::Stop)
        ));
        assert!(input.eof);
    }
}
