//! Single controller-thread nonblocking transport. No blocked reader to abandon.
use super::protocol::{self, Command};

const OUTPUT: usize = 4 * 1024 * 1024;
pub(super) struct Io {
    fds: [i32; 2],
    flags: [i32; 2],
    input: Vec<u8>,
    eof: bool,
    output: Vec<u8>,
    written: usize,
    write_blocked: u64,
}
impl Io {
    pub(super) fn new() -> Result<Self, String> {
        Self::open([0, 1])
    }
    // Descriptor owners outlive this flag-restoring transport. Tests use
    // independent sockets without replacing the harness's standard descriptors.
    fn open(fds: [i32; 2]) -> Result<Self, String> {
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
            output: Vec::with_capacity(OUTPUT),
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
    pub(super) fn eof(&self) -> bool {
        self.eof && self.input.is_empty()
    }
    pub(super) fn emit(&mut self, line: String) -> Result<(), String> {
        // Every fixed-format row is <=350 bytes even at maximum u64 values.
        // At most4096 RESULT-or-FLUSHED,4096 SAMPLE,4097 HISTORY,4096 REPORT,
        // plus READY/IO/DONE. The tighter per-kind layouts keep the sum below4MiB;
        // the total guard remains authoritative and never discards a row.
        if line.len() > 350
            || line.bytes().filter(|&b| b == b'\n').count() != 1
            || !line.ends_with('\n')
        {
            return Err("session row shape".into());
        }
        if self
            .output
            .len()
            .checked_add(line.len())
            .is_none_or(|n| n > OUTPUT)
        {
            return Err("session output capacity".into());
        }
        self.output.extend_from_slice(line.as_bytes());
        Ok(())
    }
    /// At most one 8 KiB write. All unsent bytes remain owned on backpressure.
    pub(super) fn write(&mut self) -> Result<(), String> {
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
    pub(super) fn drained(&self) -> bool {
        self.written == self.output.len()
    }
    pub(super) fn write_blocked(&self) -> u64 {
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
