//! Same real nonblocking transport and authoritative capacity check; no workloads.
use super::*;
use std::os::{fd::AsRawFd, unix::net::UnixStream};

#[test]
fn complete_rosters_fit_only_the_explicit_accuracy_output_capacity() {
    for (n, records, expected) in [
        (1, 2048, 4_137_000),
        (2, 2048, 7_006_300),
        (3, 1365, 6_767_950),
        (4, 1024, 6_652_100),
    ] {
        assert_eq!(records, 2048.min(4096 / n));
        let calls = n * records;
        let rows = 4 * calls + records + 3 * 520 + 6 * n + 14;
        assert_eq!(rows * 350, expected);
        assert!(expected <= ACCURACY_OUTPUT);
    }
    assert_eq!(OUTPUT, 4 * 1024 * 1024);
    assert_eq!(ACCURACY_OUTPUT, 8 * 1024 * 1024);
}

#[test]
fn both_caps_refuse_one_byte_over_without_discarding_pending_output() {
    let (socket, _peer) = UnixStream::pair().unwrap();
    for limit in [OUTPUT, ACCURACY_OUTPUT] {
        let mut io = Io::open_with_limit([socket.as_raw_fd(); 2], limit).unwrap();
        assert_eq!(io.output_limit, limit);
        io.output.resize(limit - 2, b'x');
        io.written = 17;
        io.write_blocked = 9;
        io.emit("x\n".into()).unwrap();
        let saved = io.output.clone();
        assert_eq!(io.emit("\n".into()), Err("session output capacity".into()));
        assert_eq!(io.output, saved);
        assert_eq!((io.written, io.write_blocked), (17, 9));
        assert_eq!(
            io.emit("x".repeat(350) + "\n"),
            Err("session row shape".into())
        );
        assert_eq!(io.output, saved);
    }
    let io = Io::open([socket.as_raw_fd(); 2]).unwrap();
    assert_eq!(io.output_limit, OUTPUT);
}
