//! Deterministic cleanup-candidate controls: no process creation or proc reads.
#![deny(warnings)]
#![forbid(unsafe_code)]

#[path = "support/bounded_proc_stat.rs"]
mod bounded_proc_stat;
#[path = "support/owned_group_candidate.rs"]
mod owned_group_candidate;

use bounded_proc_stat::read_bounded_stat;
use owned_group_candidate::{Inventory, owned_group_candidate};
use std::cell::Cell;
use std::collections::VecDeque;
use std::io::{self, Cursor, Read};

const PID: i32 = 41;
const GROUP: i32 = 37;
const PARENT: u32 = 23;

fn stat(pid: i32, parent: u32, group: i32) -> Vec<u8> {
    format!("{pid} (fixed fixture) Z {parent} {group} 19\n").into_bytes()
}

fn check_stat(bytes: Vec<u8>) -> Result<bool, String> {
    let looked_up = Cell::new(0);
    let read = Cell::new(0);
    let result = owned_group_candidate(
        PID,
        PARENT,
        GROUP,
        || false,
        |pid| {
            assert_eq!(pid, PID);
            looked_up.set(looked_up.get() + 1);
            Ok(GROUP)
        },
        || {
            read.set(read.get() + 1);
            read_bounded_stat(Cursor::new(bytes))
        },
    );
    assert_eq!((looked_up.get(), read.get()), (1, 1));
    result
}

#[test]
fn foreign_group_and_disappeared_candidate_never_open_stat() {
    for answer in [
        Ok(0),
        Ok(GROUP + 1),
        Err(io::Error::from_raw_os_error(libc::ESRCH)),
    ] {
        let queries = Cell::new(0);
        assert_eq!(
            owned_group_candidate(
                PID,
                PARENT,
                GROUP,
                || false,
                |pid| {
                    assert_eq!(pid, PID);
                    queries.set(queries.get() + 1);
                    answer
                },
                || panic!("foreign/disappeared candidate must not open stat"),
            ),
            Ok(false)
        );
        assert_eq!(queries.get(), 1);
    }
}

#[test]
fn lookup_errors_other_than_raw_esrch_remain_failures() {
    for errno in [libc::EPERM, libc::EINVAL, libc::ENOENT, libc::EIO] {
        let expected = format!("getpgid({PID}): {}", io::Error::from_raw_os_error(errno));
        assert_eq!(
            owned_group_candidate(
                PID,
                PARENT,
                GROUP,
                || false,
                |_| Err(io::Error::from_raw_os_error(errno)),
                || panic!("lookup error must not open stat"),
            ),
            Err(expected)
        );
    }
    let error = owned_group_candidate(
        PID,
        PARENT,
        GROUP,
        || false,
        |_| {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "synthetic, no errno",
            ))
        },
        || panic!("synthetic NotFound is not raw ESRCH"),
    )
    .unwrap_err();
    assert!(error.contains("synthetic, no errno"));
}

#[test]
fn nonpositive_requested_identities_refuse_before_lookup() {
    for (pid, parent, group) in [
        (0, PARENT, GROUP),
        (-1, PARENT, GROUP),
        (PID, 0, GROUP),
        (PID, PARENT, 0),
        (PID, PARENT, -1),
    ] {
        assert_eq!(
            owned_group_candidate(
                pid,
                parent,
                group,
                || panic!("invalid identity must fail before clock or syscalls"),
                |_| panic!("invalid identity must not query getpgid"),
                || panic!("invalid identity must not open stat"),
            ),
            Err("invalid positive process ownership identity".into())
        );
    }
}

#[test]
fn negative_kernel_group_refuses_without_opening_stat() {
    for answer in [-1, i32::MIN] {
        assert_eq!(
            owned_group_candidate(
                PID,
                PARENT,
                GROUP,
                || false,
                |_| Ok(answer),
                || panic!("invalid kernel group must not open stat"),
            ),
            Err("invalid kernel process group".into())
        );
    }
}

#[test]
fn matching_group_requires_exact_stat_identity_parent_and_group() {
    assert_eq!(check_stat(stat(PID, PARENT, GROUP)), Ok(true));
    assert_eq!(
        check_stat(stat(PID + 1, PARENT, GROUP)),
        Err("process stat identity mismatch".into())
    );
    assert_eq!(check_stat(stat(PID, PARENT + 1, GROUP)), Ok(false));
    assert_eq!(check_stat(stat(PID, PARENT, 0)), Ok(false));
    assert_eq!(check_stat(stat(PID, PARENT, GROUP + 1)), Ok(false));
    assert_eq!(check_stat(stat(PID, PARENT + 1, GROUP + 1)), Ok(false));
}

#[test]
fn original_stat_comm_and_numeric_parser_checks_are_retained() {
    let mut non_utf8_comm = format!("{PID} (").into_bytes();
    non_utf8_comm.extend_from_slice(b"nested ) ( \xff bytes");
    non_utf8_comm.extend_from_slice(format!(") Z {PARENT} {GROUP} 19\n").as_bytes());
    assert_eq!(check_stat(non_utf8_comm), Ok(true));
    for (bytes, message) in [
        (
            format!("{PID} (missing delimiter").into_bytes(),
            "malformed process stat",
        ),
        (
            format!("{PID} (x) Z {PARENT}\n").into_bytes(),
            "short process stat",
        ),
        (
            format!("{PID} (x) Z not-a-pid {GROUP}\n").into_bytes(),
            "invalid parent PID",
        ),
        (
            format!("{PID} (x) Z {PARENT} not-a-group\n").into_bytes(),
            "invalid process group",
        ),
        (
            format!("{PID} (x) Z -1 {GROUP}\n").into_bytes(),
            "invalid parent PID",
        ),
    ] {
        assert_eq!(check_stat(bytes), Err(message.into()));
    }
    let mut invalid_suffix = format!("{PID} (x) Z {PARENT} ").into_bytes();
    invalid_suffix.push(0xff);
    assert_eq!(
        check_stat(invalid_suffix),
        Err("non-ASCII numeric process fields".into())
    );
}

#[test]
fn deadline_before_lookup_performs_no_process_access() {
    assert_eq!(
        owned_group_candidate(
            PID,
            PARENT,
            GROUP,
            || true,
            |_| panic!("expired deadline must not query getpgid"),
            || panic!("expired deadline must not open stat"),
        ),
        Err("bounded process inventory deadline before group lookup".into())
    );
}

#[test]
fn deadline_after_lookup_refuses_members_foreign_and_esrch_without_stat() {
    for answer in [
        Ok(GROUP),
        Ok(0),
        Ok(GROUP + 1),
        Err(io::Error::from_raw_os_error(libc::ESRCH)),
    ] {
        let mut clock = VecDeque::from([false, true]);
        assert_eq!(
            owned_group_candidate(
                PID,
                PARENT,
                GROUP,
                || clock.pop_front().expect("unexpected clock reset"),
                |_| answer,
                || panic!("original deadline expired before stat open"),
            ),
            Err("bounded process inventory deadline after group lookup".into())
        );
        assert!(clock.is_empty());
    }
}

#[test]
fn deadline_after_stat_refuses_even_when_candidate_disappears() {
    for answer in [Some(stat(PID, PARENT, GROUP)), None] {
        let mut clock = VecDeque::from([false, false, true]);
        let reads = Cell::new(0);
        assert_eq!(
            owned_group_candidate(
                PID,
                PARENT,
                GROUP,
                || clock.pop_front().expect("unexpected clock reset"),
                |_| Ok(GROUP),
                || {
                    reads.set(reads.get() + 1);
                    Ok(answer)
                },
            ),
            Err("bounded process stat read deadline exhausted".into())
        );
        assert_eq!(reads.get(), 1);
        assert!(clock.is_empty());
    }
}

#[test]
fn candidate_stat_keeps_4096_byte_gate_and_4097_byte_read_ceiling() {
    for (len, expected) in [
        (4096, Ok(true)),
        (
            4097,
            Err("bounded process stat size exhausted: bytes=4097".into()),
        ),
        (
            8192,
            Err("bounded process stat size exhausted: bytes=4097".into()),
        ),
    ] {
        let mut bytes = stat(PID, PARENT, GROUP);
        bytes.resize(len, b' ');
        let mut reader = Cursor::new(bytes);
        assert_eq!(
            owned_group_candidate(
                PID,
                PARENT,
                GROUP,
                || false,
                |_| Ok(GROUP),
                || read_bounded_stat(&mut reader),
            ),
            expected
        );
        assert_eq!(reader.position(), len.min(4097) as u64);
    }
}

#[test]
fn stat_read_errors_and_partial_esrch_are_not_disappearance() {
    struct Partial {
        sent: bool,
        errno: i32,
    }
    impl Read for Partial {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if !self.sent {
                self.sent = true;
                out[0] = b'4';
                Ok(1)
            } else {
                Err(io::Error::from_raw_os_error(self.errno))
            }
        }
    }
    for errno in [libc::ESRCH, libc::ENOENT, libc::EPERM, libc::EIO] {
        let expected = format!(
            "read /proc/{PID}/stat: {}",
            io::Error::from_raw_os_error(errno)
        );
        assert_eq!(
            owned_group_candidate(
                PID,
                PARENT,
                GROUP,
                || false,
                |_| Ok(GROUP),
                || read_bounded_stat(Partial { sent: false, errno }),
            ),
            Err(expected)
        );
    }
    assert_eq!(
        owned_group_candidate(PID, PARENT, GROUP, || false, |_| Ok(GROUP), || Ok(None),),
        Ok(false)
    );
}

#[test]
fn inventory_counts_all_entries_and_distinguishes_original_limits() {
    let mut inventory = Inventory::default();
    // Nonnumeric entries are deliberately not exempt from the fixed cap.
    for expected in 1..=65536 {
        assert_eq!(inventory.entry(false), Ok(()));
        assert_eq!(inventory.entries, expected);
        assert_eq!(inventory.numeric, 0);
    }
    assert_eq!(inventory.entry(false), Err(
        "bounded process inventory entry limit exhausted; entries=65537 numeric=0 same_group=0 stat_open_attempts=0 stat_reads=0".into(),
    ));
    let mut expired = Inventory::default();
    assert_eq!(expired.entry(true), Err(
        "bounded process inventory deadline exhausted; entries=1 numeric=0 same_group=0 stat_open_attempts=0 stat_reads=0".into(),
    ));
    inventory.numeric = 4;
    inventory.same_group = 2;
    inventory.stat_open_attempts = 2;
    inventory.stat_reads = 1;
    assert_eq!(
        inventory.error("refused"),
        "refused; entries=65537 numeric=4 same_group=2 stat_open_attempts=2 stat_reads=1"
    );
}
