//! Pure raw-record/geometry controls: no procfs, CPUID or ptrace is executed.
use super::*;

#[test]
fn stack_native_proc_path_is_exact_bounded_positive_tid() {
    let mut bytes = [0xff; 32];
    assert_eq!(
        proc_path(1, &mut bytes).unwrap().to_bytes_with_nul(),
        b"/proc/1\0"
    );
    assert_eq!(
        proc_path(i32::MAX, &mut bytes).unwrap().to_bytes_with_nul(),
        b"/proc/2147483647\0"
    );
    assert!(bytes[17..].iter().all(|byte| *byte == 0));
    for tid in [0, -1, i32::MIN] {
        assert!(proc_path(tid, &mut bytes).is_err());
    }
}
fn geometry(rsp: u64) -> OperandGeometry {
    OperandGeometry::derive(
        0x401000,
        &[0xc3],
        rsp,
        &(0x800000..0x804000),
        &(0x600000..0x601000),
    )
    .unwrap()
}
#[test]
fn stack_native_pagemap_extent_rebuilds_exact_frozen_one_or_two_pages() {
    let single = geometry(0x802000);
    assert_eq!(pagemap_extent(&single).unwrap(), (0x4010, 8));
    let crossing = geometry(0x801ffd);
    assert_eq!(crossing.slot, 0x801ffd..0x802005);
    assert_eq!(crossing.envelope, 0x801ff8..0x802008);
    assert_eq!(pagemap_extent(&crossing).unwrap(), (0x4008, 16));
    for field in 0..8 {
        let mut bad = crossing.clone();
        match field {
            0 => bad.envelope.start -= 8,
            1 => bad.envelope.end += 8,
            2 => bad.slot.start += 1,
            3 => bad.original_rsp += 1,
            4 => bad.length = usize::MAX,
            5 => bad.encoding[0] = 0x90,
            6 => bad.pc = u64::MAX,
            _ => bad.stack.end = bad.envelope.end - 1,
        }
        assert!(pagemap_extent(&bad).is_err(), "corruption {field}");
    }
}
fn synthetic_access() -> PagemapAccess {
    PagemapAccess {
        started: true,
        complete: true,
        directory_open: Some(Request {
            result: 10,
            errno: None,
        }),
        directory_statfs: Some(success()),
        directory_filesystem: Some(libc::PROC_SUPER_MAGIC),
        file_open: Some(Request {
            result: 11,
            errno: None,
        }),
        file_statfs: Some(success()),
        file_filesystem: Some(libc::PROC_SUPER_MAGIC),
        file_close: Some(success()),
        directory_close: Some(success()),
        first_failure: None,
    }
}
#[test]
fn stack_native_pagemap_access_requires_both_owned_fds_procfs_and_closes() {
    // Supplied data validates consistency only; no native certificate is built.
    let good = synthetic_access();
    assert_eq!(good.validate(), Ok(()));
    let mut pread = PagemapObservation {
        fd: 11,
        ..Default::default()
    };
    assert_eq!(good.validate_for(&pread), Ok(()));
    pread.fd = 10;
    assert_eq!(good.validate_for(&pread), Err(StackError::Request));
    pread.fd = -1;
    assert_eq!(good.validate_for(&pread), Err(StackError::Request));
    for count in [8, 16] {
        assert!(
            require_pagemap_read(
                Request {
                    result: count as i64,
                    errno: None
                },
                count
            )
            .is_ok()
        );
        for result in [-1, 0, count as i64 - 1, count as i64 + 1] {
            assert!(
                require_pagemap_read(
                    Request {
                        result,
                        errno: None
                    },
                    count
                )
                .is_err()
            );
        }
        assert!(
            require_pagemap_read(
                Request {
                    result: count as i64,
                    errno: Some(libc::EFAULT)
                },
                count
            )
            .is_err()
        );
    }
    assert!(
        require_pagemap_read(
            Request {
                result: 0,
                errno: None
            },
            0
        )
        .is_err()
    );
    for field in 0..17 {
        let mut bad = good;
        match field {
            0 => bad.started = false,
            1 => bad.complete = false,
            2 => bad.directory_open = None,
            3 => bad.file_open = None,
            4 => bad.directory_open.as_mut().unwrap().result = -1,
            5 => bad.file_open.as_mut().unwrap().result = i64::from(i32::MAX) + 1,
            6 => bad.file_open = bad.directory_open,
            7 => bad.directory_open.as_mut().unwrap().errno = Some(libc::EACCES),
            8 => bad.file_open.as_mut().unwrap().errno = Some(libc::EIO),
            9 => bad.directory_statfs = None,
            10 => bad.file_statfs.as_mut().unwrap().result = -1,
            11 => bad.directory_filesystem = Some(0),
            12 => bad.file_filesystem = Some(0),
            13 => bad.file_close = None,
            14 => bad.directory_close = None,
            15 => bad.file_close.as_mut().unwrap().errno = Some(libc::EINTR),
            _ => bad.first_failure = Some(StackError::Pagemap),
        }
        assert!(bad.validate().is_err(), "corruption {field}");
    }
}
#[test]
fn stack_native_peek_keeps_all_ones_and_failed_second_request_prefix() {
    let mut word = WordObservation::default();
    let all_ones = Request {
        result: -1,
        errno: None,
    };
    retain_peek(&mut word, 0, 0x801ff8, all_ones).unwrap();
    assert_eq!(word.copied, 8);
    assert_eq!(&word.bytes[..8], &[0xff; 8]);
    let fault = Request {
        result: -1,
        errno: Some(libc::EIO),
    };
    assert!(matches!(
        retain_peek(&mut word, 1, 0x802000, fault),
        Err(LaunchError::System {
            operation: "read owned stack word",
            ..
        })
    ));
    assert_eq!(
        word.peek[0],
        Some(PeekRecord {
            address: 0x801ff8,
            request: all_ones
        })
    );
    assert_eq!(
        word.peek[1],
        Some(PeekRecord {
            address: 0x802000,
            request: fault
        })
    );
    assert_eq!(word.copied, 8);
    assert_eq!(&word.bytes[..8], &[0xff; 8]);
    assert_eq!(&word.bytes[8..], &[0; 8]);
    let saved = word;
    assert!(retain_peek(&mut word, 1, 0x802000, all_ones).is_err());
    assert_eq!(word, saved);
    assert!(retain_peek(&mut word, usize::MAX, 0, all_ones).is_err());
    assert_eq!(word, saved);
}
