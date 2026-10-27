//! Lower raw fixtures are I/O/validator refusal evidence. They cannot produce
//! the connected original-stack permit or a native completion seal.
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime_stack::{
    StackError,
    metadata::{StackDescriptor, validate_smaps},
    operand::{OperandGeometry, WordObservation},
    storage::StackObservationStorage,
};
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native::acquire::{
    ModelPagemapAccess, RawIoFault, RawIoRecord, RawStoppedIo,
};

fn geometry(
    original: &Before,
    registers: &crate::RegisterSnapshot,
    program: &Program,
) -> OperandGeometry {
    // This is only a descriptive geometry for the raw bounded reader. The
    // dummy disjoint exclusion range is not a claimed installed trusted island.
    OperandGeometry::derive(
        program.call_pc,
        &program.encoding,
        registers.rsp,
        &original.stack_range,
        &(0x700000000000..0x700000001000),
    )
    .unwrap()
}
fn waits(owner: &Owner) -> Vec<(i32, i32)> {
    owner
        .owned
        .iter()
        .map(|tid| (*tid, *owner.stopped.get(tid).unwrap()))
        .collect()
}
fn storage() -> StackObservationStorage {
    let mut value = StackObservationStorage::empty();
    value.allocate_payloads().unwrap();
    value
}
pub(super) fn nonresident() {
    let program = Program::call(4096, false);
    support::with_raw_owner(&program, |owner, initial, until, original| {
        let before = raw::first(owner, initial, until, original, program.entry);
        let geometry = geometry(original, &before.registers, &program);
        let page = geometry.slot.start & !4095;
        assert_eq!(
            raw::syscall(
                owner,
                until,
                libc::SYS_madvise as u64,
                [page, 4096, libc::MADV_DONTNEED as u64, 0, 0, 0]
            ),
            0
        );
        // No PEEK or whole-stack read occurred before this actual pagemap read.
        let held = waits(owner);
        let reader = RawStoppedIo::acquire(owner, owner.pid, &held, until, None).unwrap();
        let mut word = WordObservation::default();
        let mut access = ModelPagemapAccess::default();
        let result = reader.capture_pagemap(&geometry, &mut word, &mut access);
        assert!(matches!(
            result,
            Err(LaunchError::Invalid(
                "owned stack actual page is not resident and exclusive"
            ))
        ));
        assert_eq!(
            word.pagemap.request,
            Some(NativeRequest {
                result: 8,
                errno: None
            })
        );
        let actual = u64::from_le_bytes(word.pagemap.bytes[..8].try_into().unwrap());
        assert_eq!(actual & (1 << 63), 0);
        assert_eq!(access.first_failure, Some(StackError::Pagemap));
        assert!(access.complete);
        assert_eq!(word.peek, [None; 2]);
        assert_eq!(word.copied, 0);
        assert!(!word.complete);
        assert_eq!(word.bytes, [0; 16]);
        reader.require_held().unwrap();
        assert!(owner.runtime.is_none());
        let records = reader.records();
        let saved = (word, access, records);
        move || {
            assert_eq!((word, access, records), saved);
        }
    });
}
pub(super) fn nonexclusive() {
    let program = Program::literal(4096, &[0xc3]);
    support::with_raw_owner(&program, |owner, initial, until, original| {
        let before = raw::first(owner, initial, until, original, program.entry);
        // The actual argc word at initial RSP is kernel-written and resident.
        // This raw reader never executes RET; it avoids an unproved resident
        // assumption about the unused word below a page-boundary initial RSP.
        let geometry = OperandGeometry::derive(
            program.entry,
            &[0xc3],
            before.registers.rsp,
            &original.stack_range,
            &(0x700000000000..0x700000001000),
        )
        .unwrap();
        let both = raw::fork_held(owner, until);
        let reader = RawStoppedIo::acquire(owner, owner.pid, &both, until, None).unwrap();
        let mut word = WordObservation::default();
        let mut access = ModelPagemapAccess::default();
        let result = reader.capture_pagemap(&geometry, &mut word, &mut access);
        assert!(matches!(
            result,
            Err(LaunchError::Invalid(
                "owned stack actual page is not resident and exclusive"
            ))
        ));
        assert_eq!(
            word.pagemap.request,
            Some(NativeRequest {
                result: 8,
                errno: None
            })
        );
        let actual = u64::from_le_bytes(word.pagemap.bytes[..8].try_into().unwrap());
        assert_ne!(actual & (1 << 63), 0);
        assert_eq!(actual & (1 << 56), 0);
        assert_eq!(access.first_failure, Some(StackError::Pagemap));
        assert!(access.complete);
        assert_eq!(word.peek, [None; 2]);
        assert_eq!(word.copied, 0);
        assert_eq!(word.bytes, [0; 16]);
        assert!(!word.complete);
        reader.require_held().unwrap();
        assert_eq!(owner.owned.len(), 2);
        assert!(owner.runtime.is_none());
        let records = reader.records();
        let saved = (word, access, records);
        move || {
            assert_eq!((word, access, records), saved);
        }
    });
}
pub(super) fn metadata() {
    for mode in 0..3 {
        let program = Program::call(4096, false);
        support::with_raw_owner(&program, |owner, initial, until, original| {
            let before = raw::first(owner, initial, until, original, program.entry);
            let old = StackDescriptor::validate(
                &original.maps,
                &original.maps,
                before.registers.rsp,
                &(0x700000000000..0x700000001000),
            )
            .unwrap();
            let range = original.stack_range.clone();
            let mut actual_key = None;
            match mode {
                0 => {
                    let key = raw::syscall(owner, until, libc::SYS_pkey_alloc as u64, [0; 6]);
                    assert!((1..16).contains(&key));
                    actual_key = Some(key);
                    assert_eq!(
                        raw::syscall(
                            owner,
                            until,
                            libc::SYS_pkey_mprotect as u64,
                            [range.start, range.end - range.start, 3, key as u64, 0, 0]
                        ),
                        0
                    );
                }
                1 => {
                    let page = (before.registers.rsp & !4095) - 4096;
                    assert!(range.start < page && page + 4096 < range.end);
                    assert_eq!(
                        raw::syscall(
                            owner,
                            until,
                            libc::SYS_mprotect as u64,
                            [page, 4096, 1, 0, 0, 0]
                        ),
                        0
                    );
                }
                2 => assert_eq!(
                    raw::syscall(
                        owner,
                        until,
                        libc::SYS_madvise as u64,
                        [
                            range.start,
                            range.end - range.start,
                            libc::MADV_DONTDUMP as u64,
                            0,
                            0,
                            0
                        ]
                    ),
                    0
                ),
                _ => unreachable!(),
            }
            let held = waits(owner);
            let reader = RawStoppedIo::acquire(owner, owner.pid, &held, until, None).unwrap();
            let mut captured = storage();
            let mut eof = [0; 2];
            reader
                .capture_file(
                    c"smaps",
                    &mut captured.smaps,
                    &mut captured.smaps_capture,
                    &mut eof[0],
                )
                .unwrap();
            reader
                .capture_file(
                    c"maps",
                    &mut captured.maps,
                    &mut captured.maps_capture,
                    &mut eof[1],
                )
                .unwrap();
            let smaps = captured.smaps_capture.bytes(&captured.smaps).unwrap();
            let current = captured.maps_capture.bytes(&captured.maps).unwrap();
            match mode {
                0 => {
                    let index = old.require_current(&original.maps, current).unwrap();
                    assert_eq!(
                        validate_smaps(smaps, current, index),
                        Err(StackError::Metadata)
                    );
                    let header = rows(current)[index].raw.clone();
                    let start = smaps
                        .windows(header.len())
                        .position(|bytes| bytes == header)
                        .unwrap();
                    let record = smaps[start..]
                        .split(|b| *b == b'\n')
                        .find(|line| line.starts_with(b"ProtectionKey:"))
                        .unwrap();
                    let value = std::str::from_utf8(&record[b"ProtectionKey:".len()..])
                        .unwrap()
                        .trim()
                        .parse::<i64>()
                        .unwrap();
                    assert_eq!(Some(value), actual_key);
                }
                1 => assert_eq!(
                    old.require_current(&original.maps, current),
                    Err(StackError::Provenance)
                ),
                2 => {
                    let index = old.require_current(&original.maps, current).unwrap();
                    assert_eq!(
                        validate_smaps(smaps, current, index),
                        Err(StackError::Flags)
                    );
                    let header = rows(current)[index].raw.clone();
                    let start = smaps
                        .windows(header.len())
                        .position(|bytes| bytes == header)
                        .unwrap();
                    let flags = smaps[start..]
                        .split(|b| *b == b'\n')
                        .find(|line| line.starts_with(b"VmFlags:"))
                        .unwrap();
                    assert!(flags.split(|b| *b == b' ').any(|field| field == b"dd"));
                }
                _ => unreachable!(),
            }
            assert_eq!(captured.state.registers_request, None);
            assert!(owner.runtime.is_none());
            reader.require_held().unwrap();
            let records = reader.records();
            let saved = (retention::observation(&captured), records);
            move || {
                assert_eq!((retention::observation(&captured), records), saved);
            }
        });
    }
}
pub(super) fn raw_io() {
    for fault in [
        RawIoFault::MissingBasename,
        RawIoFault::InvalidStatfs,
        RawIoFault::NullRead,
        RawIoFault::NullPread,
        RawIoFault::InvalidCloseProbe,
        RawIoFault::ExpireAfterPositiveRead,
    ] {
        let program = Program::call(4096, false);
        support::with_raw_owner(&program, |owner, initial, until, original| {
            let before = raw::first(owner, initial, until, original, program.entry);
            let geometry = geometry(original, &before.registers, &program);
            let held = waits(owner);
            let reader =
                RawStoppedIo::acquire(owner, owner.pid, &held, until, Some(fault)).unwrap();
            let mut captured = storage();
            let mut eof = 0;
            let mut word = WordObservation::default();
            let mut access = ModelPagemapAccess::default();
            let result = if fault == RawIoFault::NullPread {
                reader.capture_pagemap(&geometry, &mut word, &mut access)
            } else {
                reader.capture_file(
                    c"maps",
                    &mut captured.maps,
                    &mut captured.maps_capture,
                    &mut eof,
                )
            };
            match fault {
                RawIoFault::MissingBasename => assert!(
                    matches!(result,Err(LaunchError::System{source,..}) if source.raw_os_error()==Some(libc::ENOENT))
                ),
                RawIoFault::InvalidStatfs | RawIoFault::InvalidCloseProbe => assert!(
                    matches!(result,Err(LaunchError::System{source,..}) if source.raw_os_error()==Some(libc::EBADF))
                ),
                RawIoFault::NullRead | RawIoFault::NullPread => assert!(
                    matches!(result,Err(LaunchError::System{source,..}) if source.raw_os_error()==Some(libc::EFAULT))
                ),
                RawIoFault::ExpireAfterPositiveRead => {
                    assert!(matches!(result, Err(LaunchError::Timeout(_))));
                    assert!(captured.maps_capture.copied > 0);
                    assert_eq!(captured.maps_capture.read_calls, 1);
                    assert!(!captured.maps_capture.complete);
                }
            }
            let records = reader.records();
            assert!(records.iter().any(Option::is_some));
            if matches!(fault, RawIoFault::NullRead | RawIoFault::NullPread) {
                assert!(records.iter().flatten().any(|r|matches!(r,RawIoRecord::Read{record,..} if record.destination==0&&record.request==NativeRequest{result:-1,errno:Some(libc::EFAULT)})));
                assert_eq!(word.peek, [None; 2]);
            }
            // The first failing prefix stays unchanged while an independent
            // later reader runs, except when the original deadline expired.
            let mut later_state = None;
            let mut later_records = None;
            let mut later_word = None;
            let mut later_access = None;
            if fault != RawIoFault::ExpireAfterPositiveRead {
                let saved = (
                    captured.maps_capture,
                    captured.maps.clone(),
                    word,
                    access,
                    records,
                );
                let later = RawStoppedIo::acquire(owner, owner.pid, &held, until, None).unwrap();
                let mut independent = StateSlot::allocate().unwrap();
                let failure = later.null_getregs_then_state(&mut independent).unwrap();
                assert_eq!(
                    failure,
                    NativeRequest {
                        result: -1,
                        errno: Some(libc::EFAULT)
                    }
                );
                compare::slot(&independent);
                assert_eq!(independent.state, before);
                assert_eq!(
                    (
                        captured.maps_capture,
                        captured.maps.clone(),
                        word,
                        access,
                        reader.records()
                    ),
                    saved
                );
                assert!(later.records().iter().flatten().any(
                    |r| matches!(r,RawIoRecord::Getregs{output:0,request,..} if *request==failure)
                ));
                // A later successful raw read uses the kernel-written argc
                // word. This is descriptive RET geometry for the shared I/O
                // body, not an instruction/operand authentication or execution.
                let argc_geometry = OperandGeometry::derive(
                    before.registers.rip,
                    &[0xc3],
                    before.registers.rsp,
                    &original.stack_range,
                    &(0x700000000000..0x700000001000),
                )
                .unwrap();
                let mut actual_word = WordObservation::default();
                let mut actual_access = ModelPagemapAccess::default();
                later
                    .capture_pagemap(&argc_geometry, &mut actual_word, &mut actual_access)
                    .unwrap();
                later
                    .capture_word(&argc_geometry, &mut actual_word, &actual_access)
                    .unwrap();
                assert_eq!(actual_word.validate(&argc_geometry).unwrap(), 1);
                actual_access.validate_for(&actual_word.pagemap).unwrap();
                assert_eq!(
                    (
                        captured.maps_capture,
                        captured.maps.clone(),
                        word,
                        access,
                        reader.records()
                    ),
                    saved
                );
                later_word = Some(actual_word);
                later_access = Some(actual_access);
                later_records = Some(later.records());
                later_state = Some(independent);
            }
            assert!(owner.runtime.is_none());
            let saved = (
                retention::observation(&captured),
                word,
                access,
                records,
                later_state.as_ref().map(retention::slot),
                later_records,
                later_word,
                later_access,
            );
            move || {
                assert_eq!(
                    (
                        retention::observation(&captured),
                        word,
                        access,
                        records,
                        later_state.as_ref().map(retention::slot),
                        later_records,
                        later_word,
                        later_access
                    ),
                    saved
                );
            }
        });
    }
}
