//! Synthetic capture phases with the real MapCapture destructor. These tests
//! perform no procfs read, native wait, mapping operation or cleanup claim.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

const TID: i32 = 101;
const TABLE: &[u8] = b"00400000-00401000 r-xp 0 00:00 0\n";

fn archive() -> MappingCaptureArchive {
    MappingCaptureArchive::new(KernelAttemptId {
        session: 97,
        invocation: 3,
    })
    .unwrap()
}

// Seed only initialized bookkeeping at an explicitly synthetic read boundary.
// The production begin/terminal methods and actual Drop implementation remain
// the code under test; no synthetic bytes are described as a native capture.
fn started(
    archive: &MappingCaptureArchive,
    prefix: &[u8],
    phase: MapCapturePhase,
    complete: bool,
) -> MapCapture {
    let mut capture = MapCapture::archived(archive, MappingCaptureSlot::BeforeWindow).unwrap();
    archive
        .begin(MappingCaptureSlot::BeforeWindow, TID, None)
        .unwrap();
    capture.attempted = true;
    Arc::get_mut(&mut capture.storage).unwrap()[..prefix.len()].copy_from_slice(prefix);
    capture.len = prefix.len();
    capture.phase = phase;
    capture.complete = complete;
    capture
}

fn exact_prefix(archive: &MappingCaptureArchive, prefix: &[u8], status: MappingCaptureStatus) {
    let snapshot = archive.snapshot();
    assert_eq!(
        snapshot.attempt,
        KernelAttemptId {
            session: 97,
            invocation: 3
        }
    );
    assert!(!snapshot.archive_poisoned);
    let row = &snapshot.records[0];
    assert_eq!(row.slot, MappingCaptureSlot::BeforeWindow);
    assert_eq!(row.tid, Some(TID));
    assert_eq!(row.wait_status, None);
    assert_eq!(row.status, status);
    assert_eq!(row.initialized_len, prefix.len());
    assert_eq!(row.bytes(), Some(prefix));
    let storage = row.initialized_storage().unwrap();
    assert_eq!(storage.len(), MAP_CAPTURE_BYTES);
    assert!(storage[prefix.len()..].iter().all(|byte| *byte == 0));
    assert!(snapshot.records[1..].iter().all(|row| {
        row.status == MappingCaptureStatus::Unused
            && row.tid.is_none()
            && row.wait_status.is_none()
            && row.bytes().is_none()
            && row.initialized_len == 0
    }));
}

#[test]
fn unattempted_capture_drop_does_not_invent_an_observation() {
    let archive = archive();
    let before = archive.snapshot();
    let mut capture = MapCapture::archived(&archive, MappingCaptureSlot::BeforeWindow).unwrap();
    assert!(matches!(
        capture.capture(0),
        Err(LaunchError::Invalid("mapping capture slot is stale"))
    ));
    assert!(!capture.attempted);
    drop(capture);
    assert_eq!(archive.snapshot(), before);
}

#[test]
fn normal_capture_drop_retains_partial_and_unparsed_complete_prefixes() {
    for (prefix, phase, complete) in [
        (&TABLE[..17], MapCapturePhase::Read, false),
        (TABLE, MapCapturePhase::Parse, true),
    ] {
        let archive = archive();
        let capture = started(&archive, prefix, phase, complete);
        let original_storage = capture.storage.as_ptr();
        let progress = archive.snapshot();
        assert_eq!(progress.records[0].status, MappingCaptureStatus::InProgress);
        assert_eq!(progress.records[0].bytes(), None);
        drop(capture);
        exact_prefix(
            &archive,
            prefix,
            MappingCaptureStatus::Abandoned {
                phase,
                read_complete: complete,
            },
        );
        assert_eq!(
            archive.snapshot().records[0]
                .initialized_storage()
                .unwrap()
                .as_ptr(),
            original_storage
        );
    }
}

#[test]
fn actual_unwind_drop_retains_prefix_without_claiming_capture_completion() {
    const PAYLOAD: &str = "intentional mapping capture bookkeeping unwind";
    for (prefix, phase, complete) in [
        (&TABLE[..17], MapCapturePhase::Read, false),
        (TABLE, MapCapturePhase::Parse, true),
    ] {
        let archive = archive();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let capture = started(&archive, prefix, phase, complete);
            assert!(!capture.archived);
            std::panic::panic_any(PAYLOAD);
        }));
        let payload = result.expect_err("the exact intentional unwind must occur");
        assert_eq!(payload.downcast_ref::<&str>(), Some(&PAYLOAD));
        exact_prefix(
            &archive,
            prefix,
            MappingCaptureStatus::Unwound {
                phase,
                read_complete: complete,
            },
        );
    }
}

#[test]
fn terminal_capture_results_survive_drop_without_overwrite_or_new_read() {
    for (prefix, phase, complete, terminal) in [
        (
            TABLE,
            MapCapturePhase::Complete,
            true,
            MappingCaptureStatus::Complete,
        ),
        (
            &TABLE[..17],
            MapCapturePhase::Read,
            false,
            MappingCaptureStatus::Failed {
                phase: MapCapturePhase::Read,
                errno: Some(libc::EIO),
                read_complete: false,
            },
        ),
        (
            &b"malformed complete table\n"[..],
            MapCapturePhase::Parse,
            true,
            MappingCaptureStatus::Failed {
                phase: MapCapturePhase::Parse,
                errno: None,
                read_complete: true,
            },
        ),
    ] {
        let archive = archive();
        let mut capture = started(&archive, prefix, phase, complete);
        if terminal == MappingCaptureStatus::Complete {
            assert_eq!(capture.view().unwrap().raw(), TABLE);
        } else if complete {
            assert!(matches!(
                capture.view(),
                Err(LaunchError::Invalid(
                    "mapping capture is malformed or exceeds row bound"
                ))
            ));
        }
        capture.archive_terminal(terminal).unwrap();
        assert!(capture.archived);
        assert!(Arc::get_mut(&mut capture.storage).is_none());
        let before = archive.snapshot();
        assert!(matches!(
            capture.capture(TID),
            Err(LaunchError::Invalid("mapping capture slot is stale"))
        ));
        assert_eq!(archive.snapshot(), before);
        drop(capture);
        assert_eq!(archive.snapshot(), before);
        exact_prefix(&archive, prefix, terminal);
    }
}
