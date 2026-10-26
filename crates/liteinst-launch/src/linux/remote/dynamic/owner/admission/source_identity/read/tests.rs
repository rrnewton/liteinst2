//! Pure initialized-result controls. No model row proves a native read.
use super::*;

#[test]
fn source_prefix_unaligned_words_preserve_exact_requested_bytes() {
    let mut bytes = [0_u8; 10];
    let mut progress = SourceReadProgress::default();
    progress.begin(bytes.len()).unwrap();
    let end = checked_geometry(0x1003, bytes.len()).unwrap();
    accept_word(
        &mut bytes,
        0x1003,
        end,
        i64::from_ne_bytes(*b"ABCDEFGH"),
        None,
        &mut progress,
    )
    .unwrap();
    assert_eq!(progress.copied_bytes, 5);
    assert_eq!(&bytes, b"DEFGH\0\0\0\0\0");
    accept_word(
        &mut bytes,
        0x1003,
        end,
        i64::from_ne_bytes(*b"IJKLMNOP"),
        None,
        &mut progress,
    )
    .unwrap();
    assert_eq!(&bytes, b"DEFGHIJKLM");
    assert_eq!(progress.copied_bytes, 10);
    assert!(!progress.complete);
    assert_eq!(progress.last_request.unwrap().address, 0x1008);
    assert_eq!(progress.last_request.unwrap().count, 8);
    // A legitimate all-one word is not confused with a negative errno result.
    let mut ones = [0_u8; 8];
    let mut p = SourceReadProgress::default();
    p.begin(8).unwrap();
    accept_word(&mut ones, 0x2000, 0x2008, -1, None, &mut p).unwrap();
    assert_eq!(ones, [255; 8]);
}

#[test]
fn source_prefix_failed_word_retains_prior_bytes_and_exact_errno() {
    let mut bytes = [0_u8; 13];
    let mut progress = SourceReadProgress::default();
    progress.begin(bytes.len()).unwrap();
    accept_word(
        &mut bytes,
        0x1000,
        0x100d,
        i64::from_ne_bytes(*b"ABCDEFGH"),
        None,
        &mut progress,
    )
    .unwrap();
    let error = accept_word(
        &mut bytes,
        0x1000,
        0x100d,
        -1,
        Some(libc::EFAULT),
        &mut progress,
    )
    .unwrap_err();
    progress.failed(SourceReadOperation::PeekMemory, &error);
    assert_eq!(&bytes, b"ABCDEFGH\0\0\0\0\0");
    assert_eq!(progress.copied_bytes, 8);
    assert!(
        matches!(&error, GateError::Control(LaunchError::System { source, .. }) if source.raw_os_error() == Some(libc::EFAULT))
    );
    assert_eq!(
        progress.last_request,
        Some(SourceReadRequest {
            operation: SourceReadOperation::PeekMemory,
            address: 0x1008,
            count: 8,
            result: -1,
            errno: Some(libc::EFAULT),
        })
    );
    let failure = progress.failure;
    progress.failed(
        SourceReadOperation::Authenticate,
        &LaunchError::Timeout("later").into(),
    );
    assert_eq!(progress.failure, failure);
    assert!(!progress.complete);
}

#[test]
fn source_prefix_late_deadline_keeps_complete_bytes_unqualified() {
    let mut bytes = [0_u8; 4];
    let mut progress = SourceReadProgress::default();
    progress.begin(4).unwrap();
    accept_word(
        &mut bytes,
        0x1000,
        0x1004,
        i64::from_ne_bytes(*b"ABCDEFGH"),
        None,
        &mut progress,
    )
    .unwrap();
    let request = progress.last_request;
    progress.failed(
        SourceReadOperation::Authenticate,
        &LaunchError::Timeout("source original deadline").into(),
    );
    assert_eq!(bytes, *b"ABCD");
    assert_eq!(progress.copied_bytes, 4);
    assert_eq!(progress.last_request, request);
    assert_eq!(
        progress.failure,
        Some(SourceReadFailure {
            operation: SourceReadOperation::Authenticate,
            timeout: true,
            errno: None,
        })
    );
    assert!(!progress.complete);
}

#[test]
fn source_maps_full_prefix_requires_actual_zero_bound_read() {
    let mut progress = SourceReadProgress::default();
    progress.begin(MAP_BYTES).unwrap();
    assert!(!map_count(&mut progress, MAP_BYTES, (MAP_BYTES - 1) as i64, false).unwrap());
    assert!(!map_count(&mut progress, MAP_BYTES, 1, false).unwrap());
    assert_eq!(progress.copied_bytes, MAP_BYTES);
    let prior = progress;
    assert!(matches!(
        map_count(&mut progress, MAP_BYTES, 1, true),
        Err(GateError::Refused(
            "exec source maps exceed fixed capture bound"
        ))
    ));
    assert_eq!(progress, prior);
    assert!(map_count(&mut progress, MAP_BYTES, 0, true).unwrap());
    assert_eq!(progress.copied_bytes, MAP_BYTES);
    assert!(!progress.complete);
    let mut short = SourceReadProgress::default();
    short.begin(8).unwrap();
    assert!(map_count(&mut short, 8, 9, false).is_err());
    assert_eq!(short.copied_bytes, 0);
}

#[test]
fn source_prefix_reuse_refuses_without_replacing_prior_observation() {
    let mut progress = SourceReadProgress::default();
    progress.begin(17).unwrap();
    progress.copied_bytes = 9;
    progress.failed(
        SourceReadOperation::ReadMaps,
        &LaunchError::Timeout("first").into(),
    );
    let before = progress;
    assert!(matches!(
        progress.begin(100),
        Err(GateError::Refused("source read progress was already used"))
    ));
    assert_eq!(progress, before);
}

#[test]
fn source_prefix_range_rejects_empty_overflow_and_original_limit_excess() {
    assert!(checked_geometry(0x1000, 0).is_err());
    assert!(checked_geometry(0x1000, crate::linux::MAX_MEMORY_READ + 1).is_err());
    assert!(checked_geometry(u64::MAX - 6, 8).is_err());
    assert_eq!(
        checked_geometry(0x1000, crate::linux::MAX_MEMORY_READ).unwrap(),
        0x11000
    );
    assert_eq!(checked_geometry(u64::MAX - 8, 8).unwrap(), u64::MAX);
}
