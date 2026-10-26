//! Pure prefix controls. These fabricated progress rows are not native proof.
use super::super::source_identity::{
    SourceReadFailure, SourceReadOperation, SourceReadProgress, SourceReadRequest,
};
use super::*;

const MAPS: &[u8] =
    b"00400000-00402000 r-xp 00000000 08:02 17 /fixture\n00600000-00601000 rw-p 00000000 00:00 0\n";

fn complete(storage: &[u8], copied: usize) -> SourceReadProgress {
    SourceReadProgress {
        started: true,
        attempted: true,
        requested_bytes: storage.len(),
        copied_bytes: copied,
        complete: true,
        filesystem_type: Some(libc::PROC_SUPER_MAGIC as i64),
        last_request: Some(SourceReadRequest {
            operation: SourceReadOperation::ReadMaps,
            address: copied as u64,
            count: storage.len() - copied,
            result: 0,
            errno: None,
        }),
        failure: None,
    }
}

#[test]
fn initial_runtime_prefix_uses_observed_extent_and_preserves_initialized_storage() {
    let mut storage = vec![0; 64 * 1024];
    storage[..MAPS.len()].copy_from_slice(MAPS);
    let original = storage.clone();
    let progress = complete(&storage, MAPS.len());
    assert!(InitialBootstrapShape::from_original(&storage).is_err());
    let observed = initial_maps_prefix(&storage, &progress).unwrap();
    assert_eq!(observed, MAPS);
    assert_eq!(observed.as_ptr(), storage.as_ptr());
    InitialBootstrapShape::from_original(observed).unwrap();
    assert_eq!(storage, original);
    assert_eq!(storage.len(), 64 * 1024);
    assert!(storage[MAPS.len()..].iter().all(|byte| *byte == 0));
}

#[test]
fn initial_runtime_prefix_rejects_incomplete_failed_foreign_or_unbounded_progress() {
    let mut storage = vec![0; 64 * 1024];
    storage[..MAPS.len()].copy_from_slice(MAPS);
    let original = storage.clone();
    let valid = complete(&storage, MAPS.len());
    for mutation in 0..15 {
        let mut progress = valid;
        match mutation {
            0 => progress.started = false,
            1 => progress.attempted = false,
            2 => progress.complete = false,
            3 => {
                progress.failure = Some(SourceReadFailure {
                    operation: SourceReadOperation::ReadMaps,
                    timeout: false,
                    errno: Some(libc::EIO),
                })
            }
            4 => progress.requested_bytes -= 1,
            5 => progress.copied_bytes = 0,
            6 => progress.copied_bytes = storage.len() + 1,
            7 => progress.copied_bytes = usize::MAX,
            8 => progress.filesystem_type = None,
            9 => progress.filesystem_type = Some(0),
            10 => progress.last_request = None,
            11 => progress.last_request.as_mut().unwrap().errno = Some(libc::EIO),
            12 => progress.last_request.as_mut().unwrap().result = -1,
            13 => progress.last_request.as_mut().unwrap().result = 1,
            14 => progress.last_request.as_mut().unwrap().count = 0,
            _ => unreachable!(),
        }
        assert!(matches!(
            initial_maps_prefix(&storage, &progress),
            Err(GateError::Refused(
                "runtime original map capture is incomplete"
            ))
        ));
        assert_eq!(storage, original);
    }
    assert_eq!(initial_maps_prefix(&storage, &valid).unwrap(), MAPS);
}

#[test]
fn initial_runtime_prefix_does_not_hide_malformed_observed_suffixes() {
    for mutation in 0..4 {
        let mut observed = MAPS.to_vec();
        match mutation {
            0 => observed.push(0),
            1 => {
                observed.pop();
            }
            2 => observed.extend_from_slice(b"unparsed suffix\n"),
            3 => observed[10] = 0,
            _ => unreachable!(),
        }
        let mut storage = vec![0; 64 * 1024];
        storage[..observed.len()].copy_from_slice(&observed);
        let progress = complete(&storage, observed.len());
        let prefix = initial_maps_prefix(&storage, &progress).unwrap();
        assert_eq!(prefix, observed);
        assert!(InitialBootstrapShape::from_original(prefix).is_err());
        assert_eq!(&storage[..observed.len()], observed);
    }
}
