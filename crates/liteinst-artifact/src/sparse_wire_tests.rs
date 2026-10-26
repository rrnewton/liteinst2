use super::*;
use crate::sparse;

fn limits() -> Limits {
    Limits {
        bytes: 20_000,
        content: sparse::Limits {
            edits: 8,
            edited_bytes: 100,
            pages: 4,
        },
    }
}
fn fixture() -> (Vec<u8>, SparsePages, Vec<u8>) {
    let original: Vec<_> = (0..4099).map(|n| (n % 251) as u8).collect();
    let edits = vec![FileEdit {
        offset: 4095,
        expected: original[4095..4098].to_vec(),
        replacement: vec![0xef, 0xee, 0xed],
    }];
    let pages = SparsePages::build(&original, edits, limits().content).unwrap();
    let bytes = encode(&pages, limits()).unwrap();
    (original, pages, bytes)
}
fn resign(bytes: &mut [u8]) {
    let digest = checksum(bytes);
    bytes[24..56].copy_from_slice(&digest.0);
}
fn mutate64(bytes: &[u8], at: usize, value: u64) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    changed[at..at + 8].copy_from_slice(&value.to_le_bytes());
    resign(&mut changed);
    changed
}
#[test]
fn round_trip_reconstructs_original_pages_and_explicit_short_tail() {
    let (original, pages, bytes) = fixture();
    assert_eq!(decode(&bytes, &original, limits()).unwrap(), pages);
    assert_eq!(bytes.len(), 120 + 16 + 6 + 16 + 4096 + 16 + 3);
    assert_eq!(&bytes[..8], b"LI2SPRS\0");
    assert_eq!(&bytes[112..120], &[0, 16, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[120..128], &4095_u64.to_le_bytes());
    assert_eq!(&bytes[142..150], &0_u64.to_le_bytes());
    assert_eq!(&bytes[4254..4262], &4096_u64.to_le_bytes());
    assert_eq!(pages.pages()[1].bytes.len(), 3);
    assert_ne!(pages.original_id(), crate::ContentId::of(&bytes));
    for original in [vec![], vec![1, 2, 3]] {
        let empty = SparsePages::build(&original, vec![], limits().content).unwrap();
        assert_eq!(
            decode(&encode(&empty, limits()).unwrap(), &original, limits()).unwrap(),
            empty
        );
    }
}
#[test]
fn every_corrupted_byte_truncation_and_append_is_rejected() {
    let (original, _, bytes) = fixture();
    for at in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(decode(&changed, &original, limits()).is_err(), "byte {at}");
        assert!(
            decode(&bytes[..at], &original, limits()).is_err(),
            "length {at}"
        );
    }
    let mut changed = bytes.clone();
    changed.push(0);
    assert_eq!(
        decode(&changed, &original, limits()),
        Err(Error::Envelope(crate::Error::Length))
    );
}
#[test]
fn valid_checksum_does_not_hide_stale_source_or_undeclared_page_change() {
    let (original, _, bytes) = fixture();
    let mut stale = original.clone();
    stale[0] ^= 1;
    assert_eq!(
        decode(&bytes, &stale, limits()),
        Err(Error::Content(sparse::Error::StaleOriginal))
    );
    let mut changed = bytes.clone();
    changed[136] ^= 1;
    resign(&mut changed);
    assert_eq!(
        decode(&changed, &original, limits()),
        Err(Error::Content(sparse::Error::StaleEdit))
    );
    let mut changed = bytes.clone();
    changed[158] ^= 1;
    resign(&mut changed);
    assert_eq!(
        decode(&changed, &original, limits()),
        Err(Error::Content(sparse::Error::PageMismatch))
    );
}
#[test]
fn prospective_resource_limits_apply_to_encode_and_decode() {
    let (original, pages, bytes) = fixture();
    for bounded in [
        Limits {
            bytes: bytes.len() - 1,
            ..limits()
        },
        Limits {
            content: sparse::Limits {
                edits: 0,
                ..limits().content
            },
            ..limits()
        },
        Limits {
            content: sparse::Limits {
                edited_bytes: 2,
                ..limits().content
            },
            ..limits()
        },
        Limits {
            content: sparse::Limits {
                pages: 1,
                ..limits().content
            },
            ..limits()
        },
    ] {
        assert_eq!(
            encode(&pages, bounded),
            Err(Error::Envelope(crate::Error::ResourceLimit))
        );
        assert_eq!(
            decode(&bytes, &original, bounded),
            Err(Error::Envelope(crate::Error::ResourceLimit))
        );
    }
    for at in [96, 104, 128, 150] {
        assert_eq!(
            decode(&mutate64(&bytes, at, u64::MAX), &original, limits()),
            Err(Error::Envelope(crate::Error::ResourceLimit)),
            "field {at}"
        );
    }
    // Generous caller limits still cannot allocate a count absent from the input.
    let generous = Limits {
        content: sparse::Limits {
            edits: usize::MAX,
            pages: usize::MAX,
            ..limits().content
        },
        ..limits()
    };
    assert_eq!(
        decode(&mutate64(&bytes, 96, 1_000_000), &original, generous),
        Err(Error::Envelope(crate::Error::Length))
    );
}
#[test]
fn valid_checksum_invalid_page_shapes_ranges_and_envelopes_refuse() {
    let (original, _, bytes) = fixture();
    for (at, value) in [(142, 1), (142, 8192), (150, 4095), (4254, 0), (4262, 2)] {
        assert_eq!(
            decode(&mutate64(&bytes, at, value), &original, limits()),
            Err(Error::Content(sparse::Error::PageMismatch)),
            "field {at} value {value}"
        );
    }
    for at in [0, 8, 12, 112, 116] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        resign(&mut changed);
        assert_eq!(
            decode(&changed, &original, limits()),
            Err(Error::Envelope(crate::Error::Format)),
            "field {at}"
        );
    }
    assert_eq!(
        decode(&mutate64(&bytes, 120, u64::MAX), &original, limits()),
        Err(Error::Content(sparse::Error::OutOfBounds))
    );
    assert_eq!(
        decode(&mutate64(&bytes, 128, 0), &original, limits()),
        Err(Error::Content(sparse::Error::InvalidEdit))
    );
}
#[test]
fn reordered_overlapping_and_cumulatively_oversized_edits_refuse() {
    let original = vec![0; 4096];
    let pages = SparsePages::build(
        &original,
        vec![
            FileEdit {
                offset: 10,
                expected: vec![0; 2],
                replacement: vec![1; 2],
            },
            FileEdit {
                offset: 20,
                expected: vec![0; 2],
                replacement: vec![2; 2],
            },
        ],
        limits().content,
    )
    .unwrap();
    let bytes = encode(&pages, limits()).unwrap();
    for offset in [0, 10, 11] {
        assert_eq!(
            decode(&mutate64(&bytes, 140, offset), &original, limits()),
            Err(Error::Content(sparse::Error::OverlapOrOrder))
        );
    }
    let bounded = Limits {
        content: sparse::Limits {
            edited_bytes: 3,
            ..limits().content
        },
        ..limits()
    };
    assert_eq!(
        decode(&bytes, &original, bounded),
        Err(Error::Envelope(crate::Error::ResourceLimit))
    );
}
