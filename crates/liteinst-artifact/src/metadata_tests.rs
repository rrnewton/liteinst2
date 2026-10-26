use super::*;

fn policy() -> Compatibility {
    Compatibility {
        planner: 1,
        encoder: 2,
        hook_abi: 3,
        arena: 4,
        target: ContentId([0x55; 32]),
        binding: ContentId([0xaa; 32]),
    }
}
fn sites() -> Vec<Site> {
    vec![
        Site {
            id: 10,
            original_pc: 0x401000,
            file_offset: 0,
            length: 5,
            outcome: Outcome::Rewritten(Tactic::GeneralizedPun),
        },
        Site {
            id: 20,
            original_pc: 0x401100,
            file_offset: 65_536,
            length: 3,
            outcome: Outcome::Refused(11),
        },
    ]
}
fn fixture() -> (Vec<u8>, Metadata) {
    let original: Vec<_> = (0..65_539).map(|i| (i % 251) as u8).collect();
    let metadata = Metadata::new(&original, ContentId([0x33; 32]), policy(), sites()).unwrap();
    (original, metadata)
}
fn resign(bytes: &mut [u8]) {
    let id = checksum(bytes);
    bytes[24..56].copy_from_slice(&id.0);
}

#[test]
fn sha256_known_vectors_and_distinct_original_artifact_identities() {
    assert_eq!(
        ContentId::of(b""),
        ContentId([
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55
        ])
    );
    assert_eq!(
        ContentId::of(b"abc"),
        ContentId([
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ])
    );
    let (original, metadata) = fixture();
    let bytes = metadata.encode(Limits::default()).unwrap();
    assert_eq!(metadata.original_id(), ContentId::of(&original));
    assert_ne!(metadata.original_id(), ContentId::of(&bytes));
    assert_ne!(&bytes[24..56], &metadata.original_id().0);
}

#[test]
fn exact_wire_layout_and_roundtrip_preserve_all_declared_outcomes() {
    let (_, metadata) = fixture();
    let bytes = metadata.encode(Limits::default()).unwrap();
    assert_eq!(bytes.len(), 56 + 176 + 64 + 80);
    assert_eq!(
        &bytes[..24],
        &[
            b'L', b'I', b'2', b'M', b'E', b'T', b'A', 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x40, 1, 0, 0, 0,
            0, 0, 0
        ]
    );
    assert_eq!(&bytes[56..64], &65_539_u64.to_le_bytes());
    assert_eq!(&bytes[208..216], &[0, 0, 1, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[216..224], &2_u64.to_le_bytes());
    assert_eq!(&bytes[224..232], &2_u64.to_le_bytes());
    assert_eq!(
        Metadata::decode(&bytes, &policy(), Limits::default()).unwrap(),
        metadata
    );
    assert!(!metadata.declares_complete_trampoline_coverage());
    metadata
        .verify_selection(ContentId([0x33; 32]), &[10, 20])
        .unwrap();
    for ids in [&[10][..], &[20, 10][..], &[10, 20, 30][..], &[10, 10][..]] {
        assert_eq!(
            metadata.verify_selection(ContentId([0x33; 32]), ids),
            Err(Error::Selection)
        );
    }
    assert_eq!(
        metadata.verify_selection(ContentId([0x34; 32]), &[10, 20]),
        Err(Error::Selection)
    );
}

#[test]
fn every_encoded_byte_is_covered_and_every_truncation_refuses() {
    let (_, metadata) = fixture();
    let bytes = metadata.encode(Limits::default()).unwrap();
    for i in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[i] ^= 1;
        assert!(
            Metadata::decode(&changed, &policy(), Limits::default()).is_err(),
            "byte {i}"
        );
        assert!(
            Metadata::decode(&bytes[..i], &policy(), Limits::default()).is_err(),
            "cut {i}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(
        Metadata::decode(&extra, &policy(), Limits::default()),
        Err(Error::Length)
    );
}

#[test]
fn all_policy_fields_require_exact_equality() {
    let (_, metadata) = fixture();
    let bytes = metadata.encode(Limits::default()).unwrap();
    for index in 0..6 {
        let mut other = policy();
        match index {
            0 => other.planner += 1,
            1 => other.encoder += 1,
            2 => other.hook_abi += 1,
            3 => other.arena += 1,
            4 => other.target.0[31] ^= 1,
            5 => other.binding.0[31] ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            Metadata::decode(&bytes, &other, Limits::default()),
            Err(Error::Incompatible)
        );
    }
}

#[test]
fn complete_chunk_and_full_content_authentication_refuse_stale_or_short_inputs() {
    let (original, metadata) = fixture();
    metadata.verify_original(&original).unwrap();
    assert_eq!(
        metadata.verify_chunk(65_539, 0, &original[..65_536]),
        Ok(0..65_536)
    );
    assert_eq!(
        metadata.verify_chunk(65_539, 1, &original[65_536..]),
        Ok(65_536..65_539)
    );
    assert_eq!(
        metadata.verify_chunk(65_540, 0, &original[..65_536]),
        Err(Error::Stale)
    );
    assert_eq!(
        metadata.verify_chunk(65_539, 2, &[]),
        Err(Error::InvalidRecord)
    );
    assert_eq!(
        metadata.verify_chunk(65_539, 0, &original[..65_535]),
        Err(Error::Stale)
    );
    assert_eq!(
        metadata.verify_chunk(65_539, 1, &original[65_536..65_538]),
        Err(Error::Stale)
    );
    for position in [0, 65_535, 65_536, 65_538] {
        let mut changed = original.clone();
        changed[position] ^= 0xff;
        assert_eq!(metadata.verify_original(&changed), Err(Error::Stale));
        let index = position / CHUNK_BYTES;
        let start = index * CHUNK_BYTES;
        assert_eq!(
            metadata.verify_chunk(
                65_539,
                index,
                &changed[start..(start + CHUNK_BYTES).min(changed.len())]
            ),
            Err(Error::Stale)
        );
    }
}

#[test]
fn resource_counts_are_bounded_before_allocation_and_checked_for_overflow() {
    let (_, metadata) = fixture();
    let bytes = metadata.encode(Limits::default()).unwrap();
    for limit in [
        Limits {
            bytes: bytes.len() - 1,
            ..Limits::default()
        },
        Limits {
            chunks: 1,
            ..Limits::default()
        },
        Limits {
            sites: 1,
            ..Limits::default()
        },
    ] {
        assert_eq!(metadata.encode(limit), Err(Error::ResourceLimit));
        assert_eq!(
            Metadata::decode(&bytes, &policy(), limit),
            Err(Error::ResourceLimit)
        );
    }
    for offset in [216, 224] {
        let mut malformed = bytes.clone();
        malformed[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        resign(&mut malformed);
        assert_eq!(
            Metadata::decode(&malformed, &policy(), Limits::default()),
            Err(Error::ResourceLimit)
        );
    }
    assert_eq!(
        payload_size(
            usize::MAX,
            usize::MAX,
            Limits {
                bytes: usize::MAX,
                chunks: usize::MAX,
                sites: usize::MAX
            }
        ),
        Err(Error::ResourceLimit)
    );
}

#[test]
fn valid_checksums_do_not_hide_unknown_tags_reserved_bytes_or_invalid_ranges() {
    let (_, metadata) = fixture();
    let bytes = metadata.encode(Limits::default()).unwrap();
    let first = 56 + 176 + 64;
    for (offset, value) in [
        (12, 1),
        (212, 1),
        (first + 27, 1),
        (first + 32, 1),
        (first + 25, 9),
        (first + 26, 0),
        (first + 28, 1),
    ] {
        let mut malformed = bytes.clone();
        malformed[offset] = value;
        resign(&mut malformed);
        assert_eq!(
            Metadata::decode(&malformed, &policy(), Limits::default()),
            Err(Error::Format),
            "offset {offset}"
        );
    }
    for (offset, value) in [(first + 24, 0), (first + 24, 16)] {
        let mut malformed = bytes.clone();
        malformed[offset] = value;
        resign(&mut malformed);
        assert_eq!(
            Metadata::decode(&malformed, &policy(), Limits::default()),
            Err(Error::InvalidRecord)
        );
    }
    for offset in [first + 8, first + 16] {
        let mut malformed = bytes.clone();
        malformed[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        resign(&mut malformed);
        assert_eq!(
            Metadata::decode(&malformed, &policy(), Limits::default()),
            Err(Error::InvalidRecord)
        );
    }
    let mut duplicate = bytes.clone();
    duplicate[first + 40..first + 48].copy_from_slice(&10_u64.to_le_bytes());
    resign(&mut duplicate);
    assert_eq!(
        Metadata::decode(&duplicate, &policy(), Limits::default()),
        Err(Error::InvalidRecord)
    );
}

#[test]
fn all_five_tactics_trap_and_refusal_remain_distinct() {
    let outcomes = [
        Outcome::Rewritten(Tactic::Relocation),
        Outcome::Rewritten(Tactic::GeneralizedPun),
        Outcome::Rewritten(Tactic::PrefixedPun),
        Outcome::Rewritten(Tactic::SuccessorEviction),
        Outcome::Rewritten(Tactic::NeighborEviction),
        Outcome::Trap,
        Outcome::Refused(u32::MAX),
    ];
    for outcome in outcomes {
        let site = Site {
            id: 0,
            original_pc: 0,
            file_offset: 0,
            length: 1,
            outcome,
        };
        let metadata = Metadata::new(&[0x90], ContentId([0; 32]), policy(), vec![site]).unwrap();
        let decoded = Metadata::decode(
            &metadata.encode(Limits::default()).unwrap(),
            &policy(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(decoded.sites()[0].outcome, outcome);
        assert_eq!(
            decoded.declares_complete_trampoline_coverage(),
            matches!(outcome, Outcome::Rewritten(_))
        );
    }
}

#[test]
fn empty_content_has_zero_chunks_and_cannot_authorize_any_site_or_chunk() {
    let empty = Metadata::new(&[], ContentId([0; 32]), policy(), vec![]).unwrap();
    let bytes = empty.encode(Limits::default()).unwrap();
    assert_eq!(bytes.len(), 232);
    assert_eq!(
        Metadata::decode(&bytes, &policy(), Limits::default()).unwrap(),
        empty
    );
    assert_eq!(empty.verify_chunk(0, 0, &[]), Err(Error::InvalidRecord));
    empty.verify_original(&[]).unwrap();
    empty.verify_selection(ContentId([0; 32]), &[]).unwrap();
    let site = Site {
        id: 0,
        original_pc: 0,
        file_offset: 0,
        length: 1,
        outcome: Outcome::Trap,
    };
    assert_eq!(
        Metadata::new(&[], ContentId([0; 32]), policy(), vec![site]),
        Err(Error::InvalidRecord)
    );
}
