//! Pure immutable catalog controls. commit_model inserts only synthetic facts;
//! it never constructs a native ReplacementCommit or changes real permissions.
use super::*;
use liteinst_admission::MappingId;
use liteinst_admission::entries::{Completeness, EntryProvenance};
use liteinst_admission::scan::{Boundary, WriteControl};
use std::time::Duration;

const BASE: u64 = 0x40_0000;
const HEAD: u64 = BASE + 16;
const EXTRA: u64 = BASE + 4 * PAGE;

fn until() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

fn image(version: u64, opcode: [u8; 2]) -> Image {
    let mut bytes = vec![0x90; PAGE as usize];
    bytes[16..18].copy_from_slice(&opcode);
    let snapshot = Snapshot::new(
        MappingId(100 + version),
        Generation(version),
        BASE,
        bytes,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let entries = LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        version,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        [(HEAD, EntryProvenance::VerifiedInstruction)],
        [],
    )
    .unwrap();
    let mut source = [0; 32];
    source[..8].copy_from_slice(&(100 + version).to_le_bytes());
    Image {
        mapping: MemoryMapping {
            start: BASE,
            end: BASE + PAGE,
            permissions: "r-xp".into(),
            file_offset: 0,
            pathname: None,
        },
        snapshot,
        entries,
        core_identity: liteinst2::contracts::CodeIdentity {
            source: liteinst2::contracts::SourceIdentity(source),
            mapping: 100 + version,
            generation: version,
        },
    }
}

fn identity(old: SourceBinding, new: SourceBinding) -> ReplacementIdentity {
    ReplacementIdentity {
        old_binding: old,
        new_binding: new,
        old_generation: 0,
        new_generation: 1,
        old_entry_version: 0,
        new_entry_version: 1,
    }
}

fn refused<T>(result: Result<T, GateError>, expected: &str) {
    match result {
        Err(GateError::Refused(actual)) => assert_eq!(actual, expected),
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("expected refusal: {expected}"),
    }
}

type CatalogFingerprint = Vec<(SourceBinding, usize, Vec<Vec<u8>>)>;

fn fingerprint(catalog: &SourceCatalog) -> CatalogFingerprint {
    catalog
        .leaves
        .iter()
        .map(|leaf| {
            (
                leaf.binding,
                leaf.retained_bytes,
                leaf.images
                    .iter()
                    .map(|image| image.snapshot.bytes().to_vec())
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn same_address_versions_keep_independent_old_decodes_after_removal_and_reuse() {
    let first = image(0, [0x0f, 0xa2]);
    let policy = Policy::default();
    let (mut catalog, old) = SourceCatalog::new(
        std::slice::from_ref(&first),
        std::slice::from_ref(&first.mapping),
        &policy,
        until(),
    )
    .unwrap();
    catalog.reserve_append().unwrap();
    let removed = catalog.stage(&[], &[], &policy, until()).unwrap();
    let absent = removed.binding();
    catalog
        .commit_model(removed, identity(old, absent))
        .unwrap();
    assert!(!catalog.contains_page(absent, BASE).unwrap());
    assert_eq!(catalog.original_decode(old, HEAD).unwrap(), [0x0f, 0xa2]);
    let second = image(2, [0x0f, 0x31]);
    catalog.reserve_append().unwrap();
    let reused = catalog
        .stage(
            std::slice::from_ref(&second),
            std::slice::from_ref(&second.mapping),
            &policy,
            until(),
        )
        .unwrap();
    let new = reused.binding();
    catalog.commit_model(reused, identity(absent, new)).unwrap();
    assert_ne!(old, new);
    assert_ne!(first.snapshot.mapping, second.snapshot.mapping);
    assert_eq!(catalog.original_decode(old, HEAD).unwrap(), [0x0f, 0xa2]);
    assert_eq!(catalog.original_decode(new, HEAD).unwrap(), [0x0f, 0x31]);
    refused(
        catalog.validate_retained(old, &second.snapshot, &second.entries, &policy),
        "dynamic resource basis original source differs",
    );
    assert_eq!(catalog.leaves.len(), 3);
}

#[test]
fn staged_candidates_reject_foreign_catalog_and_wrong_binding_without_installation() {
    let first = image(0, [0x0f, 0xa2]);
    let policy = Policy::default();
    let construct = || {
        SourceCatalog::new(
            std::slice::from_ref(&first),
            std::slice::from_ref(&first.mapping),
            &policy,
            until(),
        )
        .unwrap()
    };
    let (mut local, binding) = construct();
    let (foreign, foreign_binding) = construct();
    local.reserve_append().unwrap();
    let candidate = foreign.stage(&[], &[], &policy, until()).unwrap();
    let candidate_binding = candidate.binding();
    let before = (
        fingerprint(&local),
        local.retained_bytes(),
        local.decoded_starts(),
    );
    refused(
        local.commit_model(candidate, identity(binding, candidate_binding)),
        "dynamic replacement candidate is stale or foreign",
    );
    assert_eq!(
        (
            fingerprint(&local),
            local.retained_bytes(),
            local.decoded_starts()
        ),
        before
    );
    let candidate = local.stage(&[], &[], &policy, until()).unwrap();
    refused(
        local.commit_model(candidate, identity(binding, foreign_binding)),
        "dynamic replacement candidate is stale or foreign",
    );
    assert_eq!(
        (
            fingerprint(&local),
            local.retained_bytes(),
            local.decoded_starts()
        ),
        before
    );
    refused(
        local.validate_binding(foreign_binding),
        "dynamic retained source binding differs",
    );

    // Exact preallocated-slot refusal, independent of Vec's growth strategy.
    local.leaves = std::mem::take(&mut local.leaves)
        .into_boxed_slice()
        .into_vec();
    assert_eq!(local.leaves.len(), local.leaves.capacity());
    let candidate = local.stage(&[], &[], &policy, until()).unwrap();
    let next = candidate.binding();
    refused(
        local.commit_model(candidate, identity(binding, next)),
        "dynamic replacement catalog slot was not allocated",
    );
    assert_eq!(
        (
            fingerprint(&local),
            local.retained_bytes(),
            local.decoded_starts()
        ),
        before
    );

    local.reserve_append().unwrap();
    local.retained_bytes = usize::MAX;
    let before = (
        fingerprint(&local),
        local.retained_bytes(),
        local.decoded_starts(),
    );
    let candidate = local.stage(&[], &[], &policy, until()).unwrap();
    let next = candidate.binding();
    refused(
        local.commit_model(candidate, identity(binding, next)),
        "dynamic resource basis size overflows",
    );
    assert_eq!(
        (
            fingerprint(&local),
            local.retained_bytes(),
            local.decoded_starts()
        ),
        before
    );
}

#[test]
fn immutable_identity_cannot_be_reused_for_changed_bytes_heads_mapping_or_policy() {
    let original = image(0, [0x0f, 0xa2]);
    let policy = Policy::default();
    let (catalog, _) = SourceCatalog::new(
        std::slice::from_ref(&original),
        std::slice::from_ref(&original.mapping),
        &policy,
        until(),
    )
    .unwrap();
    let before = (
        fingerprint(&catalog),
        catalog.retained_bytes(),
        catalog.decoded_starts(),
    );
    for row in 0..4 {
        let mut changed = image(0, [0x0f, 0xa2]);
        match row {
            0 => {
                let mut bytes = changed.snapshot.bytes().to_vec();
                bytes[64] = 0xcc;
                changed.snapshot = Snapshot::new(
                    changed.snapshot.mapping,
                    Generation(0),
                    BASE,
                    bytes,
                    Boundary::NonExecutable,
                    Boundary::NonExecutable,
                    WriteControl::Owned,
                )
                .unwrap();
            }
            1 => {
                changed.entries = LegalEntrySet::new(
                    changed.snapshot.mapping,
                    Generation(0),
                    0,
                    changed.snapshot.range(),
                    Completeness::AllInstructionHeads,
                    [(HEAD + 2, EntryProvenance::VerifiedInstruction)],
                    [],
                )
                .unwrap()
            }
            2 => changed.mapping.file_offset = PAGE,
            _ => changed.core_identity.source = liteinst2::contracts::SourceIdentity([0x7a; 32]),
        }
        refused(
            catalog.stage(
                std::slice::from_ref(&changed),
                std::slice::from_ref(&changed.mapping),
                &policy,
                until(),
            ),
            "dynamic replacement reuses an immutable source identity",
        );
        assert_eq!(
            (
                fingerprint(&catalog),
                catalog.retained_bytes(),
                catalog.decoded_starts()
            ),
            before
        );
    }
    let mut changed_policy = policy.clone();
    changed_policy.version += 1;
    refused(
        catalog.stage(&[], &[], &changed_policy, until()),
        "dynamic replacement policy differs",
    );
    assert_eq!(
        (
            fingerprint(&catalog),
            catalog.retained_bytes(),
            catalog.decoded_starts()
        ),
        before
    );
}

#[test]
fn every_full_set_copy_is_charged_and_uncensused_inventory_stays_leaf_specific() {
    let original = image(0, [0x0f, 0xa2]);
    let policy = Policy::default();
    let (mut catalog, old) = SourceCatalog::new(
        std::slice::from_ref(&original),
        std::slice::from_ref(&original.mapping),
        &policy,
        until(),
    )
    .unwrap();
    let extra = MemoryMapping {
        start: EXTRA,
        end: EXTRA + PAGE,
        permissions: "r-xp".into(),
        file_offset: 0,
        pathname: None,
    };
    let maps = vec![original.mapping.clone(), extra];
    catalog.reserve_append().unwrap();
    let candidate = catalog
        .stage(std::slice::from_ref(&original), &maps, &policy, until())
        .unwrap();
    let new = candidate.binding();
    let bytes = candidate.retained_bytes();
    assert!(bytes >= PAGE as usize + 2 * size_of::<MemoryMapping>());
    let before = catalog.retained_bytes();
    let scans = catalog.decoded_starts();
    catalog.commit_model(candidate, identity(old, new)).unwrap();
    assert_eq!(catalog.retained_bytes(), before.checked_add(bytes).unwrap());
    assert_eq!(catalog.decoded_starts(), scans + PAGE as usize);
    assert!(!catalog.contains_page(old, EXTRA).unwrap());
    assert!(catalog.contains_page(new, EXTRA).unwrap());
    refused(
        catalog.original_decode(new, EXTRA),
        "dynamic continuation has no original image census",
    );
    let charged = catalog.retained_bytes();
    catalog.reserve_append().unwrap();
    let empty = catalog.stage(&[], &[], &policy, until()).unwrap();
    let empty_binding = empty.binding();
    let empty_bytes = empty.retained_bytes();
    catalog
        .commit_model(empty, identity(new, empty_binding))
        .unwrap();
    assert_eq!(catalog.retained_bytes(), charged + empty_bytes);
    assert_eq!(catalog.original_decode(old, HEAD).unwrap(), [0x0f, 0xa2]);
    assert!(catalog.contains_page(new, EXTRA).unwrap());
}
