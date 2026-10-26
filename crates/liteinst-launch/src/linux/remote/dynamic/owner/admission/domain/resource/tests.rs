//! Synthetic immutable-source facts only. No test supplies a native hold,
//! mapping replacement witness, permission transition or release authority.
use super::*;
use liteinst_admission::entries::{Completeness, EntryProvenance, ResumeKind};
use liteinst_admission::scan::{Boundary, SiteClass, WriteControl};
use liteinst_admission::{AddressRange, MappingId};
use std::time::Duration;

const BASE: u64 = 0x40_0000;
const UNCENSUSED: u64 = BASE + 8 * PAGE;
const HEAD: u64 = BASE + 32;

fn until() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

fn image(start: u64, mapping_id: u64) -> Image {
    let mut bytes = vec![0x90; PAGE as usize];
    bytes[32..37].copy_from_slice(&[0xb8, 0x0f, 0xa2, 0x00, 0x00]);
    bytes[PAGE as usize - 1] = 0x0f;
    let mapping = MemoryMapping {
        start,
        end: start + PAGE,
        permissions: "r-xp".into(),
        file_offset: 0x1000,
        pathname: Some("/model/original".into()),
    };
    let snapshot = Snapshot::new(
        MappingId(mapping_id),
        Generation(0),
        start,
        bytes,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    let entries = LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        0,
        snapshot.range(),
        Completeness::AllInstructionHeads,
        [(start + 32, EntryProvenance::VerifiedInstruction)],
        [],
    )
    .unwrap();
    Image {
        mapping,
        snapshot,
        entries,
        core_identity: liteinst2::contracts::CodeIdentity {
            source: liteinst2::contracts::SourceIdentity([0x45; 32]),
            mapping: mapping_id,
            generation: 0,
        },
    }
}

fn fixture() -> (Vec<Image>, Vec<MemoryMapping>, Policy) {
    let images = vec![image(BASE, 17)];
    let mappings = vec![
        images[0].mapping.clone(),
        MemoryMapping {
            start: UNCENSUSED,
            end: UNCENSUSED + 2 * PAGE,
            permissions: "r-xp".into(),
            file_offset: 0,
            pathname: Some("/model/uncensused".into()),
        },
    ];
    (images, mappings, Policy::default())
}

fn entries(
    snapshot: &Snapshot,
    version: u64,
    completeness: Completeness,
    heads: &[(u64, EntryProvenance)],
    resumes: &[(u64, ResumeKind)],
) -> LegalEntrySet {
    LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        version,
        snapshot.range(),
        completeness,
        heads.iter().copied(),
        resumes.iter().copied(),
    )
    .unwrap()
}

fn refused<T>(result: Result<T, GateError>, expected: &str) {
    match result {
        Err(GateError::Refused(message)) => assert_eq!(message, expected),
        Err(error) => panic!("wrong refusal category: {error:?}"),
        Ok(_) => panic!("expected exact refusal: {expected}"),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Retained {
    binding: SourceBinding,
    policy: Policy,
    images: Vec<(
        usize,
        liteinst2::contracts::CodeIdentity,
        Snapshot,
        LegalEntrySet,
    )>,
    mappings: Vec<MemoryMapping>,
    candidates: usize,
    decoded_starts: usize,
    retained_bytes: usize,
}

fn retained(basis: &ResourceBasis) -> Retained {
    Retained {
        binding: basis.binding,
        policy: basis.policy.clone(),
        images: basis
            .images
            .iter()
            .map(|image| {
                (
                    image.mapping_index,
                    image.core_identity,
                    image.snapshot.clone(),
                    image.entries.clone(),
                )
            })
            .collect(),
        mappings: basis.original_executables.clone(),
        candidates: basis.candidates,
        decoded_starts: basis.decoded_starts,
        retained_bytes: basis.retained_bytes,
    }
}

#[test]
fn identical_catalogs_still_reject_swapped_opaque_bindings_at_every_lookup() {
    let (images, mappings, policy) = fixture();
    let (one, first) = ResourceBasis::new(&images, &mappings, &policy, until()).unwrap();
    let (two, second) = ResourceBasis::new(&images, &mappings, &policy, until()).unwrap();
    assert_ne!(first, second);
    let before = (retained(&one), retained(&two));
    let pages = planning::initial_pages(&mappings).unwrap();
    for (basis, wrong) in [(&one, second), (&two, first)] {
        let message = "dynamic retained source binding differs";
        refused(basis.validate_binding(wrong), message);
        refused(
            basis.validate_live(wrong, &images, &mappings, &policy),
            message,
        );
        refused(
            basis.candidates(wrong, &images, &mappings, &policy),
            message,
        );
        refused(
            basis.validate_retained(wrong, &images[0].snapshot, &images[0].entries, &policy),
            message,
        );
        refused(basis.validate_pages(wrong, &pages), message);
        refused(basis.contains_page(wrong, BASE), message);
        refused(basis.original_decode(wrong, HEAD), message);
        refused(basis.original_candidate_decode(wrong, HEAD + 1), message);
    }
    assert_eq!((retained(&one), retained(&two)), before);
    assert!(one.validate_binding(first).is_ok());
    assert!(two.validate_binding(second).is_ok());
}

#[test]
fn source_bytes_boundaries_writers_heads_and_identity_are_exact_for_live_and_history() {
    let (mut images, mappings, policy) = fixture();
    let (basis, binding) = ResourceBasis::new(&images, &mappings, &policy, until()).unwrap();
    let before = retained(&basis);
    let original_snapshot = images[0].snapshot.clone();
    let original_entries = images[0].entries.clone();
    for field in 0..13 {
        let mut snapshot = original_snapshot.clone();
        let mut changed_entries = original_entries.clone();
        match field {
            0 => snapshot.mapping = MappingId(99),
            1 => {
                snapshot = Snapshot::new(
                    snapshot.mapping,
                    snapshot.generation,
                    BASE + 1,
                    snapshot.bytes().to_vec(),
                    snapshot.before,
                    snapshot.after,
                    snapshot.writes,
                )
                .unwrap();
            }
            2 => {
                let mut bytes = snapshot.bytes().to_vec();
                bytes[34] ^= 1;
                snapshot = Snapshot::new(
                    snapshot.mapping,
                    snapshot.generation,
                    BASE,
                    bytes,
                    snapshot.before,
                    snapshot.after,
                    snapshot.writes,
                )
                .unwrap();
            }
            3 => snapshot.before = Boundary::Unknown,
            4 => snapshot.after = Boundary::Unknown,
            5 => snapshot.writes = WriteControl::UnownedAlias,
            6 => snapshot.writes = WriteControl::ExternalWriter,
            7 => {
                changed_entries = LegalEntrySet::new(
                    MappingId(99),
                    Generation(0),
                    0,
                    snapshot.range(),
                    Completeness::AllInstructionHeads,
                    [(HEAD, EntryProvenance::VerifiedInstruction)],
                    [],
                )
                .unwrap();
            }
            8 => {
                changed_entries = LegalEntrySet::new(
                    snapshot.mapping,
                    snapshot.generation,
                    0,
                    AddressRange::new(BASE, BASE + PAGE - 1).unwrap(),
                    Completeness::AllInstructionHeads,
                    [(HEAD, EntryProvenance::VerifiedInstruction)],
                    [],
                )
                .unwrap();
            }
            9 => {
                changed_entries = entries(
                    &snapshot,
                    0,
                    Completeness::Partial,
                    &[(HEAD, EntryProvenance::VerifiedInstruction)],
                    &[],
                );
            }
            10 => {
                changed_entries = entries(
                    &snapshot,
                    0,
                    Completeness::AllInstructionHeads,
                    &[
                        (HEAD, EntryProvenance::VerifiedInstruction),
                        (HEAD, EntryProvenance::DirectBranch),
                    ],
                    &[],
                );
            }
            11 => {
                changed_entries = entries(
                    &snapshot,
                    0,
                    Completeness::AllInstructionHeads,
                    &[(HEAD + 1, EntryProvenance::VerifiedInstruction)],
                    &[],
                );
            }
            12 => snapshot.generation = Generation(1), // entries must agree even in a later epoch
            _ => unreachable!(),
        }
        images[0].snapshot = snapshot;
        images[0].entries = changed_entries;
        refused(
            basis.validate_live(binding, &images, &mappings, &policy),
            "dynamic resource basis original source differs",
        );
        refused(
            basis.validate_retained(binding, &images[0].snapshot, &images[0].entries, &policy),
            "dynamic resource basis original source differs",
        );
        assert_eq!(retained(&basis), before);
    }
    images[0].snapshot = original_snapshot;
    images[0].entries = original_entries;
    assert!(
        basis
            .validate_live(binding, &images, &mappings, &policy)
            .is_ok()
    );
    assert!(
        basis
            .validate_retained(binding, &images[0].snapshot, &images[0].entries, &policy)
            .is_ok()
    );
}

#[test]
fn full_original_descriptors_and_policy_cannot_be_rebound_by_matching_pages() {
    let (mut images, mappings, policy) = fixture();
    let (basis, binding) = ResourceBasis::new(&images, &mappings, &policy, until()).unwrap();
    let before = retained(&basis);
    let pages = planning::initial_pages(&mappings).unwrap();
    for index in 0..mappings.len() {
        for field in 0..5 {
            let mut changed = mappings.clone();
            match field {
                0 => changed[index].start += PAGE,
                1 => changed[index].end += PAGE,
                2 => changed[index].permissions = "r--p".into(),
                3 => changed[index].file_offset += PAGE,
                4 => changed[index].pathname = Some("/model/replaced".into()),
                _ => unreachable!(),
            }
            refused(
                basis.validate_live(binding, &images, &changed, &policy),
                "dynamic resource basis mapping inventory differs",
            );
            assert!(basis.validate_pages(binding, &pages).is_ok());
        }
    }
    images[0].mapping.file_offset += 1;
    refused(
        basis.validate_live(binding, &images, &mappings, &policy),
        "dynamic resource basis original source differs",
    );
    images[0].mapping = mappings[0].clone();
    let original_core = images[0].core_identity;
    for field in 0..3 {
        images[0].core_identity = original_core;
        match field {
            0 => images[0].core_identity.source.0[0] ^= 1,
            1 => images[0].core_identity.mapping += 1,
            2 => images[0].core_identity.generation += 1,
            _ => unreachable!(),
        }
        refused(
            basis.validate_live(binding, &images, &mappings, &policy),
            "dynamic resource basis original source differs",
        );
        assert_eq!(retained(&basis), before);
    }
    images[0].core_identity = original_core;
    for changed in [
        Policy {
            version: policy.version + 1,
            selected: policy.selected.clone(),
        },
        Policy {
            version: policy.version,
            selected: BTreeSet::from([SiteClass::Cpuid]),
        },
    ] {
        refused(
            basis.candidates(binding, &images, &mappings, &changed),
            "dynamic resource basis identity differs",
        );
        refused(
            basis.validate_retained(binding, &images[0].snapshot, &images[0].entries, &changed),
            "dynamic resource basis identity differs",
        );
    }
    assert_eq!(retained(&basis), before);
    assert!(
        basis
            .validate_live(binding, &images, &mappings, &policy)
            .is_ok()
    );
}

#[test]
fn coherent_later_epochs_and_resume_projections_keep_the_same_original_source() {
    let (mut images, mappings, policy) = fixture();
    let (basis, binding) = ResourceBasis::new(&images, &mappings, &policy, until()).unwrap();
    let before = retained(&basis);
    let candidates = basis
        .candidates(binding, &images, &mappings, &policy)
        .unwrap();
    assert_eq!(candidates, 1); // the bare CPUID embedded in the original MOV
    assert_eq!(basis.decoded_starts, PAGE as usize);
    for (generation, version) in [(1, 1), (7, 11)] {
        images[0].snapshot.generation = Generation(generation);
        images[0].entries = entries(
            &images[0].snapshot,
            version,
            Completeness::AllInstructionHeads,
            &[(HEAD, EntryProvenance::VerifiedInstruction)],
            &[
                (HEAD, ResumeKind::ParkedThread),
                (HEAD, ResumeKind::SyscallReturn),
            ],
        );
        images[0].core_identity.generation = generation;
        assert!(
            basis
                .validate_live(binding, &images, &mappings, &policy)
                .is_ok()
        );
        assert!(
            basis
                .validate_retained(binding, &images[0].snapshot, &images[0].entries, &policy)
                .is_ok()
        );
        assert_eq!(
            basis
                .candidates(binding, &images, &mappings, &policy)
                .unwrap(),
            candidates
        );
        let report = RuntimeScan.inspect(
            &images[0].snapshot,
            images[0].snapshot.range(),
            &images[0].entries,
            &policy,
        );
        assert!(
            report
                .obligations()
                .contains(&liteinst_admission::scan::Obligation::SavedResume(HEAD))
        );
        assert_eq!(report.verdict(), liteinst_admission::scan::Verdict::Refused);
        assert_eq!(retained(&basis), before);
    }
    // Nonadjacent generations are a valid immutable-source lookup, never a
    // Domain epoch commit. The parent still enforces its exact epoch chain.
}

#[test]
fn historical_candidate_and_head_decodes_use_retained_bytes_with_distinct_contracts() {
    let (mut images, mappings, policy) = fixture();
    let (basis, binding) = ResourceBasis::new(&images, &mappings, &policy, until()).unwrap();
    let before = retained(&basis);
    assert_eq!(
        basis.original_decode(binding, HEAD).unwrap(),
        [0xb8, 0x0f, 0xa2, 0x00, 0x00]
    );
    assert_eq!(
        basis.original_candidate_decode(binding, HEAD + 1).unwrap(),
        [0x0f, 0xa2]
    );
    refused(
        basis.original_decode(binding, HEAD + 1),
        "dynamic continuation is not a declared instruction head",
    );
    refused(
        basis.original_candidate_decode(binding, BASE + PAGE - 1),
        "dynamic continuation lacks a whole original decode",
    );
    assert!(basis.contains_page(binding, UNCENSUSED).unwrap());
    for pc in [BASE - 1, BASE + PAGE, UNCENSUSED] {
        refused(
            basis.original_candidate_decode(binding, pc),
            "dynamic continuation has no original image census",
        );
    }
    let mut changed = images[0].snapshot.bytes().to_vec();
    changed[32..37].fill(0x90);
    images[0].snapshot = Snapshot::new(
        MappingId(17),
        Generation(0),
        BASE,
        changed,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap();
    refused(
        basis.validate_live(binding, &images, &mappings, &policy),
        "dynamic resource basis original source differs",
    );
    // Retained-history lookup is independent of a corrupted mutable live image;
    // the combined owner release path must still reject the live corruption.
    assert_eq!(
        basis.original_decode(binding, HEAD).unwrap(),
        [0xb8, 0x0f, 0xa2, 0x00, 0x00]
    );
    assert_eq!(
        basis.original_candidate_decode(binding, HEAD + 1).unwrap(),
        [0x0f, 0xa2]
    );
    assert_eq!(retained(&basis), before);
}

#[test]
fn retained_page_inventory_includes_uncensused_nx_ranges_and_rejects_equal_count_substitution() {
    let (images, mappings, policy) = fixture();
    let (basis, binding) = ResourceBasis::new(&images, &mappings, &policy, until()).unwrap();
    let before = retained(&basis);
    let pages = planning::initial_pages(&mappings).unwrap();
    assert_eq!(
        pages.keys().copied().collect::<Vec<_>>(),
        [BASE, UNCENSUSED, UNCENSUSED + PAGE]
    );
    assert!(basis.validate_pages(binding, &pages).is_ok());
    let mut changed = pages.clone();
    for value in changed.values_mut() {
        *value = true;
    }
    assert!(basis.validate_pages(binding, &changed).is_ok()); // no permission claim
    changed.remove(&UNCENSUSED);
    refused(
        basis.validate_pages(binding, &changed),
        "dynamic retained page inventory differs",
    );
    changed.insert(BASE + 2 * PAGE, false);
    assert_eq!(changed.len(), pages.len());
    refused(
        basis.validate_pages(binding, &changed),
        "dynamic retained page inventory differs",
    );
    changed.remove(&(BASE + 2 * PAGE));
    changed.insert(UNCENSUSED + 1, false);
    refused(
        basis.validate_pages(binding, &changed),
        "dynamic retained page inventory differs",
    );
    for absent in [BASE + PAGE, UNCENSUSED + 2 * PAGE, BASE + 1, !(PAGE - 1)] {
        assert!(!basis.contains_page(binding, absent).unwrap());
    }
    assert_eq!(retained(&basis), before);
    let (empty, empty_binding) = ResourceBasis::new(&[], &[], &policy, until()).unwrap();
    assert!(empty.validate_binding(empty_binding).is_ok());
    assert!(
        empty
            .validate_pages(empty_binding, &BTreeMap::new())
            .is_ok()
    );
    assert!(!empty.contains_page(empty_binding, BASE).unwrap());
}

#[test]
fn constructor_rejects_ambiguous_source_or_mapping_sets_without_mutating_inputs() {
    let (images, mappings, policy) = fixture();
    let original_mappings = mappings.clone();
    for field in 0..5 {
        let mut changed = mappings.clone();
        match field {
            0 => changed.push(changed[0].clone()),
            1 => changed[1].start = BASE,
            2 => changed[1].end = changed[1].start,
            3 => changed[1].permissions = "rwxp".into(),
            4 => changed[1].start += 1,
            _ => unreachable!(),
        }
        refused(
            ResourceBasis::new(&images, &changed, &policy, until()),
            "dynamic resource basis mapping inventory differs",
        );
    }
    let duplicate = vec![image(BASE, 17), image(BASE + 4 * PAGE, 17)];
    let duplicate_maps = duplicate
        .iter()
        .map(|image| image.mapping.clone())
        .collect::<Vec<_>>();
    refused(
        ResourceBasis::new(&duplicate, &duplicate_maps, &policy, until()),
        "dynamic resource basis original source differs",
    );
    let mut detached = vec![image(BASE, 17)];
    detached[0].mapping.file_offset += 1;
    refused(
        ResourceBasis::new(&detached, &mappings, &policy, until()),
        "dynamic resource basis original source differs",
    );
    detached[0].mapping = mappings[0].clone();
    for field in 0..2 {
        detached[0].core_identity = images[0].core_identity;
        if field == 0 {
            detached[0].core_identity.mapping += 1;
        } else {
            detached[0].core_identity.generation += 1;
        }
        refused(
            ResourceBasis::new(&detached, &mappings, &policy, until()),
            "dynamic resource basis original source differs",
        );
    }
    assert_eq!(mappings, original_mappings);
    assert_eq!(
        images[0].snapshot.bytes()[32..37],
        [0xb8, 0x0f, 0xa2, 0x00, 0x00]
    );
    assert!(ResourceBasis::new(&images, &mappings, &policy, until()).is_ok());
}

#[test]
fn descriptor_storage_is_charged_without_duplicate_page_payloads_or_new_scan_credit() {
    let (images, mut mappings, policy) = fixture();
    let (before, _) = ResourceBasis::new(&images, &mappings, &policy, until()).unwrap();
    let original_bytes = ResourceBasis::mapping_bytes(&mappings).unwrap();
    let added = MemoryMapping {
        start: BASE + 256 * PAGE,
        end: BASE + 512 * PAGE,
        permissions: "r-xp".into(),
        file_offset: 17 * PAGE,
        pathname: Some("/model/extra-uncensused-pages".into()),
    };
    let expected = size_of::<MemoryMapping>()
        + added.permissions.len()
        + added.pathname.as_ref().unwrap().len();
    mappings.push(added);
    let (after, _) = ResourceBasis::new(&images, &mappings, &policy, until()).unwrap();
    assert_eq!(
        ResourceBasis::mapping_bytes(&mappings).unwrap() - original_bytes,
        expected
    );
    assert_eq!(after.retained_bytes - before.retained_bytes, expected);
    assert_eq!(after.decoded_starts, before.decoded_starts);
    assert_eq!(after.candidates, before.candidates);
    assert_eq!(after.images.len(), before.images.len());
    assert_eq!(after.images[0].snapshot, before.images[0].snapshot);
    assert_eq!(after.images[0].entries, before.images[0].entries);
    refused(add(usize::MAX, 1), "dynamic resource basis size overflows");
    refused(
        ResourceBasis::new(
            &images,
            &mappings,
            &policy,
            Instant::now() - Duration::from_secs(1),
        ),
        "whole-event deadline exhausted",
    );
}
