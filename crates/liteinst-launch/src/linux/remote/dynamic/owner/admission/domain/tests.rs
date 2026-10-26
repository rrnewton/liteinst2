//! Pure Domain-history controls over independently supplied literal source.
//! No fixture runs, holds a task, writes native code or grants executable
//! permission. The model helpers below deliberately construct retained records;
//! their success is not a native publication or mapping-replacement witness.
use super::*;
use crate::gate::ImageFacts;
use liteinst_admission::entries::{EntryProvenance, LegalEntrySet};
use liteinst_admission::scan::SiteClass;

const BASE: u64 = 0x40_0000;
const CALL: u64 = BASE + 8;
const RETURN: u64 = BASE + 13;
const SELECTED: u64 = BASE + 32;
const SPARE: u64 = BASE + 48;
const UNCENSUSED: u64 = BASE + 2 * PAGE;

fn until() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

fn literal_bytes() -> Vec<u8> {
    let mut bytes = vec![0xcc; PAGE as usize];
    bytes[8..13].copy_from_slice(&[0xe8, 0x13, 0, 0, 0]);
    bytes[13] = 0x90;
    bytes[32..34].copy_from_slice(&[0x0f, 0xa2]);
    bytes[48..50].copy_from_slice(&[0x90, 0x90]);
    bytes
}

fn fixture(uncensused: bool) -> Domain {
    let bytes = literal_bytes();
    let mut mappings = vec![MemoryMapping {
        start: BASE,
        end: BASE + PAGE,
        permissions: "r-xp".into(),
        file_offset: 0,
        pathname: None,
    }];
    if uncensused {
        mappings.push(MemoryMapping {
            start: UNCENSUSED,
            end: UNCENSUSED + PAGE,
            permissions: "r-xp".into(),
            file_offset: PAGE,
            pathname: Some("uncensused-model-image".into()),
        });
    }
    Domain::new(
        vec![ImageFacts {
            start: BASE,
            bytes: bytes.clone(),
            heads: BTreeSet::from([CALL, RETURN, SELECTED, SPARE]),
        }],
        mappings,
        &DynamicAdmissionOptions {
            // The CALL's potential return intersects selected publication.
            // Use the existing explicit coverage proof; strict mode's original
            // CALL refusal remains required and is not bypassed by this model.
            backend: DynamicAdmissionBackend::CoverageTrap(TrapCoverageBudget::default()),
            ..DynamicAdmissionOptions::default()
        },
        until(),
        |address, length| {
            assert_eq!(address, BASE);
            assert_eq!(length, PAGE as usize);
            Ok(bytes.clone())
        },
    )
    .unwrap()
}

fn assert_refused(result: Result<(), GateError>, expected: &str) {
    match result {
        Err(GateError::Refused(reason)) => assert_eq!(reason, expected),
        other => panic!("expected exact refusal {expected:?}, got {other:?}"),
    }
}

fn with_bytes(snapshot: &Snapshot, bytes: Vec<u8>) -> Snapshot {
    Snapshot::new(
        snapshot.mapping,
        snapshot.generation,
        snapshot.range().start(),
        bytes,
        snapshot.before,
        snapshot.after,
        snapshot.writes,
    )
    .unwrap()
}

fn entries_with(
    entries: &LegalEntrySet,
    generation: Generation,
    version: u64,
    heads: Vec<(u64, EntryProvenance)>,
) -> LegalEntrySet {
    LegalEntrySet::new(
        entries.mapping(),
        generation,
        version,
        entries.scope(),
        entries.completeness(),
        heads,
        entries
            .resumes()
            .iter()
            .flat_map(|(&pc, kinds)| kinds.iter().map(move |&kind| (pc, kind))),
    )
    .unwrap()
}

fn heads(entries: &LegalEntrySet) -> Vec<(u64, EntryProvenance)> {
    entries
        .heads()
        .iter()
        .flat_map(|(&pc, kinds)| kinds.iter().map(move |&kind| (pc, kind)))
        .collect()
}

// Models only the recorded outcome of publication, not the unsafe native
// preconditions required by a real caller of record_installed.
fn model_install(domain: &mut Domain) {
    let pending = domain.plan(BASE, until()).unwrap();
    assert_eq!(pending.pages(), &BTreeSet::from([BASE]));
    assert_eq!(pending.guards().len(), 1);
    assert_eq!(pending.guards()[&SELECTED].original_bytes(), [0x0f, 0xa2]);
    assert_eq!(pending.planned_calls().len(), 1);
    let call = pending.planned_calls()[0].clone();
    assert_eq!(call.call_address, CALL);
    assert_eq!(call.call_bytes, [0xe8, 0x13, 0, 0, 0]);
    assert_eq!(call.return_pc, RETURN);
    domain.record_callers(&pending).unwrap();
    let id = domain.allocate_plan_id().unwrap();
    let route = super::super::routes::ResolvedRoute {
        origin: super::super::routes::RouteOrigin::Call {
            obligation: call,
            planned: true,
        },
        pc: RETURN,
        // This expectation comes from the literal fixture, not a production
        // decode or the returned plan.
        original: vec![0x90],
        route: super::super::routes::Route::OriginalUnchanged,
        generation: domain.generation,
        entry_version: domain.entry_version,
        plan: id,
    };
    domain.record_installed(id, pending, vec![route]).unwrap();
    assert_eq!(
        domain.plans.last().unwrap().source_binding,
        domain.source_binding
    );
    domain.audit_history().unwrap();
}

// The real path requires revoked native bytes, sync and a new held-mm proof.
// This helper constructs only the analogous pure retained history.
fn model_retire(domain: &mut Domain) {
    let next = domain.generation.checked_add(1).unwrap();
    let projections = domain
        .images
        .iter()
        .map(|image| super::super::census::Projection {
            mapping: image.snapshot.mapping,
            generation: Generation(next),
            scope: image.snapshot.range(),
            origins: Vec::new(),
            resumes: image.entries.resumes().clone(),
        })
        .collect::<Vec<_>>();
    let images = domain.projected_images(next, &projections).unwrap();
    domain.generations.push(RetiredGeneration {
        generation: domain.generation,
        entry_version: domain.entry_version,
        source_binding: domain.source_binding,
        executable_pages: domain.executable_pages(),
        guards: std::mem::take(&mut domain.guards),
        sites: std::mem::take(&mut domain.sites),
    });
    domain
        .pages
        .values_mut()
        .for_each(|executable| *executable = false);
    domain.images = images;
    domain.generation = next;
    domain.entry_version = next;
    domain.audit_history().unwrap();
}

fn history() -> Domain {
    let mut domain = fixture(false);
    model_install(&mut domain);
    model_retire(&mut domain);
    domain
}

#[derive(Clone, Copy)]
enum FactChange {
    NoncandidateByte,
    HeadAddress,
    HeadProvenance,
    PolicyVersion,
    PolicySelection,
}

// Create an actually planned, internally coherent alternate report without
// weakening Domain::validate_plan or giving the pure planner native authority.
// Its identity/shape is deliberately the original identity/shape: the audit
// must compare full source facts, not fail merely on a newly minted MappingId.
fn alternate_pending(domain: &Domain, change: FactChange) -> PendingAdmission {
    let original = &domain.plans[0].pending;
    let mut image = Image {
        mapping: domain.images[0].mapping.clone(),
        snapshot: original.snapshot().clone(),
        entries: original.entries().clone(),
        core_identity: domain.images[0].core_identity,
    };
    image.core_identity.generation = original.snapshot().generation.0;
    let mut policy = original.policy().clone();
    match change {
        FactChange::NoncandidateByte => {
            let mut bytes = image.snapshot.bytes().to_vec();
            bytes[96] = 0x90;
            image.snapshot = with_bytes(&image.snapshot, bytes);
        }
        FactChange::HeadAddress | FactChange::HeadProvenance => {
            let mut changed = heads(&image.entries);
            if matches!(change, FactChange::HeadAddress) {
                changed.iter_mut().find(|(pc, _)| *pc == SPARE).unwrap().0 += 1;
            } else {
                changed.push((SPARE, EntryProvenance::Function));
            }
            image.entries = entries_with(
                &image.entries,
                image.entries.generation(),
                image.entries.version(),
                changed,
            );
        }
        FactChange::PolicyVersion => policy.version = policy.version.checked_add(1).unwrap(),
        FactChange::PolicySelection => assert!(policy.selected.remove(&SiteClass::Rdtscp)),
    }
    let oracle = GateOracle::new(Default::default()).unwrap();
    let returns = CallReturnLedger::new();
    let installed = BTreeMap::new();
    let alternate = planning::prepare_covered_admission_pending_resumes(
        (&image, &oracle),
        BASE,
        &policy,
        &returns,
        (&installed, TrapCoverageBudget::default()),
        until(),
    )
    .unwrap();
    assert_eq!(alternate.snapshot().mapping, original.snapshot().mapping);
    assert_eq!(
        alternate.snapshot().generation,
        original.snapshot().generation
    );
    assert_eq!(alternate.snapshot().range(), original.snapshot().range());
    assert_eq!(alternate.pages(), original.pages());
    assert_eq!(alternate.guards(), original.guards());
    assert_eq!(alternate.planned_calls(), original.planned_calls());
    alternate
}

#[test]
fn complete_model_history_retains_independent_source_across_two_epochs() {
    let mut domain = fixture(false);
    let binding = domain.source_binding;
    let original = literal_bytes();
    let retained = domain.resource_basis_bytes();
    for generation in 0..3 {
        assert_eq!(domain.generation, generation);
        model_install(&mut domain);
        if generation < 2 {
            model_retire(&mut domain);
        }
    }
    assert_eq!(domain.plans.len(), 3);
    assert_eq!(domain.generations.len(), 2);
    assert_eq!(domain.resource_basis_bytes(), retained);
    assert_eq!(domain.source_candidate_bound().unwrap(), 1);
    assert_eq!(domain.resource_scan_decoded_starts(), PAGE as usize);
    for (generation, plan) in domain.plans.iter().enumerate() {
        assert_eq!(plan.source_binding, binding);
        assert_eq!(
            plan.pending.snapshot().generation,
            Generation(generation as u64)
        );
        assert_eq!(plan.pending.snapshot().bytes(), original);
        assert_eq!(plan.routes[0].original, [0x90]);
    }
    assert_eq!(domain.returns.obligations().count(), 3);
    domain.audit_retained_history().unwrap();
    domain.audit_history().unwrap();
}

#[test]
fn identical_domains_cannot_exchange_live_plan_or_retired_bindings() {
    for row in 0..5 {
        let mut domain = fixture(false);
        let foreign = fixture(false);
        assert_eq!(
            domain.images[0].snapshot.bytes(),
            foreign.images[0].snapshot.bytes()
        );
        assert_eq!(
            domain.images[0].entries.heads(),
            foreign.images[0].entries.heads()
        );
        assert_eq!(domain.original_executables, foreign.original_executables);
        assert_eq!(domain.policy, foreign.policy);
        assert_ne!(domain.source_binding, foreign.source_binding);
        if row != 4 {
            model_install(&mut domain);
        }
        model_retire(&mut domain);
        model_install(&mut domain);
        let expected = match row {
            0 => {
                domain.source_binding = foreign.source_binding;
                "dynamic retained source binding differs"
            }
            1 | 4 => {
                domain.generations[0].source_binding = foreign.source_binding;
                "dynamic retained source binding differs"
            }
            2 => {
                domain.plans.last_mut().unwrap().source_binding = foreign.source_binding;
                "dynamic retained plan identity is reused or stale"
            }
            3 => {
                domain.generations[0].source_binding = foreign.source_binding;
                domain.plans[0].source_binding = foreign.source_binding;
                "dynamic retained source binding differs"
            }
            _ => unreachable!(),
        };
        assert_refused(domain.audit_history(), expected);
    }
}

#[test]
fn retained_full_facts_refuse_same_shape_forgeries_while_live_bytes_match() {
    for change in [
        FactChange::NoncandidateByte,
        FactChange::HeadAddress,
        FactChange::HeadProvenance,
        FactChange::PolicyVersion,
        FactChange::PolicySelection,
    ] {
        let mut domain = history();
        let live = domain.images[0].snapshot.clone();
        let forged = alternate_pending(&domain, change);
        let original = std::mem::replace(&mut domain.plans[0].pending, forged);
        let expected = if matches!(
            change,
            FactChange::PolicyVersion | FactChange::PolicySelection
        ) {
            "dynamic resource basis identity differs"
        } else {
            "dynamic resource basis original source differs"
        };
        assert_eq!(domain.images[0].snapshot, live);
        assert_eq!(domain.source_candidate_bound().unwrap(), 1);
        assert_refused(domain.audit_retained_history(), expected);
        assert_refused(domain.audit_history(), expected);
        domain.plans[0].pending = original;
        domain.audit_history().unwrap();
    }
}

#[test]
fn retained_audit_does_not_decode_against_mutable_current_images() {
    for row in 0..4 {
        let mut domain = history();
        let expected = match row {
            0 => {
                let mut bytes = domain.images[0].snapshot.bytes().to_vec();
                bytes[32..34].copy_from_slice(&[0x90, 0x90]);
                domain.images[0].snapshot = with_bytes(&domain.images[0].snapshot, bytes);
                assert_eq!(domain.original_decode(SELECTED).unwrap(), [0x90]);
                "dynamic resource basis original source differs"
            }
            1 => {
                domain.images.clear();
                "dynamic resource basis identity differs"
            }
            2 => {
                domain.pages.clear();
                "dynamic retained page inventory differs"
            }
            3 => {
                domain.original_executables.clear();
                "dynamic resource basis mapping inventory differs"
            }
            _ => unreachable!(),
        };
        assert_eq!(
            domain
                .resource_basis
                .original_candidate_decode(domain.source_binding, SELECTED)
                .unwrap(),
            [0x0f, 0xa2]
        );
        assert_eq!(
            domain
                .resource_basis
                .original_decode(domain.source_binding, RETURN)
                .unwrap(),
            [0x90]
        );
        domain.audit_retained_history().unwrap();
        // A valid historical audit grants no live/source/publication authority.
        assert_refused(domain.audit_history(), expected);
    }
}

#[test]
fn forged_plan_and_matching_live_snapshot_cannot_self_authenticate() {
    let mut domain = history();
    let forged = alternate_pending(&domain, FactChange::NoncandidateByte);
    let live = domain.images[0].snapshot.clone();
    domain.images[0].snapshot = with_bytes(&live, forged.snapshot().bytes().to_vec());
    let original = std::mem::replace(&mut domain.plans[0].pending, forged);
    assert_eq!(
        domain.images[0].snapshot.bytes(),
        domain.plans[0].pending.snapshot().bytes()
    );
    assert_eq!(
        domain.plans[0].pending.snapshot().bytes().len(),
        PAGE as usize
    );
    assert_refused(
        domain.audit_retained_history(),
        "dynamic resource basis original source differs",
    );
    assert_refused(
        domain.audit_history(),
        "dynamic resource basis original source differs",
    );
    domain.images[0].snapshot = live;
    domain.plans[0].pending = original;
    domain.audit_history().unwrap();
}

#[test]
fn missing_swapped_duplicate_or_misversioned_epochs_remain_refused() {
    for row in 0..4 {
        let mut domain = history();
        model_install(&mut domain);
        model_retire(&mut domain);
        model_install(&mut domain);
        let expected = match row {
            0 => {
                domain.generations.remove(0);
                "dynamic retained epoch chain is discontinuous"
            }
            1 => {
                domain.generations.swap(0, 1);
                "dynamic retired generation identity differs"
            }
            2 => {
                domain.generations[1].generation = 0;
                "dynamic retired generation identity differs"
            }
            3 => {
                domain.generations[0].entry_version = 1;
                "dynamic retired generation identity differs"
            }
            _ => unreachable!(),
        };
        assert_refused(domain.audit_retained_history(), expected);
        assert_refused(domain.audit_history(), expected);
    }
}

#[test]
fn retained_routes_bind_literal_original_bytes_head_and_epoch() {
    for row in 0..7 {
        let mut domain = history();
        let saved = domain.plans[0].routes[0].clone();
        let route = &mut domain.plans[0].routes[0];
        let expected = match row {
            0 => {
                route.original[0] = 0xcc;
                "dynamic retained route lost its original plan facts"
            }
            1 => {
                route.original.push(0x90);
                "dynamic retained route lost its original plan facts"
            }
            2 => {
                route.pc = SPARE + 1;
                "dynamic continuation is not a declared instruction head"
            }
            3 => {
                route.pc = UNCENSUSED;
                "dynamic continuation has no original image census"
            }
            4 => {
                route.generation += 1;
                "dynamic retained route lost its original plan facts"
            }
            5 => {
                route.entry_version += 1;
                "dynamic retained route lost its original plan facts"
            }
            6 => {
                route.plan += 1;
                "dynamic retained route lost its original plan facts"
            }
            _ => unreachable!(),
        };
        assert_refused(domain.audit_retained_history(), expected);
        domain.plans[0].routes[0] = saved;
        domain.audit_history().unwrap();
    }
}

#[test]
fn retired_guard_site_and_page_inventory_require_complete_matching_history() {
    for row in 0..6 {
        let mut domain = history();
        let expected = match row {
            0 => {
                domain.generations[0].executable_pages.insert(BASE + PAGE);
                "dynamic retired page lost its source identity"
            }
            1 => {
                domain.generations[0].executable_pages.clear();
                "dynamic retired guard lost its source identity"
            }
            2 => {
                domain.plans.clear();
                "dynamic retired guard lost its source identity"
            }
            3 => {
                domain.generations[0]
                    .sites
                    .get_mut(&SELECTED)
                    .unwrap()
                    .class = SiteClass::Rdtsc;
                "dynamic retired selected site differs from its guard"
            }
            4 => {
                let mut site = domain.generations[0].sites[&SELECTED];
                site.address = SPARE;
                domain.generations[0].sites.insert(SPARE, site);
                "dynamic retired selected inventory has an unguarded site"
            }
            5 => {
                let guard = domain.generations[0].guards.remove(&SELECTED).unwrap();
                domain.generations[0].guards.insert(SELECTED + 1, guard);
                "dynamic retired guard lost its source identity"
            }
            _ => unreachable!(),
        };
        assert_refused(domain.audit_retained_history(), expected);
        assert_refused(domain.audit_history(), expected);
    }
}

#[test]
fn current_live_mapping_page_and_epoch_geometry_is_not_a_history_receipt() {
    for row in 0..8 {
        let mut domain = history();
        let expected = match row {
            0 => {
                domain.images[0].mapping.permissions = "r--p".into();
                "dynamic resource basis original source differs"
            }
            1 => {
                domain.original_executables[0].file_offset = PAGE;
                "dynamic resource basis mapping inventory differs"
            }
            2 => {
                domain.original_executables[0].pathname = Some("another-model-image".into());
                "dynamic resource basis mapping inventory differs"
            }
            3 => {
                domain.pages.remove(&BASE);
                "dynamic retained page inventory differs"
            }
            4 => {
                domain.pages.insert(BASE + PAGE, false);
                "dynamic retained page inventory differs"
            }
            5 => {
                let image = &mut domain.images[0];
                image.snapshot.generation = Generation(2);
                image.entries =
                    entries_with(&image.entries, Generation(2), 1, heads(&image.entries));
                image.core_identity.generation = 2;
                "dynamic live source epoch differs"
            }
            6 => {
                let image = &mut domain.images[0];
                image.entries =
                    entries_with(&image.entries, Generation(1), 2, heads(&image.entries));
                "dynamic live source epoch differs"
            }
            7 => {
                domain.images[0].core_identity.generation = 2;
                "dynamic resource basis original source differs"
            }
            _ => unreachable!(),
        };
        domain.audit_retained_history().unwrap();
        assert_refused(domain.audit_history(), expected);
    }
}

#[test]
fn uncensused_pages_and_embedded_candidates_do_not_invent_declared_heads() {
    let mut domain = fixture(true);
    assert_eq!(
        domain.pages,
        BTreeMap::from([(BASE, false), (UNCENSUSED, false)])
    );
    assert_eq!(domain.images.len(), 1);
    model_install(&mut domain);
    model_retire(&mut domain);
    assert!(!domain.pages[&UNCENSUSED]);
    assert_eq!(
        domain.generations[0].executable_pages,
        BTreeSet::from([BASE])
    );
    assert!(
        domain
            .resource_basis
            .contains_page(domain.source_binding, UNCENSUSED)
            .unwrap()
    );
    assert!(
        !domain
            .resource_basis
            .contains_page(domain.source_binding, UNCENSUSED + 1)
            .unwrap()
    );
    assert_refused(
        domain
            .resource_basis
            .original_decode(domain.source_binding, UNCENSUSED)
            .map(|_| ()),
        "dynamic continuation has no original image census",
    );
    assert_refused(
        domain
            .resource_basis
            .original_candidate_decode(domain.source_binding, UNCENSUSED)
            .map(|_| ()),
        "dynamic continuation has no original image census",
    );
    assert_refused(
        domain.plan(UNCENSUSED, until()).map(|_| ()),
        "dynamic continuation has no original image census",
    );
    domain.audit_history().unwrap();

    // RDPID's bare RDSEED suffix is an actual all-start candidate, but is not
    // thereby a declared continuation head. Coverage retains both guards while
    // the bound original-route decoder keeps its stronger head requirement.
    let mut bytes = vec![0xcc; PAGE as usize];
    bytes[32..36].copy_from_slice(&[0xf3, 0x0f, 0xc7, 0xf8]);
    let mut embedded = Domain::new(
        vec![ImageFacts {
            start: BASE,
            bytes: bytes.clone(),
            heads: BTreeSet::from([SELECTED]),
        }],
        vec![MemoryMapping {
            start: BASE,
            end: BASE + PAGE,
            permissions: "r-xp".into(),
            file_offset: 0,
            pathname: None,
        }],
        &DynamicAdmissionOptions {
            backend: DynamicAdmissionBackend::CoverageTrap(TrapCoverageBudget::default()),
            ..DynamicAdmissionOptions::default()
        },
        until(),
        |address, length| {
            assert_eq!(address, BASE);
            assert_eq!(length, bytes.len());
            Ok(bytes.clone())
        },
    )
    .unwrap();
    let pending = embedded.plan(BASE, until()).unwrap();
    assert_eq!(pending.guards().len(), 2);
    assert_eq!(
        pending.guards()[&(SELECTED + 1)].original_bytes(),
        [0x0f, 0xc7, 0xf8]
    );
    let id = embedded.allocate_plan_id().unwrap();
    embedded.record_installed(id, pending, Vec::new()).unwrap();
    model_retire(&mut embedded);
    assert_eq!(
        embedded
            .resource_basis
            .original_candidate_decode(embedded.source_binding, SELECTED + 1)
            .unwrap(),
        [0x0f, 0xc7, 0xf8]
    );
    assert_refused(
        embedded
            .resource_basis
            .original_decode(embedded.source_binding, SELECTED + 1)
            .map(|_| ()),
        "dynamic continuation is not a declared instruction head",
    );
    embedded.audit_history().unwrap();
}

// Replacement controls below are pure source-history models. In particular,
// preserving a CALL record while removing its target is NOT native permission
// to do so: the root mapping witness must refuse that affected live obligation.
fn model_revoke_for_replacement(domain: &mut Domain) {
    domain.generations.push(RetiredGeneration {
        generation: domain.generation,
        entry_version: domain.entry_version,
        source_binding: domain.source_binding,
        executable_pages: domain.executable_pages(),
        guards: std::mem::take(&mut domain.guards),
        sites: std::mem::take(&mut domain.sites),
    });
    domain
        .pages
        .values_mut()
        .for_each(|executable| *executable = false);
}

fn replacement_source(domain: &Domain) -> (Vec<Image>, Vec<MemoryMapping>) {
    let generation = domain.generation.checked_add(1).unwrap();
    let mut core_identity = planning::new_core_identity().unwrap();
    core_identity.generation = generation;
    let mut bytes = literal_bytes();
    bytes[32..34].copy_from_slice(&[0x0f, 0x31]);
    let mapping = MemoryMapping {
        start: BASE,
        end: BASE + PAGE,
        permissions: "r-xp".into(),
        file_offset: 0,
        pathname: None,
    };
    let snapshot = Snapshot::new(
        liteinst_admission::MappingId(core_identity.mapping),
        Generation(generation),
        BASE,
        bytes,
        liteinst_admission::scan::Boundary::NonExecutable,
        liteinst_admission::scan::Boundary::NonExecutable,
        liteinst_admission::scan::WriteControl::Owned,
    )
    .unwrap();
    let entries = LegalEntrySet::new(
        snapshot.mapping,
        snapshot.generation,
        domain.entry_version.checked_add(1).unwrap(),
        snapshot.range(),
        liteinst_admission::entries::Completeness::AllInstructionHeads,
        [CALL, RETURN, SELECTED, SPARE]
            .into_iter()
            .map(|pc| (pc, EntryProvenance::VerifiedInstruction)),
        [],
    )
    .unwrap();
    (
        vec![Image {
            mapping: mapping.clone(),
            snapshot,
            entries,
            core_identity,
        }],
        vec![mapping],
    )
}

#[test]
fn replacement_model_retains_old_plan_guards_routes_and_calls_after_remove_and_reuse() {
    let mut domain = fixture(false);
    model_install(&mut domain);
    let old_binding = domain.source_binding;
    let old_mapping = domain.images[0].snapshot.mapping;
    let calls = domain.returns.obligations().cloned().collect::<Vec<_>>();
    assert_eq!(calls.len(), 1);
    domain.reserve_replacement_catalog_slot().unwrap();
    let removed = domain
        .stage_replacement(Vec::new(), Vec::new(), until())
        .unwrap();
    let removed_binding = removed.identity().new_binding;
    let retained_before = domain.resource_basis_bytes();
    let removal_bytes = removed.catalog_bytes();
    model_revoke_for_replacement(&mut domain);
    domain.commit_replacement_model(removed).unwrap();
    assert!(domain.images.is_empty());
    assert!(domain.pages.is_empty());
    assert_eq!(domain.generation, 1);
    assert_eq!(domain.source_binding, removed_binding);
    assert_eq!(
        domain.resource_basis_bytes(),
        retained_before + removal_bytes
    );
    assert_eq!(
        domain.returns.obligations().cloned().collect::<Vec<_>>(),
        calls
    );
    assert_eq!(
        domain
            .resource_basis
            .original_decode(old_binding, SELECTED)
            .unwrap(),
        [0x0f, 0xa2]
    );
    assert!(
        !domain
            .resource_basis
            .contains_page(removed_binding, BASE)
            .unwrap()
    );
    domain.audit_history().unwrap();

    let (images, maps) = replacement_source(&domain);
    assert_ne!(images[0].snapshot.mapping, old_mapping);
    domain.reserve_replacement_catalog_slot().unwrap();
    let reused = domain.stage_replacement(images, maps, until()).unwrap();
    let reused_binding = reused.identity().new_binding;
    assert_ne!(reused_binding, old_binding);
    let reuse_bytes = reused.catalog_bytes();
    model_revoke_for_replacement(&mut domain);
    domain.commit_replacement_model(reused).unwrap();
    assert_eq!(domain.generation, 2);
    assert_eq!(domain.entry_version, 2);
    assert_eq!(domain.source_binding, reused_binding);
    assert_eq!(domain.pages, BTreeMap::from([(BASE, false)]));
    assert_eq!(domain.original_decode(SELECTED).unwrap(), [0x0f, 0x31]);
    assert_eq!(
        domain
            .resource_basis
            .original_decode(old_binding, SELECTED)
            .unwrap(),
        [0x0f, 0xa2]
    );
    assert_eq!(
        domain.resource_basis_bytes(),
        retained_before + removal_bytes + reuse_bytes
    );
    assert_eq!(domain.plans.len(), 1);
    assert_eq!(domain.plans[0].source_binding, old_binding);
    assert_eq!(domain.plans[0].routes[0].original, [0x90]);
    assert_eq!(
        domain.generations[0].guards[&SELECTED].original_bytes(),
        [0x0f, 0xa2]
    );
    assert_eq!(domain.generations[1].source_binding, removed_binding);
    assert_eq!(
        domain.returns.obligations().cloned().collect::<Vec<_>>(),
        calls
    );
    domain.audit_history().unwrap();
}

#[test]
fn replacement_model_requires_exact_revoked_prefix_and_rejects_stale_candidate() {
    let mut domain = fixture(false);
    model_install(&mut domain);
    domain.reserve_replacement_catalog_slot().unwrap();
    let premature = domain
        .stage_replacement(Vec::new(), Vec::new(), until())
        .unwrap();
    let binding = domain.source_binding;
    let retained = domain.resource_basis_bytes();
    assert_refused(
        domain.commit_replacement_model(premature),
        "dynamic replacement does not follow exact revocation",
    );
    assert_eq!(domain.source_binding, binding);
    assert_eq!(domain.resource_basis_bytes(), retained);
    assert!(domain.pages[&BASE]);
    assert_eq!(domain.guards[&SELECTED].original_bytes(), [0x0f, 0xa2]);
    domain.audit_history().unwrap();
    let stale = domain
        .stage_replacement(Vec::new(), Vec::new(), until())
        .unwrap();
    let chosen = domain
        .stage_replacement(Vec::new(), Vec::new(), until())
        .unwrap();
    model_revoke_for_replacement(&mut domain);
    domain.commit_replacement_model(chosen).unwrap();
    let current = domain.source_binding;
    let retained = domain.resource_basis_bytes();
    assert_refused(
        domain.commit_replacement_model(stale),
        "dynamic replacement does not follow exact revocation",
    );
    assert_eq!(domain.source_binding, current);
    assert_eq!(domain.resource_basis_bytes(), retained);
    assert_eq!(domain.generation, 1);
    assert_eq!(domain.generations.len(), 1);
    assert_eq!(domain.plans.len(), 1);
    domain.audit_history().unwrap();
}

#[test]
fn replaced_live_source_does_not_authenticate_altered_historical_plan_or_binding() {
    for wrong_binding in [false, true] {
        let mut domain = fixture(false);
        model_install(&mut domain);
        let changed = alternate_pending(&domain, FactChange::NoncandidateByte);
        let (images, maps) = replacement_source(&domain);
        domain.reserve_replacement_catalog_slot().unwrap();
        let staged = domain.stage_replacement(images, maps, until()).unwrap();
        model_revoke_for_replacement(&mut domain);
        domain.commit_replacement_model(staged).unwrap();
        domain.audit_history().unwrap();
        if wrong_binding {
            domain.plans[0].source_binding = domain.source_binding;
            assert_refused(
                domain.audit_history(),
                "dynamic retired guard lost its source identity",
            );
        } else {
            domain.plans[0].pending = changed;
            assert_refused(
                domain.audit_history(),
                "dynamic resource basis original source differs",
            );
        }
        assert_eq!(domain.images[0].snapshot.bytes()[32..34], [0x0f, 0x31]);
        assert_eq!(domain.returns.obligations().count(), 1);
    }
}

#[test]
fn replacement_keeps_live_source_and_epoch_checks_separate_from_retained_history() {
    for row in 0..4 {
        let mut domain = fixture(false);
        model_install(&mut domain);
        let (images, maps) = replacement_source(&domain);
        domain.reserve_replacement_catalog_slot().unwrap();
        let staged = domain.stage_replacement(images, maps, until()).unwrap();
        model_revoke_for_replacement(&mut domain);
        domain.commit_replacement_model(staged).unwrap();
        let expected = match row {
            0 => {
                let image = &mut domain.images[0];
                let mut bytes = image.snapshot.bytes().to_vec();
                bytes[96] ^= 1;
                image.snapshot = with_bytes(&image.snapshot, bytes);
                "dynamic resource basis original source differs"
            }
            1 => {
                domain.original_executables[0].file_offset = PAGE;
                "dynamic resource basis mapping inventory differs"
            }
            2 => {
                domain.pages.remove(&BASE);
                "dynamic retained page inventory differs"
            }
            _ => {
                domain.images[0].core_identity.generation += 1;
                "dynamic resource basis original source differs"
            }
        };
        domain.audit_retained_history().unwrap();
        assert_refused(domain.audit_history(), expected);
        assert_eq!(
            domain.generations[0].guards[&SELECTED].original_bytes(),
            [0x0f, 0xa2]
        );
        assert_eq!(domain.returns.obligations().count(), 1);
    }
}
