//! Pure prospective geometry/accounting controls. No row authenticates native
//! NX bytes, an actual mapping replacement, source completeness or publication.
use super::*;
use crate::lifecycle::{LifecycleRegistry, Limits};
use liteinst_admission::Generation;
use liteinst_admission::scan::{Obligation, Verdict};

const BASE: u64 = 0x400000;
const TARGET: u64 = 0x800000;
fn until() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn fixture(target_pages: usize, dense_heads: bool) -> Domain {
    let mut facts = vec![ImageFacts {
        start: BASE,
        bytes: vec![0x90; PAGE as usize],
        heads: BTreeSet::from([BASE]),
    }];
    if target_pages != 0 {
        let mut bytes = vec![0x90; target_pages * PAGE as usize];
        let heads = if dense_heads {
            (TARGET..TARGET + bytes.len() as u64).collect()
        } else {
            // One declared MOV contains both a declared prefixed selected
            // decode and an embedded bare decode, across the page boundary.
            let offset = PAGE as usize - 3;
            bytes[offset..offset + 5].copy_from_slice(&[0xb8, 0x66, 0x0f, 0xa2, 0]);
            BTreeSet::from([TARGET + offset as u64, TARGET + offset as u64 + 1])
        };
        facts.push(ImageFacts {
            start: TARGET,
            bytes,
            heads,
        });
    }
    let maps = facts
        .iter()
        .map(|fact| MemoryMapping {
            start: fact.start,
            end: fact.start + fact.bytes.len() as u64,
            permissions: "r-xp".into(),
            file_offset: 0,
            pathname: None,
        })
        .collect();
    let originals = facts.clone();
    Domain::new(
        facts,
        maps,
        &DynamicAdmissionOptions {
            backend: DynamicAdmissionBackend::CoverageTrap(TrapCoverageBudget::default()),
            ..DynamicAdmissionOptions::default()
        },
        until(),
        |start, len| {
            let original = originals.iter().find(|fact| fact.start == start).unwrap();
            assert_eq!(len, original.bytes.len());
            Ok(original.bytes.clone())
        },
    )
    .unwrap()
}
fn componentwise(actual: BudgetCharge, bound: BudgetCharge) {
    assert!(
        actual.source_fact_bytes <= bound.source_fact_bytes,
        "actual={actual:?}, bound={bound:?}"
    );
    assert!(actual.reports <= bound.reports);
    assert!(actual.epochs <= bound.epochs);
    assert!(actual.origins <= bound.origins);
    assert!(actual.witnesses <= bound.witnesses);
    assert!(actual.plan_history <= bound.plan_history);
}
fn census(limits: census::Limits) -> ResumeCensus {
    let registry = LifecycleRegistry::new_after_exec_syscall_exit(
        Limits {
            tasks: 1,
            processes: 1,
            address_spaces: 1,
            obligations: 8,
        },
        101,
        BASE,
    )
    .unwrap();
    ResumeCensus::new(
        91,
        registry.task(registry.root_task()).unwrap().address_space,
        0,
        limits,
    )
    .unwrap()
}

#[test]
fn dense_whole_page_and_cross_page_original_plans_fit_full_prospective_geometry() {
    let original = fixture(0, false);
    for (pages, dense) in [(1, true), (2, false)] {
        let candidate = fixture(pages, dense);
        let range_bytes = pages * PAGE as usize;
        let plan = candidate.plan(TARGET, until()).unwrap();
        if dense {
            assert_eq!(candidate.images[1].entries.heads().len(), PAGE as usize);
            assert!(
                plan.reports()
                    .iter()
                    .all(|report| report.candidates().is_empty())
            );
        } else {
            assert_eq!(plan.reports().len(), 2);
            assert_eq!(
                plan.reports()
                    .iter()
                    .map(|report| report.candidates().len())
                    .sum::<usize>(),
                4
            );
            assert!(
                plan.reports()
                    .iter()
                    .all(|report| report.verdict() == Verdict::Refused)
            );
            assert!(plan.reports().iter().any(|report| {
                report
                    .obligations()
                    .iter()
                    .any(|obligation| matches!(obligation, Obligation::EmbeddedCandidate(_)))
            }));
            assert_eq!(plan.guards().len(), 3);
        }
        let bound = source_budget(
            &original,
            3,
            MappingSourceShape::MayAcquireRx { range_bytes },
        )
        .unwrap();
        componentwise(actual_plan_charge(&plan, 3).unwrap(), bound.publication);
        // Independent actual immutable staging, including all descriptor and
        // source copies. Old identity is irrelevant to this pure byte bound;
        // the separate staging tests require unchanged identity in production.
        let projections = candidate
            .images
            .iter()
            .map(|image| census::Projection {
                mapping: image.snapshot.mapping,
                generation: Generation(1),
                scope: image.snapshot.range(),
                origins: Vec::new(),
                resumes: BTreeMap::new(),
            })
            .collect::<Vec<_>>();
        let images = candidate.projected_images(1, &projections).unwrap();
        let staged = original
            .stage_replacement(images, candidate.original_executables.clone(), until())
            .unwrap();
        assert!(mapping_staged_storage_bytes(&staged).unwrap() <= bound.storage_bytes);
        assert!(
            staged.catalog_bytes()
                >= candidate
                    .images
                    .iter()
                    .map(|image| image.snapshot.bytes().len())
                    .sum::<usize>()
        );
        let old = plan_upper_bound(&original, 3, 0).unwrap();
        let whole = combine(old, bound.charge().unwrap()).unwrap();
        assert_eq!(whole.reports, old.reports + bound.publication.reports);
        assert_eq!(
            whole.plan_history,
            old.plan_history + bound.publication.plan_history
        );
        assert_eq!(
            whole.source_fact_bytes,
            old.source_fact_bytes + bound.storage_bytes + bound.publication.source_fact_bytes
        );
    }
}

#[test]
fn prospective_bound_rejects_invalid_overflow_and_reserves_every_dimension_without_refund() {
    let original = fixture(0, false);
    for bytes in [0, 1, PAGE as usize - 1, 65537, usize::MAX] {
        assert!(matches!(
            source_budget(
                &original,
                1,
                MappingSourceShape::MayAcquireRx { range_bytes: bytes }
            ),
            Err(GateError::Refused(
                "mapping source budget requires one complete bounded VMA"
            ))
        ));
    }
    assert!(matches!(
        source_budget(
            &original,
            usize::MAX,
            MappingSourceShape::MayAcquireRx {
                range_bytes: PAGE as usize
            }
        ),
        Err(GateError::Refused(
            "dynamic transition evidence size overflows"
        ))
    ));
    let bound = source_budget(
        &original,
        1,
        MappingSourceShape::MayAcquireRx {
            range_bytes: PAGE as usize,
        },
    )
    .unwrap()
    .charge()
    .unwrap();
    let old =
        effect_charge_with_payload(StatePayload::maximum(), &original, 1, 1, 1, true, 1).unwrap();
    let whole = combine(old, bound).unwrap();
    assert_eq!(whole.epochs, old.epochs);
    assert_eq!(whole.origins, old.origins);
    assert_eq!(whole.witnesses, old.witnesses);
    let limits = census::Limits {
        epochs: whole.epochs + 1,
        source_fact_bytes: whole.source_fact_bytes,
        reports: whole.reports,
        origins: whole.origins,
        witnesses: whole.witnesses,
        plan_history: whole.plan_history,
    };
    let mut exact = census(limits);
    let reservation = exact.reserve(whole).unwrap();
    let charged = exact.charged();
    exact.finish_reservation(reservation).unwrap();
    assert_eq!(exact.charged(), charged);
    assert_eq!(exact.used().source_fact_bytes, 0);
    for dimension in 0..3 {
        let mut short = limits;
        match dimension {
            0 => short.source_fact_bytes -= 1,
            1 => short.reports -= 1,
            2 => short.plan_history -= 1,
            _ => unreachable!(),
        }
        let mut model = census(short);
        let before = (
            model.charged(),
            model.used(),
            model.rows().cloned().collect::<Vec<_>>(),
            model.history().to_vec(),
        );
        assert!(matches!(
            model.reserve(whole),
            Err(census::CensusError::Capacity)
        ));
        assert_eq!(
            (
                model.charged(),
                model.used(),
                model.rows().cloned().collect::<Vec<_>>(),
                model.history().to_vec()
            ),
            before
        );
    }
    assert_eq!(
        DynamicAdmissionLimits::default().source_fact_bytes,
        64 * 1024 * 1024
    );
    assert_eq!(StatePayload::maximum().xstate_bytes, 64 * 1024);
}

#[test]
fn no_capture_retains_whole_source_storage_and_old_plan_bound_for_same_or_subset_sets() {
    let original = fixture(2, false);
    let bound = source_budget(&original, 3, MappingSourceShape::RetainedOnly).unwrap();
    assert_eq!(bound.publication, BudgetCharge::default());
    assert_eq!(
        bound.charge().unwrap(),
        BudgetCharge {
            source_fact_bytes: bound.storage_bytes,
            ..BudgetCharge::default()
        }
    );
    let old_plan_bound = plan_upper_bound(&original, 3, 0).unwrap();
    for keep_target in [true, false] {
        let projections = original
            .images
            .iter()
            .map(|image| census::Projection {
                mapping: image.snapshot.mapping,
                generation: Generation(1),
                scope: image.snapshot.range(),
                origins: Vec::new(),
                resumes: BTreeMap::new(),
            })
            .collect::<Vec<_>>();
        let mut images = original.projected_images(1, &projections).unwrap();
        let mut maps = original.original_executables.clone();
        if !keep_target {
            images.retain(|image| image.snapshot.range().start() == BASE);
            maps.retain(|mapping| mapping.start == BASE);
        }
        let staged = original.stage_replacement(images, maps, until()).unwrap();
        assert_eq!(staged.images().len(), if keep_target { 2 } else { 1 });
        assert!(mapping_staged_storage_bytes(&staged).unwrap() <= bound.storage_bytes);
        // A separately constructed planner uses the exact surviving bytes and
        // declared heads. No fake native commit or old plan is reused here.
        let candidate = fixture(if keep_target { 2 } else { 0 }, false);
        for page in candidate.pages.keys() {
            let plan = candidate.plan(*page, until()).unwrap();
            componentwise(actual_plan_charge(&plan, 3).unwrap(), old_plan_bound);
        }
    }
    assert!(matches!(
        source_budget(&original, usize::MAX, MappingSourceShape::RetainedOnly),
        Err(GateError::Refused(
            "dynamic transition evidence size overflows"
        ))
    ));
    assert_eq!(
        DynamicAdmissionLimits::default().source_fact_bytes,
        64 * 1024 * 1024
    );
}
