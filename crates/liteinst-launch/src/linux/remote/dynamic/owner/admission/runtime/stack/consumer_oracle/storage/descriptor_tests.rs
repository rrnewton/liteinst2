//! Actual bookkeeping/allocator controls over supplied descriptive inputs.
//! No Owner, native stop, successful seal or physical-cleanup proof is made.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn consumer_descriptor_plan_counts_actual_reserve_frontiers() {
    let fixture = super::super::artifact::tests::model();
    let plan = super::super::artifact::tests::parse(&fixture).unwrap();
    assert_eq!(plan.len(), 13);
    assert_eq!(
        descriptor_demand(plan.instructions().map(|i| i.kind())).unwrap(),
        ConsumerDescriptorDemand {
            origins: 12,
            history: 90
        }
    );
    let mut kinds = vec![PlannedKind::Ordinary; 30];
    kinds.extend([
        PlannedKind::Syscall { number: 39 },
        PlannedKind::Call,
        PlannedKind::Ret,
        PlannedKind::Syscall { number: 186 },
        PlannedKind::Syscall { number: 231 },
    ]);
    assert_eq!(kinds.len(), PLAN_CAP);
    assert_eq!(
        descriptor_demand(kinds.iter().copied()).unwrap(),
        ConsumerDescriptorDemand {
            origins: 34,
            history: 244
        }
    );
    for malformed in [
        vec![
            PlannedKind::Syscall { number: 39 },
            PlannedKind::Ret,
            PlannedKind::Call,
            PlannedKind::Syscall { number: 186 },
            PlannedKind::Syscall { number: 231 },
        ],
        vec![
            PlannedKind::Syscall { number: 39 },
            PlannedKind::Call,
            PlannedKind::Ret,
            PlannedKind::Syscall { number: 186 },
            PlannedKind::Syscall { number: 60 },
        ],
        vec![
            PlannedKind::Syscall { number: 39 },
            PlannedKind::Call,
            PlannedKind::Ret,
            PlannedKind::Syscall { number: 186 },
        ],
        vec![
            PlannedKind::Syscall { number: 39 },
            PlannedKind::Call,
            PlannedKind::Ret,
            PlannedKind::Syscall { number: 186 },
            PlannedKind::Syscall { number: 231 },
            PlannedKind::Ordinary,
        ],
    ] {
        assert!(descriptor_demand(malformed).is_err());
    }
    kinds.insert(0, PlannedKind::Ordinary);
    assert!(descriptor_demand(kinds).is_err());
}

#[test]
fn consumer_descriptor_q_settles_partial_preallocation_without_refund() {
    for (before, after) in [
        (None, None),
        (Some(0), None),
        (Some(1), None),
        (None, Some(0)),
        (None, Some(1)),
    ] {
        let mut census = PreparedConsumerDescriptors::supplied_model_for_test();
        let mut owner = PreparedConsumerDescriptors::empty();
        owner.set_allocation_fault(before, after);
        owner
            .plan(
                &census,
                ConsumerDescriptorDemand {
                    origins: 11,
                    history: 83,
                },
            )
            .unwrap();
        let bound = owner.reservation_bytes().unwrap();
        let temporary = consumer_descriptor_temporary_bytes().unwrap();
        let reserved = bound.checked_add(temporary).unwrap();
        let mut q = ObserverReservation::empty();
        q.started = true;
        q.before = Some(BudgetObservation::of(&census));
        q.reservation_bytes = Some(reserved);
        q.retained_bound = Some(bound);
        q.temporary_bound = Some(temporary);
        let token = census
            .reserve(BudgetCharge {
                source_fact_bytes: reserved,
                ..BudgetCharge::default()
            })
            .unwrap();
        q.token = Some(token);
        q.reserve = Some(Ok(token));
        let allocation = catch_unwind(AssertUnwindSafe(|| {
            owner.allocate_in_place(&mut census, token)
        }));
        q.allocation_unwound = allocation.is_err();
        if allocation.is_err() {
            owner.mark_aborted();
        }
        q.allocation_complete = matches!(allocation, Ok(Ok(())));
        let actual = owner.allocated_bytes(Some(&census)).unwrap();
        q.measured = Some(Ok(actual));
        let settled = q.settle(&mut census);
        assert!(settled.is_ok());
        assert_eq!(q.debit, Some(Ok(())));
        assert_eq!(q.finish, Some(Ok(())));
        assert_eq!(q.formula_checked, Some(true));
        assert_eq!(
            census.charged().source_fact_bytes,
            q.before.unwrap().charged.source_fact_bytes + reserved
        );
        assert_eq!(
            census.used().source_fact_bytes,
            q.before.unwrap().used.source_fact_bytes + actual
        );
        assert!(actual <= bound);
        let observed = allocation.map(|result| result.map_err(OracleError::Observer));
        let propagated = catch_unwind(AssertUnwindSafe(|| q.propagate(observed, settled)));
        match (before, after) {
            (None, None) => {
                assert!(propagated.unwrap().is_ok());
                q.require_finished().unwrap();
                owner.require_complete(&census).unwrap();
            }
            (Some(_), None) => {
                assert!(matches!(
                    propagated.unwrap(),
                    Err(OracleError::Observer(CensusConsumerError::Allocation))
                ));
                assert!(q.require_finished().is_err());
            }
            (None, Some(_)) => {
                assert_eq!(
                    *propagated.unwrap_err().downcast::<u32>().unwrap(),
                    0x4445_5343
                );
                assert!(q.require_finished().is_err());
            }
            _ => unreachable!(),
        }
        let prefix = owner.retention_snapshot(Some(&census)).unwrap();
        owner.require_retention(Some(&census), &prefix).unwrap();
        let charged = census.charged();
        let later = census.reserve(BudgetCharge::default()).unwrap();
        census.finish_reservation(later).unwrap();
        assert_eq!(census.charged(), charged);
    }
}
