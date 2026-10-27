//! Real one-short lifetime reservation, under the unchanged actual Owner route.
use super::*;
use crate::linux::remote::dynamic::owner::admission::census::{
    BudgetCharge, CensusError, Limits, Reservation,
};

type BudgetView = (Limits, BudgetCharge, BudgetCharge, Option<BudgetCharge>);
struct CreditCase {
    expected: TaskStateSnapshot,
    pre_credit_state: observe::Diagnostic,
    before_state: observe::Diagnostic,
    after_state: observe::Diagnostic,
    pre_credit: Option<OrdinaryAllocationSnapshot>,
    pre_budget: Option<BudgetView>,
    next: Option<BudgetCharge>,
    credit: Option<BudgetCharge>,
    reserved: Option<Result<Reservation, CensusError>>,
    finished: Option<Result<(), CensusError>>,
    before: Option<OrdinaryAllocationSnapshot>,
    before_budget: Option<BudgetView>,
    original: Option<OriginalOutcome>,
    retained: Option<OrdinaryAllocationSnapshot>,
    action_failure: Option<PanicPayload>,
    retention_failure: Option<PanicPayload>,
    cleanup_callback: bool,
}
fn require_capacity(outcome: &OriginalOutcome) {
    match outcome {
        Ok(Err(GateError::Refused(reason))) => {
            assert_eq!(*reason, "dynamic continuation lifetime capacity exhausted");
        }
        Ok(Err(error)) => panic!("ordinary one-short original refusal differs: {error:?}"),
        Ok(Ok(_)) => panic!("ordinary one-short unexpectedly succeeded"),
        Err(_) => panic!("ordinary one-short unexpectedly unwound"),
    }
}
fn require_credit(case: &CreditCase, runtime: &RuntimeOwner) {
    let token = case.reserved.unwrap().unwrap();
    let credit = case.credit.unwrap();
    assert_eq!(case.finished, Some(Ok(())));
    runtime.test_require_ordinary_credit(case.pre_credit.as_ref().unwrap(), token, credit);
    let (limits, charged, used, remaining) = case.pre_budget.unwrap();
    let actual = runtime.census.as_ref().unwrap().test_allocation_budget();
    let mut expected_charged = charged;
    expected_charged.source_fact_bytes += credit.source_fact_bytes;
    assert_eq!(remaining, None);
    assert_eq!(actual, (limits, expected_charged, used, None));
    assert_eq!(actual, case.before_budget.unwrap());
    assert_eq!(
        limits.source_fact_bytes - actual.1.source_fact_bytes,
        case.next.unwrap().source_fact_bytes - 1
    );
    assert_eq!(
        runtime
            .census
            .as_ref()
            .unwrap()
            .check_reserved(token, BudgetCharge::default()),
        Err(CensusError::StaleReservation)
    );
}

pub(super) fn trajectory() {
    let code = [0x90, 0xeb, 0xfe];
    let fixture = Fixture::code(&code);
    // Install the diagnostic owner before credit or observation. Its first
    // request/result prefixes and original outcome survive action/cleanup panic.
    let record = RefCell::new(None::<CreditCase>);
    let physical = catch_unwind(AssertUnwindSafe(|| {
        with_owner(
            &fixture,
            &code,
            |owner, initial, until, original| {
                let expected = begin(owner, initial, until, original);
                *record.borrow_mut() = Some(CreditCase {
                    expected,
                    pre_credit_state: observe::Diagnostic::allocate(original),
                    before_state: observe::Diagnostic::allocate(original),
                    after_state: observe::Diagnostic::allocate(original),
                    pre_credit: None,
                    pre_budget: None,
                    next: None,
                    credit: None,
                    reserved: None,
                    finished: None,
                    before: None,
                    before_budget: None,
                    original: None,
                    retained: None,
                    action_failure: None,
                    retention_failure: None,
                    cleanup_callback: false,
                });
                let action = catch_unwind(AssertUnwindSafe(|| {
                    let mut borrowed = record.borrow_mut();
                    let case = borrowed.as_mut().unwrap();
                    case.pre_credit_state.capture(owner, until, original);
                    case.pre_credit_state
                        .require_baseline(owner, original, &case.expected);
                    {
                        let runtime = owner.runtime.as_mut().unwrap();
                        case.pre_credit = Some(runtime.test_ordinary_allocation_snapshot());
                        case.next = Some(runtime.test_next_ordinary_charge(until).unwrap());
                        let census = runtime.census.as_mut().unwrap();
                        let budget = census.test_allocation_budget();
                        case.pre_budget = Some(budget);
                        assert_eq!(budget.0.source_fact_bytes, 64 * 1024 * 1024);
                        assert_eq!(budget.3, None);
                        let next = case.next.unwrap();
                        assert!(next.source_fact_bytes > 1);
                        // Every non-byte axis still admits this exact request.
                        for (charged, added, limit) in [
                            (budget.1.epochs, next.epochs, budget.0.epochs),
                            (budget.1.reports, next.reports, budget.0.reports),
                            (budget.1.origins, next.origins, budget.0.origins),
                            (budget.1.witnesses, next.witnesses, budget.0.witnesses),
                            (
                                budget.1.plan_history,
                                next.plan_history,
                                budget.0.plan_history,
                            ),
                        ] {
                            assert!(charged.checked_add(added).unwrap() <= limit);
                        }
                        let credit = BudgetCharge {
                            source_fact_bytes: budget
                                .0
                                .source_fact_bytes
                                .checked_sub(budget.1.source_fact_bytes)
                                .unwrap()
                                .checked_sub(next.source_fact_bytes - 1)
                                .unwrap(),
                            ..BudgetCharge::default()
                        };
                        assert!(credit.source_fact_bytes > 0);
                        case.credit = Some(credit);
                        let reserved = census.reserve(credit);
                        case.reserved = Some(reserved);
                        let token = reserved.unwrap();
                        let finished = census.finish_reservation(token);
                        case.finished = Some(finished);
                        finished.unwrap();
                        // Refusal baseline is AFTER the deliberate lifetime credit.
                        case.before = Some(runtime.test_ordinary_allocation_snapshot());
                        case.before_budget =
                            Some(runtime.census.as_ref().unwrap().test_allocation_budget());
                        require_credit(case, runtime);
                        assert_eq!(runtime.test_next_ordinary_charge(until).unwrap(), next);
                    }
                    case.before_state.capture(owner, until, original);
                    case.before_state.require_unchanged(&case.pre_credit_state);
                    case.before_state
                        .require_baseline(owner, original, &case.expected);
                    case.original = Some(catch_unwind(AssertUnwindSafe(|| {
                        observe::invoke(owner, until)
                    })));
                    require_capacity(case.original.as_ref().unwrap());
                    assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                    // Preflight may have queried native state; it must not have
                    // released the original instruction or changed its state.
                    case.after_state.capture(owner, until, original);
                    case.after_state.require_unchanged(&case.before_state);
                    let runtime = owner.runtime.as_ref().unwrap();
                    require_credit(case, runtime);
                    case.retained = Some(runtime.test_ordinary_allocation_snapshot());
                    assert_eq!(
                        case.retained.as_ref().unwrap(),
                        case.before.as_ref().unwrap()
                    );
                }));
                record.borrow_mut().as_mut().unwrap().action_failure = action.err();
            },
            |owner, &()| {
                let retained = catch_unwind(AssertUnwindSafe(|| {
                    let borrowed = record.borrow();
                    let case = borrowed.as_ref().unwrap();
                    require_capacity(case.original.as_ref().unwrap());
                    assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                    let runtime = owner.runtime.as_ref().unwrap();
                    require_credit(case, runtime);
                    assert_eq!(
                        runtime.test_ordinary_allocation_snapshot(),
                        *case
                            .retained
                            .as_ref()
                            .expect("one-short retained snapshot absent")
                    );
                    assert_eq!(
                        case.retained.as_ref().unwrap(),
                        case.before.as_ref().unwrap()
                    );
                    case.pre_credit_state.require_complete();
                    case.before_state.require_unchanged(&case.pre_credit_state);
                    case.after_state.require_unchanged(&case.before_state);
                }));
                let mut borrowed = record.borrow_mut();
                let case = borrowed.as_mut().unwrap();
                case.cleanup_callback = true;
                case.retention_failure = retained.err();
            },
        );
    }));
    match record.into_inner() {
        Some(mut case) => {
            // Unexpected real unwind stays primary. Expected refusal remains
            // retained while independent cleanup/diagnostic failures are checked.
            match case.original.take() {
                Some(Err(payload)) => resume_unwind(payload),
                original => case.original = original,
            }
            if let Some(outcome) = &case.original {
                require_capacity(outcome);
            } else if let Some(payload) = case.action_failure.take() {
                resume_unwind(payload);
            }
            if let Err(payload) = physical {
                resume_unwind(payload);
            }
            assert!(case.cleanup_callback);
            if let Some(payload) = case.action_failure.take() {
                resume_unwind(payload);
            }
            if let Some(payload) = case.retention_failure.take() {
                resume_unwind(payload);
            }
            assert!(case.original.is_some());
        }
        None => match physical {
            Err(payload) => resume_unwind(payload),
            Ok(()) => panic!("ordinary one-short evidence absent"),
        },
    }
}
