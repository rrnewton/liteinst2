//! Actual held-owner allocation failures. All four methods require native cleanup.
use super::super::storage::native_oracle::{
    OrdinaryAllocationFault as Fault, OrdinaryAllocationSnapshot,
};
use super::*;
use crate::linux::remote::dynamic::{Request as DynamicRequest, Response};
use std::cell::RefCell;
mod observe;

type PanicPayload = Box<dyn std::any::Any + Send>;
type OriginalOutcome = Result<Result<AdmissionReply, GateError>, PanicPayload>;
struct Case {
    original: OriginalOutcome,
    original_pointer: Option<usize>,
    before: OrdinaryAllocationSnapshot,
    before_state: observe::Diagnostic,
    after_state: observe::Diagnostic,
    retained: Option<OrdinaryAllocationSnapshot>,
    transport_failure: Option<PanicPayload>,
    diagnostic_failure: Option<PanicPayload>,
    retention_failure: Option<PanicPayload>,
    cleanup_callback: bool,
}
fn primary(value: &OriginalOutcome, fault: Fault) {
    if fault.unwinds() {
        let payload = match value {
            Err(payload) => payload,
            Ok(_) => panic!("ordinary expected original unwind was not retained"),
        };
        assert_eq!(payload.downcast_ref::<u32>(), Some(&0x4f52_4441));
    } else {
        match value {
            Ok(Err(GateError::Refused(reason))) => assert_eq!(*reason, fault.reason()),
            _ => panic!("ordinary expected original refusal differs"),
        }
    }
}
fn pointer(value: &OriginalOutcome) -> Option<usize> {
    value
        .as_ref()
        .err()
        .map(|p| &**p as *const (dyn std::any::Any + Send) as *const () as usize)
}
fn trajectory(fault: Fault, growth: bool) {
    let code = if growth {
        vec![0x90, 0x90, 0xeb, 0xfe]
    } else {
        vec![0x90, 0xeb, 0xfe]
    };
    let fixture = Fixture::code(&code);
    // Outer-owned expected outcome and diagnostic prefixes survive any action
    // or cleanup assertion. No secondary panic can bypass physical cleanup.
    let record = RefCell::new(None::<Case>);
    let physical = catch_unwind(AssertUnwindSafe(|| {
        with_owner(
            &fixture,
            &code,
            |owner, initial, until, original| {
                let mut expected = begin(owner, initial, until, original);
                if growth {
                    let previous = expected.clone();
                    expected.registers.rip += 1;
                    one(owner, until);
                    check(owner, &previous, &expected, original, 0, until);
                }
                let mut before_state = observe::Diagnostic::allocate(original);
                before_state.capture(owner, until, original);
                before_state.require_baseline(owner, original, &expected);
                let after_state = observe::Diagnostic::allocate(original);
                let before = owner
                    .runtime
                    .as_ref()
                    .unwrap()
                    .test_ordinary_allocation_snapshot();
                owner
                    .runtime
                    .as_mut()
                    .unwrap()
                    .test_ordinary_allocation_fault(fault)
                    .unwrap();
                let mut transport_failure = None;
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    if fault.unwinds() {
                        observe::invoke_unwind(owner, original, until, &mut transport_failure)
                    } else {
                        observe::invoke(owner, until)
                    }
                }));
                let original_pointer = pointer(&outcome);
                *record.borrow_mut() = Some(Case {
                    original: outcome,
                    original_pointer,
                    before,
                    before_state,
                    after_state,
                    retained: None,
                    transport_failure,
                    diagnostic_failure: None,
                    retention_failure: None,
                    cleanup_callback: false,
                });
                let observed = catch_unwind(AssertUnwindSafe(|| {
                    let mut borrowed = record.borrow_mut();
                    let case = borrowed.as_mut().unwrap();
                    primary(&case.original, fault);
                    assert_eq!(pointer(&case.original), case.original_pointer);
                    assert!(owner.cancel.load(Ordering::Acquire));
                    assert_eq!(owner.closing, !fault.unwinds());
                    case.after_state.capture(owner, until, original);
                    case.after_state.require_unchanged(&case.before_state);
                    owner
                        .runtime
                        .as_ref()
                        .unwrap()
                        .test_require_ordinary_failure(&case.before, fault, until);
                    case.retained = Some(
                        owner
                            .runtime
                            .as_ref()
                            .unwrap()
                            .test_ordinary_allocation_snapshot(),
                    );
                }));
                record.borrow_mut().as_mut().unwrap().diagnostic_failure = observed.err();
            },
            |owner, &()| {
                let retained = catch_unwind(AssertUnwindSafe(|| {
                    let borrowed = record.borrow();
                    let case = borrowed.as_ref().unwrap();
                    primary(&case.original, fault);
                    assert_eq!(pointer(&case.original), case.original_pointer);
                    assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                    let expected = case
                        .retained
                        .as_ref()
                        .expect("ordinary partial snapshot absent after diagnosis");
                    assert_eq!(
                        owner
                            .runtime
                            .as_ref()
                            .unwrap()
                            .test_ordinary_allocation_snapshot(),
                        *expected
                    );
                    case.before_state.require_complete();
                    case.after_state.require_complete();
                    case.after_state.require_unchanged(&case.before_state);
                }));
                let mut borrowed = record.borrow_mut();
                let case = borrowed.as_mut().unwrap();
                case.cleanup_callback = true;
                case.retention_failure = retained.err();
            },
        );
    }));
    let case = record.into_inner();
    if let Some(mut case) = case {
        // Check the same original error/payload after the real cleanup path.
        // Secondary failures remain separate and make the control fail.
        let original_check = catch_unwind(AssertUnwindSafe(|| {
            primary(&case.original, fault);
            assert_eq!(pointer(&case.original), case.original_pointer);
        }));
        if let Err(payload) = original_check {
            resume_unwind(payload);
        }
        if let Err(payload) = physical {
            resume_unwind(payload);
        }
        assert!(case.cleanup_callback);
        if let Some(payload) = case.transport_failure.take() {
            resume_unwind(payload);
        }
        if let Some(payload) = case.diagnostic_failure.take() {
            resume_unwind(payload);
        }
        if let Some(payload) = case.retention_failure.take() {
            resume_unwind(payload);
        }
    } else {
        match physical {
            Err(payload) => resume_unwind(payload),
            Ok(()) => panic!("ordinary actual fault record absent"),
        }
    }
}

#[test]
fn runtime_ordinary_allocation_errors_retain_actual_pending_custody() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::allocation::runtime_ordinary_allocation_errors_retain_actual_pending_custody",
        || {
            for ordinal in 0..23 {
                trajectory(Fault::Before(ordinal), false);
            }
        },
    );
}
#[test]
fn runtime_ordinary_allocation_unwinds_retain_actual_pending_custody() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::allocation::runtime_ordinary_allocation_unwinds_retain_actual_pending_custody",
        || {
            for ordinal in 0..23 {
                trajectory(Fault::After(ordinal), false);
            }
        },
    );
}
#[test]
fn runtime_ordinary_transfer_copy_conversion_failures_retain_actual_custody() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::allocation::runtime_ordinary_transfer_copy_conversion_failures_retain_actual_custody",
        || {
            for point in 0..6 {
                for unwind in [false, true] {
                    trajectory(Fault::Boundary { point, unwind }, false);
                }
            }
        },
    );
}
#[test]
fn runtime_ordinary_growth_failures_preserve_prior_completed_custody() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::allocation::runtime_ordinary_growth_failures_preserve_prior_completed_custody",
        || {
            for point in 0..2 {
                for unwind in [false, true] {
                    trajectory(Fault::Boundary { point, unwind }, true);
                }
            }
        },
    );
}
