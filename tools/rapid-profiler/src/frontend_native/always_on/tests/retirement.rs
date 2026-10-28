//! Metadata-only retirement controls; no native return or code-quiescence credit.
use super::*;
use crate::frontend::{ActionKind, RecordObservation};
use crate::generation::{Disposition, Terminal};

#[derive(Debug, Eq, PartialEq)]
struct Slot {
    generation: GenerationId,
    reservations: usize,
    report_ready: bool,
    records: Vec<RecordObservation>,
}
fn slots(c: &IntervalController) -> Vec<Option<Slot>> {
    c.epochs
        .iter()
        .map(|owner| {
            owner.as_ref().map(|owner| Slot {
                generation: owner.generation(),
                reservations: owner.reservations(),
                report_ready: owner.try_report().is_some(),
                records: owner.records().collect(),
            })
        })
        .collect()
}
fn view(c: &IntervalController) -> (ControllerSnapshot, Vec<Option<Slot>>, usize) {
    (
        c.binding.session.snapshot().unwrap(),
        slots(c),
        c.binding.session.retained_epochs(),
    )
}
fn refused(c: &mut IntervalController, e: &IntervalEpoch, cause: Cause) {
    let before = view(c);
    assert!(matches!(c.retire(e), Err(BridgeError { cause: actual }) if actual == cause));
    assert_eq!(view(c), before);
}
fn stale(c: &mut IntervalController, e: &IntervalEpoch) {
    let before = view(c);
    assert_eq!(c.arm(e), Err(error(Cause::Epoch)));
    assert_eq!(view(c), before);
    assert_eq!(c.disarm(e), Err(error(Cause::Epoch)));
    assert_eq!(view(c), before);
    assert!(matches!(
        c.report(e),
        Err(BridgeError {
            cause: Cause::Epoch
        })
    ));
    assert_eq!(view(c), before);
    refused(c, e, Cause::Epoch);
}
fn epoch_limit(c: &mut IntervalController) {
    let before = view(c);
    assert!(matches!(
        c.stage(config(1)),
        Err(BridgeError {
            cause: Cause::Setup(SetupError::EpochLimit)
        })
    ));
    assert_eq!(view(c), before);
}

#[test]
fn retirement_reports_hold_the_last_permit_and_stale_tokens_never_rebind() {
    let mut l = limits();
    l.epochs = 1;
    let mut p = prepared(l);
    let old = p.stage(config(1)).unwrap();
    let (mut c, client) = activate(p);
    let mut s = state(&client);
    c.arm(&old).unwrap();
    enter(&mut s, 0x8000);
    finish(&mut s, 0x8000);
    c.disarm(&old).unwrap();
    let observed = c.report(&old).unwrap().unwrap();
    let expected: Vec<_> = observed.records().collect();
    let history = c.history().unwrap();
    let retired = c.retire(&old).unwrap();
    assert_eq!(retired.generation(), old.generation());
    assert_eq!(retired.records().collect::<Vec<_>>(), expected);
    assert_eq!(c.history().unwrap(), history);
    assert_eq!(c.epochs.len(), 1);
    assert!(c.epochs[0].is_none());
    stale(&mut c, &old);
    epoch_limit(&mut c);
    drop(observed);
    epoch_limit(&mut c);
    assert_eq!(retired.records().collect::<Vec<_>>(), expected);
    drop(retired);
    assert_eq!(c.binding.session.retained_epochs(), 0);
    let fresh = c.stage(config(1)).unwrap();
    assert_eq!(fresh.index, old.index);
    assert_ne!(fresh.generation(), old.generation());
    stale(&mut c, &old);
    c.arm(&fresh).unwrap();
    enter(&mut s, 0x8000);
    finish(&mut s, 0x8000);
    c.disarm(&fresh).unwrap();
    let report = c.retire(&fresh).unwrap();
    assert_eq!(report.records().count(), 1);
    assert_eq!(
        report.records().next().unwrap().record.admission.generation,
        fresh.generation()
    );
    assert_eq!(s.model.completed_sequence(), 2);
}

#[test]
fn retirement_sixteen_epochs_keep_one_registration_ordinals_and_complete_history() {
    let mut l = limits();
    l.epochs = 1;
    let (mut c, client) = activate(prepared(l));
    let mut s = state(&client);
    let mut generations = Vec::new();
    for i in 0..16 {
        let e = c.stage(config(1)).unwrap();
        assert_eq!(e.index, 0);
        assert!(!generations.contains(&e.generation()));
        generations.push(e.generation());
        c.arm(&e).unwrap();
        enter(&mut s, 0x8000);
        finish(&mut s, 0x8000);
        c.disarm(&e).unwrap();
        let report = c.retire(&e).unwrap();
        let records: Vec<_> = report.records().collect();
        assert_eq!(records.len(), 1);
        let admission = records[0].record.admission;
        assert_eq!(
            (
                admission.generation,
                admission.function,
                admission.invocation
            ),
            (e.generation(), FUNCTION, 0)
        );
        assert_eq!(admission.entry_value, i as u64 + 1);
        assert_eq!(
            records[0].record.terminal,
            Some(Terminal::Completed {
                value: 0,
                disposition: Disposition::Retained { rank: 0 }
            })
        );
        let payload = records[0].payload.unwrap();
        assert_eq!(
            (payload.admission, payload.thread, payload.start_sequence),
            (admission, 1, i as u64)
        );
        assert_eq!(
            payload.outcome,
            PayloadOutcome::Completed {
                end: Observation::Value(i as u64 + 1),
                completed_children: 0
            }
        );
        let bits = (((2 * i + 1) as u64) << 13) | 1;
        assert_eq!(
            row(&s, 2 * i),
            [
                1,
                i as u64 + 1,
                0x1000,
                0x8000,
                0x2005,
                e.generation().get(),
                bits
            ]
        );
        assert_eq!(
            row(&s, 2 * i + 1),
            [
                2,
                i as u64 + 1,
                0x1012,
                0x8000,
                0x2005,
                e.generation().get(),
                bits
            ]
        );
        let h = c.history().unwrap();
        assert_eq!(h.actions.len(), 2 * (i + 1));
        assert_eq!(
            (h.actions[2 * i].kind, h.actions[2 * i].generation),
            (ActionKind::Published, e.generation())
        );
        assert_eq!(
            (h.actions[2 * i + 1].kind, h.actions[2 * i + 1].generation),
            (ActionKind::Removed, e.generation())
        );
        drop(report);
        assert_eq!(c.binding.session.retained_epochs(), 0);
    }
    assert_eq!(
        (
            s.registration,
            s.depth,
            s.model.depth(),
            s.next,
            s.journal.used()
        ),
        (1, 0, 0, 17, 32)
    );
    assert_eq!(s.model.completed_sequence(), 16);
    assert_eq!(
        s.totals,
        PairTotals {
            entries: 16,
            returns: 16,
            completed: 16,
            unsampled: 0
        }
    );
    assert!(s.failure.is_none());
}

#[test]
fn retirement_vacancies_are_explicit_and_setup_failure_preserves_them() {
    let mut l = limits();
    l.epochs = 3;
    let mut p = prepared(l);
    let a = p.stage(config(1)).unwrap();
    let b = p.stage(config(1)).unwrap();
    let d = p.stage(config(1)).unwrap();
    let (mut c, _client) = activate(p);
    c.arm(&a).unwrap();
    c.arm(&b).unwrap();
    c.arm(&d).unwrap();
    c.disarm(&d).unwrap();
    for old in [&b, &a, &d] {
        drop(c.retire(old).unwrap());
        let before = view(&c);
        let mut invalid = config(1);
        invalid.max_invocations = l.records_per_epoch + 1;
        assert!(matches!(
            c.stage(invalid),
            Err(BridgeError {
                cause: Cause::Setup(SetupError::InvalidLimits)
            })
        ));
        assert_eq!(view(&c), before);
        let fresh = c.stage(config(1)).unwrap();
        assert_eq!(fresh.index, old.index);
        assert_ne!(fresh.generation(), old.generation());
    }
    assert!(matches!(
        c.stage(config(1)),
        Err(BridgeError {
            cause: Cause::Capacity
        })
    ));
    assert_eq!(c.epochs.len(), 3);
}

#[test]
fn retirement_refuses_open_current_and_outstanding_owners_before_removal() {
    let mut p = prepared(limits());
    let a = p.stage(config(2)).unwrap();
    let b = p.stage(config(2)).unwrap();
    let (mut c, client) = activate(p);
    let mut s = state(&client);
    refused(&mut c, &a, Cause::NotDrained);
    c.arm(&a).unwrap();
    refused(&mut c, &a, Cause::CurrentEpoch);
    enter(&mut s, 0x8000);
    c.arm(&b).unwrap();
    refused(&mut c, &a, Cause::NotDrained);
    finish(&mut s, 0x8000);
    let report = c.retire(&a).unwrap();
    assert_eq!(
        report.records().next().unwrap().record.admission.generation,
        a.generation()
    );
    assert_eq!(c.history().unwrap().current, Some(b.generation()));
    c.disarm(&b).unwrap();
}

#[test]
fn retirement_function_closed_receipt_keeps_permit_until_exit_consumption() {
    let mut l = limits();
    l.epochs = 1;
    let mut p = prepared(l);
    let e = p.stage(config(1)).unwrap();
    let (mut c, client) = activate(p);
    let mut s = state(&client);
    c.arm(&e).unwrap();
    enter(&mut s, 0x8000);
    finish(&mut s, 0x8000);
    enter(&mut s, 0x8000);
    assert!(
        matches!(s.pairs[0].as_ref().unwrap().receipt.summary(), Some(IntervalEntrySummary::Unsampled { reason: UnsampledSummary::FunctionClosed { generation, function: FUNCTION }, .. }) if generation == e.generation())
    );
    assert_eq!(c.owner(&e).unwrap().reservations(), 0);
    c.disarm(&e).unwrap();
    let observed = c.report(&e).unwrap().unwrap();
    let expected: Vec<_> = observed.records().collect();
    let report = c.retire(&e).unwrap();
    assert_eq!(report.records().collect::<Vec<_>>(), expected);
    drop(observed);
    drop(report);
    epoch_limit(&mut c);
    let entry = row(&s, 2);
    assert_eq!(entry[5], e.generation().get());
    finish(&mut s, 0x8000);
    assert_eq!(
        row(&s, 3),
        [4, entry[1], 0x1012, entry[3], entry[4], entry[5], entry[6]]
    );
    assert_eq!(
        s.totals,
        PairTotals {
            entries: 2,
            returns: 2,
            completed: 1,
            unsampled: 1
        }
    );
    assert_eq!(c.binding.session.retained_epochs(), 0);
    // The receipt is consumed INSIDE finish_interval in the exit callback.
    // This metadata test supplies no physical RET or code-quiescence evidence.
    let fresh = c.stage(config(1)).unwrap();
    assert_eq!(fresh.index, e.index);
    assert_ne!(fresh.generation(), e.generation());
}

#[test]
fn retirement_authenticates_key_index_generation_process_and_controller_scope() {
    let mut p = prepared(limits());
    let e = p.stage(config(1)).unwrap();
    let other = p.stage(config(1)).unwrap();
    let (mut c, client) = activate(p);
    drop(client);
    c.arm(&e).unwrap();
    c.disarm(&e).unwrap();
    for bad in [
        IntervalEpoch {
            key: Arc::new(()),
            index: e.index,
            generation: e.generation,
        },
        IntervalEpoch {
            key: Arc::clone(&e.key),
            index: usize::MAX,
            generation: e.generation,
        },
        IntervalEpoch {
            key: Arc::clone(&e.key),
            index: e.index,
            generation: other.generation,
        },
    ] {
        refused(&mut c, &bad, Cause::Epoch);
    }
    let before = view(&c);
    {
        let _scope = ControllerScope::enter().unwrap();
        assert!(matches!(
            c.retire(&e),
            Err(BridgeError {
                cause: Cause::ControllerReentry
            })
        ));
        assert!(CONTROLLER_ACTIVE.get());
    }
    assert_eq!(view(&c), before);
    Arc::get_mut(&mut c.binding).unwrap().pid ^= 1;
    refused(&mut c, &e, Cause::Process);
}

#[test]
fn retirement_refuses_terminal_and_writer_poison_without_taking_the_slot() {
    for poisoned in [false, true] {
        let mut p = prepared(limits());
        let old = p.stage(config(1)).unwrap();
        let next = p.stage(config(1)).unwrap();
        let (mut c, _client) = activate(p);
        c.arm(&old).unwrap();
        c.disarm(&old).unwrap();
        let owner = c.owner(&next).unwrap().clone();
        if poisoned {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                c.binding
                    .session
                    .publish_with_controls(&owner, FailurePoint::None, |_| {
                        panic!("required writer-poison retirement control");
                    })
                    .unwrap();
            }));
            assert!(result.is_err());
            let before = slots(&c);
            let retained = c.binding.session.retained_epochs();
            assert!(matches!(
                c.retire(&old),
                Err(BridgeError {
                    cause: Cause::Control(ControlError::Poisoned)
                })
            ));
            assert_eq!(slots(&c), before);
            assert_eq!(c.binding.session.retained_epochs(), retained);
            assert_eq!(c.binding.session.snapshot(), Err(ControlError::Poisoned));
        } else {
            assert_eq!(
                c.binding
                    .session
                    .publish(&owner, FailurePoint::AfterMutation),
                Err(ControlError::InjectedAfter)
            );
            refused(&mut c, &old, Cause::Control(ControlError::TerminalFailure));
        }
    }
}

#[test]
fn retirement_reuses_slots_but_never_refunds_the_256_action_history() {
    let mut l = limits();
    l.epochs = 1;
    l.actions = 256;
    let (mut c, _client) = activate(prepared(l));
    let mut generations = Vec::new();
    for i in 0..128 {
        let e = c.stage(config(1)).unwrap();
        assert_eq!(e.index, 0);
        assert!(!generations.contains(&e.generation()));
        generations.push(e.generation());
        c.arm(&e).unwrap();
        c.disarm(&e).unwrap();
        let report = c.retire(&e).unwrap();
        assert_eq!(report.records().count(), 0);
        drop(report);
        assert_eq!(c.binding.session.retained_epochs(), 0);
        assert_eq!(c.history().unwrap().actions.len(), 2 * (i + 1));
    }
    let e = c.stage(config(1)).unwrap();
    assert!(!generations.contains(&e.generation()));
    let before = view(&c);
    assert_eq!(
        c.arm(&e),
        Err(error(Cause::Control(ControlError::HistoryFull)))
    );
    assert_eq!(view(&c), before);
    refused(&mut c, &e, Cause::NotDrained);
    assert_eq!(c.history().unwrap().actions.len(), 256);
}
