use super::*;
use std::collections::BTreeMap;
use std::sync::{Barrier, mpsc};
use std::time::Duration;

const A: FunctionId = FunctionId(11);
const B: FunctionId = FunctionId(29);

fn epoch(k: usize, m: usize, a: usize) -> Epoch {
    Epoch::new(
        &[A, B],
        Config {
            retained_per_function: k,
            max_inflight: m,
            max_invocations: a,
        },
    )
    .unwrap()
}

fn final_population(epoch: &Epoch, function: FunctionId) -> Population {
    epoch
        .try_drain()
        .expect("required drain")
        .population(function)
        .unwrap()
}

#[test]
fn retained_budget_is_per_function_for_one_ten_and_thousand() {
    for k in [1, 10, 1000] {
        let e = epoch(k, 1, 2 * k);
        for rank in 0..k {
            for function in [A, B] {
                let result = e
                    .enter(function, rank as u64)
                    .unwrap()
                    .complete(100 + rank as u64);
                assert_eq!(result.disposition, Disposition::Retained { rank });
                assert_eq!(result.deactivate.is_some(), rank + 1 == k);
            }
        }
        assert_eq!(e.function_closed(A), Some(true));
        assert_eq!(e.function_closed(B), Some(true));
        assert!(!e.is_closed());
        e.close();
        for function in [A, B] {
            assert_eq!(
                final_population(&e, function),
                Population {
                    admitted: k,
                    completed: k,
                    retained: k,
                    ..Population::default()
                }
            );
        }
    }
}

#[test]
fn close_before_admission_refuses_without_record() {
    let e = epoch(2, 2, 4);
    assert_eq!(e.close(), 0);
    assert!(matches!(e.enter(A, 1), Err(AdmissionRefusal::EpochClosed)));
    assert_eq!(e.records().count(), 0);
    assert_eq!(final_population(&e, A), Population::default());
}

#[test]
fn close_after_admission_waits_for_terminal_record() {
    let e = epoch(2, 2, 4);
    let t = e.enter(A, 7).unwrap();
    assert_eq!(e.close(), 1);
    assert!(e.try_drain().is_none());
    assert_eq!(
        e.population(A),
        Some(PopulationObservation {
            population: Population {
                admitted: 1,
                unfinished: 1,
                ..Population::default()
            },
            final_report: false
        })
    );
    t.complete(91);
    assert_eq!(
        final_population(&e, A),
        Population {
            admitted: 1,
            completed: 1,
            retained: 1,
            ..Population::default()
        }
    );
    assert_eq!(
        e.try_drain().unwrap().records().next().unwrap().1,
        Terminal::Completed {
            value: 91,
            disposition: Disposition::Retained { rank: 0 }
        }
    );
}

#[test]
fn inflight_refusal_does_not_consume_a_slot() {
    let e = epoch(4, 1, 4);
    let first = e.enter(A, 1).unwrap();
    assert!(matches!(
        e.enter(B, 2),
        Err(AdmissionRefusal::InflightLimit)
    ));
    assert_eq!(e.assigned.load(Ordering::Acquire), 1);
    first.complete(3);
    let second = e.enter(B, 4).unwrap();
    assert_eq!(second.admission().invocation, 1);
    second.cancel();
    e.close();
    assert_eq!(e.try_drain().unwrap().records().count(), 2);
}

#[test]
fn total_storage_exhaustion_closes_epoch_without_losing_records() {
    let e = epoch(10, 2, 3);
    e.enter(A, 1).unwrap().complete(11);
    let pending = e.enter(B, 2).unwrap();
    e.enter(A, 3).unwrap().complete(13);
    assert!(matches!(
        e.enter(A, 4),
        Err(AdmissionRefusal::StorageExhausted)
    ));
    assert!(e.is_closed());
    assert_eq!(e.reservations(), 1);
    assert!(matches!(e.enter(B, 5), Err(AdmissionRefusal::EpochClosed)));
    assert!(e.try_drain().is_none());
    pending.cancel();
    assert_eq!(e.try_drain().unwrap().records().count(), 3);
    assert_eq!(
        final_population(&e, A),
        Population {
            admitted: 2,
            completed: 2,
            retained: 2,
            ..Population::default()
        }
    );
    assert_eq!(
        final_population(&e, B),
        Population {
            admitted: 1,
            cancelled: 1,
            ..Population::default()
        }
    );
}

#[test]
fn old_ticket_completion_does_not_close_or_write_new_epoch() {
    let old = epoch(1, 2, 4);
    let previous = old.enter(A, 17).unwrap();
    old.close();
    let new = epoch(1, 2, 4);
    assert_ne!(old.id(), new.id());
    let current = new.enter(A, 19).unwrap();
    let completed = previous.complete(23);
    assert_eq!(
        completed.deactivate,
        Some(DeactivationRequest {
            generation: old.id(),
            function: A
        })
    );
    assert_eq!(old.function_closed(A), Some(true));
    assert_eq!(new.function_closed(A), Some(false));
    assert!(!new.is_closed());
    assert_eq!(new.population(A).unwrap().population.unfinished, 1);
    assert_eq!(new.population(A).unwrap().population.completed, 0);
    assert_eq!(
        old.try_drain()
            .unwrap()
            .records()
            .next()
            .unwrap()
            .0
            .generation,
        old.id()
    );
    current.complete(31);
    new.close();
    assert_eq!(
        new.try_drain()
            .unwrap()
            .records()
            .next()
            .unwrap()
            .0
            .generation,
        new.id()
    );
}

#[test]
fn nested_invocations_keep_identity_and_completion_selection_order() {
    let e = epoch(1, 2, 4);
    let outer = e.enter(A, 101).unwrap();
    let inner = e.enter(A, 102).unwrap();
    assert_eq!(outer.admission().invocation, 0);
    assert_eq!(inner.admission().invocation, 1);
    assert_eq!(
        inner.complete(202).disposition,
        Disposition::Retained { rank: 0 }
    );
    assert_eq!(
        outer.complete(201).disposition,
        Disposition::DroppedAfterBudget
    );
    e.close();
    assert_eq!(
        final_population(&e, A),
        Population {
            admitted: 2,
            completed: 2,
            retained: 1,
            dropped: 1,
            ..Population::default()
        }
    );
    let values: Vec<_> = e
        .try_drain()
        .unwrap()
        .records()
        .map(|(a, t)| (a.invocation, a.entry_value, t))
        .collect();
    assert_eq!(
        values,
        vec![
            (
                0,
                101,
                Terminal::Completed {
                    value: 201,
                    disposition: Disposition::DroppedAfterBudget
                }
            ),
            (
                1,
                102,
                Terminal::Completed {
                    value: 202,
                    disposition: Disposition::Retained { rank: 0 }
                }
            )
        ]
    );
}

#[test]
fn explicit_and_drop_cancellation_are_distinct_and_do_not_consume_k() {
    let e = epoch(1, 1, 4);
    e.enter(A, 3).unwrap().cancel();
    drop(e.enter(A, 5).unwrap());
    assert_eq!(e.function_closed(A), Some(false));
    let result = e.enter(A, 7).unwrap().complete(11);
    assert_eq!(result.disposition, Disposition::Retained { rank: 0 });
    e.close();
    let outcomes: Vec<_> = e
        .try_drain()
        .unwrap()
        .records()
        .map(|(_, terminal)| terminal)
        .collect();
    assert_eq!(
        outcomes,
        vec![
            Terminal::Cancelled(CancelReason::Explicit),
            Terminal::Cancelled(CancelReason::DroppedTicket),
            Terminal::Completed {
                value: 11,
                disposition: Disposition::Retained { rank: 0 }
            }
        ]
    );
    assert_eq!(
        final_population(&e, A),
        Population {
            admitted: 3,
            completed: 1,
            retained: 1,
            cancelled: 2,
            ..Population::default()
        }
    );
}

#[test]
fn close_gap_allows_five_post_k_completions_but_only_one_other_reservation() {
    let e = epoch(1, 2, 8);
    let kth = e.enter(A, 1).unwrap();
    let (paused_tx, paused_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            kth.complete_before_close(10, || {
                paused_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            })
        });
        paused_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut results = Vec::new();
        for value in 2..=6 {
            results.push(e.enter(A, value).unwrap().complete(10 * value));
        }
        let held = e.enter(A, 7).unwrap();
        release_tx.send(()).unwrap();
        let kth_result = worker.join().unwrap();
        assert_eq!(kth_result.disposition, Disposition::Retained { rank: 0 });
        assert_eq!(kth_result.other_reservations_after_close, Some(1));
        assert_eq!(results.len(), 5);
        assert!(results.len() > e.config.max_inflight - 1);
        assert!(results.iter().all(|r| r.disposition == Disposition::DroppedAfterBudget && r.deactivate.is_none()));
        assert!(matches!(
            e.enter(A, 8),
            Err(AdmissionRefusal::FunctionClosed)
        ));
        assert_eq!(e.reservations(), 1);
        assert_eq!(
            held.complete(70).disposition,
            Disposition::DroppedAfterBudget
        );
    });
    assert!(!e.is_closed());
    e.close();
    assert_eq!(
        final_population(&e, A),
        Population {
            admitted: 7,
            completed: 7,
            retained: 1,
            dropped: 6,
            ..Population::default()
        }
    );
}

#[test]
fn simultaneous_completions_have_exactly_one_final_retention_and_request() {
    let e = epoch(1, 2, 2);
    let a = e.enter(A, 100).unwrap();
    let b = e.enter(A, 200).unwrap();
    let barrier = Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            barrier.wait();
            a.complete(101)
        });
        barrier.wait();
        let second = b.complete(201);
        [worker.join().unwrap(), second]
    });
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| r.disposition == Disposition::Retained { rank: 0 })
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| r.disposition == Disposition::DroppedAfterBudget)
            .count(),
        1
    );
    assert_eq!(
        outcomes.iter().filter(|r| r.deactivate.is_some()).count(),
        1
    );
    for outcome in outcomes {
        if let Some(count) = outcome.other_reservations_after_close {
            assert!(count <= 1);
        }
    }
    e.close();
    assert_eq!(
        final_population(&e, A),
        Population {
            admitted: 2,
            completed: 2,
            retained: 1,
            dropped: 1,
            ..Population::default()
        }
    );
    assert_eq!(
        e.try_drain()
            .unwrap()
            .records()
            .map(|(admission, _)| admission.entry_value)
            .collect::<Vec<_>>(),
        vec![100, 200]
    );
}

#[test]
fn final_acquire_observes_all_sixteen_exact_terminal_values() {
    let e = epoch(16, 16, 16);
    let tickets: Vec<_> = (0..16).map(|i| e.enter(A, i).unwrap()).collect();
    assert_eq!(e.close(), 16);
    // Caller plus one scoped worker, not one thread per slot.
    let (release_tx, release_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let mut left = Vec::new();
        let mut right = Vec::new();
        for ticket in tickets {
            if ticket.admission().invocation % 2 == 0 {
                left.push(ticket);
            } else {
                right.push(ticket);
            }
        }
        let worker = scope.spawn(move || {
            for ticket in left {
                let i = ticket.admission().entry_value;
                ticket.complete(i ^ 0xfedc_ba98);
            }
            // There is no worker-to-parent completion message before drain.
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        for ticket in right {
            let i = ticket.admission().entry_value;
            ticket.complete(i ^ 0xfedc_ba98);
        }
        // Observe final records while the worker is still held alive. A join
        // cannot provide the visibility used by these assertions.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let prejoin = loop {
            if let Some(drained) = e.try_drain() {
                break drained;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "required bounded pre-join drain"
            );
            std::thread::yield_now();
        };
        assert_eq!(prejoin.records().count(), 16);
        assert_eq!(
            prejoin.population(A),
            Some(Population {
                admitted: 16,
                completed: 16,
                retained: 16,
                ..Population::default()
            })
        );
        assert_eq!(
            prejoin
                .records()
                .map(|(admission, terminal)| (
                    admission.invocation,
                    admission.entry_value,
                    match terminal {
                        Terminal::Completed {
                            value,
                            disposition: Disposition::Retained { .. },
                        } => value,
                        _ => panic!("required retained completion before join"),
                    }
                ))
                .collect::<Vec<_>>(),
            (0_usize..16)
                .map(|i| (i, i as u64, (i as u64) ^ 0xfedc_ba98))
                .collect::<Vec<_>>()
        );
        release_tx.send(()).unwrap();
        worker.join().unwrap();
    });
    let drained = e.try_drain().unwrap();
    assert_eq!(
        final_population(&e, A),
        Population {
            admitted: 16,
            completed: 16,
            retained: 16,
            ..Population::default()
        }
    );
    for (admission, terminal) in drained.records() {
        assert!(
            matches!(terminal, Terminal::Completed { value, disposition: Disposition::Retained { .. } } if value == admission.entry_value ^ 0xfedc_ba98)
        );
    }
    let before: Vec<_> = drained.records().collect();
    assert_eq!(e.close(), 0);
    assert_eq!(drained.records().collect::<Vec<_>>(), before);
}

#[test]
fn partial_records_keep_unfinished_in_two_epochs_separate() {
    let old = epoch(2, 2, 4);
    let new = epoch(2, 2, 4);
    let a = old.enter(A, 1).unwrap();
    let b = new.enter(B, 2).unwrap();
    old.close();
    assert!(old.try_drain().is_none() && new.try_drain().is_none());
    assert_eq!(
        old.population(A).unwrap(),
        PopulationObservation {
            population: Population {
                admitted: 1,
                unfinished: 1,
                ..Population::default()
            },
            final_report: false
        }
    );
    assert_eq!(new.population(B).unwrap().population.unfinished, 1);
    assert!(old.records().all(|r| r.admission.generation == old.id()));
    assert!(new.records().all(|r| r.admission.generation == new.id()));
    a.cancel();
    assert!(old.try_drain().is_some());
    assert!(new.try_drain().is_none());
    b.cancel();
    assert!(new.try_drain().is_none());
    new.close();
    assert!(new.try_drain().is_some());
}

#[test]
fn exact_constructor_refusals_and_largest_budget_do_not_wrap() {
    let valid = Config {
        retained_per_function: 1,
        max_inflight: 1,
        max_invocations: 1,
    };
    assert_eq!(
        Epoch::new(&[], valid).err(),
        Some(CreateError::EmptyFunctions)
    );
    assert_eq!(
        Epoch::new(&[A; MAX_FUNCTIONS + 1], valid).err(),
        Some(CreateError::TooManyFunctions)
    );
    assert_eq!(
        Epoch::new(&[A, A], valid).err(),
        Some(CreateError::DuplicateFunction)
    );
    assert_eq!(
        Epoch::new(
            &[A],
            Config {
                retained_per_function: 0,
                ..valid
            }
        )
        .err(),
        Some(CreateError::ZeroRetainedBudget)
    );
    for max_inflight in [0, CLOSED] {
        assert_eq!(
            Epoch::new(
                &[A],
                Config {
                    max_inflight,
                    ..valid
                }
            )
            .err(),
            Some(CreateError::InvalidInflightLimit)
        );
    }
    for max_invocations in [0, MAX_RECORDS + 1] {
        assert_eq!(
            Epoch::new(
                &[A],
                Config {
                    max_invocations,
                    ..valid
                }
            )
            .err(),
            Some(CreateError::InvalidInvocationLimit)
        );
    }
    let e = Epoch::new(
        &[A],
        Config {
            retained_per_function: usize::MAX,
            max_inflight: COUNT_MASK,
            ..valid
        },
    )
    .unwrap();
    e.enter(A, 0).unwrap().complete(1);
    e.close();
    assert_eq!(final_population(&e, A).retained, 1);
}

#[test]
fn checked_generation_exhaustion_never_wraps_or_reuses() {
    let next = AtomicU64::new(u64::MAX - 1);
    assert_eq!(allocate_id(&next), Ok(GenerationId(u64::MAX - 1)));
    assert_eq!(allocate_id(&next), Err(CreateError::GenerationExhausted));
    assert_eq!(allocate_id(&next), Err(CreateError::GenerationExhausted));
    assert_eq!(next.load(Ordering::Acquire), u64::MAX);
    let invalid = AtomicU64::new(0);
    assert_eq!(allocate_id(&invalid), Err(CreateError::GenerationExhausted));
    assert_eq!(invalid.load(Ordering::Acquire), 0);
}

#[test]
fn unknown_function_refusal_and_closed_function_do_not_hide_other_function() {
    let e = epoch(1, 1, 2);
    assert!(matches!(
        e.enter(FunctionId(99), 0),
        Err(AdmissionRefusal::UnknownFunction)
    ));
    assert_eq!(e.assigned.load(Ordering::Acquire), 0);
    assert_eq!(e.population(FunctionId(99)), None);
    assert_eq!(e.function_closed(FunctionId(99)), None);
    e.enter(A, 1).unwrap().complete(2);
    assert!(matches!(
        e.enter(A, 3),
        Err(AdmissionRefusal::FunctionClosed)
    ));
    assert_eq!(
        e.enter(B, 4).unwrap().complete(5).disposition,
        Disposition::Retained { rank: 0 }
    );
    e.close();
    assert_eq!(final_population(&e, A).retained, 1);
    assert_eq!(final_population(&e, B).retained, 1);
}

// Independent expected-record ledger: literal events and terminal outcomes,
// without replaying the production atomics, retention CAS, or close algorithm.
fn reference(
    generation: GenerationId,
    entries: &[(usize, FunctionId, u64, Option<Terminal>)],
) -> BTreeMap<(GenerationId, usize), Record> {
    entries
        .iter()
        .map(|&(invocation, function, entry_value, terminal)| {
            let admission = Admission {
                generation,
                invocation,
                function,
                entry_value,
            };
            (
                (generation, invocation),
                Record {
                    admission,
                    terminal,
                },
            )
        })
        .collect()
}

fn observed(epochs: &[&Epoch]) -> BTreeMap<(GenerationId, usize), Record> {
    let mut result = BTreeMap::new();
    for e in epochs {
        for record in e.records() {
            assert!(
                result
                    .insert(
                        (record.admission.generation, record.admission.invocation),
                        record
                    )
                    .is_none()
            );
        }
    }
    result
}

#[test]
fn independent_two_generation_two_function_event_ledger() {
    let old = epoch(1, 3, 4);
    let old_outer = old.enter(A, 1).unwrap();
    let old_inner = old.enter(A, 2).unwrap();
    let old_b = old.enter(B, 3).unwrap();
    old_inner.complete(20);
    old.close();
    let new = epoch(1, 2, 4);
    let new_a = new.enter(A, 4).unwrap();
    let new_b = new.enter(B, 5).unwrap();
    let retained = |value| {
        Some(Terminal::Completed {
            value,
            disposition: Disposition::Retained { rank: 0 },
        })
    };
    let mut expected = reference(
        old.id(),
        &[(0, A, 1, None), (1, A, 2, retained(20)), (2, B, 3, None)],
    );
    expected.extend(reference(new.id(), &[(0, A, 4, None), (1, B, 5, None)]));
    assert_eq!(observed(&[&old, &new]), expected);
    old_outer.complete(10);
    old_b.cancel();
    new_a.complete(40);
    drop(new_b);
    new.close();
    let mut expected = reference(
        old.id(),
        &[
            (
                0,
                A,
                1,
                Some(Terminal::Completed {
                    value: 10,
                    disposition: Disposition::DroppedAfterBudget,
                }),
            ),
            (1, A, 2, retained(20)),
            (2, B, 3, Some(Terminal::Cancelled(CancelReason::Explicit))),
        ],
    );
    expected.extend(reference(
        new.id(),
        &[
            (0, A, 4, retained(40)),
            (
                1,
                B,
                5,
                Some(Terminal::Cancelled(CancelReason::DroppedTicket)),
            ),
        ],
    ));
    assert_eq!(observed(&[&old, &new]), expected);
    assert!(old.try_drain().is_some() && new.try_drain().is_some());
}

#[test]
fn independent_ledger_rejects_six_wrong_populations_or_identities() {
    let id = GenerationId(17);
    let retained = Some(Terminal::Completed {
        value: 4,
        disposition: Disposition::Retained { rank: 0 },
    });
    let expected = reference(
        id,
        &[
            (0, A, 1, retained),
            (1, B, 2, Some(Terminal::Cancelled(CancelReason::Explicit))),
            (2, A, 3, None),
        ],
    );
    let mut mutants = Vec::new();
    let mut m = expected.clone();
    m.get_mut(&(id, 0)).unwrap().admission.generation = GenerationId(18);
    mutants.push(m);
    let mut m = expected.clone();
    m.get_mut(&(id, 0)).unwrap().admission.function = B;
    mutants.push(m);
    let mut m = expected.clone();
    m.get_mut(&(id, 0)).unwrap().terminal = Some(Terminal::Completed {
        value: 4,
        disposition: Disposition::DroppedAfterBudget,
    });
    mutants.push(m);
    let mut m = expected.clone();
    m.remove(&(id, 1));
    mutants.push(m);
    let mut m = expected.clone();
    m.get_mut(&(id, 1)).unwrap().terminal = retained;
    mutants.push(m);
    let mut m = expected.clone();
    m.get_mut(&(id, 2)).unwrap().terminal = Some(Terminal::Cancelled(CancelReason::DroppedTicket));
    mutants.push(m);
    assert_eq!(mutants.len(), 6);
    for mutant in mutants {
        assert_ne!(mutant, expected);
    }
    assert_eq!(expected.clone(), expected);
}
