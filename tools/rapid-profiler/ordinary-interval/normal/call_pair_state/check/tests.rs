//! Fabricated copied facts use real opaque generation IDs; never a loaded owner.
use super::*;
use rapid_profiler::frontend_native::RawTimestamp;
use rapid_profiler::generation::{Admission, Config, Epoch, Record};
use std::panic::{AssertUnwindSafe, catch_unwind};
fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
type Fixture = (
    Ready,
    [Row; 2],
    Vec<(u64, Vec<RecordObservation>)>,
    Vec<Action>,
);
fn fixture(scenario: Scenario) -> Fixture {
    let new = || {
        Epoch::new(
            &native::FUNCTIONS.map(FunctionId),
            Config {
                retained_per_function: 10,
                max_inflight: 2,
                max_invocations: 20,
            },
        )
        .unwrap()
        .id()
    };
    let a = new();
    let b = new();
    let mut parent = vec![
        0x48, 0x83, 0xec, 24, 0x48, 0x89, 0x74, 0x24, 8, 0xe8, 0, 0, 0, 0, 0x48, 0x8b, 0x54, 0x24,
        8, 0x48, 0xc1, 0xe2, 32, 0x48, 0x09, 0xd0, 0x48, 0x83, 0xc4, 24, 0xc3,
    ];
    parent[10..14].copy_from_slice(&(0x3200i32 - 0x310e).to_le_bytes());
    let mut page = vec![0x90; 4096];
    page[0x100..0x11f].copy_from_slice(&parent);
    page[0x205] = 0xc3;
    let plan = caller_oracle::rust_invoke::admit(&[
        0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff, 0xd0,
        0x48, 0x89, 0x03, 0x5b, 0xc3,
    ])
    .unwrap();
    let ready = Ready {
        caller: 0x1080,
        caller_immutable: Vec::new(),
        functions: [
            caller_oracle::module::Function {
                entry: 0x3100,
                heads: vec![
                    0x3100, 0x3104, 0x3109, 0x310e, 0x3113, 0x3117, 0x311a, 0x311e,
                ],
                returns: vec![0x311e],
                boundaries: Vec::new(),
            },
            caller_oracle::module::Function {
                entry: 0x3200,
                heads: (0..6).map(|i| 0x3200 + i).collect(),
                returns: vec![0x3205],
                boundaries: Vec::new(),
            },
        ],
        immutable: vec![(0x3000, page.clone())],
        original_sources: vec![(0x3000, page)],
        journal: Some(JournalReady {
            address: 0x8000,
            a_generation: a.get(),
            b_generation: (scenario == Scenario::RearmB).then_some(b.get()),
            helper_tid: scenario.helper().then_some(99),
        }),
        case: Case::new(10, 0, scenario, [0x3100, 0x3200], [31, 6]),
        plan,
        layout: [240, 416, 144, 400],
    };
    let rows = std::array::from_fn(|n| {
        let sampled = n == 0 || scenario.sampled_child();
        let generation = if n == 1 && scenario == Scenario::RearmB {
            b
        } else {
            a
        };
        let invocation = usize::from(n == 1 && scenario == Scenario::StableA);
        let raw = RawInterval {
            ordinal: n as u64 + 1,
            entry_pc: ready.functions[n].entry,
            return_pc: ready.functions[n].returns[0],
            owner: if sampled {
                RawIntervalOwner::Sampled {
                    generation: generation.get(),
                    invocation,
                }
            } else {
                RawIntervalOwner::Removed {
                    generation: a.get(),
                }
            },
            start: RawTimestamp { ticks: 10, aux: 3 },
            end: RawTimestamp { ticks: 20, aux: 3 },
        };
        let children = if n == 0 {
            u64::from(scenario.sampled_child())
        } else {
            0
        };
        let admission = Admission {
            generation,
            function: FunctionId(native::FUNCTIONS[n]),
            invocation,
            entry_value: 10,
        };
        let rsp = 0x9008 - ready.plan.subject_rsp_delta() - if n == 1 { 32 } else { 0 };
        let word = if n == 0 {
            ready.caller + ready.plan.continuations()[0]
        } else {
            0x310e
        };
        Row {
            function: admission.function,
            node: n,
            parent: 1,
            raw,
            rsp,
            word,
            resume: word,
            resume_rsp: rsp + 8,
            value: if n == 0 {
                ready.case.value()
            } else {
                ready.case.fields()
            },
            ack: if n == 0 {
                Ack::CallerCheckpoint
            } else {
                Ack::ChildContinuation
            },
            prefix: if n == 0 || scenario == Scenario::StableA {
                1
            } else {
                2
            },
            before: 0,
            actual: u64::from(n == 0),
            sampled: sampled.then_some(children),
            completion: sampled.then_some(Completion {
                admission,
                disposition: Disposition::Retained { rank: 0 },
                deactivate: None,
                other_reservations_after_close: None,
            }),
            payload: sampled.then_some(Payload {
                admission,
                thread: 1,
                start_sequence: 0,
                outcome: PayloadOutcome::Completed {
                    end: Observation::Value(20),
                    completed_children: children,
                },
            }),
        }
    });
    let mut reports = vec![(a.get(), Vec::new())];
    if scenario == Scenario::RearmB {
        reports.push((b.get(), Vec::new()));
    }
    for r in &rows {
        if let Some(c) = r.completion {
            reports
                .iter_mut()
                .find(|(g, _)| *g == c.admission.generation.get())
                .unwrap()
                .1
                .push(RecordObservation {
                    record: Record {
                        admission: c.admission,
                        terminal: Some(Terminal::Completed {
                            value: c.admission.invocation as u64,
                            disposition: c.disposition,
                        }),
                    },
                    payload: r.payload,
                });
        }
    }
    let mut actions = vec![Action {
        kind: ActionKind::Published,
        generation: a,
        current: Some(a),
        function: None,
        group: None,
    }];
    if scenario == Scenario::RearmB {
        actions.push(Action {
            kind: ActionKind::Published,
            generation: b,
            current: Some(b),
            function: None,
            group: None,
        });
    }
    actions.push(Action {
        kind: ActionKind::Removed,
        generation: if scenario == Scenario::RearmB { b } else { a },
        current: None,
        function: None,
        group: None,
    });
    (ready, rows, reports, actions)
}
#[test]
fn call_pair_records_join_lifo_sequences_actual_and_sampled_children() {
    for scenario in [Scenario::StableA, Scenario::RearmB, Scenario::RemovedChild] {
        let (r, good, _, _) = fixture(scenario);
        let journal = native::journal(&r, 7, 0x9008, Some(0x3205), Some(0x311e), 4, 0);
        rows(&r, 0x9008, 7, &good, &journal);
        for (ending, aux, expected) in [
            (5, 4, Observation::Unavailable(1)),
            (5, 3, Observation::Unavailable(2)),
            (10, 3, Observation::Value(10)),
        ] {
            let mut varied = good;
            varied[0].raw.end = RawTimestamp { ticks: ending, aux };
            let children = varied[0].sampled.unwrap();
            varied[0].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                end: expected,
                completed_children: children,
            };
            rows(&r, 0x9008, 7, &varied, &journal);
        }
        for n in 0..10 {
            let mut bad = good;
            match n {
                0 => bad.swap(0, 1),
                1 => bad[1].function = bad[0].function,
                2 => bad[1].raw.owner = bad[0].raw.owner,
                3 => bad[1].rsp += 8,
                4 => bad[1].word += 1,
                5 => bad[1].ack = Ack::CallerCheckpoint,
                6 => bad[0].sampled = Some(9),
                7 => bad[0].value ^= 1,
                8 => bad[1].before = 1,
                _ => bad[0].prefix += 1,
            }
            refuses(|| rows(&r, 0x9008, 7, &bad, &journal));
        }
        for n in 0..512 {
            let mut bad = journal;
            bad[n] ^= 1;
            refuses(|| rows(&r, 0x9008, 7, &good, &bad));
        }
    }
}
#[test]
fn call_pair_reports_history_and_owner_closure_are_complete() {
    for scenario in [Scenario::StableA, Scenario::RearmB, Scenario::RemovedChild] {
        let (r, good, records, actions) = fixture(scenario);
        super::reports(&r, &good, &records);
        super::actions(&r, &actions);
        let mut wrong_slot = records.clone();
        wrong_slot[0].1[0].record.terminal = Some(Terminal::Completed {
            value: 99,
            disposition: Disposition::Retained { rank: 0 },
        });
        refuses(|| super::reports(&r, &good, &wrong_slot));
        let mut wrong_children = records.clone();
        wrong_children[0].1[0].payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
            end: Observation::Value(20),
            completed_children: 99,
        };
        refuses(|| super::reports(&r, &good, &wrong_children));
        let mut bad = records.clone();
        bad[0].1[0].record.terminal = None;
        refuses(|| super::reports(&r, &good, &bad));
        let mut bad = records.clone();
        bad[0].1[0].payload.as_mut().unwrap().thread = 2;
        refuses(|| super::reports(&r, &good, &bad));
        let mut bad = records.clone();
        bad[0].1.push(records[0].1[0]);
        refuses(|| super::reports(&r, &good, &bad));
        for n in 0..actions.len() {
            let mut bad = actions.clone();
            bad[n].kind = ActionKind::Stale;
            refuses(|| super::actions(&r, &bad));
        }
        let mut bad = actions.clone();
        bad.pop();
        refuses(|| super::actions(&r, &bad));
    }
}
