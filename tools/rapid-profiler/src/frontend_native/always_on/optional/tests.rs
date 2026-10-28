//! Pure model/metadata controls. No generated instructions, CALL or native qualification.
use super::*;
use crate::frontend::PayloadOutcome;
use gate::tests as frames;
use liteinst2::precontext::{PreContextAction, PreContextRole, PreContextSelector};
fn state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|c| f(c.borrow_mut().as_mut().unwrap()))
}
struct Fixture {
    thread: OptionalThread,
    c: OptionalController,
    gate: Arc<OptionalCallGate>,
}
impl Fixture {
    fn new(base: u64) -> Self {
        POISONED.set(false);
        frames::idle_at(base);
        let gate = frames::descriptor();
        let (selector, writer) = PreContextSelector::new(false);
        let roles = vec![
            PreContextAction::new(
                gate.target(),
                PreContextRole::Entry,
                &selector,
                entry_callback,
            ),
            PreContextAction::new(0x1010, PreContextRole::Return, &selector, exit_callback),
        ];
        let p = PreparedOptionalController::new(
            InstalledOptionalSite {
                site: Arc::new(site::Site {
                    roles,
                    gate: gate.clone(),
                    selector,
                }),
                writer,
            },
            71,
            FunctionId(11),
            Limits {
                epochs: 2,
                threads: 1,
                depth: 1,
                records_per_epoch: 128,
                actions: 64,
            },
        )
        .unwrap();
        let (c, client) = unsafe { p.activate_concurrent() }.unwrap();
        let thread = unsafe {
            client.attach(
                1,
                ReadableStack {
                    start: 0x7000,
                    end: 0x9000,
                },
                IntervalJournal::allocate(),
            )
        }
        .unwrap();
        Self { thread, c, gate }
    }
    fn stage(&mut self, k: usize) -> IntervalEpoch {
        self.c
            .stage(Config {
                retained_per_function: k,
                max_inflight: 1,
                max_invocations: 128,
            })
            .unwrap()
    }
    fn begin(&self, slow: bool) -> Result<(Checkpoint, Option<OptionalTotals>), BridgeError> {
        state(|s| s.reserve())?;
        let before = state(|s| Checkpoint::new(s));
        let previous = self.thread.finished.replace(None);
        let token = frames::begin(&self.gate, slow);
        if let Some(token) = token {
            state(|s| {
                s.enter(
                    self.gate.target(),
                    0x7ff8,
                    self.gate.continuation(),
                    RawTimestamp {
                        ticks: before.totals.physical * 10,
                        aux: 7,
                    },
                    token,
                )
            })?;
        }
        Ok((before, previous))
    }
    fn finish(
        &self,
        slow: bool,
        before: Checkpoint,
        previous: Option<OptionalTotals>,
    ) -> Result<gate::Returned, BridgeError> {
        if slow {
            state(|s| {
                let p = s.pair.as_ref().unwrap();
                let r = frames::proof(&self.gate, &p.token);
                s.finish(
                    0x1010,
                    0x7ff8,
                    self.gate.continuation(),
                    RawTimestamp {
                        ticks: before.totals.physical * 10 + 3,
                        aux: 7,
                    },
                    r,
                )
            })?;
        }
        let returned = frames::resume(&self.gate, slow);
        state(|s| {
            s.empty()?;
            s.binding.healthy()?;
            let totals = account(&before, s, returned)?;
            s.totals = totals;
            self.thread
                .finished
                .set((previous == Some(before.totals)).then_some(totals));
            Ok::<(), BridgeError>(())
        })?;
        Ok(returned)
    }
    fn call(&self, slow: bool) -> Result<gate::Returned, BridgeError> {
        let (b, p) = self.begin(slow)?;
        self.finish(slow, b, p)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Test-only metadata cleanup; no real execution exists. Failed state is not
        // rehabilitated by a production API or counted as an invocation.
        self.thread.active = false;
        STATE.with(|c| {
            c.borrow_mut().take();
        });
        POISONED.set(false);
        frames::idle_at(0);
    }
}
#[test]
fn physical_sequence_keeps_original_base_and_fast_is_not_an_unsampled_row() {
    let mut f = Fixture::new(17);
    assert!(f.thread.drain_completed().unwrap().is_none());
    let fast = f.call(false).unwrap();
    assert_eq!(fast.sequence, 18);
    let slow = f.call(true).unwrap();
    assert_eq!(slow.sequence, 19); // Genuine InitialDisarmed model receipt.
    let batch = f.thread.drain_completed().unwrap().unwrap();
    assert_eq!(batch.physical_range(), 0..2);
    assert_eq!(batch.raw_range(), 0..1);
    assert_eq!(batch.event_range(), 0..2);
    assert_eq!(batch.gate_base(), 17);
    assert_eq!(batch.gate_sequence(), 19);
    assert_eq!(batch.observed_gate_sequences(), [19]);
    assert_eq!(batch.rows()[0].owner, RawIntervalOwner::InitialDisarmed);
    assert_eq!(batch.rows()[0].ordinal, 1);
    assert_eq!(
        batch.totals().1,
        OptionalTotals {
            physical: 2,
            bypassed: 1,
            observed: PairTotals {
                entries: 1,
                returns: 1,
                completed: 0,
                unsampled: 1
            }
        }
    );
    assert_eq!(&batch.journal()[..4], &[2, 0, batch.tid(), 0]);
    assert!(batch.journal()[18..].iter().all(|&x| x == 0));
    f.call(false).unwrap();
    let only_fast = f.thread.drain_completed().unwrap().unwrap();
    assert_eq!(only_fast.physical_range(), 2..3);
    assert!(only_fast.rows().is_empty());
    assert!(only_fast.observed_gate_sequences().is_empty());
    assert_eq!(&only_fast.journal()[..4], &[0, 0, only_fast.tid(), 0]);
    assert!(only_fast.journal()[4..].iter().all(|&x| x == 0));
}
#[test]
fn two_full_reuses_preserve_old_batch_and_every_report_join() {
    let mut f = Fixture::new(9);
    let e = f.stage(64);
    f.c.arm(&e).unwrap();
    let mut held = None;
    for batch in 0..2 {
        for _ in 0..32 {
            f.call(true).unwrap();
        }
        let before = f.thread.totals().unwrap();
        let journal = state(|s| s.journal.page.0);
        let sequence = f.gate.idle_checkpoint().unwrap();
        assert_eq!(f.call(false), Err(error(Cause::Capacity))); // Off cannot evade possible-Slow capacity.
        assert_eq!(f.thread.totals().unwrap(), before);
        assert_eq!(state(|s| s.journal.page.0), journal);
        assert_eq!(f.gate.idle_checkpoint().unwrap(), sequence);
        let out = f.thread.drain_completed().unwrap().unwrap();
        assert_eq!(out.number(), batch + 1);
        assert_eq!(out.rows().len(), 32);
        assert_eq!(out.journal().len(), 512);
        assert_eq!(out.journal()[0], 64);
        assert!(out.journal()[452..].iter().all(|&v| v == 0));
        for (i, row) in out.rows().iter().enumerate() {
            let n = batch * 32 + i as u64 + 1;
            assert_eq!(row.ordinal, n);
            assert_eq!(
                row.owner,
                RawIntervalOwner::Sampled {
                    generation: e.generation().get(),
                    invocation: n as usize - 1
                }
            );
            assert_eq!(out.observed_gate_sequences()[i], 9 + n);
            let at = 4 + i * 14;
            assert_eq!(
                &out.journal()[at..at + 7],
                &[
                    1,
                    n,
                    0x1000,
                    0x7ff8,
                    f.gate.continuation(),
                    e.generation().get(),
                    8192 + n
                ]
            );
            assert_eq!(
                &out.journal()[at + 7..at + 14],
                &[
                    2,
                    n,
                    0x1010,
                    0x7ff8,
                    f.gate.continuation(),
                    e.generation().get(),
                    8192 + n
                ]
            );
        }
        if batch == 0 {
            held = Some(out);
        } else {
            let old = held.as_ref().unwrap();
            assert_eq!(old.physical_range(), 0..32);
            assert_eq!(old.rows()[31].ordinal, 32);
            assert_eq!(old.observed_gate_sequences()[31], 41);
        }
        assert!(f.thread.drain_completed().unwrap().is_none());
    }
    assert!(f.c.binding.site.selector.is_enabled()); // K alone is not physical off.
    assert_eq!(f.c.scan_closed().unwrap(), 1);
    assert!(!f.c.binding.site.selector.is_enabled());
    f.c.disarm(&e).unwrap();
    let report = f.c.report(&e).unwrap().unwrap();
    let records: Vec<_> = report.records().collect();
    assert_eq!(records.len(), 64);
    for (n, r) in records.iter().enumerate() {
        let p = r.payload.unwrap();
        assert_eq!(p.admission.generation, e.generation());
        assert_eq!(p.admission.invocation, n);
        assert_eq!(p.thread, 1);
        assert_eq!(p.start_sequence, n as u64);
        assert_eq!(
            p.outcome,
            PayloadOutcome::Completed {
                end: Observation::Value(n as u64 * 10 + 3),
                completed_children: 0
            }
        );
    }
}
#[test]
fn old_slow_owner_and_fast_choice_survive_rearm_without_selector_retest() {
    let mut f = Fixture::new(0);
    let a = f.stage(1);
    let b = f.stage(2);
    f.c.arm(&a).unwrap();
    let (before, previous) = f.begin(true).unwrap();
    f.c.disarm(&a).unwrap();
    assert!(f.c.retire(&a).is_err());
    f.c.arm(&b).unwrap();
    f.finish(true, before, previous).unwrap();
    assert!(f.c.binding.site.selector.is_enabled());
    assert_eq!(f.c.scan_closed().unwrap(), 0); // A cannot disable B.
    let report = f.c.retire(&a).unwrap();
    assert_eq!(report.generation(), a.generation());
    assert_eq!(report.records().count(), 1);
    assert!(matches!(
        f.c.stage(Config {
            retained_per_function: 1,
            max_inflight: 1,
            max_invocations: 1
        }),
        Err(BridgeError {
            cause: Cause::Setup(SetupError::EpochLimit)
        })
    ));
    drop(report);
    let replacement = f.stage(1);
    f.c.disarm(&b).unwrap();
    let (before, previous) = f.begin(false).unwrap();
    // Choose a separately staged owner after actual Fast metadata selection.
    f.c.arm(&replacement).unwrap();
    f.finish(false, before, previous).unwrap();
    assert_eq!(f.thread.totals().unwrap().observed.returns, 1);
    assert_eq!(f.thread.totals().unwrap().bypassed, 1);
}
#[test]
fn stale_true_after_k_and_remove_gets_real_unsampled_receipts() {
    let mut f = Fixture::new(0);
    let e = f.stage(1);
    f.c.arm(&e).unwrap();
    f.call(true).unwrap();
    f.call(true).unwrap();
    f.c.disarm(&e).unwrap();
    f.call(true).unwrap();
    let batch = f.thread.drain_completed().unwrap().unwrap();
    assert_eq!(
        batch.rows()[1].owner,
        RawIntervalOwner::FunctionClosed {
            generation: e.generation().get()
        }
    );
    assert_eq!(
        batch.rows()[2].owner,
        RawIntervalOwner::Removed {
            generation: e.generation().get()
        }
    );
    assert_eq!(
        batch.totals().1.observed,
        PairTotals {
            entries: 3,
            returns: 3,
            completed: 1,
            unsampled: 2
        }
    );
}
#[test]
fn false_selector_never_hides_failed_after_or_poisoned_writer() {
    for poison in [false, true] {
        let mut f = Fixture::new(0);
        let e = f.stage(2);
        assert!(!f.c.binding.site.selector.is_enabled());
        if poison {
            let owner = f.c.owner(&e).unwrap().clone();
            let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                f.c.binding
                    .session
                    .publish_with_controls(&owner, FailurePoint::None, |_| {
                        panic!("required writer poison")
                    })
                    .unwrap();
            }));
            assert!(failed.is_err());
            assert!(f.c.arm(&e).is_err());
        } else {
            assert_eq!(
                f.c.publish(&e, FailurePoint::AfterMutation),
                Err(error(Cause::Control(ControlError::InjectedAfter)))
            );
        }
        assert!(f.c.binding.failed.load(Ordering::Acquire));
        assert!(!f.c.binding.site.selector.is_enabled());
        let n = f.gate.idle_checkpoint().unwrap();
        assert!(f.call(false).is_err());
        assert_eq!(f.gate.idle_checkpoint().unwrap(), n);
        assert_eq!(f.thread.totals().unwrap(), OptionalTotals::default());
    }
}
#[test]
fn drain_rejects_corrupt_unused_words_sequence_join_and_missing_checkpoint_atomically() {
    let mut f = Fixture::new(4);
    f.call(false).unwrap();
    f.call(true).unwrap();
    let journal = state(|s| s.journal.page.0);
    let joins = state(|s| s.joins);
    let totals = f.thread.totals().unwrap();
    for target in 0..4 {
        state(|s| match target {
            0 => s.journal.word(511, 1),
            1 => s.joins[0] = 4,
            2 => s.joins[1] = 7,
            _ => s.journal.word(4, 1),
        });
        assert!(f.thread.drain_completed().is_err());
        assert_eq!(f.thread.totals().unwrap(), totals);
        state(|s| {
            s.journal.page.0 = journal;
            s.joins = joins;
        });
    }
    let checkpoint = f.thread.finished.replace(None);
    assert!(f.thread.drain_completed().is_err());
    f.thread.finished.set(checkpoint);
    let batch = f.thread.drain_completed().unwrap().unwrap();
    assert_eq!(batch.physical_range(), 0..2);
    assert_eq!(batch.observed_gate_sequences(), [6]);
}
#[test]
fn fast_accounting_checks_entire_existing_buffer_and_refuses_counter_wrap() {
    let f = Fixture::new(0);
    f.call(true).unwrap();
    let before = state(|s| Checkpoint::new(s));
    frames::begin(&f.gate, false);
    let r = frames::resume(&f.gate, false);
    state(|s| {
        s.journal.word(511, 1);
        assert!(account(&before, s, r).is_err());
        s.journal.word(511, 0);
        s.next += 1;
        assert!(account(&before, s, r).is_err());
        s.next -= 1;
        assert!(account(&before, s, r).is_ok());
        s.totals.physical = u64::MAX;
        assert_eq!(s.reserve(), Err(error(Cause::Capacity)));
    });
}

#[test]
fn controller_failure_after_selection_preserves_slow_owner_but_refuses_facade_credit() {
    for slow in [false, true] {
        let mut f = Fixture::new(0);
        let a = f.stage(1);
        let b = f.stage(1);
        if slow {
            f.c.arm(&a).unwrap();
        }
        let owner = f.c.owner(&a).unwrap().clone();
        let (before, previous) = f.begin(slow).unwrap();
        assert_eq!(
            f.c.publish(&b, FailurePoint::AfterMutation),
            Err(error(Cause::Control(ControlError::InjectedAfter)))
        );
        let err = f.finish(slow, before, previous).unwrap_err();
        assert_eq!(err, error(Cause::Control(ControlError::TerminalFailure)));
        assert_eq!(f.gate.idle_checkpoint(), Ok(1)); // Simulated physical metadata; never native credit.
        assert_eq!(f.thread.finished.get(), None);
        assert_eq!(state(|s| s.totals.physical), 0);
        assert_eq!(state(|s| s.totals.observed.returns), u64::from(slow));
        assert_eq!(state(|s| s.model.completed_sequence()), u64::from(slow));
        if slow {
            assert_eq!(owner.try_report().unwrap().records().count(), 1);
        }
        f.thread.poison(err);
        f.thread.poison(error(Cause::Invariant));
        assert_eq!(state(|s| s.failure), Some(err));
        assert!(f.thread.drain_completed().is_err());
        assert!(f.call(false).is_err());
        assert_eq!(f.gate.idle_checkpoint(), Ok(1));
    }
}
#[test]
fn missing_finished_checkpoint_cannot_be_repaired_by_a_later_success() {
    let mut f = Fixture::new(0);
    f.thread.finished.set(None);
    f.call(false).unwrap();
    assert_eq!(f.thread.finished.get(), None);
    assert!(f.thread.drain_completed().is_err());
    assert!(f.thread.detach().is_err());
    assert_eq!(f.thread.totals().unwrap().physical, 1);
}

// Separate explicit ignored release qualification; all existing controls remain pure.
pub(super) mod native;

mod history;
