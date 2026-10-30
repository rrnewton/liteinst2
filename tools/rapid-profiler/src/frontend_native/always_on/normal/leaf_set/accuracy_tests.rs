//! Real Session/bank/receipt controls with inert geometry; no native entry.
use super::tests::{ENTRY, Fixture, IDS};
use super::*;
use liteinst2::contracts::SourceIdentity;

fn site(n: usize) -> Arc<site::ordinary::LeafSetSite> {
    let geometry: Vec<_> = ENTRY[..n]
        .iter()
        .map(|&entry| (entry, entry + 32, vec![entry + 16, entry + 24]))
        .collect();
    site::ordinary::LeafSetSite::synthetic(
        CodeIdentity {
            source: SourceIdentity([193; 32]),
            mapping: ENTRY[0],
            generation: 1,
        },
        &geometry,
    )
}
fn prepared(n: usize, policy: Policy) -> PreparedNormalLeafSetSessionController {
    PreparedNormalLeafSetSessionController::prepare_for(
        site(n),
        71,
        &IDS[..n],
        policy.retained(),
        Some(policy),
    )
    .unwrap()
}
fn controller(
    n: usize,
    policy: Policy,
) -> (NormalLeafSetSessionController, Vec<IntervalEpochStorage>) {
    let mut prepared = prepared(n, policy);
    let banks = prepared.prepare_epoch_storage().unwrap();
    assert_eq!(banks.len(), 3);
    // SAFETY: inert metadata only, no published source or native entry.
    let (controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    assert_eq!(client.accuracy_policy(), Some(policy));
    assert_eq!(
        controller
            .history_window()
            .unwrap()
            .stream()
            .accuracy_policy(),
        Some(policy)
    );
    drop(client);
    (controller, banks)
}
fn fixture(policy: Policy) -> Fixture {
    let (mut controller, mut banks) = controller(2, policy);
    let epoch = controller.stage_prepared(banks.pop().unwrap()).unwrap();
    let binding = Arc::clone(&controller.0.binding);
    let model = binding.session.register_thread(7).unwrap();
    let mut state = NormalState::new(
        binding,
        7,
        ReadableStack {
            start: 0x7000,
            end: 0x100000,
        },
        IntervalJournal::allocate(),
        model,
    );
    state.journal.header(state.tid, 0);
    controller.arm(&epoch).unwrap();
    Fixture {
        state,
        controller,
        epoch: Some(epoch),
        banks,
    }
}

#[test]
fn accuracy_bindings_require_explicit_policy_exact_config_and_original_limits() {
    for n in 1..=4 {
        for k in [1, 10, 100, 1000] {
            for ms in [1, 10, 100] {
                let p = Policy::accuracy(k, ms, 520, 4096).unwrap();
                let mut prepared = prepared(n, p);
                let limits = prepared.inner.limits;
                let config = prepared.config;
                assert_eq!(
                    limits,
                    Limits {
                        epochs: 3,
                        threads: 1,
                        depth: 1,
                        records_per_epoch: n * k,
                        actions: 8
                    }
                );
                assert_eq!(
                    config,
                    Config {
                        retained_per_function: k,
                        max_inflight: 1,
                        max_invocations: n * k
                    }
                );
                assert!(profile_matches(&prepared.inner.profile, limits, config));
                for bad in [
                    Config {
                        retained_per_function: k + 1,
                        ..config
                    },
                    Config {
                        max_inflight: 2,
                        ..config
                    },
                    Config {
                        max_invocations: n * k + 1,
                        ..config
                    },
                ] {
                    assert!(!profile_matches(&prepared.inner.profile, limits, bad));
                }
                for bad in [
                    Limits {
                        epochs: 4,
                        ..limits
                    },
                    Limits {
                        threads: 2,
                        ..limits
                    },
                    Limits { depth: 2, ..limits },
                    Limits {
                        records_per_epoch: n * k + 1,
                        ..limits
                    },
                    Limits {
                        actions: 9,
                        ..limits
                    },
                ] {
                    assert!(!profile_matches(&prepared.inner.profile, bad, config));
                }
                let before = prepared.inner.session.snapshot_for_bridge().unwrap();
                if let BindingProfile::LeafSet { accuracy, .. } = &mut prepared.inner.profile {
                    *accuracy = Some(Policy::ten_ms(10, 520, 4096).unwrap());
                } else {
                    panic!();
                }
                assert!(prepared.prepare_epoch_storage().is_err());
                assert!(!prepared.banks_prepared);
                assert_eq!(
                    prepared.inner.session.snapshot_for_bridge().unwrap(),
                    before
                );
            }
        }
    }
    let old = Policy::ten_ms(10, 520, 4096).unwrap();
    assert!(
        PreparedNormalLeafSetSessionController::prepare_for(site(1), 71, &IDS[..1], 10, Some(old))
            .is_err()
    );
    for k in [1, 100] {
        assert!(
            PreparedNormalLeafSetSessionController::prepare(site(1), 71, &IDS[..1], k).is_err()
        );
    }
    let p = Policy::accuracy(1, 1, 520, 4096).unwrap();
    assert!(
        PreparedNormalLeafSetSessionController::prepare_for(site(1), 71, &IDS[..1], 100, Some(p))
            .is_err()
    );
    assert!(
        PreparedNormalLeafSetSessionController::prepare_for(site(2), 71, &IDS[..1], 1, Some(p))
            .is_err()
    );
    for ids in [vec![], vec![IDS[0]; 2], vec![IDS[0]; 5]] {
        assert!(
            PreparedNormalLeafSetSessionController::prepare_for(site(1), 71, &ids, 1, Some(p))
                .is_err()
        );
    }
}

#[test]
fn old_and_accuracy_banks_cannot_substitute_even_at_identical_k_and_period() {
    let p = Policy::accuracy(10, 10, 520, 4096).unwrap();
    let (mut accuracy, mut new_banks) = controller(2, p);
    let (mut old, mut old_banks) = tests::controller(2, 10);
    assert_eq!(
        old.history_window().unwrap().stream().accuracy_policy(),
        None
    );
    assert_ne!(
        accuracy.history_window().unwrap().stream(),
        old.history_window().unwrap().stream()
    );
    for (target, bank) in [
        (&mut accuracy, old_banks.pop().unwrap()),
        (&mut old, new_banks.pop().unwrap()),
    ] {
        let fingerprint = bank.test_fingerprint();
        let before = target.0.binding.session.snapshot_for_bridge().unwrap();
        let (error, bank) = match target.stage_prepared(bank) {
            Err(pair) => pair,
            Ok(_) => panic!("cross-profile bank accepted"),
        };
        assert_eq!(error, super::error(Cause::Epoch));
        assert_eq!(bank.test_fingerprint(), fingerprint);
        assert_eq!(
            target.0.binding.session.snapshot_for_bridge().unwrap(),
            before
        );
    }
    let bank = new_banks.pop().unwrap();
    let fingerprint = bank.test_fingerprint();
    let (error, bank) = match accuracy.0.stage_prepared(bank) {
        Err(pair) => pair,
        Ok(_) => panic!("single facade accepted leaf-set bank"),
    };
    assert_eq!(error, super::error(Cause::Identity));
    assert_eq!(bank.test_fingerprint(), fingerprint);
}

#[test]
fn matrix_uses_real_k_closure_receipt_acknowledgement_recycled_banks_and_history() {
    for k in [1, 10, 100, 1000] {
        for ms in [1, 10, 100] {
            let mut f = fixture(Policy::accuracy(k, ms, 520, 4096).unwrap());
            let first_history = f.controller.drain_history().unwrap().unwrap();
            for i in 0..k {
                f.call(0);
                if (i + 1) % CALLS == 0 {
                    f.transfer();
                }
            }
            f.call(0); // mandatory hook still records the first FunctionClosed call
            let old = f.epoch.take().unwrap();
            let generation = old.generation();
            let next = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
            f.controller.arm(&next).unwrap();
            let second_history = f.controller.drain_history().unwrap().unwrap();
            assert!(second_history.follows(&first_history));
            let rows: Vec<_> = f
                .controller
                .report(&old)
                .unwrap()
                .unwrap()
                .records()
                .collect();
            assert_eq!(rows.len(), k);
            for (i, row) in rows.iter().enumerate() {
                assert_eq!(row.record.admission.function, IDS[0]);
                assert_eq!(row.record.admission.invocation, i);
            }
            let old = match f.controller.reclaim_storage(old) {
                Err((EpochStorageReclaimError::SharedOwner, epoch)) => epoch,
                _ => panic!("pending closed receipt lost its epoch owner"),
            };
            let batch = f.transfer(); // existing acknowledgement consumes the saved receipt
            assert_eq!(batch.history_high_water(), 2);
            let last = batch.records().last().unwrap();
            assert_eq!(last.function, IDS[0]);
            assert_eq!(
                last.record.raw.owner,
                RawIntervalOwner::FunctionClosed {
                    generation: generation.get()
                }
            );
            f.banks.push(tests::reclaim(&mut f.controller, old));
            f.call(1);
            let batch = f.transfer();
            assert_eq!(batch.records().len(), 1);
            assert_eq!(batch.records()[0].function, IDS[1]);
            assert_eq!(
                batch.records()[0].record.raw.owner,
                RawIntervalOwner::Sampled {
                    generation: next.generation().get(),
                    invocation: 0
                }
            );
            f.controller.disarm(&next).unwrap();
            let third_history = f.controller.drain_history().unwrap().unwrap();
            assert!(third_history.follows(&second_history));
            assert_eq!(third_history.range().end, 3);
            f.banks.push(tests::reclaim(&mut f.controller, next));
            assert_eq!(f.banks.len(), 3);
            assert_eq!(f.state.totals.entered, k as u64 + 2);
            assert_eq!(
                (f.state.totals.completed, f.state.totals.unsampled),
                (k as u64 + 1, 1)
            );
        }
    }
}
