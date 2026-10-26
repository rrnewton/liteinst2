//! Comparator-only synthetic control records. No native permission/completion
//! is constructed or exercised by these fixtures.
use super::*;
fn stop() -> AdmissionStop {
    let registry = crate::lifecycle::LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 1,
            processes: 1,
            address_spaces: 1,
            obligations: 1,
        },
        42,
        0x401000,
    )
    .unwrap();
    let task = registry.root_task();
    let row = registry.task(task).unwrap();
    AdmissionStop {
        token: DynamicStop {
            session: 7,
            tid: 42,
            task: Some(task),
            sequence: 17,
        },
        identity: DynamicTask {
            task,
            process: row.process,
            address_space: row.address_space,
            generation: 0,
        },
        phase: AdmissionPhase::Restored,
        signal: None,
    }
}
fn model_profile(dr6: u64) -> ControlProfile {
    let mut value = ControlProfile {
        complete: true,
        tid: Some(42),
        rseq_request: Some(Request {
            result: 24,
            errno: None,
        }),
        ..ControlProfile::default()
    };
    value.cet.complete = true; // synthetic certificate predicate, never a query claim
    value.debug.values = [0, 0, 0, 0, dr6, 0];
    value.debug.requests = std::array::from_fn(|index| {
        Some(Request {
            result: value.debug.values[index] as i64,
            errno: None,
        })
    });
    value
}
fn invalid<T>(value: Result<T, LaunchError>, reason: &'static str) {
    assert!(matches!(value, Err(LaunchError::Invalid(actual)) if actual == reason));
}
#[test]
fn owned_native_lineage_never_accepts_an_unrelated_or_refreshed_checkpoint() {
    let stop = stop();
    let lineage = ControlLineage {
        checkpoint: stop.clone(),
        dr6: DR_BASE,
    };
    lineage
        .authenticate(&stop, &model_profile(DR_BASE))
        .unwrap();
    for field in 0..6 {
        let mut changed = stop.clone();
        match field {
            0 => changed.token.sequence += 1,
            1 => changed.token.tid += 1,
            2 => changed.token.session += 1,
            3 => changed.token.task = None,
            4 => changed.identity.generation += 1,
            _ => changed.phase = AdmissionPhase::NativeCompleted,
        }
        invalid(
            lineage.authenticate(&changed, &model_profile(DR_BASE)),
            "owned instruction control lineage is stale",
        );
    }
    invalid(
        lineage.authenticate(&stop, &model_profile(DR_TRACE)),
        "owned instruction debug profile differs",
    );
    let mut foreign = model_profile(DR_BASE);
    foreign.tid = Some(43);
    invalid(
        lineage.authenticate(&stop, &foreign),
        "owned instruction control lineage is stale",
    );
    let prior_step = ControlLineage {
        checkpoint: stop.clone(),
        dr6: DR_TRACE,
    };
    prior_step
        .authenticate(&stop, &model_profile(DR_TRACE))
        .unwrap();
    invalid(
        prior_step.authenticate(&stop, &model_profile(DR_BASE)),
        "owned instruction debug profile differs",
    );
}
#[test]
fn owned_native_profile_requires_all_rseq_bytes_exact_count_and_cet_completion() {
    for index in 0..24 {
        let mut changed = model_profile(DR_BASE);
        changed.rseq[index] = 1;
        invalid(
            changed.require(DR_BASE),
            "owned instruction control profile incomplete",
        );
    }
    for result in [0, 1, 23, 25, -1] {
        let mut changed = model_profile(DR_BASE);
        changed.rseq_request = Some(Request {
            result,
            errno: None,
        });
        invalid(
            changed.require(DR_BASE),
            "owned instruction control profile incomplete",
        );
    }
    let mut changed = model_profile(DR_BASE);
    changed.rseq_request = Some(Request {
        result: -1,
        errno: Some(libc::EINVAL),
    });
    invalid(
        changed.require(DR_BASE),
        "owned instruction control profile incomplete",
    );
    let mut changed = model_profile(DR_BASE);
    changed.cet.complete = false;
    invalid(
        changed.require(DR_BASE),
        "owned instruction control profile incomplete",
    );
    let mut changed = model_profile(DR_BASE);
    changed.complete = false;
    invalid(
        changed.require(DR_BASE),
        "owned instruction control profile incomplete",
    );
}
