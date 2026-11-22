#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! The host CPUID single-step probe and its FAIL-by-name gate.
//!
//! The pure decisions are pinned with constructed records; the live probe
//! runs once here as a positive control and prints its verdict.
#[path = "support/host_cpuid_step.rs"]
mod host_cpuid_step;

use host_cpuid_step::{
    DELIVERED_OFFSET, PROBE_STEPS, ProbeResult, StepStop, classify, require_calibrated_with,
};
use std::sync::Mutex;

static FILE_FORK: Mutex<()> = Mutex::new(());

fn trace(offset: u64) -> StepStop {
    StepStop::Trace { offset }
}

#[test]
fn probe_counts_only_exact_trace_stops_as_delivered() {
    assert_eq!(
        classify(&vec![trace(DELIVERED_OFFSET); PROBE_STEPS]),
        ProbeResult::Calibrated { steps: PROBE_STEPS }
    );
}

#[test]
fn probe_counts_a_stop_after_the_next_nop_as_lost() {
    // A lost trap after CPUID also retires the first nop: +3, not +2.
    assert_eq!(
        classify(&[trace(2), trace(3), trace(2), trace(3)]),
        ProbeResult::Uncalibrated {
            lost: 2,
            steps: 4,
            first_observed_offset: 3,
        }
    );
    assert_eq!(
        classify(&[trace(0)]),
        ProbeResult::Uncalibrated {
            lost: 1,
            steps: 1,
            first_observed_offset: 0,
        }
    );
}

#[test]
#[should_panic(expected = "host probe failed: no stop within")]
fn probe_failure_is_a_hard_failure_never_uncalibrated() {
    classify(&[
        trace(DELIVERED_OFFSET),
        trace(3),
        StepStop::Failed("no stop within 10s".to_owned()),
    ]);
}

#[test]
#[should_panic(expected = "host probe failed: no single-step was recorded")]
fn probe_with_no_recorded_step_is_a_hard_failure() {
    classify(&[]);
}

#[test]
fn gate_returns_for_a_calibrated_result() {
    require_calibrated_with(
        ProbeResult::Calibrated { steps: PROBE_STEPS },
        "host_cpuid_step_gate::gate_returns_for_a_calibrated_result",
    );
}

#[test]
#[should_panic(
    expected = "UNCALIBRATED HOST: host_cpuid_step_gate::constructed: single-step trap lost \
                after CPUID in 3/64 probe steps (first stop at +3, expected +2); native CPUID \
                completion cannot be verified on this host (issues 112, 115). Not a liteinst \
                result."
)]
fn gate_fails_by_name_for_an_uncalibrated_result() {
    require_calibrated_with(
        ProbeResult::Uncalibrated {
            lost: 3,
            steps: PROBE_STEPS,
            first_observed_offset: 3,
        },
        "host_cpuid_step_gate::constructed",
    );
}

#[test]
fn host_probe_positive_control() {
    host_cpuid_step::require_calibrated(
        &FILE_FORK,
        "host_cpuid_step_gate::host_probe_positive_control",
    );
    let result = host_cpuid_step::host_result(&FILE_FORK);
    // Printed only with --nocapture; libtest hides a passing test's output.
    println!("host cpuid step probe: {result}");
    assert_eq!(result, ProbeResult::Calibrated { steps: PROBE_STEPS });
}

#[test]
fn host_probe_measures_one_retired_nop_as_plus_three() {
    // Live negative control of the measurement: one single-step from +2, the
    // first nop, stops at +3, the offset a trap lost after CPUID reports.
    // Unlike CPUID, a nop never leaves the guest, so this holds on every host.
    assert_eq!(
        host_cpuid_step::record_steps(&FILE_FORK, DELIVERED_OFFSET, 1),
        vec![trace(DELIVERED_OFFSET + 1)]
    );
}
