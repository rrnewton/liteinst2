//! Dedicated initial one-pair R/RX native controls. All three require real
//! original-stop ownership; model inventories never manufacture completion.
use super::super::runtime_capture::{CaptureFailure, CaptureFailureKind, CaptureStage};
use super::super::source_identity::{SourceReadOperation, SourceReadProgress};
use super::native_tests::{
    NativeMap, bytes as memory, maps as read_maps, ready, rows, start, state,
};
use super::*;
use crate::linux::remote::dynamic::owner::bootstrap::{
    InitialBootstrapFailureKind, InitialCoalescenceStage, MapBuffer, Request as NativeRequest,
    StateSlot,
};
use crate::linux::remote::dynamic::owner::tests::{Fixture, Harness, pin, reaped};
use liteinst_admission::entries::{Completeness, EntryProvenance};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

mod check;
mod maps;
mod retained;
mod support;

const BASE: u64 = 0x400000;
const ENTRY: u64 = BASE + 4096;
const END: u64 = BASE + 8192;
const MARKER: u64 = 0x0123_4567_89ab_cdef;
// NOP; MOV RBX,marker; loop. Exactly one original NOP is authorized below.
const CODE: &[u8] = &[
    0x90, 0x48, 0xbb, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xeb, 0xfe,
];

#[test]
fn initial_runtime_coalescence_merges_pair_and_recloses_original_rx_fetch() {
    super::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::coalescence_native_tests::initial_runtime_coalescence_merges_pair_and_recloses_original_rx_fetch",
        || {
            support::with_owner(
                |owner, initial, until, before| {
                    let actual = ready(start(
                        owner,
                        initial,
                        DynamicRuntimeOptions::default(),
                        until,
                    ));
                    let restored = check::ready(owner, before, &actual, until);
                    let baseline = read_maps(owner.pid);
                    let mut expected = restored.clone();
                    expected.registers.rip += 1;
                    super::ordinary::native_tests::coalescence::one(owner, until);
                    super::ordinary::native_tests::coalescence::check(
                        owner,
                        &restored,
                        &expected,
                        &before.bytes[4096..],
                        &baseline,
                        until,
                        |baseline, opened| maps::opened(baseline, opened, &before.pair),
                    );
                    before.bytes_unchanged(owner, until);
                    assert_eq!(read_maps(owner.pid), baseline);
                    assert_eq!(state(owner.pid), expected);
                    assert_eq!(expected.registers.rbx, restored.registers.rbx);
                    assert_ne!(
                        expected.registers.rbx, MARKER,
                        "same-page successor executed"
                    );
                    assert_eq!(expected.registers.rip, ENTRY + 1);
                    let runtime = owner.runtime.as_ref().unwrap();
                    assert_eq!(
                        runtime.pages,
                        [RuntimePage {
                            address: ENTRY,
                            window: 0,
                            executable: false
                        }]
                    );
                    assert_eq!(
                        runtime.sources.window(0).unwrap().snapshot.bytes(),
                        &before.bytes[4096..]
                    );
                    (
                        retained::capture(owner),
                        super::ordinary::native_tests::support::retained(owner),
                    )
                },
                |owner, (startup, ordinary)| {
                    retained::after_cleanup(owner, startup);
                    super::ordinary::native_tests::support::after_cleanup(owner, ordinary);
                },
            );
        },
    );
}

#[test]
fn initial_runtime_coalescence_one_short_capacity_keeps_pristine_exec() {
    super::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::coalescence_native_tests::initial_runtime_coalescence_one_short_capacity_keeps_pristine_exec",
        || {
            for capture_bound in [false, true] {
                support::with_owner(
                    |owner, initial, until, before| {
                        let mut options = DynamicRuntimeOptions::default();
                        // The source is one page even when its actual container is two.
                        // Keep this profile valid while setting the total to one short.
                        if capture_bound {
                            options.capture.max_window_bytes = 8192;
                        }
                        let mut prospective = support::allocate(&options, until);
                        let first = prospective.startup.charged();
                        prospective
                            .sources
                            .capture_original(owner, initial)
                            .unwrap();
                        let (plan, executable) = prospective
                            .sources
                            .coalescence_plan(owner, initial)
                            .unwrap()
                            .unwrap();
                        assert_eq!(plan.pair_range(), BASE..END);
                        assert_eq!(plan.rx_range(), ENTRY..END);
                        let sizing = prospective
                            .sources
                            .preflight_coalesced(&plan, executable)
                            .unwrap();
                        assert_eq!(sizing.window_bytes(), 4096);
                        assert_eq!(sizing.pair_capture_bytes(), 16384);
                        assert_eq!(sizing.total_capture_bytes().unwrap(), 20480);
                        let (storage, progress) = prospective.sources.original_maps();
                        let original = initial_maps_prefix(storage, progress).unwrap();
                        assert_eq!(original, before.maps);
                        let extra = RuntimeOwner::coalescence_reservation(
                            &plan,
                            original,
                            support::profile(&options),
                        )
                        .unwrap();
                        let bootstrap = InitialBootstrapShape::from_original(original)
                            .unwrap()
                            .reservation_bytes()
                            .unwrap()
                            .checked_sub(size_of::<PreparedInitialBootstrap>())
                            .unwrap();
                        assert!(extra >= 3 * 65536 + 2 * MAX_XSTATE + 16384 && bootstrap > 0);
                        if capture_bound {
                            options.capture.max_total_capture_bytes = sizing
                                .total_capture_bytes()
                                .unwrap()
                                .checked_sub(1)
                                .unwrap();
                            support::profile(&options).validate().unwrap();
                        } else {
                            options.limits.source_fact_bytes = first
                                .source_fact_bytes
                                .checked_add(extra)
                                .unwrap()
                                .checked_add(bootstrap)
                                .unwrap()
                                .checked_sub(1)
                                .unwrap();
                        }
                        drop(prospective);
                        let result = start(owner, initial, options, until);
                        if capture_bound {
                            assert!(matches!(
                                result,
                                Err(GateError::Refused(
                                    "initial runtime pair and overlapping capture bytes exceed their bound"
                                ))
                            ));
                        } else {
                            assert!(matches!(
                                result,
                                Err(GateError::Refused(
                                    "dynamic continuation lifetime capacity exhausted"
                                ))
                            ));
                        }
                        before.pristine_after_refusal(owner, initial, until);
                        let runtime = owner.runtime.as_ref().unwrap();
                        assert!(
                            runtime.bootstrap.is_none()
                                && runtime.native.is_none()
                                && runtime.census.is_none()
                        );
                        assert!(owner.lifecycle.is_none() && owner.admission.is_none());
                        assert!(
                            !runtime.ready_issued
                                && runtime.initial_origin.is_none()
                                && runtime.pages.is_empty()
                        );
                        assert!(runtime.sources.original_complete());
                        let (storage, progress) = runtime.sources.original_maps();
                        assert_eq!(initial_maps_prefix(storage, progress).unwrap(), before.maps);
                        assert!(
                            !runtime.sources.capture_complete()
                                && !runtime.sources.recheck_complete()
                        );
                        if capture_bound {
                            assert_eq!(runtime.stage, RuntimeStage::OriginalCapture);
                            assert!(runtime.coalescence.is_none());
                            assert_eq!(runtime.startup.charged(), first);
                            let failure = runtime.sources.failure().unwrap();
                            assert_eq!(failure.stage, CaptureStage::CoalescencePreflight);
                            assert_eq!(
                                failure.kind,
                                CaptureFailureKind::Refused(
                                    "initial runtime pair and overlapping capture bytes exceed their bound"
                                )
                            );
                        } else {
                            assert_eq!(runtime.stage, RuntimeStage::BootstrapAllocation);
                            let q = runtime.coalescence.as_ref().unwrap();
                            let d = q.diagnostics();
                            assert_eq!(d.stage, InitialCoalescenceStage::OriginalCaptured);
                            assert_eq!(
                                d.first_failure,
                                Some(InitialBootstrapFailureKind::Invalid(
                                    "dynamic continuation lifetime capacity exhausted"
                                ))
                            );
                            assert_eq!(d.original_bytes, before.bytes);
                            assert!(d.final_bytes.iter().all(|byte| *byte == 0));
                            assert!(
                                d.read_progress[0].complete && d.read_progress[0].failure.is_none()
                            );
                            assert_eq!(d.read_progress[0].copied_bytes, 8192);
                            assert_eq!(d.read_progress[1], SourceReadProgress::default());
                            assert!(d.states.iter().all(|state| !state.complete
                                && state.registers_request.is_none()
                                && state.xstate_request.is_none()
                                && state.mask_request.is_none()));
                            for map in d.maps {
                                let map = map.as_ref().unwrap();
                                assert!(
                                    !map.complete
                                        && map.bytes().is_empty()
                                        && map.request.is_none()
                                );
                            }
                            assert!(
                                d.before_stop.is_none()
                                    && d.after_stop.is_none()
                                    && d.final_stop.is_none()
                            );
                            assert!(
                                d.call.wait.is_none()
                                    && !d.call.queries_started
                                    && !d.call.complete
                            );
                            assert!(d.projection.is_none() && !d.output_transferred);
                            q.validate_allocations(None).unwrap();
                            let mut charged = first;
                            charged.source_fact_bytes =
                                charged.source_fact_bytes.checked_add(extra).unwrap();
                            assert_eq!(
                                runtime.startup.charged(),
                                charged,
                                "the accepted reservation is not refunded on later refusal"
                            );
                        }
                        assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
                        retained::capture(owner)
                    },
                    retained::after_cleanup,
                );
            }
        },
    );
}

#[test]
fn initial_runtime_coalescence_unwind_retains_native_evidence_through_cleanup() {
    super::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::coalescence_native_tests::initial_runtime_coalescence_unwind_retains_native_evidence_through_cleanup",
        || {
            support::with_owner(
                |owner, initial, until, before| {
                    owner.runtime_panic_after_bootstrap = true;
                    let outcome = catch_unwind(AssertUnwindSafe(|| {
                        start(owner, initial, DynamicRuntimeOptions::default(), until)
                    }));
                    let payload = match outcome {
                        Err(payload) => payload,
                        Ok(_) => panic!("bootstrap unwind hook did not run"),
                    };
                    let message = payload
                        .downcast_ref::<&str>()
                        .copied()
                        .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
                    assert_eq!(
                        message,
                        Some("injected runtime unwind after actual bootstrap custody transfer")
                    );
                    assert!(!owner.runtime_panic_after_bootstrap);
                    check::bootstrap(owner, before, until, true);
                    let runtime = owner.runtime.as_ref().unwrap();
                    assert_eq!(runtime.stage, RuntimeStage::Bootstrap);
                    assert!(
                        runtime.census.is_none()
                            && runtime.initial_origin.is_none()
                            && !runtime.ready_issued
                    );
                    assert!(
                        runtime.pages.is_empty()
                            && runtime.ordinary_attempts.is_empty()
                            && runtime.selected_attempts.is_empty()
                    );
                    assert!(
                        runtime.sources.original_complete()
                            && !runtime.sources.capture_complete()
                            && !runtime.sources.recheck_complete()
                    );
                    assert!(runtime.sources.current_binding().is_none());
                    assert_eq!(
                        runtime.sources.failure(),
                        Some(CaptureFailure {
                            stage: CaptureStage::CoalescencePreflight,
                            window: None,
                            kind: CaptureFailureKind::Aborted,
                        })
                    );
                    // This direct-owner test catches the rethrown panic before
                    // Owner::serve's outer close path. The wrapper below owns
                    // mandatory physical cleanup; no close flag is fabricated.
                    assert!(
                        runtime.startup.charged().source_fact_bytes
                            <= DynamicAdmissionLimits::default().source_fact_bytes
                    );
                    retained::capture(owner)
                },
                retained::after_cleanup,
            );
        },
    );
}
