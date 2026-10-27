//! Typed copies of retained values and their original allocation identities.
//! These observations never manufacture a native permit. Private seal internals
//! and unused MapBuffer tails are not represented as complete byte snapshots.
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime_stack::storage::StackObservationStorage;
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native::acquire::StackWordView;
use std::fmt::Debug;

fn bytes(value: &Vec<u8>) -> impl Eq + Debug + use<> {
    (
        value.clone(),
        value.as_ptr() as usize,
        value.len(),
        value.capacity(),
    )
}
pub(super) fn slot(value: &StateSlot) -> impl Eq + Debug + use<> {
    (
        value.state.clone(),
        bytes(&value.state.xstate),
        (
            value.registers_request,
            value.xstate_request,
            value.mask_request,
            value.requested_pointer,
            value.returned_pointer,
            value.returned_length,
            value.complete,
        ),
    )
}
pub(super) fn observation(value: &StackObservationStorage) -> impl Eq + Debug + use<> {
    (
        bytes(&value.maps),
        bytes(&value.smaps),
        slot(&value.state),
        value.maps_capture,
        value.smaps_capture,
        value.allocation,
        value.installed_pointers,
    )
}
fn word(value: StackWordView<'_>) -> impl Eq + Debug + use<> {
    (
        observation(value.observation),
        *value.word,
        *value.pagemap_access,
        value.association.cloned(),
        value.complete,
        value.first_failure,
    )
}
fn native(attempt: &RuntimeStackAttempt) -> impl Eq + Debug + use<> {
    let value = attempt.native.diagnostics();
    let p = attempt.native.progress();
    let control = value.profile;
    let cet = (
        control
            .cet
            .queries
            .iter()
            .map(|q| {
                q.as_ref().map(|q| {
                    (
                        q.request,
                        q.bytes.to_vec(),
                        q.requested_pointer,
                        q.returned_pointer,
                        q.returned_length,
                    )
                })
            })
            .collect::<Vec<_>>(),
        control
            .cet
            .status
            .iter()
            .map(|s| {
                (
                    s.bytes.to_vec(),
                    s.length,
                    s.open,
                    s.filesystem_request,
                    s.last_read,
                    s.filesystem,
                    s.complete,
                )
            })
            .collect::<Vec<_>>(),
        control.cet.complete,
    );
    let peek = value.memory;
    (
        (
            p.phase,
            p.first_failure,
            p.waits,
            p.queries_started,
            p.instruction_completed,
            p.nx_closed,
            p.failed_held_attempted,
            p.failed_held_failure,
            p.effects().to_vec(),
        ),
        (
            value.states.iter().map(slot).collect::<Vec<_>>(),
            value.maps.map(|m| {
                m.map(|m| {
                    (
                        m.bytes().to_vec(),
                        m.bytes().as_ptr() as usize,
                        m.length,
                        m.request,
                        m.filesystem,
                        m.complete,
                    )
                })
            }),
        ),
        (
            value
                .signals
                .iter()
                .map(|s| (s.bytes, s.request))
                .collect::<Vec<_>>(),
            value
                .debug
                .iter()
                .map(|d| (d.values, d.requests))
                .collect::<Vec<_>>(),
        ),
        (
            (
                control.debug.values,
                control.debug.requests,
                control.rseq,
                control.rseq_request,
            ),
            cet,
        ),
        (
            peek.address,
            peek.requested,
            peek.copied,
            peek.last_word,
            peek.bytes,
            peek.last_request,
            peek.complete,
        ),
        value.words.map(word),
        (
            value.initial.cloned(),
            (*value.stops).clone(),
            value.identity.cloned(),
            value.trace,
            value.call_id,
            value.claimed,
        ),
        (
            value.encoding.to_vec(),
            value.membership.to_vec(),
            value.membership.as_ptr() as usize,
            value.membership_capacity,
            value.native_payload_bytes,
        ),
        attempt.native.allocated_bytes().unwrap(),
    )
}
fn attempt(value: &RuntimeStackAttempt) -> impl Eq + Debug + use<> {
    (
        (
            value.reservation,
            value.origin,
            value.serial,
            value.until,
            value.stop.clone(),
        ),
        (
            value.before.clone(),
            bytes(&value.before.xstate),
            value.geometry,
            value.window_bytes,
            value.is_call,
        ),
        (
            value.allocated,
            value.allocation_started,
            value.allocation_ordinal,
            value.allocation_fault.before,
            value.allocation_fault.after,
            value.nested_fault,
            value.settled,
            value.stage,
            value.failure,
            value.settlement_failure,
        ),
        (
            value.source.bytes.iter().map(bytes).collect::<Vec<_>>(),
            value.source.progress,
            bytes(&value.source.identity),
            value.source.checkpoint.clone(),
            bytes(&value.source.checkpoint.xstate),
            value.source.checkpoint_stop.clone(),
        ),
        native(value),
        word(value.operand.view()),
        (
            value.operand.progress().stage,
            value.operand.progress().started,
            value.operand.progress().complete,
            value.operand.progress().first_failure,
            value.operand.allocated_bytes().unwrap(),
        ),
        value.census.as_ref().map(|p| p.test_snapshot()),
        value.call.as_ref().map(|p| p.test_snapshot()),
    )
}
fn stack(value: &RuntimeStackState) -> impl Eq + Debug + use<> {
    let progress = value.profile.progress();
    (
        (
            value.capacity,
            value.count,
            value.attempts.as_ptr() as usize,
            value.attempts.len(),
        ),
        (
            value.startup_started,
            value.startup_complete,
            value.startup_ordinal,
            value.startup_reserved,
            value.startup_actual,
            value.startup_settled,
        ),
        (
            value.pending.as_ref().map(|p| {
                (
                    p.reservation,
                    p.origin,
                    p.serial,
                    p.until,
                    p.stage,
                    p.failure,
                )
            }),
            value.failure,
            value.settlement_failure,
        ),
        (
            progress.stage,
            progress.started,
            progress.complete,
            progress.first_failure,
            value.profile.allocated_bytes().unwrap(),
        ),
        observation(value.profile.observation()),
        value.profile.identity().ok().map(|p| {
            (
                p.description().clone(),
                *p.layout_evidence(),
                p.stop().clone(),
                p.until(),
            )
        }),
        value
            .attempts
            .iter()
            .map(|v| v.as_deref().map(attempt))
            .collect::<Vec<_>>(),
        value.calls.test_snapshot(),
    )
}

/// Exact root/census/CALL/native/source prefixes survive physical cleanup.
/// The boxed closure captures owned typed values, never borrowed owner state.
pub(super) fn retained(owner: &Owner) -> impl Fn(&Owner) + use<> {
    let runtime = owner.runtime.as_ref().unwrap();
    let saved = runtime.stack.as_ref().map(stack);
    let census = runtime.census.as_ref().map(|c| c.test_stack_snapshot());
    let origin = runtime.initial_origin;
    let serial = runtime.next_execution;
    let original = runtime.sources.original_maps();
    let original = (original.0.to_vec(), *original.1);
    let baseline = runtime
        .sources
        .runtime_baseline_maps()
        .ok()
        .map(<[u8]>::to_vec);
    let windows = (0..runtime.sources.window_count())
        .map(|index| {
            let window = runtime.sources.window(index).unwrap();
            (
                window.snapshot.bytes().to_vec(),
                window.snapshot.bytes().as_ptr() as usize,
                window.snapshot.range(),
                window.target,
            )
        })
        .collect::<Vec<_>>();
    move |owner| {
        let runtime = owner.runtime.as_ref().unwrap();
        assert!(
            runtime.stack.as_ref().map(stack) == saved,
            "retained stack owner differs"
        );
        assert!(
            runtime.census.as_ref().map(|c| c.test_stack_snapshot()) == census,
            "retained census differs"
        );
        assert_eq!(runtime.initial_origin, origin);
        assert_eq!(runtime.next_execution, serial);
        let current = runtime.sources.original_maps();
        assert_eq!(current.0, original.0);
        assert_eq!(*current.1, original.1);
        assert_eq!(
            runtime
                .sources
                .runtime_baseline_maps()
                .ok()
                .map(<[u8]>::to_vec),
            baseline
        );
        assert_eq!(runtime.sources.window_count(), windows.len());
        for (index, expected) in windows.iter().enumerate() {
            let window = runtime.sources.window(index).unwrap();
            assert_eq!(
                (
                    window.snapshot.bytes().to_vec(),
                    window.snapshot.bytes().as_ptr() as usize,
                    window.snapshot.range(),
                    window.target
                ),
                *expected
            );
        }
    }
}
