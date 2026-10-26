//! Five finite native puzzles. The independent expected state comes from
//! literal instructions/raw stepping, never a fabricated completion seal.
use super::super::super::super::bootstrap::{Request as NativeRequest, StateSlot};
use super::super::super::super::tests::{Fixture, Harness, pin, reaped};
use super::super::native_tests::{bytes as memory, exact_nx_maps, maps, ready, rows, start, state};
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

pub(in crate::linux::remote::dynamic::owner::admission::runtime) mod cross_page;
mod raw;
pub(in crate::linux::remote::dynamic::owner::admission::runtime) mod support;
use support::{BASE, ENTRY, after_cleanup, begin, check, one, retained, with_owner};

/// Read-only test assertion shared by the independent selected/refusal cohort.
/// A prepared census is not itself release authority. No diagnostic is changed.
pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn assert_unreleased(
    runtime: &RuntimeOwner,
    census_prepared: &[bool],
) {
    assert_eq!(runtime.ordinary_attempts.len(), census_prepared.len());
    for (attempt, prepared) in runtime.ordinary_attempts.iter().zip(census_prepared) {
        assert_eq!(attempt.census.is_some(), *prepared);
        let progress = attempt.native.progress();
        assert!(progress.effects().is_empty());
        assert_eq!(progress.waits, [None; 7]);
        assert_eq!(progress.queries_started, [false; 7]);
        assert!(!progress.instruction_completed && !progress.nx_closed);
        assert!(attempt.native.completed().is_none());
    }
}

#[test]
fn runtime_ordinary_literal_moves_and_add_preserve_exact_checkpoints() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_literal_moves_and_add_preserve_exact_checkpoints",
        || {
            // MOV RAX,5; MOV RBX,7; ADD RAX,RBX; same-page successor marker.
            let code = [
                0x48, 0xb8, 5, 0, 0, 0, 0, 0, 0, 0, 0x48, 0xbb, 7, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x01,
                0xd8, 0x48, 0xb9, 0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0, 0xeb, 0xfe,
            ];
            let fixture = Fixture::code(&code);
            with_owner(
                &fixture,
                &code,
                |owner, initial, until, original| {
                    let mut before = begin(owner, initial, until, original);
                    for ordinal in 0..3 {
                        let mut expected = before.clone();
                        match ordinal {
                            0 => {
                                expected.registers.rax = 5;
                                expected.registers.rip += 10;
                            }
                            1 => {
                                expected.registers.rbx = 7;
                                expected.registers.rip += 10;
                            }
                            2 => {
                                expected.registers.rax = 12;
                                expected.registers.rip += 3;
                                // Exact architecturally written arithmetic flags for 5+7:
                                // PF=1; CF/AF/ZF/SF/OF=0. Every other bit stays exact.
                                expected.registers.eflags = (before.registers.eflags & !0x8d5) | 4;
                            }
                            _ => unreachable!(),
                        }
                        one(owner, until);
                        check(owner, &before, &expected, original, ordinal, until);
                        before = expected;
                    }
                    assert_eq!(before.registers.rip, ENTRY + 23);
                    assert_ne!(before.registers.rcx, 0xdead_beef);
                    retained(owner)
                },
                after_cleanup,
            );
        },
    );
}

#[test]
fn runtime_ordinary_single_step_stops_before_same_page_marker() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_single_step_stops_before_same_page_marker",
        || {
            let marker = 0x0123_4567_89ab_cdef;
            let code = [
                0x90, 0x48, 0xbb, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xeb, 0xfe,
            ];
            let fixture = Fixture::code(&code);
            with_owner(
                &fixture,
                &code,
                |owner, initial, until, original| {
                    let before = begin(owner, initial, until, original);
                    assert_ne!(before.registers.rbx, marker);
                    let mut expected = before.clone();
                    expected.registers.rip += 1;
                    one(owner, until);
                    check(owner, &before, &expected, original, 0, until);
                    assert_eq!(state(owner.pid).registers.rbx, before.registers.rbx);
                    // Then independently show that the untouched marker really changes RBX
                    // when it is the one original instruction admitted by the next call.
                    let before = expected;
                    let mut expected = before.clone();
                    expected.registers.rbx = marker;
                    expected.registers.rip += 10;
                    one(owner, until);
                    check(owner, &before, &expected, original, 1, until);
                    retained(owner)
                },
                after_cleanup,
            );
        },
    );
}

#[test]
fn runtime_ordinary_conditional_branch_preserves_complete_state() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_conditional_branch_preserves_complete_state",
        || {
            for taken in [false, true] {
                // MOV EAX,input; CMP RAX,0; JZ +5; MOV ECX,marker; NOP; loop.
                let value = u8::from(!taken);
                let code = [
                    0xb8, value, 0, 0, 0, 0x48, 0x83, 0xf8, 0, 0x74, 5, 0xb9, 0xef, 0xbe, 0xad,
                    0xde, 0x90, 0xeb, 0xfe,
                ];
                let fixture = Fixture::code(&code);
                with_owner(
                    &fixture,
                    &code,
                    |owner, initial, until, original| {
                        let mut before = begin(owner, initial, until, original);
                        for ordinal in 0..3 {
                            let mut expected = before.clone();
                            match ordinal {
                                0 => {
                                    expected.registers.rax = u64::from(value);
                                    expected.registers.rip += 5;
                                }
                                1 => {
                                    expected.registers.rip += 4;
                                    expected.registers.eflags = (before.registers.eflags & !0x8d5)
                                        | if taken { 0x44 } else { 0 };
                                }
                                2 => {
                                    expected.registers.rip = ENTRY + if taken { 16 } else { 11 };
                                }
                                _ => unreachable!(),
                            }
                            one(owner, until);
                            check(owner, &before, &expected, original, ordinal, until);
                            before = expected;
                        }
                        assert_ne!(before.registers.rcx, 0xdead_beef);
                        retained(owner)
                    },
                    after_cleanup,
                );
            }
        },
    );
}

#[test]
fn runtime_ordinary_same_pc_loop_consumes_distinct_origin() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_same_pc_loop_consumes_distinct_origin",
        || {
            let code = [0xeb, 0xfe];
            let fixture = Fixture::code(&code);
            with_owner(
                &fixture,
                &code,
                |owner, initial, until, original| {
                    let expected = begin(owner, initial, until, original);
                    let mut origins = vec![owner.runtime.as_ref().unwrap().initial_origin.unwrap()];
                    let mut prior_token = owner
                        .runtime
                        .as_ref()
                        .unwrap()
                        .native
                        .as_ref()
                        .unwrap()
                        .admission_current(
                            owner
                                .runtime
                                .as_ref()
                                .unwrap()
                                .sources
                                .current_binding()
                                .unwrap()
                                .stop
                                .identity
                                .task,
                        )
                        .unwrap()
                        .token;
                    for ordinal in 0..3 {
                        one(owner, until);
                        check(owner, &expected, &expected, original, ordinal, until);
                        let runtime = owner.runtime.as_ref().unwrap();
                        let origin = runtime.initial_origin.unwrap();
                        assert!(!origins.contains(&origin));
                        origins.push(origin);
                        let current = runtime
                            .census
                            .as_ref()
                            .unwrap()
                            .current_observation(origin)
                            .unwrap();
                        assert_eq!(current.logical_pc, ENTRY);
                        assert!(current.token.sequence > prior_token.sequence);
                        assert_eq!(current.token.task, prior_token.task);
                        prior_token = current.token.clone();
                    }
                    assert_eq!(origins.len(), 4);
                    retained(owner)
                },
                after_cleanup,
            );
        },
    );
}

#[test]
fn runtime_ordinary_nop_matches_independent_raw_single_step() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_nop_matches_independent_raw_single_step",
        || {
            let code = [
                0x90, 0x48, 0xbb, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xeb, 0xfe,
            ];
            let fixture = Fixture::code(&code);
            let raw = raw::nop(&fixture, &code);
            with_owner(
                &fixture,
                &code,
                |owner, initial, until, original| {
                    let before = begin(owner, initial, until, original);
                    let mut expected = before.clone();
                    expected.registers.rip += 1;
                    one(owner, until);
                    check(owner, &before, &expected, original, 0, until);
                    let after = state(owner.pid);
                    raw.compare(&before, &after, &original.maps);
                    retained(owner)
                },
                after_cleanup,
            );
        },
    );
}
