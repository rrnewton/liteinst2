//! Closed original-resident stack-word native controls. Model mutations are
//! explicitly labelled and never construct a native operand/completion.
use super::*;
use crate::linux::remote::dynamic::admission::{RuntimeKernelProfile, RuntimeStackProfile};
use crate::linux::remote::dynamic::owner::admission::runtime::native_tests::{
    bytes as memory, exact_nx_maps, maps, ready, rows, start, state,
};
use crate::linux::remote::dynamic::owner::bootstrap::{Request as NativeRequest, StateSlot};
use crate::linux::remote::dynamic::owner::trusted::{AdmissionPhase, TaskStateSnapshot};
use crate::linux::remote::dynamic::owner::{
    broker,
    tests::{Fixture, Harness, pin, reaped},
};
use crate::linux::remote::dynamic::{DynamicResume, Request as DynamicRequest, Response};
use crate::linux::remote::{MAX_XSTATE, NT_X86_XSTATE};
use std::mem::size_of;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

mod allocation;
mod compare;
mod connected;
mod fault;
mod fixture;
mod ledger;
mod models;
mod raw;
mod refusal;
mod retention;
mod seed;
mod support;
use fixture::{BASE, CALLEE, MARK, Program};
use support::Before;

fn positive(program: Program) {
    let reference = raw::pair(&program);
    let _ = support::with_owner(
        &program,
        true,
        |owner, initial, until, original| {
            let mut before = support::begin(owner, initial, until, original, support::options());
            for ordinal in 0..program.setup {
                let expected = compare::setup(&before, ordinal);
                support::ordinary(owner, until);
                assert_eq!(state(owner.pid), expected);
                assert_eq!(
                    original.read_stack(owner, until),
                    *original.stack.as_ref().unwrap()
                );
                before = expected;
            }
            assert_eq!(before.registers.rip, program.call_pc);
            ledger::install(owner);
            let call_start = owner
                .runtime
                .as_ref()
                .unwrap()
                .census
                .as_ref()
                .unwrap()
                .history()
                .len();
            let stack_before = original.read_stack(owner, until);
            let call_after = compare::successor(&before, program.target, true);
            support::one(owner, until).unwrap();
            compare::completed(
                owner,
                original,
                compare::CompletionExpected {
                    before: &before,
                    after: &call_after,
                    stack_before: &stack_before,
                    ordinal: 0,
                    call: true,
                    next: program.next,
                },
                until,
            );
            ledger::chain(owner, 0, call_start);
            if program.entry == BASE + 4096 && program.setup == 0 {
                models::sensitivity(owner, 0);
            }
            ledger::check(owner, 1);
            let pushed = original.read_stack(owner, until);
            let ret_start = owner
                .runtime
                .as_ref()
                .unwrap()
                .census
                .as_ref()
                .unwrap()
                .history()
                .len();
            let ret_after = compare::successor(&call_after, program.next, false);
            support::one(owner, until).unwrap();
            compare::completed(
                owner,
                original,
                compare::CompletionExpected {
                    before: &call_after,
                    after: &ret_after,
                    stack_before: &pushed,
                    ordinal: 1,
                    call: false,
                    next: program.target + 1,
                },
                until,
            );
            assert_eq!(original.read_stack(owner, until), pushed);
            ledger::chain(owner, 1, ret_start);
            ledger::check(owner, 1);
            // Full same-lane equations were checked above and by raw::pair. Across
            // independent ASLR lanes compare the exact operation, never rewritten
            // full register files. Absolute RSP is retained with its own stack row.
            assert_eq!(
                reference.call.before.registers.rsp - reference.call.after.registers.rsp,
                before.registers.rsp - call_after.registers.rsp
            );
            assert_eq!(
                reference.ret.after.registers.rsp - reference.ret.before.registers.rsp,
                ret_after.registers.rsp - call_after.registers.rsp
            );
            assert_eq!(reference.call.after.registers.rip, call_after.registers.rip);
            assert_eq!(reference.ret.after.registers.rip, ret_after.registers.rip);
            assert_ne!(before.registers.r12, MARK);
            assert_eq!(ret_after.registers.r12, before.registers.r12);
            retention::retained(owner)
        },
        |owner, retained| {
            retained(owner);
            ledger::check(owner, 1);
        },
    );
}

#[test]
fn runtime_stack_call_ret_matches_raw_full_state_and_stack() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_call_ret_matches_raw_full_state_and_stack",
        || positive(Program::call(4096, false).with_initial_call_word_seed()),
    );
}
#[test]
fn runtime_stack_boundary_call_ret_keeps_unexecuted_next_page_nx() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_boundary_call_ret_keeps_unexecuted_next_page_nx",
        || positive(Program::call(4091, false).with_initial_call_word_seed()),
    );
}
#[test]
fn runtime_stack_crossing_call_opens_exact_two_pages() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_crossing_call_opens_exact_two_pages",
        || positive(Program::call(4093, false).with_initial_call_word_seed()),
    );
}
#[test]
fn runtime_stack_unaligned_two_page_word_preserves_neighbors() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_unaligned_two_page_word_preserves_neighbors",
        || positive(Program::call(4096, true)),
    );
}

#[test]
fn runtime_stack_metadata_changes_refuse_with_actual_records() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_metadata_changes_refuse_with_actual_records",
        refusal::metadata,
    );
}

#[test]
fn runtime_stack_nonresident_word_refuses_before_peek() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_nonresident_word_refuses_before_peek",
        refusal::nonresident,
    );
}

#[test]
fn runtime_stack_nonexclusive_word_refuses_with_two_owned_pins() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_nonexclusive_word_refuses_with_two_owned_pins",
        refusal::nonexclusive,
    );
}

#[test]
fn runtime_stack_raw_io_failures_keep_request_prefix_and_cleanup() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_raw_io_failures_keep_request_prefix_and_cleanup",
        refusal::raw_io,
    );
}

#[test]
fn runtime_stack_after_a_ac_refuses_before_private_effects() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_after_a_ac_refuses_before_private_effects",
        || {
            fault::run(
                runtime_stack_native::InterventionPoint::AfterA,
                runtime_stack_native::InterventionKind::Ac,
            )
        },
    );
}

#[test]
fn runtime_stack_after_a_pkru_refuses_before_private_effects() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_after_a_pkru_refuses_before_private_effects",
        || {
            fault::run(
                runtime_stack_native::InterventionPoint::AfterA,
                runtime_stack_native::InterventionKind::PkruKeyZeroDeny,
            )
        },
    );
}

#[test]
fn runtime_stack_after_b_ac_retains_actual_alignment_fault() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_after_b_ac_retains_actual_alignment_fault",
        || {
            fault::run(
                runtime_stack_native::InterventionPoint::AfterB,
                runtime_stack_native::InterventionKind::Ac,
            )
        },
    );
}

#[test]
fn runtime_stack_after_b_pkru_retains_actual_access_fault() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_after_b_pkru_retains_actual_access_fault",
        || {
            fault::run(
                runtime_stack_native::InterventionPoint::AfterB,
                runtime_stack_native::InterventionKind::PkruKeyZeroDeny,
            )
        },
    );
}

#[test]
fn runtime_stack_kernel_selected_ordinary_chain_preserves_call_history() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_kernel_selected_ordinary_chain_preserves_call_history",
        connected::mixed,
    );
}

#[test]
fn runtime_stack_default_encodings_targets_and_slot_refuse_before_release() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_default_encodings_targets_and_slot_refuse_before_release",
        connected::refusals,
    );
}

#[test]
fn runtime_stack_late_failure_and_unwind_retain_call_custody() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_late_failure_and_unwind_retain_call_custody",
        connected::late,
    );
}

#[test]
fn runtime_stack_budget_deadline_and_stale_source_refuse_before_effects() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_budget_deadline_and_stale_source_refuse_before_effects",
        connected::budgets,
    );
}

#[test]
fn runtime_stack_installed_allocation_failures_settle_before_cleanup() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::stack::native_tests::runtime_stack_installed_allocation_failures_settle_before_cleanup",
        allocation::run,
    );
}
