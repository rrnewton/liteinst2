#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Finite four-way comparison: dynamic page admission, explicit static trap
//! interpretation, a handwritten fixture interpreter, and a raw-ptrace strict
//! block reference. This is not a production BlockGate/JIT or bootstrap oracle.
//! All selected outputs are scripted; no unrelated hardware samples are equated.
use liteinst_admission::scan::{Policy, SiteClass};
use liteinst_launch::gate::{
    GateError, ImageFacts, SelectedCompletion, SelectedEvent, SelectedExecution, SelectedMetrics,
    SelectedPageGate,
};
use liteinst_launch::selected::{
    InstructionProvider, ProviderDecision, SelectedInput, SelectedResult, SemanticsError,
    SyscallAliases, SyscallResult,
};
use liteinst_launch::{
    DynamicAdmissionBackend, DynamicAdmissionEvent, DynamicAdmissionOptions,
    DynamicAdmissionSession, ExecCheckpoint, LaunchCommand, RegisterSnapshot,
};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;
const TIMEOUT: Duration = Duration::from_secs(3);
const STEP_BUDGET: usize = 128;
static FILE_FORK: Mutex<()> = Mutex::new(());
#[path = "support/b2_reference/image.rs"]
mod image;
#[path = "support/b2_reference/model.rs"]
mod model;
#[path = "support/b2_reference/raw.rs"]
mod raw;
use image::{BASE, Builder, DATA, DATA_LEN, FLAGS, Fixture, MASK, PAGE, STACK};
use model::{Reply, Row, State, Trace};
#[path = "support/b2_reference/cases.rs"]
mod cases;
#[path = "support/b2_reference/checks.rs"]
mod checks;
use checks::{Replay, check_completion, check_metrics, rethrow};

fn static_gate(fixture: &Fixture, rows: &[Row], covered: bool) -> SelectedPageGate<Replay> {
    let checkpoint = {
        let _fork = FILE_FORK.lock().unwrap();
        let _mask = raw::MaskGuard::new();
        ExecCheckpoint::launch(&LaunchCommand::new(&fixture.path), TIMEOUT).unwrap()
    };
    // SAFETY: fixed single-task ELF, exact original head census including every
    // declared alternate entry, immutable private RX source and private RW/NX
    // data; no external writers/readers, handlers, aliases or island entries.
    // Original selected execution is entirely scripted. No competing waits or
    // mutations occur; the test's mask query is read-only on the same tracer.
    unsafe {
        if covered {
            SelectedPageGate::new_with_coverage(
                checkpoint,
                vec![fixture.facts()],
                Policy::default(),
                SyscallAliases::new(),
                Replay::new(rows),
                TIMEOUT,
                Default::default(),
            )
        } else {
            SelectedPageGate::new(
                checkpoint,
                vec![fixture.facts()],
                Policy::default(),
                SyscallAliases::new(),
                Replay::new(rows),
                TIMEOUT,
            )
        }
    }
    .unwrap()
}
fn dynamic_gate(fixture: &Fixture, rows: &[Row], covered: bool) -> DynamicAdmissionSession<Replay> {
    let options = DynamicAdmissionOptions {
        backend: if covered {
            DynamicAdmissionBackend::CoverageTrap(Default::default())
        } else {
            DynamicAdmissionBackend::StrictTrap
        },
        ..Default::default()
    };
    let _fork = FILE_FORK.lock().unwrap();
    let _mask = raw::MaskGuard::new();
    // SAFETY: same closed finite source/entry/memory facts as static_gate.
    // Only this private owner controls the task; no client-side ptrace requests
    // target it. CALL origins are real and remain under production census rules.
    unsafe {
        DynamicAdmissionSession::launch(
            &LaunchCommand::new(&fixture.path),
            vec![fixture.facts()],
            options,
            Replay::new(rows),
            TIMEOUT,
        )
    }
    .unwrap()
}
fn compare(fixture: &Fixture, replies: &[Reply], covered: bool, collateral: usize) -> Trace {
    let mut native = raw::Raw::launch(fixture);
    let raw_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let initial = native.state();
        // Independently stopped setup, never production initial_state. The raw
        // setup asserts fixed GPRs/segments/mask/x87/SSE fields and all data.
        let expected = model::interpret(fixture, initial, replies, STEP_BUDGET).unwrap();
        let raw_trace = native.run(fixture, replies, STEP_BUDGET).unwrap();
        assert_eq!(
            raw_trace, expected,
            "ordinary block execution and interception order"
        );
        expected
    }));
    native.finish(); // Same owner, retained original pidfd, before rethrow.
    let expected = rethrow(raw_result);
    let mut static_gate = static_gate(fixture, &expected.rows, covered);
    let static_pin = raw::pin(static_gate.pid());
    let static_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(
            static_gate.read_memory(BASE, fixture.bytes.len()).unwrap(),
            fixture.bytes
        );
        raw::nx(static_gate.pid(), &static_pin, BASE + PAGE as u64);
        let mut states = Vec::new();
        for row in &expected.rows {
            let SelectedEvent::Completed(done) = static_gate.next_event().unwrap() else {
                panic!("static lane did not complete the exact scripted invocation");
            };
            check_completion(&done, row);
            let observed = State {
                registers: static_gate.read_registers().unwrap(),
                xstate: static_gate.read_xstate().unwrap(),
                mask: raw::held_mask(static_gate.pid(), &static_pin),
                data: static_gate.read_memory(DATA, DATA_LEN).unwrap(),
            };
            assert_eq!(observed, row.after);
            states.push(observed);
        }
        assert_eq!(static_gate.provider().calls, replies.len());
        check_metrics(static_gate.metrics(), &expected.rows);
        assert_eq!(
            static_gate.gate_metrics().collateral_completions,
            collateral
        );
        states
    }));
    drop(static_gate);
    raw::reaped(&static_pin);
    let static_states = rethrow(static_result);

    let mut dynamic = dynamic_gate(fixture, &expected.rows, covered);
    let dynamic_pin = raw::pin(dynamic.pid());
    let dynamic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let task = dynamic.initial_state().task.task;
        assert_eq!(
            dynamic
                .read_memory(task, BASE, fixture.bytes.len())
                .unwrap(),
            fixture.bytes
        );
        raw::nx(dynamic.pid(), &dynamic_pin, BASE + PAGE as u64);
        let mut states = Vec::new();
        for row in &expected.rows {
            let DynamicAdmissionEvent::Completed(done) = dynamic.next_event().unwrap() else {
                panic!("dynamic lane did not complete the exact scripted invocation");
            };
            check_completion(&done.selected, row);
            assert_eq!(done.before_signal_mask, row.before.mask);
            assert_eq!(done.signal_mask, row.after.mask);
            let held = dynamic.state(done.after_task.task).unwrap();
            let observed = State {
                registers: held.registers,
                xstate: held.xstate,
                mask: held.signal_mask,
                data: dynamic
                    .read_memory(done.after_task.task, DATA, DATA_LEN)
                    .unwrap(),
            };
            assert_eq!(observed, row.after);
            states.push(observed);
        }
        assert_eq!(dynamic.provider().calls, replies.len());
        let metrics = dynamic.metrics().unwrap();
        check_metrics(&metrics.selected, &expected.rows);
        assert_eq!(metrics.pages.collateral_completions, collateral);
        states
    }));
    let pid = dynamic.pid();
    let cleaned = dynamic.terminate(TIMEOUT);
    raw::reaped(&dynamic_pin);
    assert_eq!(cleaned.unwrap().reaped, [pid]);
    let dynamic_states = rethrow(dynamic_result);
    assert_eq!(dynamic_states, static_states);
    assert_eq!(
        dynamic_states,
        expected
            .rows
            .iter()
            .map(|r| r.after.clone())
            .collect::<Vec<_>>()
    );
    expected
}
fn exact_embedded_refusal(error: GateError, address: u64) {
    let GateError::Scan(obligations) = error else {
        panic!("refusal was not a scan obligation: {error:?}");
    };
    assert!(obligations.iter().any(|obligation| matches!(obligation,
        liteinst_admission::scan::Obligation::EmbeddedCandidate(found) if *found==address)));
}

#[test]
fn masked_cpuid_random_chain_agrees_in_all_four_modes() {
    let case = cases::masked();
    assert_eq!(case.id, "masked_cpuid_random");
    let trace = compare(&case.fixture, &case.replies, case.covered, case.collateral);
    case.check_trace(&trace);
}

#[test]
fn timestamps_processor_id_and_scripted_syscall_agree_in_all_four_modes() {
    let case = cases::timestamps();
    assert_eq!(case.id, "timestamps_processor_syscall");
    let trace = compare(&case.fixture, &case.replies, case.covered, case.collateral);
    case.check_trace(&trace);
}

#[test]
fn prefixed_and_alternate_embedded_entries_have_exact_callback_trajectories() {
    let case = cases::prefixed();
    assert_eq!(case.id, "prefixed_suffix");
    let trace = compare(&case.fixture, &case.replies, case.covered, case.collateral);
    case.check_trace(&trace);
    let case = cases::embedded();
    assert_eq!(case.id, "embedded_alternate");
    let trace = compare(&case.fixture, &case.replies, case.covered, case.collateral);
    case.check_trace(&trace);
}

#[test]
fn cross_page_call_return_reaches_the_same_original_selected_head() {
    let case = cases::cross_page();
    assert_eq!(case.id, "cross_page_call");
    let trace = compare(&case.fixture, &case.replies, case.covered, case.collateral);
    case.check_trace(&trace);
}

#[test]
fn strict_embedded_refusal_is_not_relabelled_as_reference_success() {
    let mut b = Builder::new(2);
    b.emit(&[0xf3, 0x0f, 0xc7, 0xfa]);
    let f = b.finish();
    let mut gate = static_gate(&f, &[], false);
    let pin = raw::pin(gate.pid());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exact_embedded_refusal(gate.next_event().unwrap_err(), f.marker + 2);
        assert_eq!(gate.provider().calls, 0);
        assert_eq!(gate.read_memory(BASE, f.bytes.len()).unwrap(), f.bytes);
        raw::nx(gate.pid(), &pin, BASE + PAGE as u64);
        assert!(gate.next_event().is_err());
    }));
    drop(gate);
    raw::reaped(&pin);
    rethrow(result);
    let mut gate = dynamic_gate(&f, &[], false);
    let pin = raw::pin(gate.pid());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let task = gate.initial_state().task.task;
        assert_eq!(
            gate.read_memory(task, BASE, f.bytes.len()).unwrap(),
            f.bytes
        );
        raw::nx(gate.pid(), &pin, BASE + PAGE as u64);
        exact_embedded_refusal(gate.next_event().unwrap_err(), f.marker + 2);
        assert_eq!(gate.provider().calls, 0);
        assert!(gate.next_event().is_err());
        // No post-error source or NX observation is inferred from earlier reads.
    }));
    let pid = gate.pid();
    let cleanup = gate.terminate(TIMEOUT);
    raw::reaped(&pin);
    assert_eq!(cleanup.unwrap().reaped, [pid]);
    rethrow(result);
}

#[test]
fn strict_reference_refuses_unknown_heads_bytes_and_scripts_without_execution() {
    let mut b = Builder::new(2);
    b.emit(&[0x0f, 0xa2]);
    let mut f = b.finish();
    let mut native = raw::Raw::launch(&f);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let before = native.state();
        let pc = before.registers.rip;
        assert!(f.heads.remove(&pc));
        assert_eq!(
            native.authenticate(&f),
            Err("PC not in exact declared head census")
        );
        assert_eq!(native.state(), before);
        f.heads.insert(pc);
        let offset = (pc - BASE) as usize;
        f.bytes[offset] ^= 1;
        assert_eq!(native.authenticate(&f), Err("original source bytes differ"));
        assert_eq!(native.state(), before);
        f.bytes[offset] ^= 1;
        assert_eq!(
            native.run(&f, &[Reply::Rdpid(1)], STEP_BUDGET),
            Err("script/class mismatch")
        );
        assert_eq!(native.state(), before);
        assert_eq!(
            native.run(&f, &[Reply::Cpuid([0; 4])], 0),
            Err("strict fixture instruction budget exhausted")
        );
        assert_eq!(native.state(), before);
        for alias in [&[0x0f, 0x34][..], &[0xcd, 0x80][..]] {
            assert_eq!(
                model::decode(pc, alias),
                Err("instruction outside independent finite decoder")
            );
        }
        assert_eq!(
            model::interpret(&f, before.clone(), &[Reply::Cpuid([0; 4])], 0),
            Err("strict fixture instruction budget exhausted")
        );
        // Equality controls are deliberately full-state; flags, kernel metadata,
        // preserved GPRs, signal mask, XSTATE and stack/data corruption all differ.
        for which in 0..8 {
            let mut corrupt = before.clone();
            match which {
                0 => corrupt.registers.rsp += 8,
                1 => corrupt.registers.r11 ^= 1,
                2 => corrupt.registers.eflags ^= 0x100,
                3 => corrupt.registers.eflags ^= 0x10000,
                4 => corrupt.registers.orig_rax = 0,
                5 => corrupt.mask ^= 1,
                6 => corrupt.xstate[0] ^= 1,
                _ => corrupt.data[(STACK - DATA) as usize] ^= 1,
            }
            assert_ne!(before, corrupt);
        }
    }));
    native.finish();
    rethrow(result);
}
