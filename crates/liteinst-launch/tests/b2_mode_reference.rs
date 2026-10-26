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

#[derive(Clone)]
struct Replay {
    rows: Vec<Row>,
    calls: usize,
}
impl Replay {
    fn new(rows: &[Row]) -> Self {
        Self {
            rows: rows.to_vec(),
            calls: 0,
        }
    }
}
impl InstructionProvider for Replay {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        let row = self
            .rows
            .get(self.calls)
            .ok_or(SemanticsError::ScriptMismatch)?;
        if input.registers() != &row.before.registers
            || input.instruction().logical_pc() != row.before.registers.rip
            || input.instruction().bytes() != row.bytes
            || input.instruction().operation().class() != row.selected.class()
        {
            return Err(SemanticsError::ScriptMismatch);
        }
        self.calls += 1;
        Ok(ProviderDecision::Complete(row.reply.result()))
    }
}
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
fn check_completion(actual: &SelectedCompletion, row: &Row) {
    assert_eq!(actual.execution, SelectedExecution::Scripted);
    assert_eq!(actual.input.registers(), &row.before.registers);
    assert_eq!(
        actual.input.instruction().logical_pc(),
        row.before.registers.rip
    );
    assert_eq!(actual.input.instruction().bytes(), row.bytes);
    assert_eq!(
        actual.input.instruction().operation().class(),
        row.selected.class()
    );
    assert_eq!(actual.before_xstate, row.before.xstate);
    assert_eq!(actual.after, row.after.registers);
    assert_eq!(actual.xstate, row.after.xstate);
}
fn check_metrics(metrics: &SelectedMetrics, rows: &[Row]) {
    let mut counts = BTreeMap::new();
    for row in rows {
        *counts.entry(row.selected.class()).or_insert(0) += 1;
    }
    assert_eq!(metrics.callbacks, counts);
    assert_eq!(metrics.scripted_completions, rows.len());
    assert_eq!(metrics.native_completions, 0);
    assert_eq!(metrics.provider_faults, 0);
    assert_eq!(metrics.native_signals, 0);
    assert_eq!(metrics.refusals, 0);
}
fn rethrow<T>(result: std::thread::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
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
    let mut b = Builder::new(2);
    let first = b.emit(&[0x0f, 0xa2]);
    b.store(1, 0);
    b.mov(0, 7);
    b.mov(1, 0);
    b.emit(&[0x0f, 0xa2]);
    b.store(3, 1);
    b.emit(&[0x0f, 0xc7, 0xf0]);
    b.store(0, 2);
    b.emit(&[0x0f, 0xc7, 0xfa]);
    let f = b.finish();
    let trace = compare(
        &f,
        &[
            Reply::Cpuid([0, 0, 0, 0]),
            Reply::Cpuid([0, 0, 0, 0]),
            Reply::Rdrand {
                value: 0x9988_7766,
                carry: true,
            },
            Reply::Rdseed {
                value: 0,
                carry: false,
            },
        ],
        false,
        0,
    );
    assert_eq!(trace.rows.len(), 4);
    assert_eq!(trace.rows[0].before.registers.rip, first);
    assert_eq!(trace.rows[0].before.registers.rax as u32, 1);
    assert_eq!(trace.rows[0].after.registers.rcx & (1 << 30), 0);
    assert_eq!(trace.rows[1].before.registers.rax, 7);
    assert_eq!(trace.rows[1].before.registers.rcx, 0);
    assert_eq!(trace.rows[1].after.registers.rbx & (1 << 18), 0);
    assert_eq!(trace.rows[2].selected.class(), SiteClass::Rdrand);
    assert_eq!(trace.rows[3].selected.class(), SiteClass::Rdseed);
}

#[test]
fn timestamps_processor_id_and_scripted_syscall_agree_in_all_four_modes() {
    let mut b = Builder::new(2);
    b.emit(&[0x0f, 0x31]);
    b.store(0, 0);
    b.store(2, 1);
    b.mov(0, 0x9988_7766_5544_3322);
    b.mov(1, 0x1234_5678_9abc_def0);
    b.mov(2, 0xffee_ddcc_bbaa_9988);
    b.emit(&[0x0f, 0x01, 0xf9]);
    b.store(1, 2);
    b.emit(&[0xf3, 0x41, 0x0f, 0xc7, 0xf9]);
    b.store(9, 3);
    b.mov(0, 39);
    b.emit(&[0x0f, 0x05]);
    let f = b.finish();
    let trace = compare(
        &f,
        &[
            Reply::Rdtsc(0x8877_6655_4433_2211),
            Reply::Rdtscp(0x1234_5678_9abc_def0, 0xabba_cafe),
            Reply::Rdpid(0xface_babe),
            Reply::GetId(173),
        ],
        true,
        0,
    );
    assert_eq!(
        trace
            .rows
            .iter()
            .map(|r| r.selected.class())
            .collect::<Vec<_>>(),
        [
            SiteClass::Rdtsc,
            SiteClass::Rdtscp,
            SiteClass::Rdpid,
            SiteClass::Syscall
        ]
    );
    let syscall = trace.rows.last().unwrap();
    assert_eq!(
        syscall.after.registers.rcx,
        syscall.before.registers.rip + 2
    );
    assert_eq!(syscall.after.registers.r11, FLAGS);
    assert_eq!(syscall.after.registers.orig_rax, u64::MAX);
}

#[test]
fn prefixed_and_alternate_embedded_entries_have_exact_callback_trajectories() {
    // Width/high-register representatives, followed by an explicit suffix entry.
    let mut b = Builder::new(2);
    b.emit(&[0x66, 0x41, 0x0f, 0xc7, 0xf1]);
    b.store(9, 0);
    b.emit(&[0x48, 0x0f, 0xc7, 0xfb]);
    b.store(3, 1);
    let rdpid = b.emit(&[0xf3, 0x0f, 0xc7, 0xfa]);
    b.heads.insert(rdpid + 1);
    b.branch(0xe9, rdpid + 1);
    let f = b.finish();
    let trace = compare(
        &f,
        &[
            Reply::Rdrand {
                value: 0xbeef,
                carry: true,
            },
            Reply::Rdseed {
                value: 0,
                carry: false,
            },
            Reply::Rdpid(0xaabb_ccdd),
            Reply::Rdseed {
                value: 0x1234_5678,
                carry: true,
            },
        ],
        true,
        0,
    );
    assert_eq!(
        trace.rows[0].after.registers.r9 & !0xffff,
        image::seed(9) & !0xffff
    );
    assert_eq!(trace.rows[3].before.registers.rip, rdpid + 1);
    assert_eq!(trace.rows[3].bytes, [0x0f, 0xc7, 0xfa]);

    // A collateral MOV contains RDSEED in its immediate. It must execute as MOV
    // with zero callback first, and later dispatch only on an actual alternate
    // entry. Both trajectories use exactly the same immutable original bytes.
    let mut b = Builder::new(2);
    let mov = b.pc();
    b.mov(3, 0x9090_9090_f8c7_0f90);
    b.store(3, 0);
    b.emit(&[0x0f, 0x31]);
    b.heads
        .extend([mov + 3, mov + 6, mov + 7, mov + 8, mov + 9]);
    b.branch(0xe9, mov + 3);
    let f = b.finish();
    let trace = compare(
        &f,
        &[
            Reply::Rdtsc(0x1122_3344_5566_7788),
            Reply::Rdseed {
                value: 0xfedc_ba98,
                carry: true,
            },
            Reply::Rdtsc(0x8877_6655_4433_2211),
        ],
        true,
        1,
    );
    assert_eq!(
        trace
            .rows
            .iter()
            .map(|r| r.selected.class())
            .collect::<Vec<_>>(),
        [SiteClass::Rdtsc, SiteClass::Rdseed, SiteClass::Rdtsc]
    );
    assert_eq!(trace.rows[0].before.registers.rbx, 0x9090_9090_f8c7_0f90);
    assert!(trace.ordinary.iter().any(|(pc, _)| *pc == mov));
}

#[test]
fn cross_page_call_return_reaches_the_same_original_selected_head() {
    let mut b = Builder::new(4);
    let call = BASE + 2 * PAGE as u64 - 5;
    b.branch(0xe9, call);
    b.cursor = 2 * PAGE - 5;
    b.branch(0xe8, BASE + 3 * PAGE as u64);
    let returned = b.emit(&[0xf3, 0x0f, 0xc7, 0xfa]);
    b.store(2, 0);
    b.emit(&[0x0f, 0x31]);
    let end = b.cursor;
    b.cursor = 3 * PAGE;
    b.emit(&[0xc3]);
    b.cursor = end;
    let f = b.finish();
    let trace = compare(
        &f,
        &[
            Reply::Rdpid(0x1234_5678),
            Reply::Rdtsc(0x9988_7766_5544_3322),
        ],
        true,
        0,
    );
    assert_eq!(returned, BASE + 2 * PAGE as u64);
    assert_eq!(trace.rows[0].before.registers.rsp, STACK);
    let slot = (STACK - 8 - DATA) as usize;
    assert_eq!(
        &trace.rows[0].before.data[slot..slot + 8],
        &returned.to_le_bytes()
    );
    assert!(trace.ordinary.iter().any(|(pc, _)| *pc == call));
    assert!(
        trace
            .ordinary
            .iter()
            .any(|(pc, _)| *pc == BASE + 3 * PAGE as u64)
    );
    assert_eq!(
        trace.blocks,
        [f.marker + 1, call, BASE + 3 * PAGE as u64, returned]
    );
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
