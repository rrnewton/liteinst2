//! One real CALL/RET across an admitted-page boundary, with the original
//! return slot retained across admission generations. This is an
//! additive fixture; it does not infer saved-context completeness from NX.
use super::*;
use liteinst_admission::scan::SiteClass;
use liteinst_launch::{DynamicAdmissionMetrics, DynamicAdmissionState};
use std::io::Read;

const CALL_FLAGS: u64 = 0xed7;
const COUNTER: u64 = 0x1234_5678_0000_0000;

fn relative(image: &mut Image, opcode: u8, target: u64) -> u64 {
    let pc = image.base + image.cursor as u64;
    let offset = i32::try_from(i128::from(target) - i128::from(pc + 5)).unwrap();
    let mut bytes = vec![opcode];
    bytes.extend_from_slice(&offset.to_le_bytes());
    image.emit(&bytes)
}

fn seeded(register: u8) -> u64 {
    match register {
        0 => 0x1234_5678_0000_0000, // Native CPUID leaf zero.
        1 => 0x8765_4321_0000_0000, // Native CPUID subleaf zero.
        4 => STACK,
        _ => 0x2233_4455_6677_8800 | u64::from(register),
    }
}

fn seed_registers(mut state: RegisterSnapshot) -> RegisterSnapshot {
    state.rax = seeded(0);
    state.rcx = seeded(1);
    state.rdx = seeded(2);
    state.rbx = seeded(3);
    state.rsp = seeded(4);
    state.rbp = seeded(5);
    state.rsi = seeded(6);
    state.rdi = seeded(7);
    state.r8 = seeded(8);
    state.r9 = seeded(9);
    state.r10 = seeded(10);
    state.r11 = seeded(11);
    state.r12 = seeded(12);
    state.r13 = seeded(13);
    state.r14 = seeded(14);
    state.r15 = seeded(15);
    state.eflags = CALL_FLAGS;
    state.orig_rax = u64::MAX;
    state
}

fn cpuid_after(mut before: RegisterSnapshot) -> RegisterSnapshot {
    // Leaf zero has no task-specific output. This host instruction is an
    // independent value oracle, not a call to production selected semantics.
    let value = std::arch::x86_64::__cpuid_count(before.rax as u32, before.rcx as u32);
    before.rax = u64::from(value.eax);
    before.rbx = u64::from(value.ebx);
    before.rcx = u64::from(value.ecx);
    before.rdx = u64::from(value.edx);
    before.rip += 2;
    before
}

#[derive(Clone)]
struct CallRow {
    bytes: Vec<u8>,
    before: RegisterSnapshot,
    after: RegisterSnapshot,
    native: bool,
}

struct CallProvider {
    rows: Vec<CallRow>,
    calls: usize,
}

impl InstructionProvider for CallProvider {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        let row = self
            .rows
            .get(self.calls)
            .ok_or(SemanticsError::ScriptMismatch)?;
        if input.instruction().bytes() != row.bytes
            || input.instruction().logical_pc() != row.before.rip
            || input.registers() != &row.before
        {
            return Err(SemanticsError::ScriptMismatch);
        }
        self.calls += 1;
        Ok(if row.native {
            ProviderDecision::Native
        } else {
            ProviderDecision::Complete(SelectedResult::Rdtsc { counter: COUNTER })
        })
    }
}

fn require_live_pin(pin: &OwnedFd) -> Result<(), String> {
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the retained original pidfd is borrowed for this nonblocking
    // read-only observation, and poll writes only this initialized local value.
    let result = unsafe { libc::poll(&raw mut poll, 1, 0) };
    if result != 0 || poll.revents != 0 {
        return Err("original process pidfd is terminal or its liveness is uncertain".into());
    }
    Ok(())
}

fn executable_page(pid: i32, pin: &OwnedFd, page: u64) -> Result<bool, String> {
    // Retaining a pidfd alone does not prevent numeric PID reuse after exit.
    // Bracket the numeric proc read with actual original-incarnation liveness;
    // any terminal event, error, or nonzero revents refuses the observation.
    require_live_pin(pin)?;
    let file = fs::File::open(format!("/proc/{pid}/maps")).map_err(|_| "maps open")?;
    let mut maps = String::new();
    file.take(128 * 1024 + 1)
        .read_to_string(&mut maps)
        .map_err(|_| "maps read")?;
    require_live_pin(pin)?;
    if maps.len() > 128 * 1024 {
        return Err("maps exceeded fixture bound".into());
    }
    let mut found = None;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next().ok_or("maps range absent")?;
        let permissions = fields.next().ok_or("maps permissions absent")?;
        let (start, end) = range.split_once('-').ok_or("maps range malformed")?;
        let start = u64::from_str_radix(start, 16).map_err(|_| "maps start malformed")?;
        let end = u64::from_str_radix(end, 16).map_err(|_| "maps end malformed")?;
        if start <= page && page + PAGE as u64 <= end {
            if found.is_some() || !matches!(permissions, "r--p" | "r-xp") {
                return Err("image mapping is not uniquely private and immutable".into());
            }
            found = Some(permissions == "r-xp");
        }
    }
    found.ok_or_else(|| "fixture page mapping absent".into())
}

struct CallStage {
    done: DynamicAdmissionCompletion,
    held: DynamicAdmissionState,
    data: Vec<u8>,
    original_stack: Vec<u8>,
    call_bytes: Vec<u8>,
    target_bytes: Vec<u8>,
    caller_executable: bool,
    target_executable: bool,
    metrics: DynamicAdmissionMetrics,
}

#[test]
fn native_call_return_into_never_executed_nx_page_keeps_old_generation_obligation() {
    let directory = Directory::new();
    let mut image = Image::new(BASE, 3);
    for register in 0..16 {
        image.mov(register, seeded(register));
    }
    let mut flags = vec![0x68];
    flags.extend_from_slice(&(CALL_FLAGS as u32).to_le_bytes());
    image.emit(&flags);
    image.emit(&[0x9d]);
    let call = BASE + (2 * PAGE - 5) as u64;
    relative(&mut image, 0xe9, call);
    image.cursor = PAGE + 512;
    let callee = image.emit(&[0x0f, 0xa2]);
    let ret = image.emit(&[0xc3]);
    image.cursor = 2 * PAGE - 5;
    assert_eq!(relative(&mut image, 0xe8, callee), call);
    assert_eq!(image.cursor, 2 * PAGE);
    let destination = image.emit(&[0x0f, 0x31]);
    let last_cpuid = image.emit(&[0x0f, 0xa2]);
    image.spin();
    let original_call = image.bytes[2 * PAGE - 5..2 * PAGE].to_vec();
    let original_target = image.bytes[2 * PAGE..3 * PAGE].to_vec();
    let path = image.write(&directory, "call-boundary");
    let options = DynamicAdmissionOptions {
        backend: DynamicAdmissionBackend::CoverageTrap(TrapCoverageBudget::default()),
        ..DynamicAdmissionOptions::default()
    };
    let mut session = launch(
        &path,
        vec![image.facts()],
        options,
        CallProvider {
            rows: Vec::new(),
            calls: 0,
        },
    );
    let pin = pin(session.pid());
    let initial = session.initial_state().clone();
    let mut first_before = seed_registers(initial.registers);
    first_before.rsp = STACK - 8;
    first_before.rip = callee;
    let first_after = cpuid_after(first_before);
    let mut second_before = first_after;
    second_before.rsp = STACK;
    second_before.rip = destination;
    let mut second_after = second_before;
    second_after.rax = u64::from(COUNTER as u32);
    second_after.rdx = COUNTER >> 32;
    second_after.rip += 2;
    let third_before = second_after;
    let rows = vec![
        CallRow {
            bytes: vec![0x0f, 0xa2],
            before: first_before,
            after: first_after,
            native: true,
        },
        CallRow {
            bytes: vec![0x0f, 0x31],
            before: second_before,
            after: second_after,
            native: false,
        },
        CallRow {
            bytes: vec![0x0f, 0xa2],
            before: third_before,
            after: cpuid_after(third_before),
            native: true,
        },
    ];
    session.provider_mut().rows = rows.clone();

    // Collect fallible live observations without assertions. Even a provider,
    // transport or permission failure reaches explicit cleanup before failure.
    let observed = (|| -> Result<_, String> {
        let initial_caller_x = executable_page(session.pid(), &pin, BASE + PAGE as u64)?;
        let initial_target_x = executable_page(session.pid(), &pin, destination)?;
        let initial_data = session
            .read_memory(initial.task.task, DATA, 2 * PAGE)
            .map_err(|e| format!("{e:?}"))?;
        let initial_stack = session
            .read_memory(initial.task.task, initial.registers.rsp, 256)
            .map_err(|e| format!("{e:?}"))?;
        let mut stages = Vec::new();
        for _ in 0..3 {
            let event = session.next_event().map_err(|e| format!("{e:?}"))?;
            let DynamicAdmissionEvent::Completed(done) = event else {
                return Err(
                    "CALL puzzle produced an unexpected lifecycle/signal/fault event".into(),
                );
            };
            stages.push(CallStage {
                done: *done,
                held: session
                    .state(initial.task.task)
                    .map_err(|e| format!("{e:?}"))?,
                data: session
                    .read_memory(initial.task.task, DATA, 2 * PAGE)
                    .map_err(|e| format!("{e:?}"))?,
                original_stack: session
                    .read_memory(initial.task.task, initial.registers.rsp, 256)
                    .map_err(|e| format!("{e:?}"))?,
                call_bytes: session
                    .read_memory(initial.task.task, call, 5)
                    .map_err(|e| format!("{e:?}"))?,
                target_bytes: session
                    .read_memory(initial.task.task, destination, PAGE)
                    .map_err(|e| format!("{e:?}"))?,
                caller_executable: executable_page(session.pid(), &pin, BASE + PAGE as u64)?,
                target_executable: executable_page(session.pid(), &pin, destination)?,
                metrics: session.metrics().map_err(|e| format!("{e:?}"))?,
            });
        }
        Ok((
            initial_caller_x,
            initial_target_x,
            initial_data,
            initial_stack,
            stages,
        ))
    })();
    let calls = session.provider().calls;
    cleanup(session, &pin);
    let (initial_caller_x, initial_target_x, mut expected_data, initial_stack, stages) =
        observed.unwrap();

    assert_eq!(initial.registers.rip, BASE + PAGE as u64);
    assert_eq!(initial.registers.rax, 0);
    assert_eq!(initial.registers.orig_rax, u64::MAX);
    assert_eq!(initial.registers.cs, 0x33);
    assert_eq!(initial.registers.eflags & (0x100 | 0x10000), 0);
    assert!(!initial_caller_x);
    assert!(!initial_target_x);
    assert_eq!(ret, callee + 2);
    assert_eq!(destination, call + 5);
    assert_eq!(last_cpuid, destination + 2);
    assert_eq!(calls, 3);
    assert_eq!(expected_data, vec![0x5a; 2 * PAGE]);
    let slot = usize::try_from(STACK - 8 - DATA).unwrap();
    expected_data[slot..slot + 8].copy_from_slice(&destination.to_le_bytes());
    let mut armed_target = original_target.clone();
    armed_target[0] = 0xcc;
    armed_target[2] = 0xcc;
    let mut retained = 0;
    for (index, (stage, row)) in stages.iter().zip(&rows).enumerate() {
        assert_eq!(stage.done.selected.input.instruction().bytes(), row.bytes);
        assert_eq!(
            stage.done.selected.input.instruction().logical_pc(),
            row.before.rip
        );
        assert_eq!(stage.done.selected.input.registers(), &row.before);
        assert_eq!(stage.done.selected.after, row.after);
        assert_eq!(
            stage.done.selected.execution,
            if row.native {
                SelectedExecution::Native
            } else {
                SelectedExecution::Scripted
            }
        );
        assert_eq!(stage.done.selected.before_xstate, initial.xstate);
        assert_eq!(stage.done.selected.xstate, initial.xstate);
        assert_eq!(stage.done.before_signal_mask, initial.signal_mask);
        assert_eq!(stage.done.signal_mask, initial.signal_mask);
        assert_eq!(stage.done.before_task.task, initial.task.task);
        assert_eq!(stage.done.after_task.task, initial.task.task);
        assert_eq!(stage.done.before_task.process, initial.task.process);
        assert_eq!(stage.done.after_task.process, initial.task.process);
        assert_eq!(
            stage.done.before_task.address_space,
            initial.task.address_space
        );
        assert_eq!(
            stage.done.after_task.address_space,
            initial.task.address_space
        );
        assert_eq!(
            stage.done.after_task.generation,
            stage.done.before_task.generation + 1
        );
        assert_eq!(stage.held.task, stage.done.after_task);
        assert_eq!(stage.held.registers, row.after);
        assert_eq!(stage.held.xstate, initial.xstate);
        assert_eq!(stage.held.signal_mask, initial.signal_mask);
        assert_eq!(stage.data, expected_data);
        assert_eq!(stage.original_stack, initial_stack);
        assert_eq!(stage.call_bytes, original_call);
        assert_eq!(&stage.data[slot..slot + 8], &destination.to_le_bytes());
        assert_eq!(stage.caller_executable, index == 0);
        assert_eq!(stage.target_executable, index != 0);
        assert_eq!(
            &stage.target_bytes,
            if index == 0 {
                &original_target
            } else {
                &armed_target
            }
        );
        assert_eq!(stage.metrics.fetch_faults, if index == 0 { 1 } else { 2 });
        assert_eq!(stage.metrics.guard_stops, index + 1);
        assert_eq!(
            stage.metrics.generation_changes as u64,
            stage.done.after_task.generation
        );
        // Additive read-only metrics must come directly from the retained CALL
        // ledger, never from this fixture's address or callback count.
        assert!(stage.metrics.retained_call_obligations >= 1);
        assert!(stage.metrics.retained_call_obligations >= retained);
        assert_eq!(stage.metrics.oldest_call_generation, Some(0));
        retained = stage.metrics.retained_call_obligations;
        assert_eq!(stage.metrics.selected.provider_faults, 0);
        assert_eq!(stage.metrics.selected.native_signals, 0);
        assert_eq!(stage.metrics.selected.refusals, 0);
    }
    assert!(stages[0].done.before_task.generation > 0);
    assert!(stages[1].done.before_task.generation > stages[0].done.after_task.generation);
    assert_eq!(
        stages[2].done.before_task.generation,
        stages[1].done.after_task.generation
    );
    assert_eq!(stages[0].done.selected.input.registers().rsp, STACK - 8);
    assert_eq!(stages[0].done.selected.after.rsp, STACK - 8);
    assert_eq!(stages[1].done.selected.input.registers().rsp, STACK);
    let final_metrics = &stages[2].metrics;
    assert_eq!(final_metrics.selected.callbacks.len(), 2);
    assert_eq!(
        final_metrics.selected.callbacks.get(&SiteClass::Cpuid),
        Some(&2)
    );
    assert_eq!(
        final_metrics.selected.callbacks.get(&SiteClass::Rdtsc),
        Some(&1)
    );
    assert_eq!(final_metrics.selected.native_completions, 2);
    assert_eq!(final_metrics.selected.scripted_completions, 1);
}
