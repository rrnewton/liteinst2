//! The provider runs on the real caller thread through public transport.
use super::*;
use crate::DynamicAdmissionSession;
use crate::linux::remote::dynamic::owner::admission::runtime::native_tests::{maps, rows};
use crate::linux::remote::dynamic::owner::kernel_journal::KernelWriterStatus;
use crate::linux::remote::dynamic::owner::tests::{Fixture, pin, reaped};
use crate::selected::{InstructionProvider, SemanticsError};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

struct Provider {
    thread: std::thread::ThreadId,
    expected: Option<(RegisterSnapshot, [u8; 2], ProviderDecision)>,
    inputs: Vec<SelectedInput>,
}
impl InstructionProvider for Provider {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        assert_eq!(std::thread::current().id(), self.thread);
        let (registers, bytes, decision) = self
            .expected
            .take()
            .expect("exact public invocation expected");
        assert_eq!(input.registers(), &registers);
        assert_eq!(input.instruction().bytes(), bytes);
        self.inputs.push(input.clone());
        Ok(decision)
    }
}
pub(super) fn consumer(number: u8, terminate: u8, cpu: bool) {
    let program = code(number, terminate, cpu);
    let fixture = Fixture::code(&program);
    let command = fixture.command();
    let provider = Provider {
        thread: std::thread::current().id(),
        expected: None,
        inputs: Vec::new(),
    };
    // SAFETY: singleton owned immutable literal ELF, no external writers,
    // signals, TLS/stack accesses, mapping operations or escaping control flow.
    // Only this explicit finite kernel profile authorizes the four numbers.
    let mut session = Some({
        let _fork = crate::TEST_FILE_FORK.lock().unwrap();
        unsafe { DynamicAdmissionSession::launch_runtime(&command, options(), provider, TIMEOUT) }
            .unwrap()
    });
    let mut app = None;
    let mut broker = None;
    let mut journal = None;
    let mut before_cleanup = None;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let session = session.as_mut().unwrap();
        let pid = session.pid();
        app = Some(pin(pid));
        let app = app.as_ref().unwrap();
        live(app);
        let broker_pid = parent(pid);
        broker = Some(pin(broker_pid));
        live(broker.as_ref().unwrap());
        assert_eq!(parent(pid), broker_pid);
        live(app);
        let initial = session.initial_state().clone();
        assert_eq!(
            (
                initial.registers.rip,
                initial.registers.rax,
                initial.registers.orig_rax
            ),
            (BASE + 4096, 0, u64::MAX)
        );
        assert_eq!(session.state(initial.task.task).unwrap(), initial);
        let memory = Memory::capture(pid, app, maps(pid));
        assert_eq!(&memory.source[4096..4096 + program.len()], program);
        let parsed = rows(&memory.maps);
        let main = parsed
            .iter()
            .filter(|r| r.start == BASE && r.end == BASE + 8192)
            .collect::<Vec<_>>();
        assert_eq!(main.len(), 1);
        assert_eq!(main[0].permissions, *b"r--p");
        let x = parsed
            .iter()
            .filter(|r| r.permissions[2] == b'x' && !r.raw.ends_with(b"[vsyscall]"))
            .collect::<Vec<_>>();
        assert_eq!(x.len(), 1);
        assert_eq!(x[0].end - x[0].start, 4096);
        assert_eq!(x[0].permissions, *b"r-xp");
        let fields = std::str::from_utf8(&x[0].raw)
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), 5);
        assert_eq!(&fields[2..], ["00000000", "00:00", "0"]);
        let reader = session.kernel_progress();
        journal = Some(reader.clone());
        assert!(reader.snapshot().runtime_attempts.is_empty());
        let mut expected = TaskStateSnapshot {
            registers: initial.registers,
            xstate: initial.xstate.clone(),
            mask: initial.signal_mask,
        };
        expected.registers.rax = number as u64;
        expected.registers.rip += 2;
        session.provider_mut().expected =
            Some((expected.registers, [0x0f, 0x05], ProviderDecision::Native));
        let DynamicAdmissionEvent::Completed(event) = session.next_event().unwrap() else {
            panic!("get-id did not return actual native completion")
        };
        assert_eq!(event.selected.input.registers(), &expected.registers);
        assert_eq!(event.selected.before_xstate, expected.xstate);
        assert_eq!(event.before_signal_mask, expected.mask);
        let syscall_before = expected.clone();
        expected = syscall_after(&expected, pid);
        check_public(&event, &initial.task, &expected, SelectedExecution::Native);
        let actual = session.state(initial.task.task).unwrap();
        assert_eq!(actual.registers, expected.registers);
        assert_eq!(actual.xstate, expected.xstate);
        assert_eq!(actual.signal_mask, expected.mask);
        assert_eq!(actual.task, initial.task);
        memory.unchanged(pid, app);
        assert_eq!(
            session.read_memory(initial.task.task, BASE, 8192).unwrap(),
            memory.source
        );
        let first = reader.snapshot();
        assert_eq!(first.runtime_attempts.len(), 1);
        assert!(first.attempts.is_empty() && !first.archive_poisoned);
        archive::journal(
            &first.runtime_attempts[0],
            &syscall_before,
            Some(&expected),
            pid,
        );
        if cpu {
            session.provider_mut().expected = Some((
                expected.registers,
                [0x0f, 0xa2],
                ProviderDecision::Complete(SCRIPT),
            ));
            let DynamicAdmissionEvent::Completed(event) = session.next_event().unwrap() else {
                panic!("CPU selected transport lost inherited return provenance")
            };
            assert_eq!(event.selected.input.registers(), &expected.registers);
            assert_eq!(event.selected.input.registers().orig_rax, number as u64);
            assert_eq!(event.selected.before_xstate, expected.xstate);
            assert_eq!(event.before_signal_mask, expected.mask);
            expected = cpu_after(&expected);
            check_public(
                &event,
                &initial.task,
                &expected,
                SelectedExecution::Scripted,
            );
            let actual = session.state(initial.task.task).unwrap();
            assert_eq!(actual.registers, expected.registers);
            assert_eq!(actual.xstate, expected.xstate);
            assert_eq!(actual.signal_mask, expected.mask);
            memory.unchanged(pid, app);
            assert_eq!(reader.snapshot().runtime_attempts, first.runtime_attempts);
            expected.registers.r12 = MARK;
            expected.registers.rip += 10;
        }
        expected.registers.rax = terminate as u64;
        expected.registers.rdi = 7;
        expected.registers.rip += 10;
        expected.registers.orig_rax = u64::MAX;
        session.provider_mut().expected =
            Some((expected.registers, [0x0f, 0x05], ProviderDecision::Native));
        let DynamicAdmissionEvent::TaskTerminal {
            task,
            status,
            all_terminal,
        } = session.next_event().unwrap()
        else {
            panic!("exit invented a returned completion")
        };
        assert_eq!(task, initial.task);
        assert_eq!(status, ExitStatus::Code(7));
        assert!(all_terminal && session.is_closed());
        assert!(session.provider().expected.is_none());
        assert_eq!(session.provider().inputs.len(), if cpu { 3 } else { 2 });
        // Kernel terminal already proved app death; terminate below separately
        // drains the physical natural reaper and its distinct retained pin.
        reaped(app);
        let last = reader.snapshot();
        assert!(!last.archive_poisoned);
        assert_eq!(last.runtime_attempts.len(), 2);
        assert_eq!(last.runtime_attempts[0], first.runtime_attempts[0]);
        archive::journal(&last.runtime_attempts[1], &expected, None, pid);
        before_cleanup = Some(last.runtime_attempts);
    }));
    if let Err(payload) = &outcome {
        panic_diagnostic("public body", payload.as_ref());
    }
    let pid = session.as_ref().unwrap().pid();
    let cleanup = session
        .take()
        .unwrap()
        .terminate(TIMEOUT)
        .unwrap_or_else(|error| {
            failure_diagnostic("public physical cleanup", &format!("{error:?}"));
            std::process::abort()
        });
    assert_eq!(cleanup.reaped, [pid]);
    let (Some(app), Some(broker)) = (app, broker) else {
        failure_diagnostic("public pins", "missing application or broker pin");
        std::process::abort()
    };
    reaped(&app);
    reaped(&broker);
    if let Err(payload) = outcome {
        resume_unwind(payload);
    }
    let after = journal.unwrap().snapshot();
    assert_eq!(after.writer, KernelWriterStatus::Cleaned);
    assert!(!after.archive_poisoned);
    assert_eq!(after.runtime_attempts, before_cleanup.unwrap());
    assert!(after.attempts.is_empty());
}
fn check_public(
    event: &DynamicAdmissionCompletion,
    task: &DynamicTask,
    expected: &TaskStateSnapshot,
    execution: SelectedExecution,
) {
    assert_eq!((&event.before_task, &event.after_task), (task, task));
    assert_eq!(event.selected.execution, execution);
    assert_eq!(event.selected.after, expected.registers);
    assert_eq!(event.selected.xstate, expected.xstate);
    assert_eq!(event.signal_mask, expected.mask);
}
