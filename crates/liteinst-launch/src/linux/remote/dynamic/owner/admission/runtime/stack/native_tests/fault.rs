use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native::acquire::StackCaptureAssociation;
use crate::linux::remote::dynamic::owner::admission::runtime_stack_native::{
    InterventionKind, InterventionPoint,
};

// Linux x86 UAPI siginfo code for a protection-key access violation.
const SEGV_PKUERR: i32 = 4;

fn raw_intervene(owner: &Owner, until: Instant, kind: InterventionKind) -> TaskStateSnapshot {
    support::held(owner, until);
    let before = support::observe_state(owner, until);
    let mut expected = before.clone();
    match kind {
        InterventionKind::Ac => {
            expected.registers.eflags |= 1 << 18;
            let regs: libc::user_regs_struct = expected.registers.into();
            raw::checked(
                libc::PTRACE_SETREGS,
                owner.pid,
                0,
                (&raw const regs) as usize,
            );
        }
        InterventionKind::PkruKeyZeroDeny => {
            // Independent raw CPUID read and exact exported component-9 bounds.
            // Keep the minimum-Rust unsafe signature; newer Rust makes it safe.
            #[allow(unused_unsafe)]
            let layout = unsafe { std::arch::x86_64::__cpuid_count(13, 9) };
            assert_eq!(layout.eax, 8);
            let offset = layout.ebx as usize;
            assert!(offset >= 576 && offset + 8 <= expected.xstate.len());
            assert_ne!(
                u64::from_le_bytes(expected.xstate[464..472].try_into().unwrap()) & (1 << 9),
                0
            );
            assert_ne!(
                u64::from_le_bytes(expected.xstate[512..520].try_into().unwrap()) & (1 << 9),
                0
            );
            assert_eq!(
                u64::from_le_bytes(expected.xstate[520..528].try_into().unwrap()),
                0
            );
            let old = u32::from_le_bytes(expected.xstate[offset..offset + 4].try_into().unwrap());
            assert_eq!(old & 3, 0);
            expected.xstate[offset..offset + 4].copy_from_slice(&(old | 3).to_le_bytes());
            let vector = libc::iovec {
                iov_base: expected.xstate.as_ptr().cast_mut().cast(),
                iov_len: expected.xstate.len(),
            };
            raw::checked(
                libc::PTRACE_SETREGSET,
                owner.pid,
                NT_X86_XSTATE,
                (&raw const vector) as usize,
            );
        }
    }
    assert_eq!(support::observe_state(owner, until), expected);
    support::held(owner, until);
    expected
}
fn raw_fault(program: &Program, kind: InterventionKind) -> raw::Step {
    support::with_owner(
        program,
        true,
        |owner, initial, until, original| {
            let mut before = raw::first(owner, initial, until, original, program.entry);
            for ordinal in 0..program.setup {
                let step = raw::step(owner, until, original, libc::SIGTRAP);
                assert_eq!(step.before, before);
                assert_eq!(step.after, compare::setup(&before, ordinal));
                before = step.after;
            }
            raw_intervene(owner, until, kind);
            let expected_signal = match kind {
                InterventionKind::Ac => libc::SIGBUS,
                InterventionKind::PkruKeyZeroDeny => libc::SIGSEGV,
            };
            let observed = raw::step(owner, until, original, expected_signal);
            assert_eq!(observed.signal.1, 0);
            assert_eq!(
                observed.signal.2,
                match kind {
                    InterventionKind::Ac => libc::BUS_ADRALN,
                    InterventionKind::PkruKeyZeroDeny => SEGV_PKUERR,
                }
            );
            if kind == InterventionKind::PkruKeyZeroDeny {
                assert_eq!(observed.signal.3, observed.before.registers.rsp - 8);
            }
            assert_eq!(observed.after.registers.rip, program.call_pc);
            assert_eq!(observed.after.registers.rsp, observed.before.registers.rsp);
            assert_eq!(observed.stack_after, observed.stack_before);
            observed
        },
        |_, _| {},
    )
}
pub(super) fn run(point: InterventionPoint, kind: InterventionKind) {
    let program = Program::call(4096, kind == InterventionKind::Ac);
    let program = if kind == InterventionKind::PkruKeyZeroDeny {
        program.with_initial_call_word_seed()
    } else {
        program
    };
    let reference = (point == InterventionPoint::AfterB).then(|| raw_fault(&program, kind));
    let _ = support::with_owner(
        &program,
        true,
        |owner, initial, until, original| {
            let mut before = support::begin(owner, initial, until, original, support::options());
            for ordinal in 0..program.setup {
                support::ordinary(owner, until);
                before = compare::setup(&before, ordinal);
                assert_eq!(support::observe_state(owner, until), before);
            }
            if point == InterventionPoint::AfterA {
                ledger::install_after_a(owner);
            } else {
                ledger::install(owner);
            }
            let runtime = owner.runtime.as_mut().unwrap();
            let old_origin = runtime.initial_origin;
            let old_history = runtime.census.as_ref().unwrap().history().to_vec();
            runtime.stack.as_mut().unwrap().native_intervention = Some((point, kind));
            let result = support::invoke(owner, AdmissionRequest::Advance, until);
            assert!(
                matches!(result,Err(GateError::Control(LaunchError::Invalid(reason))) if reason==match point {InterventionPoint::AfterA=>"owned private before-state differs",InterventionPoint::AfterB=>"owned original did not reach exact trace stop"}),
                "stack intervention {point:?}/{kind:?}: error={:?}",
                result.as_ref().err()
            );
            let runtime = owner.runtime.as_ref().unwrap();
            let retained = runtime.stack.as_ref().unwrap();
            let attempt = retained.attempts[0].as_ref().unwrap();
            let native = attempt.native.diagnostics();
            let progress = attempt.native.progress();
            let intervention = attempt.native.intervention().unwrap();
            assert_eq!(intervention.point, point);
            assert_eq!(intervention.kind, kind);
            assert!(intervention.started && intervention.complete);
            assert_eq!(
                intervention.setter,
                Some(NativeRequest {
                    result: 0,
                    errno: None
                })
            );
            let previous = intervention.before.unwrap();
            let changed = intervention.after.unwrap();
            assert!(previous.complete && changed.complete);
            for record in [previous, changed] {
                assert_eq!(
                    record.requests,
                    [Some(NativeRequest {
                        result: 0,
                        errno: None
                    }); 3]
                );
                assert_eq!(record.requested_pointer, record.returned_pointer);
                assert_eq!(record.returned_length, before.xstate.len());
            }
            assert_eq!(previous.registers, before.registers);
            assert_eq!(previous.mask, before.mask);
            assert_eq!(changed.mask, before.mask);
            let mut changed_registers = before.registers;
            if kind == InterventionKind::Ac {
                changed_registers.eflags |= 1 << 18;
            } else {
                assert_eq!(
                    intervention.changed_pkru,
                    Some(intervention.old_pkru.unwrap() | 3)
                );
            }
            assert_eq!(changed.registers, changed_registers);
            assert!(attempt.operand.view().complete);
            assert_eq!(attempt.operand.view().first_failure, None);
            assert!(!native.claimed);
            assert!(native.trace.is_none());
            assert!(!progress.instruction_completed && !progress.nx_closed);
            assert_eq!(runtime.initial_origin, old_origin);
            assert_eq!(runtime.census.as_ref().unwrap().history(), old_history);
            assert!(owner.closing && owner.cancel.load(Ordering::Acquire));
            if point == InterventionPoint::AfterA {
                assert!(progress.effects().is_empty());
                assert_eq!(progress.waits, [None; 7]);
                assert_eq!(progress.queries_started, [false; 7]);
                assert!(
                    native
                        .words
                        .iter()
                        .all(|word| !word.complete && word.association.is_none())
                );
                let mut expected = before.clone();
                expected.registers = changed_registers;
                if kind == InterventionKind::PkruKeyZeroDeny {
                    let offset = intervention.pkru_offset.unwrap();
                    expected.xstate[offset..offset + 4]
                        .copy_from_slice(&intervention.changed_pkru.unwrap().to_le_bytes());
                }
                assert_eq!(support::observe_state(owner, until), expected);
                assert_eq!(
                    support::observe_maps(owner, until),
                    runtime.sources.runtime_baseline_maps().unwrap()
                );
                assert_eq!(
                    original.read_stack(owner, until),
                    *original.stack.as_ref().unwrap()
                );
            } else {
                assert_eq!(progress.waits[4..], [None; 3]);
                assert_eq!(
                    progress.queries_started,
                    [true, true, true, true, false, false, false]
                );
                assert!(progress.failed_held_attempted);
                assert!(progress.failed_held_failure.is_none());
                let (tid, status) = progress.waits[3].unwrap();
                assert_eq!(tid, owner.pid);
                assert_eq!(owner.stopped.get(&tid), Some(&status));
                assert!(libc::WIFSTOPPED(status));
                let reference = reference.as_ref().unwrap();
                assert_eq!(libc::WSTOPSIG(status), reference.signal.0);
                assert_eq!(status >> 16, 0);
                let signal = &native.signals[3];
                assert_eq!(
                    signal.request,
                    Some(NativeRequest {
                        result: 0,
                        errno: None
                    })
                );
                let info = unsafe {
                    std::ptr::read_unaligned(signal.bytes.as_ptr().cast::<libc::siginfo_t>())
                };
                assert_eq!(
                    (info.si_signo, info.si_errno, info.si_code),
                    (reference.signal.0, reference.signal.1, reference.signal.2)
                );
                if kind == InterventionKind::PkruKeyZeroDeny {
                    assert_eq!(
                        unsafe { info.si_addr() } as usize as u64,
                        before.registers.rsp - 8
                    );
                }
                compare::slot(&native.states[4]);
                let actual = support::observe_state(owner, until);
                assert_eq!(native.states[4].state, actual);
                assert_eq!(actual.registers.rip, before.registers.rip);
                assert_eq!(actual.registers.rsp, before.registers.rsp);
                // The kernel may change forced-signal mask/flags. Preserve and
                // compare the actual complete own-lane fault state, never before.
                compare::slot(&native.words[1].observation.state);
                assert_eq!(native.words[1].observation.state.state, actual);
                assert!(native.stops[3..].iter().all(Option::is_none));
                assert!(
                    matches!(native.words[1].association,Some(StackCaptureAssociation::FailedHeld{ordinal:3,raw_wait,..}) if *raw_wait==(tid,status))
                );
                assert!(native.words[2].association.is_none() && !native.words[2].complete);
                compare::opened(
                    runtime.sources.runtime_baseline_maps().unwrap(),
                    &support::observe_maps(owner, until),
                    before.registers.rip,
                    5,
                );
                assert_eq!(
                    original.read_stack(owner, until),
                    *original.stack.as_ref().unwrap()
                );
                assert_eq!(
                    reference.after.registers.rsp,
                    reference.before.registers.rsp
                );
            }
            original.require_source(owner, until);
            ledger::check(owner, 1);
            retention::retained(owner)
        },
        |owner, retained| {
            retained(owner);
            ledger::check(owner, 1);
        },
    );
}
