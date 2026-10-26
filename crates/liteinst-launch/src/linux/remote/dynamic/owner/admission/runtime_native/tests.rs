//! Pure literal/model controls. No constructor fabricates native completion.
use super::super::runtime_instruction::{DebugDisposition, classify};
use super::*;
use crate::lifecycle::{LifecycleRegistry, Limits};
use liteinst_admission::scan::{Boundary, Snapshot, WriteControl};
use liteinst_admission::{Generation, MappingId};

fn state(pc: u64) -> TaskStateSnapshot {
    let mut registers: RegisterSnapshot =
        unsafe { std::mem::zeroed::<libc::user_regs_struct>() }.into();
    registers.rip = pc;
    registers.rsp = 0x800000;
    registers.cs = 0x33;
    registers.ss = 0x2b;
    registers.orig_rax = u64::MAX;
    registers.eflags = 0x202;
    TaskStateSnapshot {
        registers,
        xstate: vec![0x5a; 832],
        mask: 0x200,
    }
}
fn capability(bytes: &[u8]) -> Result<(), LaunchError> {
    let source = Snapshot::new(
        MappingId(9),
        Generation(0),
        0x401000,
        bytes.to_vec(),
        Boundary::Unknown,
        Boundary::Unknown,
        WriteControl::Owned,
    )
    .unwrap();
    let state = state(0x401000);
    let candidate = classify(
        &source,
        &state.registers,
        DebugDisposition::Absent,
        &crate::selected::SyscallAliases::new(),
    )
    .unwrap();
    runner::no_memory(&candidate)
}
fn invalid<T>(result: Result<T, LaunchError>, expected: &'static str) {
    assert!(matches!(result, Err(LaunchError::Invalid(actual)) if actual == expected));
}
fn debug() -> DebugRead {
    let values = [0, 0, 0, 0, DR_TRACE, 0];
    DebugRead {
        values,
        requests: std::array::from_fn(|index| {
            Some(Request {
                result: values[index] as i64,
                errno: None,
            })
        }),
    }
}
fn siginfo(pc: u64) -> [u8; 128] {
    let mut raw = [0; 128];
    raw[..4].copy_from_slice(&libc::SIGTRAP.to_ne_bytes());
    raw[8..12].copy_from_slice(&libc::TRAP_TRACE.to_ne_bytes());
    raw[16..24].copy_from_slice(&pc.to_ne_bytes());
    raw
}
fn stop(sequence: u64, phase: AdmissionPhase) -> AdmissionStop {
    let registry = LifecycleRegistry::new(
        Limits {
            tasks: 4,
            processes: 2,
            address_spaces: 2,
            obligations: 16,
        },
        42,
        0x401000,
    )
    .unwrap();
    let task = registry.root_task();
    let row = registry.task(task).unwrap();
    AdmissionStop {
        token: DynamicStop {
            session: 7,
            tid: 42,
            task: Some(task),
            sequence,
        },
        identity: DynamicTask {
            task,
            process: row.process,
            address_space: row.address_space,
            generation: 0,
        },
        phase,
        signal: None,
    }
}
#[test]
fn owned_native_capability_accepts_only_nonaccessing_literal_families() {
    for bytes in [
        &[0x48, 0x89, 0xc8][..],
        &[0xb8, 1, 0, 0, 0],
        &[0x48, 0x01, 0xc8],
        &[0x48, 0x83, 0xf8, 1],
        &[0x48, 0x8d, 0x44, 0x88, 7],
        &[0x90],
        &[0x0f, 0x1f, 0x00],
        &[0xeb, 0xfe],
        &[0x75, 0xfe],
        &[0xe9, 0, 0, 0, 0],
    ] {
        capability(bytes).unwrap();
    }
}
#[test]
fn owned_native_capability_refuses_memory_stack_indirect_and_selected() {
    for bytes in [
        &[0x48, 0x8b, 0x00][..],
        &[0x48, 0x89, 0x00],
        &[0x48, 0x01, 0x00],
        &[0x48, 0x39, 0x00],
    ] {
        invalid(
            capability(bytes),
            "owned ordinary memory access is unsupported",
        );
    }
    for bytes in [
        &[0x50][..],
        &[0x58],
        &[0xff, 0xe0],
        &[0xff, 0xd0],
        &[0xe8, 0, 0, 0, 0],
        &[0xc3],
    ] {
        invalid(
            capability(bytes),
            "owned ordinary control family is unsupported",
        );
    }
    invalid(
        capability(&[0x0f, 0xa2]),
        "owned ordinary request is selected",
    );
}
#[test]
fn owned_native_state_refuses_tf_rf_mode_and_partial_extent() {
    let original = state(0x401000);
    runner::require_state(&original).unwrap();
    for flags in [0, 0x302, 0x10202] {
        let mut changed = original.clone();
        changed.registers.eflags = flags;
        invalid(
            runner::require_state(&changed),
            "owned instruction native state profile differs",
        );
    }
    for length in [0, 511, MAX_XSTATE, MAX_XSTATE + 1] {
        let mut changed = original.clone();
        changed.xstate.resize(length, 0);
        invalid(
            runner::require_state(&changed),
            "owned instruction native state profile differs",
        );
    }
    let mut changed = original.clone();
    changed.registers.cs = 0x23;
    invalid(
        runner::require_state(&changed),
        "owned instruction native state profile differs",
    );
    let mut changed = original;
    changed.registers.orig_rax = 0;
    invalid(
        runner::require_state(&changed),
        "owned instruction native state profile differs",
    );
}
#[test]
fn owned_native_trace_requires_actual_identity_code_errno_address_and_dr6() {
    let state = state(0x401000);
    let raw = siginfo(state.registers.rip);
    let status = (libc::SIGTRAP << 8) | 0x7f;
    let actual = runner::validate_trace(42, 42, status, raw, &state, &debug()).unwrap();
    assert_eq!(
        actual,
        NativeTrace {
            ordinal: 3,
            tid: 42,
            status,
            signal: raw,
            dr6: DR_TRACE
        }
    );
    for (tid, status) in [
        (43, status),
        (42, 0),
        (42, libc::SIGKILL),
        (42, status | (libc::PTRACE_EVENT_EXEC << 16)),
        (42, (libc::SIGSEGV << 8) | 0x7f),
    ] {
        invalid(
            runner::validate_trace(tid, 42, status, raw, &state, &debug()),
            "owned original did not reach exact trace stop",
        );
    }
    for (offset, value) in [
        (0, libc::SIGSEGV),
        (4, libc::EINVAL),
        (8, libc::TRAP_BRKPT),
        (8, libc::SI_KERNEL),
        (8, libc::SI_USER),
    ] {
        let mut changed = raw;
        changed[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        invalid(
            runner::validate_trace(42, 42, status, changed, &state, &debug()),
            "owned original trace signal differs",
        );
    }
    let mut changed = raw;
    changed[16] ^= 1;
    invalid(
        runner::validate_trace(42, 42, status, changed, &state, &debug()),
        "owned original trace signal differs",
    );
}
#[test]
fn owned_native_debug_requires_all_observed_words_and_exact_status() {
    debug().require(DR_TRACE).unwrap();
    for index in 0..6 {
        let mut changed = debug();
        changed.values[index] ^= 1;
        invalid(
            changed.require(DR_TRACE),
            "owned instruction debug profile differs",
        );
        let mut changed = debug();
        changed.requests[index] = None;
        invalid(
            changed.require(DR_TRACE),
            "owned instruction debug profile differs",
        );
        let mut changed = debug();
        changed.requests[index] = Some(Request {
            result: -1,
            errno: Some(libc::EIO),
        });
        invalid(
            changed.require(DR_TRACE),
            "owned instruction debug profile differs",
        );
    }
    for dr6 in [0, 0xffff0ff0, DR_TRACE | 1, DR_TRACE | 0x2000, u64::MAX] {
        let mut changed = debug();
        changed.values[4] = dr6;
        invalid(
            changed.require(DR_TRACE),
            "owned instruction debug profile differs",
        );
    }
}
#[test]
fn owned_native_whole_control_comparison_retains_xstate_mask_and_flags() {
    let before = state(0x401000);
    let mut after = before.clone();
    after.registers.rip = before.registers.rip; // a completed self branch is not progress-by-PC
    after.registers.rax = 71;
    after.registers.eflags ^= 1;
    runner::control_unchanged(&before, &after).unwrap();
    for bit in [8, 9, 10, 16, 18, 21] {
        let mut changed = after.clone();
        changed.registers.eflags ^= 1 << bit;
        invalid(
            runner::control_unchanged(&before, &changed),
            "owned ordinary changed non-arithmetic control state",
        );
    }
    for index in [0, 831] {
        let mut changed = after.clone();
        changed.xstate[index] ^= 1;
        invalid(
            runner::control_unchanged(&before, &changed),
            "owned ordinary changed non-arithmetic control state",
        );
    }
    let mut changed = after.clone();
    changed.mask ^= 1;
    invalid(
        runner::control_unchanged(&before, &changed),
        "owned ordinary changed non-arithmetic control state",
    );
    for field in 0..9 {
        let mut changed = after.clone();
        let value = match field {
            0 => &mut changed.registers.cs,
            1 => &mut changed.registers.ss,
            2 => &mut changed.registers.ds,
            3 => &mut changed.registers.es,
            4 => &mut changed.registers.fs,
            5 => &mut changed.registers.gs,
            6 => &mut changed.registers.fs_base,
            7 => &mut changed.registers.gs_base,
            _ => &mut changed.registers.orig_rax,
        };
        *value ^= 1;
        invalid(
            runner::control_unchanged(&before, &changed),
            "owned ordinary changed non-arithmetic control state",
        );
    }
}
#[test]
fn owned_native_checkpoint_requires_real_sequence_and_same_identity() {
    let before = stop(17, AdmissionPhase::Restored);
    let mut after = before.clone();
    after.token.sequence += 1;
    after.phase = AdmissionPhase::NativeCompleted;
    runner::next_stop(&before, &after).unwrap();
    for sequence in [0, 16, 17] {
        let mut changed = after.clone();
        changed.token.sequence = sequence;
        invalid(
            runner::next_stop(&before, &changed),
            "owned instruction checkpoint lineage differs",
        );
    }
    for field in 0..4 {
        let mut changed = after.clone();
        match field {
            0 => changed.token.session += 1,
            1 => changed.token.tid += 1,
            2 => changed.token.task = None,
            _ => changed.identity.generation += 1,
        }
        invalid(
            runner::next_stop(&before, &changed),
            "owned instruction checkpoint lineage differs",
        );
    }
}
#[test]
fn owned_native_storage_reserves_all_raw_waits_and_never_grants_empty_completion() {
    let shape = InstructionAttemptShape {
        fetch_start: 0x400000,
        fetch_end: 0x402000,
    };
    let mut attempt =
        PreparedInstructionAttempt::allocate(shape, Instant::now() + Duration::from_secs(1))
            .unwrap();
    assert_eq!(
        shape.reservation_bytes().unwrap(),
        size_of::<PreparedInstructionAttempt>() + 9 * MAX_XSTATE + 6 * MAP_BYTES
    );
    assert!(attempt.allocated_bytes().unwrap() <= shape.reservation_bytes().unwrap());
    assert_eq!(attempt.states.len(), 9);
    assert_eq!(attempt.signals.len(), 7);
    for state in &attempt.states {
        assert_eq!(state.state.xstate.len(), MAX_XSTATE);
        assert!(state.state.xstate.iter().all(|byte| *byte == 0));
    }
    assert!(attempt.completed().is_none());
    invalid(
        attempt.take_completed(),
        "owned instruction completion unavailable",
    );
    assert!(!attempt.claimed);
    attempt.progress.phase = InstructionPhase::Original;
    attempt
        .progress
        .fail(Some(&LaunchError::Invalid("first actual refusal")));
    attempt
        .progress
        .fail(Some(&LaunchError::Timeout("later cleanup")));
    assert_eq!(
        attempt.progress.first_failure,
        Some((
            InstructionPhase::Original,
            InstructionFailure::Invalid("first actual refusal")
        ))
    );
    assert!(!attempt.progress.nx_closed);
    assert!(!attempt.progress.instruction_completed);
}
