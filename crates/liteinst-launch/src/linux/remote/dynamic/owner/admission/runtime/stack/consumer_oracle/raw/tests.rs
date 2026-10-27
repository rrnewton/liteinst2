//! Pure corruption models, with no owner, syscall, wait, ptrace or live pin.
use super::*;
fn state() -> TaskStateSnapshot {
    let mut slot = observe::empty_state();
    slot.state.registers.rip = 0x201002;
    slot.state.registers.rsp = 0x9000;
    slot.state.registers.rdi = 7;
    slot.state.xstate = vec![1, 2, 3];
    slot.state.mask = 5;
    slot.state
}
fn entry() -> Wait {
    let state = state();
    let mut value = Wait::empty();
    value.syscall_request = Some(Outcome {
        result: 80,
        errno: 0,
    });
    value.syscall[0] = 1;
    value.syscall[4..8].copy_from_slice(&0xc000003e_u32.to_ne_bytes());
    value.syscall[8..16].copy_from_slice(&state.registers.rip.to_ne_bytes());
    value.syscall[16..24].copy_from_slice(&state.registers.rsp.to_ne_bytes());
    value.syscall[24..32].copy_from_slice(&231_u64.to_ne_bytes());
    value.syscall[32..40].copy_from_slice(&7_u64.to_ne_bytes());
    value
}
#[test]
fn consumer_raw_syscall_model_requires_real_extent_architecture_and_arguments() {
    let state = state();
    let value = entry();
    validate_syscall(&value, &state, 1, Some(231), None).unwrap();
    for offset in [0, 4, 8, 16, 24, 32, 39, 40, 48, 56, 64, 72] {
        let mut changed = entry();
        changed.syscall[offset] ^= 1;
        assert!(validate_syscall(&changed, &state, 1, Some(231), None).is_err());
    }
    let mut short = entry();
    short.syscall_request = Some(Outcome {
        result: 79,
        errno: 0,
    });
    assert!(validate_syscall(&short, &state, 1, Some(231), None).is_err());
}
#[test]
fn consumer_raw_exit_model_rejects_error_flag_and_wrong_result() {
    let state = state();
    let mut value = entry();
    value.syscall[0] = 2;
    value.syscall[24..32].copy_from_slice(&17_u64.to_ne_bytes());
    value.syscall[32] = 0;
    value.syscall_request = Some(Outcome {
        result: 33,
        errno: 0,
    });
    validate_syscall(&value, &state, 2, None, Some(17)).unwrap();
    value.syscall[32] = 1;
    assert!(validate_syscall(&value, &state, 2, None, Some(17)).is_err());
    value.syscall[32] = 0;
    assert!(validate_syscall(&value, &state, 2, None, Some(18)).is_err());
}
#[test]
fn consumer_raw_model_full_state_preserves_all_unrelated_payloads() {
    let record = namespace::Record {
        opened: Some(Outcome {
            result: 7,
            errno: 0,
        }),
        stat: Some(Outcome {
            result: 0,
            errno: 0,
        }),
        filesystem: Some(Outcome {
            result: 0,
            errno: 0,
        }),
        device: 1,
        inode: 2,
        magic: 0x6e736673,
        closed: Some(Outcome {
            result: 0,
            errno: 0,
        }),
        complete: true,
    };
    namespace::require_records(&[record, record]).unwrap();
    for changed in [
        namespace::Record {
            device: 2,
            ..record
        },
        namespace::Record { inode: 3, ..record },
        namespace::Record { magic: 0, ..record },
        namespace::Record {
            closed: None,
            ..record
        },
        namespace::Record {
            complete: false,
            ..record
        },
    ] {
        assert!(namespace::require_records(&[record, changed]).is_err());
    }
    let before = state();
    let mut actual = state();
    actual.registers = entry_registers(before.registers, 0x201004, 39);
    require_entry(&before, &actual, 0x201004, 39).unwrap();
    actual.xstate[0] ^= 1;
    assert!(require_entry(&before, &actual, 0x201004, 39).is_err());
    actual.xstate[0] ^= 1;
    actual.mask ^= 1;
    assert!(require_entry(&before, &actual, 0x201004, 39).is_err());
    actual.mask ^= 1;
    actual.registers.r15 ^= 1;
    assert!(require_entry(&before, &actual, 0x201004, 39).is_err());
}
#[test]
fn consumer_raw_model_never_calls_a_breakpoint_a_trace() {
    let mut value = Wait::empty();
    value.signal_request = Some(Outcome {
        result: 0,
        errno: 0,
    });
    value.signal[..4].copy_from_slice(&libc::SIGTRAP.to_ne_bytes());
    value.signal[8..12].copy_from_slice(&libc::TRAP_TRACE.to_ne_bytes());
    require_signal(&value, true).unwrap();
    assert!(require_signal(&value, false).is_err());
    value.signal[8..12].copy_from_slice(&libc::TRAP_BRKPT.to_ne_bytes());
    require_signal(&value, false).unwrap();
    assert!(require_signal(&value, true).is_err());
}
