//! Detached initialized data, never ptrace calls or a completion constructor.
use super::*;

fn invalid<T>(result: Result<T, LaunchError>, expected: &'static str) {
    assert!(matches!(result, Err(LaunchError::Invalid(actual)) if actual == expected));
}
#[test]
fn runtime_kernel_raw_state_keeps_full_initialized_substrate_and_exact_extent() {
    let mut slot = StateRead::default();
    slot.allocate().unwrap();
    let pointer = slot.state.xstate.as_ptr() as usize;
    slot.state.xstate[0] = 0x31;
    slot.state.xstate[832] = 0x7a;
    slot.state.xstate.truncate(832);
    slot.requested_pointer = pointer;
    slot.requested_length = MAX_XSTATE;
    slot.vector = libc::iovec {
        iov_base: pointer as *mut libc::c_void,
        iov_len: 832,
    };
    slot.xstate_request = Some(Request {
        result: -1,
        errno: Some(libc::EIO),
    });
    let view = slot.view();
    assert_eq!(view.xstate_initialized.len(), MAX_XSTATE);
    assert_eq!(
        (view.xstate_initialized[0], view.xstate_initialized[832]),
        (0x31, 0x7a)
    );
    assert_eq!(view.returned_length, 832);
    assert_eq!(
        view.xstate_request,
        Some(Request {
            result: -1,
            errno: Some(libc::EIO)
        })
    );
    assert!(!view.complete && view.state.is_none());
    assert!(valid_xstate(pointer, pointer, 512));
    assert!(valid_xstate(pointer, pointer, MAX_XSTATE - 1));
    for (requested, returned, count) in [
        (0, 0, 832),
        (pointer, pointer + 1, 832),
        (pointer, pointer, 0),
        (pointer, pointer, 511),
        (pointer, pointer, MAX_XSTATE),
        (pointer, pointer, MAX_XSTATE + 1),
    ] {
        assert!(!valid_xstate(requested, returned, count));
    }
    slot.reset_requests();
    let reset = slot.view();
    assert!(!reset.complete && reset.state.is_none());
    assert!(
        reset.registers_request.is_none()
            && reset.xstate_request.is_none()
            && reset.mask_request.is_none()
    );
    assert_eq!(
        (
            reset.requested_pointer,
            reset.returned_pointer,
            reset.requested_length,
            reset.returned_length
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(reset.xstate_initialized.as_ptr() as usize, pointer);
}

#[test]
fn runtime_kernel_raw_owned_trap_requires_exact_si_kernel_and_request_success() {
    let mut raw = FixedReads {
        signal_request: Some(Request {
            result: 0,
            errno: None,
        }),
        ..FixedReads::default()
    };
    raw.signal[..4].copy_from_slice(&libc::SIGTRAP.to_ne_bytes());
    raw.signal[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
    raw.owned_trap().unwrap();
    for (offset, value) in [
        (0, libc::SIGSEGV),
        (4, libc::EIO),
        (8, libc::TRAP_TRACE),
        (8, libc::TRAP_BRKPT),
    ] {
        let original = raw.signal;
        raw.signal[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        invalid(raw.owned_trap(), "runtime kernel owned INT3 signal differs");
        raw.signal = original;
    }
    raw.signal_request = None;
    invalid(raw.owned_trap(), "runtime kernel trap signal unattempted");
    raw.signal_request = Some(Request {
        result: 1,
        errno: None,
    });
    invalid(raw.owned_trap(), "runtime kernel request returned nonzero");
    raw.signal_request = Some(Request {
        result: -1,
        errno: Some(libc::EIO),
    });
    assert!(
        matches!(raw.owned_trap(), Err(LaunchError::System { source, .. }) if source.raw_os_error() == Some(libc::EIO))
    );
}

#[test]
fn runtime_kernel_raw_syscall_header_checks_meaningful_length_arch_and_phase() {
    let mut state = StateRead::default().state;
    state.registers.rip = 0x400002;
    state.registers.rsp = 0x800000;
    for entry in [true, false] {
        let minimum = if entry { 80 } else { 33 };
        let mut raw = FixedReads::default();
        raw.syscall_info[0] = if entry {
            libc::PTRACE_SYSCALL_INFO_ENTRY
        } else {
            libc::PTRACE_SYSCALL_INFO_EXIT
        };
        raw.syscall_info[4..8].copy_from_slice(&0xc000_003eu32.to_ne_bytes());
        raw.syscall_info[8..16].copy_from_slice(&state.registers.rip.to_ne_bytes());
        raw.syscall_info[16..24].copy_from_slice(&state.registers.rsp.to_ne_bytes());
        for count in [minimum, 88] {
            raw.syscall_info_request = Some(Request {
                result: count,
                errno: None,
            });
            raw.syscall_header(entry, &state).unwrap();
        }
        for count in [0, minimum - 1, 89] {
            raw.syscall_info_request = Some(Request {
                result: count,
                errno: None,
            });
            invalid(
                raw.syscall_header(entry, &state),
                "runtime kernel meaningful syscall info truncated",
            );
        }
        raw.syscall_info_request = Some(Request {
            result: 88,
            errno: None,
        });
        for offset in [0, 4, 8, 16] {
            raw.syscall_info[offset] ^= 1;
            invalid(
                raw.syscall_header(entry, &state),
                "runtime kernel syscall info identity differs",
            );
            raw.syscall_info[offset] ^= 1;
        }
        raw.syscall_info_request = None;
        invalid(
            raw.syscall_header(entry, &state),
            "runtime kernel syscall info unattempted",
        );
    }
}
