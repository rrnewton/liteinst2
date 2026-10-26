//! Synthetic profile decisions only. No native extent, procfs authenticity,
//! original syscall or physical cleanup is established by these controls.
use super::*;
use crate::lifecycle::LifecycleRegistry;

fn state(length: usize) -> TaskStateSnapshot {
    // SAFETY: user_regs_struct contains only integer scalar fields.
    let mut registers =
        RegisterSnapshot::from(unsafe { std::mem::zeroed::<libc::user_regs_struct>() });
    registers.cs = 0x33;
    registers.rip = 0x401000;
    TaskStateSnapshot {
        registers,
        xstate: vec![0x5a; length],
        mask: 0x80,
    }
}

fn query(length: usize) -> MaximumXstateQuery {
    let mut initialized = vec![0; MAX_XSTATE];
    if length <= MAX_XSTATE {
        initialized[..length].fill(0x5a);
    }
    let pointer = initialized.as_mut_ptr() as usize;
    MaximumXstateQuery {
        requested_bytes: MAX_XSTATE,
        original_pointer: pointer,
        returned_pointer: pointer,
        result: 0,
        errno: None,
        reported_bytes: length,
        initialized,
    }
}

fn identity(tid: i32) -> (DynamicStop, DynamicTask) {
    let registry =
        LifecycleRegistry::new(crate::lifecycle::Limits::default(), tid, 0x401000).unwrap();
    let task = registry.root_task();
    let record = registry.task(task).unwrap();
    (
        DynamicStop {
            session: 103,
            tid,
            task: Some(task),
            sequence: 7,
        },
        DynamicTask {
            task,
            process: record.process,
            address_space: record.address_space,
            generation: 2,
        },
    )
}

fn personality(raw: &[u8]) -> PersonalityObservation {
    let mut initialized = [0; PERSONALITY_BYTES];
    initialized[..raw.len()].copy_from_slice(raw);
    PersonalityObservation {
        initialized,
        length: raw.len(),
        procfs_type: libc::PROC_SUPER_MAGIC as libc::__fsword_t,
        value: parse_personality(raw).unwrap(),
    }
}

fn receipt(length: usize) -> MappingProfileEvidence {
    let (initial, identity) = identity(111);
    let mut signal_info = [0; 128];
    signal_info[0..4].copy_from_slice(&libc::SIGTRAP.to_ne_bytes());
    signal_info[8..12].copy_from_slice(&libc::TRAP_BRKPT.to_ne_bytes());
    MappingProfileEvidence {
        initial,
        identity,
        wait_status: libc::SIGTRAP << 8 | 0x7f,
        signal_info,
        query: query(length),
        before: state(length),
        after: state(length),
        personality: personality(b"00000000\n"),
    }
}

fn query_refused(query: &MaximumXstateQuery, state: &TaskStateSnapshot) {
    assert!(matches!(
        validate_query(query, state),
        Err(GateError::Refused(
            "mapping XSTATE maximum request did not authenticate a fixed ABI extent"
        ))
    ));
}

#[test]
fn positive_maximum_query_requires_complete_native_bytes_and_exact_outcomes() {
    for length in [512, 832, MAX_XSTATE - 8] {
        validate_query(&query(length), &state(length)).unwrap();
    }
    for length in [0, 504, 511, 513, MAX_XSTATE, MAX_XSTATE + 8] {
        query_refused(&query(length), &state(length));
    }
    for case in 0..13 {
        let mut query = query(832);
        let mut state = state(832);
        match case {
            0 => {
                query.result = -1;
                query.errno = Some(libc::EIO);
            }
            1 => query.result = 1,
            2 => query.errno = Some(libc::EPERM),
            3 => query.returned_pointer += 8,
            4 => {
                query.original_pointer = 0;
                query.returned_pointer = 0;
            }
            5 => query.requested_bytes = 832,
            6 => {
                query.initialized.pop();
            }
            7 => state.registers.cs = 0x23,
            8 => {
                state.xstate.pop();
            }
            9 => state.xstate.push(0),
            10 => state.xstate[600] ^= 1,
            11 => query.initialized[831] ^= 1,
            12 => {
                query.original_pointer += 8;
                query.returned_pointer += 8;
            }
            _ => unreachable!(),
        }
        query_refused(&query, &state);
    }
}

#[test]
fn immutable_extent_rejects_foreign_identity_regression_and_later_growth() {
    let certificate = receipt(832);
    certificate.validate_retained().unwrap();
    let actual = state(832);
    certificate
        .verify(&certificate.initial, certificate.identity, &actual)
        .unwrap();
    let mut later = certificate.initial.clone();
    later.sequence += 1;
    let mut rebound = certificate.identity;
    rebound.generation += 1;
    certificate.verify(&later, rebound, &actual).unwrap();
    let (_, foreign) = identity(112);
    for case in 0..11 {
        let mut token = certificate.initial.clone();
        let mut task = certificate.identity;
        let mut observed = actual.clone();
        match case {
            0 => token.session += 1,
            1 => token.tid += 1,
            2 => token.task = None,
            3 => token.sequence -= 1,
            4 => {
                token.task = Some(foreign.task);
                task.task = foreign.task;
            }
            5 => task.process = foreign.process,
            6 => task.address_space = foreign.address_space,
            7 => task.generation -= 1,
            8 => observed.registers.cs = 0x23,
            9 => {
                observed.xstate.pop();
            }
            10 => observed.xstate.push(0),
            _ => unreachable!(),
        }
        assert!(matches!(
            certificate.verify(&token, task, &observed),
            Err(GateError::Refused(
                "mapping state differs from its immutable native XSTATE extent"
            ))
        ));
        assert_eq!(certificate.extent(), 832);
        assert_eq!(certificate.before, actual);
        assert_eq!(certificate.after, actual);
    }
}

#[test]
fn retained_bootstrap_state_and_raw_stop_cannot_self_authenticate_corruption() {
    for case in 0..9 {
        let mut certificate = receipt(832);
        match case {
            0 => certificate.before.registers.rax ^= 1,
            1 => certificate.after.mask ^= 1,
            2 => certificate.after.xstate[700] ^= 1,
            3 => certificate.wait_status = libc::SIGSTOP << 8 | 0x7f,
            4 => certificate.wait_status |= libc::PTRACE_EVENT_EXEC << 16,
            5 => certificate.signal_info[..4].copy_from_slice(&libc::SIGSTOP.to_ne_bytes()),
            6 => certificate.signal_info[8..12].copy_from_slice(&libc::SI_USER.to_ne_bytes()),
            7 => certificate.initial.session = 0,
            8 => certificate.initial.task = None,
            _ => unreachable!(),
        }
        assert!(matches!(
            certificate.validate_retained(),
            Err(GateError::Refused(_))
        ));
    }
    for code in [libc::TRAP_BRKPT, libc::SI_KERNEL] {
        let mut certificate = receipt(832);
        certificate.signal_info[8..12].copy_from_slice(&code.to_ne_bytes());
        certificate.validate_retained().unwrap();
    }
}

#[test]
fn personality_requires_exact_framing_native_base_and_positive_procfs_fact() {
    for (raw, expected) in [
        (&b"00000000\n"[..], 0),
        (&b"00040000\n"[..], 0x0004_0000),
        (&b"00200000\n"[..], 0x0020_0000),
    ] {
        assert_eq!(parse_personality(raw).unwrap(), expected);
        validate_personality(&personality(raw)).unwrap();
    }
    for raw in [
        &b""[..],
        &b"00000000"[..],
        &b"00000000\n\n"[..],
        &b"0000000\n"[..],
        &b"000000000\n"[..],
        &b"0000000A\n"[..],
        &b"0x000000\n"[..],
        &b"0000000\0\n"[..],
        &b" 0000000\n"[..],
        &b"00000008\n"[..],
        &b"00400000\n"[..],
        &b"00440000\n"[..],
    ] {
        assert!(matches!(parse_personality(raw), Err(GateError::Refused(_))));
    }
    for case in 0..4 {
        let mut observed = personality(b"00000000\n");
        match case {
            0 => observed.procfs_type = 0,
            1 => observed.value = 0x0004_0000,
            2 => observed.length = PERSONALITY_BYTES + 1,
            3 => observed.initialized[15] = 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            validate_personality(&observed),
            Err(GateError::Refused(_))
        ));
    }
    // Distinct accepted non-executable compatibility bits remain distinct,
    // rather than being normalized away before the live exact recheck.
    assert_ne!(personality(b"00000000\n"), personality(b"00040000\n"));
}

#[test]
fn retained_accounting_keeps_maximum_diagnostics_without_reducing_any_cap() {
    let fixed = MappingProfileEvidence::reservation_bytes().unwrap();
    assert_eq!(fixed, size_of::<MappingProfileEvidence>() + 3 * MAX_XSTATE);
    for length in [512, 832, MAX_XSTATE - 8] {
        let certificate = receipt(length);
        certificate.validate_retained().unwrap();
        assert_eq!(certificate.query.initialized.len(), MAX_XSTATE);
        assert_eq!(certificate.query.requested_bytes, MAX_XSTATE);
        assert_eq!(
            certificate.retained_bytes().unwrap(),
            size_of::<MappingProfileEvidence>() + MAX_XSTATE + 2 * length
        );
        assert!(certificate.retained_bytes().unwrap() <= fixed);
    }
    assert_eq!(MAX_XSTATE, 64 * 1024);
    assert_eq!(
        DynamicAdmissionLimits::default().source_fact_bytes,
        64 * 1024 * 1024
    );
}
