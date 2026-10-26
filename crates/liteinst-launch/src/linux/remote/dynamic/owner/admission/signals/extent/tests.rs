//! Synthetic decision controls, not native extent or ptrace evidence.
use super::*;
use crate::lifecycle::LifecycleRegistry;

fn state(size: usize) -> TaskStateSnapshot {
    let mut registers =
        RegisterSnapshot::from(unsafe { std::mem::zeroed::<libc::user_regs_struct>() });
    registers.cs = 0x33;
    TaskStateSnapshot {
        registers,
        xstate: vec![0x5a; size],
        mask: 0x80,
    }
}

fn query(size: usize) -> SignalXstateRead {
    SignalXstateRead {
        result: 0,
        errno: None,
        reported_bytes: size,
        pointer_unchanged: true,
    }
}

fn identity(tid: i32) -> (DynamicStop, DynamicTask) {
    let registry =
        LifecycleRegistry::new(crate::lifecycle::Limits::default(), tid, 0x401000).unwrap();
    let task = registry.root_task();
    let record = registry.task(task).unwrap();
    (
        DynamicStop {
            session: 91,
            tid,
            task: Some(task),
            sequence: 7,
        },
        DynamicTask {
            task,
            process: record.process,
            address_space: record.address_space,
            generation: 0,
        },
    )
}

#[test]
fn extent_decision_requires_complete_positive_max_request_and_native_mode() {
    for size in [512, 832, MAX_XSTATE - 8] {
        validate_query(query(size), &state(size)).unwrap();
    }
    for size in [0, 504, 511, 513, MAX_XSTATE, MAX_XSTATE + 8] {
        assert!(validate_query(query(size), &state(size)).is_err());
    }
    let original = state(832);
    for case in 0..7 {
        let mut observed = original.clone();
        let mut outcome = query(832);
        match case {
            0 => {
                outcome.result = -1;
                outcome.errno = Some(libc::EIO);
            }
            1 => {
                outcome.result = 1;
            }
            2 => {
                outcome.errno = Some(libc::EIO);
            }
            3 => {
                outcome.pointer_unchanged = false;
            }
            4 => {
                observed.registers.cs = 0x23;
            }
            5 => {
                observed.xstate.pop();
            }
            6 => {
                observed.xstate.push(0);
            }
            _ => unreachable!(),
        }
        assert!(validate_query(outcome, &observed).is_err());
        assert_eq!(original.xstate, vec![0x5a; 832]);
    }
}

#[test]
fn extent_binding_rejects_replacement_identity_and_length_without_rebinding() {
    let (token, task) = identity(111);
    let certificate = NativeExtent {
        initial: token.clone(),
        identity: task,
        query: query(832),
    };
    let actual = state(832);
    certificate.verify(&token, task, &actual).unwrap();
    let mut next_token = token.clone();
    next_token.sequence += 1;
    let mut rebound = task;
    rebound.generation += 1;
    certificate.verify(&next_token, rebound, &actual).unwrap();
    let (_, foreign) = identity(112);
    for case in 0..10 {
        let mut stop = token.clone();
        let mut identity = task;
        let mut raw = actual.clone();
        match case {
            0 => {
                stop.session += 1;
            }
            1 => {
                stop.tid += 1;
            }
            2 => {
                stop.task = None;
            }
            3 => {
                stop.sequence -= 1;
            }
            4 => {
                stop.task = Some(foreign.task);
                identity.task = foreign.task;
            }
            5 => {
                identity.process = foreign.process;
            }
            6 => {
                identity.address_space = foreign.address_space;
            }
            7 => {
                raw.registers.cs = 0x23;
            }
            8 => {
                raw.xstate.pop();
            }
            9 => {
                raw.xstate.push(0);
            }
            _ => unreachable!(),
        }
        assert!(certificate.verify(&stop, identity, &raw).is_err());
        assert_eq!(certificate.bytes(), 832);
        assert_eq!(certificate.initial, token);
        assert_eq!(certificate.identity, task);
        assert_eq!(actual.xstate, vec![0x5a; 832]);
    }
}
