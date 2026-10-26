//! Pure allocation/receipt-shape controls; no native request or seal is made.
use super::*;
#[test]
fn selected_control_preapply_storage_is_distinct_and_fully_charged() {
    let value = PreparedNativeSelected::allocate().unwrap();
    assert_eq!(value.states.len(), 5);
    for (index, state) in value.states.iter().enumerate() {
        assert_eq!(state.initialized_state().xstate.capacity(), MAX_XSTATE);
        assert!(!state.complete);
        assert!(state.registers_request.is_none());
        assert!(state.xstate_request.is_none());
        assert!(state.mask_request.is_none());
        for other in &value.states[..index] {
            assert_ne!(
                state.initialized_state().xstate.as_ptr(),
                other.initialized_state().xstate.as_ptr()
            );
        }
    }
    assert_eq!(
        value.payload_bytes().unwrap(),
        5 * MAX_XSTATE + 3 * MAP_BYTES
    );
    assert_eq!(
        value.payload_bytes().unwrap(),
        PreparedNativeSelected::payload_bound()
    );
    assert!(value.effects.iter().all(Option::is_none));
    assert!(value.wait.is_none());
    assert!(!value.queries_started);
    assert!(value.final_state().is_err());
}
#[test]
fn selected_control_full_state_comparison_keeps_orig_xstate_and_mask_exact() {
    let mut registers: RegisterSnapshot =
        unsafe { std::mem::zeroed::<libc::user_regs_struct>() }.into();
    registers.cs = 0x33;
    registers.eflags = 0x202;
    registers.rip = 0x401000;
    registers.orig_rax = libc::SYS_gettid as u64;
    let mut value = PreparedNativeSelected::allocate().unwrap();
    let state = &mut value.states[BEFORE].state;
    state.registers = registers;
    state.xstate.truncate(832);
    state.mask = 0x200;
    let registry = crate::lifecycle::LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 1,
            processes: 1,
            address_spaces: 1,
            obligations: 1,
        },
        42,
        registers.rip,
    )
    .unwrap();
    let task = registry.root_task();
    let row = registry.task(task).unwrap();
    let before = ObservedStop {
        token: DynamicStop {
            session: 7,
            tid: 42,
            task: Some(task),
            sequence: 17,
        },
        task: DynamicTask {
            task,
            process: row.process,
            address_space: row.address_space,
            generation: 0,
        },
        logical_pc: registers.rip,
        registers,
        xstate: state.xstate.clone(),
        signal_mask: state.mask,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    };
    require_state(state, &registers, &before).unwrap();
    state.registers.orig_rax = u64::MAX;
    assert!(require_state(state, &registers, &before).is_err());
    state.registers = registers;
    state.xstate[17] ^= 1;
    assert!(require_state(state, &registers, &before).is_err());
    state.xstate[17] ^= 1;
    state.mask ^= 1;
    assert!(require_state(state, &registers, &before).is_err());
    assert_eq!(value.states[BEFORE].state.xstate.capacity(), MAX_XSTATE);
    assert!(value.effects.iter().all(Option::is_none));
}
