//! Supplied records only: these controls do not authenticate a stopped task.
use super::super::artifact::tests::{model, parse};
use super::*;
#[test]
fn consumer_observer_rejects_nonowned_or_outside_initial_stack_models() {
    let maps = b"8000-a000 rw-p 00000000 00:00 0 [stack]\n";
    let stack = stack_description(maps, 0x9000).unwrap();
    assert_eq!(stack.range, 0x8000..0xa000);
    assert_eq!(stack.original_rsp, 0x9000);
    for bad in [
        &b"8000-a000 r--p 00000000 00:00 0 [stack]\n"[..],
        &b"8000-a000 rw-p 00000000 00:01 9 [stack]\n"[..],
        &b"8000-a000 rw-p 00001000 00:00 0 [stack]\n"[..],
    ] {
        assert!(stack_description(bad, 0x9000).is_err());
    }
    assert!(stack_description(maps, 0x8000).is_err());
    assert!(stack_description(maps, 0x9008).is_err());
    assert!(stack_description(maps, 0xa000).is_err());
}
#[test]
fn consumer_observer_shape_counts_all_full_frames_and_four_stack_payloads() {
    let plan = parse(&model()).unwrap();
    let small = LaneShape::for_plan(&plan, 4096).unwrap();
    let larger = LaneShape::for_plan(&plan, 8192).unwrap();
    assert_eq!(small.frames, 2 * plan.len() - 1);
    assert_eq!(larger.retained_bytes - small.retained_bytes, 4 * 4096);
    assert_eq!(small.temporary_bytes, larger.temporary_bytes);
    for bytes in [0, 1, 4095, STACK_CAP + 4096, usize::MAX] {
        assert!(LaneShape::for_plan(&plan, bytes).is_err());
    }
}
#[test]
fn consumer_observer_empty_state_and_requests_claim_no_completed_read() {
    let slot = empty_state();
    assert!(!slot.complete);
    assert_eq!(slot.state.xstate.capacity(), 0);
    assert!(slot.registers_request.is_none());
    assert!(slot.xstate_request.is_none());
    assert!(slot.mask_request.is_none());
    let lane = PreparedLane::empty();
    assert!(!lane.metadata.complete);
    assert!(lane.frame(0, false).is_err());
    assert_eq!(lane.allocated_bytes().unwrap(), size_of::<PreparedLane>());
}

// Supplied records exercise the same pure gates used by admitted metadata and
// raw frame0. They cannot construct an Owner, a held stop or native authority.
fn user_metadata() -> Metadata {
    let mut value = Metadata::empty();
    allocate_state(&mut value.state).unwrap();
    value.state.state.xstate.truncate(840);
    value.state.state.xstate[464..472].copy_from_slice(&(1_u64 << 9).to_le_bytes());
    value.state.state.xstate[512..520].copy_from_slice(&(1_u64 << 9).to_le_bytes());
    value.state.state.registers.cs = 0x33;
    value.state.state.registers.ss = 0x2b;
    value.state.state.registers.eflags = 0x202;
    let success = Some(crate::linux::remote::dynamic::owner::bootstrap::Request {
        result: 0,
        errno: None,
    });
    value.state.registers_request = success;
    value.state.xstate_request = success;
    value.state.mask_request = success;
    value.state.requested_pointer = value.state.state.xstate.as_ptr() as usize;
    value.state.returned_pointer = value.state.requested_pointer;
    value.state.returned_length = value.state.state.xstate.len();
    value.state.complete = true;
    let outputs = [
        [13, 0, 0, 0],
        [0, 0, (1 << 26) | (1 << 27), 0],
        [0, 0, (1 << 3) | (1 << 4), 0],
        [1 << 9, 0, 0, 0],
        [8, 832, 0, 0],
    ];
    for (index, (leaf, subleaf)) in CPUID_INPUTS.into_iter().enumerate() {
        value.layout.records[index] = Some(CpuidRecord {
            leaf,
            subleaf,
            registers: outputs[index],
        });
    }
    value
}
#[test]
fn consumer_observer_exec_phase_does_not_grant_user_access() {
    let mut value = user_metadata();
    require_user_state(&value.state, &value.layout).unwrap();
    assert!(value.require_user_access().is_err());
    value.complete = true;
    assert!(value.require_user_access().is_err());
    value.phase = Some(MetadataPhase::ExecEvent);
    assert!(matches!(
        value.require_user_access(),
        Err(OracleError::Invalid(
            "oracle metadata is not restored user access"
        ))
    ));
    value.phase = Some(MetadataPhase::RestoredUser);
    value.complete = false;
    assert!(value.require_user_access().is_err());
    value.complete = true;
    value.require_user_access().unwrap();
    // A different phase name cannot make absent component-9 state valid.
    value.state.state.xstate[512..520].fill(0);
    assert!(matches!(
        value.require_user_access(),
        Err(OracleError::Invalid(
            "oracle user-state XSTATE or PKRU differs"
        ))
    ));
}
#[test]
fn consumer_observer_restored_user_state_keeps_request_xstate_mode_refusals() {
    let mut value = user_metadata();
    value.phase = Some(MetadataPhase::RestoredUser);
    value.complete = true;
    value.require_user_access().unwrap();
    let pointer = value.state.requested_pointer;
    value.state.requested_pointer ^= 8;
    assert!(matches!(
        require_user_state(&value.state, &value.layout),
        Err(OracleError::Invalid(
            "oracle user-state request evidence differs"
        ))
    ));
    value.state.requested_pointer = pointer;
    let request = value.state.xstate_request;
    value.state.xstate_request.as_mut().unwrap().errno = Some(libc::EIO);
    assert!(matches!(
        value.require_user_access(),
        Err(OracleError::Invalid(
            "oracle user-state request evidence differs"
        ))
    ));
    value.state.xstate_request = request;
    for offset in [465, 513, 520, 528, 832, 836] {
        value.state.state.xstate[offset] ^= if matches!(offset, 465 | 513) { 2 } else { 1 };
        assert!(matches!(
            require_user_state(&value.state, &value.layout),
            Err(OracleError::Invalid(
                "oracle user-state XSTATE or PKRU differs"
            ))
        ));
        value.state.state.xstate[offset] ^= if matches!(offset, 465 | 513) { 2 } else { 1 };
        value.require_user_access().unwrap();
    }
    for bit in [8, 16, 17, 18] {
        value.state.state.registers.eflags ^= 1 << bit;
        assert!(matches!(
            require_user_state(&value.state, &value.layout),
            Err(OracleError::Invalid(
                "oracle user-state mode or flags differ"
            ))
        ));
        value.state.state.registers.eflags ^= 1 << bit;
        value.require_user_access().unwrap();
    }
    let cs = value.state.state.registers.cs;
    value.state.state.registers.cs = 0x23;
    assert!(matches!(
        value.require_user_access(),
        Err(OracleError::Invalid(
            "oracle user-state mode or flags differ"
        ))
    ));
    value.state.state.registers.cs = cs;
    value.layout.records[4].as_mut().unwrap().registers[0] = 4;
    assert!(matches!(
        require_user_state(&value.state, &value.layout),
        Err(OracleError::Invalid("oracle PKU layout differs"))
    ));
    value.layout.records[4].as_mut().unwrap().registers[0] = 8;
    value.require_user_access().unwrap();
}
