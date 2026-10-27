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
