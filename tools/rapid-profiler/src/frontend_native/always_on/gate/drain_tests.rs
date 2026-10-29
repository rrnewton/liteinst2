//! Synthetic frame transitions only; never assembly or executable authority.
use super::super::{RawTimestamp, State};
use super::*;

pub(in crate::frontend_native::always_on) struct FrameScope(Frame);
impl FrameScope {
    pub(in crate::frontend_native::always_on) fn new() -> Self {
        FRAME.with(|cell| {
            let old = unsafe { cell.get().read() };
            idle(old).unwrap();
            Self(old)
        })
    }
}
impl Drop for FrameScope {
    fn drop(&mut self) {
        FRAME.with(|cell| unsafe { cell.get().write(self.0) });
    }
}
pub(in crate::frontend_native::always_on) fn descriptor() -> Arc<CallGate> {
    Arc::new(CallGate {
        profile: GateProfile::Legacy,
        target: 0x1000,
        returns: vec![0x1012].into(),
        pid: std::process::id(),
    })
}
pub(in crate::frontend_native::always_on) fn snapshot() -> [u64; 14] {
    let f = FRAME.with(|cell| unsafe { cell.get().read() });
    [
        f.phase,
        f.sequence,
        f.gate,
        f.pid,
        f.tid,
        f.target,
        f.observed_target,
        f.pre_call_rsp,
        f.resumed_rsp,
        f.stack_start,
        f.stack_end,
        f.entry_rsp,
        f.return_word,
        f.return_pc,
    ]
}
pub(in crate::frontend_native::always_on) fn begin(state: &mut State, start: RawTimestamp) {
    let gate = state.binding.single_site().unwrap().gate.as_ref().unwrap();
    let id = gate.identity().unwrap();
    let token = FRAME.with(|cell| {
        let mut frame = arm(
            unsafe { cell.get().read() },
            id,
            state.stack.start,
            state.stack.end,
        )
        .unwrap();
        frame.observed_target = id.target;
        frame.pre_call_rsp = 0x8000;
        let token = entry(&mut frame, id, id.target, 0x7ff8, id.continuation).unwrap();
        unsafe {
            cell.get().write(frame);
        }
        token
    });
    state
        .enter_observed(id.target, 0x7ff8, id.continuation, Some(start), Some(token))
        .unwrap();
}
pub(in crate::frontend_native::always_on) fn complete(state: &mut State, end: RawTimestamp) {
    let gate = state.binding.single_site().unwrap().gate.as_ref().unwrap();
    let id = gate.identity().unwrap();
    let pc = gate.declared_returns()[0];
    let proof = FRAME.with(|cell| {
        returning(
            unsafe { cell.get().read() },
            id,
            state.pairs[0].as_ref().unwrap().gate.as_ref().unwrap(),
            pc,
            0x7ff8,
            id.continuation,
            gate.declared_returns(),
        )
        .unwrap()
    });
    state
        .finish_observed(pc, 0x7ff8, id.continuation, Some(end), Some(proof))
        .unwrap();
}
pub(in crate::frontend_native::always_on) fn resume(state: &State) {
    let gate = state.binding.single_site().unwrap().gate.as_ref().unwrap();
    FRAME.with(|cell| {
        let mut frame = unsafe { cell.get().read() };
        frame.resumed_rsp = frame.pre_call_rsp;
        resumed(frame, gate.identity().unwrap(), 42, gate.declared_returns()).unwrap();
        unsafe {
            cell.get().write(Frame {
                sequence: frame.sequence,
                ..Frame::default()
            });
        }
    });
}

#[test]
fn drain_checkpoint_requires_every_idle_word_and_preserves_sequence() {
    for phase in [ARMED, ENTERED, COMPLETED, POISONED, u64::MAX] {
        assert_eq!(
            idle(Frame {
                phase,
                sequence: 19,
                ..Frame::default()
            }),
            Err(GateError::Completion)
        );
    }
    for n in 0..12 {
        let mut frame = Frame {
            sequence: 19,
            ..Frame::default()
        };
        match n {
            0 => frame.gate = 1,
            1 => frame.pid = 1,
            2 => frame.tid = 1,
            3 => frame.target = 1,
            4 => frame.observed_target = 1,
            5 => frame.pre_call_rsp = 1,
            6 => frame.resumed_rsp = 1,
            7 => frame.stack_start = 1,
            8 => frame.stack_end = 1,
            9 => frame.entry_rsp = 1,
            10 => frame.return_word = 1,
            _ => frame.return_pc = 1,
        }
        assert_eq!(idle(frame), Err(GateError::Completion));
    }
    for sequence in [0, 19, u64::MAX] {
        assert_eq!(
            idle(Frame {
                sequence,
                ..Frame::default()
            }),
            Ok(sequence)
        );
    }
    let _scope = FrameScope::new();
    let before = snapshot();
    assert_eq!(descriptor().idle_checkpoint(), Ok(before[1]));
    let foreign = CallGate {
        profile: GateProfile::Legacy,
        target: 0x1000,
        returns: vec![0x1012].into(),
        pid: 0,
    };
    assert_eq!(foreign.idle_checkpoint(), Err(GateError::Process));
    assert_eq!(snapshot(), before);
}
