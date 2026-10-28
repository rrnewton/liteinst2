//! Metadata only. Simulated assembly stores below are not native CALL/RET evidence.
use super::*;
fn id() -> Identity {
    Identity {
        gate: 0x4000,
        pid: 7,
        tid: 8,
        target: 0x1000,
        continuation: 0x5000,
    }
}
fn at_call() -> Meta {
    let mut m = arm(
        Meta::default(),
        id(),
        &ReadableStack {
            start: 0x7000,
            end: 0x9000,
        },
    )
    .unwrap();
    m.observed_target = id().target;
    m.pre_rsp = 0x8000;
    m
}
fn scratch(d: Disposition) -> ScratchSnapshot {
    ScratchSnapshot {
        phase: ScratchPhase::ReturnObserved,
        disposition: Some(d),
        entry_pc: 0x1000,
        entry_rsp: 0x7ff8,
        entry_word: 0x5000,
        return_pc: 0x1010,
        return_rsp: 0x7ff8,
        return_word: 0x5000,
    }
}
#[test]
fn fast_requires_actual_resume_and_every_entry_ret_join() {
    let mut m = at_call();
    let s = scratch(Disposition::FastBypass);
    assert!(resumed(m, id(), s, 42, &[0x1010]).is_err());
    m.resumed_rsp = m.pre_rsp;
    let actual = resumed(m, id(), s, 42, &[0x1010]).unwrap();
    assert_eq!(actual.value, 42);
    assert_eq!(actual.sequence, 1);
    for field in 0..9 {
        let mut bad = s;
        match field {
            0 => bad.phase = ScratchPhase::Entered,
            1 => bad.disposition = None,
            2 => bad.entry_pc += 1,
            3 => bad.entry_rsp -= 8,
            4 => bad.entry_word += 1,
            5 => bad.return_pc += 1,
            6 => bad.return_rsp -= 8,
            7 => bad.return_word += 1,
            _ => bad.disposition = Some(Disposition::Slow),
        }
        assert!(
            resumed(m, id(), bad, 42, &[0x1010]).is_err(),
            "field {field}"
        );
    }
    for field in 0..8 {
        let mut bad = m;
        match field {
            0 => bad.pid += 1,
            1 => bad.tid += 1,
            2 => bad.gate += 1,
            3 => bad.sequence = 0,
            4 => bad.target += 1,
            5 => bad.observed_target += 1,
            6 => bad.resumed_rsp += 8,
            _ => bad.entry_rsp = 0x7ff8,
        }
        assert!(
            resumed(bad, id(), s, 42, &[0x1010]).is_err(),
            "meta {field}"
        );
    }
}
#[test]
fn slow_ret_validation_is_not_completion_or_physical_return() {
    let mut m = at_call();
    let token = enter(&mut m, id(), 0x1000, 0x7ff8, 0x5000).unwrap();
    assert!(enter(&mut m, id(), 0x1000, 0x7ff8, 0x5000).is_err());
    for (pc, rsp, word) in [
        (0x1011, 0x7ff8, 0x5000),
        (0x1010, 0x7ff0, 0x5000),
        (0x1010, 0x7ff8, 0x5001),
    ] {
        assert!(returning(m, id(), &token, pc, rsp, word, &[0x1010]).is_err());
    }
    let proof = returning(m, id(), &token, 0x1010, 0x7ff8, 0x5000, &[0x1010]).unwrap();
    let s = scratch(Disposition::Slow);
    assert!(resumed(m, id(), s, 99, &[0x1010]).is_err());
    complete(&mut m, id(), proof, &[0x1010]).unwrap();
    assert!(resumed(m, id(), s, 99, &[0x1010]).is_err());
    m.resumed_rsp = m.pre_rsp;
    assert_eq!(resumed(m, id(), s, 99, &[0x1010]).unwrap().value, 99);
    assert!(resumed(m, id(), scratch(Disposition::FastBypass), 99, &[0x1010]).is_err());
}
#[test]
fn stack_and_sequence_refusals_do_not_repair_state() {
    for (pre, rsp, start, end) in [
        (0x8008, 0x8000, 0x7000, 0x9000),
        (0x8000, 0x7ff0, 0x7000, 0x9000),
        (0x8000, 0x7ff8, 0x7ff9, 0x9000),
        (0x8000, 0x7ff8, 0x7000, 0x7fff),
        (0, u64::MAX - 7, 0x7000, u64::MAX),
    ] {
        let mut m = at_call();
        m.pre_rsp = pre;
        m.stack_start = start;
        m.stack_end = end;
        let before = m;
        assert!(enter(&mut m, id(), 0x1000, rsp, 0x5000).is_err());
        assert_eq!(m, before);
    }
    assert!(
        arm(
            Meta {
                sequence: u64::MAX,
                ..Meta::default()
            },
            id(),
            &ReadableStack { start: 1, end: 10 }
        )
        .is_err()
    );
    for phase in [ARMED, ENTERED, COMPLETED, POISONED] {
        assert!(
            idle(Meta {
                phase,
                ..Meta::default()
            })
            .is_err()
        );
    }
    assert_eq!(
        idle(Meta {
            sequence: 51,
            ..Meta::default()
        }),
        Ok(51)
    );
}

// Small shared model-test seam. No source/receipt or native-execution authority.
pub(in super::super) fn descriptor() -> Arc<OptionalCallGate> {
    Arc::new(OptionalCallGate {
        target: 0x1000,
        returns: vec![0x1010].into_boxed_slice(),
        pid: std::process::id(),
    })
}
pub(in super::super) fn idle_at(sequence: u64) {
    FRAME.with(|c| unsafe {
        core::ptr::addr_of_mut!((*c.get()).scratch).write(CallScratch::armed());
        core::ptr::addr_of_mut!((*c.get()).meta).write(Meta {
            sequence,
            ..Meta::default()
        });
    });
}
pub(in super::super) fn begin(g: &OptionalCallGate, slow: bool) -> Option<Entry> {
    FRAME.with(|c| {
        let p = unsafe { core::ptr::addr_of_mut!((*c.get()).meta) };
        let mut m = arm(
            unsafe { p.read() },
            g.identity().unwrap(),
            &ReadableStack {
                start: 0x7000,
                end: 0x9000,
            },
        )
        .unwrap();
        m.observed_target = g.target();
        m.pre_rsp = 0x8000;
        let token = slow.then(|| {
            enter(
                &mut m,
                g.identity().unwrap(),
                g.target(),
                0x7ff8,
                g.continuation(),
            )
            .unwrap()
        });
        unsafe {
            p.write(m);
        }
        token
    })
}
pub(in super::super) fn proof(g: &OptionalCallGate, e: &Entry) -> Return {
    FRAME.with(|c| {
        returning(
            unsafe { core::ptr::addr_of!((*c.get()).meta).read() },
            g.identity().unwrap(),
            e,
            0x1010,
            0x7ff8,
            g.continuation(),
            g.returns(),
        )
        .unwrap()
    })
}
pub(in super::super) fn resume(g: &OptionalCallGate, slow: bool) -> Returned {
    FRAME.with(|c| {
        let p = unsafe { core::ptr::addr_of_mut!((*c.get()).meta) };
        let mut m = unsafe { p.read() };
        m.resumed_rsp = m.pre_rsp;
        let s = ScratchSnapshot {
            phase: ScratchPhase::ReturnObserved,
            disposition: Some(if slow {
                Disposition::Slow
            } else {
                Disposition::FastBypass
            }),
            entry_pc: g.target(),
            entry_rsp: 0x7ff8,
            entry_word: g.continuation(),
            return_pc: 0x1010,
            return_rsp: 0x7ff8,
            return_word: g.continuation(),
        };
        let r = resumed(m, g.identity().unwrap(), s, 42, g.returns()).unwrap();
        unsafe {
            p.write(Meta {
                sequence: m.sequence,
                ..Meta::default()
            });
        }
        r
    })
}

#[test]
fn wrong_saved_rbx_refuses_before_any_stack_or_header_read() {
    let gate = descriptor();
    idle_at(0);
    let mut context = HookContext::default();
    context.rbx = 1;
    context.stack_pointer = u64::MAX;
    context.instruction_pointer = gate.target();
    assert!(matches!(gate.enter(&context), Err(GateError::Identity)));
    assert_eq!(gate.idle_checkpoint(), Ok(0));
}
