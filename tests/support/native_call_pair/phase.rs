//! Two real nested CALLs and LIFO RETs inside the shared Walk/Tracee engine.
use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum Event {
    None,
    ParentCall,
    ChildCall,
    ChildReturn,
    ParentReturn,
}

pub(super) fn advance(stage: u8, event: Event, landing: bool) -> u8 {
    match (stage, event, landing) {
        (0, Event::ParentCall, false) => 1,
        (1, Event::ChildCall, false) => 2,
        (2, Event::ChildReturn, true) => 3,
        (3, Event::None, true) => 4,
        (4, Event::ParentReturn, false) => 5,
        _ => panic!("nested physical transition"),
    }
}
pub(super) fn landing(
    ready: &Ready,
    delta: u64,
    event: Event,
    [rip, rsp, rax, word]: [u64; 4],
    caller_rsp: u64,
) {
    let parent_rsp = caller_rsp
        .checked_sub(ready.plan.subject_rsp_delta())
        .unwrap();
    let child_rsp = parent_rsp.checked_sub(delta).unwrap();
    let cont = ready.parent().entry + ready.parent_plan().continuation;
    match event {
        Event::ChildCall => assert_eq!((rip, rsp, word), (ready.child().entry, child_rsp, cont)),
        Event::ChildReturn => assert_eq!(
            (rip, rsp, rax, word),
            (cont, child_rsp + 8, ready.case.fields(), cont)
        ),
        Event::ParentReturn => assert_eq!(
            (rip, rsp, rax, word),
            (
                ready.caller + ready.plan.continuations()[0],
                parent_rsp + 8,
                ready.case.value(),
                ready.caller + ready.plan.continuations()[0]
            )
        ),
        _ => panic!("nested landing role"),
    }
}
// Parent-side completed single-step requests, not retired instruction counts.
// Buckets: reach-caller, existing nested stages 0..5, actual outer RET.
pub(in super::super) struct StepAttribution {
    candidate: bool,
    pub(super) counts: [usize; 8],
}
pub(in super::super) struct StepPoint {
    pub(in super::super) bucket: usize,
    pub(in super::super) steps: usize,
    pub(in super::super) rip: u64,
    pub(in super::super) pid: libc::pid_t,
}
impl StepAttribution {
    pub(in super::super) fn new(candidate: bool) -> Self {
        Self {
            candidate,
            counts: [0; 8],
        }
    }
    pub(in super::super) fn completed(&mut self, bucket: usize) {
        self.counts[bucket] = self.counts[bucket].checked_add(1).unwrap();
    }
    pub(in super::super) fn write_exhaustion(
        &self,
        out: &mut impl std::io::Write,
        profile: &Profile,
        seed: u64,
        point: StepPoint,
    ) -> std::io::Result<()> {
        if point.steps < MAX_STEPS {
            return Ok(());
        }
        let (elf_va, load_bias) = profile.diagnostic_origin.unwrap_or((0, 0));
        writeln!(
            out,
            "call-pair step attribution: candidate={} k={} seed={seed} index={} scenario={} pid={} steps={} bucket={} rip={:#x} caller={:#x} origin_joined={} caller_elf_va={elf_va:#x} executable_load_bias={load_bias:#x} completed={:?}",
            u8::from(self.candidate),
            profile.case.k,
            profile.case.index + 1,
            profile.case.scenario.id(),
            point.pid,
            point.steps,
            point.bucket,
            point.rip,
            profile.caller,
            u8::from(profile.diagnostic_origin.is_some()),
            self.counts,
        )
    }
}

pub(in super::super) struct Phase {
    parent: parent::Parent,
    stage: u8,
    child_ret: Option<u64>,
    parent_ret: Option<u64>,
    landed: Option<Snapshot>,
}
impl Phase {
    pub(in super::super) fn new(ready: &Ready) -> Self {
        Self {
            parent: ready.parent_plan(),
            stage: 0,
            child_ret: None,
            parent_ret: None,
            landed: None,
        }
    }
    pub(in super::super) fn step_bucket(&self) -> usize {
        usize::from(self.stage) + 1
    }
    pub(in super::super) fn logical(
        &mut self,
        oracle: &NormalOracle,
        child: &Tracee,
        ready: &Ready,
        logical: u64,
    ) {
        if logical == ready.parent().entry + self.parent.continuation {
            assert_eq!(self.stage, 3);
            let before = self.landed.take().expect("actual child C3 landing");
            assert_state(
                &before,
                &oracle.snapshot(child, &WalkReady::CallPair(ready.clone()), logical),
            );
            if ready.journal.is_some() {
                self.check(oracle, child, ready, 3, 1);
            }
            self.stage = advance(self.stage, Event::None, true);
        }
    }
    fn check(&self, oracle: &NormalOracle, child: &Tracee, ready: &Ready, used: usize, depth: u64) {
        let j = ready.journal.as_ref().unwrap();
        check_journal(
            &child.memory(j.address, PAGE),
            &journal(
                ready,
                child.pid as u64,
                oracle.caller_rsp(),
                self.child_ret,
                self.parent_ret,
                used,
                depth,
            ),
        );
    }
    fn command(
        &self,
        (stage, logical, used, depth): (usize, u64, usize, u64),
        oracle: &NormalOracle,
        walk: &Walk<'_>,
        ready: &Ready,
        channel: &mut Option<ControlParent>,
    ) {
        if ready.journal.is_none() || !ready.case.scenario.helper() {
            return;
        }
        let child = walk.child;
        let wr = WalkReady::CallPair(ready.clone());
        let before = oracle.snapshot(child, &wr, logical);
        let pc = child.registers().rip;
        channel
            .as_mut()
            .expect("owned controller channel")
            .request_with(stage, oracle.deadline, |words| {
                super::check_ack(words, stage, child.pid as u64, ready)
            });
        assert_eq!(child.registers().rip, pc);
        assert_state(&before, &oracle.snapshot(child, &wr, logical));
        self.check(oracle, child, ready, used, depth);
    }
    pub(in super::super) fn before(
        &mut self,
        oracle: &NormalOracle,
        walk: &Walk<'_>,
        ready: &Ready,
        logical: Option<u64>,
        channel: &mut Option<ControlParent>,
    ) -> Event {
        let r = walk.child.registers();
        let rsp = oracle.caller_rsp();
        let prsp = rsp.checked_sub(ready.plan.subject_rsp_delta()).unwrap();
        let crsp = prsp.checked_sub(self.parent.delta).unwrap();
        let word = |at| word_at(&walk.child.memory(at, 8), at, at);
        if r.rip == ready.caller + ready.plan.calls()[0] {
            assert_eq!(self.stage, 0);
            let step = ready
                .plan
                .steps()
                .iter()
                .find(|s| s.offset == ready.plan.calls()[0])
                .unwrap();
            assert_eq!(
                walk.child.memory(r.rip, usize::from(step.length)),
                ready.plan.bytes()
                    [step.offset as usize..step.offset as usize + usize::from(step.length)]
            );
            copied_rust::call_before_view(
                &r,
                ready.view(),
                0,
                rsp,
                oracle.data.address(),
                ready.case.bound(),
            );
            return Event::ParentCall;
        }
        if logical == Some(ready.parent().entry + self.parent.call) {
            assert_eq!(self.stage, 1);
            assert_eq!(
                r.rip,
                ready.parent().entry + self.parent.call,
                "original E8 address"
            );
            assert_eq!(
                walk.child.memory(r.rip, 5),
                self.parent.code[self.parent.call as usize..self.parent.call as usize + 5]
            );
            assert_eq!(
                (r.rsp, r.rdi, r.rsi),
                (
                    crsp.checked_add(8).unwrap(),
                    oracle.data.address() + INPUT as u64,
                    ready.case.bound() as u64
                )
            );
            assert_eq!(word(prsp), ready.caller + ready.plan.continuations()[0]);
            if ready.journal.is_some() {
                self.check(oracle, walk.child, ready, 1, 1);
            }
            self.command((1, logical.unwrap(), 1, 1), oracle, walk, ready, channel);
            return Event::ChildCall;
        }
        if logical.is_some_and(|p| ready.child().returns.contains(&p)) {
            assert_eq!(self.stage, 2);
            assert_eq!(walk.child.memory(r.rip, 1), [0xc3]);
            assert_eq!(
                (r.rsp, r.rax, word(r.rsp)),
                (
                    crsp,
                    ready.case.fields(),
                    ready.parent().entry + self.parent.continuation
                )
            );
            self.child_ret = logical;
            if ready.journal.is_some() {
                self.check(oracle, walk.child, ready, 3, 2);
            }
            return Event::ChildReturn;
        }
        if logical == Some(ready.parent().returns[0]) {
            assert_eq!(self.stage, 4);
            assert!(self.landed.is_none());
            assert_eq!(walk.child.memory(r.rip, 1), [0xc3]);
            assert_eq!(
                (r.rsp, r.rax, word(r.rsp)),
                (
                    prsp,
                    ready.case.value(),
                    ready.caller + ready.plan.continuations()[0]
                )
            );
            self.parent_ret = logical;
            if ready.journal.is_some() {
                self.check(oracle, walk.child, ready, 4, 1);
            }
            self.command((2, logical.unwrap(), 4, 1), oracle, walk, ready, channel);
            return Event::ParentReturn;
        }
        Event::None
    }
    pub(in super::super) fn after(
        &mut self,
        event: Event,
        oracle: &NormalOracle,
        walk: &Walk<'_>,
        ready: &Ready,
    ) {
        let r = walk.child.registers();
        let rsp = oracle.caller_rsp();
        let prsp = rsp.checked_sub(ready.plan.subject_rsp_delta()).unwrap();
        let crsp = prsp.checked_sub(self.parent.delta).unwrap();
        let cont = ready.parent().entry + self.parent.continuation;
        let word = |at| word_at(&walk.child.memory(at, 8), at, at);
        match event {
            Event::None => {}
            Event::ParentCall => {
                assert_eq!(self.stage, 0);
                copied_rust::call_after_view(&r, ready.view(), 0, rsp, word(r.rsp));
                self.stage = advance(self.stage, event, false);
            }
            Event::ChildCall => {
                assert_eq!(self.stage, 1);
                landing(
                    ready,
                    self.parent.delta,
                    event,
                    [r.rip, r.rsp, r.rax, word(r.rsp)],
                    rsp,
                );
                self.stage = advance(self.stage, event, false);
            }
            Event::ChildReturn => {
                assert_eq!(self.stage, 2);
                landing(
                    ready,
                    self.parent.delta,
                    event,
                    [r.rip, r.rsp, r.rax, word(crsp)],
                    rsp,
                );
                if ready.journal.is_some() {
                    self.check(oracle, walk.child, ready, 3, 2);
                }
                self.landed =
                    Some(oracle.snapshot(walk.child, &WalkReady::CallPair(ready.clone()), cont));
                self.stage = advance(self.stage, event, true);
            }
            Event::ParentReturn => {
                assert_eq!(self.stage, 4);
                landing(
                    ready,
                    self.parent.delta,
                    event,
                    [r.rip, r.rsp, r.rax, word(prsp)],
                    rsp,
                );
                self.stage = advance(self.stage, event, false);
            }
        }
    }
    pub(in super::super) fn finish(&self) {
        assert_eq!(self.stage, 5);
        assert!(self.landed.is_none() && self.child_ret.is_some() && self.parent_ret.is_some());
    }
}
