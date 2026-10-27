//! Independent original-site reference lane. It owns real wait/query prefixes,
//! uses no admitted permit, and never converts a partial stop into completion.
use super::{
    OracleError,
    artifact::{ArtifactPlan, Outcome, PinnedArtifact, PlannedKind, exact, outcome},
    dataflow::{self, DataflowContract, FrameObservation},
    observe::{self, DebugExpectation, LaneShape, PreparedLane},
};
use crate::linux::remote::dynamic::owner::admission::source_identity;
use crate::linux::remote::dynamic::owner::trusted::TaskStateSnapshot;
use crate::linux::remote::dynamic::owner::{
    Owner, State,
    bootstrap::{self, StateSlot},
};
use crate::{DynamicEvent, DynamicEventKind, RegisterSnapshot};
use std::{mem::size_of, time::Instant};
mod namespace;
mod projection;
use namespace::Namespace;
use observe::control::{EntryControls, EntryPhase};
#[cfg(test)]
mod tests;

const STATES: usize = 6; // exec EXIT, entry trap, three actual ENTRY, terminal pre-exit
const WAITS: usize = 42; // two startup +30 ordinary+CALL+RET +six syscall stops+terminal
const REQUESTS: usize = 64;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RawBoundary {
    Returned { ordinal: usize, number: u64 },
    Terminal { status: i32 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RawPhase {
    Empty,
    Metadata,
    Allocated,
    ExecExit,
    EntryTrap,
    Restored,
    Original,
    SyscallEntry,
    SyscallExit,
    PreExit,
    Terminal,
    Complete,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct RawRequest {
    pub(super) operation: u32,
    pub(super) address: usize,
    pub(super) data: usize,
    pub(super) result: Outcome,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Wait {
    pub(super) actual: Option<(i32, i32)>,
    pub(super) query_started: bool,
    pub(super) signal: [u8; 128],
    pub(super) signal_request: Option<Outcome>,
    pub(super) syscall: [u8; 88],
    pub(super) syscall_request: Option<Outcome>,
    pub(super) event_message: u64,
    pub(super) message_request: Option<Outcome>,
}
impl Wait {
    fn empty() -> Self {
        Self {
            actual: None,
            query_started: false,
            signal: [0; 128],
            signal_request: None,
            syscall: [0; 88],
            syscall_request: None,
            event_message: 0,
            message_request: None,
        }
    }
}
pub(super) struct PreparedRawLane {
    pub(super) lane: PreparedLane,
    controls: EntryControls,
    projection: projection::ExecutableProjection,
    pub(super) states: [StateSlot; STATES],
    pub(super) waits: [Wait; WAITS],
    pub(super) requests: [Option<RawRequest>; REQUESTS],
    pub(super) namespaces: [Namespace; 5],
    pub(super) phase: RawPhase,
    pub(super) first_failure: Option<RawPhase>,
    pub(super) initial_word: Option<[u8; 8]>,
    pub(super) patched_word: Option<[u8; 8]>,
    pub(super) peek_values: [Option<u64>; 2],
    pub(super) segments: [Option<Instant>; 3],
    pub(super) frame: Option<FrameObservation>,
    pub(super) terminal: Option<(i32, i32)>,
    pub(super) physical_reaped: bool,
    next: usize,
    wait_count: usize,
    request_count: usize,
    segment: usize,
    namespace_count: usize,
    allocated: bool,
    initialized: bool,
    trace_seen: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RawProgress {
    pub(super) phase: RawPhase,
    pub(super) first_failure: Option<RawPhase>,
    pub(super) next: usize,
    pub(super) waits: usize,
    pub(super) requests: usize,
    pub(super) segment: usize,
    pub(super) namespaces: usize,
    pub(super) allocated: bool,
    pub(super) initialized: bool,
    pub(super) trace_seen: bool,
}
impl PreparedRawLane {
    pub(super) fn empty() -> Self {
        Self {
            lane: PreparedLane::empty(),
            controls: EntryControls::empty(),
            projection: projection::ExecutableProjection::empty(),
            states: std::array::from_fn(|_| observe::empty_state()),
            waits: std::array::from_fn(|_| Wait::empty()),
            requests: [None; REQUESTS],
            namespaces: std::array::from_fn(|_| Namespace::empty()),
            phase: RawPhase::Empty,
            first_failure: None,
            initial_word: None,
            patched_word: None,
            peek_values: [None; 2],
            segments: [None; 3],
            frame: None,
            terminal: None,
            physical_reaped: false,
            next: 0,
            wait_count: 0,
            request_count: 0,
            segment: 0,
            namespace_count: 0,
            allocated: false,
            initialized: false,
            trace_seen: false,
        }
    }
    pub(super) fn progress(&self) -> RawProgress {
        RawProgress {
            phase: self.phase,
            first_failure: self.first_failure,
            next: self.next,
            waits: self.wait_count,
            requests: self.request_count,
            segment: self.segment,
            namespaces: self.namespace_count,
            allocated: self.allocated,
            initialized: self.initialized,
            trace_seen: self.trace_seen,
        }
    }
    pub(super) fn mark_aborted(&mut self) {
        self.first_failure.get_or_insert(self.phase);
        self.projection.mark_aborted();
    }
    fn result<T>(&mut self, result: Result<T, OracleError>) -> Result<T, OracleError> {
        if result.is_err() {
            self.first_failure.get_or_insert(self.phase);
        }
        result
    }
    pub(super) fn allocate_metadata(&mut self) -> Result<(), OracleError> {
        if self.phase != RawPhase::Empty {
            return Err(OracleError::Invalid("raw metadata reused"));
        }
        self.phase = RawPhase::Metadata;
        let result = (|| {
            self.lane.allocate_metadata()?;
            self.projection.allocate_payloads()
        })();
        self.result(result)
    }
    pub(super) fn capture_initial(
        &mut self,
        owner: &Owner,
        initial: &DynamicEvent,
        plan: &ArtifactPlan,
        file: &PinnedArtifact,
        until: Instant,
    ) -> Result<LaneShape, OracleError> {
        let result = (|| {
            if self.phase != RawPhase::Metadata
                || self.first_failure.is_some()
                || initial.tid != owner.pid
                || !matches!(initial.kind, DynamicEventKind::Exec { .. })
            {
                return Err(OracleError::Invalid("raw actual EXEC identity differs"));
            }
            owner.require_stop(
                initial
                    .stop_token()
                    .ok_or(OracleError::Invalid("raw initial token absent"))?,
            )?;
            self.lane
                .capture_exec_metadata(owner, initial, plan, file.bytes()?, until)?;
            let state = &self.lane.metadata.state.state;
            if state.registers.rip != plan.entry
                || state.registers.orig_rax != libc::SYS_execve as u64
                || state.registers.rax != (-i64::from(libc::ENOSYS)) as u64
            {
                return Err(OracleError::Invalid("raw native EXEC state differs"));
            }
            self.projection.capture(
                owner,
                initial.stop_token().ok_or(OracleError::Invalid(
                    "raw executable projection EXEC token absent",
                ))?,
                file,
                plan,
                self.lane.metadata.maps.prefix(),
                until,
            )?;
            self.frame = Some(dataflow::require_frame(plan, state)?);
            self.segments[0] = Some(until);
            self.lane.observed_shape(plan)
        })();
        self.result(result)
    }
    pub(super) fn allocate_remainder(
        &mut self,
        plan: &ArtifactPlan,
        shape: LaneShape,
    ) -> Result<(), OracleError> {
        let result = (|| {
            if self.allocated || self.first_failure.is_some() || !self.lane.metadata.complete {
                return Err(OracleError::Invalid("raw allocation phase differs"));
            }
            if shape != self.lane.observed_shape(plan)? {
                return Err(OracleError::Invalid(
                    "raw allocation differs from actual stack shape",
                ));
            }
            self.lane.allocate_frames(plan, shape)?;
            self.controls.allocate()?;
            for state in &mut self.states {
                observe::allocate_state(state)?;
            }
            self.allocated = true;
            self.phase = RawPhase::Allocated;
            Ok(())
        })();
        self.result(result)
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize, OracleError> {
        let own = size_of::<Self>() - size_of::<PreparedLane>();
        own.checked_add(self.lane.allocated_bytes()?)
            .and_then(|n| n.checked_add(self.controls.allocated_payload_bytes()))
            .and_then(|n| n.checked_add(self.projection.allocated_payload_bytes()))
            .and_then(|n| {
                n.checked_add(
                    self.states
                        .iter()
                        .map(|s| s.state.xstate.capacity())
                        .sum::<usize>(),
                )
            })
            .ok_or(OracleError::Invalid("raw capacity overflows"))
    }
    pub(super) fn reservation_bytes(shape: LaneShape) -> Result<usize, OracleError> {
        (size_of::<Self>() - size_of::<PreparedLane>())
            .checked_add(shape.retained_bytes)
            .and_then(|n| n.checked_add(EntryControls::reserved_payload_bytes()))
            .and_then(|n| n.checked_add(projection::ExecutableProjection::reserved_payload_bytes()))
            .and_then(|n| n.checked_add(STATES * 64 * 1024))
            .ok_or(OracleError::Invalid("raw reservation overflows"))
    }
    pub(super) fn temporary_bytes(shape: LaneShape) -> Result<usize, OracleError> {
        let projection = projection::ExecutableProjection::temporary_bytes()?;
        shape
            .temporary_bytes
            .checked_add(
                size_of::<libc::siginfo_t>()
                    + size_of::<libc::user_regs_struct>()
                    + 3 * size_of::<RegisterSnapshot>()
                    + size_of::<Namespace>()
                    + size_of::<PreparedRawLane>()
                    + size_of::<libc::stat>()
                    + size_of::<libc::statfs>()
                    + 48
                    + 10
                    + 2 * 8
                    + 32 * size_of::<usize>(),
            )
            .and_then(|n| n.checked_add(projection))
            .ok_or(OracleError::Invalid("raw temporary overflows"))
    }
    pub(super) fn initialize(
        &mut self,
        owner: &mut Owner,
        initial: &DynamicEvent,
        plan: &ArtifactPlan,
        until: Instant,
    ) -> Result<(), OracleError> {
        let result = self.initialize_inner(owner, initial, plan, until);
        self.result(result)
    }
    fn initialize_inner(
        &mut self,
        owner: &mut Owner,
        initial: &DynamicEvent,
        plan: &ArtifactPlan,
        until: Instant,
    ) -> Result<(), OracleError> {
        if !self.allocated
            || self.initialized
            || self.first_failure.is_some()
            || self.segments[0] != Some(until)
        {
            return Err(OracleError::Invalid(
                "raw initialization reused or deadline differs",
            ));
        }
        owner.require_stop(
            initial
                .stop_token()
                .ok_or(OracleError::Invalid("raw actual EXEC token absent"))?,
        )?;
        self.projection.require_at(
            plan,
            self.lane.metadata.maps.prefix(),
            initial.stop_token().ok_or(OracleError::Invalid(
                "raw executable projection release token absent",
            ))?,
            until,
        )?;
        self.phase = RawPhase::ExecExit;
        self.release(owner, libc::PTRACE_SYSCALL, until)?;
        let wait = self.wait(owner, until, libc::SIGTRAP | 0x80, 0)?;
        let info = self.syscall_info(owner, wait, until);
        let state = capture(owner, &mut self.states[0], until);
        info?;
        state?;
        let original = &self.lane.metadata.state.state;
        let exited = &self.states[0].state;
        let mut expected = original.registers;
        expected.rax = 0;
        if exited.registers != expected
            || exited.xstate != original.xstate
            || exited.mask != original.mask
        {
            return Err(OracleError::Invalid("raw real exec EXIT differs"));
        }
        validate_syscall(&self.waits[wait], exited, 2, None, Some(0))?;
        // EXEC is before kernel rseq reset. Authenticate the actual EXIT
        // profile before any entry POKE/CONT; a later INT3 cannot prove this.
        self.lane.metadata.require_exec_control(until)?;
        if wait != 0 {
            return Err(OracleError::Invalid(
                "raw initial EXIT wait ordinal differs",
            ));
        }
        self.controls.capture(
            owner,
            &self.lane.metadata.exec_control,
            EntryPhase::ExecExit,
            self.waits[wait]
                .actual
                .ok_or(OracleError::Invalid("raw EXIT wait absent"))?,
            &self.states[0],
        )?;
        let offset = usize::try_from(plan.entry - plan.read_load.start)
            .map_err(|_| OracleError::Invalid("raw entry offset differs"))?;
        let word: [u8; 8] = self
            .lane
            .metadata
            .source
            .prefix()
            .get(offset..offset + 8)
            .ok_or(OracleError::Invalid("raw entry word outside source"))?
            .try_into()
            .map_err(|_| OracleError::Invalid("raw entry word differs"))?;
        self.initial_word = Some(word);
        let mut patched = word;
        patched[0] = 0xcc;
        self.patched_word = Some(patched);
        self.request(
            owner,
            libc::PTRACE_POKEDATA,
            plan.entry as usize,
            u64::from_ne_bytes(patched) as usize,
            until,
        )?;
        let value = self.peek(owner, plan.entry, until)?;
        self.peek_values[0] = Some(value);
        if value.to_ne_bytes() != patched {
            return Err(OracleError::Invalid("raw entry patch did not verify"));
        }
        self.phase = RawPhase::EntryTrap;
        self.release(owner, libc::PTRACE_CONT, until)?;
        let wait = self.wait(owner, until, libc::SIGTRAP, 0)?;
        let signal = self.signal(owner, wait, until);
        let state = capture(owner, &mut self.states[1], until);
        signal?;
        state?;
        require_signal(&self.waits[wait], false)?;
        let first = &self.states[1].state;
        let exited = &self.states[0].state;
        let mut expected = exited.registers;
        expected.rip = plan.entry + 1;
        expected.orig_rax = u64::MAX;
        if first.registers != expected || first.mask != exited.mask {
            return Err(OracleError::Invalid(
                "raw first-user trap changed unrelated state",
            ));
        }
        let mut restored = first.registers;
        restored.rip = plan.entry;
        self.request(
            owner,
            libc::PTRACE_POKEDATA,
            plan.entry as usize,
            u64::from_ne_bytes(word) as usize,
            until,
        )?;
        let value = self.peek(owner, plan.entry, until)?;
        self.peek_values[1] = Some(value);
        if value.to_ne_bytes() != word {
            return Err(OracleError::Invalid("raw entry restoration did not verify"));
        }
        let registers: libc::user_regs_struct = restored.into();
        self.request(
            owner,
            libc::PTRACE_SETREGS,
            0,
            (&raw const registers) as usize,
            until,
        )?;
        self.phase = RawPhase::Restored;
        self.lane
            .capture(owner, plan, 0, false, DebugExpectation::Initial, until)?;
        let actual = &self.lane.frame(0, false)?.state.state;
        if actual.registers != restored
            || actual.xstate != self.states[1].state.xstate
            || actual.mask != self.states[1].state.mask
        {
            return Err(OracleError::Invalid(
                "raw restored initial full state differs",
            ));
        }
        // Frame0 is normally ordinary and has no stack payload. Its capture
        // therefore does not run access(); validate the actual restored state
        // unconditionally, after exact INT3 restoration and before readiness
        // or the first original instruction. EXEC metadata remains pre-user.
        observe::require_user_state(
            &self.lane.frame(0, false)?.state,
            &self.lane.metadata.layout,
        )?;
        // This is a fresh profile: neither the pre-reset EXEC observation
        // nor the EXIT qualification may stand in for restored-user control.
        if wait != 1 {
            return Err(OracleError::Invalid("raw first-user wait ordinal differs"));
        }
        self.controls.capture(
            owner,
            &self.lane.metadata.exec_control,
            EntryPhase::Restored,
            self.waits[wait]
                .actual
                .ok_or(OracleError::Invalid("raw first-user wait absent"))?,
            &self.lane.frame(0, false)?.state,
        )?;
        self.require_initial_controls(plan)?;
        self.initialized = true;
        Ok(())
    }
    fn require_initial_controls(&self, plan: &ArtifactPlan) -> Result<(), OracleError> {
        let until = self.segments[0].ok_or(OracleError::Invalid("raw initial deadline absent"))?;
        self.lane.metadata.require_exec_control(until)?;
        self.controls.require(
            &self.lane.metadata.exec_control,
            EntryPhase::ExecExit,
            self.waits[0]
                .actual
                .ok_or(OracleError::Invalid("raw retained EXIT wait absent"))?,
            &self.states[0],
        )?;
        self.controls.require(
            &self.lane.metadata.exec_control,
            EntryPhase::Restored,
            self.waits[1]
                .actual
                .ok_or(OracleError::Invalid("raw retained first-user wait absent"))?,
            &self.lane.frame(0, false)?.state,
        )?;
        // Recheck the same full bridge observations; no successful phase flag
        // substitutes for the actual retained state, signal, source or requests.
        let original = &self.lane.metadata.state.state;
        let exited = &self.states[0].state;
        let mut expected = original.registers;
        expected.rax = 0;
        if exited.registers != expected
            || exited.xstate != original.xstate
            || exited.mask != original.mask
        {
            return Err(OracleError::Invalid("raw retained exec EXIT differs"));
        }
        validate_syscall(&self.waits[0], exited, 2, None, Some(0))?;
        require_signal(&self.waits[1], false)?;
        let first = &self.states[1].state;
        expected.rip = plan.entry + 1;
        expected.orig_rax = u64::MAX;
        if first.registers != expected || first.mask != exited.mask {
            return Err(OracleError::Invalid("raw retained first-user trap differs"));
        }
        expected.rip = plan.entry;
        let restored = &self.lane.frame(0, false)?.state;
        if restored.state.registers != expected
            || restored.state.xstate != first.xstate
            || restored.state.mask != first.mask
        {
            return Err(OracleError::Invalid(
                "raw retained restored full state differs",
            ));
        }
        observe::require_user_state(restored, &self.lane.metadata.layout)
    }
    fn request(
        &mut self,
        owner: &Owner,
        operation: u32,
        address: usize,
        data: usize,
        until: Instant,
    ) -> Result<(), OracleError> {
        bootstrap::physical(owner, until)?;
        if self.request_count == REQUESTS {
            return Err(OracleError::Invalid("raw request count exceeds bound"));
        }
        let result = ptrace(operation, owner.pid, address, data);
        self.requests[self.request_count] = Some(RawRequest {
            operation,
            address,
            data,
            result,
        });
        self.request_count += 1;
        exact(result, 0, "raw original ptrace request")?;
        bootstrap::physical(owner, until)?;
        Ok(())
    }
    fn peek(&mut self, owner: &Owner, address: u64, until: Instant) -> Result<u64, OracleError> {
        bootstrap::physical(owner, until)?;
        if self.request_count == REQUESTS {
            return Err(OracleError::Invalid("raw request count exceeds bound"));
        }
        let result = ptrace(libc::PTRACE_PEEKDATA, owner.pid, address as usize, 0);
        self.requests[self.request_count] = Some(RawRequest {
            operation: libc::PTRACE_PEEKDATA,
            address: address as usize,
            data: 0,
            result,
        });
        self.request_count += 1;
        if result.errno != 0 {
            return Err(OracleError::Io {
                operation: "raw entry word read",
                errno: Some(result.errno),
            });
        }
        bootstrap::physical(owner, until)?;
        Ok(result.result as u64)
    }
    fn release(
        &mut self,
        owner: &mut Owner,
        operation: u32,
        until: Instant,
    ) -> Result<(), OracleError> {
        bootstrap::physical(owner, until)?;
        if self.request_count == REQUESTS {
            return Err(OracleError::Invalid("raw request count exceeds bound"));
        }
        let result = ptrace(operation, owner.pid, 0, 0);
        self.requests[self.request_count] = Some(RawRequest {
            operation,
            address: 0,
            data: 0,
            result,
        });
        self.request_count += 1;
        // Successful release retires stopped authority before any fallible
        // post-call check. A deadline error cannot leave a running task labelled held.
        if result.result == 0 {
            owner.released(owner.pid);
            owner.state = State::Running;
        }
        exact(result, 0, "raw original release")
    }
    fn wait(
        &mut self,
        owner: &mut Owner,
        until: Instant,
        signal: i32,
        event: i32,
    ) -> Result<usize, OracleError> {
        if self.wait_count == WAITS {
            return Err(OracleError::Invalid("raw wait count exceeds bound"));
        }
        let index = self.wait_count;
        self.wait_count += 1;
        let (tid, status) = owner.wait_raw(until, "raw finite consumer wait")?;
        self.waits[index].actual = Some((tid, status));
        bootstrap::raw_held(owner, tid, status, until)?;
        self.waits[index].query_started = true;
        if tid != owner.pid || libc::WSTOPSIG(status) != signal || status >> 16 != event {
            return Err(OracleError::Invalid("raw original wait phase differs"));
        }
        Ok(index)
    }
    fn signal(&mut self, owner: &Owner, index: usize, until: Instant) -> Result<(), OracleError> {
        bootstrap::physical(owner, until)?;
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = ptrace(
            libc::PTRACE_GETSIGINFO,
            owner.pid,
            0,
            (&raw mut info) as usize,
        );
        self.waits[index].signal_request = Some(result);
        // SAFETY: Linux siginfo_t is the fixed initialized 128-byte raw image.
        if size_of::<libc::siginfo_t>() != 128 {
            return Err(OracleError::Invalid("raw siginfo layout differs"));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&raw const info).cast::<u8>(),
                self.waits[index].signal.as_mut_ptr(),
                128,
            )
        };
        exact(result, 0, "raw actual siginfo")?;
        bootstrap::physical(owner, until)?;
        Ok(())
    }
    fn syscall_info(
        &mut self,
        owner: &Owner,
        index: usize,
        until: Instant,
    ) -> Result<(), OracleError> {
        bootstrap::physical(owner, until)?;
        let raw = &mut self.waits[index];
        let result = ptrace(
            libc::PTRACE_GET_SYSCALL_INFO,
            owner.pid,
            88,
            raw.syscall.as_mut_ptr() as usize,
        );
        raw.syscall_request = Some(result);
        if result.errno != 0 || !(33..=88).contains(&result.result) {
            return Err(OracleError::Invalid("raw syscall-info extent differs"));
        }
        bootstrap::physical(owner, until)?;
        Ok(())
    }
    fn namespace(&mut self, owner: &Owner, until: Instant) -> Result<(), OracleError> {
        if self.namespace_count == 5 {
            return Err(OracleError::Invalid("raw namespace count exceeds bound"));
        }
        self.namespaces[self.namespace_count].capture(owner, until)?;
        if self.namespace_count != 0
            && self.namespaces[self.namespace_count].identity() != self.namespaces[0].identity()
        {
            return Err(OracleError::Invalid("raw PID namespace changed"));
        }
        self.namespace_count += 1;
        Ok(())
    }
}
pub(super) fn run_segment(
    owner: &mut Owner,
    p: &mut PreparedRawLane,
    plan: &ArtifactPlan,
    until: Instant,
) -> Result<RawBoundary, OracleError> {
    let result = segment(owner, p, plan, until);
    p.result(result)
}
fn segment(
    owner: &mut Owner,
    p: &mut PreparedRawLane,
    plan: &ArtifactPlan,
    until: Instant,
) -> Result<RawBoundary, OracleError> {
    if !p.initialized || p.first_failure.is_some() || p.segment >= 3 {
        return Err(OracleError::Invalid("raw segment phase differs"));
    }
    if p.segment == 0 {
        if p.segments[0] != Some(until) {
            return Err(OracleError::Invalid("raw first deadline changed"));
        }
    } else {
        if p.segments[p.segment].is_some() {
            return Err(OracleError::Invalid("raw segment deadline reused"));
        }
        p.segments[p.segment] = Some(until);
    }
    loop {
        let ordinal = p.next;
        let instruction = plan.instruction(ordinal)?;
        let debug = if p.trace_seen {
            DebugExpectation::Trace
        } else {
            DebugExpectation::Initial
        };
        if !(ordinal == 0 && p.lane.completed == 1) {
            p.lane.capture(owner, plan, ordinal, false, debug, until)?;
        }
        let before = &p.lane.frame(ordinal, false)?.state.state;
        if before.registers.rip != instruction.pc() {
            return Err(OracleError::Invalid(
                "raw actual PC differs from closed plan",
            ));
        }
        p.phase = RawPhase::Original;
        match instruction.kind() {
            PlannedKind::Ordinary | PlannedKind::Call | PlannedKind::Ret => {
                p.release(owner, libc::PTRACE_SINGLESTEP, until)?;
                let wait = p.wait(owner, until, libc::SIGTRAP, 0)?;
                let signal = p.signal(owner, wait, until);
                let observed =
                    p.lane
                        .capture(owner, plan, ordinal, true, DebugExpectation::Trace, until);
                signal?;
                observed?;
                require_signal(&p.waits[wait], true)?;
                p.lane.require_transition(
                    plan,
                    ordinal,
                    p.frame.ok_or(OracleError::Invalid("raw frame absent"))?,
                )?;
                p.trace_seen = true;
                p.next += 1;
            }
            PlannedKind::Syscall { number } => {
                if before.registers.rax != number {
                    return Err(OracleError::Invalid("raw actual syscall number differs"));
                }
                p.namespace(owner, until)?;
                p.phase = RawPhase::SyscallEntry;
                p.release(owner, libc::PTRACE_SYSCALL, until)?;
                let entry = p.wait(owner, until, libc::SIGTRAP | 0x80, 0)?;
                let info = p.syscall_info(owner, entry, until);
                let state = capture(owner, &mut p.states[2 + p.segment], until);
                info?;
                state?;
                let before = &p.lane.frame(ordinal, false)?.state.state;
                let actual = &p.states[2 + p.segment].state;
                validate_syscall(&p.waits[entry], actual, 1, Some(number), None)?;
                require_entry(before, actual, instruction.next_pc(), number)?;
                if number == 231 {
                    if before.registers.rdi != 7 {
                        return Err(OracleError::Invalid("raw terminal full argument differs"));
                    }
                    p.phase = RawPhase::PreExit;
                    p.release(owner, libc::PTRACE_CONT, until)?;
                    let wait = p.wait(owner, until, libc::SIGTRAP, libc::PTRACE_EVENT_EXIT)?;
                    bootstrap::physical(owner, until)?;
                    let slot = &mut p.waits[wait];
                    let result = ptrace(
                        libc::PTRACE_GETEVENTMSG,
                        owner.pid,
                        0,
                        (&raw mut slot.event_message) as usize,
                    );
                    slot.message_request = Some(result);
                    let state = capture(owner, &mut p.states[5], until);
                    exact(result, 0, "raw pre-exit event message")?;
                    state?;
                    if p.waits[wait].event_message != 7 << 8 {
                        return Err(OracleError::Invalid("raw actual pre-exit status differs"));
                    }
                    p.phase = RawPhase::Terminal;
                    p.release(owner, libc::PTRACE_CONT, until)?;
                    let actual = owner.wait_raw(until, "raw finite consumer terminal")?;
                    p.terminal = Some(actual);
                    if actual.0 != owner.pid || !libc::WIFEXITED(actual.1) || actual.1 != 7 << 8 {
                        return Err(OracleError::Invalid("raw actual terminal differs"));
                    }
                    // No ptrace query is legal after this consumed terminal.
                    owner.wait_physical(actual.0, actual.1, until)?;
                    p.physical_reaped = true;
                    p.next += 1;
                    p.segment += 1;
                    p.phase = RawPhase::Complete;
                    return Ok(RawBoundary::Terminal { status: actual.1 });
                }
                p.phase = RawPhase::SyscallExit;
                p.release(owner, libc::PTRACE_SYSCALL, until)?;
                let exit = p.wait(owner, until, libc::SIGTRAP | 0x80, 0)?;
                let info = p.syscall_info(owner, exit, until);
                let state = p.lane.capture(owner, plan, ordinal, true, debug, until);
                info?;
                state?;
                let before = &p.lane.frame(ordinal, false)?.state.state;
                let after = &p.lane.frame(ordinal, true)?.state.state;
                validate_syscall(&p.waits[exit], after, 2, None, Some(i64::from(owner.pid)))?;
                require_exit(before, after, instruction.next_pc(), number, owner.pid)?;
                p.namespace(owner, until)?;
                p.next += 1;
                p.segment += 1;
                return Ok(RawBoundary::Returned { ordinal, number });
            }
        }
    }
}
pub(super) fn require_complete(
    p: &PreparedRawLane,
    plan: &ArtifactPlan,
    contract: &DataflowContract,
) -> Result<(), OracleError> {
    if p.phase != RawPhase::Complete
        || !p.initialized
        || p.first_failure.is_some()
        || !p.physical_reaped
        || p.next != plan.len()
        || p.segment != 3
        || p.namespace_count != 5
        || p.wait_count != plan.len() + 5
        || p.request_count != plan.len() + 11
        || p.waits[..p.wait_count]
            .iter()
            .any(|w| w.actual.is_none() || !w.query_started)
        || p.waits[p.wait_count..]
            .iter()
            .any(|w| w.actual.is_some() || w.query_started)
        || p.requests[..p.request_count].iter().any(Option::is_none)
        || p.requests[p.request_count..].iter().any(Option::is_some)
        || p.states.iter().any(|s| !s.complete)
        || p.segments.iter().any(Option::is_none)
        || p.lane.completed != 2 * plan.len() - 1
    {
        return Err(OracleError::Invalid("raw finite evidence incomplete"));
    }
    p.require_initial_controls(plan)?;
    for namespace in &p.namespaces {
        namespace.require_complete()?;
    }
    let actual_pid = p
        .terminal
        .ok_or(OracleError::Invalid("raw actual terminal absent"))?
        .0;
    p.projection.require_retained(
        plan,
        p.lane.metadata.maps.prefix(),
        p.segments[0].ok_or(OracleError::Invalid("raw projection deadline absent"))?,
        actual_pid,
    )?;
    p.lane.require_complete(
        plan,
        contract,
        p.frame.ok_or(OracleError::Invalid("raw frame absent"))?,
        actual_pid,
    )
}
fn ptrace(operation: u32, pid: i32, address: usize, data: usize) -> Outcome {
    outcome(|| unsafe { libc::ptrace(operation, pid, address, data) as i64 })
}
fn capture(owner: &Owner, state: &mut StateSlot, until: Instant) -> Result<(), OracleError> {
    if state.state.xstate.capacity() != 64 * 1024
        || state.registers_request.is_some()
        || state.xstate_request.is_some()
        || state.mask_request.is_some()
    {
        return Err(OracleError::Invalid("raw state slot unallocated or reused"));
    }
    bootstrap::physical(owner, until)?;
    let result = state.capture(owner, until);
    let held = bootstrap::physical(owner, until);
    result?;
    held?;
    Ok(())
}
fn require_signal(wait: &Wait, trace: bool) -> Result<(), OracleError> {
    let read = |offset| i32::from_ne_bytes(wait.signal[offset..offset + 4].try_into().unwrap());
    if wait.signal_request
        != Some(Outcome {
            result: 0,
            errno: 0,
        })
        || read(0) != libc::SIGTRAP
        || read(4) != 0
        || if trace {
            read(8) != libc::TRAP_TRACE
        } else {
            !matches!(read(8), libc::SI_KERNEL | libc::TRAP_BRKPT)
        }
    {
        return Err(OracleError::Invalid("raw actual trap code differs"));
    }
    Ok(())
}
fn u64_raw(raw: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(raw[offset..offset + 8].try_into().unwrap())
}
fn validate_syscall(
    wait: &Wait,
    state: &TaskStateSnapshot,
    op: u8,
    number: Option<u64>,
    result: Option<i64>,
) -> Result<(), OracleError> {
    let r = wait
        .syscall_request
        .ok_or(OracleError::Invalid("raw syscall read absent"))?;
    let raw = &wait.syscall;
    let minimum = if op == 1 { 80 } else { 33 };
    if r.errno != 0
        || !(minimum..=88).contains(&r.result)
        || raw[0] != op
        || u32::from_ne_bytes(raw[4..8].try_into().unwrap()) != 0xc000003e
        || u64_raw(raw, 8) != state.registers.rip
        || u64_raw(raw, 16) != state.registers.rsp
    {
        return Err(OracleError::Invalid("raw syscall header differs"));
    }
    if let Some(number) = number {
        let regs = &state.registers;
        let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
        if u64_raw(raw, 24) != number
            || args
                .into_iter()
                .enumerate()
                .any(|(i, v)| u64_raw(raw, 32 + 8 * i) != v)
        {
            return Err(OracleError::Invalid("raw syscall payload differs"));
        }
    }
    if let Some(result) = result {
        if u64_raw(raw, 24) != result as u64 || raw[32] != 0 {
            return Err(OracleError::Invalid("raw syscall result differs"));
        }
    }
    Ok(())
}
fn entry_registers(before: RegisterSnapshot, next: u64, number: u64) -> RegisterSnapshot {
    RegisterSnapshot {
        rip: next,
        rcx: next,
        r11: before.eflags & !0x10000,
        eflags: before.eflags & !0x10000,
        orig_rax: number,
        rax: (-i64::from(libc::ENOSYS)) as u64,
        ..before
    }
}
fn require_entry(
    before: &TaskStateSnapshot,
    actual: &TaskStateSnapshot,
    next: u64,
    number: u64,
) -> Result<(), OracleError> {
    if actual.registers != entry_registers(before.registers, next, number)
        || actual.xstate != before.xstate
        || actual.mask != before.mask
    {
        return Err(OracleError::Invalid("raw actual ENTRY full state differs"));
    }
    Ok(())
}
fn require_exit(
    before: &TaskStateSnapshot,
    actual: &TaskStateSnapshot,
    next: u64,
    number: u64,
    pid: i32,
) -> Result<(), OracleError> {
    let mut registers = entry_registers(before.registers, next, number);
    registers.rax = pid as u64;
    if actual.registers != registers || actual.xstate != before.xstate || actual.mask != before.mask
    {
        return Err(OracleError::Invalid("raw actual EXIT full state differs"));
    }
    Ok(())
}
fn require_original_maps(
    plan: &ArtifactPlan,
    id: source_identity::FileIdentity,
    maps: &[u8],
) -> Result<(), OracleError> {
    let mut matched = 0;
    for row in source_identity::parse(maps)?.entries() {
        if row.inode == id.inode && row.device_major == id.major && row.device_minor == id.minor {
            let expected = if row.start == plan.read_load.start {
                (plan.read_load.end, 0, *b"r--p")
            } else if row.start == plan.text_load.start {
                (plan.text_load.end, 4096, *b"r-xp")
            } else {
                return Err(OracleError::Invalid(
                    "raw executable alias is outside two-load profile",
                ));
            };
            if row.end != expected.0
                || row.file_offset != expected.1
                || row.permissions.bytes() != expected.2
            {
                return Err(OracleError::Invalid(
                    "raw original executable mapping differs",
                ));
            }
            matched += 1;
        }
    }
    if matched != 2 {
        return Err(OracleError::Invalid("raw original executable rows absent"));
    }
    Ok(())
}
