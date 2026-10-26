//! One original admitted exec, with no success continuation in the old mm.
//! Archive ownership and all storage reservations precede this transport.
use super::*;

// Stop sequence numbers belong to a TaskId. Exec creates a fresh TaskId at
// sequence zero; actual dispatch/ExecTicket and the archive order link the two
// namespaces. These consistency predicates confer no native authority.
fn original_entry_follows(original: &DynamicStop, entry: &DynamicStop) -> bool {
    original.task.is_some()
        && entry.task == original.task
        && entry.session == original.session
        && entry.tid == original.tid
        && entry.sequence > original.sequence
}

fn replacement_exec_birth(entry: &DynamicStop, exec: &DynamicStop) -> bool {
    entry.task.is_some()
        && exec.task.is_some()
        && exec.task != entry.task
        && exec.session == entry.session
        && exec.tid == entry.tid
        && exec.sequence == 0
}

/// Exact original input after the owner's ordinary private-control settlement.
/// The observer authenticates its preattached archive against these same facts.
pub(in crate::linux::remote::dynamic::owner) struct ExecInvocation<'a> {
    pub(in crate::linux::remote::dynamic::owner) stop: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner) input: &'a SelectedInput,
    pub(in crate::linux::remote::dynamic::owner) before: &'a TaskStateSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum ExecRelease {
    Original,
    Entry,
    ExecEvent,
}

/// These callbacks record evidence; none grants a new native capability.
/// There are deliberately no default implementations. In particular `raw`
/// must retain the actual initialized prefix and independent read outcomes
/// before the lifecycle dispatcher can reject ELF, ABI or identity evidence.
pub(in crate::linux::remote::dynamic::owner) trait ExecObservation {
    fn prepared(
        &mut self,
        owner: &Owner,
        invocation: &ExecInvocation<'_>,
        until: Instant,
    ) -> Result<(), LaunchError>;
    fn raw(&mut self, owner: &Owner, tid: i32, status: i32) -> Result<(), LaunchError>;
    fn entry(&mut self, event: &DynamicEvent, state: &TaskStateSnapshot)
    -> Result<(), LaunchError>;
    fn replaced(
        &mut self,
        previous: DynamicTask,
        event: &DynamicEvent,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError>;
    fn exit(&mut self, event: &DynamicEvent, state: &TaskStateSnapshot) -> Result<(), LaunchError>;
    fn release_attempt(
        &mut self,
        phase: ExecRelease,
        stop: &DynamicStop,
    ) -> Result<(), LaunchError>;
    fn release_succeeded(
        &mut self,
        phase: ExecRelease,
        stop: &DynamicStop,
    ) -> Result<(), LaunchError>;
    fn failed(&mut self, error: &LaunchError);
}

/// Immutable identity/phase history. Only this module constructs it, following
/// actual native registry replacement and actual syscall EXIT. It is not Clone.
pub(in crate::linux::remote::dynamic::owner) struct ExecTransition {
    previous: DynamicTask,
    current: DynamicTask,
    entry: DynamicEvent,
    entry_state: TaskStateSnapshot,
    exec: DynamicEvent,
    exit: DynamicEvent,
    until: Instant,
}

impl ExecTransition {
    pub(in crate::linux::remote::dynamic::owner) fn previous(&self) -> DynamicTask {
        self.previous
    }
    pub(in crate::linux::remote::dynamic::owner) fn current(&self) -> DynamicTask {
        self.current
    }
    pub(in crate::linux::remote::dynamic::owner) fn entry(&self) -> &DynamicEvent {
        &self.entry
    }
    pub(in crate::linux::remote::dynamic::owner) fn entry_state(&self) -> &TaskStateSnapshot {
        &self.entry_state
    }
    pub(in crate::linux::remote::dynamic::owner) fn exec_event(&self) -> &DynamicEvent {
        &self.exec
    }
    pub(in crate::linux::remote::dynamic::owner) fn exit(&self) -> &DynamicEvent {
        &self.exit
    }
    pub(in crate::linux::remote::dynamic::owner) fn until(&self) -> Instant {
        self.until
    }
    pub(in crate::linux::remote::dynamic::owner) fn retained_bytes(
        &self,
    ) -> Result<usize, LaunchError> {
        std::mem::size_of::<Self>()
            .checked_add(self.entry_state.xstate.capacity())
            .and_then(|bytes| bytes.checked_add(event_payload(&self.exec)))
            .ok_or(LaunchError::Invalid("exec transition size overflows"))
    }
}

/// Consumable bootstrap permission for the actual new-mm exec EXIT. It cannot
/// be made from a syscall number, return value, source request or model snapshot.
pub(in crate::linux::remote::dynamic::owner) struct ExecExitReady {
    transition: ExecTransition,
    exec_state: TaskStateSnapshot,
    exit_state: TaskStateSnapshot,
}

impl ExecExitReady {
    pub(in crate::linux::remote::dynamic::owner) fn authenticate(
        &self,
        owner: &Owner,
        native: &lifecycle::NativeLifecycle,
        until: Instant,
    ) -> Result<(), LaunchError> {
        owner.time_left(until, "admitted exec EXIT authentication")?;
        let identity = self.transition.current;
        let event = &self.transition.exit;
        let token = event
            .stop_token()
            .ok_or(LaunchError::Invalid("exec EXIT lacks its token"))?;
        if until != self.transition.until
            || event.kind
                != (DynamicEventKind::SyscallExit {
                    result: 0,
                    is_error: false,
                })
            || event.task != Some(identity)
            || token.session != owner.session
            || token.tid != owner.pid
            || token.task != Some(identity.task)
            || native.admission_held_event(identity.task)? != *event
            || !native.admission_events_empty()
            || owner.owned.len() != 1
            || !owner.owned.contains(&owner.pid)
            || owner.pin_kinds.get(&owner.pid) != Some(&PinKind::Process)
            || owner.handles.get(&owner.pid).is_none_or(broker::hup)
            || owner.reaped.contains(&owner.pid)
            || owner.tracer_terminal.contains_key(&owner.pid)
        {
            return Err(LaunchError::Invalid(
                "exec EXIT identity or custody changed",
            ));
        }
        let status = owner
            .stopped
            .get(&owner.pid)
            .copied()
            .ok_or(LaunchError::Invalid("exec EXIT lost its actual held wait"))?;
        if !libc::WIFSTOPPED(status)
            || libc::WSTOPSIG(status) != (libc::SIGTRAP | 0x80)
            || status >> 16 != 0
        {
            return Err(LaunchError::Invalid("exec EXIT raw wait differs"));
        }
        let membership = native.check_admission_mm(owner, identity.task)?;
        if membership.address_space != identity.address_space
            || membership.process != identity.process
            || membership.generation != 0
            || identity.generation != 0
            || membership.tgid != owner.pid
            || membership.tids.len() != 1
            || !membership.tids.contains(&owner.pid)
            || membership.candidate.tasks.as_slice() != [identity.task]
            || TaskStateSnapshot::read(owner.pid)? != self.exit_state
        {
            return Err(LaunchError::Invalid("exec EXIT new-mm state differs"));
        }
        owner.time_left(until, "admitted exec EXIT authentication")?;
        Ok(())
    }

    pub(in crate::linux::remote::dynamic::owner) fn into_parts(
        self,
    ) -> (ExecTransition, TaskStateSnapshot, TaskStateSnapshot) {
        (self.transition, self.exec_state, self.exit_state)
    }
}

fn event_payload(event: &DynamicEvent) -> usize {
    match &event.kind {
        DynamicEventKind::ExecReplaced { evidence, .. } => evidence
            .interpreter
            .as_ref()
            .map_or(0, |path| path.capacity()),
        _ => 0,
    }
}

/// # Safety
/// The owner authenticated the exact restored original decode, all old-mm
/// continuations/input ranges and the closed singleton exec profile. Its
/// preattached archive and nonrefundable reservation cover this entire native
/// transaction and the replacement bootstrap/source acquisition. The old-mm
/// interlock cannot reopen on any result. No callback here is application code.
pub(in crate::linux::remote::dynamic::owner) unsafe fn execute_exec(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    old_island: &TrustedIsland,
    invocation: ExecInvocation<'_>,
    observation: &mut dyn ExecObservation,
    until: Instant,
) -> Result<ExecExitReady, LaunchError> {
    let result = execute_inner(owner, native, old_island, invocation, observation, until);
    if let Err(error) = &result {
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
        observation.failed(error);
    }
    result
}

fn execute_inner(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    old_island: &TrustedIsland,
    invocation: ExecInvocation<'_>,
    observation: &mut dyn ExecObservation,
    until: Instant,
) -> Result<ExecExitReady, LaunchError> {
    owner.time_left(until, "admitted exec invocation")?;
    native.require_admission_exec_profile(owner, invocation.stop)?;
    let before = invocation.before;
    let input = invocation.input;
    let instruction = input.instruction();
    let previous = invocation.stop.identity;
    let tid = invocation.stop.token.tid;
    if previous.address_space != old_island.address_space
        || previous.generation != old_island.generation
        || input.registers() != &before.registers
        || before.registers.rip != instruction.logical_pc()
        || before.registers.cs != 0x33
        || before.registers.eflags & 0x100 != 0
        || !(512..MAX_XSTATE).contains(&before.xstate.len())
        || before.registers.rax != libc::SYS_execve as u64
        || !matches!(
            instruction.operation(),
            Operation::Syscall {
                abi: SyscallAbi::LinuxX64
            }
        )
    {
        return Err(LaunchError::Invalid("admitted exec original input differs"));
    }
    let decoded = crate::selected::decode(
        instruction.logical_pc(),
        instruction.bytes(),
        &SyscallAliases::new(),
    )
    .map_err(|_| LaunchError::Invalid("admitted exec original decode differs"))?;
    if decoded != *instruction || decoded.bytes().len() != instruction.bytes().len() {
        return Err(LaunchError::Invalid(
            "admitted exec decode is not exact and complete",
        ));
    }
    if TaskStateSnapshot::read(tid)? != *before {
        return Err(LaunchError::Invalid(
            "admitted exec complete input state differs",
        ));
    }
    old_island.verify(tid)?;
    verify_original(tid, instruction.logical_pc(), instruction.bytes())?;
    observation.prepared(owner, &invocation, until)?;
    observation.release_attempt(ExecRelease::Original, &invocation.stop.token)?;
    owner.time_left(until, "admitted exec original release")?;
    // SAFETY: exact full state/source/profile/whole-mm checks above and the
    // caller's closed original-execution permit apply to this single release.
    unsafe {
        native.begin_admission_original(owner, invocation.stop, libc::PTRACE_SYSCALL)?;
    }
    observation.release_succeeded(ExecRelease::Original, &invocation.stop.token)?;

    let entry = next_event(owner, native, observation, RawPhase::Entry, until)?;
    let entry_token = entry
        .stop_token()
        .ok_or(LaunchError::Invalid("exec ENTRY lacks token"))?;
    let next = instruction.next_pc();
    let entry_state = TaskStateSnapshot::read(tid)?;
    let mut expected = before.registers;
    expected.rip = next;
    expected.orig_rax = libc::SYS_execve as u64;
    expected.rax = (-i64::from(libc::ENOSYS)) as u64;
    expected.rcx = next;
    expected.r11 = before.registers.eflags & !0x10000;
    expected.eflags &= !0x10000;
    if entry.tid != tid
        || entry.task != Some(previous)
        || !original_entry_follows(&invocation.stop.token, entry_token)
        || entry.kind
            != (DynamicEventKind::SyscallEntry {
                number: libc::SYS_execve as u64,
                arguments: arguments(&before.registers),
            })
        || entry_state.registers != expected
        || entry_state.xstate != before.xstate
        || entry_state.mask != before.mask
    {
        return Err(LaunchError::Invalid(
            "admitted exec ENTRY full state differs",
        ));
    }
    observation.entry(&entry, &entry_state)?;
    #[cfg(test)]
    owner.exec_oracle_entry(&entry, until)?;
    resume(
        owner,
        native,
        observation,
        ExecRelease::Entry,
        &entry,
        until,
    )?;

    // From here onward an EXEC may have destroyed every old numeric address.
    // Never reverify the old instruction, island or old before-state again.
    let exec = next_event(owner, native, observation, RawPhase::Exec, until)?;
    let current = exec
        .task
        .ok_or(LaunchError::Invalid("admitted EXEC lacks identity"))?;
    let exec_state = TaskStateSnapshot::read(tid)?;
    let exec_token = exec
        .stop_token()
        .ok_or(LaunchError::Invalid("EXEC lacks token"))?;
    if exec.tid != tid
        || !matches!(&exec.kind, DynamicEventKind::ExecReplaced { previous: old, .. } if *old == previous)
        || current.task == previous.task
        || current.address_space == previous.address_space
        || current.process != previous.process
        || current.generation != 0
        || exec_token.session != entry_token.session
        || exec_token.task != Some(current.task)
        || !replacement_exec_birth(entry_token, exec_token)
        || exec_state.registers.cs != 0x33
        || exec_state.registers.orig_rax != libc::SYS_execve as u64
        || exec_state.registers.rax != (-i64::from(libc::ENOSYS)) as u64
        || exec_state.registers.eflags != 0x202
        || exec_state.mask != before.mask
        || native.admission_held_event(current.task)? != exec
    {
        return Err(LaunchError::Invalid("admitted EXEC replacement differs"));
    }
    observation.replaced(previous, &exec, &exec_state)?;
    resume(
        owner,
        native,
        observation,
        ExecRelease::ExecEvent,
        &exec,
        until,
    )?;

    let exit = next_event(owner, native, observation, RawPhase::Exit, until)?;
    let exit_state = TaskStateSnapshot::read(tid)?;
    let exit_token = exit
        .stop_token()
        .ok_or(LaunchError::Invalid("exec EXIT lacks token"))?;
    let mut expected_exit = exec_state.registers;
    expected_exit.rax = 0;
    if exit.tid != tid
        || exit.task != Some(current)
        || exit.kind
            != (DynamicEventKind::SyscallExit {
                result: 0,
                is_error: false,
            })
        || exit_token.session != exec_token.session
        || exit_token.task != Some(current.task)
        || exit_token.sequence <= exec_token.sequence
        || exit_state.registers != expected_exit
        || exit_state.xstate != exec_state.xstate
        || exit_state.mask != exec_state.mask
        || !native.admission_events_empty()
    {
        return Err(LaunchError::Invalid(
            "admitted exec EXIT full state differs",
        ));
    }
    observation.exit(&exit, &exit_state)?;
    let ready = ExecExitReady {
        transition: ExecTransition {
            previous,
            current,
            entry,
            entry_state,
            exec,
            exit,
            until,
        },
        exec_state,
        exit_state,
    };
    ready.authenticate(owner, native, until)?;
    Ok(ready)
}

enum RawPhase {
    Entry,
    Exec,
    Exit,
}

fn next_event(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    observation: &mut dyn ExecObservation,
    phase: RawPhase,
    until: Instant,
) -> Result<DynamicEvent, LaunchError> {
    if !native.admission_events_empty() {
        return Err(LaunchError::Invalid(
            "admitted exec has a queued unrelated event",
        ));
    }
    let (tid, status) = owner.wait_raw(until, "admitted original exec lifecycle")?;
    observation.raw(owner, tid, status)?;
    owner.time_left(until, "admitted original exec raw observation")?;
    let syscall = libc::WIFSTOPPED(status)
        && libc::WSTOPSIG(status) == (libc::SIGTRAP | 0x80)
        && status >> 16 == 0;
    let exec = libc::WIFSTOPPED(status)
        && libc::WSTOPSIG(status) == libc::SIGTRAP
        && status >> 16 == libc::PTRACE_EVENT_EXEC;
    if tid != owner.pid
        || match phase {
            RawPhase::Entry | RawPhase::Exit => !syscall,
            // Let the existing native dispatcher retain its exact no-EXEC errno
            // refusal when an actual syscall EXIT arrives instead of EXEC.
            RawPhase::Exec => !(exec || syscall),
        }
    {
        return Err(LaunchError::Invalid(
            "admitted exec reached an unexpected raw phase",
        ));
    }
    native
        .observe_admission_other(owner, tid, status)?
        .ok_or(LaunchError::Invalid(
            "admitted exec did not produce its real held event",
        ))
}

fn resume(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    observation: &mut dyn ExecObservation,
    phase: ExecRelease,
    event: &DynamicEvent,
    until: Instant,
) -> Result<(), LaunchError> {
    let token = event
        .stop_token()
        .ok_or(LaunchError::Invalid("admitted exec release lacks token"))?;
    observation.release_attempt(phase, token)?;
    owner.time_left(until, "admitted exec held event release")?;
    // SAFETY: only the exact original ENTRY and its real EXEC event reach this
    // function. NativeLifecycle repeats its existing phase and exec checks.
    unsafe {
        native.resume_admission_event(owner, token, DynamicResume::Continue)?;
    }
    observation.release_succeeded(phase, token)
}

#[cfg(test)]
mod tests;
