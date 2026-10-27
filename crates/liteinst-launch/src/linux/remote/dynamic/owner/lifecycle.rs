//! Opt-in bounded native fork/thread/exec ownership. This module authenticates kernel events; the
//! pure registry only retains their identities and obligations. The ordinary
//! lifecycle dispatcher changes no code bytes or executable permissions. Its
//! private admission child adds distinct owner-authenticated phase transitions;
//! real publication remains in the separate whole-mm native guard.
use super::*;

pub(crate) mod admission;
mod exec;
mod thread;
use exec::ExecPending;

#[cfg(test)]
mod tests;
use crate::lifecycle::{
    CreationEvent, CreationEventKind, CreationRequest, CreationTicket, ExitStatus, HoldReason,
    LifecycleRegistry, Limits, ObligationId, SignalEvent, SignalScope, TaskId,
};
use std::collections::VecDeque;
use std::os::unix::fs::MetadataExt;

struct Task {
    identity: DynamicTask,
    state: State,
    interrupt_stops_remaining: u8,
    syscall_open: bool,
    fork_return: Option<ForkReturn>,
    signal_obligation: Option<ObligationId>,
}

struct ForkReturn {
    ticket: CreationTicket,
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
    mask: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreationKind {
    Fork,
    Thread { stack: u64 },
}

struct ForkPending {
    kind: CreationKind,
    parent: TaskId,
    ticket: CreationTicket,
    entry: RegisterSnapshot,
    xstate: Vec<u8>,
    mask: u64,
    child: Option<libc::pid_t>,
    parent_event: bool,
    newborn: Option<(libc::pid_t, RegisterSnapshot)>,
}

pub(in crate::linux::remote::dynamic) struct NativeLifecycle {
    session: u64,
    options: DynamicLifecycleOptions,
    exec_policy: DynamicExecPolicy,
    exec_successes: usize,
    exec_pending: Option<ExecPending>,
    registry: LifecycleRegistry,
    tasks: BTreeMap<libc::pid_t, Task>,
    pending: Option<ForkPending>,
    events: VecDeque<DynamicEvent>,
}

fn recorded<T>(value: Result<T, crate::lifecycle::LifecycleError>) -> Result<T, LaunchError> {
    value.map_err(|_| LaunchError::Invalid("native lifecycle registry transition refused"))
}

impl NativeLifecycle {
    pub(super) fn new(
        session: u64,
        pid: libc::pid_t,
        registers: RegisterSnapshot,
        options: DynamicLifecycleOptions,
        exec_policy: DynamicExecPolicy,
    ) -> Result<(Self, DynamicEvent), LaunchError> {
        // At most max_tasks native TID records are ever inserted, including
        // terminals. Fork/Refuse retain their separate physical-process budget;
        // ThreadClone has one process/mm regardless of its two native tasks.
        // Exec replaces one slot at most once and reserves one extra retained
        // task/mm record; it never consumes a process record. Pending
        // lifecycle transactions are serialized and no retirement refunds either
        // budget, so this bound covers either fork/exec order before release.
        let incarnation_limit = options
            .max_tasks
            .checked_add(usize::from(exec_policy == DynamicExecPolicy::ExecveOnce))
            .ok_or(LaunchError::Invalid("native incarnation budget overflow"))?;
        let registry = recorded(LifecycleRegistry::new_after_exec_syscall_exit(
            Limits {
                tasks: incarnation_limit,
                processes: if options.creation == DynamicCreationPolicy::ThreadClone {
                    1
                } else {
                    options.max_tasks
                },
                address_spaces: if options.creation == DynamicCreationPolicy::ThreadClone {
                    1 + usize::from(exec_policy == DynamicExecPolicy::ExecveOnce)
                } else {
                    incarnation_limit
                },
                obligations: 4096,
            },
            pid,
            registers.rip,
        ))?;
        let id = registry.root_task();
        let record = recorded(registry.task(id))?;
        let identity = DynamicTask {
            task: id,
            process: record.process,
            address_space: record.address_space,
            generation: recorded(registry.address_space(record.address_space))?.generation,
        };
        let event = DynamicEvent {
            tid: pid,
            task: Some(identity),
            kind: DynamicEventKind::SyscallExit {
                result: 0,
                is_error: false,
            },
            stop: Some(DynamicStop {
                session,
                sequence: 0,
                tid: pid,
                task: Some(id),
            }),
        };
        let tasks = BTreeMap::from([(
            pid,
            Task {
                identity,
                state: State::Held(Box::new(event.clone())),
                interrupt_stops_remaining: 0,
                syscall_open: false,
                fork_return: None,
                signal_obligation: None,
            },
        )]);
        Ok((
            Self {
                session,
                options,
                exec_policy,
                exec_successes: 0,
                exec_pending: None,
                registry,
                tasks,
                pending: None,
                events: VecDeque::new(),
            },
            event,
        ))
    }

    pub(super) fn execute(
        &mut self,
        owner: &mut Owner,
        request: Request,
        until: Instant,
    ) -> Result<Response, LaunchError> {
        match request {
            Request::Admission(_) => Err(LaunchError::Invalid(
                "admission request escaped its dedicated owner dispatcher",
            )),
            #[cfg(test)]
            Request::PanicForCleanupTest => panic!("injected dynamic tracer unwind"),
            Request::LifecycleSnapshot => {
                Ok(Response::LifecycleSnapshot(Some(self.registry.snapshot())))
            }
            Request::Resume(token, action) => {
                self.resume(owner, &token, action).map(|()| Response::Unit)
            }
            Request::Wait => {
                if self.events.is_empty()
                    && !self.tasks.values().any(|task| {
                        matches!(
                            task.state,
                            State::Running | State::Listening | State::Exiting
                        )
                    })
                {
                    return Err(LaunchError::Invalid(
                        "dynamic wait requires a released task",
                    ));
                }
                self.wait(owner, until).map(Response::Event)
            }
            Request::Interrupt => {
                let task = self
                    .tasks
                    .get(&owner.pid)
                    .ok_or(LaunchError::Invalid("original native process is unknown"))?
                    .identity
                    .task;
                self.interrupt(owner, task, until).map(Response::Event)
            }
            Request::InterruptTask(task) => self.interrupt(owner, task, until).map(Response::Event),
            Request::Registers(token) => {
                self.require_stop(&token)?;
                read_registers(token.tid).map(Response::Registers)
            }
            Request::Xstate(token) => {
                self.require_stop(&token)?;
                xstate(token.tid).map(Response::Bytes)
            }
            Request::Memory(token, address, len) => {
                self.require_stop(&token)?;
                read_memory(token.tid, address, len).map(Response::Bytes)
            }
            Request::Mask(token) => {
                self.require_stop(&token)?;
                launch::task_mask(token.tid).map(Response::Mask)
            }
        }
    }

    fn require_stop(&self, token: &DynamicStop) -> Result<&DynamicEvent, LaunchError> {
        match self.tasks.get(&token.tid).map(|task| &task.state) {
            Some(State::Held(event)) if event.stop.as_ref() == Some(token) => Ok(event),
            _ => Err(LaunchError::Invalid("dynamic stop token is not current")),
        }
    }

    fn sequence(&self, tid: libc::pid_t) -> Result<u64, LaunchError> {
        let task = self
            .tasks
            .get(&tid)
            .ok_or(LaunchError::Invalid("unknown native task"))?;
        recorded(self.registry.task(task.identity.task))?
            .sequence
            .checked_add(1)
            .ok_or(LaunchError::Invalid("native task stop identity exhausted"))
    }

    fn held(
        &mut self,
        tid: libc::pid_t,
        kind: DynamicEventKind,
    ) -> Result<DynamicEvent, LaunchError> {
        let task = self
            .tasks
            .get_mut(&tid)
            .ok_or(LaunchError::Invalid("unknown held native task"))?;
        let sequence = recorded(self.registry.task(task.identity.task))?.sequence;
        let event = DynamicEvent {
            tid,
            task: Some(task.identity),
            kind,
            stop: Some(DynamicStop {
                session: self.session,
                sequence,
                tid,
                task: Some(task.identity.task),
            }),
        };
        task.state = State::Held(Box::new(event.clone()));
        Ok(event)
    }

    fn resume(
        &mut self,
        owner: &mut Owner,
        token: &DynamicStop,
        action: DynamicResume,
    ) -> Result<(), LaunchError> {
        let event = self.require_stop(token)?.clone();
        let (request, signal) = match (&event.kind, action) {
            (DynamicEventKind::SignalDelivery(info), DynamicResume::DeliverOriginal) => {
                (libc::PTRACE_SYSCALL, info.signal())
            }
            (DynamicEventKind::GroupStop { .. }, DynamicResume::Listen) => (libc::PTRACE_LISTEN, 0),
            (
                DynamicEventKind::SyscallEntry { .. }
                | DynamicEventKind::SyscallExit { .. }
                | DynamicEventKind::Interrupted
                | DynamicEventKind::GroupContinued
                | DynamicEventKind::Created { .. }
                | DynamicEventKind::Newborn { .. }
                | DynamicEventKind::ExecReplaced { .. },
                DynamicResume::Continue,
            ) => (libc::PTRACE_SYSCALL, 0),
            _ => {
                return Err(LaunchError::Invalid(
                    "dynamic stop requires its exact signal or control disposition",
                ));
            }
        };
        // From this point, any uncertainty closes the session. Invalid tokens or
        // dispositions above have not changed state and can be corrected.
        let result = (|| {
            let identity = self.tasks[&token.tid].identity;
            if let DynamicEventKind::SyscallEntry { number, .. } = event.kind {
                if number == libc::SYS_fork as u64 {
                    if self.options.creation != DynamicCreationPolicy::Fork {
                        return Err(LaunchError::Invalid("dynamic fork policy refuses creation"));
                    }
                    if self.tasks.len() >= self.options.max_tasks
                        || self.pending.is_some()
                        || self.exec_pending.is_some()
                    {
                        return Err(LaunchError::Invalid(
                            "dynamic lifetime task bound exhausted",
                        ));
                    }
                    same_pid_namespace(token.tid)?;
                    let entry = read_registers(token.tid)?;
                    let info = syscall_info(token.tid)?;
                    if info.op != libc::PTRACE_SYSCALL_INFO_ENTRY
                        || info.arch != AUDIT_ARCH_X86_64
                        || entry.cs != 0x33
                        || entry.orig_rax != number
                        || entry.eflags & 0x100 != 0
                        || info.instruction_pointer != entry.rip
                        || info.stack_pointer != entry.rsp
                    {
                        return Err(LaunchError::Invalid("fork entry did not authenticate"));
                    }
                    // SAFETY: op ENTRY authenticated the initialized member.
                    let saved = unsafe { info.u.entry };
                    if saved.nr != number || saved.args != arguments(&entry) {
                        return Err(LaunchError::Invalid("fork entry arguments differ"));
                    }
                    let extended = xstate(token.tid)?;
                    let mask = launch::task_mask(token.tid)?;
                    let ticket = recorded(
                        self.registry
                            .prepare_creation(identity.task, CreationRequest::Fork),
                    )?;
                    self.pending = Some(ForkPending {
                        kind: CreationKind::Fork,
                        parent: identity.task,
                        ticket,
                        entry,
                        xstate: extended,
                        mask,
                        child: None,
                        parent_event: false,
                        newborn: None,
                    });
                } else if number == libc::SYS_clone as u64
                    && self.options.creation == DynamicCreationPolicy::ThreadClone
                {
                    self.prepare_native_thread(owner, token.tid)?;
                } else if number == libc::SYS_execve as u64
                    && self.exec_policy == DynamicExecPolicy::ExecveOnce
                {
                    self.prepare_native_exec(owner, token.tid)?;
                } else if matches!(
                    number as libc::c_long,
                    libc::SYS_clone
                        | libc::SYS_clone3
                        | libc::SYS_vfork
                        | libc::SYS_execve
                        | libc::SYS_execveat
                ) {
                    return Err(LaunchError::Invalid(
                        "dynamic creation and later exec are not yet qualified",
                    ));
                }
            }
            recorded(self.registry.resume(identity.task, token.sequence))?;
            ptrace(request, token.tid, 0, signal as usize)?;
            owner.released(token.tid);
            self.tasks.get_mut(&token.tid).unwrap().state = if request == libc::PTRACE_LISTEN {
                State::Listening
            } else {
                State::Running
            };
            Ok(())
        })();
        if result.is_err() {
            owner.closing = true;
        }
        result
    }

    fn interrupt(
        &mut self,
        owner: &mut Owner,
        id: TaskId,
        until: Instant,
    ) -> Result<DynamicEvent, LaunchError> {
        let record = recorded(self.registry.task(id))?;
        let tid = record.tid;
        if !self
            .tasks
            .get(&tid)
            .is_some_and(|task| task.identity.task == id && matches!(task.state, State::Running))
        {
            return Err(LaunchError::Invalid(
                "dynamic interruption requires running execution",
            ));
        }
        if let Err(error) = ptrace(libc::PTRACE_INTERRUPT, tid, 0, 0) {
            owner.closing = true;
            return Err(error);
        }
        self.tasks.get_mut(&tid).unwrap().interrupt_stops_remaining = 2;
        // A sibling's stop does not authenticate interruption of this target.
        // Retain other events without resuming them while awaiting this task.
        let result = (|| loop {
            let (observed, status) = owner.wait_raw(until, "targeted lifecycle interruption")?;
            if let Some(event) = self.observe(owner, observed, status)? {
                if event.task.is_some_and(|task| task.task == id)
                    || matches!(&event.kind, DynamicEventKind::ExecReplaced { previous, .. } if previous.task == id)
                {
                    return Ok(event);
                }
                self.events.push_back(event);
            }
        })();
        if result.is_err() {
            owner.closing = true;
        }
        result
    }

    fn wait(&mut self, owner: &mut Owner, until: Instant) -> Result<DynamicEvent, LaunchError> {
        if let Some(event) = self.events.pop_front() {
            return Ok(event);
        }
        let result = (|| loop {
            let (tid, status) = owner.wait_raw(until, "native lifecycle event")?;
            if let Some(event) = self.observe(owner, tid, status)? {
                return Ok(event);
            }
        })();
        if result.is_err() {
            owner.closing = true;
        }
        result
    }

    fn observe(
        &mut self,
        owner: &mut Owner,
        tid: libc::pid_t,
        status: i32,
    ) -> Result<Option<DynamicEvent>, LaunchError> {
        if !self.tasks.contains_key(&tid) {
            return self.newborn(owner, tid, status);
        }
        let id = self.tasks[&tid].identity.task;
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            let status = if libc::WIFEXITED(status) {
                ExitStatus::Code(libc::WEXITSTATUS(status) as u8)
            } else {
                ExitStatus::Signal(libc::WTERMSIG(status) as u8)
            };
            recorded(self.registry.observe_exit(id, self.sequence(tid)?, status))?;
            let task = self.tasks.get_mut(&tid).unwrap();
            task.state = State::Terminal;
            return Ok(Some(DynamicEvent {
                tid,
                task: Some(task.identity),
                kind: DynamicEventKind::TaskTerminal { status },
                stop: None,
            }));
        }
        if !libc::WIFSTOPPED(status) {
            return Err(LaunchError::Invalid("invalid lifecycle wait status"));
        }
        let task = self.tasks.get_mut(&tid).unwrap();
        let possible_interrupt = task.interrupt_stops_remaining != 0;
        task.interrupt_stops_remaining = task.interrupt_stops_remaining.saturating_sub(1);
        let listening = matches!(task.state, State::Listening);
        let signal = libc::WSTOPSIG(status);
        let event = status >> 16;
        if event == libc::PTRACE_EVENT_EXIT {
            if self.options.creation == DynamicCreationPolicy::ThreadClone {
                return self.observe_thread_exiting(owner, tid, signal).map(Some);
            }
            // Preserve the established Fork/Refuse notification contract.
            // No original instruction can execute from this kernel pre-exit stop.
            ptrace(libc::PTRACE_CONT, tid, 0, 0)?;
            owner.released(tid);
            return Ok(None);
        }
        if event == libc::PTRACE_EVENT_EXEC {
            if signal != libc::SIGTRAP {
                return Err(LaunchError::Invalid("exec event has wrong stop signal"));
            }
            return self.observe_native_exec(owner, tid).map(Some);
        }
        if event == libc::PTRACE_EVENT_FORK
            || (event == libc::PTRACE_EVENT_CLONE
                && self.options.creation == DynamicCreationPolicy::ThreadClone)
        {
            if signal != libc::SIGTRAP {
                return Err(LaunchError::Invalid("fork event has wrong stop signal"));
            }
            let expected = self.pending.as_ref().map(|pending| match pending.kind {
                CreationKind::Fork => libc::PTRACE_EVENT_FORK,
                CreationKind::Thread { .. } => libc::PTRACE_EVENT_CLONE,
            });
            if expected != Some(event) {
                owner.discover_event_child(tid, status);
                return Err(LaunchError::Invalid(
                    "creation event differs from entry intent",
                ));
            }
            return self.parent_created(owner, tid);
        }
        if event != 0 && event != libc::PTRACE_EVENT_STOP {
            owner.discover_event_child(tid, status);
            return Err(LaunchError::Invalid("unqualified native lifecycle event"));
        }
        if event == libc::PTRACE_EVENT_STOP {
            let (kind, reason) = if matches!(
                signal,
                libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
            ) {
                (
                    DynamicEventKind::GroupStop { signal },
                    HoldReason::GroupStop,
                )
            } else if signal == libc::SIGTRAP && listening {
                (DynamicEventKind::GroupContinued, HoldReason::GroupContinued)
            } else if signal == libc::SIGTRAP && possible_interrupt {
                (DynamicEventKind::Interrupted, HoldReason::Interrupt)
            } else {
                return Err(LaunchError::Invalid("unowned lifecycle control stop"));
            };
            let pc = read_registers(tid)?.rip;
            recorded(
                self.registry
                    .observe_stop(id, self.sequence(tid)?, pc, reason),
            )?;
            return self.held(tid, kind).map(Some);
        }
        if signal == (libc::SIGTRAP | 0x80) {
            return self.syscall(tid).map(Some);
        }
        let mut raw = [0_u8; 128];
        if let Some(journal) = &owner.signal_journal {
            // Both independent raw observations are retained before a shared
            // failure gate or any signal/registry authentication can reject.
            let (captured, _) = journal.capture_signal_state(tid, status)?;
            raw = captured;
        } else {
            ptrace(libc::PTRACE_GETSIGINFO, tid, 0, raw.as_mut_ptr() as usize)?;
        }
        let info = DynamicSignalInfo { raw };
        if info.signal() != signal {
            return Err(LaunchError::Invalid(
                "lifecycle siginfo disagrees with wait status",
            ));
        }
        let registers = read_registers(tid)?;
        // siginfo does not authenticate pending-queue provenance. Preserve an
        // explicitly Unknown obligation, even for familiar SI_* codes.
        let obligation = recorded(self.registry.observe_signal(
            id,
            self.sequence(tid)?,
            SignalEvent {
                pc: registers.rip,
                signal: signal as u8,
                code: info.code(),
                scope: SignalScope::Unknown,
            },
        ))?;
        self.tasks.get_mut(&tid).unwrap().signal_obligation = Some(obligation);
        self.held(tid, DynamicEventKind::SignalDelivery(info))
            .map(Some)
    }

    fn syscall(&mut self, tid: libc::pid_t) -> Result<DynamicEvent, LaunchError> {
        let info = syscall_info(tid)?;
        let registers = read_registers(tid)?;
        let id = self.tasks[&tid].identity.task;
        let sequence = self.sequence(tid)?;
        if info.arch != AUDIT_ARCH_X86_64
            || registers.cs != 0x33
            || info.instruction_pointer != registers.rip
            || info.stack_pointer != registers.rsp
        {
            return Err(LaunchError::Invalid(
                "dynamic syscall ABI/state did not authenticate",
            ));
        }
        match info.op {
            libc::PTRACE_SYSCALL_INFO_ENTRY => {
                // SAFETY: ENTRY authenticates this initialized union member.
                let entry = unsafe { info.u.entry };
                if self.tasks[&tid].syscall_open
                    || entry.nr > i32::MAX as u64
                    || entry.nr & 0x4000_0000 != 0
                    || entry.nr != registers.orig_rax
                    || entry.args != arguments(&registers)
                {
                    return Err(LaunchError::Invalid(
                        "dynamic syscall entry is out of order or non-native",
                    ));
                }
                recorded(self.registry.observe_stop(
                    id,
                    sequence,
                    registers.rip,
                    HoldReason::SyscallEntry,
                ))?;
                self.tasks.get_mut(&tid).unwrap().syscall_open = true;
                self.held(
                    tid,
                    DynamicEventKind::SyscallEntry {
                        number: entry.nr,
                        arguments: entry.args,
                    },
                )
            }
            libc::PTRACE_SYSCALL_INFO_EXIT => {
                // SAFETY: EXIT authenticates this initialized union member.
                let exit = unsafe { info.u.exit };
                if !self.tasks[&tid].syscall_open
                    || registers.rax as i64 != exit.sval
                    || (exit.is_error != 0) != (-4095..=-1).contains(&exit.sval)
                {
                    return Err(LaunchError::Invalid(
                        "dynamic syscall exit is out of order or changed",
                    ));
                }
                if self
                    .exec_pending
                    .as_ref()
                    .is_some_and(|pending| pending.task == id)
                {
                    self.complete_native_exec(
                        tid,
                        sequence,
                        &registers,
                        exit.sval,
                        exit.is_error != 0,
                    )?;
                } else if let Some(returned) = self.tasks.get_mut(&tid).unwrap().fork_return.take()
                {
                    if registers != returned.registers
                        || xstate(tid)? != returned.xstate
                        || returned
                            .mask
                            .is_some_and(|mask| launch::task_mask(tid).ok() != Some(mask))
                        || exit.is_error != 0
                    {
                        return Err(LaunchError::Invalid("native fork return state differs"));
                    }
                    recorded(self.registry.observe_creation_exit(
                        returned.ticket,
                        sequence,
                        registers.rip,
                        exit.sval,
                    ))?;
                } else if self
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.parent == id)
                {
                    let pending = self.pending.take().unwrap();
                    if pending.parent_event
                        || pending.child.is_some()
                        || pending.newborn.is_some()
                        || exit.is_error == 0
                        || !(-4095..=-1).contains(&exit.sval)
                    {
                        return Err(LaunchError::Invalid(
                            "fork failure has inconsistent child evidence",
                        ));
                    }
                    let mut expected = pending.entry;
                    expected.rax = exit.sval as u64;
                    if registers != expected
                        || xstate(tid)? != pending.xstate
                        || (matches!(pending.kind, CreationKind::Thread { .. })
                            && launch::task_mask(tid)? != pending.mask)
                    {
                        return Err(LaunchError::Invalid("failed fork changed unrelated state"));
                    }
                    recorded(self.registry.observe_creation_exit(
                        pending.ticket,
                        sequence,
                        registers.rip,
                        exit.sval,
                    ))?;
                } else {
                    recorded(self.registry.observe_stop(
                        id,
                        sequence,
                        registers.rip,
                        HoldReason::SyscallExit,
                    ))?;
                }
                self.tasks.get_mut(&tid).unwrap().syscall_open = false;
                self.held(
                    tid,
                    DynamicEventKind::SyscallExit {
                        result: exit.sval,
                        is_error: exit.is_error != 0,
                    },
                )
            }
            _ => Err(LaunchError::Invalid("unsupported dynamic syscall stop")),
        }
    }

    fn parent_created(
        &mut self,
        owner: &mut Owner,
        tid: libc::pid_t,
    ) -> Result<Option<DynamicEvent>, LaunchError> {
        let id = self.tasks[&tid].identity.task;
        let pending = self
            .pending
            .as_mut()
            .ok_or(LaunchError::Invalid("fork event lacks an entry intent"))?;
        if pending.parent != id || pending.parent_event {
            return Err(LaunchError::Invalid(
                "duplicate or foreign fork parent event",
            ));
        }
        let mut child = 0_u64;
        ptrace(libc::PTRACE_GETEVENTMSG, tid, 0, (&raw mut child) as usize)?;
        let child = i32::try_from(child)
            .map_err(|_| LaunchError::Invalid("fork child identity overflow"))?;
        if child <= 0 || self.tasks.contains_key(&child) {
            return Err(LaunchError::Invalid("fork child identity collision"));
        }
        if owner.reaped.contains(&child) || owner.tracer_terminal.contains_key(&child) {
            return Err(LaunchError::Invalid(
                "fork payload names a retired incarnation",
            ));
        }
        // The ptrace event and automatic child stop pin this newborn until its
        // tracer consumes the terminal. Establish ownership before fallible reads.
        owner.owned.insert(child);
        owner.pin_task(child)?;
        if read_registers(tid)? != pending.entry || xstate(tid)? != pending.xstate {
            return Err(LaunchError::Invalid(
                "fork parent event changed entry state",
            ));
        }
        if matches!(pending.kind, CreationKind::Thread { .. }) {
            thread::shadow_stack_disabled(tid)?;
            if launch::task_mask(tid)? != pending.mask {
                return Err(LaunchError::Invalid(
                    "thread parent event changed signal mask",
                ));
            }
        }
        pending.parent_event = true;
        pending.child = Some(child);
        self.join_created()
    }

    fn newborn(
        &mut self,
        owner: &mut Owner,
        tid: libc::pid_t,
        status: i32,
    ) -> Result<Option<DynamicEvent>, LaunchError> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(LaunchError::Invalid("unknown child lacks a fork intent"))?;
        if pending.newborn.is_some()
            || !libc::WIFSTOPPED(status)
            || libc::WSTOPSIG(status) != libc::SIGTRAP
            || status >> 16 != libc::PTRACE_EVENT_STOP
        {
            return Err(LaunchError::Invalid(
                "fork newborn automatic stop did not authenticate",
            ));
        }
        let registers = read_registers(tid)?;
        let mut expected = pending.entry;
        expected.rax = 0;
        if let CreationKind::Thread { stack } = pending.kind {
            expected.rsp = stack;
            thread::shadow_stack_disabled(tid)?;
            if owner.pin_kinds.get(&tid) != Some(&PinKind::Thread) {
                return Err(LaunchError::Invalid("thread newborn lacks a task pidfd"));
            }
        }
        if registers != expected
            || xstate(tid)? != pending.xstate
            || launch::task_mask(tid)? != pending.mask
        {
            return Err(LaunchError::Invalid("fork newborn initial state differs"));
        }
        let status = std::fs::read_to_string(format!("/proc/{tid}/status"))
            .map_err(|error| io_error("read fork newborn thread group", error))?;
        let tgid = status
            .lines()
            .find_map(|line| line.strip_prefix("Tgid:\t"))
            .and_then(|value| value.parse::<i32>().ok());
        match pending.kind {
            CreationKind::Fork => {
                if tgid != Some(tid) {
                    return Err(LaunchError::Invalid("fork newborn is not a process leader"));
                }
                owner.pin_process(tid)?;
            }
            CreationKind::Thread { .. } => {
                let parent_tid = recorded(self.registry.task(pending.parent))?.tid;
                if tgid != Some(parent_tid) || tid == parent_tid {
                    return Err(LaunchError::Invalid(
                        "thread newborn has a different process",
                    ));
                }
            }
        }
        pending.newborn = Some((tid, registers));
        self.join_created()
    }

    fn join_created(&mut self) -> Result<Option<DynamicEvent>, LaunchError> {
        let ready = self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.parent_event && pending.newborn.is_some());
        if !ready {
            return Ok(None);
        }
        let pending = self.pending.take().unwrap();
        let (tid, child_registers) = pending.newborn.unwrap();
        if pending.child != Some(tid) {
            return Err(LaunchError::Invalid(
                "fork event and newborn identities differ",
            ));
        }
        let parent_tid = recorded(self.registry.task(pending.parent))?.tid;
        let parent_identity = self.tasks[&parent_tid].identity;
        let child = recorded(self.registry.observe_creation(
            pending.ticket,
            self.sequence(parent_tid)?,
            CreationEvent {
                kind: match pending.kind {
                    CreationKind::Fork => CreationEventKind::Fork,
                    CreationKind::Thread { .. } => CreationEventKind::Clone,
                },
                child_tid: tid,
                child_tgid: match pending.kind {
                    CreationKind::Fork => tid,
                    CreationKind::Thread { .. } => parent_tid,
                },
                parent_visible_tid: tid,
                parent_pc: pending.entry.rip,
            },
        ))?;
        recorded(
            self.registry
                .observe_newborn_return_ready(child, 1, child_registers.rip),
        )?;
        let record = recorded(self.registry.task(child))?;
        let child_identity = DynamicTask {
            task: child,
            process: record.process,
            address_space: record.address_space,
            generation: recorded(self.registry.address_space(record.address_space))?.generation,
        };
        self.tasks.insert(
            tid,
            Task {
                identity: child_identity,
                state: State::Startup,
                interrupt_stops_remaining: 0,
                // copy_process cleared SYSCALL_TRACE. The automatic stop is in
                // the later return-to-user signal/job-control loop, after this
                // child's one-time syscall-exit tracing decision. PTRACE_SYSCALL
                // here can observe its next entry, not a fork-exit event.
                syscall_open: false,
                fork_return: None,
                signal_obligation: None,
            },
        );
        let mut parent_return = pending.entry;
        parent_return.rax = tid as u64;
        self.tasks.get_mut(&parent_tid).unwrap().fork_return = Some(ForkReturn {
            ticket: pending.ticket,
            registers: parent_return,
            xstate: pending.xstate,
            mask: match pending.kind {
                CreationKind::Fork => None,
                CreationKind::Thread { .. } => Some(pending.mask),
            },
        });
        let newborn = self.held(
            tid,
            DynamicEventKind::Newborn {
                parent: parent_identity,
            },
        )?;
        self.events.push_back(newborn);
        self.held(
            parent_tid,
            DynamicEventKind::Created {
                child: child_identity,
            },
        )
        .map(Some)
    }
}

fn same_pid_namespace(tid: libc::pid_t) -> Result<(), LaunchError> {
    let expected = std::fs::metadata("/proc/self/ns/pid")
        .map_err(|error| io_error("read tracer PID namespace", error))?;
    for namespace in ["pid", "pid_for_children"] {
        let actual = std::fs::metadata(format!("/proc/{tid}/ns/{namespace}"))
            .map_err(|error| io_error("read fork PID namespace", error))?;
        if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
            return Err(LaunchError::Invalid(
                "fork PID namespace translation is unqualified",
            ));
        }
    }
    Ok(())
}

// The initial anchor uses exactly the existing per-task disabled-state proof.
// Ownership authentication is performed by Owner before this read-only call.
pub(super) fn anchor_shadow_stack_disabled(tid: i32) -> Result<(), LaunchError> {
    thread::shadow_stack_disabled(tid)
}

#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner) use thread::CetRetainedSnapshot;
pub(in crate::linux::remote::dynamic::owner) use thread::{BoundedCet, certify_bounded_cet};
