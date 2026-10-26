//! Exact original/ENTRY releases and pre-exit interception for the opt-in
//! singleton kernel profile. Existing generic lifecycle behavior is unchanged.
use super::*;
use crate::lifecycle::InitialKernelPhase;
use crate::linux::remote::dynamic::owner::bootstrap::{self, Request};

#[derive(Clone, Copy)]
pub(in crate::linux::remote::dynamic::owner) struct RuntimeKernelPreExit<'a> {
    pub(in crate::linux::remote::dynamic::owner) original: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner) entry: &'a DynamicEvent,
    pub(in crate::linux::remote::dynamic::owner) tid: i32,
    pub(in crate::linux::remote::dynamic::owner) status: i32,
}
pub(in crate::linux::remote::dynamic::owner) struct RuntimeKernelExitMessage<'a> {
    pub(in crate::linux::remote::dynamic::owner) observation: RuntimeKernelPreExit<'a>,
    pub(in crate::linux::remote::dynamic::owner) event_message: u64,
}

fn request(mode: libc::c_uint, tid: i32, stored: &mut Option<Request>) -> Result<(), LaunchError> {
    if stored.is_some() {
        return Err(LaunchError::Invalid("runtime kernel release record reused"));
    }
    unsafe { *libc::__errno_location() = 0 };
    let result = unsafe { libc::ptrace(mode, tid, 0usize, 0usize) };
    let code = unsafe { *libc::__errno_location() };
    let value = Request {
        result,
        errno: (code != 0).then_some(code),
    };
    *stored = Some(value);
    if let Some(errno) = value.errno {
        return Err(io_error(
            "runtime kernel release",
            std::io::Error::from_raw_os_error(errno),
        ));
    }
    if value.result != 0 {
        return Err(LaunchError::Invalid(
            "runtime kernel release result differs",
        ));
    }
    Ok(())
}
fn allowed(number: u64) -> bool {
    [
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ]
    .into_iter()
    .any(|value| number == value as u64)
}

impl NativeLifecycle {
    /// # Safety
    /// The native producer proved the exact original bytes/fetch RX window,
    /// finite syscall policy and unchanged current full state under one until.
    pub(in crate::linux::remote::dynamic::owner) unsafe fn begin_runtime_kernel_original(
        &mut self,
        owner: &mut Owner,
        stop: &AdmissionStop,
        result: &mut Option<Request>,
    ) -> Result<(), LaunchError> {
        self.require_admission_stop(stop)?;
        if result.is_some() || self.admission_interrupt_credit(stop.token.tid)? != 0 {
            return Err(LaunchError::Invalid(
                "runtime kernel original release is not fresh",
            ));
        }
        let outcome = (|| {
            recorded(
                self.registry
                    .resume(stop.identity.task, stop.token.sequence),
            )?;
            request(libc::PTRACE_SYSCALL, stop.token.tid, result)?;
            owner.released(stop.token.tid);
            self.tasks.get_mut(&stop.token.tid).unwrap().state = State::Running;
            Ok(())
        })();
        if outcome.is_err() {
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
        }
        outcome
    }
    /// # Safety
    /// Only the exact freshly authenticated native syscall ENTRY may reach
    /// this helper. Caller reserved every remaining effect and cleanup bound.
    pub(in crate::linux::remote::dynamic::owner) unsafe fn resume_runtime_kernel_entry(
        &mut self,
        owner: &mut Owner,
        event: &DynamicEvent,
        result: &mut Option<Request>,
    ) -> Result<(), LaunchError> {
        let token = event
            .stop_token()
            .ok_or(LaunchError::Invalid("runtime kernel ENTRY has no token"))?;
        let DynamicEventKind::SyscallEntry { number, .. } = event.kind else {
            return Err(LaunchError::Invalid(
                "runtime kernel continuation is not ENTRY",
            ));
        };
        if !allowed(number)
            || result.is_some()
            || self.require_stop(token)? != event
            || self.admission_interrupt_credit(token.tid)? != 0
        {
            return Err(LaunchError::Invalid("runtime kernel ENTRY release differs"));
        }
        let identity = event
            .task
            .ok_or(LaunchError::Invalid("runtime kernel ENTRY lacks task"))?;
        let outcome = (|| {
            recorded(self.registry.resume(identity.task, token.sequence))?;
            request(libc::PTRACE_SYSCALL, token.tid, result)?;
            owner.released(token.tid);
            self.tasks.get_mut(&token.tid).unwrap().state = State::Running;
            Ok(())
        })();
        if outcome.is_err() {
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
        }
        outcome
    }
    fn runtime_kernel_common(
        &self,
        owner: &Owner,
        original: &AdmissionStop,
        until: Instant,
    ) -> Result<(), LaunchError> {
        bootstrap::physical(owner, until)?;
        let task = self
            .tasks
            .get(&owner.pid)
            .ok_or(LaunchError::Invalid("runtime kernel original task absent"))?;
        if self.session != owner.session
            || original.token.session != owner.session
            || original.token.tid != owner.pid
            || original.token.task != Some(original.identity.task)
            || original.identity.generation != 0
            || task.identity != original.identity
            || self.options != DynamicLifecycleOptions::default()
            || self.exec_policy != DynamicExecPolicy::Refuse
            || self.tasks.len() != 1
            || self.pending.is_some()
            || self.exec_pending.is_some()
            || self.exec_successes != 0
            || !self.events.is_empty()
            || task.interrupt_stops_remaining != 0
            || task.fork_return.is_some()
            || task.signal_obligation.is_some()
            || original.signal.is_some()
            || !matches!(
                original.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
            || owner.lifecycle.is_some()
        {
            return Err(LaunchError::Invalid(
                "runtime kernel singleton profile differs",
            ));
        }
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner) fn require_runtime_kernel_event(
        &self,
        owner: &Owner,
        original: &AdmissionStop,
        event: &DynamicEvent,
        until: Instant,
        scratch: &mut [u8],
    ) -> Result<(), LaunchError> {
        self.runtime_kernel_common(owner, original, until)?;
        let token = event
            .stop_token()
            .ok_or(LaunchError::Invalid("runtime kernel event has no token"))?;
        let phase = match event.kind {
            DynamicEventKind::SyscallEntry { number, .. } if allowed(number) => {
                InitialKernelPhase::Entry
            }
            DynamicEventKind::SyscallExit { .. } => InitialKernelPhase::Exit,
            _ => return Err(LaunchError::Invalid("runtime kernel event phase differs")),
        };
        let open = phase == InitialKernelPhase::Entry;
        let task = &self.tasks[&owner.pid];
        if self.require_stop(token)? != event
            || token.session != owner.session
            || token.tid != owner.pid
            || token.task != Some(original.identity.task)
            || event.task != Some(original.identity)
            || event.tid != owner.pid
            || token.sequence <= original.token.sequence
            || task.syscall_open != open
            || owner.stopped.get(&owner.pid).is_none_or(|status| {
                !libc::WIFSTOPPED(*status)
                    || libc::WSTOPSIG(*status) != (libc::SIGTRAP | 0x80)
                    || (*status >> 16) != 0
            })
        {
            return Err(LaunchError::Invalid(
                "runtime kernel actual event custody differs",
            ));
        }
        recorded(self.registry.require_initial_kernel_singleton(
            original.identity.task,
            original.identity.process,
            original.identity.address_space,
            owner.pid,
            phase,
        ))?;
        if recorded(self.registry.task(original.identity.task))?.sequence != token.sequence {
            return Err(LaunchError::Invalid(
                "runtime kernel event sequence differs",
            ));
        }
        super::super::super::admission::require_initial_task_identity(owner, until, scratch)?;
        self.runtime_kernel_common(owner, original, until)?;
        self.require_stop(token)?;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner) fn require_runtime_kernel_pre_exit(
        &self,
        owner: &Owner,
        observed: RuntimeKernelPreExit<'_>,
        until: Instant,
        scratch: &mut [u8],
    ) -> Result<(), LaunchError> {
        let RuntimeKernelPreExit {
            original,
            entry,
            tid,
            status,
        } = observed;
        self.runtime_kernel_common(owner, original, until)?;
        let token = entry.stop_token().ok_or(LaunchError::Invalid(
            "runtime kernel historical ENTRY token absent",
        ))?;
        let DynamicEventKind::SyscallEntry { number, .. } = entry.kind else {
            return Err(LaunchError::Invalid(
                "runtime kernel historical ENTRY phase differs",
            ));
        };
        if ![libc::SYS_exit as u64, libc::SYS_exit_group as u64].contains(&number)
            || tid != owner.pid
            || entry.tid != tid
            || entry.task != Some(original.identity)
            || token.tid != tid
            || token.task != Some(original.identity.task)
            || token.session != owner.session
            || token.sequence <= original.token.sequence
            || !libc::WIFSTOPPED(status)
            || libc::WSTOPSIG(status) != libc::SIGTRAP
            || status >> 16 != libc::PTRACE_EVENT_EXIT
            || owner.stopped.get(&tid) != Some(&status)
            || !matches!(self.tasks[&tid].state, State::Running)
            || !self.tasks[&tid].syscall_open
            || recorded(self.registry.task(original.identity.task))?.sequence != token.sequence
        {
            return Err(LaunchError::Invalid(
                "runtime kernel pre-exit custody differs",
            ));
        }
        recorded(self.registry.require_initial_kernel_singleton(
            original.identity.task,
            original.identity.process,
            original.identity.address_space,
            tid,
            InitialKernelPhase::PreExit,
        ))?;
        super::super::super::admission::require_initial_task_identity(owner, until, scratch)?;
        self.runtime_kernel_common(owner, original, until)?;
        Ok(())
    }
    /// # Safety
    /// Native raw custody and actual GETEVENTMSG were retained before this
    /// kernel-only CONT. The message is checked against the original exit intent.
    pub(in crate::linux::remote::dynamic::owner) unsafe fn continue_runtime_kernel_pre_exit(
        &mut self,
        owner: &mut Owner,
        exit: RuntimeKernelExitMessage<'_>,
        until: Instant,
        scratch: &mut [u8],
        result: &mut Option<Request>,
    ) -> Result<(DynamicEvent, u64), LaunchError> {
        self.require_runtime_kernel_pre_exit(owner, exit.observation, until, scratch)?;
        let observed = exit.observation;
        let DynamicEventKind::SyscallEntry { arguments, .. } = observed.entry.kind else {
            unreachable!()
        };
        let expected = ((arguments[0] as u32 & 0xff) << 8) as u64;
        if exit.event_message != expected || result.is_some() {
            return Err(LaunchError::Invalid(
                "runtime kernel pre-exit message differs from exit intent",
            ));
        }
        let status = ExitStatus::Code((arguments[0] & 0xff) as u8);
        let sequence = self.sequence(observed.tid)?;
        let outcome = (|| {
            request(libc::PTRACE_CONT, observed.tid, result)?;
            owner.released(observed.tid);
            self.tasks.get_mut(&observed.tid).unwrap().state = State::Exiting;
            recorded(self.registry.observe_exit_event(
                observed.original.identity.task,
                sequence,
                status,
            ))?;
            Ok((
                DynamicEvent {
                    tid: observed.tid,
                    task: Some(observed.original.identity),
                    kind: DynamicEventKind::TaskExiting { status },
                    stop: None,
                },
                sequence,
            ))
        })();
        if outcome.is_err() {
            owner.closing = true;
            owner.cancel.store(true, Ordering::Release);
        }
        outcome
    }
    pub(in crate::linux::remote::dynamic::owner) fn runtime_kernel_sequence(
        &self,
        task: DynamicTask,
    ) -> Result<u64, LaunchError> {
        let (&tid, _) = self
            .tasks
            .iter()
            .find(|(_, native)| native.identity == task)
            .ok_or(LaunchError::Invalid("runtime kernel task identity absent"))?;
        let record = recorded(self.registry.task(task.task))?;
        if record.process != task.process
            || record.address_space != task.address_space
            || recorded(self.registry.address_space(task.address_space))?.generation
                != task.generation
            || record.tid != tid
        {
            return Err(LaunchError::Invalid(
                "runtime kernel registry identity differs",
            ));
        }
        Ok(record.sequence)
    }
}
