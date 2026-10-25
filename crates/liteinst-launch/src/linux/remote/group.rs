//! Fixed-membership cooperative rendezvous for real threads sharing one mm.

use super::*;
use crate::publication::{PublicationOperations, PublicationStop, sealed};
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::mpsc::{SyncSender, sync_channel};

/// The only clone flags accepted during the bounded registration phase.
pub const FIXED_CLONE_FLAGS: u64 = (libc::CLONE_VM
    | libc::CLONE_THREAD
    | libc::CLONE_SIGHAND
    | libc::CLONE_FS
    | libc::CLONE_FILES
    | libc::CLONE_SYSVSEM) as u64;
const OPTIONS: usize = (libc::PTRACE_O_TRACECLONE
    | libc::PTRACE_O_TRACEEXEC
    | libc::PTRACE_O_TRACESYSGOOD
    | libc::PTRACE_O_EXITKILL) as usize;

/// An owned event from one registered worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskEvent {
    /// Kernel task ID; distinct from the process's thread-group ID.
    pub tid: libc::pid_t,
    /// The worker's exact stop or terminal event.
    pub event: ProcessEvent,
}

struct Task {
    state: State,
    sequence: u64,
    reaped: bool,
    stack: Option<Range<u64>>,
}

/// Owns a fixed set of real traced tasks in one address space.
///
/// The leader stays at its declared registration trap. All workers are resumed
/// before collecting their next stops. A worker without a bounded cooperative
/// stop causes whole-group termination; no publication occurs while it runs.
pub struct SharedMmProcess {
    process: StoppedProcess,
    tasks: BTreeMap<libc::pid_t, Task>,
    kill_handle: Option<OwnedFd>,
    cleanup: Option<SyncSender<ReapGroup>>,
    closed: bool,
    last_rendezvous: Duration,
}

/// Borrows the entire stopped registry, selecting one task for trusted work.
pub struct AllThreadsStop<'a> {
    group: &'a mut SharedMmProcess,
    tid: libc::pid_t,
}

/// Narrow publication operations under a borrowed all-task exclusion guard.
pub struct GroupLeaseOps<'scope, 'owner> {
    held: &'scope RefCell<AllThreadsStop<'owner>>,
}

struct GroupExclusion<'scope, 'owner> {
    held: &'scope RefCell<AllThreadsStop<'owner>>,
}

struct ReapGroup {
    tgid: libc::pid_t,
    handle: OwnedFd,
    tids: BTreeSet<libc::pid_t>,
    discover_members: bool,
}

impl SharedMmProcess {
    /// Runs a declared factory, registering 2..=8 actual clone workers, then
    /// holds its leader at `freeze_pc`, which must contain an original INT3.
    /// Every child is held at its automatic ptrace attach stop before executing.
    ///
    /// # Safety
    /// The caller certifies immutable, complete factory instruction facts and
    /// exclusive ownership of the mm, code, aliases and external accesses. Only
    /// declared factory pages may be executable; all other worker/application
    /// code remains NX. Child stacks are distinct private RW/NX pages. The
    /// factory must execute exactly `worker_count` checked clones and then the
    /// declared trap, without entering the private island. No independent
    /// tracer/reaper or process may mutate this execution domain.
    pub unsafe fn register(
        process: StoppedProcess,
        worker_count: usize,
        freeze_pc: u64,
        timeout: Duration,
    ) -> Result<Self, LaunchError> {
        let until = deadline(timeout)?;
        if !(2..=8).contains(&worker_count) {
            return Err(LaunchError::Invalid(
                "shared-mm registration requires 2..=8 workers",
            ));
        }
        process.ensure_stopped()?;
        process.owned_signal_stop()?;
        single_task(process.pid())?;
        if process.island.contains(&freeze_pc)
            || !process
                .mappings()
                .iter()
                .any(|m| m.contains_executable(freeze_pc))
            || process.read_memory(freeze_pc, 1)? != [0xcc]
        {
            return Err(LaunchError::Invalid(
                "factory freeze is not a declared executable INT3",
            ));
        }
        // Reserve delayed cleanup before authorizing any clone.
        let (cleanup, receiver) = sync_channel::<ReapGroup>(1);
        std::thread::Builder::new()
            .name("liteinst-group-reaper".into())
            .spawn(move || {
                if let Ok(mut job) = receiver.recv() {
                    while !job.poll() {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            })
            .map_err(|e| io_error("reserve group reaper", e))?;
        // SAFETY: pidfd_open receives the exclusively owned thread-group ID.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, process.pid(), 0) };
        if descriptor < 0 {
            return Err(system("pidfd_open owned group"));
        }
        // SAFETY: this successful syscall returned a new descriptor.
        let handle = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
        let tgid = process.pid();
        let leader_state = process.state.clone();
        let mut group = Self {
            process,
            tasks: BTreeMap::from([(
                tgid,
                Task {
                    state: leader_state,
                    sequence: 0,
                    reaped: false,
                    stack: None,
                },
            )]),
            kill_handle: Some(handle),
            cleanup: Some(cleanup),
            closed: false,
            last_rendezvous: Duration::ZERO,
        };
        ptrace(libc::PTRACE_SETOPTIONS, tgid, 0, OPTIONS)?;
        group.register_inner(worker_count, freeze_pc, until)?;
        group.verify_all_stopped()?;
        Ok(group)
    }

    fn register_inner(
        &mut self,
        count: usize,
        freeze_pc: u64,
        until: Instant,
    ) -> Result<(), LaunchError> {
        let leader = self.pid();
        let mut clone_stack: Option<Range<u64>> = None;
        let mut clone_child = None;
        loop {
            ptrace(libc::PTRACE_SYSCALL, leader, 0, 0)?;
            self.tasks.get_mut(&leader).unwrap().state = State::Running;
            let status = wait_owned(leader, until, "factory registration")?;
            if !libc::WIFSTOPPED(status) {
                self.record_terminal(leader, status);
                return Err(LaunchError::Invalid("factory terminated before freeze"));
            }
            self.tasks.get_mut(&leader).unwrap().state = State::Stopped(Phase::SyscallExit);
            if status >> 16 == libc::PTRACE_EVENT_CLONE {
                let stack = clone_stack
                    .as_ref()
                    .ok_or(LaunchError::Invalid("clone event without checked entry"))?
                    .clone();
                if clone_child.is_some() || self.tasks.len() > count {
                    return Err(LaunchError::Invalid("unexpected extra factory clone"));
                }
                let mut raw = 0_u64;
                ptrace(libc::PTRACE_GETEVENTMSG, leader, 0, (&raw mut raw) as usize)?;
                let tid = libc::pid_t::try_from(raw)
                    .map_err(|_| LaunchError::Invalid("invalid clone task ID"))?;
                if tid <= 0 || self.tasks.contains_key(&tid) {
                    return Err(LaunchError::Invalid("duplicate clone task ID"));
                }
                // Record cleanup ownership before any fallible child operation.
                self.tasks.insert(
                    tid,
                    Task {
                        state: State::Running,
                        sequence: 0,
                        reaped: false,
                        stack: Some(stack),
                    },
                );
                let child_status = wait_owned(tid, until, "automatic clone attach stop")?;
                if !libc::WIFSTOPPED(child_status)
                    || libc::WSTOPSIG(child_status) != libc::SIGSTOP
                    || child_status >> 16 != 0
                {
                    self.record_terminal(tid, child_status);
                    return Err(LaunchError::Invalid(
                        "clone child lacks authenticated attach stop",
                    ));
                }
                if task_tgid(tid)? != leader {
                    return Err(LaunchError::Invalid(
                        "clone child is outside owned thread group",
                    ));
                }
                ptrace(libc::PTRACE_SETOPTIONS, tid, 0, OPTIONS)?;
                // This is safe to resume but not yet a materialized user stop
                // suitable for injected instructions.
                self.tasks.get_mut(&tid).unwrap().state = State::Stopped(Phase::SyscallExit);
                clone_child = Some(tid);
                continue;
            }
            if status >> 16 != 0 {
                return Err(LaunchError::Invalid("unsupported factory lifecycle event"));
            }
            if libc::WSTOPSIG(status) == libc::SIGTRAP | 0x80 {
                let info = syscall_info(leader)?;
                if info.arch != AUDIT_ARCH_X86_64 {
                    return Err(LaunchError::Invalid("non-native factory syscall"));
                }
                match info.op {
                    libc::PTRACE_SYSCALL_INFO_ENTRY => {
                        // SAFETY: the checked discriminator initializes entry.
                        let entry = unsafe { info.u.entry };
                        if entry.nr != libc::SYS_clone as u64
                            || clone_stack.is_some()
                            || self.tasks.len() > count
                        {
                            return Err(LaunchError::Invalid(
                                "factory syscall is not an expected clone",
                            ));
                        }
                        clone_stack = Some(self.check_clone(entry.args)?);
                    }
                    libc::PTRACE_SYSCALL_INFO_EXIT => {
                        // SAFETY: the checked discriminator initializes exit.
                        let exit = unsafe { info.u.exit };
                        if exit.is_error != 0 || Some(exit.sval) != clone_child.map(i64::from) {
                            return Err(LaunchError::Invalid(
                                "factory clone did not produce its registered child",
                            ));
                        }
                        clone_child = None;
                        clone_stack = None;
                    }
                    _ => return Err(LaunchError::Invalid("unsupported factory syscall stop")),
                }
                continue;
            }
            let event = self.signal_event(leader, status)?;
            if let ProcessEvent::Signal(signal) = event {
                if self.tasks.len() == count + 1
                    && clone_stack.is_none()
                    && signal.signal == libc::SIGTRAP
                    && matches!(signal.code, libc::SI_KERNEL | libc::TRAP_BRKPT)
                    && signal.instruction_pointer
                        == freeze_pc
                            .checked_add(1)
                            .ok_or(LaunchError::Invalid("freeze PC overflow"))?
                    && read_memory(leader, freeze_pc, 1)? == [0xcc]
                {
                    self.tasks.get_mut(&leader).unwrap().state = State::Stopped(Phase::Signal {
                        stop: signal,
                        owned: true,
                    });
                    return Ok(());
                }
            }
            return Err(LaunchError::Invalid(
                "factory did not reach its declared freeze",
            ));
        }
    }

    fn check_clone(&mut self, args: [u64; 6]) -> Result<Range<u64>, LaunchError> {
        if args[0] != FIXED_CLONE_FLAGS || args[2..5] != [0; 3] || args[1] % 16 != 0 {
            return Err(LaunchError::Invalid(
                "clone flags, optional pointers, or stack are unsupported",
            ));
        }
        self.process.checkpoint.mappings = read_maps(self.pid())?;
        let start = args[1]
            .checked_sub(self.process.page_size as u64)
            .ok_or(LaunchError::Invalid("child stack underflow"))?;
        self.check_range(start, self.process.page_size, Some("rw-p"))?;
        let range = start..args[1];
        if self
            .tasks
            .values()
            .filter_map(|task| task.stack.as_ref())
            .any(|stack| range.start < stack.end && stack.start < range.end)
        {
            return Err(LaunchError::Invalid("registered child stacks overlap"));
        }
        let leader_sp = read_registers(self.pid())?.rsp;
        if range.contains(&leader_sp) {
            return Err(LaunchError::Invalid("child stack overlaps leader stack"));
        }
        Ok(range)
    }

    /// Returns the shared thread-group ID.
    pub fn pid(&self) -> libc::pid_t {
        self.process.pid()
    }
    /// Returns all live registered task IDs, including the frozen leader.
    pub fn task_ids(&self) -> Vec<libc::pid_t> {
        self.tasks
            .iter()
            .filter_map(|(&tid, t)| (!t.reaped).then_some(tid))
            .collect()
    }
    /// Returns live worker IDs, excluding the frozen leader.
    pub fn worker_ids(&self) -> Vec<libc::pid_t> {
        self.task_ids()
            .into_iter()
            .filter(|tid| *tid != self.pid())
            .collect()
    }
    /// Returns the number of live registered workers.
    pub fn live_worker_count(&self) -> usize {
        self.worker_ids().len()
    }
    /// Returns time from first observed owned event through complete exclusion
    /// for the most recent worker rendezvous.
    pub fn last_rendezvous_duration(&self) -> Duration {
        self.last_rendezvous
    }
    /// Reads shared memory while all registered tasks remain held.
    pub fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        self.verify_all_stopped()?;
        read_memory(self.pid(), address, len)
    }
    /// Reads every live worker's registers under collective exclusion. The
    /// permanently frozen leader is deliberately excluded from this list.
    pub fn stopped_registers(&self) -> Result<Vec<(libc::pid_t, RegisterSnapshot)>, LaunchError> {
        self.verify_all_stopped()?;
        self.worker_ids()
            .into_iter()
            .map(|tid| read_registers(tid).map(|regs| (tid, regs)))
            .collect()
    }
    /// Returns the original executable mappings.
    pub fn initial_image_mappings(&self) -> &[MemoryMapping] {
        &self.process.images
    }
    /// Returns the current shared mapping snapshot.
    pub fn mappings(&self) -> &[MemoryMapping] {
        self.process.mappings()
    }
    /// Returns the target page size.
    pub fn page_size(&self) -> usize {
        self.process.page_size
    }
    /// Returns original executable/interpreter entry evidence.
    pub fn entries(&self) -> &EntryEvidence {
        self.process.entries()
    }

    /// Releases every live worker before waiting for any event, then collects
    /// one stop/exit per worker under one deadline. No stopped worker is resumed
    /// while collecting, and the leader remains frozen throughout.
    pub fn resume_workers_until_all_stopped(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<TaskEvent>, LaunchError> {
        let until = deadline(timeout)?;
        let result = self.resume_workers_inner(until);
        match result {
            Ok(events) => Ok(events),
            Err(error) => self.fail(error),
        }
    }

    fn resume_workers_inner(&mut self, until: Instant) -> Result<Vec<TaskEvent>, LaunchError> {
        self.verify_all_stopped()?;
        let workers = self.worker_ids();
        for &tid in &workers {
            match &self.tasks[&tid].state {
                State::Stopped(Phase::Signal { owned: false, .. }) => {
                    return Err(LaunchError::Invalid("worker signal is not acknowledged"));
                }
                State::Stopped(Phase::SyscallEntry) => {
                    let registers = read_registers(tid)?;
                    worker_syscall(registers.orig_rax)?;
                }
                State::Stopped(_) => {}
                _ => return Err(LaunchError::Invalid("worker is not stopped")),
            }
        }
        for &tid in &workers {
            ptrace(libc::PTRACE_SYSCALL, tid, 0, 0)?;
            self.tasks.get_mut(&tid).unwrap().state = State::Running;
        }
        let mut events = Vec::new();
        let mut first_observed = None;
        let mut pending: BTreeSet<_> = workers.into_iter().collect();
        while !pending.is_empty() {
            for tid in pending.clone() {
                if let Some(status) = poll_owned(tid)? {
                    first_observed.get_or_insert_with(Instant::now);
                    let event = self.worker_event(tid, status)?;
                    pending.remove(&tid);
                    events.push(TaskEvent { tid, event });
                }
            }
            if !pending.is_empty() {
                if Instant::now() >= until {
                    return Err(LaunchError::Timeout("collective worker rendezvous"));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        self.verify_all_stopped()?;
        self.last_rendezvous = first_observed.map_or(Duration::ZERO, |first| first.elapsed());
        Ok(events)
    }

    fn worker_event(&mut self, tid: libc::pid_t, status: i32) -> Result<ProcessEvent, LaunchError> {
        if let Some(event) = self.record_terminal(tid, status) {
            return Ok(event);
        }
        if !libc::WIFSTOPPED(status) || status >> 16 != 0 {
            return Err(LaunchError::Invalid("fixed-membership lifecycle event"));
        }
        if libc::WSTOPSIG(status) == libc::SIGTRAP | 0x80 {
            let info = syscall_info(tid)?;
            if info.arch != AUDIT_ARCH_X86_64
                || self.process.island.contains(&info.instruction_pointer)
            {
                return Err(LaunchError::Invalid(
                    "worker syscall ABI or island entry is unsupported",
                ));
            }
            return match info.op {
                libc::PTRACE_SYSCALL_INFO_ENTRY => {
                    // SAFETY: the discriminator identifies entry.
                    let entry = unsafe { info.u.entry };
                    worker_syscall(entry.nr)?;
                    self.tasks.get_mut(&tid).unwrap().state = State::Stopped(Phase::SyscallEntry);
                    Ok(ProcessEvent::SyscallEntry {
                        number: entry.nr,
                        arguments: entry.args,
                    })
                }
                libc::PTRACE_SYSCALL_INFO_EXIT => {
                    // SAFETY: the discriminator identifies exit.
                    let exit = unsafe { info.u.exit };
                    self.tasks.get_mut(&tid).unwrap().state = State::Stopped(Phase::SyscallExit);
                    Ok(ProcessEvent::SyscallExit {
                        result: exit.sval,
                        is_error: exit.is_error != 0,
                    })
                }
                _ => Err(LaunchError::Invalid("unsupported worker syscall stop")),
            };
        }
        self.signal_event(tid, status)
    }

    fn signal_event(&mut self, tid: libc::pid_t, status: i32) -> Result<ProcessEvent, LaunchError> {
        let info = siginfo(tid)?;
        let registers = read_registers(tid)?;
        if info.si_signo != libc::WSTOPSIG(status) || self.process.island.contains(&registers.rip) {
            return Err(LaunchError::Invalid(
                "unowned task signal or private island entry",
            ));
        }
        let task = self.tasks.get_mut(&tid).unwrap();
        task.sequence = task
            .sequence
            .checked_add(1)
            .ok_or(LaunchError::Invalid("task stop sequence exhausted"))?;
        let address = if matches!(
            info.si_signo,
            libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGTRAP | libc::SIGFPE
        ) {
            // SAFETY: these signal variants carry the fault address member.
            Some(unsafe { info.si_addr() } as u64)
        } else {
            None
        };
        let stop = SignalStop {
            signal: info.si_signo,
            code: info.si_code,
            address,
            instruction_pointer: registers.rip,
            pid: tid,
            sequence: task.sequence,
        };
        task.state = State::Stopped(Phase::Signal {
            stop: stop.clone(),
            owned: false,
        });
        Ok(ProcessEvent::Signal(stop))
    }

    fn record_terminal(&mut self, tid: libc::pid_t, status: i32) -> Option<ProcessEvent> {
        let event = if libc::WIFEXITED(status) {
            ProcessEvent::Exited {
                code: libc::WEXITSTATUS(status),
            }
        } else if libc::WIFSIGNALED(status) {
            ProcessEvent::Signaled {
                signal: libc::WTERMSIG(status),
            }
        } else {
            return None;
        };
        if let Some(task) = self.tasks.get_mut(&tid) {
            task.reaped = true;
            task.state = State::Dead;
        }
        if tid == self.pid() {
            self.process.checkpoint.child.reaped = true;
        }
        Some(event)
    }

    fn verify_all_stopped(&self) -> Result<(), LaunchError> {
        if self.closed || self.tasks[&self.pid()].reaped {
            return Err(LaunchError::Invalid("shared-mm owner is closed"));
        }
        let expected: BTreeSet<_> = self.task_ids().into_iter().collect();
        if proc_tasks(self.pid())? != expected {
            return Err(LaunchError::Invalid("live task registry changed"));
        }
        for &tid in &expected {
            if !matches!(self.tasks[&tid].state, State::Stopped(_)) {
                return Err(LaunchError::Invalid(
                    "collective exclusion has a running task",
                ));
            }
            read_registers(tid)?;
        }
        Ok(())
    }

    /// Borrows actual whole-registry exclusion and selects a live task.
    pub fn hold_for(&mut self, tid: libc::pid_t) -> Result<AllThreadsStop<'_>, LaunchError> {
        if let Err(error) = self.verify_all_stopped() {
            return self.fail(error);
        }
        if self.tasks.get(&tid).is_none_or(|task| task.reaped) {
            return Err(LaunchError::Invalid("selected task is not live and owned"));
        }
        Ok(AllThreadsStop { group: self, tid })
    }

    /// Kills the entire group and reaps every owned TID, with bounded foreground
    /// cleanup and reserved delayed reaping if the kernel postpones exit.
    pub fn terminate(mut self) -> Result<(), LaunchError> {
        self.close()
    }

    fn fail<T>(&mut self, error: LaunchError) -> Result<T, LaunchError> {
        let _ = self.close();
        Err(error)
    }

    fn close(&mut self) -> Result<(), LaunchError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.process.state = State::Dead;
        let mut job = ReapGroup {
            tgid: self.pid(),
            handle: self.kill_handle.take().unwrap(),
            tids: self.task_ids().into_iter().collect(),
            discover_members: !self.tasks[&self.pid()].reaped,
        };
        // Ownership of the leader's eventual reap moves into this job too.
        self.process.checkpoint.child.reaped = true;
        let until = Instant::now() + Duration::from_secs(2);
        while !job.poll() {
            if Instant::now() >= until {
                if let Err(error) = self.cleanup.take().unwrap().send(job) {
                    let mut job = error.0;
                    while !job.poll() {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                return Err(LaunchError::Timeout(
                    "group cleanup transferred to reserved reaper",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        self.cleanup.take();
        Ok(())
    }

    fn check_range(
        &self,
        address: u64,
        len: usize,
        permissions: Option<&str>,
    ) -> Result<(), LaunchError> {
        let end = address
            .checked_add(len as u64)
            .ok_or(LaunchError::Invalid("group memory range overflow"))?;
        if address < self.process.island.end && self.process.island.start < end {
            return Err(LaunchError::Invalid(
                "operation overlaps immutable syscall island",
            ));
        }
        let mut cursor = address;
        while cursor < end {
            let mapping = self
                .mappings()
                .iter()
                .find(|m| m.start <= cursor && cursor < m.end)
                .ok_or(LaunchError::Invalid("group range is not mapped"))?;
            if mapping.permissions.as_bytes()[3] != b'p'
                || mapping.pathname.as_deref() == Some("[vsyscall]")
                || permissions.is_some_and(|required| required != mapping.permissions)
            {
                return Err(LaunchError::Invalid(
                    "group range permissions are unsupported",
                ));
            }
            cursor = mapping.end.min(end);
        }
        Ok(())
    }
}

impl Drop for SharedMmProcess {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl AllThreadsStop<'_> {
    /// Returns the shared thread-group identity.
    pub fn pid(&self) -> libc::pid_t {
        self.group.pid()
    }
    /// Returns the selected stopped worker's task identity.
    pub fn task_id(&self) -> libc::pid_t {
        self.tid
    }
    /// Returns the target page size.
    pub fn page_size(&self) -> usize {
        self.group.page_size()
    }
    /// Copies the checked shared mapping snapshot.
    pub fn mappings(&self) -> Vec<MemoryMapping> {
        self.group.mappings().to_vec()
    }
    /// Reads memory without releasing any registered task.
    pub fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        self.group.verify_all_stopped()?;
        read_memory(self.tid, address, len)
    }
    /// Reads the selected task's complete general registers.
    pub fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        self.group.verify_all_stopped()?;
        read_registers(self.tid)
    }
    /// Reads the selected task's complete extended state.
    pub fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        self.group.verify_all_stopped()?;
        xstate(self.tid)
    }
    /// Acknowledges only the exact pending owned fault for this selected TID.
    pub fn acknowledge_owned_signal(&mut self, event: &SignalStop) -> Result<(), LaunchError> {
        self.group.verify_all_stopped()?;
        if !matches!(event.signal, libc::SIGSEGV | libc::SIGTRAP | libc::SIGILL) {
            return Err(LaunchError::Invalid(
                "signal is outside the owned-fault envelope",
            ));
        }
        match &mut self.group.tasks.get_mut(&self.tid).unwrap().state {
            State::Stopped(Phase::Signal { stop, owned })
                if stop == event && event.pid == self.tid =>
            {
                *owned = true;
                Ok(())
            }
            _ => Err(LaunchError::Invalid(
                "signal event does not match selected task stop",
            )),
        }
    }

    fn ready(&self) -> Result<(), LaunchError> {
        self.group.verify_all_stopped()?;
        match self.group.tasks[&self.tid].state {
            State::Stopped(Phase::OwnedTrap | Phase::Signal { owned: true, .. }) => Ok(()),
            _ => Err(LaunchError::Invalid(
                "trusted group operation requires an acknowledged user stop",
            )),
        }
    }

    fn refresh(&mut self) -> Result<(), LaunchError> {
        self.group.verify_all_stopped()?;
        self.group.process.checkpoint.mappings = read_maps(self.pid())?;
        verify_island(self.tid, self.group.mappings(), &self.group.process.island)
    }

    // The selected task alone executes immutable trusted instructions. Every
    // other registered task retains its exact stop throughout this operation.
    fn trusted(
        &mut self,
        address: u64,
        len: usize,
        setup: impl FnOnce(&mut RegisterSnapshot),
        exact_registers: bool,
        until: Instant,
    ) -> Result<u64, LaunchError> {
        self.ready()?;
        self.refresh()?;
        let saved = read_registers(self.tid)?;
        let extended = xstate(self.tid)?;
        let mut injected = saved;
        injected.rip = address;
        injected.orig_rax = u64::MAX;
        injected.eflags &= !(0x100 | 0x10000 | 0x40000);
        setup(&mut injected);
        let mut stopped = true;
        let result = (|| {
            set_registers(self.tid, &injected)?;
            ptrace(libc::PTRACE_CONT, self.tid, 0, 0)?;
            stopped = false;
            self.group.tasks.get_mut(&self.tid).unwrap().state = State::Running;
            let status = wait_owned(self.tid, until, "trusted all-stop island operation")?;
            stopped = libc::WIFSTOPPED(status);
            if !stopped {
                self.group.record_terminal(self.tid, status);
                return Err(LaunchError::Invalid("trusted group task terminated"));
            }
            if libc::WSTOPSIG(status) != libc::SIGTRAP || status >> 16 != 0 {
                return Err(LaunchError::Invalid(
                    "trusted group operation missed its trap",
                ));
            }
            let info = siginfo(self.tid)?;
            let result = read_registers(self.tid)?;
            injected.rip = address + len as u64;
            if info.si_signo != libc::SIGTRAP
                || !matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT)
                || result.rip != injected.rip
                || (exact_registers && result != injected)
            {
                return Err(LaunchError::Invalid(
                    "unowned or state-changing trusted group trap",
                ));
            }
            Ok(result.rax)
        })();
        if stopped {
            if let Err(error) = restore_state(self.tid, &saved, &extended) {
                return self.group.fail(error);
            }
            self.group.tasks.get_mut(&self.tid).unwrap().state = State::Stopped(Phase::OwnedTrap);
        }
        match result {
            Ok(value) => match self.group.verify_all_stopped() {
                Ok(()) => Ok(value),
                Err(error) => self.group.fail(error),
            },
            Err(error) => self.group.fail(error),
        }
    }

    fn syscall(
        &mut self,
        number: libc::c_long,
        args: [u64; 6],
        timeout: Duration,
    ) -> Result<u64, LaunchError> {
        let until = deadline(timeout)?;
        self.trusted(
            self.group.process.island.start,
            STUB.len(),
            |registers| {
                registers.rax = number as u64;
                registers.rdi = args[0];
                registers.rsi = args[1];
                registers.rdx = args[2];
                registers.r10 = args[3];
                registers.r8 = args[4];
                registers.r9 = args[5];
            },
            false,
            until,
        )
    }

    /// Initializes whole private pages at an exact unused address, then makes
    /// them RX and synchronizes the shared mm. Partial failures kill the group.
    pub fn map_private_code(
        &mut self,
        address: u64,
        image: &[u8],
        timeout: Duration,
    ) -> Result<Range<u64>, LaunchError> {
        self.ready()?;
        let until = deadline(timeout)?;
        let end = address
            .checked_add(image.len() as u64)
            .ok_or(LaunchError::Invalid("code allocation overflow"))?;
        if address == 0
            || address % self.page_size() as u64 != 0
            || image.is_empty()
            || image.len() > MAX_MEMORY_READ
            || image.len() % self.page_size() != 0
        {
            return Err(LaunchError::Invalid("invalid private code image range"));
        }
        self.refresh()?;
        if self
            .group
            .mappings()
            .iter()
            .any(|m| address < m.end && m.start < end)
        {
            return Err(LaunchError::Invalid(
                "private code allocation overlaps mapping",
            ));
        }
        let allocated = syscall_result(
            self.syscall(
                libc::SYS_mmap,
                [
                    address,
                    image.len() as u64,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64,
                    u64::MAX,
                    0,
                ],
                remaining(until)?,
            )?,
            "group fixed code allocation",
        )?;
        let result = (|| {
            if allocated != address {
                return Err(LaunchError::Invalid(
                    "fixed allocation returned another address",
                ));
            }
            self.refresh()?;
            self.group.check_range(address, image.len(), Some("rw-p"))?;
            if self
                .group
                .mappings()
                .iter()
                .any(|m| address < m.end && m.start < end && m.pathname.is_some())
            {
                return Err(LaunchError::Invalid(
                    "private allocation has unexpected backing",
                ));
            }
            if self
                .read_memory(address, image.len())?
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(LaunchError::Invalid(
                    "private allocation is not zero initialized",
                ));
            }
            poke_bytes(self.tid, address, image)?;
            if self.read_memory(address, image.len())? != image {
                return Err(LaunchError::Invalid(
                    "private code initialization did not verify",
                ));
            }
            self.mprotect(
                address,
                image.len(),
                libc::PROT_READ | libc::PROT_EXEC,
                remaining(until)?,
            )?;
            self.sync_core(remaining(until)?)?;
            if self.read_memory(address, image.len())? != image {
                return Err(LaunchError::Invalid("finalized private code changed"));
            }
            Ok(address..end)
        })();
        match result {
            Ok(range) => Ok(range),
            Err(error) => self.group.fail(error),
        }
    }

    /// Performs one native MOV of exactly 1, 2, 4, or 8 bytes while all other
    /// tasks remain held. Requires a private RW/NX destination and verifies its
    /// complete surrounding word envelope plus exact restored GPR/XSTATE.
    pub fn exact_store_checked(
        &mut self,
        address: u64,
        expected: &[u8],
        replacement: &[u8],
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        self.ready()?;
        let until = deadline(timeout)?;
        let index = match expected.len() {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => {
                return Err(LaunchError::Invalid(
                    "exact store width must be 1, 2, 4, or 8",
                ));
            }
        };
        if expected.len() != replacement.len() {
            return Err(LaunchError::Invalid("exact store lengths differ"));
        }
        let end = address
            .checked_add(expected.len() as u64)
            .ok_or(LaunchError::Invalid("exact store overflow"))?;
        let envelope = (address & !7)
            ..(end
                .checked_add(7)
                .ok_or(LaunchError::Invalid("store envelope overflow"))?
                & !7);
        self.refresh()?;
        self.group.check_range(
            envelope.start,
            (envelope.end - envelope.start) as usize,
            Some("rw-p"),
        )?;
        let mut after =
            self.read_memory(envelope.start, (envelope.end - envelope.start) as usize)?;
        let offset = (address - envelope.start) as usize;
        if &after[offset..offset + expected.len()] != expected {
            return Err(LaunchError::Invalid("remote expected bytes mismatch"));
        }
        after[offset..offset + replacement.len()].copy_from_slice(replacement);
        let mut value = [0; 8];
        value[..replacement.len()].copy_from_slice(replacement);
        let (stub_offset, stub) = STORE_STUBS[index];
        self.trusted(
            self.group.process.island.start + stub_offset as u64,
            stub.len(),
            |registers| {
                registers.rdi = address;
                registers.rax = u64::from_le_bytes(value);
            },
            true,
            until,
        )?;
        match self.read_memory(envelope.start, after.len()) {
            Ok(actual) if actual == after => Ok(()),
            Ok(_) => self.group.fail(LaunchError::Invalid(
                "exact group store or adjacent bytes did not verify",
            )),
            Err(error) => self.group.fail(error),
        }
    }

    /// Changes and verifies private shared-mm page permissions. RWX and all
    /// operations overlapping the immutable island are refused.
    pub fn mprotect(
        &mut self,
        address: u64,
        len: usize,
        protection: i32,
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        self.ready()?;
        if len == 0
            || address % self.page_size() as u64 != 0
            || len % self.page_size() != 0
            || protection & !(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) != 0
            || protection & (libc::PROT_WRITE | libc::PROT_EXEC)
                == libc::PROT_WRITE | libc::PROT_EXEC
        {
            return Err(LaunchError::Invalid(
                "unsupported permission range or RWX protection",
            ));
        }
        self.refresh()?;
        self.group.check_range(address, len, None)?;
        let result = self.syscall(
            libc::SYS_mprotect,
            [address, len as u64, protection as u64, 0, 0, 0],
            timeout,
        )?;
        let result = (|| {
            syscall_result(result, "group mprotect")?;
            self.refresh()?;
            let end = address + len as u64;
            if self
                .group
                .mappings()
                .iter()
                .filter(|m| address < m.end && m.start < end)
                .any(|m| super_protection(m).ok() != Some(protection))
            {
                return Err(LaunchError::Invalid("group mprotect did not verify"));
            }
            self.group.check_range(address, len, None)
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.group.fail(error),
        }
    }

    /// Synchronizes instruction streams throughout the target shared mm.
    pub fn sync_core(&mut self, timeout: Duration) -> Result<(), LaunchError> {
        let result = self.syscall(libc::SYS_membarrier, [SYNC_CORE, 0, 0, 0, 0, 0], timeout)?;
        match syscall_result(result, "group sync-core") {
            Ok(_) => Ok(()),
            Err(error) => self.group.fail(error),
        }
    }

    /// Borrows the real all-task owner for one core publication transaction.
    /// Errors, poisoned results and unwinding terminate the complete group.
    ///
    /// # Safety
    /// The caller must uphold the complete `QuiescenceLease::new` contract:
    /// identity, all dependencies, aliases, external readers/writers, legal
    /// entries and saved resumes must remain certified for this entire scope.
    /// All local tasks being stopped proves execution exclusion only. No other
    /// tracer, reaper, or external process may access the ownership envelope.
    pub unsafe fn with_core_lease<T>(
        &mut self,
        identity: CodeIdentity,
        ranges: Vec<AddressRange>,
        action: impl FnOnce(
            &mut GroupLeaseOps<'_, '_>,
            &mut QuiescenceLease<'_>,
        ) -> Result<T, LaunchError>,
    ) -> Result<T, LaunchError> {
        if let Err(error) = self.ready() {
            return self.group.fail(error);
        }
        let outcome = {
            let held = RefCell::new(AllThreadsStop {
                group: &mut *self.group,
                tid: self.tid,
            });
            let mut guard = GroupExclusion { held: &held };
            let mut operations = GroupLeaseOps { held: &held };
            guard.held.borrow().ready()?;
            // SAFETY: the caller certifies the full core contract, and guard
            // borrows actual whole-registry exclusion until lease destruction.
            let mut lease = unsafe { QuiescenceLease::new(&mut guard, identity, ranges) };
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match action(&mut operations, &mut lease) {
                    Ok(value) if lease.is_poisoned() => {
                        drop(value);
                        Err(LaunchError::Invalid(
                            "core group publication lease remained poisoned",
                        ))
                    }
                    result => result,
                }
            }))
        };
        match outcome {
            Ok(Ok(value)) => match self.ready() {
                Ok(()) => Ok(value),
                Err(error) => self.group.fail(error),
            },
            Ok(Err(error)) => self.group.fail(error),
            Err(payload) => {
                let _ = self.group.close();
                std::panic::resume_unwind(payload)
            }
        }
    }
}

impl GroupLeaseOps<'_, '_> {
    /// Returns the shared thread-group identity.
    pub fn pid(&self) -> libc::pid_t {
        self.held.borrow().pid()
    }
    /// Returns the target page size.
    pub fn page_size(&self) -> usize {
        self.held.borrow().page_size()
    }
    /// Copies the checked shared mapping snapshot.
    pub fn mappings(&self) -> Vec<MemoryMapping> {
        self.held.borrow().mappings()
    }
    /// Reads shared memory while every application task remains held.
    pub fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        self.held.borrow().read_memory(address, len)
    }
    /// Reads the selected task's complete general registers.
    pub fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        self.held.borrow().read_registers()
    }
    /// Reads the selected task's complete extended state.
    pub fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        self.held.borrow().read_xstate()
    }
    /// Allocates and finalizes a complete private RX image without replacing mappings.
    pub fn map_private_code(
        &mut self,
        address: u64,
        image: &[u8],
        timeout: Duration,
    ) -> Result<Range<u64>, LaunchError> {
        self.held
            .borrow_mut()
            .map_private_code(address, image, timeout)
    }
    /// Performs one checked exact-width native store into private RW/NX memory.
    pub fn exact_store_checked(
        &mut self,
        address: u64,
        expected: &[u8],
        replacement: &[u8],
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        self.held
            .borrow_mut()
            .exact_store_checked(address, expected, replacement, timeout)
    }
    /// Changes private page permissions while retaining complete group exclusion.
    pub fn mprotect(
        &mut self,
        address: u64,
        len: usize,
        protection: i32,
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        self.held
            .borrow_mut()
            .mprotect(address, len, protection, timeout)
    }
    /// Synchronizes the shared mm's instruction stream.
    pub fn sync_core(&mut self, timeout: Duration) -> Result<(), LaunchError> {
        self.held.borrow_mut().sync_core(timeout)
    }
}

impl sealed::Sealed for GroupLeaseOps<'_, '_> {}
impl PublicationOperations for GroupLeaseOps<'_, '_> {
    fn pid(&self) -> libc::pid_t {
        GroupLeaseOps::pid(self)
    }
    fn page_size(&self) -> usize {
        GroupLeaseOps::page_size(self)
    }
    fn mappings(&self) -> Vec<MemoryMapping> {
        GroupLeaseOps::mappings(self)
    }
    fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        GroupLeaseOps::read_memory(self, address, len)
    }
    fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        GroupLeaseOps::read_registers(self)
    }
    fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        GroupLeaseOps::read_xstate(self)
    }
    fn map_private_code(
        &mut self,
        address: u64,
        image: &[u8],
        timeout: Duration,
    ) -> Result<Range<u64>, LaunchError> {
        GroupLeaseOps::map_private_code(self, address, image, timeout)
    }
    fn exact_store_checked(
        &mut self,
        address: u64,
        expected: &[u8],
        replacement: &[u8],
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        GroupLeaseOps::exact_store_checked(self, address, expected, replacement, timeout)
    }
    fn mprotect(
        &mut self,
        address: u64,
        len: usize,
        protection: i32,
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        GroupLeaseOps::mprotect(self, address, len, protection, timeout)
    }
    fn sync_core(&mut self, timeout: Duration) -> Result<(), LaunchError> {
        GroupLeaseOps::sync_core(self, timeout)
    }
}

impl sealed::Sealed for AllThreadsStop<'_> {}
impl PublicationStop for AllThreadsStop<'_> {
    fn pid(&self) -> libc::pid_t {
        AllThreadsStop::pid(self)
    }
    fn page_size(&self) -> usize {
        AllThreadsStop::page_size(self)
    }
    fn mappings(&self) -> Vec<MemoryMapping> {
        AllThreadsStop::mappings(self)
    }
    fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        AllThreadsStop::read_memory(self, address, len)
    }
    fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        AllThreadsStop::read_registers(self)
    }
    fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        AllThreadsStop::read_xstate(self)
    }
    fn acknowledge_owned_signal(&mut self, event: &SignalStop) -> Result<(), LaunchError> {
        AllThreadsStop::acknowledge_owned_signal(self, event)
    }
    unsafe fn with_publication_lease<T>(
        &mut self,
        identity: CodeIdentity,
        ranges: Vec<AddressRange>,
        action: impl FnOnce(
            &mut dyn PublicationOperations,
            &mut QuiescenceLease<'_>,
        ) -> Result<T, LaunchError>,
    ) -> Result<T, LaunchError> {
        // SAFETY: the trait caller certifies the identical complete contract.
        unsafe { self.with_core_lease(identity, ranges, |ops, lease| action(ops, lease)) }
    }
}

impl ReapGroup {
    fn discover_with(
        &mut self,
        discover: impl FnOnce(libc::pid_t) -> Result<BTreeSet<libc::pid_t>, LaunchError>,
    ) {
        if self.discover_members {
            if let Ok(tasks) = discover(self.tgid) {
                self.tids.extend(tasks);
            }
        }
    }

    fn finished_wait(&mut self, tid: libc::pid_t) {
        self.tids.remove(&tid);
        if tid == self.tgid {
            self.discover_members = false;
        }
    }

    fn poll(&mut self) -> bool {
        // Include a child whose clone event was queued when registration failed.
        // Numeric TGIDs may be reused after the leader's terminal wait. The
        // pidfd pins signal identity, not procfs path identity. Discover only
        // while the original leader is still ours to reap, then retain the
        // already established TID set without ever reopening that proc path.
        self.discover_with(proc_tasks);
        // SAFETY: the stable pidfd identifies only this owned thread group.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.handle.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
        for tid in self.tids.clone() {
            match poll_owned(tid) {
                Ok(Some(status)) if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) => {
                    self.finished_wait(tid);
                }
                Err(LaunchError::System { source, .. })
                    if source.raw_os_error() == Some(libc::ECHILD) =>
                {
                    self.finished_wait(tid);
                }
                _ => {}
            }
        }
        self.tids.is_empty()
    }
}

fn poll_owned(tid: libc::pid_t) -> Result<Option<i32>, LaunchError> {
    let mut status = 0;
    // SAFETY: callers own this specific traced task; no global wait is used.
    let result = unsafe { libc::waitpid(tid, &mut status, libc::WNOHANG | libc::__WALL) };
    if result == tid {
        Ok(Some(status))
    } else if result == 0 {
        Ok(None)
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            Ok(None)
        } else {
            Err(io_error("wait owned task", error))
        }
    }
}

fn wait_owned(
    tid: libc::pid_t,
    until: Instant,
    operation: &'static str,
) -> Result<i32, LaunchError> {
    loop {
        if let Some(status) = poll_owned(tid)? {
            return Ok(status);
        }
        if Instant::now() >= until {
            return Err(LaunchError::Timeout(operation));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn proc_tasks(tgid: libc::pid_t) -> Result<BTreeSet<libc::pid_t>, LaunchError> {
    let entries = std::fs::read_dir(format!("/proc/{tgid}/task"))
        .map_err(|e| io_error("list group tasks", e))?;
    let mut tasks = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|e| io_error("read group task", e))?;
        let tid = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse().ok())
            .ok_or(LaunchError::Invalid("invalid group task ID"))?;
        tasks.insert(tid);
    }
    Ok(tasks)
}

fn task_tgid(tid: libc::pid_t) -> Result<libc::pid_t, LaunchError> {
    let bytes = read_bounded(Path::new(&format!("/proc/{tid}/status")), MAX_PROC_FILE)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| LaunchError::Invalid("invalid task status"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .and_then(|value| value.trim().parse().ok())
        .ok_or(LaunchError::Invalid("missing task thread-group identity"))
}

fn worker_syscall(number: u64) -> Result<(), LaunchError> {
    if matches!(
        number as libc::c_long,
        libc::SYS_getpid | libc::SYS_gettid | libc::SYS_exit
    ) {
        Ok(())
    } else {
        Err(LaunchError::Invalid(
            "syscall is outside fixed-membership worker allowlist",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_never_discovers_reused_tgid_after_leader_reap() {
        // No signal or wait syscall is used by this transition test. A harmless
        // descriptor merely fills the unexercised production cleanup field.
        let mut cleanup = ReapGroup {
            tgid: 10,
            handle: std::fs::File::open("/dev/null").unwrap().into(),
            tids: BTreeSet::from([10, 11, 12]),
            discover_members: true,
        };
        cleanup.discover_with(|tgid| {
            assert_eq!(tgid, 10);
            Ok(BTreeSet::from([10, 11, 12, 13]))
        });
        cleanup.finished_wait(10);
        // Numeric TGID 10 could now identify an unrelated process. Reopening
        // that path would include unrelated task 99 in the owned wait set.
        let mut called = false;
        cleanup.discover_with(|_| {
            called = true;
            Ok(BTreeSet::from([10, 99]))
        });
        assert!(!called);
        assert_eq!(cleanup.tids, BTreeSet::from([11, 12, 13]));
        cleanup.finished_wait(11);
        assert_eq!(cleanup.tids, BTreeSet::from([12, 13]));

        // close() also initializes this state when its leader was already
        // terminal before the cleanup owner was constructed.
        let mut already_reaped = ReapGroup {
            tgid: 10,
            handle: std::fs::File::open("/dev/null").unwrap().into(),
            tids: BTreeSet::from([12, 13]),
            discover_members: false,
        };
        already_reaped
            .discover_with(|_| panic!("reaped leader must not reopen numeric procfs identity"));
        assert_eq!(already_reaped.tids, BTreeSet::from([12, 13]));
    }
}
