use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
mod tests;

mod admission;
pub(crate) mod bootstrap;
mod lifecycle;
pub(crate) mod publication;
pub(crate) mod selected;
pub(crate) mod trusted;

enum State {
    Startup,
    Held(Box<DynamicEvent>),
    AdmissionHeld(Box<trusted::AdmissionStop>),
    Running,
    Listening,
    Exiting,
    Terminal,
}

/// Kind of stable kernel identity held by a pidfd. Thread pins are acquired
/// before consuming unknown WNOWAIT identities, even if they later prove leaders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PinKind {
    Process,
    Thread,
}

pub(super) struct Owner {
    // Ptrace wait-domain ownership is tied to the original tracer thread.
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
    pub(super) pid: libc::pid_t,
    pub(super) initial_exec: Option<RegisterSnapshot>,
    lifecycle_options: Option<DynamicLifecycleOptions>,
    exec_policy: DynamicExecPolicy,
    lifecycle: Option<lifecycle::NativeLifecycle>,
    admission: Option<admission::AdmissionOwner>,
    session: u64,
    sequence: u64,
    state: State,
    cancel: Arc<AtomicBool>,
    closing: bool,
    // An observed stop may have been queued before INTERRUPT. After that first
    // stop is resumed, the next stop is necessarily newer and clears the kernel
    // pending request (Linux v7.1.3 ptrace_request/ptrace_stop). This is an upper
    // bound on possible deferred control, not an assertion about queue timing.
    interrupt_stops_remaining: u8,
    syscall_open: bool,
    owned: BTreeSet<libc::pid_t>,
    stopped: BTreeMap<libc::pid_t, i32>,
    handles: BTreeMap<libc::pid_t, OwnedFd>,
    pin_kinds: BTreeMap<libc::pid_t, PinKind>,
    reaped: Vec<libc::pid_t>,
    lost_wait: bool,
    missing_pin: bool,
    broker: Option<broker::Broker>,
    attached: bool,
    tracer_terminal: BTreeMap<libc::pid_t, i32>,
    #[cfg(test)]
    pub(super) fail_before_seize: bool,
    #[cfg(test)]
    pub(super) fail_before_ready: bool,
    #[cfg(test)]
    pub(super) die_before_ready: bool,
    #[cfg(test)]
    pub(super) abort_before_seize: bool,
    #[cfg(test)]
    deny_kill_for_test: bool,
    #[cfg(test)]
    deny_pin_for_test: bool,
}

pub(super) fn run(start: TracerStart) {
    let TracerStart {
        command,
        session,
        inherited_mask,
        lifecycle,
        exec,
        until,
        cancel,
        commands,
        ready,
        done,
    } = start;
    let mut owner = Owner::new(session, cancel);
    owner.lifecycle_options = lifecycle;
    owner.exec_policy = exec;
    let mut announced = false;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // NPTL may unblock its own reserved cancellation signal during thread
        // initialization. Ordinary application-handler signals were inherited
        // blocked; finish the exact kernel mask before touching the wait domain.
        launch::set_current_mask(u64::MAX)?;
        let initial = launch::start(&mut owner, &command, inherited_mask, until)?;
        ready
            .send(Ok(initial))
            .map_err(|_| LaunchError::Invalid("seized launch client disconnected"))?;
        announced = true;
        owner.serve(commands)
    }));
    let failure = match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some(LaunchError::Invalid(
            "dynamic tracer unwound; cleanup remains owned",
        )),
    };
    if !announced {
        let _ = ready.send(Err(
            failure.unwrap_or(LaunchError::Invalid("dynamic launch cancelled"))
        ));
    }
    let cleanup = owner.cleanup();
    let _ = done.send(cleanup);
}

impl Owner {
    fn new(session: u64, cancel: Arc<AtomicBool>) -> Self {
        Self {
            _thread: std::marker::PhantomData,
            pid: 0,
            initial_exec: None,
            lifecycle_options: None,
            exec_policy: DynamicExecPolicy::Refuse,
            lifecycle: None,
            admission: None,
            session,
            sequence: 0,
            state: State::Startup,
            cancel,
            closing: false,
            interrupt_stops_remaining: 0,
            syscall_open: true,
            owned: BTreeSet::new(),
            stopped: BTreeMap::new(),
            handles: BTreeMap::new(),
            pin_kinds: BTreeMap::new(),
            reaped: Vec::new(),
            lost_wait: false,
            missing_pin: false,
            broker: None,
            attached: false,
            tracer_terminal: BTreeMap::new(),
            #[cfg(test)]
            fail_before_seize: false,
            #[cfg(test)]
            fail_before_ready: false,
            #[cfg(test)]
            die_before_ready: false,
            #[cfg(test)]
            abort_before_seize: false,
            #[cfg(test)]
            deny_kill_for_test: false,
            #[cfg(test)]
            deny_pin_for_test: false,
        }
    }
    pub(super) fn spawn_broker(&mut self, bootstrap: launch::Bootstrap) -> Result<(), LaunchError> {
        self.broker = Some(broker::Broker::spawn(self.session, bootstrap)?);
        Ok(())
    }
    fn poll_broker(&mut self) -> Result<(), LaunchError> {
        let Some(broker) = &mut self.broker else {
            return Ok(());
        };
        let result = broker.poll();
        if let Some((pid, handle)) = broker.root.take() {
            if self.pid != 0 {
                return Err(LaunchError::Invalid("duplicate application identity"));
            }
            self.pid = pid;
            self.owned.insert(pid);
            self.handles.insert(pid, handle);
            self.pin_kinds.insert(pid, PinKind::Process);
        }
        // Before SEIZE, only the real parent can wait for A. This authentic
        // natural-parent receipt replaces no ptrace status and grants no new
        // numeric signalling authority.
        if !self.attached && self.pid > 0 && broker.physical.contains_key(&self.pid) {
            self.owned.remove(&self.pid);
            if !self.reaped.contains(&self.pid) {
                self.reaped.push(self.pid);
            }
        }
        result
    }
    pub(super) fn wait_broker_ready(&mut self, until: Instant) -> Result<(), LaunchError> {
        loop {
            self.time_left(until, "private reaper bootstrap")?;
            self.poll_broker()?;
            if self.pid > 0 {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    pub(super) fn seized(&mut self) -> Result<(), LaunchError> {
        // Establish ptrace numeric authority before the fallible acknowledgement.
        // R cannot reap A until it has received Seized or cleanup's Abort.
        self.attached = true;
        self.broker
            .as_mut()
            .ok_or(LaunchError::Invalid("missing private reaper"))?
            .acknowledge(true)
    }
    fn wait_physical(
        &mut self,
        tid: libc::pid_t,
        status: i32,
        until: Instant,
    ) -> Result<(), LaunchError> {
        loop {
            self.time_left(until, "physical application reap")?;
            self.poll_broker()?;
            let broker = self
                .broker
                .as_ref()
                .ok_or(LaunchError::Invalid("missing physical reaper"))?;
            if let Some(&physical_status) = broker.physical.get(&tid) {
                if status != physical_status {
                    return Err(LaunchError::Invalid(
                        "physical and ptrace terminal status differ",
                    ));
                }
                if self.handles.get(&tid).is_some_and(broker::hup) {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    #[cfg(test)]
    pub(super) fn kill_bootstrap_for_test(&self) -> Result<(), LaunchError> {
        let handle = self.handles.get(&self.pid).unwrap();
        // SAFETY: CLONE_PIDFD pinned this exact bootstrap before any fallible
        // operation. This private failure injection runs before PTRACE_SEIZE.
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                handle.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(system("private bootstrap kill"))
        }
    }
    pub(super) fn released(&mut self, tid: libc::pid_t) {
        self.stopped.remove(&tid);
    }
    pub(super) fn time_left(
        &self,
        until: Instant,
        operation: &'static str,
    ) -> Result<(), LaunchError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(LaunchError::Invalid("dynamic operation cancelled"));
        }
        if Instant::now() >= until {
            return Err(LaunchError::Timeout(operation));
        }
        Ok(())
    }
    /// WNOWAIT or an owned creation payload pins the numeric incarnation until
    /// a stable descriptor is acquired. ThreadClone always requests PIDFD_THREAD;
    /// legacy process profiles retain flags=0 first. No TGID read precedes it.
    pub(super) fn pin_task(&mut self, tid: libc::pid_t) -> Result<(), LaunchError> {
        if self.handles.contains_key(&tid) {
            return Ok(());
        }
        if self
            .lifecycle_options
            .is_some_and(|options| options.creation == DynamicCreationPolicy::ThreadClone)
        {
            return self.open_pin(tid, PinKind::Thread);
        }
        // Preserve the existing process-only profiles' kernel capability
        // envelope. A successful flags=0 open authenticates a process pin.
        // Linux returns ENOENT for a nonleader; this does not establish its
        // kind, but permits an explicit task-pin attempt while WNOWAIT/the
        // creation payload still preserves exact ownership. Only that second
        // successful syscall authenticates Thread. No unrelated errno retries.
        match self.open_pin(tid, PinKind::Process) {
            Err(LaunchError::System { source, .. })
                if source.raw_os_error() == Some(libc::ENOENT) =>
            {
                self.open_pin(tid, PinKind::Thread)
            }
            result => result,
        }
    }

    /// Only an authenticated process leader may be promoted to a process pin.
    /// Acquire the replacement before dropping its existing stable task pin.
    pub(super) fn pin_process(&mut self, tid: libc::pid_t) -> Result<(), LaunchError> {
        if self.pin_kinds.get(&tid) == Some(&PinKind::Process) {
            return Ok(());
        }
        self.open_pin(tid, PinKind::Process)
    }

    fn open_pin(&mut self, tid: libc::pid_t, kind: PinKind) -> Result<(), LaunchError> {
        #[cfg(test)]
        if self.deny_pin_for_test {
            return Err(io_error(
                "pidfd_open dynamic process",
                io::Error::from_raw_os_error(libc::EMFILE),
            ));
        }
        let flags = if kind == PinKind::Thread {
            libc::O_EXCL
        } else {
            0
        };
        // SAFETY: this exact incarnation is owned and unreaped. Linux
        // PIDFD_THREAD == O_EXCL. This syscall's successful result authenticates
        // the requested pin kind; errors never establish a task/process kind.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, flags) };
        if descriptor < 0 {
            return Err(system("pidfd_open dynamic process"));
        }
        // SAFETY: the syscall returned one newly owned descriptor. In a
        // promotion, the prior pin remains owned until this insertion succeeds.
        self.handles
            .insert(tid, unsafe { OwnedFd::from_raw_fd(descriptor as i32) });
        self.pin_kinds.insert(tid, kind);
        Ok(())
    }
    fn terminal(&mut self, tid: libc::pid_t, status: i32) {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            // Retire numeric signalling authority before any caller assertion.
            self.owned.remove(&tid);
            self.stopped.remove(&tid);
            self.reaped.push(tid);
            self.tracer_terminal.insert(tid, status);
        }
    }
    fn poll_raw(&mut self) -> Result<Option<(libc::pid_t, i32)>, LaunchError> {
        // WNOWAIT preserves identity until the atomic pidfd has been acquired.
        // A terminal newborn may be observed before its parent's creation event;
        // pinning after waitpid would race the real parent's physical reap.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let peek = unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
                &raw mut info,
                libc::WEXITED
                    | libc::WSTOPPED
                    | libc::WNOHANG
                    | libc::WNOWAIT
                    | libc::__WALL
                    | libc::__WNOTHREAD,
            )
        };
        if peek < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(None)
            } else {
                Err(io_error("wait dynamic tracer domain", error))
            };
        }
        let tid = unsafe { info.si_pid() };
        if tid == 0 {
            return Ok(None);
        }
        let helper = self.broker.as_ref().is_some_and(|broker| broker.pid == tid);
        if !helper {
            // WNOWAIT itself grants exact unreaped numeric authority. Register
            // it before pidfd allocation, which may fail (for example EMFILE).
            self.owned.insert(tid);
            if let Err(error) = self.pin_task(tid) {
                if !self.closing {
                    return Err(error);
                }
                // Cleanup still consumes/kills/drains this owned incarnation,
                // but cannot claim the missing independent HUP witness.
                self.lost_wait = true;
                self.missing_pin = true;
            }
        }
        let mut status = 0;
        // SAFETY: exclusively owned thread wait domain; the exact WNOWAIT
        // identity above remains held. The helper is never an application task.
        let consumed = unsafe {
            libc::waitpid(
                tid,
                &raw mut status,
                libc::WNOHANG | libc::__WALL | libc::__WNOTHREAD,
            )
        };
        if consumed != tid {
            return Err(system("consume pinned dynamic wait"));
        }
        if helper {
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                self.broker.as_mut().unwrap().terminal(status);
                self.poll_broker()?;
            } else {
                return Err(LaunchError::Invalid("private reaper unexpectedly stopped"));
            }
            return Ok(None);
        }
        if libc::WIFSTOPPED(status) {
            self.owned.insert(tid);
            self.stopped.insert(tid, status);
        }
        self.terminal(tid, status);
        Ok(Some((tid, status)))
    }
    pub(super) fn wait_raw(
        &mut self,
        until: Instant,
        operation: &'static str,
    ) -> Result<(libc::pid_t, i32), LaunchError> {
        loop {
            self.time_left(until, operation)?;
            self.poll_broker()?;
            if let Some(event) = self.poll_raw()? {
                return Ok(event);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    pub(super) fn hold(&mut self, kind: DynamicEventKind) -> Result<DynamicEvent, LaunchError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(LaunchError::Invalid("dynamic stop identity exhausted"))?;
        let event = DynamicEvent {
            tid: self.pid,
            task: None,
            kind,
            stop: Some(DynamicStop {
                session: self.session,
                sequence: self.sequence,
                tid: self.pid,
                task: None,
            }),
        };
        self.state = State::Held(Box::new(event.clone()));
        Ok(event)
    }
    fn require_stop(&self, token: &DynamicStop) -> Result<&DynamicEvent, LaunchError> {
        match &self.state {
            State::Held(event) if event.stop.as_ref() == Some(token) => Ok(event),
            _ => Err(LaunchError::Invalid("dynamic stop token is not current")),
        }
    }
    fn serve(&mut self, commands: Receiver<Command>) -> Result<(), LaunchError> {
        while !self.cancel.load(Ordering::Acquire) && !self.closing {
            if self
                .admission
                .as_ref()
                .is_some_and(|admission| admission.provider_expired(Instant::now()))
            {
                self.closing = true;
                self.cancel.store(true, Ordering::Release);
                break;
            }
            let command = match commands.recv_timeout(Duration::from_millis(1)) {
                Ok(command) => command,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let response = self.execute(command.request, command.until);
            if matches!(&response, Err(LaunchError::Timeout(_))) {
                self.closing = true;
            }
            if self.closing {
                self.cancel.store(true, Ordering::Release);
            }
            if command.reply.send(response).is_err() {
                self.closing = true;
            }
        }
        Ok(())
    }
    fn execute(&mut self, request: Request, until: Instant) -> Result<Response, LaunchError> {
        self.time_left(until, "dynamic command")?;
        let request = match request {
            Request::Admission(request) => {
                let result = self.execute_admission(*request, until);
                if result.is_err() {
                    self.closing = true;
                    self.cancel.store(true, Ordering::Release);
                }
                return Ok(Response::Admission(Box::new(result)));
            }
            request => request,
        };
        if self.admission.is_some() {
            return Err(LaunchError::Invalid(
                "raw dynamic requests cannot bypass admission ownership",
            ));
        }
        if let Some(mut lifecycle) = self.lifecycle.take() {
            // A panic still leaves all native wait/pidfd ownership in Owner;
            // the catch-unwind path proceeds directly to physical cleanup.
            let result = lifecycle.execute(self, request, until);
            self.lifecycle = Some(lifecycle);
            return result;
        }
        match request {
            Request::Admission(_) => Err(LaunchError::Invalid(
                "admission request escaped its owner dispatcher",
            )),
            Request::LifecycleSnapshot => Ok(Response::LifecycleSnapshot(None)),
            Request::InterruptTask(_) => {
                Err(LaunchError::Invalid("dynamic lifecycle is not initialized"))
            }
            #[cfg(test)]
            Request::PanicForCleanupTest => panic!("injected dynamic tracer unwind"),
            Request::Resume(token, action) => self.resume(&token, action).map(|()| Response::Unit),
            Request::Wait => {
                if !matches!(self.state, State::Running | State::Listening) {
                    return Err(LaunchError::Invalid(
                        "dynamic wait requires a released task",
                    ));
                }
                self.wait_event(until).map(Response::Event)
            }
            Request::Interrupt => {
                if !matches!(self.state, State::Running) {
                    return Err(LaunchError::Invalid(
                        "dynamic interruption requires running execution",
                    ));
                }
                if let Err(error) = ptrace(libc::PTRACE_INTERRUPT, self.pid, 0, 0) {
                    self.closing = true;
                    return Err(error);
                }
                self.interrupt_stops_remaining = 2;
                self.wait_event(until).map(Response::Event)
            }
            Request::Registers(token) => {
                self.require_stop(&token)?;
                read_registers(self.pid).map(Response::Registers)
            }
            Request::Xstate(token) => {
                self.require_stop(&token)?;
                xstate(self.pid).map(Response::Bytes)
            }
            Request::Memory(token, address, len) => {
                self.require_stop(&token)?;
                read_memory(self.pid, address, len).map(Response::Bytes)
            }
            Request::Mask(token) => {
                self.require_stop(&token)?;
                launch::task_mask(self.pid).map(Response::Mask)
            }
        }
    }
    fn resume(&mut self, token: &DynamicStop, action: DynamicResume) -> Result<(), LaunchError> {
        let event = self.require_stop(token)?;
        let (request, signal) = match (&event.kind, action) {
            (DynamicEventKind::SignalDelivery(info), DynamicResume::DeliverOriginal) => {
                (libc::PTRACE_SYSCALL, info.signal())
            }
            (DynamicEventKind::GroupStop { .. }, DynamicResume::Listen) => (libc::PTRACE_LISTEN, 0),
            (
                DynamicEventKind::Exec { .. }
                | DynamicEventKind::SyscallEntry { .. }
                | DynamicEventKind::SyscallExit { .. }
                | DynamicEventKind::Interrupted
                | DynamicEventKind::GroupContinued,
                DynamicResume::Continue,
            ) => (libc::PTRACE_SYSCALL, 0),
            _ => {
                return Err(LaunchError::Invalid(
                    "dynamic stop requires its exact signal or control disposition",
                ));
            }
        };
        if let DynamicEventKind::SyscallEntry { number, .. } = &event.kind {
            if matches!(
                *number as libc::c_long,
                libc::SYS_clone
                    | libc::SYS_clone3
                    | libc::SYS_fork
                    | libc::SYS_vfork
                    | libc::SYS_execve
                    | libc::SYS_execveat
            ) {
                self.closing = true;
                return Err(LaunchError::Invalid(
                    "dynamic creation and later exec are not yet qualified",
                ));
            }
        }
        if let Err(error) = ptrace(request, self.pid, 0, signal as usize) {
            self.closing = true;
            return Err(error);
        }
        self.released(self.pid);
        self.state = if request == libc::PTRACE_LISTEN {
            State::Listening
        } else {
            State::Running
        };
        Ok(())
    }
    fn wait_event(&mut self, until: Instant) -> Result<DynamicEvent, LaunchError> {
        let result = (|| {
            loop {
                let (tid, status) = self.wait_raw(until, "dynamic native event")?;
                if tid != self.pid {
                    return Err(LaunchError::Invalid(
                        "unexpected dynamic child is owned for cleanup",
                    ));
                }
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.wait_physical(tid, status, until)?;
                    self.state = State::Terminal;
                    return Ok(DynamicEvent {
                        tid,
                        task: None,
                        stop: None,
                        kind: if libc::WIFEXITED(status) {
                            DynamicEventKind::Exited {
                                code: libc::WEXITSTATUS(status),
                            }
                        } else {
                            DynamicEventKind::Signaled {
                                signal: libc::WTERMSIG(status),
                            }
                        },
                    });
                }
                if !libc::WIFSTOPPED(status) {
                    return Err(LaunchError::Invalid("invalid dynamic wait status"));
                }
                let possible_interrupt = self.interrupt_stops_remaining != 0;
                self.interrupt_stops_remaining = self.interrupt_stops_remaining.saturating_sub(1);
                let signal = libc::WSTOPSIG(status);
                let event = status >> 16;
                if event == libc::PTRACE_EVENT_EXIT {
                    // Pre-exit is not a reaping receipt. No original instruction
                    // remains to run; continue to the actual terminal wait.
                    ptrace(libc::PTRACE_CONT, tid, 0, 0)?;
                    self.released(tid);
                    continue;
                }
                if event == libc::PTRACE_EVENT_STOP {
                    if matches!(
                        signal,
                        libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
                    ) {
                        return self.hold(DynamicEventKind::GroupStop { signal });
                    }
                    if signal == libc::SIGTRAP {
                        if matches!(self.state, State::Listening) {
                            // Linux v7.1.3 do_jobctl_trap emits SIGTRAP only
                            // after group_stop_count and SIGNAL_STOP_STOPPED
                            // clear. Even a deferred INTERRUPT cannot bypass
                            // a live job-control stop: it retains the stop signal.
                            return self.hold(DynamicEventKind::GroupContinued);
                        }
                        if possible_interrupt {
                            return self.hold(DynamicEventKind::Interrupted);
                        }
                    }
                    return Err(LaunchError::Invalid("unowned dynamic control stop"));
                }
                if event != 0 {
                    self.discover_event_child(tid, status);
                    return Err(LaunchError::Invalid("unexpected dynamic lifecycle event"));
                }
                if signal == (libc::SIGTRAP | 0x80) {
                    return self.syscall_event();
                }
                let mut raw = [0_u8; 128];
                ptrace(libc::PTRACE_GETSIGINFO, tid, 0, raw.as_mut_ptr() as usize)?;
                let info = DynamicSignalInfo { raw };
                if info.signal() != signal {
                    return Err(LaunchError::Invalid(
                        "dynamic siginfo disagrees with wait status",
                    ));
                }
                read_registers(tid)?;
                return self.hold(DynamicEventKind::SignalDelivery(info));
            }
        })();
        if result.is_err() {
            self.closing = true;
        }
        result
    }
    fn syscall_event(&mut self) -> Result<DynamicEvent, LaunchError> {
        let info = syscall_info(self.pid)?;
        let registers = read_registers(self.pid)?;
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
                // SAFETY: GET_SYSCALL_INFO authenticated the ENTRY variant.
                let entry = unsafe { info.u.entry };
                // Linux dispatch uses a signed 32-bit syscall number. Refuse
                // upper-word aliases before they can bypass native lifecycle
                // checks (and refuse the distinct x32 ABI explicitly).
                if self.syscall_open
                    || entry.nr > i32::MAX as u64
                    || entry.nr & 0x4000_0000 != 0
                    || entry.nr != registers.orig_rax
                    || entry.args != arguments(&registers)
                {
                    return Err(LaunchError::Invalid(
                        "dynamic syscall entry is out of order or non-native",
                    ));
                }
                self.syscall_open = true;
                self.hold(DynamicEventKind::SyscallEntry {
                    number: entry.nr,
                    arguments: entry.args,
                })
            }
            libc::PTRACE_SYSCALL_INFO_EXIT => {
                // SAFETY: GET_SYSCALL_INFO authenticated the EXIT variant.
                let exit = unsafe { info.u.exit };
                if !self.syscall_open || registers.rax as i64 != exit.sval {
                    return Err(LaunchError::Invalid(
                        "dynamic syscall exit is out of order or changed",
                    ));
                }
                let initial_exec_exit = self.initial_exec.is_some();
                if let Some(mut expected) = self.initial_exec.take() {
                    expected.rax = 0;
                    if registers != expected || exit.sval != 0 || exit.is_error != 0 {
                        return Err(LaunchError::Invalid(
                            "initial dynamic exec return changed state",
                        ));
                    }
                }
                self.syscall_open = false;
                if let Some(options) = self.lifecycle_options {
                    if !initial_exec_exit {
                        return Err(LaunchError::Invalid(
                            "lifecycle registry lacks initial exec-exit evidence",
                        ));
                    }
                    let (lifecycle, event) = lifecycle::NativeLifecycle::new(
                        self.session,
                        self.pid,
                        registers,
                        options,
                        self.exec_policy,
                    )?;
                    self.lifecycle = Some(lifecycle);
                    return Ok(event);
                }
                self.hold(DynamicEventKind::SyscallExit {
                    result: exit.sval,
                    is_error: exit.is_error != 0,
                })
            }
            _ => Err(LaunchError::Invalid("unsupported dynamic syscall stop")),
        }
    }
    fn discover_event_child(&mut self, tid: libc::pid_t, status: i32) {
        if !matches!(
            status >> 16,
            libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE
        ) {
            return;
        }
        let mut child = 0_u64;
        if ptrace(libc::PTRACE_GETEVENTMSG, tid, 0, (&raw mut child) as usize).is_ok() {
            if let Ok(child) = libc::pid_t::try_from(child) {
                // Child terminal and parent creation statuses may be consumed
                // in either order. A late payload must not recreate numeric
                // signalling authority after the child has already been reaped.
                // Default policy refuses creation; the opt-in policy has at
                // most two lifetime records, including retired tasks. Cleanup
                // never resumes original code, so a retired number cannot
                // legitimately gain a second creation incarnation here.
                if child > 0 && !self.reaped.contains(&child) {
                    self.owned.insert(child);
                    let _ = self.pin_task(child);
                }
            }
        }
    }
    fn kill_owned(&self) -> BTreeSet<libc::pid_t> {
        let mut confirmed = BTreeSet::new();
        #[cfg(test)]
        if self.deny_kill_for_test {
            return confirmed;
        }
        for &tid in &self.owned {
            if let Some(handle) = self.handles.get(&tid) {
                // SAFETY: this descriptor pins this exact owned process.
                if unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        handle.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                } == 0
                {
                    confirmed.insert(tid);
                    continue;
                }
            }
            // SAFETY: only this thread consumes these terminal waits. Numeric
            // authority is removed immediately when a terminal status is seen.
            if self.attached && unsafe { libc::syscall(libc::SYS_tkill, tid, libc::SIGKILL) } == 0 {
                confirmed.insert(tid);
            }
        }
        confirmed
    }
    fn release_killed_stops(&mut self, killed: &BTreeSet<libc::pid_t>) {
        self.stopped.retain(|&tid, status| {
            // A pre-exit event cannot return to application instructions. Every
            // other stop needs positive SIGKILL success for this exact task;
            // ESRCH, permission failure or any uncertain result is not evidence.
            if *status >> 16 != libc::PTRACE_EVENT_EXIT && !killed.contains(&tid) {
                return true;
            }
            ptrace(libc::PTRACE_CONT, tid, 0, 0).is_err()
        });
    }
    fn cleanup(&mut self) -> Result<DynamicCleanup, LaunchError> {
        self.closing = true;
        if self.broker.is_none() {
            return Ok(DynamicCleanup { reaped: Vec::new() });
        }
        loop {
            // Receive Ready before Abort: R keeps the root unreaped until the
            // transferred pidfd has been authenticated, even during cancellation.
            if self.poll_broker().is_err() {
                self.lost_wait = true;
            }
            if self.pid > 0 || self.lost_wait {
                self.broker.as_mut().unwrap().cancel();
            }
            let mut domain_empty = false;
            loop {
                match self.poll_raw() {
                    Ok(Some((tid, status))) => {
                        if libc::WIFSTOPPED(status) {
                            self.discover_event_child(tid, status);
                        }
                    }
                    Ok(None) => break,
                    Err(LaunchError::System { source, .. })
                        if source.raw_os_error() == Some(libc::ECHILD) =>
                    {
                        domain_empty = true;
                        break;
                    }
                    Err(_) => {
                        self.lost_wait = true;
                        break;
                    }
                }
            }
            let killed = self.kill_owned();
            self.release_killed_stops(&killed);
            let broker = self.broker.as_ref().unwrap();
            // No cleanup result, including a failed proof, retires an original
            // retained incarnation before its independent physical HUP witness.
            if domain_empty && self.handles.values().all(broker::hup) {
                match broker.finished() {
                    Ok(true) => {
                        let statuses = broker.physical.iter().all(|(tid, status)| {
                            self.tracer_terminal
                                .get(tid)
                                .map_or(!self.attached && *tid == self.pid, |observed| {
                                    observed == status
                                })
                        });
                        return if self.lost_wait || !self.owned.is_empty() || !statuses {
                            Err(LaunchError::Invalid(
                                "dynamic physical cleanup ownership was lost",
                            ))
                        } else {
                            Ok(DynamicCleanup {
                                reaped: std::mem::take(&mut self.reaped),
                            })
                        };
                    }
                    Err(error) => {
                        // A dead helper can reparent zombies outside our local
                        // natural-parent domain. Failure does not release the
                        // original owner while any retained incarnation exists.
                        // Without an authenticated root, absence of Ready says
                        // nothing about whether R already cloned A. Likewise a
                        // lost later pin needs an authenticated helper drain.
                        if broker.done || (self.pid > 0 && !self.missing_pin) {
                            return Err(error);
                        }
                    }
                    Ok(false) => {}
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
