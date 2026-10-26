//! Seized native ownership, independent of the fixed-membership page gates.
//!
//! This first owner runs original code without instrumentation. It authenticates
//! kernel stops, preserves signal deliveries and actively interrupts execution.
//! It is not an admission gate or a quiescence lease. Application creation and
//! subsequent exec syscalls refuse by default. An explicit bounded lifecycle
//! option qualifies one successful fork or one exact 0x10f00 thread clone with
//! at most two lifetime native task records, without publication authority.
//! Separate composed options permit one native leader exec. Other clone/vfork
//! profiles and native failed-exec continuation remain unqualified.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

mod admission;
pub use admission::*;
use admission::{AdmissionReply, AdmissionRequest};

mod broker;
mod launch;
mod owner;
pub use owner::kernel_journal::{
    KernelAttemptId, KernelAttemptSnapshot, KernelCaptureStatus, KernelCapturedState,
    KernelFailureKind, KernelJournalFact, KernelJournalFailure, KernelJournalStage, KernelPinKind,
    KernelProgressReader, KernelProgressSnapshot, KernelReleasePhase, KernelStateRecord,
    KernelStateSlot, KernelStopIdentity, KernelSyscallInfo, KernelWriterStatus,
};

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
const KERNEL_SIGSET_BYTES: usize = 8;
const _: () = assert!(std::mem::size_of::<libc::siginfo_t>() == 128);
const OPTIONS: usize = (libc::PTRACE_O_TRACEFORK
    | libc::PTRACE_O_TRACEVFORK
    | libc::PTRACE_O_TRACEVFORKDONE
    | libc::PTRACE_O_TRACECLONE
    | libc::PTRACE_O_TRACEEXEC
    | libc::PTRACE_O_TRACEEXIT
    | libc::PTRACE_O_TRACESYSGOOD
    | libc::PTRACE_O_EXITKILL) as usize;

/// Unforgeable ownership of one particular native stop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicStop {
    session: u64,
    sequence: u64,
    tid: libc::pid_t,
    task: Option<crate::lifecycle::TaskId>,
}

/// Explicit native creation policy. Later policies must receive independent
/// kernel-stop, identity, cleanup and state qualification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DynamicCreationPolicy {
    /// Every creation syscall refuses before kernel entry.
    #[default]
    Refuse,
    /// Native SYS_fork only; clone, clone3, vfork and later exec still refuse.
    Fork,
    /// One native SYS_clone with flags 0x10f00, from a singleton leader.
    /// Shares the process/mm; TLS and TID outputs are excluded. Requires an
    /// authenticated zero per-task shadow-stack/WRSS status or a controlled
    /// native-ABI absence certificate, and exact inherited XSTATE before either
    /// task resumes. This is not pthread qualification.
    ThreadClone,
}

/// Bounded native lifecycle options, independent of page admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicLifecycleOptions {
    /// Checked creation mechanism.
    pub creation: DynamicCreationPolicy,
    /// Lifetime task-record bound, including retired tasks. This increment
    /// accepts only one or two records; retirement never replenishes the budget.
    pub max_tasks: usize,
}
impl Default for DynamicLifecycleOptions {
    fn default() -> Self {
        Self {
            creation: DynamicCreationPolicy::Refuse,
            max_tasks: 1,
        }
    }
}
impl DynamicLifecycleOptions {
    /// At most one successful fork, with distinct parent/child task and mm identities.
    pub const fn fork_only() -> Self {
        Self {
            creation: DynamicCreationPolicy::Fork,
            max_tasks: 2,
        }
    }
    /// At most one successful thread clone: two native task records, one process/mm.
    pub const fn thread_only() -> Self {
        Self {
            creation: DynamicCreationPolicy::ThreadClone,
            max_tasks: 2,
        }
    }
    fn validate(self) -> Result<Self, LaunchError> {
        if !(1..=2).contains(&self.max_tasks) {
            return Err(LaunchError::Invalid(
                "dynamic lifecycle task bound must be one or two",
            ));
        }
        Ok(self)
    }
}

/// Explicit later native exec policy, independent of creation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DynamicExecPolicy {
    /// Later exec refuses before kernel entry.
    #[default]
    Refuse,
    /// At most one successful native SYS_execve per session. Failed exec
    /// outcomes close the owner because errno alone cannot prove old-mm survival.
    ExecveOnce,
}

/// Composed native ownership options. No option grants page admission.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DynamicSessionOptions {
    /// Creation policy and lifetime native-task budget. For the existing Fork
    /// and Refuse policies each native task is a distinct physical process;
    /// those physical-process limits retain their original meaning. ThreadClone
    /// permits at most two native tasks sharing one physical process/mm.
    /// This composed API separately reserves one extra logical task/mm record
    /// for ExecveOnce: two native tasks may retain three logical TaskIds.
    /// Retirement never refunds either bound. `launch_with_lifecycle` still
    /// has no exec reservation and keeps its total task-record bound.
    pub lifecycle: DynamicLifecycleOptions,
    /// Later image-replacement policy.
    pub exec: DynamicExecPolicy,
}

/// Non-reused task/process/mm identity from the native owner's registry.
/// This is diagnostic bookkeeping, never a publication or exclusion capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicTask {
    /// One task incarnation.
    pub task: crate::lifecycle::TaskId,
    /// Thread-group lifetime.
    pub process: crate::lifecycle::ProcessId,
    /// Address-space incarnation; fork creates a distinct identity.
    pub address_space: crate::lifecycle::AddressSpaceId,
    /// Registry generation only. This uninstrumented owner has not connected
    /// mmap/mprotect/alias invalidation; zero does not prove mappings unchanged
    /// and grants no executable-admission or publication authority.
    pub generation: u64,
}

/// Full kernel signal information, retained without guessing its pending queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSignalInfo {
    raw: [u8; 128],
}

impl DynamicSignalInfo {
    fn native(&self) -> libc::siginfo_t {
        // SAFETY: GETSIGINFO filled a zero-initialized, exact-size native image.
        // The byte array need not have the native type's alignment.
        unsafe { std::ptr::read_unaligned(self.raw.as_ptr().cast()) }
    }

    /// Native signal number.
    pub fn signal(&self) -> i32 {
        self.native().si_signo
    }
    /// Exact kernel cause code.
    pub fn code(&self) -> i32 {
        self.native().si_code
    }
    /// Exact kernel errno field.
    pub fn errno(&self) -> i32 {
        self.native().si_errno
    }
    /// Sender identity for signal variants which actually carry that field.
    pub fn sender_pid(&self) -> Option<i32> {
        let info = self.native();
        if matches!(
            info.si_code,
            libc::SI_USER | libc::SI_QUEUE | libc::SI_TKILL
        ) || (info.si_signo == libc::SIGCHLD
            && matches!(
                info.si_code,
                libc::CLD_EXITED
                    | libc::CLD_KILLED
                    | libc::CLD_DUMPED
                    | libc::CLD_TRAPPED
                    | libc::CLD_STOPPED
                    | libc::CLD_CONTINUED
            ))
        {
            // SAFETY: these signal variants carry the sender/child identity.
            Some(unsafe { info.si_pid() })
        } else {
            None
        }
    }
    /// Sender UID for signal variants which actually carry that field.
    pub fn sender_uid(&self) -> Option<u32> {
        self.sender_pid()?;
        // SAFETY: the same variants also carry the UID.
        Some(unsafe { self.native().si_uid() })
    }
    /// Exact queued signal value; absent for variants with a different union.
    pub fn value(&self) -> Option<u64> {
        (self.code() == libc::SI_QUEUE).then(|| {
            // SAFETY: SI_QUEUE identifies the sigval member.
            unsafe { self.native().si_value().sival_ptr as u64 }
        })
    }
    /// Fault address only for synchronous fault/trap variants.
    pub fn fault_address(&self) -> Option<u64> {
        let info = self.native();
        let address_variant = match info.si_signo {
            libc::SIGSEGV => matches!(info.si_code, 1..=4),
            libc::SIGBUS => matches!(info.si_code, 1..=5),
            libc::SIGILL => matches!(info.si_code, 1..=9),
            libc::SIGFPE => matches!(info.si_code, 1..=8),
            libc::SIGTRAP => matches!(info.si_code, 1..=4),
            _ => false,
        };
        address_variant.then(|| {
            // SAFETY: these explicit Linux codes carry the fault-address union.
            // SI_KERNEL and unknown future codes remain raw-only.
            unsafe { info.si_addr() as u64 }
        })
    }
    /// Complete initialized kernel image, including fields not interpreted here.
    pub fn raw_bytes(&self) -> &[u8; 128] {
        &self.raw
    }
}

/// The authenticated kernel event; phases are never relabelled as user entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DynamicEventKind {
    /// Actual PTRACE_EVENT_EXEC, before the exec syscall has returned.
    Exec {
        /// Checked ELF and auxiliary-vector relationships.
        evidence: EntryEvidence,
    },
    /// Actual native syscall entry, before kernel execution.
    SyscallEntry {
        /// Native syscall number.
        number: u64,
        /// Arguments in native ABI order.
        arguments: [u64; 6],
    },
    /// Actual syscall-exit stop, not a materialized first-user state.
    SyscallExit {
        /// Raw kernel result (including restart values).
        result: i64,
        /// GET_SYSCALL_INFO errno classification.
        is_error: bool,
    },
    /// Actual later EXEC event. The event's task/token belong to the new
    /// incarnation; physical PID, pidfd, real parent and ProcessId are retained.
    /// Syscall EXIT and first user execution have not yet occurred.
    ExecReplaced {
        /// Superseded logical task, never a physical terminal receipt.
        previous: DynamicTask,
        /// Authenticated new executable/interpreter entry.
        evidence: EntryEvidence,
    },
    /// Application signal delivery; the signal has not been suppressed.
    SignalDelivery(DynamicSignalInfo),
    /// Actual EVENT_STOP/SIGTRAP while an interruption may still be pending.
    /// A previously queued control stop can race the interruption request.
    Interrupted,
    /// Kernel job-control group stop, requiring LISTEN to retain its semantics.
    GroupStop {
        /// Native stopping signal.
        signal: i32,
    },
    /// LISTEN ended at EVENT_STOP/SIGTRAP: the kernel group stop has ended.
    /// This does not infer the provenance of a pending signal or control request.
    GroupContinued,
    /// Authenticated parent FORK/CLONE event and registered stopped child. Neither
    /// task runs automatically; the child's Newborn event is queued separately.
    Created {
        /// Stopped child identity; its automatic stop has already authenticated.
        child: DynamicTask,
    },
    /// Original automatic stop after the child has passed creation syscall-exit
    /// tracing, but before it may return to user code. Resuming it does not
    /// produce a child creation syscall-exit event. This is not first-user state.
    Newborn {
        /// Creator's retained task identity.
        parent: DynamicTask,
    },
    /// ThreadClone profile's real kernel pre-exit event, internally continued.
    /// There is no stop token and no application continuation. The task remains
    /// owned as Exiting until its actual terminal wait; a leader can remain in
    /// this phase while a held worker still needs to run. This is not a terminal
    /// or physical-reaping receipt, and it does not promise the final status.
    TaskExiting {
        /// Status observed at PTRACE_EVENT_EXIT. A later group exit may differ.
        status: crate::lifecycle::ExitStatus,
    },
    /// Opt-in lifecycle task terminal observed by the tracer. This is NOT a
    /// physical reaping receipt: a stopped real parent may still need wait4.
    /// The original pidfd remains retained until final cleanup proves removal.
    TaskTerminal {
        /// Actual kernel exit or terminating-signal status.
        status: crate::lifecycle::ExitStatus,
    },
    /// Consumed terminal wait status with matching real-parent reap and pidfd HUP.
    Exited {
        /// Native exit status.
        code: i32,
    },
    /// Consumed terminal signal status with matching real-parent reap and pidfd HUP.
    Signaled {
        /// Native terminating signal.
        signal: i32,
    },
}

/// One owned stop or terminal event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicEvent {
    /// Numeric task identity for diagnostics, not authority for external waits.
    pub tid: libc::pid_t,
    /// Opt-in registry identity; absent before initial exec syscall exit and
    /// throughout the legacy default mode.
    pub task: Option<DynamicTask>,
    /// Exact event classification.
    pub kind: DynamicEventKind,
    stop: Option<DynamicStop>,
}

impl DynamicEvent {
    /// Token for a current stop. Pre-exit notifications and terminal events
    /// have no token and cannot be resumed or inspected through this API.
    pub fn stop_token(&self) -> Option<&DynamicStop> {
        self.stop.as_ref()
    }
}

/// Explicit disposition of an authenticated stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicResume {
    /// Continue under PTRACE_SYSCALL from a normal or control stop.
    Continue,
    /// Deliver the exact original signal from its original delivery stop.
    DeliverOriginal,
    /// Preserve an actual job-control stop using PTRACE_LISTEN.
    Listen,
}

/// Completed native cleanup: all tracer terminals, the real-ancestor reaper's
/// ECHILD receipt, retained application pidfds at HUP, and the reaper's own
/// terminal wait and HUP. Tracer ECHILD or pidfd POLLIN alone do not suffice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicCleanup {
    /// Application terminal identities, including unexpected attached children.
    /// The private real-parent helper is physically reaped but is not in this list.
    pub reaped: Vec<libc::pid_t>,
}

enum Request {
    Admission(Box<AdmissionRequest>),
    Wait,
    Interrupt,
    InterruptTask(crate::lifecycle::TaskId),
    LifecycleSnapshot,
    Resume(DynamicStop, DynamicResume),
    Registers(DynamicStop),
    Xstate(DynamicStop),
    Memory(DynamicStop, u64, usize),
    Mask(DynamicStop),
    #[cfg(test)]
    PanicForCleanupTest,
}
enum Response {
    Admission(Box<Result<AdmissionReply, crate::gate::GateError>>),
    Unit,
    Event(DynamicEvent),
    Registers(RegisterSnapshot),
    Bytes(Vec<u8>),
    Mask(u64),
    LifecycleSnapshot(Option<crate::lifecycle::RegistrySnapshot>),
}
struct Command {
    request: Request,
    until: Instant,
    reply: Sender<Result<Response, LaunchError>>,
}
struct Ready {
    pid: libc::pid_t,
    event: DynamicEvent,
}
struct TracerStart {
    command: LaunchCommand,
    session: u64,
    inherited_mask: u64,
    lifecycle: Option<DynamicLifecycleOptions>,
    exec: DynamicExecPolicy,
    until: Instant,
    cancel: Arc<AtomicBool>,
    commands: Receiver<Command>,
    ready: Sender<Result<Ready, LaunchError>>,
    done: Sender<Result<DynamicCleanup, LaunchError>>,
}

/// A dedicated native tracer with bounded client waits and nonblocking cancel.
///
/// All ptrace operations and ptrace waits run on its private tracer thread.
/// Natural-parent waits run in its private raw-syscall reaper process. Neither
/// invokes supplied client callbacks. The tracer retains cleanup coordination
/// after a client timeout; its exclusive wait domain is never transferred.
/// External tracing/reaping of these children is unsupported. No method grants
/// executable-page admission or a core publication lease.
/// The tracer inherits blocked application-handler signals across thread
/// creation, then reapplies the full raw mask before bootstrap because NPTL may
/// unblock its private cancellation signal during startup. Embedding signal
/// handlers remain blocked. The exclusive wait-domain contract also prohibits
/// global hooks or custom allocators from creating or reaping children on the
/// tracer thread; it does not assert that arbitrary host code cannot run there.
/// A private raw-syscall reaper is the application's real parent, so its PPID
/// differs from a direct launch by the embedding host. The helper alone becomes
/// a subreaper; the host's subreaper setting is unchanged. Both helper and app
/// start as signal-zero clone children with atomic pidfds. The app stays
/// unreaped until the tracer acknowledges SEIZE or abandons attachment. Ptrace
/// terminal status and the real parent's physical reap are recorded separately;
/// cleanup retains the helper until its descendants and the helper are gone.
/// Unexpected helper death destroys local natural-parent reaping authority.
/// The tracer then retains original application pidfds until they reach HUP and
/// returns a failed proof, never a complete cleanup receipt. If the root was
/// never authenticated or a later task pin was lost, that proof cannot be
/// completed without an authenticated helper drain; bounded client waits may
/// time out while ownership remains in the
/// background. The controller does not protect the helper from arbitrary
/// application or external signals and is not a process-isolation sandbox.
pub struct DynamicSession {
    pid: libc::pid_t,
    initial: DynamicEvent,
    commands: Sender<Command>,
    cancel: Arc<AtomicBool>,
    done: Receiver<Result<DynamicCleanup, LaunchError>>,
    operation_timeout: Duration,
}

fn command_deadlines(
    event_timeout: Duration,
    response_timeout: Duration,
) -> Result<(Instant, Instant), LaunchError> {
    let start = Instant::now();
    if event_timeout.is_zero()
        || event_timeout > MAX_LAUNCH_TIMEOUT
        || response_timeout.is_zero()
        || response_timeout > MAX_LAUNCH_TIMEOUT
    {
        return Err(LaunchError::Invalid(
            "operation timeout must be in (0, 30 seconds]",
        ));
    }
    if response_timeout < event_timeout {
        return Err(LaunchError::Invalid(
            "response timeout must not precede event timeout",
        ));
    }
    let until = start
        .checked_add(event_timeout)
        .ok_or(LaunchError::Invalid("dynamic event deadline overflow"))?;
    let response_until = start
        .checked_add(response_timeout)
        .ok_or(LaunchError::Invalid("dynamic response deadline overflow"))?;
    Ok((until, response_until))
}

impl DynamicSession {
    /// Launches a seized native ELF and stops at its actual exec event.
    /// A failed or timed-out launch can leave cleanup running on its dedicated
    /// tracer; returning an error does not assert synchronous terminal reaping.
    pub fn launch(command: &LaunchCommand, timeout: Duration) -> Result<Self, LaunchError> {
        Self::launch_options(command, timeout, None, DynamicExecPolicy::Refuse)
    }

    /// Opts into bounded native lifecycle ownership. The first event remains
    /// the original exec event; task/mm registry identities begin only at its
    /// authenticated syscall EXIT, not at an invented first-user transition.
    /// Fork requires TF clear at native syscall entry and the same PID namespace
    /// (including pid_for_children) as the tracer. It has a lifetime maximum of
    /// two task records; failed attempts do not create or recycle task records.
    /// ThreadClone instead permits exactly flags 0x10f00, a nonzero child stack
    /// with 128 readable/writable bytes below it, and zero TLS/TID arguments.
    /// It requires TF clear, a singleton leader in the tracer's PID namespace,
    /// PIDFD_THREAD support, and either an exact zero shadow-stack/WRSS status
    /// or the controlled native-ABI absence certificate. An unavailable
    /// interface alone is insufficient; CPU feature inference is unused.
    /// Exact parent/child XSTATE must agree before either original task resumes;
    /// unsupported inheritance (including dynamic state) closes the session.
    /// No other clone, exec, vfork, mapping invalidation or publication is qualified.
    /// Signal delivery retains full siginfo and an Unknown queue obligation;
    /// no queue provenance or signal-entry admission is inferred.
    pub fn launch_with_lifecycle(
        command: &LaunchCommand,
        options: DynamicLifecycleOptions,
        timeout: Duration,
    ) -> Result<Self, LaunchError> {
        Self::launch_options(
            command,
            timeout,
            Some(options.validate()?),
            DynamicExecPolicy::Refuse,
        )
    }

    /// Composes bounded creation ownership with one native leader exec. Registry
    /// task/mm limits include the additional exec incarnation. Fork retains its
    /// physical-process bound; ThreadClone retains one process and two native
    /// tasks. A leader may exec before clone or after the worker's actual terminal
    /// and thread-pidfd HUP; live-sibling and nonleader exec remain refused.
    /// Both old entry points
    /// retain their existing refusal behavior. Exec requires native x86-64,
    /// TF-clear syscall entry, one thread in the process and the tracer's PID
    /// namespace. Failed exec cannot resume through this initial profile.
    pub fn launch_with_options(
        command: &LaunchCommand,
        options: DynamicSessionOptions,
        timeout: Duration,
    ) -> Result<Self, LaunchError> {
        let lifecycle = options.lifecycle.validate()?;
        if options == DynamicSessionOptions::default() {
            return Self::launch(command, timeout);
        }
        Self::launch_options(command, timeout, Some(lifecycle), options.exec)
    }

    fn launch_options(
        command: &LaunchCommand,
        timeout: Duration,
        lifecycle: Option<DynamicLifecycleOptions>,
        exec: DynamicExecPolicy,
    ) -> Result<Self, LaunchError> {
        let until = deadline(timeout)?;
        Self::launch_options_until(command, timeout, lifecycle, exec, until)
    }

    // Admission already owns an absolute construction budget. Legacy entry
    // points pass the same Instant previously used by this unchanged body.
    fn launch_options_until(
        command: &LaunchCommand,
        timeout: Duration,
        lifecycle: Option<DynamicLifecycleOptions>,
        exec: DynamicExecPolicy,
        until: Instant,
    ) -> Result<Self, LaunchError> {
        let session = NEXT_SESSION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| LaunchError::Invalid("dynamic session identity exhausted"))?;
        let command = command.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let thread_cancel = Arc::clone(&cancel);
        let (commands, receiver) = channel();
        let (ready_tx, ready_rx) = channel();
        let (done_tx, done) = channel();
        // Block before spawn, not merely at the thread's first instruction:
        // otherwise an embedding signal handler could run before owner::run.
        let blocked = launch::BlockedSignals::new()?;
        let inherited_mask = blocked.original();
        let spawned = std::thread::Builder::new()
            .name("liteinst-dynamic-tracer".into())
            .spawn(move || {
                owner::run(TracerStart {
                    command,
                    session,
                    inherited_mask,
                    lifecycle,
                    exec,
                    until,
                    cancel: thread_cancel,
                    commands: receiver,
                    ready: ready_tx,
                    done: done_tx,
                })
            });
        if let Err(error) = blocked.restore() {
            cancel.store(true, Ordering::Release);
            return Err(error);
        }
        spawned.map_err(|error| io_error("start dynamic tracer", error))?;
        let ready = match ready_rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(Ok(ready)) => ready,
            Ok(Err(error)) => {
                cancel.store(true, Ordering::Release);
                return Err(error);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                cancel.store(true, Ordering::Release);
                return Err(LaunchError::Timeout("seized launch"));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                cancel.store(true, Ordering::Release);
                return Err(LaunchError::Invalid("dynamic launch tracer closed"));
            }
        };
        Ok(Self {
            pid: ready.pid,
            initial: ready.event,
            commands,
            cancel,
            done,
            operation_timeout: timeout,
        })
    }

    /// Original numeric PID, retained across exec and for diagnostics after terminal events.
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }
    /// Initial actual exec event. Its token becomes stale after the first resume.
    pub fn initial_event(&self) -> &DynamicEvent {
        &self.initial
    }

    fn call(&mut self, request: Request, timeout: Duration) -> Result<Response, LaunchError> {
        self.call_with_response_timeout(request, timeout, timeout)
    }

    fn call_with_response_timeout(
        &mut self,
        request: Request,
        event_timeout: Duration,
        response_timeout: Duration,
    ) -> Result<Response, LaunchError> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(LaunchError::Invalid("dynamic session is closing"));
        }
        let (until, response_until) = command_deadlines(event_timeout, response_timeout)?;
        let (reply, response) = channel();
        self.commands
            .send(Command {
                request,
                until,
                reply,
            })
            .map_err(|_| LaunchError::Invalid("dynamic tracer is closed"))?;
        match response.recv_timeout(response_until.saturating_duration_since(Instant::now())) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                self.cancel.store(true, Ordering::Release);
                Err(LaunchError::Timeout("dynamic tracer response"))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                self.cancel.store(true, Ordering::Release);
                Err(LaunchError::Invalid("dynamic tracer is closed"))
            }
        }
    }
    /// Waits for the next kernel event without resuming any stopped task.
    pub fn next_event(&mut self, timeout: Duration) -> Result<DynamicEvent, LaunchError> {
        match self.call(Request::Wait, timeout)? {
            Response::Event(event) => Ok(event),
            _ => unreachable!(),
        }
    }

    /// Waits with separate event and response deadlines from the same start.
    /// Both durations must be in (0, MAX_LAUNCH_TIMEOUT], and response_timeout
    /// must be at least event_timeout. Invalid budgets never queue a command.
    /// The event deadline includes dispatch time; an already expired command
    /// retains its command-timeout error. The response deadline is the total
    /// client wait, not an extra duration after the event deadline. A longer
    /// response budget lets the owner deliver its event-expiry error; it does
    /// not extend native event collection or guarantee scheduling latency.
    /// Any timeout retains the existing cancellation and cleanup ownership.
    /// next_event(timeout) continues using one equal deadline for both waits.
    pub fn next_event_with_response_timeout(
        &mut self,
        event_timeout: Duration,
        response_timeout: Duration,
    ) -> Result<DynamicEvent, LaunchError> {
        match self.call_with_response_timeout(Request::Wait, event_timeout, response_timeout)? {
            Response::Event(event) => Ok(event),
            _ => unreachable!(),
        }
    }
    /// Actively interrupts a running task; a racing real event is preserved.
    /// Listening job-control tasks must receive SIGCONT, rather than be bypassed.
    pub fn interrupt(&mut self, timeout: Duration) -> Result<DynamicEvent, LaunchError> {
        match self.call(Request::Interrupt, timeout)? {
            Response::Event(event) => Ok(event),
            _ => unreachable!(),
        }
    }
    /// Interrupts one running opt-in incarnation. Foreign or retired identities
    /// cannot select a numeric PID. Other task stops remain held independently.
    /// If the requested incarnation execs while interruption is pending, the
    /// returned ExecReplaced event names it in `previous` and holds the new task.
    pub fn interrupt_task(
        &mut self,
        task: crate::lifecycle::TaskId,
        timeout: Duration,
    ) -> Result<DynamicEvent, LaunchError> {
        match self.call(Request::InterruptTask(task), timeout)? {
            Response::Event(event) => Ok(event),
            _ => unreachable!(),
        }
    }

    /// Retained bookkeeping only, not a quiescence proof. None before the first
    /// authenticated exec syscall exit, or in default refusal-only mode.
    pub fn lifecycle_snapshot(
        &mut self,
    ) -> Result<Option<crate::lifecycle::RegistrySnapshot>, LaunchError> {
        match self.call(Request::LifecycleSnapshot, self.operation_timeout)? {
            Response::LifecycleSnapshot(snapshot) => Ok(snapshot),
            _ => unreachable!(),
        }
    }

    /// Applies exactly the disposition permitted for this current stop token.
    pub fn resume(&mut self, stop: &DynamicStop, action: DynamicResume) -> Result<(), LaunchError> {
        match self.call(
            Request::Resume(stop.clone(), action),
            self.operation_timeout,
        )? {
            Response::Unit => Ok(()),
            _ => unreachable!(),
        }
    }
    /// Complete native general registers at the exact held stop.
    pub fn read_registers(&mut self, stop: &DynamicStop) -> Result<RegisterSnapshot, LaunchError> {
        match self.call(Request::Registers(stop.clone()), self.operation_timeout)? {
            Response::Registers(value) => Ok(value),
            _ => unreachable!(),
        }
    }
    /// Complete kernel XSTATE at this stop; no user-return phase is inferred.
    pub fn read_xstate(&mut self, stop: &DynamicStop) -> Result<Vec<u8>, LaunchError> {
        match self.call(Request::Xstate(stop.clone()), self.operation_timeout)? {
            Response::Bytes(value) => Ok(value),
            _ => unreachable!(),
        }
    }
    /// Reads at most MAX_MEMORY_READ bytes from the exact held task.
    pub fn read_memory(
        &mut self,
        stop: &DynamicStop,
        address: u64,
        len: usize,
    ) -> Result<Vec<u8>, LaunchError> {
        match self.call(
            Request::Memory(stop.clone(), address, len),
            self.operation_timeout,
        )? {
            Response::Bytes(value) => Ok(value),
            _ => unreachable!(),
        }
    }
    /// Reads the exact Linux x86-64 eight-byte kernel signal mask.
    pub fn signal_mask(&mut self, stop: &DynamicStop) -> Result<u64, LaunchError> {
        match self.call(Request::Mask(stop.clone()), self.operation_timeout)? {
            Response::Mask(value) => Ok(value),
            _ => unreachable!(),
        }
    }
    /// Cancels nonblockingly, then waits up to timeout for complete cleanup.
    /// On timeout the dedicated tracer continues owning cleanup in the background.
    pub fn terminate(self, timeout: Duration) -> Result<DynamicCleanup, LaunchError> {
        let until = deadline(timeout)?;
        self.cancel.store(true, Ordering::Release);
        self.done
            .recv_timeout(until.saturating_duration_since(Instant::now()))
            .map_err(|error| match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => {
                    LaunchError::Timeout("dynamic cleanup remains owned by tracer")
                }
                std::sync::mpsc::RecvTimeoutError::Disconnected => {
                    LaunchError::Invalid("dynamic cleanup owner ended without a receipt")
                }
            })?
    }
}

impl Drop for DynamicSession {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}
