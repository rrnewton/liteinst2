//! Restricted single-task control. Numeric tracee addresses are passed only to
//! ptrace or to the tracee's syscall ABI, never dereferenced by this process.

use super::*;
use std::cell::RefCell;
use std::ops::Range;

use iced_x86::{Code, Decoder, DecoderOptions};
use liteinst2::contracts::{AddressRange, CodeIdentity, QuiescenceLease};

mod group;
pub use group::*;

const STUB: [u8; 3] = [0x0f, 0x05, 0xcc];
// Each entry is one exact native MOV to [RDI], then its own terminating INT3.
const STORE_STUBS: [(usize, &[u8]); 4] = [
    (16, &[0x88, 0x07, 0xcc]),
    (32, &[0x66, 0x89, 0x07, 0xcc]),
    (48, &[0x89, 0x07, 0xcc]),
    (64, &[0x48, 0x89, 0x07, 0xcc]),
];
const NT_X86_XSTATE: usize = 0x202;
const MAX_XSTATE: usize = 64 * 1024;
const SYNC_CORE: u64 = 1 << 5;
const REGISTER_SYNC_CORE: u64 = 1 << 6;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// A signal-delivery stop belonging to one particular process and stop event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalStop {
    /// Pending signal, which has not been delivered to application code.
    pub signal: i32,
    /// Kernel `si_code`.
    pub code: i32,
    /// Kernel fault address for fault/trap signals; this need not equal RIP.
    pub address: Option<u64>,
    /// Stopped instruction pointer.
    pub instruction_pointer: u64,
    pid: libc::pid_t,
    sequence: u64,
}

/// An event reached by resuming only the owned tracee.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessEvent {
    /// A signal has stopped the tracee before user delivery.
    Signal(SignalStop),
    /// A permitted syscall is stopped before kernel execution.
    SyscallEntry {
        /// Native x86-64 syscall number.
        number: u64,
        /// Syscall arguments in Linux ABI order.
        arguments: [u64; 6],
    },
    /// A syscall completed and the tracee is stopped before user return.
    SyscallExit {
        /// Raw signed return value.
        result: i64,
        /// Kernel classification of an errno result.
        is_error: bool,
    },
    /// The owned child exited and has been reaped.
    Exited {
        /// Exit status.
        code: i32,
    },
    /// The owned child died from a signal and has been reaped.
    Signaled {
        /// Terminating signal.
        signal: i32,
    },
}

/// Actual kernel result of one authenticated native SYSCALL instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeSyscallCompletion {
    /// Complete registers at the syscall-exit stop, including its original
    /// application continuation and kernel `orig_rax` bookkeeping.
    pub registers: RegisterSnapshot,
    /// Complete kernel extended state at that same exit stop.
    pub xstate: Vec<u8>,
    /// Raw signed return value, authenticated against GET_SYSCALL_INFO.
    pub result: i64,
    /// Kernel classification of an errno return. An errno is a completion,
    /// rather than an instruction fault or an instrumentation failure.
    pub is_error: bool,
}

/// Result of executing a selected native SYSCALL without debugger trap flags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeSyscallOutcome {
    /// The syscall returned and an actual private INT3 established a safe
    /// injection stop. The exact kernel-exit state has been restored, so source
    /// rearming and sync-core operations may now run under the held owner.
    Completed(Box<NativeSyscallCompletion>),
    /// An application signal interrupted execution. It remains unacknowledged;
    /// no bridge or instruction completion is inferred from this stop.
    ApplicationSignal {
        /// Exact pending kernel signal and stop identity.
        stop: SignalStop,
        /// Complete application registers at the signal stop.
        registers: Box<RegisterSnapshot>,
        /// Complete kernel extended state at the signal stop.
        xstate: Vec<u8>,
    },
    /// The syscall terminated the child, which has been reaped.
    Exited {
        /// Native exit status.
        code: i32,
    },
    /// The child died from a signal and has been reaped.
    Signaled {
        /// Native terminating signal.
        signal: i32,
    },
}

#[derive(Clone, Debug)]
enum Phase {
    // An internally authenticated syscall-island INT3, with application state restored.
    OwnedTrap,
    Signal { stop: SignalStop, owned: bool },
    SyscallEntry,
    SyscallExit,
}

#[derive(Clone, Debug)]
enum State {
    Stopped(Phase),
    Running,
    Dead,
}

/// Restricted control of one traced task and an immutable private syscall island.
///
/// This type is neither Send nor Sync. It refuses unrecognized syscalls before
/// kernel execution. The supported application syscalls are read on fd 0, write
/// on fd 1 or 2, getpid, gettid, exit, and exit_group. Thread creation, mapping
/// changes, signal contexts, and descriptor creation are consequently refused.
/// The supervisor must separately certify source identities, writer exclusion,
/// aliases, legal entries, and saved resumes before publishing patches.
pub struct StoppedProcess {
    checkpoint: ExecCheckpoint,
    first_execution_registers: RegisterSnapshot,
    exec_event_xstate: Vec<u8>,
    first_execution_xstate: Vec<u8>,
    island: Range<u64>,
    images: Vec<MemoryMapping>,
    state: State,
    sequence: u64,
    page_size: usize,
}

/// A scoped borrow proving that the sole owned task is currently ptrace-stopped.
///
/// It is not a core quiescence lease: private VMAs do not prove that another
/// process cannot change backing storage, and saved contexts still need the
/// publisher's entry/resume checks. Every mutating method checks stopped state.
pub struct SingleThreadStop<'a> {
    process: &'a mut StoppedProcess,
}

/// Publication operations available while a core lease borrows actual stopped
/// execution. Application resume, stepping, and register changes are absent.
pub struct RemoteLeaseOps<'scope, 'process> {
    held: &'scope RefCell<SingleThreadStop<'process>>,
}

// This guard references the RefCell that owns the actual process-stop borrow.
// Neither the guard nor its narrow operation view can release application
// execution; the outer method retains the borrow until lease destruction.
struct HeldExclusion<'scope, 'process> {
    held: &'scope RefCell<SingleThreadStop<'process>>,
}

impl ExecCheckpoint {
    /// Reads the exec-stopped extended-register image before remote bootstrap.
    pub fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        xstate(self.pid())
    }

    /// Completes the kernel's exec return, then installs an immutable RX syscall
    /// island while preserving original code and the first user instruction's
    /// general/extended registers, and transfers child ownership.
    ///
    /// The initial executable PC temporarily holds an entry INT3, then
    /// `syscall; int3`, while the sole task is stopped. Only those trusted
    /// instructions execute. Original bytes and registers are checked after
    /// restoration. The exec event has a
    /// transient RAX of -ENOSYS; the authenticated successful syscall exit must
    /// change only RAX to zero, before either image executes an instruction.
    /// The entry trap then materializes deferred kernel user-return state,
    /// including initial PKRU, before the extended-register snapshot is saved.
    /// Any other transition or uncertain error terminates the child; no
    /// partially restored process is returned.
    pub fn into_stopped_process(
        mut self,
        timeout: Duration,
    ) -> Result<StoppedProcess, LaunchError> {
        let deadline = deadline(timeout)?;
        single_task(self.pid())?;
        let exec_event = self.read_registers()?;
        if exec_event != self.initial_registers
            || exec_event.cs != 0x33
            || exec_event.orig_rax != libc::SYS_execve as u64
            || exec_event.rax != (-i64::from(libc::ENOSYS)) as u64
        {
            return Err(LaunchError::Invalid(
                "checkpoint is not at its original native exec stop",
            ));
        }
        let exec_event_xstate = xstate(self.pid())?;
        // The exec event is emitted inside execve. Finish its kernel return
        // before injecting RAX, which syscall completion could otherwise
        // overwrite. PTRACE_SYSCALL stops at that exit without executing a
        // single instruction from either loaded image.
        ptrace(
            libc::PTRACE_SETOPTIONS,
            self.pid(),
            0,
            (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACESYSGOOD)
                as usize,
        )?;
        ptrace(libc::PTRACE_SYSCALL, self.pid(), 0, 0)?;
        let status = self.child.wait(deadline, "initial exec syscall exit")?;
        if !libc::WIFSTOPPED(status)
            || libc::WSTOPSIG(status) != (libc::SIGTRAP | 0x80)
            || status >> 16 != 0
        {
            return Err(LaunchError::Invalid(
                "exec did not reach its syscall-exit stop",
            ));
        }
        let info = syscall_info(self.pid())?;
        if info.arch != AUDIT_ARCH_X86_64 || info.op != libc::PTRACE_SYSCALL_INFO_EXIT {
            return Err(LaunchError::Invalid(
                "exec completion is not an authenticated native syscall exit",
            ));
        }
        // SAFETY: the checked operation identifies the initialized exit variant.
        let exit = unsafe { info.u.exit };
        let mut expected = exec_event;
        expected.rax = 0;
        let saved = self.read_registers()?;
        if exit.sval != 0
            || exit.is_error != 0
            || info.instruction_pointer != saved.rip
            || info.stack_pointer != saved.rsp
            || saved != expected
            || xstate(self.pid())? != exec_event_xstate
        {
            return Err(LaunchError::Invalid(
                "exec completion changed more than its successful RAX result",
            ));
        }
        let page_size = page_size()?;
        let end = saved
            .rip
            .checked_add(STUB.len() as u64)
            .ok_or(LaunchError::Invalid("bootstrap address overflow"))?;
        if !self.mappings.iter().any(|mapping| {
            mapping.contains_executable(saved.rip)
                && end <= mapping.end
                && mapping.permissions.as_bytes()[3] == b'p'
        }) {
            return Err(LaunchError::Invalid(
                "bootstrap span is not in one private executable mapping",
            ));
        }
        let envelope = (saved.rip & !7)
            ..(end
                .checked_add(7)
                .ok_or(LaunchError::Invalid("bootstrap envelope overflow"))?
                & !7);
        let original =
            self.read_memory(envelope.start, (envelope.end - envelope.start) as usize)?;
        let saved_xstate =
            first_user_state(&mut self.child, &saved, envelope.start, &original, deadline)?;
        let result = (|| {
            poke_bytes(self.pid(), saved.rip, &STUB)?;
            if self.read_memory(saved.rip, STUB.len())? != STUB {
                return Err(LaunchError::Invalid("bootstrap bytes did not verify"));
            }
            let address = syscall_result(
                run_stub(
                    &mut self.child,
                    saved.rip,
                    libc::SYS_mmap,
                    [
                        0,
                        page_size as u64,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                        u64::MAX,
                        0,
                    ],
                    deadline,
                )?,
                "remote mmap syscall island",
            )?;
            let island_end = address
                .checked_add(page_size as u64)
                .ok_or(LaunchError::Invalid("syscall island overflow"))?;
            if address == 0
                || address % page_size as u64 != 0
                || (address < envelope.end && envelope.start < island_end)
            {
                return Err(LaunchError::Invalid("unexpected syscall island address"));
            }
            poke_bytes(self.pid(), address, &island_code())?;
            syscall_result(
                run_stub(
                    &mut self.child,
                    saved.rip,
                    libc::SYS_mprotect,
                    [
                        address,
                        page_size as u64,
                        (libc::PROT_READ | libc::PROT_EXEC) as u64,
                        0,
                        0,
                        0,
                    ],
                    deadline,
                )?,
                "remote mprotect syscall island",
            )?;
            let supported = syscall_result(
                run_stub(
                    &mut self.child,
                    saved.rip,
                    libc::SYS_membarrier,
                    [0; 6],
                    deadline,
                )?,
                "remote membarrier query",
            )?;
            if supported & (SYNC_CORE | REGISTER_SYNC_CORE) != SYNC_CORE | REGISTER_SYNC_CORE {
                return Err(LaunchError::Invalid(
                    "target process lacks sync-core support",
                ));
            }
            syscall_result(
                run_stub(
                    &mut self.child,
                    saved.rip,
                    libc::SYS_membarrier,
                    [REGISTER_SYNC_CORE, 0, 0, 0, 0, 0],
                    deadline,
                )?,
                "remote register sync-core",
            )?;
            syscall_result(
                run_stub(
                    &mut self.child,
                    saved.rip,
                    libc::SYS_membarrier,
                    [SYNC_CORE, 0, 0, 0, 0, 0],
                    deadline,
                )?,
                "remote bootstrap sync-core",
            )?;
            Ok(address..island_end)
        })();
        // On a known stop, restore even when a syscall returned an error. If
        // the child is no longer stopped, do not race it with restoration writes.
        let restoration = if !self.child.reaped && read_registers(self.pid()).is_ok() {
            (|| {
                poke_bytes(self.pid(), envelope.start, &original)?;
                restore_state(self.pid(), &saved, &saved_xstate)?;
                if self.read_memory(envelope.start, original.len())? != original {
                    return Err(LaunchError::Invalid(
                        "bootstrap original bytes did not restore",
                    ));
                }
                Ok(())
            })()
        } else {
            Err(LaunchError::Invalid("bootstrap lost its stopped task"))
        };
        restoration?;
        let island = result?;
        // The island was synchronized before its first execution. Synchronize
        // the restored original image before it can be resumed too.
        syscall_result(
            run_stub(
                &mut self.child,
                island.start,
                libc::SYS_membarrier,
                [SYNC_CORE, 0, 0, 0, 0, 0],
                deadline,
            )?,
            "remote restored-image sync-core",
        )?;
        if self.read_registers()? != saved
            || self.read_memory(envelope.start, original.len())? != original
            || xstate(self.pid())? != saved_xstate
        {
            return Err(LaunchError::Invalid(
                "bootstrap changed original process state",
            ));
        }
        let images = self
            .mappings
            .iter()
            .filter(|mapping| {
                mapping.permissions.as_bytes()[2] == b'x'
                    && mapping.pathname.as_deref() != Some("[vsyscall]")
            })
            .cloned()
            .collect();
        self.mappings = read_maps(self.pid())?;
        verify_island(self.pid(), &self.mappings, &island)?;
        ptrace(
            libc::PTRACE_SETOPTIONS,
            self.pid(),
            0,
            (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACESYSGOOD)
                as usize,
        )?;
        Ok(StoppedProcess {
            checkpoint: self,
            first_execution_registers: saved,
            exec_event_xstate,
            first_execution_xstate: saved_xstate,
            island,
            images,
            state: State::Stopped(Phase::OwnedTrap),
            sequence: 0,
            page_size,
        })
    }
}

impl StoppedProcess {
    /// Returns the owned task ID; external tracing or reaping is unsupported.
    pub fn pid(&self) -> libc::pid_t {
        self.checkpoint.pid()
    }

    /// The kernel exec-event snapshot, whose transient RAX is -ENOSYS.
    ///
    /// This is earlier than the completed exec state seen by application code.
    pub fn exec_event_registers(&self) -> &RegisterSnapshot {
        self.checkpoint.initial_registers()
    }

    /// The authenticated successful exec-return state at the first user PC.
    ///
    /// No original instruction has executed. Only RAX differs from the exec
    /// event: zero replaces -ENOSYS. Bootstrap preserves every field exactly.
    /// The entry trap's RIP increment is reversed; `orig_rax`, kernel syscall
    /// metadata rather than an architectural register, retains the exec value.
    pub fn first_execution_registers(&self) -> &RegisterSnapshot {
        &self.first_execution_registers
    }

    /// The extended-state image at the kernel exec event, for diagnostics.
    ///
    /// It can precede deferred user-return initialization such as initial PKRU
    /// and must not be restored as the first user instruction's state.
    pub fn exec_event_xstate(&self) -> &[u8] {
        &self.exec_event_xstate
    }

    /// Complete extended state after the authenticated first-user INT3, before
    /// any original instruction or injected syscall executes.
    ///
    /// The trap does not change architectural extended state. This snapshot
    /// includes deferred kernel user-return initialization and is preserved
    /// exactly throughout syscall-island bootstrap.
    pub fn first_execution_xstate(&self) -> &[u8] {
        &self.first_execution_xstate
    }

    /// Returns the entry evidence captured before bootstrap.
    pub fn entries(&self) -> &EntryEvidence {
        self.checkpoint.entries()
    }

    /// Returns the last checked kernel mapping snapshot, including the island.
    pub fn mappings(&self) -> &[MemoryMapping] {
        self.checkpoint.mappings()
    }

    /// Original executable image mappings, including vDSO and excluding only
    /// the kernel's fixed `[vsyscall]` pseudo-mapping.
    pub fn initial_image_mappings(&self) -> &[MemoryMapping] {
        &self.images
    }

    /// Returns the immutable private syscall island's numeric address range.
    pub fn island_range(&self) -> Range<u64> {
        self.island.clone()
    }

    /// Returns the kernel page size used for permission operations.
    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Reads the currently stopped general registers.
    pub fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        self.ensure_stopped()?;
        read_registers(self.pid())
    }

    /// Reads the complete kernel-provided standard XSAVE register image.
    pub fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        self.ensure_stopped()?;
        xstate(self.pid())
    }

    /// Reads bounded tracee memory while the owned task is stopped.
    pub fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        self.ensure_stopped()?;
        read_memory(self.pid(), address, len)
    }

    /// Rechecks the sole task and refreshes the kernel mapping snapshot.
    pub fn refresh_mappings(&mut self) -> Result<&[MemoryMapping], LaunchError> {
        self.ensure_stopped()?;
        single_task(self.pid())?;
        self.checkpoint.mappings = read_maps(self.pid())?;
        Ok(&self.checkpoint.mappings)
    }

    /// Borrows the stopped task after checking that no sibling task exists.
    pub fn hold(&mut self) -> Result<SingleThreadStop<'_>, LaunchError> {
        self.ensure_stopped()?;
        if let Err(error) =
            single_task(self.pid()).and_then(|()| read_registers(self.pid()).map(|_| ()))
        {
            return self.fail(error);
        }
        Ok(SingleThreadStop { process: self })
    }

    /// Removes execute permission from every tracked initial image, including
    /// vDSO. The fixed kernel vsyscall pseudo-mapping is explicitly excluded.
    /// Returns the original mappings so the supervisor can record its gate.
    pub fn gate_initial_images(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<MemoryMapping>, LaunchError> {
        let images = self.images.clone();
        let deadline = deadline(timeout)?;
        for mapping in &images {
            let protection = protection(mapping)? & !libc::PROT_EXEC;
            self.hold()?.mprotect(
                mapping.start,
                (mapping.end - mapping.start) as usize,
                protection,
                remaining(deadline)?,
            )?;
        }
        Ok(images)
    }

    /// Restores original image permissions. This grants execution and therefore
    /// requires the supervisor to have satisfied its separate admission policy.
    pub fn restore_initial_permissions(&mut self, timeout: Duration) -> Result<(), LaunchError> {
        let deadline = deadline(timeout)?;
        for mapping in self.images.clone() {
            self.hold()?.mprotect(
                mapping.start,
                (mapping.end - mapping.start) as usize,
                protection(&mapping)?,
                remaining(deadline)?,
            )?;
        }
        Ok(())
    }

    /// Resumes until a syscall, signal, or exit event, with a bounded child-only
    /// wait. Unacknowledged signals and unapproved syscalls cannot be resumed.
    pub fn resume_until_event(&mut self, timeout: Duration) -> Result<ProcessEvent, LaunchError> {
        self.resume(libc::PTRACE_SYSCALL, timeout)
    }

    /// Kills and reaps the owned process.
    pub fn terminate(mut self) -> Result<(), LaunchError> {
        self.state = State::Dead;
        self.checkpoint.child.terminate()
    }

    fn ensure_stopped(&self) -> Result<(), LaunchError> {
        if !matches!(self.state, State::Stopped(_)) || self.checkpoint.child.reaped {
            return Err(LaunchError::Invalid(
                "operation requires a live stopped task",
            ));
        }
        Ok(())
    }

    fn owned_signal_stop(&self) -> Result<(), LaunchError> {
        match &self.state {
            State::Stopped(Phase::OwnedTrap | Phase::Signal { owned: true, .. }) => Ok(()),
            _ => Err(LaunchError::Invalid(
                "island syscall requires an acknowledged signal stop",
            )),
        }
    }

    fn fail<T>(&mut self, error: LaunchError) -> Result<T, LaunchError> {
        self.state = State::Dead;
        let _ = self.checkpoint.child.terminate();
        Err(error)
    }

    fn remote_syscall(
        &mut self,
        number: libc::c_long,
        arguments: [u64; 6],
        timeout: Duration,
    ) -> Result<u64, LaunchError> {
        self.owned_signal_stop()?;
        let deadline = deadline(timeout)?;
        if let Err(error) = single_task(self.pid())
            .and_then(|()| verify_island(self.pid(), self.mappings(), &self.island))
        {
            return self.fail(error);
        }
        self.state = State::Running;
        match run_stub(
            &mut self.checkpoint.child,
            self.island.start,
            number,
            arguments,
            deadline,
        ) {
            Ok(result) => {
                self.state = State::Stopped(Phase::OwnedTrap);
                Ok(result)
            }
            Err(error) => self.fail(error),
        }
    }

    fn resume(&mut self, request: u32, timeout: Duration) -> Result<ProcessEvent, LaunchError> {
        self.resume_before(request, deadline(timeout)?)
    }

    fn resume_before(
        &mut self,
        request: u32,
        deadline: Instant,
    ) -> Result<ProcessEvent, LaunchError> {
        self.ensure_stopped()?;
        if Instant::now() >= deadline {
            return self.fail(LaunchError::Timeout("owned process event"));
        }
        if let Err(error) = single_task(self.pid()) {
            return self.fail(error);
        }
        if self.island.contains(&self.read_registers()?.rip) {
            return self.fail(LaunchError::Invalid(
                "application entered private syscall island",
            ));
        }
        if matches!(
            self.state,
            State::Stopped(Phase::Signal { owned: false, .. })
        ) {
            return Err(LaunchError::Invalid(
                "pending signal is not acknowledged as owned",
            ));
        }
        if matches!(self.state, State::Stopped(Phase::SyscallEntry)) {
            if request == libc::PTRACE_SINGLESTEP {
                return Err(LaunchError::Invalid(
                    "cannot single-step a pending syscall entry",
                ));
            }
            let registers = self.read_registers()?;
            if let Err(error) = permitted_syscall(registers.orig_rax, arguments(&registers)) {
                return self.fail(error);
            }
        }
        if request == libc::PTRACE_SINGLESTEP {
            if let Err(error) = qualify_single_step(self.pid()) {
                return self.fail(error);
            }
        }
        ptrace(request, self.pid(), 0, 0)?;
        self.state = State::Running;
        let status = match self.checkpoint.child.wait(deadline, "owned process event") {
            Ok(status) => status,
            Err(error) => return self.fail(error),
        };
        match self.event(status) {
            Ok(event) => Ok(event),
            Err(error) => self.fail(error),
        }
    }

    fn event(&mut self, status: i32) -> Result<ProcessEvent, LaunchError> {
        if libc::WIFEXITED(status) {
            self.state = State::Dead;
            return Ok(ProcessEvent::Exited {
                code: libc::WEXITSTATUS(status),
            });
        }
        if libc::WIFSIGNALED(status) {
            self.state = State::Dead;
            return Ok(ProcessEvent::Signaled {
                signal: libc::WTERMSIG(status),
            });
        }
        if !libc::WIFSTOPPED(status) || status >> 16 != 0 {
            return Err(LaunchError::Invalid("unexpected process lifecycle event"));
        }
        if libc::WSTOPSIG(status) == libc::SIGTRAP | 0x80 {
            let info = syscall_info(self.pid())?;
            if info.arch != AUDIT_ARCH_X86_64 {
                return Err(LaunchError::Invalid("non-native syscall ABI"));
            }
            if self.island.contains(&info.instruction_pointer) {
                return Err(LaunchError::Invalid(
                    "application entered private syscall island",
                ));
            }
            return match info.op {
                libc::PTRACE_SYSCALL_INFO_ENTRY => {
                    // SAFETY: the kernel's ENTRY discriminator initializes this member.
                    let entry = unsafe { info.u.entry };
                    permitted_syscall(entry.nr, entry.args)?;
                    self.state = State::Stopped(Phase::SyscallEntry);
                    Ok(ProcessEvent::SyscallEntry {
                        number: entry.nr,
                        arguments: entry.args,
                    })
                }
                libc::PTRACE_SYSCALL_INFO_EXIT => {
                    // SAFETY: the kernel's EXIT discriminator initializes this member.
                    let exit = unsafe { info.u.exit };
                    self.state = State::Stopped(Phase::SyscallExit);
                    Ok(ProcessEvent::SyscallExit {
                        result: exit.sval,
                        is_error: exit.is_error != 0,
                    })
                }
                _ => Err(LaunchError::Invalid("missing syscall-entry/exit evidence")),
            };
        }
        let info = siginfo(self.pid())?;
        let registers = read_registers(self.pid())?;
        if self.island.contains(&registers.rip) {
            return Err(LaunchError::Invalid(
                "application entered private syscall island",
            ));
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(LaunchError::Invalid("stop sequence exhausted"))?;
        let address = if matches!(
            info.si_signo,
            libc::SIGSEGV | libc::SIGBUS | libc::SIGILL | libc::SIGTRAP | libc::SIGFPE
        ) {
            // SAFETY: these fault/trap signal variants carry the fault-address union member.
            Some(unsafe { info.si_addr() } as u64)
        } else {
            None
        };
        let stop = SignalStop {
            signal: info.si_signo,
            code: info.si_code,
            address,
            instruction_pointer: registers.rip,
            pid: self.pid(),
            sequence: self.sequence,
        };
        self.state = State::Stopped(Phase::Signal {
            stop: stop.clone(),
            owned: false,
        });
        Ok(ProcessEvent::Signal(stop))
    }
}

impl SingleThreadStop<'_> {
    /// Returns the exclusively owned stopped task ID.
    pub fn pid(&self) -> libc::pid_t {
        self.process.pid()
    }

    /// Copies the last checked mapping snapshot under the stopped-task borrow.
    pub fn mappings(&self) -> Vec<MemoryMapping> {
        self.process.mappings().to_vec()
    }

    /// Returns the target kernel page size.
    pub fn page_size(&self) -> usize {
        self.process.page_size
    }

    /// Borrows the real held process through a core quiescence lease and a
    /// restricted publication view. Errors, a poisoned lease, and unwinding
    /// terminate the child; successful return leaves application execution held.
    ///
    /// # Safety
    /// The caller must authenticate identity and hold every core dependency,
    /// including external readers/writers, aliases, entries, and saved resumes,
    /// for the entire callback, as required by `QuiescenceLease::new` and the
    /// core interface contract. A sole ptrace-stopped task proves only local
    /// execution exclusion. Operations may execute trusted island instructions
    /// but cannot resume application code. No independent tracer/reaper or
    /// process outside the certified ownership envelope may access the ranges.
    pub unsafe fn with_core_lease<T>(
        &mut self,
        identity: CodeIdentity,
        ranges: Vec<AddressRange>,
        action: impl FnOnce(
            &mut RemoteLeaseOps<'_, '_>,
            &mut QuiescenceLease<'_>,
        ) -> Result<T, LaunchError>,
    ) -> Result<T, LaunchError> {
        self.process.ensure_stopped()?;
        self.process.owned_signal_stop()?;
        if let Err(error) = single_task(self.process.pid()) {
            return self.process.fail(error);
        }
        let outcome = {
            let held = RefCell::new(SingleThreadStop {
                process: &mut *self.process,
            });
            let mut guard = HeldExclusion { held: &held };
            let mut operations = RemoteLeaseOps { held: &held };
            // Inspect through the actual guard before lending its lifetime.
            guard.held.borrow().process.ensure_stopped()?;
            // SAFETY: the caller certifies the complete core contract; guard
            // references the real stop owner, which cannot expose a resume
            // operation until this scope and its lease have ended.
            let mut lease = unsafe { QuiescenceLease::new(&mut guard, identity, ranges) };
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match action(&mut operations, &mut lease) {
                    Ok(value) if lease.is_poisoned() => {
                        // A caller-provided result may panic in Drop. Its
                        // destruction belongs inside the same unwind boundary
                        // so exclusion cannot escape without terminating the child.
                        drop(value);
                        Err(LaunchError::Invalid(
                            "core publication lease remained poisoned",
                        ))
                    }
                    result => result,
                }
            }))
        };
        match outcome {
            Ok(Ok(value)) => {
                if let Err(error) = self
                    .process
                    .ensure_stopped()
                    .and_then(|()| self.process.owned_signal_stop())
                    .and_then(|()| single_task(self.process.pid()))
                    .and_then(|()| read_registers(self.process.pid()).map(|_| ()))
                {
                    return self.process.fail(error);
                }
                Ok(value)
            }
            Ok(Err(error)) => self.process.fail(error),
            Err(payload) => {
                let _ = self
                    .process
                    .fail::<()>(LaunchError::Invalid("core publication unwound"));
                std::panic::resume_unwind(payload)
            }
        }
    }

    /// Reads stopped general registers.
    pub fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        self.process.read_registers()
    }

    /// Reads the stopped extended-state image.
    pub fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        self.process.read_xstate()
    }

    /// Reads bounded memory under this stopped-task borrow.
    pub fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        self.process.read_memory(address, len)
    }

    /// Acknowledges exactly the current fault/trap after the supervisor has
    /// authenticated it as its own admission or instrumentation event. No other
    /// pending signal is silently suppressed by remote control operations.
    pub fn acknowledge_owned_signal(&mut self, event: &SignalStop) -> Result<(), LaunchError> {
        if !matches!(event.signal, libc::SIGSEGV | libc::SIGTRAP | libc::SIGILL) {
            return Err(LaunchError::Invalid(
                "signal is outside the owned-fault envelope",
            ));
        }
        match &mut self.process.state {
            State::Stopped(Phase::Signal { stop, owned }) if stop == event => {
                *owned = true;
                Ok(())
            }
            _ => Err(LaunchError::Invalid(
                "signal event does not match current stop",
            )),
        }
    }

    /// Changes general registers while stopped and verifies the exact result.
    /// Segment selectors must retain the native x86-64 execution mode.
    pub fn write_registers(&mut self, registers: &RegisterSnapshot) -> Result<(), LaunchError> {
        self.process.ensure_stopped()?;
        let current = self.process.read_registers()?;
        if registers.cs != current.cs || registers.ss != current.ss || registers.cs != 0x33 {
            return Err(LaunchError::Invalid(
                "register write changes execution mode",
            ));
        }
        if let Err(error) = set_registers(self.process.pid(), registers).and_then(|()| {
            if read_registers(self.process.pid())? != *registers {
                Err(LaunchError::Invalid("register write did not verify"))
            } else {
                Ok(())
            }
        }) {
            return self.process.fail(error);
        }
        Ok(())
    }

    /// Compares expected bytes, writes through ptrace, and verifies replacement
    /// bytes. A prewrite mismatch leaves memory untouched; any uncertain write
    /// terminates the process. The immutable syscall island cannot be targeted.
    pub fn write_memory_checked(
        &mut self,
        address: u64,
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<(), LaunchError> {
        self.process.ensure_stopped()?;
        if expected.len() != replacement.len() || expected.len() > MAX_MEMORY_READ {
            return Err(LaunchError::Invalid("invalid checked-write lengths"));
        }
        self.process.target_range(address, replacement.len())?;
        if self.process.read_memory(address, expected.len())? != expected {
            return Err(LaunchError::Invalid("remote expected bytes mismatch"));
        }
        if let Err(error) = poke_bytes(self.process.pid(), address, replacement).and_then(|()| {
            if read_memory(self.process.pid(), address, replacement.len())? != replacement {
                Err(LaunchError::Invalid("remote write did not verify"))
            } else {
                Ok(())
            }
        }) {
            return self.process.fail(error);
        }
        Ok(())
    }

    /// Allocates exactly the requested unused address range, initializes a
    /// complete page image while RW, then makes it RX and synchronizes the
    /// target instruction stream. The image must contain 1..=64 KiB of whole
    /// pages; callers can place code or data at any offset within those pages.
    ///
    /// Existing mappings are never replaced. Any failure after allocation
    /// terminates the owner rather than returning a partial executable image.
    pub fn map_private_code(
        &mut self,
        address: u64,
        image: &[u8],
        timeout: Duration,
    ) -> Result<Range<u64>, LaunchError> {
        self.process.ensure_stopped()?;
        self.process.owned_signal_stop()?;
        let deadline = deadline(timeout)?;
        let end = address
            .checked_add(image.len() as u64)
            .ok_or(LaunchError::Invalid("code allocation address overflow"))?;
        if address == 0
            || address % self.process.page_size as u64 != 0
            || image.is_empty()
            || image.len() > MAX_MEMORY_READ
            || image.len() % self.process.page_size != 0
        {
            return Err(LaunchError::Invalid("invalid private code image range"));
        }
        self.process.refresh_mappings()?;
        if self
            .process
            .mappings()
            .iter()
            .any(|mapping| address < mapping.end && mapping.start < end)
        {
            return Err(LaunchError::Invalid(
                "private code allocation overlaps mapping",
            ));
        }
        let allocated = syscall_result(
            self.process.remote_syscall(
                libc::SYS_mmap,
                [
                    address,
                    image.len() as u64,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64,
                    u64::MAX,
                    0,
                ],
                remaining(deadline)?,
            )?,
            "remote fixed private code allocation",
        )?;
        let result = (|| {
            // Older kernels may ignore MAP_FIXED_NOREPLACE. Never accept a
            // fallback mapping, even when its contents could be initialized.
            if allocated != address {
                return Err(LaunchError::Invalid(
                    "fixed allocation returned another address",
                ));
            }
            self.process.refresh_mappings()?;
            self.process.require_rw_nx(address, image.len())?;
            let mut cursor = address;
            while cursor < end {
                let mapping = self
                    .process
                    .mappings()
                    .iter()
                    .find(|mapping| mapping.start <= cursor && cursor < mapping.end)
                    .ok_or(LaunchError::Invalid("private allocation disappeared"))?;
                if mapping.pathname.is_some() {
                    return Err(LaunchError::Invalid(
                        "private allocation has unexpected backing",
                    ));
                }
                cursor = mapping.end.min(end);
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
            poke_bytes(self.process.pid(), address, image)?;
            if self.read_memory(address, image.len())? != image {
                return Err(LaunchError::Invalid(
                    "private code initialization did not verify",
                ));
            }
            self.mprotect(
                address,
                image.len(),
                libc::PROT_READ | libc::PROT_EXEC,
                remaining(deadline)?,
            )?;
            self.sync_core(remaining(deadline)?)?;
            if self.read_memory(address, image.len())? != image {
                return Err(LaunchError::Invalid("finalized private code changed"));
            }
            Ok(address..end)
        })();
        match result {
            Ok(range) => Ok(range),
            Err(error) => self.process.fail(error),
        }
    }

    /// Performs one native MOV of exactly 1, 2, 4, or 8 little-endian bytes.
    /// The entire destination must be private RW and non-executable. Unaligned
    /// and mapped page-crossing stores are permitted while the sole task is
    /// held; this does not claim atomicity against external readers or writers.
    ///
    /// Expected-byte mismatch leaves memory untouched. The aligned surrounding
    /// word envelope is verified after the store, and GPRs/XSTATE are restored
    /// exactly. Any uncertainty after starting the MOV terminates the child.
    /// The caller must synchronize and finalize permissions before publication.
    pub fn exact_store_checked(
        &mut self,
        address: u64,
        expected: &[u8],
        replacement: &[u8],
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        self.process.ensure_stopped()?;
        self.process.owned_signal_stop()?;
        let deadline = deadline(timeout)?;
        let stub_index = match expected.len() {
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
            .ok_or(LaunchError::Invalid("exact store address overflow"))?;
        let envelope = (address & !7)
            ..(end
                .checked_add(7)
                .ok_or(LaunchError::Invalid("exact store envelope overflow"))?
                & !7);
        self.process.refresh_mappings()?;
        self.process
            .require_rw_nx(envelope.start, (envelope.end - envelope.start) as usize)?;
        let mut after =
            self.read_memory(envelope.start, (envelope.end - envelope.start) as usize)?;
        let offset = (address - envelope.start) as usize;
        if &after[offset..offset + expected.len()] != expected {
            return Err(LaunchError::Invalid("remote expected bytes mismatch"));
        }
        after[offset..offset + replacement.len()].copy_from_slice(replacement);
        if let Err(error) = single_task(self.process.pid()).and_then(|()| {
            verify_island(
                self.process.pid(),
                self.process.mappings(),
                &self.process.island,
            )
        }) {
            return self.process.fail(error);
        }
        let (stub_offset, stub) = STORE_STUBS[stub_index];
        let mut value = [0_u8; 8];
        value[..replacement.len()].copy_from_slice(replacement);
        let stub_address = self.process.island.start + stub_offset as u64;
        self.process.state = State::Running;
        let result = run_store(
            &mut self.process.checkpoint.child,
            stub_address,
            stub.len(),
            address,
            u64::from_le_bytes(value),
            deadline,
        );
        if let Err(error) = result {
            return self.process.fail(error);
        }
        self.process.state = State::Stopped(Phase::OwnedTrap);
        match self.read_memory(envelope.start, after.len()) {
            Ok(actual) if actual == after => Ok(()),
            Ok(_) => self.process.fail(LaunchError::Invalid(
                "exact store or adjacent bytes did not verify",
            )),
            Err(error) => self.process.fail(error),
        }
    }

    /// Changes page permissions through the private island. The complete range
    /// must be mapped privately, page-aligned, and outside the island. RWX is
    /// refused. This primitive does not itself certify code admission.
    pub fn mprotect(
        &mut self,
        address: u64,
        len: usize,
        protection: i32,
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        self.process.ensure_stopped()?;
        if len == 0
            || address % self.process.page_size as u64 != 0
            || len % self.process.page_size != 0
            || protection & !(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) != 0
            || protection & (libc::PROT_WRITE | libc::PROT_EXEC)
                == libc::PROT_WRITE | libc::PROT_EXEC
        {
            return Err(LaunchError::Invalid(
                "unsupported permission range or RWX protection",
            ));
        }
        self.process.target_range(address, len)?;
        let result = self.process.remote_syscall(
            libc::SYS_mprotect,
            [address, len as u64, protection as u64, 0, 0, 0],
            timeout,
        )?;
        if let Err(error) = syscall_result(result, "remote mprotect") {
            return self.process.fail(error);
        }
        let result = (|| {
            self.process.checkpoint.mappings = read_maps(self.process.pid())?;
            let end = address + len as u64;
            let mut cursor = address;
            while cursor < end {
                let mapping = self
                    .process
                    .mappings()
                    .iter()
                    .find(|mapping| mapping.start <= cursor && cursor < mapping.end)
                    .ok_or(LaunchError::Invalid("mprotect left an unmapped range"))?;
                if super_protection(mapping)? != protection {
                    return Err(LaunchError::Invalid("mprotect result did not verify"));
                }
                cursor = mapping.end.min(end);
            }
            Ok(())
        })();
        if let Err(error) = result {
            return self.process.fail(error);
        }
        Ok(())
    }

    /// Completes target-process instruction-stream synchronization; a parent
    /// process membarrier would not synchronize the tracee's address space.
    pub fn sync_core(&mut self, timeout: Duration) -> Result<(), LaunchError> {
        let result = self.process.remote_syscall(
            libc::SYS_membarrier,
            [SYNC_CORE, 0, 0, 0, 0, 0],
            timeout,
        )?;
        if let Err(error) = syscall_result(result, "remote sync-core") {
            return self.process.fail(error);
        }
        Ok(())
    }

    /// Executes one original instruction under a bounded ptrace single-step.
    /// Pending syscall-entry stops and unsupported syscall instructions refuse
    /// before execution. The returned signal still requires ownership checking.
    ///
    /// This is a raw debugging operation, not a no-op instrumentation guarantee.
    /// In particular, a stepped SYSCALL can report TRAP_BRKPT and copy the
    /// debugger's trap flag into R11. Callers must separately qualify each
    /// instruction class and must not treat every SIGTRAP as TRAP_TRACE.
    pub fn single_step_until_event(
        &mut self,
        timeout: Duration,
    ) -> Result<ProcessEvent, LaunchError> {
        self.process.resume(libc::PTRACE_SINGLESTEP, timeout)
    }

    /// Executes one authenticated native SYSCALL through kernel entry and exit
    /// stops, without installing TF or executing its application continuation.
    ///
    /// The task must be at an acknowledged signal or trusted island stop, with
    /// RIP equal to `expected_pc` and TF clear. `expected_bytes` must match one
    /// complete decoded x86-64 SYSCALL (including any valid ignored prefixes).
    /// SYSENTER and INT 0x80 are different ABIs and refuse before execution.
    /// The ordinary single-task syscall allowlist remains in force.
    ///
    /// The caller is responsible for source publication and synchronization
    /// before this call. Successful completion executes a neutral private INT3,
    /// authenticates it, and restores the *actual* complete syscall-exit state.
    /// That real signal stop permits subsequent source rearming and sync-core;
    /// a syscall-exit stop is never merely relabelled as an injection stop.
    /// Entry, exit, and bridge share one cumulative deadline. An uncertain
    /// execution or bridge failure terminates the owned child.
    pub fn execute_native_syscall(
        &mut self,
        expected_pc: u64,
        expected_bytes: &[u8],
        timeout: Duration,
    ) -> Result<NativeSyscallOutcome, LaunchError> {
        let deadline = deadline(timeout)?;
        self.process.owned_signal_stop()?;
        if expected_bytes.is_empty() || expected_bytes.len() > 15 {
            return Err(LaunchError::Invalid(
                "invalid native syscall encoding length",
            ));
        }
        let next_pc = expected_pc
            .checked_add(expected_bytes.len() as u64)
            .ok_or(LaunchError::Invalid("native syscall address overflow"))?;
        let instruction =
            Decoder::with_ip(64, expected_bytes, expected_pc, DecoderOptions::NONE).decode();
        if instruction.code() != Code::Syscall || instruction.next_ip() != next_pc {
            return Err(LaunchError::Invalid(
                "requires one native SYSCALL instruction",
            ));
        }
        let before = self.process.read_registers()?;
        if before.rip != expected_pc || before.cs != 0x33 || before.eflags & 0x100 != 0 {
            return Err(LaunchError::Invalid(
                "native syscall needs exact PC, native CS and clear TF",
            ));
        }
        if self
            .process
            .read_memory(expected_pc, expected_bytes.len())?
            != expected_bytes
        {
            return Err(LaunchError::Invalid("native syscall source bytes differ"));
        }
        permitted_syscall(before.rax, arguments(&before))?;
        let outcome = (|| {
            single_task(self.pid())?;
            verify_island(self.pid(), &self.mappings(), &self.process.island)?;
            let entry = self.process.resume_before(libc::PTRACE_SYSCALL, deadline)?;
            match entry {
                ProcessEvent::SyscallEntry {
                    number,
                    arguments: actual,
                } => {
                    let info = syscall_info(self.pid())?;
                    let registers = self.read_registers()?;
                    if number != before.rax
                        || actual != arguments(&before)
                        || info.op != libc::PTRACE_SYSCALL_INFO_ENTRY
                        || info.arch != AUDIT_ARCH_X86_64
                        || info.instruction_pointer != next_pc
                        || info.stack_pointer != before.rsp
                        || registers.rip != next_pc
                        || registers.rsp != before.rsp
                        || registers.orig_rax != before.rax
                    {
                        return Err(LaunchError::Invalid(
                            "native syscall entry did not authenticate",
                        ));
                    }
                }
                ProcessEvent::Exited { .. } => {
                    return Err(LaunchError::Invalid(
                        "native syscall terminated before its entry stop",
                    ));
                }
                other => return self.native_syscall_terminal(other),
            }
            let exit = self.process.resume_before(libc::PTRACE_SYSCALL, deadline)?;
            match exit {
                ProcessEvent::SyscallExit { result, is_error } => {
                    let info = syscall_info(self.pid())?;
                    let registers = self.read_registers()?;
                    let extended = self.read_xstate()?;
                    if info.op != libc::PTRACE_SYSCALL_INFO_EXIT
                        || info.arch != AUDIT_ARCH_X86_64
                        || info.instruction_pointer != next_pc
                        || info.stack_pointer != before.rsp
                        || registers.rip != next_pc
                        || registers.rsp != before.rsp
                        || registers.orig_rax != before.rax
                        || registers.rax != result as u64
                        || is_error != (-4095..=-1).contains(&result)
                    {
                        return Err(LaunchError::Invalid(
                            "native syscall exit did not authenticate",
                        ));
                    }
                    syscall_time_left(deadline)?;
                    let island = self.process.island.clone();
                    verify_island(self.pid(), &self.mappings(), &island)?;
                    self.process.state = State::Running;
                    syscall_return_bridge(
                        &mut self.process.checkpoint.child,
                        island.start + 2,
                        &registers,
                        &extended,
                        deadline,
                    )?;
                    single_task(self.pid())?;
                    verify_island(self.pid(), &self.mappings(), &island)?;
                    syscall_time_left(deadline)?;
                    // The bridge has now executed and authenticated an actual
                    // owned trap and restored every saved kernel-exit byte.
                    self.process.state = State::Stopped(Phase::OwnedTrap);
                    Ok(NativeSyscallOutcome::Completed(Box::new(
                        NativeSyscallCompletion {
                            registers,
                            xstate: extended,
                            result,
                            is_error,
                        },
                    )))
                }
                other => self.native_syscall_terminal(other),
            }
        })();
        match outcome {
            Ok(outcome) => Ok(outcome),
            Err(error) => self.process.fail(error),
        }
    }

    fn native_syscall_terminal(
        &self,
        event: ProcessEvent,
    ) -> Result<NativeSyscallOutcome, LaunchError> {
        Ok(match event {
            ProcessEvent::Signal(stop) => NativeSyscallOutcome::ApplicationSignal {
                stop,
                registers: Box::new(self.read_registers()?),
                xstate: self.read_xstate()?,
            },
            ProcessEvent::Exited { code } => NativeSyscallOutcome::Exited { code },
            ProcessEvent::Signaled { signal } => NativeSyscallOutcome::Signaled { signal },
            _ => {
                return Err(LaunchError::Invalid(
                    "native syscall entry/exit order differs",
                ));
            }
        })
    }
}

impl RemoteLeaseOps<'_, '_> {
    /// Returns the held task ID.
    pub fn pid(&self) -> libc::pid_t {
        self.held.borrow().pid()
    }

    /// Returns the target page size.
    pub fn page_size(&self) -> usize {
        self.held.borrow().page_size()
    }

    /// Copies the most recently checked mappings.
    pub fn mappings(&self) -> Vec<MemoryMapping> {
        self.held.borrow().mappings()
    }

    /// Reads original or published bytes without executing application code.
    pub fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        self.held.borrow().read_memory(address, len)
    }

    /// Reads all general registers under the held exclusion.
    pub fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        self.held.borrow().read_registers()
    }

    /// Reads the complete extended state under the held exclusion.
    pub fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        self.held.borrow().read_xstate()
    }

    /// Initializes a complete private code image at an exact unused address.
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

    /// Performs a verified ptrace initialization write under the held exclusion.
    pub fn write_memory_checked(
        &mut self,
        address: u64,
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<(), LaunchError> {
        self.held
            .borrow_mut()
            .write_memory_checked(address, expected, replacement)
    }

    /// Performs one verified native store of the requested exact width.
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

    /// Changes permissions while application execution remains excluded.
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

    /// Synchronizes the held target's instruction stream.
    pub fn sync_core(&mut self, timeout: Duration) -> Result<(), LaunchError> {
        self.held.borrow_mut().sync_core(timeout)
    }
}

impl StoppedProcess {
    fn require_rw_nx(&self, address: u64, len: usize) -> Result<(), LaunchError> {
        self.target_range(address, len)?;
        let end = address + len as u64;
        let mut cursor = address;
        while cursor < end {
            let mapping = self
                .mappings()
                .iter()
                .find(|mapping| mapping.start <= cursor && cursor < mapping.end)
                .ok_or(LaunchError::Invalid("exact store range is not mapped"))?;
            if mapping.permissions != "rw-p" {
                return Err(LaunchError::Invalid(
                    "exact store requires private RW and NX memory",
                ));
            }
            cursor = mapping.end.min(end);
        }
        Ok(())
    }

    fn target_range(&self, address: u64, len: usize) -> Result<(), LaunchError> {
        let end = address
            .checked_add(len as u64)
            .ok_or(LaunchError::Invalid("target range overflow"))?;
        if address < self.island.end && self.island.start < end {
            return Err(LaunchError::Invalid(
                "operation overlaps immutable syscall island",
            ));
        }
        let mut cursor = address;
        while cursor < end {
            let mapping = self
                .mappings()
                .iter()
                .find(|mapping| mapping.start <= cursor && cursor < mapping.end)
                .ok_or(LaunchError::Invalid("target range is not fully mapped"))?;
            if mapping.permissions.as_bytes()[3] != b'p'
                || mapping.pathname.as_deref() == Some("[vsyscall]")
            {
                return Err(LaunchError::Invalid(
                    "target range is not a private user mapping",
                ));
            }
            cursor = mapping.end.min(end);
        }
        Ok(())
    }
}

fn page_size() -> Result<usize, LaunchError> {
    // SAFETY: sysconf reads a scalar process-independent platform property.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 || !(value as usize).is_power_of_two() {
        return Err(LaunchError::Invalid("unsupported kernel page size"));
    }
    Ok(value as usize)
}

fn deadline(timeout: Duration) -> Result<Instant, LaunchError> {
    if timeout.is_zero() || timeout > MAX_LAUNCH_TIMEOUT {
        return Err(LaunchError::Invalid(
            "operation timeout must be in (0, 30 seconds]",
        ));
    }
    Ok(Instant::now() + timeout)
}

fn remaining(deadline: Instant) -> Result<Duration, LaunchError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(LaunchError::Timeout("remote permission transaction"))
}

fn syscall_time_left(deadline: Instant) -> Result<(), LaunchError> {
    if Instant::now() >= deadline {
        Err(LaunchError::Timeout("native syscall completion"))
    } else {
        Ok(())
    }
}

fn single_task(pid: libc::pid_t) -> Result<(), LaunchError> {
    let entries = std::fs::read_dir(format!("/proc/{pid}/task"))
        .map_err(|error| io_error("list owned tasks", error))?;
    let mut found = false;
    for entry in entries {
        let entry = entry.map_err(|error| io_error("read owned task", error))?;
        if found || entry.file_name() != OsString::from(pid.to_string()) {
            return Err(LaunchError::Invalid(
                "remote control requires exactly one owned task",
            ));
        }
        found = true;
    }
    if !found {
        return Err(LaunchError::Invalid("owned task disappeared"));
    }
    Ok(())
}

fn protection(mapping: &MemoryMapping) -> Result<i32, LaunchError> {
    let bytes = mapping.permissions.as_bytes();
    if bytes.len() != 4 || bytes[3] != b'p' {
        return Err(LaunchError::Invalid("unsupported mapping protection"));
    }
    Ok(if bytes[0] == b'r' { libc::PROT_READ } else { 0 }
        | if bytes[1] == b'w' {
            libc::PROT_WRITE
        } else {
            0
        }
        | if bytes[2] == b'x' { libc::PROT_EXEC } else { 0 })
}

// Keep the mprotect argument's descriptive name without shadowing this helper.
fn super_protection(mapping: &MemoryMapping) -> Result<i32, LaunchError> {
    protection(mapping)
}

fn verify_island(
    pid: libc::pid_t,
    maps: &[MemoryMapping],
    island: &Range<u64>,
) -> Result<(), LaunchError> {
    if !maps.iter().any(|mapping| {
        mapping.start <= island.start
            && island.end <= mapping.end
            && mapping.permissions == "r-xp"
            && mapping.pathname.is_none()
    }) || read_memory(pid, island.start, island_code().len())? != island_code()
    {
        return Err(LaunchError::Invalid(
            "immutable RX syscall island did not verify",
        ));
    }
    Ok(())
}

fn island_code() -> Vec<u8> {
    let mut bytes = vec![0xcc; 68];
    bytes[..STUB.len()].copy_from_slice(&STUB);
    for (offset, stub) in STORE_STUBS {
        bytes[offset..offset + stub.len()].copy_from_slice(stub);
    }
    bytes
}

fn set_registers(pid: libc::pid_t, snapshot: &RegisterSnapshot) -> Result<(), LaunchError> {
    let raw = libc::user_regs_struct::from(*snapshot);
    ptrace(libc::PTRACE_SETREGS, pid, 0, (&raw const raw) as usize)
}

// The syscall-exit ptrace stop still precedes the final kernel return to user
// mode. In particular, its XSAVE image can lack initial PKRU. Observe that
// return through a trusted INT3 before saving the state any syscall must restore.
fn first_user_state(
    child: &mut ChildOwner,
    registers: &RegisterSnapshot,
    envelope: u64,
    original: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, LaunchError> {
    let result = (|| {
        poke_bytes(child.pid, registers.rip, &[0xcc])?;
        if read_memory(child.pid, registers.rip, 1)? != [0xcc] {
            return Err(LaunchError::Invalid("entry trap bytes did not verify"));
        }
        ptrace(libc::PTRACE_CONT, child.pid, 0, 0)?;
        let status = child.wait(deadline, "first user-return trap")?;
        if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTRAP || status >> 16 != 0
        {
            return Err(LaunchError::Invalid("exec did not reach owned entry trap"));
        }
        let signal = siginfo(child.pid)?;
        let mut expected = *registers;
        expected.rip = expected
            .rip
            .checked_add(1)
            .ok_or(LaunchError::Invalid("entry trap address overflow"))?;
        // Linux records -1 for an instruction trap, rather than a syscall.
        // All architectural GPRs and flags must still match exactly.
        expected.orig_rax = u64::MAX;
        if signal.si_signo != libc::SIGTRAP
            || !matches!(signal.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT)
            || read_registers(child.pid)? != expected
        {
            return Err(LaunchError::Invalid("unowned or state-changing entry trap"));
        }
        xstate(child.pid)
    })();
    // Restore source and GPRs even on a known stopped failure. Never write the
    // stale exec-event extended image over the kernel's user-return state.
    if child.reaped || read_registers(child.pid).is_err() {
        return Err(LaunchError::Invalid("entry trap lost its stopped task"));
    }
    poke_bytes(child.pid, envelope, original)?;
    set_registers(child.pid, registers)?;
    if read_memory(child.pid, envelope, original.len())? != original
        || read_registers(child.pid)? != *registers
    {
        return Err(LaunchError::Invalid(
            "entry trap restoration did not verify",
        ));
    }
    let extended = result?;
    if xstate(child.pid)? != extended {
        return Err(LaunchError::Invalid(
            "entry trap restoration changed xstate",
        ));
    }
    Ok(extended)
}

fn xstate(pid: libc::pid_t) -> Result<Vec<u8>, LaunchError> {
    let mut bytes = vec![0_u8; MAX_XSTATE];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    ptrace(
        libc::PTRACE_GETREGSET,
        pid,
        NT_X86_XSTATE,
        (&raw mut vector) as usize,
    )?;
    if vector.iov_len < 512 || vector.iov_len >= bytes.len() {
        return Err(LaunchError::Invalid("missing or truncated xstate image"));
    }
    bytes.truncate(vector.iov_len);
    Ok(bytes)
}

fn restore_state(
    pid: libc::pid_t,
    registers: &RegisterSnapshot,
    extended: &[u8],
) -> Result<(), LaunchError> {
    if xstate(pid)? != extended {
        let mut vector = libc::iovec {
            iov_base: extended.as_ptr().cast_mut().cast(),
            iov_len: extended.len(),
        };
        ptrace(
            libc::PTRACE_SETREGSET,
            pid,
            NT_X86_XSTATE,
            (&raw mut vector) as usize,
        )?;
    }
    set_registers(pid, registers)?;
    if read_registers(pid)? != *registers || xstate(pid)? != extended {
        return Err(LaunchError::Invalid(
            "remote syscall register restoration did not verify",
        ));
    }
    Ok(())
}

fn poke_bytes(pid: libc::pid_t, address: u64, bytes: &[u8]) -> Result<(), LaunchError> {
    let end = address
        .checked_add(bytes.len() as u64)
        .ok_or(LaunchError::Invalid("remote write overflow"))?;
    let mut cursor = address;
    while cursor < end {
        let aligned = cursor & !7;
        let mut word: [u8; 8] = read_memory(pid, aligned, 8)?.try_into().unwrap();
        let offset = (cursor - aligned) as usize;
        let count = (8 - offset).min((end - cursor) as usize);
        let source = (cursor - address) as usize;
        word[offset..offset + count].copy_from_slice(&bytes[source..source + count]);
        ptrace(
            libc::PTRACE_POKEDATA,
            pid,
            aligned as usize,
            u64::from_ne_bytes(word) as usize,
        )?;
        cursor += count as u64;
    }
    Ok(())
}

fn siginfo(pid: libc::pid_t) -> Result<libc::siginfo_t, LaunchError> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
    ptrace(libc::PTRACE_GETSIGINFO, pid, 0, info.as_mut_ptr() as usize)?;
    // SAFETY: GETSIGINFO initialized the entire siginfo object on success.
    Ok(unsafe { info.assume_init() })
}

// A syscall-exit stop precedes the actual kernel return to user mode. Execute
// only the already authenticated island INT3, then restore the actual syscall
// result before permitting any source-publication operation.
fn syscall_return_bridge(
    child: &mut ChildOwner,
    trap: u64,
    saved: &RegisterSnapshot,
    extended: &[u8],
    deadline: Instant,
) -> Result<(), LaunchError> {
    syscall_time_left(deadline)?;
    let mut temporary = *saved;
    temporary.rip = trap;
    temporary.orig_rax = u64::MAX;
    // These bits affect trusted execution or its completion comparison. Their
    // actual application values, including RF, are restored without masking.
    temporary.eflags &= !(0x100 | 0x10000 | 0x40000);
    set_registers(child.pid, &temporary)?;
    if read_registers(child.pid)? != temporary || xstate(child.pid)? != extended {
        return Err(LaunchError::Invalid("syscall bridge setup changed state"));
    }
    ptrace(libc::PTRACE_CONT, child.pid, 0, 0)?;
    let status = child.wait(deadline, "native syscall user-return bridge")?;
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTRAP || status >> 16 != 0 {
        return Err(LaunchError::Invalid(
            "syscall bridge did not reach its owned trap",
        ));
    }
    let signal = siginfo(child.pid)?;
    temporary.rip = trap
        .checked_add(1)
        .ok_or(LaunchError::Invalid("syscall bridge address overflow"))?;
    if signal.si_signo != libc::SIGTRAP
        || !matches!(signal.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT)
        || read_registers(child.pid)? != temporary
        || xstate(child.pid)? != extended
        || read_memory(child.pid, trap, 1)? != [0xcc]
    {
        return Err(LaunchError::Invalid(
            "unowned or state-changing syscall bridge trap",
        ));
    }
    syscall_time_left(deadline)?;
    restore_state(child.pid, saved, extended)
}

fn run_stub(
    child: &mut ChildOwner,
    address: u64,
    number: libc::c_long,
    arguments: [u64; 6],
    deadline: Instant,
) -> Result<u64, LaunchError> {
    let saved = read_registers(child.pid)?;
    let extended = xstate(child.pid)?;
    let mut registers = saved;
    registers.rip = address;
    registers.rax = number as u64;
    registers.orig_rax = u64::MAX;
    registers.eflags &= !0x100; // Trusted instructions must not inherit user TF.
    registers.rdi = arguments[0];
    registers.rsi = arguments[1];
    registers.rdx = arguments[2];
    registers.r10 = arguments[3];
    registers.r8 = arguments[4];
    registers.r9 = arguments[5];
    let mut stopped = true;
    let result = (|| {
        set_registers(child.pid, &registers)?;
        ptrace(libc::PTRACE_CONT, child.pid, 0, 0)?;
        stopped = false;
        let status = child.wait(deadline, "trusted remote syscall")?;
        stopped = libc::WIFSTOPPED(status);
        if !stopped || libc::WSTOPSIG(status) != libc::SIGTRAP || status >> 16 != 0 {
            return Err(LaunchError::Invalid(
                "remote syscall did not reach its owned trap",
            ));
        }
        let info = siginfo(child.pid)?;
        let result = read_registers(child.pid)?;
        if info.si_signo != libc::SIGTRAP
            || !matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT)
            || result.rip != address + STUB.len() as u64
        {
            return Err(LaunchError::Invalid("unowned trap during remote syscall"));
        }
        Ok(result.rax)
    })();
    if stopped {
        restore_state(child.pid, &saved, &extended)?;
    }
    result
}

fn run_store(
    child: &mut ChildOwner,
    stub_address: u64,
    stub_len: usize,
    destination: u64,
    value: u64,
    deadline: Instant,
) -> Result<(), LaunchError> {
    let saved = read_registers(child.pid)?;
    let extended = xstate(child.pid)?;
    let mut registers = saved;
    registers.rip = stub_address;
    registers.rax = value;
    registers.rdi = destination;
    registers.orig_rax = u64::MAX;
    // Trusted unaligned stores must not inherit application TF or AC. An NX
    // fault can also leave RF set; MOV clears RF before the following INT3.
    // Start trusted execution with RF clear so the exact completion comparison
    // remains valid. All three bits are restored in the complete original flags.
    registers.eflags &= !(0x100 | 0x10000 | 0x40000);
    let mut stopped = true;
    let result = (|| {
        set_registers(child.pid, &registers)?;
        ptrace(libc::PTRACE_CONT, child.pid, 0, 0)?;
        stopped = false;
        let status = child.wait(deadline, "trusted exact-width store")?;
        stopped = libc::WIFSTOPPED(status);
        if !stopped || libc::WSTOPSIG(status) != libc::SIGTRAP || status >> 16 != 0 {
            return Err(LaunchError::Invalid(
                "exact store did not reach its owned trap",
            ));
        }
        let info = siginfo(child.pid)?;
        registers.rip = stub_address + stub_len as u64;
        if info.si_signo != libc::SIGTRAP
            || !matches!(info.si_code, libc::SI_KERNEL | libc::TRAP_BRKPT)
            || read_registers(child.pid)? != registers
        {
            return Err(LaunchError::Invalid(
                "unowned or state-changing exact-store trap",
            ));
        }
        Ok(())
    })();
    if stopped {
        restore_state(child.pid, &saved, &extended)?;
    }
    result
}

fn syscall_result(result: u64, operation: &'static str) -> Result<u64, LaunchError> {
    let signed = result as i64;
    if (-4095..=-1).contains(&signed) {
        return Err(io_error(
            operation,
            io::Error::from_raw_os_error((-signed) as i32),
        ));
    }
    Ok(result)
}

fn syscall_info(pid: libc::pid_t) -> Result<libc::ptrace_syscall_info, LaunchError> {
    // Zero initialization also ensures no uninitialized union padding is exposed.
    let mut info: libc::ptrace_syscall_info = unsafe { std::mem::zeroed() };
    // SAFETY: info is writable local storage; the address argument is its size.
    let count = unsafe {
        libc::ptrace(
            libc::PTRACE_GET_SYSCALL_INFO,
            pid,
            std::mem::size_of_val(&info),
            &raw mut info,
        )
    };
    if count == -1 {
        return Err(system("PTRACE_GET_SYSCALL_INFO"));
    }
    let minimum = match info.op {
        libc::PTRACE_SYSCALL_INFO_ENTRY => 80,
        libc::PTRACE_SYSCALL_INFO_EXIT => 33,
        _ => return Err(LaunchError::Invalid("unsupported syscall stop kind")),
    };
    if count < minimum {
        return Err(LaunchError::Invalid("truncated syscall-stop information"));
    }
    Ok(info)
}

fn arguments(registers: &RegisterSnapshot) -> [u64; 6] {
    [
        registers.rdi,
        registers.rsi,
        registers.rdx,
        registers.r10,
        registers.r8,
        registers.r9,
    ]
}

fn permitted_syscall(number: u64, arguments: [u64; 6]) -> Result<(), LaunchError> {
    let allowed = match number as libc::c_long {
        libc::SYS_read => arguments[0] == 0,
        libc::SYS_write => matches!(arguments[0], 1 | 2),
        libc::SYS_getpid | libc::SYS_gettid | libc::SYS_exit | libc::SYS_exit_group => true,
        _ => false,
    };
    if !allowed {
        return Err(LaunchError::Invalid(
            "syscall is outside the single-task launch allowlist",
        ));
    }
    Ok(())
}

fn qualify_single_step(pid: libc::pid_t) -> Result<(), LaunchError> {
    let registers = read_registers(pid)?;
    if registers.cs != 0x33 {
        return Err(LaunchError::Invalid(
            "single-step requires native x86-64 mode",
        ));
    }
    let mut cursor = registers.rip;
    for _ in 0..15 {
        let byte = read_memory(pid, cursor, 1)?[0];
        cursor = cursor
            .checked_add(1)
            .ok_or(LaunchError::Invalid("instruction address overflow"))?;
        if matches!(
            byte,
            0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67 | 0x40
                ..=0x4f
        ) {
            continue;
        }
        if matches!(byte, 0x0f | 0xcd) {
            let next = read_memory(pid, cursor, 1)?[0];
            if byte == 0x0f && next == 0x05 {
                return permitted_syscall(registers.rax, arguments(&registers));
            }
            if (byte == 0x0f && next == 0x34) || (byte == 0xcd && next == 0x80) {
                return Err(LaunchError::Invalid(
                    "compatibility syscall instruction is unsupported",
                ));
            }
        }
        return Ok(());
    }
    Err(LaunchError::Invalid(
        "instruction prefix sequence exceeds native limit",
    ))
}
