//! Explicit single-task selected-instruction trap/interpreter execution.
//!
//! This path reuses page admission and owns every selected trap. It does not
//! claim A1 publication. The optional coverage backend preserves original scan
//! refusals and supplies a separate guard proof; neither backend is an implicit
//! fallback from a core refusal.

use super::{GateError, GateEvent, GateMetrics, ImageFacts, SingleThreadPageGate, remaining};
use crate::selected::{
    FaultedInstruction, InstructionProvider, Operation, ProviderDecision, SelectedInput,
    SelectedResult, SemanticsError, SyscallAbi, SyscallAliases, SyscallResult, decode,
};
use crate::{ExecCheckpoint, NativeSyscallOutcome, ProcessEvent, RegisterSnapshot, SignalStop};
use liteinst_admission::scan::{Policy, SiteClass};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const DEBUG_FLAGS: u64 = (1 << 8) | (1 << 16); // TF and RF.

/// How a selected instruction obtained its completed result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedExecution {
    /// The original operation executed once in the owned child.
    Native,
    /// A typed provider result was applied to the full stopped register file.
    Scripted,
}

/// One complete selected transition, retaining exact kernel snapshots.
#[derive(Clone, Debug)]
pub struct SelectedCompletion {
    /// Authenticated original instruction and full input register file.
    pub input: SelectedInput,
    /// Full completed register file, including kernel bookkeeping.
    pub after: RegisterSnapshot,
    /// Kernel extended state before completion.
    pub before_xstate: Vec<u8>,
    /// Kernel extended state after completion and source rearming.
    pub xstate: Vec<u8>,
    /// Explicit result mechanism; scripted completion is not native evidence.
    pub execution: SelectedExecution,
}

/// An unowned application signal, never silently converted into completion.
#[derive(Clone, Debug)]
pub struct SelectedSignal {
    /// Pending signal number.
    pub signal: i32,
    /// Kernel cause code.
    pub code: i32,
    /// Kernel fault address, if present.
    pub address: Option<u64>,
    /// Actual full register snapshot at this signal stop.
    pub registers: RegisterSnapshot,
    /// Actual complete kernel extended state at this stop.
    pub xstate: Vec<u8>,
    /// Selected invocation interrupted by the signal, if any.
    pub input: Option<SelectedInput>,
}

/// Selected execution events; fault/exit events permanently close the loop.
#[derive(Clone, Debug)]
pub enum SelectedEvent {
    /// A completed native or scripted transition with exact input/output state.
    Completed(Box<SelectedCompletion>),
    /// A provider's uncompleted architectural fault. No kernel signal was sent.
    Fault(Box<FaultedInstruction>),
    /// An actual kernel signal pending at its original application state.
    ApplicationSignal(Box<SelectedSignal>),
    /// An unselected application exit, already reaped by the owner.
    Exited(i32),
    /// A selected native syscall terminated the child, which is already reaped.
    Terminated {
        /// The selected syscall and original complete input state.
        input: Box<SelectedInput>,
        /// Actual child exit status.
        code: i32,
    },
    /// A selected native syscall's task died from a signal and was reaped.
    Signaled {
        /// The selected syscall whose execution was interrupted.
        input: Box<SelectedInput>,
        /// Actual terminating signal.
        signal: i32,
    },
}

/// Counts explicit selected dispatch and completion mechanisms.
#[derive(Clone, Debug, Default)]
pub struct SelectedMetrics {
    /// Provider invocations by selected class, including explicit faults/refusals.
    pub callbacks: BTreeMap<SiteClass, usize>,
    /// Successful native completions; this excludes terminal syscalls.
    pub native_completions: usize,
    /// Successful typed interpreter completions.
    pub scripted_completions: usize,
    /// Provider-generated faults, distinct from actual kernel signals.
    pub provider_faults: usize,
    /// Actual signals while executing a selected instruction.
    pub native_signals: usize,
    /// First errors closing the execution loop; repeated calls are not counted.
    pub refusals: usize,
}

/// An explicitly chosen single-task trap/interpreter path for selected classes.
///
/// Complete original heads, immutable private code and the same ownership
/// certifications as the B1 reference remain required. Native CPU instructions
/// run at their original address. Native SYSCALL uses authenticated syscall
/// stops and a private return bridge, never SINGLESTEP. Scripted completion
/// changes only the stopped full register file, including a genuine RSP result.
/// The pure semantics module limits successful syscall emulation to its frozen
/// side-effect-free getpid/gettid profiles. Declared INT80 uses its separate
/// i386 execution owner; SYSENTER has no qualified successful return.
pub struct SelectedPageGate<P: InstructionProvider> {
    inner: SingleThreadPageGate,
    provider: P,
    metrics: SelectedMetrics,
    closed: bool,
}

impl<P: InstructionProvider> SelectedPageGate<P> {
    #[cfg(test)]
    pub(super) fn inject_coverage_failure(&mut self, phase: super::coverage::failure::Phase) {
        self.inner.coverage_failure = Some(super::coverage::failure::Injection::new(phase));
    }

    #[cfg(test)]
    pub(super) fn coverage_failure_evidence(&self) -> &super::coverage::failure::Injection {
        self.inner
            .coverage_failure
            .as_ref()
            .expect("test configured injection")
    }

    /// Creates the explicit trap/interpreter backend before original execution.
    /// No selected site is deselected when decoding, scanning or execution fails.
    ///
    /// # Safety
    /// All ownership, complete-head, immutable-code, no-alias and no-code-as-data
    /// certifications of [`SingleThreadPageGate::new`] apply. The provider is
    /// trusted to return promptly and to implement the caller's chosen replacement
    /// policy; a scripted result is not a claim of native instruction execution.
    /// TF and RF must be clear on every original selected-instruction entry.
    /// The inserted INT3 cannot certify the pre-trap RF value; checking the
    /// observed flags alone does not establish this caller-owned condition.
    /// In particular, arbitrary signal-return and IRET paths are unqualified.
    /// The caller must not independently trace, reap or mutate the child.
    pub unsafe fn new(
        checkpoint: ExecCheckpoint,
        facts: Vec<ImageFacts>,
        policy: Policy,
        aliases: SyscallAliases,
        provider: P,
        timeout: Duration,
    ) -> Result<Self, GateError> {
        // SAFETY: this constructor forwards the exact reference ownership contract.
        let mut inner = unsafe { SingleThreadPageGate::new(checkpoint, facts, policy, timeout)? };
        inner.selected_aliases = Some(aliases);
        Ok(Self {
            inner,
            provider,
            metrics: SelectedMetrics::default(),
            closed: false,
        })
    }

    /// Selects explicit trap coverage for overlapping selected instruction starts.
    ///
    /// Unlike the strict reference constructor, this backend may discharge
    /// embedded-candidate obligations using a separately checked guard closure.
    /// Collateral guards execute original instructions without logical callbacks.
    /// Unsupported collateral instructions refuse before publication. This is
    /// an explicitly selected backend, never an implicit fallback from A1.
    ///
    /// # Safety
    /// All certifications of [`Self::new`] apply, including complete original
    /// instruction heads, immutable private code, no code-as-data and clear TF/RF
    /// at every guarded instruction entry. Overlapping streams must all appear
    /// in the supplied head census; they are decoded independently.
    pub unsafe fn new_with_coverage(
        checkpoint: ExecCheckpoint,
        facts: Vec<ImageFacts>,
        policy: Policy,
        aliases: SyscallAliases,
        provider: P,
        timeout: Duration,
        budget: crate::trap_coverage::TrapCoverageBudget,
    ) -> Result<Self, GateError> {
        // SAFETY: forwards all ownership and original-entry certifications.
        let mut gate = unsafe { Self::new(checkpoint, facts, policy, aliases, provider, timeout)? };
        gate.inner.coverage_budget = Some(budget);
        Ok(gate)
    }

    /// Configures the same-owner in-memory oracle before any application resume.
    /// See [`SingleThreadPageGate::configure_oracle`]; RuntimeScan remains mandatory.
    pub fn configure_oracle(
        &mut self,
        limits: liteinst_admission::oracle_chain::CacheLimits,
    ) -> Result<(), GateError> {
        self.inner.configure_oracle(limits)
    }

    /// Bounded preparation with no publication or execution effects. Original
    /// refused reports remain refused; any coverage proof is performed on demand.
    pub fn prepare_oracle(
        &mut self,
        pages: &[u64],
    ) -> Result<Vec<liteinst_admission::oracle_chain::Inspection>, GateError> {
        self.inner.prepare_oracle(pages)
    }

    /// Preparation and demand work, excluding admitted-page revisits.
    pub fn oracle_metrics(&self) -> super::GateOracleMetrics {
        self.inner.oracle_metrics()
    }

    /// Current bounded retained cache storage, with explicit corruption errors.
    pub fn oracle_usage(
        &self,
    ) -> Result<
        liteinst_admission::oracle_chain::CacheUsage,
        liteinst_admission::oracle_chain::CacheCorruption,
    > {
        self.inner.oracle_usage()
    }

    /// Owned task identity, for diagnostics only.
    pub fn pid(&self) -> libc::pid_t {
        self.inner.pid()
    }
    /// Original page admission measurements, separate from dispatch mechanisms.
    pub fn gate_metrics(&self) -> &GateMetrics {
        self.inner.metrics()
    }
    /// Selected callback, completion, fault and refusal counts.
    pub fn metrics(&self) -> &SelectedMetrics {
        &self.metrics
    }
    /// Inspects provider state without exposing a process-control handle.
    pub fn provider(&self) -> &P {
        &self.provider
    }
    /// Updates the caller-owned provider between completed invocations.
    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }
    /// Whether an original page has passed the complete page-admission proof.
    pub fn is_admitted(&self, address: u64) -> bool {
        self.inner.is_admitted(address)
    }
    /// Reads bounded application memory while the task is held.
    pub fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, GateError> {
        self.inner.read_memory(address, len)
    }
    /// Reads the actual complete kernel extended state while held.
    pub fn read_xstate(&self) -> Result<Vec<u8>, GateError> {
        self.inner.read_xstate()
    }
    /// Reads the actual full stopped register file.
    pub fn read_registers(&self) -> Result<RegisterSnapshot, GateError> {
        self.inner.read_registers()
    }

    /// Invokes the provider once at one selected trap and reports its outcome.
    /// Errors and provider unwinding permanently close the wrapper. Kernel
    /// signals remain unacknowledged; faults are never resumed by this API.
    pub fn next_event(&mut self) -> Result<SelectedEvent, GateError> {
        if self.closed {
            return Err(GateError::Refused("selected execution loop is closed"));
        }
        // Set before calling any fallible code or the provider. Catching a
        // provider panic outside this method cannot revive an unfinished call.
        self.closed = true;
        let result = self.advance();
        match &result {
            Ok(SelectedEvent::Completed(_)) => self.closed = false,
            Err(_) => self.metrics.refusals += 1,
            _ => {}
        }
        result
    }

    fn advance(&mut self) -> Result<SelectedEvent, GateError> {
        let deadline = Instant::now() + self.inner.timeout;
        let observation = match self.inner.next_event()? {
            GateEvent::Observe(observation) => observation,
            GateEvent::Exited(code) => return Ok(SelectedEvent::Exited(code)),
            GateEvent::ApplicationSignal {
                signal,
                code,
                address,
                registers,
            } => {
                return Ok(SelectedEvent::ApplicationSignal(Box::new(SelectedSignal {
                    signal,
                    code,
                    address,
                    registers,
                    xstate: self.inner.read_xstate()?,
                    input: None,
                })));
            }
        };
        remaining(deadline)?;
        if self.inner.pending.take() != Some(observation.site) {
            return Err(GateError::Refused(
                "selected trap has no matching pending site",
            ));
        }
        let site = observation.site;
        let image = self
            .inner
            .images
            .iter()
            .find(|image| image.snapshot.range().contains(site.address))
            .ok_or(GateError::Refused("selected site has no original image"))?;
        let offset = (site.address - image.mapping.start) as usize;
        let bytes = &image.snapshot.bytes()[offset..offset + usize::from(site.len)];
        let instruction = decode(
            site.address,
            bytes,
            self.inner
                .selected_aliases
                .as_ref()
                .expect("constructor sets aliases"),
        )?;
        if instruction.bytes().len() != usize::from(site.len)
            || instruction.operation().class() != site.class
        {
            return Err(GateError::Refused("selected observation decode mismatch"));
        }
        let input = SelectedInput::new(instruction, observation.registers)?;
        if input.registers().eflags & DEBUG_FLAGS != 0 {
            return Err(GateError::Refused("selected trap requires clear TF and RF"));
        }
        self.authenticate_trap(&input)?;
        *self.metrics.callbacks.entry(site.class).or_default() += 1;
        let decision = self.provider.decide(&input)?;
        remaining(deadline)?;
        match decision {
            ProviderDecision::Fault(fault) => {
                self.metrics.provider_faults += 1;
                Ok(SelectedEvent::Fault(Box::new(input.fault(fault))))
            }
            ProviderDecision::Complete(result) => {
                let completed = input.complete(result)?;
                let mut stop = self.inner.process.hold()?;
                if stop.read_registers()? != *input.registers()
                    || stop.read_xstate()? != observation.xstate
                {
                    return Err(GateError::Refused(
                        "selected input changed during provider call",
                    ));
                }
                stop.write_registers(&completed.after)?;
                let xstate = stop.read_xstate()?;
                if xstate != observation.xstate {
                    return Err(GateError::Refused(
                        "scripted completion changed extended state",
                    ));
                }
                self.metrics.scripted_completions += 1;
                Ok(SelectedEvent::Completed(Box::new(SelectedCompletion {
                    input,
                    after: completed.after,
                    before_xstate: observation.xstate,
                    xstate,
                    execution: SelectedExecution::Scripted,
                })))
            }
            ProviderDecision::Native => self.execute_native(input, observation.xstate, deadline),
        }
    }

    fn authenticate_trap(&self, input: &SelectedInput) -> Result<(), GateError> {
        let expected = self.inner.armed_instruction(
            input.instruction().logical_pc(),
            input.instruction().bytes(),
        );
        if self
            .inner
            .read_memory(input.instruction().logical_pc(), expected.len())?
            != expected
        {
            return Err(GateError::Refused(
                "selected trap or instruction tail changed",
            ));
        }
        Ok(())
    }

    fn execute_native(
        &mut self,
        input: SelectedInput,
        before_xstate: Vec<u8>,
        deadline: Instant,
    ) -> Result<SelectedEvent, GateError> {
        let operation = input.instruction().operation();
        if let Operation::Syscall { abi } = operation {
            match abi {
                SyscallAbi::LinuxX64 => {}
                SyscallAbi::LinuxI386Int80 => {
                    // Refuse unsupported requests/flags before restoring any
                    // original source bytes. The native owner authenticates
                    // this exact identity again against the kernel result.
                    input.complete(SelectedResult::Syscall(
                        SyscallResult::LinuxI386Int80GetId {
                            value: self.pid() as u32,
                        },
                    ))?;
                }
                SyscallAbi::DeclaredSysenter(_) => {
                    return Err(SemanticsError::UnqualifiedSyscallCompletion.into());
                }
            }
        }
        self.authenticate_trap(&input)?;
        let pc = input.instruction().logical_pc();
        let original = input.instruction().bytes();
        let armed = self.inner.armed_instruction(pc, original);
        let mut stop = self.inner.process.hold()?;
        if stop.read_registers()? != *input.registers() || stop.read_xstate()? != before_xstate {
            return Err(GateError::Refused("native selected input changed"));
        }
        #[cfg(test)]
        super::coverage::failure::capture(
            &mut self.inner.coverage_failure,
            super::coverage::failure::Scope::Selected,
            &stop,
        )?;
        stop.write_memory_checked(pc, &armed, original)?;
        stop.sync_core(remaining(deadline)?)?;
        #[cfg(test)]
        super::coverage::failure::hit(
            &mut self.inner.coverage_failure,
            super::coverage::failure::Phase::SelectedRestored,
            &stop,
        )?;
        let (after, xstate) = if let Operation::Syscall { abi } = operation {
            let outcome = match abi {
                SyscallAbi::LinuxX64 => stop.execute_native_syscall(
                    pc,
                    input.instruction().bytes(),
                    remaining(deadline)?,
                ),
                SyscallAbi::LinuxI386Int80 => stop.execute_linux_int80_getid(
                    pc,
                    input.instruction().bytes(),
                    remaining(deadline)?,
                ),
                SyscallAbi::DeclaredSysenter(_) => {
                    return Err(SemanticsError::UnqualifiedSyscallCompletion.into());
                }
            }?;
            match outcome {
                NativeSyscallOutcome::Completed(completed) => {
                    (completed.registers, completed.xstate)
                }
                NativeSyscallOutcome::ApplicationSignal {
                    stop: signal,
                    registers,
                    xstate,
                } => {
                    self.metrics.native_signals += 1;
                    return Ok(native_signal(input, signal, *registers, xstate));
                }
                NativeSyscallOutcome::Exited { code } => {
                    return Ok(SelectedEvent::Terminated {
                        input: Box::new(input),
                        code,
                    });
                }
                NativeSyscallOutcome::Signaled { signal } => {
                    return Ok(SelectedEvent::Signaled {
                        input: Box::new(input),
                        signal,
                    });
                }
            }
        } else {
            match stop.single_step_until_event(remaining(deadline)?)? {
                ProcessEvent::Signal(signal)
                    if signal.signal == libc::SIGTRAP && signal.code == libc::TRAP_TRACE =>
                {
                    let mut stop = self.inner.process.hold()?;
                    stop.acknowledge_owned_signal(&signal)?;
                    let after = stop.read_registers()?;
                    input.validate_native_completion(&after)?;
                    (after, stop.read_xstate()?)
                }
                ProcessEvent::Signal(signal) => {
                    self.metrics.native_signals += 1;
                    return Ok(native_signal(
                        input,
                        signal,
                        self.inner.read_registers()?,
                        self.inner.read_xstate()?,
                    ));
                }
                _ => {
                    return Err(GateError::Refused(
                        "selected CPU instruction did not complete",
                    ));
                }
            }
        };
        if after.rip != input.instruction().next_pc() || xstate != before_xstate {
            return Err(GateError::Refused(
                "native selected continuation or extended state changed",
            ));
        }
        let mut stop = self.inner.process.hold()?;
        #[cfg(test)]
        super::coverage::failure::hit(
            &mut self.inner.coverage_failure,
            super::coverage::failure::Phase::SelectedCompleted,
            &stop,
        )?;
        stop.write_memory_checked(pc, original, &armed)?;
        stop.sync_core(remaining(deadline)?)?;
        if stop.read_registers()? != after || stop.read_xstate()? != xstate {
            return Err(GateError::Refused(
                "native selected rearming changed completed state",
            ));
        }
        self.metrics.native_completions += 1;
        Ok(SelectedEvent::Completed(Box::new(SelectedCompletion {
            input,
            after,
            before_xstate,
            xstate,
            execution: SelectedExecution::Native,
        })))
    }
}

fn native_signal(
    input: SelectedInput,
    signal: SignalStop,
    registers: RegisterSnapshot,
    xstate: Vec<u8>,
) -> SelectedEvent {
    SelectedEvent::ApplicationSignal(Box::new(SelectedSignal {
        signal: signal.signal,
        code: signal.code,
        address: signal.address,
        registers,
        xstate,
        input: Some(input),
    }))
}
