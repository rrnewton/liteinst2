//! First-touch page gating with separate A1 and ptrace-reference CPUID paths.
//!
//! The single-task gate offers a slow native SINGLESTEP reference and a native
//! replacement callback through A1. The concurrent gate registers a fixed set
//! of real shared-mm workers and publishes under collective stopped exclusion.
//! Both require declared immutable code. The explicit selected backend supplies
//! typed CPU/syscall dispatch and optional overlap guards; general lifecycle
//! support is outside this module.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use iced_x86::{Decoder, DecoderOptions};
use liteinst_admission::AddressRange;
use liteinst_admission::oracle_chain::{
    CacheCorruption, CacheLimits, CacheUsage, Inspection, InspectionSource, OracleMiss,
};
use liteinst_admission::returns::CallReturnLedger;
use liteinst_admission::scan::{AdmissionOracle, Candidate, Policy, Verdict};
use liteinst2::contracts as core;

use crate::core_remote::CpuidPublisher;

mod concurrent;
pub use concurrent::*;

mod selected;
pub use selected::*;

mod coverage;
pub(crate) mod domain;

use domain::{
    AdmissionBundle, GateOracle, Image, PAGE, prepare_admission, qualify_collateral, remaining,
};

use crate::{
    ExecCheckpoint, LaunchError, ProcessEvent, RegisterSnapshot, SignalStop, StoppedProcess,
};

const SEGV_ACCERR: i32 = 2;

/// A caller-certified complete instruction-head census for one original VMA.
/// Addresses and bytes are rechecked against the stopped child before use.
#[derive(Clone, Debug)]
pub struct ImageFacts {
    /// Original mapping start, including any mapped ELF headers.
    pub start: u64,
    /// Complete original mapping bytes (at most 64 KiB in this reference).
    pub bytes: Vec<u8>,
    /// Every possible instruction head, including alternate and indirect entries.
    pub heads: BTreeSet<u64>,
}

/// A first-touch or reference-interception failure; the child stays owned.
#[derive(Debug)]
pub enum GateError {
    /// The child control operation failed and must not be bypassed.
    Control(LaunchError),
    /// The declared envelope or runtime fact could not be established.
    Refused(&'static str),
    /// Explicit coverage proof failure, including its remaining obligations.
    Coverage(crate::trap_coverage::TrapCoverageRefusal),
    /// RuntimeScan retained an unresolved obligation.
    Scan(Vec<liteinst_admission::scan::Obligation>),
    /// The A1 planner refused the selected instruction's required tactic.
    Core(core::Refusal),
    /// A typed selected decode, provider decision or completion was refused.
    Selected(crate::selected::SemanticsError),
}

impl From<LaunchError> for GateError {
    fn from(value: LaunchError) -> Self {
        Self::Control(value)
    }
}

impl From<crate::selected::SemanticsError> for GateError {
    fn from(value: crate::selected::SemanticsError) -> Self {
        Self::Selected(value)
    }
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Control(error) => write!(f, "{error}"),
            Self::Refused(reason) => write!(f, "page gate refused: {reason}"),
            Self::Coverage(reason) => write!(f, "trap coverage refused: {reason}"),
            Self::Scan(obligations) => write!(f, "page scan refused: {obligations:?}"),
            Self::Core(reason) => write!(f, "core planning refused: {reason}"),
            Self::Selected(reason) => write!(f, "selected instruction refused: {reason}"),
        }
    }
}
impl std::error::Error for GateError {}

/// An observation made before the selected original instruction executes.
#[derive(Clone, Debug)]
pub struct Observation {
    /// Original selected instruction, with its class and exact byte length.
    pub site: Candidate,
    /// Original application GPRs, including the original instruction pointer.
    pub registers: RegisterSnapshot,
    /// Kernel NT_X86_XSTATE bytes before the original instruction.
    pub xstate: Vec<u8>,
}

/// The externally observable events of the reference execution loop.
#[derive(Clone, Debug)]
pub enum GateEvent {
    /// The next call executes this instruction once through the chosen path.
    Observe(Observation),
    /// Normal application termination.
    Exited(i32),
    /// An unowned application signal; the task remains stopped, then is killed
    /// on drop. Signal delivery and application handlers are outside this API.
    ApplicationSignal {
        /// Pending application signal number.
        signal: i32,
        /// Kernel signal cause.
        code: i32,
        /// Kernel fault address, when supplied.
        address: Option<u64>,
        /// Application registers at the faulting instruction.
        registers: RegisterSnapshot,
    },
}

/// Diagnostics, not stable performance or release thresholds.
#[derive(Clone, Debug, Default)]
pub struct GateMetrics {
    /// Bootstrap and initial NX setup time, excluding exec-checkpoint capture.
    pub startup: Duration,
    /// Successful page-bundle admission durations.
    pub first_touch: Vec<Duration>,
    /// Pages whose original execute permission has been restored.
    pub admitted_pages: usize,
    /// Original executable pages that remain NX.
    pub untouched_pages: usize,
    /// Selected-instruction observations delivered to the caller.
    pub observations: usize,
    /// Selected candidate starts protected by the explicit coverage backend.
    pub covered_candidates: usize,
    /// Non-selected instruction heads guarded to preserve embedded bytes.
    pub collateral_guards: usize,
    /// Original collateral instructions completed without logical callbacks.
    pub collateral_completions: usize,
}

/// Work in one live-owner inspection phase, never historical report metrics.
#[derive(Clone, Debug, Default)]
pub struct OraclePhaseMetrics {
    /// Actual calls to the oracle; admitted-page revisits do not increment this.
    pub inspections: u64,
    /// Exact immutable report reuse.
    pub hits: u64,
    /// Actual mandatory terminal scans, including cache misses and corruption.
    pub runtime_scans: u64,
    /// Misses with no matching target entry.
    pub no_entry: u64,
    /// Entries whose complete facts no longer match.
    pub stale: u64,
    /// Cache integrity failures followed by RuntimeScan.
    pub corrupt: u64,
    /// Reports retaining unresolved scanner obligations, even if a separate
    /// coverage proof subsequently preserves the affected instruction streams.
    pub refused: u64,
    /// Actual decoded starts; a cache hit contributes zero.
    pub decoded_starts: u64,
    /// Exact-fact lookup, including lock acquisition; no hashing is performed.
    pub lookup_elapsed: Duration,
    /// Time in newly executed RuntimeScan calls only.
    pub fresh_scan_elapsed: Duration,
    /// Cache insertion/eviction work.
    pub store_elapsed: Duration,
    /// Saturated values are lower bounds, not exact observations.
    pub saturated: bool,
}

impl OraclePhaseMetrics {
    fn record(&mut self, inspection: &Inspection) {
        let increments = [
            (&mut self.inspections, 1),
            (
                &mut self.hits,
                u64::from(inspection.source == InspectionSource::Cache),
            ),
            (
                &mut self.runtime_scans,
                u64::from(inspection.source == InspectionSource::RuntimeScan),
            ),
            (
                &mut self.no_entry,
                u64::from(matches!(inspection.miss, Some(OracleMiss::NoEntry))),
            ),
            (
                &mut self.stale,
                u64::from(matches!(inspection.miss, Some(OracleMiss::Stale(_)))),
            ),
            (
                &mut self.corrupt,
                u64::from(matches!(inspection.miss, Some(OracleMiss::Corrupt(_)))),
            ),
            (
                &mut self.refused,
                u64::from(inspection.report.verdict() == Verdict::Refused),
            ),
            (
                &mut self.decoded_starts,
                inspection.work.decoded_starts as u64,
            ),
        ];
        for (counter, increment) in increments {
            let next = counter.checked_add(increment);
            self.saturated |= next.is_none();
            *counter = next.unwrap_or(u64::MAX);
        }
        for (total, elapsed) in [
            (&mut self.lookup_elapsed, inspection.work.lookup_elapsed),
            (
                &mut self.fresh_scan_elapsed,
                inspection.work.fresh_scan_elapsed.unwrap_or_default(),
            ),
            (&mut self.store_elapsed, inspection.work.store_elapsed),
        ] {
            let next = total.checked_add(elapsed);
            self.saturated |= next.is_none();
            *total = next.unwrap_or(Duration::MAX);
        }
    }
}

/// Preparation is explicit work before any original application resume. Demand
/// includes actual admission and the concurrent factory's clean-page preflight.
#[derive(Clone, Debug, Default)]
pub struct GateOracleMetrics {
    /// Optional same-owner scans used to seed the bounded in-memory cache.
    pub preparation: OraclePhaseMetrics,
    /// Inspections required by actual page admission and guard closure.
    pub demand: OraclePhaseMetrics,
}

/// Owns one launched task from its exec checkpoint through exit or termination.
/// Uncertain events poison the loop; dropping the owner kills and reaps it.
pub struct SingleThreadPageGate {
    process: StoppedProcess,
    oracle: GateOracle,
    application_started: bool,
    images: Vec<Image>,
    pages: BTreeMap<u64, bool>,
    sites: BTreeMap<u64, Candidate>,
    returns: CallReturnLedger,
    policy: Policy,
    pending: Option<Candidate>,
    stopped_signal: bool,
    poisoned: bool,
    timeout: Duration,
    metrics: GateMetrics,
    core: Option<CpuidPublisher>,
    selected_aliases: Option<crate::selected::SyscallAliases>,
    coverage_budget: Option<crate::trap_coverage::TrapCoverageBudget>,
    covered_guards: BTreeMap<u64, crate::trap_coverage::TrapGuard>,
    #[cfg(test)]
    coverage_failure: Option<coverage::failure::Injection>,
}

impl SingleThreadPageGate {
    /// Installs the remote control island and gates every initial executable VMA.
    /// Code without a supplied census stays NX and refuses on first touch.
    ///
    /// # Safety
    /// The caller must own the child's entire execution and mapping lifecycle.
    /// No external process, alias, device, debugger or signal sender may modify
    /// its code or access bytes being patched. Supplied heads must enumerate
    /// every executable instruction stream in their mapping, not just symbols.
    /// No code may modify executable storage through PKRU or another mechanism.
    /// Application code must not read instrumented code bytes as data or depend
    /// on their original representation; the installed INT3 byte is observable.
    /// Execution must not enter the private island or the fixed kernel vsyscall
    /// pseudo-mapping. These are outside the declared application instruction set.
    /// The caller must not independently trace or reap the child. These are
    /// closed-world certifications; `/proc` observations alone do not prove them.
    pub unsafe fn new(
        checkpoint: ExecCheckpoint,
        facts: Vec<ImageFacts>,
        policy: Policy,
        timeout: Duration,
    ) -> Result<Self, GateError> {
        let started = Instant::now();
        domain::validate_image_count(&facts)?;
        let mut process = checkpoint.into_stopped_process(timeout)?;
        let mappings = process.gate_initial_images(timeout)?;
        let pages = domain::initial_pages(&mappings)?;
        let images = domain::prepare_images(facts, &mappings, |address, len| {
            process.read_memory(address, len)
        })?;
        let metrics = GateMetrics {
            startup: started.elapsed(),
            untouched_pages: pages.len(),
            ..GateMetrics::default()
        };
        Ok(Self {
            process,
            oracle: GateOracle::new(CacheLimits::DISABLED)?,
            application_started: false,
            images,
            pages,
            sites: BTreeMap::new(),
            returns: CallReturnLedger::default(),
            policy,
            pending: None,
            stopped_signal: false,
            poisoned: false,
            timeout,
            metrics,
            core: None,
            selected_aliases: None,
            coverage_budget: None,
            covered_guards: BTreeMap::new(),
            #[cfg(test)]
            coverage_failure: None,
        })
    }

    /// Gates pages using A1 generalized puns and a remote native CPUID callback.
    /// Every selected site must admit the required tactic; there is no fallback
    /// to the trap reference. Generated mappings live until the child exits.
    ///
    /// # Safety
    /// All certifications of [`Self::new`] apply. Execution must additionally
    /// obey the System V ABI, with sufficient writable stack below the red zone
    /// for A1's extended-state frame. The target must have the emitter's exact
    /// enabled extended-state layout, with no CET or AMX use or dynamic
    /// extended-state permission changes. Instrumentation-private stack must
    /// never be read or written as application data. Generated code may be entered
    /// only through published source entries, never the callback directly.
    /// Every saved application continuation must refer
    /// to a declared instruction head; arbitrary synthetic interior resumes are
    /// forbidden. These certifications apply throughout the child's lifetime.
    pub unsafe fn new_core(
        checkpoint: ExecCheckpoint,
        facts: Vec<ImageFacts>,
        policy: Policy,
        timeout: Duration,
    ) -> Result<Self, GateError> {
        // SAFETY: this constructor forwards the same ownership certifications.
        let mut gate = unsafe { Self::new(checkpoint, facts, policy, timeout)? };
        gate.core = Some(CpuidPublisher::default());
        Ok(gate)
    }

    /// Chooses bounded in-memory reuse before any application resume or scan.
    /// The default is [`CacheLimits::DISABLED`]; every mode retains RuntimeScan.
    /// A cache cannot be imported from another owner or configured after use.
    pub fn configure_oracle(&mut self, limits: CacheLimits) -> Result<(), GateError> {
        let metrics = self.oracle.metrics.borrow();
        if self.application_started
            || metrics.preparation.inspections != 0
            || metrics.demand.inspections != 0
        {
            return Err(GateError::Refused("oracle configuration is already in use"));
        }
        drop(metrics);
        self.oracle = GateOracle::new(limits)?;
        Ok(())
    }

    /// Inspects at most 64 whole original pages over this owner's lifetime,
    /// before its first application resume. The complete batch is validated
    /// before scanning. This changes cache facts only: no code writes, execute
    /// permission, publication, CALL census or callback invocation occurs.
    /// Refused reports remain refused in the returned evidence and cache.
    /// Preparation work is distinct from subsequent demand work; this is not
    /// an offline artifact load or a cross-process cache hit.
    pub fn prepare_oracle(&mut self, pages: &[u64]) -> Result<Vec<Inspection>, GateError> {
        if self.application_started {
            return Err(GateError::Refused(
                "oracle preparation requires an unstarted owner",
            ));
        }
        domain::prepare_oracle(
            &self.oracle,
            &self.images,
            &self.pages,
            pages,
            &self.policy,
            self.timeout,
        )
    }

    /// Separate actual work before execution and during first-touch admission.
    pub fn oracle_metrics(&self) -> GateOracleMetrics {
        self.oracle.metrics()
    }

    /// Current bounded cache storage; poisoning is explicit and uses runtime fallback.
    pub fn oracle_usage(&self) -> Result<CacheUsage, CacheCorruption> {
        self.oracle.usage()
    }

    /// The owned child identifier, for diagnostics only.
    pub fn pid(&self) -> libc::pid_t {
        self.process.pid()
    }
    /// Admission/callback measurements accumulated so far.
    pub fn metrics(&self) -> &GateMetrics {
        &self.metrics
    }
    /// Potential CALL returns remain recorded even before their destination runs.
    pub fn call_returns(&self) -> &CallReturnLedger {
        &self.returns
    }
    /// Whether a particular original page has been admitted.
    pub fn is_admitted(&self, address: u64) -> bool {
        self.pages.get(&(address & !(PAGE - 1))) == Some(&true)
    }
    /// Read application memory while the owned child is stopped.
    pub fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, GateError> {
        Ok(self.process.read_memory(address, len)?)
    }
    /// Read kernel extended state at the current application stop.
    pub fn read_xstate(&self) -> Result<Vec<u8>, GateError> {
        Ok(self.process.read_xstate()?)
    }
    /// Read the stopped original register state, including after a refusal.
    pub fn read_registers(&self) -> Result<RegisterSnapshot, GateError> {
        Ok(self.process.read_registers()?)
    }

    /// Advances to one selected pre-instruction observation, exit, or unowned
    /// signal. Errors permanently close execution; dropping kills the child.
    pub fn next_event(&mut self) -> Result<GateEvent, GateError> {
        if self.poisoned || self.stopped_signal {
            return Err(GateError::Refused("execution loop is closed"));
        }
        self.application_started = true;
        let result = self.advance();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn advance(&mut self) -> Result<GateEvent, GateError> {
        let deadline = Instant::now() + self.timeout;
        if let Some(site) = self.pending.take() {
            let original = self.original_byte(site.address)?;
            let mut stop = self.process.hold()?;
            stop.write_memory_checked(site.address, &[0xcc], &[original])?;
            stop.sync_core(remaining(deadline)?)?;
            let event = stop.single_step_until_event(remaining(deadline)?)?;
            match event {
                ProcessEvent::Signal(signal)
                    if signal.signal == libc::SIGTRAP && signal.code == libc::TRAP_TRACE =>
                {
                    let mut stop = self.process.hold()?;
                    stop.acknowledge_owned_signal(&signal)?;
                    stop.write_memory_checked(site.address, &[original], &[0xcc])?;
                    stop.sync_core(remaining(deadline)?)?;
                }
                ProcessEvent::Exited { code } => return Ok(GateEvent::Exited(code)),
                ProcessEvent::Signal(signal) => return self.application_signal(signal),
                _ => {
                    return Err(GateError::Refused(
                        "selected instruction did not produce a native completion stop",
                    ));
                }
            }
        }
        loop {
            match self.process.resume_until_event(remaining(deadline)?)? {
                ProcessEvent::Exited { code } => return Ok(GateEvent::Exited(code)),
                ProcessEvent::Signaled { .. } => {
                    return Err(GateError::Refused("child terminated by signal"));
                }
                ProcessEvent::SyscallEntry { .. } | ProcessEvent::SyscallExit { .. } => continue,
                ProcessEvent::Signal(signal) => {
                    if signal.signal == libc::SIGSEGV
                        && signal.code == SEGV_ACCERR
                        && self.is_owned_fetch(&signal)?
                    {
                        self.admit(&signal, deadline)?;
                        continue;
                    }
                    if signal.signal == libc::SIGTRAP
                        && (signal.code == libc::SI_KERNEL || signal.code == libc::TRAP_BRKPT)
                    {
                        if let Some(guard) = signal
                            .instruction_pointer
                            .checked_sub(1)
                            .and_then(|pc| self.covered_guards.get(&pc))
                            .filter(|guard| {
                                matches!(
                                    guard.role(),
                                    crate::trap_coverage::TrapGuardRole::Collateral
                                )
                            })
                            .cloned()
                        {
                            if let Some(event) =
                                self.execute_collateral(&guard, &signal, deadline)?
                            {
                                return Ok(event);
                            }
                            continue;
                        }
                        if let Some(publisher) = &self.core {
                            if publisher
                                .callback_address()
                                .and_then(|pc| pc.checked_add(1))
                                == Some(signal.instruction_pointer)
                            {
                                let mut stop = self.process.hold()?;
                                let observed = publisher.observe(&mut stop, &signal)?;
                                self.metrics.observations += 1;
                                return Ok(GateEvent::Observe(Observation {
                                    site: observed.site,
                                    registers: observed.registers,
                                    xstate: observed.xstate,
                                }));
                            }
                        }
                        if let Some(site) = signal
                            .instruction_pointer
                            .checked_sub(1)
                            .and_then(|pc| self.sites.get(&pc))
                            .copied()
                        {
                            let mut stop = self.process.hold()?;
                            if stop.read_memory(site.address, 1)? != [0xcc] {
                                return Err(GateError::Refused("selected trap changed"));
                            }
                            stop.acknowledge_owned_signal(&signal)?;
                            let mut registers = stop.read_registers()?;
                            registers.rip = site.address;
                            stop.write_registers(&registers)?;
                            let xstate = stop.read_xstate()?;
                            self.pending = Some(site);
                            self.metrics.observations += 1;
                            return Ok(GateEvent::Observe(Observation {
                                site,
                                registers,
                                xstate,
                            }));
                        }
                    }
                    return self.application_signal(signal);
                }
            }
        }
    }

    fn application_signal(&mut self, signal: SignalStop) -> Result<GateEvent, GateError> {
        self.stopped_signal = true;
        Ok(GateEvent::ApplicationSignal {
            signal: signal.signal,
            code: signal.code,
            address: signal.address,
            registers: self.process.read_registers()?,
        })
    }

    fn original_byte(&self, pc: u64) -> Result<u8, GateError> {
        domain::original_byte(&self.images, pc)
    }

    fn is_owned_fetch(&self, signal: &SignalStop) -> Result<bool, GateError> {
        domain::owned_fetch(&self.images, &self.pages, signal)
    }

    fn admit(&mut self, signal: &SignalStop, deadline: Instant) -> Result<(), GateError> {
        if self.coverage_budget.is_some() {
            return self.admit_covered(signal, deadline);
        }
        let started = Instant::now();
        let address = signal
            .address
            .ok_or(GateError::Refused("missing fetch address"))?;
        let page = address & !(PAGE - 1);
        let image = self
            .images
            .iter()
            .find(|image| image.snapshot.range().contains(page))
            .ok_or(GateError::Refused("missing image facts"))?;
        let AdmissionBundle {
            pages: bundle,
            candidates,
            prepared,
        } = prepare_admission(
            (image, &self.oracle),
            page,
            &self.policy,
            &self.returns,
            self.core.as_ref(),
            self.selected_aliases.as_ref(),
            deadline,
        )?;
        for &next in &bundle {
            remaining(deadline)?;
            self.returns
                .record_before_admission(
                    &image.snapshot,
                    AddressRange::new(next, next + PAGE).unwrap(),
                    &image.entries,
                )
                .map_err(|_| GateError::Refused("CALL-return census is unresolved"))?;
            remaining(deadline)?;
        }
        let expected = domain::expected_source_bytes(image, &self.sites, self.core.as_ref());
        let mut stop = self.process.hold()?;
        stop.acknowledge_owned_signal(signal)?;
        if stop.read_memory(image.mapping.start, expected.len())? != expected {
            return Err(GateError::Refused("source changed before publication"));
        }
        let protection = libc::PROT_EXEC
            | if image.mapping.permissions.as_bytes()[0] == b'r' {
                libc::PROT_READ
            } else {
                0
            };
        if let Some(publisher) = &mut self.core {
            let prepared: Vec<_> = prepared.into_values().collect();
            if prepared.is_empty() {
                for &next in &bundle {
                    stop.mprotect(next, PAGE as usize, protection, remaining(deadline)?)?;
                }
                stop.sync_core(remaining(deadline)?)?;
            } else {
                // SAFETY: the held sole-task stop, immutable image/facts, complete
                // declared resumes and constructor ownership contract cover this
                // bundle. Publication's finalizer restores only scanned pages.
                unsafe {
                    publisher.publish_bundle(
                        &mut stop,
                        &prepared,
                        image.core_identity,
                        remaining(deadline)?,
                        |operations| {
                            for &next in &bundle {
                                operations.mprotect(
                                    next,
                                    PAGE as usize,
                                    protection,
                                    control_remaining(deadline)?,
                                )?;
                            }
                            operations.sync_core(control_remaining(deadline)?)
                        },
                    )?;
                }
            }
        } else {
            for site in candidates.values() {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    self.sites.entry(site.address)
                {
                    let original =
                        image.snapshot.bytes()[(site.address - image.mapping.start) as usize];
                    stop.write_memory_checked(site.address, &[original], &[0xcc])?;
                    entry.insert(*site);
                }
            }
            for &next in &bundle {
                stop.mprotect(next, PAGE as usize, protection, remaining(deadline)?)?;
            }
            stop.sync_core(remaining(deadline)?)?;
        }
        for next in bundle {
            if self.pages.insert(next, true) == Some(false) {
                self.metrics.admitted_pages += 1;
                self.metrics.untouched_pages -= 1;
            }
        }
        self.metrics.first_touch.push(started.elapsed());
        Ok(())
    }
}

fn control_remaining(deadline: Instant) -> Result<Duration, LaunchError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(LaunchError::Timeout("whole-event deadline"))
}
