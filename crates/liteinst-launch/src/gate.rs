//! First-touch page gating with separate A1 and ptrace-reference CPUID paths.
//!
//! The single-task gate offers a slow native SINGLESTEP reference and a native
//! replacement callback through A1. The concurrent gate registers a fixed set
//! of real shared-mm workers and publishes under collective stopped exclusion.
//! Both require declared immutable code. Other selected classes remain explicit
//! prepublication refusals; general lifecycle support is outside this module.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use iced_x86::{Decoder, DecoderOptions};
use liteinst_admission::entries::{Completeness, EntryProvenance, LegalEntrySet};
use liteinst_admission::returns::CallReturnLedger;
use liteinst_admission::scan::{
    AdmissionOracle, Boundary, Candidate, Policy, RuntimeScan, Snapshot, Verdict, WriteControl,
};
use liteinst_admission::{AddressRange, Generation, MappingId};
use liteinst2::contracts as core;
use liteinst2::quiescent::AllocationPolicy;

use crate::core_remote::{CpuidPlanRequest, CpuidPublisher, MAX_CPUID_BUNDLE, PreparedCpuid};

mod concurrent;
pub use concurrent::*;

mod selected;
pub use selected::*;

use crate::{
    ExecCheckpoint, LaunchError, MemoryMapping, ProcessEvent, RegisterSnapshot, SignalStop,
    StoppedProcess,
};

const PAGE: u64 = 4096;
const SEGV_ACCERR: i32 = 2;
const MAX_IMAGES: usize = 64;
const MAX_IMAGE_BYTES: usize = 64 * 1024;
const MAX_GATED_PAGES: u64 = 16 * 1024;
static NEXT_IMAGE_ID: AtomicU64 = AtomicU64::new(1);

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
}

struct Image {
    mapping: MemoryMapping,
    snapshot: Snapshot,
    entries: LegalEntrySet,
    core_identity: core::CodeIdentity,
}

/// Owns one launched task from its exec checkpoint through exit or termination.
/// Uncertain events poison the loop; dropping the owner kills and reaps it.
pub struct SingleThreadPageGate {
    process: StoppedProcess,
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
        if facts.len() > MAX_IMAGES {
            return Err(GateError::Refused("too many image censuses"));
        }
        let mut process = checkpoint.into_stopped_process(timeout)?;
        let mappings = process.gate_initial_images(timeout)?;
        let page_count = mappings.iter().try_fold(0_u64, |count, mapping| {
            count.checked_add((mapping.end - mapping.start) / PAGE)
        });
        if mappings.len() > MAX_IMAGES || page_count.is_none_or(|count| count > MAX_GATED_PAGES) {
            return Err(GateError::Refused(
                "initial executable mapping budget exceeded",
            ));
        }
        let mut pages = BTreeMap::new();
        for mapping in &mappings {
            if mapping.start % PAGE != 0
                || mapping.end % PAGE != 0
                || mapping.permissions.as_bytes().get(1) == Some(&b'w')
                || mapping.permissions.as_bytes().get(3) != Some(&b'p')
            {
                return Err(GateError::Refused(
                    "requires page-aligned private non-writable code",
                ));
            }
            for address in (mapping.start..mapping.end).step_by(PAGE as usize) {
                pages.insert(address, false);
            }
        }
        let census_starts: BTreeSet<_> = facts.iter().map(|fact| fact.start).collect();
        let mut images = Vec::new();
        for fact in facts {
            let mapping = mappings
                .iter()
                .find(|m| m.start == fact.start && m.end - m.start == fact.bytes.len() as u64)
                .ok_or(GateError::Refused(
                    "census must cover exactly one original executable VMA",
                ))?
                .clone();
            if fact.bytes.len() > MAX_IMAGE_BYTES
                || images
                    .iter()
                    .any(|image: &Image| image.mapping.start == fact.start)
            {
                return Err(GateError::Refused("oversized or duplicate census"));
            }
            if process.read_memory(fact.start, fact.bytes.len())? != fact.bytes {
                return Err(GateError::Refused("original image bytes differ"));
            }
            // Adjacent admitted VMAs require a cross-mapping proof. A neighbor
            // with no census stays NX for this owner's whole lifetime: facts
            // cannot be added later and every first touch there is refused.
            if mappings.iter().any(|m| {
                census_starts.contains(&m.start)
                    && (m.end == mapping.start || m.start == mapping.end)
            }) {
                return Err(GateError::Refused(
                    "adjacent executable VMAs need a joint census",
                ));
            }
            let identity = MappingId(images.len() as u64 + 1);
            let snapshot = Snapshot::new(
                identity,
                Generation(0),
                fact.start,
                fact.bytes,
                Boundary::NonExecutable,
                Boundary::NonExecutable,
                WriteControl::Owned,
            )
            .ok_or(GateError::Refused("invalid census range"))?;
            let entries = LegalEntrySet::new(
                identity,
                Generation(0),
                0,
                snapshot.range(),
                Completeness::AllInstructionHeads,
                fact.heads
                    .into_iter()
                    .map(|pc| (pc, EntryProvenance::VerifiedInstruction)),
                [],
            )
            .map_err(|_| GateError::Refused("instruction head outside mapping"))?;
            images.push(Image {
                mapping,
                snapshot,
                entries,
                core_identity: new_core_identity()?,
            });
        }
        let metrics = GateMetrics {
            startup: started.elapsed(),
            untouched_pages: pages.len(),
            ..GateMetrics::default()
        };
        Ok(Self {
            process,
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
        self.images
            .iter()
            .find(|image| image.snapshot.range().contains(pc))
            .map(|image| image.snapshot.bytes()[(pc - image.mapping.start) as usize])
            .ok_or(GateError::Refused("no original source byte"))
    }

    fn is_owned_fetch(&self, signal: &SignalStop) -> Result<bool, GateError> {
        let Some(address) = signal.address else {
            return Ok(false);
        };
        if self.pages.get(&(address & !(PAGE - 1))) != Some(&false) {
            return Ok(false);
        }
        let Some(image) = self
            .images
            .iter()
            .find(|image| image.snapshot.range().contains(signal.instruction_pointer))
        else {
            return Err(GateError::Refused("first touch has no complete census"));
        };
        if !image
            .entries
            .heads()
            .contains_key(&signal.instruction_pointer)
        {
            return Err(GateError::Refused("first touch at an undeclared head"));
        }
        let offset = (signal.instruction_pointer - image.mapping.start) as usize;
        let instruction = Decoder::with_ip(
            64,
            &image.snapshot.bytes()[offset..],
            signal.instruction_pointer,
            DecoderOptions::NONE,
        )
        .decode();
        Ok(!instruction.is_invalid()
            && address >= instruction.ip()
            && address < instruction.next_ip())
    }

    fn admit(&mut self, signal: &SignalStop, deadline: Instant) -> Result<(), GateError> {
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
            image,
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
        let mut expected = image.snapshot.bytes().to_vec();
        for (&pc, _) in self.sites.range(image.snapshot.range().as_range()) {
            expected[(pc - image.mapping.start) as usize] = 0xcc;
        }
        if let Some(publisher) = &self.core {
            for installed in publisher.installed() {
                for edit in &installed.plan().parts().writes {
                    if image.snapshot.range().contains(edit.address) {
                        let offset = (edit.address - image.mapping.start) as usize;
                        expected[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
                    }
                }
            }
        }
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

struct AdmissionBundle {
    pages: BTreeSet<u64>,
    candidates: BTreeMap<u64, Candidate>,
    prepared: BTreeMap<u64, PreparedCpuid>,
}

fn prepare_admission(
    image: &Image,
    page: u64,
    policy: &Policy,
    returns: &CallReturnLedger,
    publisher: Option<&CpuidPublisher>,
    selected_aliases: Option<&crate::selected::SyscallAliases>,
    deadline: Instant,
) -> Result<AdmissionBundle, GateError> {
    // Close over complete pages required by every selected straddler.
    // Granting X to a halo without scanning its entire page is forbidden.
    let mut bundle = BTreeSet::from([page]);
    let mut scanned = BTreeSet::new();
    let mut candidates = BTreeMap::new();
    let mut prepared = BTreeMap::new();
    while let Some(next) = bundle.difference(&scanned).next().copied() {
        remaining(deadline)?;
        if !image
            .snapshot
            .range()
            .covers(AddressRange::new(next, next + PAGE).unwrap())
        {
            return Err(GateError::Refused(
                "selected instruction crosses image census",
            ));
        }
        let target = AddressRange::new(next, next + PAGE).unwrap();
        let report = RuntimeScan.inspect(&image.snapshot, target, &image.entries, policy);
        remaining(deadline)?;
        if report.verdict() == Verdict::Refused {
            return Err(GateError::Scan(report.obligations().to_vec()));
        }
        // NX history is never an exhaustive proof that no resumes exist.
        if !report.candidates().is_empty()
            && returns.obligations_in(report.dependency()).next().is_some()
        {
            return Err(GateError::Refused(
                "potential saved CALL return intersects selected publication",
            ));
        }
        for site in report.candidates() {
            remaining(deadline)?;
            if let Some(aliases) = selected_aliases {
                let start = (site.address - image.mapping.start) as usize;
                let end = start + usize::from(site.len);
                let decoded = crate::selected::decode(
                    site.address,
                    &image.snapshot.bytes()[start..end],
                    aliases,
                )?;
                if decoded.bytes().len() != usize::from(site.len)
                    || decoded.operation().class() != site.class
                {
                    return Err(GateError::Refused("selected decode differs from scan"));
                }
            } else if site.class != liteinst_admission::scan::SiteClass::Cpuid {
                return Err(GateError::Refused(
                    "selected class lacks reference single-step qualification",
                ));
            }
            candidates.insert(site.address, *site);
            bundle.insert(site.address & !(PAGE - 1));
            bundle.insert((site.address + u64::from(site.len) - 1) & !(PAGE - 1));
            if let Some(publisher) = publisher {
                if !publisher
                    .installed()
                    .iter()
                    .any(|installed| installed.plan().parts().logical_pc == site.address)
                    && !prepared.contains_key(&site.address)
                {
                    if prepared.len() == MAX_CPUID_BUNDLE {
                        return Err(GateError::Refused(
                            "core publication bundle budget exceeded",
                        ));
                    }
                    let plan = prepare_cpuid(image, *site)?;
                    remaining(deadline)?;
                    let consumed = plan.consumed();
                    bundle.insert(consumed.start() & !(PAGE - 1));
                    bundle.insert((consumed.end() - 1) & !(PAGE - 1));
                    prepared.insert(site.address, plan);
                }
            }
        }
        scanned.insert(next);
    }
    Ok(AdmissionBundle {
        pages: bundle,
        candidates,
        prepared,
    })
}

fn new_core_identity() -> Result<core::CodeIdentity, GateError> {
    let nonce = NEXT_IMAGE_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| GateError::Refused("image identity space exhausted"))?;
    let mut source = [0; 32];
    source[..8].copy_from_slice(b"li2image");
    source[8..16].copy_from_slice(&nonce.to_le_bytes());
    // This is a non-reused owner key bound to an immutable image and policy,
    // not a content hash. Publication always authenticates exact bytes too.
    Ok(core::CodeIdentity {
        source: core::SourceIdentity(source),
        mapping: nonce,
        generation: 0,
    })
}

fn prepare_cpuid(image: &Image, site: Candidate) -> Result<PreparedCpuid, GateError> {
    let offset = (site.address - image.mapping.start) as usize;
    let mut decoder = Decoder::with_ip(
        64,
        &image.snapshot.bytes()[offset..],
        site.address,
        DecoderOptions::NONE,
    );
    while decoder.ip() < site.address + 5 {
        if !image.entries.heads().contains_key(&decoder.ip()) {
            return Err(GateError::Refused(
                "pun dependency lacks a verified instruction head",
            ));
        }
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err(GateError::Refused(
                "pun dependency is not complete instructions",
            ));
        }
    }
    let size = (decoder.ip() - site.address) as usize;
    let entries = core::LegalEntrySet {
        identity: image.core_identity,
        scope: core::AddressRange::new(image.mapping.start, image.snapshot.bytes().len())
            .map_err(GateError::Core)?,
        provenance: core::EntryProvenance::Declared(
            "immutable launch instruction-head census".into(),
        ),
        completeness: core::EntryCompleteness::AllInstructionHeads,
        entries: image
            .entries
            .heads()
            .keys()
            .map(|&address| core::LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        // A conservative superset: the unsafe constructor certifies that any
        // saved continuation is a declared head. NX history proves nothing.
        resumes: core::ResumeObligation::Enumerated(
            image.entries.heads().keys().copied().collect(),
        ),
    };
    let allocation = AllocationPolicy::near(site.address).map_err(GateError::Core)?;
    PreparedCpuid::prepare(CpuidPlanRequest {
        identity: image.core_identity,
        address: site.address,
        code: &image.snapshot.bytes()[offset..offset + size],
        entries: &entries,
        allocation: &allocation,
    })
    .map_err(GateError::Core)
}

fn control_remaining(deadline: Instant) -> Result<Duration, LaunchError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(LaunchError::Timeout("whole-event deadline"))
}

fn remaining(deadline: Instant) -> Result<Duration, GateError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(GateError::Refused("whole-event deadline exhausted"))
}
