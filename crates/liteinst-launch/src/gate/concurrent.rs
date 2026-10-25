//! Fixed-membership cooperative admission of a shared address space.

use super::*;
use std::collections::VecDeque;

use crate::publication::PublicationStop;
use crate::{SharedMmProcess, TaskEvent};

/// Bounded native worker registration performed by a declared factory page.
#[derive(Clone, Copy, Debug)]
pub struct ConcurrentConfig {
    /// Number of checked native clone workers, from two through eight.
    pub worker_count: usize,
    /// Original INT3 at which the factory leader remains held permanently.
    pub freeze_pc: u64,
}

/// One logical event while every registered task remains stopped.
#[derive(Clone, Debug)]
pub enum ConcurrentEvent {
    /// One worker is about to execute the original native CPUID semantics.
    Observe {
        /// Kernel worker task identifier.
        tid: libc::pid_t,
        /// Authenticated original instruction and saved state.
        observation: Box<Observation>,
    },
    /// One worker has exited and been reaped.
    WorkerExited {
        /// Kernel worker task identifier.
        tid: libc::pid_t,
        /// Native exit status.
        code: i32,
    },
    /// All workers exited; the permanently held factory was killed and reaped.
    Complete,
}

/// Diagnostics for the fixed-membership concurrent gate.
#[derive(Clone, Debug, Default)]
pub struct ConcurrentMetrics {
    /// Common initial gating, page admission and observation measurements.
    pub gate: GateMetrics,
    /// First observed worker stop through verified all-worker exclusion, per epoch.
    pub rendezvous: Vec<Duration>,
    /// Authenticated pending NX faults collected before any publication, per epoch.
    pub faults_per_rendezvous: Vec<usize>,
    /// Successful transactions containing selected A1 plans; clean pages excluded.
    pub publication_bundles: usize,
}

/// Real shared-mm workers with bounded cooperative all-task rendezvous.
///
/// Every runnable worker must reach a ptrace fault/syscall stop within the one
/// event deadline. A worker which does not cooperate terminates the whole owner.
/// Membership is frozen before worker execution; this is not general lifecycle
/// or application-signal support.
pub struct ConcurrentPageGate {
    process: Option<SharedMmProcess>,
    pid: libc::pid_t,
    worker_ids: Vec<libc::pid_t>,
    images: Vec<Image>,
    pages: BTreeMap<u64, bool>,
    returns: CallReturnLedger,
    policy: Policy,
    publisher: CpuidPublisher,
    metrics: ConcurrentMetrics,
    pending: VecDeque<ConcurrentEvent>,
    timeout: Duration,
    poisoned: bool,
    complete: bool,
}

impl ConcurrentPageGate {
    /// Gates the initial image, admits its clean factory page, and registers all
    /// workers before any worker executes its first original instruction.
    ///
    /// # Safety
    /// All [`SingleThreadPageGate::new_core`] certifications apply to the whole
    /// shared address space and every worker. The entry page must be a complete
    /// declared factory without selected instructions. It executes exactly the
    /// checked clone sequence accepted by [`SharedMmProcess::register`], followed
    /// by `config.freeze_pc`'s INT3 on that same page. Workers use distinct private
    /// writable stacks and execute only declared heads. The leader never resumes
    /// after registration. No worker may read or write instrumentation-private
    /// frames, including another worker's frames, or inspect private code as
    /// application data. Every worker must reach a bounded cooperative stop, and no other
    /// tracer, reaper, external reader/writer or alias may enter the owned domain.
    pub unsafe fn new(
        checkpoint: ExecCheckpoint,
        facts: Vec<ImageFacts>,
        policy: Policy,
        config: ConcurrentConfig,
        timeout: Duration,
    ) -> Result<Self, GateError> {
        let started = Instant::now();
        let deadline = started + timeout;
        // SAFETY: the caller supplies the complete core owner certifications.
        let mut gate =
            unsafe { SingleThreadPageGate::new_core(checkpoint, facts, policy, timeout)? };
        let event = gate.process.resume_until_event(remaining(deadline)?)?;
        let ProcessEvent::Signal(signal) = event else {
            return Err(GateError::Refused("factory did not first enter an NX page"));
        };
        if signal.signal != libc::SIGSEGV
            || signal.code != SEGV_ACCERR
            || !gate.is_owned_fetch(&signal)?
        {
            return Err(GateError::Refused("factory first fetch is not owned"));
        }
        let page = signal.instruction_pointer & !(PAGE - 1);
        if config.freeze_pc & !(PAGE - 1) != page {
            return Err(GateError::Refused(
                "factory freeze must share its initial page",
            ));
        }
        let image = gate
            .images
            .iter()
            .find(|image| image.snapshot.range().contains(page))
            .ok_or(GateError::Refused("factory has no census"))?;
        let report = RuntimeScan.inspect(
            &image.snapshot,
            AddressRange::new(page, page + PAGE).unwrap(),
            &image.entries,
            &gate.policy,
        );
        if report.verdict() != Verdict::Clean
            || !image.entries.heads().contains_key(&config.freeze_pc)
        {
            return Err(GateError::Refused(
                "factory page must be clean with a declared freeze head",
            ));
        }
        gate.admit(&signal, deadline)?;
        let SingleThreadPageGate {
            process,
            images,
            pages,
            returns,
            policy,
            core,
            metrics,
            ..
        } = gate;
        // SAFETY: only the scanned factory page has been admitted; the caller
        // certifies its fixed clone sequence and worker ownership requirements.
        let process = unsafe {
            SharedMmProcess::register(
                process,
                config.worker_count,
                config.freeze_pc,
                remaining(deadline)?,
            )?
        };
        let pid = process.pid();
        let worker_ids = process.worker_ids();
        let mut metrics = ConcurrentMetrics {
            gate: metrics,
            ..ConcurrentMetrics::default()
        };
        metrics.gate.startup = started.elapsed();
        Ok(Self {
            process: Some(process),
            pid,
            worker_ids,
            images,
            pages,
            returns,
            policy,
            publisher: core.expect("new_core always constructs its publisher"),
            metrics,
            pending: VecDeque::new(),
            timeout,
            poisoned: false,
            complete: false,
        })
    }

    /// Original thread-group identifier, retained after cleanup for diagnostics.
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }
    /// All registered worker identifiers, including workers which later exited.
    pub fn worker_ids(&self) -> &[libc::pid_t] {
        &self.worker_ids
    }
    /// Recorded admission, exactly-once publication and rendezvous measurements.
    pub fn metrics(&self) -> &ConcurrentMetrics {
        &self.metrics
    }
    /// Whether an original page has been admitted under this generation.
    pub fn is_admitted(&self, address: u64) -> bool {
        self.pages.get(&(address & !(PAGE - 1))) == Some(&true)
    }
    /// Reads shared memory while the whole execution owner remains held.
    pub fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, GateError> {
        Ok(self
            .process
            .as_ref()
            .ok_or(GateError::Refused("concurrent owner is complete"))?
            .read_memory(address, len)?)
    }
    /// Retained conservative CALL-return obligations across all admitted pages.
    pub fn call_returns(&self) -> &CallReturnLedger {
        &self.returns
    }

    /// Runs all live workers to their next collective stop, publishes any new
    /// page bundles once, and returns the next immutable logical event.
    pub fn next_event(&mut self) -> Result<ConcurrentEvent, GateError> {
        if self.poisoned || self.complete {
            return Err(GateError::Refused("concurrent execution loop is closed"));
        }
        if let Some(event) = self.dequeue() {
            return Ok(event);
        }
        let result = self.advance();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn advance(&mut self) -> Result<ConcurrentEvent, GateError> {
        let deadline = Instant::now() + self.timeout;
        loop {
            let process = self
                .process
                .as_mut()
                .ok_or(GateError::Refused("concurrent owner is complete"))?;
            let events = process.resume_workers_until_all_stopped(remaining(deadline)?)?;
            self.metrics
                .rendezvous
                .push(process.last_rendezvous_duration());
            let mut faults = Vec::new();
            let mut callback_pcs = BTreeMap::new();
            for TaskEvent { tid, event } in events {
                remaining(deadline)?;
                match event {
                    ProcessEvent::Signal(signal) => {
                        if signal.signal == libc::SIGTRAP
                            && self
                                .publisher
                                .callback_address()
                                .and_then(|pc| pc.checked_add(1))
                                == Some(signal.instruction_pointer)
                        {
                            let observed = self
                                .publisher
                                .observe(&mut process.hold_for(tid)?, &signal)?;
                            callback_pcs.insert(tid, observed.site.address);
                            self.pending.push_back(ConcurrentEvent::Observe {
                                tid,
                                observation: Box::new(Observation {
                                    site: observed.site,
                                    registers: observed.registers,
                                    xstate: observed.xstate,
                                }),
                            });
                        } else if signal.signal == libc::SIGSEGV
                            && signal.code == SEGV_ACCERR
                            && owned_fetch(&self.images, &self.pages, &signal)?
                        {
                            faults.push((tid, signal));
                        } else {
                            return Err(GateError::Refused(
                                "unowned concurrent application signal",
                            ));
                        }
                    }
                    ProcessEvent::Exited { code } => self
                        .pending
                        .push_back(ConcurrentEvent::WorkerExited { tid, code }),
                    ProcessEvent::SyscallEntry { .. } | ProcessEvent::SyscallExit { .. } => {}
                    ProcessEvent::Signaled { .. } => {
                        return Err(GateError::Refused("concurrent worker died from signal"));
                    }
                }
            }
            // Account for every current worker PC, including syscall-return
            // stops and logical PCs represented by authenticated callback frames.
            for (tid, registers) in process.stopped_registers()? {
                let pc = callback_pcs.get(&tid).copied().unwrap_or(registers.rip);
                if !self
                    .images
                    .iter()
                    .any(|image| image.entries.heads().contains_key(&pc))
                {
                    return Err(GateError::Refused(
                        "concurrent saved PC is not a declared head",
                    ));
                }
            }
            self.metrics.faults_per_rendezvous.push(faults.len());
            for (tid, signal) in faults {
                let page = signal
                    .address
                    .ok_or(GateError::Refused("missing concurrent fetch address"))?
                    & !(PAGE - 1);
                if self.pages.get(&page) == Some(&true) {
                    // This stop predates the already completed same-bundle
                    // publication. Consume that ready generation without writes.
                    self.process
                        .as_mut()
                        .unwrap()
                        .hold_for(tid)?
                        .acknowledge_owned_signal(&signal)?;
                } else {
                    self.admit(tid, &signal, deadline)?;
                }
            }
            if self.process.as_ref().unwrap().live_worker_count() == 0 {
                self.process.take().unwrap().terminate()?;
                self.pending.push_back(ConcurrentEvent::Complete);
            }
            if let Some(event) = self.dequeue() {
                return Ok(event);
            }
        }
    }

    fn dequeue(&mut self) -> Option<ConcurrentEvent> {
        let event = self.pending.pop_front()?;
        match &event {
            ConcurrentEvent::Observe { .. } => self.metrics.gate.observations += 1,
            ConcurrentEvent::Complete => self.complete = true,
            ConcurrentEvent::WorkerExited { .. } => {}
        }
        Some(event)
    }

    fn admit(
        &mut self,
        tid: libc::pid_t,
        signal: &SignalStop,
        deadline: Instant,
    ) -> Result<(), GateError> {
        let started = Instant::now();
        let page = signal
            .address
            .ok_or(GateError::Refused("missing concurrent fetch address"))?
            & !(PAGE - 1);
        let image = self
            .images
            .iter()
            .find(|image| image.snapshot.range().contains(page))
            .ok_or(GateError::Refused("missing concurrent image facts"))?;
        let bundle = prepare_admission(
            image,
            page,
            &self.policy,
            &self.returns,
            Some(&self.publisher),
            None,
            deadline,
        )?;
        for &next in &bundle.pages {
            remaining(deadline)?;
            self.returns
                .record_before_admission(
                    &image.snapshot,
                    AddressRange::new(next, next + PAGE).unwrap(),
                    &image.entries,
                )
                .map_err(|_| GateError::Refused("concurrent CALL-return census unresolved"))?;
        }
        let mut expected = image.snapshot.bytes().to_vec();
        for installed in self.publisher.installed() {
            for edit in &installed.plan().parts().writes {
                if image.snapshot.range().contains(edit.address) {
                    let offset = (edit.address - image.mapping.start) as usize;
                    expected[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
                }
            }
        }
        let mut stop = self.process.as_mut().unwrap().hold_for(tid)?;
        stop.acknowledge_owned_signal(signal)?;
        if stop.read_memory(image.mapping.start, expected.len())? != expected {
            return Err(GateError::Refused(
                "concurrent source changed before publication",
            ));
        }
        let protection = libc::PROT_EXEC
            | if image.mapping.permissions.as_bytes()[0] == b'r' {
                libc::PROT_READ
            } else {
                0
            };
        let prepared: Vec<_> = bundle.prepared.into_values().collect();
        if prepared.is_empty() {
            let ranges = vec![
                core::AddressRange::new(image.mapping.start, expected.len())
                    .map_err(GateError::Core)?,
            ];
            // SAFETY: the same full-domain owner certifications and all-task
            // exclusion cover clean admission; no source bytes are modified.
            unsafe {
                stop.with_publication_lease(image.core_identity, ranges, |operations, _lease| {
                    for &next in &bundle.pages {
                        operations.mprotect(
                            next,
                            PAGE as usize,
                            protection,
                            control_remaining(deadline)?,
                        )?;
                    }
                    operations.sync_core(control_remaining(deadline)?)
                })?;
            }
        } else {
            // SAFETY: all registered tasks remain stopped under this actual
            // all-thread borrow; complete entry/resume and external exclusion
            // certifications remain bound to this immutable source generation.
            unsafe {
                self.publisher.publish_bundle(
                    &mut stop,
                    &prepared,
                    image.core_identity,
                    remaining(deadline)?,
                    |operations| {
                        for &next in &bundle.pages {
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
            self.metrics.publication_bundles += 1;
        }
        for next in bundle.pages {
            if self.pages.insert(next, true) == Some(false) {
                self.metrics.gate.admitted_pages += 1;
                self.metrics.gate.untouched_pages -= 1;
            }
        }
        self.metrics.gate.first_touch.push(started.elapsed());
        Ok(())
    }
}

fn owned_fetch(
    images: &[Image],
    pages: &BTreeMap<u64, bool>,
    signal: &SignalStop,
) -> Result<bool, GateError> {
    let Some(address) = signal.address else {
        return Ok(false);
    };
    if pages.get(&(address & !(PAGE - 1))) != Some(&false) {
        return Ok(false);
    }
    let image = images
        .iter()
        .find(|image| image.snapshot.range().contains(signal.instruction_pointer))
        .ok_or(GateError::Refused("concurrent first touch has no census"))?;
    if !image
        .entries
        .heads()
        .contains_key(&signal.instruction_pointer)
    {
        return Err(GateError::Refused(
            "concurrent first touch is not a declared head",
        ));
    }
    let offset = (signal.instruction_pointer - image.mapping.start) as usize;
    let instruction = Decoder::with_ip(
        64,
        &image.snapshot.bytes()[offset..],
        signal.instruction_pointer,
        DecoderOptions::NONE,
    )
    .decode();
    Ok(!instruction.is_invalid() && address >= instruction.ip() && address < instruction.next_ip())
}
