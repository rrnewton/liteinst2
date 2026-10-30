//! Exclusive finite inline clock. All callable source addresses remain private.
//! Worker lease + begin_call exclude concurrency/reentry BEFORE the first spill.
use super::*;
use counter::{MAX_STOPS, Memory, Stop, WAIT};
use liteinst2::backedge_clock::{
    BackedgeClock, BackedgeClockAction, CLOCK_CANARY, ClockGateLayout, ClockMode, ClockWords,
};
use liteinst2::controls::ControlIdentity;
use liteinst2::quiescent::plan_backedge_clock_detailed;
use liteinst2::trampoline::HookContext;
use std::cell::Cell;
use std::io::Write;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

mod rendezvous;
use rendezvous::Error as HandoffError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Transport {
    Channels,
    Spsc,
}
impl Transport {
    pub(super) fn profile(self) -> &'static str {
        match self {
            Self::Channels => "inline-clock-v1",
            Self::Spsc => "inline-clock-spsc-v1",
        }
    }
    pub(super) fn command_prefix(self) -> &'static str {
        match self {
            Self::Channels => "inline",
            Self::Spsc => "inline-spsc",
        }
    }
    fn channel(self) -> (WorkerTransport, ControllerTransport) {
        match self {
            Self::Channels => {
                let (events_tx, events_rx) = mpsc::sync_channel(1);
                let (resume_tx, resume_rx) = mpsc::sync_channel(1);
                (
                    WorkerTransport::Channels(events_tx, resume_rx),
                    ControllerTransport::Channels(events_rx, resume_tx),
                )
            }
            Self::Spsc => {
                let (worker, controller) = rendezvous::channel();
                (
                    WorkerTransport::Spsc(worker),
                    ControllerTransport::Spsc(controller),
                )
            }
        }
    }
}
fn receive_error(error: mpsc::RecvTimeoutError) -> HandoffError {
    match error {
        mpsc::RecvTimeoutError::Disconnected => HandoffError::Disconnected,
        mpsc::RecvTimeoutError::Timeout => HandoffError::Timeout,
    }
}
enum WorkerTransport {
    Channels(mpsc::SyncSender<Stop>, mpsc::Receiver<(u64, u64)>),
    Spsc(rendezvous::Worker),
}
impl WorkerTransport {
    fn exchange(&mut self, event: Stop) -> Result<(u64, u64), HandoffError> {
        match self {
            Self::Channels(events, resumes) => {
                events.send(event).map_err(|_| HandoffError::Disconnected)?;
                resumes.recv_timeout(WAIT).map_err(receive_error)
            }
            Self::Spsc(worker) => worker.exchange(event, WAIT),
        }
    }
}
enum ControllerTransport {
    Channels(mpsc::Receiver<Stop>, mpsc::SyncSender<(u64, u64)>),
    Spsc(rendezvous::Controller),
}
enum Received<'a> {
    Channels(Stop, &'a mpsc::SyncSender<(u64, u64)>),
    Spsc(rendezvous::Event<'a>),
}
impl ControllerTransport {
    fn receive(&mut self) -> Result<Received<'_>, HandoffError> {
        match self {
            Self::Channels(events, resumes) => events
                .recv_timeout(WAIT)
                .map(|event| Received::Channels(event, resumes))
                .map_err(receive_error),
            Self::Spsc(controller) => controller.receive(WAIT).map(Received::Spsc),
        }
    }
}
impl Received<'_> {
    fn stop(&self) -> &Stop {
        match self {
            Self::Channels(event, _) => event,
            Self::Spsc(event) => event.stop(),
        }
    }
    fn resume(self, site: u64, count: u64) -> Result<Stop, HandoffError> {
        match self {
            Self::Channels(event, resumes) => {
                resumes
                    .send((site, count))
                    .map_err(|_| HandoffError::Disconnected)?;
                Ok(event)
            }
            Self::Spsc(event) => event.resume(site, count),
        }
    }
}

pub(super) struct InlineProgram {
    pub(super) inner: Program,
    pub(super) clock: BackedgeClock,
    pub(super) gate: ClockGateLayout,
    pub(super) image: (u64, usize),
    mode: ClockMode,
    transport: Transport,
}
// The two page spans are disjoint owners: process-lived source + owned RW clock.
// Their initial adjacency supplies a bounded RIP-relative clock operand without
// widening executable allocation/search caps. No source entry escapes this module.
fn mapped_pair(bytes: &[u8]) -> (Mapping, BackedgeClock) {
    assert!(!bytes.is_empty() && bytes.len() <= 4096);
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            8192,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(p, libc::MAP_FAILED);
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), p.cast(), bytes.len()) };
    let source = Mapping {
        address: p as usize as u64,
        original: bytes.to_vec(),
    };
    let clock = unsafe { BackedgeClock::from_owned_mapping(source.address + 4096, 4096) }
        .expect("independent adjacent RW clock ownership");
    source.protect(libc::PROT_READ | libc::PROT_EXEC).unwrap();
    (source, clock)
}
impl InlineProgram {
    pub(super) fn new(case: Case, mode: ClockMode) -> Self {
        Self::with_transport(case, mode, Transport::Channels)
    }
    pub(super) fn with_transport(case: Case, mode: ClockMode, transport: Transport) -> Self {
        single_main();
        let bytes = case.bytes();
        let native = Mapping::new(&bytes);
        let (candidate, clock) = mapped_pair(&bytes);
        assert_eq!(native.bytes(), candidate.bytes());
        let base = candidate.address;
        let site = corpus::admit(&bytes, base).expect("whole authored function admission");
        let identity = CodeIdentity {
            source: SourceIdentity([case as u8 + 1; 32]),
            mapping: base,
            generation: 1,
        };
        let scope = AddressRange::new(base, bytes.len()).unwrap();
        let entries = LegalEntrySet { identity,scope,provenance:EntryProvenance::Declared("complete decoded heads of private authored call-free function; no external entry or saved resume".into()),completeness:EntryCompleteness::Complete,
            entries:site.heads.iter().map(|&address| LegalEntry { address,requires_endbr:false }).collect(),resumes:ResumeObligation::NoneExist };
        let (control, writer) = ProbeControl::new_managed_bound(hook, true);
        let pc = base + site.offset as u64;
        let allocation = AllocationPolicy::near(pc).unwrap();
        assert_eq!(
            (
                allocation.max_candidates,
                allocation.max_mappings,
                allocation.max_mapped_bytes
            ),
            (256, 1, 8192)
        );
        let action = BackedgeClockAction::new(
            identity,
            base,
            &bytes,
            pc,
            (control.clone(), writer),
            clock.clone(),
            mode,
        )
        .expect("exact clock/source/control");
        let planned = plan_backedge_clock_detailed(
            &InstallRequest {
                identity,
                code: &bytes,
                base_address: base,
                function: scope,
                block: AddressRange::new(pc, site.length).unwrap(),
                logical_pc: pc,
                entries: &entries,
                hook: unused_hook,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::RelocationOnly,
                    max_upstream_bytes: 0,
                    max_displaced_bytes: 15,
                    max_sites: 1,
                },
            },
            &action,
        )
        .expect("required real branch instrumentation refused");
        assert_eq!(planned.plan().parts().kind, PlanKind::Relocation);
        assert_eq!(planned.plan().parts().physical_pc, pc);
        assert_eq!(
            planned.plan().parts().displaced,
            AddressRange::new(pc, site.length).unwrap()
        );
        assert!(!planned.plan().parts().requirements.sigill_router);
        assert!(
            planned
                .plan()
                .parts()
                .obligations
                .iter()
                .all(|o| matches!(o, EntryObligation::Preserved(_)))
        );
        assert_eq!(planned.image().controls(), std::slice::from_ref(&control));
        let image = (planned.image().address(), planned.image().bytes().len());
        let gate = planned
            .image()
            .clock_gate()
            .expect("inline gate boundaries");
        assert_eq!(planned.image().clock(), Some(&clock));
        let ranges: Vec<_> = planned
            .plan()
            .parts()
            .dependencies
            .iter()
            .copied()
            .chain(planned.plan().parts().allocations.iter().map(|a| a.range))
            .collect();
        candidate
            .protect(libc::PROT_READ | libc::PROT_WRITE)
            .unwrap();
        let mut result = Program {
            native,
            candidate,
            site,
            identity,
            control,
            installed: None,
            ranges,
        };
        let (installed, receipt) = {
            // SAFETY: this exclusive program owns the entire private source,
            // complete heads and no resumes; only the current main thread exists.
            // No callable pointer is handed to a worker until the final RX store,
            // exact publisher checks and this lease have completed.
            let address = result.candidate.address;
            let mut lease =
                unsafe { QuiescenceLease::new(&mut result, identity, result_ranges(&planned)) };
            let publication = unsafe {
                planned.publish_with(address as usize as *mut u8, &mut lease, || {
                    if libc::mprotect(
                        address as usize as *mut libc::c_void,
                        4096,
                        libc::PROT_READ | libc::PROT_EXEC,
                    ) != 0
                    {
                        return Err(Refusal::Backend(
                            std::io::Error::last_os_error().to_string(),
                        ));
                    }
                    Ok(())
                })
            }
            .expect("publication failure is fatal, never native eligibility");
            assert!(!lease.is_poisoned());
            publication
        };
        assert_eq!(receipt.plan(), planned.plan());
        assert_eq!(installed.plan(), planned.plan());
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(
                    planned.image().address() as usize as *const u8,
                    planned.image().bytes().len(),
                )
            },
            planned.image().bytes()
        );
        let mut expected = bytes;
        for edit in &planned.plan().parts().writes {
            let offset = usize::try_from(edit.address - base).unwrap();
            expected[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
        assert_eq!(result.candidate.bytes(), expected);
        assert_eq!(result.native.bytes(), result.native.original);
        result.installed = Some(installed);
        Self {
            inner: result,
            clock,
            gate,
            image,
            mode,
            transport,
        }
    }
    pub(super) fn run(
        &self,
        mode: Mode,
        n: u64,
        rounds: u64,
        quantum: u64,
        hold: bool,
    ) -> ResultRow {
        if mode == Mode::Native {
            return self.inner.run(mode, n, rounds, quantum, hold);
        }
        assert_eq!(
            self.mode,
            if mode == Mode::Counter {
                ClockMode::Counter
            } else {
                ClockMode::Stop
            }
        );
        run(self, n, rounds, quantum, hold, None)
    }
    pub(super) fn retire(&mut self) {
        self.inner.retire();
    }
}

struct State {
    pid: u32,
    tid: libc::c_long,
    site: u64,
    offset: u64,
    condition: Option<u8>,
    control: ProbeControl,
    clock: BackedgeClock,
    quantum: u64,
    max_work: u64,
    stops: usize,
    last_count: u64,
    memory: Arc<Memory>,
    // Only separately selected negative controls own this callback-write FD.
    refusal: Option<std::fs::File>,
    handoff: WorkerTransport,
}
thread_local! { static CURRENT: Cell<*mut State> = const { Cell::new(std::ptr::null_mut()) }; }
fn fatal() -> ! {
    unsafe { libc::_exit(123) }
}
// Fixed witness of the ACTUAL returned handoff outcome, never the requested
// fault name. A matching acknowledgement cannot produce a rejection witness.
fn refusal_witness(
    outcome: Result<(u64, u64), HandoffError>,
    site: u64,
    clock: ClockWords,
    words: [u64; 3],
) -> Option<[u8; 104]> {
    let (cause, present, actual_site, actual_count) = match outcome {
        Ok((actual_site, actual_count)) if (actual_site, actual_count) != (site, clock.counted) => {
            (1, 1, actual_site, actual_count)
        }
        Ok(_) => return None,
        Err(HandoffError::Timeout) => (2, 0, 0, 0),
        Err(HandoffError::Disconnected) => (3, 0, 0, 0),
        Err(HandoffError::Protocol) => (4, 0, 0, 0),
    };
    let fields = [
        cause,
        site,
        clock.counted,
        clock.encounters,
        clock.remaining,
        clock.saved_rcx,
        present,
        actual_site,
        actual_count,
        words[0],
        words[1],
        words[2],
    ];
    let mut bytes = [0; 104];
    bytes[..8].copy_from_slice(b"LI2SPSC1");
    for (i, value) in fields.into_iter().enumerate() {
        bytes[8 + i * 8..16 + i * 8].copy_from_slice(&value.to_le_bytes());
    }
    Some(bytes)
}
fn registers(c: &HookContext) -> [u64; 18] {
    [
        c.instruction_pointer,
        c.stack_pointer,
        c.r15,
        c.r14,
        c.r13,
        c.r12,
        c.r11,
        c.r10,
        c.r9,
        c.r8,
        c.rdi,
        c.rsi,
        c.rbp,
        c.rbx,
        c.rdx,
        c.rcx,
        c.rax,
        c.rflags,
    ]
}
unsafe extern "C" fn hook(context: *mut HookContext, identity: ControlIdentity<'_>) {
    if context.is_null() || CURRENT.get().is_null() {
        fatal();
    }
    // Only the exclusive worker installs this stack-owned state for its lease.
    let state = unsafe { &mut *CURRENT.get() };
    let c = unsafe { &*context };
    if state.pid != std::process::id()
        || state.tid != unsafe { libc::syscall(libc::SYS_gettid) }
        || c.instruction_pointer != state.site
        || !state.control.has_identity(identity)
        || !corpus::taken(state.condition, c.rflags)
        || state.stops == MAX_STOPS
    {
        fatal();
    }
    // This hook is reached only AFTER the generated gate charged this edge.
    // The same worker owns the page; no callback increments any clock field.
    let (clock, tail) = unsafe { state.clock.snapshot_parked() };
    if tail != [CLOCK_CANARY; 4064]
        || clock.remaining != 0
        || clock.saved_rcx != c.rcx
        || state.last_count.checked_add(state.quantum) != Some(clock.counted)
        || clock.counted > state.max_work
        || clock.encounters > state.max_work
        || clock.encounters < clock.counted
    {
        fatal();
    }
    let before = registers(c);
    let words = std::array::from_fn(|i| unsafe { state.memory.pointer().add(i).read_volatile() });
    let event = Stop {
        site: state.offset,
        count: clock.counted,
        encounters: clock.encounters,
        registers: before,
        words,
    };
    match state.handoff.exchange(event) {
        Ok((site, count)) if site == state.offset && count == clock.counted => {}
        outcome => {
            if let Some(file) = state.refusal.as_mut() {
                let current_words: [u64; 3] = std::array::from_fn(|i| unsafe {
                    state.memory.pointer().add(i).read_volatile()
                });
                // A cause witness is emitted only by this stopped callback,
                // after its actual result and exact parked-state comparisons.
                // Missing/partial output or any other failure refuses the control.
                if before == registers(c)
                    && unsafe { state.clock.snapshot_parked() } == (clock, tail)
                    && current_words == words
                {
                    if let Some(witness) = refusal_witness(outcome, state.offset, clock, words) {
                        // One fixed write, with no retry or substitute evidence.
                        // A short/error result leaves a nonmatching witness.
                        let complete = matches!(file.write(&witness), Ok(104));
                        if !complete {
                            fatal();
                        }
                    }
                }
            }
            fatal(); // No error, including a witnessed error, reaches refill.
        }
    }
    if before != registers(c) || unsafe { state.clock.snapshot_parked() } != (clock, tail) {
        fatal();
    }
    // Matching controller handoff received; the branch still has not executed.
    if unsafe { state.clock.refill_after_resume(state.quantum) }.is_err() {
        fatal();
    }
    state.last_count = clock.counted;
    state.stops += 1;
}
fn run(
    program: &InlineProgram,
    n: u64,
    rounds: u64,
    quantum: u64,
    hold: bool,
    fault: Option<(&str, &Path)>,
) -> ResultRow {
    assert!(quantum > 0 && (1..=4096).contains(&n) && (1..=128).contains(&rounds));
    let max_work = n.checked_mul(rounds).unwrap();
    assert!(max_work <= 32768 && (!hold || program.mode == ClockMode::Stop));
    let memory = Arc::new(Memory::new());
    let worker_memory = Arc::clone(&memory);
    let clock = program.clock.clone();
    let worker_clock = clock.clone();
    let control = program.inner.control.clone();
    let (entry, offset, condition) = (
        program.inner.candidate.address,
        program.inner.site.offset as u64,
        program.inner.site.condition,
    );
    let (handoff, mut controller) = program.transport.channel();
    // Create-new prevents stale witness reuse. The File moves into the exact
    // worker; the controller retains no descriptor and never writes this path.
    let refusal = fault.map(|(_, output)| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join("refusal.bin"))
            .expect("fresh callback-only rejection witness")
    });
    let worker = std::thread::spawn(move || {
        // SAFETY: private callable source is reachable only through this worker;
        // no signal/callback has an entry pointer. The call guard precedes the
        // first generated spill. All source/image/clock owners outlive join.
        let lease =
            unsafe { worker_clock.acquire(quantum, max_work) }.expect("exclusive clock lease");
        let mut state = State {
            pid: std::process::id(),
            tid: unsafe { libc::syscall(libc::SYS_gettid) },
            site: entry + offset,
            offset,
            condition,
            control,
            clock: worker_clock.clone(),
            quantum,
            max_work,
            stops: 0,
            last_count: 0,
            memory: worker_memory,
            refusal,
            handoff,
        };
        assert!(CURRENT.get().is_null());
        CURRENT.set(&raw mut state);
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                CURRENT.set(std::ptr::null_mut());
            }
        }
        let clear = Clear;
        let function: unsafe extern "C" fn(u64, *mut u64) -> u64 =
            unsafe { std::mem::transmute(entry as usize) };
        let start = Instant::now();
        let mut checksum = 0u64;
        for _ in 0..rounds {
            let call = lease
                .begin_call()
                .expect("no invocation/reentry before spill");
            checksum = checksum.wrapping_add(unsafe { function(n, state.memory.pointer()) });
            drop(call);
        }
        let elapsed_ns = start.elapsed().as_nanos();
        drop(clear);
        (elapsed_ns, checksum, state.stops)
    });
    let mut stops = Vec::new();
    let mut parked_checks = 0;
    loop {
        match controller.receive() {
            Ok(received) => {
                let event = received.stop();
                assert_eq!(program.mode, ClockMode::Stop);
                assert!(stops.len() < MAX_STOPS);
                assert_eq!(event.site, offset);
                assert_eq!(event.count, (stops.len() as u64 + 1) * quantum);
                let before = memory.snapshot();
                // Actual page observations, not a progress cache updated only at callbacks.
                let observed = unsafe { clock.snapshot_parked() };
                assert_eq!(observed.1, [CLOCK_CANARY; 4064]);
                assert_eq!(
                    (
                        observed.0.counted,
                        observed.0.encounters,
                        observed.0.remaining
                    ),
                    (event.count, event.encounters, 0)
                );
                assert_eq!(before[..3], event.words);
                if hold {
                    std::thread::sleep(Duration::from_millis(1));
                    assert_eq!(
                        memory.snapshot(),
                        before,
                        "whole application page advanced before resume"
                    );
                    assert_eq!(
                        unsafe { clock.snapshot_parked() },
                        observed,
                        "actual clock advanced before resume"
                    );
                    parked_checks += 1;
                }
                let reply = if let Some((name, output)) = fault {
                    assert_eq!(program.transport, Transport::Spsc);
                    assert_eq!((n, rounds, quantum, stops.len()), (2, 1, 1, 0));
                    assert_eq!((event.site, event.count, event.encounters), (27, 1, 1));
                    assert_eq!(event.words, [2, 1, 1]);
                    std::fs::write(output.join("parked.json"), format!(
                        "{{\"fault\":\"{name}\",\"site\":27,\"count\":1,\"encounters\":1,\"words\":[2,1,1],\"remaining\":0}}\n"
                    )).unwrap();
                    match name {
                        "wrong-site" => (event.site + 1, event.count),
                        "wrong-count" => (event.site, event.count + 1),
                        // Keep the event/owners alive without replying. The
                        // actual callback's unchanged WAIT must terminate us.
                        "no-reply" => loop {
                            std::thread::park_timeout(WAIT);
                        },
                        _ => unreachable!("validated fault name"),
                    }
                } else {
                    (event.site, event.count)
                };
                let event = received.resume(reply.0, reply.1).unwrap();
                stops.push(event);
            }
            Err(HandoffError::Disconnected) => break,
            Err(HandoffError::Timeout) => panic!("bounded inline rendezvous expired"),
            Err(HandoffError::Protocol) => panic!("inline rendezvous protocol refusal"),
        }
    }
    let (elapsed_ns, checksum, closed_stops) = worker.join().expect("exact inline worker joined");
    assert_eq!(closed_stops, stops.len());
    assert!(CURRENT.get().is_null());
    let (words, tail) = unsafe { clock.snapshot_parked() };
    assert_eq!(tail, [CLOCK_CANARY; 4064]);
    assert!(words.counted <= max_work && words.encounters <= max_work);
    assert_eq!(
        words.remaining,
        if program.mode == ClockMode::Counter {
            quantum
        } else {
            quantum - words.counted % quantum
        }
    );
    ResultRow {
        elapsed_ns,
        checksum,
        counted: words.counted,
        encounters: words.encounters,
        stops,
        memory: memory.snapshot(),
        parked_checks,
    }
}

// Separate fatal-control commands; never part of qualification/timing rows.
pub(super) fn fatal_control(name: &str, output: &Path) -> ! {
    assert!(matches!(name, "wrong-site" | "wrong-count" | "no-reply"));
    let program = InlineProgram::with_transport(Case::Countdown, ClockMode::Stop, Transport::Spsc);
    let _ = run(&program, 2, 1, 1, true, Some((name, output)));
    panic!("fatal rendezvous control unexpectedly returned");
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    fn clock() -> ClockWords {
        ClockWords {
            saved_rcx: 1,
            encounters: 1,
            counted: 1,
            remaining: 0,
        }
    }

    #[test]
    fn valid_reply_cannot_produce_a_rejection_witness() {
        assert_eq!(refusal_witness(Ok((27, 1)), 27, clock(), [2, 1, 1]), None);
    }

    #[test]
    fn actual_timeout_and_bad_tuple_produce_different_causes() {
        let timeout = refusal_witness(Err(HandoffError::Timeout), 27, clock(), [2, 1, 1]).unwrap();
        let wrong_site = refusal_witness(Ok((28, 1)), 27, clock(), [2, 1, 1]).unwrap();
        let wrong_count = refusal_witness(Ok((27, 2)), 27, clock(), [2, 1, 1]).unwrap();
        assert_ne!(timeout, wrong_site);
        assert_ne!(timeout, wrong_count);
        assert_ne!(wrong_site, wrong_count);
        assert_eq!(&timeout[8..16], &2u64.to_le_bytes());
        assert_eq!(&wrong_site[8..16], &1u64.to_le_bytes());
        assert_eq!(&wrong_count[8..16], &1u64.to_le_bytes());
        assert_eq!(&wrong_site[64..72], &28u64.to_le_bytes());
        assert_eq!(&wrong_site[72..80], &1u64.to_le_bytes());
        assert_eq!(&wrong_count[64..72], &27u64.to_le_bytes());
        assert_eq!(&wrong_count[72..80], &2u64.to_le_bytes());
    }
}
