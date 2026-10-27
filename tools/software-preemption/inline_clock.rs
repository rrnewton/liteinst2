//! Exclusive finite inline clock. All callable source addresses remain private.
//! Worker lease + begin_call exclude concurrency/reentry BEFORE the first spill.
use super::*;
use counter::{MAX_STOPS, Memory, Stop, WAIT};
use liteinst2::backedge_clock::{
    BackedgeClock, BackedgeClockAction, CLOCK_CANARY, ClockGateLayout, ClockMode,
};
use liteinst2::controls::ControlIdentity;
use liteinst2::quiescent::plan_backedge_clock_detailed;
use liteinst2::trampoline::HookContext;
use std::cell::Cell;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

pub(super) struct InlineProgram {
    pub(super) inner: Program,
    pub(super) clock: BackedgeClock,
    pub(super) gate: ClockGateLayout,
    pub(super) image: (u64, usize),
    mode: ClockMode,
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
        run(self, n, rounds, quantum, hold)
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
    events: mpsc::SyncSender<Stop>,
    resumes: mpsc::Receiver<(u64, u64)>,
}
thread_local! { static CURRENT: Cell<*mut State> = const { Cell::new(std::ptr::null_mut()) }; }
fn fatal() -> ! {
    unsafe { libc::_exit(123) }
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
    if state.events.send(event).is_err() {
        fatal();
    }
    match state.resumes.recv_timeout(WAIT) {
        Ok((site, count)) if site == state.offset && count == clock.counted => {}
        _ => fatal(),
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
fn run(program: &InlineProgram, n: u64, rounds: u64, quantum: u64, hold: bool) -> ResultRow {
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
    let (events_tx, events_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
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
            events: events_tx,
            resumes: resume_rx,
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
        match events_rx.recv_timeout(WAIT) {
            Ok(event) => {
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
                resume_tx.send((event.site, event.count)).unwrap();
                stops.push(event);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("bounded inline rendezvous expired"),
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
