//! One owned scalar region, two clocked backedges and real quiescent publication.
//! Positive client integration only: no retirement, throughput or full-state
//! comparison after callbacks. Code and installed routes remain process-lived.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("owned_region_clock requires Linux x86-64");

use liteinst2::backedge_clock::{
    BackedgeClock, BackedgeClockRegion, CLOCK_CANARY, ClockMode, ClockWords, MAX_WORK,
};
use liteinst2::contracts::*;
use liteinst2::controls::{ControlIdentity, ProbeControl};
use liteinst2::quiescent::{AllocationPolicy, InstalledOnce, plan_owned_clock_region_detailed};
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::HookContext;
use std::cell::Cell;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const WAIT: Duration = Duration::from_secs(2);
const ARGUMENT_ERROR: &str = "invalid arguments: expected outer inner quantum; outer and inner in 1..=32, quantum in 1..=32768";
// SysV fn(outer: u64, inner: u64) -> u64, positive bounded arguments only.
// xor eax,eax; mov r8,rdi; outer: mov rcx,rsi; inner: add rax,rcx;
// dec rcx; near jnz inner; dec r8; near jnz outer; ret.
const CODE: [u8; 30] = [
    0x31, 0xc0, 0x49, 0x89, 0xf8, 0x48, 0x89, 0xf1, 0x48, 0x01, 0xc8, 0x48, 0xff, 0xc9, 0x0f, 0x85,
    0xf4, 0xff, 0xff, 0xff, 0x49, 0xff, 0xc8, 0x0f, 0x85, 0xe8, 0xff, 0xff, 0xff, 0xc3,
];
const HEADS: [u64; 9] = [0, 2, 5, 8, 11, 14, 20, 23, 29];
const LEADERS: [u64; 5] = [0, 5, 8, 20, 29];
const SITES: [u64; 2] = [14, 23];
type Function = unsafe extern "C" fn(u64, u64) -> u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Input {
    outer: u64,
    inner: u64,
    quantum: u64,
}
impl Input {
    fn parse(args: &[String]) -> Result<Self, ()> {
        let values = match args {
            [] => [3, 4, 2],
            [outer, inner, quantum] => [
                outer.parse::<u64>().map_err(|_| ())?,
                inner.parse::<u64>().map_err(|_| ())?,
                quantum.parse::<u64>().map_err(|_| ())?,
            ],
            _ => return Err(()),
        };
        let [outer, inner, quantum] = values;
        if !(1..=32).contains(&outer)
            || !(1..=32).contains(&inner)
            || !(1..=MAX_WORK).contains(&quantum)
            || outer
                .checked_mul(inner.checked_add(1).ok_or(())?)
                .ok_or(())?
                > MAX_WORK
        {
            return Err(());
        }
        Ok(Self {
            outer,
            inner,
            quantum,
        })
    }
    fn result(self) -> u64 {
        self.outer * self.inner * (self.inner + 1) / 2
    }
    fn encounters(self) -> u64 {
        self.outer * (self.inner + 1)
    }
    fn taken(self) -> u64 {
        self.outer * self.inner - 1
    }
    fn stops(self) -> u64 {
        self.taken() / self.quantum
    }
    fn final_clock(self) -> ClockWords {
        ClockWords {
            saved_rcx: 0,
            encounters: self.encounters(),
            counted: self.taken(),
            remaining: self.quantum - self.taken() % self.quantum,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Expected {
    site: u64,
    count: u64,
    encounters: u64,
    rax: u64,
    rcx: u64,
    r8: u64,
}
// Closed forms independent of the generated instruction stream and clock code.
fn expected(input: Input, count: u64) -> Expected {
    assert!((1..=input.taken()).contains(&count));
    let a = (count - 1) / input.inner;
    let t = count - a * input.inner;
    let triangular = input.inner * (input.inner + 1) / 2;
    if t < input.inner {
        Expected {
            site: SITES[0],
            count,
            encounters: a * (input.inner + 1) + t,
            rax: a * triangular + t * (2 * input.inner - t + 1) / 2,
            rcx: input.inner - t,
            r8: input.outer - a,
        }
    } else {
        Expected {
            site: SITES[1],
            count,
            encounters: (a + 1) * (input.inner + 1),
            rax: (a + 1) * triangular,
            rcx: 0,
            r8: input.outer - a - 1,
        }
    }
}

// No unmapping Drop: even failure must not reclaim possibly reachable code.
struct Source {
    address: u64,
}
impl Source {
    fn new(pages: usize) -> Self {
        assert!((1..=2).contains(&pages));
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                pages * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED, "private source mapping");
        unsafe { std::ptr::copy_nonoverlapping(CODE.as_ptr(), p.cast(), CODE.len()) };
        let source = Self {
            address: p as usize as u64,
        };
        source.protect(libc::PROT_READ | libc::PROT_EXEC).unwrap();
        source
    }
    fn protect(&self, flags: i32) -> Result<(), Refusal> {
        if unsafe { libc::mprotect(self.address as usize as *mut libc::c_void, PAGE, flags) } != 0 {
            return Err(Refusal::Backend(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        Ok(())
    }
    fn bytes(&self) -> [u8; CODE.len()] {
        std::array::from_fn(|i| unsafe {
            (self.address as usize as *const u8).add(i).read_volatile()
        })
    }
}
fn sigill_unblocked() {
    let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut mask) },
        0
    );
    assert_eq!(unsafe { libc::sigismember(&mask, libc::SIGILL) }, 0);
}
struct Program {
    native: Source,
    candidate: Source,
    controls: [ProbeControl; 2],
    clock: BackedgeClock,
    installed: &'static InstalledOnce,
    published: [u8; CODE.len()],
    image: u64,
    image_bytes: Vec<u8>,
}
impl Program {
    fn new() -> Self {
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) },
            libc::c_long::from(std::process::id())
        );
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        sigill_unblocked();
        let native = Source::new(1);
        let mut candidate = Source::new(2);
        let base = candidate.address;
        // SAFETY: transfer only the separate second anonymous RW/non-X page.
        // There is no other unmapping owner, alias or access to its storage.
        let clock = unsafe { BackedgeClock::from_owned_mapping(base + PAGE as u64, PAGE) }.unwrap();
        let identity = CodeIdentity {
            source: SourceIdentity([0x94; 32]),
            mapping: base,
            generation: 1,
        };
        let scope = AddressRange::new(base, CODE.len()).unwrap();
        let scan = InstructionScanner::default().scan(&CODE, base).unwrap();
        assert_eq!(scan.snapshot(), CODE);
        assert_eq!(
            scan.instructions()
                .iter()
                .map(|i| i.address() - base)
                .collect::<Vec<_>>(),
            HEADS
        );
        let entries = LegalEntrySet { identity, scope, completeness: EntryCompleteness::Complete,
            provenance: EntryProvenance::Declared("private scalar region; sole external base entry, exact internal leaders, no resumes".into()),
            entries: LEADERS.into_iter().map(|offset| LegalEntry { address: base + offset, requires_endbr: false }).collect(),
            resumes: ResumeObligation::NoneExist };
        let (first, first_writer) = ProbeControl::new_managed_bound(hook, true);
        let (second, second_writer) = ProbeControl::new_managed_bound(hook, true);
        assert_ne!(first, second);
        let controls = [first.clone(), second.clone()];
        let region = BackedgeClockRegion::new_owned_region(
            identity,
            base,
            &CODE,
            [
                (base + SITES[0], first, first_writer),
                (base + SITES[1], second, second_writer),
            ],
            clock.clone(),
            ClockMode::Stop,
        )
        .expect("closed whole-region admission");
        assert_eq!(region.clock(), &clock);
        for (i, (pc, control)) in region.controls().into_iter().enumerate() {
            assert_eq!((pc, control), (base + SITES[i], &controls[i]));
        }
        let allocation = AllocationPolicy::near(base).unwrap();
        assert_eq!(
            (
                allocation.max_candidates,
                allocation.max_mappings,
                allocation.max_mapped_bytes
            ),
            (256, 1, 8192)
        );
        // SAFETY: no callable candidate pointer or worker exists. The exact
        // source has sole external entry at base, no signals/recursion/fork or
        // saved resumes into it, and every admitted input has finite aggregate
        // work <= MAX_WORK. Each later call holds one whole-region lease/guard.
        let planned = unsafe { plan_owned_clock_region_detailed(&region, &entries, &allocation) }
            .expect("required whole-region plan");
        let parts = planned.plan().parts();
        assert_eq!(parts.identity, identity);
        assert_eq!(parts.profile, ApplicationProfile::InstallOnce);
        assert_eq!(parts.kind, PlanKind::Relocation);
        assert_eq!(
            (parts.logical_pc, parts.physical_pc, parts.displaced),
            (base + SITES[0], base, scope)
        );
        assert_eq!(parts.entries, entries);
        assert_eq!(parts.dependencies, [scope]);
        assert_eq!(parts.reads.len(), 1);
        assert_eq!(
            (parts.reads[0].address, parts.reads[0].bytes.as_slice()),
            (base, CODE.as_slice())
        );
        assert_eq!(candidate.bytes(), CODE);
        assert_eq!(
            parts.requirements,
            PublicationRequirements {
                quiescent: true,
                sync_core: true,
                sigill_router: true
            }
        );
        assert_eq!(parts.allocations.len(), 1);
        let owned = parts.allocations[0].range;
        assert!(owned.len() <= 8192 && owned.start() & 4095 == 0 && owned.len() & 4095 == 0);
        assert_eq!(parts.allocations[0].alignment, PAGE);
        assert!(!owned.overlaps(AddressRange::new(native.address, PAGE).unwrap()));
        assert!(!owned.overlaps(AddressRange::new(base, 2 * PAGE).unwrap()));
        let image = planned.image();
        assert_eq!(image.clock(), Some(&clock));
        assert_eq!(image.clock_gate(), None);
        assert_eq!(image.controls(), &controls);
        assert_eq!(image.layout().return_len, 5);
        assert_eq!(image.entry_routes().len(), HEADS.len());
        assert_eq!(image.instruction_boundaries().len(), HEADS.len());
        assert_eq!(image.clock_region_gates().len(), SITES.len());
        assert!(owned.covers(AddressRange::new(image.address(), image.bytes().len()).unwrap()));
        for (i, &head) in HEADS.iter().enumerate() {
            let route = image.entry_routes()[i];
            let body = image.instruction_boundaries()[i];
            assert_eq!((route.0, body.0), (base + head, base + head));
            assert!(owned.contains(route.1) && owned.contains(body.1));
            assert!(
                image
                    .program_counter_mappings()
                    .iter()
                    .any(|m| m.translate(body.1) == Some(base + head))
            );
            if let Some(index) = SITES.iter().position(|&site| site == head) {
                let gate = image.clock_region_gates()[index];
                assert_eq!(
                    (gate.logical_pc, gate.gate.entry, gate.gate.original_body),
                    (base + head, route.1, body.1)
                );
                assert!(route.1 < gate.gate.observing_entry && gate.gate.observing_entry < body.1);
            } else {
                assert_eq!(route.1, body.1);
            }
        }
        assert_eq!(image.entry_routes()[0].1, image.address());
        let mut obligations = vec![EntryObligation::Preserved(base)];
        for offset in &LEADERS[1..] {
            let &(original, generated) = image
                .entry_routes()
                .iter()
                .find(|&&(pc, _)| pc == base + offset)
                .unwrap();
            obligations.push(EntryObligation::Routed(EntryRoute {
                original,
                generated,
            }));
        }
        assert_eq!(parts.obligations, obligations); // Four routes, even with sole external base entry.
        assert_eq!(parts.generated.len(), 1);
        assert_eq!(parts.generated[0].address, image.address());
        assert_eq!(parts.generated[0].bytes, image.bytes());
        assert_eq!(
            parts.generated[0].program_counters,
            image.program_counter_mappings()
        );
        assert_eq!(parts.writes.len(), 1);
        assert_eq!(parts.writes[0].address, base);
        let published: [u8; CODE.len()] = parts.writes[0].bytes.as_slice().try_into().unwrap();
        let image_address = image.address();
        let image_bytes = image.bytes().to_vec();
        let ranges = parts
            .dependencies
            .iter()
            .copied()
            .chain(parts.allocations.iter().map(|a| a.range))
            .collect();
        candidate
            .protect(libc::PROT_READ | libc::PROT_WRITE)
            .unwrap();
        let (installed, receipt) = {
            // SAFETY: sole thread, private source generation, no candidate
            // entry/resume, exact source/image ranges. The publisher acquires
            // its own image, stages SIGILL routes and synchronizes cores.
            let mut lease = unsafe { QuiescenceLease::new(&mut candidate, identity, ranges) };
            let result = unsafe {
                planned.publish_with(base as usize as *mut u8, &mut lease, || {
                    if libc::mprotect(
                        base as usize as *mut libc::c_void,
                        PAGE,
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
            .expect("real publication before entry");
            assert!(!lease.is_poisoned());
            result
        };
        // Keep executable controls, clock, routes and code alive even if a
        // later assertion fails. This is retention, not retirement/drainage.
        let installed: &'static InstalledOnce = Box::leak(Box::new(installed));
        assert_eq!(receipt.plan(), planned.plan());
        assert_eq!(installed.plan(), planned.plan());
        assert_eq!(
            installed.trampoline().program_counter_mappings(),
            image.program_counter_mappings()
        );
        assert!(!installed.is_retired());
        assert_eq!(installed.routed_entries(), 0);
        drop(planned);
        drop(region);
        let program = Self {
            native,
            candidate,
            controls,
            clock,
            installed,
            published,
            image: image_address,
            image_bytes,
        };
        program.assert_code();
        program
    }
    fn assert_code(&self) {
        assert_eq!(self.native.bytes(), CODE);
        assert_eq!(self.candidate.bytes(), self.published);
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(self.image as usize as *const u8, self.image_bytes.len())
            },
            self.image_bytes
        );
        assert_eq!(self.installed.routed_entries(), 0);
        assert!(!self.installed.is_retired());
        assert!(self.controls.iter().all(ProbeControl::is_enabled));
    }
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
struct Event {
    expected: Expected,
    pid: u32,
    tid: libc::c_long,
    frame: usize,
    registers: [u64; 18],
    clock: ClockWords,
}
struct State {
    input: Input,
    pid: u32,
    tid: libc::c_long,
    source: u64,
    last: u64,
    controls: [ProbeControl; 2],
    clock: BackedgeClock,
    events: mpsc::SyncSender<Event>,
    resumes: mpsc::Receiver<(u64, u64)>,
}
thread_local! { static CURRENT: Cell<*mut State> = const { Cell::new(std::ptr::null_mut()) }; }
fn fatal() -> ! {
    unsafe { libc::_exit(123) }
}
unsafe extern "C" fn hook(context: *mut HookContext, identity: ControlIdentity<'_>) {
    if context.is_null() || CURRENT.get().is_null() {
        fatal();
    }
    let state = unsafe { &mut *CURRENT.get() };
    let c = unsafe { &*context };
    let count = state.last + state.input.quantum;
    if count > state.input.taken() {
        fatal();
    }
    let want = expected(state.input, count);
    let index = if want.site == SITES[0] { 0 } else { 1 };
    if state.pid != std::process::id()
        || state.tid != unsafe { libc::syscall(libc::SYS_gettid) }
        || !state.controls[index].has_identity(identity)
        || c.instruction_pointer != state.source + want.site
        || (c.rax, c.rcx, c.r8, c.rdi, c.rsi)
            != (
                want.rax,
                want.rcx,
                want.r8,
                state.input.outer,
                state.input.inner,
            )
        || c.rflags & (1 << 6) != 0
    {
        fatal();
    }
    let observed = unsafe { state.clock.snapshot_parked() };
    if observed
        != (
            ClockWords {
                saved_rcx: want.rcx,
                encounters: want.encounters,
                counted: count,
                remaining: 0,
            },
            [CLOCK_CANARY; 4064],
        )
    {
        fatal();
    }
    let before = registers(c);
    if state
        .events
        .try_send(Event {
            expected: want,
            pid: state.pid,
            tid: state.tid,
            frame: context as usize,
            registers: before,
            clock: observed.0,
        })
        .is_err()
    {
        fatal();
    }
    match state.resumes.recv_timeout(WAIT) {
        Ok((site, resumed)) if (site, resumed) == (state.source + want.site, count) => {}
        _ => fatal(),
    }
    // The controller has stopped reading before this exact resume. No saved
    // word, clock word or canary byte may have changed during the rendezvous.
    if registers(c) != before || unsafe { state.clock.snapshot_parked() } != observed {
        fatal();
    }
    if unsafe { state.clock.refill_after_resume(state.input.quantum) }.is_err() {
        fatal();
    }
    if registers(c) != before
        || unsafe { state.clock.snapshot_parked() }
            != (
                ClockWords {
                    remaining: state.input.quantum,
                    ..observed.0
                },
                observed.1,
            )
    {
        fatal();
    }
    state.last = count;
}

fn joined_task_gone(tid: libc::c_long) {
    let main = libc::c_long::from(std::process::id());
    assert!(tid > 0 && tid != main);
    let deadline = Instant::now() + WAIT;
    let mut allowed = [main, tid];
    allowed.sort_unstable();
    loop {
        assert!(
            Instant::now() < deadline,
            "joined TID disappearance deadline"
        );
        let mut tasks = std::fs::read_dir("/proc/self/task")
            .unwrap()
            .map(|entry| {
                let name = entry.unwrap().file_name().into_string().unwrap();
                let id = name.parse::<libc::c_long>().unwrap();
                assert!(id > 0 && id.to_string() == name);
                id
            })
            .collect::<Vec<_>>();
        assert!(Instant::now() < deadline, "late task observation");
        tasks.sort_unstable();
        if tasks == [main] {
            return;
        }
        assert_eq!(tasks, allowed, "unexpected task after exact join");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn run(input: Input) {
    let program = Program::new();
    let native: Function = unsafe { std::mem::transmute(program.native.address as usize) };
    // SAFETY: exact private call-free SysV code, sole base entry, bounded
    // positive integer arguments; no memory operand or external callback.
    let native_result = unsafe { native(input.outer, input.inner) };
    assert_eq!(native_result, input.result());
    let clock = program.clock.clone();
    let controls = program.controls.clone();
    let source = program.candidate.address;
    let (events_tx, events_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        sigill_unblocked(); // SIGILL disposition/mask is never changed by this client.
        let pid = std::process::id();
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        // SAFETY: one worker, one entry, no signals/recursion/fork/interior
        // entry. This lease bounds both sites together, including untaken
        // encounters. Its call guard precedes the first possible RCX spill.
        let lease = unsafe { clock.acquire(input.quantum, input.encounters()) }.unwrap();
        let mut state = State {
            input,
            pid,
            tid,
            source,
            last: 0,
            controls,
            clock: clock.clone(),
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
        ready_tx.try_send((pid, tid)).unwrap();
        drop(ready_tx);
        let function: Function = unsafe { std::mem::transmute(source as usize) };
        let call = lease.begin_call().expect("one exclusive region invocation");
        // SAFETY: actual published entry; owners remain alive through join,
        // same input/ABI as native, no callback modifies application state.
        let result = unsafe { function(input.outer, input.inner) };
        drop(call);
        drop(clear);
        assert_eq!(state.last, input.stops() * input.quantum);
        let final_clock = unsafe { clock.snapshot_parked() };
        (result, state.last, tid, final_clock)
    });
    let (pid, tid) = ready_rx
        .recv_timeout(WAIT)
        .expect("bounded worker identity");
    assert_eq!(pid, std::process::id());
    assert!(tid > 0 && tid != libc::c_long::from(pid));
    let mut counts = [0u64; 2];
    for stop in 1..=input.stops() {
        let want = expected(input, stop * input.quantum);
        let event = events_rx.recv_timeout(WAIT).expect("required bounded stop");
        assert_eq!(event.expected, want);
        assert_eq!((event.pid, event.tid), (pid, tid));
        assert_ne!(event.frame, 0);
        assert_eq!(event.registers[0], source + want.site);
        assert_eq!(
            (event.registers[16], event.registers[15], event.registers[9]),
            (want.rax, want.rcx, want.r8)
        );
        assert_eq!(
            (event.registers[10], event.registers[11]),
            (input.outer, input.inner)
        );
        assert_eq!(event.registers[17] & (1 << 6), 0);
        assert_eq!(
            event.clock,
            ClockWords {
                saved_rcx: want.rcx,
                encounters: want.encounters,
                counted: want.count,
                remaining: 0
            }
        );
        // SAFETY: receiving this event synchronizes the worker's writes. The
        // worker cannot resume/change its frame or clock before our exact reply.
        assert_eq!(
            unsafe { registers(&*(event.frame as *const HookContext)) },
            event.registers
        );
        assert_eq!(
            unsafe { program.clock.snapshot_parked() },
            (event.clock, [CLOCK_CANARY; 4064])
        );
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(
            unsafe { registers(&*(event.frame as *const HookContext)) },
            event.registers
        );
        assert_eq!(
            unsafe { program.clock.snapshot_parked() },
            (event.clock, [CLOCK_CANARY; 4064])
        );
        program.assert_code();
        counts[if want.site == SITES[0] { 0 } else { 1 }] += 1;
        resume_tx
            .try_send((source + want.site, want.count))
            .expect("matching resume");
        // No frame/clock access until the next event or the exact worker join.
    }
    assert!(
        matches!(
            events_rx.recv_timeout(WAIT),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ),
        "extra stop or incomplete worker"
    );
    let deadline = Instant::now() + WAIT;
    while !worker.is_finished() {
        assert!(Instant::now() < deadline, "worker completion deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
    let (result, last, joined_tid, final_clock) = worker.join().expect("exact worker completed");
    assert_eq!(joined_tid, tid);
    joined_task_gone(tid);
    assert!(CURRENT.get().is_null());
    assert_eq!(
        (result, last),
        (native_result, input.stops() * input.quantum)
    );
    assert_eq!(result, input.result());
    assert_eq!(counts.iter().sum::<u64>(), input.stops());
    assert_eq!(final_clock, (input.final_clock(), [CLOCK_CANARY; 4064]));
    assert_eq!(unsafe { program.clock.snapshot_parked() }, final_clock);
    program.assert_code();
    println!(
        "{{\"status\":\"PASS\",\"profile\":\"owned-region-publisher-v1\",\"outer\":{},\"inner\":{},\"quantum\":{},\"result\":{result},\"encounters\":{},\"taken\":{},\"stops\":{},\"inner_stops\":{},\"outer_stops\":{},\"parked\":{},\"joined\":true,\"publication\":\"publish_with\",\"handled_routes\":0}}",
        input.outer,
        input.inner,
        input.quantum,
        input.encounters(),
        input.taken(),
        input.stops(),
        counts[0],
        counts[1],
        input.stops()
    );
}
fn main() {
    // Parse/reject before mapping, publication, workers or native execution.
    let args = std::env::args_os()
        .skip(1)
        .map(|s| s.into_string().map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>();
    let input = args
        .as_ref()
        .map_err(|_| ())
        .and_then(|args| Input::parse(args));
    let Ok(input) = input else {
        eprintln!("{ARGUMENT_ERROR}");
        std::process::exit(2)
    };
    // An error ends this standalone process; it never returns a reusable
    // client with a detached worker, altered source or reclaimed active code.
    if std::panic::catch_unwind(|| run(input)).is_err() {
        fatal();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(values: &[&str]) -> Result<Input, ()> {
        Input::parse(&values.iter().map(|s| (*s).into()).collect::<Vec<_>>())
    }
    #[test]
    fn parser_rejects_outside_finite_domain_before_runtime() {
        assert_eq!(
            input(&[]).unwrap(),
            Input {
                outer: 3,
                inner: 4,
                quantum: 2
            }
        );
        for bad in [
            vec!["0", "4", "2"],
            vec!["3", "0", "2"],
            vec!["33", "4", "2"],
            vec!["3", "33", "2"],
            vec!["3", "4", "0"],
            vec!["3", "4", "32769"],
            vec!["x", "4", "2"],
            vec!["3", "4"],
            vec!["18446744073709551616", "4", "2"],
        ] {
            assert_eq!(input(&bad), Err(()));
        }
        assert_eq!(input(&["32", "32", "32768"]).unwrap().encounters(), 1056);
    }
    #[test]
    fn literal_default_and_last_taken_stop_states() {
        let i = input(&[]).unwrap();
        let actual = (1..=i.stops())
            .map(|n| {
                let e = expected(i, n * i.quantum);
                (e.site, e.count, e.encounters, e.rax, e.rcx, e.r8)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            [
                (14, 2, 2, 7, 2, 3),
                (23, 4, 5, 10, 0, 2),
                (14, 6, 7, 17, 2, 2),
                (23, 8, 10, 20, 0, 1),
                (14, 10, 12, 27, 2, 1)
            ]
        );
        let boundary = input(&["32", "32", "1023"]).unwrap();
        assert_eq!(
            expected(boundary, 1023),
            Expected {
                site: 14,
                count: 1023,
                encounters: 1054,
                rax: 16895,
                rcx: 1,
                r8: 1
            }
        );
        assert_eq!(
            boundary.final_clock(),
            ClockWords {
                saved_rcx: 0,
                encounters: 1056,
                counted: 1023,
                remaining: 1023
            }
        );
    }
    #[test]
    fn scalar_nested_loop_independently_checks_every_taken_state() {
        for (outer, inner) in (1..=32).flat_map(|outer| (1..=32).map(move |inner| (outer, inner))) {
            let quantum = 7;
            let i = Input {
                outer,
                inner,
                quantum,
            };
            let (mut rax, mut r8, mut visits, mut taken, mut stops) = (0, outer, 0, 0, 0);
            loop {
                let mut rcx = inner;
                loop {
                    rax += rcx;
                    rcx -= 1;
                    visits += 1;
                    if rcx == 0 {
                        break;
                    }
                    taken += 1;
                    assert_eq!(
                        expected(i, taken),
                        Expected {
                            site: 14,
                            count: taken,
                            encounters: visits,
                            rax,
                            rcx,
                            r8
                        }
                    );
                    if taken % quantum == 0 {
                        stops += 1;
                    }
                }
                r8 -= 1;
                visits += 1;
                if r8 == 0 {
                    break;
                }
                taken += 1;
                assert_eq!(
                    expected(i, taken),
                    Expected {
                        site: 23,
                        count: taken,
                        encounters: visits,
                        rax,
                        rcx: 0,
                        r8
                    }
                );
                if taken % quantum == 0 {
                    stops += 1;
                }
            }
            assert_eq!(
                (rax, visits, taken, stops),
                (i.result(), i.encounters(), i.taken(), i.stops())
            );
        }
    }
}
