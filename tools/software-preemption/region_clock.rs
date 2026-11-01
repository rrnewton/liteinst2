//! Fixed two-backedge planner/emitter/native oracle, not a publisher benchmark.
//! Source/native/clock pages stay held. The planner-selected image is acquired
//! once with NOREPLACE; no hole, replacement, retry or occupied-range exception.
use super::*;
use liteinst2::backedge_clock::{
    BackedgeClock, BackedgeClockRegion, CLOCK_CANARY, ClockMode, ClockRegionGateLayout, ClockWords,
};
use liteinst2::controls::ControlIdentity;
use liteinst2::quiescent::{PlannedInstall, plan_owned_clock_region_detailed};
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::HookContext;
use std::cell::Cell;
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub(super) const PAGE: usize = 4096;
// mov eax,0; mov r8d,3; outer: mov ecx,4; inner: inc eax; dec ecx;
// near jnz inner; dec r8d; near jnz outer; ret. No application memory operand.
pub(super) const CODE: [u8; 36] = [
    0xb8, 0, 0, 0, 0, 0x41, 0xb8, 3, 0, 0, 0, 0xb9, 4, 0, 0, 0, 0xff, 0xc0, 0xff, 0xc9, 0x0f, 0x85,
    0xf6, 0xff, 0xff, 0xff, 0x41, 0xff, 0xc8, 0x0f, 0x85, 0xe8, 0xff, 0xff, 0xff, 0xc3,
];
pub(super) const HEADS: [u64; 9] = [0, 5, 11, 16, 18, 20, 26, 29, 35];
const LEADERS: [u64; 5] = [0, 11, 16, 26, 35];
pub(super) const SITES: [u64; 2] = [20, 29];

pub(super) struct RegionProgram {
    pub(super) native: u64,
    pub(super) source: u64,
    pub(super) clock: BackedgeClock,
    pub(super) image: u64,
    pub(super) image_len: usize,
    pub(super) routes: [u64; 9],
    pub(super) bodies: [u64; 9],
    pub(super) gates: [ClockRegionGateLayout; 2],
    controls: [ProbeControl; 2],
    source_bytes: Vec<u8>,
    image_bytes: Vec<u8>,
    // Custom copied code remains process-lived even on failure. This retained
    // image keeps the exact controls and RW clock alive for that lifetime.
    _plan: ManuallyDrop<PlannedInstall>,
}

fn bytes(address: u64, len: usize) -> Vec<u8> {
    // SAFETY: callers supply a retained, readable fixture-owned range.
    unsafe { std::slice::from_raw_parts(address as usize as *const u8, len) }.to_vec()
}

impl RegionProgram {
    pub(super) fn new(mode: ClockMode) -> Self {
        Self::new_with_hook(mode, hook)
    }

    pub(super) fn controls(&self) -> &[ProbeControl; 2] {
        &self.controls
    }

    pub(super) fn new_with_hook(
        mode: ClockMode,
        hook: liteinst2::controls::ManagedCallback,
    ) -> Self {
        single_main();
        // One fresh anonymous owner partitioned without unmapping: native RX,
        // source RX, then a separately transferred clock RW/non-X page.
        let arena = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                3 * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(arena, libc::MAP_FAILED, "required source/clock arena");
        let native = arena as usize as u64;
        let source = native + PAGE as u64;
        unsafe {
            std::ptr::copy_nonoverlapping(CODE.as_ptr(), arena.cast(), CODE.len());
            std::ptr::copy_nonoverlapping(
                CODE.as_ptr(),
                (source as usize as *mut u8).cast(),
                CODE.len(),
            );
        }
        let clock = unsafe { BackedgeClock::from_owned_mapping(source + PAGE as u64, PAGE) }
            .expect("separate held RW clock");
        let identity = CodeIdentity {
            source: SourceIdentity([0x93; 32]),
            mapping: source,
            generation: 1,
        };
        let scan = InstructionScanner::default().scan(&CODE, source).unwrap();
        assert_eq!(
            scan.instructions()
                .iter()
                .map(|i| i.address() - source)
                .collect::<Vec<_>>(),
            HEADS,
        );
        let (first, first_writer) = ProbeControl::new_managed_bound(hook, true);
        let (second, second_writer) = ProbeControl::new_managed_bound(hook, true);
        assert_ne!(first, second);
        let controls = [first.clone(), second.clone()];
        let region = BackedgeClockRegion::new_owned_region(
            identity,
            source,
            &CODE,
            [
                (source + SITES[0], first, first_writer),
                (source + SITES[1], second, second_writer),
            ],
            clock.clone(),
            mode,
        )
        .expect("authored closed two-backedge region");
        assert_eq!(region.clock(), &clock);
        for (index, (pc, control)) in region.controls().into_iter().enumerate() {
            assert_eq!(pc, source + SITES[index]);
            assert_eq!(control, &controls[index]);
        }
        let entries = LegalEntrySet {
            identity,
            scope: AddressRange::new(source, CODE.len()).unwrap(),
            provenance: EntryProvenance::Declared(
                "private region; sole external entry, exact authored internal leaders, no resumes"
                    .into(),
            ),
            completeness: EntryCompleteness::Complete,
            entries: LEADERS
                .into_iter()
                .map(|offset| LegalEntry {
                    address: source + offset,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let allocation = AllocationPolicy::near(source).unwrap();
        assert_eq!(
            (
                allocation.max_candidates,
                allocation.max_mappings,
                allocation.max_mapped_bytes
            ),
            (256, 1, 8192)
        );
        // SAFETY: exact immutable bytes, sole external entry and no callable
        // pointer yet. This finite loop has exactly 15 aggregate encounters.
        let planned = unsafe { plan_owned_clock_region_detailed(&region, &entries, &allocation) }
            .expect("required region plan, no alternative candidate oracle");
        let parts = planned.plan().parts();
        assert_eq!(parts.kind, PlanKind::Relocation);
        assert_eq!(parts.physical_pc, source);
        assert_eq!(
            parts.displaced,
            AddressRange::new(source, CODE.len()).unwrap()
        );
        assert_eq!(parts.allocations.len(), 1);
        let owned = parts.allocations[0].range;
        assert!(owned.len() <= 8192 && owned.start() & 4095 == 0 && owned.len() & 4095 == 0);
        let owned_len = usize::try_from(owned.len()).expect("bounded image mapping length");
        assert!(!owned.overlaps(AddressRange::new(native, 3 * PAGE).unwrap()));
        let image = planned.image();
        assert_eq!(image.clock(), Some(&clock));
        assert_eq!(image.clock_gate(), None);
        assert_eq!(image.controls(), &controls);
        assert_eq!(image.entry_routes().len(), HEADS.len());
        assert_eq!(image.instruction_boundaries().len(), HEADS.len());
        let gates: [ClockRegionGateLayout; 2] = image.clock_region_gates().try_into().unwrap();
        let routes = std::array::from_fn(|i| {
            assert_eq!(image.entry_routes()[i].0, source + HEADS[i]);
            image.entry_routes()[i].1
        });
        let bodies = std::array::from_fn(|i| {
            assert_eq!(image.instruction_boundaries()[i].0, source + HEADS[i]);
            image.instruction_boundaries()[i].1
        });
        for (i, gate) in gates.iter().enumerate() {
            let head = HEADS.iter().position(|&h| h == SITES[i]).unwrap();
            assert_eq!(gate.logical_pc, source + SITES[i]);
            assert_eq!(gate.gate.entry, routes[head]);
            assert_eq!(gate.gate.original_body, bodies[head]);
            assert!(
                gate.gate.entry < gate.gate.observing_entry
                    && gate.gate.observing_entry < gate.gate.original_body
            );
        }
        assert_eq!(routes[0], image.address());
        assert!(
            image.address() >= owned.start()
                && image
                    .address()
                    .checked_add(image.bytes().len() as u64)
                    .unwrap()
                    <= owned.end()
        );
        // The live planner deliberately rejects occupied ranges. Acquire its
        // exact vacant result once, while still the sole thread; a collision is
        // a required failure. NOREPLACE never clobbers a mapping or releases one.
        single_main();
        let acquired = unsafe {
            libc::mmap(
                owned.start() as usize as *mut _,
                owned_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_ne!(
            acquired,
            libc::MAP_FAILED,
            "required exact image acquisition"
        );
        assert_eq!(acquired as usize as u64, owned.start());
        for read in &parts.reads {
            assert!(
                read.address >= source
                    && read.address + read.bytes.len() as u64 <= source + CODE.len() as u64
            );
            assert_eq!(bytes(read.address, read.bytes.len()), read.bytes);
        }
        let mut expected_source = CODE.to_vec();
        for write in &parts.writes {
            let offset = usize::try_from(write.address.checked_sub(source).unwrap()).unwrap();
            expected_source
                .get_mut(offset..offset + write.bytes.len())
                .unwrap()
                .copy_from_slice(&write.bytes);
        }
        let image_address = image.address();
        let image_bytes = image.bytes().to_vec();
        unsafe {
            std::ptr::copy_nonoverlapping(
                image_bytes.as_ptr(),
                image_address as usize as *mut u8,
                image_bytes.len(),
            );
            std::ptr::copy_nonoverlapping(
                expected_source.as_ptr(),
                source as usize as *mut u8,
                expected_source.len(),
            );
            assert_eq!(
                libc::mprotect(acquired, owned_len, libc::PROT_READ | libc::PROT_EXEC),
                0
            );
            assert_eq!(
                libc::mprotect(arena, 2 * PAGE, libc::PROT_READ | libc::PROT_EXEC),
                0
            );
        }
        // This custom installation authenticates emitted bytes, not the live
        // publisher/router/sync-core protocol. Only the sole source entry runs;
        // internal branches target generated routes and never source interiors.
        let result = Self {
            native,
            source,
            clock,
            image: image_address,
            image_len: image_bytes.len(),
            routes,
            bodies,
            gates,
            controls,
            source_bytes: expected_source,
            image_bytes,
            _plan: ManuallyDrop::new(planned),
        };
        result.assert_code();
        result
    }

    pub(super) fn assert_code(&self) {
        assert_eq!(bytes(self.native, CODE.len()), CODE);
        assert_eq!(bytes(self.source, CODE.len()), self.source_bytes);
        assert_eq!(bytes(self.image, self.image_len), self.image_bytes);
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
static Q2: [Expected; 5] = [
    Expected {
        site: 20,
        count: 2,
        encounters: 2,
        rax: 2,
        rcx: 2,
        r8: 3,
    },
    Expected {
        site: 29,
        count: 4,
        encounters: 5,
        rax: 4,
        rcx: 0,
        r8: 2,
    },
    Expected {
        site: 20,
        count: 6,
        encounters: 7,
        rax: 6,
        rcx: 2,
        r8: 2,
    },
    Expected {
        site: 29,
        count: 8,
        encounters: 10,
        rax: 8,
        rcx: 0,
        r8: 1,
    },
    Expected {
        site: 20,
        count: 10,
        encounters: 12,
        rax: 10,
        rcx: 2,
        r8: 1,
    },
];
static Q11: [Expected; 1] = [Expected {
    site: 20,
    count: 11,
    encounters: 13,
    rax: 11,
    rcx: 1,
    r8: 1,
}];

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
    frame: usize,
    registers: [u64; 18],
    clock: ClockWords,
}
#[derive(Clone, Copy)]
enum BadReply {
    Site,
    Count,
}
impl BadReply {
    fn reply(self, expected: Expected) -> (u64, u64) {
        match self {
            Self::Site => (expected.site + 1, expected.count),
            Self::Count => (expected.site, expected.count + 1),
        }
    }
    fn code(self) -> u64 {
        match self {
            Self::Site => 1,
            Self::Count => 2,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Site => "wrong-site",
            Self::Count => "wrong-count",
        }
    }
}
const REJECTION_MAGIC: &[u8; 8] = b"LI2RGN01";
const REJECTION_BYTES: usize = 8 + 30 * 8;
struct State {
    pid: u32,
    tid: libc::c_long,
    source: u64,
    clock: BackedgeClock,
    controls: [ProbeControl; 2],
    quantum: u64,
    expected: &'static [Expected],
    stops: usize,
    events: mpsc::SyncSender<Event>,
    resumes: mpsc::Receiver<(u64, u64)>,
    rejection_witness: Option<OwnedFd>,
}
thread_local! { static CURRENT: Cell<*mut State> = const { Cell::new(std::ptr::null_mut()) }; }
fn fatal() -> ! {
    unsafe { libc::_exit(123) }
}
unsafe extern "C" fn hook(context: *mut HookContext, identity: ControlIdentity<'_>) {
    if context.is_null() || CURRENT.get().is_null() {
        fatal();
    }
    // Only the active worker exposes this stack-owned TLS/frame during its call.
    let state = unsafe { &mut *CURRENT.get() };
    let c = unsafe { &*context };
    let Some(index) = SITES
        .iter()
        .position(|offset| state.source + offset == c.instruction_pointer)
    else {
        fatal()
    };
    let Some(&expected) = state.expected.get(state.stops) else {
        fatal()
    };
    if state.pid != std::process::id()
        || state.tid != unsafe { libc::syscall(libc::SYS_gettid) }
        || !state.controls[index].has_identity(identity)
        || c.rflags & (1 << 6) != 0
        || (SITES[index], c.rax, c.rcx, c.r8)
            != (expected.site, expected.rax, expected.rcx, expected.r8)
    {
        fatal();
    }
    let (clock, tail) = unsafe { state.clock.snapshot_parked() };
    if tail != [CLOCK_CANARY; 4064]
        || clock.remaining != 0
        || clock.saved_rcx != c.rcx
        || (clock.counted, clock.encounters) != (expected.count, expected.encounters)
        || clock.counted != (state.stops as u64 + 1) * state.quantum
    {
        fatal();
    }
    let before = registers(c);
    if state
        .events
        .send(Event {
            expected,
            frame: context as usize,
            registers: before,
            clock,
        })
        .is_err()
    {
        fatal();
    }
    match state.resumes.recv_timeout(counter::WAIT) {
        Ok(reply) if reply == (expected.site, expected.count) => {}
        Ok(reply) => {
            // The negative child may prove only this first real stopped
            // callback. Its fault label is not passed to the hook: derive the
            // cause from the actual reply after the normal site/control/PID/
            // TID/condition/count authentication above. Any other rejection
            // still exits, but cannot produce an accepted witness.
            let Some(witness) = state.rejection_witness.as_ref() else {
                fatal()
            };
            if state.stops != 0
                || state.quantum != 2
                || expected != Q2[0]
                || clock
                    != (ClockWords {
                        saved_rcx: 2,
                        encounters: 2,
                        counted: 2,
                        remaining: 0,
                    })
                || before != registers(c)
                || unsafe { state.clock.snapshot_parked() } != (clock, tail)
            {
                fatal();
            }
            let cause = if reply == (expected.site + 1, expected.count) {
                1
            } else if reply == (expected.site, expected.count + 1) {
                2
            } else {
                fatal()
            };
            let mut words = [0u64; 30];
            words[..12].copy_from_slice(&[
                cause,
                u64::from(state.pid),
                state.tid as u64,
                state.source,
                expected.site,
                expected.count,
                reply.0,
                reply.1,
                clock.saved_rcx,
                clock.encounters,
                clock.counted,
                clock.remaining,
            ]);
            words[12..].copy_from_slice(&before);
            let mut record = [0u8; REJECTION_BYTES];
            record[..8].copy_from_slice(REJECTION_MAGIC);
            for (destination, word) in record[8..].chunks_exact_mut(8).zip(words) {
                destination.copy_from_slice(&word.to_le_bytes());
            }
            // Fixed PIPE_BUF-sized nonblocking write, once, before any refill.
            // A short/failed write cannot pass the parent's exact record check.
            if unsafe { libc::write(witness.as_raw_fd(), record.as_ptr().cast(), record.len()) }
                != REJECTION_BYTES as isize
            {
                fatal();
            }
            fatal();
        }
        Err(_) => fatal(),
    }
    if before != registers(c) || unsafe { state.clock.snapshot_parked() } != (clock, tail) {
        fatal();
    }
    if unsafe { state.clock.refill_after_resume(state.quantum) }.is_err() {
        fatal();
    }
    let refilled = ClockWords {
        remaining: state.quantum,
        ..clock
    };
    if unsafe { state.clock.snapshot_parked() } != (refilled, tail) || before != registers(c) {
        fatal();
    }
    state.stops += 1;
}

fn run_stop(
    program: &RegionProgram,
    quantum: u64,
    expected: &'static [Expected],
    rejection: Option<(BadReply, OwnedFd)>,
    events_csv: &mut String,
) -> (usize, u64) {
    let (bad_reply, rejection_witness) = match rejection {
        None => (None, None),
        Some((kind, fd)) => (Some(kind), Some(fd)),
    };
    let (tx, rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let clock = program.clock.clone();
    let controls = program.controls.clone();
    let source = program.source;
    let worker = std::thread::spawn(move || {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        // SAFETY: sole callable entry stays in this worker, all owners stay
        // live, and exactly 15 aggregate branch encounters bound this call.
        let lease = unsafe { clock.acquire(quantum, 15) }.unwrap();
        let mut state = State {
            pid: std::process::id(),
            tid,
            source,
            clock: clock.clone(),
            controls,
            quantum,
            expected,
            stops: 0,
            events: tx,
            resumes: resume_rx,
            rejection_witness,
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
        let call = lease.begin_call().unwrap();
        let function: unsafe extern "C" fn() -> u64 =
            unsafe { std::mem::transmute(source as usize) };
        let result = unsafe { function() };
        drop(call);
        drop(clear);
        let final_clock = unsafe { clock.snapshot_parked() };
        (result, state.stops, final_clock, tid)
    });
    let mut observed = Vec::new();
    loop {
        match rx.recv_timeout(counter::WAIT) {
            Ok(event) => {
                assert_eq!(event.expected, expected[observed.len()]);
                assert_eq!(
                    unsafe { program.clock.snapshot_parked() },
                    (event.clock, [CLOCK_CANARY; 4064])
                );
                // Release/acquire channel delivery exposes an immutable
                // actual saved frame while its worker waits for our reply.
                assert_eq!(
                    unsafe { registers(&*(event.frame as *const HookContext)) },
                    event.registers
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
                let e = event.expected;
                events_csv.push_str(&format!(
                    "{quantum},{},{},{},{},{},{}\n",
                    e.site, e.count, e.encounters, e.rax, e.rcx, e.r8
                ));
                observed.push(e);
                let reply = match bad_reply {
                    None => (e.site, e.count),
                    Some(kind) => {
                        assert_eq!((quantum, observed.len(), e), (2, 1, Q2[0]));
                        kind.reply(e)
                    }
                };
                resume_tx.send(reply).unwrap();
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("bounded region callback handoff expired")
            }
        }
    }
    let (result, stops, (words, tail), tid) = worker.join().expect("exact region worker joined");
    joined_worker_retired(tid);
    assert_eq!(observed, expected);
    assert_eq!(stops, expected.len());
    assert_eq!(result, 12);
    assert_eq!(tail, [CLOCK_CANARY; 4064]);
    assert_eq!(
        words,
        ClockWords {
            saved_rcx: 0,
            encounters: 15,
            counted: 11,
            remaining: quantum - 11 % quantum
        }
    );
    assert_eq!(unsafe { program.clock.snapshot_parked() }, (words, tail));
    program.assert_code();
    (stops, words.remaining)
}

struct RejectionChild {
    pid: libc::pid_t,
    reaped: bool,
}
impl RejectionChild {
    fn wait(&mut self) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid {
                assert!(libc::WIFEXITED(status) || libc::WIFSIGNALED(status));
                self.reaped = true;
                return status;
            }
            assert_eq!(result, 0, "exact rejection child wait failed");
            assert!(
                Instant::now() < deadline,
                "rejection child deadline exhausted"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for RejectionChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Cleanup only this owned PID on any assertion; never wait unboundedly
        // or signal an unrelated process/group. Failure cannot become PASS.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                self.reaped = true;
                break;
            }
            if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
            {
                self.reaped = true;
                break;
            }
            if Instant::now() >= deadline {
                assert!(
                    std::thread::panicking(),
                    "rejection child cleanup exhausted"
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn rejection_controls(output: &Path) {
    let mut rows = String::from("fault,pid,tid,site,count,reply_site,reply_count,exit,result\n");
    for kind in [BadReply::Site, BadReply::Count] {
        single_main();
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let read_pipe = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        let write_pipe = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "required negative child, no retry");
        if pid == 0 {
            drop(read_pipe);
            let result = std::panic::catch_unwind(|| {
                // New owners and lease in the child, never the inherited idle
                // parent region. The intended rejection exits inside the hook.
                let program = RegionProgram::new(ClockMode::Stop);
                run_stop(
                    &program,
                    2,
                    &Q2,
                    Some((kind, write_pipe)),
                    &mut String::new(),
                );
            });
            // Never unwind through inherited parent owners; a setup panic or
            // erroneously completed native call is distinct from exit 123.
            unsafe { libc::_exit(if result.is_err() { 120 } else { 124 }) }
        }
        let mut child = RejectionChild { pid, reaped: false };
        drop(write_pipe);
        let status = child.wait();
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 123);
        // Read only after the exact owned process has terminated. Nonblocking
        // reads additionally prevent an inherited descriptor from hanging us.
        let mut record = [0u8; REJECTION_BYTES + 1];
        let n = unsafe {
            libc::read(
                read_pipe.as_raw_fd(),
                record.as_mut_ptr().cast(),
                record.len(),
            )
        };
        assert_eq!(n, REJECTION_BYTES as isize);
        let mut extra = [0u8; 1];
        assert_eq!(
            unsafe { libc::read(read_pipe.as_raw_fd(), extra.as_mut_ptr().cast(), 1) },
            0
        );
        assert_eq!(&record[..8], REJECTION_MAGIC);
        let words: [u64; 30] = std::array::from_fn(|i| {
            u64::from_le_bytes(record[8 + i * 8..16 + i * 8].try_into().unwrap())
        });
        let reply = kind.reply(Q2[0]);
        assert_eq!(words[0], kind.code());
        assert_eq!(words[1], pid as u64);
        assert!(words[2] > 0 && words[2] != words[1]);
        assert!(words[3] > 0);
        assert_eq!(&words[4..12], &[20, 2, reply.0, reply.1, 2, 2, 2, 0]);
        let frame = &words[12..];
        assert_eq!(frame[0], words[3].checked_add(20).unwrap());
        assert!(frame[1] > 0);
        assert_eq!((frame[9], frame[15], frame[16]), (3, 2, 2));
        assert_eq!(frame[17] & (1 << 6), 0);
        let mut absent = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut absent, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        single_main();
        std::fs::write(
            output.join(format!("region-rejection-{}.bin", kind.name())),
            &record[..REJECTION_BYTES],
        )
        .unwrap();
        rows.push_str(&format!(
            "{},{},{},20,2,{},{},123,PASS\n",
            kind.name(),
            pid,
            words[2],
            reply.0,
            reply.1
        ));
    }
    std::fs::write(output.join("region-rejections.csv"), rows).unwrap();
    println!("preemption:region-rejections:2-children:2-first-stop-witnesses:2-exit123-echild");
}

pub(super) fn qualify(output: &Path) {
    single_main();
    let program = RegionProgram::new(ClockMode::Stop);
    // Ordinary native execution supplies an independent exact return result.
    let original: unsafe extern "C" fn() -> u64 =
        unsafe { std::mem::transmute(program.native as usize) };
    assert_eq!(unsafe { original() }, 12);
    let mut rows = String::from("quantum,encounters,taken,stops,parked_checks,remaining,result\n");
    let mut events_csv = String::from("quantum,site,count,encounters,rax,rcx,r8\n");
    for (quantum, expected) in [(2, Q2.as_slice()), (11, Q11.as_slice()), (12, &[][..])] {
        let (stops, remaining) = run_stop(&program, quantum, expected, None, &mut events_csv);
        rows.push_str(&format!(
            "{quantum},15,11,{stops},{stops},{remaining},PASS\n"
        ));
    }
    // Every positive worker has joined and disappeared before these forks.
    // Each child constructs and leases fresh owners; it never uses the idle
    // inherited parent's region, and exits without unwinding through it.
    rejection_controls(output);
    std::fs::write(output.join("region-stops.csv"), rows).unwrap();
    std::fs::write(output.join("region-events.csv"), events_csv).unwrap();
    println!("preemption:region-stops:3-quanta:15-encounters:11-taken:6-stops:6-parked-checks");
}
