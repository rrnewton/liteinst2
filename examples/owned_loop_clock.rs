//! One private SysV buffer transform with synchronous BEFORE-backedge stops.
//! Explicit standalone example for a fixed call-free function and owned buffer.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("owned_loop_clock requires Linux x86-64");

use liteinst2::backedge_clock::{BackedgeClock, BackedgeClockAction, CLOCK_CANARY, ClockMode};
use liteinst2::contracts::*;
use liteinst2::controls::{ControlIdentity, ProbeControl};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_backedge_clock_detailed,
};
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::HookContext;
use std::cell::{Cell, UnsafeCell};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const N: usize = 64;
const GUARD: usize = 16;
const TOTAL: usize = N + 2 * GUARD;
const SITE: u64 = 23;
const QUANTUM: u64 = 16;
const STOPS: [u64; 3] = [16, 32, 48];
const WAIT: Duration = Duration::from_secs(2);
// unsafe extern "C" fn(*mut u8, usize) -> u64; this client calls ONLY with N.
// xor r8d,r8d; mov rcx,rsi; [head6] xor eax,eax; mov al,[rdi]; xor al,0x5a;
// mov [rdi],al; add r8,rax; inc rdi; dec rcx; jnz head6; mov rax,r8; ret.
const CODE: [u8; 33] = [
    0x45, 0x31, 0xc0, 0x48, 0x89, 0xf1, 0x31, 0xc0, 0x8a, 0x07, 0x34, 0x5a, 0x88, 0x07, 0x49, 0x01,
    0xc0, 0x48, 0xff, 0xc7, 0x48, 0xff, 0xc9, 0x0f, 0x85, 0xe9, 0xff, 0xff, 0xff, 0x4c, 0x89, 0xc0,
    0xc3,
];
type Transform = unsafe extern "C" fn(*mut u8, usize) -> u64;

fn expected(done: usize) -> [u8; TOTAL] {
    assert!(done <= N);
    let mut bytes = [0xa5; TOTAL];
    for (i, byte) in bytes[GUARD..GUARD + N].iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
        if i < done {
            *byte ^= 0x5a;
        }
    }
    bytes
}
fn sum_prefix(bytes: &[u8; TOTAL], done: usize) -> u64 {
    bytes[GUARD..GUARD + done]
        .iter()
        .map(|&b| u64::from(b))
        .sum()
}

// Source mappings deliberately have no unmapping Drop: reachable code stays
// process-lived on both success and failure. This is not a retirement proof.
struct Source {
    address: u64,
}
impl Source {
    fn new(pages: usize) -> Self {
        assert!((1..=2).contains(&pages));
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                pages * 4096,
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
        if unsafe { libc::mprotect(self.address as usize as *mut libc::c_void, 4096, flags) } != 0 {
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
struct Program {
    native: Source,
    candidate: Source,
    control: ProbeControl,
    clock: BackedgeClock,
}
impl Program {
    fn new() -> Self {
        // Publication happens before any worker or callable pointer exists.
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) },
            libc::c_long::from(std::process::id())
        );
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        let native = Source::new(1);
        let mut candidate = Source::new(2);
        // SAFETY: transfer only the separate second anonymous RW/non-X page;
        // no Rust references or other unmapping owner exist for either span.
        let clock = unsafe { BackedgeClock::from_owned_mapping(candidate.address + 4096, 4096) }
            .expect("owned adjacent clock page");
        let base = candidate.address;
        let pc = base + SITE;
        let identity = CodeIdentity {
            source: SourceIdentity(*b"owned-loop-xor-byte-client-v1..."),
            mapping: base,
            generation: 1,
        };
        let scope = AddressRange::new(base, CODE.len()).unwrap();
        let scan = InstructionScanner::default().scan(&CODE, base).unwrap();
        let entries = LegalEntrySet {
            identity,
            scope,
            provenance: EntryProvenance::Declared(
                "private complete decoded heads; no exposed entry or saved resume".into(),
            ),
            completeness: EntryCompleteness::Complete,
            entries: scan
                .instructions()
                .iter()
                .map(|i| LegalEntry {
                    address: i.address(),
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let (control, writer) = ProbeControl::new_managed_bound(hook, true);
        let action = BackedgeClockAction::new_owned_loop(
            identity,
            base,
            &CODE,
            pc,
            (control.clone(), writer),
            clock.clone(),
            ClockMode::Stop,
        )
        .expect("whole owned-loop byte/CFG admission");
        let allocation = AllocationPolicy::near(pc).unwrap();
        assert_eq!(
            (
                allocation.max_candidates,
                allocation.max_mappings,
                allocation.max_mapped_bytes
            ),
            (256, 1, 8192)
        );
        let planned = plan_backedge_clock_detailed(
            &InstallRequest {
                identity,
                code: &CODE,
                base_address: base,
                function: scope,
                block: AddressRange::new(pc, 6).unwrap(),
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
        .expect("required branch instrumentation");
        assert_eq!(planned.plan().parts().kind, PlanKind::Relocation);
        assert_eq!(planned.plan().parts().physical_pc, pc);
        assert_eq!(
            planned.plan().parts().displaced,
            AddressRange::new(pc, 6).unwrap()
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
        assert_eq!(planned.image().clock(), Some(&clock));
        assert!(planned.image().clock_gate().is_some());
        let ranges = planned
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
        let (installed, receipt) = {
            // SAFETY: sole thread, exact private source/image owners and no
            // invocation/resume. The only callable pointers are made later.
            let mut lease = unsafe { QuiescenceLease::new(&mut candidate, identity, ranges) };
            let result = unsafe {
                planned.publish_with(base as usize as *mut u8, &mut lease, || {
                    if libc::mprotect(
                        base as usize as *mut libc::c_void,
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
            .expect("publication must succeed before entry");
            assert!(!lease.is_poisoned());
            result
        };
        assert_eq!(receipt.plan(), planned.plan());
        assert_eq!(installed.plan(), planned.plan());
        // Retain immediately, before any later assertion could unwind.
        let _retained = Box::leak(Box::new(installed));
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(
                    planned.image().address() as usize as *const u8,
                    planned.image().bytes().len(),
                )
            },
            planned.image().bytes()
        );
        let mut published = CODE;
        for edit in &planned.plan().parts().writes {
            let start = usize::try_from(edit.address - base).unwrap();
            published[start..start + edit.bytes.len()].copy_from_slice(&edit.bytes);
        }
        assert_eq!(candidate.bytes(), published);
        assert_eq!(native.bytes(), CODE);
        Self {
            native,
            candidate,
            control,
            clock,
        }
    }
}

// Only the generated worker writes these bytes. The controller reads solely
// after a stop-event receive and before its matching resume, or after join.
struct Buffer(UnsafeCell<[u8; TOTAL]>);
unsafe impl Send for Buffer {}
unsafe impl Sync for Buffer {}
impl Buffer {
    fn pointer(&self) -> *mut u8 {
        unsafe { self.0.get().cast::<u8>().add(GUARD) }
    }
    unsafe fn snapshot(&self) -> [u8; TOTAL] {
        std::array::from_fn(|i| unsafe { self.0.get().cast::<u8>().add(i).read_volatile() })
    }
}
// A failed controller never leaves data reclamation to a detached worker.
// Only the successful post-join path takes this Arc for ordinary destruction.
struct DataOwner(Option<Arc<Buffer>>);
impl Drop for DataOwner {
    fn drop(&mut self) {
        if let Some(buffer) = self.0.take() {
            std::mem::forget(buffer);
        }
    }
}
struct Stop {
    count: u64,
    registers: [u64; 18],
    buffer: [u8; TOTAL],
}
struct State {
    pid: u32,
    tid: libc::c_long,
    site: u64,
    last: u64,
    control: ProbeControl,
    clock: BackedgeClock,
    buffer: Arc<Buffer>,
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
unsafe extern "C" fn unused_hook(_: *mut HookContext) {
    fatal()
}
unsafe extern "C" fn hook(context: *mut HookContext, identity: ControlIdentity<'_>) {
    if context.is_null() || CURRENT.get().is_null() {
        fatal();
    }
    let state = unsafe { &mut *CURRENT.get() };
    let c = unsafe { &*context };
    if state.pid != std::process::id()
        || state.tid != unsafe { libc::syscall(libc::SYS_gettid) }
        || c.instruction_pointer != state.site
        || !state.control.has_identity(identity)
        || c.rflags & (1 << 6) != 0
    {
        fatal();
    }
    // The gate already charged this scheduled taken edge, before executing it.
    let observed = unsafe { state.clock.snapshot_parked() };
    let words = observed.0;
    if observed.1 != [CLOCK_CANARY; 4064]
        || words.remaining != 0
        || words.saved_rcx != c.rcx
        || words.counted != state.last + QUANTUM
        || !STOPS.contains(&words.counted)
        || words.encounters != words.counted
        || c.rcx != N as u64 - words.counted
    {
        fatal();
    }
    let before = registers(c);
    let bytes = unsafe { state.buffer.snapshot() };
    if state
        .events
        .try_send(Stop {
            count: words.counted,
            registers: before,
            buffer: bytes,
        })
        .is_err()
    {
        fatal();
    }
    match state.resumes.recv_timeout(WAIT) {
        Ok((site, count)) if site == state.site && count == words.counted => {}
        _ => fatal(),
    }
    // No controller read remains after its resume send. No application
    // instruction or generated clock write occurred during this rendezvous.
    if registers(c) != before
        || unsafe { state.buffer.snapshot() } != bytes
        || unsafe { state.clock.snapshot_parked() } != observed
    {
        fatal();
    }
    if unsafe { state.clock.refill_after_resume(QUANTUM) }.is_err() {
        fatal();
    }
    state.last = words.counted;
}

fn run() {
    assert_eq!(
        std::env::args_os().count(),
        1,
        "this fixed example accepts no case filters"
    );
    let program = Program::new();
    let mut native_bytes = Box::new(expected(0));
    let native: Transform = unsafe { std::mem::transmute(program.native.address as usize) };
    // SAFETY: private 33-byte SysV function; exactly N valid writable bytes,
    // no alias or concurrency, one entry, positive finite length and no calls.
    let native_sum = unsafe { native(native_bytes.as_mut_ptr().add(GUARD), N) };
    assert_eq!(*native_bytes, expected(N));
    assert_eq!(native_sum, sum_prefix(&expected(N), N));

    let mut owner = DataOwner(Some(Arc::new(Buffer(UnsafeCell::new(expected(0))))));
    let buffer = owner.0.as_ref().unwrap();
    let worker_buffer = Arc::clone(buffer);
    let clock = program.clock.clone();
    let control = program.control.clone();
    let entry = program.candidate.address;
    let site = entry + SITE;
    let (events_tx, events_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        // SAFETY: this is the sole owner of the private entry; no callback or
        // signal handler receives it. Exact N bounds all 64 visits/63 taken
        // decisions. No previous worker exists; begin_call precedes any spill.
        let lease = unsafe { clock.acquire(QUANTUM, N as u64) }.expect("exclusive worker lease");
        let mut state = State {
            pid: std::process::id(),
            tid: unsafe { libc::syscall(libc::SYS_gettid) },
            site,
            last: 0,
            control,
            clock: clock.clone(),
            buffer: worker_buffer,
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
        let function: Transform = unsafe { std::mem::transmute(entry as usize) };
        let pointer = state.buffer.pointer();
        let call = lease.begin_call().expect("no recursive entry");
        // SAFETY: same exact SysV/data contract as native; only this worker
        // invokes the installed entry, with owners retained through its join.
        let sum = unsafe { function(pointer, N) };
        drop(call);
        drop(clear);
        assert_eq!(state.last, 48);
        sum
    });
    for count in STOPS {
        let event = events_rx.recv_timeout(WAIT).expect("required bounded stop");
        assert_eq!(event.count, count);
        let wanted = expected(count as usize);
        assert_eq!(event.buffer, wanted);
        assert_eq!(event.registers[0], site);
        assert_eq!(event.registers[9], sum_prefix(&wanted, count as usize)); // R8
        assert_eq!(
            event.registers[10],
            buffer.pointer() as usize as u64 + count
        ); // RDI
        assert_eq!(event.registers[11], N as u64); // RSI
        assert_eq!(event.registers[15], N as u64 - count); // RCX
        assert_eq!(event.registers[17] & (1 << 6), 0); // JNZ taken
        // SAFETY: event receive synchronizes the worker's completed writes;
        // it cannot leave the callback until this exact controller resumes it.
        let actual = unsafe { buffer.snapshot() };
        let actual_clock = unsafe { program.clock.snapshot_parked() };
        assert_eq!(actual, wanted);
        assert_eq!(actual_clock.1, [CLOCK_CANARY; 4064]);
        assert_eq!(
            (
                actual_clock.0.counted,
                actual_clock.0.encounters,
                actual_clock.0.remaining
            ),
            (count, count, 0)
        );
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(
            unsafe { buffer.snapshot() },
            actual,
            "whole buffer advanced while parked"
        );
        assert_eq!(
            unsafe { program.clock.snapshot_parked() },
            actual_clock,
            "clock advanced while parked"
        );
        resume_tx
            .send((site, count))
            .expect("matching resume delivered");
        // No buffer/clock reads from here until the next event or exact join.
    }
    assert!(
        matches!(
            events_rx.recv_timeout(WAIT),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ),
        "extra stop or incomplete worker is a failure"
    );
    let deadline = Instant::now() + WAIT;
    while !worker.is_finished() {
        if Instant::now() >= deadline {
            fatal();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let instrumented_sum = worker.join().expect("exact worker joined without panic");
    assert!(CURRENT.get().is_null());
    assert_eq!(Arc::strong_count(buffer), 1);
    assert_eq!(instrumented_sum, native_sum);
    assert_eq!(unsafe { buffer.snapshot() }, *native_bytes);
    assert_eq!(unsafe { buffer.snapshot() }, expected(N));
    let (words, tail) = unsafe { program.clock.snapshot_parked() };
    assert_eq!(tail, [CLOCK_CANARY; 4064]);
    assert_eq!(
        (
            words.counted,
            words.encounters,
            words.remaining,
            words.saved_rcx
        ),
        (63, 64, 1, 0)
    );
    assert_eq!(program.native.bytes(), CODE);
    let buffer = owner.0.take().unwrap(); // Exact join and all data checks precede release.
    let weak = Arc::downgrade(&buffer);
    drop(buffer); // Ordinary data reclamation follows the exact joined worker.
    assert!(weak.upgrade().is_none());
    drop(weak); // Release the Arc allocation before reporting reclamation.
    println!(
        "owned-loop PASS bytes=64 stops=16,32,48 taken=63 encounters=64 parked=3 joined=true data_reclaimed=true checksum={native_sum}"
    );
}
fn main() {
    // Failures terminate this standalone process. They never detach a worker
    // and return a reusable client: DataOwner retains its data, and all
    // executable owners remain process-lived. No asynchronous cancel is offered.
    if std::panic::catch_unwind(run).is_err() {
        fatal();
    }
}
