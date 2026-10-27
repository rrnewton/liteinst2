//! Synchronous BEFORE-taken-backedge clock. No callback changes saved state.
use crate::corpus::taken;
use liteinst2::controls::{ControlIdentity, ProbeControl};
use liteinst2::trampoline::HookContext;
use std::cell::{Cell, UnsafeCell};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

pub const WAIT: Duration = Duration::from_secs(2);
pub const MAX_STOPS: usize = 4096;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Native,
    Counter,
    Stop,
}
impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Counter => "counter-only",
            Self::Stop => "before-taken-backedge-stop-resume",
        }
    }
}

#[repr(C, align(4096))]
struct Page([u64; 512]);
pub struct Memory {
    page: UnsafeCell<Page>,
}
// One worker writes while running. The controller reads only between the
// synchronous Stop message and its matching Resume; the worker cannot return
// from the hook in that interval. No other API exposes a concurrent reader.
unsafe impl Send for Memory {}
unsafe impl Sync for Memory {}
impl Memory {
    pub fn new() -> Self {
        Self {
            page: UnsafeCell::new(Page([0x5a5a_5a5a_5a5a_5a5a; 512])),
        }
    }
    pub fn pointer(&self) -> *mut u64 {
        self.page.get().cast::<u64>()
    }
    pub fn snapshot(&self) -> [u64; 512] {
        // SAFETY: callers are the writer itself, or the controller while parked/joined.
        std::array::from_fn(|i| unsafe { self.pointer().add(i).read_volatile() })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stop {
    pub site: u64,
    pub count: u64,
    pub encounters: u64,
    pub registers: [u64; 18],
    pub words: [u64; 3],
}
#[derive(Clone, Copy)]
struct Resume {
    count: u64,
    site: u64,
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
struct Counter {
    pid: u32,
    tid: libc::c_long,
    site: u64,
    offset: u64,
    condition: Option<u8>,
    control: ProbeControl,
    mode: Mode,
    quantum: u64,
    remaining: u64,
    counted: u64,
    encounters: u64,
    stops: usize,
    memory: Arc<Memory>,
    progress: Arc<AtomicU64>,
    events: mpsc::SyncSender<Stop>,
    resumes: mpsc::Receiver<Resume>,
}
thread_local! { static CURRENT: Cell<*mut Counter> = const { Cell::new(std::ptr::null_mut()) }; }
fn fatal() -> ! {
    // A callback cannot unwind through generated machine code or manufacture a result.
    unsafe { libc::_exit(123) }
}
pub unsafe extern "C" fn hook(context: *mut HookContext, identity: ControlIdentity<'_>) {
    if context.is_null() {
        fatal();
    }
    let p = CURRENT.get();
    if p.is_null() {
        fatal();
    }
    // SAFETY: only run() installs this live stack-owned Counter for this worker.
    let state = unsafe { &mut *p };
    let c = unsafe { &*context };
    if state.pid != std::process::id()
        || state.tid != unsafe { libc::syscall(libc::SYS_gettid) }
        || c.instruction_pointer != state.site
        || !state.control.has_identity(identity)
    {
        fatal();
    }
    state.encounters = match state.encounters.checked_add(1) {
        Some(n) => n,
        None => fatal(),
    };
    state.progress.store(state.encounters, Ordering::Release);
    if !taken(state.condition, c.rflags) {
        return;
    }
    state.counted = match state.counted.checked_add(1) {
        Some(n) => n,
        None => fatal(),
    };
    if state.mode != Mode::Stop {
        return;
    }
    state.remaining = match state.remaining.checked_sub(1) {
        Some(n) => n,
        None => fatal(),
    };
    if state.remaining != 0 {
        return;
    }
    if state.stops == MAX_STOPS {
        fatal();
    }
    let before = registers(c);
    let words = std::array::from_fn(|i| unsafe { state.memory.pointer().add(i).read_volatile() });
    let event = Stop {
        site: state.offset,
        count: state.counted,
        encounters: state.encounters,
        registers: before,
        words,
    };
    if state.events.send(event).is_err() {
        fatal();
    }
    // This is the actual preemption: the original branch has NOT executed.
    // No timer decides when to stop. Timeout is only an error/cleanup backstop.
    match state.resumes.recv_timeout(WAIT) {
        Ok(r) if r.count == state.counted && r.site == state.offset => {}
        _ => fatal(),
    }
    if before != registers(c) {
        fatal();
    }
    state.stops += 1;
    state.remaining = state.quantum;
}

pub struct ResultRow {
    pub elapsed_ns: u128,
    pub checksum: u64,
    pub counted: u64,
    pub encounters: u64,
    pub stops: Vec<Stop>,
    pub memory: [u64; 512],
    pub parked_checks: usize,
}
pub struct Run<'a> {
    pub entry: u64,
    pub site: u64,
    pub offset: u64,
    pub condition: Option<u8>,
    pub control: &'a ProbeControl,
    pub mode: Mode,
    pub quantum: u64,
    pub n: u64,
    pub rounds: u64,
    pub check_parked: bool,
}
pub fn run(request: Run<'_>) -> ResultRow {
    assert!(
        request.quantum > 0
            && (1..=4096).contains(&request.n)
            && (1..=128).contains(&request.rounds)
    );
    assert!(request.n.checked_mul(request.rounds).unwrap() <= 32768);
    assert!(!request.check_parked || request.mode == Mode::Stop);
    let memory = Arc::new(Memory::new());
    let progress = Arc::new(AtomicU64::new(0));
    let (events_tx, events_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let worker_memory = Arc::clone(&memory);
    let worker_progress = Arc::clone(&progress);
    let control = request.control.clone();
    let (entry, site, offset, condition, mode, quantum, n, rounds) = (
        request.entry,
        request.site,
        request.offset,
        request.condition,
        request.mode,
        request.quantum,
        request.n,
        request.rounds,
    );
    let worker = std::thread::spawn(move || {
        let mut state = Counter {
            pid: std::process::id(),
            tid: unsafe { libc::syscall(libc::SYS_gettid) },
            site,
            offset,
            condition,
            control,
            mode,
            quantum,
            remaining: quantum,
            counted: 0,
            encounters: 0,
            stops: 0,
            memory: worker_memory,
            progress: worker_progress,
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
        let guard = Clear;
        // SAFETY: caller owns exactly the authenticated fixed SysV function and
        // retains all source/image/control allocations until this worker joins.
        let f: unsafe extern "C" fn(u64, *mut u64) -> u64 =
            unsafe { std::mem::transmute(entry as usize) };
        let start = Instant::now();
        let mut checksum = 0u64;
        for _ in 0..rounds {
            checksum = checksum.wrapping_add(unsafe { f(n, state.memory.pointer()) });
        }
        let elapsed = start.elapsed().as_nanos();
        drop(guard);
        (
            elapsed,
            checksum,
            state.counted,
            state.encounters,
            state.stops,
        )
    });
    let mut stops = Vec::new();
    let mut parked_checks = 0;
    loop {
        match events_rx.recv_timeout(WAIT) {
            Ok(event) => {
                assert_eq!(request.mode, Mode::Stop);
                assert!(stops.len() < MAX_STOPS);
                assert_eq!(event.site, request.offset);
                assert_eq!(event.count, (stops.len() as u64 + 1) * request.quantum);
                let before = memory.snapshot();
                assert_eq!(before[..3], event.words);
                assert_eq!(progress.load(Ordering::Acquire), event.encounters);
                if request.check_parked {
                    std::thread::sleep(Duration::from_millis(1));
                    assert_eq!(
                        memory.snapshot(),
                        before,
                        "application memory advanced while parked"
                    );
                    assert_eq!(
                        progress.load(Ordering::Acquire),
                        event.encounters,
                        "next branch reached before resume"
                    );
                    parked_checks += 1;
                }
                resume_tx
                    .send(Resume {
                        count: event.count,
                        site: event.site,
                    })
                    .unwrap();
                stops.push(event);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("bounded worker/stop rendezvous expired")
            }
        }
    }
    let (elapsed_ns, checksum, counted, encounters, closed_stops) =
        worker.join().expect("owned worker completion");
    assert_eq!(closed_stops, stops.len());
    assert!(
        CURRENT.get().is_null(),
        "worker TLS never installed in controller"
    );
    ResultRow {
        elapsed_ns,
        checksum,
        counted,
        encounters,
        stops,
        memory: memory.snapshot(),
        parked_checks,
    }
}
