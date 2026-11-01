//! One ordered cohort; process replication/randomization belongs to its owner.
use super::{counter, joined_worker_retired, region_clock::RegionProgram, single_main};
use liteinst2::backedge_clock::{BackedgeClock, CLOCK_CANARY, ClockMode, ClockWords};
use liteinst2::controls::{ControlIdentity, ProbeControl};
use liteinst2::trampoline::HookContext;
use std::cell::Cell;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const CALLS: u64 = 2048;
const ENCOUNTERS: u64 = 15 * CALLS;
const TAKEN: u64 = 11 * CALLS;
const CHECKSUM: u64 = 12 * CALLS;
const QUANTUM: u64 = 64;
const STOPS: usize = (TAKEN / QUANTUM) as usize;
const WARMUPS: usize = 3;
const MEASUREMENTS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Arm {
    Native,
    Counter,
    Stop,
}
impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Counter => "counter",
            Self::Stop => "stop",
        }
    }
}
fn order(text: &str) -> [Arm; 3] {
    use Arm::{Counter as C, Native as N, Stop as S};
    match text {
        "native,counter,stop" => [N, C, S],
        "native,stop,counter" => [N, S, C],
        "counter,native,stop" => [C, N, S],
        "counter,stop,native" => [C, S, N],
        "stop,native,counter" => [S, N, C],
        "stop,counter,native" => [S, C, N],
        _ => panic!("required exact permutation of native,counter,stop"),
    }
}
fn affinity() -> Vec<usize> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) },
        0
    );
    (0..libc::CPU_SETSIZE as usize)
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
        .collect()
}
fn pin(cpu: usize) {
    assert!(cpu < libc::CPU_SETSIZE as usize);
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
    }
    assert_eq!(
        unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) },
        0
    );
    assert_eq!(affinity(), [cpu]);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Expected {
    site: u64,
    rax: u64,
    r8: u64,
    words: ClockWords,
}
fn expected(count: u64) -> Expected {
    assert!((1..=TAKEN).contains(&count));
    // Independent literal taken-branch order of the unchanged 36-byte body:
    // (site offset, encounter within call, RAX, RCX, R8).
    const LOCAL: [(u64, u64, u64, u64, u64); 11] = [
        (20, 1, 1, 3, 3),
        (20, 2, 2, 2, 3),
        (20, 3, 3, 1, 3),
        (29, 5, 4, 0, 2),
        (20, 6, 5, 3, 2),
        (20, 7, 6, 2, 2),
        (20, 8, 7, 1, 2),
        (29, 10, 8, 0, 1),
        (20, 11, 9, 3, 1),
        (20, 12, 10, 2, 1),
        (20, 13, 11, 1, 1),
    ];
    let (site, encounter, rax, rcx, r8) = LOCAL[((count - 1) % 11) as usize];
    Expected {
        site,
        rax,
        r8,
        words: ClockWords {
            saved_rcx: rcx,
            encounters: 15 * ((count - 1) / 11) + encounter,
            counted: count,
            remaining: 0,
        },
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
fn accepts(source: u64, e: Expected, regs: &[u64; 18], words: ClockWords) -> bool {
    words == e.words
        && regs[0] == source + e.site
        && regs[17] & (1 << 6) == 0
        && (regs[16], regs[15], regs[9]) == (e.rax, e.words.saved_rcx, e.r8)
}
fn reply_matches(e: Expected, reply: (u64, u64)) -> bool {
    reply == (e.site, e.words.counted)
}
#[derive(Clone, Copy)]
enum BadReply {
    Site,
    Count,
}
impl BadReply {
    fn reply(self, e: Expected) -> (u64, u64) {
        match self {
            Self::Site => (e.site + 1, e.words.counted),
            Self::Count => (e.site, e.words.counted + 1),
        }
    }
    fn code(self) -> u64 {
        match self {
            Self::Site => 1,
            Self::Count => 2,
        }
    }
}
const REJECTION_BYTES: usize = 248;
const REJECTION_MAGIC: &[u8; 8] = b"LI2RBQ64";
struct Event {
    expected: Expected,
    frame: usize,
    registers: [u64; 18],
    words: ClockWords,
}
struct State {
    pid: u32,
    tid: libc::c_long,
    source: u64,
    clock: BackedgeClock,
    controls: [ProbeControl; 2],
    call_index: u64,
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
    let state = unsafe { &mut *CURRENT.get() };
    let c = unsafe { &*context };
    let Some(site) = [20, 29]
        .iter()
        .position(|offset| state.source + offset == c.instruction_pointer)
    else {
        fatal()
    };
    if state.pid != std::process::id()
        || state.tid != unsafe { libc::syscall(libc::SYS_gettid) }
        || !state.controls[site].has_identity(identity)
        || state.stops >= STOPS
    {
        fatal();
    }
    let e = expected(QUANTUM * (state.stops as u64 + 1));
    let (words, tail) = unsafe { state.clock.snapshot_parked() };
    let before = registers(c);
    if !accepts(state.source, e, &before, words)
        || tail != [CLOCK_CANARY; 4064]
        || state.call_index != (e.words.counted - 1) / 11
    {
        fatal();
    }
    if state
        .events
        .send(Event {
            expected: e,
            frame: context as usize,
            registers: before,
            words,
        })
        .is_err()
    {
        fatal();
    }
    match state.resumes.recv_timeout(counter::WAIT) {
        Ok(reply) if reply_matches(e, reply) => {}
        Ok(reply) => {
            let Some(fd) = state.rejection_witness.as_ref() else {
                fatal()
            };
            if state.stops != 0
                || state.call_index != 5
                || e != expected(64)
                || words
                    != (ClockWords {
                        saved_rcx: 3,
                        encounters: 86,
                        counted: 64,
                        remaining: 0,
                    })
                || before != registers(c)
                || unsafe { state.clock.snapshot_parked() } != (words, tail)
            {
                fatal();
            }
            // Derive cause from the actual reply; no expected-fault tag reaches this hook.
            let cause = if reply == (21, 64) {
                1
            } else if reply == (20, 65) {
                2
            } else {
                fatal()
            };
            let mut record = [0u8; REJECTION_BYTES];
            record[..8].copy_from_slice(REJECTION_MAGIC);
            let mut values = [0u64; 30];
            values[..12].copy_from_slice(&[
                cause,
                u64::from(state.pid),
                state.tid as u64,
                state.source,
                e.site,
                e.words.counted,
                reply.0,
                reply.1,
                words.saved_rcx,
                words.encounters,
                words.counted,
                words.remaining,
            ]);
            values[12..].copy_from_slice(&before);
            for (destination, word) in record[8..].chunks_exact_mut(8).zip(values) {
                destination.copy_from_slice(&word.to_le_bytes());
            }
            // One bounded witness before refill; any short write cannot pass.
            if unsafe { libc::write(fd.as_raw_fd(), record.as_ptr().cast(), record.len()) }
                != REJECTION_BYTES as isize
            {
                fatal();
            }
            fatal();
        }
        Err(_) => fatal(),
    }
    if before != registers(c) || unsafe { state.clock.snapshot_parked() } != (words, tail) {
        fatal();
    }
    if unsafe { state.clock.refill_after_resume(QUANTUM) }.is_err() {
        fatal();
    }
    let refilled = ClockWords {
        remaining: QUANTUM,
        ..words
    };
    if before != registers(c) || unsafe { state.clock.snapshot_parked() } != (refilled, tail) {
        fatal();
    }
    state.stops += 1;
}

fn validate_schedule() {
    assert!(QUANTUM.is_power_of_two());
    // Independent scalar execution supplies every expected tuple, including
    // both false JNZ encounters per completed outer iteration/call.
    let (mut count, mut encounters, mut inner, mut outer) = (0, 0, 0, 0);
    for call in 0..CALLS {
        let mut rax = 0;
        for remaining_outer in (1..=3).rev() {
            for remaining_inner in (0..4).rev() {
                rax += 1;
                encounters += 1;
                if remaining_inner != 0 {
                    count += 1;
                    assert_eq!(
                        expected(count),
                        Expected {
                            site: 20,
                            rax,
                            r8: remaining_outer,
                            words: ClockWords {
                                saved_rcx: remaining_inner,
                                counted: count,
                                encounters,
                                remaining: 0
                            }
                        }
                    );
                    inner += usize::from(count & (QUANTUM - 1) == 0);
                }
            }
            encounters += 1;
            if remaining_outer != 1 {
                count += 1;
                assert_eq!(
                    expected(count),
                    Expected {
                        site: 29,
                        rax,
                        r8: remaining_outer - 1,
                        words: ClockWords {
                            saved_rcx: 0,
                            counted: count,
                            encounters,
                            remaining: 0
                        }
                    }
                );
                outer += usize::from(count & (QUANTUM - 1) == 0);
            }
        }
        assert_eq!(
            (rax, encounters, count),
            (12, 15 * (call + 1), 11 * (call + 1))
        );
    }
    assert_eq!(
        (count, encounters, inner, outer),
        (TAKEN, ENCOUNTERS, 288, 64)
    );
}

struct ResultRow {
    elapsed_ns: Option<u128>,
    checksum: u64,
    stops: usize,
    clock: Option<ClockWords>,
    tid: libc::c_long,
}
fn batch(
    program: &RegionProgram,
    arm: Arm,
    controller_cpu: usize,
    worker_cpu: usize,
    timed: bool,
    rejection: Option<(BadReply, OwnedFd)>,
) -> ResultRow {
    single_main();
    assert_eq!(affinity(), [controller_cpu]);
    program.assert_code();
    const { assert!(ENCOUNTERS <= liteinst2::backedge_clock::MAX_WORK) };
    let before_clock = unsafe { program.clock.snapshot_parked() };
    let (tx, rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (go_tx, go_rx) = mpsc::sync_channel(1);
    let source = program.source;
    let entry = if arm == Arm::Native {
        program.native
    } else {
        source
    };
    let clock = program.clock.clone();
    let controls = (*program.controls()).clone();
    let (bad_reply, rejection_witness) = match rejection {
        None => (None, None),
        Some((fault, fd)) => (Some(fault), Some(fd)),
    };
    assert!(bad_reply.is_none() || (arm == Arm::Stop && !timed));
    let worker = std::thread::spawn(move || {
        pin(worker_cpu);
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        // A batch, not the complete campaign, is the finite lease obligation.
        // Native is an ordinary indirect-call baseline with no artificial guard.
        let lease = if arm == Arm::Native {
            None
        } else {
            Some(unsafe { clock.acquire(QUANTUM, ENCOUNTERS) }.expect("one exclusive batch lease"))
        };
        let mut state = State {
            pid: std::process::id(),
            tid,
            source,
            clock: clock.clone(),
            controls,
            call_index: 0,
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
        let function: unsafe extern "C" fn() -> u64 =
            unsafe { std::mem::transmute(entry as usize) };
        let mut checksum = 0u64;
        // All setup, including actual lease/TLS/affinity, precedes Ready. Each
        // one-shot channel has an empty slot, so its sole send cannot wait for
        // capacity. Both receives retain the existing bounded WAIT.
        assert_eq!(affinity(), [worker_cpu]);
        ready_tx
            .send((state.pid, tid, worker_cpu))
            .expect("worker Ready delivery");
        assert_eq!(
            go_rx
                .recv_timeout(counter::WAIT)
                .expect("bounded worker Go"),
            (state.pid, tid)
        );
        let start = timed.then(Instant::now);
        for call_index in 0..CALLS {
            state.call_index = call_index;
            let call = lease
                .as_ref()
                .map(|lease| lease.begin_call().expect("per-call admission"));
            let returned = unsafe { function() };
            if !timed {
                assert_eq!(returned, 12, "every qualification call returns twelve");
            }
            checksum = checksum.wrapping_add(returned);
            drop(call);
        }
        let elapsed_ns = start.map(|start| start.elapsed().as_nanos());
        drop(clear);
        let final_clock = unsafe { clock.snapshot_parked() };
        drop(lease);
        assert_eq!(affinity(), [worker_cpu]);
        (elapsed_ns, checksum, state.stops, final_clock, tid)
    });
    let (mut stops, mut inner, mut outer) = (0, 0, 0);
    // Spawn has returned and the controller counters exist before Go, for all
    // three arms and untimed qualification/rejection batches alike.
    let (ready_pid, ready_tid, ready_cpu) = ready_rx
        .recv_timeout(counter::WAIT)
        .expect("bounded controller Ready");
    assert_eq!((ready_pid, ready_cpu), (std::process::id(), worker_cpu));
    assert!(ready_tid > 0 && ready_tid != unsafe { libc::syscall(libc::SYS_gettid) });
    assert_eq!(affinity(), [controller_cpu]);
    go_tx
        .send((ready_pid, ready_tid))
        .expect("controller Go delivery");
    loop {
        match rx.recv_timeout(counter::WAIT) {
            Ok(event) => {
                assert_eq!(arm, Arm::Stop);
                assert!(stops < STOPS);
                let e = expected(QUANTUM * (stops as u64 + 1));
                assert_eq!(event.expected, e);
                assert!(accepts(source, e, &event.registers, event.words));
                assert_eq!(
                    unsafe { program.clock.snapshot_parked() },
                    (e.words, [CLOCK_CANARY; 4064])
                );
                // Exact saved frame and full clock while the worker waits;
                // no sleep, debugger or deliberate parked interval in timing.
                assert_eq!(
                    unsafe { registers(&*(event.frame as *const HookContext)) },
                    event.registers
                );
                assert_eq!(
                    unsafe { program.clock.snapshot_parked() },
                    (e.words, [CLOCK_CANARY; 4064])
                );
                assert_eq!(
                    unsafe { registers(&*(event.frame as *const HookContext)) },
                    event.registers
                );
                if e.site == 20 {
                    inner += 1;
                } else {
                    assert_eq!(e.site, 29);
                    outer += 1;
                }
                stops += 1;
                let reply = if let Some(fault) = bad_reply {
                    assert_eq!((stops, e), (1, expected(64)));
                    fault.reply(e)
                } else {
                    (e.site, e.words.counted)
                };
                resume_tx.send(reply).unwrap();
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("unchanged bounded handoff deadline"),
        }
    }
    let (elapsed_ns, checksum, closed_stops, (words, tail), tid) =
        worker.join().expect("exact worker joined");
    assert_eq!(tid, ready_tid, "joined worker must be the Ready sender");
    joined_worker_retired(tid);
    assert_eq!(affinity(), [controller_cpu]);
    assert_eq!(checksum, CHECKSUM);
    assert_eq!(closed_stops, stops);
    assert_eq!(tail, [CLOCK_CANARY; 4064]);
    let recorded = if arm == Arm::Native {
        assert_eq!((words, tail), before_clock);
        assert_eq!((stops, inner, outer), (0, 0, 0));
        None
    } else {
        assert_eq!(
            words,
            ClockWords {
                saved_rcx: 0,
                encounters: ENCOUNTERS,
                counted: TAKEN,
                remaining: QUANTUM
            }
        );
        assert_eq!(
            (stops, inner, outer),
            if arm == Arm::Stop {
                (STOPS, 288, 64)
            } else {
                (0, 0, 0)
            }
        );
        Some(words)
    };
    program.assert_code();
    ResultRow {
        elapsed_ns,
        checksum,
        stops,
        clock: recorded,
        tid,
    }
}

struct Child {
    pid: libc::pid_t,
    reaped: bool,
}
impl Child {
    fn wait(&mut self) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let mut status = 0;
            let found = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if found == self.pid {
                assert!(libc::WIFEXITED(status) || libc::WIFSIGNALED(status));
                self.reaped = true;
                return status;
            }
            assert_eq!(found, 0);
            assert!(Instant::now() < deadline, "rejection child deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut status = 0;
            let found = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if (found == self.pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)))
                || (found == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
            {
                self.reaped = true;
                break;
            }
            if Instant::now() >= deadline {
                assert!(std::thread::panicking(), "exact child cleanup deadline");
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
fn rejected_resumes(output: &Path, controller: usize, worker: usize) {
    let mut csv = String::from("fault,pid,tid,site,count,reply_site,reply_count,exit,result\n");
    for fault in [BadReply::Site, BadReply::Count] {
        single_main();
        assert_eq!(affinity(), [controller]);
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "one required rejection child, no retry");
        if pid == 0 {
            drop(read);
            let result = std::panic::catch_unwind(|| {
                // Fresh child owners/clock/lease; inherited idle images never execute.
                let program = RegionProgram::new_with_hook(ClockMode::Stop, hook);
                batch(
                    &program,
                    Arm::Stop,
                    controller,
                    worker,
                    false,
                    Some((fault, write)),
                );
            });
            unsafe { libc::_exit(if result.is_err() { 120 } else { 124 }) }
        }
        let mut child = Child { pid, reaped: false };
        drop(write);
        let status = child.wait();
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 123);
        let mut record = [0u8; REJECTION_BYTES + 1];
        assert_eq!(
            unsafe { libc::read(read.as_raw_fd(), record.as_mut_ptr().cast(), record.len()) },
            REJECTION_BYTES as isize
        );
        let mut extra = [0u8; 1];
        assert_eq!(
            unsafe { libc::read(read.as_raw_fd(), extra.as_mut_ptr().cast(), 1) },
            0
        );
        assert_eq!(&record[..8], REJECTION_MAGIC);
        let words: [u64; 30] = std::array::from_fn(|i| {
            u64::from_le_bytes(record[8 + i * 8..16 + i * 8].try_into().unwrap())
        });
        assert_eq!(words[0], fault.code());
        assert_eq!(words[1], pid as u64);
        assert!(words[2] > 0 && words[2] != words[1] && words[3] > 0);
        let reply = fault.reply(expected(64));
        assert_eq!(&words[4..12], &[20, 64, reply.0, reply.1, 3, 86, 64, 0]);
        let frame = &words[12..];
        assert_eq!(frame[0], words[3].checked_add(20).unwrap());
        assert!(frame[1] > 0);
        assert_eq!((frame[9], frame[15], frame[16]), (1, 3, 9));
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
            output.join(format!("rejection-{}.bin", fault.code())),
            &record[..REJECTION_BYTES],
        )
        .unwrap();
        csv.push_str(&format!(
            "{},{},{},20,64,{},{},123,PASS\n",
            fault.code(),
            pid,
            words[2],
            reply.0,
            reply.1
        ));
        std::fs::write(output.join("rejections.csv"), &csv).unwrap();
    }
    println!(
        "preemption:region-bench-rejections:2-children:2-before-refill-witnesses:2-exit123-echild"
    );
}

struct Row {
    arm: Arm,
    phase: &'static str,
    index: usize,
    status: &'static str,
    result: Option<ResultRow>,
}
fn save_rows(output: &Path, rows: &[Row]) {
    use std::fmt::Write;
    let mut csv = String::from(
        "pid,worker_tid,arm,phase,batch,status,calls,expected_encounters,expected_taken,elapsed_ns,checksum,clock_encounters,clock_taken,stops,remaining\n",
    );
    for row in rows {
        let values = row
            .result
            .as_ref()
            .map(|r| {
                let (encounters, taken, remaining) = r
                    .clock
                    .map(|w| {
                        (
                            w.encounters.to_string(),
                            w.counted.to_string(),
                            w.remaining.to_string(),
                        )
                    })
                    .unwrap_or_else(|| (String::new(), String::new(), String::new()));
                format!(
                    "{},{},{},{},{},{}",
                    r.elapsed_ns.map(|ns| ns.to_string()).unwrap_or_default(),
                    r.checksum,
                    encounters,
                    taken,
                    r.stops,
                    remaining
                )
            })
            .unwrap_or_else(|| ",,,,,".into());
        let tid = row
            .result
            .as_ref()
            .map(|r| r.tid.to_string())
            .unwrap_or_default();
        writeln!(
            csv,
            "{},{tid},{},{},{},{},{CALLS},{ENCOUNTERS},{TAKEN},{values}",
            std::process::id(),
            row.arm.name(),
            row.phase,
            row.index,
            row.status
        )
        .unwrap();
    }
    std::fs::write(output.join("measurements.next"), csv).unwrap();
    std::fs::rename(
        output.join("measurements.next"),
        output.join("measurements.csv"),
    )
    .unwrap();
}
pub(super) fn run(text: &str, output: &Path) {
    single_main();
    let ordered = order(text);
    let cpus = affinity();
    assert_eq!(cpus.len(), 2, "exact externally reserved disjoint CPU pair");
    let mut rows = Vec::new();
    for arm in [Arm::Native, Arm::Counter, Arm::Stop] {
        rows.push(Row {
            arm,
            phase: "qualification",
            index: 0,
            status: "UNOBSERVED",
            result: None,
        });
    }
    for arm in ordered {
        for index in 0..WARMUPS + MEASUREMENTS {
            rows.push(Row {
                arm,
                phase: if index < WARMUPS {
                    "warmup"
                } else {
                    "measured"
                },
                index: if index < WARMUPS {
                    index
                } else {
                    index - WARMUPS
                },
                status: "UNOBSERVED",
                result: None,
            });
        }
    }
    save_rows(output, &rows);
    std::fs::write(
        output.join("summary.json"),
        "{\"status\":\"INCOMPLETE\",\"profile\":\"owned-two-backedge-throughput-v1\"}\n",
    )
    .unwrap();
    let mut active = None;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        validate_schedule();
        // Both complete constructors run before any worker exists.
        let counter = RegionProgram::new_with_hook(ClockMode::Counter, hook);
        let stop = RegionProgram::new_with_hook(ClockMode::Stop, hook);
        pin(cpus[0]);
        let mut index = 0;
        while index < rows.len() {
            if index == 3 {
                rejected_resumes(output, cpus[0], cpus[1]);
            }
            active = Some(index);
            rows[index].status = "DISPATCHED";
            save_rows(output, &rows);
            let arm = rows[index].arm;
            let program = if arm == Arm::Stop { &stop } else { &counter };
            let result = batch(
                program,
                arm,
                cpus[0],
                cpus[1],
                rows[index].phase != "qualification",
                None,
            );
            rows[index].result = Some(result);
            rows[index].status = "PASS";
            active = None;
            save_rows(output, &rows);
            index += 1;
        }
        assert_eq!(rows.len(), 204);
    }));
    if let Err(error) = outcome {
        if let Some(index) = active {
            rows[index].status = "FAILED";
        }
        save_rows(output, &rows);
        std::fs::write(
            output.join("summary.json"),
            "{\"status\":\"FAILED\",\"profile\":\"owned-two-backedge-throughput-v1\"}\n",
        )
        .unwrap();
        std::panic::resume_unwind(error);
    }
    std::fs::write(output.join("summary.json"), format!(
        "{{\"status\":\"PASS\",\"profile\":\"owned-two-backedge-throughput-v1\",\"order\":\"{text}\",\"controller_cpu\":{},\"worker_cpu\":{},\"qualification_rows\":3,\"rejection_children\":2,\"rejection_witnesses\":2,\"warmup_rows\":9,\"measured_rows\":192,\"calls_per_batch\":2048,\"encounters_per_lease\":30720,\"quantum\":64,\"stop_handoffs_per_batch\":352,\"publisher_validation\":false,\"full_state_after_callback\":false,\"performance_threshold\":false}}\n", cpus[0],cpus[1])).unwrap();
    println!("preemption:region-bench:3-qualified:9-warmups:192-measured:no-outlier-filter");
}

#[cfg(test)]
mod tests {
    #[test]
    fn repeated_region_schedule_matches_nested_loop() {
        super::validate_schedule();
    }
}
