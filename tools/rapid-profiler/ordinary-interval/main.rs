//! Fixed ordinary-DSO client, not function discovery or calibrated timing.
#![deny(warnings)]
#![forbid(unsafe_op_in_unsafe_fn)]

use joined_task::Handle as JoinHandle;
use liteinst2::bundle::WritableAlias;
use liteinst2::contracts::*;
use rapid_profiler::frontend::{Limits, Observation, PayloadOutcome, RecordObservation, Report};
use rapid_profiler::frontend_native::{
    CallGate, CallResult, IntegerLeafContract, IntervalJournal, LoadedIntegerLeaf,
    OrdinarySitePreparation, PairTotals, PreparedIntervalController, RawInterval, RawIntervalOwner,
    ReadableStack, SiteError,
};
use rapid_profiler::generation::{Config, Disposition, FunctionId, Terminal};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

mod backoff;
#[path = "selected/check.rs"]
mod consumer_checks;
mod counter;
mod exact;
mod joined_task;
mod normal;
mod selected;
mod streamed;
mod strnlen;
mod timed;
mod tree;

const LENGTHS: [usize; 8] = [1, 2, 17, 64, 3, 63, 7, 32];
const WAIT: Duration = Duration::from_secs(2);
const FUNCTION: FunctionId = FunctionId(1);
const CONTRACT: IntegerLeafContract = IntegerLeafContract {
    single_external_entry: true,
    ordinary_ret_only: true,
    no_active_cet: true,
};

fn pin(cpu: Option<usize>) -> usize {
    // Linux x86-64 affinity bitset, sized exactly as the native libc type.
    const WORDS: usize = std::mem::size_of::<libc::cpu_set_t>() / std::mem::size_of::<usize>();
    const BITS: usize = usize::BITS as usize;
    let mut allowed = [0_usize; WORDS];
    assert_eq!(
        unsafe {
            libc::sched_getaffinity(
                0,
                std::mem::size_of_val(&allowed),
                allowed.as_mut_ptr().cast(),
            )
        },
        0
    );
    let selected = cpu.unwrap_or_else(|| {
        (0..allowed.len() * BITS)
            .find(|&n| allowed[n / BITS] & (1 << (n % BITS)) != 0)
            .expect("nonempty CPU affinity")
    });
    assert!(
        selected < allowed.len() * BITS && allowed[selected / BITS] & (1 << (selected % BITS)) != 0
    );
    let mut one = [0_usize; WORDS];
    one[selected / BITS] = 1 << (selected % BITS);
    assert_eq!(
        unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&one), one.as_ptr().cast()) },
        0
    );
    assert_eq!(
        unsafe {
            libc::sched_getaffinity(
                0,
                std::mem::size_of_val(&allowed),
                allowed.as_mut_ptr().cast(),
            )
        },
        0
    );
    assert_eq!(allowed, one);
    assert_eq!(unsafe { libc::sched_getcpu() }, selected as i32);
    selected
}

fn single_main() {
    let pid = std::process::id();
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_gettid) },
        libc::c_long::from(pid)
    );
    let tasks: Vec<_> = std::fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<Result<_, _>>()
        .expect("complete task-directory observation");
    assert_eq!(tasks, [std::ffi::OsString::from(pid.to_string())]);
}

#[inline(never)]
fn establish_callback_stack() {
    // Grow the main thread's actual Linux stack mapping before observing it.
    // A reservation or an untouched large array does not prove mapped headroom.
    const BYTES: usize = 256 * 1024;
    let mut storage = std::mem::MaybeUninit::<[u8; BYTES]>::uninit();
    let bytes = storage.as_mut_ptr().cast::<u8>();
    for offset in (0..BYTES).step_by(4096) {
        // SAFETY: each write lies inside this live stack allocation. Volatile
        // writes force actual page touches; no uninitialized byte is read.
        unsafe { bytes.add(offset).write_volatile(0) };
    }
    unsafe { bytes.add(BYTES - 1).write_volatile(0) };
    std::hint::black_box(storage.as_mut_ptr());
}

fn stack() -> ReadableStack {
    establish_callback_stack();
    let rsp: u64;
    // SAFETY: observe the actual stack pointer, not the pthread reservation.
    unsafe {
        std::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let rows: Vec<_> = maps
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let (a, b) = words.next()?.split_once('-')?;
            let (a, b) = (
                u64::from_str_radix(a, 16).ok()?,
                u64::from_str_radix(b, 16).ok()?,
            );
            (a <= rsp && rsp < b).then(|| (a, b, words.next().unwrap()))
        })
        .collect();
    assert_eq!(rows.len(), 1, "one actual RSP VMA");
    let (start, end, permissions) = rows[0];
    assert_eq!(permissions, "rw-p");
    assert!(
        rsp.checked_sub(start).is_some_and(|n| n >= 128 * 1024),
        "mapped callback stack headroom"
    );
    // SAFETY: fixed native thread, no unmap/signal/nonlocal exit; the discovered
    // current VMA stays live through every real RET. No uncommitted reserve claimed.
    unsafe { ReadableStack::new(start, end) }.unwrap()
}

fn expected_file(candidate: &Path, expected: &Path) -> Vec<u8> {
    let mut file = File::open(expected).unwrap();
    let before = file.metadata().unwrap();
    let other = std::fs::metadata(candidate).unwrap();
    assert!(before.is_file() && other.is_file());
    assert_ne!(
        (before.dev(), before.ino()),
        (other.dev(), other.ino()),
        "independent expected file"
    );
    assert!((1..=1024 * 1024).contains(&before.len()));
    let mut bytes = Vec::new();
    (&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    let stamp = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    assert_eq!(stamp(&before), stamp(&file.metadata().unwrap()));
    assert_eq!(bytes.len() as u64, before.len());
    bytes
}

fn identity(entry: u64) -> CodeIdentity {
    // Caller-selected namespace, NOT a claimed hash. The loader authenticates
    // whole candidate bytes against the separately trusted expected ELF.
    CodeIdentity {
        source: SourceIdentity([0x6f; 32]),
        mapping: entry,
        generation: 1,
    }
}

fn protect(range: AddressRange, flags: i32) -> Result<(), Refusal> {
    // SAFETY: the caller exclusively owns this exact complete source-page range.
    if unsafe {
        libc::mprotect(
            range.start() as usize as *mut libc::c_void,
            range.len() as usize,
            flags,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

fn publish(
    prep: OrdinarySitePreparation,
) -> rapid_profiler::frontend_native::InstalledIntervalSite {
    single_main();
    let planned = prep.plan();
    let originals = planned.plan().originals();
    assert_eq!(originals.len(), 1);
    let source = AddressRange::new(originals[0].address, originals[0].bytes.len()).unwrap();
    assert_eq!(source.start() % 4096, 0);
    assert!(matches!(source.len(), 4096 | 8192));
    let mut ranges = vec![source];
    ranges.extend(
        planned
            .plan()
            .steps()
            .iter()
            .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
    );
    // The borrowed complete preparation is the publication guard: its only
    // callable original method needs &mut self. This binary still has one
    // thread, no signal handler/foreign entry/saved resume, and no code writer.
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    let alias = unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap();
    let result = {
        // SAFETY: actual single-thread exclusion and full page/allocation ranges
        // above; no source execution is admitted before successful sealing.
        let mut lease =
            unsafe { QuiescenceLease::new(&mut exclusive, planned.plan().identity(), ranges) };
        let result = unsafe {
            planned.publish_with(&[alias], &mut lease, || {
                protect(source, libc::PROT_READ | libc::PROT_EXEC)
            })
        };
        if result.is_ok() {
            assert!(!lease.is_poisoned());
        }
        result
    };
    let (installed, receipt) = match result {
        Ok(pair) => pair,
        Err(failure) => {
            // Never unwind/drop controls past a partially published source.
            // Process termination retains/gates all code until the OS reclaims it.
            eprintln!("ordinary publication FAILED: {failure:?}");
            std::process::abort();
        }
    };
    // SAFETY: exact successful transaction, final RX and sole-thread exclusion.
    // seal retains source, control, image, receipt and installed owners forever,
    // including correspondence refusal. No unload/retire/reclaim is attempted.
    unsafe { prep.seal(installed, receipt) }.unwrap()
}

fn guarded() -> [u8; 96] {
    let mut bytes = [0xa5; 96];
    for (i, b) in bytes[16..80].iter_mut().enumerate() {
        *b = (i * 37 + 11) as u8;
    }
    bytes[80..].fill(0x5a);
    bytes
}
fn model(bytes: &[u8]) -> u64 {
    assert!((1..=64).contains(&bytes.len()));
    bytes.iter().map(|&b| u64::from(b ^ 0x5a)).sum::<u64>() ^ 0x9e37_79b9_7f4a_7c15
}

struct Done {
    calls: Vec<CallResult>,
    rows: Vec<RawInterval>,
    totals: PairTotals,
}
struct Worker<T> {
    resume: Option<mpsc::SyncSender<()>>,
    handle: Option<JoinHandle<T>>,
}
impl<T> Worker<T> {
    fn wait(&self, until: Instant) {
        while !self.handle.as_ref().unwrap().is_finished() {
            if Instant::now() >= until {
                eprintln!("ordinary worker FAILED to close within 2 seconds");
                std::process::abort(); // No detached worker can outlive input ownership.
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
    fn finish(&mut self) -> thread::Result<T> {
        // One existing WAIT covers closure completion, native join and task
        // retirement. No second allowance begins when pthread_join returns.
        let until = Instant::now() + WAIT;
        self.wait(until);
        let mut joined = self.handle.take().unwrap().join();
        if let Err(error) = joined.wait_until(until) {
            eprintln!("ordinary worker FAILED to retire: {error}");
            std::process::abort(); // Keep result and caller owners until fail-stop.
        }
        joined.into_result()
    }
    fn join(&mut self) -> T {
        self.finish().expect("worker failure")
    }
}
impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        self.resume.take(); // Disconnect a parked worker on main-thread failure.
        if self.handle.is_some() {
            let _ = self.finish();
        }
    }
}

fn check_report(report: &Report, rows: &[RawInterval], generation: u64, sequence: u64) {
    assert_eq!(report.generation().get(), generation);
    let records: Vec<_> = report.records().collect();
    assert_eq!(records.len(), rows.len());
    for (rank, (record, row)) in records.iter().zip(rows).enumerate() {
        let admission = record.record.admission;
        assert_eq!(
            row.owner,
            RawIntervalOwner::Sampled {
                generation,
                invocation: rank
            }
        );
        assert_eq!(admission.generation.get(), generation);
        assert_eq!(admission.function, FUNCTION);
        assert_eq!(admission.invocation, rank);
        assert_eq!(admission.entry_value, row.start.ticks);
        // The frontend terminal stores its invocation index; the separately
        // published payload carries the endpoint observation checked below.
        assert_eq!(
            record.record.terminal,
            Some(Terminal::Completed {
                value: admission.invocation as u64,
                disposition: Disposition::Retained { rank },
            })
        );
        let payload = record.payload.unwrap();
        assert_eq!(payload.admission, admission);
        assert_eq!(payload.thread, 1);
        assert_eq!(payload.start_sequence, sequence + rank as u64);
        assert_eq!(
            payload.outcome,
            PayloadOutcome::Completed {
                end: Observation::Value(row.end.ticks),
                completed_children: 0
            }
        );
    }
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-observer-backoff-pending-owner") {
        normal::observer::backoff::pending_owner::run(&args[2..]);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-observer-backoff") {
        normal::observer::backoff::run(&args[2..]);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-observer-throughput") {
        normal::observer::throughput::run(&args[2..]);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-observer-work") {
        normal::observer::run(&args[2..]);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-reference-leg") {
        normal::reference::leg::run(&args[2..]);
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-reference-work") {
        assert_eq!(
            args.len(),
            8,
            "ordinary-interval normal-reference-work CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL"
        );
        normal::reference::run(
            Path::new(&args[2]),
            Path::new(&args[3]),
            strnlen::number(args[4].to_str().unwrap()),
            strnlen::number(args[5].to_str().unwrap()),
            Path::new(&args[6]),
            Path::new(&args[7]),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-session-two-exact") {
        assert_eq!(
            args.len(),
            8,
            "ordinary-interval normal-session-two-exact CANDIDATE FINAL ELF_VA LENGTH K EPOCHS"
        );
        normal::session::two::run_exact(
            Path::new(&args[2]),
            Path::new(&args[3]),
            strnlen::number(args[4].to_str().unwrap()),
            strnlen::number(args[5].to_str().unwrap()),
            usize::try_from(strnlen::number(args[6].to_str().unwrap())).unwrap(),
            u32::try_from(strnlen::number(args[7].to_str().unwrap())).unwrap(),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-session-two") {
        assert_eq!(
            args.len(),
            8,
            "ordinary-interval normal-session-two CANDIDATE FINAL ELF_VA LENGTH K EPOCHS"
        );
        normal::session::two::run(
            Path::new(&args[2]),
            Path::new(&args[3]),
            strnlen::number(args[4].to_str().unwrap()),
            strnlen::number(args[5].to_str().unwrap()),
            usize::try_from(strnlen::number(args[6].to_str().unwrap())).unwrap(),
            u32::try_from(strnlen::number(args[7].to_str().unwrap())).unwrap(),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("normal-session") {
        assert_eq!(
            args.len(),
            8,
            "ordinary-interval normal-session CANDIDATE FINAL ELF_VA LENGTH K EPOCHS"
        );
        normal::session::run(
            Path::new(&args[2]),
            Path::new(&args[3]),
            strnlen::number(args[4].to_str().unwrap()),
            strnlen::number(args[5].to_str().unwrap()),
            args[6].to_str().unwrap().parse().unwrap(),
            args[7].to_str().unwrap().parse().unwrap(),
        );
        return;
    }
    if let Some(mode) = args
        .get(1)
        .and_then(|s| s.to_str())
        .and_then(normal::Mode::parse)
    {
        assert_eq!(
            args.len(),
            8,
            "ordinary-interval normal-work CANDIDATE FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL"
        );
        normal::run(
            Path::new(&args[2]),
            Path::new(&args[3]),
            strnlen::number(args[4].to_str().unwrap()),
            strnlen::number(args[5].to_str().unwrap()),
            Path::new(&args[6]),
            Path::new(&args[7]),
            mode,
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("strnlen-work") {
        assert_eq!(
            args.len(),
            6,
            "ordinary-interval strnlen-work CANDIDATE FINAL ELF_VA LENGTH"
        );
        strnlen::run(
            Path::new(&args[2]),
            Path::new(&args[3]),
            strnlen::number(args[4].to_str().unwrap()),
            strnlen::number(args[5].to_str().unwrap()),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("strnlen-refusals") {
        assert_eq!(
            args.len(),
            7,
            "ordinary-interval strnlen-refusals PRESTRIP FINAL MUTATED ELF_VA LENGTH"
        );
        strnlen::refusals(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
            strnlen::number(args[5].to_str().unwrap()),
            strnlen::number(args[6].to_str().unwrap()),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("selected-work") {
        assert_eq!(
            args.len(),
            6,
            "ordinary-interval selected-work CANDIDATE FINAL ELF_VA LENGTH"
        );
        selected::run(
            Path::new(&args[2]),
            Path::new(&args[3]),
            selected::number(args[4].to_str().unwrap()),
            selected::number(args[5].to_str().unwrap()),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("selected-refusals") {
        assert_eq!(
            args.len(),
            7,
            "ordinary-interval selected-refusals PRESTRIP FINAL MUTATED ELF_VA LENGTH"
        );
        selected::refusals(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
            selected::number(args[5].to_str().unwrap()),
            selected::number(args[6].to_str().unwrap()),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("tree-comparison-batch") {
        assert_eq!(
            args.len(),
            5,
            "ordinary-interval tree-comparison-batch MODE CANDIDATE TRUSTED"
        );
        tree::throughput::batch::run(
            args[2].to_str().unwrap(),
            Path::new(&args[3]),
            Path::new(&args[4]),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("tree-comparison") {
        assert_eq!(
            args.len(),
            5,
            "ordinary-interval tree-comparison MODE CANDIDATE TRUSTED"
        );
        tree::throughput::run_matched(
            args[2].to_str().unwrap(),
            Path::new(&args[3]),
            Path::new(&args[4]),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("tree-throughput") {
        assert_eq!(
            args.len(),
            5,
            "ordinary-interval tree-throughput MODE CANDIDATE TRUSTED"
        );
        tree::throughput::run(
            args[2].to_str().unwrap(),
            Path::new(&args[3]),
            Path::new(&args[4]),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("tree-population") {
        assert_eq!(
            args.len(),
            5,
            "ordinary-interval tree-population CANDIDATE TRUSTED K"
        );
        tree::run(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].to_str().unwrap().parse().unwrap(),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("counter-cache-probe") {
        assert_eq!(
            args.len(),
            5,
            "ordinary-interval counter-cache-probe CANDIDATE TRUSTED NEW_OUTPUT_DIRECTORY"
        );
        std::process::exit(counter::run(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
        ));
    }
    if matches!(
        args.get(1).and_then(|s| s.to_str()),
        Some("optional-backoff-work-sink-wait" | "optional-backoff-work-both-wait")
    ) {
        assert_eq!(
            args.len(),
            8,
            "ordinary-interval optional-backoff-work-sink-wait or optional-backoff-work-both-wait CANDIDATE TRUSTED K EPOCHS CALL_LIMIT NEW_EXPORT_FILE"
        );
        backoff::run_optional_sink_wait(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].to_str().unwrap().parse().unwrap(),
            args[5].to_str().unwrap().parse().unwrap(),
            args[6].to_str().unwrap().parse().unwrap(),
            Path::new(&args[7]),
            args[1].to_str() == Some("optional-backoff-work-both-wait"),
        );
        return;
    }
    if matches!(
        args.get(1).and_then(|s| s.to_str()),
        Some("optional-backoff-work" | "optional-backoff-work-wait")
    ) {
        assert_eq!(
            args.len(),
            8,
            "ordinary-interval optional-backoff-work[-wait] CANDIDATE TRUSTED K EPOCHS CALL_LIMIT NEW_EXPORT_FILE"
        );
        backoff::run_optional(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].to_str().unwrap().parse().unwrap(),
            args[5].to_str().unwrap().parse().unwrap(),
            args[6].to_str().unwrap().parse().unwrap(),
            Path::new(&args[7]),
            args[1].to_str() == Some("optional-backoff-work-wait"),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("backoff-work-wait") {
        assert_eq!(
            args.len(),
            8,
            "ordinary-interval backoff-work-wait CANDIDATE TRUSTED K EPOCHS CALL_LIMIT NEW_EXPORT_FILE"
        );
        backoff::run_wait(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].to_str().unwrap().parse().unwrap(),
            args[5].to_str().unwrap().parse().unwrap(),
            args[6].to_str().unwrap().parse().unwrap(),
            Path::new(&args[7]),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("backoff-work") {
        assert_eq!(
            args.len(),
            8,
            "ordinary-interval backoff-work CANDIDATE TRUSTED K EPOCHS CALL_LIMIT NEW_EXPORT_FILE"
        );
        backoff::run(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].to_str().unwrap().parse().unwrap(),
            args[5].to_str().unwrap().parse().unwrap(),
            args[6].to_str().unwrap().parse().unwrap(),
            Path::new(&args[7]),
        );
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("streamed-work") {
        assert_eq!(
            args.len(),
            4,
            "ordinary-interval streamed-work CANDIDATE TRUSTED"
        );
        streamed::run(Path::new(&args[2]), Path::new(&args[3]));
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("timed-work") {
        assert_eq!(
            args.len(),
            4,
            "ordinary-interval timed-work CANDIDATE TRUSTED"
        );
        timed::run(Path::new(&args[2]), Path::new(&args[3]));
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("exact-reference") {
        assert_eq!(
            args.len(),
            4,
            "ordinary-interval exact-reference CANDIDATE TRUSTED"
        );
        exact::run_reference(Path::new(&args[2]), Path::new(&args[3]));
        return;
    }
    if args.get(1).and_then(|s| s.to_str()) == Some("exact-work") {
        assert_eq!(
            args.len(),
            6,
            "ordinary-interval exact-work CANDIDATE TRUSTED SCHEDULE K"
        );
        exact::run(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].to_str().unwrap(),
            args[5].to_str().unwrap().parse().unwrap(),
        );
        return;
    }
    assert_eq!(
        args.len(),
        3,
        "usage: ordinary-interval CANDIDATE_ELF INDEPENDENT_TRUSTED_EXPECTED_ELF"
    );
    let (candidate, expected) = (Path::new(&args[1]), Path::new(&args[2]));
    single_main();
    let cpu = pin(None);
    let bytes = expected_file(candidate, expected);
    // SAFETY: this explicit executable is only for independently pinned trusted
    // compiler output of the supplied two C functions. Arbitrary ELF is outside
    // its contract. No DSO constructors/dependencies, foreign callers, CET,
    // signals/nonlocal exits, aliases, unload, or concurrent source mutation.
    let negative =
        unsafe { LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum", CONTRACT) }
            .unwrap();
    let certificate = negative.certificate();
    assert!(
        certificate
            .returns()
            .iter()
            .any(|&ret| certificate.blocks().contains(&(ret, ret + 1))),
        "required real one-byte RET block"
    );
    let negative_id = identity(negative.entry());
    let gate = CallGate::new(certificate).unwrap();
    assert!(
        matches!(
            OrdinarySitePreparation::new(negative, gate, negative_id),
            Err(SiteError::Core(Refusal::NoPatchWindow))
        ),
        "short RET must refuse the whole factory"
    );

    // SAFETY: same trusted whole ELF; positive symbol additionally requires1..64.
    let owner = unsafe {
        LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum_nonempty", CONTRACT)
    }
    .unwrap();
    let entry = owner.entry();
    let returns: BTreeSet<_> = owner.certificate().returns().iter().copied().collect();
    let gate = CallGate::new(owner.certificate()).unwrap();
    let mut prep = OrdinarySitePreparation::new(owner, gate, identity(entry)).unwrap();
    assert_eq!(
        prep.role_pcs().collect::<Vec<_>>(),
        std::iter::once(entry)
            .chain(returns.iter().copied())
            .collect::<Vec<_>>()
    );
    let expected_input = guarded();
    let input = Arc::new(expected_input);
    let original_stack = stack();
    let mut originals = Vec::new();
    for length in LENGTHS {
        let slice = &input[16..16 + length];
        // SAFETY: unpatched trusted nonempty symbol, complete readable actual
        // stack VMA, immutable bounded buffer, one thread and no publication yet.
        let result =
            unsafe { prep.invoke_original(slice.as_ptr(), slice.len(), &original_stack) }.unwrap();
        assert_eq!(result.value, model(slice));
        assert_eq!(result.pre_call_rsp, result.resumed_rsp);
        assert_eq!(*input, expected_input);
        originals.push(result.value);
    }
    let site = publish(prep);
    let mut prepared = PreparedIntervalController::new(
        site,
        0x6f72_6401,
        FUNCTION,
        Limits {
            epochs: 2,
            threads: 1,
            depth: 1,
            records_per_epoch: 8,
            actions: 8,
        },
    )
    .unwrap();
    let first = prepared
        .stage(Config {
            retained_per_function: 4,
            max_inflight: 1,
            max_invocations: 8,
        })
        .unwrap();
    let second = prepared
        .stage(Config {
            retained_per_function: 2,
            max_inflight: 1,
            max_invocations: 8,
        })
        .unwrap();
    let (g1, g2) = (first.generation().get(), second.generation().get());
    // SAFETY: no fork, source publication complete; no client/TLS exists yet.
    let (mut controller, client) = unsafe { prepared.activate() }.unwrap();
    controller.arm(&first).unwrap();
    let (park_tx, park_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let worker_input = Arc::clone(&input);
    let handle = joined_task::spawn(move || {
        pin(Some(cpu));
        let readable = stack();
        // SAFETY: matching sealed site, actual worker/VMA, only this worker calls
        // the private gate; all code/source owners are process-lived.
        let mut attached =
            unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
        let mut calls = Vec::new();
        for (index, length) in LENGTHS.into_iter().enumerate() {
            let slice = &worker_input[16..16 + length];
            // SAFETY: exact nonempty1..64 input, matching attached gate; no
            // signal, nonlocal exit, reentry, mutation or code reclamation.
            let result = unsafe { attached.invoke_integer_leaf(slice) }.unwrap();
            assert_eq!(result.value, model(slice));
            assert_eq!(result.pre_call_rsp, result.resumed_rsp);
            assert_eq!(result.entry_rsp.checked_add(8), Some(result.pre_call_rsp));
            assert_eq!(*worker_input, expected_input);
            calls.push(result);
            if index == 5 {
                assert_eq!(
                    attached.totals().unwrap(),
                    PairTotals {
                        entries: 6,
                        returns: 6,
                        completed: 4,
                        unsampled: 2
                    }
                );
                park_tx.send(()).unwrap();
                resume_rx
                    .recv_timeout(WAIT)
                    .expect("controller rearm rendezvous");
            }
        }
        let totals = attached.totals().unwrap(); // Empty, unpoisoned state required.
        let rows = attached.raw_intervals().unwrap(); // Only this worker reads TLS.
        assert_eq!(rows.len(), 8);
        assert_eq!(attached.detach().unwrap(), totals);
        assert_eq!(*worker_input, expected_input);
        Done {
            calls,
            rows,
            totals,
        }
    });
    // Declared after input: failure cleanup always joins before its last owner drops.
    let mut worker = Worker {
        resume: Some(resume_tx),
        handle: Some(handle),
    };
    park_rx
        .recv_timeout(WAIT)
        .expect("six-call worker rendezvous");
    controller.disarm(&first).unwrap();
    let old_report = controller
        .report(&first)
        .unwrap()
        .expect("old owner drained");
    let old_generation = old_report.generation();
    let old_rows: Vec<RecordObservation> = old_report.records().collect();
    assert_eq!(old_rows.len(), 4);
    controller.arm(&second).unwrap();
    worker.resume.as_ref().unwrap().send(()).unwrap();
    let done = worker.join();
    assert_eq!(*input, expected_input);
    assert_eq!(
        Arc::strong_count(&input),
        1,
        "worker input owner ended after join"
    );
    assert_eq!(
        done.totals,
        PairTotals {
            entries: 8,
            returns: 8,
            completed: 6,
            unsampled: 2
        }
    );
    assert_eq!(done.calls.len(), 8);
    controller.disarm(&second).unwrap();
    let new_report = controller
        .report(&second)
        .unwrap()
        .expect("new owner drained");
    assert_eq!(old_report.generation(), old_generation);
    assert_eq!(old_report.records().collect::<Vec<_>>(), old_rows);
    let queried_old = controller.report(&first).unwrap().unwrap();
    assert_eq!(queried_old.generation(), old_generation);
    assert_eq!(queried_old.records().collect::<Vec<_>>(), old_rows);
    check_report(&old_report, &done.rows[..4], g1, 0);
    check_report(&new_report, &done.rows[6..], g2, 4);
    assert_eq!(
        done.rows
            .iter()
            .map(|r| r.return_pc)
            .collect::<BTreeSet<_>>(),
        returns,
        "complete actual RET coverage"
    );
    for (index, row) in done.rows.iter().enumerate() {
        assert_eq!(row.ordinal, index as u64 + 1);
        assert_eq!(row.entry_pc, entry);
        assert_eq!(row.return_pc, done.calls[index].return_pc);
        assert_eq!(done.calls[index].value, originals[index]);
        assert!(
            row.elapsed_ticks().is_some(),
            "raw endpoint unavailable, no timing PASS"
        );
        if (4..6).contains(&index) {
            assert_eq!(
                row.owner,
                RawIntervalOwner::FunctionClosed { generation: g1 }
            );
        }
    }
    pin(Some(cpu));
    single_main();
    println!(
        "# raw callback-positioned RDTSCP ticks; uncalibrated, includes instrumentation/descheduling; no accuracy or nanosecond claim"
    );
    println!(
        "ordinal,length,owner,generation,invocation,ret_offset,native_value,value,start_ticks,end_ticks,start_aux,end_aux,elapsed_ticks"
    );
    for (index, row) in done.rows.iter().enumerate() {
        let (owner, generation, invocation) = match row.owner {
            RawIntervalOwner::Sampled {
                generation,
                invocation,
            } => ("sampled", generation, invocation.to_string()),
            RawIntervalOwner::FunctionClosed { generation } => {
                ("closed", generation, String::new())
            }
            _ => unreachable!("exact two-owner schedule checked"),
        };
        println!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{}",
            row.ordinal,
            LENGTHS[index],
            owner,
            generation,
            invocation,
            row.return_pc - entry,
            originals[index],
            done.calls[index].value,
            row.start.ticks,
            row.end.ticks,
            row.start.aux,
            row.end.aux,
            row.elapsed_ticks().unwrap()
        );
    }
    println!(
        "ordinary-interval PASS originals=8 calls=8 entries=8 returns=8 completed=6 unsampled=2 raw_rows=8 reports=4+2 short_ret_refused=true input_unchanged=true joined=true"
    );
}
