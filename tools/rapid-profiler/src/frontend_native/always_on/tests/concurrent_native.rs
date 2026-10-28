//! Native qualification; cfg(test) only. Requires a separately built trusted fixture.
use super::super::*;
use crate::frontend::{Action, ActionKind, Observation, PayloadOutcome, Report};
use crate::frontend_native::{
    CallGate, CallResult, IntegerLeafContract, LoadedIntegerLeaf, OrdinarySitePreparation,
};
use crate::generation::{Config, Disposition, FunctionId, Terminal};
use liteinst2::bundle::WritableAlias;
use liteinst2::contracts::*;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const LENGTHS: [usize; 6] = [1, 64, 1, 64, 1, 64];
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

fn publish(prep: OrdinarySitePreparation) -> crate::frontend_native::InstalledIntervalSite {
    // NEW qualification-only exclusion proof, not the old single_main claim:
    // this fresh exact-test subprocess has no other selected test. Its passive
    // libtest harness has no DSO/gate/owner capability. This test alone loaded
    // the fresh, constructor/dependency-free RTLD_LOCAL fixture. No subject
    // pointer escaped and no worker exists yet. There are no foreign callers,
    // signal entries, saved resumes, source writers or published entrypoints.
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
    // callable original method needs &mut self. No other thread has a
    // subject entry capability; no signal/foreign entry, saved resume or code writer exists.
    let mut exclusive = &prep;
    protect(source, libc::PROT_READ | libc::PROT_WRITE).unwrap();
    let alias = unsafe { WritableAlias::new(source, source.start() as usize as *mut u8) }.unwrap();
    let result = {
        // SAFETY: exclusive new-DSO entry ownership and full page/allocation ranges
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
    // SAFETY: exact successful transaction, final RX and the exclusive new-DSO proof above.
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

// Only the test build contains this fixed rendezvous; no arbitrary callback runs
// under model locks. The selected pause is after real Pair+journal publication.
pub(crate) struct EntryPause {
    ordinal: u64,
    entered: AtomicBool,
    resume: AtomicBool,
}
impl EntryPause {
    fn new(ordinal: u64) -> Self {
        Self {
            ordinal,
            entered: AtomicBool::new(false),
            resume: AtomicBool::new(false),
        }
    }
    pub(crate) fn wait(&self, ordinal: u64) -> Result<(), BridgeError> {
        if ordinal != self.ordinal {
            return Ok(());
        }
        if self.entered.swap(true, Ordering::AcqRel) {
            return Err(error(Cause::Invariant));
        }
        let until = Instant::now() + WAIT;
        while !self.resume.load(Ordering::Acquire) {
            if Instant::now() >= until {
                return Err(error(Cause::Invariant));
            }
            thread::yield_now();
        }
        Ok(())
    }
}
fn until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "required native rendezvous timed out"
        );
        thread::yield_now();
    }
}
struct Done {
    calls: Vec<CallResult>,
    rows: Vec<RawInterval>,
    totals: PairTotals,
    journal: [u64; 512],
    tid: u64,
}
struct Worker {
    commands: Option<mpsc::SyncSender<(u64, usize)>>,
    pause: Arc<EntryPause>,
    handle: Option<JoinHandle<Done>>,
}
impl Worker {
    fn send(&self, index: usize) {
        self.commands
            .as_ref()
            .unwrap()
            .send((100 + index as u64, LENGTHS[index]))
            .unwrap();
    }
    fn wait(&self) {
        let deadline = Instant::now() + WAIT;
        while !self.handle.as_ref().unwrap().is_finished() {
            if Instant::now() >= deadline {
                // Do not detach a worker or drop its borrowed native ownership.
                std::process::abort();
            }
            thread::yield_now();
        }
    }
    fn join(&mut self) -> Done {
        self.wait();
        self.handle
            .take()
            .unwrap()
            .join()
            .expect("native worker failed")
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.pause.resume.store(true, Ordering::Release);
        self.commands.take();
        if self.handle.is_some() {
            self.wait();
            let _ = self.handle.take().unwrap().join();
        }
    }
}

#[test]
#[ignore = "requires release fixture reproducer"]
fn ordinary_native_concurrent_arm_remove_and_old_owner() {
    // Mandatory explicit invocation: absence is FAILURE, never an implicit skip.
    let candidate = std::env::var_os("RAPID_CONCURRENT_CANDIDATE").expect("candidate ELF");
    let expected = std::env::var_os("RAPID_CONCURRENT_EXPECTED").expect("independent expected ELF");
    let candidate = Path::new(&candidate);
    let expected = Path::new(&expected);
    let bytes = expected_file(candidate, expected);
    let cpu = pin(None);
    // SAFETY: exact selected subprocess only; constructor/dependency-free trusted
    // compiler fixture, no other subject capability, no CET/signals/unwind/alias
    // writer/unload. The normal loader still checks every candidate byte/owner.
    let owner = unsafe {
        LoadedIntegerLeaf::load(candidate, &bytes, c"ordinary_checksum_nonempty", CONTRACT)
    }
    .unwrap();
    let entry = owner.entry();
    let returns: BTreeSet<_> = owner.certificate().returns().iter().copied().collect();
    let gate = CallGate::new(owner.certificate()).unwrap();
    let continuation = gate.continuation();
    let mut prep = OrdinarySitePreparation::new(owner, gate, identity(entry)).unwrap();
    assert_eq!(
        prep.role_pcs().collect::<Vec<_>>(),
        std::iter::once(entry)
            .chain(returns.iter().copied())
            .collect::<Vec<_>>()
    );
    let input_before = guarded();
    let input = Arc::new(input_before);
    let original_stack = stack();
    let mut originals = Vec::new();
    for length in LENGTHS {
        let slice = &input[16..16 + length];
        // SAFETY: exclusive uninstalled owner and actual mapped stack, same
        // trusted1..64 input and normal-return obligations as ordinary client.
        let result =
            unsafe { prep.invoke_original(slice.as_ptr(), slice.len(), &original_stack) }.unwrap();
        assert_eq!(result.value, model(slice));
        assert_eq!(result.pre_call_rsp, result.resumed_rsp);
        assert_eq!(*input, input_before);
        originals.push(result.value);
    }
    let site = publish(prep);
    let mut prepared = PreparedIntervalController::new(
        site,
        0x636f_6e01,
        FUNCTION,
        Limits {
            epochs: 2,
            threads: 1,
            depth: 1,
            records_per_epoch: 6,
            actions: 8,
        },
    )
    .unwrap();
    let config = Config {
        retained_per_function: 2,
        max_inflight: 1,
        max_invocations: 6,
    };
    let first = prepared.stage(config).unwrap();
    let second = prepared.stage(config).unwrap();
    let (g1, g2) = (first.generation(), second.generation());
    // SAFETY: no fork/TLS/client/outstanding work; publication already sealed.
    // The only deliberate test lock waits below depend on pre-lock WouldBlock,
    // never on callback acquisition/completion while the controller owns a lock.
    let (mut controller, client) = unsafe { prepared.activate_concurrent() }.unwrap();
    let pause = Arc::new(EntryPause::new(2));
    assert!(
        controller
            .binding
            .native_entry_pause
            .set(Arc::clone(&pause))
            .is_ok()
    );
    assert_eq!(controller.binding.session.interval_waits(), [0, 0]);
    let (command_tx, command_rx) = mpsc::sync_channel(1);
    let (ack_tx, ack_rx) = mpsc::sync_channel(1);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let worker_input = Arc::clone(&input);
    let handle = thread::spawn(move || {
        pin(Some(cpu));
        let readable = stack();
        // SAFETY: only this worker gets invocation authority after publication;
        // all source/generated/input/stack owners live through its final RET.
        let mut attached =
            unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
        let mut calls = Vec::with_capacity(6);
        ready_tx.send(()).unwrap();
        for (index, length) in LENGTHS.into_iter().enumerate() {
            // IDs assigned by controller before the actual invocation.
            let id = 100 + index as u64;
            assert_eq!(command_rx.recv_timeout(WAIT).unwrap(), (id, length));
            let slice = &worker_input[16..16 + length];
            // SAFETY: fixed immutable nonempty input, real sealed CALL gate,
            // pinned worker, no reentry/signal/nonlocal exit or source mutation.
            let result = unsafe { attached.invoke_integer_leaf(slice) }.unwrap();
            assert_eq!(result.value, model(slice));
            assert_eq!(result.pre_call_rsp, result.resumed_rsp);
            assert_eq!(result.entry_rsp.checked_add(8), Some(result.pre_call_rsp));
            assert_eq!(*worker_input, input_before);
            assert_eq!(attached.raw_intervals().unwrap().len(), index + 1);
            calls.push(result);
            ack_tx.send(id).unwrap();
        }
        let totals = attached.totals().unwrap();
        let rows = attached.raw_intervals().unwrap();
        // Only the actual attached worker reads its journal. No racy external
        // volatile reads of thread-owned non-atomic journal storage.
        let (journal, tid) = STATE.with(|cell| {
            let storage = cell.borrow();
            let state = storage.as_ref().unwrap();
            assert_eq!((state.depth, state.model.depth()), (0, 0));
            assert!(state.failure.is_none());
            (state.journal.page.0, state.tid)
        });
        assert_eq!(attached.detach().unwrap(), totals);
        Done {
            calls,
            rows,
            totals,
            journal,
            tid,
        }
    });
    let mut worker = Worker {
        commands: Some(command_tx),
        pause: Arc::clone(&pause),
        handle: Some(handle),
    };
    ready_rx
        .recv_timeout(WAIT)
        .expect("attached worker ready before contention");
    let ack = |index: usize| assert_eq!(ack_rx.recv_timeout(WAIT).unwrap(), 100 + index as u64);
    // Real postcommit arm path; writer and registry remain held in this closure.
    // Public arm's ControllerScope guard is tested separately, not exercised here.
    controller
        .binding
        .session
        .publish_with_controls(
            controller.owner(&first).unwrap(),
            FailurePoint::None,
            |_| {
                worker.send(0);
                until(|| controller.binding.session.interval_waits() == [1, 0]);
            },
        )
        .unwrap();
    ack(0);
    worker.send(1);
    until(|| pause.entered.load(Ordering::Acquire)); // actual second A reservation
    assert!(controller.report(&first).unwrap().is_none());
    controller.arm(&second).unwrap(); // public path, closes A with one live ticket
    assert!(controller.report(&first).unwrap().is_none());
    pause.resume.store(true, Ordering::Release);
    ack(1);
    let old = controller
        .report(&first)
        .unwrap()
        .expect("A drained after its own RET");
    let old_rows: Vec<_> = old.records().collect();
    assert_eq!(old_rows.len(), 2);
    for index in 2..5 {
        worker.send(index);
        ack(index);
    }
    assert!(controller.report(&second).unwrap().is_none()); // function closed, epoch still current
    controller
        .binding
        .session
        .remove_with_controls(Some(g2), |_| {
            worker.send(5);
            until(|| controller.binding.session.interval_waits() == [2, 0]);
        })
        .unwrap();
    ack(5);
    let done = worker.join();
    assert_eq!(*input, input_before);
    assert_eq!(Arc::strong_count(&input), 1);
    assert_eq!(controller.binding.session.interval_waits(), [2, 0]);
    assert_eq!(
        done.totals,
        PairTotals {
            entries: 6,
            returns: 6,
            completed: 4,
            unsampled: 2
        }
    );
    assert_eq!((done.calls.len(), done.rows.len()), (6, 6));
    let new = controller
        .report(&second)
        .unwrap()
        .expect("B drained after remove");
    check_report(&old, &done.rows[..2], g1.get(), 0);
    check_report(&new, &done.rows[2..4], g2.get(), 2);
    assert_eq!(old.records().collect::<Vec<_>>(), old_rows);
    assert_eq!(
        controller
            .report(&first)
            .unwrap()
            .unwrap()
            .records()
            .collect::<Vec<_>>(),
        old_rows
    );
    let history = controller.history().unwrap();
    assert_eq!(history.status, ControllerStatus::Ready);
    assert_eq!(history.current, None);
    assert_eq!(history.enabled, [true]); // mandatory hooks never disabled
    assert_eq!(history.retained_failed_generation, None);
    assert_eq!(
        history.actions,
        vec![
            Action {
                kind: ActionKind::Published,
                generation: g1,
                function: None,
                current: Some(g1),
                group: None
            },
            Action {
                kind: ActionKind::Published,
                generation: g2,
                function: None,
                current: Some(g2),
                group: None
            },
            Action {
                kind: ActionKind::Removed,
                generation: g2,
                function: None,
                current: None,
                group: None
            },
        ]
    );
    assert_eq!(
        done.rows
            .iter()
            .map(|r| r.return_pc)
            .collect::<BTreeSet<_>>(),
        returns
    );
    // Exact independently written packing: inv+1 | history_len<<13 | reason<<22.
    let bits = [8193, 8194, 16385, 16386, 12_599_296, 8_413_184];
    assert_eq!(&done.journal[..4], &[12, 0, done.tid, 0]);
    assert!(done.journal[4 + 12 * 7..].iter().all(|&v| v == 0));
    for (index, row) in done.rows.iter().enumerate() {
        let call = &done.calls[index];
        assert_eq!(row.ordinal, index as u64 + 1);
        assert_eq!(row.entry_pc, entry);
        assert_eq!(row.return_pc, call.return_pc);
        assert_eq!(call.value, originals[index]);
        assert!(
            row.elapsed_ticks().is_some(),
            "clock failure is not a timing PASS"
        );
        let (kind, generation) = if index < 4 {
            (1, if index < 2 { g1.get() } else { g2.get() })
        } else {
            (3, g2.get())
        };
        if index == 4 {
            assert_eq!(
                row.owner,
                RawIntervalOwner::FunctionClosed {
                    generation: g2.get()
                }
            );
        }
        if index == 5 {
            assert_eq!(
                row.owner,
                RawIntervalOwner::Removed {
                    generation: g2.get()
                }
            );
        }
        for side in 0..2 {
            let offset = 4 + (index * 2 + side) * 7;
            assert_eq!(
                &done.journal[offset..offset + 7],
                &[
                    kind + side as u64,
                    index as u64 + 1,
                    if side == 0 { entry } else { row.return_pc },
                    call.entry_rsp,
                    continuation,
                    generation,
                    bits[index],
                ]
            );
        }
    }
    println!(
        "concurrent-native PASS originals=6 calls=6 entries=6 returns=6 sampled=4 closed=1 removed=1 reports=2+2 writer_contentions=2 registry_contentions=0 inflight_rearm=1 joined=true"
    );
}

mod retirement_native;

mod drain_native;

mod history_native;
