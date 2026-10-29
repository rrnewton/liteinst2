//! Module adapter for the existing receive/idle-flush/stop loop.
use super::*;
use rapid_profiler::frontend_native::{NormalModuleClient, NormalModuleThread};
use shared::worker::{Event, Runtime};
use std::path::PathBuf;
use std::sync::OnceLock;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::normal) struct Identity {
    pub pid: u32,
    pub tid: u64,
    pub cpu: usize,
    pub stack: (u64, u64),
    pub caller: (u64, u64),
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Stamp {
    dev: u64,
    ino: u64,
    mode: u32,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl Stamp {
    fn read(path: &Path) -> Self {
        let m = std::fs::metadata(path).unwrap();
        assert!(m.is_file());
        Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            len: m.len(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}
pub(in crate::normal) struct Custody {
    paths: [PathBuf; 2],
    stamps: [Stamp; 2],
    bytes: Vec<u8>,
    pub source: Vec<(u64, Vec<u8>)>,
    pub generated: Vec<(u64, Vec<u8>)>,
    pub pid: u32,
}
impl Custody {
    pub(in crate::normal) fn new(candidate: &Path, trusted: &Path, bytes: Vec<u8>) -> Self {
        let paths = [candidate.to_path_buf(), trusted.to_path_buf()];
        let stamps = paths.each_ref().map(|p| Stamp::read(p));
        assert_ne!(
            (stamps[0].dev, stamps[0].ino),
            (stamps[1].dev, stamps[1].ino)
        );
        Self {
            paths,
            stamps,
            bytes,
            source: Vec::new(),
            generated: Vec::new(),
            pid: std::process::id(),
        }
    }
    pub(in crate::normal) fn files_and_code(&self) {
        assert_eq!(std::process::id(), self.pid);
        for i in 0..2 {
            assert_eq!(Stamp::read(&self.paths[i]), self.stamps[i]);
            let mut actual = Vec::new();
            File::open(&self.paths[i])
                .unwrap()
                .take(1024 * 1024 + 1)
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, self.bytes);
            assert_eq!(Stamp::read(&self.paths[i]), self.stamps[i]);
        }
        for (spans, mode) in [(&self.source, "r-xp"), (&self.generated, "r-xs")] {
            for (address, bytes) in spans {
                let (a, b) = csv::mapping(*address, mode);
                assert!(
                    a <= *address
                        && address
                            .checked_add(bytes.len() as u64)
                            .is_some_and(|end| end <= b)
                );
            }
            // Process-lived sealed owners and the no-writer/no-unmap contract
            // remain authority. A scan alone does not establish safe custody.
            unsafe { immutable(spans) };
        }
    }
    pub(in crate::normal) fn worker(&self, expected: Identity) {
        assert_eq!(std::process::id(), expected.pid);
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) } as u64,
            expected.tid
        );
        cpu_is(expected.cpu);
        assert_eq!(csv::stack_bounds(), expected.stack);
        assert_eq!(
            csv::mapping(csv::invoke as *const () as usize as u64, "r-xp"),
            expected.caller
        );
        let mut tasks: Vec<u64> = std::fs::read_dir("/proc/self/task")
            .unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap())
            .collect();
        tasks.sort_unstable();
        let mut expected_tasks = [u64::from(expected.pid), expected.tid];
        expected_tasks.sort_unstable();
        assert_ne!(expected.tid, u64::from(expected.pid));
        assert_eq!(tasks, expected_tasks);
        self.files_and_code();
    }
}
pub(in crate::normal) fn cpu_is(cpu: usize) {
    let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert!(cpu < libc::CPU_SETSIZE as usize);
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&mask), &mut mask) },
        0
    );
    assert_eq!(unsafe { libc::CPU_COUNT(&mask) }, 1);
    assert!(unsafe { libc::CPU_ISSET(cpu, &mask) });
    assert_eq!(unsafe { libc::sched_getcpu() }, cpu as i32);
}
#[repr(C)]
struct Stored {
    before: [u64; 2],
    value: u64,
    after: [u64; 2],
}
pub(in crate::normal) struct Call {
    pub record: Arc<input::Record>,
    pub function: usize,
    stored: Box<Stored>,
}
impl Call {
    // The caller must authenticate the actual target and retain code/input owners.
    // This private extraction does not fabricate return or SDK acknowledgement.
    pub(in crate::normal) unsafe fn invoke(
        record: Arc<input::Record>,
        function: usize,
        target: csv::Csv,
    ) -> Self {
        let mut call = Call {
            record,
            function,
            stored: Box::new(Stored {
                before: [0xa7a7; 2],
                value: u64::MAX,
                after: [0x5a5a; 2],
            }),
        };
        assert_eq!(call.stored.value, u64::MAX);
        // SAFETY: exact independently selected scalar ABI, immutable guarded
        // bytes and live sealed owner; real ordinary CALL then volatile store.
        unsafe { csv::invoke(target, call.record.bytes(), &mut call.stored.value) };
        call
    }

    pub(in crate::normal) fn value(&self) -> u64 {
        self.stored.value
    }
    pub(super) fn check(&self) {
        self.record.check();
        assert!(self.function < 2);
        assert_eq!(self.stored.before, [0xa7a7; 2]);
        assert_eq!(self.stored.after, [0x5a5a; 2]);
        assert_eq!(
            self.value(),
            if self.function == 0 {
                self.record.fields
            } else {
                self.record.length as u64
            }
        );
    }
    pub(in crate::normal) fn check_expected(&self, n: usize, expected: u64) {
        self.record.check();
        assert!((1..=4).contains(&n) && self.function < n);
        assert_eq!(self.stored.before, [0xa7a7; 2]);
        assert_eq!(self.stored.after, [0x5a5a; 2]);
        assert_eq!(self.value(), expected);
    }
    #[cfg(test)]
    pub(in crate::normal) fn corrupt_guard_for_test(&mut self, before: bool) {
        if before {
            self.stored.before[1] ^= 1;
        } else {
            self.stored.after[0] ^= 1;
        }
    }
    #[cfg(test)]
    pub(in crate::normal) fn fabricated(
        record: Arc<input::Record>,
        function: usize,
        value: u64,
    ) -> Self {
        Self {
            record,
            function,
            stored: Box::new(Stored {
                before: [0xa7a7; 2],
                value,
                after: [0x5a5a; 2],
            }),
        }
    }
}
// Declared first so a panic cannot unwind attached owners before process abort.
// No caught panic or Result failure is a fabricated detach/return acknowledgement.
pub(super) struct Worker {
    fail_stop: csv::FailStop,
    attached: Option<NormalModuleThread>,
    calls: Vec<Call>,
    targets: [csv::Csv; 2],
    custody: Arc<Custody>,
    identity: Identity,
}
impl Worker {
    pub(super) fn attach(
        entries: [u64; 2],
        client: NormalModuleClient,
        custody: Arc<Custody>,
        cpu: usize,
    ) -> Self {
        let mut fail_stop = csv::FailStop(true);
        pin(Some(cpu));
        let readable = stack();
        let identity = Identity {
            pid: std::process::id(),
            tid: unsafe { libc::syscall(libc::SYS_gettid) } as u64,
            cpu,
            stack: csv::stack_bounds(),
            caller: csv::mapping(csv::invoke as *const () as usize as u64, "r-xp"),
        };
        custody.worker(identity);
        // SAFETY: sole actual calling worker, original stack/no signal/reentry or
        // nonlocal exits, immutable two-function module and independent controller.
        let attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
        assert_eq!(attached.totals().unwrap(), NormalTotals::default());
        let worker = Self {
            fail_stop: csv::FailStop(true),
            attached: Some(attached),
            calls: Vec::with_capacity(4),
            targets: entries
                .map(|entry| unsafe { std::mem::transmute::<usize, csv::Csv>(entry as usize) }),
            custody,
            identity,
        };
        fail_stop.0 = false;
        worker
    }
    pub(super) fn call_one(&mut self, record: Arc<input::Record>, function: usize) {
        assert!(self.calls.len() < 4 && function < 2);
        self.postflight();
        record.check();
        // SAFETY: unchanged authenticated worker target and retained owners.
        let call = unsafe { Call::invoke(record, function, self.targets[function]) };
        call.check();
        self.calls.push(call); // Returned owner survives every subsequent refusal.
        self.postflight();
    }
    pub(super) fn postflight(&self) {
        self.custody.worker(self.identity);
        for call in &self.calls {
            call.check();
        }
    }
    // Complete postflight and actual checkpoint are shared; no adapter can
    // manufacture a returned call from a phase counter or output row.
    pub(super) fn take_batch(&mut self) -> Option<Event<Call, NormalModuleBatch>> {
        self.postflight();
        // SAFETY: all retained calls physically returned through invoke/store;
        // full input/output/source/thread/caller/stack postflight completed first.
        let batch = unsafe { self.attached.as_mut().unwrap().checkpoint_after_returns() }.unwrap();
        if let Some(native) = batch {
            assert_eq!(native.records().len(), self.calls.len());
            let calls = std::mem::replace(&mut self.calls, Vec::with_capacity(4));
            Some(Event::Batch {
                calls,
                native: Box::new(native),
            })
        } else {
            assert!(self.calls.is_empty());
            None
        }
    }
    pub(super) fn flush(&mut self, tx: &mpsc::SyncSender<Event<Call, NormalModuleBatch>>) {
        if let Some(event) = self.take_batch() {
            if let Err(error) = tx.send(event) {
                // Keep the returned event live; do not unwind its Call/Batch owners.
                let _retained = error.0;
                std::process::abort();
            }
        }
    }
    pub(super) fn identity(&self) -> Identity {
        self.identity
    }
}
impl Runtime for Worker {
    type Command = input::Command;
    type Call = Call;
    type Batch = NormalModuleBatch;
    fn pending(&self) -> usize {
        self.calls.len()
    }
    fn call(&mut self, command: input::Command) {
        let input::Command::Record(record) = command else {
            unreachable!()
        };
        assert!(matches!(self.calls.len(), 0 | 2));
        self.call_one(Arc::clone(&record), 0);
        self.call_one(record, 1);
    }
    fn flush(&mut self, tx: &mpsc::SyncSender<Event<Call, NormalModuleBatch>>) {
        Worker::flush(self, tx)
    }
    fn totals(&self) -> NormalTotals {
        self.attached.as_ref().unwrap().totals().unwrap()
    }
    fn finish(mut self) -> NormalTotals {
        self.postflight();
        assert!(
            unsafe { self.attached.as_mut().unwrap().checkpoint_after_returns() }
                .unwrap()
                .is_none()
        );
        let totals = self.attached.as_ref().unwrap().totals().unwrap();
        assert_eq!(self.attached.take().unwrap().detach().unwrap(), totals);
        self.postflight();
        self.fail_stop.0 = false;
        totals
    }
}
pub(super) fn run(
    entries: [u64; 2],
    client: NormalModuleClient,
    custody: Arc<Custody>,
    ready: Arc<OnceLock<Identity>>,
    rx: mpsc::Receiver<input::Command>,
    tx: mpsc::SyncSender<Event<Call, NormalModuleBatch>>,
    cpu: usize,
) {
    let worker = Worker::attach(entries, client, custody, cpu);
    let identity = worker.identity();
    ready.set(identity).unwrap();
    tx.send(Event::Ready { tid: identity.tid }).unwrap();
    shared::worker::drive(worker, rx, tx);
}
