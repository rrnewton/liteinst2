//! Private leaf-set adapter; shared receive/idle/Stop loop and actual invoke body.
use super::*;
use rapid_profiler::frontend_native::NormalLeafSetClient;
use shared::worker::{Event, Runtime};
pub(in crate::normal) struct Call {
    pub inner: pair_worker::Call,
    expectation: Expectation,
}
impl Call {
    pub(super) fn check(&self, n: usize) {
        self.inner.check_expected(
            n,
            self.expectation
                .value(&self.inner.record, self.inner.function, n),
        );
    }
    pub(super) fn value(&self) -> u64 {
        self.inner.value()
    }
}
struct Worker<const N: usize> {
    // Fail-stop precedes every attached/code/returned owner in drop order.
    fail_stop: csv::FailStop,
    attached: Option<counter::Thread>,
    counter: Option<Arc<counter::Custody>>,
    phase: Option<phase::Worker>,
    calls: Vec<Call>,
    targets: [csv::Csv; N],
    expectations: Expectations<N>,
    custody: Arc<pair_worker::Custody>,
    identity: pair_worker::Identity,
}
fn complete_record(pending: usize, n: usize) -> bool {
    assert!((1..=4).contains(&n));
    assert_eq!(pending, n);
    true
}
impl<const N: usize> Worker<N> {
    fn postflight(&self) {
        self.custody.worker(self.identity);
        for call in &self.calls {
            call.check(N);
        }
    }
    fn attach(
        entries: [u64; N],
        expectations: Expectations<N>,
        client: NormalLeafSetClient,
        custody: Arc<pair_worker::Custody>,
        cpu: usize,
        counter: Option<Arc<counter::Custody>>,
        phase: Option<Arc<phase::Shared>>,
    ) -> Self {
        assert!((1..=4).contains(&N));
        let mut fail_stop = csv::FailStop(true);
        pin(Some(cpu));
        let readable = stack();
        let identity = pair_worker::Identity {
            pid: std::process::id(),
            tid: unsafe { libc::syscall(libc::SYS_gettid) } as u64,
            cpu,
            stack: csv::stack_bounds(),
            caller: csv::mapping(csv::invoke as *const () as usize as u64, "r-xp"),
        };
        custody.worker(identity);
        // SAFETY: sole actual caller, retained immutable complete leaf set, no signals,
        // reentry/nonlocal exits or stack substitution; main is independent controller.
        let attached = unsafe { counter::Thread::attach(&client, readable, counter.as_deref()) };
        assert_eq!(attached.totals(), NormalTotals::default());
        let worker = Self {
            fail_stop: csv::FailStop(true),
            attached: Some(attached),
            counter,
            phase: phase.map(phase::Worker::new),
            calls: Vec::with_capacity(4),
            targets: entries
                .map(|entry| unsafe { std::mem::transmute::<usize, csv::Csv>(entry as usize) }),
            expectations,
            custody,
            identity,
        };
        fail_stop.0 = false;
        worker
    }
}
impl<const N: usize> Runtime for Worker<N> {
    type Command = input::Command;
    type Call = Call;
    type Batch = counter::Batch;
    fn pending(&self) -> usize {
        self.calls.len()
    }
    fn flush_after_command(&self) -> bool {
        complete_record(self.calls.len(), N)
    }
    fn call(&mut self, command: input::Command) {
        let input::Command::Record(record) = command else {
            unreachable!()
        };
        assert!(self.calls.is_empty());
        // Independently authenticate the complete frozen row before the first
        // actual invocation; no value is learned from target output.
        let witnesses = self.expectations.record(&record).unwrap();
        for (function, expectation) in witnesses.into_iter().enumerate() {
            self.postflight();
            record.check();
            // SAFETY: independently selected actual scalar target, live original input
            // and guarded output; this calls the shared, unchanged csv::invoke body.
            if let Some(phase) = &mut self.phase {
                let (inner, observed) = unsafe {
                    pair_worker::Call::invoke_phase(
                        Arc::clone(&record),
                        function,
                        self.targets[function],
                        phase,
                    )
                }
                .unwrap();
                self.calls.push(Call { inner, expectation });
                // Actual return owner precedes every fallible post-clock check.
                phase.returned(observed).unwrap();
            } else {
                let inner = unsafe {
                    pair_worker::Call::invoke(Arc::clone(&record), function, self.targets[function])
                };
                self.calls.push(Call { inner, expectation });
            }
            // Returned owners are already retained before fallible postflight.
            self.postflight();
        }
        assert!(complete_record(self.calls.len(), N));
    }
    fn flush(&mut self, tx: &mpsc::SyncSender<Event<Call, counter::Batch>>) {
        self.postflight();
        // SAFETY: every actual call returned through CALL/store, with complete
        // input/output/source/caller/thread/stack custody checked above.
        let batch = unsafe { self.attached.as_mut().unwrap().checkpoint() };
        if let Some(native) = batch {
            assert_eq!(native.normal().records().len(), N);
            assert_eq!(native.normal().records().len(), self.calls.len());
            let calls = std::mem::replace(&mut self.calls, Vec::with_capacity(4));
            if let Err(error) = tx.send(Event::Batch {
                calls,
                native: Box::new(native),
            }) {
                let _retained = error.0;
                std::process::abort();
            }
        } else {
            assert!(self.calls.is_empty());
        }
    }
    fn totals(&self) -> NormalTotals {
        self.attached.as_ref().unwrap().totals()
    }
    fn finish(mut self) -> NormalTotals {
        self.postflight();
        assert!(unsafe { self.attached.as_mut().unwrap().checkpoint() }.is_none());
        let totals = self.attached.as_ref().unwrap().totals();
        assert_eq!(
            self.attached
                .take()
                .unwrap()
                .detach(self.counter.as_deref()),
            totals
        );
        self.postflight();
        self.fail_stop.0 = false;
        totals
    }
}
type WorkerEvidence = (
    Arc<OnceLock<pair_worker::Identity>>,
    Option<Arc<counter::Custody>>,
    Option<Arc<phase::Shared>>,
);
pub(super) fn run<const N: usize>(
    targets: ([u64; N], Expectations<N>),
    client: NormalLeafSetClient,
    custody: Arc<pair_worker::Custody>,
    evidence: WorkerEvidence,
    rx: mpsc::Receiver<input::Command>,
    tx: mpsc::SyncSender<Event<Call, counter::Batch>>,
    cpu: usize,
) {
    let (ready, counter, phase) = evidence;
    let worker = Worker::attach(targets.0, targets.1, client, custody, cpu, counter, phase);
    let id = worker.identity;
    ready.set(id).unwrap();
    tx.send(Event::Ready { tid: id.tid }).unwrap();
    shared::worker::drive(worker, rx, tx);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn refuse(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    struct DefaultFlush(usize);
    impl Runtime for DefaultFlush {
        type Command = input::Command;
        type Call = ();
        type Batch = ();
        fn pending(&self) -> usize {
            self.0
        }
        fn call(&mut self, _: input::Command) {
            panic!("not a native worker")
        }
        fn flush(&mut self, _: &mpsc::SyncSender<Event<(), ()>>) {
            panic!("not a native worker")
        }
        fn totals(&self) -> NormalTotals {
            NormalTotals::default()
        }
        fn finish(self) -> NormalTotals {
            NormalTotals::default()
        }
    }
    #[test]
    fn command_flush_boundary_is_exact_for_each_cardinality_and_old_default() {
        for n in 1..=4 {
            assert!(complete_record(n, n));
            for pending in 0..=8 {
                if pending != n {
                    refuse(|| {
                        complete_record(pending, n);
                    });
                }
            }
        }
        for pending in 0..=8 {
            assert_eq!(DefaultFlush(pending).flush_after_command(), pending == 4);
        }
        refuse(|| {
            complete_record(6, 3);
        });
    }
    #[test]
    fn guarded_return_checks_all_operations_and_owner_retention() {
        let record = Arc::new(input::Record::new(1, b"\"1 2\", 3").unwrap());
        for (f, (operation, value)) in [
            (Operation::Csv, 2),
            (Operation::Length, 8),
            (Operation::Digits, 3),
            (Operation::Spaces, 2),
        ]
        .into_iter()
        .enumerate()
        {
            let call = Call {
                inner: pair_worker::Call::fabricated(Arc::clone(&record), f, value),
                expectation: Expectation::Builtin(operation),
            };
            call.check(4);
            assert!(Arc::ptr_eq(&call.inner.record, &record));
            let wrong = Call {
                inner: pair_worker::Call::fabricated(Arc::clone(&record), f, value + 1),
                expectation: Expectation::Builtin(operation),
            };
            refuse(|| wrong.check(4));
            for before in [false, true] {
                let mut bad = Call {
                    inner: pair_worker::Call::fabricated(Arc::clone(&record), f, value),
                    expectation: Expectation::Builtin(operation),
                };
                bad.inner.corrupt_guard_for_test(before);
                refuse(|| bad.check(4));
            }
        }
        let bad = Call {
            inner: pair_worker::Call::fabricated(Arc::clone(&record), 4, 2),
            expectation: Expectation::Builtin(Operation::Csv),
        };
        refuse(|| bad.check(4));
        record.check();
        assert_eq!(record.bytes(), b"\"1 2\", 3");
    }
}

#[cfg(test)]
pub(in crate::normal) mod selected_controls {
    use super::*;
    fn refuse(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    pub(in crate::normal) fn selected_guarded_returns_reject_each_value_and_guard_drift() {
        let functions = [FunctionId(1), FunctionId(2), FunctionId(3), FunctionId(4)];
        let table = selected::Table::parse(
            b"LI2SELECTED 1 4 1\nfunctions 1 2 3 4\nrecord 1 413d62 0 66 18446744073709551614 18446744073709551615\nEND\n",
            &functions,
        ).unwrap();
        let source = Expectations::frozen(Arc::new(table), functions);
        let record = Arc::new(input::Record::new(1, b"A=b").unwrap());
        for (function, value) in [0, 66, u64::MAX - 1, u64::MAX].into_iter().enumerate() {
            let call = Call {
                inner: pair_worker::Call::fabricated(Arc::clone(&record), function, value),
                expectation: source
                    .record(&record)
                    .unwrap()
                    .into_iter()
                    .nth(function)
                    .unwrap(),
            };
            call.check(4);
            assert!(Arc::ptr_eq(&call.inner.record, &record));
            let wrong = Call {
                inner: pair_worker::Call::fabricated(Arc::clone(&record), function, value ^ 1),
                expectation: source
                    .record(&record)
                    .unwrap()
                    .into_iter()
                    .nth(function)
                    .unwrap(),
            };
            refuse(|| wrong.check(4));
            for before in [false, true] {
                let mut bad = Call {
                    inner: pair_worker::Call::fabricated(Arc::clone(&record), function, value),
                    expectation: source
                        .record(&record)
                        .unwrap()
                        .into_iter()
                        .nth(function)
                        .unwrap(),
                };
                bad.inner.corrupt_guard_for_test(before);
                refuse(|| bad.check(4));
            }
        }
        let shifted = Call {
            inner: pair_worker::Call::fabricated(Arc::clone(&record), 1, 0),
            expectation: source.record(&record).unwrap().into_iter().next().unwrap(),
        };
        refuse(|| shifted.check(4));
        record.check();
        assert_eq!(record.bytes(), b"A=b");
    }
}
