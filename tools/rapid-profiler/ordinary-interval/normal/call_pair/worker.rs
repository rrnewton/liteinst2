//! Actual parent CALL/store and postflight; the admitted original E8 owns the child call.
use super::*;
use rapid_profiler::frontend_native::{NormalCallPairClient, NormalCallPairThread};
use shared::worker::{Event, Runtime};
pub(super) type Call = pair_worker::Call;

pub(super) fn complete(totals: NormalCallPairTotals, roots: u64) -> NormalTotals {
    assert!(roots <= input::RECORDS as u64);
    assert_eq!((totals.roots, totals.child_acks), (roots, roots));
    let calls = roots.checked_mul(2).unwrap();
    let p = totals.pairs;
    assert_eq!(
        (p.entered, p.ret_observed, p.confirmed),
        (calls, calls, calls)
    );
    assert_eq!(p.completed.checked_add(p.unsampled), Some(calls));
    p
}
fn returned(call: &Call) {
    assert_eq!(call.function, 0);
    call.check_expected(1, packed(&call.record));
}
fn flush_root(pending: usize) -> bool {
    assert_eq!(pending, 1);
    true
}
struct Worker {
    // This field aborts before any attached/returned/code owner is dropped.
    fail_stop: csv::FailStop,
    attached: Option<NormalCallPairThread>,
    calls: Vec<Call>,
    batch: Option<Box<NormalCallPairBatch>>,
    target: csv::Csv,
    custody: Arc<pair_worker::Custody>,
    identity: pair_worker::Identity,
    roots: u64,
    previous: NormalCallPairTotals,
}
impl Worker {
    fn postflight(&self) {
        self.custody.worker(self.identity);
        for call in &self.calls {
            returned(call);
        }
    }
    fn attach(
        entry: u64,
        client: NormalCallPairClient,
        custody: Arc<pair_worker::Custody>,
        cpu: usize,
    ) -> Self {
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
        // SAFETY: the sole worker owns its continuous ordinary stack, no signals,
        // reentry/nonlocal exits or writers, exact installed parent/child and caller.
        // The CallPair240 save and full actual callback stack must remain writable;
        // map bounds/this functional adapter are not an independent native proof.
        let attached = unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap();
        let previous = attached.totals().unwrap();
        assert_eq!(complete(previous, 0), NormalTotals::default());
        let worker = Self {
            fail_stop: csv::FailStop(true),
            attached: Some(attached),
            calls: Vec::with_capacity(1),
            batch: None,
            target: unsafe { std::mem::transmute::<usize, csv::Csv>(entry as usize) },
            custody,
            identity,
            roots: 0,
            previous,
        };
        fail_stop.0 = false;
        worker
    }
}
impl Runtime for Worker {
    type Command = input::Command;
    type Call = Call;
    type Batch = NormalCallPairBatch;
    fn pending(&self) -> usize {
        self.calls.len()
    }
    fn flush_after_command(&self) -> bool {
        flush_root(self.calls.len())
    }
    fn call(&mut self, command: input::Command) {
        let input::Command::Record(record) = command else {
            unreachable!()
        };
        assert!(self.calls.is_empty() && self.batch.is_none());
        assert!(self.roots < input::RECORDS as u64);
        self.postflight();
        record.check();
        // SAFETY: one real unchanged invoke CALL/store of the authenticated parent.
        // The child is reached only by its admitted original E8, never by this adapter.
        let call = unsafe { Call::invoke(record, 0, self.target) };
        self.calls.push(call); // Retain the real return before any result assertion.
        self.roots += 1;
        self.postflight();
    }
    fn flush(&mut self, tx: &mpsc::SyncSender<Event<Call, NormalCallPairBatch>>) {
        assert!(self.batch.is_none());
        self.postflight();
        // SAFETY: parent physically returned through invoke/store; complete immutable
        // file/code/input/guard/caller/stack/thread postflight above precedes root ack.
        self.batch = unsafe { self.attached.as_mut().unwrap().checkpoint_after_returns() }
            .unwrap()
            .map(Box::new);
        if let Some(batch) = self.batch.as_ref() {
            assert_eq!(self.calls.len(), 1);
            assert_eq!(batch.records().len(), 2);
            assert_eq!(batch.before(), self.previous);
            complete(batch.after(), self.roots);
            self.previous = batch.after();
            let calls = std::mem::replace(&mut self.calls, Vec::with_capacity(1));
            let event = Event::Batch {
                calls,
                native: self.batch.take().unwrap(),
            };
            if let Err(error) = tx.send(event) {
                let _retained = error.0;
                std::process::abort();
            }
        } else {
            assert!(self.calls.is_empty());
            assert_eq!(
                self.attached.as_ref().unwrap().totals().unwrap(),
                self.previous
            );
            complete(self.previous, self.roots);
        }
    }
    fn totals(&self) -> NormalTotals {
        complete(
            self.attached.as_ref().unwrap().totals().unwrap(),
            self.roots,
        )
    }
    fn finish(mut self) -> NormalTotals {
        self.postflight();
        assert!(self.calls.is_empty() && self.batch.is_none());
        self.batch = unsafe { self.attached.as_mut().unwrap().checkpoint_after_returns() }
            .unwrap()
            .map(Box::new);
        assert!(self.batch.is_none());
        let nested = self.attached.as_ref().unwrap().totals().unwrap();
        assert_eq!(nested, self.previous);
        let totals = complete(nested, self.roots);
        assert_eq!(self.attached.take().unwrap().detach().unwrap(), nested);
        self.postflight();
        self.fail_stop.0 = false;
        totals
    }
}
pub(super) fn run(
    entry: u64,
    client: NormalCallPairClient,
    custody: Arc<pair_worker::Custody>,
    ready: Arc<OnceLock<pair_worker::Identity>>,
    rx: mpsc::Receiver<input::Command>,
    tx: mpsc::SyncSender<Event<Call, NormalCallPairBatch>>,
    cpu: usize,
) {
    let worker = Worker::attach(entry, client, custody, cpu);
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
    #[test]
    fn complete_roots_require_both_rows_child_acks_and_all_pair_totals() {
        for roots in [0_u64, 1, 2048] {
            for sampled in [0, roots, roots * 2] {
                let t = NormalCallPairTotals {
                    roots,
                    child_acks: roots,
                    pairs: NormalTotals {
                        entered: roots * 2,
                        ret_observed: roots * 2,
                        confirmed: roots * 2,
                        completed: sampled,
                        unsampled: roots * 2 - sampled,
                    },
                };
                assert_eq!(complete(t, roots), t.pairs);
                for field in 0..7 {
                    let mut bad = t;
                    match field {
                        0 => bad.roots += 1,
                        1 => bad.child_acks += 1,
                        2 => bad.pairs.entered += 1,
                        3 => bad.pairs.ret_observed += 1,
                        4 => bad.pairs.confirmed += 1,
                        5 => bad.pairs.completed += 1,
                        6 => bad.pairs.unsampled += 1,
                        _ => unreachable!(),
                    }
                    refuse(|| {
                        complete(bad, roots);
                    });
                }
            }
        }
        assert!(flush_root(1));
        for n in [0, 2, 3, 4] {
            refuse(|| {
                flush_root(n);
            });
        }
    }
    #[test]
    fn packed_guarded_parent_value_keeps_one_real_call_owner_shape() {
        for bytes in [b"".as_slice(), b"a,b", b"\"a,b\",c", &[b','; 64]] {
            let record = Arc::new(input::Record::new(1, bytes).unwrap());
            let value = ((record.length as u64) << 32) | record.fields;
            let call = Call::fabricated(Arc::clone(&record), 0, value);
            returned(&call);
            assert!(Arc::ptr_eq(&record, &call.record));
            for delta in [1, 1_u64 << 32] {
                let bad = Call::fabricated(Arc::clone(&record), 0, value ^ delta);
                refuse(|| returned(&bad));
            }
            let bad = Call::fabricated(Arc::clone(&record), 1, value);
            refuse(|| returned(&bad));
            for before in [false, true] {
                let mut bad = Call::fabricated(Arc::clone(&record), 0, value);
                bad.corrupt_guard_for_test(before);
                refuse(|| returned(&bad));
            }
        }
    }
}
