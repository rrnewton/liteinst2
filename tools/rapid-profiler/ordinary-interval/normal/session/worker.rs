//! One attached calling thread; requests make ordinary C ABI calls.
use super::*;

pub(in crate::normal) struct Call {
    pub id: u64,
    pub bound: usize,
    pub bytes: Vec<u8>,
    pub value: u64,
    guard: Vec<u8>,
}
pub(in crate::normal) enum Event<C = Call, B = NormalBatch> {
    Ready { tid: u64 },
    Batch { calls: Vec<C>, native: Box<B> },
    Flushed { id: u64, totals: NormalTotals },
    Finished(NormalTotals),
}
fn flush(
    attached: &mut rapid_profiler::frontend_native::NormalThread,
    calls: &mut Vec<Call>,
    spans: &[(u64, Vec<u8>)],
    tx: &mpsc::SyncSender<Event>,
) {
    // These checks precede the unsafe acknowledgement, including for idle flush.
    unsafe { immutable(spans) };
    for call in calls.iter() {
        assert_eq!(&call.guard[..16], &[0xa5; 16]);
        assert_eq!(&call.guard[16..16 + call.bytes.len()], call.bytes);
        assert_eq!(&call.guard[16 + call.bytes.len()..], &[0x5a; 16]);
        assert_eq!(call.value, scalar(&call.bytes, call.bound));
    }
    // SAFETY: all calls above physically returned to this worker; no active
    // subject, reentry, signals/nonlocal exits or code/input changes. The checks
    // do not replace continuous custody, and confer no unmapping authority.
    let batch = unsafe { attached.checkpoint_after_returns() }.unwrap();
    if let Some(native) = batch {
        assert_eq!(native.records().len(), calls.len());
        let calls = std::mem::replace(calls, Vec::with_capacity(4));
        tx.send(Event::Batch {
            calls,
            native: Box::new(native),
        })
        .unwrap();
    } else {
        assert!(calls.is_empty());
    }
}
pub(super) fn scalar(bytes: &[u8], bound: usize) -> u64 {
    bytes[..bound].iter().position(|&b| b == 0).unwrap_or(bound) as u64
}
pub(super) fn run(
    entry: u64,
    client: rapid_profiler::frontend_native::NormalClient,
    spans: Arc<Vec<(u64, Vec<u8>)>>,
    rx: mpsc::Receiver<Command>,
    tx: mpsc::SyncSender<Event>,
    cpu: usize,
) {
    pin(Some(cpu));
    // SAFETY: sole controlled caller, actual stack, immutable sealed installation;
    // no per-request API invocation or library CALL gate is introduced.
    let attached = unsafe { client.attach(1, stack(), IntervalJournal::allocate()) }.unwrap();
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
    tx.send(Event::Ready { tid }).unwrap();
    let calls = Vec::with_capacity(4);
    // SAFETY: authenticated complete function and exact unsafe loader ABI.
    let target: unsafe extern "C" fn(*const u8, usize) -> u64 =
        unsafe { std::mem::transmute(entry as usize) };
    drive(
        Single {
            attached: Some(attached),
            calls,
            spans,
            target,
        },
        rx,
        tx,
    );
}

pub(in crate::normal) trait Work: Sized {
    fn kind(&self) -> u8;
    fn flush_id(&self) -> Option<u64>;
    fn stop() -> Self;
    fn name(&self) -> &'static str {
        match self.kind() {
            1 => "call",
            2 => "flush",
            3 => "stop",
            _ => unreachable!(),
        }
    }
}
impl Work for Command {
    fn kind(&self) -> u8 {
        match self {
            Self::Call { .. } => 1,
            Self::Flush { .. } => 2,
            Self::Stop => 3,
        }
    }
    fn flush_id(&self) -> Option<u64> {
        if let Self::Flush { id } = self {
            Some(*id)
        } else {
            None
        }
    }
    fn stop() -> Self {
        Self::Stop
    }
}
pub(in crate::normal) trait Runtime {
    type Command: Work;
    type Call;
    type Batch;
    fn pending(&self) -> usize;
    fn flush_after_command(&self) -> bool {
        self.pending() == 4
    }
    fn deferred(&self) -> bool {
        false
    }
    fn poll_deferred(&mut self) {}
    fn cancel_deferred(&mut self) {}
    fn call(&mut self, command: Self::Command);
    fn flush(&mut self, tx: &mpsc::SyncSender<Event<Self::Call, Self::Batch>>);
    fn totals(&self) -> NormalTotals;
    fn finish(self) -> NormalTotals;
}
pub(in crate::normal) fn drive<R: Runtime>(
    mut runtime: R,
    rx: mpsc::Receiver<R::Command>,
    tx: mpsc::SyncSender<Event<R::Call, R::Batch>>,
) {
    loop {
        let command = match rx.try_recv() {
            Ok(command) => command,
            Err(TryRecvError::Empty) if runtime.deferred() => {
                runtime.poll_deferred();
                if runtime.pending() != 0 {
                    runtime.flush(&tx);
                }
                std::hint::spin_loop();
                continue;
            }
            Err(TryRecvError::Empty) => {
                // A lone returned request need not wait for another command.
                if runtime.pending() != 0 {
                    runtime.flush(&tx);
                }
                rx.recv().expect("session controller remains alive")
            }
            Err(TryRecvError::Disconnected) => panic!("session controller disconnected"),
        };
        match command.kind() {
            1 => {
                runtime.call(command);
                if runtime.flush_after_command() {
                    runtime.flush(&tx);
                }
            }
            2 => {
                let id = command.flush_id().expect("closed Flush variant");
                runtime.flush(&tx);
                tx.send(Event::Flushed {
                    id,
                    totals: runtime.totals(),
                })
                .unwrap();
            }
            3 => {
                runtime.cancel_deferred();
                runtime.flush(&tx);
                let totals = runtime.finish();
                tx.send(Event::Finished(totals)).unwrap();
                return;
            }
            _ => unreachable!("closed command variants"),
        }
    }
}
#[cfg(test)]
mod prepared_tests;

struct Single {
    attached: Option<rapid_profiler::frontend_native::NormalThread>,
    calls: Vec<Call>,
    spans: Arc<Vec<(u64, Vec<u8>)>>,
    target: unsafe extern "C" fn(*const u8, usize) -> u64,
}
impl Runtime for Single {
    type Command = Command;
    type Call = Call;
    type Batch = NormalBatch;
    fn pending(&self) -> usize {
        self.calls.len()
    }
    fn call(&mut self, command: Command) {
        let Command::Call { id, bound, bytes } = command else {
            unreachable!()
        };
        let calls = &mut self.calls;
        let target = self.target;
        assert!(calls.len() < 4 && bound <= bytes.len() && bytes.len() <= protocol::INPUT);
        let mut guard = vec![0xa5; bytes.len() + 32];
        guard[16..16 + bytes.len()].copy_from_slice(&bytes);
        guard[16 + bytes.len()..].fill(0x5a);
        // SAFETY: immutable owned readable bytes, exact bound, sole attached
        // thread and normal CALL/RET. The compiled call site uses its result
        // immediately below, so this is not a tail transfer to the subject.
        let value = unsafe { target(guard[16..].as_ptr(), bound) };
        assert_eq!(value, scalar(&bytes, bound));
        calls.push(Call {
            id,
            bound,
            bytes,
            value,
            guard,
        });
    }
    fn flush(&mut self, tx: &mpsc::SyncSender<Event>) {
        flush(
            self.attached.as_mut().unwrap(),
            &mut self.calls,
            &self.spans,
            tx,
        );
    }
    fn totals(&self) -> NormalTotals {
        self.attached.as_ref().unwrap().totals().unwrap()
    }
    fn finish(mut self) -> NormalTotals {
        // Explicit second idle checkpoint must transfer nothing.
        unsafe { immutable(&self.spans) };
        assert!(
            unsafe { self.attached.as_mut().unwrap().checkpoint_after_returns() }
                .unwrap()
                .is_none()
        );
        let totals = self.attached.as_ref().unwrap().totals().unwrap();
        assert_eq!(self.attached.take().unwrap().detach().unwrap(), totals);
        totals
    }
}

#[cfg(test)]
mod leaf_set_tests {
    use super::*;
    use crate::normal::module::session::input;
    use std::sync::Mutex;
    struct Model {
        pending: usize,
        trace: Arc<Mutex<Vec<(&'static str, usize)>>>,
    }
    impl Runtime for Model {
        type Command = input::Command;
        type Call = ();
        type Batch = ();
        fn pending(&self) -> usize {
            self.pending
        }
        fn flush_after_command(&self) -> bool {
            assert_eq!(self.pending, 3);
            true
        }
        fn call(&mut self, c: input::Command) {
            assert!(matches!(c, input::Command::Record(_)));
            assert_eq!(self.pending, 0);
            self.pending += 3;
            self.trace.lock().unwrap().push(("call", self.pending));
        }
        fn flush(&mut self, _: &mpsc::SyncSender<Event<(), ()>>) {
            assert!(self.pending == 0 || self.pending == 3);
            self.trace.lock().unwrap().push(("flush", self.pending));
            self.pending = 0;
        }
        fn totals(&self) -> NormalTotals {
            NormalTotals::default()
        }
        fn finish(self) -> NormalTotals {
            assert_eq!(self.pending, 0);
            self.trace.lock().unwrap().push(("finish", 0));
            NormalTotals::default()
        }
    }
    #[test]
    fn actual_drive_flushes_each_three_call_command_before_next() {
        // Fabricated work counts through actual shared dispatch, never a native receipt.
        let (tx, rx) = mpsc::sync_channel(3);
        let (events, replies) = mpsc::sync_channel(1);
        for id in 1..=2 {
            tx.send(input::Command::Record(Arc::new(
                input::Record::new(id, b"a").unwrap(),
            )))
            .unwrap();
        }
        tx.send(input::Command::Stop).unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        drive(
            Model {
                pending: 0,
                trace: Arc::clone(&trace),
            },
            rx,
            events,
        );
        assert!(matches!(replies.try_recv().unwrap(), Event::Finished(_)));
        assert_eq!(
            *trace.lock().unwrap(),
            [
                ("call", 3),
                ("flush", 3),
                ("call", 3),
                ("flush", 3),
                ("flush", 0),
                ("finish", 0)
            ]
        );
    }
}
