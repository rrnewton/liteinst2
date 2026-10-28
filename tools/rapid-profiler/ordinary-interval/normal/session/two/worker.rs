//! One of two actual attached callers; each checkpoint acknowledges only this worker.
use super::*;

pub(super) struct Call {
    pub id: u64,
    pub bound: usize,
    pub bytes: Vec<u8>,
    pub value: u64,
    guard: Vec<u8>,
}
pub(super) enum Event {
    Ready {
        tid: u64,
    },
    Batch {
        calls: Vec<Call>,
        native: Box<NormalBatch>,
    },
    Flushed {
        id: u64,
        totals: NormalTotals,
    },
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
use super::super::worker::scalar;
pub(super) fn run(
    entry: u64,
    client: rapid_profiler::frontend_native::NormalClient,
    spans: Arc<Vec<(u64, Vec<u8>)>>,
    rx: mpsc::Receiver<Command>,
    tx: mpsc::SyncSender<Event>,
    cpu: usize,
    registration: u64,
) {
    pin(Some(cpu));
    assert!(matches!(registration, 1 | 2));
    // SAFETY: this actual worker owns its stack/journal; the controller dispatches
    // no CALL until BOTH actual Ready events. The immutable Two profile, D1,
    // no signal/reentry/unwind and continuous source/input custody hold.
    let mut attached =
        unsafe { client.attach_two_callers(registration, stack(), IntervalJournal::allocate()) }
            .unwrap();
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
    tx.send(Event::Ready { tid }).unwrap();
    let mut calls = Vec::with_capacity(4);
    // SAFETY: authenticated complete function and exact unsafe loader ABI.
    let target: unsafe extern "C" fn(*const u8, usize) -> u64 =
        unsafe { std::mem::transmute(entry as usize) };
    loop {
        let command = match rx.try_recv() {
            Ok(command) => command,
            Err(TryRecvError::Empty) => {
                // A lone returned request need not wait for another command.
                if !calls.is_empty() {
                    flush(&mut attached, &mut calls, &spans, &tx);
                }
                rx.recv().expect("session controller remains alive")
            }
            Err(TryRecvError::Disconnected) => panic!("session controller disconnected"),
        };
        match command {
            Command::Call { id, bound, bytes } => {
                assert!(calls.len() < 4 && bound <= bytes.len() && bytes.len() <= protocol::INPUT);
                let mut guard = vec![0xa5; bytes.len() + 32];
                guard[16..16 + bytes.len()].copy_from_slice(&bytes);
                guard[16 + bytes.len()..].fill(0x5a);
                // SAFETY: immutable owned readable bytes, exact bound, this attached
                // worker and normal CALL/RET. The compiled call site uses its result
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
                if calls.len() == 4 {
                    flush(&mut attached, &mut calls, &spans, &tx);
                }
            }
            Command::Flush { id } => {
                flush(&mut attached, &mut calls, &spans, &tx);
                tx.send(Event::Flushed {
                    id,
                    totals: attached.totals().unwrap(),
                })
                .unwrap();
            }
            Command::Stop => {
                flush(&mut attached, &mut calls, &spans, &tx);
                // Explicit second idle checkpoint must transfer nothing.
                unsafe { immutable(&spans) };
                assert!(
                    unsafe { attached.checkpoint_after_returns() }
                        .unwrap()
                        .is_none()
                );
                let totals = attached.totals().unwrap();
                assert_eq!(attached.detach().unwrap(), totals);
                tx.send(Event::Finished(totals)).unwrap();
                return;
            }
        }
    }
}
