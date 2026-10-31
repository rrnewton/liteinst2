//! Real shared receive/Stop loop with a pure owned-deferred runtime, no SDK/native call.
use super::*;
use std::cell::RefCell;
use std::rc::Rc;
#[derive(Clone, Copy, Debug)]
enum Command {
    Prepare,
    Stop,
}
impl Work for Command {
    fn kind(&self) -> u8 {
        match self {
            Self::Prepare => 1,
            Self::Stop => 3,
        }
    }
    fn flush_id(&self) -> Option<u64> {
        None
    }
    fn stop() -> Self {
        Self::Stop
    }
}
struct Deferred {
    log: Rc<RefCell<Vec<&'static str>>>,
    tx: mpsc::SyncSender<Command>,
    owned: bool,
    returned: bool,
    release: bool,
}
impl Runtime for Deferred {
    type Command = Command;
    type Call = ();
    type Batch = ();
    fn pending(&self) -> usize {
        usize::from(self.returned)
    }
    fn flush_after_command(&self) -> bool {
        false
    }
    fn deferred(&self) -> bool {
        self.owned
    }
    fn call(&mut self, _: Command) {
        assert!(!self.owned);
        self.owned = true;
        self.log.borrow_mut().push("prepared");
    }
    fn poll_deferred(&mut self) {
        assert!(self.owned);
        self.log.borrow_mut().push("poll");
        if self.release {
            self.owned = false;
            self.returned = true;
            self.log.borrow_mut().push("returned");
        }
        self.tx.try_send(Command::Stop).unwrap();
    }
    fn cancel_deferred(&mut self) {
        if self.owned {
            assert!(!self.returned);
            self.owned = false;
            self.log.borrow_mut().push("cancelled");
        }
    }
    fn flush(&mut self, _: &mpsc::SyncSender<Event<(), ()>>) {
        self.log.borrow_mut().push(if self.returned {
            "actual-return-flush"
        } else {
            "empty-checkpoint"
        });
        self.returned = false;
    }
    fn totals(&self) -> NormalTotals {
        NormalTotals::default()
    }
    fn finish(self) -> NormalTotals {
        assert!(!self.owned && !self.returned);
        self.log.borrow_mut().push("detach");
        self.totals()
    }
}
fn run(queued_stop: bool, release: bool) -> Vec<&'static str> {
    let log = Rc::new(RefCell::new(Vec::new()));
    let (tx, rx) = mpsc::sync_channel(4);
    let (out, replies) = mpsc::sync_channel(1);
    tx.send(Command::Prepare).unwrap();
    if queued_stop {
        tx.send(Command::Stop).unwrap();
    }
    drive(
        Deferred {
            log: Rc::clone(&log),
            tx,
            owned: false,
            returned: false,
            release,
        },
        rx,
        out,
    );
    assert!(matches!(replies.try_recv().unwrap(),Event::Finished(t) if t==NormalTotals::default()));
    assert!(replies.try_recv().is_err()); // no fabricated Batch/Flushed
    Rc::try_unwrap(log).unwrap().into_inner()
}
#[test]
fn prepared_queued_stop_wins_before_poll_and_only_idle_checkpoint_detaches() {
    assert_eq!(
        run(true, true),
        ["prepared", "cancelled", "empty-checkpoint", "detach"]
    );
}
#[test]
fn prepared_wait_does_not_block_internal_stop_or_invent_return() {
    assert_eq!(
        run(false, false),
        [
            "prepared",
            "poll",
            "cancelled",
            "empty-checkpoint",
            "detach"
        ]
    );
}
#[test]
fn prepared_stop_after_release_waits_for_actual_return_and_flush_before_detach() {
    assert_eq!(
        run(false, true),
        [
            "prepared",
            "poll",
            "returned",
            "actual-return-flush",
            "empty-checkpoint",
            "detach"
        ]
    );
}
