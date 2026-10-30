//! One run, one producer and one consumer. A disconnect never proves drainage.
use super::{MAX_STOPS, Stop};
use std::cell::{Cell, UnsafeCell};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const IDLE: u64 = 0;
const PUBLISHED: u64 = 1;
const OBSERVED: u64 = 2;
const ACKNOWLEDGED: u64 = 3;
fn word(generation: u64, phase: u64) -> u64 {
    (generation << 2) | phase
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Disconnected,
    Timeout,
    Protocol,
}
struct Slot {
    phase: AtomicU64,
    worker_closed: AtomicBool,
    controller_closed: AtomicBool,
    stop: UnsafeCell<Option<Stop>>,
    reply: UnsafeCell<Option<(u64, u64)>>,
}
// Only the unique worker writes stop in Idle; only the unique controller takes
// it after acquiring Published. Only the controller writes reply in Observed;
// only the worker takes it after acquiring Acknowledged. The next publication
// follows that consumption. No payload reference escapes either endpoint.
// Peer Drop touches only atomic flags, never either cell or the phase. The Arc
// retains cells even if an endpoint/worker is detached or forgotten.
unsafe impl Sync for Slot {}

pub(super) struct Worker {
    slot: Arc<Slot>,
    next: u64,
    failure: Option<Error>,
    _not_sync: PhantomData<Cell<()>>,
}
pub(super) struct Controller {
    slot: Arc<Slot>,
    next: u64,
    failure: Option<Error>,
    _not_sync: PhantomData<Cell<()>>,
}
pub(super) struct Event<'a> {
    controller: &'a mut Controller,
    stop: Option<Stop>,
    _thread: PhantomData<Rc<()>>,
}
pub(super) fn channel() -> (Worker, Controller) {
    let slot = Arc::new(Slot {
        phase: AtomicU64::new(word(0, IDLE)),
        worker_closed: AtomicBool::new(false),
        controller_closed: AtomicBool::new(false),
        stop: UnsafeCell::new(None),
        reply: UnsafeCell::new(None),
    });
    (
        Worker {
            slot: slot.clone(),
            next: 1,
            failure: None,
            _not_sync: PhantomData,
        },
        Controller {
            slot,
            next: 1,
            failure: None,
            _not_sync: PhantomData,
        },
    )
}
impl Worker {
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        let error = *self.failure.get_or_insert(error);
        self.slot.worker_closed.store(true, Ordering::Release);
        Err(error)
    }
    fn publish(&mut self, stop: Stop) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.next > MAX_STOPS as u64
            || self.slot.phase.load(Ordering::Acquire) != word(self.next - 1, IDLE)
        {
            return self.fail(Error::Protocol);
        }
        if self.slot.controller_closed.load(Ordering::Acquire) {
            return self.fail(Error::Disconnected);
        }
        // SAFETY: exact Idle owns both cells; prior acknowledgement was acquired.
        unsafe {
            if (*self.slot.stop.get()).is_some() || (*self.slot.reply.get()).is_some() {
                return self.fail(Error::Protocol);
            }
            *self.slot.stop.get() = Some(stop);
        }
        // Publishes Stop AND the worker's preceding application/clock writes.
        self.slot
            .phase
            .store(word(self.next, PUBLISHED), Ordering::Release);
        Ok(())
    }
    fn poll_reply(&mut self) -> Result<Option<(u64, u64)>, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        // Read closure before phase: observing closure must also observe its
        // preceding queued reply. A stale phase must not discard that reply.
        let closed = self.slot.controller_closed.load(Ordering::Acquire);
        let phase = self.slot.phase.load(Ordering::Acquire);
        if phase == word(self.next, ACKNOWLEDGED) {
            // SAFETY: acquire follows the controller's final reads and reply
            // write; that controller cannot access cells again before Publish.
            let reply = unsafe { (*self.slot.reply.get()).take() };
            let Some(reply) = reply else {
                return self.fail(Error::Protocol);
            };
            self.slot
                .phase
                .store(word(self.next, IDLE), Ordering::Release);
            self.next += 1; // bounded by MAX_STOPS + 1; no generation wrap
            return Ok(Some(reply));
        }
        if phase != word(self.next, PUBLISHED) && phase != word(self.next, OBSERVED) {
            return self.fail(Error::Protocol);
        }
        // A queued acknowledgement wins over sender closure, as with mpsc.
        if closed {
            return self.fail(Error::Disconnected);
        }
        Ok(None)
    }
    fn wait_reply(&mut self, deadline: Instant) -> Result<(u64, u64), Error> {
        loop {
            if let Some(reply) = self.poll_reply()? {
                return Ok(reply);
            }
            if Instant::now() >= deadline {
                return self.fail(Error::Timeout);
            }
            std::hint::spin_loop();
        }
    }
    pub(super) fn exchange(&mut self, stop: Stop, wait: Duration) -> Result<(u64, u64), Error> {
        self.publish(stop)?;
        // One absolute deadline, starting after publication, never reset.
        let Some(deadline) = Instant::now().checked_add(wait) else {
            return self.fail(Error::Protocol);
        };
        self.wait_reply(deadline)
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.slot.worker_closed.store(true, Ordering::Release);
    }
}
impl Controller {
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        let error = *self.failure.get_or_insert(error);
        self.slot.controller_closed.store(true, Ordering::Release);
        Err(error)
    }
    fn poll_stop(&mut self) -> Result<Option<Stop>, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        // Acquiring closure first joins any final queued Stop before phase is
        // examined; queued data therefore retains precedence over closure.
        let closed = self.slot.worker_closed.load(Ordering::Acquire);
        let phase = self.slot.phase.load(Ordering::Acquire);
        if self.next <= MAX_STOPS as u64 && phase == word(self.next, PUBLISHED) {
            // Only this controller changes Published to Observed. This store
            // does not grant the worker payload ownership; only reply does.
            self.slot
                .phase
                .store(word(self.next, OBSERVED), Ordering::Relaxed);
            // SAFETY: acquired Publish, unique consumer, no escaping reference.
            return match unsafe { (*self.slot.stop.get()).take() } {
                Some(stop) => Ok(Some(stop)),
                None => self.fail(Error::Protocol),
            };
        }
        if phase != word(self.next - 1, IDLE) && phase != word(self.next - 1, ACKNOWLEDGED) {
            return self.fail(Error::Protocol);
        }
        // A queued Stop wins over worker closure. Completion still needs join.
        if closed {
            return self.fail(Error::Disconnected);
        }
        Ok(None)
    }
    pub(super) fn receive(&mut self, wait: Duration) -> Result<Event<'_>, Error> {
        let Some(deadline) = Instant::now().checked_add(wait) else {
            return self.fail(Error::Protocol);
        };
        loop {
            if let Some(stop) = self.poll_stop()? {
                return Ok(Event {
                    controller: self,
                    stop: Some(stop),
                    _thread: PhantomData,
                });
            }
            if Instant::now() >= deadline {
                return self.fail(Error::Timeout);
            }
            std::hint::spin_loop();
        }
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.slot.controller_closed.store(true, Ordering::Release);
    }
}
impl Event<'_> {
    pub(super) fn stop(&self) -> &Stop {
        self.stop.as_ref().expect("owned event")
    }
    pub(super) fn resume(mut self, site: u64, count: u64) -> Result<Stop, Error> {
        let c = &mut *self.controller;
        if let Some(error) = c.failure {
            return Err(error);
        }
        if c.next > MAX_STOPS as u64
            || c.slot.phase.load(Ordering::Acquire) != word(c.next, OBSERVED)
        {
            return c.fail(Error::Protocol);
        }
        if c.slot.worker_closed.load(Ordering::Acquire) {
            return c.fail(Error::Disconnected);
        }
        // SAFETY: this unique event owns reply until publishing Acknowledged.
        unsafe {
            *c.slot.reply.get() = Some((site, count));
        }
        c.slot
            .phase
            .store(word(c.next, ACKNOWLEDGED), Ordering::Release);
        c.next += 1;
        // Taking Stop disarms failure Drop only AFTER acknowledgement release.
        Ok(self.stop.take().expect("owned event"))
    }
}
impl Drop for Event<'_> {
    fn drop(&mut self) {
        if self.stop.is_some() {
            let _: Result<(), Error> = self.controller.fail(Error::Protocol);
        }
    }
}

#[cfg(test)]
mod tests;
