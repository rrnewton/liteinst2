//! Opt-in queue retries; no native, durability, stop-acknowledgement or join authority.
use super::*;

const QUANTUM: Duration = Duration::from_micros(250);

/// Immutable Clock snapshot. Keep the inclusive arm and exclusive shutdown
/// boundaries separate even when their timestamps coincide.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Budget {
    start: Instant,
    arm: Option<(Instant, Instant)>,
    shutdown: Instant,
    arm_started: Option<Instant>,
}
impl Budget {
    pub(super) fn new(
        start: Instant,
        due: Option<Instant>,
        lateness: Duration,
        shutdown: Instant,
        arm_started: Option<Instant>,
    ) -> Result<Self, Error> {
        let arm = match due {
            Some(due) => Some((due, due.checked_add(lateness).ok_or(Error::Policy)?)),
            None => None,
        };
        Ok(Self {
            start,
            arm,
            shutdown,
            arm_started,
        })
    }
    fn failure(self, now: Instant, accepted: bool) -> Option<DeadlineFailure> {
        let (due, limit, inclusive) = if now >= self.shutdown {
            (self.shutdown, self.shutdown, true)
        } else if let Some((due, limit)) = self.arm {
            if now <= limit {
                return None;
            }
            (due, limit, false)
        } else {
            return None;
        };
        Some(DeadlineFailure::at(
            if accepted {
                DeadlinePhase::SinkExportAccepted
            } else {
                DeadlinePhase::SinkExportPending
            },
            self.start,
            Some(due),
            Some(limit),
            now,
            self.arm_started,
            inclusive,
        ))
    }
    fn remaining(self, now: Instant) -> Duration {
        self.arm
            .map_or(self.shutdown, |(_, limit)| limit.min(self.shutdown))
            .saturating_duration_since(now)
    }
}

pub(super) enum Outcome<T> {
    Accepted(Option<DeadlineFailure>),
    Retained {
        packet: T,
        error: Error,
        deadline: Option<DeadlineFailure>,
    },
}
fn retained<T>(packet: T, error: Error, deadline: Option<DeadlineFailure>) -> Outcome<T> {
    Outcome::Retained {
        packet,
        error,
        deadline,
    }
}

/// The local window admits retries; it is not an OS-operation latency promise.
/// A successful send always transfers ownership, even when its post-check fails.
fn transfer<T>(
    tx: &mpsc::SyncSender<T>,
    mut packet: T,
    budget: Option<Budget>,
    mut now: impl FnMut() -> Instant,
    mut wait: impl FnMut(Duration),
) -> Outcome<T> {
    let Some(budget) = budget else {
        return retained(packet, Error::Sequence, None);
    };
    let origin = now();
    let Some(retry_until) = origin.checked_add(POLL) else {
        return retained(packet, Error::Policy, None);
    };
    let mut observed = origin;
    let mut first = true;
    loop {
        if let Some(failure) = budget.failure(observed, false) {
            return retained(packet, Error::Deadline, Some(failure));
        }
        if !first && observed >= retry_until {
            return retained(packet, Error::Full, None);
        }
        packet = match send(tx, packet) {
            Ok(()) => return Outcome::Accepted(budget.failure(now(), true)),
            Err((Error::Full, value)) => value,
            Err((error, value)) => return retained(value, error, None),
        };
        observed = now();
        // Hard expiry wins when local-window expiry occurs at the same time.
        if let Some(failure) = budget.failure(observed, false) {
            return retained(packet, Error::Deadline, Some(failure));
        }
        let left = retry_until
            .saturating_duration_since(observed)
            .min(budget.remaining(observed));
        if left.is_zero() {
            return retained(packet, Error::Full, None);
        }
        wait(QUANTUM.min(left));
        observed = now();
        first = false;
    }
}

#[derive(Default)]
pub(super) struct Context {
    pub(super) budget: Option<Budget>,
}
impl Context {
    /// Common accounting for both typed drivers. The default path never calls
    /// this method, so its original send/error behavior remains literal.
    pub(super) fn emit<T>(
        &mut self,
        tx: &mpsc::SyncSender<T>,
        packet: T,
        pending: &mut Option<T>,
        exported: &mut u64,
        deadline_failure: &mut Option<DeadlineFailure>,
    ) -> Result<(), Error> {
        if pending.is_some() {
            return Err(Error::Sequence);
        }
        #[cfg(test)]
        let outcome = CLOCK.with(|slot| {
            let mut clock = slot.borrow_mut();
            if let Some(clock) = clock.as_mut() {
                transfer(tx, packet, self.budget, &mut clock.now, &mut clock.wait)
            } else {
                transfer(tx, packet, self.budget, Instant::now, std::thread::sleep)
            }
        });
        #[cfg(not(test))]
        let outcome = transfer(tx, packet, self.budget, Instant::now, std::thread::sleep);
        let (error, failure) = match outcome {
            Outcome::Accepted(failure) => {
                *exported += 1;
                match failure {
                    None => return Ok(()),
                    Some(failure) => (Error::Deadline, Some(failure)),
                }
            }
            Outcome::Retained {
                packet,
                error,
                deadline,
            } => {
                *pending = Some(packet);
                (error, deadline)
            }
        };
        if let Some(failure) = failure {
            deadline_failure.get_or_insert(failure);
        }
        Err(error)
    }
}

/// Controls alter only time observations/waits around the actual channel and
/// driver methods. This seam does not exist in production builds.
#[cfg(test)]
pub(super) struct TestClock {
    now: Box<dyn FnMut() -> Instant>,
    wait: Box<dyn FnMut(Duration)>,
}
#[cfg(test)]
impl TestClock {
    pub(super) fn new(
        now: impl FnMut() -> Instant + 'static,
        wait: impl FnMut(Duration) + 'static,
    ) -> Self {
        Self {
            now: Box::new(now),
            wait: Box::new(wait),
        }
    }
}

#[cfg(test)]
thread_local! {
    static CLOCK: std::cell::RefCell<Option<TestClock>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn with_clock<R>(clock: TestClock, body: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CLOCK.with(|slot| {
                slot.replace(None);
            });
        }
    }
    CLOCK.with(|slot| {
        assert!(slot.borrow().is_none(), "nested sink test clock");
        slot.replace(Some(clock));
    });
    let _reset = Reset;
    body()
}
#[cfg(test)]
mod tests;
