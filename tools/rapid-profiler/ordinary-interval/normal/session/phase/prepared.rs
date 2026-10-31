//! Separate fixed-j profile; no changes to the original absolute-delay gate.
use super::*;
use crate::normal::session::ArmObservation;
use std::sync::atomic::{AtomicU8, Ordering};

pub(in crate::normal) const COMMAND: &str = "normal-selected-accuracy-prepared-phase-session";
const WIRE: &str = "selected-accuracy-prepared-phase-session-v1";
const WAITING: u8 = 0;
const PREPARED: u8 = 1;
const INVOKING: u8 = 2;
const RETURNED: u8 = 3;
const CANCELLED: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::normal) struct Request {
    phase: super::Request,
    target: u64,
    end: u64,
}
impl Request {
    pub(in crate::normal) fn new(phase: super::Request, j: u64) -> Result<Self> {
        let period = ns(phase.policy.period())?;
        let end = period
            .checked_mul(u64::from(phase.policy.epoch_limit()))
            .ok_or("prepared original end overflow")?;
        let target = period
            .checked_add(phase.delay)
            .ok_or("prepared target overflow")?;
        if j != 1 || phase.policy.epoch_limit() <= 1 || target >= end {
            return Err("prepared requires fixed j=1 inside the original epoch population");
        }
        Ok(Self { phase, target, end })
    }
    pub(in crate::normal) fn phase(self) -> super::Request {
        self.phase
    }
    pub(in crate::normal) fn ready(self) -> String {
        self.phase.ready().replacen(super::WIRE, WIRE, 1)
    }
    pub(in crate::normal) fn header(self) -> String {
        format!(
            "PREPARED_PHASE,{},{},1,{}\n",
            self.phase.kind, self.phase.delay, self.target
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Gate {
    entered: u64,
    opened: u64,
}

/// One shared first-call disposition, never an epoch or a fabricated NORMAL row.
#[derive(Debug)]
pub(in crate::normal) struct Shared {
    request: Request,
    phase: Arc<super::Shared>,
    state: AtomicU8,
    prepared: OnceLock<Instant>,
    arm: OnceLock<ArmObservation>,
    entered: OnceLock<u64>,
    gate: OnceLock<Gate>,
}
impl Shared {
    pub(in crate::normal) fn new(request: Request, phase: Arc<super::Shared>) -> Arc<Self> {
        assert_eq!(phase.request(), request.phase);
        Arc::new(Self {
            request,
            phase,
            state: AtomicU8::new(WAITING),
            prepared: OnceLock::new(),
            arm: OnceLock::new(),
            entered: OnceLock::new(),
            gate: OnceLock::new(),
        })
    }
    pub(in crate::normal) fn request(&self) -> Request {
        self.request
    }
    pub(in crate::normal) fn prepared(&self, observed: Instant) -> Result<()> {
        if self.state.load(Ordering::Acquire) != WAITING || self.phase.origin.get().is_some() {
            return Err("prepared owner must precede Schedule origin exactly once");
        }
        self.prepared
            .set(observed)
            .map_err(|_| "prepared receipt already retained")?;
        self.transition(WAITING, PREPARED)
    }
    pub(in crate::normal) fn is_prepared(&self) -> bool {
        self.state.load(Ordering::Acquire) == PREPARED
    }
    pub(in crate::normal) fn hold_input(&self) -> bool {
        // Do not accept a second record while the first is deferred or invoking.
        // CSV has no external Stop; EOF is deliberately not polled here.
        self.state.load(Ordering::Acquire) != RETURNED
    }
    pub(in crate::normal) fn start(&self, origin: Instant, policy: Policy) -> Result<()> {
        if !self.is_prepared() || self.prepared.get().is_none_or(|ready| *ready > origin) {
            return Err("Schedule cannot start before actual prepared ownership");
        }
        self.phase.start(origin, policy)
    }
    pub(in crate::normal) fn barrier_line(&self) -> Result<String> {
        let origin = *self
            .phase
            .origin
            .get()
            .ok_or("prepared origin unavailable")?;
        let ready = *self.prepared.get().ok_or("prepared receipt unavailable")?;
        let before = origin
            .checked_duration_since(ready)
            .ok_or("prepared origin regression")?;
        Ok(format!("PREPARED,1,{FUNCTION},{}\n", ns(before)?))
    }
    pub(in crate::normal) fn target_arm(&self, a: ArmObservation) -> Result<String> {
        let policy = self.request.phase.policy;
        if self.phase.origin.get().is_none()
            || self.phase.first_arm.get().is_none()
            || a.number != 2
            || !a.accepted
            || a.generation == 0
            || a.due != policy.period()
            || a.started < a.due
            || a.completed < a.started
            || a.completed > a.due + policy.lateness()
        {
            return Err("prepared requires actual accepted ARM2 on its original due");
        }
        self.arm
            .set(a)
            .map_err(|_| "prepared target arm already retained")?;
        Ok(format!(
            "TARGET_ARM,2,{},{},{},{}\n",
            a.generation,
            ns(a.due)?,
            ns(a.started)?,
            ns(a.completed)?
        ))
    }
    /// One nonblocking observation, sharing the existing worker monotone clock.
    /// The receive loop always checks queued commands before calling this method.
    pub(in crate::normal) fn poll(&self, worker: &mut super::Worker) -> Result<bool> {
        self.poll_with(worker, super::now)
    }
    fn poll_with(
        &self,
        worker: &mut super::Worker,
        clock: impl FnOnce() -> Instant,
    ) -> Result<bool> {
        if !Arc::ptr_eq(&self.phase, &worker.shared) || !self.is_prepared() {
            return Err("prepared gate ownership mismatch");
        }
        if self.phase.origin.get().is_none() {
            return Ok(false);
        }
        // Acquire the immutable origin before taking a sample. Publishing it
        // concurrently cannot turn a pre-acquisition sample into a regression.
        let value = worker.observe(clock())?;
        let _ = self.entered.get_or_init(|| value);
        let Some(arm) = self.arm.get() else {
            return Ok(false);
        };
        if value < ns(arm.completed)? {
            // ARM2 may have been published after this poll captured its time.
            // Wait for another monotone sample; never call this a clock failure.
            return Ok(false);
        }
        Ok(value >= self.request.target && value < self.request.end)
    }
    /// Recheck after custody/guard work. The last actual pre-CALL observation
    /// must be before original end, not merely before end+shutdown. No release
    /// or pending timing is created on a miss; receive-loop Stop can cancel it.
    pub(in crate::normal) fn begin(&self, worker: &mut super::Worker) -> Result<bool> {
        self.begin_with(worker, super::now)
    }
    fn begin_with(
        &self,
        worker: &mut super::Worker,
        mut clock: impl FnMut() -> Instant,
    ) -> Result<bool> {
        if !Arc::ptr_eq(&self.phase, &worker.shared)
            || !self.is_prepared()
            || worker.next != 1
            || worker.pending.is_some()
            || worker.failed
        {
            return Err("prepared invocation ownership mismatch");
        }
        let Some(arm) = self.arm.get() else {
            return Ok(false);
        };
        let entered = worker.observe(clock())?;
        if entered < self.request.target
            || entered < ns(arm.completed)?
            || entered >= self.request.end
        {
            return Ok(false);
        }
        let before = worker.observe(clock())?;
        if before >= self.request.end {
            return Ok(false);
        }
        let first_poll = *self.entered.get().ok_or("prepared gate never polled")?;
        // This is the same actual already-due sample for enter/released; no
        // delayed spin, synthesized timestamp, or modification to old before().
        self.phase
            .release
            .set(super::Release {
                enter: entered,
                released: entered,
            })
            .map_err(|_| "prepared first release already retained")?;
        worker.pending = Some(before);
        self.gate
            .set(Gate {
                entered: first_poll,
                opened: entered,
            })
            .map_err(|_| "prepared gate already opened")?;
        self.transition(PREPARED, INVOKING)?;
        Ok(true)
    }
    #[cfg(test)]
    pub(in crate::normal) fn poll_at_for_test(
        &self,
        worker: &mut super::Worker,
        at: Instant,
    ) -> Result<bool> {
        self.poll_with(worker, || at)
    }
    #[cfg(test)]
    pub(in crate::normal) fn begin_at_for_test(
        &self,
        worker: &mut super::Worker,
        at: Instant,
    ) -> Result<bool> {
        self.begin_with(worker, || at)
    }
    pub(in crate::normal) fn returned(&self) -> Result<()> {
        self.transition(INVOKING, RETURNED)
    }
    pub(in crate::normal) fn cancel(&self) -> Result<()> {
        // Worker only: unused guard and original record are still owned here.
        // No cancelled state is possible once physical invocation has started.
        self.transition(PREPARED, CANCELLED)
    }
    fn transition(&self, before: u8, after: u8) -> Result<()> {
        self.state
            .compare_exchange(before, after, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| "prepared disposition transition refused")
    }
    pub(in crate::normal) fn cancelled(&self) -> bool {
        self.state.load(Ordering::Acquire) == CANCELLED
    }
    pub(in crate::normal) fn cancellation_line(&self) -> Result<String> {
        if !self.cancelled()
            || self.gate.get().is_some()
            || self.phase.release.get().is_some()
            || self.phase.rows.iter().any(|r| r.get().is_some())
        {
            return Err("cancelled owner has invocation evidence");
        }
        Ok(format!(
            "CANCELLED,1,{FUNCTION},never_invoked,{},1,0\n",
            self.request.target
        ))
    }
    pub(in crate::normal) fn gate_line(&self) -> Result<String> {
        if self.state.load(Ordering::Acquire) != RETURNED {
            return Err("prepared call did not return");
        }
        let gate = self.gate.get().ok_or("prepared gate unavailable")?;
        Ok(format!(
            "GATE,1,{FUNCTION},{},{}\n",
            gate.entered, gate.opened
        ))
    }
    pub(in crate::normal) fn complete(&self) -> Result<()> {
        self.gate_line()?;
        if self.arm.get().is_none() {
            return Err("prepared target arm unavailable");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
