//! Closed public access to the existing finite Clock; no driver or call authority.
use super::{Clock, Decision, StopReason, arm_due};
use crate::frontend_native::backoff::{Error, Policy};
use std::time::{Duration, Instant};

/// One control boundary. A request arriving during an arm is observed at the
/// next poll, after the caller acknowledges that arm and its history transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleDecision {
    Arm { due: Instant },
    Stop,
    Wait,
}

/// Fixed K10/K1000, 10ms/2ms scheduling policy shared with the existing drivers.
///
/// This owns only clock/accounting state. It does not publish, drain, invoke,
/// stop, detach or join anything. It accepts observations from Instant::now;
/// callers must supply them in actual execution order. In particular, an Arm
/// acknowledgement belongs AFTER successful stage/publication and the complete
/// associated history transfer, never before the operation or after a failed
/// operation. Neither that acknowledgement nor completion proves native return.
///
/// A missed deadline or protocol refusal is sticky. No retry, catch-up arm or
/// replacement start is supplied. Existing mandatory/optional drivers and their
/// packet types are unchanged; a normal-caller consumer retains its own typed
/// records, pending owners, unsafe returned checkpoint and actual worker join.
pub struct Schedule {
    clock: Clock,
    arms: u32,
    pending: Option<Instant>,
    failure: Option<Error>,
    completed: bool,
}
impl Schedule {
    pub fn new(start: Instant, policy: Policy) -> Result<Self, Error> {
        Ok(Self {
            clock: Clock::new(start, policy)?,
            arms: 0,
            pending: None,
            failure: None,
            completed: false,
        })
    }
    /// Actual successful arm+history operations reported to this scheduler,
    /// including an operation whose post-completion time check then failed.
    pub fn armed(&self) -> u32 {
        self.arms
    }
    /// Issued grant without a successful-operation acknowledgement. The caller
    /// retains any partial publication/history failure; Some does not prove that
    /// no metadata action occurred. A completed-late operation clears this value.
    pub fn pending_arm(&self) -> Option<Instant> {
        self.pending
    }
    /// True only after poll actually returned Stop. Not a worker-stop observation.
    pub fn is_stopping(&self) -> bool {
        self.clock.stopping.is_some()
    }
    pub fn stop_reason(&self) -> Option<StopReason> {
        self.clock.stop_reason
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        Err(*self.failure.get_or_insert(error))
    }
    fn open(&mut self) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.completed {
            return self.fail(Error::Sequence);
        }
        Ok(())
    }
    /// Poll the unchanged original schedule. Calling again with an unacknowledged
    /// Arm is a protocol error, not a second arm or a silent wait.
    pub fn poll(
        &mut self,
        observed: Instant,
        stop_requested: bool,
    ) -> Result<ScheduleDecision, Error> {
        self.open()?;
        if self.pending.is_some() {
            return self.fail(Error::Sequence);
        }
        match self.clock.poll(observed, stop_requested, self.arms) {
            Ok(Decision::Arm(due)) => {
                self.pending = Some(due);
                Ok(ScheduleDecision::Arm { due })
            }
            Ok(Decision::Stop) => Ok(ScheduleDecision::Stop),
            Ok(Decision::Wait) => Ok(ScheduleDecision::Wait),
            Err(error) => self.fail(error),
        }
    }
    /// Acknowledge one actual successful arm AND its complete history operation.
    /// Uses the same due+2ms predicate as the existing driver's post-arm check;
    /// equality is accepted. The actual operation count advances before the
    /// time check, so an accepted-late operation cannot disappear from diagnostics.
    pub fn arm_completed(&mut self, observed: Instant) -> Result<(), Error> {
        self.open()?;
        let Some(due) = self.pending else {
            return self.fail(Error::Sequence);
        };
        if self.clock.stopping.is_some() || self.arms >= self.clock.policy.epoch_limit() {
            return self.fail(Error::Sequence);
        }
        let Some(arms) = self.arms.checked_add(1) else {
            return self.fail(Error::Sequence);
        };
        // The caller already completed the real arm and history operation. Keep
        // that fact even when its post-observation refuses; never permit a retry.
        self.arms = arms;
        self.pending = None;
        match arm_due(observed, due, self.clock.policy.lateness()) {
            Ok(true) => Ok(()),
            // An observation before the granted due violates execution order.
            Ok(false) => self.fail(Error::Sequence),
            Err(error) => self.fail(error),
        }
    }
    /// Maximum duration of the next external wait, capped by the existing 1ms
    /// poll, next original arm/end and immutable shutdown deadline. No clock is
    /// read here; this observation must follow the caller's preceding work.
    pub fn wait_bound(&mut self, observed: Instant) -> Result<Duration, Error> {
        self.open()?;
        if self.pending.is_some() {
            return self.fail(Error::Sequence);
        }
        if let Err(error) = self.clock.check_deadline(observed) {
            return self.fail(error);
        }
        Ok(self.clock.wait_bound(observed, self.arms))
    }
    /// Once-only final clock check AFTER Stop and all caller-owned shutdown work.
    /// The caller separately proves removal/history, final returned checkpoint,
    /// population/export, empty detach and actual joins; this method proves none
    /// of them. Equality at either original or earlier stop deadline is late.
    pub fn check_completion(&mut self, observed: Instant) -> Result<StopReason, Error> {
        self.open()?;
        if self.pending.is_some() || self.clock.stopping.is_none() {
            return self.fail(Error::Sequence);
        }
        if let Err(error) = self.clock.check_deadline(observed) {
            return self.fail(error);
        }
        let Some(reason) = self.clock.stop_reason else {
            return self.fail(Error::Sequence);
        };
        self.completed = true;
        Ok(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }
    fn policy(k: usize, epochs: u32) -> Policy {
        Policy::ten_ms(k, epochs, 1_000_000).unwrap()
    }
    fn grant(schedule: &mut Schedule, due: Instant) {
        assert_eq!(schedule.poll(due, false), Ok(ScheduleDecision::Arm { due }));
    }

    #[test]
    fn pending_arm_refuses_another_poll_without_count_or_deadline_reset() {
        let start = start();
        let mut s = Schedule::new(start, policy(10, 2)).unwrap();
        grant(&mut s, start);
        assert_eq!(s.armed(), 0);
        assert_eq!(s.pending_arm(), Some(start));
        assert_eq!(s.poll(start, true), Err(Error::Sequence));
        assert_eq!(s.arm_completed(start), Err(Error::Sequence));
        assert_eq!(s.check_completion(start), Err(Error::Sequence));
        assert_eq!(s.armed(), 0);
        assert!(!s.is_stopping());
        assert_eq!(s.stop_reason(), None);

        let mut s = Schedule::new(start, policy(10, 2)).unwrap();
        grant(&mut s, start);
        assert_eq!(s.wait_bound(start), Err(Error::Sequence));
        assert_eq!(s.arm_completed(start), Err(Error::Sequence));
        assert_eq!(s.armed(), 0);
    }

    #[test]
    fn post_arm_history_observation_accepts_equality_but_refuses_one_nanosecond_late() {
        let start = start();
        for k in [10, 1000] {
            let p = policy(k, 2);
            let mut s = Schedule::new(start, p).unwrap();
            grant(&mut s, start);
            assert_eq!(s.arm_completed(start + p.lateness()), Ok(()));
            assert_eq!(s.armed(), 1);
            let due = start + p.period();
            grant(&mut s, due);
            assert_eq!(
                s.arm_completed(due + p.lateness() + Duration::from_nanos(1)),
                Err(Error::Deadline)
            );
            assert_eq!(s.armed(), 2);
            assert_eq!(s.pending_arm(), None);
            assert_eq!(s.poll(due, true), Err(Error::Deadline));
            assert_eq!(s.arm_completed(due), Err(Error::Deadline));
            assert_eq!(s.armed(), 2);
            assert!(!s.is_stopping());
        }
    }

    #[test]
    fn arm_acknowledgements_require_a_grant_and_cannot_precede_due() {
        let start = start();
        let mut s = Schedule::new(start, policy(10, 1)).unwrap();
        assert_eq!(s.arm_completed(start), Err(Error::Sequence));
        assert_eq!(s.poll(start, false), Err(Error::Sequence));
        let mut s = Schedule::new(start, policy(10, 1)).unwrap();
        grant(&mut s, start);
        assert_eq!(
            s.arm_completed(start - Duration::from_nanos(1)),
            Err(Error::Sequence)
        );
        assert_eq!(s.armed(), 1);
        assert_eq!(s.pending_arm(), None);
        let mut s = Schedule::new(start, policy(10, 1)).unwrap();
        grant(&mut s, start);
        s.arm_completed(start).unwrap();
        assert_eq!(s.arm_completed(start), Err(Error::Sequence));
        assert_eq!(s.armed(), 1);
    }

    #[test]
    fn missed_original_arm_and_incomplete_epoch_limit_refuse_without_catchup() {
        let start = start();
        let p = policy(10, 2);
        let mut s = Schedule::new(start, p).unwrap();
        grant(&mut s, start);
        s.arm_completed(start).unwrap();
        assert_eq!(
            s.poll(
                start + p.period() + p.lateness() + Duration::from_nanos(1),
                false
            ),
            Err(Error::Deadline)
        );
        assert_eq!(s.poll(start + p.period(), false), Err(Error::Deadline));
        assert_eq!(s.armed(), 1);
        let mut s = Schedule::new(start, p).unwrap();
        grant(&mut s, start);
        s.arm_completed(start).unwrap();
        assert_eq!(
            s.poll(start + p.period() * p.epoch_limit(), false),
            Err(Error::Deadline)
        );
        assert!(!s.is_stopping());
        assert_eq!(s.stop_reason(), None);
    }

    #[test]
    fn requested_stop_is_once_only_and_uses_exclusive_original_capped_shutdown() {
        let start = start();
        let p = policy(10, 2);
        let stopped = start + Duration::from_millis(1);
        for equality in [false, true] {
            let mut s = Schedule::new(start, p).unwrap();
            grant(&mut s, start);
            s.arm_completed(start).unwrap();
            assert_eq!(s.poll(stopped, true), Ok(ScheduleDecision::Stop));
            assert!(s.is_stopping());
            assert_eq!(s.stop_reason(), Some(StopReason::Requested));
            assert_eq!(s.poll(stopped, false), Ok(ScheduleDecision::Wait));
            let limit = stopped + p.shutdown();
            if equality {
                assert_eq!(s.check_completion(limit), Err(Error::Deadline));
                assert_eq!(s.check_completion(stopped), Err(Error::Deadline));
            } else {
                assert_eq!(
                    s.check_completion(limit - Duration::from_nanos(1)),
                    Ok(StopReason::Requested)
                );
                assert_eq!(
                    s.poll(limit - Duration::from_nanos(1), false),
                    Err(Error::Sequence)
                );
                assert_eq!(
                    s.check_completion(limit - Duration::from_nanos(1)),
                    Err(Error::Sequence)
                );
            }
            assert_eq!(s.armed(), 1);
        }
        // A late observed request gets no fresh end+2s beyond the original cap.
        let end = start + p.period() * p.epoch_limit();
        let mut s = Schedule::new(start, p).unwrap();
        assert_eq!(
            s.poll(end + Duration::from_millis(1), true),
            Ok(ScheduleDecision::Stop)
        );
        assert_eq!(s.check_completion(end + p.shutdown()), Err(Error::Deadline));
    }

    #[test]
    fn wait_caps_follow_original_due_end_and_stop_without_poll_extension() {
        let start = start();
        let p = policy(10, 1);
        let mut s = Schedule::new(start, p).unwrap();
        let before = start - Duration::from_nanos(1);
        assert_eq!(s.poll(before, false), Ok(ScheduleDecision::Wait));
        assert_eq!(s.wait_bound(before), Ok(Duration::from_nanos(1)));
        grant(&mut s, start);
        s.arm_completed(start).unwrap();
        assert_eq!(s.wait_bound(start), Ok(Duration::from_millis(1)));
        let end = start + p.period();
        assert_eq!(
            s.wait_bound(end - Duration::from_nanos(1)),
            Ok(Duration::from_nanos(1))
        );
        assert_eq!(s.poll(end, false), Ok(ScheduleDecision::Stop));
        let limit = end + p.shutdown();
        assert_eq!(
            s.wait_bound(limit - Duration::from_nanos(1)),
            Ok(Duration::from_nanos(1))
        );
        assert_eq!(s.wait_bound(limit), Err(Error::Deadline));
        assert_eq!(s.check_completion(end), Err(Error::Deadline));
    }

    #[test]
    fn both_fixed_policies_issue_520_arms_and_complete_only_after_original_end() {
        let start = start();
        for k in [10, 1000] {
            let p = policy(k, 520);
            let mut s = Schedule::new(start, p).unwrap();
            for n in 0..520 {
                let due = start + p.period() * n;
                assert_eq!(s.armed(), n);
                grant(&mut s, due);
                assert_eq!(s.armed(), n);
                s.arm_completed(due).unwrap();
                assert_eq!(s.armed(), n + 1);
            }
            let end = start + p.period() * p.epoch_limit();
            assert_eq!(
                s.poll(end - Duration::from_nanos(1), false),
                Ok(ScheduleDecision::Wait)
            );
            assert_eq!(s.poll(end, false), Ok(ScheduleDecision::Stop));
            assert_eq!(s.stop_reason(), Some(StopReason::EpochLimit));
            assert_eq!(
                s.check_completion(end + p.shutdown() - Duration::from_nanos(1)),
                Ok(StopReason::EpochLimit)
            );
            assert_eq!(s.armed(), 520);
        }
        let p = policy(10, 1);
        let mut s = Schedule::new(start, p).unwrap();
        assert_eq!(s.check_completion(start), Err(Error::Sequence));
        let mut s = Schedule::new(start, p).unwrap();
        grant(&mut s, start);
        s.arm_completed(start).unwrap();
        let end = start + p.period();
        assert_eq!(s.poll(end, false), Ok(ScheduleDecision::Stop));
        assert_eq!(s.check_completion(end + p.shutdown()), Err(Error::Deadline));
    }
}
