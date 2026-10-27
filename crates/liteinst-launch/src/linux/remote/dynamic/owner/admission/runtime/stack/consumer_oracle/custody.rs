//! Closed outer observations. A later cleanup failure cannot replace the
//! original error or unwind, and no partially executed action is called done.
use super::OracleError;
use std::any::Any;

pub(super) type Unwind = Box<dyn Any + Send>;
pub(super) type Observed = Result<Result<(), OracleError>, Unwind>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(super) enum Step {
    Arguments,
    Artifact,
    Plan,
    RawLaunch,
    RawExecution,
    RawAborted,
    RawBeforeCleanup,
    RawCleanup,
    RawRetention,
    RawMask,
    AdmittedLaunch,
    AdmittedStart,
    AdmittedAllocation,
    AdmittedExecution,
    AdmittedAborted,
    AdmittedSeal,
    StackPrefix0Capture,
    StackPrefix1Capture,
    CallPrefixCapture,
    JournalBeforeCleanup,
    AdmittedCleanup,
    AdmittedRetention,
    StackPrefix0Retention,
    StackPrefix1Retention,
    CallPrefixRetention,
    JournalRetention,
    SinkRetirement,
    CallRetirementRetention,
    AdmittedMask,
    Comparison,
    FinalArtifact,
    ArtifactClose,
    Output,
}
const STEPS: usize = Step::Output as usize + 1;

impl Step {
    pub(super) const fn code(self) -> &'static str {
        match self {
            Self::Arguments => "arguments",
            Self::Artifact | Self::FinalArtifact | Self::ArtifactClose => "artifact",
            Self::Plan => "plan",
            Self::RawLaunch => "raw_launch",
            Self::RawExecution | Self::RawAborted => "raw_execution",
            Self::RawBeforeCleanup | Self::RawCleanup | Self::RawRetention | Self::RawMask => {
                "raw_cleanup"
            }
            Self::AdmittedLaunch | Self::AdmittedStart => "admitted_launch",
            Self::AdmittedAllocation => "allocation",
            Self::AdmittedExecution
            | Self::AdmittedAborted
            | Self::AdmittedSeal
            | Self::StackPrefix0Capture
            | Self::StackPrefix1Capture
            | Self::CallPrefixCapture
            | Self::JournalBeforeCleanup => "admitted_execution",
            Self::AdmittedCleanup
            | Self::AdmittedRetention
            | Self::StackPrefix0Retention
            | Self::StackPrefix1Retention
            | Self::CallPrefixRetention
            | Self::JournalRetention
            | Self::SinkRetirement
            | Self::CallRetirementRetention
            | Self::AdmittedMask => "admitted_cleanup",
            Self::Comparison => "comparison",
            Self::Output => "output",
        }
    }
}

pub(super) enum Outcome {
    Unattempted,
    Started,
    Returned(Result<(), OracleError>),
    Unwound(Option<Unwind>),
}
impl Outcome {
    pub(super) fn succeeded(&self) -> bool {
        matches!(self, Self::Returned(Ok(())))
    }
    pub(super) fn attempted(&self) -> bool {
        !matches!(self, Self::Unattempted)
    }
    pub(super) fn check(&self) -> Option<bool> {
        self.attempted().then(|| self.succeeded())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FirstFailure {
    Step(Step),
    Reused(Step),
}

/// Every slot has a statically named once-only caller. Even the refusal of an
/// accidental repeated caller is sticky and happens before its closure runs.
pub(super) struct Custody {
    outcomes: [Outcome; STEPS],
    first: Option<FirstFailure>,
    reuse: Option<Step>,
}
impl Custody {
    pub(super) fn empty() -> Self {
        Self {
            outcomes: std::array::from_fn(|_| Outcome::Unattempted),
            first: None,
            reuse: None,
        }
    }
    pub(super) fn outcome(&self, step: Step) -> &Outcome {
        &self.outcomes[step as usize]
    }
    pub(super) fn begin(&mut self, step: Step) -> bool {
        if self.outcome(step).attempted() {
            self.reuse.get_or_insert(step);
            self.first.get_or_insert(FirstFailure::Reused(step));
            return false;
        }
        self.outcomes[step as usize] = Outcome::Started;
        true
    }
    /// Called immediately after the matching catch returns. No allocator,
    /// formatter, callback or other fallible operation intervenes.
    pub(super) fn finish(&mut self, step: Step, observed: Observed) -> bool {
        let outcome = match observed {
            Ok(result) => Outcome::Returned(result),
            Err(payload) => Outcome::Unwound(Some(payload)),
        };
        let succeeded = outcome.succeeded();
        self.outcomes[step as usize] = outcome;
        if !succeeded {
            self.first.get_or_insert(FirstFailure::Step(step));
        }
        succeeded
    }
    pub(super) fn failed(&self) -> bool {
        self.first.is_some()
    }
    pub(super) fn first_outcome(&self) -> Option<&Outcome> {
        match self.first {
            Some(FirstFailure::Step(step)) => Some(self.outcome(step)),
            _ => None,
        }
    }
    pub(super) fn first_code(&self) -> Option<&'static str> {
        self.first.map(|first| match first {
            FirstFailure::Step(step) if matches!(self.outcome(step), Outcome::Unwound(_)) => {
                "caught_panic"
            }
            FirstFailure::Step(step) | FirstFailure::Reused(step) => step.code(),
        })
    }
    pub(super) fn take_primary_unwind(&mut self) -> Option<Unwind> {
        let Some(FirstFailure::Step(step)) = self.first else {
            return None;
        };
        match &mut self.outcomes[step as usize] {
            Outcome::Unwound(payload) => payload.take(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumer_oracle_custody_preserves_error_before_cleanup_unwind() {
        let mut c = Custody::empty();
        assert!(c.begin(Step::RawExecution));
        assert!(!c.finish(
            Step::RawExecution,
            Ok(Err(OracleError::Invalid("original body")))
        ));
        assert!(c.begin(Step::RawCleanup));
        assert!(!c.finish(Step::RawCleanup, Err(Box::new(17_u32))));
        assert_eq!(c.first_code(), Some("raw_execution"));
        assert!(c.take_primary_unwind().is_none());
        assert!(matches!(
            c.outcome(Step::RawExecution),
            Outcome::Returned(Err(OracleError::Invalid("original body")))
        ));
        let Outcome::Unwound(Some(value)) = c.outcome(Step::RawCleanup) else {
            panic!("secondary unwind lost")
        };
        assert_eq!(value.downcast_ref::<u32>(), Some(&17));
    }

    #[test]
    fn consumer_oracle_custody_retains_primary_payload_and_separate_epilogues() {
        let mut c = Custody::empty();
        let payload: Unwind = Box::new([0x35_u8; 9]);
        let address = (&*payload as *const dyn Any).cast::<()>();
        assert!(c.begin(Step::AdmittedExecution));
        assert!(!c.finish(Step::AdmittedExecution, Err(payload)));
        for step in [
            Step::AdmittedCleanup,
            Step::AdmittedRetention,
            Step::JournalRetention,
            Step::SinkRetirement,
            Step::AdmittedMask,
        ] {
            assert!(c.begin(step));
            assert!(c.finish(step, Ok(Ok(()))));
        }
        assert_eq!(c.first_code(), Some("caught_panic"));
        let original = c.take_primary_unwind().expect("original unwind");
        assert_eq!((&*original as *const dyn Any).cast::<()>(), address);
        assert_eq!(original.downcast_ref::<[u8; 9]>(), Some(&[0x35; 9]));
        assert!(c.take_primary_unwind().is_none());
        assert!(c.failed());
    }

    #[test]
    fn consumer_oracle_custody_refuses_reuse_and_never_completes_missing_work() {
        let mut c = Custody::empty();
        assert_eq!(c.outcome(Step::AdmittedExecution).check(), None);
        assert!(c.begin(Step::RawLaunch));
        assert_eq!(c.outcome(Step::RawLaunch).check(), Some(false));
        assert!(c.finish(Step::RawLaunch, Ok(Ok(()))));
        assert!(!c.begin(Step::RawLaunch));
        assert!(c.outcome(Step::RawLaunch).succeeded());
        assert!(c.failed());
        assert_eq!(c.first_code(), Some("raw_launch"));
    }
}
