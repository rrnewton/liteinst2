//! Failure-only stack formatting. No source bytes, error strings or attempt dump.
use liteinst2::contracts::Refusal;
use rapid_profiler::frontend_native::SiteError;

const CAP: usize = 256;
const PREFIX: &[u8] = b"normal-leaf-set-session PREPARATION_FAILED stage=site class=";
const FALLBACK: &[u8] = b"normal-leaf-set-session PREPARATION_FAILED stage=site class=diagnostic_overflow reason=none\n";

struct Line {
    bytes: [u8; CAP],
    len: usize,
}
impl Line {
    fn new() -> Self {
        Self {
            bytes: [0; CAP],
            len: 0,
        }
    }
    fn append(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.len.checked_add(bytes.len())?;
        self.bytes.get_mut(self.len..end)?.copy_from_slice(bytes);
        self.len = end;
        Some(())
    }
    fn number(&mut self, mut value: u64) -> Option<()> {
        let mut digits = [0_u8; 20];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                return self.append(&digits[start..]);
            }
        }
    }
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn reason(reason: &Refusal) -> &'static [u8] {
    match reason {
        Refusal::InvalidRange => b"invalid_range",
        Refusal::InvalidPlan => b"invalid_plan",
        Refusal::StaleGeneration => b"stale_generation",
        Refusal::ExpectedBytesChanged => b"expected_bytes_changed",
        Refusal::DependencyNotHeld => b"dependency_not_held",
        Refusal::LeasePoisoned => b"lease_poisoned",
        Refusal::UnresolvedEntry => b"unresolved_entry",
        Refusal::NotInstructionHead => b"not_instruction_head",
        Refusal::NoPatchWindow => b"no_patch_window",
        Refusal::UnsupportedSemantics(_) => b"unsupported_semantics",
        Refusal::AllocationUnavailable => b"allocation_unavailable",
        Refusal::OwnershipConflict => b"ownership_conflict",
        Refusal::SignalContract => b"signal_contract",
        Refusal::Synchronization => b"synchronization",
        Refusal::Backend(_) => b"backend",
    }
}

fn planning_counts(
    line: &mut Line,
    counts: [u64; 3],
    accepted: bool,
    complete: bool,
) -> Option<()> {
    for (label, value) in [b" attempts=".as_slice(), b" runs=", b" refusals="]
        .into_iter()
        .zip(counts)
    {
        line.append(label)?;
        line.number(value)?;
    }
    line.append(b" accepted=")?;
    line.number(u64::from(accepted))?;
    line.append(b" complete=")?;
    line.number(u64::from(complete))
}

fn format(error: &SiteError) -> Option<Line> {
    let (class, why): (&[u8], &[u8]) = match error {
        SiteError::ClockUnsupported => (b"clock_unsupported", b"none"),
        SiteError::Gate(_) => (b"gate", b"none"),
        SiteError::Source(_) => (b"source", b"none"),
        SiteError::Planning(failure) => (b"planning", reason(&failure.reason)),
        SiteError::Core(failure) => (b"core", reason(failure)),
        SiteError::Correspondence => (b"correspondence", b"none"),
    };
    let mut line = Line::new();
    line.append(PREFIX)?;
    line.append(class)?;
    line.append(b" reason=")?;
    line.append(why)?;
    if let SiteError::Planning(failure) = error {
        planning_counts(
            &mut line,
            [
                u64::try_from(failure.attempts.len()).ok()?,
                u64::try_from(failure.search.runs.len()).ok()?,
                u64::try_from(failure.search.refusals.len()).ok()?,
            ],
            failure.search.accepted,
            failure.search.classification_complete,
        )?;
    }
    line.append(b"\n")?;
    Some(line)
}

fn selected_line(line: &Option<Line>) -> &[u8] {
    line.as_ref().map_or(FALLBACK, Line::as_bytes)
}

pub(super) fn abort(error: &SiteError) -> ! {
    let line = format(error);
    let bytes = selected_line(&line);
    // SAFETY: bytes borrows a live stack buffer or static literal for this call.
    // One bounded write attempt: no logging lock, heap growth, retry or teardown.
    // A short/failed write is ignored. Delivery and latency are not guaranteed.
    let _ = unsafe { libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len()) };
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use super::*;
    use liteinst2::quiescent::{PatchTactic, PlanningFailure, SiteAttempt};
    use liteinst2::search::{
        RefusalClass, RefusalEvidence, SearchDomain, SearchEvidence, SearchRun, SearchScope,
        SearchStop,
    };
    use rapid_profiler::frontend_native::{GateError, SetupRefusal};

    #[test]
    fn fixed_site_classes_keep_failure_framing() {
        for (error, class, why) in [
            (SiteError::ClockUnsupported, "clock_unsupported", "none"),
            (SiteError::Gate(GateError::Identity), "gate", "none"),
            (
                SiteError::Source(SetupRefusal::SourceBytes),
                "source",
                "none",
            ),
            (
                SiteError::Core(Refusal::NoPatchWindow),
                "core",
                "no_patch_window",
            ),
            (SiteError::Correspondence, "correspondence", "none"),
        ] {
            let line = format(&error).unwrap();
            assert_eq!(
                line.as_bytes(),
                format!("normal-leaf-set-session PREPARATION_FAILED stage=site class={class} reason={why}\n").as_bytes()
            );
            assert!(line.len <= CAP && line.as_bytes().is_ascii());
            assert_eq!(line.as_bytes().iter().filter(|&&b| b == b'\n').count(), 1);
        }
    }

    #[test]
    fn fixed_reasons_never_format_dynamic_error_strings() {
        for (error, label) in [
            (Refusal::InvalidRange, "invalid_range"),
            (Refusal::InvalidPlan, "invalid_plan"),
            (Refusal::StaleGeneration, "stale_generation"),
            (Refusal::ExpectedBytesChanged, "expected_bytes_changed"),
            (Refusal::DependencyNotHeld, "dependency_not_held"),
            (Refusal::LeasePoisoned, "lease_poisoned"),
            (Refusal::UnresolvedEntry, "unresolved_entry"),
            (Refusal::NotInstructionHead, "not_instruction_head"),
            (Refusal::NoPatchWindow, "no_patch_window"),
            (
                Refusal::UnsupportedSemantics("secret\r\n\0é".repeat(512)),
                "unsupported_semantics",
            ),
            (Refusal::AllocationUnavailable, "allocation_unavailable"),
            (Refusal::OwnershipConflict, "ownership_conflict"),
            (Refusal::SignalContract, "signal_contract"),
            (Refusal::Synchronization, "synchronization"),
            (Refusal::Backend("secret\r\n\0é".repeat(512)), "backend"),
        ] {
            let line = format(&SiteError::Core(error)).unwrap();
            assert_eq!(
                line.as_bytes(),
                format!("normal-leaf-set-session PREPARATION_FAILED stage=site class=core reason={label}\n").as_bytes()
            );
        }
    }

    #[test]
    fn planning_metadata_uses_only_retained_lengths_and_flags() {
        let error = SiteError::Planning(PlanningFailure {
            reason: Refusal::NoPatchWindow,
            attempts: vec![
                SiteAttempt {
                    tactic: PatchTactic::Relocation,
                    physical_pc: u64::MAX,
                    refusal: Some(Refusal::Backend("private attempt".into())),
                };
                3
            ],
            search: SearchEvidence {
                accepted: false,
                classification_complete: true,
                runs: vec![
                    SearchRun {
                        domain: SearchDomain::PhysicalSites,
                        scope: SearchScope {
                            physical_pc: Some(u64::MAX),
                            ..SearchScope::default()
                        },
                        limit: 65,
                        examined: 65,
                        finite_total: None,
                        stop: SearchStop::UnclassifiedBoundedStop,
                        candidates: None,
                    };
                    2
                ],
                refusals: vec![
                    RefusalEvidence {
                        reason: Refusal::Backend("private refusal".into()),
                        class: RefusalClass::Backend,
                        scope: SearchScope::default(),
                    };
                    4
                ],
            },
        });
        let line = format(&error).unwrap();
        assert_eq!(line.as_bytes(), b"normal-leaf-set-session PREPARATION_FAILED stage=site class=planning reason=no_patch_window attempts=3 runs=2 refusals=4 accepted=0 complete=1\n");
        // A second borrow preserves the original error and its retained inventory.
        assert_eq!(format(&error).unwrap().as_bytes(), line.as_bytes());
        let SiteError::Planning(failure) = &error else {
            panic!()
        };
        assert_eq!(failure.attempts[0].physical_pc, u64::MAX);
        assert_eq!(
            failure.attempts[0].refusal,
            Some(Refusal::Backend("private attempt".into()))
        );
        assert_eq!(
            failure.search.refusals[0].reason,
            Refusal::Backend("private refusal".into())
        );
    }

    #[test]
    fn maximum_counters_and_overflow_keep_one_bounded_failure_line() {
        // Synthetic maximum counters exercise the same writer without huge Vecs.
        let mut line = Line::new();
        line.append(PREFIX).unwrap();
        line.append(b"planning reason=allocation_unavailable")
            .unwrap();
        planning_counts(&mut line, [u64::MAX; 3], true, true).unwrap();
        line.append(b"\n").unwrap();
        assert_eq!(line.as_bytes(), b"normal-leaf-set-session PREPARATION_FAILED stage=site class=planning reason=allocation_unavailable attempts=18446744073709551615 runs=18446744073709551615 refusals=18446744073709551615 accepted=1 complete=1\n");
        assert_eq!(line.len, 207);
        let mut zero = Line::new();
        zero.number(0).unwrap();
        assert_eq!(zero.as_bytes(), b"0");
        let mut full = Line::new();
        full.append(&[b'x'; CAP]).unwrap();
        let original = full.bytes;
        assert!(full.append(b"y").is_none());
        assert_eq!(full.len, CAP);
        assert_eq!(full.bytes, original);
        assert_eq!(selected_line(&None), FALLBACK);
        assert!(FALLBACK.len() <= CAP && FALLBACK.is_ascii());
        assert_eq!(FALLBACK.iter().filter(|&&b| b == b'\n').count(), 1);
        let formatted = Some(line);
        assert_eq!(
            selected_line(&formatted),
            formatted.as_ref().unwrap().as_bytes()
        );
    }
}
