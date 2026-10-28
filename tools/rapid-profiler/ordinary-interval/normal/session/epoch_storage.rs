//! Fixed-slot consumer custody; this is not an SDK storage or return proof.
use rapid_profiler::frontend_native::{BridgeError, EpochStorageReclaimError, IntervalEpoch};

pub(super) trait Identity {
    fn generation(&self) -> u64;
}
impl Identity for IntervalEpoch {
    fn generation(&self) -> u64 {
        IntervalEpoch::generation(self).get()
    }
}

// The same consuming restore path handles stage and reclaim errors. The caller
// keeps this owner cell in its fail-stop scope; no map_err drops the returned T.
pub(super) fn transfer<T, U, E>(
    owner: &mut Option<T>,
    operation: impl FnOnce(T) -> Result<U, (E, T)>,
) -> Result<U, E> {
    match operation(owner.take().expect("retained transfer owner")) {
        Ok(value) => Ok(value),
        Err((error, value)) => {
            *owner = Some(value);
            Err(error)
        }
    }
}

enum Output {
    Pending,
    Emitted,
    Failed(String),
}
struct Copied {
    generation: u64,
    report_index: usize,
    line: String,
    output: Output,
}
pub(super) struct Slot<T> {
    epoch: Option<T>,
    generation: u64,
    copied: Option<Copied>,
}
impl<T: Identity> Slot<T> {
    pub(super) fn new(epoch: T) -> Self {
        let generation = epoch.generation();
        assert_ne!(generation, 0);
        Self {
            epoch: Some(epoch),
            generation,
            copied: None,
        }
    }
    pub(super) fn epoch(&self) -> &T {
        let epoch = self.epoch.as_ref().expect("live retained epoch");
        assert_eq!(epoch.generation(), self.generation);
        epoch
    }
    pub(super) fn report_index(&self) -> Option<usize> {
        self.copied.as_ref().map(|copied| {
            assert_eq!(copied.generation, self.epoch().generation());
            copied.report_index
        })
    }
    // The Engine has already checked and retained the complete record copy.
    // Retain its exact index and one output obligation before dropping Report.
    pub(super) fn copied(&mut self, generation: u64, report_index: usize, line: String) {
        assert_eq!(generation, self.epoch().generation());
        assert!(self.copied.is_none(), "one copied Report per generation");
        self.copied = Some(Copied {
            generation,
            report_index,
            line,
            output: Output::Pending,
        });
    }
    pub(super) fn emit(
        &mut self,
        emit: impl FnOnce(String) -> Result<(), String>,
    ) -> Result<(), String> {
        assert!(self.report_index().is_some());
        let copied = self.copied.as_mut().unwrap();
        match &copied.output {
            Output::Emitted => return Ok(()),
            Output::Failed(error) => return Err(error.clone()),
            Output::Pending => (),
        }
        // Keep the original obligation even if Io::emit consumes/refuses its
        // argument. A terminal output error is sticky, never a retry policy.
        match emit(copied.line.clone()) {
            Ok(()) => {
                copied.output = Output::Emitted;
                Ok(())
            }
            Err(error) => {
                copied.output = Output::Failed(error.clone());
                Err(error)
            }
        }
    }
    pub(super) fn reclaim<B>(
        &mut self,
        reclaim: impl FnOnce(T) -> Result<B, (EpochStorageReclaimError, T)>,
    ) -> Result<Option<B>, BridgeError> {
        assert!(self.report_index().is_some());
        assert!(matches!(
            self.copied.as_ref().unwrap().output,
            Output::Emitted
        ));
        match transfer(&mut self.epoch, reclaim) {
            Ok(bank) => Ok(Some(bank)),
            Err(EpochStorageReclaimError::SharedOwner) => Ok(None),
            Err(EpochStorageReclaimError::Bridge(error)) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    // Simulated identity-bearing tokens exercise the real consumer helper.
    // Actual Arc/receipt exclusivity belongs to the separate SDK controls.
    struct Token {
        generation: u64,
        identity: Box<u64>,
    }
    impl Identity for Token {
        fn generation(&self) -> u64 {
            self.generation
        }
    }
    fn token(generation: u64) -> Token {
        Token {
            generation,
            identity: Box::new(generation),
        }
    }

    #[test]
    fn shared_owner_repeats_keep_one_report_output_and_exact_token_until_success() {
        let mut slot = Slot::new(token(17));
        let identity = slot.epoch().identity.as_ref() as *const u64;
        let mut reports = Vec::new();
        let mut output = Vec::new();
        for _ in 0..3 {
            if slot.report_index().is_none() {
                reports.push((17, vec![3, 5, 8]));
                slot.copied(17, reports.len() - 1, "REPORT,17,3\n".into());
            }
            slot.emit(|line| {
                output.push(line);
                Ok(())
            })
            .unwrap();
            let bank: Option<()> = slot
                .reclaim(|token| Err((EpochStorageReclaimError::SharedOwner, token)))
                .unwrap();
            assert!(bank.is_none());
            assert_eq!(slot.epoch().identity.as_ref() as *const u64, identity);
            assert_eq!(slot.report_index(), Some(0));
            assert_eq!(reports, [(17, vec![3, 5, 8])]);
            assert_eq!(output, ["REPORT,17,3\n"]);
        }
        let bank = slot.reclaim(|token| Ok(token.identity)).unwrap().unwrap();
        assert_eq!(bank.as_ref() as *const u64, identity);
        assert!(slot.epoch.is_none());
        assert_eq!(reports, [(17, vec![3, 5, 8])]);
        assert_eq!(output, ["REPORT,17,3\n"]);
    }

    #[test]
    fn fresh_generation_requires_new_report_and_rejects_stale_or_duplicate_marks() {
        let mut slot = Slot::new(token(31));
        slot.copied(31, 0, "REPORT,31,0\n".into());
        slot.emit(|_| Ok(())).unwrap();
        let identity = slot.reclaim(|token| Ok(token.identity)).unwrap().unwrap();
        let mut fresh = Slot::new(Token {
            generation: 97,
            identity,
        });
        assert_eq!(fresh.report_index(), None);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                fresh.copied(31, 0, "REPORT,31,0\n".into());
            }))
            .is_err()
        );
        assert_eq!(fresh.report_index(), None);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _: Option<()> = fresh.reclaim(|_| panic!("no early reclaim")).unwrap();
            }))
            .is_err()
        );
        assert_eq!(fresh.epoch().generation, 97);
        fresh.copied(97, 1, "REPORT,97,1\n".into());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                fresh.copied(97, 2, "REPORT,97,1\n".into());
            }))
            .is_err()
        );
        assert_eq!(fresh.report_index(), Some(1));
        let mut lines = Vec::new();
        fresh
            .emit(|line| {
                lines.push(line);
                Ok(())
            })
            .unwrap();
        fresh.emit(|_| panic!("no duplicate output")).unwrap();
        assert_eq!(lines, ["REPORT,97,1\n"]);
    }

    #[test]
    fn output_refusal_keeps_obligation_and_token_without_retry_or_reclaim() {
        let mut slot = Slot::new(token(43));
        slot.copied(43, 4, "REPORT,43,2\n".into());
        assert_eq!(
            slot.emit(|line| {
                assert_eq!(line, "REPORT,43,2\n");
                Err("output capacity".into())
            }),
            Err("output capacity".into())
        );
        assert_eq!(
            slot.emit(|_| panic!("terminal failure cannot retry")),
            Err("output capacity".into())
        );
        assert_eq!(slot.copied.as_ref().unwrap().line, "REPORT,43,2\n");
        assert_eq!(slot.report_index(), Some(4));
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _: Option<()> = slot
                    .reclaim(|_| panic!("no reclaim after output failure"))
                    .unwrap();
            }))
            .is_err()
        );
        assert_eq!(slot.epoch().generation, 43);
    }

    #[test]
    fn consuming_error_restores_original_owner_before_propagation() {
        // The exact transfer function is used for stage and reclaim. The error
        // value is synthetic; SDK controls supply real typed failure causes.
        let mut owner = Some(token(59));
        let identity = owner.as_ref().unwrap().identity.as_ref() as *const u64;
        let result: Result<(), &str> = transfer(&mut owner, |token| Err(("refused", token)));
        assert_eq!(result, Err("refused"));
        assert_eq!(owner.as_ref().unwrap().generation, 59);
        assert_eq!(
            owner.as_ref().unwrap().identity.as_ref() as *const u64,
            identity
        );
        let result: Result<Box<u64>, &str> = transfer(&mut owner, |token| Ok(token.identity));
        assert_eq!(result.unwrap().as_ref() as *const u64, identity);
        assert!(owner.is_none());
    }
}
