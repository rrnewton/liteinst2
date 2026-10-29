//! Additive T2/D1 preparation and attachment; one shared normal TLS runtime.
use super::*;

fn profile_matches(site: &site::Site, limits: Limits) -> bool {
    site.is_normal_two_callers() && limits.threads == 2 && limits.depth == 1
}
pub(super) fn binding_matches(binding: &Binding) -> bool {
    profile_matches(&binding.site, binding.limits)
        && matches!(binding.entry_mode, EntryMode::Concurrent)
}

/// Explicit two-caller preparation. Old T1 constructors never produce this type.
/// E/A/history remain finite Session limits; the caller must budget all retained
/// owners and all admitted records, including DroppedAfterBudget completions.
/// E4, M2, A4096 is one finite 4096-call cohort policy, not a new global maximum.
pub struct PreparedTwoCallerNormalController(PreparedIntervalController);
impl PreparedTwoCallerNormalController {
    pub fn new(
        site: site::ordinary::InstalledTwoCallerNormalSite,
        install: u64,
        function: FunctionId,
        limits: Limits,
    ) -> Result<Self, BridgeError> {
        Self::prepare(site, install, function, limits, HistoryMode::Legacy)
    }
    /// Bounded resident history with absolute prefixes. The consumer retains
    /// every HistoryBatch and joins both local streams; draining proves no RET.
    pub fn new_streaming_history(
        site: site::ordinary::InstalledTwoCallerNormalSite,
        install: u64,
        function: FunctionId,
        limits: Limits,
    ) -> Result<Self, BridgeError> {
        Self::prepare(site, install, function, limits, HistoryMode::Absolute)
    }
    fn prepare(
        site: site::ordinary::InstalledTwoCallerNormalSite,
        install: u64,
        function: FunctionId,
        limits: Limits,
        mode: HistoryMode,
    ) -> Result<Self, BridgeError> {
        if !profile_matches(&site.site, limits) {
            return Err(error(Cause::Identity));
        }
        if !timing::supported() {
            return Err(error(Cause::ClockProfile));
        }
        let constructor = match mode {
            HistoryMode::Legacy => PreparedIntervalController::new,
            HistoryMode::Absolute => PreparedIntervalController::new_streaming_history,
        };
        constructor(
            site::InstalledIntervalSite { site: site.site },
            install,
            function,
            limits,
        )
        .map(Self)
    }
    pub fn stage(&mut self, config: Config) -> Result<IntervalEpoch, BridgeError> {
        self.0.stage(config)
    }
    /// Prepare exactly Limits.epochs fixed-Config banks once, before activation,
    /// staging or registration, in pristine streaming-history mode. Ordinary
    /// allocating stage then refuses; dropping banks or legacy retirement loses
    /// capacity. Initialization touches logical slot state only, not all byte
    /// storage capacity, and guarantees neither residency nor a 2 ms deadline.
    /// Both-Ready-before-work and every original T2 lifetime obligation remain.
    pub fn prepare_epoch_storage(
        &mut self,
        config: Config,
    ) -> Result<Vec<IntervalEpochStorage>, BridgeError> {
        super::super::epoch_storage::prepare(&mut self.0, config)
    }
    /// Only the existing concurrent-entry mode is available in T2.
    ///
    /// # Safety
    /// PreparedIntervalController::activate_concurrent's pristine process/fork,
    /// no-reentry/no-signal/no-callback-dependent-lock contracts all hold.
    /// The sealed TwoCallerNormalLeafContract and global publication quiescence
    /// hold continuously. Both actual worker attachment Ready handshakes precede
    /// either worker's physical work. The caller supplies this barrier; activation
    /// does not observe it. Each worker is D1, owns its input/stack/journal and can
    /// acknowledge only its own normally returned calls. Code owners are process-
    /// lived. Contention has no fairness or bounded-latency guarantee.
    pub unsafe fn activate_concurrent(
        self,
    ) -> Result<(IntervalController, NormalClient), BridgeError> {
        PreparedNormalController::available()?;
        // SAFETY: full distinct two-caller and original concurrent contracts above.
        let (controller, client) = unsafe { self.0.activate_concurrent()? };
        if !binding_matches(&client.binding) {
            return Err(error(Cause::Identity));
        }
        Ok((
            controller,
            NormalClient {
                binding: client.binding,
            },
        ))
    }
}

impl NormalClient {
    /// Attach one of the two fixed lifetime identities; old attach remains T1-only.
    ///
    /// # Safety
    /// The complete TwoCallerNormalLeafContract, successful publication and both-
    /// Ready-before-work barrier apply. This actual worker exclusively owns its
    /// readable stack, immutable valid inputs and journal. No signal/reentry,
    /// cancellation, unwind, tail/nonlocal exit, fork, writer or unload occurs.
    /// Each batch is finite <=32 calls and this thread performs all source/image
    /// and guarded-input checks before its unsafe returned checkpoint. RDTSCP and
    /// sufficient writable callback/XSAVE stack are available on this thread.
    /// Initial attachment is globally quiescent; after release, checkpoint and
    /// empty detach require this worker's quiescence, never acknowledgement or
    /// return of the other worker. Both workers are stopped/joined before final
    /// application shutdown; metadata does not authorize executable reclamation.
    /// No per-call SDK gate or source/input scan is supplied by this method.
    pub unsafe fn attach_two_callers(
        &self,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<NormalThread, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        if !binding_matches(&self.binding)
            || registration == 0
            || journal.page.0.iter().any(|&word| word != 0)
        {
            return Err(error(Cause::Attachment));
        }
        if !timing::supported() {
            return Err(error(Cause::ClockProfile));
        }
        self.attach_ready(registration, stack, journal)
    }
}

#[cfg(test)]
mod native;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::PayloadOutcome;
    use crate::generation::{Disposition, Terminal};

    fn limits() -> Limits {
        Limits {
            epochs: 4,
            threads: 2,
            depth: 1,
            records_per_epoch: 4096,
            actions: 8,
        }
    }
    fn binding(two: bool, mode: EntryMode) -> Arc<Binding> {
        let limits = limits();
        Arc::new(Binding {
            session: Session::new(
                71,
                &[FunctionSpec {
                    function: FunctionId(11),
                    group: 0,
                }],
                &[GroupSpec { mandatory: true }],
                limits,
            )
            .unwrap(),
            site: site::synthetic_normal_site(two).site,
            key: Arc::new(()),
            pid: std::process::id(),
            install: 71,
            function: FunctionId(11),
            limits,
            entry_mode: mode,
            native_entry_pause: std::sync::OnceLock::new(),
        })
    }
    fn state(binding: &Arc<Binding>, registration: u64, model: ThreadModel) -> NormalState {
        let mut state = NormalState::new(
            Arc::clone(binding),
            registration,
            ReadableStack {
                start: 0x7000,
                end: 0xa000,
            },
            IntervalJournal::allocate(),
            model,
        );
        state.journal.header(state.tid, 0);
        state
    }
    fn observed(state: &mut NormalState) {
        let ticks = state.next * 100;
        state
            .enter(0x1000, 0x8008, 0x9000, RawTimestamp { ticks, aux: 7 })
            .unwrap();
        state
            .observe(
                0x1012,
                0x8008,
                0x9000,
                RawTimestamp {
                    ticks: ticks + 10,
                    aux: 7,
                },
            )
            .unwrap();
    }
    fn transfer(state: &mut NormalState) -> NormalBatch {
        let (rows, page) = outputs().unwrap();
        state.transfer(rows, page).unwrap().unwrap()
    }

    #[test]
    fn two_caller_profile_requires_exact_site_limits_and_concurrent_mode() {
        let one = site::synthetic_normal_site(false).site;
        let two = site::synthetic_normal_site(true).site;
        let legacy = site::synthetic_site().site;
        assert!(!one.is_normal_two_callers() && one.is_normal());
        assert!(two.is_normal_two_callers() && !two.is_normal());
        assert!(!legacy.is_normal() && !legacy.is_normal_two_callers());
        assert!(profile_matches(&two, limits()));
        for wrong in [legacy, one] {
            assert!(!profile_matches(&wrong, limits()));
            assert!(matches!(
                PreparedTwoCallerNormalController::new(
                    site::ordinary::InstalledTwoCallerNormalSite { site: wrong },
                    71,
                    FunctionId(11),
                    limits()
                ),
                Err(BridgeError {
                    cause: Cause::Identity
                })
            ));
        }
        for wrong in [
            Limits {
                threads: 1,
                ..limits()
            },
            Limits {
                threads: 3,
                ..limits()
            },
            Limits {
                depth: 2,
                ..limits()
            },
        ] {
            assert!(!profile_matches(&two, wrong));
            assert!(matches!(
                PreparedTwoCallerNormalController::new_streaming_history(
                    site::ordinary::InstalledTwoCallerNormalSite {
                        site: Arc::clone(&two)
                    },
                    71,
                    FunctionId(11),
                    wrong
                ),
                Err(BridgeError {
                    cause: Cause::Identity
                })
            ));
        }
        // Neither a T2 tag nor larger Limits can upgrade an old T1 constructor.
        for source in [site::synthetic_normal_site(false).site, Arc::clone(&two)] {
            assert!(matches!(
                PreparedNormalController::new(
                    site::ordinary::InstalledNormalSite { site: source },
                    71,
                    FunctionId(11),
                    limits()
                ),
                Err(BridgeError {
                    cause: Cause::Identity
                })
            ));
        }
        let nonblocking = binding(true, EntryMode::NonBlocking);
        assert!(!binding_matches(&nonblocking));
        assert!(!normal_binding_matches(&nonblocking));
        let concurrent = binding(true, EntryMode::Concurrent);
        assert!(binding_matches(&concurrent) && normal_binding_matches(&concurrent));
        let relabelled = binding(false, EntryMode::Concurrent);
        assert!(!binding_matches(&relabelled) && !normal_binding_matches(&relabelled));
    }

    #[test]
    fn two_registration_limit_and_identity_reuse_refuse_without_recycling() {
        let binding = binding(true, EntryMode::Concurrent);
        let a = binding.session.register_thread(1).unwrap();
        assert!(matches!(
            binding.session.register_thread(1),
            Err(SetupError::DuplicateThread)
        ));
        let b = binding.session.register_thread(2).unwrap();
        assert_eq!((a.identity(), b.identity()), (1, 2));
        assert_eq!(
            (
                a.depth(),
                b.depth(),
                a.completed_sequence(),
                b.completed_sequence()
            ),
            (0, 0, 0, 0)
        );
        assert!(matches!(
            binding.session.register_thread(3),
            Err(SetupError::ThreadLimit)
        ));
        drop(a);
        drop(b);
        assert!(matches!(
            binding.session.register_thread(1),
            Err(SetupError::DuplicateThread)
        ));
        assert!(matches!(
            binding.session.register_thread(2),
            Err(SetupError::DuplicateThread)
        ));
        assert!(matches!(
            binding.session.register_thread(3),
            Err(SetupError::ThreadLimit)
        ));
    }

    #[test]
    fn two_pending_owners_confirm_locally_with_retained_dropped_and_closed_results() {
        // Metadata only: two registrations on this test thread, copied PCs/words.
        // This does not claim actual worker/TLS readiness, native CALL/RET or return attestation.
        for first in [0, 1] {
            let binding = binding(true, EntryMode::Concurrent);
            let mut states = [
                state(&binding, 1, binding.session.register_thread(1).unwrap()),
                state(&binding, 2, binding.session.register_thread(2).unwrap()),
            ];
            let epoch = binding
                .session
                .stage(Config {
                    retained_per_function: 1,
                    max_inflight: 2,
                    max_invocations: 2,
                })
                .unwrap();
            binding.session.publish(&epoch, FailurePoint::None).unwrap();
            observed(&mut states[0]);
            observed(&mut states[1]);
            assert_eq!(epoch.reservations(), 2);
            let [a, b] = &mut states;
            let pending = a.pending.as_mut().unwrap();
            let summary = pending.receipt.summary();
            let slot = pending.slot;
            assert_eq!(
                b.model.finish_interval(
                    &mut pending.receipt,
                    &mut pending.slot,
                    Observation::Value(999)
                ),
                Err(IntervalExitError::ForeignEntry)
            );
            assert_eq!(pending.receipt.summary(), summary);
            assert_eq!(pending.slot, slot);
            assert_eq!((a.model.depth(), b.model.depth()), (1, 1));
            assert_eq!((a.totals.confirmed, b.totals.confirmed), (0, 0));
            a.shape().unwrap();
            b.shape().unwrap();
            let first_batch = transfer(&mut states[first]);
            assert_eq!(first_batch.registration(), first as u64 + 1);
            assert_eq!(first_batch.completed_sequences(), (0, 1));
            assert_eq!(first_batch.records().len(), 1);
            assert_eq!(epoch.reservations(), 1);
            assert!(states[1 - first].pending.is_some());
            assert_eq!(states[1 - first].totals.confirmed, 0);
            let second_batch = transfer(&mut states[1 - first]);
            assert_eq!(second_batch.completed_sequences(), (0, 1));
            assert_eq!(epoch.reservations(), 0);
            assert!(epoch.try_report().is_none());
            // Function closure and zero reservations alone are not a final report.
            // This explicit metadata close grants no executable-return credit.
            assert_eq!(epoch.close(), 0);
            let report = epoch.try_report().unwrap();
            let rows: Vec<_> = report.records().collect();
            assert_eq!(rows.len(), 2);
            for (index, row) in rows.iter().enumerate() {
                assert_eq!(row.record.admission.invocation, index);
                let disposition = if index == first {
                    Disposition::Retained { rank: 0 }
                } else {
                    Disposition::DroppedAfterBudget
                };
                assert_eq!(
                    row.record.terminal,
                    Some(Terminal::Completed {
                        value: index as u64,
                        disposition
                    })
                );
                let payload = row.payload.unwrap();
                assert_eq!(
                    (payload.thread, payload.start_sequence),
                    (index as u64 + 1, 0)
                );
                assert!(matches!(
                    payload.outcome,
                    PayloadOutcome::Completed {
                        completed_children: 0,
                        ..
                    }
                ));
            }
            drop(report);
            observed(&mut states[0]);
            observed(&mut states[1]);
            for s in &states {
                assert!(matches!(
                    s.pending.as_ref().unwrap().summary,
                    Some(IntervalEntrySummary::Unsampled {
                        reason: UnsampledSummary::FunctionClosed { .. },
                        ..
                    })
                ));
            }
            let [a, b] = &mut states;
            let pending = a.pending.as_mut().unwrap();
            let summary = pending.receipt.summary();
            let slot = pending.slot;
            assert_eq!(
                b.model.finish_interval(
                    &mut pending.receipt,
                    &mut pending.slot,
                    Observation::Value(999)
                ),
                Err(IntervalExitError::ForeignEntry)
            );
            assert_eq!(pending.receipt.summary(), summary);
            assert_eq!(pending.slot, slot);
            binding.session.remove_current().unwrap();
            drop(epoch);
            assert_eq!(binding.session.retained_epochs(), 1);
            let batch = transfer(&mut states[first]);
            assert_eq!(batch.totals().1.unsampled, 1);
            assert_eq!(binding.session.retained_epochs(), 1);
            assert!(states[1 - first].pending.is_some());
            let batch = transfer(&mut states[1 - first]);
            assert_eq!(batch.totals().1.unsampled, 1);
            assert_eq!(binding.session.retained_epochs(), 0);
        }
    }
}
