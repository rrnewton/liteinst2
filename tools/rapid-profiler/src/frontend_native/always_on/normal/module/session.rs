//! Exact streaming two-function profile; one existing normal TLS and receipt path.
use super::*;

fn fixed(k: usize) -> Option<(Limits, Config)> {
    let a = match k {
        10 => 20,
        1000 => 2000,
        _ => return None,
    };
    Some((
        Limits {
            epochs: 3,
            threads: 1,
            depth: 1,
            records_per_epoch: a,
            actions: 8,
        },
        Config {
            retained_per_function: k,
            max_inflight: 1,
            max_invocations: a,
        },
    ))
}
pub(super) fn profile_matches(profile: &BindingProfile, limits: Limits, config: Config) -> bool {
    matches!(profile, BindingProfile::Module { functions, .. } if functions[0] != functions[1])
        && fixed(config.retained_per_function) == Some((limits, config))
}
pub(super) fn binding_matches(binding: &Binding) -> bool {
    let k = match binding.limits.records_per_epoch {
        20 => 10,
        2000 => 1000,
        _ => return false,
    };
    let Some((_, config)) = fixed(k) else {
        return false;
    };
    profile_matches(&binding.profile, binding.limits, config)
        && matches!(binding.entry_mode, EntryMode::Concurrent)
        && binding.session.history_mode() == HistoryMode::Absolute
}

/// Separate pristine streaming preparation. No finite, Single or gated conversion.
pub struct PreparedNormalModuleSessionController {
    inner: PreparedIntervalController,
    config: Config,
    banks_prepared: bool,
}
impl PreparedNormalModuleSessionController {
    /// Two distinct IDs in sealed ELF order, mandatory group 0, E3/T1/D1,
    /// K10 or K1000 per function, global M1/A2K and eight resident actions.
    pub fn new(
        site: site::ordinary::InstalledNormalModuleSite,
        install: u64,
        functions: [FunctionId; 2],
        k: usize,
    ) -> Result<Self, BridgeError> {
        if !timing::supported() {
            return Err(error(Cause::ClockProfile));
        }
        Self::prepare(site.site, install, functions, k)
    }
    // Also used by nonexecuting metadata controls; never fabricates a loaded owner.
    fn prepare(
        site: Arc<site::ordinary::ModuleSite>,
        install: u64,
        functions: [FunctionId; 2],
        k: usize,
    ) -> Result<Self, BridgeError> {
        let (limits, config) = fixed(k).ok_or(error(Cause::Identity))?;
        if functions[0] == functions[1] {
            return Err(error(Cause::Identity));
        }
        let session = Session::new_streaming_history(
            install,
            &functions.map(|function| FunctionSpec { function, group: 0 }),
            &[GroupSpec { mandatory: true }],
            limits,
        )
        .map_err(|e| error(Cause::Setup(e)))?;
        let mut epochs = Vec::new();
        epochs
            .try_reserve_exact(limits.epochs)
            .map_err(|_| error(Cause::Capacity))?;
        Ok(Self {
            inner: PreparedIntervalController {
                session,
                profile: BindingProfile::Module { site, functions },
                key: Arc::new(()),
                install,
                limits,
                epochs,
                _exclusive: PhantomData,
            },
            config,
            banks_prepared: false,
        })
    }
    /// Prepare exactly three fixed-Config banks once, before activation or use.
    /// All fallible Vec reservations precede the bank-mode commit. Initialization
    /// touches initialized slot state only: neither full-byte residency nor a
    /// deadline guarantee follows. Lost banks are not replaced.
    pub fn prepare_epoch_storage(&mut self) -> Result<Vec<IntervalEpochStorage>, BridgeError> {
        let banks =
            super::super::super::epoch_storage::prepare_module(&mut self.inner, self.config)?;
        self.banks_prepared = true;
        Ok(banks)
    }
    /// # Safety
    /// The original pristine process/fork, concurrent-entry, no-reentry/signal
    /// and no callback-dependent-lock contracts hold. Both sealed leaves and all
    /// source/generated/control owners remain immutable and process-lived.
    /// One actual caller attaches before work, owns its stack/input/journal and
    /// observes ordinary nonnested CALL/RET. No cancellation, unwind, nonlocal
    /// exit, CET, fork, alias writer or unload is permitted. Publication changes
    /// only the shared metadata epoch; it grants no executable quiescence.
    pub unsafe fn activate_concurrent(
        self,
    ) -> Result<(NormalModuleSessionController, NormalModuleClient), BridgeError> {
        if !self.banks_prepared {
            return Err(error(Cause::Setup(SetupError::StorageMode)));
        }
        if !profile_matches(&self.inner.profile, self.inner.limits, self.config)
            || self.inner.session.history_mode() != HistoryMode::Absolute
            || !self.inner.epochs.is_empty()
        {
            return Err(error(Cause::Identity));
        }
        PreparedNormalController::available()?;
        let (controller, binding) = self.inner.activate_binding(EntryMode::Concurrent)?;
        Ok((
            NormalModuleSessionController(controller),
            NormalModuleClient { binding },
        ))
    }
}

/// One metadata controller, Send but not Sync; only prepared storage may stage.
/// Reports/history never prove a physical RET or authorize code reclamation.
pub struct NormalModuleSessionController(pub(super) IntervalController);
impl NormalModuleSessionController {
    fn check(&self) -> Result<(), BridgeError> {
        self.0.binding.process()?;
        if !binding_matches(&self.0.binding) {
            return Err(error(Cause::Identity));
        }
        Ok(())
    }
    /// Consume one fixed bank, returning that same bank on every Result refusal.
    /// Fresh Arc shells still allocate; no scheduling/residency bound is promised.
    #[allow(clippy::result_large_err)] // Keep the returned bank inline until custody is restored.
    pub fn stage_prepared(
        &mut self,
        bank: IntervalEpochStorage,
    ) -> Result<IntervalEpoch, (BridgeError, IntervalEpochStorage)> {
        super::super::super::epoch_storage::stage_module(&mut self.0, bank)
    }
    /// Reclaim only closed, noncurrent, drained, exclusively owned metadata.
    /// Refusal preserves the same token. A pending FunctionClosed receipt or
    /// retained Report may prevent reclamation; no waiting for owners is added.
    pub fn reclaim_storage(
        &mut self,
        epoch: IntervalEpoch,
    ) -> Result<IntervalEpochStorage, (EpochStorageReclaimError, IntervalEpoch)> {
        if let Err(e) = self.check() {
            return Err((EpochStorageReclaimError::Bridge(e), epoch));
        }
        self.0.reclaim_storage(epoch)
    }
    pub fn arm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        self.check()?;
        self.0.arm(epoch)
    }
    pub fn disarm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        self.check()?;
        self.0.disarm(epoch)
    }
    pub fn report(&self, epoch: &IntervalEpoch) -> Result<Option<Report>, BridgeError> {
        self.check()?;
        self.0.report(epoch)
    }
    /// Transfer the bounded resident actions; retain unsent batches yourself.
    /// No epoch/receipt is released and no sink or native-return acknowledgement occurs.
    pub fn drain_history(&mut self) -> Result<Option<NormalModuleHistoryBatch>, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.check()?;
        let stream = session_history::stream_for(&self.0.binding).ok_or(error(Cause::Identity))?;
        self.0
            .binding
            .session
            .drain_history()
            .map_err(|e| error(Cause::Control(e)))
            .map(|chunk| chunk.map(|chunk| NormalModuleHistoryBatch::from_checked(stream, chunk)))
    }
    /// Read a qualified resident suffix, including terminal diagnostics; never
    /// substitute it for the complete chained stream or permission to drain.
    pub fn history_window(&self) -> Result<NormalModuleHistoryWindow, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.check()?;
        let stream = session_history::stream_for(&self.0.binding).ok_or(error(Cause::Identity))?;
        let view = self
            .0
            .binding
            .session
            .history_window()
            .map_err(|e| error(Cause::Control(e)))?;
        Ok(NormalModuleHistoryWindow::from_checked(stream, view))
    }
}

#[cfg(test)]
pub(super) mod tests;
