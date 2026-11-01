//! Fixed E3/T1/D1, K10/K1000 banks; only the two entry controls are mutable.
use super::*;

pub struct PreparedEarlyEntryModuleSessionController {
    inner: PreparedIntervalController,
    config: Config,
    writers: [ControlWriter; 2],
    prepared: bool,
}
impl PreparedEarlyEntryModuleSessionController {
    pub fn new(
        site: InstalledEarlyEntryModuleSite,
        install: u64,
        functions: [FunctionId; 2],
        k: usize,
    ) -> Result<Self, BridgeError> {
        if !timing::supported()
            || !site.site.is_early_entry()
            || functions[0] == functions[1]
            || site.role_controls().any(|(r, c)| {
                c.is_enabled() != (r.kind == site::ordinary::NormalModuleRoleKind::Return)
            })
        {
            return Err(error(Cause::Identity));
        }
        Self::prepare(site.site, site.writers, install, functions, k)
    }
    pub(super) fn prepare(
        site: Arc<site::ordinary::ModuleSite>,
        writers: [ControlWriter; 2],
        install: u64,
        functions: [FunctionId; 2],
        k: usize,
    ) -> Result<Self, BridgeError> {
        let (limits, config) =
            super::super::super::session::fixed(k).ok_or(error(Cause::Identity))?;
        let profile = BindingProfile::Module { site, functions };
        if !profile_matches(&profile, limits, config) {
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
                profile,
                key: Arc::new(()),
                install,
                limits,
                epochs,
                _exclusive: PhantomData,
            },
            config,
            writers,
            prepared: false,
        })
    }
    pub fn prepare_epoch_storage(&mut self) -> Result<Vec<IntervalEpochStorage>, BridgeError> {
        let result = crate::frontend_native::always_on::epoch_storage::prepare_early_module(
            &mut self.inner,
            self.config,
        )?;
        self.prepared = true;
        Ok(result)
    }
    /// # Safety
    /// The unchanged pristine process/fork, immutable process-lived publication,
    /// no signal/unwind/reentry/callback-dependent-lock contracts hold. Exactly
    /// one worker attaches through this profile's owned caller before any entry.
    /// Controller publication changes metadata only, never executable ownership.
    pub unsafe fn activate_concurrent(
        self,
    ) -> Result<(EarlyEntryModuleSessionController, EarlyEntryModuleClient), BridgeError> {
        if !self.prepared
            || !profile_matches(&self.inner.profile, self.inner.limits, self.config)
            || self.inner.session.history_mode() != HistoryMode::Absolute
            || !self.inner.epochs.is_empty()
        {
            return Err(error(Cause::Identity));
        }
        PreparedNormalController::available()?;
        PHYSICAL
            .try_with(|p| {
                if p.try_borrow()
                    .map_err(|_| error(Cause::Attachment))?
                    .is_none()
                {
                    Ok(())
                } else {
                    Err(error(Cause::Attachment))
                }
            })
            .unwrap_or(Err(error(Cause::Attachment)))?;
        let (inner, binding) = self.inner.activate_binding(EntryMode::Concurrent)?;
        let shared = Arc::new(Shared {
            binding,
            failed: AtomicBool::new(false),
        });
        Ok((
            EarlyEntryModuleSessionController {
                inner,
                writers: self.writers,
                shared: Arc::clone(&shared),
            },
            EarlyEntryModuleClient { shared },
        ))
    }
}

/// Unique controller; selectors are updated inside the existing Session writer
/// transaction using per-function flags. Mandatory group visibility is distinct.
pub struct EarlyEntryModuleSessionController {
    inner: IntervalController,
    writers: [ControlWriter; 2],
    shared: Arc<Shared>,
}
impl EarlyEntryModuleSessionController {
    fn mutation<T>(&self, result: Result<T, BridgeError>) -> Result<T, BridgeError> {
        if result.is_err() {
            self.shared.failed.store(true, Ordering::Release);
        }
        result
    }
    #[allow(clippy::result_large_err)] // Preserve the same bank on refusal.
    pub fn stage_prepared(
        &mut self,
        bank: IntervalEpochStorage,
    ) -> Result<IntervalEpoch, (BridgeError, IntervalEpochStorage)> {
        if let Err(e) = self.shared.check() {
            return Err((e, bank));
        }
        crate::frontend_native::always_on::epoch_storage::stage_early_module(&mut self.inner, bank)
    }
    pub fn reclaim_storage(
        &mut self,
        epoch: IntervalEpoch,
    ) -> Result<IntervalEpochStorage, (EpochStorageReclaimError, IntervalEpoch)> {
        if let Err(e) = self.shared.check() {
            return Err((EpochStorageReclaimError::Bridge(e), epoch));
        }
        self.inner.reclaim_storage(epoch)
    }
    pub fn arm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        let result = (|| {
            let _scope = ControllerScope::enter()?;
            self.shared.check()?;
            let owner = self.inner.owner(epoch)?.clone();
            let writers = &mut self.writers;
            self.shared
                .binding
                .session
                .publish_with_controls(&owner, FailurePoint::None, |flags| {
                    writers[0].set_enabled(flags[0]);
                    writers[1].set_enabled(flags[1]);
                })
                .map_err(|e| error(Cause::Control(e)))
        })();
        self.mutation(result)
    }
    pub fn disarm(&mut self, epoch: &IntervalEpoch) -> Result<(), BridgeError> {
        let result = (|| {
            let _scope = ControllerScope::enter()?;
            self.shared.check()?;
            let generation = self.inner.owner(epoch)?.generation();
            let writers = &mut self.writers;
            self.shared
                .binding
                .session
                .remove_with_controls(Some(generation), |flags| {
                    writers[0].set_enabled(flags[0]);
                    writers[1].set_enabled(flags[1]);
                })
                .map_err(|e| error(Cause::Control(e)))
        })();
        self.mutation(result)
    }
    pub fn scan_closed(&mut self) -> Result<usize, BridgeError> {
        let result = (|| {
            let _scope = ControllerScope::enter()?;
            self.shared.check()?;
            let writers = &mut self.writers;
            self.shared
                .binding
                .session
                .scan_with_controls(|flags| {
                    writers[0].set_enabled(flags[0]);
                    writers[1].set_enabled(flags[1]);
                })
                .map_err(|e| error(Cause::Control(e)))
        })();
        self.mutation(result)
    }
    pub fn report(&self, epoch: &IntervalEpoch) -> Result<Option<Report>, BridgeError> {
        self.shared.check()?;
        self.inner.report(epoch)
    }
    pub fn drain_history(&mut self) -> Result<Option<NormalModuleHistoryBatch>, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.shared.check()?;
        let stream = super::super::super::session_history::early_stream_for(&self.shared.binding)
            .ok_or(error(Cause::Identity))?;
        self.shared
            .binding
            .session
            .drain_history()
            .map_err(|e| error(Cause::Control(e)))
            .map(|chunk| chunk.map(|chunk| NormalModuleHistoryBatch::from_checked(stream, chunk)))
    }
    pub fn history_window(&self) -> Result<NormalModuleHistoryWindow, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.shared.check()?;
        let stream = super::super::super::session_history::early_stream_for(&self.shared.binding)
            .ok_or(error(Cause::Identity))?;
        let view = self
            .shared
            .binding
            .session
            .history_window()
            .map_err(|e| error(Cause::Control(e)))?;
        Ok(NormalModuleHistoryWindow::from_checked(stream, view))
    }
}
impl Drop for EarlyEntryModuleSessionController {
    fn drop(&mut self) {
        self.shared.failed.store(true, Ordering::Release);
        for writer in &mut self.writers {
            writer.set_enabled(false);
        }
        // The unchanged IntervalController Drop closes and retains old owners.
    }
}

pub(super) struct EarlyOutput {
    inner: ModuleOutput,
}
impl TransferOutput for EarlyOutput {
    type Batch = NormalModuleBatch;
    type Identity = ModuleIdentity;
    const PROFILE: TransferProfile = TransferProfile::EarlyModule;
    fn allocate() -> Result<(Self, Vec<u64>), BridgeError> {
        let (inner, journal) = ModuleOutput::allocate()?;
        Ok((Self { inner }, journal))
    }
    fn capacity(&self) -> bool {
        self.inner.capacity()
    }
    fn identity(&self, state: &NormalState) -> Result<ModuleIdentity, BridgeError> {
        if !early_binding(&state.binding) {
            return Err(error(Cause::Identity));
        }
        let BindingProfile::Module { site, functions } = &state.binding.profile else {
            return Err(error(Cause::Identity));
        };
        let stream = super::super::super::session_history::early_stream_for(&state.binding)
            .ok_or(error(Cause::Identity))?;
        let end = state.history_bound();
        if end > crate::frontend::MAX_HISTORY_POSITION {
            return Err(error(Cause::Capacity));
        }
        Ok(ModuleIdentity {
            stream: Some(stream),
            history_end: Some(end),
            identity: site.identity(),
            functions: *functions,
            entries: [site.functions()[0].entry(), site.functions()[1].entry()],
        })
    }
    fn push(&mut self, record: NormalRecord, selected: SelectedFunction) {
        self.inner.push(record, selected);
    }
    fn finish(
        self,
        id: ModuleIdentity,
        header: TransferHeader,
        journal: Vec<u64>,
    ) -> NormalModuleBatch {
        self.inner.finish(id, header, journal)
    }
}

#[cfg(test)]
mod tests;
