//! Once-issued fixed vector banks for the explicit concurrent normal facade.
//! Idle banks retain no SessionInner, generation or frontend Permit. Reclaim is
//! metadata ownership only: no report-export, physical-return or code-drain proof.
use super::*;
use crate::generation::storage::{self, Storage};

pub(crate) struct EpochStorage {
    spec: Arc<Spec>,
    index: usize,
    config: Config,
    model: Storage,
    payloads: Vec<OnceLock<Payload>>,
}

// Diagnostic identity only; no owner, mutable buffer or payload escape.
impl std::fmt::Debug for EpochStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochStorage")
            .field("index", &self.index)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageReclaimError {
    SharedOwner,
    Control(ControlError),
    Current,
    NotDrained,
    InvalidStorage,
}

fn reserved<T>(n: usize) -> Result<Vec<T>, SetupError> {
    storage::reserved(n).map_err(|_| SetupError::Allocation)
}

impl Session {
    /// Exactly E banks, once, on an exclusive pristine absolute-history session.
    /// All Vec allocations and initialized-state touches precede the mode commit.
    /// This does not promise residency or bound scheduling/allocation latency.
    pub(crate) fn prepare_epoch_storage(
        &mut self,
        config: Config,
    ) -> Result<Vec<EpochStorage>, SetupError> {
        let inner = Arc::get_mut(&mut self.inner).ok_or(SetupError::InvalidStorage)?;
        if inner.history_mode != HistoryMode::Absolute || inner.storage_mode.is_some() {
            return Err(SetupError::StorageMode);
        }
        if config.max_invocations > inner.spec.limits.records_per_epoch {
            return Err(SetupError::InvalidLimits);
        }
        Storage::validate(&inner.spec.ids, config).map_err(SetupError::Generation)?;
        if inner.ever_staged.load(Ordering::Acquire)
            || inner.pool.active.load(Ordering::Acquire) != 0
        {
            return Err(SetupError::InvalidStorage);
        }
        {
            let w = inner.writer.lock().map_err(|_| SetupError::Poisoned)?;
            let r = inner.registry.lock().map_err(|_| SetupError::Poisoned)?;
            if history_stream::validate(inner, &w, &r, true).is_err()
                || w.current.is_some()
                || r.current.is_some()
                || !r.threads.is_empty()
                || w.failed_owner.is_some()
                || w.enabled.iter().any(|&enabled| enabled)
                || !w.actions.is_empty()
                || w.history.base != 0
                || w.history.number != 0
                || w.history.carry != BindingChange::Initial
                || inner.committed_end.load(Ordering::Acquire) != 0
            {
                return Err(SetupError::InvalidStorage);
            }
        }
        let mut banks = reserved(inner.spec.limits.epochs)?;
        for index in 0..inner.spec.limits.epochs {
            let model =
                Storage::prepare(&inner.spec.ids, config).map_err(SetupError::Generation)?;
            let mut payloads = reserved(config.max_invocations)?;
            payloads.resize_with(config.max_invocations, OnceLock::new);
            for payload in &payloads {
                let _ = std::hint::black_box(std::hint::black_box(payload).get());
            }
            banks.push(EpochStorage {
                spec: Arc::clone(&inner.spec),
                index,
                config,
                model,
                payloads,
            });
        }
        inner.storage_mode = Some(config);
        Ok(banks)
    }

    /// On any recoverable refusal the exact clean bank is returned unchanged.
    /// Standard two-Arc OOM behavior is unchanged; no A-sized Vec is allocated.
    #[allow(clippy::result_large_err)] // Preserve the bank, without another Box allocation.
    pub(crate) fn stage_prepared_storage(
        &self,
        bank: EpochStorage,
    ) -> Result<EpochHandle, (SetupError, EpochStorage)> {
        self.stage_storage_with(bank, Storage::into_epoch)
    }

    // The only production constructor is Storage::into_epoch. The private seam
    // also exercises global-ID exhaustion using a local test AtomicU64.
    #[allow(clippy::result_large_err)]
    fn stage_storage_with(
        &self,
        bank: EpochStorage,
        make_epoch: impl FnOnce(Storage) -> Result<Epoch, (CreateError, Storage)>,
    ) -> Result<EpochHandle, (SetupError, EpochStorage)> {
        if self.inner.storage_mode != Some(bank.config)
            || !Arc::ptr_eq(&self.inner.spec, &bank.spec)
            || bank.index >= self.inner.spec.limits.epochs
            || bank.payloads.len() != bank.config.max_invocations
            || !bank.model.matches(&self.inner.spec.ids, bank.config)
        {
            return Err((SetupError::InvalidStorage, bank));
        }
        let permit = match self.inner.pool.reserve() {
            Ok(permit) => permit,
            Err(error) => return Err((error, bank)),
        };
        let EpochStorage {
            spec,
            index,
            config,
            model,
            payloads,
        } = bank;
        let epoch = match make_epoch(model) {
            Ok(epoch) => epoch,
            Err((error, model)) => {
                drop(permit);
                return Err((
                    SetupError::Generation(error),
                    EpochStorage {
                        spec,
                        index,
                        config,
                        model,
                        payloads,
                    },
                ));
            }
        };
        let handle = EpochHandle {
            owner: Arc::new(FrontendEpoch {
                epoch: Arc::new(epoch),
                spec,
                payloads,
                storage_bank: Some(index),
                _permit: permit,
            }),
        };
        self.inner.ever_staged.store(true, Ordering::Release);
        Ok(handle)
    }

    /// Both Arc layers must be uniquely borrowed before any field is extracted.
    /// Writer and registry authority prevent publication racing the preflight.
    /// Slot/owners/records/permit remain unchanged on every Result refusal.
    pub(crate) fn reclaim_epoch_storage(
        &self,
        slot: &mut Option<EpochHandle>,
    ) -> Result<EpochStorage, StorageReclaimError> {
        use StorageReclaimError as E;
        let config = self.inner.storage_mode.ok_or(E::InvalidStorage)?;
        let w = self
            .inner
            .writer
            .lock()
            .map_err(|_| E::Control(ControlError::Poisoned))?;
        let r = self
            .inner
            .registry
            .lock()
            .map_err(|_| E::Control(ControlError::Poisoned))?;
        history_stream::validate(&self.inner, &w, &r, true).map_err(E::Control)?;
        let handle = slot.as_mut().ok_or(E::InvalidStorage)?;
        if !Arc::ptr_eq(&self.inner.spec, &handle.owner.spec) {
            return Err(E::InvalidStorage);
        }
        let index = handle.owner.storage_bank.ok_or(E::InvalidStorage)?;
        if index >= self.inner.spec.limits.epochs || handle.owner.epoch.config() != config {
            return Err(E::InvalidStorage);
        }
        if w.current == Some(handle.generation()) {
            return Err(E::Current);
        }
        if handle.owner.epoch.try_drain().is_none() {
            return Err(E::NotDrained);
        }
        let owner = Arc::get_mut(&mut handle.owner).ok_or(E::SharedOwner)?;
        let epoch = Arc::get_mut(&mut owner.epoch).ok_or(E::SharedOwner)?;
        if owner.payloads.len() != config.max_invocations
            || !storage::matches_epoch(epoch, &self.inner.spec.ids, config)
        {
            return Err(E::InvalidStorage);
        }
        // Infallible commit begins. No arbitrary callback, new validation or
        // allocation follows extraction. Original shells and Permit die here.
        let retired = storage::extract(epoch);
        let mut payloads = std::mem::take(&mut owner.payloads);
        drop(slot.take());
        drop(r);
        drop(w);
        // Reset the whole logical A extent, including unused tail, after locks.
        let model = retired.reset();
        for payload in &mut payloads {
            let _ = payload.take();
        }
        Ok(EpochStorage {
            spec: Arc::clone(&self.inner.spec),
            index,
            config,
            model,
            payloads,
        })
    }
}

#[cfg(test)]
mod tests;
