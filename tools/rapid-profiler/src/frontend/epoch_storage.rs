//! Once-issued fixed vector banks for the explicit concurrent normal facade.
//! Idle banks retain no SessionInner or frontend Permit. Recycled banks retain
//! inaccessible CLOSED metadata and both Arc shells. Reclaim is metadata ownership
//! only: no report-export, physical-return or code-drain proof.
use super::*;
use crate::generation::storage::{self, Storage};

pub(crate) struct EpochStorage {
    spec: Arc<Spec>,
    index: usize,
    config: Config,
    storage: Bank,
}

// No Clone or owner accessor. Only the successful reclaim commit constructs
// Recycled; its old ID is inaccessible until replaced by a fresh global ID.
enum Bank {
    Fresh {
        model: Storage,
        payloads: Vec<OnceLock<Payload>>,
    },
    Recycled {
        owner: Arc<FrontendEpoch>,
    },
}
impl EpochStorage {
    fn matches(&mut self, ids: &[FunctionId]) -> bool {
        match &mut self.storage {
            Bank::Fresh { model, payloads } => {
                payloads.len() == self.config.max_invocations && model.matches(ids, self.config)
            }
            Bank::Recycled { owner } => {
                if !Arc::ptr_eq(&self.spec, &owner.spec)
                    || owner.storage_bank != Some(self.index)
                    || owner._permit.is_some()
                    || owner.payloads.len() != self.config.max_invocations
                    || !storage::matches_recycled(&owner.epoch, ids, self.config)
                {
                    return false;
                }
                let Some(owner) = Arc::get_mut(owner) else {
                    return false;
                };
                Arc::get_mut(&mut owner.epoch).is_some()
            }
        }
    }
}

#[cfg(test)]
type TestBankParts<'a> = ([(usize, usize, usize); 2], &'a Vec<OnceLock<Payload>>, bool);

#[cfg(test)]
impl EpochStorage {
    fn test_parts(&self) -> TestBankParts<'_> {
        match &self.storage {
            Bank::Fresh { model, payloads } => (model.geometry(), payloads, model.clean()),
            Bank::Recycled { owner } => (
                storage::epoch_geometry(&owner.epoch),
                &owner.payloads,
                storage::recycled_clean(&owner.epoch),
            ),
        }
    }

    fn test_payloads_mut(&mut self) -> &mut Vec<OnceLock<Payload>> {
        match &mut self.storage {
            Bank::Fresh { payloads, .. } => payloads,
            Bank::Recycled { owner } => {
                &mut Arc::get_mut(owner).expect("exclusive test bank").payloads
            }
        }
    }

    /// Borrowed storage identity and state; the copy retains no storage owner.
    pub(crate) fn test_fingerprint(&self) -> impl std::fmt::Debug + Eq + use<> {
        #[derive(Debug, Eq, PartialEq)]
        struct RecycledFingerprint {
            shells: [usize; 2],
            spec: usize,
            bank: Option<usize>,
            generation: GenerationId,
            config: Config,
            counts: [usize; 4],
            state: (usize, usize),
            permit: bool,
        }
        #[derive(Debug, Eq, PartialEq)]
        struct Fingerprint {
            spec: usize,
            index: usize,
            config: Config,
            model: [(usize, usize, usize); 2],
            payload: (usize, usize, usize),
            clean: bool,
            recycled: Option<RecycledFingerprint>,
        }
        let (model, payloads, clean) = self.test_parts();
        Fingerprint {
            spec: Arc::as_ptr(&self.spec) as usize,
            index: self.index,
            config: self.config,
            model,
            payload: (
                payloads.as_ptr() as usize,
                payloads.len(),
                payloads.capacity(),
            ),
            clean: clean && payloads.iter().all(|p| p.get().is_none()),
            recycled: match &self.storage {
                Bank::Fresh { .. } => None,
                Bank::Recycled { owner } => Some(RecycledFingerprint {
                    shells: [
                        Arc::as_ptr(owner) as usize,
                        Arc::as_ptr(&owner.epoch) as usize,
                    ],
                    spec: Arc::as_ptr(&owner.spec) as usize,
                    bank: owner.storage_bank,
                    generation: owner.epoch.id(),
                    config: owner.epoch.config(),
                    counts: [
                        Arc::strong_count(owner),
                        Arc::weak_count(owner),
                        Arc::strong_count(&owner.epoch),
                        Arc::weak_count(&owner.epoch),
                    ],
                    state: storage::epoch_state(&owner.epoch),
                    permit: owner._permit.is_some(),
                }),
            },
        }
    }
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
                storage: Bank::Fresh { model, payloads },
            });
        }
        inner.storage_mode = Some(config);
        Ok(banks)
    }

    /// On any recoverable refusal the exact clean bank is returned unchanged.
    /// First use allocates two Arc shells; recycled stages reuse both shells.
    /// No A-sized Vec is allocated; this is not an allocation-free arm guarantee.
    #[allow(clippy::result_large_err)] // Preserve the bank, without another Box allocation.
    pub(crate) fn stage_prepared_storage(
        &self,
        bank: EpochStorage,
    ) -> Result<EpochHandle, (SetupError, EpochStorage)> {
        self.stage_storage_with(bank, Storage::into_epoch, storage::restart)
    }

    // Production always uses the unchanged global ID allocator. These private
    // constructors also exercise exhaustion using local test AtomicU64 values.
    #[allow(clippy::result_large_err)]
    fn stage_storage_with(
        &self,
        mut bank: EpochStorage,
        make_epoch: impl FnOnce(Storage) -> Result<Epoch, (CreateError, Storage)>,
        restart_epoch: impl FnOnce(&mut Epoch) -> Result<(), CreateError>,
    ) -> Result<EpochHandle, (SetupError, EpochStorage)> {
        if self.inner.storage_mode != Some(bank.config)
            || !Arc::ptr_eq(&self.inner.spec, &bank.spec)
            || bank.index >= self.inner.spec.limits.epochs
            || !bank.matches(&self.inner.spec.ids)
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
            storage,
        } = bank;
        let owner = match storage {
            Bank::Fresh { model, payloads } => {
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
                                storage: Bank::Fresh { model, payloads },
                            },
                        ));
                    }
                };
                shell(FrontendEpoch {
                    epoch: shell(epoch),
                    spec,
                    payloads,
                    storage_bank: Some(index),
                    _permit: Some(permit),
                })
            }
            Bank::Recycled { mut owner } => {
                // Preflight proved both layers unique, including weak owners.
                // No alias can be minted from the consumed private bank.
                let inner = Arc::get_mut(&mut owner).expect("exclusive recycled owner");
                let epoch = Arc::get_mut(&mut inner.epoch).expect("exclusive recycled epoch");
                if let Err(error) = restart_epoch(epoch) {
                    drop(permit);
                    return Err((
                        SetupError::Generation(error),
                        EpochStorage {
                            spec,
                            index,
                            config,
                            storage: Bank::Recycled { owner },
                        },
                    ));
                }
                // No lookup, validation or allocation follows successful ID consumption.
                inner._permit = Some(permit);
                owner
            }
        };
        let handle = EpochHandle { owner };
        self.inner.ever_staged.store(true, Ordering::Release);
        Ok(handle)
    }

    /// Both Arc layers must be uniquely borrowed before any field is changed.
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
            || owner._permit.is_none()
        {
            return Err(E::InvalidStorage);
        }
        // Infallible commit begins. Preserve both allocations, release only the
        // live permit, then clear the whole A extent outside metadata locks.
        let permit = owner._permit.take().expect("validated live permit");
        let mut owner = slot.take().expect("validated retained slot").owner;
        drop(permit);
        drop(r);
        drop(w);
        let inner = Arc::get_mut(&mut owner).expect("exclusive reclaimed owner");
        let epoch = Arc::get_mut(&mut inner.epoch).expect("exclusive reclaimed epoch");
        storage::reset_recycled(epoch);
        for payload in &mut inner.payloads {
            let _ = payload.take();
        }
        Ok(EpochStorage {
            spec: Arc::clone(&self.inner.spec),
            index,
            config,
            storage: Bank::Recycled { owner },
        })
    }
}

// The two actual first-use allocation sites share this narrow counting seam.
// It does not replace Arc allocation or count unrelated arm-path allocations.
fn shell<T>(value: T) -> Arc<T> {
    #[cfg(test)]
    shell_probe::allocated();
    Arc::new(value)
}

#[cfg(test)]
mod shell_probe {
    use std::cell::Cell;
    thread_local! { static COUNT: Cell<usize> = const { Cell::new(0) }; }
    pub(super) struct Guard(usize);
    pub(super) fn start() -> Guard {
        Guard(COUNT.replace(0))
    }
    pub(super) fn allocated() {
        COUNT.set(COUNT.get() + 1);
    }
    pub(super) fn calls() -> usize {
        COUNT.get()
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            COUNT.set(self.0);
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod reuse_tests;
