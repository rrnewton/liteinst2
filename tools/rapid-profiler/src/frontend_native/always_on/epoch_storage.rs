//! Explicit bounded metadata storage. No owner scavenging or executable retirement.
use super::*;
use crate::frontend::{EpochStorage, StorageReclaimError};

/// One opaque, non-Clone bank, bound to one preparation and its fixed Config.
/// Idle storage exposes no generation and owns no live epoch permit. Recycled
/// storage retains inaccessible closed metadata. Dropping or forgetting
/// a bank loses that capacity permanently; there is no replacement allocation.
/// It carries no source, publication, native-return or executable-drain authority.
pub struct IntervalEpochStorage {
    key: Arc<()>,
    storage: EpochStorage,
}
#[cfg(test)]
impl IntervalEpochStorage {
    pub(super) fn test_fingerprint(&self) -> impl std::fmt::Debug + Eq + use<> {
        (
            Arc::as_ptr(&self.key) as usize,
            self.storage.test_fingerprint(),
        )
    }
}
impl std::fmt::Debug for IntervalEpochStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntervalEpochStorage")
            .finish_non_exhaustive()
    }
}

/// Reclamation does not wait for outstanding owners and preserves the owner on
/// refusal. SharedOwner includes
/// Reports, acquired handles and pending FunctionClosed receipts; a ready Report
/// alone does not establish exclusive storage ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochStorageReclaimError {
    SharedOwner,
    Bridge(BridgeError),
}

fn normal_profile(site: &site::Site, limits: Limits) -> bool {
    limits.depth == 1
        && ((site.is_normal() && limits.threads == 1)
            || (site.is_normal_two_callers() && limits.threads == 2))
}

#[derive(Clone, Copy)]
enum Profile {
    Normal,
    ModuleSession,
}

pub(super) fn prepare_module(
    prepared: &mut PreparedIntervalController,
    config: Config,
) -> Result<Vec<IntervalEpochStorage>, BridgeError> {
    prepare_for(prepared, config, Profile::ModuleSession)
}

#[allow(clippy::result_large_err)] // Return the same bank without allocating an error box.
pub(super) fn stage_module(
    controller: &mut IntervalController,
    bank: IntervalEpochStorage,
) -> Result<IntervalEpoch, (BridgeError, IntervalEpochStorage)> {
    controller.stage_prepared_for(bank, Profile::ModuleSession)
}

pub(super) fn prepare(
    prepared: &mut PreparedIntervalController,
    config: Config,
) -> Result<Vec<IntervalEpochStorage>, BridgeError> {
    prepare_for(prepared, config, Profile::Normal)
}

fn prepare_for(
    prepared: &mut PreparedIntervalController,
    config: Config,
    profile: Profile,
) -> Result<Vec<IntervalEpochStorage>, BridgeError> {
    let _scope = ControllerScope::enter()?;
    match profile {
        Profile::Normal => {
            if !normal_profile(prepared.profile.single()?.0, prepared.limits) {
                return Err(error(Cause::Identity));
            }
        }
        Profile::ModuleSession => {
            if !normal::module_session_profile_matches(&prepared.profile, prepared.limits, config)
                || prepared.session.history_mode() != HistoryMode::Absolute
            {
                return Err(error(Cause::Identity));
            }
        }
    }
    // Reserve the facade result before the core can commit banked mode. The core
    // authenticates Absolute/pristine/once-only state and completes all other
    // fallible allocations before its commit. Afterwards only moves and Arc key
    // clones remain; these clones retain no Session or epoch owner.
    let mut result = Vec::new();
    result
        .try_reserve_exact(prepared.limits.epochs)
        .map_err(|_| error(Cause::Capacity))?;
    let banks = prepared
        .session
        .prepare_epoch_storage(config)
        .map_err(|e| error(Cause::Setup(e)))?;
    for storage in banks {
        result.push(IntervalEpochStorage {
            key: Arc::clone(&prepared.key),
            storage,
        });
    }
    Ok(result)
}

impl IntervalController {
    /// Consume a prepared bank into a fresh generation in a vacant controller
    /// slot. Returns the same bank on every recoverable refusal. No publication
    /// occurs and no old generation or history coordinate is reused. First use of a
    /// bank allocates two Arc shells; subsequent stages reuse them. This is not
    /// an allocation-free arm or a scheduling guarantee.
    #[allow(clippy::result_large_err)] // Return the same bank without a boxed error allocation.
    pub fn stage_prepared(
        &mut self,
        bank: IntervalEpochStorage,
    ) -> Result<IntervalEpoch, (BridgeError, IntervalEpochStorage)> {
        self.stage_prepared_for(bank, Profile::Normal)
    }

    #[allow(clippy::result_large_err)] // Preserve the returned bank until custody is restored.
    fn stage_prepared_for(
        &mut self,
        bank: IntervalEpochStorage,
        profile: Profile,
    ) -> Result<IntervalEpoch, (BridgeError, IntervalEpochStorage)> {
        let _scope = match ControllerScope::enter() {
            Ok(scope) => scope,
            Err(e) => return Err((e, bank)),
        };
        if let Err(e) = self.binding.process() {
            return Err((e, bank));
        }
        if !Arc::ptr_eq(&bank.key, &self.binding.key) {
            return Err((error(Cause::Epoch), bank));
        }
        match profile {
            Profile::Normal => {
                if !self
                    .binding
                    .single_site()
                    .is_ok_and(|site| normal_profile(site, self.binding.limits))
                    || !matches!(self.binding.entry_mode, EntryMode::Concurrent)
                    || self.binding.session.history_mode() != HistoryMode::Absolute
                {
                    return Err((error(Cause::Identity), bank));
                }
            }
            Profile::ModuleSession => {
                if !normal::module_session_binding_matches(&self.binding) {
                    return Err((error(Cause::Identity), bank));
                }
            }
        }
        let index = self
            .epochs
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.epochs.len());
        if index >= self.binding.limits.epochs {
            return Err((error(Cause::Capacity), bank));
        }
        let IntervalEpochStorage { key, storage } = bank;
        let owner = match self.binding.session.stage_prepared_storage(storage) {
            Ok(owner) => owner,
            Err((e, storage)) => {
                return Err((
                    error(Cause::Setup(e)),
                    IntervalEpochStorage { key, storage },
                ));
            }
        };
        let epoch = IntervalEpoch {
            key,
            index,
            generation: owner.generation(),
        };
        if index == self.epochs.len() {
            self.epochs.push(Some(owner)); // Capacity reserved before activation.
        } else {
            self.epochs[index] = Some(owner);
        }
        Ok(epoch)
    }

    /// Consume a closed, noncurrent, drained and exclusively owned generation
    /// into its original fixed bank. Every refusal returns the same epoch token
    /// and preserves its slot, records and permit. Copy required Report records
    /// once, release every Report/receipt/handle, then retry SharedOwner explicitly.
    /// Reclamation clears initialized slot state under exclusive ownership; it
    /// does not reset registrations, history, ordinals or completion sequences.
    /// No source/image reclamation, physical RET, byte residency or 2 ms guarantee
    /// follows from success. Legacy profiles keep their old stage/retire paths;
    /// banked mode refuses allocating stage and retirement forfeits storage.
    pub fn reclaim_storage(
        &mut self,
        epoch: IntervalEpoch,
    ) -> Result<IntervalEpochStorage, (EpochStorageReclaimError, IntervalEpoch)> {
        let _scope = match ControllerScope::enter() {
            Ok(scope) => scope,
            Err(e) => return Err((EpochStorageReclaimError::Bridge(e), epoch)),
        };
        if let Err(e) = self.owner(&epoch) {
            return Err((EpochStorageReclaimError::Bridge(e), epoch));
        }
        match self
            .binding
            .session
            .reclaim_epoch_storage(&mut self.epochs[epoch.index])
        {
            Ok(storage) => Ok(IntervalEpochStorage {
                key: epoch.key,
                storage,
            }),
            Err(e) => {
                let failure = match e {
                    StorageReclaimError::SharedOwner => EpochStorageReclaimError::SharedOwner,
                    StorageReclaimError::Control(e) => {
                        EpochStorageReclaimError::Bridge(error(Cause::Control(e)))
                    }
                    StorageReclaimError::Current => {
                        EpochStorageReclaimError::Bridge(error(Cause::CurrentEpoch))
                    }
                    StorageReclaimError::NotDrained => {
                        EpochStorageReclaimError::Bridge(error(Cause::NotDrained))
                    }
                    StorageReclaimError::InvalidStorage => {
                        EpochStorageReclaimError::Bridge(error(Cause::Identity))
                    }
                };
                Err((failure, epoch))
            }
        }
    }
}

#[cfg(test)]
mod tests;
