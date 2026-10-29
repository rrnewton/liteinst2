//! Exclusive vector custody. No ID is minted by preparation or reclamation.
//! Legacy Epoch::new and every admission/completion predicate remain separate.
use super::*;

/// Clean, fixed-configuration storage, never Clone and never a published owner.
pub(crate) struct Storage {
    config: Config,
    functions: Vec<Function>,
    slots: Vec<Slot>,
}

/// Extracted but not yet reset. This type cannot be staged.
#[cfg(test)]
pub(crate) struct RetiredStorage(Storage);

// One actual bounded Vec-allocation seam for every new bank vector. Tests can
// fail/count these reservations on their own thread; Arc allocations stay real.
pub(crate) fn reserved<T>(n: usize) -> Result<Vec<T>, CreateError> {
    #[cfg(test)]
    allocation_probe::before_reserve()?;
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| CreateError::Allocation)?;
    Ok(v)
}

impl Storage {
    pub(crate) fn validate(function_ids: &[FunctionId], config: Config) -> Result<(), CreateError> {
        // Literal legacy validation order; K, M and A remain independent.
        if function_ids.is_empty() {
            return Err(CreateError::EmptyFunctions);
        }
        if function_ids.len() > MAX_FUNCTIONS {
            return Err(CreateError::TooManyFunctions);
        }
        if function_ids
            .iter()
            .enumerate()
            .any(|(i, id)| function_ids[..i].contains(id))
        {
            return Err(CreateError::DuplicateFunction);
        }
        if config.retained_per_function == 0 {
            return Err(CreateError::ZeroRetainedBudget);
        }
        if config.max_inflight == 0 || config.max_inflight > COUNT_MASK {
            return Err(CreateError::InvalidInflightLimit);
        }
        if config.max_invocations == 0 || config.max_invocations > MAX_RECORDS {
            return Err(CreateError::InvalidInvocationLimit);
        }
        Ok(())
    }

    pub(crate) fn prepare(
        function_ids: &[FunctionId],
        config: Config,
    ) -> Result<Self, CreateError> {
        Self::validate(function_ids, config)?;
        let mut functions = reserved(function_ids.len())?;
        for &id in function_ids {
            functions.push(Function {
                id,
                retained: AtomicUsize::new(0),
                closed: AtomicBool::new(false),
            });
        }
        let mut slots = reserved(config.max_invocations)?;
        for _ in 0..config.max_invocations {
            slots.push(Slot {
                admission: OnceLock::new(),
                terminal: OnceLock::new(),
            });
        }
        let storage = Self {
            config,
            functions,
            slots,
        };
        // Touch only initialized IDs/counters and OnceLock states. Neither an
        // uninitialized payload byte nor a fake Admission is read or written.
        for f in &storage.functions {
            let f = std::hint::black_box(f);
            let _ = std::hint::black_box((
                f.id,
                f.retained.load(Ordering::Relaxed),
                f.closed.load(Ordering::Relaxed),
            ));
        }
        for s in &storage.slots {
            let s = std::hint::black_box(s);
            let _ = std::hint::black_box((s.admission.get(), s.terminal.get()));
        }
        Ok(storage)
    }

    // This is an identity/geometry check, not an A-sized clean-state scan.
    // Only preparation/reset can construct clean Storage in ordinary code.
    pub(crate) fn matches(&self, ids: &[FunctionId], config: Config) -> bool {
        self.config == config
            && self.functions.len() == ids.len()
            && self.functions.iter().zip(ids).all(|(f, id)| f.id == *id)
            && self.slots.len() == config.max_invocations
    }

    pub(crate) fn into_epoch(self) -> Result<Epoch, (CreateError, Self)> {
        self.into_epoch_with(&NEXT_GENERATION)
    }

    // A local AtomicU64 tests exhaustion without touching NEXT_GENERATION.
    fn into_epoch_with(self, next: &AtomicU64) -> Result<Epoch, (CreateError, Self)> {
        let id = match allocate_id(next) {
            Ok(id) => id,
            Err(error) => return Err((error, self)),
        };
        Ok(Epoch {
            id,
            config: self.config,
            functions: self.functions,
            slots: self.slots,
            state: AtomicUsize::new(0),
            assigned: AtomicUsize::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn test_exhausted(self) -> Result<Epoch, (CreateError, Self)> {
        self.into_epoch_with(&AtomicU64::new(u64::MAX))
    }

    #[cfg(test)]
    pub(crate) fn test_into_epoch_with(
        self,
        next: &AtomicU64,
    ) -> Result<Epoch, (CreateError, Self)> {
        self.into_epoch_with(next)
    }

    #[cfg(test)]
    pub(crate) fn geometry(&self) -> [(usize, usize, usize); 2] {
        [
            (
                self.functions.as_ptr() as usize,
                self.functions.len(),
                self.functions.capacity(),
            ),
            (
                self.slots.as_ptr() as usize,
                self.slots.len(),
                self.slots.capacity(),
            ),
        ]
    }

    #[cfg(test)]
    pub(crate) fn clean(&self) -> bool {
        self.functions
            .iter()
            .all(|f| f.retained.load(Ordering::Relaxed) == 0 && !f.closed.load(Ordering::Relaxed))
            && self
                .slots
                .iter()
                .all(|s| s.admission.get().is_none() && s.terminal.get().is_none())
    }
}

/// Geometry-only check under both unique Arc borrows, before extraction.
pub(crate) fn matches_epoch(epoch: &Epoch, ids: &[FunctionId], config: Config) -> bool {
    epoch.config == config
        && epoch.functions.len() == ids.len()
        && epoch.functions.iter().zip(ids).all(|(f, id)| f.id == *id)
        && epoch.slots.len() == config.max_invocations
}

/// Geometry and reset counters only; clean slots follow from exclusive reset.
/// This never scans A slots or accepts an open, still-assigned generation.
pub(crate) fn matches_recycled(epoch: &Epoch, ids: &[FunctionId], config: Config) -> bool {
    matches_epoch(epoch, ids, config)
        && epoch.state.load(Ordering::Acquire) == CLOSED
        && epoch.assigned.load(Ordering::Acquire) == 0
}

/// Caller holds unique outer and inner Arcs after closed+zero reclamation.
/// Keep the old ID inaccessible and CLOSED until a successful fresh-ID restart.
pub(crate) fn reset_recycled(epoch: &mut Epoch) {
    for f in &mut epoch.functions {
        *f.retained.get_mut() = 0;
        *f.closed.get_mut() = false;
    }
    for s in &mut epoch.slots {
        let _ = s.admission.take();
        let _ = s.terminal.take();
    }
    *epoch.assigned.get_mut() = 0;
    *epoch.state.get_mut() = CLOSED;
}

/// All identity, geometry, ownership and permit preflights precede this call.
/// ID exhaustion leaves the epoch unchanged; success has no fallible tail.
pub(crate) fn restart(epoch: &mut Epoch) -> Result<(), CreateError> {
    restart_with(epoch, &NEXT_GENERATION)
}

fn restart_with(epoch: &mut Epoch, next: &AtomicU64) -> Result<(), CreateError> {
    let id = allocate_id(next)?;
    epoch.id = id;
    *epoch.state.get_mut() = 0;
    *epoch.assigned.get_mut() = 0;
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_restart_with(epoch: &mut Epoch, next: &AtomicU64) -> Result<(), CreateError> {
    restart_with(epoch, next)
}

#[cfg(test)]
pub(crate) fn recycled_clean(epoch: &Epoch) -> bool {
    epoch.state.load(Ordering::Acquire) == CLOSED
        && epoch.assigned.load(Ordering::Acquire) == 0
        && epoch
            .functions
            .iter()
            .all(|f| f.retained.load(Ordering::Relaxed) == 0 && !f.closed.load(Ordering::Relaxed))
        && epoch
            .slots
            .iter()
            .all(|s| s.admission.get().is_none() && s.terminal.get().is_none())
}

#[cfg(test)]
pub(crate) fn epoch_state(epoch: &Epoch) -> (usize, usize) {
    (
        epoch.state.load(Ordering::Acquire),
        epoch.assigned.load(Ordering::Acquire),
    )
}

#[cfg(test)]
pub(crate) fn epoch_geometry(epoch: &Epoch) -> [(usize, usize, usize); 2] {
    [
        (
            epoch.functions.as_ptr() as usize,
            epoch.functions.len(),
            epoch.functions.capacity(),
        ),
        (
            epoch.slots.as_ptr() as usize,
            epoch.slots.len(),
            epoch.slots.capacity(),
        ),
    ]
}

/// Caller has already authenticated closed+zero and both unique Arc layers.
/// Infallible extraction; the old shell is dropped before reset, not republished.
/// Kept for the original extraction controls; production now retains the shell.
#[cfg(test)]
pub(crate) fn extract(epoch: &mut Epoch) -> RetiredStorage {
    RetiredStorage(Storage {
        config: epoch.config,
        functions: std::mem::take(&mut epoch.functions),
        slots: std::mem::take(&mut epoch.slots),
    })
}

#[cfg(test)]
impl RetiredStorage {
    pub(crate) fn reset(mut self) -> Storage {
        for f in &mut self.0.functions {
            *f.retained.get_mut() = 0;
            *f.closed.get_mut() = false;
        }
        for s in &mut self.0.slots {
            let _ = s.admission.take();
            let _ = s.terminal.take();
        }
        self.0
    }
}

#[cfg(test)]
pub(crate) mod allocation_probe {
    use super::CreateError;
    use std::cell::Cell;
    thread_local! {
        static PROBE: Cell<(usize, Option<usize>)> = const { Cell::new((0, None)) };
    }
    pub(crate) struct Guard((usize, Option<usize>));
    pub(crate) fn start(fail_at: Option<usize>) -> Guard {
        Guard(PROBE.replace((0, fail_at)))
    }
    pub(crate) fn calls() -> usize {
        PROBE.get().0
    }
    pub(super) fn before_reserve() -> Result<(), CreateError> {
        let (n, fail) = PROBE.get();
        PROBE.set((n + 1, fail));
        if fail == Some(n) {
            Err(CreateError::Allocation)
        } else {
            Ok(())
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            PROBE.set(self.0);
        }
    }
}

#[cfg(test)]
mod tests;
