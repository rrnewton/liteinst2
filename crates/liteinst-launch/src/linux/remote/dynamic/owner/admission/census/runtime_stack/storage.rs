//! Exact safe owning allocation and monotone settlement. No native operations.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) enum StorageFailure {
    Error(CensusError),
    Aborted,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct PayloadProgress {
    pub(in crate::linux::remote::dynamic::owner::admission::census) started: bool,
    pub(in crate::linux::remote::dynamic::owner::admission::census) complete: bool,
    pub(in crate::linux::remote::dynamic::owner::admission::census) payload: usize,
    pub(in crate::linux::remote::dynamic::owner::admission::census) failure: Option<StorageFailure>,
}
impl PayloadProgress {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn begin(
        &mut self,
    ) -> Result<(), CensusError> {
        if self.started || self.failure.is_some() {
            return Err(CensusError::InvalidConsumption);
        }
        self.started = true;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn fail(
        &mut self,
        error: CensusError,
    ) {
        if self.failure.is_none() {
            self.failure = Some(StorageFailure::Error(error));
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn abort(&mut self) {
        if self.failure.is_none() {
            self.failure = Some(StorageFailure::Aborted);
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn require_complete(
        &self,
    ) -> Result<(), CensusError> {
        if !self.started || !self.complete || self.failure.is_some() {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(())
    }
}
impl PreparedStackCensus {
    pub(in super::super::super) fn empty() -> Self {
        Self {
            binding: None,
            before: None,
            buffers: std::array::from_fn(|_| Vec::new()),
            evidence: None,
            allocation: PayloadProgress::default(),
            settled_bytes: 0,
            prepared: false,
            committed: false,
            #[cfg(test)]
            allocation_fail_before: None,
            #[cfg(test)]
            allocation_panic_after: None,
        }
    }
    pub(in super::super::super) fn allocate_payloads(&mut self) -> Result<(), CensusError> {
        #[cfg(not(test))]
        {
            self.allocate_with(|_| Ok(()), |_| {})
        }
        #[cfg(test)]
        {
            let before = self.allocation_fail_before;
            let after = self.allocation_panic_after;
            self.allocate_with(
                |index| {
                    if before == Some(index) {
                        Err(CensusError::Allocation)
                    } else {
                        Ok(())
                    }
                },
                |index| {
                    if after == Some(index) {
                        std::panic::panic_any(0x5354_434e_u32);
                    }
                },
            )
        }
    }
    pub(super) fn allocate_with(
        &mut self,
        mut before: impl FnMut(usize) -> Result<(), CensusError>,
        mut after: impl FnMut(usize),
    ) -> Result<(), CensusError> {
        self.allocation.begin()?;
        let result = (|| {
            for index in 0..STATES {
                let next = add(self.allocation.payload, MAX_XSTATE_BYTES)?;
                before(index)?;
                let value =
                    exact_storage::empty_bytes(MAX_XSTATE_BYTES).map_err(allocation_error)?;
                self.buffers[index] = value;
                self.allocation.payload = next;
                after(index);
            }
            let next = add(self.allocation.payload, size_of::<StackEvidence>())?;
            before(STATES)?;
            let value = exact_storage::one(StackEvidence {
                binding: None,
                trace: None,
                words: None,
                call: None,
            })
            .map_err(allocation_error)?;
            self.evidence = Some(value);
            self.allocation.payload = next;
            after(STATES);
            self.allocation.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            self.allocation.fail(error);
        }
        result
    }
    pub(in super::super::super) fn allocated_bytes(&self) -> Result<usize, CensusError> {
        let mut bytes = size_of::<Self>();
        if let Some(before) = &self.before {
            bytes = add(bytes, before.xstate.capacity())?;
        }
        for buffer in &self.buffers {
            bytes = add(bytes, buffer.capacity())?;
        }
        if let Some(evidence) = &self.evidence {
            bytes = add(bytes, mul(evidence.len(), size_of::<StackEvidence>())?)?;
        }
        Ok(bytes)
    }
    pub(in super::super::super) fn mark_aborted(&mut self) {
        self.allocation.abort();
    }
    /// Caller invokes on Ok/Err/caught unwind before another read/effect/cleanup.
    /// Updating the settled marker cannot precede the real account mutation.
    pub(in super::super::super) fn settle_storage(
        &mut self,
        census: &mut ResumeCensus,
        reservation: Reservation,
    ) -> Result<(), CensusError> {
        if self.committed {
            return Err(CensusError::InvalidConsumption);
        }
        let actual = self.allocated_bytes()?;
        let delta = actual
            .checked_sub(self.settled_bytes)
            .ok_or(CensusError::Capacity)?;
        census.account_external(
            reservation,
            BudgetCharge {
                source_fact_bytes: delta,
                ..BudgetCharge::default()
            },
        )?;
        self.settled_bytes = actual;
        Ok(())
    }
    pub(in super::super::super) fn remaining_charge(&self) -> Result<BudgetCharge, CensusError> {
        if !self.prepared || self.committed {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(BudgetCharge {
            source_fact_bytes: fixed_commit_bytes()?,
            origins: 1,
            witnesses: WITNESSES,
            ..BudgetCharge::default()
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn require_allocated(
        &self,
    ) -> Result<(), CensusError> {
        self.allocation.require_complete()?;
        if self.allocation.payload != STATES * MAX_XSTATE_BYTES + size_of::<StackEvidence>()
            || self.before.is_some()
            || self
                .buffers
                .iter()
                .any(|v| v.capacity() != MAX_XSTATE_BYTES || !v.is_empty())
            || self.evidence.as_ref().is_none_or(|v| {
                v.len() != 1
                    || v[0].binding.is_some()
                    || v[0].trace.is_some()
                    || v[0].words.is_some()
                    || v[0].call.is_some()
            })
        {
            return Err(CensusError::Capacity);
        }
        Ok(())
    }
}
