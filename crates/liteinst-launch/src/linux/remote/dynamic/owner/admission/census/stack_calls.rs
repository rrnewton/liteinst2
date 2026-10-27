//! Append-only potential CALL returns. A row is a conservative continuation
//! record, never a source head, native permit, or completed execution claim.
use super::super::exact_storage;
use super::super::runtime::stack::RuntimeStackBinding;
use super::super::runtime_capture::PreparedInitialSources;
use super::super::runtime_stack::operand::StackOperation;
use super::runtime_stack::binding::{Binding, validate_operand};
use super::runtime_stack::storage::PayloadProgress;
use super::runtime_stack::{add, allocation_error, copy_observed, mul};
use super::*;
use std::mem::size_of;
use std::time::Instant;

#[cfg(feature = "dev-owned-stack-consumer-oracle")]
pub(in crate::linux::remote::dynamic::owner::admission::census) mod consumer_oracle;
#[cfg(test)]
pub(super) mod native_oracle;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct PotentialCallId {
    census: u64,
    session: u64,
    // Address of the permanent fixed slot allocation, compared only. It is
    // never dereferenced and does not escape this owned lifetime as authority.
    ledger: usize,
    serial: usize,
}

pub(in super::super) struct PreparedCallRecord {
    binding: Option<Binding>,
    before: Option<ObservedStop>,
    buffer: Vec<u8>,
    allocation: PayloadProgress,
    settled_bytes: usize,
    id: Option<PotentialCallId>,
    #[cfg(test)]
    allocation_fail_before: Option<usize>,
    #[cfg(test)]
    allocation_panic_after: Option<usize>,
}

/// Non-Clone borrow returned only after the same complete Box was appended.
/// The native producer consumes this temporary borrow before original release.
pub(in super::super) struct RecordedCall<'a> {
    row: &'a PreparedCallRecord,
}
impl RecordedCall<'_> {
    pub(in super::super) fn id(&self) -> PotentialCallId {
        self.row.id.expect("appended potential CALL identity")
    }
    pub(in super::super) fn require(
        &self,
        actual: &RuntimeStackBinding<'_, '_>,
    ) -> Result<(), CensusError> {
        let binding = self
            .row
            .binding
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        let before = self
            .row
            .before
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        self.row.require_filled()?;
        if self.row.id.is_none() || Instant::now() >= binding.until {
            return Err(CensusError::StaleObservation);
        }
        binding.require_actual(actual, before)
    }
}

/// Installed during opt-in startup. Slots never grow, shrink, remove or refund.
/// The startup owner reserves/settles this exact slot payload separately; each
/// CALL Box and its MAX state were already charged in its originating attempt.
pub(in super::super) struct RuntimeCallLedger {
    slots: Option<Box<[Option<Box<PreparedCallRecord>>]>>,
    allocation: PayloadProgress,
    count: usize,
    identity: Option<(u64, u64)>,
}
impl RuntimeCallLedger {
    pub(in super::super) fn empty() -> Self {
        Self {
            slots: None,
            allocation: PayloadProgress::default(),
            count: 0,
            identity: None,
        }
    }
    pub(in super::super) fn reservation_bytes(records: usize) -> Result<usize, CensusError> {
        if records == 0 {
            return Err(CensusError::Capacity);
        }
        add(
            size_of::<Self>(),
            mul(records, size_of::<Option<Box<PreparedCallRecord>>>())?,
        )
    }
    pub(in super::super) fn allocate_payloads(
        &mut self,
        records: usize,
    ) -> Result<(), CensusError> {
        self.allocation.begin()?;
        let result = (|| {
            let payload = Self::reservation_bytes(records)? - size_of::<Self>();
            let slots = exact_storage::empty_slots(records).map_err(allocation_error)?;
            self.slots = Some(slots);
            self.allocation.payload = payload;
            self.allocation.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            self.allocation.fail(error);
        }
        result
    }
    pub(in super::super) fn mark_aborted(&mut self) {
        self.allocation.abort();
    }
    pub(in super::super) fn allocated_bytes(&self) -> Result<usize, CensusError> {
        let mut bytes = size_of::<Self>();
        if let Some(slots) = &self.slots {
            bytes = add(
                bytes,
                mul(slots.len(), size_of::<Option<Box<PreparedCallRecord>>>())?,
            )?;
            for record in slots.iter().flatten() {
                bytes = add(bytes, record.allocated_bytes()?)?;
            }
        }
        Ok(bytes)
    }
    fn require_slots(&self) -> Result<&[Option<Box<PreparedCallRecord>>], CensusError> {
        self.allocation.require_complete()?;
        let slots = self.slots.as_deref().ok_or(CensusError::Capacity)?;
        if slots.is_empty()
            || self.count > slots.len()
            || self.allocation.payload
                != mul(slots.len(), size_of::<Option<Box<PreparedCallRecord>>>())?
            || slots[..self.count].iter().any(Option::is_none)
            || slots[self.count..].iter().any(Option::is_some)
            || (self.count == 0) != self.identity.is_none()
        {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(slots)
    }
    #[cfg(test)]
    pub(super) fn prepare_model_test(
        &self,
        census: &ResumeCensus,
        binding: Binding,
        prepared: &mut PreparedCallRecord,
    ) -> Result<(), CensusError> {
        self.prepare_model(census, binding, prepared)
    }
    #[cfg(test)]
    pub(super) fn append_model_test<'a>(
        &'a mut self,
        census: &ResumeCensus,
        prepared: &mut Option<Box<PreparedCallRecord>>,
    ) -> Result<RecordedCall<'a>, CensusError> {
        self.append_model(census, prepared)
    }
    #[cfg(test)]
    pub(super) fn count(&self) -> usize {
        self.count
    }
    pub(in super::super) fn prepare(
        &self,
        census: &ResumeCensus,
        reservation: Reservation,
        actual: &RuntimeStackBinding<'_, '_>,
        prepared: &mut PreparedCallRecord,
    ) -> Result<(), CensusError> {
        let binding = Binding::from_actual(census, reservation, actual)?;
        self.prepare_model(census, binding, prepared)
    }
    fn prepare_model(
        &self,
        census: &ResumeCensus,
        binding: Binding,
        prepared: &mut PreparedCallRecord,
    ) -> Result<(), CensusError> {
        let slots = self.require_slots()?;
        binding.validate_current(census)?;
        prepared.require_empty_allocated()?;
        if slots.len() != census.limits.origins
            || self.count == slots.len()
            || self
                .identity
                .is_some_and(|id| id != (census.identity, census.session))
            || binding.operand.geometry.operation != StackOperation::DirectCall
        {
            return Err(CensusError::InvalidConsumption);
        }
        let before = census.current_observation(binding.origin)?;
        prepared.before = Some(copy_observed(before, std::mem::take(&mut prepared.buffer)));
        prepared.binding = Some(binding);
        Ok(())
    }
    pub(in super::super) fn append_before_opening<'a>(
        &'a mut self,
        census: &ResumeCensus,
        prepared: &mut Option<Box<PreparedCallRecord>>,
        actual: &RuntimeStackBinding<'_, '_>,
    ) -> Result<RecordedCall<'a>, CensusError> {
        let record = prepared.as_deref().ok_or(CensusError::InvalidConsumption)?;
        record
            .binding
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?
            .require_actual(
                actual,
                record
                    .before
                    .as_ref()
                    .ok_or(CensusError::InvalidConsumption)?,
            )?;
        self.append_model(census, prepared)
    }
    fn append_model<'a>(
        &'a mut self,
        census: &ResumeCensus,
        prepared: &mut Option<Box<PreparedCallRecord>>,
    ) -> Result<RecordedCall<'a>, CensusError> {
        let slots = self.require_slots()?;
        let record = prepared.as_deref().ok_or(CensusError::InvalidConsumption)?;
        record.require_filled()?;
        let binding = record
            .binding
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        binding.validate_current(census)?;
        if record.id.is_some()
            || slots.len() != census.limits.origins
            || self.count == slots.len()
            || record.before.as_ref() != Some(census.current_observation(binding.origin)?)
            || self
                .identity
                .is_some_and(|id| id != (census.identity, census.session))
        {
            return Err(CensusError::StaleObservation);
        }
        let next = self.count.checked_add(1).ok_or(CensusError::Capacity)?;
        let id = PotentialCallId {
            census: census.identity,
            session: census.session,
            ledger: slots.as_ptr() as usize,
            serial: next,
        };
        // Validation ends here. Move the same Box into its existing empty slot;
        // no allocation, callback, fallible operation, or debit follows the take.
        let mut record = prepared.take().expect("validated CALL owner");
        record.id = Some(id);
        let slots = self.slots.as_mut().expect("allocated CALL slots");
        slots[self.count] = Some(record);
        self.count = next;
        self.identity = Some((census.identity, census.session));
        Ok(RecordedCall {
            row: slots[next - 1].as_deref().expect("appended CALL"),
        })
    }
    pub(in super::super) fn audit(
        &self,
        sources: &PreparedInitialSources,
    ) -> Result<(), CensusError> {
        let slots = self.require_slots()?;
        for (index, record) in slots[..self.count].iter().enumerate() {
            let record = record.as_deref().ok_or(CensusError::InvalidConsumption)?;
            self.require_record(index, record)?;
            record
                .binding
                .as_ref()
                .ok_or(CensusError::InvalidConsumption)?
                .require_source(sources)?;
        }
        Ok(())
    }
    fn require_record(&self, index: usize, record: &PreparedCallRecord) -> Result<(), CensusError> {
        record.require_filled()?;
        let (census, session) = self.identity.ok_or(CensusError::IdentityMismatch)?;
        let slots = self.slots.as_deref().ok_or(CensusError::Capacity)?;
        let id = PotentialCallId {
            census,
            session,
            ledger: slots.as_ptr() as usize,
            serial: index + 1,
        };
        let binding = record
            .binding
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        let before = record
            .before
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        if record.id != Some(id)
            || binding.census != census
            || binding.execution.session != session
            || before.token.session != session
            || before.phase != StopPhase::UserCheckpoint
            || before.signal.is_some()
            || before.task.generation != 0
            || binding.source.id.identity().generation != 0
        {
            return Err(CensusError::IdentityMismatch);
        }
        // Historical deadlines are retained exactly; expiration cannot delete
        // conservative return rows. Only a new release checks Instant::now().
        validate_operand(&binding.operand, &binding.profile, before)
    }
    pub(super) fn require_completed_call(
        &self,
        id: Option<PotentialCallId>,
        binding: &Binding,
        before: &ObservedStop,
    ) -> Result<(), CensusError> {
        let slots = self.require_slots()?;
        if binding.operand.geometry.operation == StackOperation::Return {
            if id.is_some() {
                return Err(CensusError::InvalidConsumption);
            }
            return Ok(());
        }
        let id = id.ok_or(CensusError::InvalidConsumption)?;
        let index = id
            .serial
            .checked_sub(1)
            .ok_or(CensusError::IdentityMismatch)?;
        let record = slots
            .get(index)
            .and_then(Option::as_deref)
            .ok_or(CensusError::IdentityMismatch)?;
        if index >= self.count {
            return Err(CensusError::IdentityMismatch);
        }
        self.require_record(index, record)?;
        if record.id != Some(id)
            || record.binding.as_ref() != Some(binding)
            || record.before.as_ref() != Some(before)
        {
            return Err(CensusError::InvalidConsumption);
        }
        Ok(())
    }
}

impl PreparedCallRecord {
    pub(in super::super) fn empty() -> Self {
        Self {
            binding: None,
            before: None,
            buffer: Vec::new(),
            allocation: PayloadProgress::default(),
            settled_bytes: 0,
            id: None,
            #[cfg(test)]
            allocation_fail_before: None,
            #[cfg(test)]
            allocation_panic_after: None,
        }
    }
    pub(in super::super) fn reservation_bytes() -> Result<usize, CensusError> {
        add(size_of::<Self>(), MAX_XSTATE_BYTES)
    }
    pub(in super::super) fn allocate_payloads(&mut self) -> Result<(), CensusError> {
        #[cfg(not(test))]
        {
            self.allocate_with(|| Ok(()), || {})
        }
        #[cfg(test)]
        {
            let before = self.allocation_fail_before;
            let after = self.allocation_panic_after;
            self.allocate_with(
                || {
                    if before == Some(0) {
                        Err(CensusError::Allocation)
                    } else {
                        Ok(())
                    }
                },
                || {
                    if after == Some(0) {
                        std::panic::panic_any(0x5343_414c_u32);
                    }
                },
            )
        }
    }
    fn allocate_with(
        &mut self,
        before: impl FnOnce() -> Result<(), CensusError>,
        after: impl FnOnce(),
    ) -> Result<(), CensusError> {
        self.allocation.begin()?;
        let result = (|| {
            before()?;
            let value = exact_storage::empty_bytes(MAX_XSTATE_BYTES).map_err(allocation_error)?;
            self.buffer = value;
            self.allocation.payload = MAX_XSTATE_BYTES;
            after();
            self.allocation.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            self.allocation.fail(error);
        }
        result
    }
    pub(in super::super) fn mark_aborted(&mut self) {
        self.allocation.abort();
    }
    pub(in super::super) fn allocated_bytes(&self) -> Result<usize, CensusError> {
        add(
            size_of::<Self>(),
            add(
                self.buffer.capacity(),
                self.before.as_ref().map_or(0, |v| v.xstate.capacity()),
            )?,
        )
    }
    pub(in super::super) fn settle_storage(
        &mut self,
        census: &mut ResumeCensus,
        reservation: Reservation,
    ) -> Result<(), CensusError> {
        if self.id.is_some() {
            return Err(CensusError::InvalidConsumption);
        }
        let bytes = self.allocated_bytes()?;
        let delta = bytes
            .checked_sub(self.settled_bytes)
            .ok_or(CensusError::Capacity)?;
        census.account_external(
            reservation,
            BudgetCharge {
                source_fact_bytes: delta,
                ..BudgetCharge::default()
            },
        )?;
        self.settled_bytes = bytes;
        Ok(())
    }
    fn require_empty_allocated(&self) -> Result<(), CensusError> {
        self.allocation.require_complete()?;
        if self.binding.is_some()
            || self.before.is_some()
            || self.id.is_some()
            || !self.buffer.is_empty()
            || self.buffer.capacity() != MAX_XSTATE_BYTES
            || self.allocation.payload != MAX_XSTATE_BYTES
            || self.settled_bytes != Self::reservation_bytes()?
        {
            return Err(CensusError::Capacity);
        }
        Ok(())
    }
    fn require_filled(&self) -> Result<(), CensusError> {
        self.allocation.require_complete()?;
        let binding = self
            .binding
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        let before = self
            .before
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        if binding.operand.geometry.operation != StackOperation::DirectCall
            || self.buffer.capacity() != 0
            || !self.buffer.is_empty()
            || before.xstate.capacity() != MAX_XSTATE_BYTES
            || !(576..MAX_XSTATE_BYTES).contains(&before.xstate.len())
            || self.allocation.payload != MAX_XSTATE_BYTES
            || self.settled_bytes != Self::reservation_bytes()?
        {
            return Err(CensusError::InvalidConsumption);
        }
        validate_operand(&binding.operand, &binding.profile, before)
    }
}
