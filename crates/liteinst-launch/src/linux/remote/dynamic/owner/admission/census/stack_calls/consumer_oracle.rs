//! Feature-only prepaid copies of genuine appended CALL rows. Historical
//! comparison never constructs a record, clears history, or reuses a deadline.
use super::super::runtime_stack::consumer_oracle::storage::{
    BufferIdentity, CensusConsumerError, ConsumerAllocationView, ConsumerBindingView,
    ConsumerProgress, checked_add, copy_state, require, state_bytes,
};
use super::*;

pub(in crate::linux::remote::dynamic::owner::admission::census) mod prefix_mirror;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CallHeader {
    address: usize,
    binding: Binding,
    id: PotentialCallId,
    before_allocation: BufferIdentity,
    buffer_allocation: BufferIdentity,
    allocation: PayloadProgress,
    settled_bytes: usize,
    allocated_bytes: usize,
}
impl CallHeader {
    fn actual(row: &PreparedCallRecord) -> Result<Self, CensusConsumerError> {
        row.require_filled()?;
        let before = row.before.as_ref().ok_or(CensusConsumerError::Incomplete)?;
        Ok(Self {
            address: std::ptr::from_ref(row) as usize,
            binding: row
                .binding
                .as_ref()
                .ok_or(CensusConsumerError::Incomplete)?
                .clone(),
            id: row.id.ok_or(CensusConsumerError::Incomplete)?,
            before_allocation: BufferIdentity::of(&before.xstate),
            buffer_allocation: BufferIdentity::of(&row.buffer),
            allocation: row.allocation,
            settled_bytes: row.settled_bytes,
            allocated_bytes: row.allocated_bytes()?,
        })
    }
}
pub(in crate::linux::remote::dynamic::owner::admission) struct PreparedCallObservation {
    allocation: ConsumerProgress,
    capture: ConsumerProgress,
    payload: usize,
    source_capacity: Option<usize>,
    header: Option<CallHeader>,
    before: Option<ObservedStop>,
    buffer: Vec<u8>,
    source: Vec<u8>,
    #[cfg(test)]
    allocation_fault: Option<tests::Fault>,
}
impl PreparedCallObservation {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            allocation: ConsumerProgress::default(),
            capture: ConsumerProgress::default(),
            payload: 0,
            source_capacity: None,
            header: None,
            before: None,
            buffer: Vec::new(),
            source: Vec::new(),
            #[cfg(test)]
            allocation_fault: None,
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn reservation_bytes(
        source_capacity: usize,
    ) -> Result<usize, CensusConsumerError> {
        require(source_capacity > 0)?;
        checked_add(
            checked_add(size_of::<Self>(), MAX_XSTATE_BYTES)?,
            source_capacity,
        )
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocate_payloads(
        &mut self,
        source_capacity: usize,
    ) -> Result<(), CensusConsumerError> {
        self.allocation.begin()?;
        let result = (|| {
            Self::reservation_bytes(source_capacity)?;
            require(
                self.payload == 0 && self.buffer.capacity() == 0 && self.source.capacity() == 0,
            )?;
            self.source_capacity = Some(source_capacity);
            let next = checked_add(self.payload, MAX_XSTATE_BYTES)?;
            #[cfg(test)]
            tests::before(self.allocation_fault, 0)?;
            self.buffer = exact_storage::empty_bytes(MAX_XSTATE_BYTES)?;
            self.payload = next;
            self.allocation.filled = 1;
            #[cfg(test)]
            tests::after(self.allocation_fault, 0);
            let next = checked_add(self.payload, source_capacity)?;
            #[cfg(test)]
            tests::before(self.allocation_fault, 1)?;
            self.source = exact_storage::empty_bytes(source_capacity)?;
            self.payload = next;
            self.allocation.filled = 2;
            #[cfg(test)]
            tests::after(self.allocation_fault, 1);
            self.allocation.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            self.allocation.fail(error);
        }
        result
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocated_bytes(
        &self,
    ) -> Result<usize, CensusConsumerError> {
        let payload = checked_add(
            state_bytes(&self.before, &self.buffer)?,
            self.source.capacity(),
        )?;
        require(
            payload == self.payload && self.source.capacity() <= self.source_capacity.unwrap_or(0),
        )?;
        checked_add(size_of::<Self>(), payload)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        self.allocation.abort();
        self.capture.abort();
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn call_id(
        &self,
    ) -> Option<PotentialCallId> {
        self.header.as_ref().map(|v| v.id)
    }
}
impl RecordedCall<'_> {
    pub(in crate::linux::remote::dynamic::owner::admission) fn copy_consumer_observation_into(
        &self,
        binding: &RuntimeStackBinding<'_, '_>,
        out: &mut PreparedCallObservation,
    ) -> Result<(), CensusConsumerError> {
        out.capture.begin()?;
        let result = (|| {
            out.allocation.require_complete()?;
            require(
                out.allocated_bytes()?
                    == PreparedCallObservation::reservation_bytes(
                        out.source_capacity.ok_or(CensusConsumerError::Incomplete)?,
                    )?,
            )?;
            // Authentic appended row and live immutable binding are required
            // before the first private opening effect. No supplied model can
            // construct RecordedCall or its opaque ID through this interface.
            self.require(binding)?;
            let header = CallHeader::actual(self.row)?;
            require(
                header.id == self.id()
                    && header.binding.operand.geometry.operation == StackOperation::DirectCall,
            )?;
            out.header = Some(header);
            out.capture.filled = 1;
            let source = binding.window().snapshot.bytes();
            require(out.source.is_empty() && source.len() <= out.source.capacity())?;
            out.source.extend_from_slice(source);
            out.capture.filled = 2;
            copy_state(
                self.row
                    .before
                    .as_ref()
                    .ok_or(CensusConsumerError::Incomplete)?,
                &mut out.before,
                &mut out.buffer,
            )?;
            out.capture.filled = 3;
            out.capture.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            out.capture.fail(error);
        }
        result
    }
}
impl RuntimeCallLedger {
    /// Actual retained prefix length; descriptive only, including failed runs.
    pub(in crate::linux::remote::dynamic::owner::admission) fn consumer_count(&self) -> usize {
        self.count
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_consumer_observation(
        &self,
        out: &PreparedCallObservation,
        sources: &PreparedInitialSources,
    ) -> Result<(), CensusConsumerError> {
        out.allocation.require_complete()?;
        out.capture.require_complete()?;
        let header = out.header.as_ref().ok_or(CensusConsumerError::Incomplete)?;
        self.require_slots()?;
        let index = header
            .id
            .serial
            .checked_sub(1)
            .ok_or(CensusConsumerError::Mismatch)?;
        require(index < self.count)?;
        let row = self
            .slots
            .as_deref()
            .and_then(|v| v.get(index))
            .and_then(Option::as_deref)
            .ok_or(CensusConsumerError::Incomplete)?;
        self.require_record(index, row)?;
        require(CallHeader::actual(row)? == *header && row.before.as_ref() == out.before.as_ref())?;
        header.binding.require_source(sources)?;
        let window = sources
            .window(header.binding.source.id.index())
            .ok_or(CensusConsumerError::Incomplete)?;
        require(window.snapshot.bytes() == out.source.as_slice())?;
        require(
            out.allocated_bytes()?
                == PreparedCallObservation::reservation_bytes(
                    out.source_capacity.ok_or(CensusConsumerError::Incomplete)?,
                )?,
        )
    }
}

pub(in crate::linux::remote::dynamic::owner::admission::census) fn temporary_bytes()
-> Result<usize, CensusConsumerError> {
    let mut total = checked_add(2 * size_of::<CallHeader>(), 2 * size_of::<ObservedStop>())?;
    for size in [
        2 * size_of::<Binding>(),
        3 * size_of::<BufferIdentity>(),
        2 * size_of::<ConsumerProgress>(),
        size_of::<CallPartialView<'_>>(),
        size_of::<CallHeaderView<'_>>(),
        size_of::<ConsumerBindingView<'_>>(),
        size_of::<ConsumerAllocationView>(),
        6 * size_of::<Result<(), CensusConsumerError>>(),
    ] {
        total = checked_add(total, size)?;
    }
    Ok(total)
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct CallHeaderView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) address: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) binding: ConsumerBindingView<'a>,
    pub(in crate::linux::remote::dynamic::owner::admission) id: PotentialCallId,
    pub(in crate::linux::remote::dynamic::owner::admission) before_allocation: BufferIdentity,
    pub(in crate::linux::remote::dynamic::owner::admission) buffer_allocation: BufferIdentity,
    pub(in crate::linux::remote::dynamic::owner::admission) allocation: ConsumerAllocationView,
    pub(in crate::linux::remote::dynamic::owner::admission) settled_bytes: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) allocated_bytes: usize,
}
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct CallPartialView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) address: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) copied_before_allocation:
        Option<BufferIdentity>,
    pub(in crate::linux::remote::dynamic::owner::admission) buffer_allocation: BufferIdentity,
    pub(in crate::linux::remote::dynamic::owner::admission) source_allocation: BufferIdentity,
    pub(in crate::linux::remote::dynamic::owner::admission) allocation: &'a ConsumerProgress,
    pub(in crate::linux::remote::dynamic::owner::admission) capture: &'a ConsumerProgress,
    pub(in crate::linux::remote::dynamic::owner::admission) payload: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) source_capacity: Option<usize>,
    pub(in crate::linux::remote::dynamic::owner::admission) header: Option<CallHeaderView<'a>>,
    pub(in crate::linux::remote::dynamic::owner::admission) before: Option<&'a ObservedStop>,
    pub(in crate::linux::remote::dynamic::owner::admission) buffer: &'a Vec<u8>,
    pub(in crate::linux::remote::dynamic::owner::admission) source: &'a Vec<u8>,
}
impl PreparedCallObservation {
    /// Valid even before allocation/capture or after an error/unwind. Vec::len
    /// is the initialized extent; spare capacity never masquerades as bytes.
    pub(in crate::linux::remote::dynamic::owner::admission) fn partial_view(
        &self,
    ) -> CallPartialView<'_> {
        CallPartialView {
            address: std::ptr::from_ref(self) as usize,
            copied_before_allocation: self
                .before
                .as_ref()
                .map(|value| BufferIdentity::of(&value.xstate)),
            buffer_allocation: BufferIdentity::of(&self.buffer),
            source_allocation: BufferIdentity::of(&self.source),
            allocation: &self.allocation,
            capture: &self.capture,
            payload: self.payload,
            source_capacity: self.source_capacity,
            header: self.header.as_ref().map(|header| CallHeaderView {
                address: header.address,
                binding: ConsumerBindingView::of(&header.binding),
                id: header.id,
                before_allocation: header.before_allocation,
                buffer_allocation: header.buffer_allocation,
                allocation: ConsumerAllocationView::of(header.allocation),
                settled_bytes: header.settled_bytes,
                allocated_bytes: header.allocated_bytes,
            }),
            before: self.before.as_ref(),
            buffer: &self.buffer,
            source: &self.source,
        }
    }
}
