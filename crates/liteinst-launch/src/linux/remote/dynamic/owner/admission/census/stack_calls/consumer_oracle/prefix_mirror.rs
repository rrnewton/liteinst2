//! Exact optional CALL-copy prefix, retained across physical cleanup and
//! same-Box TLS retirement. None is absence, never a completed CALL claim.
use super::super::super::runtime_stack::consumer_oracle::prefix_mirror::state::{
    self, StatePrefix,
};
use super::*;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CallPrefixHeader {
    address: usize,
    copied_before_allocation: Option<BufferIdentity>,
    buffer_allocation: BufferIdentity,
    source_allocation: BufferIdentity,
    allocation: ConsumerProgress,
    capture: ConsumerProgress,
    payload: usize,
    source_capacity: Option<usize>,
    header: Option<CallHeader>,
}
impl CallPrefixHeader {
    fn of(source: &PreparedCallObservation) -> Result<Self, CensusConsumerError> {
        let CallPartialView {
            address,
            copied_before_allocation,
            buffer_allocation,
            source_allocation,
            allocation,
            capture,
            payload,
            source_capacity,
            header,
            before: _,
            buffer: _,
            source: _,
        } = source.partial_view();
        let owned = source.header.clone();
        require(
            owned.as_ref().map(|value| CallHeaderView {
                address: value.address,
                binding: ConsumerBindingView::of(&value.binding),
                id: value.id,
                before_allocation: value.before_allocation,
                buffer_allocation: value.buffer_allocation,
                allocation: ConsumerAllocationView::of(value.allocation),
                settled_bytes: value.settled_bytes,
                allocated_bytes: value.allocated_bytes,
            }) == header,
        )?;
        Ok(Self {
            address,
            copied_before_allocation,
            buffer_allocation,
            source_allocation,
            allocation: *allocation,
            capture: *capture,
            payload,
            source_capacity,
            header: owned,
        })
    }
}
pub(in crate::linux::remote::dynamic::owner::admission) struct PreparedCallPrefixMirror {
    allocation: ConsumerProgress,
    capture: ConsumerProgress,
    payload: usize,
    source_capacity: Option<usize>,
    present: Option<bool>,
    header: Option<CallPrefixHeader>,
    before: StatePrefix,
    source: Vec<u8>,
    #[cfg(test)]
    allocation_fault: Option<tests::Fault>,
}
impl PreparedCallPrefixMirror {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            allocation: ConsumerProgress::default(),
            capture: ConsumerProgress::default(),
            payload: 0,
            source_capacity: None,
            present: None,
            header: None,
            before: StatePrefix::empty(),
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
            require(self.payload == 0 && self.source.capacity() == 0)?;
            self.source_capacity = Some(source_capacity);
            let next = checked_add(self.payload, MAX_XSTATE_BYTES)?;
            #[cfg(test)]
            tests::before(self.allocation_fault, 0)?;
            self.before.allocate()?;
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
        let payload = checked_add(self.before.allocated_bytes()?, self.source.capacity())?;
        require(
            payload == self.payload && self.source.capacity() <= self.source_capacity.unwrap_or(0),
        )?;
        checked_add(size_of::<Self>(), payload)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn capture(
        &mut self,
        source: Option<&PreparedCallObservation>,
    ) -> Result<(), CensusConsumerError> {
        self.capture.begin()?;
        let result = (|| {
            self.allocation.require_complete()?;
            require(
                self.allocated_bytes()?
                    == Self::reservation_bytes(
                        self.source_capacity
                            .ok_or(CensusConsumerError::Incomplete)?,
                    )?,
            )?;
            self.present = Some(source.is_some());
            self.capture.filled = 1;
            if let Some(source) = source {
                self.header = Some(CallPrefixHeader::of(source)?);
                self.capture.filled = 2;
                let view = source.partial_view();
                require(
                    view.source.capacity() <= self.source.capacity()
                        && view.source.len() <= self.source.capacity(),
                )?;
                self.source.extend_from_slice(view.source);
                self.capture.filled = 3;
                self.before.capture(view.before, view.buffer)?;
                self.capture.filled = 4;
            }
            self.capture.complete = true;
            Ok(())
        })();
        if let Err(error) = result {
            self.capture.fail(error);
        }
        result
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_preserved(
        &self,
        source: Option<&PreparedCallObservation>,
    ) -> Result<(), CensusConsumerError> {
        self.allocation.require_complete()?;
        self.capture.require_complete()?;
        require(
            self.allocated_bytes()?
                == Self::reservation_bytes(
                    self.source_capacity
                        .ok_or(CensusConsumerError::Incomplete)?,
                )?,
        )?;
        require(self.present == Some(source.is_some()))?;
        if let Some(source) = source {
            require(self.header.as_ref() == Some(&CallPrefixHeader::of(source)?))?;
            let view = source.partial_view();
            require(self.source.as_slice() == view.source.as_slice())?;
            self.before.require_preserved(view.before, view.buffer)?;
        } else {
            require(self.header.is_none() && self.source.is_empty())?;
        }
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        self.allocation.abort();
        self.capture.abort();
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn progress(
        &self,
    ) -> (&ConsumerProgress, &ConsumerProgress) {
        (&self.allocation, &self.capture)
    }
}
pub(in crate::linux::remote::dynamic::owner::admission) fn call_prefix_mirror_temporary_bytes()
-> Result<usize, CensusConsumerError> {
    let mut total = state::temporary_bytes()?;
    for size in [
        size_of::<PreparedCallPrefixMirror>(),
        size_of::<StatePrefix>(),
        2 * size_of::<CallPrefixHeader>(),
        2 * size_of::<CallHeader>(),
        2 * size_of::<Binding>(),
        3 * size_of::<CallPartialView<'_>>(),
        2 * size_of::<CallHeaderView<'_>>(),
        2 * size_of::<ConsumerBindingView<'_>>(),
        4 * size_of::<ConsumerProgress>(),
        4 * size_of::<Option<&PreparedCallObservation>>(),
        4 * size_of::<&[u8]>(),
        6 * size_of::<usize>(),
        8 * size_of::<Result<(), CensusConsumerError>>(),
        2 * size_of::<Result<CallPrefixHeader, CensusConsumerError>>(),
        3 * size_of::<Result<usize, CensusConsumerError>>(),
        // This calculator's expanded term array, iterator and fixed control locals.
        size_of::<[usize; 16]>()
            + size_of::<std::array::IntoIter<usize, 16>>()
            + 4 * size_of::<usize>()
            + 2 * size_of::<Option<usize>>()
            + 2 * size_of::<Result<usize, CensusConsumerError>>()
            + size_of::<CensusConsumerError>(),
    ] {
        total = checked_add(total, size)?;
    }
    Ok(total)
}
