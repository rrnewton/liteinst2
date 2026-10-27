//! Owning mirror of every initialized committed-copy or failed-copy prefix.
//! All capacity is installed under Q before dispatch; copying grants no permit.
use super::*;
pub(in crate::linux::remote::dynamic::owner::admission::census) mod state;
use state::StatePrefix;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq)]
struct StackHeader {
    address: usize,
    copied_allocations: [Option<BufferIdentity>; STATES],
    buffer_allocations: [BufferIdentity; STATES],
    allocation: ConsumerProgress,
    capture: ConsumerProgress,
    payload: usize,
    census: Option<CensusHeader>,
    start: Option<usize>,
    rows: [Option<RowHeader>; 7],
    evidence: Option<StackEvidence>,
    evidence_allocation: Option<(usize, usize)>,
    old_origin: Option<OriginHeader>,
    new_origin: Option<OriginHeader>,
    old_current_allocation: Option<BufferIdentity>,
    actual_allocations: [Option<BufferIdentity>; STATES],
}
impl StackHeader {
    fn of(source: &PreparedStackObservation) -> Result<Self, CensusConsumerError> {
        let StackPartialView {
            address,
            copied_allocations,
            buffer_allocations,
            allocation,
            capture,
            payload,
            census,
            start,
            rows,
            evidence,
            evidence_allocation,
            old_origin,
            new_origin,
            old_current_allocation,
            states: _,
            buffers: _,
            actual_allocations,
        } = source.partial_view();
        // Only the actual private fixed header is cloned. The complete public-
        // to-admission view is checked too; no authoritative Binding is built.
        let owned_evidence = source.evidence.clone();
        require(
            owned_evidence.as_ref().map(|value| StackEvidenceView {
                binding: value.binding.as_ref().map(ConsumerBindingView::of),
                trace: value.trace,
                words: value.words.as_ref(),
                call: value.call,
            }) == evidence,
        )?;
        Ok(Self {
            address,
            copied_allocations,
            buffer_allocations,
            allocation: *allocation,
            capture: *capture,
            payload,
            census: census.copied(),
            start,
            rows: *rows,
            evidence: owned_evidence,
            evidence_allocation,
            old_origin: old_origin.copied(),
            new_origin: new_origin.copied(),
            old_current_allocation,
            actual_allocations: *actual_allocations,
        })
    }
}
pub(in crate::linux::remote::dynamic::owner::admission) struct PreparedStackPrefixMirror {
    allocation: ConsumerProgress,
    capture: ConsumerProgress,
    payload: usize,
    header: Option<StackHeader>,
    states: [StatePrefix; STATES],
    #[cfg(test)]
    allocation_fault: Option<tests::Fault>,
}
impl PreparedStackPrefixMirror {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            allocation: ConsumerProgress::default(),
            capture: ConsumerProgress::default(),
            payload: 0,
            header: None,
            states: std::array::from_fn(|_| StatePrefix::empty()),
            #[cfg(test)]
            allocation_fault: None,
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn reservation_bytes()
    -> Result<usize, CensusConsumerError> {
        checked_add(
            size_of::<Self>(),
            STATES
                .checked_mul(MAX_XSTATE_BYTES)
                .ok_or(CensusConsumerError::Capacity)?,
        )
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocate_payloads(
        &mut self,
    ) -> Result<(), CensusConsumerError> {
        self.allocation.begin()?;
        let result = (|| {
            Self::reservation_bytes()?;
            for index in 0..STATES {
                let next = checked_add(self.payload, MAX_XSTATE_BYTES)?;
                #[cfg(test)]
                tests::before(self.allocation_fault, index)?;
                self.states[index].allocate()?;
                self.payload = next;
                self.allocation.filled = index + 1;
                #[cfg(test)]
                tests::after(self.allocation_fault, index);
            }
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
        let mut payload = 0;
        for state in &self.states {
            payload = checked_add(payload, state.allocated_bytes()?)?;
        }
        require(payload == self.payload)?;
        checked_add(size_of::<Self>(), payload)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn capture(
        &mut self,
        source: &PreparedStackObservation,
    ) -> Result<(), CensusConsumerError> {
        self.capture.begin()?;
        let result = (|| {
            self.allocation.require_complete()?;
            require(self.allocated_bytes()? == Self::reservation_bytes()?)?;
            self.header = Some(StackHeader::of(source)?);
            self.capture.filled = 1;
            let view = source.partial_view();
            for index in 0..STATES {
                self.states[index].capture(view.states[index].as_ref(), &view.buffers[index])?;
                self.capture.filled = index + 2;
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
        source: &PreparedStackObservation,
    ) -> Result<(), CensusConsumerError> {
        self.allocation.require_complete()?;
        self.capture.require_complete()?;
        require(self.allocated_bytes()? == Self::reservation_bytes()?)?;
        require(self.header.as_ref() == Some(&StackHeader::of(source)?))?;
        let view = source.partial_view();
        for index in 0..STATES {
            self.states[index]
                .require_preserved(view.states[index].as_ref(), &view.buffers[index])?;
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
pub(in crate::linux::remote::dynamic::owner::admission) fn stack_prefix_mirror_temporary_bytes()
-> Result<usize, CensusConsumerError> {
    let mut total = state::temporary_bytes()?;
    for size in [
        size_of::<PreparedStackPrefixMirror>(),
        size_of::<[StatePrefix; STATES]>(),
        2 * size_of::<StackHeader>(),
        2 * size_of::<StackEvidence>(),
        2 * size_of::<Binding>(),
        3 * size_of::<StackPartialView<'_>>(),
        2 * size_of::<StackEvidenceView<'_>>(),
        2 * size_of::<ConsumerBindingView<'_>>(),
        size_of::<storage::ConsumerSourceView>(),
        size_of::<storage::ConsumerProfileView<'_>>(),
        4 * size_of::<ConsumerProgress>(),
        size_of::<std::ops::Range<usize>>(),
        size_of::<std::slice::Iter<'_, StatePrefix>>(),
        size_of::<[usize; 8]>(),
        8 * size_of::<Result<(), CensusConsumerError>>(),
        2 * size_of::<Result<StackHeader, CensusConsumerError>>(),
        3 * size_of::<Result<usize, CensusConsumerError>>(),
        // This calculator's expanded term array, iterator and fixed control locals.
        size_of::<[usize; 18]>()
            + size_of::<std::array::IntoIter<usize, 18>>()
            + 4 * size_of::<usize>()
            + 2 * size_of::<Option<usize>>()
            + 2 * size_of::<Result<usize, CensusConsumerError>>()
            + size_of::<CensusConsumerError>(),
    ] {
        total = checked_add(total, size)?;
    }
    Ok(total)
}
