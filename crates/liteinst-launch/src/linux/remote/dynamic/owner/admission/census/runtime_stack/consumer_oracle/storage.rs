//! Exact installed diagnostic copies. No native authority and no census mutation.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum CensusConsumerError {
    Capacity,
    Allocation,
    Reused,
    Incomplete,
    Mismatch,
    Aborted,
    Census(CensusError),
}
impl From<CensusError> for CensusConsumerError {
    fn from(value: CensusError) -> Self {
        Self::Census(value)
    }
}
impl From<exact_storage::AllocationError> for CensusConsumerError {
    fn from(value: exact_storage::AllocationError) -> Self {
        match value {
            exact_storage::AllocationError::Capacity => Self::Capacity,
            exact_storage::AllocationError::Allocation => Self::Allocation,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ConsumerProgress {
    pub(in crate::linux::remote::dynamic::owner::admission) started: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) complete: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) filled: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) first_failure:
        Option<CensusConsumerError>,
}
impl ConsumerProgress {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn begin(
        &mut self,
    ) -> Result<(), CensusConsumerError> {
        if *self != Self::default() {
            return Err(CensusConsumerError::Reused);
        }
        self.started = true;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn fail(
        &mut self,
        error: CensusConsumerError,
    ) {
        self.first_failure.get_or_insert(error);
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn abort(&mut self) {
        if self.started && !self.complete {
            self.fail(CensusConsumerError::Aborted);
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn require_complete(
        &self,
    ) -> Result<(), CensusConsumerError> {
        if !self.started || !self.complete || self.first_failure.is_some() {
            return Err(CensusConsumerError::Incomplete);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct BufferIdentity {
    pub(in crate::linux::remote::dynamic::owner::admission) pointer: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) length: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) capacity: usize,
}
impl BufferIdentity {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn of(value: &Vec<u8>) -> Self {
        Self {
            pointer: value.as_ptr() as usize,
            length: value.len(),
            capacity: value.capacity(),
        }
    }
}
pub(in crate::linux::remote::dynamic::owner::admission::census) fn checked_add(
    a: usize,
    b: usize,
) -> Result<usize, CensusConsumerError> {
    a.checked_add(b).ok_or(CensusConsumerError::Capacity)
}
pub(in crate::linux::remote::dynamic::owner::admission::census) fn require(
    value: bool,
) -> Result<(), CensusConsumerError> {
    if value {
        Ok(())
    } else {
        Err(CensusConsumerError::Mismatch)
    }
}
pub(in crate::linux::remote::dynamic::owner::admission::census) fn copy_state(
    source: &ObservedStop,
    destination: &mut Option<ObservedStop>,
    buffer: &mut Vec<u8>,
) -> Result<(), CensusConsumerError> {
    require(destination.is_none() && buffer.is_empty() && buffer.capacity() == MAX_XSTATE_BYTES)?;
    require(
        (576..MAX_XSTATE_BYTES).contains(&source.xstate.len())
            && source.xstate.capacity() == MAX_XSTATE_BYTES,
    )?;
    // Every bound is checked before moving the exact buffer. The fixed metadata
    // Clone operations contain no allocation; extend cannot exceed capacity.
    *destination = Some(copy_observed(source, std::mem::take(buffer)));
    Ok(())
}
pub(in crate::linux::remote::dynamic::owner::admission::census) fn state_bytes(
    state: &Option<ObservedStop>,
    buffer: &Vec<u8>,
) -> Result<usize, CensusConsumerError> {
    let used = state.as_ref().map_or(0, |v| v.xstate.capacity());
    require(
        matches!(buffer.capacity(), 0 | MAX_XSTATE_BYTES) && matches!(used, 0 | MAX_XSTATE_BYTES),
    )?;
    let total = checked_add(buffer.capacity(), used)?;
    require(total <= MAX_XSTATE_BYTES)?;
    Ok(total)
}

/// Fixed metadata projections borrow the actual copied Binding; constructing a
/// view manually grants no authority and cannot be fed into census production.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ConsumerSourceView {
    pub(in crate::linux::remote::dynamic::owner::admission) id: SourceWindowId,
    pub(in crate::linux::remote::dynamic::owner::admission) initial:
        super::super::super::super::source_identity::InitialSourceVma,
    pub(in crate::linux::remote::dynamic::owner::admission) range: AddressRange,
    pub(in crate::linux::remote::dynamic::owner::admission) target: AddressRange,
    pub(in crate::linux::remote::dynamic::owner::admission) before:
        liteinst_admission::scan::Boundary,
    pub(in crate::linux::remote::dynamic::owner::admission) after:
        liteinst_admission::scan::Boundary,
    pub(in crate::linux::remote::dynamic::owner::admission) writes:
        liteinst_admission::scan::WriteControl,
    pub(in crate::linux::remote::dynamic::owner::admission) snapshot_address: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) bytes_address: usize,
}
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ConsumerProfileView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) stack: StackDescriptor,
    pub(in crate::linux::remote::dynamic::owner::admission) metadata: StackMetadata,
    pub(in crate::linux::remote::dynamic::owner::admission) layout: PkuLayout,
    pub(in crate::linux::remote::dynamic::owner::admission) initial_rsp: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) island: &'a std::ops::Range<u64>,
    pub(in crate::linux::remote::dynamic::owner::admission) restored: &'a AdmissionStop,
}
#[derive(Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ConsumerBindingView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) census: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) reservation: Reservation,
    pub(in crate::linux::remote::dynamic::owner::admission) candidate_serial: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) origin: OriginId,
    pub(in crate::linux::remote::dynamic::owner::admission) execution: ExecutionId,
    pub(in crate::linux::remote::dynamic::owner::admission) source: ConsumerSourceView,
    pub(in crate::linux::remote::dynamic::owner::admission) fetch: &'a FetchGeometry,
    pub(in crate::linux::remote::dynamic::owner::admission) operand: &'a OperandDescription,
    pub(in crate::linux::remote::dynamic::owner::admission) profile: ConsumerProfileView<'a>,
    pub(in crate::linux::remote::dynamic::owner::admission) until: Instant,
}
impl ConsumerBindingView<'_> {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn of(
        binding: &Binding,
    ) -> ConsumerBindingView<'_> {
        let p = &binding.profile;
        ConsumerBindingView {
            census: binding.census,
            reservation: binding.reservation,
            candidate_serial: binding.candidate_serial,
            origin: binding.origin,
            execution: binding.execution,
            source: binding.source.consumer_view(),
            fetch: &binding.fetch,
            operand: &binding.operand,
            profile: ConsumerProfileView {
                stack: p.stack,
                metadata: p.metadata,
                layout: p.layout,
                initial_rsp: p.initial_rsp,
                island: &p.island,
                restored: &p.restored,
            },
            until: binding.until,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ConsumerAllocationView {
    pub(in crate::linux::remote::dynamic::owner::admission) started: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) complete: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) payload: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) failure: Option<CensusConsumerError>,
}
impl ConsumerAllocationView {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn of(
        value: PayloadProgress,
    ) -> Self {
        use super::super::storage::StorageFailure;
        Self {
            started: value.started,
            complete: value.complete,
            payload: value.payload,
            failure: value.failure.map(|failure| match failure {
                StorageFailure::Error(error) => CensusConsumerError::Census(error),
                StorageFailure::Aborted => CensusConsumerError::Aborted,
            }),
        }
    }
}
