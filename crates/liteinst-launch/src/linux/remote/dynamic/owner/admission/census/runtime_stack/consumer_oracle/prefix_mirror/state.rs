//! Fixed descriptive state metadata and one prepaid initialized byte prefix.
//! Neither an empty nor copied record is accepted as native authority.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
struct StateMetadata {
    token: DynamicStop,
    task: DynamicTask,
    logical_pc: u64,
    registers: RegisterSnapshot,
    signal_mask: u64,
    phase: StopPhase,
    signal: Option<DynamicSignalInfo>,
}
impl StateMetadata {
    fn of(value: &ObservedStop) -> Self {
        let ObservedStop {
            token,
            task,
            logical_pc,
            registers,
            xstate: _,
            signal_mask,
            phase,
            signal,
        } = value;
        Self {
            token: token.clone(),
            task: *task,
            logical_pc: *logical_pc,
            registers: *registers,
            signal_mask: *signal_mask,
            phase: *phase,
            signal: signal.clone(),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct StateDescription {
    state: Option<StateMetadata>,
    state_allocation: Option<BufferIdentity>,
    buffer_allocation: BufferIdentity,
}
impl StateDescription {
    fn of(state: Option<&ObservedStop>, buffer: &Vec<u8>) -> Self {
        Self {
            state: state.map(StateMetadata::of),
            state_allocation: state.map(|value| BufferIdentity::of(&value.xstate)),
            buffer_allocation: BufferIdentity::of(buffer),
        }
    }
}
pub(in crate::linux::remote::dynamic::owner::admission::census) struct StatePrefix {
    description: Option<StateDescription>,
    bytes: Vec<u8>,
}
impl StatePrefix {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn empty() -> Self {
        Self {
            description: None,
            bytes: Vec::new(),
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn allocate(
        &mut self,
    ) -> Result<(), CensusConsumerError> {
        require(self.description.is_none() && self.bytes.is_empty() && self.bytes.capacity() == 0)?;
        self.bytes = exact_storage::empty_bytes(MAX_XSTATE_BYTES)?;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn allocated_bytes(
        &self,
    ) -> Result<usize, CensusConsumerError> {
        require(matches!(self.bytes.capacity(), 0 | MAX_XSTATE_BYTES))?;
        Ok(self.bytes.capacity())
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn capture(
        &mut self,
        state: Option<&ObservedStop>,
        buffer: &Vec<u8>,
    ) -> Result<(), CensusConsumerError> {
        require(
            self.description.is_none()
                && self.bytes.is_empty()
                && self.bytes.capacity() == MAX_XSTATE_BYTES,
        )?;
        self.description = Some(StateDescription::of(state, buffer));
        let state_capacity = state.map_or(0, |value| value.xstate.capacity());
        let state_bytes = state.map_or(&[][..], |value| value.xstate.as_slice());
        let total_capacity = checked_add(state_capacity, buffer.capacity())?;
        let total_length = checked_add(state_bytes.len(), buffer.len())?;
        require(total_capacity <= MAX_XSTATE_BYTES && total_length <= self.bytes.capacity())?;
        // Zero and incomplete initialized lengths are evidence too. No valid-
        // XSTATE or source-complete premise is imposed on failed-prefix copies.
        self.bytes.extend_from_slice(state_bytes);
        self.bytes.extend_from_slice(buffer);
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn require_preserved(
        &self,
        state: Option<&ObservedStop>,
        buffer: &Vec<u8>,
    ) -> Result<(), CensusConsumerError> {
        require(self.description.as_ref() == Some(&StateDescription::of(state, buffer)))?;
        let state_bytes = state.map_or(&[][..], |value| value.xstate.as_slice());
        let length = checked_add(state_bytes.len(), buffer.len())?;
        require(self.bytes.capacity() == MAX_XSTATE_BYTES && self.bytes.len() == length)?;
        require(
            self.bytes.get(..state_bytes.len()) == Some(state_bytes)
                && self.bytes.get(state_bytes.len()..) == Some(buffer.as_slice()),
        )
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn identity(
        &self,
    ) -> BufferIdentity {
        BufferIdentity::of(&self.bytes)
    }
}
pub(in crate::linux::remote::dynamic::owner::admission::census) fn temporary_bytes()
-> Result<usize, CensusConsumerError> {
    let mut total = 0;
    for size in [
        2 * size_of::<StateDescription>(),
        2 * size_of::<StateMetadata>(),
        4 * size_of::<BufferIdentity>(),
        3 * size_of::<Option<&ObservedStop>>(),
        6 * size_of::<&[u8]>(),
        2 * size_of::<&Vec<u8>>(),
        6 * size_of::<usize>(),
        4 * size_of::<Result<(), CensusConsumerError>>(),
        2 * size_of::<Result<usize, CensusConsumerError>>(),
        size_of::<exact_storage::AllocationError>(),
        4 * size_of::<bool>(),
        2 * size_of::<std::alloc::Layout>(),
        2 * size_of::<*mut u8>(),
        2 * size_of::<Vec<u8>>(),
        size_of::<Result<Vec<u8>, exact_storage::AllocationError>>(),
        size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>(),
        2 * size_of::<std::slice::Iter<'_, u8>>(),
        size_of::<fn(&ObservedStop) -> StateMetadata>(),
        // This calculator's expanded term array, iterator and fixed control locals.
        size_of::<[usize; 19]>()
            + size_of::<std::array::IntoIter<usize, 19>>()
            + 4 * size_of::<usize>()
            + 2 * size_of::<Option<usize>>()
            + 2 * size_of::<Result<usize, CensusConsumerError>>()
            + size_of::<CensusConsumerError>(),
    ] {
        total = checked_add(total, size)?;
    }
    Ok(total)
}
