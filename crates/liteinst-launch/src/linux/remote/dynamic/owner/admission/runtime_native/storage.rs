//! Installed independent native storage; allocation never creates a stop or seal.
use super::*;

pub(in crate::linux::remote::dynamic::owner::admission) struct NativeInstructionStorage {
    pending: Option<PendingInstructionStorage>,
    allocated: Option<PreparedInstructionAttempt>,
    next: usize,
    first_failure: Option<InstructionFailure>,
}

struct PendingInstructionStorage {
    shape: InstructionAttemptShape,
    until: Instant,
    states: [Option<StateSlot>; STATES],
    maps: [Option<MapBuffer>; 5],
    membership: Option<Box<[u8; MAP_BYTES]>>,
    signals: [SignalObservation; WAITS],
    debug: [DebugRead; WAITS],
    profile: ControlProfile,
    peek: MemoryObservation,
    progress: InstructionProgress,
    initial: Option<AdmissionStop>,
    stops: [Option<AdmissionStop>; WAITS],
    source: Option<SourceWindowId>,
    origin: Option<OriginId>,
    execution: Option<ExecutionId>,
    encoding: [u8; 15],
    encoding_len: usize,
    trace: Option<NativeTrace>,
    claimed: bool,
}

enum NativeStorageConversion {
    Allocated(PreparedInstructionAttempt),
    Partial(PendingInstructionStorage),
}

impl PendingInstructionStorage {
    fn empty(shape: InstructionAttemptShape, until: Instant) -> Self {
        Self {
            shape,
            until,
            states: std::array::from_fn(|_| None),
            maps: std::array::from_fn(|_| None),
            membership: None,
            signals: std::array::from_fn(|_| SignalObservation::default()),
            debug: [DebugRead::default(); WAITS],
            profile: ControlProfile::default(),
            peek: MemoryObservation::default(),
            progress: InstructionProgress {
                phase: InstructionPhase::Allocated,
                first_failure: None,
                waits: [None; WAITS],
                queries_started: [false; WAITS],
                instruction_completed: false,
                nx_closed: false,
                effects: [None; EFFECTS],
                effects_len: 0,
            },
            initial: None,
            stops: std::array::from_fn(|_| None),
            source: None,
            origin: None,
            execution: None,
            encoding: [0; 15],
            encoding_len: 0,
            trace: None,
            claimed: false,
        }
    }

    // Exhaustive and guard-free. Failed matching returns the ENTIRE owner.
    // No fallible call, callback, extraction or assertion occurs in either arm.
    fn into_allocated(self) -> NativeStorageConversion {
        match self {
            Self {
                states:
                    [
                        Some(s0),
                        Some(s1),
                        Some(s2),
                        Some(s3),
                        Some(s4),
                        Some(s5),
                        Some(s6),
                        Some(s7),
                        Some(s8),
                    ],
                maps: [Some(m0), Some(m1), Some(m2), Some(m3), Some(m4)],
                membership: Some(membership),
                shape,
                until,
                signals,
                debug,
                profile,
                peek,
                progress,
                initial,
                stops,
                source,
                origin,
                execution,
                encoding,
                encoding_len,
                trace,
                claimed,
            } => NativeStorageConversion::Allocated(PreparedInstructionAttempt {
                states: [s0, s1, s2, s3, s4, s5, s6, s7, s8],
                maps: [m0, m1, m2, m3, m4],
                membership,
                shape,
                until,
                signals,
                debug,
                profile,
                peek,
                progress,
                initial,
                stops,
                source,
                origin,
                execution,
                encoding,
                encoding_len,
                trace,
                claimed,
            }),
            partial => NativeStorageConversion::Partial(partial),
        }
    }
}

impl NativeInstructionStorage {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty(
        shape: InstructionAttemptShape,
        until: Instant,
    ) -> Self {
        Self {
            pending: Some(PendingInstructionStorage::empty(shape, until)),
            allocated: None,
            next: 0,
            first_failure: None,
        }
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn payload_reservation(
        shape: InstructionAttemptShape,
    ) -> Result<usize, LaunchError> {
        shape
            .reservation_bytes()?
            .checked_sub(size_of::<PreparedInstructionAttempt>())
            .ok_or(LaunchError::Invalid(
                "ordinary native embedded header differs",
            ))
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn allocate_one(
        &mut self,
        ordinal: usize,
    ) -> Result<(), LaunchError> {
        if ordinal != self.next
            || ordinal >= 15
            || self.allocated.is_some()
            || self.first_failure.is_some()
        {
            return Err(LaunchError::Invalid("ordinary native allocation reused"));
        }
        let result = (|| {
            let pending = self.pending.as_mut().ok_or(LaunchError::Invalid(
                "ordinary native pending storage absent",
            ))?;
            match ordinal {
                0..=8 => {
                    if pending.states[ordinal].is_some() {
                        return Err(LaunchError::Invalid(
                            "ordinary native state already allocated",
                        ));
                    }
                    pending.states[ordinal] = Some(StateSlot::allocate()?);
                    let state = pending.states[ordinal]
                        .as_ref()
                        .ok_or(LaunchError::Invalid(
                            "ordinary native state allocation absent",
                        ))?;
                    if state.state.xstate.capacity() != MAX_XSTATE
                        || state.state.xstate.len() != MAX_XSTATE
                    {
                        return Err(LaunchError::Invalid(
                            "ordinary native state capacity differs",
                        ));
                    }
                }
                9..=13 => {
                    let index = ordinal - 9;
                    if pending.maps[index].is_some() {
                        return Err(LaunchError::Invalid(
                            "ordinary native maps already allocated",
                        ));
                    }
                    pending.maps[index] = Some(MapBuffer::allocate()?);
                }
                14 => {
                    if pending.membership.is_some() {
                        return Err(LaunchError::Invalid(
                            "ordinary native membership already allocated",
                        ));
                    }
                    pending.membership = Some(fixed_buffer()?);
                }
                _ => {
                    return Err(LaunchError::Invalid(
                        "ordinary native allocation ordinal differs",
                    ));
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.next += 1;
                Ok(())
            }
            Err(error) => {
                self.fail(Some(&error));
                Err(error)
            }
        }
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn finish_allocation(
        &mut self,
    ) -> Result<(), LaunchError> {
        if self.next != 15 || self.first_failure.is_some() || self.allocated.is_some() {
            return Err(LaunchError::Invalid(
                "ordinary native allocation incomplete",
            ));
        }
        {
            let value = self.pending.as_ref().ok_or(LaunchError::Invalid(
                "ordinary native pending storage absent",
            ))?;
            if self.payload_bytes()? > Self::payload_reservation(value.shape)? {
                return Err(LaunchError::Invalid(
                    "ordinary native allocation exceeds reservation",
                ));
            }
            if value.states.iter().any(|slot| {
                slot.as_ref().is_none_or(|s| {
                    s.state.xstate.capacity() != MAX_XSTATE || s.state.xstate.len() != MAX_XSTATE
                })
            }) || value.maps.iter().any(Option::is_none)
                || value.membership.is_none()
                || value.progress.first_failure.is_some()
                || value.claimed
                || value.initial.is_some()
                || value.stops.iter().any(Option::is_some)
                || value.source.is_some()
                || value.origin.is_some()
                || value.execution.is_some()
                || value.encoding_len != 0
                || value.trace.is_some()
            {
                return Err(LaunchError::Invalid(
                    "ordinary native allocation fields differ",
                ));
            }
        }
        // From the take through reinstallation: only closed matches and moves.
        let pending = match self.pending.take() {
            Some(value) => value,
            None => {
                return Err(LaunchError::Invalid(
                    "ordinary native pending storage absent",
                ));
            }
        };
        match pending.into_allocated() {
            NativeStorageConversion::Allocated(value) => {
                self.allocated = Some(value);
                Ok(())
            }
            NativeStorageConversion::Partial(value) => {
                self.pending = Some(value);
                Err(LaunchError::Invalid(
                    "ordinary native allocation owners incomplete",
                ))
            }
        }
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn require_complete(
        &self,
    ) -> Result<&PreparedInstructionAttempt, LaunchError> {
        if self.pending.is_some() || self.next != 15 || self.first_failure.is_some() {
            return Err(LaunchError::Invalid(
                "ordinary native allocation is not ready",
            ));
        }
        self.allocated.as_ref().ok_or(LaunchError::Invalid(
            "ordinary native allocated owner absent",
        ))
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_complete_mut(
        &mut self,
    ) -> Result<&mut PreparedInstructionAttempt, LaunchError> {
        self.require_complete()?;
        self.allocated.as_mut().ok_or(LaunchError::Invalid(
            "ordinary native allocated owner absent",
        ))
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn take_completed(
        &mut self,
    ) -> Result<OwnedInstructionCompletion<'_>, LaunchError> {
        self.require_complete_mut()?.take_completed()
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn payload_bytes(
        &self,
    ) -> Result<usize, LaunchError> {
        let mut bytes = 0_usize;
        if let Some(value) = &self.pending {
            for slot in value.states.iter().flatten() {
                bytes = bytes
                    .checked_add(slot.state.xstate.capacity())
                    .ok_or(LaunchError::Invalid("ordinary native payload overflow"))?;
            }
            bytes = bytes
                .checked_add(value.maps.iter().filter(|slot| slot.is_some()).count() * MAP_BYTES)
                .and_then(|n| n.checked_add(usize::from(value.membership.is_some()) * MAP_BYTES))
                .ok_or(LaunchError::Invalid("ordinary native payload overflow"))?;
        }
        if let Some(value) = &self.allocated {
            bytes = bytes
                .checked_add(
                    value
                        .allocated_bytes()?
                        .checked_sub(size_of::<PreparedInstructionAttempt>())
                        .ok_or(LaunchError::Invalid(
                            "ordinary native header subtraction differs",
                        ))?,
                )
                .ok_or(LaunchError::Invalid("ordinary native payload overflow"))?;
        }
        Ok(bytes)
    }

    fn fail(&mut self, error: Option<&LaunchError>) {
        let failure = match error {
            Some(LaunchError::Invalid(reason)) => InstructionFailure::Invalid(reason),
            Some(LaunchError::System { operation, source }) => {
                InstructionFailure::System(operation, source.raw_os_error())
            }
            Some(LaunchError::Timeout(operation)) => InstructionFailure::Timeout(operation),
            Some(LaunchError::Child { status }) => InstructionFailure::Child(*status),
            None => InstructionFailure::Unwound,
        };
        self.first_failure.get_or_insert(failure);
        if let Some(value) = &mut self.pending {
            value.progress.fail(error);
        }
        if let Some(value) = &mut self.allocated {
            value.progress.fail(error);
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        self.fail(None);
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn temporary_bytes()
    -> Result<usize, LaunchError> {
        let terms = [
            size_of::<Self>(),
            size_of::<PendingInstructionStorage>(),
            size_of::<NativeStorageConversion>(),
            size_of::<PreparedInstructionAttempt>(),
            size_of::<Option<PendingInstructionStorage>>(),
            size_of::<Option<PreparedInstructionAttempt>>(),
            size_of::<StateSlot>(),
            size_of::<MapBuffer>(),
            size_of::<Result<StateSlot, LaunchError>>(),
            size_of::<Result<MapBuffer, LaunchError>>(),
            size_of::<Result<Box<[u8; MAP_BYTES]>, LaunchError>>(),
            size_of::<Result<(), LaunchError>>(),
            size_of::<[usize; 8]>(),
            size_of::<[bool; 8]>(),
            size_of::<[Option<usize>; 4]>(),
            size_of::<std::slice::Iter<'_, Option<StateSlot>>>(),
            size_of::<std::slice::Iter<'_, Option<MapBuffer>>>(),
            size_of::<std::iter::Flatten<std::slice::Iter<'_, Option<StateSlot>>>>(),
            size_of::<(InstructionAttemptShape, Instant, Option<InstructionFailure>)>(),
            size_of::<[&Self; 4]>(),
            size_of::<[&PendingInstructionStorage; 4]>(),
            size_of::<[&StateSlot; 4]>(),
            size_of::<[&MapBuffer; 4]>(),
            size_of::<std::ops::Range<usize>>(),
            size_of::<(
                std::alloc::Layout,
                *mut u8,
                Option<usize>,
                Result<usize, LaunchError>,
            )>(),
        ];
        let mut total = size_of::<[usize; 25]>()
            + size_of::<std::array::IntoIter<usize, 25>>()
            + size_of::<([usize; 6], Option<usize>, Result<usize, LaunchError>)>();
        for item in terms {
            total = total
                .checked_add(item)
                .ok_or(LaunchError::Invalid("ordinary native temporary overflow"))?;
        }
        Ok(total)
    }

    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn progress(
        &self,
    ) -> &InstructionProgress {
        if let Some(value) = &self.allocated {
            value.progress()
        } else {
            &self
                .pending
                .as_ref()
                .expect("retained native pending owner")
                .progress
        }
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn diagnostics(
        &self,
    ) -> InstructionDiagnostics<'_> {
        self.allocated
            .as_ref()
            .expect("allocated native diagnostics")
            .diagnostics()
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn completed(
        &self,
    ) -> Option<InstructionCompletionView<'_>> {
        self.allocated
            .as_ref()
            .and_then(PreparedInstructionAttempt::completed)
    }
}

#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner::admission) struct NativeAllocationView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) states: [Option<&'a StateSlot>; STATES],
    pub(in crate::linux::remote::dynamic::owner::admission) maps: [Option<&'a MapBuffer>; 5],
    pub(in crate::linux::remote::dynamic::owner::admission) membership: Option<&'a [u8; MAP_BYTES]>,
    pub(in crate::linux::remote::dynamic::owner::admission) next: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) first_failure:
        Option<InstructionFailure>,
    pub(in crate::linux::remote::dynamic::owner::admission) pending: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) allocated: bool,
}
#[cfg(test)]
impl NativeInstructionStorage {
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocation_test_shape()
    -> InstructionAttemptShape {
        InstructionAttemptShape {
            fetch_start: 0x401000,
            fetch_end: 0x402000,
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn partial_view(
        &self,
    ) -> NativeAllocationView<'_> {
        match (&self.pending, &self.allocated) {
            (Some(value), _) => NativeAllocationView {
                states: std::array::from_fn(|i| value.states[i].as_ref()),
                maps: std::array::from_fn(|i| value.maps[i].as_ref()),
                membership: value.membership.as_deref(),
                next: self.next,
                first_failure: self.first_failure,
                pending: true,
                allocated: self.allocated.is_some(),
            },
            (None, Some(value)) => NativeAllocationView {
                states: std::array::from_fn(|i| Some(&value.states[i])),
                maps: std::array::from_fn(|i| Some(&value.maps[i])),
                membership: Some(&value.membership),
                next: self.next,
                first_failure: self.first_failure,
                pending: false,
                allocated: true,
            },
            (None, None) => NativeAllocationView {
                states: [None; STATES],
                maps: [None; 5],
                membership: None,
                next: self.next,
                first_failure: self.first_failure,
                pending: false,
                allocated: false,
            },
        }
    }
}
#[cfg(test)]
mod native_oracle;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner::admission) use native_oracle::NativeStorageSnapshot;
