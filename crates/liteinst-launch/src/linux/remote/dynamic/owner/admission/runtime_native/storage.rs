//! Installed independent native storage; allocation never creates a stop or seal.
use super::super::exact_storage;
use super::*;

pub(in crate::linux::remote::dynamic::owner::admission) struct NativeInstructionStorage {
    owner: Option<NativeStorageConversion>,
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
    profile: Option<Box<ControlProfile>>,
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
            profile: None,
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
                profile: Some(profile),
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

// The caller has already reserved the complete header and construction peak.
// This empty default contains no native observation or separately owned payload.
pub(super) fn allocate_profile() -> Result<Box<ControlProfile>, LaunchError> {
    exact_storage::value(ControlProfile::default()).map_err(|error| match error {
        exact_storage::AllocationError::Capacity => {
            LaunchError::Invalid("ordinary native profile allocation capacity differs")
        }
        exact_storage::AllocationError::Allocation => {
            LaunchError::Invalid("ordinary native profile allocation failed")
        }
    })
}

impl NativeInstructionStorage {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty(
        shape: InstructionAttemptShape,
        until: Instant,
    ) -> Self {
        Self {
            owner: Some(NativeStorageConversion::Partial(
                PendingInstructionStorage::empty(shape, until),
            )),
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
            || ordinal >= 16
            || matches!(self.owner, Some(NativeStorageConversion::Allocated(_)))
            || self.first_failure.is_some()
        {
            return Err(LaunchError::Invalid("ordinary native allocation reused"));
        }
        let result = (|| {
            let pending = match self.owner.as_mut() {
                Some(NativeStorageConversion::Partial(value)) => value,
                _ => {
                    return Err(LaunchError::Invalid(
                        "ordinary native pending storage absent",
                    ));
                }
            };
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
                15 => {
                    if pending.profile.is_some() {
                        return Err(LaunchError::Invalid(
                            "ordinary native profile already allocated",
                        ));
                    }
                    // Install before the root's after-allocation hook or any
                    // later fallible check. Existing payload ordinals stay fixed.
                    pending.profile = Some(allocate_profile()?);
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
        if self.next != 16
            || self.first_failure.is_some()
            || matches!(self.owner, Some(NativeStorageConversion::Allocated(_)))
        {
            return Err(LaunchError::Invalid(
                "ordinary native allocation incomplete",
            ));
        }
        {
            let value = match self.owner.as_ref() {
                Some(NativeStorageConversion::Partial(value)) => value,
                _ => {
                    return Err(LaunchError::Invalid(
                        "ordinary native pending storage absent",
                    ));
                }
            };
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
                || value.profile.is_none()
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
        // Consume the input Option before constructing the output Option.
        // Every taken owner is reinstalled before any error or observation.
        // There is no callback, assertion, allocation or fallible move interval.
        match self.owner.take() {
            Some(NativeStorageConversion::Partial(value)) => {
                self.owner = Some(value.into_allocated());
            }
            Some(NativeStorageConversion::Allocated(value)) => {
                self.owner = Some(NativeStorageConversion::Allocated(value));
                return Err(LaunchError::Invalid(
                    "ordinary native allocation incomplete",
                ));
            }
            None => {
                return Err(LaunchError::Invalid(
                    "ordinary native pending storage absent",
                ));
            }
        }
        match self.owner.as_ref() {
            Some(NativeStorageConversion::Allocated(_)) => Ok(()),
            _ => Err(LaunchError::Invalid(
                "ordinary native allocation owners incomplete",
            )),
        }
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn require_complete(
        &self,
    ) -> Result<&PreparedInstructionAttempt, LaunchError> {
        if matches!(self.owner, Some(NativeStorageConversion::Partial(_)))
            || self.next != 16
            || self.first_failure.is_some()
        {
            return Err(LaunchError::Invalid(
                "ordinary native allocation is not ready",
            ));
        }
        match self.owner.as_ref() {
            Some(NativeStorageConversion::Allocated(value)) => Ok(value),
            _ => Err(LaunchError::Invalid(
                "ordinary native allocated owner absent",
            )),
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_complete_mut(
        &mut self,
    ) -> Result<&mut PreparedInstructionAttempt, LaunchError> {
        self.require_complete()?;
        match self.owner.as_mut() {
            Some(NativeStorageConversion::Allocated(value)) => Ok(value),
            _ => Err(LaunchError::Invalid(
                "ordinary native allocated owner absent",
            )),
        }
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
        if let Some(NativeStorageConversion::Partial(value)) = &self.owner {
            for slot in value.states.iter().flatten() {
                bytes = bytes
                    .checked_add(slot.state.xstate.capacity())
                    .ok_or(LaunchError::Invalid("ordinary native payload overflow"))?;
            }
            bytes = bytes
                .checked_add(value.maps.iter().filter(|slot| slot.is_some()).count() * MAP_BYTES)
                .and_then(|n| n.checked_add(usize::from(value.membership.is_some()) * MAP_BYTES))
                .and_then(|n| {
                    n.checked_add(
                        usize::from(value.profile.is_some()) * size_of::<ControlProfile>(),
                    )
                })
                .ok_or(LaunchError::Invalid("ordinary native payload overflow"))?;
        }
        if let Some(NativeStorageConversion::Allocated(value)) = &self.owner {
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
        if let Some(NativeStorageConversion::Partial(value)) = &mut self.owner {
            value.progress.fail(error);
        }
        if let Some(NativeStorageConversion::Allocated(value)) = &mut self.owner {
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
            // The take input is destructured before the output Some exists.
            size_of::<Option<NativeStorageConversion>>(),
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
            ControlProfile::allocation_temporary_bytes()?,
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
        match self.owner.as_ref() {
            Some(NativeStorageConversion::Allocated(value)) => value.progress(),
            Some(NativeStorageConversion::Partial(value)) => &value.progress,
            None => panic!("retained native pending owner"),
        }
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn diagnostics(
        &self,
    ) -> InstructionDiagnostics<'_> {
        match self.owner.as_ref() {
            Some(NativeStorageConversion::Allocated(value)) => value.diagnostics(),
            _ => panic!("allocated native diagnostics"),
        }
    }
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission) fn completed(
        &self,
    ) -> Option<InstructionCompletionView<'_>> {
        match self.owner.as_ref() {
            Some(NativeStorageConversion::Allocated(value)) => value.completed(),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner::admission) struct NativeAllocationView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) states: [Option<&'a StateSlot>; STATES],
    pub(in crate::linux::remote::dynamic::owner::admission) maps: [Option<&'a MapBuffer>; 5],
    pub(in crate::linux::remote::dynamic::owner::admission) membership: Option<&'a [u8; MAP_BYTES]>,
    pub(in crate::linux::remote::dynamic::owner::admission) profile: Option<&'a ControlProfile>,
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
        match self.owner.as_ref() {
            Some(NativeStorageConversion::Partial(value)) => NativeAllocationView {
                states: std::array::from_fn(|i| value.states[i].as_ref()),
                maps: std::array::from_fn(|i| value.maps[i].as_ref()),
                membership: value.membership.as_deref(),
                profile: value.profile.as_deref(),
                next: self.next,
                first_failure: self.first_failure,
                pending: true,
                allocated: false,
            },
            Some(NativeStorageConversion::Allocated(value)) => NativeAllocationView {
                states: std::array::from_fn(|i| Some(&value.states[i])),
                maps: std::array::from_fn(|i| Some(&value.maps[i])),
                membership: Some(&value.membership),
                profile: Some(&value.profile),
                next: self.next,
                first_failure: self.first_failure,
                pending: false,
                allocated: true,
            },
            None => NativeAllocationView {
                states: [None; STATES],
                maps: [None; 5],
                membership: None,
                profile: None,
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
