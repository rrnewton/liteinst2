//! Installed native ownership. Allocation never grants a read or release.
use super::*;
use std::ops::{Deref, DerefMut};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StackNativeShape {
    pub(super) start: u64,
    pub(super) end: u64,
}
impl StackNativeShape {
    pub(super) fn from_geometry(geometry: &FetchGeometry) -> Result<Self, LaunchError> {
        let pages = geometry.pages();
        let length = pages
            .end()
            .checked_sub(pages.start())
            .ok_or(LaunchError::Invalid("owned stack fetch extent underflows"))?;
        if pages.start() % 4096 != 0 || !matches!(length, 4096 | 8192) {
            return Err(LaunchError::Invalid("owned stack fetch extent differs"));
        }
        Ok(Self {
            start: pages.start(),
            end: pages.end(),
        })
    }
}

/// MapBuffer's exact boxed payload is absent until this owner is installed.
/// Its unchanged reader is used only after require_allocated has succeeded.
#[derive(Default)]
pub(super) struct StackMapSlot {
    value: Option<MapBuffer>,
}
impl StackMapSlot {
    pub(super) fn payload_bytes(&self) -> usize {
        usize::from(self.value.is_some()) * MAP_BYTES
    }
    #[cfg(feature = "dev-owned-stack-consumer-oracle")]
    pub(super) fn consumer_retained(&self) -> Option<&MapBuffer> {
        self.value.as_ref()
    }
    #[cfg(test)]
    pub(super) fn retained(&self) -> Option<&MapBuffer> {
        self.value.as_ref()
    }
}
impl Deref for StackMapSlot {
    type Target = MapBuffer;
    fn deref(&self) -> &Self::Target {
        self.value
            .as_ref()
            .expect("installed owned stack map payload")
    }
}
impl DerefMut for StackMapSlot {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value
            .as_mut()
            .expect("installed owned stack map payload")
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct AllocationFault {
    pub(super) before: Option<usize>,
    pub(super) after: Option<usize>,
}

impl PreparedStackNative {
    pub(in crate::linux::remote::dynamic::owner::admission) fn empty() -> Self {
        Self {
            shape: None,
            until: None,
            states: [
                empty_state(),
                empty_state(),
                empty_state(),
                empty_state(),
                empty_state(),
                empty_state(),
                empty_state(),
                empty_state(),
                empty_state(),
            ],
            maps: [
                StackMapSlot::default(),
                StackMapSlot::default(),
                StackMapSlot::default(),
                StackMapSlot::default(),
                StackMapSlot::default(),
            ],
            membership: Vec::new(),
            signals: [
                SignalObservation::default(),
                SignalObservation::default(),
                SignalObservation::default(),
                SignalObservation::default(),
                SignalObservation::default(),
                SignalObservation::default(),
                SignalObservation::default(),
            ],
            debug: [DebugRead::default(); WAITS],
            profile: ControlProfile::default(),
            peek: MemoryObservation::default(),
            words: [
                NativeStackWordCapture::empty(),
                NativeStackWordCapture::empty(),
                NativeStackWordCapture::empty(),
            ],
            progress: StackProgress::default(),
            initial: None,
            stops: [None, None, None, None, None, None, None],
            source: None,
            origin: None,
            execution: None,
            encoding: [0; 5],
            encoding_len: 0,
            identity: None,
            trace: None,
            call_id: None,
            claimed: false,
            native_payload_bytes: 0,
            #[cfg(test)]
            allocation_fault: AllocationFault::default(),
            #[cfg(test)]
            intervention: None,
        }
    }
    /// Both valid fetch extents use this exact fixed payload. Geometry never
    /// relaxes a capture or increases a capacity.
    pub(in crate::linux::remote::dynamic::owner::admission) fn reservation_bytes()
    -> Result<usize, LaunchError> {
        let word_payload = NativeStackWordCapture::reservation_bytes()?
            .checked_sub(size_of::<NativeStackWordCapture>())
            .ok_or(LaunchError::Invalid(
                "owned stack word header exceeds reservation",
            ))?;
        add(
            add(size_of::<Self>(), STATES * MAX_XSTATE + 6 * MAP_BYTES)?,
            word_payload
                .checked_mul(3)
                .ok_or(LaunchError::Invalid("owned stack word storage overflows"))?,
        )
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocate_payloads(
        &mut self,
        geometry: &FetchGeometry,
        until: Instant,
    ) -> Result<(), LaunchError> {
        if self.progress.phase != StackPhase::Empty
            || self.progress.first_failure.is_some()
            || self.shape.is_some()
            || self.until.is_some()
            || self.allocated_bytes()? != size_of::<Self>()
        {
            return Err(LaunchError::Invalid("owned stack native allocation reused"));
        }
        let shape = StackNativeShape::from_geometry(geometry)?;
        Self::reservation_bytes()?;
        self.shape = Some(shape);
        self.until = Some(until);
        self.progress.phase = StackPhase::Allocating;
        let result = self.allocate_inner();
        if let Err(error) = &result {
            self.progress.fail(Some(error));
        }
        result
    }
    fn allocate_inner(&mut self) -> Result<(), LaunchError> {
        // The native core has fifteen independent exact payload owners. Each
        // pointer and tally is installed before another fallible operation.
        for slot in 0..STATES + MAPS + 1 {
            let next = add(self.native_payload_bytes, MAP_BYTES)?;
            #[cfg(test)]
            if self.allocation_fault.before == Some(slot) {
                return Err(LaunchError::Invalid(
                    "owned stack native model allocation failure",
                ));
            }
            match slot {
                0..=8 => {
                    let bytes = super::super::exact_storage::empty_bytes(MAX_XSTATE)
                        .map_err(|_| LaunchError::Invalid("owned stack state allocation failed"))?;
                    self.states[slot].state.xstate = bytes;
                    self.native_payload_bytes = next;
                    self.states[slot].state.xstate.resize(MAX_XSTATE, 0);
                }
                9..=13 => {
                    let map = MapBuffer::allocate()?;
                    self.maps[slot - STATES].value = Some(map);
                    self.native_payload_bytes = next;
                }
                _ => {
                    let bytes =
                        super::super::exact_storage::empty_bytes(MAP_BYTES).map_err(|_| {
                            LaunchError::Invalid("owned stack membership allocation failed")
                        })?;
                    self.membership = bytes;
                    self.native_payload_bytes = next;
                    self.membership.resize(MAP_BYTES, 0);
                }
            }
            #[cfg(test)]
            if self.allocation_fault.after == Some(slot) {
                panic!("owned stack native allocation model unwind");
            }
        }
        // Each delegated capture owns its own three-slot prefix/tally. An Err
        // does not return/drop a temporary capture or any previous word owner.
        for index in 0..3 {
            #[cfg(test)]
            let slot = STATES + MAPS + 1 + index;
            #[cfg(test)]
            if self.allocation_fault.before == Some(slot) {
                return Err(LaunchError::Invalid(
                    "owned stack native model allocation failure",
                ));
            }
            self.words[index].allocate_payloads()?;
            #[cfg(test)]
            if self.allocation_fault.after == Some(slot) {
                panic!("owned stack native allocation model unwind");
            }
        }
        if self.allocated_bytes()? != Self::reservation_bytes()? {
            return Err(LaunchError::Invalid(
                "owned stack native allocated shape differs",
            ));
        }
        self.progress.phase = StackPhase::Allocated;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn allocated_bytes(
        &self,
    ) -> Result<usize, LaunchError> {
        let mut payload = 0;
        for state in &self.states {
            let capacity = state.state.xstate.capacity();
            if !matches!(capacity, 0 | MAX_XSTATE) {
                return Err(LaunchError::Invalid(
                    "owned stack native state capacity differs",
                ));
            }
            payload = add(payload, capacity)?;
        }
        for map in &self.maps {
            payload = add(payload, map.payload_bytes())?;
        }
        let capacity = self.membership.capacity();
        if !matches!(capacity, 0 | MAP_BYTES) {
            return Err(LaunchError::Invalid(
                "owned stack membership capacity differs",
            ));
        }
        payload = add(payload, capacity)?;
        if payload != self.native_payload_bytes {
            return Err(LaunchError::Invalid(
                "owned stack installed payload tally differs",
            ));
        }
        let mut total = add(size_of::<Self>(), payload)?;
        for word in &self.words {
            total = add(
                total,
                word.allocated_bytes()?
                    .checked_sub(size_of::<NativeStackWordCapture>())
                    .ok_or(LaunchError::Invalid("owned stack word storage underflows"))?,
            )?;
        }
        Ok(total)
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn mark_aborted(&mut self) {
        self.progress.fail(None);
        for word in &mut self.words {
            word.mark_aborted();
        }
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn require_allocated(
        &self,
    ) -> Result<(), LaunchError> {
        if self.progress.phase != StackPhase::Allocated
            || self.progress.first_failure.is_some()
            || self.shape.is_none()
            || self.until.is_none()
            || self.allocated_bytes()? != Self::reservation_bytes()?
            || self.native_payload_bytes != STATES * MAX_XSTATE + 6 * MAP_BYTES
            || self.membership.len() != MAP_BYTES
            || self
                .states
                .iter()
                .any(|state| state.state.xstate.len() != MAX_XSTATE)
        {
            return Err(LaunchError::Invalid(
                "owned stack native allocation incomplete",
            ));
        }
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn deadline(&self) -> Instant {
        self.until.expect("installed owned stack deadline")
    }
}

fn add(a: usize, b: usize) -> Result<usize, LaunchError> {
    a.checked_add(b)
        .ok_or(LaunchError::Invalid("owned stack native storage overflows"))
}
fn empty_state() -> StateSlot {
    let registers = RegisterSnapshot {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rax: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        orig_rax: 0,
        rip: 0,
        cs: 0,
        eflags: 0,
        rsp: 0,
        ss: 0,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    };
    StateSlot {
        state: TaskStateSnapshot {
            registers,
            xstate: Vec::new(),
            mask: 0,
        },
        registers_request: None,
        xstate_request: None,
        mask_request: None,
        requested_pointer: 0,
        returned_pointer: 0,
        returned_length: 0,
        complete: false,
    }
}
