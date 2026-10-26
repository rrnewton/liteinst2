//! One retained initial R/RX quarantine. Only actual native observations can
//! finish this producer; a descriptive map projection cannot construct proof.
use super::super::super::admission::initial_coalescence::{
    InitialMapPlan, InitialMapProjection, InitialMapView, InitialSourceRow,
};
use super::super::super::admission::{
    InitialCheckpointSourceRead, InitialReadScratch, InitialSourceCheckpoint, MapEntries,
    SourceReadOperation, SourceReadProgress,
};
use super::*;

mod storage;
#[cfg(test)]
mod tests;
use storage::{add, mul};

const PAIR_BYTES: usize = 2 * PAGE;

fn invalid() -> LaunchError {
    LaunchError::Invalid("initial coalescence native evidence differs")
}
fn native_error(error: crate::GateError) -> LaunchError {
    match error {
        crate::GateError::Control(error) => error,
        crate::GateError::Refused(reason) => LaunchError::Invalid(reason),
        _ => invalid(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum InitialCoalescenceStage {
    Installed,
    Allocating,
    Allocated,
    OriginalRead,
    OriginalCaptured,
    BeforeQuarantine,
    Quarantine,
    AfterQuarantine,
    FinalRead,
    FinalCaptured,
    Descriptors,
    Complete,
}

/// Fixed retained raw wait/query facts, copied before any interpretation or
/// restoration. The two separate StateSlots retain pre/post restored states;
/// this header does not claim to retain a third full trap XSTATE image.
#[derive(Default)]
pub(in crate::linux::remote::dynamic::owner) struct CoalescenceCallObservation {
    pub(in crate::linux::remote::dynamic::owner) wait: Option<(i32, i32)>,
    pub(in crate::linux::remote::dynamic::owner) queries_started: bool,
    pub(in crate::linux::remote::dynamic::owner) signal: SignalObservation,
    pub(in crate::linux::remote::dynamic::owner) registers: Option<RegisterSnapshot>,
    pub(in crate::linux::remote::dynamic::owner) requests: [Option<Request>; 3],
    pub(in crate::linux::remote::dynamic::owner) mask: u64,
    pub(in crate::linux::remote::dynamic::owner) returned_length: usize,
    pub(in crate::linux::remote::dynamic::owner) result: Option<u64>,
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
}
impl CoalescenceCallObservation {
    pub(super) fn retain_queries(&mut self, p: &PreparedInitialBootstrap) {
        self.signal.bytes = p.runner_signal.bytes;
        self.signal.request = p.runner_signal.request;
        let state = &p.states[READBACK];
        self.requests = [
            state.registers_request,
            state.xstate_request,
            state.mask_request,
        ];
        self.mask = state.state.mask;
        self.returned_length = state.returned_length;
        if state.registers_request
            == Some(Request {
                result: 0,
                errno: None,
            })
        {
            self.registers = Some(state.state.registers);
            self.result = Some(state.state.registers.rax);
        }
    }
    fn validate(&self, tid: i32, original_mask: u64) -> Result<(), LaunchError> {
        let (actual, status) = self.wait.ok_or_else(invalid)?;
        if actual != tid
            || !libc::WIFSTOPPED(status)
            || libc::WSTOPSIG(status) != libc::SIGTRAP
            || status >> 16 != 0
            || !self.queries_started
            || self.signal.request
                != Some(Request {
                    result: 0,
                    errno: None,
                })
            || self.mask != original_mask
            || !self.complete
            || self.result != Some(0)
            || self.requests
                != [Some(Request {
                    result: 0,
                    errno: None,
                }); 3]
            || !(512..MAX_XSTATE).contains(&self.returned_length)
            || self.registers.is_none_or(|registers| registers.rax != 0)
        {
            return Err(invalid());
        }
        self.signal.validate()
    }
}

/// Installed inline before allocation. Every successfully returned payload is
/// assigned here before another fallible operation. No Drop cleanup callback.
pub(in crate::linux::remote::dynamic::owner) struct PreparedInitialCoalescence {
    until: Instant,
    plan: InitialMapPlan,
    original_identity: (usize, usize),
    stage: InitialCoalescenceStage,
    first_failure: Option<InitialBootstrapFailureKind>,
    original_bytes: Vec<u8>,
    final_bytes: Vec<u8>,
    read_progress: [SourceReadProgress; 2],
    maps: [Option<MapBuffer>; 3],
    states: [StateSlot; 2],
    before_stop: Option<AdmissionStop>,
    after_stop: Option<AdmissionStop>,
    final_stop: Option<AdmissionStop>,
    call: CoalescenceCallObservation,
    projection: Option<InitialMapProjection>,
    pool: Vec<Option<MemoryMapping>>,
    output: Vec<MemoryMapping>,
    // Original bootstrap mappings move here, without dropping any payload.
    retired_descriptors: Vec<MemoryMapping>,
    output_transferred: bool,
    borrowed_island_payload: usize,
    successful_payload_bytes: usize,
    reserved_payload_bytes: usize,
    #[cfg(test)]
    allocation_steps: usize,
    #[cfg(test)]
    allocation_fault: Option<(usize, bool)>,
}

impl PreparedInitialCoalescence {
    pub(in crate::linux::remote::dynamic::owner) fn installed(
        plan: InitialMapPlan,
        original: &[u8],
        until: Instant,
    ) -> Result<Self, LaunchError> {
        let reserved_payload_bytes = Self::reservation_payload(original, &plan)?;
        Ok(Self {
            until,
            plan,
            original_identity: (original.as_ptr() as usize, original.len()),
            stage: InitialCoalescenceStage::Installed,
            first_failure: None,
            original_bytes: Vec::new(),
            final_bytes: Vec::new(),
            read_progress: [SourceReadProgress::default(), SourceReadProgress::default()],
            maps: [None, None, None],
            states: [StateSlot::empty(), StateSlot::empty()],
            before_stop: None,
            after_stop: None,
            final_stop: None,
            call: CoalescenceCallObservation::default(),
            projection: None,
            pool: Vec::new(),
            output: Vec::new(),
            retired_descriptors: Vec::new(),
            output_transferred: false,
            borrowed_island_payload: 0,
            successful_payload_bytes: 0,
            reserved_payload_bytes,
            #[cfg(test)]
            allocation_steps: 0,
            #[cfg(test)]
            allocation_fault: None,
        })
    }

    /// Complete new payload plus a conservative sum of managed temporary
    /// substrates across this call tree. Embedded owner headers are already
    /// charged by RuntimeOwner::allocate; they are deliberately excluded here.
    pub(in crate::linux::remote::dynamic::owner) fn reservation_payload(
        original: &[u8],
        plan: &InitialMapPlan,
    ) -> Result<usize, LaunchError> {
        let rows = parse(original)?;
        if rows.entries().len() != plan.original_rows() {
            return Err(invalid());
        }
        let mut bytes = 3 * MAP_BYTES + 2 * MAX_XSTATE + 2 * PAIR_BYTES;
        bytes = add(
            bytes,
            mul(rows.entries().len(), size_of::<Option<MemoryMapping>>())?,
        )?;
        bytes = add(
            bytes,
            mul(add(rows.entries().len(), 1)?, size_of::<MemoryMapping>())?,
        )?;
        for row in rows.entries() {
            bytes = add(bytes, 4)?;
            bytes = add(bytes, super::storage::pathname(row)?.map_or(0, str::len))?;
        }
        add(bytes, Self::temporary_bytes())
    }

    fn temporary_bytes() -> usize {
        // All simultaneously borrowed records plus a conservative additive
        // allowance for nested pure inventory iterators and native requests.
        // The source reader declares its own bounded authentication peak.
        size_of::<CompletedInitialCoalescence<'_>>()
            + 4 * size_of::<InitialMapProjection>()
            + 2 * size_of::<InitialMapView<'_>>()
            + 4 * size_of::<InitialSourceRow<'_>>()
            + 8 * size_of::<ParsedMaps<'_>>()
            + 8 * size_of::<MapEntries<'_>>()
            + 16 * size_of::<MapEntry<'_>>()
            + 4 * size_of::<AdmissionStop>()
            + 4 * size_of::<RegisterSnapshot>()
            + size_of::<libc::iovec>()
            + size_of::<libc::statfs>()
            + 2 * size_of::<std::os::fd::OwnedFd>()
            + 32
            + 10
            + 68
            + 1
            + InitialCheckpointSourceRead::temporary_bytes()
    }

    fn require_original(&self, original: &[u8]) -> Result<(), LaunchError> {
        if self.original_identity != (original.as_ptr() as usize, original.len()) {
            return Err(invalid());
        }
        Ok(())
    }
    fn debit(&mut self, bytes: usize) -> Result<(), LaunchError> {
        self.successful_payload_bytes = add(self.successful_payload_bytes, bytes)?;
        if add(self.successful_payload_bytes, Self::temporary_bytes())?
            > self.reserved_payload_bytes
        {
            return Err(invalid());
        }
        #[cfg(test)]
        {
            self.allocation_steps += 1;
            if let Some((step, unwind)) = self.allocation_fault
                && step == self.allocation_steps
            {
                if unwind {
                    panic!("injected coalescence allocation unwind");
                }
                return Err(LaunchError::Invalid(
                    "injected coalescence allocation refusal",
                ));
            }
        }
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner) fn allocate_payloads(
        &mut self,
        original: &[u8],
    ) -> Result<(), LaunchError> {
        self.require_original(original)?;
        if self.stage != InitialCoalescenceStage::Installed || self.first_failure.is_some() {
            return Err(invalid());
        }
        // An attempted allocation cannot be restarted over a retained prefix,
        // including when the caller accidentally ignores its first error.
        self.stage = InitialCoalescenceStage::Allocating;
        self.original_bytes = storage::vector(PAIR_BYTES)?;
        self.debit(self.original_bytes.capacity())?;
        self.original_bytes.resize(PAIR_BYTES, 0);
        self.final_bytes = storage::vector(PAIR_BYTES)?;
        self.debit(self.final_bytes.capacity())?;
        self.final_bytes.resize(PAIR_BYTES, 0);
        for index in 0..3 {
            self.maps[index] = Some(MapBuffer::allocate()?);
            self.debit(MAP_BYTES)?;
        }
        for index in 0..2 {
            self.states[index].state.xstate = storage::vector(MAX_XSTATE)?;
            self.debit(self.states[index].state.xstate.capacity())?;
            self.states[index].state.xstate.resize(MAX_XSTATE, 0);
        }
        self.pool = storage::vector(self.plan.original_rows())?;
        self.debit(mul(
            self.pool.capacity(),
            size_of::<Option<MemoryMapping>>(),
        )?)?;
        self.output = storage::vector(add(self.plan.original_rows(), 1)?)?;
        self.debit(mul(self.output.capacity(), size_of::<MemoryMapping>())?)?;
        for row in parse(original)?.entries() {
            if self.pool.len() == self.pool.capacity() {
                return Err(invalid());
            }
            let path = super::storage::pathname(row)?;
            self.pool.push(Some(MemoryMapping {
                start: row.start,
                end: row.end,
                permissions: String::new(),
                file_offset: row.file_offset,
                pathname: None,
            }));
            let index = self.pool.len() - 1;
            self.pool[index].as_mut().ok_or_else(invalid)?.permissions = storage::string(4)?;
            self.debit(4)?;
            self.pool[index]
                .as_mut()
                .ok_or_else(invalid)?
                .permissions
                .push_str(std::str::from_utf8(&row.permissions.bytes()).map_err(|_| invalid())?);
            if let Some(path) = path {
                self.pool[index].as_mut().ok_or_else(invalid)?.pathname =
                    Some(storage::string(path.len())?);
                self.debit(path.len())?;
                self.pool[index]
                    .as_mut()
                    .and_then(|row| row.pathname.as_mut())
                    .ok_or_else(invalid)?
                    .push_str(path);
            }
        }
        self.validate_allocations(None)?;
        self.stage = InitialCoalescenceStage::Allocated;
        Ok(())
    }

    pub(in crate::linux::remote::dynamic::owner) fn original_capture_storage(
        &mut self,
    ) -> Result<(&InitialMapPlan, &mut [u8], &mut SourceReadProgress), LaunchError> {
        if self.stage != InitialCoalescenceStage::Allocated || self.first_failure.is_some() {
            return Err(invalid());
        }
        self.stage = InitialCoalescenceStage::OriginalRead;
        Ok((
            &self.plan,
            &mut self.original_bytes,
            &mut self.read_progress[0],
        ))
    }
    pub(in crate::linux::remote::dynamic::owner) fn original_captured(
        &mut self,
    ) -> Result<(), LaunchError> {
        if self.stage != InitialCoalescenceStage::OriginalRead {
            return Err(invalid());
        }
        require_read(&self.read_progress[0], self.plan.pair_range().start)?;
        self.stage = InitialCoalescenceStage::OriginalCaptured;
        Ok(())
    }
    pub(super) fn plan(&self) -> &InitialMapPlan {
        &self.plan
    }

    pub(super) fn before_quarantine(
        &mut self,
        owner: &Owner,
        native: &lifecycle::NativeLifecycle,
        p: &mut PreparedInitialBootstrap,
        original: &[u8],
        site: runner::Site<'_>,
    ) -> Result<(), LaunchError> {
        self.require_original(original)?;
        if self.stage != InitialCoalescenceStage::OriginalCaptured
            || self.first_failure.is_some()
            || self.until != p.until
        {
            return Err(invalid());
        }
        self.stage = InitialCoalescenceStage::BeforeQuarantine;
        let island = site.island.ok_or_else(invalid)?;
        let stop = native.admission_current(site.root)?;
        self.before_stop = Some(stop.clone());
        if stop.phase != AdmissionPhase::Restored || stop.identity.generation != 0 {
            return Err(invalid());
        }
        runner::ready(owner, native, p, &stop, Some(island))?;
        self.states[0].capture(owner, self.until)?;
        self.maps[0]
            .as_mut()
            .ok_or_else(invalid)?
            .capture(owner, self.until)?;
        if self.states[0].state != p.states[RESTORED].state
            || self.maps[0].as_ref().ok_or_else(invalid)?.bytes() != p.current_maps.bytes()
        {
            return Err(invalid());
        }
        self.plan.verify_snapshot(
            original,
            self.maps[0].as_ref().ok_or_else(invalid)?.bytes(),
            &island.range,
            self.plan.target_executable_ordinal(),
        )?;
        native.require_admission_stop(&stop)?;
        physical(owner, self.until)?;
        self.stage = InitialCoalescenceStage::Quarantine;
        Ok(())
    }
    pub(super) fn call_observation(
        &mut self,
    ) -> Result<&mut CoalescenceCallObservation, LaunchError> {
        if self.stage != InitialCoalescenceStage::Quarantine || self.call.wait.is_some() {
            return Err(invalid());
        }
        Ok(&mut self.call)
    }
    pub(super) fn after_quarantine(
        &mut self,
        owner: &Owner,
        native: &lifecycle::NativeLifecycle,
        p: &mut PreparedInitialBootstrap,
        original: &[u8],
        site: runner::Site<'_>,
    ) -> Result<(), LaunchError> {
        self.require_original(original)?;
        if self.stage != InitialCoalescenceStage::Quarantine {
            return Err(invalid());
        }
        self.stage = InitialCoalescenceStage::AfterQuarantine;
        let island = site.island.ok_or_else(invalid)?;
        let stop = native.admission_current(site.root)?;
        self.after_stop = Some(stop.clone());
        self.states[1].capture(owner, self.until)?;
        self.maps[1]
            .as_mut()
            .ok_or_else(invalid)?
            .capture(owner, self.until)?;
        let before = self.before_stop.as_ref().ok_or_else(invalid)?;
        if stop.phase != AdmissionPhase::Restored
            || stop.identity != before.identity
            || stop.token.session != before.token.session
            || stop.token.tid != before.token.tid
            || stop.token.task != before.token.task
            || stop.token.sequence != before.token.sequence.checked_add(1).ok_or_else(invalid)?
            || stop.signal.is_some()
            || before.signal.is_some()
            || self.states[0].state != self.states[1].state
            || self.states[0].state != p.states[SAVED].state
            || self.states[1].state != p.states[RESTORED].state
            || self.maps[1].as_ref().ok_or_else(invalid)?.bytes() != p.current_maps.bytes()
        {
            return Err(invalid());
        }
        self.call.validate(owner.pid, self.states[0].state.mask)?;
        self.projection = Some(self.plan.verify_transition(
            original,
            self.maps[0].as_ref().ok_or_else(invalid)?.bytes(),
            self.maps[1].as_ref().ok_or_else(invalid)?.bytes(),
            &island.range,
        )?);
        native.require_admission_stop(&stop)?;
        runner::ready(owner, native, p, &stop, Some(island))?;
        if self.maps[1].as_ref().ok_or_else(invalid)?.bytes() != p.current_maps.bytes() {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn finish_capture(
        &mut self,
        owner: &Owner,
        native: &lifecycle::NativeLifecycle,
        p: &mut PreparedInitialBootstrap,
        checkpoint: FinalCheckpoint<'_>,
    ) -> Result<(), LaunchError> {
        let FinalCheckpoint {
            original,
            island,
            stop,
            scratch,
        } = checkpoint;
        self.require_original(original)?;
        if self.stage != InitialCoalescenceStage::AfterQuarantine
            || self.first_failure.is_some()
            || self.projection.is_none()
        {
            return Err(invalid());
        }
        self.stage = InitialCoalescenceStage::FinalRead;
        self.final_stop = Some(stop.clone());
        let after = self.after_stop.as_ref().ok_or_else(invalid)?;
        if stop.phase != AdmissionPhase::Restored
            || stop.identity != after.identity
            || stop.token.session != after.token.session
            || stop.token.tid != after.token.tid
            || stop.token.task != after.token.task
            || stop.token.sequence
                != after
                    .token
                    .sequence
                    .checked_add(
                        u64::try_from(
                            self.plan.executable_count() - self.plan.target_executable_ordinal(),
                        )
                        .map_err(|_| invalid())?,
                    )
                    .ok_or_else(invalid)?
            || stop.signal.is_some()
            || p.states[READBACK].state != p.states[RESTORED].state
        {
            return Err(invalid());
        }
        let projection = self.plan.verify_snapshot(
            original,
            p.current_maps.bytes(),
            &island.range,
            self.plan.executable_count(),
        )?;
        let immediate_island = parse(self.maps[1].as_ref().ok_or_else(invalid)?.bytes())?
            .entries()
            .find(|row| row.start == island.range.start && row.end == island.range.end)
            .ok_or_else(invalid)?;
        let final_island = parse(p.current_maps.bytes())?
            .entries()
            .find(|row| row.start == island.range.start && row.end == island.range.end)
            .ok_or_else(invalid)?;
        if immediate_island.raw_line != final_island.raw_line {
            return Err(invalid());
        }
        let checkpoint = InitialSourceCheckpoint {
            stop,
            island,
            state: &p.states[RESTORED].state,
            maps: p.current_maps.bytes(),
        };
        let read =
            InitialCheckpointSourceRead::acquire(owner, native, checkpoint, scratch, self.until)
                .map_err(native_error)?;
        read.read_memory_capture(
            self.plan.pair_range().start,
            &mut self.final_bytes,
            &mut self.read_progress[1],
        )
        .map_err(native_error)?;
        require_read(&self.read_progress[1], self.plan.pair_range().start)?;
        if self.original_bytes != self.final_bytes {
            return Err(invalid());
        }
        self.maps[2]
            .as_mut()
            .ok_or_else(invalid)?
            .capture(owner, self.until)?;
        if self.maps[2].as_ref().ok_or_else(invalid)?.bytes() != p.current_maps.bytes() {
            return Err(invalid());
        }
        p.states[READBACK].capture(owner, self.until)?;
        if p.states[READBACK].state != p.states[RESTORED].state {
            return Err(invalid());
        }
        native.require_admission_stop(stop)?;
        runner::ready(owner, native, p, stop, Some(island))?;
        if self.maps[2].as_ref().ok_or_else(invalid)?.bytes() != p.current_maps.bytes() {
            return Err(invalid());
        }
        self.projection = Some(projection);
        self.stage = InitialCoalescenceStage::FinalCaptured;
        Ok(())
    }

    pub(super) fn install_descriptors(
        &mut self,
        p: &mut PreparedInitialBootstrap,
        original: &[u8],
        island: &TrustedIsland,
    ) -> Result<(), LaunchError> {
        self.require_original(original)?;
        if self.stage != InitialCoalescenceStage::FinalCaptured
            || !self.output.is_empty()
            || !self.retired_descriptors.is_empty()
            || self.output_transferred
        {
            return Err(invalid());
        }
        self.stage = InitialCoalescenceStage::Descriptors;
        let projection = self.projection.as_ref().ok_or_else(invalid)?;
        let final_maps = self.maps[2].as_ref().ok_or_else(invalid)?;
        let view = projection.view(original, final_maps.bytes(), &island.range)?;
        // Validate both full prepaid inventories before moving the first owner.
        if self.pool.len() != view.originals().entries().len()
            || self.pool.capacity() != self.plan.original_rows()
            || self.output.capacity() != self.plan.original_rows() + 1
            || p.mappings.len() != view.originals().entries().len()
        {
            return Err(invalid());
        }
        for (index, raw) in view.originals().entries().enumerate() {
            let row = self.pool[index].as_ref().ok_or_else(invalid)?;
            if !descriptor_matches(row, raw, false)?
                || !descriptor_matches(&p.mappings[index], raw, false)?
            {
                return Err(invalid());
            }
        }
        let island_row = p.island_row.as_ref().ok_or_else(invalid)?;
        if island_row.permissions != "r-xp"
            || island_row.pathname.is_some()
            || island_row.permissions.capacity() != 4
            || island_row.file_offset != 0
        {
            return Err(invalid());
        }
        for (index, actual) in view.current().entries().enumerate() {
            if self.output.len() == self.output.capacity() {
                return Err(invalid());
            }
            if let Some(source) = view.descriptor_pool_index(index)? {
                let row = self
                    .pool
                    .get_mut(source)
                    .and_then(Option::as_mut)
                    .ok_or_else(invalid)?;
                // Exact projection already proves all other fields unchanged.
                row.end = actual.end;
                let permissions = actual.permissions.bytes();
                let text = std::str::from_utf8(&permissions).map_err(|_| invalid())?;
                row.permissions.clear();
                row.permissions.push_str(text);
                if !descriptor_matches(row, actual, false)? {
                    return Err(invalid());
                }
                self.output
                    .push(self.pool[source].take().ok_or_else(invalid)?);
            } else {
                let row = p.island_row.as_mut().ok_or_else(invalid)?;
                row.start = island.range.start;
                row.end = island.range.end;
                if !descriptor_matches(row, actual, false)? {
                    return Err(invalid());
                }
                self.borrowed_island_payload = row.permissions.capacity();
                self.output.push(p.island_row.take().ok_or_else(invalid)?);
            }
        }
        self.validate_allocations(None)?;
        // Both owners remain installed. There is no allocation or drop here.
        self.retired_descriptors =
            std::mem::replace(&mut p.mappings, std::mem::take(&mut self.output));
        self.output_transferred = true;
        self.validate_allocations(Some(&p.mappings))?;
        self.stage = InitialCoalescenceStage::Complete;
        Ok(())
    }

    /// Actual currently owned payload. The complete root sum also includes
    /// BootstrapMm's transferred output; old mappings now retained here still
    /// count exactly once under their original bootstrap reservation.
    pub(in crate::linux::remote::dynamic::owner) fn allocated_bytes(
        &self,
    ) -> Result<usize, LaunchError> {
        let mut bytes = add(self.original_bytes.capacity(), self.final_bytes.capacity())?;
        for map in &self.maps {
            if map.is_some() {
                bytes = add(bytes, MAP_BYTES)?;
            }
        }
        for state in &self.states {
            bytes = add(bytes, state.state.xstate.capacity())?;
        }
        bytes = add(
            bytes,
            mul(self.pool.capacity(), size_of::<Option<MemoryMapping>>())?,
        )?;
        for row in self.pool.iter().flatten() {
            bytes = add(bytes, storage::mapping_bytes(row)?)?;
        }
        bytes = add(bytes, storage::mappings_bytes(&self.output)?)?;
        add(bytes, storage::mappings_bytes(&self.retired_descriptors)?)
    }
    pub(in crate::linux::remote::dynamic::owner) fn validate_allocations(
        &self,
        external_ready_mappings: Option<&Vec<MemoryMapping>>,
    ) -> Result<(), LaunchError> {
        if self.output_transferred != external_ready_mappings.is_some() {
            return Err(invalid());
        }
        let mut own_new = self
            .allocated_bytes()?
            .checked_sub(storage::mappings_bytes(&self.retired_descriptors)?)
            .ok_or_else(invalid)?;
        if let Some(external) = external_ready_mappings {
            own_new = add(own_new, storage::mappings_bytes(external)?)?;
        }
        own_new = own_new
            .checked_sub(self.borrowed_island_payload)
            .ok_or_else(invalid)?;
        if own_new != self.successful_payload_bytes
            || add(own_new, Self::temporary_bytes())? > self.reserved_payload_bytes
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(in crate::linux::remote::dynamic::owner) fn fail_gate(&mut self, error: &crate::GateError) {
        match error {
            crate::GateError::Control(error) => self.fail(Some(error)),
            crate::GateError::Refused(reason) => self.fail(Some(&LaunchError::Invalid(reason))),
            _ => self.fail(Some(&LaunchError::Invalid(
                "initial coalescence startup refused",
            ))),
        }
    }

    pub(in crate::linux::remote::dynamic::owner) fn fail(&mut self, error: Option<&LaunchError>) {
        if self.first_failure.is_some() {
            return;
        }
        self.first_failure = Some(match error {
            Some(LaunchError::Invalid(reason)) => InitialBootstrapFailureKind::Invalid(reason),
            Some(LaunchError::System { operation, source }) => {
                InitialBootstrapFailureKind::System(operation, source.raw_os_error())
            }
            Some(LaunchError::Timeout(reason)) => InitialBootstrapFailureKind::Timeout(reason),
            Some(LaunchError::Child { status }) => InitialBootstrapFailureKind::Child(*status),
            None => InitialBootstrapFailureKind::Unwound,
        });
    }

    pub(in crate::linux::remote::dynamic::owner) fn completed<'a>(
        &'a self,
        boot: &'a BootstrapMm,
    ) -> Result<CompletedInitialCoalescence<'a>, LaunchError> {
        if self.stage != InitialCoalescenceStage::Complete
            || self.first_failure.is_some()
            || self.final_stop.as_ref() != Some(&boot.stop)
            || !self.output_transferred
            || self.states.iter().any(|state| !state.complete)
            || self
                .maps
                .iter()
                .any(|map| map.as_ref().is_none_or(|map| !map.complete))
            || self.original_bytes != self.final_bytes
        {
            return Err(invalid());
        }
        require_read(&self.read_progress[0], self.plan.pair_range().start)?;
        require_read(&self.read_progress[1], self.plan.pair_range().start)?;
        self.validate_allocations(Some(&boot.mappings))?;
        let projection = self.projection.as_ref().ok_or_else(invalid)?;
        if projection.cleared_prefix() != self.plan.executable_count() {
            return Err(invalid());
        }
        Ok(CompletedInitialCoalescence {
            prepared: self,
            boot,
        })
    }
}

pub(super) struct FinalCheckpoint<'a> {
    pub(super) original: &'a [u8],
    pub(super) island: &'a TrustedIsland,
    pub(super) stop: &'a AdmissionStop,
    pub(super) scratch: &'a InitialReadScratch,
}

fn require_read(progress: &SourceReadProgress, start: u64) -> Result<(), LaunchError> {
    if !progress.started
        || !progress.attempted
        || !progress.complete
        || progress.failure.is_some()
        || progress.requested_bytes != PAIR_BYTES
        || progress.copied_bytes != PAIR_BYTES
        || progress.filesystem_type.is_some()
        || progress.last_request.is_none_or(|request| {
            request.errno.is_some()
                || request.operation != SourceReadOperation::PeekMemory
                || request.count != 8
                || Some(request.address) != start.checked_add((PAIR_BYTES - 8) as u64)
        })
    {
        return Err(invalid());
    }
    Ok(())
}

/// Borrow only, privately constructed after the genuine producer completed.
pub(in crate::linux::remote::dynamic::owner) struct CompletedInitialCoalescence<'a> {
    prepared: &'a PreparedInitialCoalescence,
    boot: &'a BootstrapMm,
}
impl CompletedInitialCoalescence<'_> {
    pub(in crate::linux::remote::dynamic::owner) fn original_maps<'a>(
        &self,
        original: &'a [u8],
    ) -> Result<&'a [u8], LaunchError> {
        self.prepared.require_original(original)?;
        self.projection()
            .view(original, self.final_maps(), &self.boot.island.range)?;
        Ok(original)
    }
    pub(in crate::linux::remote::dynamic::owner) fn final_maps(&self) -> &[u8] {
        // Private constructor established Some and complete; no mutable borrow
        // of the installed owner can coexist with this completed view.
        self.prepared.maps[2]
            .as_ref()
            .expect("completed map storage")
            .bytes()
    }
    pub(in crate::linux::remote::dynamic::owner) fn projection(&self) -> &InitialMapProjection {
        self.prepared
            .projection
            .as_ref()
            .expect("completed map projection")
    }
    pub(in crate::linux::remote::dynamic::owner) fn until(&self) -> Instant {
        self.prepared.until
    }
    pub(in crate::linux::remote::dynamic::owner) fn final_stop(&self) -> &AdmissionStop {
        &self.boot.stop
    }
}

#[cfg(test)]
pub(in crate::linux::remote::dynamic::owner) struct InitialCoalescenceDiagnostics<'a> {
    pub(in crate::linux::remote::dynamic::owner) plan: &'a InitialMapPlan,
    pub(in crate::linux::remote::dynamic::owner) projection: Option<&'a InitialMapProjection>,
    pub(in crate::linux::remote::dynamic::owner) stage: InitialCoalescenceStage,
    pub(in crate::linux::remote::dynamic::owner) first_failure: Option<InitialBootstrapFailureKind>,
    pub(in crate::linux::remote::dynamic::owner) original_bytes: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner) final_bytes: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner) read_progress: &'a [SourceReadProgress; 2],
    pub(in crate::linux::remote::dynamic::owner) maps: &'a [Option<MapBuffer>; 3],
    pub(in crate::linux::remote::dynamic::owner) states: &'a [StateSlot; 2],
    pub(in crate::linux::remote::dynamic::owner) before_stop: Option<&'a AdmissionStop>,
    pub(in crate::linux::remote::dynamic::owner) after_stop: Option<&'a AdmissionStop>,
    pub(in crate::linux::remote::dynamic::owner) final_stop: Option<&'a AdmissionStop>,
    pub(in crate::linux::remote::dynamic::owner) call: &'a CoalescenceCallObservation,
    pub(in crate::linux::remote::dynamic::owner) pool: &'a [Option<MemoryMapping>],
    pub(in crate::linux::remote::dynamic::owner) output: &'a [MemoryMapping],
    pub(in crate::linux::remote::dynamic::owner) retired_descriptors: &'a [MemoryMapping],
    pub(in crate::linux::remote::dynamic::owner) pool_capacity: usize,
    pub(in crate::linux::remote::dynamic::owner) output_capacity: usize,
    pub(in crate::linux::remote::dynamic::owner) retired_capacity: usize,
    pub(in crate::linux::remote::dynamic::owner) output_transferred: bool,
    pub(in crate::linux::remote::dynamic::owner) original_capacity: usize,
    pub(in crate::linux::remote::dynamic::owner) final_capacity: usize,
    pub(in crate::linux::remote::dynamic::owner) successful_payload_bytes: usize,
    pub(in crate::linux::remote::dynamic::owner) reserved_payload_bytes: usize,
}
#[cfg(test)]
impl PreparedInitialCoalescence {
    pub(in crate::linux::remote::dynamic::owner) fn diagnostics(
        &self,
    ) -> InitialCoalescenceDiagnostics<'_> {
        InitialCoalescenceDiagnostics {
            plan: &self.plan,
            projection: self.projection.as_ref(),
            stage: self.stage,
            first_failure: self.first_failure,
            original_bytes: &self.original_bytes,
            final_bytes: &self.final_bytes,
            read_progress: &self.read_progress,
            maps: &self.maps,
            states: &self.states,
            before_stop: self.before_stop.as_ref(),
            after_stop: self.after_stop.as_ref(),
            final_stop: self.final_stop.as_ref(),
            call: &self.call,
            pool: &self.pool,
            output: &self.output,
            retired_descriptors: &self.retired_descriptors,
            pool_capacity: self.pool.capacity(),
            output_capacity: self.output.capacity(),
            retired_capacity: self.retired_descriptors.capacity(),
            output_transferred: self.output_transferred,
            original_capacity: self.original_bytes.capacity(),
            final_capacity: self.final_bytes.capacity(),
            successful_payload_bytes: self.successful_payload_bytes,
            reserved_payload_bytes: self.reserved_payload_bytes,
        }
    }
}
