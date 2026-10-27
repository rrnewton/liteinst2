//! Full own-lane observations. Caller descriptions never create an admitted
//! stack identity, origin, lifecycle checkpoint or native completion seal.
use super::{
    OracleError,
    artifact::{ArtifactPlan, PlannedKind},
    dataflow::{self, FrameObservation},
};
use crate::linux::remote::dynamic::owner::admission::runtime_native::ControlProfile;
use crate::linux::remote::dynamic::owner::admission::runtime_stack::StackError;
use crate::linux::remote::dynamic::owner::admission::runtime_stack::access::{
    CPUID_INPUTS, CpuidRecord, PagemapObservation, PkuLayout, PkuLayoutEvidence, validate_state,
};
use crate::linux::remote::dynamic::owner::admission::runtime_stack::metadata::validate_smaps;
use crate::linux::remote::dynamic::owner::admission::{exact_storage, source_identity};
use crate::linux::remote::dynamic::owner::trusted::TaskStateSnapshot;
use crate::linux::remote::dynamic::owner::{
    Owner,
    bootstrap::{self, StateSlot},
};
use crate::linux::remote::dynamic::{DynamicEvent, DynamicEventKind};
use std::{mem::size_of, ops::Range, time::Instant};
pub(super) mod io;
use io::IoBuffer;
#[cfg(test)]
mod tests;
const MAX: usize = 64 * 1024;
const FRAMES: usize = 70;
const STACK_CAP: usize = 1024 * 1024;

pub(super) fn empty_state() -> StateSlot {
    // SAFETY: all-zero user_regs_struct is initialized scalar storage only;
    // no successful read or authority is claimed by this empty slot.
    let registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    StateSlot {
        state: TaskStateSnapshot {
            registers: registers.into(),
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
pub(super) fn allocate_state(state: &mut StateSlot) -> Result<(), OracleError> {
    if state.state.xstate.capacity() != 0 || state.complete {
        return Err(OracleError::Invalid("oracle state allocation reused"));
    }
    state.state.xstate = exact_storage::empty_bytes(MAX)
        .map_err(|_| OracleError::Invalid("oracle state allocation failed"))?;
    state.state.xstate.resize(MAX, 0);
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DebugExpectation {
    Initial,
    Trace,
}
impl DebugExpectation {
    fn value(self) -> u64 {
        match self {
            Self::Initial => 0xffff_0ff0,
            Self::Trace => 0xffff_4ff0,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RawStackDescription {
    pub(super) range: Range<u64>,
    pub(super) index: usize,
    pub(super) original_rsp: u64,
}
fn stack_description(maps: &[u8], rsp: u64) -> Result<RawStackDescription, OracleError> {
    if rsp == 0 || rsp % 16 != 0 || rsp >= 0x0000_8000_0000_0000 {
        return Err(OracleError::Invalid("oracle initial stack ABI differs"));
    }
    let parsed = source_identity::parse(maps)?;
    let mut found = None;
    for (index, row) in parsed.entries().enumerate() {
        if row.start <= rsp && rsp < row.end {
            if found.is_some()
                || row.start == 0
                || row.start % 4096 != 0
                || row.end % 4096 != 0
                || row.end > 0x0000_8000_0000_0000
                || row.end - row.start > STACK_CAP as u64
                || row.permissions.bytes() != *b"rw-p"
                || row.file_offset != 0
                || row.device_major != 0
                || row.device_minor != 0
                || row.inode != 0
                || rsp.checked_sub(8).is_none_or(|slot| slot < row.start)
            {
                return Err(OracleError::Invalid(
                    "oracle original anonymous stack row differs",
                ));
            }
            found = Some(RawStackDescription {
                range: row.start..row.end,
                index,
                original_rsp: rsp,
            });
        }
    }
    found.ok_or(OracleError::Invalid("oracle original stack absent"))
}
fn layout() -> PkuLayoutEvidence {
    let mut result = PkuLayoutEvidence::default();
    for (index, (leaf, subleaf)) in CPUID_INPUTS.into_iter().enumerate() {
        // SAFETY: native x86-64 provides CPUID; the closed validator checks
        // the retained leaves. Rust 1.85 requires unsafe; newer Rust makes it safe.
        #[allow(unused_unsafe)]
        let value = unsafe { std::arch::x86_64::__cpuid_count(leaf, subleaf) };
        result.records[index] = Some(CpuidRecord {
            leaf,
            subleaf,
            registers: [value.eax, value.ebx, value.ecx, value.edx],
        });
    }
    result
}
fn state_capture(owner: &Owner, state: &mut StateSlot, until: Instant) -> Result<(), OracleError> {
    if state.state.xstate.capacity() != MAX
        || state.registers_request.is_some()
        || state.xstate_request.is_some()
        || state.mask_request.is_some()
    {
        return Err(OracleError::Invalid(
            "oracle state capture unallocated or reused",
        ));
    }
    bootstrap::physical(owner, until)?;
    let result = state.capture(owner, until);
    let held = bootstrap::physical(owner, until);
    result?;
    held?;
    Ok(())
}
struct AccessCapture<'a> {
    stack: &'a RawStackDescription,
    state: &'a StateSlot,
    cpuid: &'a mut PkuLayoutEvidence,
    smaps: &'a mut IoBuffer,
    pagemap: &'a mut IoBuffer,
    maps: &'a [u8],
}
/// Pure validation of a retained actual user-state read. It creates no held
/// stop or stack authority; callers must independently bind the physical phase.
pub(super) fn require_user_state(
    state: &StateSlot,
    cpuid: &PkuLayoutEvidence,
) -> Result<(), OracleError> {
    let layout = cpuid
        .validate()
        .map_err(|_| OracleError::Invalid("oracle PKU layout differs"))?;
    validate_state(state, layout).map_err(|error| match error {
        StackError::Request => OracleError::Invalid("oracle user-state request evidence differs"),
        StackError::Xstate => OracleError::Invalid("oracle user-state XSTATE or PKRU differs"),
        StackError::Mode => OracleError::Invalid("oracle user-state mode or flags differ"),
        _ => OracleError::Invalid("oracle user-state validation differs"),
    })?;
    Ok(())
}
fn access(owner: &Owner, capture: AccessCapture<'_>, until: Instant) -> Result<(), OracleError> {
    bootstrap::physical(owner, until)?;
    *capture.cpuid = layout();
    require_user_state(capture.state, capture.cpuid)?;
    mapping_access(owner, capture, until)
}
/// EXEC is before the existing first-user INT3 bridge. Its full state remains
/// retained and compared to exec EXIT, but is not a user-access qualification.
fn exec_access(
    owner: &Owner,
    capture: AccessCapture<'_>,
    until: Instant,
) -> Result<(), OracleError> {
    bootstrap::physical(owner, until)?;
    *capture.cpuid = layout();
    capture
        .cpuid
        .validate()
        .map_err(|_| OracleError::Invalid("oracle PKU layout differs"))?;
    mapping_access(owner, capture, until)
}
fn mapping_access(
    owner: &Owner,
    capture: AccessCapture<'_>,
    until: Instant,
) -> Result<(), OracleError> {
    let AccessCapture {
        stack,
        state: _,
        cpuid: _,
        smaps,
        pagemap,
        maps,
    } = capture;
    smaps.read_proc(owner, c"smaps", until)?;
    validate_smaps(smaps.prefix(), maps, stack.index)
        .map_err(|_| OracleError::Invalid("oracle actual stack smaps differs"))?;
    let slot = stack
        .original_rsp
        .checked_sub(8)
        .ok_or(OracleError::Invalid("oracle stack slot underflows"))?;
    // Original RSP is16-aligned; [S-8,S) is exactly one natural page word.
    let offset = (slot / 4096)
        .checked_mul(8)
        .ok_or(OracleError::Invalid("oracle pagemap offset overflows"))?;
    pagemap.read_pagemap(owner, offset, until)?;
    let read = pagemap.reads[0].ok_or(OracleError::Invalid("oracle pagemap read absent"))?;
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(pagemap.prefix());
    let observed = PagemapObservation {
        fd: pagemap
            .opened
            .ok_or(OracleError::Invalid("oracle pagemap open absent"))?
            .result as i32,
        offset,
        requested: 8,
        copied: pagemap.copied,
        bytes,
        request: Some(crate::linux::remote::dynamic::owner::bootstrap::Request {
            result: read.result.result,
            errno: (read.result.errno != 0).then_some(read.result.errno),
        }),
    };
    observed
        .validate(&(slot..stack.original_rsp))
        .map_err(|_| {
            OracleError::Invalid("oracle natural stack word is not resident and exclusive")
        })?;
    bootstrap::physical(owner, until)?;
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetadataPhase {
    ExecEvent,
    RestoredUser,
}
pub(super) struct Metadata {
    pub(super) state: StateSlot,
    pub(super) maps: IoBuffer,
    pub(super) source: IoBuffer,
    pub(super) smaps: IoBuffer,
    pub(super) pagemap: IoBuffer,
    pub(super) layout: PkuLayoutEvidence,
    pub(super) profile: Option<Box<ControlProfile>>,
    pub(super) stack: Option<RawStackDescription>,
    phase: Option<MetadataPhase>,
    /// All observations for `phase` completed. ExecEvent is never user access.
    pub(super) complete: bool,
}
impl Metadata {
    fn empty() -> Self {
        Self {
            state: empty_state(),
            maps: IoBuffer::empty(),
            source: IoBuffer::empty(),
            smaps: IoBuffer::empty(),
            pagemap: IoBuffer::empty(),
            layout: PkuLayoutEvidence::default(),
            profile: None,
            stack: None,
            phase: None,
            complete: false,
        }
    }
    fn allocate(&mut self) -> Result<(), OracleError> {
        allocate_state(&mut self.state)?;
        self.maps.allocate_payload(MAX)?;
        self.source.allocate_payload(8192)?;
        self.smaps.allocate_payload(MAX)?;
        self.pagemap.allocate_payload(8)?;
        self.profile = Some(
            exact_storage::value(ControlProfile::default())
                .map_err(|_| OracleError::Invalid("oracle control allocation failed"))?,
        );
        Ok(())
    }
    fn capture(
        &mut self,
        owner: &Owner,
        plan: &ArtifactPlan,
        file: &[u8],
        debug: DebugExpectation,
        phase: MetadataPhase,
        until: Instant,
    ) -> Result<(), OracleError> {
        if self.phase.is_some() || self.complete || self.maps.started || !self.allocated() {
            return Err(OracleError::Invalid(
                "oracle metadata capture unallocated or reused",
            ));
        }
        self.phase = Some(phase);
        state_capture(owner, &mut self.state, until)?;
        self.maps.read_proc(owner, c"maps", until)?;
        self.stack = Some(stack_description(
            self.maps.prefix(),
            self.state.state.registers.rsp,
        )?);
        let stack = self.stack.as_ref().unwrap();
        let capture = AccessCapture {
            stack,
            state: &self.state,
            cpuid: &mut self.layout,
            smaps: &mut self.smaps,
            pagemap: &mut self.pagemap,
            maps: self.maps.prefix(),
        };
        match phase {
            MetadataPhase::ExecEvent => exec_access(owner, capture, until)?,
            MetadataPhase::RestoredUser => access(owner, capture, until)?,
        }
        let profile = self
            .profile
            .as_mut()
            .ok_or(OracleError::Invalid("oracle control storage absent"))?;
        profile.capture(owner, until)?;
        profile.require(debug.value())?;
        self.source
            .read_memory(owner, plan.read_load.start, until)?;
        plan.require_image(file, self.source.prefix())?;
        self.complete = true;
        Ok(())
    }
    fn require_user_access(&self) -> Result<(), OracleError> {
        if !self.complete || self.phase != Some(MetadataPhase::RestoredUser) {
            return Err(OracleError::Invalid(
                "oracle metadata is not restored user access",
            ));
        }
        require_user_state(&self.state, &self.layout)
    }
    fn allocated(&self) -> bool {
        self.state.state.xstate.capacity() == MAX
            && self.maps.bytes.capacity() == MAX
            && self.source.bytes.capacity() == 8192
            && self.smaps.bytes.capacity() == MAX
            && self.pagemap.bytes.capacity() == 8
            && self.profile.is_some()
    }
    fn payload_bytes(&self) -> usize {
        self.state.state.xstate.capacity()
            + self.maps.bytes.capacity()
            + self.source.bytes.capacity()
            + self.smaps.bytes.capacity()
            + self.pagemap.bytes.capacity()
            + self
                .profile
                .as_ref()
                .map_or(0, |_| size_of::<ControlProfile>())
    }
}
pub(super) struct Frame {
    pub(super) state: StateSlot,
    pub(super) maps: IoBuffer,
    pub(super) source: IoBuffer,
    pub(super) stack: IoBuffer,
    pub(super) smaps: IoBuffer,
    pub(super) pagemap: IoBuffer,
    pub(super) layout: PkuLayoutEvidence,
    pub(super) profile: Option<Box<ControlProfile>>,
    pub(super) ordinal: usize,
    pub(super) after: bool,
    pub(super) until: Option<Instant>,
    pub(super) complete: bool,
}
impl Frame {
    fn empty(ordinal: usize, after: bool) -> Self {
        Self {
            state: empty_state(),
            maps: IoBuffer::empty(),
            source: IoBuffer::empty(),
            stack: IoBuffer::empty(),
            smaps: IoBuffer::empty(),
            pagemap: IoBuffer::empty(),
            layout: PkuLayoutEvidence::default(),
            profile: None,
            ordinal,
            after,
            until: None,
            complete: false,
        }
    }
    fn allocate(&mut self, stack: Option<usize>) -> Result<(), OracleError> {
        allocate_state(&mut self.state)?;
        self.maps.allocate_payload(MAX)?;
        self.source.allocate_payload(8192)?;
        if let Some(bytes) = stack {
            self.stack.allocate_payload(bytes)?;
            self.smaps.allocate_payload(MAX)?;
            self.pagemap.allocate_payload(8)?;
            self.profile = Some(
                exact_storage::value(ControlProfile::default())
                    .map_err(|_| OracleError::Invalid("oracle frame control allocation failed"))?,
            );
        }
        Ok(())
    }
    fn payload_bytes(&self) -> usize {
        self.state.state.xstate.capacity()
            + self.maps.bytes.capacity()
            + self.source.bytes.capacity()
            + self.stack.bytes.capacity()
            + self.smaps.bytes.capacity()
            + self.pagemap.bytes.capacity()
            + self
                .profile
                .as_ref()
                .map_or(0, |_| size_of::<ControlProfile>())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LaneShape {
    pub(super) stack_bytes: usize,
    pub(super) frames: usize,
    pub(super) retained_bytes: usize,
    pub(super) temporary_bytes: usize,
}
impl LaneShape {
    pub(super) fn for_plan(plan: &ArtifactPlan, stack_bytes: usize) -> Result<Self, OracleError> {
        if stack_bytes == 0 || stack_bytes > STACK_CAP || stack_bytes % 4096 != 0 || plan.len() > 35
        {
            return Err(OracleError::Invalid("oracle lane shape differs"));
        }
        let frames = plan
            .len()
            .checked_mul(2)
            .and_then(|v| v.checked_sub(1))
            .ok_or(OracleError::Invalid("oracle frame count overflows"))?;
        let metadata = 3 * MAX + 8192 + 8 + size_of::<ControlProfile>();
        let per = size_of::<Frame>() + 2 * MAX + 8192;
        let extra = stack_bytes + MAX + 8 + size_of::<ControlProfile>();
        let retained_bytes = size_of::<PreparedLane>()
            .checked_add(FRAMES * size_of::<Option<Box<Frame>>>())
            .and_then(|v| v.checked_add(metadata))
            .and_then(|v| v.checked_add(frames.checked_mul(per)?))
            .and_then(|v| v.checked_add(4 * extra))
            .ok_or(OracleError::Invalid("oracle lane capacity overflows"))?;
        let temporary_bytes = ControlProfile::temporary_bytes()?
            .checked_add(dataflow::temporary_bytes()?)
            .and_then(|n|n.checked_add(
                2*size_of::<ControlProfile>()+size_of::<PreparedLane>()+size_of::<Metadata>()+size_of::<Frame>()
                    +2*size_of::<libc::statfs>()+size_of::<libc::iovec>()+2*size_of::<RegisterSnapshot>()
                    +2*48+10+size_of::<PagemapObservation>()+2*size_of::<PkuLayoutEvidence>()
                    +size_of::<AccessCapture<'static>>()
                    // Additional phase/collector and nested pure-validator headers;
                    // retained header growth is already in PreparedLane/Metadata.
                    +size_of::<AccessCapture<'static>>()
                    +2*size_of::<MetadataPhase>()+size_of::<Option<MetadataPhase>>()
                    +size_of::<PkuLayout>()+size_of::<Result<PkuLayout, StackError>>()
                    +size_of::<Result<u32, StackError>>()+size_of::<StackError>()
                    +2*size_of::<Result<(), OracleError>>()+size_of::<OracleError>()
                    +size_of::<&StateSlot>()+size_of::<&PkuLayoutEvidence>()
                    +2*size_of::<&DynamicEvent>()
                    +size_of::<Result<&DynamicEvent, crate::LaunchError>>()
                    +4*size_of::<crate::linux::remote::dynamic::owner::admission::mapping::maps::MapEntry<'static>>()
                    +2*size_of::<crate::linux::remote::dynamic::owner::admission::mapping::maps::ParsedMaps<'static>>()
                    +32*size_of::<usize>()))
            .ok_or(OracleError::Invalid("oracle lane temporary overflows"))?;
        Ok(Self {
            stack_bytes,
            frames,
            retained_bytes,
            temporary_bytes,
        })
    }
}
use crate::RegisterSnapshot;
pub(super) struct PreparedLane {
    pub(super) metadata: Metadata,
    frames: Option<Box<[Option<Box<Frame>>]>>,
    shape: Option<LaneShape>,
    metadata_allocated: bool,
    frames_started: bool,
    allocated: bool,
    pub(super) completed: usize,
}
impl PreparedLane {
    pub(super) fn empty() -> Self {
        Self {
            metadata: Metadata::empty(),
            frames: None,
            shape: None,
            metadata_allocated: false,
            frames_started: false,
            allocated: false,
            completed: 0,
        }
    }
    pub(super) fn allocate_metadata(&mut self) -> Result<(), OracleError> {
        if self.metadata_allocated {
            return Err(OracleError::Invalid("oracle metadata allocation reused"));
        }
        self.metadata_allocated = true;
        self.metadata.allocate()
    }
    pub(super) fn capture_metadata(
        &mut self,
        owner: &Owner,
        plan: &ArtifactPlan,
        file: &[u8],
        debug: DebugExpectation,
        until: Instant,
    ) -> Result<(), OracleError> {
        // Admitted observation is always the restored-user route. No caller
        // can select EXEC here or use that phase to bypass user access.
        self.metadata
            .capture(owner, plan, file, debug, MetadataPhase::RestoredUser, until)?;
        self.metadata.require_user_access()?;
        if self
            .shape
            .is_some_and(|shape| self.observed_shape(plan).ok() != Some(shape))
        {
            return Err(OracleError::Invalid(
                "oracle supplied stack shape differs from actual metadata",
            ));
        }
        Ok(())
    }
    pub(super) fn capture_exec_metadata(
        &mut self,
        owner: &Owner,
        initial: &DynamicEvent,
        plan: &ArtifactPlan,
        file: &[u8],
        until: Instant,
    ) -> Result<(), OracleError> {
        if initial.tid != owner.pid || !matches!(initial.kind, DynamicEventKind::Exec { .. }) {
            return Err(OracleError::Invalid("oracle metadata is not actual EXEC"));
        }
        let token = initial
            .stop_token()
            .ok_or(OracleError::Invalid("oracle EXEC metadata token absent"))?;
        if owner.require_stop(token)? != initial {
            return Err(OracleError::Invalid("oracle EXEC metadata event differs"));
        }
        let result = self.metadata.capture(
            owner,
            plan,
            file,
            DebugExpectation::Initial,
            MetadataPhase::ExecEvent,
            until,
        );
        let held = owner.require_stop(token);
        result?;
        if held? != initial {
            return Err(OracleError::Invalid("oracle EXEC metadata event changed"));
        }
        Ok(())
    }
    pub(super) fn observed_shape(&self, plan: &ArtifactPlan) -> Result<LaneShape, OracleError> {
        if !self.metadata.complete {
            return Err(OracleError::Invalid("oracle metadata incomplete"));
        }
        let stack = self.metadata.stack.as_ref().unwrap();
        LaneShape::for_plan(plan, (stack.range.end - stack.range.start) as usize)
    }
    /// Admitted caller derives shape from real retained startup metadata and
    /// settles this entire owner before its first production reservation.
    pub(super) fn allocate_frames(
        &mut self,
        plan: &ArtifactPlan,
        shape: LaneShape,
    ) -> Result<(), OracleError> {
        if self.frames_started
            || !self.metadata.allocated()
            || shape != LaneShape::for_plan(plan, shape.stack_bytes)?
        {
            return Err(OracleError::Invalid(
                "oracle frame allocation reused or differs",
            ));
        }
        self.frames_started = true;
        self.shape = Some(shape);
        self.frames = Some(
            exact_storage::empty_slots(FRAMES)
                .map_err(|_| OracleError::Invalid("oracle frame slots allocation failed"))?,
        );
        let frames = self.frames.as_mut().unwrap();
        for (index, slot) in frames.iter_mut().enumerate().take(shape.frames) {
            let ordinal = index / 2;
            let after = index % 2 != 0;
            *slot = Some(
                exact_storage::value(Frame::empty(ordinal, after))
                    .map_err(|_| OracleError::Invalid("oracle frame header allocation failed"))?,
            );
            let stack = matches!(
                plan.instruction(ordinal)?.kind(),
                PlannedKind::Call | PlannedKind::Ret
            )
            .then_some(shape.stack_bytes);
            slot.as_mut().unwrap().allocate(stack)?;
        }
        self.allocated = true;
        Ok(())
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize, OracleError> {
        let mut result = size_of::<Self>()
            .checked_add(self.metadata.payload_bytes())
            .ok_or(OracleError::Invalid("oracle capacity overflows"))?;
        if let Some(frames) = &self.frames {
            result = result
                .checked_add(frames.len() * size_of::<Option<Box<Frame>>>())
                .ok_or(OracleError::Invalid("oracle slot bytes overflow"))?;
            for frame in frames.iter().flatten() {
                result = result
                    .checked_add(size_of::<Frame>() + frame.payload_bytes())
                    .ok_or(OracleError::Invalid("oracle frame bytes overflow"))?;
            }
        }
        Ok(result)
    }
    pub(super) fn frame(&self, ordinal: usize, after: bool) -> Result<&Frame, OracleError> {
        let index = ordinal
            .checked_mul(2)
            .and_then(|n| n.checked_add(usize::from(after)))
            .ok_or(OracleError::Invalid("oracle ordinal overflow"))?;
        self.frames
            .as_ref()
            .and_then(|v| v.get(index))
            .and_then(Option::as_deref)
            .ok_or(OracleError::Invalid("oracle frame absent"))
    }
    pub(super) fn capture(
        &mut self,
        owner: &Owner,
        plan: &ArtifactPlan,
        ordinal: usize,
        after: bool,
        debug: DebugExpectation,
        until: Instant,
    ) -> Result<(), OracleError> {
        if !self.allocated
            || !self.metadata.complete
            || self.shape != Some(self.observed_shape(plan)?)
        {
            return Err(OracleError::Invalid("oracle observations unprepared"));
        }
        let index = ordinal
            .checked_mul(2)
            .and_then(|n| n.checked_add(usize::from(after)))
            .ok_or(OracleError::Invalid("oracle ordinal overflow"))?;
        if index != self.completed {
            return Err(OracleError::Invalid("oracle observation order differs"));
        }
        let frame = self
            .frames
            .as_mut()
            .unwrap()
            .get_mut(index)
            .and_then(Option::as_deref_mut)
            .ok_or(OracleError::Invalid("oracle frame absent"))?;
        if frame.until.is_some() {
            return Err(OracleError::Invalid("oracle frame reused"));
        }
        frame.until = Some(until);
        state_capture(owner, &mut frame.state, until)?;
        frame.maps.read_proc(owner, c"maps", until)?;
        if frame.maps.prefix() != self.metadata.maps.prefix() {
            return Err(OracleError::Invalid("oracle complete maps changed"));
        }
        let stack = self.metadata.stack.as_ref().unwrap();
        if !frame.stack.bytes.is_empty() {
            access(
                owner,
                AccessCapture {
                    stack,
                    state: &frame.state,
                    cpuid: &mut frame.layout,
                    smaps: &mut frame.smaps,
                    pagemap: &mut frame.pagemap,
                    maps: frame.maps.prefix(),
                },
                until,
            )?;
            if frame
                .layout
                .validate()
                .map_err(|_| OracleError::Invalid("oracle layout incomplete"))?
                != self
                    .metadata
                    .layout
                    .validate()
                    .map_err(|_| OracleError::Invalid("oracle initial layout incomplete"))?
            {
                return Err(OracleError::Invalid("oracle PKU layout changed"));
            }
            let profile = frame.profile.as_mut().unwrap();
            profile.capture(owner, until)?;
            profile.require(debug.value())?;
            // Every actual metadata/access/pagemap check precedes this first
            // possible stack-data touch. Natural refusal has no retry/seed.
            frame.stack.read_memory(owner, stack.range.start, until)?;
        }
        frame
            .source
            .read_memory(owner, plan.read_load.start, until)?;
        if frame.source.prefix() != self.metadata.source.prefix() {
            return Err(OracleError::Invalid(
                "oracle full actual source pages changed",
            ));
        }
        frame.complete = true;
        if !after && ordinal != 0 {
            let previous = &self.frame(ordinal - 1, true)?.state.state;
            let current = &self.frame(ordinal, false)?.state.state;
            if previous.registers != current.registers
                || previous.xstate != current.xstate
                || previous.mask != current.mask
            {
                return Err(OracleError::Invalid(
                    "oracle intervening full state changed",
                ));
            }
        }
        self.completed += 1;
        Ok(())
    }
    /// Post-cleanup validation reads only retained evidence. Physical terminal
    /// completion and committed CALL/census snapshots are separate obligations.
    pub(super) fn require_complete(
        &self,
        plan: &ArtifactPlan,
        contract: &dataflow::DataflowContract,
        frame: FrameObservation,
        actual_pid: i32,
    ) -> Result<(), OracleError> {
        if !self.allocated
            || !self.metadata.complete
            || self.shape != Some(self.observed_shape(plan)?)
            || self.completed != 2 * plan.len() - 1
        {
            return Err(OracleError::Invalid("oracle full lane incomplete"));
        }
        let shape = self.shape.unwrap();
        if self.allocated_bytes()? != shape.retained_bytes {
            return Err(OracleError::Invalid("oracle full allocation differs"));
        }
        for instruction in plan.instructions() {
            let ordinal = instruction.ordinal();
            let before = self.frame(ordinal, false)?;
            if !before.complete
                || before.ordinal != ordinal
                || before.after
                || before.until.is_none()
                || before.state.state.registers.rip != instruction.pc()
            {
                return Err(OracleError::Invalid(
                    "oracle complete before observation differs",
                ));
            }
            if ordinal != 0 {
                let prior = &self.frame(ordinal - 1, true)?.state.state;
                let current = &before.state.state;
                if prior.registers != current.registers
                    || prior.xstate != current.xstate
                    || prior.mask != current.mask
                {
                    return Err(OracleError::Invalid("oracle complete state chain differs"));
                }
            }
            if matches!(instruction.kind(), PlannedKind::Syscall { number: 231 }) {
                if ordinal != plan.len() - 1
                    || self.frame(ordinal, true).is_ok()
                    || before.state.state.registers.rsp != frame.initial_rsp
                {
                    return Err(OracleError::Invalid(
                        "oracle terminal has fictitious successor or stack frame",
                    ));
                }
                continue;
            }
            let after = self.frame(ordinal, true)?;
            if !after.complete
                || after.ordinal != ordinal
                || !after.after
                || after.until != before.until
            {
                return Err(OracleError::Invalid(
                    "oracle complete after observation differs",
                ));
            }
            match instruction.kind() {
                PlannedKind::Syscall { .. } => dataflow::compare_kernel_return(
                    instruction,
                    &before.state.state,
                    &after.state.state,
                    actual_pid,
                )?,
                _ => self.require_transition(plan, ordinal, frame)?,
            }
        }
        // The helper's intervening register-only instructions cannot change
        // any stack byte. This compares the two actual complete observations.
        if self.frame(plan.call, true)?.stack.prefix()
            != self.frame(plan.ret, false)?.stack.prefix()
        {
            return Err(OracleError::Invalid(
                "oracle helper changed the complete stack",
            ));
        }
        dataflow::compare_value_flow(plan, contract, |ordinal| {
            Ok((
                &self.frame(ordinal, false)?.state.state,
                if ordinal == plan.syscalls[2] {
                    None
                } else {
                    Some(&self.frame(ordinal, true)?.state.state)
                },
            ))
        })
    }
    pub(super) fn require_transition(
        &self,
        plan: &ArtifactPlan,
        ordinal: usize,
        frame: FrameObservation,
    ) -> Result<(), OracleError> {
        let before = self.frame(ordinal, false)?;
        let after = self.frame(ordinal, true)?;
        if !before.complete || !after.complete {
            return Err(OracleError::Invalid("oracle transition incomplete"));
        }
        match plan.instruction(ordinal)?.kind() {
            PlannedKind::Ordinary => dataflow::compare_ordinary(
                plan.instruction(ordinal)?,
                &before.state.state,
                &after.state.state,
            ),
            PlannedKind::Call | PlannedKind::Ret => {
                dataflow::compare_stack(
                    plan,
                    frame,
                    ordinal,
                    &before.state.state,
                    &after.state.state,
                )?;
                let stack = self.metadata.stack.as_ref().unwrap();
                let offset = frame
                    .call_slot
                    .checked_sub(stack.range.start)
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or(OracleError::Invalid("oracle stack offset differs"))?;
                let a = before.stack.prefix();
                let b = after.stack.prefix();
                if a.len() != self.shape.unwrap().stack_bytes
                    || b.len() != a.len()
                    || offset.checked_add(8).is_none_or(|end| end > a.len())
                {
                    return Err(OracleError::Invalid(
                        "oracle complete stack capture differs",
                    ));
                }
                if plan.instruction(ordinal)?.kind() == PlannedKind::Call {
                    if a[..offset] != b[..offset]
                        || a[offset + 8..] != b[offset + 8..]
                        || b[offset..offset + 8] != frame.return_pc.to_le_bytes()
                    {
                        return Err(OracleError::Invalid(
                            "oracle CALL whole-stack effect differs",
                        ));
                    }
                } else if a != b || a[offset..offset + 8] != frame.return_pc.to_le_bytes() {
                    return Err(OracleError::Invalid(
                        "oracle RET changed stack or consumed wrong PC",
                    ));
                }
                Ok(())
            }
            _ => Err(OracleError::Invalid(
                "oracle selected transition needs actual syscall evidence",
            )),
        }
    }
}
