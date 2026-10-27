//! Raw EXEC observations are not completed user-control profiles. Exact EXIT
//! and restored-user qualifications use distinct, unchanged production reads.
use super::{ControlProfile, StateSlot};
use crate::linux::remote::dynamic::owner::admission::exact_storage;
use crate::linux::remote::dynamic::owner::bootstrap::{self, Request};
use crate::linux::remote::dynamic::owner::lifecycle::certify_bounded_cet;
use crate::linux::remote::dynamic::owner::{Owner, State};
use crate::{DynamicEventKind, DynamicStop, LaunchError, RegisterSnapshot};
use std::{mem::size_of, time::Instant};

const INITIAL_DEBUG: u64 = 0xffff_0ff0;
const MAX: usize = 64 * 1024;

/// Copy of an actual result category; the original error is returned unchanged
/// to outer custody. Every native response stays in its owning profile too.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadResult {
    Ok,
    Invalid(&'static str),
    System(&'static str, Option<i32>),
    Timeout(&'static str),
    Child(i32),
}
impl ReadResult {
    fn of(result: &Result<(), LaunchError>) -> Self {
        match result {
            Ok(()) => Self::Ok,
            Err(LaunchError::Invalid(message)) => Self::Invalid(message),
            Err(LaunchError::System { operation, source }) => {
                Self::System(operation, source.raw_os_error())
            }
            Err(LaunchError::Timeout(operation)) => Self::Timeout(operation),
            Err(LaunchError::Child { status }) => Self::Child(*status),
        }
    }
}

/// Exact fixed header of a retained read; the full XSTATE owner is borrowed,
/// never replaced with a copy or scalar qualification. No native authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StateStamp {
    registers: RegisterSnapshot,
    mask: u64,
    pointer: usize,
    length: usize,
    capacity: usize,
    registers_request: Option<Request>,
    xstate_request: Option<Request>,
    mask_request: Option<Request>,
    requested_pointer: usize,
    returned_pointer: usize,
    returned_length: usize,
    complete: bool,
}
impl StateStamp {
    fn of(state: &StateSlot) -> Self {
        Self {
            registers: state.state.registers,
            mask: state.state.mask,
            pointer: state.state.xstate.as_ptr() as usize,
            length: state.state.xstate.len(),
            capacity: state.state.xstate.capacity(),
            registers_request: state.registers_request,
            xstate_request: state.xstate_request,
            mask_request: state.mask_request,
            requested_pointer: state.requested_pointer,
            returned_pointer: state.returned_pointer,
            returned_length: state.returned_length,
            complete: state.complete,
        }
    }
    fn require(&self, state: &StateSlot) -> Result<(), LaunchError> {
        let success = Some(Request {
            result: 0,
            errno: None,
        });
        if *self != Self::of(state)
            || !self.complete
            || self.capacity != MAX
            || self.length == 0
            || self.length > MAX
            || self.registers_request != success
            || self.xstate_request != success
            || self.mask_request != success
            || self.requested_pointer != self.pointer
            || self.returned_pointer != self.pointer
            || self.returned_length != self.length
        {
            return Err(LaunchError::Invalid(
                "raw control state association differs",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecAssociation {
    initial: DynamicStop,
    until: Instant,
    state: StateStamp,
}
impl ExecAssociation {
    fn require_state(&self, state: &StateSlot, until: Instant) -> Result<(), LaunchError> {
        if self.until != until {
            return Err(LaunchError::Invalid("raw EXEC control deadline differs"));
        }
        self.state.require(state)
    }
    fn require_held(&self, owner: &Owner) -> Result<(), LaunchError> {
        bootstrap::physical(owner, self.until)?;
        let actual = owner.require_stop(&self.initial)?;
        if actual.tid != owner.pid || !matches!(actual.kind, DynamicEventKind::Exec { .. }) {
            return Err(LaunchError::Invalid("raw EXEC control stop differs"));
        }
        Ok(())
    }
}

pub(in super::super) struct ExecObservation {
    association: Option<ExecAssociation>,
    before: Option<ReadResult>,
    debug: Option<ReadResult>,
    rseq: Option<ReadResult>,
    rseq_pointer: usize,
    cet: Option<ReadResult>,
    debug_required: Option<ReadResult>,
    after: Option<ReadResult>,
    complete: bool,
}
impl ExecObservation {
    pub(super) const fn empty() -> Self {
        Self {
            association: None,
            before: None,
            debug: None,
            rseq: None,
            rseq_pointer: 0,
            cet: None,
            debug_required: None,
            after: None,
            complete: false,
        }
    }
    /// This is called only by the actual EXEC metadata route. The existing
    /// profile Box owns the raw buffers, but its private complete/tid fields
    /// are never set: this read cannot mint a production ControlProfile.
    pub(super) fn capture(
        &mut self,
        owner: &Owner,
        profile: &mut ControlProfile,
        state: &StateSlot,
        until: Instant,
    ) -> Result<(), LaunchError> {
        if self.association.is_some() || self.complete || profile.rseq_request.is_some() {
            return Err(LaunchError::Invalid("raw EXEC control storage reused"));
        }
        let State::Held(event) = &owner.state else {
            return Err(LaunchError::Invalid("raw EXEC control has no held event"));
        };
        if !matches!(event.kind, DynamicEventKind::Exec { .. }) {
            return Err(LaunchError::Invalid("raw EXEC control has wrong event"));
        }
        let initial = event
            .stop_token()
            .ok_or(LaunchError::Invalid("raw EXEC control token absent"))?
            .clone();
        self.association = Some(ExecAssociation {
            initial,
            until,
            state: StateStamp::of(state),
        });
        let association = self.association.as_ref().unwrap();
        association.require_state(state, until)?;
        let before = association.require_held(owner);
        self.before = Some(ReadResult::of(&before));
        before?;
        // Same original request order: all six debug reads, rseq, then CET,
        // even when an earlier debug read returned an error.
        let debug = profile.debug.capture(owner.pid);
        self.debug = Some(ReadResult::of(&debug));
        self.rseq_pointer = profile.rseq.as_mut_ptr() as usize;
        let rseq = rseq_request(owner.pid, self.rseq_pointer);
        profile.rseq_request = Some(rseq);
        let transport = require_rseq_transport(rseq);
        self.rseq = Some(ReadResult::of(&transport));
        let cet = certify_bounded_cet(owner, &mut profile.cet, until);
        self.cet = Some(ReadResult::of(&cet));
        debug?;
        transport?;
        // CET remains an extra strict EXEC precondition. No Invalid result is
        // swallowed or classified by message text. Only rseq CONTENT is deferred.
        cet?;
        let debug_required = profile.debug.require(INITIAL_DEBUG);
        self.debug_required = Some(ReadResult::of(&debug_required));
        debug_required?;
        let after = association.require_held(owner);
        self.after = Some(ReadResult::of(&after));
        after?;
        self.complete = true;
        Ok(())
    }
    pub(in super::super) fn require(
        &self,
        profile: &ControlProfile,
        state: &StateSlot,
        until: Instant,
    ) -> Result<(), LaunchError> {
        self.association
            .as_ref()
            .ok_or(LaunchError::Invalid("raw EXEC control observation absent"))?
            .require_state(state, until)?;
        if !self.complete
            || [
                self.before,
                self.debug,
                self.rseq,
                self.cet,
                self.debug_required,
                self.after,
            ]
            .into_iter()
            .any(|result| result != Some(ReadResult::Ok))
            || self.rseq_pointer != profile.rseq.as_ptr() as usize
            || !profile.cet.complete
            || profile.require(INITIAL_DEBUG).is_ok()
        {
            return Err(LaunchError::Invalid(
                "raw EXEC control observation incomplete or promoted",
            ));
        }
        require_rseq_transport(
            profile
                .rseq_request
                .ok_or(LaunchError::Invalid("raw EXEC rseq observation absent"))?,
        )?;
        profile.debug.require(INITIAL_DEBUG)
    }
}
fn rseq_request(tid: i32, pointer: usize) -> Request {
    // SAFETY: pointer names the installed initialized 24-byte array and the
    // caller has authenticated continuous physical ownership of this stop.
    unsafe {
        *libc::__errno_location() = 0;
    }
    let result = unsafe { libc::ptrace(0x420f_u32, tid, 24_usize, pointer) };
    let errno = if result == -1 {
        let value = unsafe { *libc::__errno_location() };
        (value != 0).then_some(value)
    } else {
        None
    };
    Request { result, errno }
}
fn require_rseq_transport(result: Request) -> Result<(), LaunchError> {
    if let Some(errno) = result.errno {
        return Err(LaunchError::System {
            operation: "PTRACE_GET_RSEQ_CONFIGURATION",
            source: std::io::Error::from_raw_os_error(errno),
        });
    }
    if result.result != 24 {
        return Err(LaunchError::Invalid("raw EXEC rseq native extent differs"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum EntryPhase {
    ExecExit,
    Restored,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct EntryAssociation {
    initial: DynamicStop,
    phase: EntryPhase,
    wait_index: usize,
    actual: (i32, i32),
    until: Instant,
    state: StateStamp,
}
impl EntryAssociation {
    fn require(
        &self,
        exec: &ExecAssociation,
        phase: EntryPhase,
        actual: (i32, i32),
        state: &StateSlot,
    ) -> Result<(), LaunchError> {
        let (index, signal) = match phase {
            EntryPhase::ExecExit => (0, libc::SIGTRAP | 0x80),
            EntryPhase::Restored => (1, libc::SIGTRAP),
        };
        if self.initial != exec.initial
            || self.until != exec.until
            || self.phase != phase
            || self.wait_index != index
            || self.actual != actual
            || actual.0 != exec.initial.tid
            || !libc::WIFSTOPPED(actual.1)
            || libc::WSTOPSIG(actual.1) != signal
            || actual.1 >> 16 != 0
        {
            return Err(LaunchError::Invalid(
                "raw entry control phase association differs",
            ));
        }
        self.state.require(state)
    }
    fn require_held(&self, owner: &Owner) -> Result<(), LaunchError> {
        bootstrap::physical(owner, self.until)?;
        if owner.session != self.initial.session
            || owner.pid != self.actual.0
            || owner.stopped.get(&owner.pid) != Some(&self.actual.1)
        {
            return Err(LaunchError::Invalid(
                "raw entry control held identity differs",
            ));
        }
        Ok(())
    }
}
struct EntryControl {
    profile: Option<Box<ControlProfile>>,
    association: Option<EntryAssociation>,
    before: Option<ReadResult>,
    capture: Option<ReadResult>,
    required: Option<ReadResult>,
    after: Option<ReadResult>,
    complete: bool,
}
impl EntryControl {
    const fn empty() -> Self {
        Self {
            profile: None,
            association: None,
            before: None,
            capture: None,
            required: None,
            after: None,
            complete: false,
        }
    }
    fn allocate(&mut self) -> Result<(), LaunchError> {
        if self.profile.is_some() || self.association.is_some() {
            return Err(LaunchError::Invalid("raw entry control allocation reused"));
        }
        self.profile = Some(
            exact_storage::value(ControlProfile::default())
                .map_err(|_| LaunchError::Invalid("raw entry control allocation failed"))?,
        );
        Ok(())
    }
    fn capture(
        &mut self,
        owner: &Owner,
        exec: &ExecAssociation,
        phase: EntryPhase,
        actual: (i32, i32),
        state: &StateSlot,
    ) -> Result<(), LaunchError> {
        if self.association.is_some() || self.complete || self.profile.is_none() {
            return Err(LaunchError::Invalid(
                "raw entry control unallocated or reused",
            ));
        }
        self.association = Some(EntryAssociation {
            initial: exec.initial.clone(),
            phase,
            wait_index: match phase {
                EntryPhase::ExecExit => 0,
                EntryPhase::Restored => 1,
            },
            actual,
            until: exec.until,
            state: StateStamp::of(state),
        });
        let association = self.association.as_ref().unwrap();
        association.require(exec, phase, actual, state)?;
        let before = association.require_held(owner);
        self.before = Some(ReadResult::of(&before));
        before?;
        let profile = self.profile.as_mut().unwrap();
        let captured = profile.capture(owner, exec.until);
        self.capture = Some(ReadResult::of(&captured));
        captured?;
        let required = profile.require(INITIAL_DEBUG);
        self.required = Some(ReadResult::of(&required));
        required?;
        let after = association.require_held(owner);
        self.after = Some(ReadResult::of(&after));
        after?;
        self.complete = true;
        Ok(())
    }
    fn require(
        &self,
        exec: &ExecAssociation,
        phase: EntryPhase,
        actual: (i32, i32),
        state: &StateSlot,
    ) -> Result<(), LaunchError> {
        self.association
            .as_ref()
            .ok_or(LaunchError::Invalid("raw entry control association absent"))?
            .require(exec, phase, actual, state)?;
        if !self.complete
            || [self.before, self.capture, self.required, self.after]
                .into_iter()
                .any(|result| result != Some(ReadResult::Ok))
        {
            return Err(LaunchError::Invalid(
                "raw entry control qualification incomplete",
            ));
        }
        self.profile
            .as_ref()
            .ok_or(LaunchError::Invalid("raw entry control profile absent"))?
            .require(INITIAL_DEBUG)
    }
}

pub(in super::super) struct EntryControls {
    exit: EntryControl,
    restored: EntryControl,
    allocation_started: bool,
    allocated: bool,
}
impl EntryControls {
    pub(in super::super) const fn empty() -> Self {
        Self {
            exit: EntryControl::empty(),
            restored: EntryControl::empty(),
            allocation_started: false,
            allocated: false,
        }
    }
    pub(in super::super) fn allocate(&mut self) -> Result<(), LaunchError> {
        if self.allocation_started {
            return Err(LaunchError::Invalid(
                "raw entry controls allocation attempted twice",
            ));
        }
        self.allocation_started = true;
        self.exit.allocate()?;
        self.restored.allocate()?;
        self.allocated = true;
        Ok(())
    }
    pub(in super::super) fn allocated_payload_bytes(&self) -> usize {
        usize::from(self.exit.profile.is_some()) * size_of::<ControlProfile>()
            + usize::from(self.restored.profile.is_some()) * size_of::<ControlProfile>()
    }
    pub(in super::super) const fn reserved_payload_bytes() -> usize {
        2 * size_of::<ControlProfile>()
    }
    pub(in super::super) fn capture(
        &mut self,
        owner: &Owner,
        exec: &ExecObservation,
        phase: EntryPhase,
        actual: (i32, i32),
        state: &StateSlot,
    ) -> Result<(), LaunchError> {
        if !self.allocated || !exec.complete {
            return Err(LaunchError::Invalid("raw entry controls unprepared"));
        }
        let binding = exec.association.as_ref().ok_or(LaunchError::Invalid(
            "raw entry controls lack EXEC observation",
        ))?;
        match phase {
            EntryPhase::ExecExit => self.exit.capture(owner, binding, phase, actual, state),
            EntryPhase::Restored => {
                if !self.exit.complete {
                    return Err(LaunchError::Invalid(
                        "raw restored controls precede actual EXIT",
                    ));
                }
                self.restored.capture(owner, binding, phase, actual, state)
            }
        }
    }
    pub(in super::super) fn require(
        &self,
        exec: &ExecObservation,
        phase: EntryPhase,
        actual: (i32, i32),
        state: &StateSlot,
    ) -> Result<(), LaunchError> {
        if !self.allocated || !exec.complete {
            return Err(LaunchError::Invalid(
                "raw retained entry controls unprepared",
            ));
        }
        let binding = exec.association.as_ref().ok_or(LaunchError::Invalid(
            "raw retained entry controls lack EXEC observation",
        ))?;
        let control = match phase {
            EntryPhase::ExecExit => &self.exit,
            EntryPhase::Restored => &self.restored,
        };
        control.require(binding, phase, actual, state)
    }
}

pub(super) fn temporary_bytes() -> Result<usize, LaunchError> {
    // Additional concrete metadata/construction peaks only. Existing caller
    // terms stay unchanged. No compiler frame-size or RSS claim is made.
    let terms = [
        size_of::<ExecObservation>(),
        size_of::<EntryControls>(),
        3 * size_of::<ExecAssociation>(),
        4 * size_of::<EntryAssociation>(),
        8 * size_of::<StateStamp>(),
        4 * size_of::<DynamicStop>(),
        2 * size_of::<ControlProfile>(),
        8 * size_of::<ReadResult>(),
        8 * size_of::<Option<ReadResult>>(),
        8 * size_of::<Result<(), LaunchError>>(),
        4 * size_of::<Request>(),
        4 * size_of::<Option<Request>>(),
        2 * ControlProfile::temporary_bytes()?,
        2 * size_of::<[Option<ReadResult>; 6]>(),
        size_of::<std::array::IntoIter<Option<ReadResult>, 6>>(),
        size_of::<std::array::IntoIter<Option<ReadResult>, 4>>(),
        16 * size_of::<usize>(),
        // New pure bridge recheck and caller conversion/borrow metadata.
        size_of::<RegisterSnapshot>(),
        4 * size_of::<(i32, i32)>(),
        4 * size_of::<EntryPhase>(),
        4 * size_of::<Instant>(),
        16 * size_of::<&StateSlot>(),
        4 * size_of::<Result<(), super::OracleError>>(),
        size_of::<super::OracleError>(),
        size_of::<[usize; 25]>() + size_of::<std::array::IntoIter<usize, 25>>(),
    ];
    terms.into_iter().try_fold(0_usize, |n, item| {
        n.checked_add(item).ok_or(LaunchError::Invalid(
            "raw control temporary storage overflows",
        ))
    })
}

#[cfg(test)]
mod tests;
