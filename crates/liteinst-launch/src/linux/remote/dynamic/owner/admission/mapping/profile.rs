//! Mapping-only native extent and personality prerequisites. The successful
//! receipt retains the original maximum request, not an inferred active-feature
//! size. Failed read-only acquisition returns its error and closes construction;
//! it does not claim a persistent startup-failure archive.
use super::super::super::bootstrap::BootstrapMm;
use super::*;

const PERSONALITY_BYTES: usize = 16;
const PER_MASK: u32 = 0x00ff;
const READ_IMPLIES_EXEC: u32 = 0x0040_0000;

#[derive(Clone, Debug, Eq, PartialEq)]
struct PersonalityObservation {
    initialized: [u8; PERSONALITY_BYTES],
    length: usize,
    procfs_type: libc::__fsword_t,
    value: u32,
}

struct MaximumXstateQuery {
    requested_bytes: usize,
    original_pointer: usize,
    returned_pointer: usize,
    result: libc::c_long,
    errno: Option<i32>,
    reported_bytes: usize,
    initialized: Vec<u8>,
}

/// Immutable task-incarnation receipt. It never changes the fixed raw buffer
/// limits, publishes code or authorizes a native task release.
pub(in super::super) struct MappingProfileEvidence {
    initial: DynamicStop,
    identity: DynamicTask,
    wait_status: i32,
    signal_info: [u8; 128],
    query: MaximumXstateQuery,
    before: TaskStateSnapshot,
    after: TaskStateSnapshot,
    personality: PersonalityObservation,
}

impl MappingProfileEvidence {
    /// Reserve this before bootstrap effects. It includes the unchanged MAX
    /// query storage plus both maximum logical full-state payloads; the fixed
    /// receipt contains its initialized siginfo/personality/scalar metadata.
    pub(in super::super) fn reservation_bytes() -> Result<usize, GateError> {
        size_of::<Self>()
            .checked_add(
                MAX_XSTATE
                    .checked_mul(3)
                    .ok_or_else(|| refused("mapping profile reservation overflows"))?,
            )
            .ok_or_else(|| refused("mapping profile reservation overflows"))
    }

    pub(in super::super) fn acquire(
        owner: &Owner,
        boot: &BootstrapMm,
        until: Instant,
    ) -> Result<Self, GateError> {
        owner.time_left(until, "mapping profile acquisition")?;
        let stop = &boot.stop;
        let native = owner
            .lifecycle
            .as_ref()
            .ok_or_else(|| refused("mapping profile lacks native lifecycle ownership"))?;
        native.require_admission_stop(stop)?;
        let members = native.check_admission_mm(owner, stop.identity.task)?;
        if stop.token.session != owner.session
            || stop.token.tid != owner.pid
            || stop.token.task != Some(stop.identity.task)
            || !matches!(
                stop.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
            || stop.signal.is_some()
            || !native.admission_events_empty()
            || members.candidate.tasks.as_slice() != [stop.identity.task]
            || members.address_space != stop.identity.address_space
            || members.process != stop.identity.process
            || members.generation != stop.identity.generation
            || members.tgid != owner.pid
            || members.tids != BTreeSet::from([owner.pid])
            || !owner.owned.contains(&owner.pid)
            || owner.handles.get(&owner.pid).is_none_or(broker::hup)
        {
            return Err(refused(
                "mapping profile bootstrap identity or phase differs",
            ));
        }
        let wait_status = *owner
            .stopped
            .get(&owner.pid)
            .ok_or_else(|| refused("mapping profile has no retained real stop"))?;
        let mut signal_info = [0_u8; 128];
        // SAFETY: the real held owner identity is authenticated above; storage
        // is initialized and has the native siginfo ABI size.
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_GETSIGINFO,
                owner.pid,
                0,
                signal_info.as_mut_ptr(),
            )
        };
        exact_result(result, "mapping profile GETSIGINFO")?;
        validate_stop(wait_status, &signal_info)?;
        let before = TaskStateSnapshot::read(owner.pid)?;
        if before != boot.evidence.restored_entry {
            return Err(refused(
                "mapping profile differs from exact bootstrap state",
            ));
        }
        owner.time_left(until, "mapping profile maximum request")?;
        let query = MaximumXstateQuery::read(owner.pid)?;
        validate_query(&query, &before)?;
        let personality = read_personality(owner.pid, until)?;
        let after = TaskStateSnapshot::read(owner.pid)?;
        if after != before {
            return Err(refused(
                "mapping profile changed during read-only acquisition",
            ));
        }
        native.require_admission_stop(stop)?;
        owner.time_left(until, "mapping profile authentication")?;
        let receipt = Self {
            initial: stop.token.clone(),
            identity: stop.identity,
            wait_status,
            signal_info,
            query,
            before,
            after,
            personality,
        };
        receipt.validate_retained()?;
        if receipt.retained_bytes()? > Self::reservation_bytes()? {
            return Err(refused("mapping profile exceeds its original reservation"));
        }
        Ok(receipt)
    }

    pub(in super::super) fn extent(&self) -> usize {
        self.query.reported_bytes
    }

    /// The caller separately proves the current held phase/registry generation.
    /// A same-mm epoch may advance; task, process, mm and session may not change.
    /// Reject a later shorter OR longer image before using a smaller envelope.
    pub(in super::super) fn verify(
        &self,
        token: &DynamicStop,
        identity: DynamicTask,
        state: &TaskStateSnapshot,
    ) -> Result<(), GateError> {
        self.validate_retained()?;
        if token.session != self.initial.session
            || token.tid != self.initial.tid
            || token.task != Some(self.identity.task)
            || token.task != Some(identity.task)
            || token.sequence < self.initial.sequence
            || identity.task != self.identity.task
            || identity.process != self.identity.process
            || identity.address_space != self.identity.address_space
            || identity.generation < self.identity.generation
            || state.registers.cs != 0x33
            || state.xstate.len() != self.extent()
        {
            return Err(refused(
                "mapping state differs from its immutable native XSTATE extent",
            ));
        }
        Ok(())
    }

    /// Read the exact same native task's complete personality immediately
    /// before its mapping effect, under the existing caller-held custody proof.
    /// No personality setter or substituted expected output is used.
    pub(in super::super) fn verify_personality(
        &self,
        tid: i32,
        until: Instant,
    ) -> Result<(), GateError> {
        self.validate_retained()?;
        if tid != self.initial.tid {
            return Err(refused("mapping personality belongs to another task"));
        }
        let actual = read_personality(tid, until)?;
        if actual != self.personality {
            return Err(refused(
                "mapping personality changed before its original effect",
            ));
        }
        Ok(())
    }

    pub(in super::super) fn retained_bytes(&self) -> Result<usize, GateError> {
        size_of::<Self>()
            .checked_add(self.query.initialized.len())
            .and_then(|bytes| bytes.checked_add(self.before.xstate.len()))
            .and_then(|bytes| bytes.checked_add(self.after.xstate.len()))
            .ok_or_else(|| refused("mapping profile retained size overflows"))
    }

    fn validate_retained(&self) -> Result<(), GateError> {
        if self.initial.session == 0
            || self.initial.tid <= 0
            || self.initial.task != Some(self.identity.task)
            || self.before != self.after
        {
            return Err(refused("mapping profile retained state binding differs"));
        }
        validate_stop(self.wait_status, &self.signal_info)?;
        validate_query(&self.query, &self.before)?;
        validate_personality(&self.personality)
    }
}

impl MaximumXstateQuery {
    fn read(tid: i32) -> Result<Self, LaunchError> {
        let mut initialized = Vec::new();
        initialized
            .try_reserve_exact(MAX_XSTATE)
            .map_err(|_| invalid("mapping profile maximum buffer allocation failed"))?;
        initialized.resize(MAX_XSTATE, 0);
        let pointer = initialized.as_mut_ptr();
        let mut iov = libc::iovec {
            iov_base: pointer.cast(),
            iov_len: MAX_XSTATE,
        };
        // SAFETY: original task is held; iovec points to this exclusive initialized
        // MAX buffer. No smaller observed extent is used as the request capacity.
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                tid,
                NT_X86_XSTATE,
                &mut iov as *mut libc::iovec,
            )
        };
        let error = (result == -1).then(std::io::Error::last_os_error);
        let query = Self {
            requested_bytes: MAX_XSTATE,
            original_pointer: pointer as usize,
            returned_pointer: iov.iov_base as usize,
            result,
            errno: error.as_ref().and_then(std::io::Error::raw_os_error),
            reported_bytes: iov.iov_len,
            initialized,
        };
        if let Some(error) = error {
            return Err(io_error("mapping profile GETREGSET", error));
        }
        Ok(query)
    }
}

fn exact_result(result: libc::c_long, operation: &'static str) -> Result<(), LaunchError> {
    if result == -1 {
        return Err(io_error(operation, std::io::Error::last_os_error()));
    }
    if result != 0 {
        return Err(invalid("mapping profile native query result differs"));
    }
    Ok(())
}

fn validate_stop(status: i32, raw: &[u8; 128]) -> Result<(), GateError> {
    let info = DynamicSignalInfo { raw: *raw };
    if !libc::WIFSTOPPED(status)
        || status >> 16 != 0
        || libc::WSTOPSIG(status) != libc::SIGTRAP
        || info.signal() != libc::SIGTRAP
        || !matches!(info.code(), libc::SI_KERNEL | libc::TRAP_BRKPT)
    {
        return Err(refused(
            "mapping profile lacks its real bootstrap neutral stop",
        ));
    }
    Ok(())
}

fn validate_query(query: &MaximumXstateQuery, state: &TaskStateSnapshot) -> Result<(), GateError> {
    if query.requested_bytes != MAX_XSTATE
        || query.initialized.len() != MAX_XSTATE
        || query.original_pointer == 0
        || query.original_pointer != query.initialized.as_ptr() as usize
        || query.returned_pointer != query.original_pointer
        || query.result != 0
        || query.errno.is_some()
        || query.reported_bytes < 512
        || query.reported_bytes >= MAX_XSTATE
        || query.reported_bytes % 8 != 0
        || state.registers.cs != 0x33
        || state.xstate.len() != query.reported_bytes
        || state.xstate != query.initialized[..query.reported_bytes]
    {
        return Err(refused(
            "mapping XSTATE maximum request did not authenticate a fixed ABI extent",
        ));
    }
    Ok(())
}

fn read_personality(tid: i32, until: Instant) -> Result<PersonalityObservation, GateError> {
    control_remaining(until)?;
    if tid <= 0 {
        return Err(refused("mapping personality task is invalid"));
    }
    let mut file = std::fs::File::open(format!("/proc/{tid}/personality"))
        .map_err(|error| io_error("open mapping personality", error))?;
    let mut initialized = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: the open file owns its fd; statfs output is initialized and native.
    if unsafe { libc::fstatfs(file.as_raw_fd(), initialized.as_mut_ptr()) } != 0 {
        return Err(system("authenticate mapping personality procfs").into());
    }
    // SAFETY: successful fstatfs initialized this structure.
    let procfs_type = unsafe { initialized.assume_init() }.f_type;
    if procfs_type != libc::PROC_SUPER_MAGIC as libc::__fsword_t {
        return Err(refused("mapping personality is not a procfs observation"));
    }
    let mut observation = PersonalityObservation {
        initialized: [0; PERSONALITY_BYTES],
        length: 0,
        procfs_type,
        value: 0,
    };
    loop {
        control_remaining(until)?;
        if observation.length == PERSONALITY_BYTES {
            return Err(refused("mapping personality exceeds its fixed bound"));
        }
        let count = file
            .read(&mut observation.initialized[observation.length..])
            .map_err(|error| io_error("read mapping personality", error))?;
        control_remaining(until)?;
        if count == 0 {
            break;
        }
        observation.length += count;
    }
    observation.value = parse_personality(&observation.initialized[..observation.length])?;
    validate_personality(&observation)?;
    Ok(observation)
}

fn parse_personality(raw: &[u8]) -> Result<u32, GateError> {
    if raw.len() != 9 || raw[8] != b'\n' {
        return Err(refused("mapping personality has malformed framing"));
    }
    let mut value = 0_u32;
    for &byte in &raw[..8] {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a' + 10),
            _ => return Err(refused("mapping personality has malformed digits")),
        };
        value = (value << 4) | digit;
    }
    if value & PER_MASK != 0 || value & READ_IMPLIES_EXEC != 0 {
        return Err(refused(
            "mapping personality is not native Linux with READ_IMPLIES_EXEC clear",
        ));
    }
    Ok(value)
}

fn validate_personality(observation: &PersonalityObservation) -> Result<(), GateError> {
    if observation.procfs_type != libc::PROC_SUPER_MAGIC as libc::__fsword_t
        || observation.length > observation.initialized.len()
        || parse_personality(&observation.initialized[..observation.length])? != observation.value
        || observation.initialized[observation.length..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(refused("mapping personality retained observation differs"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
