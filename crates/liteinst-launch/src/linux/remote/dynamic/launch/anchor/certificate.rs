//! Read-only prerequisites for the one private pre-exec helper.
use super::*;

/// Initialized exact kernel rseq query, including a failed native result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RseqObservation {
    count: i64,
    error: Option<i32>,
    bytes: [u8; 24],
}
impl RseqObservation {
    /// Actual ptrace return value.
    pub fn count(&self) -> i64 {
        self.count
    }
    /// Native errno when the request returned -1.
    pub fn errno(&self) -> Option<i32> {
        self.error
    }
    /// Initialized buffer; a failed request does not establish its contents.
    pub fn raw_bytes(&self) -> &[u8; 24] {
        &self.bytes
    }
    pub(super) fn configuration(self) -> Result<RseqConfiguration, LaunchError> {
        if self.count == -1 {
            return Err(io_error(
                "read anchor rseq configuration",
                io::Error::from_raw_os_error(self.error.unwrap_or(libc::EIO)),
            ));
        }
        let value =
            unsafe { std::ptr::read_unaligned(self.bytes.as_ptr().cast::<RseqConfiguration>()) };
        if self.count != 24 || value.flags != 0 || value.padding != 0 {
            return Err(LaunchError::Invalid(
                "unsupported anchor rseq configuration",
            ));
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(super) struct RseqConfiguration {
    pointer: u64,
    length: u32,
    signature: u32,
    flags: u32,
    padding: u32,
}
const _: () = assert!(std::mem::size_of::<RseqConfiguration>() == 24);
impl RseqConfiguration {
    pub(super) fn is_zero(self) -> bool {
        self == Self::default()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct RseqEvidence {
    configuration: RseqConfiguration,
}

pub(super) fn observe_configuration(tid: i32) -> RseqObservation {
    let mut value = RseqObservation {
        count: 0,
        error: None,
        bytes: [0; 24],
    };
    // Linux v7.1.3 kernel/ptrace.c:ptrace_get_rseq_configuration returns the
    // complete native structure size. No errno/absence interpretation is used.
    let count =
        unsafe { libc::ptrace(0x420f_u32, tid, value.bytes.len(), value.bytes.as_mut_ptr()) };
    value.count = count as i64;
    if count == -1 {
        value.error = io::Error::last_os_error().raw_os_error();
    }
    value
}

fn private_rw(
    mappings: &[MemoryMapping],
    start: u64,
    length: u64,
) -> Result<[u64; 2], LaunchError> {
    let end = start
        .checked_add(length)
        .ok_or(LaunchError::Invalid("anchor mapping overflow"))?;
    mappings
        .iter()
        .find(|mapping| {
            mapping.start <= start && end <= mapping.end && mapping.permissions == "rw-p"
        })
        .map(|mapping| [mapping.start, mapping.end])
        .ok_or(LaunchError::Invalid(
            "anchor storage is not private writable memory",
        ))
}

pub(super) fn certify(
    owner: &owner::Owner,
    tid: i32,
    address: u64,
    expected: &storage::Context,
    actual: &storage::Context,
    code: &mut [u8],
    rseq_observations: &mut [Option<RseqObservation>; 3],
) -> Result<RseqEvidence, LaunchError> {
    let before = read_registers(tid)?;
    if before.cs != 0x33
        || before.eflags & (0x100 | 0x40000) != 0
        || before.r12 != address
        || before.rsp < actual.stack_low
        || before.rsp > actual.stack_top
        || task_mask(tid)? != BLOCKED
    {
        return Err(LaunchError::Invalid(
            "anchor initial held native state differs",
        ));
    }
    single_task(tid)?;
    let mut permitted = *expected;
    permitted.tid = tid as u64;
    permitted.old_mask = BLOCKED;
    permitted.old_action = actual.old_action;
    permitted.old_stack = actual.old_stack;
    permitted.prepared.tid = tid as u64;
    permitted.anchor.tid = tid as u64;
    let signal =
        unsafe { std::slice::from_raw_parts_mut(permitted.signal.as_mut_ptr().cast::<u8>(), 128) };
    signal[16..20].copy_from_slice(&tid.to_ne_bytes());
    if *actual != permitted {
        return Err(LaunchError::Invalid(
            "anchor Prepared context differs from fixed helper",
        ));
    }
    let mappings = read_maps(tid)?;
    private_rw(
        &mappings,
        address,
        std::mem::size_of::<storage::Context>() as u64,
    )?;
    private_rw(
        &mappings,
        actual.stack_low,
        actual.stack_top - actual.stack_low,
    )?;
    let stack = actual.old_stack;
    if stack.flags == libc::SS_DISABLE as u64 {
        if stack.address != 0 || stack.size != 0 {
            return Err(LaunchError::Invalid(
                "disabled anchor altstack has unexpected storage",
            ));
        }
    } else if stack.flags == 0 && stack.size != 0 {
        let end = stack
            .address
            .checked_add(stack.size)
            .ok_or(LaunchError::Invalid("anchor altstack overflow"))?;
        if stack.address < actual.stack_top && actual.stack_low < end {
            return Err(LaunchError::Invalid(
                "anchor normal stack overlaps configured altstack",
            ));
        }
    } else {
        return Err(LaunchError::Invalid(
            "anchor refuses on-stack or autodisarm altstack",
        ));
    }
    let range = raw::code_range();
    let count = usize::try_from(
        range
            .end
            .checked_sub(range.start)
            .ok_or(LaunchError::Invalid("anchor code range reversed"))?,
    )
    .map_err(|_| LaunchError::Invalid("anchor code range too large"))?;
    if count == 0
        || count > code.len()
        || !mappings.iter().any(|mapping| {
            mapping.start <= range.start
                && range.end <= mapping.end
                && mapping.permissions == "r-xp"
        })
    {
        return Err(LaunchError::Invalid(
            "anchor code is not its bounded immutable mapping",
        ));
    }
    storage::read_into(tid, range.start, &mut code[..count])?;
    // Both copies derive from the same pre-clone immutable helper text. The
    // child bytes are still independently read through current ptrace ownership.
    let original = unsafe { std::slice::from_raw_parts(range.start as *const u8, count) };
    if &code[..count] != original {
        return Err(LaunchError::Invalid("anchor helper code differs"));
    }
    owner.anchor_shadow_stack_disabled(tid)?;
    let raw = observe_configuration(tid);
    rseq_observations[0] = Some(raw);
    let configured = raw.configuration()?;
    let evidence = RseqEvidence {
        configuration: configured,
    };
    if !configured.is_zero() {
        // S receives the kernel CLONE_VM reset before its first instruction;
        // private R/A copy that exact zero and never register. A late inactive
        // rseq_cs value would not prove that inherited history, so refuse it.
        return Err(LaunchError::Invalid(
            "anchor reset lineage has nonzero rseq registration",
        ));
    }
    let raw = observe_configuration(tid);
    rseq_observations[1] = Some(raw);
    if raw.configuration()? != evidence.configuration {
        return Err(LaunchError::Invalid(
            "anchor rseq registration changed while held",
        ));
    }
    if read_registers(tid)? != before || task_mask(tid)? != BLOCKED {
        return Err(LaunchError::Invalid(
            "anchor read-only prerequisites changed native state",
        ));
    }
    Ok(evidence)
}
