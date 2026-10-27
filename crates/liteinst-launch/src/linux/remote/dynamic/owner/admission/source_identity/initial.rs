//! Initial-only fixed storage. Legacy exec keeps its original authentication
//! and complete-map reader; this adapter does not change those allocations.
use super::*;
use std::cell::RefCell;
mod checkpoint;
pub(in crate::linux::remote::dynamic::owner) use checkpoint::{
    InitialCheckpointSourceRead, InitialSourceCheckpoint,
};
mod runtime;
mod runtime_kernel;
mod stack;
pub(in crate::linux::remote::dynamic::owner::admission) use runtime::{
    RuntimeReadCheckpoint, RuntimeSourceRead,
};
pub(in crate::linux::remote::dynamic::owner::admission) use runtime_kernel::{
    RuntimeKernelReadCheckpoint, RuntimeKernelSourceRead,
};
#[cfg(test)]
mod tests;

pub(in crate::linux::remote::dynamic::owner) struct InitialReadScratch {
    bytes: RefCell<Box<[u8; MAP_BYTES]>>,
}
impl InitialReadScratch {
    pub(in crate::linux::remote::dynamic::owner) fn allocate() -> Result<Self, GateError> {
        let layout = std::alloc::Layout::new::<[u8; MAP_BYTES]>();
        // An exact fixed Layout avoids relying on Vec capacity growth. The
        // global allocator's hidden bookkeeping/RSS is not managed payload.
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        if raw.is_null() {
            return Err(refused("initial source authentication allocation failed"));
        }
        // SAFETY: non-null aligned global allocation of this exact fully zeroed
        // array Layout, transferred once; Box uses that same Layout on drop.
        let bytes = unsafe { Box::from_raw(raw.cast::<[u8; MAP_BYTES]>()) };
        Ok(Self {
            bytes: RefCell::new(bytes),
        })
    }
    /// Includes the inline header; a parent already charging size_of<Self>
    /// subtracts that header when adding this allocation's payload.
    pub(in crate::linux::remote::dynamic::owner) fn reservation_bytes() -> usize {
        size_of::<Self>() + MAP_BYTES
    }
    pub(in crate::linux::remote::dynamic::owner) fn allocated_bytes(&self) -> usize {
        Self::reservation_bytes()
    }
}

fn pid_component(pid: i32, bytes: &mut [u8; 11]) -> Result<&[u8], GateError> {
    let mut value = u32::try_from(pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| refused("source proc task id differs"))?;
    let mut start = bytes.len();
    while value != 0 {
        start -= 1;
        bytes[start] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    Ok(&bytes[start..])
}

pub(super) fn proc_directory(context: &SourceReadContext<'_>) -> Result<File, GateError> {
    context
        .owner
        .time_left(context.until, "exec source proc directory")?;
    let mut path = [0_u8; 32];
    path[..6].copy_from_slice(b"/proc/");
    let mut number = [0_u8; 11];
    let component = pid_component(context.owner.pid, &mut number)?;
    path[6..6 + component.len()].copy_from_slice(component);
    let fd = unsafe {
        libc::open(
            path.as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(system("open exec source proc directory").into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut raw: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut raw) } != 0 {
        return Err(system("stat exec source proc filesystem").into());
    }
    if raw.f_type != libc::PROC_SUPER_MAGIC as libc::__fsword_t {
        return Err(refused("exec source directory is not procfs"));
    }
    context
        .owner
        .time_left(context.until, "exec source proc directory")?;
    Ok(file)
}

/// Bounded equivalent of single_task: all records are inspected, exactly one
/// numeric task is required, and the full getdents stream must reach EOF.
/// NativeLifecycle's new initial-only seam supplies the independent registry
/// checks; this initial-EXEC caller has no registry yet. Both paths also
/// require the exact native Tgid from the same proc directory.
pub(super) fn original_singleton(
    context: &SourceReadContext<'_>,
    scratch: &InitialReadScratch,
) -> Result<(), GateError> {
    let mut storage = scratch
        .bytes
        .try_borrow_mut()
        .map_err(|_| refused("initial source authentication scratch is already borrowed"))?;
    require_initial_task_identity(context.owner, context.until, storage.as_mut_slice())?;
    Ok(())
}

pub(in crate::linux::remote::dynamic::owner) fn require_initial_task_identity(
    owner: &Owner,
    until: Instant,
    scratch: &mut [u8],
) -> Result<(), LaunchError> {
    let context = SourceReadContext {
        owner,
        until,
        bounded: true,
    };
    kernel_identity(&context, scratch).map_err(|error| match error {
        GateError::Control(error) => error,
        GateError::Refused(reason) => LaunchError::Invalid(reason),
        _ => LaunchError::Invalid("initial task identity returned an unexpected failure class"),
    })
}

fn kernel_identity(context: &SourceReadContext<'_>, storage: &mut [u8]) -> Result<(), GateError> {
    if storage.len() != MAP_BYTES {
        return Err(refused("initial source authentication scratch differs"));
    }
    let directory = proc_directory(context)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"task".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(system("list owned tasks").into());
    }
    let tasks = unsafe { File::from_raw_fd(fd) };
    let mut number = [0_u8; 11];
    let expected = pid_component(context.owner.pid, &mut number)?;
    let mut seen = false;
    let mut records = 0_usize;
    loop {
        context
            .owner
            .time_left(context.until, "initial source kernel task census")?;
        storage.fill(0);
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                tasks.as_raw_fd(),
                storage.as_mut_ptr(),
                storage.len(),
            )
        };
        if count < 0 {
            return Err(system("read owned task").into());
        }
        context
            .owner
            .time_left(context.until, "initial source kernel task census")?;
        if count == 0 {
            break;
        }
        let length = usize::try_from(count)
            .ok()
            .filter(|n| *n <= storage.len())
            .ok_or_else(|| refused("initial source task census length differs"))?;
        task_records(&storage[..length], expected, &mut seen, &mut records)?;
    }
    if !seen {
        return Err(LaunchError::Invalid("owned task disappeared").into());
    }
    drop(tasks);
    context
        .owner
        .time_left(context.until, "initial source kernel task identity")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"status".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(system("open held task status").into());
    }
    let status = unsafe { File::from_raw_fd(fd) };
    storage.fill(0);
    let mut length = 0;
    loop {
        context
            .owner
            .time_left(context.until, "initial source kernel task identity")?;
        let mut extra = 0_u8;
        let (address, count) = if length == storage.len() {
            (&mut extra as *mut u8, 1)
        } else {
            (storage[length..].as_mut_ptr(), storage.len() - length)
        };
        let count = unsafe { libc::read(status.as_raw_fd(), address.cast(), count) };
        if count < 0 {
            return Err(system("read held task status").into());
        }
        context
            .owner
            .time_left(context.until, "initial source kernel task identity")?;
        if count == 0 {
            break;
        }
        if length == storage.len() {
            return Err(LaunchError::Invalid("image metadata exceeds limit").into());
        }
        length = length
            .checked_add(count as usize)
            .filter(|length| *length <= storage.len())
            .ok_or_else(|| refused("initial source status read length differs"))?;
    }
    status_tgid(&storage[..length], context.owner.pid)?;
    Ok(())
}

fn status_tgid(bytes: &[u8], pid: i32) -> Result<(), GateError> {
    let status = std::str::from_utf8(bytes)
        .map_err(|_| LaunchError::Invalid("held task status is not UTF-8"))?;
    let mut tgid = status.lines().filter_map(|line| line.strip_prefix("Tgid:"));
    if tgid.next().and_then(|line| line.trim().parse::<i32>().ok()) != Some(pid)
        || tgid.next().is_some()
    {
        return Err(
            LaunchError::Invalid("held task is not in the authenticated thread group").into(),
        );
    }
    Ok(())
}

fn task_records(
    bytes: &[u8],
    expected: &[u8],
    seen: &mut bool,
    records: &mut usize,
) -> Result<(), GateError> {
    let mut offset = 0;
    while offset < bytes.len() {
        // linux_dirent64: ino64/off64/reclen16/type8/name[], native x86-64.
        let header = bytes
            .get(offset..offset + 19)
            .ok_or_else(|| refused("initial source task record is truncated"))?;
        let length = u16::from_ne_bytes([header[16], header[17]]) as usize;
        if length < 20 || length % 8 != 0 {
            return Err(refused("initial source task record length differs"));
        }
        let record = bytes
            .get(
                offset
                    ..offset
                        .checked_add(length)
                        .ok_or_else(|| refused("initial source task record overflows"))?,
            )
            .ok_or_else(|| refused("initial source task record is truncated"))?;
        let name = &record[19..];
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| refused("initial source task name is unterminated"))?;
        let name = &name[..end];
        *records = records
            .checked_add(1)
            .ok_or_else(|| refused("initial source task census overflows"))?;
        if *records > 3 {
            return Err(refused(
                "initial source task census exceeds singleton bound",
            ));
        }
        if name != b"." && name != b".." {
            if *seen || name != expected {
                return Err(
                    LaunchError::Invalid("remote control requires exactly one owned task").into(),
                );
            }
            *seen = true;
        }
        offset += length;
    }
    Ok(())
}

pub(super) fn authenticate(
    context: &SourceReadContext<'_>,
    native: &NativeLifecycle,
    boot: &BootstrapMm,
    scratch: &InitialReadScratch,
) -> Result<(), GateError> {
    let mut storage = scratch
        .bytes
        .try_borrow_mut()
        .map_err(|_| refused("initial source authentication scratch is already borrowed"))?;
    context
        .owner
        .time_left(context.until, "initial held source authentication")?;
    // Root-owned integration seam: exact pristine singleton registry/native
    // proof with this caller storage, no cloned membership or candidate Vec.
    native.require_initial_source_mm(
        context.owner,
        &boot.stop,
        context.until,
        storage.as_mut_slice(),
    )?;
    if context.owner.lifecycle.is_some()
        || !matches!(
            boot.stop.phase,
            AdmissionPhase::EntryReady | AdmissionPhase::Restored
        )
        || boot.stop.signal.is_some()
        || boot.stop.identity.generation != 0
        || boot.island.address_space != boot.stop.identity.address_space
        || boot.island.generation != 0
    {
        return Err(refused(
            "exec bootstrap no longer owns the exact held singleton",
        ));
    }
    let mut progress = SourceReadProgress::default();
    let length = read::maps_capture(context, storage.as_mut_slice(), &mut progress, || Ok(()))?;
    let maps = parse(&storage[..length])?;
    if !maps.entries().any(|row| {
        row.start <= boot.island.range.start
            && boot.island.range.end <= row.end
            && row.permissions.bytes() == *b"r-xp"
            && row.pathname.is_none()
    }) {
        return Err(LaunchError::Invalid("immutable RX syscall island did not verify").into());
    }
    // Reuse the same authoritative STUB/STORE_STUBS as remote::island_code;
    // this fixed buffer avoids constructing that legacy Vec in the new path.
    let mut expected = [0xcc_u8; 68];
    expected[..STUB.len()].copy_from_slice(&STUB);
    for (offset, stub) in STORE_STUBS {
        expected[offset..offset + stub.len()].copy_from_slice(stub);
    }
    let mut actual = [0_u8; 68];
    let mut progress = SourceReadProgress::default();
    read::memory_capture(
        context,
        boot.island.range.start,
        &mut actual,
        &mut progress,
        || Ok(()),
    )?;
    if actual != expected {
        return Err(LaunchError::Invalid("immutable RX syscall island did not verify").into());
    }
    context
        .owner
        .time_left(context.until, "initial held source authentication")?;
    let registers = read_registers(context.owner.pid)?;
    storage.fill(0);
    let pointer = storage.as_mut_ptr().cast::<libc::c_void>();
    let mut vector = libc::iovec {
        iov_base: pointer,
        iov_len: storage.len(),
    };
    ptrace(
        libc::PTRACE_GETREGSET,
        context.owner.pid,
        NT_X86_XSTATE,
        (&raw mut vector) as usize,
    )?;
    if vector.iov_base != pointer || vector.iov_len < 512 || vector.iov_len >= storage.len() {
        return Err(LaunchError::Invalid("missing or truncated xstate image").into());
    }
    let mask = launch::task_mask(context.owner.pid)?;
    if registers != boot.evidence.restored_entry.registers
        || storage[..vector.iov_len] != boot.evidence.restored_entry.xstate
        || mask != boot.evidence.restored_entry.mask
    {
        return Err(refused(
            "exec source acquisition changed complete bootstrap state",
        ));
    }
    if context
        .owner
        .handles
        .get(&context.owner.pid)
        .is_none_or(broker::hup)
    {
        return Err(refused(
            "initial source original process pin is no longer live",
        ));
    }
    context
        .owner
        .time_left(context.until, "exec source current-state authentication")?;
    Ok(())
}
