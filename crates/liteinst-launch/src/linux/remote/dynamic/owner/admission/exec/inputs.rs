//! Bounded original execve inputs. These observations grant no native authority.
use crate::gate::GateError;
use crate::selected::{Operation, SelectedArguments, SelectedInput, SyscallAbi};
use crate::{
    DynamicExecProfile, DynamicStop, DynamicTask, LaunchError, MemoryMapping, RegisterSnapshot,
};
use std::io::ErrorKind;
use std::mem::size_of;
use std::ops::Range;
use std::time::Instant;

#[cfg(test)]
mod tests;

const MAX_POINTERS: usize = 4096;
const MAX_STRINGS: usize = 64 * 1024;
// Actual private mapping coverage is also mandatory, so a four-level kernel
// cannot acquire a nonexistent five-level address through this upper bound.
const USER_END: u64 = 1 << 56;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputVector {
    Argv,
    Envp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StringRole {
    Filename,
    Argument { vector: InputVector, index: usize },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ReadProgress {
    pub(super) attempted: bool,
    pub(super) reported_bytes: usize,
    pub(super) complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PointerInput {
    pub(super) vector: InputVector,
    pub(super) index: usize,
    pub(super) address: u64,
    pub(super) initialized: [u8; 8],
    pub(super) capture: ReadProgress,
    pub(super) recheck: ReadProgress,
    pub(super) recheck_equal: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StringInput {
    pub(super) role: StringRole,
    pub(super) address: u64,
    pub(super) offset: usize,
    pub(super) requested_bytes: usize,
    pub(super) observed_bytes: usize,
    pub(super) terminated: bool,
    /// The most recent one-byte capture request; earlier successful bytes are
    /// counted by observed_bytes. This remains attempted if the reader unwinds.
    pub(super) capture: ReadProgress,
    pub(super) recheck: ReadProgress,
    pub(super) recheck_equal: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InputBinding {
    pub(super) registers: RegisterSnapshot,
    pub(super) logical_pc: u64,
    pub(super) next_pc: u64,
    pub(super) instruction: [u8; 15],
    pub(super) instruction_len: usize,
}

impl InputBinding {
    fn new(input: &SelectedInput) -> Result<Self, GateError> {
        if input.registers().cs != 0x33
            || input.instruction().operation()
                != (Operation::Syscall {
                    abi: SyscallAbi::LinuxX64,
                })
            || !matches!(input.arguments(), SelectedArguments::Syscall {
                abi: SyscallAbi::LinuxX64, number, ..
            } if number == libc::SYS_execve as u64)
        {
            return Err(refused("exec inputs require exact native64 SYS_execve"));
        }
        let bytes = input.instruction().bytes();
        if bytes.is_empty() || bytes.len() > 15 {
            return Err(refused("exec input instruction extent differs"));
        }
        let mut instruction = [0; 15];
        instruction[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            registers: *input.registers(),
            logical_pc: input.instruction().logical_pc(),
            next_pc: input.instruction().next_pc(),
            instruction,
            instruction_len: bytes.len(),
        })
    }
}

/// The caller authenticates this exact currently held old-mm inventory and
/// complete forbidden set; this borrowed description is not a native lease.
#[derive(Clone, Copy)]
pub(super) struct InputMemory<'a> {
    pub(super) task: DynamicTask,
    pub(super) stop: &'a DynamicStop,
    pub(super) mappings: &'a [MemoryMapping],
    pub(super) forbidden: &'a [Range<u64>],
    pub(super) until: Instant,
}

/// A reader may report a known prefix and an error together. Unreported bytes
/// remain initialized diagnostic substrate, never claimed successful reads.
pub(super) struct InputReadOutcome {
    pub(super) copied: usize,
    pub(super) error: Option<LaunchError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputPhase {
    Capture,
    Recheck,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputLocation {
    Pointer { index: usize, address: u64 },
    String { index: usize, address: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputFailureCause {
    Refused(&'static str),
    NativeInvalid(&'static str),
    NativeSystem {
        operation: &'static str,
        errno: Option<i32>,
        kind: ErrorKind,
    },
    NativeChild(i32),
    Timeout(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InputFailure {
    pub(super) phase: InputPhase,
    pub(super) location: Option<InputLocation>,
    pub(super) cause: InputFailureCause,
}

/// Non-Clone private retained storage. Root must install its custody before
/// reads/effects and charge allocated_bytes from the prepaid lifetime budget.
pub(super) struct ExecInputs {
    max_pointers: usize,
    max_strings: usize,
    pointers: Vec<PointerInput>,
    strings: Vec<StringInput>,
    initialized_strings: Vec<u8>,
    initialized_recheck: Vec<u8>,
    binding: Option<InputBinding>,
    task: Option<DynamicTask>,
    capture_stop: Option<DynamicStop>,
    recheck_stop: Option<DynamicStop>,
    original_until: Option<Instant>,
    logical_pointer_slots: usize,
    string_requested: usize,
    capture_attempted: bool,
    capture_complete: bool,
    recheck_attempted: bool,
    recheck_complete: bool,
    failure: Option<InputFailure>,
    active_read: Option<InputLocation>,
}

/// Immutable views borrow the original storage; they neither allocate a copy
/// nor authorize a release. Complete flags and read prefixes are independent.
pub(super) struct ExecInputView<'a> {
    pub(super) binding: Option<&'a InputBinding>,
    pub(super) task: Option<DynamicTask>,
    pub(super) capture_stop: Option<&'a DynamicStop>,
    pub(super) recheck_stop: Option<&'a DynamicStop>,
    pub(super) logical_pointer_slots: usize,
    pub(super) pointers: &'a [PointerInput],
    pub(super) strings: &'a [StringInput],
    pub(super) initialized_strings: &'a [u8],
    pub(super) initialized_recheck: &'a [u8],
    pub(super) recheck_string_offset: usize,
    pub(super) capture_complete: bool,
    pub(super) recheck_complete: bool,
    pub(super) failure: Option<InputFailure>,
}

impl ExecInputs {
    pub(super) fn reservation_bytes(profile: &DynamicExecProfile) -> Result<usize, GateError> {
        let (p, s) = input_limits(profile)?;
        storage_bytes(p, p - 1, s, recheck_len(p, s)?)
    }

    pub(super) fn prepare(profile: &DynamicExecProfile) -> Result<Self, GateError> {
        let (p, s) = input_limits(profile)?;
        let maximum = Self::reservation_bytes(profile)?;
        let mut initialized_strings = reserved(s)?;
        initialized_strings.resize(s, 0);
        let r = recheck_len(p, s)?;
        let mut initialized_recheck = reserved(r)?;
        initialized_recheck.resize(r, 0);
        let storage = Self {
            max_pointers: p,
            max_strings: s,
            pointers: reserved(p)?,
            strings: reserved(p - 1)?,
            initialized_strings,
            initialized_recheck,
            binding: None,
            task: None,
            capture_stop: None,
            recheck_stop: None,
            original_until: None,
            logical_pointer_slots: 0,
            string_requested: 0,
            capture_attempted: false,
            capture_complete: false,
            recheck_attempted: false,
            recheck_complete: false,
            failure: None,
            active_read: None,
        };
        if storage.allocated_bytes()? != maximum {
            return Err(refused("exec input allocation differs from reserved bound"));
        }
        Ok(storage)
    }

    pub(super) fn allocated_bytes(&self) -> Result<usize, GateError> {
        storage_bytes(
            self.pointers.capacity(),
            self.strings.capacity(),
            self.initialized_strings.capacity(),
            self.initialized_recheck.capacity(),
        )
    }

    pub(super) fn view(&self) -> ExecInputView<'_> {
        ExecInputView {
            binding: self.binding.as_ref(),
            task: self.task,
            capture_stop: self.capture_stop.as_ref(),
            recheck_stop: self.recheck_stop.as_ref(),
            logical_pointer_slots: self.logical_pointer_slots,
            pointers: &self.pointers,
            strings: &self.strings,
            initialized_strings: &self.initialized_strings,
            initialized_recheck: &self.initialized_recheck,
            recheck_string_offset: self.max_pointers * 8,
            capture_complete: self.capture_complete,
            recheck_complete: self.recheck_complete,
            failure: self.failure,
        }
    }

    pub(super) fn capture(
        &mut self,
        input: &SelectedInput,
        memory: InputMemory<'_>,
        mut reader: impl FnMut(u64, &mut [u8]) -> InputReadOutcome,
    ) -> Result<(), GateError> {
        self.active_read = None;
        let result = self.capture_inner(input, memory, &mut reader);
        self.retain_failure(InputPhase::Capture, &result);
        result
    }

    fn capture_inner(
        &mut self,
        input: &SelectedInput,
        memory: InputMemory<'_>,
        reader: &mut impl FnMut(u64, &mut [u8]) -> InputReadOutcome,
    ) -> Result<(), GateError> {
        if self.capture_attempted || self.failure.is_some() {
            return Err(refused("exec input capture is one-use"));
        }
        self.capture_attempted = true;
        self.binding = Some(InputBinding::new(input)?);
        check_context(memory)?;
        self.task = Some(memory.task);
        self.capture_stop = Some(memory.stop.clone());
        self.original_until = Some(memory.until);
        let registers = input.registers();
        self.capture_string(StringRole::Filename, registers.rdi, memory, reader)?;
        self.capture_vector(InputVector::Argv, registers.rsi, memory, reader)?;
        self.capture_vector(InputVector::Envp, registers.rdx, memory, reader)?;
        deadline(memory.until)?;
        self.capture_complete = true;
        Ok(())
    }

    fn capture_vector(
        &mut self,
        vector: InputVector,
        base: u64,
        memory: InputMemory<'_>,
        reader: &mut impl FnMut(u64, &mut [u8]) -> InputReadOutcome,
    ) -> Result<(), GateError> {
        if base == 0 {
            // Logical empty-array terminator; no invented read or pointer row.
            return self.pointer_slot();
        }
        let mut index = 0usize;
        loop {
            self.pointer_slot()?;
            let offset = index
                .checked_mul(8)
                .and_then(|v| u64::try_from(v).ok())
                .ok_or_else(|| refused("exec pointer offset overflows"))?;
            let address = base
                .checked_add(offset)
                .ok_or_else(|| refused("exec pointer address overflows"))?;
            if self.pointers.len() == self.pointers.capacity() {
                return Err(refused("exec pointer storage is exhausted"));
            }
            let row = self.pointers.len();
            self.pointers.push(PointerInput {
                vector,
                index,
                address,
                initialized: [0; 8],
                capture: ReadProgress::default(),
                recheck: ReadProgress::default(),
                recheck_equal: false,
            });
            self.active_read = Some(InputLocation::Pointer {
                index: row,
                address,
            });
            let record = &mut self.pointers[row];
            read(
                memory,
                reader,
                address,
                &mut record.initialized,
                &mut record.capture,
            )?;
            let pointer = u64::from_le_bytes(record.initialized);
            self.active_read = None;
            if pointer == 0 {
                return Ok(());
            }
            let terminators = if vector == InputVector::Argv { 2 } else { 1 };
            if self
                .logical_pointer_slots
                .checked_add(terminators)
                .is_none_or(|needed| needed > self.max_pointers)
            {
                return Err(refused(
                    "exec combined pointer bound lacks required terminators",
                ));
            }
            self.capture_string(
                StringRole::Argument { vector, index },
                pointer,
                memory,
                reader,
            )?;
            index = index
                .checked_add(1)
                .ok_or_else(|| refused("exec pointer count overflows"))?;
        }
    }

    fn pointer_slot(&mut self) -> Result<(), GateError> {
        if self.logical_pointer_slots >= self.max_pointers {
            return Err(refused("exec combined pointer bound is exhausted"));
        }
        self.logical_pointer_slots += 1;
        Ok(())
    }

    fn capture_string(
        &mut self,
        role: StringRole,
        address: u64,
        memory: InputMemory<'_>,
        reader: &mut impl FnMut(u64, &mut [u8]) -> InputReadOutcome,
    ) -> Result<(), GateError> {
        if self.strings.len() == self.strings.capacity() {
            return Err(refused("exec string header bound is exhausted"));
        }
        let row = self.strings.len();
        self.strings.push(StringInput {
            role,
            address,
            offset: self.string_requested,
            requested_bytes: 0,
            observed_bytes: 0,
            terminated: false,
            capture: ReadProgress::default(),
            recheck: ReadProgress::default(),
            recheck_equal: false,
        });
        loop {
            if self.string_requested >= self.max_strings {
                return Err(refused(
                    "exec combined string bound lacks a terminating NUL",
                ));
            }
            let current = address
                .checked_add(self.strings[row].requested_bytes as u64)
                .ok_or_else(|| refused("exec string address overflows"))?;
            let offset = self.string_requested;
            self.string_requested += 1;
            self.strings[row].requested_bytes += 1;
            self.active_read = Some(InputLocation::String {
                index: row,
                address: current,
            });
            let result = read(
                memory,
                reader,
                current,
                &mut self.initialized_strings[offset..offset + 1],
                &mut self.strings[row].capture,
            );
            if self.strings[row].capture.reported_bytes <= 1 {
                self.strings[row].observed_bytes += self.strings[row].capture.reported_bytes;
            }
            result?;
            self.active_read = None;
            if self.initialized_strings[offset] == 0 {
                self.strings[row].terminated = true;
                return Ok(());
            }
        }
    }

    pub(super) fn recheck(
        &mut self,
        input: &SelectedInput,
        memory: InputMemory<'_>,
        mut reader: impl FnMut(u64, &mut [u8]) -> InputReadOutcome,
    ) -> Result<(), GateError> {
        self.active_read = None;
        let result = self.recheck_inner(input, memory, &mut reader);
        self.retain_failure(InputPhase::Recheck, &result);
        result
    }

    fn recheck_inner(
        &mut self,
        input: &SelectedInput,
        memory: InputMemory<'_>,
        reader: &mut impl FnMut(u64, &mut [u8]) -> InputReadOutcome,
    ) -> Result<(), GateError> {
        if !self.capture_complete || self.recheck_attempted || self.failure.is_some() {
            return Err(refused(
                "exec input recheck requires one complete unused capture",
            ));
        }
        self.recheck_attempted = true;
        if self.binding != Some(InputBinding::new(input)?) {
            return Err(refused(
                "exec input binding changed before original ENTRY release",
            ));
        }
        check_context(memory)?;
        let original = self
            .capture_stop
            .as_ref()
            .ok_or_else(|| refused("exec input original stop is absent"))?;
        if Some(memory.task) != self.task
            || memory.stop.session != original.session
            || memory.stop.tid != original.tid
            || memory.stop.task != original.task
            || memory.stop.sequence <= original.sequence
            || Some(memory.until) != self.original_until
        {
            return Err(refused(
                "exec input recheck is not the later original old-mm stop",
            ));
        }
        self.recheck_stop = Some(memory.stop.clone());
        for (index, record) in self.pointers.iter_mut().enumerate() {
            self.active_read = Some(InputLocation::Pointer {
                index,
                address: record.address,
            });
            let offset = index * 8;
            let target = &mut self.initialized_recheck[offset..offset + 8];
            read(memory, reader, record.address, target, &mut record.recheck)?;
            if &*target != record.initialized.as_slice() {
                return Err(refused(
                    "exec pointer bytes changed before original ENTRY release",
                ));
            }
            record.recheck_equal = true;
            self.active_read = None;
        }
        let prefix = self.max_pointers * 8;
        for (index, record) in self.strings.iter_mut().enumerate() {
            self.active_read = Some(InputLocation::String {
                index,
                address: record.address,
            });
            let start = prefix + record.offset;
            let target = &mut self.initialized_recheck[start..start + record.observed_bytes];
            read(memory, reader, record.address, target, &mut record.recheck)?;
            if &*target
                != &self.initialized_strings[record.offset..record.offset + record.observed_bytes]
            {
                return Err(refused(
                    "exec string bytes changed before original ENTRY release",
                ));
            }
            record.recheck_equal = true;
            self.active_read = None;
        }
        deadline(memory.until)?;
        self.recheck_complete = true;
        Ok(())
    }

    fn retain_failure(&mut self, phase: InputPhase, result: &Result<(), GateError>) {
        if self.failure.is_none() {
            if let Err(error) = result {
                let cause = match error {
                    GateError::Refused(reason) => InputFailureCause::Refused(*reason),
                    GateError::Control(LaunchError::Invalid(reason)) => {
                        InputFailureCause::NativeInvalid(*reason)
                    }
                    GateError::Control(LaunchError::System { operation, source }) => {
                        InputFailureCause::NativeSystem {
                            operation: *operation,
                            errno: source.raw_os_error(),
                            kind: source.kind(),
                        }
                    }
                    GateError::Control(LaunchError::Child { status }) => {
                        InputFailureCause::NativeChild(*status)
                    }
                    GateError::Control(LaunchError::Timeout(reason)) => {
                        InputFailureCause::Timeout(*reason)
                    }
                    // This leaf constructs only Refused or Control failures.
                    _ => InputFailureCause::Refused("exec input unexpected internal failure"),
                };
                self.failure = Some(InputFailure {
                    phase,
                    location: self.active_read,
                    cause,
                });
            }
        }
    }
}

fn refused(reason: &'static str) -> GateError {
    GateError::Refused(reason)
}

fn input_limits(profile: &DynamicExecProfile) -> Result<(usize, usize), GateError> {
    if !(2..=MAX_POINTERS).contains(&profile.max_argument_pointers)
        || !(1..=MAX_STRINGS).contains(&profile.max_string_bytes)
    {
        return Err(refused("exec input limits are invalid"));
    }
    Ok((profile.max_argument_pointers, profile.max_string_bytes))
}

fn recheck_len(pointers: usize, strings: usize) -> Result<usize, GateError> {
    pointers
        .checked_mul(8)
        .and_then(|v| v.checked_add(strings))
        .ok_or_else(|| refused("exec input storage bound overflows"))
}

fn storage_bytes(
    pointers: usize,
    strings: usize,
    captured: usize,
    rechecked: usize,
) -> Result<usize, GateError> {
    pointers
        .checked_mul(size_of::<PointerInput>())
        .and_then(|v| {
            strings
                .checked_mul(size_of::<StringInput>())
                .and_then(|n| v.checked_add(n))
        })
        .and_then(|v| v.checked_add(captured))
        .and_then(|v| v.checked_add(rechecked))
        .and_then(|v| v.checked_add(size_of::<ExecInputs>()))
        .ok_or_else(|| refused("exec input storage bound overflows"))
}

fn reserved<T>(count: usize) -> Result<Vec<T>, GateError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| refused("exec input allocation failed"))?;
    if values.capacity() != count {
        return Err(refused("exec input allocator exceeded reserved capacity"));
    }
    Ok(values)
}

fn deadline(until: Instant) -> Result<(), GateError> {
    if Instant::now() >= until {
        return Err(LaunchError::Timeout("original exec input capture").into());
    }
    Ok(())
}

fn check_context(memory: InputMemory<'_>) -> Result<(), GateError> {
    deadline(memory.until)?;
    if memory.stop.session == 0
        || memory.stop.tid <= 0
        || memory.stop.task != Some(memory.task.task)
    {
        return Err(refused("exec input current identity is invalid"));
    }
    let mut end = 0;
    for mapping in memory.mappings {
        let p = mapping.permissions.as_bytes();
        if mapping.start < end
            || mapping.start >= mapping.end
            || p.len() != 4
            || !matches!(p[0], b'r' | b'-')
            || !matches!(p[1], b'w' | b'-')
            || !matches!(p[2], b'x' | b'-')
            || !matches!(p[3], b'p' | b's')
        {
            return Err(refused("exec input mapping inventory is malformed"));
        }
        end = mapping.end;
    }
    if memory
        .forbidden
        .iter()
        .any(|range| range.start >= range.end)
    {
        return Err(refused("exec input forbidden interval is malformed"));
    }
    Ok(())
}

fn readable(memory: InputMemory<'_>, address: u64, len: usize) -> Result<(), GateError> {
    let len = u64::try_from(len).map_err(|_| refused("exec input read length overflows"))?;
    let end = address
        .checked_add(len)
        .ok_or_else(|| refused("exec input read range overflows"))?;
    if address == 0 || len == 0 || end > USER_END {
        return Err(refused("exec input read is outside canonical user memory"));
    }
    if memory
        .forbidden
        .iter()
        .any(|range| address < range.end && range.start < end)
    {
        return Err(refused(
            "exec input aliases an instrumented or trusted interval",
        ));
    }
    let mut cursor = address;
    for mapping in memory.mappings {
        if mapping.end <= cursor {
            continue;
        }
        if mapping.start > cursor {
            break;
        }
        let p = mapping.permissions.as_bytes();
        if p[0] != b'r' || p[3] != b'p' {
            break;
        }
        cursor = mapping.end.min(end);
        if cursor == end {
            return Ok(());
        }
    }
    Err(refused("exec input is not wholly private readable memory"))
}

fn read(
    memory: InputMemory<'_>,
    reader: &mut impl FnMut(u64, &mut [u8]) -> InputReadOutcome,
    address: u64,
    target: &mut [u8],
    progress: &mut ReadProgress,
) -> Result<(), GateError> {
    *progress = ReadProgress::default();
    deadline(memory.until)?;
    readable(memory, address, target.len())?;
    progress.attempted = true;
    let outcome = reader(address, target);
    progress.reported_bytes = outcome.copied;
    if let Some(error) = outcome.error {
        return Err(error.into());
    }
    if outcome.copied != target.len() {
        return Err(refused(
            "exec input reader did not return the exact requested bytes",
        ));
    }
    progress.complete = true;
    deadline(memory.until)?;
    Ok(())
}
