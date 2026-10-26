use super::*;

fn add(a: usize, b: usize) -> Result<usize, LaunchError> {
    a.checked_add(b)
        .ok_or(invalid("runtime journal charge overflows"))
}
fn mul(a: usize, b: usize) -> Result<usize, LaunchError> {
    a.checked_mul(b)
        .ok_or(invalid("runtime journal charge overflows"))
}

// Allocate precisely the managed capacity already covered by the reservation.
// Global-allocator bookkeeping is not exposed as evidence payload capacity.
pub(super) fn exact_vec<T>(capacity: usize) -> Result<Vec<T>, LaunchError> {
    if capacity == 0 {
        return Ok(Vec::new());
    }
    let layout = std::alloc::Layout::array::<T>(capacity)
        .map_err(|_| invalid("runtime journal allocation layout overflows"))?;
    if layout.size() == 0 {
        return Err(invalid(
            "runtime journal allocation has zero-sized elements",
        ));
    }
    // SAFETY: layout is nonzero and checked. This is the same global allocator
    // used by Vec. No element is initialized until Vec's ordinary writes.
    let pointer = unsafe { std::alloc::alloc(layout) }.cast::<T>();
    if pointer.is_null() {
        return Err(invalid("runtime journal allocation failed"));
    }
    // SAFETY: pointer is aligned for T and owns exactly Layout::array<T>(capacity).
    // Length zero exposes no uninitialized T. Vec drops only initialized elements
    // and deallocates with this identical capacity/alignment/allocator layout.
    Ok(unsafe { Vec::from_raw_parts(pointer, 0, capacity) })
}

/// Pure layout. Root must reserve this peak before any prepare allocation.
pub(in crate::linux::remote::dynamic::owner) struct RuntimeJournalShape {
    length: usize,
    capacity: usize,
    version: u64,
    replacement: usize,
    reservation: usize,
    old_index: usize,
}
impl RuntimeJournalShape {
    pub(super) fn new(length: usize, capacity: usize, version: u64) -> Result<Self, LaunchError> {
        if length > capacity || version == u64::MAX {
            return Err(invalid("runtime journal shape is invalid"));
        }
        let replacement = if length == capacity {
            add(length, 1)?
        } else {
            0
        };
        let old_index = mul(capacity, size_of::<RuntimeAttempt>())?;
        let archive_header = if length == 0 {
            size_of::<RuntimeArchive>()
        } else {
            0
        };
        let reservation = add(
            add(
                add(
                    size_of::<PreparedRuntimeJournal>(),
                    STATE_COUNT * MAX_XSTATE,
                )?,
                mul(replacement, size_of::<RuntimeAttempt>())?,
            )?,
            archive_header,
        )?;
        Ok(Self {
            length,
            capacity,
            version,
            replacement,
            reservation,
            old_index,
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn reservation_bytes(&self) -> usize {
        self.reservation
    }
    // Old retained index is already charged. This explicit peak helps root
    // audit the coexistence; it is not an instruction to debit old bytes twice.
    pub(in crate::linux::remote::dynamic::owner) fn allocation_peak_bytes(
        &self,
    ) -> Result<usize, LaunchError> {
        add(self.old_index, self.reservation)
    }
}

/// Unattached buffers own no release authority. Partial preparation errors drop
/// only new local allocations; persistent index capacity is never changed.
pub(in crate::linux::remote::dynamic::owner) struct PreparedRuntimeJournal {
    archive: Arc<Mutex<Archive>>,
    shape: RuntimeJournalShape,
    pub(super) attempt: RuntimeAttempt,
    replacement: Vec<RuntimeAttempt>,
}
impl PreparedRuntimeJournal {
    pub(in crate::linux::remote::dynamic::owner) fn retained_bytes(&self) -> usize {
        self.attempt.charge
    }
    pub(in crate::linux::remote::dynamic::owner) fn allocation_peak_bytes(
        &self,
    ) -> Result<usize, LaunchError> {
        add(self.shape.old_index, self.attempt.charge)
    }
}

fn empty_state(slot: RuntimeKernelStateSlot) -> RuntimeKernelStateRecord {
    RuntimeKernelStateRecord {
        slot,
        captured: false,
        finalized: false,
        complete: false,
        raw_ordinal: None,
        stop: None,
        registers: [0; 216],
        registers_request: None,
        initialized_xstate: Vec::new(),
        xstate_request: None,
        requested_pointer: 0,
        returned_pointer: 0,
        requested_length: 0,
        returned_length: 0,
        mask: [0; 8],
        mask_request: None,
    }
}
pub(super) fn empty_attempt(binding: Binding) -> RuntimeAttempt {
    let slots = [
        RuntimeKernelStateSlot::Original,
        RuntimeKernelStateSlot::Entry,
        RuntimeKernelStateSlot::Exit,
        RuntimeKernelStateSlot::BridgeTrap,
        RuntimeKernelStateSlot::RestoredReturn,
        RuntimeKernelStateSlot::Closed,
        RuntimeKernelStateSlot::PreExit,
        RuntimeKernelStateSlot::Unexpected,
    ];
    RuntimeAttempt {
        binding,
        charge: 0,
        raw: std::array::from_fn(|_| None),
        raw_count: 0,
        states: slots.map(empty_state),
        facts: [None; FACT_COUNT],
        fact_count: 0,
        stage: RuntimeKernelJournalStage::Prepared,
        failure: None,
        completed: false,
    }
}
fn binding(
    identity: &RuntimeKernelIdentity,
    original: &AdmissionStop,
    input: &SelectedInput,
    before: RuntimeJournalBefore<'_>,
) -> Result<Binding, LaunchError> {
    let pending = identity.pending();
    let (source, window) = identity.journal_source();
    let result = Binding {
        pending: pending.clone(),
        original: original.clone(),
        source,
        window,
        origin: identity.journal_origin(),
        execution: identity.journal_execution(),
        registers: *input.registers(),
        original_mask: before.mask,
        original_xstate_len: before.xstate.len(),
        number: identity.number(),
        arguments: identity.arguments(),
        until: identity.until(),
    };
    let registers = input.registers();
    if !result.matches(identity)
        || identity.attempt().session == 0
        || identity.attempt().invocation == 0
        || pending.stop != original.token
        || pending.task != original.identity
        || pending.stop.task != Some(pending.task.task)
        || pending.stop.tid <= 0
        || pending.task.generation != 0
        || original.signal.is_some()
        || !matches!(
            original.phase,
            trusted::AdmissionPhase::EntryReady | trusted::AdmissionPhase::Restored
        )
        || !matches!(
            input.instruction().operation(),
            Operation::Syscall {
                abi: SyscallAbi::LinuxX64
            }
        )
        || input.instruction().bytes() != [0x0f, 0x05]
        || input.instruction().logical_pc() != pending.pc
        || registers.rip != pending.pc
        || registers.rax != result.number
        || registers.cs != 0x33
        || !matches!(result.number, value if value == libc::SYS_getpid as u64 || value == libc::SYS_gettid as u64 || value == libc::SYS_exit as u64 || value == libc::SYS_exit_group as u64)
        || result.arguments
            != [
                registers.rdi,
                registers.rsi,
                registers.rdx,
                registers.r10,
                registers.r8,
                registers.r9,
            ]
        || result.origin.0 == 0
        || result.origin.1 == 0
        || result.execution.0 != pending.stop.session
        || result.execution.1 == 0
        || result.window != pending.window
        || before.registers != registers
        || !(512..MAX_XSTATE).contains(&before.xstate.len())
    {
        return Err(invalid(
            "runtime journal binding is not an exact finite invocation",
        ));
    }
    Ok(result)
}

impl KernelJournalWriter {
    pub(in crate::linux::remote::dynamic::owner) fn runtime_shape(
        &self,
    ) -> Result<RuntimeJournalShape, LaunchError> {
        let archive = self.lock();
        if self.active.is_some()
            || archive.runtime.active.is_some()
            || archive.poisoned
            || archive.status != KernelWriterStatus::Active
        {
            return Err(invalid("runtime journal preparation is unavailable"));
        }
        RuntimeJournalShape::new(
            archive.runtime.attempts.len(),
            archive.runtime.attempts.capacity(),
            archive.runtime.version,
        )
    }
    /// Caller has already taken the complete combined reservation. No query or
    /// effect is performed here, and no persistent allocation is changed.
    pub(in crate::linux::remote::dynamic::owner) fn prepare_runtime(
        &self,
        shape: RuntimeJournalShape,
        identity: &RuntimeKernelIdentity,
        original: &AdmissionStop,
        input: &SelectedInput,
        before: RuntimeJournalBefore<'_>,
    ) -> Result<PreparedRuntimeJournal, LaunchError> {
        let binding = binding(identity, original, input, before)?;
        {
            let archive = self.lock();
            check_shape(&archive, self.active, &shape, binding.id())?;
        }
        prepare_owned(Arc::clone(&self.archive), shape, binding)
    }
    /// Root has installed and debited the measured preparation before calling.
    /// This move has no allocation and never refunds the old index's charge.
    pub(in crate::linux::remote::dynamic::owner) fn attach_runtime(
        &mut self,
        prepared: PreparedRuntimeJournal,
    ) -> Result<(RuntimeKernelHandle, RuntimeJournalSink), LaunchError> {
        if !Arc::ptr_eq(&self.archive, &prepared.archive) {
            return Err(invalid("runtime journal prepared archive differs"));
        }
        let handle = {
            let mut archive = self.lock();
            check_shape(
                &archive,
                self.active,
                &prepared.shape,
                prepared.attempt.binding.id(),
            )?;
            let PreparedRuntimeJournal {
                attempt,
                mut replacement,
                shape,
                ..
            } = prepared;
            // Every fallible check precedes the first move from retained history.
            if shape.replacement != 0 && replacement.capacity() < shape.length + 1 {
                return Err(invalid("runtime journal replacement capacity differs"));
            }
            let handle = RuntimeKernelHandle {
                id: attempt.binding.id(),
                index: shape.length,
            };
            if shape.replacement != 0 {
                replacement.append(&mut archive.runtime.attempts);
                replacement.push(attempt);
                archive.runtime.attempts = replacement;
            } else {
                archive.runtime.attempts.push(attempt);
            }
            archive.runtime.version += 1;
            archive.runtime.active = Some(handle);
            handle
        };
        Ok((
            handle,
            RuntimeJournalSink {
                archive: Arc::clone(&self.archive),
                handle,
                _thread: PhantomData,
            },
        ))
    }
}
pub(super) fn check_shape(
    archive: &Archive,
    legacy: Option<KernelAttemptHandle>,
    shape: &RuntimeJournalShape,
    id: KernelAttemptId,
) -> Result<(), LaunchError> {
    if legacy.is_some()
        || archive.runtime.active.is_some()
        || archive.poisoned
        || archive.status != KernelWriterStatus::Active
        || archive.session != id.session
        || archive.runtime.version != shape.version
        || archive.runtime.attempts.len() != shape.length
        || archive.runtime.attempts.capacity() != shape.capacity
        || archive
            .attempts
            .iter()
            .any(|attempt| attempt.id.invocation >= id.invocation)
        || archive
            .runtime
            .attempts
            .iter()
            .any(|attempt| attempt.binding.id().invocation >= id.invocation)
    {
        return Err(invalid("runtime journal shape or invocation is stale"));
    }
    Ok(())
}
pub(super) fn prepare_owned(
    archive: Arc<Mutex<Archive>>,
    shape: RuntimeJournalShape,
    binding: Binding,
) -> Result<PreparedRuntimeJournal, LaunchError> {
    let mut attempt = empty_attempt(binding);
    for state in &mut attempt.states {
        state.initialized_xstate = exact_vec(MAX_XSTATE)?;
        if state.initialized_xstate.capacity() != MAX_XSTATE {
            return Err(invalid("runtime journal state allocation capacity differs"));
        }
        state.initialized_xstate.resize(MAX_XSTATE, 0);
    }
    let replacement = exact_vec(shape.replacement)?;
    if replacement.capacity() != shape.replacement {
        return Err(invalid("runtime journal index allocation capacity differs"));
    }
    let mut charge = add(
        size_of::<PreparedRuntimeJournal>(),
        mul(replacement.capacity(), size_of::<RuntimeAttempt>())?,
    )?;
    if shape.length == 0 {
        charge = add(charge, size_of::<RuntimeArchive>())?;
    }
    for state in &attempt.states {
        charge = add(charge, state.initialized_xstate.capacity())?;
    }
    if charge > shape.reservation {
        return Err(invalid("runtime journal allocation exceeds reservation"));
    }
    attempt.charge = charge;
    Ok(PreparedRuntimeJournal {
        archive,
        shape,
        attempt,
        replacement,
    })
}
