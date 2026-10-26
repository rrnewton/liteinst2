//! Measured, pre-effect storage. No native authority is created by allocation.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct InitialBootstrapShape {
    rows: usize,
    executables: usize,
    paths: usize,
    executable_paths: usize,
    pages: u64,
}
impl InitialBootstrapShape {
    pub(in crate::linux::remote::dynamic::owner) fn from_original(
        raw: &[u8],
    ) -> Result<Self, LaunchError> {
        let maps = parse(raw)?;
        let mut shape = Self {
            rows: 0,
            executables: 0,
            paths: 0,
            executable_paths: 0,
            pages: 0,
        };
        for row in maps.entries() {
            shape.rows = add(shape.rows, 1)?;
            let path = pathname(row)?.map_or(0, str::len);
            shape.paths = add(shape.paths, path)?;
            if executable(row) {
                let permissions = row.permissions.bytes();
                if permissions[1] == b'w' || permissions[3] != b'p' {
                    return Err(LaunchError::Invalid(
                        "bootstrap requires aligned private immutable executable mappings",
                    ));
                }
                shape.executables = add(shape.executables, 1)?;
                shape.executable_paths = add(shape.executable_paths, path)?;
                shape.pages = shape
                    .pages
                    .checked_add((row.end - row.start) / PAGE as u64)
                    .ok_or(LaunchError::Invalid("bootstrap page inventory overflow"))?;
            }
        }
        if shape.rows >= MAP_ROWS
            || shape.executables == 0
            || shape.executables > 64
            || shape.pages > 16 * 1024
        {
            return Err(LaunchError::Invalid(
                "bootstrap executable inventory exceeds bound",
            ));
        }
        Ok(shape)
    }
    /// New retained managed payload only; existing native registry/control
    /// containers are not source evidence. No transitive heap/RSS claim.
    pub(in crate::linux::remote::dynamic::owner) fn reservation_bytes(
        &self,
    ) -> Result<usize, LaunchError> {
        let descriptors = add(add(self.rows, 1)?, self.executables)?;
        let mut bytes = size_of::<PreparedInitialBootstrap>();
        bytes = add(bytes, 6 * MAX_XSTATE + 3 * MAP_BYTES)?;
        bytes = add(bytes, mul(descriptors, size_of::<MemoryMapping>() + 4)?)?;
        add(add(bytes, self.paths)?, self.executable_paths)
    }
}

pub(super) fn add(a: usize, b: usize) -> Result<usize, LaunchError> {
    a.checked_add(b)
        .ok_or(LaunchError::Invalid("initial bootstrap storage overflow"))
}
fn mul(a: usize, b: usize) -> Result<usize, LaunchError> {
    a.checked_mul(b)
        .ok_or(LaunchError::Invalid("initial bootstrap storage overflow"))
}
pub(super) fn require_capacity(actual: usize, reserved: usize) -> Result<(), LaunchError> {
    if actual > reserved {
        return Err(LaunchError::Invalid(
            "initial bootstrap allocation exceeds reservation",
        ));
    }
    Ok(())
}
fn vector<T>(count: usize) -> Result<Vec<T>, LaunchError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| LaunchError::Invalid("initial bootstrap allocation failed"))?;
    Ok(values)
}
fn string(bytes: &[u8]) -> Result<String, LaunchError> {
    let text = std::str::from_utf8(bytes).map_err(|_| LaunchError::Invalid("maps is not UTF-8"))?;
    let mut result = String::new();
    result
        .try_reserve_exact(text.len())
        .map_err(|_| LaunchError::Invalid("initial bootstrap allocation failed"))?;
    result.push_str(text);
    Ok(result)
}
fn mapping(row: MapEntry<'_>) -> Result<MemoryMapping, LaunchError> {
    Ok(MemoryMapping {
        start: row.start,
        end: row.end,
        permissions: string(&row.permissions.bytes())?,
        file_offset: row.file_offset,
        pathname: row.pathname.map(string).transpose()?,
    })
}
fn mapping_storage(rows: &[MemoryMapping], capacity: usize) -> Result<usize, LaunchError> {
    let mut bytes = mul(capacity, size_of::<MemoryMapping>())?;
    for row in rows {
        bytes = add(bytes, row.permissions.capacity())?;
        bytes = add(bytes, row.pathname.as_ref().map_or(0, String::capacity))?;
    }
    Ok(bytes)
}

pub(in crate::linux::remote::dynamic::owner) struct PreparedInitialBootstrap {
    pub(super) shape: InitialBootstrapShape,
    pub(super) until: Instant,
    pub(super) progress: InitialBootstrapProgress,
    pub(super) states: [StateSlot; 6],
    pub(super) exit_maps: MapBuffer,
    pub(super) current_maps: MapBuffer,
    pub(super) membership: Box<[u8; MAP_BYTES]>,
    pub(super) originals: Vec<MemoryMapping>,
    pub(super) mappings: Vec<MemoryMapping>,
    pub(super) island_row: Option<MemoryMapping>,
    pub(super) original_bytes: [u8; 16],
    pub(super) original_len: usize,
    pub(super) envelope: u64,
    pub(super) syscall: SyscallObservation,
    pub(super) first_signal: SignalObservation,
    pub(super) runner_signal: SignalObservation,
    pub(super) peek: MemoryObservation,
    pub(super) ready: Option<BootstrapMm>,
    pub(super) exit_stop: Option<DynamicStop>,
}
impl PreparedInitialBootstrap {
    pub(in crate::linux::remote::dynamic::owner) fn allocate(
        shape: InitialBootstrapShape,
        original_raw: &[u8],
        until: Instant,
    ) -> Result<Self, LaunchError> {
        if InitialBootstrapShape::from_original(original_raw)? != shape {
            return Err(LaunchError::Invalid(
                "initial bootstrap allocation shape differs",
            ));
        }
        let mut originals = vector(shape.executables)?;
        let mut mappings = vector(add(shape.rows, 1)?)?;
        for row in parse(original_raw)?.entries() {
            if executable(row) {
                originals.push(mapping(row)?);
            }
            mappings.push(mapping(row)?);
        }
        let island_row = Some(MemoryMapping {
            start: 0,
            end: 0,
            permissions: string(b"r-xp")?,
            file_offset: 0,
            pathname: None,
        });
        let value = Self {
            shape,
            until,
            progress: InitialBootstrapProgress::default(),
            states: [
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
                StateSlot::allocate()?,
            ],
            exit_maps: MapBuffer::allocate()?,
            current_maps: MapBuffer::allocate()?,
            membership: fixed_buffer()?,
            originals,
            mappings,
            island_row,
            original_bytes: [0; 16],
            original_len: 0,
            envelope: 0,
            syscall: SyscallObservation::default(),
            first_signal: SignalObservation::default(),
            runner_signal: SignalObservation::default(),
            peek: MemoryObservation::default(),
            ready: None,
            exit_stop: None,
        };
        require_capacity(value.allocated_bytes()?, value.shape.reservation_bytes()?)?;
        Ok(value)
    }
    pub(in crate::linux::remote::dynamic::owner) fn allocated_bytes(
        &self,
    ) -> Result<usize, LaunchError> {
        let mut bytes = add(size_of::<Self>(), 3 * MAP_BYTES)?;
        for state in &self.states {
            bytes = add(bytes, state.state.xstate.capacity())?;
        }
        bytes = add(
            bytes,
            mapping_storage(&self.originals, self.originals.capacity())?,
        )?;
        bytes = add(
            bytes,
            mapping_storage(&self.mappings, self.mappings.capacity())?,
        )?;
        if let Some(row) = &self.island_row {
            bytes = add(bytes, row.permissions.capacity())?;
        }
        if let Some(ready) = &self.ready {
            for state in [
                &ready.evidence.exec_event,
                &ready.evidence.exec_exit,
                &ready.evidence.entry_trap,
                &ready.evidence.restored_entry,
            ] {
                bytes = add(bytes, state.xstate.capacity())?;
            }
            bytes = add(
                bytes,
                mapping_storage(
                    &ready.original_executables,
                    ready.original_executables.capacity(),
                )?,
            )?;
            bytes = add(
                bytes,
                mapping_storage(&ready.mappings, ready.mappings.capacity())?,
            )?;
        }
        Ok(bytes)
    }
    pub(in crate::linux::remote::dynamic::owner) fn progress(&self) -> &InitialBootstrapProgress {
        &self.progress
    }
    pub(in crate::linux::remote::dynamic::owner) fn diagnostics(
        &self,
    ) -> InitialBootstrapDiagnostics<'_> {
        InitialBootstrapDiagnostics {
            states: &self.states,
            exit_maps: &self.exit_maps,
            current_maps: &self.current_maps,
            syscall: &self.syscall,
            first_signal: &self.first_signal,
            runner_signal: &self.runner_signal,
            memory: &self.peek,
            original_bytes: &self.original_bytes[..self.original_len],
            exit_stop: self.exit_stop.as_ref(),
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn completed(&self) -> Option<&BootstrapMm> {
        (self.progress.phase == InitialBootstrapPhase::Complete
            && self.progress.first_failure.is_none())
        .then_some(self.ready.as_ref())
        .flatten()
    }
    pub(in crate::linux::remote::dynamic::owner) fn take_completed(
        &mut self,
    ) -> Result<BootstrapMm, LaunchError> {
        transfer(&mut self.progress, &mut self.ready)
    }
    pub(super) fn validate_plan(&self, original_raw: &[u8]) -> Result<(), LaunchError> {
        if self.progress.phase != InitialBootstrapPhase::Allocated
            || self.progress.first_failure.is_some()
            || self.ready.is_some()
            || InitialBootstrapShape::from_original(original_raw)? != self.shape
        {
            return Err(LaunchError::Invalid(
                "initial bootstrap preparation was reused or differs",
            ));
        }
        let mut originals = self.originals.iter();
        let mut rows = self.mappings.iter();
        for raw in parse(original_raw)?.entries() {
            if !descriptor_matches(
                rows.next()
                    .ok_or(LaunchError::Invalid("initial bootstrap row absent"))?,
                raw,
                false,
            )? {
                return Err(LaunchError::Invalid(
                    "initial bootstrap reserved descriptors differ",
                ));
            }
            if executable(raw)
                && !descriptor_matches(
                    originals
                        .next()
                        .ok_or(LaunchError::Invalid("initial bootstrap executable absent"))?,
                    raw,
                    false,
                )?
            {
                return Err(LaunchError::Invalid(
                    "initial bootstrap reserved executable differs",
                ));
            }
        }
        if rows.next().is_some() || originals.next().is_some() {
            return Err(LaunchError::Invalid(
                "initial bootstrap reserved row count differs",
            ));
        }
        require_capacity(self.allocated_bytes()?, self.shape.reservation_bytes()?)
    }
}
pub(super) fn descriptor_matches(
    row: &MemoryMapping,
    raw: MapEntry<'_>,
    quarantine: bool,
) -> Result<bool, LaunchError> {
    let mut permissions = raw.permissions.bytes();
    if quarantine && executable(raw) {
        permissions[2] = b'-';
    }
    Ok(row.start == raw.start
        && row.end == raw.end
        && row.file_offset == raw.file_offset
        && row.permissions.as_bytes() == permissions
        && row.pathname.as_deref() == pathname(raw)?)
}
pub(super) fn pathname(row: MapEntry<'_>) -> Result<Option<&str>, LaunchError> {
    row.pathname
        .map(|value| {
            std::str::from_utf8(value).map_err(|_| LaunchError::Invalid("maps is not UTF-8"))
        })
        .transpose()
}
pub(super) fn fixed_buffer() -> Result<Box<[u8; MAP_BYTES]>, LaunchError> {
    let layout = std::alloc::Layout::new::<[u8; MAP_BYTES]>();
    let pointer = unsafe { std::alloc::alloc_zeroed(layout) };
    if pointer.is_null() {
        return Err(LaunchError::Invalid("initial bootstrap allocation failed"));
    }
    // SAFETY: exactly this initialized array Layout, uniquely transferred.
    Ok(unsafe { Box::from_raw(pointer.cast()) })
}
pub(super) fn state_bytes() -> Result<Vec<u8>, LaunchError> {
    let mut bytes = vector(MAX_XSTATE)?;
    bytes.resize(MAX_XSTATE, 0);
    Ok(bytes)
}

/// Pure ownership movement; only the connected finish path creates a native
/// BootstrapMm. The generic parameter permits a data-only ownership control.
pub(super) fn transfer<T>(
    progress: &mut InitialBootstrapProgress,
    ready: &mut Option<T>,
) -> Result<T, LaunchError> {
    if progress.phase != InitialBootstrapPhase::Complete || progress.first_failure.is_some() {
        return Err(LaunchError::Invalid("initial bootstrap is not complete"));
    }
    let value = ready.take().ok_or(LaunchError::Invalid(
        "initial bootstrap was already transferred",
    ))?;
    progress.phase = InitialBootstrapPhase::Transferred;
    Ok(value)
}
