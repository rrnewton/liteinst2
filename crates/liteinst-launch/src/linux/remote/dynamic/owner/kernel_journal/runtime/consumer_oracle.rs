//! Feature-only prepaid journal copy. No native request or authority is created.
use super::*;

mod storage;
use storage::{AttemptCopy, StateCopy};
#[cfg(test)]
mod tests;

const ATTEMPTS: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct JournalAllocation {
    pub(in crate::linux::remote::dynamic::owner) address: usize,
    pub(in crate::linux::remote::dynamic::owner) length: usize,
    pub(in crate::linux::remote::dynamic::owner) capacity: usize,
}
impl JournalAllocation {
    fn of<T>(value: &Vec<T>) -> Self {
        Self {
            address: value.as_ptr() as usize,
            length: value.len(),
            capacity: value.capacity(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum JournalObservationPhase {
    Allocation,
    Capture,
    Retention,
    Aborted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct JournalObservationFailure {
    pub(in crate::linux::remote::dynamic::owner) phase: JournalObservationPhase,
    pub(in crate::linux::remote::dynamic::owner) kind: KernelFailureKind,
    pub(in crate::linux::remote::dynamic::owner) detail: Option<&'static str>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct JournalWriterTransition {
    pub(in crate::linux::remote::dynamic::owner) before: KernelWriterStatus,
    pub(in crate::linux::remote::dynamic::owner) after: KernelWriterStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct JournalObservationProgress {
    pub(in crate::linux::remote::dynamic::owner) allocation_started: bool,
    pub(in crate::linux::remote::dynamic::owner) allocation_complete: bool,
    pub(in crate::linux::remote::dynamic::owner) capture_started: bool,
    pub(in crate::linux::remote::dynamic::owner) capture_complete: bool,
    pub(in crate::linux::remote::dynamic::owner) headers_copied: usize,
    pub(in crate::linux::remote::dynamic::owner) retention_started: bool,
    pub(in crate::linux::remote::dynamic::owner) retention: Option<JournalWriterTransition>,
    pub(in crate::linux::remote::dynamic::owner) first_failure: Option<JournalObservationFailure>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct JournalArchiveHeader {
    pub(in crate::linux::remote::dynamic::owner) archive_address: usize,
    pub(in crate::linux::remote::dynamic::owner) session: u64,
    pub(in crate::linux::remote::dynamic::owner) writer: KernelWriterStatus,
    pub(in crate::linux::remote::dynamic::owner) poisoned: bool,
    pub(in crate::linux::remote::dynamic::owner) lock_poisoned: bool,
    pub(in crate::linux::remote::dynamic::owner) legacy_index: JournalAllocation,
    pub(in crate::linux::remote::dynamic::owner) legacy_active: Option<KernelAttemptHandle>,
    pub(in crate::linux::remote::dynamic::owner) runtime_index: JournalAllocation,
    pub(in crate::linux::remote::dynamic::owner) runtime_active: Option<RuntimeKernelHandle>,
    pub(in crate::linux::remote::dynamic::owner) version: u64,
}
impl JournalArchiveHeader {
    fn read(writer: &KernelJournalWriter, archive: &Archive, lock_poisoned: bool) -> Self {
        Self {
            archive_address: Arc::as_ptr(&writer.archive) as usize,
            session: archive.session,
            writer: archive.status,
            poisoned: archive.poisoned,
            lock_poisoned,
            legacy_index: JournalAllocation::of(&archive.attempts),
            legacy_active: writer.active,
            runtime_index: JournalAllocation::of(&archive.runtime.attempts),
            runtime_active: archive.runtime.active,
            version: archive.runtime.version,
        }
    }
    fn require_history(&self, after: &Self) -> Result<(), LaunchError> {
        let expected = Self {
            writer: after.writer,
            ..*self
        };
        if expected != *after {
            return Err(invalid(
                "consumer journal archive identity or history header changed",
            ));
        }
        Ok(())
    }
}

/// Fixed fields borrowed from the copied actual Binding, not a constructor.
pub(in crate::linux::remote::dynamic::owner) struct JournalBindingView<'a> {
    pub(in crate::linux::remote::dynamic::owner) pending: &'a RuntimePendingToken,
    pub(in crate::linux::remote::dynamic::owner) original: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner) source: CodeIdentity,
    pub(in crate::linux::remote::dynamic::owner) window: usize,
    pub(in crate::linux::remote::dynamic::owner) origin: (u64, u64),
    pub(in crate::linux::remote::dynamic::owner) execution: (u64, u64),
    pub(in crate::linux::remote::dynamic::owner) registers: &'a RegisterSnapshot,
    pub(in crate::linux::remote::dynamic::owner) original_mask: u64,
    pub(in crate::linux::remote::dynamic::owner) original_xstate_len: usize,
    pub(in crate::linux::remote::dynamic::owner) number: u64,
    pub(in crate::linux::remote::dynamic::owner) arguments: [u64; 6],
    pub(in crate::linux::remote::dynamic::owner) until: Instant,
}
impl<'a> From<&'a Binding> for JournalBindingView<'a> {
    fn from(value: &'a Binding) -> Self {
        Self {
            pending: &value.pending,
            original: &value.original,
            source: value.source,
            window: value.window,
            origin: value.origin,
            execution: value.execution,
            registers: &value.registers,
            original_mask: value.original_mask,
            original_xstate_len: value.original_xstate_len,
            number: value.number,
            arguments: value.arguments,
            until: value.until,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct JournalAttemptHeader {
    pub(in crate::linux::remote::dynamic::owner) charge: usize,
    pub(in crate::linux::remote::dynamic::owner) raw_count: usize,
    pub(in crate::linux::remote::dynamic::owner) fact_count: usize,
    pub(in crate::linux::remote::dynamic::owner) stage: RuntimeKernelJournalStage,
    pub(in crate::linux::remote::dynamic::owner) failure: Option<RuntimeKernelJournalFailure>,
    pub(in crate::linux::remote::dynamic::owner) completed: bool,
}
impl From<&RuntimeAttempt> for JournalAttemptHeader {
    fn from(value: &RuntimeAttempt) -> Self {
        Self {
            charge: value.charge,
            raw_count: value.raw_count,
            fact_count: value.fact_count,
            stage: value.stage,
            failure: value.failure,
            completed: value.completed,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct JournalStateHeader {
    pub(in crate::linux::remote::dynamic::owner) slot: RuntimeKernelStateSlot,
    pub(in crate::linux::remote::dynamic::owner) captured: bool,
    pub(in crate::linux::remote::dynamic::owner) finalized: bool,
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
    pub(in crate::linux::remote::dynamic::owner) raw_ordinal: Option<usize>,
    pub(in crate::linux::remote::dynamic::owner) stop: Option<KernelStopIdentity>,
    pub(in crate::linux::remote::dynamic::owner) registers: [u8; 216],
    pub(in crate::linux::remote::dynamic::owner) registers_request: Option<RuntimeKernelRequest>,
    pub(in crate::linux::remote::dynamic::owner) xstate_request: Option<RuntimeKernelRequest>,
    pub(in crate::linux::remote::dynamic::owner) requested_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner) returned_pointer: usize,
    pub(in crate::linux::remote::dynamic::owner) requested_length: usize,
    pub(in crate::linux::remote::dynamic::owner) returned_length: usize,
    pub(in crate::linux::remote::dynamic::owner) mask: [u8; 8],
    pub(in crate::linux::remote::dynamic::owner) mask_request: Option<RuntimeKernelRequest>,
}
impl From<&RuntimeKernelStateRecord> for JournalStateHeader {
    fn from(value: &RuntimeKernelStateRecord) -> Self {
        Self {
            slot: value.slot,
            captured: value.captured,
            finalized: value.finalized,
            complete: value.complete,
            raw_ordinal: value.raw_ordinal,
            stop: value.stop,
            registers: value.registers,
            registers_request: value.registers_request,
            xstate_request: value.xstate_request,
            requested_pointer: value.requested_pointer,
            returned_pointer: value.returned_pointer,
            requested_length: value.requested_length,
            returned_length: value.returned_length,
            mask: value.mask,
            mask_request: value.mask_request,
        }
    }
}

pub(in crate::linux::remote::dynamic::owner) struct JournalStateView<'a> {
    pub(in crate::linux::remote::dynamic::owner) allocation: JournalAllocation,
    pub(in crate::linux::remote::dynamic::owner) installed: Option<JournalAllocation>,
    pub(in crate::linux::remote::dynamic::owner) source: Option<JournalAllocation>,
    pub(in crate::linux::remote::dynamic::owner) header: Option<&'a JournalStateHeader>,
    /// All initialized destination bytes; only copied_prefix came from the archive.
    pub(in crate::linux::remote::dynamic::owner) initialized: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner) copied_prefix: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
}
pub(in crate::linux::remote::dynamic::owner) struct JournalAttemptView<'a> {
    pub(in crate::linux::remote::dynamic::owner) binding: Option<JournalBindingView<'a>>,
    pub(in crate::linux::remote::dynamic::owner) header: Option<&'a JournalAttemptHeader>,
    pub(in crate::linux::remote::dynamic::owner) raw: &'a [Option<RuntimeKernelRawRecord>; RAW],
    pub(in crate::linux::remote::dynamic::owner) raw_slots_copied: usize,
    pub(in crate::linux::remote::dynamic::owner) facts: &'a [Option<RuntimeKernelFact>; FACT_COUNT],
    pub(in crate::linux::remote::dynamic::owner) fact_slots_copied: usize,
    pub(in crate::linux::remote::dynamic::owner) state_slots_copied: usize,
    pub(in crate::linux::remote::dynamic::owner) complete: bool,
    states: &'a [StateCopy; STATE_COUNT],
}
impl JournalAttemptView<'_> {
    pub(in crate::linux::remote::dynamic::owner) fn state(
        &self,
        index: usize,
    ) -> Option<JournalStateView<'_>> {
        self.states.get(index).map(StateCopy::view)
    }
}
pub(in crate::linux::remote::dynamic::owner) struct JournalPartialView<'a> {
    pub(in crate::linux::remote::dynamic::owner) allocation: JournalAllocation,
    pub(in crate::linux::remote::dynamic::owner) installed: Option<JournalAllocation>,
    pub(in crate::linux::remote::dynamic::owner) header: Option<&'a JournalArchiveHeader>,
    pub(in crate::linux::remote::dynamic::owner) progress: JournalObservationProgress,
    attempts: &'a [AttemptCopy],
}
impl JournalPartialView<'_> {
    pub(in crate::linux::remote::dynamic::owner) fn attempt(
        &self,
        index: usize,
    ) -> Option<JournalAttemptView<'_>> {
        self.attempts.get(index).map(AttemptCopy::view)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct JournalAttemptCounts {
    pub(in crate::linux::remote::dynamic::owner) id: KernelAttemptId,
    pub(in crate::linux::remote::dynamic::owner) number: u64,
    pub(in crate::linux::remote::dynamic::owner) raw: usize,
    pub(in crate::linux::remote::dynamic::owner) captured_states: usize,
    pub(in crate::linux::remote::dynamic::owner) finalized_states: usize,
    pub(in crate::linux::remote::dynamic::owner) complete_states: usize,
    pub(in crate::linux::remote::dynamic::owner) facts: usize,
    pub(in crate::linux::remote::dynamic::owner) completed: bool,
    pub(in crate::linux::remote::dynamic::owner) failure: Option<RuntimeKernelJournalFailure>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct JournalCounts {
    pub(in crate::linux::remote::dynamic::owner) attempts: usize,
    pub(in crate::linux::remote::dynamic::owner) raw_waits: usize,
    pub(in crate::linux::remote::dynamic::owner) captured_states: usize,
    pub(in crate::linux::remote::dynamic::owner) finalized_states: usize,
    pub(in crate::linux::remote::dynamic::owner) complete_states: usize,
    pub(in crate::linux::remote::dynamic::owner) per_attempt:
        [Option<JournalAttemptCounts>; ATTEMPTS],
}

/// Empty fixed owner must be installed in the parent before allocation under Q.
pub(in crate::linux::remote::dynamic::owner) struct PreparedKernelObservation {
    attempts: Vec<AttemptCopy>,
    installed: Option<JournalAllocation>,
    header: Option<JournalArchiveHeader>,
    progress: JournalObservationProgress,
}
impl PreparedKernelObservation {
    pub(in crate::linux::remote::dynamic::owner) fn empty() -> Self {
        Self {
            attempts: Vec::new(),
            installed: None,
            header: None,
            progress: JournalObservationProgress {
                allocation_started: false,
                allocation_complete: false,
                capture_started: false,
                capture_complete: false,
                headers_copied: 0,
                retention_started: false,
                retention: None,
                first_failure: None,
            },
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn reservation_bytes() -> Result<usize, LaunchError>
    {
        size_of::<Self>()
            .checked_add(storage::payload_bytes()?)
            .ok_or(invalid("consumer journal reservation overflows"))
    }
    pub(in crate::linux::remote::dynamic::owner) fn allocated_bytes(
        &self,
    ) -> Result<usize, LaunchError> {
        let mut bytes = self
            .attempts
            .capacity()
            .checked_mul(size_of::<AttemptCopy>())
            .and_then(|value| value.checked_add(size_of::<Self>()))
            .ok_or(invalid("consumer journal actual charge overflows"))?;
        for attempt in &self.attempts {
            for state in &attempt.states {
                bytes = bytes
                    .checked_add(state.bytes.capacity())
                    .ok_or(invalid("consumer journal state charge overflows"))?;
            }
        }
        Ok(bytes)
    }
    pub(in crate::linux::remote::dynamic::owner) fn temporary_bytes() -> Result<usize, LaunchError>
    {
        storage::temporary_bytes()
    }
    fn remember(&mut self, phase: JournalObservationPhase, error: &LaunchError) {
        if self.progress.first_failure.is_none() {
            self.progress.first_failure = Some(JournalObservationFailure {
                phase,
                kind: super::super::failure_kind(error),
                detail: if let LaunchError::Invalid(message) = error {
                    Some(*message)
                } else {
                    None
                },
            });
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn mark_aborted(&mut self) {
        if self.progress.first_failure.is_none() {
            self.progress.first_failure = Some(JournalObservationFailure {
                phase: JournalObservationPhase::Aborted,
                kind: KernelFailureKind::CaughtPanic,
                detail: None,
            });
        }
    }
    pub(in crate::linux::remote::dynamic::owner) fn allocate_payloads(
        &mut self,
    ) -> Result<(), LaunchError> {
        let result = self.allocate_with(|_| Ok(()));
        if let Err(error) = &result {
            self.remember(JournalObservationPhase::Allocation, error);
        }
        result
    }
    pub(in crate::linux::remote::dynamic::owner) fn capture(
        &mut self,
        writer: &KernelJournalWriter,
    ) -> Result<(), LaunchError> {
        let result = self.capture_inner(writer);
        if let Err(error) = &result {
            self.remember(JournalObservationPhase::Capture, error);
        }
        result
    }
    fn capture_inner(&mut self, writer: &KernelJournalWriter) -> Result<(), LaunchError> {
        if !self.progress.allocation_complete
            || self.progress.capture_started
            || self.progress.first_failure.is_some()
        {
            return Err(invalid(
                "consumer journal capture lacks fresh complete allocation",
            ));
        }
        self.progress.capture_started = true;
        self.require_allocation()?;
        let (archive, poisoned) = match writer.archive.lock() {
            Ok(value) => (value, false),
            Err(error) => (error.into_inner(), true),
        };
        let header = JournalArchiveHeader::read(writer, &archive, poisoned);
        self.header = Some(header);
        for (index, source) in archive.runtime.attempts.iter().take(ATTEMPTS).enumerate() {
            let target = &mut self.attempts[index];
            target.binding = Some(source.binding.clone());
            target.header = Some(source.into());
            self.progress.headers_copied = index + 1;
            target.capture_body(source)?;
        }
        if header.poisoned
            || header.lock_poisoned
            || header.legacy_index.length != 0
            || header.legacy_active.is_some()
            || header.runtime_index.length > ATTEMPTS
            || !matches!(
                header.writer,
                KernelWriterStatus::Active | KernelWriterStatus::Closing
            )
        {
            return Err(invalid(
                "consumer journal source is poisoned, mixed, oversized or already closed",
            ));
        }
        self.progress.capture_complete = true;
        Ok(())
    }
    pub(in crate::linux::remote::dynamic::owner) fn require_retained(
        &mut self,
        writer: &KernelJournalWriter,
    ) -> Result<JournalWriterTransition, LaunchError> {
        if self.progress.retention_started {
            let error = invalid("consumer journal retention was already attempted");
            self.remember(JournalObservationPhase::Retention, &error);
            return Err(error);
        }
        self.progress.retention_started = true;
        let result = self.retained_inner(writer);
        match &result {
            Ok(value) => self.progress.retention = Some(*value),
            Err(error) => self.remember(JournalObservationPhase::Retention, error),
        }
        result
    }
    fn retained_inner(
        &self,
        writer: &KernelJournalWriter,
    ) -> Result<JournalWriterTransition, LaunchError> {
        let before = self
            .header
            .as_ref()
            .ok_or(invalid("consumer journal has no captured archive"))?;
        self.require_allocation()?;
        let (archive, poisoned) = match writer.archive.lock() {
            Ok(value) => (value, false),
            Err(error) => (error.into_inner(), true),
        };
        let after = JournalArchiveHeader::read(writer, &archive, poisoned);
        before.require_history(&after)?;
        if !matches!(
            before.writer,
            KernelWriterStatus::Active | KernelWriterStatus::Closing
        ) || !matches!(
            after.writer,
            KernelWriterStatus::Cleaned | KernelWriterStatus::FailedCleanup
        ) {
            return Err(invalid(
                "consumer journal writer lacks actual cleanup status transition",
            ));
        }
        for index in 0..self.progress.headers_copied {
            let source = archive
                .runtime
                .attempts
                .get(index)
                .ok_or(invalid("consumer journal captured attempt disappeared"))?;
            self.attempts[index].require_retained(source)?;
        }
        Ok(JournalWriterTransition {
            before: before.writer,
            after: after.writer,
        })
    }
    pub(in crate::linux::remote::dynamic::owner) fn partial_view(&self) -> JournalPartialView<'_> {
        JournalPartialView {
            allocation: JournalAllocation::of(&self.attempts),
            installed: self.installed,
            header: self.header.as_ref(),
            progress: self.progress,
            attempts: &self.attempts,
        }
    }
    /// Counts are observations, including failed attempts; they grant no success.
    pub(in crate::linux::remote::dynamic::owner) fn counts(
        &self,
    ) -> Result<JournalCounts, LaunchError> {
        if !self.progress.capture_complete {
            return Err(invalid(
                "consumer journal count requires a complete archive copy",
            ));
        }
        let header = self
            .header
            .as_ref()
            .ok_or(invalid("consumer journal count lacks archive header"))?;
        let mut result = JournalCounts {
            attempts: header.runtime_index.length,
            raw_waits: 0,
            captured_states: 0,
            finalized_states: 0,
            complete_states: 0,
            per_attempt: [None; ATTEMPTS],
        };
        for index in 0..result.attempts {
            let count = self.attempts[index].counts()?;
            result.raw_waits += count.raw;
            result.captured_states += count.captured_states;
            result.finalized_states += count.finalized_states;
            result.complete_states += count.complete_states;
            result.per_attempt[index] = Some(count);
        }
        Ok(result)
    }
}
