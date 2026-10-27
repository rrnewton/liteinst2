use super::*;

pub(super) struct StateCopy {
    pub(super) bytes: Vec<u8>,
    installed: Option<JournalAllocation>,
    source: Option<JournalAllocation>,
    header: Option<JournalStateHeader>,
    copied: usize,
    complete: bool,
}
impl StateCopy {
    pub(super) fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            installed: None,
            source: None,
            header: None,
            copied: 0,
            complete: false,
        }
    }
    pub(super) fn allocate(&mut self) -> Result<(), LaunchError> {
        self.bytes = super::super::storage::exact_vec(MAX_XSTATE)?;
        self.installed = Some(JournalAllocation::of(&self.bytes));
        self.bytes.resize(MAX_XSTATE, 0);
        self.installed = Some(JournalAllocation::of(&self.bytes));
        self.require_allocation()
    }
    pub(super) fn require_allocation(&self) -> Result<(), LaunchError> {
        if self.installed != Some(JournalAllocation::of(&self.bytes))
            || self.bytes.len() != MAX_XSTATE
            || self.bytes.capacity() != MAX_XSTATE
        {
            return Err(invalid(
                "consumer journal state allocation identity or extent differs",
            ));
        }
        Ok(())
    }
    pub(super) fn capture(&mut self, source: &RuntimeKernelStateRecord) -> Result<(), LaunchError> {
        self.require_allocation()?;
        if self.header.is_some() {
            return Err(invalid("consumer journal state was already captured"));
        }
        self.source = Some(JournalAllocation::of(&source.initialized_xstate));
        self.header = Some(source.into());
        let length = source.initialized_xstate.len().min(self.bytes.len());
        self.bytes[..length].copy_from_slice(&source.initialized_xstate[..length]);
        self.copied = length;
        if source.initialized_xstate.len() != MAX_XSTATE
            || source.initialized_xstate.capacity() != MAX_XSTATE
        {
            return Err(invalid(
                "consumer journal source state lacks exact MAX allocation",
            ));
        }
        self.complete = true;
        Ok(())
    }
    pub(super) fn require_retained(
        &self,
        source: &RuntimeKernelStateRecord,
    ) -> Result<(), LaunchError> {
        self.require_allocation()?;
        let Some(header) = self.header else {
            return Ok(());
        };
        if self.source != Some(JournalAllocation::of(&source.initialized_xstate))
            || header != JournalStateHeader::from(source)
            || self.copied > source.initialized_xstate.len()
            || self.copied > self.bytes.len()
            || self.bytes[..self.copied] != source.initialized_xstate[..self.copied]
            || self.bytes[self.copied..].iter().any(|byte| *byte != 0)
            || (self.complete && self.copied != MAX_XSTATE)
        {
            return Err(invalid(
                "consumer journal copied state or initialized prefix changed",
            ));
        }
        Ok(())
    }
    pub(super) fn view(&self) -> JournalStateView<'_> {
        JournalStateView {
            allocation: JournalAllocation::of(&self.bytes),
            installed: self.installed,
            source: self.source,
            header: self.header.as_ref(),
            initialized: &self.bytes,
            copied_prefix: &self.bytes[..self.copied],
            complete: self.complete,
        }
    }
}

pub(super) struct AttemptCopy {
    pub(super) binding: Option<Binding>,
    pub(super) header: Option<JournalAttemptHeader>,
    raw: [Option<RuntimeKernelRawRecord>; RAW],
    raw_slots_copied: usize,
    pub(super) states: [StateCopy; STATE_COUNT],
    state_slots_copied: usize,
    facts: [Option<RuntimeKernelFact>; FACT_COUNT],
    fact_slots_copied: usize,
    complete: bool,
}
impl AttemptCopy {
    pub(super) fn empty() -> Self {
        Self {
            binding: None,
            header: None,
            raw: std::array::from_fn(|_| None),
            raw_slots_copied: 0,
            states: std::array::from_fn(|_| StateCopy::empty()),
            state_slots_copied: 0,
            facts: [None; FACT_COUNT],
            fact_slots_copied: 0,
            complete: false,
        }
    }
    pub(super) fn capture_body(&mut self, source: &RuntimeAttempt) -> Result<(), LaunchError> {
        for index in 0..RAW {
            self.raw[index] = source.raw[index].clone();
            self.raw_slots_copied = index + 1;
        }
        // Mark entry to each state before its fallible copy, so a failed state's
        // initialized prefix is included in the subsequent retention check.
        for index in 0..STATE_COUNT {
            self.state_slots_copied = index + 1;
            self.states[index].capture(&source.states[index])?;
        }
        for index in 0..FACT_COUNT {
            self.facts[index] = source.facts[index];
            self.fact_slots_copied = index + 1;
        }
        if source.raw_count > RAW
            || source.fact_count > FACT_COUNT
            || source.raw[..source.raw_count].iter().any(Option::is_none)
            || source.raw[source.raw_count..].iter().any(Option::is_some)
            || source.facts[..source.fact_count]
                .iter()
                .any(Option::is_none)
            || source.facts[source.fact_count..]
                .iter()
                .any(Option::is_some)
        {
            return Err(invalid("consumer journal chronological slot counts differ"));
        }
        self.complete = true;
        Ok(())
    }
    pub(super) fn require_retained(&self, source: &RuntimeAttempt) -> Result<(), LaunchError> {
        if self.binding.as_ref() != Some(&source.binding)
            || self.header != Some(JournalAttemptHeader::from(source))
            || self.raw_slots_copied > RAW
            || self.state_slots_copied > STATE_COUNT
            || self.fact_slots_copied > FACT_COUNT
            || self.raw[..self.raw_slots_copied] != source.raw[..self.raw_slots_copied]
            || self.facts[..self.fact_slots_copied] != source.facts[..self.fact_slots_copied]
        {
            return Err(invalid(
                "consumer journal attempt binding, raw or fact prefix changed",
            ));
        }
        for index in 0..self.state_slots_copied {
            self.states[index].require_retained(&source.states[index])?;
        }
        if self.complete
            && (self.raw_slots_copied != RAW
                || self.state_slots_copied != STATE_COUNT
                || self.fact_slots_copied != FACT_COUNT
                || self.states.iter().any(|state| !state.complete))
        {
            return Err(invalid(
                "consumer journal completed copy lost a recorded family",
            ));
        }
        Ok(())
    }
    pub(super) fn counts(&self) -> Result<JournalAttemptCounts, LaunchError> {
        let binding = self
            .binding
            .as_ref()
            .ok_or(invalid("consumer journal count lacks binding"))?;
        let header = self
            .header
            .ok_or(invalid("consumer journal count lacks attempt header"))?;
        if !self.complete {
            return Err(invalid(
                "consumer journal count lacks complete attempt copy",
            ));
        }
        let mut result = JournalAttemptCounts {
            id: binding.id(),
            number: binding.number,
            raw: header.raw_count,
            captured_states: 0,
            finalized_states: 0,
            complete_states: 0,
            facts: header.fact_count,
            completed: header.completed,
            failure: header.failure,
        };
        for state in &self.states {
            let header = state
                .header
                .ok_or(invalid("consumer journal count lacks state header"))?;
            result.captured_states += usize::from(header.captured);
            result.finalized_states += usize::from(header.finalized);
            result.complete_states += usize::from(header.complete);
        }
        Ok(result)
    }
    pub(super) fn view(&self) -> JournalAttemptView<'_> {
        JournalAttemptView {
            binding: self.binding.as_ref().map(Into::into),
            header: self.header.as_ref(),
            raw: &self.raw,
            raw_slots_copied: self.raw_slots_copied,
            facts: &self.facts,
            fact_slots_copied: self.fact_slots_copied,
            state_slots_copied: self.state_slots_copied,
            complete: self.complete,
            states: &self.states,
        }
    }
}

pub(super) fn payload_bytes() -> Result<usize, LaunchError> {
    ATTEMPTS
        .checked_mul(size_of::<AttemptCopy>())
        .and_then(|headers| {
            ATTEMPTS
                .checked_mul(STATE_COUNT)
                .and_then(|states| states.checked_mul(MAX_XSTATE))
                .and_then(|bytes| headers.checked_add(bytes))
        })
        .ok_or(invalid("consumer journal payload charge overflows"))
}

impl PreparedKernelObservation {
    // The callback is a pure allocation-boundary model used by the feature-only
    // controls. Production passes a no-op; it cannot alter a journal or native IO.
    pub(super) fn allocate_with(
        &mut self,
        mut before: impl FnMut(usize) -> Result<(), LaunchError>,
    ) -> Result<(), LaunchError> {
        if self.progress.allocation_started
            || self.progress.capture_started
            || self.progress.first_failure.is_some()
            || !self.attempts.is_empty()
            || self.attempts.capacity() != 0
        {
            return Err(invalid("consumer journal allocation owner is not empty"));
        }
        self.progress.allocation_started = true;
        before(0)?;
        self.attempts = super::super::storage::exact_vec(ATTEMPTS)?;
        self.installed = Some(JournalAllocation::of(&self.attempts));
        for _ in 0..ATTEMPTS {
            self.attempts.push(AttemptCopy::empty());
            self.installed = Some(JournalAllocation::of(&self.attempts));
        }
        let mut ordinal = 1;
        for attempt in &mut self.attempts {
            for state in &mut attempt.states {
                before(ordinal)?;
                state.allocate()?;
                ordinal += 1;
            }
        }
        self.require_allocation()?;
        if self.allocated_bytes()? != Self::reservation_bytes()? {
            return Err(invalid(
                "consumer journal installed allocation differs from reservation",
            ));
        }
        self.progress.allocation_complete = true;
        Ok(())
    }
    pub(super) fn require_allocation(&self) -> Result<(), LaunchError> {
        if self.installed != Some(JournalAllocation::of(&self.attempts))
            || self.attempts.len() != ATTEMPTS
            || self.attempts.capacity() != ATTEMPTS
        {
            return Err(invalid(
                "consumer journal attempt allocation identity or extent differs",
            ));
        }
        for attempt in &self.attempts {
            for state in &attempt.states {
                state.require_allocation()?;
            }
        }
        Ok(())
    }
}

type ArchiveLock<'a> =
    Result<MutexGuard<'a, Archive>, std::sync::PoisonError<MutexGuard<'a, Archive>>>;
type RuntimeIteration<'a> =
    std::iter::Enumerate<std::iter::Take<std::slice::Iter<'a, RuntimeAttempt>>>;

pub(super) fn temporary_bytes() -> Result<usize, LaunchError> {
    // Sum construction/copy/lock/view frames conservatively, even when sequential.
    // Whole byte payloads are copied in place; no MAX-sized temporary exists.
    [
        2 * size_of::<AttemptCopy>(),
        size_of::<StateCopy>(),
        2 * size_of::<Binding>(),
        2 * size_of::<JournalArchiveHeader>(),
        2 * size_of::<JournalAttemptHeader>(),
        2 * size_of::<JournalStateHeader>(),
        2 * size_of::<RuntimeKernelRawRecord>(),
        2 * size_of::<RuntimeKernelFact>(),
        size_of::<JournalBindingView<'static>>(),
        size_of::<JournalStateView<'static>>(),
        size_of::<JournalAttemptView<'static>>(),
        size_of::<JournalPartialView<'static>>(),
        size_of::<JournalCounts>(),
        size_of::<JournalAttemptCounts>(),
        size_of::<MutexGuard<'static, Archive>>(),
        size_of::<std::sync::PoisonError<MutexGuard<'static, Archive>>>(),
        size_of::<ArchiveLock<'static>>(),
        size_of::<std::alloc::Layout>(),
        size_of::<Result<Vec<AttemptCopy>, LaunchError>>(),
        size_of::<Result<Vec<u8>, LaunchError>>(),
        size_of::<Result<JournalWriterTransition, LaunchError>>(),
        12 * size_of::<&[u8]>(),
        24 * size_of::<usize>(),
        4 * size_of::<std::ops::Range<usize>>(),
        size_of::<std::slice::Iter<'static, RuntimeAttempt>>(),
        size_of::<RuntimeIteration<'static>>(),
        size_of::<std::slice::Iter<'static, AttemptCopy>>(),
        size_of::<std::slice::IterMut<'static, AttemptCopy>>(),
        size_of::<std::slice::Iter<'static, StateCopy>>(),
        size_of::<std::slice::IterMut<'static, StateCopy>>(),
        size_of::<[usize; 31]>()
            + size_of::<std::array::IntoIter<usize, 31>>()
            + 2 * size_of::<Result<usize, LaunchError>>()
            + size_of::<Option<usize>>(),
    ]
    .into_iter()
    .try_fold(0_usize, |sum, value| {
        sum.checked_add(value)
            .ok_or(invalid("consumer journal temporary charge overflows"))
    })
}
