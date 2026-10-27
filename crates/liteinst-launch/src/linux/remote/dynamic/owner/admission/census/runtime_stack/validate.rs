//! Complete comparison before any census mutation. A supplied model is only
//! data; production reaches this module from the sole consumed native seal.
use super::super::super::source_identity::SourceReadProgress;
use super::*;

fn invalid<T>(_: T) -> CensusError {
    CensusError::InvalidConsumption
}
fn observed_maps<'a>(
    bytes: &'a [u8],
    progress: &SourceReadProgress,
) -> Result<&'a [u8], CensusError> {
    if !progress.started
        || !progress.attempted
        || !progress.complete
        || progress.failure.is_some()
        || progress.copied_bytes == 0
        || progress.copied_bytes > bytes.len()
        || progress.filesystem_type != Some(libc::PROC_SUPER_MAGIC)
        || progress.requested_bytes != bytes.len()
    {
        return Err(CensusError::InvalidConsumption);
    }
    Ok(&bytes[..progress.copied_bytes])
}
pub(super) fn require_catalog_maps(
    sources: &PreparedInitialSources,
    words: &StackWordViews<'_>,
) -> Result<(), CensusError> {
    let (original, original_progress) = sources.original_maps();
    let baseline = sources.runtime_baseline_maps().map_err(invalid)?;
    if observed_maps(original, original_progress)? != words.original_maps
        || baseline != words.baseline_maps
    {
        return Err(CensusError::IdentityMismatch);
    }
    Ok(())
}
fn checkpoint_identity(
    before: &ObservedStop,
    checkpoint: NativeCheckpoint<'_>,
    opening: bool,
) -> bool {
    checkpoint.stop.identity == before.task
        && checkpoint.stop.token.session == before.token.session
        && checkpoint.stop.token.tid == before.token.tid
        && checkpoint.stop.token.task == before.token.task
        && checkpoint.state.registers.cs == 0x33
        && checkpoint.state.registers.rip != 0
        && checkpoint.state.registers.orig_rax
            == if opening {
                before.registers.orig_rax
            } else {
                u64::MAX
            }
        && (576..MAX_XSTATE_BYTES).contains(&checkpoint.state.xstate.len())
}
fn require_word(
    view: StackWordView<'_>,
    profile: &ProfileDescription,
    original_maps: &[u8],
    maps: &[u8],
    state: &TaskStateSnapshot,
    geometry: &OperandGeometry,
) -> Result<u64, CensusError> {
    if !view.complete || view.first_failure.is_some() || view.association.is_none() {
        return Err(CensusError::InvalidConsumption);
    }
    view.observation.require_ready().map_err(invalid)?;
    validate_state(&view.observation.state, profile.layout).map_err(invalid)?;
    view.pagemap_access
        .validate_for(&view.word.pagemap)
        .map_err(invalid)?;
    let value = view.word.validate(geometry).map_err(invalid)?;
    let actual_maps = view
        .observation
        .maps_capture
        .bytes(&view.observation.maps)
        .map_err(invalid)?;
    let smaps = view
        .observation
        .smaps_capture
        .bytes(&view.observation.smaps)
        .map_err(invalid)?;
    let index = profile
        .stack
        .require_current(original_maps, actual_maps)
        .map_err(invalid)?;
    if &view.observation.state.state != state
        || actual_maps != maps
        || validate_smaps(smaps, actual_maps, index).map_err(invalid)? != profile.metadata
    {
        return Err(CensusError::InvalidConsumption);
    }
    Ok(value)
}
fn require_words(actual: &CompletionModel<'_>, binding: &Binding) -> Result<(), CensusError> {
    let words = &actual.words;
    let [a, b, c, d] = words.captures;
    let profile = &binding.profile;
    let geometry = &binding.operand.geometry;
    if ProfileRecord::from(words.profile) != *profile
        || words.operand != &binding.operand
        || !std::ptr::eq(actual.profile, words.profile)
        || actual.operand != words.operand
        || geometry.stack != profile.stack.range()
        || geometry.island != profile.island
    {
        return Err(CensusError::IdentityMismatch);
    }
    binding
        .fetch
        .verify_open(words.baseline_maps, words.opened_maps)
        .map_err(invalid)?;
    let value = require_word(
        a,
        words.profile,
        words.original_maps,
        words.baseline_maps,
        actual.logical.state,
        geometry,
    )?;
    require_word(
        b,
        words.profile,
        words.original_maps,
        words.opened_maps,
        actual.opening[2].state,
        geometry,
    )?;
    require_word(
        c,
        words.profile,
        words.original_maps,
        words.opened_maps,
        actual.step.state,
        geometry,
    )?;
    require_word(
        d,
        words.profile,
        words.original_maps,
        words.baseline_maps,
        actual.closing[2].state,
        geometry,
    )?;
    if value != binding.operand.value
        || validate_state(&a.observation.state, profile.layout).map_err(invalid)?
            != binding.operand.pkru
        || a.word.bytes != b.word.bytes
        || c.word.bytes != d.word.bytes
    {
        return Err(CensusError::InvalidConsumption);
    }
    match a.association {
        Some(StackCaptureAssociation::A {
            stop,
            source_id,
            until,
        }) if stop == actual.logical.stop
            && *source_id == binding.source.id
            && *until == binding.until => {}
        _ => return Err(CensusError::IdentityMismatch),
    }
    match b.association {
        Some(StackCaptureAssociation::B { stop, until })
            if stop == actual.opening[2].stop && *until == binding.until => {}
        _ => return Err(CensusError::IdentityMismatch),
    }
    match c.association {
        Some(StackCaptureAssociation::C {
            original,
            raw_wait,
            ordinal,
            until,
        }) if original == actual.opening[2].stop
            && *raw_wait == (actual.trace.tid, actual.trace.status)
            && *ordinal == 3
            && *until == binding.until => {}
        _ => return Err(CensusError::IdentityMismatch),
    }
    match d.association {
        Some(StackCaptureAssociation::D { stop, until })
            if stop == actual.closing[2].stop && *until == binding.until => {}
        _ => return Err(CensusError::IdentityMismatch),
    }
    validate_effect(
        actual.logical.state,
        actual.step.state,
        words.operand,
        &a.word.bytes,
        &c.word.bytes,
    )
    .map_err(invalid)
}

impl ResumeCensus {
    pub(super) fn validate_stack_model(
        &self,
        reservation: Reservation,
        actual: &CompletionModel<'_>,
        prepared: &PreparedStackCensus,
        calls: &RuntimeCallLedger,
    ) -> Result<(usize, u64, BudgetCharge, BudgetCharge), CensusError> {
        let expected = prepared
            .binding
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        let retained_before = prepared
            .before
            .as_ref()
            .ok_or(CensusError::InvalidConsumption)?;
        prepared.allocation.require_complete()?;
        if !prepared.prepared
            || prepared.committed
            || expected.reservation != reservation
            || actual.origin != expected.origin
            || actual.execution != expected.execution
            || actual.source != expected.source.id
            || actual.until != expected.until
            || actual.operand != &expected.operand
            || ProfileRecord::from(actual.profile) != expected.profile
            || actual.identity_stop != &expected.operand.stop
            || actual.identity_initial != &expected.profile.restored
            || actual.identity_stack != expected.profile.stack
            || actual.identity_metadata != expected.profile.metadata
            || actual.identity_layout != expected.profile.layout
            || actual.identity_rsp != expected.profile.initial_rsp
        {
            return Err(CensusError::IdentityMismatch);
        }
        expected.validate_current(self)?;
        let index = self.active_index(expected.origin)?;
        let before = self.current_observation(expected.origin)?;
        if before != retained_before {
            return Err(CensusError::StaleObservation);
        }
        if !checkpoint_identity(before, actual.logical, true)
            || actual.logical.stop != &expected.operand.stop
            || actual.logical.stop.token != before.token
            || actual.logical.stop.signal.is_some()
            || !matches!(
                actual.logical.stop.phase,
                AdmissionPhase::EntryReady | AdmissionPhase::Restored
            )
            || !same_architecture(before, actual.logical.state)
        {
            return Err(CensusError::InvalidConsumption);
        }
        let mut sequence = before.token.sequence;
        for checkpoint in actual.opening {
            if !checkpoint_identity(before, checkpoint, true)
                || checkpoint.stop.token.sequence <= sequence
                || checkpoint.stop.phase != AdmissionPhase::Restored
                || checkpoint.stop.signal.is_some()
                || !same_architecture(before, checkpoint.state)
            {
                return Err(CensusError::InvalidConsumption);
            }
            sequence = checkpoint.stop.token.sequence;
        }
        let step = actual.step;
        let signal = DynamicSignalInfo {
            raw: actual.trace.signal,
        };
        if !checkpoint_identity(before, step, false)
            || step.stop.token.sequence <= sequence
            || step.stop.phase != AdmissionPhase::NativeCompleted
            || step.stop.signal.is_some()
            || actual.trace.ordinal != 3
            || actual.trace.tid != before.token.tid
            || !libc::WIFSTOPPED(actual.trace.status)
            || libc::WSTOPSIG(actual.trace.status) != libc::SIGTRAP
            || actual.trace.status >> 16 != 0
            || actual.trace.dr6 != TRACE_DR6
            || signal.signal() != libc::SIGTRAP
            || signal.errno() != 0
            || signal.code() != libc::TRAP_TRACE
            || u64::from_ne_bytes(actual.trace.signal[16..24].try_into().map_err(invalid)?)
                != step.state.registers.rip
        {
            return Err(CensusError::InvalidConsumption);
        }
        sequence = step.stop.token.sequence;
        for checkpoint in actual.closing {
            if !checkpoint_identity(before, checkpoint, false)
                || checkpoint.stop.token.sequence <= sequence
                || checkpoint.stop.phase != AdmissionPhase::Restored
                || checkpoint.stop.signal.is_some()
                || checkpoint.state != step.state
            {
                return Err(CensusError::InvalidConsumption);
            }
            sequence = checkpoint.stop.token.sequence;
        }
        require_words(actual, expected)?;
        calls.require_completed_call(actual.call, expected, before)?;
        if retained_before.xstate.capacity() != MAX_XSTATE_BYTES
            || prepared.buffers[0].capacity() != 0
            || !prepared.buffers[0].is_empty()
            || prepared.buffers[1..]
                .iter()
                .any(|b| !b.is_empty() || b.capacity() != MAX_XSTATE_BYTES)
            || prepared.evidence.as_ref().is_none_or(|v| {
                v.len() != 1
                    || v[0].binding.as_ref() != Some(expected)
                    || v[0].trace.is_some()
                    || v[0].words.is_some()
                    || v[0].call.is_some()
            })
            || prepared.settled_bytes != preparation_bytes()?
            || self.state.origins.len() == self.state.origins.capacity()
            || self
                .state
                .history
                .capacity()
                .saturating_sub(self.state.history.len())
                < WITNESSES
        {
            return Err(CensusError::Capacity);
        }
        let next = self
            .state
            .next_serial
            .checked_add(1)
            .ok_or(CensusError::Capacity)?;
        let (remaining, used) = self.prepare_debit(reservation, prepared.remaining_charge()?)?;
        Ok((index, next, remaining, used))
    }
}
