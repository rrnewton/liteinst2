use super::*;

impl From<ExecRelease> for ExecReleasePhase {
    fn from(phase: ExecRelease) -> Self {
        match phase {
            ExecRelease::Original => Self::Original,
            ExecRelease::Entry => Self::Entry,
            ExecRelease::ExecEvent => Self::ExecEvent,
        }
    }
}
impl From<BootstrapEffect> for ExecBootstrapEffect {
    fn from(effect: BootstrapEffect) -> Self {
        match effect {
            BootstrapEffect::PatchEntry => Self::PatchEntry,
            BootstrapEffect::FirstUserResume => Self::FirstUserResume,
            BootstrapEffect::RestoreEntry => Self::RestoreEntry,
            BootstrapEffect::WriteStub => Self::WriteStub,
            BootstrapEffect::MapIsland => Self::MapIsland,
            BootstrapEffect::WriteIsland { address } => Self::WriteIsland { address },
            BootstrapEffect::ProtectIsland { address, length } => {
                Self::ProtectIsland { address, length }
            }
            BootstrapEffect::QueryMembarrier => Self::QueryMembarrier,
            BootstrapEffect::RegisterMembarrier => Self::RegisterMembarrier,
            BootstrapEffect::BootstrapSync => Self::BootstrapSync,
            BootstrapEffect::RestoreOriginal => Self::RestoreOriginal,
            BootstrapEffect::QuarantineSyncBefore => Self::QuarantineSyncBefore,
            BootstrapEffect::Quarantine { start, length } => Self::Quarantine { start, length },
            BootstrapEffect::QuarantineSyncAfter => Self::QuarantineSyncAfter,
        }
    }
}
fn token_matches(token: &DynamicStop, identity: DynamicTask, attempt: &Attempt) -> bool {
    token.session == attempt.id.session
        && token.tid == attempt.pending.stop.tid
        && token.task == Some(identity.task)
}
fn raw_state<'a>(
    attempt: &'a Attempt,
    state: &TaskStateSnapshot,
) -> Result<(u8, &'a ExecRawRecord), LaunchError> {
    let ordinal = attempt
        .pending_raw
        .ok_or(invalid("exec journal validated phase has no raw wait"))?;
    let raw = &attempt.raw[usize::from(ordinal)];
    if !raw.state_equals(state) {
        return Err(invalid(
            "exec journal validated full state differs from raw capture",
        ));
    }
    Ok((ordinal, &raw.record))
}
fn raw_syscall(record: &ExecRawRecord, state: &TaskStateSnapshot, operation: u8) -> bool {
    let bytes = &record.syscall_info;
    let word = |at: usize| u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap());
    record.status == (((libc::SIGTRAP | 0x80) << 8) | 0x7f)
        && bytes[0] == operation
        && u32::from_ne_bytes(bytes[4..8].try_into().unwrap()) == 0xc000_003e
        && word(8) == state.registers.rip
        && word(16) == state.registers.rsp
}
impl ExecObservation for ExecJournalObserver {
    fn prepared(
        &mut self,
        owner: &Owner,
        invocation: &ExecInvocation<'_>,
        until: Instant,
    ) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            self.handle,
            ExecJournalStage::Prepared,
            |attempt| {
                check_time(attempt.until)?;
                if attempt.native_phase != NativePhase::Restored
                    || attempt.original_stop.is_some()
                    || until != attempt.until
                    || original_input(invocation.input)? != attempt.input
                    || !attempt.before.equals(invocation.before)
                    || invocation.stop.identity != attempt.pending.task
                    || !token_matches(&invocation.stop.token, invocation.stop.identity, attempt)
                    || invocation.stop.token.sequence < attempt.pending.stop.sequence
                    || invocation.stop.signal.is_some()
                    || !matches!(
                        invocation.stop.phase,
                        trusted::AdmissionPhase::Restored | trusted::AdmissionPhase::EntryReady
                    )
                    || owner.session != attempt.id.session
                    || owner.pid != invocation.stop.token.tid
                    || owner.owned.len() != 1
                    || !owner.owned.contains(&owner.pid)
                    || !owner.stopped.contains_key(&owner.pid)
                    || owner.pin_kinds.get(&owner.pid) != Some(&PinKind::Process)
                    || owner.handles.get(&owner.pid).is_none_or(broker::hup)
                {
                    return Err(invalid("exec journal native prepared binding differs"));
                }
                attempt.original_stop = Some((&invocation.stop.token).into());
                attempt.native_phase = NativePhase::Ready;
                Ok(())
            },
        )
    }
    fn raw(&mut self, owner: &Owner, tid: i32, status: i32) -> Result<(), LaunchError> {
        self.capture_raw(owner, tid, status)
    }
    fn entry(
        &mut self,
        event: &DynamicEvent,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            self.handle,
            ExecJournalStage::Entry,
            |attempt| {
                let (ordinal, raw) = raw_state(attempt, state)?;
                let token = event
                    .stop_token()
                    .ok_or(invalid("exec journal ENTRY token is absent"))?;
                if attempt.native_phase != NativePhase::OriginalReleased
                    || event.tid != raw.tid
                    || event.task != Some(attempt.pending.task)
                    || !token_matches(token, attempt.pending.task, attempt)
                    || token.sequence
                        <= attempt
                            .original_stop
                            .ok_or(invalid("exec journal original stop absent"))?
                            .sequence
                    || event.kind
                        != (DynamicEventKind::SyscallEntry {
                            number: libc::SYS_execve as u64,
                            arguments: attempt.input.arguments,
                        })
                    || !raw_syscall(raw, state, 1)
                    || u64::from_ne_bytes(raw.syscall_info[24..32].try_into().unwrap())
                        != libc::SYS_execve as u64
                    || (0..6).any(|index| {
                        u64::from_ne_bytes(
                            raw.syscall_info[32 + index * 8..40 + index * 8]
                                .try_into()
                                .unwrap(),
                        ) != attempt.input.arguments[index]
                    })
                {
                    return Err(invalid("exec journal ENTRY validation differs"));
                }
                let stop = token.into();
                attempt.append(ExecJournalFact::Validated {
                    phase: ExecValidatedPhase::Entry,
                    ordinal,
                    stop,
                    identity: attempt.pending.task,
                })?;
                attempt.entry_stop = Some(stop);
                attempt.pending_raw = None;
                attempt.native_phase = NativePhase::EntrySeen;
                Ok(())
            },
        )
    }
    fn replaced(
        &mut self,
        previous: DynamicTask,
        event: &DynamicEvent,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            self.handle,
            ExecJournalStage::Replaced,
            |attempt| {
                let (ordinal, raw) = raw_state(attempt, state)?;
                let identity = event
                    .task
                    .ok_or(invalid("exec journal EXEC identity absent"))?;
                let token = event
                    .stop_token()
                    .ok_or(invalid("exec journal EXEC token absent"))?;
                if attempt.native_phase != NativePhase::EntryReleased
                    || previous != attempt.pending.task
                    || !matches!(&event.kind, DynamicEventKind::ExecReplaced { previous: old, .. } if *old == previous)
                    || identity.process != previous.process
                    || identity.task == previous.task
                    || identity.address_space == previous.address_space
                    || identity.generation != 0
                    || !token_matches(token, identity, attempt)
                    || token.sequence != 0
                    || event.tid != raw.tid
                    || raw.status != ((libc::PTRACE_EVENT_EXEC << 16) | (libc::SIGTRAP << 8) | 0x7f)
                    || raw.event_read.is_none_or(|read| read.result != 0)
                    || raw.event_message != event.tid as u64
                {
                    return Err(invalid(
                        "exec journal replacement identity or raw EXEC differs",
                    ));
                }
                let stop = token.into();
                attempt.append(ExecJournalFact::Validated {
                    phase: ExecValidatedPhase::Replaced,
                    ordinal,
                    stop,
                    identity,
                })?;
                attempt.exec_stop = Some(stop);
                attempt.replacement = Some(identity);
                attempt.pending_raw = None;
                attempt.native_phase = NativePhase::ExecSeen;
                Ok(())
            },
        )
    }
    fn exit(&mut self, event: &DynamicEvent, state: &TaskStateSnapshot) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            self.handle,
            ExecJournalStage::Exit,
            |attempt| {
                let (ordinal, raw) = raw_state(attempt, state)?;
                let identity = attempt
                    .replacement
                    .ok_or(invalid("exec journal replacement identity absent"))?;
                let token = event
                    .stop_token()
                    .ok_or(invalid("exec journal EXIT token absent"))?;
                if attempt.native_phase != NativePhase::ExecReleased
                    || event.task != Some(identity)
                    || event.tid != raw.tid
                    || !token_matches(token, identity, attempt)
                    || token.sequence
                        <= attempt
                            .exec_stop
                            .ok_or(invalid("exec journal EXEC stop absent"))?
                            .sequence
                    || event.kind
                        != (DynamicEventKind::SyscallExit {
                            result: 0,
                            is_error: false,
                        })
                    || !raw_syscall(raw, state, 2)
                    || raw.syscall_info[32] != 0
                    || i64::from_ne_bytes(raw.syscall_info[24..32].try_into().unwrap()) != 0
                {
                    return Err(invalid("exec journal actual EXIT validation differs"));
                }
                let stop = token.into();
                attempt.append(ExecJournalFact::Validated {
                    phase: ExecValidatedPhase::Exit,
                    ordinal,
                    stop,
                    identity,
                })?;
                attempt.exit_stop = Some(stop);
                attempt.pending_raw = None;
                attempt.native_phase = NativePhase::ExitSeen;
                Ok(())
            },
        )
    }
    fn release_attempt(
        &mut self,
        phase: ExecRelease,
        stop: &DynamicStop,
    ) -> Result<(), LaunchError> {
        self.release(phase, stop, false)
    }
    fn release_succeeded(
        &mut self,
        phase: ExecRelease,
        stop: &DynamicStop,
    ) -> Result<(), LaunchError> {
        self.release(phase, stop, true)
    }
    fn failed(&mut self, error: &LaunchError) {
        lock(&self.archive).fail(failure(error));
    }
}
impl ExecJournalObserver {
    fn release(
        &self,
        phase: ExecRelease,
        stop: &DynamicStop,
        completed: bool,
    ) -> Result<(), LaunchError> {
        let (stage, before, attempted, after) = match phase {
            ExecRelease::Original => (
                ExecJournalStage::OriginalRelease,
                NativePhase::Ready,
                NativePhase::OriginalAttempted,
                NativePhase::OriginalReleased,
            ),
            ExecRelease::Entry => (
                ExecJournalStage::EntryRelease,
                NativePhase::EntrySeen,
                NativePhase::EntryAttempted,
                NativePhase::EntryReleased,
            ),
            ExecRelease::ExecEvent => (
                ExecJournalStage::ExecRelease,
                NativePhase::ExecSeen,
                NativePhase::ExecAttempted,
                NativePhase::ExecReleased,
            ),
        };
        mutate(&self.archive, self.handle, stage, |attempt| {
            if !completed {
                check_time(attempt.until)?;
                if attempt
                    .fact_count
                    .checked_add(2)
                    .is_none_or(|count| count > FACTS)
                {
                    return Err(invalid("exec journal release pair capacity exhausted"));
                }
            }
            let expected = match phase {
                ExecRelease::Original => attempt.original_stop,
                ExecRelease::Entry => attempt.entry_stop,
                ExecRelease::ExecEvent => attempt.exec_stop,
            };
            if expected != Some(stop.into())
                || attempt.native_phase != if completed { attempted } else { before }
            {
                return Err(invalid("exec journal original release pair differs"));
            }
            attempt.append(if completed {
                ExecJournalFact::ReleaseSucceeded {
                    phase: phase.into(),
                    stop: stop.into(),
                }
            } else {
                ExecJournalFact::ReleaseAttempt {
                    phase: phase.into(),
                    stop: stop.into(),
                }
            })?;
            attempt.native_phase = if completed { after } else { attempted };
            Ok(())
        })
    }
}
fn expected_effect(attempt: &Attempt, effect: ExecBootstrapEffect) -> bool {
    match (attempt.effect_index, effect) {
        (0, ExecBootstrapEffect::PatchEntry) | (1, ExecBootstrapEffect::FirstUserResume) => true,
        (2, ExecBootstrapEffect::RestoreEntry) => attempt.trap_raw.is_some(),
        (3, ExecBootstrapEffect::WriteStub) => attempt.restored_entry.complete,
        (4, ExecBootstrapEffect::MapIsland) => true,
        (5, ExecBootstrapEffect::WriteIsland { address }) => attempt.island == Some(address),
        (6, ExecBootstrapEffect::ProtectIsland { address, length }) => {
            attempt.island == Some(address) && length == 4096
        }
        (7, ExecBootstrapEffect::QueryMembarrier)
        | (8, ExecBootstrapEffect::RegisterMembarrier)
        | (9, ExecBootstrapEffect::BootstrapSync)
        | (10, ExecBootstrapEffect::RestoreOriginal)
        | (11, ExecBootstrapEffect::QuarantineSyncBefore) => true,
        (12, ExecBootstrapEffect::Quarantine { start, length }) => {
            attempt.quarantine_count < QUARANTINE_LIMIT
                && length != 0
                && start % 4096 == 0
                && length % 4096 == 0
                && start >= attempt.quarantine_end
                && start.checked_add(length as u64).is_some()
        }
        (12, ExecBootstrapEffect::QuarantineSyncAfter) => attempt.quarantine_count != 0,
        _ => false,
    }
}
impl ReplacedBootstrapObservation for ExecJournalObserver {
    fn before_effect(&mut self, effect: BootstrapEffect) -> Result<(), LaunchError> {
        let effect = effect.into();
        mutate(
            &self.archive,
            self.handle,
            ExecJournalStage::Bootstrap,
            |attempt| {
                check_time(attempt.until)?;
                if !matches!(
                    attempt.native_phase,
                    NativePhase::ExitSeen | NativePhase::Bootstrapping
                ) || attempt.outstanding_effect.is_some()
                    || !expected_effect(attempt, effect)
                {
                    return Err(invalid(
                        "exec journal bootstrap effect order or geometry differs",
                    ));
                }
                // Reserve both facts before the native effect; completion cannot
                // discover a fact-capacity failure after the effect has happened.
                if attempt
                    .fact_count
                    .checked_add(2)
                    .is_none_or(|count| count > FACTS)
                {
                    return Err(invalid("exec journal bootstrap pair capacity exhausted"));
                }
                attempt.append(ExecJournalFact::EffectAttempt { effect })?;
                attempt.outstanding_effect = Some(effect);
                attempt.native_phase = NativePhase::Bootstrapping;
                Ok(())
            },
        )
    }
    fn effect_complete(
        &mut self,
        effect: BootstrapEffect,
        result: Option<u64>,
    ) -> Result<(), LaunchError> {
        let effect = effect.into();
        mutate(
            &self.archive,
            self.handle,
            ExecJournalStage::Bootstrap,
            |attempt| {
                if attempt.native_phase != NativePhase::Bootstrapping
                    || attempt.outstanding_effect != Some(effect)
                {
                    return Err(invalid("exec journal bootstrap completion pair differs"));
                }
                // Retain the actual returned value before interpreting it. A later
                // payload rejection leaves this successful-call fact and failure.
                attempt.append(ExecJournalFact::EffectComplete { effect, result })?;
                if matches!(
                    effect,
                    ExecBootstrapEffect::MapIsland | ExecBootstrapEffect::QueryMembarrier
                ) != result.is_some()
                {
                    return Err(invalid("exec journal bootstrap completion payload differs"));
                }
                if effect == ExecBootstrapEffect::MapIsland
                    && result.is_none_or(|address| address == 0 || address % 4096 != 0)
                {
                    return Err(invalid("exec journal mapped island result differs"));
                }
                if effect == ExecBootstrapEffect::MapIsland {
                    attempt.island = result;
                }
                match effect {
                    ExecBootstrapEffect::Quarantine { start, length } => {
                        attempt.quarantine_count += 1;
                        attempt.quarantine_end = start + length as u64;
                    }
                    ExecBootstrapEffect::QuarantineSyncAfter => attempt.effect_index = 14,
                    _ => attempt.effect_index += 1,
                }
                attempt.outstanding_effect = None;
                Ok(())
            },
        )
    }
    fn raw(&mut self, owner: &Owner, tid: i32, status: i32) -> Result<(), LaunchError> {
        self.capture_raw(owner, tid, status)
    }
    fn entry_trap(&mut self, state: &TaskStateSnapshot) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            self.handle,
            ExecJournalStage::Bootstrap,
            |attempt| {
                let (ordinal, raw) = raw_state(attempt, state)?;
                if attempt.native_phase != NativePhase::Bootstrapping
                    || attempt.effect_index != 2
                    || attempt.outstanding_effect.is_some()
                    || attempt.trap_raw.is_some()
                    || raw.status != ((libc::SIGTRAP << 8) | 0x7f)
                    || raw.siginfo_read.is_none_or(|read| read.result != 0)
                {
                    return Err(invalid("exec journal first-user trap differs"));
                }
                attempt.append(ExecJournalFact::FirstUserTrap { ordinal })?;
                attempt.trap_raw = Some(ordinal);
                attempt.pending_raw = None;
                Ok(())
            },
        )
    }
    fn restored_entry(
        &mut self,
        stop: &AdmissionStop,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            self.handle,
            ExecJournalStage::Bootstrap,
            |attempt| {
                let raw = &attempt.raw[usize::from(
                    attempt
                        .trap_raw
                        .ok_or(invalid("exec journal first-user trap absent"))?,
                )]
                .record;
                let mut expected = raw.registers;
                expected.rip = expected
                    .rip
                    .checked_sub(1)
                    .ok_or(invalid("exec journal first-user RIP underflows"))?;
                let query = raw
                    .xstate_query
                    .ok_or(invalid("exec journal first-user XSTATE absent"))?;
                let identity = attempt
                    .replacement
                    .ok_or(invalid("exec journal replacement identity absent"))?;
                if attempt.native_phase != NativePhase::Bootstrapping
                    || attempt.effect_index != 3
                    || attempt.outstanding_effect.is_some()
                    || state.registers != expected
                    || raw.initialized_xstate[..query.reported_bytes] != state.xstate
                    || raw.signal_mask != state.mask
                    || stop.identity != identity
                    || !token_matches(&stop.token, identity, attempt)
                    || stop.token.sequence
                        <= attempt
                            .exit_stop
                            .ok_or(invalid("exec journal actual EXIT absent"))?
                            .sequence
                    || stop.signal.is_some()
                {
                    return Err(invalid("exec journal restored first-user state differs"));
                }
                attempt.restored_entry.save(state)?;
                attempt.append(ExecJournalFact::RestoredEntry {
                    stop: (&stop.token).into(),
                })?;
                Ok(())
            },
        )
    }
    fn complete(&mut self, bootstrap: &BootstrapMm) -> Result<(), LaunchError> {
        mutate(
            &self.archive,
            self.handle,
            ExecJournalStage::Bootstrap,
            |attempt| {
                let identity = attempt
                    .replacement
                    .ok_or(invalid("exec journal replacement identity absent"))?;
                if attempt.native_phase != NativePhase::Bootstrapping
                    || attempt.effect_index != 14
                    || attempt.outstanding_effect.is_some()
                    || attempt.pending_raw.is_some()
                    || bootstrap.stop.identity != identity
                    || !token_matches(&bootstrap.stop.token, identity, attempt)
                    || bootstrap.stop.token.sequence
                        <= attempt
                            .exit_stop
                            .ok_or(invalid("exec journal EXIT absent"))?
                            .sequence
                    || bootstrap.stop.signal.is_some()
                    || bootstrap.original_executables.len() != attempt.quarantine_count
                    || !attempt
                        .restored_entry
                        .equals(&bootstrap.evidence.restored_entry)
                    || !bootstrap_raw_states_match(attempt, bootstrap)
                    || !bootstrap_ranges_match(attempt, bootstrap)
                {
                    return Err(invalid("exec journal final bootstrap binding differs"));
                }
                // Native complete is called only after a fresh full-state comparison
                // with this exact restored-entry image. Internal runner waits are not
                // fabricated as separately captured raw observations.
                attempt
                    .final_state
                    .save(&bootstrap.evidence.restored_entry)?;
                let stop = (&bootstrap.stop.token).into();
                attempt.append(ExecJournalFact::BootstrapComplete { stop })?;
                attempt.final_stop = Some(stop);
                attempt.native_phase = NativePhase::BootstrapComplete;
                Ok(())
            },
        )
    }
    fn failed(&mut self, error: &LaunchError) {
        lock(&self.archive).fail(failure(error));
    }
}

fn bootstrap_raw_states_match(attempt: &Attempt, bootstrap: &BootstrapMm) -> bool {
    let matches = |phase, state: &TaskStateSnapshot| {
        attempt.facts[..attempt.fact_count]
            .iter()
            .flatten()
            .find_map(|fact| match fact {
                ExecJournalFact::Validated {
                    phase: actual,
                    ordinal,
                    ..
                } if *actual == phase => {
                    Some(attempt.raw[usize::from(*ordinal)].state_equals(state))
                }
                _ => None,
            })
            .unwrap_or(false)
    };
    matches(ExecValidatedPhase::Replaced, &bootstrap.evidence.exec_event)
        && matches(ExecValidatedPhase::Exit, &bootstrap.evidence.exec_exit)
        && attempt.trap_raw.is_some_and(|ordinal| {
            attempt.raw[usize::from(ordinal)].state_equals(&bootstrap.evidence.entry_trap)
        })
}
fn bootstrap_ranges_match(attempt: &Attempt, bootstrap: &BootstrapMm) -> bool {
    if bootstrap
        .original_executables
        .iter()
        .any(|map| map.end <= map.start)
    {
        return false;
    }
    attempt.facts[..attempt.fact_count]
        .iter()
        .flatten()
        .filter_map(|fact| match fact {
            ExecJournalFact::EffectComplete {
                effect: ExecBootstrapEffect::Quarantine { start, length },
                result: None,
            } => Some((*start, *length)),
            _ => None,
        })
        .eq(bootstrap
            .original_executables
            .iter()
            .map(|map| (map.start, (map.end - map.start) as usize)))
}
