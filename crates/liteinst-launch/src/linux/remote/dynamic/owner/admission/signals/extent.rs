//! Positive fixed native-x86-64 regset extent, scoped to one held incarnation.
//!
//! Linux's native NT_X86_XSTATE regset count is set from fpu_user_cfg.max_size
//! during boot and is read-only afterward. A successful oversized request thus
//! observes the exported ABI extent, including absent dynamic components. This
//! does not infer allocator capacity, RSS, active features or vendor build
//! identity. All diagnostic buffers retain their original 64 KiB capacity.
use super::super::super::signal_journal::SignalXstateRead;
use super::*;

pub(super) struct NativeExtent {
    initial: DynamicStop,
    identity: DynamicTask,
    query: SignalXstateRead,
}

impl NativeExtent {
    pub(super) fn acquire(
        owner: &Owner,
        boot: &super::super::super::bootstrap::BootstrapMm,
        until: Instant,
    ) -> Result<Self, GateError> {
        owner.time_left(until, "signal XSTATE extent acquisition")?;
        let stop = &boot.stop;
        let native = owner.lifecycle.as_ref().ok_or(GateError::Refused(
            "signal extent lacks native lifecycle ownership",
        ))?;
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
            || members.candidate.tasks != vec![stop.identity.task]
            || members.address_space != stop.identity.address_space
            || members.process != stop.identity.process
            || members.generation != stop.identity.generation
            || members.tgid != owner.pid
            || members.tids != BTreeSet::from([owner.pid])
            || !owner.owned.contains(&owner.pid)
            || owner.handles.get(&owner.pid).is_none_or(broker::hup)
        {
            return Err(GateError::Refused(
                "signal extent bootstrap identity or phase differs",
            ));
        }
        let status = *owner.stopped.get(&owner.pid).ok_or(GateError::Refused(
            "signal extent has no retained real stop",
        ))?;
        let journal = owner.signal_journal.as_ref().ok_or(GateError::Refused(
            "signal extent has no preallocated archive",
        ))?;
        // Retain the actual wait, siginfo, complete/partial state and each query
        // result before phase or extent interpretation. No invented stop event.
        let result = (|| {
            let (raw_info, state, query) = journal.capture_extent_state(owner.pid, status)?;
            let info = DynamicSignalInfo { raw: raw_info };
            if !libc::WIFSTOPPED(status)
                || status >> 16 != 0
                || libc::WSTOPSIG(status) != libc::SIGTRAP
                || info.signal() != libc::SIGTRAP
                || !matches!(info.code(), libc::SI_KERNEL | libc::TRAP_BRKPT)
                || state != boot.evidence.restored_entry
                || TaskStateSnapshot::read(owner.pid)? != state
            {
                return Err(GateError::Refused(
                    "signal extent does not retain the exact bootstrap neutral state",
                ));
            }
            validate_query(query, &state)?;
            native.require_admission_stop(stop)?;
            owner.time_left(until, "signal XSTATE extent authentication")?;
            Ok(Self {
                initial: stop.token.clone(),
                identity: stop.identity,
                query,
            })
        })();
        if let Err(error) = &result {
            match error {
                GateError::Control(error) => journal.fail_error(error),
                _ => journal
                    .fail(super::super::super::signal_journal::SignalJournalFailure::InvalidState),
            }
        }
        result
    }

    pub(super) fn bytes(&self) -> usize {
        self.query.reported_bytes
    }

    /// The caller independently authenticates this token against the current
    /// registry generation/held phase. Legitimate same-mm rebinds change that
    /// generation; they never replace this immutable task/process/mm binding.
    pub(super) fn verify(
        &self,
        token: &DynamicStop,
        identity: DynamicTask,
        state: &TaskStateSnapshot,
    ) -> Result<(), GateError> {
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
            || state.xstate.len() != self.bytes()
        {
            return Err(GateError::Refused(
                "signal state differs from its immutable native XSTATE extent",
            ));
        }
        Ok(())
    }
}

fn validate_query(query: SignalXstateRead, state: &TaskStateSnapshot) -> Result<(), GateError> {
    if state.registers.cs != 0x33
        || query.result != 0
        || query.errno.is_some()
        || !query.pointer_unchanged
        || query.reported_bytes < 512
        || query.reported_bytes >= MAX_XSTATE
        || query.reported_bytes % 8 != 0
        || state.xstate.len() != query.reported_bytes
    {
        return Err(GateError::Refused(
            "signal XSTATE maximum request did not authenticate a fixed ABI extent",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
