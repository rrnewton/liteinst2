//! Optional facade over the existing absolute history engine. No new log or reset.
use super::super::history as shared;
use super::*;
use crate::frontend::MAX_HISTORY_POSITION;

impl PreparedOptionalController {
    /// Opt in to bounded resident history transfer. Legacy `new` stays finite.
    /// Lifetime prefixes remain absolute and checked; drained chunks own no epoch.
    pub fn new_streaming_history(
        site: InstalledOptionalSite,
        install: u64,
        function: FunctionId,
        limits: Limits,
    ) -> Result<Self, BridgeError> {
        let session = Session::new_streaming_history(
            install,
            &[FunctionSpec { function, group: 0 }],
            &[GroupSpec { mandatory: false }],
            limits,
        )
        .map_err(|e| error(Cause::Setup(e)))?;
        let mut epochs = Vec::new();
        epochs
            .try_reserve_exact(limits.epochs)
            .map_err(|_| error(Cause::Capacity))?;
        Ok(Self {
            session,
            site: site.site,
            writer: site.writer,
            key: Arc::new(()),
            install,
            function,
            limits,
            epochs,
            _exclusive: PhantomData,
        })
    }
}
fn stream(binding: &Binding) -> Result<HistoryStream, BridgeError> {
    if binding.session.history_mode() != HistoryMode::Absolute {
        return Err(error(Cause::Control(ControlError::HistoryMode)));
    }
    Ok(HistoryStream::from_binding(
        &binding.key,
        binding.pid,
        binding.install,
        binding.function,
    ))
}
fn control_error(binding: &Binding, e: ControlError) -> BridgeError {
    // A diagnostic exposing poison/terminal inconsistency must also protect Fast.
    // Explicit mode and output-reservation refusals do not mutate execution health.
    if matches!(
        e,
        ControlError::Poisoned | ControlError::TerminalFailure | ControlError::HistoryInvariant
    ) {
        binding.failed.store(true, Ordering::Release);
    }
    error(Cause::Control(e))
}
impl OptionalController {
    /// Transfer all resident actions. Allocation precedes writer→registry locks;
    /// no selector store, epoch release, native-return or sink acknowledgement.
    /// An optional mutation failure stays sticky and cannot authorize this drain.
    pub fn drain_history(&mut self) -> Result<Option<HistoryBatch>, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.healthy()?;
        let stream = stream(&self.binding)?;
        self.binding
            .session
            .drain_history()
            .map_err(|e| control_error(&self.binding, e))
            .map(|chunk| chunk.map(|chunk| HistoryBatch::from_checked(stream, chunk)))
    }
    /// Qualified diagnostic suffix, including FailedAfter. It is never a complete
    /// history or normal transferred batch. `enabled` is model history metadata,
    /// not an observation of the physical selector (e.g. after removal).
    pub fn history_window(&self) -> Result<HistoryWindow, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        let stream = stream(&self.binding)?;
        let view = self
            .binding
            .session
            .history_window()
            .map_err(|e| control_error(&self.binding, e))?;
        Ok(HistoryWindow::from_checked(stream, view))
    }
}
pub(super) fn packed_for(
    binding: &Binding,
    summary: IntervalEntrySummary,
) -> Result<(u64, u64, u64), BridgeError> {
    if binding.session.history_mode() == HistoryMode::Legacy {
        packed(summary, binding.function)
    } else {
        shared::packed_absolute(
            summary,
            binding.function,
            binding.session.history_committed_end(),
        )
    }
}
pub(super) fn decode(bits: u64, high_water: u64) -> Option<(u64, u64, u64)> {
    shared::decode_absolute(bits, high_water)
}
pub(super) fn batch_identity(
    binding: &Binding,
) -> Result<(Option<HistoryStream>, Option<u64>), BridgeError> {
    if binding.session.history_mode() == HistoryMode::Legacy {
        return Ok((None, None));
    }
    // Capture after validating every row; committed_end only advances. The key
    // clone allocates nothing and both values precede the storage-clear commit.
    let high_water = binding.session.history_committed_end();
    if high_water > MAX_HISTORY_POSITION {
        return Err(error(Cause::Invariant));
    }
    Ok((Some(stream(binding)?), Some(high_water)))
}
pub(super) fn pair_matches_absolute(
    row: &RawInterval,
    entry: &[u64],
    exit: &[u64],
    s: &State,
) -> bool {
    let bits = entry[6];
    let Some((invocation, prefix, reason)) =
        decode(bits, s.binding.session.history_committed_end())
    else {
        return false;
    };
    let (kind, generation, owner) = match row.owner {
        RawIntervalOwner::Sampled {
            generation,
            invocation: n,
        } => (
            1,
            generation,
            generation != 0
                && reason == 0
                && n.checked_add(1).and_then(|n| u64::try_from(n).ok()) == Some(invocation)
                && invocation != 0
                && prefix != 0,
        ),
        RawIntervalOwner::InitialDisarmed => (3, 0, reason == 1 && invocation == 0),
        RawIntervalOwner::Removed { generation } => (
            3,
            generation,
            generation != 0 && reason == 2 && invocation == 0 && prefix != 0,
        ),
        RawIntervalOwner::FunctionClosed { generation } => (
            3,
            generation,
            generation != 0 && reason == 3 && invocation == 0 && prefix != 0,
        ),
    };
    let gate = &s.binding.site.gate;
    owner
        && invocation <= 4096
        && bits == (invocation | ((prefix & 0x1ff) << 13) | (reason << 22) | ((prefix >> 9) << 24))
        && row.entry_pc == gate.target()
        && gate.returns().contains(&row.return_pc)
        && entry
            == [
                kind,
                row.ordinal,
                row.entry_pc,
                entry[3],
                gate.continuation(),
                generation,
                bits,
            ]
        && exit
            == [
                kind + 1,
                row.ordinal,
                row.return_pc,
                entry[3],
                entry[4],
                generation,
                bits,
            ]
        && entry[3] >= s.stack.start
        && entry[3] & 15 == 8
        && entry[3]
            .checked_add(8)
            .is_some_and(|end| end <= s.stack.end)
}

// Test-only actual model ownership. These objects have no published instructions;
// no native return, gate completion, fabricated raw row or receipt is supplied.
#[cfg(test)]
pub(crate) fn metadata_site() -> InstalledOptionalSite {
    use liteinst2::precontext::{PreContextAction, PreContextRole, PreContextSelector};
    let gate = gate::tests::descriptor();
    let (selector, writer) = PreContextSelector::new(false);
    let roles = vec![
        PreContextAction::new(
            gate.target(),
            PreContextRole::Entry,
            &selector,
            entry_callback,
        ),
        PreContextAction::new(
            gate.returns()[0],
            PreContextRole::Return,
            &selector,
            exit_callback,
        ),
    ];
    InstalledOptionalSite {
        site: Arc::new(site::Site {
            roles,
            gate,
            selector,
        }),
        writer,
    }
}
#[cfg(test)]
impl OptionalController {
    /// Register exactly once per metadata test; lifetime registration is retained.
    pub(crate) fn metadata_model(&self) -> Result<ThreadModel, BridgeError> {
        self.binding.healthy()?;
        self.binding
            .session
            .register_thread(1)
            .map_err(|e| error(Cause::Setup(e)))
    }
    pub(crate) fn metadata_complete(
        &mut self,
        model: &mut ThreadModel,
        e: &IntervalEpoch,
        count: usize,
    ) -> Result<(), BridgeError> {
        let generation = self.owner(e)?.generation();
        if self
            .binding
            .session
            .snapshot_for_bridge()
            .map_err(|e| error(Cause::Control(e)))?
            .current
            != Some(generation)
        {
            return Err(error(Cause::CurrentEpoch));
        }
        for n in 0..count {
            let mut slot = ModelReturnSlot {
                identity: n as u64 + 1,
                word: TOKEN,
            };
            let mut entered = model
                .enter_interval_waiting(self.binding.install, self.binding.function, 10, &mut slot)
                .map_err(|e| error(Cause::Entry(e)))?;
            assert!(
                matches!(entered.summary(),Some(IntervalEntrySummary::Admitted{generation:g,..}) if g==generation)
            );
            model
                .finish_interval(&mut entered, &mut slot, Observation::Value(13))
                .map_err(|e| error(Cause::Exit(e)))?;
            assert_eq!(slot.word, TOKEN);
        }
        Ok(())
    }
}
