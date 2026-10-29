//! Explicit bounded action transfer. No epoch/code quiescence or durable export.
use super::*;
use crate::frontend::{Action, ActionKind, HistoryChunk, HistoryView, MAX_HISTORY_POSITION};
use std::ops::Range;

/// The old word layout is selected only by legacy construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryFormat {
    LegacyV1,
    AbsoluteV1,
}

/// Opaque in-process identity, not a globally unique installation number.
/// Its key retains no Session, epoch, ticket, source or gate owner.
#[derive(Clone, Debug)]
pub struct HistoryStream {
    key: Arc<()>,
    pid: u32,
    install: u64,
    function: FunctionId,
}
impl PartialEq for HistoryStream {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.key, &other.key)
            && self.pid == other.pid
            && self.install == other.install
            && self.function == other.function
    }
}
impl Eq for HistoryStream {}
impl HistoryStream {
    // Crate-owned facade bindings only; never a public forgeable identity.
    pub(super) fn from_binding(
        key: &Arc<()>,
        pid: u32,
        install: u64,
        function: FunctionId,
    ) -> Self {
        Self {
            key: Arc::clone(key),
            pid,
            install,
            function,
        }
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn install(&self) -> u64 {
        self.install
    }
    pub fn function(&self) -> FunctionId {
        self.function
    }
    pub fn format(&self) -> HistoryFormat {
        HistoryFormat::AbsoluteV1
    }
}
pub(super) fn stream_for(binding: &Binding) -> Option<HistoryStream> {
    let function = binding.single_function().ok()?;
    (binding.session.history_mode() == HistoryMode::Absolute).then(|| HistoryStream {
        key: Arc::clone(&binding.key),
        pid: binding.pid,
        install: binding.install,
        function,
    })
}

/// Immutable contiguous action transfer. Retaining or dropping it consumes no
/// epoch permit and acknowledges neither an external sink nor a native return.
#[derive(Debug, Eq, PartialEq)]
pub struct HistoryBatch {
    stream: HistoryStream,
    chunk: HistoryChunk,
}
impl HistoryBatch {
    pub(super) fn from_checked(stream: HistoryStream, chunk: HistoryChunk) -> Self {
        Self { stream, chunk }
    }
    pub fn stream(&self) -> &HistoryStream {
        &self.stream
    }
    pub fn number(&self) -> u64 {
        self.chunk.number
    }
    pub fn range(&self) -> Range<u64> {
        self.chunk.range.clone()
    }
    pub fn before(&self) -> HistoryBinding {
        self.chunk.before
    }
    pub fn after(&self) -> HistoryBinding {
        self.chunk.after
    }
    pub fn actions(&self) -> &[Action] {
        &self.chunk.actions
    }
    /// Reject foreign, duplicate, missing, reordered or discontinuous chunks.
    /// A complete stream must additionally start at number 1/range 0/Initial.
    pub fn follows(&self, previous: &Self) -> bool {
        self.stream == previous.stream
            && previous.number().checked_add(1) == Some(self.number())
            && previous.chunk.range.end == self.chunk.range.start
            && previous.after() == self.before()
    }
    /// Replay the binding at an absolute prefix in this retained chunk. The
    /// prefix is the count of committed actions, not a local action index.
    /// Consumers join this generation with the row/report owner themselves.
    pub fn binding_at(&self, prefix: u64) -> Option<HistoryBinding> {
        replay(&self.chunk, prefix)
    }
}
fn replay(chunk: &HistoryChunk, prefix: u64) -> Option<HistoryBinding> {
    if prefix < chunk.range.start
        || prefix > chunk.range.end
        || chunk.range.end.checked_sub(chunk.range.start)? != chunk.actions.len() as u64
    {
        return None;
    }
    let mut binding = chunk.before;
    for (offset, action) in chunk
        .actions
        .iter()
        .take((prefix - chunk.range.start) as usize)
        .enumerate()
    {
        let action_index = chunk.range.start.checked_add(offset as u64)?;
        match action.kind {
            ActionKind::Published
                if action.current == Some(action.generation)
                    && action.function.is_none()
                    && action.group.is_none() =>
            {
                binding = HistoryBinding::Published {
                    action_index,
                    generation: action.generation,
                };
            }
            ActionKind::Removed
                if action.current.is_none()
                    && action.function.is_none()
                    && action.group.is_none() =>
            {
                binding = HistoryBinding::Removed {
                    action_index,
                    generation: action.generation,
                };
            }
            ActionKind::Published | ActionKind::Removed | ActionKind::FailedAfter => return None,
            _ => {}
        }
    }
    Some(binding)
}

/// Qualified bounded resident suffix, including its absolute carry-in. Terminal
/// status remains diagnostic and cannot authorize a subsequent history drain.
#[derive(Debug, Eq, PartialEq)]
pub struct HistoryWindow {
    stream: HistoryStream,
    view: HistoryView,
}
impl HistoryWindow {
    pub(super) fn from_checked(stream: HistoryStream, view: HistoryView) -> Self {
        Self { stream, view }
    }
    pub fn stream(&self) -> &HistoryStream {
        &self.stream
    }
    pub fn range(&self) -> Range<u64> {
        self.view.chunk.range.clone()
    }
    pub fn last_batch_number(&self) -> u64 {
        self.view.chunk.number
    }
    pub fn before(&self) -> HistoryBinding {
        self.view.chunk.before
    }
    pub fn after(&self) -> HistoryBinding {
        self.view.chunk.after
    }
    pub fn actions(&self) -> &[Action] {
        &self.view.chunk.actions
    }
    pub fn status(&self) -> ControllerStatus {
        self.view.status
    }
    pub fn current(&self) -> Option<GenerationId> {
        self.view.current
    }
    pub fn enabled(&self) -> &[bool] {
        &self.view.enabled
    }
    pub fn retained_failed_generation(&self) -> Option<GenerationId> {
        self.view.retained_failed_generation
    }
}
impl IntervalController {
    /// Copy and explicitly remove every resident action under writer→registry
    /// authority. Does not wait for callbacks or alter publication/owners. The
    /// caller must retain an unsent batch and stop on bounded sink backpressure.
    pub fn drain_history(&mut self) -> Result<Option<HistoryBatch>, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        if !matches!(self.binding.entry_mode, EntryMode::Concurrent) {
            return Err(error(Cause::Control(ControlError::HistoryMode)));
        }
        // Key clone is allocation-free and owns no epoch; all output allocation
        // occurs inside drain_history before its writer/registry transaction.
        let stream =
            stream_for(&self.binding).ok_or(error(Cause::Control(ControlError::HistoryMode)))?;
        self.binding
            .session
            .drain_history()
            .map_err(|e| error(Cause::Control(e)))
            .map(|chunk| chunk.map(|chunk| HistoryBatch { stream, chunk }))
    }
    /// Read a qualified resident window, never a complete-history suffix in disguise.
    pub fn history_window(&self) -> Result<HistoryWindow, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        if !matches!(self.binding.entry_mode, EntryMode::Concurrent) {
            return Err(error(Cause::Control(ControlError::HistoryMode)));
        }
        let stream =
            stream_for(&self.binding).ok_or(error(Cause::Control(ControlError::HistoryMode)))?;
        let view = self
            .binding
            .session
            .history_window()
            .map_err(|e| error(Cause::Control(e)))?;
        Ok(HistoryWindow { stream, view })
    }
}

// Bounds authentication only. Trusted journal writers preserve the immutable
// EntryStamp through return. Full generation-to-prefix association requires
// consumer replay against contiguous HistoryBatches, not this high-water alone.
pub(super) fn decode_absolute(bits: u64, high_water: u64) -> Option<(u64, u64, u64)> {
    let invocation = bits & 0x1fff;
    let prefix = ((bits >> 13) & 0x1ff) | ((bits >> 24) << 9);
    let reason = (bits >> 22) & 3;
    (high_water <= MAX_HISTORY_POSITION && prefix <= high_water && invocation <= 4096)
        .then_some((invocation, prefix, reason))
}
pub(super) fn packed_for(
    binding: &Binding,
    summary: IntervalEntrySummary,
) -> Result<(u64, u64, u64), BridgeError> {
    packed_for_function(&binding.session, binding.single_function()?, summary)
}

pub(super) fn packed_for_function(
    session: &Session,
    function: FunctionId,
    summary: IntervalEntrySummary,
) -> Result<(u64, u64, u64), BridgeError> {
    if session.history_mode() == HistoryMode::Legacy {
        packed(summary, function)
    } else {
        packed_absolute(summary, function, session.history_committed_end())
    }
}

pub(super) fn packed_absolute(
    summary: IntervalEntrySummary,
    function: FunctionId,
    high_water: u64,
) -> Result<(u64, u64, u64), BridgeError> {
    let (kind, generation, inv1, prefix, reason, binding) = match summary {
        IntervalEntrySummary::Admitted {
            generation,
            invocation,
            history_len,
            binding,
        } => (
            1,
            generation.get(),
            invocation.checked_add(1).ok_or(error(Cause::Capacity))?,
            history_len,
            0,
            binding,
        ),
        IntervalEntrySummary::Unsampled {
            reason,
            history_len,
            binding,
        } => {
            let (generation, code) = match reason {
                UnsampledSummary::InitialDisarmed => (0, 1),
                UnsampledSummary::Removed { generation } => (generation.get(), 2),
                UnsampledSummary::FunctionClosed {
                    generation,
                    function: actual,
                } if actual == function => (generation.get(), 3),
                _ => return Err(error(Cause::Invariant)),
            };
            (3, generation, 0, history_len, code, binding)
        }
    };
    if prefix as u64 > MAX_HISTORY_POSITION
        || prefix as u64 > high_water
        || high_water > MAX_HISTORY_POSITION
        || inv1 > 4096
        || (kind == 1 && inv1 == 0)
    {
        return Err(error(Cause::Capacity));
    }
    let binding_matches = match binding {
        BindingChange::Initial => generation == 0 && reason == 1,
        BindingChange::Published {
            action_index,
            generation: owner,
        } => action_index < prefix && owner.get() == generation && (reason == 0 || reason == 3),
        BindingChange::Removed {
            action_index,
            generation: owner,
        } => action_index < prefix && owner.get() == generation && reason == 2,
    };
    if !binding_matches {
        return Err(error(Cause::Invariant));
    }
    let prefix = prefix as u64;
    let value = (inv1 as u64) | ((prefix & 0x1ff) << 13) | (reason << 22) | ((prefix >> 9) << 24);
    Ok((kind, generation, value))
}

pub(super) fn pair_matches_absolute(
    row: &RawInterval,
    entry: &[u64],
    exit: &[u64],
    state: &State,
    gate: &CallGate,
) -> bool {
    let bits = entry[6];
    let Some((invocation, prefix, reason)) =
        decode_absolute(bits, state.binding.session.history_committed_end())
    else {
        return false;
    };
    let (kind, generation, owner_matches) = match row.owner {
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
    owner_matches
        && invocation <= 4096
        && bits == (invocation | ((prefix & 0x1ff) << 13) | (reason << 22) | ((prefix >> 9) << 24))
        && row.entry_pc == gate.target()
        && gate.declared_returns().contains(&row.return_pc)
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
        && entry[3] >= state.stack.start
        && entry[3] & 15 == 8
        && entry[3]
            .checked_add(8)
            .is_some_and(|end| end <= state.stack.end)
}

#[cfg(test)]
mod tests;
