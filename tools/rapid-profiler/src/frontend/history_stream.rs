//! Opt-in absolute history. Legacy construction and complete snapshots stay separate.
use super::*;
use std::ops::Range;

pub(crate) const MAX_HISTORY_POSITION: u64 = (1u64 << 49) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HistoryMode {
    Legacy,
    Absolute,
}

/// Last binding change before an absolute history boundary. This is data only;
/// it neither owns an epoch nor authorizes invocation or native return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryBinding {
    Initial,
    Published {
        action_index: u64,
        generation: GenerationId,
    },
    Removed {
        action_index: u64,
        generation: GenerationId,
    },
}
impl From<BindingChange> for HistoryBinding {
    fn from(value: BindingChange) -> Self {
        match value {
            BindingChange::Initial => Self::Initial,
            BindingChange::Published {
                action_index,
                generation,
            } => Self::Published {
                action_index: action_index as u64,
                generation,
            },
            BindingChange::Removed {
                action_index,
                generation,
            } => Self::Removed {
                action_index: action_index as u64,
                generation,
            },
        }
    }
}

pub(crate) struct HistoryState {
    pub(super) base: u64,
    pub(super) carry: BindingChange,
    pub(super) number: u64,
}
impl HistoryState {
    pub(super) fn new() -> Self {
        Self {
            base: 0,
            carry: BindingChange::Initial,
            number: 0,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HistoryChunk {
    pub range: Range<u64>,
    pub number: u64,
    pub before: HistoryBinding,
    pub after: HistoryBinding,
    pub actions: Vec<Action>,
}
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HistoryView {
    pub chunk: HistoryChunk,
    pub status: ControllerStatus,
    pub current: Option<GenerationId>,
    pub enabled: Vec<bool>,
    pub retained_failed_generation: Option<GenerationId>,
}

fn end(w: &Controller) -> Result<u64, ControlError> {
    w.history
        .base
        .checked_add(w.actions.len() as u64)
        .filter(|&n| n <= MAX_HISTORY_POSITION)
        .ok_or(ControlError::HistoryExhausted)
}
fn boundary(w: &Controller) -> Result<BindingChange, ControlError> {
    let mut binding = w.history.carry;
    match binding {
        BindingChange::Initial => {}
        BindingChange::Published { action_index, .. }
        | BindingChange::Removed { action_index, .. }
            if (action_index as u64) < w.history.base => {}
        _ => return Err(ControlError::HistoryInvariant),
    }
    for (offset, action) in w.actions.iter().enumerate().rev() {
        if matches!(action.kind, ActionKind::Published | ActionKind::Removed) {
            if action.function.is_some() || action.group.is_some() {
                return Err(ControlError::HistoryInvariant);
            }
            let action_index = usize::try_from(
                w.history
                    .base
                    .checked_add(offset as u64)
                    .ok_or(ControlError::HistoryExhausted)?,
            )
            .map_err(|_| ControlError::HistoryExhausted)?;
            binding = if action.kind == ActionKind::Published {
                if action.current != Some(action.generation) {
                    return Err(ControlError::HistoryInvariant);
                }
                BindingChange::Published {
                    action_index,
                    generation: action.generation,
                }
            } else {
                if action.current.is_some() {
                    return Err(ControlError::HistoryInvariant);
                }
                BindingChange::Removed {
                    action_index,
                    generation: action.generation,
                }
            };
            break;
        }
    }
    Ok(binding)
}

pub(super) fn validate(
    session: &SessionInner,
    w: &Controller,
    r: &Registry,
    ready: bool,
) -> Result<(u64, BindingChange), ControlError> {
    if session.history_mode != HistoryMode::Absolute {
        return Err(ControlError::HistoryMode);
    }
    if ready && w.status != ControllerStatus::Ready {
        return Err(ControlError::TerminalFailure);
    }
    let end = end(w)?;
    if w.actions.len() > session.spec.limits.actions
        || w.actions.len() > MAX_ACTIONS
        || end != session.committed_end.load(Ordering::Acquire)
        || r.current.as_ref().map(|owner| owner.epoch.id()) != w.current
        || r.current
            .as_ref()
            .is_some_and(|owner| !Arc::ptr_eq(&owner.spec, &session.spec))
    {
        return Err(ControlError::HistoryInvariant);
    }
    let binding = boundary(w)?;
    // A terminal FailedAfter diagnostic may intentionally disagree with the last
    // committed Published/Removed row. It cannot authorize entry or a drain.
    if w.status == ControllerStatus::Ready {
        match (w.current, binding) {
            (Some(current), BindingChange::Published { generation, .. })
                if current == generation => {}
            (None, BindingChange::Initial | BindingChange::Removed { .. }) => {}
            _ => return Err(ControlError::HistoryInvariant),
        }
    }
    Ok((end, binding))
}

#[cfg(test)]
thread_local! { static FAIL_RESERVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
fn output<T>(capacity: usize) -> Result<Vec<T>, ControlError> {
    #[cfg(test)]
    if FAIL_RESERVE.get() {
        return Err(ControlError::HistoryAllocation);
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(capacity)
        .map_err(|_| ControlError::HistoryAllocation)?;
    Ok(rows)
}

impl Session {
    // Controls of both facades exercise the real shared output reservation.
    #[cfg(test)]
    pub(crate) fn test_history_reserve_failure(&self, fail: bool) {
        FAIL_RESERVE.set(fail);
    }

    // Only the sealed concurrent facade exposes this construction publicly.
    pub(crate) fn new_streaming_history(
        install: u64,
        functions: &[FunctionSpec],
        groups: &[GroupSpec],
        limits: Limits,
    ) -> Result<Self, SetupError> {
        if usize::try_from(MAX_HISTORY_POSITION).is_err() {
            return Err(SetupError::InvalidLimits);
        }
        let mut session = Self::new(install, functions, groups, limits)?;
        // No thread, epoch, client or publication can exist before return.
        Arc::get_mut(&mut session.inner)
            .expect("new session has one owner")
            .history_mode = HistoryMode::Absolute;
        Ok(session)
    }
    pub(crate) fn history_mode(&self) -> HistoryMode {
        self.inner.history_mode
    }
    pub(crate) fn history_committed_end(&self) -> u64 {
        self.inner.committed_end.load(Ordering::Acquire)
    }
    // Caller enters ControllerScope before this allocation. No external sink or
    // callback is invoked, and no epoch owner is copied or dropped by the commit.
    pub(crate) fn drain_history(&self) -> Result<Option<HistoryChunk>, ControlError> {
        if self.history_mode() != HistoryMode::Absolute {
            return Err(ControlError::HistoryMode);
        }
        let mut actions = output(self.inner.spec.limits.actions)?;
        let mut w = self
            .inner
            .writer
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        let r = self
            .inner
            .registry
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        let (end, after) = validate(&self.inner, &w, &r, true)?;
        if w.actions.is_empty() {
            return Ok(None);
        }
        let number = w
            .history
            .number
            .checked_add(1)
            .ok_or(ControlError::HistoryExhausted)?;
        actions.extend_from_slice(&w.actions);
        let chunk = HistoryChunk {
            range: w.history.base..end,
            number,
            before: w.history.carry.into(),
            after: after.into(),
            actions,
        };
        // Infallible commit; Action is Copy and holds no owner. Keep Vec capacity.
        w.actions.clear();
        w.history.base = end;
        w.history.carry = after;
        w.history.number = number;
        Ok(Some(chunk))
    }
    pub(crate) fn history_window(&self) -> Result<HistoryView, ControlError> {
        if self.history_mode() != HistoryMode::Absolute {
            return Err(ControlError::HistoryMode);
        }
        let mut actions = output(self.inner.spec.limits.actions)?;
        let mut enabled = output(self.inner.spec.groups.len())?;
        let w = self
            .inner
            .writer
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        let r = self
            .inner
            .registry
            .lock()
            .map_err(|_| ControlError::Poisoned)?;
        let (end, after) = validate(&self.inner, &w, &r, false)?;
        actions.extend_from_slice(&w.actions);
        enabled.extend_from_slice(&w.enabled);
        Ok(HistoryView {
            chunk: HistoryChunk {
                range: w.history.base..end,
                number: w.history.number,
                before: w.history.carry.into(),
                after: after.into(),
                actions,
            },
            status: w.status,
            current: w.current,
            enabled,
            retained_failed_generation: w.failed_owner.as_ref().map(|owner| owner.epoch.id()),
        })
    }
}
impl SessionInner {
    pub(super) fn preflight_absolute(
        &self,
        w: &Controller,
        count: usize,
    ) -> Result<(), ControlError> {
        if self.history_mode == HistoryMode::Absolute {
            let current = end(w)?;
            if current != self.committed_end.load(Ordering::Acquire) {
                return Err(ControlError::HistoryInvariant);
            }
            if current
                .checked_add(count as u64)
                .is_none_or(|n| n > MAX_HISTORY_POSITION)
            {
                return Err(ControlError::HistoryExhausted);
            }
        }
        Ok(())
    }
    // Every call is covered by preflight_writer(count), including scan's whole
    // worst-case count. Publish the actual append, never its reservation.
    pub(super) fn append_action(&self, w: &mut Controller, action: Action) {
        w.actions.push(action);
        self.committed_end
            .store(w.history.base + w.actions.len() as u64, Ordering::Release);
    }
}

#[cfg(test)]
mod tests;
