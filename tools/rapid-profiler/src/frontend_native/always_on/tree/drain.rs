use super::*;
use crate::frontend::{Action, ActionKind};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Cursor {
    pub number: u64,
    pub totals: TreeTotals,
    pub sequence: u64,
    pub external: u64,
}
/// Immutable full tree buffer. This key owns no Session/epoch/code permit.
#[derive(Debug)]
pub struct TreeBatch {
    key: Arc<()>,
    pid: u32,
    tid: u64,
    install: u64,
    registration: u64,
    functions: [FunctionId; 2],
    before: Cursor,
    after: Cursor,
    gate_base: u64,
    gate_sequence: u64,
    rows: Vec<TreeRecord>,
    journal: Vec<u64>,
}
impl TreeBatch {
    pub fn same_stream(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.key, &other.key)
            && self.pid == other.pid
            && self.tid == other.tid
            && self.install == other.install
            && self.registration == other.registration
            && self.functions == other.functions
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn tid(&self) -> u64 {
        self.tid
    }
    pub fn install(&self) -> u64 {
        self.install
    }
    pub fn registration(&self) -> u64 {
        self.registration
    }
    pub fn functions(&self) -> [FunctionId; 2] {
        self.functions
    }
    pub fn number(&self) -> u64 {
        self.after.number
    }
    pub fn totals(&self) -> (TreeTotals, TreeTotals) {
        (self.before.totals, self.after.totals)
    }
    pub fn completed_sequences(&self) -> (u64, u64) {
        (self.before.sequence, self.after.sequence)
    }
    pub fn gate_base(&self) -> u64 {
        self.gate_base
    }
    pub fn gate_sequence(&self) -> u64 {
        self.gate_sequence
    }
    pub fn rows(&self) -> &[TreeRecord] {
        &self.rows
    }
    pub fn journal(&self) -> &[u64] {
        &self.journal
    }
}
fn balanced(t: TreeTotals) -> bool {
    t.roots.checked_mul(2) == Some(t.pairs.entries)
        && t.pairs.entries == t.pairs.returns
        && t.pairs.completed.checked_add(t.pairs.unsampled) == Some(t.pairs.returns)
}
fn binding_at(actions: &[Action], prefix: usize) -> Option<BindingChange> {
    let mut binding = BindingChange::Initial;
    for (index, action) in actions.get(..prefix)?.iter().enumerate() {
        match action.kind {
            ActionKind::Published
                if action.function.is_none()
                    && action.group.is_none()
                    && action.current == Some(action.generation) =>
            {
                binding = BindingChange::Published {
                    action_index: index,
                    generation: action.generation,
                };
            }
            ActionKind::Removed
                if action.function.is_none()
                    && action.group.is_none()
                    && action.current.is_none() =>
            {
                binding = BindingChange::Removed {
                    action_index: index,
                    generation: action.generation,
                };
            }
            ActionKind::Published | ActionKind::Removed | ActionKind::FailedAfter => return None,
            _ => {}
        }
    }
    Some(binding)
}
fn row_matches(
    row: &TreeRecord,
    entry: &[u64],
    exit: &[u64],
    state: &runtime::State,
    actions: &[Action],
) -> bool {
    let node = usize::from(row.node);
    if node > 1 {
        return false;
    }
    let (kind, generation, bits) = match packed(row.summary, row.function) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let binding = match row.summary {
        IntervalEntrySummary::Admitted { binding, .. }
        | IntervalEntrySummary::Unsampled { binding, .. } => binding,
    };
    let site = &state.binding.site;
    let (pc, ret, continuation) = if node == 0 {
        (site.root, site.root + 22, site.gate.continuation())
    } else {
        (site.child, site.child + 38, site.root + 14)
    };
    row.function == state.binding.functions[node]
        && row.registration == state.registration
        && row.raw.owner == timing::owner(row.summary)
        && row.raw.entry_pc == pc
        && row.raw.return_pc == ret
        && row.word == continuation
        && row.resume_pc == continuation
        && row.entry_rsp & 15 == 8
        && row.entry_rsp >= state.stack.start
        && row
            .entry_rsp
            .checked_add(8)
            .is_some_and(|n| n <= state.stack.end)
        && row.entry_rsp.checked_add(8) == Some(row.resume_rsp)
        && row.callsite == (node == 1).then_some(site.root + 9)
        && row.history_prefix() <= state.binding.limits.actions
        && binding_at(actions, row.history_prefix()) == Some(binding)
        && entry
            == [
                kind,
                row.raw.ordinal,
                pc,
                row.entry_rsp,
                row.word,
                generation,
                bits,
            ]
        && exit
            == [
                kind + 1,
                row.raw.ordinal,
                ret,
                row.entry_rsp,
                row.word,
                generation,
                bits,
            ]
        && row.start_sequence.is_some() == (kind == 1)
        && row.children.is_some() == (kind == 1)
}

pub(super) fn validate(
    state: &runtime::State,
    before: Cursor,
    rows: &[TreeRecord],
    journal: &[u64],
    gate_sequence: u64,
    actions: &[Action],
) -> Result<Cursor, BridgeError> {
    state.empty()?;
    let total = state.totals;
    let sequence = state.model.completed_sequence();
    let count = total
        .roots
        .checked_sub(before.totals.roots)
        .ok_or(error(Cause::Invariant))?;
    if !balanced(before.totals)
        || !balanced(total)
        || before.sequence != before.totals.pairs.completed
        || sequence != total.pairs.completed
        || total.pairs.entries.checked_add(1) != Some(state.next)
        || state.model.identity() != state.registration
        || count > 16
        || rows.len() as u64 != count * 2
        || journal.len() != 512
        || state.len != rows.len()
        || journal[..4] != [count * 4, 0, state.tid, 0]
        || journal[4 + rows.len() * 14..].iter().any(|&w| w != 0)
        || state.gate_base.checked_add(total.roots) != Some(gate_sequence)
    {
        return Err(error(Cause::Invariant));
    }
    let mut completed = before.sequence;
    let mut sampled = 0u64;
    let mut previous_external = before.external;
    for (index, pair) in rows.chunks_exact(2).enumerate() {
        let (root, child) = (&pair[0], &pair[1]);
        let first = before
            .totals
            .pairs
            .returns
            .checked_add(index as u64 * 2)
            .and_then(|x| x.checked_add(1))
            .ok_or(error(Cause::Capacity))?;
        let gate = state
            .gate_base
            .checked_add(before.totals.roots)
            .and_then(|x| x.checked_add(index as u64 + 1))
            .ok_or(error(Cause::Capacity))?;
        let at = 4 + index * 28;
        if root.node != 0
            || child.node != 1
            || root.external_id == 0
            || root.external_id <= previous_external
            || root.external_id != child.external_id
            || root.raw.ordinal != first
            || child.raw.ordinal != first + 1
            || root.gate_sequence != gate
            || child.gate_sequence != gate
            || root.entry_rsp.checked_sub(16) != Some(child.entry_rsp)
            || root.value != child.value.wrapping_add(1)
            || !row_matches(
                root,
                &journal[at..at + 7],
                &journal[at + 21..at + 28],
                state,
                actions,
            )
            || !row_matches(
                child,
                &journal[at + 7..at + 14],
                &journal[at + 14..at + 21],
                state,
                actions,
            )
        {
            return Err(error(Cause::Invariant));
        }
        let root_sampled = matches!(root.raw.owner, RawIntervalOwner::Sampled { .. });
        let child_sampled = matches!(child.raw.owner, RawIntervalOwner::Sampled { .. });
        if root.start_sequence != root_sampled.then_some(completed)
            || child.start_sequence != child_sampled.then_some(completed)
            || child.children != child_sampled.then_some(0)
            || root.children != root_sampled.then_some(u64::from(child_sampled))
        {
            return Err(error(Cause::Invariant));
        }
        let n = u64::from(root_sampled) + u64::from(child_sampled);
        completed = completed.checked_add(n).ok_or(error(Cause::Capacity))?;
        sampled += n;
        previous_external = root.external_id;
    }
    if completed != sequence
        || before.totals.pairs.completed.checked_add(sampled) != Some(total.pairs.completed)
        || before
            .totals
            .pairs
            .unsampled
            .checked_add(count * 2 - sampled)
            != Some(total.pairs.unsampled)
    {
        return Err(error(Cause::Invariant));
    }
    Ok(Cursor {
        number: if count == 0 {
            before.number
        } else {
            before.number.checked_add(1).ok_or(error(Cause::Capacity))?
        },
        totals: total,
        sequence,
        external: previous_external,
    })
}

impl TreeThread {
    /// Transfer both complete buffers only after a successful actual tree return.
    /// Allocation/validation failure preserves both live buffers; IDs never reset.
    pub fn drain_completed(&mut self) -> Result<Option<TreeBatch>, BridgeError> {
        self.batch.closed().map_err(|_| error(Cause::Outstanding))?;
        let _scope = ControllerScope::enter()?;
        let mut rows = Vec::new();
        let mut journal = Vec::new();
        rows.try_reserve_exact(EVENTS / 2)
            .map_err(|_| error(Cause::Capacity))?;
        journal
            .try_reserve_exact(512)
            .map_err(|_| error(Cause::Capacity))?;
        let snapshot = self
            .binding
            .session
            .snapshot_for_bridge()
            .map_err(|e| error(Cause::Control(e)))?;
        TREE_STATE
            .try_with(|cell| {
                let mut storage = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                let state = storage.as_mut().ok_or(error(Cause::Attachment))?;
                if !self.matches(state) || self.finished != Some(state.totals) {
                    return Err(error(Cause::Outstanding));
                }
                state.empty()?;
                let gate_sequence = state
                    .binding
                    .site
                    .gate
                    .idle_checkpoint()
                    .map_err(|e| error(Cause::Gate(e)))?;
                if state.len > state.rows.len()
                    || state.rows[..state.len].iter().any(Option::is_none)
                    || state.rows[state.len..].iter().any(Option::is_some)
                {
                    return Err(error(Cause::Invariant));
                }
                transfer(
                    state,
                    &mut self.cursor,
                    gate_sequence,
                    &snapshot.actions,
                    rows,
                    journal,
                )
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}

// The caller proves actual-thread attachment, successful invoke and canonical
// gate IDLE before this buffer transaction. Tests exercise this transaction with
// real model receipts only; that is not evidence of a physical CALL/RET.
fn transfer(
    state: &mut runtime::State,
    cursor: &mut Cursor,
    gate_sequence: u64,
    actions: &[Action],
    mut rows: Vec<TreeRecord>,
    mut journal: Vec<u64>,
) -> Result<Option<TreeBatch>, BridgeError> {
    if rows.capacity() < EVENTS / 2
        || journal.capacity() < 512
        || !rows.is_empty()
        || !journal.is_empty()
        || state.len > state.rows.len()
        || state.rows[..state.len].iter().any(Option::is_none)
        || state.rows[state.len..].iter().any(Option::is_some)
    {
        return Err(error(Cause::Capacity));
    }
    rows.extend(state.rows[..state.len].iter().flatten().copied());
    journal.extend(
        state
            .journal
            .page
            .0
            .iter()
            .map(|w| unsafe { std::ptr::read_volatile(w) }),
    );
    let after = validate(state, *cursor, &rows, &journal, gate_sequence, actions)?;
    if rows.is_empty() {
        return Ok(None);
    }
    let batch = TreeBatch {
        key: Arc::clone(&state.binding.key),
        pid: state.binding.pid,
        tid: state.tid,
        install: state.binding.install,
        registration: state.registration,
        functions: state.binding.functions,
        before: *cursor,
        after,
        gate_base: state.gate_base,
        gate_sequence,
        rows,
        journal,
    };
    // Infallible reset of copy-only buffers; no model/owner destruction.
    state.rows = [None; EVENTS / 2];
    state.len = 0;
    for index in 0..512 {
        state.journal.word(index, 0);
    }
    state.journal.header(state.tid, 0);
    *cursor = after;
    Ok(Some(batch))
}
#[cfg(test)]
pub(super) fn metadata_transfer(
    state: &mut runtime::State,
    cursor: &mut Cursor,
) -> Result<Option<TreeBatch>, BridgeError> {
    let actions = state
        .binding
        .session
        .snapshot()
        .map_err(|e| error(Cause::Control(e)))?
        .actions;
    let sequence = state.gate_base + state.totals.roots;
    transfer(
        state,
        cursor,
        sequence,
        &actions,
        Vec::with_capacity(EVENTS / 2),
        Vec::with_capacity(512),
    )
}
#[cfg(test)]
pub(super) fn metadata_unreserved(
    state: &mut runtime::State,
    cursor: &mut Cursor,
) -> Result<Option<TreeBatch>, BridgeError> {
    let sequence = state.gate_base + state.totals.roots;
    transfer(state, cursor, sequence, &[], Vec::new(), Vec::new())
}
