//! Distinct normal parent/original-CALL/child profile. No gate or old-profile conversion.
use super::*;
use crate::frontend::{Payload, PayloadOutcome};
use crate::generation::{Admission, Completion, Disposition, Terminal};
use liteinst2::contracts::CodeIdentity;
use liteinst2::controls::ManagedCallback;
use liteinst2::trampoline::{ObservationStackProfile, SavedExtendedStateLayout};
use site::ordinary::call_pair::{CallPairSite, NormalCallPairRoleKind as Role};
pub(super) mod runtime;
mod session;
mod stream;
#[cfg(test)]
mod tests;
pub use session::{NormalCallPairSessionController, PreparedNormalCallPairSessionController};
pub use stream::{
    NormalCallPairHistoryBatch, NormalCallPairHistoryStream, NormalCallPairHistoryWindow,
};
pub(in crate::frontend_native::always_on) fn binding_matches(binding: &Binding) -> bool {
    session::binding_matches(binding)
}
pub(in crate::frontend_native::always_on) fn profile_matches(
    profile: &BindingProfile,
    limits: Limits,
    config: Config,
) -> bool {
    session::profile_matches(profile, limits, config)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NormalCallPairTotals {
    pub roots: u64,
    pub child_acks: u64,
    pub pairs: NormalTotals,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalCallPairAcknowledgement {
    ChildContinuation,
    CallerCheckpoint,
}
/// Immutable value copy; neither the receipt nor its epoch owner escapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalCallPairRecord {
    function: FunctionId,
    node: usize,
    parent_ordinal: u64,
    raw: RawInterval,
    entry_rsp: u64,
    return_word: u64,
    resume_pc: u64,
    resume_rsp: u64,
    value: u64,
    ack: NormalCallPairAcknowledgement,
    summary: IntervalEntrySummary,
    sequence_before: u64,
    sampled_children: Option<u64>,
    completion: Option<Completion>,
    payload: Option<Payload>,
    k: usize,
}
impl NormalCallPairRecord {
    pub fn function(&self) -> FunctionId {
        self.function
    }
    pub fn node(&self) -> usize {
        self.node
    }
    pub fn parent_ordinal(&self) -> u64 {
        self.parent_ordinal
    }
    pub fn raw(&self) -> RawInterval {
        self.raw
    }
    pub fn entry_rsp(&self) -> u64 {
        self.entry_rsp
    }
    pub fn return_word(&self) -> u64 {
        self.return_word
    }
    pub fn resume_pc(&self) -> u64 {
        self.resume_pc
    }
    pub fn resume_rsp(&self) -> u64 {
        self.resume_rsp
    }
    pub fn value(&self) -> u64 {
        self.value
    }
    pub fn acknowledgement(&self) -> NormalCallPairAcknowledgement {
        self.ack
    }
    pub fn history_prefix(&self) -> u64 {
        prefix(self.summary)
    }
    pub fn sequence_before(&self) -> u64 {
        self.sequence_before
    }
    pub fn actual_children(&self) -> u64 {
        u64::from(self.node == 0)
    }
    pub fn sampled_children(&self) -> Option<u64> {
        self.sampled_children
    }
    pub fn completion(&self) -> Option<Completion> {
        self.completion
    }
    pub fn payload(&self) -> Option<Payload> {
        self.payload
    }
    /// Join this record to an already-final Report. The consumer must retain and
    /// join every record/Report/history, including empty generations, before
    /// release. This operation neither waits nor establishes exclusive ownership,
    /// native return, complete campaign coverage or executable quiescence.
    pub fn matches_report(&self, report: &Report) -> Result<bool, BridgeError> {
        let generation = match self.raw.owner {
            RawIntervalOwner::Sampled { generation, .. }
            | RawIntervalOwner::FunctionClosed { generation }
            | RawIntervalOwner::Removed { generation } => generation,
            RawIntervalOwner::InitialDisarmed => return Ok(false),
        };
        if report.generation().get() != generation {
            return Ok(false);
        }
        if let Some(completion) = self.completion {
            let row = report
                .records()
                .nth(completion.admission.invocation)
                .ok_or(error(Cause::Invariant))?;
            // The core terminal joins its global invocation slot. The separate
            // interval payload carries the sampled child count.
            if row.record.admission != completion.admission
                || !matches!(self.payload, Some(Payload {
                    outcome: PayloadOutcome::Completed { completed_children, .. }, ..
                }) if Some(completed_children) == self.sampled_children)
                || row.record.terminal
                    != Some(Terminal::Completed {
                        value: completion.admission.invocation as u64,
                        disposition: completion.disposition,
                    })
                || row.payload != self.payload
            {
                return Err(error(Cause::Invariant));
            }
        } else if matches!(self.raw.owner, RawIntervalOwner::FunctionClosed { .. }) {
            let mut count = 0usize;
            for row in report
                .records()
                .filter(|r| r.record.admission.function == self.function)
            {
                let payload = row.payload.ok_or(error(Cause::Invariant))?;
                if row.record.admission.generation.get() != generation
                    || payload.admission != row.record.admission
                    || !matches!(row.record.terminal, Some(Terminal::Completed { value, disposition: Disposition::Retained { rank } }) if rank == count && value == row.record.admission.invocation as u64)
                    || !matches!(payload.outcome, PayloadOutcome::Completed { .. })
                {
                    return Err(error(Cause::Invariant));
                }
                count = count.checked_add(1).ok_or(error(Cause::Capacity))?;
            }
            if count != self.k {
                return Err(error(Cause::Invariant));
            }
        }
        Ok(true)
    }
}
fn prefix(summary: IntervalEntrySummary) -> u64 {
    match summary {
        IntervalEntrySummary::Admitted { history_len, .. }
        | IntervalEntrySummary::Unsampled { history_len, .. } => history_len as u64,
    }
}
/// Exactly one returned root, two entry-order rows, and all 512 journal words.
#[derive(Debug)]
pub struct NormalCallPairBatch {
    pid: u32,
    tid: u64,
    registration: u64,
    install: u64,
    stream: NormalCallPairHistoryStream,
    number: u64,
    before: NormalCallPairTotals,
    after: NormalCallPairTotals,
    history_end: u64,
    records: [NormalCallPairRecord; 2],
    journal: [u64; 512],
}
impl NormalCallPairBatch {
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn tid(&self) -> u64 {
        self.tid
    }
    pub fn registration(&self) -> u64 {
        self.registration
    }
    pub fn install(&self) -> u64 {
        self.install
    }
    pub fn stream(&self) -> &NormalCallPairHistoryStream {
        &self.stream
    }
    pub fn number(&self) -> u64 {
        self.number
    }
    pub fn before(&self) -> NormalCallPairTotals {
        self.before
    }
    pub fn after(&self) -> NormalCallPairTotals {
        self.after
    }
    pub fn history_end(&self) -> u64 {
        self.history_end
    }
    pub fn records(&self) -> &[NormalCallPairRecord; 2] {
        &self.records
    }
    pub fn journal(&self) -> &[u64; 512] {
        &self.journal
    }
}
#[derive(Clone)]
pub struct NormalCallPairClient {
    binding: Arc<Binding>,
}
pub struct NormalCallPairThread {
    inner: NormalThread,
}
impl NormalCallPairClient {
    /// # Safety
    /// The actual attached thread is the only subject caller. Source, generated
    /// images, original E8, controls and all owners remain immutable/process-lived.
    /// Every root executes exactly its admitted child CALL, matching child RET and
    /// continuation, and root RET; no signal, recursion, cancellation, CET, unwind,
    /// nonlocal entry, alias writer, unload or fork. Input/source/caller postflight
    /// is external and precedes every checkpoint. Exactly one root per checkpoint.
    ///
    /// `stack` must additionally be continuously WRITABLE over the actual complete
    /// CallPair240 context/extended-state allocation AND the entire actual callback
    /// call stack below it, throughout all callbacks. Its readable constructor is
    /// not a writability proof. The caller establishes sufficient real callback
    /// headroom; no constant here guesses its compiled stack use. Per-thread
    /// XSAVE state must equal the emitted layout throughout attachment. Numeric
    /// descriptor checks are additional checks, not a substitute for this proof.
    pub unsafe fn attach(
        &self,
        registration: u64,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<NormalCallPairThread, BridgeError> {
        let _scope = ControllerScope::enter()?;
        self.binding.process()?;
        let (site, _) = table(&self.binding)?;
        if !binding_matches(&self.binding)
            || registration == 0
            || journal.page.0.iter().any(|&word| word != 0)
            || !timing::supported()
            || site.stack_profile() != ObservationStackProfile::CallPair240
            || SavedExtendedStateLayout::detect().ok() != Some(site.layout())
        {
            return Err(error(Cause::Attachment));
        }
        let pair = Box::new(runtime::State::new());
        let inner = attach_profile(&self.binding, registration, stack, journal, Some(pair))?;
        Ok(NormalCallPairThread { inner })
    }
}
fn table(binding: &Binding) -> Result<(&CallPairSite, &[FunctionId; 2]), BridgeError> {
    if !binding_matches(binding) {
        return Err(error(Cause::Identity));
    }
    match &binding.profile {
        BindingProfile::CallPair { site, functions } => Ok((site, functions)),
        _ => Err(error(Cause::Identity)),
    }
}
impl NormalCallPairThread {
    fn matches(&self, state: &NormalState) -> bool {
        self.inner.matches_identity(state)
            && binding_matches(&state.binding)
            && state.call_pair.is_some()
    }
    pub fn totals(&self) -> Result<NormalCallPairTotals, BridgeError> {
        NORMAL
            .try_with(|cell| {
                let storage = cell.try_borrow().map_err(|_| error(Cause::Attachment))?;
                let state = storage.0.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.matches(state) {
                    return Err(error(Cause::Attachment));
                }
                state.health()?;
                state
                    .call_pair
                    .as_ref()
                    .ok_or(error(Cause::Attachment))?
                    .validate(runtime::View::of(state))?;
                Ok(state
                    .call_pair
                    .as_ref()
                    .ok_or(error(Cause::Attachment))?
                    .totals)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
    /// # Safety
    /// Same actual thread; the entire root actually returned normally to its
    /// caller, no callback/subject is active, and complete input/source/image and
    /// caller postflight succeeded first. A pre-RET, Report or counter cannot
    /// supply this attestation. Never reread the now-dead outer return slot.
    pub unsafe fn checkpoint_after_returns(
        &mut self,
    ) -> Result<Option<NormalCallPairBatch>, BridgeError> {
        let _scope = ControllerScope::enter()?;
        NORMAL
            .try_with(|cell| {
                let mut storage = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                let state = storage.0.as_mut().ok_or(error(Cause::Attachment))?;
                if !self.matches(state) {
                    return Err(error(Cause::Attachment));
                }
                runtime::transfer_checked(state)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
    /// Empty-only detach; no pending receipt, unexported row or event is dropped.
    pub fn detach(&mut self) -> Result<NormalCallPairTotals, BridgeError> {
        let _scope = ControllerScope::enter()?;
        NORMAL
            .try_with(|cell| {
                let mut storage = cell
                    .try_borrow_mut()
                    .map_err(|_| error(Cause::Attachment))?;
                let state = storage.0.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.matches(state) {
                    return Err(error(Cause::Attachment));
                }
                state.health()?;
                let pair = state.call_pair.as_ref().ok_or(error(Cause::Attachment))?;
                pair.validate(runtime::View::of(state))?;
                if !pair.empty() {
                    return Err(error(Cause::Outstanding));
                }
                let totals = pair.totals;
                drop(storage.0.take());
                self.inner.active = false;
                Ok(totals)
            })
            .unwrap_or(Err(error(Cause::Attachment)))
    }
}
// Actual dispatch uses only the one shared NORMAL slot. Any logical failure
// poisons it and retains the entire state/receipts; later checkpoint cannot retry.
fn dispatch(
    c: &HookContext,
    control: ControlIdentity<'_>,
    role: Role,
    stamp: Option<RawTimestamp>,
) {
    if CONTROLLER_ACTIVE.get() || NORMAL_POISON.get() {
        fatal()
    }
    let result = NORMAL
        .try_with(|cell| {
            let mut storage = cell
                .try_borrow_mut()
                .map_err(|_| error(Cause::Attachment))?;
            let state = storage.0.as_mut().ok_or(error(Cause::Attachment))?;
            state.health()?;
            state.busy = true;
            match runtime::callback(state, c, control, role, stamp) {
                Ok(()) => {
                    state.busy = false;
                    Ok(())
                }
                Err(e) => Err(state.fail(e)),
            }
        })
        .unwrap_or(Err(error(Cause::Attachment)));
    if result.is_err() {
        fatal()
    }
}
macro_rules! role_callback {
    ($name:ident, $role:ident, $clock:expr) => {
        unsafe extern "C" fn $name<'a>(context: *mut HookContext, control: ControlIdentity<'a>) {
            // SAFETY: publication required RDTSCP and actual generated context.
            let stamp = if $clock {
                Some(unsafe { timing::read() })
            } else {
                None
            };
            let Some(c) = (unsafe { context.as_ref() }) else {
                fatal()
            };
            dispatch(c, control, Role::$role, stamp);
        }
    };
}
role_callback!(parent_entry, ParentEntry, true);
role_callback!(child_entry, ChildEntry, true);
role_callback!(child_ret, ChildRet, true);
role_callback!(child_ack, ChildAck, false);
role_callback!(parent_ret, ParentRet, true);
pub(in crate::frontend_native::always_on) fn callback_for(role: Role) -> ManagedCallback {
    match role {
        Role::ParentEntry => parent_entry,
        Role::ChildEntry => child_entry,
        Role::ChildRet => child_ret,
        Role::ChildAck => child_ack,
        Role::ParentRet => parent_ret,
    }
}
