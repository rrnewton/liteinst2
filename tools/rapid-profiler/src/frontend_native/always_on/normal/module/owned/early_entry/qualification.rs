//! Explicit oracle feature, not the default client or a new public call ABI.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PauseKind {
    AfterEntryPublished,
    AfterPreRetPublished,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerSnapshot {
    pub owner: RawIntervalOwner,
    pub history_len: usize,
    pub binding: HistoryBinding,
    pub closed_function: Option<FunctionId>,
}
fn owner_snapshot(summary: IntervalEntrySummary) -> OwnerSnapshot {
    let (history_len, binding, closed_function) = match summary {
        IntervalEntrySummary::Admitted {
            history_len,
            binding,
            ..
        } => (history_len, binding, None),
        IntervalEntrySummary::Unsampled {
            history_len,
            binding,
            reason,
        } => (
            history_len,
            binding,
            if let UnsampledSummary::FunctionClosed { function, .. } = reason {
                Some(function)
            } else {
                None
            },
        ),
    };
    OwnerSnapshot {
        owner: timing::owner(summary),
        history_len,
        binding: binding.into(),
        closed_function,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingSnapshot {
    pub physical_batch: u64,
    pub physical_position: usize,
    pub function: FunctionId,
    pub ordinal: u64,
    pub entry_pc: u64,
    pub rsp: u64,
    pub word: u64,
    pub start: RawTimestamp,
    pub summary: Option<OwnerSnapshot>,
    pub actual_summary: Option<OwnerSnapshot>,
    pub returned: Option<RawInterval>,
    pub slot: ModelReturnSlot,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationSnapshot {
    pub binding_key: usize,
    pub pid: u32,
    pub tid: u64,
    pub registration: u64,
    pub completed_batches: u64,
    pub completed_calls: u64,
    pub active_batch: Option<u64>,
    pub position: Option<usize>,
    pub entry_seen: [Option<u64>; 4],
    pub pre_rets: [Option<EarlyEntryModulePhysicalRow>; 4],
    pub pending: Option<PendingSnapshot>,
    pub next_ordinal: u64,
    pub totals: NormalTotals,
    pub interval_batch: u64,
    pub interval_cursor_totals: NormalTotals,
    pub model_depth: usize,
    pub completed_sequence: u64,
    pub journal: [u64; 512],
}
/// Read only the calling worker's TLS. Another thread must receive this copied
/// witness through its own authenticated release/acquire or channel handshake.
pub fn qualification_snapshot() -> Result<QualificationSnapshot, BridgeError> {
    NORMAL
        .try_with(|normal| {
            let storage = normal.try_borrow().map_err(|_| error(Cause::Attachment))?;
            let s = storage.0.as_ref().ok_or(error(Cause::Attachment))?;
            s.health()?;
            if s.actual_thread != thread::current().id() || s.tid != tid() {
                return Err(error(Cause::Identity));
            }
            PHYSICAL
                .try_with(|physical| {
                    let p = physical
                        .try_borrow()
                        .map_err(|_| error(Cause::Attachment))?;
                    let p = p.as_ref().ok_or(error(Cause::Attachment))?;
                    p.matches(s)?;
                    if p.active.is_some() {
                        p.shape(s)?;
                    } else {
                        drained(s)?;
                    }
                    let b = p.active.as_ref();
                    let pending = match (&s.pending, b.and_then(|b| b.pending_position)) {
                        (None, None) => None,
                        (Some(v), Some(position)) => Some(PendingSnapshot {
                            physical_batch: b.unwrap().number,
                            physical_position: position,
                            function: v.selected.function,
                            ordinal: v.ordinal,
                            entry_pc: v.entry_pc,
                            rsp: v.rsp,
                            word: v.word,
                            start: v.start,
                            summary: v.summary.map(owner_snapshot),
                            actual_summary: v.receipt.summary().map(owner_snapshot),
                            returned: v.returned,
                            slot: v.slot,
                        }),
                        _ => return Err(error(Cause::Invariant)),
                    };
                    Ok(QualificationSnapshot {
                        binding_key: Arc::as_ptr(&s.binding.key) as usize,
                        pid: s.binding.pid,
                        tid: s.tid,
                        registration: s.registration,
                        completed_batches: p.batches,
                        completed_calls: p.calls,
                        active_batch: b.map(|b| b.number),
                        position: b.map(|b| b.position),
                        entry_seen: b.map_or([None; 4], |b| b.seen),
                        pre_rets: b.map_or([None; 4], |b| b.rows),
                        pending,
                        next_ordinal: s.next,
                        totals: s.totals,
                        interval_batch: s.cursor.number,
                        interval_cursor_totals: s.cursor.totals,
                        model_depth: s.model.depth(),
                        completed_sequence: s.model.completed_sequence(),
                        journal: s.journal.page.0,
                    })
                })
                .unwrap_or(Err(error(Cause::Attachment)))
        })
        .unwrap_or(Err(error(Cause::Attachment)))
}
type Observer = Box<dyn FnMut(PauseKind, QualificationSnapshot)>;
thread_local! { static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) }; }
/// # Safety
/// Qualification only: observer never enters subject/controller/model code on
/// this worker, unwinds or alters code/control/state. Any wait has the fixed
/// native-owner deadline and a separate real controller ACK; no model/TLS lock
/// is held while it runs. Its copied witness is not another thread's TLS access.
pub unsafe fn install_observer(
    observer: impl FnMut(PauseKind, QualificationSnapshot) + 'static,
) -> Result<(), BridgeError> {
    OBSERVER
        .try_with(|cell| {
            let mut slot = cell
                .try_borrow_mut()
                .map_err(|_| error(Cause::Attachment))?;
            if slot.is_some() {
                return Err(error(Cause::Attachment));
            }
            *slot = Some(Box::new(observer));
            Ok(())
        })
        .unwrap_or(Err(error(Cause::Attachment)))
}
#[inline(never)]
pub(super) fn after_published(kind: PauseKind) {
    // Both production callback borrows and the model transaction have ended.
    let outcome = OBSERVER
        .try_with(|cell| {
            let mut observer = cell
                .try_borrow_mut()
                .map_err(|_| error(Cause::Attachment))?;
            if let Some(observer) = observer.as_mut() {
                observer(kind, qualification_snapshot()?);
            }
            Ok(())
        })
        .unwrap_or(Err(error(Cause::Attachment)));
    if outcome.is_err() {
        fatal();
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QualificationRequest {
    pub data: *const u8,
    pub bound: usize,
}
/// Borrowed, non-Clone sealed caller capability; no pointer/address extraction.
pub struct QualificationInvocation<'a> {
    caller: &'a mut LoadedNormalModuleCaller,
    entries: [u64; 2],
    returned: Option<u64>,
    invoked: bool,
}
impl QualificationInvocation<'_> {
    pub fn entries(&self) -> [u64; 2] {
        self.entries
    }
    pub fn continuations(&self) -> [u64; 4] {
        self.caller.continuations()
    }
    /// # Safety
    /// Oracle owns these disjoint exact C-layout arrays and readonly input
    /// slices, and the stack/entire full-state witness, through genuine return.
    /// The complete original attachment contract holds. Guarded stack/array
    /// redirection is qualification-only and must be independently validated;
    /// it does not qualify default run_batch's private-array wrapper.
    pub unsafe fn invoke_arrays(
        &mut self,
        targets: &[u64; 2],
        requests: &[QualificationRequest; 2],
        results: &mut [u64; 4],
    ) -> Result<u64, BridgeError> {
        if self.invoked
            || *targets != self.entries
            || requests
                .iter()
                .any(|r| r.bound > 64 || (r.bound != 0 && r.data.is_null()))
        {
            return Err(error(Cause::Identity));
        }
        self.invoked = true;
        // SAFETY: exact sealed caller, checked targets/domain and oracle custody.
        let sum = unsafe {
            self.caller.invoke_qualification(
                targets.as_ptr(),
                requests.as_ptr().cast(),
                results.as_mut_ptr(),
            )
        };
        self.returned = Some(sum);
        Ok(sum)
    }
}
impl OwnedEarlyEntryModuleThread {
    /// # Safety
    /// Exactly one invocation through the supplied borrowed capability, with
    /// complete unchanged architectural/input/result/source checks before body
    /// returns its actual scalar sum and four stored results. No forged return,
    /// alternate caller, early checkpoint, reentry or replacement of the unsafe
    /// attachment contract is permitted. Any panic leaves admission poisoned.
    pub unsafe fn qualification_run_batch(
        &mut self,
        body: impl FnOnce(&mut QualificationInvocation<'_>) -> (u64, [u64; 4]),
    ) -> Result<OwnedEarlyEntryModuleResult, BridgeError> {
        self.execute_body(|caller, entries| {
            let mut call = QualificationInvocation {
                caller,
                entries,
                returned: None,
                invoked: false,
            };
            let (sum, values) = body(&mut call);
            assert!(
                call.invoked && call.returned == Some(sum),
                "qualification requires one real outer return"
            );
            (sum, values)
        })
    }
}
