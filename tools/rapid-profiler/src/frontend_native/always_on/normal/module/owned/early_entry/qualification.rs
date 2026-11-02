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
    let mut snapshot = std::mem::MaybeUninit::uninit();
    qualification_snapshot_into(&mut snapshot)?;
    // SAFETY: success initialized every field and returned after both TLS
    // borrows ended. This wrapper preserves the public owned-result API.
    Ok(unsafe { snapshot.assume_init() })
}

// Return only status across this boundary. The observer's complete witness is
// initialized directly in its own local slot, never returned as a large Result.
#[inline(never)]
fn qualification_snapshot_into(
    destination: &mut std::mem::MaybeUninit<QualificationSnapshot>,
) -> Result<(), BridgeError> {
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
                    destination.write(QualificationSnapshot {
                        binding_key: Arc::as_ptr(&s.binding.key) as usize,
                        pid: s.binding.pid,
                        tid: s.tid,
                        registration: s.registration,
                        completed_batches: p.batches,
                        completed_calls: p.calls,
                        active_batch: b.map(|b| b.number),
                        position: b.map(|b| b.position),
                        entry_seen: b.map_or([None; 4], |b| *b.seen),
                        pre_rets: b.map_or([None; 4], |b| *b.rows),
                        pending,
                        next_ordinal: s.next,
                        totals: s.totals,
                        interval_batch: s.cursor.number,
                        interval_cursor_totals: s.cursor.totals,
                        model_depth: s.model.depth(),
                        completed_sequence: s.model.completed_sequence(),
                        journal: s.journal.page.0,
                    });
                    Ok(())
                })
                .unwrap_or(Err(error(Cause::Attachment)))
        })
        .unwrap_or(Err(error(Cause::Attachment)))
}
// Private owned scratch. Every successful capture overwrites all 640 words;
// none of these prior values or the presence bit is a validation cache.
struct FlatSnapshot {
    header: [u64; 128],
    journal: [u64; 512],
    active: bool,
}
struct FlatObserverState {
    snapshot: FlatSnapshot,
    sequence: u64,
}
impl FlatObserverState {
    fn new() -> Self {
        Self {
            snapshot: FlatSnapshot {
                header: [0; 128],
                journal: [0; 512],
                active: false,
            },
            sequence: 0,
        }
    }
    fn prepare(&mut self, kind: PauseKind) -> Result<(), BridgeError> {
        qualification_words_into(&mut self.snapshot)?;
        // Preserve the old child order: successful owned capture, both TLS
        // borrows released, sequence increment, then active-snapshot unwrap.
        self.sequence += 1;
        self.snapshot.active.then_some(()).unwrap();
        self.snapshot.header[0] = 0x6561_726c_796d_6f64;
        self.snapshot.header[1] = match kind {
            PauseKind::AfterEntryPublished => 1,
            PauseKind::AfterPreRetPublished => 2,
        };
        self.snapshot.header[2] = self.sequence;
        Ok(())
    }
}

// Shared by the real boxed adapter and private failure-order controls. No
// externally supplied callback runs before complete capture and header finish.
struct EncodedObserver<F> {
    state: FlatObserverState,
    observer: F,
}
impl<F: FnMut(&[u64; 128], &[u64; 512])> EncodedObserver<F> {
    fn call(&mut self, kind: PauseKind) -> Result<(), BridgeError> {
        self.state.prepare(kind)?;
        (self.observer)(&self.state.snapshot.header, &self.state.snapshot.journal);
        Ok(())
    }
}

// Serialize the actual summary once, without an intermediate OwnerSnapshot.
fn flat_summary(destination: &mut [u64; 8], summary: IntervalEntrySummary) {
    let (kind, generation, invocation, history_len, binding, closed_function) = match summary {
        IntervalEntrySummary::Admitted {
            generation,
            invocation,
            history_len,
            binding,
        } => (
            1,
            generation.get(),
            invocation as u64,
            history_len,
            binding,
            0,
        ),
        IntervalEntrySummary::Unsampled {
            reason,
            history_len,
            binding,
        } => {
            let (kind, generation, closed_function) = match reason {
                UnsampledSummary::InitialDisarmed => (2, 0, 0),
                UnsampledSummary::Removed { generation } => (3, generation.get(), 0),
                UnsampledSummary::FunctionClosed {
                    generation,
                    function,
                } => (4, generation.get(), function.0),
            };
            (kind, generation, 0, history_len, binding, closed_function)
        }
    };
    let (binding, index, bound_generation) = match binding {
        BindingChange::Initial => (0, 0, 0),
        BindingChange::Published {
            action_index,
            generation,
        } => (1, action_index as u64, generation.get()),
        BindingChange::Removed {
            action_index,
            generation,
        } => (2, action_index as u64, generation.get()),
    };
    destination[0] = kind;
    destination[1] = generation;
    destination[2] = invocation;
    destination[3] = history_len as u64;
    destination[4] = binding;
    destination[5] = index;
    destination[6] = bound_generation;
    destination[7] = closed_function;
}

// This independent TLS reborrow retains the typed helper's complete ordered
// checks. Only after its last possible BridgeError do any destination writes
// occur. The journal is still an ordinary complete owned copy under the borrows.
#[inline(never)]
fn qualification_words_into(destination: &mut FlatSnapshot) -> Result<(), BridgeError> {
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
                        (Some(v), Some(position)) => Some((v, position)),
                        _ => return Err(error(Cause::Invariant)),
                    };
                    let h = &mut destination.header;
                    h.fill(0);
                    if let Some((v, position)) = pending {
                        h[57] = 1;
                        h[58] = b.unwrap().number;
                        h[59] = position as u64;
                        h[60] = v.selected.function.0;
                        h[61] = v.ordinal;
                        h[62] = v.entry_pc;
                        h[63] = v.rsp;
                        h[64] = v.word;
                        h[65] = v.start.ticks;
                        h[66] = u64::from(v.start.aux);
                        if let Some(summary) = v.summary {
                            h[75] = 1;
                            flat_summary((&mut h[76..84]).try_into().unwrap(), summary);
                        }
                        // Read the actual receipt independently and before the
                        // later model scalars/journal, just as the typed capture.
                        if let Some(summary) = v.receipt.summary() {
                            h[84] = 1;
                            flat_summary((&mut h[85..93]).try_into().unwrap(), summary);
                            h[71] = h[86];
                            h[72] = h[87];
                        }
                        if let Some(r) = v.returned {
                            h[67] = 1;
                            h[68] = r.return_pc;
                            h[69] = r.end.ticks;
                            h[70] = u64::from(r.end.aux);
                            let (kind, generation, invocation) = match r.owner {
                                RawIntervalOwner::Sampled {
                                    generation,
                                    invocation,
                                } => (1, generation, invocation as u64),
                                RawIntervalOwner::InitialDisarmed => (2, 0, 0),
                                RawIntervalOwner::Removed { generation } => (3, generation, 0),
                                RawIntervalOwner::FunctionClosed { generation } => {
                                    (4, generation, 0)
                                }
                            };
                            h[93] = r.ordinal;
                            h[94] = r.entry_pc;
                            h[95] = r.return_pc;
                            h[96] = kind;
                            h[97] = generation;
                            h[98] = invocation;
                            h[99] = r.start.ticks;
                            h[100] = u64::from(r.start.aux);
                            h[101] = r.end.ticks;
                            h[102] = u64::from(r.end.aux);
                        }
                        h[73] = v.slot.identity;
                        h[74] = v.slot.word;
                    }
                    h[3] = Arc::as_ptr(&s.binding.key) as usize as u64;
                    h[4] = u64::from(s.binding.pid);
                    h[5] = s.tid;
                    h[6] = s.registration;
                    h[7] = p.batches;
                    h[8] = p.calls;
                    destination.active = b.is_some();
                    if let Some(b) = b {
                        h[9] = b.number;
                        h[10] = b.position as u64;
                        for (i, seen) in b.seen.iter().enumerate() {
                            h[25 + i] = seen.unwrap_or(0);
                        }
                        for (i, row) in b.rows.iter().enumerate() {
                            if let Some(r) = row {
                                let at = 29 + i * 7;
                                h[at] = r.batch;
                                h[at + 1] = r.position as u64;
                                h[at + 2] = r.function.0;
                                h[at + 3] = r.observed_ordinal.unwrap_or(0);
                                h[at + 4] = r.return_pc;
                                h[at + 5] = r.entry_rsp;
                                h[at + 6] = r.return_word;
                            }
                        }
                    }
                    h[11] = s.next;
                    h[15] = s.totals.entered;
                    h[16] = s.totals.ret_observed;
                    h[17] = s.totals.confirmed;
                    h[18] = s.totals.completed;
                    h[19] = s.totals.unsampled;
                    h[14] = s.cursor.number;
                    h[20] = s.cursor.totals.entered;
                    h[21] = s.cursor.totals.ret_observed;
                    h[22] = s.cursor.totals.confirmed;
                    h[23] = s.cursor.totals.completed;
                    h[24] = s.cursor.totals.unsampled;
                    h[12] = s.model.depth() as u64;
                    h[13] = s.model.completed_sequence();
                    destination.journal.copy_from_slice(&s.journal.page.0);
                    Ok(())
                })
                .unwrap_or(Err(error(Cause::Attachment)))
        })
        .unwrap_or(Err(error(Cause::Attachment)))
}

type Observer = Box<dyn FnMut(PauseKind) -> Result<(), BridgeError>>;
thread_local! { static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) }; }
/// # Safety
/// Qualification only: observer never enters subject/controller/model code on
/// this worker, unwinds or alters code/control/state. Any wait has the fixed
/// native-owner deadline and a separate real controller ACK; no model/TLS lock
/// is held while it runs. Its copied witness is not another thread's TLS access.
/// The borrowed snapshot is an owned local copy valid only for this call; an
/// observer that retains or transfers it must make its own owned copy.
pub unsafe fn install_observer(
    mut observer: impl FnMut(PauseKind, &QualificationSnapshot) + 'static,
) -> Result<(), BridgeError> {
    install_preparing_observer(|| -> Observer {
        Box::new(move |kind| {
            let mut snapshot = std::mem::MaybeUninit::uninit();
            qualification_snapshot_into(&mut snapshot)?;
            // SAFETY: unchanged typed helper initialized every field and
            // released both TLS borrows before this existing typed callback.
            observer(kind, unsafe { snapshot.assume_init_ref() });
            Ok(())
        })
    })
}

/// Install the qualification-only complete 128-word header / 512-word journal
/// observer. Its single observer allocation owns reusable ordinary scratch;
/// every successful capture overwrites all words before this callback runs.
/// The header includes the pause kind and a sequence starting at one.
///
/// # Safety
/// The full no-reentry/no-unwind/state-preservation and bounded-wait contract of
/// `install_observer` applies unchanged. Both TLS borrows end before the callback.
/// Arrays are disjoint owned copies, borrowed only for this call. Retaining or
/// transferring their values requires another owned copy, never their addresses.
/// This observer requires the same active-batch publication points as the native
/// witness encoder; an inactive snapshot panics after capture/sequence advance.
pub unsafe fn install_encoded_observer(
    observer: impl FnMut(&[u64; 128], &[u64; 512]) + 'static,
) -> Result<(), BridgeError> {
    install_preparing_observer(|| -> Observer {
        let mut adapter = EncodedObserver {
            state: FlatObserverState::new(),
            observer,
        };
        Box::new(move |kind| adapter.call(kind))
    })
}

// The factory is invoked only after the original attachment/empty-slot checks.
// It enlarges the one observer allocation; callbacks do not allocate scratch.
fn install_preparing_observer(make: impl FnOnce() -> Observer) -> Result<(), BridgeError> {
    OBSERVER
        .try_with(|cell| {
            let mut slot = cell
                .try_borrow_mut()
                .map_err(|_| error(Cause::Attachment))?;
            if slot.is_some() {
                return Err(error(Cause::Attachment));
            }
            *slot = Some(make());
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
                observer(kind)?;
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

#[cfg(test)]
mod tests;
