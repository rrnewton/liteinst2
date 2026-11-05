//! Separate finite admission interval; ordinary call guards remain unchanged.

use super::{Admission, ClockError, ClockLease, MAX_WORK, thread_id};

impl ClockLease {
    /// Admit one fixed batch on an otherwise unused acquired clock lease.
    ///
    /// Both positive budgets are checked before admission. Their product must
    /// fit the exact work bound supplied to `BackedgeClock::acquire`, not merely
    /// the profile ceiling. No clock word is reset or changed by this method.
    /// Ordinary calls and batches cannot share or reuse the admitted budget.
    ///
    /// Owner PID/TID are checked here and again at explicit batch completion.
    /// Lightweight per-call tokens do not repeat those owner queries. This is
    /// an explicit stronger interval contract, not a change to `begin_call`.
    ///
    /// # Safety
    /// All acquisition, source/control binding, mapping-lifetime and callback
    /// obligations of the original lease remain in force. The caller excludes
    /// every foreign, recursive, signal-handler and interior entry for the
    /// entire batch, including host-loop gaps and callbacks. No thread may fork
    /// an inheriting child with usable entry, and this worker may not migrate
    /// to another thread or process. Non-Send/Sync types do not exclude fork.
    ///
    /// Each token authorizes exactly one native invocation. Obtain it before
    /// the first generated spill and call `returned` only after that exact
    /// invocation and every callback have drained. Do not expose a callable
    /// entry or token to callbacks, or enter generated code without its token.
    /// `max_work_per_call` bounds all encounters and taken decisions across all
    /// sites in each invocation, including untaken encounters. These pre-entry
    /// proofs prevent overflow; the generated clock does not trap on budgets.
    /// Counters/remaining quantum continue across calls without resets. Only
    /// the existing authenticated stopped callback may refill a zero quantum.
    ///
    /// Complete every declared call and explicitly finish the batch. Abandoned
    /// tokens, incomplete batches and failed finishes leave the lease held.
    /// Dropping a token or batch during unwinding cannot release it, and
    /// completion attempted while unwinding is refused. Panics caught entirely
    /// between completed invocations do not change this protocol state.
    /// Dropping a value is not evidence that execution drained.
    pub unsafe fn begin_batch(
        &self,
        calls: u64,
        max_work_per_call: u64,
    ) -> Result<ClockBatch<'_>, ClockError> {
        if self.clock.inner.pid != std::process::id() || self.tid != thread_id() {
            return Err(ClockError::Owner);
        }
        if self.admission.get() != Admission::Fresh || self.in_call.get() {
            return Err(ClockError::Invocation);
        }
        let work = calls
            .checked_mul(max_work_per_call)
            .filter(|&work| {
                calls != 0
                    && max_work_per_call != 0
                    && work <= self.admitted_work
                    && self.admitted_work <= MAX_WORK
            })
            .ok_or(ClockError::Invocation)?;
        self.in_call.set(true);
        self.admission.set(Admission::Batch);
        Ok(ClockBatch {
            lease: self,
            calls,
            remaining_calls: calls,
            remaining_work: work,
            work_per_call: max_work_per_call,
            completed: 0,
            in_call: false,
            poisoned: false,
        })
    }
}

/// A fixed borrowed admission interval, requiring explicit completion.
///
/// The enclosing lease remains in-call even between native invocations. Drop
/// intentionally has no release action, including after every call returned:
/// only `finish` performs the closing owner check and clears that latch.
///
/// ```compile_fail
/// use liteinst::backedge_clock::ClockBatch;
/// fn require_send<T: Send>() {}
/// require_send::<ClockBatch<'static>>();
/// ```
/// ```compile_fail
/// use liteinst::backedge_clock::ClockBatch;
/// fn require_sync<T: Sync>() {}
/// require_sync::<ClockBatch<'static>>();
/// ```
/// ```compile_fail
/// use liteinst::backedge_clock::ClockBatch;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ClockBatch<'static>>();
/// ```
#[must_use = "a batch must complete every call and explicitly finish"]
pub struct ClockBatch<'lease> {
    lease: &'lease ClockLease,
    calls: u64,
    remaining_calls: u64,
    remaining_work: u64,
    work_per_call: u64,
    completed: u64,
    in_call: bool,
    poisoned: bool,
}

impl<'lease> ClockBatch<'lease> {
    /// Precharge one call and its work allowance before native entry.
    ///
    /// The mutable borrow excludes overlapping tokens. A forgotten token also
    /// leaves a runtime latch set, so forgetting it cannot enable another call.
    /// This method performs no owner syscall or clock-word access; the unsafe
    /// whole-batch interval obligations remain the caller's responsibility.
    ///
    /// ```compile_fail
    /// use liteinst::backedge_clock::ClockBatch;
    /// fn overlapping(batch: &mut ClockBatch<'_>) {
    ///     let first = batch.begin_call().unwrap();
    ///     let second = batch.begin_call().unwrap();
    ///     first.returned();
    ///     second.returned();
    /// }
    /// ```
    pub fn begin_call(&mut self) -> Result<ClockBatchCall<'_, 'lease>, ClockError> {
        if self.poisoned || self.in_call || self.remaining_calls == 0 {
            return Err(ClockError::Invocation);
        }
        let remaining_work = self
            .remaining_work
            .checked_sub(self.work_per_call)
            .ok_or(ClockError::Invocation)?;
        self.remaining_calls -= 1;
        self.remaining_work = remaining_work;
        self.in_call = true;
        Ok(ClockBatchCall {
            batch: self,
            returned: false,
        })
    }

    /// Close only a fully completed batch on the admitted actual worker.
    ///
    /// A failed finish consumes this handle but leaves the enclosing lease
    /// held. It never resets words or makes an unproven invocation reusable.
    /// A successful finish still cannot admit more calls on the same lease.
    pub fn finish(self) -> Result<(), ClockError> {
        if self.lease.clock.inner.pid != std::process::id() || self.lease.tid != thread_id() {
            return Err(ClockError::Owner);
        }
        if std::thread::panicking()
            || self.poisoned
            || self.in_call
            || self.remaining_calls != 0
            || self.remaining_work != 0
            || self.completed != self.calls
            || self.lease.admission.get() != Admission::Batch
            || !self.lease.in_call.get()
        {
            return Err(ClockError::Invocation);
        }
        self.lease.admission.set(Admission::Finished);
        self.lease.in_call.set(false);
        Ok(())
    }
}

/// One precharged invocation, held through its exact native return.
///
/// `returned` is explicit; Drop and unwind leave the batch poisoned and held.
/// The safety obligation belongs to the unsafe batch admission: completion may
/// not be declared early or used to authorize more than this one invocation.
///
/// ```compile_fail
/// use liteinst::backedge_clock::ClockBatchCall;
/// fn require_send<T: Send>() {}
/// require_send::<ClockBatchCall<'static, 'static>>();
/// ```
/// ```compile_fail
/// use liteinst::backedge_clock::ClockBatchCall;
/// fn require_sync<T: Sync>() {}
/// require_sync::<ClockBatchCall<'static, 'static>>();
/// ```
/// ```compile_fail
/// use liteinst::backedge_clock::ClockBatchCall;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ClockBatchCall<'static, 'static>>();
/// ```
/// ```compile_fail
/// use liteinst::backedge_clock::{ClockBatchCall, ClockLease};
/// fn escape<'a>(lease: &'a ClockLease) -> ClockBatchCall<'a, 'a> {
///     let mut batch = unsafe { lease.begin_batch(1, 1).unwrap() };
///     batch.begin_call().unwrap()
/// }
/// ```
#[must_use = "retain the token through native return, then call returned"]
pub struct ClockBatchCall<'call, 'lease> {
    batch: &'call mut ClockBatch<'lease>,
    returned: bool,
}

impl ClockBatchCall<'_, '_> {
    /// Acknowledge the exact drained native invocation admitted by this token.
    /// Calling this while unwinding cannot complete or release the invocation.
    pub fn returned(mut self) {
        if std::thread::panicking() {
            return;
        }
        // Admission bounds completed <= calls <= MAX_WORK, so this cannot wrap.
        self.batch.completed += 1;
        self.batch.in_call = false;
        self.returned = true;
    }
}

impl Drop for ClockBatchCall<'_, '_> {
    fn drop(&mut self) {
        if !self.returned {
            self.batch.poisoned = true;
            // Keep both in-call latches held: Drop is not a drainage proof.
        }
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
