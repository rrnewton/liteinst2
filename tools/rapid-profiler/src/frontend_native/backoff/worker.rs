use super::*;

// Private transport seam: production supplies Instant::now/sleep; controls use
// the same real capacity-two channel with deterministic observations/waits.
// This is called only after drain_completed returned an owned, post-RET packet.
fn transfer<T>(
    tx: &mpsc::SyncSender<T>,
    mut value: T,
    policy: Policy,
    shared: &Shared,
    mut now: impl FnMut() -> Instant,
    mut wait: impl FnMut(Duration),
) -> Result<(), (Error, T)> {
    if !policy.worker_backpressure() {
        return send(tx, value);
    }
    let Some(start) = shared.start.get() else {
        return Err((Error::NotStarted, value));
    };
    let Some(cutoff) = policy
        .period()
        .checked_mul(policy.epoch_limit())
        .and_then(|duration| start.checked_add(duration))
        .and_then(|end| end.checked_add(policy.shutdown()))
    else {
        return Err((Error::Deadline, value));
    };
    // Observe failure before the first send and after every wait. The cutoff
    // never depends on Full, a new packet, or the current clock observation.
    let checkpoint = |now: &mut dyn FnMut() -> Instant| {
        if shared.controller_failed.load(Ordering::Acquire) {
            return Err(Error::ControllerFailed);
        }
        cutoff
            .checked_duration_since(now())
            .filter(|left| !left.is_zero())
            .ok_or(Error::Deadline)
    };
    loop {
        if let Err(error) = checkpoint(&mut now) {
            return Err((error, value));
        }
        value = match send(tx, value) {
            Ok(()) => return Ok(()),
            Err((Error::Full, retained)) => retained,
            Err(error) => return Err(error),
        };
        // Recheck after the failed send so its duration cannot enlarge sleep.
        let left = match checkpoint(&mut now) {
            Ok(left) => left,
            Err(error) => return Err((error, value)),
        };
        wait(POLL.min(left));
    }
}

/// Moves to the worker before attachment. Deliberately not Clone.
pub struct Client {
    pub(super) client: IntervalClient,
    pub(super) policy: Policy,
    pub(super) shared: Arc<Shared>,
    pub(super) tx: mpsc::SyncSender<CompletedBatch>,
}
impl Client {
    /// # Safety
    /// The ordinary leaf's existing attachment, stack, pinning, immutable input,
    /// no-signal/no-unwind and normal-return contracts apply until finish returns.
    /// Allocate the journal and attach on the actual sole worker; neither is Send.
    pub unsafe fn attach(
        self,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<Thread, Error> {
        if self.shared.attached.swap(true, Ordering::AcqRel) {
            return Err(Error::Worker);
        }
        // SAFETY: caller supplies the unchanged attachment contract above.
        let attached = match unsafe { self.client.attach(1, stack, journal) } {
            Ok(v) => v,
            Err(e) => {
                self.shared.stop.store(true, Ordering::Release);
                return Err(e.into());
            }
        };
        Ok(Thread {
            attached,
            policy: self.policy,
            shared: self.shared,
            tx: self.tx,
            calls: [None; ROWS],
            count: 0,
            pending: None,
            error: None,
            last_flush: Instant::now(),
            finished: false,
            drained: false,
        })
    }
}

/// Thread-local, non-Clone and !Send through its actual IntervalThread member.
/// No external callback or per-call controller rendezvous is introduced.
///
/// ```compile_fail
/// use rapid_profiler::frontend_native::backoff::Thread;
/// fn require_send<T: Send>() {}
/// require_send::<Thread>();
/// ```
pub struct Thread {
    attached: IntervalThread,
    policy: Policy,
    shared: Arc<Shared>,
    tx: mpsc::SyncSender<CompletedBatch>,
    calls: [Option<CompletedCall>; ROWS],
    count: usize,
    pending: Option<CompletedBatch>,
    error: Option<Error>,
    last_flush: Instant,
    finished: bool,
    drained: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallOutcome {
    StoppedBeforeCall,
    Returned {
        call: CallResult,
        export_error: Option<Error>,
    },
}
/// Returned on the worker. Moving this metadata value is NOT an OS join proof.
#[derive(Debug)]
pub struct WorkerFinish {
    pub status: WorkerStatus,
    pub unexported: Option<CompletedBatch>,
    /// Genuine returned calls whose native drain refused; no invented batch.
    pub partial_calls: [Option<CompletedCall>; ROWS],
}
impl Thread {
    fn fail(&mut self, e: Error) -> Error {
        self.error.get_or_insert(e);
        self.shared.stop.store(true, Ordering::Release);
        e
    }
    /// Flush idle work explicitly. Terminal export failure retains exactly the
    /// drained packet; no later invocation can overwrite it or reset the error.
    /// Opt-in worker backpressure waits only here, outside native/TLS locks.
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(self.error.unwrap_or(Error::Full));
        }
        self.drained = false;
        let native = match self.attached.drain_completed() {
            Ok(Some(v)) => v,
            Ok(None) if self.count == 0 => {
                self.drained = true;
                return Ok(());
            }
            Ok(None) => return Err(self.fail(Error::Sequence)),
            Err(e) => return Err(self.fail(e.into())),
        };
        let count_matches = native.rows().len() == self.count;
        let packet = CompletedBatch {
            native,
            calls: self.calls,
        };
        self.drained = true;
        self.calls = [None; ROWS];
        self.count = 0;
        self.last_flush = Instant::now();
        if !count_matches {
            self.pending = Some(packet);
            return Err(self.fail(Error::Sequence));
        }
        match transfer(
            &self.tx,
            packet,
            self.policy,
            &self.shared,
            Instant::now,
            std::thread::sleep,
        ) {
            Ok(()) => Ok(()),
            Err((e, packet)) => {
                self.pending = Some(packet);
                Err(self.fail(e))
            }
        }
    }
    /// # Safety
    /// The exact ordinary readonly leaf contract holds for this input and the
    /// actual gate invocation. This method cannot interrupt or cancel a call.
    pub unsafe fn invoke(&mut self, bytes: &[u8]) -> Result<CallOutcome, Error> {
        if self.error.is_some() || self.shared.stop.load(Ordering::Acquire) {
            return Ok(CallOutcome::StoppedBeforeCall);
        }
        let origin = *self.shared.start.get().ok_or(Error::NotStarted)?;
        if Instant::now() < origin {
            return Err(Error::NotStarted);
        }
        let totals = match self.attached.totals() {
            Ok(v) => v,
            Err(e) => return Err(self.fail(e.into())),
        };
        if totals.entries == self.policy.calls {
            self.shared.stop.store(true, Ordering::Release);
            return Ok(CallOutcome::StoppedBeforeCall);
        }
        if totals.entries > self.policy.calls || self.count == ROWS {
            return Err(self.fail(Error::CallLimit));
        }
        self.drained = false;
        let before = Instant::now().duration_since(origin);
        // SAFETY: delegated exact unsafe input/ABI/termination contract above.
        let call = match unsafe { self.attached.invoke_integer_leaf(bytes) } {
            Ok(v) => v,
            Err(e) => return Err(self.fail(e.into())),
        };
        let after = Instant::now().duration_since(origin);
        self.calls[self.count] = Some(CompletedCall {
            ordinal: totals.entries + 1,
            length: bytes.len(),
            result: call,
            before,
            after,
        });
        self.count += 1;
        let export_error =
            if self.count == ROWS || self.last_flush.elapsed() >= self.policy.period() {
                self.flush().err()
            } else {
                None
            };
        if totals.entries + 1 == self.policy.calls {
            self.shared.stop.store(true, Ordering::Release);
        }
        Ok(CallOutcome::Returned { call, export_error })
    }
    /// Final flush then empty detach on the actual worker. On failure, retained
    /// packets/partial calls are returned without claiming a successful drain.
    /// Caller must still join the actual thread before reclaiming its input.
    pub fn finish(mut self) -> WorkerFinish {
        self.shared.stop.store(true, Ordering::Release);
        let _ = self.flush(); // First error is retained, never converted to success.
        let totals = match self.attached.totals() {
            Ok(v) => Some(v),
            Err(e) => {
                self.fail(e.into());
                None
            }
        };
        let detached = if self.drained && self.count == 0 {
            match self.attached.detach() {
                Ok(v) if Some(v) == totals => true,
                Ok(_) => {
                    self.fail(Error::Sequence);
                    false
                }
                Err(e) => {
                    self.fail(e.into());
                    false
                }
            }
        } else {
            false
        };
        let status = WorkerStatus {
            totals,
            detached,
            error: self.error,
            unexported: self.pending.is_some() || self.count != 0,
        };
        // Single consuming finish, single attachment, no overwrite or restart.
        if self.shared.finished.set(status).is_err() {
            self.fail(Error::Worker);
        }
        self.finished = true;
        WorkerFinish {
            status,
            unexported: self.pending.take(),
            partial_calls: self.calls,
        }
    }
}
#[cfg(test)]
mod tests;

impl Drop for Thread {
    fn drop(&mut self) {
        if !self.finished {
            self.shared.stop.store(true, Ordering::Release);
        }
        // Existing IntervalThread Drop still owns its native cleanup/refusal.
        // Missing explicit finish is never acknowledged as driver completion.
    }
}
