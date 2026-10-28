use super::*;

/// One transferable attachment authority; no clone or application-side call mutex.
pub struct OptionalClient {
    pub(super) client: NativeClient,
    pub(super) policy: Policy,
    pub(super) shared: Arc<SharedOptional>,
    pub(super) tx: mpsc::SyncSender<OptionalCompletedBatch>,
}
impl OptionalClient {
    /// # Safety
    /// Attach on the actual sole pinned worker with a valid stack and fresh journal.
    /// Every optional readonly-leaf ABI, lifetime and normal-return contract applies.
    pub unsafe fn attach(
        self,
        stack: ReadableStack,
        journal: IntervalJournal,
    ) -> Result<OptionalThread, Error> {
        if self.shared.common.attached.swap(true, Ordering::AcqRel) {
            return Err(Error::Worker);
        }
        // SAFETY: caller supplies the exact actual-thread attachment contract.
        let attached = match unsafe { self.client.attach(1, stack, journal) } {
            Ok(t) => t,
            Err(e) => {
                self.shared.common.stop.store(true, Ordering::Release);
                return Err(e.into());
            }
        };
        Ok(OptionalThread {
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
/// Actual-thread-only state; the native OptionalThread is neither Send nor Sync.
/// ```compile_fail
/// use rapid_profiler::frontend_native::backoff::OptionalThread;
/// fn send<T: Send>() {}
/// send::<OptionalThread>();
/// ```
pub struct OptionalThread {
    attached: NativeThread,
    policy: Policy,
    shared: Arc<SharedOptional>,
    tx: mpsc::SyncSender<OptionalCompletedBatch>,
    calls: [Option<OptionalCompletedCall>; ROWS],
    count: usize,
    pending: Option<OptionalCompletedBatch>,
    error: Option<Error>,
    last_flush: Instant,
    finished: bool,
    drained: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionalCallOutcome {
    StoppedBeforeCall,
    Returned {
        call: OptionalCallResult,
        export_error: Option<Error>,
    },
}
#[derive(Debug)]
pub struct OptionalWorkerFinish {
    pub status: OptionalWorkerStatus,
    pub unexported: Option<OptionalCompletedBatch>,
    /// Successfully returned calls retained when actual native drain refused.
    pub partial_calls: [Option<OptionalCompletedCall>; ROWS],
}
impl OptionalThread {
    fn fail(&mut self, e: Error) -> Error {
        self.error.get_or_insert(e);
        self.shared.common.stop.store(true, Ordering::Release);
        e
    }
    /// Transfer only after the real successful-return/idle checkpoint. A failed
    /// transfer keeps the original full packet and forbids further invocation.
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(self.error.unwrap_or(Error::Full));
        }
        self.drained = false;
        let native = match self.attached.drain_completed() {
            Ok(Some(b)) => b,
            Ok(None) if self.count == 0 => {
                self.drained = true;
                return Ok(());
            }
            Ok(None) => return Err(self.fail(Error::Sequence)),
            Err(e) => return Err(self.fail(e.into())),
        };
        let range = native.physical_range();
        let matches = range.end.checked_sub(range.start) == Some(self.count as u64);
        let packet = OptionalCompletedBatch {
            native,
            calls: self.calls,
        };
        self.drained = true;
        self.calls = [None; ROWS];
        self.count = 0;
        self.last_flush = Instant::now();
        if !matches {
            self.pending = Some(packet);
            return Err(self.fail(Error::Sequence));
        }
        match super::super::worker::transfer(
            &self.tx,
            packet,
            self.policy,
            &self.shared.common,
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
    /// Only valid immutable input for the admitted ordinary leaf, with exact
    /// optional-gate/stack/publication and normal-return obligations, may be used.
    pub unsafe fn invoke(&mut self, bytes: &[u8]) -> Result<OptionalCallOutcome, Error> {
        if self.error.is_some() || self.shared.common.stop.load(Ordering::Acquire) {
            return Ok(OptionalCallOutcome::StoppedBeforeCall);
        }
        let start = *self.shared.common.start.get().ok_or(Error::NotStarted)?;
        if Instant::now() < start {
            return Err(Error::NotStarted);
        }
        let totals = match self.attached.totals() {
            Ok(v) => v,
            Err(e) => return Err(self.fail(e.into())),
        };
        if totals.physical == self.policy.calls {
            self.shared.common.stop.store(true, Ordering::Release);
            return Ok(OptionalCallOutcome::StoppedBeforeCall);
        }
        if totals.physical > self.policy.calls || self.count == ROWS {
            return Err(self.fail(Error::CallLimit));
        }
        self.drained = false;
        let before = Instant::now().duration_since(start);
        // SAFETY: exact delegated optional invocation contract above.
        let call = match unsafe { self.attached.invoke_integer_leaf(bytes) } {
            Ok(call) => call,
            Err(e) => return Err(self.fail(e.into())),
        };
        let after = Instant::now().duration_since(start);
        // Keep actual returned evidence before any subsequent validation/refusal.
        self.calls[self.count] = Some(OptionalCompletedCall {
            length: bytes.len(),
            result: call,
            before,
            after,
        });
        self.count += 1;
        if totals.physical.checked_add(1) != Some(call.physical) {
            return Ok(OptionalCallOutcome::Returned {
                call,
                export_error: Some(self.fail(Error::Sequence)),
            });
        }
        let export_error =
            if self.count == ROWS || self.last_flush.elapsed() >= self.policy.period() {
                self.flush().err()
            } else {
                None
            };
        if call.physical == self.policy.calls {
            self.shared.common.stop.store(true, Ordering::Release);
        }
        Ok(OptionalCallOutcome::Returned { call, export_error })
    }
    /// Actual same-thread final flush/detach; returned metadata is not OS join.
    pub fn finish(mut self) -> OptionalWorkerFinish {
        self.shared.common.stop.store(true, Ordering::Release);
        let _ = self.flush();
        let totals = match self.attached.totals() {
            Ok(v) => Some(v),
            Err(e) => {
                self.fail(e.into());
                None
            }
        };
        let detached = if self.drained && self.count == 0 {
            match self.attached.detach() {
                Ok(t) if Some(t) == totals => true,
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
        let status = OptionalWorkerStatus {
            totals,
            detached,
            error: self.error,
            unexported: self.pending.is_some() || self.count != 0,
        };
        if self.shared.finished.set(status).is_err() {
            self.fail(Error::Worker);
        }
        self.finished = true;
        OptionalWorkerFinish {
            status,
            unexported: self.pending.take(),
            partial_calls: self.calls,
        }
    }
}
impl Drop for OptionalThread {
    fn drop(&mut self) {
        if !self.finished {
            self.shared.common.stop.store(true, Ordering::Release);
        }
        // Native attachment owns its existing cleanup; no fabricated finish.
    }
}
