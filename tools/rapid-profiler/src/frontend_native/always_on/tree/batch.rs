//! Explicit eight-call provenance policy; legacy calls retain their full checks.
use super::*;
pub(super) use crate::frontend_native::module::ordinary::TreeSourceProof as SourceProof;

const CALLS: usize = 8;

#[derive(Clone, Copy)]
pub(super) enum SourceAuthority<'a> {
    Full,
    Batch(&'a SourceProof),
}

/// A failed batch stays failed. The first concrete call error remains retained.
#[derive(Clone, Debug)]
pub enum TreeSourceBatchError {
    /// An admitted batch was forgotten, is executing, or has not been finished.
    Unfinished,
    /// Exactly eight successful calls are required; no extra call is permitted.
    CallCount,
    /// The guard was dropped without a successful explicit finish.
    Abandoned,
    /// The exact first source, gate or model refusal, without fallback.
    Call(Rc<TreeError>),
}
impl From<TreeError> for TreeSourceBatchError {
    fn from(e: TreeError) -> Self {
        // Error retention can allocate, but must not allow callback reentry.
        // On an already-active scope its existing marker remains in force.
        let _scope = ControllerScope::enter();
        Self::Call(Rc::new(e))
    }
}
impl From<SiteError> for TreeSourceBatchError {
    fn from(e: SiteError) -> Self {
        TreeError::Site(e).into()
    }
}
impl From<BridgeError> for TreeSourceBatchError {
    fn from(e: BridgeError) -> Self {
        TreeError::Bridge(e).into()
    }
}
impl From<GateError> for TreeSourceBatchError {
    fn from(e: GateError) -> Self {
        TreeError::Gate(e).into()
    }
}

// Resident in the actual owner, never just in the guard. Busy persists through
// a caught invoke unwind; forgetting a guard cannot return this latch to Closed.
pub(super) enum Latch {
    Closed,
    Open(usize),
    Busy(usize),
    Failed(TreeSourceBatchError),
}
impl Latch {
    pub(super) fn closed(&self) -> Result<(), TreeSourceBatchError> {
        match self {
            Self::Closed => Ok(()),
            Self::Failed(e) => Err(e.clone()),
            _ => Err(TreeSourceBatchError::Unfinished),
        }
    }
    fn start(&mut self, finish: bool) -> Result<usize, TreeSourceBatchError> {
        match self {
            Self::Open(n) if (!finish && *n < CALLS) || (finish && *n == CALLS) => {
                let n = *n;
                *self = Self::Busy(n);
                Ok(n)
            }
            Self::Open(_) => Err(TreeSourceBatchError::CallCount),
            Self::Failed(e) => Err(e.clone()),
            _ => Err(TreeSourceBatchError::Unfinished),
        }
    }
    // Observation borrows the same owner but never admits/finishes a call.
    // Busy precedes every scope/TLS/gate check so an unwind cannot expose Open.
    fn begin_observation(&mut self) -> Result<usize, TreeSourceBatchError> {
        match self {
            Self::Open(n) if *n <= CALLS => {
                let n = *n;
                *self = Self::Busy(n);
                Ok(n)
            }
            Self::Open(_) => Err(TreeSourceBatchError::CallCount),
            Self::Failed(e) => Err(e.clone()),
            _ => Err(TreeSourceBatchError::Unfinished),
        }
    }
    fn complete_observation(&mut self, expected: usize) -> Result<(), TreeSourceBatchError> {
        match self {
            Self::Busy(n) if *n == expected && expected <= CALLS => {
                *self = Self::Open(expected);
                Ok(())
            }
            Self::Failed(e) => Err(e.clone()),
            _ => Err(TreeSourceBatchError::Unfinished),
        }
    }
    fn completed_call(&mut self) {
        // Only the successful path after start(false), with no user callback.
        if let Self::Busy(n) = self {
            *self = Self::Open(*n + 1);
        } else {
            unreachable!("batch call completed without its private busy latch");
        }
    }
    fn fail(&mut self, e: TreeSourceBatchError) -> TreeSourceBatchError {
        if let Self::Failed(first) = self {
            return first.clone();
        }
        *self = Self::Failed(e.clone());
        e
    }
    fn abandon(&mut self) {
        if matches!(self, Self::Open(_) | Self::Busy(_)) {
            *self = Self::Failed(TreeSourceBatchError::Abandoned);
        }
    }
}

/// One borrowed input and its caller-supplied, strictly increasing external ID.
#[derive(Clone, Copy)]
pub struct TreeSourceBatchRequest<'a> {
    pub bytes: &'a [u8],
    pub external_id: u64,
}
/// Successful final file/mapping revalidation for exactly eight actual calls.
/// This is neither an executable-retirement lease nor an epoch/model owner.
#[derive(Debug, Eq, PartialEq)]
pub struct TreeSourceBatchVerification {
    calls: usize,
}
impl TreeSourceBatchVerification {
    pub fn calls(&self) -> usize {
        self.calls
    }
}

fn inputs<'a>(
    bytes: impl IntoIterator<Item = &'a [u8]>,
) -> Result<[[u8; 1024]; CALLS], BridgeError> {
    let mut snapshots = [[0; 1024]; CALLS];
    let mut n = 0;
    for bytes in bytes {
        let at = snapshots.get_mut(n).ok_or(error(Cause::Capacity))?;
        *at = input_copy(bytes)?;
        n += 1;
    }
    if n != CALLS {
        return Err(error(Cause::Capacity));
    }
    Ok(snapshots)
}
fn unchanged(bytes: &[u8], before: &[u8; 1024]) -> Result<(), BridgeError> {
    if input_copy(bytes)? != *before {
        return Err(error(Cause::Invariant));
    }
    Ok(())
}
fn totals(before: TreeTotals, after: TreeTotals, calls: usize) -> Result<(), BridgeError> {
    let roots = u64::try_from(calls).map_err(|_| error(Cause::Capacity))?;
    let nodes = roots.checked_mul(2).ok_or(error(Cause::Capacity))?;
    if calls > CALLS
        || before.roots.checked_add(roots) != Some(after.roots)
        || before.pairs.entries.checked_add(nodes) != Some(after.pairs.entries)
        || before.pairs.returns.checked_add(nodes) != Some(after.pairs.returns)
        || after
            .pairs
            .completed
            .checked_sub(before.pairs.completed)
            .and_then(|n| {
                after
                    .pairs
                    .unsampled
                    .checked_sub(before.pairs.unsampled)
                    .and_then(|m| n.checked_add(m))
            })
            != Some(nodes)
    {
        return Err(error(Cause::Outstanding));
    }
    Ok(())
}

/// Local original-only batch borrowing its actual retained loader and all inputs.
/// File/mapping provenance is checked at begin/finish; all 4096 source bytes and
/// the selected complete input are checked on every call. Transient forbidden
/// file/mapping changes may evade this schedule. No intermediate result certifies
/// final batch provenance. Drop/forget/unwind do not cancel or reopen the owner.
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::OriginalTreeSourceBatch;
/// fn send<T: Send>() {}
/// send::<OriginalTreeSourceBatch<'static>>();
/// ```
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::OriginalTreeSourceBatch;
/// fn sync<T: Sync>() {}
/// sync::<OriginalTreeSourceBatch<'static>>();
/// ```
pub struct OriginalTreeSourceBatch<'a> {
    prep: &'a mut TreeSitePreparation,
    requests: &'a [&'a [u8]; CALLS],
    inputs: [[u8; 1024]; CALLS],
    stack: &'a ReadableStack,
    proof: SourceProof,
    pid: u32,
    tid: u64,
    sequence: u64,
}
impl TreeSitePreparation {
    /// Admit exactly eight ordered inputs without reserving any invocation.
    ///
    /// # Safety
    /// All unsafe load and original-call contracts hold continuously through
    /// successful finish, including gaps between calls: same actual thread,
    /// retained readable RX source, immutable file/mappings/inputs, no alias writer,
    /// fork, publication, foreign entry, signal, unload, reentry or nonlocal exit;
    /// valid bounded writable stack and normal original CALL/RET. Boundary checks
    /// do not provide the old per-call file/mapping diagnostics for invalid clients.
    pub unsafe fn begin_original_source_batch<'a>(
        &'a mut self,
        requests: &'a [&'a [u8]; CALLS],
        stack: &'a ReadableStack,
    ) -> Result<OriginalTreeSourceBatch<'a>, TreeSourceBatchError> {
        self.batch.closed()?;
        let _scope = ControllerScope::enter()?;
        let actual = tid();
        if actual == 0 || actual > i32::MAX as u64 {
            return Err(GateError::Identity.into());
        }
        let sequence = self.gate().idle_checkpoint()?;
        sequence
            .checked_add(CALLS as u64)
            .ok_or(error(Cause::Capacity))?;
        let inputs = inputs(requests.iter().copied())?;
        let proof = self.original_source_proof()?;
        self.batch = Latch::Open(0);
        Ok(OriginalTreeSourceBatch {
            prep: self,
            requests,
            inputs,
            stack,
            proof,
            pid: std::process::id(),
            tid: actual,
            sequence,
        })
    }
}
impl OriginalTreeSourceBatch<'_> {
    fn checkpoint(&self, calls: usize) -> Result<(), TreeSourceBatchError> {
        if self.pid != std::process::id()
            || self.tid != tid()
            || self.sequence.checked_add(calls as u64) != Some(self.prep.gate().idle_checkpoint()?)
        {
            return Err(GateError::Identity.into());
        }
        Ok(())
    }
    /// Invoke the next admitted input through the unchanged real original gate.
    /// # Safety
    /// The complete begin contract has held continuously, including all gaps.
    pub unsafe fn invoke_next(&mut self) -> Result<OriginalTreeCallResult, TreeSourceBatchError> {
        let result = (|| {
            let n = self.prep.batch.start(false)?;
            {
                let _scope = ControllerScope::enter()?;
                self.checkpoint(n)?;
                unchanged(self.requests[n], &self.inputs[n])?;
                self.prep
                    .verify_source(SourceAuthority::Batch(&self.proof))?;
            }
            let call = unsafe {
                self.prep.invoke_original_batch(
                    self.requests[n],
                    self.stack,
                    self.pid,
                    self.tid,
                    &self.proof,
                )
            }?;
            Ok(call)
        })();
        match result {
            Ok(call) => {
                self.prep.batch.completed_call();
                Ok(call)
            }
            Err(e) => Err(self.prep.batch.fail(e)),
        }
    }
    /// Require all eight real returns and final full provenance before success.
    pub fn finish(self) -> Result<TreeSourceBatchVerification, TreeSourceBatchError> {
        let result = (|| {
            let n = self.prep.batch.start(true)?;
            let _scope = ControllerScope::enter()?;
            self.checkpoint(n)?;
            for (bytes, before) in self.requests.iter().zip(&self.inputs) {
                unchanged(bytes, before)?;
            }
            self.prep.verify_source(SourceAuthority::Full)?;
            Ok(TreeSourceBatchVerification { calls: n })
        })();
        match result {
            Ok(v) => {
                self.prep.batch = Latch::Closed;
                Ok(v)
            }
            Err(e) => Err(self.prep.batch.fail(e)),
        }
    }
}
impl Drop for OriginalTreeSourceBatch<'_> {
    fn drop(&mut self) {
        self.prep.batch.abandon();
    }
}

/// Local installed batch; each real entry still chooses and retains its own epoch.
/// Calls retain complete source/image/input and gate/model checks. Only file and
/// mapping provenance checks move to the two explicit boundaries. A remote Report
/// can contain completed model calls before finish; it is not batch verification.
/// Only successful finish permits the caller's subsequent drain/detach/legacy call.
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::TreeSourceBatch;
/// fn send<T: Send>() {}
/// send::<TreeSourceBatch<'static>>();
/// ```
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::TreeSourceBatch;
/// fn sync<T: Sync>() {}
/// sync::<TreeSourceBatch<'static>>();
/// ```
/// ```compile_fail,E0499
/// use rapid_profiler::frontend_native::{TreeThread, TreeSourceBatchRequest};
/// unsafe fn overlap(t: &mut TreeThread, r: &[TreeSourceBatchRequest<'_>; 8]) {
///     let batch = unsafe { t.begin_source_batch(r) }.unwrap();
///     let _ = t.drain_completed();
///     drop(batch);
/// }
/// ```
/// ```compile_fail,E0502
/// use rapid_profiler::frontend_native::{TreeThread, TreeSourceBatchRequest};
/// unsafe fn mutate(t: &mut TreeThread, bytes: &mut [u8]) {
///     let r = [TreeSourceBatchRequest { bytes, external_id: 1 }; 8];
///     let batch = unsafe { t.begin_source_batch(&r) }.unwrap();
///     bytes[0] ^= 1;
///     drop(batch);
/// }
/// ```
/// ```compile_fail,E0515
/// use rapid_profiler::frontend_native::{TreeThread, TreeSourceBatch, TreeSourceBatchRequest};
/// unsafe fn escape(t: &mut TreeThread) -> TreeSourceBatch<'_> {
///     let bytes = [0_u8; 1024];
///     let r = [TreeSourceBatchRequest { bytes: &bytes, external_id: 1 }; 8];
///     unsafe { t.begin_source_batch(&r) }.unwrap()
/// }
/// ```
pub struct TreeSourceBatch<'a> {
    thread: &'a mut TreeThread,
    requests: &'a [TreeSourceBatchRequest<'a>; CALLS],
    inputs: [[u8; 1024]; CALLS],
    proof: SourceProof,
    before: TreeTotals,
}
impl TreeThread {
    /// Admit exactly eight requests with existing remaining row/event capacity.
    /// No ID, gate sequence, epoch or model receipt is reserved at admission.
    ///
    /// # Safety
    /// All attach/prepared-call contracts hold continuously through finish,
    /// including gaps: same actual caller thread, retained source/generated RX
    /// mappings and owners, immutable file/input, valid bounded writable stack,
    /// no code publication/retirement, alias writer, fork, foreign entry, signal,
    /// reentry, nonlocal exit or unload. Controller epoch changes remain allowed;
    /// they confer no executable-retirement authority. Boundary provenance checks
    /// do not detect every transient invalid-client file/mapping change.
    pub unsafe fn begin_source_batch<'a>(
        &'a mut self,
        requests: &'a [TreeSourceBatchRequest<'a>; CALLS],
    ) -> Result<TreeSourceBatch<'a>, TreeSourceBatchError> {
        self.batch.closed()?;
        let _scope = ControllerScope::enter()?;
        let before = self.checkpoint_totals()?;
        let inputs = inputs(requests.iter().map(|r| r.bytes))?;
        let ids = requests.map(|r| r.external_id);
        TREE_STATE
            .try_with(|cell| {
                let s = cell.try_borrow().map_err(|_| error(Cause::Attachment))?;
                let state = s.as_ref().ok_or(error(Cause::Attachment))?;
                if !self.matches(state) {
                    return Err(error(Cause::Attachment));
                }
                state.check_source_batch(&ids)
            })
            .unwrap_or(Err(error(Cause::Attachment)))?;
        let proof = self.live.source_proof()?;
        self.batch = Latch::Open(0);
        Ok(TreeSourceBatch {
            thread: self,
            requests,
            inputs,
            proof,
            before,
        })
    }
}
impl TreeSourceBatch<'_> {
    /// Copy actual lifetime counters between successful calls of this batch.
    ///
    /// Accepts only an open guard with zero through eight completed calls. The
    /// actual thread, healthy empty TLS, last successful return and idle gate
    /// are authenticated, then the same cumulative batch delta is checked.
    /// Repeated observations preserve the completed-call count and consume no
    /// invocation, ID, sequence, row or owner. Callers may compare the returned
    /// sampled/unsampled partition with their own exact K policy.
    ///
    /// This does not revalidate source/input provenance, finish the batch, grant
    /// drain/retirement authority or return an owner/reference. Explicit finish
    /// remains required after exactly eight calls. Errors retain the first cause;
    /// an unwind during observation leaves the owner busy and cannot reopen it.
    pub fn totals(&mut self) -> Result<TreeTotals, TreeSourceBatchError> {
        let result = (|| {
            let n = self.thread.batch.begin_observation()?;
            let _scope = ControllerScope::enter()?;
            let actual = self.thread.checkpoint_totals()?;
            totals(self.before, actual, n)?;
            self.thread.batch.complete_observation(n)?;
            Ok(actual)
        })();
        match result {
            Ok(actual) => Ok(actual),
            Err(e) => Err(self.thread.batch.fail(e)),
        }
    }
    /// Invoke exactly the next input/ID; per-call real receipt completion remains.
    /// # Safety
    /// The complete begin contract has held continuously, including all gaps.
    pub unsafe fn invoke_next(&mut self) -> Result<TreeCallResult, TreeSourceBatchError> {
        let result = (|| {
            let n = self.thread.batch.start(false)?;
            let request = self.requests[n];
            let before;
            let input;
            {
                let _scope = ControllerScope::enter()?;
                input = input_copy(request.bytes)?;
                unchanged(request.bytes, &self.inputs[n])?;
                before = self.thread.checkpoint_totals()?;
                totals(self.before, before, n)?;
                self.thread.live.verify_source_proof(&self.proof)?;
            }
            // The same final prepared checkpoint and reservation/return path.
            prepared::checkpoint(
                request.bytes,
                &input,
                self.thread.checkpoint_totals()?,
                before,
            )?;
            let call = unsafe {
                self.thread.invoke_prepared(
                    request.bytes,
                    input,
                    request.external_id,
                    before,
                    SourceAuthority::Batch(&self.proof),
                )
            }?;
            Ok(call)
        })();
        match result {
            Ok(call) => {
                self.thread.batch.completed_call();
                Ok(call)
            }
            Err(e) => Err(self.thread.batch.fail(e)),
        }
    }
    /// Full final provenance plus exact cumulative deltas; never repairs a call.
    pub fn finish(self) -> Result<TreeSourceBatchVerification, TreeSourceBatchError> {
        let result = (|| {
            let n = self.thread.batch.start(true)?;
            let _scope = ControllerScope::enter()?;
            totals(self.before, self.thread.checkpoint_totals()?, n)?;
            for (r, before) in self.requests.iter().zip(&self.inputs) {
                unchanged(r.bytes, before)?;
            }
            self.thread.live.verify()?;
            Ok(TreeSourceBatchVerification { calls: n })
        })();
        match result {
            Ok(v) => {
                self.thread.batch = Latch::Closed;
                Ok(v)
            }
            Err(e) => Err(self.thread.batch.fail(e)),
        }
    }
}
impl Drop for TreeSourceBatch<'_> {
    fn drop(&mut self) {
        self.thread.batch.abandon();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[repr(align(64))]
    struct Aligned([u8; 1024]);

    #[test]
    fn source_batch_latch_requires_exact_count_and_cannot_reenter_busy() {
        let mut latch = Latch::Closed;
        assert!(latch.closed().is_ok());
        assert!(latch.start(false).is_err());
        latch = Latch::Open(0);
        for n in 0..CALLS {
            assert!(latch.closed().is_err());
            assert!(matches!(
                latch.start(true),
                Err(TreeSourceBatchError::CallCount)
            ));
            assert_eq!(latch.start(false).unwrap(), n);
            assert!(matches!(
                latch.start(false),
                Err(TreeSourceBatchError::Unfinished)
            ));
            assert!(matches!(
                latch.start(true),
                Err(TreeSourceBatchError::Unfinished)
            ));
            latch.completed_call();
        }
        assert!(matches!(
            latch.start(false),
            Err(TreeSourceBatchError::CallCount)
        ));
        assert_eq!(latch.start(true).unwrap(), CALLS);
        assert!(latch.closed().is_err()); // only full finish may close it
        latch.abandon();
        assert!(matches!(
            latch.closed(),
            Err(TreeSourceBatchError::Abandoned)
        ));
        for n in [CALLS + 1, usize::MAX] {
            let mut corrupt = Latch::Open(n);
            assert!(matches!(
                corrupt.start(false),
                Err(TreeSourceBatchError::CallCount)
            ));
            assert!(matches!(
                corrupt.start(true),
                Err(TreeSourceBatchError::CallCount)
            ));
        }
    }
    #[test]
    fn source_batch_first_failure_retains_exact_error_across_abandonment() {
        let first = Rc::new(TreeError::Gate(GateError::Completion));
        let mut latch = Latch::Open(0);
        let _ = latch.fail(TreeSourceBatchError::Call(Rc::clone(&first)));
        for replacement in [
            TreeSourceBatchError::CallCount,
            TreeSourceBatchError::Abandoned,
        ] {
            let TreeSourceBatchError::Call(actual) = latch.fail(replacement) else {
                panic!("lost first failure");
            };
            assert!(Rc::ptr_eq(&first, &actual));
            latch.abandon();
            let Err(TreeSourceBatchError::Call(actual)) = latch.closed() else {
                panic!("reopened");
            };
            assert!(Rc::ptr_eq(&first, &actual));
        }
    }
    #[test]
    fn source_batch_caught_unwind_leaves_owner_busy_until_abandoned() {
        let mut latch = Latch::Open(3);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_eq!(latch.start(false).unwrap(), 3);
                panic!("scripted verifier unwind");
            }))
            .is_err()
        );
        assert!(latch.closed().is_err());
        assert!(latch.start(false).is_err());
        assert!(latch.start(true).is_err());
        latch.abandon();
        assert!(matches!(
            latch.closed(),
            Err(TreeSourceBatchError::Abandoned)
        ));
    }
    #[test]
    fn source_batch_input_snapshots_reject_every_changed_byte_extent_and_alignment() {
        let mut input = Aligned(std::array::from_fn(|i| i as u8));
        let snapshots = inputs([&input.0[..]; CALLS]).unwrap();
        for i in 0..1024 {
            input.0[i] ^= 1;
            for before in &snapshots {
                assert_eq!(unchanged(&input.0, before), Err(error(Cause::Invariant)));
            }
            input.0[i] ^= 1;
        }
        assert!(inputs([&input.0[..]; CALLS - 1]).is_err());
        assert!(inputs([&input.0[..]; CALLS + 1]).is_err());
        assert!(inputs([&input.0[..1023]; CALLS]).is_err());
        #[repr(align(64))]
        struct Larger([u8; 1088]);
        let larger = Larger([0; 1088]);
        let unaligned = &larger.0[1..1025];
        assert_eq!(unaligned.len(), 1024);
        assert!(input_copy(unaligned).is_err());
        for before in &snapshots {
            assert_eq!(unchanged(&input.0, before), Ok(()));
        }
    }
    #[test]
    fn source_batch_cumulative_delta_preserves_sampled_and_closed_partitions() {
        let before = TreeTotals {
            roots: 13,
            pairs: PairTotals {
                entries: 26,
                returns: 26,
                completed: 10,
                unsampled: 16,
            },
        };
        for calls in 0..=CALLS {
            for sampled in 0..=2 * calls {
                let after = TreeTotals {
                    roots: before.roots + calls as u64,
                    pairs: PairTotals {
                        entries: 26 + 2 * calls as u64,
                        returns: 26 + 2 * calls as u64,
                        completed: 10 + sampled as u64,
                        unsampled: 16 + (2 * calls - sampled) as u64,
                    },
                };
                assert_eq!(totals(before, after, calls), Ok(()));
                for field in 0..5 {
                    let mut changed = after;
                    match field {
                        0 => changed.roots += 1,
                        1 => changed.pairs.entries += 1,
                        2 => changed.pairs.returns += 1,
                        3 => changed.pairs.completed += 1,
                        4 => changed.pairs.unsampled += 1,
                        _ => unreachable!(),
                    }
                    assert_eq!(
                        totals(before, changed, calls),
                        Err(error(Cause::Outstanding))
                    );
                }
            }
        }
        let mut overflow = before;
        overflow.roots = u64::MAX;
        assert!(totals(overflow, before, 1).is_err());
        assert!(totals(before, before, CALLS + 1).is_err());
    }

    #[test]
    fn source_batch_observation_preserves_every_count_and_call_finish_threshold() {
        for n in 0..=CALLS {
            let mut latch = Latch::Open(n);
            for _ in 0..3 {
                assert_eq!(latch.begin_observation().unwrap(), n);
                assert!(matches!(latch, Latch::Busy(actual) if actual == n));
                assert!(latch.closed().is_err());
                assert!(matches!(
                    latch.start(false),
                    Err(TreeSourceBatchError::Unfinished)
                ));
                assert!(matches!(
                    latch.start(true),
                    Err(TreeSourceBatchError::Unfinished)
                ));
                assert!(matches!(
                    latch.begin_observation(),
                    Err(TreeSourceBatchError::Unfinished)
                ));
                latch.complete_observation(n).unwrap();
                assert!(matches!(latch, Latch::Open(actual) if actual == n));
                assert!(latch.closed().is_err()); // an observation is never finish
            }
            if n < CALLS {
                assert!(matches!(
                    latch.start(true),
                    Err(TreeSourceBatchError::CallCount)
                ));
                assert_eq!(latch.start(false).unwrap(), n);
                latch.completed_call();
                assert!(matches!(latch, Latch::Open(actual) if actual == n + 1));
            } else {
                assert!(matches!(
                    latch.start(false),
                    Err(TreeSourceBatchError::CallCount)
                ));
                assert_eq!(latch.start(true).unwrap(), CALLS);
                assert!(matches!(latch, Latch::Busy(CALLS)));
            }
        }
    }

    #[test]
    fn source_batch_observation_refuses_closed_busy_and_invalid_counts() {
        let mut closed = Latch::Closed;
        assert!(matches!(
            closed.begin_observation(),
            Err(TreeSourceBatchError::Unfinished)
        ));
        assert!(matches!(closed, Latch::Closed));
        for n in [0, 1, CALLS, CALLS + 1, usize::MAX] {
            let mut busy = Latch::Busy(n);
            assert!(matches!(
                busy.begin_observation(),
                Err(TreeSourceBatchError::Unfinished)
            ));
            assert!(matches!(busy, Latch::Busy(actual) if actual == n));
        }
        for n in [CALLS + 1, usize::MAX] {
            let mut invalid = Latch::Open(n);
            let error = invalid.begin_observation().unwrap_err();
            assert!(matches!(error, TreeSourceBatchError::CallCount));
            assert!(matches!(invalid, Latch::Open(actual) if actual == n));
            let _ = invalid.fail(error); // same error path as the public accessor
            assert!(matches!(
                invalid.begin_observation(),
                Err(TreeSourceBatchError::CallCount)
            ));
            assert!(matches!(
                invalid,
                Latch::Failed(TreeSourceBatchError::CallCount)
            ));
        }
    }

    #[test]
    fn source_batch_observation_completion_requires_the_same_busy_count() {
        for n in 0..=CALLS {
            let mut latch = Latch::Open(n);
            let expected = latch.begin_observation().unwrap();
            for wrong in [n + 1, CALLS + 1, usize::MAX] {
                assert!(matches!(
                    latch.complete_observation(wrong),
                    Err(TreeSourceBatchError::Unfinished)
                ));
                assert!(matches!(latch, Latch::Busy(actual) if actual == n));
            }
            latch.complete_observation(expected).unwrap();
            assert!(matches!(
                latch.complete_observation(expected),
                Err(TreeSourceBatchError::Unfinished)
            ));
            assert!(matches!(latch, Latch::Open(actual) if actual == n));
        }
        let mut closed = Latch::Closed;
        assert!(matches!(
            closed.complete_observation(0),
            Err(TreeSourceBatchError::Unfinished)
        ));
        assert!(matches!(closed, Latch::Closed));
        let mut invalid = Latch::Busy(CALLS + 1);
        assert!(matches!(
            invalid.complete_observation(CALLS + 1),
            Err(TreeSourceBatchError::Unfinished)
        ));
        assert!(matches!(invalid, Latch::Busy(n) if n == CALLS + 1));
    }

    #[test]
    fn source_batch_observation_retains_first_error_through_repeat_and_drop() {
        let first = Rc::new(TreeError::Gate(GateError::Completion));
        let mut latch = Latch::Open(3);
        assert_eq!(latch.begin_observation().unwrap(), 3);
        let TreeSourceBatchError::Call(actual) =
            latch.fail(TreeSourceBatchError::Call(Rc::clone(&first)))
        else {
            panic!("first error not retained");
        };
        assert!(Rc::ptr_eq(&actual, &first));
        for _ in 0..3 {
            let Err(TreeSourceBatchError::Call(actual)) = latch.begin_observation() else {
                panic!("failed owner reopened");
            };
            assert!(Rc::ptr_eq(&actual, &first));
            let Err(TreeSourceBatchError::Call(actual)) = latch.complete_observation(3) else {
                panic!("observation completed after failure");
            };
            assert!(Rc::ptr_eq(&actual, &first));
            let TreeSourceBatchError::Call(actual) = latch.fail(TreeSourceBatchError::Unfinished)
            else {
                panic!("replacement erased first cause");
            };
            assert!(Rc::ptr_eq(&actual, &first));
            latch.abandon();
            let Err(TreeSourceBatchError::Call(actual)) = latch.closed() else {
                panic!("drop erased first cause");
            };
            assert!(Rc::ptr_eq(&actual, &first));
        }
    }

    #[test]
    fn source_batch_observation_caught_unwind_never_reopens_owner() {
        for n in 0..=CALLS {
            let mut latch = Latch::Open(n);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    assert_eq!(latch.begin_observation().unwrap(), n);
                    panic!("scripted observation check unwind");
                }))
                .is_err()
            );
            assert!(matches!(latch, Latch::Busy(actual) if actual == n));
            assert!(latch.closed().is_err());
            assert!(latch.start(false).is_err());
            assert!(latch.start(true).is_err());
            assert!(matches!(
                latch.begin_observation(),
                Err(TreeSourceBatchError::Unfinished)
            ));
            latch.abandon();
            assert!(matches!(
                latch.begin_observation(),
                Err(TreeSourceBatchError::Abandoned)
            ));
            assert!(matches!(
                latch.complete_observation(n),
                Err(TreeSourceBatchError::Abandoned)
            ));
            assert!(latch.closed().is_err());
        }
    }
}
