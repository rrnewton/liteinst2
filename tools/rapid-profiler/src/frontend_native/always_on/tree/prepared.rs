//! Exclusive preflight checkpoint; no receipt, gate reservation or callback token.
use super::*;

/// One local installed-tree invocation after full source/input preflight.
/// Holds the thread's exclusive borrow and the input's immutable borrow. This
/// value has no Drop action and owns no active model or gate reservation.
///
/// It cannot be transferred or shared across actual caller threads:
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::PreparedTreeCall;
/// fn send<T: Send>() {}
/// send::<PreparedTreeCall<'static>>();
/// ```
/// ```compile_fail,E0277
/// use rapid_profiler::frontend_native::PreparedTreeCall;
/// fn sync<T: Sync>() {}
/// sync::<PreparedTreeCall<'static>>();
/// ```
/// The attachment cannot be used while its prepared call remains live:
/// ```compile_fail,E0502
/// use rapid_profiler::frontend_native::TreeThread;
/// unsafe fn overlapping(thread: &mut TreeThread, bytes: &[u8]) {
///     let call = unsafe { thread.prepare_tree_call(bytes, 1) }.unwrap();
///     let _ = thread.totals();
///     drop(call);
/// }
/// ```
/// The input cannot be mutably borrowed while the guard retains it:
/// ```compile_fail,E0502
/// use rapid_profiler::frontend_native::TreeThread;
/// unsafe fn mutate(thread: &mut TreeThread, bytes: &mut [u8]) {
///     let call = unsafe { thread.prepare_tree_call(bytes, 1) }.unwrap();
///     let _other = &mut bytes[0];
///     drop(call);
/// }
/// ```
/// The consumed guard cannot issue a second invocation:
/// ```compile_fail,E0382
/// use rapid_profiler::frontend_native::PreparedTreeCall;
/// unsafe fn twice(call: PreparedTreeCall<'_>) {
///     let _ = unsafe { call.invoke() };
///     let _ = unsafe { call.invoke() };
/// }
/// ```
/// It cannot outlive the input whose full snapshot it retains:
/// ```compile_fail,E0515
/// use rapid_profiler::frontend_native::{PreparedTreeCall, TreeThread};
/// unsafe fn escape(thread: &mut TreeThread) -> PreparedTreeCall<'_> {
///     let bytes = [0_u8; 1024];
///     unsafe { thread.prepare_tree_call(&bytes, 1) }.unwrap()
/// }
/// ```
/// Dropping an unused guard releases both borrows. This example is compile-only;
/// it is not credited as a runtime guard-drop or native-call control:
/// ```no_run
/// use rapid_profiler::frontend_native::{TreeError, TreeThread, TreeTotals};
/// unsafe fn unused(thread: &mut TreeThread, bytes: &[u8]) -> Result<TreeTotals, TreeError> {
///     let before = thread.totals()?;
///     let call = unsafe { thread.prepare_tree_call(bytes, 1) }?;
///     drop(call);
///     let after = thread.totals()?;
///     assert_eq!(before, after);
///     Ok(after)
/// }
/// ```
pub struct PreparedTreeCall<'call> {
    pub(super) thread: &'call mut TreeThread,
    pub(super) bytes: &'call [u8],
    pub(super) external_id: u64,
    pub(super) input: [u8; 1024],
    pub(super) before: TreeTotals,
    pub(super) _local: PhantomData<Rc<()>>,
}

// Rechecked at consumption before any active invocation or ID is published.
pub(super) fn checkpoint(
    bytes: &[u8],
    input: &[u8; 1024],
    current: TreeTotals,
    before: TreeTotals,
) -> Result<(), BridgeError> {
    if bytes != input {
        return Err(error(Cause::Invariant));
    }
    if current != before {
        return Err(error(Cause::Outstanding));
    }
    Ok(())
}

impl PreparedTreeCall<'_> {
    /// Consume this guard for the real installed CALL/RET and complete postflight.
    /// The current epoch is selected by the real entry callback, not preparation.
    ///
    /// # Safety
    /// All preparation contracts have remained true without interruption;
    /// same actual caller thread, normal returns and no handler, source/input
    /// writer, foreign entry, reentry, unload or fork. A controlled stop grants
    /// no exception to these obligations. No raw subject pointer escapes.
    pub unsafe fn invoke(self) -> Result<TreeCallResult, TreeError> {
        let Self {
            thread,
            bytes,
            external_id,
            input,
            before,
            _local: _,
        } = self;
        // totals() repeats actual process/thread identity, empty healthy TLS,
        // successful-invoke checkpoint and canonical gate-idle authentication.
        checkpoint(bytes, &input, thread.totals()?, before)?;
        // Stack/sequence/capacity/external-ID validation and begin remain inside
        // this private path immediately before the real CALL. Postflight is exact.
        unsafe {
            thread.invoke_prepared(
                bytes,
                input,
                external_id,
                before,
                batch::SourceAuthority::Full,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn totals() -> TreeTotals {
        TreeTotals {
            roots: 2,
            pairs: PairTotals {
                entries: 4,
                returns: 4,
                completed: 3,
                unsampled: 1,
            },
        }
    }
    #[test]
    fn prepared_checkpoint_refuses_each_changed_input_byte_and_extent() {
        // Pure checkpoint bytes, not a fabricated loaded/native input or receipt.
        let input: [u8; 1024] = std::array::from_fn(|i| i as u8);
        let before = totals();
        assert_eq!(checkpoint(&input, &input, before, before), Ok(()));
        for i in 0..1024 {
            let mut changed = input;
            changed[i] ^= 1;
            assert_eq!(
                checkpoint(&changed, &input, before, before),
                Err(error(Cause::Invariant))
            );
        }
        for changed in [&input[..0], &input[..1023], &[0_u8; 1025][..]] {
            assert_eq!(
                checkpoint(changed, &input, before, before),
                Err(error(Cause::Invariant))
            );
        }
        assert_eq!(checkpoint(&input, &input, before, before), Ok(()));
    }
    #[test]
    fn prepared_checkpoint_refuses_each_changed_lifetime_counter() {
        let input = [0_u8; 1024];
        let before = totals();
        assert_eq!(checkpoint(&input, &input, before, before), Ok(()));
        for field in 0..5 {
            let mut changed = before;
            match field {
                0 => changed.roots += 1,
                1 => changed.pairs.entries += 1,
                2 => changed.pairs.returns += 1,
                3 => changed.pairs.completed += 1,
                4 => changed.pairs.unsampled += 1,
                _ => unreachable!(),
            }
            assert_eq!(
                checkpoint(&input, &input, changed, before),
                Err(error(Cause::Outstanding))
            );
        }
        assert_eq!(checkpoint(&input, &input, before, before), Ok(()));
    }
}
