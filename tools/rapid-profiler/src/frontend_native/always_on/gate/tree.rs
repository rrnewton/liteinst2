//! Separate closed-tree gate; the Legacy Frame and CALL bytes remain unchanged.
use super::*;
use crate::frontend_native::TreeRootCertificate;
use std::marker::PhantomData;
use std::rc::Rc;

// A root RET observation is not a model completion or a physical return.
const TREE_RETURN_OBSERVED: u64 = 5;

/// Immutable geometry for the separately certified two-function tree.
pub struct TreeCallGate {
    target: u64,
    returns: [u64; 1],
    pid: u32,
}
/// Actual original-only return; no child callback/RET evidence is fabricated.
pub type OriginalTreeCallResult = OriginalCallResult;
/// Actual outer return joined to one completed tree after source postflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeCallResult {
    pub external_id: u64,
    pub gate_sequence: u64,
    pub value: u64,
    pub pre_call_rsp: u64,
    pub entry_rsp: u64,
    pub resumed_rsp: u64,
    pub return_pc: u64,
}

fn tree_resumed(
    frame: Frame,
    id: Identity,
    value: u64,
    returns: &[u64],
) -> Result<CallResult, GateError> {
    same(frame, id, TREE_RETURN_OBSERVED)?;
    stack_word(frame, frame.entry_rsp)?;
    if frame.resumed_rsp != frame.pre_call_rsp
        || frame.return_word != id.continuation
        || returns != [frame.return_pc]
    {
        return Err(GateError::Completion);
    }
    Ok(CallResult {
        value,
        pre_call_rsp: frame.pre_call_rsp,
        entry_rsp: frame.entry_rsp,
        resumed_rsp: frame.resumed_rsp,
        return_pc: frame.return_pc,
    })
}

struct Flight {
    raw: *mut Frame,
    finished: bool,
    _local: PhantomData<Rc<()>>,
}
impl Drop for Flight {
    fn drop(&mut self) {
        if !self.finished {
            // SAFETY: private actual-thread slot; no Rust reference spans CALL.
            unsafe {
                (*self.raw).phase = POISONED;
            }
        }
    }
}
pub(in crate::frontend_native::always_on) struct Pending<'a, T> {
    gate: &'a TreeCallGate,
    identity: Identity,
    snapshot: Frame,
    result: T,
    flight: Flight,
}
pub(in crate::frontend_native::always_on) struct Ready<T> {
    snapshot: Frame,
    result: T,
    flight: Flight,
}
impl<T> Pending<'_, T> {
    pub(in crate::frontend_native::always_on) fn result(&self) -> &T {
        &self.result
    }
    // Must precede owner consumption. No user code runs between this and commit.
    pub(in crate::frontend_native::always_on) fn validate(self) -> Result<Ready<T>, GateError> {
        if self.gate.identity()? != self.identity
            || unsafe { self.flight.raw.read() } != self.snapshot
        {
            return Err(GateError::Identity);
        }
        Ok(Ready {
            snapshot: self.snapshot,
            result: self.result,
            flight: self.flight,
        })
    }
}
impl<T> Ready<T> {
    pub(in crate::frontend_native::always_on) fn commit(mut self) -> T {
        // Infallible local publication after all model and source postconditions.
        unsafe {
            self.flight.raw.write(Frame {
                sequence: self.snapshot.sequence,
                ..Frame::default()
            });
        }
        self.flight.finished = true;
        self.result
    }
}

impl TreeCallGate {
    pub fn new(certificate: &TreeRootCertificate) -> Result<Arc<Self>, GateError> {
        let entry = certificate.entry();
        if entry == 0
            || entry.checked_add(23) != Some(certificate.range().1)
            || certificate.range().0 != entry
            || certificate.returns() != [entry.checked_add(22).ok_or(GateError::Descriptor)?]
            || certificate.call().call_pc() != entry + 9
            || certificate.call().continuation() != entry + 14
            || certificate.call().callee_entry()
                != entry.checked_add(32).ok_or(GateError::Descriptor)?
            || certificate.child_stack_delta() != 16
        {
            return Err(GateError::Descriptor);
        }
        Ok(Arc::new(Self {
            target: entry,
            returns: [entry + 22],
            pid: std::process::id(),
        }))
    }
    pub fn target(&self) -> u64 {
        self.target
    }
    pub fn continuation(&self) -> u64 {
        core::ptr::addr_of!(__rapid_profiler_ordinary_after_call_v1) as usize as u64
    }
    pub fn declared_returns(&self) -> &[u64] {
        &self.returns
    }
    pub(crate) fn process_matches(&self) -> bool {
        self.pid == std::process::id()
    }
    fn identity(&self) -> Result<Identity, GateError> {
        let tid = thread_id();
        if !self.process_matches() {
            return Err(GateError::Process);
        }
        if tid == 0 || tid > i32::MAX as u64 {
            return Err(GateError::Identity);
        }
        Ok(Identity {
            gate: core::ptr::from_ref(self) as usize as u64,
            pid: u64::from(self.pid),
            tid,
            target: self.target,
            continuation: self.continuation(),
        })
    }
    pub(in crate::frontend_native::always_on) fn idle_checkpoint(&self) -> Result<u64, GateError> {
        self.identity()?;
        FRAME
            .try_with(|cell| idle(unsafe { cell.get().read() }))
            .map_err(|_| GateError::ThreadStorage)?
    }
    pub(in crate::frontend_native::always_on) fn enter(
        &self,
        context: &HookContext,
    ) -> Result<GateEntry, GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let mut frame = unsafe { cell.get().read() };
                same(frame, id, ARMED)?;
                stack_word(frame, context.stack_pointer)?;
                let word =
                    unsafe { (context.stack_pointer as usize as *const u64).read_unaligned() };
                let token = entry(
                    &mut frame,
                    id,
                    context.instruction_pointer,
                    context.stack_pointer,
                    word,
                )?;
                unsafe {
                    cell.get().write(frame);
                }
                Ok(token)
            })
            .map_err(|_| GateError::ThreadStorage)?
    }
    pub(in crate::frontend_native::always_on) fn observe_return(
        &self,
        token: &GateEntry,
        context: &HookContext,
    ) -> Result<(), GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let mut frame = unsafe { cell.get().read() };
                stack_word(frame, context.stack_pointer)?;
                let word =
                    unsafe { (context.stack_pointer as usize as *const u64).read_unaligned() };
                returning(
                    frame,
                    id,
                    token,
                    context.instruction_pointer,
                    context.stack_pointer,
                    word,
                    &self.returns,
                )?;
                frame.return_pc = context.instruction_pointer;
                frame.phase = TREE_RETURN_OBSERVED;
                unsafe {
                    cell.get().write(frame);
                }
                Ok(())
            })
            .map_err(|_| GateError::ThreadStorage)?
    }
    /// # Safety
    /// Only the sealed tree facade may call; both functions, all five controls,
    /// writable callback stack, input and no-reentry/normal-return contract hold.
    pub(in crate::frontend_native::always_on) unsafe fn invoke(
        &self,
        bytes: &[u8],
        stack: &ReadableStack,
        external_id: u64,
    ) -> Result<Pending<'_, TreeCallResult>, GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let raw = cell.get();
                let armed = arm(unsafe { raw.read() }, id, stack.start, stack.end)?;
                unsafe {
                    raw.write(armed);
                }
                let flight = Flight {
                    raw,
                    finished: false,
                    _local: PhantomData,
                };
                let value =
                    unsafe { __rapid_profiler_ordinary_call_v1(raw, bytes.as_ptr(), bytes.len()) };
                let snapshot = unsafe { raw.read() };
                let call = tree_resumed(snapshot, self.identity()?, value, &self.returns)?;
                let result = TreeCallResult {
                    external_id,
                    gate_sequence: snapshot.sequence,
                    value: call.value,
                    pre_call_rsp: call.pre_call_rsp,
                    entry_rsp: call.entry_rsp,
                    resumed_rsp: call.resumed_rsp,
                    return_pc: call.return_pc,
                };
                Ok(Pending {
                    gate: self,
                    identity: id,
                    snapshot,
                    result,
                    flight,
                })
            })
            .map_err(|_| GateError::ThreadStorage)?
    }
    /// # Safety
    /// Exclusive original wrapper owns complete source checks, no publication,
    /// and the same input/stack/normal-return/no-reentry obligations.
    pub(in crate::frontend_native::always_on) unsafe fn invoke_original(
        &self,
        bytes: &[u8],
        stack: &ReadableStack,
    ) -> Result<Pending<'_, OriginalTreeCallResult>, GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let raw = cell.get();
                unsafe {
                    raw.write(arm(raw.read(), id, stack.start, stack.end)?);
                }
                let flight = Flight {
                    raw,
                    finished: false,
                    _local: PhantomData,
                };
                let value =
                    unsafe { __rapid_profiler_ordinary_call_v1(raw, bytes.as_ptr(), bytes.len()) };
                let snapshot = unsafe { raw.read() };
                let result = original_resumed(snapshot, self.identity()?, value)?;
                Ok(Pending {
                    gate: self,
                    identity: id,
                    snapshot,
                    result,
                    flight,
                })
            })
            .map_err(|_| GateError::ThreadStorage)?
    }
}

// Pure metadata fixtures: no live FRAME write, assembly CALL or native credit.
#[cfg(test)]
impl TreeCallGate {
    pub(in crate::frontend_native::always_on) fn metadata_descriptor() -> Arc<Self> {
        Arc::new(Self {
            target: 0x1000,
            returns: [0x1016],
            pid: std::process::id(),
        })
    }
    pub(in crate::frontend_native::always_on) fn metadata_entry(
        &self,
        sequence: u64,
        rsp: u64,
    ) -> GateEntry {
        let id = self.identity().unwrap();
        let mut frame = arm(
            Frame {
                sequence: sequence - 1,
                ..Frame::default()
            },
            id,
            0x7000,
            0x9000,
        )
        .unwrap();
        frame.pre_call_rsp = rsp + 8;
        frame.observed_target = self.target;
        entry(&mut frame, id, self.target, rsp, self.continuation()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tree_return_observation_is_not_leaf_completion_or_resumption() {
        let id = Identity {
            gate: 1,
            pid: 2,
            tid: 3,
            target: 0x1000,
            continuation: 0x2000,
        };
        let f = Frame {
            phase: TREE_RETURN_OBSERVED,
            sequence: 7,
            gate: 1,
            pid: 2,
            tid: 3,
            target: 0x1000,
            observed_target: 0x1000,
            pre_call_rsp: 0x4010,
            resumed_rsp: 0x4010,
            stack_start: 0x3000,
            stack_end: 0x5000,
            entry_rsp: 0x4008,
            return_word: 0x2000,
            return_pc: 0x1016,
        };
        assert_eq!(tree_resumed(f, id, 9, &[0x1016]).unwrap().value, 9);
        assert!(resumed(f, id, 9, &[0x1016]).is_err());
        for phase in [IDLE, ARMED, ENTERED, COMPLETED, POISONED] {
            assert!(tree_resumed(Frame { phase, ..f }, id, 9, &[0x1016]).is_err());
        }
        for broken in [
            Frame {
                resumed_rsp: 0,
                ..f
            },
            Frame {
                return_word: 0x2008,
                ..f
            },
            Frame {
                entry_rsp: 0x4018,
                ..f
            },
            Frame {
                return_pc: 0x1020,
                ..f
            },
            Frame { gate: 9, ..f },
        ] {
            assert!(tree_resumed(broken, id, 9, &[0x1016]).is_err());
        }
    }
}
