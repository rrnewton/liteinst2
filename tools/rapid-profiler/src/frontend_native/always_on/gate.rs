//! Separate ordinary SysV CALL/RET gate; fixed-profile callers are unchanged.
//!
//! The descriptor is immutable and shareable. Invocation storage is private to
//! the actual thread. No Rust reference to that storage spans the assembly CALL
//! or a callback, and no application return word is ever written by this module.

use super::ReadableStack;
use crate::frontend_native::IntegerLeafCertificate;
use liteinst2::trampoline::HookContext;
use std::cell::UnsafeCell;
use std::sync::Arc;

const IDLE: u64 = 0;
const ARMED: u64 = 1;
const ENTERED: u64 = 2;
const COMPLETED: u64 = 3;
const POISONED: u64 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Exact gate refusal; a failed invocation is never credited as a completed pair.
pub enum GateError {
    /// The supplied immutable source certificate has invalid geometry.
    Descriptor,
    /// The descriptor belongs to a different process.
    Process,
    /// Actual-thread storage is unavailable.
    ThreadStorage,
    /// An invocation or retained failure already owns this thread's gate slot.
    Reentry,
    /// The per-thread invocation sequence cannot advance without wrapping.
    Sequence,
    /// Exact gate, process, thread, target or phase identity differs.
    Identity,
    /// The stack extent, CALL alignment or eight-byte return slot differs.
    Stack,
    /// Entry, original RET, continuation or retained pair identity differs.
    Return,
    /// A real resumed call lacks its exact completed pair or stack observation.
    Completion,
}

/// Immutable call geometry, not a publication receipt or ownership of the DSO.
/// The site factory must retain its source, publication and every mandatory
/// entry/RET control separately. Sharing this descriptor shares no mutable state.
pub struct CallGate {
    target: u64,
    returns: Box<[u64]>,
    pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Frame {
    phase: u64,
    sequence: u64,
    gate: u64,
    pid: u64,
    tid: u64,
    target: u64,
    observed_target: u64,
    pre_call_rsp: u64,
    resumed_rsp: u64,
    stack_start: u64,
    stack_end: u64,
    entry_rsp: u64,
    return_word: u64,
    return_pc: u64,
}

thread_local! {
    // Copy-only, no destructor or reference-bearing fields. All accesses use raw
    // reads/writes through get(); a copied Frame is never an alias of this cell.
    static FRAME: UnsafeCell<Frame> = const { UnsafeCell::new(Frame {
        phase: IDLE, sequence: 0, gate: 0, pid: 0, tid: 0, target: 0,
        observed_target: 0, pre_call_rsp: 0, resumed_rsp: 0,
        stack_start: 0, stack_end: 0, entry_rsp: 0, return_word: 0, return_pc: 0,
    }) };
}

core::arch::global_asm!(
    r#"
    .pushsection .text.rapid_profiler_ordinary_call,"ax",@progbits
    .p2align 4
    .global __rapid_profiler_ordinary_call_v1
    .hidden __rapid_profiler_ordinary_call_v1
    .type __rapid_profiler_ordinary_call_v1,@function
__rapid_profiler_ordinary_call_v1:
    push rbx
    mov rbx, rdi
    mov rdi, rsi
    mov rsi, rdx
    mov r11, [rbx + {target}]
    mov [rbx + {observed_target}], r11
    mov [rbx + {pre_call_rsp}], rsp
    call r11
    .global __rapid_profiler_ordinary_after_call_v1
    .hidden __rapid_profiler_ordinary_after_call_v1
__rapid_profiler_ordinary_after_call_v1:
    mov [rbx + {resumed_rsp}], rsp
    pop rbx
    ret
    .size __rapid_profiler_ordinary_call_v1, .-__rapid_profiler_ordinary_call_v1
    .popsection
"#,
    target = const core::mem::offset_of!(Frame, target),
    observed_target = const core::mem::offset_of!(Frame, observed_target),
    pre_call_rsp = const core::mem::offset_of!(Frame, pre_call_rsp),
    resumed_rsp = const core::mem::offset_of!(Frame, resumed_rsp),
);

unsafe extern "C" {
    fn __rapid_profiler_ordinary_call_v1(frame: *mut Frame, data: *const u8, len: usize) -> u64;
    static __rapid_profiler_ordinary_after_call_v1: u8;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    gate: u64,
    pid: u64,
    tid: u64,
    target: u64,
    continuation: u64,
}

/// Non-Clone identity retained in the existing interval Pair until its original
/// owner completes. This is not an epoch receipt and grants no model authority.
#[derive(Debug)]
pub(super) struct GateEntry {
    identity: Identity,
    sequence: u64,
    rsp: u64,
    word: u64,
}

/// Created only by validation at an authenticated original RET, then consumed
/// after the existing model finish and all of its postconditions succeed.
#[derive(Debug)]
pub(super) struct GateReturn {
    identity: Identity,
    sequence: u64,
    rsp: u64,
    word: u64,
    pc: u64,
}

/// Actual returned value and stack observations; not a full-state qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallResult {
    /// The subject's actual SysV RAX result, forwarded by the gate unchanged.
    pub value: u64,
    /// RSP stored immediately before the actual CALL.
    pub pre_call_rsp: u64,
    /// Original application RSP observed by the admitted entry callback.
    pub entry_rsp: u64,
    /// RSP stored by the first instruction after the actual RET.
    pub resumed_rsp: u64,
    /// The exact admitted original RET that completed the retained pair.
    pub return_pc: u64,
}

/// Actual original-only call observations. No entry/RET callback or pair
/// completion is asserted by this separate prepublication result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalCallResult {
    /// Actual original subject RAX result.
    pub value: u64,
    /// Actual RSP stored immediately before CALL.
    pub pre_call_rsp: u64,
    /// Actual RSP stored immediately after RET.
    pub resumed_rsp: u64,
}

fn thread_id() -> u64 {
    // SAFETY: read-only actual kernel identity, not a caller-provided thread key.
    unsafe { libc::syscall(libc::SYS_gettid) as u64 }
}

fn same(frame: Frame, id: Identity, phase: u64) -> Result<(), GateError> {
    if frame.phase != phase
        || frame.sequence == 0
        || (frame.gate, frame.pid, frame.tid, frame.target) != (id.gate, id.pid, id.tid, id.target)
        || frame.observed_target != id.target
    {
        return Err(GateError::Identity);
    }
    Ok(())
}

fn stack_word(frame: Frame, rsp: u64) -> Result<(), GateError> {
    if rsp < frame.stack_start
        || rsp.checked_add(8).is_none_or(|end| end > frame.stack_end)
        || frame.pre_call_rsp == 0
        || frame.pre_call_rsp % 16 != 0
        || frame.pre_call_rsp.checked_sub(8) != Some(rsp)
    {
        return Err(GateError::Stack);
    }
    Ok(())
}

fn arm(previous: Frame, id: Identity, start: u64, end: u64) -> Result<Frame, GateError> {
    if previous.phase != IDLE {
        return Err(GateError::Reentry);
    }
    if start == 0 || start.checked_add(8).is_none_or(|n| n > end) {
        return Err(GateError::Stack);
    }
    let sequence = previous
        .sequence
        .checked_add(1)
        .ok_or(GateError::Sequence)?;
    Ok(Frame {
        phase: ARMED,
        sequence,
        gate: id.gate,
        pid: id.pid,
        tid: id.tid,
        target: id.target,
        stack_start: start,
        stack_end: end,
        ..Frame::default()
    })
}

fn entry(
    frame: &mut Frame,
    id: Identity,
    pc: u64,
    rsp: u64,
    word: u64,
) -> Result<GateEntry, GateError> {
    same(*frame, id, ARMED)?;
    stack_word(*frame, rsp)?;
    if pc != id.target || word != id.continuation || frame.resumed_rsp != 0 {
        return Err(GateError::Return);
    }
    let token = GateEntry {
        identity: id,
        sequence: frame.sequence,
        rsp,
        word,
    };
    frame.entry_rsp = rsp;
    frame.return_word = word;
    frame.phase = ENTERED;
    Ok(token)
}

fn returning(
    frame: Frame,
    id: Identity,
    token: &GateEntry,
    pc: u64,
    rsp: u64,
    word: u64,
    returns: &[u64],
) -> Result<GateReturn, GateError> {
    same(frame, id, ENTERED)?;
    stack_word(frame, rsp)?;
    if token.identity != id
        || token.sequence != frame.sequence
        || token.rsp != rsp
        || token.word != word
        || frame.entry_rsp != rsp
        || frame.return_word != word
        || word != id.continuation
        || frame.resumed_rsp != 0
        || !returns.contains(&pc)
    {
        return Err(GateError::Return);
    }
    Ok(GateReturn {
        identity: id,
        sequence: frame.sequence,
        rsp,
        word,
        pc,
    })
}

fn complete(
    frame: &mut Frame,
    id: Identity,
    token: GateReturn,
    returns: &[u64],
) -> Result<(), GateError> {
    // Recheck the actual active invocation after the model has finished. No
    // arbitrary callback or caller-supplied Boolean can mark a pair complete.
    let entry = GateEntry {
        identity: token.identity,
        sequence: token.sequence,
        rsp: token.rsp,
        word: token.word,
    };
    returning(*frame, id, &entry, token.pc, token.rsp, token.word, returns)?;
    frame.return_pc = token.pc;
    frame.phase = COMPLETED;
    Ok(())
}

fn resumed(
    frame: Frame,
    id: Identity,
    value: u64,
    returns: &[u64],
) -> Result<CallResult, GateError> {
    same(frame, id, COMPLETED)?;
    stack_word(frame, frame.entry_rsp)?;
    if frame.resumed_rsp != frame.pre_call_rsp
        || frame.return_word != id.continuation
        || !returns.contains(&frame.return_pc)
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

fn original_resumed(
    frame: Frame,
    id: Identity,
    value: u64,
) -> Result<OriginalCallResult, GateError> {
    same(frame, id, ARMED)?;
    // This checks where the real CALL's return slot necessarily lies; it does
    // not manufacture an observation of application RSP at the original entry.
    let slot = frame.pre_call_rsp.checked_sub(8).ok_or(GateError::Stack)?;
    stack_word(frame, slot)?;
    if frame.resumed_rsp != frame.pre_call_rsp
        || (frame.entry_rsp, frame.return_word, frame.return_pc) != (0, 0, 0)
    {
        return Err(GateError::Completion);
    }
    Ok(OriginalCallResult {
        value,
        pre_call_rsp: frame.pre_call_rsp,
        resumed_rsp: frame.resumed_rsp,
    })
}

// This guard retains the active poison on any Rust-side early return/unwind.
// Subject/callback unwind across the C/assembly boundary is forbidden, not caught.
struct Invocation {
    frame: *mut Frame,
    finished: bool,
}
impl Drop for Invocation {
    fn drop(&mut self) {
        if !self.finished {
            // SAFETY: this actual thread still owns its initialized TLS cell;
            // assembly has returned or was never entered. No Frame reference exists.
            unsafe {
                (*self.frame).phase = POISONED;
            }
        }
    }
}

impl CallGate {
    /// Copy only the exact admitted geometry. This does not verify current bytes,
    /// publish a site, retain executable owners, or authorize invoking the target.
    pub fn new(certificate: &IntegerLeafCertificate) -> Result<Arc<Self>, GateError> {
        let (start, end) = certificate.range();
        let returns = certificate.returns();
        if start == 0
            || certificate.entry() != start
            || end <= start
            || end - start > 256
            || !(1..=4).contains(&returns.len())
            || returns.iter().any(|&pc| pc < start || pc >= end)
            || returns.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(GateError::Descriptor);
        }
        Ok(Arc::new(Self {
            target: start,
            returns: returns.into(),
            pid: std::process::id(),
        }))
    }
    /// Exact admitted symbol entry; no alternate target setter exists.
    pub fn target(&self) -> u64 {
        self.target
    }
    /// Address of the ordinary MOV immediately following this library's CALL.
    /// It is derived from the compiled gate label, never a client-supplied integer.
    pub fn continuation(&self) -> u64 {
        core::ptr::addr_of!(__rapid_profiler_ordinary_after_call_v1) as usize as u64
    }
    pub(crate) fn declared_returns(&self) -> &[u64] {
        &self.returns
    }
    pub(crate) fn process_matches(&self) -> bool {
        self.pid == std::process::id()
    }
    fn identity(&self) -> Result<Identity, GateError> {
        if !self.process_matches() {
            return Err(GateError::Process);
        }
        let tid = thread_id();
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

    /// # Safety
    /// The exact admitted target and its source/publication/control owners stay
    /// valid and immutable for this whole call; every admitted entry and RET is
    /// instrumented by the matching site's mandatory controls. The caller has
    /// attached the same site on this thread and supplied a valid readable stack
    /// and input for the exact SysV `(*const u8, usize) -> u64` ABI. The subject
    /// returns normally, preserving all SysV callee-saved registers. No signal,
    /// unwind, longjmp, cancellation, concurrent mutation, external entry, or
    /// reentrant subject call may intervene. CET assumptions remain those of the
    /// admitted certificate. The caller still owns externally known source PCs;
    /// this gate does not make arbitrary foreign entries impossible.
    pub(super) unsafe fn invoke(
        &self,
        data: *const u8,
        len: usize,
        stack: &ReadableStack,
    ) -> Result<CallResult, GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let raw = cell.get();
                // SAFETY: one actual thread, raw Copy snapshot; no reference escapes.
                let next = arm(unsafe { raw.read() }, id, stack.start, stack.end)?;
                unsafe {
                    raw.write(next);
                }
                let mut invocation = Invocation {
                    frame: raw,
                    finished: false,
                };
                // SAFETY: the caller's explicit contract holds; this static assembly
                // receives only the raw UnsafeCell pointer. RBX is saved/restored;
                // entry RSP%16==8, PUSH makes pre-CALL RSP%16==0. The subject may
                // clobber every SysV caller-saved register. Its real RAX is returned.
                let value = unsafe { __rapid_profiler_ordinary_call_v1(raw, data, len) };
                let result = resumed(
                    unsafe { raw.read() },
                    self.identity()?,
                    value,
                    &self.returns,
                )?;
                // Reset only after one authenticated entry, completed original-owner
                // RET and actual return to the immutable continuation. Keep sequence.
                unsafe {
                    raw.write(Frame {
                        sequence: next.sequence,
                        ..Frame::default()
                    });
                }
                invocation.finished = true;
                Ok(result)
            })
            .map_err(|_| GateError::ThreadStorage)?
    }

    /// Original-only path for the owning site's unsafe prepublication wrapper.
    /// No public gate method can invoke this or provide a completion exemption.
    ///
    /// # Safety
    /// The wrapper verifies the complete uninstrumented source owner before and
    /// after this call, retains it, and certifies quiescence from publication.
    /// The original subject, data, stack, ABI, CET, external-entry, signal and
    /// normal-return obligations of invoke apply, except that no instrumentation
    /// or attachment exists. A native qualifier must use production invoke for
    /// its instrumented candidate. This method never mints a pair or RET token.
    pub(super) unsafe fn invoke_original(
        &self,
        data: *const u8,
        len: usize,
        stack: &ReadableStack,
    ) -> Result<OriginalCallResult, GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let raw = cell.get();
                // SAFETY: same private actual-thread cell; no reference crosses CALL.
                let next = arm(unsafe { raw.read() }, id, stack.start, stack.end)?;
                unsafe {
                    raw.write(next);
                }
                let mut invocation = Invocation {
                    frame: raw,
                    finished: false,
                };
                // SAFETY: distinct original-only contract, identical CALL/RET code.
                let value = unsafe { __rapid_profiler_ordinary_call_v1(raw, data, len) };
                let result = original_resumed(unsafe { raw.read() }, self.identity()?, value)?;
                unsafe {
                    raw.write(Frame {
                        sequence: next.sequence,
                        ..Frame::default()
                    });
                }
                invocation.finished = true;
                Ok(result)
            })
            .map_err(|_| GateError::ThreadStorage)?
    }

    // The existing site must authenticate the exact role/control first. These
    // methods neither replace that check nor acquire/complete an epoch receipt.
    pub(super) fn enter(&self, context: &HookContext) -> Result<GateEntry, GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let raw = cell.get();
                let mut frame = unsafe { raw.read() };
                same(frame, id, ARMED)?;
                stack_word(frame, context.stack_pointer)?;
                // SAFETY: active invoke inherited the caller's readable-stack
                // contract; exact eight-byte extent checked before the read.
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
                    raw.write(frame);
                }
                Ok(token)
            })
            .map_err(|_| GateError::ThreadStorage)?
    }

    pub(super) fn validate_ret(
        &self,
        token: &GateEntry,
        context: &HookContext,
    ) -> Result<GateReturn, GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let frame = unsafe { cell.get().read() };
                same(frame, id, ENTERED)?;
                stack_word(frame, context.stack_pointer)?;
                // SAFETY: same invocation's checked readable extent, no write/repair.
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
                )
            })
            .map_err(|_| GateError::ThreadStorage)?
    }

    pub(super) fn complete_ret(&self, token: GateReturn) -> Result<(), GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let raw = cell.get();
                let mut frame = unsafe { raw.read() };
                complete(&mut frame, id, token, &self.returns)?;
                unsafe {
                    raw.write(frame);
                }
                Ok(())
            })
            .map_err(|_| GateError::ThreadStorage)?
    }
}

#[cfg(test)]
mod tests;
