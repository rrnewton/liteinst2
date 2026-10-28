//! Real CALL gate for the separate optional profile. Scratch is never callback state.
use super::super::{GateError, OriginalCallResult, ReadableStack, tid};
use crate::frontend_native::IntegerLeafCertificate;
use liteinst2::precontext::{CallScratch, Disposition, ScratchPhase, ScratchSnapshot};
use liteinst2::trampoline::HookContext;
use std::cell::UnsafeCell;
use std::sync::Arc;

const ARMED: u64 = 1;
const ENTERED: u64 = 2;
const COMPLETED: u64 = 3;
const POISONED: u64 = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Meta {
    phase: u64,
    sequence: u64,
    gate: u64,
    pid: u64,
    tid: u64,
    target: u64,
    observed_target: u64,
    pre_rsp: u64,
    resumed_rsp: u64,
    stack_start: u64,
    stack_end: u64,
    entry_rsp: u64,
    word: u64,
    return_pc: u64,
}
#[repr(C)]
struct Frame {
    scratch: CallScratch,
    meta: Meta,
}
const _: () = assert!(core::mem::offset_of!(Frame, scratch) == 0);
const _: () = assert!(core::mem::offset_of!(Frame, meta) == 72);
const _: () = assert!(core::mem::size_of::<CallScratch>() == 72);
const _: () = assert!(core::mem::align_of::<CallScratch>() == 8);
// Fixed optional native adapter authenticates these exact compiler-derived offsets.
const _: () = {
    assert!(core::mem::size_of::<Frame>() == 184);
    assert!(core::mem::size_of::<Meta>() == 112);
    assert!(core::mem::align_of::<Frame>() == 8);
    assert!(core::mem::offset_of!(Frame, meta) + core::mem::offset_of!(Meta, target) == 112);
    assert!(
        core::mem::offset_of!(Frame, meta) + core::mem::offset_of!(Meta, observed_target) == 120
    );
    assert!(core::mem::offset_of!(Frame, meta) + core::mem::offset_of!(Meta, pre_rsp) == 128);
    assert!(core::mem::offset_of!(Frame, meta) + core::mem::offset_of!(Meta, resumed_rsp) == 136);
};
thread_local! {
    static FRAME: UnsafeCell<Frame> = const { UnsafeCell::new(Frame {
        scratch: CallScratch::armed(), meta: Meta { phase:0, sequence:0, gate:0,
        pid:0, tid:0, target:0, observed_target:0, pre_rsp:0, resumed_rsp:0,
        stack_start:0, stack_end:0, entry_rsp:0, word:0, return_pc:0 }
    }) };
}
core::arch::global_asm!(r#"
.pushsection .text.rapid_profiler_optional_call,"ax",@progbits
.p2align 4
.global __rapid_profiler_optional_call_v1
.hidden __rapid_profiler_optional_call_v1
.type __rapid_profiler_optional_call_v1,@function
__rapid_profiler_optional_call_v1:
    push rbx
    mov rbx, rdi
    mov rdi, rsi
    mov rsi, rdx
    mov r11, [rbx + {target}]
    mov [rbx + {observed}], r11
    mov [rbx + {pre}], rsp
    call r11
.global __rapid_profiler_optional_after_v1
.hidden __rapid_profiler_optional_after_v1
__rapid_profiler_optional_after_v1:
    mov [rbx + {resumed}], rsp
    pop rbx
    ret
.size __rapid_profiler_optional_call_v1, .-__rapid_profiler_optional_call_v1
.popsection
"#,
 target=const core::mem::offset_of!(Frame, meta)+core::mem::offset_of!(Meta,target),
 observed=const core::mem::offset_of!(Frame, meta)+core::mem::offset_of!(Meta,observed_target),
 pre=const core::mem::offset_of!(Frame, meta)+core::mem::offset_of!(Meta,pre_rsp),
 resumed=const core::mem::offset_of!(Frame, meta)+core::mem::offset_of!(Meta,resumed_rsp));
unsafe extern "C" {
    fn __rapid_profiler_optional_call_v1(frame: *mut Frame, data: *const u8, len: usize) -> u64;
    static __rapid_profiler_optional_after_v1: u8;
}

/// Immutable geometry; source/publication authority stays with its sealed site.
pub struct OptionalCallGate {
    target: u64,
    returns: Box<[u64]>,
    pid: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    gate: u64,
    pid: u64,
    tid: u64,
    target: u64,
    continuation: u64,
}
#[derive(Debug)]
pub(super) struct Entry {
    id: Identity,
    sequence: u64,
    rsp: u64,
    word: u64,
}
pub(super) struct Return {
    entry: Entry,
    pc: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Returned {
    pub sequence: u64,
    pub disposition: Disposition,
    pub value: u64,
    pub pre_rsp: u64,
    pub entry_rsp: u64,
    pub resumed_rsp: u64,
    pub return_pc: u64,
}
fn idle(m: Meta) -> Result<u64, GateError> {
    if m != (Meta {
        sequence: m.sequence,
        ..Meta::default()
    }) {
        return Err(GateError::Completion);
    }
    Ok(m.sequence)
}
fn same(m: Meta, id: Identity, phase: u64) -> Result<(), GateError> {
    if m.phase != phase
        || m.sequence == 0
        || (m.gate, m.pid, m.tid, m.target, m.observed_target)
            != (id.gate, id.pid, id.tid, id.target, id.target)
    {
        return Err(GateError::Identity);
    }
    Ok(())
}
fn stack(m: Meta, rsp: u64) -> Result<(), GateError> {
    if m.pre_rsp == 0
        || m.pre_rsp % 16 != 0
        || m.pre_rsp.checked_sub(8) != Some(rsp)
        || rsp < m.stack_start
        || rsp.checked_add(8).is_none_or(|n| n > m.stack_end)
    {
        return Err(GateError::Stack);
    }
    Ok(())
}
fn arm(m: Meta, id: Identity, extent: &ReadableStack) -> Result<Meta, GateError> {
    idle(m)?;
    if extent.start == 0 || extent.start.checked_add(8).is_none_or(|n| n > extent.end) {
        return Err(GateError::Stack);
    }
    Ok(Meta {
        phase: ARMED,
        sequence: m.sequence.checked_add(1).ok_or(GateError::Sequence)?,
        gate: id.gate,
        pid: id.pid,
        tid: id.tid,
        target: id.target,
        stack_start: extent.start,
        stack_end: extent.end,
        ..Meta::default()
    })
}
fn enter(m: &mut Meta, id: Identity, pc: u64, rsp: u64, word: u64) -> Result<Entry, GateError> {
    same(*m, id, ARMED)?;
    stack(*m, rsp)?;
    if pc != id.target
        || word != id.continuation
        || m.resumed_rsp != 0
        || (m.entry_rsp, m.word, m.return_pc) != (0, 0, 0)
    {
        return Err(GateError::Return);
    }
    let token = Entry {
        id,
        sequence: m.sequence,
        rsp,
        word,
    };
    m.phase = ENTERED;
    m.entry_rsp = rsp;
    m.word = word;
    Ok(token)
}
fn returning(
    m: Meta,
    id: Identity,
    e: &Entry,
    pc: u64,
    rsp: u64,
    word: u64,
    rets: &[u64],
) -> Result<Return, GateError> {
    same(m, id, ENTERED)?;
    stack(m, rsp)?;
    if e.id != id
        || e.sequence != m.sequence
        || e.rsp != rsp
        || e.word != word
        || m.entry_rsp != rsp
        || m.word != word
        || word != id.continuation
        || m.resumed_rsp != 0
        || m.return_pc != 0
        || !rets.contains(&pc)
    {
        return Err(GateError::Return);
    }
    Ok(Return {
        entry: Entry {
            id,
            sequence: e.sequence,
            rsp,
            word,
        },
        pc,
    })
}
fn complete(m: &mut Meta, id: Identity, r: Return, rets: &[u64]) -> Result<(), GateError> {
    returning(*m, id, &r.entry, r.pc, r.entry.rsp, r.entry.word, rets)?;
    m.phase = COMPLETED;
    m.return_pc = r.pc;
    Ok(())
}
fn resumed(
    m: Meta,
    id: Identity,
    s: ScratchSnapshot,
    value: u64,
    rets: &[u64],
) -> Result<Returned, GateError> {
    let disposition = s.disposition.ok_or(GateError::Completion)?;
    same(
        m,
        id,
        match disposition {
            Disposition::FastBypass => ARMED,
            Disposition::Slow => COMPLETED,
        },
    )?;
    stack(m, s.entry_rsp)?;
    if s.phase != ScratchPhase::ReturnObserved
        || s.entry_pc != id.target
        || s.return_rsp != s.entry_rsp
        || s.entry_word != id.continuation
        || s.return_word != s.entry_word
        || !rets.contains(&s.return_pc)
        || m.resumed_rsp != m.pre_rsp
    {
        return Err(GateError::Completion);
    }
    let expected = match disposition {
        Disposition::FastBypass => (0, 0, 0),
        Disposition::Slow => (s.entry_rsp, s.entry_word, s.return_pc),
    };
    if (m.entry_rsp, m.word, m.return_pc) != expected {
        return Err(GateError::Completion);
    }
    Ok(Returned {
        sequence: m.sequence,
        disposition,
        value,
        pre_rsp: m.pre_rsp,
        entry_rsp: s.entry_rsp,
        resumed_rsp: m.resumed_rsp,
        return_pc: s.return_pc,
    })
}
struct Invocation {
    raw: *mut Frame,
    finished: bool,
}
impl Drop for Invocation {
    fn drop(&mut self) {
        if !self.finished {
            // SAFETY: actual thread owns raw initialized TLS; only the Copy tail is touched.
            unsafe {
                (*self.raw).meta.phase = POISONED;
            }
        }
    }
}
impl OptionalCallGate {
    pub(super) fn new(c: &IntegerLeafCertificate) -> Result<Arc<Self>, GateError> {
        let (start, end) = c.range();
        let rets = c.returns();
        if start == 0
            || c.entry() != start
            || end <= start
            || end - start > 256
            || !(1..=4).contains(&rets.len())
            || rets.iter().any(|&r| r < start || r >= end)
            || rets.windows(2).any(|r| r[0] >= r[1])
        {
            return Err(GateError::Descriptor);
        }
        Ok(Arc::new(Self {
            target: start,
            returns: rets.into(),
            pid: std::process::id(),
        }))
    }
    pub fn target(&self) -> u64 {
        self.target
    }
    pub fn continuation(&self) -> u64 {
        core::ptr::addr_of!(__rapid_profiler_optional_after_v1) as usize as u64
    }
    pub(super) fn returns(&self) -> &[u64] {
        &self.returns
    }
    pub(super) fn process_matches(&self) -> bool {
        self.pid == std::process::id()
    }
    fn identity(&self) -> Result<Identity, GateError> {
        if !self.process_matches() {
            return Err(GateError::Process);
        }
        let thread = tid();
        if thread == 0 || thread > i32::MAX as u64 {
            return Err(GateError::Identity);
        }
        Ok(Identity {
            gate: core::ptr::from_ref(self) as usize as u64,
            pid: u64::from(self.pid),
            tid: thread,
            target: self.target,
            continuation: self.continuation(),
        })
    }
    pub(super) fn idle_checkpoint(&self) -> Result<u64, GateError> {
        self.identity()?;
        FRAME
            .try_with(|c| {
                // SAFETY: no borrowed frame crosses execution; idle metadata permits header read.
                let p = c.get();
                let m = unsafe { core::ptr::addr_of!((*p).meta).read() };
                let n = idle(m)?;
                let s = unsafe { &*core::ptr::addr_of!((*p).scratch) }
                    .snapshot()
                    .map_err(|_| GateError::Completion)?;
                if s.phase != ScratchPhase::Armed {
                    return Err(GateError::Completion);
                }
                Ok(n)
            })
            .map_err(|_| GateError::ThreadStorage)?
    }
    // Callbacks never access the scratch header, not even for a diagnostic read.
    fn callback<R>(
        &self,
        c: &HookContext,
        f: impl FnOnce(&mut Meta, Identity, u64) -> Result<R, GateError>,
    ) -> Result<R, GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let p = cell.get();
                if c.rbx != p as usize as u64 {
                    return Err(GateError::Identity);
                }
                let mp = unsafe { core::ptr::addr_of_mut!((*p).meta) };
                let mut m = unsafe { mp.read() };
                stack(m, c.stack_pointer)?;
                // SAFETY: exact extent inherited from unsafe invoke, checked before read.
                let word = unsafe { (c.stack_pointer as usize as *const u64).read_unaligned() };
                let result = f(&mut m, id, word)?;
                unsafe {
                    mp.write(m);
                }
                Ok(result)
            })
            .map_err(|_| GateError::ThreadStorage)?
    }
    pub(super) fn enter(&self, c: &HookContext) -> Result<Entry, GateError> {
        self.callback(c, |m, id, word| {
            enter(m, id, c.instruction_pointer, c.stack_pointer, word)
        })
    }
    pub(super) fn validate_ret(&self, e: &Entry, c: &HookContext) -> Result<Return, GateError> {
        self.callback(c, |m, id, word| {
            returning(
                *m,
                id,
                e,
                c.instruction_pointer,
                c.stack_pointer,
                word,
                &self.returns,
            )
        })
    }
    pub(super) fn complete_ret(&self, r: Return) -> Result<(), GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let mp = unsafe { core::ptr::addr_of_mut!((*cell.get()).meta) };
                let mut m = unsafe { mp.read() };
                complete(&mut m, id, r, &self.returns)?;
                unsafe {
                    mp.write(m);
                }
                Ok(())
            })
            .map_err(|_| GateError::ThreadStorage)?
    }
    /// Private installed path: the sealed whole leaf, permanent controls and actual
    /// attachment are live. Input/stack/normal return/no fork/signal/reentry/CET
    /// contracts hold. No reference to this frame crosses assembly or callbacks.
    pub(super) unsafe fn invoke(
        &self,
        data: *const u8,
        len: usize,
        extent: &ReadableStack,
    ) -> Result<Returned, GateError> {
        unsafe { self.call(data, len, extent, false) }.and_then(|r| match r {
            Outcome::Installed(r) => Ok(r),
            _ => Err(GateError::Completion),
        })
    }
    /// Separate original-only path, callable only by the owning preparation wrapper.
    /// Full original verification and no publication before/after are required.
    pub(super) unsafe fn invoke_original(
        &self,
        data: *const u8,
        len: usize,
        extent: &ReadableStack,
    ) -> Result<OriginalCallResult, GateError> {
        unsafe { self.call(data, len, extent, true) }.and_then(|r| match r {
            Outcome::Original(r) => Ok(r),
            _ => Err(GateError::Completion),
        })
    }
    unsafe fn call(
        &self,
        data: *const u8,
        len: usize,
        extent: &ReadableStack,
        original: bool,
    ) -> Result<Outcome, GateError> {
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                let p = cell.get();
                let mp = unsafe { core::ptr::addr_of_mut!((*p).meta) };
                let next = arm(unsafe { mp.read() }, id, extent)?;
                // Fresh scratch is written only while canonical idle is proven.
                self.idle_checkpoint()?;
                unsafe {
                    core::ptr::addr_of_mut!((*p).scratch).write(CallScratch::armed());
                    mp.write(next);
                }
                let mut guard = Invocation {
                    raw: p,
                    finished: false,
                };
                let value = unsafe { __rapid_profiler_optional_call_v1(p, data, len) };
                let m = unsafe { mp.read() };
                let current = self.identity()?;
                let scratch = unsafe { &*core::ptr::addr_of!((*p).scratch) }
                    .snapshot()
                    .map_err(|_| GateError::Completion)?;
                let result = if original {
                    same(m, current, ARMED)?;
                    stack(m, m.pre_rsp.checked_sub(8).ok_or(GateError::Stack)?)?;
                    if scratch.phase != ScratchPhase::Armed
                        || m.resumed_rsp != m.pre_rsp
                        || (m.entry_rsp, m.word, m.return_pc) != (0, 0, 0)
                    {
                        return Err(GateError::Completion);
                    }
                    Outcome::Original(OriginalCallResult {
                        value,
                        pre_call_rsp: m.pre_rsp,
                        resumed_rsp: m.resumed_rsp,
                    })
                } else {
                    Outcome::Installed(resumed(m, current, scratch, value, &self.returns)?)
                };
                unsafe {
                    core::ptr::addr_of_mut!((*p).scratch).write(CallScratch::armed());
                    mp.write(Meta {
                        sequence: next.sequence,
                        ..Meta::default()
                    });
                }
                guard.finished = true;
                Ok(result)
            })
            .map_err(|_| GateError::ThreadStorage)?
    }
}
enum Outcome {
    Installed(Returned),
    Original(OriginalCallResult),
}
#[cfg(test)]
pub(super) mod tests;
