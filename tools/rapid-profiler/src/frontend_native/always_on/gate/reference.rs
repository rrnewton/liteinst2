//! Separately stored real-CALL enclosure. No calibration or accuracy policy.
use super::*;
use std::marker::PhantomData;
use std::rc::Rc;

mod hardware;

// One strict admission implementation for the opt-in reference and raw-counter
// brackets. The legacy callback clock remains unchanged.
pub(in crate::frontend_native::always_on) fn check_clock() -> Result<(), GateError> {
    hardware::check()
}

/// Immutable gate ABI. Selecting a profile never changes an existing descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateProfile {
    /// The unchanged ordinary CALL stub and callback-only timing.
    Legacy,
    /// Separate reference stub; explicit AMD LFENCE/TSC admission is required.
    ReferenceAmdV1,
}

/// Which real call produced a separately retained reference enclosure.
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLeg {
    Original = 1,
    Installed = 2,
}

/// Independently read, uncorrected TSC/AUX words; not callback row endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceTimestamp {
    pub ticks: u64,
    pub aux: u32,
}

/// Returned only after physical return AND the owning facade's full postflight.
/// Identity labels are diagnostic, not invocation/publication/retirement tokens.
/// The two timestamps enclose CALL, body and declared save/restore gaps. They
/// include descheduling; neither is an on-CPU, nanosecond or accuracy estimate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceInterval {
    leg: ReferenceLeg,
    external_id: u64,
    gate: u64,
    sequence: u64,
    pid: u64,
    tid: u64,
    target: u64,
    continuation: u64,
    pre_call_rsp: u64,
    resumed_rsp: u64,
    start: ReferenceTimestamp,
    end: ReferenceTimestamp,
}
impl ReferenceInterval {
    pub fn leg(&self) -> ReferenceLeg {
        self.leg
    }
    pub fn external_id(&self) -> u64 {
        self.external_id
    }
    pub fn gate_identity(&self) -> u64 {
        self.gate
    }
    pub fn gate_sequence(&self) -> u64 {
        self.sequence
    }
    pub fn pid(&self) -> u64 {
        self.pid
    }
    pub fn tid(&self) -> u64 {
        self.tid
    }
    pub fn target(&self) -> u64 {
        self.target
    }
    pub fn continuation(&self) -> u64 {
        self.continuation
    }
    pub fn pre_call_rsp(&self) -> u64 {
        self.pre_call_rsp
    }
    pub fn resumed_rsp(&self) -> u64 {
        self.resumed_rsp
    }
    pub fn start(&self) -> ReferenceTimestamp {
        self.start
    }
    pub fn end(&self) -> ReferenceTimestamp {
        self.end
    }
    /// Checked raw difference only; equal AUX is not a no-migration proof.
    pub fn elapsed_ticks(&self) -> Option<u64> {
        (self.start.aux == self.end.aux)
            .then(|| self.end.ticks.checked_sub(self.start.ticks))
            .flatten()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceCallResult {
    pub call: CallResult,
    pub reference: ReferenceInterval,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceOriginalCallResult {
    pub call: OriginalCallResult,
    pub reference: ReferenceInterval,
}

const RETURNED: u64 = 2;
const CANARY: u64 = 0x7265_6654_5343_7631;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReferenceFrame {
    phase: u64,
    sequence: u64,
    gate: u64,
    pid: u64,
    tid: u64,
    target: u64,
    continuation: u64,
    external_id: u64,
    leg: u64,
    start_lo: u64,
    start_hi: u64,
    start_aux: u64,
    end_lo: u64,
    end_hi: u64,
    end_aux: u64,
    before_rax: u64,
    before_rcx: u64,
    before_rdx: u64,
    after_rax: u64,
    after_rcx: u64,
    after_rdx: u64,
    canary: u64,
}
const _: () = {
    assert!(core::mem::size_of::<ReferenceFrame>() == 176);
    assert!(core::mem::align_of::<ReferenceFrame>() == 8);
    assert!(core::mem::offset_of!(ReferenceFrame, phase) == 0);
    assert!(core::mem::offset_of!(ReferenceFrame, sequence) == 8);
    assert!(core::mem::offset_of!(ReferenceFrame, gate) == 16);
    assert!(core::mem::offset_of!(ReferenceFrame, pid) == 24);
    assert!(core::mem::offset_of!(ReferenceFrame, tid) == 32);
    assert!(core::mem::offset_of!(ReferenceFrame, target) == 40);
    assert!(core::mem::offset_of!(ReferenceFrame, continuation) == 48);
    assert!(core::mem::offset_of!(ReferenceFrame, external_id) == 56);
    assert!(core::mem::offset_of!(ReferenceFrame, leg) == 64);
    assert!(core::mem::offset_of!(ReferenceFrame, start_lo) == 72);
    assert!(core::mem::offset_of!(ReferenceFrame, start_hi) == 80);
    assert!(core::mem::offset_of!(ReferenceFrame, start_aux) == 88);
    assert!(core::mem::offset_of!(ReferenceFrame, end_lo) == 96);
    assert!(core::mem::offset_of!(ReferenceFrame, end_hi) == 104);
    assert!(core::mem::offset_of!(ReferenceFrame, end_aux) == 112);
    assert!(core::mem::offset_of!(ReferenceFrame, before_rax) == 120);
    assert!(core::mem::offset_of!(ReferenceFrame, before_rcx) == 128);
    assert!(core::mem::offset_of!(ReferenceFrame, before_rdx) == 136);
    assert!(core::mem::offset_of!(ReferenceFrame, after_rax) == 144);
    assert!(core::mem::offset_of!(ReferenceFrame, after_rcx) == 152);
    assert!(core::mem::offset_of!(ReferenceFrame, after_rdx) == 160);
    assert!(core::mem::offset_of!(ReferenceFrame, canary) == 168);
    assert!(core::mem::size_of::<Frame>() == 112);
    assert!(core::mem::align_of::<Frame>() == 8);
    assert!(core::mem::offset_of!(Frame, target) == 40);
    assert!(core::mem::offset_of!(Frame, observed_target) == 48);
    assert!(core::mem::offset_of!(Frame, pre_call_rsp) == 56);
    assert!(core::mem::offset_of!(Frame, resumed_rsp) == 64);
};

thread_local! {
    // Copy-only and destructor-free. Never expose a Rust reference across CALL.
    static REFERENCE: UnsafeCell<ReferenceFrame> = const {
        UnsafeCell::new(ReferenceFrame {
            phase: 0, sequence: 0, gate: 0, pid: 0, tid: 0, target: 0,
            continuation: 0, external_id: 0, leg: 0,
            start_lo: 0, start_hi: 0, start_aux: 0, end_lo: 0, end_hi: 0, end_aux: 0,
            before_rax: 0, before_rcx: 0, before_rdx: 0,
            after_rax: 0, after_rcx: 0, after_rdx: 0, canary: 0,
        })
    };
}

// RBX/R12 belong to this gate. The admitted scalar certificate excludes every
// callee-saved register read/write/address operand. Incoming RSP=S is 8 mod16;
// subject entry RSP=S-32. New native qualification must retain [S-32-128,end),
// including the extra sixteen application red-zone bytes relative to Legacy.
core::arch::global_asm!(
    r#"
    .pushsection .text.rapid_profiler_reference_call,"ax",@progbits
    .p2align 4
    .global __rapid_profiler_reference_call_v1
    .hidden __rapid_profiler_reference_call_v1
    .type __rapid_profiler_reference_call_v1,@function
__rapid_profiler_reference_call_v1:
    push rbx
    push r12
    lea rsp, [rsp - 8]
    mov rbx, rdi
    mov r12, rcx
    mov rdi, rsi
    mov rsi, rdx
    mov r11, [rbx + {target}]
    mov [rbx + {observed_target}], r11
    mov [rbx + {pre_call_rsp}], rsp
    .global __rapid_profiler_reference_before_start_v1
    .hidden __rapid_profiler_reference_before_start_v1
__rapid_profiler_reference_before_start_v1:
    mov [r12 + {before_rax}], rax
    mov [r12 + {before_rcx}], rcx
    mov [r12 + {before_rdx}], rdx
    lfence
    rdtscp
    lfence
    mov [r12 + {start_lo}], eax
    mov [r12 + {start_hi}], edx
    mov [r12 + {start_aux}], ecx
    mov rax, [r12 + {before_rax}]
    mov rcx, [r12 + {before_rcx}]
    mov rdx, [r12 + {before_rdx}]
    .global __rapid_profiler_reference_after_start_v1
    .hidden __rapid_profiler_reference_after_start_v1
__rapid_profiler_reference_after_start_v1:
    call r11
    .global __rapid_profiler_reference_after_call_v1
    .hidden __rapid_profiler_reference_after_call_v1
__rapid_profiler_reference_after_call_v1:
    mov [rbx + {resumed_rsp}], rsp
    .global __rapid_profiler_reference_before_end_v1
    .hidden __rapid_profiler_reference_before_end_v1
__rapid_profiler_reference_before_end_v1:
    mov [r12 + {after_rax}], rax
    mov [r12 + {after_rcx}], rcx
    mov [r12 + {after_rdx}], rdx
    lfence
    rdtscp
    lfence
    mov [r12 + {end_lo}], eax
    mov [r12 + {end_hi}], edx
    mov [r12 + {end_aux}], ecx
    mov rax, [r12 + {after_rax}]
    mov rcx, [r12 + {after_rcx}]
    mov rdx, [r12 + {after_rdx}]
    mov qword ptr [r12 + {phase}], {returned}
    .global __rapid_profiler_reference_after_end_v1
    .hidden __rapid_profiler_reference_after_end_v1
__rapid_profiler_reference_after_end_v1:
    lea rsp, [rsp + 8]
    pop r12
    pop rbx
    ret
    .global __rapid_profiler_reference_call_end_v1
    .hidden __rapid_profiler_reference_call_end_v1
__rapid_profiler_reference_call_end_v1:
    .size __rapid_profiler_reference_call_v1, .-__rapid_profiler_reference_call_v1
    .popsection
"#,
    target = const core::mem::offset_of!(Frame, target),
    observed_target = const core::mem::offset_of!(Frame, observed_target),
    pre_call_rsp = const core::mem::offset_of!(Frame, pre_call_rsp),
    resumed_rsp = const core::mem::offset_of!(Frame, resumed_rsp),
    before_rax = const core::mem::offset_of!(ReferenceFrame, before_rax),
    before_rcx = const core::mem::offset_of!(ReferenceFrame, before_rcx),
    before_rdx = const core::mem::offset_of!(ReferenceFrame, before_rdx),
    after_rax = const core::mem::offset_of!(ReferenceFrame, after_rax),
    after_rcx = const core::mem::offset_of!(ReferenceFrame, after_rcx),
    after_rdx = const core::mem::offset_of!(ReferenceFrame, after_rdx),
    start_lo = const core::mem::offset_of!(ReferenceFrame, start_lo),
    start_hi = const core::mem::offset_of!(ReferenceFrame, start_hi),
    start_aux = const core::mem::offset_of!(ReferenceFrame, start_aux),
    end_lo = const core::mem::offset_of!(ReferenceFrame, end_lo),
    end_hi = const core::mem::offset_of!(ReferenceFrame, end_hi),
    end_aux = const core::mem::offset_of!(ReferenceFrame, end_aux),
    phase = const core::mem::offset_of!(ReferenceFrame, phase),
    returned = const RETURNED,
);
unsafe extern "C" {
    fn __rapid_profiler_reference_call_v1(
        frame: *mut Frame,
        data: *const u8,
        len: usize,
        reference: *mut ReferenceFrame,
    ) -> u64;
    static __rapid_profiler_reference_after_call_v1: u8;
    #[cfg(test)]
    static __rapid_profiler_reference_call_end_v1: u8;
    #[cfg(test)]
    static __rapid_profiler_reference_before_start_v1: u8;
    #[cfg(test)]
    static __rapid_profiler_reference_after_start_v1: u8;
    #[cfg(test)]
    static __rapid_profiler_reference_before_end_v1: u8;
    #[cfg(test)]
    static __rapid_profiler_reference_after_end_v1: u8;
}

fn reference_idle(frame: ReferenceFrame) -> Result<u64, GateError> {
    if frame
        != (ReferenceFrame {
            sequence: frame.sequence,
            ..ReferenceFrame::default()
        })
    {
        return Err(GateError::Completion);
    }
    Ok(frame.sequence)
}
pub(super) fn idle_checkpoint(sequence: u64) -> Result<(), GateError> {
    REFERENCE
        .try_with(|cell| {
            let previous = reference_idle(unsafe { cell.get().read() })?;
            // Legacy calls can occur between reference calls; their sequence is real,
            // not reset or confused with the independently starting raw ordinal.
            if previous > sequence {
                Err(GateError::Sequence)
            } else {
                Ok(())
            }
        })
        .map_err(|_| GateError::ThreadStorage)?
}
fn arm_reference(
    old: ReferenceFrame,
    id: Identity,
    sequence: u64,
    external_id: u64,
    leg: ReferenceLeg,
) -> Result<ReferenceFrame, GateError> {
    let previous = reference_idle(old)?;
    if sequence == 0 || sequence <= previous {
        return Err(GateError::Sequence);
    }
    Ok(ReferenceFrame {
        phase: ARMED,
        sequence,
        gate: id.gate,
        pid: id.pid,
        tid: id.tid,
        target: id.target,
        continuation: id.continuation,
        external_id,
        leg: leg as u64,
        canary: CANARY,
        ..ReferenceFrame::default()
    })
}
fn observed(
    f: ReferenceFrame,
    expected: ReferenceFrame,
    call: Frame,
    id: Identity,
    leg: ReferenceLeg,
    value: u64,
) -> Result<ReferenceInterval, GateError> {
    // Only the six read words, six preserved-register slots and actual return
    // marker may differ from the complete immutable armed identity.
    let metadata = ReferenceFrame {
        phase: ARMED,
        start_lo: 0,
        start_hi: 0,
        start_aux: 0,
        end_lo: 0,
        end_hi: 0,
        end_aux: 0,
        before_rax: 0,
        before_rcx: 0,
        before_rdx: 0,
        after_rax: 0,
        after_rcx: 0,
        after_rdx: 0,
        ..f
    };
    if metadata != expected
        || f.phase != RETURNED
        || f.leg != leg as u64
        || (f.gate, f.pid, f.tid, f.target, f.continuation)
            != (id.gate, id.pid, id.tid, id.target, id.continuation)
        || f.sequence != call.sequence
        || f.after_rax != value
    {
        return Err(GateError::Identity);
    }
    let word = |x| u32::try_from(x).map_err(|_| GateError::ReferenceClock);
    let start = ReferenceTimestamp {
        ticks: (u64::from(word(f.start_hi)?) << 32) | u64::from(word(f.start_lo)?),
        aux: word(f.start_aux)?,
    };
    let end = ReferenceTimestamp {
        ticks: (u64::from(word(f.end_hi)?) << 32) | u64::from(word(f.end_lo)?),
        aux: word(f.end_aux)?,
    };
    if start.aux != end.aux || end.ticks < start.ticks {
        return Err(GateError::ReferenceClock);
    }
    Ok(ReferenceInterval {
        leg,
        external_id: f.external_id,
        gate: id.gate,
        sequence: f.sequence,
        pid: id.pid,
        tid: id.tid,
        target: id.target,
        continuation: id.continuation,
        pre_call_rsp: call.pre_call_rsp,
        resumed_rsp: call.resumed_rsp,
        start,
        end,
    })
}

struct Flight {
    frame: *mut Frame,
    reference: *mut ReferenceFrame,
    finished: bool,
    _local: PhantomData<Rc<()>>,
}
impl Drop for Flight {
    fn drop(&mut self) {
        if !self.finished {
            // SAFETY: actual-thread private initialized cells remain live through
            // postflight; no references exist and no signal/fork/reentry is allowed.
            unsafe {
                (*self.frame).phase = POISONED;
                (*self.reference).phase = POISONED;
            }
        }
    }
}

// No caller can extract either result before its own postflight succeeds. This
// guard is !Send/!Sync and poisons BOTH slots on a failed source/totals check.
pub(in crate::frontend_native::always_on) struct Pending<'a, T> {
    gate: &'a CallGate,
    flight: Flight,
    frame: Frame,
    reference_frame: ReferenceFrame,
    call: T,
    interval: ReferenceInterval,
}
impl<T> Pending<'_, T> {
    pub(in crate::frontend_native::always_on) fn commit(
        mut self,
    ) -> Result<(T, ReferenceInterval), GateError> {
        let id = self.gate.identity()?;
        if (id.gate, id.pid, id.tid, id.target, id.continuation)
            != (
                self.interval.gate,
                self.interval.pid,
                self.interval.tid,
                self.interval.target,
                self.interval.continuation,
            )
            || unsafe { self.flight.frame.read() } != self.frame
            || unsafe { self.flight.reference.read() } != self.reference_frame
        {
            return Err(GateError::Identity);
        }
        // Every fallible check precedes the two local stores. No allocation,
        // external call or callback occurs between commit and result publication.
        unsafe {
            self.flight.frame.write(Frame {
                sequence: self.frame.sequence,
                ..Frame::default()
            });
            self.flight.reference.write(ReferenceFrame {
                sequence: self.frame.sequence,
                ..ReferenceFrame::default()
            });
        }
        self.flight.finished = true;
        Ok((self.call, self.interval))
    }
}

impl CallGate {
    /// Opt into the distinct real-CALL reference ABI. No existing descriptor is
    /// modified. Refuses absent TSC/RDTSCP/invariant-TSC/SSE2, missing AMD
    /// LFENCEAlwaysSerializing, advertised virtualization or disabled user TSC.
    /// Invocation rechecks the actual thread before entering the new stub.
    /// This does not admit migration, infer a frequency or establish accuracy.
    pub fn new_reference(certificate: &IntegerLeafCertificate) -> Result<Arc<Self>, GateError> {
        hardware::check()?;
        let mut gate = Self::new(certificate)?;
        Arc::get_mut(&mut gate)
            .ok_or(GateError::Descriptor)?
            .profile = GateProfile::ReferenceAmdV1;
        Ok(gate)
    }
    pub fn profile(&self) -> GateProfile {
        self.profile
    }
    pub(in crate::frontend_native::always_on) fn require_reference(&self) -> Result<(), GateError> {
        if self.profile != GateProfile::ReferenceAmdV1 {
            return Err(GateError::Profile);
        }
        self.identity()?;
        hardware::check()
    }
    pub(super) fn reference_continuation() -> u64 {
        core::ptr::addr_of!(__rapid_profiler_reference_after_call_v1) as usize as u64
    }

    // Only the two fixed owning wrappers select this private validator and leg.
    // It grants no arbitrary reference-call/receipt/postflight bypass API.
    unsafe fn reference_call<T>(
        &self,
        data: *const u8,
        len: usize,
        stack: &ReadableStack,
        external_id: u64,
        leg: ReferenceLeg,
        validate: fn(Frame, Identity, u64, &[u64]) -> Result<T, GateError>,
    ) -> Result<Pending<'_, T>, GateError> {
        self.require_reference()?;
        let id = self.identity()?;
        FRAME
            .try_with(|cell| {
                REFERENCE
                    .try_with(|reference| {
                        let raw = cell.get();
                        let reference = reference.get();
                        // Both preflight checks precede mutation; failure changes no slot.
                        let next = arm(unsafe { raw.read() }, id, stack.start, stack.end)?;
                        let armed = arm_reference(
                            unsafe { reference.read() },
                            id,
                            next.sequence,
                            external_id,
                            leg,
                        )?;
                        unsafe {
                            raw.write(next);
                            reference.write(armed);
                        }
                        let flight = Flight {
                            frame: raw,
                            reference,
                            finished: false,
                            _local: PhantomData,
                        };
                        // SAFETY: same admitted readonly ABI/source and no-signal contract
                        // as the default gate. The separate cells are exclusive and the
                        // certificate excludes RBX/R12. No Rust reference spans CALL.
                        let value = unsafe {
                            __rapid_profiler_reference_call_v1(raw, data, len, reference)
                        };
                        let frame = unsafe { raw.read() };
                        let reference_frame = unsafe { reference.read() };
                        let id = self.identity()?;
                        let call = validate(frame, id, value, &self.returns)?;
                        let interval = observed(reference_frame, armed, frame, id, leg, value)?;
                        Ok(Pending {
                            gate: self,
                            flight,
                            frame,
                            reference_frame,
                            call,
                            interval,
                        })
                    })
                    .map_err(|_| GateError::ThreadStorage)?
            })
            .map_err(|_| GateError::ThreadStorage)?
    }
    pub(in crate::frontend_native::always_on) unsafe fn invoke_reference(
        &self,
        data: *const u8,
        len: usize,
        stack: &ReadableStack,
        external_id: u64,
    ) -> Result<Pending<'_, CallResult>, GateError> {
        // SAFETY: caller is the attached facade, with all default gate obligations.
        unsafe {
            self.reference_call(
                data,
                len,
                stack,
                external_id,
                ReferenceLeg::Installed,
                resumed,
            )
        }
    }
    pub(in crate::frontend_native::always_on) unsafe fn invoke_original_reference(
        &self,
        data: *const u8,
        len: usize,
        stack: &ReadableStack,
        external_id: u64,
    ) -> Result<Pending<'_, OriginalCallResult>, GateError> {
        // SAFETY: only the owning preparation calls this, retaining Pending until
        // complete source verification after the actual return has succeeded.
        unsafe {
            self.reference_call(
                data,
                len,
                stack,
                external_id,
                ReferenceLeg::Original,
                |f, id, value, _| original_resumed(f, id, value),
            )
        }
    }
}

#[cfg(test)]
mod tests;
