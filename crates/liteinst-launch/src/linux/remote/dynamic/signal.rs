//! Explicit finite signal profile and immutable original-signal evidence.
//! These values never grant raw ptrace, frame-write or publication authority.
use super::*;
use crate::gate::{GateError, ImageFacts};
use crate::selected::SelectedInput;

#[cfg(test)]
mod tests;

/// Exact declared edits made by original handler instructions.
/// Other frame bytes, including DF/TF/RF and all other FP state, must agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSignalFrameEdits {
    /// One declared original landing head, protected before handler release.
    pub landing_pc: u64,
    /// Exact final saved RAX; this is not a syscall errno interpretation.
    pub rax: u64,
    /// Only CF may be cleared; no other saved RFLAGS bit may change.
    pub clear_carry: bool,
    /// Exact final eight-byte mask, excluding unmaskable signals.
    pub signal_mask: u64,
    /// Exact final saved XMM0 bytes; the other extended state is unchanged.
    pub xmm0: [u8; 16],
}

/// One queued native RT delivery and one genuine return in a singleton mm.
/// Original setup performs the exact declared native action and optional stack
/// installation. No action, stack or signal-disposition mutation is synthetic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSignalProfile {
    /// Application RT signal (34 through 64); libc-reserved signals are excluded.
    pub signal: u8,
    /// Exact original sigaction blocking mask; no unmaskable bits are allowed.
    pub action_mask: u64,
    /// Exact SI_QUEUE payload. Sender identity remains actual kernel evidence.
    pub queued_value: u64,
    /// First original handler instruction, initially NX at delivery.
    pub handler: u64,
    /// Original restorer head containing the selected native rt_sigreturn.
    pub restorer: u64,
    /// Exact original closed-user delivery boundary.
    pub delivery_pc: u64,
    /// Complete declared private normal-stack range, with no external writer.
    pub normal_stack: Range<u64>,
    /// Optional private non-autodisarm alternate stack, installed by original code.
    pub alternate_stack: Option<Range<u64>>,
    /// None preserves the whole projected frame; Some permits only these edits.
    pub frame_edits: Option<DynamicSignalFrameEdits>,
}

impl DynamicSignalProfile {
    pub(super) fn validate(
        &self,
        options: &DynamicAdmissionOptions,
        facts: &[ImageFacts],
    ) -> Result<(), GateError> {
        if options.lifecycle != DynamicLifecycleOptions::default()
            || !(34..=64).contains(&self.signal)
            || self.action_mask & unmaskable() != 0
            || !valid_stack(&self.normal_stack)
            || self
                .alternate_stack
                .as_ref()
                .is_some_and(|range| !valid_stack(range) || overlaps(range, &self.normal_stack))
        {
            return Err(GateError::Refused(
                "signal profile is not an exact singleton stack profile",
            ));
        }
        let head = |pc: u64| {
            pc != 0
                && facts
                    .iter()
                    .filter(|fact| {
                        let start = fact.start;
                        start
                            .checked_add(fact.bytes.len() as u64)
                            .is_some_and(|end| start <= pc && pc < end && fact.heads.contains(&pc))
                    })
                    .count()
                    == 1
        };
        if !head(self.handler)
            || !head(self.restorer)
            || !head(self.delivery_pc)
            || self.handler == self.restorer
            || self.handler == self.delivery_pc
            || self.restorer == self.delivery_pc
        {
            return Err(GateError::Refused(
                "signal profile lacks distinct exact original heads",
            ));
        }
        let encoding = |pc: u64, wanted: &[u8]| {
            facts.iter().any(|fact| {
                fact.heads.contains(&pc)
                    && pc
                        .checked_sub(fact.start)
                        .and_then(|offset| usize::try_from(offset).ok())
                        .and_then(|offset| {
                            fact.bytes.get(offset..offset.checked_add(wanted.len())?)
                        })
                        == Some(wanted)
            })
        };
        if !encoding(self.handler, &[0x0f, 0xa2])
            || !encoding(self.delivery_pc, &[0xeb, 0xfe])
            || !encoding(self.restorer, &[0xb8, 15, 0, 0, 0, 0x0f, 0x05])
            || !self.restorer.checked_add(5).is_some_and(head)
        {
            return Err(GateError::Refused(
                "signal profile lacks fixed CPUID/loop/restorer geometry",
            ));
        }
        for fact in facts {
            let end = fact
                .start
                .checked_add(fact.bytes.len() as u64)
                .ok_or(GateError::Refused("signal source range overflows"))?;
            let source = fact.start..end;
            if overlaps(&source, &self.normal_stack)
                || self
                    .alternate_stack
                    .as_ref()
                    .is_some_and(|stack| overlaps(&source, stack))
            {
                return Err(GateError::Refused("signal stack overlaps original source"));
            }
        }
        if let Some(edits) = &self.frame_edits {
            if !head(edits.landing_pc)
                || edits.landing_pc == self.delivery_pc
                || edits.landing_pc == self.handler
                || edits.landing_pc == self.restorer
                || edits.signal_mask & unmaskable() != 0
            {
                return Err(GateError::Refused(
                    "signal edits exceed the exact declared profile",
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn unmaskable() -> u64 {
    (1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1))
}
fn valid_stack(range: &Range<u64>) -> bool {
    range.start >= 4096
        && range.start < range.end
        && range.end < (1_u64 << 47)
        && range.start % 4096 == 0
        && range.end % 4096 == 0
        && range.end - range.start >= 4 * 4096
        && range.end - range.start <= 1024 * 1024
}
pub(super) fn overlaps(left: &Range<u64>, right: &Range<u64>) -> bool {
    left.start < right.end && right.start < left.end
}

/// Exact original exception metadata exposed in a later real native frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicExceptionMetadata {
    /// Saved x86 exception vector from the authenticated original context.
    pub trapno: u64,
    /// Saved x86 exception error code, including a genuine zero value.
    pub error_code: u64,
    /// Saved page-fault address field from the original context.
    pub cr2: u64,
}

/// Opaque same-deadline delivery identity. Cloning does not allow replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalDeliveryToken {
    pub(super) stop: DynamicStop,
    pub(super) task: DynamicTask,
    pub(super) plan: u64,
    pub(super) serial: u64,
    pub(super) until: Instant,
}

/// A real held application signal, pending the one supported original delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSignalPending {
    /// Single-use identity tied to this owned stop and its original deadline.
    pub token: SignalDeliveryToken,
    /// Complete authenticated interrupted state at the pending delivery stop.
    pub state: DynamicAdmissionState,
    /// Actual native signal information at that stop.
    pub signal: DynamicSignalInfo,
}

/// Non-reused identity of one actual live frame; never a memory-write permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalFrameId {
    /// Session identity; a frame from another session cannot be substituted.
    pub session: u64,
    /// Non-reused frame sequence within the session.
    pub serial: u64,
}

/// Complete bounded frame bytes, including native padding and extended state.
/// Addresses are original process addresses, not local pointers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSignalFrame {
    /// Identity of the actual frame to which these bytes belong.
    pub id: SignalFrameId,
    /// Immutable census version for this retained frame observation.
    pub version: u64,
    /// Original address of the beginning of the retained frame image.
    pub address: u64,
    /// Original address of the frame's floating-point state payload.
    pub fpstate: u64,
    /// Complete retained image beginning at `address`, including native padding.
    pub bytes: Vec<u8>,
}

/// Handler entry before its first original instruction. The raw and projected
/// frames are intentionally distinct observations; projection is not a claim
/// that the original kernel frame was already transparent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSignalEntry {
    /// Complete original state interrupted by the delivered signal.
    pub interrupted: DynamicAdmissionState,
    /// Actual first NX fault, before private work; RF is retained exactly.
    pub handler_fetch: DynamicAdmissionState,
    /// Actual owned handler-head INT3 before RIP-only neutral restoration.
    pub handler_guard: DynamicAdmissionState,
    /// Actual signal information associated with the owned handler guard stop.
    pub handler_guard_signal: DynamicSignalInfo,
    /// Complete logical head state after the genuine neutral bridge.
    pub handler: DynamicAdmissionState,
    /// Actual information for the original application signal being delivered.
    pub signal: DynamicSignalInfo,
    /// Authenticated original exception fields used for the three-word projection.
    pub original_metadata: DynamicExceptionMetadata,
    /// Actual kernel-constructed frame before metadata projection.
    pub raw_frame: DynamicSignalFrame,
    /// Application-visible frame after the exact three-word projection.
    pub projected_frame: DynamicSignalFrame,
}

/// Actual native syscall EXIT information retained without semantic relabeling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicSignalReturnInfo {
    /// Architecture identifier reported by `PTRACE_GET_SYSCALL_INFO`.
    pub architecture: u32,
    /// Instruction pointer reported at the actual return EXIT stop.
    pub instruction_pointer: u64,
    /// Stack pointer reported at that stop.
    pub stack_pointer: u64,
    /// Raw EXIT result bits, retained even when restored RAX resembles an errno.
    pub result: i64,
    /// Kernel-reported error flag, without reinterpreting restored application state.
    pub is_error: bool,
}

/// Genuine rt_sigreturn and a rearmed original landing. Restored RAX, RIP,
/// RCX/R11 and orig_rax are not an ordinary selected-SYSCALL completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSignalReturn {
    /// Identity of the frame consumed by the actual return.
    pub frame: SignalFrameId,
    /// Final authenticated frame version consumed by the return.
    pub version: u64,
    /// Selected original `rt_sigreturn` input before kernel entry.
    pub input: SelectedInput,
    /// Complete state at the genuine syscall ENTRY stop.
    pub entry: DynamicAdmissionState,
    /// Complete restored state observed at the genuine return EXIT stop.
    /// This historical observation retains its generation before the single
    /// source rebind that follows the return. When this event is delivered,
    /// the current held task has generation exactly one greater; its task,
    /// process, address space and complete native state are unchanged.
    pub returned: DynamicAdmissionState,
    /// Raw native EXIT information accompanying the restored state.
    pub information: DynamicSignalReturnInfo,
}

/// Only the opt-in signal constructor returns this evidence-bearing failure.
/// An absent archive means validation/allocation failed before any anchor existed.
pub struct DynamicSignalLaunchFailure {
    /// Original constructor failure, independent of later cleanup observations.
    pub error: GateError,
    /// Retained anchor reader when its archive existed before the failure.
    pub anchor: Option<AnchorReader>,
    pub(super) native_owner_started: bool,
}
impl std::fmt::Debug for DynamicSignalLaunchFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynamicSignalLaunchFailure")
            .field("error", &self.error)
            .field("anchor_retained", &self.anchor.is_some())
            .field("native_owner_started", &self.native_owner_started)
            .finish()
    }
}
impl DynamicSignalLaunchFailure {
    /// Whether creation of the original tracer thread succeeded. This does not
    /// assert that a child existed or that cleanup completed. When true, the
    /// retained reader's cleanup status is the independent owner observation.
    pub fn native_owner_started(&self) -> bool {
        self.native_owner_started
    }
    pub(super) fn before_anchor(error: impl Into<GateError>) -> Self {
        Self {
            error: error.into(),
            anchor: None,
            native_owner_started: false,
        }
    }
}

/// Fixed pre-clone storage certificate. This reserves actual anchor/journal
/// buffers and explicitly bounded additional retained frame/public-state copies.
/// It grants no native authority and cannot replenish the lifetime budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SignalBudget {
    pub(super) bytes: usize,
}
impl SignalBudget {
    pub(super) fn new(
        facts: &[ImageFacts],
        options: &DynamicAdmissionOptions,
    ) -> Result<Self, GateError> {
        let initial = facts
            .iter()
            .try_fold(0_usize, |sum, fact| {
                sum.checked_add(fact.bytes.len().checked_mul(2)?)?
                    .checked_add(fact.heads.len().checked_mul(512)?)
            })
            .and_then(|value| value.checked_add(MAX_XSTATE.checked_mul(8)?))
            .and_then(|value| value.checked_add(64 * 1024))
            .ok_or(GateError::Refused("signal startup evidence size overflows"))?;
        // The journal itself preallocates both retained raw buffers and one
        // returned copy per slot. The extra copies here are fixed live frame
        // images (projected/final/public) and public complete-state receipts.
        let bytes = launch::anchor::ANCHOR_EVIDENCE_BOUND
            .checked_add(owner::signal_journal::evidence_bound())
            .and_then(|value| value.checked_add(8 * owner::signal_journal::FRAME_BOUND))
            .and_then(|value| {
                value.checked_add(16 * (MAX_XSTATE + std::mem::size_of::<DynamicAdmissionState>()))
            })
            .ok_or(GateError::Refused("signal evidence envelope overflows"))?;
        if initial
            .checked_add(bytes)
            .is_none_or(|total| total > options.limits.source_fact_bytes)
        {
            return Err(GateError::Refused(
                "signal startup exceeds the unchanged lifetime source budget",
            ));
        }
        Ok(Self { bytes })
    }
}
