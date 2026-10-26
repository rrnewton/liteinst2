//! Opt-in singleton signal transaction. Configuration is not evidence of a
//! delivered frame or return: every transition below retains actual native
//! observations in the owner's independent journal before interpreting them.
use super::super::signal_journal::{SignalJournalFact, SignalJournalPhase};
use super::super::trusted::TaskStateSnapshot;
use super::*;
use crate::lifecycle::ObligationRecord;
use std::ops::Range;
use std::sync::Arc;

mod delivery;
mod extent;
mod frame;
mod refresh;
mod returns;
mod setup;

pub(super) struct SignalTransaction {
    profile: DynamicSignalProfile,
    metadata: DynamicExceptionMetadata,
    action_installed: bool,
    alternate_installed: bool,
    pending: Option<PendingDelivery>,
    live: Option<LiveFrame>,
    retired: Option<LiveFrame>,
    delivered: bool,
    returned: bool,
    frame_storage: Option<frame::FrameStorage>,
    extent: extent::NativeExtent,
}

struct PendingDelivery {
    token: SignalDeliveryToken,
    event: DynamicEvent,
    obligation: ObligationRecord,
    observed: ObservedStop,
}

struct LiveFrame {
    captured: frame::CapturedFrame,
    facts: Arc<census::FrameFacts>,
    origins: Vec<OriginId>,
    interrupted: ObservedStop,
}

impl SignalTransaction {
    pub(super) fn new(
        owner: &Owner,
        profile: DynamicSignalProfile,
        boot: &super::super::bootstrap::BootstrapMm,
        until: Instant,
    ) -> Result<Self, GateError> {
        let receipt = owner.anchor_receipt.as_ref().ok_or(GateError::Refused(
            "signal launch has no original metadata receipt",
        ))?;
        if !owner.anchor_exit_authenticated
            || receipt.session() != owner.session
            || receipt.tid() != owner.pid
        {
            return Err(GateError::Refused(
                "signal launch has no authenticated actual exec EXIT",
            ));
        }
        validate_stack(&boot.mappings, &profile.normal_stack)?;
        if let Some(range) = &profile.alternate_stack {
            validate_stack(&boot.mappings, range)?;
        }
        let metadata = receipt.metadata();
        let extent = extent::NativeExtent::acquire(owner, boot, until)?;
        Ok(Self {
            profile,
            metadata: DynamicExceptionMetadata {
                trapno: metadata.trapno,
                error_code: metadata.error_code,
                cr2: metadata.cr2,
            },
            action_installed: false,
            alternate_installed: false,
            pending: None,
            live: None,
            retired: None,
            delivered: false,
            returned: false,
            frame_storage: Some(frame::FrameStorage::new()?),
            extent,
        })
    }
    pub(super) fn pending_until(&self) -> Option<Instant> {
        self.pending.as_ref().map(|pending| pending.token.until)
    }
    pub(super) fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub(super) fn is_setup_ready(&self) -> bool {
        self.action_installed
            && (self.profile.alternate_stack.is_none() || self.alternate_installed)
    }
    pub(super) fn initial_storage_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self
                .frame_storage
                .as_ref()
                .map_or(0, |storage| storage.retained_bytes())
    }
    pub(super) fn xstate_extent(&self) -> usize {
        self.extent.bytes()
    }
    pub(super) fn verify_extent(
        &self,
        token: &DynamicStop,
        identity: DynamicTask,
        state: &TaskStateSnapshot,
    ) -> Result<(), GateError> {
        self.extent.verify(token, identity, state)
    }
    pub(super) fn verify_event_extent(
        &self,
        event: &DynamicEvent,
        state: &TaskStateSnapshot,
    ) -> Result<(), GateError> {
        let token = event.stop_token().ok_or(GateError::Refused(
            "signal extent observation has no real stop token",
        ))?;
        let identity = event.task.ok_or(GateError::Refused(
            "signal extent observation has no task identity",
        ))?;
        self.verify_extent(token, identity, state)
    }
}

fn validate_stack(mappings: &[MemoryMapping], range: &Range<u64>) -> Result<(), GateError> {
    // This finite profile accepts complete private RW, nonexecutable ranges.
    // A merely overlapping VMA or a writable alias is not a complete witness.
    let mut next = range.start;
    for mapping in mappings
        .iter()
        .filter(|mapping| mapping.start < range.end && range.start < mapping.end)
    {
        if mapping.start > next || !mapping.permissions.as_bytes().starts_with(b"rw-p") {
            return Err(GateError::Refused(
                "signal stack is not completely private RW/NX",
            ));
        }
        next = next.max(mapping.end.min(range.end));
    }
    if next != range.end {
        return Err(GateError::Refused("signal stack range has an unmapped gap"));
    }
    Ok(())
}

fn dynamic_state(observed: &ObservedStop) -> DynamicAdmissionState {
    DynamicAdmissionState {
        task: observed.task,
        registers: observed.registers,
        xstate: observed.xstate.clone(),
        signal_mask: observed.signal_mask,
    }
}

fn raw_state(observed: &ObservedStop) -> TaskStateSnapshot {
    TaskStateSnapshot {
        registers: observed.registers,
        xstate: observed.xstate.clone(),
        mask: observed.signal_mask,
    }
}
