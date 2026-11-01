//! Separate optional entry admission with permanent return observations.

use super::{ControlWriter, ControlledAction, ManagedCallback, ProbeControl};
use crate::contracts::Refusal;
use crate::scanner::ScanResult;
use iced_x86::{FlowControl, OpKind};

/// Exact role in a caller-certified, depth-one function interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryAdmissionRole {
    /// The sole original function entry; may bypass admission before capture.
    Entry,
    /// One literal original C3; always captures and invokes its callback.
    Return,
}

/// A typed optional entry or permanent return, bound to one original function.
///
/// Cloning retains the callback identity, never its unique write authority.
/// Return controls are born enabled and their writers are consumed internally.
/// There is no conversion from arbitrary controls, point actions or clocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryAdmissionAction {
    function_entry: u64,
    role: EntryAdmissionRole,
    controlled: ControlledAction,
}

impl EntryAdmissionAction {
    /// Create the optional entry and its unique controller-owned writer.
    /// A false early load or later dispatcher recheck admits no interval. A
    /// callback that actually runs follows the owner's admission protocol.
    ///
    /// # Safety
    /// Before any generated execution, the caller authenticates a complete
    /// scalar function with this sole entry, every literal RET, and a depth-one
    /// owned caller. Every RET is permanently observed, including bypassed
    /// invocations. Its callback authenticates the actual call position,
    /// function/control, thread, stack and continuation before distinguishing
    /// absence of entry from a live or returned receipt. An active receipt may
    /// never become bypass because the entry flag changed. Retained returned
    /// receipts keep their original owner across bypass, disable and rearm,
    /// until a genuine later entry or physical caller-return checkpoint.
    ///
    /// The complete physical call/RET census is independent of sparse observed
    /// intervals; missing, duplicate or stale roles poison/refuse. Callbacks
    /// preserve architectural/extended state and never unwind or reenter.
    /// Exclude nesting, recursion, signals, cancellation, fork, CET, source or
    /// return-word mutation, and foreign entry/resume. Keep the ordinary writable
    /// stack envelope and all source/input/callback/control/code owners alive
    /// through actual return, even when disabled. A store neither drains old
    /// callbacks nor permits executable retirement. This is not a point,
    /// pre-context scratch, call-pair, clock or arbitrary optional-hook contract.
    pub unsafe fn entry(
        function_entry: u64,
        callback: ManagedCallback,
        enabled: bool,
    ) -> (Self, ControlWriter) {
        let (control, writer) = ProbeControl::new_managed_bound(callback, enabled);
        (
            Self {
                function_entry,
                role: EntryAdmissionRole::Entry,
                controlled: ControlledAction {
                    logical_pc: function_entry,
                    control,
                },
            },
            writer,
        )
    }

    /// Create one permanent return callback. No writer escapes construction;
    /// planning authenticates this role against the original literal C3.
    pub fn mandatory_return(
        function_entry: u64,
        logical_pc: u64,
        callback: ManagedCallback,
    ) -> Self {
        let (control, writer) = ProbeControl::new_managed_bound(callback, true);
        drop(writer);
        Self {
            function_entry,
            role: EntryAdmissionRole::Return,
            controlled: ControlledAction {
                logical_pc,
                control,
            },
        }
    }

    /// Original sole function entry shared by all roles in this profile.
    pub fn function_entry(&self) -> u64 {
        self.function_entry
    }

    /// Original instruction head associated with this exact callback identity.
    pub fn logical_pc(&self) -> u64 {
        self.controlled.logical_pc
    }

    /// Exact role; only Entry receives an early gate.
    pub fn role(&self) -> EntryAdmissionRole {
        self.role
    }

    /// Read-only managed callback identity; cannot recover a writer.
    pub fn control(&self) -> &ProbeControl {
        &self.controlled.control
    }

    pub(crate) fn controlled(&self) -> &ControlledAction {
        &self.controlled
    }
}

/// Structural source/role checks only. The unsafe caller still certifies the
/// complete scalar CFG, external entries, all planned RETs and pairing runtime.
pub(crate) fn validate(scan: &ScanResult, actions: &[EntryAdmissionAction]) -> Result<(), Refusal> {
    let first = scan.instructions().first().ok_or(Refusal::InvalidRange)?;
    let base = first.address();
    if base == 0 || !(1..=256).contains(&scan.snapshot().len()) {
        return Err(Refusal::InvalidRange);
    }
    if !(1..=5).contains(&actions.len()) {
        return Err(Refusal::InvalidPlan);
    }
    let mut returns = 0;
    for item in scan.instructions() {
        let instruction = item.instruction();
        match instruction.flow_control() {
            FlowControl::Next => {}
            FlowControl::Return => {
                if scan.snapshot()[item.offset()..item.offset() + item.len()] != [0xc3] {
                    return Err(Refusal::InvalidPlan);
                }
                returns += 1;
            }
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if instruction.op0_kind() != OpKind::NearBranch64
                    || instruction.near_branch_target() == base
                    || scan.site(instruction.near_branch_target()).is_none()
                {
                    return Err(Refusal::InvalidPlan);
                }
            }
            _ => return Err(Refusal::InvalidPlan),
        }
    }
    if !(1..=4).contains(&returns) {
        return Err(Refusal::InvalidPlan);
    }
    for (index, action) in actions.iter().enumerate() {
        if action.function_entry != base
            || !action.control().is_managed_bound()
            || (index > 0 && actions[index - 1].logical_pc() >= action.logical_pc())
            || actions[..index]
                .iter()
                .any(|prior| prior.control() == action.control())
        {
            return Err(Refusal::InvalidPlan);
        }
        let original = scan
            .instructions()
            .iter()
            .find(|item| item.address() == action.logical_pc())
            .ok_or(Refusal::NotInstructionHead)?;
        match action.role {
            EntryAdmissionRole::Entry
                if action.logical_pc() == base
                    && original.instruction().flow_control() != FlowControl::Return => {}
            EntryAdmissionRole::Return
                if action.logical_pc() != base
                    && original.instruction().flow_control() == FlowControl::Return
                    && action.control().is_enabled() => {}
            _ => return Err(Refusal::InvalidPlan),
        }
    }
    Ok(())
}
