//! Read-only ENTRY input recheck and reservation gates around native effects.
use super::super::super::bootstrap::{BootstrapEffect, ReplacedBootstrapObservation};
use super::super::super::exec_journal::ExecJournalObserver;
use super::super::super::selected::{ExecInvocation, ExecObservation, ExecRelease};
use super::inputs::{InputMemory, InputReadOutcome};
use super::*;

pub(super) struct ExecObserver<'a> {
    pub(super) journal: ExecJournalObserver,
    pub(super) census: &'a ResumeCensus,
    pub(super) reservation: Reservation,
    pub(super) future: BudgetCharge,
    pub(super) inputs: &'a mut ExecInputs,
    pub(super) input: &'a SelectedInput,
    pub(super) forbidden: &'a [Range<u64>],
    pub(super) previous: DynamicTask,
    pub(super) until: Instant,
}

fn native_error(error: GateError) -> LaunchError {
    match error {
        GateError::Control(error) => error,
        _ => LaunchError::Invalid("exec original input recheck refused"),
    }
}

pub(super) fn read_input(tid: i32, address: u64, destination: &mut [u8]) -> InputReadOutcome {
    match read_memory(tid, address, destination.len()) {
        Ok(bytes) if bytes.len() <= destination.len() => {
            destination[..bytes.len()].copy_from_slice(&bytes);
            InputReadOutcome {
                copied: bytes.len(),
                error: None,
            }
        }
        Ok(_) => InputReadOutcome {
            copied: 0,
            error: Some(LaunchError::Invalid("exec input reader exceeded its bound")),
        },
        // This existing reader returns all-or-error. It does not expose a
        // failed PEEK prefix; never claim that discarded prefix was observed.
        Err(error) => InputReadOutcome {
            copied: 0,
            error: Some(error),
        },
    }
}

impl ExecObserver<'_> {
    fn check_reserved(&self) -> Result<(), LaunchError> {
        control_remaining(self.until)?;
        self.census
            .check_reserved(self.reservation, self.future)
            .map_err(|_| LaunchError::Invalid("exec remaining lifetime reservation differs"))
    }
}

impl ExecObservation for ExecObserver<'_> {
    fn prepared(
        &mut self,
        owner: &Owner,
        invocation: &ExecInvocation<'_>,
        until: Instant,
    ) -> Result<(), LaunchError> {
        self.check_reserved()?;
        if until != self.until
            || invocation.stop.identity != self.previous
            || invocation.input != self.input
            || !self.inputs.capture_complete()
            || self.inputs.recheck_complete()
        {
            return Err(LaunchError::Invalid(
                "exec input observer preparation differs",
            ));
        }
        ExecObservation::prepared(&mut self.journal, owner, invocation, until)
    }

    fn raw(&mut self, owner: &Owner, tid: i32, status: i32) -> Result<(), LaunchError> {
        ExecObservation::raw(&mut self.journal, owner, tid, status)
    }

    fn entry(
        &mut self,
        event: &DynamicEvent,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        ExecObservation::entry(&mut self.journal, event, state)?;
        self.check_reserved()?;
        let stop = event
            .stop_token()
            .ok_or(LaunchError::Invalid("exec ENTRY has no token"))?;
        if event.task != Some(self.previous)
            || stop.task != Some(self.previous.task)
            || !matches!(event.kind, DynamicEventKind::SyscallEntry { number, .. }
                if number == libc::SYS_execve as u64)
        {
            return Err(LaunchError::Invalid(
                "exec inputs cannot be read outside original ENTRY",
            ));
        }
        let maps = read_maps(event.tid)?;
        self.inputs
            .recheck(
                self.input,
                InputMemory {
                    task: self.previous,
                    stop,
                    mappings: &maps,
                    forbidden: self.forbidden,
                    until: self.until,
                },
                |address, destination| read_input(event.tid, address, destination),
            )
            .map_err(native_error)?;
        if TaskStateSnapshot::read(event.tid)? != *state {
            return Err(LaunchError::Invalid(
                "exec input reread changed the held ENTRY state",
            ));
        }
        self.check_reserved()
    }

    fn replaced(
        &mut self,
        previous: DynamicTask,
        event: &DynamicEvent,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        ExecObservation::replaced(&mut self.journal, previous, event, state)
    }

    fn exit(&mut self, event: &DynamicEvent, state: &TaskStateSnapshot) -> Result<(), LaunchError> {
        ExecObservation::exit(&mut self.journal, event, state)
    }

    fn release_attempt(
        &mut self,
        phase: ExecRelease,
        stop: &DynamicStop,
    ) -> Result<(), LaunchError> {
        self.check_reserved()?;
        if matches!(phase, ExecRelease::Entry | ExecRelease::ExecEvent)
            && !self.inputs.recheck_complete()
        {
            return Err(LaunchError::Invalid(
                "exec ENTRY input reread is incomplete",
            ));
        }
        ExecObservation::release_attempt(&mut self.journal, phase, stop)
    }

    fn release_succeeded(
        &mut self,
        phase: ExecRelease,
        stop: &DynamicStop,
    ) -> Result<(), LaunchError> {
        ExecObservation::release_succeeded(&mut self.journal, phase, stop)
    }

    fn failed(&mut self, error: &LaunchError) {
        ExecObservation::failed(&mut self.journal, error);
    }
}

impl ReplacedBootstrapObservation for ExecObserver<'_> {
    fn before_effect(&mut self, effect: BootstrapEffect) -> Result<(), LaunchError> {
        self.check_reserved()?;
        ReplacedBootstrapObservation::before_effect(&mut self.journal, effect)
    }

    fn effect_complete(
        &mut self,
        effect: BootstrapEffect,
        result: Option<u64>,
    ) -> Result<(), LaunchError> {
        ReplacedBootstrapObservation::effect_complete(&mut self.journal, effect, result)
    }

    fn raw(&mut self, owner: &Owner, tid: i32, status: i32) -> Result<(), LaunchError> {
        ReplacedBootstrapObservation::raw(&mut self.journal, owner, tid, status)
    }

    fn entry_trap(&mut self, state: &TaskStateSnapshot) -> Result<(), LaunchError> {
        ReplacedBootstrapObservation::entry_trap(&mut self.journal, state)
    }

    fn restored_entry(
        &mut self,
        stop: &AdmissionStop,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError> {
        ReplacedBootstrapObservation::restored_entry(&mut self.journal, stop, state)
    }

    fn complete(&mut self, bootstrap: &BootstrapMm) -> Result<(), LaunchError> {
        // Completion is evidence about effects that already happened. Record
        // it before a remaining-budget/deadline gate can stop later work.
        ReplacedBootstrapObservation::complete(&mut self.journal, bootstrap)?;
        self.check_reserved()
    }

    fn failed(&mut self, error: &LaunchError) {
        ReplacedBootstrapObservation::failed(&mut self.journal, error);
    }
}
