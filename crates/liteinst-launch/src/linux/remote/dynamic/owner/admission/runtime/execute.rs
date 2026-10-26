//! Runtime command dispatch. Classification proposes a path; each path then
//! authenticates actual native/source custody before any effect or completion.
use super::super::runtime_capture::CapturedRuntimeRead;
use super::super::runtime_instruction::{CandidateKind, DebugDisposition, classify};
use super::super::source_identity::SourceReadProgress;
use super::*;
use crate::selected::SyscallAliases;

const QUERY_BYTES: usize = 64 * 1024;

impl RuntimeOwner {
    pub(in crate::linux::remote::dynamic::owner) fn provider_expired(&self, now: Instant) -> bool {
        self.selected_deadline().is_some_and(|until| now >= until)
    }

    pub(super) fn execute(
        &mut self,
        owner: &mut Owner,
        request: AdmissionRequest,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        if self.stage != RuntimeStage::Ready || !self.ready_issued {
            return Err(GateError::Refused("runtime startup is incomplete"));
        }
        owner.time_left(until, "runtime admission command")?;
        if self.selected_pending.is_some()
            && !matches!(&request, AdmissionRequest::CompleteRuntime { .. })
        {
            return Err(GateError::Refused(
                "runtime provider invocation remains pending",
            ));
        }
        match request {
            AdmissionRequest::Advance => self.advance(owner, until),
            AdmissionRequest::CompleteRuntime { token, decision } => {
                self.complete_selected(owner, token, decision, until)
            }
            AdmissionRequest::State(task) => self.query(owner, task, None, until),
            AdmissionRequest::Memory { task, address, len } => {
                self.query(owner, task, Some((address, len)), until)
            }
            AdmissionRequest::Metrics => {
                let census = self
                    .census
                    .as_ref()
                    .ok_or(GateError::Refused("runtime census custody absent"))?;
                self.metrics.retained_origins = census.rows().count();
                self.metrics.continuation_history_records = census.history().len();
                self.metrics.charged_source_bytes = census.charged().source_fact_bytes;
                self.metrics.retained_source_bytes = census.used().source_fact_bytes;
                self.metrics.pages.admitted_pages =
                    self.pages.iter().filter(|page| page.executable).count();
                self.metrics.pages.untouched_pages =
                    self.pages.len() - self.metrics.pages.admitted_pages;
                let boot = self
                    .bootstrap
                    .as_ref()
                    .and_then(PreparedInitialBootstrap::completed)
                    .ok_or(GateError::Refused("runtime bootstrap custody absent"))?;
                self.metrics.bootstrap_xstate_bytes = boot.evidence.exec_event.xstate.len()
                    + boot.evidence.exec_exit.xstate.len()
                    + boot.evidence.entry_trap.xstate.len()
                    + boot.evidence.restored_entry.xstate.len();
                Ok(AdmissionReply::Metrics(self.metrics.clone()))
            }
            _ => Err(GateError::Refused(
                "runtime request requires an unqualified profile transition",
            )),
        }
    }

    fn advance(&mut self, owner: &mut Owner, until: Instant) -> Result<AdmissionReply, GateError> {
        loop {
            owner.time_left(until, "runtime original instruction dispatch")?;
            let census = self
                .census
                .as_ref()
                .ok_or(GateError::Refused("runtime census custody absent"))?;
            let origin = self
                .initial_origin
                .ok_or(GateError::Refused("runtime current origin absent"))?;
            let before = census.current_observation(origin).map_err(census_error)?;
            let page = before.logical_pc & !4095;
            let entry = self
                .pages
                .binary_search_by_key(&page, |page| page.address)
                .ok()
                .and_then(|index| self.pages.get(index))
                .ok_or(GateError::Refused(
                    "runtime actual PC lacks a captured source window",
                ))?;
            if entry.executable {
                return Err(GateError::Refused(
                    "runtime dispatcher expected all original pages NX",
                ));
            }
            let index = entry.window;
            let window = self
                .sources
                .window(index)
                .ok_or(GateError::Refused("runtime source window is incomplete"))?;
            // Absent describes the required ordinary profile, not an observed
            // debugger state. The selected/native adapters perform all actual
            // current source and architectural-control reads independently.
            let candidate = classify(
                window.snapshot,
                &before.registers,
                DebugDisposition::Absent,
                &SyscallAliases::default(),
            )
            .map_err(|_| GateError::Refused("runtime actual instruction is unqualified"))?;
            if matches!(candidate.kind(), CandidateKind::Selected(_)) {
                return self
                    .prepare_selected(owner, index, until)
                    .map(AdmissionReply::RuntimeProvider);
            }
            self.ordinary(owner, index, until)?;
        }
    }

    /// Read-only diagnostics have prospective bounded response storage. Their
    /// fresh actual-state check grants no release or saved-context completeness.
    fn query(
        &mut self,
        owner: &Owner,
        task: TaskId,
        memory: Option<(u64, usize)>,
        until: Instant,
    ) -> Result<AdmissionReply, GateError> {
        let length = memory.map_or(MAX_XSTATE, |(_, length)| length);
        if length == 0
            || length > QUERY_BYTES
            || memory.is_some_and(|(address, length)| address.checked_add(length as u64).is_none())
        {
            return Err(GateError::Refused(
                "runtime diagnostic byte range exceeds its bound",
            ));
        }
        let census = self
            .census
            .as_mut()
            .ok_or(GateError::Refused("runtime census custody absent"))?;
        let origin = self
            .initial_origin
            .ok_or(GateError::Refused("runtime current origin absent"))?;
        if census
            .current_observation(origin)
            .map_err(census_error)?
            .task
            .task
            != task
        {
            return Err(GateError::Refused("runtime diagnostic names another task"));
        }
        let bytes = add(
            add(length, size_of::<DynamicAdmissionState>())?,
            add(
                CapturedRuntimeRead::temporary_bytes(),
                size_of::<SourceReadProgress>(),
            )?,
        )?;
        let charge = BudgetCharge {
            source_fact_bytes: bytes,
            ..BudgetCharge::default()
        };
        let reservation = census.reserve(charge).map_err(census_error)?;
        let mut output = storage(length)?;
        if output.capacity() != length {
            return Err(GateError::Refused(
                "runtime diagnostic capacity exceeds reservation",
            ));
        }
        output.resize(length, 0);
        let before = census.current_observation(origin).map_err(census_error)?;
        let native = self
            .native
            .as_ref()
            .ok_or(GateError::Refused("runtime native custody absent"))?;
        let stop = native.admission_current(task)?;
        let island = &self
            .bootstrap
            .as_ref()
            .and_then(PreparedInitialBootstrap::completed)
            .ok_or(GateError::Refused("runtime bootstrap custody absent"))?
            .island;
        let reader = self
            .sources
            .runtime_read(owner, native, island, &stop, before, until)?;
        let reply = if let Some((address, _)) = memory {
            let mut progress = SourceReadProgress::default();
            reader.read_memory_into(address, &mut output, &mut progress)?;
            if !progress.complete || progress.copied_bytes != length {
                return Err(GateError::Refused(
                    "runtime diagnostic memory read is incomplete",
                ));
            }
            AdmissionReply::Bytes(output)
        } else {
            if before.xstate.len() > output.len() {
                return Err(GateError::Refused(
                    "runtime diagnostic state exceeds reservation",
                ));
            }
            output[..before.xstate.len()].copy_from_slice(&before.xstate);
            output.truncate(before.xstate.len());
            AdmissionReply::State(DynamicAdmissionState {
                task: before.task,
                registers: before.registers,
                xstate: output,
                signal_mask: before.signal_mask,
            })
        };
        owner.time_left(until, "runtime diagnostic response")?;
        census
            .account_external(reservation, charge)
            .map_err(census_error)?;
        census
            .finish_reservation(reservation)
            .map_err(census_error)?;
        Ok(reply)
    }
}
