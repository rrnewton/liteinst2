//! Compose source, reservation and diagnostic obligations at real boundaries.
use super::*;
use crate::linux::remote::dynamic::owner::bootstrap::Request;
use crate::linux::remote::dynamic::owner::kernel_journal::RuntimeKernelReleaseSource;

pub(super) struct KernelObserver<'a, 'binding> {
    pub(super) sources: &'a PreparedInitialSources,
    pub(super) binding: &'a RuntimeKernelBinding<'binding>,
    pub(super) census: &'a ResumeCensus,
    pub(super) reservation: Reservation,
    pub(super) remaining: BudgetCharge,
    pub(super) storage: &'a mut KernelSourceChecks,
    pub(super) pages: &'a mut [RuntimePage],
    pub(super) sink: &'a mut RuntimeJournalSink,
}
impl KernelObserver<'_, '_> {
    fn identity(&self, identity: &RuntimeKernelIdentity) -> Result<(), LaunchError> {
        if identity != self.binding.identity() {
            return Err(LaunchError::Invalid(
                "runtime kernel observer identity differs",
            ));
        }
        Ok(())
    }
    fn remaining(
        &self,
        owner: &Owner,
        identity: &RuntimeKernelIdentity,
        until: Instant,
    ) -> Result<(), LaunchError> {
        self.identity(identity)?;
        if until != self.binding.until() {
            return Err(LaunchError::Invalid(
                "runtime kernel original deadline changed",
            ));
        }
        self.census
            .check_reserved(self.reservation, self.remaining)
            .map_err(census_error)
            .map_err(native_error)?;
        owner.time_left(until, "runtime kernel prepared native effect")?;
        Ok(())
    }
    fn record_permissions(&mut self, executable: bool) -> Result<(), LaunchError> {
        let pages = self.binding.geometry().pages();
        let expected = (pages.end() - pages.start()) / 4096;
        let count = self
            .pages
            .iter()
            .filter(|page| pages.contains(page.address))
            .count();
        if count as u64 != expected {
            return Err(LaunchError::Invalid(
                "runtime kernel page directory lost fetch extent",
            ));
        }
        for page in self
            .pages
            .iter_mut()
            .filter(|page| pages.contains(page.address))
        {
            page.executable = executable;
        }
        Ok(())
    }
}
impl RuntimeKernelObservation for KernelObserver<'_, '_> {
    fn before_effect(
        &mut self,
        owner: &Owner,
        _native: &NativeLifecycle,
        identity: &RuntimeKernelIdentity,
        effect: RuntimeKernelEffect,
        current: RuntimeKernelEffectContext<'_>,
        until: Instant,
    ) -> Result<(), LaunchError> {
        self.remaining(owner, identity, until)?;
        // The private-call context is historical canonical state, not a claim
        // that temporarily injected hardware registers equal that snapshot.
        match (effect, current) {
            (
                RuntimeKernelEffect::OriginalRelease,
                RuntimeKernelEffectContext::Settled(current),
            ) => self.sink.release_attempt(
                identity,
                RuntimeKernelReleasePhase::Original,
                &current.stop.token,
            ),
            (RuntimeKernelEffect::EntryRelease, RuntimeKernelEffectContext::Syscall(current)) => {
                let stop = current.event.stop_token().ok_or(LaunchError::Invalid(
                    "runtime kernel entry release lost token",
                ))?;
                self.sink
                    .release_attempt(identity, RuntimeKernelReleasePhase::Entry, stop)
            }
            (RuntimeKernelEffect::PreExitRelease, RuntimeKernelEffectContext::PreExit(current)) => {
                // Bind the actual callback header to the retained pre-exit
                // record before recording or attempting its kernel-only CONT.
                self.sink.pre_exit_release(
                    identity,
                    RuntimeKernelReleaseSource::PreExit {
                        ordinal: current.raw.ordinal,
                        tid: current.raw.tid,
                        status: current.raw.status,
                    },
                )
            }
            (
                RuntimeKernelEffect::OriginalRelease
                | RuntimeKernelEffect::EntryRelease
                | RuntimeKernelEffect::PreExitRelease,
                _,
            ) => Err(LaunchError::Invalid(
                "runtime kernel release context phase differs",
            )),
            _ => Ok(()),
        }
    }
    fn effect_result(
        &mut self,
        identity: &RuntimeKernelIdentity,
        effect: RuntimeKernelEffect,
        actual: Request,
    ) -> Result<(), LaunchError> {
        self.identity(identity)?;
        let phase = match effect {
            RuntimeKernelEffect::OriginalRelease => RuntimeKernelReleasePhase::Original,
            RuntimeKernelEffect::EntryRelease => RuntimeKernelReleasePhase::Entry,
            RuntimeKernelEffect::PreExitRelease => RuntimeKernelReleasePhase::PreExit,
            _ => return Ok(()),
        };
        self.sink.release_result(identity, phase, actual)
    }
    fn wait(
        &mut self,
        identity: &RuntimeKernelIdentity,
        ordinal: usize,
        tid: i32,
        status: i32,
        custody: RuntimeWaitCustody,
    ) -> Result<(), LaunchError> {
        self.identity(identity)?;
        self.sink.wait(identity, ordinal, tid, status, custody)
    }
    fn raw(
        &mut self,
        identity: &RuntimeKernelIdentity,
        raw: RuntimeRawWaitView<'_>,
    ) -> Result<(), LaunchError> {
        self.identity(identity)?;
        self.sink.raw(identity, raw)
    }
    fn readback(
        &mut self,
        identity: &RuntimeKernelIdentity,
        kind: RuntimeKernelReadback,
        stop: Option<&AdmissionStop>,
        state: RuntimeStateReadView<'_>,
    ) -> Result<(), LaunchError> {
        self.identity(identity)?;
        self.sink.readback(identity, kind, stop, state)
    }
    fn opened(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        identity: &RuntimeKernelIdentity,
        checkpoint: NativeCheckpoint<'_>,
        maps: &[u8],
        until: Instant,
    ) -> Result<(), LaunchError> {
        self.remaining(owner, identity, until)?;
        if checkpoint.state.registers != self.binding.before().registers
            || checkpoint.state.xstate != self.binding.before().xstate
            || checkpoint.state.mask != self.binding.before().signal_mask
        {
            return Err(LaunchError::Invalid(
                "runtime kernel opening changed original state",
            ));
        }
        self.storage.checkpoint(checkpoint)?;
        let reader = self
            .sources
            .runtime_read_opened(
                owner,
                native,
                RuntimeCatalogCheckpoint {
                    island: self.binding.island(),
                    stop: &self.storage.stop,
                    observed: &self.storage.checkpoint,
                },
                self.binding.geometry(),
                maps,
                until,
            )
            .map_err(native_error)?;
        reader
            .recheck_window(
                self.binding.source_id(),
                &mut self.storage.bytes[2],
                &mut self.storage.progress[2],
                &mut self.storage.identity,
            )
            .map_err(native_error)?;
        self.record_permissions(true)?;
        self.sink
            .opened(identity, checkpoint.stop, checkpoint.state)
    }
    fn entry(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        identity: &RuntimeKernelIdentity,
        checkpoint: NativeSyscallCheckpoint<'_>,
        until: Instant,
    ) -> Result<(), LaunchError> {
        self.remaining(owner, identity, until)?;
        let raw = checkpoint
            .raw
            .maps
            .ok_or(LaunchError::Invalid("runtime kernel ENTRY maps absent"))?;
        if !raw.complete || raw.length == 0 || raw.length > raw.initialized.len() {
            return Err(LaunchError::Invalid("runtime kernel ENTRY maps incomplete"));
        }
        let reader = self
            .sources
            .runtime_kernel_read(
                owner,
                native,
                KernelCatalogCheckpoint {
                    island: self.binding.island(),
                    original: self.binding.stop(),
                    event: checkpoint.event,
                    state: checkpoint.state,
                },
                self.binding.geometry(),
                &raw.initialized[..raw.length],
                until,
            )
            .map_err(native_error)?;
        reader
            .recheck_window(
                self.binding.source_id(),
                &mut self.storage.bytes[3],
                &mut self.storage.progress[3],
                &mut self.storage.identity,
            )
            .map_err(native_error)?;
        self.sink
            .entry(identity, checkpoint.event, checkpoint.state)
    }
    fn exit(
        &mut self,
        identity: &RuntimeKernelIdentity,
        checkpoint: NativeSyscallCheckpoint<'_>,
    ) -> Result<(), LaunchError> {
        self.identity(identity)?;
        self.sink.exit(identity, checkpoint.event, checkpoint.state)
    }
    fn closed(
        &mut self,
        owner: &Owner,
        native: &NativeLifecycle,
        identity: &RuntimeKernelIdentity,
        checkpoint: NativeCheckpoint<'_>,
        maps: &[u8],
        until: Instant,
    ) -> Result<(), LaunchError> {
        self.remaining(owner, identity, until)?;
        super::super::maps::verify_closed(self.binding.baseline_maps(), maps)
            .map_err(native_error)?;
        self.storage.checkpoint(checkpoint)?;
        let reader = self
            .sources
            .runtime_read(
                owner,
                native,
                self.binding.island(),
                &self.storage.stop,
                &self.storage.checkpoint,
                until,
            )
            .map_err(native_error)?;
        reader
            .recheck_window(
                self.binding.source_id(),
                &mut self.storage.bytes[4],
                &mut self.storage.progress[4],
                &mut self.storage.identity,
            )
            .map_err(native_error)?;
        self.record_permissions(false)?;
        self.sink
            .closed(identity, checkpoint.stop, checkpoint.state)
    }
    fn pre_exit(
        &mut self,
        identity: &RuntimeKernelIdentity,
        checkpoint: NativePreExitCheckpoint<'_>,
    ) -> Result<(), LaunchError> {
        self.identity(identity)?;
        self.sink.pre_exit(identity, checkpoint.event_message)
    }
    fn terminal(
        &mut self,
        identity: &RuntimeKernelIdentity,
        event: &DynamicEvent,
        trace: NativeKernelTerminalTrace,
    ) -> Result<(), LaunchError> {
        self.identity(identity)?;
        // No NX-close or returned observation is invented after mm destruction.
        self.sink.terminal(identity, event, trace)
    }
}
