//! Later exec bootstrap consumes actual new-mm EXIT authority. No old-mm
//! source, address, island or ordinary return bridge is used here.
use super::super::selected::{ExecExitReady, ExecTransition};
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) enum BootstrapEffect {
    PatchEntry,
    FirstUserResume,
    RestoreEntry,
    WriteStub,
    MapIsland,
    WriteIsland { address: u64 },
    ProtectIsland { address: u64, length: usize },
    QueryMembarrier,
    RegisterMembarrier,
    BootstrapSync,
    RestoreOriginal,
    QuarantineSyncBefore,
    Quarantine { start: u64, length: usize },
    QuarantineSyncAfter,
}

/// The owner supplies a preallocated archive/budget observer. Stage callbacks
/// do not claim that every internal trusted-runner wait has been archived.
/// The actual first-user raw stop is retained before any fallible validation.
pub(in crate::linux::remote::dynamic::owner) trait ReplacedBootstrapObservation {
    fn before_effect(&mut self, effect: BootstrapEffect) -> Result<(), LaunchError>;
    fn effect_complete(
        &mut self,
        effect: BootstrapEffect,
        result: Option<u64>,
    ) -> Result<(), LaunchError>;
    fn raw(&mut self, owner: &Owner, tid: i32, status: i32) -> Result<(), LaunchError>;
    fn entry_trap(&mut self, state: &TaskStateSnapshot) -> Result<(), LaunchError>;
    fn restored_entry(
        &mut self,
        stop: &AdmissionStop,
        state: &TaskStateSnapshot,
    ) -> Result<(), LaunchError>;
    fn complete(&mut self, bootstrap: &BootstrapMm) -> Result<(), LaunchError>;
    fn failed(&mut self, error: &LaunchError);
}

/// A completed replacement bootstrap with its original native identity chain.
/// Its history cannot authorize a later mutation or release by itself.
pub(in crate::linux::remote::dynamic::owner) struct ExecBootstrapReady {
    transition: ExecTransition,
    bootstrap: BootstrapMm,
}

impl ExecBootstrapReady {
    pub(in crate::linux::remote::dynamic::owner) fn transition(&self) -> &ExecTransition {
        &self.transition
    }
    pub(in crate::linux::remote::dynamic::owner) fn bootstrap(&self) -> &BootstrapMm {
        &self.bootstrap
    }
    pub(in crate::linux::remote::dynamic::owner) fn retained_bytes(
        &self,
    ) -> Result<usize, LaunchError> {
        let transition = self
            .transition
            .retained_bytes()?
            .checked_sub(std::mem::size_of::<ExecTransition>())
            .ok_or(LaunchError::Invalid(
                "exec bootstrap transition size differs",
            ))?;
        let mut bytes =
            std::mem::size_of::<Self>()
                .checked_add(transition)
                .ok_or(LaunchError::Invalid(
                    "exec bootstrap retained size overflows",
                ))?;
        for state in [
            &self.bootstrap.evidence.exec_event,
            &self.bootstrap.evidence.exec_exit,
            &self.bootstrap.evidence.entry_trap,
            &self.bootstrap.evidence.restored_entry,
        ] {
            bytes = bytes
                .checked_add(state.xstate.capacity())
                .ok_or(LaunchError::Invalid("exec bootstrap state size overflows"))?;
        }
        for maps in [
            &self.bootstrap.original_executables,
            &self.bootstrap.mappings,
        ] {
            bytes = bytes
                .checked_add(
                    maps.capacity()
                        .checked_mul(std::mem::size_of::<MemoryMapping>())
                        .ok_or(LaunchError::Invalid("exec bootstrap maps size overflows"))?,
                )
                .ok_or(LaunchError::Invalid("exec bootstrap maps size overflows"))?;
            for map in maps {
                bytes = bytes
                    .checked_add(map.permissions.capacity())
                    .and_then(|bytes| {
                        bytes.checked_add(map.pathname.as_ref().map_or(0, String::capacity))
                    })
                    .ok_or(LaunchError::Invalid(
                        "exec bootstrap descriptor size overflows",
                    ))?;
            }
        }
        Ok(bytes)
    }
    pub(in crate::linux::remote::dynamic::owner) fn into_parts(
        self,
    ) -> (ExecTransition, BootstrapMm) {
        (self.transition, self.bootstrap)
    }
}

/// # Safety
/// The owner retains the old mm as history, has reserved the entire new-mm
/// bootstrap/source transaction, and supplies its actual pre-poke executable
/// census. The no-writer/no-code-as-data/singleton bootstrap exception remains
/// the same as bootstrap_admission. No source callback can run before NX.
pub(in crate::linux::remote::dynamic::owner) unsafe fn bootstrap_replaced_admission(
    owner: &mut Owner,
    native: &mut lifecycle::NativeLifecycle,
    ready: ExecExitReady,
    expected_new_mappings: &[MemoryMapping],
    observation: &mut dyn ReplacedBootstrapObservation,
    until: Instant,
) -> Result<ExecBootstrapReady, LaunchError> {
    let result = (|| {
        ready.authenticate(owner, native, until)?;
        if owner.lifecycle.is_some() {
            return Err(LaunchError::Invalid(
                "exec bootstrap has competing lifecycle ownership",
            ));
        }
        let (transition, exec_event, exec_exit) = ready.into_parts();
        let exit = transition.exit().stop_token().ok_or(LaunchError::Invalid(
            "exec bootstrap lacks its consumed real EXIT",
        ))?;
        let bootstrap = bootstrap_inner(
            owner,
            native,
            BootstrapRequest {
                exit,
                exec_event,
                exec_exit,
                expected_mappings: expected_new_mappings,
                observation: Some(&mut *observation),
            },
            until,
        )?;
        if bootstrap.stop.identity != transition.current()
            || bootstrap.stop.token.session != owner.session
            || bootstrap.stop.token.tid != owner.pid
            || bootstrap.stop.token.sequence <= exit.sequence
        {
            return Err(LaunchError::Invalid(
                "exec bootstrap changed replacement identity",
            ));
        }
        // Preserve the already validated native checkpoint before a deadline
        // gate can refuse later work. No native effect follows this callback.
        observation.complete(&bootstrap)?;
        owner.time_left(until, "admitted exec bootstrap completion")?;
        Ok(ExecBootstrapReady {
            transition,
            bootstrap,
        })
    })();
    if let Err(error) = &result {
        owner.closing = true;
        owner.cancel.store(true, Ordering::Release);
        observation.failed(error);
    }
    result
}
