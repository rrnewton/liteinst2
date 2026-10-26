//! Complete original-window rechecks at actual original syscall events.
//! This adapter cannot mint an actual-PC RuntimeWindowProof or an owned stop.
use super::super::super::source_identity::{RuntimeKernelReadCheckpoint, RuntimeKernelSourceRead};
use super::*;
use crate::linux::remote::dynamic::owner::trusted::TaskStateSnapshot;

pub(in crate::linux::remote::dynamic::owner::admission) struct KernelCatalogCheckpoint<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) island: &'a TrustedIsland,
    pub(in crate::linux::remote::dynamic::owner::admission) original: &'a AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner::admission) event: &'a DynamicEvent,
    pub(in crate::linux::remote::dynamic::owner::admission) state: &'a TaskStateSnapshot,
}
pub(in crate::linux::remote::dynamic::owner::admission) struct CapturedKernelRead<'a> {
    reader: RuntimeKernelSourceRead<'a>,
    catalog: &'a PreparedInitialSources,
    executable: ExecutableIdentity,
}
impl PreparedInitialSources {
    pub(in crate::linux::remote::dynamic::owner::admission) fn runtime_kernel_read<'a>(
        &'a self,
        owner: &'a Owner,
        native: &'a NativeLifecycle,
        checkpoint: KernelCatalogCheckpoint<'a>,
        geometry: &super::super::super::runtime::maps::FetchGeometry,
        maps: &'a [u8],
        until: Instant,
    ) -> Result<CapturedKernelRead<'a>, GateError> {
        geometry.verify_open(self.runtime_baseline_maps()?, maps)?;
        if !self.storage.capture_complete
            || !self.storage.recheck_complete
            || self.storage.failure.is_some()
            || self
                .storage
                .current
                .as_ref()
                .is_none_or(|initial| initial.stop.identity != checkpoint.original.identity)
        {
            return Err(refused(
                "runtime kernel source catalog is not the captured initial mm",
            ));
        }
        let executable = self
            .storage
            .executable
            .ok_or_else(|| refused("runtime kernel executable identity absent"))?;
        let reader = RuntimeKernelSourceRead::acquire(
            owner,
            native,
            RuntimeKernelReadCheckpoint {
                island: checkpoint.island,
                original: checkpoint.original,
                event: checkpoint.event,
                state: checkpoint.state,
                maps,
            },
            &self.authentication,
            until,
        )?;
        Ok(CapturedKernelRead {
            reader,
            catalog: self,
            executable,
        })
    }
}
impl CapturedKernelRead<'_> {
    pub(in crate::linux::remote::dynamic::owner::admission) fn temporary_bytes() -> usize {
        RuntimeKernelSourceRead::temporary_bytes() + size_of::<Self>()
            - size_of::<RuntimeKernelSourceRead<'_>>()
            + size_of::<KernelCatalogCheckpoint<'_>>()
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn recheck_window(
        &self,
        id: SourceWindowId,
        bytes: &mut [u8],
        progress: &mut SourceReadProgress,
        identity: &mut [u8],
    ) -> Result<(), GateError> {
        let window = self
            .catalog
            .window(id.index())
            .ok_or_else(|| refused("runtime kernel source window incomplete"))?;
        if window.id != id
            || window.snapshot.bytes().len() != bytes.len()
            || window.snapshot.mapping != MappingId(id.identity().mapping)
            || window.snapshot.generation != Generation(id.identity().generation)
        {
            return Err(refused("runtime kernel source dependency identity differs"));
        }
        if self.reader.executable_projection(identity)? != self.executable {
            return Err(refused(
                "runtime kernel executable backing identity changed",
            ));
        }
        self.reader
            .read_memory_into(window.snapshot.range().start(), bytes, progress)?;
        if !progress.complete
            || progress.copied_bytes != bytes.len()
            || bytes != window.snapshot.bytes()
        {
            return Err(refused("runtime kernel complete source window changed"));
        }
        if self.reader.executable_projection(identity)? != self.executable {
            return Err(refused(
                "runtime kernel executable backing identity changed",
            ));
        }
        self.reader.reauthenticate()?;
        Ok(())
    }
}
