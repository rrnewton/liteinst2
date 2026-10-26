//! Reuse the retained initial catalog at a new, independently authenticated
//! current stop. Initial raw capture/bindings remain immutable history.
use super::super::census::ObservedStop;
use super::super::source_identity::{RuntimeReadCheckpoint, RuntimeSourceRead};
use super::*;
use crate::linux::remote::dynamic::owner::trusted::TrustedIsland;

pub(in crate::linux::remote::dynamic::owner::admission) struct CapturedRuntimeRead<'source, 'read> {
    reader: RuntimeSourceRead<'read>,
    catalog: &'source PreparedInitialSources,
    stop: &'source AdmissionStop,
    observed: &'source ObservedStop,
    until: Instant,
    executable: ExecutableIdentity,
    projection: RuntimeMapProjection,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RuntimeMapProjection {
    Quarantined,
    Opened,
}

/// Borrowed checkpoint description; the reader independently authenticates it.
pub(in crate::linux::remote::dynamic::owner::admission) struct RuntimeCatalogCheckpoint<
    'source,
    'read,
> {
    pub(in crate::linux::remote::dynamic::owner::admission) island: &'read TrustedIsland,
    pub(in crate::linux::remote::dynamic::owner::admission) stop: &'source AdmissionStop,
    pub(in crate::linux::remote::dynamic::owner::admission) observed: &'source ObservedStop,
}

/// One complete retained window matched against live bytes at its actual PC.
/// This supplies read evidence only; no census, debug/control-state, writer,
/// permission, or one-instruction execution authority is manufactured here.
pub(in crate::linux::remote::dynamic::owner::admission) struct RuntimeWindowProof<'a> {
    window: WindowView<'a>,
    stop: &'a AdmissionStop,
    observed: &'a ObservedStop,
    until: Instant,
    baseline: &'a [u8],
}
impl<'a> RuntimeWindowProof<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) fn window(&self) -> &WindowView<'a> {
        &self.window
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn stop(&self) -> &'a AdmissionStop {
        self.stop
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn observed(&self) -> &'a ObservedStop {
        self.observed
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn until(&self) -> Instant {
        self.until
    }
    pub(in crate::linux::remote::dynamic::owner::admission) fn baseline_maps(&self) -> &'a [u8] {
        self.baseline
    }
}

impl PreparedInitialSources {
    pub(in crate::linux::remote::dynamic::owner::admission) fn runtime_read<
        'source: 'read,
        'read,
    >(
        &'source self,
        owner: &'read Owner,
        native: &'read NativeLifecycle,
        island: &'read TrustedIsland,
        stop: &'source AdmissionStop,
        observed: &'source ObservedStop,
        until: Instant,
    ) -> Result<CapturedRuntimeRead<'source, 'read>, GateError> {
        let maps = self.runtime_baseline_maps()?;
        self.runtime_read_with_maps(
            owner,
            native,
            RuntimeCatalogCheckpoint {
                island,
                stop,
                observed,
            },
            maps,
            RuntimeMapProjection::Quarantined,
            until,
        )
    }

    /// The exact closed inventory remains immutable initial-capture evidence.
    pub(in crate::linux::remote::dynamic::owner::admission) fn runtime_baseline_maps(
        &self,
    ) -> Result<&[u8], GateError> {
        observed_maps(&self.storage.quarantine_maps, &self.storage.quarantine_read)
    }

    /// Read-only reauthentication after the native transport's actual opening
    /// calls. Arbitrary supplied maps cannot become the current source domain:
    /// first prove the sole allowed split/X projection of the retained VMA.
    pub(in crate::linux::remote::dynamic::owner::admission) fn runtime_read_opened<
        'source: 'read,
        'read,
    >(
        &'source self,
        owner: &'read Owner,
        native: &'read NativeLifecycle,
        checkpoint: RuntimeCatalogCheckpoint<'source, 'read>,
        geometry: &super::super::runtime::maps::FetchGeometry,
        actual_maps: &'read [u8],
        until: Instant,
    ) -> Result<CapturedRuntimeRead<'source, 'read>, GateError> {
        geometry.verify_open(self.runtime_baseline_maps()?, actual_maps)?;
        self.runtime_read_with_maps(
            owner,
            native,
            checkpoint,
            actual_maps,
            RuntimeMapProjection::Opened,
            until,
        )
    }

    fn runtime_read_with_maps<'source: 'read, 'read>(
        &'source self,
        owner: &'read Owner,
        native: &'read NativeLifecycle,
        checkpoint: RuntimeCatalogCheckpoint<'source, 'read>,
        maps: &'read [u8],
        projection: RuntimeMapProjection,
        until: Instant,
    ) -> Result<CapturedRuntimeRead<'source, 'read>, GateError> {
        let RuntimeCatalogCheckpoint {
            island,
            stop,
            observed,
        } = checkpoint;
        if !self.storage.capture_complete
            || !self.storage.recheck_complete
            || self.storage.failure.is_some()
            || self
                .storage
                .current
                .as_ref()
                .is_none_or(|initial| initial.stop.identity != stop.identity)
        {
            return Err(refused(
                "runtime current source catalog is not the captured initial mm",
            ));
        }
        let executable = self
            .storage
            .executable
            .ok_or_else(|| refused("runtime source executable identity is absent"))?;
        let reader = RuntimeSourceRead::acquire(
            owner,
            native,
            RuntimeReadCheckpoint {
                island,
                stop,
                observed,
                maps,
            },
            &self.authentication,
            until,
        )?;
        Ok(CapturedRuntimeRead {
            reader,
            catalog: self,
            stop,
            observed,
            until,
            executable,
            projection,
        })
    }
}

impl<'source, 'read> CapturedRuntimeRead<'source, 'read> {
    /// New current-operation temporary peak, separate from the unchanged
    /// initial capture bound. Caller-owned query/prefix buffers are separate.
    pub(in crate::linux::remote::dynamic::owner::admission) fn temporary_bytes() -> usize {
        RuntimeSourceRead::temporary_bytes() + size_of::<Self>()
            - size_of::<RuntimeSourceRead<'_>>()
            + size_of::<RuntimeWindowProof<'_>>()
            + size_of::<RuntimeCatalogCheckpoint<'_, '_>>()
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn read_memory_into(
        &self,
        address: u64,
        bytes: &mut [u8],
        progress: &mut SourceReadProgress,
    ) -> Result<(), GateError> {
        self.reader.read_memory_into(address, bytes, progress)
    }

    pub(in crate::linux::remote::dynamic::owner::admission) fn verify_window(
        &self,
        index: usize,
        bytes: &mut [u8],
        progress: &mut SourceReadProgress,
        identity_scratch: &mut [u8],
    ) -> Result<RuntimeWindowProof<'source>, GateError> {
        let window = self
            .catalog
            .window(index)
            .ok_or_else(|| refused("runtime source window is incomplete"))?;
        if self.projection != RuntimeMapProjection::Quarantined
            || window.id.index() != index
            || !window.target.contains(self.observed.logical_pc)
        {
            return Err(refused(
                "runtime actual PC or complete source window differs",
            ));
        }
        self.recheck_window(window.id, bytes, progress, identity_scratch)?;
        Ok(RuntimeWindowProof {
            window,
            stop: self.stop,
            observed: self.observed,
            until: self.until,
            baseline: self.catalog.runtime_baseline_maps()?,
        })
    }

    /// Recheck the same complete source dependency after a private checkpoint
    /// or original instruction. The successor PC may leave this window. This
    /// supplies no actual-PC proof for that successor and no new instruction.
    pub(in crate::linux::remote::dynamic::owner::admission) fn recheck_window(
        &self,
        id: SourceWindowId,
        bytes: &mut [u8],
        progress: &mut SourceReadProgress,
        identity_scratch: &mut [u8],
    ) -> Result<(), GateError> {
        let window = self
            .catalog
            .window(id.index())
            .ok_or_else(|| refused("runtime source window is incomplete"))?;
        if window.id != id
            || window.snapshot.bytes().len() != bytes.len()
            || window.snapshot.mapping != MappingId(id.identity().mapping)
            || window.snapshot.generation != Generation(id.identity().generation)
        {
            return Err(refused(
                "runtime complete source dependency identity differs",
            ));
        }
        if self.reader.executable_projection(identity_scratch)? != self.executable {
            return Err(refused("runtime executable backing identity changed"));
        }
        self.reader
            .read_memory_into(window.snapshot.range().start(), bytes, progress)?;
        if !progress.complete
            || progress.copied_bytes != bytes.len()
            || bytes != window.snapshot.bytes()
        {
            return Err(refused("runtime complete original source window changed"));
        }
        if self.reader.executable_projection(identity_scratch)? != self.executable {
            return Err(refused("runtime executable backing identity changed"));
        }
        self.reader.reauthenticate()?;
        Ok(())
    }
}
