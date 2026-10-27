//! Retained filesystem/VMA identity binding at the genuine original EXEC.
//! The existing source reader supplies native authentication and cleanup;
//! these observations and pure comparisons create no execution authority.
use super::super::artifact::{ArtifactPlan, FileIdentity, PinnedArtifact};
use super::{OracleError, require_original_maps};
use crate::DynamicStop;
use crate::gate::GateError;
use crate::linux::remote::dynamic::owner::Owner;
use crate::linux::remote::dynamic::owner::admission::source_identity::{
    InitialReadScratch, OriginalSourceRead,
    backing::{DescriptorIdentity, ExecutableIdentity},
};
use crate::linux::remote::dynamic::owner::admission::{exact_storage, source_identity};
use std::{mem::size_of, time::Instant};

const MAX: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Empty,
    AuthenticationAllocation,
    ProjectionAllocation,
    Allocated,
    Acquire,
    Observe,
    Validate,
    Complete,
}

pub(super) struct ExecutableProjection {
    authentication: Option<InitialReadScratch>,
    scratch: Vec<u8>,
    initial: Option<DynamicStop>,
    until: Option<Instant>,
    pinned: Option<FileIdentity>,
    observed: Option<ExecutableIdentity>,
    phase: Phase,
    first_failure: Option<Phase>,
}
impl ExecutableProjection {
    pub(super) fn empty() -> Self {
        Self {
            authentication: None,
            scratch: Vec::new(),
            initial: None,
            until: None,
            pinned: None,
            observed: None,
            phase: Phase::Empty,
            first_failure: None,
        }
    }
    fn result<T>(&mut self, result: Result<T, OracleError>) -> Result<T, OracleError> {
        if result.is_err() {
            self.first_failure.get_or_insert(self.phase);
        }
        result
    }
    pub(super) fn mark_aborted(&mut self) {
        // A later raw-lane failure cannot relabel a finished projection or an
        // allocated but unattempted observation as an observation failure.
        if matches!(
            self.phase,
            Phase::AuthenticationAllocation
                | Phase::ProjectionAllocation
                | Phase::Acquire
                | Phase::Observe
                | Phase::Validate
        ) {
            self.first_failure.get_or_insert(self.phase);
        }
    }
    pub(super) fn allocate_payloads(&mut self) -> Result<(), OracleError> {
        let result = (|| {
            if self.phase != Phase::Empty
                || self.first_failure.is_some()
                || self.authentication.is_some()
                || self.scratch.capacity() != 0
            {
                return Err(OracleError::Invalid(
                    "raw executable projection allocation reused",
                ));
            }
            self.phase = Phase::AuthenticationAllocation;
            self.authentication = Some(InitialReadScratch::allocate()?);
            self.phase = Phase::ProjectionAllocation;
            self.scratch = exact_storage::empty_bytes(MAX)
                .map_err(|_| OracleError::Invalid("raw executable projection allocation failed"))?;
            // Exact fixed capacity is already installed. u8 initialization
            // cannot grow the allocation or invoke application code.
            self.scratch.resize(MAX, 0);
            self.phase = Phase::Allocated;
            Ok(())
        })();
        self.result(result)
    }
    pub(super) fn allocated_payload_bytes(&self) -> usize {
        self.authentication.as_ref().map_or(0, |scratch| {
            scratch.allocated_bytes() - size_of::<InitialReadScratch>()
        }) + self.scratch.capacity()
    }
    pub(super) const fn reserved_payload_bytes() -> usize {
        // Both headers are already inline in PreparedRawLane.
        2 * MAX
    }
    pub(super) fn capture(
        &mut self,
        owner: &Owner,
        initial: &DynamicStop,
        file: &PinnedArtifact,
        plan: &ArtifactPlan,
        maps: &[u8],
        until: Instant,
    ) -> Result<(), OracleError> {
        let result = (|| {
            if self.phase != Phase::Allocated
                || self.first_failure.is_some()
                || self.initial.is_some()
                || self.until.is_some()
                || self.pinned.is_some()
                || self.observed.is_some()
            {
                return Err(OracleError::Invalid(
                    "raw executable projection capture reused",
                ));
            }
            self.initial = Some(initial.clone());
            self.until = Some(until);
            self.phase = Phase::Acquire;
            self.pinned = Some(file.identity()?);
            self.require_allocated()?;
            let authentication = self.authentication.as_ref().ok_or(OracleError::Invalid(
                "raw executable authentication storage absent",
            ))?;
            let reader = OriginalSourceRead::acquire(owner, initial, until, authentication)?;
            self.phase = Phase::Observe;
            // The reader authenticates before and after the exact held-exe
            // PROT_NONE projection. It owns all internal fd/mmap cleanup.
            self.observed = Some(reader.executable_projection(self.scratch.as_mut_slice())?);
            self.phase = Phase::Validate;
            self.require_binding(plan, maps)?;
            self.phase = Phase::Complete;
            Ok(())
        })();
        self.result(result)
    }
    fn require_allocated(&self) -> Result<(), OracleError> {
        if self.authentication.as_ref().is_none_or(|scratch| {
            scratch.allocated_bytes() != InitialReadScratch::reservation_bytes()
        }) || self.scratch.len() != MAX
            || self.scratch.capacity() != MAX
        {
            return Err(OracleError::Invalid(
                "raw executable projection storage differs",
            ));
        }
        Ok(())
    }
    fn require_binding(&self, plan: &ArtifactPlan, maps: &[u8]) -> Result<(), OracleError> {
        let pinned = self.pinned.ok_or(OracleError::Invalid(
            "raw pinned executable identity absent",
        ))?;
        let observed = self
            .observed
            .ok_or(OracleError::Invalid("raw executable projection absent"))?;
        let expected = pinned_descriptor(pinned)?;
        require_descriptor(&expected, &observed)?;
        require_original_maps(plan, observed.vma, maps)
    }
    pub(super) fn require_at(
        &self,
        plan: &ArtifactPlan,
        maps: &[u8],
        initial: &DynamicStop,
        until: Instant,
    ) -> Result<(), OracleError> {
        if self.initial.as_ref() != Some(initial) {
            return Err(OracleError::Invalid(
                "raw executable projection stop differs",
            ));
        }
        self.require_retained(plan, maps, until, initial.tid)
    }
    pub(super) fn require_retained(
        &self,
        plan: &ArtifactPlan,
        maps: &[u8],
        until: Instant,
        pid: i32,
    ) -> Result<(), OracleError> {
        if self.phase != Phase::Complete
            || self.first_failure.is_some()
            || self.until != Some(until)
            || self.initial.as_ref().is_none_or(|initial| {
                initial.tid != pid || initial.session == 0 || initial.task.is_some()
            })
        {
            return Err(OracleError::Invalid("raw executable projection incomplete"));
        }
        self.require_allocated()?;
        self.require_binding(plan, maps)
    }
}

fn pinned_descriptor(file: FileIdentity) -> Result<DescriptorIdentity, OracleError> {
    Ok(DescriptorIdentity {
        file: source_identity::FileIdentity {
            major: libc::major(file.device),
            minor: libc::minor(file.device),
            inode: file.inode,
        },
        mode: file.mode,
        length: u64::try_from(file.size)
            .map_err(|_| OracleError::Invalid("raw pinned executable length overflows"))?,
    })
}

// Pure equality of supplied descriptor projections. Only capture() obtains the
// actual held-executable projection; this comparator cannot authenticate one.
fn require_descriptor(
    pinned: &DescriptorIdentity,
    observed: &ExecutableIdentity,
) -> Result<(), OracleError> {
    if observed.opened != *pinned {
        return Err(OracleError::Invalid(
            "raw opened executable differs from pinned artifact",
        ));
    }
    Ok(())
}

impl ExecutableProjection {
    pub(super) fn temporary_bytes() -> Result<usize, OracleError> {
        // Existing authenticated reader/RAII bound includes its transient
        // PROT_NONE page. Add wrapper, parser and calculator metadata; this is
        // source-managed accounting, not an observed compiler-frame/RSS bound.
        [
            source_identity::initial_temporary_bytes(),
            map_parser_temporary_bytes()?,
            2 * size_of::<Self>(),
            2 * size_of::<OriginalSourceRead<'static>>(),
            2 * size_of::<InitialReadScratch>(),
            3 * size_of::<DynamicStop>(),
            3 * size_of::<Option<DynamicStop>>(),
            3 * size_of::<Instant>(),
            3 * size_of::<Option<Instant>>(),
            4 * size_of::<FileIdentity>(),
            4 * size_of::<DescriptorIdentity>(),
            4 * size_of::<ExecutableIdentity>(),
            2 * size_of::<Option<ExecutableIdentity>>(),
            6 * size_of::<Phase>(),
            2 * size_of::<Option<Phase>>(),
            2 * size_of::<Result<OriginalSourceRead<'static>, GateError>>(),
            3 * size_of::<Result<ExecutableIdentity, GateError>>(),
            3 * size_of::<Result<DescriptorIdentity, OracleError>>(),
            2 * size_of::<Result<FileIdentity, OracleError>>(),
            3 * size_of::<Result<(), GateError>>(),
            6 * size_of::<Result<(), OracleError>>(),
            2 * size_of::<Result<usize, OracleError>>(),
            2 * size_of::<Result<u64, std::num::TryFromIntError>>(),
            2 * size_of::<Result<InitialReadScratch, GateError>>(),
            2 * size_of::<Result<Vec<u8>, exact_storage::AllocationError>>(),
            3 * size_of::<Vec<u8>>(),
            20 * size_of::<&Owner>(),
            2 * size_of::<Option<&InitialReadScratch>>(),
            2 * size_of::<Option<&DynamicStop>>(),
            2 * size_of::<(
                &mut Self,
                &Owner,
                &DynamicStop,
                &PinnedArtifact,
                &ArtifactPlan,
                &[u8],
                Instant,
            )>(),
            8 * size_of::<&[u8]>(),
            4 * size_of::<&mut [u8]>(),
            32 * size_of::<usize>(),
            8 * size_of::<bool>(),
            size_of::<[usize; 35]>()
                + size_of::<std::array::IntoIter<usize, 35>>()
                + 4 * size_of::<usize>()
                + 2 * size_of::<Option<usize>>()
                + size_of::<Result<usize, OracleError>>()
                + size_of::<OracleError>()
                + size_of::<&'static str>(),
        ]
        .into_iter()
        .try_fold(0_usize, |total, value| {
            total.checked_add(value).ok_or(OracleError::Invalid(
                "raw executable projection temporary overflows",
            ))
        })
    }
}

fn map_parser_temporary_bytes() -> Result<usize, OracleError> {
    use crate::linux::remote::dynamic::owner::admission::mapping::maps::{
        MapEntries, MapEntry, MapParseError, MapPermissions, ParsedMaps,
    };
    // Sum the fixed parser families for both backing projection and the
    // separate strict child-map comparison, including complete-table checks.
    [
        4 * size_of::<ParsedMaps<'static>>(),
        4 * size_of::<MapEntries<'static>>(),
        6 * size_of::<MapEntry<'static>>(),
        4 * size_of::<Option<MapEntry<'static>>>(),
        4 * size_of::<Result<ParsedMaps<'static>, MapParseError>>(),
        4 * size_of::<Result<MapEntry<'static>, MapParseError>>(),
        4 * size_of::<Result<ParsedMaps<'static>, GateError>>(),
        4 * size_of::<Result<(), MapParseError>>(),
        4 * size_of::<Result<&'static [u8], MapParseError>>(),
        4 * size_of::<Result<(&'static [u8], &'static [u8]), MapParseError>>(),
        4 * size_of::<Result<u64, MapParseError>>(),
        4 * size_of::<Result<u32, MapParseError>>(),
        4 * size_of::<Option<u64>>(),
        8 * size_of::<Option<usize>>(),
        4 * size_of::<MapPermissions>(),
        4 * size_of::<[u8; 4]>(),
        2 * size_of::<std::slice::Split<'static, u8, fn(&u8) -> bool>>(),
        4 * size_of::<std::slice::Iter<'static, u8>>(),
        4 * size_of::<std::ops::Range<u64>>(),
        4 * size_of::<std::ops::Range<usize>>(),
        24 * size_of::<&'static [u8]>(),
        32 * size_of::<u64>(),
        24 * size_of::<usize>(),
        16 * size_of::<bool>(),
        4 * size_of::<(u64, u64, [u8; 4])>(),
        4 * size_of::<Result<(), OracleError>>(),
        size_of::<[usize; 27]>()
            + size_of::<std::array::IntoIter<usize, 27>>()
            + 4 * size_of::<usize>()
            + 2 * size_of::<Option<usize>>()
            + size_of::<Result<usize, OracleError>>()
            + size_of::<OracleError>()
            + size_of::<&'static str>(),
    ]
    .into_iter()
    .try_fold(0_usize, |total, value| {
        total.checked_add(value).ok_or(OracleError::Invalid(
            "raw executable map parser temporary overflows",
        ))
    })
}

#[cfg(test)]
mod tests;
