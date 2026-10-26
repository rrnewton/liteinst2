//! Bounded immutable source observations and caller-certified head replies.
//! No value here grants native mapping, publication or task-release authority.
use super::*;
use crate::MemoryMapping;
use std::collections::BTreeSet;
use std::ops::Range;

#[cfg(test)]
pub(super) mod tests;

const PAGE: u64 = 4096;
const MAX_IMAGES: usize = 64;
const MAX_IMAGE_BYTES: usize = 64 * 1024;
const MAX_DOMAIN_BYTES: u64 = 64 * 1024 * 1024;

/// Explicit singleton anonymous/private mapping profile. The original program
/// alone performs writes; native permission changes require owner validation.
/// There is no default opt-in, source-version script or generic syscall escape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicMappingProfile {
    /// Page-aligned disjoint address envelopes for original anonymous mappings.
    pub allowed_ranges: Vec<Range<u64>>,
    /// Maximum attempted original mapping operations over the whole session.
    pub max_operations: usize,
    /// Maximum simultaneously owned anonymous mapping incarnations.
    pub max_live_mappings: usize,
    /// Maximum lifetime source-resolution requests, including abandoned ones.
    pub max_source_requests: usize,
    /// Maximum bytes in any one original mapping range and source capture.
    /// The first profile uses one complete VMA per request, at most 64 KiB.
    pub max_capture_bytes: usize,
}

impl DynamicMappingProfile {
    pub(in super::super) fn validate(
        &self,
        options: &DynamicAdmissionOptions,
        facts: &[ImageFacts],
    ) -> Result<(), GateError> {
        options.validate()?;
        if options.lifecycle != DynamicLifecycleOptions::default()
            || self.allowed_ranges.is_empty()
            || self.allowed_ranges.len() > MAX_IMAGES
            || !(1..=4096).contains(&self.max_operations)
            || !(1..=MAX_IMAGES).contains(&self.max_live_mappings)
            || self.max_source_requests == 0
            || self.max_source_requests > self.max_operations
            || self.max_capture_bytes == 0
            || self.max_capture_bytes > MAX_IMAGE_BYTES
            || self.max_capture_bytes % PAGE as usize != 0
            || self.max_capture_bytes > options.limits.source_fact_bytes
        {
            return Err(GateError::Refused(
                "invalid singleton anonymous mapping profile",
            ));
        }
        let mut total = 0_u64;
        for (index, range) in self.allowed_ranges.iter().enumerate() {
            if range.start == 0
                || range.end <= range.start
                || range.start % PAGE != 0
                || range.end % PAGE != 0
                || self.allowed_ranges[..index]
                    .iter()
                    .any(|old| overlaps(old, range))
            {
                return Err(GateError::Refused(
                    "invalid anonymous mapping address envelope",
                ));
            }
            total = total
                .checked_add(range.end - range.start)
                .ok_or(GateError::Refused("anonymous mapping envelope overflows"))?;
            for fact in facts {
                let end = fact
                    .start
                    .checked_add(fact.bytes.len() as u64)
                    .ok_or(GateError::Refused("initial image range overflows"))?;
                if overlaps(range, &(fact.start..end)) {
                    return Err(GateError::Refused(
                        "anonymous mapping envelope overlaps initial source",
                    ));
                }
            }
        }
        if total > MAX_DOMAIN_BYTES {
            return Err(GateError::Refused(
                "anonymous mapping address envelope exceeds page bound",
            ));
        }
        Ok(())
    }

    pub(in super::super) fn contains_range(&self, range: &Range<u64>) -> bool {
        range.start != 0
            && range.start < range.end
            && range.start % PAGE == 0
            && range.end % PAGE == 0
            && range.end - range.start <= self.max_capture_bytes as u64
            && self
                .allowed_ranges
                .iter()
                .any(|allowed| allowed.start <= range.start && range.end <= allowed.end)
    }
}

fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Diagnostic source-request identity. Only the owner issues its session and
/// serial; copying it grants no stop, mapping or catalog-commit authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct DynamicSourceRequestId {
    pub(in super::super) session: u64,
    pub(in super::super) serial: u64,
}
impl DynamicSourceRequestId {
    /// Non-reused native owner-session identity, not an operating-system PID.
    pub fn session(self) -> u64 {
        self.session
    }
    /// Lifetime request serial; abandonment must not recycle it.
    pub fn serial(self) -> u64 {
        self.serial
    }
}

/// One immutable source candidate in an exact source request. This is not an
/// installed SourceVersion or a public catalog binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct DynamicSourceCaptureId {
    pub(in super::super) request: DynamicSourceRequestId,
    pub(in super::super) index: usize,
}
impl DynamicSourceCaptureId {
    /// Original request owning this candidate.
    pub fn request(self) -> DynamicSourceRequestId {
        self.request
    }
    /// Position in its bounded immutable batch.
    pub fn index(self) -> usize {
        self.index
    }
}

/// Actual source bytes captured while the original owner holds the singleton
/// and keeps this complete VMA NX. Observations alone are not a native lease.
#[derive(Debug)]
pub struct DynamicSourceImage {
    pub(in super::super) id: DynamicSourceCaptureId,
    pub(in super::super) mapping_incarnation: u64,
    pub(in super::super) original: MemoryMapping,
    pub(in super::super) quarantined: MemoryMapping,
    pub(in super::super) bytes: Arc<[u8]>,
    pub(in super::super) lower_neighbor: Option<MemoryMapping>,
    pub(in super::super) upper_neighbor: Option<MemoryMapping>,
}
impl DynamicSourceImage {
    /// Exact owner-issued candidate identifier used in the head reply.
    pub fn id(&self) -> DynamicSourceCaptureId {
        self.id
    }
    /// Session-local actual mapping incarnation; same-address reuse differs.
    pub fn mapping_incarnation(&self) -> u64 {
        self.mapping_incarnation
    }
    /// Complete actual VMA range; not a smaller page relabelled as a VMA.
    pub fn range(&self) -> Range<u64> {
        self.original.start..self.original.end
    }
    /// Complete captured original bytes, never resolver-supplied replacement code.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Actual original kernel EXIT mapping descriptor, before owner quarantine.
    pub fn original_mapping(&self) -> &MemoryMapping {
        &self.original
    }
    /// Actual owner-managed NX mapping descriptor at capture.
    pub fn quarantined_mapping(&self) -> &MemoryMapping {
        &self.quarantined
    }
    /// Immediately adjacent lower mapping, if present in the owner census.
    pub fn lower_neighbor(&self) -> Option<&MemoryMapping> {
        self.lower_neighbor.as_ref()
    }
    /// Immediately adjacent upper mapping, if present in the owner census.
    pub fn upper_neighbor(&self) -> Option<&MemoryMapping> {
        self.upper_neighbor.as_ref()
    }
}

/// Private dispatch binding only. The owner separately retains and rechecks
/// source-set/reservation identity, complete state/maps/census and native proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in super::super) struct PendingSourceToken {
    pub(in super::super) id: DynamicSourceRequestId,
    pub(in super::super) original: PendingToken,
    pub(in super::super) capture_stop: DynamicStop,
    pub(in super::super) task: DynamicTask,
    pub(in super::super) candidate_epoch: u64,
    pub(in super::super) until: Instant,
}

/// Owner-issued immutable source acquisition. It is delivered only after the
/// original kernel EXIT, private return bridge and complete NX quarantine.
/// Facts returned for it cannot release a task or commit a source set.
#[derive(Debug)]
pub struct DynamicSourceRequest {
    pub(in super::super) token: PendingSourceToken,
    pub(in super::super) images: Arc<[DynamicSourceImage]>,
}
impl DynamicSourceRequest {
    /// Exact lifetime request identity.
    pub fn id(&self) -> DynamicSourceRequestId {
        self.token.id
    }
    /// Actual old-generation identity at the held post-bridge capture.
    pub fn task(&self) -> DynamicTask {
        self.token.task
    }
    /// Current committed epoch. The first mapping profile keeps the same mm.
    pub fn previous_epoch(&self) -> u64 {
        self.token.original.epoch
    }
    /// Reserved candidate epoch; it is not committed before reply validation.
    pub fn candidate_epoch(&self) -> u64 {
        self.token.candidate_epoch
    }
    /// Original selected syscall attempt whose real EXIT preceded this capture.
    pub fn kernel_attempt(&self) -> KernelAttemptId {
        KernelAttemptId {
            session: self.token.id.session,
            invocation: self.token.original.invocation,
        }
    }
    /// Unchanged original transaction deadline, including both client callbacks.
    pub fn expires_at(&self) -> Instant {
        self.token.until
    }
    /// Complete immutable batch. This first profile requires exactly one VMA.
    pub fn images(&self) -> &[DynamicSourceImage] {
        &self.images
    }

    pub(in super::super) fn check_mapping_binding(
        &self,
        expected: &PendingToken,
        profile: &DynamicMappingProfile,
        until: Instant,
    ) -> Result<(), GateError> {
        let token = &self.token;
        if token.original != *expected
            || token.until != until
            || token.id.session != expected.stop.session
            || token.id.serial == 0
            || token.task != expected.task
            || expected.epoch != expected.task.generation
            || expected.stop.task != Some(expected.task.task)
            || token.capture_stop.session != expected.stop.session
            || token.capture_stop.tid != expected.stop.tid
            || token.capture_stop.task != Some(expected.task.task)
            || token.capture_stop.sequence <= expected.stop.sequence
            || expected.epoch.checked_add(1) != Some(token.candidate_epoch)
        {
            return Err(GateError::Refused("dynamic source request binding differs"));
        }
        if self.images.len() != 1 {
            return Err(GateError::Refused(
                "mapping source request requires one complete VMA",
            ));
        }
        for (index, image) in self.images.iter().enumerate() {
            let range = image.range();
            if image.id
                != (DynamicSourceCaptureId {
                    request: token.id,
                    index,
                })
                || image.mapping_incarnation == 0
                || !profile.contains_range(&range)
                || u64::try_from(image.bytes.len()).ok() != range.end.checked_sub(range.start)
                || image.original.permissions != "r-xp"
                || image.original.file_offset != 0
                || image.original.pathname.is_some()
                || image.quarantined.start != image.original.start
                || image.quarantined.end != image.original.end
                || image.quarantined.permissions != "r--p"
                || image.quarantined.file_offset != image.original.file_offset
                || image.quarantined.pathname != image.original.pathname
                || image.lower_neighbor.as_ref().is_some_and(|neighbor| {
                    neighbor.end != range.start
                        || neighbor.start >= neighbor.end
                        || !valid_nx_neighbor(neighbor)
                })
                || image.upper_neighbor.as_ref().is_some_and(|neighbor| {
                    neighbor.start != range.end
                        || neighbor.start >= neighbor.end
                        || !valid_nx_neighbor(neighbor)
                })
            {
                return Err(GateError::Refused(
                    "dynamic source capture geometry differs",
                ));
            }
        }
        Ok(())
    }

    pub(in super::super) fn check_facts(
        &self,
        facts: &DynamicSourceFacts,
    ) -> Result<(), GateError> {
        if facts.images.len() != self.images.len() {
            return Err(GateError::Refused("dynamic source reply image set differs"));
        }
        for image in self.images.iter() {
            let mut rows = facts.images.iter().filter(|row| row.capture == image.id);
            let row = rows
                .next()
                .ok_or(GateError::Refused("dynamic source reply image set differs"))?;
            if rows.next().is_some() {
                return Err(GateError::Refused("dynamic source reply image set differs"));
            }
            if row.heads.len() > image.bytes.len()
                || row.heads.iter().any(|head| !image.range().contains(head))
            {
                return Err(GateError::Refused(
                    "dynamic source reply head lies outside capture",
                ));
            }
        }
        Ok(())
    }
}

fn valid_nx_neighbor(mapping: &MemoryMapping) -> bool {
    let permissions = mapping.permissions.as_bytes();
    mapping.start % PAGE == 0
        && mapping.end % PAGE == 0
        && permissions.len() == 4
        && matches!(permissions[0], b'r' | b'-')
        && matches!(permissions[1], b'w' | b'-')
        && permissions[2] == b'-'
        && matches!(permissions[3], b'p' | b's')
}

/// Complete caller-certified legal head set for one exact captured image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSourceHeads {
    /// Owner-issued candidate identity; neither address nor vector index alone.
    pub capture: DynamicSourceCaptureId,
    /// Every possible original/alternate/indirect instruction head in the VMA.
    pub heads: BTreeSet<u64>,
}

/// Heads-only answer. Source bytes, mappings, permissions and epoch authority
/// always remain with the original owner and cannot be replaced by this reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicSourceFacts {
    /// Exactly one complete head set for each requested captured image.
    pub images: Vec<DynamicSourceHeads>,
}

/// Caller-thread source resolver. The unsafe session constructor requires the
/// returned head census to be complete; byte decoding alone does not prove that.
/// Refusal, panic or expiry closes the pending native admission transaction.
pub trait DynamicSourceResolver {
    /// Propose complete heads for the owner's immutable actual source capture.
    fn resolve(&mut self, request: &DynamicSourceRequest) -> Result<DynamicSourceFacts, GateError>;
}
