//! Artifact-only storage envelope. The body image/layout remain unchanged.
//!
//! Geometry is not allocation authority: the caller must retain the exact
//! source-window proof, full-page permits/occupancy and complete pair admission.
//! There is deliberately no conversion to a live image or publication handle.

use super::*;
use crate::contracts::{AddressRange, Refusal};

const PAGE_BYTES: usize = 4096;
const VENEER_BYTES: usize = 5;
const GAP_BYTE: u8 = 0xcc;

/// Checked pre-encode geometry, not a claim about emitted bytes or ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EntryVeneerPlacement {
    page: AddressRange,
    entry: u64,
    size_bound: usize,
}

impl EntryVeneerPlacement {
    pub(crate) fn new(storage: u64, entry: u64, size_bound: usize) -> Result<Self, Refusal> {
        if storage & (PAGE_BYTES as u64 - 1) != 0 {
            return Err(Refusal::InvalidRange);
        }
        let page = AddressRange::new(storage, PAGE_BYTES)?;
        if size_bound == 0 || size_bound > PAGE_BYTES - VENEER_BYTES {
            return Err(Refusal::AllocationUnavailable);
        }
        let offset = entry.checked_sub(storage).ok_or(Refusal::InvalidRange)?;
        if offset < size_bound as u64 || offset > (PAGE_BYTES - VENEER_BYTES) as u64 {
            return Err(Refusal::AllocationUnavailable);
        }
        Ok(Self {
            page,
            entry,
            size_bound,
        })
    }

    pub(crate) const fn storage_address(self) -> u64 {
        self.page.start()
    }
    pub(crate) const fn entry_address(self) -> u64 {
        self.entry
    }
    pub(crate) const fn mapping(self) -> AddressRange {
        self.page
    }
    pub(crate) const fn size_bound(self) -> usize {
        self.size_bound
    }
    pub(crate) const fn entry_offset(self) -> usize {
        (self.entry - self.page.start()) as usize
    }
    pub(crate) const fn storage_len(self) -> usize {
        self.entry_offset() + VENEER_BYTES
    }
}

/// Owns one unchanged body plus every byte through its separate entry veneer.
/// Padding is physically RX when mapped; it has no logical-PC/entry authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactTrampolineAllocation {
    body: TrampolineImage,
    placement: EntryVeneerPlacement,
    bytes: Vec<u8>,
    metadata: ArtifactImageMetadata,
    program_counters: Vec<ProgramCounterMapping>,
}

impl ArtifactTrampolineAllocation {
    /// Exactly one consuming body encode. No candidate encode or retry exists
    /// here; a final field/extent/provenance refusal is the result of this slot.
    pub(crate) fn emit(
        prepared: PreparedArtifact,
        placement: EntryVeneerPlacement,
    ) -> Result<Self, TrampolineError> {
        if prepared.size_bound() != placement.size_bound() {
            return Err(invalid(
                "veneer certificate does not bind the prepared body",
            ));
        }
        let body = prepared.emit_at(placement.storage_address())?;
        Self::from_body(body, placement)
    }

    // Not an externally supplied image admission path. Only emit() reaches it
    // outside this module's mutation controls, after the unchanged body emitter.
    fn from_body(
        body: TrampolineImage,
        placement: EntryVeneerPlacement,
    ) -> Result<Self, TrampolineError> {
        let (original_pc, domain) = validate_body(&body, placement)?;
        let offset = placement.entry_offset();
        let mut template = body.bytes().to_vec();
        template.resize(offset, GAP_BYTE);
        template.extend_from_slice(&[0xe9, 0, 0, 0, 0]);
        let field = veneer_fixup(placement, original_pc);
        let bytes = fixups::link_bias_invariant(
            ImageId(placement.storage_address()),
            &template,
            &[field],
            &[ImagePlacement {
                image: ImageId(placement.storage_address()),
                address: RelativeAddress {
                    domain: BiasDomain(domain),
                    offset: i128::from(placement.storage_address()),
                },
                len: template.len() as u64,
            }],
        )
        .map_err(artifact_fixup_error)?;
        let mut metadata = body
            .artifact_metadata()
            .ok_or_else(|| invalid("missing body metadata"))?
            .clone();
        metadata
            .fields
            .push(veneer_field(placement, original_pc, domain));
        let mut program_counters = body.program_counter_mappings().to_vec();
        program_counters.push(veneer_pc(placement, original_pc));
        let allocation = Self {
            body,
            placement,
            bytes,
            metadata,
            program_counters,
        };
        allocation.validate()?;
        Ok(allocation)
    }

    pub(crate) const fn storage_address(&self) -> u64 {
        self.placement.storage_address()
    }
    pub(crate) const fn entry_address(&self) -> u64 {
        self.placement.entry_address()
    }
    pub(crate) const fn placement(&self) -> EntryVeneerPlacement {
        self.placement
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn body_len(&self) -> usize {
        self.body.bytes().len()
    }
    pub(crate) const fn body_layout(&self) -> TrampolineLayout {
        self.body.layout()
    }
    pub(crate) fn artifact_metadata(&self) -> &ArtifactImageMetadata {
        &self.metadata
    }
    pub(crate) fn entry_routes(&self) -> &[(u64, u64)] {
        self.body.entry_routes()
    }
    pub(crate) fn instruction_boundaries(&self) -> &[(u64, u64)] {
        self.body.instruction_boundaries()
    }
    pub(crate) fn program_counter_mappings(&self) -> &[ProgramCounterMapping] {
        &self.program_counters
    }

    /// The separate external edge is E -> B. It does not replace the original
    /// head's body route or assert an application-restored boundary at E.
    pub(crate) const fn entry_transfer(&self) -> (u64, u64) {
        (self.entry_address(), self.storage_address())
    }

    pub(crate) fn require_artifact_router(&mut self) {
        self.body.require_artifact_router();
        if !self
            .metadata
            .requirements
            .contains(&ArtifactRequirement::EntryRouterBootstrap)
        {
            self.metadata
                .requirements
                .push(ArtifactRequirement::EntryRouterBootstrap);
        }
    }

    pub(crate) fn validate(&self) -> Result<(), TrampolineError> {
        let (original_pc, domain) = validate_body(&self.body, self.placement)?;
        let body_metadata = self
            .body
            .artifact_metadata()
            .ok_or_else(|| invalid("missing body metadata"))?;
        let body_len = self.body_len();
        let entry = self.placement.entry_offset();
        if self.bytes.len() != self.placement.storage_len()
            || self.bytes.get(..body_len) != Some(self.body.bytes())
            || self
                .bytes
                .get(body_len..entry)
                .is_none_or(|gap| gap.iter().any(|&byte| byte != GAP_BYTE))
            || self.bytes.get(entry) != Some(&0xe9)
        {
            return Err(invalid("veneer body/gap/instruction partition changed"));
        }
        if self.metadata.fields.len() != body_metadata.fields.len() + 1
            || self.metadata.fields.get(..body_metadata.fields.len())
                != Some(body_metadata.fields.as_slice())
            || self.metadata.fields.last()
                != Some(&veneer_field(self.placement, original_pc, domain))
            || self.metadata.requirements != body_metadata.requirements
        {
            return Err(invalid(
                "veneer field inventory or outstanding requirements changed",
            ));
        }
        validate_fields(
            &self.bytes,
            self.storage_address(),
            domain,
            &self.metadata.fields,
        )?;
        let body_maps = self.body.program_counter_mappings();
        if self.program_counters.len() != body_maps.len() + 1
            || self.program_counters.get(..body_maps.len()) != Some(body_maps)
            || self.program_counters.last() != Some(&veneer_pc(self.placement, original_pc))
        {
            return Err(invalid(
                "veneer PC inventory changed or grants padding authority",
            ));
        }
        let mut decoder = Decoder::with_ip(
            64,
            &self.bytes[entry..],
            self.entry_address(),
            DecoderOptions::NONE,
        );
        let jump = decoder.decode();
        if jump.code() != Code::Jmp_rel32_64
            || jump.len() != VENEER_BYTES
            || jump.near_branch_target() != self.storage_address()
            || jump.next_ip() != self.placement.mapping().start() + self.bytes.len() as u64
            || decoder.can_decode()
        {
            return Err(invalid(
                "veneer is not the exact five-byte entry-to-body jump",
            ));
        }
        Ok(())
    }
}

fn invalid(message: &str) -> TrampolineError {
    TrampolineError::Artifact {
        reason: crate::emission::ArtifactRefusalKind::InvalidFieldLedger,
        message: message.into(),
    }
}

fn veneer_fixup(placement: EntryVeneerPlacement, original_pc: u64) -> Fixup {
    Fixup {
        offset: placement.entry_offset() as u64 + 1,
        encoding: Encoding::PcRelative32 {
            next: placement.storage_len() as u64,
        },
        target: Target::Image {
            image: ImageId(placement.storage_address()),
            offset: 0,
        },
        role: Role::EntryVeneer { original_pc },
        expected: vec![0; 4],
    }
}

fn veneer_field(placement: EntryVeneerPlacement, original_pc: u64, domain: u64) -> ArtifactField {
    ArtifactField {
        offset: placement.entry_offset() as u64 + 1,
        width: 4,
        encoding: ArtifactFieldEncoding::Relative,
        origin: placement.storage_len() as u64,
        target: i128::from(placement.storage_address()),
        bias_domain: domain,
        role: format!("{:?}", Role::EntryVeneer { original_pc }),
    }
}

fn veneer_pc(placement: EntryVeneerPlacement, original_pc: u64) -> ProgramCounterMapping {
    ProgramCounterMapping {
        generated_start: placement.entry_address(),
        generated_end: placement.storage_address() + placement.storage_len() as u64,
        logical_address: original_pc,
    }
}

fn validate_body(
    body: &TrampolineImage,
    placement: EntryVeneerPlacement,
) -> Result<(u64, u64), TrampolineError> {
    if EntryVeneerPlacement::new(
        placement.storage_address(),
        placement.entry_address(),
        placement.size_bound(),
    )
    .ok()
        != Some(placement)
        || body.address() != placement.storage_address()
        || body.bytes().len() <= VENEER_BYTES
        || body.bytes().len() > placement.size_bound()
        || body.layout().total_len() != Some(body.bytes().len())
        || body.layout().return_len != VENEER_BYTES
        || !body.controls().is_empty()
        || body.clock().is_some()
        || body.clock_gate().is_some()
        || body.precontext_selector().is_some()
        || !body.precontext_gates().is_empty()
    {
        return Err(invalid("veneer body/certificate/owner geometry mismatch"));
    }
    let [(original_pc, route)] = body.entry_routes() else {
        return Err(invalid(
            "veneer requires exactly one selected original head",
        ));
    };
    let [(boundary_pc, restored)] = body.instruction_boundaries() else {
        return Err(invalid(
            "veneer requires exactly one unchanged restored boundary",
        ));
    };
    let end = body
        .address()
        .checked_add(body.bytes().len() as u64)
        .ok_or_else(|| invalid("body extent overflow"))?;
    if *route != body.address()
        || boundary_pc != original_pc
        || *restored < body.address()
        || *restored >= end - VENEER_BYTES as u64
    {
        return Err(invalid(
            "veneer body route or restored boundary is not original",
        ));
    }
    let metadata = body
        .artifact_metadata()
        .ok_or_else(|| invalid("veneer requires artifact provenance"))?;
    let mut returns = metadata
        .fields
        .iter()
        .filter(|field| field.role == "Return");
    let returned = returns
        .next()
        .ok_or_else(|| invalid("missing exact body return field"))?;
    if returns.next().is_some()
        || returned.encoding != ArtifactFieldEncoding::Relative
        || returned.width != 4
        || returned.origin != body.bytes().len() as u64
        || returned.offset != body.bytes().len() as u64 - 4
        || body.bytes()[body.bytes().len() - VENEER_BYTES] != 0xe9
    {
        return Err(invalid("veneer requires the unchanged single near return"));
    }
    let original_len = returned
        .target
        .checked_sub(i128::from(*original_pc))
        .filter(|length| (2..=4).contains(length))
        .ok_or_else(|| {
            invalid("veneer is restricted to one original 2..=4-byte selected instruction")
        })?;
    let original_range = AddressRange::new(*original_pc, original_len as usize)
        .map_err(|_| invalid("original short range wraps"))?;
    if placement.mapping().overlaps(original_range) {
        return Err(invalid("veneer page overlaps its original instruction"));
    }
    let domain = returned.bias_domain;
    validate_fields(body.bytes(), body.address(), domain, &metadata.fields)?;
    for field in &metadata.fields {
        // No previously local endpoint may silently become padding/veneer after
        // extending storage. Body-local generated edges retain the old emitter's
        // exact target proof; original/module targets outside this page remain.
        if field.target >= i128::from(end) && field.target < i128::from(placement.mapping().end()) {
            return Err(invalid("body field points into the new padding or veneer"));
        }
    }
    let mut cursor = body.address();
    for mapping in body.program_counter_mappings() {
        if mapping.generated_start() != cursor
            || mapping.generated_end() <= cursor
            || mapping.generated_end() > end
            || (mapping.logical_address() != *original_pc
                && i128::from(mapping.logical_address()) != returned.target)
        {
            return Err(invalid(
                "body PC map is not the complete unchanged short body",
            ));
        }
        cursor = mapping.generated_end();
    }
    if cursor != end {
        return Err(invalid(
            "body PC map does not cover its exact emitted bytes",
        ));
    }
    Ok((*original_pc, domain))
}

// Independent readback of signed field arithmetic. No new field is inferred
// from a scan, and no old field/role is removed or reconstructed speculatively.
fn validate_fields(
    bytes: &[u8],
    base: u64,
    domain: u64,
    fields: &[ArtifactField],
) -> Result<(), TrampolineError> {
    let mut ordered: Vec<_> = fields.iter().collect();
    ordered.sort_unstable_by_key(|field| field.offset);
    let mut previous_end = 0_u64;
    for field in ordered {
        let end = field
            .offset
            .checked_add(field.width as u64)
            .ok_or_else(|| invalid("artifact field extent overflow"))?;
        if field.bias_domain != domain
            || field.offset < previous_end
            || end > bytes.len() as u64
            || field.origin > bytes.len() as u64
        {
            return Err(invalid(
                "artifact field domain/extent/origin/overlap mismatch",
            ));
        }
        let raw = &bytes[field.offset as usize..end as usize];
        let actual = match (field.encoding, raw) {
            (ArtifactFieldEncoding::Relative, [a]) => i128::from(i8::from_le_bytes([*a])),
            (ArtifactFieldEncoding::Relative, [a, b, c, d]) => {
                i128::from(i32::from_le_bytes([*a, *b, *c, *d]))
            }
            (ArtifactFieldEncoding::Delta, [a, b, c, d, e, f, g, h]) => {
                i128::from(i64::from_le_bytes([*a, *b, *c, *d, *e, *f, *g, *h]))
            }
            _ => return Err(invalid("artifact field encoding/width mismatch")),
        };
        let expected = field
            .target
            .checked_sub(i128::from(base) + i128::from(field.origin))
            .ok_or_else(|| invalid("artifact field arithmetic overflow"))?;
        if actual != expected {
            return Err(invalid(
                "artifact field bytes do not encode their exact target",
            ));
        }
        previous_end = end;
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
