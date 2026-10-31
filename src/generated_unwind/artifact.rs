//! Position-independent normal-backtrace records for a source-certified artifact.
//!
//! This is an offline byte product. It neither registers records nor creates a
//! live publication handle. The carrier must install a complete loader-visible
//! unwind index, preserve original records, authenticate the source and hook at
//! load time, and qualify the actual unwinder before executing the artifact.
//! Exception propagation, LSDA handling and asynchronous unwinding are excluded.

use super::{Limits, Refusal, cfi, parser};
use crate::contracts::{CodeIdentity, PatchPlan};
use crate::emission::{ArtifactFrameTrace, SymbolicHook};
use crate::frame_trace::{FrameCallKind, FrameEntryOrigin, FrameInstructionKind};
use crate::trampoline::{ObservationStackProfile, TrampolineImage};
use iced_x86::{Mnemonic, OpKind};
use std::sync::Arc;

/// Original CFI bytes in one ELF module's virtual-address coordinates.
/// These are not pointers into the compiler's process.
#[derive(Clone, Debug)]
pub struct OriginalArtifactCfi {
    /// ELF virtual address of the CIE's length field.
    pub cie_address: u64,
    /// Complete original CIE, including its length field.
    pub cie: Vec<u8>,
    /// ELF virtual address of the FDE's length field.
    pub fde_address: u64,
    /// Complete original FDE, including its length field.
    pub fde: Vec<u8>,
}

/// Immutable source records plus separately certified exact-point semantics.
/// No mapped-source owner or runtime lifetime authority is implied.
pub struct ArtifactSourceCertificate {
    identity: CodeIdentity,
    bias_domain: u64,
    points: Vec<u64>,
    rows: Vec<parser::Rows>,
    records: Vec<OriginalArtifactCfi>,
}

impl ArtifactSourceCertificate {
    /// Parses original ELF-coordinate CFI without consulting the host process.
    ///
    /// # Safety
    /// `identity` must authenticate the immutable original artifact used by the
    /// planner. All coordinates must belong to `bias_domain`. The records must
    /// be complete byte-authenticated copies with unique original ELF owners,
    /// and FDE ownership must be complete and unambiguous at every point.
    /// Independently establish each point as an exact instruction boundary and
    /// prove its CFA and caller-recovery rules valid there. A compiler flag,
    /// interval lookup or conventional call-site-only CFI is insufficient.
    /// These premises must remain true for the lifetime of this certificate;
    /// runtime identity and lifetime checks are separate carrier obligations.
    pub unsafe fn certify(
        identity: CodeIdentity,
        bias_domain: u64,
        records: Vec<OriginalArtifactCfi>,
        points: Vec<u64>,
        limits: Limits,
    ) -> Result<Self, Refusal> {
        if records.is_empty()
            || records.len() > limits.dependencies
            || records.len() > limits.fdes
            || points.is_empty()
            || points.len() > limits.rows
        {
            return Err(Refusal::Limit);
        }
        if points.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Refusal::SourcePoint);
        }
        let mut rows = Vec::new();
        let mut count = 0_usize;
        for record in &records {
            let decoded = parser::parse(
                record.cie_address,
                &record.cie,
                record.fde_address,
                &record.fde,
                limits,
            )?;
            count = count
                .checked_add(decoded.rows.len())
                .ok_or(Refusal::Arithmetic)?;
            if count > limits.rows {
                return Err(Refusal::Limit);
            }
            rows.push(decoded);
        }
        rows.sort_by_key(|row| row.start);
        if rows.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Err(Refusal::SourceIdentity);
        }
        let result = Self {
            identity,
            bias_domain,
            points,
            rows,
            records,
        };
        for &point in &result.points {
            result.row(point)?;
        }
        Ok(result)
    }

    fn row(&self, pc: u64) -> Result<&parser::Row, Refusal> {
        if self.points.binary_search(&pc).is_err() {
            return Err(Refusal::SourcePoint);
        }
        self.rows
            .iter()
            .find(|row| row.start <= pc && pc < row.end)
            .ok_or(Refusal::SourcePoint)?
            .at(pc)
    }
}

/// A source-bound symbolic observer with the extra normal-backtrace contract.
#[derive(Clone, Copy, Debug)]
pub struct ArtifactFramePreservingHook {
    identity: CodeIdentity,
    bias_domain: u64,
    hook: SymbolicHook,
}

impl ArtifactFramePreservingHook {
    /// Certifies target code, without constructing a host function pointer.
    ///
    /// # Safety
    /// `identity` and `bias_domain` must authenticate the exact hook code and
    /// dependencies in the source artifact. At `hook.address`, the callback
    /// must accept the emitted HookContext under the SysV ABI, return normally,
    /// and leave the entire context and every original CFA/caller-memory
    /// dependency unchanged. It must not unwind, cancel, longjmp, switch stacks
    /// or replace context. Its dependencies must be ready before a redirect is
    /// reachable. A loader must recheck the binding and retain code, metadata
    /// and dependencies throughout all generated-frame execution and walks.
    pub unsafe fn certify(
        identity: CodeIdentity,
        bias_domain: u64,
        hook: SymbolicHook,
    ) -> Result<Self, Refusal> {
        if hook.address.is_none() {
            return Err(Refusal::HookContract);
        }
        Ok(Self {
            identity,
            bias_domain,
            hook,
        })
    }
}

/// Generated `.eh_frame` bytes bound to one image and one metadata coordinate.
/// Original records are retained as source dependencies, not copied into this
/// block. A carrier must preserve and index both original and generated FDEs.
pub struct PreparedArtifactUnwind {
    identity: CodeIdentity,
    bias_domain: u64,
    hook: SymbolicHook,
    source_step: PatchPlan,
    image: TrampolineImage,
    address: u64,
    bytes: Vec<u8>,
    fdes: Vec<(u64, u64, usize)>,
    source: Arc<ArtifactSourceCertificate>,
}

impl PreparedArtifactUnwind {
    /// Composes the existing normal-backtrace rules with an authenticated NOP5
    /// artifact trace, then encodes relative FDE locations at `address`.
    /// All coordinates share the trace's bias domain; out-of-range signed32
    /// fields refuse rather than introducing absolute runtime pointers.
    pub fn prepare(
        emission: &ArtifactFrameTrace,
        source: Arc<ArtifactSourceCertificate>,
        hook: ArtifactFramePreservingHook,
        address: u64,
        limits: Limits,
    ) -> Result<Self, Refusal> {
        let trace = emission.trace();
        let image = emission.exact_image();
        if source.identity != emission.identity()
            || source.bias_domain != emission.bias_domain()
            || !trace.matches_image(image)
        {
            return Err(Refusal::SourceIdentity);
        }
        if hook.identity != source.identity
            || hook.bias_domain != source.bias_domain
            || hook.hook != emission.symbolic_hook()
        {
            return Err(Refusal::HookContract);
        }
        if trace.origin() != FrameEntryOrigin::ApplicationStack
            || trace.observation_stack_profile() != ObservationStackProfile::Legacy128
            || trace.calls().len() != 1
            || trace.calls()[0].kind() != FrameCallKind::Observer
        {
            return Err(Refusal::FrameShape);
        }
        let call = trace.calls()[0];
        let call_row = trace
            .instructions()
            .iter()
            .find(|row| row.start() == call.call_pc() && row.end() == call.return_pc())
            .ok_or(Refusal::FrameShape)?;
        let FrameInstructionKind::Helper(helper) = call_row.kind() else {
            return Err(Refusal::FrameShape);
        };
        let instruction = helper.instruction();
        if instruction.mnemonic() != Mnemonic::Call
            || instruction.op0_kind() != OpKind::NearBranch64
            || Some(instruction.near_branch_target()) != hook.hook.address
        {
            return Err(Refusal::HookContract);
        }
        if trace.instructions().len() > limits.rows {
            return Err(Refusal::Limit);
        }
        let mut rows = Vec::new();
        let continuation = call
            .original_pc()
            .checked_add(5)
            .ok_or(Refusal::Arithmetic)?;
        for instruction in trace.instructions() {
            let original = source.row(instruction.original_pc())?;
            let state = match instruction.kind() {
                FrameInstructionKind::Helper(helper) => Some(helper.before()),
                FrameInstructionKind::Relocated(original)
                    if original.ip() == call.original_pc()
                        && original.mnemonic() == Mnemonic::Nop
                        && original.len() == 5 =>
                {
                    None
                }
                FrameInstructionKind::ReturnTransfer(target) if *target == continuation => None,
                _ => return Err(Refusal::FrameShape),
            };
            rows.push(cfi::compose(
                instruction.start(),
                instruction.end(),
                original,
                state,
                limits,
            )?);
        }
        let before = rows
            .iter()
            .find(|row| row.start == call.call_pc())
            .ok_or(Refusal::ReturnConvention)?;
        let after = rows
            .iter()
            .find(|row| row.start == call.return_pc())
            .ok_or(Refusal::ReturnConvention)?;
        if before.instructions != after.instructions {
            return Err(Refusal::ReturnConvention);
        }
        let (bytes, fdes) = cfi::encode_relative(&rows, address, limits)?;
        let end = address
            .checked_add(bytes.len() as u64)
            .ok_or(Refusal::Arithmetic)?;
        let image_end = image
            .address()
            .checked_add(image.bytes().len() as u64)
            .ok_or(Refusal::Arithmetic)?;
        if address < image_end && image.address() < end {
            return Err(Refusal::SourceIdentity);
        }
        Ok(Self {
            identity: source.identity,
            bias_domain: source.bias_domain,
            hook: hook.hook,
            source_step: emission.source_step().clone(),
            image: image.clone(),
            address,
            bytes,
            fdes,
            source,
        })
    }

    /// Exact metadata coordinate; these bytes cannot be moved independently.
    pub const fn address(&self) -> u64 {
        self.address
    }
    /// Complete relative `.eh_frame` block, including its zero terminator.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Generated [start, end) coordinates and FDE offsets in `bytes()`.
    pub fn fdes(&self) -> &[(u64, u64, usize)] {
        &self.fdes
    }
    /// Full original source expectations and entry obligations retained from
    /// planning; a carrier must authenticate them when embedding these bytes.
    pub const fn source_step(&self) -> &PatchPlan {
        &self.source_step
    }
    /// Exact original CIE/FDE copies retained by the source certificate.
    /// A carrier must match their addresses and complete bytes to its preserved
    /// original record stream. This byte check does not establish the separate
    /// exact-point semantics required by `ArtifactSourceCertificate::certify`.
    pub fn source_records(&self) -> &[OriginalArtifactCfi] {
        &self.source.records
    }
    /// Exact source/image/hook/domain association, without runtime authority.
    pub fn matches_trace(&self, emission: &ArtifactFrameTrace) -> bool {
        self.identity == emission.identity()
            && self.bias_domain == emission.bias_domain()
            && self.hook == emission.symbolic_hook()
            && self.source_step == *emission.source_step()
            && self.image == *emission.exact_image()
            && emission.trace().matches_image(&self.image)
    }
    /// Loader discovery, consumer semantics and runtime ownership remain owed.
    /// This API never discharges `ArtifactRequirement::GeneratedUnwindInformation`.
    pub const fn qualification_complete(&self) -> bool {
        false
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
