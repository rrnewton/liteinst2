//! Opt-in, source-certified normal backtracing; no exception or signal admission.

pub mod artifact;
mod cfi;
mod parser;

use crate::contracts::{CodeIdentity, PatchPlan, PlanKind};
use crate::frame_trace::{FrameCallKind, FrameEmission, FrameEntryOrigin, FrameInstructionKind};
use crate::quiescent::PlannedInstall;
use crate::trampoline::{HookCallback, TrampolineImage};
use iced_x86::{Mnemonic, OpKind, Register};
use std::sync::Arc;

/// Independent unwind-admission refusal; ordinary emission remains unaffected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// A byte record is truncated or internally inconsistent.
    MalformedCfi,
    /// A CFI opcode, augmentation or architecture is not admitted.
    UnsupportedCfi,
    /// An exact original point has no semantic certificate or decoded row.
    SourcePoint,
    /// Source, image, generation or metadata ownership differs.
    SourceIdentity,
    /// Caller recovery needs a rule not supported by this consumer.
    CallerRule,
    /// The frame-preserving hook contract is absent or mismatched.
    HookContract,
    /// Producer metadata or the selected relocation shape is not admitted.
    FrameShape,
    /// The normal call-return lookup convention does not preserve the row.
    ReturnConvention,
    /// A prospective metadata bound was reached.
    Limit,
    /// Checked address or signed-offset arithmetic failed.
    Arithmetic,
    /// A read-only metadata mapping could not be staged.
    Allocation,
    /// Registered lookup did not return the exact retained FDE.
    RegistrationLookup,
}

/// Admission consequences for the additional unwind publication transaction.
#[derive(Clone, Debug)]
pub enum PublicationError {
    /// No registry call or source write occurred; staged resources are released.
    Preparation(Refusal),
    /// No source write occurred, but registration/code/CFI are retained forever.
    RetainedBeforeWrite(Refusal),
    /// The original publication contract, including postwrite KeepGated, applies.
    Publication(crate::contracts::PublicationFailure),
}

/// Explicit metadata bounds; these do not enlarge ordinary emitter limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum FDE count.
    pub fdes: usize,
    /// Maximum decoded source/generated row count.
    pub rows: usize,
    /// Maximum encoded expression length.
    pub expression_bytes: usize,
    /// Maximum size of each original CIE/FDE record.
    pub source_record_bytes: usize,
    /// Maximum total generated CFI bytes.
    pub metadata_bytes: usize,
    /// Maximum original record dependencies.
    pub dependencies: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            fdes: 64,
            rows: 4096,
            expression_bytes: 128,
            source_record_bytes: 65536,
            metadata_bytes: 1024 * 1024,
            dependencies: 128,
        }
    }
}

/// Actual mapped original records, copied from an authenticated ELF owner.
#[derive(Clone, Debug)]
pub struct OriginalCfi {
    /// Original mapped address used by the CIE/FDE pointer encodings.
    pub cie_address: u64,
    /// Complete CIE, including its length field.
    pub cie: Vec<u8>,
    /// Original mapped address of this FDE's length field.
    pub fde_address: u64,
    /// Complete FDE, including its length field.
    pub fde: Vec<u8>,
}

/// Retained source-module authority, rechecked immediately before publication.
///
/// # Safety
/// The object must pin every certified code/CFI module for its own lifetime,
/// prevent address reuse/unload, and report stale identity or metadata changes.
/// `revalidate` must not unwind, publish code, or admit concurrent mutation.
pub unsafe trait SourceOwner: Send + Sync {
    /// Rechecks the authenticated original CFI/module generation.
    fn revalidate(&self) -> Result<(), Refusal>;
}

/// Parsed actual source CFI plus independent exact-point semantic authority.
pub struct SourceCertificate {
    identity: CodeIdentity,
    points: Vec<u64>,
    rows: Vec<parser::Rows>,
    _records: Vec<OriginalCfi>,
    owner: Arc<dyn SourceOwner>,
}
impl SourceCertificate {
    /// Parses actual records while retaining separately supplied point authority.
    ///
    /// # Safety
    /// `records` must be byte-authenticated against their unique immutable ELF
    /// owners at the supplied mapped addresses. FDE ownership must be complete
    /// and unambiguous for every point. Every point's original CFA/caller rules
    /// must be independently known valid at that exact instruction boundary;
    /// interval containment or compiler call-site-only CFI is insufficient.
    /// `identity` must name that code incarnation and `owner` must pin all code,
    /// metadata and semantic provenance until its last reference is destroyed.
    pub unsafe fn certify(
        identity: CodeIdentity,
        records: Vec<OriginalCfi>,
        points: Vec<u64>,
        owner: Arc<dyn SourceOwner>,
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
        owner.revalidate()?;
        let mut rows = Vec::new();
        let mut count = 0_usize;
        for record in &records {
            let parsed = parser::parse(
                record.cie_address,
                &record.cie,
                record.fde_address,
                &record.fde,
                limits,
            )?;
            count = count
                .checked_add(parsed.rows.len())
                .ok_or(Refusal::Arithmetic)?;
            if count > limits.rows {
                return Err(Refusal::Limit);
            }
            if rows
                .iter()
                .any(|old: &parser::Rows| old.start < parsed.end && parsed.start < old.end)
            {
                return Err(Refusal::SourceIdentity);
            }
            rows.push(parsed);
        }
        let certificate = Self {
            identity,
            points,
            rows,
            _records: records,
            owner,
        };
        for &pc in &certificate.points {
            certificate.row(pc)?;
        }
        Ok(certificate)
    }
    fn row(&self, pc: u64) -> Result<&parser::Row, Refusal> {
        if self.points.binary_search(&pc).is_err() {
            return Err(Refusal::SourcePoint);
        }
        let mut matching = self
            .rows
            .iter()
            .filter(|rows| rows.start <= pc && pc < rows.end);
        let row = matching.next().ok_or(Refusal::SourcePoint)?.at(pc)?;
        if matching.next().is_some() {
            return Err(Refusal::SourceIdentity);
        }
        Ok(row)
    }
}

/// Explicit observing callback contract, stronger than ordinary HookCallback.
#[derive(Clone, Copy)]
pub struct FramePreservingHook {
    callback: HookCallback,
}
impl FramePreservingHook {
    /// Certifies a callback's normal-return and frame-preservation obligations.
    ///
    /// # Safety
    /// The callback and everything it calls must return normally via System V,
    /// never unwind/cancel/longjmp, and leave the entire HookContext and every
    /// original CFA/caller-rule memory dependency unchanged. No stack switching
    /// or context replacement is permitted. Its code must remain callable for
    /// the lifetime of every generated image using this certificate.
    pub unsafe fn certify(callback: HookCallback) -> Self {
        Self { callback }
    }
}

/// Qualified normal libgcc-style registration/lookup ABI and retained owner.
pub struct Backend {
    register: unsafe extern "C" fn(*const u8),
    lookup: unsafe extern "C" fn(u64) -> *const u8,
    _owner: Arc<dyn Send + Sync>,
}
impl Backend {
    /// Binds already-qualified consumer functions without invoking them.
    ///
    /// # Safety
    /// Both functions must belong to the same pinned consumer used for walks.
    /// Registration has the real void __register_frame semantics and may not
    /// unwind; lookup must return the exact FDE start for a normal lookup PC.
    /// The caller must establish the actual ABI, return-PC convention, source
    /// and generated record formats, single-thread registration/fork policy and
    /// process-lifetime ownership. No result may be synthesized by an adapter.
    pub unsafe fn qualified(
        register: unsafe extern "C" fn(*const u8),
        lookup: unsafe extern "C" fn(u64) -> *const u8,
        owner: Arc<dyn Send + Sync>,
    ) -> Self {
        Self {
            register,
            lookup,
            _owner: owner,
        }
    }
}

/// Prepared immutable generated CFI; no executable/CFI mapping, registration or redirect.
pub struct PreparedUnwind {
    plan: PatchPlan,
    image: TrampolineImage,
    source: Arc<SourceCertificate>,
    backend: Arc<Backend>,
    bytes: Vec<u8>,
    fdes: Vec<(u64, u64, usize)>,
    calls: Vec<(u64, u64)>,
}
impl PreparedUnwind {
    /// Composes the first explicitly qualified NOP5/static-observer envelope.
    pub fn prepare(
        install: &PlannedInstall,
        emission: &FrameEmission,
        source: Arc<SourceCertificate>,
        hook: FramePreservingHook,
        backend: Arc<Backend>,
        limits: Limits,
    ) -> Result<Self, Refusal> {
        let plan = install.plan();
        let image = install.image();
        let trace = emission.trace().map_err(|_| Refusal::FrameShape)?;
        if emission.image() != image
            || !trace.matches_image(image)
            || source.identity != plan.parts().identity
        {
            return Err(Refusal::SourceIdentity);
        }
        if image.layout().observation_stack_profile
            != crate::trampoline::ObservationStackProfile::Legacy128
            || trace.origin() != FrameEntryOrigin::ApplicationStack
            || trace.calls().len() != 1
            || trace.calls()[0].kind() != FrameCallKind::Observer
            || plan.parts().kind != PlanKind::Relocation
            || plan.parts().physical_pc != plan.parts().logical_pc
            || plan.parts().displaced.len() != 5
        {
            return Err(Refusal::FrameShape);
        }
        let read = &plan.parts().reads[0];
        let offset = usize::try_from(
            plan.parts()
                .logical_pc
                .checked_sub(read.address)
                .ok_or(Refusal::SourceIdentity)?,
        )
        .map_err(|_| Refusal::Arithmetic)?;
        if read
            .bytes
            .get(offset..offset.checked_add(5).ok_or(Refusal::Arithmetic)?)
            != Some(&[0x0f, 0x1f, 0x44, 0, 0])
        {
            return Err(Refusal::FrameShape);
        }
        let call = trace.calls()[0];
        let index = trace
            .instructions()
            .iter()
            .position(|row| row.start() == call.call_pc())
            .ok_or(Refusal::HookContract)?;
        let prior = index
            .checked_sub(1)
            .and_then(|n| trace.instructions().get(n))
            .ok_or(Refusal::HookContract)?;
        match prior.kind() {
            FrameInstructionKind::Helper(helper)
                if helper.instruction().mnemonic() == Mnemonic::Mov
                    && helper.instruction().op0_register() == Register::RAX
                    && helper.instruction().op1_kind() == OpKind::Immediate64
                    && helper.instruction().immediate64()
                        == hook.callback as *const () as usize as u64 => {}
            _ => return Err(Refusal::HookContract),
        }
        if trace.instructions().len() > limits.rows {
            return Err(Refusal::Limit);
        }
        let mut rows = Vec::new();
        for instruction in trace.instructions() {
            let original = source.row(instruction.original_pc())?;
            let state = match instruction.kind() {
                FrameInstructionKind::Helper(helper) => Some(helper.before()),
                FrameInstructionKind::Relocated(original)
                    if original.mnemonic() == Mnemonic::Nop && original.len() == 5 =>
                {
                    None
                }
                FrameInstructionKind::ReturnTransfer(target)
                    if *target == plan.parts().displaced.end() =>
                {
                    None
                }
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
        let (bytes, fdes) = cfi::encode(&rows, limits)?;
        source.owner.revalidate()?;
        Ok(Self {
            plan: plan.clone(),
            image: image.clone(),
            source,
            backend,
            bytes,
            fdes,
            calls: vec![(call.call_pc(), call.return_pc())],
        })
    }
    /// Complete encoded .eh_frame block, ending in the required zero record.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Exact code extents and FDE byte offsets in the encoded block.
    pub fn fdes(&self) -> &[(u64, u64, usize)] {
        &self.fdes
    }
    pub(crate) fn check(&self, plan: &PatchPlan, image: &TrampolineImage) -> Result<(), Refusal> {
        if plan != &self.plan || image != &self.image {
            return Err(Refusal::SourceIdentity);
        }
        self.source.owner.revalidate()
    }
    pub(crate) fn stage(&self) -> Result<StagedRegistration, Refusal> {
        self.source.owner.revalidate()?;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = usize::try_from(page).map_err(|_| Refusal::Allocation)?;
        if !page.is_power_of_two() {
            return Err(Refusal::Allocation);
        }
        let len = self
            .bytes
            .len()
            .checked_add(page - 1)
            .ok_or(Refusal::Arithmetic)?
            & !(page - 1);
        let pointer = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(Refusal::Allocation);
        }
        let staged = StagedRegistration {
            pointer: pointer.cast(),
            len,
            source: self.source.clone(),
            backend: self.backend.clone(),
            fdes: self.fdes.clone(),
            calls: self.calls.clone(),
        };
        unsafe {
            core::ptr::copy_nonoverlapping(self.bytes.as_ptr(), staged.pointer, self.bytes.len());
        }
        if unsafe { libc::mprotect(pointer, len, libc::PROT_READ) } != 0 {
            return Err(Refusal::Allocation);
        }
        Ok(staged)
    }
}

pub(crate) struct StagedRegistration {
    pointer: *mut u8,
    len: usize,
    source: Arc<SourceCertificate>,
    backend: Arc<Backend>,
    fdes: Vec<(u64, u64, usize)>,
    calls: Vec<(u64, u64)>,
}
impl Drop for StagedRegistration {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.pointer.cast(), self.len);
        }
    }
}
impl StagedRegistration {
    pub(crate) fn commit(self) -> Result<RegisteredUnwind, Refusal> {
        // Intentionally leak before the void registration call: no later
        // return path, lookup failure or retired source may release these.
        let retained = Box::leak(Box::new(self));
        unsafe {
            (retained.backend.register)(retained.pointer);
        }
        for &(call, returned) in &retained.calls {
            for pc in [
                call,
                returned.checked_sub(1).ok_or(Refusal::Arithmetic)?,
                returned,
            ] {
                let offset = retained
                    .fdes
                    .iter()
                    .find(|(start, end, _)| *start <= pc && pc < *end)
                    .ok_or(Refusal::RegistrationLookup)?
                    .2;
                let expected = unsafe { retained.pointer.add(offset) };
                if unsafe { (retained.backend.lookup)(pc) } != expected {
                    return Err(Refusal::RegistrationLookup);
                }
            }
        }
        let _ = &retained.source;
        Ok(RegisteredUnwind {
            address: retained.pointer as usize as u64,
            len: retained.len,
        })
    }
}

/// Evidence of retained process-lifetime CFI; Drop never deregisters it.
pub struct RegisteredUnwind {
    address: u64,
    len: usize,
}
impl RegisteredUnwind {
    /// Start of immutable retained CFI storage.
    pub const fn address(&self) -> u64 {
        self.address
    }
    /// Full retained read-only mapping length.
    pub const fn mapping_len(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
mod tests;
